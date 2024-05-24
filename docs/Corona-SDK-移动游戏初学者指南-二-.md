# Corona SDK 移动游戏初学者指南（二）

> 原文：[`zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82`](https://zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：制作我们的第一个游戏 - 破坏者

> *到目前为止，我们已经学习了 Lua 编程中的一些重要基础，并在 Corona 模拟器中应用了一些代码。了解术语只是学习如何创建应用程序的一小部分。我们需要更进一层，亲身体验从开始到结束构建一个项目的全过程。我们将通过从零开始创建我们的第一个游戏来实现这一点。这将推动你进一步理解更大的代码块，并应用一些游戏逻辑来创建一个功能性的游戏。*

到本章结束时，你将理解：

+   如何在 Corona 项目中构建游戏文件结构

+   如何为游戏创建变量

+   如何向屏幕添加游戏对象

+   如何创建警告信息

+   如何显示得分和关卡数字

让我们开始享受乐趣！

# 破坏者 - 重温旧式游戏

在过去几十年里，你可能已经见过许多破坏者的版本，尤其是在雅达利时代。为了让你对这款游戏有一个大致的了解，以下是 Big Fish Games 关于破坏者历史的简要编辑：[`www.bigfishgames.com/blog/the-history-of-breakout/`](http://www.bigfishgames.com/blog/the-history-of-breakout/)。以下截图是破坏者游戏的示例：

![破坏者 - 重温旧式游戏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_03_01.jpg)

在游戏屏幕上，有几列砖块放置在屏幕顶部附近。一个球在屏幕上移动，从屏幕顶部和侧壁弹回。当击中砖块时，球会弹开，砖块被摧毁。当球触碰到屏幕底部时，玩家将输掉这一轮。为了防止这种情况发生，玩家有一个可移动的挡板来将球弹起，保持游戏进行。

我们将使用触摸事件和加速度计来创建一个克隆版本，玩家将控制挡板的活动。我们将为球添加一些物理效果，使其能在屏幕上弹跳。

在下一章中，我们将添加游戏对象的活动、碰撞检测、计分以及胜利/失败条件。现在，我们要专注于如何设置破坏者游戏模板。

# 理解 Corona 物理 API

Corona 使向游戏中添加物理效果变得方便，尤其是如果你以前从未处理过这类工作。这个引擎使用 Box2D，只需几行代码就可以将其集成到你的应用程序中，而这通常需要更多的设置。

在 Corona 中使用物理引擎相当简单。你使用显示对象并在代码中将它们设置为物理实体。图像、精灵和矢量形状可以被转化为物理对象。这对于可视化你想要在创建的环境中对象如何反应非常有帮助。你可以立即看到结果，而不是猜测它们在物理世界中可能的行为。

## 设置物理世界

在你的应用程序中使物理引擎可用需要以下这行代码：

```kt
local physics = require "physics"
```

### 启动、暂停和停止物理引擎

有三个主要函数会影响物理模拟。以下是启动、暂停和停止物理引擎的命令：

+   `physics.start()`：这将启动或恢复物理环境。通常在应用程序开始时激活，使物理实体生效。

+   `physics.pause()`：这会暂时停止物理引擎。

+   `physics.stop()`：这基本上完全销毁物理世界。

### physics.setGravity

此函数用于设置全局重力向量的 x 和 y 参数，单位为每秒平方米（加速度单位）。默认值为 (0, 9.8)，以模拟标准的地球重力，指向 *y* 轴的下方。其语法为 `physics.setGravity(gx, gy)`：

```kt
physics.setGravity( 0, 9.8 ): Standard Earth gravity
```

### physics.getGravity

此函数返回全局重力向量的 x 和 y 参数，单位为每秒平方厘米（加速度单位）。

语法为 `gx, gy = physics.getGravity()`。

### 基于倾斜的重力

当你应用了 `physics.setGravity(gx, gy)` 和加速度计 API，实现基于倾斜的动态重力是简单的。以下是创建基于倾斜功能的示例：

```kt
function movePaddle(event)

  paddle.x = display.contentCenterX - (display.contentCenterX * (event.yGravity*3))

end

Runtime:addEventListener( "accelerometer", movePaddle )
```

Corona 模拟器中没有加速度计；必须创建设备构建才能看到效果。

### physics.setScale

此函数设置内部每米像素比率，用于在屏幕上的 Corona 坐标和模拟物理坐标之间转换。这应该在实例化任何物理对象之前完成。

默认缩放值为 30。对于分辨率较高的设备，如 iPad、Android 或 iPhone 4，你可能希望将此值增加到 60 或更多。

语法为 `physics.setScale(value)`：

```kt
physics.setScale( 60 )
```

### physics.setDrawMode

物理引擎有三种渲染模式。这可以在任何时候更改。

语法为 `physics.setDrawMode(mode)`。三种渲染模式分别为：

+   `physics.setDrawMode("debug")`：此模式仅显示碰撞引擎轮廓，如下面的截图所示：![physics.setDrawMode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_03_02.jpg)

+   `physics.setDrawMode("hybrid")`：此模式在正常 Corona 对象上叠加碰撞轮廓，如下面的截图所示：![physics.setDrawMode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_03_03.jpg)

+   `physics.setDrawMode("normal")`：此模式是默认的 Corona 渲染器，没有碰撞轮廓：![physics.setDrawMode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_03_04.jpg)

物理数据使用颜色编码的矢量图形显示，反映了不同的对象类型和属性：

+   **橙色**：用于表示动态物理实体（默认实体类型）

+   **深蓝色**：用于表示运动学物理实体

+   **绿色**：用于表示静态物理实体，如地面或墙壁

+   **灰色**：用于表示因缺乏活动而处于 *休眠* 状态的实体

+   **浅蓝色**：用于表示关节

### physics.setPositionIterations

这个函数设置了引擎位置计算的精确度。默认值是 `8`，意味着引擎将每帧为每个对象进行八次位置近似迭代，但这会增加处理器的参与度，因此需要小心处理，因为它可能会减慢应用程序的运行。

语法是 `physics.setPositionIterations(值)`：

```kt
physics.setPositionIterations(16)
```

### `physics.setVelocityIterations`

这个函数设置了引擎速度计算的精确度。默认值是 3，意味着引擎将每帧为每个对象进行三次速度近似迭代。然而，这将增加处理器的参与度，因此需要小心处理，因为它可能会减慢应用程序的运行。

语法是 `physics.setVelocityIterations(值)`：

```kt
physics.setVelocityIterations( 6 )
```

# 配置应用程序

本教程兼容 iOS 和 Android 设备。图形设计已调整以适应两个平台的多种屏幕尺寸。

## 构建配置

默认情况下，所有设备屏幕上显示的项目都以竖屏模式展示。我们将特别在横屏模式下创建这个游戏，因此我们需要更改一些构建设置并配置屏幕上所有项目的显示方式。在横屏模式下玩游戏实际上会增加更多玩家互动，因为挡板将有更多的屏幕空间移动，球体的空中时间也会减少。

# 动手时间——添加 `build.settings` 文件

构建时属性可以在可选的 `build.settings` 文件中提供，该文件使用 Lua 语法。`build.settings` 文件用于设置应用程序的屏幕方向和自动旋转行为以及各种特定平台的构建参数。要在你的项目文件夹中添加 `build.settings` 文件，请执行以下步骤：

1.  在你的桌面上创建一个名为 `Breakout` 的新项目文件夹。

1.  在你偏好的文本编辑器中，创建一个名为 `build.settings` 的新文件，并将其保存在你的项目文件夹中。

1.  输入以下几行：

    ```kt
    settings =
    {
      orientation =
      {
        default = "landscapeRight",
        supported = { "landscapeLeft", "landscapeRight" },
      }
    }
    ```

1.  保存并关闭文件。`build.settings` 文件已完成。

## *刚才发生了什么？*

默认方向设置决定了设备上的初始启动方向以及 Corona 模拟器的初始方向。

默认方向不会影响 Android 设备。方向初始化为设备的实际方向（除非只指定了一个方向）。另外，唯一支持的方向是 `landscapeRight` 和 `portrait`。在设备上，你可以切换到 `landscapeRight` 或 `landscapeLeft`，但操作系统只报告一种横屏模式，而 Corona 的方向事件选择 `landscapeRight`。

我们创建这个应用程序是为了支持`landscapeRight`的横屏方向。我们将这个方向设置为默认值，这样它就不会切换到`landscapeLeft`或任何`portrait`模式。在 iOS 设备上工作时，如果在启动应用程序之前没有设置`build.settings`，它将进入默认的竖屏模式。

## 动态缩放

Corona 可以针对 iOS 和 Android 多个设备构建应用程序，显示不同分辨率的各种艺术资源。Corona 可以根据你的起始分辨率向上或向下缩放。它还可以在需要时替换高分辨率的图像文件，确保你的应用程序在所有设备上清晰锐利。

# 动手时间——添加`config.lua`文件

如果没有指定内容大小，返回的内容宽度和高度将与设备的物理屏幕宽度和高度相同。如果在`config.lua`中指定了不同的内容宽度和高度，内容宽度和高度将采用这些值。要在你的项目文件夹中添加`config.lua`文件，请执行以下步骤：

1.  在你的文本编辑器中，创建一个名为`config.lua`的新文件，并将其保存到你的项目文件夹中。

1.  输入以下几行：

    ```kt
    application =
    {
      content =
      {
        width = 320,
        height = 480, 
        scale = "letterbox",
        fps = 60,
      },
    }
    ```

1.  保存并关闭你的文件。

## *刚才发生了什么？*

内容宽度和高度允许你选择一个与物理设备屏幕尺寸无关的虚拟屏幕尺寸。我们将尺寸设置为针对 iPhone 3GS，因为它在 iOS 和 Android 平台的大多数设备上显示的是常见的尺寸之一。

这个应用程序使用的缩放比例设置为`letterbox`。它将尽可能统一放大内容，同时仍然在屏幕上显示所有内容。

我们将`fps`设置为`60`。默认情况下，帧率是 30 fps。在这个应用程序中，这将使球的移动看起来更快，便于我们方便地提高速度。我们可以将帧率拉伸到 60 fps，这是 Corona 允许的最大值。

# 构建应用程序

现在我们已经将应用程序配置为横屏模式，并设置显示内容在多个设备上缩放，我们准备开始设计游戏。在我们开始为游戏编写代码之前，我们需要添加一些将在屏幕上显示的艺术资源。你可以在`第三章资源`文件夹中找到它们。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。以下是你需要添加到你的`Breakout`项目文件夹中的文件：

+   `alertBox.png`

+   `bg.png`

+   `mmScreen.png`

+   `ball.png`

+   `paddle.png`

+   `brick.png`

+   `playbtn.png`

## 显示组

我们将在游戏中介绍一个重要的功能 `display.newGroup()`。显示组允许你添加和移除子显示对象，并收集相关的显示对象。最初，组中没有子对象。本地原点位于父对象的原点；锚点初始化为此本地原点。你可以轻松地将显示对象组织在单独的组中，并通过组名称引用它们。例如，在 Breakout 中，我们将**标题**屏幕和**播放**按钮等菜单项组合在一个名为 `menuScreenGroup` 的组中。每次我们访问 `menuScreenGroup`，显示组中包含的任何显示对象都将被处理。

### display.newGroup()

这个函数创建了一个组，你可以在其中添加和移除子显示对象。

语法是 `display.newGroup()`。

例如：

```kt
local rect = display.newRect(0, 0, 150, 150)
rect:setFillColor(1, 1, 1)

local myGroup = display.newGroup()
myGroup:insert(rect)
```

## 使用系统函数

我们在本章中将要介绍的系统函数将返回有关系统（设备信息和当前方向）的信息，并控制系统函数（启用多点触控和控制空闲时间、加速度计和 GPS）。我们将使用以下系统函数返回应用程序将运行的环境信息以及加速度计事件的响应频率。

### system.getInfo()

这个函数返回有关应用程序正在运行上的系统的信息。

语法是 `system.getInfo(param)`:

```kt
print(system.getInfo("name")) -- display the deviceID
```

参数的有效值如下：

+   `"name"`: 这将返回设备的型号名称。例如，在 iTouch 上，这将是出现在 iTunes 中的手机名称，如"Pat's iTouch"。

+   `"model"`: 这将返回设备类型。包括以下内容：

    +   iPhone

    +   iPad

    +   iPhone 模拟器

    +   Nexus One

    +   Droid

    +   myTouch

    +   Galaxy Tab

+   `"deviceID"`: 这将返回设备的哈希编码设备 ID。

+   `"environment"`: 这将返回应用程序正在运行的环境。包括以下内容：

    +   `"simulator"`: Corona 模拟器

    +   `"device"`: iOS, Android 设备以及 Xcode 模拟器

+   `"platformName"`: 这将返回平台名称（操作系统名称），可以是以下任何一个：

    +   Mac OS X (Corona 模拟器在 Mac 上)

    +   Win (Corona 模拟器在 Windows 上)

    +   iPhone OS (所有 iOS 设备)

    +   Android (所有 Android 设备)

+   `"platformVersion"`: 这将返回平台版本的字符串表示。

+   `"build"`: 这将返回 Corona 构建字符串。

+   `"textureMemoryUsed"`: 这将返回纹理内存使用量（字节）。

+   `"maxTextureSize"`: 这将返回设备支持的最大纹理宽度或高度。

+   `"architectureInfo"`: 这将返回描述你正在运行的设备底层 CPU 架构的字符串。

### system.setAccelerometerInterval()

此函数设置加速度计事件的频率。在 iPhone 上，最低频率为 10 Hz，最高为 100 Hz。加速度计事件对电池的消耗很大，因此只有在你需要更快响应时，比如在游戏中，才增加频率。尽可能降低频率以节省电池寿命。

语法是 `system.setAccelerometerInterval( frequency )`：

```kt
system.setAccelerometerInterval( 75 )
```

该函数设置样本间隔，单位为赫兹。赫兹是每秒的周期数，即每秒要进行的测量次数。如果你将频率设置为 75，那么系统将每秒进行 75 次测量。

在将 `第三章` 的 `Resources` 文件夹中的资源添加到你的项目文件夹后，我们将开始编写一些代码！

# 动手操作——为游戏创建变量

为了启动任何应用程序，我们需要创建一个 `main.lua` 文件。这在第二章 *Lua 速成与 Corona 框架* 中讨论过，当时我们使用了一些示例代码并通过模拟器运行了它。

当游戏完成时，代码将相应地在你的 `main.lua` 文件中构建：

+   必要的类（例如，`physics` 或 `ui`）

+   变量和常量

+   主函数

+   对象方法

+   调用主函数（必须始终调用，否则你的应用程序将无法运行）

将代码组织成前面的结构是一种保持事物有序和高效运行应用程序的好习惯。

在本节中，我们将介绍一个显示组，该显示组将展示主菜单屏幕和一个**播放**按钮，用户可以通过与该按钮互动进入主游戏屏幕。游戏中的所有元素，如挡板、球、砖块对象以及抬头显示元素，都是在玩家与**播放**按钮互动后出现的。我们还将介绍胜利和失败的条件，这些条件将被称作`alertDisplayGroup`。所有这些游戏元素都将在代码开始时初始化。

1.  在你的文本编辑器中创建一个新的 `main.lua` 文件，并将其保存到项目文件夹中。

1.  我们将隐藏状态栏（特别是针对 iOS 设备）并加载物理引擎。Corona 使用的是已经内置在 SDK 中的 Box2D 引擎：

    ```kt
    display.setStatusBar(display.HiddenStatusBar)

    local physics = require "physics"
    physics.start()
    physics.setGravity(0, 0)

    system.setAccelerometerInterval(100)
    ```

    ### 注意

    有关 Corona 物理 API 的更多信息可以在 Corona 网站找到，地址是[`docs.coronalabs.com/guide/physics/physicsSetup/index.html`](http://docs.coronalabs.com/guide/physics/physicsSetup/index.html)。

    Corona SDK 中使用的 Box2D 物理引擎是由 Blizzard Entertainment 的 Erin Catto 编写的。关于 Box2D 的更多信息可以在[`box2d.org/manual.pdf`](http://box2d.org/manual.pdf)找到。

1.  添加菜单屏幕对象：

    ```kt
    local menuScreenGroup  -- display.newGroup()
    local mmScreen
    local playBtn
    ```

1.  添加游戏屏幕对象：

    ```kt
    local background
    local paddle
    local brick
    local ball
    ```

1.  添加分数和等级的 HUD 元素：

    ```kt
    local scoreText
    local scoreNum
    local levelText
    local levelNum
    ```

    ### 注意

    HUD 也被称为抬头显示。它是在游戏屏幕上视觉化表示角色信息的方法。

1.  接下来，我们将添加用于胜利/失败条件的警告显示组：

    ```kt
    local alertDisplayGroup    -- display.newGroup()
    local alertBox
    local conditionDisplay
    local messageText
    ```

1.  以下变量保存了砖块显示组、得分、球速度和游戏内事件的值：

    ```kt
    local _W = display.contentWidth / 2
    local _H = display.contentHeight / 2
    local bricks = display.newGroup()
    local brickWidth = 35
    local brickHeight = 15
    local row
    local column
    local score = 0
    local scoreIncrease = 100
    local currentLevel
    local vx = 3
    local vy = -3
    local gameEvent = ""
    ```

1.  加速度计事件只能在设备上测试，因此我们将通过调用 `"simulator"` 环境为桨添加一个触摸事件变量。这样我们可以在 Corona 模拟器中测试桨的运动。如果你在设备上测试应用程序，桨上的触摸和加速度计事件监听器不会发生冲突：

    ```kt
    local isSimulator = "simulator" == system.getInfo("environment")
    ```

1.  最后，加入 `main()` 函数。这将启动我们的应用程序：

    ```kt
    function main()

    end

    --[[
    This empty space will hold other functions and methods to run the application
    ]]--

    main()
    ```

## *刚才发生了什么？*

`display.setStatusBar(display.HiddenStatusBar)` 方法仅适用于 iOS 设备。它隐藏了设备上状态栏的外观。

我们为这个游戏添加的新 Corona API 是物理引擎。我们将为主要的游戏对象（桨、球和砖块）添加物理参数以进行碰撞检测。设置 `setGravity(0,0)` 将允许球在游戏场内自由弹跳。

`local menuScreenGroup`、`local alertDisplayGroup` 和 `local bricks` 对象都是显示组的类型，我们可以通过它们来分离和组织显示对象。例如，`local menuScreenGroup` 专门用于主菜单屏幕上出现的对象。因此，它们可以作为一个组被移除，而不是单个对象。

某些已添加的变量已经具有应用于特定游戏对象的值。球体已经使用 `local vx = 3` 和 `local vy = -3` 设置了速度。x 和 y 速度决定了球在游戏屏幕上的移动方式。根据球与对象碰撞的位置，球将沿着连续的路径移动。`brickWidth` 和 `brickHeight` 对象具有在应用程序的整个过程中保持恒定的值，因此我们可以将砖块对象在屏幕上均匀排列。

`local gameEvent = " "` 将存储游戏事件，如 `"win"`、`"lose"` 和 `"finished"`。当函数检查游戏状态是否有这些事件之一时，它将在屏幕上显示适当的状态。

我们还加入了一些系统函数。我们创建了 `local isSimulator = "simulator" == system.getInfo("environment")` 以返回有关运行应用程序的系统的信息。这将用于桨触控事件，以便我们可以在模拟器中测试应用程序。如果将构建移植到设备上，你只能使用加速度计来移动桨。模拟器无法测试加速度计事件。另一个系统函数是 `system.setAccelerometerInterval( 100 )`。它设置了加速度计事件的频率。iPhone 上的最低频率是 10 Hz，最高是 100 Hz。

`main()`空函数集将开始显示层次结构。可以把它看作是一个故事板。你首先看到的是介绍，然后中间发生一些动作，告诉你主要内容是什么。在这种情况下，主要内容是游戏玩法。你最后看到的是某种结尾或闭合，将故事联系在一起。结尾是在关卡结束时显示的胜负条件。

# 理解事件和监听器

事件被发送到监听者，由移动屏幕上的触摸、点击、加速度计等执行。函数或对象可以作为事件监听器。当事件发生时，监听器将被调用，并通过一个表示事件的表进行通知。所有事件都将有一个标识事件类型的属性名。

## 注册事件

显示对象和全局运行时对象可以作为事件监听器。你可以使用以下对象方法添加和移除事件监听器：

+   `object:addEventListener()`: 这将一个监听器添加到对象的监听器列表中。当命名的事件发生时，将调用监听器，并提供一个表示事件的表。

+   `object:removeEventListener()`: 这将指定的监听器从对象监听器列表中移除，使其不再接收与指定事件对应的事件通知。

在以下示例中，一个图像显示对象注册以接收触摸事件。触摸事件不会全局广播。注册了事件并在其下方的显示对象将成为接收事件的候选对象：

```kt
local playBtn = display.newImage("playbtn.png")
playBtn.name = "playbutton"

local function listener(event)
  if event.target.name == "playbutton" then

    print("The button was touched.")

end
end

playBtn:addEventListener("touch", listener )
```

运行时事件由系统发送，会广播给所有监听者。以下是注册`enterFrame`事件的一个例子：

```kt
local playBtn = display.newImage("playbtn.png") 

local function listener(event) 
  print("The button appeared.")
end

Runtime:addEventListener("enterFrame", listener )
```

## 运行时事件

我们正在创建的应用程序使用了运行时事件。运行时事件没有特定的目标，只发送到全局运行时。它们广播给所有注册的监听者。

运行时事件由系统发送，会广播给所有监听者。以下是注册`enterFrame`事件的一个例子：

```kt
local playBtn = display.newImage("playbtn.png")

local function listener(event)
  print("The button appeared.")
end

Runtime:addEventListener("enterFrame", listener )
```

以下事件都有字符串名称，并将应用于 Breakout 游戏。

### enterFrame

`enterFrame`事件在应用程序的帧间隔发生。它们只发送到全局运行时对象。例如，如果帧率是 30 fps，那么它将大约每秒发生 30 次。

此事件中可用的属性如下：

+   `event.name`是字符串`"enterFrame"`

+   `event.time`是自应用程序开始以来的毫秒数

### 加速度计

加速度计事件允许你检测移动并确定设备相对于重力的方向。这些事件只发送到支持加速度计的设备。它们只发送到全局运行时对象。

此事件可用的属性如下：

+   `event.name`是字符串`"accelerometer"`

+   `event.xGravity`是*x*方向上的重力加速度

+   `event.yGravity` 是 *y* 方向的由重力引起的加速度。

+   `event.zGravity` 是 *z* 方向的由重力引起的加速度。

+   `event.xInstant` 是 *x* 方向的瞬时加速度。

+   `event.yInstant` 是 *y* 方向的瞬时加速度。

+   `event.zInstant` 是 *z* 方向的瞬时加速度。

+   `event.isShake` 是当用户摇动设备时为真。

## 触摸事件（Touch events）

当用户的手指触摸屏幕时，会生成一个命中事件并将其派发到显示层次结构中的显示对象。只有与屏幕上手指位置相交的对象才可能接收到事件。

### 单点触摸（Touch，single touch）

触摸事件是一种特殊的命中事件。当用户的手指触摸屏幕时，它们开始了一系列具有不同阶段的触摸事件。

+   `event.name` 是字符串 `"touch"`。

+   `event.x` 是触摸点在屏幕坐标中的 *x* 位置。

+   `event.y` 是触摸点在屏幕坐标中的 *y* 位置。

+   `event.xStart` 是触摸序列 `"began"` 阶段的 *x* 位置。

+   `event.yStart` 是触摸序列 `"began"` 阶段的 *y* 位置。

+   `event.phase` 是一个字符串，用于标识事件在触摸序列中的哪个阶段发生：

    +   `"began"`：这表示手指触摸了屏幕。

    +   `"moved"`：这表示手指在屏幕上移动。

    +   `"ended"`：这表示手指从屏幕上抬起。

    +   `"cancelled"`：这表示系统取消了触摸的跟踪。

### 轻击（tap）

当用户触摸屏幕时，它会生成一个命中事件。该事件被派发到显示层次结构中的显示对象。这与触摸事件类似，不同之处在于事件回调中提供了点击次数（轻击次数），并且不使用事件阶段。事件 API 如下：

+   `event.name` 是字符串 `"tap"`。

+   `event.numTaps` 返回屏幕上的轻击次数。

+   `event.x` 是轻击在屏幕坐标中的 *x* 位置。

+   `event.y` 是触摸点在屏幕坐标中的 *y* 位置。

# 过渡（Transitions）

在本章中，我们将介绍 `transition.to()` 和 `transition.from()`：

+   `transition.to()`：这会随着时间的推移，使用 `easing` 过渡动画显示对象的属性。

    语法为 `handle = transition.to( target, params )`。

+   `transition.from()`：这与 `transition.to()` 类似，不同之处在于起始属性值在函数参数表中指定，最终值是在调用之前目标中的相应属性值。语法为 `handle = transition.from( target, params )`。

    使用的参数如下：

    +   `target`：这是过渡动画的目标显示对象。

    +   `params`：这是一个指定将进行动画的显示对象属性以及以下一个或多个可选的非动画属性的表：

        +   `params.time`：这指定了过渡的持续时间（以毫秒为单位）。默认情况下，持续时间为 500 毫秒（0.5 秒）。

        +   `params.transition`：默认为`easing.linear`。

        +   `params.delay`：这指定了补间开始前延迟的毫秒数（默认为无）。

        +   `params.delta`：这是一个布尔值，指定非控制参数是作为最终结束值还是作为值的变化来解释。默认为`nil`，即假。

        +   `params.onStart`：这是一个在补间开始之前调用的函数或表监听器。

        +   `params.onComplete`：这是一个在补间完成后调用的函数或表监听器。

例如：

```kt
_W = display.contentWidth
_H = display.contentHeight

local square = display.newRect( 0, 0, 100, 100 )
square:setFillColor( 1, 1, 1 )
square.x = _W/2; square.y = _H/2

local square2 = display.newRect( 0, 0, 50, 50 )
square2:setFillColor( 1, 1, 1 )
square2.x = _W/2; square2.y = _H/2

transition.to( square, { time=1500, x=250, y=400 } )
transition.from( square2, { time=1500, x=275, y=0 } )
```

前面的示例展示了两个显示对象如何在设备屏幕上过渡空间。从当前位置开始，`square`显示对象将在 1500 毫秒内移动到新的位置`x = 250`和`y = 400`。`square2`显示对象将从`x = 275`和`y = 0`的位置在 1500 毫秒内过渡到其初始位置。

# 创建菜单屏幕

拥有菜单屏幕可以让玩家在应用程序的不同部分之间过渡。通常，游戏会从显示游戏标题的某种屏幕开始，并带有一个标有**播放**或**开始**的交互式用户界面按钮，让玩家选择玩游戏。在任何移动应用程序中，在过渡到主要内容之前都有一个菜单屏幕是标准的。

# 行动时间——添加主菜单屏幕

主菜单界面将是玩家在应用程序启动后与菜单系统交互的第一个东西。这是介绍游戏标题并让玩家了解他们将面对的游戏环境类型的好方法。我们肯定不希望玩家在没有适当通知的情况下突然跳入应用程序。当玩家启动应用程序时，让他们为即将到来的内容做好准备是很重要的。

1.  我们将创建一个名为`mainMenu()`的函数来介绍标题屏幕。所以，在`function main()`结束后，加入以下几行：

    ```kt
    function mainMenu()  

    end
    ```

1.  我们将向这个函数中添加一个显示组和两个显示对象。一个显示对象是将代表主菜单屏幕的图像，另一个是一个名为**播放**的 UI 按钮。将它们添加到`function mainMenu()`内部：

    ```kt
      menuScreenGroup = display.newGroup()

      mmScreen = display.newImage("mmScreen.png", 0, 0, true)
      mmScreen.x = _W
      mmScreen.y = _H

      playBtn = display.newImage("playbtn.png")
      playBtn.anchorX = 0.5; playBtn.anchorY = 0.5  
      playBtn.x = _W; playBtn.y = _H + 50
      playBtn.name = "playbutton"

      menuScreenGroup:insert(mmScreen)
      menuScreenGroup:insert(playBtn)
    ```

1.  记得那个空的`main()`函数集吗？我们需要在其中调用`mainMenu()`。整个函数应该像这样：

    ```kt
    function main()
      mainMenu()
    end 
    ```

1.  在`mainMenu()`函数之后，我们将创建另一个名为`loadGame()`的函数。这个函数将初始化来自`playbtn`的事件以过渡到主游戏屏幕。事件将改变`menuScreenGroup`的 alpha 为`0`，使其在屏幕上不可见。通过调用`addGameScreen()`函数完成过渡（将在本章的*行动时间——添加游戏对象*部分讨论`addGameScreen()`）：

    ```kt
    function loadGame(event)
      if event.target.name == "playbutton" then

        transition.to(menuScreenGroup,{time = 0, alpha=0, onComplete = addGameScreen})

        playBtn:removeEventListener("tap", loadGame)
      end
    end
    ```

1.  接下来，我们需要为`playBtn`添加一个事件监听器，这样当它被点击时，就会调用`loadGame()`函数。在`mainMenu()`函数中的最后一个方法后添加以下这行代码：

    ```kt
    playBtn:addEventListener("tap", loadGame)
    ```

1.  在模拟器中运行项目。你应该会看到主菜单屏幕显示**Breakout**和**Play**按钮。

## *刚才发生了什么？*

创建一个主菜单屏幕只需要几块代码。对于`loadGame(event)`，我们传递了一个名为`event`的参数。当调用`if`语句时，它取`playbutton`，它引用显示对象`playBtn`，并检查它是否为真。既然如此，`menuScreenGroup`将从舞台中移除并在`addGameScreen()`函数中被调用。同时，`playBtn`的事件监听器将从场景中移除。

## 动手试试——创建帮助屏幕

目前，菜单系统的设计是设置成从主菜单屏幕过渡到游戏玩法屏幕。你可以选择扩展菜单屏幕，而不必立即跳转到游戏中。可以在主菜单屏幕之后添加的一个额外功能是帮助菜单屏幕，它向玩家解释如何玩游戏。

在你喜欢的图像编辑程序中创建一个新的图像，并写出如何进行游戏的步骤。然后你可以创建一个名为**Next**的新按钮，并将这两个艺术资源添加到你的项目文件夹中。在你的代码中，你将必须为你的**Next**按钮创建一个新的函数和事件监听器，它会过渡到游戏玩法屏幕。

# 创建游戏玩法场景

现在我们已经有一个菜单系统在位，我们可以开始处理应用程序的游戏玩法元素。我们将开始添加玩家将与之互动的所有主要游戏对象。在添加游戏对象时需要注意的一件事是它们在屏幕上的位置。考虑到这个游戏将在横屏模式下进行，我们必须记住在*x*方向上有足够的空间，而在*y*方向上的空间较少。根据游戏的原始设计，屏幕底部的墙壁会导致玩家失去关卡或转向，如果球落在这个区域。因此，如果我们要确定一个放置挡板对象的位置，我们不会将其设置在屏幕顶部附近。让挡板尽可能靠近屏幕底部以更好地保护球更有意义。

# 动手时间——添加游戏对象

让我们添加玩家在游戏玩法中会看到的显示对象：

1.  在`loadGame()`函数之后，我们将创建另一个函数，用于在屏幕上显示所有游戏对象。以下几行将显示为这个教程创建的艺术资源：

    ```kt
    function addGameScreen()

      background = display.newImage("bg.png", 0, 0, true )
      background.x = _W 
      background.y = _H

      paddle = display.newImage("paddle.png")
      paddle.x = 240; paddle.y = 300
      paddle.name = "paddle"

      ball = display.newImage("ball.png")
      ball.x = 240; ball.y = 290
      ball.name = "ball"
    ```

1.  接下来，我们将添加在游戏中显示分数和关卡编号的文本：

    ```kt
      scoreText = display.newText("Score:", 25, 10, "Arial", 14)
      scoreText:setFillColor( 1, 1, 1 )

      scoreNum = display.newText("0", 54, 10, "Arial", 14)
      scoreNum: setFillColor( 1, 1, 1 )

      levelText = display.newText("Level:", 440, 10, "Arial", 14)
      levelText:setFillColor( 1, 1, 1 )

      levelNum = display.newText("1", 470, 10, "Arial", 14)
      levelNum:setFillColor( 1, 1, 1 )
    ```

1.  为了构建第一个游戏关卡，我们将调用`gameLevel1()`函数，该函数将在本章后面解释。别忘了用`end`结束`addGameScreen()`函数：

    ```kt
      gameLevel1() 

    end
    ```

## *刚才发生了什么？*

`addGameScreen()` 函数显示游戏过程中出现的所有游戏对象。我们从本章提供的美工资源中添加了 `background`、`paddle` 和 `ball` 显示对象。

我们在游戏屏幕顶部添加了分数和等级的文本。`scoreNum` 最初设置为 `0`。在下一章，我们将讨论当砖块碰撞时如何更新分数。`levelNum` 从 1 开始，完成等级后更新，并进入下一个等级。

我们通过调用 `gameLevel1()` 来结束函数，这将在下一节中实现，以开始第一关。

# 是时候行动了——构建砖块。

砖块是我们需要为这个应用程序添加的最后一个游戏对象。我们将为这个游戏创建两个不同的等级，每个等级的砖块布局都不同于另一个：

1.  我们将要为第一关创建一个函数。让我们创建一个新函数 `gameLevel1()`。我们还将 `currentLevel` 设置为 `1`，因为应用程序从第一关开始。然后，我们将添加 `bricks` 显示组并将其设置为 `toFront()`，使其在游戏背景前显示：

    ```kt
    function gameLevel1()

      currentLevel = 1

      bricks:toFront()
    ```

    `object:toFront()` 方法将目标对象移动到其父组 (`object.parent`) 的视觉最前方。在这种情况下，我们将 `bricks` 组设置为游戏过程中最前端的显示组，使其在背景图片前方显示。

1.  接下来，添加一些局部变量，以显示屏幕上将显示多少行和列的砖块，以及每个砖块在游戏场中的位置：

    ```kt
      local numOfRows = 4
      local numOfColumns = 4
      local brickPlacement = {x = (_W) - (brickWidth * numOfColumns ) / 2  + 20, y = 50}
    ```

1.  创建双重 `for` 循环，一个用于 `numOfRows`，另一个用于 `numOfColumns`。根据其宽度、高度以及 `numOfRows` 和 `numOfColumns` 的对应数字创建一个砖块实例。本章提供了砖块显示对象的美工资源。然后，使用 `end` 结束函数：

    ```kt
      for row = 0, numOfRows - 1 do
        for column = 0, numOfColumns - 1 do

          local brick = display.newImage("brick.png")
          brick.name = "brick"
          brick.x = brickPlacement.x + (column * brickWidth)
          brick.y = brickPlacement.y + (row * brickHeight)
          physics.addBody(brick, "static", {density = 1, friction = 0, bounce = 0})
          bricks.insert(bricks, brick)

        end
      end
    end
    ```

1.  第二关的设置与第一关的排列类似。代码几乎相同，除了我们新的函数名为 `gameLevel2()`，`currentLevel` 设置为 `2`，并且 `numOfRows` 和 `numOfColumns` 的值不同。在 `gameLevel1()` 函数后添加以下代码块：

    ```kt
    function gameLevel2()

      currentLevel = 2

      bricks:toFront()

      local numOfRows = 5
      local numOfColumns = 8
      local brickPlacement = {x = (_W) - (brickWidth * numOfColumns ) / 2  + 20, y = 50}

      for row = 0, numOfRows - 1 do
        for column = 0, numOfColumns - 1 do

          -- Create a brick
          local brick = display.newImage("brick.png")
          brick.name = "brick"
          brick.x = brickPlacement.x + (column * brickWidth)
          brick.y = brickPlacement.y + (row * brickHeight)
          physics.addBody(brick, "static", {density = 1, friction = 0, bounce = 0})
          bricks.insert(bricks, brick)

        end
      end
    end
    ```

1.  保存你的文件并重新启动模拟器。你将能够与 **Play** 按钮互动，并从主菜单屏幕过渡到游戏屏幕。你将在屏幕上看到第一关的游戏布局。

## *刚才发生了什么？*

`bricks` 显示组被设置为 `bricks:toFront()`。这意味着除了 `background`、`paddle` 和 `ball` 显示对象之外，该组将始终位于显示层次结构的前面。

`gameLevel1()`方法为游戏场地中显示的砖块对象数量设定了固定值。它们将基于设备外壳的`contentWidth`居中，并在 y 方向上设置为`50`。通过`brickPlacement`将砖块组放置在左上角附近，占据屏幕中间位置，并减去所有砖块对象总宽度的一半。然后在 x 方向上再加上 20 个像素，使其与挡板居中。

我们为`numOfRows`和`numOfColumns`创建了双层`for`循环，从屏幕左上角开始创建砖块对象。

请注意，`brick`显示对象被命名为`brick`。只需记住，在调用对象时，不能像使用`brick`那样使用`brick`。`brick`对象是`brick`的一个实例。它仅当调用事件参数时作为字符串使用，例如：

```kt
if event.other.name == "brick" and ball.x + ball.width * 0.5 < event.other.x + event.other.width * 0.5 then
        vx = -vx 
elseif event.other.name == "brick" and ball.x + ball.width * 0.5 >= event.other.x + event.other.width * 0.5 then
        vx = vx 
end
```

`brick`的物理体被设置为`"static"`，因此它不会受到重力下拉的影响。然后，通过`bricks.insert(bricks, brick)`将其添加到`bricks`组中。

## 做一个尝试英雄——专注于平台游戏

在完成本章和下一章后，请随意重新设计显示图像，以便关注特定平台。例如，你可以轻松地将代码转换为兼容所有 iOS 设备。这可以通过将显示对象转换为`display.newImageRect( [parentGroup,] filename [, baseDirectory] w, h )`来实现，这样你就可以替换具有更大屏幕尺寸的设备（如 iPhone 5/Samsung Galaxy S5）上的图像尺寸。请记住，你将不得不调整配置设置以应用这些更改。这涉及到在你的`config.lua`文件中添加独特的图像后缀（或你喜欢的后缀命名约定）。

# 红色警报！

在每个游戏中，当主要动作结束时，都会有一种消息告诉你进度状态。对于这个应用程序，我们需要一种方法让玩家知道他们是否赢得或输掉了一轮，他们如何再次玩，或者游戏何时正式完成。

# 是时候采取行动了——显示游戏消息

让我们设置一些胜利/失败的提示，以便我们可以显示游戏中发生的事件：

1.  创建一个名为`alertScreen()`的新函数，并传递两个名为`title`和`message`的参数。添加一个新的显示对象`alertbox`，并使用`easing.outExpo`使其从`xScale`和`yScale`为 0.5 的过渡效果：

    ```kt
    function alertScreen(title, message)

      alertBox = display.newImage("alertBox.png")
      alertBox.x = 240; alertBox.y = 160

      transition.from(alertBox, {time = 500, xScale = 0.5, yScale = 0.5, transition = easing.outExpo})
    ```

1.  将`title`参数存储在名为`conditionDisplay`的文本对象中：

    ```kt
      conditionDisplay = display.newText(title, 0, 0, "Arial", 38)
      conditionDisplay:setFillColor( 1, 1, 1 )
      conditionDisplay.xScale = 0.5
      conditionDisplay.yScale = 0.5
      conditionDisplay.anchorX = 0.5
      conditionDisplay.x =  display.contentCenterX
      conditionDisplay.y = display.contentCenterY - 15
    ```

1.  将`message`参数存储在名为`messageText`的文本对象中：

    ```kt
      messageText = display.newText(message, 0, 0, "Arial", 24)
      messageText:setFillColor( 1, 1, 1 )
      messageText.xScale = 0.5
      messageText.yScale = 0.5
      messageText.anchorX = 0.5  
      messageText.x = display.contentCenterX
      messageText.y = display.contentCenterY + 15
    ```

1.  创建一个新的显示组，名为`alertDisplayGroup`，并将所有对象插入到该组中。关闭函数：

    ```kt
      alertDisplayGroup = display.newGroup()
      alertDisplayGroup:insert(alertBox)
      alertDisplayGroup:insert(conditionDisplay)
      alertDisplayGroup:insert(messageText)
    end
    ```

1.  保存你的文件并在模拟器中运行项目。**Play**按钮的功能仍然会进入**Level: 1**的游戏玩法屏幕。目前，所有对象都没有任何移动。我们将在下一章添加触摸事件、球体移动和碰撞。所有游戏对象应如以下截图所示布局：![Time for action – displaying game messages](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_03_05.jpg)

## *刚才发生了什么？*

我们已经为游戏设置了警报系统，但在我们添加更多游戏功能使游戏对象动起来之前，它目前还不能操作。下一章将展示`alertScreen()`函数如何传递两个参数，`title`和`message`。当满足条件后，`alertBox`显示对象会作为警报文本的背景弹出。当`alertBox`弹出时，它会从 0.5 的`xScale`和`yScale`过渡到全图像大小，耗时 500 毫秒。这基本上相当于半秒钟。

`conditionDisplay`对象传递`title`参数。这将显示**You Win**或**You Lose**的文本。

`messageText`对象传递`message`参数。当达到某个条件后，带有此参数的文本会显示如**Play Again**或**Continue**的消息。

此函数中的所有对象都将被插入到`alertDisplayGroup = display.newGroup()`中。它们在舞台上出现和消失时，会作为一个整体而不是单独的对象。

在模拟器中运行代码时，如果终端窗口出现错误，务必检查导致错误的行。有时，一个简单的字母大小写错误，甚至是一个缺失的逗号或引号，都可能导致你的应用无法在模拟器中运行。请留意这些常见错误，它们很容易被忽视。

你可以参考`第三章`文件夹中的`Breakout – Part 1`文件夹，了解本教程前半部分代码的设置。

## 小测验——构建一个游戏

Q1\. 在你的代码中添加物理引擎时，哪些函数可以添加到你的应用程序中？

1.  `physics.start()`

1.  `physics.pause()`

1.  `physics.stop()`

1.  以上都不对

Q2\. 添加事件监听器以下哪个是正确的？

1.  `button:addeventlistener("touch", listener)`

1.  `button:AddEventListener("touch", listener)`

1.  `button:addEventListener(touch, listener)`

1.  `button:addEventListener("touch", listener)`

Q3\. 以下显示对象正确过渡到`x = 300`，`y = 150`，并将 alpha 改为 0.5，耗时 2 秒的方式是？

```kt
local square = display.newRect( 0, 0, 50, 50 )
square:setFillColor( 1, 1, 1 )
square.x = 100 square2.y = 300
```

1.  `transition.to( square, { time=2000, x=300, y=150, alpha=0.5 })`

1.  `transition.from( square, { time=2000, x=300, y=150, alpha=0.5 })`

1.  `transition.to( square, { time=2, x=300, y=150, alpha=0.5 })`

1.  以上都不对

# 总结

我们已经完成了这个游戏教程的前半部分。正确理解如何构建 Corona 项目结构，可以让你的代码更有组织性，更好地追踪你的资源。我们已经尝试处理了与游戏中所需的小部分逻辑相关的代码块，这些代码块使得应用程序能够运行。

到目前为止，我们已经完成了：

+   指定了在 Android 和 iOS 设备上显示内容的构建配置

+   介绍了将在应用程序中运行的主要变量和常量

+   实例化了物理引擎，并开始将其应用到需要物理体的游戏对象上

+   创建了从菜单到游戏玩屏幕的过渡

+   向屏幕添加了显示对象和游戏信息

到目前为止我们已经完成了很多工作，包括在编码应用程序的过程中学习了一个新的 API，这已经是一个相当大的成就了。在游戏能够完全功能之前，我们还有很多内容需要添加。

在下一章中，我们将完成这个游戏教程的后半部分。我们将处理挡板、球、砖块和墙壁对象的碰撞检测。同时，我们还将学习如何在移除场景中的砖块时更新得分，并激活我们的赢/输条件。我们已经进入最后的冲刺阶段，让我们继续前进！


# 第四章：游戏控制

> *到目前为止，我们在上一章完成了游戏的前半部分。我们通过向屏幕引入游戏对象来开发项目的初始结构。目前，挡板和球体的移动是无效的，但在模拟器中显示的所有内容都根据原始游戏设计进行了缩放。完成本教程的最后阶段是添加游戏中将发生的所有动作，包括对象移动和更新得分。*

在本章中，我们将涵盖以下主题：

+   使用触摸事件和加速度计移动挡板

+   场景中所有游戏对象之间的碰撞检测

+   在碰撞检测时移除对象

+   在屏幕边界内球体的移动

+   计算得分

+   胜利和失败条件

最后阶段！我们能行！

# 向上移动

如果你认为让对象在屏幕上出现很有趣，那么等到你看到它们移动时！`Breakout`游戏的主要目标是保持球在挡板位置之上以保持游戏进行，并让它与所有砖块碰撞以完成关卡。让悬念持续的是对球在游戏屏幕周围移动的期待。如果没有在游戏对象上添加物理边界以对碰撞检测做出反应，这是不可能的。

# 让我们变得更加物理化

在上一章中，我们讨论了如何将物理引擎集成到代码中。我们还开始为砖块对象实现物理实体，现在，我们需要对其他活动游戏对象（如挡板和球）做同样的处理。让我们继续后半部分的教程。我们将继续使用`Breakout`项目文件夹中的`main.lua`文件。

## physics.addBody()

Corona 显示对象可以用一行代码变成模拟的物理对象。以下信息解释了不同的物理实体形式：

+   如果没有指定形状信息，显示对象将采用原始图像的实际矩形边界来创建物理实体。例如，如果一个显示对象是 100x100 像素，那么这将是物理实体的实际大小。

+   如果指定了一个形状，那么实体的边界将遵循该形状提供的多边形。形状坐标必须按顺时针顺序定义，且结果形状只能是凸的。

+   如果指定了半径，那么实体边界将是圆形的，以用于创建物理实体的显示对象的中心为中心。

一个实体形状是一个相对于显示对象中心的本地（x,y）坐标表。

实体形状的语法如下：

+   圆形形状：

    ```kt
    physics.addBody(object, [bodyType,] {density=d, friction=f, bounce=b [,radius=r]})
    ```

+   多边形形状：

    ```kt
    physics.addBody(object, [bodyType,] {density=d, friction=f, bounce=b [,shape=s]})
    ```

以下是实体形状的示例：

+   圆形实体：

    ```kt
    local ball = display.newImage("ball.png")
    physics.addBody( ball, "dynamic" { density = 1.0, friction = 0.3, bounce = 0.2, radius = 25 } )
    ```

+   多边形实体：

    ```kt
    local rectangle = display.newImage("rectangle.png")
    rectangleShape = { -6,-48, 6,-48, 6,48, -6,48 }
    physics.addBody( rectangle, { density=2.0, friction=0.5, bounce=0.2, shape=rectangleShape } )
    ```

现在，我们将讨论前面方法的相关参数：

+   `对象`：这是一个显示对象。

+   `bodyType`：这是一个字符串，用于指定身体类型是可选的。它在第一个身体元素之前使用一个字符串参数。可能的类型是`"static"`（静态）、`"dynamic"`（动态）和`"kinematic"`（动力学）。如果未指定值，默认类型是`"dynamic"`。让我们来谈谈这些类型：

    +   静态物体除非在代码中手动移动，否则不会移动，它们也不会相互交互；静态物体的例子包括弹球机的地面或墙壁。

    +   动态物体受重力和与其他物体类型的碰撞影响。

    +   动力学物体受力的影响，但不受重力影响，因此你通常应该将可拖动的物体设置为动力学物体，至少在拖动事件期间是这样。

+   `Density`：这是一个数值，通过乘以物体形状的面积来确定质量。它基于水的标准值 1.0。较轻的材料（如木材）的密度低于 1.0，而较重的材料（如石头）的密度则高于 1.0。默认值为`1.0`。

+   `Friction`：这是一个数值。可以是任何非负值；0 表示没有摩擦力，1.0 表示相当强的摩擦力。默认值为`0.3`。

+   `Bounce`：这是一个数值，决定了物体碰撞后返回的速度。默认值为`0.2`。

+   `Radius`：这是一个数值。这是边界圆的半径，单位为像素。

+   `Shape`：这是一个数值。它是形状顶点的表格形式的形状值，即{x1, y1, x2, y2, …, xn, yn}，例如`rectangleShape = { -6,-48, 6,-48, 6,48, -6,48 }`。坐标必须按顺时针顺序定义，且结果形状必须是凸的。物理引擎假设物体的(0,0)点是物体的中心。一个*负 x*坐标将位于物体中心的左侧，而*负 y*坐标将位于物体中心的顶部。

# 动手时间——为挡板和球启动物理效果。

目前，我们的显示对象相当静止。为了让游戏开始，我们必须为挡板和球激活物理效果，以发生碰撞检测。执行以下步骤：

1.  在`gameLevel1()`函数之上，创建一个名为`startGame()`的新函数：

    ```kt
    function startGame()
    ```

1.  添加以下几行代码来为挡板和球实例化物理效果：

    ```kt
      physics.addBody(paddle, "static", {density = 1, friction = 0, bounce = 0})
      physics.addBody(ball, "dynamic", {density = 1, friction = 0, bounce = 0})
    ```

1.  创建一个事件监听器，使用背景显示对象来移除`startGame()`的`"tap"`事件。使用`end`关闭函数：

    ```kt
      background:removeEventListener("tap", startGame)
    end
    ```

1.  在上一章中我们创建的`addGameScreen()`函数里，需要在调用`gameLevel1()`函数之后添加以下这行代码。这样，当触摸背景时，就会开始实际的游戏：

    ```kt
      background:addEventListener("tap", startGame)
    ```

## *刚才发生了什么？*

挡板对象有一个`"static"`（静态）的物体类型，所以它不会受到任何与之相撞的碰撞影响。

球对象有一个`"dynamic"`（动态）的物体类型，因为我们需要它受到屏幕上由于墙壁边界、砖块和挡板造成的方向改变而产生的碰撞影响。

`startGame()`函数中从背景移除了事件监听器；这样它就不会影响游戏中应用的其他触摸事件。

# 挡板移动

让挡板左右移动是必须完成的关键动作之一。游戏设计的一部分是防止球到达屏幕底部。我们将把模拟器中的挡板移动与加速度计分离。在模拟器中的移动使我们能够通过触摸事件进行测试，因为加速度计动作无法在模拟器中测试。

# 动作时间——在模拟器中拖动挡板

目前，挡板根本不会移动。没有设置允许挡板在屏幕上左右移动的坐标。所以让我们通过执行以下步骤来创建它们：

1.  在`addGameScreen()`函数下方，创建一个名为`dragPaddle(event)`的新函数：

    ```kt
    function dragPaddle(event)
    ```

1.  接下来，我们将关注在游戏屏幕边界内左右移动挡板。添加以下代码块以在模拟器中启用挡板移动，然后关闭函数。添加此代码块的原因是模拟器不支持加速度计事件：

    ```kt
      if isSimulator then

        if event.phase == "began" then
          moveX = event.x - paddle.x
        elseif event.phase == "moved" then
          paddle.x = event.x - moveX
        end

        if((paddle.x - paddle.width * 0.5) < 0) then
          paddle.x = paddle.width * 0.5
        elseif((paddle.x + paddle.width * 0.5) > display.contentWidth) then
          paddle.x = display.contentWidth - paddle.width * 0.5
        end

      end

    end
    ```

查看以下图像，预测球与砖块和挡板碰撞后球将向何处移动：

![动作时间——在模拟器中拖动挡板](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_04_01.jpg)

## *刚才发生了什么？*

我们创建了一个仅在模拟器中起作用的拖动事件函数。对于`if event.phase == "began"`，已经对挡板进行了触摸事件。在`elseif event.phase == "moved"`，已经对挡板从原始位置移动的触摸事件进行了处理。

为了防止挡板移动超过墙壁边界，当挡板碰到坐标时，`paddle.x`在*x*方向上不会小于`0`。当挡板滑向屏幕右侧时，`paddle.x`在*x*方向上不会大于`display.contentWidth`。

由于代码应该适用于 iOS 和 Android 设备上所有屏幕尺寸，因此没有指定屏幕右侧的坐标。这两个平台具有不同的屏幕分辨率，所以`display.contentWidth`考虑到了这一点。

# 动作时间——使用加速度计移动挡板

如前所述，加速度计事件无法在模拟器中测试。它们仅在将游戏构建上传到设备以查看结果时才起作用。挡板移动将保持在关卡*x*轴上的墙壁边界内。要移动挡板，请按照以下步骤操作：

1.  在`dragPaddle()`函数下方，创建一个名为`movePaddle(event)`的新函数：

    ```kt
    function movePaddle(event)
    ```

1.  使用`yGravity`添加加速度计移动。它提供了*y*方向上的重力加速度：

    ```kt
      paddle.x = display.contentCenterX - (display.contentCenterX * (event.yGravity*3))
    ```

1.  添加关卡墙壁边界并在函数末尾关闭：

    ```kt
      if((paddle.x - paddle.width * 0.5) < 0) then
        paddle.x = paddle.width * 0.5
      elseif((paddle.x + paddle.width * 0.5) > display.contentWidth) then
        paddle.x = display.contentWidth - paddle.width * 0.5
      end
    end
    ```

## *刚才发生了什么？*

要使加速度计移动在设备上工作，我们必须使用`yGravity`。

### 注意事项

当使用`xGravity`和`yGravity`时，加速度计事件基于竖屏刻度。当显示对象被指定为横屏模式时，`xGravity`和`yGravity`的值会交换，以补偿事件正常工作。

我们对挡板应用了与`function dragPaddle()`中相同的代码：

```kt
  if((paddle.x - paddle.width * 0.5) < 0) then
    paddle.x = paddle.width * 0.5
  elseif((paddle.x + paddle.width * 0.5) > display.contentWidth) then
    paddle.x = display.contentWidth - paddle.width * 0.5
  end
```

这仍然可以防止挡板越过任何墙壁边界。

# 球与挡板的碰撞

每次球与挡板碰撞时，其运动都必须流畅。这意味着在游戏场的所有侧面都要有适当的方向改变。

# 动手时间——让球反弹到挡板上

我们将检查球击中了挡板的哪一侧，以选择它接下来将移动的一侧。让运动跟随任何方向打击，就像在真实环境中一样，这很重要。每次与挡板碰撞，我们都要确保球向上移动。为此，请按照以下步骤操作：

1.  在`movePaddle()`函数后创建一个名为`bounce()`的新函数，用于处理球：

    ```kt
    function bounce()
    ```

1.  在*y*方向上添加一个值为`-3`的速度。这将使球向上移动：

    ```kt
      vy = -3
    ```

1.  检查`paddle`和`ball`对象之间的碰撞，并关闭函数：

    ```kt
      if((ball.x + ball.width * 0.5) < paddle.x) then
        vx = -vx
      elseif((ball.x + ball.width * 0.5) >= paddle.x) then
        vx = vx
      end
    end
    ```

## *刚才发生了什么？*

当球与挡板碰撞时，其运动取决于球接触挡板的哪一侧。在`if`语句的第一部分，球在*x*方向上向 0 移动。`if`语句的最后部分显示了球在*x*方向上向屏幕的另一侧移动。

# 从场景中移除对象

设备上的资源是有限的。我们希望它们能像桌面一样强大，拥有如此多的内存，但现在还没有达到这个水平。这就是为什么当您在应用程序中不再使用显示对象时，从显示层次结构中移除它们很重要的原因。这有助于通过减少内存消耗来提高整体系统性能，并消除不必要的绘制。

当创建显示对象时，默认会添加到显示层次结构的根对象中。这个对象是一种特殊的组对象，称为**舞台**对象。

为了防止对象在屏幕上渲染，需要将其从场景中移除。需要明确地从其父对象中移除该对象。这将对象从显示层次结构中移除。可以通过以下方式完成：

```kt
myImage.parent:remove( myImage ) -- remove myImage from hierarchy
```

或者，可以使用以下代码行完成此操作：

```kt
myImage:removeSelf( ) -- same as above
```

这并不会释放显示对象所有的内存。为了确保显示对象被正确移除，我们需要消除所有对其的变量引用。

## 变量引用

即使显示对象已从层次结构中移除，但在某些情况下，对象仍然存在。为此，我们将属性设置为`nil`：

```kt
local ball = display.newImage("ball.png")
local myTimer = 3

function time()
  myTimer = myTimer - 1
  print(myTimer)

  if myTimer == 0 then 

    ball:removeSelf()
    ball = nil

  end
end

timer.performWithDelay( 1000, time, myTimer )
```

# 一砖一瓦

游戏中的砖块是主要的障碍物，因为必须清除它们才能进入下一轮。在这个版本的打砖块游戏中，玩家必须一次性摧毁所有砖块。如果做不到这一点，则需要从当前关卡的开始处重新开始。

# 行动时间——移除砖块

当球与砖块碰撞时，我们将使用与挡板相同的技术来确定球的路径。当击中砖块时，我们需要找出哪块砖被触碰，然后将其从舞台和砖块组中移除。每移除一块砖，分数增加 100 分。分数将从`score`常数中取出，并作为文本添加到当前分数中。要移除游戏中的砖块，请按照以下步骤操作：

1.  在`gameLevel2()`函数下方，创建一个名为`removeBrick(event)`的函数：

    ```kt
    function removeBrick(event)
    ```

1.  使用`if`语句检查球击中砖块的哪一侧。在检查事件时，我们将事件引用到对象名称`"brick"`。这是我们给`brick`显示对象起的名字：

    ```kt
      if event.other.name == "brick" and ball.x + ball.width * 0.5 < event.other.x + event.other.width * 0.5 then
        vx = -vx 
      elseif event.other.name == "brick" and ball.x + ball.width * 0.5 >= event.other.x + event.other.width * 0.5 then
        vx = vx 
      end
    ```

1.  添加以下`if`语句，当球与砖块碰撞时，从场景中移除砖块。碰撞发生后，将`score`增加 1。将`scoreNum`初始化为取分数的值，并将其乘以`scoreIncrease`：

    ```kt
      if event.other.name == "brick" then
        vy = vy * -1
        event.other:removeSelf()
        event.other = nil
        bricks.numChildren = bricks.numChildren - 1

        score = score + 1
        scoreNum.text = score * scoreIncrease
        scoreNum.anchorX = 0
        scoreNum.x = 54 
      end
    ```

1.  当关卡中的所有砖块被摧毁时，创建一个`if`语句，弹出胜利条件的警告屏幕，并将`gameEvent`字符串设置为`"win"`；

    ```kt
      if bricks.numChildren < 0 then
        alertScreen("YOU WIN!", "Continue")
        gameEvent = "win"
      end
    ```

1.  使用`end`关闭函数：

    ```kt
    end
    ```

以下是球与挡板碰撞的截图：

![行动时间——移除砖块](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_04_02.jpg)

## *刚才发生了什么？*

如果你记得上一章的内容，我们给`brick`对象起了一个名为`"brick"`的名字。

当球击中砖块的左侧时，它会向左移动。当球击中砖块的右侧时，它会向右移动。每个对象的宽度被视为整体，以计算球移动的方向。

当砖块被击中时，球会向上弹起（即*y*方向）。球与每块砖碰撞后，砖块会从场景中移除，并从内存中销毁。

`bricks.numChildren – 1`语句从最初开始的总砖块数中减去计数。每当移除一块砖，分数增加 100 分。每当击中砖块时，`scoreNum`文本对象会更新分数。

当所有砖块都被移除时，警告屏幕会弹出通知玩家已经赢得关卡。我们还设置`gameEvent`等于`"win"`，这将在另一个函数中使用，以将事件过渡到新场景。

# 方向变化

除了球与挡板相对运动之外，另一个因素是球与墙壁边界的碰撞状态。当发生碰撞时，球会以相反的方向改变其移动方向。每个动作都有相应的反应，就像现实世界中的物理一样。

# 动作时间——更新球的位置

球需要以连续的运动移动，不受重力影响。我们需要考虑侧墙以及顶底墙壁。当球在任何边界上发生碰撞时，*x*和*y*方向的速度必须反射回来。我们需要设置坐标，以便球只能通过并在穿过挡板区域以下时发出警告。让我们执行以下步骤：

1.  在`removeBrick(event)`函数下方创建一个名为`function updateBall()`的新函数：

    ```kt
    function updateBall()
    ```

1.  添加球的移动：

    ```kt
      ball.x = ball.x + vx
      ball.y = ball.y + vy
    ```

1.  添加球在*x*方向上的移动：

    ```kt
      if ball.x < 0 or ball.x + ball.width > display.contentWidth then
        vx = -vx
      end
    ```

    下面的截图展示了球在*x*方向上的移动：

    ![动作时间——更新球的位置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_04_03.jpg)

1.  添加球在*y*方向上的移动：

    ```kt
      if ball.y < 0 then 
        vy = -vy 
      end
    ```

    下面的截图展示了球在*y*方向上的移动：

    ![动作时间——更新球的位置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_04_04.jpg)

1.  添加球与游戏屏幕底部碰撞时的移动。创建失败警告屏幕并设置一个`"lose"`的游戏事件。使用`end`结束函数：

    ```kt
      if ball.y + ball.height > paddle.y + paddle.height then 
        alertScreen("YOU LOSE!", "Play Again") gameEvent = "lose" 
      end
    end
    ```

    下面的截图显示了当球与游戏屏幕底部碰撞时出现的失败警告屏幕：

    ![动作时间——更新球的位置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_04_05.jpg)

## *刚才发生了什么？*

球移动的每个位置，当它撞击墙壁时都需要改变方向。每当球撞击侧墙，我们使用`vx = -vx`。当球撞击顶部边界时，使用`vy = -vy`。唯一球不会反射相反方向的情况是它撞击屏幕底部。

警告屏幕显示了失败条件，这强调了玩家需要再次游戏。`gameEvent = "lose"`的声明将在另一个`if`语句中使用，以重置当前关卡。

# 转换关卡

当出现胜利或失败的条件时，游戏需要一种方式来转换到下一个关卡或重复当前关卡。主要游戏对象必须被重置到起始位置，并且重新绘制砖块。这与游戏开始时的想法基本相同。

# 动作时间——重置和改变关卡

我们需要创建一些函数来设置游戏中的第一关和第二关。如果一个关卡需要重玩，只能访问用户在当前关卡中失败的那一关。以下是转换关卡之间的步骤：

1.  创建一个名为`changeLevel1()`的新函数。这将被放置在`updateBall()`函数下方：

    ```kt
    function changeLevel1()
    ```

1.  当玩家输掉一轮游戏时，清除`bricks`组，然后重置它们：

    ```kt
      bricks:removeSelf()

      bricks.numChildren = 0
      bricks = display.newGroup()
    ```

1.  移除`alertDisplayGroup`：

    ```kt
      alertBox:removeEventListener("tap", restart)
      alertDisplayGroup:removeSelf()
      alertDisplayGroup = nil
    ```

1.  重置`ball`和`paddle`的位置：

    ```kt
      ball.x = (display.contentWidth * 0.5) - (ball.width * 0.5)
      ball.y = (paddle.y - paddle.height) - (ball.height * 0.5) -2

      paddle.x = display.contentWidth * 0.5
    ```

1.  重新绘制当前关卡的砖块：

    ```kt
    gameLevel1()
    ```

1.  在`background`对象上添加一个`startGame()`的事件监听器，并结束此函数：

    ```kt
      background:addEventListener("tap", startGame)
    end
    ```

1.  接下来，创建一个名为`changeLevel2()`的新函数。应用与`changeLevel1()`相同的代码，但确保为`gameLevel2()`重绘砖块：

    ```kt
    function changeLevel2()

      bricks:removeSelf()

      bricks.numChildren = 0
      bricks = display.newGroup()

      alertBox:removeEventListener("tap", restart)
      alertDisplayGroup:removeSelf()
      alertDisplayGroup = nil

      ball.x = (display.contentWidth * 0.5) - (ball.width * 0.5)
      ball.y = (paddle.y - paddle.height) - (ball.height * 0.5) -2

      paddle.x = display.contentWidth * 0.5

     gameLevel2() -- Redraw bricks for level 2

      background:addEventListener("tap", startGame)
    end
    ```

## *刚才发生了什么？*

当需要重置或更改关卡时，必须从屏幕上清除显示对象。在这种情况下，我们使用`bricks:removeSelf()`移除了`bricks`组。

当任何提示屏幕弹出时，无论是赢还是输，整个`alertDisplayGroup`在重置时也会被移除。`ball`和`paddle`对象会被设置回起始位置。

`gameLevel1()`函数被调用，以重绘第一关的砖块。该函数负责`brick`显示对象和`bricks`组的初始设置。

`background`对象再次使用事件监听器调用`startGame()`函数。当需要设置第二关时，使用与`changeLevel1()`函数相同的程序，但是调用`changeLevel2()`和`gameLevel2()`来重绘砖块。

## 尝试英雄——添加更多关卡。

目前，游戏只有两个关卡。要扩展这个游戏，可以添加更多的关卡。它们可以使用与`gameLevel1()`和`gameLevel2()`相同的逻辑来创建，通过调整用于创建砖块行和列的数字。你需要创建一个新的函数来重置关卡。我们可以使用与`changeLevel1()`和`changeLevel2()`相同的方法来重新创建并重置关卡。

# 有赢就有输。

没有什么比期待胜利更令人兴奋了。直到你犯了一个小错误，导致你必须重新开始。别担心，这并不是世界末日；你总是可以再次尝试并从错误中学习，以打败这一关卡。

游戏事件，如胜负条件，会提示玩家他们的进度。游戏必须有某种方式指导玩家下一步需要采取什么行动来重玩关卡或进入下一关。

# 是时候制定胜负条件了。

为了让游戏中的任何提示出现，我们需要为每个关卡中可能出现的每一种情况创建一些`if`语句。当这种情况发生时，分数需要重置回零。要制定胜负条件，请按照以下步骤操作：

1.  在`alertScreen()`函数下面，创建一个名为`restart()`的新函数：

    ```kt
    function restart()
    ```

1.  为在完成第一关并过渡到第二关时创建一个游戏胜利的`if`语句：

    ```kt
      if gameEvent == "win" and currentLevel == 1 then
        currentLevel = currentLevel + 1
        changeLevel2()
        levelNum.text = tostring(currentLevel)
    ```

    ### 注意

    `tostring()`方法将任何参数转换为字符串。在前面示例中，当发生`"win"`游戏事件时，`currentLevel`的值从`1`变为`2`。该值将转换为字符串格式，以便`levelNum`文本对象可以在屏幕上显示第二关的数字。

1.  为在完成第二关时创建一个游戏胜利的`elseif`语句，并在通知玩家游戏已完成时：

    ```kt
      elseif gameEvent == "win" and currentLevel == 2 then
        alertScreen("  Game Over", "  Congratulations!")
        gameEvent = "completed"
    ```

1.  在第一级中为`"lose"`游戏事件添加另一个`elseif`语句。将分数重置为零，重新开始第一级：

    ```kt
      elseif gameEvent == "lose" and currentLevel == 1 then
        score = 0
        scoreNum.text = "0"
        changeLevel1()
    ```

1.  为第二级的`"lose"`游戏事件添加另一个`elseif`语句。将分数重置为零，重新开始第二级：

    ```kt
      elseif gameEvent == "lose" and currentLevel == 2 then
        score = 0
        scoreNum.text = "0"
        changeLevel2()
    ```

1.  最后，为`gameEvent = "completed"`添加另一个`elseif`语句。用`end`结束函数：

    ```kt
      elseif gameEvent == "completed" then
        alertBox:removeEventListener("tap", restart)
      end
    end
    ```

1.  现在，我们需要回溯并在`alertScreen()`函数中使用`alertBox`对象添加一个事件监听器。我们将它添加到函数底部。这将激活`restart()`函数：

    ```kt
      alertBox:addEventListener("tap", restart)
    ```

## *刚才发生了什么？*

`restart()`函数检查游戏过程中发生的所有`gameEvent`和`currentLevel`变量。当一个游戏事件检查到`"win"`字符串时，它也会继续执行下面的语句，看哪个为真。例如，如果玩家赢了且当前在第一级，那么玩家将进入第二级。

如果玩家输了，`gameEvent == "lose"`变为真，代码会检查玩家在哪个级别输掉。无论玩家在哪个级别输掉，分数都会重置为 0，并且玩家所在的当前级别将重新设置。

# 激活事件监听器

这个游戏中的事件监听器基本上控制了物体的运动开关。我们已经编写了执行游戏对象动作的函数来运行级别。现在是时候通过特定类型的事件来激活它们了。正如你在前一章注意到的，我们可以向显示对象添加事件监听器，或者让它们全局运行。

## 碰撞事件

物理引擎中的碰撞事件通过 Corona 的事件监听器模型发生。有三个新的事件类型，如下所示：

+   `"collision"`：此事件包括`"began"`和`"ended"`阶段，分别表示初次接触和接触断开时刻。这些阶段适用于正常的两物体碰撞和物体传感器碰撞。如果你没有实现`"collision"`监听器，此事件将不会触发。

+   `"preCollision"`：这是一个在物体开始交互之前触发的事件类型。根据你的游戏逻辑，你可能希望检测此事件并有条件地覆盖碰撞。它也可能导致每个接触点多次报告，影响应用程序的性能。

+   `"postCollision"`：这是一个在物体交互后立即触发的事件类型。这是唯一一个报告碰撞力的事件。如果你没有实现`"postCollision"`监听器，此事件将不会触发。

碰撞事件在对象对之间报告，可以通过运行时监听器全局检测，或者在对象内部使用表监听器本地检测。

### 全局碰撞监听器

当作为运行时事件检测时，每个碰撞事件包括`event.object1`，其中包含涉及到的 Corona 显示对象的表 ID。

这是一个例子：

```kt
local physics = require "physics"
physics.start()

local box1 = display.newImage( "box.png" )
physics.addBody( box1, "dynamic", { density = 1.0, friction = 0.3, bounce = 0.2 } )
box1.myName = "Box 1"

local box2 = display.newImage( "box.png", 0, 350)
physics.addBody( box2, "static", { density = 1.0, friction = 0.3, bounce = 0.2 } )
box2.myName = "Box 2"

local function onCollision( event )
  if event.phase == "began" and event.object1.myName == "Box 1" then

    print( "Collision made." )

  end
end

Runtime:addEventListener( "collision", onCollision )

```

### 本地碰撞监听器

当在对象内部使用表监听器检测时，每个碰撞事件都包括`event.other`，其中包含参与碰撞的另一个显示对象的表 ID。

这是一个示例：

```kt
local physics = require "physics"
physics.start()

local box1 = display.newImage( "box.png" )
physics.addBody( box1, "dynamic", { density = 1.0, friction = 0.3, bounce = 0.2 } )
box1.myName = "Box 1"

local box2 = display.newImage( "box.png", 0, 350)
physics.addBody( box2, "static", { density = 1.0, friction = 0.3, bounce = 0.2 } )
box2.myName = "Box 2"

local function onCollision( self, event )
  if event.phase == "began" and self.myName == "Box 1" then

    print( "Collision made." )

  end
end

box1.collision = onCollision
box1:addEventListener( "collision", box1 )

box2.collision = onCollision
box2:addEventListener( "collision", box2 )

```

# 行动时间——添加游戏监听器

对于我们为游戏对象创建的许多功能，我们需要激活事件监听器，以便它们能够运行代码，并在游戏停止时禁用它们。要添加游戏监听器，请按照以下步骤操作：

1.  为了完成这个游戏，我们需要创建的最后一个函数叫做`gameListeners()`，它还将有一个名为`event`的参数。这应该在`gameLevel2()`函数之后直接添加：

    ```kt
    function gameListeners(event)
    ```

1.  添加以下事件监听器，它们将使用`if`语句在应用程序中启动多个事件：

    ```kt
      if event == "add" then
        Runtime:addEventListener("accelerometer", movePaddle)
        Runtime:addEventListener("enterFrame", updateBall)
        paddle:addEventListener("collision", bounce)
        ball:addEventListener("collision", removeBrick)
        paddle:addEventListener("touch", dragPaddle)
    ```

1.  接下来，我们将为事件监听器添加一个`elseif`语句，以移除事件并关闭函数：

    ```kt
      elseif event == "remove" then
        Runtime:removeEventListener("accelerometer", movePaddle)
        Runtime:removeEventListener("enterFrame", updateBall)
        paddle:removeEventListener("collision", bounce)
        ball:removeEventListener("collision", removeBrick)
        paddle:removeEventListener("touch", dragPaddle)

      end
    end
    ```

1.  为了使`function gameListeners()`正常工作，我们需要在`startGame()`函数中使用参数中的`"add"`字符串对其进行实例化。将其放在函数末尾之前：

    ```kt
      gameListeners("add")
    ```

1.  在`alertScreen()`函数中，将`"remove"`字符串添加到参数中，并将其放在函数开始处：

    ```kt
      gameListeners("remove")
    ```

1.  所有代码都已经编写完成！继续在模拟器中运行游戏。该应用程序也适用于设备。为你正在开发的设备制作一个符合所需尺寸的简单图标图像。编译构建并在你的设备上运行。

## *刚才发生了什么？*

对于`event`参数，有两个`if`语句集：`"add"`和`"remove"`。

这个函数中的所有事件监听器在使游戏运行方面都起着重要作用。`"accelerometer"`和`"enterframe"`事件被用作运行时事件，因为它们没有特定的目标。

`挡板`和`球`对象都具有`"collision"`事件，在任何对象接触时都会执行其功能。

`"touch"`事件允许用户触摸并拖动挡板，使其在模拟器中来回移动。

请注意，当`event == "remove"`时，它会移除游戏中所有活动的事件监听器。当游戏开始时，`gameListeners("add")`会被激活。当达到胜利或失败条件时，`gameListeners("remove")`会被激活。

## 尝试一下吧——让我们将一切颠倒过来

如果我们决定将游戏上下颠倒，也就是说，将挡板放置在屏幕顶部附近，球在挡板下方，砖块组靠近屏幕底部，该怎么办？

你需要考虑的事情如下：

+   现在顶部墙壁是你必须防止球进入的区域

+   当球与砖块碰撞时，*y*方向是球移动的方向

+   当球与底部墙壁碰撞时，它必须从底部墙壁反射回来

如你所见，在将值从负数切换到正数以及反之之前，有一些事情需要考虑。在创建这个新变体时，请确保验证你的逻辑，并确保它是有意义的。

# 结果出来了！

让我们总结一下你所做的工作，确保你的游戏中已经包含了所有内容。你也可以参考`Chapter 4`文件夹中的`Breakout Final`文件夹，查看最终的代码。你确保了在游戏中引入了必要的变量。你还初始化了启动游戏玩的`main()`函数。实现了一个主菜单屏幕，带有游戏标题和一个播放按钮。

接下来，你将`menuScreenGroup`从屏幕上移开，加载主游戏区域。添加了游戏的主要显示对象，如挡板、球和砖块。分数和关卡数作为 UI 元素显示并在游戏过程中更新。还添加了模拟器和加速度计中的挡板移动以及挡板和球的碰撞检测。

在游戏开始时添加了挡板和球的物理属性。为两个关卡创建了砖块布局。你还在游戏对象需要激活时添加了事件监听器，并在游戏结束时移除。

每当球与砖块碰撞，砖块就会从场景中移除。球的方向变化在每次与墙壁、挡板或砖块碰撞后都会更新。每当出现赢或输的条件时，所有游戏对象都会重置，以便开始当前或新关卡。

当发生某个条件时，会弹出一个警告屏幕，通知玩家发生了什么。触发警告的显示对象是在一个函数中创建的。最后，创建了赢和输的参数，以确定是否需要重玩当前关卡，玩家是否进入下一关，或者游戏是否已经完成。

注意大小写敏感的变量和函数，以免遇到错误。同时，确保你没有遗漏代码中所需的标点符号。这些容易被忽视。如果在模拟器中遇到错误，请参考终端窗口中的错误引用。

## 小测验——使用游戏控制

Q1. 你应该如何正确地从舞台中移除一个显示对象？

1.  `remove()`

1.  `object: remove()`

1.  `object:removeSelf()`

    `object = nil`

1.  以上都不是。

Q2. 将以下显示对象转换为物理对象正确的方法是什么？

```kt
local ball = display.newImage("ball.png")
```

1.  `physics.addBody( ball, { density=2.0, friction=0.5, bounce=0.2,radius = 25 })`

1.  `physics.addBody( ball, "dynamic", { density=2.0, friction=0.5, bounce=0.2,radius = 15 } )`

1.  `1and 2`.（这一行似乎不完整，但按照要求保留原文）

1.  以上都不是。

Q3. 在以下函数中，`"began"`一词的最佳解释是什么？

```kt
local function onCollision( event )
  if event.phase == "began" and event.object1.myName == "Box 1" then

    print( "Collision made." )

  end
end
```

1.  手指在屏幕上移动。

1.  一个手指从屏幕上抬起。

1.  系统取消了开始触摸的跟踪。

1.  一个手指触摸了屏幕。

# 总结

恭喜你！你已经完成了你的第一个游戏制作！你应当为自己感到非常骄傲。现在，你已经体验到了使用 Corona SDK 制作应用程序有多么简单。只需几百行代码就能制作一个应用程序。

在本章中，我们完成了以下工作：

+   为挡板添加了触摸事件移动

+   引入了加速度计功能

+   为所有受影响的游戏对象实现了碰撞事件监听器

+   当游戏屏幕不再需要对象时，从内存中移除它们

+   将球的移动实现为物理对象

+   更新了每次砖块碰撞的计分板

+   学习了如何处理胜利和失败的条件

最后两章并没有那么糟糕，不是吗？随着你继续使用 Lua 编程，你会越来越熟悉工作流程。只要你不断进步并与不同的游戏框架合作，理解起来肯定会更加容易。

下一章将介绍另一个肯定会吸引你注意的游戏。你将为你的显示对象创建动画精灵表。这对视觉来说是不是很棒？


# 第五章：动画我们的游戏

> *在我们移动游戏开发的旅程中，我们已经开始了很好的起步。我们已经经历了大量的编程，从游戏逻辑到在屏幕上显示对象。Corona SDK 最强大的功能之一就是任何显示对象都可以被动画化。这是对 Corona 提供的灵活图形模型的证明。*
> 
> *动画为游戏中的用户体验增添了大量的角色。这是通过生成一系列帧来实现的，这些帧从一帧平滑地演变到下一帧。我们将学习这项技能并将其应用于将要创建的新游戏。*

在本章中，我们将：

+   使用动作和过渡进行操作

+   使用图像表进行动画

+   为显示对象创建一个游戏循环

+   构建我们的下一个游戏框架

让我们开始动画吧！

# 熊猫星星捕手

本节将创建我们的第二个游戏，名为熊猫星星捕手。主要角色是一只名叫玲玲的熊猫，它需要被发射到空中，并在计时器耗尽之前捕捉尽可能多的星星。熊猫将会有动画效果，每个行动过程都有不同的动作，例如发射前的设置和空中的动作。还将应用弹弓机制将玲玲发射到空中。你可能已经在如*愤怒的小鸟*和*城堡破坏者*之类的游戏中见过类似的功能。

# 让我们来让一切动起来

我们在第三章中介绍了过渡，并简要地接触了它。让我们更详细地了解。

## 过渡效果

过渡库允许你通过一行代码创建动画，通过允许你补间显示对象的一个或多个属性。我们在第三章中讨论了过渡的基础，*创建我们的第一个游戏 - 破坏者*。

这可以通过`transition.to`方法实现，它接收一个显示对象和一个包含控制参数的表。控制参数指定动画的持续时间以及显示对象的属性的最终值。属性的中间值由可选的缓动函数确定，该函数也作为控制参数指定。

`transition.to()` 方法使用“缓动”算法，随时间动画显示对象的属性。

语法是 `handle = transition.to( target, params )`。

返回函数是一个对象。参数如下：

+   `target`：这是一个将成为过渡目标的对象。这包括显示对象。

+   `params`：这是一个指定要动画显示对象的属性的表，以及以下一个或多个可选的非动画属性：

    +   `params.time`：这指定了过渡的持续时间（以毫秒为单位）。默认情况下，持续时间为 500 毫秒（0.5 秒）。

    +   `params.transition`: 默认情况下，此参数为 `easing.linear`。

    +   `params.delay`: 此参数指定了补间动画开始前的延迟时间（默认为无延迟），单位为毫秒。

    +   `params.delta`: 这是一个布尔值，指定非控制参数是作为最终结束值还是作为值的改变量来解释。默认为 `nil`，即 false。

    +   `params.onStart`: 这是一个在补间动画开始前调用的函数或表监听器。

    +   `params.onComplete`: 这是一个在补间动画完成后调用的函数或表监听器。

## 缓动函数

缓动库是过渡库使用的一系列插值函数的集合。例如，打开抽屉的动作，最初是快速移动，然后在停止之前进行缓慢精确的移动。以下是几个缓动示例：

+   `easing.linear(t, tMax, start, delta)`: 此函数定义了一个没有加速度的恒定运动

+   `easing.inQuad(t, tMax, start, delta)`: 此函数在过渡中对动画属性值进行二次插值运算

+   `easing.outQuad(t, tMax, start, delta)`: 此函数一开始速度很快，然后在执行过程中减速至零速度

+   `easing.inOutQuad(t, tMax, start, delta)`: 此函数从零速度开始动画，加速然后减速至零速度

+   `easing.inExpo(t, tMax, start, delta)`: 此函数从零速度开始，然后在执行过程中逐渐加速

+   `easing.outExpo(t, tMax, start, delta)`: 此函数一开始速度很快，然后在执行过程中减速至零速度

+   `easing.inOutExpo(t, tMax, start, delta)`: 此函数从零速度开始，使用指数缓动方程加速然后减速至零速度

你可以创建自己的缓动函数来在起始值和最终值之间插值。函数的参数定义如下：

+   `t`: 这是过渡开始后的毫秒数时间

+   `tMax`: 这是过渡的持续时间

+   `start`: 这是起始值

+   `delta`: 这是值的改变量（最终值 = `start` + `delta`）

例如：

```kt
local square = display.newRect( 0, 0, 50, 50 )
square:setFillColor( 1,1,1 )
square.x = 50; square.y = 100

local square2 = display.newRect( 0, 0, 50, 50 )
square2:setFillColor( 1,1,1 )
square2.x = 50; square2.y = 300

transition.to( square, { time=1500, x=250, y=0 } )
transition.from( square2, { time=1500, x=250, y=0, transition = easing.outExpo } )
```

# 定时函数的价值

使用可以在稍后调用的函数，在组织应用程序中游戏对象出现的时间时可能很有帮助。定时器库将允许我们及时处理函数。

## 定时器

定时器函数使你能够选择一个特定的延迟（以毫秒为单位）来触发事件。

+   `timer.performWithDelay(delay, listener [, iterations])`: 此函数在指定的延迟毫秒数后调用监听器，并返回一个句柄对象，你可以通过传递给 `timer.cancel()` 来取消定时器，防止在调用监听器之前触发。例如：

    ```kt
    local function myEvent()
      print( "myEvent called" )
    end
    timer.performWithDelay( 1000, myEvent )
    ```

+   `timer.cancel(timerId)`: 这取消了使用 `timer.performWithDelay()` 初始化的定时器操作。参数如下：

    +   `timerId`: 这是通过调用 `timer.performWithDelay()` 返回的对象句柄。例如：

        ```kt
        local count = 0

        local function myEvent()
          count = count + 1
          print( count )

          if count >= 3 then
            timer.cancel( myTimerID ) -- Cancels myTimerID
            end
          end
        ```

+   `timer.pause(timerId)`: 这将暂停使用`timer.performWithDelay()`启动的定时器对象。参数如下：

    +   `timerId`: 这是来自`timer.performWithDelay()`的定时器 ID 对象。例如：

        ```kt
        local count = 0

        local function myEvent()
          count = count + 1
          print( count )

          if count >= 5 then
            timer.pause( myTimerID ) -- Pauses myTimerID
            end
        end

        myTimerID = timer.performWithDelay(1000, myEvent, 0)
        ```

+   `timer.resume(timerId)`: 这将恢复使用`timer.pause(timerId)`暂停的定时器。参数如下：

    +   `timerID`: 这是来自`timer.performWithDelay()`的定时器 ID。例如：

        ```kt
        local function myEvent()
          print( "myEvent called" )
        end

        myTimerID = timer.performWithDelay( 3000, myEvent )  -- wait 3 seconds

        result = timer.pause( myTimerID ) -- Pauses myTimerID
        print( "Time paused at " .. result )

        result = timer.resume( myTimerID ) -- Resumes myTimerID
        print( "Time resumed at " .. result )
        ```

# 什么是图像表？

Corona SDK 包括一个图像表功能，用于构建动画精灵（也称为精灵表）。

### 注意

有关图像表的更多信息，请参考以下链接：[`docs.coronalabs.com/guide/media/imageSheets/index.html`](http://docs.coronalabs.com/guide/media/imageSheets/index.html)。

图像表是节省纹理内存的有效方式。建议在复杂的角色动画或涉及大量动画类型时使用。

图像表需要更多的编码和更高级的设置。它们需要构建一个大型动画帧表。

# 这是精灵狂热！

图像表是将多个帧编译成单个纹理图像的 2D 动画。这是一种节省纹理内存的有效方式。它对移动设备有益，并最小化加载时间。

## 图像表 API

`graphics.newImageSheet`函数创建一个新的图像表。参考以下代码：

```kt
graphics.newImageSheet( filename, [baseDir, ] options )
```

例如，图像表中的帧数假定为`floor(imageWidth/frameWidth) * floor(imageHeight/frameHeight)`。第一帧放置在左上角位置，从左到右读取，并在适用的情况下继续下一行。以下图像表有五个 128 x 128 像素的帧。整个图像表图像是 384 像素 x 256 像素。如果要在 Corona 中集成，一个示例方法将如下所示：

```kt
local options =
{
  width = 128,
  height = 128,
  numFrames = 5,
  sheetContentWidth=384, 
  sheetContentHeight=256
}
local sheet = graphics.newImageSheet( "mySheet.png", options )
```

![图像表 API](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_01.jpg)

`display.newSprite(imageSheet, sequenceData)`函数从一个图像表中创建一个新的精灵。精灵定义了属于同一个角色或其他移动资产的帧集合，然后可以将其细分为不同的动画序列以供播放。`sequenceData`参数是你设置的一系列动画序列数组。序列可以在多个精灵对象之间共享。以下是一些示例：

+   单序列（连续帧）：

    ```kt
    local sequenceData =
    {
      name="run", start=1, count=5, time=200, loopCount=0
    }

    local myCharacter = display.newSprite(imageSheet, sequenceData)
    ```

+   单序列（非连续帧）：

    ```kt
    local sequenceData =
    {
      name="jump", 
      frames= { 6, 7, 8 }, 
      time=200,
      loopCount=0
    }

    local myCharacter = display.newSprite(imageSheet, sequenceData)
    ```

+   多序列（连续和非连续帧）：

    ```kt
    local sequenceData =
    {
      { name="run", start=1, count=5, time=200 },
      {name="jump", frames= { 6, 7, 8 }, time=200, loopCount=0 }
    }

    local myCharacter = display.newSprite(imageSheet, sequenceData)
    ```

+   `object:pause()`: 这将暂停当前动画。帧将保持在当前显示的帧。

+   `object:play()`: 这将从当前帧开始播放动画序列。

+   `object:setFrame()`: 这在当前加载的序列中设置帧。

+   `object:setSequence()`: 这通过名称加载一个动画序列。

# 游戏时间！

既然我们已经学会了如何设置图像表，那么让我们尝试将它们应用到`Panda Star Catcher`中！你可以从 Packt Publishing 网站下载伴随这本书的项目文件。在`Chapter 5`文件夹中有一个名为`Panda Star Catcher`的项目文件夹。它已经为你设置了`config.lua`和`build.settings`文件。文件夹中还包括了美术资源。从第三章，*构建我们的第一个游戏——Breakout*和第四章，*游戏控制*，你可能已经注意到构建和运行时的配置有类似的设置。本教程适用于 iOS 和 Android 设备。项目文件夹中包含的图形已经设计好，可以在两个平台上正确显示。游戏的欢迎屏幕将如下所示：

![游戏时间！](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_02.jpg)

# 动手时间——设置变量

让我们先介绍运行游戏所需的所有变量：

1.  创建一个全新的`main.lua`文件，并将其添加到`Panda Star Catcher`项目文件夹中。

1.  让我们从设备上隐藏状态栏，并设置游戏中所需的所有变量：

    ```kt
    display.setStatusBar( display.HiddenStatusBar ) -- Hides the status bar in iOS only

    -- Display groups
    local hudGroup = display.newGroup() -- Displays the HUD
    local gameGroup = display.newGroup()
    local levelGroup = display.newGroup()
    local stars = display.newGroup() -- Displays the stars

    -- Modules
    local physics = require ("physics")

    local mCeil = math.ceil
    local mAtan2 = math.atan2
    local mPi = math.pi
    local mSqrt = math.sqrt

    -- Game Objects
    local background
    local ground
    local powerShot
    local arrow
    local panda
    local poof
    local starGone
    local scoreText
    local gameOverDisplay

    -- Variables
    local gameIsActive = false
    local waitingForNewRound
    local restartTimer
    local counter
    local timerInfo 
    local numSeconds = 30 -- Time the round starts at
    local counterSize = 50
    local gameScore = 0 -- Round starts at a score of 0
    local starWidth = 30
    local starHeight = 30
    ```

## *刚才发生了什么？*

在应用程序开始时，我们隐藏了状态栏。这仅适用于 iOS 设备。有四个不同的组设置，它们在游戏中都扮演着重要的角色。

注意`gameIsActive`设置为`false`。这使我们能够激活应用程序的属性，以便在显示对象需要停止动画、出现在屏幕上并受触摸事件影响时影响回合。

代码开始部分也设置了计时器的元素。将`numSeconds`设置为`30`表示回合将倒计时多少秒。`starWidth`和`starHeight`描述了对象的尺寸。

# 让我们开始这一轮

在游戏屏幕上的熊猫发射之前，我们需要先加载熊猫。熊猫将从屏幕底部过渡并在屏幕上移，然后才能发生触摸事件。

# 动手时间——开始游戏

现在，我们需要为熊猫设置一个屏幕外的位置，并让它过渡到起始发射位置，以便用户可以与之互动。

1.  添加变量后，创建一个名为`startNewRound()`的新局部函数，并添加一个`if`语句来初始化`panda`对象进入场景：

    ```kt
    local startNewRound = function()
      if panda then
    ```

1.  在`startNewRound()`内添加一个名为`activateRound()`的新局部函数。设置屏幕上`panda`显示对象的起始位置，并添加`ground:toFront()`，使地面出现在熊猫角色前面：

    ```kt
      local activateRound = function()

        waitingForNewRound = false

        if restartTimer then
          timer.cancel( restartTimer )
        end

        ground:toFront()
        panda.x = 240
        panda.y = 300
        panda.rotation = 0
        panda.isVisible = true
    ```

1.  创建另一个名为`pandaLoaded()`的局部函数。将`gameIsActive`设置为`true`，并将`panda`对象的空气和击打属性设置为`false`。添加`panda:toFront()`，使其在屏幕上所有其他游戏对象的前面，并将身体类型设置为`"static"`：

    ```kt
        local pandaLoaded = function()

          gameIsActive = true
          panda.inAir = false
          panda.isHit = false
          panda:toFront()

          panda.bodyType = "static"

        end
    ```

1.  在 1,000 毫秒内将熊猫过渡到`y=225`。当补间动画完成后，使用`onComplete`命令调用`pandaLoaded()`函数。使用`end`关闭`activateRound()`函数，并调用它。关闭`panda`的`if`语句和`startNewRound()`函数，使用`end`：

    ```kt
        transition.to( panda, { time=1000, y=225, onComplete=pandaLoaded } )
        end

        activateRound()

      end
    end
    ```

    ![行动时间——开始游戏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_03.jpg)

## *刚才发生了什么？*

当关卡被激活时，熊猫被放置在地面以下，在玩家可见之前。对于`pandaLoaded()`，游戏通过`gameIsActive = true`激活，熊猫准备好被玩家发射。熊猫从地面过渡到屏幕上可以被访问的区域。

# 嘭！消失了！

在一轮结束后，熊猫需要从舞台上消失。我们不是让它消失在空气中，而是当它与屏幕上的任何物体发生碰撞时，添加一个“poof”效果。

# 行动时间——在舞台上重新加载熊猫

当熊猫在空中停留一定时间或碰到屏幕外的任何边界区域时，它将变成一股烟雾。当与屏幕边缘或地面发生碰撞事件时，熊猫将被“poof”图像替换。为了使“poof”效果起作用，必须关闭熊猫的可见属性。当发生碰撞后，需要将熊猫重新加载到屏幕上，同时游戏仍然激活。

1.  创建一个名为`callNewRound()`的局部函数。包括一个名为`isGameOver`的局部变量，并将其设置为`false`：

    ```kt
    local callNewRound = function()
      local isGameOver = false
    ```

1.  在当前函数内，创建一个名为`pandaGone()`的新局部函数。为熊猫添加新属性，使其不再在游戏舞台上显示：

    ```kt
      local pandaGone = function()

        panda:setLinearVelocity( 0, 0 )
        panda.bodyType = "static"
        panda.isVisible = false
        panda.rotation = 0

        poof.x = panda.x; poof.y = panda.y
        poof.alpha = 0
        poof.isVisible = true
    ```

1.  为`poof`对象添加一个名为`fadePoof()`的新函数。使用`onComplete`命令，设置`time`为`50`和`alpha`为`1`进行过渡。让`poof`对象在`time`设置为`100`和`alpha`设置为`0`时淡出。关闭`pandaGone()`函数，并使用`timer.performWithDelay`调用它：

    ```kt
        local fadePoof = function()
           transition.to( poof, { time=100, alpha=0 } )
        end
        transition.to( poof, { time=50, alpha=1.0, onComplete=fadePoof } )

        restartTimer = timer.performWithDelay( 300, function()
           waitingForNewRound = true; 
           end, 1)

      end

      local poofTimer = timer.performWithDelay( 500, pandaGone, 1 )
    ```

1.  当`isGameOver`仍为`false`时，为`startNewRound()`添加`timer.performWithDelay`方法。关闭`callNewRound()`函数：

    ```kt
      if isGameOver == false then
        restartTimer = timer.performWithDelay(1500, startNewRound, 1)
      end
    end
    ```

## *刚才发生了什么？*

当熊猫不再在屏幕上显示且倒计时仍在进行时，将开始新一轮。当`isGameOver`仍为`false`时，通过调用`startNewRound()`重新加载熊猫。

熊猫碰撞通过`pandaGone()`发生。通过应用`panda.isVisible = false`，所有物理属性都变为不活跃。

烟雾正好在熊猫消失的地方出现。当`poof.x = panda.x; poof.y = panda.y`时，会发生这种情况。通过`fadePoof()`，`poof`短暂可见。一旦它淡出，新一轮即将到来，将`waitingForNewRound`设置为`true`。

# 赚取一些分数

当熊猫捕捉到天空中的任何星星时，都会获得分数。游戏是在计时器上进行的，所以玩家的任务是尽可能在时间耗尽前捕捉更多星星。让我们积累一些分数吧！

# 行动时间——跟踪分数

分数通过名为`scoreNum`的参数更新，并在游戏进行时显示。分数是通过`gameScore`接收的。

1.  下一个要创建的函数名为`setScore`，带有一个名为`scoreNum`的参数：

    ```kt
    local setScore = function( scoreNum )
    ```

1.  使用名为`newScore`的局部变量并将其设置为`scoreNum`。设置`gameScore = newScore`。为`gameScore`提供一个`if`语句，以便在游戏进行时将分数设置为 0：

    ```kt
      local newScore = scoreNum
      gameScore = newScore

      if gameScore < 0 then gameScore = 0; end
    ```

1.  添加`scoreText`显示对象，并将其设置为等于`gameScore`。关闭函数：

    ```kt
      scoreText.text = gameScore
      scoreText.xScale = 0.5; scoreText.yScale = 0.5
      scoreText.x = (480 - (scoreText.contentWidth * 0.5)) - 15
      scoreText.y = 20
    end
    ```

## *刚才发生了什么？*

对于`setScore = function(scoreNum)`函数，我们设置了一个名为`scoreNum`的参数。`scoreNum`参数会通过`local newScore`持续更新游戏分数。`newScore`将通过`gameScore`更新，这是计分的基础。同时，在游戏中，`scoreText`会显示`gameScore`的值。

# 当游戏结束时

这场游戏没有输家，每个人都是赢家！在计时器耗尽前，尽可能多地收集星星，你的肾上腺素仍会激增。当一切结束时，我们还需要通知大家时间已到。

# 行动时间——显示游戏结束屏幕

我们需要设置游戏结束屏幕，并在本回合结束时显示玩家获得的最终得分：

1.  创建一个名为`callGameOver()`的新局部函数：

    ```kt
    local callGameOver = function()
    ```

1.  将`gameIsActive`设置为`false`并暂停物理引擎。从舞台中移除`panda`和`stars`对象：

    ```kt
      gameIsActive = false
      physics.pause()

      panda:removeSelf()
      panda = nil
      stars:removeSelf()
      stars = nil
    ```

1.  显示游戏结束对象并将它们插入到`hudGroup`组中。使用`transition.to`方法在屏幕上显示游戏结束对象：

    ```kt
      local shade = display.newRect( 0, 0, 480, 320 )
      shade:setFillColor( 0, 0, 0, 0.5)
      shade.x = display.contentCenterX
      shade.y = display.contentCenterY

      gameOverDisplay = display.newImage( "gameOverScreen.png")
      gameOverDisplay.x = 240; gameOverDisplay.y = 160
      gameOverDisplay.alpha = 0

      hudGroup:insert( shade )
      hudGroup:insert( gameOverDisplay )

      transition.to( shade, { time=200 } )
      transition.to( gameOverDisplay, { time=500, alpha=1 } )
    ```

1.  使用名为`newScore`的局部变量更新最终得分。将`counter`和`scoreText`的`isVisible`设置为`false`。再次引入`scoreText`以在设备屏幕的另一位置显示最终得分。关闭函数：

    ```kt
      local newScore = gameScore
      setScore( newScore )

      counter.isVisible = false

      scoreText.isVisible = false
      scoreText.text = "Score: " .. gameScore
      scoreText.xScale = 0.5; scoreText.yScale = 0.5
      scoreText.x = 280
      scoreText.y = 160
      scoreText:toFront()
      timer.performWithDelay( 1000, function() scoreText.isVisible = true; end, 1 )

    end
    ```

    ![行动时间——显示游戏结束屏幕](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_04.jpg)

## *刚才发生了什么？*

当时间耗尽或所有星星被收集时，`callGameOver()`方法会显示游戏结束屏幕。我们将`gameIsActive`设置为`false`并暂停所有物理效果，这样熊猫就不能通过任何屏幕触摸来移动了。然后从场景中移除熊猫和星星。通过`transition.to`使`shade`和`gameOverDisplay`对象可见，这样它就会通知玩家本回合已经结束。最终得分将在回合结束时在`gameOverDisplay`对象前显示。

# 背景展示

熊猫在游戏中需要一个关于其所在位置的通用设置。让我们设置背景和地面对象。

# 行动时间——添加背景元素

1.  将 `background` 和 `ground` 显示对象添加到 `drawBackground()` 函数中。将这些对象插入到名为 `gameGroup` 的组中：

    ```kt
    local drawBackground = function()

      background = display.newImage( "background.png" )
      background.x = 240; background.y = 160

      gameGroup:insert( background )

      ground = display.newImage( "ground.png" )
      ground.x = 240; ground.y = 300

      local groundShape = { -240,-18, 240,-18, 240,18, -240,18 }
      physics.addBody( ground, "static", { density=1.0, bounce=0, friction=0.5, shape=groundShape } )

      gameGroup:insert( ground )

    end
    ```

## *刚才发生了什么？*

`background` 和 `ground` 显示对象被放置在 `drawBackground()` 函数中。`ground` 对象有一个自定义的物理形状，它的大小与原始显示对象不同。所以如果熊猫碰巧撞到地面，它会与之碰撞，但不会穿过。

# 注意！

在游戏开始之前，我们需要了解如何操作游戏控制。幸运的是，我们将添加一个帮助屏幕，解释如何进行游戏。还需要显示**抬头显示**（**HUD**），以便玩家了解剩余时间以及他们积累了多少分。

# 行动时间——显示计时器和得分

让我们设置在游戏中需要显示的帮助屏幕和 HUD 元素：

1.  创建一个名为 `hud()` 的新本地函数：

    ```kt
    local hud = function()
    ```

1.  在游戏开始时显示 `helpText` 10 秒钟。通过向左滑动并设置可见性为 `false` 来过渡它。将 `helpText` 添加到 `hudGroup` 组中：

    ```kt
      local helpText = display.newImage("help.png")
      helpText.x = 240; helpText.y = 160
      helpText.isVisible = true
      hudGroup:insert( helpText )

      timer.performWithDelay( 10000, function() helpText.isVisible = false; end, 1 )

      transition.to( helpText, { delay=9000, time=1000, x=-320, transition=easing.inOutExpo })
    ```

1.  在屏幕顶部附近显示 `counter` 和 `scoreText`。也将 `scoreText` 添加到 `hudGroup` 组中。使用 `end` 结束函数：

    ```kt
      counter = display.newText( "Time: " .. tostring(numSeconds), 0, 0, "Helvetica-Bold", counterSize )
      counter:setFillColor( 1, 1, 1 )
      counter.xScale = 0.5; counter.yScale = 0.5
      counter.x = 60; counter.y = 15 
      counter.alpha = 0

      transition.to( counter, { delay=9000, time=1000, alpha=1, transition=easing.inOutExpo })

      hudGroup:insert( counter )

      scoreText = display.newText( "0", 470, 22, "Helvetica-Bold", 52 )
      scoreText: setFillColor( 1, 1, 1 )--> white
      scoreText.text = gameScore
      scoreText.xScale = 0.5; scoreText.yScale = 0.5
      scoreText.x = (480 - (scoreText.contentWidth * 0.5)) - 15
      scoreText.y = 15
      scoreText.alpha = 0

      transition.to( scoreText, { delay=9000, time=1000, alpha=1, transition=easing.inOutExpo })

      hudGroup:insert( scoreText )

    end
    ```

## *刚才发生了什么？*

`helpText` 对象在游戏开始前出现，并在主设备显示上停留 9 秒钟，然后在 1 秒内沿 *x* 方向过渡到 -320。这是通过 `transition.to( helpText, { delay=9000, time=1000, x=-320, transition=easing.inOutExpo })` 实现的。

`counter` 对象显示 `"Time: " .. tostring(numSeconds)`，其中 `numSeconds` 表示从 30 开始倒数的秒数。它位于屏幕左上角附近。

`scoreText` 对象显示 `gameScore`，并且每次星星碰撞都会更新。这将被放置在屏幕的右上角。`local hud = function()` 中的所有对象都插入到 `hudGroup` 中。

# 一次又一次

这个游戏有一个定时器，玩家需要在它用完之前尽可能多地捕捉星星。我们将在帮助文本离开舞台后立即开始倒计时。

# 行动时间——设置定时器

我们需要创建几个函数，激活倒计时并在游戏结束时停止在 0 秒：

1.  使用名为 `myTimer()` 的本地函数为游戏设置定时器倒计时：

    ```kt
    local myTimer = function()
    ```

1.  将定时器倒计时的秒数增加 1。使用 `counter` 文本对象，通过 `numSeconds` 显示时间。在终端窗口中输出 `numSeconds` 来查看倒计时：

    ```kt
      numSeconds = numSeconds - 1
      counter.text = "Time: " .. tostring( numSeconds )
      print(numSeconds)
    ```

1.  创建一个 `if` 语句，用于当定时器用完或所有星星消失时。在块内，取消定时器并调用 `callGameOver()` 来结束这一轮。使用 `end` 结束 `myTimer()` 函数。

    ```kt
      if numSeconds < 1 or stars.numChildren <= 0 then
        timer.cancel(timerInfo)
        panda:pause()
        restartTimer = timer.performWithDelay( 300, function() callGameOver(); end, 1 )
      end

    end
    ```

1.  使用名为`startTimer()`的新局部函数启动`myTimer()`函数。这将开始游戏玩法开始时的倒计时：

    ```kt
    local startTimer = function()
      print("Start Timer")
      timerInfo = timer.performWithDelay( 1000, myTimer, 0 )
    end
    ```

## *刚才发生了什么？*

主要的计时器函数在`myTimer()`中。我们使用`numSeconds = numSeconds – 1`来倒数秒数。秒数将在`counter`显示对象中更新。`print(numSeconds)`将在终端窗口中更新，以查看倒计时在代码内部运行的速度。

当时间耗尽或所有星星都被收集时，将创建一个`if`语句来检查是否有任何参数为真。当任何语句评估为真时，计时器停止倒数，熊猫动画暂停，并调用`callGameOver()`函数。这将调用显示游戏结束屏幕的函数。

计时器通过`local startTimer = function()`以每 1,000 毫秒的速度启动倒计时，这相当于 1 秒。

# 它如此发光

熊猫需要另一个元素来显示发射它到天空所需的力量。我们将添加一个微妙的类似发光的显示对象来表示这一点。

# 动作时间——制作能量射击

我们需要为`powerShot`创建一个单独的函数，以便在熊猫准备发射时调用：

1.  通过名为`createPowerShot()`的新局部函数显示`powerShot`对象。将其插入到`gameGroup`组中：

    ```kt
    local createPowerShot = function()
      powerShot = display.newImage( "glow.png" )
      powerShot.xScale = 1.0; powerShot.yScale = 1.0
      powerShot.isVisible = false

      gameGroup:insert( powerShot )
    end
    ```

## *刚才发生了什么？*

通过`createPowerShot()`函数创建`powerShot`对象，并在熊猫准备发射时调用。

# 熊猫！

在屏幕上看到动画的东西将会很激动人心。我们的主角将为游戏玩法中应用的每个动作指定动画。

# 动作时间——创建熊猫角色

我们需要设置熊猫的碰撞事件，并相应地为其设置动画，使用图像表：

1.  我们需要创建一个局部函数来处理熊猫的碰撞和触摸事件。我们将它称为`createPanda()`：

    ```kt
    local createPanda = function()
    ```

1.  当熊猫与星星碰撞时，使用带有参数`self`和`event`的`onPandaCollision()`。每次与星星或屏幕边缘发生碰撞时，使用`callNewRound()`重新加载`panda`：

    ```kt
      local onPandaCollision = function( self, event )
        if event.phase == "began" then

          if panda.isHit == false then

            panda.isHit = true

            if event.other.myName == "star" then
              callNewRound( true, "yes" )
            else
              callNewRound( true, "no" )
            end

            if event.other.myName == "wall" then
              callNewRound( true, "yes" )
            else
              callNewRound( true, "no" )
            end

            elseif panda.isHit then
              return true
            end
        end
      end
    ```

1.  创建一个方向箭头，允许用户瞄准发射熊猫的区域。将其插入到`gameGroup`组中：

    ```kt
      arrow = display.newImage( "arrow.png" )
      arrow.x = 240; arrow.y = 225
      arrow.isVisible = false

      gameGroup:insert( arrow )
    ```

1.  创建一个具有三种不同动画序列（称为`"set"`、`"crouch"`和`"air"`）的熊猫图像表：

    ```kt
      local sheetData = { width=128, height=128, numFrames=5, sheetContentWidth=384, sheetContentHeight=256 }
      local sheet = graphics.newImageSheet( "pandaSprite.png", sheetData )

      local sequenceData = 
      {
        { name="set", start=1, count=2, time=200 }, 
        { name="crouch", start=3, count= 1, time=1 }, 
        { name="air", start=4, count=2, time=100 }  
      }

      panda = display.newSprite( sheet, sequenceData )

      panda:setSequence("set")
      panda:play()
    ```

1.  在熊猫发射到空中之前，为其添加以下属性：

    ```kt
      panda.x = 240; panda.y = 225
      panda.isVisible = false

      panda.isReady = false
      panda.inAir = false
      panda.isHit = false
      panda.isBullet = true
      panda.trailNum = 0

      panda.radius = 12
      physics.addBody( panda, "static", { density=1.0, bounce=0.4, friction=0.15, radius=panda.radius } )
      panda.rotation = 0
    ```

1.  使用`"collision"`为`panda`设置碰撞，并应用事件监听器：

    ```kt
      panda.collision = onPandaCollision
      panda:addEventListener( "collision", panda )
    ```

1.  创建`poof`对象：

    ```kt
      poof = display.newImage( "poof.png" )
      poof.alpha = 1.0
      poof.isVisible = false
    ```

1.  将`panda`和`poof`对象插入到`gameGroup`组中。关闭函数：

    ```kt
      gameGroup:insert( panda )
      gameGroup:insert( poof )
    end
    ```

1.  我们需要滚动到`activateRound()`函数，并为熊猫添加`"set"`动画序列：

    ```kt
      panda:setSequence("set")
      panda:play()
    ```

## *刚才发生了什么？*

熊猫发生的碰撞事件从`if event.phase == "began"`开始。通过几个`if`语句的情况，熊猫在屏幕上重新加载。当熊猫向舞台的右侧、左侧或顶部发射离开屏幕时，`event.other.myName == "star"`将调用新一轮。

熊猫的图片表有三个动画组。它们被称为`"set"`、`"air"`和`"crouch"`。图片表总共有五个帧。

在发射前设置熊猫的物理属性。身体类型设置为`"static"`，在空中时将改变。

熊猫的碰撞事件通过`panda:addEventListener( "collision", panda )`调用。

图片表设置好后，需要在`activateRound()`函数中添加`"set"`动画以启动移动。

# 星空。

星星在游戏中扮演着重要角色。它们是熊猫在倒计时结束前为了获得分数必须克服的主要障碍。

# 是时候行动了——创建星星碰撞。

星星碰撞需要被创建并从舞台移除，以便玩家可以累积分数。

1.  为星星碰撞创建一个名为`onStarCollision()`的函数，并带有`self`和`event`参数：

    ```kt
    local onStarCollision = function( self, event )
    ```

1.  添加`if`语句，当发生碰撞时，从游戏屏幕上移除`stars`子项。每次从屏幕上移除一个星星，分数增加 500。用`end`关闭函数：

    ```kt
      if event.phase == "began" and self.isHit == false then

        self.isHit = true
        print( "star destroyed!")
        self.isVisible = false

        stars.numChildren = stars.numChildren - 1

        if stars.numChildren < 0 then
          stars.numChildren = 0
        end

        self.parent:remove( self )
        self = nil

        local newScore = gameScore + 500
        setScore( newScore )
      end
    end
    ```

    ![是时候行动了——创建星星碰撞](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_05.jpg)

## *刚才发生了什么？*

星星碰撞在第一次接触时发生，条件是`if event.phase == "began"`和`self.isHit == false`，假设星星还没有被熊猫触碰。通过`self.parent:remove( self )`和`self = nil`，星星从屏幕上移除。分数通过`gameScore`增加 500，并更新为`setScore = (scoreNum)`。

## 尝试英雄——跟踪星星计数。

尝试跟踪游戏过程中熊猫捕捉到的星星数量。逻辑与创建游戏分数类似。每次捕捉到的星星都需要在每次碰撞时增加 1。星星计数放在`onStarCollision()`函数中。需要创建一个新的函数和方法来显示星星计数的文本，并且每次计数更改时都要更新。

# 屏幕触摸。

熊猫需要通过创建类似弹弓的发射机制来穿越游戏场地，以到达星星。力量在推动熊猫上升的过程中将发挥重要作用。

# 是时候行动了——发射熊猫。

让我们为熊猫添加一个触摸事件，使其向星星弹射。`powerShot`对象将帮助玩家可视化在熊猫起飞前需要施加多大的力量。

1.  为熊猫实现触摸事件。创建一个名为`onScreenTouch()`的局部函数，带有事件参数：

    ```kt
    local onScreenTouch = function( event )
    ```

1.  当启动`gameIsActive`时，添加一个`if`语句，用于当触摸事件开始时，通过使用`event.phase ==` `"began"`。在此事件期间，使用“蹲下”动画集来准备`panda`的发射：

    ```kt
      if gameIsActive then
        if event.phase == "began" and panda.inAir == false then

          panda.y = 225
          panda.isReady = true
          powerShot.isVisible = true
          powerShot.alpha = 0.75
          powerShot.x = panda.x; powerShot.y = panda.y
          powerShot.xScale = 0.1; powerShot.yScale = 0.1

          arrow.isVisible = true

          panda:setSequence("crouch")
          panda:play()
    ```

1.  添加一个`elseif`语句，用于当触摸事件结束时，通过使用`event.phase == "ended"`。创建一个名为`fling()`的新局部函数，它将在发射`panda`向`star`对象时保存`panda`的属性。应用一个与触摸事件拖动方向相反的力。当触摸事件从角色处拉远时，向外扩展`powerShot`显示对象的大小：

    ```kt
        elseif event.phase == "ended" and panda.isReady then

          local fling = function()
            powerShot.isVisible = false
            arrow.isVisible = false

            local x = event.x
            local y = event.y
            local xForce = (panda.x-x) * 4
            local yForce = (panda.y-y) * 4

            panda:setSequence("air")
            panda:play()

            panda.bodyType = "dynamic"
            panda:applyForce( xForce, yForce, panda.x, panda.y )
            panda.isReady = false
            panda.inAir = true

          end

        transition.to( powerShot, { time=175, xScale=0.1, yScale=0.1, onComplete=fling} )

        end

        if powerShot.isVisible == true then

          local xOffset = panda.x
          local yOffset = panda.y

          local distanceBetween = mCeil(mSqrt( ((event.y - yOffset) ^ 2) + ((event.x - xOffset) ^ 2) ))

          powerShot.xScale = -distanceBetween * 0.02
          powerShot.yScale = -distanceBetween * 0.02

          local angleBetween = mCeil(mAtan2( (event.y - yOffset), (event.x - xOffset) ) * 180 / mPi) + 90

          panda.rotation = angleBetween + 180
          arrow.rotation = panda.rotation
        end

      end
    end
    ```

    ![行动时间——发射熊猫](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_05_06.jpg)

## *刚才发生了什么？*

一旦游戏激活并在屏幕上加载了熊猫，就可以启动一个触摸事件来发射熊猫。熊猫将从“静态”物理状态变为“动态”物理状态。`powerShot`显示对象的大小随着事件触摸将熊猫拉得越远而增加。

熊猫发射的力由`local fling = function()`应用。发射力由`xForce`和`yForce`产生。熊猫对象通过`panda:applyForce( xForce, yForce, panda.x, panda.y )`推进。注意，身体类型变为“动态”，这样重力就可以影响对象。

# 组织显示对象

当设置好回合后，需要重新排列游戏对象的显示层次结构。最重要的对象显示在屏幕前方。

# 行动时间——重新排序层次

1.  需要创建一个新的局部函数`reorderLayers()`，以在游戏进行时组织屏幕上对象的显示层次结构：

    ```kt
    local reorderLayers = function()

      gameGroup:insert( levelGroup )
      ground:toFront()
      panda:toFront()
      poof:toFront()
      hudGroup:toFront()

    end
    ```

## *刚才发生了什么？*

`gameGroup`、`hudGroup`和其他显示对象在游戏屏幕的显示层次结构中重新组织。最重要的对象被设置在前面，而最不重要的对象在后面。

# 创建星星

天空背景需要填满星星，这样熊猫就能捕捉到尽可能多的星星。

# 行动时间——在关卡中创建星星

我们需要在游戏中添加星星的布局，并使它们移动，以添加一些效果来显示它们是活跃的。需要应用一个碰撞事件，当熊猫与它们相撞时，将它们移除。

1.  创建一个名为`createStars()`的新函数，并通过`for`循环布置`star`对象。添加一个`"collision"`事件，该事件会被`onStarCollision()`调用，以在星星被熊猫击中时移除它们。让星星每 10 秒向前和向后旋转 1,080 度和-1,080 度，这将使星星前后旋转三个完整的周期。为屏幕左右两侧创建墙壁：

    ```kt
    local createStars = function()

      local numOfRows = 4
      local numOfColumns = 12
      local starPlacement = {x = (display.contentWidth  * 0.5) - (starWidth * numOfColumns ) / 2  + 10, y = 50}

      for row = 0, numOfRows - 1 do
        for column = 0, numOfColumns - 1 do

          -- Create a star
          local star = display.newImage("star.png")
          star.name = "star"
          star.isHit = false
          star.x = starPlacement.x + (column * starWidth)
          star.y = starPlacement.y + (row * starHeight)
          physics.addBody(star, "static", {density = 1, friction = 0, bounce = 0, isSensor = true})
          stars.insert(stars, star)

          star.collision = onStarCollision
          star:addEventListener( "collision", star )

          local function starAnimation()
            local starRotation = function()
              transition.to( star, { time=10000, rotation = 1080, onComplete=starAnimation })
            end

            transition.to( star, { time=10000, rotation = -1080, onComplete=starRotation })
          end

          starAnimation()

        end
      end

      local leftWall  = display.newRect (0, 0, 0, display.contentHeight)
      leftWall.name = "wall"

      local rightWall = display.newRect (display.contentWidth, 0, 0, display.contentHeight)
        rightWall.name = "wall"

        physics.addBody (leftWall, "static", {bounce = 0.0, friction = 10})
        physics.addBody (rightWall, "static", {bounce = 0.0, friction = 10})

        reorderLayers()
    end
    ```

## *刚才发生了什么？*

屏幕上显示的星星数量由 `numOfRows` 和 `numOfColumns` 设置。一个 `for` 循环用于显示每个单独的星星对象，并将其放置在 `stars` 组中。通过 `onStarCollision()` 的事件监听器检测 `star` 的碰撞。

`leftWall` 和 `rightWall` 对象也有物理属性，并将考虑与熊猫的碰撞检测。

星星通过 `starAnimation()` 和 `starRotation()` 进行动画处理。每个函数轮流旋转每个星星对象 10 秒钟（10,000 毫秒），在 1,080 度和-1,080 度之间交替。

# 开始游戏

游戏从倒计时开始时启动，熊猫被加载到屏幕上。一旦熊猫在屏幕上设定，玩家需要迅速瞄准并发射它，以便立即重新加载熊猫。

# 动手时间——初始化游戏

要运行游戏，需要初始化物理和剩余的游戏功能。所有游戏动作都需要延迟，直到帮助屏幕离开舞台。

1.  通过创建一个名为 `gameInit()` 的新函数来启动游戏，该函数将包含物理属性并在舞台上激活显示对象：

    ```kt
    local gameInit = function()
      physics.start( true )
      physics.setGravity( 0, 9.8 )

      drawBackground()
      createPowerShot()
      createPanda()
      createStars()
      hud()
    ```

1.  添加一个 `Runtime` 事件监听器，使用 `"touch"` 来 `onScreenTouch()`：

    ```kt
      Runtime:addEventListener( "touch", onScreenTouch )
    ```

1.  让关卡和计时器在 10 秒后开始，这样用户就有时间阅读帮助文本。关闭函数并通过 `gameInit()` 开始游戏：

    ```kt
      local roundTimer = timer.performWithDelay( 10000, function() startNewRound(); end, 1 )
      local gameTimer = timer.performWithDelay( 10000, function() startTimer(); end, 1 )
    end

    gameInit()
    ```

所有代码都完成了！在模拟器中运行游戏，亲自看看它是如何工作的。如果出现错误，请确保检查代码中是否有任何拼写错误。

## *刚才发生了什么？*

通过 `gameInit()` 初始化一轮游戏。此时运行物理引擎和剩余的函数。同时添加 `onScreenTouch()` 的事件监听器。通过 `timer.performWithDelay` 在启动应用程序 10 秒后初始化 `startNewRound()` 和 `startTimer()` 函数。

## 小测验——动画图形

Q1. 正确暂停图像表的动画的方法是什么？

1.  `object:stop()`

1.  `object:pause()`

1.  `object:dispose()`

1.  以上都不正确

Q2. 如何让动画序列永远循环？

1.  `local sequenceData =`

    ```kt
     {
     name="run", start=1, count=5, time=100, loopCount=1 
     }

    ```

1.  `local sequenceData =`

    ```kt
     {
     name="run", start=1, count=5, time=100, loopCount=0 
     }

    ```

1.  `local sequenceData =`

    ```kt
     {
     name="run", start=1, count=5, time=100, loopCount=-1
     }

    ```

1.  `local sequenceData =`

    ```kt
     {
     name="run", start=1, count=5, time=100, loopCount=100
     }

    ```

Q3. 如何创建一个新的图像表？

1.  `myCharacter = display.newSprite(sequenceData)`

1.  `myCharacter = display.newSprite(imageSheet, sequenceData)`

1.  `myCharacter = sprite.newSpriteSheet("myImage.png", frameWidth, frameHeight)`

1.  以上都不正确

# 概括

我们的第二款游戏《熊猫星星捕手》终于完成了！我们现在对编写更多函数和不同类型的游戏逻辑有了很好的掌握，而且我们还掌握了动画制作！干的漂亮！

在本章中，我们完成了以下工作：

+   更深入地了解了过渡，并应用了缓动技术

+   理解了图像表和精灵动画

+   为需要在屏幕上连续重新加载的显示对象创建了一个游戏循环

+   对一个显示对象施加力，使其向指定方向推进

+   添加了一个碰撞事件，用以从一个显示对象切换到另一个显示对象

我们在整整一个章节中完成了一个游戏的制作！使用 Corona SDK 进行开发是如此简单和快速上手。即便创建一个简单的游戏，也无需编写成千上万行代码。

在下一章中，我们将学习创建游戏、音效和音乐的另一个重要元素！这将是一段美妙的旅程。
