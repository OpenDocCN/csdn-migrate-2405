# Corona SDK 移动游戏初学者指南（四）

> 原文：[`zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82`](https://zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：处理多设备和网络应用

> *允许您的应用程序与社交网络集成是推广您成品的好方法。许多游戏允许玩家上传他们的高分并与其他玩相同游戏的人分享。有些提供需要成功完成才能解锁成就的挑战。社交网络增强了游戏体验并为开发者提供了很好的曝光机会。*

由于我们越来越习惯编程，我们还将更详细地介绍构建配置。理解配置设备构建的重要性对跨平台开发至关重要。这是 Corona SDK 可以轻松地在 iOS 和 Android 设备上处理的能力。

在本章中，我们将学习以下主题：

+   重新访问配置设置

+   发布消息到 Twitter

+   发布消息到 Facebook

让我们添加这些最后的润色！

# 返回配置

在第二章中简要讨论了构建设置和运行时配置，*Lua 速成课程和 Corona 框架*。让我们深入了解如何处理在 iOS 和 Android 平台上工作的各种设备的具体细节。

## 构建配置

有多种方法可以处理设备方向，以匹配您的游戏设计所需的设置。

### 方向支持（iOS）

有时您希望原生用户界面（UI）元素自动旋转或以特定方式定向，但同时也需要在 Corona 中保持固定的坐标系统。

要锁定 Corona 的方向同时允许原生 iPhone UI 元素旋转，可以在 `build.settings` 中添加以下内容参数：

```kt
settings =
{
  orientation =
  {
 default = "portrait",
 content = "portrait",
    supported =
    {
      "landscapeLeft", "landscapeRight", "portrait", "portraitUpsideDown",
    },
  },
}
```

要将 Corona 的内部坐标系统锁定为纵向同时将 iPhone UI 元素锁定为横向，您可以在 `build.settings` 中执行以下操作：

```kt
settings =
{
  orientation =
  {
 default ="landscapeRight",
 content = "portrait",
    supported =
    {
      "landscapeRight", "landscapeLeft",
    },
  },
}
```

### 方向支持（安卓）

安卓平台支持纵向和横向方向。方向 *portraitUpsideDown* 在某些安卓设备上可能不可用。此外，目前安卓设备不支持自动旋转。默认方向不会影响安卓设备。方向初始化为设备的实际方向（除非只指定了一个方向）。

下面是一个针对安卓的 `build.settings` 文件的示例（您也可以在同一个文件中组合安卓和 iPhone 设置）：

```kt
settings =
{
  android =
  {
    versionCode = "2",
    versionName = "2.0"

    usesPermissions =
    {
      "android.permission.INTERNET",
    },
  },

  orientation =
  {
    default = "portrait"
  },
}
```

### 版本代码和版本名称（安卓）

`versionCode` 和 `versionName` 字段可以在 `build.settings` 中的可选 `"android"` 表中设置。

如果在`build.settings`文件中没有设置，`versionCode`字段默认为`"1"`，而`versionName`字段默认为`"1.0"`。当将应用程序的更新版本提交到 Google Play 商店时，也必须更新`versionCode`和`versionName`字段。`versionCode`的所有版本号都必须是整数。`versionCode`字段不能包含任何小数，而`versionName`字段可以包含小数。

想要了解更多信息，请查看[`developer.android.com/guide/topics/manifest/manifest-element.html#vcode`](http://developer.android.com/guide/topics/manifest/manifest-element.html#vcode)中的*android:versionCode*和*android:versionName*。

### 注意

`versionCode`属性是一个内部数字，用于在 Google Play 商店中区分应用程序版本。它与 Corona 构建对话框提供的版本不同。`versionName`属性是向用户显示的版本号。

### 应用权限（Android）

可以使用可选的`"usesPermissions"`表来指定权限，使用的是在 Android 清单参考中给出的字符串值：[`developer.android.com/reference/android/Manifest.permission.html`](http://developer.android.com/reference/android/Manifest.permission.html)。

开发者应该使用符合他们应用程序需求的权限。例如，如果需要网络访问，就需要设置互联网权限。

### 注意

想要了解更多关于 Corona SDK 中应用的`android.permission`键的信息，请参考[`docs.coronalabs.com/guide/distribution/buildSettings/index.html#permissions`](http://docs.coronalabs.com/guide/distribution/buildSettings/index.html#permissions)。

## 更简单的层次内容缩放

如果你在`config.lua`文件中从未处理过，那么在多个设备上调整内容大小有时可能会让人感到沮丧。有许多不同的屏幕尺寸。例如，iPhone 5 的尺寸为 640 x 1136 像素，iPad 2 的尺寸为 768 x 1024 像素，Droid 的尺寸为 480 x 854 像素，三星 Galaxy 平板的尺寸为 600 x 1024 像素等。由于图像大小限制，内存可能会很容易耗尽。

在设置你的`config.lua`时，就像我们在前面的章节中所做的那样，我们将内容设置为`width = 320`，`height = 480`，以及`scale = "letterbox"`。如果为 Android 设备构建，`"zoomStretch"`最适合于适应该平台上不同的屏幕尺寸。这为 iOS 和 Android 创建了一个共同的构建，并展示了足够大的显示图像以适应各种屏幕尺寸。

如果你想要先为更大的屏幕尺寸进行缩放，然后再缩小，请使用 iPad 2 的屏幕尺寸。你的`config.lua`文件将类似于以下代码：

```kt
application =
{
  content =
  {
    width = 768,
    height = 1024,
    scale = "letterbox"
  }
}
```

虽然前面的例子是缩放内容的另一种解决方案，但重要的是要记住，较大（高分辨率）图像涉及的纹理内存限制。像 iPad 带 Retina 显示屏、iPhone 5s 和三星 Galaxy Tab 4 平板电脑这样的设备可以很好地处理这个问题，但 iPhone 4s 和更旧的设备可用的纹理内存要少得多，无法处理大图形。

解决这个潜在问题的方法之一是使用动态图像解析，以替换更适合低端设备和高端设备的资源。我们将在本节的后面更详细地讨论这个话题。

### 两全其美的方案

你可能已经注意到，我们在示例应用中使用的某些背景图像被缩放到了 380 x 570。这个尺寸恰好能填满 iOS 和 Android 所有常见设备的整个屏幕。更重要的是，它是任何设备上高低分辨率图像的折中方案。

为了让你的内容尽可能均匀地显示，以下设置必须相应地进行：

`config.lua`的设置如下：

```kt
application =
{
  content =
  {
    width = 320,
    height = 480,
    scale = "letterbox"
  }
}
```

在包含显示图像的任何文件中，典型的背景会如下所示：

```kt
local backgroundImage = display.newImage( "bg.png", true )
backgroundImage.x = display.contentCenterX
backgroundImage.y = display.contentCenterY
```

任何尺寸为 320 x 480 的内容都被认为是焦点区域。区域之外的内容将被裁剪，但在任何设备上都会用内容填满屏幕。

## 动态图像选择的深层含义

我们知道我们可以交换用于较小设备（iPhone 4s）和较大设备（iPhone 6 和 Kindle Fire HD）的基本图像。在尝试在同一个构建中缩放多个设备时，会发生这种情况。

针对 iOS 和 Android 设备，有一个文件命名方案可供使用。了解如何处理受提议设备影响的资源的缩放，是成功的一半。我们将需要定义 Corona 需要解决哪个分辨率比例，以便访问它们所指向的资源。

使用`display.newImageRect( [parentGroup,] filename [, baseDirectory] w, h )`这行代码将调用你的动态分辨率图像。

通常，我们在项目中为 iOS 设备调用更高分辨率图像时使用`["@2x"] = 2`：

```kt
application =
{
  content =
  {
    width = 320,
    height = 480,
    scale = "letterbox",

    imageSuffix =
    {
      ["@2x"] = 2,
    },
  },
}
```

前面的例子只适用于 iPhone 4s 和 iPad 2，因为它超出了这两台设备的基本尺寸 320 x 480。如果我们想要让 Droid 2 也能访问，那么比例阈值将是 1.5。对于像三星 Galaxy 平板电脑这样的 Android 平板来说，比例阈值是 1.875。那么我们如何得出这些数字呢？简单。取高端设备的宽度，除以 320（基本尺寸）。例如，Droid 2 的尺寸是 480 x 854。将 480 除以 320，等于 1.5。

三星 Galaxy Tab 4 平板电脑的尺寸是 800 x 1280。将 800 除以 320，等于 2.5。

如果尝试在同一个项目中管理 iOS 和 Android 设备，你可以在`config.lua`中更改你的`imageSuffix`，如下代码所示：

```kt
    imageSuffix =
    {
 ["@2x"] = 1.5, -- this will handle most Android devices such as the Droid 2, Nexus, Galaxy Tablet, etc...
    }
```

或者，你可以使用以下代码：

```kt
    imageSuffix =
    {
 ["@2x"] = 2.5, -- this will handle the Galaxy Tab 4 and similar sized devices
    }
```

使用前面任一示例将触发提议的安卓设备显示更高分辨率的图像。

`imageSuffix` 字符串不一定非要是 `"@2x"`；它可以是像 `"@2"`，`"_lrg"`，甚至是 `"-2x"` 这样的任何东西。只要你的更高分辨率图像在主图像名称后具有预期的后缀，它就能正常工作。

## 高分辨率精灵表

高分辨率精灵表的处理方式与动态图像选择不同。虽然你可以继续使用相同的命名约定来区分你的高分辨率图像和基本图像，但图像将无法在引用精灵表时使用 `display.newImageRect()`。

如果你的 `config.lua` 文件中当前的内容缩放设置为 `width = 320`，`height = 480`，以及 `scale = "letterbox"`，那么以下设备的缩放输出将展示如下：

+   `iPhone = 1`

+   `iPhone 4s = 0.5`

+   `Droid 2 = 0.666666668653488`

+   `iPad 2 = 0.46875`

应用与 iPhone 尺寸相匹配的基本精灵表将显示清晰锐利的图像。当相同的精灵表应用于 iPhone 4 时，显示将匹配设备的内容缩放，但精灵表在边缘处看起来会有些像素化和模糊。使用 `display.contentScaleX` 并调用一些方法将为你解决这个问题。注意 `displayScale < 1` 将根据前述设备比例访问高分辨率精灵表：

```kt
    local sheetData 
    local myObject

 local displayScale = display.contentScaleX –- scales sprite sheets down
 if displayScale < 1 then –- pertains to all high-res devices

      sheetData = { width=256, height=256, numFrames=4, sheetContentWidth=512, sheetContentHeight=512 }
    else
      sheetData = { width=128, height=128, numFrames=4, sheetContentWidth=256, sheetContentHeight=256 }
    end

    local sheet = graphics.newImageSheet( "charSprite.png", sheetData)

    local sequenceData = 
    {
      { name="move", start=1, count=4, time=400 } 
    }

    myObject = = display.newSprite( sheet, sequenceData )

 if displayScale < 1 then --scale the high-res sprite sheet if you're on a high-res device.
      myObject.xScale = .5; myObject.yScale = .5
    end

    myObject.x = display.contentWidth / 2
    myObject.y = display.contentHeight / 2

    myObject.x = 150; myObject.y = 195

    myObject: setSequence("move")
    myObject:play()
```

# 应用网络化

当你完成主要游戏框架的开发后，如果决定这样做，考虑如何将其网络化是很有好处的。

在我们生活的某个时刻，我们所有人都使用过某种网络工具，比如 Twitter 或 Facebook。你可能现在正在使用这些应用程序，但重点是，你可以从其他用户那里阅读关于新游戏发布的更新，或者有人传播下载游戏并与他们竞争的消息。你可以成为他们谈论的那个游戏的开发者！

在你的游戏中融入网络机制不必是一件麻烦事。只需几行代码就能让它工作。

## 发布到 Twitter

推推推……Twitter 是一个网络工具，能让你接触到吸引你兴趣的最新信息。它还是一个分享你业务信息，当然还有你的游戏的好工具。通过推广你的应用，接触游戏开发受众。

那些想要将帖子分享到 Twitter 的用户需要先在[`twitter.com/`](http://twitter.com/)创建一个账户，并确保他们已经登录。

# 行动时间——将 Twitter 加入你的应用

我们将通过 UI 按钮访问网络服务，在我们的应用中实现 Twitter 功能。

1.  在`Chapter 9`文件夹中，将`Twitter Web Pop-Up`项目文件夹复制到你的桌面。所有需要的配置、库和资源都已包含。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。

1.  创建一个新的`main.lua`文件并将其保存到项目文件夹中。

1.  在代码开始时设置以下变量：

    ```kt
    display.setStatusBar( display.HiddenStatusBar )

    local ui = require("ui")

    local openBtn
    local closeBtn
    local score = 100
    ```

1.  创建一个名为`onOpenTouch()`的本地函数，带有事件参数。添加一个`if`语句，以便事件接收一个`"release"`动作：

    ```kt
    local onOpenTouch = function( event )
      if event.phase == "release" then
    ```

1.  使用名为`message`的局部变量，添加以下字符串语句并拼接`score`：

    ```kt
    local message = "Posting to Twitter from Corona SDK and got a final score of " ..score.. "."
    ```

1.  添加`local myString`并应用`string.gsub()`对`message`进行处理，替换空格实例：

    ```kt
    local myString = string.gsub(message, "( )", "%%20")
    ```

1.  引入链接到 Twitter 账户的`native.showWebPopup()`函数。将`myString`拼接进来以包含预加载的消息。关闭函数：

    ```kt
        native.showWebPopup(0, 0, 320, 300, "http://twitter.com/intent/tweet?text="..myString)

      end
    end
    ```

1.  设置`openBtn` UI 函数：

    ```kt
      openBtn = ui.newButton{
      defaultSrc = "openbtn.png",
      defaultX = 90,
      defaultY = 90,
      overSrc = "openbtn-over.png",
      overX = 90,
      overY = 90,
      onEvent = onOpenTouch,
    }

    openBtn.x = 110; openBtn.y = 350
    ```

1.  创建一个名为`onCloseTouch()`的本地函数，带有`event`参数。添加一个`if`语句，其中`event.phase == "release"`以激活`native.cancelWebPopup()`：

    ```kt
    local onCloseTouch = function( event )
      if event.phase == "release" then    

        native.cancelWebPopup()    

      end
    end
    ```

1.  设置`closeBtn` UI 函数：

    ```kt
      closeBtn = ui.newButton{
      defaultSrc = "closebtn.png",
      defaultX = 90,
      defaultY = 90,
      overSrc = "closebtn-over.png",
      overX = 90,
      overY = 90,
      onEvent = onCloseTouch,
    }

    closeBtn.x = 210; closeBtn.y = 350
    ```

1.  保存文件并在模拟器中运行项目。确保你连接到互联网以查看结果。

    ### 注意

    如果你当前没有登录你的 Twitter 账户，你将被要求在查看我们代码中的推文结果之前登录。

    ![行动时间——将 Twitter 添加到你的应用中](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_09_01.jpg)

## *刚才发生了什么？*

在代码的顶部，我们设置了一个变量`local score = 100`。这将在我们的 Twitter 消息中使用。

在`onOpenTouch(event)`函数中，当释放`openBtn`时将加载一个网页弹窗。要发布的文本以字符串格式显示在变量`local message`下。你会注意到我们将`score`拼接到字符串中，以便在消息发布时显示其值。

`local myString`和`string.gsub()`用于替换字符串中模式指示的所有实例。在这种情况下，它取消息中的字符串，并搜索每个单词之间的每个空格，并将其替换为`%20`。`%20`编码 URL 参数以表示空格。额外的`%`充当转义字符。

`native.showWebPopup()`函数以 320 x 300 的尺寸显示，这大约是设备屏幕尺寸的一半。添加显示 Twitter 消息对话框的 URL 并拼接`myString`。

当网页弹窗不再需要使用并需要关闭时，`closeBtn`会调用`onCloseTouch(event)`。这将传递参数`"release"`给`event`，并调用`native.cancelWebPopup()`。这个特定的函数将会关闭当前的网页弹窗。

## 发布到 Facebook

另一个可以用来分享关于你的游戏信息的社交网络工具是 Facebook。你可以轻松地自定义一个帖子来链接关于你的游戏的信息，或者分享关于高分的消息，并鼓励其他用户下载。

为了在 Facebook 上发布消息，你需要登录到你的 Facebook 账户或创建一个账户，网址为 [`www.facebook.com/`](https://www.facebook.com/)。你还需要从 Facebook 开发者网站 [`developers.facebook.com/`](https://developers.facebook.com/) 获取一个 App ID。App ID 是你站点的唯一标识符，它决定了用户与应用页面/网站之间适当的安全级别。

创建 App ID 后，你还需要编辑应用信息，并选择应用与 Facebook 的集成方式。这里有几个选项，如网站、原生 iOS 应用和原生 Android 应用等。网站集成必须选中，并填写有效的 URL，以便 Facebook 在处理涉及网页弹窗的帖子时重定向到指定 URL。

# 行动时间——将 Facebook 添加到你的应用中

类似于我们的 Twitter 示例，我们也将通过网页弹窗整合 Facebook 帖子：

1.  在 `Chapter 9` 文件夹中，将 `Facebook Web Pop-Up` 项目文件夹复制到你的桌面。所有需要的配置、库和资源都已包含在内。你可以从 Packt Publishing 网站下载伴随本书的项目文件。

1.  创建一个新的 `main.lua` 文件并将其保存到项目文件夹中。

1.  在代码开始处设置以下变量：

    ```kt
    display.setStatusBar( display.HiddenStatusBar )

    local ui = require("ui")

    local openBtn
    local closeBtn
    local score = 100
    ```

1.  创建一个名为 `onOpenTouch()` 的局部函数，并带有一个事件参数。当事件接收到 `"release"` 动作时，添加一个 `if` 语句：

    ```kt
    local onOpenTouch = function( event )
      if event.phase == "release" then
    ```

1.  添加以下局部变量，包括我们将在 Facebook 帖子中实施的字符串：

    ```kt
     local appId = "0123456789" -- Your personal FB App ID from the facebook developer's website

        local message1 = "Your App Name Here"
        local message2 = "Posting to Facebook from Corona SDK and got a final score of " ..score.. "."
        local message3 = "Download the game and play!"

        local myString1 = string.gsub(message1, "( )", "%%20")
        local myString2 = string.gsub(message2, "( )", "%%20")
        local myString3 = string.gsub(message3, "( )", "%%20")
    ```

1.  引入连接到 Facebook 账户的本地网页弹窗功能。包括 Facebook 对话框参数，用于重定向你首选网站的 URL，以触摸模式连接到你的应用 URL 的显示，以及展示你的应用图标或公司标志的图片 URL。使用字符串方法连接所有变量以输出所有消息。关闭函数。在 `openBtn` UI 函数中加入。你需要将以下所有 URL 信息替换为你自己的：

    ```kt
    native.showWebPopup(0, 0, 320, 300, "http://www.facebook.com/dialog/feed?app_id=" .. appId .. "&redirect_uri=http://www.yourwebsite.com&display=touch&link=http://www.yourgamelink.com&picture=http://www.yourwebsite.com/image.png&name=" ..myString1.. "&caption=" ..myString2.. "&description=".. myString3)  

      end
    end

      openBtn = ui.newButton{
      defaultSrc = "openbtn.png",
      defaultX = 90,
      defaultY = 90,
      overSrc = "openbtn-over.png",
      overX = 90,
      overY = 90,
      onEvent = onOpenTouch,
    }
    openBtn.x = 110; openBtn.y = 350
    ```

    ### 注意

    关于 Facebook 对话框的更多信息可以在 Facebook 开发者网站找到，网址为 [`developers.facebook.com/docs/reference/dialogs/`](http://developers.facebook.com/docs/reference/dialogs/)。

1.  创建一个名为 `onCloseTouch()` 的局部函数，并带有一个事件参数。添加一个 `if` 语句，判断 `event.phase == "release"` 以激活 `native.cancelWebPopup()`。设置 `closeBtn` UI 函数：

    ```kt
    local onCloseTouch = function( event )
      if event.phase == "release" then    

        native.cancelWebPopup()    

      end
    end

      closeBtn = ui.newButton{
      defaultSrc = "closebtn.png",
      defaultX = 90,
      defaultY = 90,
      overSrc = "closebtn-over.png",
      overX = 90,
      overY = 90,
      onEvent = onCloseTouch,
    }

    closeBtn.x = 210; closeBtn.y = 350
    ```

1.  保存文件并在模拟器中运行项目。确保你已连接到互联网并登录你的 Facebook 账户以查看结果。![行动时间——将 Facebook 添加到你的应用中](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_09_02.jpg)

## *刚才发生了什么？*

在 `onOpenTouch(event)` 函数内部，当按下并释放 `openBtn` 时会调用几个变量。注意 `local appId` 表示你在 Facebook Developers 网站上创建应用后可以获得的数字字符串。

`message1`、`message2` 和 `message3` 是显示信息帖子的字符串。`myString1`、`myString2` 和 `myString3` 用于替换 `message1`、`message2` 和 `message3` 中指定的空格。

`native.showWebPopup()` 函数以 320 x 300 的尺寸显示，并将对话框 URL 呈现给 Facebook。以下参数相应地显示：

+   `app_id`：这是你在 Facebook Developer 网站上创建的唯一 ID。例如，`"1234567"`。

+   `redirect_uri`：用户在对话框上点击按钮后重定向的 URL。这是参数中必需的。

+   `display`：这显示渲染对话框的模式。

+   `touch`：这用于如 iPhone 和 Android 这样的智能手机设备。这使对话框屏幕适应较小的尺寸。

+   `link`：这是帖子附带的链接。

+   `picture`：这是帖子图片的 URL。

+   `name`：这是链接附件的名称。

+   `caption`：这是链接的标题（显示在链接名称下方）。

+   `description`：这是链接的描述（显示在链接标题下方）。

当网页弹窗不再需要并需要关闭时，`closeBtn` 会调用 `onCloseTouch(event)`。这将使用事件参数 `"release"` 并调用 `native.cancelWebPopup()`。这个特定的函数将关闭当前的网页弹窗。

# Facebook Connect

这个库提供了一系列通过官方 Facebook Connect 接口访问 [`www.facebook.com`](http://www.facebook.com) 的功能。

# 动手操作时间——使用 Facebook Connect 发布分数。

Facebook Connect 是另一种使用原生 Facebook UI 功能在墙贴上发布信息的方式。我们将创建一种不同的方法来将消息和分数发布到新闻源。为了了解 Facebook Connect 的工作方式，你需要将构建加载到设备上查看结果。它不会在模拟器中运行。

1.  在 `Chapter 9` 文件夹中，将 `Facebook Connect` 项目文件夹复制到你的桌面。所有需要的配置、库和资源都已包含在内。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。

1.  创建一个名为 `main.lua` 的新文件并将其保存到项目文件夹中。

1.  在代码开始时设置以下变量：

    ```kt
    display.setStatusBar( display.HiddenStatusBar )

    local ui = require("ui")
    local facebook = require "facebook"

    local fbBtn
    local score = 100
    ```

1.  创建一个名为 `onFBTouch()` 的本地函数，带有一个事件参数。添加一个包含 `event.phase == release` 的 `if` 语句。同时，以字符串格式包含你的 Facebook 应用 ID：

    ```kt
    local onFBTouch = function( event )
      if event.phase == "release" then    

     local fbAppID = "0123456789" -- Your FB App ID from facebook developer's panel

    ```

1.  在 `onFBTouch(event)` 内部创建另一个本地函数，名为 `facebookListener()`，同样带有一个事件参数。包含一个引用 `"session" == event.type` 的 `if` 语句：

    ```kt
        local facebookListener = function( event )
          if ( "session" == event.type ) then
    ```

1.  在另一个 `if` 语句中添加 `"login"` 等于 `event.phase` 的条件。包含一个名为 `theMessage` 的局部变量，以显示你想要与其他 Facebook 用户分享的消息：

    ```kt
            if ( "login" == event.phase ) then  

              local theMessage = "Got a score of " .. score .. " on Your App Name Here!"  
    ```

1.  添加 `facebook.request()` 函数，它将在用户的 Facebook 墙上发布以下消息。在 `facebookListener(event)` 函数中用 `end` 关闭任何剩余的 `if` 语句：

    ```kt
              facebook.request( "me/feed", "POST", {
                message=theMessage,
                name="Your App Name Here",
                caption="Download and compete with me!",
                link="http://itunes.apple.com/us/app/your-app-name/id382456881?mt=8",
                picture="http://www.yoursite.com/yourimage.png"} )
            end
          end
        end
    ```

    ### 注意

    `link` 参数展示了一个 iOS 应用的 URL。你可以将 URL 指向类似 `https://play.google.com/store/apps/details?id=com.yourcompany.yourappname` 的 Android 应用或你选择的任何通用网站 URL。

1.  调用 `facebook.login()` 函数，其中包括你的 App ID、监听器和在用户 Facebook 墙上发布的权限。关闭 `onFBTouch(event)` 函数的其余部分：

    ```kt
        facebook.login(fbAppID, facebookListener, {"publish_actions"})

      end
    end
    ```

1.  启用 `fbBtn` UI 功能并保存你的文件：

    ```kt
    fbBtn = ui.newButton{
      defaultSrc = "facebookbtn.png",
      defaultX = 100,
      defaultY = 100,
      overSrc = "facebookbtn-over.png",
      overX = 100,
      overY = 100,
      onEvent = onFBTouch,
    }

    fbBtn.x = 160; fbBtn.y = 160
    ```

1.  为 iOS 或 Android 创建一个新的设备构建。将构建加载到你的设备上并运行应用程序。在你能看到应用程序的结果之前，系统会要求你登录到你的 Facebook 账户。![行动时间——使用 Facebook Connect 发布分数](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_09_03.jpg)

## *刚才发生了什么？*

需要完成的最重要的任务之一是 `require "facebook"` 以便 Facebook API 能够工作。我们还创建了一个名为 `score` 的局部变量，其值为 100。

`onFBTouch(event)` 函数将在 `fbBtn` 的 `"release"` 上初始化事件参数。在函数中，`fbAppID` 以字符串格式包含字符。这将是一组你必须在 Facebook 开发者网站上获取的独特数字。当你在该网站上创建应用页面时，系统会为你创建 App ID。

另一个函数 `facebookListener(event)` 被创建，它将初始化所有的 `fbConnect` 事件。包含 `("login" == event.phase)` 的 `if` 语句将通过 `"me/feed", "POST"` 请求在你的动态中发布一条消息。该动态包含以下内容：

+   `message=theMessage`：这指的是属于变量的字符串。它还连接分数，因此也会显示值。

+   `name`：这是一条包含你的应用名称或主题的消息。

+   `caption`：这是一条简短的吸引其他用户关注玩游戏的宣传信息。

+   `link`：这提供了从 App Store 或 Google Play Store 下载游戏的 URL。

+   `picture`：这是一个包含你的应用图标或游戏视觉表示的图片 URL。

设置参数后，`facebook.login()` 将引用 `fbAppID` 和 `facebookListener()` 以查看是否使用了有效的应用程序 ID 在 Facebook 上发布。成功后，将通过 `"publish_actions"` 发布帖子。

## 尝试成为英雄——创建一个对话框

看看你能否弄清楚如何使用 Facebook Connect 显示一个对话框，并使用前面示例中展示的相同设置。以下行将显示为：

```kt
facebook.showDialog( {action="stream.publish"} )
```

现在，查看代码中可以访问`facebook.showDialog()`的位置。这是发布消息到 Facebook 的另一种方式。

## 小测验——处理社交网络

Q1.哪个特定的 API 可以缩小高分辨率精灵表？

1.  `object.xScale`

1.  `display.contentScaleX`

1.  `object.xReference`

1.  以上都不正确

Q2.允许在 Facebook 上在用户墙上发布的内容的发布权限叫什么？

1.  `"publish_stream"`

1.  `"publish_actions"`

1.  `"post"`

1.  `"post_listener"`

Q3. `facebook.login()`需要哪些参数？

1.  `appId`

1.  `listener`

1.  `permissions`

1.  所有以上选项

# 总结

我们已经涵盖了关于增强配置设置以及将当今媒体中最受欢迎的三个社交网络整合到我们的应用中的多个领域。

我们还深入了解了以下内容：

+   构建设置

+   动态内容缩放和动态图像分辨率

+   高分辨率精灵表

+   将消息推送到 Twitter 和 Facebook

在下一章中，我们将详细介绍如何将我们的游戏提交到 App Store 和 Google Play Store。你绝对不想错过这个！


# 第十章：优化、测试和发布你的游戏

> *将游戏开发到完成阶段是一项伟大的成就。这离与全世界分享又近了一步，这样其他人就可以玩你新开发的游戏了。使用 Corona SDK 创建游戏的好处在于，你可以选择为 iOS 和/或 Android 构建游戏。你需要确保应用程序准备好提交，以便可以在你开发的移动平台上发布。我们将详细介绍准备游戏发布所需的过程。*

### 注意

这里使用的应用程序界面经常更新；然而，无论你使用的是哪种界面，你都能完成所有步骤。

在本章中，我们将涵盖以下主题：

+   提高应用程序的性能

+   为 App Store 设置分发供应配置文件

+   在 iTunes Connect 中管理应用程序信息

+   学习如何将应用程序提交到 App Store 的应用程序加载器

+   为 Android 签名应用程序

+   学习如何将应用程序提交到 Google Play 商店

# 理解内存效率

在开发应用程序时，你应该始终考虑你的设计选择如何影响应用程序的性能。尽管计算能力和内存有所提升，但设备内存仍然有其限制。设备内的性能和优化不仅能实现更快的响应时间，还能帮助最小化内存使用并最大化电池寿命。如何检查内存使用的示例链接可以在[`gist.github.com/JesterXL/5615023`](https://gist.github.com/JesterXL/5615023)找到。

内存是移动设备上重要的资源。当消耗过多内存时，设备可能会在你最意想不到的时候强制退出你的应用程序。以下是在开发过程中需要注意的一些事项：

+   **消除内存泄漏**：允许内存泄漏存在意味着你的应用程序中有多余的已使用内存，这些内存占据了宝贵的空间。尽管 Lua 有自动内存管理，但你的代码中仍然可能出现内存泄漏。例如，当你向应用程序中引入全局变量时，你需要告诉 Lua 何时不再需要这些变量，以便释放内存。这可以通过在代码中使用`nil`来实现（`myVariable = nil`）。

+   **显示图像的文件大小应尽可能小**：你可能希望在场景中拥有许多显示图像，但它们可能会占用过多的纹理内存。精灵表（Sprite sheets）可能会对应用程序的内存造成负担。它们应尽可能方便地创建得较小，并具有清晰展示动画的适当数量的帧数。对于所有你已显示的项目，规划出哪些元素始终在你的背景和前景中。如果可以将多个图像组合在一起，使它们不移动，那么就这样做。这将有助于在添加多个显示图像时节省内存。

+   **不要一次性加载所有资源**：避免在需要之前加载资源文件。这将有助于节省内存，并防止应用程序在尝试一次性加载过多内容时崩溃。

+   **从显示层次结构中移除对象**：创建显示对象时，它会隐式地添加到显示层次结构中。当你不再需要显示对象时，应该将其从显示层次结构中移除，特别是当对象包含图像时。这可以通过 `display.remove( myImage ); myImage = nil` 或 `myImage:removeSelf()` 来实现。

    这里有一个例子：

    ```kt
    local box = display.newRect( 0, 50, 100, 100)
    box:setFillColor( 1, 1, 1)
    box.alpha = 1

    local function removeBox()
      if box.alpha == 1 then
        print("box removed")
        display.remove( box )
        box = nil
      end
    end
    timer.performWithDelay( 1000, removeBox, 1 ) -- Runs timer to 1000 milliseconds before calling the block within removeBox()
    ```

+   **声音文件应尽可能小**：使用免费程序，如 Audacity，或你偏爱的音频软件来压缩音乐或音效，并为设备构建。最好将未处理的音频与压缩后的音频进行比较，以听出质量上的差异。这将帮助你确定在音频质量和文件大小之间的良好折中。

## 图形

如果你没有注意同时使用的图片的大小和数量，显示图片会占用大量的纹理内存。

### 分组对象

如果多个对象的属性设置为相同的值，最好将对象添加到组中，然后修改组的属性。这将使编码变得更容易，同时也优化了你的动画。

### 在不使用动画时关闭它们

当不需要或在使它们不可见时，很容易忘记停止后台运行的动画。

当你包含如 `"enterFrame"` 的监听器，且监听器下注册的对象被设置为 `.isVisible = false` 时，即使屏幕上看不到，它仍会在后台运行。确保在不必要时移除监听器。

### 优化图片大小

当你的应用包含大文件大小，尤其是全屏图片时，由于加载所需时间，应用程序的响应速度会变慢，而且还会占用大量内存。在使用大图片时，尽量使用图像编辑工具（如 Photoshop 或 ImageOptim([`imageoptim.com`](https://imageoptim.com)）压缩文件大小。这将帮助你减少文件体积，避免应用延迟带来的困扰。长期来看，压缩大图片尺寸是有益的。如果图片是背景，可以考虑切换到平铺图像。

# 分发 iOS 应用程序

当你的游戏最终调试完成，接下来要做什么呢？假设你已经注册了 iOS 开发者计划，那么在将应用程序提交到 App Store 之前，需要遵循一些指导原则。

## 准备你的应用图标

根据您的应用程序为哪些 iOS 设备开发，应用程序图标需要各种尺寸和命名约定。您可以在苹果开发者网站的[iOS 人机界面指南](https://developer.apple.com/library/ios/documentation/UserExperience/Conceptual/MobileHIG/AppIcons.html#//apple_ref/doc/uid/TP40006556-CH19-SW1)中的**图标和图像设计**部分的**应用图标**子节找到最新信息。

以下是应用程序图标的要求，也需要采用非交错式的`.png`格式：

+   `iTunesArtwork@2x`：这是一张 1024 x 1024 像素的图片。这张图片需要移除`.png`扩展名。

+   `Icon-60@2x.png`：这是一张 120 x 120 像素的图片，用于 Retina iPhone。

+   `Icon-60@3x.png`：这是一张 180 x 180 像素的图片，用于 iPhone 6 Plus。

+   `Icon-76.png`：这是一张 76 x 76 像素的图片，用于 iPad。

+   `Icon-76@2x.png`：这是一张 152 x 152 像素的图片，用于 Retina iPad。

+   `Icon-Small-40.png`：这是一张 40 x 40 像素的图片，用于 iPad 2 和 iPad mini 搜索。

+   `Icon-Small-40@2.png`：这是一张 80 x 80 像素的图片，用于 Retina iPhone/iPad 搜索。

+   `Icon-Small-40@3x.png`：这是一张 120 x 120 像素的图片，用于 iPhone 6 Plus 搜索。

+   `Icon-Small.png`：这是一张 29 x 29 像素的图片，用于 iPad 2 和 iPad mini 设置。

+   `Icon-Small@2x.png`：这是一张 58 x 58 像素的图片，用于 Retina iPhone/iPad 设置。

+   `Icon-Small@3x.png`：这是一张 87 x 87 像素的图片，用于 iPhone 6 Plus 设置。

在您的`build.settings`文件中，您需要包含您应用程序支持的所有设备的图标引用。以下是如果您创建通用构建，如何设置文件的示例：

```kt
settings =
{
  orientation =
  {
    default = "landscapeRight", 
  },

  iphone =
    {
       plist =
       {
         CFBundleIconFiles = {
           "Icon-60@2x.png",
           "Icon-60@3x.png",
           "Icon-76.png",
           "Icon-76@2x.png",
           "Icon-Small-40.png",
           "Icon-Small-40@2x.png",
           "Icon-Small-40@3x.png",
           "Icon-Small.png",
           "Icon-Small@2x.png",
           "Icon-Small@3x.png",
         },

       },
    },

}
```

您不需要在`plist`中包含`iTunesArtwork@2x`图片，但请确保将其插入到应用程序的基础项目文件夹中。

# 是时候行动了——为 App Store 设置您的分发证书和配置文件。

我们一直专注于创建开发证书和配置文件，以便在设备上测试和调试我们的应用程序。现在，我们需要创建它们的分发版本，以便提交 iOS 应用程序。请注意，苹果公司可能会随时更改其网站的设计。因此，如果步骤和屏幕截图不匹配，请不要感到沮丧：

1.  登录到你的 Apple 开发者账户，然后进入**证书、标识符和配置文件**。点击**App IDs**。在右上角选择**+**图标创建新的 App ID，并创建与应用程序相关的描述以便于识别。如果你在开发过程中已经使用了一个现有的 App ID，可以跳过这一步。![行动时间——为 App Store 设置你的分发证书和配置文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_01.jpg)

1.  在**配置文件**下点击**分发**。选择**分发**部分下的**+**按钮，然后选择**App Store**。按下**继续**。

1.  选择你希望与文件关联的 App ID，并点击**继续**。接下来，选择将与你配置文件关联的证书，并点击**继续**。

1.  为你的配置文件提供一个名称，并选择**生成**按钮。

1.  在下一个屏幕上，点击**下载**按钮，然后双击文件将其安装在你的机器上。

## *刚才发生了什么？*

你使用的 App ID 对于标识你将要提交的应用至关重要。最好使用独特的反向域名风格字符串。确保为 Corona 应用创建明确的 App ID。不要使用通配符 App ID。

为了在 App Store 上分发，你需要创建一个 App Store 分发配置文件和一个生产证书。任何开发配置文件都不会被接受。这个过程与创建开发配置文件和开发证书类似。

你可以在 Apple 开发者网站上的[`developer.apple.com/ios/manage/distribution/index.action`](https://developer.apple.com/ios/manage/distribution/index.action)（如果你还没有登录，系统会要求你登录到你的 Apple 开发者账户）和 Corona Labs 网站上的[`docs.coronalabs.com/guide/distribution/iOSBuild/index.html`](http://docs.coronalabs.com/guide/distribution/iOSBuild/index.html)找到更多关于分发配置文件的信息。

# iTunes Connect

iTunes Connect 是一套基于网络的工具，允许你提交和管理在 App Store 上分发的应用程序。在 iTunes Connect 中，你将能够检查合同的状态；设置你的税务和银行信息；获取销售和财务报告；请求促销代码；以及管理用户、应用程序、元数据和你的应用内购买目录。

## 合同、税务和银行

如果你打算出售你的应用，你需要有一个付费的商业协议，以便它可以被发布到 App Store。你将需要申请一个关于 iOS 付费应用的合同。所有这些都可以通过 iTunes Connect 下的**合同**、**税务**和**银行**链接完成。

当请求合同时，要注意可能发生的问题，比如苹果首次处理你的信息时产生的延迟，或在 iTunes Connect 中更改当前联系信息时（例如，如果你搬到不同的地点，更改地址）的问题。你有责任定期联系苹果支持，确保合同中的信息始终是最新的。

# 行动时间——在 iTunes Connect 中管理你的应用

我们现在将介绍如何在 iTunes Connect 中设置应用信息。任何关于用户账户、合同和银行的其他信息，你可以在[`developer.apple.com/app-store/review/`](https://developer.apple.com/app-store/review/)找到。

1.  在 [`itunesconnect.apple.com/`](http://itunesconnect.apple.com/) 登录 iTunes Connect。你的登录信息与你的 iOS 开发者账户相同。登录后，选择**管理你的应用**。点击**添加新应用**按钮。**应用名称**是你的应用的名称。**SKU 编号**是应用唯一的字母数字标识符。**捆绑 ID**是在 iOS 供应门户中创建的那个。填写信息并点击**继续**：![行动时间——在 iTunes Connect 中管理你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_02.jpg)

1.  下一步是选择你希望应用在 App Store 上线的时间和想要的**价格层级**。有一个可选的**对教育机构打折**复选框。这只适用于那些希望为教育机构同时购买多份应用副本时打折的情况。完成后，点击**继续**：![行动时间——在 iTunes Connect 中管理你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_03.jpg)

1.  接下来，填写关于你应用的**元数据**部分。这包括版本号、游戏描述、分类、与应用相关的关键词、版权、联系方式和支持网址：![行动时间——在 iTunes Connect 中管理你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_04.jpg)

1.  **评级**部分基于你的应用内容。对于每个描述，选择最能描述你应用频率的级别。某些内容类型会导致自动拒绝，比如应用中描绘的现实暴力或针对个人或团体的个人攻击。你可以了解更多关于*App Store 审核指南*的信息，请访问[`developer.apple.com/appstore/resources/approval/guidelines.html`](https://developer.apple.com/appstore/resources/approval/guidelines.html)。![行动时间——在 iTunes Connect 中管理你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_05.jpg)

1.  如前文**上传**部分所述，你需要一个大型应用图标版本，即 iPhone/iPod Touch 截图和 iPad 截图（如果应用在 iPad 上运行）。

1.  你将看到一个关于你的应用程序信息的页面摘要。检查显示的信息是否正确，然后点击**完成**：![行动时间 – 在 iTunes Connect 中管理你的应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_06.jpg)

1.  你将被送回到版本详细信息页面。注意一个写着**准备上传二进制文件**的按钮。点击该按钮，你将需要回答关于**出口** **合规性**的几个问题。完成后，你将获得通过**应用程序** **加载器**上传二进制文件的权利。![行动时间 – 在 iTunes Connect 中管理你的应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_07.jpg)

## *刚才发生了什么？*

iTunes Connect 是你在此后管理应用程序并分发到 App Store 的地方。你想要展示关于应用程序的每一块信息都是通过 iTunes Connect 完成的。

一旦进入**应用程序信息**部分，请确保你的**SKU 编号**是唯一的，并且与你的应用程序相关，这样你以后可以识别它。同时，确保你为应用程序指定的**捆绑** **ID**是正确的。

在**权利和定价**部分，应用程序的可用性控制了当你提交的应用一旦获得批准，你希望它何时上线。设置一个从提交日期起几周后的日期是一个好选择。只要提交没有问题，从**审核中**到**准备销售**的审核过程可能需要几天到几周的时间。价格层级是你为应用程序设置价格的地方，也可以设置为**免费**。你可以点击**查看定价矩阵**来确定你希望出售应用程序的价格。

**元数据**部分的信息是用户在 App Store 中将看到的内容。**评级**部分与 Apple 内容描述有关。确保将频率级别选择得尽可能接近你的应用程序内容。

**上传**部分是你添加 1024 x 1024 像素的应用程序图标和视觉上最适合你应用程序的截图的地方。确保你提供正确的图片尺寸。当你回到**应用程序信息**屏幕后，你会注意到状态显示为**准备上传**。当你在**版本详细信息**页面上点击**准备上传二进制文件**按钮时，你将回答关于**出口合规性**的问题。之后不久，状态将变为**等待上传**。

有关 iTunes Connect 的更多信息可以在 [`developer.apple.com/library/ios/iTunesConnectGuide`](http://developer.apple.com/library/ios/iTunesConnectGuide) 找到。

# 在 Corona 中构建用于分发的 iOS 应用程序

我们已经进入了将您的 iOS 应用程序提交到 App Store 的最后阶段。假设您已经测试了您的应用程序，并使用开发配置文件进行了调试，那么您现在可以创建一个分发构建，这将生成您应用程序的二进制 ZIP 文件。

# 是时候行动了——构建您的应用程序并将其上传到应用程序加载器。

是时候创建最终的 iOS 分发游戏构建，并将其上传到应用程序加载器，以便在苹果公司的审查下进行审核。

1.  启动 Corona 模拟器，导航到应用程序项目文件夹，并运行它。前往 Corona 模拟器的菜单栏，然后选择**文件** | **构建** | **iOS**。填写您的所有应用程序详细信息。确保您的**应用程序名称**和**版本**字段与您的 iTunes Connect 账户中显示的内容相匹配。选择**设备**以构建应用程序包。接下来，从**支持设备**下拉菜单中选择您的应用程序所针对的目标设备（iPhone 或 iPad）。在**代码签名身份**下拉菜单下，选择您在 iOS 配置门户中创建的**分发** **配置文件**选项。在**保存到文件夹**部分，点击**浏览**并选择您希望保存应用程序的位置。完成后点击**构建**按钮：![是时候行动了——构建您的应用程序并将其上传到应用程序加载器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_08.jpg)

1.  当构建完成后，您将看到显示您的应用程序已准备好分发的界面。选择**上传到 App Store**按钮。

1.  当**欢迎使用应用程序加载器**窗口弹出时，使用您的 iTunes Connect 信息登录。然后您将被带到另一个窗口，窗口中有**交付您的 App**或**创建新包**选项。选择**交付您的 App**。下一个窗口显示一个下拉菜单；选择您将提交的应用程序的名称，然后点击**下一步**按钮。

1.  在 iTunes Connect 中显示的可用应用程序信息。验证其正确无误后，点击**选择**按钮。

1.  点击省略号（**…**）按钮，在提交之前替换当前文件，然后选择**发送**按钮。

1.  应用程序加载器将开始将您应用程序的二进制文件提交到 App Store。

1.  如果您的二进制文件上传成功，您将收到确认您的应用程序已送达 App Store 的消息。当您的应用程序进入审查、准备销售、上线等状态时，您可以在 iTunes Connect 中检查应用程序的状态。每次应用程序状态发生变化时，都会向您发送电子邮件。就是这样！这就是您如何将应用程序提交到 App Store 的方法！

1.  当你的应用经过审核并获得 App Store 批准后，你可以进入 iTunes Connect，如果批准时间早于你提出的发布日期，可以调整可用日期。你的应用将立即在 App Store 上线：![行动时间——构建你的应用程序并将其上传到 Application Loader](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_09.jpg)

## *刚才发生了什么？*

当你在**代码签名标识**下构建你的应用时，重要的是选择为你分发构建创建的分发配置文件。在你的构建编译完成后，你可以启动 Application Loader。确保你已经安装了 Xcode。在选择**上传到 App Store**按钮后，Application Loader 将立即启动。

当你处于 Application Loader 中时，一旦你将二进制信息加载到 iTunes Connect，应用的名字就会显示在下拉菜单中。当你交付应用时，从你保存文件的地点选择压缩后的二进制文件。

文件上传后，确认窗口会出现，同时一封电子邮件会发送到分配给你 Apple 账户的 Apple ID。你的二进制文件将在 iTunes Connect 中显示为**等待审核**状态。

完成所有这些步骤后，你现在知道如何将 iOS 应用提交到 App Store 了。万岁！

## 尝试英雄——制作一个通用的 iOS 构建版本。

如果你只为 iPhone 开发了应用，尝试也实现一个 iPad 版本，这样它就可以成为一个通用构建版本。利用你在前面章节中学到的知识，使用你的 `build.settings` 和 `config.lua` 文件调整你的应用程序大小。同时，也不要忘记你的应用图标的要求。这可谓是一石二鸟！

# Google Play 商店

Google Play 商店是一个发布平台，可以帮助你宣传、销售和向全球用户分发你的 Android 应用。

要注册成为 Google Play 开发者并开始发布应用，请访问 Google Play Android 开发者控制台发布商网站。你可以在[`play.google.com/apps/publish/`](https://play.google.com/apps/publish/)注册一个账户。

## 创建启动器图标

启动器图标是代表你应用程序的图形。启动器图标由应用程序使用，并出现在用户的桌面上。它们也可以用来在应用程序中表示快捷方式。这些与为 iOS 应用程序创建的图标类似。以下是启动器图标的要求，也需要是 32 位 `.png` 格式：

+   `Icon-ldpi.png`：这是一张 120 dpi 的 36 x 36 像素图像，用于低密度屏幕。

+   `Icon-mdpi.png`：这是一张 160 dpi 的 48 x 48 像素图像，用于中等密度的屏幕。

+   `Icon-hdpi.png`：这是一张 240 dpi 的 72 x 72 像素图像，用于高密度屏幕。

+   `Icon-xhdpi.png`：这是一张 320 dpi 的 96 x 96 像素图像，用于超高密度屏幕。

+   `Icon-xxhdpi.png`：这是一个 144 x 144 像素，480 dpi 的图像，用于 xx 高密度屏幕。

+   `Icon-xxxhdpi.png`：这是一个 192 x 192 像素，640 dpi 的图像，用于 xxx 高密度屏幕。

启动器图标需要在构建应用程序时放置在你的项目文件夹中。Google Play 商店还要求你有一个 512 x 512 像素的图标版本，可以在上传构建时在开发者控制台上传。关于启动器图标的更多信息，请访问[`developer.android.com/guide/practices/ui_guidelines/icon_design_launcher.html`](http://developer.android.com/guide/practices/ui_guidelines/icon_design_launcher.html)。

# 行动时间——为 Google Play 商店签名你的应用

安卓系统要求所有安装的应用程序都必须使用持有私钥的证书进行数字签名。安卓系统使用证书来识别应用程序的作者，并在应用程序之间建立信任关系。证书不用于控制用户可以安装哪些应用程序。证书不需要由证书颁发机构签名；它可以自签名。证书可以在 Mac 或 Windows 系统上签名。

1.  在 Mac 上，前往**应用程序** | **实用工具** | **终端**。在 Windows 上，前往**开始菜单** | **所有程序** | **附件** | **命令提示符**。使用`keytool`命令，加入以下行并按下*回车*：

    ```kt
    keytool -genkey -v -keystore my-release-key.keystore -alias aliasname -keyalg RSA -validity 999999

    ```

    ### 注意

    将`my-release-key`替换为你的应用程序名称，将`aliasname`替换为相似或相同的别名。另外，如果你在`999999`之后添加任何额外的数字（即额外的 9），应用程序将显示为损坏。

    ![行动时间——为 Google Play 商店签名你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_10.jpg)

1.  系统会要求你输入一个密钥库密码。从这里，你将创建一个独特的密码，作为开发者你必须想出一个。系统会要求你重新输入它。接下来会被问及的问题将涉及到你的开发者/公司信息、位置等。全部填写。一旦填写了所需信息，你就生成了一个用于签名你的 Android 构建的关键。关于应用签名的更多信息，请访问[`developer.android.com/tools/publishing/app-signing.html`](http://developer.android.com/tools/publishing/app-signing.html)。

1.  启动 Corona 模拟器，导航到应用程序项目文件夹并运行它。前往 Corona 模拟器的菜单栏，然后选择**文件** | **构建** | **Android**。填写与你的应用程序相关的**应用名称**、**版本代码**和**版本名称**。使用 Java 方案指定一个**包**名称。从**目标应用商店**菜单中选择**Google Play**。在**密钥库**下，选择**浏览**按钮来定位你签名的私钥，然后从下拉菜单中选择你为发布构建生成的密钥。系统会提示你输入在`keytool`命令中用于签名应用程序的密钥库密码。在**密钥别名**下，从下拉菜单中选择你为密钥创建的别名名称，并在提示时输入密码。选择**浏览**按钮来选择应用程序构建的位置。完成后选择**构建**按钮：![行动时间——为 Google Play 商店签名你的应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_10_11.jpg)

## *刚才发生了什么？*

`keytool`命令会生成一个名为`my-release-key.keystore`的密钥库文件。密钥库和密钥由你输入的密码保护。密钥库包含一个单一密钥，有效期为 999999 天。别名是你在签名应用程序时稍后用来指代此密钥库的名称。

你的密钥库密码是你在 Corona 中构建应用程序时创建并必须记住的内容。如果你想要为别名名称使用不同的密码，将有一个选项。当你在终端或命令提示符中时，可以按*Enter*使用相同的密码。

当你在 Corona 中创建构建时，请确保你的版本号是一个没有特殊字符的整数。此外，你还需要确保你的`build.settings`文件中包含了`versionCode`。这个数字将与你的版本号相同。更多信息请参考第九章，*处理多设备和网络应用*。

你的构建中的 Java 方案是域名反转，加上你的产品/公司名称，再加上你的应用名称，例如，`com.mycompany.games.mygame`。

当你使用你的私钥构建应用程序，并选择了一个别名名称后，`.apk`文件将被创建，并准备好发布到 Google Play 商店。

# 行动时间——向 Google Play 商店提交应用

我们将使用开发者控制台。这是创建开发者资料以发布到 Google Play 商店的地方。

1.  登录到开发者控制台后，点击 Android 图标并选择标有**添加新应用**的按钮。你将看到一个弹出窗口，允许你上传你的构建版本。从下拉菜单中选择你的默认语言，并在**标题**下输入你的应用名称。点击**上传 APK**按钮进入下一页。行动时间 – 向 Google Play 商店提交应用

1.  点击**将你的第一个 APK 上传到生产环境**，然后点击**浏览文件**以找到你的应用的`.apk`文件。选择**打开**按钮以上传你的文件。行动时间 – 向 Google Play 商店提交应用

1.  上传`.apk`文件后，选择**商店列表**标签。填写你应用的相关信息，包括**标题**、**简短描述**和**完整描述**：行动时间 – 向 Google Play 商店提交应用

1.  在图形资产部分，添加你的应用屏幕截图。至少需要两张截图才能提交你的应用。其他需要的强制性图形包括**高分辨率图标**和**功能图形**。

1.  分类、联系详情和隐私政策部分需要处理。确保你完成这些部分，并在转到下一个标签之前点击页面顶部的**保存**按钮。

1.  选择**定价与分销**标签。选择与应用相关的信息。定价默认设置为**免费**。如果你想制作付费版本，你必须与 Google Checkout 设置一个商家账户。完成后点击**保存**：行动时间 – 向 Google Play 商店提交应用

1.  填写完所有与应用相关的信息后，请确保 APK、商店列表和定价与分销标签旁边有绿色的勾选标记。

1.  最后，点击**准备发布**按钮，并在下拉菜单中选择**发布此应用**。恭喜你！你刚刚将你的应用发布到了 Google Play 商店！！行动时间 – 向 Google Play 商店提交应用

## *刚才发生了什么？*

开发者控制台页面展示了一个简单的分步流程，指导你如何发布`.apk`文件。

发布应用所需的资产在每部分旁边显示了可接受的分辨率和图像类型。包括促销图形、功能图形和促销视频是可选的，但为了你的最佳利益，最好为你的应用页面添加足够的实质内容。这将使它吸引潜在客户。

完成所有与应用相关的信息后，确保保存你的进度。选择**发布此应用**菜单后，你就完成了！你应该能在你发布后的小时内看到你的应用在 Google Play 商店中。

## 尝试英雄 – 添加更多促销信息

Google Play 商店为你提供了许多推广应用程序的方式。可以从开发者控制台添加额外的资源。尝试以下方法：

+   添加宣传图像作为展示你应用程序的市场推广工具。

+   添加一个功能图像。

+   创建你的应用程序的宣传视频。像 YouTube 这样的网站是分享你的游戏预告片的好方式。

## 小测验 - 发布应用程序

Q1. 创建 iOS 分发配置文件时，你需要使用哪种分发方法？

1.  开发

1.  应用商店

1.  Ad hoc

1.  以上都不是

Q2. 你在哪里查看提交的 iOS 应用程序的状态？

1.  iTunes Connect

1.  iOS 配置门户

1.  应用程序加载器

1.  以上都不是

Q3. 为 Google Play 商店构建应用程序需要什么？

1.  使用 `keytool` 命令创建一个私钥

1.  使用调试密钥为你的应用程序签名

1.  使用你的私钥为应用程序签名

1.  a 和 c

# 总结

通过本章的学习，我们已经完成了一个巨大的里程碑。我们不仅学会了如何提交到一个，而是两个主要的应用市场！最终，将你的应用程序发布到 App Store 和 Google Play 商店并不那么可怕。

我们已经涵盖了以下主题：

+   内存效率的重要性

+   创建用于向 App Store 分发的配置文件

+   管理 iTunes Connect

+   向应用程序加载器提交二进制文件

+   为 Android 应用程序签署发布构建

+   向 Google Play 商店提交 `.apk` 文件

在下一章中，我们将看看 iOS 平台的 Apple iTunes 商店中的应用内购买。


# 第十一章：实现 应用内购买

> *应用内购买是开发者可以选择使用的一个功能，可以直接在应用中嵌入商店。有时，你可能希望扩展当前游戏的一些功能，以保持玩家的兴趣。现在就是你的机会，也许还能让你的口袋里收入更多！*

本章仅关注 iOS 平台上 Apple iTunes Store 的应用内购买。希望在应用中实现应用内购买的 Android 开发者可以参考相关内容。iOS 和 Android 的应用内购买设置方式类似。但是，在 `build.settings` 文件和代码中需要设置一些不同之处。

### 注意

这里使用的应用程序界面经常更新。但无论你使用的是哪种界面，你都能完成所有步骤。

我们将在本章介绍以下内容：

+   消耗性、非消耗性和订阅购买

+   进行交易

+   恢复已购项目

+   初始化 Corona 的商店模块

+   在设备上创建和测试应用内购买

准备，设定，出发！

# 应用内购买的奇妙之处

实施应用内购买的目的在于为应用添加应用内支付功能，以收取增强功能或游戏内可使用的额外内容的费用。以下是将此功能融入应用的选择：

+   提供除默认内容之外的全新关卡包进行游戏的应用

+   允许你通过购买虚拟货币在游戏过程中创建或建立新资产的高级游戏

+   添加额外的角色或特殊能力提升以增强游戏元素

以下是一些可以使用应用内购买实现的示例。

应用内购买允许用户在应用程序内购买额外内容。App Store 只管理交易信息。开发者不能使用 App Store 传送内容。因此，你可以在发布应用时捆绑内容（购买后即可解锁），或者如果你希望传送内容，需要自己设计下载数据的系统。

## 应用内购买的类型

你可以在应用中使用几种不同的应用内购买类型。

### 注意

你可以在 Apple 网站上找到更多关于应用内购买的信息，地址为[`developer.apple.com/library/ios/documentation/LanguagesUtilities/Conceptual/iTunesConnectInAppPurchase_Guide/Chapters/CreatingInAppPurchaseProducts.html`](https://developer.apple.com/library/ios/documentation/LanguagesUtilities/Conceptual/iTunesConnectInAppPurchase_Guide/Chapters/CreatingInAppPurchaseProducts.html)。

+   **消耗性**：这些是用户每次需要该物品时都必须购买的产品。它们通常是单次服务，如在需要支付建造建筑物的供应品的游戏中使用的货币。

+   **非消耗性**：这些是用户只需购买一次的产品。这些可能是游戏中的附加关卡包。

+   **自动续订订阅**：这些产品允许用户购买一定时间内的应用内内容。一个自动续订订阅的例子是一份利用 iOS 内置的自动续订功能的杂志或报纸。

+   **免费订阅**：这些用于在 Newsstand 中放置免费订阅内容。一旦用户注册了免费订阅，它将在与该用户 Apple ID 相关联的所有设备上可用。请注意，免费订阅不会过期，并且只能在启用 Newsstand 的应用中提供。

+   **非续订订阅**：与自动续订订阅类似，这些是非续订订阅，要求用户在订阅到期时每次都进行续订。你的应用必须包含识别到期发生的代码。还必须提示用户购买新的订阅。自动续订订阅则省略了这些步骤。

# Corona 的商店模块

在你的应用程序中应用应用内购买可能是一个相当令人困惑和繁琐的过程。与 Corona 集成需要调用商店模块：

```kt
store = require("store")
```

商店模块已经整合到 Corona API 中，类似于 Facebook 和游戏网络。你可以在 [`docs.coronalabs.com/daily/guide/monetization/IAP/index.html`](http://docs.coronalabs.com/daily/guide/monetization/IAP/index.html) 了解更多关于 Corona 商店模块的信息。

## store.init()

在处理应用程序中的商店交易时，必须调用 `store.init()` 函数。它激活了应用内购买，并允许你使用指定的监听函数接收回调：

```kt
store.init( listener )
```

这里唯一的参数是 `listener`。它是一个处理交易回调事件的功能函数。

以下代码块确定了在应用内购买过程中可能发生的交易状态。四种不同的状态分别是：购买、恢复、取消和失败：

```kt
function transactionCallback( event )
  local transaction = event.transaction
  if transaction.state == "purchased" then
    print("Transaction successful!")
    print("productIdentifier", transaction.productIdentifier)
    print("receipt", transaction.receipt)
    print("transactionIdentifier", transaction.identifier)
    print("date", transaction.date)

    elseif  transaction.state == "restored" then
    print("Transaction restored (from previous session)")
    print("productIdentifier", transaction.productIdentifier)
    print("receipt", transaction.receipt)
    print("transactionIdentifier", transaction.identifier)
    print("date", transaction.date)
    print("originalReceipt", transaction.originalReceipt)
    print("originalTransactionIdentifier", transaction.originalIdentifier)
    print("originalDate", transaction.originalDate)

    elseif transaction.state == "cancelled" then
    print("User cancelled transaction")

    elseif transaction.state == "failed" then
    print("Transaction failed, type:", transaction.errorType, transaction.errorString)

    else
    print("unknown event")
    end

    -- Once we are done with a transaction, call this to tell the store
    -- we are done with the transaction.
    -- If you are providing downloadable content, wait to call this until
    -- after the download completes.
    store.finishTransaction( transaction )
end

store.init( "apple", transactionCallback )
```

### event.transaction

`event.transaction` 对象包含了交易信息。

交易对象支持以下只读属性：

+   `"state"`：这是一个字符串，包含交易的状态。有效的值有 `"purchased"`、`"restored"`、`"cancelled"` 和 `"failed"`。

+   `"productIdentifier"`：这是与交易关联的产品标识符。

+   `"receipt"`：这是从 App Store 返回的唯一收据。它以十六进制字符串的形式返回。

+   `"signature"`：这是一个用于验证购买的有效字符串。对于 Google Play，它由 `"inapp_signature"` 返回。在 iOS 中，它返回 `nil`。

+   `"identifier"`：这是从 App Store 返回的唯一交易标识符。它是一个字符串。

+   `"date"`：这是交易发生的日期。

+   `"originalReceipt"`：这是从 App Store 原始购买尝试返回的唯一收据。它主要在恢复的情况下相关。它以十六进制字符串的形式返回。

+   `"originalIdentifier"`：这是从商店原始购买尝试返回的唯一交易标识符。这在恢复的情况下最为相关。它是一个字符串。

+   `"originalDate"`：这是原始交易的日期。这在恢复的情况下最为相关。

+   `"errorType"`：这是状态为`"failed"`时发生的错误类型（一个字符串）。

+   `"errorString"`：这是在`"failed"`情况下出现问题的描述性错误信息。

## store.loadProducts()

`store.loadProducts()`函数获取有关待售商品的信息。这包括每件商品的价格、名称和描述：

```kt
store.loadProducts( arrayOfProductIdentifiers, listener )
```

它的参数如下：

+   `arrayOfProductIdentifiers`：这是一个数组，每个元素包含你想要了解的应用内产品产品 ID 的字符串。

+   `listener`：这是一个回调函数，当商店完成获取产品信息时被调用

以下代码块显示了应用中可用的产品列表。可以通过`loadProductsCallback()`函数获取产品信息，并判断其有效或无效：

```kt
-- Contains your Product ID's set in iTunes Connect
local listOfProducts = 
{
  "com.mycompany.InAppPurchaseExample.Consumable",
  "com.mycompany.InAppPurchaseExample.NonConsumable",
  "com.mycompany.InAppPurchaseExample.Subscription",
}

function loadProductsCallback ( event )
  print("showing valid products", #event.products)
  for i=1, #event.products do
    print(event.products[i].title)
    print(event.products[i].description)
    print(event.products[i].price)
    print(event.products[i].productIdentifier)
  end

  print("showing invalidProducts", #event.invalidProducts)
    for i=1, #event.invalidProducts do
      print(event.invalidProducts[i])
end
end

store.loadProducts( listOfProducts, loadProductsCallback )
```

### event.products

当`store.loadProducts()`返回请求的产品列表时，可以通过`event.products`属性访问产品信息数组。

产品信息，如标题、描述、价格和产品标识符，包含在表格中：

```kt
event.products
```

`event.products`数组中的每个条目支持以下字段：

+   `title`：这是项目的本地化名称

+   `description`：这是项目的本地化描述

+   `price`：这是项目的价格（作为一个数字）

+   `productIdentifier`：这是产品标识符

### event.invalidProducts

当`store.loadProducts()`返回其请求的产品列表时，任何你请求的不可售产品将以数组形式返回。你可以通过`event.invalidProducts`属性访问无效产品的数组。

这是一个 Lua 数组，包含从`store.loadProducts()`请求的产品标识符字符串：

```kt
event.invalidProducts
```

## store.canMakePurchases

`store.canMakePurchases`函数如果允许购买则返回 true，否则返回 false。Corona 的 API 可以检查是否可以进行购买。iOS 设备提供了一个禁用购买的设置。这可以用来避免意外购买应用。

```kt
    if store.canMakePurchases then
      store.purchase( listOfProducts )
    else
      print("Store purchases are not available")
    end
```

## store.purchase()

`store.purchase()`函数启动对提供的产品列表的购买交易。

这个函数将向商店发送购买请求。当商店处理完交易后，将在`store.init()`中指定的监听器将被调用：

```kt
store.purchase( arrayOfProducts )
```

它唯一的参数是`arrayOfProducts`，一个指定你想要购买的产品数组：

```kt
store.purchase{ "com.mycompany.InAppPurchaseExample.Consumable"}
```

## store.finishTransaction()

这个函数通知应用商店交易已完成。

在你完成事务处理后，必须在该事务对象上调用`store.finishTransaction()`。如果你不这样做，App Store 会认为你的事务被中断，并会在下次应用程序启动时尝试恢复它。

语法：

```kt
store.finishTransaction( transaction )
```

参数：

事务：属于你想标记为完成的事务的`transaction`对象。

示例：

```kt
store.finishTransaction( transaction )
```

## store.restore()

任何之前购买的项目，如果从设备上清除或升级到新设备，都可以在用户的账户上恢复，无需再次为产品付费。`store.restore()` API 会启动这个过程。通过使用`store.init()`注册的`transactionCallback`监听器，可以恢复事务。事务状态将是`"restored"`，然后你的应用程序可以使用事务对象的`"originalReceipt"`、`"originalIdentifier"`和`"originalDate"`字段。

```kt
store.restore()
```

该代码块将通过`transactionCallback()`函数运行，并确定之前是否从应用程序购买过产品。如果结果为真，`store.restore()`将启动获取产品的过程，而无需让用户再次付费：

```kt
function transactionCallback( event )
  local transaction = event.transaction
  if transaction.state == "purchased" then
    print("Transaction successful!")
    print("productIdentifier", transaction.productIdentifier)
    print("receipt", transaction.receipt)
    print("transactionIdentifier", transaction.identifier)
    print("date", transaction.date)

  elseif  transaction.state == "restored" then
    print("Transaction restored (from previous session)")
    print("productIdentifier", transaction.productIdentifier)
    print("receipt", transaction.receipt)
    print("transactionIdentifier", transaction.identifier)
    print("date", transaction.date)
    print("originalReceipt", transaction.originalReceipt)
    print("originalTransactionIdentifier", transaction.originalIdentifier)
    print("originalDate", transaction.originalDate)

  elseif transaction.state == "cancelled" then
      print("User cancelled transaction")

  elseif transaction.state == "failed" then
    print("Transaction failed, type:", transaction.errorType, transaction.errorString)

  else
    print("unknown event")
  end

  -- Once we are done with a transaction, call this to tell the store
  -- we are done with the transaction.
  -- If you are providing downloadable content, wait to call this until
  -- after the download completes.
  store.finishTransaction( transaction )
end

store.init( transactionCallback )
store.restore()
```

# 创建应用内购买

在继续之前，请确保你知道如何从 iOS 配置门户创建 App ID 和分发配置文件。还要确保你知道如何在 iTunes Connect 中管理新应用程序。如果你不确定，请参考第十章，*优化、测试和发布你的游戏*，了解更多信息。在创建应用内购买之前，以下是你应用中需要准备的事项：

+   为你的应用已经制作好的分发证书。

+   为你的应用程序指定一个显式的 App ID，例如，`com.companyname.appname`。不要使用通配符（星号："*"）。为了使用应用内购买功能，捆绑 ID 需要完全唯一。

+   一个临时分发配置文件（用于测试应用内购买）。当你准备提交带有应用内购买的应用程序时，需要一个 App Store 分发配置文件。创建应用内购买

+   你的应用程序信息必须在 iTunes Connect 中设置。在创建或测试应用内购买时，你不需要上传你的二进制文件。

+   确保你已经与苹果公司签订了有效的 iOS 付费应用程序合同。如果没有，你需要在 iTunes Connect 主页上的**合同、税务和银行信息**中申请。你需要提供你的银行和税务信息，以便在应用中提供应用内购买。

# 动手操作——在 iTunes Connect 中创建应用内购买

我们将通过 iTunes Connect 实现应用内购买，并在示例应用程序中创建一个将调用事务的场景。让我们创建将在应用内购买中使用的产品 ID：

1.  登录到 iTunes Connect。在首页上，选择**管理您的应用程序**。选择您计划添加应用内购买的应用程序。

1.  当您在应用概览页面时，点击**管理应用内购买**按钮，然后在左上角点击**创建新购买项目**按钮。![行动时间——在 iTunes Connect 中创建应用内购买]

1.  您将看到一个页面，该页面显示了您可以创建的应用内购买类型概览。在本例中，选择了**非消耗性**。我们将创建一个只需购买一次的产品。

1.  在下一个页面，您需要填写有关产品的信息。这些信息适用于消耗性、非消耗性和非续订订阅的应用内购买。为您的产品填写**参考名称**和**产品 ID**字段。产品 ID 需要是一个唯一的标识符，可以是字母和数字的任意组合（例如，`com.companyname.appname.productid`）。

    ### 注意

    自动续订订阅需要您生成一个共享密钥。如果您要在应用中使用自动续订订阅，请在**管理应用内购买**页面上，点击**查看或生成共享密钥**链接。您将被带到生成共享密钥的页面。点击**生成**按钮。共享密钥将显示 32 个随机生成的字母数字字符。当您选择自动续订订阅时，与其他应用内购买类型的不同之处在于，您必须选择产品之间自动续订的持续时间。有关自动续订订阅的更多信息，请访问[`developer.apple.com/library/ios/iTunesConnectGuide`](http://developer.apple.com/library/ios/iTunesConnectGuide)。

    ![行动时间——在 iTunes Connect 中创建应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_03.jpg)

1.  点击**添加语言**按钮。选择将用于应用内购买的语言。为您的产品添加一个显示名称和简短描述。完成后，点击**保存**按钮。![行动时间——在 iTunes Connect 中创建应用内购买]

1.  在**定价和可用性**部分，确保**已清除销售**选项选择为**是**。在**价格层级**下拉菜单中，选择您计划销售应用内购买的价格。在本例中，选择了**层级 1**。在**审核截图**部分，您需要上传应用内购买的截图。如果您在临时版本上进行测试，则无需截图。当您准备分发时，需要上传截图以便在提交审核时对应用内购买进行审查。完成后点击**保存**按钮。![行动时间——在 iTunes Connect 中创建应用内购买]

1.  你将在下一页看到你创建的应用内购买的摘要。如果所有信息看起来都正确，请点击**完成**按钮。![动手时间——在 iTunes Connect 中创建应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_06.jpg)

## *刚才发生了什么？*

添加新的应用内购买是一个非常简单的过程。交易过程中将调用产品 ID 中包含的信息。管理应用内购买类型完全取决于你想在游戏中销售的产品类型。这个例子展示了购买/解锁游戏中一个新级别的非消耗性产品的目的。这对于想要销售关卡包的用户来说是一个常见场景。

你的应用程序不需要完成就可以测试应用内购买。需要做的是在 iTunes Connect 中设置你的应用程序信息，这样你就可以管理应用内购买的功能。

# 动手时间——使用 Corona 商店模块创建应用内购买

既然我们在 iTunes Connect 中为应用内购买设置了产品 ID，我们就可以在应用中实现它，以购买我们将要销售的产品。创建了一个 Breakout 的示例菜单应用，以演示如何在应用程序内购买关卡。该应用在关卡选择屏幕上包含两个级别。第一个默认可用。第二个被锁定，只能通过支付 0.99 美元来解锁。我们将创建一个关卡选择屏幕，使其按此方式操作：

1.  在`第十一章`文件夹中，将`Breakout 应用内购买演示`项目文件夹复制到你的桌面。你可以从 Packt Publishing 网站下载伴随这本书的项目文件。你会注意到，配置、库、资源和`.lua`文件都已包含。

1.  创建一个新的`levelselect.lua`文件并将其保存到项目文件夹中。

1.  使用以下变量和保存/加载函数设置场景。最重要的变量是`local store = require("store")`，它调用应用内购买的商店模块：

    ```kt
    local composer = require( "composer" )
    local scene = composer.newScene()

    local ui = require("ui")
    local movieclip = require( "movieclip" )
    local store = require("store")

    ---------------------------------------------------------------------------------
    -- BEGINNING OF YOUR IMPLEMENTATION
    ---------------------------------------------------------------------------------

    local menuTimer

    -- AUDIO
    local tapSound = audio.loadSound( "tapsound.wav" )

    --***************************************************

    -- saveValue() --> used for saving high score, etc.

    --***************************************************
    local saveValue = function( strFilename, strValue )
      -- will save specified value to specified file
      local theFile = strFilename
      local theValue = strValue

      local path = system.pathForFile( theFile, system.DocumentsDirectory )

      -- io.open opens a file at path. returns nil if no file found
      local file = io.open( path, "w+" )
      if file then
        -- write game score to the text file
        file:write( theValue )
        io.close( file )
      end
    end

    --***************************************************

    -- loadValue() --> load saved value from file (returns loaded value as string)

    --***************************************************
    local loadValue = function( strFilename )
      -- will load specified file, or create new file if it doesn't exist

      local theFile = strFilename

      local path = system.pathForFile( theFile, system.DocumentsDirectory )

      -- io.open opens a file at path. returns nil if no file found
      local file = io.open( path, "r" )
      if file then
        -- read all contents of file into a string
        local contents = file:read( "*a" )
        io.close( file )
        return contents
      else
        -- create file b/c it doesn't exist yet
        file = io.open( path, "w" )
        file:write( "0" )
        io.close( file )
        return "0"
      end
    end

    -- DATA SAVING
    local level2Unlocked = 1
    local level2Filename = "level2.data"
    local loadedLevel2Unlocked = loadValue( level2Filename )
    ```

1.  创建一个`create()`事件，并移除`"mainmenu"`、`"level1"`和`"level2"`场景：

    ```kt
    -- Called when the scene's view does not exist:
    function scene:create( event )
      local sceneGroup = self.view

      -- completely remove maingame and options
      composer.removeScene( "mainmenu" )
      composer.removeScene( "level1" )
      composer.removeScene( "level2" )

      print( "\nlevelselect: create event" )
    end
    ```

1.  接下来，创建一个`show()`事件和一个数组，其中包含设置为 iTunes Connect 中应用内购买的**产品 ID**的字符串：

    ```kt
    function scene:show( event )
      local sceneGroup = self.view

      print( "levelselect: show event" )

      local listOfProducts = 
      {
        -- These Product IDs must already be set up in your store
        -- Replace Product ID with a valid one from iTunes Connect
        "com.companyname.appname.NonConsumable", -- Non Consumable In-App Purchase
      }
    ```

1.  为`validProducts`和`invalidProducts`添加一个本地空表。创建一个名为`unpackValidProducts()`的本地函数，检查有效的和无效的产品 ID：

    ```kt
      local validProducts = {} 
        local invalidProducts = {}

        local unpackValidProducts = function()
            print ("Loading product list")
            if not validProducts then
                native.showAlert( "In-App features not available", "initStore() failed", { "OK" } )
            else
              print( "Found " .. #validProducts .. " valid items ")
                for i=1, #invalidProducts do
                  -- Debug:  display the product info 
                    native.showAlert( "Item " .. invalidProducts[i] .. " is invalid.",{ "OK" } )
                    print("Item " .. invalidProducts[i] .. " is invalid.")
                end

            end
        end
    ```

1.  创建一个名为`loadProductsCallback()`的本地函数，带有一个`event`参数。设置处理程序以使用打印语句接收产品信息：

    ```kt
      local loadProductsCallback = function( event )
        -- Debug info for testing
            print("loadProductsCallback()")
            print("event, event.name", event, event.name)
            print(event.products)
            print("#event.products", #event.products)

            validProducts = event.products
            invalidProducts = event.invalidProducts    
            unpackValidProducts ()
        end
    ```

1.  创建一个名为 `transactionCallback()` 的局部函数，带有 `event` 参数。为每个 `transaction.state` 事件可能发生的结果添加几种情况。当商店完成交易时，在函数结束前调用 `store.finishTransaction(event.transaction)`。设置另一个名为 `setUpStore()` 的局部函数，带有 `event` 参数，以调用 `store.loadProducts(listOfProducts, loadProductsCallback)`：

    ```kt
      local transactionCallback = function( event )
        if event.transaction.state == "purchased" then 
          print("Transaction successful!")
            saveValue( level2Filename, tostring(level2Unlocked) 
        elseif event.transcation.state == "restored" then 
          print("productIdentifier", event.transaction.productIdentifier)
          print("receipt", event.transaction.receipt)
          print("transactionIdentifier", event.transaction.transactionIdentifier)
          print("date", event.transaction.date)
          print("originalReceipt", event.transaction.originalReceipt)
        elseif event.transaction.state == "cancelled" then
          print("Transaction cancelled by user.")
        elseif event.transaction.state == "failed" then
          print("Transaction failed, type: ", event.transaction.errorType, event.transaction.errorString)
          local alert = native.showAlert("Failed ", infoString,{ "OK" })
        else
          print("Unknown event")
          local alert = native.showAlert("Unknown ", infoString,{ "OK" })
        end
        -- Tell the store we are done with the transaction.
        store.finishTransaction( event.transaction )
        end

        local setupMyStore = function(event)
          store.loadProducts( listOfProducts, loadProductsCallback)
          print ("After store.loadProducts(), waiting for callback")
        end
    ```

1.  设置背景和关卡**1**按钮的显示对象：

    ```kt
      local backgroundImage = display.newImageRect( "levelSelectScreen.png", 480, 320 )
      backgroundImage.x = 240; backgroundImage.y = 160
      sceneGroup:insert( backgroundImage )

      local level1Btn = movieclip.newAnim({"level1btn.png"}, 200, 60)
      level1Btn.x = 240; level1Btn.y = 100
      sceneGroup:insert( level1Btn )

      local function level1touch( event )
        if event.phase == "ended" then
          audio.play( tapSound )
          composer.gotoScene( "loadlevel1", "fade", 300  )
        end
      end
      level1Btn:addEventListener( "touch", level1touch )
      level1Btn:stopAtFrame(1)
    ```

1.  设置关卡**2**按钮的位置：

    ```kt
      -- LEVEL 2
      local level2Btn = movieclip.newAnim({"levelLocked.png","level2btn.png"}, 200, 60)
      level2Btn.x = 240; level2Btn.y = 180
      sceneGroup:insert( level2Btn )
    ```

1.  使用局部函数 `onBuyLevel2Touch(event)` 并创建一个 `if` 语句，检查 `event.phase == ended and level2Unlocked ~= tonumber(loadedLevel2Unlocked)`，以便场景切换到 `mainmenu.lua`：

    ```kt
      local onBuyLevel2Touch = function( event )
        if event.phase == "ended" and level2Unlocked ~= tonumber(loadedLevel2Unlocked) then
          audio.play( tapSound )
          composer.gotoScene( "mainmenu", "fade", 300  )
    ```

1.  在同一个 `if` 语句中，创建一个名为 `buyLevel2()` 的局部函数，带有 `product` 参数，以调用 `store.purchase()` 函数：

    ```kt
        local buyLevel2 = function ( product ) 
          print ("Congrats! Purchasing " ..product)

         -- Purchase the item
          if store.canMakePurchases then 
            store.purchase( {validProducts[1]} ) 
          else
            native.showAlert("Store purchases are not available, please try again later",  { "OK" } ) – Will occur only due to phone setting/account restrictions
          end 
        end 
        -- Enter your product ID here
         -- Replace Product ID with a valid one from iTunes Connect
     buyLevel2("com.companyname.appname.NonConsumable")

    ```

1.  添加一个 `elseif` 语句，以检查在交易完成后，是否已购买并解锁了关卡 2：

    ```kt
        elseif event.phase == "ended" and level2Unlocked == tonumber(loadedLevel2Unlocked) then
          audio.play( tapSound )
          composer.gotoScene( "loadlevel2", "fade", 300  )
        end
      end
      level2Btn:addEventListener( "touch", onBuyLevel2Touch )

      if level2Unlocked == tonumber(loadedLevel2Unlocked) then
        level2Btn:stopAtFrame(2)
      end
    ```

1.  使用 `store.init()` 激活应用内购买，并将 `transactionCallback()` 作为参数调用。同时以 500 毫秒的定时器调用 `setupMyStore()`：

    ```kt
      store.init( "apple", transactionCallback) 
        timer.performWithDelay (500, setupMyStore)
    ```

1.  创建一个**关闭**的 UI 按钮，以及一个名为 `onCloseTouch()` 的局部函数，带有事件参数。让该函数在释放**关闭**按钮时，切换到 `loadmainmenu.lua` 场景。使用 `end` 结束 `enterScene()` 事件：

    ```kt
      local closeBtn

      local onCloseTouch = function( event )
        if event.phase == "release" then

          audio.play( tapSound )
          composer.gotoScene( "loadmainmenu", "fade", 300  )

        end
      end

      closeBtn = ui.newButton{
        defaultSrc = "closebtn.png",
        defaultX = 100,
        defaultY = 30,
        overSrc = "closebtn.png",
        overX = 105,
        overY = 35,
        onEvent = onCloseTouch,
        id = "CloseButton",
        text = "",
        font = "Helvetica",
        textColor = { 255, 255, 255, 255 },
        size = 16,
        emboss = false
      }

      closeBtn.x = 80; closeBtn.y = 280
      closeBtn.isVisible = false
      sceneGroup:insert( closeBtn )

      menuTimer = timer.performWithDelay( 200, function() closeBtn.isVisible = true; end, 1 )

    end
    ```

1.  创建 `hide()` 和 `destroy()` 事件。在 `hide()` 事件中，取消 `menuTimer` 定时器。为场景事件添加所有事件监听器并 `return scene`：

    ```kt
    -- Called when scene is about to move offscreen:
    function scene:hide()

      if menuTimer then timer.cancel( menuTimer ); end

        print( "levelselect: hide event" )

      end

    -- Called prior to the removal of scene's "view" (display group)
    function scene:destroy( event )

      print( "destroying levelselect's view" )
    end

    -- "create" event is dispatched if scene's view does not exist
    scene:addEventListener( "create", scene )

    -- "show" event is dispatched whenever scene transition has finished
    scene:addEventListener( "show", scene )

    -- "hide" event is dispatched before next scene's transition begins
    scene:addEventListener( "hide", scene )

    -- "destroy" event is dispatched before view is unloaded, which can be
    scene:addEventListener( "destroy", scene )

    return scene
    ```

1.  保存文件，并在 Corona 模拟器中运行项目。当你点击**播放**按钮时，你会在关卡选择屏幕上注意到一个**1**按钮和一个**锁定**按钮。当你按下**锁定**按钮时，它会调用商店进行交易。你会在终端中注意到一条打印语句，显示正在参考哪个**产品 ID**进行购买。完整的内购功能无法在模拟器中测试。你将需要创建一个发行版本，并在 iOS 设备上上传以在商店中发起购买。![行动时间 – 使用 Corona 商店模块创建应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_07.jpg)

## *刚才发生了什么？*

在此示例中，我们使用了 BeebeGames 类中的 `saveValue()` 和 `loadValue()` 函数，来实现如何通过电影剪辑作为按钮，使我们的锁定关卡从锁定模式转变为解锁模式。`local listOfProducts` 中的数组以字符串格式显示**产品 ID**。在此示例中，产品 ID 需要是一种非消耗性应用内购买类型，并且必须在 iTunes Connect 中已存在。

`unpackValidProducts()`函数检查应用内购买中有多少有效和无效的商品。`loadProductsCallback()`函数接收商店中的产品信息。`transactionCallback(event)`函数检查每种状态：`"purchased"`，`"restored"`，`"cancelled"`和`"failed"`。在应用内购买中实现`"purchased"`状态时，会调用`saveValue()`函数来更改`level2.data`的值。交易完成后，需要调用`store.finishTransaction(event.transaction)`来告诉商店你的购买已经完成。

`setupMyStore(event)`函数调用`store.loadProducts(listOfProducts, loadProductsCallback)`并检查应用程序中可用的产品 ID（或 IDs）。一旦`store.init(transactionCallback)`初始化并调用`setupMyStore()`，事件就会被处理。

`onBuyLevel2Touch(event)`函数允许我们检查是否已为锁定级别进行了应用内购买。当用户能够购买并接受应用内购买时，将处理交易，`level2Unlocked`的值将与`tonumber(loadedLevel2Unlocked)`相匹配。`buyLevel2(product)`函数一旦产品 ID 返回有效，就会使用`store.purchase()`验证购买的商品。

应用内购买完成后，屏幕会过渡到主菜单，允许**锁定**按钮变为级别**2**的按钮。一旦按钮变为帧 2，级别 2 就可以访问了。

## 尝试英雄——处理多个产品 ID

既然你知道如何为单一产品创建应用内购买，尝试为同一应用程序添加多个产品。场景是开放式的。

你可以添加以下内容：

+   更多可供购买的级别

+   如果你的游戏有主角，可以设置多种角色供用户扮演。

+   为你的应用程序添加新的背景场景

你如何处理商店的新产品完全由你决定。

# 测试应用内购买

你需要确保购买能够正确进行。苹果提供了一个沙盒环境，允许你测试应用内购买。沙盒环境与 App Store 使用相同的模型，但不会处理实际支付。交易会返回，就像支付已经成功处理一样。在提交给苹果审核之前，测试应用内购买在沙盒环境中是必须的。

在沙盒环境中测试时，你需要创建一个与当前 iTunes Connect 账户不同的独立用户测试账户。在沙盒环境中测试你的商店时，不允许使用你的当前账户。

## 用户测试账户

当您登录到您的 iTunes Connect 账户时，您需要从主页选择**管理用户**链接。在**选择用户类型**页面选择**测试用户**。添加一个新用户，并确保测试账户使用的电子邮件地址没有与其他任何 Apple 账户关联。所有测试账户在测试应用内购买时只应在测试环境中使用。当所有信息填写完毕后，点击**保存**按钮。

创建用户测试账户后，您需要确保在设备的**商店**设置中已登出您的 Apple 账户。这将防止在测试应用内购买时使用非测试账户。当应用内购买沙盒提示时，您只能登录到您的用户测试账户以测试应用程序。在启动应用程序之前，不要登录到您的测试账户。这将防止它使您的测试账户无效。

# 行动时间 – 使用 Breakout 应用内购买演示测试应用内购买

在您可以在 iOS 设备上测试应用内购买之前，请确保您在 iTunes Connect 中有一个测试用户账户。同时，请确保您使用临时分发配置文件为要测试应用内购买功能的应用创建了一个分发构建。如果您按照本章前面的所有步骤操作，通过商店进行购买测试将相应地顺利进行：

1.  在 Corona 模拟器中，创建 Breakout 应用内购买演示的分发构建。一旦构建完成编译，将构建上传到您的 iOS 设备。

1.  保持设备与您的机器连接，并启动 Xcode。从工具栏中，转到**窗口** | **组织者**。一旦进入**组织者**，在**设备**部分选择已连接的设备，然后选择**控制台**。这将允许您检查设备上的控制台输出，以捕获代码中的调试信息（即打印语句）以及任何应用程序崩溃。

1.  在启动应用程序之前，您需要在设备上选择**设置**图标。向上滚动直到看到**商店**图标并选择它。![行动时间 – 使用 Breakout 应用内购买演示测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_08.jpg)

1.  如果您已登录 iTunes 商店账户，请登出，这样您就可以在沙盒环境中测试应用内购买。![行动时间 – 使用 Breakout 应用内购买演示测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_09.jpg)

1.  从您的设备上启动 Breakout 应用内购买演示。选择**播放**按钮，然后选择**锁定**按钮。屏幕将转回主菜单，并弹出一个窗口以确认您的应用内购买。按下**确定**继续购买。![行动时间 – 使用 Breakout 应用内购买演示测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_10.jpg)

1.  接下来，你将看到一个窗口，提示你使用 Apple ID 登录。在这里，你需要使用在 iTunes Connect 中创建的测试用户账户登录。不要使用用于登录 iTunes Connect 的实际 Apple 账户。![行动时间——使用 Breakout In-App Purchase Demo 测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_11.jpg)

1.  登录后，再次选择**播放**按钮。你会注意到**2**按钮已经被解锁。选择它后，你将可以访问那个场景。![行动时间——使用 Breakout In-App Purchase Demo 测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_12.jpg)

1.  退出应用程序并参考控制台。你会注意到来自设备的输出和你的代码中一些熟悉的打印语句。控制台日志显示了用于应用内购买的产品 ID，并通知你它是否有效以及交易是否成功。![行动时间——使用 Breakout In-App Purchase Demo 测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_13.jpg)

1.  如果你想要确保应用内购买确实有效，请从你的设备上删除应用程序，并退出你的测试用户账户。上传同样的版本到你的设备上——无需创建新的版本。启动应用程序并重新运行应用内购买。使用同样的测试用户账户登录。你应该会看到一个弹出窗口，提示你已经购买了该产品，并询问你是否希望再次免费下载。收到通知意味着你的应用内购买成功了。![行动时间——使用 Breakout In-App Purchase Demo 测试应用内购买](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_11_14.jpg)

## *刚才发生了什么？*

正确遵循应用内购买测试步骤非常重要。为了确保你在沙盒环境中获得准确的结果，从**商店**设置中退出你的 Apple 账户是整个流程的关键。

启动应用程序并通过按下锁定按钮调用商店功能后，你会注意到应用内购买的商品的显示名称和价格。如果你正确实现，它应该与你在 iTunes Connect 中创建的内容相匹配。

使用在 iTunes Connect 中创建的测试用户账户登录后，假设苹果服务器端没有问题或设备连接没有问题，交易应该能够顺利进行，不会出现任何错误。在关卡选择屏幕上的第 2 级将会被解锁并可以访问。恭喜你！你已经创建了一个应用内购买（In-App Purchase）。

## 动手试试——使用其他类型的应用内购买英雄*（注：此处"Have a go hero"可能指的是一种鼓励尝试的挑战，直译可能不太通顺，故保留原文，仅将"using other In-App Purchase types"翻译为“使用其他类型的应用内购买”）*。

在 Breakout In-App Purchase Demo 中，我们更关注非消耗性应用内购买。尝试将消耗性、自动续订或非续订订阅与你自己应用整合。

那些包含消耗性产品的应用是那些在免费游戏环境中需要货币购买或建造物品的游戏。订阅产品可以针对那些永不结束且不断更新新关卡的游戏，或者可能需要在线服务器在多人环境中交互的游戏。看看您能想出什么！

## 关于应用内购买的小测验。

Q1. 非消耗性购买是什么？

1.  用户只需购买一次的产品。

1.  用户每次需要该项物品时都需要购买的产品。

1.  允许用户购买一定时间期限内容的产品。

1.  用户每次到期都需要续订的订阅。

Q2. 关于测试应用内购买，以下哪个是正确的？

1.  您需要始终登录到您的账户。

1.  您的 Apple 账户用于测试应用内购买。

1.  当在应用内购买沙盒中提示时，登录您的用户测试账户。

1.  以上都不是。

Q3. 测试应用内购买必须使用哪种配置文件？

1.  开发配置文件。

1.  Ad Hoc 分发配置文件。

1.  App Store 分发配置文件。

1.  以上都不是。

# 总结。

我们终于看到了隧道尽头的光明。至此，您应该对如何在您的游戏中实现应用内购买有了初步了解。这是一个非常耗时的过程，需要组织、设置代码，并在沙盒环境中测试准确的购买。

本章节中讲解了以下内容：

+   如何在 iTunes Connect 中为应用内购买设置产品 ID。

+   使用 Corona 的商店模块实现购买项目。

+   在 iTunes Connect 中添加测试用户账户。

+   在设备上测试应用内购买。

掌握应用内购买的概念可能需要一些时间。最好研究示例代码，并查看与 Corona 的商店模块相关的功能。

请查看苹果的*应用内购买编程指南*：[`developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/StoreKitGuide/StoreKitGuide.pdf`](https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/StoreKitGuide/StoreKitGuide.pdf)，以及 Corona Labs 网站 API 参考部分中的应用内购买，了解更多关于此话题的参考资料。

经过 11 章的学习，我们已经到了这本书的结尾。现在，您已经获得了足够的知识来创建自己的应用程序，并在 Apple App Store 或 Google Play Store 中销售。希望您获得的所有信息都能有所帮助。我期待听到您使用 Corona SDK 开发的游戏！


# 附录 A. 小测验答案

# 第一章：– 开始使用 Corona SDK

## 小测验 – 了解 Corona

| Q1 使用 Corona 模拟器有哪些正确之处？ | 1 |
| --- | --- |
| Q2 在 iPhone 开发者计划中，你可以使用多少个 iOS 设备进行开发？ | 4 |
| Q3 使用 Corona SDK 为 Android 构建时，版本代码需要是什么？ | 2 |

# 第二章：– Lua 速成课程和 Corona 框架

## 小测验 – Lua 基础

| Q1 以下哪些是值？ | 4 |
| --- | --- |
| Q2 哪个关系运算符是错误的？ | 3 |
| Q3 正确缩放对象在*x*方向的方法是什么？ | 4 |

# 第三章：– 建立我们的第一个游戏 – Breakout

## 小测验 – 构建游戏

| Q1 在代码中添加物理引擎时，哪些函数可以添加到你的应用程序中？ | 4 |
| --- | --- |
| Q2 添加事件监听器时以下哪个是正确的？ | 4 |
| Q3 以下显示对象正确过渡到`x = 300`, `y = 150`并将 alpha 改为 0.5，需要 2 秒的方法是什么？ | 1 |

# 第四章：– 游戏控制

## 小测验 – 使用游戏控制

| Q1 正确从舞台移除显示对象的方法是什么？ | 3 |
| --- | --- |

| Q2 将以下显示对象正确转换为物理对象的方法是什么？ |

```kt
local ball = display.newImage("ball.png")
```

| 3 |
| --- |

| Q3 在以下函数中，`"began"`最好表示什么意思？ |

```kt
local function onCollision( event )
  if event.phase == "began" and event.object1.myName == "Box 1" then

    print( "Collision made." )

  end
end
```

| 4 |
| --- |

# 第五章：– 让我们的游戏动起来

## 小测验 – 动画图形

| Q1 正确暂停图像表动画的方法是什么？ | 1 |
| --- | --- |
| Q2 如何使动画序列无限循环？ | 3 |
| Q3 如何创建一个新的图像表？ | 4 |

# 第六章：– 播放声音和音乐

## 小测验 – 关于音频的一切

| Q1 正确清除内存中音频文件的方法是什么？ | 3 |
| --- | --- |
| Q2 应用程序中可以同时播放多少个音频通道？ | 4 |
| Q3 如何使音频文件无限循环？ | 1 |

# 第七章：– 物理 – 下落物体

## 小测验 – 动画图形

| Q1 有哪个功能可以获取或设置文本对象的文本字符串？ | 1 |
| --- | --- |
| Q2 有哪个函数能将任何参数转换成字符串？ | 3 |
| Q3 哪种体型受到重力和其他体型碰撞的影响？ | 1 |

# 第八章：– 操作 Composer

## 小测验 – 游戏过渡和场景

| Q1 使用 Composer 改变场景时需要调用哪个函数？ | 2 |
| --- | --- |
| Q2 有哪个函数能将任何参数转换成数字或 nil？ | 1 |
| Q3 如何暂停一个计时器？ | 3 |
| Q4. 如何恢复一个计时器？ | 2 |

# 第九章：– 处理多设备和网络应用

## 小测验 – 处理社交网络

| Q1 缩放高分辨率精灵表的特定 API 是什么？ | 2 |
| --- | --- |
| Q2 在 Facebook 上允许在用户墙发布内容的发布权限叫什么？ | 2 |
| Q3 `facebook.login()`需要哪些参数？ | 4 |

# 第十章：– 优化、测试和发布你的游戏

## 小测验 – 发布应用

| Q1 创建 iOS Distribution Provisioning 文件时，需要使用哪种分发方法？ | 2 |
| --- | --- |
| Q2 提交的 iOS 应用程序的状态应在哪里查询？ | 1 |
| Q3 在 Google Play 商店中构建应用需要什么？ | 4 |

# 第十一章：– 实现应用内购买

## 突击测验 – 关于应用内购买的一切

| Q1 非消耗性购买是什么？ | 1 |
| --- | --- |
| Q2 关于测试应用内购买，以下哪项是正确的？ | 3 |
| Q3 测试应用内购买必须使用哪种类型的 Provisioning Profile？ | 2 |
