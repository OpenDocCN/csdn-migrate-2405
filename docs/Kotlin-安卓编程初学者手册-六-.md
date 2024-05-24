# Kotlin 安卓编程初学者手册（六）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：动画和插值

在这里，我们将看到如何使用`Animation`类使我们的 UI 不那么静态，更有趣。正如我们所期望的那样，Android API 将允许我们用相对简单的代码做一些相当高级的事情，`Animation`类也不例外。

本章大致可分为以下几个部分：

+   介绍了 Android 中动画的工作原理和实现方式

+   介绍了一个我们尚未探索的 UI 小部件`SeekBar`类

+   一个有效的动画应用程序

首先，让我们探索一下 Android 中的动画是如何工作的。

# Android 中的动画

在 Android 中创建动画的常规方式是通过 XML。我们可以编写 XML 动画，然后通过 Kotlin 代码在指定的 UI 小部件上加载和播放它们。因此，例如，我们可以编写一个动画，在三秒内淡入淡出五次，然后在`ImageView`或任何其他小部件上播放该动画。我们可以将这些 XML 动画看作脚本，因为它们定义了类型、顺序和时间。

让我们探索一些可以分配给我们的动画的不同属性，如何在我们的 Kotlin 代码中使用它们，最后，我们可以制作一个漂亮的动画应用程序来尝试一切。

## 在 XML 中设计酷炫的动画

我们已经了解到 XML 不仅可以用来描述 UI 布局，还可以用来描述动画，但让我们确切地了解一下。我们可以为动画的属性值指定起始和结束外观的小部件。然后，我们的 Kotlin 代码可以通过引用包含动画的 XML 文件的名称来加载 XML，将其转换为可用的 Kotlin 对象，再次，与 UI 布局类似。

许多动画属性成对出现。以下是一些我们可以使用的动画属性对的快速查看。在查看了一些 XML 后，我们将看到如何使用它。

### 淡入淡出

Alpha 是透明度的度量。因此，通过说明起始`fromAlpha`和结束`toAlpha`值，我们可以淡入淡出物品。值`0.0`是不可见的，`1.0`是对象的正常外观。在两者之间稳定移动会产生淡入效果：

```kt
<alpha
   android:fromAlpha = "0.0"
   android:toAlpha = "1.0" />
```

### 移动它，移动它

我们可以使用类似的技术在 UI 中移动对象；`fromXDelta`和`toXDelta`的值可以设置为被动画化对象大小的百分比。

以下代码将使对象从左到右移动，距离等于对象本身的宽度：

```kt
<translate     
android:fromXDelta = "-100%"
android:toXDelta = "0%"/>
```

此外，还有用于上下移动动画的`fromYDelta`和`toYDelta`属性。

### 缩放或拉伸

`fromXScale`和`toXScale`属性将增加或减少对象的比例。例如，以下代码将使运行动画的对象从正常大小变为不可见：

```kt
<scale
android:fromXScale = "1.0"
android:fromYScale = "0.0"/>
```

作为另一个例子，我们可以使用`android:fromYScale = "0.1"`将对象缩小到通常大小的十分之一，或者使用`android:fromYScale = "10.0"`将其放大十倍。

### 控制持续时间

当然，如果这些动画只是立即结束，那将不会特别有趣。因此，为了使我们的动画更有趣，我们可以设置它们的持续时间（以毫秒为单位）。毫秒是一秒的千分之一。我们还可以通过设置`startOffset`属性（也是以毫秒为单位）来使时间更容易，特别是与其他动画相关。

下一个代码将在我们启动动画的 1/3 秒后开始（在代码中），并且需要 2/3 秒才能完成：

```kt
android:duration = "666"
android:startOffset = "333"
```

### 旋转动画

如果要使某物旋转，只需使用`fromDegrees`和`toDegrees`属性。下一个代码，可能可以预测，将使小部件在一个完整的圆圈中旋转，因为当然，一个圆圈有 360 度：

```kt
<rotate android:fromDegrees = "360"
        android:toDegrees = "0"
/>
```

### 重复动画

在一些动画中，重复可能很重要，也许是摇摆或抖动效果，因此我们可以添加一个`repeatCount`属性。此外，我们可以通过设置`repeatMode`属性来指定动画的重复方式。

以下代码将重复一个动画 10 次，每次都会反转动画的方向。`repeatMode`属性是相对于动画的当前状态。这意味着，如果你将一个按钮从 0 度旋转到 360 度，例如，动画的第二部分（第一次重复）将以相反的方式旋转，从 360 度回到 0 度。动画的第三部分（第二次重复）将再次反转，并从 0 度旋转到 360 度：

```kt
android:repeatMode = "reverse"
android:repeatCount = "10"
```

### 将动画的属性与集合结合

要组合这些效果的组，我们需要一组属性。这段代码展示了我们如何将我们刚刚看到的所有先前的代码片段组合成一个实际的 XML 动画，它将被编译：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set 
     ...All our animations go here
</set>
```

到目前为止我们还没有看到任何 Kotlin 来使这些动画生动起来。让我们现在来解决这个问题。

## 实例化动画并使用 Kotlin 代码控制它们

下面的代码片段展示了我们如何声明一个`Animation`类型的对象，用一个名为`fade_in.xml`的 XML 文件中包含的动画来初始化它，并在一个`ImageView`小部件上启动动画。我们很快将在一个项目中这样做，并且还会看到我们可以放置 XML 动画的地方：

```kt
// Declare an Animation object
var animFadeOut: Animation? = null

// Initialize it 
animFadeIn = AnimationUtils.loadAnimation(
                this, R.anim.fade_in)

// Start the animation on the ImageView
// with an id property set to imageView
imageView.startAnimation(animFadeIn)
```

我们已经有了相当强大的动画和控制特性，比如时间控制。但是 Android API 还给了我们更多的东西。

## 更多动画特性

我们可以监听动画的状态，就像我们可以监听按钮的点击一样。我们还可以使用**插值器**使我们的动画更加生动和愉悦。让我们先看看监听器。

### 监听器

如果我们实现`AnimationListener`接口，我们确实可以通过覆盖告诉我们发生了什么的三个函数来监听动画的状态。然后我们可以根据这些事件来采取行动。

`OnAnimationEnd`宣布动画结束，`onAnimationRepeat`在每次动画开始重复时调用，而-也许可以预料到-`onAnimationStart`在动画开始动画时调用。如果在动画 XML 中设置了`startOffset`，这可能不是调用`startAnimation`时的同一时间：

```kt
override fun onAnimationEnd(animation: Animation) {   
   // Take some action here

}

override fun onAnimationStart(animation: Animation) {

   // Take some action here

}

override fun onAnimationRepeat(animation: Animation){

   // Take some action here

}
```

我们将在 Animations 演示应用程序中看到`AnimationListener`的工作原理，并且我们还将把另一个小部件`SeekBar`投入使用。

### 动画插值器

如果你能回想起高中时的情景，你可能会记得关于计算加速度的激动人心的课程。如果我们以恒定的速度对某物进行动画处理，乍一看，事情可能看起来还不错。如果我们将动画与另一个使用渐进加速的动画进行比较，那么后者几乎肯定会更令人愉悦地观看。

有可能，如果我们没有被告知两个动画之间唯一的区别是一个使用了加速度，另一个没有，我们可能无法说出*为什么*我们更喜欢它。我们的大脑更容易接受符合我们周围世界规范的事物。因此，添加一点真实世界的物理，比如加速和减速，可以改善我们的动画。

然而，我们最不想做的事情是开始做一堆数学计算，只是为了将一个按钮滑动到屏幕上或者让一些文本在圆圈中旋转。

这就是**插值器**的用武之地。它们是我们可以在我们的 XML 中用一行代码设置的动画修改器。

一些插值器的例子是`accelerate_interpolator`和`cycle_interpolator`：

```kt
android:interpolator="@android:anim/accelerate_interpolator"
android:interpolator="@android:anim/cycle_interpolator"/>
```

接下来我们将投入使用一些插值器，以及一些 XML 动画和相关的 Kotlin 代码。

### 提示

您可以在 Android 开发者网站上了解有关插值器和 Android `Animation`类的更多信息：[`developer.android.com/guide/topics/resources/animation-resource.html`](http://developer.android.com/guide/topics/resources/animation-resource.html)。

# 动画演示应用程序-介绍 SeekBar

这就足够的理论了，尤其是对于应该如此明显的东西。让我们构建一个动画演示应用程序，探索我们刚刚讨论过的一切，以及更多内容。

这个应用程序涉及许多不同文件中少量的代码。因此，我已经尽量清楚地说明了哪些代码在哪个文件中，这样您就可以跟踪发生了什么。这也将使我们为这个应用程序编写的 Kotlin 更容易理解。

该应用程序将演示旋转、淡入淡出、平移、动画事件、插值和使用`SeekBar`小部件控制持续时间的功能。解释`SeekBar`的最佳方法是构建它，然后观察它的运行情况。

## 布局动画演示

使用**空活动**模板创建一个名为`Animation Demo`的新项目，将所有其他设置保持为通常的设置。如果您希望通过复制和粘贴布局、代码或动画 XML 来加快速度，可以在`Chapter19`文件夹中找到所有内容。

使用完成布局的参考截图来帮助您完成接下来的步骤：

![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_10.jpg)

以下是您可以为此应用程序布局 UI 的方法：

1.  在编辑器窗口的设计视图中打开`activity_main.xml`。

1.  删除默认的**Hello world!** `TextView`。

1.  在布局的顶部中心部分添加一个**ImageView**。使用之前的参考截图来指导您。在弹出的**资源**窗口中选择**项目** | **ic_launcher**，使用`@mipmap/ic_launcher`来在`ImageView`中显示 Android 机器人。

1.  将`ImageView`的`id`属性设置为`imageView`。

1.  在`ImageView`的正下方，添加一个`TextView`。将`id`设置为`textStatus`。我通过拖动其边缘（而不是约束手柄）使我的`TextView`变大，并将其`textSize`属性更改为`40sp`。到目前为止，布局应该看起来像下一个截图：![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_01.jpg)

1.  现在我们将在布局中添加大量的**Button**小部件。确切的定位并不重要，但稍后在教程中为它们添加的确切`id`属性值是重要的。按照下一个截图的指示，在布局中放置 12 个按钮。修改`text`属性，使您的按钮与下一个截图中的按钮具有相同的文本。如果截图不够清晰，`text`属性将在下一步中具体详细说明：![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_02.jpg)

### 提示

为了加快布局按钮的过程，首先大致布局它们，然后从下一步中添加`text`属性，最后微调按钮位置以获得整洁的布局。

1.  按照截图中的方式添加`text`值；从左到右，从上到下，这里是所有的值：`淡入`、`淡出`、`淡入淡出`、`放大`、`缩小`、`左右`、`右左`、`上下`、`弹跳`、`闪烁`、`向左旋转`和`向右旋转`。

1.  从左侧的调色板中的**小部件**类别中添加一个`SeekBar`小部件，将`id`属性设置为`seekBarSpeed`，将`max`属性设置为`5000`。这意味着`SeekBar`小部件将在用户从左向右拖动时保持一个值在 0 到 5000 之间。我们将看到如何读取和使用这些数据。

1.  我们想要让`SeekBar`小部件变得更宽。为了实现这一点，您可以使用与任何小部件相同的技术；只需拖动小部件的边缘。然而，由于`SeekBar`小部件相当小，很难增加其大小而不小心选择约束手柄。为了克服这个问题，通过按住*Ctrl*键并向前滚动鼠标滚轮来放大设计视图。然后，您可以抓住`SeekBar`小部件的边缘，而不触摸约束手柄。我在下一个截图中展示了这一点：![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_07.jpg)

1.  现在，在`SeekBar`小部件的右侧添加一个`TextView`小部件，并将其`id`属性设置为`textSeekerSpeed`。这一步，结合前两步，应该看起来像这张截图：![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_03.jpg)

1.  微调位置，使其看起来像这些步骤开始时的参考截图，然后单击**推断约束**按钮以锁定位置。当然，如果你想练习，你也可以手动完成。这是一个包含所有约束的截图：![布局动画演示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_08.jpg)

1.  接下来，根据你已经设置的文本属性，为按钮添加以下`id`属性。如果在输入这些值时询问是否要**更新用法…**，请选择**是**：

| **现有文本属性** | **要设置的 id 属性的值** |
| --- | --- |
| 淡入 | `btnFadeIn` |
| 淡出 | `btnFadeOut` |
| 淡入淡出 | `btnFadeInOut` |
| 放大 | `btnZoomIn` |
| 缩小 | `btnZoomOut` |
| 左右 | `btnLeftRight` |
| 右左 | `btnRightLeft` |
| 上下 | `btnTopBottom` |
| 弹跳 | `btnBounce` |
| 闪烁 | `btnFlash` |
| 旋转左侧 | `btnRotateLeft` |
| 旋转右侧 | `btnRotateRight` |

当我们在几节时间内编写`MainActivity`类时，我们将看到如何使用这个新来的 UI(`SeekBar`)。

## 编写 XML 动画

右键单击**res**文件夹，然后选择**新建 | Android 资源目录**。在`目录名称：`字段中输入`anim`，然后左键单击**确定**。

现在右键单击新的**anim**目录，然后选择**新建 | 动画资源文件**。在**文件名：**字段中，键入`fade_in`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set 
   android:fillAfter="true" >

   <alpha
   android:fromAlpha = "0.0"
   android:interpolator = 
              "@android:anim/accelerate_interpolator"

   android:toAlpha="1.0" />
</set>
```

右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在`文件名：`字段中，键入`fade_out`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set 
   android:fillAfter = "true" >

   <alpha  
         android:fromAlpha = "1.0"
         android:interpolator = 
              "@android:anim/accelerate_interpolator"

   android:toAlpha = "0.0" />
</set>
```

右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在`文件名：`字段中，键入`fade_in_out`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set 
    android:fillAfter = "true" >

    <alpha
          android:fromAlpha="0.0"
          android:interpolator = 
          "@android:anim/accelerate_interpolator"

          android:toAlpha = "1.0" />

    <alpha
       android:fromAlpha = "1.0"
          android:interpolator = 
         "@android:anim/accelerate_interpolator"

         android:toAlpha = "0.0" />
</set>
```

右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在`文件名：`字段中，键入`zoom_in`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<set 
    android:fillAfter = "true" >

    <scale
        android:fromXScale = "1"
        android:fromYScale = "1"
        android:pivotX = "50%"
        android:pivotY = "50%"
        android:toXScale = "6"
        android:toYScale = "6" >
    </scale>
</set>
```

右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在`文件名：`字段中，键入`zoom_out`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <scale
        android:fromXScale = "6"
        android:fromYScale = "6"
        android:pivotX = "50%"
        android:pivotY = "50%"
        android:toXScale = "1"
        android:toYScale = "1" >
    </scale>
</set>
```

右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在`文件名：`字段中，键入`left_right`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <translate     

        android:fromXDelta = "-500%"
        android:toXDelta = "0%"/>
</set>
```

再次右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在**文件名：**字段中，键入`right_left`，然后左键单击**确定**。删除整个内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <translate 
        android:fillAfter = "false"
        android:fromXDelta = "500%"
        android:toXDelta = "0%"/>
</set>
```

与以前一样，右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在**文件名：**字段中，键入`top_bot`，然后左键单击**确定**。删除整个内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <translate 
        android:fillAfter = "false"
        android:fromYDelta = "-100%"
        android:toYDelta = "0%"/>
</set>
```

你猜对了；右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在**文件名：**字段中，键入`flash`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <alpha android:fromAlpha = "0.0"
        android:toAlpha = "1.0"
        android:interpolator = 
           "@android:anim/accelerate_interpolator"

        android:repeatMode = "reverse"
        android:repeatCount = "10"/>
</set>
```

还有一些要做 - 右键单击**anim**目录，然后选择**新建 | 动画资源文件**。在**文件名：**字段中，键入`bounce`，然后左键单击**确定**。删除内容并添加以下代码来创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set 
    android:fillAfter = "true"
    android:interpolator = 
         "@android:anim/bounce_interpolator">

    <scale
        android:fromXScale = "1.0"
        android:fromYScale = "0.0"
        android:toXScale = "1.0"
        android:toYScale = "1.0" />

</set>
```

右键单击**anim**目录，然后选择**New | Animation resource file**。在**File name:**字段中，键入`rotate_left`，然后左键单击**OK**。删除内容并添加此代码以创建动画。在这里，我们看到了一些新东西，`pivotX="50%"`和`pivotY="50%"`。这使得旋转动画在将要被动画化的小部件上是中心的。我们可以将其视为设置动画的*中心*点：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <rotate android:fromDegrees = "360"
        android:toDegrees = "0"
        android:pivotX = "50%"
        android:pivotY = "50%"
        android:interpolator = 
           "@android:anim/cycle_interpolator"/>
</set>
```

右键单击**anim**目录，然后选择**New | Animation resource file**。在**File name:**字段中，键入`rotate_right`，然后左键单击**OK**。删除内容并添加此代码以创建动画：

```kt
<?xml version="1.0" encoding="utf-8"?>
<set >
    <rotate android:fromDegrees = "0"
        android:toDegrees = "360"
        android:pivotX = "50%"
        android:pivotY = "50%"
        android:interpolator =
             "@android:anim/cycle_interpolator"/>

</set>
```

呼！现在我们可以编写 Kotlin 代码将我们的动画添加到我们的 UI 中。

## 在 Kotlin 中连接动画演示应用程序

打开`MainActivity.kt`文件。现在，在类声明之后，我们可以声明以下动画属性：

```kt
var seekSpeedProgress: Int = 0

private lateinit var animFadeIn: Animation
private lateinit var animFadeOut: Animation
private lateinit var animFadeInOut: Animation

private lateinit var animZoomIn: Animation
private lateinit var animZoomOut: Animation

private lateinit var animLeftRight: Animation
private lateinit var animRightLeft: Animation
private lateinit var animTopBottom: Animation

private lateinit var animBounce: Animation
private lateinit var animFlash: Animation 

private lateinit var animRotateLeft: Animation
private lateinit var animRotateRight: Animation
```

### 提示

此时，您需要添加以下`import`语句：

```kt
import android.view.animation.Animation;
```

在上述代码中，我们在声明`Animation`实例时使用了`lateinit`关键字。这意味着 Kotlin 将在使用每个实例之前检查它是否已初始化。这避免了我们在每次在这些实例中使用函数时使用`!!`（空检查）。有关`!!`运算符的复习，请参阅第十二章*将我们的 Kotlin 连接到 UI 和空值*。

我们还添加了一个`Int`属性`seekSpeedProgress`，它将用于跟踪`SeekBar`的当前值/位置。

现在，在`setContentView`调用之后，让我们从`onCreate`中调用一个新函数：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
   super.onCreate(savedInstanceState)
   setContentView(R.layout.activity_main)

 loadAnimations()
}
```

在这一点上，新的代码行在实现新函数之前将出现错误。

现在我们将实现`loadAnimations`函数。虽然这个函数中的代码相当庞大，但也非常直接。我们所做的就是使用`AnimationUtils`类的`loadAnimation`函数，用我们的 XML 动画初始化每个`Animation`引用之一。您还会注意到，对于`animFadeIn` `Animation`，我们还在其上调用`setAnimationListener`。我们将很快编写监听事件的函数。

添加`loadAnimations`函数：

```kt
private fun loadAnimations() {

   animFadeIn = AnimationUtils.loadAnimation(
                this, R.anim.fade_in)
   animFadeIn.setAnimationListener(this)
   animFadeOut = AnimationUtils.loadAnimation(
                this, R.anim.fade_out)
   animFadeInOut = AnimationUtils.loadAnimation(
                this, R.anim.fade_in_out)

   animZoomIn = AnimationUtils.loadAnimation(
                this, R.anim.zoom_in)
   animZoomOut = AnimationUtils.loadAnimation(
                this, R.anim.zoom_out)

   animLeftRight = AnimationUtils.loadAnimation(
                 this, R.anim.left_right)
   animRightLeft = AnimationUtils.loadAnimation(
                 this, R.anim.right_left)
   animTopBottom = AnimationUtils.loadAnimation(
                 this, R.anim.top_bot)

   animBounce = AnimationUtils.loadAnimation(
                 this, R.anim.bounce)
   animFlash = AnimationUtils.loadAnimation(
                 this, R.anim.flash)

   animRotateLeft = AnimationUtils.loadAnimation(
                 this, R.anim.rotate_left)
   animRotateRight = AnimationUtils.loadAnimation(
                 this, R.anim.rotate_right)
}
```

### 提示

此时，您需要导入一个新的类：

```kt
import android.view.animation.AnimationUtils
```

现在，我们将为每个按钮添加一个点击监听器。在`onCreate`函数的右大括号之前立即添加以下代码：

```kt
btnFadeIn.setOnClickListener(this)
btnFadeOut.setOnClickListener(this)
btnFadeInOut.setOnClickListener(this)
btnZoomIn.setOnClickListener(this)
btnZoomOut.setOnClickListener(this)
btnLeftRight.setOnClickListener(this)
btnRightLeft.setOnClickListener(this)
btnTopBottom.setOnClickListener(this)
btnBounce.setOnClickListener(this)
btnFlash.setOnClickListener(this)
btnRotateLeft.setOnClickListener(this)
btnRotateRight.setOnClickListener(this)
```

### 注意

我们刚刚添加的代码在所有代码行中都创建了错误。我们现在可以忽略它们，因为我们很快就会修复它们并讨论发生了什么。

现在，我们可以使用 lambda 来处理`SeekBar`的交互。我们将重写三个函数，因为在实现`OnSeekBarChangeListener`时接口要求这样做：

+   一个检测`SeekBar`小部件位置变化的函数，称为`onProgressChanged`

+   一个检测用户开始改变位置的函数，称为`onStartTrackingTouch`

+   一个检测用户完成使用`SeekBar`小部件的函数，称为`onStopTrackingTouch`

为了实现我们的目标，我们只需要向`onProgressChanged`函数添加代码，但我们仍然必须重写它们全部。

在`onProgressChanged`函数中，我们所做的就是将`SeekBar`对象的当前值分配给`seekSpeedProgress`成员变量，以便可以从其他地方访问。然后，我们使用这个值以及`SeekBar`对象的最大可能值，通过使用`seekBarSpeed.max`，并向`textSeekerSpeed` `TextView`输出一条消息。

在`onCreate`函数的右大括号之前添加我们刚刚讨论过的代码：

```kt
seekBarSpeed.setOnSeekBarChangeListener(
         object : SeekBar.OnSeekBarChangeListener {

   override fun onProgressChanged(
                seekBar: SeekBar, value: Int, 
                fromUser: Boolean) {

         seekSpeedProgress = value
         textSeekerSpeed.text =
               "$seekSpeedProgress of $seekBarSpeed.max"
  }

  override fun onStartTrackingTouch(seekBar: SeekBar) {}

  override fun onStopTrackingTouch(seekBar: SeekBar) {}
})
```

现在，我们需要修改`MainActivity`类声明以实现两个接口。在这个应用程序中，我们将监听点击和动画事件，所以我们将使用的两个接口是`View.OnClickListener`和`Animation.AnimationListener`。您会注意到，要实现多个接口，我们只需用逗号分隔接口。

通过添加我们刚讨论过的突出显示的代码来修改`MainActivity`类声明：

```kt
class MainActivity : AppCompatActivity(),
        View.OnClickListener,
 Animation.AnimationListener {
```

在这个阶段，我们可以添加并实现这些接口所需的函数。首先是`AnimationListener`函数，`onAnimationEnd`，`onAnimationRepeat`和`onAnimationStart`。我们只需要在这些函数中的两个中添加一点代码。在`onAnimationEnd`中，我们将`textStatus`的`text`属性设置为`STOPPED`，在`onAnimationStart`中，我们将其设置为`RUNNING`。这将演示我们的动画监听器确实在监听和工作：

```kt
override fun onAnimationEnd(animation: Animation) {
   textStatus.text = "STOPPED"
}

override fun onAnimationRepeat(animation: Animation) {
}

override fun onAnimationStart(animation: Animation) {
   textStatus.text = "RUNNING"
}
```

`onClick`函数非常长，但并不复杂。`when`块的每个选项处理 UI 中的每个按钮，根据`SeekBar`小部件的当前位置设置动画的持续时间，设置动画以便监听事件，然后启动动画。

### 提示

您需要使用您喜欢的技术来导入`View`类：

```kt
import android.view.View;

```

添加我们刚讨论过的`onClick`函数，然后我们就完成了这个迷你应用程序：

```kt
override fun onClick(v: View) {
when (v.id) {
  R.id.btnFadeIn -> {
        animFadeIn.duration = seekSpeedProgress.toLong()
        animFadeIn.setAnimationListener(this)
        imageView.startAnimation(animFadeIn)
  }

  R.id.btnFadeOut -> {
        animFadeOut.duration = seekSpeedProgress.toLong()
        animFadeOut.setAnimationListener(this)
        imageView.startAnimation(animFadeOut)
  }

  R.id.btnFadeInOut -> {

        animFadeInOut.duration = seekSpeedProgress.toLong()
        animFadeInOut.setAnimationListener(this)
        imageView.startAnimation(animFadeInOut)
  }

  R.id.btnZoomIn -> {
        animZoomIn.duration = seekSpeedProgress.toLong()
        animZoomIn.setAnimationListener(this)
        imageView.startAnimation(animZoomIn)
  }

  R.id.btnZoomOut -> {
        animZoomOut.duration = seekSpeedProgress.toLong()
        animZoomOut.setAnimationListener(this)
        imageView.startAnimation(animZoomOut)
  }

  R.id.btnLeftRight -> {
        animLeftRight.duration = seekSpeedProgress.toLong()
        animLeftRight.setAnimationListener(this)
        imageView.startAnimation(animLeftRight)
  }

  R.id.btnRightLeft -> {
        animRightLeft.duration = seekSpeedProgress.toLong()
        animRightLeft.setAnimationListener(this)
        imageView.startAnimation(animRightLeft)
  }

  R.id.btnTopBottom -> {
        animTopBottom.duration = seekSpeedProgress.toLong()
        animTopBottom.setAnimationListener(this)
        imageView.startAnimation(animTopBottom)
  }

  R.id.btnBounce -> {
        /*
        Divide seekSpeedProgress by 10 because with
        the seekbar having a max value of 5000 it
        will make the animations range between
        almost instant and half a second
        5000 / 10 = 500 milliseconds
        */
        animBounce.duration = 
              (seekSpeedProgress / 10).toLong()
        animBounce.setAnimationListener(this)
        imageView.startAnimation(animBounce)
  }

  R.id.btnFlash -> {
        animFlash.duration = (seekSpeedProgress / 10).toLong()
        animFlash.setAnimationListener(this)
        imageView.startAnimation(animFlash)
  }

  R.id.btnRotateLeft -> {
        animRotateLeft.duration = seekSpeedProgress.toLong()
        animRotateLeft.setAnimationListener(this)
        imageView.startAnimation(animRotateLeft)
  }

  R.id.btnRotateRight -> {
        animRotateRight.duration = seekSpeedProgress.toLong()
        animRotateRight.setAnimationListener(this)
        imageView.startAnimation(animRotateRight)
  }
}

}
```

现在运行应用程序，并将`SeekBar`小部件移动到大致中心，以便动画运行一段合理的时间：

![在 Kotlin 中连接动画演示应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_04.jpg)

点击**放大**按钮：

![在 Kotlin 中连接动画演示应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_05.jpg)

注意 Android 机器人上的文本在适当的时间从**RUNNING**更改为**STOPPED**。现在，点击其中一个**ROTATE**按钮：

![在 Kotlin 中连接动画演示应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_19_06.jpg)

大多数其他动画在截图中无法展现出自己的价值，所以一定要自己尝试它们。

# 经常问的问题

Q.1) 我们现在知道如何为小部件添加动画，但是我自己创建的形状或图像呢？

A) 一个`ImageView`小部件可以容纳任何您喜欢的图像。只需将图像添加到`drawable`文件夹，然后在`ImageView`小部件上设置适当的`src`属性。然后您可以对`ImageView`小部件中显示的任何图像进行动画处理。

Q.2) 但是如果我想要比这更灵活的功能，更像是一个绘画应用程序甚至是一个游戏呢？

A) 要实现这种功能，我们需要学习另一个称为**线程**的通用计算概念，以及一些更多的 Android 类（如`Paint`，`Canvas`和`SurfaceView`）。我们将学习如何从单个像素到形状绘制任何东西，然后将它们移动到屏幕上，从下一章开始，第二十章 *绘制图形*。

# 总结

现在我们有另一个增强应用程序的技巧。在本章中，我们看到 Android 中的动画非常简单。我们在 XML 中设计了一个动画，并将文件添加到`anim`文件夹中。接下来，我们在 Kotlin 代码中使用`Animation`对象获取了 XML 中动画的引用。

然后，我们在 UI 中使用小部件的引用，使用`setAnimation`为其设置动画，并传入`Animation`对象。通过在小部件的引用上调用`startAnimation`来启动动画。

我们还看到我们可以控制动画的时间并监听动画事件。

在下一章中，我们将学习在 Android 中绘制图形。这将是关于图形的几章中的开始，我们将构建一个儿童风格的绘画应用程序。


# 第二十章：绘图图形

整个章节将讨论 Android 的`Canvas`类以及一些相关类，如`Paint`，`Color`和`Bitmap`。当这些类结合在一起时，在屏幕上绘图时会带来巨大的力量。有时，Android API 提供的默认 UI 并不是我们所需要的。如果我们想要制作一个绘图应用程序，绘制图表，或者制作游戏，我们需要控制 Android 设备提供的每个像素。

在本章中，我们将涵盖以下主题：

+   了解`Canvas`类及一些相关类

+   编写一个基于`Canvas`的演示应用程序

+   查看 Android 坐标系统，以便知道在哪里进行绘制

+   学习绘制和操作位图图形

+   编写一个基于位图图形的演示应用程序

所以，让我们开始绘图吧！

# 了解 Canvas 类

`Canvas`类是`android.graphics`包的一部分。在接下来的两章中，我们将使用`android.graphics`包中的所有以下`import`语句以及来自现在熟悉的`View`包的另一个`import`语句。它们为我们提供了从 Android API 中获取一些强大绘图功能的途径：

```kt
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.widget.ImageView

```

首先，让我们讨论前面代码中突出显示的`Bitmap`，`Canvas`和`ImageView`。

## 使用 Bitmap，Canvas 和 ImageView 开始绘制

由于 Android 设计用于运行各种类型的移动应用程序，我们不能立即开始输入我们的绘图代码并期望它能够工作。我们需要做一些准备（也就是更多的编码）来考虑我们的应用程序运行在特定设备上。这种准备有时可能有点反直觉，但我们将一步一步地进行。

### Canvas 和 Bitmap

根据您如何使用`Canvas`类，这个术语可能会有点误导。虽然`Canvas`类确实是您绘制图形的类，就像绘画画布一样，但您仍然需要一个**表面**来转置画布。

在这种情况下（以及我们的前两个演示应用程序中），表面将来自`Bitmap`类。

### 提示

请注意，位图是一种图像类型，Android 有一个`Bitmap`类。`Bitmap`类可用于将位图图像绘制到屏幕上，但正如我们将看到的那样，它还有其他用途。在谈论位图图像和`Bitmap`类时，我会尽量清晰明了，以便区分得更清楚。

我们可以将这个过程看作是：我们得到一个`Canvas`对象和一个`Bitmap`对象，然后将`Bitmap`对象设置为`Canvas`对象的一部分来进行绘制。

如果按照字面意义理解"画布"这个词有点反直觉，但一旦设置好了，我们就可以忘记它，专注于我们想要绘制的图形。

### 提示

`Canvas`类提供了绘制的*能力*。它具有绘制形状、文本、线条和图像文件（如其他位图）的所有功能，甚至支持绘制单个像素。

`Bitmap`类由`Canvas`类使用，是被绘制的表面。您可以将`Bitmap`实例视为位于`Canvas`实例上的图片框。

### Paint

除了`Canvas`和`Bitmap`，我们还将使用`Paint`类。这更容易理解；`Paint`是用于配置特定属性的类，例如我们将在`Canvas`实例中绘制的颜色（在`Canvas`实例内的`Bitmap`实例上）。

然而，在我们开始绘制之前，还有一个谜题需要解决。

### ImageView 和 Activity

`ImageView`类是`Activity`类用于向用户显示输出的类。引入这第三层抽象的原因是，正如我们在整本书中所看到的，`Activity`类需要将一个`View`引用传递给`setContentView`函数，以向用户显示内容。在整本书中，这一直是我们在可视化设计器或 XML 代码中创建的布局。

然而，这一次我们不需要用户界面 - 相反，我们需要绘制线条、像素、图像和形状。

有多个从 `View` 继承的类，可以制作所有不同类型的应用程序，并且它们都与 `Activity` 类兼容，这是所有常规 Android 应用程序（包括绘图应用程序和游戏）的基础。

因此，有必要将在 `Canvas` 上绘制的 `Bitmap` 类与 `ImageView` 类关联起来，一旦绘制完成。最后一步是通过将其传递给 `setContentView` 来告诉 `Activity` 类，我们的 `ImageView` 代表用户要看到的内容。

### Canvas、Bitmap、Paint 和 ImageView - 简要总结

如果我们需要设置的代码结构理论看起来并不简单，那么当你看到稍后的相对简单的代码时，你会松一口气。

到目前为止，我们已经覆盖了以下内容：

+   每个应用程序都需要一个 `Activity` 类来与用户和底层操作系统交互。因此，如果我们想成功，我们必须遵循所需的层次结构。

+   我们将使用继承自 `View` 类的 `ImageView` 类。`View` 类是 `Activity` 需要显示我们的应用程序给用户的东西。

+   `Canvas` 类提供了绘制线条、像素和其他图形的 *能力*。它具有执行诸如绘制形状、文本、线条和图像文件等操作的所有功能，甚至支持绘制单个像素。

+   `Bitmap` 类将与 `Canvas` 类关联，它是被绘制的表面。

+   `Canvas` 类使用 `Paint` 类来配置细节，比如绘制的颜色。

+   最后，一旦 `Bitmap` 实例被绘制，我们必须将其与 `ImageView` 类关联起来，而 `ImageView` 类又被设置为 `Activity` 实例的视图。

结果将是我们在 `Canvas` 实例中绘制的 `Bitmap` 实例将通过调用 `setContentView` 显示给用户的 `ImageView` 实例。呼～

### 提示

如果这并不是 100%清楚也没关系。不是你看不清楚 - 它只是没有清晰的关系。编写代码并反复使用这些技术将使事情变得更清晰。看看代码，执行本章和下一章的演示应用程序，然后重新阅读本节。

让我们看看如何在代码中建立这种关系 - 不要担心输入代码；我们先来学习它。

# 使用 Canvas 类

让我们看看代码和获取绘图所需的不同阶段，然后我们可以快速转移到使用 `Canvas` 演示应用程序真正绘制一些东西。

## 准备所需类的实例

第一步是将我们需要的类转换为可用的实例。

首先，我们声明我们需要的所有实例。我们不能立即初始化这些实例，但我们可以确保在使用它们之前初始化它们，所以我们在同样的方式中使用 `lateinit`，就像在动画演示应用程序中一样：

```kt
// Here are all the objects(instances)
// of classes that we need to do some drawing
lateinit var myImageView: ImageView
lateinit var myBlankBitmap: Bitmap
lateinit var myCanvas: Canvas
lateinit var myPaint: Paint
```

上一个代码声明了 `ImageView`、`Bitmap`、`Canvas` 和 `Paint` 类型的引用。它们分别被命名为 `myImageView`、`myBlankBitmap`、`myCanvas` 和 `myPaint`。

## 初始化对象

接下来，我们需要在使用它们之前初始化我们的新对象：

```kt
// Initialize all the objects ready for drawing
// We will do this inside the onCreate function
val widthInPixels = 800
val heightInPixels = 600

// Create a new Bitmap
myBlankBitmap = Bitmap.createBitmap(widthInPixels,
         heightInPixels,
         Bitmap.Config.ARGB_8888)

// Initialize the Canvas and associate it
// with the Bitmap to draw on
myCanvas = Canvas(myBlankBitmap)

// Initialize the ImageView and the Paint
myImageView = ImageView(this)
myPaint = Paint()
// Do drawing here
```

请注意上一个代码中的以下注释：

```kt
// Do drawing here
```

这是我们将配置颜色并绘制图形的地方。另外，请注意在代码顶部我们声明并初始化了两个 `Int` 变量，称为 `widthInPixels` 和 `heightInPixels`。当我们编写 `Canvas` 演示应用程序时，我将更详细地介绍其中一些代码行。

现在我们已经准备好绘制；我们所需要做的就是通过 `setContentView` 函数将 `ImageView` 实例分配给 `Activity`。

## 设置 Activity 内容

最后，在我们看到我们的绘图之前，我们告诉 Android 使用我们的名为`myImageView`的`ImageView`实例作为要显示给用户的内容：

```kt
// Associate the drawn upon Bitmap with the ImageView
myImageView.setImageBitmap(myBlankBitmap);
// Tell Android to set our drawing
// as the view for this app
// via the ImageView
setContentView(myImageView);
```

正如您在迄今为止的每个应用程序中已经看到的，`setContentView`函数是`Activity`类的一部分，这一次我们将`myImageView`作为参数传递，而不是像我们在整本书中一直做的那样传递 XML 布局。就是这样 - 现在我们要学习的就是如何在`Bitmap`实例上实际绘制。

在进行一些绘图之前，启动一个真正的项目将非常有用。我们将逐步复制并粘贴我们刚刚讨论过的代码到正确的位置，然后实际上在屏幕上看到一些绘制的东西。

所以，让我们开始绘图吧。

# Canvas Demo 应用程序

首先，创建一个新项目来探索使用`Canvas`进行绘图的主题。我们将重复利用我们所学到的知识，这一次我们还将绘制到`Bitmap`实例上。

## 创建一个新项目

创建一个新项目，将其命名为`Canvas Demo`，并确保选择**空活动**模板选项。

在这个应用程序中，我们将进行一个以前未见过的更改。我们将使用`Activity`类的原始版本。因此，`MainActivity`将继承自`Activity`，而不是之前一直使用的`AppCompatActivity`。我们这样做是因为我们不使用来自 XML 文件的布局，因此我们不需要`AppCompatActivity`的向后兼容功能，就像在以前的所有项目中一样。

您应该编辑类声明如下。

```kt
class MainActivity : Activity() {
```

您还需要添加以下导入语句：

```kt
import android.app.Activity
```

### 注意

此应用程序的完整代码可以在`Chapter20/Canvas Demo`文件夹的下载包中找到。

### 编写 Canvas 演示应用程序

接下来，删除`onCreate`函数的所有内容，除了声明/签名、调用 super.onCreate 以及打开和关闭大括号。

现在，我们可以在类声明之后但在`onCreate`函数之前添加以下突出显示的代码。在此步骤之后，代码将如下所示：

```kt
// Here are all the objects(instances)
// of classes that we need to do some drawing
lateinit var myImageView: ImageView
lateinit var myBlankBitmap: Bitmap
lateinit var myCanvas: Canvas
lateinit var myPaint: Paint

override fun onCreate(savedInstanceState: Bundle?) {
   super.onCreate(savedInstanceState)
}
```

在 Android Studio 中，四个新类都被下划线标记为红色。这是因为我们需要添加适当的`import`语句。您可以从本章的第一页复制它们，但更快的方法是依次将鼠标光标放在每个错误上，然后按住*ALT*键并轻按*Enter*键。如果从弹出选项中提示，请选择**导入类**。

完成对`ImageView`、`Bitmap`、`Canvas`和`Paint`的操作后，所有错误都将消失，并且相关的`import`语句将被添加到代码的顶部。

现在我们已经声明了所需类的实例，我们可以对它们进行初始化。将以下代码添加到`onCreate`函数中，添加到“super.onCreate…”之后，如下所示：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
   super.onCreate(savedInstanceState)

   // Initialize all the objects ready for drawing
   // We will do this inside the onCreate function
   val widthInPixels = 800
   val heightInPixels = 600

   // Create a new Bitmap
   myBlankBitmap = Bitmap.createBitmap(widthInPixels,
                heightInPixels,
                Bitmap.Config.ARGB_8888)

   // Initialize the Canvas and associate it
   // with the Bitmap to draw on
   myCanvas = Canvas(myBlankBitmap)

   // Initialize the ImageView and the Paint
   myImageView = ImageView(this)
   myPaint = Paint()
}
```

前面的代码与我们在理论上讨论`Canvas`时看到的代码相同。但是，值得更深入地探索`Bitmap`类的初始化，因为它并不简单。

#### 探索位图初始化

位图在基于图形的应用程序和游戏中更常见，用于表示不同的画笔、玩家角色、背景、游戏对象等对象。在这里，我们只是用它来绘制。在下一个项目中，我们将使用位图来表示我们绘制的主题，而不仅仅是绘制的表面。

需要解释的函数是`createBitmap`函数。从左到右的参数如下：

+   宽度（以像素为单位）

+   高度（以像素为单位）

+   位图配置

`Bitmap`实例可以以几种不同的方式进行配置；`ARGB_8888`配置意味着每个像素由四个字节的内存表示。

### 注意

Android 可以使用多种位图格式。这种格式非常适合绘制一系列颜色，并确保我们使用的位图和请求的颜色将按预期绘制。还有更高和更低的配置，但`ARGB_8888`非常适合本书。

现在，我们可以进行实际绘制。

### 在屏幕上绘制

在`myPaint`初始化之后和`onCreate`函数的闭合大括号内添加以下突出显示的代码：

```kt
// Draw on the Bitmap
// Wipe the Bitmap with a blue color
myCanvas.drawColor(Color.argb(255, 0, 0, 255))

// Re-size the text
myPaint.textSize = 100f
// Change the paint to white
myPaint.color = Color.argb(255, 255, 255, 255)
// Draw some text
myCanvas.drawText("Hello World!",100f, 100f, myPaint)

// Change the paint to yellow
myPaint.color = Color.argb(255, 212, 207, 62)
// Draw a circle
myCanvas.drawCircle(400f, 250f, 100f, myPaint)
```

前面的代码使用：

+   `myCanvas.drawColor`用颜色填充屏幕

+   `myPaint.textSize`属性定义了接下来将绘制的文本的大小

+   `myPaint.color`属性决定了未来任何绘图的颜色

+   `myCanvas.drawText`函数实际上将文本绘制到屏幕上。

如果我们分析传递给`drawText`的参数，我们可以看到文本将会显示"Hello World!"，并且将在我们的`Bitmap`实例(`myBitmap`)的左侧 100 像素和顶部 100 像素处绘制。

接下来，我们再次使用`color`属性来更改将用于绘制的颜色。最后，我们使用`drawCircle`函数来绘制一个距左侧 400 像素，顶部 100 像素的圆。圆的半径为 100 像素。

直到现在，我一直没有解释`Color.argb`函数。

#### 解释 Color.argb

`Color`类，不出所料，帮助我们操纵和表示颜色。`argb`函数返回使用**a**lpha（不透明度和透明度）、**r**ed、**g**reen、**b**lue 模型构建的颜色。该模型对于每个元素使用从 0（无颜色）到 255（全颜色）的值。重要的是要注意 - 尽管这似乎是显而易见的 - 混合颜色是不同颜色光的强度，结果与我们混合颜料时发生的情况完全不同。

### 提示

要设计 ARGB 值并进一步探索这个模型，请查看这个方便的网站：[`www.rapidtables.com/web/color/RGB_Color.html`](https://www.rapidtables.com/web/color/RGB_Color.html)。该网站可以帮助您选择 RGB 值；然后您可以尝试 alpha 值。

用于清除绘图表面的值是`255`、`0`、`0`和`255`。这些值表示完全不透明（即纯色），没有红色，没有绿色，完全蓝色。这会产生蓝色。

对`argb`函数的下一个调用是在`setColor`的第一个调用中，我们正在为文本设置所需的颜色。`255`、`255`、`255`和`255`的值表示完全不透明，完全红色，完全绿色和完全蓝色。当您将光与这些值结合时，您将得到白色。

对`argb`的最终调用是在`setColor`的最终调用中，我们正在设置绘制圆的颜色；`255`、`21`、`207`和`62`产生太阳黄色。

在运行代码之前，我们需要执行的最后一步是添加对`setContentView`函数的调用，将我们的`ImageView`实例(`myImageView`)放置为此应用程序的内容视图。以下是我们已经添加的代码之后，但在`onCreate`的闭合大括号之前的最后几行代码：

```kt
// Associate the drawn upon Bitmap with the ImageView
myImageView.setImageBitmap(myBlankBitmap);
// Tell Android to set our drawing
// as the view for this app
// via the ImageView
setContentView(myImageView);
```

最后，我们通过调用`setContentView`告诉`Activity`类使用`myImageView`。

下面的屏幕截图展示了当您运行 Canvas 演示应用程序时的外观。我们可以看到一个 800x800 像素的绘图。在下一章中，我们将使用更高级的技术来利用整个屏幕，并且我们还将学习有关线程，以使图形实时移动：

![解释 Color.argb](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_01.jpg)

如果您了解 Android 坐标系统的更多信息，将有助于您理解我们在`Canvas`绘图函数中使用的坐标的结果。

# Android 坐标系统

正如您将看到的，绘制位图图形是微不足道的。但是，我们用来绘制图形的坐标系统需要简要解释。

## 绘图和绘制

当我们在屏幕上绘制位图图形时，我们传入要绘制对象的坐标。给定 Android 设备的可用坐标取决于其屏幕的分辨率。

例如，Google Pixel 手机在横向方向上的屏幕分辨率为 1,920 像素（横向）x 1,080 像素（纵向）。

这些坐标的编号系统从左上角的 0,0 开始，向下和向右移动，直到右下角是像素 1919, 1079。1,920/1,919 和 1,080/1,079 之间明显的 1 像素差异是因为编号从 0 开始。

因此，当我们在屏幕上绘制位图图形或其他任何东西（如`Canvas`圆和矩形）时，我们必须指定*x*，*y*坐标。

此外，位图图形（或`Canvas`形状）当然包括许多像素。因此，我们将要指定的*x*，*y*屏幕坐标上绘制给定位图图形的哪个像素？ 

答案是位图图形的左上角像素。看一下下一个图表，它应该使用 Google Pixel 手机作为示例来澄清屏幕坐标。作为解释 Android 坐标绘制系统的图形手段，我将使用一个可爱的太空飞船图形：

![绘图和绘制](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_02.jpg)

此外，这些坐标是相对于您绘制的内容。因此，在我们刚刚编写的`Canvas`演示和下一个演示中，坐标是相对于`Bitmap`对象（`myBitmap`）的。在下一章中，我们将使用整个屏幕，上一个图表将更准确地表示发生的情况。

让我们做一些更多的绘图 - 这次使用位图图形（再次使用`Bitmap`类）。我们将使用与此应用程序中看到的相同的起始代码。

# 使用 Bitmap 类创建位图图形

在我们深入代码之前，让我们先研究一些理论，并考虑我们将如何将图像绘制到屏幕上。要绘制位图图形，我们将使用`Canvas`类的`drawBitmap`函数。

首先，我们需要在`res/drawable`文件夹中的项目中添加一个位图图形 - 我们将在 Bitmap 演示应用程序中进行这个操作。现在，假设图形文件/位图的名称为`myImage.png`。

接下来，我们将以与我们在上一个演示中用于背景的`Bitmap`对象相同的方式声明`Bitmap`类型的对象。

接下来，我们需要使用我们之前添加到项目的`drawable`文件夹中的首选图像文件来初始化`myBitmap`实例：

```kt
myBitmap = BitmapFactory.decodeResource
                (resources, R.drawable.myImage)
```

`BitmapFactory`类的`decodeResource`函数用于初始化`myBitmap`。它需要两个参数；第一个是`Activity`类提供的`resources`属性。这个函数，正如其名称所示，可以访问项目资源，第二个参数`R.drawable.myImage`指向`drawable`文件夹中的`myImage.png`文件。`Bitmap`（`myBitmap`）实例现在已准备好由`Canvas`类绘制。

现在，您可以使用以下代码通过`Bitmap`实例绘制位图图形：

```kt
// Draw the bitmap at coordinates 100, 100
canvas.drawBitmap(myBitmap, 
                100, 100, myPaint);
```

当在屏幕上绘制时，上一节中太空飞船图形的样子如下（仅供参考，当我们谈论旋转位图时）：

![使用 Bitmap 类创建位图图形](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_03.jpg)

# 操作位图

然而，通常情况下，我们需要以旋转或其他方式改变的状态绘制位图。使用 Photoshop 或您喜欢的其他图像编辑软件创建更多的位图以面向其他方向是非常容易的。然后，当我们要绘制位图时，我们可以简单地决定以哪种方式绘制适当的预加载位图。

然而，如果我们只使用一个单一的源图像并学习 Android 提供的用于在 Kotlin 代码中操作图像的类，那将会更有趣和有教育意义。然后，你就可以将旋转和反转图形添加到你的应用程序开发工具包中。

## 什么是位图？

位图之所以被称为位图，是因为它确实就是一个“位的地图”。虽然有许多使用不同范围和值来表示颜色和透明度的位图格式，但它们都归结为同一件事。它们是一组值的网格或地图，每个值代表一个像素的颜色。

因此，要旋转、缩放或反转位图，我们必须对位图的每个像素或位进行适当的数学计算。这些计算并不是非常复杂，但也不是特别简单。如果你上完高中的数学课，你可能不会对这些数学感到太困难。

不幸的是，理解数学还不够。我们还需要设计高效的代码，了解位图格式，然后针对每种格式修改我们的代码；这并不是微不足道的。幸运的是（正如我们所期望的那样），Android API 已经为我们做好了一切 - 认识`Matrix`类。

## Matrix 类

这个类被命名为`Matrix`，是因为它使用数学概念和规则来对一系列值进行计算，这些值被称为矩阵 - 矩阵的复数。

### 提示

Android 的`Matrix`类与同名电影系列无关。然而，作者建议所有有抱负的应用程序开发者服用**红色**药丸。

你可能对矩阵很熟悉，但如果你不熟悉也不用担心，因为`Matrix`类将所有复杂性都隐藏起来了。此外，`Matrix`类不仅允许我们对一系列值进行计算，还具有一些预先准备好的计算，使我们能够做一些事情，比如围绕另一个点旋转一个点特定角度，而无需了解三角学。

### 提示

如果你对`Matrix`类背后的数学运作感兴趣，并且想要一个绝对初学者指南来学习旋转游戏对象的数学，那么请查看我网站上的这一系列 Android 教程，其中包括一个可飞行和可旋转的太空飞船。这些教程是用 Java 编写的，但应该很容易理解：

[`gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/`](http://gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/)

[`gamecodeschool.com/essentials/rotating-graphics-in-2d-games-using-trigonometric-functions-part-2/`](http://gamecodeschool.com/essentials/rotating-graphics-in-2d-games-using-trigonometric-functions-part-2/)

[`gamecodeschool.com/android/2d-rotation-and-heading-demo/`](http://gamecodeschool.com/android/2d-rotation-and-heading-demo/)

这本书将继续使用 Android 的`Matrix`类，但在下一章中创建粒子系统时，我们将进行稍微更高级的数学运算。

### 将位图反转以面对相反方向

首先，我们需要创建一个`Matrix`类的实例。下面的代码行以熟悉的方式调用默认构造函数来实现这一点：

```kt
val matrix = Matrix()
```

### 提示

请注意，你现在不需要将任何这些代码添加到项目中；它很快就会再次显示，并且会有更多的上下文。我只是觉得在此之前单独看到所有与`Matrix`相关的代码会更容易些。

现在我们可以使用`Matrix`类的许多巧妙功能之一。`preScale`函数接受两个参数；一个用于水平变化，一个用于垂直变化。看一下下面的代码行：

```kt
matrix.preScale(-1, 1)
```

`preScale`函数将循环遍历每个像素位置，并将所有水平坐标乘以`-1`，所有垂直坐标乘以`1`。

这些计算的效果是所有垂直坐标将保持不变，因为如果乘以一，那么数字不会改变。但是，当您乘以负一时，像素的水平位置将被倒转。例如，水平位置 0、1、2、3 和 4 将变为 0、-1、-2、-3 和-4。

在这个阶段，我们已经创建了一个可以在位图上执行必要计算的矩阵。我们实际上还没有对位图做任何事情。要使用`Matrix`实例，我们调用`Bitmap`类的`createBitmap`函数，如下面的代码行：

```kt
myBitmapLeft = Bitmap
    .createBitmap(myBitmapRight,
          0, 0, 50, 25, matrix, true)
```

上面的代码假设`myBitmapLeft`已经与`myBitmapRight`一起初始化。`createBitmap`函数的参数解释如下：

+   `myBitmapRight`是一个已经创建并缩放的`Bitmap`对象，并且已经加载了图像（面向右侧）。这是将用作创建新`Bitmap`实例的源的图像。源`Bitmap`对象将不会被改变。

+   `0, 0`是我们希望将新的`Bitmap`实例映射到的水平和垂直起始位置。

+   `50, 25`参数是设置位图缩放到的大小。

+   下一个参数是我们预先准备的`Matrix`实例`matrix`。

+   最后一个参数`true`指示`createBitmap`函数需要过滤以正确处理`Bitmap`类型的创建。

这就是在绘制到屏幕时`myBitmapLeft`的样子：

![将位图反转以面向相反方向](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_04.jpg)

我们还可以使用旋转矩阵创建面向上和下的位图。

### 将位图旋转以面向上和下

让我们看看如何旋转`Bitmap`实例，然后我们可以构建演示应用程序。我们已经有了`Matrix`类的一个实例，所以我们只需要调用`preRotate`函数来创建一个能够将每个像素旋转指定角度的矩阵，该角度作为`preRotate`的单个参数。看看下面的代码行：

```kt
// A matrix for rotating
matrix.preRotate(-90)
```

是不是很简单？`matrix`实例现在已经准备好以逆时针（`-`）`90`度旋转我们传递给它的任何一系列数字（位图）。

以下代码行与我们分解的先前对`createBitmap`的调用具有相同的参数，只是新的`Bitmap`实例分配给了`myBitmapUp`，并且`matrix`的效果是执行旋转而不是`preScale`函数：

```kt
mBitmapUp = Bitmap
   .createBitmap(mBitmap,
         0, 0, 25, 50, matrix, true)
```

这就是在绘制时`myBitmapUp`的样子：

![将位图旋转以面向上和下](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_05.jpg)

您还可以使用相同的技术，但在`preRotate`的参数中使用不同的值，以使位图面向下。让我们继续演示应用程序，看看所有这些东西是如何运作的。

# Bitmap 操作演示应用程序

现在我们已经学习了理论，让我们绘制和旋转一些位图。首先，创建一个新项目并将其命名为`Bitmap manipulation`。选择**空活动**选项，其他设置与整本书中的设置相同。

## 将 Bob 图形添加到项目中

右键单击并选择**复制**，从`Chapter20/Bitmap Manipulation/drawable`文件夹中的下载包中复制`bob.png`图形文件。由`bob.png`表示的 Bob 是一个简单的静态视频游戏角色。

在 Android Studio 中，定位项目资源管理器窗口中的`app/res/drawable`文件夹，并将`bob.png`图像文件粘贴到其中。以下屏幕截图清楚地显示了该文件夹的位置以及带有`bob.png`图像的外观：

![将 Bob 图形添加到项目中](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_06.jpg)

右键单击`drawable`文件夹，然后选择**粘贴**以将`bob.png`文件添加到项目中。点击两次**确定**以确认将文件导入项目的默认选项。

在这个应用程序中，我们将做与上一个应用程序相同的更改。我们将使用`Activity`类的原始版本。因此，`MainActivity`将继承自`Activity`而不是`AppCompatActivity`，这是以前的情况。我们这样做是因为，再次强调，我们不使用来自 XML 文件的布局，因此我们不需要`AppCompatActivity`的向后兼容功能，就像在以前的所有项目中一样。

您应该编辑类声明如下。

```kt
class MainActivity : Activity() {
```

您还需要添加以下导入语句：

```kt
import android.app.Activity
```

在`MainActivity`类的类声明之后，在`onCreate`函数之前，添加以下必需的属性，准备进行一些绘图：

```kt
// Here are all the objects(instances)
// of classes that we need to do some drawing
lateinit var myImageView: ImageView
lateinit var myBlankBitmap: Bitmap
lateinit var bobBitmap: Bitmap
lateinit var myCanvas: Canvas
lateinit var myPaint: Paint
```

### 提示

在包声明之后添加以下导入：

```kt
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.widget.ImageView
```

现在，我们可以在`onCreate`中初始化所有实例，如下所示：

```kt
// Initialize all the objects ready for drawing
val widthInPixels = 2000
val heightInPixels = 1000

// Create a new Bitmap
myBlankBitmap = Bitmap.createBitmap(widthInPixels,
         heightInPixels,
         Bitmap.Config.ARGB_8888)

// Initialize Bob
bobBitmap = BitmapFactory.decodeResource(
          resources, R.drawable.bob)

// Initialize the Canvas and associate it
// with the Bitmap to draw on
myCanvas = Canvas(myBlankBitmap)

// Initialize the ImageView and the Paint
myImageView = ImageView(this)
myPaint = Paint()

// Draw on the Bitmap
// Wipe the Bitmap with a blue color
myCanvas.drawColor(Color.argb(
         255, 0, 0, 255))
```

接下来，我们添加对三个函数的调用，我们很快将编写这些函数，并将我们的新绘图设置为应用程序的视图：

```kt
// Draw some bitmaps
drawRotatedBitmaps()
drawEnlargedBitmap()
drawShrunkenBitmap()

// Associate the drawn upon Bitmap
// with the ImageView
myImageView.setImageBitmap(myBlankBitmap)
// Tell Android to set our drawing
// as the view for this app
// via the ImageView
setContentView(myImageView)
```

现在，添加`drawRotatedBitmap`函数，执行位图操作：

```kt
fun drawRotatedBitmaps() {
   var rotation = 0f
   var horizontalPosition = 350
   var verticalPosition = 25
   val matrix = Matrix()

   var rotatedBitmap: Bitmap

   rotation = 0f
   while (rotation < 360) {
         matrix.reset()
         matrix.preRotate(rotation)
         rotatedBitmap = Bitmap
                      .createBitmap(bobBitmap, 
                      0, 0, bobBitmap.width - 1,
                      bobBitmap.height - 1,
                      matrix, true)

        myCanvas.drawBitmap(
                    rotatedBitmap,
                    horizontalPosition.toFloat(),
                    verticalPosition.toFloat(),
                    myPaint)

        horizontalPosition += 120
        verticalPosition += 70
        rotation += 30f
  }
}
```

先前的代码使用循环迭代 360 度，每次 30 度。值（在循环中的每次通过）用于在`Matrix`实例中旋转 Bob 的图像，然后使用`drawBitmap`函数将其绘制到屏幕上。

添加最后两个函数，如下所示：

```kt
fun drawEnlargedBitmap() {
  bobBitmap = Bitmap
               .createScaledBitmap(bobBitmap,
                           300, 400, false)
  myCanvas.drawBitmap(bobBitmap, 25f, 25f, myPaint)

}

fun drawShrunkenBitmap() {
  bobBitmap = Bitmap
              .createScaledBitmap(bobBitmap,
                          50, 75, false)
  myCanvas.drawBitmap(bobBitmap, 250f, 25f, myPaint)
}
```

`drawEnlargedBitmap`函数使用`createScaledBitmap`函数，将位图图形放大到 300 x 400 像素。然后`drawBitmap`函数将其绘制到屏幕上。

`drawShrunkenBitmap`函数使用完全相同的技术，只是它缩放然后绘制一个 50 x 75 像素的图像。

最后，运行应用程序，看到 Bob 在 30 度间隔下生长、缩小，然后围绕 360 度旋转，如下截图所示：

![将 Bob 图形添加到项目中](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C20_07.jpg)

我们绘图库中唯一缺少的是观看所有这些活动发生的能力。我们将在下一步中填补这一知识空白。

# 常见问题

Q 1）我知道如何进行所有这些绘图，但为什么我看不到任何东西移动？

A）要看到物体移动，您需要能够调节绘图的每个部分发生的时间。您需要使用动画技术。这并不是微不足道的，但对于一个有决心的初学者来说也不是难以掌握的。我们将在下一章中学习所需的主题。

# 摘要

在本章中，我们学习了如何绘制自定义形状、文本和位图。现在我们知道如何绘制和操作原始形状、文本和位图，我们可以提升一级。

在下一章中，我们将开始我们的下一个多章节应用程序，这是一个儿童风格的绘图应用程序，只需轻按按钮即可生动起来。


# 第二十一章：线程和启动实时绘图应用程序

在本章中，我们将开始我们的下一个应用程序。这个应用程序将是一个儿童风格的绘图应用程序，用户可以使用手指在屏幕上绘图。然而，我们创建的绘图应用程序将略有不同。用户绘制的线条将由粒子系统组成，这些粒子系统会爆炸成成千上万的碎片。我们将把项目称为*实时绘图*。

为了实现这一点，我们将在本章中涵盖以下主题：

+   开始使用实时绘图应用程序

+   学习实时交互，有时被称为游戏循环

+   学习关于线程

+   编写一个准备好进行绘制的实时系统

让我们开始吧！

# 创建实时绘图项目

要开始，可以在 Android Studio 中创建一个名为`Live Drawing`的新项目。使用**空活动**项目，并将其余设置保持默认。

与上一章的两个绘图应用程序类似，这个应用程序只包含 Kotlin 文件，没有布局文件。到本章结束为止的所有 Kotlin 文件和代码都可以在下载包的`Chapter21`文件夹中找到。完整的项目可以在下载包的`Chapter22`文件夹中找到。

接下来，我们将创建一些空的类，这些类将在接下来的两章中进行编码。创建一个名为`LiveDrawingView`的新类，一个名为`ParticleSystem`的新类，以及一个名为`Particle`的新类。

# 展望实时绘图应用程序

由于这个应用程序更加深入，需要实时响应，因此需要使用稍微更深入的结构。起初，这可能看起来有些复杂，但从长远来看，这将使我们的代码更简单，更容易理解。

在实时绘图应用程序中，我们将有四个类，如下：

+   `MainActivity`：Android API 提供的`Activity`类是与操作系统（OS）交互的类。我们已经看到了当用户点击应用程序图标启动应用程序时，操作系统如何与`onCreate`交互。与其让`MainActivity`类做所有事情，这个基于`Activity`的类将只处理应用程序的启动和关闭，并通过计算屏幕分辨率来提供一些初始化的帮助。这个类将是`Activity`类型而不是`AppCompatActivity`是有道理的。然而，很快你会看到，我们将通过触摸委托交互给另一个类，也就是将处理几乎每个方面的同一个类。这将为我们介绍一些新的有趣的概念。

+   `LiveDrawingView`：这个类将负责绘图，并创建允许用户在其创作移动和发展的同时进行交互的实时环境。

+   `ParticleSystem`：这是一个类，将管理多达数千个`Particle`类的实例。

+   `Particle`：这个类将是最简单的类；它将在屏幕上具有位置和方向。当由`LiveDrawingView`类提示时，它将每秒更新自己大约 60 次。

现在，我们可以开始编码。

# 编写 MainActivity 类

让我们开始编写基于`Activity`的类。通常情况下，这个类被称为`MainActivity`，当我们创建项目时，它是自动生成的。

编辑类声明并添加`MainActivity`类的代码的第一部分：

```kt
import android.app.Activity
import android.os.Bundle
import android.graphics.Point

class MainActivity : Activity() {

    private lateinit var liveDrawingView: LiveDrawingView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val display = windowManager.defaultDisplay
        val size = Point()
        display.getSize(size)

        liveDrawingView = LiveDrawingView(this, size.x)

        setContentView(liveDrawingView)

    }
}
```

上述代码显示了我们将很快讨论的几个错误。首先要注意的是，我们正在声明`LiveDrawingView`类的一个实例。目前，这是一个空类：

```kt
private lateinit var liveDrawingView: LiveDrawingView
```

下面的代码以以下方式获取设备的像素数（水平和垂直）：

```kt
val display = windowManager.defaultDisplay
```

我们创建了一个名为`display`的`Display`类型的对象，并用`windowManager.defaultDisplay`进行初始化，这是`Activity`类的一部分。

然后，我们创建一个名为`size`的`Point`类型的新对象。我们将`size`作为参数发送到`display.getSize`函数。`Point`类型有`x`和`y`属性，因此`size`对象也有这些属性，在第三行代码之后，`size`现在保存了显示的宽度和高度（以像素为单位）。现在，我们在`size`对象的`x`和`y`属性中有了屏幕分辨率。

接下来，在`onCreate`中，我们初始化`liveDrawingView`如下：

```kt
liveDrawingView = LiveDrawingView(this, size.x)
```

我们正在向`LiveDrawingView`构造函数传递两个参数。显然，我们还没有编写构造函数，而且我们知道，默认构造函数不带参数。因此，在我们解决这个问题之前，这行代码将导致错误。

传入的参数很有趣。首先是`this`，它是对`MainActivity`的引用。`LiveDrawingView`类将需要执行一些操作（使用一些函数），它需要这个引用。

第二个参数是水平屏幕分辨率。我们的应用程序需要这些参数来执行任务，例如将其他绘图对象缩放到适当的大小。当我们开始编写`LiveDrawingView`的构造函数时，我们将进一步讨论这些参数。

现在，看一下接下来的更奇怪的一行：

```kt
setContentView(liveDrawingView)
```

这是在 Canvas Demo 应用程序中，我们将`ImageView`设置为应用程序的内容。请记住，`Activity`类的`setContentView`函数必须接受一个`View`对象，而`ImageView`是一个`View`对象。前面的代码似乎在暗示我们将使用`LiveDrawingView`类作为应用程序的可见内容？但是`LiveDrawingView`，尽管名字是这样，却不是一个`View`对象。至少目前还不是。

在我们向`MainActivity`添加几行代码之后，我们将解决构造函数和不是`View`类型的问题。

添加这两个重写的函数，然后我们将讨论它们。将它们添加到`onCreate`的闭合大括号下面，但在`MainActivity`的闭合大括号之前：

```kt
override fun onResume() {
   super.onResume()

   // More code here later in the chapter
}

override fun onPause() {
   super.onPause()

  // More code here later in the chapter
}
```

我们在这里做的是重写`Activity`类的另外两个函数。我们将看到为什么需要这样做以及我们将在这些函数中做什么。需要注意的是，通过添加这些重写的函数，我们给了操作系统在两种情况下通知我们用户意图的机会，就像我们在 Note to self 应用程序中保存和加载数据时所做的那样。

在这一点上，继续前进到这个应用程序最重要的类`LiveDrawingView`。我们将在本章末尾讨论`MainActivity`。

# 编写 LiveDrawingView 类

我们要做的第一件事是解决`LiveDrawingView`类不是`View`类型并且具有错误构造函数的问题。更新类声明如下：

```kt
class LiveDrawingView(
        context: Context,
        screenX: Int)
    : SurfaceView(context){
```

您将被提示导入`android.view.SurfaceView`类，如下截图所示：

![编写 LiveDrawingView 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_21_01.jpg)

点击**确定**以确认。

`SurfaceView`是`View`的后代，现在`LiveDrawingView`也是`View`的一种类型，通过继承。看一下已添加的`import`语句。这种关系在下面的代码中得到了明确的说明：

```kt
android.view.SurfaceView

```

### 提示

请记住，正是由于多态性，我们可以将`View`的后代发送到`MainActivity`类的`setContentView`函数中，而正是由于继承，`LiveDrawingView`现在是`SurfaceView`的一种类型。

有很多`View`的后代可以扩展以解决这个初始问题，但是随着我们的继续，我们将看到`SurfaceView`具有一些非常特定的功能，非常适合实时交互应用程序，并且这对我们来说是正确的选择。我们还提供了一个与从`MainActivity`调用的参数匹配的构造函数。

要导入`Context`类，请按照以下步骤操作：

1.  将鼠标光标放在新构造函数签名中红色的`Context`文本上。

1.  按住*Alt*键并点击*Enter*键。从弹出选项中选择**导入类**。

前面的步骤将导入`Context`类。现在，我们的`LiveDrawingView`类或初始化它的`MainActivity`类中都没有错误。

在这个阶段，我们可以运行应用程序，看看使用`LiveDrawingView`作为`setContentView`中的`View`参数是否有效，并且我们有一个美丽的空白屏幕，准备在上面绘制我们的粒子系统。如果你愿意，你可以尝试一下，但我们将编写`LiveDrawingView`类，以便它接下来会做一些事情。

记住`LiveDrawingView`无法看到`MainActivity`中的变量。通过构造函数，`MainActivity`提供了一个对自身（`this`）的引用以及包含在`size.x`中的像素屏幕分辨率给`LiveDrawingView`。

在这个项目的过程中，我们将不断回到这个类。我们现在要做的是准备好设置基础，以便在下一章编写`ParticleSystem`实例后添加它们。

为了实现这一点，我们首先会添加一些属性。之后，我们将编写`draw`函数，它将揭示我们需要在屏幕上每秒绘制 60 次的新步骤。此外，我们将看到一些使用我们上一章的老朋友`Canvas`、`Paint`和`drawText`的熟悉代码。

在这一点上，我们需要讨论一些更多的理论；例如，我们将如何计时粒子的动画，以及如何在不干扰 Android 的平稳运行的情况下锁定这些时间。这最后两个主题，即**游戏循环**和**线程**，将允许我们在添加本章的最终代码并观察我们的粒子系统绘画应用程序的同时，尽管只有一点点文本。

### 提示

游戏循环是一个描述允许虚拟系统同时更新和绘制自身的概念，同时允许用户对其进行修改和交互。

## 添加属性

在我们编写的`LiveDrawingView`声明和构造函数之后添加属性，如下面的代码块所示：

```kt
// Are we debugging?
private val debugging = true

// These objects are needed to do the drawing
private lateinit var canvas: Canvas
private val paint: Paint = Paint()

// How many frames per second did we get?
private var fps: Long = 0
// The number of milliseconds in a second
private val millisInSecond: Long = 1000

// How big will the text be?
// Font is 5% (1/20th) of screen width
// Margin is 1.5% (1/75th) of screen width
private val fontSize: Int = mScreenX / 20
private val fontMargin: Int = mScreenX / 75

// The particle systems will be declared here later
```

确保你学习了代码，然后我们会讨论它。注意所有的属性都声明为`private`。你可以愉快地删除所有的`private`访问修饰符，代码仍然可以正常工作，但是，由于我们不需要从这个类的外部访问任何这些属性，所以通过声明它们为`private`来保证这永远不会发生是明智的。

第一个属性是`debugging`。我们将使用它来手动切换打印调试信息和不打印调试信息。

我们声明的两个类实例将处理屏幕上的绘制：

```kt
// These objects are needed to do the drawing
private lateinit var canvas: Canvas
private val paint: Paint = Paint()
```

以下两个属性将为我们提供一些关于我们需要实现平滑和一致动画的见解：

```kt
// How many frames per second did we get?
private var fps: Long = 0
// The number of milliseconds in a second
private val millisInSecond: Long = 1000
```

这两个属性都是`long`类型，因为它们将保存一个我们将用来测量时间的大数字。计算机根据自 1970 年以来的毫秒数来测量时间。我们将在学习游戏循环时更多地讨论这个问题；然而，现在，我们需要知道监视和测量每一帧动画的速度是如何确保粒子移动正如它们应该的。

第一个变量`fps`将在每一帧动画中重新初始化，大约每秒 60 次。它将被传递到每个`ParticleSystem`对象（每一帧动画）中，以便它们知道经过了多少时间，然后可以计算应该移动多远或不移动。

`millisInSecond`变量初始化为`1000`。一秒钟确实有`1000`毫秒。我们将在计算中使用这个变量，因为它会使我们的代码比使用字面值 1,000 更清晰。

我们刚刚添加的代码的下一部分如下所示：

```kt
// How big will the text be?
// Font is 5% (1/20th) of screen width
// Margin is 1.5% (1/75th) of screen width
private val fontSize: Int = screenX / 20
private val fontMargin: Int = screenX / 75
```

`fontSize`和`marginSize`属性将根据通过构造函数传入的像素屏幕分辨率（`screenX`）进行初始化。它们将保存以像素为单位的值，以使我们的文本格式整洁而简洁，而不是为每个文本部分不断进行计算。

在我们继续之前，我们应该明确一下，这些是您目前应该在`LiveDrawingView.kt`代码文件顶部拥有的`import`语句：

```kt
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.view.SurfaceView
```

现在，让我们准备好绘制。

## 编写 draw 函数

在我们刚刚添加的属性之后立即添加`draw`函数。代码中会有一些错误。我们将首先处理它们，然后我们将详细讨论`draw`函数与`SurfaceView`的关系，因为其中有一些看起来很陌生的代码行，以及一些熟悉的代码行。添加以下代码：

```kt
// Draw the particle systems and the HUD
private fun draw() {
   if (holder.surface.isValid) {
         // Lock the canvas (graphics memory) ready to draw
         canvas = holder.lockCanvas()

         // Fill the screen with a solid color
         canvas.drawColor(Color.argb(255, 0, 0, 0))

         // Choose a color to paint with
         paint.color = Color.argb(255, 255, 255, 255)

         // Choose the font size
         paint.textSize = fontSize.toFloat()

         // Draw the particle systems

         // Draw the HUD

         if (debugging) {
               printDebuggingText()
         }
         // Display the drawing on screen
         // unlockCanvasAndPost is a 
         // function of SurfaceHolder
         holder.unlockCanvasAndPost(canvas)
   }
}
```

我们有两个错误 - 一个错误是需要导入`Color`类。您可以按照通常的方式修复这个问题，或者手动添加下一行代码。无论您选择哪种方法，以下额外的行需要添加到文件顶部的代码中：

```kt
import android.graphics.Color;
```

现在让我们处理另一个错误。

### 添加 printDebuggingText 函数

第二个错误是调用`printDebuggingText`。该函数尚不存在，所以现在让我们添加它。按照以下方式在`draw`函数之后添加代码：

```kt
private fun printDebuggingText() {
   val debugSize = fontSize / 2
   val debugStart = 150
   paint.textSize = debugSize.toFloat()
   canvas.drawText("fps: $fps",
         10f, (debugStart + debugSize).toFloat(), paint)

 }
```

先前的代码使用本地的`debugSize`变量来保存`fontSize`属性值的一半。这意味着，由于`fontSize`（用于**HUD**）是根据屏幕分辨率动态初始化的，`debugSize`将始终是其一半。

### 提示

HUD 代表抬头显示，是指覆盖应用程序中其他对象的按钮和文本的一种花哨方式。

然后使用`debugSize`变量来设置字体的大小，然后开始绘制文本。`debugStart`变量是一个整洁的垂直位置的猜测，用于开始打印调试文本，并留有一些填充，以免它被挤得太靠近屏幕边缘。

然后使用这两个值来定位屏幕上显示当前每秒帧数的一行文本。由于此函数是从`draw`调用的，而`draw`又将从游戏循环中调用，因此这行文本将每秒刷新多达 60 次。

### 注意

在非常高或非常低分辨率屏幕上，您可能需要尝试不同的值，以找到适合您屏幕的值。

让我们探索`draw`函数中的这些新代码行，并确切地检查我们如何使用`SurfaceView`来处理所有绘图需求，从而处理我们的`LiveDrawingView`类的派生。

## 理解 draw 函数和 SurfaceView 类

从函数的中间开始，向外工作，我们有一些熟悉的东西，比如调用`drawColor`，然后我们像以前一样设置颜色和文本大小。我们还可以看到注释，指示我们最终将添加绘制粒子系统和 HUD 的代码的位置：

+   `drawColor`代码用纯色清除屏幕。

+   `paint`的`textSize`属性设置了绘制 HUD 的文本大小。

+   一旦我们更深入地探索了粒子系统，我们将编写绘制 HUD 的过程。我们将让玩家知道他们的绘图由多少个粒子和系统组成。

然而，完全新的是`draw`函数开头的代码，如下面的代码块所示：

```kt
if (holder.surface.isValid) {
         // Lock the canvas (graphics memory) ready to draw
         canvas = holder.lockCanvas()
```

`if`条件是`holder.surface.isValid`。如果这行返回 true，则确认我们要操作的内存区域以表示我们的绘图帧是可用的，然后代码继续在`if`语句内部。

这是因为我们所有的绘图和其他处理（比如移动对象）都将异步进行，而代码则会检测用户输入并监听操作系统的消息。这在以前的项目中不是问题，因为我们的代码只是坐在那里等待输入，绘制一个帧，然后再次坐在那里等待。

现在我们想要每秒连续执行 60 次代码，我们需要确认我们能够访问绘图的内存，然后再访问它。

这引发了另一个关于这段代码如何异步运行的问题。但这将在我们不久后讨论线程时得到解答。现在，只需知道这行代码检查另一部分我们的代码或 Android 本身是否正在使用所需的内存部分。如果空闲，那么`if`语句内的代码将执行。

此外，在`if`语句内执行的第一行代码调用`lockCanvas`，这样如果代码的另一部分在我们访问内存时尝试访问内存，它将无法访问 - 然后我们进行所有的绘制。

最后，在`draw`函数中，以下代码（加上注释）出现在最后：

```kt
// Display the drawing on screen
// unlockCanvasAndPost is a 
// function of SurfaceHolder
holder.unlockCanvasAndPost(canvas)
```

`unlockCanvasAndPost`函数将我们新装饰的`Canvas`对象（`canvas`）发送到屏幕上进行绘制，并释放锁定，以便其他代码区域可以使用它，尽管非常短暂，在整个过程开始之前。这个过程发生在每一帧动画中。

我们现在理解了`draw`函数中的代码。然而，我们仍然没有调用`draw`函数的机制。事实上，我们甚至没有调用`draw`函数一次。接下来，我们将讨论游戏循环和线程。

# 游戏循环

那么，游戏循环到底是什么？几乎每个实时绘图、基于图形的应用程序和游戏都有一个游戏循环。甚至你可能没有想到的游戏，比如回合制游戏，仍然需要将玩家输入与绘图和人工智能同步，同时遵循底层操作系统的规则。

应用程序中的对象需要不断更新，比如移动它们并在当前位置绘制所有内容，同时响应用户输入：

![游戏循环](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_21_03.jpg)

我们的游戏循环包括三个主要阶段：

1.  通过移动它们、检测碰撞和处理人工智能（如粒子运动和状态变化）来更新所有游戏和绘图对象

1.  根据刚刚更新的数据，绘制动画的最新状态帧

1.  响应用户的屏幕触摸

我们已经有一个`draw`函数来处理循环的这一部分。这表明我们将有一个函数来进行所有的更新。我们很快将编写一个`update`函数的大纲。此外，我们知道我们可以响应屏幕触摸，尽管我们需要稍微调整之前所有项目的方式，因为我们不再在`Activity`类内部工作，也不再使用布局中的传统 UI 小部件。

还有一个问题，就是（我简要提到过的）所有的更新和绘制都是异步进行的，以便检测屏幕触摸并监听操作系统。

### 提示

只是为了明确，异步意味着它不会同时发生。我们的代码将通过与 Android 和 UI 共享执行时间来工作。CPU 将在我们的代码、Android 或用户输入之间非常快速地来回切换。

但这三个阶段将如何循环？我们将如何编写这个异步系统，从中可以调用`update`和`draw`，并且如何使循环以正确的速度（或帧率）运行？

正如你可能猜到的那样，编写一个高效的游戏循环并不像一个`while`循环那样简单。

### 注意

然而，我们的游戏循环也将包含一个`while`循环。

我们需要考虑时间、开始和停止循环，以及不会导致操作系统变得无响应，因为我们正在独占整个 CPU 在我们的单个循环中。

但是我们何时以及如何调用我们的`draw`函数？我们如何测量和跟踪帧速率？考虑到这些问题，我们完成的游戏循环可能更好地由以下图表表示——注意引入**线程**的概念：

![游戏循环](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_21_04.jpg)

既然我们知道我们想要实现什么，那么让我们学习一下线程。

# 线程

那么，什么是线程？你可以把编程中的线程看作是故事中的线程。在故事的一个线程中，我们可能有主要角色在前线与敌人作战，而在另一个线程中，士兵的家人正在过着日常生活。当然，一个故事不一定只有两个线程——我们可以引入第三个线程。例如，故事还讲述了政治家和军事指挥官做出决策，这些决策会以微妙或不那么微妙的方式影响其他线程中发生的事情。

编程线程就像这样。我们在程序中创建部分或线程来控制不同的方面。在 Android 中，当我们需要确保一个任务不会干扰应用程序的主（UI）线程时，或者当我们有一个需要很长时间才能完成并且不能中断主线程执行的后台任务时，线程尤其有用。我们引入线程来代表这些不同的方面，原因如下：

+   从组织的角度来看，这是有道理的

+   它们是一种经过验证的构建程序的方法。

+   我们正在处理的系统的性质迫使我们无论如何都要使用它们

在 Android 中，我们同时出于这三个原因使用线程——因为这是有道理的，它有效，而且我们必须使用线程，因为 Android 系统的设计要求如此。

通常，我们在不知情的情况下使用线程。这是因为我们使用的类会代表我们使用线程。我们在第十九章中编写的所有动画，*动画和插值*，都在线程中运行。在 Android 中的另一个例子是`SoundPool`类，它在一个线程中加载声音。我们将在第二十三章中看到，或者说听到，`SoundPool`的作用，*Android 音效和 Spinner 小部件*。我们将再次看到，我们的代码不必处理我们即将学习的线程方面，因为这一切都由类内部处理。然而，在这个项目中，我们需要更多地参与其中。

在实时系统中，想象一下一个线程同时接收玩家的左右移动按钮点击，同时监听来自操作系统的消息，比如调用`onCreate`（以及我们稍后将看到的其他函数）的一个线程，以及另一个线程绘制所有图形并计算所有移动。

## 线程的问题

具有多个线程的程序可能会出现与之相关的问题，就像故事的线程一样；如果适当的同步没有发生，那么事情可能会出错。如果我们的士兵在战斗甚至战争之前就进入了战斗，会发生什么？

假设我们有一个变量，`Int x`，代表我们程序的三个线程使用的一个关键数据。如果一个线程稍微超前于自己，并使数据对其他两个线程来说“错误”会发生什么？这个问题是由多个线程竞争完成而保持无视而引起的**正确性**问题——因为毕竟，它们只是愚蠢的代码。

正确性问题可以通过对线程和锁定的密切监督来解决。**锁定**意味着暂时阻止一个线程的执行，以确保事情以同步的方式工作；这类似于防止士兵在战船靠岸并放下舷梯之前登船，从而避免尴尬的溅水。

多线程程序的另一个问题是**死锁**问题。在这种情况下，一个或多个线程被锁定，等待“正确”的时刻来访问`Int x`；然而，那个时刻永远不会到来，最终整个程序都会停滞不前。

你可能已经注意到，第一个问题（正确性）的解决方案是第二个问题（死锁）的原因。

幸运的是，这个问题已经为我们解决了。就像我们使用`Activity`类并重写`onCreate`来知道何时需要创建我们的应用程序一样，我们也可以使用其他类来创建和管理我们的线程。例如，对于`Activity`，我们只需要知道如何使用它们，而不需要知道它们是如何工作的。

那么，当你不需要了解它们时，我为什么要告诉你关于线程呢？这只是因为我们将编写看起来不同并且结构不熟悉的代码。我们可以实现以下目标：

+   理解线程的一般概念，它与几乎同时发生的故事线程相同

+   学习使用线程的几条规则

通过这样做，我们将毫无困难地编写我们的 Kotlin 代码来创建和在我们的线程中工作。Android 有几个不同的类来处理线程，不同的线程类在不同的情况下效果最好。

我们需要记住的是，我们将编写程序的部分，它们几乎同时运行。

### 提示

几乎是什么意思？发生的是 CPU 在线程之间轮换/异步地。然而，这发生得如此之快，以至于我们除了同时性/同步性之外无法感知任何东西。当然，在故事线程的类比中，人们确实是完全同步地行动。

让我们来看看我们的线程代码将是什么样子。现在先不要向项目添加任何代码。我们可以声明一个`Thread`类型的对象，如下所示：

```kt
private lateinit var thread: Thread
```

然后可以按以下方式初始化并启动它：

```kt
// Initialize the instance of Thread
thread = Thread(this)

// Start the thread
thread.start()
```

线程还有一个谜团；再看一下初始化线程的构造函数。以下是代码行，以方便你查看：

```kt
thread = Thread(this)
```

看一下传递给构造函数的参数；我们传入了`this`。请记住，代码是放在`LiveDrawingView`类中的，而不是`MainActivity`。因此，我们可以推断`this`是对`LiveDrawingView`类（它扩展了`SurfaceView`）的引用。

在 Android 总部的工程师编写`Thread`类时，他们很可能不会意识到有一天我们会编写我们的`LiveDrawingView`类。那么，这怎么可能呢？

`Thread`类需要传入一个完全不同的类型到它的构造函数。`Thread`构造函数需要一个`Runnable`对象。

### 注意

你可以通过查看 Android 开发者网站上的`Thread`类来确认这一事实：[`developer.android.com/reference/java/lang/Thread.html#Thread(java.lang.Runnable)`](https://developer.android.com/reference/java/lang/Thread.html#Thread(java.lang.Runnable))。

你还记得我们在第十二章中讨论过接口吗，*将我们的 Kotlin 连接到 UI 和空值*？作为提醒，我们可以通过在类声明后添加接口名称来实现接口。

然后我们必须实现接口的抽象函数。`Runnable`只有一个函数，就是`run`函数。

### 注意

你可以通过查看 Android 开发者网站上的`Runnable`接口来确认这个事实：[`developer.android.com/reference/java/lang/Runnable.html`](https://developer.android.com/reference/java/lang/Runnable.html)。

我们可以使用`override`关键字来改变当操作系统允许我们的线程对象运行其代码时发生的情况：

```kt
override fun run() {
         // Anything in here executes in a thread
         // No skill needed on our part
         // It is all handled by Android, the Thread class
         // and the Runnable interface
}
```

在重写的`run`函数中，我们将调用两个函数，一个是我们已经开始的`draw`，另一个是`update`。 `update`函数是我们所有计算和人工智能的地方。代码将类似于以下代码块，但现在不要添加：

```kt
override fun run() { 
    // Update the drawing based on
    // user input and physics
    update()

    // Draw all the particle systems in their updated locations
    draw() 
}
```

在适当的时候，我们也可以停止我们的线程，如下所示：

```kt
thread.join()
```

现在，`run`函数中的所有内容都在一个单独的线程中执行，使默认或 UI 线程监听触摸和系统事件。我们很快将看到这两个线程如何相互通信在绘图项目中。

请注意，我们的应用程序中所有这些代码的确切位置尚未解释，但在真实项目中向您展示会更容易。

# 使用线程实现游戏循环

现在我们已经了解了游戏循环和线程，我们可以将它们全部整合到 Living Drawing 项目中来实现我们的游戏循环。

我们将添加整个游戏循环的代码，包括在`MainActivity`类中编写两个函数的代码，以启动和停止控制循环的线程。

### 提示

**读者挑战**

您能自己想出`Activity`-based 类将如何在`LiveDrawingView`类中启动和停止线程吗？

## 实现 Runnable 并提供 run 函数

通过实现`Runnable`来更新类声明，如下所示：

```kt
class LiveDrawingView(
        context: Context,
        screenX: Int)
    : SurfaceView(context), Runnable {
```

请注意，代码中出现了一个新错误。将鼠标光标悬停在`Runnable`一词上，您将看到一条消息，告诉您我们需要实现`run`函数，就像我们在上一节关于接口和线程的讨论中讨论的那样。添加空的`run`函数，包括`override`标签。

无论您在何处添加它，只要在`LiveDrawingView`类的大括号内而不是在另一个函数内。添加空的`run`函数，如下所示：

```kt
// When we start the thread with:
// thread.start();
// the run function is continuously called by Android
// because we implemented the Runnable interface
// Calling thread.join();
// will stop the thread
override fun run() {

}
```

错误已经消失，现在我们可以声明和初始化一个`Thread`对象了。

## 编写线程

在`LiveDrawingView`类的所有其他成员下面声明一些变量和实例，如下所示：

```kt
// Here is the Thread and two control variables
private lateinit var thread: Thread
// This volatile variable can be accessed
// from inside and outside the thread
@Volatile
private var drawing: Boolean = false
private var paused = true
```

现在，我们可以启动和停止线程了-花点时间考虑我们可能在哪里这样做。请记住，应用程序需要响应启动和停止应用程序的操作系统。

## 启动和停止线程

现在，我们需要启动和停止线程。我们已经看到了我们需要的代码，但是何时何地应该这样做呢？让我们添加两个函数的代码-一个用于启动，一个用于停止-然后我们可以考虑何时何地调用这些函数。在`LiveDrawingView`类中添加这两个函数。如果它们的名称听起来很熟悉，那并非偶然：

```kt
// This function is called by MainActivity
// when the user quits the app
fun pause() {
   // Set drawing to false
   // Stopping the thread isn't
   // always instant
   drawing = false
   try {
         // Stop the thread
         thread.join()
  }  catch (e: InterruptedException) {
     Log.e("Error:", "joining thread")
  }

}

// This function is called by MainActivity
// when the player starts the app
fun resume() {
    drawing = true
    // Initialize the instance of Thread
    thread = Thread(this)

    // Start the thread
    thread.start()
}
```

注释略微透露了发生的事情。现在我们有一个`pause`和`resume`函数，使用我们之前讨论过的相同代码来停止和启动`Thread`对象。

请注意，新函数是`public`的，因此它们可以从类外部访问，任何具有`LiveDrawingView`实例的其他类都可以访问。请记住，`MainActivity`保存了完全声明和初始化的`LiveDrawingView`实例。

让我们使用 Android Activity 生命周期来调用这两个新函数。

## 使用 Activity 生命周期来启动和停止线程

更新`MainActivity`中重写的`onResume`和`onPause`函数，如下所示：

```kt
override fun onResume() {
  super.onResume()

  // More code here later in the chapter
 liveDrawingView.resume()
}

override fun onPause() {
   super.onPause()

   // More code here later in the chapter
 liveDrawingView.pause()
}
```

现在，我们的线程将在操作系统恢复和暂停我们的应用程序时启动和停止。请记住，`onResume`在应用程序首次启动时（不仅是从暂停恢复时）调用，而不仅仅是在从暂停恢复后调用。在`onResume`和`onPause`中的代码使用`liveDrawingView`对象调用其`resume`和`pause`函数，这些函数又调用启动和停止线程的代码。然后触发线程的`run`函数执行。就是在这个`run`函数（在`LiveDrawingView`中）中，我们将编写我们的游戏循环。现在让我们来做这个。

## 编写 run 函数

尽管我们的线程已经设置好并准备就绪，但由于`run`函数为空，所以什么也不会发生。编写`run`函数，如下所示：

```kt
override fun run() {
   // The drawing Boolean gives us finer control
   // rather than just relying on the calls to run
   // drawing must be true AND
   // the thread running for the main
   // loop to execute
   while (drawing) {

         // What time is it now at the 
         // start of the loop?
         val frameStartTime = 
               System.currentTimeMillis()

        // Provided the app isn't paused
        // call the update function
        if (!paused) {
              update()
        }

        // The movement has been handled
        // we can draw the scene.
        draw()

        // How long did this frame/loop take?
        // Store the answer in timeThisFrame
        val timeThisFrame = System.currentTimeMillis() 
            - frameStartTime

      // Make sure timeThisFrame is 
      // at least 1 millisecond
      // because accidentally dividing
      // by zero crashes the app
      if (timeThisFrame > 0) {
            // Store the current frame rate in fps
            // ready to pass to the update functions of
            // of our particles in the next frame/loop
            fps = millisInSecond / timeThisFrame
      }
   }
}
```

请注意，Android Studio 中有两个错误。这是因为我们还没有编写`update`函数。让我们快速添加一个空函数（带有注释）；我在`run`函数后面添加了我的：

```kt
private fun update() {
   // Update the particles
}
```

现在，让我们逐步详细讨论`run`函数中的代码如何通过一步一步的方式实现游戏循环的目标。

这第一部分启动了一个`while`循环，条件是`drawing`，然后将代码的其余部分包装在`run`中，以便线程需要启动（调用`run`）并且`drawing`需要为`true`才能执行`while`循环：

```kt
override fun run() {
   // The drawing Boolean gives us finer control
   // rather than just relying on the calls to run
   // drawing must be true AND
   // the thread running for the main
   // loop to execute
   while (drawing) {
```

`while`循环内的第一行代码声明并初始化了一个名为`frameStartTime`的局部变量，其值为当前时间。`System`类的`currentTimeMillis`函数返回此值。如果以后我们想要测量一帧花费了多长时间，那么我们需要知道它开始的时间：

```kt
// What time is it now at the 
// start of the loop?
val frameStartTime = 
  System.currentTimeMillis()
```

接下来，在`while`循环中，我们检查应用程序是否暂停，只有在应用程序没有暂停的情况下，才会执行下一段代码。如果逻辑允许在此块内执行，则调用`update`：

```kt
// Provided the app isn't paused
// call the update function
if (!paused) {
   update()
}
```

在前一个`if`语句之外，调用`draw`函数以绘制所有对象的最新位置。此时，另一个局部变量被声明并初始化为完成整个帧（更新和绘制）所花费的时间长度。这个值是通过获取当前时间（再次使用`currentTimeMillis`）并从中减去`frameStartTime`来计算的，如下所示：

```kt
// The movement has been handled
// we can draw the scene.
draw()

// How long did this frame/loop take?
// Store the answer in timeThisFrame
val timeThisFrame = System.currentTimeMillis() 
  - frameStartTime
```

下一个`if`语句检测`timeThisFrame`是否大于零。如果线程在对象初始化之前运行，该值可能为零。如果您查看`if`语句内的代码，它通过将经过的时间除以`millisInSecond`来计算帧速率。如果除以零，应用程序将崩溃，这就是我们进行检查的原因。

一旦`fps`获得了分配给它的值，我们可以在下一帧中使用它传递给`update`函数，该函数将更新我们将在下一章中编写的所有粒子。它们将使用该值来确保它们根据其目标速度和刚刚结束的动画帧的长度移动了精确的数量：

```kt
// Make sure timeThisFrame is 
// at least 1 millisecond
// because accidentally dividing
// by zero crashes the app
if (timeThisFrame > 0) {
   // Store the current frame rate in fps
   // ready to pass to the update functions of
   // of our particles in the next frame/loop
   fps = millisInSecond / timeThisFrame
}
```

在每一帧中初始化`fps`的计算结果是，`fps`将保存一个分数。随着帧速率的波动，`fps`将保存不同的值，并为粒子系统提供适当的数量来计算每次移动。

# 运行应用程序

在 Android Studio 中单击播放按钮，本章的辛勤工作和理论将变为现实：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_21_05.jpg)

您可以看到，我们现在使用我们的游戏循环和线程创建了一个实时系统。如果您在真实设备上运行此应用程序，您将很容易在此阶段实现每秒 60 帧。

# 总结

这可能是迄今为止最技术性的一章。我们探讨了线程、游戏循环、定时、使用接口和`Activity`生命周期 - 这是一个非常长的主题列表。

如果这些事物之间的确切相互关系仍然不是很清楚，那也没关系。您只需要知道，当用户启动和停止应用程序时，`MainActivity`类将通过调用`LiveDrawingView`类的`pause`和`resume`函数来处理启动和停止线程。它通过重写的`onPause`和`onResume`函数来实现，这些函数由操作系统调用。

一旦线程运行，`run`函数内的代码将与监听用户输入的 UI 线程一起执行。通过同时从`run`函数调用`update`和`draw`函数，并跟踪每帧花费的时间，我们的应用程序已经准备就绪。

我们只需要允许用户向他们的艺术作品添加一些粒子，然后我们可以在每次调用`update`时更新它们，并在每次调用`draw`时绘制它们。

在下一章中，我们将编写、更新和绘制`Particle`和“ParticleSystem”类。此外，我们还将为用户编写代码，使其能够与应用程序进行交互（进行一些绘图）。
