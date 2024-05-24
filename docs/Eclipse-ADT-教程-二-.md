# Eclipse ADT 教程（二）

> 原文：[`zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363`](https://zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：布局模式

在前面的章节中，我们已经了解了创建对象时最常用的模式以及一些最常使用的材质组件。为了将这些内容整合在一起，我们需要考虑应用程序可能需要的整体布局。这使我们能够更详细地规划我们的应用程序，同时也带来了为不同尺寸屏幕和方向设计应用程序的有趣挑战。Android 平台为开发各种屏幕尺寸和形状提供了非常简单直观的方法，并且只需编写很少的额外代码。最后，我们将探索并创建一个策略模式。

在本章中，您将学习如何：

+   使用相对布局和线性布局

+   应用重力和权重

+   使用 weightSum 缩放权重

+   使用百分比支持库

+   为特定屏幕尺寸开发布局

+   创建策略模式

Android 平台提供了一系列布局类。从非常简单的**帧布局**到支持库提供的相当复杂的布局。最广泛使用且最灵活的是线性布局和相对布局。

# 线性布局

在相对布局和线性布局之间选择通常非常简单。如果您的组件是从一边到另一边堆叠的，那么**线性布局**是明显的选择。尽管嵌套视图组是可能的，但对于更复杂的布局，相对布局通常是最好的选择。这主要是因为嵌套布局会消耗资源，应尽可能避免深层层次结构。**相对布局**可以用来创建许多复杂的布局，而无需大量嵌套。

无论哪种形式最适合我们的需求，一旦开始在形状不同的屏幕上测试我们的布局，或者将屏幕旋转 90°，我们很快就会发现我们在创建具有美观比例的组件上所做的所有思考都白费了。通常，这些问题可以通过使用**重力**属性定位元素并通过**权重**属性进行缩放来解决。

## 权重和重力

能够设置位置和比例而不必过分关注屏幕的确切形状可以为我们节省大量工作。通过设置组件和控件的权重属性，我们可以确定单个组件占用的屏幕宽度或高度的比例。当我们希望大多数控件使用`wrap_content`，以便根据用户需求进行扩展，但同时也希望一个视图占用尽可能多的空间时，这特别有用。

例如，在以下布局中的图像将随着上方文本的增长而适当缩小。

![权重和重力](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_001.jpg)

在此图中，只有图像视图应用了权重，其他视图的`height`都使用`wrap_content`声明。正如这里所看到的，我们需要将`layout_height`设置为`0dp`以避免在设置视图高度时发生内部冲突：

```kt
<ImageView 
    android:id="@+id/feedback_image" 
    android:layout_width="match_parent" 
    android:layout_height="0dp" 
    android:layout_weight="1" 
    android:contentDescription="@string/content_description" 
    android:src="img/tomatoes" /> 

```

### 提示

权重不仅可以应用于单个小部件和视图，还可以应用于视图组和嵌套布局。

自动填充可能变化的屏幕空间非常有用，但权重可以应用于多个视图，以创建每个视图占用活动指定相对面积的布局。例如，以下图片就使用了`1`、`2`、`3`和`2`的权重进行缩放。

![权重和重力](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_002.jpg)

尽管通常应避免在一个布局中嵌套另一个布局，但考虑一两个层级往往是有价值的，因为这可以产生一些非常实用的活动。例如：

![权重和重力](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_003.jpg)

这个布局仅使用两个嵌套的视图组，且权重的使用可以使得结构在相当广泛的屏幕尺寸上都能很好地工作。当然，这个布局在竖屏模式下看起来会很糟糕，但我们在本章后面会看到如何解决这个问题。生成此类布局的 XML 代码如下所示：

```kt
<FrameLayout 
    android:layout_width="match_parent" 
    android:layout_height="56dp" /> 

<LinearLayout 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="horizontal"> 

    <FrameLayout 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_weight="2" /> 

    <LinearLayout 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_weight="1" 
        android:orientation="vertical"> 

        <FrameLayout 
            android:layout_width="match_parent" 
            android:layout_height="0dp" 
            android:layout_weight="3" /> 

        <FrameLayout 
            android:layout_width="match_parent" 
            android:layout_height="0dp" 
            android:layout_weight="2" /> 

    </LinearLayout> 

    <FrameLayout 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_weight="1" /> 

</LinearLayout> 

```

上面的示例引出了一个有趣的问题。如果我们不想填满布局的整个宽度和高度怎么办？如果我们想要留出一些空间呢？这可以通过**weightSum**属性轻松管理。

要了解`weightSum`是如何工作的，可以在上一个示例中的内部线性布局定义中添加以下突出显示的属性：

```kt
<LinearLayout 
    android:layout_width="0dp" 
    android:layout_height="match_parent" 
    android:layout_weight="1" 
    android:orientation="vertical" 
    android:weightSum="10"> 

```

通过为布局设置最大权重，内部权重将按比例设置。在这个例子中，`weightSum`为`10`设置了内部权重，即`3`和`2`，分别占布局高度的 3/10 和 2/10，如下所示：

|  |   |
| --- | --- |
|  | ![权重和重力](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_004.jpg) |

### 提示

请注意，权重和`weightSum`都是浮点属性，使用如下这样的行可以取得更高的精确度：`android:weightSum="20.5"`。

使用权重是充分利用未知屏幕大小和形状的极其有用的方法。管理整体屏幕空间的另一种技术是使用重力来定位组件及其内容。

**gravity**属性用于对齐视图及其内容。在之前给出的示例中，以下标记被用于将动作定位在活动的底部：

```kt
<TextView 
    android:id="@+id/action_post" 
    android:layout_width="100dp" 
    android:layout_height="wrap_content" 
    android:layout_gravity="right" 
    android:clickable="true" 
    android:padding="16dp" 
    android:text="@string/action_post" 
    android:textColor="@color/colorAccent" 
    android:textSize="24sp" /> 

```

这个示例演示了如何使用`layout_gravity`来对齐容器内的视图（或视图组）。单个视图的内容也可以通过`gravity`属性在视图内部定位，可以像这样设置：

```kt
android:layout_gravity="top|left" 

```

将布局按行和列排序可能是考虑屏幕布局的最简单方法，但这不是唯一的方法。**相对布局**提供了一种基于位置而非比例的替代技术。相对布局还允许我们使用**百分比支持库**来对其内容进行比例调整。

# 相对布局

相对布局最大的优势可能是它能够减少在构建复杂布局时嵌套视图组数量。这是通过定义视图的位置以及它们如何通过属性如`layout_below`和`layout_toEndOf`相互定位和对齐来实现的。要看这是如何操作的，可以考虑上一个示例中的线性布局。我们可以将其重新创建为一个没有嵌套视图组的相对布局，如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  
    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <FrameLayout 
        android:id="@+id/header" 
        android:layout_width="match_parent" 
        android:layout_height="56dp" 
        android:layout_alignParentTop="true" 
        android:layout_centerHorizontal="true" /> 

    <FrameLayout 
        android:id="@+id/main_panel" 
        android:layout_width="320dp" 
        android:layout_height="match_parent" 
        android:layout_alignParentStart="true" 
        android:layout_below="@+id/header" /> 

    <FrameLayout 
        android:id="@+id/center_column_top" 
        android:layout_width="160dp" 
        android:layout_height="192dp" 
        android:layout_below="@+id/header" 
        android:layout_toEndOf="@+id/main_panel" /> 

    <FrameLayout 
        android:id="@+id/center_column_bottom" 
        android:layout_width="160dp" 
        android:layout_height="match_parent" 
        android:layout_below="@+id/center_column_top" 
        android:layout_toEndOf="@+id/main_panel" /> 

    <FrameLayout 
        android:id="@+id/right_column" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:layout_below="@+id/header" 
        android:layout_toEndOf="@+id/center_column_top" /> 

</RelativeLayout> 

```

尽管这种方法的明显优势是不需要嵌套视图组，但我们必须明确设置单个视图的尺寸，一旦在不同屏幕上预览输出，这些比例很快就会丢失，或者至少会被扭曲。

解决这个问题的方法之一可能是为不同的屏幕配置创建单独的`dimens.xml`文件，但如果我们想要填充屏幕的精确百分比，那么我们永远无法保证在每种可能的设备上都能实现这一点。幸运的是，Android 提供了一个非常有用的支持库。

## 百分比支持库

在相对布局中为给定组件定义确切比例可能是一个问题，因为我们只能描述事物在哪里，而不能描述它们在组内的突出程度。幸运的是，百分比库提供了**PercentRelativeLayout**来解决这一问题。

与其他支持库一样，百分比库必须包含在`build.gradle`文件中：

```kt
compile 'com.android.support:percent:23.4.0' 

```

要创建之前的相同布局，我们将使用以下代码：

```kt
<android.support.percent.PercentRelativeLayout  

    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <FrameLayout 
        android:id="@+id/header" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_alignParentTop="true" 
        android:layout_centerHorizontal="true" 
        app:layout_heightPercent="20%" /> 

    <FrameLayout 
        android:id="@+id/main_panel" 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_alignParentStart="true" 
        android:layout_below="@+id/header" 
        app:layout_widthPercent="50%" /> 

    <FrameLayout 
        android:id="@+id/center_column_top" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_below="@+id/header" 
        android:layout_toEndOf="@+id/main_panel" 
        app:layout_heightPercent="48%" 
        app:layout_widthPercent="25%" /> 

    <FrameLayout 
        android:id="@+id/center_column_bottom" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_below="@+id/center_column_top" 
        android:layout_toEndOf="@+id/main_panel" 
        app:layout_heightPercent="32%" 
        app:layout_widthPercent="25%" /> 

    <FrameLayout 
        android:id="@+id/right_column" 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_below="@+id/header" 
        android:layout_toEndOf="@+id/center_column_top" 
        app:layout_widthPercent="25%" /> 

</android.support.percent.PercentRelativeLayout> 

```

百分比库提供了一种直观且简单的方法来创建比例，这些比例在未测试的形态因素上显示时不容易被扭曲。这些模型在其他具有相同方向的设备上测试时工作得非常好。然而，一旦我们将这些布局旋转 90°，我们就能看到问题所在。幸运的是，Android SDK 允许我们重用我们的布局模式，以最小的重新编码创建替代版本。正如我们所料，这是通过创建指定的布局配置来实现的。

# 屏幕旋转

大多数，如果不是全部的移动设备，都允许屏幕重新定向。许多应用程序（如视频播放器）更适合一个方向而不是另一个。一般来说，我们希望我们的应用程序无论旋转多少度都能看起来最好。

当从竖屏转换为横屏或反之亦然时，大多数布局看起来都很糟糕。显然，我们需要为这些情况创建替代方案。幸运的是，我们不需要从头开始。要看这是如何实现的，可以从这里的一个标准的竖屏布局开始：

![屏幕旋转](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_005.jpg)

这可以通过以下代码重新创建：

```kt

    <android.support.percent.PercentRelativeLayout  

    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <FrameLayout 
        android:id="@+id/header" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_alignParentTop="true" 
        android:layout_centerHorizontal="true" 
        android:background="@color/colorPrimary" 
        android:elevation="6dp" 
        app:layout_heightPercent="10%" /> 

    <ImageView 
        android:id="@+id/main_panel" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_alignParentStart="true" 
        android:layout_below="@+id/header" 
        android:background="@color/colorAccent" 
        android:contentDescription="@string/image_description" 
        android:elevation="4dp" 
        android:scaleType="centerCrop" 
        android:src="img/cheese" 
        app:layout_heightPercent="40%" /> 

    <FrameLayout 
        android:id="@+id/panel_b" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_alignParentEnd="true" 
        android:layout_below="@+id/main_panel" 
        android:background="@color/material_grey_300" 
        app:layout_heightPercent="30%" 
        app:layout_widthPercent="50%" /> 

    <FrameLayout 
        android:id="@+id/panel_c" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_alignParentEnd="true" 
        android:layout_below="@+id/panel_b" 
        android:background="@color/material_grey_100" 
        app:layout_heightPercent="20%" 
        app:layout_widthPercent="50%" /> 

    <FrameLayout 
        android:id="@+id/panel_a" 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_alignParentStart="true" 
        android:layout_below="@+id/main_panel" 
        android:elevation="4dp" 
        app:layout_widthPercent="50%" /> 

</android.support.percent.PercentRelativeLayout> 

```

同样，一旦旋转，它看起来设计得非常糟糕。为了创建一个可接受的横屏版本，请在设计模式下查看你的布局，并点击设计面板左上角的配置图标，选择**创建横屏变体**：

![屏幕旋转](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_006.jpg)

这会在一个文件夹中创建我们文件的副本，该文件夹在应用程序处于横屏模式时会引用其布局定义。这个目录与`res/layout`文件夹并列，名为`res/layout-land`。现在只需重新排列我们的视图以适应这种新格式，实际上，我们可以使用本章早些时候的布局，如下所示：

```kt
<android.support.percent.PercentRelativeLayout  

    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <FrameLayout 
        android:id="@+id/header" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_alignParentTop="true" 
        android:layout_centerHorizontal="true" 
        android:background="@color/colorPrimary" 
        android:elevation="6dp" 
        app:layout_heightPercent="15%" /> 

    <ImageView 
        android:id="@+id/main_panel" 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_alignParentStart="true" 
        android:layout_below="@+id/header" 
        android:background="@color/colorAccent" 
        android:contentDescription="@string/image_description" 
        android:elevation="4dp" 
        android:scaleType="centerCrop" 
        android:src="img/cheese" 
        app:layout_widthPercent="50%" /> 

    <FrameLayout 
        android:id="@+id/panel_a" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_below="@+id/header" 
        android:layout_toRightOf="@id/main_panel" 
        android:background="@color/material_grey_300" 
        app:layout_heightPercent="50%" 
        app:layout_widthPercent="25%" /> 

    <FrameLayout 
        android:id="@+id/panel_b" 
        android:layout_width="0dp" 
        android:layout_height="0dp" 
        android:layout_below="@+id/panel_a" 
        android:layout_toRightOf="@id/main_panel" 
        android:background="@color/material_grey_100" 
        app:layout_heightPercent="35%" 
        app:layout_widthPercent="25%" /> 

    <FrameLayout 
        android:id="@+id/panel_c" 
        android:layout_width="0dp" 
        android:layout_height="match_parent" 
        android:layout_alignParentEnd="true" 
        android:layout_below="@+id/header" 
        android:elevation="4dp" 
        app:layout_widthPercent="25%" /> 

</android.support.percent.PercentRelativeLayout> 

```

![屏幕旋转](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_007.jpg)

应用这些更改并创建横屏布局只需几秒钟，但我们还可以做得更多。特别是，我们可以创建专门为大屏幕和平板电脑设计的布局。

# 大屏幕布局

当我们从配置菜单创建我们布局的横屏版本时，你无疑注意到了**创建 layout-xlarge 版本**的选项，正如你所想象的，这是用于为平板电脑和甚至电视的大屏幕创建合适的布局。

如果你选择这个选项，你会立即看到我们对百分比库的明智使用产生了相同的布局，可能会觉得这个布局是不必要的，但这会忽略重点。像 10 英寸平板这样的设备提供了更多的空间，我们不仅应该放大我们的布局，还应该利用这个机会提供更多的内容。

在这个例子中，我们只为 xlarge 版本添加一个额外的框架。这很容易做到，只需添加以下 XML，并调整其他视图的高度百分比值：

```kt
<FrameLayout 
    android:id="@+id/panel_d" 
    android:layout_width="0dp" 
    android:layout_height="0dp" 
    android:layout_alignParentEnd="true" 
    android:layout_below="@+id/panel_c" 
    android:background="@color/colorAccent" 
    android:elevation="4dp" 
    app:layout_heightPercent="30%" 
    app:layout_widthPercent="50%" /> 

```

![大屏幕布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_008.jpg)

除了充分利用大屏幕，我们也可以通过使用`small`限定符为小屏幕实现相反的效果。这有助于优化小屏幕的布局，通过缩小元素大小，甚至移除不那么重要的内容。

我们在这里看到的限定符非常有用，但它们仍然相当宽泛。根据设备分辨率，我们可能会很容易地发现相同的布局被应用于大手机和小平板上。幸运的是，框架提供了让我们在定义布局时更加精确的方法。

## 宽度限定符

作为开发者，我们花费大量时间和精力寻找和创造优质的图像和其他媒体内容。重要的是，我们要让这些工作得到应有的展示，确保它们以最佳效果呈现。想象一下，你有一个至少需要 720 像素宽才能最好地欣赏的布局。在这种情况下，我们可以做两件事。

首先，我们可以确保我们的应用程序只在至少具有我们所需屏幕分辨率的设备上可用，这可以通过编辑`AndroidManifest`文件来实现，在`manifest`元素内添加以下标签：

```kt
 <supports-screens android:requiresSmallestWidthDp="720" /> 

```

通常，让我们的应用对小型屏幕用户不可用是一件遗憾的事，我们可能这样做的情况很少。为大型电视屏幕设计或精确照片编辑的应用可能是例外。更常见的是，我们更愿意创建适合尽可能多的屏幕尺寸的布局，这导致了我们的第二个选项。

安卓平台允许我们根据诸如 **最小和可用宽度**（以像素为单位）的具体屏幕尺寸标准来设计布局。通过*最小*，我们指的是两个屏幕尺寸中最窄的一个，无论方向如何。对于大多数设备来说，这意味着在纵向模式下查看时的宽度，以及横向模式下的高度。使用*可用*宽度提供了另一个级别的灵活性，即宽度是根据屏幕的方向来测量的，这允许我们设计一些非常特定的布局。根据最小宽度优化布局非常简单，就像以前使用限定符一样。所以一个名为：

```kt
res/layout-sw720dp/activity_main.xml 

```

将替换

```kt
res/layout/activity_main.xml 

```

在最短边为 720 dp 或更大的设备上。

当然，我们可以创建任意大小文件夹，例如 `res/layout-sw600dp`。

这种技术非常适合为大型屏幕设计布局，无论方向如何。然而，根据设备在特定时刻的方向来应用基于外观宽度的布局设计可能非常有用。这是通过指定目录以类似方式实现的。为了设计可用宽度，使用：

```kt
res/layout-w720dp 

```

为了优化可用高度，使用：

```kt
res/layout-h720dp 

```

这些限定符提供了确保我们的设计充分利用可用硬件的非常有用的技术，但如果我们想要为运行 Android 3.1 或更低版本的设备开发，就有一个小缺点。在这些设备上，最小和可用宽度限定符不可用，我们必须使用 `large` 和 `xlarge` 限定符。这可能导致两个相同的布局，浪费空间并增加我们的维护成本。幸运的是，有一种方法可以解决这个问题，那就是布局别名。

## 布局别名

为了演示布局别名如何工作，我们将想象一个简单的案例，我们只有两个布局，一个是默认的 `activity_main.xml` 文件，其中只有两个视图，另一个是我们称之为 `activity_main_large.xml` 的布局，它有三个视图，以利用更大的屏幕。要了解如何完成此操作，请按照以下步骤操作：

1.  打开 `activity_main` 文件，为其提供以下两个视图：

    ```kt
    <ImageView 
        android:id="@+id/image_view" 
        android:layout_width="match_parent" 
        android:layout_height="256dp" 
        android:layout_alignParentLeft="true" 
        android:layout_alignParentStart="true" 
        android:layout_alignParentTop="true" 
        android:contentDescription="@string/content_description" 
        android:scaleType="fitStart" 
        android:src="img/sandwich" /> 

    <TextView 
        android:id="@+id/text_view" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_below="@+id/image_view" 
        android:layout_centerHorizontal="true" 
        android:layout_centerVertical="true" 
        android:text="@string/text_value" 
        android:textAppearance="?android:attr/textAppearanceLarge" /> 

    ```

1.  复制此文件，将其命名为 `activity_main_large` 并添加以下视图：

    ```kt
    <TextView 
        android:id="@+id/text_view2" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_alignParentEnd="true" 
        android:layout_alignParentRight="true" 
        android:layout_below="@+id/text_view" 
        android:layout_marginTop="16dp" 
        android:text="@string/extra_text" 
        android:textAppearance="?android:attr/textAppearanceMedium" /> 

    ```

    ```kt
    <ImageView 
        android:id="@+id/image_view" 
        android:layout_width="match_parent" 
        android:layout_height="256dp" 
        android:layout_alignParentLeft="true" 
        android:layout_alignParentStart="true" 
        android:layout_alignParentTop="true" 
        android:contentDescription="@string/content_description" 
        android:scaleType="fitStart" 
        android:src="img/sandwich" /> 

    <TextView 
        android:id="@+id/text_view" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_below="@+id/image_view" 
        android:layout_centerHorizontal="true" 
        android:layout_centerVertical="true" 
        android:text="@string/text_value" 
        android:textAppearance="?android:attr/textAppearanceLarge" /> 

    ```

1.  创建两个名为 `res/values-large` 和 `res/values-sw720dp` 的 **新建 | 安卓资源目录**。

1.  在 `values-large` 文件夹中，创建一个名为 `layout.xml` 的文件，并完成如下：

    ```kt
    <resources> 
        <item name="main" type="layout">@layout/activity_main_large</item> 
    </resources> 

    ```

1.  最后，在 `values-sw720dp` 文件夹中创建一个相同的文件：![布局别名](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_009.jpg)

以这种方式使用布局别名意味着我们只需要创建一个大型布局，无论设备运行的是哪个 Android 平台，它都将应用于大屏幕。

在这个例子中，我们选择`720dp`作为我们的阈值。在大多数情况下，这将针对 10 英寸平板和更大的设备。如果我们希望我们的较大布局在大多数 7 英寸平板和大手机上运行，我们会使用`600dp`，当然我们可以选择任何符合我们目的的值。

### 提示

有时，我们可能希望限制应用仅支持横屏或竖屏。这可以通过在清单文件的 activity 标签中添加`android:screenOrientation="portrait"`或`android:screenOrientation="landscape"`来实现。

### 注意

通常来说，我们应该为手机、7 英寸平板和 10 英寸平板创建横屏和竖屏布局。

设计吸引人且直观的布局是我们作为开发者面临的最重要任务之一，这里引入的快捷方式大大减少了我们的工作量，使我们能够专注于设计吸引人的应用程序。

与上一章一样，我们关注的是更实际的布局结构问题，这当然是进一步开发的前提。然而，有很多模式需要我们熟悉，我们越早熟悉它们越好，这样我们就越有可能识别出那些可能从应用模式中受益的结构。本章探讨的情况中可以应用的一种模式就是策略设计模式。

# 策略模式

策略模式是另一种被广泛使用且极其有用的模式。其美妙之处在于它的灵活性，因为它可以应用于众多场景中。其目的是在运行时为给定问题提供一系列解决方案（策略）。一个很好的例子就是，一个应用在安装于 Windows、Mac OS 或 Linux 系统时，会采用不同的策略来运行不同的代码。如果我们上面用来为不同设备设计 UI 的系统如此高效，我们可以轻松地使用策略模式来完成这项任务。它看起来会像这样：

![策略模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_010.jpg)

目前，我们将稍微向前迈进一步，设想一下我们的三明治制作应用用户准备支付的情况。我们将假设三种支付方式：信用卡、现金和优惠券。现金支付的用户将直接支付设定的价格。有些不公平的是，信用卡支付的用户将被收取小额费用，而持有优惠券的用户将获得 10%的折扣。我们还将使用单例来表示应用这些策略之前的基本价格。按照以下步骤设置策略模式：

1.  我们通常从接口开始：

    ```kt
    public interface Strategy { 

        String processPayment(float price); 
    } 

    ```

1.  接下来，创建这个接口的具体实现，如下所示：

    ```kt
    public class Cash implements Strategy{ 

        @Override 
        public String processPayment(float price) { 

            return String.format("%.2f", price); 
        } 
    } 

    public class Card implements Strategy{ 
       ... 
            return String.format("%.2f", price + 0.25f); 
       ... 
    } 

    public class Coupon implements Strategy{ 
        ... 
            return String.format("%.2f", price * 0.9f); 
        ... 
    } 

    ```

1.  现在添加以下类：

    ```kt
    public class Payment { 
        // Provide context for strategies 

        private Strategy strategy; 

        public Payment(Strategy strategy) { 
            this.strategy = strategy; 
        } 

        public String employStrategy(float f) { 
            return strategy.processPayment(f); 
        } 
    } 

    ```

1.  最后，添加将提供我们基本价格的单例类：

    ```kt
    public class BasicPrice { 
        private static BasicPrice basicPrice = new BasicPrice(); 
        private float price; 

        // Prevent more than one copy 
        private BasicPrice() { 
        } 

        // Return only instance 
        public static BasicPrice getInstance() { 
            return basicPrice; 
        } 

        protected float getPrice() { 
            return price; 
        } 

        protected void setPrice(float v) { 
            price = v; 
        } 
    } 

    ```

这就是我们需要创建模式所做的一切。使用单例是因为当前三明治的价格是需要只有一个实例并且在代码的任何地方都能访问到的东西。在我们构建用户界面并测试我们的模式之前，让我们快速查看一下策略类图：

![策略模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_011.jpg)

从图中我们可以看到，活动包含了一个`onClick()`回调。在我们了解这是如何工作的之前，我们需要创建一个带有三个操作按钮的布局，以测试我们的三种支付选项。按照以下步骤来实现这一点：

1.  创建一个以水平线性布局为根的布局文件。

1.  添加以下视图和内部布局：

    ```kt
    <ImageView 
        android:id="@+id/image_view" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_weight="1" 
        android:scaleType="centerCrop" 
        android:src="img/logo" /> 

    <RelativeLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:orientation="horizontal" 
        android:paddingTop="@dimen/layout_paddingTop"> 

    </RelativeLayout> 

    ```

1.  现在给相对布局添加按钮。前两个按钮看起来像这样：

    ```kt
    <Button 
        android:id="@+id/action_card" 
        style="?attr/borderlessButtonStyle" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_alignParentEnd="true" 
        android:layout_gravity="end" 
        android:gravity="center_horizontal" 
        android:minWidth="@dimen/action_minWidth" 
        android:padding="@dimen/padding" 
        android:text="@string/card" 
        android:textColor="@color/colorAccent" /> 

    <Button 
        android:id="@+id/action_cash" 
        style="?attr/borderlessButtonStyle" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_gravity="end" 
        android:layout_toStartOf="@id/action_card" 
        android:gravity="center_horizontal" 
        android:minWidth="@dimen/action_minWidth" 
        android:padding="@dimen/padding" 
        android:text="@string/cash" 
        android:textColor="@color/colorAccent" /> 

    ```

1.  第三个与第二个相同，除了以下例外：

    ```kt
    <Button 
        android:id="@+id/action_coupon" 
        ... 
        android:layout_toStartOf="@id/action_cash" 
        ... 
        android:text="@string/voucher" 
        ... /> 

    ```

1.  现在打开 Java 活动文件，扩展它，使其实现这个监听器：

    ```kt
    public class MainActivity extends AppCompatActivity implements View.OnClickListener 

    ```

1.  接下来添加以下字段：

    ```kt
    public BasicPrice basicPrice = BasicPrice.getInstance(); 

    ```

1.  在`onCreate()`方法中包含以下这些行：

    ```kt
    // Instantiate action views 
    Button actionCash = (TextView) findViewById(R.id.action_cash); 
    Button actionCard = (TextView) findViewById(R.id.action_card); 
    Button actionCoupon = (TextView) findViewById(R.id.action_coupon); 

    // Connect to local click listener 
    actionCash.setOnClickListener(this); 
    actionCard.setOnClickListener(this); 
    actionCoupon.setOnClickListener(this); 

    // Simulate price calculation 
    basicPrice.setPrice(1.5f); 

    ```

1.  最后添加`onClick()`方法，如下所示：

    ```kt
        @Override 
        public void onClick(View view) { 
            Payment payment; 

            switch (view.getId()) { 

                case R.id.action_card: 
                    payment = new Payment(new Card()); 
                    break; 

                case R.id.action_coupon: 
                    payment = new Payment(new Coupon()); 
                    break; 

                default: 
                    payment = new Payment((new Cash())); 
                    break; 
            } 

            // Output price 
            String price = new StringBuilder() 
                    .append("Total cost : $") 
                    .append(payment.employStrategy(basicPrice.getPrice())) 
                    .append("c") 
                    .toString(); 

            Toast toast = Toast.makeText(this, price, Toast.LENGTH_LONG); 
            toast.show(); 
        } 

    ```

现在我们可以测试在设备或模拟器上的输出了：

![策略模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_04_012.jpg)

策略模式可以应用于许多情况，并且在你开发几乎任何软件时，你都会遇到可以一次又一次应用它的情况。我们肯定会在这里再次讨论它。希望现在介绍它能够帮助你发现可以利用它的情况。

# 总结

在本章中，我们了解了如何充分利用 Android 布局。这包括决定哪种布局类型适合哪种用途，尽管还有很多其他类型，但线性布局和相对布局提供了非常多的可能布局的功能和灵活性。选择了一个布局之后，我们可以使用权重和重力属性来组织空间。通过使用百分比库和 PercentRelativeLayout，大大简化了为各种可能的屏幕尺寸设计布局的过程。

开发者在为可能运行我们应用的众多现实世界设备设计 Android 布局时面临的最大挑战。幸运的是，资源指定的使用使得这项工作变得轻松。

当我们有了可用的布局后，我们可以继续了解如何利用这个空间显示一些有用的信息。这将引导我们在下一章中探讨 recycler view 如何管理列表及其数据。


# 第五章：结构型模式

到目前为止，在这本书中，我们已经了解了用于保存和返回数据的模式，以及将对象组合成更大的对象的模式，但我们还没有考虑如何向用户提供选择的方式。

在规划我们的三明治制作应用时，我们理想情况下希望能为客户提供多种可能的食材选择。展示这些选择的最佳方式可能是通过列表，或者对于大量数据集合，一系列的列表。Android 通过**回收视图（RecyclerView）**很好地管理这些过程，它是一个列表容器和管理器，取代了之前的 ListView。这并不是说我们不应该使用普通的旧列表视图，在只需要短列表、简单文本列表几个项目的情况下，使用回收视图可能被认为是大材小用，列表视图通常是更好的选择。话虽如此，回收视图在管理数据方面要优越得多，特别是当它包含在协调器布局中时，可以保持内存占用小、滚动平滑，并允许用户拖放或滑动删除列表项。

为了了解如何完成所有这些工作，我们将构建一个界面，该界面将由用户从中选择的一系列食材列表组成。这将需要回收视图来持有列表，进而将介绍我们适配器模式。

在本章中，你将学习如何：

+   应用回收视图（RecyclerView）

+   应用协调器布局（CoordinatorLayout）

+   生成列表

+   翻译字符串资源

+   应用视图持有者（ViewHolder）

+   使用回收视图适配器（RecyclerView adapter）

+   创建适配器设计模式

+   构建桥接设计模式

+   应用外观模式（facade patterns）

+   使用模式来过滤数据

# 生成列表

回收视图是相对较新的添加项，取代了旧版本中的 ListView。它执行相同的功能，但数据管理效率要高得多，特别是对于非常长的列表。回收视图是 v7 支持库的一部分，需要在`build.gradle`文件中编译，以及这里显示的其他内容：

```kt
compile 'com.android.support:appcompat-v7:24.1.1'compile 'com.android.support:design:24.1.1'compile 'com.android.support:cardview-v7:24.1.1'compile 'com.android.support:recyclerview-v7:24.1.1'
```

协调器布局将形成主活动的根布局，看起来会像这样：

```kt
<android.support.design.widget.CoordinatorLayoutandroid:id="@+id/content"android:layout_width="match_parent"android:layout_height="match_parent"></android.support.design.widget.CoordinatorLayout>
```

然后，回收视图可以被放置在布局内：

```kt
<android.support.v7.widget.RecyclerView 
    android:id="@+id/main_recycler_view" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    /> 

```

![生成列表](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_001.jpg)

回收视图为我们提供了一个虚拟列表，但我们将从卡片视图中创建我们的列表。

# 列表项布局

使用卡片视图显示列表中的单个项目非常诱人，你可以找到许多这样的例子。然而，这种做法并不被谷歌推荐，并且有充分的理由。卡片设计用于显示大小不一的内容，而圆角和阴影只会让屏幕显得杂乱。当列表项大小相同并符合相同的布局时，它们应该显示为简单的矩形布局，有时用简单的分隔线隔开。

在本书的后面，我们将创建复杂的、可交互的列表项，所以现在我们只将图像和字符串作为我们的项目视图。

创建一个以水平线性布局为根的布局文件，并将这两个视图放在其中：

```kt
<ImageView 
    android:id="@+id/item_image" 
    android:layout_width="@dimen/item_image_size" 
    android:layout_height="@dimen/item_image_size" 
    android:layout_gravity="center_vertical|end" 
    android:layout_margin="@dimen/item_image_margin" 
    android:scaleType="fitXY" 
    android:src="img/placeholder" /> 

<TextView 
    android:id="@+id/item_name" 
    android:layout_width="0dp" 
    android:layout_height="wrap_content" 
    android:layout_gravity="center_vertical" 
    android:layout_weight="1" 
    android:paddingBottom="24dp" 
    android:paddingStart="@dimen/item_name_paddingStart" 
    tools:text="placeholder" 
    android:textSize="@dimen/item_name_textSize" /> 

```

我们在这里使用了`tools`命名空间，稍后应该移除它，这样我们就可以在不编译整个项目的情况下看到布局的外观：

![列表项布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_002.jpg)

### 提示

你可能已经注意到，在旧设备上测试时，CardViews 的一些边距和填充看起来不同。与其创建替代布局资源，通常使用`card_view:cardUseCompatPadding="true"`属性可以解决此问题。

我们在这里应用的文本大小和边距不是任意的，而是由材料设计指南指定的。

## 材料字体大小

在材料设计中，文本大小非常重要，且在特定上下文中只允许使用特定大小的文本。在当前示例中，我们为名称选择了 24sp，为描述选择了 16sp。一般来说，我们在材料设计应用程序中显示的几乎所有文本都将是 12、14、16、20、24 或 34sp 的大小。在选择使用哪种大小以及何时使用时，有一定的灵活性，但以下列表应提供良好的指导：

![材料字体大小](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_003.jpg)

# 连接数据

Android 配备了**SQLite**库，这是一个创建和管理复杂数据库的强大工具。关于这个主题，可以轻松地填满整整一个章节甚至整本书。这里我们没有处理大量数据集，创建我们自己的数据类会更简单，希望也更清晰。

### 注意

如果你想了解更多关于 SQLite 的信息，可以在以下链接找到全面的文档：[`developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html`](http://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html)

稍后我们将创建复杂的数据结构，但现在我们只需要了解设置是如何工作的，因此我们只创建三个条目。要添加这些，请创建一个名为`Filling`的新 Java 类，如下完成：

```kt
public class Filling { 
    private int image; 
    private int name; 

    public Filling(int image, int name) { 
        this.image = image; 
        this.name = name; 
    } 
} 

```

这可以在主活动中这样定义：

```kt
static final Filling fillings[] = new Filling[3]; 
fillings[0] = new Filling(R.drawable.cheese, R.string.cheese); 
fillings[1] = new Filling(R.drawable.ham, R.string.ham); 
fillings[2] = new Filling(R.drawable.tomato, R.string.tomato); 

```

如你所见，我们在`strings.xml`文件中定义了我们的字符串资源：

```kt
<string name="cheese">Cheese</string> 
<string name="ham">Ham</string> 
<string name="tomato">Tomato</string> 

```

这有两个很大的优势。首先，它允许我们保持视图和模型分离；其次，如果我们有朝一日将应用程序翻译成其他语言，现在只需要一个替代的`strings`文件。实际上，Android Studio 使这个过程变得如此简单，值得花时间了解如何完成。

# 翻译字符串资源

Android Studio 提供了一个**翻译编辑器**，以简化提供替代资源的过程。正如我们为不同的屏幕尺寸创建指定文件夹一样，我们也为不同的语言创建替代的值目录。编辑器为我们管理这些操作，我们实际上并不需要了解太多，但知道这一点很有用：如果我们希望将应用翻译成意大利语，例如，编辑器将创建一个名为`values-it`的文件夹，并将替代的`strings.xml`文件放在其中。

![翻译字符串资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_004.jpg)

要访问翻译编辑器，只需在项目资源管理器中右键点击现有的`strings.xml`文件，并选择它。

尽管 RecyclerView 是一个在高效管理绑定数据方面非常出色的工具，但它确实需要相当多的设置。除了视图和数据之外，还需要两个其他元素来将数据绑定到我们的活动上，即**布局管理器**和**数据适配器**。

## 适配器和布局管理器

RecyclerView 通过使用`RecyclerView.LayoutManager`和`RecyclerView.Adapter`来管理其数据。可以将 LayoutManager 视为属于 RecyclerView 的一部分，它是与适配器通信的，而适配器则以以下图表所示的方式绑定到我们的数据：

![适配器和布局管理器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_005.jpg)

创建布局管理器非常简单。只需按照以下两个步骤操作。

1.  打开`MainActivity.Java`文件，并包含以下字段：

    ```kt
    RecyclerView recyclerView; 
    DataAdapter adapter;; 

    ```

1.  然后，将以下行添加到`onCreate()`方法中：

    ```kt
    final ArrayList<Filling> fillings = initializeData(); 
    adapter = new DataAdapter(fillings); 

    recyclerView = (RecyclerView) findViewById(R.id.recycler_view); 
    recyclerView.setHasFixedSize(true); 
    recyclerView.setLayoutManager(new LinearLayoutManager(this)); 
    recyclerView.setAdapter(adapter); 

    ```

这段代码很容易理解，但`RecyclerView.setHasFixedSize(true)`命令的目的可能需要一些解释。如果我们提前知道列表总是相同长度，那么这个调用将使列表的管理更加高效。

要创建适配器，请按照以下步骤操作：

1.  创建一个新的 Java 类，名为`DataAdapter`，并让它继承`RecyclerView.Adapter<RecyclerViewAdapter.ViewHolder>`。

1.  这将生成一个错误，点击红色的快速修复图标并实施建议的方法。

1.  这三个方法应按照这里所示填写：

    ```kt
    // Inflate recycler view 
    @Override 
    public DataAdapter.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) { 
        Context context = parent.getContext(); 
        LayoutInflater inflater = LayoutInflater.from(context); 

        View v = inflater.inflate(R.layout.item, parent, false); 
        return new ViewHolder(v); 
        } 

    // Display data 
    @Override 
    public void onBindViewHolder(DataAdapter.ViewHolder holder, int position) { 
        Filling filling = fillings.get(position); 

        ImageView imageView = holder.imageView; 
        imageView.setImageResource(filling.getImage()); 

        TextView textView = holder.nameView; 
        textView.setText(filling.getName()); 
    } 

    @Override 
    @Overridepublic int getItemCount() {    return fillings.size();}
    ```

1.  最后，是 ViewHolder：

    ```kt
    public class ViewHolder extends RecyclerView.ViewHolder { 
        ImageView imageView; 
        TextView nameView; 

        public ViewHolder(View itemView) { 
            super(itemView); 
            imageView = (ImageView) itemView.findViewById(R.id.item_image); 
            nameView = (TextView) itemView.findViewById(R.id.item_name); 
        } 
    } 

    ```

**ViewHolder**通过只调用一次`findViewById()`来加速长列表，这是一个资源密集型的过程。

该示例现在可以在模拟器或手机上运行，并且将产生类似于这里看到的输出：

![适配器和布局管理器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_006.jpg)

显然，我们想要的填充物远不止三个，但从这个例子中可以很容易看出，我们可以根据需要添加更多。

我们在这里已经详细介绍了如何使用 RecyclerView，足以让我们在各种情况下实现一个。这里我们使用了一个 LinearLayoutManager 来创建我们的列表，但还有**GridLayoutManager**和**StaggeredGridLayoutManager**以非常类似的方式工作。

# 适配器模式

在我们一直研究的这个例子中，我们使用了适配器模式将我们的数据以`DataAdapter`的形式与布局连接起来。这是一个现成的适配器，尽管它的工作原理很清晰，但它并没有告诉我们关于适配器结构或如何自己构建适配器的内容。

在很多情况下，Android 提供了内置的模式，这非常有用，但经常会有我们需要为自己创建的类适配器的时候，现在我们将看到如何做到这一点，以及如何创建相关的设计模式——桥接（bridge）。最好是从概念上了解这些模式开始。

适配器的作用可能是最容易理解的。一个好的类比就是当我们把电子设备带到其他国家时使用的物理适配器，那些国家的电源插座工作在不同的电压和频率上。适配器有两面，一面接受我们的插头，另一面适合插座。一些适配器甚至足够智能，可以接受多种配置，这正是软件适配器的工作原理。

![适配器模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_007.jpg)

在很多情况下，我们遇到的接口并不能像插头与插座那样完美匹配，适配器（adapter）就是最广泛采用的设计模式之一。我们之前看到，Android API 本身就使用了这种模式。

解决不兼容接口问题的一种方法是改变接口本身，但这可能导致代码非常混乱，并且类之间的联系像意大利面条一样复杂。适配器解决了这个问题，同时也允许我们在不真正破坏整体结构的情况下对软件进行大规模更改。

假设我们的三明治应用已经推出并且运行良好，但是后来我们送达的办公室改变了他们的楼层计划，从独立小办公室变成了开放式办公结构。之前我们使用建筑、楼层、办公室和办公桌字段来定位客户，但现在办公室字段不再有意义，我们必须相应地重新设计。

如果我们的应用程序稍微复杂一些，无疑会有许多地方引用和使用位置类，重写它们可能会非常耗时。幸运的是，适配器模式意味着我们可以非常轻松地适应这种变化。

这是原始的位置接口：

```kt
public interface OldLocation { 

    String getBuilding(); 
    void setBuilding(String building); 

    int getFloor(); 
    void setFloor(int floor); 

    String getOffice(); 
    void setOffice(String office); 

    int getDesk(); 
    void setDesk(int desk); 
} 

```

这是它的实现方式：

```kt
public class CustomerLocation implements OldLocation { 
    String building; 
    int floor; 
    String office; 
    int desk; 

    @Override 
    public String getBuilding() { return building; } 

    @Override 
    public void setBuilding(String building) { 
        this.building = building; 
    } 

    @Override 
    public int getFloor() { return floor; } 

    @Override 
    public void setFloor(int floor) { 
        this.floor = floor; 
    } 

    @Override 
    public String getOffice() { return office; } 

    @Override 
    public void setOffice(String office) { 
        this.office = office; 
    } 

    @Override 
    public int getDesk() { return desk; } 

    @Override 
    public void setDesk(int desk) { 
        this.desk = desk; 
    } 
} 

```

假设这些类已经存在，并且是我们希望适配的类，那么只需要一个适配器类和一些测试代码就可以将整个应用程序从旧系统转换到新系统：

1.  适配器类：

    ```kt
    public class Adapter implements NewLocation { 
        final OldLocation oldLocation; 

        String building; 
        int floor; 
        int desk; 

        // Wrap in old interface 
        public Adapter(OldLocation oldLocation) { 
            this.oldLocation = oldLocation; 
            setBuilding(this.oldLocation.getBuilding()); 
            setFloor(this.oldLocation.getFloor()); 
            setDesk(this.oldLocation.getDesk()); 
        } 

        @Override 
        public String getBuilding() { return building; } 

        @Override 
        public void setBuilding(String building) { 
            this.building = building; 
        } 

        @Override 
        public int getFloor() { return floor; } 

        @Override 
        public void setFloor(int floor) { 
            this.floor = floor; 
        } 

        @Override 
        public int getDesk() { return desk; } 

        @Override 
        public void setDesk(int desk) { 
            this.desk = desk; 
        } 
    } 

    ```

1.  测试代码：

    ```kt
    TextView textView = (TextView)findViewById(R.id.text_view); 

    OldLocation oldLocation = new CustomerLocation(); 
    oldLocation.setBuilding("Town Hall"); 
    oldLocation.setFloor(3); 
    oldLocation.setDesk(14); 

    NewLocation newLocation = new Adapter(oldLocation); 

    textView.setText(new StringBuilder() 
            .append(newLocation.getBuilding()) 
            .append(", floor ") 
            .append(newLocation.getFloor()) 
            .append(", desk ") 
            .append(newLocation.getDesk()) 
            .toString()); 

    ```

    尽管适配器模式非常有用，但它的结构非常简单，正如这里所示的图表：

    ![适配器模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_008.jpg)

适配器模式的关键在于适配器类实现新接口并包装旧接口的方式。

很容易看出这种模式如何应用于其他许多情况，在这些情况下，我们需要将一种接口转换为另一种接口。适配器是最有用和最常应用的结构型模式之一。在某种意义上，它与我们将遇到的下一个模式——桥接模式相似，因为它们都有一个用于转换接口的类。然而，正如我们接下来将看到的，桥接模式具有完全不同的功能。

# 桥接模式

适配器和桥接的主要区别在于，适配器是为了解决设计中出现的不兼容问题而构建的，而桥接是在之前构建的，其目的是将接口与其实现分离，这样我们就可以在不更改客户端代码的情况下修改甚至替换实现。

在以下示例中，我们将假设我们的三明治制作应用程序的用户可以选择开放或封闭的三明治。除了这一因素外，这些三明治在可以包含任意填充组合方面是相同的，尽管为了简化问题，只会有最多两个配料。这将演示如何将抽象类与其实现解耦，以便可以独立修改它们。

以下步骤解释了如何构建一个简单的桥接模式：

1.  首先，创建一个像这样的接口：

    ```kt
    public interface SandwichInterface { 

        void makeSandwich(String filling1, String filling2); 
    } 

    ```

1.  接下来，像这样创建一个抽象类：

    ```kt
    public abstract class AbstractSandwich { 
        protected SandwichInterface sandwichInterface; 

        protected AbstractSandwich(SandwichInterface sandwichInterface) { 
            this.sandwichInterface = sandwichInterface; 
        } 

        public abstract void make(); 
    } 

    ```

1.  现在像这样扩展这个类：

    ```kt
    public class Sandwich extends AbstractSandwich { 
        private String filling1, filling2; 

        public Sandwich(String filling1, String filling2, SandwichInterface sandwichInterface) { 
            super(sandwichInterface); 
            this.filling1 = filling1; 
            this.filling2 = filling2; 
        } 

        @Override 
        public void make() { 
            sandwichInterface.makeSandwich(filling1, filling2); 
        } 
    } 

    ```

1.  然后创建两个具体类来表示我们选择的三明治：

    ```kt
    public class Open implements SandwichInterface { 
        private static final String DEBUG_TAG = "tag"; 

        @Override 
        public void makeSandwich(String filling1, String filling2) { 
            Log.d(DEBUG_TAG, "Open sandwich " + filling1 + filling2); 
        } 
    } 

    public class Closed implements SandwichInterface { 
        private static final String DEBUG_TAG = "tag"; 

        @Override 
        public void makeSandwich(String filling1, String filling2) { 
            Log.d(DEBUG_TAG, "Closed sandwich " + filling1 + filling2); 
        } 
    } 

    ```

1.  现在，可以通过向客户端代码中添加以下几行来测试此模式：

    ```kt
    AbstractSandwich openSandwich = new Sandwich("Cheese ", "Tomato", new Open()); 
    openSandwich.make(); 

    AbstractSandwich closedSandwich = new Sandwich("Ham ", "Eggs", new Closed()); 
    closedSandwich.make();  

    ```

1.  然后调试屏幕上的输出将与以下内容相匹配：

    ```kt
    D/tag: Open sandwich Cheese Tomato 
    D/tag: Closed sandwich Ham Eggs 

    ```

这展示了该模式如何允许我们使用相同的抽象类方法以不同的方式制作三明治，但使用不同的桥接实现类。

适配器和桥接模式都通过创建清晰的结构来工作，我们可以使用这些结构来统一或分离类和接口，以解决出现的结构不兼容问题，或者在规划期间预测这些问题。从图解上观察，两者的区别变得更加明显：

![桥接模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_009.jpg)

大多数结构型模式（以及一般的设计模式）依赖于创建这些额外的层次来澄清代码。简化复杂结构无疑是设计模式最大的优点，而门面模式帮助我们简化代码的能力很少有模式能比肩。

# 门面模式

门面模式或许是最简单的结构型模式之一，易于理解和创建。顾名思义，它就像一个位于复杂系统前面的面孔。在编写客户端代码时，如果我们有一个门面来代表它，我们永远不必关心系统其余部分的复杂逻辑。我们只需要处理门面本身，这意味着我们可以设计门面以最大化简化。

将外观模式想象成在典型自动售货机上可能找到的简单键盘。自动售货机是非常复杂的系统，结合了各种机械和物理组件。然而，要操作它，我们只需要知道如何在它的键盘上输入一两个数字。键盘就是外观，它隐藏了所有背后的复杂性。我们可以通过考虑以下步骤中概述的假想自动售货机来演示这一点：

1.  从创建以下接口开始：

    ```kt
    public interface Product { 

        int dispense(); 
    } 

    ```

1.  接下来，像这样添加三个具体实现：

    ```kt
    public class Crisps implements Product { 

        @Override 
        public int dispense() { 
            return R.drawable.crisps; 
        } 
    } 

    public class Drink implements Product { 
       ... 
            return R.drawable.drink; 
       ... 
    } 

    public class Fruit implements Product { 
        ... 
            return R.drawable.fruit; 
        ... 
    } 

    ```

1.  现在添加外观类：

    ```kt
    public class Facade { 
        private Product crisps; 
        private Product fruit; 
        private Product drink; 

        public Facade() { 
            crisps = new Crisps(); 
            fruit = new Fruit(); 
            drink = new Drink(); 
        } 

        public int dispenseCrisps() { 
            return crisps.dispense(); 
        } 

        public int dispenseFruit() { 
            return fruit.dispense(); 
        } 

        public int dispenseDrink() { 
            return drink.dispense(); 
        } 
    } 

    ```

1.  在适当的可绘制目录中放置合适的图像。

1.  创建一个简单的布局文件，其中包含类似于这样的图像视图：

    ```kt
    <ImageView 
        android:id="@+id/image_view" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" /> 

    ```

1.  向活动类中添加一个`ImageView`：

    ```kt
    ImageView imageView = (ImageView) findViewById(R.id.image_view); 

    ```

1.  创建一个外观：

    ```kt
    Facade facade = new Facade(); 

    ```

1.  然后通过类似于此处的调用测试输出：

    ```kt
    imageView.setImageResource(facade.dispenseCrisps()); 

    ```

    这构成了我们的外观模式。它非常简单，容易可视化：

    ![外观模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_010.jpg)

当然，此示例中的外观模式可能看起来毫无意义。`dispense()`方法所做的不过是显示一个图像，并不需要简化。然而，在一个更现实的模拟中，分发过程将涉及各种调用和检查，需要计算找零，检查库存可用性，以及设置多个伺服电机的动作。外观模式的优点是，如果我们要实施所有这些程序，我们不需要更改客户端代码或外观类中的任何一行。对`dispenseDrink()`的单个调用将产生正确的结果，不管背后的逻辑有多复杂。

尽管外观模式非常简单，但在许多情况下它都非常有用，比如我们想要为复杂的系统提供一个简单且有序的接口。不那么简单但同样有用的是标准（或过滤）模式，它允许我们查询复杂的数据结构。

# 标准模式

标准设计模式为根据设定标准过滤对象提供了一种清晰且简洁的技术。它可能是一个非常强大的工具，接下来的练习将证明这一点。

在此示例中，我们将应用一个过滤模式来筛选一系列食材，并根据它们是否为素食以及产地来过滤它们：

1.  从创建如下所示的过滤器接口开始：

    ```kt
    public interface Filter { 

        List<Ingredient> meetCriteria(List<Ingredient> ingredients); 
    } 

    ```

1.  接着添加如下所示的配料类：

    ```kt
    public class Ingredient { 

        String name; 
        String local; 
        boolean vegetarian; 

        public Ingredient(String name, String local, boolean vegetarian){ 
            this.name = name; 
            this.local = local; 
            this.vegetarian = vegetarian; 
        } 

        public String getName() { 
            return name; 
        } 

        public String getLocal() { 
            return local; 
        } 

        public boolean isVegetarian(){ 
            return vegetarian; 
        } 
    } 

    ```

1.  现在实现满足素食标准的过滤器：

    ```kt
    public class VegetarianFilter implements Filter { 

        @Override 
        public List<Ingredient> meetCriteria(List<Ingredient> ingredients) { 
            List<Ingredient> vegetarian = new ArrayList<Ingredient>(); 

            for (Ingredient ingredient : ingredients) { 
                if (ingredient.isVegetarian()) { 
                    vegetarian.add(ingredient); 
                } 
            } 
            return vegetarian; 
        } 
    } 

    ```

1.  然后添加一个测试本地产品的过滤器：

    ```kt
    public class LocalFilter implements Filter { 

        @Override 
        public List<Ingredient> meetCriteria(List<Ingredient> ingredients) { 
            List<Ingredient> local = new ArrayList<Ingredient>(); 

            for (Ingredient ingredient : ingredients) { 
                if (Objects.equals(ingredient.getLocal(), "Locally produced")) { 
                    local.add(ingredient); 
                } 
            } 
            return local; 
        } 
    } 

    ```

1.  再为非本地食材添加一个：

    ```kt
    public class NonLocalFilter implements Filter { 

        @Override 
        public List<Ingredient> meetCriteria(List<Ingredient> ingredients) { 
            List<Ingredient> nonLocal = new ArrayList<Ingredient>(); 

            for (Ingredient ingredient : ingredients) { 
                if (ingredient.getLocal() != "Locally produced") { 
                    nonLocal.add(ingredient); 
                } 
            } 
            return nonLocal; 
        } 
    } 

    ```

1.  现在我们需要包含一个`AND`标准过滤器：

    ```kt
    public class AndCriteria implements Filter { 
        Filter criteria; 
        Filter otherCriteria; 

        public AndCriteria(Filter criteria, Filter otherCriteria) { 
            this.criteria = criteria; 
            this.otherCriteria = otherCriteria; 
        } 

        @Override 
        public List<Ingredient> meetCriteria(List<Ingredient> ingredients) { 
            List<Ingredient> firstCriteria = criteria.meetCriteria(ingredients); 
            return otherCriteria.meetCriteria(firstCriteria); 
        } 
    } 

    ```

1.  接着是一个`OR`标准：

    ```kt
    public class OrCriteria implements Filter { 
        Filter criteria; 
        Filter otherCriteria; 

        public OrCriteria(Filter criteria, Filter otherCriteria) { 
            this.criteria = criteria; 
            this.otherCriteria = otherCriteria; 
        } 

        @Override 
        public List<Ingredient> meetCriteria(List<Ingredient> ingredients) { 
            List<Ingredient> firstCriteria = criteria.meetCriteria(ingredients); 
            List<Ingredient> nextCriteria = otherCriteria.meetCriteria(ingredients); 

            for (Ingredient ingredient : nextCriteria) { 
                if (!firstCriteria.contains(ingredient)) { 
                    firstCriteria.add(ingredient); 
                } 
            } 
            return firstCriteria; 
        } 
    } 

    ```

1.  现在，添加如下所示的小型数据集：

    ```kt
    List<Ingredient> ingredients = new ArrayList<Ingredient>(); 

    ingredients.add(new Ingredient("Cheddar", "Locally produced", true)); 
    ingredients.add(new Ingredient("Ham", "Cheshire", false)); 
    ingredients.add(new Ingredient("Tomato", "Kent", true)); 
    ingredients.add(new Ingredient("Turkey", "Locally produced", false)); 

    ```

1.  在主活动中，创建以下过滤器：

    ```kt
    Filter local = new LocalFilter(); 
    Filter nonLocal = new NonLocalFilter(); 
    Filter vegetarian = new VegetarianFilter(); 
    Filter localAndVegetarian = new AndCriteria(local, vegetarian); 
    Filter localOrVegetarian = new OrCriteria(local, vegetarian); 

    ```

1.  创建一个带有基本文本视图的简单布局。

1.  向主活动添加以下方法：

    ```kt
    public void printIngredients(List<Ingredient> ingredients, String header) { 

        textView.append(header); 

        for (Ingredient ingredient : ingredients) { 
            textView.append(new StringBuilder() 
                    .append(ingredient.getName()) 
                    .append(" ") 
                    .append(ingredient.getLocal()) 
                    .append("\n") 
                    .toString()); 
        } 
    } 

    ```

1.  现在可以使用类似于此处的调用测试该模式：

    ```kt
    printIngredients(local.meetCriteria(ingredients), 
    "LOCAL:\n"); 
    printIngredients(nonLocal.meetCriteria(ingredients), 
    "\nNOT LOCAL:\n"); 
    printIngredients(vegetarian.meetCriteria(ingredients), 
    "\nVEGETARIAN:\n"); 
    printIngredients(localAndVegetarian.meetCriteria(ingredients), 
    "\nLOCAL VEGETARIAN:\n"); 
    printIngredients(localOrVegetarian.meetCriteria(ingredients), 
    "\nENVIRONMENTALLY FRIENDLY:\n"); 

    ```

在设备上测试该模式应产生此输出：

![标准模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_011.jpg)

我们在这里只应用了一些简单的标准，但我们同样可以轻松地包含有关过敏、卡路里、价格以及我们选择的任何其他信息，以及相应的过滤器。正是这种能够从多个标准创建单一标准的能力，使得这个模式如此有用和多变。它可以像这样视觉化地呈现：

![标准模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_05_012.jpg)

过滤器模式，像许多其他模式一样，并没有做任何我们之前没有做过的事情。相反，它展示了执行熟悉和常见任务（如根据特定标准过滤数据）的另一种方式。只要我们为正确的任务选择正确的模式，这些经过验证的结构模式几乎必然会使最佳实践成为可能。

# 总结

在本章中，我们介绍了一些最常应用和最有用的结构模式。我们从框架如何将模型与视图分离开始，然后学习了如何使用 RecyclerView 及其适配器管理数据结构，以及这与适配器设计模式的相似之处。建立这种联系后，我们接着创建了一个示例，说明如何使用适配器来解决对象之间不可避免的兼容性问题，而我们随后构建的桥接模式则是在设计之初就预定好的。

这一章以非常实用的内容开始，最后通过深入探讨另外两个重要的结构模式作结：门面模式，用于简化结构的明显功能；以及标准模式，它处理数据集，返回经过筛选的对象集，像我们可能只应用一个标准那样简单地应用多个标准。

在下一章中，我们将探讨用户界面以及如何应用设计库来实现滑动和取消行为。我们还将重新审视工厂模式，并将其应用于我们的布局，使用自定义对话框来显示其输出。


# 第六章：激活模式

之前的章节作为扩展介绍，探讨了 Android 开发的实用性以及设计模式应用的理论。我们已经涵盖了 Android 应用许多基本组件，并了解了最有用的模式是如何构建的，但我们还没有将这两者结合起来。

在本章中，我们将构建应用的一个主要部分：成分选择菜单。这将涉及一个可滚动的填充物列表，可以选中、展开和关闭。在途中，我们还将看看可折叠工具栏以及其他一两个有用的支持库功能，为操作按钮、浮动操作按钮和警告对话框添加功能。

在这段代码的核心，我们将应用一个简单的工厂模式来创建每个成分。这将很好地展示这种模式如何将创建逻辑从客户类中隐藏起来。在本章中，我们将只创建一个填充类型的示例，以了解其实现方式，但相同的结构和过程稍后会在添加更多复杂性时使用。这将引导我们探索回收视图格式和装饰，如网格布局和分隔线。

然后，我们将继续生成并自定义一个警告对话框，通过点击按钮来实现。这将需要使用内置的构建器模式，并引导我们了解如何为膨胀布局创建自己的构建器模式。

在本章中，你将学习如何：

+   创建应用栏布局

+   应用可折叠工具栏

+   控制滚动行为

+   包含嵌套滚动视图

+   应用数据工厂

+   创建列表项视图

+   将文本视图转换为按钮

+   应用网格布局

+   添加分隔线装饰

+   配置操作图标

+   创建警告对话框

+   自定义对话框

+   添加第二个活动

+   应用滑动和关闭行为

+   创建布局构建器模式

+   在运行时创建布局

我们的应用用户需要某种方式来选择成分。我们当然可以向他们展示一个长长的列表，但这会既麻烦又不吸引人。显然，我们需要将成分分类。在以下示例中，我们将专注于这些组中的一个，这将有助于简化稍后考虑更复杂场景时的底层过程。我们将从创建必要的布局开始，首先从可折叠工具栏布局开始。

# 可折叠工具栏

工具栏能够方便地滑出是材料设计 UI 的一个常见特性，并为手机甚至笔记本电脑上有限的空间提供了优雅和聪明的利用方式。

![可折叠工具栏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_06_01-1.jpg)

如你所想，**CollapsingToolbarLayout**是设计支持库的一部分。它是**AppBarLayout**的子视图，后者是一个线性布局，专门为材料设计特性而设计。

折叠工具栏优雅地管理空间，也提供了一个展示吸引人图形和推广我们产品的好机会。它们实现起来不需要太多时间，而且很容易适应。

看它们如何工作的最佳方式是构建一个，以下步骤将展示如何进行：

1.  开始一个新项目，并包含回收视图和设计支持库。

1.  通过更改主题来移除操作栏：

    ```kt
    Theme.AppCompat.Light.NoActionBar 

    ```

1.  打开 `activity_main.xml` 文件，并应用以下根布局：

    ```kt
    <android.support.design.widget.CoordinatorLayout  

        android:layout_width="match_parent" 
        android:layout_height="match_parent"> 

    </android.support.design.widget.CoordinatorLayout> 

    ```

1.  在此内部，添加这个 `AppBarLayout`：

    ```kt
    <android.support.design.widget.AppBarLayout 
        android:id="@+id/app_bar" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:fitsSystemWindows="true"> 

    </android.support.design.widget.AppBarLayout> 

    ```

1.  将此 `CollapsingToolbarLayout` 放在应用栏内：

    ```kt
    <android.support.design.widget.CollapsingToolbarLayout 
        android:id="@+id/collapsing_toolbar" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:fitsSystemWindows="true" 
        app:contentScrim="?attr/colorPrimary" 
        app:layout_scrollFlags="scroll|exitUntilCollapsed|enterAlwaysCollapsed"> 

    </android.support.design.widget.CollapsingToolbarLayout> 

    ```

1.  折叠工具栏的内容是以下两个视图：

    ```kt
    <ImageView 
        android:id="@+id/toolbar_image" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:fitsSystemWindows="true" 
        android:scaleType="centerCrop" 
        android:src="img/some_drawable" 
        app:layout_collapseMode="parallax" /> 

    <android.support.v7.widget.Toolbar 
        android:id="@+id/toolbar" 
        android:layout_width="match_parent" 
        android:layout_height="?attr/actionBarSize" 
        app:layout_collapseMode="pin" /> 

    ```

1.  现在，在 app-bar 布局下方，添加这个回收视图：

    ```kt
    <android.support.v7.widget.RecyclerView 
        android:id="@+id/recycler_view" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:scrollbars="vertical" 
        app:layout_behavior="@string/appbar_scrolling_view_behavior" /> 

    ```

1.  最后，添加这个浮动操作按钮：

    ```kt
    <android.support.design.widget.FloatingActionButton 
        android:id="@+id/fab" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_marginEnd="@dimen/fab_margin_end" 
        app:layout_anchor="@id/app_bar" 
        app:layout_anchorGravity="bottom|end" /> 

    ```

    ![折叠工具栏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_002.jpg)

    ### 提示

    有时我们希望将状态栏设置为半透明，以便我们的应用栏图片能够显示在状态栏后面。这通过在 styles.xml 文件中添加以下两项来实现：

    ```kt
    <item name="android:windowDrawsSystemBarBackgrounds">true</item> 
    <item name="android:statusBarColor">@android:color/transparent</item> 

    ```

在前面的章节中我们已经遇到了协调布局，并看到了它如何实现许多材料设计功能。`AppBarLayout` 做类似的事情，通常用作折叠工具栏的容器。

另一方面，**CollapsingToolbarLayout** 需要解释一两个要点。首先，使用 `android:layout_height="wrap_content"` 将根据其 ImageView 包含的图片高度产生不同的效果。这样做的目的是，当我们为不同的屏幕尺寸和密度设计替代布局时，我们可以相应地缩放此图像。这里配置的是小（480 x 854dp）240dpi 设备，高度为 192dp。当然，我们也可以在 dp 中设置布局高度，并在不同的 `dimens.xml` 文件中缩放此值。然而，我们仍然需要缩放图像，所以这个方法是一石二鸟。

关于折叠工具栏布局的另一个有趣点是我们可以控制它的滚动方式，正如你所想象的，这是通过 **layout_scrollFlags** 属性处理的。这里我们使用了 `scroll`、`exitUntilCollapsed`、`enterAlwaysCollapsed`。这意味着工具栏永远不会从屏幕顶部消失，且当列表无法再向下滚动时，工具栏不会展开。

有五种滚动标志，它们是：

+   `scroll` - 启用滚动

+   `exitUntilCollapsed` - 当向上滚动时防止工具栏消失（省略此项，直到向下滚动时工具栏才会消失）

+   `enterAlways` - 列表向下滚动时工具栏展开

+   `enterAlwaysCollapsed` - 工具栏仅从列表顶部展开

+   `snap` - 工具栏直接定位而不是滑动

折叠工具栏内的图像视图几乎与我们可能见过的任何其他图像视图相同，除了可能有的 `layout_collapseMode` 属性。这个属性有两个可能的设置，`pin` 和 `parallax`：

+   `pin` - 列表和工具栏一起移动

+   `视差` - 列表和工具栏分别移动

欣赏这些效果的最佳方式就是尝试一下。我们也可以将这些布局折叠模式之一应用于图片下方的工具栏，但由于我们希望工具栏保持屏幕显示，因此无需关心其折叠行为。

这里将包含我们数据的回收视图与本书前面使用的唯一区别在于包含以下这行：

```kt
app:layout_behavior="@string/appbar_scrolling_view_behavior" 

```

这个属性是我们需要添加到任何位于应用栏下方的视图或视图组中的，以允许它们协调滚动行为。

这些简单的类在实现材料设计时为我们节省了大量工作，并让我们专注于提供功能。除了图片的大小，要创建一个在大数量可能设备上工作的布局，几乎不需要重构。

尽管这里我们使用了回收视图，但完全有可能在应用栏下方放置任意数量的视图和视图组。只要它们具有`app:layout_behavior="@string/appbar_scrolling_view_behavior"`属性，它们就会与栏一起移动。有一个特别适合此目的的布局，那就是**NestedScrollView**。举个例子，它看起来像这样：

```kt
<android.support.v4.widget.NestedScrollView 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    app:layout_behavior="@string/appbar_scrolling_view_behavior"> 

    <TextView 
        android:id="@+id/nested_text" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:padding="@dimen/nested_text_padding" 
        android:text="@string/some_text" 
        android:textSize="@dimen/nested_text_textSize" /> 

</android.support.v4.widget.NestedScrollView> 

```

下一步逻辑上是创建一个布局来填充回收视图，但首先我们需要准备数据。在本章中，我们将开发一个应用程序组件，负责向用户展示特定类别（在本例中是奶酪）的配料列表。我们将使用**工厂模式**来创建这些对象。

# 应用数据工厂模式

在本节中，我们将应用工厂模式来创建类型为*奶酪*的对象。这将进而实现一个*填充物*接口。每个对象将由几个属性组成，如价格和热量值。其中一些值将在我们的列表项中展示，其他值则只能通过扩展视图或在代码中访问。

设计模式为数不多的缺点之一是很快就会累积大量的类。因此，在开始以下练习之前，请在`java`目录中创建一个名为`fillings`的新包。

按照以下步骤生成我们的奶酪工厂：

1.  在`fillings`包中创建一个名为`Filling`的新接口，并按照以下方式完成它：

    ```kt

    public interface Filling { 

        String getName(); 
        int getImage(); 
        int getKcal(); 
        boolean isVeg(); 
        int getPrice(); 
    } 

    ```

1.  接下来，创建一个实现`Filling`的抽象类，名为`Cheese`，如下所示：

    ```kt
    public abstract class Cheese implements Filling { 
        private String name; 
        private int image; 
        private String description; 
        private int kcal; 
        private boolean vegetarian; 
        private int price; 

        public Cheese() { 
        } 

        public abstract String getName(); 

        public abstract int getImage(); 

        public abstract int getKcal(); 

        public abstract boolean getVeg(); 

        public abstract int getPrice(); 
    } 

    ```

1.  创建一个名为`Cheddar`的具体类，如下所示：

    ```kt
    public class Cheddar extends Cheese implements Filling { 

        @Override 
        public String getName() { 
            return "Cheddar"; 
        } 

        @Override 
        public int getImage() { 
            return R.drawable.cheddar; 
        } 

        @Override 
        public int getKcal() { 
            return 130; 
        } 

        @Override 
        public boolean getVeg() { 
            return true; 
        } 

        @Override 
        public int getPrice() { 
            return 75; 
        } 
    } 

    ```

1.  按照与`Cheddar`类似的方式创建其他几个`Cheese`类。

创建了工厂之后，我们需要一种方法来表示每一种奶酪。为此，我们将创建一个条目布局。

# 定位条目布局

为了保持界面整洁，我们将为回收视图列表创建一个非常简单的条目。它将只包含一个图片、一个字符串和一个用户添加配料到三明治的操作按钮。

初始项目布局将如下所示：

![定位项目布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_003.jpg)

这可能看起来是一个非常简单的布局，但它比看上去要复杂得多。以下是三个视图的代码：

图片如下：

```kt
<ImageView 
    android:id="@+id/item_image" 
    android:layout_width="@dimen/item_image_size" 
    android:layout_height="@dimen/item_image_size" 
    android:layout_gravity="center_vertical|end" 
    android:layout_margin="@dimen/item_image_margin" 
    android:scaleType="fitXY" 
    android:src="img/placeholder" /> 

```

标题：

```kt
<TextView 
    android:id="@+id/item_name" 
    android:layout_width="0dp" 
    android:layout_height="wrap_content" 
    android:layout_gravity="center_vertical" 
    android:layout_weight="1" 
    android:paddingBottom="@dimen/item_name_paddingBottom" 
    android:paddingStart="@dimen/item_name_paddingStart" 
    android:text="@string/placeholder" 
    android:textSize="@dimen/item_name_textSize" /> 

```

操作按钮：

```kt
<Button 
    android:id="@+id/action_add" 
    style="?attr/borderlessButtonStyle" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_gravity="center_vertical|bottom" 
    android:layout_marginEnd="@dimen/action_marginEnd"" 
    android:minWidth="64dp" 
    android:padding="@dimen/action_padding" 
    android:paddingEnd="@dimen/action_paddingEnd" 
    android:paddingStart="@dimen/action_paddingStart" 
    android:text="@string/action_add_text" 
    android:textColor="@color/colorAccent" 
    android:textSize="@dimen/action_add_textSize" /> 

```

值得一看的是这里管理各种资源的方式。以下是`dimens.xml`文件：

```kt
<dimen name="item_name_paddingBottom">12dp</dimen> 
<dimen name="item_name_paddingStart">24dp</dimen> 
<dimen name="item_name_textSize">16sp</dimen> 

<dimen name="item_image_size">64dp</dimen> 
<dimen name="item_image_margin">12dp</dimen> 

<dimen name="action_padding">12dp</dimen> 
<dimen name="action_paddingStart">16dp</dimen> 
<dimen name="action_paddingEnd">16dp</dimen> 
<dimen name="action_marginEnd">12dp</dimen> 
<dimen name="action_textSize">16sp</dimen> 

<dimen name="fab_marginEnd">16dp</dimen> 

```

很明显，这些属性中有几个携带相同的值，我们可能只需要五个就能达到同样的效果。然而，这可能会导致代码混淆，尤其是在后期进行修改时，尽管这种方法有些过分，但仍然存在一定的效率。操作按钮的填充和边距设置对于整个应用程序中的所有此类按钮都将相同，从它们的名称可以清晰地读取，并且只需要声明一次。同样，此布局中的文本和图像视图在此应用程序中是唯一的，因此也相应地命名。这也使得调整单个属性更加清晰。

最后，使用`android:minWidth="64dp"`是材料规定，旨在确保所有这样的按钮宽度都能适应平均手指大小。

这完成了此活动的布局，并且我们的对象工厂也准备就绪，现在我们可以像之前一样，使用数据适配器和视图持有者填充我们的回收视图。

# 使用工厂与 RecyclerView

正如我们在本书前面简要看到的那样，RecyclerView 利用了一个内部的 LayoutManager。这进而通过适配器与数据集通信。这些适配器与我们之前在书中探讨的适配器设计模式完全相同。这个功能可能不是那么明显，但它充当数据集和回收视图的布局管理器之间的桥梁。适配器通过其 ViewHolder 跨过这座桥。适配器的工作与客户端代码整洁地分离，我们只需要几行代码就可以创建一个新的适配器和布局管理器。

考虑到这一点，我们的数据准备就绪，可以按照以下简单步骤快速组合一个适配器：

1.  首先，在主包中创建这个新类：

    ```kt
    public class DataAdapter extends RecyclerView.Adapter<DataAdapter.ViewHolder> { 

    ```

1.  它需要以下字段和构造函数：

    ```kt
    private List<Cheese> cheeses; 

    public DataAdapter(List<Cheese> cheeses) { 
        this.cheeses = cheeses; 
    } 

    ```

1.  现在，像这样将`ViewHolder`添加为一个内部类：

    ```kt
    public static class ViewHolder extends RecyclerView.ViewHolder { 
        public ImageView imageView; 
        public TextView nameView; 

        public ViewHolder(View itemView) { 
            super(itemView); 

            imageView = (ImageView) itemView.findViewById(R.id.item_image); 
            nameView = (TextView) itemView.findViewById(R.id.item_name); 
        } 
    } 

    ```

1.  有三个必须重写的方法。`onCreateViewHolder()`方法：

    ```kt
    @Override 
    public DataAdapter.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) { 
        Context context = parent.getContext(); 
        LayoutInflater inflater = LayoutInflater.from(context); 

        View cheeseView = inflater.inflate(R.layout.item_view, parent, false); 

        return new ViewHolder(cheeseView); 
    } 

    ```

1.  `onBindViewHolder()`方法：

    ```kt
    @Override 
    public void onBindViewHolder(DataAdapter.ViewHolder viewHolder, int position) { 
        Cheese cheese = cheeses.get(position); 

        ImageView imageView = viewHolder.imageView; 
        imageView.setImageResource(cheese.getImage()); 

        TextView nameView = viewHolder.nameView; 
        nameView.setText(cheese.getName()); 
    } 

    ```

1.  `getItemCount()`方法：

    ```kt
    @Override 
    public int getItemCount() { 
        return cheeses.size(); 
    } 

    ```

这样适配器就完成了，我们需要关心的就是将其连接到我们的数据和回收视图。这是在主活动的`onCreate()`方法中完成的。首先，我们需要创建一个包含所有奶酪的列表。有了我们的模式，这非常简单。以下方法可以放在任何地方，但这里放在主活动中：

```kt
private ArrayList<Cheese> buildList() { 
    ArrayList<Cheese> cheeses = new ArrayList<>(); 

    cheeses.add(new Brie()); 
    cheeses.add(new Camembert()); 
    cheeses.add(new Cheddar()); 
    cheeses.add(new Emmental()); 
    cheeses.add(new Gouda()); 
    cheeses.add(new Manchego()); 
    cheeses.add(new Roquefort()); 

    return cheeses; 
}
```

### 注意

需要注意的是，你需要从 Fillings 包中导入这些类。

我们现在可以通过适配器将这个连接到我们的回收视图，在主活动的`onCreate()`方法中添加以下几行：

```kt
RecyclerView recyclerView = (RecyclerView) findViewById(R.id.recycler_view); 

ArrayList<Cheese> cheeses = buildList(); 
DataAdapter adapter = new DataAdapter(cheeses); 

recyclerView.setLayoutManager(new LinearLayoutManager(this)); 
recyclerView.setAdapter(adapter); 

recyclerView.setHasFixedSize(true); 

```

首先值得注意的是，所需的客户端代码非常少，而且非常易懂。不仅仅是设置回收视图和适配器的代码，还包括构建列表的代码。如果没有这种模式，我们最终可能会得到这样的代码：

```kt
cheeses.add(new Cheese("Emmental", R.drawable.emmental), 120, true, 65); 

```

项目现在可以在设备上进行测试了。

![在 RecyclerView 中使用工厂](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_004.jpg)

我们在这里使用的线性布局管理器不是唯一可用的。还有另外两个管理器，一个用于网格布局，另一个用于交错布局。可以这样应用：

```kt
recyclerView.setLayoutManager(new StaggeredGridLayoutManager(3, StaggeredGridLayoutManager.VERTICAL)); 

recyclerView.setLayoutManager(new GridLayoutManager(this, 2)); 

```

这只需要稍微调整布局文件，我们甚至可以提供替代布局并允许用户选择他们喜欢的布局。

从视觉角度来看，我们基本上已经准备就绪。然而，由于这样一个稀疏的项目设计，在项目之间添加分隔线可能会更好。这不像人们想象的那么简单，但这个过程简单而优雅。

# 添加分隔线

在回收视图之前，ListView 带有自己的分隔元素。而回收视图则没有。然而，这不应当被视为缺点，因为后者允许更大的灵活性。

添加一个非常窄的视图在项目布局底部以创建分隔线可能看起来很诱人，但这被认为是非常不好的做法，因为当项目移动或被移除时，分隔线也会随之移动。

回收视图使用内部类**ItemDecoration**来提供项目之间的分隔线，以及间距和突出显示。它还有一个非常有用的子类，即 ItemTouchHelper，当我们看到如何滑动和关闭卡片时会遇到它。

首先，按照以下步骤向我们的回收视图添加分隔线：

1.  创建一个新的 ItemDecoration 类：

    ```kt
    public class ItemDivider extends RecyclerView.ItemDecoration 

    ```

1.  包含这个 Drawable 字段：

    ```kt
    Private Drawable divider; 

    ```

1.  接着是这个构造函数：

    ```kt
        public ItemDivider(Context context) { 
            final TypedArray styledAttributes = context.obtainStyledAttributes(ATTRS); 
            divider = styledAttributes.getDrawable(0); 
            styledAttributes.recycle(); 
        } 

    ```

1.  然后重写`onDraw()`方法：

    ```kt
    @Override 
    public void onDraw(Canvas canvas, RecyclerView parent, RecyclerView.State state) { 
        int left = parent.getPaddingLeft(); 
        int right = parent.getWidth() - parent.getPaddingRight(); 

        int count = parent.getChildCount(); 
        for (int i = 0; i < count; i++) { 
            View child = parent.getChildAt(i); 

            RecyclerView.LayoutParams params = (RecyclerView.LayoutParams) child.getLayoutParams(); 

            int top = child.getBottom() + params.bottomMargin; 
            int bottom = top + divider.getIntrinsicHeight(); 

            divider.setBounds(left, top, right, bottom); 
            divider.draw(canvas); 
        } 
    } 

    ```

1.  现在，需要做的就是在`onCreate()`方法中实例化分隔线，在设置了`LayoutManager`之后：

    ```kt
    recyclerView.addItemDecoration(new ItemDivider(this)); 

    ```

这段代码提供了我们项目之间的系统分隔线。项目装饰还可以非常简单地创建**自定义分隔线**。

按照以下两个步骤看看是如何完成的：

1.  在`drawable`目录中创建一个名为`item_divider.xml`的 XML 文件，内容如下：

    ```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <shape  
        android:shape="rectangle"> 

        <size android:height="1dp" /> 
        <solid android:color="@color/colorPrimaryDark" /> 

    </shape> 

    ```

1.  向`ItemDivider`类中添加第二个构造函数，如下所示：

    ```kt
    public ItemDivider(Context context, int resId) { 
        divider = ContextCompat.getDrawable(context, resId); 
    } 

    ```

1.  然后将活动中的分隔符初始化替换为此处：

    ```kt
    recyclerView.addItemDecoration(new ItemDivider(this, R.drawable.item_divider)); 

    ```

    当运行时，这两种技术将产生如下所示的结果：

    ![添加分隔符](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_005.jpg)

    ### 提示

    前面的方法是在视图之前绘制分隔符。如果您有一个花哨的分隔符，并希望其部分与视图重叠，那么您需要重写`onDrawOver()`方法，这将导致在视图之后绘制分隔符。

现在是时候为我们的项目添加一些功能了。我们将从考虑为我们的小悬浮操作按钮提供哪些功能开始。

# 配置悬浮操作按钮

到目前为止，我们的布局只提供了一个操作，即每个列表项上的*添加*操作按钮。这将用于包括用户最终的三明治填充。确保用户始终只需点击一次就能消费，因此我们将在活动中添加结账功能。

我们首先需要的是一个图标。图标最佳的来源可能是我们在书中早些时候使用的资产工作室。这是在项目中包含图标的好方法，主要是因为它自动为所有可用的屏幕密度生成版本。然而，图标的数量有限，没有结账篮子。在这里我们有两个选择：我们可以在网上找一个图标，或者我们可以自己设计一个。

网上有大量的符合材料设计规范的图标，谷歌也有自己的图标，可以在以下位置找到：

+   [design.google.com/icons/](http://design.google.com/icons/)

许多开发者喜欢设计自己的图形，而且总会有我们找不到所需图标的时候。谷歌还提供了图标设计的综合指南，可在以下位置找到：

+   [material.google.com/style/icons.html](http://material.google.com/style/icons.html)

无论您选择哪个选项，都可以通过按钮的`src`属性添加，如下所示：

```kt
android:src="img/ic_cart" 

```

创建了我们的图标后，现在需要考虑颜色。根据材料设计指南，操作和系统图标应与主文本或次文本颜色相同。它们不是如我们所想的两种灰色阴影，而是通过透明度级别定义的。这样做是因为在彩色背景上效果远比灰色阴影好。到目前为止，我们使用了默认的文本颜色，并没有在我们的`styles.xml`文件中包含这一点。根据材料文本颜色的规则，这样做是很容易的，规则如下：

![配置悬浮操作按钮](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_06_07.jpg)

要为我们的主题添加主文本和次文本颜色，请在`colors`文件中添加以下这些行：

```kt
<color name="text_primary_dark">#DE000000</color> 
<color name="text_secondary_dark">#8A000000</color> 

<color name="text_primary_light">#FFFFFFFF</color> 
<color name="text_secondary_light">#B3FFFFFF</color> 

```

然后根据背景阴影，在`styles`文件中添加适当的行，例如：

```kt

<item name="android:textColorPrimary">@color/text_primary_light</item> 
<item name="android:textColorSecondary">@color/text_secondary_light</item> 

```

如果您使用了图像资源或下载了谷歌的材料图标之一，系统将自动将主文本颜色应用到我们的 FAB 图标上。否则，您需要直接为您的图标着色。

现在我们可以通过以下两个步骤激活工具栏和 FAB：

1.  在主活动的`onCreate()`方法中添加以下几行代码：

    ```kt
    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
    setSupportActionBar(toolbar); 

    ```

1.  在其活动的`onCreate()`方法中添加以下点击监听器：

    ```kt
    FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab); 
    fab.setOnClickListener(new View.OnClickListener() { 

        @Override 
        public void onClick(View view) { 
            // SYSTEM DISMISSES DIALOG 
        } 
    }); 

    ```

    现在，当视图滚动时，FAB 图标和工具栏标题将可见并正确动画：

    ![配置悬浮操作按钮](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_007.jpg)

点击悬浮操作按钮（FAB）应将用户带到另一个活动，即结账活动。然而，用户可能误点击了按钮，因此我们首先应该弹出一个对话框，让用户确认选择。

# 对话框构建器

除了少数应用外，Android 对话框对所有应用都是必不可少的，它也是了解框架本身如何应用设计模式的好方法。在这个例子中，它是对话框构建器，它通过一系列 setter 来构建我们的对话框。

在当前情况下，我们真正需要的只是一个非常简单的对话框，允许用户确认他们的选择，但对话框构建是一个非常有趣的话题，因此我们将更详细地了解它是如何完成的，以及内置构建器模式是如何用于构建它们的。

我们即将构建的对话框，如果得到确认，将把用户带到另一个活动，因此在这样做之前，我们应该创建该活动。通过从项目资源管理器菜单中选择`新建 | 活动 | 空白活动`可以轻松完成。这里我们称它为`CheckoutActivity.java`。

创建此活动后，请按照以下两个步骤操作：

1.  悬浮操作按钮的点击监听器将构建并显示我们的对话框。它相当长，所以创建一个名为`buildDialog()`的新方法：并在`onCreate()`方法的底部添加以下两行：

    ```kt
    fab = (FloatingActionButton) findViewById(id.fab); 
    buildDialog(fab); 

    ```

1.  然后像这样定义方法：

    ```kt
    private void buildDialog(FloatingActionButton fab) { 
        fab.setOnClickListener(new View.OnClickListener() { 

            @Override 
            public void onClick(View view) { 
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this); 

                LayoutInflater inflater = MainActivity.this.getLayoutInflater(); 

            builder.setTitle(R.string.checkout_dialog_title) 

                    .setMessage(R.string.checkout_dialog_message) 

                    .setIcon(R.drawable.ic_sandwich_primary) 

                    .setPositiveButton(R.string.action_ok_text, new DialogInterface.OnClickListener() { 

                        public void onClick(DialogInterface dialog, int id) { 
                            Intent intent = new Intent(MainActivity.this, CheckoutActivity.class); 
                            startActivity(intent); 
                        } 
                    }) 

                    .setNegativeButton(R.string.action_cancel_text, new DialogInterface.OnClickListener() { 

                        public void onClick(DialogInterface dialog, int id) { 
                            // SYSTEM DISMISSES DIALOG 
                        } 
                    }); 

                AlertDialog dialog = builder.create(); 
                dialog.show(); 
            } 
        }); 
    } 

    ```

    ![对话框构建器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_008.jpg)

对于这样一个简单的对话框，标题和图标是不必要的，这里包括它们只是为了示例。`AlertDialog.Builder`提供了许多其他属性，并且可以在以下位置找到全面的指南：

developer.android.com/reference/android/app/AlertDialog.Builder.html

这为我们几乎可以想到的任何警告对话框提供了一种便捷的构建方式，但它有一些不足之处。例如，上述对话框使用默认主题给按钮文字上色。在我们的自定义主题中，将这种颜色应用到我们的对话框会很不错。通过创建自定义对话框，可以轻松实现这一点。

## 自定义对话框

如您所料，自定义对话框是用 XML 布局文件定义的，这与我们设计其他任何布局的方式相同。此外，我们可以在构建器链中填充此布局，这意味着我们可以在同一个对话框中组合自定义和默认功能。

要自定义我们的对话框，只需以下两个步骤：

1.  首先，创建一个名为`checkout_dialog.xml`的新布局资源文件，并完成如下：

    ```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout  
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:orientation="vertical" 
        android:theme="@style/AppTheme"> 

        <ImageView 
            android:id="@+id/dialog_title" 
            android:layout_width="match_parent" 
            android:layout_height="@dimen/dialog_title_height" 
            android:src="img/dialog_title" /> 

        <TextView 
        android:id="@+id/dialog_content" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:paddingStart="@dimen/dialog_message_padding" 
        android:text="@string/checkout_dialog_message" 
        android:textAppearance="?android:attr/textAppearanceSmall" 
        android:textColor="@color/text_secondary_dark" /> 

    </LinearLayout> 

    ```

1.  然后，将`buildDialog()`方法编辑成与这里看到的一致。与之前方法的变化已被突出显示：

    ```kt
    private void buildDialog(FloatingActionButton fab) { 
        fab.setOnClickListener(new View.OnClickListener() { 

            @Override 
            public void onClick(View view) { 
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this); 

                LayoutInflater inflater = MainActivity.this.getLayoutInflater(); 

                builder.setView(inflater.inflate(layout.checkout_dialog, null)) 

                        .setPositiveButton(string.action_ok_text, new DialogInterface.OnClickListener() { 
                            public void onClick(DialogInterface dialog, int id) { 
                                Intent intent = new Intent(MainActivity.this, CheckoutActivity.class); 
                                startActivity(intent); 
                            } 
                        }) 

                        .setNegativeButton(string.action_cancel_text, new DialogInterface.OnClickListener() { 
                            public void onClick(DialogInterface dialog, int id) { 
                                // System dismisses dialog 
                            } 
                        }); 

                AlertDialog dialog = builder.create(); 
                dialog.show(); 

                Button cancelButton = dialog.getButton(DialogInterface.BUTTON_NEGATIVE); 
                cancelButton.setTextColor(getResources().getColor(color.colorAccent)); 

                Button okButton = dialog.getButton(DialogInterface.BUTTON_POSITIVE); 
                okButton.setTextColor(getResources().getColor(color.colorAccent)); 
            } 
        }); 
    } 

    ```

在这里，我们使用了`AlertDialog.Builder`将视图设置为我们的自定义布局。这需要布局资源和父级，但在这个例子中，我们从监听器内部构建，所以它保持为`null`。

在设备上测试时，输出应该类似于以下屏幕截图：

![自定义对话框](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_009.jpg)

### 提示

值得注意的是，在为按钮定义字符串资源时，最好*不要*将整个字符串大写，只大写首字母。例如，以下定义创建了上一个示例中按钮上的文本：

```kt
<string name="action_ok_text">Eat now</string> 
<string name="action_cancel_text">Continue</string> 

```

在这个例子中，我们自定义了对话框的标题和内容，但仍然使用了提供的确定和取消按钮，我们可以将我们自己的自定义与对话框的许多设置器混合匹配。

在我们继续之前，我们将为回收视图提供另一种功能，即滑动并取消的行为。

# 添加滑动并取消操作

在这个特定的应用中，我们不太可能需要滑动并取消的行为，因为列表很短，允许用户编辑它们也没有太大的好处。然而，为了让我们了解这个重要且有用的功能是如何应用的，即使最终设计中不会包含它，我们也将在这里实现它。

滑动以及拖放操作主要由**ItemTouchHelper**管理，它是一种 RecyclerView.ItemDecoration 的类型。这个类提供的回调允许我们检测项目的移动和方向，并拦截这些操作，然后在代码中响应它们。

如您在此处所见，实现滑动并取消行为只需几个步骤：

1.  首先，我们的列表现在将改变长度，因此删除这行代码`recyclerView.setHasFixedSize(true);`或者将其设置为`false`。

1.  保持`onCreate()`方法尽可能简单总是一个好主意，因为那里通常有很多事情发生。我们将创建一个单独的方法来初始化我们的项目触摸助手，并在`onCreate()`中调用它。以下是该方法：

    ```kt
    private void initItemTouchHelper() { 
        ItemTouchHelper.SimpleCallback callback = new ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT | ItemTouchHelper.RIGHT) { 

            @Override 
            public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, RecyclerView.ViewHolder viewHolder1) { 
                return false; 
            } 

            @Override 
            public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) { 
                int position = viewHolder.getAdapterPosition(); 
                adapter.removeItem(position); 
            } 
        }; 

        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(callback); 
        itemTouchHelper.attachToRecyclerView(recyclerView); 
    } 

    ```

1.  现在将以下行添加到`onCreate()`方法中：

    ```kt
    InitItemTouchHelper(); 

    ```

    尽管执行了半个函数的功能，`onCreate()`方法仍然保持简短和清晰：

    ```kt
    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(layout.activity_main); 

        Toolbar toolbar = (Toolbar) findViewById(id.toolbar); 
        setSupportActionBar(toolbar); 

        final ArrayList<Cheese> cheeses = buildList(); 
        adapter = new DataAdapter(cheeses); 

        recyclerView = (RecyclerView) findViewById(id.recycler_view); 
        recyclerView.setLayoutManager(new LinearLayoutManager(this)); 
        recyclerView.addItemDecoration(new ItemDivider(this)); 
        recyclerView.setAdapter(adapter); 

        initItemTouchHelper(); 

        fab = (FloatingActionButton) findViewById(id.fab); 
        buildDialog(fab); 
    } 

    ```

如果您在此时测试应用，您会注意到尽管项目在滑动时会从屏幕上消失，但间隙并没有关闭。这是因为我们还没有通知回收视图它已被移除。尽管这可以在`initItemTouchHelper()`方法中完成，但它实际上属于适配器类，因为它使用了它的方法。在适配器中添加以下方法以完成此任务：

```kt
public void removeItem(int position) { 
    cheeses.remove(position); 
    notifyItemRemoved(position); 
    notifyItemRangeChanged(position, cheeses.size()); 

```

现在当移除一个项目时，回收视图列表将会重新排序：

![添加滑动并取消操作](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_010.jpg)

在此示例中，用户可以左右滑动以关闭项目，这对我们这里的目的来说是可以的，但在很多情况下这种区分非常有用。许多移动应用程序使用向右滑动来接受一个项目，向左滑动来关闭它。这可以通过使用`onSwiped()`方法的方向参数轻松实现。例如：

```kt
if (direction == ItemTouchHelper.LEFT) { 
    Log.d(DEBUG_TAG, "Swiped LEFT"); 
} else { 
    Log.d(DEBUG_TAG, "Swiped RIGHT"); 
} 

```

在本章前面，我们使用了一个本地模式，即 AlertDialog.Builder 来构建布局。正如创建性模式的本意，背后的逻辑对我们是隐藏的，但构建器设计模式为从单个视图组件构建布局和视图组提供了一个非常好的机制，我们将在下面看到这一点。

# 构造布局构建器

到目前为止，在这本书中，我们构建的所有布局都是静态的 XML 定义。然而，正如你所期望的，完全可以从我们的源代码中动态构建和填充 UI。此外，Android 布局非常适合构建器模式，正如我们在警告对话框中所看到的，因为它们由一系列有序的小对象组成。

下面的示例将遵循构建器设计模式，从一系列预定义的*布局视图*中填充一个线性布局。像之前一样，我们将从接口构建到抽象和具体类。我们将创建两种布局项，标题或*头条*视图和*内容*视图。然后我们制作这些的具体示例，可以通过构建器来构建。因为所有视图都有一些共同的特征（在这种情况下是文本和背景颜色），我们将通过另一个接口来避免重复方法，这个接口有自己的具体扩展来处理这种着色。

为了更好地了解这是如何工作的，请启动一个新的 Android 项目，并按照以下步骤构建模型：

1.  创建一个名为`builder`的内部包。将以下所有类添加到这个包中。

1.  为我们的视图类创建以下接口：

    ```kt
    public interface LayoutView { 

        ViewGroup.LayoutParams layoutParams(); 
        int textSize(); 
        int content(); 
        Shading shading(); 
        int[] padding(); 
    } 

    ```

1.  现在创建文本和背景颜色的接口，如下所示：

    ```kt
    public interface Shading { 

        int shade(); 
        int background(); 
    } 

    ```

1.  我们将创建`Shading`的具体示例。它们看起来像这样：

    ```kt
    public class HeaderShading implements Shading{ 

        @Override 
        public int shade() { 
            return R.color.text_primary_dark; 
        } 

        @Override 
        public int background() { 
            return R.color.title_background; 
        } 
    } 

    public class ContentShading implements Shading{ 

        ... 
            return R.color.text_secondary_dark; 
        ... 

        ... 
            return R.color.content_background; 
        ... 
    } 

    ```

1.  现在我们可以创建我们想要的两种视图类型的抽象实现。这些应该符合以下要求：

    ```kt
    public abstract class Header implements LayoutView { 

        @Override 
        public Shading shading() { 
            return new HeaderShading(); 
        } 
    } 

    public abstract class Content implements LayoutView { 

        ... 
            return new ContentShading(); 
        ... 
    } 

    ```

1.  接下来，我们需要创建这两种类型的具体类。首先是标题：

    ```kt
    public class Headline extends Header { 

        @Override 
        public ViewGroup.LayoutParams layoutParams() { 
            final int width = ViewGroup.LayoutParams.MATCH_PARENT; 
            final int height = ViewGroup.LayoutParams.WRAP_CONTENT; 

            return new ViewGroup.LayoutParams(width,height); 
        } 

        @Override 
        public int textSize() { 
            return 24; 
        } 

        @Override 
        public int content() { 
            return R.string.headline; 
        } 

        @Override 
        public int[] padding() { 
            return new int[]{24, 16, 16, 0}; 
        } 
    } 

    public class SubHeadline extends Header { 

        ... 

        @Override 
        public int textSize() { 
            return 18; 
        } 

        @Override 
        public int content() { 
            return R.string.sub_head; 
        } 

        @Override 
        public int[] padding() { 
            return new int[]{32, 0, 16, 8}; 
        } 
        ... 

    ```

1.  然后是内容：

    ```kt
    public class SimpleContent extends Content { 

        @Override 
        public ViewGroup.LayoutParams layoutParams() { 
            final int width = ViewGroup.LayoutParams.MATCH_PARENT; 
            final int height = ViewGroup.LayoutParams.MATCH_PARENT; 

            return new ViewGroup.LayoutParams(width, height); 
        } 

        @Override 
        public int textSize() { 
            return 14; 
        } 

        @Override 
        public int content() { 
            return R.string.short_text; 
        } 

        @Override 
        public int[] padding() { 
            return new int[]{16, 18, 16, 16}; 
        } 
    } 

    public class DetailedContent extends Content { 

        ... 
            final int height = ViewGroup.LayoutParams.WRAP_CONTENT; 
        ... 

        @Override 
        public int textSize() { 
            return 12; 
        } 

        @Override 
        public int content() { 
            return R.string.long_text; 
        } 

        ... 

    ```

这样我们的模型就完成了。我们有两个单独的视图以及每种视图的颜色设置。现在我们可以创建一个助手类，按照我们希望的顺序组合这些视图。这里我们只需要两个，一个用于简单的输出，另一个用于更详细的布局。

构建器的样子如下：

```kt
public class LayoutBuilder { 

    public List<LayoutView> displayDetailed() { 
        List<LayoutView> views = new ArrayList<LayoutView>(); 
        views.add(new Headline()); 
        views.add(new SubHeadline()); 
        views.add(new DetailedContent()); 
        return views; 
    } 

    public List<LayoutView> displaySimple() { 
        List<LayoutView> views = new ArrayList<LayoutView>(); 
        views.add(new Headline()); 
        views.add(new SimpleContent()); 
        return views; 
    } 
} 

```

此模式的类图如下：

![Constructing layout builders](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_06_13.jpg)

正如构建器模式和其他一般模式所期望的，我们所做的一切工作都是为了将模型逻辑从客户端代码中隐藏起来，在我们的例子中，特别是当前活动和`onCreate()`方法。

当然，我们可以在主 XML 活动提供的默认根视图组中扩展这些视图，但动态生成这些视图通常也很有用，特别是如果我们想要生成嵌套布局。

下一个活动演示了我们现在如何使用构建器动态扩展布局：

```kt
public class MainActivity extends AppCompatActivity { 
    TextView textView; 
    LinearLayout layout; 

    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        final int width = ViewGroup.LayoutParams.MATCH_PARENT; 
        final int height = ViewGroup.LayoutParams.WRAP_CONTENT; 

        super.onCreate(savedInstanceState); 

        layout = new LinearLayout(this); 
        layout.setOrientation(LinearLayout.VERTICAL); 
        layout.setLayoutParams(new ViewGroup.LayoutParams(width, height)); 

        setContentView(layout); 

        // COULD USE layoutBuilder.displaySimple() INSTEAD         
        LayoutBuilder layoutBuilder = new LayoutBuilder(); 
        List<LayoutView> layoutViews = layoutBuilder.displayDetailed(); 

                for (LayoutView layoutView : layoutViews) { 
            ViewGroup.LayoutParams params = layoutView.layoutParams(); 
            textView = new TextView(this); 

            textView.setLayoutParams(params); 
            textView.setText(layoutView.content()); 
            textView.setTextSize(TypedValue.COMPLEX_UNIT_SP, layoutView.textSize()); 
            textView.setTextColor(layoutView.shading().shade()); 
            textView.setBackgroundResource(layoutView.shading().background()); 

            int[] pad = layoutView.padding(); 
            textView.setPadding(dp(pad[0]), dp(pad[1]), dp(pad[2]), dp(pad[3])); 

            layout.addView(textView); 
        } 
    } 
} 

```

您还需要以下方法，该方法用于从`px`转换为`dp`：

```kt
public int dp(int px) { 
    final float scale = getResources().getDisplayMetrics().density; 
    return (int) (px * scale + 0.5f); 
} 

```

在设备上运行时，将产生以下两种 UI 之一：

![构建布局构建器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_06_012.jpg)

如预期的那样，客户端代码简单、简短且易于理解。

不必使用程序化布局或静态布局，两者可以混合使用。视图可以在 XML 中设计，然后像我们在这里用 Java 所做的那样进行扩展。我们可以甚至保持这里使用的相同模式。

这里还有很多内容可以介绍，比如如何使用适配器或桥接模式包含其他类型的视图，例如图片，但我们将在书中稍后介绍组合模式。现在，我们已经了解了布局构建器的工作原理以及它是如何将其逻辑与客户端代码分离的。

# 总结

本章内容相当丰富。我们从创建一个折叠工具栏和一个功能性的回收视图开始。我们了解了如何为布局的大部分添加基本功能，以及如何将工厂模式应用于特定案例。这引导我们探索构建器（内部和创建的）如何用于构建详细布局。

在下一章中，我们将进一步探讨如何响应用户活动，现在我们有了某些工作的控件和视图，我们将了解如何将它们连接到有用的逻辑。
