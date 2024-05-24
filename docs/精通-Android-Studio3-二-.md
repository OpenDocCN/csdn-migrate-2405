# 精通 Android Studio3（二）

> 原文：[`zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9`](https://zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：资产和资源

到目前为止，在本书中，我们已经涵盖了布局、设计以及支持它们的库和工具。然后我们继续探讨为不同的屏幕尺寸、形状和密度以及其他形态因素进行开发。这是 UI 开发模块中的最后一章，我们将看看 Android Studio 如何管理各种资产和资源，如图标和其他可绘制图形。

当涉及将可绘制图标包含在我们的项目中时，Android Studio 非常包容，特别是在涉及矢量图形时，这对于 Android 开发人员非常宝贵，因为它们可以很好地适应不同的屏幕尺寸和密度，这是通过一个非常有价值的工具——矢量资产工作室来实现的。除此之外，还有一个资产工作室用于生成和配置位图图像。

矢量可绘制图标广泛用于应用程序图标和组件，如菜单、选项卡和通知区域，并且在对图标进行动画和从一个图标转换为另一个图标时也非常灵活，在小屏幕上非常有用的节省空间的功能。

在本章中，您将学会以下内容：

+   使用资源工作室创建图标

+   构建自适应图标

+   创建材料启动器图标

+   使用材料图标插件

+   创建矢量资产

+   导入矢量资产

+   图标动画

+   使用插件查看动态布局

+   从图像中提取显著颜色

# 资产工作室

几乎没有任何应用程序不使用某种形式的图标，即使这些只是启动器和操作图标，正确的选择和设计也决定了成功的 UI 和令人困惑的 UI 之间的区别。

尽管这并非必需，但 Google 非常希望我们使用材料设计图标。这是为了在整个平台上创建统一的用户体验，以抵消 iOS 提供更一致感觉的认知。这并不奇怪，因为 iOS 是一个对开发人员施加了很多限制的封闭系统。另一方面，Google 更愿意为开发人员提供更多的创造自由。过去，这导致苹果设备获得了比 Android 更为流畅的声誉，为了抵消这一点，Google 推出了材料设计指南，这些指南远远超出了最初的预期，现在可以在许多其他平台上找到，包括 iOS。

正如预期的那样，Android Studio 提供了工具来帮助我们整合这些设计特性和可绘制图标。这就是资源工作室的形式。这有助于创建和配置各种图标，从色彩鲜艳的详细启动器图标到完全定制和可伸缩的矢量图形操作和通知图标。随着 API 级别 26，Android 引入了自适应图标，可以在不同设备上显示为不同形状并执行简单的动画。

资源工作室具有两个单独的界面：一个用于一般图像，一个用于矢量图形。我们将在下一节中看到第一个。

# 图像资产工作室

在为不同的屏幕配置创建图像时，我们经常必须创建相同图像的几个版本，这通常不是一件大事。另一方面，当涉及到图标时，我们可能有几个单独的图标和数十个版本，使得调整大小和缩放它们变得繁琐。幸运的是，Android Studio 提供了一个简洁的解决方案，即图像资产工作室。

设备制造商可能更关心在其型号之间创建一致的外观和感觉。当涉及到启动器图标在其主屏幕上的显示方式时，这尤为明显。理想的情况是，开发人员可以设计一个单一的图标，然后制造商可以将其放入统一的形状中，例如方形或圆形，具体取决于其在设备上的位置和制造商自己的设计理念。

图像资产工作室通过创建一个使用我们原始图像和一个纯色背景层的双层图标来实现这一点，可以对其应用蒙版以创建所需的整体形状，通常是以下三个图像之一：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/57e21fe8-da87-44d0-9670-6f448e910fec.png)

自适应图标

可以通过从项目的可绘制上下文菜单中选择“新建|图像资产”来打开图像资产工作室：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/d11bba09-ec4b-48cf-8586-b6735f08a1d8.png)

资产工作室

创建能够在最广泛的设备和 API 级别上运行的图标有几个阶段，这些阶段由向导中的以下三个选项卡表示：前景层、背景层和传统。每个选项卡中都包含一些有价值的功能，将在下一节中概述。

# 分层图标

前景层是我们应用图像的地方。这可以是我们自己的艺术品，如果我们正在创建操作图标，也可以是剪贴画/文本。向导会自动生成每种可能用途的图标，包括 Play 商店图标，这涉及创建一个全新的资产。“显示安全区域”功能无疑是预览功能中最有用的功能，因为它显示了一个边界圆圈，如果我们的图标要在所有设备和平台上正确显示，我们的资产不应该超出这个区域。调整大小：控件允许我们快速确保我们的图标没有超出这个区域。

选择修剪：作为缩放选项将在创建完成的图标之前删除任何多余的像素，这意味着顶层的多余透明像素将被删除，通常会显著减小文件大小。

自适应图标的背景层需要足够大，以允许对其进行修剪，以创建前面图像中显示的形状和大小。默认的`ic_launcher_background.xml`生成描述网格的矢量图形。这在定位和调整我们的艺术品时非常有帮助，但不适用于已完成的应用程序。Google 建议您使用没有边框或外部阴影的纯色背景，尽管 Material 指南允许一些内部阴影，但最简单的解决方案是使用颜色而不是图像作为背景层。这还允许我们从我们的主题中选择一个突出的颜色，进一步推广我们的品牌。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/2d18238f-a8b7-42c3-bdcc-dfd16b44248e.png)

资产背景选择

前面的图像使用了剪贴画选择的图标，这很好地展示了在设计我们自己的图标时指南的目的。

只有在编辑前景层时才能选择源图像，无论您正在使用哪个选项卡。

传统选项卡使我们能够确保我们的图标仍然可以在运行 API 级别 25 及更低版本的设备上运行，并为运行这些较早版本的设备提供所需的所有设计功能，例如适合许多这些设备的细长矩形图标。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/eb4cbc81-2154-4ca8-a0b5-9e0121e8a6a7.png)

编辑传统图标

许多开发人员也是优秀的艺术家，他们将非常乐意从头开始设计启动器图标。对于这些读者来说，重要的是要知道，自 API 级别 26 开始，启动器图标的指定尺寸已经发生了变化。尽管图标是为`48 x 48 px`的网格设计的，但现在必须是`108 x 108 px`，中心的`72 x 72 px`代表了必须始终可见的部分。但是，无法保证未来的制造商会如何遵循这些指南，因此建议尽可能多地针对所有设备进行测试。

这里给出的指南不仅有助于确保我们的图像不会被不必要地裁剪，还有助于满足许多制造商现在包含的脉冲和摇摆动画。这些动画通常用于指示尝试的用户交互的成功或失败。

当然，创建自适应图标并不是严格必要的，一旦掌握了基础知识，我们当然可以直接设计和包含我们自己的 XML。这可以在清单文件中使用`android:roundIcon`标识符来完成，如下所示：

```kt
<application
 . . . 
     android:roundIcon="@mipmap/ic_launcher_round"
 . . . >
</application>
```

自适应图标可以使用`adaptive-icon`属性添加到任何 XML 布局中，如下所示：

```kt
<adaptive-icon>
     <background android:drawable="@color/ic_some_background"/>
     <foreground android:drawable="@mipmap/ic_some_foreground"/>
</adaptive-icon>
```

尽管包含的动作图标集很全面，但尽可能多的选择总是好的，可以在[material.io/icons/](http://material.io/icons/)找到一个更大更不断更新的集合。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/615b0235-0a87-4edb-b1ca-4b6d884a081c.png)

材料图标

图像资产工具非常适合生成我们在选项卡、操作栏等上使用的小型应用内图标，但在创建启动器图标时受到限制，启动器图标应该是明亮、多彩的，并且在材料方面是 3D 的。因此，启动器图标值得拥有自己的小节。

# 启动器图标工具

一般来说，启动器图标是使用外部编辑器创建的，正如我们将看到的，有 Studio 插件可以帮助我们创建时尚的 Android 图标。其中一个最好的工具是 Asset Studio 本身的在线、替代和增强版本。它是由谷歌设计师 Roman Nurik 创建的，可以在 GitHub 上找到[romannurik.github.io/AndroidAssetStudio](http://romannurik.github.io/AndroidAssetStudio)。

这个在线版本提供了半打不同的图标生成器，包括原生版本中没有的功能，以及一个整洁的图标动画。这里感兴趣的是启动器图标生成器，因为它允许我们设置 IDE 中没有提供的材料特性，如高程、阴影和评分。

这个编辑器最好的地方之一是它显示了材料设计图标的关键线。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/74245e77-6b10-488e-8fea-59e8729fc068.png)

启动器图标关键线

谷歌称之为*产品*图标的设计超出了本书的范围，但谷歌在这个问题上有一些非常有趣的指南，可以在[material.io/guidelines/style/icons](https://material.io/guidelines/style/icons.html)找到。

然而，当您配置启动器图标时，您将需要某种外部图形编辑器。有一些工具可以帮助我们将 Android Studio 与这些编辑器集成。

Android Material Design 图标生成器是来自 JetBrains 的一个很棒的插件，它正是其标题所暗示的。它不需要下载，因为它可以在插件存储库中找到。如果您想在另一个 IDE 中使用它，可以从以下 URL 下载：

[github.com/konifar/android-material-design-icon-generator-plugin](http://github.com/konifar/android-material-design-icon-generator-plugin)

如果您是 Android Studio 插件的新手，请执行以下简单步骤：

1.  从文件|设置中打开设置对话框....

1.  打开插件对话框，然后单击浏览存储库....

1.  在搜索框中键入材料，然后选择并安装插件。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/190a2f6a-e708-443d-b5e1-ac1f7d0d5bec.png)

插件存储库

1.  重新启动 Android Studio。

现在可以从大多数 New...子菜单或*Ctrl* + *Alt* + *M*打开插件。图标生成器很简单，但提供了所有重要的功能，比如能够创建位图和矢量图像以及所有密度分组的选择，以及颜色和大小选择器。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/41b24384-4dc0-43e1-b9e8-5689197f2637.png)

Android Material Design 图标生成器插件

图标生成器还有一个方便的链接到不断增长的 GitHub 材料设计图标存储库。

Sympli 是一个复杂但昂贵的设计工具，可以与您选择的图形编辑器和 Android Studio 一起使用。它可以自动生成图标和其他资产，并设计用于团队使用。它可以在[sympli.io](https://sympli.io/)找到。

虽然不是 Studio 插件本身，但 GitHub 上有一个方便的 Python 脚本，GIMP 用户可以在[github.com/ncornette/gimp-android-xdpi](https://github.com/ncornette/gimp-android-xdpi)找到。

只需下载脚本并将其保存在 GIMP 的`plug-ins`文件夹中，命名为`gimpfu_android_xdpi.py`。然后可以从图像的滤镜菜单中访问它。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/146fe493-a3f5-46fc-bdc0-1d27c930fccc.png)

自动生成图标

如前面的屏幕截图所示，此插件提供了将单个图像转换为一组图标时需要做出的所有主要选择。

使用这些工具创建和配置图标非常有用，也节省时间，但有很多时候我们根本不会使用位图作为我们的图标，而是使用矢量图形，它只需要一个图像来适配所有密度。

矢量图形加载比光栅图像慢，但一旦加载，速度会快一点。非常大的矢量图像加载速度慢，因此应该避免使用。

矢量图形在运行时以正确大小的位图进行缓存。如果要以不同大小显示相同的可绘制对象，请为每个创建一个矢量图形。

对于那些喜欢从头开始创建矢量图像的人来说，有一些非常有用的免费工具。

Method Draw 是一个在线**可缩放矢量图形**（**SVG**）编辑器，提供了一组简单但非常实用的工具，用于生成简单的矢量图像，比如我们想要用于操作和通知图标的图像。创作可以下载为`.svg`文件并直接导入到 Studio 中。它可以在`editor.method.ac`找到。

如果您需要更复杂的工具，Boxy SVG Editor 可以在 Chrome Web Store 上找到，但它可以离线使用，并提供类似于 Inkscape 或 Sketch 的功能。

# 矢量资源工作室

矢量图形资源工作室执行与光栅图形版本相同的功能，但更有趣。处理预设图标时，甚至可以更简单地使用一个只需要选择材料图标的兄弟。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/83f83504-d68e-477d-ba45-e614ba9f62c0.png)

矢量资源工作室

创建后，这样的资源将以`VectorDrawable`类的 XML 格式保存：

```kt
<vector  
    android:width="24dp" 
    android:height="24dp" 
    android:viewportHeight="24.0" 
    android:viewportWidth="24.0"> 

    <path 
        android:fillColor="#FF000000" 
        android:pathData="M19,13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" /> 

</vector> 
```

Android 矢量图形与 SVG 格式类似，有点简化，通常与`.svg`文件相关联。与光栅资源一样，使用现有图标非常容易。只有当我们想要修改这些图标或创建自己的图标时，才变得有趣。

当然，学习 SVG 或者理解`VectorDrawable`的`pathData`并不是必要的，但了解一点这个过程和我们可以使用的一些工具是有好处的。

# 矢量图形

矢量工作室允许我们导入 SVG 文件并将其转换为 VectorDrawables。有许多获取矢量图形的方法，许多图形编辑器可以从其他格式转换。还有一些非常好的在线工具可以将其他格式转换为 SVG：

[image.online-convert.com/convert-to-svg](http://image.online-convert.com/convert-to-svg)

JetBrains 插件也可以从以下位置获得：

[plugins.jetbrains.com/plugin/8103-svg2vectordrawable](https://plugins.jetbrains.com/plugin/8103-svg2vectordrawable)

当你编写自己的 SVG 对象时，你可能不会做太多事情，但了解这个过程是有用的，因为这些步骤展示了这些：

1.  将以下代码保存为`.svg`文件：

```kt
<svg 
    height="210" 
    width="210">

<polygon 
    points="100,10 40,198 190,78 10,78 160,198" 
    style="fill:black;fill-rule:nonzero;"/> 

</svg> 
```

1.  打开 Android Studio 项目，然后转到矢量工作室。

1.  选择本地文件，然后选择前面代码中创建的 SVG 文件。

1.  单击“下一步”和“完成”以转换为以下`VectorDrawable`：

```kt
<vector  
    android:width="24dp" 
    android:height="24dp" 
    android:viewportHeight="210" 
    android:viewportWidth="210"> 

    <path 
        android:fillColor="#000000" 
        android:pathData="M100,10l-60,188l150, 
                -120l-180,0l150,120z" /> 

</vector> 
```

通常将矢量图标着色为黑色，并使用`tint`属性进行着色是一个好主意。这样，一个图标可以在不同的主题下重复使用。

SVG`<polygon>`很容易理解，因为它是定义形状角的简单点列表。另一方面，`android:pathData`字符串有点更加神秘。最容易解释的方式如下：

+   `M`是移动

`100,10`

+   `l`线到

`-60,188`

+   `l`线到

`150,-120`

+   `l`线到

`-180,0`

+   `l`线到

`150,120 z`

（结束路径）

前面的格式使用大写字母表示绝对位置，小写字母表示相对位置。我们还可以使用`V`（`v`）和`H`（`h`）创建垂直和水平线。

不必在路径结束限定符 z 提供的情况下包括最终坐标。此外，如果字符与之前的字符相同，则可以省略一个字符，就像以前的`line-to`命令一样；考虑以下字符串：

```kt
M100,10l-60,188l150,-120l-180,0l150,120z 
```

前面的字符串可以写成如下形式：

```kt
M100,10 l-60,188 150,-120 -180,0z 
```

请注意，有两组图像尺寸，正如您所期望的那样--`viewportWidth`和`viewportHeight`；它们指的是原始 SVG 图像的画布大小。

关于矢量数据本身似乎是无关紧要的，因为这是由资源工作室生成的；但是，正如我们将在下面看到的，当涉及到动画图标（以及其他动画矢量图形）时，对矢量可绘制的内部结构的理解是非常有用的。

# 动画图标

每个使用 Android 设备的人都会熟悉动画图标。也许最著名的例子是当导航抽屉打开和关闭时，汉堡图标如何变换为箭头，反之亦然。矢量图形的使用使得这个过程非常简单。只要这两个图标具有相同数量的点，任何图标都可以转换为任何其他图标。

在移动设备上有效地使用空间是至关重要的，而动画化操作图标不仅看起来不错，而且还节省空间，并且如果应用得当，还会向用户传达意义。

矢量图像可以通过将原始图像上的点映射到目标图像上而轻松地从一个图像转换为另一个图像。这是通过`AnimatedVectorDrawable`类完成的。

有几种方法可以对这些可绘制进行动画处理。首先，我们可以应用许多预定义的动画，比如旋转和平移。我们还可以使用内置的插值技术来*变形*从一个可绘制到另一个，而不管点的数量。我们将研究这两种技术。然而，首先，我们将研究如何使用图像路径来控制动画，因为这给了我们最大的控制权。

以下图像表示一个箭头图标从左指向右的动画：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6a7d7807-59fe-497e-8189-986b2cc9c1cc.png)

一个动画箭头图标。

以下步骤演示了如何创建这样一个动画矢量可绘制。

1.  首先将两个箭头的路径存储为字符串，如下所示：

```kt
<!-- Spaces added for clarity only --> 
<string name="arrow_right"> 
    M50,10 l40,40 l-40,40 l0,-80z 
</string> 
<string name="arrow_left"> 
    M50,10 l-40,40 l40,40 l0,-80z 
</string> 
```

1.  由于两条路径都记录为字符串，我们只需要定义一个矢量可绘制--称之为`ic_arrow_left.xml`：

```kt
<vector  
    android:width="24dp" 
    android:height="24dp" 
    android:viewportHeight="100.0" 
    android:viewportWidth="100.0"> 

    <path 
        android:name="path_left" 
        android:fillColor="#000000" 
        android:pathData="@string/arrow_left" /> 

</vector> 
```

1.  创建`res/animator`文件夹和`arrow_animation.xml`文件，放在其中：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<set > 

    <objectAnimator 
        android:duration="5000" 
        android:propertyName="pathData" 
        android:repeatCount="-1" 
        android:repeatMode="reverse" 
        android:valueFrom="@string/arrow_left" 
        android:valueTo="@string/arrow_right" 
        android:valueType="pathType" /> 

</set> 
```

1.  我们可以使用这个来创建我们的动画可绘制，`ic_arrow_animated.xml`：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<animated-vector  

    android:drawable="@drawable/ic_arrow_left"> 

    <target 
        android:name="path_left" 
        android:animation="@animator/arrow_animation" /> 

</animated-vector> 
```

1.  要查看这个动画效果，请使用以下 Java 代码片段：

```kt
ImageView imageView = (ImageView) findViewById(R.id.image_arrow); 
Drawable drawable = imageView.getDrawable(); 

if (drawable instanceof Animatable) { 
    ((Animatable) drawable).start(); 
}
```

通过动画化矢量的路径，我们可以通过重新排列我们的点轻松地创建新的动画。

这个过程的关键是`arrow_animation`文件中的`ObjectAnimator`类。这个类比它在这里看起来的要强大得多。在这个例子中，我们选择了要动画化的`pathData`属性，但我们几乎可以动画化我们选择的任何属性。事实上，任何数值属性，包括颜色，都可以用这种方式进行动画化。

对象动画提供了创造富有想象力的新动画的机会，但只适用于现有属性。但是，如果我们想要动画化我们定义的值或者可能是反映一些特定应用程序数据的变量，该怎么办呢？在这种情况下，我们可以利用 ValueAnimator，从中派生出 ObjectAnimator。

Roman Nurik 的在线资源工作室还有一个功能强大且易于使用的动画图标生成器，可以在以下网址找到：

[romannurik.github.io/AndroidIconAnimator](http://romannurik.github.io/AndroidIconAnimator)

使用路径数据，这种方式提供了一个非常灵活的动画框架，特别是当我们想要将一个图标变形为另一个图标时，因为它改变了它的功能，通常在切换操作中经常看到，比如播放/暂停。然而，这并不是我们唯一的选择，因为有现成的动画可以应用到我们的矢量资产上，以及将图标转换为其他图标的方法，这些图标并不具有相同数量的点。

# 其他动画

变形路径数据是动画图标（和其他可绘制对象）的最有趣的方式之一，但有时我们只需要一个简单的对称运动，比如旋转和平移。

以下示例演示了如何应用这些动画类型之一：

1.  选择您喜欢的矢量可绘制对象，并将其`pathData`保存为字符串。在这里，我们使用`ic_first_page_black_24dp`图标从资源工作室获取数据。

```kt
<string name="first_page"> 
    M18.41,16.59 L13.82,12 l4.59,-4.59 L17,6 l-6,6 6,6 z 
            M6,6 h2 v12 H6 z 
</string> 
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/51ba20b3-18b6-437e-a642-5027584ccb5f.png)

ic_first_page_black_24dp 图标

1.  与以前一样，为此创建一个 XML 资源；在这里，我们将其称为`ic_first_page.xml`：

```kt
<vector  
    android:height="24dp" 
    android:width="24dp" 
    android:viewportHeight="24" 
    android:viewportWidth="24" > 

    <group 
        android:name="rotation_group" 
        android:pivotX="12.0" 
        android:pivotY="12.0" > 

        <path 
            android:name="page" 
            android:fillColor="#000000" 
            android:pathData="@string/first_page" /> 

    </group> 

</vector> 
```

1.  再次创建一个对象动画器，这次称为`rotation.xml`，并完成如下：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<set > 

    <objectAnimator 
        android:duration="5000" 
        android:propertyName="rotation" 
        android:repeatCount="-1" 
        android:valueFrom="0" 
        android:valueTo="180" /> 

</set> 
```

1.  现在，我们可以创建图标的动画版本，就像以前一样，设置一个目标。在这里，文件名为`ic_animated_page.xml`，看起来像这样：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<animated-vector 

    android:drawable="@drawable/ic_first_page"> 

    <target 
        android:name="rotation_group" 
        android:animation="@animator/rotation" /> 

</animated-vector> 
```

1.  动画可以通过首先将其添加到我们的布局中，就像我们对任何其他图标所做的那样，并从代码中调用它来调用：

```kt
ImageView imagePage = (ImageView) findViewById(R.id.image_page); 
Drawable page_drawable = imagePage.getDrawable(); 

if (page_drawable instanceof Animatable) { 
    ((Animatable) page_drawable).start(); 
} 
```

除了动画类型之外，这里最大的不同之处在于我们的`<path>`包含在`<group>`中。这通常用于当有多个目标时，但在这种情况下，是因为它允许我们使用`vectorX/Y`为旋转设置一个中心点。它还具有`scaleX/Y`、`translateX/Y`和`rotate`的等效设置。

要更改图标的透明度，在`<vector>`中设置`alpha`。

不得不构建一个项目来测试简单的图形特性，比如这些动画图标，可能非常耗时。Jimu Mirror 是一个布局预览插件，可以显示动画和其他移动组件。它通过设备或模拟器连接，并通过一个复杂的热交换过程，可以在几秒钟内编辑和重新测试布局。Jimu 不是开源的，但价格不是很昂贵，并且可以免费试用。它可以从[www.jimumirror.com](http://www.jimumirror.com)下载。

本章的重点主要是检查 Android Studio 和相关工具如何促进应用程序图标的生成。这使我们能够总体上了解 Android 可绘制对象，包括位图和矢量图形。我们在本书的前面简要地探讨了其他可绘制对象，现在我们更深入地研究了这个问题，现在是重新审视这些可绘制对象的好时机。

# 一般的可绘制对象

我们之前看到了如何使用着色将黑色图标转换为与我们的应用程序或当前活动相匹配的颜色。对于其他图像，有时它们占据了屏幕的相当大部分，我们希望应用相反的效果，使我们的图标着色以匹配我们的图形。幸运的是，Android 提供了一个支持库，可以从任何位图中提取突出和主导颜色。

# 调色板库

将我们自己的主题应用到我们的应用程序可以产生非常时尚的界面，特别是当我们处理我们自己为应用程序创建的文本、图标和图像时。许多应用程序都包含用户自己的图像，在这些情况下，事先无法知道如何选择令人愉悦的设计。**调色板支持库**为我们提供了这种功能，允许对文本、图标和背景颜色进行精细控制。

以下步骤演示了如何从位图可绘制对象中提取突出的颜色：

1.  开始一个新的 Android Studio 项目，并从“文件”菜单或*Ctrl* + *Alt* + *Shift* + *S*打开“项目结构”对话框。

1.  从应用程序模块中打开依赖选项卡，并从右上角的+图标中添加库依赖项，使用搜索工具查找库。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/954defd3-33a5-43dc-84ec-7867eb1057f0.png)

库依赖项选择器

1.  这将在您的`build.gradle`文件中添加以下行：

```kt
compile 'com.android.support:palette-v7:25.2.0' 
```

1.  创建一个带有大图像视图和至少两个文本视图的布局。将这些文本视图命名为`text_view_vibrant`和`text_view_muted`。

1.  打开您的主 Java 活动并添加以下字段：

```kt
private Palette palette; 
private Bitmap bmp; 
private TextView textViewVibrant; 
private TextView textViewMuted; 
```

1.  将前述的`TextViews`与它们的 XML 对应项关联，如下所示：

```kt
textViewVibrant = (TextView) 
        findViewById(R.id.text_view_vibrant); 

textViewMuted = (TextView) 
        findViewById(R.id.text_view_muted); 
```

1.  分配在步骤 5 中声明的位图：

```kt
 bmp = BitmapFactory.decodeResource(getResources(), 
        R.drawable.color_photo); 
```

1.  最后，添加以下条款以从图像中提取突出的鲜艳和柔和的颜色：

```kt
// Make sure object exists. 
if (bmp != null && !bmp.isRecycled()) { 
    palette = Palette.from(bmp).generate(); 

    // Select default color (black) for failed scans. 
    int default_color=000000; 

    // Assign colors if found. 
    int vibrant = palette.getVibrantColor(default_color); 
    int muted = palette.getMutedColor(default_color); 

    // Apply colors. 
    textViewVibrant.setBackgroundColor(vibrant); 
    textViewMuted.setBackgroundColor(muted); 
} 
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/21cb6ae8-5d1e-40cc-9534-da97d4dba86d.png)

提取的颜色

前面概述的方法是有效但粗糙的。调色板库还有很多功能，我们需要了解很多东西才能充分利用它。

调色板使用`default_color`是必要的，因为提取这些颜色并不总是可能的，有时会失败。这经常发生在*褪色*的图像和颜色很少的图像以及定义很少的高度不规则的图像上。有些讽刺的是，当呈现过饱和的图形和颜色很多的非常规则的图案时，扫描也可能失败，因为没有颜色（如果有的话）会支配。

在提取这些调色板时非常重要的一点是，使用大位图可能会严重消耗设备资源，所有与位图的工作在可能的情况下不应在当前线程上执行。前面的示例没有考虑到这一点，但库中有一个监听器类，允许我们异步执行这些任务。

考虑以下示例：

```kt
Palette palette = Palette.from(bmp).generate(); 
```

使用以下监听器，而不是前面的监听器，以在生成位图后做出反应：

```kt
Palette.from(bmp).generate(new PaletteAsyncListener() { 

    public void onGenerated(Palette p) { 
        // Retrieve palette here. 

    } 

}); 
```

在前面的示例中，我们只提取了两种颜色，使用`Palette.getVibrantColor()`和`Palette.getMutedColor()`。这些通常非常适合我们的目的，但如果不适合，还有每种颜色的浅色和深色版本，可以使用 getter 来访问，比如`getDarkVibrantColor()`或`getLightMutedColor()`。

调色板库的功能比我们在这里介绍的要多，比如能够选择与分析图像匹配的文本颜色，而且它并不是 Android Studio 专属的，因此从其他 IDE 切换过来的读者可能已经熟悉它。

本书中介绍的 Studio 功能展示了 IDE 在开发布局和 UI 时的实用性，但当然，这只是故事的一半。无论我们的布局多么完美，如果没有逻辑支持，它们就毫无用处，这就是 Android Studio 真正开始发挥作用的地方。

# 摘要

不仅在本章，而且在前面的三章中，我们看到了 Android Studio 如何使得在各种设备和因素上设计和测试我们的图形布局变得简单而直观。Studio 专门为 Android 的特点而设计，也是第一个集成新设计功能的工具，比如约束布局，这彻底改变了视觉活动的设计。

到目前为止，已经涵盖了 IDE 所考虑的所有基本设计问题，并希望向读者介绍了简化和澄清这个常常复杂过程的丰富功能。

在下一章中，我们将开始将这些设计变为现实，看看 Android Studio 如何简化编码、测试和调试应用程序的复杂过程。这些基本过程经常重叠，大多数开发人员会发现自己不得不在微调工作时重新访问每个过程。Android Studio 引导开发人员在这个过程中前后穿梭，使他们能够在进行时跟踪和评估。

Android Studio 已经帮助您将您的想法转化为令人愉悦的布局。下一步是用您的逻辑将这些布局变得生动起来。正如人们可能想象的那样，当涉及到逻辑时，IDE 在设计时一样有帮助。


# 第六章：模板和插件

作为开发环境，Android Studio 提供了设计和开发任何我们可以想象的 Android 应用程序的设施。在前几章中，我们看到它如何作为一个可视化设计工具，以及一个动态布局编辑器、模拟器和 XML 结构。从现在开始，我们将深入了解 IDE 如何促进、简化和加快编码、测试和微调我们的工作的过程。

大多数读者已经是专业的编码人员，不需要帮助。因此，我们将在接下来的章节中全面探讨 Android Studio 改进这一体验的方式。在本章中，我们将看到 IDE 自带的各种活动模板和 API 示例的代码示例。这些对于探索和学习各种组件的编码方式以及通过提供已经存在的起点来加快编码过程都是有用的。此外，正如我们将看到的，如果捆绑的模板选择不够，Android Studio 允许我们创建自己的模板。

在本章中，您将学习以下内容：

+   理解内置项目模板

+   访问结构工具窗口

+   安装和使用 UML 插件

+   应用简单的重构

+   应用代码模板

+   创建自定义模板

+   使用项目示例

# 项目模板

大多数读者在从 IDE 的欢迎屏幕开始新的 Android Studio 项目时已经遇到了项目模板。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c6ee59d1-aacf-4553-a917-e96a0769eb2e.png)

项目模板

即使是空活动模板也提供了几乎所有应用程序都必不可少的文件和一些代码，正如您在前面的屏幕截图中所看到的，有越来越多的项目模板集合，旨在适应许多常见的应用程序结构和目的。

# 导航抽屉模板

在这里不需要检查所有这些模板，但有一两个可能非常有教育意义，并且可以进一步了解 Android Studio 的工作原理。第一个，也许是最有用的，是导航抽屉活动模板，当按原样运行时产生以下输出：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c6aebf36-d507-4d0d-a5e9-df0809060837.png)

导航抽屉模板

如前面的屏幕截图所示，此模板提供了许多常见且推荐的 UI 组件，包括图标可绘制、菜单和操作按钮。这些模板最有趣的方面是它们创建的代码和使用的文件结构，这两者都是最佳实践的很好示例。

如果我们使用此模板开始一个新项目并开始四处看看，我们将观察到`activity_main.xml`文件与我们之前看到的不同，因为它使用`android.support.v4.widget.DrawerLayout`作为其根。在其中，我们发现来自设计库的`CoordinatorLayout`和`NavigationView`。与前面的示例一样，协调器布局包含一个工具栏和一个 FAB；然而，这些组件是在一个单独的文件中创建的，并与`include`标签一起包含，如下所示：

```kt
<include 
    layout="@layout/app_bar_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" /> 
```

这种结构可以帮助我们更容易地跟踪代码并使未来的修改更容易。正如可以看到的，这种方法也用于定义导航栏标题和主要内容。

大多数模板生成的 XML 对读者来说都很熟悉，但也有一两个片段可能需要解释。例如，`content_main.xml`文件包含以下行：

```kt
app:layout_behavior="@string/appbar_scrolling_view_behavior" 
```

引用的字符串不会在`strings.xml`文件中找到，因为它是系统提供的，并指向`AppBarLayout.ScrollingViewBehavior`类，确保我们的工具栏是它的一个实例。

`tools:showIn="@layout/app_bar_main"` 这一行可能也令人困惑。这是 `tools` 命名空间中的许多有用功能之一，用于在预览编辑器中显示导航抽屉，使开发人员无需每次想查看图形变化时都重新构建项目。

此模板和其他模板生成的 XML 资源只讲述了故事的一半，因为其中许多模板还生成了相当数量的 Java 代码，这同样有趣，甚至比 XML 更有趣。只需快速浏览一下 `MainActivity.Java` 代码，就可以看到模板如何设置处理基本导航、菜单和按钮点击的方法。这些代码都不难理解，但非常方便，因为所有这些方法都必须在某个时候由我们编写，而注释和占位符使得替换我们自己的资源和添加我们自己的代码变得非常简单。

# 结构资源管理器

以这种方式浏览代码是很好的，但很少有开发人员有这种奢侈，自然希望以一种快速查看类的结构和内容的方式。Android Studio 通过**结构工具窗口**提供了一个整洁的、图解的窗口，可以从项目资源管理器栏中选择，或者通过按 *Alt* + *7* 来选择：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/2ff9f52f-f555-409c-b47c-4477deee965f.png)

结构（*Alt *+ *7*）工具窗口

处理具有许多类的项目时，结构工具是一种非常有用的方式来保持概览，并且在处理冗长的类时，选择任何项目将在代码编辑器中突出显示相应的文本。

在结构资源管理器中选择项目后按 *F4* 将导致代码编辑器跳转到文本中的该位置。

结构窗格顶部的工具栏允许使用一些非常方便的过滤器，以便根据它们的定义类型显示我们的方法（如前图所示），以及其他级别的细节，例如是否显示属性和字段。

尽管能够从这样的角度查看任何类的视角非常有用，但通常情况下，我们希望从更多的角度查看类结构，当然也有允许更深入检查的插件。

# 类检查插件

有许多方法可以可视化类和类组，使它们更容易遵循或突出显示某些特性或属性。一种经过验证的可视化编程工具是**通用建模语言**（**UML**）。如果开发人员使用设计模式，这些对于特定用途非常有用。

有几个 UML 类图插件可供我们使用，从基本到复杂不等。如果你只想要一个简单的 UML 工具，那么 JetBrains 插件 simpleUMLCE 可以从以下链接下载：

[plugins.jetbrains.com/plugin/4946-simpleumlce](http://plugins.jetbrains.com/plugin/4946-simpleumlce)

如果您是插件新手，请按照快速步骤安装和使用 simple UML 插件：

1.  从上面的链接下载插件。

1.  从 Android Studio 的“文件 | 设置”菜单中打开插件对话框。

1.  使用“从磁盘安装插件...”按钮来定位并安装插件。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/13e8021a-801e-49a2-a069-1bb0ca76afb5.png)

插件对话框

您需要重新启动 IDE 才能访问插件。一旦您这样做了，右键单击项目资源管理器中的包或类，然后从菜单中选择“添加到 simpleUML 图表 | 新图表...”。插件将在左侧边栏添加一个选项卡，打开工具区域并显示以下截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/4e2f10ad-3cd3-49a2-b9e9-8a8b2afbda7c.png)

simpleUML 图表工具

我们在本章中使用的导航抽屉示例中使用的活动类有点太简单，无法真正展示出以图表方式查看代码的优势，但如果读者将此工具应用于更复杂的类，具有多个字段和依赖关系，其价值很快就会显现出来。

图表可以保存为图像，并且可以从窗口的工具栏中选择多种视角。

大多数 Studio 插件都会在排水沟中添加一个选项卡。这通常放置在左侧排水沟的顶部。这通常会干扰我们自己的工作区首选项。幸运的是，这些选项卡可以通过简单地将它们拖放到首选位置来重新排列。

对于大多数开发人员来说，像这样的简单 UML 工具已经足够了，但如果您喜欢更复杂的工具，那么**Code Iris**可能是适合您的插件。

Code Iris 不需要下载，因为可以通过浏览插件存储库找到。尽管如此，您仍然需要重新启动 IDE。可以通过单击“浏览存储库...”按钮来访问存储库，该按钮位于设置对话框的插件窗口中，与之前的插件相同。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/18e2cf25-40cc-4197-bbe6-d9ed94b7fe96.png)

浏览存储库对话框

快速查看项目网页的描述，可以在[plugins.jetbrains.com/plugin/7324-code-iris](https://plugins.jetbrains.com/plugin/7324-code-iris)找到，将显示 Code Iris 可以做的远不止创建类图，并且应该被视为更通用的可视化工具。该工具被描述为基于 UML 的谷歌地图，适用于您的源代码，这使其不仅是个人有用的开发工具，也是团队之间的良好沟通工具，并且更适合绘制整个项目而不是等效工具。

任何第三方插件存储库都可以通过单击“管理存储库...”按钮并将相关 URL 粘贴到生成的对话框中，使其在存储库浏览器中可用。

可以通过打开工具窗口并选择“创建/更新图表”按钮，或者从项目资源管理器中的单个模块、包或类的条目中生成代码可视化。

Code Iris 的强项在于其能够在任何规模上可视化项目，并且可以使用视图滑块快速在这些项目之间切换。与过滤器和称为**有机布局**的自动排列算法一起使用，我们可以快速生成适当且易于理解的可视化。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/d4db0b6c-dfac-4106-93b6-5c569c634ac4.png)

Code Iris 可视化

尽管其对生物学的自命不凡和英语使用不佳，有机布局工具实际上非常聪明，有用且外观良好。打开后（使用播放按钮），图表将根据我们的焦点动态排列，这可以通过简单点击感兴趣的类来指定。如果您曾经发现自己不得不处理文档不全的代码，这个工具可以节省您很多时间。

这里介绍的两个插件绝不是我们可用的唯一的检查和可视化工具，只需在互联网上快速搜索，就会发现更多。我们选择的这两个工具之所以被选择，是因为它们代表了周围的工具类型。

我们在这里探讨的导航抽屉模板非常有用，因为它包含了几乎无处不在的 UI 组件。它也非常容易理解。另一个非常方便的项目模板是主/细节流模板。

# 主/细节流模板

在移动设备上经常会发现主/细节 UI，因为它们通过在屏幕的当前宽度上分别或并排显示列表及其各个项目，非常好地最大化了空间的使用。这导致手机在纵向方向上显示两个单窗格；但是，在横向模式或较大的设备上，如平板电脑上，将会并排显示两个窗格：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/f5f71a36-1996-4a65-b982-59500d6f59d5.png)

双窗格视图

前面的屏幕截图是从未经修改的主/细节流项目模板在横向模式下查看的，以便显示两个窗格。我们之前说过，两窗格视图在手机上的横向模式下是可见的。如果您在许多手机上尝试过这一点，您会发现这并不一定正确。默认情况下，模板仅在最长边为 900dp 或更长的屏幕上显示两个窗格。这可以从`res/layout-w900dp`目录的存在中推断出来。

要在较小的设备上启用双窗格视图，我们只需要更改此文件夹的名称。当然，这可以直接从我们的文件浏览器中完成，但是 Android Studio 具有强大的重构系统和复杂的预览窗口。虽然在这种情况下并不需要，但它可能最有用的地方是它会搜索对它的引用并将它们重命名。

按下*Shift* + *F6*可以直接打开重命名对话框。

当然，如果您尝试从导航栏或项目资源管理器访问`layout-w900dp`文件夹，您将无法这样做。要做到这一点，切换从 Android 选项卡到资源管理器中的项目选项卡，因为这样可以将项目完全呈现为磁盘上的状态。

快速检查代码将会发现一个名为 DummyContent 的 Java 类。正如您将看到的，有一个 TODO 通知，指出这个类需要在发布之前被移除，尽管当然也可以简单地对其进行重构。这个文件的目的是演示如何定义内容。我们所需要做的就是用我们自己的内容替换模板中的占位符数组。当然，这可以采用我们选择的任何形式，比如视频或 Web 视图。

能够使用现成的代码开始项目非常有用，可以节省大量时间。但是，有许多时候我们可能希望以适合我们目的的自己的结构开始项目，而这可能并不是通过 IDE 可用的。然而，这种情况并不妨碍我们这样做，因为代码模板可以在任何时候使用，而且，正如我们将看到的，甚至可以创建我们自己的模板。

# 自定义模板

想象一下，你正在开发一个项目，该项目使用我们已经检查过的模板之一，但你也想要一个登录活动。幸运的是，通过 IDE 内部已经启动的项目可以轻松管理。

当我们启动新项目时，呈现给我们的项目模板屏幕可以在任何时候使用。只需从项目资源管理器的上下文敏感菜单中选择 New | Activity | Gallery...，然后选择所需的活动。然后会呈现一个自定义屏幕，与之前看到的类似，但具有声明父级和包的选项，使我们能够使用尽可能多的模板。

如果您访问了活动库，您还会注意到这些活动也可以直接选择，而无需打开库。

同样的菜单还允许我们创建和保存自己的模板。打开源代码文件夹的上下文敏感菜单，选择 New | Edit File Templates...将打开以下对话框：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/163e42a5-fc7b-4016-b9e5-88c90fbe49a1.png)

模板编辑向导

如前面的屏幕截图所示，有许多文件模板可用，以及其他三个选项卡。包含选项卡提供文件头，代码选项卡包含较小的代码单元，其中许多在测试期间非常有用。其他选项卡特别有用，提供了更大的应用程序组件的模板，例如活动、片段、清单、布局和资源。

左上角的+图标允许我们创建自己的模板（但只能从前两个选项卡）。最简单的方法是直接将代码粘贴到提供的窗口中。命名并保存后，它将出现在“文件”|“新建”菜单或项目资源管理器目录中。

仅仅快速查看一些内置模板就会立即发现`${VARIABLE}`形式的占位符变量的使用。正是这些占位符使得定制模板成为一个有用和灵活的工具。

了解这些变量如何工作的最简单方法是使用现有模板之一，看看这些占位符是如何实现的；这在以下练习中有详细说明：

1.  打开文件模板向导，如前面所述。

1.  从其他选项卡中，复制`Activity.java`条目中的代码。

1.  使用+按钮创建新模板，命名它，并将代码粘贴到提供的空间中。

1.  根据您的需求编辑代码，确保包含自定义变量，就像以下代码中所示：

```kt
package ${PACKAGE_NAME}; 

import android.app.Activity; 
import android.os.Bundle; 

#parse("File Header.java") 
public class ${NAME} extends Activity { 

public String ${USER_NAME} 

    @Override 
    public void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
    } 
} 
```

1.  点击“确定”保存模板，它将出现在“新建”菜单中。

1.  现在，每当您创建此模板的实例时，Android Studio 将提示您输入模板占位符中定义的任何变量：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a91a2bcf-ab6d-4401-b8d0-85ef9fbdb030.png)

从模板生成类

所有开发者都依赖可以反复使用的代码，尽管其他集成开发环境提供了代码模板，但内置结构的数量和创建的便利性使得这是 Android Studio 最大的节省时间的功能。

# 第三方模板

在继续之前，我们需要快速看一下另一种访问现成模板的方式：第三方模板。网上有很多这样的模板，快速搜索就会发现。很多最好的模板不幸的是并不免费，尽管很多提供免费试用。

诸如 Softstribe 和 Envato 之类的网站为大量应用程序类型提供高度开发的模板，例如广播流、餐厅预订和城市指南。这些模板大多是完全开发的应用程序，几乎只需要配置和定制。这种方法可能不适合经验丰富的开发者，但如果速度是您的首要任务，并且您有预算支持，这些服务提供了项目完成的强大快捷方式。

模板不是 Android Studio 提供现成代码时的唯一节省时间的功能，您无疑已经注意到 IDE 中提供的许多示例项目。

# 项目示例

尽管可以从示例浏览器中访问示例，但更常见的是在项目开始时打开其中一个示例。这可以从欢迎屏幕下的“导入 Android 代码示例”中完成。有数百个这样的示例（还可以在网上找到更多），这些示例在示例浏览器中被很好地分组到类别中。

与模板一样，示例可以作为更大项目的起点，但它们本身也是教育的一部分，因为它们是由非常有经验的开发者编写的，并且是最佳实践的绝佳示例：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a1208777-3180-4179-ab0b-dd9f535b4f20.png)

示例浏览器

从前面的示例浏览器中可以看到，示例不仅可以从浏览器下载，还可以在 GitHub 中查看。读者会知道，GitHub 是一个非常有用的代码存储库，对各种开发人员都非常有用，它包含了示例浏览器中找到的所有示例；还有成千上万的其他 Android 项目、代码库和插件。从示例的角度来看，这个资源是一个很好的时间节省器，因为在决定是否下载和构建之前，查看代码要快得多。

有这么多示例，它们都同样有用和有教育意义，这使得很难选择任何一个来在这里进行检查，尽管 Camera2 示例可能有助于探索，因为这是许多开发人员可能以前没有检查过的 API。这归结为以下两个因素：

+   很多时候，相机功能可以通过简单地从我们自己的应用程序中调用原生应用程序（或用户已安装的应用程序）来访问。

+   Camera2 API 与运行在 API 级别 20 及以下的设备不兼容。与许多 API 不同，没有方便的支持库可以使 Camera2 向后兼容。

尽管存在这些缺点，如果您计划开发一个专注于捕获图像和视频的应用程序，那么您将需要自己构建所有的功能。这就是这些示例可能非常有用的地方。Camera2Basic 示例可能是首选查看的最佳示例。

示例只包含三个类和一个简单的布局结构，适用于横向和纵向方向。这些类包括一个基本的启动活动，一个扩展的 TextureView，根据运行设备的不同调整要捕获的区域的大小，以及一个大部分工作的 Fragment。所有这些类都有很好的注释，基本上是自解释的，只需要快速查看代码就可以理解它的工作原理。像其他示例一样，Camera2Basic 可以在没有任何进一步修改的情况下构建和运行：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8b74924c-123e-4ddb-909e-a32a14c83c9f.png)

Camera2Basic 示例

存储库中的所有示例都同样有用，取决于您选择的项目，它们都同样写得很好并且具有教育意义。

GitHub 最有用的特性之一是那里有大量的第三方库可用，当我们更仔细地查看 Gradle 构建过程时，我们将看到这些库如何可以作为依赖项从 Android Studio 中包含。

这些并不是 GitHub 上唯一有用的工具，GitHub 也绝不是这些工具的唯一来源。随着我们从 UI 开发转向编码，现在是时候再次看一些可用于 Android Studio 的第三方插件了。

# 第三方插件

有大量不断增长的第三方插件可用，这使得选择一个公平的样本变得困难。以下部分涵盖了一小部分插件，主要是因为它们的通用用途。

# ADB Wi-Fi

这是一个 JetBrains 插件，因此可以在设置对话框的插件屏幕上使用“浏览存储库...”按钮找到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/3a3fa2a5-bdf0-4f6a-8e83-d1574feeb5e3.png)

插件对话框

这个插件简单地允许我们使用共享的 Wi-Fi 连接来调试我们的应用程序。尽管它很简单，但这个应用程序不仅仅是一个节省电缆的便利，因为它允许对许多设备的传感器进行实时调试，这些传感器如果被绑定到主机机器上将受到很大限制。健身和增强现实应用程序可以通过这种方式更轻松地进行测试。

ADB Wi-Fi 非常简单设置和使用，特别是如果您的主机和设备已经共享了 Wi-Fi 连接，并且设备之前已经用于调试。

大多数插件比这个更复杂，许多使用了一些非常复杂的技术，比如人工智能。

# Codota

最近人们对人工智能的进步大做文章，虽然许多这样的说法夸大和自负，但仍然有一些引人注目的例子，表明真正有用的人工智能是可用的，Codota 就是其中之一。

许多开发人员可能已经熟悉 Codota 作为在线搜索工具或浏览器扩展程序。尽管这些工具很聪明和有用，但 Codota 真正发挥作用的地方是作为 IDE 插件。它使用一个名为 CodeBrain 的智能和不断发展的 AI 系统。这种代码是基于一种称为 Example-Centric Programming 的新兴编程形式。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/07c59adf-13fc-40b6-a181-75d32eaacac1.png)

Codota 的 CodeBrain

从技术上讲，Codota 插件并不是真正的插件，因为它必须单独安装并在与 IDE 不连接的窗口中运行。这是因为它与 Java IDE 一起工作，而不是与个别环境连接。这有几个优势，其中之一是插件是一个 Java 插件，而不是特定于 Android，这意味着它将在任何版本的 Studio 上运行，并且（不像一些插件）不需要等待更新。

Android Studio Codota 插件作为一个独立的应用程序运行，这在某种程度上是一个优势。一旦打开，它就非常聪明（根据其算法哲学，变得越来越聪明）。该软件声称提供智能编码助手，很多时候确实如此，我挑战任何人不被其才智所折服。它有一些缺陷，但往往能够从各种在线来源（包括 stackoverflow 和 GitHub）中找到几乎总是有用的示例。

一旦下载并打开，只需打开 IDE 并点击感兴趣的代码，Codota 很可能会提供一些非常好的答案来回答您可能有的任何问题。想象一下有一个助手，虽然不是很聪明，但非常有知识，并且可以在几秒钟内扫描所有相关的在线代码。这就是 Codota，无论您将其用作浏览器扩展程序、搜索工具还是 IDE 插件，它都是最好的编码助手之一。

# 总结

在本章中，我们已经研究了两种辅助代码开发过程的方法：现成的代码和助手插件和附加组件。模板通常是快速启动项目的好方法，类检查插件使我们能够轻松理解更大的模板，而无需仔细研究大量代码。

本章中我们看到的其他插件提供了一些不同的方法，使应用程序开发任务更加轻松和有趣。当然，市面上有很多很棒的工具，编码也在不断变得不那么单调，更有创造力。

本章重点介绍了 Java 编程，但正如任何开发人员所知道的那样，这绝不是唯一可用的语言。Android Studio 支持 C++和 Kotlin（后者甚至可以与 Java 代码一起使用）。

在下一章中，我们将探讨如何支持其他语言，以及看看 Android Things，尽管不是另一种语言，但确实需要许多传统开发人员可能不熟悉的技能。幸运的是，Android Studio 提供了使为单板计算机开发与开发其他 Android 应用程序非常相似的工具。


# 第七章：语言支持

要被认为是真正必不可少的 IDE，它必须做的不仅仅是提供基础功能。特别是，它必须对来自各种背景、使用各种语言和哲学的开发者都是可访问的。例如，许多开发者更喜欢采用面向对象的方法，而其他人更喜欢更基于功能的哲学，许多潜在项目更容易适应这两种范式中的一种。

Android Studio 3 为 C++和 Kotlin 提供了完整的语言支持，使开发者有机会根据手头项目的需求专注于速度或可编程性。

除了提供这种语言支持外，Android Studio 还促进了为各种形态的设备开发应用程序。读者可能已经熟悉 Android Wear 和 Android Auto，最近 IDE 还包括了对 Android Things 的支持。

在本章中，我们将看看这些语言支持系统以及构成**物联网**（**IoT**）的令人兴奋的新形态。

在本章中，您将学习以下内容：

+   包括 Kotlin 语言支持

+   将 Kotlin 与 Java 集成

+   应用 Kotlin 扩展

+   设置本地组件

+   在项目中包括 C/C++代码

+   创建 Android Things 项目

# Kotlin 支持

自移动应用诞生以来，软件开发经历了不止一次革命，而 Android 框架也不陌生于这些变化。许多开发者更喜欢 Java，因为它相对容易使用，但总会有一些时候，我们想要 C++的原始速度，而 Java 早在移动设备出现几十年前就存在了。如果有一种高级语言，比如 Java，它是专门为移动开发而设计的，那不是很好吗。

幸运的是，俄罗斯的 JetBrains 团队创建了 Kotlin，它可以与 Java 一起工作，甚至在 Java 虚拟机上运行，以创建一个更适合 Android 开发者需求的语言。它还与 Java 完全可互操作，因此您可以在同一个项目中使用 Java 和 Kotlin 文件，一切仍然可以编译。您还可以继续使用 Kotlin 与所有现有的 Java 框架和库。

Kotlin 作为插件已经提供给开发者一段时间了，但自从 Android Studio 3.0 推出以来，Kotlin 现在已完全集成到 IDE 中，并且已被 Google 正式支持为开发语言。IDE 中包括了用 Kotlin 编写的工作样本和向导模板。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/e8482cd4-7b27-4aa5-a322-1fc29ad13536.png)

在项目设置向导中包括 Kotlin 支持

学习一门新的编程语言很少会有多少乐趣，Kotlin 也不例外。使用它的好处在于，我们不必一下子从一种语言跳到另一种语言，可以逐渐引入 Kotlin，随时选择使用。

我们中的许多人已经使用 Java 很长时间了，并且没有真正改变的理由。毕竟，Java 运行得很好，多年的经验可以带来一些非常快速的工作实践。此外，互联网上充斥着高质量的开源代码库，使得研究和学习新技能对 Java 程序员非常有吸引力。

在 Android 开发中，学习和使用 Kotlin 绝对不是必须的，但值得一看的是，为什么有这么多开发者认为它代表了 Android 应用开发的未来。

# Kotlin 的优势

除了谷歌自己的认可之外，还有许多理由让开发者考虑 Kotlin。其中一个原因可能是终结空指针异常，编译器通过不允许将 null 值分配给任何对象引用来实现这一点。语言的其他令人兴奋的特性包括更青睐组合而非继承、智能转换和创建数据类。

看到这些创新提供了多大的优势，最好的方法是看一下这些。

正如前一节中的屏幕截图所示，Kotlin 可以直接从模板向项目中包含，但是我们也可以以与添加任何其他类或文件相同的方式，从已经打开的项目中包含 Kotlin 类。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/f3358cf0-c019-4b3e-a705-6962e2ca9d66.png)

添加一个新的 Kotlin 文件/类

以这种方式包含一个 Kotlin 类将提示 IDE 自动配置 Kotlin 与 Gradle。它通过修改顶级`build.gradle`文件来实现：

```kt
buildscript { 
    ext.kotlin_version = '1.1.3-2' 

    repositories { 
        google() 
        jcenter() 
    } 
    dependencies { 
        classpath 'com.android.tools.build:gradle:3.0.0-alpha9' 
        classpath "org.jetbrains.kotlin:kotlin-gradle-
                      plugin:$kotlin_version" 
    } 
} 

allprojects { 
    repositories { 
        google() 
        jcenter() 
    } 
} 

task clean(type: Delete) { 
    delete rootProject.buildDir 
} 
```

在 Android 应用中使用 Kotlin 几乎不会产生额外开销；而且，一旦编译完成，Kotlin 代码的运行速度不会比其 Java 等价物慢，也不会占用更多的内存。

像这样包含一个新的 Kotlin 类或文件非常有用，但是如何从模板创建一个 Kotlin 活动或片段呢？作为 Java 开发人员，我们习惯于使用简单的配置对话框来设置这些。幸运的是，Kotlin 活动也没有什么不同，`配置活动`对话框允许我们适当地选择源语言。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/23a4e7b9-8cd7-4e9e-95db-f2d621c88856.png)

选择源语言

与以前一样，值得一看的是最终代码，看看与传统的 Java 活动/片段模板相比，它有多么简洁和可读。

```kt
class ItemDetailFragment : Fragment() { 

    private var mItem: DummyContent.DummyItem? = null 

    public override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 

        if (getArguments().containsKey(ARG_ITEM_ID)) { 
            mItem = DummyContent.ITEM_MAP.
                     get(getArguments().getString(ARG_ITEM_ID)) 

            val activity = this.getActivity() 
            val appBarLayout = activity.findViewById<View>
                   (R.id.toolbar_layout) as CollapsingToolbarLayout 
            if (appBarLayout != null) { 
                appBarLayout!!.setTitle(mItem!!.content) 
            } 
        } 
    } 

    public override fun onCreateView(inflater: LayoutInflater?, 
         container: ViewGroup?, savedInstanceState: Bundle?): View? { 
        val rootView = inflater!!.inflate(R.layout.item_detail, 
                               container, false) 

        if (mItem != null) { 
            (rootView.findViewById(R.id.item_detail) as 
                         TextView).setText(mItem!!.details) 
        } 

        return rootView 
    } 

    companion object { 
        val ARG_ITEM_ID = "item_id" 
    } 
} 
```

通过使用 Kotlin 扩展来删除对`findViewById()`的调用，可以使这段代码变得更加简洁，如下一节所述。

虽然这种混合语言的方式对于调整和更新现有应用非常有用，但是当应用于整个项目时，Kotlin 才能充分发挥其作用。也许它最吸引人的特点是简洁性，通过从头开始创建两个项目并比较它们的代码，这一点很容易看出。以下是导航抽屉模板代码中的`onCreate()`列表：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 
    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
    setSupportActionBar(toolbar); 

    FloatingActionButton fab = (FloatingActionButton) 
                 findViewById(R.id.fab); 
    fab.setOnClickListener(new View.OnClickListener() { 
        @Override 
        public void onClick(View view) { 
            Snackbar.make(view, "Replace with your own action", 
                   Snackbar.LENGTH_LONG) 
                    .setAction("Action", null).show(); 
        } 
    }); 

    DrawerLayout drawer = (DrawerLayout) 
              findViewById(R.id.drawer_layout); 
    ActionBarDrawerToggle toggle = new ActionBarDrawerToggle( 
            this, drawer, toolbar, R.string.navigation_drawer_open, 
                  R.string.navigation_drawer_close); 
                  drawer.addDrawerListener(toggle); 
                  toggle.syncState(); 

    NavigationView navigationView = (NavigationView) 
              findViewById(R.id.nav_view); 
    navigationView.setNavigationItemSelectedListener(this); 
} 
```

以下是它的 Kotlin 等价物：

```kt
override fun onCreate(savedInstanceState: Bundle?) { 
    super.onCreate(savedInstanceState) 
    setContentView(R.layout.activity_main) 
    setSupportActionBar(toolbar) 

    fab.setOnClickListener { view -> 
        Snackbar.make(view, "Replace with your own action", 
                  Snackbar.LENGTH_LONG) 
                .setAction("Action", null).show() 
    } 

    val toggle = ActionBarDrawerToggle( 
            this, drawer_layout, toolbar, 
            R.string.navigation_drawer_open, 
            R.string.navigation_drawer_close) 
    drawer_layout.addDrawerListener(toggle) 
    toggle.syncState() 

    nav_view.setNavigationItemSelectedListener(this) 
} 
```

这种语法的增加简洁性是所有开发人员都会欢迎的，而这绝不是使用 Kotlin 的唯一优势。

# 扩展 Kotlin

正如人们对任何强大的编程范式所期望的那样，可以通过插件来扩展它，以进一步增加其实用性。

每个 Android 开发人员都会对自己多少次输入`findViewById()`失望。他们也会意识到这种静态类型可能有多容易出错。

在项目设置期间启用 Kotlin 支持时，默认情况下会包含 Kotlin 扩展，如模块级`build.gradle`文件中所示：

```kt
apply plugin: 'com.android.application' 

apply plugin: 'kotlin-android' 

apply plugin: 'kotlin-android-extensions' 
```

使用扩展还需要将其导入到适当的类中，通常是活动或片段。读者很可能已经通过系统设置设置了自动导入。然后所需的就是以通常的方式使用 XML 创建视图，如下所示：

```kt
 <TextView 
        android:id="@+id/text_view" 
       . . . /> 
```

现在，设置该小部件的值所需的只是以下内容：

```kt
text_view.setText("Some text") 
```

无论您是否设置了自动包含导入，了解这些导入的格式是很有用的。考虑以下示例：

```kt
import kotlinx.android.synthetic.main.some_layout.* 
```

还可以导入特定视图的引用，而不是整个布局文件，如下所示：

`import kotlinx.android.synthetic.main.some_layout.text_view`

1.  在这种情况下，`some_layout.xml`将是包含我们的`text_view`的文件。

1.  如果您习惯于在活动 XML 中使用`<include>`引用内容 XML，那么您将需要两个类似于以下的导入：

```kt
import kotlinx.android.synthetic.main.some_activity.*
import kotlinx.android.synthetic.main.some_content.*
```

我们不仅可以在这里设置文本；任何我们喜欢的函数都可以以同样的方式调用，而无需通过搜索其 ID 来引用视图。

请注意，在 Kotlin 中，分号作为语句分隔符是完全可选的。

希望到目前为止，读者已经被说服了在 Kotlin 中编码的优势，但在我们继续之前，Kotlin 的一个功能隐藏在主`Code`菜单的底部。这是将 Java 文件转换为 Kotlin 文件。这正是它所说的，甚至可以找到并解决大多数转换问题，使其成为一个很好的节省时间的工具，也是学习两种语言之间差异的一种有趣方式。

使用*Ctrl* + *Alt* + *Shift* + *K*可以自动将 Java 转换为 Kotlin。

尽管 Kotlin 可能是 Android Studio 中最新的添加之一，但它并不是我们选择替代语言的唯一选择，C++提供的速度和低级内存访问已经成为许多开发人员的首选。在接下来的部分中，我们将看到这种强大的语言如何被 IDE 轻松支持。

# C/C++支持

到目前为止，我们已经看到所有编程语言都有其利弊。C 和 C++可能需要更多的纪律来掌握，但这往往会被语言提供的低级控制所弥补。

在使用 Android Studio 时，需要一组略有不同的开发工具。这包括**本地开发工具包**（**NDK**）和**Java 本机接口**（**JNI**），以及其他调试和构建方式。与 Android Studio 中的大多数流程一样，设置这些工具非常简单。

# NDK

如前一节所述，本地编程需要与我们到目前为止使用的略有不同的一套工具。正如人们所期望的那样，我们需要的一切都可以在 SDK Manager 中找到。

很可能您需要安装以下截图中突出显示的组件；您至少需要 NDK、CMake 和 LLDB：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/d0c0b7cd-f80b-4186-b30d-5d5cc1f16719.png)

本地开发组件

+   CMake：这是一个多平台测试和构建工具，与 Gradle 一起工作。有关全面的文档，请访问[cmake.org](https://cmake.org/)。

+   LLDB：这是一个功能强大的开源调试工具，专门设计用于处理多线程应用程序。其详细用法超出了本书的范围，但感兴趣的用户可以访问[lldb.llvm.org](http://lldb.llvm.org/)。

安装了正确的软件后，本地编码可以非常顺利地整合到 Android Studio 项目中，与我们的 Java/Kotlin 类和文件一起。与 Kotlin 支持一样，只需在设置过程中勾选适当的框即可。

选择此选项后，您将有机会配置 C++支持，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/4f4bb14b-8e7f-4a61-baca-37ade8605f52.png)

C++支持自定义对话框

如果您使用 CMake，选择标准作为默认的工具链是最佳选择，大多数情况下，异常支持和运行时类型信息支持也值得检查。它们的包含可以通过检查模块级`build.gradle`文件来最清楚地看到：

```kt
DefaultConfig { . . . externalNativeBuild { cmake { cppFlags "-frtti -fexceptions" } } }
```

通常情况下，要在不用弄脏手的情况下深入了解内部情况的最佳方法之一就是使用现成的 Android 示例。这些示例并不多，但都很好，而且在 GitHub 上有一个不断增长的社区项目，网址是[github.com/googlesamples/android-ndk](https://github.com/googlesamples/android-ndk)。

所有这些示例都显示了添加的代码结构以及位置；与我们之前遇到的项目结构一样，实际的文件结构不会反映在项目文件资源管理器中，该资源管理器根据文件类型而不是位置来组织文件。

明显的添加是`main/cpp`目录，其中包含源代码，以及 CMake 使用的外部构建文件。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8e2f1e49-266e-490d-89e0-fc3c9abe4844.png)

本地代码结构

一旦你选择了一个套件，系统镜像可以在[developer.android.com/things/preview/download.html](http://developer.android.com/things/preview/download.html)和你的 Things 开发者控制台上找到[partner.android.com/things/console/](http://partner.android.com/things/console/)。

Android Things

# Android Things

实际上，绝对任何设备都可以构成一个 Thing。一个设备甚至不需要有屏幕或任何按钮，只要有 IP 地址并且能够与其他设备通信。甚至可以获得一个带有 IP 地址的牙刷，尽管我对此的好处感到遗憾。

树莓派 3

可以通过一点专业知识和焊接铁来创建自己的开发板，但是像英特尔 Edison 和树莓派这样的低价位开发板，以及来自 Android 的免费系统镜像，使这个过程变得耗时。如果你有一个想法，并且想要快速测试并将其开发成一个成品项目，最好的方法是使用一个经过批准的开发套件，比如树莓派 3，如下图所示：

# 开发套件

一如既往，Android Studio 旨在尽可能地帮助我们，当然，有一个支持库、系统镜像和一个不断增长的工作样本集合来帮助我们。不幸的是，没有简单地模拟 Android Things 的方法，尽管一些功能可以在一些移动 AVD 上模拟，但仍需要一定形式的物理开发套件。

C++并不是每个人的菜，深入讨论超出了本书的范围。从 Android Studio 的角度来看，想要更充分利用 NDK 的人会发现，CMake 与 Gradle 的无缝集成使得调用本地库进行测试和构建应用程序变得非常方便。

对于用户、制造商和开发人员来说，Android 操作系统的美妙之一是它可以运行在各种设备上。起初，这种现象出现在我们的手表、电视机和汽车上。最近，物联网的发展导致需要在许多电子设备上使用复杂的操作系统。这促使谷歌开发了 Android Things。

物联网已经通过引入智能家用电器（如水壶和洗衣机）对消费者产生了影响。除此之外，许多市政当局使用这项技术来管理交通和公用事业的使用。

Android Things 和其他形式的 Android 开发之间最显著的区别可能是硬件。人们很容易认为需要嵌入式电路方面的专业知识，尽管在这个领域有一点知识是有用的，但绝对不是必需的，因为谷歌与英特尔、NXP 和树莓派等 SoC 制造商合作，生产开发套件，让我们能够快速制作和测试原型。

有关可用于 Things 的单板计算机的信息可以在[developer.android.com/things/hardware/developer-kits.html](http://developer.android.com/things/hardware/developer-kits.html)找到。每个板还有外围套件可用，并且可以在同一页上找到。

从开发者的角度来看，物联网非常令人兴奋，SDK 中的 API 的加入打开了几乎无限的新世界。当然，这些 API 已经整合到了 Android Studio 中，使得 Android Thing 的开发像其他 Android 应用程序开发一样简单和有趣。

一旦你有了套件和外围设备，你就可以开始开发你的第一个 Things 应用程序，其基础知识在下一节中概述。

# 创建 Things 项目

Android Things 使用的 API 不包含在标准 SDK 中，因此需要支持库。至少，你需要以下依赖项：

```kt
dependencies {
 ...
 provided 'com.google.android.things:androidthings:0.5-devpreview'
}
```

除了在清单中加入以下条目：

```kt
<application ...>
 <uses-library android:name="com.google.android.things"/>
 ...
</application>
```

大多数 Things 项目将需要更多的东西，这取决于使用了哪些外围设备以及项目是否将使用 Firebase 进行测试。查看提供的示例是了解需要哪些依赖项的好方法；以下片段取自 Things 门铃示例：

```kt
dependencies { provided 'com.google.android.things:androidthings:0.4-devpreview' 
  compile 'com.google.firebase:firebase-core:9.4.0'
  compile 'com.google.firebase:firebase-database:9.4.0'
  compile 'com.google.android.things.contrib:driver-button:0.3'
  compile 'com.google.apis: google-api-services-vision:v1-rev22-1.22.0'
  compile 'com.google.api-client: google-api-client-android:1.22.0' exclude module: 'httpclient'
  compile 'com.google.http-client: google-http-client-gson:1.22.0' exclude module: 'httpclient' }
```

在设置 Android Things 项目时，下一个主要的区别可以在清单文件中看到，添加以下代码中突出显示的 `<intent-filter>` 将使项目在测试和调试时成功运行：

```kt
<manifest  package="com.example.androidthings.doorbell">

  <uses-permission android:name="android.permission.CAMERA" /> 
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="com.google.android.things.permission .MANAGE_INPUT_DRIVERS" />

  <application android:allowBackup="true" android:icon="@android:drawable/sym_def_app_icon" android:label="@string/app_name">
    <uses-library android:name="com.google.android.things" />
    <activity android:name=".DoorbellActivity">

    <intent-filter>
      <action android: name="android.intent.action.MAIN" />
      <category android: name="android.intent.category.LAUNCHER" />
    </intent-filter>

    <intent-filter> 
 <action android: name="android.intent.action.MAIN" />
 <category android: name="android.intent.category.IOT_LAUNCHER" />
 <category android: name="android.intent.category.DEFAULT" />
 </intent-filter>

    </activity>
  </application>
</manifest>
```

这些实际上是设置 Android Things 项目时唯一的区别。其他的区别将更多地基于使用哪些外围设备和传感器。像往常一样，更深入地探索 Things 的最佳方式之一是通过提供的示例。虽然可用的示例不多，但数量正在增加，并且它们都是为了帮助我们学习而编写的。

为 Android Things 开发可能对许多开发者来说似乎令人生畏，但 Android Studio 通过其系统镜像、支持库和代码示例的方式使得任何有好点子的开发者都可以廉价快速地开发、测试和生产这样的产品。

# 总结

在本章中，我们探讨了一些 Android Studio 可以帮助开发者的更加奇特的方式。谷歌在数字世界中的巨大影响力提供了替代技术，比如 Kotlin 语言，并鼓励制造商开发吸引 Android 开发者的技术，使尖端技术可以被具备技能和想法的任何人使用。

Android Studio 不是唯一提供使用不同语言或不同形态因素编码的机会的软件，但 Android Studio 确实使开发者学习新技能变得更简单更容易。

在下一章中，我们将看一下最后的开发阶段之一；测试。这将给我们一个很好的机会来探索 Android Studio 最创新和有用的工具之一：设备监视器和分析器。


# 第八章：测试和分析

如果有一个理由选择 Android Studio 而不是其他 IDE，那很容易可以说是因为它强大的调试和测试工具。这些工具从简单的 Logcat 报告到基于 JUnit 框架的复杂测试机制。除了帮助我们识别代码中的错误的工具之外，Android Studio 还拥有一系列非常智能的性能监控工具，允许开发人员对项目进行微调并最大化其效率。

本章将依次探讨这些过程，从简单的内联调试调用开始，然后转向不同类型的 JUnit 测试，最后看一下如何在各种条件下监视我们应用程序的性能。

在本章中，您将学习如何：

+   配置 Logcat 调试过滤器

+   创建本地单元测试

+   构建插桩测试

+   记录 Espresso 测试

+   测试 UI

+   执行远程测试

+   压力测试应用程序

+   启用高级分析

+   记录方法跟踪

+   记录内存分配

+   检查 Java 堆转储

+   检查网络流量

# Logcat 过滤器

最简单但也最有用的调试技术之一是简单地包含 Logcat 过滤器。这可以用于报告变量值或简单跟踪调用了哪些方法。当跟踪不明显的进程时特别有用，例如对 UI 没有明显影响的服务、广播接收器和回调。

也许最简单的调试工具之一，当我们匆忙时只想检查单个值或事件时非常有用，就是包含一行类似于：

```kt
System.out.println("Something happened here"); 
```

这只是一个临时解决方案，因为输出将被埋在其他 Logcat 文本中。更容易管理的方法是配置 Logcat 过滤器。以下简短的练习演示了如何做到这一点：

1.  开始一个新项目，或打开一个新项目。

1.  选择一个活动或片段，并包括以下字段：

```kt
private static final String DEBUG_TAG = "tag"; 
```

1.  选择您想要检查的方法，并添加一行类似于这里的行：

```kt
Log.d(DEBUG_TAG, "Some method called"); 
```

1.  使用*Alt* + *6*打开 Logcat 工具。

1.  从右上角的下拉菜单中选择编辑过滤器配置，并完成结果对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/63c23fbd-c557-4978-8be9-e7ab5c431338.png)

过滤器配置

1.  运行应用程序。

1.  现在可以使用 Logcat 工具以同样的方式跟踪任何值、活动或事件。

这是迄今为止最不复杂的方式来在代码运行时进行询问，但它有其用途：它可以随时快速应用。这种方法适用于对抗单个错误；一旦我们有了可工作的代码，我们将需要在一些明确定义的条件下进行测试。这就是 Android Studio 基于 JUnit 的测试系统发挥作用的地方。

# JUnit 测试

没有开发项目可以完整，直到它经过彻底和严格的测试，而 Android Studio 直接将 JUnit 测试整合到工作区中。正如其名称所示，该框架允许测试单个代码单元。这些通常是单独的模块，但也可能是单个类或方法。

Android Studio JUnit 测试框架提供了两种不同类型的测试。它们如下：

+   本地单元测试用于在不依赖于 Android 组件或其他代码的隔离环境中测试业务逻辑，尽管可能会模拟一些依赖关系。这些测试在本地 Java 虚拟机上运行，因此比在硬件设备或模拟器上进行测试要快得多。

+   插桩测试用于测试 Android 框架本身的元素，例如我们的 UI 的行为。这些测试生成一个 APK 文件，因此构建速度较慢。

在大多数开发周期中，我们需要同时使用这两种技术，接下来我们将依次看看每种。

对于几乎所有的项目，我们可以预计将花费大约两倍的时间来测试代码的稳定性，而不是测试功能，我们将在下一节中看到这两者。

# 本地单元测试

如果您使用项目向导创建了一个 Android Studio 项目，那么两种测试类型的基本测试用例将会自动创建。向导还将包括必要的 Gradle 依赖项。如果您是以其他方式创建的项目，您将需要手动创建测试目录结构并包含 Gradle 依赖项。这些步骤如下所述：

1.  在您的`module/src`目录中，创建一个新文件夹，与`src/main`旁边叫做`src/test`。

1.  在这个`test`目录中，重新创建`main`目录内的文件夹结构，例如：

```kt
main/java/com/packt/chapterseven 
```

1.  这个目录是您将放置测试类的地方，现在可以从 IDE 的项目资源管理器中访问。

1.  最后，如果尚未包含，将以下依赖项添加到您的`build.gradle`文件中：

```kt
testImplementation 'junit:junit:4.12' 
```

如果您使用向导创建项目，那么它将包括一个示例测试类`ExampleUnitTest.Java`。这个类包含一个用于测试算术的方法：

```kt
public class ExampleUnitTest { 

    @Test 
    public void addition_isCorrect() throws Exception { 
        assertEquals(4, 2 + 2); 
    } 
}  
```

这是一个非常简单的例子，但它仍然是一个很好的方式来初步了解单元测试在这种环境中是如何工作的。最好的方法是使用项目设置向导创建一个项目，或者打开一个以这种方式创建的项目，以便它包含测试类。

尽管它们实际上位于磁盘上，但测试模块可以在 IDE 的项目资源管理器中与常规的 Java 模块一起找到。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b7261c9a-0dbd-4f2b-bb5c-b2324f2cf68e.png)

从 IDE 访问测试

看到这些测试的最简单方法并探索其他测试功能，就是修改`addition_isCorrect()`方法，使其失败。`assertEquals()`方法只是比较两个表达式，并可以设置为失败，如下所示：

```kt
public class ExampleUnitTest { 
    int valueA; 
    int valueB; 
    int valueC; 

    @Test 
    public void addition_isCorrect() throws Exception { 
        valueA = 2; 
        valueB = 2; 
        valueC = 5; 

        assertEquals("failure - A <> B + C", valueA, valueB + ValueC); 
    } 
} 
```

这将产生如下所示的可预测的输出：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/07cda69c-e4ba-4462-bbcf-14e5e586d632.png)

单元测试输出

上面显示的运行工具具有许多有用的功能，可以在工具栏中找到。特别是左侧第三个图标允许我们在进行任何更改时自动重新运行测试。主工具栏允许我们过滤和排序通过和忽略的测试，以及导入和导出结果，可以保存为 HTML、XML 或自定义格式。

单击“单击以查看差异”链接将打开一个非常有用的失败比较表格，当多个测试失败时非常有用。

测试可以像其他代码一样运行，通常只需在主工具栏中点击运行图标，但运行菜单和代码编辑器左侧的运行测试图标包括调试选项和显示类覆盖窗口的选项。这些编辑器图标特别有用，因为它们可以用来运行单独的方法。

提供的示例使用了 JUnit 的`assertEquals()`断言。我们有许多类似的 JUnit 断言和其他可用的结构，完整的文档可以在[junit.org](http://junit.org/junit4/)上找到。

上面的例子是自包含的，并没有告诉我们如何使用这些类来测试我们的应用程序代码。下面的例子演示了如何做到这一点：

1.  在默认包中创建一个 Java 类，其中包含一个函数，就像这里的一个函数：

```kt
public class PriceList { 

    public int CalculateTotal(int item1, int item2) { 

        int total; 
        total = (item1 + item2); 

        return total; 
    } 
} 
```

1.  按照以下方式在`test`包中创建一个新类：

```kt
public class PriceListTest { 

    @Test 
    public void testCalculateTotal(){ 

        PriceList priceList = new PriceList(); 
        int result = priceList.CalculateTotal(199, 250); 

        assertEquals(449,result); 
    } 
} 
```

与第一个例子不同，上面的代码演示了如何在测试代码中整合业务逻辑。

一旦我们有了几个测试，有时有必要控制这些测试运行的顺序，特别是如果我们希望在每次测试运行开始时运行准备代码。这可以通过一系列 JUnit 注释来实现，如下所示：

```kt
@BeforeClass 
@Test(timeout=50) 
public void testSomeMethod() { 
... 
```

前面的配置注解将导致该方法仅运行一次，在调用类中的所有其他方法之前运行，并且在 50 毫秒后失败。`@Before`可以用来导致一个方法在每次其他测试之前执行，还有相应的`@After`和`@AfterClass`注解。

`org.junit`包中还有许多其他断言和其他类，完整的文档可以在以下链接找到：

[junit.sourceforge.net/javadoc/org/junit/package-summary.html#package_description](http://junit.sourceforge.net/javadoc/org/junit/package-summary.html#package_description)

通常，您会希望一起运行相同的一组测试类。与其每次分别运行它们，不如重新创建一组测试并作为一个运行，类似以下代码：

`@RunWith(Suite.class)`

`@SuiteClasses({`

`        someClassTest.class,`

`          someOtherClassTest.class })`

并不总是可能或者希望完全隔离地测试每个单元。通常，我们需要测试一个单元与 Android 和其他 Java 接口和类的交互。这通常是通过创建模拟依赖来实现的。

正如读者所知，有许多种方法可以创建模拟对象和类，从从头开始构建它们的繁琐任务到使用现成的第三方框架。在大多数情况下，这第二个选项更可取，也许唯一的例外是一些完全重新定义 UI 的全屏游戏。否则，对于 Android Studio 用户来说，最简单，也可能是最好的选择是 Mockito。

Mockito 是一个强大的 Java 框架，虽然它很容易集成到 Android Studio 中，但它并不特定于它，许多读者可能已经从其他 IDE 中熟悉它。关于这个主题可以涵盖很多内容，但这超出了本书的范围。当然，Mockito 需要在我们的`build.gradle`文件中声明为依赖项，方法如下：

```kt
testImplementation 'org.mockito:mockito-core:2.8.9' 
```

幸运的是，不需要创建模拟依赖来能够调用 Android API。如果`android.jar`方法的默认返回值足够，那么我们可以通过将以下片段添加到`build.gradle`文件的 Android 部分来指示 Gradle 执行此操作：

```kt
testOptions { 
  unitTests.returnDefaultValues = true 
} 
```

Mockito 提供了结构来模拟我们可能需要测试业务逻辑的大多数 Java 类，但归根结底，我们正在开发一个 Android 应用程序，并且需要在真实设备和模拟器上进行测试。一旦我们确信我们的模型在隔离状态下运行良好，我们需要看看它在现实世界中的表现如何。

# 测试 UI

尽管在这里分开考虑，仪器化测试也可以是单元测试。有许多非 UI Android 类需要我们进行测试，尽管这些可以被模拟，但这可能是一个耗时的过程，特别是当我们知道这些类已经完全实现在我们的设备和模拟器上时。如果我们愿意牺牲模拟测试的快速构建时间，那么我们可能会插入我们的设备并启动我们的模拟器。

开发中难以模拟的一个方面是 UI 模拟和交互，一般来说，当我们想要测试我们的布局与物理手势时。幸运的是，我们有一些非常方便的工具和功能可供使用，帮助测试和优化我们的设计。

# 测试视图

在仪器化 UI 测试的核心是 Android 测试支持库。这包括 JUnit API，UI Automator 和 Espresso 测试框架。在 Android Studio 上设置 Espresso 几乎没有任何难度，因为如果您是通过项目设置向导生成的项目，它会默认作为依赖项包含在内。如果不是，您需要将以下内容添加到您的`build.gradle`文件中：

```kt
androidTestImplementation('com.android.support.test.espresso:espresso-core:2.2.2', { 

    exclude group: 'com.android.support', 
           module: 'support-annotations' 

}) 
```

如果您的测试设备上设置了开发人员动画选项，例如窗口和转换动画比例，您需要在测试期间禁用它们，以使 Espresso 能够顺利工作。

简而言之，Espresso 允许我们执行三项基本任务：

1.  识别和访问视图和其他 UI 元素。

1.  执行活动，如点击和滑动。

1.  验证断言以测试代码。

最好的方法是通过一个简单的例子来看看它是如何工作的。与单元测试类似，插装测试需要放置在正确的磁盘位置才能被 Android Studio 识别，如下所示：

`\SomeApp\app\src\androidTest`

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/1734add4-c0ee-47f9-9762-3fb3686cf7e7.png)

插装测试位置

以下步骤演示了我们如何执行刚才提到的三项任务：

1.  在活动中创建两个视图，如下所示的代码；这里使用主活动：

```kt
<EditText 
    android:id="@+id/editText" 
    . . . 
    /> 

<Button 
    android:id="@+id/button" 
    . . . 
    /> 
```

1.  在`androidTest`目录中创建一个测试类，如下所示：

```kt
@RunWith(AndroidJUnit4.class) 
@LargeTest 
public class InstrumentedTest { 

    private String string; 

    @Rule 
    public ActivityTestRule<MainActivity> testRule = new ActivityTestRule<>( 
            MainActivity.class); 

    @Before 
    public void init() { 
        string = "Some text"; 
    } 

    @Test 
    public void testUi() { 

        onView(withId(R.id.editText)) 
                .perform(typeText(string), 
                        closeSoftKeyboard()); 

        onView(withId(R.id.button)) 
                .perform(click()); 

        onView(withId(R.id.editText)) 
                .check(matches(withText("Some text"))); 
    } 
} 
```

1.  请注意，IDE 将 Espresso 术语标识为斜体：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/63090807-fe26-4bc8-b3f7-9dfd947a268b.png)

斜体的 Espresso 术语

1.  运行测试，可以从编辑器的左边栏或运行菜单中运行。

1.  应用程序将在测试设备上打开，`string`将被输入到编辑框中，按钮将被点击，活动将被完成并关闭。

1.  然后可以在 IDE 中查看测试结果。

在前面的代码中有一两个需要指出的地方，特别是对于新手来说。`ActivityTestRule`用于访问我们活动中的小部件，调用`closeSoftKeyboard()`；后者并不是严格必要的，但是，如果您运行测试，您会看到它确实像人们想象的那样关闭软键盘。

在运行插装测试时，平台会使用一个测试清单，如果您从模板创建了项目或者正在处理一个示例，它将已经包含在内。这将位于磁盘上的以下目录中：`\SomeApplication\app\build\intermediates\manifest\androidTest\debug`

这些测试中使用的几乎所有库都需要导入，尽管代码编辑器擅长发现缺少的导入，但也了解需要哪些库是很好的。以下是前面测试所需的库列表：

```kt
android.support.test.filters.LargeTest; 
android.support.test.rule.ActivityTestRule; 
android.support.test.runner.AndroidJUnit4; 

org.junit.Before; 
org.junit.Rule; 
org.junit.Test; 
org.junit.runner.RunWith; 

android.support.test.espresso.Espresso.onView; 
android.support.test.espresso.action.ViewActions.click; 
android.support.test.espresso 
        .action.ViewActions.closeSoftKeyboard; 
android.support.test.espresso.action.ViewActions.typeText; 
android.support.test.espresso.assertion.ViewAssertions.matches; 
android.support.test.espresso.matcher.ViewMatchers.withId; 
android.support.test.espresso.matcher.ViewMatchers.withText;
```

可以通过在`build.gradle`文件中包含以下依赖项来在 JUnit 测试中包含 Hamcrest 断言匹配器：

`Implementation 'org.hamcrest:hamcrest-library:1.3'`

Espresso 提供了许多其他操作，例如滚动和清除文本，以及输入和点击。Espresso 的详细文档可以在以下链接找到：

[google.github.io/android-testing-support-library/docs/](http://google.github.io/android-testing-support-library/docs/)

# 测试列表和数据

前面的示例使用`onView()`来识别我们想要使用其 ID 进行测试的视图，对于我们已经命名的组件来说这是可以的；然而，列表中的项目不能如此明确地识别，因此我们需要另一种方法。在处理列表时，例如可回收视图和下拉列表框时，Espresso 提供了`onData()`方法来识别列表项。

要查看此操作，请在应用程序活动中添加一个下拉列表框，如下所示：

```kt
public class SomeActivity extends AppCompatActivity { 

    ArrayList<String> levelList = new ArrayList<String>(); 
    TextView textView; 

    @Override 
    protected void onCreate(Bundle savedInstanceState) { 

        . . . 

        Spinner spinner = (Spinner) findViewById(R.id.spinner); 

        levelList.add("Easy"); 
        levelList.add("Medium"); 
        levelList.add("Hard"); 
        levelList.add("Impossible"); 

        ArrayAdapter<String> adapter = new ArrayAdapter 
                <String> 
                (MainActivity.this, 
                        android.R.layout.simple_spinner_item, 
                        levelList); 
        spinner.setAdapter(adapter); 

        spinner.setOnItemSelectedListener 
                (new AdapterView.OnItemSelectedListener() { 

            @Override 
            public void onItemSelected(AdapterView<?> 
                    parent, View view, int position, long id) { 

                Snackbar.make(view, "You selected the" 
                        + levelList.get(position) 
                        + " level ", Snackbar.LENGTH_LONG) 
                        .setAction("Action", null) 
                        .show(); 
            } 

            @Override 
            public void onNothingSelected(AdapterView<?> parent) { 

                Snackbar.make(view, "Nothing selected" 
                        ,Snackbar.LENGTH_LONG) 
                        .setAction("Action", null).show(); 

            } 
        }); 
    } 
```

现在我们可以使用`onData()`编写一个测试来询问小部件：

```kt
@RunWith(AndroidJUnit4.class) 
@LargeTest 
public class InstrumentedTest { 

    private String string; 

    @Rule 
    public ActivityTestRule<MainActivity> 
            testRule = new ActivityTestRule<>(MainActivity.class); 

    @Before 
    public void init() { 

        string = "Medium"; 
    } 

    @Test 
    public void testSpinner() { 

        onView(withId(R.id.spinner)) 
                .perform(click()); 

        onData(allOf(is(instanceOf(String.class)), is(string))) 
                .perform(click()); 

        onView(withId(R.id.spinner)) 
                .check(matches(withText 
                (containsString("Medium")))); 
    } 
} 
```

即使您已将 Hamcrest 作为 Gradle 依赖项包含在内，但是工作室的快速修复功能不会启动，测试代码中需要包含以下导入：

`import static org.hamcrest.Matchers.allOf;` `import static org.hamcrest.Matchers.containsString;`

`import static org.hamcrest.Matchers.instanceOf;` `import static org.hamcrest.Matchers.is;`

# 记录测试

在前面的部分中，我们看到 Android Studio 为测试我们的代码提供了一套全面的工具，但编写这些测试是耗时的，除了最琐碎的项目之外，还需要许多单独的测试。幸运的是，Android Studio 提供了一种半自动化的方式来构建测试，使用我们自己的 UI 交互来创建、识别和执行测试的代码元素。

以下简单的练习展示了如何通过手动编写之前的测试来执行测试：

1.  打开在上一个练习中创建的下拉菜单项目，或者创建一个新的项目。

1.  从“运行”菜单中选择“记录 Espresso 测试”。

1.  从下拉菜单中选择一个项目。这将在“记录您的测试”对话框中反映出来。

1.  点击“添加断言”按钮。

1.  点击下拉菜单，完成对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6de46e02-8ab1-43af-8cff-d7766132b123.png)

记录您的测试对话框

1.  保存并运行测试。

如您所见，IDE 已经接受了我们的屏幕手势并将它们转换为代码：

```kt
@Test 
public void someTest() { 
    ViewInteraction appCompatSpinner = onView( 
      allOf(withId(R.id.spinner), 
        childAtPosition( 
          childAtPosition( 
            withClassName(is("android.support.design.widget.CoordinatorLayout")), 
            1), 
          0), 
        isDisplayed())); 
    appCompatSpinner.perform(click()); 

    DataInteraction appCompatTextView = onData(anything()) 
      .inAdapterView(childAtPosition( 
        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")), 
           0)) 
      .atPosition(1); 
    appCompatTextView.perform(click()); 

    ViewInteraction textView = onView( 
      allOf(withId(android.R.id.text1), withText("medium"), 
        childAtPosition( 
          allOf(withId(R.id.spinner), 
            childAtPosition( 
              IsInstanceOf.<View>instanceOf(android.view.ViewGroup.class), 
            0)), 
         0), 
      isDisplayed())); 

    textView.check(matches(withText("medium"))); 
} 
```

这段代码可能不够高效或用户友好，但节省的时间可能是值得的，而且归根结底，所有的测试都是临时的，一旦我们对代码满意，就会被取消。

读者可能已经注意到，当从“选择部署目标”对话框运行测试时，还有一个“云测试”选项卡。这个功能允许我们直接从 IDE 访问 Firebase 测试实验室。 

# 远程测试

在为 Android 应用程序进行一般发布时，希望尽可能在许多不同的设备配置和平台版本上进行测试。在大量真实设备上进行测试是不切实际的，虚拟设备似乎是唯一的选择。幸运的是，Firebase 提供了一个基于云的测试实验室，允许我们在各种真实设备和模拟器上测试我们的应用程序。

Firebase 是一个功能强大、完整的基于云的应用开发套件，具有许多有用的功能，如文件托管和实时崩溃报告。在本章中，我们将专注于 Firebase 产品之一，即测试实验室。

IDE 中有 Firebase 助手，这是开始的最简单方式，可以在“工具”菜单中找到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c576bfbe-3ddf-457e-bdf3-136e6e2dd4b7.png)

Firebase 助手

在将 Android Studio 连接到 Firebase 之前，请使用您的 Google 帐户登录[`firebase.google.com/.`](https://firebase.google.com/)

点击“了解更多”链接将允许您直接从 IDE 连接到 Firebase。这将带您完成一个快速向导/教程，最终点击“连接到 Firebase”按钮。

现在，我们可以通过从“运行”|“编辑配置...”菜单中打开“运行/调试配置...”对话框来配置我们的基于云的测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/7075bf1c-e635-40d4-8382-0c72eb078e45.png)

测试配置

这些测试现在可以像任何其他项目一样启动，使用运行图标或菜单项，您将从测试输出中看到一个链接，可以查看结果的 HTML 版本，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a0d327e3-b6f8-4344-946f-4d467aa7cfe3.png)

Firebase 输出

值得注意的是，尽管许多人更喜欢它，但 Firebase 并不是测试 Android 应用程序的唯一云设备，感兴趣的读者应该查找**亚马逊网络服务**（**AWS**）设备农场、Xamarin 测试云、Sauce Labs、Perfecto 等其他设备。

前面概述的方法演示了我们可以应用于我们的代码的各种测试技术，以及 Android Studio 可以加快和自动化这一重要但常常令人沮丧的开发方面。在转向更有趣的主题之前，还有一种测试需要一点解释，尽管不严格属于 IDE 的一部分，但应用程序 Exerciser Monkey 仍然是一个非常有用的小工具。

# 压力测试

Android 应用程序 Exerciser Monkey 是一个方便的命令行应用程序压力测试工具。它通过执行（或注入）一系列随机输入操作，如点击、输入和滑动来工作。这就像把你的应用交给一个孩子，看看他们能不能把它弄坏。所有开发人员都明白，用户可以，也会尝试用他们的应用做出绝对荒谬和不可预测的事情，而除了坐在那里尝试复制每种可能的手势组合之外，Exerciser Monkey 是我们能够预测不可预测的最接近的方法。

Monkey 非常简单易行：只需在`sdk/platform-tools`目录中打开命令提示符，然后输入以下命令：

```kt
adb shell Monkey -p com.your.package -v 5000
```

在这里 5000 是您想要执行的随机操作的数量，输出将类似于以下片段：

```kt
. . . 
:Sending Touch (ACTION_DOWN): 0:(72.0,1072.0) 
:Sending Touch (ACTION_UP): 0:(70.79976,1060.0197) 
:Sending Touch (ACTION_DOWN): 0:(270.0,1237.0) 
:Sending Touch (ACTION_UP): 0:(284.45987,1237.01) 
:Sending Touch (ACTION_DOWN): 0:(294.0,681.0) 
:Sending Touch (ACTION_UP): 0:(301.62982,588.92365) 
:Sending Trackball (ACTION_MOVE): 0:(-3.0,-1.0) 
. . . 
```

可以在[`developer.android.com/studio/test/monkey.html`](https://developer.android.com/studio/test/monkey.html)找到包含所有 Monkey 命令行选项的表格。

测试我们的业务逻辑，它如何与系统的其余部分结合，以及在各种条件下在各种设备上的行为，是任何开发生命周期的重要部分。然而，一旦我们确信我们的代码表现如我们所愿，我们就可以继续审查它执行这些任务的效率。我们需要问问我们的工作有多有效，它是否包含内存或资源瓶颈，或者是否不必要地耗尽电池。为了做到这一点，我们需要求助于 Android Profiler。

# 性能监控

我们可能已经消除了代码中的所有问题，但仍然有很多微调要做，而 Android Studio 最具创新性的功能之一——Android Profiler，正是让我们能够做到这一点。

Android Profiler 不适用于使用 C++开发的模块。

Android Profiler 是在 Android Studio 3.0 中引入的，取代了以前的 Android Monitor。在最基本的级别上，它监视实时 CPU、内存和网络使用情况。这使我们能够在不同条件和配置下测试我们的应用，并改善其性能。它可以从 View | Tool Windows 菜单或工具窗口栏中访问。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6db1efeb-99e2-4faf-b033-5311c8a466c9.png)

性能监控

这种基本监控与以前版本的 Android Monitor 没有什么不同。这是因为诸如方法跟踪和内存分配检查之类的功能对构建时间有负面影响。可以通过 Run/Debug Configurations 对话框轻松启用高级分析，该对话框可以通过 Run | Edit Configurations...菜单找到。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a45e9025-0f2a-4a30-b747-5f12f263cac0.png)

高级性能监控

分析器现在显示特定事件信息，以及我们将在下面探讨的其他一系列功能。

# CPU 分析

Android Profiler 提供的检查比其前身 Android Monitor 更深入，允许详细检查线程活动、UI 事件和单个方法的性能。CPU 分析器还允许我们记录方法跟踪，以及一些复杂的检查工具，帮助我们使程序更有效率。

通过单击 CPU 时间轴中的任何位置，可以看到 CPU 高级分析功能。然后，它将在显示的底部显示线程活动时间轴。

像这样实时观察我们应用的行为可以非常有启发性，但是，为了最好地看到发生了什么，我们需要记录一段活动时间。这样，我们就可以检查单个线程。

以下简短的练习演示了如何记录这样的方法跟踪：

1.  单击 CPU 时间线中的任何位置以打开高级 CPU 分析器。

1.  决定要记录哪些操作。

1.  此窗格顶部有两个新的下拉菜单。选择插装而不是采样，并保持其他设置不变。

1.  如果您计划进行长时间的记录，请缩小视图。

1.  单击记录图标并执行您计划的操作。

1.  再次单击相同的图标以停止。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/4f086260-e4c6-4df1-b954-9d8a8917fa87.png)

记录的 CPU 方法跟踪

记录样本两侧的耳朵可以拖动以调整记录的长度。

正如练习所示，有两种记录方式，即插装和采样；它们的区别如下：

+   插装记录会精确记录方法调用的时间。

+   采样记录会定期对内存使用情况进行采样。

正如您将看到的，有四个选项卡可以表示这些数据，位于工具窗口底部。调用图和火焰图以图形方式显示方法层次结构，而自上而下和自下而上则将此信息显示为列表。

单击这些图表中的任何方法将打开该方法的源代码。

能够详细检查程序流程非常有帮助，可以节省大量不必要的调试，但我们需要考虑的不仅仅是处理器时间；我们还需要密切关注我们的应用程序消耗了多少内存。

# 内存分析器

充分了解我们的应用对设备 CPU 的影响只是一个考虑因素。作为开发人员，我们必须在不知道目标设备的内存能力的情况下创建应用，并且，此外，我们无法知道这些设备在我们的应用运行时正在使用内存的其他用途。

为了帮助我们规划内存使用并避免泄漏，Android Studio 配备了强大的内存分析器。这使我们能够查看 Java 堆并记录内存分配。只要启用了高级分析功能，高级内存分析器就可以通过单击实时时间线上的任何位置以与处理器分析器相同的方式打开。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/4f1c6da6-be74-40e2-90cb-a5747490dcbe.png)

高级内存分析器

如前图所示，分析器还显示自动垃圾收集。这样的清理也可以通过分析器工具栏中的垃圾桶图标手动执行。这还包括用于记录内存分配和捕获 Java 堆转储（下载图标）的按钮。

获取内存转储就像单击图标并等待一会儿收集数据一样简单。堆转储显示了在转储堆时正在使用的对象，并且是识别内存泄漏的好方法。探索堆转储的最佳时间是在进行了长时间 UI 测试后，查找应该已经被丢弃但仍占用内存的对象。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/02b77b9c-d9ca-4f6a-99c7-d0ac3917862e.png)

Java 堆转储

单击转储列表中的类将在编辑器中打开相应的源代码。

这样的内存转储非常有用，可以观察我们的对象消耗了多少内存，但它们并没有告诉我们他们如何使用这些内存。要查看这一点，我们需要记录内存分配。这是通过与 CPU 记录相同的方式完成的，即通过单击记录图标。这个方便的内存检查工具需要更多解释，引导我们到第三个和最后一个分析工具，网络分析。

# 网络分析器

这个分析器和前两个操作的方式没有太大的区别。与记录网络活动不同，只需单击并拖动到您感兴趣的时间线区域。然后在下面的窗格中列出涉及的文件，并在选择它们时提供详细信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/5bd57470-bbf1-401e-a161-bb2b5510b43d.png)

高级网络分析器

高级网络分析器提供了一种很好的方式来识别低效的网络使用。在需要网络控制器经常打开和关闭无线电以下载小文件的情况下，最好避免这种情况，而是优先下载多个小文件。

网络分析器以及其他两个分析器都是节省时间的工具的绝佳示例，这使得 Android Studio 成为开发移动应用程序的不错选择。对应用程序进行彻底测试和微调往往可以决定一个平庸的应用程序和一个成功的应用程序之间的差异。

# 总结

在本章中，我们看了一下测试和分析我们的应用程序的过程。我们不仅了解了如何利用 JUnit 集成来测试自己的业务逻辑的完整性，还了解了如何整合诸如 Mockito 和 Espresso 之类的工具来测试平台本身，以及诸如 Firebase 之类的资源来在更广泛的设备范围内进行测试。

除了测试我们的代码和用户界面之外，我们还需要一种测试我们的应用程序，硬件性能以及 CPU，内存或网络使用是否存在问题的方法。这就是 Android Studio 内置的分析器派上用场的地方，它允许我们详细检查和记录我们应用程序的性能。

我们的应用程序现在运行顺畅，并经过性能调整，我们可以看看开发的最后阶段，构建，打包和部署。Android Studio 允许我们使用 Gradle 构建系统简单地创建签名 APK，包括不同风味的 APK，并简化签名和安全性。
