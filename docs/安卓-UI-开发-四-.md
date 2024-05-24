# 安卓 UI 开发（四）

> 原文：[`zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042`](https://zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：样式化安卓应用

*到目前为止，我们一直在使用标准的 Android 主题和样式。从一致性的角度来看，这是一个非常好的事情，因为应用将与设备的主题（如果有的话）很好地融合。然而，有时候你需要能够定义自己的样式。这种样式可能只适用于单个小部件，也可能适用于整个应用。在这些情况下，你需要了解 Android 为你提供了哪些工具，以便决定如何最佳地解决问题。*

样式设计不仅仅是让应用看起来好看。另外，你认为好看的，别人可能不喜欢。这也是关于让应用对用户更有用的问题。这可能涉及到确保无论用户选择哪种语言，应用看起来都是正确的。可能涉及到为某些选定的小部件添加额外的颜色，或者简单地实现某些关键屏幕的横屏布局。

在上一章中，我们探讨了在设计应用某些屏幕时可以做出的整体选择。该章节还介绍了使用`WebView`作为内容和窗口小部件容器的想法。使用`WebView`的一个优点是你可以使用 CSS。正如任何 Web 开发者都会告诉你的，使用 CSS 可以使高级样式设计变得非常容易。然而，Android 也内置了一系列样式工具，能够实现许多与 CSS 相同的效果，并且在某些情况下能做得更多。

让屏幕上的单个按钮看起来与众不同，使其与其他所有小部件区分开来。这有助于引起注意，使其与屏幕上的其他任何东西不同，它有特殊的作用。你可能还希望在两组小部件之间绘制一条线，以告知用户它们之间存在逻辑上的分隔。就像尝试理解别人的源代码一样，掌握一个新应用就是理解别人的逻辑。正确地样式化你的应用可以大大帮助用户理解你在构建应用时的思路，同时为他们提供关于预期操作的提示。如果你需要提供如何使用应用的说明，那么你在设计和样式化应用方面的努力就失败了。

在本章中，我们将探讨 Android 如何允许你为其提供的小部件设置样式，以及如何采用你自己的样式和主题。我们还将通过示例来展示自定义样式如何使用户更容易使用应用。我们将涵盖如下主题：

+   定义样式资源

+   可以用于样式设计的不同类型的图形资源

+   创建和使用九宫格图片

+   在运行时处理设备配置的变化

+   定义可跨不同设备和屏幕移植的样式

# 使用样式资源

处理 Android 样式时的首要切入点是了解样式值是如何工作的。应用程序能够定义任意数量的样式，就像定义字符串和字符串数组资源一样。样式资源用于为某些用户界面元素定义一系列默认值，这与 CSS 规则定义样式属性的方式非常相似。主要区别在于，在 Android 中，样式可以覆盖为给定小部件类定义的任何 XML 属性。

下表快速比较了 Android 样式资源和 CSS 样式表。它们有许多共同特征，但行为却大相径庭。

| Android 样式资源 | CSS 样式表 |
| --- | --- |
| 可应用于任何 XML 属性 | 有一个目的明确的属性集，它们可以定义或更改 |
| 可以从父样式继承 | 按定义顺序级联形成复杂样式 |
| 必须明确应用于`View`、`Activity`或`Application` | 通过选择器与文档元素匹配 |
| 以普通 XML 定义 | 使用专用语法定义 |

Android 样式的级联方式与 CSS 规则类似。然而，这种级联的定义更多地归功于 Java 类层次结构。每个样式都可以声明一个父样式，从中继承参数。一旦继承，这些参数可能会被新样式选择性地覆盖。拥有一个父样式总是一个好主意，因为设备制造商可能已经修改了默认值，这样你就可以在创建自己的新样式的同时，与用户设备上安装的第一方软件保持一致。

样式声明不能简单地覆盖所有可用的`TextView`对象的样式。相反，你必须要在小部件声明中为特定小部件导入样式，或者在清单文件中引用样式作为主题，以应用于单个`Activity`或整个应用程序。首先，我们将重点放在构建样式并将其应用于单个小部件上。

样式与尺寸、字符串和字符串数组一样，都是值资源。创建样式元素时，可以将其放在`res/values`目录下的任何 XML 文件中（尽管最好是将资源分开，并将样式放在`styles.xml`文件中）。与`values`目录中的所有 XML 资源一样，根元素应为`<resources>`，之后你会列出你的`<style>`元素。以下是一个简单的样式，可用于将任何`TextView`设置为标题：

```kt
<resources>
    <style name="TitleStyle" parent="@android:style/TextAppearance">
        <item name="android:textSize">25dip</item>
        <item name="android:textColor">#ffffffff</item>
        <item name="android:textStyle">bold</item>
        <item name="android:gravity">center</item>
    </style>
</resources>
```

上面的`<style>`元素中的`name`属性是必填项，而`parent`属性可选，它决定了使用哪个样式作为默认项（在这种情况下，是`TextView`对象的默认外观）。以下代码片段声明了一个使用我们上面声明的`TitleStyle`作为其样式的`TextView`：

```kt
<TextView
    style="@style/TitleStyle"
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"
    android:text="Header"/>
```

注意在前一个例子中缺少了`android`命名空间前缀。实际上，在编译时，当资源被转换成二进制数据以便打包时，应用样式是有效的。当应用额外的属性时，任何在`<style>`元素上声明但应用样式的部件上不可用的项都会被忽略。理论上，这允许你创建更抽象的样式，并将它们应用于许多不同的部件。

应用了`TitleStyle`的`TextView`将如下渲染：

![使用样式资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_01.jpg)

### 提示

**谁覆盖了谁？**

当对部件、活动或应用应用样式时，了解覆盖的顺序很重要。每个样式都会覆盖其父样式（如果有）的样式信息，同时每个部件将覆盖应用在它上面的任何样式信息。这意味着虽然你可以将`android:text`样式项应用于`TextView`对象，但这通常并不十分有用，因为`TextView`上的任何`android:text`属性都会覆盖样式中指定的值。

# 使用形状资源

能够改变部件中字体的大小和颜色当然很好，但如何从根本上改变该部件的渲染方式呢？我们已经使用过一些 XML 可绘制对象，但还可以用它们做更多的事情。

迄今为止，使用 XML 可绘制结构的工作仅限于为设计有图像的部件放置默认图片。然而，在 Android 中所有部件都被设计为可以拥有图像。`View`类的`background`属性允许你传入任何`drawable`资源，结合样式资源。这成为了一个非常强大的工具。当在 Java 代码中加载形状资源时，它会被返回为一个`Drawable`对象。

可供你使用的形状在`android.graphics.drawable.shapes`包中，除了`Shape`类，这是一个抽象类，该包中的其他类都继承自它。你通过在`res/drawable`目录中的 XML 文件引用这些类。然而，与布局 XML 资源不同，形状的使用更为有限：

+   你不能直接访问类的属性

+   你每个形状文件只能创建一个单一形状

+   你不能绘制任意的路径（即对角线或贝塞尔曲线）

尽管有这些限制，形状非常有用且重要，因为：

+   它们会缩放到所附加部件的尺寸

+   这使得它们非常适合创建边框和/或背景结构

+   它们还区分了形状的外框和填充

## 形状的行为

你可以定义的每个形状结构与其他形状略微不同，不仅在渲染方式上，而且在于哪些属性适用于它。由于形状资源的复杂性有限，它们的使用也相对有限。

### 渲染线条

在 Android 中，线条形状始终是居中于小部件内部的直线。之前我们在记忆游戏中将线条形状用作占位图像。然而，线条形状更常见的用法是作为垂直分隔符。线条形状在与`ListView`一起使用时很常见。线条形状不支持渐变填充，因此它总是实心颜色（默认为黑色）。但是，线条形状允许使用`stroke`元素中的所有属性。

一个简单的白色线条可以在几行代码中定义，通常可以用作`ListView`或类似结构中的分隔符。以下是一个线条定义的代码片段：

```kt
<shape 
       android:shape="line">

    <stroke android:width="1sp" android:color="#ffffffff"/>
</shape>
```

# 动手操作——绘制断线

Android 中定义的所有形状都允许你使用`<stroke>`元素来定义点线或虚线结构，但它在线元素上表现得最为出色。如果我们增加线条宽度并定义一个与间隔大小两倍的虚线模式，我们得到的线条看起来就像打印页面上的一条“切割”或“撕裂”线。这是在用户界面上制作更硬分隔线的好方法。

1.  在`res/drawable`目录下创建一个新的形状资源 XML 文件，命名为`line.xml`，并在编辑器或 IDE 中打开这个文件。

1.  将文件的根元素声明为`line shape`：

    ```kt
    <shape 
           android:shape="line">
    ```

1.  声明一个新的笔画元素，为新线条设置`width`为`3sp`，颜色为白色，`dashGap`为`5sp`，以及`dashWidth`为`10sp`：

    ```kt
        <stroke android:width="3sp"
                android:color="#ffffffff"
                android:dashGap="5sp"
                android:dashWidth="10sp" />
    ```

1.  结束形状声明：

    ```kt
    </shape>
    ```

## *刚才发生了什么？*

你刚才创建的`shape`资源将显示一个虚线。线中的虚线间距正好是虚线长度的一半。大小是相对于用户首选字体大小设置的，因此虚线会根据用户偏好增大或缩小。

以下是此线条在默认模拟器设置下运行的屏幕截图：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_05.jpg)

## 渲染矩形

矩形是使用最广泛的形状资源，因为`View`对象在屏幕上占据一个矩形空间（即使它们没有使用该空间的所有像素）。矩形形状包括拥有圆角的能力，每个角可以选择性地有不同的半径。

没有额外的样式信息，基本的矩形声明将渲染一个没有可见轮廓的填充黑色方块。然而，矩形更适合创建轮廓，可以用来单独吸引一个小部件的注意，或将一组小部件从屏幕上的其他所有小部件中隔离开来。一个简单的白色矩形边框可以通过将以下代码片段复制到名为`res/drawable/border.xml`的文件中构建：

```kt
<shape 
       android:shape="rectangle">

    <stroke android:width="2dip" android:color="#ffffffff" />
    <padding android:top="8dip"
             android:left="8dip"
             android:bottom="8dip"
             android:right="8dip" />

</shape>
```

这个形状中的填充元素将导致任何使用它的`View`对象将其填充大小增加`8dip`。这将阻止小部件的内容与形状资源渲染的边框相交。

# 动手时间——创建圆角边框

矩形形状也可能对其角进行圆滑处理，以形成一个圆角矩形。圆角矩形对于设置按钮样式或创建更干净的边框非常有用。

1.  在`res/drawable`目录中创建一个名为`rounded_border.xml`的新形状资源 XML 文件，并在编辑器或 IDE 中打开此文件。

1.  将文件的根元素声明为`矩形形状`：

    ```kt
    <shape 
           android:shape="rectangle">
    ```

1.  将矩形描边设置为`2dip`宽，颜色为白色：

    ```kt
    <stroke android:width="2dip" android:color="#ffffffff" />
    ```

1.  使用`8dip`的空白空间填充矩形：

    ```kt
    <padding android:top="8dip"
                    android:left="8dip"
                    android:bottom="8dip"
                    android:right="8dip" />
    ```

1.  将角落曲线半径设置为`4dip`：

    ```kt
    <corners android:radius="4dip"/>
    ```

1.  关闭形状声明：

    ```kt
    </shape>
    ```

## *刚才发生了什么？*

要将你刚刚创建的圆角边框应用于`View`对象，你有几种不同的选项，最简单的是直接作为背景应用。为此，你可以像引用 drawable 目录中的任何其他图像文件一样引用该形状。之前，我们声明了一个`TitleStyle`并将其应用于包含单词`Header`的`TextView`。如果你将新的`rounded_border`应用于这个`TextView`，布局资源中的`TextView`声明可能看起来更像这样：

```kt
<TextView
        style="@style/TitleStyle"
 android:background="@drawable/rounded_border"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"
        android:text="Header"/>
```

另外，你也可以将此边框应用于`TitleStyle`，这样就会将新边框应用于分配了`TitleStyle`的每个小部件，这对于标题和标题小部件来说非常合适：

```kt
<style name="TitleStyle" parent="@android:style/TextAppearance">
    <item name="android:background">@drawable/rounded_border</item>
    <item name="android:textSize">25dip</item>
    <item name="android:textColor">#ffffffff</item>
    <item name="android:textStyle">bold</item>
    <item name="android:gravity">center</item>
</style>
```

这两种方法都会导致新小部件的渲染完全相同。实现的决定实际上取决于你试图达到的目标。样式是保持用于相同目的的不同小部件之间共性的最佳方式。

在`TextView`上使用上述样式将得到一个看起来很不错的标题小部件，如下所示：

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_02.jpg)

## 渲染椭圆

椭圆形正如其名所示——一个椭圆。椭圆形的使用比矩形更为受限，除非在其上绘制的组件最好由圆形或椭圆形边框，例如一个模拟时钟。也就是说，椭圆形，或者说圆形，在用户界面中作为图像使用非常有效。一个完美的例子就是通知用户他们是否连接到互联网，或者一个组件是否有效。出于这样的目的使用椭圆形与使用位图是相同的。然而，椭圆形可以根据用户的偏好进行缩放，而不会损失任何质量，而使用位图，你需要多个不同大小的位图图像来实现类似的效果（即便如此，一些位图可能还需要缩放）。

如果我们想要一个椭圆形来表示一个无效的组件（例如，当用户在选择密码时显示两个密码输入不匹配），那么最好是将椭圆形涂成红色。在以下代码片段中，我们以 XML 格式声明了一个带有灰色边框和红色填充的椭圆形：

```kt
<shape 
       android:shape="oval">

    <solid android:color="#ffff0000"/>
    <stroke android:width="1sp" android:color="#ffaaaaaa"/>
</shape>
```

在前面的例子中，我们使用 `<solid>` 元素以纯红色填充椭圆形，同时使用 `<stroke>` 元素为其围绕一个细的灰色轮廓。还要注意 `shape` 元素上没有尺寸设置。如之前所述，它们的尺寸是从它们被放置的宽度中继承的，可以作为背景，或者在 `ImageView` 的情况下，作为组件的内容。如果你想要将这个椭圆形放入 `ImageView` 中，你会在 `src` 属性中指定它，如下所示：

```kt
<ImageView
        android:src="img/oval"
        android:layout_width="8dip"
        android:layout_height="8dip"/>
```

之前的代码对于作为一个组件旁边的验证图标来说大小正合适，而将图标放大或缩小就像改变 `ImageView` 的宽度和高度一样简单。如果你使用 `wrap_content` 作为 `ImageView` 的大小，它将被设置为零像素乘零像素，实际上会从屏幕上消失。

下面是同一个椭圆形四种不同大小的截图，每一个都是前一个的两倍大小（从左边的 8x8 dip 开始）：

![渲染椭圆形](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_03.jpg)

# 动手实践——给椭圆形应用渐变

之前的截图显示，虽然椭圆形看起来还可以，但当它被组成默认安卓工具包的渐变绘制组件包围时，它不会非常吸引人。为了让这个小椭圆形更好地融入，它需要看起来更像一个球，这需要应用一个简单的径向渐变。

1.  在 `res`/`drawable` 目录中创建一个新的形状资源 XML 文件，命名为 `ball.xml`，并在编辑器或 IDE 中打开这个文件。

1.  将文件的根元素声明为 `oval`：

    ```kt
    <shape 
           android:shape="oval">
    ```

1.  与其声明一个 `solid` 颜色作为填充，不如声明一个从浅灰色开始到红色结束的 `gradient` 填充：

    ```kt
    <gradient android:type="radial"
                  android:centerX="0.5"
                  android:centerY="0.25"
                  android:startColor="#ffff9999"
                  android:endColor="#ffff0000"
                  android:gradientRadius="8" />
    ```

1.  在 `stroke` 元素中定义椭圆形的细浅灰色轮廓：

    ```kt
        <stroke android:width="1sp" android:color="#ffaaaaaa"/>
    ```

1.  结束形状声明：

    ```kt
    </shape>
    ```

## *刚才发生了什么？*

不幸的是，径向渐变的受影响半径不会随图像的其他部分一起缩放，当你将图像放大到较大尺寸时，渐变区域会变得非常小。在这种情况下，效果就是最小的图像看起来很棒，而较大的版本看起来则很糟糕。在撰写本书时，还没有直接的方法来解决这个限制。相反，如果你想要使用径向渐变，需要将椭圆形的大小与`ImageView`的大小绑定起来。

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_04.jpg)

## 渲染环

`ring`形状在渲染上也是圆形的，但它与椭圆形形状的目的非常不同。虽然椭圆形形状的内容区域是轮廓空间内的所有内容，但环形状的内容区域是一个圆圈。

下图说明了两种形状之间的逻辑差异：

![渲染环](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_09_06.jpg)

`ring`形状也有两个轮廓，一个在外部，另一个在内部（如前图所示）。将这一点与填充环内容区域的能力结合起来，你就有了用于进度旋转器（默认的 Android 不确定进度旋转器就是用环构建的）的完美形状。

# 动手操作——渲染一个旋转环

默认情况下，形状会假设它作为`LevelListDrawable`的一部分被使用，除非你禁用这个行为，否则可能不会出现。你通过在形状元素上指定`useLevel`属性为`false`来实现这一点。如果你不禁用这个功能，环可能无法正确渲染，或者根本不会渲染。

1.  在`res/drawable`目录中创建一个新的形状资源 XML 文件，命名为`spinner.xml`，并在编辑器或 IDE 中打开这个文件。

1.  将文件的根元素作为`ring shape`开始：

    ```kt
    <shape 
           android:shape="ring"
    ```

1.  `ring`形状需要在`shape`声明中设置其相对厚度：

    ```kt
           android:innerRadiusRatio="3.2"
           android:thicknessRatio="5.333"
    ```

1.  通过关闭`useLevel`功能来完成`shape`声明：

    ```kt
           android:useLevel="false">
    ```

1.  声明一个在椭圆形中心居中的`sweep`渐变：

    ```kt
        <gradient android:type="sweep"
                  android:useLevel="false"
                  android:startColor="#ffaaffff"
                  android:centerColor="#ff0000ff"
                  android:centerY="0.50"
                  android:endColor="#ff0000ff"/>
    ```

1.  用细白边框勾勒出`ring`：

    ```kt
        <stroke android:width="1sp" android:color="#ffffffff"/>
    ```

1.  结束`shape`声明：

    ```kt
    </shape>
    ```

## *刚才发生了什么*

扫描渐变是径向渐变的另一种形式。它不是从图像中心向外扩展，而是像时钟的指针一样在圆圈中扫描。

左侧的图像是一个用`sweep`渐变填充的矩形；而右侧的图像是`ring`形状。如你所见，这两个效果非常不同。右侧的图像基于 Android 1.6 用于不确定旋转指示器的图像。

![刚才发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_07b.jpg)

## 定义图层

到目前为止，我们仅将形状定义为单一元素的图像。可以将这些形状组合成更复杂的图像。这些图像以图层的形式组合在一起，这是一种常用的图形结构。在 Android 中，这是通过`layer-list`结构完成的。`layer-list`不是一种形状类型，但它是一个`Drawable`结构，这意味着它可以替代普通的位图图像。

分层图像资源不仅限于与我们前面讨论过的形状等矢量`Drawable`结构一起使用。分层的`Drawable`对象也可能包括一些位图图像图层，或任何其他可以定义的`Drawable`类型。

对于`layer-list`中的每一层，你需要定义一个`<item>`元素。`item`元素用于声明可选的元信息，如图层的 ID（这可以在你的 Java 代码中用于检索该图层的`Drawable`对象）。你还可以在`item`元素中声明图层的位置偏移或内边距。虽然你可以将图层作为外部的`Drawable`资源引用，但你也可以在`<item>`元素内内联`Drawable`对象，从而允许你在单个文件中组合各种不同的`Drawable`结构。

### 提示

**调整你的图层大小**

`layer-list`中的第一个`<item>`将根据其所在的组件大小进行调整。所有其他图层将被调整为它们的“自然”大小。对于位图图像，这是它渲染的大小。对于`<shape>`元素，自然大小是 0x0。为了指定`<shape>`的“自然”大小，你需要为`<shape>`提供一个带有`android:width`和`android:height`属性的`<size>`子元素。

如果你想让一个双层图像充当一个大的绿色按钮，你可能会声明一个灰色圆角矩形的图层作为背景，再声明一个绿色椭圆形的图层，使其看起来像是在灰色背景上的一个光点或球体。这样的`layer-list`可能看起来类似于以下的代码片段：

```kt
<layer-list >
    <item>
        <shape android:shape="rectangle" android:useLevel="false">
            <stroke android:width="1dip" android:color="#ffffffff" />

            <gradient android:type="linear"
                      android:angle="90"
                      android:startColor="#ffaaaaaa"
                      android:endColor="#ffcdcdcd" />

            <padding android:top="8dip"
                     android:left="8dip"
                     android:bottom="8dip"
                     android:right="8dip" />

            <corners android:radius="4dip" />
        </shape>
    </item>
    <item>
        <shape android:shape="oval" android:useLevel="false">
            <size android:width="32dip" android:height="32dip" />
            <gradient android:type="radial"
              android:centerX="0.45"
              android:centerY="0.25"
              android:startColor="#ff1a4e1a"
              android:endColor="#ff1ad049"
              android:gradientRadius="32" />
        </shape>
    </item>
</layer-list>
```

在前面的代码片段中，只有`shape`图层，但你可以轻松地通过在`<item>`元素中引用位图资源，来添加一个位图图层，如下面的代码片段所示：

```kt
<item android:drawable="@drawable/checkmark"/>
```

# 使用九宫格图像进行拉伸

有时你想要一个比简单线条更复杂的边框，例如，如果你想添加阴影。在网页上，你通常会找到各种 HTML 技巧，将八张或九张图片插入一个盒子中，以便在保持边框完整的同时缩放内容。在 Android 中，这种技术称为“九宫格”图像，因为它由九个不同的部分组成。在 Android 中，当九宫格图像以大于其原始尺寸的大小渲染时，会特别处理。为了将这些图像标识为特殊的，它们有一个`.9.png`扩展名（必须是有效的`PNG`文件）。

九宫格图像将边框和背景结合在单一图像中。当内容变得过大而无法适应图像时，背景区域将会扩大，图像的边框区域也会被缩放，以避免留下“空洞”。

从概念上讲，你可以从以下图表所示的九宫格图像开始思考：

![使用九宫格图像进行拉伸](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_09.jpg)

图中的箭头指出了根据中心“内容”区域大小而变大的概念性“边界”区域。九宫格图像的角落将完全不受任何缩放的影响。

## 创建九宫格图像

要创建九宫格图像，你需要一个像样的图像编辑应用程序。我个人使用**Gimp**应用程序（在[`www.gimp.org`](http://www.gimp.org)免费提供），尽管你可能更喜欢使用其他应用程序。无论你使用什么应用程序，它都必须能够输出**Portable Network Graphics** (**PNG**)文件，并且还应该能够放大到相当高的程度。九宫格图像中的所有数据实际上都编码在图像文件中，这意味着不需要 XML 文件来告诉 Android 图像的哪些部分是边框区域，哪些部分在缩放时不应受到影响。

与网页上出现的 CSS 盒子不同，Android 中对九宫格图像的大小调整是通过最近邻缩放完成的。**最近邻缩放**并不试图以任何方式改善缩放图像的质量，像素只是变成了更大颜色块。这对于渐变内容背景来说效果很好（只要它们没有被强制变得过大），但它可能导致你的图像出现一些奇怪的艺术效果。由于当前在缩放过程中没有进行颜色插值，某些效果在缩放时可能看起来相当奇怪。缩放也比简单的图像复制耗时更长，因此在调整图像大小时请记住这一点，它可能需要比你想象的要大得多。然而，这也意味着九宫格图像比你在网上可能了解的图像要灵活得多。

下面的两张图像是同一 32x32 像素九宫格图像的放大版本：

![创建九宫格图像](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_10b.jpg)

左侧的图像是原始的 PNG 文件，可用作九宫格图像。右侧的图像是同一图像的一部分被突出显示，以展示哪些区域将被缩放。顶部、底部左侧和右侧的区域将仅水平或垂直缩放，而中心区域将被拉伸以适应内容的大小。以下图像是作为`TextView`对象的背景使用的同一图像：

![创建九宫格图像](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_12.jpg)

那么，图像左侧和顶部上的黑色线条告诉安卓系统要缩放图像的哪些部分，但右侧和底部的线条表示什么呢？这两条线决定了如何放置小部件内容的位置，类似于`<shape>`资源中的`<padding>`元素。

为了了解你的九宫格图像将如何渲染以及可能的缩放方式，安卓系统在 Android SDK 安装的`tools`目录中提供了一个实用工具。`draw9patch`工具将你的九宫格图像渲染成各种形状和大小，并允许你在将图像用于应用程序之前有效地调试图像。

# 在安卓中使用位图图像

图像是塑造你的应用程序风格的重要组成部分。它们用于图标、边框、背景、标志等许多其他用途。安卓系统尽力确保你使用的资源图像能在安卓设备上的不同类型屏幕上尽可能好地渲染。

安卓系统对图片的自动处理远非完美。然而，有时你需要为应用程序提供同一图像的多种不同变体，以使其在各种不同的设备上看起来都正确。

## 处理不同的屏幕尺寸

在安卓中处理任何位图图像时，非常重要的一点是要考虑到你的应用程序将在各种不同大小和密度的屏幕上运行。在非常大的屏幕（如在笔记本电脑或平板电脑上找到的屏幕）上工作時，你需要使用比在非常小的屏幕上更大的图像。虽然九宫格图像在很大程度上简化了事情，但它们仍然使用最近邻算法进行缩放，这可能会在比你预期更大的屏幕和字体大小上开始显现。

您可以在资源目录中提供不同大小的图片。对于每种屏幕尺寸，你可以提供不同的`drawable`目录。资源加载工具会自动从与当前设备配置最接近的目录中选择文件。你不需要在每个目录中都有一份每种资源的副本，只需提供那些你希望有更合适替代品的资源。当尝试查找要加载的资源文件时，资源加载器会在匹配度较低的目录中回退查找。

安卓系统识别出与屏幕尺寸相关的五个重要参数。虽然你可以指定与屏幕上确切像素数相关的参数，但这不是一个好主意，因为你无法轻易地适应所有不同的屏幕尺寸。相反，最好坚持使用安卓系统提供的五个参数：

+   `small`

+   `medium`

+   `large`

+   `long`

+   `notlong`

前三个参数直接与屏幕尺寸相关，而后两个参数与屏幕是否为“传统”（如 VGA）格式或“宽屏”（如 WVGA）格式有关。这些参数可以以各种组合方式混合，例如：

+   `/res/drawable-small/`

+   `/res/drawable-medium-long/`

+   `/res/drawable-large-notlong/`

前面的例子都是有效的资源目录，可用于覆盖正常`drawable`目录中的文件。您不能组合相互矛盾的参数，例如：

+   `/res/drawable-small-large/`

+   `/res/drawable-long-notlong/`

在上述情况下，您将收到资源打包工具的错误信息。每当您处理位图图像时，考虑到这些尺寸参数很重要，因为有些设备的屏幕与默认模拟器显示的屏幕有很大不同。

## 处理不同的屏幕密度

**屏幕密度**通常指的是在给定物理空间内填充的像素数量（即每英寸点数或 DPI）。它还与屏幕上像素的大小有关。虽然大多数 Android 设备具有中等或高密度屏幕，但大量较便宜的设备使用相对低密度的屏幕。

这为什么会影响到九宫格和位图图像呢？同样的原因也影响到了字体渲染——密度越低，抗锯齿和阴影效果看起来越差。解释这个现象最好的方式是用图像来说明。在以下图片中，左边的是在高密度屏幕上显示的简单圆角矩形。右边的图片类似于在低密度屏幕上渲染的同一图像：

![处理不同的屏幕密度](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_13b.jpg)

尽管这两张图片源自同一张图片，且以相同的物理尺寸渲染，但像素数量的减少使得在低密度屏幕上图像看起来变得块状。

以下两张图片是从右下角截取的，并放大以更详细地说明发生的情况：

![处理不同的屏幕密度](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_09_15b.jpg)

同样，这些图片被配置为占据相同的物理空间。如果图像的尺寸以屏幕像素指定，那么在低密度屏幕上它将占据更多的物理空间。这就是为什么推荐在 Android 中使用“密度独立像素”（`dp`或`dip`）单位而不是普通像素（`px`）单位来设置图像大小的一个原因。

与屏幕尺寸一样，Android 提供了一系列配置参数，可用于为不同屏幕密度的设备提供不同的资源。选择屏幕密度的参数可以与基于屏幕尺寸选择的参数混合使用。以下是 Android 提供的可用于根据当前设备的屏幕密度提供资源的参数列表：

+   `ldpi`：低密度屏幕（约 120dpi）

+   `mdpi`：中等密度屏幕（约 160dpi）

+   `hdpi`：高密度屏幕（约 260dpi）

+   `nodpi`：特殊情况

最后一个“特殊情况”可以在你有一个不希望根据设备密度缩放的九宫格图像或位图图像时使用。默认情况下，Android 会重新缩放图像，以尝试使图像的物理尺寸尽可能接近预期的尺寸。`nodpi` 目录中的图像不会被 Android 自动缩放，而是按像素对像素进行渲染。

### 提示

**不同密度的图标**

有时大尺寸的高分辨率图标并不能很好地缩小。在这些情况下，为低密度屏幕设计完全不同的图标通常是一个好主意。

# 处理配置变更

当你为 Android 提供与各种可能的硬件配置相关的不同资源目录时，资源加载器将尝试为运行你应用程序的设备匹配最佳的资源文件。然而，并非所有的配置参数都直接与硬件相关，而是描述设备状态或某些软件配置参数。这些参数的例子包括设备语言、网络 ID 和设备方向。这些参数可能会在应用程序运行时发生变化。最常见的例子就是设备方向。Android 有一个内置机制来为你处理这些变化，在大多数情况下，你不需要任何特殊的 Java 代码来处理这些变化。然而，至少为其中一些参数提供资源文件是非常可取的。

当配置参数发生变化时，Android 会将你的 `Activity` 状态存储在一个 `Bundle` 对象中，然后关闭 `Activity`。之后，系统会以新的配置参数启动 `Activity` 的新实例，并从 `Bundle` 对象中恢复状态。所有默认的 Android 控件都会在系统关闭你的 `Activity` 之前存储它们当前的状态。这意味着通常你不需要为配置变更执行任何特殊处理。

## 提供横屏布局

到目前为止，我们在这本书中只构建了竖屏布局。与桌面或网页系统不同，移动应用程序的默认方向是竖屏（因此配置参数是 `long` 和 `notlong` 而不是 `wide` 和 `narrow`）。拥有 Android 平台的好处之一是它必须包含加速度计这一硬件，这意味着你的应用程序可以响应设备的方向。得益于 Android 的配置处理（如前所述），作为开发者的你除了提供替代的横屏布局资源外，不需要做任何事情，假设你没有在 Java 中构建用户界面的大部分内容。为了提供特定于竖屏或横屏方向的布局，你可以将布局的特定版本的 XML 资源放置在以下配置参数配置的目录中：

+   `port`：针对竖屏的布局

+   `land`：特定于横向的布局

当屏幕竖向比横向长（即肖像模式）时，使用一个简单的垂直方向的`LinearLayout`来布局一个输入表单是非常有意义的。你所使用的任何输入控件都会被放置在它们标签的下方，因此它们有更多的水平空间来显示数据。额外的水平空间使得标签可以包含更多信息。

下图展示了这两种布局概念之间的区别：

![提供横向布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_09_17.jpg)

右侧使用的布局方法在网页或桌面系统中非常常见，如果标签和输入控件的大小足够小，在移动设备上也会工作得很好。

当切换到横向模式时，水平空间的显著增加和垂直空间的巨大损失使得垂直`LinearLayout`成为一个糟糕的选择。如果你正在处理一个简单的输入表单，那么横向布局应该使用`TableLayout`或`RelativeLayout`来将标签放置在与它们相关的输入控件同一行上。

## 在横向布局上提供文本输入

在构建你的横向布局时，你需要仔细考虑用户界面的哪些部分最重要。如果屏幕被用来编写电子邮件或文档，你的横向布局可能与纵向布局几乎相同。然而，这样的布局有一个几乎隐藏的敌人：软件键盘。在纵向布局中，软件键盘会限制在屏幕底部，并占用相对较小的空间（大约四分之一到三分之一的可用屏幕空间）。然而，在横向布局中，软件键盘可能会占用你一半的垂直屏幕空间，使得构建以内容为中心的横向布局变得非常困难。如果你的布局是强烈以输入驱动的，那么在横屏模式下移除用户界面的一部分，或者重新设计用户界面，使得软件键盘不会妨碍，可能是合理的。

安卓提供了一系列的配置参数，可以告诉您关于运行您应用程序设备上的键盘信息。在构建应用程序时考虑所有可能性是一个好主意。以下是应用程序可能面临的一些可能的键盘情况简短列表：

+   只有软件键盘

+   硬件键盘

+   硬件键盘可用；软件键盘在使用中

除了这些可能性，屏幕较小的设备通常会使用 12 键键盘而不是全 QWERTY 键盘。如果这是软件键盘（通常是这种情况），键盘可能占用高达 80%的屏幕空间。当用户激活文本输入框时，Android 通常会通过打开“文本输入”屏幕来处理这个问题。你可以通过以下配置参数确定键盘的可使用状态和使用的键盘类型：

+   `nokeys`：仅限软件键盘

+   `qwerty`：可以使用完整的硬件键盘

+   `12key`：可以使用 12 键硬件手机键盘

+   `keysexposed`：用户可以看到键盘，无论是硬件还是软件的

+   `keyshidden`：当前没有任何键盘可见

+   `keyssoft`：用户将使用软件键盘（尽管它可能不可见）

在设计屏幕时，请考虑软件键盘可能占用你一半的垂直空间。确保内容区域可以滚动，而重要的控件将始终在屏幕上可见。如果一个聊天应用程序简单地被包裹在`ScrollView`中，当软件键盘可见时，输入`EditView`对象可能会变得不可见。考虑屏幕的外观不仅仅是如何，还要考虑它将如何应对用户可能带来的变化。最后，测试屏幕在有无软件键盘的情况下看起来和表现如何是至关重要的。

## 更改屏幕内容

Android XML 布局格式的一大优势是它提供的解耦。竖屏和横屏布局通常彼此差异很大，用户可能会分别找到一个更喜欢的方向来使用你的应用程序。在设计新布局时，一个不太常见但有用的技巧是能够从两个不同的布局中添加或删除“非功能性”元素。

在一个简单的例子中，你可能想要在竖屏布局中缩写标签文本，并包含一些图标作为图形提示，而在横屏布局中，你可能希望图标大小加倍并使用两行标签，所有这些都位于输入字段同一行。

下图阐述了这一概念：

![更改屏幕内容](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_09_18.jpg)

在前述图表的横屏布局中，你可以使用额外的`TextView`元素来显示标签的子文本。假设你的 Java 代码没有寻找额外的`TextView`对象，你的应用程序将完美运行。在设计`Activity`的替代布局时，能够更改用户界面的实际结构而不仅仅是布局，这是一个非常重要的考虑因素。

# 总结

应用程序的外观和感觉至关重要。对颜色或字体的一次更改就可能会影响屏幕的可用性。同时，过度设计应用程序可能会让它在使用者的设备上显得不协调。一个陌生的外观和感觉会将用户从该应用程序推向那些看起来和感觉更熟悉和舒适的应用程序。

Android 使用样式资源结构提供了一系列极其强大的功能。结合将你的图形放置在资源文件中并覆盖默认值的能力，你可以有效地重新设计任何小部件。使用样式也有助于维护你的应用程序，因为你只需要在样式资源中更改样式，而不是在每个特定样式的部件声明中进行更改。

将你的大部分小部件图形作为 `<shape>` 资源，将确保你的应用程序具有尽可能一致的外观和感觉。然而，这并不总是实用的。当你需要提供位图资源时，为用户可能使用的各种屏幕尺寸和密度提供不同的图像至关重要。

应用程序的风格设计还包括布局以及应用程序适应其运行设备的能力。拥有一个伟大的想法仅是应用程序吸引力的的一半，其风格和执行对它在“野外”的生存至关重要。关注细节是一个强大的工具，将吸引用户使用你的应用程序。那些“即开即用”的应用程序总是比那些需要时间和精力才能使用的应用程序更受欢迎。

利用 Android 模拟器提供的各种屏幕尺寸和密度，以确保你的应用程序能在尽可能多的设备上看起来良好。不要忘记，许多设备没有硬件键盘，而且软件键盘可能会占用你屏幕空间的一半。

在下一章中，我们将把这种样式知识扩展到应用程序的整体设计和主题。我们将构建一个具有许多提供布局的样式化应用程序，并进行相当广泛的样式设计。


# 第十章：构建应用程序主题

*无论是否涉及图形样式，每个应用程序都有一个主题。应用程序的主题使其具有独特的外观和逻辑。*

当用户使用移动应用程序（大多数安卓设备的情况）时，与台式机或笔记本电脑相比，他们的行为有一些根本性的不同：

+   他们通常在应用程序上的时间更少，因此耐心也更小

+   他们通常一次只专注于一个应用程序

+   触摸屏设备鼓励用户进行近乎触觉的交互响应

安卓设备种类繁多，几乎兼容所有设备，包括常见的手机、平板、笔记本电脑，甚至一些桌面电脑。一个安卓应用程序预期在这些环境中都能良好运行，应用的主题应精心构建，以便用户在各种设备上获得最佳访问体验。

设备界面构成了你的应用程序主题的一部分。在台式机或笔记本电脑上使用鼠标时，仅考虑触摸屏的用户界面可能对用户来说会显得过大（因为所有控件都需要适合手指大小）。相反，为鼠标驱动的系统设计的应用程序通常会包含悬停效果，这在触摸屏设备上无法正常工作。确保你的应用程序在所有这些不同设备上都能正常工作的唯一方法是，在构建应用程序屏幕时考虑所有这些环境。

安卓自身定义了一种主题，尽可能的话，为安卓平台构建的应用程序应尝试符合或扩展这一主题，而不是重新定义。这并不意味着你的应用程序必须看起来和行为与其他所有安卓应用程序完全相同，但你的应用程序应该基于安卓所设定的基本原则。

### 注意

请记住，许多设备制造商对基本的安卓主题定义了额外的部分，你的应用程序也应如此。

在本章中，我们将探讨应用程序的构建，包括屏幕设计、构建和样式设计。我们还将研究此应用程序如何与各种不同设备交互，确保其外观和功能符合用户预期。我们将构建一个计算器应用程序，包含标准计算器和科学计算器功能。计算器将设计得更像物理计算器而非普通的安卓应用，并根据运行设备的性能调整其功能。总体而言，我们将定义一个具有自身一致主题的应用程序。

# 创建基本的计算器布局

要构建这个项目，我们首先需要一个标准的计算器的基本纵向布局。这个基本布局将作为用户首次启动应用程序时所看到的屏幕。鉴于计算器应用程序的性质以及用户对它的感知，屏幕简单且应用程序启动越快越好，这一点非常重要。

### 提示

计算器屏幕占据所有可用空间的功能性组件非常重要，以使其尽可能快地使用（更大的按钮等于更容易使用）。

## 小测验

1.  布局资源何时变成 Java 类？

    1.  当运行资源处理器时

    1.  当应用程序包被构建时

    1.  当布局资源被加载时

    1.  从不

1.  你如何引用那些在 Android 中默认未定义的小部件？

    1.  通过使用完整的类名作为元素名称

    1.  通过为 Java 包定义一个 XML 命名空间

    1.  目前不可能

    1.  通过在 `android:package` 属性中指定 Java 包名

1.  一个 `View` 对象的默认宽度和高度是什么？

    1.  它内容的大小

    1.  零像素

    1.  它取决于它所在的 `ViewGroup`

    1.  它父级的宽度和内容的高度

1.  你将布局资源写成 XML，它以什么格式存储？

    1.  作为原始 XML 文本

    1.  Android 二进制 XML

    1.  布局特定的二进制格式

    1.  Java 类

## 设计一个标准计算器

在开始构建计算器应用程序之前，最好先勾勒出它将是什么样子。这将帮助你决定如何确切地构建屏幕。由于计算器既是一个相当古老发明的东西，也是人们非常熟悉的东西，因此遵循最常见的设计非常重要。如果你推出的计算器对人们来说太陌生，他们可能没有耐心去“了解”你的应用程序。新想法是好的（即滑动键盘），但最成功的还是现有想法的延伸。同时，要向用户明确它们的工作方式。以下是我们将开始构建的标准计算器屏幕的区块图：

![设计一个标准计算器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_10_01.jpg)

我们要最大化利用屏幕空间，因此我们会尽可能使按钮变大。同时，我们希望按钮之间稍微留点空隙，以避免用户不小心按下不想按的按钮。由于我们只有一个输出区域，我们会确保显示区域也足够大。

显示区域中的箭头将是一个图标，作为*退格*按钮，允许用户删除不需要的内容。给用户提供一种撤销操作的方法始终很重要。我们将使用与拨号应用中类似的图标，这将保持与系统的其他部分的整体一致性。这也有效地为我们提供了额外按钮的空间。这个用户界面不包括许多计算器所关联的常规“记忆”功能。基本屏幕设计得尽可能简单，我们将在开发应用程序时引入更多功能。

# 动手操作——构建标准计算器

计算器的第一个布局将由一系列正常的**0**至**9**的按钮组成，以及用于各种基本算术运算的按钮——加、减、乘、除。它还将包括等于号按钮和小数点按钮。尽管在 Java 代码中构建这样一个简单的屏幕非常容易，但我们将完全使用 XML 资源来构建这个示例。由于这个应用程序将具有相同屏幕的几种不同排列组合，使用不带 Java 代码的布局资源文件将使你的生活更加轻松。

1.  首先，为计算器创建一个新项目：

    ```kt
    android create project -n Calculator -p Calculator -k com.packtpub.calculator -a CalculatorActivity -t 3
    ```

1.  打开标准的主体布局文件`/res/layout/main.xml`。

1.  从文件中删除生成的布局结构。

1.  首先，声明一个垂直的`LinearLayout`作为根元素，以占据屏幕上所有可用空间：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  声明一个`RelativeLayout`，它将由显示和用户可以用来删除不需要输入的**删除**或**取消**按钮组成：

    ```kt
    <RelativeLayout android:layout_width="fill_parent"
                    android:layout_height="wrap_content">
    ```

1.  在`RelativeLayout`的右侧使用`ImageView`显示标准的 Android 输入删除图标：

    ```kt
    <ImageView android:id="@+id/delete"
               android:src="img/ic_input_delete"
               android:layout_centerInParent="true"
               android:layout_alignParentRight="true"
               android:layout_width="wrap_content"
               android:layout_height="wrap_content"/>
    ```

1.  在`RelativeLayout`的左侧，创建一个`TextView`，它将实际显示计算器的数字状态：

    ```kt
    <TextView android:id="@+id/display"
              android:text="0"
              android:layout_alignParentTop="true"
              android:layout_toLeftOf="@id/delete"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  在`LinearLayout`内部，声明一个`TableLayout`，用于包含简单计算器的按钮输入：

    ```kt
    <TableLayout android:id="@+id/standard_functions"
                 android:layout_width="fill_parent"
                 android:layout_height="fill_parent"
                 android:layout_margin="0px"
                 android:stretchColumns="0,1,2,3">
    ```

1.  `TableLayout`将由四个`TableRow`对象组成。声明第一个对象，无边距且`layout_weight`为`1`：

    ```kt
    <TableRow android:layout_margin="0px"  
              android:layout_weight="1">
    ```

1.  右上角的`Button`对象需要是`plus`符号，我们也将其用作`Button` ID 的名称：

    ```kt
    <Button android:id="@+id/plus"
            android:text="+"/>
    ```

1.  第一行接下来的三个`Button`对象将是数字**1**、**2**和**3**。这些也需要 ID：

    ```kt
    <Button android:id="@+id/one"
            android:text="1"/>
    <Button android:id="@+id/two"
            android:text="2"/>
    <Button android:id="@+id/three"
            android:text="3"/>
    ```

1.  继续按块状图定义的顺序声明带有按钮的`TableRow`对象。

1.  在编辑器或 IDE 中打开`CalculatorActivity.java`源文件。

1.  在`onCreate`方法中，确保将`Activity`的内容视图设置为刚才定义的`main`布局：

    ```kt
    setContentView(R.layout.main);
    ```

## *刚才发生了什么？*

现在你应该已经为计算器创建了一个基本用户界面；尽管它仍然看起来像一个非常通用的 Android 应用程序，但这至少是从基础层面开始的。用户界面需要做一些样式设计工作，包括着色和一些字体更改，但基本结构现在已经完成。使用`RelativeLayout`是为了确保我们可以正确地将删除图标定位在`TextView`的右侧，无论屏幕大小如何。

为了让按钮尽可能占用可用空间，我们告诉`TableLayout`拉伸其所有列。如果`TableLayout`不拉伸其列，那么它将只占用其子项所需的水平空间（实际上与`wrap_content`宽度相同）。尽管告诉`TableLayout`也占用所有垂直空间，但其子项将根据它们所需的空间进行大小调整，这就是为什么按钮没有占用所有可用屏幕空间的原因。以下图像是基本计算器在模拟器中运行时的截图：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_02.jpg)

# 构建计算器样式。

我们真的希望这个计算器看起来更像一个真正的计算器，为此我们需要应用一些样式。目前计算器的主题完全是标准的 Android 主题，尽管它看起来与 Android 系统的其他部分完全一样，但它并不真正适合这个应用程序。我们希望对按钮和应用程序的显示区域进行样式设计。我们将在资源文件中定义样式值，并在布局 XML 文件中引用这些样式。

首先，我们将定义一系列九宫格图像来创建我们自己的按钮设计。为此，我们需要三张不同的图片。第一张是按钮的“正常”状态，第二张是按钮的“按下”状态，最后是按钮的“聚焦”状态。

## 小测验。

1.  九宫格图像边缘周围的黑色线条是做什么的？

    1.  提供给系统关于图像中哪些部分需要复制的提示。

    1.  指示图像中哪些部分需要缩放以及小部件内容放置的位置。

    1.  定义图像中包含元信息的内容部分。

1.  九宫格图像可以存储为什么格式？

    1.  JPEG、GIF 或 PNG 图像文件。

    1.  嵌入 TIFF 的 XML 文件。

    1.  可移植网络图形图像（Portable Network Graphic image）。

1.  `draw9patch`应用程序是做什么的？

    1.  在各种形状和大小中渲染九宫格图像。

    1.  这是一个用于绘制九宫格图像的应用程序。

    1.  为九宫格图像生成元数据作为 XML 文件。

# 动手操作——创建按钮图像。

为了在本节中构建按钮图像，你需要下载“GIMP”（可在[`www.gimp.org`](http://www.gimp.org)获取）。它非常适合这种图像创建或操作，而且它还有一个开源的优势。

1.  打开“GIMP”，选择**文件** | **新建**以创建新图像。

1.  将宽度和高度更改为`38x38`像素。

1.  打开**高级选项**并将**填充为**选项更改为**透明**，这样就没有背景色了。

1.  为了帮助调整大小，放大至大约**800%**。

1.  在工具箱左上角选择**矩形**工具（默认快捷键是*R*）。

1.  启用**圆角**选项并将其设置为`5`。

1.  启用**固定**选项，并在下拉列表中选择**大小**。

1.  输入`36x36`作为矩形选择的固定大小。

1.  将选择框放在图像画布中心，选择框和图像边缘之间应该有一个单像素的边界。

1.  双击工具箱中的“前景色”（默认为黑色）。

1.  在颜色选择器的**十六进制表示**框中输入`444444`。

1.  关闭颜色选择器对话框。

1.  在工具箱中选择**桶填充**工具（默认快捷键是*Shift-B*）。

1.  在选择框内部点击，用选定的颜色填充它。

1.  使用**选择**菜单，点击**无**选项以移除选择框。

1.  选择**滤镜** | **装饰** | **添加斜角**。

1.  将**厚度**选项更改为`3`。

1.  取消勾选**在副本上工作**选项，并点击**确定**按钮。

1.  再次从工具箱中选择**矩形**工具。

1.  取消勾选**圆角**和**固定**选项。

1.  使用选择工具在“按钮”形状内部选择一个单像素宽的垂直框，小心只选择按钮内容区域的一部分，避开斜角边框空间：![行动时间 – 创建按钮图像](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_03.jpg)

1.  将光标放在选择框中间，将选择框水平拖动至图像画布边缘（在单像素边界内）。

1.  再次双击“前景”矩形。

1.  将颜色重置为纯黑色。

1.  选择**桶填充**选项。

1.  在选择框内部点击，创建一个单像素宽，黑色的垂直线条在图像左侧。

1.  在图像右侧创建一个类似的垂直线条。

1.  在图像的顶部和底部创建一个单像素高的水平黑色线条。

1.  在你的`res/drawable`目录中将图像保存为`button.9.png`，保持 PNG 选项为默认值。

1.  重复上述过程，将前景色`444444`更改为如步骤 11 中的`c16400`，并将新的图像保存为`button_focus.9.png`。

使用**翻转工具**（默认快捷键*Shift* + *F*）翻转图像，你将创建`button_down.9.png`图像。

## *刚才发生了什么？*

虽然构建图像有许多步骤，但使用正确的工具并进行一些实验，它们本质上非常容易创建。如果你只需要一个简单的按钮或类似的东西，那么找一些关于如何使用“GIMP”或类似工具的教程是很有价值的。以下链接有一些在线教程：

+   [`www.gimp.org/tutorials/`](http://www.gimp.org/tutorials/)

+   [`gimp-tutorials.net/`](http://gimp-tutorials.net/)

你在上一个部分保存的图像应该看起来像我为我的计算器应用程序创建的以下图像：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_03b.jpg)

# 动手时间——美化计算器按钮

接下来我们需要做的是使用选择器列表和你刚刚创建的九宫格图像来设置计算器按钮的样式。我们还将定义按钮样式在资源文件中，这样我们就不必为每个按钮指定所有的样式。为了用我们创建的图像替换标准按钮，我们只需要用我们创建的背景替换它的背景。

1.  在`res/drawable`目录中，创建一个名为`button.xml`的新 XML 文件，并在编辑器中打开它。

1.  将文件的根元素定义为一个固定大小的选择器：

    ```kt
    <selector

        android:constantSize="true"
        android:variablePadding="false">
    ```

1.  创建一个被按下的按钮状态，作为选择器的第一个子项：

    ```kt
    <item android:state_pressed="true" 
          android:drawable="@drawable/button_down"/>
    ```

1.  选择器的第二个子项应该是获得焦点状态：

    ```kt
    <item android:state_focused="true"
          android:drawable="@drawable/button_focus"/>
    ```

1.  选择器的最后一个子项是通用的，是正常状态：

    ```kt
    <item android:drawable="@drawable/button"/>
    ```

1.  在`res/values`目录中创建一个名为`styles.xml`的新文件，并在编辑器中打开它。

1.  `styles.xml`文件的根元素应该是一个没有命名空间声明的资源元素（在这个文件中不需要）：

    ```kt
    <resources>
    ```

1.  在文件中定义第一个样式为`CalculatorButton`，其父样式为默认的 Android `Button`小部件样式：

    ```kt
    <style name="CalculatorButton"
           parent="@android:style/Widget.Button">
    ```

1.  将文本大小设置为一种美观的大字体和浅灰色：

    ```kt
    <item name="android:textSize">30sp</item>
    <item name="android:textColor">#ffcacaca</item>
    ```

1.  将样式的背景指定为新的`button`可绘制资源：

    ```kt
    <item name="android:background">@drawable/button</item>
    ```

1.  在每个`Button`小部件周围创建一个两像素的边框，以创建一点间距：

    ```kt
    <item name="android:layout_margin">2dp</item>
    ```

1.  确保让`Button`小部件消耗它们可用的所有垂直空间：

    ```kt
    <item name="android:layout_height">fill_parent</item>
    ```

1.  在编辑器中打开`main.xml`布局资源。

1.  在每个`Button`元素上，添加一个样式属性，以赋予你刚刚在`styles.xml`文件中定义的样式：

    ```kt
    <Button style="@style/CalculatorButton"
            android:id="@+id/multiply"
            android:text="*"/>
    ```

## *刚才发生了什么？*

我们刚刚为计算器屏幕重新设计了`Button`对象。这个样式是标准 Android `Button`小部件的子样式。新的样式主要是通过将背景图像更改为我们之前创建的九宫格图像来驱动的。为了与新的背景图像一起工作，我们还指定了字体颜色和大小。运行时，新的计算器用户界面将如下截图所示：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_07.jpg)

在原始代码中，没有指定按钮周围的边距，但在新代码中，我们在自定义样式中添加了明确的边距。我们的九宫格图像在内容区域周围没有填充。

你会注意到我们在布局中为每个`Button`小部件设置样式。正如在前一章中提到的，样式属性不是 Android 资源命名空间的一部分。不幸的是，Android 目前不允许我们为特定类的所有小部件设置样式。相反，我们只能选择为每个小部件单独设置样式，或者在`Activity`或应用程序中为所有小部件设置相同的样式。作为新`Button`样式的一部分，我们声明了一个`<selector>`资源的可绘制资源。与标签结构一样，`Button`对象可以被样式化为使用不同的可绘制资源来表示它们的不同状态。在这种情况下，我们为`Button`被聚焦、按下或处于正常状态时指定背景图像。样式只适用于背景图像，因为新`Button`对象的背景是`<selector>`资源。

# 行动时间——设置显示样式

目前，数字显示看起来确实相当糟糕。这主要是因为我们还没有为其设置任何样式，现在它只是一个普通的`TextView`对象。我们希望样式能够同时涵盖`TextView`对象和`ImageView`。当前的显示效果如下截图所示：

![行动时间——设置显示样式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_08.jpg)

为了修复这个显示，并将其样式与我们的新`Button`样式保持一致，我们将创建两种不同的样式。一种是在`TextView`和`ImageView`对象周围创建边框和背景，另一种是用更合适的字体样式化`TextView`小部件。

1.  创建一个名为`display_background.xml`的新可绘制资源文件，并在你的编辑器或 IDE 中打开它。

1.  显示背景的根需要是一个矩形形状：

    ```kt
    <shape    

        android:shape="rectangle">
    ```

1.  声明一些内边距来缩进文本和图像：

    ```kt
    <padding
        android:top="5sp"
        android:bottom="5sp"
        android:left="15sp"
        android:right="15sp"/>
    ```

1.  为矩形创建一个纯灰背景色：

    ```kt
    <solid android:color="#ffcccccc"/>
    ```

1.  指定描边大小，并将其颜色设置为白色：

    ```kt
    <stroke android:width="2px"
            android:color="#ffffffff"/>
    ```

1.  在你的编辑器或 IDE 中打开`res/values/styles.xml`文件。

1.  为显示包装器添加一个新的`<style>`项，并将新样式命名为没有父样式的`CalculatorDisplay`：

    ```kt
    <style name="CalculatorDisplay">
    Set the background as the display_background:<item name="android:background">
        @drawable/display_background
    </item>
    ```

1.  在显示包装器下方创建一个小边距：

    ```kt
    <item name="android:layout_marginBottom">25sp</item>
    ```

1.  在显示上方添加一些内边距：

    ```kt
    <item name="android:layout_marginTop">50sp</item>
    ```

1.  以名称`CalculatorTextDisplay`开始一个新的`<style>`元素，父样式应该是标准的`TextView`样式：

    ```kt
    <style name="CalculatorTextDisplay"
           parent="@android:style/TextAppearance">
    ```

1.  在新样式中，将字体设置为`45`像素，黑色等宽字体：

    ```kt
    <item name="android:typeface">monospace</item>
    <item name="android:textSize">45sp</item>
    <item name="android:textColor">#ff000000</item>
    ```

1.  计算器显示的文本应该是右对齐的，因此我们还将指定应用到`TextView`的重力属性：

    ```kt
    <item name="android:gravity">right</item>
    ```

1.  在你的编辑器或 IDE 中打开`res/layout/main.xml`文件。

1.  将`RelativeLayout`的样式指定为`CalculatorDisplay`：

    ```kt
    <RelativeLayout style="@style/CalculatorDisplay"
                    android:layout_width="fill_parent"
                    android:layout_height="wrap_content">
    ```

1.  设置显示的`TextView`样式：

    ```kt
    <TextView android:id="@+id/display"
              style="@style/CalculatorTextDisplay"
              android:text="0"
              android:layout_alignParentTop="true"
              android:layout_toLeftOf="@id/delete"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

## *刚才发生了什么？*

新的样式适用于围绕`TextView`对象和`ImageView`对象的`RelativeLayout`。通过设置这个`RelativeLayout`的样式，你实际上将`TextView`和`ImageView`作为一个单一的小部件合并在一起。如果你看以下截图，你会看到这是如何为你的用户工作的：

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_09.jpg)

`TextView`对象上下的边距会减少按钮可用的空间。在长垂直空间中，按钮通常会变长，看起来不成比例，因此通过为显示区域添加边距，我们可以帮助保持按钮更接近正方形。

## 尝试英雄——添加计算器逻辑

目前，我们有一个简单计算器的优秀用户界面。然而，它只是一个看起来很不错的用户界面。接下来要做的就是在其中添加一些逻辑。

以下是完成功能计算器所需的步骤：

1.  实现`OnClickListener`接口，并将其注册到用户界面上的每个`Button`小部件。

1.  创建一个新的`Calculator`类来处理实际的计算，并存储计算器的非用户界面状态。

1.  使用`StringBuilder`类实现当前输入值的构建和显示。

1.  使用`double`数据类型实现基本计算，以便处理带小数点的数字。

## 突击测验

1.  当从布局中选取字符串时，字符串是如何被选中的？

    1.  直接从根目录`values`字符串资源

    1.  从与布局相同的目录中的`strings.xml`文件

    1.  从与当前配置最接近匹配且包含请求名称字符串的`values`目录

    1.  从具有与布局资源文件选择相同的限定符的`values`目录

1.  放置样式资源的正确文件名是什么？

    1.  `values`目录中的任何文件

    1.  `styles.xml`

    1.  `values.xml`

    1.  `theme.xml`

1.  在 Java 代码中选取资源与从 XML 资源文件中选取资源有何不同？

    1.  Java 资源选择更快

    1.  XML 资源只能引用具有相同配置限定符集合的其他资源。

    1.  没有显著差异

    1.  XML 资源只能引用所有资源类型的一个子集。

# 科学景观布局

计算器的科学布局不仅仅是更多按钮的问题，因为当设备处于横屏方向时，我们希望使用此布局。这意味着我们可用的垂直空间大大减少，而标准布局占用了很多这样的空间。为了构建这个新的用户界面，我们不仅要定义一个新的布局资源，还要为新的布局添加额外的样式。

科学布局在其新按钮上也使用了更复杂的文本。一些数学函数，如平方根或反余弦，有特定的表示法应该被使用。在这些情况下，我们将需要使用 HTML 样式或特殊字符。幸运的是，Android 完全支持 UTF-8 字符集，在功能和字体渲染方面都支持，这使得这个过程变得容易得多。

## 为科学布局定义字符串资源

对于科学功能，我们将每个功能的字符串内容定义为一个资源字符串。这既是为了使它们成为资源选择过程的一个独立部分（这总是推荐的），同时也是为了让我们利用自动的 HTML 处理。如果你在字符串资源中使用 HTML，当使用 `Resources.getText` 方法访问时，资源处理器会自动解析该 HTML，而不是通常的 `Resources.getString` 方法。这正是 `TextView` 类加载其字符串资源的方式，使得将文本内容放在 `values` 资源文件中更具吸引力。

以下是我的 `values` 目录中 `strings.xml` 文件的内容。你会注意到这里的 HTML 标记是 HTML 3.2，而不是基于 HTML 4 的。这是因为 Android 的 `Html` 类不能处理 HTML 4 标记，而 `Html` 类实际上是用来加载包含标记的字符串资源的。在 `res/values` 目录中创建一个新的资源文件，命名为 `strings.xml`，并将以下代码片段复制到新文件中：

```kt
<resources>
    <string name="inverse">1/x</string>
    <string name="square">
        x<sup><font size="10">2</font></sup>
    </string>
    <string name="cube">
        x<sup><font size="10">3</font></sup>
    </string>
    <string name="pow">
        y<sup><font size="10">x</font></sup>
    </string>
    <string name="percent">%</string>

    <string name="cos">cos</string>
    <string name="sin">sin</string>
    <string name="tan">tan</string>
    <string name="log2">
        log<sub><font size="10">2</font></sub>
    </string>
    <string name="log10">
        log<sub><font size="10">10</font></sub>
    </string>

    <string name="acos">
        cos<sup><font size="10">-1</font></sup>
    </string>
    <string name="asin">
        sin<sup><font size="10">-1</font></sup>
    </string>
    <string name="atan">
        tan<sup><font size="10">-1</font></sup>
    </string>
    <string name="log">log</string>
    <string name="log1p">log1p</string>

    <string name="e"><i>e</i></string>
 <string name="pi">π</string>
    <string name="random">rnd</string>
 <string name="sqrt">√</string>
    <string name="hyp">hyp</string>
</resources>
```

`pi` 和 `sqrt` 字符串值中的 Unicode 十六进制值用于引用小写希腊字母 Pi 符号和标准的平方根符号。

## 设计科学布局的样式

标准计算器布局中使用的样式对于科学布局来说并不是很好。为了改变科学布局的样式，你可以将新样式添加到横屏布局的新 `values` 目录中。将以下代码片段复制到名为 `res/values-land/styles.xml` 的新文件中：

```kt
<resources>
    <style name="CalculatorDisplay">
        <item name="android:background">
            @drawable/display_background
        </item>
    </style>

    <style name="ScientificButton" parent="style/CalculatorButton">
        <item name="android:textSize">12sp</item>
    </style>
</resources>
```

前一个片段中的第一个样式资源用于计算器的显示区域。与标准计算器一样，我们使用本章前面编写的 `display_background` 形状。我们还为科学按钮定义了一种新样式。科学按钮将与标准计算器按钮完全相同，只是字体要小得多。由于科学按钮比标准按钮多得多，较小的字体使我们能够更舒适地在屏幕上容纳更多按钮。

## 构建科学布局

科学计算器布局包括屏幕右侧的标准计算器按钮，以及屏幕左侧的二十个附加按钮。这些附加按钮代表数学函数和常数，其中大部分可以在`java.lang.Math`和`java.lang.StrictMath`类中找到。下图展示了我们想要布局的科学计算器样式：

![构建科学计算器布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_10_10.jpg)

新样式对横向布局的计算器显示效果将“移除”显示和按钮之间的边距。由于横向布局的垂直空间较少，这样的填充除了是浪费空间之外，什么也不是，应该用来给按钮以保持合理的大小。

# 动手时间——编写科学计算器布局代码

横向布局被分割成多个子布局，以便为两个独立的功能区域保持 ID：科学函数和标准函数。为它们分配自己的 ID 值可以更容易地从 Java 代码中检测到可用的功能。这样，Java 代码就可以使用`findViewById`并测试`null`来检查科学功能是否可用，而不是基于配置决定可用的功能。这和 JavaScript 中的“能力测试”（相对于检查）非常相似。

1.  创建一个名为`res/layout-land`的新资源目录。

1.  在`layout-land`目录中创建一个新的布局资源 XML 文件，名为`main.xml`，并在编辑器或 IDE 中打开此文件。

1.  将新布局的根元素声明为一个垂直的`LinearLayout`，占据所有可用的屏幕空间：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  新布局的第一个元素是一个`RelativeLayout`，用来包裹作为计算器显示的`TextView`和`ImageView`：

    ```kt
    <RelativeLayout style="@style/CalculatorDisplay"
                    android:layout_width="fill_parent"
                    android:layout_height="wrap_content">
    ```

1.  从标准计算器布局（`res/layout/main.xml`）复制`TextView`和`ImageView`元素，作为之前声明的`RelativeLayout`的两个子元素：

    ```kt
    <ImageView android:id="@+id/delete"
               android:src="img/ic_input_delete"
               android:layout_centerInParent="true"
               android:layout_alignParentRight="true"
               android:layout_width="wrap_content"
               android:layout_height="wrap_content"/>
    <TextView android:id="@+id/display"
              style="@style/CalculatorTextDisplay"
              android:text="0"
              android:layout_alignParentTop="true"
              android:layout_toLeftOf="@id/delete"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  根`LinearLayout`的第二个子元素是一个水平方向的`LinearLayout`，占据屏幕剩余空间：

    ```kt
    <LinearLayout android:orientation="horizontal"
                  android:layout_width="fill_parent"
                  android:layout_height="fill_parent">
    ```

1.  在新的`LinearLayout`子元素内，声明一个新的`TableLayout`来填充科学按钮：

    ```kt
    <TableLayout android:id="@+id/scientific_functions"
                 android:layout_width="wrap_content"
                 android:layout_height="fill_parent"
                 android:layout_marginRight="10dip">
    ```

1.  在`scientific_functions TableLayout`内创建一个`TableRow`元素，以包含第一行科学`Button`元素：

    ```kt
    <TableRow android:layout_margin="0px"
              android:layout_weight="1">
    ```

1.  在新的`TableRow`内声明前五个科学函数作为`Button`元素。`Button`的 ID 应与用作`Button`标签的资源字符串名称相同：

    ```kt
    <Button style="@style/ScientificButton"
            android:id="@+id/inverse"
            android:text="@string/inverse"/>
    ```

1.  第一行科学`Button`小部件包含`inverse`、`square`、`cube`、`pow`和`percent`。

1.  创建一个`TableRow`，其中包含第二行科学`Button`小部件，包括`cos`、`sin`、`tan`、`log2`和`log10`。

1.  第三行`TableRow`中的第三个科学`Button`小部件应为`acos`、`asin`、`atan`、`log`和`log1p`。

1.  第四个也是最后一个包含`Button`小部件的`TableRow`应该是`e`、`pi`、`random`、`sqrt`和`hyp`。

1.  这就是所有的科学函数，现在在`LinearLayout`子元素中为标准函数创建另一个`TableLayout`：

    ```kt
    <TableLayout android:id="@+id/standard_functions"
                 android:layout_width="fill_parent"
                 android:layout_height="fill_parent"
                 android:layout_margin="0px"
                 android:stretchColumns="0,1,2,3">
    ```

1.  将`res/layout/main.xml`中的`standard_functions TableLayout`内容复制到新的`TableLayout`元素中。

## *刚才发生了什么？*

在前面的布局中，我们重用了在标准计算器布局中创建的大部分基础内容，并添加了一个新的`TableLayout`结构来包含科学函数。新的`TableLayout`被设置为`wrap_content`的宽度，并且只占用容纳所有`Button`小部件所需的水平空间。两个`TableLayout`元素之间的主要区别在于，科学表格没有拉伸其列，因为这实际上与将其设置为`fill_parent`相同，这样就没有空间放置标准函数了。

你还会注意到，在用于创建科学`Button`标签的字符串资源中，那些使用 HTML 标记的，没有使用 XML 转义实体（如`&lt;`和`&gt;`）。这是告诉资源编译器一个字符串资源包含标记，并且应该以不同方式处理的主要指示。这种使用要求所有放入字符串资源中的 HTML 标记必须符合 HTML 3.2 规范，并且仍然是有效的 XML 内容。

为了测试新的横屏布局，你需要定义一个具有横屏大小的模拟器设备，或者在物理设备上运行应用程序。在模拟器中创建虚拟设备可以使用 Android SDK 安装目录中**tools**目录下的**android**应用程序，这个工具也用于创建项目框架。以下是新布局在物理 Android 设备上运行时的截图：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_11.jpg)

## 动手实践——在现有布局中使用 include

前面的布局重用了标准布局的几个元素。现在是把这些元素提取到它们自己的布局文件中的好时机，然后使用`include`元素将它们放置到两个特定的布局资源中。第五章 *开发非线性布局* 中介绍了布局包含的相关信息。

1.  创建一个`display.xml`布局资源，包含带有计算器显示的`RelativeLayout`，并将其包含在`main.xml`布局资源文件中的适当位置。

1.  创建一个`standard_buttons.xml`布局资源，包含名为`standard_functions`的`TableLayout`，并将其包含在`main.xml`布局资源文件中的适当位置。

## 处理活动重新启动

当设备改变方向时，屏幕上的`CalculatorActivity`对象会以新方向重新启动。在这个应用中，重新启动会导致一个严重的问题：计算器的状态丢失。正如第四章 *利用活动和意图* 中讨论的那样，有时你需要控制 Android 应用的状态——在关机前保存它，并在`Activity`再次启动时恢复它。

你需要重写`Activity.onSaveInstanceState`方法，以在提供的`Bundle`中存储计算器的当前状态。这个`Bundle`对象将在由于配置更改而重新启动时在`onCreate`方法中提供给你。在你的`onCreate`方法中，确保在从它恢复保存的参数之前，提供的`Bundle`对象非空。

## 尝试英雄——实现科学计算逻辑

目前计算器应该能够从标准计算按钮进行操作。然而，新的科学功能没有任何支持结构。此外，如果你重新调整设备方向以在科学和标准布局之间切换，任何“进行中”的计算都会丢失。

为了使科学计算按预期工作，需要完成以下步骤：

1.  实现`onSaveInstanceState`以将计算状态保存到提供的`Bundle`对象。

1.  实现`onCreate`方法，从提供的`Bundle`对象（假设有的话）恢复保存的状态。

1.  向你之前编写的`Calculator`类中添加所需的功能，使科学`Button`小部件按预期工作。

# 支持硬件键盘

我们在这里开发的计算器现在是一个很棒的 Android 屏幕计算器应用程序，具有你所期望的简单和科学功能。然而，如果一个设备有硬件键盘，用户可能会期望能够使用它，目前他们做不到。此外，如果设备没有触摸屏，点击屏幕按钮会很快变得令人沮丧。我们需要为应用程序实现硬件键盘支持。

实现硬件键盘处理代码只有在你完成了“尝试英雄”部分并构建了一个`Calculator`类来执行所需功能时才有用。为了处理硬件键盘事件，你会使用`KeyEvent.Callback`接口中声明的方法。`Activity`类已经实现了`KeyEvent.Callback`接口，并为所有方法提供了默认处理。对于这些按键事件的处理，我们只需要覆盖`onKeyDown`方法。

对于这个`onKeyDown`实现，最好确保按键事件来自硬件键盘，方法是检查`KeyEvent`的标志。在自行处理之前，将其传递给父类也是一个好主意。最后，如果你在 Android 2.0（API 级别 5）或更高版本上工作，你应该在处理之前检查`KeyEvent`是否没有被取消（这也是`KeyEvent`标志之一）。以下是我的`onKeyDown`方法实现中的代码片段：

```kt
@Override
public boolean onKeyDown(
        final int keyCode,
        final KeyEvent event) {

    super.onKeyDown(keyCode, event);

    boolean handled = false;

    if((event.getFlags() & KeyEvent.FLAG_SOFT_KEYBOARD) == 0) {
 switch(keyCode) {
 case KeyEvent.KEYCODE_0:
 calculator.zero();
 handled = true;
 break;
 case KeyEvent.KEYCODE_1:
 calculator.one();
 handled = true;
 break;
 // Cases for each of the handles keys
 }

        display.setText(calculator.getCurrentDisplay());
    }

    return handled;
}
```

上述代码片段调用了每种可以在硬件键盘上按下的不同键的方法。

### 注意事项

如果你的 Android 设备没有硬件键盘，你可以使用模拟器测试这段代码——你的 PC 键盘和模拟器显示右侧的屏幕键盘都被模拟器归类为硬件键盘。

# 添加显示动画

目前，该应用程序具备成为一个优秀计算器应用程序的所有要素。然而，当前显示只是一个简单的`TextView`对象。为了提升用户体验，我们应该使用`ViewSwitcher`对象在计算器操作更改或按下“等于”按钮时替换`TextView`。

# 动作时间——显示动画

为了为计算器显示构建一个漂亮的滑出滑入动画，我们需要定义自己的动画并将它们绑定到`ViewSwitcher`对象。这也需要我们修改 Java 代码以处理新的机制。由于我们不想在每次输入新数字时都让视图动画化，我们将直接更改当前屏幕上的`TextView`。

1.  在`res/anim`目录中创建一个名为`slide_out_top.xml`的新 XML 资源文件，并在编辑器或 IDE 中打开它。

1.  在动画资源中声明一个从`0%`到`100%`的 y 轴平移动画作为唯一的元素：

    ```kt
    <translate

        android:fromYDelta="0%"
        android:toYDelta="-100%"
        android:duration="300"/>
    ```

1.  在`res/anim`目录中创建一个名为`slide_in_bottom.xml`的新 XML 资源文件，并在编辑器或 IDE 中打开这个文件。

1.  在动画资源中声明一个从`100%`到`0%`的 y 轴平移动画作为唯一的元素：

    ```kt
    <translate

        android:fromYDelta="100%"
        android:toYDelta="0%"
        android:duration="300"/>
    ```

1.  打开你的`display.xml`文件，或者在你的编辑器或 IDE 中打开两个`main.xml`文件，具体打开哪一个取决于你是否完成了“尝试英雄——布局包含”部分。

1.  在用于显示的`RelativeLayout`中，使用两个新的动画资源将名为`display`的`TextView`替换为`ViewSwitcher`元素：

    ```kt
    <ViewSwitcher android:id="@+id/display"
                  android:inAnimation="@anim/slide_in_bottom"
                  android:outAnimation="@anim/slide_out_top"
                  android:layout_alignParentTop="true"
                  android:layout_toLeftOf="@id/delete"
                  android:layout_width="fill_parent"
                  android:layout_height="wrap_content">
    ```

1.  作为`ViewSwitcher`的子元素，声明两个具有`CalculatorTextDisplay`样式的`TextView`元素：

    ```kt
    <TextView style="@style/CalculatorTextDisplay"
              android:text="0"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  两个`TextView`元素将彼此完全相同。

## *刚才发生了什么？*

使用`ViewSwitcher`进行显示将导致现有 Java 代码崩溃，因为 Java 代码会期望该对象是某种`TextView`。你需要做的是使用`ViewSwitcher.getCurrentView`更新显示，而不是`ViewSwitcher`本身。

当使用操作`Button`时，例如乘或等于`Button`，你将希望将下一个显示内容放置在`ViewSwitcher.getNextView`小部件上，然后调用`ViewSwitcher.showNext()`方法。数字向上消失，新内容从显示底部出现的动画简单明了。这也是计算器应用程序中经常使用的，意味着用户通常会感到舒适。

在这个应用程序的案例中，动画更多的是视觉效果而非实用。然而，如果你在计算器中实现了一个历史栈，当用户按下“返回”`Button`时，动画可以反转。在计算器中，一个历史栈是一个非常实用的结构，因为它允许对同一计算进行轻微变化的反复运行。

## 动手英雄——圆角处理

在这一点上，这个计算器应用程序相当完整。它已经过样式设计，有一些不错的视觉效果，并且按预期工作。然而，它确实有一些注意事项——科学计算布局在小屏幕设备上工作得不是很好。以下截图是在小屏幕手机上以科学布局运行的应用程序：

![动手英雄——圆角处理](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_10_12.jpg)

前面的图片还展示了某些设备是如何为主题应用程序着色的。为了确保应用程序在所有设备上都能良好运行：

1.  为小屏幕设备定义一个新的`values`目录。

1.  在包含比默认样式边距和填充更小的样式的目录中创建一个新的`styles.xml`文件。

1.  在具有横向取向的小屏幕设备上，减小`display`字体的大小。

这种圆角处理过程将遵循大多数成功的 Android 应用程序项目。这是关于在各种各样的模拟器配置和设备上尝试应用程序，然后利用资源加载器确保应用程序在尽可能多的设备上良好运行的问题。

# 总结

创建应用程序主题是新的应用程序成功的关键部分，无论运行在 Android、桌面还是 Web 上。我们已经探讨了如何利用 Android 提供的各种工具，以保持应用程序的一致性，从而使其对用户友好。

一个应用程序的主题及其外观和感觉远超出简单的样式设计。你个人使用应用程序的次数越多，你越会发现稍微不同的颜色或过渡动画会有所帮助的地方。每一个小的不同之处都使得应用程序真正对用户友好，因为它让应用程序看起来更加精致。

尽管运行在数百种截然不同的设备上，安卓让开发者能够轻松地保持应用程序运行，就像它们是为该硬件特别构建的一样。资源加载系统是安卓中最关键的结构之一，不利用它，对应用程序来说可能是自杀式的行为。

我强烈建议你熟悉现有的安卓应用程序，以及其他移动设备上的应用程序。了解如何使用像样的图像处理应用程序也会有很大帮助。在开始构建它们之前，为每个屏幕绘制一张图表，而铅笔和纸通常是了解用户界面想法的最佳方式，在你开始编码之前。

仔细考虑你在哪里可以使用现有的安卓图标和样式，以及你会在哪里想要替换或扩展它们。你总是希望保持应用程序的一致性，但添加一些炫目的视觉糖果往往能使应用程序从众多竞品中脱颖而出。

结合 XML 资源和 Java 语言，安卓是一个极具吸引力的设计和编码平台。它被广泛部署并拥有出色的开发者支持。有数十家硬件制造商在生产各种形状和大小的安卓设备，还有成千上万的开发者在开发应用程序。

在这本书中，我们致力于利用安卓平台构建以用户为中心、易于使用且界面美观的应用程序。安卓平台和安卓市场为新想法提供了固定的受众和巨大的曝光度。从现在开始，你应该能够为安卓生态系统添加你自己的独特想法和工作。任何已经完成的事情总是可以做得更好，而任何尚未完成的事情，都有人在等待。无论你是团队的一员，还是在夜晚的阁楼里努力开发下一个大项目，成功应用程序的关键在于一个出色的用户界面。


# 附录 A. 快速测验答案

# 第一章

## 布局作为 XML 文件

| 问题编号 | 答案 |
| --- | --- |
| 1 | b |
| 2 | d |
| 3 | c |

## 填充一个活动

| 问题编号 | 答案 |
| --- | --- |
| 1 | b |
| 2 | c |
| 3 | c |

# 第二章

## 列表视图和适配器

| 问题编号 | 答案 |
| --- | --- |
| 1 | c |
| 2 | a |
| 3 | c |

# 第三章

## 图库对象和 ImageViews

| 问题编号 | 答案 |
| --- | --- |
| 1 | c |
| 2 | b |
| 3 | a |

# 第四章

## 意图和活动

| 问题编号 | 答案 |
| --- | --- |
| 1 | c |
| 2 | b |
| 3 | a |

# 第五章：

## 自定义布局

| 问题编号 | 答案 |
| --- | --- |
| 1 | d |
| 2 | b |
| 3 | c |

# 第六章

## 文本输入

| 问题编号 | 答案 |
| --- | --- |
| 1 | c |
| 2 | c |
| 3 | a |

# 第八章

## WebView 组件

| 问题编号 | 答案 |
| --- | --- |
| 1 | d |
| 2 | b |
| 3 | d |

## WebView 与原生布局

| 问题编号 | 答案 |
| --- | --- |
| 1 | a |
| 2 | c |
| 3 | c |

# 第十章

## 布局资源

| 问题编号 | 答案 |
| --- | --- |
| 1 | d *提示：（它们作为对象加载，而不是编译成类）* |
| 2 | d |
| 3 | c |

## 九宫格图片

| 问题编号 | 答案 |
| --- | --- |
| 1 | b |
| 2 | c |
| 3 | a |

## 安卓资源

| 问题编号 | 答案 |
| --- | --- |
| 1 | c |
| 2 | a |
| 3 | c |
