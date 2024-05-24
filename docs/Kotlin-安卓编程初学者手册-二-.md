# Kotlin 安卓编程初学者手册（二）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 CardView 和 ScrollView 创建美丽的布局

这是我们在专注于 Kotlin 和面向对象编程之前关于布局的最后一章。我们将对我们已经看到的一些不同属性进行正式学习，并且还将介绍两种更酷的布局：`ScrollView`和`CardView`。最后，我们将在平板模拟器上运行`CardView`项目。

在本章中，我们将涵盖以下主题：

+   编译 UI 属性的快速总结

+   使用`ScrollView`和`CardView`构建迄今为止最漂亮的布局

+   切换和自定义主题

+   创建和使用平板模拟器

让我们首先回顾一些属性。

# 属性-快速总结

在过去的几章中，我们已经使用和讨论了相当多不同的属性。我认为值得对一些更常见的属性进行快速总结和进一步调查。

## 使用 dp 进行大小调整

众所周知，有成千上万种不同的 Android 设备。Android 使用**密度无关像素**或**dp**作为测量单位，以尝试拥有一个可以跨不同设备工作的测量系统。其工作原理是首先计算应用程序运行的设备上的像素密度。

### 提示

我们可以通过将屏幕的水平分辨率除以屏幕的水平尺寸（以英寸为单位）来计算密度。这一切都是在我们的应用程序运行的设备上动态完成的。

我们只需在设置小部件的各种属性的大小时，使用`dp`与数字结合即可。使用密度无关的测量，我们可以设计布局，使其在尽可能多的不同屏幕上呈现统一的外观。

那么问题解决了吗？我们只需在所有地方使用`dp`，我们的布局就能在任何地方正常工作了吗？不幸的是，密度独立性只是解决方案的一部分。在本书的其余部分中，我们将看到如何使我们的应用程序在各种不同的屏幕上看起来很棒。

例如，我们可以通过向其属性添加以下代码来影响小部件的高度和宽度：

```kt
...
android:height="50dp"
android:width="150dp"
...
```

或者，我们可以使用属性窗口，并通过适当的编辑框的舒适性来添加它们。您使用哪种选项将取决于您的个人偏好，但有时在特定情况下，一种方式会感觉比另一种方式更合适。无论哪种方式都是正确的，当我们在制作应用程序时，我通常会指出一种方式是否比另一种方式*更好*。

我们还可以使用相同的`dp`单位来设置其他属性，例如边距和填充。我们将在一分钟内更仔细地研究边距和填充。

## 使用 sp 调整字体大小

另一个用于调整 Android 字体大小的设备相关单位是**可伸缩像素**或**sp**。`sp`测量单位用于字体，并且与`dp`完全相同，具有像素密度相关性。

Android 设备在决定您的字体大小时将使用额外的计算，这取决于您使用的`sp`值和用户自己的字体大小设置。因此，如果您在具有正常大小字体的设备和模拟器上测试应用程序，那么视力受损的用户（或者只是喜欢大字体的用户）并且将其字体设置为大号的用户将看到与您在测试期间看到的内容不同。

如果您想尝试调整 Android 设备的字体大小设置，可以通过选择**设置 | 显示 | 字体大小**来进行调整：

![使用 sp 调整字体大小](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_21.jpg)

正如我们在前面的屏幕截图中看到的，有相当多的设置，如果您尝试在**巨大**上进行设置，差异是巨大的！

我们可以在任何具有文本的小部件中使用`sp`设置字体大小。这包括`Button`，`TextView`以及调色板中**Text**类别下的所有 UI 元素，以及其他一些元素。我们可以通过设置`textSize`属性来实现：

```kt
android:textSize="50sp"
```

与往常一样，我们也可以使用属性窗口来实现相同的效果。

## 使用 wrap 或 match 确定大小

我们还可以决定 UI 元素的大小以及许多其他 UI 元素与包含/父元素的关系。我们可以通过将`layoutWidth`和`layoutHeight`属性设置为`wrap_content`或`match_parent`来实现。

例如，假设我们将布局上的一个孤立按钮的属性设置为以下内容：

```kt
...
android:layout_width="match_parent"
android:layout_height="match_parent"
....
```

然后，按钮将在高度和宽度上扩展以匹配父级。我们可以看到下一张图片中的按钮填满了整个屏幕：

![使用 wrap 或 match 确定大小](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_22.jpg)

按钮更常见的是`wrap_content`，如下面的代码所示：

```kt
....
android:layout_width="wrap_content"
android:layout_height="wrap_content"
....
```

这将导致按钮的大小与其需要的内容一样大（宽度和高度为`dp`，文本为`sp`）。

## 使用填充和边距

如果您曾经做过任何网页设计，您将非常熟悉接下来的两个属性。**填充**是从小部件的边缘到小部件中内容的开始的空间。**边距**是留在小部件外的空间，用于其他小部件之间的间隔-包括其他小部件的边距，如果它们有的话。这是一个可视化表示：

![使用填充和边距](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_23.jpg)

我们可以简单地为所有边指定填充和边距，如下所示：

```kt
...
android:layout_margin="43dp"
android:padding="10dp"
...
```

注意边距和填充的命名约定略有不同。填充值只称为`padding`，但边距值称为`layout_margin`。这反映了填充只影响 UI 元素本身，但边距可以影响布局中的其他小部件。

或者，我们可以指定不同的顶部、底部、左侧和右侧的边距和填充，如下所示：

```kt
android:layout_marginTop="43dp"
android:layout_marginBottom="43dp"
android:paddingLeft="5dp"
android:paddingRight="5dp"
```

为小部件指定边距和填充值是可选的，如果没有指定任何值，将假定为零。我们还可以选择指定一些不同边的边距和填充，但不指定其他边，就像前面的示例一样。

很明显，我们设计布局的方式非常灵活，但要精确地使用这些选项，需要一些练习。我们甚至可以指定负边距值来创建重叠的小部件。

让我们再看看一些属性，然后我们将继续玩一个时尚布局`CardView`。

## 使用`layout_weight`属性

权重是相对于其他 UI 元素的相对量。因此，要使`layout_weight`有用，我们需要在两个或更多元素上为`layout_weight`属性分配一个值。

然后，我们可以分配总共加起来为 100%的部分。这对于在 UI 的各个部分之间划分屏幕空间特别有用，我们希望它们占用的相对空间在屏幕大小不同的情况下保持不变。

将`layout_weight`与`sp`和`dp`单位结合使用可以创建简单灵活的布局。例如，看看这段代码：

```kt
<Button
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="0.10"
        android:text="one tenth" />

<Button
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="0.20"
        android:text="two tenths" />

<Button
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="0.30"
        android:text="three tenths" />

<Button
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="0.40"
        android:text="four tenths" />
```

这段代码将会做什么：

![使用 layout_weight 属性](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_24.jpg)

注意，所有`layout_height`属性都设置为`0dp`。实际上，`layout_weight`属性正在替换`layout_height`属性。我们使用`layout_weight`的上下文很重要（否则它不起作用），我们很快就会在一个真实的项目中看到这一点。还要注意，我们不必使用一的分数；我们可以使用整数、百分比和任何其他数字。只要它们相对于彼此，它们可能会实现您想要的效果。请注意，`layout_weight`仅在某些上下文中起作用，随着我们构建更多的布局，我们将看到它在哪些上下文中起作用。

## 使用重力

重力可以成为我们的朋友，并且可以在布局中以许多方式使用。就像太阳系中的重力一样，它通过将物品朝特定方向移动来影响物品的位置，就好像它们受到重力的作用一样。了解重力的作用最好的方法是查看一些示例代码和图表：

```kt
android:gravity="left|center_vertical"
```

如果按钮（或其他小部件）的`gravity`属性设置为`left|center_vertical`，就像前面的代码所示，它将产生以下效果：

![使用重力](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_26.jpg)

注意小部件的内容（在本例中为按钮的文本）确实是左对齐和垂直居中的。

此外，小部件可以通过`layout_gravity`元素影响其在布局元素中的位置，如下所示：

```kt
android:layout_gravity="left"
```

这将设置小部件在其布局中，如预期的那样：

![使用重力](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_25.jpg)

前面的代码允许同一布局中的不同小部件受到影响，就好像布局具有多个不同的重力一样。

通过使用与小部件相同的代码，可以通过其父布局的`gravity`属性来影响布局中所有小部件的内容：

```kt
android:gravity="left"
```

实际上，有许多属性超出了我们讨论的范围。我们在本书中不需要的属性很多，有些相当晦涩，所以您可能在整个 Android 生涯中都不需要它们。但其他一些属性是相当常用的，包括`background`、`textColor`、`alignment`、`typeface`、`visibility`和`shadowColor`。让我们现在探索一些更多的属性和布局。

# 使用 CardView 和 ScrollView 构建 UI

以通常的方式创建一个新项目。将项目命名为`CardView Layout`，并选择**空活动**项目模板。将其余所有设置保持与之前的所有项目相同。

为了能够编辑我们的主题并正确测试结果，我们需要生成我们的布局文件，并编辑 Kotlin 代码，通过调用 `onCreate` 函数中的 `setContentView` 函数来显示它。我们将在 `ScrollView` 布局内设计我们的 `CardView` 杰作，正如其名字所示，允许用户滚动布局内容。

右键单击`layout`文件夹，然后选择**新建**。注意有一个**布局资源文件**的选项。选择**布局资源文件**，然后您将看到**新资源文件**对话框窗口。

在**文件名**字段中输入 `main_layout`。名称是任意的，但这个布局将是我们的主要布局，所以名称很明显。

注意它被设置为**LinearLayout**作为**根**元素选项。将其更改为 `ScrollView`。这种布局类型似乎就像 `LinearLayout` 一样工作，除了当屏幕上有太多内容要显示时，它将允许用户通过用手指滑动来滚动内容。

点击**确定**按钮，Android Studio 将在名为 `main_layout` 的 XML 文件中生成一个新的 `ScrollView` 布局，并将其放置在 `layout` 文件夹中，准备好为我们构建基于 `CardView` 的 UI。

您可以在下一个截图中看到我们的新文件：

![使用 CardView 和 ScrollView 构建 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_03.jpg)

Android Studio 还将打开准备就绪的 UI 设计器。

## 使用 Kotlin 代码设置视图

与以前一样，我们现在将通过在`MainActivity.kt`文件中调用`setContentView`函数来加载`main_layout.xml`文件作为我们应用程序的布局。

选择`MainActivity.kt`选项卡。如果选项卡不是默认显示的，您可以在项目资源管理器中找到它，路径为`app/java/your_package_name`，其中`your_package_name`等于您创建项目时选择的包名称。

修改`onCreate`函数中的代码，使其与下面的代码完全一样。我已经突出显示了您需要添加的行：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
   super.onCreate(savedInstanceState)
   setContentView(R.layout.main_layout);
}
```

现在可以运行该应用程序，但除了一个空的`ScrollView`布局外，没有其他可见的内容。

## 添加图像资源

我们将需要一些图像来完成这个项目。这样我们就可以演示如何将它们添加到项目中（本节），并在`CardView`布局中整洁地显示和格式化它们（下一节）。

您从哪里获取图像并不重要。这个练习的目的是实际的动手经验。为了避免版权和版税问题，我将使用 Packt Publishing 网站上的一些书籍图像。这也使我能够为您提供完成项目所需的所有资源，如果您不想麻烦获取自己的图像的话。请随意在`Chapter05/CardViewLayout/res/drawable`文件夹中更换图像。

有三个图像：`image_1.png`，`image_2.png`和`image_3.png`。要将它们添加到项目中，请按照以下步骤操作。

1.  使用操作系统的文件浏览器查找图像文件。

1.  将它们全部高亮显示，然后按*Ctrl* + *C*进行复制。

1.  在 Android Studio 项目资源管理器中，通过左键单击选择`res/drawable`文件夹。

1.  右键单击`drawable`文件夹，选择**粘贴。**

1.  在弹出窗口中询问您**选择目标目录**，单击**确定**接受默认目标，即`drawable`文件夹。

1.  再次单击**确定**以**复制指定的文件**。

现在您应该能够在`drawable`文件夹中看到您的图像，以及 Android Studio 在创建项目时放置在那里的其他一些文件，如下一个截图所示：

![添加图像资源](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_04.jpg)

在我们继续进行`CardView`之前，让我们设计一下我们将放在其中的内容。

## 为卡片创建内容

我们接下来需要做的是为我们的卡片创建内容。将内容与布局分开是有意义的。我们将创建三个单独的布局，称为`card_contents_1`，`card_contents_2`和`card_contents_3`。它们将分别包含一个`LinearLayout`，其中将包含实际的图像和文本。

让我们再创建三个带有`LinearLayout`的布局：

1.  右键单击`layout`文件夹，选择**新建布局资源文件**。

1.  将文件命名为`card_contents_1`，并确保**LinearLayout**被选为**根元素**

1.  单击**确定**将文件添加到`layout`文件夹

1.  重复步骤一到三两次，每次更改文件名为`card_contents_2`和`card_contents_3`

现在，选择`card_contents_1.xml`选项卡，并确保您处于设计视图中。我们将拖放一些元素到布局中以获得基本结构，然后我们将添加一些`sp`，`dp`和 gravity 属性使它们看起来漂亮：

1.  将一个`TextView`小部件拖放到布局的顶部。

1.  将一个`ImageView`小部件拖放到`TextView`小部件下方的布局中。

1.  在**资源**弹出窗口中，选择**项目** | **image_1**，然后单击**确定**。

1.  在图像下方再拖放两个**TextView**小部件。

1.  现在您的布局应该是这样的：![为卡片创建内容](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_05.jpg)

现在，让我们使用一些材料设计指南使布局看起来更吸引人。

### 提示

当您进行这些修改时，底部布局的 UI 元素可能会从设计视图的底部消失。如果这种情况发生在您身上，请记住您可以随时从调色板下方的**组件树**窗口中选择任何 UI 元素。或者，参考下一个提示。

另一种减少问题的方法是使用更大的屏幕，如下面的说明所述：

### 提示

我将默认设备更改为**Pixel 2 XL**以创建上一个截图。我会保持这个设置，除非我特别提到我正在更改它。它允许在布局上多出一些像素，这样布局就更容易完成。如果您想做同样的事情，请查看设计视图上方的菜单栏，单击设备下拉菜单，并选择您的设计视图设备，如下截图所示：

![为卡片创建内容](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_08.jpg)

1.  将`TextView`小部件的`textSize`属性设置为`24sp`。

1.  将**Layout_Margin** | **all**属性设置为`16dp`。

1.  将`text`属性设置为**通过构建 Android 游戏学习 Java**（或者适合您图像的标题）。

1.  在`ImageView`上，将`layout_width`和`layout_height`设置为`wrap_content`。

1.  在`ImageView`上，将`layout_gravity`设置为`center_horizontal`。

1.  在`ImageView`下方的`TextView`上，将`textSize`设置为`16sp`。

1.  在相同的`TextView`上，将**Layout_Margin** | **all**设置为`16dp`。

1.  在相同的`TextView`上，将`text`属性设置为`通过构建 6 个可玩游戏从零开始学习 Java 和 Android`（或者描述您的图像的内容）。

1.  在底部的`TextView`上，将`text`属性更改为`立即购买`。

1.  在相同的`TextView`上，将**Layout_Margin** | **all**设置为`16dp`。

1.  在相同的`TextView`上，将`textSize`属性设置为`24sp`。

1.  在相同的`TextView`上，将`textColor`属性设置为`@color/colorAccent`。

1.  在包含所有其他元素的`LinearLayout`上，将`padding`设置为`15dp`。请注意，从**Component Tree**窗口中选择`LinearLayout`是最容易的。

1.  此时，您的布局将非常类似于以下截图：![为卡片创建内容](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_06.jpg)

现在，使用完全相同的尺寸和颜色布局其他两个文件（`card_contents_2`和`card_contents_3`）。当您收到**资源**弹出窗口以选择图像时，分别使用`image_2`和`image_3`。还要更改前两个`TextView`元素上的所有`text`属性，以使标题和描述是唯一的。标题和描述并不重要；我们学习的是布局和外观。

### 提示

请注意，所有尺寸和颜色都来自[`material.io/design/introduction`](https://material.io/design/introduction)上的材料设计网站，以及[`developer.android.com/guide/topics/ui/look-and-feel`](https://developer.android.com/guide/topics/ui/look-and-feel)上的 Android 特定 UI 指南。与本书一起学习或在完成本书后不久进行学习都是非常值得的。

现在我们可以转向`CardView`。

## 为 CardView 定义尺寸

右键单击`values`文件夹，然后选择**New** | **Values resource file**。在**New Resource File**弹出窗口中，将文件命名为`dimens.xml`（表示尺寸）并单击**OK**。我们将使用这个文件来创建一些常见的值，我们的`CardView`对象将通过引用它们来使用。

为了实现这一点，我们将直接编辑 XML。编辑`dimens.xml`文件，使其与以下代码相同：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <dimen name="card_corner_radius">16dp</dimen>
    <dimen name="card_margin">10dp</dimen>
</resources>
```

确保它完全相同，因为一个小的遗漏或错误可能导致错误并阻止项目工作。

我们定义了两个资源，第一个称为`card_corner_radius`，值为`16dp`，第二个称为`card_margin`，值为`10dp`。

我们将在`main_layout`文件中引用这些资源，并使用它们来一致地配置我们的三个`CardView`元素。

## 将 CardView 添加到我们的布局

切换到`main_layout.xml`选项卡，并确保您处于设计视图中。您可能还记得，我们现在正在使用一个`ScrollView`，它将滚动我们应用的内容，就像 Web 浏览器滚动网页内容一样，内容无法适应一个屏幕。

`ScrollView`有一个限制 - 它只能有一个直接的子布局。我们希望它包含三个`CardView`元素。

为了解决这个问题，从调色板的`Layouts`类别中拖动一个`LinearLayout`。确保选择**LinearLayout (vertical)**，如调色板中的图标所示：

![将 CardView 添加到我们的布局](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_07.jpg)

我们将在`LinearLayout`内添加我们的三个`CardView`对象，然后整个内容将平稳滚动，没有任何错误。

`CardView`可以在调色板的**Containers**类别中找到，所以切换到那里并找到`CardView`。

将`CardView`对象拖放到设计中的`LinearLayout`上，您将在 Android Studio 中收到一个弹出消息。这是这里所示的消息：

![将 CardView 添加到我们的布局](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_09.jpg)

点击**确定**按钮，Android Studio 将在后台进行一些工作，并向项目添加必要的部分。Android Studio 已经向项目添加了一些更多的类，具体来说，这些类为旧版本的 Android 提供了`CardView`功能，否则这些功能是不具备的。

现在你应该在设计中有一个`CardView`对象。在它里面没有内容的情况下，`CardView`对象只能在**组件树**窗口中轻松地看到。

通过**组件树**窗口选择`CardView`对象，并配置以下属性：

+   将`layout_width`设置为`wrap_content`

+   将`layout_gravity`设置为`center`

+   将**Layout_Margin** | **all**设置为`@dimens/card_margin`

+   将`cardCornerRadius`设置为`@dimens/card_corner_radius`

+   将`cardEleveation`设置为`2dp`

现在，切换到**文本**选项卡，你会发现你有一个非常类似于下面代码的东西：

```kt
<androidx.cardview.widget.CardView
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:layout_gravity="center"
   android:layout_margin="@dimen/card_margin"
   app:cardCornerRadius="@dimen/card_corner_radius"
   app:cardElevation="2dp" />
```

前面的代码列表只显示了`CardView`对象的代码。

当前问题是我们的`CardView`对象是空的。让我们通过添加`card_contents_1.xml`的内容来解决这个问题。以下是如何做到这一点。

## 在另一个布局中包含布局文件

我们需要稍微编辑代码，原因如下。我们需要向代码中添加一个`include`元素。`include`元素是将从`card_contents_1.xml`布局中插入内容的代码。问题在于，要添加这段代码，我们需要稍微改变`CardView` XML 的格式。当前的格式是用一个单一的标签开始和结束`CardView`对象，如下所示：

```kt
<androidx.cardview.widget.CardView
…
…/>
```

我们需要将格式更改为像这样的单独的开放和关闭标签（暂时不要更改任何内容）：

```kt
<androidx.cardview.widget.CardView
…
…
</androidx.cardview.widget.CardView>
```

这种格式的改变将使我们能够添加`include…`代码，我们的第一个`CardView`对象将完成。考虑到这一点，编辑`CardView`的代码，确保与以下代码完全相同。我已经突出显示了两行新代码，但也请注意，`cardElevation`属性后面的斜杠也已经被移除：

```kt
<androidx.cardview.widget.CardView
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:layout_gravity="center"
   android:layout_margin="@dimen/card_margin"
   app:cardCornerRadius="@dimen/card_corner_radius"
   app:cardElevation="2dp" >

 <include layout="@layout/card_contents_1" />

</androidx.cardview.widget.CardView>

```

你现在可以在可视化设计师中查看`main_layout`文件，并查看`CardView`对象内的布局。可视化设计师无法展现`CardView`的真实美感。我们很快就会在完成的应用程序中看到所有`CardView`小部件很好地滚动。以下是我们目前的进度截图：

![在另一个布局中包含布局文件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_10.jpg)

在布局中再添加两个`CardView`小部件，并将它们配置成与第一个相同，只有一个例外。在第二个`CardView`对象上，将`cardElevation`设置为`22dp`，在第三个`CardView`对象上，将`cardElevation`设置为`42dp`。同时，将`include`代码更改为分别引用`card_contents_2`和`card_contents_3`。

### 提示

你可以通过复制和粘贴`CardView` XML 并简单修改高程和`include`代码来快速完成这一步，就像前面的段落中提到的那样。

现在我们可以运行应用程序，看到我们三个漂亮的、高架的`CardView`小部件在运行中的效果。在下面的截图中，我将两个截图并排放置，这样你就可以看到一个完整的`CardView`布局的效果（在左边），以及右边的图像中，高程设置产生的效果，产生了非常令人愉悦的深度和阴影效果：

![在另一个布局中包含布局文件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_11.jpg)

### 注意

这张图片在黑白印刷版本的书中可能会有些不清晰。一定要构建并运行应用程序，以查看这个很酷的效果。

现在我们可以尝试编辑应用程序的主题。

# 主题和材料设计

从技术上讲，创建一个新主题非常容易，我们很快就会看到如何做到这一点。然而，从艺术角度来看，这更加困难。选择哪些颜色能很好地搭配在一起，更不用说适合你的应用程序和图像，这更加困难。幸运的是，我们可以求助于材料设计。

材料设计为 UI 设计的每个方面都提供了指南，所有这些指南都有很好的文档。甚至我们在`CardView`项目中使用的文本和填充的大小都是从材料设计指南中获取的。

材料设计不仅使您能够设计自己的配色方案，而且还提供了现成的配色方案调色板。

### 提示

这本书不是关于设计，尽管它是关于实施设计。为了让您开始，我们设计的目标可能是使我们的 UI 独特并在同一时间脱颖而出，同时使其对用户来说舒适甚至熟悉。

主题是由 XML `style`项构建的。我们在第三章中看到了`styles.xml`文件，*探索 Android Studio 和项目结构*。`styles`文件中的每个项目都定义了外观并为其命名，例如`colorPrimary`或`colorAccent`。

剩下的问题是，我们如何选择颜色，以及如何在主题中实现它们？第一个问题的答案有两种可能的选择。第一个答案是参加设计课程，并花费接下来的几年时间学习 UI 设计。更有用的答案是使用内置主题之一，并根据材料设计指南进行自定义，该指南在[`developer.android.com/guide/topics/ui/look-and-feel/`](https://developer.android.com/guide/topics/ui/look-and-feel/)中对每个 UI 元素进行了深入讨论。

我们现在将执行后者。

## 使用 Android Studio 主题设计师

从 Android Studio 主菜单中，选择**工具** | **主题编辑器**。在左侧，注意显示主题外观的 UI 示例，右侧是编辑主题方面的控件：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_12.jpg)

如前所述，创建自己的主题最简单的方法是从现有主题开始，然后进行编辑。在**主题**下拉菜单中，选择您喜欢外观的主题。我选择了**AppCompat** **Dark**：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_13.jpg)

选择右侧要更改颜色的任何项目，并在随后的屏幕中选择颜色：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_14.jpg)

您将被提示为新主题选择一个名称。我称我的为`Theme.AppCompat.MyDarkTheme`：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_15.jpg)

现在，单击**修复**文本以将您的主题应用于当前应用程序，如下图所示：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_16.jpg)

然后可以在模拟器上运行应用程序，查看主题的效果：

![使用 Android Studio 主题设计师](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_17.jpg)

到目前为止，我们所有的应用都在手机上运行。显然，Android 设备生态系统的一个重要部分是平板电脑。让我们看看如何在平板电脑模拟器上测试我们的应用程序，以及预览这个多样化生态系统可能会给我们带来的一些问题，然后我们可以开始学习如何克服这些问题。

# 创建平板电脑模拟器

选择**工具** | **AVD 管理器**，然后单击**创建虚拟设备...**按钮在**您的虚拟设备**窗口上。您将在以下屏幕截图中看到**选择硬件**窗口：

![创建平板电脑模拟器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_18.jpg)

从**类别**列表中选择**平板电脑**选项，然后从可用平板电脑选择中突出显示**Pixel C**平板电脑。这些选择在上一个屏幕截图中突出显示。

### 提示

如果您在将来某个时候阅读此内容，Pixel C 选项可能已经更新。选择平板电脑的重要性不如练习创建平板电脑模拟器并测试您的应用程序。

点击**下一步**按钮。在接下来的**系统映像**窗口中，只需点击**下一步**，因为这将选择默认的系统映像。选择自己的映像可能会导致模拟器无法正常工作。

最后，在**Android 虚拟设备**屏幕上，您可以将所有默认选项保持不变。如果愿意，可以更改模拟器的**AVD 名称**或**启动方向**（纵向或横向）：

创建平板模拟器

当您准备好时，点击**完成**按钮。

现在，每当您从 Android Studio 运行您的应用程序时，您将有选择**Pixel C**（或您创建的任何平板电脑）的选项。这是我 Pixel C 模拟器运行`CardView`应用程序的屏幕截图：

![创建平板模拟器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_05_20.jpg)

还不错，但有相当多的浪费空间，看起来有点稀疏。让我们尝试横向模式。如果您尝试在平板电脑上以横向模式运行应用程序，结果会更糟。我们可以从中学到的是，我们将不得不为不同大小的屏幕和不同方向设计我们的布局。有时，这些将是智能设计，可以适应不同的大小或方向，但通常它们将是完全不同的设计。

# 常见问题

问：我需要掌握关于材料设计的所有知识吗？

答：不需要。除非你想成为专业设计师。如果你只想制作自己的应用程序并在 Play 商店上出售或免费提供它们，那么只知道基础知识就足够了。

# 总结

在本章中，我们构建了美观的`CardView`布局，并将它们放在`ScrollView`布局中，以便用户可以通过布局的内容进行滑动，有点像浏览网页。最后，我们启动了一个平板模拟器，并看到如果我们想要适应不同的设备大小和方向，我们需要在布局设计上变得聪明起来。在第二十四章中，*设计模式，多个布局和片段*，我们将开始将我们的布局提升到下一个水平，并学习如何通过使用 Android 片段来应对如此多样化的设备。

然而，在这样做之前，更好地了解 Kotlin 以及如何使用它来控制我们的 UI 并与用户交互将对我们有所裨益。这将是接下来七章的重点。

当然，此时的悬而未决的问题是，尽管学到了很多关于布局、项目结构、Kotlin 和 XML 之间的连接以及其他许多内容，但是我们的 UI，无论多么漂亮，实际上并没有做任何事情！我们需要严肃地提升我们的 Kotlin 技能，同时学习如何在 Android 环境中应用它们。

在下一章中，我们将做到这一点。我们将看看如何通过与**Android Activity 生命周期**一起工作，添加 Kotlin 代码，以便在我们需要的确切时刻执行它。


# 第六章：Android 生命周期

在本章中，我们将熟悉 Android 应用程序的生命周期。计算机程序有生命周期这个想法一开始可能听起来很奇怪，但很快就会有意义。

生命周期是所有 Android 应用程序与 Android 操作系统交互的方式。就像人类的生命周期使他们能够与周围的世界互动一样，我们别无选择，只能与 Android 生命周期互动，并且必须准备处理许多不可预测的事件，如果我们希望我们的应用程序能够生存下来。

我们将探讨应用程序从创建到销毁经历的生命周期阶段，以及这如何帮助我们知道*何时*根据我们想要实现的目标放置我们的 Kotlin 代码。

在本章中，我们将探讨以下主题：

+   Android 应用程序的生活和时代

+   覆盖过程和`override`关键字

+   Android 生命周期的阶段

+   我们究竟需要了解和做些什么来编写我们的应用程序

+   生命周期演示应用程序

+   Android 代码的结构，以及为下一章深入学习 Kotlin 编码做准备

让我们开始学习 Android 生命周期。

# Android 应用程序的生活和时代

我们已经谈到了我们代码的结构；我们知道我们可以编写类，在这些类中我们有函数，这些函数包含我们的代码，完成任务。我们也知道当我们想要函数中的代码运行（也就是说，被**执行**）时，我们通过使用它的名称**调用**该函数。

此外，在第二章中，*Kotlin、XML 和 UI 设计师*，我们了解到 Android 在应用程序准备启动之前调用`onCreate`函数。当我们输出到 logcat 窗口并使用`Toast`类向用户发送弹出消息时，我们就看到了这一点。

在本章中，我们将研究我们编写的每个应用程序的生命周期中发生的事情；也就是说，当它启动、结束和中间阶段。我们将看到的是，每次运行时，Android 都会与我们的应用程序进行多次交互。

## Android 如何与我们的应用程序交互

Android 通过调用包含在`Activity`类中的函数与我们的应用程序交互。即使该函数在我们的 Kotlin 代码中不可见，它仍然会在适当的时间被 Android 调用。如果这看起来毫无意义，那么请继续阅读。

您是否曾经想过为什么`onCreate`函数之前有一个不寻常的`override`关键字？考虑以下代码行：

```kt
override fun onCreate(…
```

当我们重写`onCreate`等函数时，我们是在告诉 Android 当你调用`onCreate`时，请使用我们重写的版本，因为我们在其中有一些代码需要执行。

此外，您可能会记得`onCreate`函数中不寻常的第一行代码：

```kt
super.onCreate(savedInstanceState)
```

这告诉 Android 在继续使用我们重写的版本之前调用`onCreate`的原始版本。

还有许多其他函数，我们可以选择性地重写它们，它们允许我们在 Android 应用程序的生命周期内的适当时间添加我们的代码。就像`onCreate`在应用程序显示给用户之前被调用一样，还有其他在其他时间被调用的函数。我们还没有看到它们或重写它们，但它们存在，它们被调用，它们的代码被执行。

我们需要了解和理解 Android 在需要时调用的*我们*应用程序的函数，因为这些函数控制着我们代码的生死。例如，如果我们的应用程序允许用户输入重要提醒，然后在输入提醒的一半时，他们的手机响了，我们的应用程序消失了，数据（也就是用户的重要提醒）就消失了？

了解我们的应用程序的生命周期何时、为什么以及哪些功能 Android 将调用是至关重要的，而且幸运的是，这是相当简单的。然后我们可以理解我们需要重写哪些功能来添加我们自己的代码，以及在哪里添加定义我们应用程序的真正功能（代码）。

让我们来研究一下 Android 的生命周期。然后我们可以深入了解 Kotlin 的方方面面，明确我们编写的代码应该放在哪里。

# Android 生命周期的简化解释

如果你曾经使用过 Android 设备，你可能已经注意到它的工作方式与许多其他操作系统有很大不同。例如，你可以在设备上使用一个应用程序，也许在查看 Facebook 上的人们在做什么。

然后，你收到一封电子邮件通知，你点击通知来阅读它。在阅读邮件的过程中，你可能会收到 Twitter 通知，因为你正在等待某个关注者的重要消息，所以你中断了邮件阅读并触摸屏幕切换到 Twitter。

阅读完推特后，你想玩《愤怒的小鸟》；然而，在第一次射击的一半时，你突然想起了 Facebook 的帖子。所以，你退出《愤怒的小鸟》并点击 Facebook 图标。

你可能会在恢复 Facebook 时恰好回到离开它的地方。之后，你可以回到阅读邮件，决定回复推特，或者开始一个全新的应用程序。

所有这些来回需要操作系统进行相当多的管理，并且独立于各个应用程序本身。

例如，就我们刚刚讨论的内容而言，Windows PC 和 Android 之间的区别是显著的。在 Android 中，尽管用户决定使用哪个应用程序，但操作系统决定何时关闭（或销毁）应用程序以及我们用户的数据（例如假设的笔记）。我们在编写应用程序时需要考虑这一点；仅仅因为我们可能编写代码来处理用户的输入并不意味着 Android 会允许代码执行。

## 生命周期阶段的神秘

Android 系统有许多不同的阶段，任何给定的应用程序都可能处于其中之一。根据阶段，Android 系统决定用户如何查看应用程序，或者是否根本不查看。

Android 有这些阶段，以便它可以决定哪个应用程序正在使用，并且可以为应用程序分配正确数量的资源，例如内存和处理能力。

此外，当用户与设备进行交互（例如触摸屏幕）时，Android 必须将该交互的详细信息传递给正确的应用程序。例如，在《愤怒的小鸟》中进行拖动和释放动作意味着射击，但在消息应用中可能意味着删除短信。

我们已经提出了当用户退出我们的应用程序来接听电话时会丢失他们的进度、数据或重要笔记的问题。

Android 有一个系统，简化一下以便解释，意味着 Android 设备上的每个应用程序都处于以下阶段之一：

+   正在创建

+   开始

+   恢复

+   运行

+   暂停

+   停止

+   被销毁

这个阶段列表希望看起来是合乎逻辑的。例如，用户按下 Facebook 应用程序图标，应用程序正在创建；然后，它被启动。到目前为止，一切都很简单，但列表中的下一个阶段是恢复。

这并不像一开始看起来那么不合逻辑。如果我们能暂时接受应用程序在启动后恢复，那么随着我们的继续，一切都会变得清晰起来。

在恢复之后，应用程序正在运行。这时，Facebook 应用程序控制着屏幕，并且拥有更多的系统内存和处理能力，并且正在接收用户输入的详细信息。

那么，我们切换从 Facebook 应用到邮件应用的例子呢？

当我们点击去阅读我们的电子邮件时，Facebook 应用程序将进入**暂停**阶段，然后是**停止**阶段，而电子邮件应用程序将进入**被创建**阶段，然后是**恢复**，然后是**运行**。

如果我们决定重新访问 Facebook，就像在前面的情景中一样，Facebook 应用程序可能会跳过**被创建**直接进入**恢复**，然后再次**运行**（很可能在我们离开它的确切位置）。

请注意，随时，Android 都可以决定**停止**然后**销毁**一个应用程序，在这种情况下，当我们再次运行应用程序时，它将需要在第一个阶段**被创建**。

因此，如果 Facebook 应用程序长时间不活动，或者*愤怒的小鸟*需要太多系统资源，以至于 Android**销毁**了 Facebook 应用程序，那么我们之前阅读的确切帖子的体验可能会有所不同。关键是应用程序及其与生命周期的交互控制了用户的体验。

如果所有这些开始变得令人困惑，那么你会高兴地知道提到这些阶段的唯一原因是因为以下原因：

+   你知道它们存在

+   我们偶尔需要与它们交互

+   当我们做的时候，我们将一步一步地进行

# 我们如何处理生命周期阶段

当我们编写应用程序时，我们如何与这种复杂性进行交互？好消息是，当我们创建第一个项目时自动生成的 Android 代码大部分都是为我们做的。

正如我们所讨论的，我们并不只是看到处理这种交互的函数，但我们有机会覆盖它们并在需要时向该阶段添加我们自己的代码。

这意味着我们可以继续学习 Kotlin 并制作 Android 应用程序，直到我们遇到偶尔需要在其中一个阶段做一些事情的情况。

### 注意

如果我们的应用程序有多个活动，它们将各自拥有自己的生命周期。这并不一定会使事情复杂化，总的来说，这将使事情对我们更容易。

以下列表提供了 Android 提供的用于管理生命周期阶段的函数的快速解释。为了澄清我们对生命周期函数的讨论，它们被列在我们一直在讨论的相应阶段旁边。然而，正如你将看到的，函数名称本身清楚地表明了它们在哪里适用。

在列表中，还有对为什么我们可能在每个阶段使用每个函数进行交互的简要解释或建议。随着我们在书中的进展，我们将遇到大部分这些函数；当然，我们已经见过`onCreate`：

+   `onCreate`：当 Activity*被创建*时，将执行此函数。在这里，我们为应用程序准备好一切，包括 UI（例如调用`setContentView`）、图形和声音。

+   `onStart`：当应用程序处于*启动*阶段时，将执行此函数。

+   `onResume`：此函数在`onStart`之后运行，但也可以在 Activity 在先前暂停后恢复时（最合乎逻辑的）进入。我们可能会从应用程序被中断时重新加载先前保存的用户数据（例如重要的笔记），例如通过电话呼叫或用户运行另一个应用程序。

+   `onPause`：当我们的应用程序*暂停*时会发生这种情况。在这里，我们可能会保存未保存的数据（例如笔记），这些数据可以在`onResume`中重新加载。当另一个 UI 元素显示在当前 Activity 的顶部（例如弹出对话框）或 Activity 即将停止时（例如用户导航到不同的 Activity）时，Activity 总是转换到暂停状态。

+   `onStop`：这与*停止*阶段有关。这是我们可能会撤消`onCreate`中所做的一切的地方，例如释放系统资源或将信息写入数据库。如果我们到达这里，Activity 很可能很快就会被销毁。

+   `onDestroy`：这是当我们的 Activity 最终被*销毁*时发生的。在这个阶段没有回头路。这是我们有序拆除应用程序的最后机会。如果 Activity 达到这个阶段，它将需要在下次使用应用程序时从头开始经历生命周期阶段。

以下图表显示了函数之间执行的可能流程：

![我们如何处理生命周期阶段](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_06_03.jpg)

所有函数的描述及其相关阶段应该很直接。唯一真正的问题是：关于运行阶段呢？正如当我们在其他函数和阶段中编写代码时所看到的，`onCreate`、`onStart`和`onResume`函数将准备应用程序，然后保持运行阶段。然后，`onPause`、`onStop`和`onDestroy`函数将在此之后发生。

现在我们可以通过一个迷你应用程序来观察这些生命周期函数的实际运行情况。我们将通过重写它们并为每个函数添加一个`Log`消息和一个`Toast`消息来实现这一点。这将直观地演示我们的应用程序经历的各个阶段。

# 生命周期演示应用程序

在本节中，我们将进行一个快速实验，以帮助我们熟悉应用程序使用的生命周期函数，并让我们有机会玩弄更多的 Kotlin 代码。

按照以下步骤开始一个新项目，然后我们可以添加一些代码：

1.  开始一个新项目，并选择**Basic Activity**项目模板；这是因为在这个项目中，我们还将研究控制应用程序菜单的函数，而**Empty Activity**选项不会生成菜单。

1.  将其命名为**Lifecycle Demo**。代码在下载包的`Chapter06/Lifecycle Demo`文件夹中，如果您希望参考或复制粘贴它。

1.  保持其他设置与我们所有示例应用程序中的设置相同。

1.  等待 Android Studio 生成项目文件，然后通过在编辑器上方的**MainActivity**标签上单击左键来打开代码编辑器中的`MainActivity.kt`文件（如果默认情况下没有为您打开）。

对于这个演示，我们只需要`MainActivity.kt`文件，因为我们不会构建用户界面。

## 编写生命周期演示应用程序

在`MainActivity.kt`文件中，找到`onCreate`函数，并在闭合大括号（`}`）之前添加两行代码，标志着`onCreate`函数的结束：

```kt
    Toast.makeText(this, "In onCreate", 
                Toast.LENGTH_SHORT).show()

    Log.i("info", "In onCreate")
```

### 提示

请记住，您需要使用*Alt* + *Enter*键盘组合两次来导入`Toast`和`Log`所需的类。

在`onCreate`函数的闭合大括号（`}`）之后，留出一行空白，并添加以下五个生命周期函数及其包含的代码。请注意，我们添加重写的函数的顺序并不重要；无论我们以何种顺序输入它们，Android 都会按正确的顺序调用它们：

```kt
override fun onStart() {
  // First call the "official" version of this function
  super.onStart()

  Toast.makeText(this, "In onStart",
        Toast.LENGTH_SHORT).show()

  Log.i("info", "In onStart")
}

override fun onResume() {
  // First call the "official" version of this function
  super.onResume()

  Toast.makeText(this, "In onResume",
              Toast.LENGTH_SHORT).show()

  Log.i("info", "In onResume")
}

override fun onPause() {
  // First call the "official" version of this function
  super.onPause()

  Toast.makeText(this, "In onPause", 
               Toast.LENGTH_SHORT).show()

  Log.i("info", "In onPause")
}

override fun onStop() {
  // First call the "official" version of this function
  super.onStop()

  Toast.makeText(this, "In onStop", 
              Toast.LENGTH_SHORT).show()

  Log.i("info", "In onStop")
}

override fun onDestroy() {
  // First call the "official" version of this function
  super.onDestroy()

  Toast.makeText(this, "In onDestroy", 
              Toast.LENGTH_SHORT).show()

  Log.i("info", "In onDestroy")
}
```

首先，让我们谈谈代码本身。请注意，函数名称都对应于我们在本章早些时候讨论过的生命周期函数及其相关阶段。请注意，所有函数声明之前都有`override`关键字。另外，请注意每个函数内的第一行代码是`super.on...`。

以下详细解释了正在发生的事情：

+   Android 在我们已经讨论过的各个时间调用我们的函数。

+   `override`关键字表明这些函数替换或重写了作为 Android API 的一部分提供的函数的原始版本。请注意，我们看不到这些被替换的函数，但它们存在，如果我们不重写它们，Android 将调用这些原始版本而不是我们自己的版本。

+   `super.on...`代码是每个重写函数内的第一行代码，然后调用这些原始版本。因此，我们不仅仅是重写这些原始函数以添加我们自己的代码；我们还调用它们，它们的代码也会被执行。

### 注意

对于急切的读者，`super`关键字是用于超类。随着我们在本书中的进展，我们将更多地探讨函数重写和超类。

最后，您添加的代码将使每个函数输出一条`Toast`消息和一条`Log`消息。然而，输出的消息会有所不同，可以通过双引号（`""`）之间的文本看出。输出的消息将清楚地表明是哪个函数产生了它们。

## 运行生命周期演示应用程序

现在我们已经查看了代码，我们可以玩玩我们的应用程序，并从发生的事情中了解生命周期：

1.  在设备或模拟器上运行应用程序。

1.  观察模拟器的屏幕，您将看到以下内容依次出现为`Toast`消息：**在 onCreate**，**在 onStart**和**在 onResume**。

1.  注意 logcat 窗口中的以下消息；如果有太多消息，请记住可以通过将**日志级别**下拉菜单设置为**信息**来过滤它们：

```kt
 info:in onCreate
 info:in onStart
 info:in onResume

```

1.  现在在模拟器或设备上点击返回按钮。注意，您会按照以下确切顺序收到以下三条`Toast`消息：**在 onPause**，**在 onStop**和**在 onDestroy**。验证我们在 logcat 窗口中是否有匹配的输出。

1.  接下来，运行另一个应用程序。也许可以运行第一章中的 Hello World 应用程序，*使用 Android 和 Kotlin 入门*（但任何应用程序都可以），通过在模拟器或设备屏幕上点击其图标来运行。

1.  现在尝试在模拟器上打开任务管理器。

### 提示

如果您不确定如何在模拟器上执行此操作，可以参考第三章中的内容，*探索 Android Studio 和项目结构*，以及在模拟器上使用真实设备部分。

1.  现在您应该能够在设备上看到最近运行的所有应用程序。

1.  点击生命周期演示应用程序，注意通常的三条启动消息会显示；这是因为我们的应用程序以前被销毁。

1.  现在再次点击任务管理器按钮，切换到 Hello World 应用程序。注意，这一次只显示**在 onPause**和**在 onStop**消息。验证我们在 logcat 窗口中是否有匹配的输出；这应该告诉我们应用程序**没有**被销毁。

1.  现在，再次使用任务管理器按钮，切换到生命周期演示应用程序。您会看到只显示**在 onStart**和**在 onResume**消息，表明不需要`onCreate`就可以再次运行应用程序。这是预期的，因为应用程序以前并没有被销毁，而只是停止了。

接下来，让我们谈谈我们运行应用程序时看到的情况。

## 检查生命周期演示应用程序的输出

当我们第一次启动生命周期演示应用程序时，我们看到调用了`onCreate`，`onStart`和`onResume`函数。然后，当我们使用返回按钮关闭应用程序时，调用了`onPause`，`onStop`和`onDestroy`函数。

此外，我们从我们的代码中知道，所有这些函数的原始版本也被调用，因为我们在每个重写的函数中首先使用`super.on...`代码调用它们。

我们应用程序行为的怪癖出现在我们使用任务管理器在应用程序之间切换时，当从生命周期演示应用程序切换时，它并没有被销毁，因此当再次切换回来时，不需要运行`onCreate`。

### 注意

**我的 Toast 在哪里？**

开头的三条和结尾的三条`Toast`消息由操作系统排队，并且函数在它们显示时已经完成。您可以通过再次运行实验来验证这一点，并看到所有三条启动和关闭日志消息在第二条`Toast`消息甚至显示之前就已经输出。然而，`Toast`消息确实加强了我们对顺序的了解，尽管不是时间上的了解。

当您按照前面的步骤进行操作时，可能会得到略有不同的结果。可以肯定的是，当我们的应用在成千上万台不同的设备上由数百万不同的用户运行时，这些用户对与其设备交互的偏好也不同，Android 将在不可预测的时间调用生命周期函数。

例如，当用户通过按下主页按钮退出应用程序时会发生什么？如果我们依次打开两个应用程序，然后使用返回按钮切换到先前的应用程序，那会销毁还是只是停止应用程序？当用户在其任务管理器中有数十个应用程序，并且操作系统需要销毁一些先前仅停止的应用程序时，我们的应用程序会成为受害者吗？

当然，您可以在模拟器上测试所有前面的场景。但结果只对您测试的一次有效。不能保证每次都会表现出相同的行为，当然也不会在每个不同的 Android 设备上表现出相同的行为。

最后，有一些好消息；解决所有这些复杂性的方法是遵循一些简单的规则：

+   设置您的应用程序，以便在`onCreate`函数中准备运行。

+   在`onResume`函数中加载用户的数据。

+   在`onPause`函数中保存用户的数据。

+   在`onDestroy`函数中整理您的应用程序，并使其成为一个良好的 Android 公民。

+   在本书中，有几个场合我们可能想要使用`onStart`和`onStop`，要注意一下。

如果我们遵循前面的规则，我们会发现，在本书的过程中，我们可以简单地不再担心生命周期，让 Android 来处理它。

还有一些其他函数我们也可以重写；所以，让我们来看看它们。

# 一些其他重写的函数

您可能已经注意到，在使用基本活动模板的所有项目代码中，还有另外两个自动生成的函数。它们是`onCreateOptionsMenu`和`onOptionsItemSelected`。许多 Android 应用程序都有弹出菜单，因此在使用基本活动模板时，Android Studio 会默认生成一个，包括使其工作的代码概述。

您可以在项目资源管理器中的`res/menu/menu_main.xml`中查看描述菜单的 XML。XML 代码的关键行如下：

```kt
<item
      android:id="@+id/action_settings"
      android:orderInCategory="100"
      android:title="@string/action_settings"
      app:showAsAction="never" />
```

这描述了一个带有**设置**文本的菜单**项**。如果您运行使用基本活动模板构建的任何应用程序，您将会看到如下截图中所示的按钮：

![一些其他重写的函数](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_06_01.jpg)

如果您点击按钮，您可以看到它的操作如下：

![一些其他重写的函数](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_06_02.jpg)

那么，`onCreateOptionsMenu`和`onOptionsItemSelected`函数是如何产生这些结果的呢？

`onCreateOptionsMenu`函数使用以下代码行从`menu_main.xml`文件加载菜单：

```kt
menuInflater.inflate(R.menu.menu_main, menu)
```

它是由`onCreate`函数的默认版本调用的，这就是为什么我们没有看到它发生。

### 注意

我们将在第十七章中使用弹出菜单，*数据持久性和共享*，在我们的应用程序的不同屏幕之间进行切换。

当用户点击菜单按钮时，将调用`onOptionsItemSelected`函数。该函数处理当项目被选中时会发生什么。现在，什么都不会发生；它只是返回`true`。

随意向这些函数添加`Toast`和`Log`消息，以测试我刚刚描述的顺序和时间。

现在我们已经了解了 Android 生命周期的工作原理，并且已经介绍了一些可重写的函数来与这个生命周期进行交互，我们最好学习一下 Kotlin 的基础知识，这样我们就可以编写一些更有用的代码放入这些函数中，并且编写我们自己的函数。

# Kotlin 代码的结构-重新访问

我们已经看到，每次创建新的 Android 项目时，我们也会创建一个新的**包**；这是我们编写的代码的一种容器。

我们还学习了并玩耍了**类**。我们已经从 Android API 中导入并直接利用了类，比如`Log`和`Toast`。我们还使用了`AppCompatActivity`类，但方式与`Log`和`Toast`不同。你可能还记得，到目前为止我们所有项目的第一行代码，在`import`语句之后，使用了`:`符号来继承一个类：

```kt
class MainActivity : AppCompatActivity() {
```

当我们继承一个类时，与仅仅导入它不同，我们正在使它成为我们自己的。事实上，如果你再看一下代码行，你会看到我们正在创建一个新的类，用一个新的名字`MainActivity`，但是基于 Android API 中的`AppCompatActivity`类。

### 注意

`AppCompatActivity`是`Activity`的修改版本。它为较旧版本的 Android 提供了额外的功能，否则这些功能将不存在。关于`Activity`的所有讨论，比如生命周期，同样适用于`AppCompatActivity`。如果名称以`...Activity`结尾，也没关系，因为我们讨论过的和将要讨论的一切同样适用。我通常会简单地将这个类称为`Activity`。

我们可以总结我们对类的使用如下：

+   我们可以导入类来使用它们

+   我们可以继承类来使用它们并扩展它们的功能

+   我们最终可以制作自己的类（并且很快会这样做）

我们自己的类，以及其他人编写的类，都是我们代码的构建模块，类中的函数包装了功能代码 - 也就是执行工作的代码。

我们可以在扩展的类中编写函数，就像我们在第二章中所做的`topClick`和`bottomClick`一样，*Kotlin，XML 和 UI 设计师*。此外，我们重写了其他人编写的类中已经存在的函数，比如`onCreate`和`onPause`。

然而，我们在这些函数中放入的唯一代码是使用`Toast`和`Log`进行了几次调用。现在我们准备用 Kotlin 迈出更多的步伐。

# 总结

在本章中，我们学到了不仅我们可以调用我们的代码；操作系统也可以调用我们重写的函数中包含的代码。通过向各种重写的生命周期函数添加适当的代码，我们可以确保在正确的时间执行正确的代码。

现在我们需要做的是学习如何编写更多的 Kotlin 代码。在下一章中，我们将开始专注于 Kotlin，并且因为我们已经在 Android 上有了很好的基础，所以练习和使用我们学到的一切都不会有问题。


# 第七章：Kotlin 变量，运算符和表达式

在本章和下一章中，我们将学习和实践 Kotlin 的核心基础知识。事实上，我们将探索编程的主要原则。在本章中，我们将重点关注数据本身的创建和理解，在下一章中，我们将探索如何操作和响应数据。

本章将重点介绍 Kotlin 中最简单的数据类型-变量。我们将在第十五章 *处理数据和生成随机数*中重新讨论更复杂和强大的数据类型。

我们将学习的核心 Kotlin 基础知识适用于我们继承的类（例如`Activity`和`AppCompatActivity`）以及我们自己编写的类（正如我们将在第十章 *面向对象编程*中开始做的）。

由于在编写自己的类之前学习基础知识更为合理，我们将学习基础知识，然后使用扩展的`Activity`类`AppCompatActivity`来将这个新理论付诸实践。我们将再次使用`Log`和`Toast`来查看我们编码的结果。此外，我们将使用更多我们自己编写的函数（从按钮调用），以及`Activity`类的重写函数来触发我们代码的执行。然而，我们将在第九章 *Kotlin 函数*中学习有关函数的全部细节。

当我们转到第十章 *面向对象编程*，并开始编写我们自己的类，以及了解其他人编写的类如何工作时，我们在这里学到的一切也将适用于那时。

在本章结束时，您将能够舒适地编写 Kotlin 代码，在 Android 中创建和使用数据。本章将带您了解以下主题：

+   学习行话

+   学习更多关于代码注释

+   什么是变量？

+   变量类型

+   声明变量的不同方式

+   初始化变量

+   运算符和表达式

+   表达自己的演示应用程序

让我们首先找出变量究竟是什么。

# 学习行话

在整本书中，我将用简单的英语来解释许多技术概念。我不会要求您阅读以前未用非技术语言解释的 Kotlin 或 Android 概念的技术解释。

### 注

致新接触 Kotlin 的 Java 程序员的一句话：如果您已经做过一些 Java 编程，那么事情将变得奇怪！您甚至可能会发誓我犯了一些错误；也许您甚至会认为我忘记了在所有代码行的末尾添加分号！我敦促您继续阅读，因为我认为您会发现 Kotlin 比 Java 有一些优势，因为它更为简洁和表达力强。学习 Java 仍然有其存在的价值，因为大多数 Android API 仍然是 Java，即使整个 Android 社区立即放弃 Java（他们没有），也会有多年的遗留 Java 代码。我不会不断指出 Java 和 Kotlin 之间的差异，因为差异太多，这样的分析是不必要的。如果您感兴趣，我建议阅读这篇文章：[`yalantis.com/blog/kotlin-vs-java-syntax/`](https://yalantis.com/blog/kotlin-vs-java-syntax/)。最终，Kotlin 和 Java 编译为完全相同的 Dalvik 兼容 Java 字节码。事实上，Java 和 Kotlin 是 100%可互操作的，甚至可以在项目中混合使用。您甚至可以将 Java 代码粘贴到 Kotlin 项目中，它将立即转换为 Kotlin。

Kotlin 和 Android 社区充满了使用技术术语的人；因此，要加入并从这些社区中学习，您需要理解他们使用的术语。

因此，本书的方法是使用简单的语言学习概念或获得大致轮廓，同时将行话或技术术语作为学习的一部分引入。

Kotlin 语法是我们将 Kotlin 语言元素组合成可执行代码的方式。Kotlin 语法是我们使用的单词和将这些单词组成类似句子的结构的组合，这就是我们的代码。

这些 Kotlin“单词”数量众多，但是，分成小块来学习，它们肯定比任何人类语言更容易学习。我们称这些单词为**关键字**。

我相信，如果您能阅读简单的英语，那么您就可以学会 Kotlin，因为学习 Kotlin 比学习阅读英语要容易得多。那么，是什么让完成了这样一个初级 Kotlin 课程的人和专业程序员之间有所不同呢？

答案是语言学生和大师诗人之间的区别正是相同的东西。掌握 Kotlin 并不在于我们知道如何使用 Kotlin 关键字的数量，而在于我们如何使用它们。语言的掌握来自于实践、进一步的学习，以及更熟练地使用关键字。许多人认为编程与科学一样是一门艺术，这也有一定道理。

# 更多关于代码注释

随着您在编写 Kotlin 程序方面变得更加高级，您用于创建程序的解决方案将变得更长、更复杂。此外，正如我们将在后面的章节中看到的，Kotlin 旨在通过将代码分成单独的类（通常跨越多个文件）来管理复杂性。

**代码注释**是 Kotlin 文件的一部分，在程序执行中没有任何功能；也就是说，编译器会忽略它们。它们用于帮助程序员记录、解释和澄清他们的代码，以便在以后更容易理解自己，或者其他需要使用或更改代码的程序员。

我们已经看到了单行注释：

```kt
// this is a comment explaining what is going on
```

前面的注释以两个斜杠字符`//`开头。注释在行末结束。因此，该行上的任何内容仅供人阅读，而下一行上的内容（除非是另一个注释）需要是符合语法的 Kotlin 代码：

```kt
// I can write anything I like here
but this line will cause an error
```

我们可以使用多个单行注释，如下所示：

```kt
// Below is an important note
// I am an important note
// We can have as many single line comments like this as we like
```

单行注释也很有用，如果我们想临时禁用一行代码。我们可以在代码前面加上`//`，这样它就不会包含在程序中。回顾一下这段代码，它告诉 Android 加载我们的布局：

```kt
// setContentView(R.layout.activity_main)
```

在这种情况下，布局将不会加载，当运行时应用程序将显示空白屏幕，因为整行代码被编译器忽略。

### 注意

我们在第五章中看到了这一点，*使用 CardView 和 ScrollView 创建美丽的布局*，当我们暂时注释掉函数中的一行代码时。

Kotlin 中还有另一种类型的注释，称为**多行注释**。多行注释适用于跨越多行的较长注释，以及在代码文件顶部添加版权信息等内容。与单行注释一样，多行注释可以用于临时禁用代码；在这种情况下，通常跨越多行。

在`/*`字符和`*/`字符之间的所有内容都将被编译器忽略。看一下以下示例：

```kt
/*
   You can tell I am good at this because my
   code has so many helpful comments in it.
*/
```

多行注释中没有行数限制；最好使用的注释类型将取决于具体情况。在本书中，我将始终在文本中明确解释每一行代码，但您通常会在代码本身中发现大量的注释，这些注释会进一步解释、洞察或提供上下文。因此，彻底阅读所有代码总是一个好主意：

```kt
/*
   The winning lottery numbers for next Saturday are
   9,7,12,34,29,22
   But you still want to make Android apps?
*/
```

### 提示

所有最优秀的程序员都会在他们的代码中大量使用注释！

# 变量

我们可以将**变量**看作是一个命名的存储盒。我们选择一个名称，也许是`variableA`。这些名称是程序员进入用户 Android 设备内存的途径。

变量是内存中的值，当需要时可以通过它们的名称引用它们。

计算机内存有一个高度复杂的地址系统，幸运的是，我们不需要直接与之交互。Kotlin 变量允许我们为应用程序需要处理的所有数据制定自己方便的名称。操作系统将与物理（硬件）内存进行交互。

因此，我们可以将我们的 Android 设备内存看作是一个巨大的仓库，等待我们添加我们的变量。当我们为变量分配名称时，它们存储在仓库中，以备我们需要时使用。当我们使用我们的变量名称时，设备知道我们在引用什么。然后我们可以告诉它做一些事情，比如以下内容：

+   为`variableA`分配一个值

+   将`variableA`添加到`variableB`

+   测试`variableB`的值，并根据结果采取行动

在典型的应用程序中，我们可能会有一个名为`unreadMessages`的变量；也许用于保存用户未读消息的数量。当有新消息到达时，我们可以将其添加到其中，当用户阅读消息时，我们可以从中减去，并在应用程序的布局中的某个地方向用户显示它，以便他们知道有多少未读消息。

可能出现的情况包括以下几种：

+   用户收到三条新消息，所以将三条消息添加到`unreadMessages`的值中。

+   用户登录应用程序，因此使用`Toast`显示一条消息以及存储在`unreadMessages`中的值。

+   用户看到有几条消息来自他们不喜欢的人，并删除了两条消息。然后我们可以从`unreadMessages`中减去两个。

变量名是任意的，如果您不使用 Kotlin 限制的任何字符或关键字，可以随意命名变量。

然而，在实践中，最好采用**命名约定**，以便您的变量名称保持一致。在本书中，我们将使用一个简单的变量命名约定，以小写字母开头。当变量名中有多个单词时，第二个单词将以大写字母开头。这被称为**驼峰命名法**。

以下是一些驼峰命名法变量名称的示例：

+   `unreadMessages`

+   `contactName`

+   `isFriend`

在我们查看一些使用变量的实际 Kotlin 代码之前，我们需要首先看一下我们可以创建和使用的变量的**类型**。

## 变量的类型

即使是一个简单的应用程序也很容易想象会有相当多的变量。在前一节中，我们介绍了`unreadMessages`变量作为一个假设的例子。如果应用程序有一个联系人列表，并需要记住每个联系人的名字，那么我们可能需要为每个联系人创建变量。

当应用程序需要知道联系人是否也是朋友，还是普通联系人时，该怎么办？我们可能需要测试朋友状态的代码，然后将该联系人的消息添加到适当的文件夹中，以便用户知道它们是来自朋友还是其他人的消息。

计算机程序的另一个常见要求，包括 Android 应用程序，是正确或错误的测试。计算机程序使用**true**和**false**表示正确或错误的计算。

为了涵盖您可能想要存储或操作的许多其他类型的数据，Kotlin 使用不同**类型**的变量。

有许多类型的变量，我们甚至可以发明自己的类型。但是，现在我们将看一下最常用的 Kotlin 类型，这些类型将涵盖我们可能遇到的几乎所有情况。解释类型的最佳方法是通过一些示例。

我们已经讨论了假设的`unreadMessages`变量。这个变量当然是一个数字。

另一方面，假设的`contactName`变量将保存组成联系人姓名的字符或字母。

保存常规数字的类型称为**Int**（整数的缩写）类型，保存类似名称的数据的类型称为**String**。

以下是本书中将使用的变量类型列表：

+   `Int`：`Int`类型用于存储整数和整数。此类型可以存储超过 20 亿的值，包括负值。

+   `Long`：顾名思义，当需要更大的数字时，可以使用`Long`数据类型。`Long`变量可以存储高达 9,223,372,036,854,775,807 的数字。那是很多未读消息。`Long`变量有很多用途，但如果较小的变量可以胜任，我们应该使用它，因为我们的应用程序将使用更少的内存。

+   `Float`：此变量用于浮点数。也就是说，小数点后有精度的数字。由于数字的小数部分占用的内存空间与整数部分一样，因此与非浮点数相比，`Float`变量中可能的数字范围会减少。因此，除非我们的变量将使用额外的精度，否则`Float`不会是我们的数据类型选择。

+   `Double`：当`Float`变量中的精度不够时，我们有`Double`。

+   `Boolean`：我们将在整本书中使用大量布尔值。`Boolean`变量类型可以是`true`或`false`；没有其他选项。布尔值回答问题，例如：

+   联系人是朋友吗？

+   有新消息吗？

+   两个布尔值的例子足够了吗？

+   `Char`：这个类型存储单个字母数字字符。它本身不会改变世界，但如果我们把它们放在一起，它可能会有用。

+   `String`：字符串可以用来存储任何键盘字符。它类似于`Char`变量，但长度几乎可以是任意的。从联系人的姓名到整本书都可以存储在一个`String`中。我们将经常使用字符串，包括在本章中。

+   `Class`：这是最强大的数据类型，我们已经稍微讨论过了。我们将在第十章中深入探讨类，面向对象编程。

+   `Array`：这种类型有很多不同的变体，对于处理和组织大量数据至关重要。我们将在第十五章中探讨`Array`的变体，处理数据和生成随机数。

现在我们知道了变量是什么，以及有各种类型可供选择，我们几乎准备好看一些实际的 Kotlin 代码了。

## 声明和初始化变量

在我们可以使用刚讨论的变量类型之前，我们必须**声明**它们，以便编译器知道它们的存在，并且我们还必须**初始化**它们，以便它们保存一个值。

对于 Kotlin 中的每种变量类型，如`Int`、`Float`和`String`，我们可以使用两个关键字来声明它们：`val`和`var`。

`val`类型用于存储在应用程序启动之前或初始化期间由程序员决定的值，并且在执行过程中不能再次更改。`var`类型用于可以在执行过程中操作和更改的值。

因此，`val`类型只能读取。在技术术语中，它被称为**不可变**。`var`类型可读可写，这被称为**可变**。在执行过程中尝试更改`val`类型的值的代码将导致 Android Studio 显示错误，代码将无法编译。我们将在后面探讨`var`的规则。

有两种方式可以声明和初始化`String`类型；首先，通过使用`val`，如下所示：

```kt
val contactName: String = "Gordon Freeman"
```

在前面的代码中，声明了一个名为`contactName`的新`val`变量，类型为`String`，现在持有`Gordon Freeman`的值。

此外，`Gordon Freeman`文本现在是`contactName`在应用程序执行期间唯一可以持有的值。你可以尝试使用以下代码更改它：

```kt
contactName = "Apple Crumble" // Causes an error 
```

如果你将前面的代码粘贴到 Android 项目的`onCreate`函数中，你将看到以下内容：

![声明和初始化变量](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_07_01.jpg)

Android Studio 正在帮助我们强制执行我们的决定，使变量成为**常量**。当然，我们经常需要更改变量持有的值。当我们这样做时，我们将使用`var`；看一下接下来的两行代码：

```kt
var contactName: String = "Gordon Freeman" 
contactName = "Alyx Vance" // No problem
```

在前面的代码中，我们使用`var`声明了一个`String`类型，这次成功地将`contactName`持有的值更改为`Alyx Vance`。

这里要记住的一点是，如果变量在应用程序执行期间不需要更改，那么我们应该使用`val`，因为编译器可以帮助我们避免犯错。

让我们声明和初始化一些不同类型的变量：

```kt
val battleOfHastings: Int = 1066
val pi: Float = 3.14f
var worldRecord100m: Float = 9.63f
var millisecondsSince1970: Long = 1544693462311 
// True at 9:30am 13/12/2018
val beerIsTasty: Boolean = true
var isItRaining: Boolean = false
val appName: String = "Express Yourself"
var contactName: String = "Geralt"

// All the var variables can be reassigned
worldRecord100m = 9.58f
millisecondsSince1970 = 1544694713072 
// True at 9:51am 13/12/2018
contactName = "Vesemir"
```

请注意，在前面的代码中，当变量不太可能改变时，我将其声明为`val`，而当它可能会改变时，我将其声明为`var`。在开发应用程序时，你可以猜测是使用`val`还是`var`，如果有必要，你可以将`var`变量更改为`val`变量，或者反过来。另外，在前面的代码中，请注意`String`类型是用引号中的值进行初始化的，但`Int`、`Float`、`Long`和`Boolean`却不是。

## 使用类型推断节省击键

Kotlin 的设计目标是尽可能简洁。JetBrains 团队的目标之一是让开发人员用尽可能少的代码完成尽可能多的工作。我们将在整个 Kotlin 语言中看到这样的例子。如果你之前在其他语言，特别是 Java 中编码过，你会注意到输入量的显著减少。这种减少的第一个例子就是**类型推断**。

Kotlin 通常可以从上下文中推断出你需要的类型，如果是这种情况，那么你就不需要显式地写出类型；考虑下面的例子：

```kt
var contactName: String = "Xian Mei"
```

在前面的代码中，声明了一个名为`contactName`的`String`类型，并使用"Xian Mei"进行了初始化。如果你仔细想一想，它必须是一个`String`。幸运的是，Kotlin 编译器也能明白这一点。我们可以（而且应该）改进前面的代码，使用类型推断，就像下面的代码一样：

```kt
var contactName = "Xian Mei"
```

冒号和类型已被省略，但结果是相同的。

### 提示

Java 程序员也会注意到，Kotlin 代码不需要在每行末尾加上分号。然而，如果你喜欢分号，编译器也不会抱怨你在每行末尾加上分号：

```kt
var contactName = "Xian Mei"; // OK but superfluous
```

然而，我们必须记住，尽管我们没有明确指定`String`，它仍然是一个`String`类型——只是一个`String`类型。如果我们尝试对`String`类型不合适的操作，那么我们将会得到一个错误；例如，当我们尝试将其重新初始化为一个数字值时，就像这段代码中所做的那样：

```kt
contactName = 3.14f // Error
```

前面的代码将在 Android Studio 中标记，并且编译不会成功。以下是前一节代码中的所有声明和初始化，但这次使用了类型推断：

```kt
val battleOfHastings = 1066
val pi = 3.14f
var worldRecord100m = 9.63f
var millisecondsSince1970 = 1544693462311 
// True at 9:30am 13/12/2018
val beerIsTasty = true
var isItRaining = false
val appName = "Express Yourself"
var contactName =  "Geralt"
```

在接下来的两个部分中，我们将看到更多关于变量的类型推断，在后面的章节中，我们将使用类型推断来处理更复杂的类型，比如类、数组和集合。类型推断也将成为一个很好的时间节省器，使我们的代码更短、更易管理。

这可能听起来很明显，但值得一提的是，如果你在声明一个变量以便稍后初始化，那么类型推断是不可能的，就像下面的代码所示：

```kt
var widgetCount // Error
```

前面的代码会导致错误，应用程序将无法编译。

在使用类型推断时，变量的类型通常是显而易见的，但如果有任何疑问，您可以在 Android Studio 中选择一个变量，同时按*Shift* + *Ctrl* + *P*来获得一个方便的屏幕提示：

![使用类型推断节省按键](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_07_02.jpg)

偶尔省略`String`、`Int`或冒号（`:`）类型本身不会有太大变化，所以让我们学习如何通过将它们与**运算符**结合来制作**表达式**。

# 运算符和表达式

当然，在几乎任何程序中，我们都需要用这些变量的值来“做事情”。我们可以使用运算符来操作和改变变量。当我们将运算符和变量组合以获得结果时，这被称为表达式。

以下各节列出了最常见的 Kotlin 运算符，允许我们操作变量。您不需要记住它们，因为我们将在第一次使用它们时查看每行代码。

我们在上一节初始化变量时已经看到了第一个运算符，但我们将再次看到它变得更加冒险。

## 赋值运算符

这是赋值运算符：

```kt
=

```

它使运算符左侧的变量与右侧的值相同；例如，就像这行代码中的例子：

```kt
unreadMessages = newMessages
```

在前一行代码执行后，`unreadMessages`中存储的值将与`newMessages`中存储的值相同。

## 加法运算符

这是加法运算符：

```kt
+
```

它将运算符两侧的值相加。通常与赋值运算符一起使用。例如，它可以将具有数值的两个变量相加，就像下一行代码中的例子：

```kt
 unreadMessages = newMessages + unreadMessages 
```

一旦前面的代码执行了，`newMessages`和`unreadMessages`所保存的值的总和将存储在`unreadMessages`中。作为同样的例子，看看这行代码：

```kt
accountBalance = yesterdaysBalance + todaysDeposits
```

请注意，同时在运算符的两侧同时使用同一个变量是完全可以接受的（并且非常常见）。

## 减法运算符

这是减法运算符：

```kt
-
```

它将从运算符左侧的值中减去运算符右侧的值。通常与赋值运算符一起使用，就像这个例子中：

```kt
unreadMessages = unreadMessages - 1
```

减法运算符的另一个例子如下：

```kt
accountBalance = accountBalance - withdrawals
```

在前一行代码执行后，`accountBalance`将保持其原始值减去`withdrawals`中保存的值。

## 除法运算符

这是除法运算符：

```kt
/
```

它将左侧的数字除以右侧的数字。同样，通常与赋值运算符一起使用；这是一个例子行代码：

```kt
fairShare = numSweets / numChildren
```

如果在前一行代码中，`numSweets`为 9，`numChildren`为 3，则`fairShare`现在将保存值为 3。

## 乘法运算符

这是乘法运算符：

```kt
*
```

它将变量和数字相乘，与许多其他运算符一样，通常与赋值运算符一起使用；例如，看看这行代码：

```kt
answer = 10 * 10 
```

乘法运算符的另一个例子如下：

```kt
biggerAnswer = 10 * 10 * 10
```

在前两行代码执行后，`answer`保存的值为 100，`biggerAnswer`保存的值为 1000。

## 递增运算符

这是递增运算符：

```kt
   ++
```

递增运算符是将某物加一的快速方法。例如，看看下一行代码，它使用了加法运算符：

```kt
myVariable = myVariable + 1 
```

前一行代码的结果与这个更紧凑的代码相同：

```kt
myVariable ++ 
```

## 递减运算符

这是递减运算符：

```kt
      -- 
```

递减运算符（你可能已经猜到）是从某物中减去一个的快速方法。例如，看看下一行代码，它使用了减法运算符：

```kt
myVariable = myVariable -1
```

前一行代码与`myVariable --.`相同。

现在我们可以将这些新知识应用到一个工作中的应用程序中。

# 表达自己的演示应用程序

让我们尝试使用一些声明、赋值和运算符。当我们将这些元素捆绑到一些有意义的语法中时，我们称之为**表达式**。让我们写一个快速的应用程序来尝试一些。然后我们将使用`Toast`和`Log`来检查我们的结果。

创建一个名为`Express Yourself`的新项目，使用**空活动**项目模板，并将所有其他选项保持在它们通常的设置中。我们将在下载包的`Chapter07`文件夹中找到我们将在这个项目中编写的完成代码。

切换到编辑器中的**MainActivity**选项卡，我们将写一些代码。在`onCreate`函数中，在闭合大括号（`}`）之前，添加这个突出显示的代码：

```kt
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

 val name = "Nolan Bushnell"
 val yearOfBirth = 1943
 var currentYear = 2019
 var age: Int
    }
}
```

我们刚刚在`onCreate`函数中添加了四个变量。前两个是`val`变量，不能被改变。它们是一个`String`类型，保存一个人的名字，和一个`Int`类型，保存出生年份。类型在代码中没有明确提到；它们是被推断出来的。

接下来的两个变量是`var`变量。我们有一个`Int`类型来表示当前年份，和一个未初始化的`Int`类型来表示一个人的年龄。由于`age`变量未初始化，它的类型无法被推断，所以我们必须指定它。

在前面的代码之后，仍然在`onCreate`内部，添加以下行：

```kt
age = currentYear - yearOfBirth
Log.i("info", "$age")
```

运行应用程序，注意在 logcat 窗口中的以下输出：

```kt
info: 76

```

在`Log.i…`代码的引号中使用`$`符号表示我们想要输出`age`变量中存储的*值*，而不是字面上的单词"age"。

实际的值本身（76），表示存储在`yearOfBirth`（1943）中的值被减去存储在`currentYear`（2019）中的值，结果被用来初始化`age`变量。正如你将看到的，我们可以在引号中包含尽可能多的`$`符号，并将它们与文本甚至 Kotlin 表达式混合使用。这个特性被称为**字符串模板**。让我们尝试另一个字符串模板。

在`onCreate`函数内的前面的代码之后添加这两行代码：

```kt
currentYear++
Log.i("info", "$name 
was born in $yearOfBirth and is $age years old. 
Next year he will be ${currentYear - yearOfBirth} years old)")
```

关于这段代码的第一件事是，尽管它在这本书中格式化为四行，但当你输入到 Android Studio 中时，它必须输入为两行。第一行`currentYear++`，增加（加一）到存储在`currentYear`中的值。所有其余的代码都是一行。

运行应用程序，观察 logcat 窗口中的以下输出：

```kt
Nolan Bushnell was born in 1943 and is 76 years old. Next year he will be 77 years old

```

这段代码之所以有效，是因为 Kotlin 字符串模板。让我们分解这行相当长的代码。首先，我们像以前做过很多次一样调用`Log.i`函数。在第一个字符串中，我们传递了`"info"`，在第二个字符串中，我们传递了一些变量名，前面加上`$`符号，混合了一些字面文本。分解中最有趣的部分是倒数第二部分，因为我们使用一个表达式来形成字符串的一部分：

+   `$name`打印出 Nolan Bushnell

+   `Was born in`是字面文本

+   `$yearOfBirth`打印出 1943

+   字面文本`and is`接下来

+   `$currentAge`打印出 76

+   接下来是字面文本`years old`

+   字面文本`Next year he will be`接下来

+   `${currentYear - yearOfBirth}`是一个表达式，表达式的结果（77）被打印出来

+   最后的字面文本`years old`被打印出来以结束输出

这表明我们可以使用以下形式在`String`类型中包含任何有效的 Kotlin 表达式：

`${expression}`

在下一章中，我们将看到更复杂和强大的表达式。

# 总结

在本章中，我们学习了 Kotlin 中数据的基本构建块。我们探讨了不同类型及其不同用途的概述。我们还学会了如何使用字符串模板从字面值、变量和表达式构建字符串。我们还看到了在可能的情况下，我们可以和应该使用类型推断使我们的代码更简洁。

我们没有看到太多关于布尔变量类型，但在下一章中，当我们学习 Kotlin 的决策和循环时，我们将纠正这一错误。


# 第八章：Kotlin 决策和循环

我们刚刚学会了变量，并且现在了解如何使用表达式更改它们所持有的值，但是我们如何根据变量的值采取行动呢？

我们当然可以将新消息的数量添加到先前未读消息的数量中，但是例如，当用户已读完所有消息时，我们如何在应用程序内触发一个操作呢？

第一个问题是我们需要一种方法来测试变量的值，然后在值落在一系列值范围内或等于特定值时做出响应。

编程中常见的另一个问题是，我们需要根据变量的值来执行代码的某些部分一定次数（多次或有时根本不执行）。

为了解决第一个问题，我们将学习使用 `if`、`else` 和 `when` 在 Kotlin 中做决策。为了解决后者，我们将学习使用 `while`、`do` – `while`、`for`、`continue` 和 `break` 在 Kotlin 中做循环。

此外，我们将了解到，在 Kotlin 中，决策也是产生值的表达式。在本章中，我们将涵盖以下主题：

+   使用 `if`、`else`、`else` – `if` 和 `switch` 进行决策

+   `when` 演示应用程序

+   Kotlin `while` 循环和 `do` - `while` 循环

+   Kotlin `for` 循环

现在让我们更多地了解 Kotlin。

# 在 Kotlin 中做决策

我们的 Kotlin 代码将不断做出决策。例如，我们可能需要知道用户是否有新消息，或者他们是否有一定数量的朋友。我们需要能够测试我们的变量，看它们是否满足某些条件，然后根据它们是否满足条件来执行特定的代码部分。

在本节中，随着我们的代码变得更加深入，以一种更易读的方式呈现代码有助于使其更易读。让我们看一下代码缩进，以使我们关于做决策的讨论更加容易。

## 为了清晰起见缩进代码

您可能已经注意到我们项目中的 Kotlin 代码是缩进的。例如，在 `MainActivity` 类内的第一行代码被缩进了一个制表符。此外，每个函数内的第一行代码也被另一个制表符缩进；下面是一个带注释的图表，以便清楚地说明这一点：

![为了清晰起见缩进代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_08_01.jpg)

请注意，当缩进块结束时，通常是以一个闭合大括号（`}`）结束，它的缩进程度与开始块的代码行相同。

我们这样做是为了使代码更易读。然而，这并不是 Kotlin 语法的一部分，如果我们不去做这个，代码仍然会编译。

随着我们的代码变得更加复杂，缩进和注释有助于保持代码的含义和结构清晰。我现在提到这一点是因为当我们开始学习 Kotlin 中做决策的语法时，缩进变得特别有用，建议您以相同的方式缩进代码。大部分缩进是由 Android Studio 为我们完成的，但并非全部。

现在我们知道如何更清晰地呈现我们的代码，我们可以学习更多运算符，然后开始使用 Kotlin 做决策。

## 更多 Kotlin 运算符

我们已经学会了使用运算符进行添加（+）、减去（-）、乘以（*）、除以（/）、赋值（=）、递增（++）和递减（--）。现在我们将探索一些更有用的运算符，然后我们将直接学习如何使用它们。

### 提示

不要担心记住以下每个运算符。简要浏览它们和它们的解释，然后继续下一节。在那里，我们将使用一些运算符，并且当我们看到它们允许我们做什么的示例时，它们将变得更加清晰。它们在此处以列表的形式呈现，只是为了从一开始就清晰地展示运算符的种类和范围。在后面关于实现的讨论中，这个列表也会更方便以后参考。

我们使用运算符创建一个表达式，这个表达式要么为真，要么为假。我们用括号或方括号括起这个表达式，就像这样：`(表达式放在这里)`。

### 比较运算符

这是比较运算符。它测试相等性，要么为真，要么为假；它是`Boolean`类型的：

```kt
==
```

例如，表达式`(10 == 9)`是假的。10 显然不等于 9。然而，表达式`(2 + 2 == 4)`显然是真的。

### 提示

也就是说，除了在《1984》中，2 + 2 == 5（[`en.wikipedia.org/wiki/Nineteen_Eighty-Four`](https://en.wikipedia.org/wiki/Nineteen_Eighty-Four)）。

### 逻辑 NOT 运算符

这是逻辑 NOT 运算符：

```kt
!
```

它用于测试表达式的否定。如果表达式为假，那么 NOT 运算符会使表达式为真。

例如，表达式`(!(2+2 == 5))`为真，因为 2 + 2 *不是* 5。但是，`(!(2 + 2 = 4))`的进一步例子是假的。这是因为 2 + 2 *显然是* 4。

### 不等于运算符

这是不等于运算符，它是另一个比较运算符：

```kt
!=
```

不等于运算符测试是否不相等；例如，`(10 != 9)`表达式为真，因为 10 不等于 9。另一方面，`(10 != 10)`为假，因为 10 等于 10。

### 大于运算符

另一个比较运算符（还有一些其他的）是大于运算符：

```kt
>
```

这个运算符测试一个值是否大于另一个值。表达式`(10 > 9)`为真，但是表达式`(9 > 10)`为假。

### 小于运算符

你可能猜到了，这个运算符测试一个值是否小于另一个值；这是这个运算符的样子：

```kt
<
```

表达式`(10 < 9)`为假，因为 10 不小于 9，而表达式`(9 < 10)`为真。

### 大于或等于运算符

这个运算符测试一个值是否大于或等于另一个值，如果其中一个为真，结果就为真。这就是这个运算符的样子：

```kt
>=
```

例如，表达式`(10 >= 9)`为真，表达式`(10 >= 10)`也为真，但是表达式`(10 >= 11)`为假，因为 10 既不大于也不等于 11。

### 小于或等于运算符

像前一个运算符一样，这个运算符测试两个条件，但这次是**小于**或等于；看看下面的运算符：

```kt
<=
```

表达式`(10 <= 9)`为假，表达式`(10 <= 10)`为真，表达式`(10 <= 11)`也为真。

### 逻辑 AND 运算符

这个运算符称为逻辑 AND。它测试表达式的两个或多个独立部分，整个表达式的两个或所有部分都必须为真才能为真：

```kt
&&
```

逻辑 AND 通常与其他运算符一起使用，以构建更复杂的测试。表达式`((10 > 9) && (10 < 11))`为真，因为两个部分都为真。另一方面，表达式`((10 > 9) && (10 < 9))`为假，因为表达式的一个部分为真-`(10 > 9)`，而另一个部分为假-`(10 < 9)`。

### 逻辑 OR 运算符

这个运算符叫做逻辑 OR，它和逻辑 AND 一样，只是表达式的两个或多个部分中只有一个为真，整个表达式才为真：

```kt
||
```

再看一下我们用于逻辑 AND 的上一个例子，但是，用`||`替换`&&`。表达式`((10 > 9) || (10 < 9))`现在为真，因为表达式的一个或多个部分需要为真。

在本章和整本书的其余部分中，以更实际的情境看到这些运算符，将有助于澄清它们的不同用途。现在我们知道如何使用运算符、变量和值来形成表达式。接下来，我们可以看一种结构化和组合表达式的方法，以做出几个深刻的决定。

## 如何使用所有这些运算符来测试变量

所有这些运算符在没有正确使用它们来做出影响真实变量和代码的真实决定的方法时几乎是无用的。

现在我们已经拥有了所有需要的信息，我们可以看一个假设的情况，然后实际检查一些决策的代码。

### 使用 if 表达式

正如您所见，运算符本身的作用很小，但看到我们可以使用的广泛和多样的范围的一部分是很有用的。现在当我们开始使用最常见的运算符`==`时，我们可以开始看到它们为我们提供的强大而精细的控制。

让我们通过检查以下代码来使之前的示例不那么抽象。

```kt
val time = 9

val amOrPm = if(time < 12) {
  "am"
} else {
  "pm"
}

Log.i("It is ", amOrPm)
```

上述代码首先声明并初始化了一个名为`time`的`Int`类型，其值为`9`。代码的下一行非常有趣，因为它做了两件事。`if(time < 12)`表达式是一个测试；我们知道时间小于`12`，因为我们刚刚将其初始化为`9`。由于条件为真，`if`表达式返回`"am"`值，并且在`if`表达式之前的代码行的第一部分声明并初始化了一个名为`amOrPm`的新`String`类型，并赋予了该值。

如果我们将`time`变量初始化为不少于 12 的任何值（即 12 或更高），则从`else`块中返回的值将是`"pm"`。如果您将上述代码复制并粘贴到项目中，例如`onCreate`函数，logcat 中的输出将如下所示：

```kt
It is: am

```

`if`表达式被评估，如果条件为真，则执行第一组花括号中的代码（`{…}`）；如果条件为假，则执行`else {…}`块中的代码。

值得注意的是，`if`不一定要返回一个值，而是可以根据测试的结果执行一些代码；看一下以下示例代码：

```kt
val time = 13

if(time < 12) {
  // Execute some important morning task here
} else {
  // Do afternoon work here
}
```

在上述代码中，没有返回值；我们只关心正确的代码部分是否被执行。

### 提示

从技术上讲，仍然返回一个值（在这种情况下为 true 或 false），但我们选择不对其进行任何操作。

此外，我们的`if`表达式可以处理超过两个结果，我们稍后会看到。

我们还可以在 String 模板中使用`if`。我们在上一章中看到，我们可以通过在`$`符号后的花括号之间插入表达式来将表达式插入到`String`类型中。以下是上一章的代码提醒：

```kt
Log.i("info", "$name 
was born in $yearOfBirth and is $age years old. 
Next year he will be ${currentYear - yearOfBirth} years old)")
```

在上述代码中的突出部分将导致从`currentYear`中减去`yearOfBirth`的值被打印在消息的其余部分中。

以下代码示例显示了我们如何以相同的方式将整个`if`表达式插入到`String`模板中：

```kt
val weight = 30
val instruction = 
  "Put bag in ${if (weight >= 25) "hold" else "cabin" }"

Log.i("instruction is ", instruction)
```

上述代码使用`if`来测试`weight`变量是否初始化为大于或等于 25 的值。根据表达式是否为真，它将单词`hold`或单词`cabin`添加到`String`初始化中。

如果您执行上述代码，您将获得以下输出：

```kt
instruction is: Put this bag in the hold

```

如果您将`weight`的初始化更改为 25 以下的任何值并执行代码，您将获得以下输出：

```kt
instruction is: Put this bag in the cabin

```

让我们看一个更复杂的例子。

## 如果他们过桥，就射击他们！

在下一个示例中，我们将使用`if`，一些条件运算符和一个简短的故事来演示它们的用法。

船长快要死了，知道他剩下的下属经验不是很丰富，他决定写一个 Kotlin 程序（还能干什么？）在他死后传达他的最后命令。部队必须守住桥的一侧，等待增援，但有一些规则来决定他们的行动。

船长想要确保他的部队理解的第一个命令如下：

**如果他们过桥，就射击他们。**

那么，我们如何在 Kotlin 中模拟这种情况呢？我们需要一个`Boolean`变量-`isComingOverBridge`。下一部分代码假设`isComingOverBridge`变量已经被声明并初始化为`true`或`false`。

然后我们可以这样使用`if`：

```kt
if(isComingOverBridge){

   // Shoot them

}
```

如果`isComingOverBridge`布尔值为 true，则大括号内的代码将执行。如果`isComingOverBridge`为 false，则程序在`if`块之后继续执行，而不运行其中的代码。

### 否则，做这个代替

船长还想告诉他的部队，如果敌人不从桥上过来，他们应该待在原地等待。

为此，我们可以使用`else`。当我们希望在`if`表达式不为 true 时明确执行某些操作时，我们使用`else`。

例如，如果敌人不从桥上过来，我们可以编写以下代码告诉部队待在原地：

```kt
if(isComingOverBridge){

   // Shoot them

}else{

   // Hold position

}
```

然后船长意识到问题并不像他最初想的那么简单。如果敌人从桥上过来，但是部队太多怎么办？他的小队将被压制和屠杀。

因此，他提出了以下代码（这次，我们也将使用一些变量）：

```kt
var isComingOverBridge: Boolean
var enemyTroops: Int
var friendlyTroops: Int

// Code that initializes the above variables one way or another

// Now the if
if(isComingOverBridge && friendlyTroops > enemyTroops){

   // shoot them

}else if(isComingOveBridge && friendlyTroops < enemyTroops) {

   // blow the bridge

}else{

   // Hold position

}
```

上述代码有三条可能的执行路径。第一种情况是，如果敌人从桥上过来，友军数量更多：

```kt
if(isComingOverBridge && friendlyTroops > enemyTroops)
```

第二种情况是，如果敌军正在从桥上过来，但数量超过友军：

```kt
else if(isComingOveBridge && friendlyTroops < enemyTroops)
```

如果其他两条路径都不成立，第三种可能的结果是由最终的`else`语句捕获的，没有`if`条件。

### 提示

**读者挑战**

您能发现上述代码的一个缺陷吗？这可能会让一群经验不足的部队陷入完全混乱的状态？敌军和友军的数量恰好相等的可能性没有得到明确处理，因此将由最终的`else`语句处理，这是用于没有敌军的情况。任何自尊的船长都希望他的部队在这种情况下战斗，他可以改变第一个`if`语句以适应这种可能性，如下所示：

`if(isComingOverBridge && friendlyTroops >= enemyTroops)`

最后，船长最后关心的是，如果敌人拿着白旗投降并立即被屠杀，那么他的士兵将成为战争罪犯。这里需要的代码是显而易见的；使用`wavingWhiteFlag`布尔变量，他可以编写以下测试：

```kt
if (wavingWhiteFlag){

   // Take prisoners

}
```

然而，放置这段代码的位置不太清楚。最后，船长选择了以下嵌套解决方案，并将`wavingWhiteFlag`的测试更改为逻辑非，如下所示：

```kt
if (!wavingWhiteFlag){

   // not surrendering so check everything else

   if(isComingOverBridge && friendlyTroops >= enemyTroops){

          // shoot them
   }else if(isComingOverBridge && friendlyTroops < 
                enemyTroops) {

         // blow the bridge

   }

}else{

   // this is the else for our first if
   // Take prisoners

}

// Holding position
```

这表明我们可以嵌套`if`和`else`语句以创建深入和详细的决策。

我们可以继续使用`if`和`else`做出更多更复杂的决定，但是我们在这里看到的已经足够作为介绍了。

很可能值得指出的是，很多时候，解决问题有多种方法。*正确*的方法通常是以最清晰和最简单的方式解决问题。

现在我们将看一些其他在 Kotlin 中做决策的方法，然后我们可以将它们全部放在一个应用程序中。

## 使用`when`进行决策

我们已经看到了将 Kotlin 运算符与`if`和`else`语句结合使用的广泛且几乎无限的可能性。但是，有时，在 Kotlin 中做出决策可能有其他更好的方法。

当我们希望根据一系列可能的结果做出决策并执行不同的代码段时，我们可以使用`when`。以下代码声明并初始化`rating`变量，然后根据`rating`的值向 logcat 窗口输出不同的响应：

```kt
val rating:Int = 4
when (rating) {
  1 -> Log.i("Oh dear! Rating = ", "$rating stars")
  2 -> Log.i("Not good! Rating = ", "$rating stars")
  3 -> Log.i("Not bad! Rating = ", "$rating stars")
  4 -> Log.i("This is good! Rating = ", "$rating stars")
  5 -> Log.i("Amazing! Rating = ", "$rating stars")

  else -> {    
    Log.i("Error:", "$rating is not a valid rating")
  }
}
```

如果您将上述代码复制并粘贴到应用程序的`onCreate`函数中，它将产生以下输出：

```kt
This is good! Rating =: 4 stars

```

该代码首先将名为`rating`的`Int`变量初始化为`4`。然后，`when`块使用`rating`作为条件：

```kt
val rating:Int = 4
when (rating) {
```

接下来，处理了评分可能初始化为的五种不同可能性。对于每个值，从`1`到`5`，都会向 logcat 窗口输出不同的消息：

```kt
1 -> Log.i("Oh dear! Rating = ", "$rating stars")
2 -> Log.i("Not good! Rating = ", "$rating stars")
3 -> Log.i("Not bad! Rating = ", "$rating stars")
4 -> Log.i("This is good! Rating = ", "$rating stars")
5 -> Log.i("Amazing! Rating = ", "$rating stars")
```

最后，如果没有指定的选项为真，则会执行`else`块：

```kt
else -> {
  Log.i("Error:", "$rating is not a valid rating")
}
```

让我们通过构建一个小型演示应用程序来看一下`when`的稍微不同的用法。

## When Demo 应用

要开始，请创建一个名为`When Demo`的新 Android 项目。使用**空活动**项目模板，并将所有其他选项保持在通常的设置中。通过在编辑器上方单击**MainActivity.kt**标签，切换到`MainActivity.kt`文件，我们可以开始编码。

您可以在下载包的`Chapter08/When Demo`文件夹中获取此应用的代码。该文件还包括与我们先前讨论的表达式和`if`相关的代码。为什么不尝试玩一下代码，运行应用程序并研究输出呢？

在`onCreate`函数内添加以下代码。该应用程序演示了多个不同的值可以触发相同执行路径：

```kt
// Enter an ocean, river or breed of dog
val name:String = "Nile"
when (name) {
  "Atlantic","Pacific", "Arctic" -> 
    Log.i("Found:", "$name is an ocean")

  "Thames","Nile", "Mississippi" -> 
    Log.i("Found:", "$name is a river")

  "Labrador","Beagle", "Jack Russel" -> 
    Log.i("Found:", "$name is a dog")

  else -> {
    Log.i("Not found:", "$name is not in database")
  }
}
```

在前面的代码中，根据`name`变量初始化的值，有四条可能的执行路径。如果使用`Atlantic`、`Pacific`或`Arctic`的任何一个值，则执行以下代码行：

```kt
Log.i("Found:", "$name is an ocean")
```

如果使用`Thames`、`Nile`或`Mississippi`的任何一个值，则执行以下代码行：

```kt
Log.i("Found:", "$name is a river")
```

如果使用了`Labrador`、`Beagle`或`Jack Russel`的任何一个值，则执行以下代码行：

```kt
Log.i("Found:", "$name is a dog")
```

如果没有使用海洋、河流或狗来初始化`name`变量，则应用程序将分支到`else`块并执行以下代码行：

```kt
Log.i("Not found:", "$name is not in database")
```

如果使用`name`初始化为`Nile`（如前面的代码所做的那样）执行应用程序，则将在 logcat 窗口中看到以下输出：

```kt
Found:: Nile is a river

```

运行应用几次，每次将`name`的初始化更改为新的内容。注意，当您将`name`初始化为一个明确由语句处理的内容时，我们会得到预期的输出。否则，我们会得到`else`块处理的默认输出。

如果我们有很多代码要在`when`块中的选项中执行，我们可以将所有代码都放在一个函数中，然后调用该函数。我在以下假设的代码中突出显示了更改的行：

```kt
   "Atlantic","Pacific", "Arctic" -> 
         printFullDetailsOfOcean(name)

```

当然，我们将需要编写新的`printFullDetailsOfOcean`函数。然后，当`name`初始化为一个明确由语句处理的海洋之一时，将执行`printFullDetailsOfOcean`函数。然后执行将返回到`when`块之外的第一行代码。

### 提示

您可能想知道将`name`变量放在`printFullDetailsOfOcean(name)`函数调用的括号中的意义。发生的情况是，我们将存储在`name`变量中的数据传递给`printFullDetailsOfOcean`函数。这意味着`printFullDetailsOfOcean`函数可以使用该数据。这将在下一章中更详细地介绍。

当然，这段代码严重缺乏与 GUI 的交互。我们已经看到如何从按钮点击中调用函数，但即使这样也不足以使这段代码在真正的应用程序中有价值。我们将在第十二章中看到我们如何解决这个问题，*将我们的 Kotlin 连接到 UI 和可空性*。

我们还有另一个问题，那就是代码执行完毕后，就什么都不做了！我们需要它不断地询问用户的指令，不只是一次，而是一遍又一遍。我们将在下一步解决这个问题。

# 使用循环重复代码

在这里，我们将通过查看 Kotlin 中的几种**循环**类型，包括`while`循环、`do-while`循环和`for`循环，学习如何以受控且精确的方式重复执行代码的部分。我们还将了解在何种情况下使用这些不同类型的循环是最合适的。

询问循环与编程有什么关系是完全合理的，但它们确实如其名称所示。它们是重复执行代码的一种方式，或者循环执行相同的代码部分，尽管每次可能会有不同的结果。

这可能意味着重复执行相同的操作，直到循环的代码提示循环结束。它可以是由循环代码本身指定的预定次数的迭代。它可能是直到满足预定情况或**条件**为止。或者，它可能是这些事情的组合。除了`if`、`else`和`when`，循环也是 Kotlin**控制流语句**的一部分。

我们将学习 Kotlin 提供的所有主要类型的循环，使用其中一些来实现一个工作的迷你应用程序，以确保我们完全理解它们。让我们先看一下 Kotlin 中的第一种和最简单的循环类型，即`while`循环。

# while 循环

Kotlin 的`while`循环具有最简单的语法。回想一下`if`语句；我们可以在`if`语句的条件表达式中使用几乎任何组合的运算符和变量。如果表达式评估为真，则执行`if`块中的代码。对于`while`循环，我们也使用一个可以评估为真或假的表达式：

```kt
var x = 10

while(x > 0) {
  Log.i("x=", "$x")
  x--
}
```

看一下上述代码；这里发生的情况如下：

1.  在`while`循环之外，声明了一个名为`x`的`Int`类型，并将其初始化为 10。

1.  然后，`while`循环开始；它的条件是`x > 0`。因此，`while`循环将执行其主体中的代码。

1.  循环体中的代码将重复执行，直到条件评估为假。

因此，上述代码将执行 10 次。

在第一次循环中，`x`等于 10，在第二次循环中，它等于 9，然后是 8，依此类推。但一旦`x`等于 0，它当然不再大于 0。此时，执行将退出`while`循环，并继续执行`while`循环之后的第一行代码（如果有的话）。

与`if`语句一样，`while`循环可能甚至不会执行一次。看一下以下示例，`while`循环中的代码将不会执行：

```kt
var x = 10

while(x > 10){
   // more code here.
   // but it will never run 
  // unless x is greater than 10.
}
```

此外，条件表达式的复杂度或循环体中的代码量没有限制；以下是另一个例子：

```kt
var newMessages = 3
var unreadMessages = 0

while(newMessages > 0 || unreadMessages > 0){
   // Display next message
   // etc.
}

// continue here when newMessages and unreadMessages equal 0
```

上述`while`循环将继续执行，直到`newMessages`和`unreadMessages`都等于或小于零。由于条件使用逻辑或运算符(`||`)，其中一个条件为真将导致`while`循环继续执行。

值得注意的是，一旦进入循环体，即使表达式在中途评估为假，循环体也会始终完成。这是因为直到代码尝试开始另一次循环时才会再次测试：

```kt
var x = 1

while(x > 0){
   x--
   // x is now 0 so the condition is false
   // But this line still runs
   // and this one
   // and me!
}
```

上述循环体将执行一次。我们还可以设置一个永远运行的`while`循环！这被称为**无限循环**；以下是一个无限循环的例子：

```kt
var x = 0

while(true){
   x++ // I am going to get very big!
}
```

上述代码将永远不会结束；它将永远循环。我们将看到一些控制何时跳出`while`循环的解决方案。接下来，我们将看一下`while`循环的变体。

# do-while 循环

`do`-`while`循环的工作方式与普通的`while`循环相同，只是`do`块的存在保证了即使`while`表达式的条件不评估为真，代码也会至少执行一次：

```kt
var y = 10
do {
  y++
  Log.i("In the do block and y=","$y")
}
while(y < 10)
```

如果您将此代码复制并粘贴到`onCreate`函数中的一个应用程序中，然后执行它，输出可能不是您所期望的。以下是输出：

```kt
In the do block and y=: 11

```

这是一个不太常用但有时是解决问题的完美方案。即使`while`循环的条件为假，`do`块也会执行其代码，将`y`变量递增到 11，并打印一条消息到 logcat。`while`循环的条件是`y < 10`，因此`do`块中的代码不会再次执行。但是，如果`while`条件中的表达式为真，则`do`块中的代码将继续执行，就像是常规的`while`循环一样。

# 范围

为了继续讨论循环，有必要简要介绍范围的主题。范围与 Kotlin 的数组主题密切相关，我们将在第十五章*处理数据和生成随机数*中更全面地讨论。接下来是对范围的快速介绍，以便我们能够继续讨论`for`循环。

看一下使用范围的以下代码行：

```kt
val rangeOfNumbers = 1..4 
```

发生的情况是，我们使用类型推断来创建一个值的列表，其中包含值 1、2、3 和 4。

我们还可以显式声明和初始化一个列表，如下面的代码所示：

```kt
val rangeOfNumbers = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
```

上面的代码使用`listOf`关键字来显式创建一个包含 1 到 10 的数字的列表。

在我们学习关于数组的更深入的知识时，我们将更深入地探讨它们的工作原理，第十五章*处理数据和生成随机数*。然后，我们将看到范围、数组和列表比我们在这里涵盖的要多得多。通过查看`for`循环，这个快速介绍有助于我们完成对循环的讨论。

# For 循环

要使用`for`循环，我们需要一个范围或列表。然后，我们可以使用`for`循环来遍历该列表，并在每一步执行一些代码；看一下以下示例：

```kt
// We could do this...
// val list = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
// It is much quicker to do this...
val list = 1..10
for (i in list)
  Log.i("Looping through list","Current value is $i")
```

看一下如果将此内容复制并粘贴到应用程序中会产生的输出：

```kt
Looping through list: Current value is 1
Looping through list: Current value is 2
Looping through list: Current value is 3
Looping through list: Current value is 4
Looping through list: Current value is 5
Looping through list: Current value is 6
Looping through list: Current value is 7
Looping through list: Current value is 8
Looping through list: Current value is 9
Looping through list: Current value is 10

```

从输出中可以看出，`list`变量确实包含从 1 到 10 的所有值。在每次循环中，`i`变量保存当前值。您还可以看到，`for`循环允许我们遍历所有这些值，并根据这些值执行一些代码。

此外，当我们希望循环包含多行代码时，可以在`for`循环中使用开放和关闭的大括号：

```kt
for (i in list){
  Log.i("Looping through list","Current value is $i")
   // More code here
  // etc.
}
```

在 Kotlin 中，`for`循环非常灵活，可以处理的不仅仅是简单的`Int`值。在本章中，我们不会探讨所有选项，因为我们需要先了解更多关于类的知识。然而，在本书的其余部分，我们将在许多地方回到`for`循环。

# 使用`break`和`continue`控制循环

刚刚讨论了通过代码控制循环的所有方法，重要的是要知道，有时我们需要提前退出循环，而不是按照循环的条件指定的那样执行。

对于这种情况，Kotlin 有`break`关键字。以下是`break`在`while`循环中的作用：

```kt
var countDown = 10
while(countDown > 0){

  if(countDown == 5)break

  Log.i("countDown =","$countDown")
  countDown --
}
```

在上面的代码中，`while`循环的条件应该使代码在`countDown`变量大于零时重复执行。然而，在`while`循环内部，有一个`if`表达式，检查`countDown`是否等于 5。如果等于 5，则使用`break`语句。此外，在`while`循环内部，`countDown`的值被打印到 logcat 窗口，并递减（减少 1）。当执行此代码时，看一下以下输出：

```kt
countDown =: 10
countDown =: 9
countDown =: 8
countDown =: 7
countDown =: 6

```

从上面的输出可以看出，当`countDown`等于 5 时，`break`语句执行，执行提前退出`while`循环，而不会打印到 logcat 窗口。

有时，我们可能只想执行循环中的一部分代码，而不是完全停止循环。为此，Kotlin 有`continue`关键字。看看下面的带有`while`循环的代码，它演示了我们如何在应用程序中使用`continue`：

```kt
var countUp = 0
while(countUp < 10){
  countUp++

  if(countUp > 5)continue

  Log.i("Inside loop","countUp = $countUp")
}
Log.i("Outside loop","countUp = $countUp")
```

在前面的代码中，我们将一个名为`countUp`的变量初始化为零。然后我们设置了一个`while`循环，当`countUp`小于 10 时继续执行。在`while`循环内部，我们增加（加 1）`countUp`。下一行代码检查`countUp`是否大于 5，如果是，就执行`continue`语句。下一行代码将`countUp`的值打印到 logcat 窗口。只有当`countUp`为 5 或更低时，打印值的代码行才会执行，因为`continue`语句将应用程序的执行返回到循环的开始。看看下面的代码输出，以验证发生了什么：

```kt
Inside loop: countUp = 1
Inside loop: countUp = 2
Inside loop: countUp = 3
Inside loop: countUp = 4
Inside loop: countUp = 5
Outside loop: countUp = 10

```

您可以在前面的输出中看到，当`countUp`的值为 5 或更低时，它被打印出来。一旦它的值超过 5，`continue`语句将阻止执行打印的代码行。然而，循环外的最后一行代码打印了`countUp`的值，你可以看到它的值是 10，这表明循环中的第一行代码，即增加`countUp`的代码，一直执行到`while`循环条件完成。

`break`和`continue`关键字也可以用在`for`循环和`do`-`while`循环中。

# 示例代码

如果你想玩转循环代码，可以创建一个名为`Loops Demo`的新项目，并将本章中的任何代码复制到`onCreate`函数的末尾。我已经将我们在讨论循环时使用的代码放在了`Chapter08/Loops Demo`文件夹中。

# 总结

在本章中，我们使用`if`、`else`和`when`来做出表达式的决策并分支我们的代码。我们看到并练习了`while`、`for`和`do`-`while`来重复我们代码的部分。此外，我们使用`break`在条件允许之前跳出循环，并使用`continue`有条件地执行循环中的部分代码。

如果你不记得所有内容也没关系，因为我们将不断地在整本书中使用所有这些技术和关键字。我们还将探索一些更高级的使用这些技术的方法。

在下一章中，我们将更仔细地研究 Kotlin 函数，这是我们所有测试和循环代码的去处。
