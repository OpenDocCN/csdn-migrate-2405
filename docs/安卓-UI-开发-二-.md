# 安卓 UI 开发（二）

> 原文：[`zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042`](https://zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用专用 Android 控件进行开发

*除了许多通用控件，如按钮、文本字段和复选框外，Android 还包括各种更专业的控件。虽然按钮相当通用，在许多情况下都有用途，但例如图库控件则更为针对性。在本章中，我们将开始研究更专业的 Android 控件，它们的出现位置以及最佳使用方法。*

尽管这些是非常专业的`View`类，但它们非常重要。如前所述（这一点真的非常重要）良好用户界面设计的一个基石是**一致性**。例如`DatePicker`控件。它绝对不是世界上最漂亮的日期选择器。它不是一个日历控件，因此用户有时很难选择确切的日期（大多数人会想到“下周二”，而不是“17 号星期二”）。然而，`DatePicker`是标准的！所以用户确切知道如何使用它，他们不必使用一个有问题的日历实现。本章将使用 Android 更专业的`View`和布局类：

+   `Tab`布局

+   `TextSwitcher`

+   `Gallery`

+   `DatePicker`

+   `TimePicker`

+   `RatingBar`

这些类具有非常特殊的目的，其中一些在实现方式上略有不同。本章将探讨如何以及在何处使用这些控件，以及在使用它们的实现细节上需要小心。我们还将讨论如何将这些元素最佳地融入到应用程序和布局中。

# 创建一个餐厅评论应用程序

在上一章中，我们构建了一个外卖应用程序。在本章中，我们将要看看餐厅评论。该应用程序将允许用户查看其他人对餐厅的看法，一个餐厅照片的图库，以及最终在线预订的部分。我们将应用程序分为三个部分：

+   **回顾**：此餐厅的评论和评分信息

+   **照片**：餐厅的照片图库

+   **预订**：向餐厅提出预订请求

当构建一个需要快速向用户展示这三个部分的应用程序时，最合理的选择是将每个部分放在屏幕上的一个标签页中。这样用户可以在三个部分之间切换，而无需同时将它们全部显示在屏幕上。这还节省了屏幕空间，为每个部分提供更多的空间。

**回顾**标签将包括人们对正在查看的餐厅的循环评论列表，以及餐厅的平均“星级”评分。

展示餐厅的照片是**照片**标签的工作。我们将在屏幕顶部为用户提供一个缩略图“轨道”，并使用剩余的屏幕空间显示所选图像。

对于**预订**标签，我们希望捕获用户的名字以及他们希望预订的时间（日期和时间）。最后，我们还需要知道预订将是为多少人。

# 动手时间——创建机器人评审项目结构

要开始这个示例，我们需要一个带有新的`Activity`的新项目。新的布局和`Activity`将与前两章的结构略有不同。为了构建标签式布局，我们需要使用`FrameLayout`类。因此，首先，我们将创建一个新的项目结构，并从一个框架开始，这个框架最终将成为我们的标签布局结构。这可以填充三个内容区域。

1.  使用 Android 命令行工具创建一个新的 Android 项目：

    ```kt
    android create project -n RoboticReview -p RoboticReview -k com.packtpub.roboticreview -a ReviewActivity -t 3

    ```

1.  在编辑器或 IDE 中打开`res/layout/main.xml`文件。

1.  清除默认代码（保留 XML 头）。

1.  创建一个根`FrameLayout`元素：

    ```kt
    <FrameLayout 

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  在新的`FrameLayout`元素内，添加一个`垂直 LinearLayout`：

    ```kt
    <LinearLayout android:id="@+id/review"
                  android:orientation="vertical"
                  android:layout_width="fill_parent"
                  android:layout_height="wrap_content">
    </LinearLayout>
    ```

1.  在`LinearLayout`之后，添加另一个空的`LinearLayout`元素：

    ```kt
    <LinearLayout android:id="@+id/photos"
                  android:orientation="vertical"
                  android:layout_width="fill_parent"
                  android:layout_height="wrap_content">
    </LinearLayout>
    ```

1.  然后，在第二个`LinearLayout`元素之后，添加一个空的`ScrollView`：

    ```kt
    <ScrollView android:id="@+id/reservation"
                android:layout_width="fill_parent"
                android:layout_height="fill_parent">
    </ScrollView>
    ```

`FrameLayout`将被 Android 标签结构用作内容区域，每个子元素都将成为一个标签的内容。在上面的布局中，我们为**评审**和**照片**部分添加了两个`LinearLayout`元素，并为**预订**标签添加了一个`ScrollView`。

## *刚才发生了什么？*

我们刚刚开始“餐厅评审”应用程序，为用户界面构建了一个框架。在继续示例之前，我们应该先浏览一下这个`main.xml`文件的几个关键部分。

首先，我们的根元素是一个`FrameLayout`。`FrameLayout`将其所有子元素锚定在自己的左上角。实际上，两个`LinearLayout`和`ScrollView`将相互重叠。这种结构可以用来形成类似于 Java AWT `CardLayout`的东西，`TabHost`对象将使用它来在相应标签处于激活状态时显示这些对象。

其次，每个`LinearLayout`和`ScrollView`都有一个 ID。为了将它们标识为标签根，我们需要能够从 Java 代码轻松访问它们。标签结构可能在 XML 中设计，但它们需要在 Java 中组合。

# 构建 TabActivity

为了继续，我们需要我们的`Activity`类来设置我们在`main.xml`文件中声明为标签的三个标签内容元素。按偏好，Android 中的所有标签都应该有一个图标。

以下是去掉图标的标签页的截图：

![构建 TabActivity](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_01.jpg)

以下是带有图标的标签页的截图：

![构建 TabActivity](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_02.jpg)

## 创建标签图标

安卓应用程序具有由系统提供的默认控件定义的特定外观和感觉。为了使所有应用程序对用户保持一致，应用开发者应遵循一系列的用户界面指南。虽然让应用程序脱颖而出很重要，但用户经常会因为应用程序不熟悉或看起来不协调而感到沮丧（这也是自动移植的应用程序通常非常不受欢迎的原因之一）。

## 安卓的标签和图标

在为应用程序选择标签图标时，最好实践是包含几个不同版本，以适应不同的屏幕大小和密度。在高密度屏幕上看起来很好的抗锯齿角，在低密度屏幕上看起来会很糟糕。对于非常小的屏幕，你也可以提供完全不同的图标，而不是丢失所有图标细节。当安卓标签被选中时，它们会显得凸起，而在未选中时则降低到背景中。安卓标签图标应该具有与它们所在标签相反的“雕刻”效果，即选中时降低，未选中时凸起。因此，图标主要有两种状态：选中状态和未选中状态。为了在这两种状态之间切换，标签图标通常由三个资源文件组成：

+   选中图标的图像

+   未选中图标的图像

+   一个描述图标两种状态的 XML 文件

标签图标通常是简单的形状，而图像大小是正方形（通常最大为 32 x 32 像素）。对于不同像素密度的屏幕，应使用图像的不同变体（详见第一章，*开发一个简单的活动*关于“资源选择”的细节）。通常，对于选中状态，你会使用深色外凸图像，因为当标签被选中时，标签背景是浅色的。对于未选中的图标，正好相反，应该使用浅色内凹图像。

安卓应用程序中的位图图像应始终为 PNG 格式。我们将**评论**标签的选中图标命名为 `res/drawable/ic_tab_selstar.png`，未选中图标文件命名为 `res/drawable/ic_tab_unselstar.png`。为了自动在这两张图像之间切换状态，我们定义了一个特殊的 `StateListDrawable` 作为 XML 文件。因此，**评论**图标实际上在一个名为 `res/drawable/review.xml` 的文件中，其看起来像这样：

```kt
<selector 
          android:constantSize="true">

    <item
        android:drawable="@drawable/ic_tab_selstar"
        android:state_selected="false"/>

    <item
        android:drawable="@drawable/ic_tab_unselstar"
        android:state_selected="true"/>
</selector>
```

注意 `<selector>` 元素的 `android:constantSize="true"` 属性。默认情况下，安卓会假定 `StateListDrawable` 对象中的每个状态都会导致图像大小不同，进而可能导致用户界面重新运行布局计算。这可能会相当耗时，所以最好声明你的每个状态都是完全相同的大小。

在这个例子中，我们将使用三个标签图标，每个图标有两种状态。这些图标分别名为`review`、`photos`和`book`。每个图标都由三个文件组成：一个用于选中状态的 PNG 文件，一个用于未选中状态的 PNG 文件，以及一个定义状态选择器的 XML 文件。从我们的应用程序中，我们只需要直接使用状态选择器的 XML 文件，实际的 PNG 文件由 Android API 来加载。

# 实现 ReviewActivity

和往常一样，我们希望在我们的`strings.xml`文件中有本地化的文本。打开`res/values/strings.xml`文件，并复制以下代码到它里面：

```kt
<resources>
    <string name="app_name">Robotic Review</string>
    <string name="review">Review</string>
    <string name="gallery">Photos</string>
    <string name="reservation">Reservations</string>
</resources>
```

# 行动时刻——编写 ReviewActivity 类

如前所述，我们需要在 Java 代码中设置我们的标签布局结构。幸运的是，Android 提供了一个非常实用的`TabActivity`类，它为我们完成了大部分繁重的工作，提供了一个现成的`TabHost`对象，我们可以用这个对象构建`Activity`的标签结构。

1.  打开之前生成的`ReviewActivity.java`文件，在编辑器或 IDE 中。

1.  不要扩展`Activity`，将类改为继承`TabActivity`：

    ```kt
    public class ReviewActivity extends TabActivity
    ```

1.  在`onCreate`方法中，完全移除`setContentView(R.layout.main)`这一行（由`android create project`工具生成）。

1.  首先，从你的父类中获取`TabHost`对象：

    ```kt
    TabHost tabs = getTabHost();
    ```

1.  接下来，我们将布局 XML 文件加载到`TabHost`的内容视图中：

    ```kt
    getLayoutInflater().inflate(
            R.layout.main,
            tabs.getTabContentView(),
            true);
    ```

1.  我们需要访问我们应用程序的其他资源：

    ```kt
    Resources resources = getResources();
    ```

1.  现在我们为**Review**标签定义一个`TabSpec`：

    ```kt
    TabHost.TabSpec details =
            tabs.newTabSpec("review").
            setContent(R.id.review).
            setIndicator(getString(R.string.review),
            resources.getDrawable(R.drawable.review));
    ```

1.  使用前面的模式为**Photos**和**Reservation**标签定义另外两个`TabSpec`变量。

1.  将每个`TabSpec`对象添加到我们的`TabHost`中：

    ```kt
    tabs.addTab(details);
    tabs.addTab(gallery);
    tabs.addTab(reservation);
    ```

这就完成了`ReviewActivity`类的标签结构的创建。

## *刚才发生了什么？*

我们为我们的新`ReviewActivity`构建了一个非常基本的标签布局。在使用标签时，我们并没有简单地使用`Activity.setContentView`方法，而是自己加载了布局 XML 文件。然后我们使用了`TabActivity`类提供的`TabHost`对象创建了三个`TabSpec`对象。`TabSpec`是一个构建器对象，它允许你构建你的标签内容，类似于使用`StringBuilder`构建文本的方式。

`TabSpec`的内容是将会附加到屏幕上标签的内容视图（通过`setContent`方法分配）。在这个例子中，我们选择了最简单的选项，在`main.xml`文件中定义了标签内容。也可以通过使用`TabHost.TabContentFactory`接口懒加载标签内容，或者甚至通过使用`setContent(Intent)`将外部`Activity`（如拨号器或浏览器）放入标签中。但是，为了这个例子的目的，我们使用了最简单的选项。

你会注意到`TabSpec`（类似于`StringBuilder`类）支持方法调用的链式操作，这使得以“单次设置”方法（如之前所做的）或分阶段构建`TabSpec`（即在从外部服务加载时）变得简单且灵活。

我们分配给`TabSpec`的`indicator`是将在标签上显示的内容。在前一个案例中，是一段文本和我们的图标。从 API 级别 4（Android 版本 1.6）开始，可以使用`View`对象作为`indicator`，允许完全自定义标签的外观和感觉。为了保持示例简单（并与早期版本兼容），我们提供了一个`String`资源作为`indicator`。

# 行动时间 - 创建评论布局

我们已经有了一个标签结构的框架，但里面还没有内容。第一个标签标题为**评论**，这就是我们将要开始的地方。我们已经完成了足够的 Java 代码以加载标签并将它们显示在屏幕上。现在我们回到`main.xml`布局文件，用一些提供用户评论信息的部件填充这个标签。

1.  在编辑器或 IDE 中打开`res/layout/main.xml`。

1.  在我们命名为`review`的`<LayoutElement>`内，添加一个新的`TextView`，它将包含餐厅的名称：

    ```kt
    <TextView android:id="@+id/name"
              android:textStyle="bold"
              android:textSize="25sp"
              android:textColor="#ffffffff"
              android:gravity="center|center_vertical"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  在新的`TextView`下方，添加一个新的`RatingBar`，我们将在这里显示其他人对餐厅的评分：

    ```kt
    <RatingBar android:id="@+id/stars"
               android:numStars="5"
               android:layout_width="wrap_content"
               android:layout_height="wrap_content"/>
    ```

1.  为了保持这个第一个标签简单，我们添加了一个`TextSwitcher`，我们可以在其中显示其他人对餐厅的评论：

    ```kt
    <TextSwitcher android:id="@+id/reviews"
                  android:inAnimation="@android:anim/fade_in"
                  android:outAnimation="@android:anim/fade_out"
                  android:layout_width="fill_parent"
                  android:layout_height="fill_parent"/>
    ```

在这个例子中，**评论**标签只有三个小部件，但可以轻松添加更多，让用户输入自己的评论。

## *刚才发生了什么*

我们刚刚为第一个标签组合了布局。我们创建的`RatingBar`具有`wrap_content`的宽度，这非常重要。如果你使用`fill_parent`，则`RatingBar`中可见的星星数量将尽可能多地适应屏幕。如果你想控制`RatingBar`上显示的星星数量，请坚持使用`wrap_content`，但还要确保（至少在竖屏布局上）`RatingBar`有自己的水平线。如果你现在在模拟器中安装`Activity`，你将不会在`TextView`或`TextSwitcher`中看到任何内容。

`TextSwitcher`没有默认动画，因此我们将“进入”动画指定为`android`包提供的默认`fade_in`，而“退出”动画将是`fade_out`。这种语法用于访问可以在`android.R`类中找到的资源。

## 使用切换器类

我们已经放置的`TextSwitcher`用于在不同的`TextView`对象之间进行动画切换。它非常适合显示像股票价格变化、新闻标题或在我们的案例中，评论这样的内容。它继承自`ViewSwitcher`，后者可以用于在任意两个通用`View`对象之间进行动画切换。`ViewSwitcher`扩展了`ViewAnimator`，后者可以用作一种动画`CardLayout`。

我们希望展示一系列来自过去客户的评论，并通过简短动画使它们之间渐变。`TextSwitcher` 需要两个 `TextView` 对象（它会要求我们动态创建），在我们的示例中。我们希望这些对象在资源文件中。

为了示例的下一部分，我们需要一些评论。而不是使用网络服务或类似的东西来获取真实的评论，这个示例将从其应用程序资源中加载一些评论。打开 `res/values/strings.xml` 文件，并添加带有一些可能评论的 `<string-array name="comments">`：

```kt
<string-array name="comments">
    <item>Just Fantastic</item>
    <item>Amazing Food</item>
    <item>What rubbish, the food was too hairy</item>
    <item>Messy kitchen; call the health inspector.</item>
</string-array>
```

# 行动时间——开启 TextSwitcher

我们希望 `TextSwitcher` 每 5 秒钟显示下一个列出的评论。为此，我们将需要使用新的资源和一个 `Handler` 对象。`Handler` 是 Android 应用程序和服务之间在线程之间发布消息的方式，也可以用于在将来的某个时间点安排消息。它比 `java.util.Timer` 更受推荐的结构，因为 `Handler` 对象不会分配新的 `Thread`。在我们的情况下，`Timer` 过于复杂，因为只有一个任务我们想要安排。

1.  在你的 `res/layout` 目录中创建一个名为 `review_comment.xml` 的新 XML 文件。

1.  将以下代码复制到新的 `review_comment.xml` 文件中：

    ```kt
    <TextView 
    ```

    ```kt

        android:gravity="left|top"
        android:textStyle="italic"
        android:textSize="16sp"
        android:padding="5dip"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
    ```

1.  在编辑器或 IDE 中打开 `ReviewActivity.java` 文件。

1.  我们需要能够加载 `TextSwitcher` 的 `review_comment` 资源，所以 `ReviewActivity` 需要实现 `ViewSwitcher.ViewFactory` 接口。

1.  为了更新 `TextSwitcher`，我们需要与一个 `Handler` 交互，在这里最简单的方法是也实现 `Runnable`。

1.  在 `ReviewActivity` 类的顶部，声明一个 `Handler` 对象：

    ```kt
    private final Handler switchCommentHandler = new Handler();
    ```

1.  我们还希望在我们的 `run()` 方法中保留对 `TextSwitcher` 的引用，当我们切换评论时：

    ```kt
    private TextSwitcher switcher;
    ```

1.  为了显示评论，我们将需要一个评论数组，以及一个索引来跟踪 `TextSwitcher` 正在显示哪个评论：

    ```kt
    private String[] comments;
    private int commentIndex = 0;
    ```

1.  现在，在 `onCreate` 方法中，将 `TabSpec` 对象添加到 `TabHost` 之后，从 `Resources` 中读取 `comments` 字符串数组：

    ```kt
    comments = resources.getStringArray(R.array.comments);
    ```

1.  接下来，找到 `TextSwitcher` 并将其分配给 `switcher` 字段：

    ```kt
    switcher = (TextSwitcher)findViewById(R.id.reviews);
    ```

1.  告诉 `TextSwitcher`，`ReviewActivity` 对象将是它的 `ViewFactory`：

    ```kt
    switcher.setFactory(this);
    ```

1.  为了符合 `ViewFactory` 的规范，我们需要编写一个 `makeView` 方法。在我们的例子中这非常简单——只需膨胀 `review_comment` 资源：

    ```kt
    public View makeView() {
        return getLayoutInflater().inflate(
                R.layout.review_comment, null);
    }
    ```

1.  重写 `onStart` 方法，以便我们可以发布之前声明的 `Handler` 对象上的第一个定时事件：

    ```kt
    protected void onStart() {
        super.onStart();
        switchCommentHandler.postDelayed(this, 5 * 1000l);
    }
    ```

1.  类似地，重写 `onStop` 方法以取消任何未来的回调：

    ```kt
    protected void onStop() {
        super.onStop();
        switchCommentHandler.removeCallbacks(this);
    }
    ```

1.  最后，`run()` 方法在 `TextSwitcher` 中交替评论，并在 `finally` 块中，在 5 秒后将自身重新发布到 `Handler` 队列中：

    ```kt
    public void run() {
        try {
            switcher.setText(comments[commentIndex++]);
            if(commentIndex >= comments.length) {
                commentIndex = 0;
            }
        } finally {
            switchCommentHandler.postDelayed(this, 5 * 1000l);
        }
    }
    ```

使用`Handler`对象而不是创建`Thread`对象意味着所有定时任务可以共享主用户界面线程，而不是各自分配一个单独的线程。这减少了应用程序在设备上占用的内存和 CPU 负载，对应用程序性能和电池寿命有直接影响。

## *刚才发生了什么?*

我们刚刚构建了一个简单的定时器结构，用旋转的评论数组更新`TextSwitcher`。`Handler`类是在两个应用程序线程之间发布消息和操作的一种便捷方式。在 Android 中，与 Swing 一样，用户界面不是线程安全的，因此线程间通信变得非常重要。`Handler`对象试图将自己绑定到创建它的线程（在前面的情况下，是`main`线程）。

创建`Handler`对象的线程必须有一个关联的`Looper`对象，这是前提条件。你可以在自己的线程中通过继承`HandlerThread`类或使用`Looper.prepare()`方法来设置这个。发送到`Handler`对象的消息将由与同一线程关联的`Looper`执行。通过将我们的`ReviewActivity`（实现了`Runnable`）发送到我们在`main`线程中创建的`Handler`对象，我们知道无论哪个线程发布它，`ReviewActivity.run()`方法都将在`main`线程上执行。

对于长时间运行的任务（例如获取网页或长时间的计算），Android 提供了一个与`SwingWorker`类惊人相似的类，名为`AsyncTask`。`AsyncTask`（与`Handler`一样）可以在`android.os`包中找到，你可以通过继承来使用它。`AsyncTask`用于允许后台任务与用户界面之间的交互（以更新进度条或类似需求）。

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_03.jpg)

# 创建一个简单的照片画廊

`Gallery`这个词的使用有点误导人，它实际上是一个具有“单选项目”选择模型的水平行项目。在这个例子中，我们将使用`Gallery`类做它最擅长的事情，即显示缩略图。但是，正如你将看到的，它能够显示几乎任何内容的滚动列表。由于`Gallery`是一个微调器，你可以以与`Spinner`对象或`ListView`相同的方式使用它，即使用`Adapter`。

# 动手时间——构建照片标签

在我们能够将图像添加到`Gallery`之前，我们需要在屏幕上有一个`Gallery`对象。为了开始这个练习，我们将向我们的标签中的`FrameLayout`添加一个`Gallery`对象和一个`ImageView`。这将在本章开始时创建的**Photos**标签下显示。我们将坚持使用相对传统的照片画廊模型，在屏幕顶部滑动缩略图，在下面显示选定图像的完整视图。

1.  在你的编辑器或 IDE 中打开`res/layout/main.xml`。

1.  在第二个`LinearLayout`中，使用`android:id="@+id/photos"`，添加一个新的`Gallery`元素以容纳缩略图：

    ```kt
    <Gallery android:id="@+id/gallery"
             android:layout_width="fill_parent"
             android:layout_height="wrap_content"/>
    ```

1.  默认情况下，`Gallery`对象会将内容挤压在一起，这在我们的案例中看起来并不好。你可以通过使用`Gallery`类的`spacing`属性，在项目之间添加一点内边距：

    ```kt
    android:spacing="5dip"
    ```

1.  我们在`Gallery`正上方也有标签页，并且在它下面会直接放置一个`ImageView`。同样，这里不会有任何内边距，所以我们需要使用外边距来添加一些空间：

    ```kt
    android:layout_marginTop="5dip"
    android:layout_marginBottom="5dip"
    ```

1.  现在创建一个`ImageView`，我们可以用它来显示全尺寸的图片：

    ```kt
    <ImageView android:id="@+id/photo"
               android:layout_width="fill_parent"
               android:layout_height="fill_parent"/>
    ```

1.  为了确保全屏显示能正确缩放，我们需要在`ImageView`上指定`scaleType`：

    ```kt
    android:scaleType="centerInside"
    ```

`Gallery`元素在屏幕顶部为我们提供了缩略图轨道。在`Gallery`中选择的图片将在`ImageView`小部件中以全尺寸显示。

## *刚才发生了什么？*

我们刚刚用基本照片画廊所需的标准小部件填充了第二个标签页。这个结构非常通用，但用户也非常熟悉和理解。`Gallery`类将处理缩略图、滚动和选择。但是，你需要将选定的图片填充到主`ImageView`中，并提供`Gallery`对象要在屏幕上显示的缩略图小部件。

`Gallery`元素上的间距属性将添加一些空白，这作为缩略图之间的简单分隔符。你也可以在每个缩略图图像中添加边框，为返回的每个缩略图`ImageView`小部件添加边框，或者使用自定义小部件创建边框。

## 创建一个缩略图小部件

为了在`Gallery`对象中显示缩略图，我们需要为每个缩略图创建一个`ImageView`对象。我们可以在 Java 代码中轻松完成，但像往常一样，即使是最基本的小部件，也最好使用 XML 资源构建。在这种情况下，在`res/layout`目录中创建一个新的 XML 资源。将新文件命名为`gallery_thn.xml`，并将以下代码复制到其中：

```kt
<ImageView 
           android:scaleType="fitXY"/>
```

没错，它只有两行 XML，但重申一遍，这允许我们为许多不同的配置自定义此小部件，而无需编辑 Java 代码。虽然编辑代码可能看起来不是问题（资源需要重新编译），但你也同样不希望最终得到一系列长长的`if`语句来决定如何确切地创建`ImageView`对象。

## 实现一个 GalleryAdapter

为了简化问题，本例我们将继续使用应用资源。我们将有两个资源 ID 数组，一个是缩略图，另一个是完整尺寸的图片。`Adapter`实现期望为每个项目提供一个标识符。在下一个示例中，我们将提供完整尺寸图像的资源 ID 作为标识符，这样我们在`Adapter`实现之外的类中可以轻松访问完整尺寸的图像。虽然这是一个不寻常的约定，但它为我们提供了一种在已定义结构内传递图像资源的便捷方式。

为了显示你的图库，你需要一些图像进行展示（我的尺寸为 480 x 319 像素）。对于这些图像中的每一个，你都需要在`Gallery`对象中显示一个缩略图。通常，这些应该是实际图像的缩小版本（我的缩小到 128 x 84 像素）。

# 是时候行动了——GalleryAdapter

创建`GalleryAdapter`与我们在第二章中创建的`ListAdapter`类非常相似。但是，`GalleryAdapter`将使用`ImageView`对象而不是`TextView`对象。它还将两个资源列表绑定在一起，而不是使用对象模型。

1.  在你的项目根包中创建一个新的 Java 类，名为`GalleryAdapter`。它应该扩展`BaseAdapter`类。

1.  声明一个整数数组来保存缩略图资源的 ID：

    ```kt
    private final int[] thumbnails = new int[]{
        R.drawable.curry_view_thn,
        R.drawable.jai_thn,
        // your other thumbnails
    };
    ```

1.  声明一个整数数组来保存完整尺寸图像资源的 ID：

    ```kt
    private final int[] images = new int[]{
        R.drawable.curry_view,
        R.drawable.jai,
        // your other full-size images
    };
    ```

1.  `getCount()`方法仅仅是`thumbnails`数组的长度：

    ```kt
    public int getCount() {
        return thumbnails.length;
    }
    ```

1.  `getItem(int)`方法返回完整尺寸图像资源的 ID：

    ```kt
    public Object getItem(int index) {
        return Integer.valueOf(images[index]);
    }
    ```

1.  如前所述，`getItemId(int)`方法返回完整尺寸图像资源的 ID（几乎与`getItem(int)`完全一样）：

    ```kt
    public long getItemId(int index) {
        return images[index];
    }
    ```

1.  最后，`getView(int, View, ViewGroup)`方法使用`LayoutInflater`读取并填充我们在`gallery_thn.xml`布局资源中创建的`ImageView`：

    ```kt
    public View getView(int index, View reuse, ViewGroup parent) {
        ImageView view = (reuse instanceof ImageView)
                ? (ImageView)reuse
                : (ImageView)LayoutInflater.
                             from(parent.getContext()).
                             inflate(R.layout.gallery_thn, null);
        view.setImageResource(thumbnails[index]);
        return view;
    }
    ```

`Gallery`类是`AdapterView`的子类，因此其功能与`ListView`对象相同。`GalleryAdapter`将为`Gallery`对象提供`View`对象以显示缩略图。

## *刚才发生了什么*

与上一章构建的`Adapter`类类似，`GalleryAdapter`将尝试重用其`getView`方法中指定的任何`View`对象。然而，一个主要的区别是，这个`GalleryAdapter`是完全自包含的，并且总是显示相同的图像列表。

这个`GalleryAdapter`的示例非常简单。你也可以构建一个持有位图对象而不是资源 ID 引用的`GalleryAdapter`。然后你会使用`ImageView.setImageBitmap`方法，而不是`ImageView.setImageResource`。

你也可以通过让`ImageView`将全尺寸图片缩放成缩略图来消除缩略图。这将只需要修改`gallery_thn.xml`资源文件，以指定每个缩略图所需的大小。

```kt
<ImageView 
           android:maxWidth="128dip"
           android:adjustViewBounds="true"
           android:scaleType="centerInside"/>
```

`adjustViewBounds`属性告诉`ImageView`调整自身大小，以保持其中图片的宽高比。我们还改变了`scaleType`属性为`centerInside`，当图片缩放时，这也会保持图片的宽高比。最后，我们为`ImageView`设置了最大宽度。使用标准的`layout_width`或`layout_height`属性会被`Gallery`类忽略，因此我们改为向`ImageView`指定所需缩略图的大小（`layout_width`和`layout_height`属性由`Gallery`处理，而`maxWidth`和`maxHeight`由`ImageView`处理）。

这将是一个标准的速度/大小权衡。拥有缩略图会占用更多的应用空间，但让`ImageView`执行缩放会使应用变慢。`ImageView`中的缩放算法也不会像 Adobe Photoshop 这样的图像处理应用中的缩放那样高质量。在大多数情况下这不会是问题，但如果你有高细节的图片，通常使用更简单的缩放算法会出现“缩放失真”。

# 是时候行动了——让图库工作起来

既然我们已经让`GalleryAdapter`工作起来了，我们需要将`Gallery`、`GalleryAdapter`和`ImageView`连接起来，以便当选择了一个缩略图时，可以在`ImageView`对象中显示该图片的全视图。

1.  在你的编辑器或 IDE 中打开`ReviewActivity`源代码。

1.  在`ReviewActivity`实现的接口中添加`AdapterView.OnItemSelectedListener`。

1.  在`TextSwitcher`声明下方，声明一个对`ImageView`的引用，该`ImageView`将用于显示全尺寸的图片：

    ```kt
    private TextSwitcher switcher;
    private ImageView photo;
    ```

1.  在`onCreate`方法的末尾，找到名为`photo`的`ImageView`并将其分配给你刚刚声明的引用：

    ```kt
    photo = ((ImageView)findViewById(R.id.photo));
    ```

1.  现在，获取在`main.xml`布局资源中声明的`Gallery`对象：

    ```kt
    Gallery photos = ((Gallery)findViewById(R.id.gallery));
    ```

1.  创建一个新的`GalleryAdapter`并将其设置在`Gallery`对象上：

    ```kt
    photos.setAdapter(new GalleryAdapter());
    ```

1.  将`Gallery`对象的`OnItemSelectedListener`设置为`this`：

    ```kt
    photos.setOnItemSelectedListener(this);
    ```

1.  在`ReviewActivity`类的末尾，添加`onItemSelected`方法：

    ```kt
    public void onItemSelected(
            AdapterView<?> av, View view, int idx, long id) {
        photo.setImageResource((int)id);
    }
    ```

1.  `OnItemSelectedListener`还需要一个`onNothingSelected`方法，但对于这个例子，我们不需要它做任何事情。

`GalleryAdapter`通过`id`参数为`ReviewActivity`提供加载照片全视图所需的资源。如果图片位于远程服务器上，`id`参数也可以用作索引或标识符。

## *刚才发生了什么？*

我们现在已经将`Gallery`对象连接到`ImageView`，我们将在其中显示全尺寸图片，而不是缩略图。我们使用了项目 ID 作为将全尺寸图片的资源 ID 直接发送到事件监听器的方式。这是一个相当奇怪的概念，因为你通常会使用对象模型。然而，在这个例子中，引入一个对象模型不仅仅会带来一个新类，它还需要在事件触发时从`Adapter`获取图片对象的另一个方法调用。

当你在像`Gallery`这样的`AbsSpinner`类上指定一个`Adapter`时，它会默认尝试选择从其新`Adapter`返回的第一个项目。这进而会通知已注册的`OnItemSelectedListener`对象。然而，由于 Android 用户界面对象使用的单线程模型，这个事件不会立即触发，而是在我们从`onCreate`方法返回后一段时间触发。当我们在`Gallery`对象上调用`setAdapter(new GalleryAdapter())`时，它会安排一个选择变更事件，然后我们收到这个事件。该事件导致`ReviewActivity`类显示`GalleryAdapter`对象中的第一张照片。

如果你现在在模拟器中重新安装应用程序，你将能够转到**照片**标签，浏览你用`GalleryAdapter`填充的所有图片的`Gallery`。

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_04.jpg)

## 小测验

1.  如果在前一个例子中，你将`OnItemSelectedListener`替换为`OnItemClickListener`（像在`ListView`示例中所做的那样），会发生什么？

    1.  全尺寸图片不再出现。

    1.  当触摸缩略图时，`Gallery`不会旋转它们。

    1.  只有当点击缩略图时，全尺寸照片才会出现。

1.  `ScaleType`值`fitXY`和`centerInside`之间的主要区别是什么？

    1.  `fitXY`类型会将图片锚定到左上角，而`centerInside`会在`ImageView`中居中图片。

    1.  `fitXY`会使图片扭曲到`ImageView`的大小，而`centerInside`将保持图片的宽高比。

    1.  `centerInside`会使较大的轴被裁剪，以使图片适应`ImageView`，而`fitXY`会缩放图片，使较大轴的大小与`ImageView`相同。

1.  当使用`wrap_content`属性时，什么决定了包含`ImageView`对象的`Gallery`对象的大小？

    1.  `ImageView`对象的宽度和高度，由其内容图片的大小，或者它们的`maxWidth`和`maxHeight`参数决定。

    1.  `Gallery`对象上的`itemWidth`和`itemHeight`参数。

    1.  设置在`ImageView`对象上的`LayoutParams`（通过`setLayoutParams`方法，或者`layout_width`/`layout_height`属性）。

## 尝试英雄——动画和外部资源

既然你已经让基本示例运行起来，尝试稍微改善一下用户体验。当你触摸图像时，它们应该真正地动画显示，而不是立即改变。它们也应该来自外部资源，而不是应用程序资源。

1.  将全尺寸图像的`ImageView`对象更改为`ImageSwitcher`，使用标准的 Android 淡入/淡出动画。

1.  从项目中移除缩略图，并使用在`gallery_thn.xml`文件中声明的`ImageView`来缩放图像。

1.  从应用程序资源 ID 列表更改为`Uri`对象列表，以便从外部网站下载图像。

# 构建预定标签

虽然这个例子的**评论**和**照片**标签关注的是信息的展示，但**预定**标签将关注于捕获预定的详细信息。我们实际上只需要三部分信息：

+   预定需要用到的名字

+   预定的日期和时间

+   预定的人数

在这个例子的这部分，我们将创建几个具有格式化标签的小部件。例如，**人数：2**，这将随着用户更改值而更新人数。为了简单地进行这个操作，我们指定小部件的文本（在布局文件中指定）将包含用于显示的格式。作为初始化过程的一部分，我们从`View`对象读取文本，并使用它来创建一个格式结构。一旦有了格式，我们就可以用它的初始值填充`View`。

# 行动时间——实现预定布局

在我们的`main.xml`布局资源中，我们需要添加将形成**预定**标签的`View`对象。目前它仅包含一个空的`ScrollView`，如果整个用户界面不适合屏幕，这将使用户能够垂直滚动布局。

1.  在编辑器或 IDE 中打开`main.xml`文件。

1.  在我们之前为`Reservation`标签创建的`<ScrollView>`内。声明一个新的垂直`LinearLayout`元素：

    ```kt
    <LinearLayout android:orientation="vertical"
                  android:layout_width="fill_parent"
                  android:layout_height="wrap_content">
    ```

1.  在新的`LinearLayout`元素内，创建一个`TextView`以询问用户预定应使用什么名字：

    ```kt
    <TextView android:text="Under What Name:"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  在`TextView`标签后，创建一个`EditText`以允许用户输入预定的名字：

    ```kt
    <EditText android:id="@+id/name"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  创建另一个`TextView`标签，询问用户将有多少人参加。这包括一个格式元素，我们将在其中放置数字：

    ```kt
    <TextView android:id="@+id/people_label"
              android:text="How Many People: %d"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  添加一个`SeekBar`，用户可以通过它告诉我们将有多少人参加：

    ```kt
    <SeekBar android:id="@+id/people"
             android:max="20"
             android:progress="1"
             android:layout_width="fill_parent"
             android:layout_height="wrap_content"/>
    ```

1.  使用另一个`TextView`询问用户预定将在哪一天：

    ```kt
    <TextView android:text="For What Date:"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  添加一个`Button`以显示预定日期。当用户点击这个`Button`时，我们会请他选择一个新的日期：

    ```kt
    <Button android:id="@+id/date"
            android:text="dd - MMMM – yyyy"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

1.  创建另一个`TextView`标签来询问预定时间：

    ```kt
    <TextView android:text="For What Time:"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  添加另一个`Button`以显示时间，并允许用户更改它：

    ```kt
    <Button android:id="@+id/time"
            android:text="HH:mm"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

1.  最后，添加一个`Button`以完成预订，并为表单中的其余输入添加一些边距：

    ```kt
    <Button android:id="@+id/reserve"
            android:text="Make Reservation"
            android:layout_marginTop="15dip"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

前面的几个小部件包含了标签的格式而非标签文本，实际的标签将在 Java 代码中生成和设置。这是因为当用户更改日期、时间或预期预订的人数时，这些标签可能会发生变化。

## *刚才发生了什么？*

在**预订**标签中，我们询问用户预订的人数，为了获取他们的答案，我们使用了`SeekBar`对象。`SeekBar`的工作方式与 Swing 中的`JSlider`非常相似，并为用户提供了一种选择预订人数的方式，只要这个数字在我们定义的范围内即可。Android 中的`SeekBar`实际上是建立在`ProgressBar`类之上的，因此继承了其所有 XML 属性，有时这可能显得有些奇怪。不幸的是，与`JSlider`或`JProgressBar`不同，`SeekBar`类没有最小值，由于你不能为 0 人预订，我们通过在显示前始终将`SeekBar`的选择值加 1 来解决这个问题。这意味着默认值是`1`（将显示的值设置为 2 人）。

### 注意

大多数人可能会为两个人预订餐厅，因此默认值为`1`。

在**人数：**标签中，我们加入了一个`%d`，这是一个`printf`标记，用于放置用户预订的人数。当用户操作`SeekBar`时，我们将使用`String.format`更新标签为用户选择的数字。在“日期”和“时间”`Button`标签中，我们希望显示当前为预订选择的日期和时间。我们在 XML 文件中设置了要显示此数据的格式，稍后我们将使用标准的`java.text.SimpleDateFormat`解析它。

我们之前的示例中的国际化怎么办？我们不应该把标签放在`strings.xml`文件中，这样布局就不需要改变吗？答案是：是的，如果你想国际化用户界面。稍后，请确保你的所有显示文本都在应用程序资源文件中。然而，我强烈建议直接从布局中获取格式字符串，因为它允许你将格式数据解耦到一个额外的层次。

在前面的布局中，你创建了用于显示日期和时间的`Button`小部件。为什么不直接使用`DatePicker`和`TimePicker`对象呢？答案是：不幸的是，它们不适合正常的布局。它们占用了大量的垂直空间，并且不能水平缩放。如果我们在这个用户界面中内联放置一个`DatePicker`和`TimePicker`，它看起来将像左边的截图，而实际的用户界面是右边的截图。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_05b.jpg)

如你所见，`Button`对象提供了一个更整洁的用户界面。值得庆幸的是，Android 为我们提供了`DatePickerDialog`和`TimePickerDialog`，正好适用于这种情况。当用户点击其中一个`Button`小部件时，我们会弹出适当的对话框，并在他确认后更新所选`Button`的标签。

尽管使用`Button`和`Dialog`至少增加了用户界面的两次触摸操作，但它极大地改善了应用程序的外观和感觉。如果界面没有正确对齐，用户会感到烦恼，即使他们无法说出为什么感到烦恼。用户觉得讨厌或烦恼的屏幕是他们将避免的，或者更糟的是——直接卸载。

# 行动时间——初始化预订标签

在**预订**标签中我们使用了格式化的标签。这些标签不应直接显示给用户，但在让用户看到之前需要用数据填充它们。为此，我们需要再次回到 Java 代码中，构建一些功能来记住格式，并填充标签。

1.  在编辑器或 IDE 中打开`ReviewActivity`的 Java 源文件。

1.  在你迄今为止声明的所有字段下方，我们需要为**预订**标签添加一些内容。声明一个`String`来记住**人数**标签的格式：

    ```kt
    private String peopleLabelFormat;
    ```

1.  然后声明一个对**人数**标签的引用：

    ```kt
    private TextView peopleLabel;
    ```

1.  为`date Button`的格式声明一个`SimpleDateFormat`对象：

    ```kt
    private SimpleDateFormat dateFormat;
    ```

1.  声明对`date Button`的引用：

    ```kt
    private Button date;
    ```

1.  为`time Button`的格式添加另一个`SimpleDateFormat`：

    ```kt
    private SimpleDateFormat timeFormat;
    ```

1.  接下来，为`time Button`对象声明一个`Button`引用：

    ```kt
    private Button time;
    ```

1.  在`onCreate`方法的末尾，我们需要初始化**预订**标签。首先使用`TextView.getText()`方法分配`peopleLabel`并获取`peopleLabelFormat`：

    ```kt
    peopleLabel = (TextView)findViewById(R.id.people_label);
    peopleLabelFormat = peopleLabel.getText().toString();
    ```

1.  然后获取`date Button`的引用及其标签格式：

    ```kt
    date = (Button)findViewById(R.id.date);
    dateFormat = new SimpleDateFormat(date.getText().toString());
    ```

1.  对`time Button`及其标签格式做同样的操作：

    ```kt
    time = (Button)findViewById(R.id.time);
    timeFormat = new SimpleDateFormat(time.getText().toString());
    ```

1.  现在，我们需要用默认日期和时间填充`Button`对象，为此我们需要一个`Calendar`对象：

    ```kt
    Calendar calendar = Calendar.getInstance();
    ```

1.  如果现在是下午 4 点以后，那么预订很可能应该是在下一天，所以如果这种情况，我们会在`Calendar`中加一天：

    ```kt
    if(calendar.get(Calendar.HOUR_OF_DAY) >= 16) {
        calendar.add(Calendar.DATE, 1);
    }
    ```

1.  现在我们设置`Calendar`对象上的预订默认时间：

    ```kt
    calendar.set(Calendar.HOUR_OF_DAY, 18);
    calendar.clear(Calendar.MINUTE);
    calendar.clear(Calendar.SECOND);
    calendar.clear(Calendar.MILLISECOND);
    ```

1.  从`Calendar`对象设置`date`和`time`按钮的标签：

    ```kt
    Date reservationDate = calendar.getTime();
    date.setText(dateFormat.format(reservationDate));
    time.setText(timeFormat.format(reservationDate));
    ```

1.  现在，我们需要`SeekBar`以便获取其默认值（如布局应用程序资源中声明的那样）：

    ```kt
    SeekBar people = (SeekBar)findViewById(R.id.people);
    ```

1.  然后，我们可以使用标签格式和`SeekBar`值来填充**人数**标签：

    ```kt
    peopleLabel.setText(String.format(
                peopleLabelFormat,
                people.getProgress() + 1));
    ```

现在我们有了标签需要显示在用户界面上的各种格式。这允许我们在用户更改预订参数时重新生成标签。

## *刚才发生了什么？*

**预订**标签现在将用预订的默认数据填充，并且所有标签中的格式都已消失。你可能已经注意到在之前的代码中有许多对`toString()`的调用。Android 的`View`类通常接受任何`CharSequence`作为标签。这比`String`类允许更高级的内存管理，因为`CharSequence`可以是`StringBuilder`，或者可以是实际文本数据的`SoftReference`的门面。

然而，大多数传统的 Java API 期望得到一个`String`，而不是一个`CharSequence`，因此我们使用`toString()`方法以确保我们有一个`String`对象。如果底层的`CharSequence`是一个`String`对象，`toString()`方法就是一个简单的`return this;`（这将起到类型转换的作用）。

同样，为了解决`SeekBar`没有最小值的事实，我们在填充`peopleLabel`的最后一行时，将其当前值加`1`。虽然`date`和`time`格式被存储为`SimpleDateFormat`，但我们将`peopleLabelFormat`存储为`String`，并在需要更新标签时通过`String.format`运行它。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_07.jpg)

# 动手时间——监听 SeekBar

界面现在已用默认数据填充。但是，它根本不具备交互性。如果你拖动`SeekBar`，**人数：**标签将保持在其默认值**2**。我们需要一个事件监听器，在`SeekBar`被使用时更新标签。

1.  在编辑器或 IDE 中打开`ReviewActivity`的 Java 源文件。

1.  将`SeekBar.OnSeekBarChangeListener`添加到`ReviewActivity`实现的接口中。

1.  在`onCreate`中，使用`findViewById`获取`SeekBar`之后，将其`OnSeekBarChangeListener`设置为`this`：

    ```kt
    SeekBar people = (SeekBar)findViewById(R.id.people);
    people.setOnSeekBarChangeListener(this);
    ```

1.  实现`onProgressChanged`方法以更新`peopleLabel`：

    ```kt
    public void onProgressChanged(
                SeekBar bar, int progress, boolean fromUser) {
        peopleLabel.setText(String.format(
                peopleLabelFormat, progress + 1));
    }
    ```

1.  实现一个空的`onStartTrackingTouch`方法：

    ```kt
    public void onStartTrackingTouch(SeekBar bar) {}
    ```

1.  实现一个空的`onStopTrackingTouch`方法：

    ```kt
    public void onStopTrackingTouch(SeekBar bar) {}
    ```

`String.format`方法是 Android 中在本地化字符串中放置参数的常用方法。虽然这与普通的`java.text.MessageFormat`类有所不同，但在 Android 中首选这种方法（尽管仍然支持`MessageFormat`）。

## *刚才发生了什么？*

当你在模拟器中重新安装应用程序时，你现在可以使用`SeekBar`来选择预订的人数。尽管我们没有实现`onStartTrackingTouch`或`onStopTrackingTouch`方法，但如果你默认隐藏实际状态值，它们会非常有用。例如，你可以使用一个包含人员图标的`Dialog`来告知用户预订的人数。当他们触摸`SeekBar`时——显示`Dialog`，然后当他们释放`SeekBar`时——再次隐藏`Dialog`。

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_08.jpg)

# 动手时间——选择日期和时间

我们已经让`SeekBar`按预期工作，但`date`和`time Button`控件呢？当用户触摸它们时，他们希望能够为预订选择不同的日期或时间。为此，我们需要一个古老的`OnClickListener`，以及`DatePickerDialog`和`TimePickerDialog`类。

1.  再次在编辑器或 IDE 中打开`ReviewActivity` Java 源文件。

1.  将`View.OnClickListener`、`DatePickerDialog.OnDateSetListener`和`TimePickerDialog.OnTimeSetListener`添加到`ReviewActivity`实现的接口中。你的类声明现在应该看起来像这样：

    ```kt
    public class ReviewActivity extends TabActivity
            implements ViewSwitcher.ViewFactory,
            Runnable,
            AdapterView.OnItemSelectedListener,
            SeekBar.OnSeekBarChangeListener,
            View.OnClickListener,
            DatePickerDialog.OnDateSetListener,
            TimePickerDialog.OnTimeSetListener {
    ```

1.  实现一个实用方法，用指定的`SimpleDateFormat`将`CharSequence`解析为`Calendar`对象：

    ```kt
    private Calendar parseCalendar(
            CharSequence text, SimpleDateFormat format) {
    ```

1.  打开一个`try`块，以便在`CharSequence`不符合`SimpleDateFormat`格式时处理解析错误：

1.  将`CharSequence`解析为`Date`对象：

    ```kt
    Date parsedDate = format.parse(text.toString());
    ```

1.  然后创建一个新的`Calendar`对象：

    ```kt
    Calendar calendar = Calendar.getInstance();
    ```

1.  将`Calendar`对象的时间设置为`Date`对象中的时间：

    ```kt
    calendar.setTime(parsedDate);
    ```

1.  返回解析后的`Calendar`对象：

    ```kt
    return calendar;
    ```

1.  在这个方法中，你需要`捕获(ParseException)`。我建议将其包装在`RuntimeException`中并重新抛出：

    ```kt
    catch(ParseException pe) {
        throw new RuntimeException(pe);
    }
    ```

1.  在`onCreate`方法中，设置`date`和`time Button`控件的标签后，将它们的`OnClickListener`设置为`this`：

    ```kt
    date.setText(dateFormat.format(reservationDate));
    time.setText(timeFormat.format(reservationDate));
    date.setOnClickListener(this);
    time.setOnClickListener(this);

    ```

1.  实现`onClick`方法，以监听用户点击`date`或`time Button`的操作：

    ```kt
    public void onClick(View view) {
    ```

1.  使用`View`参数确定点击的`View`是否是`date Button`：

    ```kt
    if(view == date) {
    ```

1.  如果是，使用`parseCalendar`方法解析`date Button`控件的标签当前值：

    ```kt
    Calendar calendar = parseCalendar(date.getText(), dateFormat);
    ```

1.  创建一个`DatePickerDialog`并用`Calendar`中的日期填充它，然后`显示()``DatePickerDialog`：

    ```kt
    new DatePickerDialog(
            this, // pass ReviewActivity as the current Context
            this, // pass ReviewActivity as an OnDateSetListener
            calendar.get(Calendar.YEAR),
            calendar.get(Calendar.MONTH),
            calendar.get(Calendar.DAY_OF_MONTH)).show();
    ```

1.  现在检查用户是否点击了`View Button`而不是`date`：

    ```kt
    else if(view == time) {
    ```

1.  如果是，使用`time Button`控件的标签值解析一个`Calendar`：

    ```kt
    Calendar calendar = parseCalendar(time.getText(), timeFormat);
    ```

1.  现在创建一个以选定时间为准的`TimePickerDialog`，然后向用户`显示()`新的`TimePickerDialog`：

    ```kt
    new TimePickerDialog(
            this, // pass ReviewActivity as the current Context
            this, // pass ReviewActivity as an OnTimeSetListener
            calendar.get(Calendar.HOUR_OF_DAY),
            calendar.get(Calendar.MINUTE),
            false) // we want an AM / PM view; true = a 24hour view
            .show();
    ```

1.  现在实现`onDateSet`方法，以监听用户在选择新日期后接受`DatePickerDialog`的操作：

    ```kt
    public void onDateSet(
            DatePicker picker, int year, int month, int day)
    ```

1.  创建一个新的`Calendar`实例来填充日期：

    ```kt
    Calendar calendar = Calendar.getInstance();
    ```

1.  在`Calendar`上设置年、月和日：

    ```kt
    calendar.set(Calendar.YEAR, year);
    calendar.set(Calendar.MONTH, month);
    calendar.set(Calendar.DAY_OF_MONTH, day);
    ```

1.  将`date Button`的标签设置为格式化的`Calendar`：

    ```kt
    date.setText(dateFormat.format(calendar.getTime()));
    ```

1.  实现`onTimeSet`方法，以监听用户在选择新时间后接受`TimePickerDialog`的操作：

    ```kt
    public void onTimeSet(TimePicker picker, int hour, int minute)
    ```

1.  创建一个新的`Calendar`实例：

    ```kt
    Calendar calendar = Calendar.getInstance();
    ```

1.  根据`TimePickerDialog`给出的参数设置`Calendar`对象的`hour`和`minute`字段：

    ```kt
    calendar.set(Calendar.HOUR_OF_DAY, hour);
    calendar.set(Calendar.MINUTE, minute);
    ```

1.  通过格式化`Calendar`对象来设置`time Button`的标签：

    ```kt
    time.setText(timeFormat.format(calendar.getTime()));
    ```

存储了`date`和`time`对象的格式后，我们现在可以在`Button`控件中显示用户选择的值。当用户选择新的日期或时间时，我们更新`Button`标签以反映新的选择。

## *刚才发生了什么*

如果你是在模拟器中安装并运行应用程序，现在你可以点击`date`或`time Button`组件，你会看到一个模态`Dialog`，允许你选择一个新值。注意不要过度使用模态`Dialog`组件，因为它们会阻止访问应用程序的其他部分。你不应该使用它们来显示状态消息，因为它们在显示期间实际上会使应用程序的其他部分变得无用。如果你确实显示了模态`Dialog`，请确保用户有某种方式可以不进行任何其他交互就关闭`Dialog`（即一个**取消**按钮或类似的东西）。

使用`DatePickerDialog`和`TimePickerDialog`的第一个优点在于，两者都包含**设置**和**取消**按钮。这让用户可以操作`DatePicker`或`TimePicker`，然后取消更改。如果你使用内联的`DatePicker`或`TimePicker`组件，你可以提供一个**重置**按钮，但这会占用额外的屏幕空间，并且通常看起来不合适（直到实际需要它）。

`DatePickerDialog`与`DatePicker`组件相比的另一个优点是，`DatePickerDialog`在其标题区域以长格式显示选定的日期。这种长格式的日期通常包括用户当前选择的星期几。从`DatePicker`组件中明显缺失的“星期几”字段，使得它出人意料地难以使用。大多数人会想到“下个星期四”，而不是“2010 年 8 月 2 日”。让星期几可见使得`DatePickerDialog`比内联的`DatePicker`更适合日期选择。

![发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_03_09b.jpg)

# 使用 Include、Merge 和 ViewStubs 创建复杂布局

在本章中，我们构建了一个包含三个不同标签的单个布局资源。因此，`main.xml`文件变得相当大，因此更难以管理。Android 提供了几种方法，你可以用这些方法将大布局文件（如这个）分解成更小的部分。

## 使用 Include 标签

`include`标签是最简单的操作标签。它直接将一个布局 XML 文件导入另一个。对于我们之前的示例，我们可以将每个标签分离到它自己的布局资源文件中，然后在`main.xml`中`include`每个文件。`include`标签只有一个必填属性：`layout`。这个属性指向要包含的布局资源。这个标签不是静态或编译时的标签，因此包含的布局文件将通过标准的资源选择过程来选择。这允许你有一个单一的`main.xml`文件，但随后可以添加一个特殊的`reviews.xml`文件（可能是西班牙语的）。

`include`标签上的`layout`属性**不**带有`android` XML 命名空间前缀。如果你尝试将`layout`属性用为`android:layout`，你不会得到编译时错误，但你的应用程序将奇怪地无法运行。

`include`元素还可以用来分配或覆盖所包含根元素的多个属性。这些属性包括元素`android:id`以及任何`android:layout`属性。这允许你在应用程序的多个部分重用同一个布局文件，但具有不同的布局属性和不同的 ID。你甚至可以在同一屏幕上多次`include`同一个布局文件，但每个实例都有一个不同的 ID。如果我们更改`main.xml`文件以包含来自其他布局资源的每个标签，文件看起来会更像这样：

```kt
<?xml version="1.0" encoding="UTF-8"?>
<FrameLayout 
             android:layout_width="fill_parent"
             android:layout_height="fill_parent">

    <include
        android:id="@+id/review"
        layout="@layout/review"/>

    <include
        android:id="@+id/photos"
        layout="@layout/photos"/>

    <includeandroid:id="@+id/reservation"
        layout="@layout/reservations"/>
</FrameLayout>
```

## 合并布局

当你想要将单个`View`或`ViewGroup`包含到更大的布局结构中时，`include`元素是非常好用的。但是，如果你想在不暗示所包含结构中需要根元素的情况下，将多个元素包含到更大的布局结构中呢？在我们的示例中，每个标签都需要一个单一的根`View`，以便每个标签携带单一且唯一的 ID 引用。

然而，仅仅为了`include`而增加一个额外的`ViewGroup`可能会对大型布局树的性能产生不利影响。在这种情况下，`merge`标签可以提供帮助。你可以将布局的根元素声明为`<merge>`，而不是声明为`ViewGroup`。在这种情况下，所包含布局 XML 中的每个`View`对象都会成为包含它们的`ViewGroup`的直接子项。例如，如果你有一个名为`main.xml`的布局资源文件，其中包含一个`LinearLayout`，该`LinearLayout`又包含了`user_editor.xml`布局资源，那么代码看起来会像这样：

```kt
<LinearLayout android:orientation="vertical">
 <include layout="@layout/user_editor"/>
    <Button android:id="@+id/save"
            android:text="Save User"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
</LinearLayout>
```

`user_editor.xml`的简单实现看起来像这样：

```kt
<LinearLayout

    android:orientation="vertical"
    android:layout_width="fill_parent"
    android:layout_height="wrap_content">

    <TextView android:text="User Name:"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>

    <EditText android:id="@+id/user_name"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>

    <!-- the rest of the editor -->
</LinearLayout>
```

然而，当这个被包含进`main.xml`文件时，我们将`user_editor.xml`的`LinearLayout`嵌入到`main.xml`的`LinearLayout`中，导致有两个具有相同布局属性的`LinearLayout`对象。显然，直接将`user_editor.xml`中的`TextView`和`EditView`放入`main.xml`的`LinearLayout`元素中会更好。这正是`<merge>`标签的用途。如果我们现在使用`<merge>`标签而不是`LinearLayout`来重写`user_editor.xml`文件，它看起来会像这样：

```kt
<merge >
    <TextView android:text="User Name:"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>

    <EditText android:id="@+id/user_name"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>

    <!-- the rest of the editor -->
</merge>

```

注意我们不再有`LinearLayout`元素，取而代之的是`TextView`和`EditView`将直接添加到`main.xml`文件中的`LinearLayout`。要小心那些嵌套了过多`ViewGroup`对象的布局，因为它们几乎肯定会引起问题（超过大约十级嵌套很可能会导致你的应用程序崩溃！）。同时也要注意那些含有过多`View`对象的布局。同样，超过 30 个很可能会引起问题或使你的应用程序崩溃。

## 使用 ViewStub 类

当你加载包含另一个布局的布局资源时，资源加载器会立即将包含的布局加载到内存中，以便将其附加到你请求的布局中。当 `main.xml` 被 `LayoutInflator` 读取时，`reviews.xml`、`photos.xml` 和 `reservations.xml` 文件也会被读取。在具有非常大型布局结构的情况下，这可能会消耗大量的应用程序内存，甚至可能导致应用程序崩溃。Android API 包含一个名为 `ViewStub` 的专用 `View`，它允许延迟加载布局资源。

默认情况下，`ViewStub` 是一个零大小（0x0）的空 `View`，当调用其专门的 `inflate()` 方法时，它会加载布局资源并替换为加载的 `View` 对象。这个过程允许一旦调用了 `inflate()` 方法，`ViewStub` 就可以被垃圾回收。

如果在我们的示例中使用 `ViewStub`，那么当用户选择一个标签页时，你需要延迟初始化该标签页的内容。这也意味着，在标签页被选中之前，该标签页中的任何 `View` 对象都不存在。虽然使用 `ViewStub` 比直接使用 `include` 要多做一些工作，但它可以让你处理比其他情况下更大的、更复杂的布局结构。

在 `ViewStub` 上设置的任何布局属性都将传递给其展开的 `View` 对象。你也可以为展开的布局分配一个单独的 ID。如果我们想在每个标签页中使用 `ViewStub`，那么 `main.xml` 文件看起来会像这样：

```kt
<?xml version="1.0" encoding="UTF-8"?>
<FrameLayout

         android:layout_width="fill_parent"
         android:layout_height="fill_parent">

 <ViewStub android:id="@+id/review"
 android:inflatedId="@+id/inflated_review"
 android:layout="@layout/review"/>

 <ViewStub android:id="@+id/photos"
 android:inflatedId="@+id/inflated_photos"
 android:layout="@layout/photos"/>

 <ViewStub android:id="@+id/reservations"
 android:inflatedId="@+id/inflated_reservations"
 android:layout="@layout/reservations"/>
</FrameLayout>
```

注意，与 `include` 标签不同，`ViewStub` 需要使用 `android` XML 命名空间为其 `layout` 属性。当你对一个 `ViewStub` 对象执行 `inflate()` 操作后，它将不再可以通过原来的 `android:id` 引用访问。相反，你可以使用 `android:inflatedId` 引用来访问被展开的布局对象。

## 实战英雄——分离标签页

将每个标签页提取到自己的布局资源文件中，并使用 `include` 标签加载它们。这不需要对 Java 源代码进行任何更改。

为了更具挑战性，尝试使用 `ViewStub` 对象代替 `include` 标签。这将要求你分解 `onCreate` 方法，并监听标签页被点击的时候。为此，你需要使用 `TabHost.OnTabChangeListener` 来知道何时加载特定标签页的内容。

# 摘要

标签页是将 `Activity` 分割成不同工作区域的好方法。在屏幕空间有限的情况下，它们是使 `Activity` 对用户更具可访问性的好方法。由于一次只渲染一个标签页，它们也具有性能影响。

`RatingBar` 和 `SeekBar` 是两种不同的捕获或向用户显示数值数据的方法。尽管它们密切相关，并且功能方式相同，但每个类用于处理不同类型的数据。在决定是否以及在哪里使用它们之前，要考虑到这两个类的局限性。

`Gallery` 类非常出色，允许用户查看大量不同的对象。尽管在这个例子中我们仅用它来显示缩略图，但它可以用作网页浏览器中标签的替代品，通过在浏览器视图上方显示页面缩略图列表。要自定义其功能，你所需要做的就是更改从 `Adapter` 实现中返回的 `View` 对象。

当涉及到日期和时间捕获时，尽量坚持使用 `DatePickerDialog` 和 `TimePickerDialog`，而不是它们内联的对应物（除非你有充分的理由）。使用这些 `Dialog` 小部件可以帮助你节省屏幕空间并提升用户体验。当他们打开 `DatePickerDialog` 或 `TimePickerDialog` 时，他们可以比你在用户界面中通常提供的编辑器更好地访问编辑器（特别是在屏幕较小的设备上）。

在下一章中，我们将更详细地了解 `Intent` 对象、活动堆栈以及 Android 应用程序的生命周期。我们将研究如何使用 `Intent` 对象和活动堆栈作为一种使应用程序更具可用性的方法。同时，我们也将学习如何提高 `Activity` 类的重用性。


# 第四章：利用活动和意图

在许多方面，Android 应用程序管理似乎受到 JavaScript 和网页浏览器的启发，这是有道理的！网页浏览器模型已经证明它是一个用户容易操作的机制。作为一个系统，Android 与网页浏览器有许多共同之处，其中一些是显而易见的，其他的则需要你更深入地了解。

`活动`堆栈与单向的网页浏览器历史类似。当你使用`startActivity`方法启动一个`Activity`时，实际上是将控制权交还给了 Android 系统。当用户在手机上按下硬件“返回”按钮时，默认操作是从堆栈中弹出顶部`Activity`，并显示下面的一个（不总是启动它的那个）。

在本章中，我们将探讨 Android 如何运行应用程序以及如何管理`Activity`实例。虽然这对于用户界面设计并非绝对必要，但了解其工作原理很重要。正确利用这些概念将帮助你确保用户界面体验的一致性。正如你将看到的，它还有助于提高应用程序的性能，并允许你重用更多的应用程序组件。

理解`Activity`是如何创建的（以及它何时被创建），以及 Android 如何决定创建哪个`Activity`也同样重要。我们还将讨论在构建`Activity`类时应遵循的一些良好实践，以及如何在 Android 应用程序的范围内良好地表现。

我们已经在第一章和第二章中遇到了“活动堆栈”，在那里我们构建了`Intent`对象来启动特定的`Activity`类。当你使用硬件“返回”按钮时，你会自动被带到上一个`Activity`实例，无需编写任何代码（就像网页浏览器一样）。在本章中，我们将要了解：

+   `Activity`对象的生命周期

+   使用`Bundle`类维护应用程序状态

+   探索`Intent`与`Activity`之间的关系

+   通过`Intent`向`Activity`传递数据

# 探索活动类

`Activity`对象的生命周期更像 Java `Applet`而不是普通应用程序。它可能会被启动、暂停、恢复、再次暂停、被杀死，然后以看似随机的顺序重新激活。大多数 Android 设备的性能规格非常好。然而，与顶级设备相比，它们中的大多数似乎性能不足。对于那些规格好的设备，用户往往比便宜设备要求更多。在手机上，你永远无法摆脱这样一个事实：许多应用程序和服务正在共享非常有限的设备资源。

如果`Activity`对用户不可见，它可能会随时被垃圾回收。这意味着虽然你的应用程序可能在运行，但由于用户正在查看另一个`Activity`，任何不可见或后台的`Activity`对象可能会被关闭或垃圾回收以节省内存。默认情况下，Android API 会通过在关闭前存储它们的状态并在重新创建时恢复状态，优雅地处理这些关闭/启动周期。下面是一个包含两个`Activity`实例的应用程序生命周期的非常简单的图示。当"主 Activity"暂停时，它就有可能被系统垃圾回收。如果发生这种情况，它首先会在一个临时位置存储其状态，当它被带回前台时会恢复状态。

![探索 Activity 类](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_04_01.jpg)

### 提示

**用户界面状态的存储**

如果一个`Activity`被停止，所有分配了 ID 的`View`对象在可供垃圾回收之前都会尝试存储它们的状态。然而，这种状态只会在应用程序的生命周期内存储。当应用程序关闭时，这个状态就会丢失。

尽管可以一次又一次地使用`setContentView`方法来改变屏幕上的内容（就像你可能使用 AWT 的`CardLayout`对象构建向导界面一样），但这被认为是一个非常糟糕的做法。你实际上是在试图从 Android 手中夺走控制权，这总会给你带来问题。例如，如果你开发了一个只有一个`Activity`类的应用程序，并使用多个布局资源或自己的自定义`ViewGroup`对象来表示不同的屏幕，你还必须控制设备上的硬件"返回"按钮，以允许用户后退。你的应用程序在 Android 市场上发布，几个月后，一个手机制造商决定在其新手机上添加一个"前进"按钮（类似于网页浏览器中的"前进"按钮）。Android 系统会被打补丁以处理这个设备变化，但你的应用程序不会。因此，你的用户会对你的应用程序感到沮丧，因为"它不能正常工作"。

## 使用 Bundle 对象

在`Activity`类的`onCreate`方法中，我们一直在接收一个名为`saveInstanceState`的`Bundle`参数，如您所猜测的那样。它是在`Activity`的停止和启动之间存储状态信息的地方。尽管看起来是这样，但`Bundle`对象并不是一种持久化存储形式。当设备上下文的配置发生变化（例如，当用户选择了一种新语言，或从“纵向”改为“横向”模式）时，当前的`Activity`会被“重新启动”。为此，Android 请求`Activity`将其状态保存在一个`Bundle`对象中。然后它会关闭并销毁现有实例，并使用保存状态信息的`Bundle`创建`Activity`的新实例（带有新的配置参数）。

`Bundle`类实际上是一个`Map<String, ?>`，包含任意数量的值。由于`Bundle`对象用于存储短期状态（即用户正在输入的博客文章），它们主要用于存储`View`对象的状态。在这方面，它们相对于标准的 Java 序列化有两个主要优点：

+   您必须手动实现对象存储。这需要考虑如何存储对象以及需要存储它的哪些部分。例如，在用户界面中，大多数时候您不需要存储布局信息，因为可以从布局文件重新创建它。

+   由于`Bundle`是一个键值结构，它比序列化对象更面向未来且灵活。您可以省略设置为默认值的值，从而减少`Bundle`的大小。

`Bundle`对象也是一个类型安全的结构。如果您使用`putString`方法，那么只有`getString`或`getCharSequence`可以用来检索对象。我强烈建议在使用`Bundle`的`get`方法时，您应该总是提供一个默认值。

在 Android 系统暂停`Activity`之前，系统会请求它将任何状态信息保存在一个`Bundle`对象中。为此，系统会在`Activity`上调用`onSaveInstanceState`方法。这发生在`onPause`方法之前。为了恢复`Activity`的状态，系统会使用保存的状态`Bundle`调用`onCreate`方法。

### 提示

**处理 Activity 崩溃**

如果`Activity`类抛出一个未捕获的异常，用户将看到可怕的**强制关闭**对话框。Android 将尝试通过终止虚拟机并重新打开根活动来从这些错误中恢复，并提供一个带有从`onSaveInstanceState`获取的最后已知状态的`Bundle`对象。

`View`类也有一个`onSaveInstanceState`方法，以及相应的`onRestoreInstanceState`方法。如前所述，`Activity`类的默认功能将尝试在`Bundle`中保存每个带有 ID 的`View`对象。这是坚持使用 XML 布局而不是自己构建布局的另一个好理由。拥有对`View`对象的引用还不足以保存和恢复它，虽然你可以在 Java 代码中分配 ID，但这会使你的用户界面代码更加混乱。

# 行动时间 - 构建一个示例游戏：“猜数字”

我们想要构建一个简单的示例，它将从一个`Bundle`对象保存和恢复其状态。在这个示例中，我们有一个非常简单的“猜数字”游戏。`Activity`对象在 1 到 10 之间选择一个数字，并挑战用户猜测它。

这个示例的基本用户界面布局需要有一个标签告诉用户要做什么，一个输入区域供他们输入猜测，以及一个按钮告诉应用他们想要输入猜测。以下图表是用户界面应该如何构建的基本思路：

![行动时间 - 构建一个示例游戏：“猜数字”](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_04_02.jpg)

如果用户在玩这个游戏时收到短信，我们很可能会丢失他试图猜测的数字。因此，当系统要求我们保存状态时，我们将尝试猜测的数字存储在`Bundle`对象中。启动时我们还需要查找存储的数字。

1.  从命令提示符中，创建一个名为`GuessMyNumber`的新项目：

    ```kt
    android create project -n GuessMyNumber -p GuessMyNumber -k com.packtpub.guessmynumber -a GuessActivity -t 3

    ```

1.  在编辑器或 IDE 中打开默认的`res/layout/main.xml`文件。

1.  移除`LinearLayout`元素中的默认内容。

1.  添加一个新的`TextView`作为标签，告诉用户要做什么：

    ```kt
    <TextView android:text=
        "I'm thinking of a number between 1 and 10\. Can you guess what it is?"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
    ```

1.  创建一个新的`EditText`，用户将在其中输入他们的猜测。使用`TextView`的`android:numeric`属性来强制只输入`integer`（整数）：

    ```kt
    <EditText
        android:id="@+id/number"
        android:numeric="integer"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
    ```

1.  添加一个用户可以点击提交猜测的`Button`：

    ```kt
    <Button android:id="@+id/guess"
        android:text="Guess!"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
    ```

1.  现在在编辑器或 IDE 中打开`GuessActivity.java`文件。

1.  让`GuessActivity`类实现`OnClickListener`：

    ```kt
    public class GuessActivity
        extends Activity implements OnClickListener {
    ```

1.  创建一个字段变量以存储用户应该猜测的数字：

    ```kt
    private int number;
    ```

1.  创建一个实用方法以生成 1 到 10 之间的随机数：

    ```kt
    private static int random() {
        return (int)(Math.random() * 9) + 1;
    }
    ```

1.  在`onCreate`方法中，在调用`super.onCreate`之后，检查以确保传递进来的`Bundle`不为`null`：

    ```kt
    if(savedInstanceState != null) {
    ```

1.  如果`Bundle`不为`null`，尝试从其中获取存储的`Number`：

    ```kt
    number = savedInstanceState.getInt("Number", random());
    ```

1.  如果`Bundle`为`null`，则`Activity`作为新实例运行 - 生成一个随机数：

    ```kt
    else {
        number = random();
    }
    ```

1.  然后将`setContentView`设置为`main.xml`布局资源：

    ```kt
    setContentView(R.layout.main);
    ```

1.  在`main.xml`布局资源中找到你声明的`Button`对象：

    ```kt
    Button button = (Button)findViewById(R.id.guess);
    ```

1.  将`Button`对象的`OnClickListener`设置为`GuessActivity`对象：

    ```kt
    button.setOnClickListener(this);
    ```

1.  现在重写`onSaveInstanceState`方法：

    ```kt
    protected void onSaveInstanceState(Bundle outState) {
    ```

1.  首先确保允许默认的`Activity`行为：

    ```kt
    super.onSaveInstanceState(outState);
    ```

1.  然后将`number`变量存储在`Bundle`中：

    ```kt
    outState.putInt("Number", number);
    ```

1.  我们需要重写`onClick`方法来处理用户的猜测：

    ```kt
    public void onClick(View clicked) {
    ```

1.  找到用户输入猜测数字的`EditText`：

    ```kt
    EditText input = (EditText)findViewById(R.id.number);
    ```

1.  将`EditText`的当前值解析为整数：

    ```kt
    int value = Integer.parseInt(input.getText().toString());
    ```

1.  如果他们猜的数字太低，使用`Toast`告诉他们：

    ```kt
    if(value < number) {
        Toast.makeText(this, "Too low", Toast.LENGTH_SHORT).show();
    }
    ```

1.  如果他们猜的数字太高，再次使用`Toast`告诉他们：

    ```kt
    else if(value > number) {
        Toast.makeText(this, "Too high", Toast.LENGTH_SHORT).show();
    }
    ```

1.  如果他们成功猜对了数字，那么祝贺他们：

    ```kt
    else {
        Toast.makeText(
                this,
                "You got it! Try guess another one!",
                Toast.LENGTH_SHORT).show();
    ```

1.  然后为用户生成一个新的猜测数字：

    ```kt
        number = random();
    }
    ```

在之前的代码中使用了`Toast`类来显示**太高**、**太低**和**猜对了！**的输出信息。`Toast`类是显示简短输出信息的完美机制，几秒钟后它们会自动消失。然而，它们不适合长消息，因为用户无法控制它们，也不能按命令打开或关闭消息，因为它们完全是非交互式的。

## *刚才发生了什么*

在上一个示例中，我们监听`onSaveInstanceState`的调用，以记录用户应该猜测的数字。我们还有用户最近一次做出的猜测，以`EditText`的形式。由于我们在`main.xml`文件中为`EditText`分配了一个 ID 值，调用`super.onSaveInstanceState`将处理`EditText`小部件的确切状态存储（可能包括“选择”和“焦点”状态）。

在`onCreate`方法中，示例首先检查以确保`Bundle`不为`null`。如果 Android 试图创建`GuessActivity`对象的新实例，它不会传递任何保存的状态。然而，如果我们有一个`Bundle`对象，我们会调用`Bundle.getInt`方法尝试获取我们之前存储的`number`值。我们还传递一个`r` `andom()`数作为第二个参数。如果`Bundle`对象（无论什么原因）没有存储`Number`，它将返回这个随机数，这样就无需我们检查这种情况。

顺便一提，示例使用了`TextView`类的`android:numeric`属性，以强制`EditText`对象接受整数输入。切换到数字视图可以阻止用户输入除了“有效”字符以外的任何内容。它还会影响软键盘。它不会显示全键盘，只会显示数字和符号。

![刚才发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_04_03.jpg)

# 创建和使用意图：

`Intent`类是 Android 主要的“晚期绑定”方式。这是一种非常松散的耦合形式，允许你指定一个动作（以及一些参数数据），但不需要指定如何执行该动作。例如，你可以使用`Intent`指定浏览到[`www.packtpub.com/`](http://www.packtpub.com/)，但不需要指定 Android 如何执行此操作。它可能使用默认的“浏览器”应用，或者用户安装的其他网页浏览器，甚至可能询问用户他们确切想要如何访问[`www.packtpub.com/`](http://www.packtpub.com/)。有两种主要的`Intent`类型：

+   显式 Intents

+   隐式 Intents

到目前为止，我们只使用了显式`Intent`对象，我们指定了想要运行的的确切类。当从一个`Activity`切换到另一个时，这些非常重要，因为应用程序可能依赖于`Activity`的确切实现。隐式`Intent`是当我们不指定想要操作的确切类时，而是包含我们希望执行操作的抽象名称。通常，隐式`Intent`会包含更多信息，由于以下原因：

+   为了让系统在选择与哪个组件交互时做出最佳选择。

+   `Intent`可能指向一个比我们自行构建的更通用的结构，而一个更通用的结构通常需要更多信息来明确其预期行为。

`Intent`对象是真正让 Android 与其他（更传统的）操作系统不同的地方。它们平衡了应用程序之间的竞争环境，并让用户在使用手机时有更多的选择。用户不仅可以安装一个新的网页浏览器，还可以安装新的菜单、桌面甚至拨号应用。

每个`Activity`实例都保存着启动它的`Intent`对象。第一章中，我们通过*开发一个简单的活动*用到了`Activity.getIntent()`方法，从`Intent`对象中获取一些参数，这些参数告诉我们应该向用户提出哪个问题。

## 定义 Intent 动作

在隐式`Intent`中首先要看的是它的动作。动作定义了`Intent`“做什么”，但不是“怎么做”或“对什么做”。`Intent`类定义了一系列常量，代表常见动作。这些常见动作总是有某种形式的支撑逻辑，通常由电话系统定义。因此，它们总是可供应用程序使用。

例如，如果你想向用户展示拨号应用，使他们可以拨打电话号码并进行通话，你会使用带有`ACTION_DIAL`的`Intent`：

```kt
startIntent(new Intent(Intent.ACTION_DIAL));
```

`Intent`的动作值与`Activity`定义的一个动作匹配。一个`Activity`可能有多个它可以执行的动作，它们都作为应用程序`AndroidManifest.xml`文件的一部分被指定。例如，如果你想定义一个`askQuestion`动作并将其绑定到一个`Activity`，你的`AndroidManifest.xml`文件将包含一个`Activity`条目，看起来像这样：

```kt
<activity
    android:name=".AskQuestionActivity"
    android:label="Ask Question">

    <intent-filter>
        <action android:name="questions.askQuestion"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

一个`Activity`可以有多个`<intent-filter>`元素，每个元素定义了一种不同类型的匹配要在`Intent`上执行。与任何给定的`Intent`最接近匹配的`Activity`被选中来执行`Intent`对象请求的动作。

## 在 Intent 中传递数据。

向用户展示拨号器应用程序，让他们拨打一个电话号码非常好，但如果实际上我们需要他们拨打一个电话号码呢？`Intent`类不仅仅通过使用动作来工作，它还为我们提供了一个默认的空间，告诉我们想要动作执行的对象。如果我们不能告诉浏览器要访问哪个 URL，那么打开网页浏览器不是非常有用，对吧？

`Intent`提供的默认数据作为一个`Uri`对象。`Uri`在技术上可以指向任何东西。对于我们之前的代码片段，我们启动了拨号器，让用户拨打一个电话号码。那么我们如何告诉拨号器：“拨打 555-1234”呢？很简单，看看以下代码：

```kt
startActivity(new Intent(
        Intent.ACTION_DIAL,
        Uri.parse("tel://5551234")));
```

## 向 Intent 添加额外数据

有时`Uri`不允许指定足够的数据。对于这些情况，`Intent`类为你提供了一个键值对的`Map`空间，称为"额外"数据。"额外"数据的访问方法与`Bundle`类中的方法相对应。在第一章《*开发简单活动*》中，我们使用了额外数据来跟踪我们向用户提出的问题。

在定义通用的`Activity`类（如文件查看器）时，查找操作数据时建立一个三阶段回退系统是一个好主意：

+   任何自定义（非标准）参数都可以在额外字段中传递（而且它们都不应该是强制性的）。

+   检查数据`Uri`以了解你应该处理哪些信息。

+   如果没有指定数据`Uri`，优雅地回退到逻辑默认值，并为用户提供一些功能。

## 动手实践英雄——通用问题与答案

回顾一下第一章《*开发简单活动*》中的示例问题与答案应用程序。重写`QuestionActivity`类，使用数据`Uri`来指定问题 ID（通过名称），而不是额外的参数。

同时，允许使用"额外"参数传递完整问题——一个参数`Question`用于要问用户的问题文本，以及一个参数`Answers`，指定给定问题的可能答案的字符串数组。

# 使用高级 Intent 功能

`Intent`对象旨在指示用户请求的单个动作。它是一个自包含的请求，在某些方面与 HTTP 请求非常相似，既包含要执行的动作，也包含要执行动作的资源，以及可能需要的相关信息。

为了找到将处理`Intent`的`Activity`（服务或广播接收器），系统使用了意图过滤器（我们之前简要讨论过）。每个意图过滤器指示了一个`Activity`可能执行的单个动作类型。当两个或更多的`Activity`实现匹配一个`Intent`时，系统会发送一个`ACTION_PICK_ACTIVITY Intent`，以允许用户（或某些自动化系统）选择哪个`Activity`实现应该用来处理`Intent`。默认行为是询问用户他们希望使用哪个`Activity`实现。

## 从 Intent 获取数据

`Intent`并不总是单向的结构，某些`Intent`动作会提供反馈。一个很好的例子就是`Intent.ACTION_PICK`。`Intent.ACTION_PICK`动作是请求用户“挑选”或选择某种数据形式的方式（一个常见的用法是请求用户从他们的联系人列表中选择一个人或电话号码）。

当你需要从`Intent`获取信息时，应使用`startActivityForResult`方法，而不是普通的`startActivity`方法。`startActivityForResult`方法接受两个参数：要执行的`Intent`对象和一个有用的`int`值，该值将被传回给你。

如前所述，当另一个`Activity`可见而不是你的时，你的`Activity`会被暂停，甚至可能被停止并垃圾回收。因此，`startActivityForResult`方法会立即返回，并且通常可以假设在你从当前事件返回后（将控制权交还给系统），你的`Activity`将直接被暂停。

为了获取你触发的`Intent`中的信息，你需要重写`onActivityResult`方法。每次使用`startActivityForResult`启动的`Intent`返回数据时，都会调用`onActivityResult`方法。传回`onActivityResult`方法的第一参数是你传给`startActivityForResult`方法的相同整数值（允许你传回简单的参数）。

### 提示

**向另一个 Activity 传递信息**

如果你打算让一个`Activity`实现将信息传回给调用者，你可以使用`Activity.setResult`方法来传递一个结果码和带有你响应数据的`Intent`对象。

## 快速测验

1.  `onCreate`何时会接收到一个有效的`Bundle`对象？

    1.  每次创建`Activity`时

    1.  当应用程序在之前的执行中在`Bundle`中存储了信息时

    1.  当由于配置更改或崩溃而重新启动 Activity 时

1.  `onSaveInstanceState` 方法何时被调用？

    1.  在 `onStop` 方法之后

    1.  在 `onPause` 方法之前

    1.  当 `Activity` 正在被重新启动时

    1.  在 `onDestroy` 方法之前

1.  `Bundle` 对象将被存储直到：

    1.  应用程序已关闭

    1.  `Activity` 不再可见

    1.  应用已被卸载

# 动手时间——查看电话簿联系人

在这个例子中，我们将更深入地探讨 Android 系统的运作方式。我们将覆盖默认的“查看联系人”选项，提供我们自己的 `Activity` 来查看设备上电话簿中的联系人。当用户尝试打开一个联系人以发送电子邮件或拨打电话时，他们将有机会使用我们的 `Activity` 而不是默认的来查看联系人。

1.  从命令行开始创建一个新项目：

    ```kt
    android create project -n ContactViewer -p ContactViewer -k com.packtpub.contactviewer -a ViewContactActivity -t 3
    ```

1.  在编辑器或 IDE 中打开 `res/layout/main.xml` 布局资源。

1.  移除 `LinearLayout` 元素中的默认内容。

1.  添加一个新的 `TextView` 对象以包含联系人的显示名称：

    ```kt
    <TextView android:id="@+id/display_name"
              android:textSize="23sp"
              android:textStyle="bold"
              android:gravity="center"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  然后添加一个 `Button`，该按钮将用于“拨打”显示联系人的默认电话号码：

    ```kt
    <Button android:id="@+id/phone_number"
            android:layout_marginTop="5sp"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

1.  在编辑器或 IDE 中打开 `ViewContactActivity.java` 源文件。

1.  让 `ViewContactActivity` 实现 `OnClickListener`：

    ```kt
    public class ViewContactActivity
            extends Activity implements OnClickListener {
    ```

1.  在 `onCreate` 方法中的 `setContentView(R.layout.main)` 之后，找到你创建的 `TextView` 对象，以显示联系人的名称：

    ```kt
    TextView name = (TextView)findViewById(R.id.display_name);
    ```

1.  然后找到用于显示电话号码的 `Button` 控件：

    ```kt
    Button number = (Button)findViewById(R.id.phone_number);
    ```

1.  现在，使用 `Activity.managedQuery` 方法查询联系人数据库，获取我们的 `Intent` 中指定的 `data Uri`：

    ```kt
    Cursor c = managedQuery(
            getIntent().getData(),
            new String[]{
                People.NAME,
                People.NUMBER
            },
            null,
            null,
            null);
    ```

1.  在 `try {} finally{}` 代码块中，告诉 `Cursor` 执行 `moveToNext()` 并确保其这样做（这与 `ResultSet.next()` 的作用完全相同）：

    ```kt
    if(c.moveToNext()) {
    ```

1.  从 `Cursor` 中获取并显示联系人显示名称：

    ```kt
    name.setText(c.getString(0));
    ```

1.  从 `Cursor` 中获取并显示联系人的默认电话号码：

    ```kt
    number.setText(c.getString(1));
    ```

1.  在 `finally{}` 代码块中，关闭 `Cursor`：

    ```kt
    finally {
        c.close();
    }
    ```

1.  现在，将 `number Button` 的 `OnClickListener` 设置为 `this`：

    ```kt
    number.setOnClickListener(this);
    ```

1.  重写 `onClick` 方法：

    ```kt
    public void onClick(View clicked) {
    ```

1.  我们知道点击的是 `number Button`（此时唯一带有事件监听器的 `View`）。将 `View` 参数转换为 `Button`，这样我们就可以使用它了：

    ```kt
    Button btn = (Button)clicked;
    ```

1.  创建一个 `Intent` 对象以拨打选定的电话号码：

    ```kt
    Intent intent = new Intent(
            Intent.ACTION_DIAL,
            Uri.parse("tel://" + btn.getText()));
    ```

1.  使用 `startActivity` 打开拨号器应用：

    ```kt
    startActivity(intent);
    ```

1.  现在，在编辑器或 IDE 中打开 `AndroidManifest.xml` 文件。

1.  在 `<application>` 元素声明之前，我们需要读取联系人列表的权限：

    ```kt
    <uses-permission
         android:name="android.permission.READ_CONTACTS" />
    ```

1.  将 `ViewContactActivity` 的标签更改为 **查看联系人**：

    ```kt
    <activity
        android:name=".ViewContactActivity"
        android:label="View Contact">
    ```

1.  移除 `<intent-filter>` 元素内的所有默认内容。

1.  为此 `<intent-filter>` 声明一个类型为 `ACTION_VIEW` 的 `<action>`：

    ```kt
    <action android:name="android.intent.action.VIEW"/>
    ```

1.  将此 `<intent-filter>` 的 `<catagory>` 设置为 `CATAGORY_DEFAULT`：

    ```kt
    <category android:name="android.intent.category.DEFAULT"/>
    ```

1.  添加一个 `<data>` 元素以筛选 `person` 条目（这是一个 MIME 类型）：

    ```kt
    <dataandroid:mimeType="vnd.android.cursor.item/person"
        android:host="contacts" />
    ```

1.  添加另一个 `<data>` 元素以筛选 `contact` 条目：

    ```kt
    <data android:mimeType="vnd.android.cursor.item/contact"
          android:host="com.android.contacts" />
    ```

当在设备上安装时，前面的代码将成为用户打开通讯录中“联系人”的一个选项。正如你所见，替换 Android 标准框架的一部分非常简单，它允许应用程序与基础系统进行更加无缝的集成，这是更传统的应用程序架构所无法实现的。

## *刚刚发生了什么*

如果你在这个模拟器上安装这个应用程序，你会注意到在启动器中没有图标来启动它。这是因为这个应用程序不像我们迄今为止编写的所有其他应用程序那样有一个主要的入口点。相反，如果你打开“联系人”应用程序，然后点击通讯录中的一个联系人，你会看到以下屏幕：

![刚刚发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_04_04.jpg)

如果你选择第二个图标，你新的`ViewContactActivity`将被启动以查看选定的联系人。正如你所见，用户也有能力在默认情况下使用你的应用程序（只要你的应用程序在设备上可用）。

在开发新应用程序时，覆盖默认行为是一个非常重要的决定。Android 使得这变得非常简单，正如你所见，第三方应用程序可以几乎无缝地插入两个默认应用程序之间。在正常的操作系统环境中，你需要编写一个完整的“联系人管理器”，而在 Android 中，你只需要编写你感兴趣的部分。

这是你用户界面设计的一部分，因为它可以用来扩展系统的各种默认部分的 功能。例如，如果你编写了一个聊天应用程序，比如一个“Jabber”客户端，你可以将客户端嵌入到用户通讯录中每个与 Jabber ID 关联的联系人**查看联系人**`Activity`中。这将使用户可以直接从他们的通讯录与可用的联系人聊天，而无需打开你的应用程序。你的应用程序成为他们检查联系人状态的方式，甚至可能完全避免打电话。

# 总结

在正确的粒度上实现`Activity`是你用户界面设计过程的一个重要部分。尽管它不是直接与图形相关的一部分，但它定义了系统如何与你的应用程序交互，从而也定义了用户如何与它交互。

在构建`Activity`启动方式时，考虑到隐式意图是一个好主意。创建一个通用的`Activity`可以让其他应用程序与你自己的程序无缝集成，从而有效地将你的新应用程序转变为其他开发人员工作的平台。通过隐式方式启动的`Activity`可以被另一个应用程序替换或扩展，也可以在其他应用程序中被复用。在这两种情况下，用户可以像定制壁纸图像或主题一样自由地定制你的应用程序。

一定要尝试为用户可能要采取的每个动作提供一个单独的`Activity`实现，不要让一个`Activity`在同一个屏幕上做太多事情。一个很好的粒度例子就是“联系人”应用——它包含了联系人列表、联系人查看器、联系人编辑器和拨号应用。

当处理标签界面（正如我们在上一章所做的）时，可以将标签内容指定为`Intent`，实际上是将`Activity`嵌入到你的应用中。我强烈建议你在构建标签用户界面时考虑这样做，因为它可以让每个标签更容易地被你的应用重复使用，同时也允许第三方开发者一次创建一个标签来扩展你的界面。

迄今为止，我们主要使用了`LinearLayout`类，虽然这对于简单的用户界面来说是一个很好的基础，但几乎永远不够用。在下一章中，我们将探讨 Android 默认提供的许多其他类型的布局，研究每种布局的工作方式以及如何使用它们。


# 第五章：开发非线性布局

*非线性布局通常是完全的用户界面设计的基础课题。然而，在屏幕较小的设备上（许多 Android 设备都是如此），这样做并不总是合理的。也就是说，Android 设备可以切换到横屏模式，突然之间你就有大量的水平空间，而垂直空间有限。在这些情况下（以及我们将要看到的其他许多情况下），你会想要使用除了我们至今为止使用的普通`LinearLayout`结构之外的布局。*

*Android 布局的真正强大之处与旧的 Java AWT `LayoutManagers`的强大之处相同——通过将不同的布局类相互组合。例如，将`FrameLayout`与其他`ViewGroup`实现相结合，允许你将用户界面的各个部分层层叠加。*

考虑你的布局在不同大小的屏幕上的表现是很重要的。虽然 Android 允许你根据设备屏幕大小选择不同的布局，但这意味着你将不得不为不同的屏幕大小和密度维护多个布局，这些屏幕大小和密度将在野外遇到你的应用程序。尽可能使用 Android 提供的工具，并使用会根据各种`View`对象的大小进行缩放的布局。

在本章中，我们将探讨 Android 默认提供的各种其他布局样式，并研究每种布局的各种替代用途。我们还会更详细地了解如何为不同的布局指定参数，以及它们如何帮助提高可用性，而不仅仅是将你的小部件按特定顺序排列。

# 是时候行动了——创建一个布局示例项目

在我们逐一了解每种布局之前，我们需要一个公共项目，在其中展示每一种布局。

1.  从命令提示符中，创建一个名为**Layouts**的新项目：

    ```kt
    android create project -n Layouts -p Layouts -k com.packtpub.layouts -a LayoutSelectorActivity -t 3
    ```

1.  删除标准的`res/layout/main.xml`布局资源文件。

1.  在编辑器或 IDE 中打开`res/values/strings.xml`文件。

1.  在文件中添加一个名为`layouts`的新`<string-array>`：

    ```kt
    <string-array name="layouts">
    ```

1.  向新的`<string-array>`元素中添加以下项目：

    ```kt
    <item>Frame Layout</item>
    <item>Table Layout</item>
    <item>Custom Layout</item>
    <item>Relative Layout</item>
    <item>Sliding Drawer</item>
    ```

1.  在你的编辑器或 IDE 中打开`LayoutSelectorActivity`源文件。

1.  让类从`ListActivity`继承，而不是从`Activity`继承：

    ```kt
    public class LayoutSelectorActivity extends ListActivity {
    ```

1.  在`onCreate`方法中，将你在`strings.xml`资源文件中声明的`ListActivity`的内容设置为你`layouts`数组：

    ```kt
    setListAdapter(new ArrayAdapter<String>(
            this,
            android.R.layout.simple_list_item_1, Have the class inherit from"
            getResources().getStringArray(R.array.layouts)));
    ```

1.  重写`onListItemClick`方法：

    ```kt
    protected void onListItemClick(
            ListView l,
            View v,
            int position,
            long id) {
    ```

1.  在`position`参数上创建一个`switch`语句：

    ```kt
    switch(position) {
    ```

1.  添加一个`default`子句（目前唯一的一个），以让你知道你还没有为所选项目实现示例：

    ```kt
    default:
        Toast.makeText(
                this,
                "Example not yet implemented.",
                Toast.LENGTH_SHORT).show();
    ```

## *刚才发生了什么？*

新项目将作为本章每个示例的基础。对于我们要探讨的每个布局，我们将构建一个新的`Activity`，这将成为这个应用程序的一部分。目前，该应用程序只包含一个菜单，用于访问每个布局示例。现在的想法是给每个示例填充一些有趣的内容。

在本章中，我们将不仅探讨基本布局，还会了解它们如何相互作用。

# `FrameLayout`的使用

`FrameLayout`类将每个控件锚定在其自身的左上角。这意味着每个子控件都会在之前的控件上绘制。这可以通过使用`View.setVisible`来模拟 AWT 中的`CardLayout`，即显示一个子控件同时隐藏所有其他子控件（这正是`TabHost`的工作原理）。

由于`FrameLayout`实际上会绘制所有可见的子视图，因此可以用来将子控件层层叠加。在某些情况下，它会产生非常奇特的效果，而在其他情况下，它可能非常有用。例如，通过使用半透明的`View`对象和一个`FrameLayout`，可以实现除一个控件外所有控件变暗的效果。不活跃的控件是`FrameLayout`中的第一层，半透明的`View`对象是第二层，活跃的控件是第三层。

## 常见用途

`FrameLayout`最常见的用法可能是与`TabHost`结合使用——为每个标签页持有内容`View`对象。你也可以用它来模拟更像是桌面应用的感觉，通过将控件层层叠加。在游戏中也非常有效，可以用来显示游戏内的菜单，或者在游戏主菜单后面绘制动画背景。

通过将`FrameLayout`对象与占据整个屏幕的控件结合使用，可以利用`gravity`属性将对象更精确地放置在其他控件之上。为此，通常希望每个`FrameLayout`的子控件都是某种`ViewGroup`，因为除非特别指定，否则它们通常不会在背景中绘制（让下面的图层保持可见）。

`FrameLayout`还能够显示`前景`。虽然所有`View`对象都有`背景`属性，但`FrameLayout`包含一个`前景`（这也是一个可选的`Drawable`）。`前景`会在所有子控件之上绘制，允许显示一个“框架”。

# 动手实践时间——开发一个`FrameLayout`示例。

要真正理解`FrameLayout`的作用以及如何使用它，最好是通过一个示例来实践一下。在这个示例中，我们将使用`FrameLayout`将一些`Button`控件叠加在`ImageView`之上，并在点击其中一个按钮时显示和隐藏一个`TextView`消息。

为了使这个示例工作，你需要一张图片作为背景图。我将使用我朋友的一张照片。像往常一样，将你的图片放在`res/drawable`目录中，并尝试使用 PNG 文件。

1.  创建一个名为`res/layout/frame_layout.xml`的新布局资源文件。

1.  将根元素声明为占用所有可用空间的`FrameLayout`：

    ```kt
    <FrameLayout

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  在`FrameLayout`内部，创建一个`ImageView`作为背景图像。它应该缩放以填满所有可用空间：

    ```kt
    <ImageView android:src="img/jaipal"
               android:scaleType="centerCrop"
               android:layout_width="fill_parent"
               android:layout_height="fill_parent"/>
    ```

1.  现在创建一个垂直的`LinearLayout`，我们将在屏幕底部放置两个`Button`对象：

    ```kt
    <LinearLayout android:orientation="vertical"
                  android:gravity="bottom"
                  android:layout_width="fill_parent"
                  android:layout_height="fill_parent">
    ```

1.  创建一个`Button`，我们将使用它来切换`FrameLayout`的一个子层（创建类似对话框的效果）：

    ```kt
    <Button android:text="Display Overlay"
            android:id="@+id/overlay_button"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

1.  创建另一个`Button`以退出演示并返回菜单：

    ```kt
    <Button android:text="Quit"
            android:id="@+id/quit"
            android:layout_marginTop="10sp"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
    ```

1.  在`</LinearLayout>`之后，创建一个最终的`TextView`元素，我们将在点击第一个按钮时显示和隐藏它。默认情况下它是隐藏的：

    ```kt
    <TextView android:visibility="gone"
              android:id="@+id/overlay"
              android:textSize="18sp"
              android:textStyle="bold"
              android:textColor="#ffff843c"
              android:text="This is a text overlay."
              android:gravity="center|center_vertical"
              android:layout_width="fill_parent"
              android:layout_height="fill_parent"/>
    ```

1.  在项目的根包中创建一个新的`FrameLayoutActivity` Java 类，并在编辑器或 IDE 中打开源文件。新类需要从`Activity`继承并实现`OnClickListener`类（用于那两个`Button`小部件的事件）：

    ```kt
    public class FrameLayoutActivity
            extends Activity implements OnClickListener {
    ```

1.  重写`onCreate`方法：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
    ```

1.  调用`super.onCreate`方法以使`Activity`代码工作：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  将内容布局设置为刚才创建的`frame_layout`资源：

    ```kt
    setContentView(R.layout.frame_layout);
    ```

1.  在`frame_layout`资源文件中找到你声明的`overlay Button`小部件并创建一个引用：

    ```kt
    Button overlay = (Button)findViewById(R.id.overlay_button);
    ```

1.  将其`OnClickListener`设置为新的`FrameLayoutActivity`对象：

    ```kt
    overlay.setOnClickListener(this);
    ```

1.  查找你声明的`quit Button`小部件：

    ```kt
    Button quit = (Button)findViewById(R.id.quit);
    ```

1.  然后将它的`OnClickListener`设置为`FrameLayoutActivity`对象：

    ```kt
    quit.setOnClickListener(this);
    ```

1.  `OnClickListener`接口要求我们实现一个具有以下签名的`onClick`方法：

    ```kt
    public void onClick(View view) {
    ```

1.  对`View`参数的 ID 创建一个`switch`语句：

    ```kt
    switch(view.getId()) {
    ```

1.  如果用户点击的`View`是`overlay_button Button`，则使用以下代码：

    ```kt
    case R.id.overlay_button:
    ```

1.  从布局中获取`overlay View`对象：

    ```kt
    View display = findViewById(R.id.overlay);
    ```

1.  根据当前状态切换其可见性，然后从`switch`语句中`break`：

    ```kt
    display.setVisibility(
            display.getVisibility() != View.VISIBLE
            ? View.VISIBLE
            : View.GONE);
    break;
    ```

1.  如果用户点击的`View`是`quit Button`，则使用以下代码：

    ```kt
    case R.id.quit:
    ```

1.  调用`finish()`方法，并从`switch`语句中`break`：

    ```kt
    finish();
    break;
    ```

1.  在编辑器或 IDE 中打开`LayoutSelectorActivity` Java 源文件。

1.  在`onListItemClick`方法中，为`switch`语句创建一个新的`case`，用于`position`值为`0`的情况：

    ```kt
    case 0:
    ```

1.  使用显式`Intent`启动`FrameLayoutActivity`：

    ```kt
    startActivity(new Intent(this, FrameLayoutActivity.class));
    break;
    ```

1.  在编辑器或 IDE 中打开`AndroidManifest.xml`文件。

1.  将新的`FrameLayoutActivity`添加到清单文件中：

    ```kt
    <activity android:name=".FrameLayoutActivity"
              android:label="Frame Layout Example"/>
    ```

## *刚才发生了什么？*

新的`FrameLayoutActivity`使用了一个简单三层`FrameLayout`。我们使用`ImageView`对象绘制一个漂亮的背景图像，在其上放置了两个按钮。尽管第三层（`TextView`小部件）在顶部按钮被点击之前是不可见的，但需要注意的是，顶部`TextView`的背景不仅透明，而且还将点击事件委托给技术上位于其下的控件（`TextView`有一个消耗整个`FrameLayout`的控件和高度）。即使`TextView`的背景是不透明的，这也会继续工作。这更多是因为`TextView`不是“可点击”的。如果你为`overlay TextView`对象添加了一个`OnClickListener`，那么它下面的按钮将停止工作。这意味着你需要小心如何在`FrameLayout`中分层控件（尽管只要一个控件不占用另一个控件的空间，这对你来说不会成为问题）。

在这个例子中，我们在布局中添加了一个**退出**按钮，并在点击`Button`时使用`finish()`方法关闭`Activity`。你会发现你通常不会直接使用`finish()`方法，因为用户通常会继续向前浏览你的应用程序。如果用户想要返回，他们通常会使用硬件“返回”按钮，或者按下硬件“主页”按钮完全退出你的应用程序。

关于上述示例的最后说明——在`frame_layout.xml`文件中，我们将`overlay`声明为一个`TextView`小部件。然而，在 Java 代码中，我们使用`View`类而不是`TextView`来访问它。这是一个简单的解耦例子。除非你正在处理一个以性能为中心的代码段，否则最好尽可能地将你的布局小部件引用到类树的高层。这样，你就可以在以后更快地修改用户界面。在这种情况下，你可以将简单的`TextView`更改为整个`LinearLayout`，而无需更改 Java 代码。

下面是`FrameLayout`示例的两张屏幕截图，分别是有和没有启用`overlay TextView`的情况。这种布局非常适合用于游戏菜单或类似结构中，在这些地方你需要将不同的控件层层叠加在一起。

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_01b.jpg)

# 表格布局

`Table Layout`以 HTML 风格的网格排列其子项。它有点像 AWT 的`Grid Layout`类，但灵活性要大得多。与 Android 中的大多数其他布局类不同，`Table Layout`使用自己的专用直接子`View`类，名为`Table Row`。`Table Layout`类也不允许你定义行数或列数（使其更像一个 HTML 的`<table>`元素）。相反，行数和列数是由`Table Layout`及其`Table Row`子项中的控件数量计算得出的。

`Table Layout`中的单元格可以占用任意数量的行和列，尽管默认情况下，放在`Table Row`中的`View`会正好占据一个单元格。但是，如果你直接将`View`作为`Table Layout`的子项，它将占用整行。

`Table Layout`也是一个相对布局结构，这在处理 Android 设备时至关重要。能够基于网格线对齐所有内容，使得用户界面可以从低分辨率的小手机扩展到 7 英寸平板电脑上的高密度屏幕。

`android:gravity`属性在`Table Layout`中的使用远比其他布局类更为频繁。在小屏幕上看起来很棒的效果在大屏幕上可能会完全不同，这并不是因为屏幕的大小，而是因为所使用字体的缩放。特别是在标签和控件的垂直对齐上要小心。最简单的方法是先将所有表格控件垂直居中，然后在此基础上进行调整。务必在多种屏幕分辨率和尺寸上测试基于表格的布局。

## 常见用途

在大多数情况下，你会发现自己使用`Table Layout`来排列输入表单。它也适用于布局复杂信息，特别是在让某些`View`对象跨越多行和多列时。`Table Layout`最重要的特点在于它以非常严格的方式对其单元格进行对齐，同时它是一个相对尺寸的布局。

`Table Layout`也可以用来实现类似于 AWT `Border Layout`类的效果。通常，在调整`Table Layout`以适应整个屏幕时，它变成了一个非常不同于简单网格的工具，允许你在控件中间放置一个`Scroll View`。

通过在`FrameLayout`内使用`Table Layout`，你可以在内容`View`（如 Google Maps 中的控件）上方排列一个控制`View`。还要注意，与 AWT `GridLayout`不同，`TableLayout`内部的`View`尺寸并不附着在它所在的表格单元格尺寸上。通过使用`gravity`属性（可能还有布局边距），你可以在单元格内放置`View`对象，从而创建出更加用户友好的布局。

## 在记忆游戏中使用 TableLayout

为了演示`TableLayout`，我认为编写一个简单的记忆卡牌游戏会很有趣。你面对的是一个网格（以`TableLayout`的形式），你可以触摸它来有效地翻转“卡片”。然后你可以尝试匹配所有这些卡片上的内容（每次只允许翻转两张）。在这个例子中，你需要在卡片上放置一些图片（我这里复用了交付示例中的水果图标）。在这个应用中，我们还将创建一个简单的占位符图片，以 XML 文件的形式。

为了创建占位符图像，在`res/drawable`目录中创建一个新的 XML 资源，名为`line.xml`。这将是一个“形状”资源。形状资源对于创建简单、可伸缩的形状非常有用。此外，形状资源文件可以使用代码提供的任何颜色、纹理或渐变。

为了创建我们示例的简单占位符图像，将以下代码复制到`line.xml`文件中：

```kt
<?xml version="1.0" encoding="UTF-8"?>

<shape 
       android:shape="line">

    <stroke android:width="3dp"
            android:color="#ff000000"/>

    <padding android:left="1dp"
             android:top="1dp"
             android:right="1dp"
             android:bottom="1dp"/>
</shape>
```

# 是时候行动了——开发一个简单的记忆游戏

与几乎所有之前的示例不同，在这个游戏中，我们将完全在 Java 代码中生成布局。这样做的主要原因是内容高度重复，每个单元格几乎包含完全相同的控件。我们使用`TableLayout`创建网格，并在`ImageButton`控件中显示“卡片”。为了封装单个卡片的行为，我们创建了一个`MemoryCard`内部类，它持有一个对它控制的`ImageButton`的引用。

1.  在项目的根包中创建一个新的 Java 类，并将其命名为`TableLayoutActivity`。

1.  让新类继承`Activity`：

    ```kt
    public class TableLayoutActivity extends Activity {
    Declare and array of all the icon resources to use as card images, there must be eight images resources declared in this array:private static final int[] CARD_RESOURCES = new int[]{
        R.drawable.apple,
        R.drawable.banana,
        R.drawable.blackberry,
        // …
    };
    ```

1.  你需要一个定时器来将卡片翻回，因此声明一个`Handler`：

    ```kt
    private final Handler handler = new Handler();
    ```

1.  声明一个`MemoryCard`对象数组：

    ```kt
    private MemoryCard[] cards;
    ```

1.  我们要跟踪的卡片有一张或两张被翻过来。声明第一个的占位符：

    ```kt
    private MemoryCard visible = null;
    ```

1.  如果有两张卡片被翻过来，但它们不匹配，我们用一个简单的`boolean`开关禁用触摸（我们的事件监听器将检查这一点）：

    ```kt
    private boolean touchEnabled = true;
    ```

1.  现在声明一个名为`MemoryCard`的内部类，该类实现了`OnClickListener`接口：

    ```kt
    private class MemoryCard implements OnClickListener {
    ```

1.  `MemoryCard`类持有一个对`ImageButton`的引用：

    ```kt
    private ImageButton button;
    ```

1.  `MemoryCard`类还有一个值，它是卡片正面的图像资源的引用：

    ```kt
    private int faceImage;
    ```

1.  最后，`MemoryCard`使用一个`boolean`值来记住其状态（是显示正面图像还是占位符图像）：

    ```kt
    private boolean faceVisible = false;
    ```

1.  为`MemoryCard`类声明一个构造函数，它只需要获取正面图像的资源标识符：

    ```kt
    MemoryCard(int faceImage) {
    ```

1.  保存`faceImage`资源标识符以供以后使用：

    ```kt
    this.faceImage = faceImage;
    ```

1.  使用`TableLayoutActivity`对象作为其`Context`（`ImageButton`将使用它来加载图像）创建一个新的`ImageButton`对象：

    ```kt
    this.button = new ImageButton(TableLayoutActivity.this);
    ```

1.  将`ImageButton`的大小设置为固定的 64x64 像素：

    ```kt
    this.button.setLayoutParams(new TableRow.LayoutParams(64, 64));
    ```

1.  设置缩放类型，使图标适合`ImageButton`，然后将图像设置为占位符资源：

    ```kt
    this.button.setScaleType(ScaleType.FIT_XY);
    this.button.setImageResource(R.drawable.line);
    ```

1.  将`MemoryCard`对象设置为`ImageButton`对象的`OnClickListener`：

    ```kt
    this.button.setOnClickListener(this);
    ```

1.  为了方便以后使用，`MemoryCard`需要一个`setFaceVisible`方法，该方法将在显示占位符和`faceImage`资源之间切换。

    ```kt
    void setFaceVisible(boolean faceVisible) {
        this.faceVisible = faceVisible;
        button.setImageResource(faceVisible
                ? faceImage
                : R.drawable.line);
    }
    ```

1.  在`MemoryCard`类中实现`onClick`方法：

    ```kt
    public void onClick(View view) {
    ```

1.  首先确保当前脸部不可见（即我们已经翻面朝下），并且触摸功能已启用（其他一些卡片不会再次被翻面朝下）：

    ```kt
    if(!faceVisible && touchEnabled) {
    ```

1.  如果满足这些条件，我们告诉`TableLayoutActivity`我们已被触摸并希望被翻到正面朝上：

    ```kt
    onMemoryCardUncovered(this);
    ```

1.  在 `MemoryCell` 内部类之后，在 `TableLayoutActivity` 中创建一个简单的工具方法，以特定大小创建有序的 `MemoryCell` 对象数组：

    ```kt
    private MemoryCard[] createMemoryCells(int count) {
    ```

1.  当我们创建每个 `MemoryCell` 对象时，我们会成对创建它们，并且按照我们在图标资源数组中指定的顺序：

    ```kt
    MemoryCard[] array = new MemoryCard[count];
    for(int i = 0; i < count; i++) {
        array[i] = new MemoryCard(CARD_RESOURCES[i / 2]);
    }
    ```

1.  完成后，返回新的 `MemoryCell` 对象数组：

    ```kt
    return array;
    ```

1.  现在，重写 `onCreate` 方法：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
    ```

1.  调用 `Activity.onCreate` 方法：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  现在，创建一个新的 `TableLayout` 对象，将其传递给 `TableLayoutActivity` 作为 `Context` 以加载样式和资源：

    ```kt
    TableLayout table = new TableLayout(this);
    ```

1.  默认情况下，我们创建一个 4x4 的网格：

    ```kt
    int size = 4;
    cards = createMemoryCells(size * size);
    ```

1.  然后，我们将其打乱以随机化顺序：

    ```kt
    Collections.shuffle(Arrays.asList(cards));
    ```

1.  创建所需的每个 `TableRow` 对象，并用由 `MemoryCard` 对象在网格中创建的 `ImageButtons` 填充它：

    ```kt
    for(int y = 0; y < size; y++) {
        TableRow row = new TableRow(this);
        for(int x = 0; x < size; x++) {
            row.addView(cards[(y * size) + x].button);
        }
        table.addView(row);
    }
    ```

1.  将 `Activity` 内容视图设置为 `TableLayout` 对象：

    ```kt
    setContentView(table);
    ```

1.  现在，我们编写 `onMemoryCardUncovered` 方法，它由 `MemoryCard.onClick` 实现调用：

    ```kt
    private void onMemoryCardUncovered(final MemoryCard cell) {
    ```

1.  首先，检查当前是否有可见的 `MemoryCard`，如果没有，用户触摸的卡片将翻转到正面，并记住它：

    ```kt
    if(visible == null) {
        visible = cell;
        visible.setFaceVisible(true);
    }
    ```

1.  如果已经有一张正面朝上的卡片，检查它们是否具有相同的图像。如果图像相同，禁用 `ImageButton` 小部件，以便我们忽略事件：

    ```kt
    else if(visible.faceImage == cell.faceImage) {
        cell.setFaceVisible(true);
        cell.button.setEnabled(false);
        visible.button.setEnabled(false);
        visible = null;
    }
    ```

1.  最后，如果正面图像不匹配，我们将用户触摸的卡片翻转到正面，并切换我们的 `touchEnabled` 开关，使 `MemoryCard` 对象将忽略所有其他触摸事件一秒钟：

    ```kt
    else {
        cell.setFaceVisible(true);
        touchEnabled = false;
    ```

1.  然后，我们在 `Handler` 上发布一个延迟的消息，它将再次翻转两张卡片并重新启用触摸事件：

    ```kt
    handler.postDelayed(new Runnable() {
        public void run() {
            cell.setFaceVisible(false);
            visible.setFaceVisible(false);
            visible = null;
            touchEnabled = true;
        }
    }, 1000); // one second before we flip back over again
    ```

## *刚才发生了什么*

在上一个示例中，我们手动编写布局代码的原因应该很明了，如果用 XML 文件构建将会非常重复。你会注意到，代码创建了一个 `TableRow` 对象作为 `TableLayout` 的直接子项，就像我们在 XML 文件中一样。

`MemoryCard` 的 `onClick` 方法使用 `touchEnabled` 开关来确定是否调用 `onMemoryCardUncovered`。然而，这既不能阻止用户按下 `ImageButton` 对象，也不能阻止对象对用户做出反应（尽管它们不会翻转）。为了提供更友好的用户体验，最好对每个启用的 `ImageButton` 对象使用 `setClickable` 方法，以完全阻止它们对用户的触摸做出反应。

当我们创建 `ImageButton` 对象时，会将它们预设为 64x64 像素大小。这对于大屏幕模拟器来说可能没问题，但有很多设备无法容纳屏幕上的 4x4 按钮网格。我建议你使用 XML 资源来创建 `ImageButton` 对象。

之前的代码使用`setLayoutParams(new TableRow.LayoutParams(64, 64));`来设置`ImageButton`对象的大小。需要注意的是，由于我们将`ImageButton`对象放入到`TableRow`中，它们的`LayoutParams`必须是`TableRow.LayoutParams`类型。如果你尝试改为通用的`ViewGroup.LayoutParams`，那么用户界面将不会布局（它会变成空白）。以下是应用程序运行的两个截图：

![刚刚发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_03b.jpg)

## 尝试一下英雄

`TableLayout`示例效果很好，但网格的位置不佳（在屏幕左上角），并且将其放在黑色背景上相当单调。是时候让它看起来很棒了！

首先，使用`FrameLayout`为游戏添加一个背景图像。这将通过添加更多色彩来增强游戏的整体吸引力。你也应该借此机会将网格在屏幕上居中。将其放在左上角不知为何会显得不平衡。

你还应该尝试移除`touchEnabled`开关，改为在每个`ImageButton`对象上使用`setClickable`。这将阻止它们在你将牌面朝下时提供视觉上的“按下和释放”反馈。

# AbsoluteLayout/自定义布局

**不要使用 AbsoluteLayout！ AbsoluteLayout 已被弃用！** 也就是说，有时使用`AbsoluteLayout`类是有意义的。那么你为什么不应该使用`AbsoluteLayout`类，你应该在什么时候使用它呢？第一个问题的答案很简单——`AbsoluteLayout`的所有子部件都有它们的确切位置，它们在不同屏幕上不会改变大小或位置。它还使你的布局几乎不可能被复用（例如，将其导入另一个布局，或嵌入到另一个应用程序中）。

如果你要使用`AbsoluteLayout`，你应该选择以下两种方法之一来接近它：

1.  仔细为每种不同的屏幕尺寸构建一个单独的布局 XML。

1.  在 Java 代码中编写你的布局数据，而不是在 XML 中。

第一种方法不切实际，除非你指定应用程序只能在特定设备上运行，而且该布局不能在你的应用程序之外使用。然而，第二种方法开启了“正确”的道路——编写自定义布局管理器。由于`AbsoluteLayout`需要严格的位置，并且不允许与子`View`对象的测量轻松交互，定义不适合任何其他布局类的布局的最佳方法是 在你自己的`ViewGroup`类中定义一个自定义布局。

## 开发你自己的布局

由于`AbsoluteLayout`已被弃用，但仍有很多人似乎坚持使用它，这个例子将展示如何编写自己的`ViewGroup`类定义一个新布局，以及将这个布局集成到布局 XML 资源中是多么容易。这将证明使用`AbsoluteLayout`并没有充分的理由（除非它真的有意义）。

# 行动时间——创建自定义布局

为了真正展示自定义布局的使用，你需要尝试构建一些不寻常的东西。在以下示例中，你将组合一个以美观的圆形排列其子项的`ViewGroup`。这并不是一个特别出色的布局，也不特别实用，但圆形看起来很美观，并且它将在屏幕中心提供有用的空白空间（可以使用`FrameLayout`填充）。

1.  在项目的根包中创建一个名为`CircleLayout.java`的新 Java 源文件，并在编辑器或 IDE 中打开它。

1.  声明`CircleLayout`扩展自`ViewGroup`类：

    ```kt
    public class CircleLayout extends ViewGroup
    ```

1.  声明三个`ViewGroup`构造函数，并直接将它们委托给`ViewGroup`的默认构造函数：

    ```kt
    public CircleLayout(Context context) {
        super(context);
    }
    // ...
    ```

1.  我们需要知道子`View`对象宽度占用的最大像素数，以及子`View`对象高度占用的最大像素数。为了避免不必要开销，我们借此机会也`测量`子`View`对象。声明一个名为`measureChildrenSizes`的实用方法来执行这两个操作：

    ```kt
    private int[] measureChildrenSizes(int sw, int sh) {
    ```

1.  声明一个`int`来保存我们找到的最大宽度和高度：

    ```kt
    int maxWidth = 0;
    int maxHeight = 0;
    ```

1.  创建一个`for`循环，遍历此`CircleLayout`对象中的每个子`View`对象：

    ```kt
    for(int i = 0; i < getChildCount(); i++) {
    ```

1.  声明一个对当前索引处`View`的引用：

    ```kt
    View child = getChildAt(i);
    ```

1.  作为布局组件，你的类需要负责为其所有子组件设置显示大小。为了知道子组件期望的宽度和高度，你需要在`ViewGroup`类中使用`measureChild`方法：

    ```kt
    measureChild(child, sw, sh);
    ```

1.  测试子`View`对象的宽度和高度，与你之前创建的最大宽度变量和高度变量进行比较：

    ```kt
    maxWidth = Math.max(maxWidth, child.getMeasuredWidth());
    maxHeight = Math.max(maxHeight, child.getMeasuredHeight());
    ```

1.  在方法末尾，返回一个包含在过程中找到的最大宽度和高度的数组：

    ```kt
    return new int[]{maxWidth, maxHeight};
    ```

1.  实现`ViewGroup`的`onLayout`方法：

    ```kt
    protected void onLayout(boolean changed,
            int l, int t, int r, int b) {
    ```

1.  计算我们可用空间的宽度和高度：

    ```kt
    int w = r – l;
    int h = b - t;
    ```

1.  声明一个变量来保存子`View`对象的数量：

    ```kt
    int count = getChildCount();
    ```

1.  对所有子`View`对象进行测量，以确定可用空间的大小：

    ```kt
    int[] max = measureChildrenSizes(w, h);
    ```

1.  从可用空间中减去最大宽度和高度，以确保所有子`View`对象都能在屏幕上显示：

    ```kt
    w -= max[0];
    h -= max[1];
    ```

1.  计算`CircleLayout`中的中心点：

    ```kt
    int cx = w / 2;
    int cy = h / 2;
    ```

1.  创建一个`for`循环，再次遍历每个子`View`对象：

    ```kt
    for(int i = 0; i < count; i++) {
    ```

1.  声明一个变量来保存当前的子`View`对象：

    ```kt
    View child = getChildAt(i);
    ```

1.  计算子`View`对象的`x`和`y`位置：

    ```kt
    double v = 2 * Math.PI * i / count;
    int x = l + (cx + (int)(Math.cos(v) * cx));
    int y = t + (cy + (int)(Math.sin(v) * cy));
    ```

1.  使用计算出的圆中坐标调用子`View`对象的布局方法：

    ```kt
    child.layout(
            x, y,
            x + child.getMeasuredWidth(),
            y + child.getMeasuredHeight());
    ```

## *刚才发生了什么？*

`CircleLayout`类是一个非常简单的`ViewGroup`实现。除了其子项请求的宽度和高度外，它没有可以在 XML 资源中使用的特殊属性。然而，它会注意到你为子项声明的尺寸，因此`layout_width`和`layout_height`属性将正常工作。

需要注意的是，为了从布局 XML 资源中使用自定义`View`或`ViewGroup`，你需要重写所有三个默认构造函数。

### 注意

`LayoutInflater`将使用这些构造函数中的一个来创建你的类的实例。如果它想要使用的那个不存在，那么在尝试膨胀布局 XML 文件时，你会遇到可怕的**强制关闭**对话框。

`CircleLayout`有其自己的实用方法来处理其子`View`对象的测量。通常，`ViewGroup`会使用`ViewGroup.measureChildren`工具方法来确保其所有子`View`对象在执行实际布局之前都已被测量。然而，我们需要遍历子`View`对象列表以找到最大的宽度和高度，因此我们不是执行三次迭代，而是自己执行测量。

## 使用 CircleLayout

为了使用自定义`ViewGroup`实现，了解 Android 在 XML 布局资源方面为你提供了支持是很有帮助的。当你需要从 XML 布局资源中引用自定义`View`或`ViewGroup`类时，只需使用完整的类名而不是简单的类名。以下是使用`CircleLayout`的 XML 布局的一个简单示例：

```kt
<com.packtpub.layouts.CircleLayout

    android:layout_width="fill_parent"
    android:layout_height="fill_parent">

    <Button android:text="Button1"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"/>

    <Button android:text="Button2"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"/>

    <!-- 10 Buttons in total works nicely 

</com.packtpub.layouts.CircleLayout>
```

# 动手实践时间——完成 CircleLayout 示例

我们已经有了`CicleLayout`的实现，但现在我们真的应该将其包含在“layouts”示例中。为此，我们需要一个布局资源 XML 文件，一个新的`CircleLayoutActivity`类。我们还需要在 Android（在清单文件中）和我们的`LayoutSelectorActivity`类（在其事件监听器中）注册新的`Activity`。

1.  将前面的 XML 布局复制到一个名为`res/layout/circle_layout.xml`的新文件中。最好添加大约十个小部件作为`CircleLayout ViewGroup`的子项。

1.  在项目的根包中创建一个名为`CircleLayoutActivity.java`的新 Java 源文件。在编辑器或 IDE 中打开它。

1.  `CircleLayoutActivity`必须继承`Activity`类：

    ```kt
    public class CircleLayoutActivity extends Activity {
    ```

1.  重写`Activity`的`onCreate`方法：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
    ```

1.  调用父类：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  将内容视图设置为`circle_layout`布局资源：

    ```kt
    setContentView(R.layout.circle_layout);
    ```

1.  在编辑器或 IDE 中打开`AndroidManifest.xml`文件。

1.  在`TableLayoutActivity`声明之后，声明新的`CircleLayoutActivity`：

    ```kt
    <activity android:name=".CircleLayoutActivity"
              android:label="Circle Layout Example"/>
    ```

1.  在编辑器或 IDE 中打开`LayoutSelectorActivity`源文件。

1.  在`onListItemClick`方法中，在`default case`之前，添加一个新的`case`语句来启动`CircleLayoutActivity`：

    ```kt
    case 2:
        startActivity(new Intent(
            this, CircleLayoutActivity.class));
        break;
    ```

## *刚才发生了什么？*

现在你有一个使用自定义`ViewGroup`实现的新`Activity`实现。自定义`ViewGroup`类不仅在标准`ViewGroup`实现无法很好地处理难以表达的布局时有用。当默认的`ViewGroup`实现对于你想要实现的具体结构来说太慢时，自定义`ViewGroup`也是一个选项。

你在本章中一直在构建的“布局”示例现在将拥有一个可用的**自定义布局**菜单项。点击它，你会看到以下截图。尝试添加除`Button`对象之外的控件，甚至可以尝试加入一个子`ViewGroup`看看会发生什么。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_05.jpg)

## 快速测验

1.  布局通常分为两个阶段，第一个阶段叫什么？

    1.  预布局

    1.  计算

    1.  父布局

    1.  测量

1.  布局方法的四个参数表示什么？

    1.  x, y, 宽度, 高度。

    1.  左，上，右，下。

    1.  父`ViewGroup`的大小。

1.  自定义`ViewGroup`实现如何读取布局 XML 属性？

    1.  它们通过`LayoutInflator`注入到 setter 方法中。

    1.  它们通过`View.getAttribute`方法加载。

    1.  它们从传递给`ViewGroup`构造函数的`AttributeSet`对象中读取。

# RelativeLayout

`RelativeLayout`类可以说是 Android 提供的最强大的布局。它是一个相对布局，管理大小不一的控件，并使控件相互对齐，而不是与它们的父控件或网格线对齐。在某种程度上，`RelativeLayout`与 Swing 的`GroupLayout`类非常相似，尽管它远没有后者复杂。`RelativeLayout`中的每个控件都是相对于另一个控件或其父控件（即`RelativeLayout`本身）来定位的。

`RelativeLayout`通过单次循环计算每个子控件的位置，因此它非常依赖于你指定子控件的顺序。但这并不意味着你必须按照它们在屏幕上显示的顺序来指定控件。由于`RelativeLayout`的性质，子控件通常以不同的顺序声明和显示。这也要求任何用于对齐其他控件的用户界面元素必须分配一个 ID。这包括通常不需要 ID 的非交互式用户界面元素，现在也必须分配一个 ID，尽管它们永远不会在布局之外使用。

使用`RelativeLayout`非常灵活，但也可能需要一些仔细的规划。与任何用户界面一样，首先在纸上绘制布局会非常有帮助。一旦有了纸上的图表，你就可以开始根据`RelativeLayout`类的规则来规划如何构建布局了。

## 常见用途

`RelativeLayout`的用途与`TableLayout`非常相似。它非常适合绘制表单和内容视图。然而，`RelativeLayout`并不局限于`TableLayout`的网格模式，因此可以创建屏幕上物理位置相隔较远的控件之间的关联（即通过相互对齐）。

`RelativeLayout` 可以根据同一 `RelativeLayout` 中的其他组件以及/或者 `RelativeLayout` 边界来定位和设置组件的大小。这意味着某些组件可能被放置在屏幕顶部，而你可以将另一组组件对齐在屏幕底部，如下图所示。

![常见用途](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_06.jpg)

## 集成 RelativeLayout

面对联系人编辑器时，`RelativeLayout` 是制作易于使用用户界面的完美工具。在下一个示例中，我们构建了一个非常简单的联系人编辑用户界面，包括用户图像。

# 动手时间——创建一个联系人编辑器

本示例要求部分用户界面元素按非顺序声明（如之前讨论的）。我们还在屏幕底部包含了 **保存** 和 **取消** `Button` 组件。这个示例回到了在资源 XML 文件中声明用户界面，而不是在 Java 代码中编写。对于此示例，你需要一个用户联系人照片的占位图像。一个 64x64 像素的 PNG 文件是合适的大小（我使用了一个大大的笑脸图像）。

1.  首先，创建一个新的 XML 布局文件，命名为 `res/layout/relative_layout.xml`。在你的编辑器或 IDE 中打开这个文件。

1.  将根元素声明为全屏的 `RelativeLayout`：

    ```kt
    <RelativeLayout

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  创建一个带有用户图标的 `ImageButton`。`ImageButton` 应该与屏幕左上角对齐，并包含一个占位图像：

    ```kt
    <ImageButton android:src="img/face"
                 android:id="@+id/photo"
                 android:layout_alignParentTop="true"
                 android:layout_alignParentLeft="true"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"/>
    ```

1.  添加一个 `EditText`，用户可以在其中输入联系人的姓名。将其与 `ImageButton` 右下对齐：

    ```kt
    <EditText android:text="Unknown"
              android:id="@+id/contact_name"
              android:layout_alignBottom="@id/photo"
              android:layout_toRightOf="@id/photo"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  现在添加一个 `TextView` 作为 `EditText` 组件的标签。我们将这个标签与 `ImageButton` 右对齐，但位于 `EditText` 之上：

    ```kt
    <TextView android:text="Contact Name:"
              android:id="@+id/contact_label"
              android:layout_above="@id/contact_name"
              android:layout_toRightOf="@id/photo"
              android:layout_width="wrap_content"
              android:layout_height="wrap_content"/>
    ```

1.  我们需要一个 **编辑** `Button` 以允许用户编辑联系人的电话号码列表。将此按钮放置在屏幕右侧，并位于 `EditText` 下方。我们在按钮顶部添加边距，以在用户界面中形成逻辑分隔：

    ```kt
    <Button android:id="@+id/edit_numbers"
            android:text="Edit"
            android:paddingLeft="20dp"
            android:paddingRight="20dp"
            android:layout_below="@id/contact_name"
            android:layout_alignParentRight="true"
            android:layout_marginTop="10dp"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"/>
    ```

1.  创建一个大的 `TextView` 作为电话号码的标签，我们将在新的 `TextView` 和 **编辑** `Button` 下方列出电话号码：

    ```kt
    <TextView android:text="Contact Numbers:"
              android:id="@+id/numbers_label"
              android:textSize="20sp"
              android:layout_alignBaseline="@id/edit_numbers"
              android:layout_alignParentLeft="true"
              android:layout_width="wrap_content"
              android:layout_height="wrap_content"/>
    ```

1.  现在创建一个 `TableLayout` 以列出联系人电话号码，将这个 `TableLayout` 在 `RelativeLayout` 中居中对齐，并将其置于 **Contact Numbers** 标签下方，并留有微小边距：

    ```kt
    <TableLayout android:layout_below="@id/edit_numbers"
                 android:layout_marginTop="5dp"
                 android:layout_centerInParent="true"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content">
    ```

1.  向 `TableLayout` 添加两个带有一些示例内容的 `TableRow` 元素：

    ```kt
    <TableRow>
        <TextView android:text="Home"
                  android:layout_marginRight="20dp"/>
        <TextView android:text="555-987-5678"/>
    </TableRow>
    <TableRow>
        <TextView android:text="Mobile" 
                  android:layout_marginRight="20dp"/>
        <TextView android:text="555-345-7654"/>
    </TableRow>
    ```

1.  创建一个位于屏幕左下角的**保存** `Button`：

    ```kt
    <Button android:text="Save"
            android:id="@+id/save"
            android:layout_alignParentLeft="true"
            android:layout_alignParentBottom="true"
            android:layout_width="100sp"
            android:layout_height="wrap_content"/>
    ```

1.  创建一个位于屏幕右下角的**取消** `Button`：

    ```kt
    <Button android:text="Cancel"
            android:id="@+id/cancel"
            android:layout_alignParentRight="true"
            android:layout_alignParentBottom="true"
            android:layout_width="100sp"
            android:layout_height="wrap_content"/>
    ```

## *刚才发生了什么*

在上一个示例中，许多用户界面元素是按照与逻辑布局顺序相反的顺序声明的，而其他元素则是相对于 `RelativeLayout` 本身定位的，因此可以放在 XML 文件的任何位置。

**联系人姓名**标签和编辑器相对于“联系人照片”定位，而“联系人照片”又相对于屏幕（或`RelativeLayout`）。然而，由于我们希望标签直接位于编辑器上方，因此我们需要在`TextView`元素之前声明并定位`EditText`元素。

**联系人姓名**的`EditText`元素使用了`fill_parent`的宽度，在`RelativeLayout`中，这将简单地填充可用的水平空间（如果是用在控件的高度上则是垂直空间）。当你希望一个元素简单地占据“行”的剩余部分，或者横跨整个屏幕（例如，作为分割线）时，这是一个很有用的特性。在`RelativeLayout`中，你不能对同一个轴上的控件使用两个相互冲突的布局属性。例如，你不能在同一个`View`控件上同时使用`layout_toRightOf`和`layout_alignRight`。

# 行动时间——与布局示例集成

`RelativeLayout`示例的集成与之前编写的自定义`CircleLayout`示例的集成几乎相同。集成将需要一个新的`Activity`实现，然后我们需要将其注册到 Android 和`LayoutSelectorActivity`中。

1.  在“layouts”示例项目的根包中创建一个新的 Java 源文件，命名为`RelativeLayoutActivity.java`。在你的编辑器或 IDE 中打开这个文件。

1.  新的`RelativeLayoutActivity`需要扩展`Activity`类：

    ```kt
    public class RelativeLayoutActivity extends Activity {
    ```

1.  重写`onCreate`方法：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
    ```

1.  调用`super`类来设置其状态：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  将新的`Activity`的内容视图设置为之前创建的`relative_layout` XML 布局资源：

    ```kt
    setContentView(R.layout.relative_layout);
    ```

1.  在你的编辑器或 IDE 中打开`AndroidManifest.xml`文件。

1.  在`CircleLayoutActivity`之后注册`RelativeLayoutActivity`：

    ```kt
    <activity android:name=".RelativeLayoutActivity"
              android:label="Relative Layout Example"/>
    ```

1.  在你的编辑器或 IDE 中打开`LayoutSelectorActivity`的 Java 源代码。

1.  在`onListItemClick`方法中，在`default`语句之前声明一个新的`case`语句并启动新的`RelativeLayoutActivity`：

    ```kt
    case 3:
        startActivity(new Intent(
                this, RelativeLayoutActivity.class));
        break;
    ```

## *刚才发生了什么？*

现在`RelativeLayoutActivity`已经与布局示例的其余部分集成在一起，你可以启动模拟器并查看你刚刚构建的屏幕。正如以下截图所示，这个设计比我们迄今为止构建的其他大多数设计都要用户友好。这主要是因为它能够以逻辑上相互关联的方式对控件进行分组和对其，而不是被迫局限于所选`ViewGroup`的要求。

然而，这种灵活性并非没有代价。`RelativeLayout`结构比其他`ViewGroup`实现更容易被破坏，在许多情况下，它不会为你提供太多的额外灵活性。在上述示例中，我们嵌入了一个`TableLayout`来显示联系人号码列表，而不是直接在`RelativeLayout`元素下显示它们。不仅`TableLayout`更适合这项任务，它还允许我们将号码作为一个组居中排列，而不是将它们对齐到`RelativeLayout`的左右两侧。

将`RelativeLayout`与内嵌的`ScrollView`或`FrameLayout`结合使用，是提供以内容为中心的用户界面工具栏的绝佳方式。当你的用户界面以媒体为中心（如全屏地图、视频、照片或类似内容）时，使用`RelativeLayout`将工具按钮围绕屏幕边缘布局，并通过`FrameLayout`将实际内容置于其后，这在许多 Android 应用中都能看到，如谷歌地图或默认的浏览器应用。这种设计还允许你根据用户与应用的交互来显示或隐藏工具按钮，从而在用户不与工具集互动时，让他们更好地查看媒体内容。

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_07.jpg)

# 滑动抽屉

如果你使用过未主题化的 Android 安装（如在模拟器中），或大多数主题化的 Android 版本，那么你已经使用过`SlidingDrawer`。这是推动启动器菜单打开和关闭的控件。虽然它本身并不是一个布局，但`SlidingDrawer`允许你快速向用户展示大量较少使用的控件。在开发新用户界面时，这使得它成为一个重要的控件考虑因素。

通常，在使用菜单和`SlidingDrawer`之间需要做出选择。虽然菜单非常适合显示动作项，但`SlidingDrawer`可以显示你想要的任何内容。然而，`SlidingDrawer`对其使用也有一些限制。例如，它要求你将其放置在`FrameLayout`或`RelativeLayout`实例中（其中`FrameLayout`更为典型），以使其正确工作。

`SlidingDrawer`在某种程度上是一种揭示控件。它由一个手柄和内容部分组成。默认情况下，只有手柄在屏幕上是可见的，直到用户触摸或拉动手柄来打开`SlidingDrawer`并显示内容部分。

## 常见用途

`SlidingDrawer`类的打开/关闭内容特性使其成为 Android 中应用启动器的理想选择。默认情况下，它是隐藏的，因此桌面可见且可用，直到你点击手柄以查看可用的应用程序列表。

这也使得 `SlidingDrawer` 成为构建策略游戏等应用程序的绝佳工具。例如，不要为用户提供所有可用的构建选项，而是将默认屏幕视图限制为关键地图元素。当用户想要构建某物或检查某些状态信息时，他们可以从屏幕底部轻触或拖动打开 `SlidingDrawer`，从而显示所有构建/命令选项。

通常，当用户不需要经常与之交互的动作或信息时，`SlidingDrawer` 是一个展示它们的绝佳方式。当需要用户注意的关键事件发生时，它也可以从你的 Java 代码中打开和关闭。

`SlidingDrawer` 的 handle 元素也是一个完整的 `View` 或 `ViewGroup`，允许你在其中放置状态信息。`slidingdrawer` 控件的另一个常见用途是，大多数 Android 设备顶部的状态栏通常实现为 `SlidingDrawer`。当事件发生时，在 handle 上显示摘要，用户可以拖开内容以查看最近事件的完整详情。

## 创建一个 SlidingDrawer 示例

为了让 `SlidingDrawer` 示例保持简洁，我们将重用 `CircleLayout` 示例，并进行一个主要修改——背景颜色需要改变。如果 `SlidingDrawer` 的背景没有特别设置，背景将会是透明的。通常，这是不希望发生的，因为打开的 `SlidingDrawer` 控件背后的内容会变得可见，这会干扰 `SlidingDrawer` 的内容。

# 是时候行动了——创建一个 SlidingDrawer

在本例中，我们将在一张图片上方放置一个 `SlidingDrawer` 控件（我再次选择了一位朋友的照片作为背景）。`SlidingDrawer` 的 handle 将使用为 `TableLayoutActivity` 创建的线条可绘制 XML 文件。`SlidingDrawer` 的内容将使用 `circle_layout` 资源。

1.  在你的编辑器或 IDE 中打开 `res/layout/circle_layout.xml` 文件。

1.  在根元素声明中，将背景属性设置为黑色：

    ```kt
    <com.packtpub.layouts.CircleLayout

        android:background="#ff000000"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  创建一个新的布局资源文件，命名为 `sliding_drawer.xml`，并在你的编辑器或 IDE 中打开这个文件。

1.  将此布局的根元素声明为 `FrameLayout`：

    ```kt
    <FrameLayout

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  在 `FrameLayout` 内部，创建一个 `ImageView` 以包含背景图像。记得设置缩放类型和大小，使图像充满屏幕：

    ```kt
    <ImageView android:src="img/jaipal"
               android:scaleType="centerCrop"
               android:layout_width="fill_parent"
               android:layout_height="fill_parent"/>
    ```

1.  声明 `SlidingDrawer` 控件。由于 handle 和 content 控件尚未创建，你需要提前引用它们：

    ```kt
    <SlidingDrawer android:handle="@+id/handle"
                   android:content="@+id/content"
                   android:layout_width="fill_parent"
                   android:layout_height="fill_parent">
    ```

1.  在 `SlidingDrawer` 元素内部，创建一个 `ImageView`，使用之前为 `TableLayoutActivity` 创建的占位符 `line` 可绘制资源：

    ```kt
    <ImageView android:id="@id/handle"
               android:src="img/line"
               android:layout_width="fill_parent"
               android:layout_height="12dp"/>
    ```

1.  在 `SlidingDrawer` 元素内部，包含 `circle_layout` 布局资源，并将其 ID 分配为 "content"：

    ```kt
    <include android:id="@id/content"
             layout="@layout/circle_layout"/>
    ```

## *刚才发生了什么？*

你可能注意到了，在之前的例子中，`SlidingDrawer`为其手柄和内容小部件添加了 ID 引用，而小部件本身似乎访问这些 ID 而不是声明它们：

```kt
<SlidingDrawer android:handle="@+id/handle"
               android:content="@+id/content"
               android:layout_width="fill_parent"
               android:layout_height="fill_parent">
```

这是`SlidingDrawer`类工作方式的一个副作用。它需要 ID 值，然后才需要小部件本身。这种技术非常类似于向前引用，不同之处在于对象在技术上并没有被创建。`@+`语法告诉资源编译器我们正在创建一个新的 id，但不是一个新对象。当我们后来使用`@id/handle`值作为其`id`声明`ImageView`元素时，实际上我们正在引用在声明`SlidingDrawer`时生成的值。

# 行动时间——滑动抽屉集成

现在是时候将`SlidingDrawer`示例插入到“layouts”示例中了。这与其他所有集成一样，涉及一个新的`Activity`，以及将新的`Activity`注册到 Android 和`LayoutSelectorActivity`中。

1.  在“layouts”示例项目的根包中创建一个新的 Java 源文件，名为`SlidingDrawerActivity.java`。在你的编辑器或 IDE 中打开这个文件。

1.  新的`SlidingDrawerActivity`需要扩展`Activity`类：

    ```kt
    public class SlidingDrawerActivity extends Activity {
    ```

1.  重写`onCreate`方法：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
    ```

1.  调用超类来设置其状态：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  将新`Activity`的内容视图设置为之前创建的`sliding_drawer` XML 布局资源：

    ```kt
    setContentView(R.layout.sliding_drawer);
    ```

1.  在你的编辑器或 IDE 中打开`AndroidManifest.xml`文件。

1.  在声明`RelativeLayoutActivity`之后注册`SlidingDrawerActivity`：

    ```kt
    <activity android:name=".SlidingDrawerActivity"
              android:label="Sliding Drawer Example"/>
    ```

1.  在你的编辑器或 IDE 中打开`LayoutSelectorActivity` Java 源代码。

1.  在`onListItemClick`方法中，在`default`语句之前声明一个新的`case`语句，并启动新的`SlidingDrawerActivity`：

    ```kt
    case 3:
        startActivity(new Intent(
                this, SlidingDrawerActivity.class));
        break;
    ```

## *刚才发生了什么？*

你已经完成了本章中的所有布局示例。你的`switch`语句中的`default`条件不应该再次触发了！`SlidingDrawer`示例非常简单，但很好地展示了这个部件可以有多么灵活。如果这个例子是一个绘图应用程序，`SlidingDrawer`将是一个隐藏更多复杂绘图功能的完美地方。

这个`SlidingDrawer`示例的手柄是一个简单的`ImageView`，但它可以是任何`View`或`ViewGroup`（如果你愿意，可以是`TableLayout`）。然而，你希望避免手柄变得可交互（即，一个`Button`或`EditText`小部件）。手柄中的交互式小部件会在用户触摸它时引起问题。尽管小部件完全功能正常，可以像手柄一样上下拖动，但触摸它以开始交互将导致`SlidingDrawer`打开或关闭。为了防止这种情况发生，你可以选择通过`allowSingleTap`属性关闭`SlidingDrawer`的“触摸切换”选项：

```kt
<SlidingDrawer android:handle="@+id/handle"
               android:content="@+id/content"
               android:allowSingleTap="false"
               android:layout_width="fill_parent"
               android:layout_height="fill_parent">
```

也就是说，将`EditText`（或类似的控件）作为`SlidingDrawer`的把手几乎是没有意义的，这很可能会让你的用户感到非常恼火。尽可能确保你的`SlidingDrawer`小部件的把手看起来像是用户可以拖动的东西。启动器应用程序的默认把手就是一个很好的例子。

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_05_08.jpg)

# 总结

通过本章示例的学习，应该能让你很好地了解 Android 默认提供的布局，以及它们是如何实现的（以及在需要时如何实现新的布局）。在大多数情况下，这些`ViewGroup`实现将满足你的任何布局需求，但在构建 Android 布局时，仍然需要牢记以下原则： 

+   不同的设备具有不同的大小和分辨率屏幕

+   使用负空间（空白）和线条来分隔小部件组

+   你几乎肯定需要在将来修改布局

在选择使用`RelativeLayout`类时，最后一点尤为重要。虽然它比其他实现方式提供了更多的功能，但一个组合得不好的`RelativeLayout`可能会非常难以维护，且耗时。

在接下来的章节中，我们将探讨如何捕获输入以及输入验证应当作为用户界面设计决策的一部分。我们还将通过一些示例来进行实践，这些示例可以作为未来用户界面开发的基础。
