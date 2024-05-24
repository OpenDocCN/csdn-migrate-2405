# Java9 编程蓝图（三）

> 原文：[`zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA`](https://zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Sunago - 一个 Android 端口

在上一章中，我们构建了 Sunago，一个社交媒体聚合应用程序。在那一章中，我们了解到 Sunago 是一个基于 JavaFX 的应用程序，可以从各种社交媒体网络中获取帖子、推文、照片等，并在一个地方显示它们。该应用程序提供了许多有趣的架构和技术示例，但应用程序本身可能更实用--我们倾向于从手机和平板电脑等移动设备与社交网络互动，因此移动版本将更有用。因此，在本章中，我们将编写一个 Android 端口，尽可能重用尽可能多的代码。

Android 应用程序，虽然是用 Java 构建的，但看起来与桌面应用程序有很大不同。虽然我们无法涵盖 Android 开发的每个方面，但在本章中，我们将涵盖足够的内容来让您入门，包括以下内容：

+   设置 Android 开发环境

+   Gradle 构建

+   Android 视图

+   Android 状态管理

+   Android 服务

+   应用程序打包和部署

与其他章节一样，将有太多的小项目需要指出，但我们将尽力突出介绍新的项目。

# 入门

第一步是设置 Android 开发环境。与*常规*Java 开发一样，IDE 并不是绝对必要的，但它确实有帮助，所以我们将安装 Android Studio，这是一个基于 IntelliJ IDEA 的 IDE。如果您已经安装了 IDEA，您只需安装 Android 插件，就可以拥有所需的一切。不过，在这里，我们假设您两者都没有安装。

1.  要下载 Android Studio，前往[`developer.android.com/studio/index.html`](https://developer.android.com/studio/index.html)，并下载适合您操作系统的软件包。当您第一次启动 Android Studio 时，您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/74eabc68-7103-49c2-935e-bca9650a22ed.png)

1.  在我们开始一个新项目之前，让我们配置可用的 Android SDK。点击右下角的 Configure 菜单，然后点击 SDK Manager，以获取以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/34f5a1cb-3fdf-4414-9e47-5396a67f16cf.png)

您选择的 SDK 将根据您的需求而变化。您可能需要支持旧设备，比如 Android 5.0，或者您可能只想支持最新的 Android 7.0 或 7.1.1。

1.  一旦你知道需要什么，选择适当的 SDK（或者像我在前面的屏幕截图中所做的那样，选择从 5.0 版本开始的所有内容），然后点击确定。在继续之前，您需要阅读并接受许可证。

1.  安装完成后，Android Studio 将开始下载所选的 SDK 和任何依赖项。这个过程可能需要一段时间，所以请耐心等待。

1.  当 SDK 安装完成时，点击完成按钮，这将带您到欢迎屏幕。点击开始一个新的 Android Studio 项目，以获取以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/fb7938a4-e5fb-47cd-bf09-38cf4620544d.png)

1.  这里没有什么激动人心的--我们需要指定应用程序名称，公司域和应用程序的项目位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/13d262cb-6a32-4e4c-862c-7d47dbc20d05.png)

1.  接下来，我们需要指定应用程序的形态因素。我们的选项是手机和平板电脑，佩戴，电视，Android Auto 和眼镜。如前面的屏幕截图所示，我们对这个应用程序感兴趣的是手机和平板电脑。

1.  在下一个窗口中，我们需要为应用程序的主`Activity`选择一个类型。在 Android 应用程序中，我们可能称之为“屏幕”（或者如果您来自 Web 应用程序背景，可能是“页面”）的东西被称为`Activity`。不过，并非每个`Activity`都是一个屏幕。

从 Android 开发者文档([`developer.android.com/reference/android/app/Activity.html`](https://developer.android.com/reference/android/app/Activity.html))中，我们了解到以下内容：

[a]活动是用户可以执行的单一、专注的事情。几乎所有的活动都与用户进行交互，因此活动类会为您创建一个窗口...

对于我们的目的，可能可以将两者等同起来，但要松散地这样做，并始终牢记这一警告。向导为我们提供了许多选项，如在此截图中所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/d0ed3ec9-b414-48c3-80b1-0d3e62781a94.png)

1.  正如您所看到的，有几个选项：基本、空白、全屏、Google AdMobs 广告、Google 地图、登录等。选择哪个取决于应用程序的要求。就用户界面而言，我们的最低要求是告诉用户应用程序的名称，显示社交媒体项目列表，并提供一个菜单来更改应用程序设置。因此，从上面的列表中，基本活动是最接近的匹配，因此我们选择它，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/db218934-2b49-41d2-becb-43a3e9d1914c.png)

1.  前面屏幕中的默认值大多是可以接受的（请注意，活动名称已更改），但在点击完成之前，还有一些最后的话。构建任何规模的 Android 应用程序时，您将拥有许多布局、菜单、活动等。我发现将这些工件命名为您在此处看到的名称很有帮助--活动的布局命名为`activity_`加上活动名称；菜单为活动名称加上`menu_`，或者对于共享菜单，是其内容的有意义的摘要。每种工件类型都以其类型为前缀。这种一般模式将帮助您在文件数量增加时快速导航到源文件，因为这些文件的排列非常扁平和浅。

1.  最后，请注意使用片段复选框。*片段是应用程序用户界面或行为的一部分，可以放置在活动中*。实际上，这是您作为开发人员将用户界面定义分解为多个片段（或片段，因此名称）的一种方式，这些片段可以根据应用程序当前上下文以不同的方式组合成一个整体在活动中。例如，基于片段的用户界面可能在手机上有两个屏幕用于某些操作，但在平板上可能将这些组合成一个活动。当然，情况比这更复杂，但我包含了这个简短而不完整的描述，只是为了解释复选框。我们不会在我们的应用程序中使用片段，因此我们将其取消选中，然后点击完成。

处理一段时间后，Android Studio 现在为我们创建了一个基本应用程序。在开始编写应用程序之前，让我们运行它，看看该过程是什么样子。我们可以以几种方式运行应用程序--我们可以单击“运行”|“运行‘app’”；单击工具栏中间的绿色播放按钮；或按下*Shift* + *F10*。所有这三种方法都会弹出相同的选择部署目标窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/218d9d68-39b5-44d1-8f73-f81d0094ec27.png)

由于我们刚刚安装了 Android Studio，我们还没有创建任何模拟器，因此现在需要这样做。要创建模拟器，请按照以下步骤操作：

1.  单击“创建新虚拟设备”按钮后，会出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/43e46090-343b-4f45-bbd0-4f1a8971900b.png)

1.  让我们从一个相当现代的 Android 手机开始--选择 Nexus 6 配置文件，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/7361ff87-aa1a-414c-8985-781b118a8ae0.png)

在前面的屏幕中，您的选项将根据您安装了哪些 SDK 而有所不同。再次选择哪个 SDK 取决于您的目标受众、应用程序需求等等。尽管始终使用最新和最好的东西很愉快，但我们并不严格需要来自 Nougat 的任何 API。选择 Android 7.x 将限制 Sunago 仅适用于新手机上，并且没有充分的理由这样做。因此，我们将以 Lollipop（Android 5.0）为目标，这在支持尽可能多的用户和提供对新 Android 功能的访问之间取得了良好的平衡。

1.  如果需要 x86_64 ABI，请单击下载链接，选择该版本，然后在“验证配置”屏幕上单击“完成”。

1.  创建了一个模拟器后，我们现在可以在“选择部署目标”屏幕中选择它，并通过单击“确定”来运行应用程序。如果您想要在下次运行应用程序时跳过选择屏幕，可以在单击“确定”之前选中“将来启动使用相同的选择”复选框。

第一次运行应用程序时，由于应用程序正在构建和打包，模拟器正在启动，所以会花费更长的时间。几分钟后，您应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/faa68398-f03d-4db0-b58b-4bcd7cb98270.png)

这没什么特别的，但它表明一切都按预期运行。现在，我们准备开始在移植 Sunago 中进行真正的工作。

# 构建用户界面

简而言之，Android 用户界面是基于 Activities 的，它使用布局文件来描述用户界面的结构。当然，还有更多内容，但这个简单的定义对我们在 Sunago 上的工作应该足够了。那么，让我们开始看看我们的`Activity`，`MainActivity`，如下所示：

```java
    public class MainActivity extends AppCompatActivity { 
      @Override 
      protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_main); 
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
        setSupportActionBar(toolbar); 

        FloatingActionButton fab =
            (FloatingActionButton) findViewById(R.id.fab); 
        fab.setOnClickListener(new View.OnClickListener() { 
            @Override 
            public void onClick(View view) { 
                Snackbar.make(view,
                        "Replace with your own action",
                        Snackbar.LENGTH_LONG) 
                    .setAction("Action", null).show(); 
            } 
        }); 
      } 

     @Override 
     public boolean onCreateOptionsMenu(Menu menu) { 
        getMenuInflater().inflate(R.menu.menu_main, menu); 
        return true; 
     } 

     @Override 
     public boolean onOptionsItemSelected(MenuItem item) { 
        int id = item.getItemId(); 

        if (id == R.id.action_settings) { 
            return true; 
        } 

        return super.onOptionsItemSelected(item); 
      } 
    } 

```

最后一部分代码是由 Android Studio 生成的类。它非常基础，但它具有大部分创建`Activity`所需的内容。请注意，该类扩展了`AppCompatActivity`。尽管 Google 一直在积极推动 Android 平台，但他们也不遗余力地确保旧设备不会被抛弃得比必要的更早。为了实现这一点，Google 已经在“compat”（或兼容性）包中将许多新功能进行了后向兼容，这意味着许多新的 API 实际上可以在旧版本的 Android 上运行。然而，由于它们在单独的包中，所以不会破坏任何现有的功能——它们必须明确选择，这就是我们在这里要做的。虽然我们不打算支持旧版本的 Android，比如 KitKat，但建议您的`Activity`类扩展兼容性类，就像这个类一样，因为这些类内置了大量功能，否则我们将不得不自己实现。让我们逐步了解这个类，以便在接下来的步骤中了解正在进行的所有工作：

1.  第一个方法是`onCreate()`，这是一个`Activity`生命周期方法（我们稍后会详细讨论 Activity 生命周期）。当系统创建`Activity`类时，将调用此方法。在这里，我们初始化用户界面，设置值，将控件连接到数据源等。请注意，该方法需要一个**Bundle**。这是 Android 传递 Activity 状态的方式，以便可以恢复它。

在`setContentView(R.layout.activity_main)`方法中，我们告诉系统我们要为这个`Activity`使用哪个布局。一旦我们为`Activity`设置了内容`View`，我们就可以开始获取对各种元素的引用。请注意，我们首先寻找视图中定义的`Toolbar`，`findViewById(R.id.toolbar)`，然后我们告诉 Android 使用它作为我们的操作栏，通过`setSupportActionBar()`。这是一个通过`compat`类为我们实现的功能的例子。如果我们直接扩展了，比如说，`Activity`，我们将需要做更多的工作来使操作栏工作。现在，我们只需调用一个 setter，就完成了。

1.  接下来，我们查找另一个用户界面元素，即`FloatingActionButton`。在前面的屏幕截图中，这是右下角带有电子邮件图标的按钮。实际上，我们将删除它，但是由于 Android Studio 生成了它，所以在删除之前我们可以从中学到一些东西。一旦我们有了对它的引用，我们就可以附加监听器。在这种情况下，我们通过创建一个类型为`View.OnClickListener`的匿名内部类来添加一个`onClick`监听器。这样做是有效的，但是在过去的五章中，我们一直在摆脱这些。

1.  Android 构建系统现在原生支持使用 Java 8，因此我们可以修改`onClick`监听器注册，使其看起来像这样：

```java
    fab.setOnClickListener(view -> Snackbar.make(view,
        "Replace with your own action",
            Snackbar.LENGTH_LONG) 
        .setAction("Action", null).show()); 

```

当用户点击按钮时，Snackbar 会出现。根据谷歌的文档，*Snackbar 通过屏幕底部的消息提供有关操作的简短反馈*。这正是我们得到的 - 一条消息告诉我们用自己的操作替换`onClick`的结果。不过，正如前面所述，我们不需要浮动按钮，所以我们将删除这个方法，以及稍后从布局中删除视图定义。

1.  类中的下一个方法是`onCreateOptionsMenu()`。当选项菜单首次打开以填充项目列表时，将调用此方法。我们使用`MenuInflater`来填充菜单定义文件，并将其添加到系统传入的`Menu`中。这个方法只会被调用一次，所以如果你需要一个会变化的菜单，你应该重写`onPrepareOptionsMenu(Menu)`。

1.  最后一个方法`onOptionsItemSelected()`在用户点击选项菜单项时被调用。传入了特定的`MenuItem`。我们获取它的 ID，并调用适用于菜单项的方法。

这是一个基本的`Activity`，但是布局是什么样的呢？这是`activity_main.xml`的内容：

```java
    <?xml version="1.0" encoding="utf-8"?> 
     <android.support.design.widget.CoordinatorLayout  

      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:fitsSystemWindows="true" 
      tools:context="com.steeplesoft.sunago.MainActivity"> 

      <android.support.design.widget.AppBarLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:theme="@style/AppTheme.AppBarOverlay"> 

       <android.support.v7.widget.Toolbar 
            android:id="@+id/toolbar" 
            android:layout_width="match_parent" 
            android:layout_height="?attr/actionBarSize" 
            android:background="?attr/colorPrimary" 
            app:popupTheme="@style/AppTheme.PopupOverlay" /> 

      </android.support.design.widget.AppBarLayout> 

      <include layout="@layout/content_main" /> 

     <android.support.design.widget.FloatingActionButton 
        android:id="@+id/fab" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_gravity="bottom|end" 
        android:layout_margin="@dimen/fab_margin" 
        app:srcCompat="@android:drawable/ic_dialog_email" /> 

     </android.support.design.widget.CoordinatorLayout> 

```

这是相当多的 XML，所以让我们快速浏览一下主要的兴趣点，如下所示：

1.  根元素是`CoordinatorLayout`。它的 Java 文档将其描述为一个超级强大的`FrameLayout`。其预期目的之一是作为*顶级应用程序装饰或 Chrome 布局*，这正是我们在这里使用它的目的。诸如`CoordinatorLayout`之类的布局大致相当于 JavaFX 的容器。不同的布局（或`ViewGroup`）提供了各种功能，例如使用精确的 X/Y 坐标布置元素（`AbsoluteLayout`），在网格中布置元素（`GridLayout`），相对于彼此布置元素（`RelativeLayout`），等等。

1.  除了提供我们的顶级容器之外，该元素还定义了一些必需的 XML 命名空间。它还为控件设置了高度和宽度。该字段有三个可能的值 - `match_parent`（在 SDK 的早期版本中，这被称为`fill_parent`，如果你遇到过的话），这意味着控件应该与其父级的值匹配，`wrap_content`，这意味着控件应该足够大以容纳其内容；或者是一个确切的数字。

1.  接下来的元素是`AppBarLayout`，它是一个实现了一些材料设计应用栏概念的`ViewGroup`。**材料设计**是谷歌正在开发和支持的最新**视觉语言**。它为 Android 应用程序提供了现代、一致的外观和感觉。谷歌鼓励使用它，并且幸运的是，新的`Activity`向导已经设置好了让我们直接使用它。布局的宽度设置为`match_parent`，以便填满屏幕，宽度设置为`wrap_content`，以便刚好足够显示其内容，即一个`Toolbar`。

1.  暂时跳过`include`元素，视图中的最后一个元素是`FloatingActionButton`。我们唯一感兴趣的是注意到这个小部件的存在，以防其他项目中需要它。不过，就像我们在`Activity`类中所做的那样，我们需要移除这个小部件。

1.  最后，还有`include`元素。这做的就是你认为它应该做的--指定的文件被包含在布局定义中，就好像它的内容被硬编码到文件中一样。这允许我们保持布局文件的小巧，重用用户界面元素定义（对于复杂的情况尤其有帮助），等等。

包含的文件`content_main.xml`看起来是这样的：

```java
        <RelativeLayout

          android:id="@+id/content_main" 
          android:layout_width="match_parent" 
          android:layout_height="match_parent" 
          android:paddingBottom="@dimen/activity_vertical_margin" 
          android:paddingLeft="@dimen/activity_horizontal_margin" 
          android:paddingRight="@dimen/activity_horizontal_margin" 
          android:paddingTop="@dimen/activity_vertical_margin" 
          app:layout_behavior="@string/appbar_scrolling_view_behavior" 
          tools:context="com.steeplesoft.sunago.MainActivity" 
          tools:showIn="@layout/activity_main"> 

         <TextView 
            android:layout_width="wrap_content" 
            android:layout_height="wrap_content" 
            android:text="Hello World!" /> 
        </RelativeLayout> 

```

这个前面的视图使用`RelativeLayout`来包裹它唯一的子元素，一个`TextView`。请注意，我们可以设置控件的填充。这控制了控件周围*内部*空间有多大。想象一下，就像包装一个盒子--在盒子里，你可能有一个易碎的陶瓷古董，所以你填充盒子来保护它。你也可以设置控件的边距，这是控件*外部*的空间，类似于我们经常喜欢的个人空间。

不过`TextView`并不有用，所以我们将其移除，并添加我们真正需要的，即`ListView`，如下所示：

```java
    <ListView 
      android:id="@+id/listView" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:layout_alignParentTop="true" 
      android:layout_alignParentStart="true"/> 

```

`ListView`是一个在垂直滚动列表中显示项目的控件。在用户体验方面，这基本上与我们在 JavaFX 中看到的`ListView`工作方式相似。不过，它的工作方式是完全不同的。为了了解它是如何工作的，我们需要对活动的`onCreate()`方法进行一些调整，如下所示：

```java
    protected void onCreate(Bundle savedInstanceState) { 
       super.onCreate(savedInstanceState); 
       setContentView(R.layout.activity_main); 

      if (!isNetworkAvailable()) { 
         showErrorDialog( 
            "A valid internet connection can't be established"); 
      } else { 
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
        setSupportActionBar(toolbar); 
        findPlugins(); 

        adapter = new SunagoCursorAdapter(this, null, 0); 
        final ListView listView = (ListView)
            findViewById(R.id.listView); 
        listView.setAdapter(adapter); 
        listView.setOnItemClickListener( 
                new AdapterView.OnItemClickListener() { 
            @Override 
            public void onItemClick(AdapterView<?> adapterView,
                    View view, int position, long id) { 
                Cursor c = (Cursor)
                    adapterView.getItemAtPosition(position); 
                String url = c.getString(c.getColumnIndex( 
                    SunagoContentProvider.URL)); 
                Intent intent = new Intent(Intent.ACTION_VIEW,
                    Uri.parse(url)); 
                startActivity(intent); 
            } 
         }); 

         getLoaderManager().initLoader(0, null, this); 
       } 
    } 

```

这里有几件事情正在进行，这为我们讨论 Android 中的数据访问做好了准备。在我们详细讨论之前，让我们先进行一个快速概述。

1.  我们检查设备是否有工作的网络连接通过`isNetworkAvailable()`，我们稍后在本章中会看到。

1.  如果连接可用，我们配置用户界面，首先设置工具栏。

1.  接下来，我们创建一个`SunagoCursorAdapter`的实例，我们稍后会详细讨论。不过现在，只需注意`Adapter`是`ListView`与数据源连接的方式，它们可以由各种各样的东西支持，比如 SQL 数据源或`Array`。

1.  我们将适配器传递给`ListView`，从而通过`ListView.setAdapter()`完成这个连接。就像 JavaFX 的`Observable`模型属性一样，我们将能够在数据发生变化时更新用户界面，而无需直接交互。

1.  接下来，我们为列表中的项目设置一个`onClick`监听器。我们将使用这个来在外部浏览器中显示用户点击（或点击）的项目。简而言之，给定`position`参数，我们获取该位置的项目，一个`Cursor`，提取项目的 URL，然后使用设备的默认浏览器通过`Intent`显示该 URL 的页面（我们稍后会详细讨论）。

1.  最后，完成我们的数据绑定，我们初始化将以异步方式处理加载和更新`Adapter`的`LoaderManager`。

在深入数据访问之前，我们要看的最后一点代码是`isNetworkAvailable()`，如下所示：

```java
        public boolean isNetworkAvailable() { 
          boolean connected = false; 
          ConnectivityManager cm = (ConnectivityManager)  
            getSystemService(Context.CONNECTIVITY_SERVICE); 
          for (Network network : cm.getAllNetworks()) { 
            NetworkInfo networkInfo = cm.getNetworkInfo(network); 
            if (networkInfo.isConnected() == true) { 
                connected = true; 
                break; 
            } 
          } 
         return connected; 
        } 

        private void showErrorDialog(String message) { 
          AlertDialog alertDialog = new AlertDialog.Builder(this) 
            .create(); 
          alertDialog.setTitle("Error!"); 
          alertDialog.setMessage(message); 
          alertDialog.setIcon(android.R.drawable.alert_dark_frame); 
          alertDialog.setButton(DialogInterface.BUTTON_POSITIVE,
          "OK", new DialogInterface.OnClickListener() { 
            @Override 
            public void onClick(DialogInterface dialog, int which) { 
              MainActivity.this.finish(); 
            } 
          }); 

          alertDialog.show(); 
       } 

```

在前面的代码中，我们首先获取系统服务`ConnectivityManager`的引用，然后循环遍历系统中已知的每个`Network`。对于每个`Network`，我们获取其`NetworkInfo`的引用并调用`isConnected()`。如果我们找到一个连接的网络，我们返回 true，否则返回 false。在调用代码中，如果我们的返回值是`false`，我们显示一个错误对话框，其方法也在这里显示。这是一个标准的 Android 对话框。不过，我们添加了一个`onClick`监听器到 OK 按钮，它关闭应用程序。使用这个，我们告诉用户需要网络连接，然后当用户点击 OK 时关闭应用程序。当然，这种行为是否可取是值得商榷的，但是确定设备的网络状态的过程是足够有趣的，所以我在这里包含了它。

现在让我们把注意力转向 Android 应用中经常进行的数据访问--`CursorAdapters`。

# Android 数据访问

在任何平台上，都有多种访问数据的方式，从内置设施到自制 API。安卓也不例外，因此，虽然你可以编写自己的方式从任意数据源加载数据，但除非你有非常特殊的要求，通常是没有必要的，因为安卓内置了一个系统——`ContentProvider`。

安卓文档会告诉你，*内容提供者管理对数据的中央存储库的访问*，并且它提供了一个一致的、*标准的数据接口，还处理进程间通信和安全数据访问*。如果你打算向外部来源（无论是读取还是写入）公开应用程序的数据，`ContentProvider`是一个很好的选择。然而，如果你不打算公开你的数据，你完全可以自己编写所需的 CRUD 方法，手动发出各种 SQL 语句。在我们的情况下，我们将使用`ContentProvider`，因为我们有兴趣允许第三方开发人员访问数据。

要创建一个`ContentProvider`，我们需要创建一个新的类，继承`ContentProvider`，如下所示：

```java
    public class SunagoContentProvider extends ContentProvider { 

```

我们还需要在`AndroidManfest.xml`中注册提供者，我们将这样做：

```java
    <provider android:name=".data.SunagoContentProvider 
      android:authorities="com.steeplesoft.sunago.SunagoProvider" /> 

```

与`ContentProvider`的交互永远不是直接进行的。客户端代码将指定要操作的数据的 URL，安卓系统将把请求转发给适当的提供者。因此，为了确保我们的`ContentProvider`按预期运行，我们需要注册提供者的权限，这已经在之前的 XML 中看到了。在我们的提供者中，我们将创建一些静态字段来帮助我们以 DRY 的方式管理我们权限的部分和相关的 URL。

```java
    private static final String PROVIDER_NAME =  
     "com.steeplesoft.sunago.SunagoProvider"; 
    private static final String CONTENT_URL =  
     "content://" + PROVIDER_NAME + "/items"; 
    public static final Uri CONTENT_URI = Uri.parse(CONTENT_URL); 

```

在上述代码的前两个字段中，是私有的，因为在类外部不需要它们。我们在这里将它们定义为单独的字段，以便更清晰。第三个字段`CONTENT_URI`是公共的，因为我们将在应用程序的其他地方引用该字段。第三方消费者显然无法访问该字段，但需要知道它的值`content://com.steeplesoft.sunago.SunagoProvider/items`，我们会在某个地方为附加开发人员记录这个值。URL 的第一部分，协议字段，告诉安卓我们正在寻找一个`ContentProvider`。接下来的部分是权限，它唯一标识特定的`ContentProvider`，最后一个字段指定我们感兴趣的数据类型或模型。对于 Sunago，我们只有一个数据类型，`items`。

接下来，我们需要指定我们想要支持的 URI。我们只有两个——一个用于项目集合，一个用于特定项目。请参考以下代码片段：

```java
    private static final UriMatcher URI_MATCHER =  
      new UriMatcher(UriMatcher.NO_MATCH); 
    private static final int ITEM = 1; 
    private static final int ITEM_ID = 2; 
    static { 
      URI_MATCHER.addURI(PROVIDER_NAME, "items", ITEM); 
      URI_MATCHER.addURI(PROVIDER_NAME, "items/#", ITEM_ID); 
     } 

```

在最后的代码中，我们首先创建了一个`UriMatcher`。请注意，我们将`UriMatcher.NO_MATCH`传递给构造函数。这个值的作用并不立即清楚，但如果用户传入一个不匹配任何已注册的 URI 的 URI，将返回这个值。最后，我们为每个 URI 注册一个唯一的`int`标识符。

接下来，像许多安卓类一样，我们需要指定一个`onCreate`生命周期钩子，如下所示：

```java
    public boolean onCreate() { 
      openHelper = new SunagoOpenHelper(getContext(), DBNAME,  
        null, 1); 
      return true; 
    } 

```

`SunagoOpenHelper`是`SQLiteOpenHelper`的子类，它管理底层 SQLite 数据库的创建和/或更新。这个类本身非常简单，如下所示：

```java
    public class SunagoOpenHelper extends SQLiteOpenHelper { 
      public SunagoOpenHelper(Context context, String name,  
            SQLiteDatabase.CursorFactory factory, int version) { 
          super(context, name, factory, version); 
      } 

      @Override 
      public void onCreate(SQLiteDatabase db) { 
        db.execSQL(SQL_CREATE_MAIN); 
      } 

      @Override 
      public void onUpgrade(SQLiteDatabase db, int oldVersion,  
        int newVersion) { 
      } 
    } 

```

我没有展示表的创建 DDL，因为它是一个非常简单的表创建，但这个类是你创建和维护数据库所需的全部。如果你有多个表，你将在`onCreate`中发出多个创建。当应用程序更新时，将调用`onUpgrade()`来允许你根据需要修改模式。

回到我们的`ContentProvider`，我们需要实现两个方法，一个用于读取数据，一个用于插入（考虑到应用程序的性质，我们现在不关心删除或更新）。对于读取数据，我们重写`query()`如下：

```java
    public Cursor query(Uri uri, String[] projection,  
      String selection, String[] selectionArgs,  
      String sortOrder) { 
        switch (URI_MATCHER.match(uri)) { 
          case 2: 
            selection = selection + "_ID = " +  
              uri.getLastPathSegment(); 
              break; 
        } 
        SQLiteDatabase db = openHelper.getReadableDatabase(); 
        Cursor cursor = db.query("items", projection, selection,  
          selectionArgs, null, null, sortOrder); 
        cursor.setNotificationUri( 
          getContext().getContentResolver(), uri); 
        return cursor; 
    } 

```

这最后一段代码是我们的 URI 及其`int`标识符的用处。使用`UriMatcher`，我们检查调用者传入的`Uri`。鉴于我们的提供者很简单，我们只需要为`#2`做一些特殊处理，这是针对特定项目的查询。在这种情况下，我们提取传入的 ID 作为最后的路径段，并将其添加到调用者指定的选择条件中。

一旦我们按照要求配置了查询，我们就从我们的`openHelper`中获得一个可读的`SQLiteDatabase`，并使用调用者传递的值进行查询。这是`ContentProvider`合同非常方便的地方之一--我们不需要手动编写任何`SELECT`语句。

在返回游标之前，我们需要对它进行一些处理，如下所示：

```java
    cursor.setNotificationUri(getContext().getContentResolver(), uri); 

```

通过上述调用，我们告诉系统我们希望在数据更新时通知游标。由于我们使用了`Loader`，这将允许我们在插入数据时自动更新用户界面。

对于插入数据，我们重写`insert()`如下：

```java
    public Uri insert(Uri uri, ContentValues values) { 
      SQLiteDatabase db = openHelper.getWritableDatabase(); 
      long rowID = db.insert("items", "", values); 

      if (rowID > 0) { 
        Uri newUri = ContentUris.withAppendedId(CONTENT_URI,  
            rowID); 
        getContext().getContentResolver().notifyChange(newUri,  
            null); 
        return newUri; 
      } 

    throw new SQLException("Failed to add a record into " + uri); 
    } 

```

使用`openHelper`，这一次，我们获得了数据库的可写实例，在这个实例上调用`insert()`。插入方法返回刚刚插入的行的 ID。如果我们得到一个非零的 ID，我们会为这一行生成一个 URI，最终会返回它。然而，在这之前，我们会通知内容解析器数据的变化，这会触发用户界面的自动重新加载。

然而，我们还有一步要完成我们的数据加载代码。如果你回顾一下`MainActivity.onCreate()`，你会看到这一行：

```java
    getLoaderManager().initLoader(0, null, this); 

```

这最后一行告诉系统我们要初始化一个`Loader`，并且`Loader`是`this`或`MainActivity`。在我们对`MainActivity`的定义中，我们已经指定它实现了`LoaderManager.LoaderCallbacks<Cursor>`接口。这要求我们实现一些方法，如下所示：

```java
    public Loader<Cursor> onCreateLoader(int i, Bundle bundle) { 
      CursorLoader cl = new CursorLoader(this,  
        SunagoContentProvider.CONTENT_URI,  
        ITEM_PROJECTION, null, null, 
           SunagoContentProvider.TIMESTAMP + " DESC"); 
      return cl; 
    } 

    public void onLoadFinished(Loader<Cursor> loader, Cursor cursor) { 
      adapter.swapCursor(cursor); 
    } 

    public void onLoaderReset(Loader<Cursor> loader) { 
      adapter.swapCursor(null); 
    } 

```

在`onCreateLoader()`中，我们指定要加载的内容和加载的位置。我们传入刚刚创建的`ContentProvider`的 URI，通过`ITEM_PROJECTION`变量（这是一个`String[]`，这里没有显示）指定我们感兴趣的字段，最后是排序顺序（我们已经指定为项目的时间戳按降序排列，这样我们就可以得到最新的项目）。`onLoadFinished()`方法是自动重新加载发生的地方。一旦为更新的数据创建了新的`Cursor`，我们就将其替换为`Adapter`当前正在使用的`Cursor`。虽然你可以编写自己的持久化代码，但这突出了为什么尽可能使用平台设施可能是一个明智的选择。

在数据处理方面还有一个重要的内容要看--`SunagoCursorAdapter`。再次查看 Android Javadocs，我们了解到*一个*`Adapter`*对象充当*`AdapterView`*和该视图的基础数据之间的桥梁*，而`CursorAdapter`*将*`Cursor`*中的数据暴露给*`ListView`*小部件*。通常--如果不是大多数情况--特定的`ListView`将需要一个自定义的`CursorAdapter`来正确渲染基础数据。Sunago 也不例外。因此，为了创建我们的`Adapter`，我们创建一个新的类，如下所示：

```java
    public class SunagoCursorAdapter extends CursorAdapter { 
      public SunagoCursorAdapter(Context context, Cursor c,  
      int flags) { 
        super(context, c, flags); 
    } 

```

这是非常标准的做法。真正有趣的部分在于视图的创建，这也是`CursorAdapter`存在的原因之一。当`Adapter`需要创建一个新的视图来保存游标指向的数据时，它会调用以下方法。这是我们通过调用`LayoutInflater.inflate()`来指定视图的外观的地方。

```java
    public View newView(Context context, Cursor cursor,  
        ViewGroup viewGroup) { 
          View view = LayoutInflater.from(context).inflate( 
          R.layout.social_media_item, viewGroup, false); 
          ViewHolder viewHolder = new ViewHolder(); 
          viewHolder.text = (TextView)
          view.findViewById(R.id.textView); 
          viewHolder.image = (ImageView) view.findViewById( 
          R.id.imageView); 

          WindowManager wm = (WindowManager) Sunago.getAppContext() 
            .getSystemService(Context.WINDOW_SERVICE); 
          Point size = new Point(); 
          wm.getDefaultDisplay().getSize(size); 
          viewHolder.image.getLayoutParams().width =  
            (int) Math.round(size.x * 0.33); 

          view.setTag(viewHolder); 
          return view; 
     } 

```

我们稍后会看一下我们的布局定义，但首先让我们来看一下`ViewHolder`：

```java
    private static class ViewHolder { 
      public TextView text; 
      public ImageView image; 
   } 

```

通过 ID 查找视图可能是一个昂贵的操作，因此一个非常常见的模式是使用`ViewHolder`方法。在视图被膨胀后，我们立即查找我们感兴趣的字段，并将这些引用存储在`ViewHolder`实例中，然后将其作为标签存储在`View`上。由于视图被`ListView`类回收利用（意味着，根据需要重复使用，当你滚动数据时），这昂贵的`findViewById()`只调用一次并缓存每个`View`，而不是在底层数据的每个项目中调用一次。对于大型数据集（和复杂的视图），这可能是一个重大的性能提升。

在这个方法中，我们还设置了`ImageView`类的大小。Android 不支持通过 XML 标记设置视图的宽度为百分比（如下所示），因此我们在创建`View`时手动设置。我们从中获取默认显示的大小，将显示的宽度乘以 0.33，这将限制图像（如果有的话）为显示宽度的 1/3，并将`ImageView`的宽度设置为这个值。

那么，每一行的视图是什么样子的呢？

```java
    <LinearLayout  

      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:orientation="horizontal"> 

      <ImageView 
        android:id="@+id/imageView" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_marginEnd="5dip" 
        android:layout_gravity="top" 
        android:adjustViewBounds="true"/> 

      <TextView 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:id="@+id/textView" 
        android:scrollHorizontally="false" 
        android:textSize="18sp" /> 
     </LinearLayout> 

```

正如`ViewHolder`所暗示的，我们的视图由一个`ImageView`和一个`TextView`组成，由于包含的`LinearLayout`，它们是水平呈现的。

当`CursorAdapter`调用`newView()`创建一个`View`时，它调用`bindView()`来将`View`绑定到`Cursor`中的特定行。这就是`View`回收利用的地方。适配器有许多`View`实例被缓存，并根据需要传递给这个方法。我们的方法如下所示：

```java
    public void bindView(View view, Context context, Cursor cursor) { 
      final ViewHolder viewHolder = (ViewHolder) view.getTag(); 
      String image = cursor.getString(INDEX_IMAGE); 
      if (image != null) { 
        new DownloadImageTask(viewHolder.image).execute(image); 
      } else { 
        viewHolder.image.setImageBitmap(null); 
        viewHolder.image.setVisibility(View.GONE); 
      } 
      viewHolder.body.setText(cursor.getString(INDEX_BODY)); 
    } 

```

我们首先获取`ViewHolder`实例。正如之前讨论的，我们将使用存储在这里的小部件引用来更新用户界面。接下来，我们从游标中提取图像 URL。每个`SocialMediaItem`决定如何填充这个字段，但它可能是一条推文中的图像或者 Instagram 帖子中的照片。如果该项有图像，我们需要下载它以便显示。由于这需要网络操作，并且我们正在用户界面线程上运行，我们将这项工作交给`DownloadImageTask`。如果这个项目没有图像，我们需要将图像的位图设置为`null`（否则，上次使用此视图实例时显示的图像将再次显示）。这样可以释放一些内存，这总是很好的，但我们还将`ImageView`类的可见性设置为`GONE`，这将隐藏它不显示在用户界面上。你可能会想使用`INVISIBLE`，但那只会使它在用户界面上不可见**同时保留其空间**。最终，我们将`TextView`正文的文本设置为该项指定的文本。

图像下载由一个`AsyncTask`在非主线程中处理，如下所示：

```java
    private static class DownloadImageTask extends  
       AsyncTask<String, Void, Bitmap> { 
        private ImageView imageView; 

        public DownloadImageTask(ImageView imageView) { 
         this.imageView = imageView; 
        } 

```

Android 将创建一个后台`Thread`来运行此任务。我们的逻辑的主要入口点是`doInBackground()`。请参考以下代码片段：

```java
    protected Bitmap doInBackground(String... urls) { 
      Bitmap image = null; 
      try (InputStream in = new URL(urls[0]).openStream()) { 
        image = BitmapFactory.decodeStream(in); 
      } catch (java.io.IOException e) { 
         Log.e("Error", e.getMessage()); 
         } 
        return image; 
    } 

```

这不是最健壮的下载代码（例如，重定向状态代码被忽略），但它肯定是可用的。使用 Java 7 的`try-with-resources`，我们创建一个`URL`实例，然后调用`openStream()`。假设这两个操作都没有抛出`Exception`，我们调用`BitmapFactory.decodeStream()`将传入的字节转换为`Bitmap`，这是该方法预期返回的内容。

那么，一旦我们返回`Bitmap`，它会发生什么？我们在`onPostExecute()`中处理它，如下所示：

```java
    protected void onPostExecute(Bitmap result) { 
      imageView.setImageBitmap(result); 
      imageView.setVisibility(View.VISIBLE); 
      imageView.getParent().requestLayout(); 
    } 

```

在这个最后的方法中，我们使用现在下载的`Bitmap`更新`ImageView`，使其可见，然后请求视图在屏幕上更新自己。

到目前为止，我们已经构建了一个能够显示`SocialMediaItem`实例的应用程序，但我们没有任何内容可以显示。现在我们将通过查看 Android 服务来解决这个问题。

# Android 服务

对于 Sunago 的桌面版本，我们定义了一个 API，允许第三方开发者（或我们自己）为 Sunago 添加对任意社交网络的支持。这对于桌面来说是一个很好的目标，对于移动设备也是一个很好的目标。幸运的是，Android 为我们提供了一个可以实现这一目标的机制：服务。*服务是一个应用组件，代表应用程序要执行长时间操作而不与用户交互，或者为其他应用程序提供功能*。虽然服务的设计不仅仅是为了可扩展性，但我们可以利用这个功能来实现这一目标。

虽然有许多实现和与服务交互的方法，我们将把服务绑定到我们的`Activity`，以便它们的生命周期与我们的`Activity`绑定，并且我们将以异步方式向它们发送消息。我们将首先定义我们的类如下：

```java
    public class TwitterService extends IntentService { 
      public TwitterService() { 
        super("TwitterService"); 
      } 

     @Override 
      protected void onHandleIntent(Intent intent) { 
    } 

```

从技术上讲，这些是创建服务所需的唯一方法。显然，它并没有做太多事情，但我们将在片刻之后解决这个问题。在我们这样做之前，我们需要在`AndroidManifest.xml`中声明我们的新`Service`，如下所示：

```java
    <service android:name=".twitter.TwitterService"  
     android:exported="false"> 
      <intent-filter> 
        <action  
          android:name="com.steeplesoft.sunago.intent.plugin" /> 
        <category  
          android:name="android.intent.category.DEFAULT" /> 
       </intent-filter> 
    </service> 

```

请注意，除了服务声明之外，我们还通过`intent-filter`元素指定了一个`IntentFilter`。稍后我们将在`MainActivity`中使用它来查找和绑定我们的服务。虽然我们正在查看我们的服务，但让我们也看看绑定过程的这一方面。我们需要实现这两个生命周期方法：

```java
    public IBinder onBind(Intent intent) { 
      receiver = new TwitterServiceReceiver(); 
      registerReceiver(receiver,  
        new IntentFilter("sunago.service")); 
      return null; 
     } 

    public boolean onUnbind(Intent intent) { 
      unregisterReceiver(receiver); 
      return super.onUnbind(intent); 
    } 

```

这些先前的方法在服务绑定和解绑时被调用，这给了我们一个注册接收器的机会，这可能会引发一个问题：那是什么？Android 提供了**进程间通信**（**IPC**），但它在有效载荷大小上有一定限制，不能超过 1MB。虽然我们的有效载荷只是文本，但我们可以（并且根据我的测试肯定会）超过这个限制。因此，我们的方法将是通过接收器使用异步通信，并让服务通过我们的`ContentProvider`持久保存数据。

要创建一个接收器，我们扩展`android.content.BroadcastReceiver`如下：

```java
    private class TwitterServiceReceiver extends BroadcastReceiver { 
      @Override 
      public void onReceive(Context context, Intent intent) { 
        if ("REFRESH".equals(intent.getStringExtra("message"))) { 
            if (SunagoUtil.getPreferences().getBoolean( 
                getString(R.string.twitter_authd), false)) { 
                new TwitterUpdatesAsyncTask().execute(); 
            } 
          } 
       } 
     } 

```

我们的消息方案非常简单--Sunago 发送消息`REFRESH`，服务执行其工作，我们已经将其封装在`TwitterUpdatesAsyncTask`中。在`onBind()`中，我们使用特定的`IntentFilter`注册接收器，指定我们感兴趣的`Intent`广播。在`onUnbind()`中，当服务被释放时，我们取消注册接收器。

我们服务的其余部分在我们的`AsyncTask`中，如下所示：

```java
    private class TwitterUpdatesAsyncTask extends  
    AsyncTask<Void, Void, List<ContentValues>> { 
      @Override 
      protected List<ContentValues> doInBackground(Void... voids) { 
        List<ContentValues> values = new ArrayList<>(); 
        for (SocialMediaItem item :  
                TwitterClient.instance().getItems()) { 
            ContentValues cv = new ContentValues(); 
            cv.put(SunagoContentProvider.BODY, item.getBody()); 
            cv.put(SunagoContentProvider.URL, item.getUrl()); 
            cv.put(SunagoContentProvider.IMAGE, item.getImage()); 
            cv.put(SunagoContentProvider.PROVIDER,  
                item.getProvider()); 
            cv.put(SunagoContentProvider.TITLE, item.getTitle()); 
            cv.put(SunagoContentProvider.TIMESTAMP,  
                item.getTimestamp().getTime()); 
            values.add(cv); 
        } 
        return values; 
      } 

    @Override 
    protected void onPostExecute(List<ContentValues> values) { 
      Log.i(MainActivity.LOG_TAG, "Inserting " + values.size() +  
        " tweets."); 
      getContentResolver() 
        .bulkInsert(SunagoContentProvider.CONTENT_URI, 
           values.toArray(new ContentValues[0])); 
      } 
    }  

```

我们需要确保网络操作不是在用户界面线程上执行，因此我们在`AsyncTask`中执行工作。我们不需要将任何参数传递给任务，因此我们将`Params`和`Progress`类型设置为`Void`。但是，我们对`Result`类型感兴趣，它是`List<ContentValue>`，我们在`execute()`的类型声明和返回类型中看到了这一点。然后在`onPostExecute()`中，我们对`ContentProvider`进行批量插入以保存数据。通过这种方式，我们可以使新检索到的数据在不违反`IBinder`的 1MB 限制的情况下对应用程序可用。

定义了我们的服务之后，我们现在需要看看如何找到和绑定服务。回顾一下`MainActivity`，我们最终将看到一个我们已经提到过的方法`findPlugins()`：

```java
    private void findPlugins() { 
     Intent baseIntent = new Intent(PLUGIN_ACTION); 
     baseIntent.setFlags(Intent.FLAG_DEBUG_LOG_RESOLUTION); 
     List<ResolveInfo> list = getPackageManager() 
            .queryIntentServices(baseIntent, 
            PackageManager.GET_RESOLVED_FILTER); 
     for (ResolveInfo rinfo : list) { 
        ServiceInfo sinfo = rinfo.serviceInfo; 
        if (sinfo != null) { 
            plugins.add(new  
                ComponentName(sinfo.packageName, sinfo.name)); 
        } 
      } 
    } 

```

为了找到我们感兴趣的插件，我们创建一个具有特定操作的`Intent`。在这种情况下，该操作是`com.steeplesoft.sunago.intent.plugin`，我们已经在`AndroidManifest.xml`中的服务定义中看到了。使用这个`Intent`，我们查询`PackageManager`以查找与 Intent 匹配的所有`IntentServices`。接下来，我们遍历`ResolveInfo`实例列表，获取`ServiceInfo`实例，并创建和存储代表插件的`ComponentName`。

实际绑定服务是在以下`bindPlugins()`方法中完成的，我们从`onStart()`方法中调用它，以确保在活动的生命周期中适当的时间发生绑定：

```java
    private void bindPluginServices() { 
      for (ComponentName plugin : plugins) { 
        Intent intent = new Intent(); 
        intent.setComponent(plugin); 
        PluginServiceConnection conn =  
            new PluginServiceConnection(); 
        pluginServiceConnections.add(conn); 
        bindService(intent, conn, Context.BIND_AUTO_CREATE); 
      } 
    } 

```

对于找到的每个插件，我们使用我们之前创建的`ComponentName`创建一个`Intent`。每个服务绑定都需要一个`ServiceConnection`对象。为此，我们创建了`PluginServiceConnection`，它实现了该接口。它的方法是空的，所以我们不会在这里看这个类。有了我们的`ServiceConnection`实例，我们现在可以通过调用`bindService()`来绑定服务。

最后，在应用程序关闭时进行清理，我们需要解除服务的绑定。从`onStop()`中，我们调用这个方法：

```java
    private void releasePluginServices() { 
      for (PluginServiceConnection conn :  
            pluginServiceConnections) { 
        unbindService(conn); 
      } 
      pluginServiceConnections.clear(); 
    } 

```

在这里，我们只需循环遍历我们的`ServiceConnection`插件，将每个传递给`unbindService()`，这将允许 Android 回收我们可能启动的任何服务。

到目前为止，我们已经定义了一个服务，查找了它，并绑定了它。但我们如何与它交互呢？我们将采用简单的方法，并添加一个选项菜单项。为此，我们修改`res/menu/main_menu.xml`如下：

```java
    <menu  

      > 
      <item android:id="@+id/action_settings"  
        android:orderInCategory="100"  
        android: 
        app:showAsAction="never" /> 
     <item android:id="@+id/action_refresh"  
        android:orderInCategory="100"  
        android: 
        app:showAsAction="never" /> 
    </menu> 

```

要响应菜单项的选择，我们需要在这里重新访问`onOptionsItemSelected()`：

```java
    @Override 
    public boolean onOptionsItemSelected(MenuItem item) { 
      switch (item.getItemId()) { 
        case R.id.action_settings: 
            showPreferencesActivity(); 
            return true; 
        case R.id.action_refresh: 
            sendRefreshMessage(); 
            break; 
       } 

     return super.onOptionsItemSelected(item); 
    } 

```

在前面代码的`switch`块中，我们为`R.id.action_refresh`添加了一个`case`标签，该标签与我们新添加的菜单项的 ID 相匹配，在其中调用了`sendRefreshMessage()`方法：

```java
    private void sendRefreshMessage() { 
      sendMessage("REFRESH"); 
    } 

    private void sendMessage(String message) { 
      Intent intent = new Intent("sunago.service"); 
      intent.putExtra("message", message); 
      sendBroadcast(intent); 
    } 

```

第一个方法非常简单。实际上，鉴于其简单性，可能甚至是不必要的，但它确实为消费代码添加了语义上的清晰度，因此我认为这是一个很好的方法。

然而，有趣的部分是`sendMessage()`方法。我们首先创建一个指定我们动作的`Intent`，`sunago.service`。这是一个我们定义的任意字符串，然后为任何第三方消费者进行文档化。这将帮助我们的服务过滤掉没有兴趣的消息，这正是我们在`TwitterService.onBind()`中使用`registerReceiver(receiver, new IntentFilter("sunago.service"))`所做的。然后，我们将我们的应用程序想要发送的消息（在这种情况下是`REFRESH`）作为`Intent`的额外部分添加，然后通过`sendBroadcast()`进行广播。从这里，Android 将处理将消息传递给我们的服务，该服务已经在运行（因为我们已将其绑定到我们的`Activity`）并且正在监听（因为我们注册了`BroadcastReceiver`）。

# Android 选项卡和片段

我们已经看了很多，但还有一些我们没有看到的，比如`TwitterClient`的实现，以及任何关于网络集成的细节，比如我们在上一章中看到的 Instagram。在很大程度上，`TwitterClient`与我们在第五章中看到的 *Sunago - A Social Media Aggregator* 是相同的。唯一的主要区别在于流 API 的使用。一些 API 仅在特定的 Android 版本中可用，具体来说是版本 24，也被称为 Nougat。由于我们的目标是 Lollipop（SDK 版本 21），我们无法使用它们。除此之外，内部逻辑和 API 使用是相同的。您可以在源代码库中看到细节。不过，在我们结束之前，我们需要看一下 Twitter 偏好设置屏幕，因为那里有一些有趣的项目。

我们将从一个选项卡布局活动开始，如下所示：

```java
    public class PreferencesActivity extends AppCompatActivity { 
      private SectionsPagerAdapter sectionsPagerAdapter; 
      private ViewPager viewPager; 

      @Override 
      protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_preferences); 

        setSupportActionBar((Toolbar) findViewById(R.id.toolbar)); 
        sectionsPagerAdapter =  
        new SectionsPagerAdapter(getSupportFragmentManager()); 

        viewPager = (ViewPager) findViewById(R.id.container); 
        viewPager.setAdapter(sectionsPagerAdapter); 

        TabLayout tabLayout = (TabLayout) findViewById(R.id.tabs); 
        tabLayout.setupWithViewPager(viewPager); 
    } 

```

要创建一个分页界面，我们需要两样东西——`FragmentPagerAdapter`和`ViewPager`。`ViewPager`是一个实际显示选项卡的用户界面元素。把它想象成选项卡的`ListView`。然后，`FragmentPagerAdapter`就像选项卡的`CursorAdapter`。不过，与 SQL 支持的数据源不同，`FragmentPagerAdapter`是一个代表片段的适配器。在这种方法中，我们创建了我们的`SectionsPagerAdapter`的一个实例，并将其设置为我们的`ViewPager`上的适配器。我们还将`ViewPager`元素与`TabLayout`关联起来。

`SectionsPagerAdapter`是一个简单的类，写成如下：

```java
    public class SectionsPagerAdapter extends FragmentPagerAdapter { 
      public SectionsPagerAdapter(FragmentManager fm) { 
      super(fm); 
    } 

    @Override 
    public Fragment getItem(int position) { 
        switch (position) { 
            case 0 : 
                return new TwitterPreferencesFragment(); 
            case 1 : 
                return new InstagramPreferencesFragment(); 
            default: 
                throw new RuntimeException("Invalid position"); 
        } 
     } 

     @Override 
     public int getCount() { 
        return 2; 
     } 

     @Override 
     public CharSequence getPageTitle(int position) { 
        switch (position) { 
            case 0: 
                return "Twitter"; 
            case 1: 
                return "Instagram"; 
       } 
        return null; 
     } 
    } 

```

方法`getCount()`告诉系统我们支持多少个选项卡，每个选项卡的标题由`getPageTitle()`返回，所选选项卡的`Fragment`由`getItem()`返回。在这个例子中，我们根据需要创建`Fragment`实例。请注意，我们在这里暗示支持 Instagram，但其实现看起来与 Twitter 实现非常相似，因此我们不会在这里详细介绍。

`TwitterPreferencesFragment`如下所示：

```java
    public class TwitterPreferencesFragment extends Fragment { 
      @Override 
       public View onCreateView(LayoutInflater inflater,  
       ViewGroup container, Bundle savedInstanceState) { 
       return inflater.inflate( 
        R.layout.fragment_twitter_preferences,  
        container, false); 
     } 

      @Override 
      public void onStart() { 
        super.onStart(); 
        updateUI(); 
      } 

```

片段的生命周期与`Activity`略有不同。在这里，我们在`onCreateView()`中填充视图，然后在`onStart()`中使用当前状态更新用户界面。视图是什么样子？这由`R.layout.fragment_twitter_preferences`确定。

```java
    <LinearLayout  

      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:paddingBottom="@dimen/activity_vertical_margin" 
      android:paddingLeft="@dimen/activity_horizontal_margin" 
      android:paddingRight="@dimen/activity_horizontal_margin" 
      android:paddingTop="@dimen/activity_vertical_margin" 
      android:orientation="vertical"> 

     <Button 
       android:text="Login" 
       android:layout_width="wrap_content" 
       android:layout_height="wrap_content" 
       android:id="@+id/connectButton" /> 

     <LinearLayout 
       android:orientation="vertical" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:id="@+id/twitterPrefsLayout"> 

     <CheckBox 
       android:text="Include the home timeline" 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:id="@+id/showHomeTimeline" /> 

     <TextView 
       android:text="User lists to include" 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:id="@+id/textView2" /> 

     <ListView 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:id="@+id/userListsListView" /> 
     </LinearLayout> 
    </LinearLayout> 

```

简而言之，正如您在上述代码中所看到的，我们有一个用于登录和注销的按钮，以及一个`ListView`，允许用户选择要从中加载数据的 Twitter 列表。

考虑到经常使用网络与 Twitter 进行交互以及 Android 对用户界面线程上的网络访问的厌恶，这里的代码变得有些复杂。我们可以在`updateUI()`中看到这一点，如下所示：

```java
    private void updateUI() { 
      getActivity().runOnUiThread(new Runnable() { 
        @Override 
        public void run() { 
          final Button button = (Button)  
          getView().findViewById(R.id.connectButton); 
          final View prefsLayout =  
          getView().findViewById(R.id.twitterPrefsLayout); 
          if (!SunagoUtil.getPreferences().getBoolean( 
          getString(R.string.twitter_authd), false)) { 
            prefsLayout.setVisibility(View.GONE); 
            button.setOnClickListener( 
              new View.OnClickListener() { 
            @Override 
            public void onClick(View view) { 
             new TwitterAuthenticateTask().execute(); 
            } 
            }); 
            } else { 
              button.setText(getString(R.string.logout)); 
              button.setOnClickListener( 
              new View.OnClickListener() { 
                @Override 
                public void onClick(View view) { 
                 final SharedPreferences.Editor editor =  
                 SunagoUtil.getPreferences().edit(); 
                 editor.remove(getString( 
                 R.string.twitter_oauth_token)); 
                 editor.remove(getString( 
                 R.string.twitter_oauth_secret)); 
                 editor.putBoolean(getString( 
                 R.string.twitter_authd), false); 
                 editor.commit(); 
                 button.setText(getString(R.string.login)); 
                 button.setOnClickListener( 
                 new LoginClickListener()); 
               } 
              }); 

               prefsLayout.setVisibility(View.VISIBLE); 
               populateUserList(); 
              } 
            } 
        });  
      }

```

在上述代码中，应该引起注意的第一件事是第一行。由于我们正在更新用户界面，我们必须确保此代码在用户界面线程上运行。为了实现这一点，我们将逻辑包装在`Runnable`中，并将其传递给`runOnUiThread()`方法。在`Runnable`中，我们检查用户是否已登录。如果没有，我们将`prefsLayout`部分的可见性设置为`GONE`，将`Button`的文本设置为登录，并将其`onClick`监听器设置为执行`TwitterAuthenticateTask`的`View.OnClickListener`方法。

如果用户未登录，我们则相反——使`prefsLayout`可见，将`Button`文本设置为注销，将`onClick`设置为一个匿名的`View.OnClickListener`类，该类删除与身份验证相关的偏好设置，并递归调用`updateUI()`以确保界面更新以反映注销状态。

`TwitterAuthenticateTask`是另一个处理与 Twitter 身份验证的`AsyncTask`。为了进行身份验证，我们必须获取 Twitter 请求令牌，这需要网络访问，因此必须在用户界面线程之外完成，因此使用`AsyncTask`。请参考以下代码片段：

```java
    private class TwitterAuthenticateTask extends  
        AsyncTask<String, String, RequestToken> { 
      @Override 
      protected void onPostExecute(RequestToken requestToken) { 
        super.onPostExecute(requestToken); 

        Intent intent = new Intent(getContext(),  
          WebLoginActivity.class); 
        intent.putExtra("url",  
          requestToken.getAuthenticationURL()); 
        intent.putExtra("queryParam", "oauth_verifier"); 
        startActivityForResult(intent, LOGIN_REQUEST); 
      } 

      @Override 
      protected RequestToken doInBackground(String... strings) { 
        try { 
          return TwitterClient.instance().getRequestToken(); 
        } catch (TwitterException e) { 
          throw new RuntimeException(e); 
        } 
      } 
    } 

```

一旦我们有了`RequestToken`，我们就会显示`WebLoginActivity`，用户将在其中输入服务的凭据。我们将在下一段代码中看到这一点。

当该活动返回时，我们需要检查结果并做出适当的响应。

```java
    public void onActivityResult(int requestCode, int resultCode,  
    Intent data) { 
      super.onActivityResult(requestCode, resultCode, data); 
      if (requestCode == LOGIN_REQUEST) { 
        if (resultCode == Activity.RESULT_OK) { 
            new TwitterLoginAsyncTask() 
                .execute(data.getStringExtra("oauth_verifier")); 
        } 
      } 
    } 

```

当我们启动`WebLoginActivity`时，我们指定要获取结果，并指定一个标识符`LOGIN_REQUEST`，设置为 1，以唯一标识返回结果的`Activity`。如果`requestCode`是`LOGIN_REQUEST`，并且结果代码是`Activity.RESULT_OK`（见下文给出的`WebLoginActivity`），那么我们有一个成功的响应，我们需要完成登录过程，为此我们将使用另一个`AsyncTask`。

```java
    private class TwitterLoginAsyncTask  
    extends AsyncTask<String, String, AccessToken> { 
      @Override 
      protected AccessToken doInBackground(String... codes) { 
        AccessToken accessToken = null; 
        if (codes != null && codes.length > 0) { 
            String code = codes[0]; 
            TwitterClient twitterClient =  
              TwitterClient.instance(); 
            try { 
              accessToken = twitterClient.getAcccessToken( 
                twitterClient.getRequestToken(), code); 
            } catch (TwitterException e) { 
              e.printStackTrace(); 
            } 
            twitterClient.authenticateUser(accessToken.getToken(),  
              accessToken.getTokenSecret()); 
           } 

        return accessToken; 
       } 

      @Override 
      protected void onPostExecute(AccessToken accessToken) { 
        if (accessToken != null) { 
          SharedPreferences.Editor preferences =  
            SunagoUtil.getPreferences().edit(); 
          preferences.putString(getString( 
              R.string.twitter_oauth_token),  
            accessToken.getToken()); 
          preferences.putString(getString( 
              R.string.twitter_oauth_secret),  
            accessToken.getTokenSecret()); 
          preferences.putBoolean(getString( 
             R.string.twitter_authd), true); 
            preferences.commit(); 
          updateUI(); 
        } 
      } 
    } 

```

在`doInBackground()`中，我们执行网络操作。当我们有了结果`AccessToken`时，我们使用它来验证我们的`TwitterClient`实例，然后返回令牌。在`onPostExecute()`中，我们将`AccessToken`的详细信息保存到`SharedPreferences`中。从技术上讲，所有这些都可以在`doInBackground()`中完成，但我发现这样做很有帮助，特别是在学习新东西时，不要走捷径。一旦你对所有这些工作原理感到满意，当你感到舒适时，当然可以随时随地走捷径。

我们还有最后一个部分要检查，`WebLoginActivity`。在功能上，它与`LoginActivity`是相同的——它呈现一个网页视图，显示给定网络的登录页面。当登录成功时，所需的信息将返回给调用代码。由于这是 Android 而不是 JavaFX，因此机制当然有些不同。

```java
    public class WebLoginActivity extends AppCompatActivity { 
      @Override 
      protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_web_view); 
        setTitle("Login"); 
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
        setSupportActionBar(toolbar); 
        Intent intent = getIntent(); 
        final String url = intent.getStringExtra("url"); 
        final String queryParam =  
            intent.getStringExtra("queryParam"); 
        WebView webView = (WebView)findViewById(R.id.webView); 
        final WebViewClient client =  
            new LoginWebViewClient(queryParam); 
        webView.setWebViewClient(client); 
        webView.loadUrl(url); 
      } 

```

大部分前面的代码看起来非常像我们写过的其他`Activity`类。我们进行一些基本的用户界面设置，然后获取对`Intent`的引用，提取感兴趣的两个参数--登录页面的 URL 和指示成功登录的查询参数。

为了参与页面加载生命周期，我们扩展了`WebViewClient`（然后将其附加到`Activity`中的`WebView`，如前所示）。操作如下：

```java
    private class LoginWebViewClient extends WebViewClient { 
      private String queryParam; 

      public LoginWebViewClient(String queryParam) { 
        this.queryParam = queryParam; 
      } 

     @Override 
     public void onPageStarted(WebView view, String url,  
            Bitmap favicon) { 
        final Uri uri = Uri.parse(url); 
        final String value = uri.getQueryParameter(queryParam); 
        if (value != null) { 
            Intent resultIntent = new Intent(); 
            for (String name : uri.getQueryParameterNames()) { 
                resultIntent.putExtra(name,  
                    uri.getQueryParameter(name)); 
            } 
            setResult(Activity.RESULT_OK, resultIntent); 
            finish(); 
        } 
        super.onPageStarted(view, url, favicon); 
       } 
   } 

```

虽然`WebViewClient`提供了许多生命周期事件，但我们现在只关心一个，即`onPageStarted()`，当页面开始加载时会触发。通过在这里挂钩，我们可以在相关的网络活动开始之前查看 URL。我们可以检查所需的 URL，看看感兴趣的查询参数是否存在。如果存在，我们创建一个新的`Intent`将数据传递回调用者，将所有查询参数复制到其中，将`Activity`结果设置为`RESULT_OK`，然后完成`Activity`。如果您回顾一下`onActivityResult()`，现在应该能够看到`resultCode`来自哪里了。

# 总结

有了这个，我们的应用程序就完成了。它不是一个完美的应用程序，但它是一个完整的 Android 应用程序，演示了您可能在自己的应用程序中需要的许多功能，包括`Activities`、服务、数据库创建、内容提供程序、消息传递和异步处理。显然，应用程序的某些部分在错误处理方面可能需要更加健壮，或者设计需要更广泛地通用化。然而，在这种情况下这样做会使应用程序的基础知识变得太过模糊。因此，对读者来说，做出这些改变将是一个很好的练习。

在下一章中，我们将看看一个完全不同类型的应用程序。我们将构建一个小型实用程序来处理可能是一个严重问题的事情--太多的电子邮件。这个应用程序将允许我们描述一组规则，用于删除或移动电子邮件。这是一个简单的概念，但它将允许我们使用 JSON API 和`JavaMail`包。您将学到一些知识，并最终得到一个有用的小工具。


# 第七章：使用 MailFilter 进行电子邮件和垃圾邮件管理

在计算机科学中，我们有许多**定律**，其中最著名的可能是摩尔定律，它涉及计算机处理能力增加的速度。另一条定律，虽然不那么著名，当然也不那么严肃，被称为**Zawinski 定律**。杰米·扎温斯基，以其在网景和 Mozilla 的角色而闻名，曾指出“每个程序都试图扩展到可以读取邮件的程度。那些无法扩展到这一程度的程序将被可以的程序所取代。”尽管 Zawinski 定律并不像摩尔定律那样准确，但似乎确实有一定的真实性，不是吗？

本章将关注电子邮件，看看我们是否能解决困扰我们所有人的问题：电子邮件杂乱。从垃圾邮件到邮件列表的帖子，这些消息不断涌现，不断堆积。

我有几个电子邮件账户。作为家里的负责人和极客，我经常被委托管理我们的数字资产，即使他们没有意识到，而一小部分垃圾邮件可能看起来微不足道，但随着时间的推移，它可能成为一个真正的问题。在某个时候，处理起来似乎几乎不可能。

在本章中，我们将解决这个非常真实的问题，尽管可能有些夸张。这将给我们一个完美的借口来使用标准的 Java 电子邮件 API，适当地称为 JavaMail。

在本章中，我们将涵盖以下主题：

+   - JavaMail API

+   - 电子邮件协议

+   - 一些更多的 JavaFX 工作（当然）

+   - 使用 Quartz 在 Java 中创建作业计划

+   安装 Java 编写的特定于操作系统的服务

也许你已经很好地控制了你的电子邮件收件箱，如果是这样，恭喜你！然而，无论你的邮件客户端是多么整洁或令人不知所措，我们在本章中应该在探索小而强大的 JavaMail API 和电子邮件的美妙世界时玩得开心。

# 入门

在我们深入了解应用程序之前，让我们停下来快速看一下电子邮件涉及的内容。尽管电子邮件是如此普遍的工具，似乎对大多数人来说，甚至是技术上有心的人来说，它似乎是一个相当不透明的话题。如果我们要使用它，了解它将非常有帮助，即使只是一点点。如果你对协议的细节不感兴趣，那么可以跳到下一节。

# - 电子邮件协议的简要历史

像许多伟大的计算概念一样，**电子邮件**--**电子邮件**--最早是在 1960 年代引入的，尽管当时看起来大不相同。电子邮件的详细历史，虽然当然是一个很大的技术好奇心，但超出了我们在这里的目的范围，但我认为看一看今天仍然相关的一些电子邮件协议会很有帮助，其中包括用于发送邮件的 SMTP，以及用于（从您的电子邮件客户端的角度）接收邮件的 POP3 和 IMAP。（从技术上讲，电子邮件是通过 SMTP 由**邮件传输代理**（**MTA**）接收的，以将邮件从一个服务器传输到另一个服务器。我们非 MTA 作者从不以这种方式考虑，因此我们不需要过分担心这种区别）。

我们将从发送电子邮件开始，因为本章的重点将更多地放在文件夹管理上。SMTP（简单邮件传输协议）于 1982 年创建，最后更新于 1998 年，是发送电子邮件的主要协议。通常，在 SSL 和 TLS 安全连接的时代，客户端通过端口 587 连接到 SMTP 服务器。服务器和客户端之间的对话，通常称为对话，可能看起来像这样（摘自 SMTP RFC [`tools.ietf.org/html/rfc5321`](https://tools.ietf.org/html/rfc5321)）：

```java
    S: 220 foo.com Simple Mail Transfer Service Ready
    C: EHLO bar.com
    S: 250-foo.com greets bar.com
    S: 250-8BITMIME
    S: 250-SIZE
    S: 250-DSN
    S: 250 HELP
    C: MAIL FROM:<Smith@bar.com>
    S: 250 OK
    C: RCPT TO:<Jones@foo.com>
    S: 250 OK
    C: RCPT TO:<Green@foo.com>
    S: 550 No such user here
    C: RCPT TO:<Brown@foo.com>
    S: 250 OK
    C: DATA
    S: 354 Start mail input; end with <CRLF>.<CRLF>
    C: Blah blah blah...
    C: ...etc. etc. etc.
    C: .
    S: 250 OK
    C: QUIT
    S: 221 foo.com Service closing transmission channel

```

在这个简单的例子中，客户端与服务器握手，然后告诉邮件是从谁那里来的，发给谁。请注意，电子邮件地址列出了两次，但只有这些第一次出现的地方（`MAIL FROM`和`RCPT TO`，后者为每个收件人重复）才重要。第二组只是用于电子邮件的格式和显示。注意到这个特殊之处，实际的电子邮件在`DATA`行之后，这应该是相当容易理解的。一行上的孤立句号标志着消息的结束，此时服务器确认收到消息，我们通过说`QUIT`来结束。这个例子看起来非常简单，而且确实如此，但当消息有附件（如图像或办公文档）或者电子邮件以 HTML 格式进行格式化时，情况会变得更加复杂。

SMTP 用于发送邮件，而 POP3 协议用于检索邮件。POP，或者说是邮局协议，最早是在 1984 年引入的。当前标准的大部分 POP3 是在 1988 年引入的，并在 1996 年发布了更新。POP3 服务器旨在接收或下载客户端（如 Mozilla Thunderbird）的邮件。如果服务器允许，客户端可以在端口 110 上进行未加密连接，通常在端口 995 上进行安全连接。

POP3 曾经是用户下载邮件的主要协议。它快速高效，一度是我们唯一的选择。文件夹管理是必须在客户端上完成的，因为 POP3 将邮箱视为一个大存储区，没有文件夹的概念（POP4 旨在添加一些文件夹的概念，但在几年内没有对拟议的 RFC 取得任何进展）。POP3（RC 1939，位于[`tools.ietf.org/html/rfc1939`](https://tools.ietf.org/html/rfc1939)）给出了这个示例对话：

```java
    S: <wait for connection on TCP port 110>
    C: <open connection>
    S:    +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
    C:    APOP mrose c4c9334bac560ecc979e58001b3e22fb
    S:    +OK mrose's maildrop has 2 messages (320 octets)
    C:    STAT
    S:    +OK 2 320
    C:    LIST
    S:    +OK 2 messages (320 octets)
    S:    1 120
    S:    2 200
    S:    .
    C:    RETR 1
    S:    +OK 120 octets
    S:    <the POP3 server sends message 1>
    S:    .
    C:    DELE 1
    S:    +OK message 1 deleted
    C:    RETR 2
    S:    +OK 200 octets
    S:    <the POP3 server sends message 2>
    S:    .
    C:    DELE 2
    S:    +OK message 2 deleted
    C:    QUIT
    S:    +OK dewey POP3 server signing off (maildrop empty)
    C:  <close connection>
    S:  <wait for next connection>

```

请注意，客户端发送`RETR`命令来检索消息，然后发送`DELE`命令来从服务器中删除它。这似乎是大多数 POP3 客户端的标准/默认配置。

尽管如此，许多客户端可以配置为在服务器上保留邮件一定数量的天数，或者永久保留，可能在本地删除邮件时从服务器中删除邮件。如果你以这种方式管理你的邮件，你会亲眼看到这如何使电子邮件管理变得复杂。

例如，在没有笔记本电脑的时代，想象一下你在办公室有一台台式电脑，在家里也有一台。你希望能够在两个地方都阅读你的电子邮件，所以你在两台机器上都设置了 POP3 客户端。你在工作日里阅读、删除，也许还分类邮件。当你回家时，那些在工作中处理的 40 封邮件现在都在你的收件箱里，用粗体字标记为未读邮件。如果你希望保持两个客户端的状态相似，你现在必须在家里重复你的电子邮件管理任务。这是繁琐且容易出错的，这导致我们创建了 IMAP。

**IMAP**或**Internet Access Message Protocol**，创建于 1986 年，其设计目标之一是允许多个客户端完全管理邮箱、文件夹等。多年来，它经历了几次修订，IMAP 4 修订 1 是当前的标准。客户端通过端口 143 连接到 IMAP 服务器进行未加密连接，通过端口 993 连接到 SSL 到 TLS 的连接。

IMAP，因为它提供比 POP 更强大的功能，所以是一个更复杂的协议。从 RFC（[`tools.ietf.org/html/rfc3501`](https://tools.ietf.org/html/rfc3501)）中，我们可以看到以下示例对话：

```java
    S:   * OK IMAP4rev1 Service Ready 
    C:   a001 login mrc secret 
    S:   a001 OK LOGIN completed 
    C:   a002 select inbox 
    S:   * 18 EXISTS 
    S:   * FLAGS (\Answered \Flagged \Deleted \Seen \Draft) 
    S:   * 2 RECENT 
    S:   * OK [UNSEEN 17] Message 17 is the first unseen message 
    S:   * OK [UIDVALIDITY 3857529045] UIDs valid 
    S:   a002 OK [READ-WRITE] SELECT completed 
    C:   a003 fetch 12 full 
    S:   * 12 FETCH (FLAGS (\Seen) INTERNALDATE 
         "17-Jul-1996 02:44:25 -0700" 
      RFC822.SIZE 4286 ENVELOPE ("Wed,
         17 Jul 1996 02:23:25 -0700 (PDT)" 
      "IMAP4rev1 WG mtg summary and minutes" 
      (("Terry Gray" NIL "gray" "cac.washington.edu")) 
      (("Terry Gray" NIL "gray" "cac.washington.edu")) 
      (("Terry Gray" NIL "gray" "cac.washington.edu")) 
      ((NIL NIL "imap" "cac.washington.edu")) 
      ((NIL NIL "minutes" "CNRI.Reston.VA.US") 
      ("John Klensin" NIL "KLENSIN" "MIT.EDU")) NIL NIL 
      "<B27397-0100000@cac.washington.edu>") 
       BODY ("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 3028 
       92)) 
    S:    a003 OK FETCH completed 
    C:    a004 fetch 12 body[header] 
    S:    * 12 FETCH (BODY[HEADER] {342} 
    S:    Date: Wed, 17 Jul 1996 02:23:25 -0700 (PDT) 
    S:    From: Terry Gray <gray@cac.washington.edu> 
    S:    Subject: IMAP4rev1 WG mtg summary and minutes 
    S:    To: imap@cac.washington.edu 
    S:    cc: minutes@CNRI.Reston.VA.US, John Klensin <KLENSIN@MIT.EDU> 
    S:    Message-Id: <B27397-0100000@cac.washington.edu> 
    S:    MIME-Version: 1.0 
    S:    Content-Type: TEXT/PLAIN; CHARSET=US-ASCII 
    S: 
    S:    ) 
    S:    a004 OK FETCH completed 
    C:    a005 store 12 +flags \deleted 
    S:    * 12 FETCH (FLAGS (\Seen \Deleted)) 
    S:    a005 OK +FLAGS completed 
    C:    a006 logout 
    S:    * BYE IMAP4rev1 server terminating connection 
    S:    a006 OK LOGOUT completed 

```

正如你所看到的，这里比我们的示例 POP3 对话中有更多的细节。这也应该突显出为什么我们使用像 JavaMail 这样的 API，而不是直接打开套接字并直接与服务器通信。说到 JavaMail，让我们把注意力转向这个标准 API，看看它能为我们做些什么。

# JavaMail，用于电子邮件的标准 Java API

JavaMail API 是一组抽象，提供了一种与电子邮件一起工作的协议和平台无关的方式。虽然它是**Java 企业版**（**Java EE**）的必需部分，但它是 Java SE 的附加库，这意味着你需要单独下载它，我们将通过我们的 POM 文件处理。

本章的应用程序主要关注消息管理，但我们将花一点时间来看看如何使用 API 发送电子邮件，这样你以后如果需要的话就有东西可以使用。

要开始发送邮件，我们需要获取 JavaMail `Session`。为此，我们需要设置一些属性如下：

```java
    Properties props = new Properties(); 
    props.put("mail.smtps.host", "smtp.gmail.com"); 
    props.put("mail.smtps.auth", "true"); 
    props.put("mail.smtps.port", "465"); 
    props.put("mail.smtps.ssl.trust", "*"); 

```

我们将通过 Gmail 的服务器发送电子邮件，并且我们将使用 SMTP over SSL。有了这个`Properties`实例，我们可以创建我们的`Session`实例如下：

```java
    Session session = Session.getInstance(props,  
      new javax.mail.Authenticator() { 
      @Override 
      protected PasswordAuthentication getPasswordAuthentication() { 
        return new PasswordAuthentication(userName, password); 
      } 
    }); 

```

要登录服务器，我们需要指定凭据，我们通过匿名的`PasswordAuthentication`实例来实现。一旦我们有了`Session`实例，我们需要创建一个`Transport`如下：

```java
    transport = session.getTransport("smtps"); 
      transport.connect(); 

```

请注意，对于协议参数，我们指定了`smtps`，这告诉 JavaMail 实现我们希望使用 SMTP over SSL/TLS。现在我们准备使用以下代码块构建我们的消息：

```java
    MimeMessage message = new MimeMessage(session); 
    message.setFrom("jason@steeplesoft.com"); 
    message.setRecipients(Message.RecipientType.TO, 
      "jason@steeplesoft.com"); 
    message.setSubject("JavaMail Example"); 

```

电子邮件消息使用`MimeMessage`类建模，所以我们使用我们的`Session`实例创建一个实例。我们设置了发件人和收件人地址，以及主题。为了使事情更有趣，我们将使用`MimeBodyPart`附加一个文件，如下所示：

```java
    MimeBodyPart text = new MimeBodyPart(); 
    text.setText("This is some sample text"); 

    MimeBodyPart attachment = new MimeBodyPart(); 
    attachment.attachFile("src/test/resources/rules.json"); 

    Multipart multipart = new MimeMultipart(); 
    multipart.addBodyPart(text); 
    multipart.addBodyPart(attachment); 
    message.setContent(multipart); 

```

我们的消息将有两个部分，使用`MimeBodyPart`建模，一个是消息的正文，是简单的文本，另一个是附件。在这种情况下，我们只是附加了一个数据文件，我们稍后会看到。一旦我们定义了这些部分，我们使用`MimeMultipart`将它们组合起来，然后将其设置为我们的消息的内容，现在我们可以使用`transport.sendMessage()`方法：

```java
    transport.sendMessage(message, new Address[] { 
      new InternetAddress("jason@steeplesoft.com")}); 
      if (transport != null) { 
        transport.close();   
      }  

```

仅仅几秒钟内，你应该会在收件箱中看到以下电子邮件出现：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/4dd554f8-c9ec-4b1a-8d9f-b0c28215ea48.png)

如果你想发送带有文本替代的 HTML 电子邮件，可以使用以下代码：

```java
    MimeBodyPart text = new MimeBodyPart(); 
    text.setContent("This is some sample text", "text/plain");  
    MimeBodyPart html = new MimeBodyPart(); 
    html.setContent("<strong>This</strong> is some <em>sample</em>
      <span style=\"color: red\">text</span>", "text/html"); 
    Multipart multipart = new MimeMultipart("alternative"); 
    multipart.addBodyPart(text); 
    multipart.addBodyPart(html); 
    message.setContent(multipart); 
    transport.sendMessage(message, new Address[]{ 
      new InternetAddress("jason@example.com")});

```

请注意，我们在每个`MimeBodyPart`上设置了内容，指定了 mime 类型，当我们创建`Multipart`时，我们将 alternative 作为`subtype`参数传递。如果不这样做，将会导致电子邮件显示两个部分，一个接一个，这显然不是我们想要的。如果我们正确编写了应用程序，我们应该在我们的电子邮件客户端中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/a6a7a1c4-d024-48ea-8a82-d24e1dbfb7b7.png)

你当然看不到红色文本，在黑白打印中，但你可以看到粗体和斜体文本，这意味着显示的是 HTML 版本，而不是文本版本。任务完成！

发送电子邮件非常有趣，但我们在这里是为了学习文件夹和消息管理，所以让我们把注意力转向那里，并且我们将从设置我们的项目开始。

# 构建 CLI

这个项目，就像其他项目一样，将是一个多模块的 Maven 项目。我们将有一个模块用于所有核心代码，另一个模块用于我们将编写的 GUI 来帮助管理规则。

要创建项目，这次我们将做一些不同的事情。我们将使用 Maven 原型从命令行创建项目，可以将其粗略地视为项目模板，这样你就可以看到如何以这种方式完成：

```java
    $ mvn archetype:generate \ -DarchetypeGroupId=
      org.codehaus.mojo.archetypes \ -DarchetypeArtifactId=pom-root -
      DarchetypeVersion=RELEASE 
      ... 
    Define value for property 'groupId': com.steeplesoft.mailfilter 
    Define value for property 'artifactId': mailfilter-master 
    Define value for property 'version':  1.0-SNAPSHOT 
    Define value for property 'package':  com.steeplesoft.mailfilter 

```

一旦 Maven 处理完成，就切换到新项目的目录`mailfilter-master`。从这里，我们可以创建我们的第一个项目，CLI：

```java
    $ mvn archetype:generate \ -DarchetypeGroupId=
      org.apache.maven.archetypes \ -DarchetypeArtifactId=
      maven-archetype-quickstart \ -DarchetypeVersion=RELEASE 
    Define value for property 'groupId': com.steeplesoft.mailfilter 
    Define value for property 'artifactId': mailfilter-cli 
    Define value for property 'version':  1.0-SNAPSHOT 
    Define value for property 'package':  com.steeplesoft.mailfilter 

```

这将在`mailfilter-master`下创建一个名为`mailfilter-cli`的新项目。我们现在可以在 NetBeans 中打开`mailfilter-cli`并开始工作。

我们需要做的第一件事是规定我们希望这个工具如何工作。在高层次上，我们希望能够为一个帐户指定任意数量的规则。这些规则将允许我们根据某些标准移动或删除电子邮件，例如发件人或电子邮件的年龄。为了保持简单，我们将所有规则范围限定为特定帐户，并将操作限制为移动和删除。

让我们首先看一下帐户可能是什么样子：

```java
    public class Account { 
      @NotBlank(message="A value must be specified for serverName") 
      private String serverName; 
      @NotNull(message = "A value must be specified for serverPort") 
      @Min(value = 0L, message = "The value must be positive") 
      private Integer serverPort = 0; 
      private boolean useSsl = true; 
      @NotBlank(message = "A value must be specified for userName") 
      private String userName; 
      @NotBlank(message = "A value must be specified for password") 
      private String password; 
      private List<Rule> rules; 

```

这基本上是一个非常简单的**POJO**（**Plain Old Java Object**），有六个属性：`serverName`，`serverPort`，`useSsl`，`userName`，`password`和`rules`。那些注释是什么呢？那些来自一个名为 Bean Validation 的库，它提供了一些注释和支持代码，允许我们以声明方式表达对值的约束，变量可以保存。这里是我们正在使用的注释及其含义：

+   `@NotBlank`：这告诉系统该值不能为空，也不能是空字符串（实际上，`string != null && !string.trim() .equals("")`）

+   `@NotNull`：这告诉系统该值不能为空

+   `@Min`：描述最小有效值

当然，还有许多其他的方法，系统定义了一种方法让您定义自己的方法，因此这是一个非常简单但非常强大的框架，用于验证输入，这带来了一个重要的观点：这些约束只有在要求 Bean Validation 框架进行验证时才会被验证。我们可以轻松地构建一个大量的`Account`实例集合，其中每个字段都保存着无效数据，JVM 对此也会非常满意。应用 Bean Validation 约束的唯一方法是要求它检查我们提供的实例。简而言之，是 API 而不是 JVM 强制执行这些约束。这似乎是显而易见的，但有时明确说明是值得的。

在我们进一步进行之前，我们需要将 Bean Validation 添加到我们的项目中。我们将使用参考实现：`Hibernate Validator`。我们还需要在我们的项目中添加表达式语言 API 和一个实现。我们通过将以下依赖项添加到`pom.xml`中来获得所有这些依赖项：

```java
    <dependency> 
      <groupId>org.hibernate</groupId> 
      <artifactId>hibernate-validator</artifactId> 
      <version>5.3.4.Final</version> 
    </dependency> 
    <dependency> 
      <groupId>javax.el</groupId> 
      <artifactId>javax.el-api</artifactId> 
      <version>2.2.4</version> 
    </dependency> 
    <dependency> 
      <groupId>org.glassfish.web</groupId> 
      <artifactId>javax.el</artifactId> 
      <version>2.2.4</version> 
    </dependency> 

```

回到我们的模型，当然有一些 getter 和 setter，但这些并不是很有趣。但有趣的是`equals()`和`hashCode()`的实现。Josh Bloch 在他的重要作品《Effective Java》中说：

当你重写`equals`时，总是要重写`hashCode`。

他的主要观点是，不这样做违反了`equals()`合同，该合同规定相等的对象必须具有相等的哈希值，这可能导致类在任何基于哈希的集合中使用时出现不正确和/或不可预测的行为，例如`HashMap`。 Bloch 然后列出了一些创建良好的`hashCode`实现以及良好的`equals`实现的规则，但这是我的建议：让 IDE 为您完成这项工作，这就是我们在以下代码块中为`equals()`所做的。

```java
    public boolean equals(Object obj) { 
      if (this == obj) { 
        return true; 
      } 
      if (obj == null) { 
        return false; 
      } 
      if (getClass() != obj.getClass()) { 
        return false; 
      } 
      final Account other = (Account) obj; 
      if (this.useSsl != other.useSsl) { 
        return false; 
      } 
      if (!Objects.equals(this.serverName, other.serverName)) { 
        return false; 
      } 
      if (!Objects.equals(this.userName, other.userName)) { 
        return false; 
      } 
      if (!Objects.equals(this.password, other.password)) { 
        return false; 
      } 
      if (!Objects.equals(this.serverPort, other.serverPort)) { 
        return false; 
      } 
      if (!Objects.equals(this.rules, other.rules)) { 
         return false; 
      } 
      return true; 
    } 

```

我们在这里也对`hashCode()`做了同样的事情：

```java
    public int hashCode() { 
      int hash = 5; 
      hash = 59 * hash + Objects.hashCode(this.serverName); 
      hash = 59 * hash + Objects.hashCode(this.serverPort); 
      hash = 59 * hash + (this.useSsl ? 1 : 0); 
      hash = 59 * hash + Objects.hashCode(this.userName); 
      hash = 59 * hash + Objects.hashCode(this.password); 
      hash = 59 * hash + Objects.hashCode(this.rules); 
      return hash; 
    } 

```

请注意，`equals()`中测试的每个方法也在`hashCode()`中使用。您的实现必须遵循这个规则，否则您最终会得到不像应该那样工作的方法。您的 IDE 可能会在生成方法时帮助您，但您必须确保您确实使用相同的字段列表，当然，如果您修改了其中一个方法，另一个方法必须相应地更新。

现在我们有了`Account`，那么`Rule`是什么样子呢？让我们看一下以下代码片段：

```java
    @ValidRule 
    public class Rule { 
      @NotNull 
      private RuleType type = RuleType.MOVE; 
      @NotBlank(message = "Rules must specify a source folder.") 
      private String sourceFolder = "INBOX"; 
      private String destFolder; 
      private Set<String> fields = new HashSet<>(); 
      private String matchingText; 
      @Min(value = 1L, message = "The age must be greater than 0.") 
      private Integer olderThan; 

```

这个类的验证是双重的。首先，我们可以看到与`Account`上看到的相同的字段级约束：`type`不能为空，`sourceFolder`不能为空，`olderThan`必须至少为 1。虽然您可能不会认识它是什么，但我们在`@ValidRule`中也有一个类级别的约束。

字段级别的约束只能看到它们所应用的字段。这意味着如果字段的有效值取决于某个其他字段的值，这种类型的约束是不合适的。然而，类级别的规则允许我们在验证时查看整个对象，因此我们可以在验证另一个字段时查看一个字段的值。这也意味着我们需要更多的代码，所以我们将从以下注解开始：

```java
    @Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE}) 
    @Retention(RetentionPolicy.RUNTIME) 
    @Constraint(validatedBy = ValidRuleValidator.class) 
    @Documented 
    public @interface ValidRule { 
      String message() default "Validation errors"; 
      Class<?>[] groups() default {}; 
      Class<? extends Payload>[] payload() default {}; 
    } 

```

如果你以前从未见过注解的源代码，这是一个相当典型的例子。与其声明对象的类型为`class`或`interface`，我们使用了`@interface`，这是一个细微但重要的区别。注解的字段也有点不同，因为没有可见性修饰符，类型也不能是原始类型。注意使用了`default`关键字。

注解本身也有注解，如下所示：

+   `@Target`：这限制了这个注解可以应用的元素类型；在这种情况下，是类型和其他注解。

+   `@Retention`：这指示编译器是否应该将注解写入类文件，并在运行时可用。

+   `@Constraint`：这是一个 Bean 验证注解，标识我们的注解作为一个新的约束类型。这个注解的值告诉系统哪个`ConstraintValidator`处理这个约束的验证逻辑。

+   `@Documented`：这表明在任何类型上存在这个注解应该被视为该类型的公共 API 的一部分。

我们的`ConstraintValidator`实现来处理这个新的约束有点复杂。我们声明了这个类如下：

```java
    public class ValidRuleValidator implements  
      ConstraintValidator<ValidRule, Object> { 

```

Bean 验证为约束验证提供了一个参数化接口，该接口接受约束的类型和验证逻辑适用的对象类型。这允许您为不同的对象类型编写给定约束的不同验证器。在我们的情况下，我们可以指定`Rule`而不是`Object`。如果我们这样做，任何时候除了`Rule`之外的东西被注解为`@ValidRule`并且实例被验证，调用代码将看到一个异常被抛出。相反，我们所做的是验证被注解的类型，特别是在需要时添加约束违规。

接口要求我们也实现这个方法，但是我们这里没有工作要做，所以它有一个空的方法体，如下所示：

```java
    @Override 
    public void initialize(ValidRule constraintAnnotation) { 
    } 

```

有趣的方法叫做`isValid()`。它有点长，所以让我们一步一步地来看：

```java
    public boolean isValid(Object value,  
      ConstraintValidatorContext ctx) { 
        if (value == null) { 
          return true; 
        } 

```

第一步是确保`value`不为空。我们有两种选择：如果它是空的，返回`true`，表示没有问题，或者返回`false`，表示有问题。我们的选择取决于我们希望应用程序的行为。对于任何一种方法都可以提出合理的论点，但似乎认为将空的`Rule`视为无效是有道理的，所以让我们将这个部分的主体改为这样：

```java
    ctx.disableDefaultConstraintViolation(); 
    ctx.buildConstraintViolationWithTemplate( 
      "Null values are not considered valid Rules") 
      .addConstraintViolation(); 
    return false; 

```

我们使用指定的消息构建`ConstraintViolation`，将其添加到`ConstraintValidatorContext`，`ctx`，并返回`false`以指示失败。

接下来，我们要确保我们正在处理一个`Rule`的实例：

```java
    if (!(value instanceof Rule)) { 
      ctx.disableDefaultConstraintViolation(); 
      ctx.buildConstraintViolationWithTemplate( 
        "Constraint valid only on instances of Rule.") 
      .addConstraintViolation(); 
      return false; 
    } 

```

一旦我们确定我们有一个非空的`Rule`实例，我们就可以进入我们的验证逻辑的核心：

```java
    boolean valid = true; 
    Rule rule = (Rule) value; 
    if (rule.getType() == RuleType.MOVE) { 
      valid &= validateNotBlank(ctx, rule, rule.getDestFolder(),  
      "A destination folder must be specified."); 
    } 

```

我们想要能够收集所有的违规行为，所以我们创建一个`boolean`变量来保存当前状态，然后我们将值转换为`Rule`，以使处理实例更加自然。在我们的第一个测试中，我们确保，如果`Rule`的类型是`RuleType. MOVE`，它有一个指定的目标文件夹。我们使用这个私有方法来做到这一点：

```java
    private boolean validateNotBlank(ConstraintValidatorContext ctx,  
      String value, String message) { 
      if (isBlank(value)) { 
        ctx.disableDefaultConstraintViolation(); 
        ctx.buildConstraintViolationWithTemplate(message) 
        .addConstraintViolation(); 
        return false; 
      } 
      return true; 
   } 

```

如果`value`为空，我们添加`ConstraintViolation`，就像我们已经看到的那样，使用指定的消息，并返回`false`。如果不为空，我们返回`true`。然后这个值与`valid`进行 AND 运算，以更新`Rule`验证的当前状态。

`isBlank()`方法非常简单：

```java
    private boolean isBlank(String value) { 
      return (value == null || (value.trim().isEmpty())); 
    } 

```

这是一个非常常见的检查，实际上在逻辑上与 Bean Validation 的`@NotBlank`背后的验证器是相同的。

我们的下两个测试是相关的。逻辑是这样的：规则必须指定要匹配的文本，或者最大的天数。测试看起来像这样：

```java
     if (!isBlank(rule.getMatchingText())) { 
       valid &= validateFields(ctx, rule); 
     } else if (rule.getOlderThan() == null) { 
       ctx.disableDefaultConstraintViolation(); 
       ctx.buildConstraintViolationWithTemplate( 
         "Either matchingText or olderThan must be specified.") 
       .addConstraintViolation(); 
       valid = false; 
     } 

```

如果`Rule`指定了`matchingText`，那么我们验证`fields`是否已正确设置。如果既没有设置`matchingText`也没有设置`olderThan`，那么我们会添加一个`ConstraintViolation`，并设置`valid`为 false。我们的`fields`验证如下：

```java
    private boolean validateFields(ConstraintValidatorContext ctx, Rule rule) { 
      if (rule.getFields() == null || rule.getFields().isEmpty()) { 
        ctx.disableDefaultConstraintViolation(); 
        ctx.buildConstraintViolationWithTemplate( 
          "Rules which specify a matching text must specify the field(s)
            to match on.") 
          .addConstraintViolation(); 
        return false; 
      } 
      return true; 
    } 

```

我们确保`fields`既不是 null 也不是空。我们在这里不对`Set`字段的实际内容进行任何验证，尽管我们当然可以。

我们可能已经编写了我们的第一个自定义验证。你的反应可能是：“哇！这对于一个‘简单’的验证来说是相当多的代码”，你是对的。在你把孩子和洗澡水一起扔掉之前，想一想：Bean Validation 的价值在于你可以将潜在复杂的验证逻辑隐藏在一个非常小的注解后面。然后，你可以通过在适当的位置放置你的约束注解来简单地重用这个逻辑。逻辑在一个地方表达，一个地方维护，但在许多地方使用，非常整洁和简洁。

所以，是的，这是相当多的代码，但你只需要写一次，约束的使用者永远不需要看到它。实际上，与通常写的代码相比，这并没有太多额外的工作，但这取决于你是否认为这额外的工作值得一试。

现在我们已经快速浏览了自定义 Bean Validation 约束，让我们回到我们的数据模型。最后要展示的是`RuleType`枚举：

```java
    public enum RuleType { 
      DELETE, MOVE; 
      public static RuleType getRuleType(String type) { 
        switch(type.toLowerCase()) { 
          case "delete" : return DELETE; 
          case "move" : return MOVE; 
          default : throw new IllegalArgumentException( 
            "Invalid rule type specified: " + type); 
        } 
      } 
    } 

```

这是一个基本的 Java `enum`，有两个可能的值，`DELETE`和`MOVE`，但我们还添加了一个辅助方法，以返回给定字符串表示的适当的`RuleType`实例。这将在我们从 JSON 中解组`Rule`时帮助我们。

有了我们定义的数据模型，我们准备开始编写实用程序本身的代码。虽然 Maven 模块被称为`mailfilter-cli`，但我们在这里不会关心一个健壮的命令行界面，就像我们在前几章中看到的那样。相反，我们将提供一个与命令行的非常基本的交互，将 OS 服务留作首选的使用方式，我们稍后会看到。

在这一点上，我们将开始使用 JavaMail API，所以我们需要确保我们的项目设置正确，因此我们在`pom.xml`中添加以下代码：

```java
    <dependency> 
      <groupId>com.sun.mail</groupId> 
      <artifactId>javax.mail</artifactId> 
      <version>1.5.6</version> 
    </dependency> 

```

在我们的 IDE 中，我们创建一个新的类`MailFilter`，并创建如下的熟悉的`public static void main`方法：

```java
    public static void main(String... args) { 
      try { 
        final MailFilter mailFilter =  
          new MailFilter(args.length > 0 ? args[1] : null); 
        mailFilter.run(); 
        System.out.println("\tDeleted count: "  
          + mailFilter.getDeleted()); 
        System.out.println("\tMove count:    "  
          + mailFilter.getMoved()); 
      } catch (Exception e) { 
        System.err.println(e.getLocalizedMessage()); 
      } 
    } 

```

NetBeans 支持许多代码模板。这里感兴趣的模板是`psvm`，它将创建一个`public static void main`方法。要使用它，请确保你在类定义的空行上（以避免奇怪的格式问题），然后输入`psvm`并按 tab 键。NetBeans 会为你创建方法，并将光标放在空方法的第一行上，准备让你开始编码。你可以通过导航到工具 | 选项 | 编辑器 | 代码模板找到其他几十个有用的代码模板。你甚至可以定义自己的模板。

在我们的`main()`方法中，我们创建一个`MainFilter`的实例，传入可能在命令行中指定的任何规则定义文件，并调用`run()`：

```java
    public void run() { 
      try { 
        AccountService service = new AccountService(fileName); 

        for (Account account : service.getAccounts()) { 
          AccountProcessor processor =  
            new AccountProcessor(account); 
          processor.process(); 
          deleted += processor.getDeleteCount(); 
          moved += processor.getMoveCount(); 
        } 
      } catch (MessagingException ex) { 
        Logger.getLogger(MailFilter.class.getName()) 
        .log(Level.SEVERE, null, ex); 
      } 
    } 

```

我们首先创建一个`AccountService`的实例，它封装了读取和写入`Rules`文件的细节。对于指定文件中的每个帐户，我们创建一个`AccountProcessor`，它封装了规则处理逻辑。

`AccountService`实例可能听起来并不令人兴奋，但在这个公共接口的背后隐藏着一些非常有趣的技术细节。我们看到了 Bean Validation 约束是如何实际检查的，我们还看到了使用 Jackson JSON 库来读取和写入`Rules`文件。在我们可以开始使用 Jackson 之前，我们需要将其添加到我们的项目中，我们通过添加这个`pom.xml`来实现：

```java
    <dependency> 
      <groupId>com.fasterxml.jackson.core</groupId> 
      <artifactId>jackson-databind</artifactId> 
      <version>2.8.5</version> 
    </dependency> 

```

您应该始终确保您使用的是库的最新版本。

这不是一个很大的类，但这里只有三种方法是有趣的。我们将从最基本的方法开始，如下所示：

```java
    private File getRulesFile(final String fileName) { 
      final File file = new File(fileName != null ? fileName 
        : System.getProperty("user.home") + File.separatorChar 
        + ".mailfilter" + File.separatorChar + "rules.json"); 
      if (!file.exists()) { 
        throw new IllegalArgumentException( 
          "The rules file does not exist: " + rulesFile); 
      } 
      return file; 
    } 

```

我在这里包含的唯一原因是，从用户的主目录中读取文件是我发现自己经常做的事情，您可能也是如此。这个示例向您展示了如何做到这一点，如果用户没有明确指定文件，则尝试在`~/.mailfilter/rules.json`中找到规则文件。生成或指定，如果找不到规则文件，我们会抛出异常。

也许最有趣的方法是`getAccounts()`方法。我们将慢慢地逐步进行：

```java
    public List<Account> getAccounts() { 
      final Validator validator = Validation 
        .buildDefaultValidatorFactory().getValidator(); 
      final ObjectMapper mapper = new ObjectMapper() 
        .configure(DeserializationFeature. 
        ACCEPT_SINGLE_VALUE_AS_ARRAY, true); 
      List<Account> accounts = null; 

```

这三个语句正在设置一些处理账户所需的对象。首先是`Validator`，它是 Bean Validation 类，是我们应用和检查我们在数据模型上描述的约束的入口点。接下来是`ObjectMapper`，这是一个 Jackson 类，它将把 JSON 数据结构映射到我们的 Java 数据模型上。我们需要指定`ACCEPT_SINGLE_VALUE_AS_ARRAY`以确保 Jackson 正确处理我们模型中的任何列表。最后，我们创建`List`来保存我们的`Account`实例。

使用 Jackson 将规则文件读入内存并将其作为我们数据模型的实例非常容易：

```java
    accounts = mapper.readValue(rulesFile,  
      new TypeReference<List<Account>>() {}); 

```

由于我们 Java 类中的属性名称与我们的 JSON 文件中使用的键匹配，`ObjectMapper`可以轻松地从 JSON 文件中读取数据，并仅使用这一行构建我们的内存模型。请注意`TypeReference`实例。我们希望 Jackson 返回一个`List<Account>`实例，但由于 JVM 中的一些设计决策，直接访问运行时参数化类型是不可能的。然而，`TypeReference`类有助于捕获这些信息，Jackson 然后使用它来创建数据模型。如果我们传递`List.class`，我们将在运行时获得类型转换失败。

现在我们有了我们的`Account`实例，我们准备开始验证：

```java
    accounts.forEach((account) -> { 
      final Set<ConstraintViolation<Account>> violations =  
        validator.validate(account); 
      if (violations.size() > 0) { 
        System.out.println( 
          "The rule file has validation errors:"); 
        violations.forEach(a -> System.out.println("  \"" + a)); 
        throw new RuntimeException("Rule validation errors"); 
      } 
      account.getRules().sort((o1, o2) ->  
        o1.getType().compareTo(o2.getType())); 
    }); 

```

使用`List.forEach()`，我们遍历`List`中的每个账户（这里没有显示空值检查）。对于每个`Account`，我们调用`validator.validate()`，这是实际验证约束的时候。到目前为止，它们只是存储在类中的注释，JVM 很高兴地将它们一起携带，但不做其他任何事情。正如我们之前讨论的那样，Bean Validation 是注释描述的约束的执行者，在这里我们看到了手动 API 调用。

当对“验证器”进行调用时返回，我们需要查看是否有任何`ConstraintViolations`。如果有，我们会相当天真地将每个失败的详细信息打印到标准输出。如果规则有多个违规行为，由于我们编写的验证器，我们将一次看到它们所有，因此用户可以在不必多次尝试处理规则的情况下修复它们。将这些打印到控制台并不一定是最佳方法，因为我们无法以编程方式处理它们，但目前对我们的需求来说已经足够了。

Bean Validation 真正闪耀的是在代表您集成它的框架中。例如，JAX-RS，用于构建 REST 资源的标准 Java API，提供了这种类型的集成。我们在此示例 REST 资源方法中看到了功能的使用：

`@GET`

`public Response getSomething (`

`@QueryParam("foo") @NotNull Integer bar) {`

当一个请求被路由到这个方法时，JAX-RS 确保查询参数`foo`被转换为`Integer`（如果可能的话），并且它不是`null`，所以在你的代码中，你可以假设你有一个有效的`Integer`引用。

在这个类中我们要看的最后一个方法是`saveAccounts()`，这个方法保存了指定的`Account`实例到规则文件中。

```java
    public void saveAccounts(List<Account> accounts) { 
      try { 
        final ObjectMapper mapper =  
          new ObjectMapper().configure(DeserializationFeature. 
          ACCEPT_SINGLE_VALUE_AS_ARRAY, true); 
        mapper.writeValue(rulesFile, accounts); 
      } catch (IOException ex) { 
        // ... 
      } 
    } 

```

就像读取文件一样，写入文件也非常简单，只要你的 Java 类和 JSON 结构匹配。如果名称不同（例如，Java 类可能具有`accountName`属性，而 JSON 文件使用`account_name`），Jackson 提供了一些注解，可以应用于 POJO，以解释如何正确映射字段。你可以在 Jackson 的网站上找到这些完整的细节（[`github.com/FasterXML/jackson`](https://github.com/FasterXML/jackson)）。

当我们的`Account`实例加载到内存中并验证正确后，我们现在需要处理它们。入口点是`process()`方法：

```java
    public void process() throws MessagingException { 
      try { 
        getImapSession(); 

        for (Map.Entry<String, List<Rule>> entry :  
          getRulesByFolder(account.getRules()).entrySet()) { 
          processFolder(entry.getKey(), entry.getValue()); 
        } 
      } catch (Exception e) { 
        throw new RuntimeException(e); 
      } finally { 
        closeFolders(); 
        if (store != null) { 
          store.close(); 
        } 
      } 
    } 

```

需要注意的三行是对`getImapSession()`、`getRulesByFolder()`和`processFolder()`的调用，我们现在将详细讨论它们：

```java
    private void getImapSession()  
      throws MessagingException, NoSuchProviderException { 
      Properties props = new Properties(); 
      props.put("mail.imap.ssl.trust", "*"); 
      props.put("mail.imaps.ssl.trust", "*"); 
      props.setProperty("mail.imap.starttls.enable",  
        Boolean.toString(account.isUseSsl())); 
      Session session = Session.getInstance(props, null); 
      store = session.getStore(account.isUseSsl() ?  
        "imaps" : "imap"); 
      store.connect(account.getServerName(), account.getUserName(),  
        account.getPassword()); 
    } 

```

要获得 IMAP`Session`，就像我们在本章前面看到的那样，我们创建一个`Properties`实例并设置一些重要的属性。我们使用用户在规则文件中指定的协议来获取`Store`引用：对于非 SSL 连接使用`imap`，对于 SSL 连接使用`imaps`。

一旦我们有了我们的会话，我们就会遍历我们的规则，按源文件夹对它们进行分组：

```java
    private Map<String, List<Rule>> getRulesByFolder(List<Rule> rules) { 
      return rules.stream().collect( 
        Collectors.groupingBy(r -> r.getSourceFolder(), 
        Collectors.toList())); 
    } 

```

现在我们可以按照以下方式处理文件夹：

```java
    private void processFolder(String folder, List<Rule> rules)  
      throws MessagingException { 
      Arrays.stream(getFolder(folder, Folder.READ_WRITE) 
        .getMessages()).forEach(message -> 
        rules.stream().filter(rule ->  
        rule.getSearchTerm().match(message)) 
        .forEach(rule -> { 
          switch (rule.getType()) { 
            case MOVE: 
              moveMessage(message, getFolder( 
                rule.getDestFolder(),  
                Folder.READ_WRITE)); 
            break; 
            case DELETE: 
              deleteMessage(message); 
            break; 
          } 
      })); 
    } 

```

使用`Stream`，我们遍历源文件夹中的每条消息，过滤出只匹配`SearchTerm`的消息，但那是什么，它从哪里来？

`Rule`类上还有一些我们还没有看过的额外项目：

```java
    private SearchTerm term; 
    @JsonIgnore 
    public SearchTerm getSearchTerm() { 
      if (term == null) { 
        if (matchingText != null) { 
          List<SearchTerm> terms = fields.stream() 
          .map(f -> createFieldSearchTerm(f)) 
          .collect(Collectors.toList()); 
          term = new OrTerm(terms.toArray(new SearchTerm[0])); 
        } else if (olderThan != null) { 
          LocalDateTime day = LocalDateTime.now() 
          .minusDays(olderThan); 
          term = new SentDateTerm(ComparisonTerm.LE, 
            Date.from(day.toLocalDate().atStartOfDay() 
            .atZone(ZoneId.systemDefault()).toInstant())); 
        } 
      } 
      return term; 
    } 

```

我们添加了一个私有字段来缓存`SearchTerm`，这样我们就不必多次创建它。这是一个小的优化，但我们希望避免在大型文件夹上为每条消息重新创建`SearchTerm`而导致不必要的性能损失。如果规则设置了`matchingText`，我们将根据指定的字段创建一个`List<SearchTerm>`。一旦我们有了这个列表，我们就将它包装在`OrTerm`中，这将指示 JavaMail 在*任何*指定的字段与文本匹配时匹配消息。

如果设置了`olderThan`，那么我们创建`SentDateTerm`来匹配至少`olderThan`天前发送的任何消息。我们将`SearchTerm`引用保存在我们的私有实例变量中，然后返回它。

请注意，该方法具有`@JsonIgnore`注解。我们使用这个注解来确保 Jackson 不会尝试将此 getter 返回的值编组到 JSON 文件中。

对于好奇的人，`createFieldSearchTerm()`看起来像这样：

```java
    private SearchTerm createFieldSearchTerm(String f) { 
      switch (f.toLowerCase()) { 
        case "from": 
          return new FromStringTerm(matchingText); 
        case "cc": 
          return new RecipientStringTerm( 
            Message.RecipientType.CC, matchingText); 
        case "to": 
          return new RecipientStringTerm( 
            Message.RecipientType.TO, matchingText); 
        case "body": 
          return new BodyTerm(matchingText); 
        case "subject": 
          return new SubjectTerm(matchingText); 
        default: 
            return null; 
      } 
    } 

```

那么，消息实际上是如何移动或删除的呢？当然，JavaMail API 有一个用于此目的的 API，其使用可能看起来像这样：

```java
    private static final Flags FLAGS_DELETED =  
      new Flags(Flags.Flag.DELETED); 
    private void deleteMessage(Message toDelete) { 
      if (toDelete != null) { 
        try { 
          final Folder source = toDelete.getFolder(); 
          source.setFlags(new Message[]{toDelete},  
            FLAGS_DELETED, true); 
          deleteCount++; 
        } catch (MessagingException ex) { 
          throw new RuntimeException(ex); 
        } 
      } 
    } 

```

我们进行了一个快速的空值检查，然后我们获取了消息`Folder`的引用。有了这个引用，我们指示 JavaMail 在文件夹中的消息上设置一个`FLAGS_DELETED`标志。JavaMail API 更多地使用`Message`（`Message[]`）数组，所以我们需要将`Message`包装在数组中，然后将其传递给`setFlags()`。在完成时，我们增加了我们的已删除消息计数器，这样我们就可以在完成时打印我们的报告。

移动`Message`非常类似：

```java
    private void moveMessage(Message toMove, Folder dest) { 
      if (toMove != null) { 
        try { 
          final Folder source = toMove.getFolder(); 
          final Message[] messages = new Message[]{toMove}; 
          source.setFlags(messages, FLAGS_DELETED, true); 
          source.copyMessages(messages, dest); 
          moveCount++; 
        } catch (MessagingException ex) { 
          throw new RuntimeException(ex); 
        } 
      } 
    } 

```

这个方法的大部分看起来就像`deleteMessage()`，但有一个细微的区别。JavaMail 没有`moveMessages()`API。相反，我们需要调用`copyMessages()`来在目标文件夹中创建消息的副本，然后从源文件夹中删除消息。我们增加了移动计数器并返回。

感兴趣的最后两个方法处理文件夹。首先，我们需要获取文件夹，我们在这里这样做：

```java
    final private Map<String, Folder> folders = new HashMap<>(); 
    private Folder getFolder(String folderName, int mode) { 
      Folder source = null; 
      try { 
        if (folders.containsKey(folderName)) { 
          source = folders.get(folderName); 
        } else { 
          source = store.getFolder(folderName); 
          if (source == null || !source.exists()) { 
            throw new IllegalArgumentException( 
             "Invalid folder: " + folderName); 
          } 
          folders.put(folderName, source); 
        } 
        if (!source.isOpen()) { 
          source.open(mode); 
        } 
      } catch (MessagingException ex) { 
        //... 
      } 
      return source; 
    } 

```

出于性能原因，我们将每个“文件夹”实例缓存在`Map`中，以文件夹名称为键。如果我们在`Map`中找到“文件夹”，我们就使用它。如果没有，那么我们向 IMAP“存储”请求对所需的“文件夹”的引用，并将其缓存在`Map`中。最后，我们确保“文件夹”是打开的，否则我们的移动和删除命令将抛出异常。

当我们完成时，我们还需要确保关闭“文件夹”：

```java
    private void closeFolders() { 
      folders.values().stream() 
      .filter(f -> f.isOpen()) 
      .forEachOrdered(f -> { 
        try { 
          f.close(true); 
        } catch (MessagingException e) { 
        } 
      }); 
    } 

```

我们过滤我们的`Folder`流，只选择那些是打开的，然后调用`folder.close()`，忽略可能发生的任何失败。在处理的这一点上，没有太多可以做的。

我们的邮件过滤现在在技术上已经完成，但它并不像它本应该的那样可用。我们需要一种定期运行的方式，并且能够在 GUI 中查看和编辑规则将会非常好，所以我们将构建这两者。由于如果我们没有要运行的内容，安排某事就没有意义，所以我们将从 GUI 开始。

# 构建 GUI

由于我们希望尽可能地使其易于使用，我们现在将构建一个 GUI 来帮助管理这些规则。为了创建项目，我们将使用与创建 CLI 时相同的 Maven 原型：

```java
$ mvn archetype:generate \ -DarchetypeGroupId=org.apache.maven.archetypes \ -DarchetypeArtifactId=maven-archetype-quickstart \ -DarchetypeVersion=RELEASE 
Define value for property 'groupId': com.steeplesoft.mailfilter 
Define value for property 'artifactId': mailfilter-gui 
Define value for property 'version':  1.0-SNAPSHOT 
Define value for property 'package':  com.steeplesoft.mailfilter.gui 

```

一旦 POM 被创建，我们需要稍微编辑它。我们需要通过向`pom.xml`添加此元素来设置父级：

```java
    <parent> 
      <groupId>com.steeplesoft.j9bp.mailfilter</groupId> 
      <artifactId>mailfilter-master</artifactId> 
      <version>1.0-SNAPSHOT</version> 
    </parent> 

```

我们还将添加对 CLI 模块的依赖，如下所示：

```java
    <dependencies> 
      <dependency> 
        <groupId>${project.groupId}</groupId> 
        <artifactId>mailfilter-cli</artifactId> 
        <version>${project.version}</version> 
      </dependency> 
    </dependencies> 

```

由于我们不依赖 NetBeans 为我们生成 JavaFX 项目，我们还需要手动创建一些基本工件。让我们从应用程序的入口点开始：

```java
    public class MailFilter extends Application { 
      @Override 
      public void start(Stage stage) throws Exception { 
        Parent root = FXMLLoader.load(getClass() 
        .getResource("/fxml/mailfilter.fxml")); 
        Scene scene = new Scene(root); 
        stage.setTitle("MailFilter"); 
        stage.setScene(scene); 
        stage.show(); 
      } 

      public static void main(String[] args) { 
        launch(args); 
      } 
    } 

```

这是一个非常典型的 JavaFX 主类，所以我们将直接跳到 FXML 文件。现在，我们将使用以下代码创建一个存根：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <?import java.lang.*?> 
    <?import java.util.*?> 
    <?import javafx.scene.*?> 
    <?import javafx.scene.control.*?> 
    <?import javafx.scene.layout.*?> 

    <AnchorPane id="AnchorPane" prefHeight="200" prefWidth="320"  

      fx:controller= 
        "com.steeplesoft.mailfilter.gui.Controller"> 
      <children> 
        <Button layoutX="126" layoutY="90" text="Click Me!"  
          fx:id="button" /> 
        <Label layoutX="126" layoutY="120" minHeight="16"  
          minWidth="69" fx:id="label" /> 
      </children> 
    </AnchorPane> 

```

最后，我们创建控制器：

```java
    public class Controller implements Initializable { 
      @Override 
      public void initialize(URL url, ResourceBundle rb) { 
      } 
    } 

```

这给了我们一个可以启动和运行的 JavaFX 应用程序，但没有做其他太多事情。在之前的章节中，我们已经详细介绍了构建 JavaFX 应用程序，所以我们不会在这里再次重复，但是在这个应用程序中有一些有趣的挑战值得一看。

为了让您了解我们正在努力的方向，这是最终用户界面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/e6217bcf-fb27-4bc2-b84c-dbba3296e5d9.png)

在左侧，我们有`ListView`来显示规则文件中配置的`Account`。在`ListView`下方，我们有一些控件来编辑当前选定的`Account`。在右侧，我们有`TableView`来显示`Rule`，以及其下方类似的区域来编辑`Rule`。

当用户点击`Account`或`Rule`时，我们希望下方的表单区域填充相关信息。当用户修改数据时，`Account`/`Rule`以及`ListView`/`TableView`应该被更新。

通常，这是 JavaFX 真正擅长的领域之一，即属性绑定。我们已经在`ObservableList`中看到了一小部分：我们可以向`List`中添加项目，它会自动添加到已绑定的 UI 组件中。但是，我们现在所处的情况有点不同，因为我们的模型是一个 POJO，它不使用任何 JavaFX API，所以我们不会轻易获得该功能。让我们看看将这些东西连接在一起需要做些什么。

首先，让我们看一下`Account`列表。我们有`ObservableList`：

```java
    private final ObservableList<Account> accounts =  
      FXCollections.observableArrayList(); 

```

我们将我们的账户添加到这个`ObservableList`中，如下所示：

```java
    private void configureAccountsListView() { 
      accountService = new AccountService(); 
      accounts.addAll(accountService.getAccounts()); 

```

然后，我们绑定`List`和`ListView`，如下所示：

```java
    accountsListView.setItems(accounts); 

```

这里有一点变化。为了封装我们的 POJO 绑定设置，我们将创建一个名为`AccountProperty`的新类，我们很快会看到。尽管，让我们首先添加以下代码片段来处理`ListView`的点击：

```java
    accountProperty = new AccountProperty(); 
    accountsListView.setOnMouseClicked(e -> { 
      final Account account = accountsListView.getSelectionModel() 
      .getSelectedItem(); 
      if (account != null) { 
        accountProperty.set(account); 
      } 
    }); 

```

当用户点击`ListView`时，我们在`AccountProperty`实例上设置`Account`。在离开这个方法并查看`AccountProperty`之前，我们需要设置最后一个项目：

```java
    final ChangeListener<String> accountChangeListener =  
      (observable, oldValue, newValue) ->  
      accountsListView.refresh(); 
    serverName.textProperty().addListener(accountChangeListener); 
    userName.textProperty().addListener(accountChangeListener); 

```

我们定义了`ChangeListener`，它简单地调用`accountsListView.refresh()`，这指示`ListView`重新绘制自身。当模型本身更新时，我们希望它这样做，这是`ObservableList`不会向`ListView`冒泡的变化。接下来的两行将`Listener`添加到`serverName`和`userName`的`TextField`。这两个控件编辑`Account`上同名的属性，并且是用于生成`ListView`显示字符串的唯一两个控件，这里我们不展示。

`AccountProperty`是一个自定义的 JavaFX 属性，所以我们扩展`ObjectPropertyBase`如下：

```java
    private class AccountProperty extends ObjectPropertyBase<Account> { 

```

这提供了绑定解决方案的一部分，但繁重的工作由 JFXtras 项目的一个类`BeanPathAdapter`处理：

```java
    private final BeanPathAdapter<Account> pathAdapter; 

```

截至撰写本书时，JFXtras 库尚不兼容 Java 9。我们只需要这个库的一个类，所以我暂时将该类的源代码从 JFXtras 存储库复制到了这个项目中。一旦 JFXtras 在 Java 9 下运行，我们就可以删除这个副本。

文档将这个类描述为一个“适配器，它接受一个 POJO bean，并在内部和递归地将其字段绑定/解绑到其他`Property`组件”。这是一个非常强大的类，我们无法在这里完全覆盖它，所以我们将直接跳到我们的特定用法，如下所示：

```java
    public AccountProperty() { 
        pathAdapter = new BeanPathAdapter<>(new Account()); 
        pathAdapter.bindBidirectional("serverName",  
            serverName.textProperty()); 
        pathAdapter.bindBidirectional("serverPort",  
            serverPort.textProperty()); 
        pathAdapter.bindBidirectional("useSsl",  
            useSsl.selectedProperty(), Boolean.class); 
        pathAdapter.bindBidirectional("userName",  
            userName.textProperty()); 
        pathAdapter.bindBidirectional("password",  
            password.textProperty()); 
        addListener((observable, oldValue, newValue) -> { 
            rules.setAll(newValue.getRules()); 
        }); 
    } 

```

`BeanPathAdapter`允许我们将 JavaFX`Property`绑定到 POJO 上的属性，这些属性可以嵌套到任意深度，并使用点分隔路径表示。在我们的情况下，这些属性是`Account`对象上的顶级属性，因此路径是简短而简单的。在我们将控件绑定到属性之后，我们添加了一个`Listener`来使用`Rule`更新`ObservableList`规则。

在前面的代码中，当`ListView`中的`Account`选择发生变化时调用的`set()`方法非常简单：

```java
    @Override 
    public void set(Account newValue) { 
      pathAdapter.setBean(newValue); 
      super.set(newValue); 
    } 

```

有了这些部分，`Account`对象在我们在各种控件中输入时得到更新，`ListView`标签在编辑`serverName`和/或`userName`字段时得到更新。

现在我们需要为将显示用户配置的每个`Rule`的`TableView`做同样的事情。设置几乎相同：

```java
    private void configureRuleFields() { 
        ruleProperty = new RuleProperty(); 
        fields.getCheckModel().getCheckedItems().addListener( 
          new RuleFieldChangeListener()); 
        final ChangeListener<Object> ruleChangeListener =  
            (observable, oldValue, newValue) ->  
                rulesTableView.refresh(); 
        sourceFolder.textProperty() 
           .addListener(ruleChangeListener); 
        destFolder.textProperty().addListener(ruleChangeListener); 
        matchingText.textProperty() 
            .addListener(ruleChangeListener); 
        age.textProperty().addListener(ruleChangeListener); 
        type.getSelectionModel().selectedIndexProperty() 
            .addListener(ruleChangeListener); 
    } 

```

在这里，我们看到了相同的基本结构：实例化`RuleProperty`，创建`ChangeListener`来请求`TableView`刷新自身，并将该监听器添加到相关的表单字段。

`RuleProperty`也类似于`AccountProperty`：

```java
    private class RuleProperty extends ObjectPropertyBase<Rule> { 
      private final BeanPathAdapter<Rule> pathAdapter; 

      public RuleProperty() { 
        pathAdapter = new BeanPathAdapter<>(new Rule()); 
        pathAdapter.bindBidirectional("sourceFolder",  
          sourceFolder.textProperty()); 
        pathAdapter.bindBidirectional("destFolder",  
          destFolder.textProperty()); 
        pathAdapter.bindBidirectional("olderThan",  
          age.textProperty()); 
        pathAdapter.bindBidirectional("matchingText",  
          matchingText.textProperty()); 
        pathAdapter.bindBidirectional("type",  
          type.valueProperty(), String.class); 
        addListener((observable, oldValue, newValue) -> { 
          isSelectingNewRule = true; 
          type.getSelectionModel().select(type.getItems() 
          .indexOf(newValue.getType().name())); 

          IndexedCheckModel checkModel = fields.getCheckModel(); 
          checkModel.clearChecks(); 
          newValue.getFields().forEach((field) -> { 
            checkModel.check(checkModel.getItemIndex(field)); 
          }); 
          isSelectingNewRule = false; 
      }); 
    } 

```

这里最大的区别是创建的`Listener`。考虑到使用了来自 ControlsFX 项目的自定义控件`CheckListView`，值得注意的是逻辑：我们获取`IndexedCheckModel`，然后清除它，然后我们遍历每个字段，在`CheckModel`中找到其索引并进行检查。

我们通过`RuleFieldChangeListener`控制更新`Rule`上设置的字段值：

```java
    private class RuleFieldChangeListener implements ListChangeListener { 
      @Override 
      public void onChanged(ListChangeListener.Change c) { 
        if (!isSelectingNewRule && c.next()) { 
          final Rule bean = ruleProperty.getBean(); 
          bean.getFields().removeAll(c.getRemoved()); 
          bean.getFields().addAll(c.getAddedSubList()); 
        } 
      } 
    } 

```

`ListChangeListener`告诉我们移除了什么和添加了什么，所以我们相应地进行了处理。

GUI 还有其他几个移动部分，但我们在之前的章节中已经看到了它们的一个或另一个，所以我们在这里不再介绍它们。如果您对这些细节感兴趣，可以在本书的源代码存储库中找到它们。让我们把注意力转向我们项目的最后一部分：特定于操作系统的服务。

# 构建服务

这个项目的一个明确目标是能够定义规则来管理和过滤电子邮件，并且在大多数时间内运行，而不仅仅是在电子邮件客户端运行时。 （当然，我们无法控制运行此项目的机器被关闭，所以我们不能保证持续覆盖）。为了实现这一承诺的一部分，我们需要一些额外的部分。我们已经有了执行实际工作的系统部分，但我们还需要一种在计划中运行该部分的方法，还需要一个启动计划作业的部分。

对于调度方面，我们有许多选择，但我们将使用一个名为 Quartz 的库。Quartz 作业调度库是一个开源库，可以在 Java SE 和 Java EE 应用程序中使用。它提供了一个干净简单的 API，非常适合在这里使用。要将 Quartz 添加到我们的项目中，我们需要在`pom.xml`中进行如下操作：

```java
    <dependency> 
      <groupId>org.quartz-scheduler</groupId> 
      <artifactId>quartz</artifactId> 
      <version>2.2.3</version> 
    </dependency> 

```

API 有多简单呢？这是我们的`Job`定义：

```java
    public class MailFilterJob implements Job { 
      @Override 
      public void execute(JobExecutionContext jec)  
        throws JobExecutionException { 
        MailFilter filter = new MailFilter(); 
        filter.run(); 
      } 
    } 

```

我们扩展了`org.quartz.Job`，重写了`execute()`方法，在其中我们只是实例化了`MailFilter`并调用了`run()`。就是这么简单。定义了我们的任务之后，我们只需要安排它的执行，这将在`MailFilterService`中完成：

```java
    public class MailFilterService { 
      public static void main(String[] args) { 
        try { 
          final Scheduler scheduler =  
            StdSchedulerFactory.getDefaultScheduler(); 
          scheduler.start(); 

          final JobDetail job =  
            JobBuilder.newJob(MailFilterJob.class).build(); 
          final Trigger trigger = TriggerBuilder.newTrigger() 
          .startNow() 
          .withSchedule( 
             SimpleScheduleBuilder.simpleSchedule() 
             .withIntervalInMinutes(15) 
             .repeatForever()) 
          .build(); 
          scheduler.scheduleJob(job, trigger); 
        } catch (SchedulerException ex) { 
          Logger.getLogger(MailFilterService.class.getName()) 
          .log(Level.SEVERE, null, ex); 
        } 
      } 
    } 

```

我们首先获取对默认`Scheduler`的引用并启动它。接下来，我们使用`JobBuilder`创建一个新的任务，然后使用`TriggerBuilder`构建`Trigger`。我们告诉`Trigger`立即开始执行，但请注意，直到它实际构建并分配给`Scheduler`之前，它不会开始执行。一旦发生这种情况，`Job`将立即执行。最后，我们使用`SimpleScheduleBuilder`辅助类为`Trigger`定义`Schedule`，指定每 15 分钟运行一次，将永远运行。我们希望它在计算机关闭或服务停止之前一直运行。

如果现在运行/调试`MailFilterService`，我们可以观察`MailFilter`的运行。如果你这样做，而且你不是非常有耐心的话，我建议你将间隔时间降低到更合理的水平。

这让我们还有最后一件事：操作系统集成。简而言之，我们希望能够在操作系统启动时运行`MailFilterService`。理想情况下，我们希望不需要临时脚本来实现这一点。幸运的是，我们又有了许多选择。

我们将使用 Tanuki Software 的出色的 Java Service Wrapper 库（详情请参阅[`wrapper.tanukisoftware.com`](https://wrapper.tanukisoftware.com/)）。虽然我们可以手动构建服务工件，但我们更愿意让我们的构建工具为我们完成这项工作，当然，有一个名为`appassembler-maven-plugin`的 Maven 插件可以做到这一点。为了将它们整合到我们的项目中，我们需要修改 POM 文件的`build`部分，添加以下代码片段：

```java
    <build> 
      <plugins> 
        <plugin> 
          <groupId>org.codehaus.mojo</groupId> 
          <artifactId>appassembler-maven-plugin</artifactId> 
          <version>2.0.0</version> 

```

这个插件的传递依赖项将引入我们需要的一切 Java Service Wrapper，所以我们只需要配置我们的使用方式。我们首先添加一个执行，告诉 Maven 在打包项目时运行`generate-daemons`目标：

```java
    <executions> 
      <execution> 
        <id>generate-jsw-scripts</id> 
        <phase>package</phase> 
        <goals> 
          <goal>generate-daemons</goal> 
        </goals> 

```

接下来，我们需要配置插件，这可以通过`configuration`元素来实现：

```java
    <configuration> 
      <repositoryLayout>flat</repositoryLayout> 

```

`repositoryLayout`选项告诉插件构建一个**lib**风格的存储库，而不是 Maven 2 风格的布局，后者是一些嵌套目录。至少对于我们在这里的目的来说，这主要是一个样式问题，但我发现能够扫描生成的目录并一目了然地看到包含了什么是很有帮助的。

接下来，我们需要按照以下方式定义**守护进程**（来自 Unix 世界的另一个表示操作系统服务的术语，代表**磁盘和执行监视器**）：

```java
    <daemons> 
      <daemon> 
        <id>mailfilter-service</id> 
        <wrapperMainClass> 
          org.tanukisoftware.wrapper.WrapperSimpleApp 
        </wrapperMainClass> 
        <mainClass> 
         com.steeplesoft.mailfilter.service.MailFilterService 
        </mainClass> 
        <commandLineArguments> 
          <commandLineArgument>start</commandLineArgument> 
        </commandLineArguments> 

```

Java Service Wrapper 是一个非常灵活的系统，提供了多种包装 Java 项目的方式。我们的需求很简单，所以我们指示它使用`WrapperSimpleApp`，并指向主类`MailFilterService`。

该插件支持其他几种服务包装方法，但我们对 Java Service Wrapper 感兴趣，因此在这里我们使用`platform`元素来指定：

```java
        <platforms> 
          <platform>jsw</platform> 
        </platforms> 

```

最后，我们需要配置生成器，告诉它支持哪个操作系统：

```java
        <generatorConfigurations> 
          <generatorConfiguration> 
            <generator>jsw</generator> 
            <includes> 
              <include>linux-x86-64</include> 
              <include>macosx-universal-64</include> 
              <include>windows-x86-64</include> 
            </includes> 
          </generatorConfiguration> 
        </generatorConfigurations> 
      </daemon> 
    </daemons> 

```

每个操作系统定义都提供了一个 32 位选项，如果需要的话可以添加，但为了简洁起见，我在这里省略了它们。

现在构建应用程序，无论是通过`mvn package`还是`mvn install`，这个插件都会为我们的服务生成一个包装器，其中包含适用于配置的操作系统的二进制文件。好处是，它将为每个操作系统构建包装器，而不管实际运行构建的操作系统是什么。例如，这是在 Windows 机器上构建的输出（请注意 Linux 和 Mac 的二进制文件）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/fa36d256-0b22-4cf4-bf7f-7356b2448c3d.png)

包装器还可以做得更多，所以如果你感兴趣，可以在 Tanuki Software 的网站上阅读所有细节。

# 总结

就像这样，我们的应用程序又**完成**了。在本章中，我们涵盖了相当多的内容。我们首先学习了一些关于几种电子邮件协议（SMTP、POP3 和 IMAP4）的历史和技术细节，然后学习了如何使用 JavaMail API 与基于这些协议的服务进行交互。在这个过程中，我们发现了 Jackson JSON 解析器，并使用它来将 POJO 从磁盘转换为 POJO，并从磁盘转换为 POJO。我们使用了 ControlsFX 类`BeanPathAdapter`，将非 JavaFX 感知的 POJO 绑定到 JavaFX 控件，以及 Quartz 作业调度库来按计划执行代码。最后，我们使用 Java Service Wrapper 来创建安装工件，完成了我们的应用程序。

我希望我们留下的应用程序既有趣又有帮助。当然，如果你感到有动力，还有几种方法可以改进它。账户/规则数据结构可以扩展，以允许定义跨账户共享的全局规则。GUI 可以支持在账户的文件夹中查看电子邮件，并根据实时数据生成规则。构建可以扩展为创建应用程序的安装程序。你可能还能想到更多。随时随地查看代码并进行修改。如果你想到了有趣的东西，一定要分享出来，因为我很想看看你做了什么。

完成另一个项目（不是故意的），我们准备把注意力转向另一个项目。在下一章中，我们将在 GUI 中花费全部时间，构建一个照片管理系统。这将让我们有机会了解一些 JDK 的图像处理能力，包括新增的 TIFF 支持，这个功能应该会让图像爱好者非常高兴。翻页，让我们开始吧！
