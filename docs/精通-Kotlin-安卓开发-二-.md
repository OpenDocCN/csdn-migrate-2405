# 精通 Kotlin 安卓开发（二）

> 原文：[`zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5`](https://zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：连接屏幕流

你好，亲爱的读者！我们已经来到了我们应用程序开发中的一个重要点——连接我们的屏幕。正如你所知，我们在上一章中创建了屏幕，在本章中，我们将使用 Android 强大的框架来连接它们。我们将继续我们的工作，并且，通过 Android，我们将在 UI 方面做更严肃的事情。准备好自己，专注于本章的每个方面。这将非常有趣！我们保证！

在本章中，我们将涵盖以下主题：

+   创建应用程序栏

+   使用抽屉导航

+   Android 意图

+   在活动和片段之间传递信息

# 创建应用程序栏

我们正在继续我们的 Android 应用程序开发之旅。到目前为止，我们已经为我们的应用程序创建了一个基础，为 UI 定义了基础，并创建了主要屏幕；然而，这些屏幕并没有连接。在本章中，我们将连接它们并进行精彩的交互。

由于一切都始于我们的`MainActivity`类，所以在我们设置一些操作来触发其他屏幕之前，我们将进行一些改进。我们必须用应用程序栏*包装*它。什么是应用程序栏？它是用于访问应用程序的其他部分并提供具有交互元素的视觉结构的 UI 部分。我们已经有一个，但它不是通常的 Android 应用程序栏。在这一点上，我们的应用程序有一个修改过的应用程序栏，我们希望它有一个标准的 Android 应用程序栏。

在这里，我们将向您展示如何创建一个。

首先，将顶级活动扩展替换为`AppCompatActivity`。我们需要访问应用程序栏所需的功能。`AppCompatActivity`将为标准的`FragmentActivity`添加这些额外的功能。您的`BaseActivity`定义现在应该如下所示：

```kt
    abstract class BaseActivity : AppCompatActivity() {   
    ... 
```

然后更新所使用的主题应用程序，以便可以使用应用程序栏。打开 Android 清单并设置一个新主题如下：

```kt
    ... 
    <application 
      android:name=".Journaler" 
      android:allowBackup="false" 
      android:icon="@mipmap/ic_launcher" 
      android:label="@string/app_name" 
      android:roundIcon="@mipmap/ic_launcher_round" 
      android:supportsRtl="true" 
      android:theme="@style/Theme.AppCompat.Light.NoActionBar"> 
    ... 
```

现在打开你的`activity_main`布局。删除包含的页眉指令并添加`Toolbar`：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
     "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical"> 

    <android.support.v7.widget.Toolbar 
      android:id="@+id/toolbar" 
      android:layout_width="match_parent" 
      android:layout_height="50dp" 
      android:background="@color/colorPrimary" 
      android:elevation="4dp" /> 

    <android.support.v4.view.ViewPager  
      android:id="@+id/pager" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" /> 

    </LinearLayout> 

```

对所有布局应用相同的更改。完成后，更新您的`BaseActivity`代码以使用新的`Toolbar`。您的`onCreate()`方法现在应该如下所示：

```kt
    override fun onCreate(savedInstanceState: Bundle?) { 
      super.onCreate(savedInstanceState) 
      setContentView(getLayout()) 
      setSupportActionBar(toolbar)        
    Log.v(tag, "[ ON CREATE ]") 
    } 
```

通过调用`setSupportActionBar()`方法并传递布局中工具栏的 ID，我们分配了一个应用程序栏。如果您运行应用程序，它将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/89c17146-6ab6-4d9a-b96b-918002b179c1.png)

我们失去了我们在页眉中拥有的按钮！别担心，我们会把它们拿回来的！我们将创建一个菜单来处理操作，而不是按钮。在 Android 中，菜单是用于管理项目的接口，您可以定义自己的菜单资源。在`/res`目录中，创建一个`menu`文件夹。右键单击`menu`文件夹，然后选择 New | New menu resource file。将其命名为 main。一个新的 XML 文件将打开。根据这个示例更新它的内容：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <menu  
    > 

    <item 
      app:showAsAction="ifRoom" 
      android:orderInCategory="1" 
      android:id="@+id/drawing_menu" 
      android:icon="@android:drawable/ic_dialog_dialer" 
      android:title="@string/mnu" /> 

    <item 
      app:showAsAction="ifRoom" 
      android:orderInCategory="2" 
      android:id="@+id/options_menu" 
      android:icon="@android:drawable/arrow_down_float" 
      android:title="@string/mnu" /> 
    </menu>
```

我们设置了常见属性、图标和顺序。为了确保您的图标可见，请使用以下内容：

```kt
    app:showAsAction="ifRoom" 
```

通过这样做，如果有空间可用，菜单中的项目将被展开；否则，它们将通过上下文菜单访问。您可以选择的 Android 中的其他间距选项如下：

+   **始终**：此按钮始终放在应用程序栏中

+   **从不**：此按钮永远不会放在应用程序栏中

+   **collapseAction View**：此按钮可以显示为小部件

+   **withText**：此按钮显示为文本

要将菜单分配给应用程序栏，请在`BaseActivity`中添加以下内容：

```kt
    override fun onCreateOptionsMenu(menu: Menu): Boolean { 
      menuInflater.inflate(R.menu.main, menu) 

      return true 
    } 
```

最后，通过添加以下代码来将操作连接到菜单项并扩展`MainActivity`：

```kt
    override fun onOptionsItemSelected(item: MenuItem): Boolean { 
      when (item.itemId) { 
        R.id.drawing_menu -> { 
          Log.v(tag, "Main menu.") 
          return true 
        } 
        R.id.options_menu -> { 
          Log.v(tag, "Options menu.") 
          return true 
        } 
        else -> return super.onOptionsItemSelected(item) 

     } 

    } 
```

在这里，我们重写了`onOptionsItemSelected()`方法，并处理了菜单项 ID 的情况。在每次选择时，我们都添加了一个日志消息。现在运行你的应用程序。你应该会看到这些菜单项：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/a64c25e9-44f3-42c1-af22-a949c77deb86.png)

点击每个项目几次并观察 Logcat。你应该看到类似于这样的日志：

```kt
    V/Main activity: Main menu. 
    V/Main activity: Options menu. 
    V/Main activity: Options menu. 
    V/Main activity: Options menu. 

    V/Main activity: Main menu. 

    V/Main activity: Main menu. 
```

我们成功地将我们的标题切换到应用程序栏。这与应用程序线框中的标题非常不同。这一点目前并不重要，因为我们将在接下来的章节中进行一些重要的样式设置。我们的应用程序栏将看起来不同。

在接下来的部分，我们将处理导航抽屉，并开始组装我们应用程序的导航。

# 使用导航抽屉

你可能还记得，在我们的模型中，我们已经提出将有链接到过滤数据（笔记和待办事项）的功能。我们将使用导航抽屉来进行过滤。每个现代应用程序都使用导航抽屉。这是一个显示应用程序导航选项的 UI 部分。要定义抽屉，我们必须在布局中放置`DrawerLayout`视图。打开`activity_main`并应用以下修改：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <android.support.v4.widget.DrawerLayout    xmlns:android=
    "http://schemas.android.com/apk/res/android" 
     android:id="@+id/drawer_layout" 
     android:layout_width="match_parent" 
     android:layout_height="match_parent"> 

    <LinearLayout 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:orientation="vertical"> 

    <android.support.v7.widget.Toolbar 
      android:id="@+id/toolbar" 
      android:layout_width="match_parent" 
      android:layout_height="50dp" 
      android:background="@color/colorPrimary" 
      android:elevation="4dp" /> 

    <android.support.v4.view.ViewPager xmlns:android=
    "http://schemas.android.com/apk/res/android" 
      android:id="@+id/pager" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" /> 

    </LinearLayout> 

    <ListView 
       android:id="@+id/left_drawer" 
       android:layout_width="240dp" 
       android:layout_height="match_parent" 
       android:layout_gravity="start" 
       android:background="@android:color/darker_gray" 
       android:choiceMode="singleChoice" 
       android:divider="@android:color/transparent" 
       android:dividerHeight="1dp" /> 
    </android.support.v4.widget.DrawerLayout>  
```

屏幕的主要内容必须是`DrawerLayout`的第一个子项。导航抽屉使用第二个子项作为抽屉的内容。在我们的情况下，它是`ListView`。要告诉导航抽屉导航是否应该位于左侧还是右侧，使用`layout_gravity`属性。如果我们计划使用导航抽屉位于右侧，我们应该将属性值设置为`end`。

现在我们有一个空的导航抽屉，我们必须用一些按钮填充它。为每个导航项创建一个新的布局文件。将其命名为`adapter_navigation_drawer`。将其定义为一个只有一个按钮的简单线性布局：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
    "http://schemas.android.com/apk/res/android" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:orientation="vertical"> 

    <Button 
      android:id="@+id/drawer_item" 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" /> 

    </LinearLayout> 
```

然后，创建一个名为`navigation`的新包。在这个包中，创建一个新的 Kotlin`data`类，就像这样：

```kt
    package com.journaler.navigation 
    data class NavigationDrawerItem( 
      val title: String,        
      val onClick: Runnable 
    ) 
```

我们定义了一个抽屉项实体。现在再创建一个类：

```kt
    class NavigationDrawerAdapter( 
        val ctx: Context, 
        val items: List<NavigationDrawerItem> 
    ) : BaseAdapter() { 

    override fun getView(position: Int, v: View?, group: ViewGroup?):   
    View { 
      val inflater = LayoutInflater.from(ctx) 
      var view = v 
      if (view == null) { 
        view = inflater.inflate( 
          R.layout.adapter_navigation_drawer, null 
        ) as LinearLayout 
      } 

      val item = items[position] 
      val title = view.findViewById<Button>(R.id.drawer_item) 
      title.text = item.title 
      title.setOnClickListener { 
        item.onClick.run() 
      } 

      return view 
     } 

     override fun getItem(position: Int): Any { 
       return items[position] 
      } 

     override fun getItemId(position: Int): Long { 
       return 0L 
     } 

     override fun getCount(): Int {     
     return items.size 
     } 

    } 
```

这个类在这里扩展了 Android 的`BaseAdapter`并重写了适配器提供视图实例所需的方法。适配器创建的所有视图都将分配给我们导航抽屉中的`ListView`。

最后，我们将分配这个适配器。为此，我们需要通过执行以下代码更新我们的`MainActivity`类：

```kt
    class MainActivity : BaseActivity() { 
    ... 
    override fun onCreate(savedInstanceState: Bundle?) { 
      super.onCreate(savedInstanceState) 
      pager.adapter = ViewPagerAdapter(supportFragmentManager) 

      val menuItems = mutableListOf<NavigationDrawerItem>() 
      val today = NavigationDrawerItem( 
        getString(R.string.today), 
          Runnable { 
            pager.setCurrentItem(0, true) 
          } 
        ) 

        val next7Days = NavigationDrawerItem( 
           getString(R.string.next_seven_days), 
             Runnable { 
               pager.setCurrentItem(1, true) 
             } 
         ) 

         val todos = NavigationDrawerItem( 
           getString(R.string.todos), 
             Runnable { 
               pager.setCurrentItem(2, true) 
             } 
         ) 

         val notes = NavigationDrawerItem( 
           getString(R.string.notes), 
             Runnable { 
               pager.setCurrentItem(3, true) 
             } 
        ) 

        menuItems.add(today) 
        menuItems.add(next7Days) 
        menuItems.add(todos) 
        menuItems.add(notes) 

        val navgationDraweAdapter = 
          NavigationDrawerAdapter(this, menuItems) 
        left_drawer.adapter = navgationDraweAdapter 
      } 
      override fun onOptionsItemSelected(item: MenuItem): Boolean { 
        when (item.itemId) { 
          R.id.drawing_menu -> { 
            drawer_layout.openDrawer(GravityCompat.START) 
            return true 
          } 
          R.id.options_menu -> { 
             Log.v(tag, "Options menu.") 
             return true 
          } 
          else -> return super.onOptionsItemSelected(item) 
        }      
      }  
    }  
```

在这个代码示例中，我们实例化了几个`NavigationDrawerItem`实例，然后，我们为按钮和我们将执行的`Runnable`操作分配了一个标题。每个`Runnable`将跳转到我们视图页面的特定页面。我们将所有实例作为一个单一的可变列表传递给适配器。您可能还注意到，我们更改了`drawing_menu`项的行。通过点击它，我们将展开我们的导航抽屉。请按照以下步骤操作：

1.  构建你的应用程序并运行它。

1.  点击主屏幕右上方的菜单按钮或通过从屏幕的最左侧向右滑动来展开导航抽屉。

1.  点击按钮。

1.  你会注意到视图页面在导航抽屉下方的页面位置正在进行动画。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/ec3eed2d-ebf3-4377-90f5-f07682c6b54e.png)

# 连接活动

如你所记得的，除了`MainActivity`之外，我们还有一些其他活动。在我们的应用程序中，我们创建了用于创建/编辑笔记和待办事项的活动。我们的计划是将它们连接到按钮点击事件，然后，当用户点击按钮时，适当的屏幕将打开。我们将首先定义一个代表在打开的活动中执行的操作的`enum`。当我们打开它时，我们可以查看、创建或更新笔记或待办事项。创建一个名为`model`和`enum`的新包，名称为`MODE`。确保你有以下`enum`值：

```kt
    enum class MODE(val mode: Int) { 
      CREATE(0), 
      EDIT(1), 
      VIEW(2); 

      companion object { 
        val EXTRAS_KEY = "MODE" 

        fun getByValue(value: Int): MODE { 
          values().forEach { 
            item -> 

            if (item.mode == value) { 
              return item 
            } 
          } 
          return VIEW 
        } 
      }  
    } 
```

我们在这里添加了一些附加内容。在`enum`的伴随对象中，我们定义了额外键的定义。很快，你会需要它，并且你会理解它的目的。我们还创建了一个方法，它将根据其值给我们一个`enum`。

你可能还记得，用于处理笔记和待办事项的两个活动共享相同的类。打开`ItemActivity`并按以下方式扩展它：

```kt
     abstract class ItemActivity : BaseActivity() { 
       protected var mode = MODE.VIEW 
       override fun getActivityTitle() = R.string.app_name 
       override fun onCreate(savedInstanceState: Bundle?) { 
         super.onCreate(savedInstanceState) 
         val modeToSet = intent.getIntExtra(MODE.EXTRAS_KEY, 
         MODE.VIEW.mode) 
         mode = MODE.getByValue(modeToSet) 
         Log.v(tag, "Mode [ $mode ]") 
       } 
     }  
```

我们引入了一个刚定义的类型字段，它将告诉我们是否正在查看、创建或编辑一个 Note 或 Todo 项目。然后，我们重写了`onCreate()`方法。这很重要！当我们单击按钮并打开活动时，我们将向其传递一些值。此代码片段检索我们传递的值。为了实现这一点，我们访问`Intent`实例（在下一节中，我们将解释“意图”）和称为`MODE`的整数字段（`MODE.EXTRAS_KEY`的值）。给我们这个值的方法叫做`getIntExtra()`。对于每种类型都有一个方法的版本。如果没有值，将返回`MODE.VIEW.mode`。最后，我们将模式设置为我们通过从整数值获取`MODE`实例获得的值。

拼图的最后一块是触发活动打开。打开`ItemsFragment`并扩展如下：

```kt
    class ItemsFragment : BaseFragment() { 
      ... 
      override fun onCreateView( 
        inflater: LayoutInflater?, 
        container: ViewGroup?, 
        savedInstanceState: Bundle? 
      ): View? {         
          val view = inflater?.inflate(getLayout(), container, false) 
          val btn = view?.findViewById<FloatingActionButton>
          (R.id.new_item) 
          btn?.setOnClickListener { 
            val items = arrayOf( 
              getString(R.string.todos), 
              getString(R.string.notes) 
            ) 
            val builder = 
            AlertDialog.Builder(this@ItemsFragment.context) 
            .setTitle(R.string.choose_a_type) 
            .setItems( 
              items, 
              { _, which -> 
               when (which) { 
               0 -> { 
                 openCreateTodo() 
               } 
               1 -> { 
                 openCreateNote() 
               } 
               else -> Log.e(logTag, "Unknown option selected 
               [ $which ]") 
                } 
               } 
             ) 

            builder.show() 
          } 

          return view 
       } 

      private fun openCreateNote() { 
        val intent = Intent(context, NoteActivity::class.java) 
        intent.putExtra(MODE.EXTRAS_KEY, MODE.CREATE.mode) 
        startActivity(intent) 
      } 

      private fun openCreateTodo() { 
        val intent = Intent(context, TodoActivity::class.java) 
        intent.putExtra(MODE.EXTRAS_KEY, MODE.CREATE.mode) 
        startActivity(intent) 

      } 

     } 
```

我们访问了`FloatingActionButton`实例并分配了一个点击侦听器。单击时，我们将创建一个带有两个选项的对话框。这些选项中的每一个都将触发适当的活动打开方法。这两种方法的实现非常相似。例如，我们将专注于`openCreateNote()`。

我们将创建一个新的`Intent`实例。在 Android 中，`Intent`表示我们要做某事的意图。要启动一个活动，我们必须传递上下文和我们想要启动的活动的类。我们还必须为其分配一些值。这些值将传递给一个活动实例。在我们的情况下，我们正在传递`MODE.CREATE`的整数值。`startActivity()`方法将执行意图，屏幕将出现。

运行应用程序，单击屏幕右下角的圆形按钮，并从对话框中选择一个选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/86fa1e85-d1dd-4447-a404-b8a44219ebd4.png)

这将带您到这个屏幕：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e57f3569-ed85-4e67-a7fe-3396fc51415a.png)

这将进一步带您添加您自己的数据与日期和时间：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/35e3969d-bb6c-433e-bac1-9314a656490a.png)

# 深入了解 Android 意图

在 Android 中，您计划执行的大多数操作都是通过`Intent`类定义的。`Intent`可用于启动活动，启动服务（在后台运行的进程）或发送广播消息。

`Intent`通常接受我们想要传递给某个类的操作和数据。我们可以设置的操作属性包括`ACTION_VIEW`、`ACTION_EDIT`、`ACTION_MAIN`等。

除了操作和数据，我们还可以为意图设置一个类别。类别为我们设置的操作提供了额外的信息。我们还可以为意图设置类型和组件，该组件代表我们将使用的显式组件类名。

有两种类型的“意图”：

+   显式意图

+   隐式意图

显式意图设置了一个显式组件，提供了一个要运行的显式类。隐式意图没有显式组件，但系统根据我们分配的数据和属性决定如何处理它。意图解析过程负责处理这样的“意图”。

这些参数的组合是无穷无尽的。我们将给出一些例子，这样你就可以更好地理解“意图”的目的：

+   打开网页：

```kt
         val intent = Intent(Intent.ACTION_VIEW,
         Uri.parse("http://google.com")) 
         startActivity(intent) 
         Sharing: 
         val intent = Intent(Intent.ACTION_SEND) 
         intent.type = "text/plain" 
         intent.putExtra(Intent.EXTRA_TEXT, "Check out this cool app!") 
         startActivity(intent)  
```

+   从相机中捕获图像：

```kt
        val takePicture = Intent(MediaStore.ACTION_IMAGE_CAPTURE) 
        if (takePicture.resolveActivity(packageManager) != null) { 
         startActivityForResult(takePicture, REQUEST_CAPTURE_PHOTO +
         position) 
        } else { 
          logger.e(tag, "Can't take picture.") 
       }  
```

+   从图库中选择图像：

```kt
        val pickPhoto = Intent( 
         Intent.ACTION_PICK, 
         MediaStore.Images.Media.EXTERNAL_CONTENT_URI 
        ) 
        startActivityForResult(pickPhoto, REQUEST_PICK_PHOTO + 
       position) 
```

正如你所看到的，“意图”是 Android 框架的一个关键部分。在下一节中，我们将扩展我们的代码，以更多地利用“意图”。

# 在活动和片段之间传递信息

为了在我们的活动之间传递信息，我们将使用 Android Bundle。Bundle 可以包含不同类型的多个值。我们将通过扩展我们的代码来说明 Bundle 的使用。打开`ItemsFragemnt`并更新如下：

```kt
    private fun openCreateNote() { 
      val intent = Intent(context, NoteActivity::class.java) 
      val data = Bundle() 
      data.putInt(MODE.EXTRAS_KEY, MODE.CREATE.mode) 
      intent.putExtras(data) 
      startActivityForResult(intent, NOTE_REQUEST) 
    } 
    private fun openCreateTodo() { 
       val date = Date(System.currentTimeMillis()) 
       val dateFormat = SimpleDateFormat("MMM dd YYYY", Locale.ENGLISH) 
       val timeFormat = SimpleDateFormat("MM:HH", Locale.ENGLISH) 

       val intent = Intent(context, TodoActivity::class.java) 
       val data = Bundle() 
       data.putInt(MODE.EXTRAS_KEY, MODE.CREATE.mode) 
       data.putString(TodoActivity.EXTRA_DATE, dateFormat.format(date)) 
       data.putString(TodoActivity.EXTRA_TIME, 
       timeFormat.format(date)) 
       intent.putExtras(data) 
       startActivityForResult(intent, TODO_REQUEST) 
    } 

    override fun onActivityResult(requestCode: Int, resultCode: Int, 
    data: Intent?) { 
      super.onActivityResult(requestCode, resultCode, data) 
      when (requestCode) { 
         TODO_REQUEST -> { 
           if (resultCode == Activity.RESULT_OK) { 
             Log.i(logTag, "We created new TODO.") 
           } else { 
             Log.w(logTag, "We didn't created new TODO.") 
           } 
          } 
          NOTE_REQUEST -> { 
            if (resultCode == Activity.RESULT_OK) { 
              Log.i(logTag, "We created new note.") 
            } else { 
              Log.w(logTag, "We didn't created new note.") 
              } 
           } 
         } 
      } 
```

在这里，我们引入了一些重要的更改。首先，我们将我们的 Note 和 Todo 活动作为子活动启动。这意味着我们的`MainActivity`类取决于这些活动的工作结果。在启动子活动时，我们使用了`startActivityForResult()`方法，而不是`startActivity()`方法。我们传递的参数是意图和请求编号。为了获得执行结果，我们重写了`onActivityResult()`方法。如您所见，我们检查了哪个活动完成了，以及该执行是否产生了成功的结果。

我们还改变了传递信息的方式。我们创建了`Bundle`实例并分配了多个值，就像 Todo 活动的情况一样。我们添加了模式、日期和时间。使用`putExtras()`方法将 Bundle 分配给意图。为了使用这些额外值，我们也更新了我们的活动。打开`ItemsActivity`并应用更改，就像这样：

```kt
     abstract class ItemActivity : BaseActivity() { 
       protected var mode = MODE.VIEW 
       protected var success = Activity.RESULT_CANCELED 
       override fun getActivityTitle() = R.string.app_name 

       override fun onCreate(savedInstanceState: Bundle?) { 
         super.onCreate(savedInstanceState) 
         val data = intent.extras 
         data?.let{ 
           val modeToSet = data.getInt(MODE.EXTRAS_KEY, MODE.VIEW.mode) 
           mode = MODE.getByValue(modeToSet) 
         } 
         Log.v(tag, "Mode [ $mode ]") 
       } 

       override fun onDestroy() { 
         super.onDestroy() 
         setResult(success) 
      } 

    } 
```

在这里，我们介绍了保存活动工作结果的字段。我们还更新了处理传递信息的方式。如您所见，如果有任何额外值可用，我们将获得一个整数值作为模式。最后，`onDestroy()`方法设置了将可用于父活动的工作结果。

打开`TodoActivity`并应用以下更改：

```kt
     class TodoActivity : ItemActivity() { 

     companion object { 
       val EXTRA_DATE = "EXTRA_DATE" 
       val EXTRA_TIME = "EXTRA_TIME" 
     } 

     override val tag = "Todo activity" 

     override fun getLayout() = R.layout.activity_todo 

     override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       val data = intent.extras 
       data?.let { 
         val date = data.getString(EXTRA_DATE, "") 
         val time = data.getString(EXTRA_TIME, "") 
         pick_date.text = date 
         pick_time.text = time 
       } 
     } 

    }  
```

我们已经获得了日期和时间额外值，并将它们设置为日期/时间选择器按钮。运行您的应用程序并打开 Todo 活动。您的 Todo 屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e2659bc5-b44b-4bcd-a06e-677c78e168a5.png)

当您离开 Todo 活动并返回到主屏幕时，请观察您的 Logcat。将会有一个包含以下内容的日志：

W/Items fragment--我们没有创建新的 TODO。

由于我们尚未创建任何 Todo 项目，因此我们传递了适当的结果。我们通过返回到主屏幕取消了创建过程。在以后的章节和随后的章节中，我们将成功创建笔记和待办事项。

# 摘要

我们使用本章来连接我们的界面并建立真正的应用程序流程。我们通过为 UI 元素设置适当的操作来建立屏幕之间的连接。我们将数据从一个点传递到另一个点。所有这些都非常简单！我们有一个可以工作的东西，但它看起来很丑。在下一章中，我们将确保它看起来漂亮！我们将为其添加样式和一些漂亮的视觉效果。准备好迎接 Android 强大的 UI API。


# 第五章：外观

现在，应用程序具有令人惊叹的视觉外观。这是使您的应用程序独特和原创的东西。令人愉悦的外观将使您的应用程序在类似应用程序的领域中脱颖而出，但它也将强烈吸引您的用户，他们更有可能在其设备上安装和保留您的应用程序。在本章中，我们将向您展示如何使您的应用程序变得美观。我们将向您介绍 Android UI 主题的秘密！我们的重点只会放在 Android 应用程序的视觉方面。

在本章中，我们将涵盖以下主题：

+   Android 中的主题和样式

+   使用资产

+   自定义字体和着色

+   按钮设计

+   动画和动画集

# Android 框架中的主题

在上一章中，我们建立了主要 UI 元素之间的连接。我们的应用程序在获得一些颜色之前并不像一个。要获得颜色，我们将从主应用程序主题开始。我们将扩展现有的 Android 主题之一，并用我们喜欢的颜色进行覆盖。

打开`styles.xml`。在这里，您将为我们应用程序的需求设置默认主题。我们还将覆盖几种颜色。但是，我们将更改`parent`主题，并根据我们的意愿进行自定义。我们将根据以下示例更新主题：

```kt
    <resources> 

      <style name="AppTheme" 
        parent="Theme.AppCompat.Light.NoActionBar"> 
        <item name="android:colorPrimary">@color/colorPrimary</item> 
        <item name="android:statusBarColor">@color/colorPrimary</item> 
        <item name="android:colorPrimaryDark">
         @color/colorPrimaryDark</item> 
        <item name="android:colorAccent">@color/colorAccent</item> 
        <item name="android:textColor">@android:color/black</item> 
      </style> 

    </resources> 
```

我们定义了一个从`AppCompat`主题继承的主题。主要颜色代表应用程序品牌的颜色。颜色的较暗变体是`colorPrimaryDark`，而将着色的 UI 控件颜色为`colorAccent`。我们还将主要文本颜色设置为黑色。状态栏也将使用我们的主要品牌颜色。

打开`colors.xml`文件，并定义我们将在主题中使用的颜色如下：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <resources> 
      <color name="colorPrimary">#ff6600</color> 
      <color name="colorPrimaryDark">#197734</color> 
      <color name="colorAccent">#ffae00</color> 
    </resources> 
```

在运行应用程序查看主题之前，请确保主题实际应用。使用以下代码更新`manifest`文件：

```kt
    <application 
    android:theme="@style/AppTheme" 
```

还要更新`fragment_items`的浮动操作按钮的颜色如下：

```kt
    <android.support.design.widget.FloatingActionButton 
        android:backgroundTint="@color/colorPrimary" 
        android:id="@+id/new_item" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_alignParentBottom="true" 
        android:layout_alignParentEnd="true" 
        android:layout_margin="@dimen/button_margin" /> 
```

背景色属性将确保按钮与状态栏具有相同的颜色。构建并运行应用程序。恭喜，您已成功将应用程序品牌定为橙色！

# Android 中的样式

我们刚刚定义的主题代表样式。所有样式都在`styles.xml`文件中定义。我们将创建几种样式，以演示您创建样式的简易性和它们的强大性。您可以为按钮、文本或任何其他视图定义样式。您也可以继承样式。

为了进行样式设置，我们将定义应用程序中要使用的颜色调色板。打开您的`colors.xml`文件并扩展如下：

```kt
    <color name="green">#11c403</color> 
    <color name="green_dark">#0e8c05</color> 
    <color name="white">#ffffff</color> 
    <color name="white_transparent_40">#64ffffff</color> 
    <color name="black">#000000</color> 
    <color name="black_transparent_40">#64000000</color> 
    <color name="grey_disabled">#d5d5d5</color> 
    <color name="grey_text">#444d57</color> 
    <color name="grey_text_transparent_40">#64444d57</color> 
    <color name="grey_text_middle">#6d6d6d</color> 
    <color name="grey_text_light">#b9b9b9</color> 
    <color name="grey_thin_separator">#f1f1f1</color> 
    <color name="grey_thin_separator_settings">#eeeeee</color> 
    <color name="vermilion">#f3494c</color> 
    <color name="vermilion_dark">#c64145</color> 
    <color name="vermilion_transparent_40">#64f3494c</color> 
    <color name="plum">#121e2a</color> 
```

注意透明颜色！观察`白色`颜色的情况。纯`白色`颜色的代码为`#ffffff`，而`40%`透明的白色的代码为`#64ffffff`。要实现透明度，您可以使用以下值：

0% = #00

10% = #16

20% = #32

30% = #48

40% = #64

50% = #80

60% = #96

70% = #112

80% = #128

90% = #144

现在我们已经定义了颜色调色板，我们将创建我们的第一个样式。打开`styles.xml`并扩展它：

```kt
     <style name="simple_button"> 
        <item name="android:textSize">16sp</item> 
        <item name="android:textAllCaps">false</item> 
        <item name="android:textColor">@color/white</item> 
     </style> 

     <style name="simple_button_green" parent="simple_button"> 
        <item name="android:background">
        @drawable/selector_button_green</item> 
    </style> 
```

我们定义了两种样式。第一种定义了简单的按钮。它具有白色文本，字体大小为`16sp`。第二个扩展了第一个，并添加了背景属性。我们将创建一个选择器，以便演示我们定义的样式。由于我们还没有这个资源，请在`drawable resource`文件夹中创建`selector_button_green xml`：

```kt
     <?xml version="1.0" encoding="utf-8"?> 
     <selector xmlns:android=
      "http://schemas.android.com/apk/res/android"> 

      <item android:drawable="@color/grey_disabled" 
       android:state_enabled="false" /> 
      <item android:drawable="@color/green_dark"
       android:state_selected="true" /> 
      <item android:drawable="@color/green_dark"
       android:state_pressed="true" /> 
      <item android:drawable="@color/green" /> 

     </selector> 
```

我们定义了一个选择器。选择器是描述视觉行为或不同状态的 XML。我们为按钮的禁用状态添加了不同的颜色，当按钮被按下、释放或我们没有与其进行任何交互时，我们也为其添加了颜色。

查看按钮的外观，打开`activity_todo`布局，并为每个按钮设置样式：

```kt
    style="@style/simple_button_green"  
```

然后，运行应用程序并打开`Todo`屏幕。您的屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/bce22470-94fa-4995-9b9a-5af05b6f57da.png)

如果您按下按钮，您会注意到颜色已经变成了深绿色。在接下来的部分，我们将通过添加圆角边缘来进一步改进这些按钮，但在此之前，让我们创建一些更多的样式：

+   为输入字段和导航抽屉在您的`styles.xml`中添加样式：

```kt
        <style name="simple_button_grey" parent="simple_button"> 
         <item name="android:background">
          @drawable/selector_button_grey</item> 
        </style> 

        <style name="edit_text_transparent"> 
          <item name="android:textSize">14sp</item> 
          <item name="android:padding">19dp</item> 
          <item name="android:textColor">@color/white</item> 
          <item name="android:textColorHint">@color/white</item> 
          <item name="android:background">
          @color/black_transparent_40</item> 
        </style> 

       <style name="edit_text_gery_text"
         parent="edit_text_transparent"> 
         <item name="android:textAlignment">textStart</item> 
         <item name="android:textColor">@color/white</item> 
         <item name="android:background">@color/grey_text_light</item> 
       </style> 
```

+   对于输入字段，我们定义了提示的颜色。同时，我们引入了一个名为`selector_button_grey`的选择器可绘制对象：

```kt
        <?xml version="1.0" encoding="utf-8"?> 
        <selector xmlns:android=
         "http://schemas.android.com/apk/res/android"> 

         <item android:drawable="@color/grey_disabled"  
         android:state_enabled="false" /> 
         <item android:drawable="@color/grey_text_middle"  
         android:state_selected="true" /> 
         <item android:drawable="@color/grey_text_middle"
         android:state_pressed="true" /> 
         <item android:drawable="@color/grey_text" /> 
        </selector> 
```

+   对于两个屏幕（笔记和待办事项）上的`note_title`，添加样式：

```kt
        style="@style/edit_text_transparent" 
```

+   对于`note_content`添加：

```kt
        style="@style/edit_text_gery_text"  
```

+   对于`adapter_navigation_drawer`布局，将样式应用于按钮：

```kt
        style="@style/simple_button_grey" 
```

就是这样！您已经为您的应用程序添加了样式！现在运行它并查看所有屏幕和导航抽屉：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/c918278a-815c-40f5-9727-e4c6b0d254de.png)

您觉得呢？UI 现在看起来更好了吗？也观察下一个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/628914df-4308-4f98-94b7-c18cc0862535.png)

应用程序现在看起来很不错。随意根据您的愿望调整属性和颜色。我们还没有完成。我们需要一些字体来应用！在接下来的部分，我们将处理这个问题。

# 使用资源文件

现在是时候让您的应用程序使用原始资源了。一个很好的例子就是字体。我们使用的每个字体应用都将是一个存储在`assets`文件夹中的单独文件。`assets`文件夹是`main`目录或代表构建变体的目录的子目录。除了字体之外，通常还会在这里存储 txt 文件，mp3，waw，mid 等。您不能将这些类型的文件存储在`res`目录中。

# 使用自定义字体

字体是资源。因此，为了为您的应用程序提供一些字体，我们首先需要复制它们。有很多好的免费字体资源。例如，Google Fonts。下载一些字体并将它们复制到您的`assets`目录中。如果没有`assets`目录，请创建一个。我们将把我们的字体放在`assets/fonts`目录中。

在我们的示例中，我们将使用`Exo`。`Exo`带有以下`font`文件：

+   `Exo2-Black.ttf`

+   `Exo2-BlackItalic.ttf`

+   `Exo2-Bold.ttf`

+   `Exo2-BoldItalic.ttf`

+   `Exo2-ExtraBold.ttf`

+   `Exo2-ExtraBoldItalic.ttf`

+   `Exo2-ExtraLight.ttf`

+   `Exo2-ExtraLightItalic.ttf`

+   `Exo2-Italic.ttf`

+   `Exo2-Light.ttf`

+   `Exo2-LightItalic.ttf`

+   `Exo2-Medium.ttf`

+   `Exo2-MediumItalic.ttf`

+   `Exo2-Regular.ttf`

+   `Exo2-SemiBold.ttf`

+   `Exo2-SemiBoldItalic.ttf`

+   `Exo2-Thin.ttf`

+   `Exo2-ThinItalic.ttf`

将`font`文件复制到`assets`目录不会直接为我们提供对这些字体的支持。我们需要通过代码来使用它们。我们将创建一个代码，它将为我们应用字体。

打开`BaseActivity`并扩展它：

```kt
    abstract class BaseActivity : AppCompatActivity() { 
    companion object { 
      private var fontExoBold: Typeface? = null 
      private var fontExoRegular: Typeface? = null 

      fun applyFonts(view: View, ctx: Context) { 
        var vTag = "" 
        if (view.tag is String) { 
          vTag = view.tag as String 
        } 
        when (view) { 
          is ViewGroup -> { 
            for (x in 0..view.childCount - 1) { 
              applyFonts(view.getChildAt(x), ctx) 
            } 
          } 
          is Button -> { 
            when (vTag) { 
              ctx.getString(R.string.tag_font_bold) -> { 
                view.typeface = fontExoBold 
              } 
              else -> { 
                view.typeface = fontExoRegular 
              } 
             } 
            } 
            is TextView -> { 
              when (vTag) { 
                ctx.getString(R.string.tag_font_bold) -> { 
                view.typeface = fontExoBold 
                } 
                 else -> { 
                   view.typeface = fontExoRegular 
                 } 
                } 
              } 
              is EditText -> { 
                when (vTag) { 
                  ctx.getString(R.string.tag_font_bold) -> { 
                    view.typeface = fontExoBold 
                  } 
                 else -> { 
                   view.typeface = fontExoRegular 
                 } 
               } 
             } 
           } 
        } 
     } 
    ... 
    override fun onPostCreate(savedInstanceState: Bundle?) { 
        super.onPostCreate(savedInstanceState) 
        Log.v(tag, "[ ON POST CREATE ]") 
        applyFonts() 
    } 
    ... 
    protected fun applyFonts() { 
        initFonts() 
        Log.v(tag, "Applying fonts [ START ]") 
        val rootView = findViewById(android.R.id.content) 
        applyFonts(rootView, this) 
        Log.v(tag, "Applying fonts [ END ]") 
    } 

    private fun initFonts() { 
        if (fontExoBold == null) { 
            Log.v(tag, "Initializing font [ Exo2-Bold ]") 
            fontExoBold = Typeface.createFromAsset(assets, "fonts/Exo2-
            Bold.ttf") 
        } 
        if (fontExoRegular == null) { 
            Log.v(tag, "Initializing font [ Exo2-Regular ]") 
            fontExoRegular = Typeface.createFromAsset(assets,
            "fonts/Exo2-Regular.ttf") 
        } 
     }   
    } 
```

我们扩展了我们的基本活动以处理字体。当活动进入`onPostCreate()`时，`applyFonts()`方法将被调用。然后，`applyFonts()`执行以下操作：

+   调用`initFonts()`方法，该方法从资源文件创建`TypeFace`实例。`TypeFace`用作字体及其视觉属性的表示。我们为`ExoBold`和`ExoRegular`实例化了字体。

+   接下来发生的是，我们正在获取当前活动的`root`视图，并将其传递给伴随对象的`applyFonts()`方法。如果视图是一个`view group`，我们会遍历其子项，直到达到普通视图。视图有一个名为`typeface`的属性，我们将其设置为我们的`typeface`实例。您还会注意到，我们正在从每个视图中检索名为`tag`的类属性。在 Android 中，我们可以为视图设置标签。标签可以是任何类的实例。在我们的情况下，我们正在检查标签是否是具有名称`tag_font_bold`的字符串资源的`String`。

要设置标签，创建一个名为**tags**的新`xml`文件，并将其放入`values`目录中，并填充以下内容：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <resources> 
      <string name="tag_font_regular">FONT_REGULAR</string> 
      <string name="tag_font_bold">FONT_BOLD</string> 
    </resources> 
    To apply it open styles.xml and add tag to simple_button style: 
    <item name="android:tag">@string/tag_font_bold</item> 
```

现在所有应用程序的按钮都将应用粗体字体版本。现在构建您的应用程序并运行它。您会注意到字体已经改变了！

# 应用颜色

我们为我们的应用程序定义了颜色调色板。我们通过访问其资源应用了每种颜色。有时我们没有特定的颜色资源可用。可能发生的情况是，我们通过后端（作为对某些 API 调用的响应）动态获得颜色，或者由于其他原因，我们希望从代码中定义颜色。

当你需要在代码中处理颜色时，Android 非常强大。我们将涵盖一些示例，并向您展示您可以做什么。

要从现有资源中获取颜色，您可以执行以下操作：

```kt
    val color = ContextCompat.getColor(contex, R.color.plum) 
```

以前我们用来做这个：

```kt
     val color = resources.getColor(R.color.plum) 
```

但它已经在 Android 6 版本中被弃用。

当您获得颜色后，您可以将其应用于某个视图：

```kt
    pick_date.setTextColor(color) 
```

另一种获取颜色的方法是访问`Color`类的静态方法。让我们从解析一些颜色字符串开始：

```kt
    val color = Color.parseColor("#ff0000")  
```

我们必须注意，已经有一定数量的预定义颜色可用：

```kt
     val color = Color.RED 
```

所以我们不需要解析`#ff0000`。还有一些其他颜色：

```kt
    public static final int BLACK 
    public static final int BLUE 
    public static final int CYAN 
    public static final int DKGRAY 
    public static final int GRAY 
    public static final int GREEN 
    public static final int LTGRAY 
    public static final int MAGENTA 
    public static final int RED 
    public static final int TRANSPARENT 
    public static final int WHITE 
    public static final int YELLOW
```

有时，您只会有关于红色，绿色或蓝色的参数，然后基于此创建颜色：

```kt
     Color red = Color.valueOf(1.0f, 0.0f, 0.0f); 
```

我们必须注意，此方法从 API 版本 26 开始可用！

如果 RGB 不是您想要的颜色空间，那么您可以将其作为参数传递：

```kt
    val colorSpace = ColorSpace.get(ColorSpace.Named.NTSC_1953) 
    val color = Color.valueOf(1f, 1f, 1f, 1f, colorSpace) 
```

正如您所看到的，当您处理颜色时有很多可能性。如果标准颜色资源不足以管理您的颜色，您可以以一种高级方式来处理它。我们鼓励您尝试并在一些用户界面上尝试。

例如，如果您正在使用`AppCompat`库，一旦您获得`Color`实例，您可以像以下示例中那样使用它：

```kt
    counter.setTextColor( 
      ContextCompat.getColor(context, R.color.vermilion) 
    ) 
```

考虑以下截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/a593dbbc-7720-4759-b359-609f9d77da18.png)

# 让你的按钮看起来漂亮

我们给我们的按钮上色并为它们定义了状态。我们为每个状态着色。我们有禁用状态的颜色，启用状态和按下状态的颜色。现在我们将更进一步。我们将使我们的按钮变圆，并用渐变颜色而不是纯色来着色。我们将为新的按钮样式准备一个布局。打开`activity_todo`布局并修改按钮容器：

```kt
    <LinearLayout 
      android:background="@color/grey_text_light" 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:orientation="horizontal" 
      android:weightSum="1"> 

      ... 

     </LinearLayout> 
```

我们将背景设置为与我们用于编辑文本字段相同的背景。按钮将被圆角，所以我们希望它们与屏幕的其余部分在相同的背景上。现在，让我们定义一些额外的尺寸和我们将使用的颜色。我们需要定义具有圆角边角的按钮的半径：

```kt
     <dimen name="button_corner">10dp</dimen> 
```

由于我们计划使用渐变颜色，我们必须为渐变添加第二种颜色。将这些颜色添加到您的`colors.xml`中：

```kt
     <color name="green2">#208c18</color> 
     <color name="green_dark2">#0b5505</color>  
```

现在我们已经定义了这一点，我们需要更新绿色按钮的样式：

```kt
     <style name="simple_button_green" parent="simple_button"> 
        <item name="android:layout_margin">5dp</item> 
        <item name="android:background">
        @drawable/selector_button_green</item> 
     </style> 
```

我们添加了一个边距，以便按钮彼此分开。我们现在需要矩形圆角可绘制资源。创建三个可绘制资源`rect_rounded_green`，`rect_rounded_green_dark`和`rect_rounded_grey_disabled`。确保它们定义如下：

+   `rect_rounded_green`：

```kt
         <shape xmlns:android=
           "http://schemas.android.com/apk/res/android"> 
            <gradient 
            android:angle="270" 
            android:endColor="@color/green2" 
            android:startColor="@color/green" /> 

           <corners android:radius="@dimen/button_corner" /> 
         </shape>  
```

+   `rect_rounded_green_dark`:

```kt
     <shape > 
       <gradient 
       android:angle="270" 
       android:endColor="@color/green_dark2" 
       android:startColor="@color/green_dark" /> 

      <corners android:radius="@dimen/button_corner" /> 
     </shape> 
```

+   `rect_rounded_grey_disabled`：

```kt
         <shape xmlns:android=
         "http://schemas.android.com/apk/res/android"> 

         <solid android:color="@color/grey_disabled" /> 
         <corners android:radius="@dimen/button_corner" /> 
         </shape> 
```

+   我们定义了包含以下属性的渐变：

+   渐变角度（270 度）

+   起始颜色（我们使用了我们的颜色资源）

+   结束颜色（我们也使用了我们的颜色资源）

此外，每个可绘制资源都有其角半径的值。最后一步是更新我们的选择器。打开`selector_button_green`并更新它：

```kt
       <?xml version="1.0" encoding="utf-8"?> 
       <selector xmlns:android=
       "http://schemas.android.com/apk/res/android"> 

       <item  
       android:drawable="@drawable/rect_rounded_grey_disabled"  
       android:state_enabled="false" /> 

       <item  
       android:drawable="@drawable/rect_rounded_green_dark"  
       android:state_selected="true" /> 

       <item  
       android:drawable="@drawable/rect_rounded_green_dark"  
       android:state_pressed="true" /> 

       <item  
       android:drawable="@drawable/rect_rounded_green" /> 

     </selector> 
```

构建您的应用程序并运行它。打开`Todo`屏幕并看一看。按钮现在有了平滑的圆角边缘，看起来更漂亮。按钮之间通过边距分开，如果您在按钮上按下手指，您将看到我们定义的较深绿色的辅助渐变：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/6ed3b309-e081-464f-a4fc-e90dd4839dac.png)

# 设置动画

我们认为我们的布局很好看。它很漂亮。但它可以更有趣吗？当然可以！如果我们使我们的布局更具互动性，我们将实现更好的用户体验，并吸引用户使用它。我们将通过添加一些动画来实现这一点。动画可以通过代码或通过动画视图属性来定义。我们将通过添加简单而有效的开场动画来改进每个屏幕。

作为资源定义的动画位于`anim`资源目录中。我们将需要一些动画资源--`fade_in`，`fade_out`，`bottom_to_top`，`top_to_bottom`，`hide_to_top`，`hide_to_bottom`。创建它们并根据这些示例定义它们：

+   `fade_in`：

```kt
        <?xml version="1.0" encoding="utf-8"?> 
        <alpha xmlns:android=
        "http://schemas.android.com/apk/res/android" 
        android:duration="300" 
        android:fromAlpha="0.0" 
        android:interpolator="@android:anim/accelerate_interpolator" 
        android:toAlpha="1.0" /> 
```

+   `fade_out`：

```kt
         <?xml version="1.0" encoding="utf-8"?> 
         <alpha xmlns:android=
         "http://schemas.android.com/apk/res/android" 
         android:duration="300" 
         android:fillAfter="true" 
         android:fromAlpha="1.0" 
         android:interpolator="@android:anim/accelerate_interpolator" 
         android:toAlpha="0.0" /> 
         -  bottom_to_top: 
         <set xmlns:android=
          "http://schemas.android.com/apk/res/android" 
         android:fillAfter="true" 
         android:fillEnabled="true" 
         android:shareInterpolator="false"> 

         <translate 
         android:duration="900" 
         android:fromXDelta="0%" 
         android:fromYDelta="100%" 
         android:toXDelta="0%" 
         android:toYDelta="0%" /> 

         </set> 
```

+   `top_to_bottom`：

```kt
     <set  
     android:fillAfter="true" 
     android:fillEnabled="true" 
     android:shareInterpolator="false"> 
     <translate 
      android:duration="900" 
      android:fromXDelta="0%" 
      android:fromYDelta="-100%" 
      android:toXDelta="0%" 
      android:toYDelta="0%" /> 
    </set> 
```

+   `hide_to_top`：

```kt
     <set  
      android:fillAfter="true" 
      android:fillEnabled="true" 
      android:shareInterpolator="false"> 

    <translate 
      android:duration="900" 
      android:fromXDelta="0%" 
      android:fromYDelta="0%" 
      android:toXDelta="0%" 
      android:toYDelta="-100%" /> 

   </set> 
```

+   `hide_to_bottom`：

```kt
         <set xmlns:android=
          "http://schemas.android.com/apk/res/android" 
           android:fillAfter="true" 
           android:fillEnabled="true" 
           android:shareInterpolator="false"> 

        <translate 
          android:duration="900" 
          android:fromXDelta="0%" 
          android:fromYDelta="0%" 
          android:toXDelta="0%" 
          android:toYDelta="100%" /> 

       </set> 
```

看看这个例子和你可以定义的属性。在淡入淡出动画示例中，我们为视图的`alpha`属性进行了动画处理。我们设置了动画持续时间，从和到 alpha 值以及我们将用于动画的插值器。在 Android 中，对于你的动画，你可以选择这些插值器之一：

+   `accelerate_interpolator`

+   `accelerate_decelerate_interpolator`

+   `bounce_interpolator`

+   `cycle_interpolator`

+   `anticipate_interpolator`

+   `anticipate_overshot_interpolator`

+   以及其他许多动画，都定义在`@android:anim/...`中

对于其他动画，我们使用`from`和`to`参数定义了平移。

在使用这些动画之前，我们将调整一些背景，以便在动画开始之前我们的布局中没有间隙。对于`activity_main`，添加工具栏父视图的背景：

```kt
     android:background="@android:color/darker_gray" 
```

对于`activity_note`和`activity_todo`，将工具栏嵌套在一个更多的父级中，以便最终颜色与工具栏下方标题字段的颜色相同：

```kt
     <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:background="@color/black_transparent_40" 
        android:orientation="vertical"> 

      <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:background="@color/black_transparent_40" 
        android:orientation="vertical"> 

      <android.support.v7.widget.Toolbar 
        android:id="@+id/toolbar" 
        android:layout_width="match_parent" 
        android:layout_height="50dp" 
        android:background="@color/colorPrimary" 
        android:elevation="4dp" /> 

```

最后，我们将应用我们的动画。我们将为我们的屏幕打开和关闭使用淡入和淡出动画。打开`BaseActivity`并修改它如下：

```kt
     override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out) 
        setContentView(getLayout()) 
        setSupportActionBar(toolbar) 
        Log.v(tag, "[ ON CREATE ]") 

     } 
```

我们使用`overridePendingTransition()`方法覆盖了过渡效果，该方法将进入和退出动画作为参数。

也更新你的`onResume()`和`onPause()`方法：

```kt
    override fun onResume() { 
        super.onResume() 
        Log.v(tag, "[ ON RESUME ]") 
        val animation = getAnimation(R.anim.top_to_bottom) 
        findViewById(R.id.toolbar).startAnimation(animation) 
    } 

    override fun onPause() { 
        super.onPause() 
        Log.v(tag, "[ ON PAUSE ]") 
        val animation = getAnimation(R.anim.hide_to_top) 
        findViewById(R.id.toolbar).startAnimation(animation) 

    } 
```

我们创建了一个动画实例，并使用`startAnimation()`方法将其应用于视图。`getAnimation()`方法是我们自己定义的。因此，将实现添加到`BaseActivity`：

```kt
     protected fun getAnimation(animation: Int): Animation =
     AnimationUtils.loadAnimation(this, animation) 
```

由于我们使用的是 Kotlin，为了使其对所有活动都可用，而不仅仅是扩展`BaseActivity`的活动，将方法更改为扩展函数，如下所示：

```kt
     fun Activity.getAnimation(animation: Int): Animation =
     AnimationUtils.loadAnimation(this, animation) 
```

再次构建并运行应用程序。多次打开和关闭屏幕，看看我们的动画是如何工作的。

# Android 中的动画集

在之前的部分中，我们使用了在 XML 中定义的资源的动画。在本节中，我们将使用各种视图属性和动画集。我们将通过简单而有效的示例来说明目的和用途。

让我们演示代码中的第一个动画。打开`ItemsFragment`。添加以下方法：

```kt
     private fun animate(btn: FloatingActionButton, expand: Boolean =
     true) { 
        btn.animate() 
                .setInterpolator(BounceInterpolator()) 
                .scaleX(if(expand){ 1.5f } else { 1.0f }) 
                .scaleY(if(expand){ 1.5f } else { 1.0f }) 
                .setDuration(2000) 
                .start() 
      } 
```

这个方法会做什么？这个方法将使用弹跳插值对按钮进行缩放动画。如果扩展参数为`true`，我们将放大，否则我们将缩小。

将其应用到我们的浮动操作按钮。扩展按钮点击监听器：

```kt
    btn?.setOnClickListener { 

    animate(btn) 

    ... 

    } 
```

并将主对话框设置为可取消，并设置取消操作：

```kt
    val builder = AlertDialog.Builder(this@ItemsFragment.context) 
                    .setTitle(R.string.choose_a_type) 
                    .setCancelable(true) 
                    .setOnCancelListener { 
                        animate(btn, false) 
                    } 

    .setItems( ... ) 

    ... 

    builder.show() 
```

构建并运行应用程序。单击“添加项目”按钮，然后通过在其外部轻击来关闭对话框。我们有一个精彩的缩放动画！

为了使浮动操作按钮完整，添加加号的 PNG 资源并将其应用到按钮上：

```kt
     <android.support.design.widget.FloatingActionButton 
     ... 
     android:src="img/add" 
     android:scaleType="centerInside" 
     ... 
     /> 
```

通过将图标添加到按钮，动画看起来完美！让我们使它更加完美！我们将创建一个包含多个动画的动画集！

```kt
     private fun animate(btn: FloatingActionButton, expand: Boolean =
     true) { 
        val animation1 = ObjectAnimator.ofFloat(btn, "scaleX",
        if(expand){ 1.5f } else { 1.0f }) 
        animation1.duration = 2000 
        animation1.interpolator = BounceInterpolator() 

        val animation2 = ObjectAnimator.ofFloat(btn, "scaleY",
        if(expand){ 1.5f } else { 1.0f }) 
        animation2.duration = 2000 
        animation2.interpolator = BounceInterpolator() 

        val animation3 = ObjectAnimator.ofFloat(btn, "alpha",
        if(expand){ 0.3f } else { 1.0f }) 
        animation3.duration = 500 
        animation3.interpolator = AccelerateInterpolator() 

        val set = AnimatorSet() 
        set.play(animation1).with(animation2).before(animation3) 
        set.start() 
      } 
```

`AnimatorSet`类使我们能够创建复杂的动画。在这种情况下，我们定义了沿着*x*轴和*y*轴的缩放动画。这两个动画将同时进行动画处理，给我们带来了在两个方向上缩放的效果。在我们缩放视图之后，我们将减少（或增加）视图的容量。正如你所看到的，我们可以链接或按顺序执行动画。

构建你的项目并运行。你可以看到新的动画行为。

# 总结

本章是一个相当互动的章节。首先，我们向您展示了如何在 Android 中添加、定义、更改和调整主题。然后我们深入研究了 Android 的样式和资源。在本章中，我们还采用了一些自定义字体和着色。最后，我们制作了一些非常漂亮的按钮和快速动画。在下一章中，您将开始学习 Android 框架的系统部分。我们将从权限开始。


# 第六章：权限

你好！你能相信这本书的一个重要部分已经在我们身后了吗？我们已经完成了用户界面，现在，我们正在进入这本书更复杂的部分——系统。

在本章以及接下来的章节中，我们将深入了解 Android 系统的结构。您将学习有关权限、数据库处理、首选项、并发、服务、消息传递、后端、API 和高性能的知识。

然而，不要被愚弄；这本书及其内容并未涵盖整个框架。那是不可能的；Android 是一个如此庞大的框架，完全掌握它可能需要数年时间。在这里，我们只是深入了解 Android 和 Kotlin 的世界。

然而，不要灰心！在这本书中，我们将为您提供掌握 Kotlin 和 Android 所需的知识和技能。在本章中，我们将讨论 Android 中的权限。您将学习权限是什么，它们用于什么，最重要的是，为什么我们需要（强调需要）使用它们。

在本章中，我们将涵盖以下主题：

+   来自 Android 清单的权限

+   请求权限

+   以 Kotlin 方式处理权限

# 来自 Android 清单的权限

Android 应用在它们自己的进程中运行，并且与操作系统的其余部分分离。因此，为了执行一些特定于系统的操作，需要请求它们。这样的权限请求的一个例子是请求使用蓝牙、检索当前 GPS 位置、发送短信，或者读取或写入文件系统。权限授予对各种设备功能的访问。处理权限有几种方法。我们将从使用清单开始。

首先，我们必须确定需要哪些权限。在安装过程中，用户可能决定不安装应用程序，因为权限太多。例如，用户可能会问为什么一个应用程序需要发送短信功能，当应用程序本身只是一个简单的图库应用程序。

对于我们在本书中开发的 Journaler 应用程序，我们将需要以下权限：

+   读取 GPS 坐标，因为我们希望我们创建的每个笔记都有相关联的坐标

+   我们需要访问互联网，这样我们就可以稍后执行 API 调用

+   启动完成事件，我们需要它，这样应用程序服务可以在每次重新启动手机时与后端进行同步

+   读取和写入外部存储，以便我们可以读取数据或存储数据

+   访问网络状态，以便我们知道是否有可用的互联网连接

+   使用振动，这样我们就可以在从后端接收到东西时振动

打开 `AndroidManifest.xml` 文件，并使用以下权限进行更新：

```kt
    <manifest xmlns:android=
     "http://schemas.android.com/apk/res/android" 
     package="com.journaler"> 

      <uses-permission android:name="android.permission.INTERNET" /> 
      <uses-permission android:name=
       "android.permission.RECEIVE_BOOT_COMPLETED" /> 
      <uses-permission android:name=
       "android.permission.READ_EXTERNAL_STORAGE" /> 
      <uses-permission android:name=
       "android.permission.WRITE_EXTERNAL_STORAGE" /> 
      <uses-permission android:name=
       "android.permission.ACCESS_NETWORK_STATE" /> 
      <uses-permission android:name=
       "android.permission.ACCESS_FINE_LOCATION" /> 
      <uses-permission android:name=
       "android.permission.ACCESS_COARSE_LOCATION" /> 
      <uses-permission android:name="android.permission.VIBRATE" /> 
       <application ... > 
         ... 
       </application 

       ... 

     </manifest>  
```

我们刚刚请求的权限的名称基本上是不言自明的，并且它们涵盖了我们提到的所有要点。除了这些权限，您还可以请求一些其他权限。看一下每个权限的名称，您会惊讶于您实际上可以请求到什么：

```kt
     <uses-permission android:name=
     "android.permission.ACCESS_CHECKIN_PROPERTIES" /> 
     <uses-permission  android:name=
     "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS" /> 
     <uses-permission android:name=
     "android.permission.ACCESS_MOCK_LOCATION" /> 
     <uses-permission android:name=
     "android.permission.ACCESS_SURFACE_FLINGER" /> 
     <uses-permission android:name=
     "android.permission.ACCESS_WIFI_STATE" /> 
     <uses-permission android:name=
     "android.permission.ACCOUNT_MANAGER" /> 
     <uses-permission android:name=
     "android.permission.AUTHENTICATE_ACCOUNTS" /> 
     <uses-permission android:name=
     "android.permission.BATTERY_STATS" /> 
     <uses-permission android:name=
     "android.permission.BIND_APPWIDGET" /> 
     <uses-permission android:name=
     "android.permission.BIND_DEVICE_ADMIN" /> 
     <uses-permission android:name=
     "android.permission.BIND_INPUT_METHOD" /> 
     <uses-permission android:name=
     "android.permission.BIND_REMOTEVIEWS" /> 
     <uses-permission android:name=
     "android.permission.BIND_WALLPAPER" /> 
     <uses-permission android:name=
     "android.permission.BLUETOOTH" /> 
     <uses-permission android:name=
     "android.permission.BLUETOOTH_ADMIN" /> 
     <uses-permission android:name=
     "android.permission.BRICK" /> 
     <uses-permission android:name=
     "android.permission.BROADCAST_PACKAGE_REMOVED" /> 
     <uses-permission android:name=
     "android.permission.BROADCAST_SMS" /> 
     <uses-permission android:name=
     "android.permission.BROADCAST_STICKY" /> 
     <uses-permission android:name=
      "android.permission.BROADCAST_WAP_PUSH" /> 
     <uses-permission android:name=
      "android.permission.CALL_PHONE"/> 
     <uses-permission android:name=
      "android.permission.CALL_PRIVILEGED" /> 
     <uses-permission android:name=
      "android.permission.CAMERA"/> 
     <uses-permission android:name=
      "android.permission.CHANGE_COMPONENT_ENABLED_STATE" /> 
     <uses-permission android:name=
     "android.permission.CHANGE_CONFIGURATION" /> 
     <uses-permission android:name=
     "android.permission.CHANGE_NETWORK_STATE" /> 
     <uses-permission android:name=
     "android.permission.CHANGE_WIFI_MULTICAST_STATE" /> 
     <uses-permission android:name=
     "android.permission.CHANGE_WIFI_STATE" /> 
     <uses-permission android:name=
     "android.permission.CLEAR_APP_CACHE" /> 
     <uses-permission android:name=
     "android.permission.CLEAR_APP_USER_DATA" /> 
     <uses-permission android:name=
     "android.permission.CONTROL_LOCATION_UPDATES" /> 
     <uses-permission android:name=
     "android.permission.DELETE_CACHE_FILES" /> 
     <uses-permission android:name=
     "android.permission.DELETE_PACKAGES" /> 
     <uses-permission android:name=
     "android.permission.DEVICE_POWER" /> 
     <uses-permission android:name=
     "android.permission.DIAGNOSTIC" /> 
     <uses-permission android:name=
     "android.permission.DISABLE_KEYGUARD" /> 
     <uses-permission android:name=
     "android.permission.DUMP" /> 
     <uses-permission android:name=
     "android.permission.EXPAND_STATUS_BAR" /> 
     <uses-permission android:name="
     android.permission.FACTORY_TEST" /> 
     <uses-permission android:name=
     "android.permission.FLASHLIGHT" /> 
     <uses-permission android:name=
     "android.permission.FORCE_BACK" /> 
     <uses-permission android:name=
     "android.permission.GET_ACCOUNTS" /> 
     <uses-permission android:name=
     "android.permission.GET_PACKAGE_SIZE" /> 
     <uses-permission android:name=
     "android.permission.GET_TASKS" /> 
     <uses-permission android:name=
     "android.permission.GLOBAL_SEARCH" /> 
     <uses-permission android:name=
     "android.permission.HARDWARE_TEST" /> 
     <uses-permission android:name=
     "android.permission.INJECT_EVENTS" /> 
     <uses-permission android:name=
     "android.permission.INSTALL_LOCATION_PROVIDER" /> 
     <uses-permission android:name=
     "android.permission.INSTALL_PACKAGES" /> 
     <uses-permission android:name=
     "android.permission.INTERNAL_SYSTEM_WINDOW" /> 
     <uses-permission android:name=
     "android.permission.KILL_BACKGROUND_PROCESSES" /> 
     <uses-permission android:name=
     "android.permission.MANAGE_ACCOUNTS" /> 
     <uses-permission android:name=
     "android.permission.MANAGE_APP_TOKENS" /> 
     <uses-permission android:name=
     "android.permission.MASTER_CLEAR" /> 
     <uses-permission android:name=
     "android.permission.MODIFY_AUDIO_SETTINGS" /> 
     <uses-permission android:name=
     "android.permission.MODIFY_PHONE_STATE" /> 
     <uses-permission android:name=
     "android.permission.MOUNT_FORMAT_FILESYSTEMS" /> 
     <uses-permission android:name=
     "android.permission.MOUNT_UNMOUNT_FILESYSTEMS" /> 
     <uses-permission android:name=
     "android.permission.NFC" /> 
     <uses-permission android:name=
     "android.permission.PROCESS_OUTGOING_CALLS" /> 
     <uses-permission android:name=
     "android.permission.READ_CALENDAR" /> 
    <uses-permission android:name=
     "android.permission.READ_CONTACTS" /> 
    <uses-permission android:name=
    "android.permission.READ_FRAME_BUFFER" /> 
    <uses-permission android:name=
    "android.permission.READ_HISTORY_BOOKMARKS" /> 
    <uses-permission android:name=
    "android.permission.READ_INPUT_STATE" /> 
    <uses-permission android:name=
    "android.permission.READ_LOGS" /> 
    <uses-permission android:name=
    "android.permission.READ_PHONE_STATE" /> 
    <uses-permission android:name=
    "android.permission.READ_SMS" /> 
    <uses-permission android:name=
    "android.permission.READ_SYNC_SETTINGS" /> 
    <uses-permission android:name=
    "android.permission.READ_SYNC_STATS" /> 
    <uses-permission android:name=
    "android.permission.REBOOT" /> 
    <uses-permission android:name=
    "android.permission.RECEIVE_MMS" /> 
    <uses-permission android:name=
    "android.permission.RECEIVE_SMS" /> 
    <uses-permission android:name=
    "android.permission.RECEIVE_WAP_PUSH" /> 
    <uses-permission android:name=
    "android.permission.RECORD_AUDIO" /> 
    <uses-permission android:name=
    "android.permission.REORDER_TASKS" /> 
    <uses-permission android:name=
    "android.permission.RESTART_PACKAGES" /> 
    <uses-permission android:name=
    "android.permission.SEND_SMS" /> 
    <uses-permission android:name=
    "android.permission.SET_ACTIVITY_WATCHER" /> 
    <uses-permission android:name=
     "android.permission.SET_ALARM" /> 
    <uses-permission android:name=
     "android.permission.SET_ALWAYS_FINISH" /> 
    <uses-permission android:name=
     "android.permission.SET_ANIMATION_SCALE" /> 
    <uses-permission android:name=
     "android.permission.SET_DEBUG_APP" /> 
    <uses-permission android:name=
     "android.permission.SET_ORIENTATION" /> 
    <uses-permission android:name=
     "android.permission.SET_POINTER_SPEED" /> 
    <uses-permission android:name=
     "android.permission.SET_PROCESS_LIMIT" /> 
    <uses-permission android:name=
     "android.permission.SET_TIME" /> 
    <uses-permission android:name=
     "android.permission.SET_TIME_ZONE" /> 
    <uses-permission android:name=
     "android.permission.SET_WALLPAPER" /> 
    <uses-permission android:name=
     "android.permission.SET_WALLPAPER_HINTS" /> 
    <uses-permission android:name=
     "android.permission.SIGNAL_PERSISTENT_PROCESSES" /> 
    <uses-permission android:name=
     "android.permission.STATUS_BAR" /> 
    <uses-permission android:name=
     "android.permission.SUBSCRIBED_FEEDS_READ" /> 
    <uses-permission android:name=
     "android.permission.SUBSCRIBED_FEEDS_WRITE" /> 
    <uses-permission android:name=
     "android.permission.SYSTEM_ALERT_WINDOW" /> 
    <uses-permission android:name=
     "android.permission.UPDATE_DEVICE_STATS" /> 
    <uses-permission android:name=
     "android.permission.USE_CREDENTIALS" /> 
    <uses-permission android:name=
     "android.permission.USE_SIP" /> 
    <uses-permission android:name=
     "android.permission.WAKE_LOCK" /> 
    <uses-permission android:name=
     "android.permission.WRITE_APN_SETTINGS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_CALENDAR" /> 
    <uses-permission android:name=
     "android.permission.WRITE_CONTACTS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_GSERVICES" /> 
    <uses-permission android:name=
     "android.permission.WRITE_HISTORY_BOOKMARKS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_SECURE_SETTINGS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_SETTINGS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_SMS" /> 
    <uses-permission android:name=
     "android.permission.WRITE_SYNC_SETTINGS" /> 
    <uses-permission android:name=
     "android.permission.BIND_ACCESSIBILITY_SERVICE"/> 
    <uses-permission android:name=
     "android.permission.BIND_TEXT_SERVICE"/> 
    <uses-permission android:name=
     "android.permission.BIND_VPN_SERVICE"/> 
    <uses-permission android:name=
     "android.permission.PERSISTENT_ACTIVITY"/> 
    <uses-permission android:name=
     "android.permission.READ_CALL_LOG"/> 
    <uses-permission android:name=
     "com.android.browser.permission.READ_HISTORY_BOOKMARKS"/> 
    <uses-permission android:name=
     "android.permission.READ_PROFILE"/> 
    <uses-permission android:name=
     "android.permission.READ_SOCIAL_STREAM"/> 
    <uses-permission android:name=
     "android.permission.READ_USER_DICTIONARY"/> 
    <uses-permission android:name=
     "com.android.alarm.permission.SET_ALARM"/> 
    <uses-permission android:name=
     "android.permission.SET_PREFERRED_APPLICATIONS"/> 
    <uses-permission android:name=
     "android.permission.WRITE_CALL_LOG"/> 
    <uses-permission android:name=
     "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS"/> 
    <uses-permission android:name=
     "android.permission.WRITE_PROFILE"/> 
    <uses-permission android:name=
     "android.permission.WRITE_SOCIAL_STREAM"/> 
    <uses-permission android:name=
     "android.permission.WRITE_USER_DICTIONARY"/>  
```

# 请求权限

在 Android SDK 版本 23 之后，需要在运行时请求权限（并非所有权限）。这意味着我们也需要从代码中请求它们。我们将演示如何从我们的应用程序中执行此操作。我们将在用户打开应用程序时请求获取 GPS 位置所需的权限。如果没有获得批准，用户将收到一个对话框以批准权限。打开您的 `BaseActivity` 类，并将其扩展如下：

```kt
    abstract class BaseActivity : AppCompatActivity() {
      companion object { 
      val REQUEST_GPS = 0 
      ... }
      ... 
      override fun onCreate(savedInstanceState: Bundle?) {   
        super.onCreate(savedInstanceState)
        ...
        requestGpsPermissions() } 
     ...
     private fun requestGpsPermissions() {   
       ActivityCompat.requestPermissions( 
         this@BaseActivity,
         arrayOf( 
           Manifest.permission.ACCESS_FINE_LOCATION,
           Manifest.permission.ACCESS_COARSE_LOCATION ),
           REQUEST_GPS ) }
            ... 
      override fun onRequestPermissionsResult(
        requestCode:
         Int, permissions: Array<String>, grantResults: IntArray ) {
           if (requestCode == REQUEST_GPS) { 
            for (grantResult in grantResults) 
            { if (grantResult == PackageManager.PERMISSION_GRANTED)
             { Log.i( tag, String.format( Locale.ENGLISH, "Permission 
              granted [ %d ]", requestCode ) ) 
             } 
             else {
               Log.e( tag, String.format( Locale.ENGLISH, "Permission
               not granted [ %d ]", requestCode ) )
             } } } } }

```

那么这段代码到底是在做什么呢？我们将从上到下解释所有行。

在`companion`对象中，我们定义了我们请求的 ID。我们将等待该 ID 的结果。在`onCreate()`方法中，我们调用了`requestGpsPermissions()`方法，实际上是在我们定义的 ID 下进行权限请求。权限请求的结果将在`onRequestPermissionsResult()`重写方法中可用。如你所见，我们正在记录权限请求的结果。应用现在可以检索 GPS 数据。

对于所有其他安卓权限，原则是相同的。构建你的应用并运行它。将会询问你权限，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/ae6af33a-4ea1-4a16-ab34-4801233b8808.png)

# 用 Kotlin 的方式来做

如果我们的应用程序需要通过代码处理很多权限，会发生什么？这意味着我们有很多处理不同权限请求的代码。幸运的是，我们正在使用 Kotlin。Kotlin 将是我们简化事情的工具！

创建一个名为`permission`的新包。然后创建两个新的 Kotlin 文件如下：

`PermissionCompatActivity`和`PermissionRequestCallback`。

让我们定义权限请求回调如下：

```kt
     package com.journaler.permission 

     interface PermissionRequestCallback { 
       fun onPermissionGranted(permissions: List<String>) 
       fun onPermissionDenied(permissions: List<String>) 
     } 
```

这将是在解决权限时触发的`callback`。然后，定义我们的权限`compat`活动：

```kt
     package com.journaler.permission 

     import android.content.pm.PackageManager 
     import android.support.v4.app.ActivityCompat 
     import android.support.v7.app.AppCompatActivity 
     import android.util.Log 
     import java.util.concurrent.ConcurrentHashMap 
     import java.util.concurrent.atomic.AtomicInteger 

     abstract class PermissionCompatActivity : AppCompatActivity() { 

       private val tag = "Permissions extension" 
       private val latestPermissionRequest = AtomicInteger() 
       private val permissionRequests = ConcurrentHashMap<Int,
       List<String>>() 
       private val permissionCallbacks =  
        ConcurrentHashMap<List<String>, PermissionRequestCallback>() 

       private val defaultPermissionCallback = object :  
       PermissionRequestCallback { 
         override fun onPermissionGranted(permissions: List<String>) { 
            Log.i(tag, "Permission granted [ $permissions ]") 
         } 
         override fun onPermissionDenied(permissions: List<String>) { 
            Log.e(tag, "Permission denied [ $permissions ]") 
         } 
      } 

     fun requestPermissions( 
        vararg permissions: String,  
        callback: PermissionRequestCallback = defaultPermissionCallback 
     ) { 
        val id = latestPermissionRequest.incrementAndGet() 
        val items = mutableListOf<String>() 
        items.addAll(permissions) 
        permissionRequests[id] = items 
        permissionCallbacks[items] = callback 
        ActivityCompat.requestPermissions(this, permissions, id) 
     } 

     override fun onRequestPermissionsResult( 
        requestCode: Int,  
        permissions: Array<String>,  
        grantResults: IntArray 
     ) { 
        val items = permissionRequests[requestCode] 
        items?.let { 
           val callback = permissionCallbacks[items] 
           callback?.let { 
             var success = true 
              for (x in 0..grantResults.lastIndex) { 
                  val result = grantResults[x] 
                  if (result != PackageManager.PERMISSION_GRANTED) { 
                      success = false 
                      break 
                  } 
              } 
              if (success) { 
                 callback.onPermissionGranted(items) 
              } else { 
                  callback.onPermissionDenied(items) 
              } 
             } 
           } 
         } 
     }
```

这个类的理念是--我们向终端用户公开了`requestPermissions()`方法，该方法接受表示我们感兴趣的权限的可变数量的参数。我们可以传递（我们刚刚定义的）可选的`callback`（接口）。如果我们不传递自己的`callback`，将使用默认的`callback`。在权限解决后，我们触发`callback`。只有当所有权限都被授予时，我们才认为权限解决成功。

让我们更新我们的`BaseActivity`类如下：

```kt
     abstract class BaseActivity : PermissionCompatActivity() { 
     ... 
     override fun onCreate(savedInstanceState: Bundle?) { 
         ... 
         requestPermissions( 
            Manifest.permission.ACCESS_FINE_LOCATION, 
            Manifest.permission.ACCESS_COARSE_LOCATION 
         ) 
     } 
     ... 
    } 
```

如你所见，我们从`BaseActivity`类中删除了所有先前与权限相关的代码，并用一个`requestPermission()`调用替换了它。

# 总结

本章可能很短，但你学到的信息非常宝贵。每个安卓应用都需要权限。它们存在是为了保护用户和开发者。正如你所见，根据你的需求，有很多不同的权限可以使用。

在下一章中，我们将继续讲解系统部分，你将学习数据库处理。
