# 精通 Kotlin 安卓开发（五）

> 原文：[`zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5`](https://zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：调整以获得高性能

我们刚刚掌握了与后端和 API 的工作。我们接近旅程的尽头，但还没有结束！我们必须涵盖一些非常重要的要点！其中之一是性能优化。我们将指导你通过一些在实现这一目标时的良好实践。思考到目前为止我们已经开发的代码，以及如何应用这些建议。

在本章中，我们将涵盖以下主题：

+   布局优化

+   优化以保护电池寿命

+   优化以获得最大的响应性

# 优化布局

为了实现最佳的 UI 性能，请遵循以下几点：

+   **优化你的布局层次结构**：避免嵌套布局，因为它可能会影响性能！例如，你可以有多个嵌套的`LinearLayout`视图。与此相反，切换到`RelativeLayout`。这可以显著提高性能！嵌套布局需要更多的处理能力用于计算和绘制。

+   **尽可能重用布局**：Android 提供了`<include />`来实现这一点。

看一个例子：

```kt
    to_be_included.xml: 
    <RelativeLayout xmlns:android=
    "http://schemas.android.com/apk/res/android" 

      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:background="@color/main_bg" 
      tools:showIn="@layout/includes" > 

      <TextView  
       android:id="@+id/title" 
       android:layout_width="wrap_content" 
       android:layout_height="wrap_content" 
     /> 

    </RelativeLayout>

    includes.xml 
      <LinearLayout xmlns:android=
      "http://schemas.android.com/apk/res/android" 
       android:orientation="vertical" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:background="@color/main_bg" 
      > 
       ... 
      <include layout="@layout/to_be_included"/> 
      ... 
    </LinearLayout> 
```

+   此外，可以使用`<merge>`。当在一个布局中包含另一个布局时，合并可以消除视图层次结构中多余的`view groups`。让我们看一个例子：

```kt
    to_merge.xml 
    <merge > 

     <ImageView 
        android:id="@+id/first" 
        android:layout_width="fill_parent" 
        android:layout_height="wrap_content" 
        android:src="img/first"/> 

     <ImageView 
        android:id="@+id/second" 
        android:layout_width="fill_parent" 
        android:layout_height="wrap_content" 
        android:src="img/second"/> 

   </merge> 
```

当我们在另一个布局中使用 include 包含`to_merge.xml`时，就像我们在之前的例子中所做的那样，Android 会忽略`<merge>`元素，并直接将我们的视图添加到`<include />`所放置的容器中：

+   只在需要时将布局包含到屏幕中--如果你暂时不需要视图，将其可见性设置为`Gone`而不是`Invisible`。`Invisible`仍会创建视图的实例。使用`Gone`时，Android 只有在可见性更改为`Visible`时才会实例化视图。

+   使用`ListView`或`GridView`等容器来保存你的数据组。我们已经在前一章中解释了为什么你应该使用它们。

# 优化电池寿命

有很多方法可以耗尽你的电池。其中一个例子就是在应用程序中做太多的工作。过多的处理会影响电池寿命。然而，我们将指出你可以节省电池的方法以及你必须避免的事情。遵循这些要点，并在开发应用程序时时刻牢记。

为了保持电池处于最佳状态，请遵循以下建议：

+   尽量减少网络通信。频繁的网络调用会影响电池寿命。因此，尽量使其达到最佳状态。

+   确定你的手机是否在充电。这可能是启动应用程序可能需要执行的密集和性能要求的操作的好时机。

+   监控连接状态，并且只有在连接状态正常时执行与连接相关的操作。

+   合理利用广播消息。频繁和不必要地发送广播消息会影响性能。考虑发送频率，并在不需要接收消息时注销接收器。

+   注意 GPS 的使用强度。频繁的位置请求会显著影响电池寿命。

# 保持你的应用程序响应

你有多少次使用某个 Android 应用程序时收到应用程序无响应的消息？为什么会发生这种情况？我们会解释！注意以下几点，以免发生同样的情况：

+   确保没有任何东西阻塞你的输入（任何密集的操作，特别是网络流量）。

+   不要在主应用程序线程上执行长时间的任务。

+   不要在广播接收器的`onReceive()`方法中执行长时间运行的操作。

+   尽量使用`AsyncTask`类。考虑使用`ThreadPoolExecutor`。

+   尽可能使用内容加载器。

+   避免同时执行太多线程。

+   如果要写入文件系统，请使用单独的线程。

如果您的应用程序仍然出现 ANR，或者应用程序表现迟缓，请使用诸如 systrace 和 Traceview 之类的工具来跟踪问题的根源。

# 摘要

在这一简短但重要的章节中，我们强调了关于维护和实现良好应用性能和响应能力的重要要点。这些建议在应用程序优化中至关重要。因此，如果您的应用程序不遵循这些规则，您必须相应地进行优化。通过完成这一章，我们涵盖了您开发 Android 应用程序所需的一切。在下一章中，我们将对其进行测试。准备好编写一些单元测试和仪器测试！


# 第十四章：测试

我们开发了一个代码基础庞大的应用程序。我们尝试过它，我们认为我们的应用程序没有错误。但是，我们可能是错的！有时，即使我们确信我们的应用程序没有错误，也可能发生一个危险的问题在等待。如何预防这种情况？简单！我们将编写测试来为我们检查我们的代码。在本章中，我们将向您介绍测试，并举例说明如何设置、编写和运行您的测试。

在本章中，我们将涵盖以下主题：

+   如何编写你的第一个测试

+   使用测试套件

+   如何测试 UI

+   运行测试

+   单元测试和仪器测试

# 添加依赖项

要运行测试，我们必须满足一些依赖关系。我们将通过扩展`build.gradle`来更新我们的应用程序配置，以支持测试并提供我们需要的类。打开`build.gradle`并扩展如下：

```kt
    apply plugin: "com.android.application" 
    apply plugin: "kotlin-android" 
    apply plugin: "kotlin-android-extensions" 

    repositories { 
      maven { url "https://maven.google.com" } 
    } 

    android { 
      ... 
      sourceSets { 
        main.java.srcDirs += [ 
                'src/main/kotlin', 
                'src/common/kotlin', 
                'src/debug/kotlin', 
                'src/release/kotlin', 
                'src/staging/kotlin', 
                'src/preproduction/kotlin', 
                'src/debug/java', 
                'src/release/java', 
                'src/staging/java', 
                'src/preproduction/java', 
                'src/testDebug/java', 
                'src/testDebug/kotlin', 
                'src/androidTestDebug/java', 
                'src/androidTestDebug/kotlin' 
        ] 
      } 
      ... 
      testOptions { 
        unitTests.returnDefaultValues = true 
      } 
    } 
    ... 
    dependencies { 
      ... 
      compile "junit:junit:4.12" 
      testCompile "junit:junit:4.12" 

      testCompile "org.jetbrains.kotlin:kotlin-reflect:1.1.51" 
      testCompile "org.jetbrains.kotlin:kotlin-stdlib:1.1.51" 

      compile "org.jetbrains.kotlin:kotlin-test:1.1.51" 
      testCompile "org.jetbrains.kotlin:kotlin-test:1.1.51" 

      compile "org.jetbrains.kotlin:kotlin-test-junit:1.1.51" 
      testCompile "org.jetbrains.kotlin:kotlin-test-junit:1.1.51" 

      compile 'com.android.support:support-annotations:26.0.1' 
      androidTestCompile 'com.android.support:support
     -annotations:26.0.1' 

      compile 'com.android.support.test:runner:0.5' 
      androidTestCompile 'com.android.support.test:runner:0.5' 

      compile 'com.android.support.test:rules:0.5' 
      androidTestCompile 'com.android.support.test:rules:0.5' 
     } 

    It is important to highlight use of: 
    testOptions { 
        unitTests.returnDefaultValues = true 
    } 
```

这将使我们能够测试内容提供程序并在我们的测试中使用所有相关的类。如果我们不启用此功能，我们将收到以下错误：

“错误：“方法...未模拟”！”

# 更新文件夹结构

文件夹结构和其中的代码必须遵循有关构建变体的约定。对于我们的测试，我们将使用结构的以下部分：

+   对于单元测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/d56a4a2f-44a1-42ee-ae48-190b8bae52f5.png)

+   对于仪器测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/48a54d74-4342-4be5-9366-c659aef0ebb0.png)

现在我们准备开始编写我们的测试！

# 编写你的第一个测试

定位您的单元测试的`root`包，并创建一个名为`NoteTest`的新类，如下所示：

```kt
    package com.journaler 

    import android.location.Location 
    import com.journaler.database.Content 
    import com.journaler.model.Note 
    import org.junit.Test 

    class NoteTest { 

      @Test 
      fun noteTest() { 
        val note = Note( 
                "stub ${System.currentTimeMillis()}", 
                "stub ${System.currentTimeMillis()}", 
                Location("Stub") 
        ) 

        val id = Content.NOTE.insert(note) 
        note.id = id 

        assert(note.id > 0) 
     } 
    } 
```

测试非常简单。它创建一个`Note`的新实例，触发我们的内容提供程序中的 CRUD 操作来存储它，并验证接收到的 ID。要运行测试，请从项目窗格中右键单击类，然后选择“运行'NoteTest'”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/61355d1a-8c22-47c5-9985-3a5f0c6fcaf7.png)

单元测试是这样执行的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/21744fcd-f174-416e-9441-e658353e6f83.png)

如您所见，我们成功地将我们的`Note`插入到数据库中。现在，在我们创建了第一个单元测试之后，我们将创建我们的第一个仪器测试。但在我们这样做之前，让我们解释一下单元测试和仪器测试之间的区别。仪器测试在设备或模拟器上运行。当您需要测试依赖于 Android 上下文的代码时，可以使用它们。让我们测试我们的主服务。在仪器测试的`root`包中创建一个名为`MainServiceTest`的新类，如下所示：

```kt
    package com.journaler 

    import android.content.ComponentName 
    import android.content.Context 
    import android.content.Intent 
    import android.content.ServiceConnection 
    import android.os.IBinder 
    import android.support.test.InstrumentationRegistry 
    import android.util.Log 
    import com.journaler.service.MainService 
    import org.junit.After 
    import org.junit.Before 
    import org.junit.Test 
    import kotlin.test.assertNotNull 

    class MainServiceTest { 

      private var ctx: Context? = null 
      private val tag = "Main service test" 

      private val serviceConnection = object : ServiceConnection { 
        override fun onServiceConnected(p0: ComponentName?, binder:
        IBinder?) { 
          Log.v(tag, "Service connected") 
        } 

        override fun onServiceDisconnected(p0: ComponentName?) { 
          Log.v(tag, "Service disconnected") 
        } 
     } 

     @Before 
     fun beforeMainServiceTest() { 
        Log.v(tag, "Starting") 
        ctx = InstrumentationRegistry.getInstrumentation().context 
     } 

     @Test 
     fun testMainService() { 
        Log.v(tag, "Running") 
        assertNotNull(ctx) 
        val serviceIntent = Intent(ctx, MainService::class.java) 
        ctx?.startService(serviceIntent) 
        val result = ctx?.bindService( 
           serviceIntent, 
           serviceConnection, 
           android.content.Context.BIND_AUTO_CREATE 
        ) 
        assert(result != null && result) 
     } 

     @After 
     fun afterMainServiceTest() { 
       Log.v(tag, "Finishing") 
       ctx?.unbindService(serviceConnection) 
       val serviceIntent = Intent(ctx, MainService::class.java) 
       ctx?.stopService(serviceIntent) 
    } 

   } 
```

要运行它，请创建一个新的配置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/85a20a53-90ab-485d-941d-ca0f27187f4c.png)

运行新创建的配置。您将被要求选择 Android 设备或模拟器实例，以在其上运行测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/458df6df-5f0c-47a8-b2e2-bb9485cb9004.png)

等待测试执行。恭喜！您已成功创建并运行了仪器测试。现在，为了练习，尽可能定义多个测试，以覆盖应用程序的所有代码。注意测试应该是单元测试还是仪器测试。

# 使用测试套件

**测试套件**是一组测试。我们将向您展示如何创建测试集合。创建一个测试来代表集合的容器。让我们称之为`MainSuite`：

```kt
    package com.journaler 

    import org.junit.runner.RunWith 
    import org.junit.runners.Suite 

    @RunWith(Suite::class) 
    @Suite.SuiteClasses( 
        DummyTest::class, 
        MainServiceTest::class 
    ) 
    class MainSuite  
```

重复我们在示例中为仪器测试所做的步骤来运行你的测试套件。

# 如何测试 UI

测试 UI 可以帮助我们防止用户发现意外情况、使应用崩溃或性能不佳。我们强烈建议您编写 UI 测试，以确保您的 UI 表现如预期。为此，我们将介绍 Espresso 框架。

首先，我们将添加以下依赖项：

```kt
    ... 
    compile 'com.android.support.test.espresso:espresso-core:2.2.2' 
    androidTestCompile 'com.android.support.test.espresso:espresso-
    core:2.2.2' 
    ... 
```

在编写和运行 Espresso 测试之前，在测试设备上禁用动画，因为这会影响测试、预期时间和行为。我们强烈建议您这样做！在您的设备上，转到设置|开发者选项|并关闭以下选项：

+   窗口动画比例

+   过渡动画比例

+   动画器持续时间比例

现在您已经准备好编写 Espresso 测试了。学习 Espresso 框架可能需要一些努力。对您来说可能会耗费一些时间，但它的好处将是巨大的！让我们来看一个 Espresso 测试的示例：

```kt
    @RunWith(AndroidJUnit4::class) 
    class MainScreenTest { 
       @Rule 
       val mainActivityRule =   
       ActivityTestRule(MainActivity::class.java) 

       @Test 
       fun testMainActivity(){ 
        onView((withId(R.id.toolbar))).perform(click()) 
        onView(withText("My dialog")).check(matches(isDisplayed())) 
      } 

   } 
```

我们已经确定我们将测试`MainActivity`类。在测试触发工具栏按钮点击后，我们检查对话框是否存在。我们通过检查标签可用性--`"My dialog"`来做到这一点。学习整个 Espresso 框架超出了本书的范围，但至少我们给了您一些可能性的提示。花些时间学习它，因为它肯定会帮助您！

# 运行测试

我们已经通过 Android Studio 执行了我们的测试。但是，一旦您编写了所有测试，您将希望一次运行它们所有。您可以为所有构建变体运行所有单元测试，但只能为特定风格或构建类型运行。插装测试也是如此。我们将向您展示使用 Journaler 应用程序的现有构建变体来执行此操作的几个示例。

# 运行单元测试

打开终端并导航到项目的`root`包。要运行所有单元测试，请执行以下命令行：

```kt
$ ./gtradlew test
```

这将运行我们编写的所有单元测试。测试将失败，因为`NoteTest`使用内容提供程序。为此，需要使用适当的`Runner`类来执行。默认情况下，Android Studio 会这样做。但是，由于这是一个单元测试，并且我们是从终端执行它，测试将失败。您会同意这个测试实际上是必须考虑为插装测试，因为它使用了 Android 框架组件。通常做法是，如果您的类依赖于 Android 框架组件，它必须作为插装测试来执行。因此，我们将`NoteTest`移动到插装测试目录中。现在我们没有任何单元测试。至少创建一个不依赖于 Android 框架组件的单元测试。您可以将现有的`DummyTest`移动到单元测试文件夹中以实现这一目的。从您的 IDE 中拖放它，并使用相同的命令重新运行测试。

要运行构建变体的所有测试，请执行以下命令行：

```kt
$ ./gradlew testCompleteDebug 
```

我们为`Complete`风格和`Debug`构建类型执行测试。

# 运行插装测试

要运行所有插装测试，请使用以下命令行：

```kt
$ ./gradlew connectedAndroidTest 
```

它的前提是已连接设备或正在运行的模拟器。如果有多台设备或模拟器存在，它们都将运行测试。

要运行构建变体的插装测试，请使用以下命令行：

```kt
$ ./gradlew connectedCompleteDebugAndroidTest 
```

这将触发`Connected`风格的所有插装测试，使用`Debug`构建类型。

# 总结

在本章中，我们学习了如何为我们的应用程序编写和运行测试。这是迈向生产的又一步。我们建立了一个书写良好且无 bug 的产品。很快，我们将实际发布它。请耐心等待，因为那一刻即将到来！


# 第十五章：迁移到 Kotlin

如果您有一个遗留项目或要迁移到 Kotlin 的现有 Java 模块，迁移应该很容易。做到这一点的人已经考虑到了这一点。正如您记得的，Kotlin 是可互操作的。因此，一些模块不需要完全迁移；相反，它们可以包含在 Kotlin 项目中。这取决于您的决定。因此，让我们准备好进行迁移！

在本章中，我们将涵盖以下主题：

+   准备迁移

+   转换类

+   重构和清理

# 准备迁移

正如我们所说，我们需要决定是否完全将我们的模块重写为 Kotlin，还是继续用 Kotlin 编写代码，但保留其在纯 Java 中的遗留。我们会怎么做？在本章中，我们将展示一点点。

在这一点上，我们的当前项目没有任何需要迁移的内容。因此，我们将创建一些代码。如果您没有具有包结构的 Java 源目录，请创建它。现在，添加以下包：

+   `activity`

+   `model`

这些包等同于我们已经在 Kotlin 源代码中拥有的包。在`activity`包中，添加以下类：

+   `MigrationActivity.java`代码如下：

```kt
       package com.journaler.activity; 

       import android.os.Bundle; 
       import android.support.annotation.Nullable; 
       import android.support.v7.app.AppCompatActivity; 

       import com.journaler.R; 

       public class MigrationActivity extends AppCompatActivity { 

        @Override 
        protected void onCreate(@Nullable Bundle savedInstanceState) { 
          super.onCreate(savedInstanceState); 
          setContentView(R.layout.activity_main); 
        } 

        @Override 
        protected void onResume() { 
          super.onResume(); 
        } 
       }
```

+   `MigrationActivity2.java`：确保其实现与`MigrationActivity.java`完全相同。我们只需要一些代码基础来展示和迁移。

在 Android `manifest`文件中注册两个活动，如下所示：

```kt
        <manifest xmlns:android=
        "http://schemas.android.com/apk/res/android" 
        package="com.journaler"> 
        ... 
        <application 
         ... 
        > 
        ... 
         <activity 
            android:name=".activity.MainActivity" 
            android:configChanges="orientation" 
            android:screenOrientation="portrait"> 
            <intent-filter> 
              <action android:name="android.intent.action.MAIN" /> 
              <category android:name=
              "android.intent.category.LAUNCHER" /> 
            </intent-filter> 
         </activity> 

         <activity 
            android:name=".activity.NoteActivity" 
            android:configChanges="orientation" 
            android:screenOrientation="portrait" /> 

         <activity 
            android:name=".activity.TodoActivity" 
            android:configChanges="orientation" 
            android:screenOrientation="portrait" /> 

         <activity 
            android:name=".activity.MigrationActivity" 
            android:configChanges="orientation" 
            android:screenOrientation="portrait" /> 

         <activity 
            android:name=".activity.MigrationActivity2" 
            android:configChanges="orientation" 
            android:screenOrientation="portrait" /> 
        </application> 

      </manifest> 
```

正如您所看到的，Java 代码与 Kotlin 代码一起使用没有任何问题。您的 Android 项目可以同时使用两者！现在，请考虑一下，您是否真的需要进行任何转换，还是您愿意保留现有的 Java 内容？让我们在`model`包中添加类：

+   `Dummy.java`代码如下：

```kt
        package com.journaler.model; 

        public class Dummy { 

          private String title; 
          private String content; 

          public Dummy(String title) { 
            this.title = title; 
          } 

          public Dummy(String title, String content) { 
            this.title = title; 
            this.content = content; 
          } 

          public String getTitle() { 
            return title; 
          } 

          public void setTitle(String title) { 
            this.title = title; 
          } 

          public String getContent() { 
            return content; 
          } 

         public void setContent(String content) { 
           this.content = content; 
         } 

       } 
```

+   `Dummy2.java`代码如下：

```kt
        package com.journaler.model; 

        import android.os.Parcel; 
        import android.os.Parcelable; 

        public class Dummy2 implements Parcelable { 

          private int count; 
          private float result; 

          public Dummy2(int count) { 
            this.count = count; 
            this.result = count * 100; 
         } 

         public Dummy2(Parcel in) { 
           count = in.readInt(); 
           result = in.readFloat(); 
         } 

         public static final Creator<Dummy2>
         CREATOR = new Creator<Dummy2>() { 
           @Override 
           public Dummy2 createFromParcel(Parcel in) { 
             return new Dummy2(in); 
           } 

           @Override 
           public Dummy2[] newArray(int size) { 
             return new Dummy2[size]; 
           } 
         }; 

         @Override 
         public void writeToParcel(Parcel parcel, int i) { 
           parcel.writeInt(count); 
           parcel.writeFloat(result); 
         } 

         @Override 
         public int describeContents() { 
           return 0; 
         } 

         public int getCount() { 
           return count; 
         } 

         public float getResult() { 
           return result; 
         } 
       }
```

让我们再次检查项目的 Kotlin 部分是否看到了这些类。在您的 Kotlin 源目录的根目录中创建一个新的`.kt`文件。让我们称之为`kotlin_calls_java.kt`：

```kt
    package com.journaler 

    import android.content.Context 
    import android.content.Intent 
    import com.journaler.activity.MigrationActivity 
    import com.journaler.model.Dummy2 

    fun kotlinCallsJava(ctx: Context) { 

      /** 
      * We access Java class and instantiate it. 
      */ 
      val dummy = Dummy2(10) 

      /** 
      * We use Android related Java code with no problems as well. 
      */ 
       val intent = Intent(ctx, MigrationActivity::class.java) 
       intent.putExtra("dummy", dummy) 
       ctx.startActivity(intent) 

    } 
```

正如您所看到的，Kotlin 在使用 Java 代码时没有任何问题。因此，如果您仍然希望进行迁移，您可以这样做。没问题。我们将在接下来的章节中这样做。

# 危险信号

将庞大和复杂的 Java 类转换为 Kotlin 仍然是一个可选项。无论如何，提供适当的单元测试或仪器测试，以便在转换后重新测试这些类的功能。如果您的任何测试失败，请仔细检查失败的原因。

您想要迁移的类可以通过以下两种方式进行迁移：

+   自动转换

+   手动重写

在处理庞大和复杂的类时，这两种方法都可能会带来一些缺点。完全自动转换有时会给您带来不太美观的代码。因此，在完成后，您应该重新检查和重新格式化一些内容。第二个选项可能会花费您很多时间。

结论-您始终可以使用原始的 Java 代码。从您将 Kotlin 作为主要语言开始，您可以用 Kotlin 编写所有新的东西。

# 更新依赖关系

如果您将 Android 项目的 100%纯 Java 代码切换到 Kotlin，您必须从头开始。这意味着您的第一个迁移工作将是更新您的依赖关系。您必须更改`build.gradle`配置，以便识别 Kotlin 并使源代码路径可用。我们已经在第一章中解释了如何在*开始 Android*中设置 Gradle 部分; 因此，如果您的项目中没有与 Kotlin 相关的配置，您必须提供它。

让我们回顾一下我们的 Gradle 配置：

+   `build.gradle`根项目代表了主`build.gradle`文件，如下所示：

```kt
        buildscript { 
          repositories { 
            jcenter() 
            mavenCentral() 
          } 
          dependencies { 
            classpath 'com.android.tools.build:gradle:2.3.3' 
            classpath 'org.jetbrains.kotlin:kotlin-gradle-
            plugin:1.1.51' 
          } 
       } 

      repositories { 
       jcenter() 
       mavenCentral() 
      }
```

+   主应用程序`build.gradle`解决了应用程序的所有依赖关系，如下所示：

```kt
        apply plugin: "com.android.application" 
        apply plugin: "kotlin-android" 
        apply plugin: "kotlin-android-extensions" 

        repositories { 
          maven { url "https://maven.google.com" } 
        } 

        android { 
         ... 
         sourceSets { 
          main.java.srcDirs += [ 
                'src/main/kotlin', 
                'src/common/kotlin', 
                'src/debug/kotlin', 
                'src/release/kotlin', 
                'src/staging/kotlin', 
                'src/preproduction/kotlin', 
                'src/debug/java', 
                'src/release/java', 
                'src/staging/java', 
                'src/preproduction/java', 
                'src/testDebug/java', 
                'src/testDebug/kotlin', 
                'src/androidTestDebug/java', 
                'src/androidTestDebug/kotlin' 
           ] 
          } 
          ... 
          } 
         ... 
        } 

        repositories { 
          jcenter() 
          mavenCentral() 
        } 

        dependencies { 
          compile "org.jetbrains.kotlin:kotlin-reflect:1.1.51" 
          compile "org.jetbrains.kotlin:kotlin-stdlib:1.1.51" 
           ... 
          compile "com.github.salomonbrys.kotson:kotson:2.3.0" 
            ... 

          compile "junit:junit:4.12" 
          testCompile "junit:junit:4.12" 

          testCompile "org.jetbrains.kotlin:kotlin-reflect:1.1.51" 
          testCompile "org.jetbrains.kotlin:kotlin-stdlib:1.1.51" 

          compile "org.jetbrains.kotlin:kotlin-test:1.1.51" 
          testCompile "org.jetbrains.kotlin:kotlin-test:1.1.51" 

          compile "org.jetbrains.kotlin:kotlin-test-junit:1.1.51" 
          testCompile "org.jetbrains.kotlin:kotlin-test-junit:1.1.51" 
          ... 
        }
```

这些都是您应该满足的与 Kotlin 相关的依赖关系。其中之一是 Kotson，为`Gson`库提供 Kotlin 绑定。

# 转换类

最后，我们将迁移我们的类。我们有两种自动选项可用。我们将两种都使用。找到`MigrationActivity.java`并打开它。选择代码 | 将 Java 文件转换为`Kotlin`文件。转换需要几秒钟。现在，将文件从`Java`包拖放到`Kotlin`源包中。观察以下源代码：

```kt
    package com.journaler.activity 

    import android.os.Bundle 
    import android.support.v7.app.AppCompatActivity 

    import com.journaler.R 

    class MigrationActivity : AppCompatActivity() { 

      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        setContentView(R.layout.activity_main) 
      } 

      override fun onResume() { 
        super.onResume() 
      } 

    } 
```

正如我们所提到的，完全自动转换并不能得到完美的代码。在下一节中，我们将进行重构和清理。完成相同操作的第二种方法是将 Java 代码复制粘贴到`Kotlin`文件中。从`MigrationActivity2`中复制所有源代码。创建一个同名的新 Kotlin 类并粘贴代码。如果被询问，确认你希望执行自动转换。代码出现后，删除该类的 Java 版本。观察到源代码与迁移后的`MigrationActivity`类相同。

对`Dummy`和`Dummy2`类重复这两种方法。你得到的类将看起来像这样：

+   `Dummy`，第一个`Dummy`类示例：

```kt
       package com.journaler.model 

       class Dummy { 

         var title: String? = null 
         var content: String? = null 

         constructor(title: String) { 
           this.title = title 
         } 

         constructor(title: String, content: String) { 
           this.title = title 
           this.content = content 
        } 

      } 
```

+   `Dummy2`，第二个`Dummy`类示例：

```kt
        package com.journaler.model 

        import android.os.Parcel 
        import android.os.Parcelable 

        class Dummy2 : Parcelable { 

          var count: Int = 0 
          private set 
          var result: Float = 0.toFloat() 
          private set 

          constructor(count: Int) { 
            this.count = count 
            this.result = (count * 100).toFloat() 
          } 

          constructor(`in`: Parcel) { 
            count = `in`.readInt() 
            result = `in`.readFloat() 
          } 

          override fun writeToParcel(parcel: Parcel, i: Int) { 
            parcel.writeInt(count) 
            parcel.writeFloat(result) 
          } 

          override fun describeContents(): Int { 
            return 0 
          } 

         companion object { 

           val CREATOR: Parcelable.Creator<Dummy2>
           = object : Parcelable.Creator<Dummy2> { 
              override fun createFromParcel(`in`: Parcel): Dummy2 { 
                return Dummy2(`in`) 
            } 

           override fun newArray(size: Int): Array<Dummy2> { 
              return arrayOfNulls(size) 
            } 
          } 
        } 

    } 
```

`Dummy2`类在转换时出现了问题。在这种情况下，你必须自己修复它。修复源代码。问题发生在以下行：

```kt
    override fun newArray(size: Int): Array<Dummy2> { ... 
```

通过将类型从`Array<Dummy2> int Array<Dummy2?>`进行切换来修复它，如下所示：

```kt
    override fun newArsray(size: Int): Array<Dummy2?> { ... 
```

简单！

这正是你在进行迁移时可能会面临的挑战！显而易见的是，在`Dummy`和`Dummy2`类中，我们通过切换到 Kotlin 显著减少了代码库。由于不再有 Java 实现，我们可以进行重构和清理。

# 重构和清理

为了在转换后获得最佳可能的代码，我们必须进行重构和清理。我们将调整我们的代码库以符合 Kotlin 的标准和习惯用法。为此，你必须全面阅读它。只有在这样做之后，我们才能认为我们的迁移完成了！

打开你的类并阅读代码。有很多改进的空间！在你做一些工作之后，你应该得到类似这样的结果：

`MigrationActivity`的代码如下：

```kt
    ... 
    override fun onResume() = super.onResume() 
    ... 
```

正如你所看到的，对于`MigrationActivity`（和`MigrationActivity2`）来说，并没有太多的工作。这两个类都非常小。对于`Dummy`和`Dummy2`这样的类，预计需要更大的努力：

+   `Dummy`类的代码如下：

```kt
        package com.journaler.model 

        class Dummy( 
          var title: String, 
          var content: String 
          ) { 

            constructor(title: String) : this(title, "") { 
            this.title = title 
           } 

       } 
```

+   `Dummy2`类的代码如下：

```kt
        package com.journaler.model 

        import android.os.Parcel 
        import android.os.Parcelable 

        class Dummy2( 
          private var count: Int 
        ) : Parcelable { 

          companion object { 
            val CREATOR: Parcelable.Creator<Dummy2> 
            = object : Parcelable.Creator<Dummy2> { 
              override fun createFromParcel(`in`: Parcel): 
              Dummy2 = Dummy2(`in`) 
              override fun newArray(size: Int): Array<Dummy2?> =
              arrayOfNulls(size) 
            }    
          } 

         private var result: Float = (count * 100).toFloat() 

         constructor(`in`: Parcel) : this(`in`.readInt()) 

         override fun writeToParcel(parcel: Parcel, i: Int) { 
           parcel.writeInt(count) 
         } 

         override fun describeContents() = 0 

        } 
```

这两个类版本在重构后与它们最初的 Kotlin 版本相比，现在得到了极大的改进。试着将当前版本与我们最初的 Java 代码进行比较。你觉得呢？

# 总结

在本章中，我们发现了迁移到 Kotlin 编程语言的秘密。我们演示了技术并提供了如何进行迁移以及何时进行迁移的建议。幸运的是，对我们来说，这似乎并不难！下一章将是我们的最后一章，所以，正如你已经知道的，是时候将我们的应用发布到世界上了！


# 第十六章：部署您的应用程序

是时候让世界看到您的作品了。在我们发布之前还有一些事情要做。我们将做一些准备工作，然后最终将我们的应用程序发布到 Google Play 商店。

在本章中，我们将熟悉以下主题：

+   准备部署

+   代码混淆

+   签署您的应用程序

+   发布到 Google Play

# 准备部署

在发布您的应用程序之前，需要做一些准备工作。首先，删除任何未使用的资源或类。然后，关闭您的日志记录！使用一些主流的日志记录库是一个好习惯。您可以围绕`Log`类创建一个包装器，并且对于每个日志输出都有一个条件，检查它必须不是`release`构建类型。

如果您尚未将发布配置设置为可调试，请按照以下步骤操作：

```kt
    ... 
    buildTypes { 
      ... 
      release { 
        debuggable false 
      } 
    } 
    ...
```

完成后，请再次检查您的清单并进行清理。删除您不再需要的任何权限。在我们的情况下，我们将删除这个：

```kt
    <uses-permission android:name="android.permission.VIBRATE" /> 
```

我们添加了它，但从未使用过。我们要做的最后一件事是检查应用程序的兼容性。检查最小和最大 SDK 版本是否符合您的设备定位计划。

# 代码混淆

发布到 Google Play

```kt
    ... 
    buildTypes { 
      ... 
      release { 
        debuggable false 
        minifyEnabled true 
        proguardFiles getDefaultProguardFile('proguard-android.txt'),
         'proguard-rules.pro' 
      } 
    } 
    ... 
```

我们刚刚添加的配置将缩小资源并执行混淆。对于混淆，我们将使用 ProGuard。ProGuard 是一个免费的 Java 类文件缩小器，优化器，混淆器和预验证器。它执行检测未使用的类，字段，方法和属性。它还优化了字节码！

在大多数情况下，默认的 ProGuard 配置（我们使用的那个）足以删除所有未使用的代码。但是，ProGuard 可能会删除您的应用程序实际需要的代码！出于这个目的，您必须定义 ProGuard 配置以保留这些类。打开项目的 ProGuard 配置文件并追加以下内容：

```kt
    -keep public class MyClass 
```

以下是使用某些库时需要添加的 ProGuard 指令列表：

+   Retorfit：

```kt
        -dontwarn retrofit.** 
        -keep class retrofit.** { *; } 
        -keepattributes Signature 
        -keepattributes Exceptions 
```

+   下一步是启用代码混淆。打开您的`build.gradle`配置并更新如下：

```kt
        -keepattributes Signature 
        -keepattributes *Annotation* 
        -keep class okhttp3.** { *; } 
        -keep interface okhttp3.** { *; } 
        -dontwarn okhttp3.** 
        -dontnote okhttp3.** 

        # Okio 
        -keep class sun.misc.Unsafe { *; } 
        -dontwarn java.nio.file.* 
        -dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement 
```

+   Gson：

```kt
        -keep class sun.misc.Unsafe { *; } 
        -keep class com.google.gson.stream.** { *; } 
```

使用这些行更新您的`proguard-rules.pro`文件。

# 签署您的应用程序

在将发布上传到 Google Play 商店之前的最后一步是生成已签名的 APK。打开您的项目并选择构建|生成已签名的 APK：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/49eb70fe-9f7e-4f44-b646-e425ec6b3cad.png)

选择主应用程序模块，然后继续单击“下一步”：

Okhttp3：

由于我们还没有密钥库，我们将创建一个新的。点击“创建新...”如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/2c205bcd-e71f-44d2-8f4e-c50cff51b272.png)

填充数据并单击“确定”。单击“下一步”，如果需要，输入您的主密码。检查两个签名并选择完整的口味进行构建。单击“完成”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/308f8900-ff9d-4e84-9cea-0098eda58306.png)

等待构建准备就绪。我们还将更新我们的`build.gradle`，以便每次构建发布时都进行签名：

```kt
    ... 
    android { 
      signingConfigs { 
        release { 
          storeFile file("Releasing/keystore.jks") 
          storePassword "1234567" 
          keyAlias "key0" 
          keyPassword "1234567" 
        } 
      } 
      release { 
        debuggable false 
        minifyEnabled false 
        signingConfig signingConfigs.release 
        proguardFiles getDefaultProguardFile('proguard-android.txt'),
        'proguard-rules.pro' 
      } 
    } 
    ... 
```

如果对您来说更容易，您可以按照以下步骤从终端运行构建过程：

```kt
$ ./gradlew clean 
$ ./gradlew assembleCompleteRelease 
```

在本例中，我们为完整的应用程序口味组装了发布版本。

# ![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e91f2daf-47ee-4d5d-a6f7-3cec3fea8bab.png)

部署的最后一步将是发布已签名的发布 APK。除了 APK，我们还需要提供一些其他东西：

+   屏幕截图-从您的应用程序准备屏幕截图。您可以通过以下方式完成：从 Android Studio Logcat，单击屏幕截图图标（一个小相机图标）。从预览窗口，单击保存。将要求您保存图像：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/d3dd5720-451e-41ef-a04c-7395a83ee1f8.png)

+   具有以下规格的高分辨率图标：

32 位 PNG 图像（带 Alpha）

512 像素乘以 512 像素的尺寸

1024K 最大文件大小

+   功能图形（应用程序的主横幅）：

JPEG 图像或 24 位 PNG（无 Alpha！）

1024 像素乘以 500 像素的尺寸

+   如果您将应用程序发布为电视应用程序或电视横幅：

JPEG 图像或 24 位的 PNG（不带 alpha！）

1280p x 720px 的尺寸

+   促销视频--YouTube 视频（不是播放列表）

+   您的应用程序的文本描述

登录到开发者控制台（[`play.google.com/apps/publish`](https://play.google.com/apps/publish)）。

如果您尚未注册，请注册。这将使您能够发布您的应用程序。主控制台页面显示如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/748b6eb6-26d9-4e52-8251-fa824627fccc.png)

我们还没有发布任何应用程序。点击“在 Google Play 上发布 Android 应用程序”。将出现一个创建应用程序对话框。填写数据，然后点击“创建”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/b011a954-fe73-49a7-91a8-a0e53dc7040f.png)

填写表单数据如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e84ab21e-0d8e-4d1f-be8a-1280111c2a0d.png)

按照以下方式上传您的图形资产：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/d7d6acff-79f1-4463-baa1-54641c122e3b.png)

请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/140beb1a-0bd4-403a-a8ca-1d6cc7ff5248.png)

继续进行应用程序分类：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/35705756-8468-4a8b-b092-13473aad782e.png)

完成联系信息和隐私政策：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1b064350-2117-4270-9c19-0deee14fb357.png)

当您完成了所有必填数据后，滚动回到顶部，然后点击“保存草稿”按钮。现在从左侧选择“应用发布”。您将被带到应用发布屏幕，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/ba919353-3b71-4629-b38e-1faffcd17d61.png)

在这里，您有以下三个选项：

+   管理生产

+   管理测试版

+   管理测试版

根据您计划发布的版本，选择最适合您的选项。我们将选择“管理生产”，然后点击“创建发布”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1f8dcc94-51ef-4fd8-9bd0-7db80f70d5fe.png)

开始填写有关您发布的数据：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/ac2f0734-e8c3-4638-8ff4-38fcfaa6bca9.png)

首先，添加您最近生成的 APK。然后继续到页面底部，填写表单的其余部分。完成后，点击“审核”按钮以审核您的应用程序发布：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/16903c77-3eb7-4660-ae8f-0ee07e07b94d.png)

在将我们的发布推向生产之前，点击左侧的内容评级链接，然后点击继续，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/82efc67e-f497-45f9-b2d5-14c686fd1cc4.png)

填写您的**电子邮件地址**并滚动到页面的底部。选择您的类别：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/6af9a068-5f32-4e6f-8e1a-14fa467d75d4.png)

我们选择 UTILITY，PRODUCTIVITY，COMMUNICATION，OR OTHER；在下一个屏幕上，填写您被要求的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/f5885ed0-0798-40c1-a5b5-a53c59fff9fd.png)

保存您的问卷，并点击“应用评级”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/2a1a5151-25b4-41ca-9c2c-aed9617cb7fa.png)

现在切换到定价和分发部分：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/05cfc1cb-241a-42e5-865a-50b8573fab55.png)

这个表格很容易填写。按照表格设置您被要求的数据。完成后，点击屏幕顶部的保存草稿按钮。您会看到“准备发布”链接已经出现。点击它：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1f5e67ad-6b07-4a15-9a1a-e1bccb3545ac.png)

点击“管理发布”，如前面的屏幕截图所示。按照屏幕的指引，直到您到达应用发布部分的最后一个屏幕。现在您可以清楚地看到“开始推出到生产”按钮已启用。点击它，当被询问时，点击“确认”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/01500c44-bef2-4356-8444-d543d5eb9355.png)

继续：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/35e5cf11-d1cf-4e5b-af68-ea794787e441.png)

就是这样！您已成功将您的应用程序发布到 Google Play 商店！

# 总结

希望您喜欢这本书！这是一次伟大的旅程！我们从零开始，从学习基础知识开始。然后，我们继续学习关于 Android 的中级，困难和高级主题。这一章让我们对我们想要告诉您的关于 Android 的故事有了最后的总结。我们做了大量的工作！我们开发了应用程序，并逐步完成了整个部署过程。

接下来呢？嗯，你接下来应该做的事情是考虑一个你想要构建的应用程序，并从零开始着手制作它。花点时间。不要着急！在开发过程中，你会发现很多我们没有提到的东西。安卓系统非常庞大！要了解整个框架可能需要几年的时间。许多开发者并不了解它的每一个部分。你不会是唯一一个。继续你的进步，尽可能多地编写代码。这将提高你的技能，并使你学到的所有东西变得常规化。不要犹豫！投入行动吧！祝你好运！
