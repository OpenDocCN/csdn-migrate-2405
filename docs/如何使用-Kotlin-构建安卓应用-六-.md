# 如何使用 Kotlin 构建安卓应用（六）

> 原文：[`zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295`](https://zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 Dagger 和 Koin 进行依赖注入

概述

本章涵盖了依赖注入的概念以及它为 Android 应用程序提供的好处。我们将看看如何通过容器类手动执行依赖注入。我们还将介绍一些可用于 Android、Java 和 Kotlin 的框架，这些框架可以帮助开发人员应用这一概念。通过本章的学习，您将能够使用 Dagger 和 Koin 来管理应用程序的依赖项，并且将知道如何有效地组织它们。

# 介绍

在上一章中，我们看到了如何将代码结构化为不同的组件，包括 ViewModels、repositories、API 组件和持久性组件。其中一个经常出现的困难是所有这些组件之间的依赖关系，特别是当我们为它们编写单元测试时。

我们一直使用`Application`类来创建这些组件的实例，并将它们传递给上一层组件的构造函数（我们创建了 API 和 Room 实例，然后是 Repository 实例，依此类推）。我们所做的是依赖注入的简化版本。

`ViewModels`）。这样做的原因是为了增加代码的可重用性和可测试性，并将创建实例的责任从我们的组件转移到`Application`类。DI 的一个好处在于对象在整个代码库中的创建方式。DI 将对象的创建与其使用分离。换句话说，一个对象不应该关心另一个对象是如何创建的；它只应该关心与另一个对象的交互。

在本章中，我们将分析在 Android 中注入依赖项的三种方式：手动 DI、Dagger 和 Koin。

**手动 DI**是一种技术，开发人员通过创建容器类来手动处理 DI。在本章中，我们将看看如何在 Android 中实现这一点。通过研究我们如何手动管理依赖项，我们将了解其他 DI 框架的运作方式，并为我们如何集成这些框架奠定基础。

**Dagger**是为 Java 开发的 DI 框架。它允许您将依赖项分组到不同的**模块**中。您还可以定义**组件**，在这些组件中添加模块以创建依赖图，Dagger 会自动实现以执行注入。它依赖于注解处理器来生成必要的代码以执行注入。

**Koin**是为 Kotlin 开发的轻量级 DI 库。它不依赖于注解处理器；它依赖于 Kotlin 的机制来执行注入。在这里，我们还可以将依赖项拆分成**模块**。

接下来，我们将探讨这两个库的工作原理以及将它们添加到简单 Android 应用程序所需的步骤。

# 手动 DI

为了理解 DI 的工作原理，我们可以首先分析如何在 Android 应用程序中手动注入依赖项到不同的对象中。这可以通过创建包含应用程序中所需依赖项的容器对象来实现。您还可以创建代表应用程序中所需不同范围的多个容器。在这里，您可以定义只在特定屏幕显示时才需要的依赖项，并且当屏幕被销毁时，实例也可以被垃圾回收。

这里展示了一个将持续存在应用程序的实例的容器示例：

```kt
class AppContainer(applicationContext:Context) {
    val myRepository: MyRepository
    init {
        val retrofit =           Retrofit.Builder().baseUrl("https://google.com/").build()
        val myService=           retrofit.create<MyService>(MyService::class.java)
        val database = Room.databaseBuilder(applicationContext,           MyDatabase::class.java, "db").build()
        myRepository = MyRepositoryImpl(myService, database.myDao())
    }
}
```

使用该容器的`Application`类如下所示：

```kt
class MyApplication : Application() {
    lateinit var appContainer: AppContainer
    override fun onCreate() {
        super.onCreate()
        appContainer = AppContainer(this)
    }
}
```

正如您在前面的示例中所看到的，创建依赖项的责任已经从`Application`类转移到了`Container`类。代码库中的活动仍然可以使用以下命令访问依赖项：

```kt
    override fun onCreate(savedInstanceState: Bundle?) {
        .... 
        val myRepository = (application as           MyApplication).appContainer. myRepository
        ...
}
```

具有有限范围的模块可以用于创建`ViewModel`工厂之类的东西，这些工厂又被框架用来创建`ViewModel`：

```kt
class MyContainer(private val myRepository: MyRepository) {
    fun geMyViewModelFactory(): ViewModelProvider.Factory {
        return object : ViewModelProvider.Factory {
            override fun <T : ViewModel?> create(modelClass:               Class<T>): T {
                return MyViewModel(myRepository) as T
            }
        }
    }
}
```

这个特定的容器可以被一个活动或片段用来初始化`ViewModel`：

```kt
class MyActivity : AppCompatActivity() {
    private lateinit var myViewModel: MyViewModel
    private lateinit var myContainer: MyContainer
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ....
        val myRepository = (application as           MyApplication).appContainer. myRepository
        myContainer = MyContainer (myRepository)
        myViewModel = ViewModelProvider(this,           myContainer.geMyViewModelFactory())            .get(MyViewModel::class.java)
    }
}
```

再次，我们在这里看到，创建`Factory`类的责任已从`Activity`类转移到`Container`类。`MyContainer`可以扩展以在需要的情况下提供与活动相同的实例，或者构造函数可以扩展以提供具有不同生命周期的实例。

现在，让我们将其中一些示例应用于练习。

## 练习 12.01：手动注入

在这个练习中，我们将编写一个应用程序，应用手动 DI 的概念。该应用程序将具有一个存储库，该存储库将生成一个随机数，并具有一个`ViewModel`对象，其中包含一个`LiveData`对象，负责检索存储库生成的数字并在`LiveData`对象中发布它。为了做到这一点，我们需要创建两个管理以下依赖项的容器：

+   存储库

+   负责创建`ViewModel`的`ViewModel`工厂

应用程序本身将在每次点击按钮时显示随机生成的数字：

1.  让我们首先将`ViewModel`和`LiveData`库添加到`app/build.gradle`文件中：

```kt
    implementation "androidx.lifecycle:lifecycle-      extensions:2.2.0"
```

1.  接下来，让我们编写一个`NumberRepository`接口，其中将包含一个检索整数的方法：

```kt
interface NumberRepository {
    fun generateNextNumber(): Int
}
```

1.  现在，我们将为此提供实现。我们可以使用`java.util.Random`类来生成随机数：

```kt
class NumberRepositoryImpl(private val random: Random) :   NumberRepository {
    override fun generateNextNumber(): Int {
        return random.nextInt()
    }
}
```

1.  我们现在将继续创建`MainViewModel`类，其中将包含一个包含存储库中每个生成的数字的`LiveData`对象：

```kt
class MainViewModel(private val numberRepository:   NumberRepository) : ViewModel() {
    private val numberLiveData = MutableLiveData<Int>()
    fun getLiveData(): LiveData<Int> = numberLiveData
    fun generateNextNumber() {
        numberLiveData.postValue(numberRepository           .generateNextNumber())
    }
}
```

1.  接下来，让我们继续创建包含用于显示数字的`TextView`和用于生成下一个随机数字的`Button`的 UI。这将成为`res/layout/activity_main.xml`文件的一部分：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:gravity="center"
    android:orientation="vertical">
    <TextView
        android:id="@+id/activity_main_text_view"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
    <Button
        android:id="@+id/activity_main_button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/randomize" />
</LinearLayout>
```

1.  确保将按钮的字符串添加到`res/values/strings.xml`文件中：

```kt
   <string name="randomize">Randomize</string>
```

1.  现在让我们创建负责呈现前述 UI 的`MainActivity`类：

```kt
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }
}
```

1.  现在，让我们创建我们的`Application`类：

```kt
class RandomApplication : Application() {
    override fun onCreate() {
        super.onCreate()
    }
}
```

1.  让我们还将`Application`类添加到`AndroidManifest.xml`文件中的`application`标签中：

```kt
    <application
        ...
        android:name=".RandomApplication"
.../>
```

1.  现在，让我们创建我们的第一个容器，负责管理`NumberRepository`依赖项：

```kt
class ApplicationContainer {
    val numberRepository: NumberRepository =       NumberRepositoryImpl(Random())
}
```

1.  让我们将此容器添加到`RandomApplication`类中：

```kt
class RandomApplication : Application() {
    val applicationContainer = ApplicationContainer()
    override fun onCreate() {
        super.onCreate()
    }
}
```

1.  我们现在继续创建`MainContainer`，它将需要引用`NumberRepository`依赖项，并将提供一个依赖项给创建`MainViewModel`所需的`ViewModel`工厂：

```kt
class MainContainer(private val numberRepository:   NumberRepository) {
    fun getMainViewModelFactory(): ViewModelProvider.Factory {
        return object : ViewModelProvider.Factory {
            override fun <T : ViewModel?> create(modelClass:               Class<T>): T {
                return MainViewModel(numberRepository) as T
            }
        }
    }
}
```

1.  最后，我们可以修改`MainActivity`以从我们的容器中注入依赖项，并连接 UI 元素以显示输出：

```kt
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val mainContainer = MainContainer((application as           RandomApplication).applicationContainer             .numberRepository)
        val viewModel = ViewModelProvider(this,           mainContainer.getMainViewModelFactory())            .get(MainViewModel::class.java)
        viewModel.getLiveData().observe(this, Observer {
            findViewById<TextView>              (R.id.activity_main_text_view).text = it.toString()
        }
        )
        findViewById<TextView>(R.id.activity_main_button)          .setOnClickListener {
            viewModel.generateNextNumber()
        }
    }
}
```

1.  在突出显示的代码中，我们可以看到我们正在使用`ApplicationContainer`中定义的存储库，并将其注入到`MainContainer`中，然后通过`ViewModelProvider.Factory`将其注入到`ViewModel`中。前面的示例应该呈现出*图 12.1*中呈现的输出：

![图 12.1：练习 12.01 的模拟器输出，显示随机生成的数字](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_01.jpg)

图 12.1：练习 12.01 的模拟器输出，显示随机生成的数字

手动 DI 是在应用程序较小的情况下设置依赖项的一种简单方法，但随着应用程序的增长，它可能变得非常困难。想象一下，在*练习 12.01*，*手动注入*中，我们有两个类都扩展自`NumberRepository`。我们将如何处理这种情况？开发人员如何知道哪个类适用于哪个活动？这些类型的问题在 Google Play 上大多数知名应用程序中变得非常普遍，这就是为什么很少使用手动 DI。在使用时，它可能会采用我们接下来将要查看的 DI 框架类似的形式。

# Dagger

Dagger 提供了一种全面组织应用程序依赖关系的方式。它在 Kotlin 引入之前首先被 Android 开发者社区采用，这是许多 Android 应用程序将 Dagger 作为它们的 DI 框架的原因之一。该框架的另一个优势是对于用 Java 编写的 Android 项目，因为该库也是用相同的语言开发的。该框架最初由 Square（Dagger 1）开发，后来过渡到了 Google（Dagger 2）。我们将在本章中介绍 Dagger 2 并描述其优势。Dagger 2 提供的一些关键功能包括：

+   注入

+   模块化的依赖项

+   用于生成依赖图的组件

+   限定符

+   作用域

+   子组件

注解是处理 Dagger 时的关键元素，因为它生成所需的代码来执行通过注解处理器进行 DI。主要注解可以分为以下几类：

+   `@Module`负责提供可以被注入的对象（依赖对象）。

+   `@Inject`注解用于定义依赖关系。

+   `@Component`注解的接口定义了提供者和消费者之间的连接。

为了将 Dagger 添加到您的项目中，在`app/build.gradle`文件中，您将需要以下依赖项：

```kt
implementation 'com.google.dagger:dagger:2.29.1' 
kapt 'com.google.dagger:dagger-compiler:2.29.1'
```

由于我们正在处理注解处理器，在同一个`build.gradle`文件中，您需要为它们添加插件：

```kt
apply plugin: 'com.android.application'
apply plugin: 'kotlin-android'
apply plugin: 'kotlin-kapt'
```

## 消费者

Dagger 使用`javax.inject.Inject`来识别需要注入的对象。有多种注入依赖的方式，但推荐的方式是通过构造函数注入和字段注入。构造函数注入看起来类似于以下代码：

```kt
import javax.inject.Inject
class ClassA @Inject constructor()
class ClassB @Inject constructor(private val classA: ClassA)
```

当构造函数被`@Inject`注解时，Dagger 将生成`Factory`类来负责实例化对象。在`ClassB`的示例中，Dagger 将尝试找到符合构造函数签名的适当依赖项，而在这个例子中，就是`ClassA`，而 Dagger 已经为其创建了一个实例。

如果您不希望 Dagger 管理`ClassB`的实例化，但仍然希望注入对`ClassA`的依赖关系，您可以使用字段注入，代码看起来会像这样：

```kt
import javax.inject.Inject
class ClassA @Inject constructor()
class ClassB {
    @Inject
    lateinit var classA: ClassA
}
```

在这种情况下，Dagger 将生成必要的代码来注入`ClassB`和`ClassA`之间的依赖关系。

## 提供者

您会发现自己处于应用程序使用外部依赖的情况。这意味着您将无法通过构造函数注入提供实例。另一种构造函数注入不可能的情况是使用接口或抽象类。在这种情况下，Dagger 提供了使用`@Provides`注解来提供实例的可能性。然后，您需要将提供实例的方法分组到用`@Module`注解的模块中：

```kt
import dagger.Module
import dagger.Provides
class ClassA
class ClassB(private val classA: ClassA)
@Module
object MyModule {
    @Provides
    fun provideClassA(): ClassA = ClassA()
    @Provides
    fun provideClassB(classA: ClassA): ClassB = ClassB(classA)
}
```

如前面的示例所示，`ClassA`和`ClassB`没有任何 Dagger 注解。创建了一个模块，将为`ClassA`提供实例，然后用于提供`ClassB`的实例。在这种情况下，Dagger 将为每个`@Provides`注解的方法生成一个`Factory`类。

## 连接器

假设我们将有多个模块，我们需要将它们组合成一个依赖图，可以在整个应用程序中使用。Dagger 提供了`@Component`注解。这通常用于由 Dagger 实现的接口或抽象类。除了组装依赖图之外，组件还提供了向某个对象的成员注入依赖的功能。在组件中，您可以指定返回模块中提供的依赖项的提供方法：

```kt
import dagger.Component
@Component(modules = [MyModule::class])
interface MyComponent {
    fun inject(myApplication: MyApplication)
}
```

对于前面的`Component`，Dagger 将生成一个`DaggerMyComponent`类，并且我们可以按照以下代码进行构建：

```kt
import android.app.Application
import javax.inject.Inject
class MyApplication : Application() {
    @Inject
    lateinit var classB: ClassB
    override fun onCreate() {
        super.onCreate()￼
        val component = DaggerMyComponent.create()
        //needs to build the project once to generate 
        //DaggerMyComponent.class
        component.inject(this)
    }
}
```

`Application`类将创建 Dagger 依赖项图和组件。`Component`中的`inject`方法允许我们对`Application`类中用`@Inject`注释的变量执行 DI，从而让我们访问模块中定义的`ClassB`对象。

## 限定符

如果要提供同一类的多个实例（例如在整个应用程序中注入不同的字符串或整数），可以使用限定符。这些是可以帮助您标识实例的注释。其中最常见的是`@Named`限定符，如下面的代码所述：

```kt
@Module
object MyModule {
    @Named("classA1")
    @Provides
    fun provideClassA1(): ClassA = ClassA()
    @Named("classA2")
    @Provides
    fun provideClassA2(): ClassA = ClassA()
    @Provides
    fun provideClassB(@Named("classA1") classA: ClassA): ClassB =       ClassB(classA)
}
```

在此示例中，我们创建了两个`ClassA`的实例，并为它们分配了不同的名称。然后，我们尽可能使用第一个实例来创建`ClassB`。我们还可以创建自定义限定符，而不是`@Named`注释，如下面的代码所述：

```kt
import javax.inject.Qualifier
@Qualifier
@MustBeDocumented
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class ClassA1Qualifier
@Qualifier
@MustBeDocumented
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class ClassA2Qualifier
```

可以像这样更新模块：

```kt
@Module
object MyModule {
    @ClassA1Qualifier
    @Provides
    fun provideClassA1(): ClassA = ClassA()
    @ClassA2Qualifier
    @Provides
    fun provideClassA2(): ClassA = ClassA()
    @Provides
    fun provideClassB(@ClassA1Qualifier classA: ClassA): ClassB =       ClassB(classA)
}
```

## 作用域

如果要跟踪组件和依赖项的生命周期，可以使用作用域。Dagger 提供了`@Singleton`作用域。这通常表示您的组件将与应用程序一样长。作用域对对象的生命周期没有影响；它们旨在帮助开发人员识别对象的生命周期。建议为组件指定一个作用域，并将代码分组以反映该作用域。Android 上一些常见的 Dagger 作用域与活动或片段相关：

```kt
import javax.inject.Scope
@Scope
@MustBeDocumented
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class ActivityScope
@Scope
@MustBeDocumented
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class FragmentScope
```

注释可以在提供依赖项的模块中使用：

```kt
    @ActivityScope
    @Provides
    fun provideClassA(): ClassA = ClassA()
```

`Component`的代码将如下所示：

```kt
@ActivityScope
@Component(modules = [MyModule::class])
interface MyComponent {
}
```

前面的示例表明`Component`只能使用具有相同作用域的对象。如果此`Component`的任何模块包含具有不同作用域的依赖项，Dagger 将抛出错误，指示作用域存在问题。

## 子组件

与作用域紧密相关的是子组件。它们允许您为较小的作用域组织您的依赖项。Android 上的一个常见用例是为活动和片段创建子组件。子组件从父组件继承依赖项，并为子组件的作用域生成新的依赖项图。

让我们假设我们有一个单独的模块：

```kt
class ClassC
@Module
object MySubcomponentModule {
    @Provides
    fun provideClassC(): ClassC = ClassC()
}
```

将为该模块生成依赖项图的`Subcomponent`将如下所示：

```kt
import dagger.Subcomponent
@ActivityScope
@Subcomponent(modules = [MySubcomponentModule::class])
interface MySubcomponent {
    fun inject(mainActivity: MainActivity)
}
```

父组件需要声明新组件，如下面的代码片段所示：

```kt
import dagger.Component
@Component(modules = [MyModule::class])
interface MyComponent {
    fun inject(myApplication: MyApplication)
    fun createSubcomponent(mySubcomponentModule:       MySubcomponentModule): MySubcomponent
}
```

您可以将`ClassC`注入到您的活动中，如下所示：

```kt
@Inject
    lateinit var classC: ClassC
     override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        (application as MyApplication).component           .createSubcomponent(MySubcomponentModule).inject(this)
}
```

有了这些知识，让我们继续进行练习。

## 练习 12.02：Dagger 注入

在这个练习中，我们将编写一个 Android 应用程序，该应用程序将应用 Dagger 的 DI 概念。该应用程序将具有与“Exercise 12.01”，“手动注入”中定义的相同的`Repository`和`ViewModel`。我们需要使用 Dagger 来公开相同的两个依赖项：

+   `Repository`：这将具有`@Singleton`作用域，并将由`ApplicationModule`提供。现在，`ApplicationModule`将作为`ApplicationComponent`的一部分公开。

+   `ViewModelProvider.Factory`：这将具有名为`MainScope`的自定义作用域，并将由`MainModule`提供。现在，`MainModule`将由`MainSubComponent`公开。此外，`MainSubComponent`将由`ApplicationComponent`生成。

应用程序本身将在每次单击按钮时显示随机生成的数字：

1.  让我们首先在`app/build.gradle`文件中添加 Dagger 和：

```kt
    implementation 'com.google.dagger:dagger:2.29.1'
    kapt 'com.google.dagger:dagger-compiler:2.29.1'
    implementation "androidx.lifecycle:lifecycle-      extensions:2.2.0"
```

1.  我们还需要在`app/build.gradle`模块中添加`kapt`插件。按照以下方式附加插件：

```kt
apply plugin: 'kotlin-kapt'
```

1.  现在，我们需要添加`NumberRepository`，`NumberRepositoryImpl`，`MainViewModel`和`RandomApplication`类，并使用`MainActivity`构建我们的 UI。可以通过按照“Exercise 12.01”，“手动注入”的*步骤 2-9*来完成。

1.  现在，让我们继续进行`ApplicationModule`，它将提供`NumberRepository`依赖项：

```kt
@Module
    class ApplicationModule {
        @Provides
        fun provideRandom(): Random = Random()
        @Provides
        fun provideNumberRepository(random: Random):           NumberRepository = NumberRepositoryImpl(random)
}
```

1.  现在，让我们创建`MainModule`，它将提供`ViewModel.Factory`的实例：

```kt
@Module
class MainModule {

    @Provides
    fun provideMainViewModelFactory(numberRepository:       NumberRepository): ViewModelProvider.Factory {
        return object : ViewModelProvider.Factory {
            override fun <T : ViewModel?> create(modelClass:               Class<T>): T {
                return MainViewModel(numberRepository) as T
            }
        }
    }
}
```

1.  现在，让我们创建`MainScope`：

```kt
@Scope
@MustBeDocumented
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class MainScope
```

1.  我们将需要`MainSubcomponent`，它将使用前面的作用域：

```kt
@MainScope
@Subcomponent(modules = [MainModule::class])
interface MainSubcomponent {
    fun inject(mainActivity: MainActivity)
}
```

1.  接下来，我们将需要`ApplicationComponent`：

```kt
@Singleton
@Component(modules = [ApplicationModule::class])
interface ApplicationComponent {
    fun createMainSubcomponent(): MainSubcomponent
}
```

1.  我们需要导航到`Build`，在 Android Studio 中点击`Rebuild project`，以便生成 Dagger 代码来执行 DI。

1.  接下来，我们修改`RandomApplication`类，以添加所需的代码来初始化 Dagger 依赖图：

```kt
class RandomApplication : Application() {
    lateinit var applicationComponent: ApplicationComponent
    override fun onCreate() {
        super.onCreate()
        applicationComponent =           DaggerApplicationComponent.create()
    }
}
```

1.  现在我们修改`MainActivity`类，以注入`ViewModelProvider.Factory`并初始化`ViewModel`，以便显示随机数字：

```kt
class MainActivity : AppCompatActivity() {
    @Inject
    lateinit var factory: ViewModelProvider.Factory
    override fun onCreate(savedInstanceState: Bundle?) {
        (application as RandomApplication).applicationComponent           .createMainSubcomponent().inject(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val viewModel = ViewModelProvider(this,           factory).get(MainViewModel::class.java)
        viewModel.getLiveData().observe(this, Observer {
            findViewById<TextView>(R.id.activity_main_text_view)              .text = it.toString()
        }
        )
        findViewById<TextView>(R.id.activity_main_button)          .setOnClickListener {
            viewModel.generateNextNumber()
        }
    }
}
```

如果运行上述代码，将构建一个应用程序，当您点击按钮时将显示不同的随机输出：

![图 12.2：Exercise 12.02 的模拟器输出，显示随机生成的数字](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_02.jpg)

图 12.2：Exercise 12.02 的模拟器输出，显示随机生成的数字

1.  *图 12.2*显示了应用程序的外观。您可以在`app/build`文件夹中查看生成的 Dagger 代码：

![图 12.3：Exercise 12.02 的生成 Dagger 代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_03.jpg)

图 12.3：Exercise 12.02 的生成 Dagger 代码

在*图 12.3*中，我们可以看到 Dagger 生成的代码，以满足依赖关系。对于每个需要注入的依赖项，Dagger 将生成一个适当的`Factory`类（基于`Factory`设计模式），它将负责创建依赖项。Dagger 还会查看需要注入依赖项的位置，并生成一个`Injector`类，它将负责为依赖项分配值（在本例中，它将为`MainActivity`类中标有`@Inject`的成员分配值）。最后，Dagger 为具有`@Component`注解的接口创建实现。在实现中，Dagger 将处理模块的创建，并提供一个构建器，开发人员可以指定如何构建模块。

## Dagger Android

在前面的示例中，您可能已经注意到在活动中，您必须调用组件和子组件来执行注入。这在应用程序中往往会变得重复。也不建议活动和片段知道谁在执行注入。所有这些都来自 Dagger 和 Android 框架之间的根本冲突。在 Dagger 中，您负责提供和注入您的依赖关系。在 Android 中，片段和活动是由系统实例化的。换句话说，您不能将活动或片段的创建移到 Dagger 模块中并注入依赖关系，因此您必须求助于构建子组件。通过使用子组件，然后创建子组件和活动之间的依赖关系。幸运的是，Dagger 提供了一套库来解决这些 Android 问题，可以添加到您的`build.gradle`文件中：

```kt
    implementation 'com.google.dagger:dagger-android:2.29.1' 
    implementation 'com.google.dagger:dagger-android-support:2.29.1' 
    kapt 'com.google.dagger:dagger-android-processor:2.29.1'
```

Android Dagger 库提供了专门的注入方法，Dagger 使用这些方法将依赖项注入到活动和片段中。这种设置还通过消除子组件的需要，简化了较简单项目的依赖设置。一个设置注入到活动的模块将看起来像这样：

```kt
@Module
abstract class ActivityProviderModule {
    @ContributesAndroidInjector(modules = [ActivityModule::class])
    @ActivityScope
    abstract fun contributeMyActivityInjector(): MyActivity
}
```

（请注意，这些示例中没有显示导入语句。）

这里的一个重要事项是引入`@ContributesAndroidInjector`注解，当应用于抽象方法时，允许 Dagger 创建一个实现，其中它将创建`AndroidInjector`，然后用于对活动进行注入。`Application`组件将需要一个专用的`AndroidInjectionModule`或`AndroidSupportInjection`模块（如果您正在使用兼容库来实现您的片段）：

```kt
@Singleton
@Component(
    modules = [AndroidSupportInjectionModule::class,
        ApplicationModule::class,
        ActivityProviderModule::class
    ]
)
interface ApplicationComponent {
    fun inject(myApplication: MyApplication)
}
```

`AndroidSupportInjectionModule`来自 Dagger Android 库，并提供了一组绑定，当使用 Android 框架类时，通过跟踪您添加到`Application`、`Activity`和`Fragment`类的不同注入器，这些绑定会变得有用。这就是 Dagger 将知道如何将每个依赖项注入到您的活动或片段中。

在您的`Application`类中，您将需要一个`HasAndroidInjector`实现。这将负责为您的应用程序的每个活动提供注入。如果您正在使用服务或`ContentProvider`，可以应用相同的规则：

```kt
class MyApplication : Application(), HasAndroidInjector {
    @Inject
    lateinit var dispatchingAndroidInjector:       DispatchingAndroidInjector<Any>
    lateinit var applicationComponent: ApplicationComponent
    override fun onCreate() {
        super.onCreate()
        applicationComponent = DaggerApplicationComponent.create()
        applicationComponent.inject(this)
    }
    override fun androidInjector(): AndroidInjector<Any> =       dispatchingAndroidInjector
}
```

Dagger 将在您的`Application`类中，在`onCreate()`中创建图形，并将`AndroidInjector`对象注入`Application`类。然后，`AndroidInjector`对象将用于将依赖项注入到每个指定的活动中。最后，在您的活动中，您可以使用`AndroidInjection.inject()`方法来注入依赖项。当调用`inject()`时，Dagger 将查找负责 DI 的注入器。如果从活动中调用`inject()`，那么它将使用应用程序注入器。这是 Dagger 将调用应用程序中的`androidInjector()`方法的时刻。如果注入器有效，则将执行 DI。如果从片段中调用`inject()`，那么 Dagger 将在父活动中查找注入器。如果从嵌套片段中调用`inject()`，那么 Dagger 将在父片段中查找注入器，这就是为什么它只限于一个嵌套片段：

```kt
class MyActivity : AppCompatActivity() {
    @Inject
    lateinit var myClass: MyClass
    override fun onCreate(savedInstanceState: Bundle?) {
        AndroidInjection.inject(this)
        super.onCreate(savedInstanceState)
    }
}
```

为了在您的片段中执行 DI，必须遵循每个先前执行的活动的类似原则。假设`MyActivity`有`MyFragment`。我们将需要为`MyActivity`实现`HasAndroidInjector`：

```kt
class MyActivity : AppCompatActivity(), HasAndroidInjector {
    @Inject
    lateinit var dispatchingAndroidInjector:       DispatchingAndroidInjector<Any>
    override fun onCreate(savedInstanceState: Bundle?) {
        AndroidInjection.inject(this)
        super.onCreate(savedInstanceState)
    }
    override fun androidInjector(): AndroidInjector<Any> =       dispatchingAndroidInjector
}
```

接下来，我们将需要一个与活动的提供程序模块类似的片段的提供程序模块：

```kt
@Module
abstract class FragmentProviderModule {
    @ContributesAndroidInjector(modules = [FragmentModule::class])
    @FragmentScope
    abstract fun contributeMyFragmentInjector(): MyFragment
}
```

最后，在`ActivityProviderModule`中，您需要添加`FragmentProviderModule`：

```kt
    @ContributesAndroidInjector(modules = [ActivityModule::class,       FragmentProviderModule::class])
    @ActivityScope
    abstract fun contributeMyActivityInjector(): MyActivity
```

这对于每个具有需要注入的依赖项的片段的活动都是必需的。

Dagger Android 提供了一组具有`HasAndroidInjector`实现的类。如果您希望避免在您的类中实现`HasAndroidInjector`方法，可以使用以下一些类：`DaggerApplication`、`DaggerActivity`、`DaggerFragment`和`DaggerSupportFragment`。只需扩展它们而不是`Application`、`Activity`等即可。

## 练习 12.03：更改注入器

在本练习中，我们将更改*Exercise 12.02*，*Dagger Injection*，以添加 Android 注入器功能。输出将显示一个随机生成的数字，并且相同的依赖项需要以以下方式公开：

+   `Repository`：这将具有`@Singleton`范围，并将由`ApplicationModule`提供。现在，`ApplicationModule`将作为`ApplicationComponent`的一部分公开（与*Exercise 12.02*，*Dagger Injection*相同）。

+   `ViewModelProvider.Factory`：这将具有名为`MainScope`的自定义范围，并将由`MainModule`提供。现在，`MainModule`将由`MainProviderModule`公开。

+   依赖项将使用 Android 注入器注入到`MainActivity`中。Android 注入器将被添加到`RandomApplication`中，以便注入正常工作。

执行以下步骤以完成练习：

1.  让我们将 Dagger Android 依赖项添加到`app/build.gradle`文件中，这将使您的依赖项看起来像这样：

```kt
    implementation 'com.google.dagger:dagger:2.29.1'
    kapt 'com.google.dagger:dagger-compiler:2.29.1'
    implementation 'com.google.dagger:dagger-android:2.29.1'
    implementation 'com.google.dagger:dagger-android-      support:2.29.1'
    kapt 'com.google.dagger:dagger-android-processor:2.29.1'
```

1.  接下来，删除`MainSubcomponent`类。

1.  创建一个`MainProviderModule`类，它将提供`MainActivity`的引用：

```kt
@Module
abstract class MainProviderModule {
    @MainScope
    @ContributesAndroidInjector(modules = [MainModule::class])
    abstract fun contributeMainActivityInjector(): MainActivity
}
```

1.  更新`ApplicationComponent`以添加`Application`类的`inject`方法，并添加`ActivityProviderModule`和`AndroidSupportInjectionModule`：

```kt
@Singleton
@Component(modules = [ApplicationModule::class, AndroidSupportInjectionModule::class, MainProviderModule::class])
interface ApplicationComponent {
    fun inject(randomApplication: RandomApplication)
}
```

1.  将`Application`类更改为实现`HasAndroidInjector`，并让 Dagger 将一个注入器对象注入其中：

```kt
class RandomApplication : Application(), HasAndroidInjector {
    @Inject
    lateinit var dispatchingAndroidInjector:       DispatchingAndroidInjector<Any>
    lateinit var applicationComponent: ApplicationComponent
    override fun onCreate() {
        super.onCreate()
        applicationComponent =           DaggerApplicationComponent.create()
        applicationComponent.inject(this)
    }
    override fun androidInjector(): AndroidInjector<Any> =       dispatchingAndroidInjector
}
```

1.  在`MainActivity`中，用`AndroidInjection.inject`方法替换旧的注入：

```kt
    override fun onCreate(savedInstanceState: Bundle?) {
        AndroidInjection.inject(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val viewModel = ViewModelProvider(this,             factory).get(MainViewModel::class.java)
        viewModel.getLiveData().observe(this, Observer {
            findViewById<TextView>(R.id.activity_main_text_view)              .text = it.toString()
        }
        )
        findViewById<TextView>(R.id.activity_main_button)          .setOnClickListener {
            viewModel.generateNextNumber()
        }
    }
```

最终输出将如下所示：

![图 12.4：练习 12.03 的模拟器输出显示随机生成的数字](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_04.jpg)

图 12.4：练习 12.03 的模拟器输出显示随机生成的数字

在构建应用程序时查看生成的代码：

![图 12.5：练习 12.03 的生成的 Dagger 代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_05.jpg)

图 12.5：练习 12.03 的生成的 Dagger 代码

运行上述代码不应该改变练习的结果或*图 12.3*中呈现的依赖关系的范围。您可以观察到`MainActivity`对象不再依赖于`Application`类或任何组件或子组件。*图 12.5*显示了 Dagger Android 注入器的生成代码。其中大部分与现有代码类似，但我们可以看到为`MainProviderModule`生成的代码，它实际上生成了一个子组件。

当涉及组织其依赖关系时，您将发现 Android 应用程序的常见设置如下：

+   **ApplicationModule**：这是定义整个项目通用依赖关系的地方。可以在这里提供诸如上下文、资源和其他 Android 框架对象之类的对象。

+   **NetworkModule**：这是存储与 API 调用相关的依赖关系的地方。

+   `DatabaseModule`，`FilesModule`，`SharedPreferencesModule`等等。

+   `ViewModels`或`ViewModel`工厂被存储。

+   `ViewModel`。在这里，要么使用子组件，要么使用 Android 注入器来实现这一目的。

我们已经提出了一些关于手动 DI 可能出错的问题。现在我们已经看到了 Dagger 如何解决这些问题。虽然它能够胜任工作，并且在性能方面做得很快，但它也是一个非常复杂的框架，学习曲线非常陡峭。

# Koin

Koin 是一个适用于较小应用的轻量级框架。它不需要代码生成，并且是基于 Kotlin 的函数扩展构建的。它也是一种**领域特定语言**（**DSL**）。您可能已经注意到，使用 Dagger 时，必须编写大量代码来设置 DI。Koin 对 DI 的处理方式解决了大部分这些问题，可以实现更快的集成。

可以通过将以下依赖项添加到您的`build.gradle`文件中将 Koin 添加到您的项目中：

```kt
implementation 'org.koin:koin-android:2.2.0-rc-4'
```

为了在您的应用程序中设置 Koin，您需要使用 DSL 语法进行`startKoin`调用：

```kt
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidLogger(Level.INFO)
            androidContext(this@MyApplication)
            androidFileProperties()
            modules(myModules)
        }
    }
}
```

在这里，您可以配置您的应用程序上下文（在`androidContext`方法中），指定属性文件以定义 Koin 配置（在`androidFileProperties`中），指定 Koin 的 Logger Level，在`LogCat`中输出 Koin 操作的结果，具体取决于 Level（在`androidLogger`方法中），并列出您的应用程序使用的模块。创建模块时使用类似的语法：

```kt
class ClassA
class ClassB(private val classB: ClassA)
    val moduleForClassA = module {
        single { ClassA() }
    }
    val moduleForClassB = module {
        factory { ClassB(get()) }
    }
    override fun onCreate() {
        super.onCreate()
        startKoin {
            androidLogger(Level.INFO)
            androidContext(this@MyApplication)
            androidFileProperties()
            modules(listOf(moduleForClassA, moduleForClassB))
        }
    }
```

在上面的示例中，这两个对象将具有两个不同的生命周期。当使用**single**符号提供依赖项时，那么整个应用程序生命周期内只会使用一个实例。这对于存储库、数据库和 API 组件非常有用，因为多个实例对应用程序来说成本很高。**factory**符号将在执行注入时创建一个新对象。这在对象需要与活动或片段一样长寿的情况下可能很有用。

可以使用`by inject()`方法或`get()`方法注入依赖项，如下所示：

```kt
    class MainActivity : AppCompatActivity() {
      val classB: ClassB by inject()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val classB: ClassB = get()
    }
```

Koin 还提供了使用`named()`方法和限定符的可能性，当创建模块时可以使用。这允许您提供相同类型的多个实现（例如，提供两个或更多具有不同内容的列表对象）：

```kt
    val moduleForClassA = module {
        single(named("name")) { ClassA() }
    }
```

Koin 的一个主要特性是为 Android 应用程序提供活动和片段的作用域，可以按照以下代码片段中所示进行定义：

```kt
    val moduleForClassB = module {
        scope(named<MainActivity>()) {
            scoped { ClassB(get()) }
        }
    }
```

前面的示例将`ClassB`的生命周期依赖项连接到`MainActivity`的生命周期。为了将实例注入到您的活动中，您需要扩展`ScopeActivity`类。该类负责在活动存在期间保持引用。其他 Android 组件（如片段（`ScopeFragment`）和服务（`ScopeService`））也存在类似的类。

```kt
class MainActivity : ScopeActivity() {
    val classB: ClassB by inject()
}
```

您可以使用`inject()`方法将实例注入到您的活动中。这在您希望限制谁可以访问依赖项的情况下非常有用。在前面的示例中，如果另一个活动想要访问对`ClassB`的引用，那么它将无法在作用域中找到它。

另一个对 Android 非常有用的功能是`ViewModel`注入。为了设置这个，您需要将库添加到`build.gradle`中：

```kt
implementation "org.koin:koin-android-viewmodel:2.2.0-rc-4"
```

如果您还记得，`ViewModels`需要`ViewModelProvider.Factories`才能被实例化。Koin 自动解决了这个问题，允许直接注入`ViewModels`并处理工厂工作：

```kt
    val moduleForClassB = module {
        factory {
            ClassB(get())
        }
        viewModel { MyViewModel(get()) }
    }
```

为了将`ViewModel`的依赖项注入到您的活动中，您可以使用`viewModel()`方法：

```kt
class MainActivity : AppCompatActivity() {
    val model: MyViewModel by viewModel()
}
```

或者，您可以直接使用该方法：

```kt
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val model : MyViewModel = getViewModel()
    }
```

正如我们在前面的设置中所看到的，Koin 充分利用了 Kotlin 语言的特性，并减少了定义模块及其作用域所需的样板代码量。

## 练习 12.04：Koin 注入

在这里，我们将编写一个 Android 应用程序，该应用程序将使用 Koin 执行 DI。该应用程序将基于*练习 12.01*，*手动注入*，保留`NumberRepository`，`NumberRepositoryImpl`，`MainViewModel`和`MainActivity`。将注入以下依赖项：

+   `Repository`：作为名为`appModule`的模块的一部分。

+   `MainViewModel`：这将依赖于 Koin 对`ViewModels`的专门实现。这将作为名为`mainModule`的模块的一部分提供，并且将具有`MainActivity`的作用域。

执行以下步骤完成练习：

1.  应用程序本身将在每次单击按钮时显示一个随机生成的数字。让我们从添加 Koin 库开始：

```kt
implementation "androidx.lifecycle:lifecycle-extensions:2.2.0"
implementation 'org.koin:koin-android:2.2.0-rc-4'
implementation "org.koin:koin-android-viewmodel:2.2.0-rc-4"
```

1.  让我们从在`MyApplication`类中定义`appModule`变量开始。这将与 Dagger 设置的`AppModule`具有类似的结构：

```kt
class RandomApplication : Application() {
    val appModule = module {
        single {
            Random()
        }
        single<NumberRepository> {
            NumberRepositoryImpl(get())
        }
}
}
```

1.  现在，在`appModule`之后添加活动模块变量：

```kt
    val mainModule = module {
        scope(named<MainActivity>()) {
            scoped {
                MainViewModel(get())
            }
        }
    }
```

1.  现在，让我们在`RandomApplication`的`onCreate()`方法中初始化`Koin`：

```kt
        super.onCreate()
        startKoin {
            androidLogger()
            androidContext(this@RandomApplication)
            modules(listOf(appModule, mainModule))
        }
    }
```

1.  最后，让我们将依赖项注入到活动中：

```kt
class MainActivity :  ScopeActivity() {
    private val mainViewModel: MainViewModel by inject()
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mainViewModel.getLiveData().observe(this, Observer {
            findViewById<TextView>(R.id.activity_main_text_view)              .text = it.toString()
        }
        )
        findViewById<TextView>(R.id.activity_main_button)          .setOnClickListener {
            mainViewModel.generateNextNumber()
        }
    }
}
```

1.  如果您运行前面的代码，应用程序应该按照之前的示例正常工作。但是，如果您检查`LogCat`，您将看到类似于这样的输出：

```kt
[Koin]: [init] declare Android Context
[Koin]: bind type:'android.content.Context' ~ [type:Single,primary_type:'android.content.Context']
[Koin]: bind type:'android.app.Application' ~ [type:Single,primary_type:'android.app.Application']
[Koin]: bind type:'java.util.Random' ~ [type:Single,primary_type:'java.util.Random']
[Koin]: bind type:'com.android.testable.randomapplication   .NumberRepository' ~ [type:Single,primary_type:'com.android   .testable.randomapplication.NumberRepository']
[Koin]: total 5 registered definitions
[Koin]: load modules in 0.4638 ms
```

在*图 12.6*中，我们可以看到与以前练习中相同的输出：

![图 12.6：模拟器输出练习 12.04 显示随机生成的数字](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_12_06.jpg)

图 12.6：模拟器输出练习 12.04 显示随机生成的数字

从这个练习中可以看出，Koin 集成起来更快更容易，特别是其`ViewModel`库。这对于小型项目非常方便，但一旦项目增长，其性能将受到影响。

## 活动 12.01：注入的存储库

在这个活动中，您将在 Android Studio 中创建一个应用程序，该应用程序连接到一个示例 API，[`jsonplaceholder.typicode.com/posts`](https://jsonplaceholder.typicode.com/posts)，使用 Retrofit 库检索网页上的帖子列表，然后在屏幕上显示。然后，您需要设置一个 UI 测试，其中您将断言数据在屏幕上正确显示，但是不是连接到实际端点，而是提供虚拟数据供测试显示在屏幕上。您将利用 DI 概念，在应用程序执行时交换依赖项，而不是在进行测试时。

为了实现这一点，您需要构建以下内容：

+   负责下载和解析 JSON 文件的网络组件

+   从 API 层访问数据的存储库

+   一个访问存储库的`ViewModel`实例

+   一个带有`RecycleView`的活动，显示数据

+   提供存储库实例的 Dagger 模块和提供`ViewModel`工厂实例的模块，以及一个将交换存储库依赖项的测试模块

+   一个 UI 测试，断言行并使用虚拟对象生成 API 数据

注意

本次活动可以避免错误处理。

按顺序执行以下步骤以完成此活动：

1.  在 Android Studio 中，创建一个带有`Empty Activity`（`MainActivity`）的应用程序，并添加一个`api`包，其中存储了 API 调用。

1.  定义一个负责 API 调用的类。

1.  创建一个`repository`包。

1.  定义一个存储库接口，该接口将具有一个方法，返回帖子列表的`LiveData`。

1.  创建存储库类的实现。

1.  创建一个`ViewModel`实例，该实例将调用存储库以检索数据。

1.  为 UI 的行创建一个适配器。

1.  创建渲染 UI 的活动。

1.  设置一个 Dagger 模块，用于初始化与网络相关的依赖项。

1.  创建一个 Dagger 模块，负责定义活动所需的依赖项。

1.  创建一个子组件，该子组件将使用相关模块，并在活动中进行注入。

1.  创建`AppComponent`，它将管理所有模块。

1.  设置 UI 测试和测试应用程序，并提供一个单独的`RepositoryModule`类，该类将返回一个包含虚拟数据的依赖项。

1.  实施 UI 测试。

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

## Activity 12.02：Koin-Injected Repositories

在这个活动中，您将迁移*Activity 12.01*中构建的应用程序，即*Injected Repositories*，从 Dagger 到 Koin，保持要求不变。

假设您的代码中的组件与上一个活动的相同，需要按照以下步骤完成活动：

1.  从`build.gradle`和`kapt`插件中删除 Dagger 2 的依赖项。这将产生编译错误，可以指导您删除不必要的代码。

1.  添加标准的`Koin`库和`ViewModels`库。

1.  从代码中删除 Dagger 模块和组件。

1.  创建`networkModule`、`repositoryModule`和`activityModule`模块。

1.  使用上述模块设置 Koin。

1.  将`ViewModel`注入`MainActivity`。

1.  在`TestApplication`中覆盖`repositoryModule`，返回`DummyRepository`。

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 总结

在本章中，我们分析了 DI 的概念以及如何应用它以分离关注点，并防止对象具有创建其他对象的责任，以及这对于测试的巨大好处。我们从分析手动 DI 的概念开始本章。这是 DI 如何工作以及如何应用于 Android 应用程序的一个很好的例子；它作为比较 DI 框架时的基线。

我们还分析了两种帮助开发人员进行依赖注入的最流行框架。我们首先介绍了一个强大而快速的框架，即 Dagger 2，它依赖于注解处理器来生成代码以执行注入。我们还研究了 Koin，这是一个用 Kotlin 编写的轻量级框架，性能较慢，但集成更简单，且非常关注 Android 组件。

本章的练习旨在探索如何使用多种解决方案解决同一问题，并比较解决方案之间的难度程度。在本章的活动中，我们利用 Dagger 和 Koin 的模块来在运行应用程序时注入某些依赖项，并在运行使用`ViewModels`、存储库和 API 加载数据的测试时注入其他依赖项。这旨在展示多个框架的无缝集成，这些框架实现了不同的目标。这些活动还代表了在先前章节中学到的不同技能的结合，从教您如何在 UI 上显示数据的基本技能到与网络、测试、`ViewModels`、存储库和依赖注入相关的更复杂的技能。

在接下来的章节中，您将有机会在已经获得的知识基础上构建，通过添加与线程和处理后台操作相关的概念。您将有机会探索诸如 RxJava 及其对线程的响应式方法，以及协程等库，后者对线程采取了不同的方法。您还将观察到协程和 RxJava 如何与 Room 和 Retrofit 等库结合得非常有效。最后，您将能够将所有这些概念结合在一个具有高度可扩展性的强大应用程序中。


# 第十三章：RxJava 和协程

概述

本章将介绍如何使用 RxJava 和协程进行后台操作和数据操作。它涵盖了如何使用 RxJava 从外部 API 检索数据以及如何使用协程进行操作。您还将学习如何使用 RxJava 操作符和 LiveData 转换来操作和显示数据。

在本章结束时，您将能够使用 RxJava 在后台管理网络调用，并使用 RxJava 操作符转换数据。您还将能够使用 Kotlin 协程在后台执行网络任务，并使用 LiveData 转换操作来操作数据。

# 介绍

您现在已经学会了 Android 应用程序开发的基础知识，并实现了诸如 RecyclerView、通知、从网络服务获取数据和服务等功能。您还掌握了最佳实践的测试和持久化数据的技能。在上一章中，您学习了依赖注入。现在，您将学习后台操作和数据操作。

一些 Android 应用程序可以自行运行。但是，大多数应用程序可能需要后端服务器来检索或处理数据。这些操作可能需要一段时间，具体取决于互联网连接、设备设置和服务器规格。如果长时间运行的操作在主 UI 线程中运行，应用程序将被阻塞，直到任务完成。应用程序可能会变得无响应，并可能提示用户关闭并停止使用它。

为了避免这种情况，可以将可能需要花费不确定时间的任务异步运行。异步任务意味着它可以与另一个任务并行运行或在后台运行。例如，当异步从数据源获取数据时，您的 UI 仍然可以显示或与用户交互。

您可以使用 RxJava 和协程等库进行异步操作。我们将在本章讨论它们。让我们开始使用 RxJava。

# RxJava

RxJava 是**Reactive Extensions**（**Rx**）的 Java 实现，这是一种用于响应式编程的库。在响应式编程中，您有可以被观察的数据流。当值发生变化时，您的观察者可以收到通知并做出相应的反应。例如，假设点击按钮是您的可观察对象，并且您有观察者在监听它。如果用户点击该按钮，您的观察者可以做出反应并执行特定操作。

RxJava 使异步数据处理和处理错误变得更简单。以常规方式编写它很棘手且容易出错。如果您的任务涉及一系列异步任务，那么编写和调试将会更加复杂。使用 RxJava，可以更轻松地完成，并且代码量更少，更易读和易于维护。RxJava 还具有广泛的操作符，可用于将数据转换为所需的类型或格式。

RxJava 有三个主要组件：可观察对象、观察者和操作符。要使用 RxJava，您需要创建发出数据的可观察对象，使用 RxJava 操作符转换数据，并使用观察者订阅可观察对象。观察者可以等待可观察对象产生数据，而不会阻塞主线程。

## 可观察对象、观察者和操作符

让我们详细了解 RxJava 的三个主要组件。

**可观察对象**

可观察对象是可以被监听的数据源。它可以向其监听者发出数据。

`Observable`类表示一个可观察对象。您可以使用`Observable.just`和`Observable.from`方法从列表、数组或对象创建可观察对象。例如，您可以使用以下方式创建可观察对象：

```kt
val observable = Observable.just("This observable emits this string")
val observableFromList = Observable.fromIterable(listOf(1, 2, 3, 4))
```

还有更多函数可用于创建可观察对象，例如 `Observable.create`、`Observable.defer`、`Observable.empty`、`Observable.generate`、`Observable.never`、`Observable.range`、`Observable.interval` 和 `Observable.timer`。您还可以创建一个返回 `observable` 的函数。了解有关创建可观察对象的更多信息，请访问 [`github.com/ReactiveX/RxJava/wiki/Creating-Observables`](https://github.com/ReactiveX/RxJava/wiki/Creating-Observables)。

可观察对象可以是热的或冷的。冷可观察对象只有在有订阅者监听时才会发出数据。例如数据库查询或网络请求。另一方面，热可观察对象即使没有观察者也会发出数据。例如，Android 中的 UI 事件，如鼠标和键盘事件。

一旦创建了可观察对象，观察者就可以开始监听可观察对象将发送的数据。

**操作符**

操作符允许您在将数据传递给观察者之前修改和组合从可观察对象获取的数据。使用操作符会返回另一个可观察对象，因此您可以链接操作符调用。例如，假设您有一个可观察对象，它会发出从 1 到 10 的数字。您可以对其进行过滤，只获取偶数，并将列表转换为另一个包含每个项目平方的列表。要在 RxJava 中执行此操作，您可以使用以下代码：

```kt
Observable.range(1, 10)
.filter { it % 2 == 0 }
.map { it * it }
```

上述代码的输出将是一个数据流，其中包含值 4、16、36、64 和 100。

**观察者**

观察者订阅可观察对象，并在观察者发出数据时收到通知。它们可以监听可观察对象发出的下一个值或错误。`Observer` 类是观察者的接口。在创建观察者时，它有四种方法可以重写：

+   `onComplete`：当可观察对象完成发送数据时

+   `onNext`：当可观察对象发送新数据时

+   `onSubscribe`：当观察者订阅可观察对象时

+   `onError`：当可观察对象遇到错误时

要订阅可观察对象，可以调用 `Observable.subscribe()`，传入 `Observer` 接口的新实例。例如，如果要订阅从 `2` 到 `10` 的偶数可观察对象，可以执行以下操作：

```kt
Observable.fromIterable(listOf(2, 4, 6, 8, 10))
    .subscribe(object : Observer<Int> {
        override fun onComplete() {
            println("completed")
        }
        override fun onSubscribe(d: Disposable) {
            println("subscribed")
        }
        override fun onNext(t: Int) {
            println("next integer is $t")
        }
        override fun onError(e: Throwable) {
            println("error encountered")
        }
    })
```

使用此代码，观察者将打印下一个整数。它还会在订阅时打印文本，当可观察对象完成时，以及当遇到错误时。

`Observable.subscribe()` 具有不同的重载函数，其中您可以传递 `onNext`、`onError`、`onComplete` 和 `onSubscribe` 参数。这些函数返回一个 `disposable` 对象。在关闭活动时，可以调用其 `dispose` 函数以防止内存泄漏。例如，您可以使用一个变量来存储 `disposable` 对象：

```kt
val disposable = observable
            ...
            .subscribe(...)
```

然后，在您创建可观察对象的活动的 `onDestroy` 函数中，您可以调用 `disposable.dispose()` 来阻止观察者监听可观察对象：

```kt
override fun onDestroy() {
    super.onDestroy()
    disposable.dispose()
}
```

除了可观察对象、观察者和操作符之外，您还需要了解 RxJava 调度程序，这将在下一节中介绍。

## 调度程序

默认情况下，RxJava 是同步的。这意味着所有进程都在同一个线程中完成。有一些任务需要一段时间，例如数据库和网络操作，需要异步执行或在另一个线程中并行运行。为此，您需要使用调度程序。

调度程序允许您控制操作将在其中运行的线程。您可以使用两个函数：`observeOn` 和 `subscribeOn`。您可以使用 `subscribeOn` 函数设置可观察对象将在哪个线程上运行。`observeOn` 函数允许您设置下一个操作将在哪里执行。

例如，如果您有 `getData` 函数，该函数从网络获取数据并返回一个可观察对象，您可以订阅 `Schedulers.io` 并使用 `AndroidSchedulers.mainThread()` 观察 Android 主 UI 线程：

```kt
val observable = getData()
   .subscribeOn(Schedulers.io())
   .observeOn(AndroidSchedulers.mainThread())
   ...
```

`AndroidSchedulers`是 RxAndroid 的一部分，它是 RxJava 在 Android 上的扩展。您需要 RxAndroid 来在 Android 应用程序开发中使用 RxJava。

在下一节中，您将学习如何将 RxJava 和 RxAndroid 添加到您的项目中。

## 将 RxJava 添加到您的项目

您可以通过将以下代码添加到`app/build.gradle`文件的依赖项中，将 RxJava 添加到您的项目中：

```kt
implementation 'io.reactivex.rxjava3:rxandroid:3.0.0'
implementation 'io.reactivex.rxjava3:rxjava:3.0.7'
```

这将向您的 Android 项目中添加 RxJava 和 RxAndroid 库。RxAndroid 库已经包含了 RxJava，但最好还是添加 RxJava 依赖项，因为 RxAndroid 捆绑的版本可能不是最新版本。

## 在 Android 项目中使用 RxJava

RxJava 有几个好处，其中之一是处理长时间运行的操作，比如在非 UI 线程中进行网络请求。网络调用的结果可以转换为可观察对象。然后，您可以创建一个观察者来订阅可观察对象并呈现数据。在向用户显示数据之前，您可以使用 RxJava 操作符转换数据。

如果您使用 Retrofit，可以通过添加调用适配器工厂将响应转换为 RxJava 可观察对象。首先，您需要在`app/build.gradle`文件的依赖项中添加`adapter-rxjava3`，如下所示：

```kt
implementation 'com.squareup.retrofit2:adapter-rxjava3:2.9.0'
```

有了这个，您可以在您的`Retrofit`实例中使用`RxJava3CallAdapterFactory`作为调用适配器。您可以使用以下代码来实现：

```kt
val retrofit = Retrofit.Builder()
    ...
    .addCallAdapterFactory(RxJava3CallAdapterFactory.create())
    ...
```

现在，您的 Retrofit 方法可以返回您可以在代码中监听的`Observable`对象。例如，在调用电影端点的`getMovies` Retrofit 方法中，您可以使用以下内容：

```kt
@GET("movie")
fun getMovies() : Observable<Movie>
```

让我们尝试一下您迄今为止学到的知识，通过将 RxJava 添加到 Android 项目中。

## 练习 13.01：在 Android 项目中使用 RxJava

本章中，您将使用一个应用程序来显示使用 The Movie Database API 的热门电影。转到[`developers.themoviedb.org/`](https://developers.themoviedb.org/)并注册 API 密钥。在这个练习中，您将使用 RxJava 从电影/流行的端点获取所有热门电影的列表，而不考虑年份：

1.  在 Android Studio 中创建一个新项目。将项目命名为`Popular Movies`，并使用包名`com.example.popularmovies`。

1.  设置您想要保存项目的位置，然后单击`完成`按钮。

1.  打开`AndroidManifest.xml`并添加`INTERNET`权限：

```kt
<uses-permission android:name="android.permission.INTERNET" />
```

这将允许您使用设备的互联网连接进行网络调用。

1.  打开`app/build.gradle`文件，并在插件块的末尾添加 kotlin-parcelize 插件：

```kt
plugins {
    ...
    id 'kotlin-parcelize'
}
```

这将允许您为模型类使用 Parcelable。

1.  在`android`块中添加以下内容：

```kt
compileOptions {
    sourceCompatibility JavaVersion.VERSION_1_8
    targetCompatibility JavaVersion.VERSION_1_8
}
kotlinOptions {
    jvmTarget = '1.8'
}
```

这将允许您在项目中使用 Java 8。

1.  在`app/build.gradle`文件中添加以下依赖项：

```kt
implementation 'androidx.recyclerview:recyclerview:1.1.0'
implementation 'com.squareup.retrofit2:retrofit:2.9.0'
implementation 'com.squareup.retrofit2:adapter-rxjava3:2.9.0'
implementation 'io.reactivex.rxjava3:rxandroid:3.0.0'
implementation 'io.reactivex.rxjava3:rxjava:3.0.7'
implementation 'com.squareup.retrofit2:converter-moshi:2.9.0'
implementation 'com.github.bumptech.glide:glide:4.11.0'
```

这些行将向您的项目中添加 RecyclerView、Glide、Retrofit、RxJava、RxAndroid 和 Moshi 库。

1.  在`res/values`目录中创建一个`dimens.xml`文件，并添加一个`layout_margin`维度值：

```kt
<resources>
    <dimen name="layout_margin">16dp</dimen>
</resources>
```

这将用于视图的垂直和水平边距。

1.  创建一个名为`view_movie_item.xml`的新布局文件，并添加以下内容：

```kt
view_movie_item.xml
9    <ImageView
10        android:id="@+id/movie_poster"
11        android:layout_width="match_parent"
12        android:layout_height="240dp"
13        android:contentDescription="Movie Poster"
14        app:layout_constraintBottom_toBottomOf="parent"
15        app:layout_constraintEnd_toEndOf="parent"
16        app:layout_constraintStart_toStartOf="parent"
17        app:layout_constraintTop_toTopOf="parent"
18        tools:src="img/scenic" />
19
20    <TextView
21        android:id="@+id/movie_title"
22        android:layout_width="match_parent"
23        android:layout_height="wrap_content"
24        android:layout_marginStart="@dimen/layout_margin"
25        android:layout_marginEnd="@dimen/layout_margin"
26        android:ellipsize="end"
27        android:gravity="center"
28        android:lines="1"
29        android:textSize="20sp"
30        app:layout_constraintEnd_toEndOf="@id/movie_poster"
31        app:layout_constraintStart_toStartOf="@id/movie_poster"
32        app:layout_constraintTop_toBottomOf="@id/movie_poster"
33        tools:text="Movie" />
The complete code for this step can be found at http://packt.live/3sD8zmN.
```

这个布局文件包含电影海报和标题文本，将用于列表中的每部电影。

1.  打开`activity_main.xml`。用 RecyclerView 替换 Hello World TextView：

```kt
<androidx.recyclerview.widget.RecyclerView
    android:id="@+id/movie_list"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
app:layoutManager=  "androidx.recyclerview.widget.GridLayoutManager"
    app:layout_constraintBottom_toBottomOf="parent"
    app:layout_constraintTop_toTopOf="parent"
    app:spanCount="2"
    tools:listitem="@layout/view_movie_item" />
```

这个 RecyclerView 将显示电影列表。它将使用`GridLayoutManager`，有两列。

1.  为您的模型类创建一个新包`com.example.popularmovies.model`。创建一个名为`Movie`的新模型类，如下所示：

```kt
@Parcelize
data class Movie(
    val adult: Boolean = false,
    val backdrop_path: String = "",
    val id: Int = 0,
    val original_language: String = "",
    val original_title: String = "",
    val overview: String = "",
    val popularity: Float = 0f,
    val poster_path: String = "",
    val release_date: String = "",
    val title: String = "",
    val video: Boolean = false,
    val vote_average: Float = 0f,
    val vote_count: Int = 0
) : Parcelable
```

这将是代表 API 中的`Movie`对象的模型类。

1.  创建一个名为`DetailsActivity`的新活动，使用`activity_details.xml`作为布局文件。

1.  打开`AndroidManifest.xml`文件，并将`MainActivity`作为`DetailsActivity`的`parentActivityName`属性的值添加进去：

```kt
<activity android:name=".DetailsActivity"
            android:parentActivityName=".MainActivity" />
```

这将在详细信息活动中添加一个向上图标，以返回到主屏幕。

1.  打开`activity_details.xml`。添加所需的视图。（以下代码由于空间限制而被截断。请参考下面链接的文件以获取您需要添加的完整代码。）

```kt
activity_details.xml
9    <ImageView
10        android:id="@+id/movie_poster"
11        android:layout_width="160dp"
12        android:layout_height="160dp"
13        android:layout_margin="@dimen/layout_margin"
14        android:contentDescription="Poster"
15        app:layout_constraintStart_toStartOf="parent"
16        app:layout_constraintTop_toTopOf="parent"
17        tools:src="img/avatars" />
18
19    <TextView
20        android:id="@+id/title_text"
21        style="@style/TextAppearance.AppCompat.Title"
22        android:layout_width="0dp"
23        android:layout_height="wrap_content"
24        android:layout_margin="@dimen/layout_margin"
25        android:ellipsize="end"
26        android:maxLines="4"
27        app:layout_constraintEnd_toEndOf="parent"
28        app:layout_constraintStart_toEndOf="@+id/movie_poster"
29        app:layout_constraintTop_toTopOf="parent"
30        tools:text="Title" />
The complete code for this step can be found at http://packt.live/38WyRbQ.
```

这将在详情屏幕上添加海报、标题、发布日期和概述。

1.  打开`DetailsActivity`并添加以下内容：

```kt
class DetailsActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_MOVIE = "movie"
        const val IMAGE_URL = "https://image.tmdb.org/t/p/w185/"
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_details)
        val titleText: TextView = findViewById(R.id.title_text)
        val releaseText: TextView = findViewById(R.id.release_text)
        val overviewText: TextView = findViewById(R.id.overview_text)
        val poster: ImageView = findViewById(R.id.movie_poster)
        val movie = intent.getParcelableExtra<Movie>(EXTRA_MOVIE)
        movie?.run {
            titleText.text = title
            releaseText.text = release_date.take(4)
            overviewText.text = "Overview: $overview"
            Glide.with(this@DetailsActivity)
                .load("$IMAGE_URL$poster_path")
                .placeholder(R.mipmap.ic_launcher)
                .fitCenter()
                .into(poster)
        }
    }
}
```

这将显示所选电影的海报、标题、发布日期和概述。

1.  为电影列表创建一个适配器类。将类命名为`MovieAdapter`。添加以下内容：

```kt
class MovieAdapter(private val clickListener: MovieClickListener) :   RecyclerView.Adapter<MovieAdapter.MovieViewHolder>() {
    private val movies = mutableListOf<Movie>()
override fun onCreateViewHolder(parent: ViewGroup,   viewType: Int): MovieViewHolder {
        val view = LayoutInflater.from(parent.context)          .inflate(R.layout.view_movie_item, parent, false)
        return MovieViewHolder(view)
    }
    override fun getItemCount() = movies.size
    override fun onBindViewHolder(holder: MovieViewHolder,       position: Int) {
        val movie = movies[position]
        holder.bind(movie)
        holder.itemView.setOnClickListener {           clickListener.onMovieClick(movie) }
    }
    fun addMovies(movieList: List<Movie>) {
        movies.addAll(movieList)
        notifyItemRangeInserted(0, movieList.size)
    }
}
```

这个类将是您的 RecyclerView 的适配器。

1.  在`onBindViewHolder`函数之后为您的类添加`ViewHolder`：

```kt
class MovieAdapter...
    ...
    class MovieViewHolder(itemView: View) :       RecyclerView.ViewHolder(itemView) {
        private val imageUrl = "https://image.tmdb.org/t/p/w185/"
        private val titleText: TextView by lazy {
            itemView.findViewById(R.id.movie_title)
        }
        private val poster: ImageView by lazy {
            itemView.findViewById(R.id.movie_poster)
        }
        fun bind(movie: Movie) {
            titleText.text = movie.title
            Glide.with(itemView.context)
                .load("$imageUrl${movie.poster_path}")
                .placeholder(R.mipmap.ic_launcher)
                .fitCenter()
                .into(itemView.poster)
        }
    }
}
```

这将是`MovieAdapter`用于 RecyclerView 的`ViewHolder`。

1.  在`MovieViewHolder`声明之后，添加`MovieClickListener`：

```kt
class MovieAdapter...
    ...
    interface MovieClickListener {
        fun onMovieClick(movie: Movie)
    }
}
```

这个接口将在点击电影查看详情时使用。

1.  在`com.example.popularmovies.model`包中创建另一个名为`PopularMoviesResponse`的类：

```kt
data class PopularMoviesResponse (
    val page: Int,
    val results: List<Movie>
)
```

这将是您从热门电影 API 端点获取的响应的模型类。

1.  创建一个新的包`com.example.popularmovies.api`，并添加一个带有以下内容的`MovieService`接口：

```kt
interface MovieService {
@GET("movie/popular")
fun getPopularMovies(@Query("api_key") apiKey: String):   Observable<PopularMoviesResponse>
}
```

这将定义您将使用的端点来检索热门电影。

1.  创建一个`MovieRepository`类，并为`movieService`添加一个构造函数：

```kt
class MovieRepository(private val movieService: MovieService) { ... } 
```

1.  添加`apiKey`（值为 The Movie Database API 的 API 密钥）和一个`fetchMovies`函数来从端点检索列表：

```kt
private val apiKey = "your_api_key_here"
fun fetchMovies() = movieService.getPopularMovies(apiKey)
```

1.  创建一个名为`MovieApplication`的应用程序类，并为`movieRepository`添加一个属性：

```kt
class MovieApplication : Application() {
    lateinit var movieRepository: MovieRepository
}
```

这将是应用程序的应用程序类。

1.  覆盖`MovieApplication`类的`onCreate`函数并初始化`movieRepository`：

```kt
override fun onCreate() { 
  super.onCreate()
  val retrofit = Retrofit.Builder()
    .baseUrl("https://api.themoviedb.org/3/")
    .addConverterFactory(MoshiConverterFactory.create())
    .addCallAdapterFactory(RxJava3CallAdapterFactory.create())
    .build()
  val movieService = retrofit.create(MovieService::class.java)
  movieRepository = MovieRepository(movieService) 
}
```

1.  将`MovieApplication`设置为`AndroidManifest.xml`文件中应用程序的`android:name`属性的值：

```kt
<application
    ...
    android:name=".MovieApplication"
    ... />
```

1.  创建一个`MovieViewModel`类，并为`movieRepository`添加一个构造函数：

```kt
class MovieViewModel(private val movieRepository: MovieRepository) :   ViewModel() { ... }
```

1.  为`popularMovies`，`error`和`disposable`添加属性：

```kt
private val popularMoviesLiveData = MutableLiveData<List<Movie>>()
private val errorLiveData = MutableLiveData<String>()
val popularMovies: LiveData<List<Movie>>
    get() = popularMoviesLiveData
val error: LiveData<String>
    get() = errorLiveData
private var disposable = CompositeDisposable()
```

1.  定义`fetchPopularMovies`函数。在函数内部，从`movieRepository`获取热门电影：

```kt
    fun fetchPopularMovies() {
        disposable.add(movieRepository.fetchMovies()
            .subscribeOn(Schedulers.io())
            .map { it.results }
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({
                popularMoviesLiveData.postValue(it)
            }, { error ->
                errorLiveData.postValue("An error occurred:                   ${error.message}")
            })
        )
    }
```

当订阅时，这将在`Schedulers.io`线程中异步获取热门电影，并返回一个可观察对象，并在主线程上使用操作符。

1.  覆盖`MovieViewModel`的`onCleared`函数并处理`disposable`：

```kt
    override fun onCleared() {
        super.onCleared()
        disposable.dispose()
    }
```

当 ViewModel 被清除时，例如当活动被关闭时，这将处理`disposable`。

1.  打开`MainActivity`并定义一个电影适配器的字段：

```kt
private val movieAdapter by lazy {
    MovieAdapter(object : MovieAdapter.MovieClickListener {
        override fun onMovieClick(movie: Movie) {
            openMovieDetails(movie)
        }
    })
}
```

这将有一个监听器，当点击电影时将打开详情屏幕。

1.  在`onCreate`函数中，为`movie_list`的`RecyclerView`设置适配器：

```kt
val recyclerView: RecyclerView = findViewById(R.id.movie_list)
recyclerView.adapter = movieAdapter 
```

1.  在`MainActivity`上创建一个`getMovies`函数。在内部，初始化`movieRepository`和`movieViewModel`：

```kt
    private fun getMovies() {
        val movieRepository = (application as           MovieApplication).movieRepository
        val movieViewModel = ViewModelProvider(this, object :           ViewModelProvider.Factory {
            override fun <T : ViewModel?>               create(modelClass: Class<T>): T {
                return MovieViewModel(movieRepository) as T
            }
        }).get(MovieViewModel::class.java)
    }
```

1.  在`getMovies`函数的末尾，向`movieViewModel`的`popularMovies`和`error` LiveData 添加一个观察者：

```kt
private fun getMovies() {
        ...
        movieViewModel.fetchPopularMovies()
        movieViewModel.popularMovies
            .observe(this, { popularMovies ->
                movieAdapter.addMovies(popularMovies)
            })
            movieViewModel.error.observe(this, { error ->
                Toast.makeText(this, error, Toast.LENGTH_LONG).show()
            })
    }
```

1.  在`MainActivity`类的`onCreate`函数的末尾，调用`getMovies()`函数：

```kt
getMovies()
```

1.  在点击列表中的电影时添加`openMovieDetails`函数以打开详情屏幕：

```kt
private fun openMovieDetails(movie: Movie) { 
    val intent =       Intent(this, DetailsActivity::class.java).apply { 
        putExtra(DetailsActivity.EXTRA_MOVIE, movie)
    }
    startActivity(intent)
}
```

1.  运行您的应用程序。您将看到该应用程序将显示一个热门电影标题列表：![图 13.1：热门电影应用程序的外观](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_01.jpg)

图 13.1：热门电影应用程序的外观

1.  点击电影，您将看到它的发布日期和概述等详情：

![图 13.2：电影详情屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_02.jpg)

图 13.2：电影详情屏幕

您已经学会了如何使用 RxJava 从外部 API 检索响应。在下一节中，您将使用 RxJava 操作符将获取的数据转换为需要显示的数据。

## 使用 RxJava 操作符修改数据

当您有一个发出数据的 observable 时，您可以使用操作符在将其传递给观察者之前修改数据。您可以使用单个操作符或一系列操作符来获取所需的数据。您可以使用不同类型的操作符，例如转换操作符和过滤操作符。

转换操作符可以将 observable 中的项目修改为您喜欢的数据。 `flatMap（）`操作符将项目转换为 observable。在*练习 13.01* *在 Android 项目中使用 RxJava*中，您将 observable `PopularMoviesResponse`转换为 observable `Movies`如下：

```kt
.flatMap { Observable.fromIterable(it.results) }
```

另一个可以转换数据的操作符是`map`。`map（x）`操作符将函数`x`应用于每个项目，并返回具有更新值的另一个 observable。例如，如果您有一个数字列表的 observable，可以使用以下内容将其转换为另一个 observable 列表，其中每个数字都乘以 2：

```kt
.map { it * 2 }
```

过滤操作符允许您仅选择其中的一些项目。使用`filter（）`，您可以根据一组条件选择项目。例如，您可以使用以下内容过滤奇数：

```kt
.filter { it % 2 != 0 }
```

`first（）`和`last（）`操作符允许您获取第一个和最后一个项目，而使用`take（n）`或`takeLast（n）`，您可以获取*n*个第一个或最后一个项目。还有其他过滤操作符，如`debounce（）`，`distinct（）`，`elementAt（）`，`ignoreElements（）`，`sample（）`，`skip（）`和`skipLast（）`。

还有许多其他 RxJava 操作符可供您使用。让我们尝试在 Android 项目中使用 RxJava 操作符。

## 练习 13.02：使用 RxJava 操作符

在上一个练习中，您使用了 RxJava 从 The Movie Database API 获取了热门电影列表。现在，在将它们显示在 RecyclerView 之前，您将添加操作符来按标题排序电影并仅获取上个月发布的电影：

1.  打开*练习 13.01* *在 Android 项目中使用 RxJava*中的`Popular Movies`项目。

1.  打开`MovieViewModel`并导航到`fetchPopularMovies`函数。

1.  您将修改应用程序以仅显示今年的热门电影。将`.map { it.results }`替换为以下内容：

```kt
.flatMap { Observable.fromIterable(it.results) }
.toList()
```

这将把`MovieResponse`的 Observable 转换为`Movies`的 observable。

1.  在`toList（）`调用之前，添加以下内容：

```kt
.filter {
    val cal = Calendar.getInstance()
    cal.add(Calendar.MONTH, -1)
    it.release_date.startsWith(
        "${cal.get(Calendar.YEAR)}-${cal.get(Calendar.MONTH) + 1}"
    )
}
```

这将仅选择上个月发布的电影。

1.  运行应用程序。您将看到其他电影不再显示。只有今年发布的电影才会出现在列表上：![图 13.3：年度热门电影应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_03.jpg)

图 13.3：年度热门电影应用程序

1.  您还会注意到显示的电影没有按字母顺序排列。在`toList（）`调用之前使用`sorted`操作符对电影进行排序：

```kt
.sorted { movie, movie2 -> movie.title.compareTo(movie2.title) }
```

这将根据它们的标题对电影进行排序。

1.  运行应用程序。您将看到电影列表现在按标题按字母顺序排序：![图 13.4：按标题排序的年度热门电影应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_04.jpg)

图 13.4：按标题排序的年度热门电影应用程序

1.  在`toList（）`调用之前，使用`map`操作符将电影列表映射到另一个标题为大写的列表中：

```kt
.map { it.copy(title = it.title.toUpperCase(Locale.getDefault())) }
```

1.  运行应用程序。您将看到电影标题现在是大写字母：![图 13.5：电影标题为大写的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_05.jpg)

图 13.5：电影标题为大写的应用程序

1.  在`toList（）`调用之前，使用`take`操作符仅从列表中获取前四部电影：

```kt
.take(4)
```

1.  运行应用程序。您将看到 RecyclerView 只会显示四部电影：![图 13.6：只有四部电影的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_06.jpg)

图 13.6：只有四部电影的应用程序

1.  尝试其他 RxJava 操作符并运行应用程序查看结果。

您已经学会了如何使用 RxJava 操作符在显示它们之前操作来自外部 API 的检索响应。

在下一节中，您将学习如何使用协程而不是 RxJava 从外部 API 获取数据。

# 协程

Kotlin 1.3 中添加了协程，用于管理后台任务，例如进行网络调用和访问文件或数据库。Kotlin 协程是 Google 在 Android 上异步编程的官方推荐。他们的 Jetpack 库，如 LifeCycle、WorkManager 和 Room，现在包括对协程的支持。

使用协程，您可以以顺序方式编写代码。长时间运行的任务可以转换为挂起函数，当调用时可以暂停线程而不阻塞它。当挂起函数完成时，当前线程将恢复执行。这将使您的代码更易于阅读和调试。

将函数标记为挂起函数，可以在其中添加`suspend`关键字；例如，如果您有一个调用`getMovies`函数的函数，该函数从您的端点获取`movies`然后显示它：

```kt
val movies = getMovies()
displayMovies(movies) 
```

您可以通过添加`suspend`关键字将`getMovies()`函数设置为挂起函数：

```kt
suspend fun getMovies(): List<Movies> { ... }
```

在这里，调用函数将调用`getMovies`并暂停。在`getMovies`返回电影列表后，它将恢复其任务并显示电影。

挂起函数只能在挂起函数中调用，或者从协程中调用。协程具有上下文，其中包括协程调度程序。调度程序指定协程将使用的线程。您可以使用三个调度程序：

+   `Dispatchers.Main`：用于在 Android 的主线程上运行

+   `Dispatchers.IO`：用于网络、文件或数据库操作

+   `Dispatchers.Default`：用于 CPU 密集型工作

要更改协程的上下文，可以使用`withContext`函数，用于您希望在不同线程中使用的代码。例如，在您的挂起函数`getMovies`中，该函数从您的端点获取电影，您可以使用`Dispatchers.IO`：

```kt
suspend fun getMovies(): List<Movies>  {
    withContext(Dispatchers.IO) { ... }
}
```

在下一节中，我们将介绍如何创建协程。

## 创建协程

您可以使用`async`和`launch`关键字创建一个协程。`launch`关键字创建一个协程并不返回任何东西。另一方面，`async`关键字返回一个值，您可以稍后使用`await`函数获取。

`async`和`launch`必须从`CoroutineScope`创建，它定义了协程的生命周期。例如，主线程的协程范围是`MainScope`。然后，您可以使用以下内容创建协程：

```kt
MainScope().async { ... }
MainScope().launch { ... }
```

您还可以创建自己的`CoroutineScope`，而不是使用`MainScope`，通过使用`CoroutineScope`创建一个协程的上下文。例如，要为网络调用创建`CoroutineScope`，可以定义如下内容：

```kt
val scope = CoroutineScope(Dispatchers.IO)
```

当不再需要函数时，例如关闭活动时，可以取消协程。您可以通过从`CoroutineScope`调用`cancel`函数来实现：

```kt
scope.cancel()
```

ViewModel 还具有用于创建协程的默认`CoroutineScope`：`viewModelScope`。Jetpack 的 LifeCycle 还具有`lifecycleScope`，您可以使用它。当 ViewModel 被销毁时，`viewModelScope`被取消；当生命周期被销毁时，`lifecycleScope`也被取消。因此，您不再需要取消它们。

在下一节中，您将学习如何将协程添加到您的项目中。

## 将协程添加到您的项目中

您可以通过将以下代码添加到您的`app/build.gradle`文件的依赖项中，将协程添加到您的项目中：

```kt
implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.3.9"
implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.3.9"
```

`kotlinx-coroutines-core`是协程的主要库，而`kotlinx-coroutines-android`为主要的 Android 线程添加了支持。

在 Android 中进行网络调用或从本地数据库获取数据时，可以添加协程。

如果您使用的是 Retrofit 2.6.0 或更高版本，可以使用`suspend`将端点函数标记为挂起函数：

```kt
@GET("movie/latest")
suspend fun getMovies() : List<Movies>
```

然后，您可以创建一个协程，调用挂起函数`getMovies`并显示列表：

```kt
CoroutineScope(Dispatchers.IO).launch {
    val movies = movieService.getMovies()
    withContext(Dispatchers.Main) {
        displayMovies(movies)
    }
}
```

您还可以使用 LiveData 来响应您的协程。LiveData 是一个 Jetpack 类，可以保存可观察的数据。通过添加以下依赖项，您可以将 LiveData 添加到 Android 项目中：

```kt
implementation 'androidx.lifecycle:lifecycle-livedata-ktx:2.2.0'
```

让我们尝试在 Android 项目中使用协程。

## 练习 13.03：在 Android 应用程序中使用协程

在这个练习中，您将使用协程从 The Movie Database API 获取热门电影列表。您可以使用上一个练习中的`Popular Movies`项目，或者复制一个：

1.  在 Android Studio 中打开`Popular Movies`项目。

1.  打开`app/build.gradle`文件，并删除以下依赖项：

```kt
implementation 'com.squareup.retrofit2:adapter-rxjava3:2.9.0'
implementation 'io.reactivex.rxjava3:rxandroid:3.0.0'
implementation 'io.reactivex.rxjava3:rxjava:3.0.7'
```

由于您将使用协程而不是 RxJava，因此将不再需要这些依赖项。

1.  在`app/build.gradle`文件中，添加 Kotlin 协程的依赖项：

```kt
implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-core:1.3.9'
implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.3.9'
```

这将允许您在项目中使用协程。

1.  还要添加 ViewModel 和 LiveData 扩展库的依赖项：

```kt
implementation 'androidx.lifecycle:lifecycle-livedata-ktx:2.2.0'
implementation 'androidx.lifecycle:lifecycle-viewmodel-ktx:2.2.0'
```

1.  打开`MovieService`接口，并用以下代码替换它：

```kt
interface MovieService {
    @GET("movie/popular")
    suspend fun getPopularMovies(@Query("api_key") apiKey: String):       PopularMoviesResponse
}
```

这将把`getPopularMovies`标记为挂起函数。

1.  打开`MovieRepository`并为电影列表添加 movies 和 error LiveData：

```kt
    private val movieLiveData = MutableLiveData<List<Movie>>()
    private val errorLiveData = MutableLiveData<String>()
    val movies: LiveData<List<Movie>>
        get() = movieLiveData
    val error: LiveData<String>
        get() = errorLiveData
```

1.  将`fetchMovies`函数替换为一个挂起函数，以从端点检索列表：

```kt
    suspend fun fetchMovies() {
        try {
            val popularMovies = movieService.getPopularMovies(apiKey)
            movieLiveData.postValue(popularMovies.results)
        } catch (exception: Exception) {
            errorLiveData.postValue("An error occurred:               ${exception.message}")
        }
    }
```

1.  使用以下代码更新`MovieViewModel`的内容：

```kt
    init {
        fetchPopularMovies()
    }
    val popularMovies: LiveData<List<Movie>>
    get() = movieRepository.movies
    fun getError(): LiveData<String> = movieRepository.error
    private fun fetchPopularMovies() {
        viewModelScope.launch(Dispatchers.IO)  {
            movieRepository.fetchMovies()
        }
    }
```

`fetchPopularMovies`函数有一个协程，使用`viewModelScope`，它将从`movieRepository`获取电影。

1.  打开`MovieApplication`文件。在`onCreate`函数中，删除包含`addCallAdapterFactory`的行。它应该是这样的：

```kt
    override fun onCreate() {
        super.onCreate()
        val retrofit = Retrofit.Builder()
            .baseUrl("https://api.themoviedb.org/3/")
            .addConverterFactory(MoshiConverterFactory.create())
            .build()
        ...
    }
```

1.  打开`MainActivity`类。删除`getMovies`函数。

1.  在`onCreate`函数中，删除对`getMovies`的调用。然后，在`onCreate`函数的末尾，创建`movieViewModel`：

```kt
val movieRepository =   (application as MovieApplication).movieRepository
val movieViewModel =   ViewModelProvider(this, object: ViewModelProvider.Factory {
    override fun <T : ViewModel?>       create(modelClass: Class<T>): T {
        return MovieViewModel(movieRepository) as T
    }
}).get(MovieViewModel::class.java)
```

1.  之后，向`movieViewModel`的`getPopularMovies`和`error` LiveData 添加观察者：

```kt
        movieViewModel.popularMovies.observe(this, { popularMovies ->
            movieAdapter.addMovies(popularMovies
                .filter {
                    it.release_date.startsWith(
                        Calendar.getInstance().get(Calendar.YEAR)                          .toString()
                    )
                }
                .sortedBy { it.title }
            )
        })
        movieViewModel.getError().observe(this, { error ->
            Toast.makeText(this, error, Toast.LENGTH_LONG).show()
})
```

这将使用 Kotlin 的`filter`函数对电影列表进行过滤，只包括今年发布的电影。然后使用 Kotlin 的`sortedBy`函数按标题排序。

1.  运行应用程序。您将看到应用程序将显示今年发布的热门电影标题列表，按标题排序：

![图 13.7：应用程序显示今年发布的热门电影，按标题排序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_07.jpg)

图 13.7：应用程序显示今年发布的热门电影，按标题排序

您已经使用协程和 LiveData 从远程数据源检索和显示了一组热门电影列表，而不会阻塞主线程。

在将 LiveData 传递到 UI 进行显示之前，您还可以首先转换数据。您将在下一节中了解到这一点。

# 转换 LiveData

有时，您从 ViewModel 传递到 UI 层的 LiveData 在显示之前需要进行处理。例如，您只能选择部分数据或者首先对其进行一些处理。在上一个练习中，您对数据进行了过滤，只选择了当前年份的热门电影。

要修改 LiveData，您可以使用`Transformations`类。它有两个函数，`Transformations.map`和`Transformations.switchMap`，您可以使用。

`Transformations.map`将 LiveData 的值修改为另一个值。这可用于过滤、排序或格式化数据等任务。例如，您可以将`movieLiveData`从电影标题转换为字符串 LiveData：

```kt
private val movieLiveData: LiveData<Movie>
val movieTitleLiveData : LiveData<String> = 
   Transformations.map(movieLiveData) { it.title }
```

当`movieLiveData`的值发生变化时，`movieTitleLiveData`也会根据电影的标题发生变化。

使用`Transformations.switchMap`，您可以将 LiveData 的值转换为另一个 LiveData。当您想要使用原始 LiveData 进行涉及数据库或网络操作的特定任务时使用。例如，如果您有一个表示电影`id`对象的 LiveData，您可以通过应用函数`getMovieDetails`将其转换为电影 LiveData，该函数从`id`对象（例如从另一个网络或数据库调用）返回电影详细信息的 LiveData：

```kt
private val idLiveData: LiveData<Int> = MutableLiveData()
val movieLiveData : LiveData<Movie> = 
    Transformations.switchMap(idLiveData) { getMovieDetails(it) }
fun getMovieDetails(id: Int) : LiveData<Movie> = { ... }
```

让我们在使用协程获取的电影列表上使用 LiveData 转换。

## 练习 13.04：LiveData 转换

在这个练习中，您将在传递给`MainActivity`文件中的观察者之前转换电影的 LiveData 列表：

1.  在 Android Studio 中，打开您在上一个练习中使用的“热门电影”项目。

1.  打开`MainActivity`文件。在`onCreate`函数中的`movieViewModel.popularMovies`观察者中，删除过滤器和`sortedBy`函数调用。代码应如下所示：

```kt
movieViewModel.getPopularMovies().observe(this,   Observer { popularMovies ->
    movieAdapter.addMovies(popularMovies)
})
```

现在将显示列表中的所有电影，而不按标题排序。

1.  运行应用程序。您应该看到所有电影（甚至是去年的电影），而不是按标题排序：![图 13.8：未排序的热门电影应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_08.jpg)

图 13.8：未排序的热门电影应用程序

1.  打开`MovieViewModel`类，并使用 LiveData 转换来更新`popularMovies`以过滤和排序电影：

```kt
        val popularMovies: LiveData<List<Movie>>
        get() = movieRepository.movies.map { list ->
        list.filter {
            val cal = Calendar.getInstance()
            cal.add(Calendar.MONTH, -1)
            it.release_date.startsWith(
                "${cal.get(Calendar.YEAR)}-${cal.get(Calendar.MONTH)                   + 1}"
            )
        }.sortedBy { it.title }
    }
```

这将选择上个月发布的电影，并在传递给`MainActivity`中的 UI 观察者之前按标题排序。

1.  运行应用程序。您会看到应用程序显示了按标题排序的今年热门电影列表：

![图 13.9：按标题排序的今年发布的电影应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_05.jpg)

图 13.9：按标题排序的今年发布的电影应用程序

您已经使用了 LiveData 转换来修改电影列表，只选择今年发布的电影。它们在传递给 UI 层的观察者之前也按标题排序。

# 协程通道和流

如果您的协程正在获取数据流或您有多个数据源并且逐个处理数据，您可以使用通道或流。

通道允许在不同的协程之间传递数据。它们是热数据流。它将在被调用时运行并发出值，即使没有监听器。而流是冷异步流。只有在收集值时才会发出值。

要了解有关通道和流的更多信息，您可以访问[`kotlinlang.org`](https://kotlinlang.org)。

# RxJava 与协程

RxJava 和协程都可以用于在 Android 中执行后台任务，例如网络调用或数据库操作。

那么应该使用哪一个？虽然您可以在应用程序中同时使用两者，例如，对于一个任务使用 RxJava，对于另一个任务使用协程，您还可以与`LiveDataReactiveStreams`或`kotlinx-coroutines-rx3`一起使用它们。然而，这将增加您使用的依赖项数量和您的应用程序的大小。

那么，RxJava 还是协程？以下表格显示了两者之间的区别：

![图 13.10：协程和 RxJava 之间的区别](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_10.jpg)

图 13.10：协程和 RxJava 之间的区别

让我们继续下一个活动。

## 活动 13.01：创建电视指南应用程序

很多人看电视。然而，大多数时候，他们不确定当前有哪些电视节目正在播放。假设你想开发一个应用程序，可以使用 Kotlin 协程和 LiveData 从 The Movie Database API 的`tv/on_the_air`端点显示这些节目的列表。

该应用程序将有两个屏幕：主屏幕和详情屏幕。在主屏幕上，您将显示正在播出的电视节目列表。电视节目将按名称排序。点击一个电视节目将打开详情屏幕，显示有关所选电视节目的更多信息。

完成步骤：

1.  在 Android Studio 中创建一个名为`TV Guide`的新项目，并设置其包名称。

1.  在`AndroidManifest.xml`文件中添加`INTERNET`权限。

1.  在`app/build.gradle`文件中，添加 Java 8 兼容性和 RecyclerView、Glide、Retrofit、RxJava、RxAndroid、Moshi、ViewModel 和 LiveData 库的依赖项。

1.  添加`layout_margin`维度值。

1.  创建一个`view_tv_show_item.xml`布局文件，其中包含用于海报的`ImageView`和用于电视节目名称的`TextView`。

1.  在`activity_main.xml`文件中，删除 Hello World TextView，并添加一个用于电视节目列表的 RecyclerView。

1.  创建一个名为`TVShow`的模型类。

1.  创建一个名为`DetailsActivity`的新活动，使用`activity_details.xml`作为布局文件。

1.  打开`AndroidManifest.xml`文件，在`DetailsActivity`声明中添加`parentActivityName`属性。

1.  在`activity_details.xml`中，添加用于电视节目详情的视图。

1.  在`DetailsActivity`中，添加用于显示所选电视节目详情的代码。

1.  为电视节目列表创建一个`TVShowAdapter`适配器类。

1.  创建另一个名为`TVResponse`的类，用于从 API 端点获取正在播出的电视节目的响应。

1.  创建一个`TelevisionService`类，用于添加 Retrofit 方法。

1.  创建一个名为`TVShowRepository`的类，其中包含`tvService`的构造函数，以及`apiKey`和`tvShows`的属性。

1.  创建一个挂起函数，从端点检索电视节目列表。

1.  创建一个`TVShowViewModel`类，其中包含`TVShowRepository`的构造函数。添加一个`getTVShows`函数，返回电视节目列表的 LiveData，以及`fetchTVShows`函数，从存储库中获取列表。

1.  创建一个名为`TVApplication`的应用程序类，其中包含`TVShowRepository`的属性。

1.  将`TVApplication`设置为`AndroidManifest.xml`文件中应用程序的值。

1.  打开`MainActivity`并添加代码，以在`ViewModel`更新其值时更新 RecyclerView。添加一个函数，点击列表中的电视节目将打开详情屏幕。

1.  运行你的应用程序。该应用程序将显示一个电视节目列表。点击一个电视节目将打开详情活动，显示节目详情。主屏幕和详情屏幕将类似于以下图示：

![图 13.11：电视指南应用的主屏幕和详情屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_11.jpg)

图 13.11：电视指南应用的主屏幕和详情屏幕

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 总结

本章重点介绍了使用 RxJava 和协程进行后台操作。后台操作用于长时间运行的任务，例如从本地数据库或远程服务器访问数据。

您从 RxJava 的基础知识开始：可观察对象、观察者和操作符。可观察对象是提供数据的数据源。观察者监听可观察对象；当可观察对象发出数据时，观察者可以做出相应反应。操作符允许您修改可观察对象的数据，使其能够传递给观察者所需的数据。

接下来，您学习了如何使用调度程序使 RxJava 调用异步。调度程序允许您设置执行所需操作的线程。`subscribeOn`函数用于设置可观察对象将在哪个线程上运行，`observeOn`函数允许您设置下一个操作将在哪里执行。然后，您使用 RxJava 从外部 API 获取数据，并使用 RxJava 操作符对数据进行过滤、排序和修改。

接下来，你将学习使用 Kotlin 协程，这是 Google 推荐的异步编程解决方案。你可以使用`suspend`关键字将后台任务转换为挂起函数。协程可以使用`async`或`launch`关键字启动。

你已经学会了如何创建挂起函数以及如何启动协程。你还使用调度程序来改变协程运行的线程。最后，你使用协程来进行网络调用，并使用 LiveData 转换函数`map`和`switchMap`修改检索到的数据。

在下一章中，你将学习关于架构模式。你将学习诸如**MVVM**（**Model-View-ViewModel**）之类的模式，以及如何改进应用程序的架构。
