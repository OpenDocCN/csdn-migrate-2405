# 如何使用 Kotlin 构建安卓应用（五）

> 原文：[`zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295`](https://zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Android 架构组件

概述

在本章中，您将了解 Android Jetpack 库的关键组件以及它们为标准 Android 框架带来的好处。您还将学习如何使用 Jetpack 组件来构建代码并为您的类分配不同的责任。最后，您将提高代码的测试覆盖率。

通过本章的学习，您将能够轻松处理活动和片段的生命周期。您还将了解如何使用 Room 在 Android 设备上持久保存数据，以及如何使用 ViewModels 将逻辑与视图分离。

# 介绍

在之前的章节中，您学会了如何编写单元测试。问题是：您可以对什么进行单元测试？您可以对活动和片段进行单元测试吗？由于它们的构建方式，它们在您的机器上很难进行单元测试。如果您可以将代码从活动和片段中移出来，测试将会更容易。

另外，考虑一下您正在构建一个支持不同方向（如横向和纵向）和支持多种语言的应用程序的情况。在这些情景中，默认情况下会发生的情况是，当用户旋转屏幕时，活动和片段会为新的显示方向重新创建。现在，想象一下这发生在您的应用程序正在处理数据的中间。您必须跟踪您正在处理的数据，您必须跟踪用户正在做什么来与您的屏幕交互，并且您必须避免造成上下文泄漏。

注意

上下文泄漏是指您销毁的活动由于在生命周期更长的组件中引用而无法进行垃圾回收 - 比如当前正在处理数据的线程。

在许多情况下，您将不得不使用`onSaveInstanceState`来保存活动/片段的当前状态，然后在`onCreate`或`onRestoreInstanceState`中，您需要恢复活动/片段的状态。这将给您的代码增加额外的复杂性，也会使其重复，特别是如果处理代码将成为您的活动或片段的一部分。

这些情景是`ViewModel`和`LiveData`发挥作用的地方。`ViewModels`是专门用于在生命周期发生变化时保存数据的组件。它们还将逻辑与视图分离，这使它们非常容易进行单元测试。`LiveData`是一个组件，用于保存数据并在发生更改时通知观察者，同时考虑它们的生命周期。简单来说，片段只处理视图，`ViewModel`负责繁重的工作，`LiveData`负责将结果传递给片段，但只有在片段准备好时才会这样做。

如果您曾经使用 WhatsApp 或类似的消息应用，并关闭了互联网，您会注意到您仍然能够使用该应用程序。原因是因为消息被本地存储在您的设备上。在大多数情况下，这是通过使用名为**SQLite**的数据库文件实现的。Android 框架已经允许您为您的应用程序使用此功能。这需要大量样板代码来读取和写入数据。每次您想要与本地存储交互时，您必须编写 SQL 查询。当您读取 SQLite 数据时，您必须将其转换为 Java/Kotlin 对象。所有这些都需要大量的代码、时间和单元测试。如果有人处理 SQLite 连接，而您只需专注于代码部分呢？这就是**Room**的作用。这是一个包装在 SQLite 上的库。您只需要定义数据应该如何保存，然后让库来处理其余部分。

假设您希望您的活动在有互联网连接和互联网断开时知道。您可以使用称为 BroadcastReceiver 的东西。这样做的一个小问题是，每次在活动中注册 BroadcastReceiver 时，您都必须在活动销毁时注销它。您可以使用 Lifecycle 来观察活动的状态，从而允许您的接收器在所需状态下注册，并在补充状态下注销（例如，RESUMED-PAUSED，STARTED-STOPPED 或 CREATED-DESTROYED）。

ViewModels，LiveData 和 Room 都是 Android 架构组件的一部分，它们是 Android Jetpack 库的一部分。架构组件旨在帮助开发人员构建其代码，编写可测试的组件，并帮助减少样板代码。其他架构组件包括数据绑定（将视图与模型或 ViewModel 绑定，允许数据直接设置在视图中）、WorkManager（允许开发人员轻松处理后台工作）、导航（允许开发人员创建可视化导航图并指定活动和片段之间的关系）和分页（允许开发人员加载分页数据，在需要无限滚动的情况下有所帮助）。

# ViewModel 和 LiveData

ViewModel 和 LiveData 都代表生命周期机制的专门实现。它们在希望在屏幕旋转时保持数据保存以及在希望数据仅在视图可用时显示时非常有用，从而避免开发人员面临的最常见问题之一——NullPointerException——当尝试更新视图时。一个很好的用法是当您希望显示您最喜爱球队比赛的实时比分和比赛的当前分钟数时。

## ViewModel

ViewModel 组件负责保存和处理 UI 所需的数据。它的好处是在销毁和重新创建片段和活动的配置更改时能够存活，从而保留数据，然后用于重新填充 UI。当活动或片段在不重新创建或应用程序进程终止时，它最终会被销毁。这使得 ViewModel 能够履行其责任，并在不再需要时进行垃圾回收。ViewModel 唯一的方法是 onCleared()方法，当 ViewModel 终止时会调用该方法。您可以重写此方法以终止正在进行的任务并释放不再需要的资源。

将数据处理从活动迁移到 ViewModel 有助于创建更好和更快的单元测试。测试活动需要在设备上执行的 Android 测试。活动还具有状态，这意味着您的测试应该将活动置于适当的状态以使断言起作用。ViewModel 可以在开发机器上进行本地单元测试，并且可以是无状态的，这意味着您的数据处理逻辑可以单独进行测试。

ViewModel 最重要的功能之一是它允许片段之间进行通信。要在没有 ViewModel 的情况下在片段之间进行通信，您必须使您的片段与活动进行通信，然后再调用您希望进行通信的片段。通过 ViewModel 实现这一点，您可以将它们附加到父活动并在希望进行通信的片段中使用相同的 ViewModel。这将减少以前所需的样板代码。

在下图中，您可以看到`ViewModel`可以在活动的生命周期中的任何时刻创建（实际上，它们通常在`onCreate`中初始化活动和`onCreateView`或`onViewCreated`中初始化 fragment，因为这些代表了视图创建和准备更新的时刻），一旦创建，它将与活动一样长久存在：

![图 10.1：活动的生命周期与 ViewModel 生命周期的比较](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_01.jpg)

图 10.1：活动的生命周期与 ViewModel 生命周期的比较

以下图表显示了`ViewModel`如何连接到一个 fragment：

![图 10.2：片段的生命周期与 ViewModel 生命周期的比较](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_02.jpg)

图 10.2：片段的生命周期与 ViewModel 生命周期的比较

## LiveData

`LiveData`是一个生命周期感知组件，允许更新 UI，但只有在 UI 处于活动状态时才会更新（例如，如果活动或片段处于`STARTED`或`RESUMED`状态）。要监视`LiveData`的更改，您需要一个与`LifecycleOwner`结合的观察者。当活动设置为活动状态时，观察者将在更改发生时收到通知。如果活动被重新创建，那么观察者将被销毁并重新附加。一旦发生这种情况，`LiveData`的最后一个值将被发出，以便我们恢复状态。活动和片段都是`LifecycleOwners`，但片段有一个单独的`LifecycleOwner`用于视图状态。片段有这个特殊的`LifecycleOwner`是因为它们在片段`BackStack`中的行为。当片段在返回堆栈中被替换时，它们并不完全被销毁；只有它们的视图被销毁。开发人员用来触发处理逻辑的一些常见回调是`onViewCreated()`、`onActivityResumed()`和`onCreateView()`。如果我们在这些方法中在`LiveData`上注册观察者，我们可能会遇到多个观察者在片段再次出现在屏幕上时被创建的情况。

在更新`LiveData`模型时，我们有两个选项：`setValue()`和`postValue()`。`setValue()`会立即传递结果，并且只应在 UI 线程上调用。另一方面，`postValue()`可以在任何线程上调用。当调用`postValue()`时，`LiveData`将安排在 UI 线程上更新值，并在 UI 线程空闲时更新值。

在`LiveData`类中，这些方法是受保护的，这意味着有子类允许我们更改数据。`MutableLiveData`使方法公开，这为我们提供了在大多数情况下观察数据的简单解决方案。`MediatorLiveData`是`LiveData`的专门实现，允许我们将多个`LiveData`对象合并为一个（这在我们的数据保存在不同存储库并且我们想要显示组合结果的情况下非常有用）。`TransformLiveData`是另一个专门的实现，允许我们将一个对象转换为另一个对象（这在我们从一个存储库中获取数据并且我们想要从另一个依赖于先前数据的存储库中请求数据的情况下有所帮助，以及在我们想要对存储库的结果应用额外逻辑的情况下有所帮助）。`Custom LiveData`允许我们创建自己的`LiveData`实现（通常在我们定期接收更新的情况下，比如体育博彩应用中的赔率、股市更新以及 Facebook 和 Twitter 的动态）。

注意

在`ViewModel`中使用`LiveData`是一种常见做法。在 fragment 或 activity 中持有`LiveData`会导致在配置更改发生时丢失数据。

以下图表显示了`LiveData`如何与`LifecycleOwner`的生命周期连接：

![图 10.3：LiveData 与生命周期之间的关系与 LifecycleOwners 的观察者](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_03.jpg)

图 10.3：LiveData 与生命周期所有者和生命周期观察者之间的关系

注意

我们可以在`LiveData`上注册多个观察者，并且每个观察者可以为不同的`LifecycleOwner`注册。在这种情况下，`LiveData`将变为非活动状态，但只有当所有观察者都处于非活动状态时。

## 练习 10.01：创建具有配置更改的布局

您的任务是构建一个应用程序，当在纵向模式下时，屏幕分为两个部分，纵向分割，当在横向模式下时，屏幕分为两个部分，横向分割。第一部分包含一些文本，下面是一个按钮。第二部分只包含文本。打开屏幕时，两个部分的文本都显示`Total: 0`。点击按钮后，文本将更改为`Total: 1`。再次点击后，文本将更改为`Total: 2`，依此类推。当设备旋转时，最后的总数将显示在新的方向上。

为了解决这个任务，我们将定义以下内容：

+   一个包含两个片段的活动-一个用于纵向，另一个用于横向。

+   一个包含`TextView`和一个按钮的布局的片段。

+   一个包含`TextView`的布局的片段。

+   一个将在两个片段之间共享的`ViewModel`。

+   一个将保存总数的`LiveData`。

让我们从设置我们的配置开始：

1.  创建一个名为`ViewModelLiveData`的新项目，并添加一个名为`SplitActivity`的空活动。

1.  在根`build.gradle`文件中，添加`google()`存储库：

```kt
allprojects {
    repositories {
        google()
        jcenter()
    }
}
```

这将允许 Gradle（构建系统）知道在哪里定位由 Google 开发的 Android Jetpack 库。

1.  让我们将`ViewModel`和`LiveData`库添加到`app/build.gradle`中：

```kt
dependencies {
    ... 
    def lifecycle_version = "2.2.0"
    implementation "androidx.lifecycle:lifecycle-      extensions:$lifecycle_version"
    ...
}
```

这将把`ViewModel`和`LiveData`代码都引入我们的项目。

1.  创建和定义`SplitFragmentOne`：

```kt
class SplitFragmentOne : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_split_one,           container, false)
    }
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        view.findViewById<TextView>          (R.id.fragment_split_one_text_view).text =             getString(R.string.total, 0)
    }
}
```

1.  将`fragment_split_`one`.xml`文件添加到`res/layout`文件夹中：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=  "http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:gravity="center"
    android:orientation="vertical">
    <TextView
        android:id="@+id/fragment_split_one_text_view"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
    <Button
        android:id="@+id/fragment_split_one_button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/press_me" />
</LinearLayout>
```

1.  现在，让我们创建并定义`SplitFragmentTwo`：

```kt
class SplitFragmentTwo : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_split_two,           container, false)
    }
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        view.findViewById<TextView>          (R.id.fragment_split_two_text_view).text =             getString(R.string.total, 0)
    }
}
```

1.  将`fragment_split_two.xml`文件添加到`res/layout`文件夹中：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android   ="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:gravity="center"
    android:orientation="vertical">
    <TextView
        android:id="@+id/fragment_split_two_text_view"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
</LinearLayout>
```

1.  定义`SplitActivity`：

```kt
class SplitActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_split)
    }
}
```

1.  在`res/layout`文件夹中创建`activity_split.xml`文件：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android   ="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    tools:context=".SplitActivity">
    <androidx.fragment.app.FragmentContainerView
        android:id="@+id/activity_fragment_split_1"
        android:name="com.android           .testable.viewmodellivedata.SplitFragmentOne"
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="1" />
    <androidx.fragment.app.FragmentContainerView
        android:id="@+id/activity_fragment_split_2"
        android:name="com.android           .testable.viewmodellivedata.SplitFragmentTwo"
        android:layout_width="match_parent"
        android:layout_height="0dp"
        android:layout_weight="1" />
</LinearLayout>
```

1.  接下来，让我们在`res`文件夹中创建一个`layout-land`文件夹。然后，在`layout-land`文件夹中，我们将创建一个名为`activity_split.xml`的文件，其中包含以下布局：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=  "http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:baselineAligned="false"
    android:orientation="horizontal"
    tools:context=".SplitActivity">
    <androidx.fragment.app.FragmentContainerView
        android:id="@+id/activity_fragment_split_1"
        android:id attribute in both activity_split.xml files. This allows the operating system to correctly save and restore the state of the fragment during rotation.NoteMake sure to properly point to your fragments with the right package declaration in the `android:name` attribute in the `FragmentContainerView` tag in both `activity_split.xml` files. Also, the `id` attribute is a must in the ` FragmentContainerView` tag, so make sure it's present; otherwise, the app will crash.
```

1.  以下字符串应添加到`res/strings.xml`中：

```kt
<string name="press_me">Press Me</string>
<string name="total">Total %d</string>
```

1.  确保`ActivitySplit`存在于`AndroidManifest.xml`文件中：

```kt
<activity android:name=".SplitActivity">
```

注意

如果这是您清单中唯一的活动，请确保添加启动器`intent-filter`标签，以便系统知道在安装应用程序时应打开哪个活动：

`<intent-filter> <action android:name="android.intent.action.MAIN" /> <category android:name="android.intent.category.LAUNCHER" /></intent-filter>`

现在，让我们运行这个项目。运行后，您可以旋转设备，看到屏幕根据规格定向。`Total`设置为 0，点击按钮不会有任何反应：

![图 10.4：练习 10.01 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_04.jpg)

图 10.4：练习 10.01 的输出

我们需要构建所需的逻辑，以便每次单击按钮时都添加 1。该逻辑也需要是可测试的。我们可以构建一个`ViewModel`并将其附加到每个片段。这将使逻辑可测试，并且还将解决生命周期的问题。

## 练习 10.02：添加 ViewModel

现在，我们需要实现将我们的`ViewModel`与按钮点击连接起来的逻辑，并确保该值在配置更改（如旋转）时保持不变。让我们开始吧：

1.  创建一个`TotalsViewModel`，如下所示：

```kt
class TotalsViewModel : ViewModel() {
    var total = 0
    fun increaseTotal(): Int {
        total++
        return total
    }
}
```

请注意，我们是从`ViewModel`类扩展的，这是生命周期库的一部分。在`ViewModel`类中，我们定义了一个增加总数并返回更新值的方法。

1.  现在，将`updateText`和`prepareViewModel`方法添加到`SplitFragment1`片段中：

```kt
class SplitFragmentOne : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_split_one,           container, false)
    }
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prepareViewModel()
    }

    private fun prepareViewModel() {
}
    private fun updateText(total: Int) {
 view?.findViewById<TextView>        (R.id.fragment_split_one_text_view)?.text =          getString(R.string.total, total)
    }
}
```

1.  在`prepareViewModel()`函数中，让我们开始添加我们的`ViewModel`：

```kt
private fun prepareViewModel() {
    val totalsViewModel       = ViewModelProvider(this).get(TotalsViewModel::class.java)
}
```

这是访问`ViewModel`实例的方式。`ViewModelProvider(this)`将使`TotalsViewModel`绑定到 fragment 的生命周期。`.get(TotalsViewModel::class.java)`将检索我们之前定义的`TotalsViewModel`的实例。如果 fragment 是第一次创建，它将产生一个新实例，而如果 fragment 在旋转后重新创建，它将提供先前创建的实例。我们将类作为参数传递的原因是因为一个 fragment 或 activity 可以有多个 ViewModels，而类作为我们想要的`ViewModel`类型的标识符。

1.  现在，在视图上设置最后已知的值：

```kt
private fun prepareViewModel() {
    val totalsViewModel       = ViewModelProvider(this).get(TotalsViewModel::class.java)
Total 0 every time we rotate, and after every click we will see the previously computed total plus 1.
```

1.  当点击按钮时更新视图：

```kt
private fun prepareViewModel() {
    val totalsViewModel       = ViewModelProvider(this).get(TotalsViewModel::class.java)
    updateText(totalsViewModel.total)
ViewModel to recompute the total and set the new value.
```

1.  现在，运行应用程序，按下按钮，旋转屏幕，看看会发生什么：

![图 10.5：练习 10.02 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_05.jpg)

图 10.5：练习 10.02 的输出

当您按下按钮时，您会看到总数增加，当您旋转显示时，值保持不变。如果您按下返回按钮并重新打开 activity，您会注意到总数被设置为 0。我们需要通知另一个 fragment 值已更改。我们可以通过使用接口并让 activity 知道来实现这一点，以便 activity 可以通知`SplitFragmentOne`。或者，我们可以将我们的`ViewModel`附加到 activity，这将允许我们在 fragments 之间共享它。

## 练习 10.03：在 fragments 之间共享我们的 ViewModel

我们需要在`SplitFragmentOne`中访问`TotalsViewModel`并将我们的`ViewModel`附加到 activity。让我们开始吧：

1.  将我们之前使用的相同`ViewModel`添加到`SplitFragmentTwo`中：

```kt
class SplitFragmentTwo : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_split_two,           container, false)
    }
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val totalsViewModel = ViewModelProvider(this)          .get(TotalsViewModel::class.java)
ViewModel, we actually have two instances of that ViewModel for each of our fragments. We will need to limit the number of instances to one per fragment. We can achieve this by attaching our ViewModel to the SplitActivity life cycle using a method called requireActiviy.
```

1.  让我们修改我们的 fragments。在两个 fragments 中，我们需要找到并更改以下代码：

```kt
val totalsViewModel =   ViewModelProvider(this).get(TotalsViewModel::class.java)
```

我们将其更改为以下内容：

```kt
val totalsViewModel =   ViewModelProvider(requireActivity())    .get(TotalsViewModel::class.java)
```

1.  现在，让我们运行应用程序：

![图 10.6：练习 10.03 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_06.jpg)

图 10.6：练习 10.03 的输出

同样，在这里，我们可以观察到一些有趣的东西。当点击按钮时，我们在第二个 fragment 中看不到任何变化，但我们确实看到了总数。这意味着 fragments 之间进行了通信，但不是实时的。我们可以通过`LiveData`来解决这个问题。通过在两个 fragments 中观察`LiveData`，我们可以在值发生变化时更新每个 fragment 的`TextView`类。

注意

使用 ViewModels 在 fragments 之间进行通信只有在 fragments 放置在同一个 activity 中时才有效。

## 练习 10.04：添加 LiveData

现在，我们需要确保我们的 fragments 实时地相互通信。我们可以使用`LiveData`来实现这一点。这样，每当一个 fragment 进行更改时，另一个 fragment 将收到关于更改的通知并进行必要的调整。

执行以下步骤来实现这一点：

1.  我们的`TotalsViewModel`应该被修改以支持`LiveData`：

```kt
class TotalsViewModel : ViewModel() {
    private val total = MutableLiveData<Int>()
    init {
        total.postValue(0)
    }
    fun increaseTotal() {
        total.postValue((total.value ?: 0) + 1)
    }
    fun getTotal(): LiveData<Int> {
        return total
    }
}
```

在这里，我们创建了一个`MutableLiveData`，它是`LiveData`的子类，允许我们更改数据的值。当创建`ViewModel`时，我们将`0`的默认值设置为`0`，然后当我们增加总数时，我们发布先前的值加 1。我们还创建了`getTotal()`方法，它返回一个可以从 fragment 中观察但不能修改的`LiveData`类。

1.  现在，我们需要修改我们的 fragments，使它们适应新的`ViewModel`。对于`SplitFragmentOne`，我们执行以下操作：

```kt
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val totalsViewModel =           ViewModelProvider(requireActivity())            .get(TotalsViewModel::class.java)
        totalsViewModel.getTotal().observe(viewLifecycleOwner,           Observer {
            updateText(it)
        })
        view.findViewById<Button>          (R.id.fragment_split_one_button).setOnClickListener {
            totalsViewModel.increaseTotal()
        }
    }
    private fun updateText(total: Int) {
        view?.findViewById<TextView>          (R.id.fragment_split_one_text_view)?.text             = getString(R.string.total, total)
    }
```

对于`SplitFragmentTwo`，我们执行以下操作：

```kt
    override fun onViewCreated(view: View, savedInstanceState:       Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val totalsViewModel =           ViewModelProvider(requireActivity())            .get(TotalsViewModel::class.java)
        totalsViewModel.getTotal().observe(viewLifecycleOwner,           Observer {
            updateText(it)
        })
    }
    private fun updateText(total: Int) {
       view?.findViewById<TextView>         (R.id.fragment_split_two_text_view)?.text =            getString(R.string.total, total)
    }
totalsViewModel.getTotal().observe(viewLifecycleOwner, Observer {  updateText(it)})
```

`observe`方法的`LifecycleOwner`参数称为`viewLifecycleOwner`。这是从`fragment`类继承的，当我们在观察数据时，它有助于在渲染 fragment 管理的视图时进行观察。在我们的示例中，将`viewLifecycleOwner`替换为`this`不会造成影响。但如果我们的 fragment 是后退堆栈功能的一部分，那么就会有创建多个观察者的风险，这将导致对相同数据集多次通知。

1.  现在，让我们为我们的新`ViewModel`编写一个测试。我们将其命名为`TotalsViewModelTest`，并将其放在`test`包中，而不是`androidTest`。这是因为我们希望这个测试在我们的工作站上执行，而不是在设备上：

```kt
class TotalsViewModelTest {
    private val totalsViewModel = TotalsViewModel()
    @Before
    fun setUp() {
        assertEquals(0, totalsViewModel.getTotal().value)
    }
    @Test
    fun increaseTotal() {
        val total = 5
        for (i in 0 until total) {
            totalsViewModel.increaseTotal()
        }
        assertEquals(4, totalsViewModel.getTotal().value)
    }
}
```

1.  在前面的测试中，在测试开始之前，我们断言`LiveData`的初始值设置为 0。然后，我们编写了一个小测试，其中我们将总数增加了五次，并断言最终值为`5`。让我们运行测试，看看会发生什么：

```kt
java.lang.RuntimeException: Method getMainLooper in   android.os.Looper not mocked.
```

1.  会出现类似于前面的消息。这是因为`LiveData`的实现方式。在内部，它使用处理程序和循环器，这是 Android 框架的一部分，因此阻止我们执行测试。幸运的是，有一个解决方法。我们需要在 Gradle 文件中为我们的测试添加以下配置：

```kt
testImplementation 'android.arch.core:core-testing:2.1.0'
```

1.  这将向我们的测试代码添加一个测试库，而不是我们的应用程序代码。现在，让我们在代码中添加以下行，位于`ViewModel`类的实例化之前：

```kt
class TotalsViewModelTest {
    @get:Rule
    val rule = InstantTaskExecutorRule()
    private val totalsViewModel = TotalsViewModel()
```

1.  我们在这里所做的是添加了一个`TestRule`，它表示每当`LiveData`的值发生变化时，它将立即进行更改，并避免使用 Android 框架组件。我们将在这个类中编写的每个测试都受到这个规则的影响，从而使我们有自由为每个新的测试方法使用`LiveData`类。如果我们再次运行测试，我们将看到以下内容：

```kt
java.lang.RuntimeException: Method getMainLooper
```

1.  这是否意味着我们的新规则没有起作用？并非完全如此。如果您查看`TotalsViewModels`类，您会看到这个：

```kt
init {
        total.postValue(0)
}
```

1.  这意味着因为我们在规则范围之外创建了`ViewModel`类，所以规则不适用。我们可以做两件事来避免这种情况：我们可以更改我们的代码以处理当我们首次订阅`LiveData`类时发送的空值，或者我们可以调整我们的测试，以便将`ViewModel`类放在规则的范围内。让我们采用第二种方法，并更改测试中创建`ViewModel`类的方式。它应该看起来像这样：

```kt
@get:Rule
val rule = InstantTaskExecutorRule()
private lateinit var totalsViewModel: TotalsViewModel
@Before
fun setUp() {
    totalsViewModel = TotalsViewModel()
    assertEquals(0, totalsViewModel.getTotal().value)
}
```

1.  让我们再次运行测试，看看会发生什么：

```kt
java.lang.AssertionError: 
Expected :4
Actual   :5
```

看看您能否找到测试中的错误，修复它，然后重新运行它：

![图 10.7：练习 10.04 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_07.jpg)

图 10.7：练习 10.04 的输出

横向模式下的相同输出如下所示：

![图 10.8：横向模式下练习 10.04 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_08.jpg)

图 10.8：横向模式下练习 10.04 的输出

通过查看前面的例子，我们可以看到使用`LiveData`和`ViewModel`方法的结合如何帮助我们解决了问题，同时考虑了 Android 操作系统的特殊性：

+   `ViewModel`帮助我们在设备方向更改时保持数据，并解决了在片段之间通信的问题。

+   `LiveData`帮助我们在考虑片段生命周期的同时检索我们处理过的最新信息。

+   这两者的结合帮助我们以高效的方式委托我们的处理逻辑，使我们能够对这个处理逻辑进行单元测试。

# Room

Room 持久性库充当您的应用程序代码和 SQLite 存储之间的包装器。您可以将 SQLite 视为一个在没有自己服务器的情况下运行的数据库，并将所有应用程序数据保存在一个只能由您的应用程序访问的内部文件中（如果设备未被 root）。Room 将位于应用程序代码和 SQLite Android 框架之间，并将处理必要的创建、读取、更新和删除（CRUD）操作，同时公开一个抽象，您的应用程序可以使用该抽象来定义数据以及您希望处理数据的方式。这种抽象以以下对象的形式出现：

+   **实体**：您可以指定数据存储方式以及数据之间的关系。

+   **数据访问对象**（**DAO**）：可以对数据执行的操作。

+   数据库：您可以指定数据库应具有的配置（数据库名称和迁移方案）。

这些可以在以下图表中看到：

![图 10.9：您的应用程序与 Room 组件之间的关系](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_09.jpg)

图 10.9：您的应用程序与 Room 组件之间的关系

在上图中，我们可以看到 Room 组件如何相互交互。通过一个例子更容易将其可视化。假设您想制作一个消息应用程序并将每条消息存储在本地存储中。在这种情况下，`Entity`将是一个包含 ID 的`Message`对象，它将包含消息的内容、发送者、时间、状态等。为了从本地存储中访问消息，您将需要一个`MessageDao`，其中将包含诸如`insertMessage()`、`getMessagesFromUser()`、`deleteMessage()`和`updateMessage()`等方法。由于这是一个消息应用程序，您将需要一个`Contact`实体来保存消息的发送者和接收者的信息。`Contact`实体将包含诸如姓名、最后在线时间、电话号码、电子邮件等信息。为了访问联系人信息，您将需要一个`ContactDao`接口，其中将包含`createUser()`、`updateUser()`、`deleteUser()`和`getAllUsers()`。两个实体将在 SQLite 中创建一个匹配的表，其中包含我们在实体类中定义的字段作为列。为了实现这一点，我们将不得不创建一个`MessagingDatabase`，在其中我们将引用这两个实体。

在没有 Room 或类似的 DAO 库的世界中，我们需要使用 Android 框架的 SQLite 组件。这通常涉及到设置数据库时的代码，比如创建表的查询，并为每个表应用类似的查询。每次我们查询表中的数据时，我们都需要将结果对象转换为 Java 或 Kotlin 对象。然后，对于我们更新或创建的每个对象，我们都需要进行相反方向的转换并调用适当的方法。Room 消除了所有这些样板代码，使我们能够专注于应用程序的需求。

默认情况下，Room 不允许在 UI 线程上执行任何操作，以强制执行与输入输出操作相关的 Android 标准。为了进行异步调用以访问数据，Room 与许多库和框架兼容，例如 Kotlin 协程、RxJava 和`LiveData`，在其默认定义之上。

## 实体

实体有两个目的：定义表的结构和保存表行的数据。让我们使用消息应用程序的场景，并定义两个实体：一个用于用户，一个用于消息。`User`实体将包含有关谁发送消息的信息，而`Message`实体将包含有关消息内容、发送时间以及消息发送者的引用的信息。以下代码片段提供了如何使用 Room 定义实体的示例：

```kt
@Entity(tableName = "messages")
data class Message(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "message_id")       val id: Long,
    @ColumnInfo(name = "text", defaultValue = "") val text: String,
    @ColumnInfo(name = "time") val time: Long,
    @ColumnInfo(name = "user") val userId: Long,
)
@Entity(tableName = "users")
data class User(
    @PrimaryKey @ColumnInfo(name = "user_id") val id: Long,
    @ColumnInfo(name = "first_name") val firstName: String,
    @ColumnInfo(name = "last_name") val lastName: String,
    @ColumnInfo(name = "last_online") val lastOnline: Long
)
```

正如您所看到的，实体只是带有注释的*数据类*，这些注释将告诉 Room 如何在 SQLite 中构建表。我们使用的注释如下：

+   `@Entity`注释定义了表。默认情况下，表名将是类的名称。我们可以通过`Entity`注释中的`tableName`方法更改表的名称。在我们希望我们的代码被混淆但希望保持 SQLite 结构的一致性的情况下，这是有用的。

+   `@ColumnInfo`定义了特定列的配置。最常见的是列的名称。我们还可以指定默认值、字段的 SQLite 类型以及字段是否应该被索引。

+   `@PrimaryKey`指示我们的实体中将使其唯一的内容。每个实体应该至少有一个主键。如果您的主键是整数或长整数，那么我们可以添加`autogenerate`字段。这意味着每个插入到`Primary Key`字段的实体都将由 SQLite 自动生成。通常，这是通过递增前一个 ID 来完成的。如果您希望将多个字段定义为主键，那么可以调整`@Entity`注释以适应此情况；例如以下内容：

```kt
@Entity(tableName = "messages", primaryKeys = ["id", "time"])
```

假设我们的消息应用程序想要发送位置。位置有纬度、经度和名称。我们可以将它们添加到`Message`类中，但这会增加类的复杂性。我们可以创建另一个实体并在我们的类中引用 ID。这种方法的问题是，我们每次查询`Message`实体时都会查询`Location`实体。Room 通过`@Embedded`注释提供了第三种方法。现在，让我们看看更新后的`Message`实体：

```kt
@Entity(tableName = "messages")
data class Message(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "message_id")       val id: Long,
    @ColumnInfo(name = "text", defaultValue = "") val text: String,
    @ColumnInfo(name = "time") val time: Long,
    @ColumnInfo(name = "user") val userId: Long,
    @Embedded val location: Location?
)
data class Location(
    @ColumnInfo(name = "lat") val lat: Double,
    @ColumnInfo(name = "long") val log: Double,
    @ColumnInfo(name = "location_name") val name: String
)
```

这段代码的作用是向消息表添加三列（`lat`、`long`和`location_name`）。这样可以避免对象具有大量字段，同时保持表的一致性。

如果我们查看我们的实体，我们会发现它们是相互独立的。`Message`实体有一个`userId`字段，但没有任何阻止我们从无效用户添加消息。这可能导致我们收集没有任何目的的数据。如果我们想要删除特定用户以及他们的消息，那么我们必须手动执行。Room 提供了一种通过`ForeignKey`定义这种关系的方法：

```kt
@Entity(
    tableName = "messages",
    foreignKeys = [ForeignKey(
        entity = User::class,
        parentColumns = ["user_id"],
        childColumns = ["user"],
onDelete = ForeignKey.CASCADE
    )]
)
data class Message(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "message_id")       val id: Long,
    @ColumnInfo(name = "text", defaultValue = "") val text: String,
    @ColumnInfo(name = "time") val time: Long,
    @ColumnInfo(name = "user") val userId: Long,
    @Embedded val location: Location?
)
```

在前面的例子中，我们添加了`foreignKeys`字段，并为`User`实体创建了一个新的`ForeignKey`，而对于父列，我们在`User`类中定义了`user_id`字段，对于子列，在`Message`类中定义了`user`字段。每次我们向表中添加消息时，`users`表中都需要有一个`User`条目。如果我们尝试删除一个用户，而仍然存在来自该用户的任何消息，那么默认情况下，这将不起作用，因为存在依赖关系。但是，我们可以告诉 Room 执行级联删除，这将删除用户和相关的消息。

## DAO

如果实体指定了我们如何定义和保存我们的数据，那么 DAOs 指定了对该数据的操作。DAO 类是我们定义 CRUD 操作的地方。理想情况下，每个实体应该有一个对应的 DAO，但也有一些情况发生了交叉（通常是在我们需要处理两个表之间的 JOIN 时发生）。

继续我们之前的例子，让我们为我们的实体构建一些相应的 DAOs。

```kt
@Dao
interface MessageDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertMessages(vararg messages: Message)
    @Update
    fun updateMessages(vararg messages: Message)
    @Delete
    fun deleteMessages(vararg messages: Message)
    @Query("SELECT * FROM messages")
    fun loadAllMessages(): List<Message>
    @Query("SELECT * FROM messages WHERE user=:userId AND       time>=:time")
    fun loadMessagesFromUserAfterTime(userId: String, time: Long):       List<Message>
}
@Dao
interface UserDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertUser(user: User)
    @Update
    fun updateUser(user: User)
    @Delete
    fun deleteUser(user: User)
    @Query("SELECT * FROM users")
    fun loadAllUsers(): List<User>
}
```

对于我们的消息，我们已经定义了以下函数：插入一个或多个消息，更新一个或多个消息，删除一个或多个消息，以及检索某个用户在特定时间之前的所有消息。对于我们的用户，我们可以插入一个用户，更新一个用户，删除一个用户，并检索所有用户。

如果查看我们的`Insert`方法，您会看到我们已经定义了在冲突的情况下（当我们尝试插入已经存在的 ID 的内容时），它将替换现有条目。`Update`字段具有类似的配置，但在我们的情况下，我们选择了默认值。这意味着如果更新无法发生，将不会发生任何事情。

`@Query`注释与其他所有注释不同。这是我们使用 SQLite 代码定义读取操作的地方。`SELECT *`表示我们要读取表中每一行的所有数据，这将填充所有我们实体的字段。`WHERE`子句表示我们要应用于查询的限制。我们也可以定义一个方法如下：

```kt
@Query("SELECT * FROM messages WHERE user IN (:userIds) AND   time>=:time")
fun loadMessagesFromUserAfterTime(userIds: List<String>, time: Long):   List<Message>
```

这使我们可以过滤来自多个用户的消息。

我们可以定义一个新类如下：

```kt
data class TextWithTime(
    @ColumnInfo(name = "text") val text: String,
    @ColumnInfo(name = "time") val time: Long
)
```

现在，我们可以定义以下查询：

```kt
@Query("SELECT text,time FROM messages")
fun loadTextsAndTimes(): List<TextWithTime>
```

这将允许我们一次从某些列中提取信息，而不是整行。

现在，假设你想要将发送者的用户信息添加到每条消息中。在这里，我们需要使用与之前相似的方法：

```kt
data class MessageWithUser(
    @Embedded val message: Message,
    @Embedded val user: User
)
```

通过使用新的数据类，我们可以定义这个查询：

```kt
@Query("SELECT * FROM messages INNER JOIN users on   users.user_id=messages.user")
fun loadMessagesAndUsers(): List<MessageWithUser>
```

现在，我们为要显示的每条消息都有了用户信息。这在诸如群聊之类的场景中会很有用，我们应该显示每条消息的发送者姓名。

## 设置数据库

到目前为止，我们有一堆 DAO 和实体。现在是将它们放在一起的时候了。首先，让我们定义我们的数据库：

```kt
@Database(entities = [User::class, Message::class], version = 1)
abstract class ChatDatabase : RoomDatabase() {
    companion object {
        private lateinit var chatDatabase: ChatDatabase
        fun getDatabase(applicationContext: Context): ChatDatabase {
            if (!(::chatDatabase.isInitialized)) {
                chatDatabase =
                    Room.databaseBuilder(applicationContext,                       chatDatabase::class.java, "chat-db")
                        .build()
            }
            return chatDatabase
        }
    }
    abstract fun userDao(): UserDao
    abstract fun messageDao(): MessageDao
}
```

在`@Database`注解中，我们指定了哪些实体放入我们的数据库，还指定了我们的版本。然后，对于每个 DAO，我们在`RoomDatabase`中定义了一个抽象方法。这允许构建系统构建我们类的子类，在其中为这些方法提供实现。构建系统还将创建与我们实体相关的表。

伴生对象中的`getDatabase`方法用于说明我们如何创建`ChatDatabase`类的实例。理想情况下，由于构建新数据库对象涉及的复杂性，我们的应用程序应该只有一个数据库实例。这可以通过依赖注入框架更好地实现。

假设你已经发布了你的聊天应用程序。你的数据库当前是版本 1，但你的用户抱怨说消息状态功能缺失。你决定在下一个版本中添加这个功能。这涉及改变数据库的结构，可能会影响已经构建其结构的数据库。幸运的是，Room 提供了一种叫做迁移的东西。在迁移中，我们可以定义我们的数据库在版本 1 和 2 之间的变化。所以，让我们看看我们的例子：

```kt
data class Message(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "message_id")       val id: Long,
    @ColumnInfo(name = "text", defaultValue = "") val text: String,
    @ColumnInfo(name = "time") val time: Long,
    @ColumnInfo(name = "user") val userId: Long,
    @ColumnInfo(name = "status") val status: Int,
    @Embedded val location: Location?
)
```

在这里，我们向`Message`实体添加了状态标志。

现在，让我们看看我们的`ChatDatabase`：

```kt
Database(entities = [User::class, Message::class], version = 2)
abstract class ChatDatabase : RoomDatabase() {
    companion object {
        private lateinit var chatDatabase: ChatDatabase
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(database: SupportSQLiteDatabase) {
                database.execSQL("ALTER TABLE messages ADD COLUMN                   status INTEGER")
            }
        }
        fun getDatabase(applicationContext: Context): ChatDatabase {
            if (!(::chatDatabase.isInitialized)) {
                chatDatabase =
                    Room.databaseBuilder(applicationContext,                       chatDatabase::class.java, "chat-db")
                        .addMigrations(MIGRATION_1_2)
                        .build()
            }
            return chatDatabase
        }
    }
    abstract fun userDao(): UserDao
    abstract fun messageDao(): MessageDao
}
```

在我们的数据库中，我们将版本增加到 2，并在版本 1 和 2 之间添加了迁移。在这里，我们向表中添加了状态列。当我们构建数据库时，我们将添加此迁移。一旦我们发布了新代码，当打开更新后的应用程序并执行构建数据库的代码时，它将比较存储数据上的版本与我们类中指定的版本，并注意到差异。然后，它将执行我们指定的迁移，直到达到最新版本。这使我们能够在多年内维护应用程序，而不影响用户的体验。

如果你看我们的`Message`类，你可能已经注意到我们将时间定义为 Long。在 Java 和 Kotlin 中，我们有`Date`对象，这可能比消息的时间戳更有用。幸运的是，Room 在 TypeConverters 中有解决方案。以下表格显示了我们可以在我们的代码中使用的数据类型和 SQLite 等效。需要使用 TypeConverters 将复杂数据类型降至这些级别：

![图 10.10：Kotlin/Java 数据类型与 SQLite 数据类型之间的关系](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_10.jpg)

图 10.10：Kotlin/Java 数据类型与 SQLite 数据类型之间的关系

在这里，我们修改了`lastOnline`字段，使其为`Date`类型：

```kt
data class User(
    @PrimaryKey @ColumnInfo(name = "user_id") val id: Long,
    @ColumnInfo(name = "first_name") val firstName: String,
    @ColumnInfo(name = "last_name") val lastName: String,
    @ColumnInfo(name = "last_online") val lastOnline: Date
)
```

在这里，我们定义了一对方法，将`Date`对象转换为`Long`，反之亦然。`@TypeConverter`注解帮助 Room 识别转换发生的位置：

```kt
class DateConverter {
    @TypeConverter
    fun from(value: Long?): Date? {
        return value?.let { Date(it) }
    }
    @TypeConverter
    fun to(date: Date?): Long? {
        return date?.time
    }
}
```

最后，我们将通过`@TypeConverters`注解将我们的转换器添加到 Room 中：

```kt
@Database(entities = [User::class, Message::class], version = 2)
@TypeConverters(DateConverter::class)
abstract class ChatDatabase : RoomDatabase() {
```

在下一节中，我们将看一些第三方框架。

## 第三方框架

Room 与 LiveData、RxJava 和协程等第三方框架很好地配合。这解决了多线程和观察数据变化的两个问题。

`LiveData`将使 DAO 中的`@Query`注解方法具有反应性，这意味着如果添加了新数据，`LiveData`将通知观察者：

```kt
    @Query("SELECT * FROM users")
    fun loadAllUsers(): LiveData<List<User>>
```

Kotlin 协程通过使`@Insert`、`@Delete`和`@Update`方法异步化来补充`LiveData`：

```kt
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUser(user: User)
    @Update
    suspend fun updateUser(user: User)
    @Delete
    suspend fun deleteUser(user: User)
```

`@Query`方法通过`Publisher`、`Observable`或`Flowable`等组件变得响应式，并通过`Completable`、`Single`或`Maybe`等使其余的方法异步化：

```kt
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertUser(user: User) : Completable
    @Update
    fun updateUser(user: User) : Completable
    @Delete
    fun deleteUser(user: User) : Completable
    @Query("SELECT * FROM users")
    fun loadAllUsers(): Flowable<List<User>>
```

**执行器和线程**是 Java 框架自带的，如果你的项目中没有前面提到的第三方集成，它们可以是解决 Room 中线程问题的有用解决方案。你的 DAO 类不会受到任何修改的影响；然而，你需要访问 DAO 的组件来调整并使用执行器或线程：

```kt
    @Query("SELECT * FROM users")
    fun loadAllUsers(): List<User>
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertUser(user: User)
    @Update
    fun updateUser(user: User)
    @Delete
    fun deleteUser(user: User)
```

访问 DAO 的一个例子如下：

```kt
    fun getUsers(usersCallback:()->List<User>){
        Thread(Runnable {
           usersCallback.invoke(userDao.loadUsers())
        }).start()
     }
```

上面的例子将创建一个新的线程，并在每次我们想要检索用户列表时启动它。这段代码有两个主要问题：

+   线程创建是一个昂贵的操作

+   这段代码很难测试

第一个问题的解决方案可以通过`ThreadPools`和`Executors`来解决。Java 框架在`ThreadPools`方面提供了强大的选项。线程池是一个负责线程创建和销毁的组件，并允许开发人员指定池中的线程数量。线程池中的多个线程将确保可以同时执行多个任务。

我们可以将上面的代码重写如下：

```kt
    private val executor:Executor =       Executors.newSingleThreadExecutor()
    fun getUsers(usersCallback:(List<User>)->Unit){
        executor.execute {
            usersCallback.invoke(userDao.loadUsers())
        }
    }
```

在上面的例子中，我们定义了一个使用 1 个线程池的执行器。当我们想要访问用户列表时，我们将查询放在执行器内部，当数据加载时，我们的回调 lambda 将被调用。

## 练习 10.05：做一个小小的 Room

你被一家新闻机构聘用来构建一个新闻应用程序。该应用程序将显示由记者撰写的文章列表。一篇文章可以由一个或多个记者撰写，每个记者可以撰写一篇或多篇文章。每篇文章的数据信息包括文章的标题、内容和日期。记者的信息包括他们的名字、姓氏和职称。你需要构建一个 Room 数据库来保存这些信息以便进行测试。

在我们开始之前，让我们看一下实体之间的关系。在聊天应用程序的例子中，我们定义了一个用户可以发送一个或多个消息的规则。这种关系被称为一对多关系。这种关系被实现为一个实体对另一个实体的引用（用户在消息表中被定义，以便与发送者连接）。在这种情况下，我们有一个多对多的关系。为了实现多对多的关系，我们需要创建一个实体，它持有将连接另外两个实体的引用。让我们开始吧：

1.  让我们首先在`app/build.gradle`中添加注解处理插件。这将读取 Room 使用的注解，并生成与数据库交互所需的代码：

```kt
    apply plugin: 'kotlin-kapt' 
```

1.  接下来，让我们在`app/build.gradle`中添加 Room 库：

```kt
def room_version = "2.2.5"
implementation "androidx.room:room-runtime:$room_version"
kapt "androidx.room:room-compiler:$room_version"
```

第一行定义了库版本，第二行引入了 Java 和 Kotlin 的 Room 库，最后一行是 Kotlin 注解处理器。这允许构建系统从 Room 注解中生成样板代码。

1.  让我们定义我们的实体：

```kt
@Entity(tableName = "article")
data class Article(
    @PrimaryKey(autoGenerate = true)       @ColumnInfo(name = "id") val id: Long = 0,
    @ColumnInfo(name = "title") val title: String,
    @ColumnInfo(name = "content") val content: String,
    @ColumnInfo(name = "time") val time: Long
)
@Entity(tableName = "journalist")
data class Journalist(
    @PrimaryKey(autoGenerate = true)       @ColumnInfo(name = "id") val id: Long = 0,
    @ColumnInfo(name = "first_name") val firstName: String,
    @ColumnInfo(name = "last_name") val lastName: String,
    @ColumnInfo(name = "job_title") val jobTitle: String
)
```

1.  现在，定义连接记者和文章以及适当的约束的实体：

```kt
@Entity(
    tableName = "joined_article_journalist",
    primaryKeys = ["article_id", "journalist_id"],
    foreignKeys = [ForeignKey(
        entity = Article::class,
        parentColumns = arrayOf("id"),
        childColumns = arrayOf("article_id"),
        onDelete = ForeignKey.CASCADE
    ), ForeignKey(
        entity = Journalist::class,
        parentColumns = arrayOf("id"),
        childColumns = arrayOf("journalist_id"),
        onDelete = ForeignKey.CASCADE
    )]
)
data class JoinedArticleJournalist(
    @ColumnInfo(name = "article_id") val articleId: Long,
    @ColumnInfo(name = "journalist_id") val journalistId: Long
)
```

在上面的代码中，我们定义了我们的连接实体。正如你所看到的，我们没有为唯一性定义 ID，但是当文章和记者一起使用时，它们将是唯一的。我们还为我们的实体引用的每个其他实体定义了外键。

1.  创建`ArticleDao` DAO：

```kt
@Dao
interface ArticleDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertArticle(article: Article)
    @Update
    fun updateArticle(article: Article)
    @Delete
    fun deleteArticle(article: Article)
    @Query("SELECT * FROM article")
    fun loadAllArticles(): List<Article>
    @Query("SELECT * FROM article INNER JOIN       joined_article_journalist ON         article.id=joined_article_journalist.article_id WHERE           joined_article_journalist.journalist_id=:journalistId")
    fun loadArticlesForAuthor(journalistId: Long): List<Article>
}
```

1.  现在，创建`JournalistDao`数据访问对象：

```kt
@Dao
interface JournalistDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertJournalist(journalist: Journalist)
    @Update
    fun updateJournalist(journalist: Journalist)
    @Delete
    fun deleteJournalist(journalist: Journalist)
    @Query("SELECT * FROM journalist")
    fun loadAllJournalists(): List<Journalist>
    @Query("SELECT * FROM journalist INNER JOIN       joined_article_journalist ON         journalist.id=joined_article_journalist.journalist_id           WHERE joined_article_journalist.article_id=:articleId")
    fun getAuthorsForArticle(articleId: Long): List<Journalist>
}
```

1.  创建`JoinedArticleJournalistDao` DAO：

```kt
@Dao
interface JoinedArticleJournalistDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertArticleJournalist(joinedArticleJournalist:       JoinedArticleJournalist)
    @Delete
    fun deleteArticleJournalist(joinedArticleJournalist:       JoinedArticleJournalist)
}
```

让我们稍微分析一下我们的代码。对于文章和记者，我们有添加、插入、删除和更新查询的能力。对于文章，我们有提取所有文章的能力，还可以从特定作者提取文章。我们还有选项来提取写过文章的所有记者。这是通过与我们的中间实体进行 JOIN 来完成的。对于该实体，我们定义了插入选项（将文章链接到记者）和删除选项（将删除该链接）。

1.  最后，让我们定义我们的`Database`类：

```kt
@Database(
    entities = [Article::class, Journalist::class,       JoinedArticleJournalist::class],
    version = 1
)
abstract class NewsDatabase : RoomDatabase() {
    abstract fun articleDao(): ArticleDao
    abstract fun journalistDao(): JournalistDao
    abstract fun joinedArticleJournalistDao():       JoinedArticleJournalistDao
}
```

我们避免在这里定义`getInstance`方法，因为我们不会在任何地方调用数据库。但如果我们不这样做，我们怎么知道它是否有效？答案是我们将测试它。这不会是在您的计算机上运行的测试，而是在设备上运行的测试。这意味着我们将在`androidTest`文件夹中创建它。

1.  让我们从设置测试数据开始。在这里，我们将向数据库中添加一些文章和记者：

```kt
NewsDatabaseTest.kt
15@RunWith(AndroidJUnit4::class)
16class NewsDatabaseTest {
17
18    private lateinit var db: NewsDatabase
19    private lateinit var articleDao: ArticleDao
20    private lateinit var journalistDao: JournalistDao
21    private lateinit var joinedArticleJournalistDao:         JoinedArticleJournalistDao
22
23     @Before
24     fun setUp() {
25        val context =             ApplicationProvider.getApplicationContext<Context>()
26        db = Room.inMemoryDatabaseBuilder(context,             NewsDatabase::class.java).build()
27        articleDao = db.articleDao()
28        journalistDao = db.journalistDao()
29        joinedArticleJournalistDao =             db.joinedArticleJournalistDao()
30        initData()
31    }
The complete code for this step can be found at http://packt.live/3oWok6a.
```

1.  让我们测试数据是否已更新：

```kt
    @Test
    fun updateArticle() {
        val article = articleDao.loadAllArticles()[0]
        articleDao.updateArticle(article.copy(title =           "new title"))
        assertEquals("new title",           articleDao.loadAllArticles()[0].title)
    }
    @Test
    fun updateJournalist() {
        val journalist = journalistDao.loadAllJournalists()[0]
        journalistDao.updateJournalist(journalist.copy(jobTitle           = "new job title"))
        assertEquals("new job title",           journalistDao.loadAllJournalists()[0].jobTitle)
    }
```

1.  接下来，让我们测试清除数据：

```kt
    @Test
    fun deleteArticle() {
        val article = articleDao.loadAllArticles()[0]
        assertEquals(2,           journalistDao.getAuthorsForArticle(article.id).size)
        articleDao.deleteArticle(article)
        assertEquals(4, articleDao.loadAllArticles().size)
        assertEquals(0,           journalistDao.getAuthorsForArticle(article.id).size)
    }
```

在这里，我们定义了一些测试 Room 数据库的示例。有趣的是我们如何构建数据库。我们的数据库是一个内存数据库。这意味着只要测试运行，所有数据都将被保留，并在之后被丢弃。这使我们可以为每个新状态从零开始，并避免每个测试会话的后果相互影响。在我们的测试中，我们设置了五篇文章和十位记者。第一篇文章是由前两位记者写的，而第二篇文章是由第一位记者写的。其余的文章没有作者。通过这样做，我们可以测试我们的更新和删除方法。对于删除方法，我们还可以测试我们的外键关系。在测试中，我们可以看到，如果我们删除文章 1，它将删除文章和写作它的记者之间的关系。在测试数据库时，您应该添加您的应用程序将使用的场景。请随意添加其他测试场景，并改进您自己数据库中的先前测试。

# 自定义生命周期

之前，我们讨论了`LiveData`以及如何通过`LifecycleOwner`观察它。我们可以使用 LifecycleOwners 订阅`LifecycleObserver`，以便它将监视所有者状态的变化。这在您希望在调用特定生命周期回调时触发某些函数的情况下非常有用；例如，从您的活动/片段请求位置、启动/停止视频以及监视连接更改。我们可以通过使用`LifecycleObserver`来实现这一点。

```kt
class ToastyLifecycleObserver(val onStarted: () -> Unit) :   LifecycleObserver {
    @OnLifecycleEvent(Lifecycle.Event.ON_START)
    fun onStarted() {
        onStarted.invoke()
    }
}
```

在上述代码中，我们定义了一个实现`LifecycleObserver`接口的类，并定义了一个在生命周期进入`ON_START`事件时将被调用的方法。`@OnLifecycleEvent`注解将被构建系统用于生成调用它所用于的注解的样板代码。

接下来，我们需要在活动/片段中注册我们的观察者：

```kt
    lifecycle.addObserver(ToastyLifecycleObserver {
        Toast.makeText(this, "Started", Toast.LENGTH_LONG).show()
})
```

在上述代码中，我们在`Lifecycle`对象上注册了观察者。`Lifecycle`对象是通过`getLifecycle()`方法从父活动类继承的。

注意

`LiveData`是这一原则的专门用途。在`LiveData`场景中，您可以有多个 LifecycleOwners 订阅单个`LiveData`。在这里，您可以为相同的`LifecycleOwner`订阅新的所有者。

## 练习 10.06：重新发明轮子

在这个练习中，我们将实现一个自定义的`LifecycleOwner`，当活动启动时，它将触发`ToastyLifecycleObserver`中的`Lifecycle.Event.ON_START`事件。让我们开始创建一个名为 SplitActivity 的空活动的新 Android Studio 项目：

1.  让我们从将观察者添加到我们的活动开始：

```kt
class SplitActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycle.addObserver(ToastyLifecycleObserver {
            Toast.makeText(this, "Started",               Toast.LENGTH_LONG).show()
        })
    }
}
```

如果您运行代码并打开活动，旋转设备，将应用程序置于后台，然后恢复应用程序，您将看到`Started`提示。

1.  现在，定义一个新的活动，将重新发明轮子并使其变得更糟：

```kt
class LifecycleActivity : Activity(), LifecycleOwner {
    private val lifecycleRegistry: LifecycleRegistry =       LifecycleRegistry(this)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleRegistry.currentState = Lifecycle.State.CREATED
        lifecycleRegistry.addObserver(ToastyLifecycleObserver {
            Toast.makeText(applicationContext, "Started",               Toast.LENGTH_LONG).show()
        })
    }
    override fun getLifecycle(): Lifecycle {
        return lifecycleRegistry
    }

    override fun onStop() {
super.onStop()
        lifecycleRegistry.currentState = Lifecycle.State.STARTED
    }
}
```

1.  在`AndroidManifest.xml`文件中，您可以用 LifecycleActivity 替换 SplitActivity，效果会是这样的

```kt
        <activity android:name=".LifecycleActivity" >
            <intent-filter>
                <action android:name="android.intent.action.MAIN"                   />
                <category android:name=                  "android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
```

如果我们运行上述代码，我们将看到每次启动活动时都会出现一个提示。

![图 10.11：练习 10.06 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_11.jpg)

图 10.11：练习 10.06 的输出

请注意，这是在不覆盖`Activity`类的`onStart()`方法的情况下触发的。您可以进一步尝试使用`LifecycleObserver`类来触发`Activity`类的其他状态中的提示。

现在，让我们分析一下我们新活动的代码。请注意，我们扩展了活动而不是`AppCompatActivity`类。这是因为`AppCompatActivity`类已经包含了`LifecycleRegistry`逻辑。在我们的新活动中，我们定义了一个`LifecycleRegistry`，它将负责添加我们的观察者和改变状态。然后，我们实现了`LifecycleOwner`接口，并在`getLifecycle()`方法中返回`LifecycleRegistry`。然后，对于我们的每个回调，我们可以改变注册表的状态。在`onCreate()`方法中，我们将注册表设置为`CREATED`状态（这将触发`LifecycleObservers`上的`ON_CREATE`事件），然后我们注册了我们的`LifecycleObserver`。为了实现我们的任务，我们在`onStop()`方法中发送了`STARTED`事件。如果我们运行上述示例并最小化我们的活动，我们应该会看到我们的`Started`提示。

## 活动 10.01：购物笔记应用

您想跟踪您的购物物品，因此决定构建一个应用程序，您可以在其中保存您希望在下次去商店时购买的物品。此需求如下：

+   UI 将分为两部分：纵向模式为上/下，横向模式为左/右。UI 将类似于以下截图所示。

+   第一半将显示笔记的数量、文本字段和按钮。每次按下按钮时，将使用放置在文本字段中的文本添加一个笔记。

+   第二半将显示笔记列表。

+   对于每一半，您将拥有一个将保存相关数据的视图模型。

+   您应该定义一个存储库，它将在 Room 数据库之上使用以访问您的数据。

+   您还应该定义一个 Room 数据库，用于保存您的笔记。

+   笔记实体将具有以下属性：id、text：

![图 10.12：活动 10.01 可能的输出示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_10_12.jpg)

图 10.12：活动 10.01 可能的输出示例

执行以下步骤以完成此活动：

1.  通过创建`Entity`、`Dao`和`Database`方法开始 Room 集成。对于`Dao`，`@Query`注释的方法可以直接返回`LiveData`对象，以便如果数据发生更改，观察者可以直接收到通知。

1.  以接口形式定义我们的存储库的模板。

1.  实现存储库。存储库将有一个对我们之前定义的`Dao`对象的引用。插入数据的代码需要移动到一个单独的线程。创建`NotesApplication`类以提供将在整个应用程序中使用的存储库的一个实例。确保更新`AndroidManifest.xml`文件中的`<application>`标签，以添加您的新应用程序类。

1.  对存储库进行单元测试并定义`ViewModels`，如下所示：

+   定义`NoteListViewModel`和相关测试。这将引用存储库并返回笔记列表。

+   定义`CountNotesViewModel`和相关测试。`CountViewModel`将引用存储库并返回`LiveData`的笔记总数。它还将负责插入新的笔记。

+   定义`CountNotesFragment`及其关联的`fragment_count_notes.xml`布局。在布局中，定义一个将显示总数的`TextView`，一个用于新笔记名称的`EditText`，以及一个将插入`EditText`中引入的笔记的按钮。

+   为笔记列表定义一个适配器，名为`NoteListAdapter`，并为行定义一个关联的布局文件，名为`view_note_item.xml`。

+   定义关联的布局文件，名为`fragment_note_list.xml`，其中将包含一个`RecyclerView`。该布局将被`NoteListFragment`使用，它将连接`NoteListAdapter`到`RecyclerView`。它还将观察来自`NoteListViewModel`的数据并更新适配器。

+   为横向模式和纵向模式定义`NotesActivity`及其关联的布局。

1.  确保你在`strings.xml`中有所有必要的数据。

注意

此活动的解决方案可以在以下网址找到：http://packt.live/3sKj1cp

# 总结

在本章中，我们分析了构建可维护应用程序所需的基本组件。我们还研究了在使用 Android 框架时开发人员经常遇到的最常见问题之一，即在生命周期更改期间维护对象的状态。

我们首先分析了`ViewModels`以及它们如何解决在方向更改期间保存数据的问题。我们将`LiveData`添加到`ViewModels`中，以展示它们如何互补。

然后，我们转向 Room，展示了如何在不需要大量 SQLite 样板代码的情况下轻松持久化数据。我们还探讨了一对多和多对多关系，以及如何迁移数据并将复杂对象分解为存储的基本类型。

之后，我们重新发明了`Lifecycle`轮，以展示`LifecycleOwners`和`LifecycleObservers`如何交互。

我们还建立了我们的第一个存储库，在接下来的章节中，当其他数据源被添加到其中时，我们将对其进行扩展。

本章完成的活动作为 Android 应用程序发展方向的一个示例。然而，由于您将发现许多框架和库，这并不是一个完整的示例，这些框架和库将为开发人员提供灵活性，使他们能够朝不同的方向发展。

在本章中学到的信息将为下一章服务，下一章将扩展存储库的概念。这将允许您将从服务器获取的数据保存到 Room 数据库中。持久化数据的概念也将得到扩展，您将探索通过`SharedPreferences`和文件等其他持久化数据的方式。我们将重点放在某些类型的文件上：从设备相机获取的媒体文件。


# 第十一章：持久化数据

概述

本章将深入探讨 Android 中的数据持久性，以及探索存储库模式。在本章结束时，您将能够构建一个可以连接到多个数据源的存储库，然后使用该存储库从 API 下载文件并将其保存在设备上。您将了解直接在设备上存储（持久化）数据的多种方法以及可用于执行此操作的框架。在处理文件系统时，您将学习其如何分区以及如何在不同位置和使用不同框架中读取和写入文件。

# 介绍

在上一章中，您学习了如何构建代码结构以及如何保存数据。在活动中，您还有机会构建一个存储库，并使用它来访问数据并通过 Room 保存数据。您可能会问：为什么需要这个存储库？本章将试图回答这个问题。通过存储库模式，您将能够以集中的方式从服务器检索数据并将其存储在本地。该模式在需要在多个地方使用相同数据的情况下非常有用，从而避免代码重复，同时还保持 ViewModel 清除任何不必要的额外逻辑。

如果您查看设备上的设置应用程序或许多应用程序的设置功能，您将看到一些相似之处。一系列带有可以打开或关闭的切换的项目。这是通过`SharedPreferences`和`PreferenceFragments`实现的。`SharedPreferences`是一种允许您以键值对的方式将值存储在文件中的方法。它具有专门的读写机制，从而消除了关于线程的担忧。它对小量数据非常有用，并消除了对诸如 Room 之类的东西的需求。

在本章中，您还将了解 Android 文件系统以及其如何结构化为外部和内部存储器。您还将加深对读取和写入权限的理解，以及如何创建`FileProvider`类以便其他应用程序访问您的文件，以及如何在外部驱动器上保存这些文件而无需请求权限。您还将了解如何从互联网下载文件并将其保存在文件系统中。

本章还将探讨的另一个概念是使用*相机*应用程序代表您的应用程序拍摄照片和视频，并使用 FileProviders 将它们保存到外部存储。

# 存储库

存储库是一种模式，它帮助开发人员将数据源的代码与活动和 ViewModel 分开。它提供对数据的集中访问，然后可以进行单元测试：

![图 11.1：存储库架构图](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_01.jpg)

图 11.1：存储库架构图

在上图中，您可以看到存储库在应用程序代码中的核心作用。其职责包括：

+   保留活动或应用程序所需的所有数据源（SQLite、网络、文件系统）

+   将来自多个源的数据组合和转换为活动级别所需的单一输出

+   将数据从一个数据源传输到另一个数据源（将网络调用的结果保存到 Room 中）

+   刷新过期数据（如果需要）

Room、网络层和`FileManager`代表存储库可以拥有的不同类型的数据源。Room 可用于保存来自网络的大量数据，而文件系统可用于存储小量（`SharedPreferences`）或整个文件。

`ViewModel`将引用您的存储库并将结果传递给活动，活动将显示结果。

注意

存储库应该根据域进行组织，这意味着您的应用程序应该针对不同的域具有不同的存储库，而不是一个巨大的存储库。

## 练习 11.01：创建存储库

在这个练习中，我们将在 Android Studio 中创建一个应用程序，该应用程序使用 Retrofit 连接到位于[`jsonplaceholder.typicode.com/posts`](https://jsonplaceholder.typicode.com/posts)的 API，并检索一系列帖子，然后使用 Room 保存。UI 将在`RecyclerView`中显示每个帖子的标题和正文。我们将使用`ViewModel`实现存储库模式。

为了完成这个练习，我们需要构建以下内容：

+   负责下载和解析 JSON 文件的网络组件

+   负责使用一个实体存储数据的 Room 数据库

+   管理先前构建的组件之间的数据的存储库

+   访问存储库的`ViewModel`

+   显示数据的带有`RecyclerView`模型的活动

执行以下步骤以完成此练习：

1.  让我们从`app/build.gradle`文件夹开始添加。

```kt
    implementation "androidx.constraintlayout       :constraintlayout:2.0.4"
    implementation 'androidx.recyclerview:recyclerview:1.1.0'
    def lifecycle_version = "2.2.0"
    implementation "androidx.lifecycle:lifecycle-extensions       :$lifecycle_version"
    def room_version = "2.2.5"
      implementation "androidx.room:room-runtime:$room_version"
    kapt "androidx.room:room-compiler:$room_version"
    implementation 'com.squareup.retrofit2:retrofit:2.6.2'
    implementation 'com.squareup.retrofit2:converter-gson:2.6.2'
    implementation 'com.google.code.gson:gson:2.8.6'
    testImplementation 'junit:junit:4.12'
    testImplementation 'android.arch.core:core-testing:2.1.0'
    testImplementation 'org.mockito:mockito-core:2.23.0'
    androidTestImplementation 'androidx.test.ext:junit:1.1.2'
    androidTestImplementation 'androidx.test.espresso:espresso-      core:3.3.0
```

1.  我们将需要对处理 API 通信的类进行分组。我们将通过创建一个包含所需网络类的`api`包来实现这一点。

1.  接下来，我们定义一个`Post`类，它将映射 JSON 文件中的数据。在我们的新模型中，将定义 JSON 文件中表示帖子的每个字段：

```kt
data class Post(
    @SerializedName("id") val id: Long,
    @SerializedName("userId") val userId: Long,
    @SerializedName("title") val title: String,
    @SerializedName("body") val body: String
)
```

1.  接下来，我们创建一个`PostService`接口，负责通过 Retrofit 从服务器加载数据。该类将具有一个用于检索帖子列表的方法，并将执行`HTTP GET`调用以检索数据：

```kt
interface PostService {
    @GET("posts")
    fun getPosts(): Call<List<Post>>
}
```

1.  接下来，让我们设置我们的 Room 数据库，其中将包含一个实体和一个数据访问对象。让我们为此定义一个`db`包。

1.  `PostEntity`类将与`Post`类具有类似的字段：

```kt
@Entity(tableName = "posts")
data class PostEntity(
    @PrimaryKey(autoGenerate = true) @ColumnInfo(name = "id")       val id: Long,
    @ColumnInfo(name = "userId") val userId: Long,
    @ColumnInfo(name = "title") val title: String,
    @ColumnInfo(name = "body") val body: String
)
```

1.  `PostDao`应包含用于存储帖子列表和检索帖子列表的方法：

```kt
@Dao
interface PostDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertPosts(posts: List<PostEntity>)
    @Query("SELECT * FROM posts")
    fun loadPosts(): LiveData<List<PostEntity>>
}
```

1.  最后，在 Room 配置的情况下，`Post`数据库应如下所示：

```kt
@Database(
    entities = [PostEntity::class],
    version = 1
)
abstract class PostDatabase : RoomDatabase() {
    abstract fun postDao(): PostDao
}
```

现在是时候进入`Repository`领域了。因此，让我们创建一个存储库包。

1.  之前，我们定义了两种类型的`Post`，一个是基于 JSON 的模型，一个是实体。让我们定义一个`PostMapper`类，将一个转换为另一个：

```kt
class PostMapper {
    fun serviceToEntity(post: Post): PostEntity {
        return PostEntity(post.id, post.userId, post.title,           post.body)
    }
}
```

1.  现在，让我们定义一个存储库接口，负责加载数据。存储库将从 API 加载数据并使用 Room 存储，然后提供带有 UI 层将消耗的`Room`实体的`LiveData`：

```kt
interface PostRepository {
    fun getPosts(): LiveData<List<PostEntity>>
}
```

1.  现在，让我们为此提供实现：

```kt
class PostRepositoryImpl(
    private val postService: PostService,
    private val postDao: PostDao,
    private val postMapper: PostMapper,
    private val executor: Executor
) : PostRepository {
    override fun getPosts(): LiveData<List<PostEntity>> {
        postService.getPosts().enqueue(object :           Callback<List<Post>> {
            override fun onFailure(call: Call<List<Post>>, t:               Throwable) {
            }
            override fun onResponse(call: Call<List<Post>>,               response: Response<List<Post>>) {
                response.body()?.let { posts ->
                    executor.execute {
                        postDao.insertPosts(posts.map { post ->
                            postMapper.serviceToEntity(post)
                        })
                    }
                }
            }
        })
        return postDao.loadPosts()
    }
}
```

如果您查看上述代码，您会看到当加载帖子时，我们将异步调用网络以加载帖子。调用完成后，我们将在单独的线程上使用新的帖子列表更新 Room。该方法将始终返回 Room 返回的内容。这是因为当 Room 中的数据最终发生变化时，它将传播到观察者。

1.  现在让我们设置我们的依赖关系。因为我们没有依赖注入框架，所以我们将不得不依赖`Application`类，这意味着我们将需要一个`RepositoryApplication`类，在其中我们将初始化存储库所需的所有服务，然后创建存储库：

```kt
class RepositoryApplication : Application() {
    lateinit var postRepository: PostRepository
    override fun onCreate() {
        super.onCreate()
        val retrofit = Retrofit.Builder()
            .baseUrl("https://jsonplaceholder.typicode.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        val postService =           retrofit.create<PostService>(PostService::class.java)
        val notesDatabase =
            Room.databaseBuilder(applicationContext,               PostDatabase::class.java, "post-db")
                .build()
        postRepository = PostRepositoryImpl(
            postService,
            notesDatabase.postDao(),
            PostMapper(),
            Executors.newSingleThreadExecutor()
        )
    }
}
```

1.  将`RepositoryApplication`添加到`AndroidManifest.xml`中`<application>`标签中的`android:name`。

1.  将互联网权限添加到`AndroidManifest.xml`文件中：

```kt
<uses-permission android:name="android.permission.INTERNET" />
```

1.  现在让我们定义我们的`ViewModel`：

```kt
class PostViewModel(private val postRepository: PostRepository) :   ViewModel() {
    fun getPosts() = postRepository.getPosts()
}
```

1.  每行的`view_post_row.xml`布局文件将如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout   xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:padding="10dp">
    <TextView
        android:id="@+id/view_post_row_title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent" />
    <TextView
        android:id="@+id/view_post_row_body"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="5dp"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf           ="@id/view_post_row_title" />
</androidx.constraintlayout.widget.ConstraintLayout>
```

1.  我们活动的`activity_main.xml`布局文件将如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout   xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">
    <androidx.recyclerview.widget.RecyclerView
        android:id="@+id/activity_main_recycler_view"
        android:layout_width="0dp"
        android:layout_height="0dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintLeft_toLeftOf="parent"
        app:layout_constraintRight_toRightOf="parent"
        app:layout_constraintTop_toTopOf="parent" />
</androidx.constraintlayout.widget.ConstraintLayout>
```

1.  用于行的`PostAdapter`类将如下所示：

```kt
class PostAdapter(private val layoutInflater: LayoutInflater) :
    RecyclerView.Adapter<PostAdapter.PostViewHolder>() {
    private val posts = mutableListOf<PostEntity>()
    override fun onCreateViewHolder(parent: ViewGroup, viewType:       Int): PostViewHolder =
        PostViewHolder(layoutInflater.inflate           (R.layout.view_post_row, parent, false))
    override fun getItemCount() = posts.size
    override fun onBindViewHolder(holder: PostViewHolder,       position: Int) {
        holder.bind(posts[position])
    }
    fun updatePosts(posts: List<PostEntity>) {
        this.posts.clear()
        this.posts.addAll(posts)
        this.notifyDataSetChanged()
    }
    inner class PostViewHolder(containerView: View) :       RecyclerView.ViewHolder(containerView) {
        private val titleTextView: TextView =           containerView.findViewById<TextView>            (R.id.view_post_row_title)
        private val bodyTextView: TextView = 
          containerView.findViewById<TextView>            (R.id.view_post_row_body)
        fun bind(postEntity: PostEntity) {
            bodyTextView.text = postEntity.body
            titleTextView.text = postEntity.title
        }
    }
}
```

1.  最后，`MainActivity`文件将如下所示：

```kt
class MainActivity : AppCompatActivity() {
    private lateinit var postAdapter: PostAdapter
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        postAdapter = PostAdapter(LayoutInflater.from(this))
        val recyclerView = findViewById<RecyclerView>          (R.id.activity_main_recycler_view)
        recyclerView.adapter = postAdapter
        recyclerView.layoutManager = LinearLayoutManager(this)
        val postRepository = (application as           RepositoryApplication).postRepository
        val postViewModel = ViewModelProvider(this, object :           ViewModelProvider.Factory {
            override fun <T : ViewModel?> create(modelClass:               Class<T>): T {
                return PostViewModel(postRepository) as T
            }
        }).get(PostViewModel::class.java)
        postViewModel.getPosts().observe(this, Observer {
            postAdapter.updatePosts(it)
        })
    }
}
```

如果您运行上述代码，您将看到以下输出：

![图 11.2：练习 11.01 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_02.jpg)

图 11.2：练习 11.01 的输出

您现在可以打开和关闭互联网，关闭和重新打开应用程序，以查看最初持久化的数据是否会继续显示。在当前实现中，错误处理目前为空。这意味着如果在检索帖子列表时出现问题，用户将不会得到通知。这可能会成为一个问题，并使用户感到沮丧。大多数应用程序在其用户界面上显示一些错误消息或其他内容，其中最常见的错误消息之一是“出现问题，请重试”，这是在错误没有被正确识别时用作通用占位符。

## 练习 11.02：添加错误处理

在这个练习中，我们将修改之前的练习。在出现互联网错误的情况下，我们将确保它会显示一个带有消息“出现问题”的提示。在添加错误处理的过程中，我们还需要通过创建一个新的模型类来消除 UI 和实体类之间的依赖，该模型类将保存相关数据。

为了处理错误，我们需要构建以下内容：

+   一个新的模型类，只包含正文和文本

+   一个包含成功、错误和加载三个内部类的密封类

+   我们的新模型和网络帖子之间的映射函数

执行以下步骤以完成此练习：

1.  让我们从我们的新模型开始。当与存储库模式结合使用时，这种类型的模型很常见，原因很简单。新模型可能包含特定于此屏幕的数据，需要一些额外的逻辑（假设您有一个具有`firstName`和`lastName`的用户，但您的 UI 要求在同一个`TextView`中显示两者。通过创建一个具有名称字段的新模型，您可以解决此问题，并且还可以对转换进行单元测试，并避免将连接移动到 UI 层）：

```kt
data class UiPost(
    val title: String,
    val body: String
)
```

1.  现在我们来看看我们的新密封类。这个密封类的子类包含了数据加载的所有状态。当存储库开始加载数据时，将发出“加载”状态；当存储库成功加载数据并包含帖子列表时，将发出“成功”状态；当发生错误时，将发出“错误”状态：

```kt
sealed class Result {
    object Loading : Result()
    class Success(val uiPosts: List<UiPost>) : Result()
    class Error(val throwable: Throwable) : Result()
}
```

1.  `PostMapper`中的映射方法将如下所示。它有一个额外的方法，将从 API 中提取的数据转换为 UI 模型，该模型只包含 UI 正确显示所需的字段：

```kt
class PostMapper {
    fun serviceToEntity(post: Post): PostEntity {
        return PostEntity(post.id, post.userId, post.title,           post.body)
    }
    fun serviceToUi(post: Post): UiPost {
        return UiPost(post.title, post.body)
    }
}
```

1.  现在，让我们修改`PostRepository`：

```kt
interface PostRepository {
    fun getPosts(): LiveData<Result>
}
```

1.  现在让我们修改`PostRepositoryImpl`。我们的结果将是`MutableLiveData`，它将以“加载”值开始，并根据 HTTP 请求的状态，它将发送一个带有项目列表的“成功”消息，或者带有错误“Retrofit 遇到”的“错误”消息。这种方法将不再依赖于始终显示存储的值。当请求成功时，将传递 HTTP 调用的输出，而不是 Room 的输出：

```kt
override fun getPosts(): LiveData<Result> {
        val result = MutableLiveData<Result>()
        result.postValue(Result.Loading)
        postService.getPosts().enqueue(object :           Callback<List<Post>> {
            override fun onFailure(call: Call<List<Post>>, t:               Throwable) {
                result.postValue(Result.Error(t))
            }
            override fun onResponse(call: Call<List<Post>>,               response: Response<List<Post>>) {
                if (response.isSuccessful) {
                    response.body()?.let { posts ->
                        executor.execute {
                            postDao.insertPosts(posts.map                               { post ->
                                postMapper.serviceToEntity(post)
                            })
                            result.postValue(Result                               .Success(posts.map { post ->
                                postMapper.serviceToUi(post)
                            }))
                        }
                    }
                } else {
                    result.postValue(Result.Error                       (RuntimeException("Unexpected error")))
                }
            }
        })
        return result
    }
```

1.  在您观察实时数据的活动中，需要实现以下更改。在这里，我们将检查每个状态并相应地更新 UI。如果出现错误，我们显示错误消息；如果成功，我们显示项目列表；当正在加载时，我们显示一个进度条，向用户指示后台正在进行工作：

```kt
        postViewModel.getPosts().observe(this,           Observer { result ->
            when (result) {
                is Result.Error -> {
                    Toast.makeText(applicationContext,                       R.string.error_message, Toast.LENGTH_LONG)
                        .show()
                    result.throwable.printStackTrace()
                }
                is Result.Loading -> {
                    // TODO show loading spinner
                }
                is Result.Success -> {
                    postAdapter.updatePosts(result.uiPosts)
                }
            }
        })
```

1.  最后，您的适配器应该如下所示：

```kt
class PostAdapter(private val layoutInflater: LayoutInflater) :
    RecyclerView.Adapter<PostAdapter.PostViewHolder>() {
    private val posts = mutableListOf<UiPost>()
    override fun onCreateViewHolder(parent: ViewGroup, viewType:       Int): PostViewHolder =
        PostViewHolder(layoutInflater           .inflate(R.layout.view_post_row, parent, false))
    override fun getItemCount(): Int = posts.size
    override fun onBindViewHolder(holder: PostViewHolder,       position: Int) {
        holder.bind(posts[position])
    }
    fun updatePosts(posts: List<UiPost>) {
        this.posts.clear()
        this.posts.addAll(posts)
        this.notifyDataSetChanged()
    }
    inner class PostViewHolder(containerView: View) :       RecyclerView.ViewHolder(containerView) {
        private val titleTextView: TextView =         containerView.findViewById<TextView>          (R.id.view_post_row_title)
        private val bodyTextView: TextView =           containerView.findViewById<TextView>            (R.id.view_post_row_body)
        fun bind(post: UiPost) {
            bodyTextView.text = post.body
            titleTextView.text = post.title
        }
    }
}
```

当您运行上述代码时，您应该看到*图 11.3*中呈现的屏幕：

![图 11.3：练习 11.02 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_03.jpg)

图 11.3：练习 11.02 的输出

从这一点开始，存储库可以以多种方式扩展：

+   添加算法，只有在经过一定时间后才会请求数据

+   定义一个更复杂的结果类，该类将能够存储缓存数据以及错误消息

+   添加内存缓存

+   添加滑动刷新功能，当`RecyclerView`向下滑动时刷新数据，并将加载小部件连接到`Loading`状态

# 偏好设置

假设您的任务是集成使用 OAuth 等内容的第三方 API，以实现使用 Facebook、Google 等方式进行登录。这些机制的工作方式如下：它们会给您一个令牌，您必须将其存储在本地，然后可以使用它发送其他请求以访问用户数据。您面临的问题是：您如何存储该令牌？您是否只使用 Room 存储一个令牌？您是否将令牌保存在单独的文件中，并实现用于编写文件的方法？如果必须同时访问该文件的多个位置怎么办？`SharedPreferences`是这些问题的答案。`SharedPreferences`是一种功能，允许您将布尔值、整数、浮点数、长整型、字符串和字符串集保存到 XML 文件中。当您想要保存新值时，您指定要为关联键保存哪些值，完成后，您提交更改，这将以异步方式触发将更改保存到 XML 文件中。`SharedPreferences`映射也保存在内存中，因此当您想要读取这些值时，它是瞬时的，从而消除了读取 XML 文件的异步调用的需要。

访问`SharedPreferences`数据的标准方式是通过`SharedPreferences`对象和更近期的`EncryptedSharedPreferences`选项（如果您希望保持数据加密）。还有一种通过`PreferenceFragments`的专门实现。在您想要实现类似设置的屏幕，并且希望存储用户希望调整的不同配置数据的情况下，这些是有用的。

## SharedPreferences

访问`SharedPreference`对象的方式是通过`Context`对象：

```kt
val prefs = getSharedPreferences("my-prefs-file",   Context.MODE_PRIVATE)
```

第一个参数是您指定偏好名称的地方，第二个是您希望如何将文件暴露给其他应用程序。目前，最佳模式是私有模式。其他所有模式都存在潜在的安全风险。

有一种专门的实现用于访问默认的`SharedPreferences`文件，这是由`PreferenceFragment`使用的。

```kt
PreferenceManager.getDefaultSharedPreferences(context)
```

如果要将数据写入偏好文件，首先需要访问偏好编辑器。编辑器将允许您访问写入数据。然后可以在编辑器中写入数据。完成写入后，必须应用更改，这将触发将数据持久保存到 XML 文件，并同时更改内存中的值。对于应用偏好文件上的更改，您有两种选择：`apply`或`commit`。 `apply`将立即保存更改到内存中，但然后写入磁盘将是异步的，这对于您想从应用程序的主线程调用此操作是有利的。 `commit`会同步执行所有操作，并给您一个布尔结果，通知您操作是否成功。在实践中，`apply`往往优于`commit`。

```kt
     val editor = prefs.edit()
     editor.putBoolean("my_key_1", true)
     editor.putString("my_key_2", "my string")
     editor.putLong("my_key_3", 1L)
     editor.apply()
```

现在，您想要清除所有数据。同样的原则将适用；您需要`editor`、`clear`和`apply`：

```kt
     val editor = prefs.edit()
     editor.clear()
     editor.apply()
```

如果要读取先前保存的值，可以使用`SharedPreferences`对象读取存储的值。如果没有保存的值，可以选择返回默认值。

```kt
     prefs.getBoolean("my_key_1", false)
     prefs.getString("my_key_2", "")
     prefs.getLong("my_key_3", 0L)
```

## 练习 11.03：包装 SharedPreferences

我们将构建一个应用程序，显示`TextView`、`EditText`和一个按钮。`TextView`将显示在`SharedPreferences`中保存的先前值。用户可以输入新文本，当单击按钮时，文本将保存在`SharedPreferences`中，`TextView`将显示更新后的文本。为了使代码更具可测试性，我们需要使用`ViewModel`和`LiveData`。

为了完成这个练习，我们需要创建一个`Wrapper`类，它将负责保存文本。这个类将以`LiveData`的形式返回文本的值。这将被注入到我们的`ViewModel`中，并绑定到活动中：

1.  让我们首先将适当的库添加到`app/build.gradle`中：

```kt
    implementation       "androidx.constraintlayout:constraintlayout:2.0.4"
    def lifecycle_version = "2.2.0"
    implementation "androidx.lifecycle:lifecycle-      extensions:$lifecycle_version"
    testImplementation 'junit:junit:4.12'
    testImplementation 'android.arch.core:core-testing:2.1.0'
    testImplementation 'org.mockito:mockito-core:2.23.0'
    androidTestImplementation 'androidx.test.ext:junit:1.1.2'
    androidTestImplementation       'androidx.test.espresso:espresso-core:3.3.0'
```

1.  让我们制作我们的`Wrapper`类，它将监听`SharedPreferences`的更改，并在偏好更改时更新`LiveData`的值。该类将包含保存新文本和检索`LiveData`的方法：

```kt
const val KEY_TEXT = "keyText"
class PreferenceWrapper(private val sharedPreferences:   SharedPreferences) {
    private val textLiveData = MutableLiveData<String>()
    init {
        sharedPreferences           .registerOnSharedPreferenceChangeListener { _, key ->
            when (key) {
                KEY_TEXT -> {
                    textLiveData.postValue(sharedPreferences                       .getString(KEY_TEXT, ""))
                }
            }
        }
    }
    fun saveText(text: String) {
        sharedPreferences.edit()
            .putString(KEY_TEXT, text)
            .apply()
    }
    fun getText(): LiveData<String> {
        textLiveData.postValue(sharedPreferences           .getString(KEY_TEXT, ""))
        return textLiveData
    }
}
```

注意文件顶部。我们添加了一个监听器，这样当我们的`SharedPreferences`值改变时，我们可以查找新值并更新我们的`LiveData`模型。这将允许我们观察`LiveData`的任何更改并只更新 UI。`saveText`方法将打开编辑器，设置新值并应用更改。`getText`方法将读取上次保存的值，在`LiveData`中设置它，并返回`LiveData`对象。这在应用程序打开并且我们想要在应用程序关闭之前访问上次的值时非常有用。

1.  现在，让我们使用偏好设置的实例设置`Application`类：

```kt
class PreferenceApplication : Application() {
    lateinit var preferenceWrapper: PreferenceWrapper
    override fun onCreate() {
        super.onCreate()
        preferenceWrapper =           PreferenceWrapper(getSharedPreferences("prefs",             Context.MODE_PRIVATE))
    }
}
```

1.  现在，让我们在`AndroidManifest.xml`的`application`标签中添加适当的属性：

```kt
android:name=".PreferenceApplication"
```

1.  现在，让我们构建`ViewModel`组件：

```kt
class PreferenceViewModel(private val preferenceWrapper:   PreferenceWrapper) : ViewModel() {
    fun saveText(text: String) {
        preferenceWrapper.saveText(text)
    }
    fun getText(): LiveData<String> {
        return preferenceWrapper.getText()
    }
}
```

1.  最后，让我们定义我们的`activity_main.xml`布局文件：

```kt
activity_main.xml
9    <TextView
10        android:id="@+id/activity_main_text_view"
11        android:layout_width="wrap_content"
12        android:layout_height="wrap_content"
13        android:layout_marginTop="50dp"
14        app:layout_constraintLeft_toLeftOf="parent"
15        app:layout_constraintRight_toRightOf="parent"
16        app:layout_constraintTop_toTopOf="parent" />
17
18    <EditText
19        android:id="@+id/activity_main_edit_text"
20        android:layout_width="200dp"
21        android:layout_height="wrap_content"
22        android:inputType="none"
23        app:layout_constraintLeft_toLeftOf="parent"
24        app:layout_constraintRight_toRightOf="parent"
25        app:layout_constraintTop_toBottomOf=             "@id/activity_main_text_view" />
26
27    <Button
28        android:id="@+id/activity_main_button"
29        android:layout_width="wrap_content"
30        android:layout_height="wrap_content"
31        android:inputType="none"
32        android:text="@android:string/ok"
33        app:layout_constraintLeft_toLeftOf="parent"
34        app:layout_constraintRight_toRightOf="parent"
35        app:layout_constraintTop_toBottomOf=            "@id/activity_main_edit_text" /> 
The complete code for this step can be found at http://packt.live/39RhIj0.
```

1.  最后，在`MainActivity`中执行以下步骤：

```kt
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val preferenceWrapper = (application as         PreferenceApplication).preferenceWrapper
        val preferenceViewModel = ViewModelProvider(this, object           : ViewModelProvider.Factory {
            override fun <T : ViewModel?> create(modelClass:               Class<T>): T {
                return PreferenceViewModel(preferenceWrapper)                   as T
            }
        }).get(PreferenceViewModel::class.java)
        preferenceViewModel.getText().observe(this, Observer {
        findViewById<TextView>(R.id.activity_main_text_view)           .text = it
        })
        findViewById<Button>(R.id.activity_main_button)          .setOnClickListener {
        preferenceViewModel.saveText(findViewById<EditText>          (R.id.activity_main_edit_text).text.toString())
        }
    }
}
```

上述代码将产生*图 11.4*中呈现的输出：

![图 11.4：练习 11.03 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_04.jpg)

图 11.4：练习 11.03 的输出

插入值后，尝试关闭应用程序并重新打开它。应用程序将显示上次持久化的值。

## PreferenceFragment

如前所述，`PreferenceFragment`是依赖于`SharedPreferences`来存储用户设置的片段的专门实现。其功能包括基于开/关切换存储布尔值，基于向用户显示的对话框存储文本，基于单选和多选对话框存储字符串集，基于`SeekBars`存储整数，并对部分进行分类并链接到其他`PreferenceFragment`类。

虽然`PreferenceFragment`类是 Android 框架的一部分，但它们被标记为已弃用，这意味着片段的推荐方法是依赖于 Jetpack Preference 库，该库引入了`PreferenceFragmentCompat`。`PreferenceFragmentCompat`对确保新的 Android 框架和旧的 Android 框架之间的向后兼容性非常有用。

构建`PreferenceFragment`类需要两个东西：

+   `res/xml`文件夹中的资源，其中包含偏好设置的结构

+   一个扩展`PreferenceFragment`的类，它将 XML 文件与片段链接起来

如果您想从非`PreferenceFragment`资源访问您的`PreferenceFragment`存储的值，可以使用`PreferenceManager.getDefaultSharedPreferences(context)`方法访问`SharedPreference`对象。访问值的键是您在 XML 文件中定义的键。

名为 settings_preference.xml 的偏好 XML 文件示例如下：

```kt
<?xml version="1.0" encoding="utf-8"?>
<PreferenceScreen xmlns:app="http://schemas.android.com/apk/res-auto">
    <PreferenceCategory app:title="Primary settings">
        <SwitchPreferenceCompat
            app:key="work_offline"
            app:title="Work offline" />
        <Preference
            app:icon="@mipmap/ic_launcher"
            app:key="my_key"
            app:summary="Summary"
            app:title="Title" />
    </PreferenceCategory>
</PreferenceScreen>
```

对于每个偏好设置，您可以显示图标、标题、摘要、当前值以及它是否可选择。一个重要的事情是键以及如何将其链接到您的 Kotlin 代码。您可以使用`strings.xml`文件声明不可翻译的字符串，然后在您的 Kotlin 代码中提取它们。

您的`PreferenceFragment`将类似于这样：

```kt
class MyPreferenceFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?,       rootKey: String?) {
        setPreferencesFromResource(R.xml.settings_preferences,           rootKey)
    }
}
```

`onCreatePreferences`方法是抽象的，您需要实现它以通过`setPreferencesFromResource`方法指定偏好设置的 XML 资源。

您还可以使用`findPreference`方法以编程方式访问偏好设置：

```kt
findPreference<>(key)
```

这将返回一个将从`Preference`扩展的对象。对象的性质应与在 XML 中为该特定键声明的类型匹配。您可以以编程方式修改`Preference`对象并更改所需的字段。

您还可以使用`PreferenceFragment`中继承的`PreferenceManager`类上的`createPreferenceScreen(Context)`来以编程方式构建设置屏幕：

```kt
val preferenceScreen =   preferenceManager.createPreferenceScreen(context)
```

您可以在`PreferenceScreen`容器上使用`addPreference(Preference)`方法添加新的`Preference`对象：

```kt
val editTextPreference = EditTextPreference(context)
editTextPreference.key = "key"
editTextPreference.title = "title"
val preferenceScreen = preferenceManager.createPreferenceScreen(context)
preferenceScreen.addPreference(editTextPreference)
setPreferenceScreen(preferenceScreen)
```

现在让我们继续下一个练习，自定义您的设置。

## 练习 11.04：自定义设置

在这个练习中，我们将构建 VPN 应用的设置。设置页面的产品要求如下：

+   `SeekBar`

+   **配置**：IP 地址 - 文本；域 - 文本

+   `使用移动数据`，带有一个切换和一个下面包含文本`明智地管理您的移动数据`的不可选择选项。

执行以下步骤以完成此练习：

1.  让我们首先添加 Jetpack Preference 库：

```kt
implementation 'androidx.preference:preference-ktx:1.1.1'
```

1.  在`res/values`中，创建一个名为`preference_keys.xml`的文件，并定义`More preferences`屏幕的键：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="key_mobile_data"       translatable="false">mobile_data</string>
</resources>
```

1.  如果`res`中没有`xml`文件夹，请创建一个。

1.  在`res/xml`文件夹中创建`preferences_more.xml`文件。

1.  在`preferences_more.xml`文件中，添加以下首选项：

```kt
<?xml version="1.0" encoding="utf-8"?>
<PreferenceScreen xmlns:app=  "http://schemas.android.com/apk/res-auto">
    <SwitchPreferenceCompat
        app:key="@string/key_mobile_data"
        app:title="@string/mobile_data" />
    <Preference
        app:selectable="false"
        app:summary="@string/manage_data_wisely" />
</PreferenceScreen>
```

1.  在`strings.xml`中，添加以下字符串：

```kt
<string name="mobile_data">Mobile data</string>
<string name="manage_data_wisely">Manage your data   wisely</string>
```

1.  创建一个名为`MorePreferenceFragment`的`PreferenceFragment`类：

```kt
class MorePreferenceFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?,       rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences_more,           rootKey)
    }
}
```

我们已经完成了`More`部分。现在让我们创建主要部分。

1.  让我们为主要首选项部分创建键。在`preference_keys.xml`中，添加以下内容：

```kt
<string name="key_network_scan"   translatable="false">network_scan</string>
<string name="key_frequency"   translatable="false">frequency</string>
<string name="key_ip_address"   translatable="false">ip_address</string>
<string name="key_domain" translatable="false">domain</string>
```

1.  在`res/xml`中，创建`preferences_settings.xml`文件。

1.  现在，根据规格定义您的首选项：

```kt
<?xml version="1.0" encoding="utf-8"?>
<PreferenceScreen xmlns:app=  "http://schemas.android.com/apk/res-auto">
    <PreferenceCategory app:title="@string/connectivity">
        <SwitchPreferenceCompat
            app:key="@string/key_network_scan"
            app:title="@string/network_scan" />
        <SeekBarPreference
            app:key="@string/key_frequency"
            app:title="@string/frequency" />
    </PreferenceCategory>
    <PreferenceCategory app:title="@string/configuration">
        <EditTextPreference
            app:key="@string/key_ip_address"
            app:title="@string/ip_address" />
        <EditTextPreference
            app:key="@string/key_domain"
            app:title="@string/domain" />
    </PreferenceCategory>
PreferenceFragment and another. By default, the system will do the transition for us, but there is a way to override this behavior in case we want to update our UI.
```

1.  在`strings.xml`中，确保您有以下值：

```kt
<string name="connectivity">Connectivity</string>
<string name="network_scan">Network scan</string>
<string name="frequency">Frequency</string>
<string name="configuration">Configuration</string>
<string name="ip_address">IP Address</string>
<string name="domain">Domain</string>
<string name="more">More</string>
```

1.  创建一个名为`SettingsPreferenceFragment`的片段。

1.  添加以下设置：

```kt
class SettingsPreferenceFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?,       rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences_settings,           rootKey)
    }
}
```

1.  现在，让我们将`Fragments`添加到我们的活动中。

1.  在`activity_main.xml`中，定义一个`FrameLayout`标签来包含片段：

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout   xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity"
    android:id="@+id/fragment_container"/>
```

1.  最后，在`MainActivity`中执行以下步骤：

```kt
class MainActivity : AppCompatActivity(),
    onPreferenceStartFragment from the PreferenceFragmentCompat.OnPreferenceStartFragmentCallback interface. This allows us to intercept the switch between fragments and add our own behavior. The first half of the method will use the inputs of the method to create a new instance of MorePreferenceFragment, while the second half performs the fragment transaction. Then, we return true because we have handled the transition ourselves.
```

1.  运行上述代码将产生以下输出：![图 11.5：练习 11.04 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_05.jpg)

图 11.5：练习 11.04 的输出

现在，我们可以监视首选项的更改并在 UI 中显示它们。我们可以将此功能应用于 IP 地址和域部分，以显示用户输入的摘要。

1.  现在让我们修改`SettingsPreferenceFragment`，以便在值更改时以编程方式设置监听器，这将在摘要中显示新值。当首次打开屏幕时，我们还需要设置保存的值。我们需要使用`findPreference(key)`来定位我们想要修改的首选项。这允许我们以编程方式修改首选项。我们还可以在首选项上注册监听器，这将使我们能够访问新值。在我们的情况下，我们可以注册一个监听器，以便在 IP 地址更改时更新字段的摘要，这样我们就可以根据用户在`EditText`中输入的内容更新字段的摘要：

```kt
class SettingsPreferenceFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?,       rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences_settings,           rootKey)
        val ipAddressPref =           findPreference<EditTextPreference>(getString             (R.string.key_ip_address))
        ipAddressPref?.setOnPreferenceChangeListener {           preference, newValue ->
            preference.summary = newValue.toString()
            true
        }
        val domainPref = findPreference<EditTextPreference>          (getString(R.string.key_domain))
        domainPref?.setOnPreferenceChangeListener { preference,           newValue ->
            preference.summary = newValue.toString()
            true
        }
        val sharedPrefs = PreferenceManager           .getDefaultSharedPreferences(requireContext())
        ipAddressPref?.summary = sharedPrefs           .getString(getString(R.string.key_ip_address), "")
        domainPref?.summary = sharedPrefs           .getString(getString(R.string.key_domain), "")
    }
}
```

`PreferenceFragment`是为任何应用构建类似设置功能的好方法。它与`SharedPreferences`的集成和内置 UI 组件允许开发人员比通常更快地构建元素，并解决处理每个设置元素的点击和插入的许多问题。

# 文件

我们已经讨论了 Room 和`SharedPreferences`，并指定了它们存储的数据是如何写入文件的。您可能会问自己，这些文件存储在哪里？这些特定的文件存储在内部存储中。内部存储是每个应用程序的专用空间，其他应用程序无法访问（除非设备已 root）。您的应用程序使用的存储空间没有限制。但是，用户可以从“设置”菜单中删除您的应用程序文件的能力。内部存储占用总可用空间的一小部分，这意味着在存储文件时应该小心。还有外部存储。您的应用程序存储的文件可供其他应用程序访问，其他应用程序存储的文件也可供您的应用程序访问：

注意

在 Android Studio 中，您可以使用设备文件浏览器工具浏览设备或模拟器上的文件。内部存储位于`/data/data/{packageName}`。如果您可以访问此文件夹，这意味着设备已经 root。使用这个，您可以可视化数据库文件和`SharedPreferences`文件。

![图 11.6：Android 设备文件浏览器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_06.jpg)

图 11.6：Android 设备文件浏览器

## 内部存储

内部存储不需要用户的权限。要访问内部存储目录，可以使用`Context`对象的以下方法之一：

+   `getDataDir()`: 返回应用沙盒的根文件夹。

+   `getFilesDir()`: 一个专门用于应用文件的文件夹；推荐使用。

+   `getCacheDir()`: 一个专门用于缓存文件的文件夹。在这里存储文件并不保证以后可以检索到它们，因为系统可能决定删除此目录以释放内存。这个文件夹与“设置”中的“清除缓存”选项相关联。

+   `getDir(name, mode)`: 返回一个文件夹，如果不存在则根据指定的名称创建。

当用户从“设置”中使用“清除数据”选项时，大多数这些文件夹将被删除，使应用程序回到类似于新安装的状态。当应用被卸载时，这些文件也将被删除。

读取缓存文件的典型示例如下：

```kt
        val cacheDir = context.cacheDir
        val fileToReadFrom = File(cacheDir, "my-file.txt")
        val size = fileToReadFrom.length().toInt()
        val bytes = ByteArray(size)
        val tmpBuff = ByteArray(size)
        val fis = FileInputStream(fileToReadFrom)
        try {
            var read = fis.read(bytes, 0, size)
            if (read < size) {
                var remain = size - read
                while (remain > 0) {
                    read = fis.read(tmpBuff, 0, remain)
                    System.arraycopy(tmpBuff, 0, bytes,                                      size - remain, read)
                    remain -= read
                }
            }
        } catch (e: IOException) {
            throw e
        } finally {
            fis.close()
        }
```

上面的示例将从`Cache`目录中的`my-file.txt`读取，并为该文件创建`FileInputStream`。然后，将使用一个缓冲区来收集文件中的字节。收集到的字节将被放入`bytes`字节数组中，其中包含从该文件中读取的所有数据。当文件的整个长度被读取时，读取将停止。

写入`my-file.txt`文件将如下所示：

```kt
        val bytesToWrite = ByteArray(100)
        val cacheDir = context.cacheDir
        val fileToWriteIn = File(cacheDir, "my-file.txt")
        try {
            if (!fileToWriteIn.exists()) {
                fileToWriteIn.createNewFile()
            }
            val fos = FileOutputStream(fileToWriteIn)
            fos.write(bytesToWrite)
            fos.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
```

上面的示例所做的是获取要写入的字节数组，创建一个新的`File`对象，如果不存在则创建文件，并通过`FileOutputStream`将字节写入文件。

注意

处理文件有许多替代方法。读取器（`StreamReader`，`StreamWriter`等）更适合基于字符的数据。还有第三方库可以帮助进行磁盘 I/O 操作。其中一个最常见的帮助进行 I/O 操作的第三方是 Okio。它起初是`OkHttp`库的一部分，用于与 Retrofit 一起进行 API 调用。Okio 提供的方法与它用于在 HTTP 通信中写入和读取数据的方法相同。

## 外部存储

在外部存储中读写需要用户的读写权限。如果授予写入权限，则您的应用程序可以读取外部存储。一旦这些权限被授予，您的应用程序就可以在外部存储上做任何它想做的事情。这可能会带来问题，因为用户可能不选择授予这些权限。然而，有专门的方法可以让您在专门为您的应用程序提供的外部存储中进行写入。

从`Context`和`Environment`对象中访问外部存储的一些常见方式是：

+   `Context.getExternalFilesDir(mode)`：这个方法将返回专门为你的应用程序在外部存储上的目录路径。指定不同的模式（图片、电影等）将创建不同的子文件夹，具体取决于你希望如何保存你的文件。这个方法*不需要权限*。

+   `Context.getExternalCacheDir()`：这将指向外部存储上应用程序的缓存目录。对这个`cache`文件夹应用相同的考虑。这个方法*不需要权限*。

+   `Environment`类可以访问设备上一些最常见文件夹的路径。然而，在新设备上，应用可能无法访问这些文件和文件夹。

注意

避免使用硬编码的文件和文件夹路径。安卓操作系统可能会根据设备或操作系统的不同而改变文件夹的位置。

## FileProvider

这代表了`ContentProviders`的一个专门实现，有助于组织应用程序的文件和文件夹结构。它允许你指定一个 XML 文件，在其中定义你的文件应该如何在内部和外部存储之间分割。它还让你有能力通过隐藏路径并生成一个唯一的 URI 来授予其他应用程序对你的文件的访问权限。

`FileProvider`让你可以在六个不同的文件夹中选择设置你的文件夹层次结构：

+   `Context.getFilesDir()`（文件路径）

+   `Context.getCacheDir()`（缓存路径）

+   `Environment.getExternalStorageDirectory()`（外部路径）

+   `Context.getExternalFilesDir(null)`（外部文件路径）

+   `Context.getExternalCacheDir()`（外部缓存路径）

+   `Context.getExternalMediaDirs()`的第一个结果（外部媒体路径）

`FileProvider`的主要优点在于它提供了对文件的抽象，因为它让开发人员在 XML 文件中定义路径，并且更重要的是，如果你选择将文件存储在外部存储上，你不需要向用户请求权限。另一个好处是它使共享内部文件更容易，同时让开发人员控制其他应用程序可以访问哪些文件，而不会暴露它们的真实位置。

让我们通过以下例子更好地理解：

```kt
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <files-path name="my-visible-name" path="/my-folder-name" />
</paths>
```

上述例子将使`FileProvider`使用内部的`files`目录，并创建一个名为`my-folder-name`的文件夹。当路径转换为 URI 时，URI 将使用`my-visible-name`。

## 存储访问框架（SAF）

SAF 是在 Android KitKat 中引入的文件选择器，应用程序可以使用它让用户选择要处理或上传的文件。你可以在你的应用程序中使用它来处理以下情况：

1.  你的应用程序需要用户处理由其他应用程序保存在设备上的文件（照片和视频）。

1.  你希望在设备上保存一个文件，并让用户选择文件的保存位置和文件的名称。

1.  你希望为你的应用程序使用的文件提供给其他应用程序，以满足类似于第 1 种情况的场景。

这再次有用，因为你的应用程序将避免读写权限，但仍然可以写入和访问外部存储。这是基于意图的工作方式。你可以使用`Intent.ACTION_OPEN_DOCUMENT`或`Intent.ACTION_CREATE_DOCUMENT`启动一个活动以获取结果。然后，在`onActivityResult`中，系统将给你一个 URI，授予你对该文件的临时权限，允许你读写。

SAF 的另一个好处是文件不必在设备上。诸如谷歌云这样的应用程序在 SAF 中公开其内容，当选择谷歌云文件时，它将被下载到设备，并且 URI 将作为结果发送。另一个重要的事情是 SAF 对虚拟文件的支持，这意味着它将公开谷歌文档，这些文档有自己的格式，但是当这些文档通过 SAF 下载时，它们的格式将被转换为 PDF 等通用格式。

## 资产文件

资产文件是您可以打包为 APK 的文件。如果您使用过在应用程序启动时或作为教程的一部分播放某些视频或 GIF 的应用程序，那么这些视频很可能已经与 APK 捆绑在一起。要将文件添加到资产中，您需要项目中的`assets`文件夹。然后，您可以使用文件夹将文件分组到资产中。

您可以通过`AssetManager`类在运行时访问这些文件，`AssetManager`本身可以通过上下文对象访问。`AssetManager`为您提供了查找文件和读取文件的能力，但不允许任何写操作：

```kt
        val assetManager = context.assets
        val root = ""
        val files = assetManager.list(root)
        files?.forEach {
            val inputStream = assetManager.open(root + it)
        }
```

前面的示例列出了`assets`文件夹根目录中的所有文件。`open`函数返回`inputStream`，如果需要，可以用它来读取文件信息。

`assets`文件夹的一个常见用途是用于自定义字体。如果您的应用程序使用自定义字体，那么可以使用`assets`文件夹来存储字体文件。

## 练习 11.05：复制文件

注意

对于这个练习，您将需要一个模拟器。您可以在 Android Studio 中选择`Tools` | `AVD Manager`来创建一个。然后，您可以使用`Create Virtual Device`选项创建一个，选择模拟器类型，单击`Next`，然后选择 x86 映像。大于棒棒糖的任何映像都应该适用于这个练习。接下来，您可以给您的映像命名并单击`Finish`。

让我们创建一个应用程序，将在`assets`目录中保留一个名为`my-app-file.txt`的文件。该应用程序将显示两个名为`FileProvider`和`SAF`的按钮。单击`FileProvider`按钮时，文件将保存在应用程序的外部存储专用区域（`Context.getExternalFilesDir(null)`）。`SAF`按钮将打开 SAF，并允许用户指示文件应保存在何处。

为了实现这个练习，将采用以下方法：

+   定义一个文件提供程序，它将使用`Context.getExternalFilesDir(null)`位置。

+   单击`FileProvider`按钮时，将`my-app-file.txt`复制到前面的位置。

+   单击`SAF`按钮时使用`Intent.ACTION_CREATE_DOCUMENT`，并将文件复制到提供的位置。

+   为文件复制使用单独的线程，以符合 Android 指南。

+   使用 Apache IO 库来帮助文件复制功能，提供允许我们从 InputStream 复制数据到 OutputStream 的方法。

完成的步骤如下：

1.  让我们从 Gradle 配置开始：

```kt
implementation 'commons-io:commons-io:2.6'
testImplementation 'org.mockito:mockito-core:2.23.0'
```

1.  在`main/assets`文件夹中创建`my-app-file.txt`文件。随意填写您想要阅读的文本。如果`main/assets`文件夹不存在，则可以创建它。要创建`assets`文件夹，可以右键单击`main`文件夹，然后选择`New`，然后选择`Directory`并命名为`assets`。此文件夹现在将被构建系统识别，并且其中的任何文件也将与应用程序一起安装在设备上。

1.  我们还可以定义一个类，它将包装`AssetManager`并定义一个访问这个特定文件的方法：

```kt
class AssetFileManager(private val assetManager: AssetManager) {
    fun getMyAppFileInputStream() =       assetManager.open("my-app-file.txt")
}
```

1.  现在，让我们来处理`FileProvider`方面。在`res`文件夹中创建`xml`文件夹。在新文件夹中定义`file_provider_paths.xml`。我们将定义`external-files-path`，命名为`docs`，并将其放在`docs/`文件夹中：

```kt
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <external-files-path name="docs" path="docs/"/>
</paths>
```

1.  接下来，我们需要将`FileProvider`添加到`AndroidManifest.xml`文件中，并将其与我们定义的新路径链接起来：

```kt
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="com.android.testable.files"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support                               .FILE_PROVIDER_PATHS"
                android:resource="@xml/file_provider_paths" />
        </provider>
```

名称将指向 Android 支持库的`FileProvider`路径。authorities 字段表示应用程序的域（通常是应用程序的包名称）。exported 字段指示我们是否希望与其他应用程序共享我们的提供程序，`grantUriPermissions`指示我们是否希望通过 URI 授予其他应用程序对某些文件的访问权限。meta-data 将我们之前定义的 XML 文件与`FileProvider`链接起来。

1.  定义`ProviderFileManager`类，负责访问`docs`文件夹并将数据写入文件：

```kt
class ProviderFileManager(
    private val context: Context,
    getDocsFolder will return the path to the docs folder we defined in the XML. If the folder does not exist, then it will be created. The writeStream method will extract the URI for the file we wish to save and, using the Android ContentResolver class, will give us access to the OutputStream class of the file we will be saving into. Notice that FileToUriMapper doesn't exist yet. The code is moved into a separate class in order to make this class testable.
```

1.  `FileToUriMapper`类如下所示：

```kt
class FileToUriMapper {
    fun getUriFromFile(context: Context, file: File): Uri {
        getUriForFile method is part of the FileProvider class and its role is to convert the path of a file into a URI that can be used by ContentProviders/ContentResolvers to access data. Because the method is static, it prevents us from testing properly.Notice the test rule we used. This comes in handy when testing files. What it does is supply the test with the necessary files and folders and when the test finishes, it will remove all the files and folders.
```

1.  现在让我们继续定义`activity_main.xml`文件的 UI：

```kt
activity_main.xml
9    <Button
10        android:id="@+id/activity_main_file_provider"
11        android:layout_width="wrap_content"
12        android:layout_height="wrap_content"
13        android:layout_marginTop="200dp"
14        android:text="@string/file_provider"
15        app:layout_constraintEnd_toEndOf="parent"
16        app:layout_constraintStart_toStartOf="parent"
17        app:layout_constraintTop_toTopOf="parent" />
18
19    <Button
20        android:id="@+id/activity_main_saf"
21        android:layout_width="wrap_content"
22        android:layout_height="wrap_content"
23        android:layout_marginTop="50dp"
24        android:text="@string/saf"
25        app:layout_constraintEnd_toEndOf="parent"
26        app:layout_constraintStart_toStartOf="parent"
27        app:layout_constraintTop_toBottomOf=            "@id/activity_main_file_provider" /> 
The complete code for this step can be found at http://packt.live/3bTNmz4.
```

1.  现在，让我们定义我们的`MainActivity`类：

```kt
class MainActivity : AppCompatActivity() {
    private val assetFileManager: AssetFileManager by lazy {
        AssetFileManager(applicationContext.assets)
    }
    private val providerFileManager: ProviderFileManager by lazy {
        ProviderFileManager(
            applicationContext,
            FileToUriMapper(),
            Executors.newSingleThreadExecutor()
        )
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<Button>(R.id.activity_main_file_provider)          .setOnClickListener {
            val newFileName = "Copied.txt"
MainActivity to create our objects and inject data into the different classes we have. If we execute this code and click the FileProvider button, we don't see an output on the UI. However, if we look with Android Device File Explorer, we can locate where the file was saved. The path may be different on different devices and operating systems. The paths could be as follows:*   `mnt/sdcard/Android/data/<package_name>/files/docs`*   `sdcard/Android/data/<package_name>/files/docs`*   `storage/emulated/0/Android/data/<package_name>/files/docs`
```

输出如下：

![图 11.7：通过 FileProvider 复制的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_07.jpg)

图 11.7：通过 FileProvider 复制的输出

1.  让我们为`SAF`按钮添加逻辑。我们需要启动一个指向`SAF`的活动，并使用`CREATE_DOCUMENT`意图，指定我们要创建一个文本文件。然后我们需要`SAF`的结果，这样我们就可以将文件复制到用户选择的位置。在`MainActivity`的`onCreateMethod`中，我们可以添加以下内容：

```kt
        findViewById<Button>(R.id.activity_main_saf)      .setOnClickListener {
            if (Build.VERSION.SDK_INT >=               Build.VERSION_CODES.KITKAT) {
                val intent =                   Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TITLE, "Copied.txt")
                }
                startActivityForResult(intent,                   REQUEST_CODE_CREATE_DOC)
            }
        }
```

上述代码将创建一个意图，以创建一个名为`Copied.txt`的文档，并使用`text/plain` MIME（多用途互联网邮件扩展）类型（适用于文本文件）。此代码仅在大于 KitKat 的 Android 版本中运行。

1.  现在让我们告诉活动如何处理文档创建的结果。我们将收到一个 URI 对象，其中用户选择了一个空文件。现在我们可以将我们的文件复制到该位置。在`MainActivity`中，我们添加`onActivityResult`，如下所示：

```kt
    override fun onActivityResult(requestCode: Int, resultCode:       Int, data: Intent?) {
        if (requestCode == REQUEST_CODE_CREATE_DOC           && resultCode == Activity.RESULT_OK) {
            data?.data?.let { uri ->
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }
```

1.  现在我们有了 URI。我们可以在`ProviderFileManager`中添加一个方法，将我们的文件复制到`uri`指定的位置：

```kt
    fun writeStreamFromUri(name: String, inputStream:       InputStream, uri:Uri){
        executor.execute {
            val outputStream =               context.contentResolver.openOutputStream(uri, "rw")
            IOUtils.copy(inputStream, outputStream)
        }
    }
```

1.  我们可以从`MainActivity`的`onActivityResult`方法中调用此方法，如下所示：

```kt
        if (requestCode == REQUEST_CODE_CREATE_DOC           && resultCode == Activity.RESULT_OK) {
            data?.data?.let { uri ->
                val newFileName = "Copied.txt"
                providerFileManager.writeStreamFromUri(
                    newFileName,
                    assetFileManager.getMyAppFileInputStream(),
                    uri
                )
            }
        }
```

如果我们运行上述代码并单击`SAF`按钮，我们将看到*图 11.8*中呈现的输出：

![图 11.8：通过 SAF 复制的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_08.jpg)

图 11.8：通过 SAF 复制的输出

如果您选择保存文件，SAF 将关闭，并且我们的活动的`onActivityResult`方法将被调用，这将触发文件复制。之后，您可以导航到 Android 设备文件管理器工具，查看文件是否已正确保存。

# 作用域存储

自 Android 10 以来，并在 Android 11 中进一步更新，引入了作用域存储的概念。其背后的主要思想是允许应用程序更多地控制外部存储上的文件，并防止其他应用程序访问这些文件。这意味着`READ_EXTERNAL_STORAGE`和`WRITE_EXTERNAL_STORAGE`仅适用于用户与之交互的文件（如媒体文件）。这会阻止应用程序在外部存储上创建自己的目录，而是坚持使用通过`Context.getExternalFilesDir`提供给它们的目录。

FileProviders 和存储访问框架是保持应用程序符合作用域存储实践的好方法，因为其中一个允许应用程序使用`Context.getExternalFilesDir`，另一个使用内置的文件浏览器应用程序，现在将避免在外部存储的`Android/data`和`Android/obb`文件夹中的其他应用程序文件。

## 相机和媒体存储

Android 提供了多种与 Android 设备上的媒体交互的方式，从构建自己的相机应用程序并控制用户如何拍照和录像，到使用现有的相机应用程序并指导其如何拍照和录像。Android 还配备了`MediaStore`内容提供程序，允许应用程序提取有关设备上设置的媒体文件和应用程序之间共享的媒体文件的信息。这在您希望为设备上存在的媒体文件（如照片或音乐播放器应用程序）自定义显示的情况下非常有用，并且在使用`MediaStore.ACTION_PICK`意图从设备中选择照片并希望提取所选媒体图像的信息的情况下也非常有用（这通常是旧应用程序的情况，无法使用 SAF）。

要使用现有的相机应用程序，您需要使用`MediaStore.ACTION_IMAGE_CAPTURE`意图启动相机应用程序以获取结果，并传递您希望保存的图像的 URI。然后用户将转到相机活动，拍照，然后您处理操作的结果：

```kt
        val intent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
        intent.putExtra(MediaStore.EXTRA_OUTPUT, photoUri)
        startActivityForResult(intent, REQUEST_IMAGE_CAPTURE)
```

`photoUri`参数将表示您希望保存照片的位置。它应指向一个具有 JPEG 扩展名的空文件。您可以通过两种方式构建此文件：

+   在外部存储上使用`File`对象创建文件（这需要`WRITE_EXTERNAL_STORAGE`权限），然后使用`Uri.fromFile()`方法将其转换为`URI` - 在 Android 10 及以上版本不再适用

+   使用`File`对象在`FileProvider`位置创建文件，然后使用`FileProvider.getUriForFile()`方法获取 URI 并在必要时授予权限-适用于您的应用程序目标为 Android 10 和 Android 11 的推荐方法

注意

相同的机制也可以应用于使用`MediaStore.ACTION_VIDEO_CAPTURE`的视频。

如果您的应用程序严重依赖相机功能，则可以通过将`<uses-feature>`标签添加到`AndroidManifest.xml`文件中来排除没有相机的设备的用户。您还可以将相机指定为非必需，并使用`Context.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)`方法查询相机是否可用。

如果您希望将文件保存在`MediaStore`中，有多种方法可以实现：

+   发送带有媒体 URI 的`ACTION_MEDIA_SCANNER_SCAN_FILE`广播：

```kt
            val intent =               Intent(Intent.ACTION_MEDIA_SCANNER_SCAN_FILE)
       intent.data = photoUri
       sendBroadcast(intent)
```

+   使用媒体扫描程序直接扫描文件：

```kt
        val paths = arrayOf("path1", "path2")
        val mimeTypes= arrayOf("type1", "type2")
        MediaScannerConnection.scanFile(context,paths,           mimeTypes) { path, uri ->
        }
```

+   直接将媒体插入`ContentProvider`使用`ContentResolver`：

```kt
        val contentValues = ContentValues()
        contentValues.put(MediaStore.Images.ImageColumns.TITLE,           "my title")
            contentValues.put(MediaStore.Images.ImageColumns               .DATE_ADDED, timeInMillis)
            contentValues.put(MediaStore.Images.ImageColumns               .MIME_TYPE, "image/*")
            contentValues.put(MediaStore.Images.ImageColumns               .DATA, "my-path")
            val newUri = contentResolver.insert(MediaStore.Video               .Media.EXTERNAL_CONTENT_URI, contentValues)
                newUri?.let { 
              val outputStream = contentResolver                 .openOutputStream(newUri)
                // Copy content in outputstream
            }
```

注意

在 Android 10 及以上版本中，`MediaScanner`功能不再添加来自`Context.getExternalFilesDir`的文件。如果应用程序选择与其他应用程序共享其媒体文件，则应依赖`insert`方法。

## 练习 11.06：拍照

我们将构建一个应用程序，其中有两个按钮：第一个按钮将打开相机应用程序以拍照，第二个按钮将打开相机应用程序以录制视频。我们将使用`FileProvider`将照片保存到外部存储（external-path）中的两个文件夹：`pictures`和`movies`。照片将使用`img_{timestamp}.jpg`保存，视频将使用`video_{timestamp}.mp4`保存。保存照片和视频后，您将从`FileProvider`复制文件到`MediaStore`中，以便其他应用程序可以看到。

1.  让我们在`app/build.gradle`中添加库：

```kt
    implementation 'commons-io:commons-io:2.6'
    testImplementation 'org.mockito:mockito-core:2.23.0'
```

1.  我们将以 Android 11 为目标，这意味着我们需要在`app/build.gradle`中进行以下配置

```kt
...
compileSdkVersion 30
    defaultConfig {
        ...
        targetSdkVersion 30
        ...
    }
...
```

1.  我们需要为低于 Android 10 的设备请求 WRITE_EXTERNAL_STORAGE 权限，这意味着我们需要在`AndroidManifest.xml`中添加以下内容：

```kt
<uses-permission
        android:name="android.permission.WRITE_EXTERNAL_STORAGE"
        android:maxSdkVersion="28" />
```

1.  让我们定义一个`FileHelper`类，其中包含一些在`test`包中难以测试的方法：

```kt
class FileHelper(private val context: Context) {
    fun getUriFromFile(file: File): Uri {
        return FileProvider.getUriForFile(context,           "com.android.testable.camera", file)
    }
    fun getPicturesFolder(): String =       Environment.DIRECTORY_PICTURES

    fun getVideosFolder(): String = Environment.DIRECTORY_MOVIES
}
```

1.  让我们在`res/xml/file_provider_paths.xml`中定义我们的`FileProvider`路径。确保在`FileProvider`中包含适当的应用程序包名称：

```kt
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <external-path name="photos" path="Android/data       /com.android.testable.camera/files/Pictures"/>
    <external-path name="videos" path="Android/data       /com.android.testable.camera/files/Movies"/>
</paths>
```

1.  让我们将文件提供程序路径添加到`AndroidManifest.xml`文件中：

```kt
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="com.android.testable.camera"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support                   .FILE_PROVIDER_PATHS"
                android:resource="@xml/file_provider_paths" />
        </provider>
```

1.  现在让我们定义一个模型，该模型将保存`Uri`和文件的关联路径：

```kt
data class FileInfo(
    val uri: Uri,
    val file: File,
    val name: String,
    val relativePath:String,
    val mimeType:String
)
```

1.  让我们创建一个`ContentHelper`类，它将为我们提供`ContentResolver`所需的数据。我们将定义两种方法来访问照片和视频内容 Uri，以及两种方法来创建`ContentValues`。我们这样做是因为获取 Uri 和创建`ContentValues`所需的静态方法使得这个功能难以测试。由于篇幅限制，以下代码已被截断。您需要添加的完整代码可以通过下面的链接找到。

```kt
MediaContentHelper.kt
7    class MediaContentHelper {
8
9        fun getImageContentUri(): Uri =
10            if (android.os.Build.VERSION.SDK_INT >=                 android.os.Build.VERSION_CODES.Q) {
11                MediaStore.Images.Media.getContentUri                     (MediaStore.VOLUME_EXTERNAL_PRIMARY)
12            } else {
13                MediaStore.Images.Media.EXTERNAL_CONTENT_URI
14            }
15
16        fun generateImageContentValues(fileInfo: FileInfo)             = ContentValues().apply {
17            this.put(MediaStore.Images.Media
                     .DISPLAY_NAME, fileInfo.name)
18        if (android.os.Build.VERSION.SDK_INT >= 
                android.os.Build.VERSION_CODES.Q) {
19                this.put(MediaStore.Images.Media                     .RELATIVE_PATH, fileInfo.relativePath)
20        }
21        this.put(MediaStore.Images.Media             .MIME_TYPE, fileInfo.mimeType)
22    }
The complete code for this step can be found at http://packt.live/3ivwekp.
```

1.  现在，让我们创建`ProviderFileManager`类，在其中我们将定义生成照片和视频文件的方法，然后由相机使用，并保存到媒体存储的方法。同样，为简洁起见，代码已被截断。请查看下面的链接以获取您需要使用的完整代码：

```kt
ProviderFileManager.kt
12    class ProviderFileManager(
13        private val context: Context,
14        private val fileHelper: FileHelper,
15        private val contentResolver: ContentResolver,
16        private val executor: Executor,
17        private val mediaContentHelper: MediaContentHelper
18    ) {
19
20        fun generatePhotoUri(time: Long): FileInfo {
21            val name = "img_$time.jpg"
22            val file = File(
23                context.getExternalFilesDir(fileHelper                     .getPicturesFolder()),
24                name
25            )
26            return FileInfo(
27                fileHelper.getUriFromFile(file),
28                file,
29                name,
30                fileHelper.getPicturesFolder(),
31                "image/jpeg"
32            )
33        }
The complete code for this step can be found at http://packt.live/2XXB9Bu.
```

请注意我们如何将根文件夹定义为`context.getExternalFilesDir(Environment.DIRECTORY_PICTURES)`和`context.getExternalFilesDir(Environment.DIRECTORY_MOVIES)`。这与`file_provider_paths.xml`相关联，并将在外部存储器上的应用程序专用文件夹中创建一组名为`Movies`和`Pictures`的文件夹。`insertToStore`方法是文件将被复制到`MediaStore`的地方。首先，我们将在存储中创建一个条目，这将为我们提供该条目的 Uri。接下来，我们将从`FileProvider`生成的 Uri 中将文件内容复制到指向`MediaStore`条目的`OutputStream`中。

1.  让我们在`res/layout/activity_main.xml`中定义我们活动的布局：

```kt
activity_main.xml
10    <Button
11        android:id="@+id/photo_button"
12        android:layout_width="wrap_content"
13        android:layout_height="wrap_content"
14        android:text="@string/photo" />
15
16    <Button
17        android:id="@+id/video_button"
18        android:layout_width="wrap_content"
19        android:layout_height="wrap_content"
20        android:layout_marginTop="5dp"
21        android:text="@string/video" />
The complete code for this step can be found at http://packt.live/3qDSyLU.
```

1.  让我们创建`MainActivity`类，我们将在其中检查是否需要请求 WRITE_STORAGE_PERMISSION，如果需要，则请求它，并在授予权限后打开相机拍摄照片或视频。与上文一样，为简洁起见，代码已被截断。您可以使用下面显示的链接访问完整的代码：

```kt
MainActivity.kt
14    class MainActivity : AppCompatActivity() {
15 
16        companion object {
17
18            private const val REQUEST_IMAGE_CAPTURE = 1
19            private const val REQUEST_VIDEO_CAPTURE = 2
20            private const val REQUEST_EXTERNAL_STORAGE = 3
21        }
22
23        private lateinit var providerFileManager:             ProviderFileManager
24        private var photoInfo: FileInfo? = null
25        private var videoInfo: FileInfo? = null
26        private var isCapturingVideo = false
27
28        override fun onCreate(savedInstanceState: Bundle?) {
29            super.onCreate(savedInstanceState)
30            setContentView(R.layout.activity_main)
31            providerFileManager =
32                ProviderFileManager(
33                    applicationContext,
34                    FileHelper(applicationContext),
35                    contentResolver,
36                    Executors.newSingleThreadExecutor(),
37                    MediaContentHelper()
38                )
The complete code for this step can be found at http://packt.live/3ivUTpm.
```

如果我们执行上述代码，我们将看到以下结果：

![图 11.9：练习 11.06 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_09.jpg)

图 11.9：练习 11.06 的输出

1.  通过点击任一按钮，您将被重定向到相机应用程序，在那里您可以拍摄照片或视频（如果您在 Android 10 及以上版本上运行示例）。如果您在较低的 Android 版本上运行，则会首先要求权限。一旦您拍摄并确认了照片，您将被带回应用程序。照片将保存在您在`FileProvider`中定义的位置：![图 11.10：通过相机应用程序捕获文件的位置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_10.jpg)

图 11.10：通过相机应用程序捕获文件的位置

在上述截图中，您可以看到借助 Android Studio 设备文件浏览器文件的位置。

1.  修改`MainActivity`并添加`onActivityResult`方法来触发文件保存到 MediaStore 的操作：

```kt
    override fun onActivityResult(requestCode: Int,       resultCode: Int, data: Intent?) {
        when (requestCode) {
            REQUEST_IMAGE_CAPTURE -> {
                providerFileManager.insertImageToStore(photoInfo)
            }
            REQUEST_VIDEO_CAPTURE -> {
                providerFileManager.insertVideoToStore(videoInfo)
            }
            else -> {
                super.onActivityResult(requestCode,                   resultCode, data)
            }
        }
    }
```

如果您打开任何文件浏览应用程序，如“文件”应用程序、画廊或 Google 照片应用程序，您将能够看到拍摄的视频和图片。

![图 11.11：应用程序中的文件在文件浏览器应用程序中的位置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_11_11.jpg)

图 11.11：应用程序中的文件在文件浏览器应用程序中的位置

## 活动 11.01：狗下载器

您的任务是构建一个针对 Android 版本高于 API 21 的应用程序，该应用程序将显示狗照片的 URL 列表。您将连接到的 URL 是 `https://dog.ceo/api/breed/hound/images/random/{number}`，其中 `number` 将通过设置屏幕控制，用户可以选择要显示的 URL 数量。设置屏幕将通过主屏幕上呈现的选项打开。当用户点击 URL 时，图像将在应用程序的外部缓存路径中本地下载。在下载图像时，用户将看到一个不确定的进度条。URL 列表将使用 Room 在本地持久化。

将使用以下技术：

+   Retrofit 用于检索 URL 列表和下载文件

+   Room 用于持久化 URL 列表

+   `SharedPreferences` 和 `PreferencesFragment` 用于存储要检索的 URL 数量

+   `FileProvider` 用于将文件存储在缓存中

+   Apache IO 用于写文件

+   组合所有数据源的存储库

+   `LiveData` 和 `ViewModel` 用于处理用户的逻辑

+   `RecyclerView` 用于项目列表

响应 JSON 将类似于这样：

```kt
{
    "message": [
        "https://images.dog.ceo/breeds/hound-          afghan/n02088094_4837.jpg",
        "https://images.dog.ceo/breeds/hound-          basset/n02088238_13908.jpg",
        "https://images.dog.ceo/breeds/hound-          ibizan/n02091244_3939.jpg"
    ],
    "status": "success"
}
```

执行以下步骤以完成此活动：

1.  创建一个包含与网络相关的类的 `api` 包。

1.  创建一个数据类，用于建模响应 JSON。

1.  创建一个 Retrofit `Service` 类，其中包含两个方法。第一个方法将代表 API 调用以返回品种列表，第二个方法将代表 API 调用以下载文件。

1.  创建一个 `storage` 包，并在 `storage` 包内创建一个 `room` 包。

1.  创建一个包含自动生成的 ID 和 URL 的 `Dog` 实体。

1.  创建一个 `DogDao` 类，其中包含插入 `Dogs` 列表、删除所有 `Dogs` 和查询所有 `Dogs` 的方法。`delete` 方法是必需的，因为 API 模型没有任何唯一标识符。

1.  在 `storage` 包内，创建一个 `preference` 包。

1.  在 `preference` 包内，创建一个围绕 `SharedPreferences` 的包装类，该类将返回我们需要使用的 URL 数量。默认值为 `10`。

1.  在 `res/xml` 中，为 `FileProvider` 定义文件夹结构。文件应保存在 `external-cache-path` 标签的根文件夹中。

1.  在 `storage` 包内创建一个 `filesystem` 包。

1.  在 `filesystem` 包内，定义一个类，负责将 `InputStream` 写入 `FileProvider` 中的文件，使用 `Context.externalCacheDir`。

1.  创建一个 `repository` 包。

1.  在 `repository` 包内，创建一个密封类，该类将保存 API 调用的结果。密封类的子类将是 `Success`、`Error` 和 `Loading`。

1.  定义一个包含两个方法的 `Repository` 接口，一个用于加载 URL 列表，另一个用于下载文件。

1.  定义一个 `DogUi` 模型类，该类将用于应用程序的 UI 层，并将在存储库中创建。

1.  定义一个映射器类，将您的 API 模型转换为实体，实体转换为 UI 模型。

1.  定义一个实现 `Repository` 的实现，该实现将实现前两个方法。存储库将持有对 `DogDao`、Retrofit `Service` 类、`Preferences` 包装类、管理文件的类、`Dog` 映射类和用于多线程的 `Executor` 类的引用。在下载文件时，我们将使用从 URL 提取的文件名。

1.  创建一个将初始化存储库的 `Application` 类。

1.  定义 UI 使用的 `ViewModel`，它将引用 `Repository` 并调用 `Repository` 加载 URL 列表和下载图片。

1.  定义您的 UI，它将由两个活动组成：

+   该活动显示 URL 列表，并将具有单击操作以开始下载。该活动将具有进度条，在下载发生时将显示。屏幕还将有一个“设置”选项，它将打开设置屏幕。

+   设置活动将显示一个设置，指示要加载的 URL 数量。

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 摘要

在本章中，我们分析了 Android 中持久化数据的不同方式，以及如何通过存储库模式将它们集中起来。我们首先看了一下模式本身，看看我们如何通过结合 Room 和 Retrofit 来组织数据源。

然后，我们继续分析了在持久化数据方面替代 Room 的选择。我们首先看了`SharedPreferences`，以及当数据以键值格式且数据量较小时，它们构成了一个方便的数据持久化解决方案。然后我们看了如何使用`SharedPreferences`直接在设备上保存数据，然后我们研究了`PreferenceFragments`以及它们如何用于接收用户输入并在本地存储。

接下来，当涉及到 Android 框架时，我们审视了一个持续变化的内容。那就是关于文件系统抽象的演变。我们首先概述了 Android 拥有的存储类型，然后更深入地研究了两种抽象：`FileProvider`，您的应用程序可以使用它在设备上存储文件，并在有需要时与他人共享；以及 SAF，它可以用于在用户选择的位置在设备上保存文件。

我们还利用了`FileProvider`的好处，为文件生成 URI，以便使用相机应用程序拍照和录制视频，并将它们保存在应用程序文件中，同时将它们添加到`MediaStore`。

本章中进行的活动结合了上述所有元素，以说明即使您必须在应用程序内部平衡多个来源，也可以以更可读的方式进行。

请注意，在本章和上一章的活动和练习中，我们一直不得不使用应用程序类来实例化数据源。在下一章中，您将学习如何通过依赖注入来克服这一问题，并了解它如何有益于 Android 应用程序。
