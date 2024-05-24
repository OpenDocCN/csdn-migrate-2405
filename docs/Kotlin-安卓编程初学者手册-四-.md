# Kotlin 安卓编程初学者手册（四）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：将我们的 Kotlin 连接到 UI 和可空性

通过本章的结束，我们的 Kotlin 代码和 XML 布局之间的缺失链接将被完全揭示，让我们有能力像以前一样向布局添加各种小部件和 UI 功能，但这一次我们将能够通过我们的代码来控制它们。

在本章中，我们将控制一些简单的 UI 元素，比如`Button`和`TextView`，在下一章中，我们将进一步操作一系列 UI 元素。

为了让我们理解发生了什么，我们需要更多地了解应用程序中的内存，特别是其中的两个区域-**堆栈**和**堆**。

在本章中，我们将涵盖以下主题：

+   Android UI 元素也是类

+   垃圾回收

+   我们的 UI 在堆上

+   更多的多态性

+   可空性- val 和 var 重新审视

+   转换为不同类型

准备让您的 UI 活起来。

# 所有的 Android UI 元素也是类

当我们的应用程序运行并且从`onCreate`函数中调用`setContentView`函数时，布局会从 XML UI 中**膨胀**，并作为可用对象加载到内存中。它们存储在内存的一个部分，称为堆。

但是这个堆在哪里？我们在代码中肯定看不到 UI 实例。我们怎么才能得到它们呢？

每个 Android 设备内部的操作系统都会为我们的应用程序分配内存。此外，它还将不同类型的变量存储在不同的位置。

我们在函数中声明和初始化的变量存储在称为堆栈的内存区域。我们已经知道如何使用简单的表达式在堆栈上操作变量。所以，让我们再谈谈堆。

### 注意

重要事实：所有类的对象都是引用类型变量，只是指向存储在堆上的实际对象的引用-它们并不是实际的对象。

把堆想象成仓库的另一个区域。堆有大量的地板空间用于奇形怪状的物体，用于较小物体的货架，以及许多长排的小尺寸隔间等。这就是对象存储的地方。问题是我们无法直接访问堆。把它想象成仓库的受限区域。你实际上不能去那里，但你可以*引用*那里存储的东西。让我们看看引用变量到底是什么。

它是一个我们通过引用引用和使用的变量。引用可以宽松地但有用地定义为地址或位置。对象的引用（地址或位置）在堆栈上。

因此，当我们使用点运算符时，我们正在要求操作系统在特定位置执行任务，这个位置存储在引用中。

### 提示

引用变量就是这样-一个引用。它们是访问和操作对象（属性和函数）的一种方式，但它们并不是实际的对象本身。

为什么我们会想要这样的系统？给我我的对象就放在堆栈上！这就是为什么。

## 快速休息一下，扔掉垃圾

整个堆栈和堆的作用是什么。

正如我们所知，操作系统会为我们跟踪所有的对象，并将它们存储在我们仓库的一个专门区域，称为堆。在我们的应用程序运行时，操作系统会定期扫描堆栈，我们仓库的常规货架，并匹配堆上的对象的引用。它发现的任何没有匹配引用的对象，都会被销毁。或者，用正确的术语来说，它进行**垃圾回收**。

想象一辆非常有洞察力的垃圾车穿过我们的堆，扫描物体以匹配参考（在堆栈上）。没有参考意味着它被垃圾回收了。

如果一个对象没有相关的引用变量，我们无法对其进行任何操作，因为我们无法访问它/引用它。垃圾收集系统通过释放未使用的内存帮助我们的应用程序更有效地运行。

如果这个任务留给我们来完成，我们的应用程序将会更加复杂。

因此，函数内声明的变量是局部的，位于堆栈上，只能在声明它们的函数内部可见。一个属性（对象的属性）位于堆上，可以在任何有引用的地方引用它，如果访问修饰符（封装）允许的话。

## 关于堆栈和堆的七个有用的事实

让我们快速看看我们对堆栈和堆学到了什么：

+   你不会删除对象，而是操作系统在认为合适的时候发送垃圾收集器。通常情况下，当对象没有活动引用时，垃圾收集器会进行清理。

+   变量位于堆栈上，只能在声明它们的特定函数内部可见。

+   属性位于堆上（与其对象/实例一起），但是对象/实例的引用（其地址）是堆栈上的局部变量。

+   我们控制着堆栈中的内容。我们可以使用堆上的对象，但只能通过引用它们。

+   堆由垃圾收集器保持清晰和最新。

+   当不再有有效引用指向对象时，对象将被垃圾收集。因此，当引用变量从堆栈中移除时，与之相关的对象就可以进行垃圾收集。当操作系统决定时机合适（通常非常迅速），它将释放 RAM 内存以避免耗尽。

+   如果我们设法引用一个不存在的对象，我们将会得到一个**NullPointerException**错误，应用程序将崩溃。Kotlin 的一个主要特性是它保护我们免受这种情况的发生。在 Kotlin 试图改进的 Java 中，**NullPointerException 错误**是应用程序崩溃的最常见原因。我们将在本章末尾附近的*Nullability –* `val` *and* `var` *revisited*部分学习更多关于 Kotlin 如何帮助我们避免**NullPointerException**错误的内容。

让我们继续看看这些信息对我们控制 UI 方面有什么帮助。

## 那么，这个堆究竟如何帮助我？

在 XML 布局中设置了`id`属性的任何 UI 元素都可以从堆中检索其引用并使用，就像我们在前两章中编写和声明自己的类一样。

如果我们使用基本活动模板创建一个项目（随意这样做，但你不需要这样做），将一个按钮拖到 UI 上，推断出约束，并在模拟器上运行应用程序。然后我们将得到下一个截图中所见的内容：

![那么，这个堆究竟如何帮助我？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_01.jpg)

这就是我们应该从前五章中已经看到的内容可以期待的。如果我们将这行代码添加到`onCreate`函数中，那么将会发生一些有趣的事情：

```kt
button.text = "WOO HOO!"
```

再次运行应用程序并观察按钮的变化：

![那么，这个堆究竟如何帮助我？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_02.jpg)

我们已经改变了按钮上的文本。

### 提示

此时，如果您之前使用 Java 编写 Android 应用程序，您可能想躺下几分钟，思考从现在开始生活将会变得多么容易。

这非常令人兴奋，因为它显示我们可以从我们的布局中获取一大堆东西的引用。然后我们可以开始使用这些对象由 Android API 提供的所有函数和属性。

代码中的`button`实例是指 XML 布局中`Button`小部件的`id`。我们代码中的`text`实例然后指的是`Button`类的`text`属性，我们代码中的`= "WOO HOO!"`文本使用了`text`属性的 setter 来改变它所持有的值。

### 提示

如果`Button`类（或其他 UI 元素）的`id`值不同，那么我们需要相应地调整我们的代码。

如果你认为在十一章之后，我们终于要开始在 Android 上做一些好玩的事情，那么你是对的！

让我们了解 OOP 的另一个方面，然后我们将能够构建迄今为止最功能强大的应用程序。

# Kotlin 接口

接口就像一个类。哦！这里没有什么复杂的。但是，它就像一个始终是抽象的类，只有抽象函数。

我们可以将接口看作是一个完全抽象的类，其所有函数和属性都是抽象的。当属性是抽象的时，它不持有值。它没有属性的后备字段。然而，当另一个类实现（使用）接口时，它必须重写属性，因此提供用于存储值的后备字段。

简而言之，接口是无状态的类。它们提供了一个没有任何数据的实现模板。

好吧，你大概能理解抽象类，因为至少它可以在其函数中传递一些功能，并在其属性中传递一些状态，这些状态不是抽象的，并且作为多态类型。

但是，说真的，这个界面似乎有点毫无意义。让我们看一个最简单的接口示例，然后我们可以进一步讨论。

定义接口，我们输入以下内容：

```kt
interface SomeInterface { 

   val someProperty: String 
   // Perhaps more properties

   fun someFunction() 
   // Perhaps more functions
   // With or without parameters
   // and return types
}
```

接口的函数没有主体，因为它们是抽象的，但它们仍然可以有返回类型和参数。

要使用接口，我们在类声明后使用相同的`:`语法：

```kt
class SomeClass() : SomeInterface{ 

   // Overriding any properties
   // is not optional
   // It is an obligation for a class
   // that uses the interface
   override val someProperty: String = "Hello" 

   override fun someFunction() { 
      // This implementation is not optional
      // It is an obligation for a class
      // that uses the interface
   } 
}
```

在前面的代码中，属性和函数已在实现接口的类中被重写。编译器强制接口的用户这样做，否则代码将无法编译。

如果您同时从一个类继承并实现一个或多个接口，那么超类就会简单地放入接口的列表中。为了清楚地表明不同的关系，惯例是将超类放在列表的第一位。然而，编译器并不要求这样做。

这使我们能够在完全不相关的继承层次结构中使用多个不同对象的多态性。如果一个类实现了一个接口，整个东西就可以被传递或用作它就像是那个东西一样，因为它就是那个东西。它是多态的（多种形式）。

我们甚至可以让一个类同时实现多个不同的接口。只需在每个接口之间添加逗号，并确保重写所有必要的函数。

在本书中，我们将更频繁地使用 Android API 的接口，而不是编写我们自己的接口。在下一节中，我们将使用`OnClickListener`接口。

许多东西可能想要在被点击时知道，比如`Button`小部件或`TextView`小部件。因此，使用接口，我们不需要为每种类型的 UI 元素单独编写不同的函数。

让我们一起看看接口在同时连接我们的 Kotlin 代码和 UI 时的作用。

# 使用按钮和 TextView 小部件从我们的布局中，借助接口的一点帮助

要跟随这个项目，创建一个新的 Android Studio 项目，将其命名为`Kotlin Meet UI`，并选择**Empty Activity**模板。您可以在`Chapter12/Kotlin Meet UI`文件夹中找到代码和 XML 布局代码。

首先，让我们通过以下步骤构建一个简单的 UI：

1.  在 Android Studio 的编辑窗口中，切换到`activity_main.xml`，确保你在**Design**选项卡上。

1.  删除自动生成的`TextView`，即那个写着“Hello world!”的。

1.  在布局的顶部中心添加一个**TextView**小部件。

1.  将其**text**属性设置为`0`，其`id`属性设置为`txtValue`，其`textSize`设置为`40sp`。请特别注意`id`值的大小写。它的`V`是大写的。

1.  现在，将六个按钮拖放到布局上，使其看起来有点像下面的图表。确切的布局并不重要：![使用按钮和 TextView 小部件从我们的布局中，借助接口的一点帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_03.jpg)

1.  当布局达到您想要的效果时，单击**Infer Constraints**按钮以约束所有 UI 项。

1.  依次双击每个按钮（从左到右，然后从上到下），并设置`text`和`id`属性，如下表所示：

| `text`属性 | `id`属性 |
| --- | --- |
| `add` | `btnAdd` |
| `take` | `btnTake` |
| `grow` | `btnGrow` |
| `shrink` | `btnShrink` |
| `hide` | `btnHide` |
| `reset` | `btnReset` |

完成后，您的布局应如下屏幕截图所示：

![使用按钮和 TextView 小部件从我们的布局中，借助接口的一点帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_04.jpg)

按钮上的精确位置和文本并不是非常重要，但是给`id`属性赋予的值必须相同。原因是我们将使用这些`id`值从我们的 Kotlin 代码中获取对此布局中的`Button`实例和`TextView`实例的引用。

切换到编辑器中的**MainActivity.kt**选项卡，并找到以下行：

```kt
class MainActivity : AppCompatActivity(){
```

现在将代码行修改为以下内容：

```kt
class MainActivity : AppCompatActivity,
   View.OnClickListener{
```

在输入时，将会弹出一个列表，询问您要选择要实现的接口。选择**OnClickListener (android.view.view)**，如下一屏幕截图所示：

![使用按钮和 TextView 小部件从我们的布局中，借助接口的一点帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_05.jpg)

### 提示

您需要导入`View`类。确保在继续下一步之前执行此操作，否则将会得到混乱的结果：

```kt
import android.view.View
```

注意到`MainActivity`声明被红色下划线标出，显示出错误。现在，因为我们已经将`MainActivity`添加为接口`OnClickListener`，我们必须实现`OnClickListener`的抽象函数。该函数称为`onClick`。当我们添加该函数时，错误将消失。

我们可以通过在包含错误的代码上任意左键单击，然后使用键盘组合*Alt* +*Enter*来让 Android Studio 为我们添加。左键单击**Implement members**，如下一屏幕截图所示：

![使用按钮和 TextView 小部件从我们的布局中，借助接口的一点帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_06.jpg)

现在，左键单击**OK**以确认我们希望 Android Studio 添加`onClick`方法/函数。错误已经消失，我们可以继续添加代码。我们还有一个`onClick`函数，很快我们将看到我们将如何使用它。

### 注意

术语上的一个快速说明。**方法**是在类中实现的函数。Kotlin 允许程序员独立于类实现函数，因此所有方法都是函数，但并非所有函数都是方法。我选择在本书中始终将所有方法称为函数。有人认为方法可能是一个更精确的术语，但在本书的上下文中，两者都是正确的。如果您愿意，可以将类中的函数称为方法。

现在，在类声明内部但在任何函数之外/之前添加以下属性：

```kt
class MainActivity : AppCompatActivity(), View.OnClickListener {

 // An Int property to hold a value
 private var value = 0

```

我们声明了一个名为`value`的`Int`属性，并将其初始化为`0`。请注意，它是一个`var`属性，因为我们需要更改它。

接下来，在`onCreate`函数内，添加以下六行代码：

```kt
// Listen for all the button clicks
btnAdd.setOnClickListener(this)
btnTake.setOnClickListener(this)
txtValue.setOnClickListener(this)
btnGrow.setOnClickListener(this)
btnShrink.setOnClickListener(this)
btnReset.setOnClickListener(this)
btnHide.setOnClickListener(this)
```

### 提示

使用*Alt* +*Enter*键组合从`activity_main.xml`布局文件中导入所有`Button`和`TextView`实例。或者，手动添加以下导入语句：

```kt
import kotlinx.android.synthetic.main.activity_main.* 
```

上述代码设置了我们的应用程序以侦听布局中按钮的点击。每行代码都执行相同的操作，但是在不同的按钮上。例如，`btnAdd`指的是我们布局中`id`属性值为`btnAdd`的按钮，`btnTake`指的是我们布局中`id`属性值为`btnTake`的按钮。

然后每个按钮实例调用自身的`setOnClickListener`函数。传入的参数是`this`。从第十章中记住，*面向对象编程*，`this`指的是代码所在的当前类。因此，在前面的代码中，`this`指的是`MainActivity`。

`setOnClickListener`函数设置我们的应用程序调用`OnClickListener`接口的`onClick`函数。现在，每当我们的按钮之一被点击，`onClick`函数将被调用。所有这些都是因为`MainActivity`实现了`OnClickListener`接口。

如果你想验证这一点，暂时从类声明的末尾删除`View.OnClickListener`代码，我们的代码将突然充满一片红色的错误。这是因为`this`不再是`OnCLickListener`类型，因此无法传递给各个按钮的`setOnClickListener`函数，`onClick`函数也会显示错误，因为编译器不知道我们试图覆盖什么。接口是使所有这些功能结合在一起的关键。

### 提示

如果之前删除了`View.OnClickListener`，请在类声明的末尾替换它。

现在，滚动到 Android Studio 在我们实现`OnClickListener`接口后添加的`onClick`函数。添加`Float size`变量声明和一个空的`when`块，使其看起来像下面的代码。要添加的新代码已经突出显示。在下一个代码中还有一件事需要注意和实现。当`onClick`函数由 Android Studio 自动生成时，在`v: View?`参数后添加了一个问号。删除问号，如下面的代码所示：

```kt
override fun onClick(v: View) {
 // A local variable to use later
 val size: Float

 when (v.id) {

 }
}
```

记住，`when`将检查匹配表达式的值。`when`条件是`v.id`。`v`变量被传递给`onClick`函数，`v.id`标识了被点击的按钮的`id`属性。它将匹配布局中我们按钮的`id`。

### 注意

如果你对我们删除的那个奇怪的问号感到好奇，它将在下一节中解释：*可空性——val 和 var 重新讨论*。

接下来我们需要处理每个按钮的操作。将下面的代码块添加到`when`表达式的大括号内，然后我们将讨论它。首先尝试自己解决代码，你会惊讶地发现我们已经理解了多少。

```kt
R.id.btnAdd -> {
   value++
   txtValue.text = "$value"
}

R.id.btnTake -> {
   value--
   txtValue.text = "$value"
}

R.id.btnReset -> {
   value = 0
   txtValue.text = "$value"
}

R.id.btnGrow -> {
   size = txtValue.textScaleX
   txtValue.textScaleX = size + 1
}

R.id.btnShrink -> {
   size = txtValue.textScaleX
   txtValue.textScaleX = size - 1
}

R.id.btnHide -> 
   if (txtValue.visibility 
            == View.VISIBLE) {
   // Currently visible so hide it
   txtValue.visibility = View.INVISIBLE

   // Change text on the button
   btnHide.text = "SHOW"

} else {
   // Currently hidden so show it
   txtValue.visibility = View.VISIBLE

   // Change text on the button
   btnHide.text = "HIDE"
}
```

以下是代码的第一行：

```kt
override fun onClick(v: View) {
```

`View`是`Button`、`TextView`等的父类。因此，也许正如我们所期望的那样，使用`v.id`将返回被点击的 UI 小部件的`id`属性，并触发首次调用`onClick`。

接下来，我们需要为我们想要响应的每个`Button` id 值提供一个`when`语句（和一个适当的操作）。以下是代码的一部分，以供您参考：

```kt
when (v.id) {

}
```

再看一下代码的下一部分：

```kt
R.id.btnAdd -> {
   value++
   txtValue.text = "$value"
}

R.id.btnTake -> {
   value--
   txtValue.text = "$value"
}

R.id.btnReset -> {
   value = 0
   txtValue.text = "$value"
}
```

前面的代码是前三个`when`分支。它们处理`R.id.btnAdd`、`R.id.btnTake`和`R.id.btnReset`。

`R.id.btnAdd`分支中的代码简单地增加了`value`变量，然后做了一些新的事情。

它设置了`txtValue`对象的`text`属性。这样做的效果是使这个`TextView`显示存储在`value`中的任何值。

**TAKE**按钮（`R.id.btnTake`）做的事情完全相同，只是从`value`中减去 1，而不是加 1。

`when`语句的第三个分支处理**RESET**按钮，将`value`设置为零，并再次更新`txtValue`的`text`属性。

在执行任何`when`分支的末尾，整个`when`块都会退出，`onClick`函数返回，生活恢复正常——直到用户的下一次点击。

让我们继续检查`when`块的下两个分支。以下是为了方便您再次查看：

```kt
R.id.btnGrow -> {
   size = txtValue.textScaleX
   txtValue.textScaleX = size + 1
}

R.id.btnShrink -> {
   size = txtValue.textScaleX
   txtValue.textScaleX = size - 1
}
```

接下来的两个分支处理我们 UI 中的**SHRINK**和**GROW**按钮。我们可以从 id 的`R.id.btnGrow`值和`R.id.btnShrink`值确认这一点。新的更有趣的是`TextView`类的 getter 和 setter 在按钮上使用。

`textScaleX`属性的 getter 返回所使用对象中文本的水平比例。我们可以看到它所使用的对象是我们的`TextView txtValue`实例。代码`size =`在代码行的开头将返回的值分配给我们的`Float`变量`size`。

每个`when`分支中的下一行代码使用`textScaleX`属性的 setter 来改变文本的水平比例。当按下**GROW**按钮时，比例设置为`size + 1`，当按下**SHRINK**按钮时，比例设置为`size - 1`。

总体效果是允许这两个按钮通过每次点击来放大和缩小`txtValue`中的文本，比例为`1`。

让我们看一下`when`代码的最后一个分支。以下是为了方便您再次查看：

```kt
R.id.btnHide -> 
   if (txtValue.visibility == View.VISIBLE) {
      // Currently visible so hide it
      txtValue.visibility = View.INVISIBLE

      // Change text on the button
      btnHide.text = "SHOW"

   } else {
      // Currently hidden so show it
      txtValue.visibility = View.VISIBLE

      // Change text on the button
      btnHide.text = "HIDE"
   }
```

前面的代码需要一点解释，所以让我们一步一步来。首先，在`when`分支内嵌套了一个`if`-`else`表达式。以下是`if`部分：

```kt
if (txtValue.visibility == View.VISIBLE)
```

要评估的条件是`txtValue.visibility == View.VISIBLE`。在`==`运算符之前的部分使用`visibility`属性的 getter 返回描述`TextView`当前是否可见的值。返回值将是`View`类中定义的三个可能的常量值之一。它们是`View.VISIBLE`，`View.INVISIBLE`和`View.GONE`。

如果`TextView`在 UI 上对用户可见，则 getter 返回`View.VISIBLE`，条件被评估为`true`，并且执行`if`块。

在`if`块内，我们使用`visibility`属性的 setter 将其对用户不可见，使用`View.INVISIBLE`值。

除此之外，我们使用`text`属性的 setter 将`btnHide`对象上的文本更改为**SHOW**。

在`if`块执行后，`txtValue`将不可见，并且我们的 UI 上有一个按钮显示**SHOW**。当用户在这种状态下点击它时，`if`语句将为 false，`else`块将执行。在`else`块中，我们将情况反转。我们将`txtValue`对象的`visibility`属性设置回`View.VISIBLE`，并将`btnHide`上的`text`属性设置回**HIDE**。

如果有任何不清楚的地方，只需输入代码，运行应用程序，然后在看到它实际运行后再回顾一下最后的代码和解释。

我们已经准备好 UI 和代码，现在是时候运行应用程序并尝试所有按钮了。请注意，**ADD**和**TAKE**按钮会分别将`value`的值增加或减少一，并在`TextView`中显示结果。在下一张图片中，我点击了**ADD**按钮三次：

![使用按钮和 TextView 小部件从我们的布局中获得帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_07.jpg)

请注意，**SHRINK**和**GROW**按钮增加了文本的宽度，**RESET**将`value`变量设置为零，并在`TextView`上显示它。在下面的截图中，我点击了**GROW**按钮八次：

![使用按钮和 TextView 小部件从我们的布局中获得帮助](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_08.jpg)

最后，**HIDE**按钮不仅隐藏`TextView`，还将其自身文本更改为**SHOW**，如果再次点击，则确实会重新显示`TextView`。

### 提示

我不会打扰你，向你展示一个隐藏的东西的图片。一定要在模拟器中尝试该应用，并跟着书本一起学习。如果你想知道`View.INVISIBLE`和`View.GONE`之间的区别，`INVISIBLE`只是隐藏了对象，但当使用`GONE`时，布局的行为就好像对象从未存在过一样，因此可能会影响剩余 UI 的布局。将代码行从`INVISIBLE`更改为`GONE`，并运行应用程序以观察差异。

请注意，在这个应用程序中不需要`Log`或`Toast`，因为我们最终是使用我们的 Kotlin 代码来操作 UI。

# 可空性 - val 和 var 重温

当我们用`val`声明一个类的实例时，并不意味着我们不能改变属性中保存的值。决定我们是否可以重新分配属性中保存的值的是属性本身是`val`还是`var`。

当我们用`val`声明一个类的实例时，这只意味着我们不能重新分配另一个实例给它。当我们想要重新分配一个实例时，我们必须用`var`声明它。以下是一些例子：

```kt
val someInstance = SomeClass()
someInstance.someMutableProperty = 1// This was declared as var
someInstance.someMutableProperty = 2// So we can change it

someInstance.someImutableProperty = 1
// This was declared with val. ERROR!
```

在前面的假设代码中，声明了一个名为`someInstance`的实例，它是`SomeClass`类型。它被声明为`val`。接下来的三行代码表明，如果它的属性被声明为`var`，我们可以更改这些属性，但是，正如我们已经学到的，当属性被声明为`val`时，我们不能更改它。那么，用`val`或`var`声明一个实例到底意味着什么？看看下面的假设代码：

```kt
// Continued from previous code
// Three more instances of the same class
val someInstance2 = SomeClass() // Immutable
val someInstance3 = SomeClass()// Immutable
var someInstance4 = SomeClass() // Mutable

// Let's change these instances around— or try to
someInstance = someInstance2 
// Error cannot reassign, someInstance is immutable

someInstance2 = someInstance3 // Error someInstance2 is immutable
someInstance3 = someInstance4 // Error someInstance3 is immutable

// However,
someInstance4 = someInstance 
// No problem! someInstance4 and someInstance are now the
// same object— refer to the same object on the heap

// Sometime in the future…
someInstance4 = someInstance3 // No problem
// Sometime in the future…
someInstance4 = someInstance2 // No problem
// Sometime in the future…
// I need a new SomeClass instance

someInstance4 = SomeClass() // No problem
// someInstance4 now uniquely refers 
// to a new object on the heap
```

前面的代码清楚地表明，当一个实例是`val`时，它不能被重新分配到堆上的另一个对象，但当它是`var`时可以。实例是`val`还是`var`并不影响其属性是`val`还是`var`。

我们已经学到，当讨论属性时，如果我们不需要改变一个值，最好的做法是声明为`val`。对于对象/实例也是如此。如果我们不需要重新分配一个实例，我们应该将其声明为`val`。

## 空对象

当我们将对象或属性声明为`var`时，我们有选择不立即初始化它，有时这正是我们需要的。当我们不初始化一个对象时，它被称为**空引用**，因为它不指向任何东西。我们经常需要声明一个对象，但直到我们的应用程序运行时才初始化它，但这可能会引起问题。看看更多的假设代码：

```kt
var someInstance5: SomeClass
someInstance5.someMutableProperty = 3
```

在前面的代码中，我们声明了一个名为`someInstance5`的`SomeClass`的新实例，但我们没有初始化它。现在，看看这个截图，看看当我们在初始化之前尝试使用这个实例时会发生什么：

![空对象](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_12_09.jpg)

编译器不允许我们这样做。当我们需要在程序执行期间初始化一个实例时，我们必须明确地将其初始化为`null`，以便编译器知道这是有意的。此外，当我们将实例初始化为`null`时，我们必须使用**可空运算符**。看看下一个修复刚才问题的假设代码：

```kt
var someInstance5: SomeClass? = null
```

在前面的代码中，可空运算符用在`SomeClass?`类型的末尾，并且实例被初始化为`null`。当我们使用可空运算符时，我们可以将实例视为不同的类型 - *SomeClass 可空*，而不仅仅是*SomeClass*。

然后，我们可以在代码中需要的时候初始化实例。我们将在第十四章中看到一些真实的例子，*Android 对话框窗口*，以及本书的其余部分，但现在，这是我们可能有条件地初始化这个空对象的一种假设方式：

```kt
var someBoolean = true
// Program execution or user input might change 
// the value of someBoolean 

if(someBoolean) {
   someInstance5 = someInstance
}else{
   someInstance5 = someInstance2
}
```

然后，我们可以像平常一样使用`someInstance5`。

### 安全调用运算符

有时我们需要更灵活性。假设我们需要`someInstance5`中一个属性的值，但无法保证它已经初始化？在这种情况下，我们可以使用**安全调用**`?`运算符：

```kt
val someInt = someInstance5?.someImmutableProperty
```

在前面的代码中，如果`someInstance5`已经初始化，则将使用`someImmutable`属性中存储的值来初始化`someInt`。如果尚未初始化，则`someInt`将被初始化为 null。因此，请注意，`someInt`被推断为可空类型`Int`，而不是普通的`Int`。

### 非空断言

会出现一些情况，我们无法在编译时保证实例已初始化，并且无法让编译器相信它会被初始化。在这种情况下，我们必须使用**非空断言**`!!`运算符来断言对象不为空。考虑以下代码：

```kt
val someBoolean = true
if(someBoolean) {
   someInstance5 = someInstance
}

someInstance5!!.someMutableProperty = 3
```

在前面的代码中，`someInstance5`可能尚未初始化，我们使用了非空断言运算符，否则代码将无法编译。

还要注意，如果我们编写了一些错误的逻辑，并且在使用时实例仍然为空，那么应用程序将崩溃。实际上，应尽量少地使用`!!`运算符，而应优先使用安全调用运算符。

## 回顾空值性

空值性还有更多内容，我们还没有涵盖到。讨论不同运算符的不同用法可能需要写很多页，而且还有更多的运算符。关键是，Kotlin 旨在帮助我们尽可能避免由于空对象而导致的崩溃。然而，看到可空类型、安全调用运算符和非空断言运算符的实际应用要比理论更有教育意义。在本书的其余部分中，我们将经常遇到这三种情况，希望它们的上下文会比它们的理论更有教育意义。

# 总结

在本章中，我们最终在代码和 UI 之间有了一些真正的交互。原来，每当我们向 UI 添加一个小部件时，我们都在添加一个我们可以在代码中引用的类的 Kotlin 实例。所有这些对象都存储在一个称为堆的内存区域中，与我们自己的类的任何实例一起。

现在我们已经可以学习并使用一些更有趣的小部件。我们将在下一章第十三章中看到很多这样的小部件，*给 Android 小部件赋予生命*，并且在本书的其余部分中我们还将继续介绍新的小部件。


# 第十三章：让 Android 小部件活起来

现在我们对 Android 应用的布局和编码有了很好的概述，以及我们对面向对象编程（OOP）的新见解以及如何从 Kotlin 代码中操作 UI，我们准备从 Android Studio 调色板中尝试更多的小部件。

有时，面向对象编程是一件棘手的事情，本章介绍了一些对初学者来说可能很尴尬的话题。然而，通过逐渐学习这些新概念并反复练习，它们将随着时间成为我们的朋友。

在本章中，我们将通过回到 Android Studio 调色板并查看半打小部件来扩大范围，这些小部件我们要么根本没有见过，要么还没有完全使用过。

一旦我们这样做了，我们将把它们全部放入布局，并练习用我们的 Kotlin 代码操纵它们。

在本章中，我们将涵盖以下主题：

+   刷新我们对声明和初始化布局小部件的记忆

+   看看如何只用 Kotlin 代码创建小部件

+   看看`EditText`，`ImageView`，`RadioButton`（和`RadioGroup`），`Switch`，`CheckBox`和`TextClock`小部件

+   学习如何使用 lambda 表达式

+   使用所有前述小部件和大量 lambda 表达式制作小部件演示迷你应用程序

让我们先快速回顾一下。

# 声明和初始化来自布局的对象

我们知道当我们在`onCreate`函数中调用`setContentView`时，Android 会膨胀所有小部件和布局，并将它们转换为堆上的*真实*实例。

我们知道要使用来自堆的小部件，我们必须具有正确类型的对象，通过其唯一的`id`属性。有时，我们必须明确从布局中获取小部件。例如，要获取具有`id`属性`txtTitle`并将其分配给一个名为`myTextView`的新对象的`TextView`类的引用，我们可以这样做：

```kt
// Grab a reference to an object on the Heap
val myTextView = findViewById<TextView>(R.id.txtTitle)
```

`myTextView`实例声明的左侧应该对前三章中声明的其他类的实例都很熟悉。这里的新东西是我们依赖函数的返回值来提供实例。`findViewById`函数确实返回在膨胀布局时在堆上创建的实例。所需的实例由与布局中小部件的`id`属性匹配的函数参数标识。看起来奇怪的`<TextView>`语法是`TextView`的**转换**，因为函数返回超类类型`View`。

现在，使用我们的`myTextView`实例变量，我们可以做任何`TextView`类设计的事情；例如，我们可以设置文本如下所示：

```kt
myTextView.text = "Hi there"
```

然后，我们可以让它消失，就像这样：

```kt
// Bye bye
myTextView.visibility = View.GONE
```

现在再次更改其文本并使其重新出现，如下所示：

```kt
myTextView.text = "BOO!"

// Surprise
myTextView.visibility = View.VISIBLE
```

值得一提的是，我们可以在 Kotlin 中操纵任何在以前章节中使用 XML 代码设置的属性。此外，我们已经暗示过，但实际上还没有看到，我们可以只使用代码从无中创建小部件。

# 从纯 Kotlin 创建 UI 小部件而不使用 XML

我们还可以从不是指向布局中对象的 Kotlin 对象创建小部件。我们可以在代码中声明、实例化和设置小部件的属性，如下所示：

```kt
Val myButton = Button()
```

上述代码创建了一个新的`Button`实例。唯一的注意事项是`Button`实例必须是布局的一部分，才能被用户看到。因此，我们可以通过与以前使用`findViewById`函数相同的方式从 XML 布局中获取对布局元素的引用，或者可以在代码中创建一个新的布局。

假设我们的 XML 中有一个`id`属性等于`linearLayout1`的`LinearLayout`，我们可以将前一行代码中的`Button`实例合并到其中，如下所示：

```kt
// Get a reference to the LinearLayout
val linearLayout = 
   findViewById<LinearLayout>(R.id.linearLayout)

// Add our Button to it
linearLayout.addView(myButton)
```

我们甚至可以通过首先创建一个新布局，然后添加所有我们想要添加的小部件，最后在具有所需小部件的布局上调用`setContentView`来纯粹使用 Kotlin 代码创建整个布局。

在下面的代码片段中，我们使用纯 Kotlin 创建了一个布局，尽管它非常简单，只有一个`LinearLayout`内部有一个`Button`实例：

```kt
// Create a new LinearLayout
val linearLayout = LinearLayout()

// Create a new Button
val myButton = Button()

// Add myButton to the LinearLayout
linearLayout.addView(myButton)

// Make the LinearLayout the main view of the app
setContentView(linearLayout)
```

这可能是显而易见的，但仍然值得一提的是，仅使用 Kotlin 设计详细和微妙的布局会更加麻烦，更难以可视化，而且不是最常见的方式。然而，有时我们会发现以这种方式做事情是有用的。

现在我们已经相当高级了，涉及到布局和小部件。然而，很明显，调色板中还有许多其他小部件（和 UI 元素）我们尚未探索或交互（除了将它们放在布局中并没有做任何处理）；所以，让我们解决这个问题。

# 探索调色板-第一部分

让我们快速浏览一下调色板中以前未探索和未使用的项目，然后我们可以将其中一些拖放到布局中，看看它们可能具有的有用功能。然后我们可以实现一个项目来利用它们。

我们已经在上一章中探索了`Button`和`TextView`。现在让我们更仔细地看看它们旁边的一些小部件。

## EditText 小部件

`EditText`小部件就像其名称所示。如果我们向用户提供`EditText`小部件，他们确实可以编辑其中的文本。我们在早期章节中看到了这一点，但我们并没有做任何处理。我们没有看到的是如何捕获其中的信息，或者我们可以在哪里输入这个捕获文本的代码。

代码的下一个块假设我们已经声明了一个类型为`EditText`的对象，并使用它来获取 XML 布局中`EditText`小部件的引用。我们可能会为按钮点击编写类似以下代码的内容，也许是表单的“提交”按钮，但它可以放在我们应用程序中认为必要的任何地方：

```kt
val editTextContents = editText.text
// editTextContents now contains whatever the user entered
```

我们将在下一个应用程序中看到`EditText`小部件的真实情境。

## ImageView 小部件

到目前为止，我们已经在布局上放置了几次图像，但在代码中我们还没有引用过它，也没有做任何处理。获取`ImageView`小部件的引用的过程与获取其他小部件的引用相同：

1.  声明一个对象。

1.  使用`findViewById`函数和有效的`id`属性获取引用，如下所示：

```kt
val imageView = findViewById<ImageView>(R.id.imageView)
```

然后，我们可以使用类似以下的代码对图像进行一些有趣的操作：

```kt
// Make the image 50% TRANSPARENT
imageView.alpha = .5f
```

### 注意

看起来奇怪的`f`值只是让编译器知道该值是`Float`类型，这是`alpha`属性所需的。

在前面的代码中，我们使用了`imageView`的`alpha`属性。`alpha`属性需要一个介于 0 和 1 之间的值。0 表示完全透明，而 1 表示完全不透明。我们将在下一个应用程序中使用`ImageView`的一些功能。

## RadioButtons 和 RadioGroups

当用户需要从两个或多个互斥的选项中进行选择时，使用`RadioButton`小部件。这意味着选择一个选项时，其他选项将不被选择；就像在老式收音机上一样。请看下面截图中带有几个`RadioButton`小部件的简单`RadioGroup`小部件：

![RadioButtons and RadioGroups](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_01.jpg)

当用户做出选择时，其他选项将自动取消选择。我们通过将`RadioButton`小部件放置在 UI 布局中的`RadioGroup`小部件中来控制`RadioButton`小部件。当然，我们可以使用可视化设计工具简单地将一堆`RadioButtons`拖放到`RadioGroup`上。这样做时，XML 代码将如下所示：

```kt
<RadioGroup
   android:layout_width="match_parent"
   android:layout_height="match_parent"
   android:layout_alignParentTop="true"
   android:layout_alignParentLeft="true"
   android:layout_alignParentStart="true"
   android:id="@+id/radioGroup">

   <RadioButton
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:text="Option 1"
         android:id="@+id/radioButton1"
         android:checked="true" />

   <RadioButton
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:text="Option 2"
         android:id="@+id/radioButton2"
         android:checked="false" />

   <RadioButton
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:text="Option 3"
         android:id="@+id/radioButton3"
         android:checked="false" />

<RadioGroup/>
```

请注意，正如前面的代码所强调的，每个`RadioButton`小部件和`RadioGroup`小部件都设置了适当的`id`属性。然后我们可以像预期的那样引用它们，如下面的代码所示：

```kt
// Get a reference to all our widgets
val radioGroup = 
   findViewById<RadioGroup>(R.id.radioGroup)

val rb1 = 
   findViewById<RadioButton>(R.id.radioButton1)

val rb2 = 
   findViewById<RadioButton> R.id.radioButton2)

val rb3 = 
   findViewById<RadioButton>(R.id.radioButton3)
```

然而，在实践中，我们几乎可以仅通过`RadioGroup`的引用来管理所有事情。

你可能会想知道他们何时被点击，或者跟踪哪一个被选中可能会很麻烦？我们需要一些来自 Android API 和 Kotlin 的帮助，以**lambda**的形式。

# Lambda

当`RadioButton`小部件是`RadioGroup`的一部分时，它们的视觉外观会被协调。我们所需要做的就是在任何给定的`RadioButton`小部件被按下时做出反应。当然，与任何其他按钮一样，我们需要知道它们何时被点击。

`RadioButton`小部件的行为与常规的`Button`小部件不同，只是在`onClick`中监听点击（在实现`OnClickListener`之后）是行不通的，因为`RadioButton`类不是设计成那样的。

我们需要做的是使用另一个 Kotlin 特性。我们需要一个特殊接口的实例，唯一的目的是监听`RadioGroup`上的点击。下面的代码块假设我们有一个名为`radioGroup`的`RadioGroup`实例的引用；以下是要检查的代码：

```kt
radioGroup.setOnCheckedChangeListener {
   group, checkedId ->
   // Handle the clicks here
}
```

前面的代码，特别是从其开头的大括号（`{`）到结束的大括号（`}`）的`setOnChekedChangeListener`，被称为 lambda。

Lambda 是一个广泛的话题，随着我们的进展，它们将进一步探讨。它们在 Kotlin 中用于避免不必要的输入。编译器知道`setOnCheckedChangeListener`需要一个特殊的接口作为参数，并在幕后为我们处理这个问题。此外，编译器知道该接口有一个我们必须重写的抽象函数。在大括号的开头和结尾之间的代码是我们实现函数的地方。看起来奇怪的`group, checkedId ->`参数是这个函数的参数。

为了进一步讨论的目的，假设前面的代码是在`onCreate`函数中编写的。请注意，当调用`onCreate`时，大括号内的代码不会运行；它只是准备好实例（`radioGroup`），以便它准备好处理任何点击。我们现在将更详细地讨论这一点。

### 注意

这个看不见的接口被称为**匿名**类。

我们正在向`radioGroup`添加一个监听器，这与我们在第十二章中实现`View.OnClickListener`的效果是非常相似的，只是这一次，我们声明并实例化了一个监听器接口，并准备让它监听`radioGroup`，同时重写所需的函数，这种情况下（虽然我们看不到名称），是`onCheckedChanged`。这就像`RadioGroup`中的`onClick`等效。

如果我们使用上面的代码来创建和实例化一个类，监听我们的`RadioGroup`的点击，在`onCreate`函数中，它将在整个 Activity 的生命周期内监听和响应。现在我们需要学习的是如何在我们重写的`onCheckedChanged`函数中处理点击。

### 提示

有些学生觉得前面的代码很简单，而其他人觉得有点压力山大。这并不是决定你如何看待它的智力水平的指标，而是你的大脑喜欢学习的方式。你可以用两种方式来处理本章的信息：

接受代码的工作，继续前进，并在以后的编程生涯中重新审视事物的工作原理。

坚持成为本章主题的专家，并在继续前进之前花费大量时间来掌握它们。

我强烈推荐选项 1。有些主题在理解其他主题之前是无法掌握的。但是，当你需要先介绍前者才能继续后者时，问题就会出现。如果你坚持要时刻完全掌握，问题就会变得循环和无法解决。有时，重要的是要接受表面下还有更多。如果你能简单地接受我们刚刚看到的代码确实在幕后起作用，并且花括号内的代码是单击单选按钮时发生的事情；那么，你就准备好继续了。现在你可以去搜索 lambda 表达式；但是，要准备好花费很多时间来学习理论。在本章和整本书中，我们将重点关注实际应用，再次讨论 lambda 表达式。

## 编写重写函数的代码

请注意，当`radioGroup`实例被按下时传入此函数的一个参数是`checkedId`。此参数是一个`Int`类型，并且它保存当前选定的`RadioButton`的`id`属性。这几乎正是我们需要的。

也许令人惊讶的是，`checkedId`是一个`Int`类型。即使我们用字母数字字符声明它们，如`radioButton1`或`radioGroup`，Android 也将所有 ID 存储为`Int`。

当应用程序编译时，所有我们熟悉的人性化名称都会转换为`Int`。那么，我们怎么知道`Int`类型是指`radioButton1`或`radioButton2`这样的 ID 呢？

我们需要做的是获取`Int`类型作为 ID 的实际对象的引用，使用`Int id`属性，然后询问对象其人性化的`id`值。我们将这样做：

```kt
val rb = group.findViewById<RadioButton>(checkedId)
```

现在我们可以使用`rb`中存储的引用来检索我们熟悉的`id`属性，该属性用于当前选定的`RadioButton`小部件，使用`id`属性的 getter 函数，如下所示：

```kt
rb.id
```

因此，我们可以通过使用`when`块处理`RadioButton`的点击，每个可能被按下的`RadioButton`都有一个分支，`rb.id`作为条件。

以下代码显示了我们刚刚讨论的`onCheckedChanged`函数的全部内容：

```kt
// Get a reference to the RadioButton 
// that is currently checked
val rb = group.findViewById<RadioButton>(checkedId)

// branch the code based on the 'friendly' id
when (rb.id) {

   R.id.radioButton1->
          // Do something here

   R.id.radioButton2->
          // Do something here

   R.id.radioButton3->
          // Do something here

}
// End when block
```

在下一个工作迷你应用程序中看到这一点的实际效果，我们可以按下按钮，这将使情况更加清晰。

让我们继续探索调色板。

# 探索调色板-第二部分，以及更多的 lambda。

现在我们已经看到了 lambda 和匿名类和接口如何工作，特别是与`RadioGroup`和`RadioButton`一起，我们现在可以继续探索调色板，并查看如何使用更多的 UI 小部件。

## `Switch`小部件

`Switch`小部件就像`Button`小部件一样，只是它有两个固定的状态，可以读取和响应。

`Switch`小部件的一个明显用途是显示和隐藏某些内容。还记得我们在第十二章的 Kotlin Meet UI 应用程序中使用`Button`来显示和隐藏`TextView`小部件吗？

每次我们隐藏或显示`TextView`小部件时，我们都会更改`Button`上的`text`属性，以表明如果再次单击它会发生什么。对于用户来说，以及对于我们作为程序员来说，更直观的做法可能是使用`Switch`小部件，如下面的屏幕截图所示：

![Switch 小部件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_02.jpg)

以下代码假设我们已经有一个名为`mySwitch`的对象，它是布局中`Switch`对象的引用。我们可以像在第十二章中的*Kotlin Meet UI*应用程序中那样显示和隐藏`TextView`小部件。

监听并响应点击/切换，我们再次使用匿名类。然而，这次我们使用`CompoundButton`版本的`OnCheckedChangeListener`。与之前一样，这些细节是推断出来的，我们可以使用非常类似和简单的代码，就像处理单选按钮小部件时一样。

我们需要重写`onCheckedChanged`函数，该函数有一个`Boolean`参数`isChecked`。`isChecked`变量对于关闭是 false，对于打开是 true。

这是我们可以更直观地通过隐藏或显示代码来替换这段文字的方法：

```kt
mySwitch.setOnCheckedChangeListener{
   buttonView, isChecked->
      if(isChecked){
            // Currently visible so hide it
            txtValue.visibility = View.INVISIBLE

      }else{
            // Currently hidden so show it
            txtValue.visibility = View.VISIBLE
      }
}
```

如果匿名类或 lambda 代码看起来有点奇怪，不要担心，因为随着我们的使用，它会变得更加熟悉。现在我们再次看看`CheckBox`时，我们将这样做。

## 复选框小部件

使用`CheckBox`小部件，我们只需在特定时刻（例如在单击特定按钮时）检测其状态（选中或未选中）。以下代码让我们可以看到这可能会发生的情况，再次使用匿名类和 lambda 作为监听器：

```kt
myCheckBox.setOnCheckedChangeListener{   
   buttonView, isChecked->

   if (myCheckBox.isChecked) {
         // It's checked so do something
   } else {
         // It's not checked do something else
   }    
}
```

在先前的代码中，我们假设`myCheckBox`已经被声明和初始化，然后使用与我们用于`Switch`相同类型的匿名类来检测和响应点击。

## TextClock 小部件

在我们的下一个应用程序中，我们将使用`TextClock`小部件展示一些其特性。由于这个小部件无法从调色板中拖放，我们需要直接将 XML 代码添加到布局中。这就是`TextClock`小部件的样子：

![TextClock 小部件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_03.jpg)

作为使用`TextClock`的示例，这是我们将如何将其时间设置为与欧洲布鲁塞尔相同的时间：

```kt
tClock.timeZone = "Europe/Brussels"
```

先前的代码假设`tClock`是布局中`TextClock`小部件的引用。

有了所有这些额外的信息，让我们制作一个应用程序，比我们迄今为止所做的更实用地使用 Android 小部件。

# 小部件探索应用程序

我们刚刚讨论了六个小部件——`EditText`、`ImageView`、`RadioButton`（和`RadioGroup`）、`Switch`、`CheckBox`和`TextClock`。让我们制作一个可用的应用程序，并对每个小部件进行一些实际操作。我们还将再次使用`Button`小部件和`TextView`小部件。

在此布局中，我们将使用`LinearLayout`作为容纳一切的布局类型，并在`LinearLayout`内部使用多个`RelativeLayout`实例。

`RelativeLayout`已被`ConstraintLayout`取代，但它们仍然常用，并且值得尝试。当您在`RelativeLayout`中构建布局时，您会发现 UI 元素的行为与`ConstraintLayout`非常相似，但底层的 XML 不同。不需要详细了解这个 XML，而是使用`RelativeLayout`将允许我们展示 Android Studio 如何使您能够将这些布局转换为`ConstraintLayout`的有趣方式。

请记住，您可以参考下载包中的完整代码。此应用程序可以在`Chapter13/Widget Exploration`文件夹中找到。

## 设置小部件探索项目和 UI

首先，我们将设置一个新项目并准备 UI 布局。这些步骤将在屏幕上放置所有小部件并设置`id`属性，准备好引用它们。在开始之前，看一下目标布局并运行它会有所帮助，如下截图所示：

![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_04.jpg)

这个应用程序将演示这些小部件的工作原理：

+   单选按钮允许用户更改显示在时钟上的时间，以选择四个时区中的一个。

+   单击**Capture**按钮将更改右侧`TextView`小部件的`text`属性为当前左侧`EditText`小部件中的内容。

+   这三个`CheckBox`小部件将向 Android 机器人图像添加和删除视觉效果。在先前的截图中，图像被调整大小（变大）并应用了颜色着色。

+   `Switch`小部件将打开和关闭`TextView`小部件，后者显示在`EditText`小部件中输入的信息（在单击按钮时捕获）。

确切的布局位置并不重要，但指定的`id`属性必须完全匹配。因此，让我们执行以下步骤来设置一个新项目并准备 UI 布局：

1.  创建一个名为`Widget Exploration`的新项目，并使用**空活动**项目模板及其通常的设置，除了一个小改变。将**最低 API 级别**选项设置为`API 17：Android 4.2（Jelly Bean）`，并将所有其他设置保持为默认设置。我们使用 API 17 是因为`TextClock`小部件的一个功能需要我们这样做。我们仍然支持超过 98%的所有 Android 设备。

1.  让我们创建一个新的布局文件，因为我们希望我们的新布局基于`LinearLayout`。在项目资源管理器中右键单击`layout`文件夹，然后从弹出菜单中选择**新建** | **布局资源文件**。

1.  在**新资源文件**窗口中，在**文件名**字段中输入`exploration_layout.xml`，然后在**根元素**字段中输入`LinearLayout`；现在点击**确定**。

1.  在**属性**窗口中，将`LinearLayout`的`orientation`属性更改为**horizontal**。

1.  使用设计视图上方的下拉控件，确保选择了横向方向的平板电脑。

### 注意

如需了解如何创建平板电脑模拟器，请参阅第三章*探索 Android Studio 和项目结构*。如需关于如何操作模拟器方向的建议，请参阅第五章*使用 CardView 和 ScrollView 创建美观布局*。

1.  现在我们可以开始创建我们的布局。从工具栏的**Legacy**类别中将三个**RelativeLayout**布局拖放到设计中，以创建我们设计的三个垂直分区。在这一步骤中，您可能会发现使用**组件树**窗口更容易。

1.  依次为每个`RelativeLayout`小部件设置**weight**属性为`.33`。现在我们有了三个相等的垂直分区，就像下面的截图一样：![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_05.jpg)

1.  检查**组件树**窗口是否如下截图所示：![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_06.jpg)

### 注意

如果您想使用`ConstraintLayout`而不是`RelativeLayout`，那么以下说明将几乎相同。只需记住通过单击**推断约束**按钮或手动设置约束来设置 UI 的最终位置，如第四章*开始使用布局和 Material Design*中所讨论的那样。或者，您可以按照本教程中详细说明的方式构建布局，并使用稍后在本章中讨论的**转换为 Constraint 布局**功能。这对于使用您已有并希望使用的布局非常有用，但更倾向于使用运行速度更快的`ConstraintLayout`。

1.  将一个**Switch**小部件拖放到右侧`RelativeLayout`小部件的顶部中心位置，然后在其下方从工具栏中拖放一个**TextView**。您的布局右侧现在应如下截图所示：![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_07.jpg)

1.  将三个**CheckBox**小部件依次拖放在一起，然后将一个**ImageView**小部件拖放到它们下方的中央`RelativeLayout`上。在弹出的**资源**对话框中，选择**项目** | **ic_launcher**以将 Android 图标用作`ImageView`小部件的图像。中央列现在应如下所示：![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_08.jpg)

1.  将一个**RadioGroup**小部件拖放到左侧的`RelativeLayout`上。

1.  在**RadioGroup**小部件内添加四个**RadioButton**小部件。使用**组件树**窗口可以更轻松地完成此步骤。

1.  在**RadioGroup**小部件下方，从调色板的**文本**类别中拖动一个**纯文本**小部件。请记住，尽管它的名字是这样，但这是一个允许用户在其中输入一些文本的小部件。很快，我们将看到如何捕获和使用输入的文本。

1.  在**纯文本**小部件的右侧添加一个**Button**小部件。您的左侧`RelativeLayout`应如下截图所示：

此时**组件树**窗口将如下截图所示：

![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_10.jpg)

1.  现在我们可以开始使用所有这些小部件与我们的 Kotlin 代码。现在为刚刚布置的小部件添加以下属性： 

### 注意

| CheckBox (top) | id | `checkBoxTransparency` |

| Widget type | Property | 要设置的值 |
| --- | --- | --- |
| RadioGroup | `id` | `radioGroup` |
| 请注意，一些属性可能已经默认正确。 |
| RadioButton (top) | `text` | `London` |
| RadioButton (top) | `checked` | 选择“勾”图标为 true |
| RadioButton (second) | `id` | `radioButtonBeijing` |
| RadioButton (second) | `text` | `Beijing` |
| RadioButton (third) | `id` | `radioButtonNewYork` |
| RadioButton (third) | `text` | `New York` |
| CheckBox (bottom) | id | `checkBoxReSize` |
| RadioButton (bottom) | text | `European Empire` |
| EditText | id | `editText` |
| Button | id | `button` |
| Button | text | `Capture` |
| CheckBox (top) | text | `Transparency` |
| RadioButton (bottom) | id | `radioButtonEuropeanEmpire` |
| CheckBox (middle) | text | `Tint` |
| CheckBox (middle) | id | `checkBoxTint` |
| CheckBox (bottom) | text | `Resize` |
| ![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_09.jpg) |
| ImageView | id | `imageView` |
| Switch | id | `switch1` |
| Switch | enabled | 选择“勾”图标为 true |
| Switch | clickable | 选择“勾”图标为 true |
| TextView | id | `textView` |
| TextView | textSize | `34sp` |
| TextView | layout_width | `match_parent` |
| TextView | layout_height | `match_parent` |

1.  现在切换到**文本**选项卡，查看布局的 XML 代码。找到第一个（左侧）`RelativeLayout`列的末尾，如下面的代码清单所示。我已经在下面的代码中添加了一个 XML 注释并对其进行了突出显示：

```kt
...
...
   </RadioGroup>

   <EditText
         android:id="@+id/editText2"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_alignParentTop="true"
         android:layout_alignParentEnd="true"
         android:layout_marginTop="263dp"
         android:layout_marginEnd="105dp"
         android:ems="10"
         android:inputType="textPersonName"
         android:text="Name" />

   <Button
         android:id="@+id/button2"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:layout_alignParentBottom="true"
         android:layout_centerHorizontal="true"
         android:layout_marginBottom="278dp"
         android:text="Button" />

   <!-- Insert TextClock here-->

</RelativeLayout>
```

1.  在`<!--Insert TextClock Here-->`注释之后，插入以下`TextClock`小部件的 XML 代码。请注意，注释是我在上一个清单中添加的，以指示您放置代码的位置。您的代码中不会出现该注释。我们之所以这样做是因为`TextClock`不能直接从调色板中获取。以下是在注释之后添加的代码：

```kt
<TextClock
   android:id="@+id/textClock"
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:layout_alignParentBottom="true"
   android:layout_centerHorizontal="true"
   android:layout_gravity="center_horizontal"
   android:layout_marginBottom="103dp" 
   android:textSize="54sp" />
```

1.  切换到**设计**选项卡，并调整布局，使其尽可能接近以下参考图表，但如果您具有正确的 UI 类型和正确的`id`属性，则即使布局不完全相同，代码仍将正常工作：![设置小部件探索项目和 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_11.jpg)

我们刚刚设置了布局所需的属性。除了一些小部件类型对我们来说是新的，布局稍微更加复杂之外，我们并没有做过什么新的事情。

| RadioButton (top) | `id` | `radioButtonLondon` |

# 编写小部件探索应用程序

我们需要更改的 Kotlin 代码的第一部分是确保我们的新布局被显示出来。我们可以通过将`onCreate`函数中对`setContentView`函数的调用更改为以下内容来实现：

```kt
setContentView(R.layout.exploration_layout)
```

这个应用程序需要很多`import`语句，所以让我们一开始就把它们全部添加上，以免在进行过程中不断提到它们。添加以下`import`语句：

```kt
import androidx.appcompat.app.AppCompatActivity
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.CompoundButton
import android.widget.RadioButton
import kotlinx.android.synthetic.main.exploration_layout.*

```

前面的代码还包括`…exploration_layout.*`代码（如前面的代码中所突出显示的）以自动启用我们刚刚配置的`id`属性作为我们 Kotlin 代码中的实例名称。这样可以避免多次使用`findViewByID`函数。这种方式并不总是可行的，有时需要知道如何使用`findViewByID`函数，就像我们在“在布局部分声明和初始化对象”中讨论的那样。

## 编码 CheckBox 小部件

现在我们可以创建一个 lambda 来监听和处理复选框的点击。以下三个代码块依次实现了每个复选框的匿名类。然而，它们各自不同的地方在于我们如何响应点击，我们将依次讨论每一个。

### 改变透明度

第一个复选框标记为**Transparency**，我们使用`imageView`实例上的`alpha`属性来改变其透明度。`alpha`属性需要一个介于 0 和 1 之间的浮点值作为参数。

0 是不可见的，1 完全不透明。因此，当选中此复选框时，我们将`alpha`属性设置为`.1`，使图像几乎不可见；然后，当取消选中时，我们将其设置为`1`，即完全可见且没有透明度。`onCheckedChanged`函数的`Boolean isChecked`参数包含一个 true 或 false 值，表示复选框是否被选中。

在`onCreate`函数中的`setContentView`函数调用之后添加以下代码：

```kt
// Listen for clicks on the button,
// the CheckBoxes and the RadioButtons

// setOnCheckedChangeListener requires an interface of type
// CompoundButton.OnCheckedChangeListener. In turn this interface
// has a function called onCheckedChanged
// It is all handled by the lambda
checkBoxTransparency.setOnCheckedChangeListener({
   view, isChecked ->
      if (isChecked) {
         // Set some transparency
         imageView.alpha = .1f
      } else {
         // Remove the transparency
         imageView.alpha = 1f
      }
})
```

在下一个匿名类中，我们处理标记为**Tint**的复选框。

### 改变颜色

在`onCheckedChanged`函数中，我们使用`setColorFilter`函数在`imageView`上叠加一个颜色层。当`isChecked`为 true 时，我们叠加一个颜色，当`isChecked`为 false 时，我们移除它。

`setColorFilter`函数以**ARGB**（**alpha**，**red**，**green**和**blue**）格式的颜色作为参数。颜色由`Color`类的`argb`函数提供。`argb`函数的四个参数分别是 alpha、red、green 和 blue 的值。这四个值创建了一种颜色。在我们的例子中，`150, 255, 0, 0`的值创建了强烈的红色色调，而`0, 0, 0, 0`的值则完全没有色调。

### 提示

要了解更多关于`Color`类的信息，请访问 Android 开发者网站：[`developer.android.com/reference/android/graphics/Color.html`](http://developer.android.com/reference/android/graphics/Color.html)，要更多了解 RGB 颜色系统，请查看维基百科：[`en.wikipedia.org/wiki/RGB_color_model`](https://en.wikipedia.org/wiki/RGB_color_model)。

在`onCreate`函数中的上一个代码块之后添加以下代码：

```kt
checkBoxTint.setOnCheckedChangeListener({
   view, isChecked ->
   if (isChecked) {
      // Checked so set some tint
      imageView.setColorFilter(Color.argb(150, 255, 0, 0))
   } else {
      // No tint required
      imageView.setColorFilter(Color.argb(0, 0, 0, 0))
   }
})
```

现在我们将看到如何通过调整`ImageView`小部件的大小来缩放 UI。

### 改变大小

在处理**Resize**标记的复选框的匿名类中，我们使用`scaleX`和`scaleY`属性来调整机器人图像的大小。当我们将`scaleX`设置为 2，`scaleY`设置为 2 时，我们将使图像的大小加倍，而将值设置为 1 将使图像恢复到其正常大小。

在`onCreate`函数中的上一个代码块之后添加以下代码：

```kt
checkBoxReSize.setOnCheckedChangeListener({
   view, isChecked ->
   if (isChecked) {
      // It's checked so make bigger
      imageView.scaleX = 2f
      imageView.scaleY = 2f
   } else {
      // It's not checked make regular size
      imageView.scaleX = 1f
      imageView.scaleY = 1f
   }
})
```

现在我们将处理这三个单选按钮。

## 编码 RadioButton 小部件

由于它们是`RadioGroup`小部件的一部分，我们可以处理它们比处理`CheckBox`对象时更简洁。

首先，我们通过在`radioGroup`实例上调用`clearCheck()`来确保它们一开始是清除的。然后，我们创建了`OnCheckedChangeListener`类型的匿名类，并重写了`onCheckedChanged`函数，使用了一个简短而甜美的 lambda。

当从 RadioGroup 小部件中点击任何`RadioButton`时，将调用此函数。我们需要做的就是获取被点击的`RadioButton`小部件的`id`属性，并做出相应的响应。我们将使用`when`语句来实现三条可能的执行路径 - 每个`RadioButton`小部件对应一条。

请记住，当我们首次讨论`RadioButton`时，在`onCheckedChanged`的`checkedId`参数中提供的`id`属性是`Int`类型。这就是为什么我们必须首先从`checkedId`创建一个新的`RadioButton`对象的原因：

```kt
val rb = group.findViewById<View>(checkedId) as RadioButton
```

然后，我们可以使用新的`RadioButton`对象的`id`属性的 getter 作为`when`的条件，如下所示：

```kt
when (rb.id) {
   …
```

然后，在每个分支中，我们使用`timeZone`属性的 setter，并将正确的 Android 时区代码作为参数。

### 提示

您可以在[`gist.github.com/arpit/1035596`](https://gist.github.com/arpit/1035596)上查看所有 Android 时区代码。

添加以下代码，其中包含我们刚刚讨论的所有内容。将其添加到处理复选框的先前代码之后的`onCreate`函数中：

```kt
// Now for the radio buttons
// Uncheck all buttons
radioGroup.clearCheck()

radioGroup.setOnCheckedChangeListener {
   group, checkedId ->
   val rb = group.findViewById<View>(checkedId) as RadioButton

   when (rb.id) {
      R.id.radioButtonLondon ->
         textClock.timeZone = "Europe/London"

      R.id.radioButtonBeijing ->
         textClock.timeZone = "CST6CDT"

      R.id.radioButtonNewYork ->
         textClock.timeZone = "America/New_York"

      R.id.radioButtonEuropeanEmpire ->
         textClock.timeZone = "Europe/Brussels"
   }
}
```

现在是时候尝试一些稍微新的东西了。

### 使用 lambda 来处理常规 Button 小部件的点击

在我们将要编写的下一个代码块中，我们将使用 lambda 来实现一个匿名类来处理常规`Button`小部件的点击。我们调用`button.setOnclickListener`，就像我们之前做过的那样。但是这一次，我们不是将`this`作为参数传递，而是创建一个全新的`View.OnClickListener`类型的类，并覆盖`onClick`函数作为参数，就像我们之前的其他匿名类一样。与我们之前的类一样，代码是被推断的，我们有简短、简洁的代码，其中我们的代码没有被太多的细节所淹没。

### 提示

在这种情况下，这种方法是可取的，因为只有一个按钮。如果我们有很多按钮，那么让`MainActivity`实现`View.OnClickListener`，然后覆盖`onClick`以处理所有点击的函数可能更可取，就像我们之前做过的那样。

在`onClick`函数中，我们使用`text`属性的 setter 来设置`textView`上的`text`属性，然后使用`editText`实例的`text`属性的 getter 来获取用户在`EditText`小部件中输入的任何文本（如果有的话）。

在`onCreate`函数中的上一个代码块之后添加以下代码：

```kt
/*
   Let's listen for clicks on our "Capture" Button.
   The compiler has worked out that the single function
   of the required interface has a single parameter.
   Therefore, the syntax is shortened (->) is removed
   and the only parameter, (should we have needed it)
   is declared invisibly as "it"
*/
button.setOnClickListener {
   // it... accesses the view that was clicked

   // We want to act on the textView and editText instances
   // Change the text on the TextView
   // to whatever is currently in the EditText
   textView.text = editText.text
}
```

接下来，我们将处理 Switch 小部件。

### 编写 Switch 小部件的代码

接下来，我们将创建另一个匿名类来监听和处理我们的`Switch`小部件的更改。

当`isChecked`变量为`true`时，我们显示`TextView`小部件，当它为 false 时，我们隐藏它。

在`onCreate`函数中的上一个代码块之后添加以下代码：

```kt
// Show or hide the TextView
switch1.setOnCheckedChangeListener {
   buttonView, isChecked ->
   if (isChecked) {
      textView.visibility = View.VISIBLE
   } else {
      textView.visibility = View.INVISIBLE
   }
}
```

现在我们可以运行我们的应用程序并尝试所有功能。

### 提示

在 Windows 上，可以通过按*Ctrl* +*F11*键组合或在 macOS 上按*Ctrl* +*fn*+*F11*将 Android 模拟器旋转为横向模式。

# 运行 Widget Exploration 应用程序

尝试选中单选按钮，看看时区在时钟上的变化。在下面的图片中，我用 Photoshop 剪裁了一些截图，以显示选择新时区时时间的变化：

![运行 Widget Exploration 应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_12.jpg)

在`EditText`小部件中输入不同的值，然后单击按钮，以查看它获取文本并在自身上显示它，就像本教程开头的截图中演示的那样。

通过使用上面的`Switch`小部件，通过不同的复选框的选中和未选中的组合以及显示和隐藏`TextView`小部件来改变应用程序中的图像。以下截图显示了两种复选框和开关小部件的组合，用于演示目的：

![运行 Widget Exploration 应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_13.jpg)

### 提示

透明度在印刷书中并不是很清晰，所以我没有勾选那个框。一定要在模拟器或真实设备上试一下。

# 将布局转换为 ConstraintLayout

最后，正如承诺的那样，这就是我们如何将布局转换为运行更快的`ConstraintLayout`：

1.  切换回**设计**选项卡

1.  右键单击父布局 - 在这种情况下是`LinearLayout` - 并选择**将 LinearLayout 转换为 ConstraintLayout**，如下面的截图所示：![将布局转换为 ConstraintLayout](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_13_14.jpg)

现在你可以将任何旧的`RelativeLayout`布局转换为更新更快的`ConstraintLayout`小部件，同时构建你自己的`RelativeLayout`。

# 总结

在本章中，我们学到了很多。除了探索了大量的小部件，我们还学会了如何在 Kotlin 代码中实现小部件而不需要任何 XML，我们使用了我们的第一个匿名类，使用简短、简洁的代码形式的 lambda 来处理小部件的点击，我们将所有新的小部件技能都应用到了一个工作中的应用程序中。

现在让我们继续看另一种显著增强我们 UI 的方法。

在下一章中，我们将看到一个全新的 UI 元素，我们不能只从调色板中拖放，但我们仍然会得到来自 Android API 的大量帮助。我们将学习有关**对话框窗口**的知识。我们还将开始制作迄今为止最重要的应用程序，名为 Note to self。这是一个备忘录、待办事项和个人笔记应用程序。


# 第十四章：Android 对话框窗口

在本章中，我们将学习如何向用户呈现弹出式对话框窗口。然后，我们可以将我们所知道的一切放入我们的第一个多章节应用程序*Note to self*的第一阶段。然后，我们将在本章和接下来的四章（直到第十八章，*本地化*）中学习更多关于 Android 和 Kotlin 的特性，然后使用我们新获得的知识来增强 Note to self 应用程序。

在每一章中，我们还将构建一系列与主要应用程序分开的较小的应用程序。那么，第十四章*Android 对话框窗口*对你有什么期待呢？本章将涵盖以下主题：

+   实现一个带有弹出式对话框的简单应用程序

+   学习如何使用`DialogFragment`来开始 Note to self 应用程序

+   启动 Note to self 应用程序，并学习如何在项目中添加字符串资源，而不是在布局中硬编码文本

+   实现更复杂的对话框以捕获用户输入

那么，让我们开始吧。

# 对话框窗口

在我们的应用程序中，我们经常会想要向用户显示一些信息，或者询问是否确认弹出窗口中的操作。这就是所谓的**对话框**窗口。如果你快速浏览一下 Android Studio 的调色板，你可能会惊讶地发现根本没有提到对话框窗口。

Android 中的对话框窗口比简单的小部件甚至整个布局更高级。它们是可以拥有自己的布局和其他 UI 元素的类。

在 Android 中创建对话框窗口的最佳方式是使用`DialogFragment`类。

### 提示

片段在 Android 中是一个广泛而重要的主题，我们将在本书的后半部分花费大量时间来探索和使用它们。然而，为我们的用户创建一个整洁的弹出式对话框（使用`DialogFragment`）是对片段的一个很好的介绍，并且一点也不复杂。

## 创建对话框演示项目

我们之前提到，在 Android 中创建对话框窗口的最佳方式是使用`DialogFragment`类。然而，在 Android 中创建对话框的另一种方式可能会更简单一些。这种更简单的`Dialog`类的问题在于它在 Activity 生命周期中的支持不是很好。甚至可能会导致应用程序意外崩溃。

如果你正在编写一个只需要一个简单弹出式对话框的固定方向布局的应用程序，可以说应该使用更简单的`Dialog`类。但是，由于我们的目标是构建具有先进功能的现代专业应用程序，因此忽略这个类将会使我们受益匪浅。

在 Android Studio 中使用**空活动**项目模板创建一个名为`Dialog Demo`的新项目。该项目的完成代码位于下载包的`Chapter14/Dialog Demo`文件夹中。

## 编写 DialogFragment 类

通过右键单击包含`MainActivity.kt`文件的包名称的文件夹，在 Android Studio 中创建一个新的类。选择**新建** | **Kotlin 文件/类**，命名为`MyDialog`，并在下拉选择器中选择**类**。单击**确定**以创建类。

你需要做的第一件事是将类声明更改为继承自`DialogFragment`。此外，让我们添加在这个类中需要的所有导入。当你这样做后，你的新类将如下所示：

```kt
import android.app.Dialog
import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment

class MyDialog : DialogFragment() {    
}
```

现在，让我们一点一点地向这个类添加代码，并解释每一步发生了什么。

与 Android API 中的许多类一样，`DialogFragment`为我们提供了可以重写以与类中发生的不同事件交互的函数。

添加覆盖`onCreateDialog`函数的以下突出显示的代码。仔细研究它，然后我们将检查发生了什么：

```kt
class MyDialog : DialogFragment() {

    override
 fun onCreateDialog(savedInstanceState: Bundle?): Dialog {

 // Use the Builder class because this dialog
 // has a simple UI.
 // We will use the more flexible onCreateView function
 // instead of onCreateDialog in the next project
 val builder = AlertDialog.Builder(this.activity!!)

 // More code here soon
 }
}
```

### 注意

代码中有一个错误，因为我们缺少返回语句，需要返回一个`Dialog`类型的对象。我们将在完成函数的其余部分编码后添加这个返回语句。

在我们刚刚添加的代码中，我们首先添加了重写的`onCreateDialog`函数，当我们稍后使用`MainActivity`类的代码显示对话框时，Android 将调用它。

然后，在`onCreateDialog`函数内部，我们得到了一个新类的实例。我们声明并初始化了一个`AlertDialog.Builder`类型的对象，它需要一个对`MainActivity`类的引用传递给它的构造函数。这就是为什么我们使用`activity!!`作为参数；我们断言该实例不为空（!!）。

### 提示

参考第十二章，“将我们的 Kotlin 连接到 UI 和可空性”，了解非空断言（!!）的用法。

`activity`属性是`Fragment`类（因此也是`DialogFragment`）的一部分，它是一个对将创建`DialogFragment`实例的`Activity`类实例的引用。在这种情况下，这是我们的`MainActivity`类。

现在我们已经声明并初始化了`builder`，让我们看看我们可以用它做什么。

### 使用链接来配置 DialogFragment 类

现在我们可以使用我们的`builder`对象来完成其余的工作。在接下来的三个代码块中有一些略微奇怪的地方。如果你往前看并快速扫描它们，你会注意到有三次使用了点运算符，但只有一次使用是实际放在`builder`对象旁边的。这表明这三个明显的代码块实际上只是编译器的一行代码。

我们之前已经见过这里发生的事情，但情况没有那么明显。当我们创建一个`Toast`消息并在其末尾添加`.show()`调用时，我们正在**链接**。也就是说，我们在同一个对象上按顺序调用多个函数。这相当于编写多行代码；只是这样更清晰、更简洁。

在`onCreateDialog`中添加这段代码，它利用了链接，然后我们将讨论它：

```kt
// Dialog will have "Make a selection" as the title
builder.setMessage("Make a selection")
   // An OK button that does nothing
   .setPositiveButton("OK", { dialog, id ->
      // Nothing happening here
   })
   // A "Cancel" button that does nothing
   .setNegativeButton("Cancel", { dialog, id ->
      // Nothing happening here either
   })
```

我们添加的代码的三个部分可以解释如下：

1.  在使用链接的三个代码块中的第一个中，我们调用`builder.setMessage`，它设置用户在对话框中看到的主要消息。另外，需要注意的是，在链接函数调用的不同部分之间添加注释是可以的，因为编译器完全忽略这些注释。

1.  然后，我们使用`setPositiveButton`函数向对话框添加一个按钮，第一个参数将其文本设置为`OK`。第二个参数是一个实现`DialogInterface.OnClickListener`的 lambda，用于处理按钮的点击。请注意，我们不会在`onClick`函数中添加任何代码，但我们可以，就像我们在上一章中所做的那样。我们只是想看到这个简单的对话框，我们将在下一个项目中进一步进行。

1.  接下来，我们在同一个`builder`对象上调用另一个函数。这次是`setNegativeButton`函数。同样，两个参数将`Cancel`设置为按钮的文本，使用 lambda 来设置监听点击。同样，为了这个演示的目的，我们不会在重写的`onClick`函数中执行任何操作。

接下来，我们将编写`return`语句以完成函数并移除错误。在`onCreateDialog`函数的最后（但保持在最终大括号内部）添加`return`语句：

```kt
   // Create the object and return it
   return builder.create()
}// End of onCreateDialog
```

这行代码的最后效果是将我们新的、完全配置好的对话框窗口返回给`MainActivity`（它首先会调用`onCreateDialog`）。我们很快将看到并添加这个调用代码。

现在我们有了从`FragmentDialog`继承的`MyDialog`类，我们所要做的就是声明`MyDialog`的一个实例，实例化它，并调用它重写的`onCreateDialog`函数。

## 使用 DialogFragment 类

在转向代码之前，让我们通过以下步骤向我们的布局添加一个按钮：

1.  切换到`activity_main.xml`选项卡，然后切换到**Design**选项卡。

1.  将**Button**小部件拖放到布局中，并确保其`id`属性设置为`button`。

1.  单击**推断约束**按钮，将按钮约束到您放置的位置，但位置并不重要；我们将如何使用它来创建我们的`MyDialog`类的实例是关键的教训。

现在切换到`MainActivity.kt`选项卡，我们将使用 lambda 来处理新按钮的点击，就像我们在第十三章中所做的那样，在 Widget 探索应用程序中。我们这样做是因为布局中只有一个按钮，这种方式似乎比另一种方式更明智和更紧凑（即实现`OnClickListener`接口，然后在整个`MainActivity`类中重写`onClick`，就像我们在第十二章中所做的那样，*将我们的 Kotlin 连接到 UI 和可空性*）。

在`MainActivity`的`onCreate`函数中添加以下代码，放在`setContentView`调用之后：

```kt
val button = findViewById<Button>(R.id.button)
// We could have removed the previous line of code by
// adding the ...synthetic.main.activity_main.* import
// as an alternative

button.setOnClickListener {
   val myDialog = MyDialog()
   myDialog.show(supportFragmentManager, "123")
   // This calls onCreateDialog
   // Don't worry about the strange looking 123
   // We will find out about this in chapter 18
}
```

### 注意

需要以下`import`语句来支持此代码：

```kt
import android.widget.Button;
```

请注意，代码中唯一发生的事情是`setOnClickListener` lambda 覆盖了`onClick`。这意味着当按钮被按下时，将创建`MyDialog`的一个新实例并调用其`show`函数，该函数将显示我们在`MyDialog`类中配置的对话框窗口。

`show`函数需要一个对`FragmentManager`的引用，我们从`supportFragmentManager`属性中获取。这是跟踪和控制`Activity`实例的所有片段实例的类。我们还传入一个 ID（`"123"`）。

更多关于`FragmentManager`的细节将在我们更深入地研究片段时揭示，从第二十四章开始，*设计模式、多个布局和片段*。

### 注意

我们使用`supportFragmentManager`属性的原因是因为我们通过扩展`AppCompatActivity`来支持旧设备。如果我们简单地扩展`Activity`，那么我们可以使用`fragmentManager`属性。缺点是该应用程序将无法在许多旧设备上运行。

现在我们可以运行应用程序，并欣赏我们点击布局中的按钮时出现的新对话框窗口。请注意，单击对话框窗口中的任一按钮都将关闭它；这是默认行为。以下屏幕截图显示了我们的对话框窗口在平板模拟器上的运行情况：

![使用 DialogFragment 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_01.jpg)

接下来，我们将制作另外两个实现对话框的类，作为我们多章节备忘录应用程序的第一阶段。我们将看到对话框窗口几乎可以有我们选择的任何布局，并且我们不必依赖`Dialog.Builder`类提供给我们的简单布局。

# 备忘录应用程序

欢迎来到本书中我们将实现的多章应用程序中的第一个。在做这些项目时，我们将比做较小的应用程序更专业。在这个项目中，我们将使用字符串资源而不是在布局中硬编码文本。

有时，当您尝试学习新的 Android 或 Kotlin 主题时，这些东西可能会过度，但它们对于尽快在真实项目中开始使用是有用且重要的。它们很快就会变得像第二天性一样，我们的应用程序质量将受益于此。

## 使用字符串资源

在第三章*探索 Android Studio 和项目结构*中，我们讨论了在布局文件中使用字符串资源而不是硬编码文本。这样做有一些好处，但也稍微冗长。

由于这是我们的第一个多章节项目，现在是做正确的时候。如果您想快速了解字符串资源的好处，请参阅第三章*探索 Android Studio 和项目结构*。

## 如何获取 Note to self 应用程序的代码文件

完全完成的应用程序，包括所有的代码和资源，可以在下载包的`Chapter18/Note to self`文件夹中找到。由于我们将在接下来的五章中实施这个应用程序，因此在每一章结束时查看部分完成的可运行应用程序也是有用的。部分完成的可运行应用程序及其所有相关的代码和资源可以在各自的文件夹中找到：

`Chapter14/Note to self`

`Chapter16/Note to self`

`Chapter17/Note to self`

`Chapter18/Note to self`

### 注意

在第十五章*处理数据和生成随机数*中没有 Note to self 的代码，因为虽然我们会学习一些在 Note to self 中使用的主题，但直到第十六章*适配器和回收器*，我们才对应用程序进行更改。

请注意，每个文件夹都包含一个独立的可运行项目，并且也包含在自己独特的包中。这样你就可以很容易地看到应用程序在完成给定章节后的运行情况。在复制和粘贴代码时，要小心不要包括包名称，因为它可能与您的包名称不同，导致代码无法编译。

如果您正在跟着做，并打算从头到尾构建 Note to self，我们将简单地构建一个名为`Note to self`的项目。然而，您仍然可以随时查看每个章节的项目文件中的代码，进行一些复制和粘贴。只是不要复制文件顶部的包指令。另外，请注意，在说明书的几个地方，您将被要求删除或替换前几章的偶尔一行代码。

因此，即使您复制和粘贴的次数多于输入代码的次数，请务必完整阅读说明，并查看书中的代码，以获取可能有用的额外注释。

在每一章中，代码将被呈现为如果您已经完全完成上一章，将显示来自早期章节的代码，必要时作为新代码的上下文。

每一章都不会完全致力于 Note to self 应用程序。我们还将学习其他相关内容，并构建一些更小更简单的应用程序。因此，当我们开始实施 Note to self 时，我们将在技术上做好准备。

## 完成的应用程序

以下功能和屏幕截图来自完成的应用程序。在开发的各个阶段，它显然会略有不同。必要时，我们将查看更多图像，作为提醒，或者查看开发过程中的差异。

完成的应用程序将允许用户点击应用程序右下角的浮动按钮图标，打开一个对话框窗口以添加新的便签。以下屏幕截图显示了这个突出的功能：

![完成的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_02.jpg)

左侧的屏幕截图显示了要点击的按钮，右侧的屏幕截图显示了用户可以添加新便签的对话框窗口。

最终，随着用户添加更多的笔记，他们将在应用程序的主屏幕上拥有所有已添加的笔记列表，如下截图所示。用户可以选择笔记是**重要**、**想法**和/或**待办事项**笔记：

![完成的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_04.jpg)

他们将能够滚动列表并点击一个笔记，以在专门用于该笔记的另一个对话框窗口中查看它。以下是显示笔记的对话框窗口：

![完成的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_05.jpg)

还将有一个非常简单的设置屏幕，可以从菜单中访问，允许用户配置笔记列表是否以分隔线格式化。以下是设置菜单选项的操作：

![完成的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_06.jpg)

现在我们确切地知道我们要构建什么，我们可以继续并开始实施它。

## 构建项目

现在让我们创建我们的新项目。将项目命名为`Note to Self`，并使用**Basic Activity**模板。请记住，从第三章*探索 Android Studio 和项目结构*中得知，此模板将生成一个简单的菜单和一个浮动操作按钮，这两者都在此项目中使用。将其他设置保留为默认设置。

## 准备字符串资源

在这里，我们将创建所有的字符串资源，我们将从布局文件中引用这些资源，而不是硬编码`text`属性，就像我们一直在做的那样。严格来说，这是一个可以避免的步骤。但是，如果您想要制作深入的 Android 应用程序，学会以这种方式做事情将使您受益匪浅。

要开始，请在项目资源管理器中的`res/values`文件夹中打开`strings.xml`文件。您将看到自动生成的资源。添加我们将在整个项目的其余部分中使用的以下突出显示的字符串资源。在关闭`</resources>`标签之前添加以下代码：

```kt
...
<resources>
    <string name="app_name">Note To Self</string>
    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>

    <string name="action_add">add</string>
    <string name="title_hint">Title</string>
    <string name="description_hint">Description</string>
    <string name="idea_text">Idea</string>
    <string name="important_text">Important</string>
    <string name="todo_text">To do</string>
    <string name="cancel_button">Cancel</string>
    <string name="ok_button">OK</string>

    <string name="settings_title">Settings</string>
    <string name="theme_title">Theme</string>
    <string name="theme_light">Light</string>
    <string name="theme_dark">Dark</string>

</resources>
```

请注意在上述代码中，每个字符串资源都有一个唯一的`name`属性，用于将其与所有其他字符串资源区分开。`name`属性还提供了一个有意义的，并且希望是记忆深刻的线索，表明它代表的实际字符串值。正是这些名称值，我们将用来从我们的布局文件中引用我们想要使用的字符串。

## 编写 Note 类

这是应用程序的基本数据结构。这是一个我们将从头开始编写的类，它具有表示单个用户笔记所需的所有属性。在第十五章*处理数据和生成随机数*中，我们将学习一些新的 Kotlin 代码，以了解如何让用户拥有数十、数百甚至数千条笔记。

通过右键单击包含`MainActivity.kt`文件的文件夹来创建一个新类 - 通常是包含`MainActivity.kt`文件的文件夹。选择**New** | **Kotlin File/class**，命名为`Note`，并从下拉选择器中选择**Class**。单击**OK**创建类。

将以下代码添加到新的`Note`类中：

```kt
class Note {
    var title: String? = null
    var description: String? = null
    var idea: Boolean = false
    var todo: Boolean = false
    var important: Boolean = false
}
```

我们有一个简单的类，没有函数，叫做`Note`。这个类有五个`var`属性，分别叫做`title`、`description`、`idea`、`todo`和`important`。它们的用途是保存用户笔记的标题、笔记的描述（或内容），以及详细说明笔记是一个想法、一个待办事项，还是一个重要的笔记。现在让我们设计两个对话框窗口的布局。

## 实现对话框设计

现在我们将做一些我们以前做过很多次的事情，但这次是出于不同的原因。正如你所知，我们将有两个对话框窗口 - 一个用于用户输入新的笔记，另一个用于用户查看他们选择的笔记。

我们可以以与之前所有布局相同的方式设计这两个对话框窗口的布局。当我们开始为`FragmentDialog`类创建 Kotlin 代码时，我们将学习如何将这些布局结合起来。

首先，让我们按照以下步骤为我们的“新笔记”对话框添加布局：

1.  在项目资源管理器中右键单击`layout`文件夹，选择**新建** | **布局资源文件**。在**文件名：**字段中输入`dialog_new_note`，然后开始输入`Constrai`以填写**根元素：**字段。注意到有一个下拉列表，其中有多个以**Constrai…**开头的选项。现在选择**androidx.constraintlayout.widget.ConstraintLayout**。左键单击**确定**生成新的布局文件，其根元素类型为`ConstraintLayout`。

1.  在按照以下说明的同时，参考下面的屏幕截图中的目标设计。我已经使用 Photoshop 将完成的布局和我们即将自动生成的约束条件放在一起，约束条件被隐藏以增加清晰度：![实现对话框设计](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_08.jpg)

1.  从**文本**类别中拖放一个**纯文本**小部件到布局的最上方和最左边，然后再添加另一个**纯文本**。现在不用担心任何属性。

1.  从**按钮**类别中拖放三个**复选框**小部件，依次放置。查看之前的参考屏幕截图以获得指导。同样，现在不用担心任何属性。

1.  从上一步中的最后一个**复选框**小部件直接下方拖放两个**按钮**到布局中，然后将第二个**按钮**水平放置，与第一个**按钮**对齐，但完全位于布局的右侧。

1.  整理布局，使其尽可能地与参考屏幕截图相似，然后点击**推断约束条件**按钮来修复您选择的位置。

1.  现在我们可以设置所有的`text`、`id`和`hint`属性。您可以使用下表中的值来设置。请记住，我们在`text`和`hint`属性中使用了我们的字符串资源。

### 注意

当您编辑第一个`id`属性时，可能会弹出一个窗口询问您是否确认更改。勾选**本次会话期间不再询问**并点击**是**继续，如下屏幕截图所示：

![实现对话框设计](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_15.jpg)

以下是要输入的值：

| **小部件类型** | **属性** | **要设置的值** |
| --- | --- | --- |
| 纯文本（顶部） | id | `editTitle` |
| 纯文本（顶部） | 提示 | `@string/title_hint` |
| 纯文本（底部） | id | `editDescription` |
| 纯文本（底部） | 提示 | `@string/description_hint` |
| 纯文本（底部） | 输入类型 | textMultiLine（取消其他选项） |
| 复选框（顶部） | id | `checkBoxIdea` |
| 复选框（顶部） | 文本 | `@string/idea_text` |
| 复选框（中部） | id | `checkBoxTodo` |
| 复选框（中部） | 文本 | `@string/todo_text` |
| 复选框（底部） | id | `checkBoxImportant` |
| 复选框（底部） | 文本 | `@string/important_text` |
| 按钮（左侧） | id | `btnCancel` |
| 按钮（左侧） | 文本 | `@string/cancel_button` |
| 按钮（右侧） | id | `btnOK` |
| 按钮（右侧） | 文本 | `@string/ok_button` |

我们现在有一个整洁的布局，准备好显示我们的 Kotlin 代码。请记住不同小部件的`id`值，因为当我们编写代码时，我们将看到它们的作用。重要的是，我们的布局看起来漂亮，并且每个相关项目都有一个`id`值，这样我们就可以引用它。

让我们布置对话框，向用户显示一个提示：

1.  在项目资源管理器中右键单击**布局**文件夹，然后选择**新建|布局资源文件**。在**文件名：**字段中输入`dialog_show_note`，然后开始输入`Constrai`以获取**根元素：**字段。注意到有一个下拉列表，其中有多个以**Constrai…**开头的选项。现在选择**androidx.constraintlayout.widget.ConstraintLayout**。单击**确定**生成具有`ConstraintLayout`类型作为其根元素的新布局文件。

1.  参考下一个截图中的目标设计，同时按照这些说明的其余部分进行操作。我已经使用 Photoshop 将包括我们即将自动生成的约束的完成布局与布局放在一起，并隐藏了约束以获得额外的清晰度：![实现对话框设计](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_09.jpg)

1.  首先，在布局的顶部垂直对齐拖放三个**TextView**小部件。

1.  接下来，在前三个`TextView`小部件的中心下方拖放另一个**TextView**小部件。

1.  在前一个下方的左侧添加另一个**TextView**小部件。

1.  现在在布局的底部水平居中位置添加一个**Button**。到目前为止，它应该是这个样子：![实现对话框设计](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_10.jpg)

1.  整理布局，使其尽可能地与参考截图相似，然后单击**推断约束**按钮以修复您选择的位置。

1.  从以下表中配置属性：

| **小部件类型** | **属性** | **要设置的值** |
| --- | --- | --- |
| TextView（左上角） | `id` | `textViewImportant` |
| TextView（左上角） | `text` | `@string/important_text` |
| TextView（顶部中心） | `id` | `textViewTodo` |
| TextView（顶部中心） | `text` | `@string/todo_text` |
| TextView（右上角） | `id` | `textViewIdea` |
| TextView（右上角） | `text` | `@string/idea_text` |
| TextView（中心，第二行） | `id` | `txtTitle` |
| TextView（中心，第二行） | `textSize` | `24sp` |
| TextView（最后一个添加的） | `id` | `txtDescription` |
| Button | `id` | `btnOK` |
| Button | `text` | `@string/ok_button` |

### 提示

在进行上述更改之后，您可能希望通过拖动它们在屏幕上调整它们的大小和内容来微调一些 UI 元素的最终位置。首先，单击**清除所有约束**，然后调整布局使其符合您的要求，最后，单击**推断约束**以再次约束位置。

现在我们有一个布局，可以用来向用户显示笔记。请注意，我们可以重用一些字符串资源。我们的应用程序越大，这样做就越有益。

## 编写对话框

现在我们已经为我们的两个对话框窗口（“显示笔记”和“新建笔记”）设计好了，我们可以利用我们对`FragmentDialog`类的了解来实现一个类来代表用户可以交互的每个对话框窗口。

我们将从“新建笔记”屏幕开始。

### 编写 DialogNewNote 类

通过右键单击具有`.kt`文件的项目文件夹并选择**新建** | **Kotlin 文件/类**来创建一个新类。命名`DialogNewNote`类并在下拉选择器中选择**类**。单击**确定**生成新类。

首先，更改类声明并继承自`DialogFragment`。还要重写`onCreateDialog`函数，这是该类中其余代码的位置。使您的代码与以下代码相同以实现这一点：

```kt
class DialogNewNote : DialogFragment() {

   override 
   fun onCreateDialog(savedInstanceState: Bundle?): Dialog {

        // All the rest of the code goes here

    }
}
```

### 提示

您还需要添加以下新的导入：

```kt
import androidx.fragment.app.DialogFragment;
import android.app.Dialog;
import android.os.Bundle;
```

我们暂时在新类中有一个错误，因为我们需要在`onCreateDialog`函数中有一个`return`语句，但我们马上就会解决这个问题。

在接下来的代码块中，我们将在一会儿添加的首先声明并初始化一个`AlertDialog.Builder`对象，就像我们以前创建对话框窗口时所做的那样。然而，这一次，我们不会像以前那样经常使用这个对象。

接下来，我们初始化一个`LayoutInflater`对象，我们将用它来填充我们的 XML 布局。 "填充"简单地意味着将我们的 XML 布局转换为 Kotlin 对象。一旦完成了这个操作，我们就可以以通常的方式访问所有小部件。我们可以将`inflater.inflate`视为替换对话框的`setContentView`函数调用。在第二行中，我们使用`inflate`函数做到了这一点。

添加我们刚刚讨论过的三行代码：

```kt
// All the rest of the code goes here
val builder = AlertDialog.Builder(activity!!)

val inflater = activity!!.layoutInflater

val dialogView = inflater.inflate
   (R.layout.dialog_new_note, null)
```

### 提示

为了支持前三行代码中的新类，您需要添加以下`import`语句：

```kt
import androidx.appcompat.app.AlertDialog
import android.view.View
import android.view.LayoutInflater
```

我们现在有一个名为`dialogView`的`View`对象，它具有来自我们的`dialog_new_note.xml`布局文件的所有 UI 元素。

现在，在上一个代码块下面，我们将添加以下代码。

此代码将获取对每个 UI 小部件的引用。在上一个代码块之后添加以下代码：

```kt
val editTitle =
      dialogView.findViewById(R.id.editTitle) as EditText

val editDescription =
      dialogView.findViewById(R.id.editDescription) as 
                EditText

val checkBoxIdea =
      dialogView.findViewById(R.id.checkBoxIdea) as CheckBox

val checkBoxTodo =
      dialogView.findViewById(R.id.checkBoxTodo) as CheckBox

val checkBoxImportant =
      dialogView.findViewById(R.id.checkBoxImportant) as 
                CheckBox

val btnCancel =
      dialogView.findViewById(R.id.btnCancel) as Button

val btnOK =
      dialogView.findViewById(R.id.btnOK) as Button
```

### 提示

确保添加以下`import`代码，以使您刚刚添加的代码无错误：

```kt
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
```

在上述代码中有一个新的 Kotlin 特性，称为`as`关键字；例如，`as EditText`，`as CheckBox`和`as Button`。由于编译器无法推断出每个 UI 小部件的具体类型，所以使用了这个特性。尝试从代码中删除一个`as…`关键字并注意产生的错误。使用`as`关键字（因为我们知道类型）可以解决这个问题。

在下一个代码块中，我们将使用`builder`实例设置对话框的消息。然后，我们将编写一个 lambda 来处理`btnCancel`的点击。在重写的`onClick`函数中，我们将简单地调用`dismiss()`，这是`DialogFragment`的一个函数，用于关闭对话框窗口。这正是用户单击**Cancel**时我们需要的。

添加我们刚刚讨论过的代码：

```kt
builder.setView(dialogView).setMessage("Add a new note")

// Handle the cancel button
btnCancel.setOnClickListener {
   dismiss()
}
```

现在，我们将添加一个 lambda 来处理用户单击**OK**按钮（`btnOK`）时发生的情况。

在其中，我们创建一个名为`newNote`的新`Note`。然后，我们将`newNote`的每个属性设置为表单的适当内容。

之后，我们使用对`MainActivity`的引用来调用`MainActivity`中的`createNewNote`函数。

### 提示

请注意，我们还没有编写`createNewNote`函数，直到本章后面我们这样做之前，函数调用将显示错误。

在这个函数中发送的参数是我们新初始化的`newNote`对象。这样做的效果是将用户的新笔记发送回`MainActivity`。我们将在本章后面看到我们如何处理这个。

最后，我们调用`dismiss`来关闭对话框窗口。在我们添加的上一个代码块之后添加我们讨论过的代码：

```kt
btnOK.setOnClickListener {
   // Create a new note
   val newNote = Note()

   // Set its properties to match the
   // user's entries on the form
   newNote.title = editTitle.text.toString()

   newNote.description = editDescription.text.toString()

   newNote.idea = checkBoxIdea.isChecked
   newNote.todo = checkBoxTodo.isChecked
   newNote.important = checkBoxImportant.isChecked

   // Get a reference to MainActivity
   val callingActivity = activity as MainActivity?

   // Pass newNote back to MainActivity
   callingActivity!!.createNewNote(newNote)

   // Quit the dialog
   dismiss()
}

return builder.create()
```

我们的第一个对话框窗口已经完成。我们还没有将其连接到`MainActivity`中，并且我们还需要实现`createNewNote`函数。我们将在创建下一个对话框之后立即执行此操作。

### 编写 DialogShowNote 类

通过右键单击包含所有`.kt`文件的项目文件夹，选择**New** | **Kotlin File/Class**来创建一个新类。命名为`DialogShowNote`类，然后在下拉选择器中选择**Class**，然后单击**OK**生成新类。

首先，更改类声明并继承自`DialogFragment`，然后重写`onCreateDialog`函数。由于这个类的大部分代码都在`onCreateDialog`函数中，所以按照以下代码中显示的签名和空体实现它，我们将在一分钟后回顾它。

请注意，我们声明了`Note`类型的`var`属性`note`。另外，添加`sendNoteSelected`函数及其初始化`note`的单行代码。这个函数将被`MainActivity`调用，并传入用户点击的`Note`对象。

添加我们刚讨论过的代码，然后我们可以查看`onCreateDialog`的细节：

```kt
class DialogShowNote : DialogFragment() {

    private var note: Note? = null

    override fun 
    onCreateDialog(savedInstanceState: Bundle?): Dialog {

        // All the other code goes here

    }

    // Receive a note from the MainActivity class
    fun sendNoteSelected(noteSelected: Note) {
        note = noteSelected
    }

}
```

### 提示

此时，您需要导入以下类：

```kt
import android.app.Dialog;
import android.os.Bundle;
import androidx.fragment.app.DialogFragment;
```

接下来，我们声明并初始化一个`AlertDialog.Builder`的实例。接下来，就像我们为`DialogNewNote`做的那样，我们声明并初始化`LayoutInflater`，然后使用它来创建一个具有对话框布局的`View`对象。在这种情况下，它是来自`dialog_show_note.xml`的布局。

最后，在下面的代码块中，我们获取对每个 UI 小部件的引用，并使用`note`中的相关属性设置`txtTitle`和`textDescription`的`text`属性，这些属性在`sendNoteSelected`函数调用中初始化。

添加我们刚刚讨论过的代码到`onCreateDialog`函数中：

```kt
val builder = AlertDialog.Builder(this.activity!!)

val inflater = activity!!.layoutInflater

val dialogView = inflater.inflate(R.layout.dialog_show_note, null)

val txtTitle = 
   dialogView.findViewById(R.id.txtTitle) as TextView

val txtDescription = 
   dialogView.findViewById(R.id.txtDescription) as TextView

txtTitle.text = note!!.title
txtDescription.text = note!!.description      

val txtImportant = 
   dialogView.findViewById(R.id.textViewImportant) as TextView

val txtTodo = 
   dialogView.findViewById(R.id.textViewTodo) as TextView

val txtIdea = 
   dialogView.findViewById(R.id.textViewIdea) as TextView
```

### 提示

将上述`import`语句添加到以前的代码中，以使所有类都可用：

```kt
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
```

下一个代码也在`onCreateDialog`函数中。它检查正在显示的笔记是否“重要”，然后相应地显示或隐藏`txtImportant TextView`小部件。然后我们对`txtTodo`和`txtIdea`小部件做同样的操作。

在上一个代码块之后添加此代码，仍然在`onCreateDialog`函数中：

```kt
if (!note!!.important){
   txtImportant.visibility = View.GONE
}

if (!note!!.todo){
   txtTodo.visibility = View.GONE
}

if (!note!!.idea){
   txtIdea.visibility = View.GONE
}
```

现在我们只需要在用户点击**OK**按钮时`dismiss`（即关闭）对话框窗口。这是通过 lambda 完成的，因为我们已经看到了好几次。`onClick`函数只是调用`dismiss`函数，关闭对话框窗口。

在上一个代码块之后添加此代码到`onCreateDialog`函数中：

```kt
val btnOK = dialogView.findViewById(R.id.btnOK) as Button

builder.setView(dialogView).setMessage("Your Note")

btnOK.setOnClickListener({
   dismiss()
})

return builder.create()
```

### 提示

使用这行代码导入`Button`类：

```kt
import android.widget.Button;
```

我们现在有两个准备好的对话框窗口。我们只需要在`MainActivity`类中添加一些代码来完成工作。

## 显示和使用我们的新对话框

在`MainActivity`声明之后添加一个新的临时属性：

```kt
// Temporary code
private var tempNote = Note()
```

### 提示

这段代码不会出现在最终的应用程序中；这只是为了让我们立即测试我们的对话框窗口。

现在添加这个函数，以便我们可以从`DialogNewNote`类接收一个新的笔记：

```kt
fun createNewNote(n: Note) {
   // Temporary code
   tempNote = n
}
```

现在，要将一个笔记发送到`DialogShowNote`函数，我们需要在`layout_main.xml`布局文件中添加一个带有`button` `id`的按钮。

为了清楚地说明这个按钮的用途，我们将把它的`text`属性更改为`Show Note`，如下所示：

+   将`Button`小部件拖放到`layout_main.xml`上，并将其`id`配置为`button`，`text`配置为`Show Note`。

+   点击**Infer Constraints**按钮，使按钮停留在您放置的位置。此按钮的确切位置在这个阶段并不重要。

### 注意

只是为了澄清，这是一个临时按钮，用于测试目的，不会在最终的应用程序中使用。在开发结束时，我们将点击列表中的笔记标题。

现在，在`onCreate`函数中，我们将设置一个 lambda 来处理对临时按钮的点击。`onClick`中的代码将执行以下操作：

+   创建一个名为`dialog`的新`DialogShowNote`实例。

+   在`dialog`上调用`sendNoteSelected`函数，将我们的`Note`对象`tempNote`作为参数传递进去。

+   最后，它将调用`show`，为我们的新对话框注入生命。

将先前描述的代码添加到`onCreate`函数中：

```kt
// Temporary code
val button = findViewById<View>(R.id.button) as Button
button.setOnClickListener {
   // Create a new DialogShowNote called dialog
   val dialog = DialogShowNote()

   // Send the note via the sendNoteSelected function
   dialog.sendNoteSelected(tempNote)

   // Create the dialog
   dialog.show(supportFragmentManager, "123")
}
```

### 提示

确保使用这行代码导入`Button`类：

```kt
import android.widget.Button;
```

现在我们可以在点击按钮时召唤我们的`DialogShowNote`对话框窗口。运行应用程序，点击**SHOW NOTE**按钮，查看`DialogShowNote`对话框窗口，其中包含`dialog_show_note.xml`布局，如下截图所示：

![显示和使用我们的新对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_11.jpg)

诚然，考虑到我们在本章中所做的大量编码，这并不是什么了不起的，但是当我们让`DialogNewNote`类起作用时，我们将看到`MainActivity`如何在两个对话框之间交互和共享数据。

让`DialogNewNote`对话框可用。

### 编写浮动操作按钮

这将很容易。浮动操作按钮已经在布局中为我们提供。作为提醒，这是浮动操作按钮：

![编写浮动操作按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_12.jpg)

它在`activity_main.xml`文件中。这是定位和定义其外观的 XML 代码：

```kt
<com.google.android.material.floatingactionbutton
    .FloatingActionButton

   android:id="@+id/fab"
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:layout_gravity="bottom|end"
   android:layout_margin="@dimen/fab_margin"
   app:srcCompat="@android:drawable/ic_dialog_email" />
```

Android Studio 甚至提供了一个现成的 lambda 来处理对浮动操作按钮的点击。我们只需要在已提供的代码的`onClick`函数中添加一些代码，就可以使用`DialogNewNote`类。

浮动操作按钮通常用于应用程序的核心操作。例如，在电子邮件应用程序中，它可能用于启动新电子邮件；或者在便签应用程序中，它可能用于添加新便签。所以，让我们现在做这个。

在`MainActivity.kt`中，在`onCreate`函数中找到 Android Studio 提供的自动生成的代码；以下是完整的代码：

```kt
fab.setOnClickListener { view ->
   Snackbar.make(view, "Replace with your own action", 
 Snackbar.LENGTH_LONG)
 .setAction("Action", null).show()
}
```

在前面的代码中，请注意突出显示的行并删除它。现在在删除的代码的位置添加以下代码：

```kt
val dialog = DialogNewNote()
dialog.show(supportFragmentManager, "")
```

新代码创建了`DialogNewNote`类型的新对话框窗口，然后向用户显示它。

现在我们可以运行应用程序；点击浮动操作按钮并添加一条便签，类似于以下截图：

![编写浮动操作按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_13.jpg)

点击“确定”保存便签并返回到主布局。接下来，我们可以点击“显示便签”按钮，在对话框窗口中查看它，就像以下截图一样：

![编写浮动操作按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_14_14.jpg)

请注意，如果您添加第二个便笺，它将覆盖第一个，因为我们只有一个`Note`实例。此外，如果您关闭手机或完全关闭应用程序，那么便签将永远丢失。我们需要涵盖一些更多的 Kotlin 来解决这些问题。

# 摘要

在本章中，我们已经看到并实现了使用`DialogFragment`类的常见 UI 设计与对话框窗口。

当我们启动“Note to self”应用程序时，我们进一步迈出了一步，通过实现更复杂的对话框，可以从用户那里捕获信息。我们看到，`DialogFragment`使我们能够在对话框中拥有任何我们喜欢的 UI。

在下一章中，我们将开始解决一个明显的问题，即用户只能有一个便签，通过探索 Kotlin 的数据处理类。
