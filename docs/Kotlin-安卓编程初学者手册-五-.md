# Kotlin 安卓编程初学者手册（五）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：处理数据和生成随机数

我们取得了很好的进展。我们对 Android UI 选项和 Kotlin 的基础知识有了一个全面的了解。在前几章中，我们开始将这两个领域结合起来，并使用 Kotlin 代码操作 UI，包括一些新的小部件。然而，在构建自我备忘录应用程序时，我们在知识上遇到了一些空白。在本章中，我们将填补这些空白中的第一个，然后在下一章中，我们将使用这些新信息来继续应用程序。我们目前没有办法管理大量相关数据。除了声明、初始化和管理数十、数百甚至数千个属性或实例之外，我们如何让我们的应用程序用户拥有多个备忘录？我们还将快速了解一下随机数。

在本章中，我们将涵盖以下主题：

+   随机数

+   数组

+   一个简单的数组迷你应用

+   一个动态数组迷你应用

+   范围

+   ArrayLists

+   哈希映射

首先，让我们了解一下`Random`类。

# 一个随机的转移

有时，我们会在我们的应用程序中需要一个随机数，对于这些情况，Kotlin 为我们提供了`Random`类。这个类有很多可能的用途，比如如果我们的应用程序想要显示每日随机提示，或者一个需要在不同场景之间选择的游戏，或者一个随机提问的测验。

`Random`类是 Android API 的一部分，在我们的 Android 应用程序中完全兼容。

让我们看看如何创建随机数。`Random`类已经为我们做好了所有的工作。首先，我们需要创建一个`Random`对象，如下所示：

```kt
val randGenerator = Random()
```

然后，我们使用我们新对象的`nextInt`函数来生成一个在某个范围内的随机数。以下代码行使用我们的`randGenerator`对象生成随机数，并将结果存储在`ourRandomNumber`变量中：

```kt
var ourRandomNumber = randGenerator.nextInt(10)
```

我们输入的范围开始于零。因此，前一行将生成一个在 0 和 9 之间的随机数。如果我们想要一个在 1 和 10 之间的随机数，我们只需在同一行的代码末尾添加增量运算符：

```kt
ourRandomNumber ++
```

我们还可以使用`Random`对象使用`nextLong`、`nextFloat`和`nextDouble`获取其他类型的随机数。

# 使用数组处理大量数据

也许你会想知道当我们有很多变量需要跟踪时会发生什么。我们的自我备忘录应用程序有 100 条备忘录，或者游戏中的高分榜有前 100 名的分数？我们可以声明和初始化 100 个单独的变量，如下所示：

```kt
var note1 = Note()
var note2 = Note()
var note3 = Note()
// 96 more lines like the above
var note100 = Note()
```

或者，通过使用高分示例，我们可以使用以下代码：

```kt
var topScore1: Int
var topScore2: Int
// 96 more lines like the above
var topScore100: Int
```

立即，这段代码可能看起来笨拙，但是当有人获得新的最高分，或者我们想让我们的用户排序他们的备忘录显示顺序时，会怎样？使用高分榜场景，我们必须将每个变量中的分数向下移动一个位置。这是一个噩梦的开始，如下代码所示：

```kt
topScore100 = topScore99;
topScore99 = topScore98;
topScore98 = topScore97;
// 96 more lines like the above
topScore1 = score;
```

肯定有更好的方法。当我们有一整个数组的变量时，我们需要的是一个 Kotlin **数组**。数组是一个对象，最多可以容纳预定的固定最大数量的元素。每个元素都是一个具有一致类型的变量。

以下代码声明了一个可以容纳`Int`类型变量的数组；例如高分榜或一系列考试成绩：

```kt
var myIntArray: IntArray
```

我们也可以声明其他类型的数组，如下所示：

```kt
var myFloatArray: FloatArray
var myBooleanArray: BooleanArray
```

在使用这些数组之前，每个数组都需要有一个固定的最大分配存储空间。就像我们对其他对象所做的那样，我们必须在使用数组之前对其进行初始化，我们可以这样做：

```kt
myIntArray = IntArray(100)
myFloatArray = FloatArray(100)
myBooleanArray = BooleanArray(100)
```

前面的代码分配了最多`100`个适当类型的存储空间。想象一下，我们的变量仓库中有 100 个连续的存储空间。这些空间可能被标记为`myIntArray[0]`，`myIntArray[1]`和`myIntArray[2]`，每个空间都包含一个`Int`值。这里稍微令人惊讶的是，存储空间从零开始，而不是 1。因此，在一个 100 宽的数组中，存储空间将从 0 到 99。

我们可以初始化一些存储空间如下：

```kt
myIntArray [0] = 5
myIntArray [1] = 6
myIntArray [2] = 7
```

但是，请注意，我们只能将预声明的类型放入数组中，并且数组保存的类型永远不会改变，如下面的代码所示：

```kt
myIntArray [3] = "John Carmack" 
// Won't compile String not Int
```

因此，当我们有一个`Int`类型的数组时，每个`Int`变量被称为什么，我们如何访问其中存储的值？数组表示法语法替换了变量的名称。此外，我们可以对数组中的变量进行与常规变量相同的操作；如下所示：

```kt
myIntArray [3] = 123
```

前面的代码将值 123 分配给数组中的第 4 个位置。

这是使用数组的另一个示例，就像使用普通变量一样：

```kt
myIntArray [10] = myIntArray [9] - myIntArray [4]
```

前面的代码从数组的第 5 个位置中减去数组的第 10 个位置中存储的值，并将答案赋给数组的第 11 个位置。

我们还可以将数组中的值赋给相同类型的常规变量，如下所示：

```kt
Val myNamedInt = myIntArray[3]
```

但是，请注意，`myNamedInt`是一个独立的变量，对它的任何更改都不会影响存储在`IntArray`引用中的值。它在仓库中有自己的空间，与数组没有其他联系。

在前面的示例中，我们没有检查任何字符串或对象。实际上，字符串是对象，当我们想要创建对象数组时，我们会稍微不同地处理它们；看一下下面的代码：

```kt
var someStrings = Array<String>(5) { "" }
// You can remove the String keyword because it can be inferred like 
// this
var someMoreStrings = Array(5) { "" }

someStrings[0]= "Hello "
someStrings[1]= "from "
someStrings[2]= "inside "
someStrings[3]= "the "
someStrings[4]= "array "
someStrings[5]= "Oh dear "
// ArrayIndexOutOfBoundsException
```

前面的代码声明了一个 String 对象数组，最多可以容纳五个对象。请记住，数组从 0 开始，因此有效的位置是从 0 到 4。如果尝试使用无效的位置，则会收到**ArrayIndexOutOfBoundsException**错误。如果编译器注意到错误，则代码将无法编译；但是，如果编译器无法发现错误，并且在应用程序执行时发生错误，则应用程序将崩溃。

我们可以避免这个问题的唯一方法是知道规则-数组从 0 开始，直到它们的长度减 1。因此，`someArray[9]`是数组中的第十个位置。我们还可以使用清晰易读的代码，这样更容易评估我们所做的事情并更容易发现问题。

您还可以在声明数组的同时初始化数组的内容，如下面的代码所示：

```kt
        var evenMoreStrings: Array<String> = 
                arrayOf("Houston", "we", "have", "an", "array")
```

前面的代码使用内置的 Kotlin 函数`arrayOf`来初始化数组。

在 Kotlin 中，您可以声明和初始化数组的方式非常灵活。我们还没有接近覆盖我们可以使用数组的所有方式，即使在书的最后，我们仍然不会覆盖所有内容。然而，让我们深入一点。

## 数组是对象

将数组变量视为给定类型的一组变量的地址。例如，使用仓库类比，`someArray`可以是过道编号。因此，`someArray[0]`和`someArray[1]`是过道编号，后跟过道中的位置编号。

因为数组也是对象，它们具有我们可以使用的函数和属性，如下面的示例所示：

```kt
val howBig = someArray.size
```

在前面的示例中，我们将`someArray`的长度（即大小）分配给名为`howBig`的`Int`变量。

我们甚至可以声明一个数组的数组。这是一个数组，其中每个位置都隐藏着另一个数组；如下所示：

```kt
val cities = arrayOf("London", "New York", "Yaren")
val countries = arrayOf("UK", "USA", "Nauru")

val countriesAndCities = arrayOf(countries, cities)

Log.d("The capital of " +
   countriesAndCities[0][0],
   " is " +
   countriesAndCities[1][0])
```

前面的`Log`代码将在 logcat 窗口中输出以下文本：

```kt
The capital of UK:  is London

```

让我们在一个真实的应用程序中使用一些数组，试着理解如何在真实代码中使用它们以及它们可能被用来做什么。

# 一个简单的迷你应用程序数组示例

让我们做一个简单的工作数组示例。您可以在可下载的代码包中找到此项目的完整代码。它可以在`Chapter15/Simple Array Example/MainActivity.kt`文件中找到。

创建一个**Empty Activity**项目模板的项目，并将其命名为`Simple Array Example`。

首先，我们声明我们的数组，分配了五个空间，并为每个元素初始化了值。然后，我们将每个值输出到**logcat**窗口。

这与我们之前看到的例子略有不同，因为我们在声明数组的同时声明了大小。

在`setContentView`调用后的`onCreate`函数中添加以下代码：

```kt
// Declaring an array
// Allocate memory for a maximum size of 5 elements
val ourArray = IntArray(5)

// Initialize ourArray with values
// The values are arbitrary, but they must be Int
// The indexes are not arbitrary. Use 0 through 4 or crash!

ourArray[0] = 25
ourArray[1] = 50
ourArray[2] = 125
ourArray[3] = 68
ourArray[4] = 47

//Output all the stored values
Log.i("info", "Here is ourArray:")
Log.i("info", "[0] = " + ourArray[0])
Log.i("info", "[1] = " + ourArray[1])
Log.i("info", "[2] = " + ourArray[2])
Log.i("info", "[3] = " + ourArray[3])
Log.i("info", "[4] = " + ourArray[4])
```

接下来，我们将数组的每个元素相加，就像我们对普通的`Int`类型变量一样。请注意，当我们将数组元素相加时，我们为了清晰起见在多行上这样做。将我们刚刚讨论的代码添加到`MainActivity.kt`中，如下所示：

```kt
/*
   We can do any calculation with an array element
   provided it is appropriate to the contained type
   Like this:
*/
val answer = ourArray[0] +
      ourArray[1] +
      ourArray[2] +
      ourArray[3] +
      ourArray[4]

Log.i("info", "Answer = $answer")
```

运行示例，并注意 logcat 窗口中的输出。请记住，在模拟器显示上不会发生任何事情，因为所有输出都将发送到 Android Studio 中的 logcat 窗口；以下是输出：

```kt
info﹕ Here is ourArray:
info﹕ [0] = 25
info﹕ [1] = 50
info﹕ [2] = 125
info﹕ [3] = 68
info﹕ [4] = 47
info﹕ Answer = 315 

```

我们声明一个名为`ourArray`的数组来保存`Int`值，然后为该类型的最多五个值分配空间。

接下来，我们为`ourArray`的五个空间分配一个值。记住第一个空间是`ourArray[0]`，最后一个空间是`ourArray[4]`。

接下来，我们简单地将每个数组位置的值打印到 logcat 窗口中，从输出中我们可以看到它们保存了我们在上一步中初始化的值。然后，我们将`ourArray`中的每个元素相加，并将它们的值初始化为`answer`变量。然后，我们将`answer`打印到 logcat 窗口中，我们可以看到确实，所有的值都被相加在一起，就像它们是普通的`Int`类型一样（它们确实是），只是以不同的方式存储。

# 使用数组进行动态操作

正如我们在本节开头讨论的，如果我们需要单独声明和初始化数组的每个元素，那么使用数组并没有比使用普通变量带来很大的好处。让我们看一个动态声明和初始化数组的例子。

## 动态数组示例

您可以在下载包中找到此示例的工作项目。它可以在`Chapter15/Dynamic Array Example/MainActivity.kt`文件中找到。

创建一个**Empty Activity**模板的项目，并将其命名为`Dynamic Array Example`。

在`onCreate`函数中的`setContentView`调用后，输入以下代码。在我们讨论和分析代码之前，看看你能否猜出输出结果是什么：

```kt
// Declaring and allocating in one step
val ourArray = IntArray(1000)

// Let's initialize ourArray using a for loop
// Because more than a few variables is allot of typing!

for (i in 0..999) {

   // Put the value into ourArray
   // At the position decided by i.
   ourArray[i] = i * 5

   //Output what is going on
   Log.i("info", "i = $i")
   Log.i("info", "ourArray[i] = ${ ourArray[i]}")
}
```

运行示例应用程序。请记住，屏幕上不会发生任何事情，因为所有输出都将发送到我们在 Android Studio 中的 logcat 窗口；以下是输出：

```kt
info﹕ i = 0
info﹕ ourArray[i] = 0
info﹕ i = 1
info﹕ ourArray[i] = 5
info﹕ i = 2
info﹕ ourArray[i] = 10

```

为了简洁起见，循环的 994 次迭代已被删除：

```kt
info﹕ ourArray[i] = 4985
info﹕ i = 998
info﹕ ourArray[i] = 4990
info﹕ i = 999
info﹕ ourArray[i] = 4995

```

首先，我们声明并分配了一个名为`ourArray`的数组，以保存最多 1,000 个`Int`值。请注意，这次我们在一行代码中执行了两个步骤：

```kt
val ourArray = IntArray(1000)
```

然后，我们使用了一个设置为循环 1,000 次的`for`循环：

```kt
for (i in 0..999) {
```

我们初始化数组中的空间，从 0 到 999，其值为`i`乘以 5，如下所示：

```kt
   ourArray[i] = i * 5
```

然后，为了演示`i`的值以及数组中每个位置的值，我们输出`i`的值，然后是数组对应位置的值，如下所示：

```kt
   //Output what is going on
   Log.i("info", "i = $i")
   Log.i("info", "ourArray[i] = ${ ourArray[i]}")
```

所有这些都发生了 1,000 次，产生了我们所看到的输出。当然，我们还没有在真实的应用程序中使用这种技术，但我们很快将使用它来使我们的自我备忘录应用程序保存几乎无限数量的备忘录。

# ArrayLists

`ArrayList`对象就像普通数组，但功能更强大。它克服了数组的一些缺点，比如必须预先确定其大小。它添加了几个有用的函数来使其数据易于管理，并被 Android API 中的许多类使用。这最后一点意味着如果我们想要使用 API 的某些部分，我们需要使用`ArrayList`。在第十六章中，*适配器和回收器*，我们将真正地让`ArrayList`发挥作用。首先是理论。

让我们看一些使用`ArrayList`的代码：

```kt
// Declare a new ArrayList called myList 
// to hold Int variables
val myList: ArrayList<Int>

// Initialize myList ready for use
myList = ArrayList()
```

在前面的代码中，我们声明并初始化了一个名为`myList`的新`ArrayList`对象。我们也可以在一步中完成这个操作，就像下面的代码所示：

```kt
val myList: ArrayList<Int> = ArrayList()
```

到目前为止，这并不特别有趣，所以让我们看看我们实际上可以用`ArrayList`做些什么。这次我们使用一个`String ArrayList`对象：

```kt
// declare and initialize a new ArrayList
val myList = ArrayList<String>()

// Add a new String to myList in 
// the next available location
myList.add("Donald Knuth")
// And another
myList.add("Rasmus Lerdorf")
// We can also choose 'where' to add an entry
myList.add(1,"Richard Stallman")

// Is there anything in our ArrayList?
if (myList.isEmpty()) {
   // Nothing to see here
} else {
   // Do something with the data
}

// How many items in our ArrayList?
val numItems = myList.size

// Now where did I put Richard?
val position = myList.indexOf("Richard Stallman")
```

在前面的代码中，我们看到我们可以在`ArrayList`对象上使用`ArrayList`类的一些有用的函数；这些函数如下：

+   我们可以添加一个条目（`myList.add`）

+   我们可以在特定位置添加一个条目（`myList.add(x, value)`）

+   我们可以检查`ArrayList`实例是否为空（`myList.isEmpty()`）

+   我们可以看到`ArrayList`实例的大小（`myList.size`）

+   我们可以获取给定条目的当前位置（`myList.indexOf...`）

### 注意

`ArrayList`类中甚至有更多的函数，但是到目前为止我们已经看到的足以完成这本书了。

有了所有这些功能，我们现在只需要一种方法来动态处理`ArrayList`实例。这就是增强`for`循环的条件的样子：

```kt
for (String s : myList)
```

前面的例子将逐个遍历`myList`中的所有项目。在每一步中，`s`将保存当前的`String`条目。

因此，这段代码将把我们上一节`ArrayList`代码示例中的所有杰出程序员打印到 logcat 窗口中，如下所示：

```kt
for (s in myList) {
   Log.i("Programmer: ", "$s")
}
```

它的工作原理是`for`循环遍历`ArrayList`中的每个`String`，并将当前的`String`条目分配给`s`。然后，依次对每个`s`使用`Log…`函数调用。前面的循环将在 logcat 窗口中创建以下输出：

```kt
Programmer:: Donald Knuth
Programmer:: Richard Stallman
Programmer:: Rasmus Lerdorf

```

`for`循环已经输出了所有的名字。Richard Stallman 之所以在 Donald Knuth 和 Rasmus Lerdof 之间是因为我们在特定位置（1）插入了他，这是`ArrayList`中的第二个位置。`insert`函数调用不会删除任何现有的条目，而是改变它们的位置。

有一个新的新闻快讯！

# 数组和 ArrayLists 是多态的

我们已经知道我们可以将对象放入数组和`ArrayList`对象中。然而，多态意味着它们可以处理多个不同类型的对象，只要它们有一个共同的父类型 - 都在同一个数组或`ArrayList`中。

在第十章，面向对象编程中，我们学到多态意味着多种形式。但在数组和`ArrayList`的上下文中，对我们意味着什么呢？

在其最简单的形式中，它意味着任何子类都可以作为使用超类的代码的一部分。

例如，如果我们有一个`Animals`数组，我们可以把任何`Animal`子类对象放在`Animals`数组中，比如`Cat`和`Dog`。

这意味着我们可以编写更简单、更易于理解和更易于更改的代码：

```kt
// This code assumes we have an Animal class
// And we have a Cat and Dog class that 
// inherits from Animal
val myAnimal = Animal()
val myDog = Dog()
val myCat = Cat()
val myAnimals = arrayOfNulls<Animal>(10)
myAnimals[0] = myAnimal // As expected
myAnimals[1] = myDog // This is OK too
myAnimals[2] = myCat // And this is fine as well
```

此外，我们可以为超类编写代码，并依赖于这样一个事实，即无论它被子类化多少次，在一定的参数范围内，代码仍然可以工作。让我们继续我们之前的例子如下：

```kt
// 6 months later we need elephants
// with its own unique aspects
// If it extends Animal we can still do this
val myElephant = Elephant()
myAnimals[3] = myElephant // And this is fine as well
```

我们刚刚讨论的一切对于`ArrayLists`也是真实的。

# 哈希映射

Kotlin 的`HashMap`很有趣；它们是`ArrayList`的一种表亲。它们封装了一些有用的数据存储技术，否则对我们来说可能会相当技术性。在回到自己的笔记应用之前，值得看一看`HashMap`。

假设我们想要存储角色扮演游戏中许多角色的数据，每个不同的角色由`Character`类型的对象表示。

我们可以使用一些我们已经了解的 Kotlin 工具，比如数组或`ArrayList`。然而，使用`HashMap`，我们可以为每个`Character`对象提供一个唯一的键或标识符，并使用相同的键或标识符访问任何这样的对象。

### 注意

"哈希"一词来自于将我们选择的键或标识符转换为`HashMap`类内部使用的东西的过程。这个过程被称为**哈希**。

我们选择的键或标识符可以访问任何`Character`实例。在`Character`类的情况下，一个好的键或标识符候选者是角色的名字。

每个键或标识符都有一个相应的对象；在这种情况下，是`Character`实例。这被称为**键值对**。

我们只需给`HashMap`一个键，它就会给我们相应的对象。我们不需要担心我们存储了角色的哪个索引，比如 Geralt、Ciri 或 Triss；只需将名字传递给`HashMap`，它就会为我们完成工作。

让我们看一些例子。你不需要输入任何代码；只需熟悉它的工作原理。

我们可以声明一个新的`HashMap`实例来保存键和`Character`实例，如下所示：

```kt
val characterMap: Map<String, Character>
```

前面的代码假设我们已经编写了一个名为`Character`的类。然后我们可以初始化`HashMap`实例如下：

```kt
characterMap = HashMap()
```

然后，我们可以添加一个新的键及其关联的对象，如下所示：

```kt
characterMap.put("Geralt", Character())
characterMap.put("Ciri", Character())
characterMap.put("Triss", Character())
```

### 提示

所有示例代码都假设我们可以以某种方式给`Character`实例赋予它们的唯一属性，以反映它们在其他地方的内部差异。

然后，我们可以按如下方式从`HashMap`实例中检索条目：

```kt
val ciri = characterMap.get("Ciri")
```

或者，我们可以直接使用`Character`类的函数：

```kt
characterMap.get("Geralt").drawSilverSword()

// Or maybe call some other hypothetical function
characterMap.get("Triss").openFastTravelPortal("Kaer Morhen")
```

前面的代码调用了假设的`drawSilverSword`和`openFastTravelPortal`函数，这些函数是存储在`HashMap`实例中的`Character`类实例的假设函数。

有了这些新的工具包，如数组、`ArrayList`、`HashMap`，以及它们的多态性，我们可以继续学习一些更多的 Android 类，很快我们将用它们来增强我们的备忘录应用。

# 备忘录应用

尽管我们已经学到了很多，但我们还没有准备好将解决方案应用到备忘录应用中。我们可以更新我们的代码，将大量的`Note`实例存储在`ArrayList`中，但在这之前，我们还需要一种方法来在 UI 中显示`ArrayList`的内容。把整个东西放在`TextView`实例中看起来不好。

答：解决方案是**适配器**和一个名为`RecyclerView`的特殊 UI 布局。我们将在下一章中介绍它们。

# 常见问题

问：一个只能进行真实计算的计算机如何可能生成真正的随机数？

问：实际上，计算机无法创建真正随机的数字，但`Random`类使用一个**种子**，产生一个在严格的统计检验下被认为是真正随机的数字。要了解更多关于种子和生成随机数的信息，请查看以下文章：[`en.wikipedia.org/wiki/Random_number_generation`](https://en.wikipedia.org/wiki/Random_number_generation)。

# 总结

在本章中，我们看了如何使用简单的 Kotlin 数组来存储大量数据，只要它们是相同类型的数据。我们还使用了`ArrayList`，它类似于一个带有许多额外功能的数组。此外，我们发现数组和`ArrayList`都是多态的，这意味着一个数组（或`ArrayList`）可以容纳多个不同的对象，只要它们都是从同一个父类派生的。

我们还了解了`HashMap`类，它也是一种数据存储解决方案，但允许以不同的方式访问。

在下一章中，我们将学习关于`Adapter`和`RecyclerView`，将理论付诸实践，并增强我们的备忘录应用。


# 第十六章：适配器和回收器

在这一章中，我们将取得很大的进展。我们将首先学习适配器和列表的理论。然后，我们将看看如何在 Kotlin 代码中使用`RecyclerAdapter`实例，并将`RecyclerView`小部件添加到布局中，它作为我们 UI 的列表，然后通过 Android API 的明显魔法将它们绑定在一起，以便`RecyclerView`实例显示`RecyclerAdapter`实例的内容，并允许用户滚动查看一个充满`Note`实例的`ArrayList`实例的内容。你可能已经猜到，我们将使用这种技术在 Note to self 应用程序中显示我们的笔记列表。

在这一章中，我们将做以下事情：

+   探索另一种 Kotlin 类 - **内部类**

+   查看适配器的理论并检查将它们绑定到我们的 UI 上

+   使用`RecyclerView`实现布局

+   为在`RecyclerView`中使用的列表项布局

+   使用`RecyclerAdapter`实现适配器

+   将适配器绑定到`RecyclerView`

+   在`ArrayList`中存储笔记，并通过`RecycleAdapter`在`RecyclerView`中显示它们

很快，我们将拥有一个自管理的布局，用来保存和显示所有的笔记，所以让我们开始吧。

# 内部类

在这个项目中，我们将使用一种我们以前没有见过的类 - **内部**类。假设我们有一个名为`SomeRegularClass`的常规类，其中有一个名为`someRegularProperty`的属性和一个名为`someRegularFunction`的函数，就像下面的代码中所示：

```kt
class SomeRegularClass{
    var someRegularProperty = 1    

    fun someRegularFunction(){
    }
}
```

内部类是在常规类内部声明的类，就像下面的高亮代码中所示：

```kt
class SomeRegularClass{
    var someRegularProperty = 1

    fun someRegularFunction(){
    }

    inner class MyInnerClass {
 val myInnerProperty = 1

 fun myInnerFunction() {
 }
 }

}
```

上面高亮显示的代码显示了一个名为`MyInnerClass`的内部类，其中有一个名为`myInnerProperty`的属性和一个名为`myInnerFunction`的函数。

一个优点是外部类可以通过声明它的实例来使用内部类的属性和函数，就像下面的代码片段中所示：

```kt
class SomeRegularClass{
    var someRegularProperty = 1

    val myInnerInstance = MyInnerClass()

    fun someRegularFunction(){
        val someVariable = myInnerInstance.myInnerProperty
 myInnerInstance.myInnerFunction()
    }

    inner class MyInnerClass {
        val myInnerProperty = 1

        fun myInnerFunction() {
        }

    }
}
```

此外，内部类还可以从`myInnerFunction`函数中访问常规类的属性。下面的代码片段展示了这一点：

```kt
fun myInnerFunction() {
 someRegularProperty ++
}
```

在类中定义新类型并创建实例并共享数据的能力在某些情况下非常有用，并且用于封装。我们将在本章后面的 Note to self 应用程序中使用内部类。

# RecyclerView 和 RecyclerAdapter

在第五章中，我们使用了`ScrollView`小部件，并用一些`CardView`小部件填充它，以便我们可以看到它滚动。我们可以利用我们刚刚学到的关于`ArrayList`的知识，创建一个`TextView`对象的容器，用它们来填充`ScrollView`小部件，并在每个`TextView`中放置一个笔记的标题。这听起来像是在 Note to self 应用程序中显示每个笔记并使其可点击的完美解决方案。

我们可以在 Kotlin 代码中动态创建`TextView`对象，将它们的`text`属性设置为笔记的标题，然后将`TextView`对象添加到`ScrollView`中包含的`LinearLayout`中。但这并不完美。

## 显示大量小部件的问题

这可能看起来不错，但是如果有几十个、几百个，甚至上千个笔记怎么办？我们不能在内存中有成千上万个`TextView`对象，因为 Android 设备可能会因为尝试处理如此大量的数据而耗尽内存，或者至少会变得非常缓慢。

现在，想象一下我们希望（我们确实希望）`ScrollView`小部件中的每个笔记都显示它是重要的、待办事项还是想法。还有关于笔记文本的简短片段呢？

我们需要设计一些巧妙的代码，从`ArrayList`中加载和销毁`Note`对象和`TextView`对象。这是可以做到的 - 但要高效地做到这一点远非易事。

## 解决显示大量小部件的问题

幸运的是，这是移动开发人员如此常见的问题，以至于 Android API 中已经内置了解决方案。

我们可以在 UI 布局中添加一个名为`RecyclerView`的小部件（就像一个环保的`ScrollView`，但也有增强功能）。`RecyclerView`类是为我们讨论的问题设计的解决方案。此外，我们需要使用一种特殊类型的类与`RecyclerView`进行交互，这个类了解`RecyclerView`的工作原理。我们将使用一个**适配器**与它进行交互。我们将使用`RecyclerAdapter`类，继承它，定制它，然后使用它来控制我们的`ArrayList`中的数据，并在`RecyclerView`类中显示它。

让我们更多地了解一下`RecyclerView`和`RecyclerAdapter`类的工作原理。

## 如何使用 RecyclerView 和 RecyclerAdapter

我们已经知道如何存储几乎无限的笔记 - 我们可以在`ArrayList`中这样做，尽管我们还没有实现它。我们还知道有一个名为`RecyclerView`的 UI 布局，专门设计用于显示潜在的长列表数据。我们只需要看看如何将它付诸实践。

要向我们的布局中添加一个`RecyclerView`小部件，我们只需从调色板中像往常一样拖放它。

### 提示

现在不要这样做。让我们先讨论一会儿。

`RecyclerView`类在 UI 设计中将如下所示：

![如何使用 RecyclerView 和 RecyclerAdapter](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_01.jpg)

然而，这种外观更多地代表了可能性，而不是在应用程序中的实际外观。如果我们在添加了`RecyclerView`小部件后立即运行应用程序，我们将只会得到一个空白屏幕。

要实际使用`RecyclerView`小部件，我们需要做的第一件事是决定列表中的每个项目将是什么样子。它可以只是一个单独的`TextView`小部件，也可以是整个布局。我们将使用`LinearLayout`。为了清晰和具体，我们将使用一个`LinearLayout`实例，它为我们的`RecyclerView`小部件中的每个项目包含三个`TextView`小部件。这将允许我们显示笔记状态（重要/想法/待办事项）、笔记标题以及实际笔记内容中的一小段文本。

列表项需要在自己的 XML 文件中定义，然后`RecyclerView`小部件可以容纳多个此列表项布局的实例。

当然，这一切都没有解释我们如何克服管理显示在哪个列表项中的数据的复杂性，以及如何从`ArrayList`中检索数据。

这个数据处理是由我们自己定制的`RecyclerAdapter`来处理的。`RecyclerAdapter`类实现了`Adapter`接口。我们不需要知道`Adapter`内部是如何工作的，我们只需要重写一些函数，然后`RecyclerAdapter`将负责与我们的`RecyclerView`小部件进行通信的所有工作。

将`RecyclerAdapter`的实现与`RecyclerView`小部件连接起来的过程，肯定比将 20 个`TextView`小部件拖放到`ScrollView`小部件上要复杂得多，但一旦完成，我们就可以忘记它，它将继续工作并自行管理，无论我们向`ArrayList`中添加了多少笔记。它还具有处理整洁格式和检测列表中哪个项目被点击的内置功能。

我们需要重写`RecyclerAdapter`的一些函数，并添加一些我们自己的代码。

## 我们将如何使用 RecyclerView 与 RecyclerAdapter 和笔记的 ArrayList

看一下所需步骤的大纲，这样我们就知道可以期待什么。为了让整个事情运转起来，我们需要做以下事情：

1.  删除临时按钮和相关代码，然后向我们的布局中添加一个具有特定`id`属性的`RecyclerView`小部件。

1.  创建一个 XML 布局来表示列表中的每个项目。我们已经提到列表中的每个项目将是一个包含三个`TextView`小部件的`LinearLayout`。

1.  创建一个新的类，该类继承自`RecyclerAdapter`，并添加代码到几个重写的函数中，以控制它的外观和行为，包括使用我们的列表项布局和装满`Note`实例的`ArrayList`。

1.  在`MainActivity`中添加代码，以使用`RecyclerAdapter`和`RecyclerView`小部件，并将其绑定到我们的`ArrayList`实例。

1.  在`MainActivity`中添加一个`ArrayList`实例，用于保存所有我们的笔记，并更新`createNewNote`函数，以将在`DialogNewNote`类中创建的任何新笔记添加到这个`ArrayList`中。

让我们逐步实现这些步骤。

# 向“Note to Self”项目添加 RecyclerView、RecyclerAdapter 和 ArrayList

打开“Note to self”项目。作为提醒，如果您想要查看基于完成本章的完整代码和工作中的应用程序，可以在`Chapter16/Note to self`文件夹中找到。

### 提示

由于本章中所需的操作在不同的文件、类和函数之间跳转，我鼓励您在首选的文本编辑器中打开下载包中的文件，以供参考。

## 删除临时的“显示笔记”按钮并添加 RecyclerView

接下来的几个步骤将消除我们在第十四章中添加的临时代码，*Android 对话框窗口*，并设置我们的`RecyclerView`准备好在本章后期绑定到`RecyclerAdapter`：

1.  在`content_main.xml`文件中，删除临时的`Button`，该按钮具有`id`为`button`，我们之前为测试目的添加的。

1.  在`MainActivity.kt`的`onCreate`函数中，删除`Button`实例的声明和初始化，以及处理其点击的 lambda，因为这段代码现在会产生错误。稍后在本章中，我们将删除更多临时代码。删除下面显示的代码：

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

1.  现在，切换回设计视图中的`content_main.xml`，并从调色板的**常用**类别中将一个**RecyclerView**小部件拖放到布局中。

1.  将其`id`属性设置为`recyclerView`。

现在，我们已经从项目中删除了临时的 UI 方面，并且我们有一个完整的`RecyclerView`小部件，具有一个独特的`id`属性，可以在我们的 Kotlin 代码中引用。

## 为 RecyclerView 创建列表项

接下来，我们需要一个布局来表示`RecyclerView`小部件中的每个项目。如前所述，我们将使用一个包含三个`TextView`小部件的`LinearLayout`实例。

这些是创建用于`RecyclerView`中使用的列表项所需的步骤：

1.  在项目资源管理器中右键单击`layout`文件夹，然后选择**新建 | 布局资源文件**。在**名称：**字段中输入`listitem`，并将**根元素：**设置为`LinearLayout`。默认的方向属性是垂直的，这正是我们需要的。

1.  查看下一个屏幕截图，以了解我们在本节剩余步骤中要实现的目标。我已经对其进行了注释，以显示成品应用程序中的每个部分将是什么样子：![为 RecyclerView 创建列表项](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_02.jpg)

1.  将三个`TextView`实例拖放到布局中，一个在另一个上方，如参考屏幕截图所示。第一个（顶部）将保存笔记状态/类型（想法/重要/待办事项），第二个（中间）将保存笔记标题，第三个（底部）将保存笔记本身的片段。

1.  根据以下表格中显示的内容，配置`LinearLayout`实例和`TextView`小部件的各种属性：

| **小部件类型** | **属性** | **要设置的值** |
| --- | --- | --- |
| LinearLayout | `layout_height` | `wrap_contents` |
| LinearLayout | `Layout_Margin all` | `5dp` |
| TextView（顶部） | `id` | `textViewStatus` |
| TextView（顶部） | `textSize` | `24sp` |
| TextView（顶部） | `textColor` | `@color/colorAccent` |
| TextView（中间） | `id` | `textViewTitle` |
| TextView（中间） | `textSize` | `24sp` |
| TextView（顶部） | `id` | `textViewDescription` |

现在我们在主布局中有一个`RecylerView`小部件和一个用于列表中每个项目的布局。我们可以继续编写我们的`RecyclerAdapter`实现。

## 编写 RecyclerAdapter 类

现在我们将创建并编写一个全新的类。让我们称我们的新类为`NoteAdapter`。以通常的方式在与`MainActivity`类（以及所有其他类）相同的文件夹中创建一个名为`NoteAdapter`的新类。

通过添加这些`import`语句并继承`RecyclerView.Adapter`类来编辑`NoteAdapter`类的代码，然后添加如下所示的两个属性。编辑`NoteAdapter`类，使其与我们刚刚讨论过的代码相同：

```kt
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class NoteAdapter(
   private val mainActivity: MainActivity, 
   private val noteList: List<Note>) 
   : RecyclerView.Adapter<NoteAdapter.ListItemHolder>() {

}
```

在前面的代码中，我们使用主构造函数声明和初始化了`NoteAdapter`类的两个属性。注意构造函数的参数。它接收一个`MainActivity`引用以及一个`List`引用。这意味着当我们使用这个类时，我们需要发送一个对这个应用程序的主活动（`MainActivity`）的引用，以及一个`List`引用。我们很快就会看到我们如何使用`MainActivity`的引用，但我们可以合理地猜测，带有`<Note>`类型的`List`引用将是对我们很快在`MainActivity`类中编写的`Note`实例的引用。`NoteAdapter`将永久持有所有用户笔记的引用。

然而，您会注意到类声明和代码的其他部分都被红色下划线标出，显示我们的代码中存在错误。

第一个错误是因为我们需要重写`RecylerView.Adapter`类（我们正在继承的类）的一些抽象函数。

### 注意

我们在第十一章*Kotlin 中的继承*中讨论了抽象类及其函数。

最快的方法是点击类声明，按住*Alt*键，然后点击*Enter*键。选择**实现成员**，如下一个截图所示：

![编写 RecyclerAdapter 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_03.jpg)

在随后的窗口中，按住*Shift*键并左键单击所有三个选项（要添加的函数），然后点击**确定**。这个过程添加了以下三个函数：

+   `onCreateViewHolder`函数在需要列表项的布局时调用

+   `onBindViewHolder`函数在将`RecyclerAdapter`实例绑定到布局中的`RecyclerView`实例时调用

+   `getItemCount`函数将用于返回`ArrayList`中`Note`实例的数量

我们很快将为这些函数中的每一个添加代码，以在特定时间做出所需的工作。

然而，请注意，我们的代码中仍然存在多个错误，包括新生成的函数以及类声明中。我们需要做一些工作来解决这些错误。

错误是因为`NoteAdapter.ListItemHolder`类不存在。当我们扩展`NoteAdapter`时，我们添加了`ListItemHolder`。这是我们选择的类类型，将用作每个列表项的持有者。目前它不存在 - 因此出现错误。另外两个函数也因为同样的原因出现了相同的错误，因为当我们要求 Android Studio 实现缺失的函数时，它们是自动生成的。

让我们通过开始创建所需的`ListItemHolder`类来解决这个问题。对于`ListItemHolder`实例与`NoteAdapter`共享数据/变量对我们很有用，因此我们将`ListItemHolder`创建为内部类。

点击类声明中的错误，然后选择**创建类'ListItemHolder'**，如下一个截图所示：

![编写 RecyclerAdapter 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_05.jpg)

在随后的弹出窗口中，选择**NoteAdapter**以在`NoteAdapter`内生成`ListItemHolder`。

以下代码已添加到`NoteAdapter`类中：

```kt
class ListItemHolder {

}
```

但我们仍然有多个错误。让我们现在修复其中一个。将鼠标悬停在类声明中的红色下划线错误上，如下一个截图所示：

![编写 RecyclerAdapter 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_06.jpg)

错误消息显示**Type argument is not within its bounds. Expected:** **RecyclerView.ViewHolder! Found: NoteAdapter.ListItemHolder**。这是因为我们可能已经添加了`ListItemHolder`，但`ListItemHolder`必须也实现`RecyclerView.ViewHolder`才能作为正确的类型使用。

修改`ListItemHolder`类的声明以匹配此代码：

```kt
    inner class ListItemHolder(view: View) : 
         RecyclerView.ViewHolder(view), 
         View.OnClickListener {
```

现在`NoteAdapter`类声明中的错误已经消失，但因为我们还实现了`View.OnClickListener`，我们需要实现`onClick`函数。此外，`ViewHolder`没有提供默认构造函数，所以我们需要添加。将以下`onClick`函数（现在为空）和这个`init`块（现在为空）添加到`ListItemHolder`类中：

```kt
init {
}

override fun onClick(view: View) {
}
```

### 提示

确保你添加的代码是在内部的`ListItemHolder`类中，而不是`NoteAdapter`类中。

让我们清理掉最后剩下的错误。当`onBindViewHolder`函数被自动生成时，Android Studio 没有为`holder`参数添加类型。这导致函数和类声明中出现错误。根据下面的代码更新`onBindViewHolder`函数的签名：

```kt
override fun onBindViewHolder(
   holder: ListItemHolder, position: Int) {
```

在`onCreateViewHolder`函数签名中，返回类型没有被自动生成。修改`onCreateViewHolder`函数的签名，如下面的代码所示：

```kt
    override fun onCreateViewHolder(
       parent: ViewGroup, viewType: Int): ListItemHolder {
```

作为最后一点良好的整理，让我们删除自动生成但不需要的三个`// TODO…`注释。每个自动生成的函数中都有一个。它们看起来像下一个截图中突出显示的那样：

![编写 RecyclerAdapter 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_10.jpg)

当你删除`TODO…`注释时，会出现更多的错误。我们需要在一些自动生成的函数中添加`return`语句。随着我们继续编写类，我们将会这样做。

经过多次调整和自动生成，我们最终有了一个几乎没有错误的`NoteAdapter`类，包括重写的函数和一个内部类，我们可以编写代码来使我们的`RecyclerAdapter`实例工作。此外，我们可以编写代码来响应每个`ListItemHolder`实例上的点击（在`onClick`中）。

接下来是代码在这个阶段应该看起来的完整清单（不包括导入语句）：

```kt
class NoteAdapter(
  private val mainActivity: MainActivity,
  private val noteList: List<Note>)
  : RecyclerView.Adapter<NoteAdapter.ListItemHolder>() {

    override fun onCreateViewHolder(
         parent: ViewGroup, viewType: Int):
         ListItemHolder {

    }

    override fun getItemCount(): Int {

    }

    override fun onBindViewHolder(
         holder: ListItemHolder, 
         position: Int) {

    }

    inner class ListItemHolder(view: View) : 
          RecyclerView.ViewHolder(view),
          View.OnClickListener {

        init {

        }

        override fun onClick(view: View) {
        }
    }
}
```

### 提示

你本可以只复制并粘贴前面的代码，而不必忍受之前页面的折磨，但那样你就不会如此近距离地体验到实现接口和内部类的过程。

现在，让我们编写函数并使这个类运行起来。

### 编写 onCreateViewHolder 函数

接下来，我们将调整自动生成的`onCreateViewHolder`函数。将下面的代码行添加到`onCreateViewHolder`函数中并学习它们：

```kt
override fun onCreateViewHolder(
   parent: ViewGroup, viewType: Int): 
   ListItemHolder {

 val itemView = LayoutInflater.from(parent.context)
 .inflate(R.layout.listitem, parent, false)

 return ListItemHolder(itemView)
}
```

这段代码通过使用`LayoutInflater`和我们新设计的`listitem`布局来初始化`itemView`。然后返回一个新的`ListItemHolder`实例，包括一个已经膨胀并且可以立即使用的布局。

### 编写 onBindViewHolder 函数

接下来，我们将调整`onBindViewHolder`函数。添加高亮代码，使函数与此代码相同，并确保也学习代码：

```kt
override fun onBindViewHolder(
         holder: ListItemHolder, position: Int) {

   val note = noteList[position]
 holder.title.text = note.title

 // Show the first 15 characters of the actual note
 holder.description.text = 
 note.description!!.substring(0, 15)

 // What is the status of the note?
 when {
 note.idea -> holder.status.text = 
 mainActivity.resources.getString(R.string.idea_text)

 note.important -> holder.status.text = 
 mainActivity.resources.getString(R.string.important_text)

 note.todo -> holder.status.text = 
 mainActivity.resources.getString(R.string.todo_text)
 }

}
```

首先，代码将文本截断为 15 个字符，以便在列表中看起来合理。请注意，如果用户输入的笔记长度小于 15 个字符，这将导致崩溃。读者可以自行回到这个项目中，发现解决这个缺陷的方法。

然后检查它是什么类型的笔记（想法/待办/重要），并使用`when`表达式从字符串资源中分配适当的标签。

这段新代码在`holder.title`，`holder.description`和`holder.status`的代码中留下了一些错误，因为我们需要将它们添加到我们的`ListItemHolder`内部类中。我们将很快做到这一点。

### 编写`getItemCount`

修改`getItemCount`函数中的代码，如下所示：

```kt
override fun getItemCount(): Int {
   if (noteList != null) {
 return noteList.size
 }
 // error
 return -1
}
```

这个函数是类内部使用的，它提供了`List`中当前项目的数量。

### 编写`ListItemHolder`内部类

现在我们可以将注意力转向`ListItemHolder`内部类。通过添加以下突出显示的代码来调整`ListItemHolder`内部类：

```kt
inner class ListItemHolder(view: View) :
         RecyclerView.ViewHolder(view),
         View.OnClickListener {

 internal var title =
 view.findViewById<View>(
 R.id.textViewTitle) as TextView

 internal var description =
 view.findViewById<View>(
 R.id.textViewDescription) as TextView

 internal var status =
 view.findViewById<View>(
 R.id.textViewStatus) as TextView

  init {

        view.isClickable = true
 view.setOnClickListener(this)
  }

  override fun onClick(view: View) {
        mainActivity.showNote(adapterPosition)
  }
}
```

`ListItemHolder`属性引用布局中的每个`TextView`小部件。`init`块代码将整个视图设置为可点击，这样操作系统将在点击持有者时调用我们讨论的下一个函数`onClick`。

在`onClick`中，对`mainActivity.showNote`的调用存在错误，因为该函数尚不存在，但我们将在下一节中修复这个问题。该调用将简单地使用我们的自定义`DialogFragment`实例显示单击的笔记。

## 编写 MainActivity 以使用 RecyclerView 和 RecyclerAdapter 类

现在，切换到编辑窗口中的`MainActivity`类。将这三个新属性添加到`MainActivity`类中，并删除临时代码：

```kt
// Temporary code
//private var tempNote = Note()

private val noteList = ArrayList<Note>()
private val recyclerView: RecyclerView? = null
private val adapter: NoteAdapter? = null
```

这三个属性是我们所有`Note`实例的`ArrayList`实例，我们的`RecyclerView`实例和我们的`NoteAdapter`类的一个实例。

### 在`onCreate`中添加代码

在处理用户按下浮动操作按钮的代码之后，在`onCreate`函数中添加以下突出显示的代码（为了上下文再次显示）：

```kt
fab.setOnClickListener { view ->
   val dialog = DialogNewNote()
   dialog.show(supportFragmentManager, "")
}

recyclerView = 
 findViewById<View>(R.id.recyclerView) 
 as RecyclerView

adapter = NoteAdapter(this, noteList)
val layoutManager = 
 LinearLayoutManager(applicationContext)

recyclerView!!.layoutManager = layoutManager
recyclerView!!.itemAnimator = DefaultItemAnimator()

// Add a neat dividing line between items in the list
recyclerView!!.addItemDecoration(
 DividerItemDecoration(this, 
 LinearLayoutManager.VERTICAL))

// set the adapter
recyclerView!!.adapter = adapter

```

在这里，我们使用布局中的`RecyclerView`小部件初始化`recyclerView`。通过调用我们编写的构造函数来初始化我们的`NoteAdapter`（`adapter`）实例。请注意，我们传入了对`MainActivity`（`this`）和`ArrayList`实例的引用，正如我们之前编写的类所要求的那样。

接下来，我们创建一个新对象 - 一个`LayoutManager`对象。在接下来的四行代码中，我们配置了`recyclerView`的一些属性。

`itemAnimator`属性和`addItemDecoration`函数使每个列表项在列表中的每个项目之间都有一个分隔线，从视觉上更加美观。稍后，当我们构建一个“设置”屏幕时，我们将让用户选择添加和删除这个分隔线的选项。

我们做的最后一件事是用我们的适配器初始化`recylerView`的`adapter`属性，将我们的适配器与我们的视图结合在一起。

现在，我们将对`createNewNote`函数进行一些更改。

### 修改`createNewNote`函数

在`createNewNote`函数中，删除我们在第十四章中添加的临时代码，*Android 对话框窗口*（显示为注释）。并添加下一个显示的新突出代码：

```kt
fun createNewNote(n: Note) {
  // Temporary code
  // tempNote = n
  noteList.add(n)
 adapter!!.notifyDataSetChanged()

}
```

新添加的突出显示的代码将一个笔记添加到`ArrayList`实例中，而不是简单地初始化一个孤立的`Note`对象，现在已经被注释掉。然后，我们需要调用`notifyDataSetChanged`，让我们的适配器知道已添加新的笔记。

### 编写`showNote`函数

添加`showNote`函数，它是从`NoteAdapter`类中使用传递给`NoteAdapter`构造函数的对这个类的引用来调用的。更准确地说，当用户点击`RecyclerView`小部件中的一个项目时，它是从`ListerItemHolder`内部类中调用的。将`showNote`函数添加到`MainActivity`类中：

```kt
fun showNote(noteToShow: Int) {
   val dialog = DialogShowNote()
   dialog.sendNoteSelected(noteList[noteToShow])
   dialog.show(supportFragmentManager, "")
}
```

### 注意

`NoteAdapter.kt`文件中的所有错误现在都已经消失。

刚刚添加的代码将启动一个新的`DialogShowNote`实例，传入由`noteToShow`引用的特定所需的笔记。

# 运行应用程序

现在，您可以运行应用程序并输入一个新的笔记，如下一个屏幕截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_07.jpg)

在输入了几种类型的笔记后，列表（`RecyclerView`）将看起来像下一个屏幕截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_08.jpg)

而且，如果您点击查看其中一条笔记，它会看起来像这样：

![运行应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_16_09.jpg)

### 笔记

**读者挑战**

我们本可以花更多时间格式化我们的两个对话框窗口的布局。为什么不参考第五章，*使用 CardView 和 ScrollView 创建美丽的布局*，以及 Material Design 网站，[`material.io/design/`](https://material.io/design/)，做得比这更好。此外，您可以通过使用`CardView`而不是`LinearLayout`来增强`RecyclerView`的笔记列表。

不要花太长时间添加新的笔记，因为有一个小问题：关闭并重新启动应用程序。哦哦，所有的笔记都消失了！

# 经常问的问题

Q.1) 我仍然不明白`RecyclerAdapter`是如何工作的？

A) 那是因为我们实际上并没有讨论过。我们没有讨论幕后的细节是因为我们不需要知道它们。如果我们重写所需的函数，就像我们刚刚看到的那样，一切都会正常工作。这就是`RecyclerAdapter`和我们使用的大多数其他类的意图：隐藏实现并公开函数以暴露必要的功能。

Q.2) 我觉得我*需要*知道`RecyclerAdapter`和其他类的内部情况。我该怎么做？

A) 的确，`RecyclerAdapter`（以及我们在本书中使用的几乎每个类）有更多细节，我们没有空间来讨论。阅读您使用的类的官方文档是一个好的做法。您可以在[`developer.android.com/reference/android/support/v7/widget/RecyclerView.Adapter`](https://developer.android.com/reference/android/support/v7/widget/RecyclerView.Adapter)上阅读更多信息。

# 摘要

现在我们已经添加了保存多个笔记的功能，并实现了显示它们的能力。

我们通过学习和使用`RecyclerAdapter`类来实现了这一点，该类实现了`Adapter`接口，允许我们将`RecyclerView`实例和`ArrayList`实例绑定在一起，从而无缝显示数据，而我们（程序员）不必担心这些类的复杂代码，甚至看不到。

在下一章中，我们将开始使用户的笔记在退出应用程序或关闭设备时持久化。此外，我们将创建一个“设置”屏幕，并看看如何使设置也持久化。我们将使用不同的技术来实现这些目标。


# 第十七章：数据持久性和共享

在本章中，我们将探讨将数据保存到 Android 设备的永久存储的几种不同方法。此外，我们还将首次向我们的应用程序添加第二个`Activity`实例。在我们的应用程序中实现一个单独的“屏幕”，比如“设置”屏幕时，这通常是有意义的，可以在一个新的`Activity`实例中这样做。我们可以通过在同一个`Activity`中隐藏原始 UI 然后显示新 UI 的方式来做到这一点，就像我们在第四章中所做的那样，*开始使用布局和材料设计*，但这很快会导致混乱和容易出错的代码。因此，我们将看到如何添加另一个`Activity`实例并在它们之间导航用户。

在本章中，我们将执行以下操作：

+   了解 Android `Intent`类以在`Activity`实例之间切换并在它们之间传递数据

+   在一个新的`Activity`实例中创建一个非常简单的设置屏幕

+   使用`SharedPreferences`类持久保存设置屏幕数据

+   了解**JavaScript 对象表示**（**JSON**）进行序列化

+   探索`try`-`catch`-`finally`

+   在我们的备忘录应用程序中实现数据保存

# Android Intent 类

`Intent`类的命名恰如其分。它是一个展示我们应用程序的`Activity`实例意图的类。它使意图清晰并且也促进了它。

到目前为止，我们的所有应用程序都只有一个`Activity`实例，但许多 Android 应用程序包含多个。

在它可能最常见的用法中，`Intent`对象允许我们在`Activity`实例之间切换。但是，当我们在这些类之间切换时，数据会发生什么？`Intent`类也通过允许我们在它们之间传递数据来解决了这个问题。

`Intent`类不仅仅是关于连接我们应用程序的活动。它们还使与其他应用程序进行交互成为可能。例如，我们可以在我们的应用程序中提供一个链接，让用户发送电子邮件，打电话，与社交媒体互动，或在浏览器中打开网页，并让电子邮件、拨号器、网络浏览器或相关的社交媒体应用程序完成所有工作。

没有足够的页面来深入了解与其他应用程序的交互，因此我们主要将专注于在活动之间切换和传递数据。

## 切换 Activity

假设我们有一个基于两个`Activity`的类的应用程序，很快我们就会有。我们可以假设，像往常一样，我们有一个名为`MainActivity`的`Activity`实例，这是应用程序的起点，以及一个名为`SettingsActivity`的第二个`Activity`实例。这是我们如何从`MainActivity`切换到`SettingsActivity`的方法：

```kt
// Declare and initialize a new Intent object called myIntent
val myIntent = Intent(this, 
         SettingsActivity::class.java)

// Switch to the SettingsActivity
startActivity(myIntent)
```

仔细查看我们如何初始化`Intent`对象。`Intent`有一个构造函数，它接受两个参数。第一个是对当前`Activity`实例`this`的引用。第二个参数是我们要打开的`Activity`实例的名称，`SettingsActivity::class`。`SettingsActivity`末尾的`class`使其成为`AndroidManifest.xml`文件中声明的`Activity`实例的完整名称，我们将在不久的将来尝试`Intent`时窥探一下。

### 注意

看起来奇怪的`.java`是因为所有的 Kotlin 代码都被转换为 Java 字节码，`SettingsActivity::class.java`是它的完全限定名称。

唯一的问题是`SettingsActivity`不共享`MainActivity`的任何数据。在某种程度上，这是一件好事，因为如果您需要从`MainActivity`获取所有数据，那么这合理地表明切换`Activity`实例可能不是处理应用程序设计的最佳方式。然而，让两个`Activity`实例封装得如此彻底，以至于它们彼此完全不知道，这是不合理的。

## 在 Activity 之间传递数据

如果我们为用户创建一个登录屏幕，并且我们希望将登录凭据传递给我们应用程序的每个`Activity`实例，我们可以使用`Intent`类来实现。

我们可以像这样向`Intent`实例添加数据：

```kt
// Create a String called username 
// and set its value to bob
val username = "Bob"

// Create a new Intent as we have already seen
val myIntent = Intent(this, 
         SettingsActivity::class.java)

// Add the username String to the Intent
// using the putExtra function of the Intent class
myIntent.putExtra("USER_NAME", username)

// Start the new Activity as we have before
startActivity(myIntent)
```

在`SettingsActivity`中，我们可以像这样检索`String`值：

```kt
// Here we need an Intent also
// But the default constructor will do
// as we are not switching Activity
val myIntent = Intent()

// Initialize username with the passed in String 
val username = intent.extras.getString("USER_NAME")
```

在前两个代码块中，我们以与我们已经看到的相同方式切换了`Activity`实例。但是，在调用`startActivity`之前，我们使用`putExtra`函数将一个`String`值加载到`myIntent`中。

我们使用**键值对**添加数据。每个数据都需要伴随一个**标识符**，以便在检索`Activity`实例中识别并检索数据。

标识符名称是任意的，但应该使用有用/易记的值。

然后，在接收的`Activity`实例中，我们只需使用默认构造函数创建一个`Intent`对象：

```kt
val myIntent = Intent();
```

然后，我们可以使用`extras.getString`函数和键值对中的适当标识符来检索数据。

`Intent`类可以帮助我们发送比这更复杂的数据，但`Intent`类有其限制。例如，我们将无法发送`Note`对象。一旦我们想要开始发送多个值，就值得考虑不同的策略。

# 向“Note to self”添加设置页面

现在我们已经掌握了关于 Android `Intent`类的所有知识，我们可以向我们的“Note to self”应用程序添加另一个屏幕（`Activity`）：一个“设置”屏幕。

首先，我们将为新屏幕创建一个新的`Activity`实例，并查看这对`AndroidManifest.xml`文件的影响。然后，我们将为设置屏幕创建一个非常简单的布局，并添加 Kotlin 代码以从`MainActivity`切换到新的布局。然而，我们将推迟将设置屏幕布局与 Kotlin 连接，直到我们学会如何将用户首选设置保存到磁盘。我们将在本章后面做这个，然后回到设置屏幕以使其数据持久化。

首先，让我们编写新的`Activity`类。我们将其称为`SettingsActivity`。

## 创建 SettingsActivity

SettingsActivity 将是一个屏幕，用户可以在其中打开或关闭`RecyclerView`小部件中每个笔记之间的装饰分隔线。这不会是一个非常全面的设置屏幕，但这将是一个有用的练习，并且我们将看到在两个`Activity`实例之间切换以及将数据保存到磁盘的操作。按照以下步骤开始：

1.  在项目资源管理器窗口中，右键单击包含所有`.kt`文件并与您的包具有相同名称的文件夹。从弹出的上下文菜单中，选择**新建|Activity|空白 Activity**。

1.  在**Activity Name:**字段中输入`SettingsActivity`。

1.  将所有其他选项保持默认值，然后单击**完成**。

Android Studio 为我们创建了一个新的`Activity`类及其关联的`.kt`文件。让我们快速查看一些在幕后为我们完成的工作，因为了解发生了什么是很有用的。

从项目资源管理器中的`manifests`文件夹中打开`AndroidManifest.xml`文件。注意文件末尾附近的以下新代码行：

```kt
<activity android:name=".SettingsActivity"></activity>
```

这是`Activity`类与操作系统**注册**的方式。如果`Activity`类未注册，则尝试运行它将使应用程序崩溃。我们可以通过在新的`.kt`文件中创建一个扩展`Activity`（或`AppCompatActivity`）的类来创建`Activity`类。但是，我们将不得不自己添加前面的代码。此外，通过使用新的 Activity 向导，我们自动生成了一个布局 XML 文件（`activity_settings.xml`）。

## 设计设置屏幕布局

我们将快速为我们的设置屏幕构建用户界面；以下步骤和屏幕截图应该使这变得简单：

1.  打开`activity_settings.xml`文件，并切换到**Design**选项卡，在那里我们将快速布置我们的设置屏幕。

1.  在遵循其余步骤时，请使用下一个截图作为指南：![设计设置屏幕布局](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_17_01.jpg)

1.  将一个**Switch**小部件拖放到布局的中上部。我通过拖动边缘来拉伸它，使其更大更清晰。

1.  添加一个`id`属性为`switch1`（如果还没有的话），以便我们可以使用 Kotlin 与其交互。

1.  使用约束处理程序来固定开关的位置，或者点击**推断约束**按钮来自动固定它。

我们现在为我们的设置屏幕有了一个漂亮（而且非常简单）的新布局，并且`id`属性已经就位，准备在本章后面的代码中与其连接。

## 使用户能够切换到“设置”屏幕

我们已经知道如何创建和切换到`SettingsActivity`实例。另外，由于我们不会向其传递任何数据，也不会从中获取任何数据，我们可以只用几行 Kotlin 代码就可以让其工作。

您可能已经注意到我们的应用程序的操作栏中有菜单图标。在下一个截图中指示了它：

![使用户能够切换到“设置”屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_17_02.jpg)

如果您点击它，您会发现其中已经有一个**设置**菜单选项，这是我们在创建应用程序时默认提供的。当您点击菜单图标时，您将看到以下内容：

![使用户能够切换到“设置”屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_17_03.jpg)

我们所需要做的就是将创建和切换到`SettingsActivity`实例的代码放在`MainActivity.kt`文件的`onOptionsItemSelected`函数中。Android Studio 甚至默认为我们提供了一个`when`块，以便我们将来有一天想要添加设置菜单时将我们的代码粘贴进去。多么体贴。

切换到编辑器窗口中的`MainActivity.kt`，并找到`onOptionsItemSelected`函数中的以下代码块：

```kt
return when (item.itemId) {
   R.id.action_settings -> true
   else -> super.onOptionsItemSelected(item)
}
```

编辑前面显示的`when`块以匹配以下代码：

```kt
return when (item.itemId) {
   R.id.action_settings -> {
         val intent = Intent(this, 
                      SettingsActivity::class.java)

         startActivity(intent)
         true
  }

  else -> super.onOptionsItemSelected(item)
}
```

### 提示

您需要使用您喜欢的技术导入`Intent`类以添加以下代码：

```kt
import android.content.Intent
```

现在您可以运行应用程序，并通过点击**设置**菜单选项来访问新的设置屏幕。此截图显示了模拟器上运行的设置屏幕：

![使用户能够切换到“设置”屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_17_04.jpg)

要从`SettingsActivity`屏幕返回到`MainActivity`屏幕，您可以点击设备上的返回按钮。

# 使用 SharedPreferences 持久化数据

在 Android 中，有几种方法可以使数据持久化。持久化的意思是，如果用户退出应用程序，然后再次打开应用程序，他们的数据仍然可用。使用哪种技术取决于应用程序和数据类型。

在本书中，我们将介绍三种使数据持久化的方法。对于保存用户的设置，我们只需要一个简单的方法。毕竟，我们只需要知道他们是否希望在`RecyclerView`小部件的每个笔记之间有装饰性分隔符。

让我们看看如何使我们的应用程序将变量保存和重新加载到设备的内部存储器中。我们需要使用`SharedPreferences`类。`SharedPreferences`是一个提供对数据访问和编辑的类，可以被应用程序的所有类访问和编辑。让我们看看如何使用它：

```kt
// A SharedPreferences instance for reading data
val prefs = getSharedPreferences(
         "My app",
          Context.MODE_PRIVATE)

// A SharedPreferences.Editor instance for writing data
val editor = prefs.edit()
```

我们通过使用`getSharedPreferences`函数并传入一个`String`值来初始化`prefs`对象，该值将用于引用使用该对象读取和写入的所有数据。通常，我们可以使用应用的名称作为此字符串值。在下一段代码中，`Mode_Private`表示任何类都可以访问它，但只能从此应用程序访问。

然后，我们使用我们新初始化的`prefs`对象通过调用`edit`函数来初始化我们的`editor`对象。

让我们假设我们想要保存用户的名字，我们在一个名为`username`的`String`实例中拥有。然后我们可以像这样将数据写入设备的内部存储器：

```kt
editor.putString("username", username)
```

`putString`函数中使用的第一个参数是一个标签，可用于引用数据，第二个参数是保存我们要保存的数据的实际变量。前面代码的第二行启动了保存过程。因此，我们可以像这样将多个变量写入磁盘：

```kt
editor.putString("username", username)
editor.putInt("age", age)
editor.putBoolean("newsletter-subscriber", subscribed)

// Save all the above data
editor.apply()
```

前面的代码演示了您可以保存其他变量类型，并且假设`username`、`age`和`subscribed`变量已经被声明并使用适当的值进行了初始化。

一旦`editor.apply()`执行，数据就被存储了。我们可以退出应用程序，甚至关闭设备，数据仍将持久存在。

# 使用 SharedPreferences 重新加载数据

让我们看看下一次应用程序运行时如何重新加载我们的数据。这段代码将重新加载前一段代码保存的三个值。我们甚至可以声明变量并使用存储的值进行初始化：

```kt
val username  = prefs.getString(
   "username", "new user")

val age  = prefs.getInt("age", -1)

val subscribed = prefs.getBoolean(
    "newsletter-subscriber", false)
```

在前面的代码中，我们使用了适用于数据类型的函数从磁盘加载数据，并使用了与我们首次保存数据时使用的相同标签。不太清楚的是每个函数调用的第二个参数。

`getString`、`getInt`和`getBoolean`函数需要第二个参数作为默认值。如果没有存储带有该标签的数据，它将返回默认值。

然后，我们可以在我们的代码中检查这些默认值，并尝试获取所需的值或处理错误。例如，参见以下代码：

```kt
if (age == -1){
   // Ask the user for his age
}
```

我们现在已经了解足够的知识来保存用户的设置在 Note to self 应用程序中。

# 使自我备忘录设置持久化

我们已经学会了如何将数据保存到设备的内存中。当我们实现保存用户的设置时，我们将再次看到我们如何处理`Switch`小部件的输入，以及我们刚刚看到的代码将如何使我们的应用程序按照我们想要的方式工作。

## 编写 SettingsActivity 类

大部分操作将在`SettingsActivity.kt`文件中进行。因此，点击适当的选项卡，我们将逐步添加代码。

首先，我们希望有一个属性来表示用户在设置屏幕上的选项 - 他们是否想要装饰性分隔线。

将以下内容添加到`SettingsActivity`中：

```kt
private val showDividers: Boolean = true
```

现在，在`onCreate`中，添加突出显示的代码以初始化`prefs`，它被推断为`SharedPreferences`实例：

```kt
val prefs = getSharedPreferences(
               "Note to self",
                Context.MODE_PRIVATE)
```

### 提示

导入`SharedPreferences`类：

```kt
import android.content.SharedPreferences
```

接下来，在`onCreate`中，让我们加载保存的数据，这些数据代表我们的用户以前选择是否显示分隔线。我们将根据需要将开关设置为打开或关闭：

```kt
showDividers  = prefs.getBoolean("dividers", true)

// Set the switch on or off as appropriate
switch1.isChecked = showDividers
```

接下来，我们将创建一个 lambda 来处理我们的`Switch`小部件的更改。我们只需将`showDividers`的值设置为`Switch`小部件的`isChecked`变量相同。将以下代码添加到`onCreate`函数中：

```kt
switch1.setOnCheckedChangeListener {
   buttonView, isChecked ->

   showDividers = isChecked
}
```

您可能已经注意到，在任何代码中的任何时候，我们都没有将任何值写入设备存储。我们可以在检测到开关变化后放置它，但是将它放在保证被调用的地方要简单得多 - 但只有一次。

我们将利用我们对`Activity`生命周期的了解，并覆盖`onPause`函数。当用户离开`SettingsActivity`屏幕时，无论是返回`MainActivity`屏幕还是退出应用程序，`onPause`都将被调用，并且设置将被保存。这样，用户可以随意切换开关，应用程序将保存他们的最终决定。添加此代码以覆盖`onPause`函数并保存用户的设置。将此代码添加到`SettingsActivity`类的结束大括号之前：

```kt
override fun onPause() {
   super.onPause()

   // Save the settings here
   val prefs = getSharedPreferences(
               "Note to self",
                Context.MODE_PRIVATE)

   val editor = prefs.edit()

   editor.putBoolean("dividers", showDividers)

   editor.apply()
}
```

前面的代码在私有模式下声明和初始化了一个新的`SharedPreferences`实例，使用了应用程序的名称。它还声明和初始化了一个新的`SharedPreferences.Editor`实例。最后，使用`putBoolean`将值输入到`editor`对象中，并使用`apply`函数写入磁盘。

现在，我们可以向`MainActivity`添加一些代码，在应用程序启动时或用户从设置屏幕切换回主屏幕时加载设置。

## 编写 MainActivity 类

在`NoteAdapter`声明后添加这段突出显示的代码：

```kt
private var adapter: NoteAdapter? = null
private var showDividers: Boolean = false

```

现在我们有一个`Boolean`属性来决定是否显示分隔线。我们将重写`onResume`函数并初始化我们的`Boolean`属性。添加重写的`onResume`函数，如下所示，添加到`MainActivity`类旁边：

```kt
override fun onResume() {
   super.onResume()

   val prefs = getSharedPreferences(
               "Note to self",
                Context.MODE_PRIVATE)

  showDividers = prefs.getBoolean(
               "dividers", true)
}
```

用户现在能够选择他们的设置。应用程序将根据需要保存和重新加载它们，但我们需要让`MainActivity`响应用户的选择。

在`onCreate`函数中找到这段代码并删除它：

```kt
recyclerView!!.addItemDecoration(
   DividerItemDecoration(this,
         LinearLayoutManager.VERTICAL))
```

先前的代码是设置列表中每个笔记之间的分隔线。将这段新代码添加到`onResume`函数中，这是相同的代码行，被一个`if`语句包围，只有在`showDividers`为`true`时才选择性地使用分隔线。在`onResume`中的先前代码之后添加这段代码：

```kt
// Add a neat dividing line between list items
if (showDividers)
    recyclerView!!.addItemDecoration(
          DividerItemDecoration(
          this, LinearLayoutManager.VERTICAL))
else {
  // check there are some dividers
  // or the app will crash
  if (recyclerView!!.itemDecorationCount > 0)
        recyclerView!!.removeItemDecorationAt(0)
}
```

运行应用程序，你会注意到分隔线消失了；转到设置屏幕，打开分隔线，返回主屏幕（使用返回按钮），你会发现：现在有分隔符了。下一张截图显示了有和没有分隔符的列表，被并排合成一张照片，以说明开关的工作，并且设置在两个`Activity`实例之间持久保存：

![编写 MainActivity 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_17_05.jpg)

一定要尝试退出应用程序并重新启动，以验证设置是否已保存到磁盘。甚至可以关闭模拟器，然后再次打开，设置将保持不变。

现在我们有一个整洁的设置屏幕，我们可以永久保存用户的选择。当然，关于持久性的一个重要缺失是用户的基本数据，他们的笔记，仍然无法持久保存。

# 更高级的持久性

让我们考虑一下我们需要做什么。我们想要将一堆笔记保存到内部存储器中。更具体地说，我们想要存储一些字符串和相关的布尔值。这些字符串和布尔值代表用户的笔记标题、文本，以及它是待办事项、重要事项还是想法。

鉴于我们已经对`SharedPreferences`类有所了解，乍一看，这似乎并不特别具有挑战性 - 直到我们更深入地了解我们的需求。如果用户喜欢我们的应用程序并最终拥有 100 条笔记，我们将需要 100 个键值对的标识符。这并非不可能，但开始变得尴尬。

现在，想象一下，我们想增强应用程序并让用户能够为它们添加日期。Android 有一个`Date`类非常适合这个用途。然后，添加一些整洁的功能，比如提醒，对我们的应用程序来说将是相当简单的。但是当涉及到保存数据时，事情突然变得复杂起来。

我们如何使用`SharedPreferences`存储日期？它并不是为此而设计的。我们可以在保存时将其转换为字符串值，然后在加载时再次转换回来，但这远非简单。

随着我们的应用程序功能的增加和用户拥有越来越多的笔记，整个持久性问题变得一团糟。我们需要一种方法来保存和加载实际的 Kotlin 对象。如果我们能简单地保存和加载对象，包括它们的内部数据（字符串、布尔值、日期或其他任何东西），我们的应用程序可以拥有我们需要适应用户的任何类型的数据。

将数据对象转换为位和字节以存储在磁盘上的过程称为**序列化**；反向过程称为**反序列化**。单独的序列化是一个广泛的主题，远非简单。幸运的是，正如我们所期望的那样，有一个类来处理大部分复杂性。

## JSON 是什么？

**JSON**代表**JavaScript 对象表示法**，它在 Android 编程之外的领域被广泛使用。它可能更经常用于在 Web 应用程序和服务器之间发送数据。

幸运的是，Android 上有可用的 JSON 类几乎完全隐藏了序列化过程的复杂性。通过学习一些更多的 Kotlin 概念，我们可以快速开始使用这些类，并开始将整个 Kotlin 对象写入设备存储，而不必担心构成对象的原始类型是什么。

与我们迄今为止看到的其他类相比，JSON 类进行的操作有比正常情况下更高的可能性失败。要了解为什么会这样以及可以采取什么措施，让我们看看**异常**。

## 异常 - try、catch 和 finally

所有这些关于 JSON 的讨论都要求我们学习另一个 Kotlin 概念：**异常**。当我们编写执行可能失败的操作的类时，特别是由于我们无法控制的原因，建议在我们的代码中明确说明这一点，以便任何使用我们的类的人都能为可能性做好准备。

保存和加载数据是一个可能发生失败的情况。想想当 SD 卡已被移除或已损坏时尝试加载数据。另一个可能失败的情况是，当我们编写依赖网络连接的代码时，如果用户在数据传输的过程中离线了会怎么样？

Kotlin 异常是解决方案，JSON 类使用它们，所以现在是学习它们的好时机。

当我们编写使用有可能失败的代码的类时，我们可以通过使用`try`、`catch`和`finally`来准备我们类的用户。

我们可以在我们的类中使用`@Throws`注解来写函数，就像这样，也许：

```kt
@Throws(someException::class)
fun somePrecariousFunction() {
   // Risky code goes here
}
```

现在，任何使用`somePrecariousFunction`的代码都需要**处理**异常。我们处理异常的方式是将代码包装在`try`和`catch`块中；也许像这样：

```kt
try {
  …
  somePrecariousFunction()
  …

} catch (e: Exception) {
   Log.e("Uh Oh!", "somePrecariousFunction failure", e)
}
```

如果需要，在`try`和`catch`块之后，我们还可以添加一个`finally`块来采取进一步的行动：

```kt
finally{
   // More action here
}
```

在我们的备忘录应用中，我们将采取最少的必要行动来处理异常，并简单地将错误输出到 logcat 窗口，但您可以做一些事情，比如通知用户，重试操作，或者实施一些聪明的备用计划。

# 备份用户数据到备忘录

因此，有了我们对异常的新认识，让我们修改一下我们的备忘录代码，然后我们可以介绍`JSONObject`和`JSONException`。

首先，让我们对我们的`Note`类进行一些小修改。

添加一些更多的属性，它们将作为我们的`Note`类的每个方面的键值对中的键：

```kt
private val JSON_TITLE = "title"
private val JSON_DESCRIPTION = "description"
private val JSON_IDEA = "idea"
private val JSON_TODO = "todo"
private val JSON_IMPORTANT = "important"
```

现在，添加一个构造函数和一个接收`JSONObject`引用并抛出`JSONException`错误的空默认构造函数。第一个构造函数的主体通过调用`JSONObject`类的`getString`或`getBoolean`函数并传入键作为参数来初始化单个`Note`对象的每个属性的成员。我们还提供了一个空构造函数，这是必需的，以便我们也可以创建一个未初始化属性的`Note`对象：

```kt
// Constructor
// Only used when created from a JSONObject
@Throws(JSONException::class)
constructor(jo: JSONObject) {

  title = jo.getString(JSON_TITLE)
  description = jo.getString(JSON_DESCRIPTION)
  idea = jo.getBoolean(JSON_IDEA)
  todo = jo.getBoolean(JSON_TODO)
  important = jo.getBoolean(JSON_IMPORTANT)
}

// Now we must provide an empty default constructor for
// when we create a Note to pass to the new note dialog
constructor() {

}
```

### 提示

您需要导入`JSONException`和`JSONObject`类：

```kt
import org.json.JSONException;
import org.json.JSONObject;
```

接下来我们将看到的代码将给定`Note`对象的属性值加载到`JSONObject`实例中。这是`Note`对象的值被打包准备好进行实际序列化的地方。

我们只需要使用适当的键和匹配的属性调用`put`函数。这个函数返回`JSONObject`（我们马上会看到在哪里），并且抛出一个`JSONObject`异常。添加我们刚刚讨论过的代码：

```kt
@Throws(JSONException::class)
fun convertToJSON(): JSONObject {

  val jo = JSONObject()

  jo.put(JSON_TITLE, title)
  jo.put(JSON_DESCRIPTION, description)
  jo.put(JSON_IDEA, idea)
  jo.put(JSON_TODO, todo)
  jo.put(JSON_IMPORTANT, important)

  return jo
}
```

现在，让我们创建一个`JSONSerializer`类，它将执行实际的序列化和反序列化。创建一个新的 Kotlin 类，命名为`JSONSerializer`。

让我们将编码分成几个块，并在编写每个块时讨论我们正在做什么。

首先，声明和一些属性：一个`String`实例来保存数据的文件名，以及一个`Context`实例，在 Android 中写入数据到文件是必要的。编辑`JSONSerializer`类的代码如下所示：

```kt
class JSONSerializer(
   private val filename: String, 
   private val context: Context) {
   // All the rest of the code goes here

}
```

### 提示

你需要导入`Context`类：

```kt
import android.content.Context
```

现在我们可以开始编写类的真正核心部分。接下来是`save`函数。它首先创建一个`JSONArray`对象，这是一个专门处理 JSON 对象的`ArrayList`类。

接下来，代码使用`for`循环遍历`notes`中的所有`Note`对象，并使用我们之前添加的`Note`类的`convertToJSON`函数将它们转换为 JSON 对象。然后，将这些转换后的`JSONObject`加载到`jArray`中。

接下来，代码使用`Writer`实例和`Outputstream`实例组合将数据写入实际文件。注意，`OutputStream`实例需要`Context`对象。添加我们刚刚讨论过的代码：

```kt
@Throws(IOException::class, JSONException::class)
fun save(notes: List<Note>) {

   // Make an array in JSON format
   val jArray = JSONArray()

   // And load it with the notes
   for (n in notes)
         jArray.put(n.convertToJSON())

  // Now write it to the private disk space of our app
  var writer: Writer? = null
  try {
    val out = context.openFileOutput(filename,
                Context.MODE_PRIVATE)

    writer = OutputStreamWriter(out)
    writer.write(jArray.toString())

  } finally {
        if (writer != null) {

        writer.close()
      }
   }
}
```

### 提示

你需要为这些新类添加以下导入语句：

```kt
import org.json.JSONArray
import org.json.JSONException
import java.io.IOException
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.io.Writer
import java.util.List
```

现在进行反序列化 - 加载数据。这次，正如我们所期望的那样，该函数没有参数，而是返回`ArrayList`。使用`context.openFileInput`创建一个`InputStream`实例，并打开包含所有数据的文件。

我们使用`for`循环将所有数据追加到一个`String`对象中，并使用我们的新`Note`构造函数，将每个`JSONObject`解包为`Note`对象并将其添加到`ArrayList`中，最后将其返回给调用代码。添加`load`函数：

```kt
@Throws(IOException::class, JSONException::class)
fun load(): ArrayList<Note> {
   val noteList = ArrayList<Note>()
   var reader: BufferedReader? = null

   try {

         val `in` = context.openFileInput(filename)
         reader = BufferedReader(InputStreamReader(`in`))
         val jsonString = StringBuilder()

    for (line in reader.readLine()) {
          jsonString.append(line)
    }

    val jArray = JSONTokener(jsonString.toString()).
                 nextValue() as JSONArray

    for (i in 0 until jArray.length()) {
           noteList.add(Note(jArray.getJSONObject(i)))
    }

  } catch (e: FileNotFoundException) {
         // we will ignore this one, since it happens
        // when we start fresh. You could add a log here.

  } finally {
   // This will always run            
            reader!!.close()
  }

  return noteList
}
```

### 提示

你需要添加这些导入：

```kt
import org.json.JSONTokener
import java.io.BufferedReader
import java.io.FileNotFoundException
import java.io.InputStream
import java.io.InputStreamReader
import java.util.ArrayList
```

现在，我们需要在`MainActivity`类中让我们的新类开始工作。在`MainActivity`声明之后添加一个新属性，如下所示。此外，删除`noteList`的初始化，只留下声明，因为我们现在将在`onCreate`函数中使用一些新代码进行初始化。我已经注释掉了你需要删除的那行：

```kt
private var mSerializer: JSONSerializer? = null
private var noteList: ArrayList<Note>? = null
//private val noteList = ArrayList<Note>()
```

现在，在`onCreate`函数中，我们通过使用文件名和`getApplicationContext()`调用`JSONSerializer`构造函数来初始化`mSerializer`，这是应用程序的`Context`实例，是必需的。然后我们可以使用`JSONSerializer load`函数来加载任何保存的数据。在处理浮动操作按钮的代码之后添加这段新的突出代码。这段新代码必须出现在我们初始化`RecyclerView`实例的代码之前：

```kt
fab.setOnClickListener { view ->
   val dialog = DialogNewNote()
   dialog.show(supportFragmentManager, "")
}

mSerializer = JSONSerializer("NoteToSelf.json",
 applicationContext)

try {
 noteList = mSerializer!!.load()
} catch (e: Exception) {
 noteList = ArrayList()
 Log.e("Error loading notes: ", "", e)
}

recyclerView =
         findViewById<View>(R.id.recyclerView) 
         as RecyclerView

adapter = NoteAdapter(this, this.noteList!!)
val layoutManager = LinearLayoutManager(
          applicationContext)
```

### 提示

在上一段代码中，我展示了大量的上下文，因为它的正确位置对其工作是必要的。如果你在使用过程中遇到任何问题，请确保将其与`Chapter17/Note to self`文件夹中的下载包中的代码进行比较。

现在，在我们的`MainActivity`类中添加一个新函数，以便我们可以调用它来保存所有用户的数据。这个新函数所做的就是调用`JSONSerializer`类的`save`函数，传入所需的`Note`对象列表：

```kt
private fun saveNotes() {
  try {
        mSerializer!!.save(this.noteList!!)

  } catch (e: Exception) {
        Log.e("Error Saving Notes", "", e)
  }
}
```

现在，我们将重写`onPause`函数，以保存我们用户的数据，就像我们保存用户设置时所做的那样。确保在`MainActivity`类中添加这段代码：

```kt
override fun onPause() {
   super.onPause()

   saveNotes()
}
```

就是这样。现在我们可以运行应用程序，并添加尽可能多的笔记。`ArrayList`实例将把它们全部存储在我们的运行应用程序中，我们的`RecyclerAdapter`将管理在`RecyclerView`小部件中显示它们，现在 JSON 将负责从磁盘加载它们，并将它们保存回磁盘。

# 常见问题

Q.1)我并没有完全理解本章的所有内容，那我适合成为程序员吗？

A) 本章介绍了许多新的类、概念和函数。如果你感到有些头痛，这是可以预料的。如果一些细节不清楚，不要让它阻碍你。继续进行下一章（它们要简单得多），然后回顾这一章，特别是检查已完成的代码文件。

Q.2)那么，序列化的详细工作原理是什么？

A）序列化确实是一个广阔的话题。你可以一辈子写应用程序，而不真正需要理解它。这是一种可能成为计算机科学学位课程主题的话题。如果你想了解更多，请看看这篇文章：[`en.wikipedia.org/wiki/Serialization`](https://en.wikipedia.org/wiki/Serialization)。

# 总结

在我们通过 Android API 的旅程中，现在值得回顾一下我们所知道的。我们可以制定自己的 UI 设计，并可以从各种各样的小部件中进行选择，以便让用户进行交互。我们可以创建多个屏幕，以及弹出对话框，并且可以捕获全面的用户数据。此外，我们现在可以使这些数据持久化。

当然，Android API 还有很多东西需要学习，甚至超出了这本书会教给你的内容，但关键是我们现在知道足够的知识来规划和实施一个可工作的应用程序。你现在就可以开始自己的应用程序了。

如果你有立即开始自己的项目的冲动，那么我的建议是继续前进并去做。不要等到你认为自己是“专家”或更加准备好了。阅读这本书，更重要的是，实施这些应用程序将使你成为更好的 Android 程序员，但没有什么比设计和实施自己的应用程序更能让你更快地学会。完全可以阅读这本书并同时在自己的项目上工作。

在下一章中，我们将通过使应用程序支持多语言来为这个应用程序添加最后的修饰。这是相当快速和简单的。


# 第十八章：本地化

本章内容简单明了，但我们将学会的内容可以使您的应用程序面向数百万潜在用户。我们将看到如何添加额外的语言，以及为什么通过字符串资源正确添加文本在添加多种语言时对我们有益。

在本章中，我们将执行以下操作：

+   通过添加西班牙语和德语语言使 Note to self 应用程序支持多语言

+   学习如何更好地使用**字符串资源**

让我们开始吧。

# 使 Note to self 应用程序支持西班牙语、英语和德语

首先，我们需要为我们的项目添加一些文件夹 - 每种新语言一个文件夹。文本被归类为**资源**，因此需要放在`res`文件夹中。按照以下步骤为项目添加西班牙语支持。

### 注意

虽然该项目的源文件存储在`Chapter18`文件夹中，但它们仅供参考。您需要按照下面描述的流程来实现多语言功能。

## 添加西班牙语支持

按照以下步骤添加西班牙语：

1.  右键单击`res`文件夹，然后选择**新建** | **Android 资源目录**。在**目录名称**字段中输入`values-es`。

1.  现在我们需要添加一个文件，我们可以在其中放置所有我们的西班牙翻译。

1.  右键单击`res`，然后选择**新建** | **Android 资源文件**，在**文件名**字段中输入`strings.xml`。在**目录名称**字段中输入`values-es`。

我们现在有一个`strings.xml`文件，任何设置为使用西班牙语的设备都将引用它。明确地说，我们现在有两个不同的`strings.xml`文件。

## 添加德语支持

按照以下步骤添加德语语言支持。

1.  右键单击`res`文件夹，然后选择**新建** | **Android 资源目录**。在**目录名称**字段中输入`values-de`。

1.  现在我们需要添加一个文件，我们可以在其中放置所有我们的德语翻译。

1.  右键单击`res`，然后选择**新建** | **Android 资源文件**，在**文件名**字段中输入`strings.xml`。在**目录名称**字段中输入`values-de`。

以下屏幕截图显示了`strings.xml`文件夹的外观。您可能想知道`strings.xml`文件夹是从哪里来的，因为它与我们似乎在之前的步骤中创建的结构不对应。

Android Studio 正在帮助我们组织我们的文件和文件夹，因为这是 Android 操作系统在 APK 格式中所需的。但是，您可以清楚地看到西班牙语和德语文件，它们通过它们的国旗以及它们的**(de)**和**(es)**后缀来表示：

![添加德语支持](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C18_01.jpg)

### 提示

根据您的 Android Studio 设置，您可能看不到国旗图标。只要您能看到三个`strings.xml`文件，一个没有后缀，一个带有**(de)**，一个带有**(es)**，那么您就可以继续了。

现在我们可以将翻译添加到刚刚创建的文件中。

## 添加字符串资源

正如我们所知，`strings.xml`文件包含应用程序将显示的单词，例如 important，to-do 和 idea。通过为每种我们想要支持的语言创建一个`strings.xml`文件，我们可以让 Android 根据用户的语言设置选择适当的文本。

在接下来的步骤中，请注意，尽管我们将要翻译的单词的翻译放在值中，但`name`属性保持不变。如果你仔细想想，这是合乎逻辑的，因为我们在布局文件中引用的是`name`属性。

让我们提供翻译，看看我们取得了什么成就，然后回来讨论我们将如何处理 Kotlin 代码中的文本。

实现此代码的最简单方法是从原始的`strings.xml`文件中复制并粘贴代码，然后编辑每个`name`属性的值：

1.  通过双击打开`strings.xml`文件。确保选择靠近西班牙国旗或**(es)**后缀的文件。编辑文件使其如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
<string name="app_name">Nota a sí mismo</string>
<string name="action_settings">Configuración</string>

<string name="action_add">add</string>
<string name="title_hint">Título</string>
<string name="description_hint">Descripción</string>
<string name="idea_text">Idea</string>
<string name="important_text">Importante</string>
<string name="todo_text">Que hacer</string>
<string name="cancel_button">Cancelar</string>
<string name="ok_button">Vale</string>

<string name="settings_title">Configuración</string>
<string name="title_activity_settings">Configuración</string>

</resources>
```

1.  通过双击打开`strings.xml`文件。确保选择靠近德国国旗或**(de)**后缀的文件。编辑文件使其看起来像这样：

```kt
    <?xml version="1.0" encoding="utf-8"?>
    <resources>
 <string name="app_name">Hinweis auf selbst</string>
 <string name="action_settings">Einstellungen</string>

 <string name="action_add">add</string>
 <string name="title_hint">Titel</string>
 <string name="description_hint">Beschreibung</string>
 <string name="idea_text">Idee</string>
 <string name="important_text">Wichtig</string>
 <string name="todo_text">zu tun</string>
 <string name="cancel_button">Abbrechen</string>
 <string name="ok_button">Okay</string>

 <string name="settings_title">Einstellungen</string>
 <string name="title_activity_settings">Einstellungen</string>
    </resources>
```

### 提示

如果你没有在额外的（西班牙语和德语）`strings.xml`文件中提供所有的字符串资源，那么缺失的资源将从默认文件中获取。

我们所做的是提供了两种翻译。Android 知道哪种翻译是哪种语言，因为它们放置在不同的文件夹中。此外，我们使用了**字符串标识符**（`name`属性）来引用这些翻译。回顾一下之前的代码，你会发现相同的标识符被用于两种翻译，以及原始的`strings.xml`文件中。

### 提示

你甚至可以将本地化到不同版本的语言，比如美国或英国英语。完整的代码列表可以在[`stackoverflow.com/questions/7973023/what-is-the-list-of-supported-languages-locales-on-android`](http://stackoverflow.com/questions/7973023/what-is-the-list-of-supported-languages-locales-on-android)找到。你甚至可以本地化资源，比如图像和声音。在[`developer.android.com/guide/topics/resources/localization.html`](http://developer.android.com/guide/topics/resources/localization.html)了解更多信息。

这些翻译是从谷歌翻译中复制并粘贴而来的，因此很可能有些翻译与正确的相去甚远。像这样廉价地进行翻译可能是将具有基本字符串资源集的应用程序放到使用不同语言的用户的设备上的有效方式。一旦你开始需要任何深度的翻译，也许是为了叙事驱动的游戏或社交媒体应用程序的文本，你肯定会受益于由人类专业人员进行的翻译。

这个练习的目的是展示 Android 的工作原理，而不是如何翻译。

### 注意

对于可能能够看到这里提供的翻译的局限性的西班牙或德国人，我表示诚挚的歉意。

现在我们有了翻译，我们可以看到它们的作用-到一定程度。

# 在德语或西班牙语中运行 Note to self

运行应用程序，看看它是否按预期工作。现在，我们可以更改本地化设置，以便在西班牙语中查看。不同的设备在如何做到这一点上略有不同，但 Pixel 2 XL 模拟器可以通过点击**Custom Locale**应用程序进行更改：

![在德语或西班牙语中运行 Note to self](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C18_02.jpg)

接下来，选择**es-ES**，然后点击屏幕左下角的**SELECT 'ES'**按钮，如下一张截图所示：

![在德语或西班牙语中运行 Note to self](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C18_03.jpg)

现在你可以以通常的方式运行应用程序。这里有一张截图显示了应用程序在西班牙语中的运行情况。我用 Photoshop 将一些图像并排放在一起，展示了 Note to self 应用程序的一些不同屏幕：

![在德语或西班牙语中运行 Note to self](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C18_04.jpg)

你可以清楚地看到我们的应用主要是翻译成了西班牙语。显然，用户输入的文本将是他们所说的任何语言-这不是我们应用程序的缺陷。然而，仔细看图片，你会注意到我指出了一些地方，文本仍然是英文的。我们在每个对话窗口中仍然有一些未翻译的文本。

这是因为文本直接包含在我们的 Kotlin 代码中。正如我们所见，使用多种语言的字符串资源并在布局中引用它们是很容易的，但是我们如何从我们的 Kotlin 代码中引用字符串资源呢？

## 使翻译在 Kotlin 代码中起作用

首先要做的是在三个`strings.xml`文件中创建资源。这是需要添加到三个不同文件中的两个资源。

在`strings.xml`（没有任何标志或后缀），在`<resources></resources>`标签中添加这两个资源：

```kt
<string name="add_new_note">Add a new note</string>
<string name="your_note">Your note</string>
```

在带有西班牙国旗和/或**(es)**后缀的`strings.xml`文件中，在`<resources></resources>`标签内添加以下两个资源：

```kt
<string name="add_new_note">Agregar una nueva nota</string>
<string name="your_note">Su nota</string>
```

在带有德国国旗和/或**(de)**后缀的`strings.xml`文件中，在`<resources></resources>`标签内添加以下两个资源：

```kt
<string name="add_new_note">Eine neue Note hinzufügen</string>
<string name="your_note">Ihre Notiz</string>
```

接下来，我们需要编辑一些 Kotlin 代码，以引用资源而不是硬编码的字符串。

打开`DialogNewNote.kt`文件，找到以下代码行：

```kt
builder.setView(dialogView).setMessage("Add a new note")
```

编辑它，使用我们刚刚添加的字符串资源，而不是硬编码的文本，如下所示：

```kt
builder.setView(dialogView).setMessage(
      resources.getString(
         R.string.add_new_note))
```

新代码使用了链式的`setView`、`setMessage`和`resources.getString`函数来替换先前硬编码的`"Add a new note"`文本。仔细看，你会发现传递给`getString`的参数是字符串`R.string.add_new_note`标识符。

`R.string`代码指的是`res`文件夹中的字符串资源，`add_new_note`是我们的标识符。然后，Android 将能够根据应用程序运行的设备的语言环境决定哪个版本（默认、西班牙语或德语）是合适的。

我们还有一个硬编码的字符串资源要更改。

打开`DialogShowNote.kt`文件，找到以下代码行：

```kt
builder.setView(dialogView).setMessage("Your Note")
```

编辑它，使用我们刚刚添加的字符串资源，而不是硬编码的文本，如下所示：

```kt
builder.setView(dialogView).setMessage(
         resources.getString(R.string.your_note))
```

新代码再次使用了链式的`setView`、`setMessage`和`resources.getString`函数来替换先前硬编码的`"Your note"`文本。而且，再次，传递给`getString`的参数是字符串标识符，在这种情况下是`R.string.your_note`。

现在，Android 可以根据应用程序运行的设备的语言环境决定哪个版本（默认、西班牙语或德语）是合适的。下一个屏幕截图显示，新的笔记屏幕现在以适当的语言显示开头文本：

![使 Kotlin 代码中的翻译工作](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_C18_05.jpg)

您可以添加任意多个字符串资源。作为第三章的提醒，*探索 Android Studio 和项目结构*，请注意，使用字符串资源是向所有项目添加所有文本的推荐方式。本书中的教程（除了 Note to Self 之外）将倾向于硬编码它们，以使教程更紧凑。

# 总结

现在我们可以全球化我们的应用，以及添加更灵活的字符串资源，而不是硬编码所有文本。

在下一章中，我们将看到如何使用动画和插值器为我们的布局添加酷炫的动画效果。
