# Kotlin 安卓编程初学者手册（三）

> 原文：[`zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A`](https://zh.annas-archive.org/md5/507BA3297D2037C2888F887A989A734A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Kotlin 函数

函数是我们应用程序的构建模块。我们编写执行特定任务的函数，然后在需要执行该特定任务时调用它们。由于我们应用程序中需要执行的任务将会非常多样化，我们的函数需要适应这一点并且非常灵活。Kotlin 函数非常灵活，比其他与 Android 相关的语言更灵活。因此，我们需要花费一个完整的章节来学习它们。函数与面向对象编程密切相关，一旦我们理解了函数的基础知识，我们就能够很好地掌握更广泛的面向对象编程学习。

这是本章的内容：

+   函数基础和回顾

+   函数返回类型和 return 关键字

+   单表达式函数

+   默认参数

+   更多与函数相关的主题

我们已经对函数有了一些了解，所以需要回顾一下。

# 函数基础和回顾

我们已经看到并使用了函数。一些是由 Android API 为我们提供的，比如`onCreate`和其他生命周期函数。

我们自己编写了其他函数；例如，`topClick`和`bottomClick`。但是，我们还没有适当地解释它们，函数还有更多我们还没有看到的内容。

### 注意

您经常会听到另一个与函数密切相关且几乎与函数同义的术语。如果您之前学过 Java 或其他面向对象的语言，情况就是如此。我指的是**方法**。从技术角度来看，方法和函数之间的区别很少重要，部分区别在于我们的代码中声明函数/方法的位置。如果您想在编程上正确，可以阅读这篇文章，其中深入探讨了这个问题，并提供了多种观点：

[`stackoverflow.com/questions/155609/whats-the-difference-between-a-method-and-a-function`](https://stackoverflow.com/questions/155609/whats-the-difference-between-a-method-and-a-function)

在本书中，我将所有方法/函数都称为函数。

## 基本函数声明

这是一个非常简单函数的例子：

```kt
fun printHello(){ 
  Log.i("Message=","Hello") 
}
```

我们可以这样调用`printHello`函数：

```kt
printHello()
```

结果将在 logcat 窗口中输出如下：

```kt
Message=: Hello

```

函数的第一行是**声明**，大括号内包含的所有代码是函数的**主体**。我们使用`fun`关键字，后面跟着函数的名称，然后是一个开括号和闭括号。名称是任意的，但最好使用描述函数功能的名称。

## 函数参数列表

声明可以采用多种形式，这给了我们很大的灵活性和权力。让我们看一些更多的例子：

```kt
fun printSum(a: Int, b: Int) { 
  Log.i("a + b = ","${a+b}") 
}
```

前面的`printSum`函数可以这样调用：

```kt
printSum(2, 3)
```

调用`printSum`函数的结果是，以下消息将输出到 logcat 窗口：

```kt
a + b =: 5
```

请注意，传递给函数的`2`和`3`值是任意的。我们可以传递任何我们喜欢的值，只要它们是`Int`类型的。

声明的这部分`(a: Int, b: Int)`称为**参数列表**，或者只是**参数**。这是函数期望并需要的类型列表，以便成功执行。参数列表可以采用多种形式，任何 Kotlin 类型都可以成为参数列表的一部分，包括根本没有参数（正如我们在第一个例子中看到的）。

当我们调用带有参数列表的函数时，我们必须在调用时提供匹配的参数。以下是我们可以调用前面的`printSum`函数示例的几种可能方式：

```kt
val number1 = 35
val number2 = 15
printSum(9, 1)// Prints a + b: = 10
printSum(10000, 1)// Prints a + b: = 10001
printSum(number1, number2)// Prints a + b: = 50
printSum(65, number1)// Prints a + b: = 100
```

如前面的例子所示，任何组合的值，其总和为两个`Int`值，都可以作为参数。我们甚至可以使用表达式作为参数，只要它们等于一个`Int`值。例如，这个调用也是可以的：

```kt
printSum(100 - 50, number1 + number2)// Prints a + b = 100
```

在上一个示例中，从 100 中减去 50，将结果（50）作为第一个参数传递，然后将`number1`加到`number2`，并将结果作为第二个参数传递。

这里是另外两个带有各种参数的函数，以及我们可能调用它们的示例：

```kt
// These functions would be declared(typed) 
// outside of other functions
// As we did for topClick and bottomClick
fun printName(first: String, second: String){
  Log.i("Joined Name =","$first $second")
}

fun printAreaCircle(radius: Float){
  Log.i("Area =","${3.14 * (radius *radius)}")
}
//…
// This code calls the functions
// Perhaps from onCreate or some other function
val firstName = "Gabe"
val secondName = "Newell"

// Call function using literal String
printName("Sid","Meier")

// Call using String variables
printName(firstName, secondName)

// If a circle has a radius of 3 
// What is the area
printAreaCircle(3f)
```

在讨论代码之前，让我们看一下我们从中得到的输出：

```kt
Joined Name =: Sid Meier
Joined Name =: Gabe Newell
Area =: 28.26

```

在上面的代码中，我们声明了两个函数。第一个叫做`printName`，它有两个`String`参数。声明与突出显示的参数名称再次显示如下。名称是任意的，但使用有意义的名称将使代码更容易理解：

```kt
fun printName(first: String, second: String){
  Log.i("Joined Name =","$first $second")
}
```

尝试使用除两个`String`值以外的任何内容调用该函数将导致错误。当我们调用这个函数时，`first`和`second`参数被初始化为变量，然后我们使用字符串模板将连接的名称打印到 logcat 窗口中。下面再次显示了实现这一点的代码行，其中突出显示了变量：

```kt
Log.i("Joined Name =","$first $second")
```

请注意代码中`$first`和`$second`之间的空格。请注意，这个空格也存在于我们之前看到的输出中。

第二个函数是`printAreaCircle`。它有一个名为`radius`的`Float`参数。这里是它的声明，以便参考：

```kt
fun printAreaCircle(radius: Float){
  Log.i("Area =","${3.14 * (radius * radius)}")
}
```

该函数使用初始化为函数调用时的`radius`变量，使用公式`3.14 * (radius * radius)`来计算圆的面积。

然后，代码继续调用第一个函数两次，第二个函数一次。以下是代码片段中再次显示的内容（为了便于理解，已删除了有用的注释）：

```kt
val firstName = "Gabe"
val secondName = "Newell"

printName("Sid","Meier")
printName(firstName, secondName)

printAreaCircle(3f)
```

请注意，我们可以使用文字值或变量调用函数，只要它们是与声明的参数匹配的正确类型。

要清楚地说明，函数声明位于任何其他函数之外，但位于类的开放和关闭大括号内。函数调用位于`onCreate`函数内。随着我们的应用程序变得更加复杂，我们将从代码的各个部分调用函数（甚至是其他代码文件）。`onCreate`函数只是一个方便的地方，用于讨论这些主题。

### 提示

如果您想更仔细地检查代码结构，包含此代码的文件位于`Chapter09/Functions Demo`文件夹中。创建一个新的 Empty Activity 项目，您可以复制并粘贴代码进行操作。

另一个观点，可能显而易见，但很值得一提的是，当我们为真实应用编写函数时，它们可以包含尽可能多的代码；它们不会像这些示例一样只是一行代码。我们在之前章节学到的任何代码都可以放入我们的函数中。

现在，让我们继续讨论另一个与函数相关的主题，它给我们更多的选择。

## 返回类型和返回关键字

我们经常需要从函数中获得一个结果。仅仅让函数知道结果是不够的。函数可以声明具有**返回类型**。看看下一个函数声明：

```kt
fun getSum(a: Int, b: Int): Int { 
  return a + b 
}
```

在上面的代码中，看一下参数列表的括号后面的突出部分。`：Int`代码表示函数可以并且必须向调用它的代码返回`Int`类型的值。函数体内的代码行使用`return`关键字来实现这一点。`return a + b`代码返回`a`和`b`的和。

我们可以像调用没有返回类型的函数一样调用`getSum`函数：

```kt
getSum(10, 10)
```

上面的代码行可以工作，但有点无意义，因为我们没有对返回的值做任何处理。下面的代码显示了更有可能的对`getSum`函数的调用：

```kt
val answer = getSum(10, 10)
```

在上述函数中，从函数返回的值用于初始化`answer`变量。由于返回类型是`Int`，Kotlin 推断`answer`也是`Int`类型。

我们还可以以其他方式使用`getSum`——下面显示了一个示例：

```kt
// Print out the returned value
Log.i("Returned value =","${getSum(10, 10)}")
```

前面的代码以另一种方式使用了`getSum`函数，通过使用字符串模板打印返回的值到 logcat 窗口。

任何类型都可以从函数中返回。以下是一些例子；首先是声明，然后是一些我们可能调用它们的方式：

```kt
// Return the area of the circle to the calling code
fun getAreaCircle(radius: Float): Float{
  return 3.14f * (radius * radius)
}

// Return the joined-up String to the calling code
fun getName(first: String, second: String): String{
  return "$first $second"
}

// Now we can call them from elsewhere in the code
Log.i("Returned area =","${getAreaCircle(3f)}")
Log.i("Returned name =","${getName("Alan","Turing")}")
```

以下是这两个函数调用将产生的输出：

```kt
Returned area =: 28.26
Returned name =: Alan Turing

```

我们可以看到圆的面积被检索并打印出来，名字被连接在一起被检索并打印出来。

### 注意

作为一个快速的健全检查，值得指出的是，我们实际上不需要编写函数来将数字相加或连接字符串。这只是一种展示函数各个方面的有用方式。

值得注意的是，即使函数没有返回类型，`return`关键字也有其用途。

例如，我们可以使用`return`关键字提前从函数返回。我们之前的所有函数示例（没有返回类型）在主体中的最后一行代码执行时自动返回到调用代码。下面是一个使用`return`关键字的例子：

```kt
fun printUpTo3(aNumber: Int){ // No return type!
  if(aNumber > 3){
    Log.i("aNumber is","TOO BIG! - Didn't you read my name")
    return // Going back to the calling code
  }

  Log.i("aNumber is","$aNumber")
}

// And now we call it with a few different values
printUpTo3(1)
printUpTo3(2)
printUpTo3(3)
printUpTo3(4)
```

看看我们运行前面的代码时的输出，然后我们将讨论它是如何工作的：

```kt
aNumber is: 1
aNumber is: 2
aNumber is: 3
aNumber is: TOO BIG! - Didn't you read my name

```

在函数体中，`if`表达式检查`aNumber`是否大于三，如果是，就打印一个不满的评论，并使用`return`关键字返回到调用代码，并避免将值打印到 logcat。从程序输出中，我们可以看到当`aNUmber`为一、二或三时，它被`printUpTo3`函数忠实地打印出来，但是一旦我们传入了四的值，我们得到了另一种结果。

## 函数体和单表达式函数

函数体可以是复杂的或简单的，我们需要它是什么样的。到目前为止，我展示的所有例子都是故意过于简单，这样我们就可以专注于函数本身而不是其中的代码。随着本书在更多真实世界的例子中的进展，我们将看到函数体中的代码变得更长更复杂。然而，函数体应该坚持执行一个特定的任务。如果你有一个函数在 Android Studio 中占据了整个屏幕，那很可能是它应该被拆分成多个函数的迹象。

当函数的主体非常简单，只包含一个表达式时，Kotlin 允许我们使用单表达式语法来缩短代码。例如，`getSum`函数可以改为以下代码：

```kt
fun getSum(a: Int, b: Int) = a + b
```

在前面的例子中，我们去掉了通常包裹在函数体中的花括号，并推断了返回类型，因为将`a`加到`b`只能得到一个`Int`变量，因为`a`和`b`本身就是`Int`变量。

# 使函数灵活

由于函数是我们代码的构建块，它们需要具有多样性，以满足我们可能需要做的任何事情。我们已经看到了如何创建非常多样的参数列表和返回类型，以及在代码中决定何时返回到调用代码。随着我们的进展，你会发现我们需要更多的选项。接下来是一些我们现在将介绍的更多 Kotlin 函数选项的快速概览，然后在本书的各个部分真正开始使用。

## 默认和命名参数

**默认参数**是指我们程序员为参数提供一个值（默认值），如果调用函数的代码没有提供该值，则将使用该值。**命名参数**是指调用函数的代码指定名称以及值。请注意，提供值是可选的。只因为为参数提供了默认值并不意味着调用代码不能通过提供值来覆盖它。看下面的例子：

```kt
fun orderProduct(giftWrap: Boolean = false,
                product: String,
                postalService: String = "Standard") {

   var details: String = ""

   if (giftWrap) {
       details += "Gift wrapped "
   }

   details += "$product "
   details += "by $postalService postage"

   Log.i("Product details",details)
}

// Here are some ways we can call this function
orderProduct(product = "Beer")
orderProduct(true, product = "Porsche")
orderProduct(true, product = "Barbie (Jet-Set Edition)", postalService = "Next Day")

orderProduct(product = "Flat-pack bookcase", 
   postalService = "Carrier Pigeon")
```

在前面的代码中，我们首先声明了一个名为`orderProduct`的函数。请注意，在参数列表中，我们声明了两个默认值，如下所示：

```kt
fun orderProduct(giftWrap: Boolean = false,
       product: String,
       postalService: String = "Standard") {
```

当我们调用函数时，可以在不指定`giftwrap`和/或`postalService`的情况下这样做。以下代码中的第一个函数调用清楚地表明了这一点：

```kt
orderProduct(product = "Beer")
```

请注意，当我们这样做时，需要指定参数的名称，它必须与参数列表中的名称以及类型匹配。在第二个函数调用中，我们为`giftwrap`和`product`指定了一个值：

```kt
orderProduct(true, product = "Porsche")
```

在第三个中，我们为所有三个参数指定了一个值，如下面的代码中再次看到的：

```kt
orderProduct(true, product = "Barbie (Jet-Set Edition)",
   postalService = "Next Day")
```

最后，在第四个中，我们指定了最后两个参数：

```kt
orderProduct(product = "Flat-pack bookcase", 
   postalService = "Carrier Pigeon")
```

函数本身的代码从声明一个名为`details`的`var`变量开始，它是一个`String`值。如果`giftwrap`的值为 true，则将`Gift Wrapped`附加到`Product details`。接下来，将`product`的值附加到`details`，最后将`postalService`的值与字面`String`值附加在两侧。

如果我们运行代码，这是在 logcat 窗口中的输出：

```kt
Product details: Beer by Standard postage
Product details: Gift wrapped Porsche by Standard postage
Product details: Gift wrapped Barbie (Jet-Set Edition) 
 by Next Day postage
Product details: Flat-pack bookcase by Carrier Pigeon postage

```

我们可以以多种方式调用函数，这非常有用。在其他编程语言中，当您希望以不同方式调用相同命名的函数时，必须提供多个版本的函数。虽然学习命名参数和默认参数可能会增加一些复杂性，但它肯定比不得不编写`orderProduct`函数的四个版本要好。这，连同类型推断，只是您经常会听到程序员赞扬 Kotlin 简洁性的两个原因之一。

使用命名参数和默认参数，我们可以选择提供尽可能多或尽可能少的数据，只要函数允许。简而言之，如果我们提供了所有没有默认值的参数的值，它将起作用。

### 提示

如果您想要使用这段代码进行操作，那么本章中的所有示例都在`Chapter09`文件夹中。创建一个空活动项目，然后将函数复制粘贴到`MainActivity`类中，将函数调用复制粘贴到`onCreate`函数中。

在我们进行这些操作时，会有一些注意事项，随着我们在整本书中进行更多的实际示例，我们将会看到它们。

## 更多关于函数的内容

函数还有更多内容，例如顶级函数、局部函数和可变参数函数，以及函数访问级别，但最好是在类和面向对象编程的主题旁边或之后讨论这些内容。

# 总结

在本章中，我们在学习函数方面取得了良好的进展。虽然函数自第一章以来一直潜伏在我们的代码中，但我们终于正式学习和理解了它们。我们了解了函数的不同部分：名称、参数和返回类型。我们已经看到函数实际上是在开放和关闭的大括号内部执行的，称为函数体。

我们还看到，我们可以使用`return`关键字随时从函数中返回，并且我们还可以将返回类型与`return`关键字结合使用，以使函数中的数据可用于首次调用函数的代码。

我们学会了如何使用默认和命名参数来提供同一函数的不同版本，而无需编写多个函数。这使我们的代码更加简洁和可管理。

我们还发现，在本章中，函数还有更多内容，但最好是在整本书中的各种项目中学习这些主题。

接下来，我们将转向最受关注的章节。我一直在参考和推迟到第十章，“面向对象编程”。最后，它来了，我们将看到类和对象与 Kotlin 结合的真正力量。在接下来的几章中，我们很快就会看到类和对象是释放 Android API 力量的关键。我们很快就能让我们的用户界面栩栩如生，并且将构建一些真正可用的应用程序，我们可以发布到 Play 商店。


# 第十章：面向对象编程

在本章中，我们将发现，在 Kotlin 中，类对几乎所有事情都是基础的，实际上，几乎所有事情都是一个类。

我们已经谈到了重用他人的代码，特别是 Android API，但在本章中，我们将真正掌握这是如何工作的，并学习**面向对象编程**（**OOP**）以及如何使用它。

在本章中，我们将涵盖以下主题：

+   介绍 OOP 和封装、多态和继承的三个关键主题

+   基本类，包括如何编写我们的第一个类，包括为数据/变量封装添加**属性**和函数以完成任务

+   探索**可见性修饰符**，进一步帮助和完善封装。

+   了解**构造函数**，使我们能够快速准备我们的类以转换为可用的对象/实例

+   编写一个基本的类小应用程序，以实践我们在本章学到的一切

如果你试图记住本章（或下一章），你将不得不在你的大脑中腾出很多空间，而且你可能会忘记一些非常重要的东西。

一个很好的目标是尽量理解它。这样，你的理解将变得更加全面。在需要时，你可以参考本章（和下一章）进行复习。

### 提示

如果你对本章或下一章的内容并不完全理解也没关系！继续阅读，并确保完成所有的应用程序。

# 介绍 OOP

在第一章中，*开始使用 Android 和 Kotlin*，我们提到 Kotlin 是一种面向对象的语言。面向对象的语言要求我们使用 OOP；这不是可选的额外部分，而是 Kotlin 的一部分。

让我们多了解一点。

## OOP 到底是什么？

OOP 是一种编程方式，它涉及将我们的需求分解成比整体更易管理的块。

每个块都是自包含的，并且可能被其他程序重用，同时与其他块一起工作。

这些块就是我们所说的对象。当我们计划/编写一个对象时，我们使用一个类。类可以被看作是对象的蓝图。

我们实现了一个类的对象。这被称为类的**实例**。想想一个房子的蓝图——你不能住在里面，但你可以建造一座房子；所以，你建造了它的一个实例。通常，当我们为我们的应用程序设计类时，我们写它们来代表现实世界的事物。

然而，OOP 不仅仅是这样。它也是一种做事情的方式——一种定义最佳实践的方法。

OOP 的三个核心原则是**封装**、**多态**和**继承**。这些听起来可能很复杂，但一步一步来说，都是相当简单的。

### 封装

**封装**意味着通过允许你选择的变量和函数来访问，使你的代码的内部工作免受使用它的代码的干扰。

这意味着你的代码可以随时更新、扩展或改进，而不会影响使用它的程序，只要暴露的部分仍然以相同的方式访问。

你可能还记得来自第一章的这行代码，*开始使用 Android 和 Kotlin*：

```kt
locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
```

通过适当的封装，如果卫星公司或 Android API 团队需要更新他们的代码工作方式，也不要紧。如果`getLastKnownLocation`函数签名保持不变，我们就不必担心内部发生了什么。我们在更新之前编写的代码在更新后仍将正常工作。

如果一辆汽车的制造商去掉了车轮，将其变成了电动悬浮汽车，如果它仍然有方向盘、油门和刹车踏板，驾驶它不应该是一个挑战。

当我们使用 Android API 的类时，我们是按照 Android 开发人员设计他们的类的方式来使用的。

在本章中，我们将深入探讨封装。

### 多态性

多态性使我们能够编写的代码不太依赖于我们试图操作的类型，使我们的代码更清晰、更高效。多态性意味着**多种形式**。如果我们编码的对象可以是多种类型的东西，那么我们就可以利用这一点。一些未来的例子将会让这一点更加清晰。类比会让你更加真实地理解。如果我们有汽车工厂，只需改变给机器人的指令和装配线上的零件，就可以制造货车和小型卡车，那么这个工厂就是多态的。

如果我们能够编写能够处理不同类型数据的代码而无需重新开始，这不是很有用吗？我们将在第十一章中看到一些例子，*Kotlin 中的继承*。

我们还将在第十二章中了解更多关于多态性的内容，*Kotlin 与 UI 和空值的连接*。

### 继承

正如它听起来的那样，**继承**意味着我们可以利用其他人的类的所有特性和好处（包括封装和多态性），同时进一步调整他们的代码以适应我们的情况。实际上，我们已经这样做了，每次使用`:`运算符时：

```kt
class MainActivity : AppCompatActivity() {
```

`AppCompatActivity`类本身继承自`Activity`。因此，每次创建新的 Android 项目时，我们都继承自`Activity`。我们可以做得更多，我们将看到这是如何有用的。

想象一下，世界上最强壮的男人和最聪明的女人在一起。他们的孩子很有可能会从基因遗传中获得重大好处。Kotlin 中的继承让我们可以用另一个人的代码和我们自己的代码做同样的事情。

我们将在下一章中看到继承的实际应用。

## 为什么要这样做？

当小心使用时，所有这些面向对象编程允许你添加新功能，而不太担心它们如何与现有功能交互。当你必须更改一个类时，它的自包含（封装）性质意味着对程序的其他部分的影响较小，甚至可能为零。这就是封装的部分。

你可以使用其他人的代码（如 Android API），而不知道甚至可能不关心它是如何工作的。想想一下 Android 生命周期、`Toast`、`Log`、所有的 UI 小部件、监听卫星等等。我们不知道，也不需要知道它们内部是如何工作的。更详细的例子是，`Button`类有将近 50 个函数 - 我们真的想要为一个按钮自己写这么多吗？最好使用别人的`Button`类。

面向对象编程使你能够轻松地为高度复杂的情况编写应用程序。

通过继承，你可以创建类的多个相似但不同的版本，而无需从头开始编写类，并且由于多态性，你仍然可以使用原始类型对象的函数来处理新对象。

这真的很有道理。而且 Kotlin 从一开始就考虑到了所有这些，所以我们被迫使用所有这些面向对象编程 - 然而，这是一件好事。让我们快速回顾一下类。

## 类回顾

类是一堆代码的容器，可以包含函数、变量、循环和我们已经学过的其他 Kotlin 语法。类是 Kotlin 包的一部分，大多数包通常会有多个类。通常情况下，尽管不总是如此，每个新类都将在其自己的`.kt`代码文件中定义，文件名与类名相同，就像我们迄今为止所有基于活动的类一样。

一旦我们编写了一个类，我们就可以使用它来创建任意数量的对象。记住，类是蓝图，我们根据蓝图制作对象。房子不是计划，就像对象不是类一样-它是从类制作的对象。对象是一个引用变量，就像一个字符串，稍后我们将发现引用变量的确切含义。现在，让我们看一些实际的代码。

# 基本类

类涉及两个主要步骤。首先，我们必须声明我们的类，然后我们可以通过实例化它将其变成一个实际可用的对象。记住，类只是一个蓝图，你必须使用蓝图来构建一个对象，然后才能对其进行任何操作。

## 声明类

类可以根据其目的的不同而具有不同的大小和复杂性。这是一个类声明的绝对最简单的例子。

记住，我们通常会在一个与类同名的文件中声明一个新的类。

### 注意

在本书的其余部分，我们将介绍一些例外情况。

让我们看看声明类的三个例子：

```kt
// This code goes in a file named Soldier.kt
class Soldier

// This code would go in a file called Message.kt
class Message

// This code would go in a file called ParticleSystem.kt
class ParticleSystem
```

### 提示

请注意，我们将在本章结束时进行一个完整的工作项目练习。在下载包的`Chapter10/Chapter Example Classes`文件夹中，还有本章中所有理论示例的完整类。

在上面的代码中要注意的第一件事是，我已经将三个类声明合并在一起。在真实的代码中，每个声明都应该包含在自己的文件中，文件名与类名相同，扩展名为`.kt`。

要声明一个类，我们使用`class`关键字，后面跟着类的名称。因此，我们可以得出结论，在前面的代码中，我们声明了一个名为`Soldier`的类，一个名为`Message`的类，以及一个名为`ParticleSystem`的类。

我们已经知道，类可以并且经常模拟现实世界的事物。因此，可以安全地假设这三个假设的类将模拟一个士兵（也许来自游戏）、一条消息（也许来自电子邮件或短信应用程序）和一个粒子系统（也许来自科学模拟应用程序）。

### 注意

粒子系统是一个包含个体粒子的系统，这些粒子作为该系统的一部分。在计算中，它们用于模拟/可视化化学反应/爆炸和粒子行为，也许是烟雾等事物。在第二十一章中，*线程和启动实时绘图应用程序*，我们将构建一个使用粒子系统使用户的绘画看起来活灵活现的酷炫绘图应用程序。

然而，很明显，像我们刚刚看到的三个简单声明并不包含足够的代码来实现任何有用的功能。我们将在一会儿扩展类声明。首先，让我们看看如何使用我们声明的类。

## 实例化类

要从我们的类构建一个可用的对象，我们需要转到另一个代码文件。到目前为止，在整本书中，我们已经使用`AppCompatActivity`类中的`onCreate`函数来演示不同的概念。虽然你可以在 Android 的任何地方实例化一个类，但由于生命周期函数的存在，通常会使用`onCreate`来实例化我们的类的对象/实例。

看一下以下代码。我已经突出了要关注的新代码：

```kt
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

         // Instantiating one of each of our classes
             val soldier = Soldier()
 val message = Message()
 val particleSystem = ParticleSystem()    

   } // End of onCreate function

}// End of MainActivity class
```

在前面的代码中，我们实例化了三个先前声明的类的实例（创建了一个可用的对象）。让我们更仔细地研究一下语法。这是实例化`Soldier`类的代码行：

```kt
val soldier = Soldier()
```

首先，我们决定是否需要更改我们的实例。与常规变量一样，我们选择`val`或`var`。接下来，我们给我们的实例命名。在前面的代码中，对象/实例被称为`soldier`，但我们也可以称之为`soldierX`，`marine`，`john117`，甚至`squashedBanana`。名称是任意的，但与变量一样，给它们起一个有意义的名字是有意义的。此外，与变量一样，按照惯例，但不是必须的，以小写字母开头的名称和名称中的任何后续单词的首字母大写。

### 注意

在使用它们来声明类的实例时，`val`和`var`之间的区别更加微妙和重要。我们将首先学习有关类的细节，在第十二章中，*将我们的 Kotlin 连接到 UI 和可空性*，我们将重新讨论`val`和`var`，以了解我们的实例底层发生了什么。

代码的最后部分包含赋值运算符`=`，后面跟着类名`Soldier`，以及一对开放和关闭的括号`()`。

赋值运算符告诉 Kotlin 编译器将代码右侧的结果赋给左侧的变量。类型推断确定`soldier`是`Soldier`类型。

类名后面那个看起来奇怪但也许熟悉的`()`暗示着我们在调用一个函数。我们确实在调用一个特殊的函数，称为**构造函数**，它是由 Kotlin 编译器提供的。关于构造函数有很多要讨论的，所以我们将把这个话题推迟到本章稍后。

现在，我们只需要知道，下一行代码创建了一个名为`soldier`的`Soldier`类型的可用对象：

```kt
val soldier = Soldier()
```

记住，面向对象编程的目标之一是我们可以重用我们的代码。我们不仅限于只有一个`Soldier`类型的对象。我们可以有任意多个。看看下面的代码块：

```kt
val soldier1 = Soldier()
val soldier2 = Soldier()
val soldier3 = Soldier()
```

`soldier1`，`soldier2`和`soldier3`实例都是独立的、不同的实例。它们都是同一类型 - 但这是它们唯一的联系。你和你的邻居可能都是人类，但你们不是同一个人。如果我们对`soldier1`做了什么，或者改变了`soldier1`的某些东西，那么这些操作只会影响`soldier1`。`soldier2`和`soldier3`实例不受影响。事实上，我们可以实例化一整支`Soldier`对象的军队。

面向对象编程的力量正在慢慢显现，但在我们讨论的这个阶段，房间里的大象是，我们的类实际上并没有做任何事情。此外，我们的实例不持有任何值（数据），因此我们也无法对它们进行任何更改。

## 类有函数和变量（有点）

当我们在本章后面的*类变量是属性*部分时，我将很快解释略微神秘的**（有点）**标题。

我们在讨论 Kotlin 时学到的任何代码都可以作为类的一部分使用。这就是我们使我们的类有意义，使我们的实例真正有用的方法。让我们扩展类声明并添加一些变量和函数。

### 使用类的变量

首先，我们将向我们空的`Soldier`类添加一些变量，就像下面的代码一样：

```kt
class Soldier{

    // Variables
    val name = "Ryan"
    val rank = "Private"
    val missing = true
}
```

记住，所有前面的代码都将放在一个名为`Soldier.kt`的文件中。现在我们有了一个带有一些成员变量的类声明，我们可以像下面的代码中所示那样使用它们：

```kt
// First declare an instance of Soldier called soldier1
val soldier1 = Soldier()

// Now access and print each of the variables  
Log.i("Name =","${soldier1.name}")
Log.i("Rank =","${soldier1.rank}")
Log.i("Missing =","${soldier1.missing}")
```

如果将代码放在`onCreate`函数中，将在 logcat 窗口中产生以下输出：

```kt
Name =: Ryan
Rank =: Private
Missing =: true

```

在前面的代码中，我们以通常的方式实例化了`Soldier`类的一个实例。但现在，因为`Soldier`类有一些带有值的变量，我们可以使用**点语法**来访问这些值：

```kt
instanceName.variableName
```

或者，我们可以通过使用这个具体的例子来访问这些值：

```kt
soldier1.name
soldier1.rank
// Etc..
```

要清楚的是，我们使用实例名称，而不是类名称：

```kt
Soldier.name // ERROR!
```

### 提示

通常情况下，我们将在继续进行时涵盖一些例外和变化。

如果我们想要更改变量的值，我们可以使用完全相同的点语法。当然，如果你回想起第七章中讲到的，*Kotlin 变量、运算符和表达式*，可以更改的变量需要声明为`var`，而不是`val`。这是重新设计的`Soldier`类，以便我们可以稍微不同地使用它：

```kt
class Soldier{

    // Member variables
    var name = "Ryan"
    var rank = "Private"
    var missing = true
}
```

现在，我们可以使用点语法来操纵变量的值，就像它们是常规的`var`变量一样：

```kt
// First declare an instance of Soldier called soldier1
val soldier1 = Soldier()

// Now access and print each of the variables  
Log.i("Name =","${soldier1.name}")
Log.i("Rank =","${soldier1.rank}")
Log.i("Missing =","${soldier1.missing}")

// Mission to rescue Private Ryan succeeds
soldier1.missing = false;

// Ryan behaved impeccably
soldier1.rank = "Private First Class"

// Now access and print each of the variables  
Log.i("Name =","${soldier1.name}")
Log.i("Rank =","${soldier1.rank}")
Log.i("Missing =","${soldier1.missing}")
```

前面的代码将在 logcat 窗口中产生以下输出：

```kt
Name =: Ryan
Rank =: Private
Missing =: true
Name =: Ryan
Rank =: Private First Class
Missing =: false

```

在前面的输出中，首先我们看到与之前相同的三行，然后我们看到另外三行，表明 Ryan 不再失踪，并且已经晋升为`列兵`。

### 使用类的函数和变量

现在我们可以给我们的类提供数据，是时候通过给它们一些可以做的事情来使它们更有用了。为了实现这一点，我们可以给我们的类提供函数。看一下`Soldier`类的这段扩展代码。我已经将变量恢复为`val`并突出显示了新代码：

```kt
class Soldier{

    // members
    val name = "Ryan"
    val rank = "Private"
    val missing = true

    // Class function
 fun getStatus() {
 var status = "$rank $name"
 if(missing){
 status = "$status is missing!"
 }else{
 status = "$status ready for duty."
 }

 // Print out the status
 Log.i("Status",status)
 }
}
```

`getStatus`函数中的代码声明了一个名为`status`的新`String`变量，并使用`rank`和`name`中包含的值对其进行初始化。然后，它使用`if`表达式检查`missing`中的值，并根据`missing`是`true`还是`false`附加`is missing`或`ready for duty`。

然后我们可以像下面的代码演示的那样使用这个新函数：

```kt
val soldier1 = Soldier()
soldier1.getStatus()
```

与之前一样，我们创建了`Soldier`类的一个实例，然后在该实例上使用点语法调用`getStatus`函数。前面的代码将在 logcat 窗口中产生以下输出：

```kt
Status: Private Ryan is missing!

```

如果我们将`missing`的值更改为`false`，将产生以下输出：

```kt
Status: Private Ryan ready for duty.

```

请注意，类中的函数可以采用我们在第九章中讨论过的任何形式，*Kotlin 函数*。

如果你认为所有这些类的东西都很棒，但同时似乎有点僵化和不灵活，那么你是正确的。如果所有`Soldier`实例都叫 Ryan 并且都失踪，那有什么意义呢？当然，我们已经看到我们可以使用`var`变量然后更改它们，但这可能仍然很尴尬和冗长。

我们需要更好地操纵和初始化每个实例中的数据的方法。如果我们回想一下本章开头时我们简要讨论了封装的主题，那么我们也会意识到我们不仅需要允许代码操纵我们的数据，还需要控制这种操纵何时以及如何进行。

为了获得这些知识，我们需要更多地了解类中的变量，然后更详细地了解封装和可见性，最后揭示当我们实例化类的实例时，在代码末尾看到的那些类似函数的括号`()`到底是什么意思。

### 类变量是属性

原来在 Kotlin 中，类变量不仅仅是我们已经了解的普通变量。它们是**属性**。到目前为止，我们已经学到的关于如何使用变量的一切仍然成立，但是属性比值更多。它有**getter**，**setter**，以及一个特殊的类变量称为**field**隐藏在幕后。

Getter 和 setter 可以被视为编译器自动生成的特殊函数。事实上，我们已经在不知情的情况下使用了它们。

当我们在类中声明的属性/变量上使用点语法时，Kotlin 使用 getter 来“获取”值。当我们使用点语法设置值时，Kotlin 使用 setter。

当我们使用刚刚看到的点语法时，并不直接访问字段/变量本身。这种抽象的原因是为了帮助封装。

如果你之前在其他面向对象的语言（也许是 Java 或 C++）中做过一些编程，这可能会让你感到困惑，但如果你使用过更现代的面向对象语言（也许是 C#），那么这对你来说不会是全新的。如果 Kotlin 是你的第一门语言，那么你可能比有过往经验的人更有优势，因为你不会受到以前学习的包袱。

而且，你可能会猜到，如果变量是`var`，那么会提供一个 getter 和一个 setter，但如果是`val`，那么只会提供一个 getter。因此，当`Soldier`类中的变量（我们从现在开始大多数时候称之为属性）是`var`时，我们可以获取和设置它们，但当它们是`val`时，我们只能获取它们。

Kotlin 给了我们灵活性来**重写**这些 getter 和 setter，以改变当我们获取和设置属性及其关联字段的值时发生的情况。

### 提示

当属性使用字段时，它被称为**后备字段**。正如我们将看到的，一些属性不需要后备字段，因为它们可以依赖于 getter 和 setter 中的逻辑来使它们有用。

在这一点上，使用字段的一些示例将使事情更清晰。

### 使用带有 getter、setter 和字段的属性的示例

我们可以使用 getter 和 setter 来控制可以分配给其后备字段的值范围。例如，考虑将下一行代码添加到`Soldier`类中：

```kt
var bullets = 100
get() {
   Log.i("Getter being used","Value = $field")
   return field
}
set(value) {
   field = if (value < 0) 0 else value
   Log.i("Setter being used","New value = $field")
}
```

前面的代码添加了一个名为`bullets`的新`var`属性，并将其初始化为 100。然后我们看到一些新代码。getter 和 setter 被重写了。去掉 getter 和 setter 中的代码，以便以最简单的形式看到其运行：

```kt
get() {
   //.. Executes when we try to retrieve the value
}
set(value) {
   //.. Executes when we try to set the value 
}
```

明确一点，在访问`Soldier`类的实例中的`bullet`值时，getter 和 setter 中的代码会执行。看看下面的代码中可能会发生的情况：

```kt
// In onCreate or some other function/class from our app
// Create a new instance of the Soldier class
val soldier = Soldier()
// Access the value of bullets
Log.i("bullets = ","${soldier.bullets}")// Getter will execute
// Reduce the number of bullets by one
soldier.bullets --
Log.i("bullets =","${soldier.bullets}")// Setter will execute
```

在前面的代码中，我们首先创建了`Soldier`类的一个实例，然后获取存储在`bullet`属性中的值并打印出来。这触发了 getter 代码的执行。

接下来，我们减少（减少一个）`bullet`属性存储的值。任何试图改变属性持有的值的操作都会触发 setter 中的代码。

如果我们执行前面的四行代码，将在 logcat 窗口中得到以下输出：

```kt
Getter being used: Value = 100
bullets =: 100
Getter being used: Value = 100
Setter being used: New value = 99
Getter being used: Value = 99
bullets =: 99

```

创建一个名为`soldier`的`Soldier`实例后，我们使用`Log.i`将值打印到 logcat 窗口。由于此代码访问了属性存储的值，getter 代码运行并打印出以下内容：

```kt
Getter being used: Value = 100

```

然后 getter 使用下一行代码将值返回给`Log.i`函数：

`return field`

当我们创建属性时，Kotlin 创建了一个后备字段。在 getter 或 setter 中访问后备字段的方式是使用名称`field`。因此，前面的代码行的工作方式与在函数中的方式相同，并返回值，允许调用代码中的`Log.i`调用打印出值，我们将得到下一行输出：

```kt
bullets =: 100

```

下一行代码可能是最有趣的。这里再次提供以便参考：

```kt
soldier.bullets --
```

我们可能会猜想这只是触发了 setter 的执行，但是如果我们检查 logcat 中的下两行输出，我们会看到生成了以下两行输出：

```kt
Getter being used: Value = 100
Setter being used: New value = 99

```

减少（或增加）的操作需要使用 getter（知道要减少多少）然后使用 setter 来改变值。

请注意，setter 有一个名为`value`的参数，我们可以在 setter 的主体中引用它，就像普通的函数参数一样。

接下来，实例被用来输出`bullets`属性所持有的值，我们可以看到再次使用了 getter，并且输出是由类中的 getter 代码和实例（类外部）中的代码生成的。接下来再次显示最后两行输出：

```kt
Getter being used: Value = 99
bullets =: 99

```

现在我们可以看另一个使用 getter 和 setter 的例子。

正如前面提到的，有时属性根本不需要后备字段。有时，允许 getter 和 setter 中的逻辑处理通过属性访问的值就足够了。查看下面的代码，我们可以将其添加到`Soldier`类中来演示这一点：

```kt
var packWeight = 150
val gunWeight = 30
var totalWeight = packWeight + gunWeight
   get() = packWeight + gunWeight
```

在上面的代码中，我们创建了三个属性：一个名为`packWeight`的`var`属性，我们将使用即将创建的实例来更改它，一个名为`gunWeight`的`val`属性，我们永远不需要更改它，以及另一个名为`totalWeight`的`var`属性，它被初始化为`packWeight + gunWeight`。有趣的部分是，我们覆盖了`totalWeight`的 getter，以便它使用`packWeight + gunWeight`重新计算其值。接下来，让我们看看如何使用`Soldier`类的实例来使用这些新属性，然后我们将看到输出：

```kt
// Create a soldier
val strongSoldier = Soldier()

// Print out the totalWeight value
Log.i("totalWeight =","${strongSoldier.totalWeight}")

// Change the value of packWeight
strongSoldier.packWeight = 300

// Print out the totalWeight value again
Log.i("totalWeight =","${strongSoldier.totalWeight}")
```

在上面的代码中，我们创建了一个名为`strongSoldier`的`Soldier`实例。接下来，我们将`totalWeight`的值打印到 logcat。第三行代码将`packWeight`的值更改为`300`，然后最后一行代码打印出`totalWeight`的值，它将使用我们覆盖的 getter。以下是这四行代码的输出：

```kt
totalWeight =: 180
totalWeight =: 330

```

从输出中我们可以看到，`totalWeight`的值完全取决于`packWeight`和`gunWeight`中存储的值。输出的第一行是`packWeight`的起始值（`150`）加上`gunWeight`的值（`30`），第二行输出等于`packWeight`的新值加上`gunWeight`。

就像函数一样，这个非常灵活的属性系统会引发一些问题。

### 何时使用覆盖的 getter 和 setter

何时利用这些不同的技术需要通过实践和经验来决定；关于何时适合使用特定技术并没有硬性规定。在这个阶段，只需要理解在类的主体（函数之外）声明的变量实际上是属性，而属性是通过 getter 和 setter 访问的。这些 getter 和 setter 对于实例的用户来说并不是透明的，并且除非被类的程序员覆盖，否则编译器会默认提供它们。这就是封装的本质；类的程序员控制类的工作方式。属性提供对其相关值（称为后备字段）的间接访问，尽管有时这个后备字段是不需要的。

### 提示

简化讨论时将属性称为变量是可以的（我有时这样做）。特别是当 getter、setter 和字段与讨论无关时。

在下一节中，我们将看到更多可以使用 getter 和 setter 的方法，所以让我们继续讨论可见性修饰符。

# 可见性修饰符

可见性修饰符用于控制变量、函数甚至整个类的访问/可见性。正如我们将看到的，根据代码中尝试访问的位置，可以有不同级别的访问权限的变量、函数和类。这允许类的设计者实践良好的封装，并且只向类的用户提供他们选择的功能和数据。举一个有点牵强但有用的例子，用于与卫星通信并获取 GPS 数据的类的设计者不会允许访问`dropOutOfTheSky`函数。

这是 Kotlin 中的四个访问修饰符。

## 公共

将类、函数和属性声明为`public`意味着它们根本不被隐藏/封装。实际上，默认可见性是`public`，因此到目前为止我们所见过和使用的一切都是公共的。我们可以通过在所有类、函数和属性声明之前使用`public`关键字来明确表示这一点，但这并不是必要的。当某物被声明为`public`（或保持默认状态）时，不使用封装。这只是偶尔我们想要的。通常，公开类的函数将公开类的核心功能。

## 私有

我们将讨论的下一个访问修饰符是`private`。通过在声明之前加上`private`关键字，属性、函数和类可以被声明为`private`，如下一个假设的代码所示：

```kt
private class SatelliteController {
   private var gpsCoordinates = "51.331958,0.029057"

   private fun dropOutOfTheSky() {
   }
}
```

`SatelliteController`类被声明为`private`，这意味着它只能在同一文件中使用（可以实例化）。尝试在`onCreate`中实例化一个实例可能会导致以下错误：

![Private](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_10_01.jpg)

这引发了一个问题，即类是否可以被使用。将类声明为`private`比使用我们将要讨论的剩余修饰符要少得多，但这确实会发生，并且有各种技术使其成为一种可行的策略。然而，更有可能的是，`SatelliteController`类将以更加可访问的`public`可见性进行声明。

继续，我们有一个名为`gpsCoordinates`的`private`属性。假设我们将`SatelliteController`类更改为公共类，那么我们就可以实例化它并继续我们的讨论。即使`SatelliteController`被声明为`public`，或者保持默认状态为`public`，私有的`gpsCoordinates`属性仍然对类的实例不可见，如下一个截图所示：

![Private](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_10_02.jpg)

正如我们在前面的截图中所看到的，`gpsCoordinates`属性是不可访问的，因为它是`private`的，正如我们在本章前面讨论属性时所看到的，当属性保持默认状态时，它是可访问的。这些访问修饰符的目的是，类的设计者可以选择何时以及何物来公开。很可能 GPS 卫星希望分享 GPS 坐标。然而，很可能它不希望类的用户在计算坐标方面起任何作用。这表明我们希望类的用户能够读取数据，但不能写入/更改数据。这是一个有趣的情况，因为第一反应可能是将属性设置为`val`属性。这样用户就可以获取数据，但不能更改数据。但问题是 GPS 坐标显然是会变化的，因此它需要是一个`var`属性，只是不希望它是一个可以从类外部更改的`var`属性。

当我们将属性声明为`private`时，Kotlin 会自动将 getter 和 setter 也设为`private`。我们可以通过重写 getter 和/或 setter 来改变这种行为。为了解决我们需要一个在类外部不可改变但在类内部可改变和可读的`var`属性的问题，我们将保留默认的 setter，使其无法在外部改变，并重写 getter，以便在外部可读。看看下面对`SatelliteController`类的重写：

```kt
class SatelliteController {
    var gpsCoordinates = "51.331958,0.029057"
    private set

    private fun dropOutOfTheSky() {
    }
}
```

在上面的代码中，`SatelliteController`类和`gpsCoordinates`属性都是`public`的。此外，`gpsCoordinates`是一个`var`属性，因此是可变的。然而，仔细看一下属性声明后的代码行，因为它将 setter 设置为`private`，这意味着类外的代码无法访问它进行更改；但因为它是一个`var`属性，类内的代码可以对其进行任何操作。

现在我们可以在`onCreate`函数中编写以下代码来使用该类：

```kt
// This still doesn't work which is what we want
// satelliteController.gpsCoordinates = "1.2345, 5.6789"

// But this will print the gpsCoordinates
Log.i("Coords=","$satelliteController.gpsCoordinates")
```

现在，由于代码将 setter 设置为私有，我们无法从实例更改值，但可以愉快地读取它，就像前面的代码演示的那样。请注意，setter 不能更改其可见性，但可以（正如我们在首次讨论属性时看到的）重写其功能。

继续讨论`dropOutOfSky`函数的功能，这是`private`且完全不可访问的。只有`SateliteController`类内部的代码才能调用该函数。如果我们希望类的用户能够访问函数，就像我们已经看到的那样，我们只需将其保留为默认可见性。`SatelliteController`类可能有类似下面代码的函数：

```kt
class SatelliteController {
    var gpsCoordinates = "51.331958,0.029057"
    private set

    private fun dropOutOfTheSky() {
    }

    fun updateCoordinates(){
        // Recalculate coordinates and update
        // the gpsCoordinates property
        gpsCoordinates = "21.123456, 2.654321"

        // user can now access the new coordinates
        // but still can't change them
    }
}
```

在前面的代码中，添加了一个公共的`updateCoordinates`函数。这允许类的实例使用以下代码：

```kt
satelliteController.updateCoordinates()
```

然后，前面的代码将触发`updateCoordinates`函数的执行，这将导致类内部更新属性，然后可以访问并提供新值。

这引出了一个问题：哪些数据应该是私有的？应该使用的可见性级别部分可以通过常识学习，部分通过经验学习，部分通过问自己这个问题：“谁真正需要访问这些数据以及在什么程度上？”我们将在本书的其余部分中练习这三件事。以下是一些更多的假设代码，显示了`SatelliteController`类的一些私有数据和更多私有函数：

```kt
class SatelliteController {
    var gpsCoordinates = "51.331958,0.029057"
    private set

    private var bigProblem = false

    private fun dropOutOfTheSky() {
    }

    private fun doDiagnostics() {
      // Maybe set bigProblem to true
      // etc
    }

    private fun recalibrateSensors(){
      // Maybe set bigProblem to true
      // etc
    }

    fun updateCoordinates(){
        // Recalculate coordinates and update
        // the gpsCoordinates property
        gpsCoordinates = "21.123456, 2.654321"

        // user can now access the new coordinates
        // but still can't change them
    }

    fun runMaintenance(){
        doDiagnostics()
        recalibrateSensors()

        if(bigProblem){
            dropOutOfTheSky()
        }

    }
}
```

在上述代码中，有一个名为`bigProblem`的新私有`Boolean`属性。它只能在内部访问。甚至不能在外部读取。有三个新函数，一个名为`runMaintenance`的公共属性，它运行两个私有函数`doDiagnostics`和`calibrateSensors`。这两个函数可以访问并更改`bigProblem`的值（如果需要）。在`runMaintenance`函数中，进行了一个检查，看看`bigProblem`是否为 true，如果是，则调用`dropOutOfTheSky`函数。

### 提示

显然，在真实卫星的代码中，除了掉出天空之外，可能首先会寻求其他解决方案。

让我们看看最后两个可见性修饰符。

## 受保护的

当使用`protected`可见性修饰符时，其影响比`public`和`private`更微妙。当函数或属性声明为`protected`时，它几乎是私有的 - 但并非完全如此。我们将在下一章中探讨的另一个关键面向对象编程主题是继承，它允许我们编写类，然后编写另一个继承该类功能的类。`protected`修饰符将允许函数和属性对这些类可见，但对所有其他代码隐藏。

我们将在整本书中进一步探讨这个问题。

## 内部

内部修饰符比其他修饰符更接近公共。它会将属性/函数暴露给同一包中的任何代码。如果考虑到一些应用程序只有一个包，那么这是相当宽松的可见性。我们不会经常使用它，我只是想让你了解一下，以便完整起见。

## 可见性修饰符总结

尽管我们已经讨论了好几页，但我们只是触及了可见性修饰符的表面。关键是它们存在，其目的是帮助封装并使您的代码不太容易出错，并且更具可重用性。结合属性、函数、getter 和 setter，Kotlin 非常灵活，我们可以用更多的例子来说明何时以及在何处使用每个可见性修饰符，以及何时、在何处以及如何以不同方式重写 getter 和 setter。使用这些技术构建工作程序更有用。这是我们将在整本书中做的事情，我经常会提到为什么我们使用特定的可见性修饰符或者为什么我们以特定的方式使用 getter/setter。我还鼓励您在本章末尾进行基本类演示应用。

# 构造函数

在本章中，我们一直在实例化对象（类的实例），并且我们已经深入讨论了各种语法。直到现在，有一小部分代码我们一直忽略。下面的代码我们以前看过几次，但我已经突出显示了一小部分，以便我们进一步讨论：

```kt
val soldier = Soldier()

```

代码末尾的括号初始化对象的代码看起来就像前一章中调用函数时的代码（没有任何参数）。事实上，情况确实如此。当我们声明一个类时，Kotlin 提供（在幕后）一个名为**构造函数**的特殊函数，用于准备实例。

到目前为止，在本章中，我们已经在一行中声明和初始化了所有的实例。通常，我们需要在初始化中使用一些更多的逻辑，而且我们经常需要允许初始化类的代码传递一些值（就像一个函数）。这就是构造函数的原因。

通常，这个默认构造函数就是我们需要的全部内容，我们可以忘记它，但有时我们需要做更多的工作来设置我们的实例，以便它准备好使用。Kotlin 允许我们声明自己的构造函数，并给我们三个主要选项：主要构造函数、次要构造函数和`init`块。

## 主要构造函数

主要构造函数是在类声明中声明的构造函数。看看下面的代码，它定义了一个允许类的用户传入两个值的构造函数。正如我们所期望的那样，这段代码将放在一个名为`Book.kt`的文件中。

```kt
class Book(val title: String, var copiesSold: Int) {
   // Here we put our code as normal
   // But title and copiesSold are properties that
   // are already declared and initialized
}
```

在上面的代码中，我们声明了一个名为`Book`的类，并提供了一个接受两个参数的构造函数。当初始化时，它需要传递一个不可变的`String`值和一个可变的`Int`值。提供这样的构造函数，然后使用它来实例化一个实例，声明和初始化了`title`和`copiesSold`属性。没有必要以通常的方式声明或初始化它们。

看看下面的代码，它展示了如何实例化这个类的一个实例：

```kt
// Instantiate a Book using the primary constructor
val book = Book("Animal Farm", 20000000)
```

在上面的代码中，使用主要构造函数实例化了一个名为`book`的对象，属性`title`和`copiesSold`分别初始化为`Animal Farm`和`20000000`（两千万）。

就像函数一样，你可以塑造构造函数，拥有任意组合、类型和数量的参数。

主要构造函数的潜在缺点是属性从传入的参数中获取值，没有任何灵活性。如果我们需要在将它们分配给属性之前对传入的值进行一些计算怎么办？幸运的是，我们可以处理这个问题。

## 次要构造函数

次要构造函数是在类声明之外单独声明的构造函数，但仍然在类体内。关于次要构造函数需要注意的几件事是，你不能在参数中声明属性，而且你还必须从次要构造函数的代码中调用主要构造函数。次要构造函数的优势在于你可以编写一些逻辑（代码）来初始化你的属性。看看下面的代码，它展示了这一点。同时，我们还将介绍一个新的关键字：

```kt
// Perhaps the user of the class 
// doesn't know the time as it
// is yet to be confirmed
class Meeting(val day: String, val person: String) {
    var time: String = "To be decided"
    // The user of the class can
    // supply the day, time and person 
    // of a meeting
    constructor(day: String, person: String, time: String)
            :this(day, person ){

        // "this" refers to the current instance
        this.time = time
        // time (the property) now equals time
        // that was passed in as a parameter
    }
}
```

在上面的代码中，我们声明了一个名为`Meeting`的类。主要构造函数声明了两个属性，一个叫做`day`，一个叫做`person`。接下来，声明了一个名为`time`的属性，并初始化为值`To be decided`。

接下来是次要构造函数。注意参数前面有`constructor`关键字。你还会注意到，次要构造函数包含三个参数，与主要构造函数相同的两个参数，还有一个叫做`time`的参数。

请注意，`time`参数与先前声明和初始化的`time`属性不是同一个实体。次要构造函数只包含“一次性”参数，它们不会成为像主构造函数那样的持久属性。这使我们首先可以调用主构造函数传递`day`和`person`，其次（在次要构造函数的主体中）将通过`time`参数传递的值分配给`time`属性。

### 提示

您可以提供多个次要构造函数，只要签名都不同。通过匹配调用/实例化代码的参数，将调用适当的次要构造函数。

### 我们需要谈谈这个

我是说，我们需要谈谈`this`关键字。当我们在类内部使用`this`时，它会引用当前实例 - 因此它会作用于自身。

因此，`this(day, person)`代码调用初始化`day`和`person`属性的主构造函数。此外，`this.time = time`代码会将通过`time`参数传递的值分配给实际的`time`属性（`this.time`）。

### 注意

顺便提一句，如果不明显的话，`Meeting`类需要额外的函数才能使其有意义，比如`setTime`、`getMeetingDetails`，可能还有其他函数。

当用户不知道时间时（通过主构造函数）或者当他们知道时间时（通过次要构造函数）可以创建`Meeting`类的实例。

### 使用 Meeting 类

我们将通过调用我们的构造函数之一来实例化我们的实例，如下面的代码所示：

```kt
// Book two meetings
// First when we don't yet know the time
val meeting = Meeting("Thursday", "Bob")

// And secondly when we do know the time
val anotherMeeting = Meeting("Wednesday","Dave","3 PM")
```

在上面的代码中，我们初始化了`Meeting`类的两个实例，一个叫做`meeting`，另一个叫做`anotherMeeting`。在第一次实例化时，我们调用了主构造函数，因为我们不知道时间；而在第二次实例化时，我们调用了次要构造函数，因为我们知道时间。

如果需要，我们可以有多个次要构造函数，只要它们都调用主构造函数。

## 初始化块

Kotlin 被设计为一种简洁的语言，通常有更简洁的方法来初始化我们的属性。如果类不依赖于多个不同的签名，那么我们可以坚持使用更简洁的主构造函数，并在`init`块中提供任何必需的初始化逻辑：

```kt
init{
  // This code runs when the class is instantiated
  // and can be used to initialize properties
}
```

这可能是足够的理论了；让我们在一个工作应用程序中使用我们一直在谈论的一切。接下来，我们将编写一个使用类的小应用程序，包括主构造函数和`init`块。

# 基本类应用程序和使用 init 块

您可以在代码下载中获取此应用程序的完整代码。它位于`Chapter10/Basic Classes`文件夹中。但是，继续阅读以创建您自己的工作示例会更有用。

我们将使用本章学到的知识创建几个不同的类，以将理论付诸实践。我们还将看到我们的第一个示例，即类如何通过将类作为参数传递到另一个类的函数中相互交互。我们已经知道如何在理论上做到这一点，只是还没有在实践中看到它。

当类首次实例化时，我们还将看到另一种初始化数据的方法，即使用`init`块。

我们将创建一个小应用程序，用于模拟船只、码头和海战的想法。

### 注意

本章和下一章应用程序的输出将只是文本，显示在 logcat 窗口中。在第十二章中，*将我们的 Kotlin 连接到 UI 和可空性*，我们将把我们在前五章学到的关于 Android UI 的知识和在接下来的六章中学到的关于 Kotlin 的知识结合起来，让我们的应用程序活起来。

使用空活动模板创建一个名为`Basic Classes`的应用程序。现在我们将创建一个名为`Destroyer`的新类：

1.  在项目资源管理器窗口中右键单击`com.gamecodeschool.basicclasses`（或者您的包名）文件夹。

1.  选择**新建** **|** **Kotlin 文件/类**。

1.  在**名称：**字段中，键入`Destroyer`。

1.  在下拉框中选择**类**。

1.  单击**OK**按钮将新类添加到项目中。

1.  重复前面的五个步骤，创建另外两个类，一个叫做`Carrier`，另一个叫做`ShipYard`。

新的类已经为我们创建了一个类声明和大括号，准备好我们的代码。自动生成的代码还包括包声明，这将根据您在创建项目时的选择而有所不同。这是我目前代码的样子。

在`Destroyer.kt`中：

```kt
package com.gamecodeschool.basicclasses

class Destroyer {
}
```

在`Carrier.kt`中：

```kt
package com.gamecodeschool.basicclasses

class Carrier {
}
```

在`ShipYard.kt`中：

```kt
package com.gamecodeschool.basicclasses

class ShipYard {
}
```

让我们从编写`Destroyer`类的第一部分开始。接下来是构造函数、一些属性和一个`init`块。添加代码到项目中，学习它，然后我们将回顾我们所做的事情：

```kt
class Destroyer(name: String) {
    // What is the name of this ship
    var name: String = ""
        private set

    // What type of ship is it
    // Always a destroyer
    val type = "Destroyer"

    // How much the ship can take before sinking
    private var hullIntegrity = 200

    // How many shots left in the arsenal
    var ammo = 1
    // Cannot be directly set externally
        private set

    // No external access whatsoever
    private var shotPower = 60

    // Has the ship been sunk
    private var sunk = false

    // This code runs as the instance is being initialized
    init {
        // So we can use the name parameter
        this.name = "$type $name"
    }
```

首先要注意的是构造函数接收一个名为`name`的`String`值。它没有声明为`val`或`var`属性。因此，它不是一个属性，只是一个在实例初始化后将不复存在的常规参数。我们很快将看到如何利用它。

在前面的代码中，我们声明了一些属性。请注意，大多数都是可变的`var`，除了`type`，它是一个初始化为`Destroyer`的`String` `val`类型。还要注意，大多数都是`private`访问，除了两个。

`type`属性是公共的，因此可以通过类的实例完全访问。`name`属性也是公共的，但具有`private`的 setter。这将允许实例获取值，但保护后备字段（值）不被实例更改。

`hullIntegrity`、`ammo`、`shotPower`和`sunk`属性都是`private`的，无法通过实例直接访问。请务必记住这些属性的值和类型。

前面代码的最后一部分是一个`init`块，在这个块中，`name`属性通过将类型和名称属性连接起来并在中间加上一个空格来进行初始化。

接下来，添加接下来的`takeDamage`函数：

```kt
fun takeDamage(damageTaken: Int) {
   if (!sunk) {
        hullIntegrity -= damageTaken
        Log.i("$name damage taken =","$damageTaken")
        Log.i("$name hull integrity =","$hullIntegrity")

        if (hullIntegrity <= 0) {
               Log.d("Destroyer", "$name has been sunk")
               sunk = true
        }
  } else {
         // Already sunk
         Log.d("Error", "Ship does not exist")
  }
}
```

在`takeDamage`函数中，`if`表达式检查`sunk`布尔值是否为 false。如果船只还没有沉没，那么`hullIntegrity`将减去传入的`damageTaken`值。因此，尽管`private`，实例仍然会间接影响`hullIntegrity`。关键是它只能以程序员决定的方式来做到这一点；在这种情况下，是我们。正如我们将看到的，所有私有属性最终都将以某种方式被操作。

此外，如果船还没有沉没，两个`Log.i`调用将损坏信息和剩余船体完整性信息输出到 logcat 窗口。最后，在未沉没的情况下`(!sunk)`，嵌套的`if`表达式检查`hullIntegrity`是否小于零。如果是，则打印一条消息表示船已经沉没，并将`sunk`布尔值设置为 true。

当调用`damageTaken`函数并且`sunk`变量为 true 时，`else`块将执行，并打印一条消息，表示船只不存在，因为它已经沉没了。

接下来，添加`shootShell`函数，它将与`takeDamage`函数一起工作。更确切地说，一个船只实例的`takeDamage`函数将与其他船只实例的`shootShell`函数一起工作，我们很快就会看到：

```kt
fun shootShell():Int {
  // Let the calling code no how much damage to do
  return if (ammo > 0) {
         ammo--
         shotPower
  }else{
        0
  }
}
```

在`shootShell`函数中，如果船只有弹药，`ammo`属性将减少一个，并将`shotPower`的值返回给调用代码。如果船只没有弹药（`ammo`不大于零），则将值`0`返回给调用代码。

最后，对于`Destroyer`类添加`serviceShip`函数，将`ammo`设置为`10`，`hullIntegrity`设置为`100`，以便船只完全准备好再次承受伤害（通过`takeDamage`）并造成伤害（通过`shootShell`）：

```kt
fun serviceShip() {
    ammo = 10
    hullIntegrity = 100
}
```

接下来，我们可以快速编写`Carrier`类，因为它非常相似。只需注意一下分配给`type`和`hullIntegrity`的值的细微差异。还要注意，我们使用`attacksRemaining`和`attackPower`，而不是`ammo`和`shotPower`。此外，`shootShell`已被替换为`launchAerialAttack`，这似乎更适合一艘航空母舰。将以下代码添加到`Carrier`类中：

```kt
class Carrier (name: String){
    // What is the name of this ship
    var name: String = ""
        private set

    // What type of ship is it
    // Always a destroyer
    val type = "Carrier"

    // How much the ship can take before sinking
    private var hullIntegrity = 100

    // How many shots left in the arsenal
    var attacksRemaining = 1
    // Cannot be directly set externally
        private set

    private var attackPower = 120

    // Has the ship been sunk
    private var sunk = false

    // This code runs as the instance is being initialized
    init {
        // So we can use the name parameter
        this.name = "$type $name"
    }

    fun takeDamage(damageTaken: Int) {
        if (!sunk) {
            hullIntegrity -= damageTaken
            Log.d("$name damage taken =","$damageTaken")
            Log.d("$name hull integrity =","$hullIntegrity")

            if (hullIntegrity <= 0) {
                Log.d("Carrier", "$name has been sunk")
                sunk = true
            }
        } else {
            // Already sunk
            Log.d("Error", "Ship does not exist")
        }
    }

    fun launchAerialAttack() :Int {
        // Let the calling code no how much damage to do
        return if (attacksRemaining > 0) {
            attacksRemaining--
            attackPower
        }else{
            0
        }
    }

    fun serviceShip() {
        attacksRemaining = 20
        hullIntegrity = 200
    }
}
```

在我们开始使用新的类之前的最后一段代码是`ShipYard`类。它有两个简单的函数：

```kt
class ShipYard {

    fun serviceDestroyer(destroyer: Destroyer){
        destroyer.serviceShip()
    }

    fun serviceCarrier(carrier: Carrier){
        carrier.serviceShip()
    }
}
```

第一个函数`serviceDestroyer`以`Destroyer`实例作为参数，并在该函数内部简单地调用实例的`serviceShip`函数。第二个函数`serviceCarrier`具有相同的效果，但以`Carrier`实例作为参数。虽然这两个函数很简短，但它们的后续使用很快就会揭示一些与类及其实例相关的有趣细微差别。

现在我们将创建一些实例，并通过模拟一场虚构的海战来让我们的类发挥作用。将以下代码添加到`MainActivity`类的`onCreate`函数中：

```kt
val friendlyDestroyer = Destroyer("Invincible")
val friendlyCarrier = Carrier("Indomitable")

val enemyDestroyer = Destroyer("Grey Death")
val enemyCarrier = Carrier("Big Grey Death")

val friendlyShipyard = ShipYard()

// Uh oh!
friendlyDestroyer.takeDamage(enemyDestroyer.shootShell())
friendlyDestroyer.takeDamage(enemyCarrier.launchAerialAttack())

// Fight back
enemyCarrier.takeDamage(friendlyCarrier.launchAerialAttack())
enemyCarrier.takeDamage(friendlyDestroyer.shootShell())

// Take stock of the supplies situation
Log.d("${friendlyDestroyer.name} ammo = ",
         "${friendlyDestroyer.ammo}")

Log.d("${friendlyCarrier.name} attacks = ",
         "${friendlyCarrier.attacksRemaining}")

// Dock at the shipyard
friendlyShipyard.serviceCarrier(friendlyCarrier)
friendlyShipyard.serviceDestroyer(friendlyDestroyer)

// Take stock of the supplies situation again
Log.d("${friendlyDestroyer.name} ammo = ",
         "${friendlyDestroyer.ammo}")

Log.d("${friendlyCarrier.name} attacks = ",
         "${friendlyCarrier.attacksRemaining}")

// Finish off the enemy
enemyDestroyer.takeDamage(friendlyDestroyer.shootShell())
enemyDestroyer.takeDamage(friendlyCarrier.launchAerialAttack())
enemyDestroyer.takeDamage(friendlyDestroyer.shootShell())
```

让我们回顾一下那段代码。代码首先实例化了两艘友方船只（`friendlyDestroyer`和`friendlyCarrier`）和两艘敌方船只（`enemyDestroyer`和`enemyCarrier`）。此外，还实例化了一个名为`friendlyShipyard`的`Shipyard`实例，为随之而来的不可避免的大屠杀做好准备：

```kt
val friendlyDestroyer = Destroyer("Invincible")
val friendlyCarrier = Carrier("Indomitable")

val enemyDestroyer = Destroyer("Grey Death")
val enemyCarrier = Carrier("Big Grey Death")

val friendlyShipyard = ShipYard()
```

接下来，`friendlyDestroyer`对象受到两次伤害。一次来自`enemyDestroyer`，一次来自`enemyCarrier`。这是通过`friendlyDestroyer`的`takeDamage`函数传入两个敌人的`shootShell`和`launchAerialAttack`函数的返回值来实现的：

```kt
// Uh oh!
friendlyDestroyer.takeDamage(enemyDestroyer.shootShell())
friendlyDestroyer.takeDamage(enemyCarrier.launchAerialAttack())
```

接下来，友方部队通过对`enemyCarrier`对象进行两次攻击进行反击，一次来自`friendlyCarrier`对象通过`launchAerialAttack`，一次来自`friendlyDestroyer`对象通过`shootShell`：

```kt
// Fight back
enemyCarrier.takeDamage(friendlyCarrier.launchAerialAttack())
enemyCarrier.takeDamage(friendlyDestroyer.shootShell())
```

然后将两艘友方船只的状态输出到 logcat 窗口：

```kt
// Take stock of the supplies situation
Log.d("${friendlyDestroyer.name} ammo = ",
         "${friendlyDestroyer.ammo}")

Log.d("${friendlyCarrier.name} attacks = ",
         "${friendlyCarrier.attacksRemaining}")
```

现在，适当的`Shipyard`实例的函数依次在适当的实例上调用。没有`enemyShipyard`对象，因此它们将无法进行修复和重新武装：

```kt
// Dock at the shipyard
friendlyShipyard.serviceCarrier(friendlyCarrier)
friendlyShipyard.serviceDestroyer(friendlyDestroyer)
```

接下来，再次打印统计数据，以便我们可以看到访问船坞后的差异：

```kt
// Take stock of the supplies situation again
Log.d("${friendlyDestroyer.name} ammo = ",
         "${friendlyDestroyer.ammo}")

Log.d("${friendlyCarrier.name} attacks = ",
         "${friendlyCarrier.attacksRemaining}")
```

然后，或许是不可避免的，友方部队击败了敌人：

```kt
// Finish off the enemy
enemyDestroyer.takeDamage(friendlyDestroyer.shootShell())
enemyDestroyer.takeDamage(friendlyCarrier.launchAerialAttack())
enemyDestroyer.takeDamage(friendlyDestroyer.shootShell())
```

运行应用程序，然后我们可以在 logcat 窗口中检查以下输出：

```kt
Destroyer Invincible damage taken =: 60
Destroyer Invincible hull integrity =: 140
Destroyer Invincible damage taken =: 120
Destroyer Invincible hull integrity =: 20
Carrier Big Grey Death damage taken =: 120
Carrier Big Grey Death hull integrity =: -20
Carrier: Carrier Big Grey Death has been sunk
Error: Ship does not exist
Destroyer Invincible ammo =: 0
Carrier Indomitable attacks =: 0
Destroyer Invincible ammo =: 10
Carrier Indomitable attacks =: 20
Destroyer Grey Death damage taken =: 60
Destroyer Grey Death hull integrity =: 140
Destroyer Grey Death damage taken =: 120
Destroyer Grey Death hull integrity =: 20
Destroyer Grey Death damage taken =: 60
Destroyer Grey Death hull integrity =: -40
Destroyer: Destroyer Grey Death has been sunk
```

这里是输出，这次分成几部分，以便我们清楚地看到哪些代码产生了哪些输出行。

友好的驱逐舰遭到袭击，使其船体接近破裂点：

```kt
Destroyer Invincible damage taken =: 60
Destroyer Invincible hull integrity =: 140
Destroyer Invincible damage taken =: 120
Destroyer Invincible hull integrity =: 20
```

敌方航空母舰遭到攻击并被击沉：

```kt
Carrier Big Grey Death damage taken =: 120
Carrier Big Grey Death hull integrity =: -20
Carrier: Carrier Big Grey Death has been sunk
```

敌方航空母舰再次遭到攻击，但因为它被击沉，`takeDamage`函数中的`else`块被执行：

```kt
Error: Ship does not exist
```

当前的弹药/可用攻击统计数据被打印出来，友方部队的情况看起来很糟糕：

```kt
Destroyer Invincible ammo =: 0
Carrier Indomitable attacks =: 0
```

快速访问船坞，情况会好得多：

```kt
Destroyer Invincible ammo =: 10
Carrier Indomitable attacks =: 20
```

友方部队全副武装并修复，完成了剩余驱逐舰的摧毁：

```kt
Destroyer Grey Death damage taken =: 60
Destroyer Grey Death hull integrity =: 140
Destroyer Grey Death damage taken =: 120
Destroyer Grey Death hull integrity =: 20
Destroyer Grey Death damage taken =: 60
Destroyer Grey Death hull integrity =: -40
Destroyer: Destroyer Grey Death has been sunk
```

如果有任何代码或输出似乎不匹配，请务必再次查看。

# 引用介绍

此时你可能会有一个困扰的想法。再次查看`Shipyard`类中的两个函数：

```kt
fun serviceDestroyer(destroyer: Destroyer){
        destroyer.serviceShip()
}

fun serviceCarrier(carrier: Carrier){
        carrier.serviceShip()
}
```

当我们调用那些函数并将`friendlyDestroyer`和`friendlyCarrier`传递给它们相应的`service…`函数时，我们从输出的前后看到，实例内的值已经改变了。通常，如果我们想保留函数的结果，我们需要使用返回值。发生的是，与具有常规类型参数的函数不同，当我们传递一个类的实例时，我们实际上是传递了**引用**到实例本身 - 不仅仅是其中的值的副本，而是实际的实例。

此外，所有与船相关的不同实例都是用`val`声明的，那么我们如何改变任何属性呢？对这个谜团的简短回答是，我们并没有改变引用本身，只是其中的属性，但显然需要进行更充分的讨论。

我们将开始探讨引用，然后深入探讨其他相关主题，比如第十二章中的 Android 设备内存，*将我们的 Kotlin 连接到 UI 和可空性*。目前，知道当我们将数据传递给函数时，如果它是一个类类型，我们传递的是一个等效的引用（虽然实际上并非如此）到真实的实例本身。

# 总结

我们终于写了我们的第一个类。我们已经看到我们可以在与类同名的文件中实现一个类。类本身在我们实例化一个对象/类的实例之前并不做任何事情。一旦我们有了一个类的实例，我们就可以使用它的特殊变量，称为属性，以及它的非私有函数。正如我们在基本类应用程序中证明的那样，每个类的实例都有自己独特的属性，就像当你买一辆工厂生产的汽车时，你会得到自己独特的方向盘、卫星导航和加速条纹。我们还遇到了引用的概念，这意味着当我们将一个类的实例传递给一个函数时，接收函数就可以访问实际的实例。

所有这些信息都会引发更多的问题。面向对象编程就是这样。因此，让我们在下一章中通过更仔细地研究继承来巩固所有这些类的内容。


# 第十一章：Kotlin 中的继承

在本章中，我们将看到继承的实际应用。实际上，我们已经看到了，但现在我们将更仔细地研究它，讨论其好处，并编写我们可以继承的类。在整个章节中，我将向您展示几个继承的实际例子，并在本章结束时改进我们在上一章中的海战模拟，并展示我们如何通过使用继承来节省大量的输入和未来的调试。

在本章中，我们将涵盖以下主题：

+   **面向对象编程**（**OOP**）和继承

+   使用开放类进行继承

+   重写函数

+   关于多态性的更多内容

+   抽象类

+   继承示例应用程序

让我们开始，让我们再多谈一点理论。

# OOP 和继承

我们已经看到了如何通过实例化/创建对象从类中重用我们自己的代码和其他人的代码。但是整个 OOP 的概念甚至比这更深入。

如果有一个类中有大量有用的功能，但不完全符合我们的要求怎么办？想想我们编写`Carrier`类时的情况。它与`Destroyer`类非常接近，我们几乎可以复制粘贴它。我们可以从一个类**继承**，然后进一步完善或添加其工作方式和功能。

您可能会惊讶地听到我们已经这样做了。实际上，我们已经对我们创建的每个应用程序都这样做了。当我们使用`:`语法时，我们正在继承。您可能还记得`MainActivity`类中的这段代码：

```kt
class MainActivity : AppCompatActivity() {
```

在这里，我们从`AppCompatActivity`类继承了所有功能-或者更具体地说，类的设计者希望我们能够访问的所有功能。

我们甚至可以重写一个函数，并在一定程度上依赖于我们继承的类中的重写函数。例如，每次我们继承`AppCompatActivity`类时，我们都重写了`onCreate`函数。但是当我们这样做时，我们也调用了类设计者提供的默认实现：

```kt
super.onCreate(... 
```

### 提示

`super`关键字指的是被继承的超类。

而且，在第六章中，*Android 生命周期*，我们重写了`Activity`类的许多生命周期函数。请注意，您可以有多个级别的继承，尽管良好的设计通常建议不要有太多级别。例如，我已经提到`AppCompatActivity`继承自`Activity`，而我们又从`AppCompatActivity`继承。

有了这个想法，让我们看一些示例类，并看看我们如何扩展它们，只是为了看到语法，作为第一步，并且能够说我们已经做到了。

# 使用开放类进行继承

在这一点上，学习的一些有用术语是被继承的类被称为**超类**或**基类**。其他常见的称呼这种关系的方式是**父**类和**子**类。子类继承自父类。

默认情况下，类不能被继承。它被称为**final**类-不开放用于扩展或继承。但是，很容易将类更改为可继承的。我们只需要在类声明中添加`open`关键字。

## 基本继承示例

看看下面的代码，它使用`open`关键字与类声明，并使该类可以被继承：

```kt
open class Soldier() {

    fun shoot () {
        Log.i("Action","Bang bang bang")
    }
}
```

### 提示

本章中的所有示例都可以在`Chapter11/Chapter Examples`文件夹中找到。

现在我们可以继续创建`Soldier`类型的对象并调用`shoot`函数，就像下面的代码一样：

```kt
val soldier = Soldier()
soldier.shoot()
```

前面的代码仍然会将`Bang bang bang`输出到 logcat 窗口；我们不必继承它才能使用它。然而，如果我们想要精细化或专门化我们对`Soldier`类的使用，我们可以创建一个专门类型的`Soldier`并继承`shoot`函数。我们可以创建更多的类，也许`Special Forces`和`Paratrooper`，并使用`:`语法从`Soldier`继承。以下是`SpecialForces`类的代码：

```kt
class SpecialForces: Soldier(){
    fun SneakUpOnEnemy(){
        Log.i("Action","Sneaking up on enemy")
    }
}
```

注意使用冒号表示继承。它还添加了一个`sneakUpOnEnemy`函数。

接下来，考虑`Paratrooper`类的以下代码：

```kt
class Paratrooper: Soldier() {
    fun jumpOutOfPlane() {
        Log.i("Action", "Jump out of plane")
    }
}
```

前面的代码还使`Paratrooper`从`Soldier`继承，并添加了`jumpOutOfPlane`函数。

这是我们如何使用这两个新的子类的：

```kt
val specialForces = SpecialForces()
specialForces.shoot()
specialForces.SneakUpOnEnemy()

val paratrooper = Paratrooper()
paratrooper.shoot()
paratrooper.jumpOutOfPlane()
```

在前面的代码中，我们实例化了一个`SpecialForces`实例和一个`Paratrooper`实例。该代码演示了两个实例都可以访问基类中的`shoot`函数，并且两个类都可以访问自己的专门函数。代码的输出将如下所示：

```kt
Action: Bang bang bang
Action: Sneaking up on enemy
Action: Bang bang bang
Action: Jump out of plane

```

继承还有更多内容。让我们看看当我们需要进一步完善基类/超类的功能时会发生什么。

## 重写函数

重写函数是我们已经做过的事情，但我们需要进一步讨论。我们已经在我们编写的每个应用程序中重写了`onCreate`函数，并且在第六章中，*Android 生命周期*，我们重写了`AppCompatActivity`类的许多其他函数。

考虑一下我们可能想要添加一个`Sniper`类。起初这可能看起来很简单。只需编写一个类，继承自`Soldier`，并添加一个`getIntoPosition`函数，也许。如果我们想让`Sniper`类的射击方式与普通的`Soldier`不同怎么办？看看`Sniper`类的以下代码，它重写了`shoot`函数，并用`Sniper`类的专门版本替换了它：

```kt
class Sniper: Soldier(){
    override fun shoot(){
        Log.i("Action","Steady… Adjust for wind… Bang.")
    }

    fun getIntoPosition(){
        Log.i("Action","Preparing line of sight to target")
    }
}
```

你可能会认为工作已经完成，但这会导致一个小问题。在`Sniper`类中有一个错误，如下一个截图所示：

![重写函数](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-prog-kt-bg/img/B12806_11_01.jpg)

错误是因为`shoot`函数没有被写成可以被重写。默认情况下，函数是 final 的，就像类一样。这意味着子类必须按原样使用它。解决方案是回到`Soldier`类并在`shoot`函数声明前面添加`open`关键字。以下是带有微妙但至关重要的添加的`Soldier`类的更新代码：

```kt
open class Soldier() {

    open fun shoot () {
        Log.i("Action","Bang bang bang")
    }
}
```

现在我们已经修复了错误，可以编写以下代码来实例化`Sniper`类并使用重写的`shoot`函数：

```kt
val sniper = Sniper()
sniper.shoot()
sniper.getIntoPosition()
```

这产生了以下输出：

```kt
Action: Steady… Adjust for wind… Bang.
Action: Preparing line of sight to target

```

我们可以看到已使用重写的函数。值得注意的是，即使子类重写了父类的函数，它仍然可以使用父类的函数。考虑一下，如果狙击手的狙击步枪用完了，需要切换到其他武器会发生什么。看看`Sniper`类的重新编写代码：

```kt
class Sniper: Soldier(){
    // He forget to bring enough ammo
    var sniperAmmo = 3

    override fun shoot(){
        when (sniperAmmo > 0) {
            true -> {
                Log.i("Action", "Steady… Adjust for wind… Bang.")
                sniperAmmo--;
            }
            false -> super.shoot()
        }
    }

    fun getIntoPosition(){
        Log.i("Action","Preparing line of sight to target")
    }
}
```

在`Sniper`类的新版本中，有一个名为`sniperAmmo`的新属性，并且初始化为`3`。重写的`shoot`函数现在使用`when`表达式来检查`sniperAmmo`是否大于零。如果大于零，则通常的文本将被打印到 logcat 窗口，并且`sniperAmmo`将被递减。这意味着表达式只会返回三次 true。`when`表达式还处理了当它为 false 时会发生什么，并调用`super.shoot()`。这行代码调用`Soldier`的`shoot`函数的版本-超类。

现在，我们可以尝试在`Sniper`实例上四次调用`shoot`函数，就像以下代码中的方式，并观察发生了什么：

```kt
val sniper = Sniper()
sniper.getIntoPosition()
sniper.shoot()
sniper.shoot()
sniper.shoot()
// Damn! where did I put that spare ammo
sniper.shoot()
```

这是我们从前面的代码中得到的输出：

```kt
Action: Preparing line of sight to target
Action: Steady… Adjust for wind… Bang.
Action: Steady… Adjust for wind… Bang.
Action: Steady… Adjust for wind… Bang.
Action: Bang bang bang

```

我们可以看到前三次调用`sniper.shoot()`都从`Sniper`类中重写的`shoot`函数输出，第四次仍然调用重写版本，但`when`表达式的`false`分支调用超类版本的`shoot`，我们从`Soldier`类中得到输出。

### 提示

到目前为止，基于继承的示例的工作项目可以在代码下载的`Chapter11`文件夹中找到。它被称为`Inheritance Examples`。

## 到目前为止的总结

好像面向对象编程还不够有用，我们现在可以模拟现实世界的对象。我们还看到，通过从其他类进行子类化/扩展/继承，我们可以使面向对象编程变得更加有用。

### 提示

通常情况下，我们可能会问自己这个关于继承的问题：为什么？原因大致如下：如果我们在父类中编写通用代码，那么我们可以更新该通用代码，所有继承它的类也将被更新。此外，我们可以通过可见性修饰符来辅助封装，因为子类只能使用公共/受保护的实例变量和函数，并且只能重写开放函数。因此，如果设计得当，这也进一步增强了封装的好处。

# 更多多态性

我们已经知道多态意味着许多形式，但对我们来说意味着什么呢？

简化到最简单的形式，意味着以下内容：

### 注意

任何子类都可以作为使用超类的代码的一部分。

这意味着我们可以编写更容易理解、更容易更改的代码。

此外，我们可以为超类编写代码，并依赖于无论它被子类化多少次，代码仍将在一定范围内工作。让我们讨论一个例子。

假设我们想使用多态来帮助编写一个动物园管理应用程序。我们可能会想要有一个函数，比如`feed`。我们还可以说我们有`Lion`，`Tiger`和`Camel`类，它们都继承自一个名为`Animal`的父类。我们可能还想将要喂食的动物的引用传递给`feed`函数。这似乎意味着我们需要为每种类型的`Animal`编写一个 feed 函数。

然而，我们可以使用多态参数编写多态函数：

```kt
fun feed(animalToFeed: Animal){
   // Feed any animal here
}
```

前面的函数有`Animal`作为参数，这意味着可以将从继承自`Animal`的类构建的任何对象传递给它。

因此，您甚至可以今天编写代码，然后在一周、一个月或一年后创建另一个子类，相同的函数和数据结构仍然可以工作。

此外，我们可以对我们的子类强制执行一组规则，规定它们可以做什么，不能做什么，以及如何做。因此，在一个阶段的巧妙设计可以影响其他阶段。

但我们真的会想要实例化一个实际的`Animal`吗？

## 抽象类和函数

抽象函数是使用`abstract`关键字声明的函数。到目前为止还没有问题。但是，抽象函数也根本没有主体。明确地说，抽象函数中没有任何代码。那么，我们为什么要这样做呢？答案是，当我们编写抽象函数时，我们强制任何从具有抽象函数的类继承的类来实现/重写该函数。以下是一个假设的抽象函数：

```kt
abstract fun attack(): Int
```

没有主体，没有代码，甚至没有空花括号。任何想要从该类继承的类必须以与前面声明的签名完全相同的方式实现`attack`函数。

`abstract`类是一个不能被实例化的类-不能成为对象。那么，这就是一个永远不会被使用的蓝图？但这就像支付一个建筑师来设计你的家，然后永远不建造它！您可能会对自己说：“我有点明白抽象函数的概念，但抽象类只是愚蠢。”

如果一个类的设计者想要强制类的用户在使用他们的类之前继承，他们可以将一个类声明为`abstract`。然后，我们就不能从中创建对象；因此，我们必须先继承它，然后从子类创建对象。

让我们看一个例子。我们通过使用`abstract`关键字声明一个类为`abstract`类，像这样：

```kt
abstract class someClass{
   /*
         All functions and properties here.
         As usual!
         Just don't try and make 
         an object out of me!
   */
}
```

是的，但为什么呢？

有时我们想要一个可以用作多态类型的类，但我们需要保证它永远不能被用作对象。例如，`Animal`本身并没有太多意义。

我们不谈论动物，我们谈论*动物的类型*。我们不会说，“哦，看那只可爱的毛茸茸的白色动物”，或者，“昨天我们去宠物店买了一只动物和一个动物床。”这太抽象了。

因此，`abstract`类有点像一个模板，可以被任何继承自它的类使用。

我们可能想要一个`Worker`类，并扩展此类以创建`Miner`、`Steelworker`、`OfficeWorker`，当然还有`Programmer`。但是一个普通的`Worker`到底是做什么的呢？为什么我们会想要实例化一个呢？

答案是我们不想实例化一个，但我们可能想要将其用作多态类型，以便我们可以在函数之间传递多个工作子类，并且可以容纳所有类型的`Worker`的数据结构。

我们称这种类为抽象类，当一个类有一个抽象函数时，它必须被声明为抽象类。所有抽象函数必须被任何继承自它的类重写。

这意味着抽象类可以提供一些在其所有子类中都可用的常见功能。例如，`Worker`类可能具有`height`、`weight`和`age`属性。

它可能还有`getPayCheck`函数，这个函数不是抽象的，在所有子类中都是相同的，但是`doWork`函数是抽象的，必须被重写，因为所有不同类型的工作者都有非常不同的`doWork`。

# 使用继承示例应用程序的类

我们已经看过了我们可以创建类的层次结构来模拟适合我们应用程序的系统的方式。因此，让我们构建一个项目，以改进我们在上一章中进行的海战。

使用空活动模板创建一个名为`Basic Classes with Inheritance Example`的新项目。如你所料，完成的代码可以在`Chapter11`文件夹中找到。

这就是我们要做的：

+   将`Carrier`和`Destroyer`类的大部分功能放入`Ship`超类中。

+   为`Carrier`和`Destroyer`类都继承自`Ship`类，从而节省大量代码维护。

+   使用多态性来调整`Shipyard`类中的`serviceShip`函数，使其以`Ship`作为参数，从而可以为继承自`Ship`的任何实例提供服务，从而减少类中的函数数量。

+   我们还将看到，不仅代码量比以前少，而且封装性也比以前更好。

创建一个名为`Ship`的新类，并编写如下代码。然后我们将讨论它与上一个项目中的`Destroyer`和`Carrier`类的比较：

```kt
abstract class Ship(
        val name: String,
        private var type: String,
        private val maxAttacks: Int,
        private val maxHullIntegrity: Int) {

    // The stats that all ships have
    private var sunk = false
    private var hullIntegrity: Int
    protected var attacksRemaining: Int

    init{
        hullIntegrity = this.maxHullIntegrity
        attacksRemaining = 1
    }

    // Anything can use this function
    fun takeDamage(damageTaken: Int) {
        if (!sunk) {
            hullIntegrity -= damageTaken
            Log.i("$name damage taken =","$damageTaken")
            Log.i("$name hull integrity =","$hullIntegrity")

            if (hullIntegrity <= 0) {
                Log.i(type, "$name has been sunk")
                sunk = true
            }
        } else {
            // Already sunk
            Log.i("Error", "Ship does not exist")
        }
    }

    fun serviceShip() {
        attacksRemaining = maxAttacks
        hullIntegrity = maxHullIntegrity
    }

    fun showStats(){
        Log.i("$type $name",
                "Attacks:$attacksRemaining - Hull:$hullIntegrity")
    }

    abstract fun attack(): Int

}
```

首先，你会注意到这个类被声明为`abstract`，所以我们知道我们必须从这个类继承，而不能直接使用它。向下扫描代码，你会看到一个名为`attack`的抽象函数。我们现在知道，当我们从`Ship`继承时，我们需要重写并提供一个名为`attack`的函数的代码。这正是我们需要的，因为你可能记得航空母舰发动攻击，驱逐舰发射炮弹。

向上扫描前面的代码，你会看到构造函数声明了四个属性。其中两个属性是新的，另外两个与之前的项目具有相同的用途，但我们如何调用构造函数才是有趣的，我们很快就会看到。

两个新属性是`maxAttacks`和`maxHullIntegrity`，这样`Shipyard`就可以将它们恢复到适合特定类型船只的水平。

在`init`块中，未在构造函数中初始化的属性被初始化。接下来是`takeDamage`函数，它具有与上一个项目中的`takeDamage`函数相同的功能，只是它只在`Ship`类中，而不是在`Carrier`和`Destroyer`类中。

最后，我们有一个`showStats`函数，用于将与日志窗口相关的统计值打印出来，这意味着这些属性也可以是私有的。

请注意，除了`name`和一个叫做`attacksRemaining`的受保护属性之外，所有属性都是私有的。请记住，`protected`意味着它只在继承自`Ship`类的实例内可见。

现在，按照下面所示的方式编写新的`Destroyer`类：

```kt
class Destroyer(name: String): Ship(
        name,
        "Destroyer",
        10,
        200) {

    // No external access whatsoever
    private var shotPower = 60

    override fun attack():Int {
        // Let the calling code no how much damage to do
        return if (attacksRemaining > 0) {
            attacksRemaining--
            shotPower
        }else{
            0
        }
    }
}
```

现在，按照下面所示的方式编写`Carrier`类，然后我们可以比较`Destroyer`和`Carrier`：

```kt
class Carrier (name: String): Ship(
        name,
        "Carrier",
        20,
        100){

    // No external access whatsoever
    private var attackPower = 120

    override fun attack(): Int {
        // Let the calling code no how much damage to do
        return if (attacksRemaining > 0) {
            attacksRemaining--
            attackPower
        }else{
            0
        }
    }
}
```

请注意，前面两个类只接收一个名为`name`的`String`值作为构造函数参数。您还会注意到`name`没有用`val`或`var`声明，因此它不是一个属性，只是一个不会持久存在的临时参数。每个类的第一件事是继承自`Ship`并调用`Ship`类的构造函数，同时传入适用于`Destroyer`或`Carrier`的值。

两个类都有与攻击相关的属性。`Destroyer`有`shotPower`，`Carrier`有`attackPower`。然后它们都实现/重写`attack`函数以适应它们将执行的攻击类型。但是，两种类型的攻击将以相同的方式通过相同的函数调用触发。

按照下面所示的方式编写新的`Shipyard`类：

```kt
class ShipYard {
    fun serviceShip(shipToBeServiced: Ship){
        shipToBeServiced.serviceShip()
        Log.i("Servicing","${shipToBeServiced.name}")
    }
}
```

在`Shipyard`类中，现在只有一个函数。它是一个多态函数，以`Ship`实例作为参数。然后调用超类的`serviceShip`函数，该函数将将弹药/攻击和`hullIntegrity`恢复到适合船只类型的水平。

### 提示

`Shipyard`类是肤浅的这一说法是正确的。我们本可以直接调用`serviceShip`而不将实例传递给另一个类。但是，这清楚地表明我们可以将两个不同的类视为相同类型，因为它们都继承自相同的类型。多态的概念甚至比这更深入，我们将在下一章中讨论接口时看到。毕竟，多态意味着许多事物，而不仅仅是两件事物。

最后，在`MainActivity`类的`onCreate`函数中添加代码，让我们的辛勤工作付诸实践：

```kt
val friendlyDestroyer = Destroyer("Invincible")
val friendlyCarrier = Carrier("Indomitable")

val enemyDestroyer = Destroyer("Grey Death")
val enemyCarrier = Carrier("Big Grey Death")

val friendlyShipyard = ShipYard()

// A small battle
friendlyDestroyer.takeDamage(enemyDestroyer.attack())
friendlyDestroyer.takeDamage(enemyCarrier.attack())
enemyCarrier.takeDamage(friendlyCarrier.attack())
enemyCarrier.takeDamage(friendlyDestroyer.attack())

// Take stock of the supplies situation
friendlyDestroyer.showStats()
friendlyCarrier.showStats()

// Dock at the shipyard
friendlyShipyard.serviceShip(friendlyCarrier)
friendlyShipyard.serviceShip(friendlyDestroyer)

// Take stock of the supplies situation
friendlyDestroyer.showStats()
friendlyCarrier.showStats()

// Finish off the enemy
enemyDestroyer.takeDamage(friendlyDestroyer.attack())
enemyDestroyer.takeDamage(friendlyCarrier.attack())
enemyDestroyer.takeDamage(friendlyDestroyer.attack())
```

这段代码完全遵循与以下相同的模式：

1.  攻击友方船只

1.  反击并击沉敌方航母

1.  打印统计数据

1.  造船厂进行修理和重新武装

1.  再次打印统计数据

1.  完成最后一个敌人

现在我们可以观察输出：

```kt
Invincible damage taken =: 60
Invincible hull integrity =: 140
Invincible damage taken =: 120
Invincible hull integrity =: 20
Big Grey Death damage taken =: 120
Big Grey Death hull integrity =: -20
Carrier: Big Grey Death has been sunk
Error: Ship does not exist
Destroyer Invincible: Attacks:0 - Hull:20
Carrier Indomitable: Attacks:0 - Hull:100
Servicing: Indomitable
Servicing: Invincible
Destroyer Invincible: Attacks:10 - Hull:200
Carrier Indomitable: Attacks:20 - Hull:100
Grey Death damage taken =: 60
Grey Death hull integrity =: 140
Grey Death damage taken =: 120
Grey Death hull integrity =: 20
Grey Death damage taken =: 60
Grey Death hull integrity =: -40
Destroyer: Grey Death has been sunk

```

在前面的输出中，我们可以看到几乎相同的输出。但是，我们用更少的代码和更多的封装实现了它，而且，如果在六个月后我们需要一个使用鱼雷进行攻击的`Submarine`类，那么我们可以在不更改任何现有代码的情况下添加它。

# 总结

如果您没有记住所有内容，或者有些代码看起来有点太深入了，那么您仍然成功了。

如果你只是理解 OOP 是通过封装、继承和多态编写可重用、可扩展和高效的代码，那么你就有成为 Kotlin 大师的潜力。

简而言之，OOP 使我们能够使用其他人的代码，即使那些其他人在编写代码时并不知道我们当时会做什么。

你所需要做的就是不断练习，因为我们将在整本书中一遍又一遍地使用这些概念，所以你不需要在这一点上甚至已经掌握它们。

在下一章中，我们将重新审视本章的一些概念，以及探讨面向对象编程的一些新方面，以及它如何使我们的 Kotlin 代码与 XML 布局进行交互。
