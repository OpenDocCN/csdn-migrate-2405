# Kotlin 安卓开发（五）

> 原文：[`zh.annas-archive.org/md5/5516731C6537B7140E922B2C519B8673`](https://zh.annas-archive.org/md5/5516731C6537B7140E922B2C519B8673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：代理

Kotlin 非常重视设计模式。之前，我们已经看到了单例模式的使用是如何通过对象声明简化的，以及观察者模式的使用是如何通过高阶函数和函数类型变得微不足道的。此外，Kotlin 通过 lambda 表达式和函数类型简化了大多数函数模式的使用。在本章中，我们将看到委托和装饰器模式的使用是如何通过类委托简化的。我们还将看到一个在编程世界中非常新的特性——属性委托——以及它是如何用来使 Kotlin 属性更加强大的。

在本章中，我们将涵盖以下主题：

+   委托模式

+   类委托

+   装饰器模式

+   属性委托

+   标准库中的属性委托

+   创建自定义属性委托

# 类委托

Kotlin 有一个名为**类委托**的特性。这是一个非常不起眼的特性，但有许多实际应用。值得注意的是，它与两种设计模式——委托模式和装饰器模式——密切相关。我们将在接下来的章节中更详细地讨论这些模式。委托和装饰器模式已经为人所知多年，但在 Java 中，它们的实现需要大量样板代码。Kotlin 是第一批为这些模式提供本地支持并将样板代码减少到最低程度的语言之一。

# 委托模式

在面向对象编程中，委托模式是一种设计模式，它是继承的一种替代方法。委托意味着对象通过将请求委托给另一个对象（委托）来处理请求，而不是扩展类。

为了支持从 Java 中所知的多态行为，两个对象都应该实现相同的接口，该接口包含所有委托的方法和属性。委托模式的一个简单示例如下：

```kt
    interface Player { // 1 
        fun playGame() 
    } 

    class RpgGamePlayer(val enemy: String) : Player { 
        override fun playGame() { 
            println("Killing $enemy") 
        } 
    } 

    class WitcherPlayer(enemy: String) : Player { 
        val player = RpgGamePlayer(enemy) // 2 

        override fun playGame() { 
            player.playGame() // 3 
        } 
    } 

    // Usage 
    RpgGamePlayer("monsters").playGame() // Prints: Killing monsters 
    WitcherPlayer("monsters").playGame() // Prints: Killing monsters 
```

1.  当我们谈论类委托时，需要有一个定义了委托方法的接口。

1.  我们要委托的对象（委托）。

1.  `WitcherPlayer`类中的所有方法都应该调用委托对象（`player`）上的相应方法。

这被称为委托，因为`WitcherPlayer`类将`Player`接口中定义的方法委托给了`RpgGamePlayer`类型的实例（`player`）。使用继承而不是委托也可以达到类似的结果。它看起来如下：

```kt
    class WitcherPlayer() : RpgGamePlayer() 
```

乍一看，这两种方法可能看起来相似，但委托和继承有很多不同之处。一方面，继承更受欢迎，使用更为普遍。它经常在 Java 中使用，并与多种面向对象模式相关联。另一方面，有一些来源强烈支持委托。例如，影响深远的《设计模式》一书，由四人组合编写，包含了这样的原则：*更倾向于对象组合而不是类继承*。此外，流行的《Effective Java》一书中包含了这样的规则：*更倾向于组合而不是继承*（第 6 条）。它们都强烈支持委托模式。以下是一些支持使用委托模式而不是继承的基本论点：

+   通常类并不是为了继承而设计的。当我们重写方法时，我们并不知道关于类内部行为的基本假设（方法何时被调用，这些调用如何影响对象、状态等）。例如，当我们重写方法时，我们可能不知道它被其他方法使用，因此重写的方法可能会被超类意外调用。即使我们检查方法何时被调用，这种行为也可能在类的新版本中发生变化（例如，如果我们从外部库扩展类），从而破坏我们子类的行为。非常少量的类被正确设计和记录为继承，但几乎所有非抽象类都是为使用而设计的（这包括委托）。

+   在 Java 中，可以将一个类委托给多个类，但只能继承一个。

+   通过接口，我们指定要委托的方法和属性。这与*接口隔离*原则（来自 SOLID 原则）兼容--我们不应该向客户端公开不必要的方法。

+   有些类是 final 的，所以我们只能委托给它们。事实上，所有不设计用于继承的类都应该是 final 的。Kotlin 的设计者意识到了这一点，并且默认情况下将 Kotlin 中的所有类都设为 final。

+   将类设为 final 并提供适当的接口是公共库的良好实践。我们可以更改类的实现而不必担心会影响库的用户（只要从接口的角度来看行为是相同的）。它们不可继承，但仍然是很好的委托候选者。

有关如何设计支持继承的类以及何时应使用委托的更多信息可以在书籍*Effective Java*中找到，在*Item 16: Favor composition over inheritance*中找到。

当然，使用委托而不是继承也有缺点。以下是主要问题：

+   我们需要创建指定应该委托哪些方法的接口

+   我们无法访问受保护的方法和属性

在 Java 中，使用继承还有一个更有力的论据：它要容易得多。即使比较我们`WitcherPlayer`示例中的代码，我们也可以看到委托需要大量额外的代码：

```kt
     class WitcherPlayer(enemy: String) : Player { 
         val player = RpgGamePlayer(enemy)    
         override fun playGame() { 
             player.playGame() 
         } 
     } 

     class WitcherPlayer() : RpgGamePlayer() 
```

当我们处理具有多个方法的接口时，这是特别棘手的。幸运的是，现代语言重视委托模式的使用，并且许多语言都具有本地类委托支持。Swift 和 Groovy 对委托模式有很强的支持，Ruby、Python、JavaScript 和 Smalltalk 也通过其他机制支持。Kotlin 也强烈支持类委托，并且使用这种模式非常简单，几乎不需要样板代码。例如，示例中的`WitcherPlayer`类可以在 Kotlin 中以这种方式实现：

```kt
    class WitcherPlayer(enemy: String) : Player by RpgGamePlayer(enemy) {} 
```

使用`by`关键字，我们通知编译器将`WitcherPlayer`中定义的`Player`接口的所有方法委托给`RpgGamePlayer`。在`WitcherPlayer`构造期间创建了一个`RpgGamePlayer`的实例。简单来说：`WitcherPlayer`将在`Player`接口中定义的方法委托给一个新的`RpgGamePlayer`对象。

这里真正发生的是，在编译期间，Kotlin 编译器从`Player`在`WitcherPlayer`中生成了未实现的方法，并用对`RpgGamePlayer`实例的调用填充它们（就像我们在第一个示例中实现的那样）。最大的改进是我们不需要自己实现这些方法。还要注意的是，如果委托方法的签名发生变化，那么我们不需要更改所有委托给它的对象，因此类更容易维护。

还有另一种创建和保存委托实例的方法。它可以由构造函数提供，就像这个例子中一样：

```kt
    class WitcherPlayer(player: Player) : Player by player 
```

我们还可以委托给构造函数中定义的属性：

```kt
    class WitcherPlayer(val player: Player) : Player by player 
```

最后，我们可以委托给在类声明期间可访问的任何属性：

```kt
    val d = RpgGamePlayer(10) 
    class WitcherPlayer(a: Player) : Player by d 
```

此外，一个对象可以有多个不同的委托：

```kt
    interface Player { 
        fun playGame() 
    } 

    interface GameMaker { // 1 
        fun developGame() 
    } 

    class WitcherPlayer(val enemy: String) : Player { 
        override fun playGame() { 
            print("Killin $enemy! ") 
        } 
    } 

    class WitcherCreator(val gameName: String) : GameMaker{ 
        override fun developGame() { 
            println("Makin $gameName! ") 
        } 
    } 

    class WitcherPassionate : 
        Player by WitcherPlayer("monsters"), 
        GameMaker by WitcherCreator("Witcher 3") { 

        fun fulfillYourDestiny() { 
            playGame() 
            developGame() 
        } 
    } 

    // Usage 
    WitcherPassionate().fulfillYourDestiny() // Killin monsters! Makin Witcher 3! 
```

1.  `WitcherPlayer`类将`Player`接口委托给一个新的`RpgGamePlayer`对象，`GameMaker`委托给一个新的`WitcherCreator`对象，并且还包括`fulfillYourDestiny`函数，该函数使用了来自两个委托的函数。请注意，`WitcherPlayer`和`WitcherCreator`都没有标记为 open，没有这个标记，它们就不能被扩展。但它们可以被委托。

有了这样的语言支持，委托模式比继承更有吸引力。虽然这种模式既有优点又有缺点，但知道何时应该使用它是很好的。应该使用委托的主要情况如下：

+   当你的子类违反了*里氏替换原则*；例如，当我们处理继承仅用于重用超类代码的情况，但它实际上并不像那样工作。

+   当子类只使用超类的部分方法时。在这种情况下，只是时间问题，直到有人调用了他们本不应该调用的超类方法。使用委托，我们只重用我们选择的方法（在接口中定义）。

+   当我们不能或者不应该继承时，因为：

+   这个类是 final 的

+   它不可访问，也不可从接口后面使用

+   它只是不适合继承

请注意，虽然 Kotlin 中的类默认是 final 的，但大多数类都将保持 final。如果这些类放在库中，那么我们很可能无法更改或打开这个类。委托将是唯一的选择，以创建具有不同行为的类。

里氏替换原则是面向对象编程中的一个概念，它规定所有子类应该像它们的超类一样工作。简单来说，如果某个类的单元测试通过，那么它的子类也应该通过。这个原则由 Robert C. Martin 推广，他将其列为最重要的面向对象编程规则之一，并在流行的书籍*Clean Code*中描述了它。

《Effective Java》一书指出：“只有在子类真正是超类的子类型的情况下才适合使用继承。”换句话说，只有当类`B`扩展类`A`时，两个类之间存在*is-a*关系。如果你想让类`B`扩展类`A`，问问自己“每个 B 都是一个 A 吗？”在接下来的部分，该书建议在其他所有情况下应该使用组合（最常见的实现是委托）。

值得注意的是，Cocoa（苹果的 UI 框架，用于构建在 iOS 上运行的软件程序）很常用委托而不是继承。这种模式变得越来越流行，在 Kotlin 中得到了很好的支持。

# 装饰器模式

另一个常见的情况是，当我们实现装饰器模式时，Kotlin 类委托非常有用。装饰器模式（也称为包装器模式）是一种设计模式，它使得可以在不使用继承的情况下向现有类添加行为。与扩展不同，我们可以在不修改对象的情况下添加新行为，装饰器模式使用委托，但是以一种非常特定的方式--委托是从类的外部提供的。经典结构如下 UML 图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00052.jpg)

装饰器模式的经典实现的 UML 图。来源：[`upload.wikimedia.org`](http://upload.wikimedia.org)

装饰器包含它装饰的对象，同时实现相同的接口。

来自 Java 世界的装饰器使用最广泛的例子是`InputStream`。有不同类型的类型扩展了`InputStream`，还有很多装饰器可以用来为它们添加功能。这个装饰器可以用来添加缓冲，获取压缩文件的内容，或者将文件内容转换为 Java 对象。让我们看一个使用多个装饰器来读取一个压缩的 Java 对象的例子：

```kt
    // Java 
    FileInputStream fis = new FileInputStream("/someFile.gz"); // 1 
    BufferedInputStream bis = new BufferedInputStream(fis); // 2 
    GzipInputStream gis = new GzipInputStream(bis); // 3 
    ObjectInputStream ois = new ObjectInputStream(gis); // 4 
    SomeObject someObject = (SomeObject) ois.readObject(); // 5 
```

1.  创建一个用于读取文件的简单流。

1.  创建一个包含缓冲的新流。

1.  创建一个包含读取 GZIP 文件格式中压缩数据功能的新流。

1.  创建一个新的流，添加反序列化原始数据和之前使用`ObjectOutputStream`写入的对象的功能。

1.  流在`ObjectInputStream`的`readObject`方法中使用，但是这个例子中的所有对象都实现了`InputStream`（这使得可以以这种方式打包它），并且可以通过这个接口指定的方法来读取。

请注意，这种模式也类似于继承，但我们可以决定我们想要使用哪些装饰器以及以什么顺序。这样更加灵活，并在使用过程中提供更多可能性。一些人认为，如果设计者能够制作一个具有所有设计功能的大类，然后使用方法来打开或关闭其中的一些功能，那么`InputStream`的使用会更好。这种方法将违反*单一责任原则*，并导致更加复杂和不太可扩展的代码。

尽管装饰器模式被认为是实际应用中最好的模式之一，但在 Java 项目中很少被使用。这是因为实现并不简单。接口通常包含多个方法，在每个装饰器中创建对它们的委托会生成大量样板代码。在 Kotlin 中情况不同--我们已经看到在 Kotlin 中类委托实际上是微不足道的。让我们看一些在装饰器模式中实际类委托使用的经典例子。假设我们想要将第一个位置作为*零*元素添加到几个不同的`ListAdapters`中。这个额外的位置有一些特殊的属性。我们无法使用继承来实现这一点，因为这些不同列表的`ListAdapters`是不同类型的（这是标准情况）。在这种情况下，我们可以改变每个类的行为（DRY 规则），或者我们可以创建一个装饰器。这是这个装饰器的简短代码：

```kt
class ZeroElementListDecorator(val arrayAdapter: ListAdapter) : 
    ListAdapter by arrayAdapter { 
  override fun getCount(): Int = arrayAdapter.count + 1 
  override fun getItem(position: Int): Any? = when { 
      position == 0 -> null 
      else -> arrayAdapter.getItem(position - 1) 
  } 

  override fun getView(position: Int, convertView: View?,parent: 

ViewGroup): View = when { 
    position == 0 -> parent.context.inflator

        .inflate(R.layout.null_element_layout, parent, false) 
    else -> arrayAdapter.getView(position - 1, convertView, parent) 
  } 
} 

override fun getItemId(position: Int): Long = when { 
  position == 0 -> 0 
  else -> arrayAdapter.getItemId(position - 1) 
} 
```

我们在这里使用了`Context`的扩展属性`inflator`，这在 Kotlin Android 项目中经常包含，并且应该从第七章 *扩展函数和属性*中了解：

```kt
    val Context.inflater: LayoutInflater 
        get() = LayoutInflater.from(this) 
```

以这种方式定义的`ZeroElementListDecorator`类总是添加一个具有静态视图的第一个元素。在这里我们可以看到它的简单使用示例：

```kt
    val arrayList = findViewById(R.id.list) as ListView 
    val list = listOf("A", "B", "C") 
    val arrayAdapter = ArrayAdapter(this, 

          android.R.layout.simple_list_item_1, list) 
    arrayList.adapter = ZeroElementListDecorator(arrayAdapter) 
```

在`ZeroElementListDecorator`中，我们可能会觉得需要重写四个方法很复杂，但实际上还有八个方法，我们不需要重写它们，这要归功于 Kotlin 的类委托。我们可以看到 Kotlin 类委托使得装饰器模式的实现变得更加容易。

装饰器模式实际上非常简单实现，而且非常直观。它可以在许多不同的情况下用来扩展类的额外功能。它非常安全，通常被称为一种良好的实践。这些例子只是类委托提供的可能性之一。我相信读者会发现更多使用这些模式的用例，并使用类委托使项目更加清晰、安全和简洁。

# 属性委托

Kotlin 不仅允许类委托，还允许属性委托。在本节中，我们将找出委托属性是什么，审查 Kotlin 标准库中的属性委托，并学习如何创建和使用自定义属性委托。

# 什么是委托属性？

让我们从解释什么是属性委托开始。这里是属性委托的使用示例：

```kt
    class User(val name: String, val surname: String) 

    var user: User by UserDelegate() // 1 

    println(user.name) 
    user = User("Marcin","Moskala")
```

1.  我们将`user`属性委托给`UserDelegate`的一个实例（由构造函数创建）。

属性委托类似于类委托。我们使用相同的关键字（`by`）将属性委托给一个对象。对属性（`set`/`get`）的每次调用都将被委托给另一个对象（`UserDelegate`）。这样我们可以为多个属性重用相同的行为，例如，仅当满足某些条件时设置属性值，或者在访问/更新属性时添加日志条目。

我们知道属性实际上不需要后备字段。它可以只由 getter（只读）或 getter/setter（读/写）定义。在幕后，属性委托只是被转换为相应的方法调用（`setValue`/`getValue`）。上面的例子将被编译为这样的代码：

```kt
    var p$delegate = UserDelegate() 
    var user: User 
    get() = p$delegate.getValue(this, ::user) 
    set(value) { 
        p$delegate.setValue(this, ::user, value) 
    } 
```

该示例显示，通过使用`by`关键字，我们将 setter 和 getter 调用委托给委托。这就是为什么任何具有正确参数的`getValue`和`setValue`函数的对象（稍后将描述）都可以用作委托（对于只读属性，只需要`getValue`，因为只需要 getter）。重要的是，作为属性委托的所有类需要具有这两种方法。不需要接口。以下是`UserDelegate`的示例实现：

```kt
class UserDelegate { 
    operator fun getValue(thisRef: Any?, property: KProperty<*>): 

          User = readUserFromFile() 

    operator fun setValue(thisRef: Any?, property: KProperty<*>, 

          user:User) { 
        saveUserToFile(user) 
    } 
    //... 
} 
```

`setValue`和`getValue`方法用于设置和获取属性的值（属性设置器调用被委托给`setValue`方法，属性获取器将值委托给`getValue`方法）。这两个函数都需要标记为`operator`关键字。它们有一些特殊的参数集，用于确定委托可以服务的位置和属性。如果属性是只读的，那么对象只需要具有`getValue`方法就能够作为其委托：

```kt
class UserDelegate { 

    operator fun getValue(thisRef: Any?, property: KProperty<*>):

        User = readUserFromFile() 
} 
```

`getValue`方法返回的类型和用户在`setValue`方法中定义的属性的类型决定了委托属性的类型。

`getValue`和`setValue`函数的第一个参数（`thisRef`）的类型包含了委托使用的上下文的引用。它可以用于限制委托可以使用的类型。例如，我们可以以以下方式定义只能在`Activity`类内部使用的委托：

```kt
class UserDelegate { 

    operator fun getValue(thisRef: Activity, property: KProperty<*>): 

          User = thisRef.intent

          .getParcelableExtra("com.example.UserKey") 
} 
```

正如我们所见，所有上下文中都会提供对`this`的引用。只有在扩展函数或扩展属性中才会放置 null。对`this`的引用用于从上下文中获取一些数据。如果我们将其类型定义为`Activity`，那么我们只能在`Activity`内部（`this`的类型为`Activity`的任何上下文）中使用此委托。

此外，如果我们想要强制委托只能在顶层使用，我们可以将第一个参数（`thisRef`）的类型指定为`Nothing?`，因为这种类型的唯一可能值是`null`。

这些方法中的另一个参数是`property`。它包含对委托属性的引用，其中包含其元数据（属性名称、类型等）。

属性委托可用于任何上下文中定义的属性（顶级属性、成员属性、局部变量等）：

```kt
    var a by SomeDelegate() // 1 

    fun someTopLevelFun() { 
        var b by SomeDelegate() // 2 
    } 

    class SomeClass() { 
        var c by SomeDelegate() // 3 

        fun someMethod() { 
            val d by SomeDelegate() // 4 
        } 
    } 
```

1.  使用委托的顶级属性

1.  使用委托的局部变量（在顶级函数内部）

1.  使用委托的成员属性

1.  使用委托的局部变量（在方法内部）

在接下来的几节中，我们将描述 Kotlin 标准库中的委托。它们不仅因为它们经常有用而重要，而且因为它们是如何使用属性委托的好例子。

# 预定义的委托

Kotlin 标准库包含一些非常方便的属性委托。让我们讨论它们如何在实际项目中使用。

# `lazy`函数

有时我们需要初始化一个对象，但我们希望确保对象只在第一次使用时初始化一次。在 Java 中，我们可以通过以下方式解决这个问题：

```kt
    private var _someProperty: SomeType? = null 
    private val somePropertyLock = Any() 
    val someProperty: SomeType 
    get() { 
        synchronized(somePropertyLock) { 
            if (_someProperty == null) { 
                _someProperty = SomeType() 
            } 
            return _someProperty!! 
        } 
    } 
```

这种构造在 Java 开发中很常见。Kotlin 允许我们通过提供`lazy`委托来以更简单的方式解决这个问题。它是最常用的委托。它只适用于只读属性（`val`），用法如下：

```kt
    val someProperty by lazy { SomeType() } 
```

标准库中提供委托的`lazy`函数：

```kt
    public fun <T> lazy(initializer: () -> T): 

          Lazy<T> =  SynchronizedLazyImpl(initializer) 
```

在这个例子中，`SynchronizedLazyImpl` 的对象被正式地用作属性委托。尽管通常它被称为**惰性委托**，来自于相应的函数名。其他委托也是从提供它们的函数的名称命名的。

惰性委托还具有线程安全机制。默认情况下，委托是完全线程安全的，但我们可以改变这种行为，使这个函数在我们知道永远不会有多个线程同时使用它的情况下更有效。要完全关闭线程安全机制，我们需要将`enum`类型值`LazyThreadSafetyMode.NONE`作为`lazy`函数的第一个参数。

`val someProperty by lazy(LazyThreadSafetyMode.NONE) { SomeType() }`

由于惰性委托，属性的初始化被延迟直到需要值。使用惰性委托提供了几个好处：

+   更快的类初始化导致更快的应用程序启动时间，因为值的初始化被延迟到第一次使用它们时

+   某些值可能永远不会在某些流程中使用，因此它们永远不会被初始化——我们在节省资源（内存、处理器时间、电池）。

另一个好处是有些对象需要在它们的类实例创建后才能创建。例如，在`Activity`中，我们不能在使用`setContentView`方法设置布局之前访问资源，这个方法通常在`onCreate`方法中调用。我将在这个例子中展示它。让我们看一下使用经典 Java 方式填充视图引用元素的 Java 类：

```kt
//Java 
public class MainActivity extends Activity { 

    TextView questionLabelView 
    EditText answerLabelView 
    Button confirmButtonView 

    @Override 
    public void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_main); 

        questionLabelView = findViewById<TextView>

              (R.id.main_question_label);    
        answerLabelView   = findViewById<EditText>

              (R.id.main_answer_label);    
        confirmButtonView = findViewById<Button>

              (R.id.main_button_confirm);      
    } 
} 
```

如果我们将其翻译成 Kotlin，一对一，它将如下所示：

```kt
class MainActivity : Activity() { 

    var questionLabelView: TextView? = null 
    var answerLabelView: TextView? = null 
    var confirmButtonView: Button? = null 

    override fun onCreate(savedInstanceState: Bundle) { 
        super.onCreate(savedInstanceState) 
        setContentView(R.layout.main_activity) 

        questionLabelView = findViewById<TextView>

              (R.id.main_question_label)   

        answerLabelView = findViewById<TextView>

              (R.id.main_answer_label)

        confirmButtonView = findViewById<Button>

              (R.id.main_button_confirm)

    } 

}
```

使用惰性委托，我们可以以更简单的方式实现这种行为：

```kt
class MainActivity : Activity() { 

   val questionLabelView: TextView by lazy 

{ findViewById(R.id.main_question_label) as TextView } 
   val answerLabelView: TextView by lazy 

{ findViewById(R.id.main_answer_label) as TextView } 
   val confirmButtonView: Button by lazy 

{ findViewById(R.id.main_button_confirm) as Button } 

   override fun onCreate(savedInstanceState: Bundle) { 
     super.onCreate(savedInstanceState) 
     setContentView(R.layout.main_activity) 
   } 
} 
```

这种方法的好处如下：

+   属性在一个地方声明和初始化，所以代码更简洁。

+   属性是非空的，而不是可空的。这可以避免大量无用的空值检查。

+   属性是只读的，因此我们可以获得所有的好处，比如线程同步或智能转换。

+   传递给惰性委托的 lambda（包含`findViewById`）只有在第一次访问属性时才会执行。

+   值将在类创建后被获取。这将加快启动速度。如果我们不使用其中一些视图，它们的值根本不会被获取（当视图复杂时，`findViewById`并不是一种高效的操作）。

+   未使用的属性将被编译器标记。在 Java 实现中不会，因为编译器会注意到设置的值作为使用。

我们可以通过提取共同的行为并将其转换为扩展函数来改进前面的实现：

```kt
fun <T: View> Activity.bindView(viewId: Int) = lazy { findViewById(viewId) as T } 
```

然后，我们可以用更简洁的代码定义视图绑定：

```kt
class MainActivity : Activity() { 

  var questionLabelView: TextView by bindView(R.id.main_question_label)  // 1 
  var answerLabelView: TextView by bindView(R.id.main_answer_label)   // 1 
  var confirmButtonView: Button by bindView(R.id.main_button_confirm) // 1 

  override fun onCreate(savedInstanceState: Bundle) { 
    super.onCreate(savedInstanceState) 
    setContentView(R.layout.main_activity) 
  } 
} 
```

1.  我们不需要为`bindView`函数提供的类型设置类型，因为它是从属性类型中推断出来的。

现在我们有一个单一的委托，在我们第一次访问特定视图时会在后台调用`findViewById`。这是一个非常简洁的解决方案。

还有另一种处理这个问题的方法。目前流行的是*Kotlin Android Extension*插件，它会在`Activities`和`Fragments`中自动生成视图的自动绑定。我们将在第九章中讨论实际应用，*制作你的 Marvel 画廊应用*。

即使有这样的支持，仍然有保持绑定的好处。一个是明确知道我们正在使用的视图元素，另一个是元素 ID 的名称和我们保存该元素的变量的名称之间的分离。此外，编译时间更快。

相同的机制可以应用于解决其他与 Android 相关的问题。例如，当我们向`Activity`传递参数时。标准的 Java 实现如下：

```kt
//Java 
class SettingsActivity extends Activity { 

  final Doctor DOCTOR_KEY = "doctorKey" 
  final String TITLE_KEY = "titleKey" 

  Doctor doctor 
  Address address 
  String title 

  public static void start ( Context context, Doctor doctor, 

  String title ) { 
    Intent intent = new Intent(context, SettingsActivity.class ) 
    intent.putExtra(DOCTOR_KEY, doctor) 
    intent.putExtra(TITLE_KEY, title) 
    context.startActivity(intent) 
  } 

  @Override 
  public void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    doctor = getExtras().getParcelable(DOCTOR_KEY)   
    title = getExtras().getString(TITLE_KEY)   

    ToastHelper.toast(this, doctor.id) 
    ToastHelper.toast(this, title) 
  } 
} 
```

我们可以在 Kotlin 中编写相同的实现，但也可以在变量声明时检索参数值（`getString` / `getParcerable` ）。为此，我们需要以下扩展函数：

```kt
fun <T : Parcelable> Activity.extra(key: String) = lazy 

    { intent.extras.getParcelable<T>(key) } 

fun Activity.extraString(key: String) = lazy 

    { intent.extras.getString(key) } 
```

然后我们可以通过使用 `extra` 和 `extraString` 委托来获取额外的参数：

```kt
class SettingsActivity : Activity() { 

    private val doctor by extra<Doctor>(DOCTOR_KEY) // 1 
    private val title by extraString(TITLE_KEY) // 1 

    override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        setContentView(R.layout.settings_activity) 
        toast(doctor.id) // 2 
        toast(title) // 2 
    } 

    companion object { // 3 
        const val DOCTOR_KEY = "doctorKey" 
        const val TITLE_KEY = "titleKey" 

    fun start(context: Context, doctor: Doctor, title: String) { // 3 
        ontext.startActivity(getIntent<SettingsActivity>().apply { // 4 
            putExtra(DOCTOR_KEY, doctor) // 5 
            putExtra(TITLE_KEY, title) // 5 
        }) 
    } 
  } 

} 
```

1.  我们正在定义应该从 `Activity` 参数中检索值的属性，使用相应的键。

1.  在 `onCreate` 方法中，我们从参数中访问属性。当我们请求属性（使用 getter）时，延迟委托将从额外中获取其值，并将其存储以供以后使用。

1.  要创建一个启动活动的静态方法，我们需要使用伴生对象。

1.  `SettingsActivity::class.java` 是 Java 类引用 `SettingsActivity.class` 的类似物。

1.  我们正在使用第七章中定义的方法，*扩展函数和属性*。

我们还可以编写函数来检索其他可以由 **Bundle** 持有的类型（例如 `Long` 、`Serializable` ）。这是一个非常好的替代方案，可以避免使用诸如 `ActivityStarter` 等参数注入库，从而保持非常快的编译时间。我们可以使用类似的函数来绑定字符串、颜色、服务、存储库和模型和逻辑的其他部分：

```kt
fun <T> Activity.bindString(@IdRes id: Int): Lazy<T> = 

    lazy { getString(id) } 
fun <T> Activity.bindColour(@IdRes id: Int): Lazy<T> = 

    lazy { getColour(id) } 
```

在 `Activity` 中，所有繁重的或依赖于参数的内容都应该使用延迟委托（或异步提供）。同时，所有依赖于需要延迟初始化的元素的元素也应该定义为延迟。例如，依赖于 `doctor` 属性的 `presenter` 的定义：

```kt
    val presenter by lazy { MainPresenter(this, doctor) } 
```

否则，尝试构造 `MainPresenter` 对象将在类创建时进行，此时我们还不能从意图中读取值，也无法填充 `doctor` 属性，应用程序将崩溃。

我认为这些示例足以让我们相信，延迟委托在 Android 项目中非常有用。它也是一个很好的属性委托入门，因为它简单而优雅。

# notNull 函数

`notNull` 委托是最简单的标准库委托，这就是为什么它将首先被介绍。使用方法如下：

```kt
    var someProperty: SomeType by notNull()
```

提供大多数标准库委托（包括 `notNull` 函数）的函数是在 `object` 委托中定义的。要使用它们，我们需要引用这个对象（`Delegates.notNull()` ），或者导入它（`import kotlin.properties.Delegates.notNull` ）。在示例中，我们将假设这个 `object` 已经被导入，因此我们将省略对它的引用。

`notNull` 委托允许我们将变量定义为非空，即在稍后初始化而不是在对象构造时初始化。我们可以定义变量为非空而不提供默认值。`notNull` 函数是 `lateinit` 的一种替代方式：

```kt
    lateinit var someProperty: SomeType 
```

`notNull` 委托提供了几乎与 `lateinit` 相同的效果（只是错误消息不同）。在尝试在设置值之前使用此属性时，它将抛出 `IllegalStateException` 并终止 Android 应用程序。因此，只有在我们知道值将在第一次尝试使用之前设置时，才应该使用它。

`lateinit` 和 `notNull` 委托之间的区别非常简单。`lateinit` 比 `notNull` 委托更快，因此应尽可能使用 `lateinit` 委托。但它有限制，`lateinit` 不能用于原始类型或顶级属性，因此在这种情况下，应使用 `notNull` 代替。

让我们来看一下 `notNull` 委托的实现。以下是 `notNull` 函数的实现：

```kt
    public fun <T: Any> notNull(): ReadWriteProperty<Any?, T> =  

        NotNullVar() 
```

如我们所见，`notNull` 实际上是一个返回对象的函数，该对象是我们实际委托的实例，隐藏在 `ReadWriteProperty` 接口后面。让我们来看一个实际的委托定义：

```kt
private class NotNullVar<T: Any>() : ReadWriteProperty<Any?, T> { // 1 
  private var value: T? = null 

  public override fun getValue(thisRef: Any?, 

  property: KProperty<*>): T { 
     return value ?: throw IllegalStateException("Property 

            ${property.name} should be initialized before get.") // 2 
  } 

  public override fun setValue(thisRef: Any?, 

  property: KProperty<*>, value: T) { 
     this.value = value 
  } 
} 
```

1.  类是私有的。这是可能的，因为它是由函数 `notNull` 提供的，该函数将其作为 `ReadWriteProperty<Any?, T>` 返回，而该接口是公共的。

1.  这里展示了如何提供返回值。如果在使用过程中为 null，则表示未设置值，方法将抛出错误。否则，它会返回该值。

这个委托应该很容易理解。`setValue`函数将值设置为可空字段，`getValue`如果不为 null 则返回该字段，如果为 null 则抛出异常。以下是此错误的示例：

```kt
    var name: String by Delegates.notNull() 
    println(name) 

    // Error: Property name should be initialized before get. 
```

这是一个关于委托属性使用的非常简单的例子，也是对属性委托工作原理的良好介绍。委托属性是非常强大的构造，具有多种应用。

# 可观察委托

可观察是可变属性最有用的标准库委托。每次设置一个值（调用`setValue`方法）时，都会调用声明中的 lambda 函数。可观察委托的一个简单示例如下：

```kt
    var name: String by Delegates.observable("Empty"){ 
        property, oldValue, newValue -> // 1 
        println("$oldValue -> $newValue") // 2 
    } 

    // Usage 
    name = "Martin" // 3, 

    Prints: Empty -> Martin 
    name = "Igor" // 3, 

    Prints: Martin -> Igor 
    name = "Igor" // 3, 4 

    Prints: Igor -> Igor
```

1.  lambda 函数的参数如下：

+   `property`：委托属性的引用。这里是对 name 的引用。这与`setValue`和`getValue`中描述的属性相同。它是`KProperty`类型。在这种情况下（以及大多数情况下），当未使用时可以使用下划线（“`_`”符号）代替。

+   `oldValue`：更改前的`property`的先前值。

+   `newValue`：更改后的`property`的新值。

1.  每次将新值设置到属性时都会调用 lambda 函数。

1.  当我们设置新值时，该值会更新，但同时也会调用委托中声明的 lambda 方法。

1.  注意，每次使用 setter 时都会调用 lambda，并且不管新值是否等于先前的值都没有关系。

特别重要的是要记住，每次设置新值时都会调用 lambda，而不是在对象的内部状态更改时。例如：

```kt
    var list: MutableList<Int> by observable(mutableListOf()) 

    { _, old, new ->  
        println("List changed from $old to $new") 
    } 

    // Usage 
    list.add(1)  // 1 
    list =  mutableListOf(2, 3) 

    // 2, prints: List changed from [1] to [2, 3] 
```

1.  不打印任何内容，因为我们没有更改属性（未使用 setter）。我们只更改了列表内部定义的属性，而不是对象本身。

1.  在这里我们改变了列表的值，因此会调用可观察委托中的 lambda 函数并打印文本。

可观察委托对于不可变类型非常有用，与可变类型相反。幸运的是，Kotlin 中的所有基本类型默认都是不可变的（`List`，`Map`，`Set`，`Int`，`String`）。让我们看一个实际的 Android 示例：

```kt
    class SomeActivity : Activity() { 

        var list: List<String> by Delegates.observable(emptyList()) { 
            prop, old, new -> if(old != new) updateListView(new) 
        }   
        //  ... 
    } 
```

每次更改列表时，视图都会更新。请注意，虽然`List`是不可变的，但是当我们想要应用任何更改时，我们需要使用 setter，以便确保在此操作之后列表将被更新。这比记住每次列表更改时都调用`updateListView`方法要容易得多。这种模式可以广泛用于项目中声明编辑视图的属性。它改变了更新视图机制的工作方式。

使用可观察委托可以解决的另一个问题是，在`ListAdapters`中，列表中的元素每次更改时都必须调用`notifyDataSetChanged`。在 Java 中，经典解决方案是封装此列表，并在修改它的每个函数中调用`notifyDataSetChanged`。在 Kotlin 中，我们可以使用可观察属性委托来简化这个过程：

```kt
var list: List<LocalDate> by observable(list) { _, old, new ->  // 1 
  if(new != old) notifyDataSetChanged() 
} 
```

1.  请注意，这里的列表是不可变的，因此没有办法在不使用`notifyDataSetChanged`的情况下更改其元素。

可观察委托用于定义在属性值更改时应发生的行为。当我们有应该在每次更改属性时执行的操作，或者当我们想要将属性值与视图或其他值绑定时，它最常用。但在函数内部，我们无法决定是否设置新值。为此，可以使用`vetoable`委托。

# 可否决的委托

`vetoable`函数是一个标准库属性委托，其工作方式类似于可观察委托，但有两个主要区别：

+   在设置新值之前，会先调用参数中的 lambda

+   它允许声明中的 lambda 函数决定是否接受或拒绝新值

例如，如果我们假设列表必须始终包含比旧列表更多的项目，则我们将定义以下`vetoable`委托：

```kt
var list: List<String> by Delegates.vetoable(emptyList()) 

{ _, old, new ->  
   new.size > old.size 
} 
```

如果新列表不包含比旧列表更多的项目，则值将不会更改。因此，我们可以将`vetoable`视为`observable`，它也决定是否应更改值。假设我们想要将列表绑定到视图，但它至少需要有三个元素。我们不允许进行任何可能导致其具有更少元素的更改。实现如下：

```kt
var list: List<String> by Delegates.vetoable(emptyList()) 

{ prop, old, new ->  
    if(new.size < 3) return@vetoable false // 1 
    updateListView(new) 
    true // 2 
} 
```

1.  如果新列表的大小小于 3，则我们不接受它，并从 lambda 返回`false`。通过标签返回的`false`值（用于从 lambda 表达式返回）是新值不应被接受的信息。

1.  此 lambda 函数需要返回一个值。此值可以从带有标签的`return`中获取，也可以从 lambda 主体的最后一行获取。这里的值`true`表示应接受新值。

这是其用法的一个简单示例：

```kt
    listVetoable = listOf("A", "B", "C") // Update A, B, C 
    println(listVetoable) // Prints: [A, B, C] 
    listVetoable = listOf("A") // Nothing happens 
    println(listVetoable) // Prints: [A, B, C] 
    listVetoable = listOf("A", "B", "C", "D", "E")  

    // Prints: [A, B, C, D, E] 
```

由于某些其他原因，我们还可以使其不可改变，例如，我们可能仍在加载数据。此外，可否决的属性委托可以用于验证器。例如：

```kt
    var name: String by Delegates.vetoable("") 

    { prop, old, new ->  
    if (isValid(new)) { 
        showNewData(new) 
        true 
    } else { 
        showNameError() 
        false 
    }
```

此属性只能更改为符合谓词`isValid(new)`的值。

# 将属性委托给 Map 类型

标准库包含了对具有`String`键类型的`Map`和`MutableMap`的扩展，提供了`getValue`和`setValue`函数。由于它们，`map`也可以用作属性委托：

```kt
    class User(map: Map<String, Any>) { // 1 
        val name: String by map 
        val kotlinProgrammer: Boolean by map 
    } 

    // Usage 
    val map: Map<String, Any> = mapOf( // 2 
        "name" to "Marcin", 
        "kotlinProgrammer" to true 
    ) 
    val user = User(map) // 3 
    println(user.name)  // Prints: Marcin 
    println(user.kotlinProgrammer)  // Prints: true 
```

1.  映射键类型需要是`String`，而值类型没有限制。通常是`Any`或`Any?`

1.  创建包含所有值的`Map`

1.  为对象提供一个`map`。

当我们在`Map`中保存数据时，这可能很有用，也适用于以下情况：

+   当我们想要简化对这些值的访问时

+   当我们定义一个结构，告诉我们应该在此映射中期望哪种键

+   当我们要求委托给`Map`的属性时，其值将从此映射值中获取，键等于属性名称

它是如何实现的？这是标准库中的简化代码：

```kt
operator fun <V, V1: V> Map<String, V>.getValue( // 1 
      thisRef: Any?, // 2 
      property: KProperty<*>): V1 { // 3 
          val key = property.name // 4 
          val value = get(key) 
          if (value == null && !containsKey(key)) { 
              throw NoSuchElementException("Key ${property.name} 

              is missing in the map.") 
          } else { 
              return value as V1 // 3 
          } 
      } 
```

1.  `V` 是列表上的一种值

1.  `thisRef`的类型是`Any?`，因此`Map`可以在任何上下文中用作属性委托。

1.  `V1`是返回类型。这通常是从属性推断出来的，但它必须是类型`V`的子类型

1.  属性的名称用作`map`上的`key`。

请记住，这只是一个扩展函数。对象要成为委托所需的一切就是包含`getValue`方法（对于读写属性还需要`setValue`）。我们甚至可以使用`object`声明从匿名类的对象创建委托：

```kt
val someProperty by object { // 1 
    operator fun  getValue(thisRef: Any?, 

    property: KProperty<*>) = "Something" 
} 
println(someProperty) // prints: Something 
```

1.  对象没有实现任何接口。它只包含具有正确签名的`getValue`方法。这足以使其作为只读属性委托工作。

请注意，在请求属性的值时，`map`中需要有一个具有这样名称的条目，否则将抛出错误（使属性可为空不会改变它）。

将字段委托给 map 可能很有用，例如，当我们从 API 中获得一个具有动态字段的对象时。我们希望将提供的数据视为对象，以便更轻松地访问其字段，但我们还需要将其保留为映射，以便能够列出 API 提供的所有字段（甚至是我们没有预期的字段）。

在前面的示例中，我们使用了不可变的`Map`；因此，对象属性是只读的（`val`）。如果我们想要创建一个可以更改的对象，那么我们应该使用`MutableMap`，然后可以将属性定义为可变的（`var`）。这是一个例子：

```kt
class User(val map: MutableMap<String, Any>) { 
    var name: String by map 
    var kotlinProgrammer: Boolean by map 

    override fun toString(): String = "Name: $name, 

    Kotlin programmer: $kotlinProgrammer" 
} 

// Usage 
val map = mutableMapOf( // 1 
    "name" to "Marcin", 
    "kotlinProgrammer" to true 
) 
val user = User(map) 
println(user) // prints: Name: Marcin, Kotlin programmer: true 
user.map.put("name", "Igor") // 1  
println(user) // prints: Name: Igor, Kotlin programmer: true 
user.name = "Michal" // 2 
println(user) // prints: Name: Michal, Kotlin programmer: true 
```

1.  属性值可以通过更改`map`的值来更改

1.  属性值也可以像其他属性一样更改。真正发生的是值的更改被委托给`setValue`，它正在更改`map`。

虽然这里的属性是可变的，但`setValue`函数也必须提供。它被实现为`MutableMap`的扩展函数。以下是简化的代码：

```kt
    operator fun <V> MutableMap<String, V>.setValue( 
        thisRef: Any?,  
        property: KProperty<*>,  
        value: V 
    ) { 
        put(property.name, value) 
    } 
```

请注意，即使是如此简单的函数也可以允许使用常见对象的创新方式。这显示了属性委托所提供的可能性。

Kotlin 允许我们定义自定义委托。现在，我们可以找到许多库，提供了可以用于 Android 中不同目的的新属性委托。在 Android 中可以使用属性委托的各种方式。在下一节中，我们将看到一些自定义属性委托的例子，并且我们将看看这个功能在哪些情况下真的很有帮助。

# 自定义委托

以前的所有委托都来自标准库，但我们可以轻松实现自己的属性委托。我们已经看到，为了允许一个类成为委托，我们需要提供`getValue`和`setValue`函数。它们必须具有具体的签名，但无需扩展类或实现接口。要将对象用作委托，我们甚至不需要更改其内部实现，因为我们可以将`getValue`和`setValue`定义为扩展函数。但是，当我们创建自定义类以成为委托时，接口可能会有用：

+   它将定义函数结构，这样我们就可以在 Android Studio 中生成适当的方法。

+   如果我们正在创建库，那么我们可能希望将委托类设置为私有或内部，以防止不当使用。我们在`notNull`部分看到了这种情况，其中类`NotNullVar`是私有的，并且作为`ReadWriteProperty<Any?, T>`的接口。

提供完整功能以允许某个类成为委托的接口是`ReadOnlyProperty`（用于只读属性）和`ReadWriteProperty`（用于读写属性）。这些接口非常有用，让我们看看它们的定义：

```kt
    public interface ReadOnlyProperty<in R, out T> { 
        public operator fun getValue(thisRef: R, 

            property: KProperty<*>): T 
    } 

    public interface ReadWriteProperty<in R, T> { 
       public operator fun getValue(thisRef: R, 

           property: KProperty<*>): T 
       public operator fun setValue(thisRef: R, 

           property: KProperty<*>, value: T) 
    } 
```

参数的值已经解释过了，但让我们再看一遍：

+   `thisRef`：委托使用的对象的引用。其类型定义了委托可以使用的上下文。

+   `property`：包含有关委托属性的数据的引用。它包含有关此属性的所有信息，例如其名称或类型。

+   `value`：要设置的新值。

`thisRef`和`property`参数在以下委托中未使用：Lazy、Observable 和 Vetoable。`Map`、`MutableMap`和`notNull`使用属性来获取键的属性名称。但是这些参数可以在不同的情况下使用。

让我们看一些小而有用的自定义属性委托的例子。我们已经看到了用于只读属性的延迟属性委托；然而，有时我们需要一个可变的延迟属性。如果在初始化之前要求值，那么它应该从初始化程序中填充其值并返回它。在其他情况下，它应该像普通的可变属性一样工作：

```kt
fun <T> mutableLazy(initializer: () -> T): ReadWriteProperty<Any?, T> = MutableLazy<T>(initializer) 

private class MutableLazy<T>(val initializer: () -> T) : ReadWriteProperty<Any?, T> { 

   private var value: T? = null 
   private var initialized = false 

   override fun getValue(thisRef: Any?, property: KProperty<*>): T { 
       synchronized(this) { 
           if (!initialized) { 
               value = initializer() 
           } 
           return value as T 
       } 
   } 

   override fun setValue(thisRef: Any?, 

       property: KProperty<*>, value: T) { 
       synchronized(this) { 
           this.value = value 
           initialized = true 
       } 
   } 
} 
```

1.  委托被隐藏在接口后面，并由一个函数提供，因此允许我们更改`MutableLazy`的实现，而不必担心它会影响使用它的代码。

1.  我们正在实现`ReadWriteProperty`。这是可选的，但非常有用，因为它强制了读写属性的正确结构。它的第一个类型是`Any?`，意味着我们可以在任何上下文中使用这个属性委托，包括顶层。它的第二个类型是泛型。请注意，对这种类型没有限制，因此它也可能是可空的。

1.  属性的值存储在`value`属性中，其存在性存储在一个初始化的属性中。我们需要这样做是因为我们希望允许`T`是可空类型。然后值中的`null`可能意味着它尚未初始化，或者它只是等于`null`。

1.  我们不需要使用`operator`修饰符，因为它已经在接口中使用了。

1.  如果在设置任何值之前调用`getValue`，则该值将使用初始化程序填充。

1.  我们需要将值转换为`T`，因为它可能不为空，并且我们将值初始化为可空，初始值为 null。

这种属性委托在 Android 开发中的不同用例中可能会很有用；例如，当属性的默认值存储在文件中，我们需要读取它（这是一个繁重的操作）：

```kt
    var gameMode : GameMode by MutableLazy { 
        getDefaultGameMode()  
    } 

    var mapConfiguration : MapConfiguration by MutableLazy { 
        getSavedMapConfiguration() 
    } 

    var screenResolution : ScreenResolution by MutableLazy { 
        getOptimalScreenResolutionForDevice() 
    } 
```

这样，如果用户在使用之前设置了此属性的自定义值，我们就不必自己计算它。第二个自定义属性委托将允许我们定义属性的 getter：

```kt
    val a: Int get() = 1 
    val b: String get() = "KOKO" 
    val c: Int get() = 1 + 100 
```

在 Kotlin 1.1 之前，我们总是需要定义属性的类型。为了避免这种情况，我们可以定义以下扩展函数到函数类型（因此也是 lambda 表达式）：

```kt
    inline operator fun <R> (() -> R).getValue( 
        thisRef: Any?, 
        property: KProperty<*> 
    ): R = invoke() 
```

然后我们可以这样定义具有类似行为的属性：

```kt
    val a by { 1 } 
    val b by { "KOKO" } 
    val c by { 1 + 100 } 
```

这种方式不被推荐，因为它的效率降低，但它是委托属性提供给我们的可能性的一个很好的例子。这样一个小的扩展函数将函数类型转换为属性委托。这是在 Kotlin 编译后的简化代码（请注意，扩展函数被标记为内联，因此它的调用被替换为它的主体）：

```kt
    private val `a$delegate` = { 1 } 
    val a: Int get() = `a$delegate`() 
    private val `b$delegate` = {  "KOKO" } 
    val b: String get() = `b$delegate`() 
    private val `c$delegate` = { 1 + 100 } 
    val c: Int get() = `c$delegate`() 
```

在下一节中，我们将看到为真实项目创建的一些自定义委托。它们将与它们解决的问题一起呈现。

# 视图绑定

当我们在项目中使用**Model-View-Presenter**（**MVP**）时，我们需要通过 Presenter 在 View 中进行所有更改。因此，我们被迫在视图上创建多个函数，例如：

```kt
    override fun getName(): String { 
        return nameView.text.toString() 
    } 

    override fun setName(name: String) { 
        nameView.text = name 
    } 
```

我们还必须在以下`interface`中定义函数：

```kt
    interface MainView { 
        fun getName(): String 
        fun setName(name: String) 
    } 
```

通过使用属性绑定，我们可以简化前面的代码并减少对 setter/getter 方法的需求。我们可以将属性绑定到视图元素。这是我们想要实现的结果：

```kt
    override var name: String by bindToTex(R.id.textView) 
```

和`interface`：

```kt
    interface MainView { 
        var name: String 
    } 
```

前面的例子更简洁，更易于维护。请注意，我们通过参数提供元素 ID。一个简单的类将给我们带来预期的结果，如下所示：

```kt
fun Activity.bindToText( 
    @IdRes viewId: Int ) = object : 

    ReadWriteProperty<Any?, String> { 

  val textView by lazy { findViewById<TextView>(viewId) } 

  override fun getValue(thisRef: Any?, 

      property: KProperty<*>): String { 
      return textView.text.toString() 
  } 

  override fun setValue(thisRef: Any?, 

      property: KProperty<*>, value: String) { 
      textView.text = value 
  } 
} 
```

我们可以为不同的视图属性和不同的上下文（`Fragment`，`Service`）创建类似的绑定。另一个非常有用的工具是绑定到可见性，它将逻辑属性（类型为`Boolean`）绑定到`view`元素的可见性：

```kt
fun Activity.bindToVisibility( 
   @IdRes viewId: Int ) = object : 

   ReadWriteProperty<Any?, Boolean> { 

   val view by lazy { findViewById(viewId) } 

  override fun getValue(thisRef: Any?, 

      property: KProperty<*>): Boolean { 
      return view.visibility == View.VISIBLE 
  } 

  override fun setValue(thisRef: Any?, 

      property: KProperty<*>, value: Boolean) { 
      view.visibility = if(value) View.VISIBLE else View.GONE 
  } 
} 
```

这些实现提供了在 Java 中很难实现的可能性。类似的绑定可以用于其他`View`元素，以使 MVP 的使用更简洁和简单。刚刚呈现的片段只是简单的例子，但更好的实现可以在库`KotlinAndroidViewBindings`中找到（[`github.com/MarcinMoskala/KotlinAndroidViewBindings`](https://github.com/MarcinMoskala/KotlinAndroidViewBindings)）。

# 首选绑定

为了展示更复杂的例子，我们将尝试帮助使用`SharedPreferences`。对于这个问题，有更好的 Kotlin 方法，但这个尝试很好分析，并且是我们在扩展属性上使用属性委托的一个合理例子。因此，我们希望能够将保存在`SharedPreferences`中的值视为`SharedPreferences`对象的属性。以下是示例用法：

```kt
    preferences.canEatPie = true 
    if(preferences.canEatPie) { 
        // Code 
    } 
```

如果我们定义以下扩展属性定义，我们就可以实现它：

```kt
    var SharedPreferences.canEatPie: 

    Boolean by bindToPreferenceField(true) // 1

    var SharedPreferences.allPieInTheWorld: 

    Long by bindToPreferenceField(0,"AllPieKey") //2
```

1.  布尔类型的属性。当属性是非空时，必须在函数的第一个参数中提供默认值。

1.  属性可以提供自定义键。这在实际项目中非常有用，因为我们必须控制这个键（例如，不要在属性重命名时无意中更改它）。

让我们通过深入研究非空属性的工作原理来分析它是如何工作的。首先，让我们看看提供函数。请注意，属性的类型决定了从 `SharedPreferences` 中获取值的方式（因为有不同的函数，比如 `getString`、`getInt` 等）。为了获取它，我们需要将这个类类型作为 `inline` 函数的 `reified` 类型提供，或者通过参数提供。这就是委托提供函数的样子：

```kt
inline fun <reified T : Any> bindToPreferenceField( 
      default: T?, 
      key: String? = null 
): ReadWriteProperty<SharedPreferences, T> // 1 
    = bindToPreferenceField(T::class, default, key) 

fun <T : Any> bindToPreferenceField( // 2 
    clazz: KClass<T>, 
    default: T?, 
    key: String? = null 
): ReadWriteProperty<SharedPreferences, T> 
      = PreferenceFieldBinder(clazz, default, key) // 1 
```

1.  这两个函数都返回接口 `ReadWriteProperty<SharedPreferences, T>` 后面的对象。请注意，这里的上下文设置为 `SharedPreferences`，因此只能在那里或在 `SharedPreferences` 扩展中使用。定义这个函数是因为类型参数不能重新定义，我们需要将类型作为普通参数提供。

1.  请注意，`bindToPreferenceField` 函数不能是私有的或内部的，因为内联函数只能使用相同或更少限制的函数。

最后，让我们看看 `PreferenceFieldDelegate` 类，它是我们的委托：

```kt
internal open class PreferenceFieldDelegate<T : Any>( 
      private val clazz: KClass<T>, 
      private val default: T?, 
      private val key: String? 
) : ReadWriteProperty<SharedPreferences, T> { 

  override operator fun getValue(thisRef: SharedPreferences, 

  property: KProperty<*>): T

    = thisRef.getLong(getValue<T>(clazz, default, getKey(property))

  override fun setValue(thisRef: SharedPreferences, 

  property: KProperty<*>, value: T) { 
     thisRef.edit().apply 

     { putValue(clazz, value, getKey(property)) }.apply() 
  } 

  private fun getKey(property: KProperty<*>) = 

  key ?: "${property.name}Key" 
} 
```

现在我们知道了 `thisRef` 参数的用法。它的类型是 `SharedPreferences`，我们可以使用它来获取和设置所有的值。以下是用于根据属性类型获取和保存值的函数的定义：

```kt
internal fun SharedPreferences.Editor.putValue(clazz: KClass<*>, value: Any, key: String) {

   when (clazz.simpleName) {

       "Long" -> putLong(key, value as Long)

       "Int" -> putInt(key, value as Int)

       "String" -> putString(key, value as String?)

       "Boolean" -> putBoolean(key, value as Boolean)

       "Float" -> putFloat(key, value as Float)

       else -> putString(key, value.toJson())

   }

}

internal fun <T: Any> SharedPreferences.getValue(clazz: KClass<*>, default: T?, key: String): T = when (clazz.simpleName) {

   "Long" -> getLong(key, default as Long)

   "Int" -> getInt(key, default as Int)

   "String" -> getString(key, default as? String)

   "Boolean" -> getBoolean(key, default as Boolean)

   "Float" -> getFloat(key, default as Float)

   else -> getString(key, default?.toJson()).fromJson(clazz)

} as T
```

我们还需要定义 `toJson` 和 `fromJson`：

```kt
var preferencesGson: Gson = GsonBuilder().create()

internal fun Any.toJson() = preferencesGson.toJson(this)!!

internal fun <T : Any> String.fromJson(clazz: KClass<T>) = preferencesGson.fromJson(this, clazz.java)
```

有了这样的定义，我们可以为 `SharedPreferences` 定义额外的扩展属性：

```kt
var SharedPreferences.canEatPie: Boolean by bindToPreferenceField(true) 
```

正如我们在第七章 *扩展函数和属性* 中已经看到的，Java 中没有我们可以添加到类中的字段。在底层，扩展属性被编译为 getter 和 setter 函数，并且它们将调用委托创建。

```kt
val 'canEatPie$delegate' = bindToPreferenceField(Boolean::class, true) 

fun SharedPreferences.getCanEatPie(): Boolean { 
  return 'canEatPie$delegate'.getValue(this, 

  SharedPreferences::canEatPie) 
} 

fun SharedPreferences.setCanEatPie(value: Boolean) { 
  'canEatPie$delegate'.setValue(this, SharedPreferences::canEatPie, 

   value) 
} 
```

还要记住，扩展函数实际上只是带有第一个参数扩展的静态函数：

```kt
val 'canEatPie$delegate' = bindToPreferenceField(Boolean::class, true) 

fun getCanEatPie(receiver: SharedPreferences): Boolean {

   return 'canEatPie$delegate'.getValue(receiver, 

   SharedPreferences::canEatPie)

}

fun setCanEatPie(receiver: SharedPreferences, value: Boolean) {

   'canEatPie$delegate'.setValue(receiver, 

    SharedPreferences::canEatPie, value)

}
```

介绍的例子应该足以理解属性委托的工作原理以及它们的用法。属性委托在 Kotlin 开源库中被广泛使用。它们被用于快速简单的依赖注入（例如 Kodein、Injekt、TornadoFX）、绑定到视图、`SharedPreferences` 或其他元素（已经包括 `PreferenceHolder` 和 `KotlinAndroidViewBindings`）、在配置定义中定义属性键（例如 Konfig），甚至用于定义数据库列结构（例如 Kwery）。还有许多用法等待被发现。

# 提供委托

自 Kotlin 1.1 开始，有一个名为 `provideDelegate` 的操作符，用于在类初始化期间提供委托。`provideDelegate` 的主要动机是它允许根据属性的特性（名称、类型、注解等）提供自定义委托。

`provideDelegate` 操作符返回委托，所有具有此操作符的类型不需要自己是委托就可以作为委托使用。以下是一个例子：

```kt
    class A(val i: Int) { 

        operator fun provideDelegate( 
            thisRef: Any?, 
            prop: KProperty<*> 
        ) = object: ReadOnlyProperty<Any?, Int> { 

            override fun getValue( 
                thisRef: Any?, 
                property: KProperty<*> 
            ) = i 
        } 
    } 

    val a by A(1) 
```

在这个例子中，`A` 被用作委托，虽然它既不实现 `getvalue` 也不实现 `setvalue` 函数。这是可能的，因为它定义了一个 `provideDelegate` 操作符，它返回将用于代替 `A` 的委托。属性委托被编译为以下代码：

```kt
    private val a$delegate = A().provideDelegate(this, this::prop) 
    val a: Int 
    get() = a1$delegate.getValue(this, this::prop) 
```

在 Kotlin 支持的库 `ActivityStarter` 的一部分中可以找到实际的例子（[`github.com/MarcinMoskala/ActivityStarter`](https://github.com/MarcinMoskala/ActivityStarter)）。活动参数是使用注解定义的，但我们可以使用属性委托来简化从 Kotlin 使用，并允许属性定义为可能是只读的而不是 `lateinit`。

```kt
    @get:Arg(optional = true) val name: String by argExtra(defaultName)

    @get:Arg(optional = true) val id: Int by argExtra(defaultId)

    @get:Arg val grade: Char  by argExtra()

    @get:Arg val passing: Boolean  by argExtra() 
```

但也有一些要求：

+   当使用 `argExtra` 时，属性的 getter 必须被注解

+   如果参数是可选的，并且类型不可为空，我们需要指定默认值。

为了检查这些要求，我们需要引用属性以获取 getter 注释。我们不能在 `argExtra` 函数中拥有这样的引用，但我们可以在 `provideDevegate` 中实现它们：

```kt
fun <T> Activity.argExtra(default: T? = null) = ArgValueDelegateProvider(default)

fun <T> Fragment.argExtra(default: T? = null) = ArgValueDelegateProvider(default)

fun <T> android.support.v4.app.Fragment.argExtra(default: T? = null) = 

        ValueDelegateProvider(default)

class ArgValueDelegateProvider<T>(val default: T? = null) {

    operator fun provideDelegate(

        thisRef: Any?,

        prop: KProperty<*>

    ): ReadWriteProperty<Any, T> {

        val annotation = prop.getter.findAnnotation<Arg>()

        when {

            annotation == null -> 

            throw Error(ErrorMessages.noAnnotation)

            annotation.optional && !prop.returnType.isMarkedNullable && 

            default == null -> 

            throw Error(ErrorMessages.optionalValueNeeded)

        }

        return ArgValueDelegate(default)

    }

}

internal object ErrorMessages {

    const val noAnnotation = 

     "Element getter must be annotated with Arg"

    const val optionalValueNeeded = 

    "Arguments that are optional and have not-

        nullable type must have defaut value specified"

}
```

当条件不满足时，这种委托会抛出适当的错误：

```kt
val a: A? by ArgValueDelegateProvider() 

// Throws error during initialization: Element getter must be annotated with Arg
```

`@get:Arg(optional = true) val a: A by ArgValueDelegateProvider()` 在初始化期间抛出错误：`必须指定可选且非空类型的参数的默认值`。

这种方式在对象初始化期间，不接受不可接受的参数定义，而是抛出适当的错误，而不是在意外情况下破坏应用程序。

# 总结

在本章中，我们描述了类委托、属性委托，以及它们如何用于消除代码中的冗余。我们将委托定义为其他对象或属性调用的对象。我们学习了与类委托密切相关的委托模式和装饰器模式的设计模式。

委托模式被提及为继承的一种替代方案，装饰器模式是一种向实现相同接口的不同类添加功能的方式。我们已经看到了属性委托的工作原理，以及 Kotlin 标准库的属性委托：`notNull`，`lazy`，`observable`，`vetoable`，以及使用 `Map` 作为委托的用法。我们学习了它们的工作原理以及何时应该使用它们。我们还看到了如何制作自定义属性委托，以及实际用例示例。

对不同特性及其用法的了解是不够的，还需要理解它们如何结合在一起构建出色的应用程序。在下一章中，我们将编写一个演示应用程序，并解释本书中描述的各种 Kotlin 特性如何结合在一起。


# 第九章：制作您的 Marvel 画廊应用程序

我们已经看到了最重要的 Kotlin 功能，它们使得 Android 开发更加简单和高效，但仅仅通过查看这些部分很难理解整个画面。因此，在本章中，我们将构建一个完整的用 Kotlin 编写的 Android 应用程序。

在本章中，选择要实现的应用程序是一个艰难的决定。它必须简短而简单，但同时应尽可能多地利用 Kotlin 功能。同时，我们希望最小化使用的库的数量，因为这是一本关于 Kotlin 的 Android 开发书籍，而不是关于 Android 库的书籍。我们希望它看起来尽可能好，但同时我们也希望避免实现自定义图形元素，因为它们通常复杂且实际上并不从 Kotlin 的角度提供好处。

我们最终决定制作一个 Marvel 画廊应用程序--一个小型应用程序，我们可以用来查找我们最喜欢的 Marvel 角色并显示他们的详细信息。所有数据都是通过 Marvel 网站的 API 提供的。

# Marvel 画廊

让我们实现我们的 Marvel 画廊应用程序。该应用程序应允许以下用例：

+   启动应用程序后，用户可以看到一个角色画廊。

+   启动应用程序后，用户可以通过角色名称搜索角色。

+   当用户点击角色图片时，会显示一个简介。角色简介包括角色名称、照片、描述和出现次数。

以下是描述应用程序主要功能的三种用例。在接下来的章节中，我们将逐一实现它们。如果在本章中迷失了方向，记住您可以随时在 GitHub 上查看完整的应用程序（[`github.com/MarcinMoskala/MarvelGallery`](https://github.com/MarcinMoskala/MarvelGallery)）。

为了更好地理解我们想要构建的内容，让我们看一些来自我们应用程序最终版本的截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00053.jpg)

# 如何使用本章

本章展示了构建应用程序所需的所有步骤和代码。其目的是展示应用程序开发的逐步过程。在阅读本章时，专注于开发过程，并尝试理解所呈现的代码的目的。您不需要完全理解布局，也不必理解单元测试的定义，只要理解它们在做什么即可。专注于应用程序结构和使最终代码更简单的 Kotlin 解决方案。大多数解决方案已在前几章中进行了描述，因此只有简要描述。本章的价值在于它们的使用是在具体应用程序的上下文中呈现的。

您可以从 GitHub（[`github.com/MarcinMoskala/MarvelGallery`](https://github.com/MarcinMoskala/MarvelGallery)）下载应用程序代码。

在 GitHub 上，您可以查看最终代码，下载它，或者使用 Git 将其克隆到您的计算机上：

```kt
git clone git@github.com:MarcinMoskala/MarvelGallery.git

```

该应用程序还包括使用**Espresso**编写的 UI 测试，但本章未展示它们，以使对 Espresso 使用不熟练的读者更容易理解。

本章的每个部分在此项目上都有一个对应的 Git 分支，因此如果您想看到每个部分结束时的代码是什么样子，只需切换到相应的分支即可：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00054.jpg)

此外，在本地，当您克隆存储库后，可以使用以下 Git 命令检出相应的分支：

```kt
git checkout Character_search

```

如果您有本书的电子版本，并且想通过复制和粘贴代码的方式制作整个应用程序，那么您可以这样做，但请记住将文件放在对应包的文件夹中。这样，您将保持项目的清晰结构。

请注意，如果您将书中的代码放在其他文件夹中，将会显示警告：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00055.jpg)

您可以故意将文件放在任何文件夹中，因为第二个修复建议是将文件移动到与定义的包对应的路径中：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00056.jpg)

您可以使用它将文件移动到正确的位置。

# 创建一个空项目

在我们开始实现功能之前，我们需要创建一个空的 Kotlin Android 项目，其中只有一个活动，`MainActivty`。这个过程在第一章中已经描述过了，*开始你的 Kotlin 冒险*。因此，我们不需要深入描述它，但我们会展示在 Android Studio 3.0 中的步骤是什么：

1.  为新项目设置名称、包和位置。记得勾选包括 Kotlin 支持选项：*.*

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00057.jpg)

1.  我们可以选择其他最小的 Android 版本，但在这个例子中，我们将设置 API 16：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00058.jpg)

1.  选择一个模板。我们不需要这些模板中的任何一个，所以我们应该从空活动开始*：*

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00059.jpg)

1.  命名新创建的活动。我们可以保留第一个视图命名为`MainActivity` *:*

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00060.jpg)

对于 Android Studio 3.x 之前的版本，我们需要遵循稍微不同的步骤：

使用空的*Activity*从模板创建项目。

1. 配置项目中的 Kotlin（例如，*Ctrl*/*Cmd* + *Shift* + *A*和配置项目中的 Kotlin）。

2. 将所有 Java 类转换为 Kotlin（例如，在`MainActivity`中*Ctrl/Cmd+Shift+A*和将 Java 文件转换为 Kotlin 文件）。

经过这些步骤，我们将拥有一个使用空 Activity 创建的 Kotlin Android 应用：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00061.jpg)

# 角色画廊

在这一部分，我们将实现一个单一用例——启动应用后，用户可以看到一个角色画廊。

这是一个相当复杂的用例，因为它需要呈现视图、与 API 进行网络连接和实现业务规则。因此，我们将把它分成以下任务：

+   视图实现

+   与 API 通信

+   角色显示的业务逻辑实现

+   把所有东西放在一起

这样的任务要容易实现得多。让我们依次实现它们。

# 视图实现

让我们从视图实现开始。在这里，我们将定义角色列表的外观。为了测试目的，我们还将定义一些角色并显示它们。

让我们从`MainActivity`布局实现开始。我们将使用`RecyclerView`来显示一个元素列表。`RecyclerView`布局分布在一个单独的依赖项中，我们需要将其添加到`app`模块的`build.gradle`文件中：

```kt
implementation "com.android.support:recyclerview-v7:$android_support_version" 
```

`android_support_version`实例是一个尚未定义的变量。其背后的原因是所有 Android 支持库的版本应该是相同的，当我们将这个版本号提取为一个分隔变量时，就更容易管理了。这就是为什么我们应该用对`android_support_version`的引用来替换每个 Android 支持库的硬编码版本：

```kt
implementation "com.android.support:appcompat-  

    v7:$android_support_version" 
implementation "com.android.support:design:$android_support_version" 
implementation "com.android.support:support-

    v4:$android_support_version" 
implementation "com.android.support:recyclerview-

    v7:$android_support_version" 
```

并且我们需要设置支持库版本值。良好的做法是在项目的`build*.*gradle`文件中的`buildscript`部分定义它，在`kotlin*_*version`定义之后：

```kt
ext.kotlin_version = '1.1.4-2' 
ext.android_support_version = "26.0.1" 
```

现在我们可以开始实现`MainActivity`布局。这是我们想要实现的效果：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00062.jpg)

我们将把角色元素放入`RecyclerView`中，打包到`SwipeRefreshLayout`中以允许滑动刷新。此外，为了满足 Marvel 的版权要求，需要有一个呈现的标签，告知数据是由 Marvel 提供的。布局`activity_main`（`res/layout/activity_main.xml`）应该被替换为以下定义：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  

   android:id="@+id/charactersView" 
   android:layout_width="match_parent" 
   android:layout_height="match_parent" 
   android:background="@android:color/white" 
   android:fitsSystemWindows="true"> 

   <android.support.v4.widget.SwipeRefreshLayout  

       android:id="@+id/swipeRefreshView" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent"> 

       <android.support.v7.widget.RecyclerView 
           android:id="@+id/recyclerView" 
           android:layout_width="match_parent" 
           android:layout_height="match_parent" 
           android:scrollbars="vertical" /> 

   </android.support.v4.widget.SwipeRefreshLayout> 

   <TextView 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:layout_alignParentBottom="true" 
       android:background="@android:color/white" 
       android:gravity="center" 
       android:text="@string/marvel_copyright_notice" /> 
</RelativeLayout> 
```

我们需要在字符串（`res/values/strings.xml`）中添加版权声明：

```kt
<string name="marvel_copyright_notice">

    Data provided by Marvel. © 2017 MARVEL

</string> 
```

这是一个预览：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00063.jpg)

下一步是定义项目视图。我们希望每个元素都是正方形的。为了做到这一点，我们需要定义一个可以保持正方形形状的视图（将其放在`view/views`中）：

```kt
package com.sample.marvelgallery.view.views 

import android.util.AttributeSet 
import android.widget.FrameLayout 
import android.content.Context 

class SquareFrameLayout @JvmOverloads constructor( // 1 
       context: Context, 
       attrs: AttributeSet? = null, 
       defStyleAttr: Int = 0 
) : FrameLayout(context, attrs, defStyleAttr) { 

   override fun onMeasure(widthMeasureSpec: Int, 

   heightMeasureSpec: Int) { 
       super.onMeasure(widthMeasureSpec, widthMeasureSpec) // 2 
   } 
} 
```

1.  使用`JvmOverloads`注解，我们避免了通常用于在 Android 中定义自定义视图的望远镜构造函数。这在第四章中有描述，*类和对象*。

1.  我们强制元素始终具有与宽度相同的高度。

使用`SquareFrameLayout`，我们可以定义画廊项目的布局。这就是我们想要的样子：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00064.jpg)

我们需要定义`ImageView`来显示角色图像，以及`TextView`来显示其名称。虽然`SquareFrameLayout`实际上是具有固定高度的`FrameLayout`，但它的子元素（图像和文本）默认情况下是一个在另一个上面。让我们将布局添加到`res/layout`文件夹中的`item_character.xml`文件中：

```kt
// ./res/layout/item_character.xml 

<com.sample.marvelgallery.view.views.SquareFrameLayout  

   android:layout_width="match_parent" 
   android:layout_height="wrap_content" 
   android:gravity="center_horizontal" 
   android:orientation="horizontal" 
   android:padding="@dimen/element_padding"> 

   <ImageView 
       android:id="@+id/imageView" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent"/> 

   <TextView 
       android:id="@+id/textView" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:gravity="center" 
       android:paddingLeft="10dp" 
       android:paddingRight="10dp" 
       android:shadowColor="#111" 
       android:shadowDx="5" 
       android:shadowDy="5" 
       android:shadowRadius="0.01" 
       android:textColor="@android:color/white" 
       android:textSize="@dimen/standard_text_size" 
       tools:text="Some name" /> 
</com.sample.marvelgallery.view.views.SquareFrameLayout> 
```

请注意，我们还在`dimens`中定义的`element_padding`等值。让我们将它们添加到`res/values`文件夹中的`dimen.xml`文件中：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
   <dimen name="character_header_height">240dp</dimen> 
   <dimen name="standard_text_size">20sp</dimen> 
   <dimen name="character_description_padding">10dp</dimen> 
   <dimen name="element_padding">10dp</dimen> 
</resources> 
```

正如我们所看到的，每个元素都需要显示角色的名称和图像。因此，角色的模型需要包含这两个属性。让我们为角色定义一个简单的模型：

```kt
package com.sample.marvelgallery.model 

data class MarvelCharacter( 
       val name: String, 
       val imageUrl: String 
) 
```

要使用`RecyclerView`显示元素列表，我们需要实现`RecyclerView`列表和一个项目适配器。列表适配器用于管理列表中的所有元素，而项目适配器是单个项目类型的适配器。在这里，我们只需要一个项目适配器，因为我们显示单一类型的项目。然而，最好假设在将来可能会有其他类型的元素在这个列表上，例如漫画或广告。列表适配器也是一样--在这个例子中我们只需要一个，但在大多数项目中不止一个列表，最好将通用行为提取到一个单独的抽象类中。

虽然这个例子旨在展示 Kotlin 如何在更大的项目中使用，我们将定义一个抽象列表适配器，我们将其命名为`RecyclerListAdapter`，以及一个抽象项目适配器，我们将其命名为`ItemAdapter`。这是`ItemAdapter`的定义：

```kt
package com.sample.marvelgallery.view.common 

import android.support.v7.widget.RecyclerView 
import android.support.annotation.LayoutRes 
import android.view.View 

abstract class ItemAdapter<T : RecyclerView.ViewHolder>

(@LayoutRes open val layoutId: Int) { // 1 

   abstract fun onCreateViewHolder(itemView: View): T // 2 

   @Suppress("UNCHECKED_CAST") // 1 
   fun bindViewHolder(holder: RecyclerView.ViewHolder) { 
       (holder as T).onBindViewHolder() // 1 
   } 

   abstract fun T.onBindViewHolder() // 1, 3 
} 
```

1.  我们需要将持有者作为类型参数传递，以允许直接对其字段进行操作。持有者是在`onCreateViewHolder`中创建的，因此我们知道它的类型将始终是类型参数`T`。因此，我们可以在`bindViewHolder`上将持有者转换为`T`并将其用作`onBindViewHolder`的接收器对象。`@Suppress("UNCHECKED_CAST")`的抑制只是为了在我们知道可以在这种情况下安全转换时隐藏警告。

1.  用于创建视图持有者的函数。在大多数情况下，它将是一个只调用构造函数的单表达式函数。

1.  在`onBindViewHolder`函数中，我们将设置 item 视图上的所有值。

这是`RecyclerListAdapter`的定义：

```kt
package com.sample.marvelgallery.view.common 

import android.support.v7.widget.RecyclerView 
import android.view.LayoutInflater 
import android.view.ViewGroup 

open class RecyclerListAdapter( // 1 
       var items List<AnyItemAdapter> = listOf() 
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() { 

   override final fun getItemCount() = items.size // 4 

   override final fun getItemViewType(position: Int) = 

       items[position].layoutId // 3, 4 

   override final fun onCreateViewHolder(parent: ViewGroup, 

       layoutId: Int): RecyclerView.ViewHolder { // 4 

   val itemView = LayoutInflater.from(parent.context)

       .inflate(layoutId, parent, false) 
       return items.first 

       { it.layoutId == layoutId }.onCreateViewHolder(itemView) // 3 
   } 

   override final fun onBindViewHolder

   (holder: RecyclerView.ViewHolder, position: Int) { // 4 
       items[position].bindViewHolder(holder) 
   } 
} 

typealias AnyItemAdapter = ItemAdapter 

    <out RecyclerView.ViewHolder> // 5 
```

1.  类是`open`而不是`abstract`，因为它可以被初始化和使用而不需要任何子类。我们定义子类是为了允许我们为不同的列表定义自定义方法。

1.  我们将项目保存在列表中。

1.  我们将使用布局来区分项目类型。因此，我们不能在同一个列表上使用具有相同布局的两个项目适配器，但这个解决方案简化了很多事情。

1.  方法是`RecyclerView.Adapter`的重写方法，但它们还使用`final`修饰符来限制它们在子类中的重写。所有扩展`RecyclerListAdapter`的列表适配器都应该操作项目。

1.  我们定义类型别名来简化任何`ItemAdapter`的定义。

使用上述定义，我们可以定义`MainListAdapter`（角色列表的适配器）和`CharacterItemAdapter`（列表上项目的适配器）。这是`MainListAdapter`的定义：

```kt
package com.sample.marvelgallery.view.main 

import com.sample.marvelgallery.view.common.AnyItemAdapter 
import com.sample.marvelgallery.view.common.RecyclerListAdapter 

class MainListAdapter(items: List<AnyItemAdapter>) : RecyclerListAdapter(items) 
```

在这个项目中，我们不需要在`MainListAdapter`中定义任何特殊方法，但是为了展示定义它们有多容易，这里呈现了具有额外添加和删除方法的`MainListAdapter`：

```kt
class MainListAdapter(items: List<AnyItemAdapter>) : RecyclerListAdapter(items) { 

   fun add(itemAdapter: AnyItemAdapter) { 
       items += itemAdapter) 
       val index = items.indexOf(itemAdapter) 
       if (index == -1) return 
       notifyItemInserted(index) 
   } 

   fun delete(itemAdapter: AnyItemAdapter) { 
       val index = items.indexOf(itemAdapter) 
       if (index == -1) return 
       items -= itemAdapter 
       notifyItemRemoved(index) 
   } 
 }    
```

这是`CharacterItemAdapter`的定义：

```kt
package com.sample.marvelgallery.view.main 

import android.support.v7.widget.RecyclerView 
import android.view.View 
import android.widget.ImageView 
import android.widget.TextView 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.view.common.ItemAdapter 
import com.sample.marvelgallery.view.common.bindView 
import com.sample.marvelgallery.view.common.loadImage 

class CharacterItemAdapter( 
       val character: MarvelCharacter // 1 
) : ItemAdapter<CharacterItemAdapter.ViewHolder>(R.layout.item_character) { 

   override fun onCreateViewHolder(itemView: View) = ViewHolder(itemView) 

   override fun ViewHolder.onBindViewHolder() { // 2 
       textView.text = character.name 
       imageView.loadImage(character.imageUrl) // 3 
   } 

   class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView)  

   { 
       val textView by bindView<TextView>(R.id.textView) // 4 
       val imageView by bindView<ImageView>(R.id.imageView) // 4 
   } 
} 
```

1.  `MarvelCharacter`通过构造函数传递。

1.  `onBindViewHolder`方法用于设置视图。它被定义为`ItemAdapter`中的抽象成员扩展函数，由于这样，现在我们可以在其主体内明确使用`textView`和`imageView`。

1.  `loadImage`函数尚未定义。我们稍后将其定义为扩展函数。

1.  在视图持有者中，我们使用`bindView`函数将属性绑定到视图元素，该函数很快将被定义。

在内部，我们使用尚未定义的函数`loadImage`和`bindView`。`bindView`是一个顶级扩展函数，用于`RecyclerView.ViewHolder`，它提供了一个懒惰的委托，该委托通过其 ID 找到视图：

```kt
// ViewExt.kt 
package com.sample.marvelgallery.view.common 

import android.support.v7.widget.RecyclerView 
import android.view.View 

fun <T : View> RecyclerView.ViewHolder.bindView(viewId: Int)  
      = lazy { itemView.findViewById<T>(viewId) } 
```

我们还需要定义`loadImage`扩展函数，它将帮助我们从 URL 下载图像并将其放入`ImageView`中。用于此目的的两个典型库是**Picasso**和**Glide**。我们将使用 Glide，并且为此，我们需要在`build.gradle`中添加依赖项：

```kt
implementation "com.android.support:recyclerview-

v7:$android_support_version" 
implementation "com.github.bumptech.glide:glide:$glide_version" 
```

在项目`build.gradle`中指定版本：

```kt
ext.android_support_version = "26.0.0" 
ext.glide_version = "3.8.0" 
```

在`AndroidManifest`中添加使用互联网的权限：

```kt
<manifest  
   package="com.sample.marvelgallery"> 
   <uses-permission android:name="android.permission.INTERNET" /> 
   <application 
... 
```

最后，我们可以为`ImaveView`类定义`loadImage`扩展函数：

```kt
// ViewExt.kt 
package com.sample.marvelgallery.view.common 

import android.support.v7.widget.RecyclerView 
import android.view.View 
import android.widget.ImageView 
import com.bumptech.glide.Glide 

fun <T : View> RecyclerView.ViewHolder.bindView(viewId: Int)  
       = lazy { itemView.findViewById<T>(viewId) } 

fun ImageView.loadImage(photoUrl: String) { 
   Glide.with(context) 
           .load(photoUrl) 
           .into(this) 
} 
```

是时候定义将显示此列表的活动了。我们将使用另一个元素，**Kotlin Android 扩展**插件。它用于简化从代码访问视图元素。它的使用很简单 - 我们在模块`build.gradle`中添加`kotlin-android-extensions`插件：

```kt
apply plugin: 'com.android.application' 
apply plugin: 'kotlin-android' 
apply plugin: 'kotlin-android-extensions' 

And we have some view defined in layout: 

<TextView 
   android:id="@+id/nameView" 
   android:layout_width="wrap_content" 
   android:layout_height="wrap_content" /> 
```

然后我们可以在`Activity`中导入对此视图的引用：

```kt
import kotlinx.android.synthetic.main.activity_main.* 
```

我们可以直接使用其名称访问`View`元素，而无需使用`findViewById`方法或定义注释：

```kt
nameView.text = "Some name" 
```

我们将在项目中的所有活动中使用 Kotlin Android 扩展。现在让我们定义`MainActivity`以显示带有图像的角色列表：

```kt
package com.sample.marvelgallery.view.main 

import android.os.Bundle 
import android.support.v7.app.AppCompatActivity 
import android.support.v7.widget.GridLayoutManager 
import android.view.Window 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.model.MarvelCharacter 
import kotlinx.android.synthetic.main.activity_main.* 

class MainActivity : AppCompatActivity() { 

   private val characters = listOf( // 1 
       MarvelCharacter(name = "3-D Man", imageUrl = "http://i.annihil.us/u/prod/marvel/i/mg/c/e0/535fecbbb9784.jpg"), 
       MarvelCharacter(name = "Abomination (Emil Blonsky)", imageUrl = "http://i.annihil.us/u/prod/marvel/i/mg/9/50/4ce18691cbf04.jpg") 
   ) 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       requestWindowFeature(Window.FEATURE_NO_TITLE) // 2 
       setContentView(R.layout.activity_main) 
       recyclerView.layoutManager = GridLayoutManager(this, 2) // 3 
       val categoryItemAdapters = characters

       .map(::CharacterItemAdapter) // 4 
       recyclerView.adapter = MainListAdapter(categoryItemAdapters) 
   } 
} 
```

1.  在这里，我们定义了一个临时的角色列表以显示。

1.  我们使用此窗口功能，因为我们不想显示标题。

1.  我们使用`GridLayoutManager`作为`RecyclerView`布局管理器以实现网格效果。

1.  我们正在使用`CharacterItemAdapter`构造函数引用从字符创建项目适配器。

现在我们可以编译项目，然后我们会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00065.jpg)

# 网络定义

到目前为止，所呈现的数据是在应用程序内部硬编码的，但我们希望改为使用 Marvel API 的数据。为此，我们需要定义一些网络机制，以从服务器检索数据。我们将使用**Retrofit**，这是一个流行的 Android 库，用于简化网络操作，以及 RxJava，这是一个用于响应式编程的流行库。对于这两个库，我们将仅使用基本功能，以使其使用尽可能简单。要使用它们，我们需要在模块`build.gradle`中添加以下依赖项：

```kt
dependencies { 
   implementation "org.jetbrains.kotlin:kotlin-stdlib-jre7:

   $kotlin_version" 
   implementation "com.android.support:appcompat-v7:

   $android_support_version" 
   implementation "com.android.support:recyclerview-v7:

   $android_support_version" 
   implementation "com.github.bumptech.glide:glide:$glide_version" 

   // RxJava 
   implementation "io.reactivex.rxjava2:rxjava:$rxjava_version" 

   // RxAndroid 
   implementation "io.reactivex.rxjava2:rxandroid:$rxandroid_version" 

   // Retrofit 
   implementation(["com.squareup.retrofit2:retrofit:$retrofit_version", 
                   "com.squareup.retrofit2:adapter- 

                    rxjava2:$retrofit_version", 
                   "com.squareup.retrofit2:converter-

                    gson:$retrofit_version", 
                   "com.squareup.okhttp3:okhttp:$okhttp_version", 
                   "com.squareup.okhttp3:logging-

                   interceptor:$okhttp_version"]) 

  testImplementation 'junit:junit:4.12' 
  androidTestImplementation 

  'com.android.support.test:runner:1.0.0' 
  androidTestImplementation   

  'com.android.support.test.espresso:espresso-core:3.0.0' 
} 
```

在项目`build.gradle`中定义版本定义：

```kt
ext.kotlin_version = '1.1.3-2' 
ext.android_support_version = "26.0.0" 
ext.glide_version = "3.8.0" 
ext.retrofit_version = '2.2.0' 
ext.okhttp_version = '3.6.0' 
ext.rxjava_version = "2.1.2" 
ext.rxandroid_version = '2.0.1' 
```

我们已经在`AndroidManifest`中定义了互联网权限，因此不需要添加它。简单的`Retrofit`定义可能如下所示：

```kt
val retrofit by lazy { makeRetrofit() } // 1 

private fun makeRetrofit(): Retrofit = Retrofit.Builder() 
       .baseUrl("http://gateway.marvel.com/v1/public/") // 2 
       .build() 
```

1.  我们可以将`retrofit`实例保留为惰性顶级属性。

1.  在这里我们定义`baseUrl`

但是 Retrofit 还有一些额外的要求需要满足。我们需要添加转换器以将 Retrofit 与 RxJava 一起使用，并将对象序列化为 JSON 进行发送。我们还需要拦截器，这些拦截器将用于提供 Marvel API 所需的标头和额外查询。这是一个小应用程序，因此我们可以将所有所需的元素定义为顶级函数。完整的 Retrofit 定义将如下所示：

```kt
// Retrofit.kt 
package com.sample.marvelgallery.data.network.provider 

import com.google.gson.Gson 
import okhttp3.OkHttpClient 
import retrofit2.Retrofit 
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory 
import retrofit2.converter.gson.GsonConverterFactory 
import java.util.concurrent.TimeUnit 

val retrofit by lazy { makeRetrofit() } 

private fun makeRetrofit(): Retrofit = Retrofit.Builder() 
       .baseUrl("http://gateway.marvel.com/v1/public/") 
       .client(makeHttpClient()) 
       .addConverterFactory(GsonConverterFactory.create(Gson())) // 1 
       .addCallAdapterFactory(RxJava2CallAdapterFactory.create()) // 2 
       .build() 

private fun makeHttpClient() = OkHttpClient.Builder() 
       .connectTimeout(60, TimeUnit.SECONDS) // 3 
       .readTimeout(60, TimeUnit.SECONDS) // 4 
       .addInterceptor(makeHeadersInterceptor()) // 5 
       .addInterceptor(makeAddSecurityQueryInterceptor()) // 6 
       .addInterceptor(makeLoggingInterceptor()) // 7 
       .build() 
```

1.  添加一个允许使用 GSON 库对对象 JSON 进行序列化和反序列化的转换器。

1.  添加一个转换器，它将允许 RxJava2 类型（Observable，Single）作为网络请求返回值的可观察对象。

1.  我们添加自定义拦截器。我们需要定义它们所有。

让我们定义所需的拦截器。`makeHeadersInterceptor`用于为每个请求添加标准标头：

```kt
// HeadersInterceptor.kt 
package com.sample.marvelgallery.data.network.provider 

import okhttp3.Interceptor 

fun makeHeadersInterceptor() = Interceptor { chain -> // 1 
   chain.proceed(chain.request().newBuilder() 
           .addHeader("Accept", "application/json") 
           .addHeader("Accept-Language", "en") 
           .addHeader("Content-Type", "application/json") 
           .build()) 
}
```

1.  拦截器是 SAM，因此我们可以使用 SAM 构造函数来定义它。

`makeLoggingInterceptor`函数用于在调试模式下运行应用程序时在控制台上显示日志：

```kt
// LoggingInterceptor.kt 
package com.sample.marvelgallery.data.network.provider 

import com.sample.marvelgallery.BuildConfig 
import okhttp3.logging.HttpLoggingInterceptor 

fun makeLoggingInterceptor() = HttpLoggingInterceptor().apply { 
   level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BODY 

           else HttpLoggingInterceptor.Level.NONE 
} 
```

`makeAddRequiredQueryInterceptor`函数更复杂，因为它用于提供 Marvel API 用于验证用户的查询参数。这些参数需要使用 MD5 算法计算的哈希。它还需要来自 Marvel API 的公钥和私钥。每个人都可以在[`developer.marvel.com/`](https://developer.marvel.com/)生成自己的密钥。生成密钥后，我们需要将它们放在`gradle.properties`文件中：

```kt
org.gradle.jvmargs=-Xmx1536m 
marvelPublicKey=REPLEACE_WITH_YOUR_PUBLIC_MARVEL_KEY 
marvelPrivateKey=REPLEACE_WITH_YOUR_PRIVATE_MARVEL_KEY 
```

还在 Android 的`defaultConfig`部分的模块`build.gradle`中添加以下定义：

```kt
defaultConfig { 
   applicationId "com.sample.marvelgallery" 
   minSdkVersion 16 
   targetSdkVersion 26 
   versionCode 1 
   versionName "1.0" 
   testInstrumentationRunner 

   "android.support.test.runner.AndroidJUnitRunner" 
   buildConfigField("String", "PUBLIC_KEY", "\"${marvelPublicKey}\"") 
   buildConfigField("String", "PRIVATE_KEY", "\"${marvelPrivateKey}\"") 
} 
```

项目重建后，您将能够通过`BuildConfig.PUBLIC_KEY`和`BuildConfig.PRIVATE_KEY`访问这些值。使用这些密钥，我们可以生成 Marvel API 所需的查询参数：

```kt
// QueryInterceptor.kt 
package com.sample.marvelgallery.data.network.provider 

import com.sample.marvelgallery.BuildConfig 
import okhttp3.Interceptor 

fun makeAddSecurityQueryInterceptor() = Interceptor { chain -> 
   val originalRequest = chain.request() 
   val timeStamp = System.currentTimeMillis() 

   // Url customization: add query parameters 
   val url = originalRequest.url().newBuilder() 
           .addQueryParameter("apikey", BuildConfig.PUBLIC_KEY) // 1 
           .addQueryParameter("ts", "$timeStamp") // 1 
           .addQueryParameter("hash", calculatedMd5(timeStamp.toString() + BuildConfig.PRIVATE_KEY + BuildConfig.PUBLIC_KEY)) // 1 
           .build() 

   // Request customization: set custom url 
   val request = originalRequest 
           .newBuilder() 
           .url(url) 
           .build() 

   chain.proceed(request) 
} 
```

1.  我们需要提供三个额外的查询：

+   `apikey`：只包括我们的公钥。

+   `ts`：只包含设备时间的毫秒数。它用于提高下一个查询中提供的哈希的安全性。

+   `hash`：这是从时间戳、私钥和公钥依次计算 MD5 哈希的`String`。

这是用于计算 MD5 哈希的函数的定义：

```kt
// MD5.kt 
package com.sample.marvelgallery.data.network.provider 

import java.math.BigInteger 
import java.security.MessageDigest 

/** 
* Calculate MD5 hash for text 
* @param timeStamp Current timeStamp 
* @return MD5 hash string 
*/ 
fun calculatedMd5(text: String): String { 
   val messageDigest = getMd5Digest(text) 
   val md5 = BigInteger(1, messageDigest).toString(16) 
   return "0" * (32 - md5.length) + md5 // 1 
} 

private fun getMd5Digest(str: String): ByteArray = MessageDigest.getInstance("MD5").digest(str.toByteArray()) 

private operator fun String.times(i: Int) = (1..i).fold("") { acc, _ -> acc + this } 
```

1.  我们正在使用 times 扩展运算符来填充哈希，如果它比 32 短。

我们已经定义了拦截器，因此我们可以定义实际的 API 方法。Marvel API 包含许多表示字符、列表等的数据模型。我们需要将它们定义为单独的类。这样的类称为**数据传输对象**（**DTOs**）。我们将定义我们需要的对象：

```kt
package com.sample.marvelgallery.data.network.dto 

class DataContainer<T> { 
   var results: T? = null 
} 

package com.sample.marvelgallery.data.network.dto 

class DataWrapper<T> { 
   var data: DataContainer<T>? = null 
} 

package com.sample.marvelgallery.data.network.dto 

class ImageDto { 

   lateinit var path: String // 1 
   lateinit var extension: String // 1 

   val completeImagePath: String 
       get() = "$path.$extension" 
} 

package com.sample.marvelgallery.data.network.dto 

class CharacterMarvelDto { 
   lateinit var name: String // 1 
   lateinit var thumbnail: ImageDto // 1 

   val imageUrl: String 
       get() = thumbnail.completeImagePath 
} 
```

1.  对于可能未提供的值，我们应该设置默认值。必须提供的值可能会用`lateinit`前缀。

Retrofit 使用反射来创建基于接口定义的 HTTP 请求。这是我们如何实现定义 HTTP 请求的接口：

```kt
package com.sample.marvelgallery.data.network 

import com.sample.marvelgallery.data.network.dto.CharacterMarvelDto 
import com.sample.marvelgallery.data.network.dto.DataWrapper 
import io.reactivex.Single 
import retrofit2.http.GET 
import retrofit2.http.Query 

interface MarvelApi { 

   @GET("characters") 
   fun getCharacters( 
           @Query("offset") offset: Int?, 
           @Query("limit") limit: Int? 
   ): Single<DataWrapper<List<CharacterMarvelDto>>> 
}  
```

有了这样的定义，我们最终可以得到一个字符列表：

```kt
retrofit.create(MarvelApi::class.java) // 1 

    .getCharacters(0, 100) // 2

    .subscribe({ /* code */ }) // 3 
```

1.  我们使用`retrofit`实例来创建一个对象，根据`MarvelApi`接口定义进行 HTTP 请求。

1.  我们创建一个准备发送到 API 的可观察对象。

1.  通过`subscribe`，我们发送一个 HTTP 请求并开始监听响应。第一个参数是在成功接收响应时调用的回调函数。

这样的网络定义可能已经足够了，但我们可能会实现得更好。最大的问题是我们现在需要操作 DTO 对象，而不是我们自己的数据模型对象。对于映射，我们应该定义一个额外的层。存储库模式用于此目的。当我们实现单元测试时，这种模式也非常有帮助，因为我们可以模拟存储库而不是整个 API 定义。这是我们想要的存储库定义：

```kt
package com.sample.marvelgallery.data 

import com.sample.marvelgallery.model.MarvelCharacter 
import io.reactivex.Single 

interface MarvelRepository { 

   fun getAllCharacters(): Single<List<MarvelCharacter>> 
} 

And here is the implementation of MarvelRepository: 

package com.sample.marvelgallery.data 

import com.sample.marvelgallery.data.network.MarvelApi 
import com.sample.marvelgallery.data.network.provider.retrofit 
import com.sample.marvelgallery.model.MarvelCharacter 
import io.reactivex.Single 

class MarvelRepositoryImpl : MarvelRepository { 

   val api = retrofit.create(MarvelApi::class.java) 

   override fun getAllCharacters(): Single<List<MarvelCharacter>> = api.getCharacters( 
           offset = 0, 
           limit = elementsOnListLimit 
   ).map { 
       it.data?.results.orEmpty().map(::MarvelCharacter) // 1 
   } 

   companion object { 
       const val elementsOnListLimit = 50 
   } 
} 
```

1.  我们正在获取 DTO 元素的列表，并使用构造函数引用将其映射到`MarvelCharacter`。

为使其工作，我们需要在`MarvelCharacter`中定义一个额外的构造函数，以`CharacterMarvelDto`作为参数：

```kt
package com.sample.marvelgallery.model 

import com.sample.marvelgallery.data.network.dto.CharacterMarvelDto 

class MarvelCharacter( 
       val name: String, 
       val imageUrl: String 
) { 

   constructor(dto: CharacterMarvelDto) : this( 
           name = dto.name, 
           imageUrl = dto.imageUrl 
   ) 
} 
```

提供`MarvelRepository`实例的不同方法。在最常见的实现中，具体的`MarvelRepository`实例作为构造函数参数传递给`Presenter`。但是对于 UI 测试（如 Espresso 测试）呢？我们不想测试 Marvel API，也不想使 UI 测试依赖于它。解决方案是制作一个机制，在正常运行时生成标准实现，但也允许我们为测试目的设置不同的实现。我们将制作以下通用机制的实现（将其放在数据中）：

```kt
package com.sample.marvelgallery.data 

abstract class Provider<T> { 

   abstract fun creator(): T 

   private val instance: T by lazy { creator() } 
   var testingInstance: T? = null 

   fun get(): T = testingInstance ?: instance 
} 
```

我们可以使用一些依赖注入库，如**Dagger**或**Kodein**，而不是定义自己的`Provider`。在 Android 开发中，Dagger 用于此类目的非常普遍，但我们决定不在此示例中包含它，以避免给不熟悉该库的开发人员增加额外的复杂性。

我们可以使`MarvelRepository`的伴生对象提供者扩展上述类：

```kt
package com.sample.marvelgallery.data 

import com.sample.marvelgallery.model.MarvelCharacter 
import io.reactivex.Single 

interface MarvelRepository { 

   fun getAllCharacters(): Single<List<MarvelCharacter>> 

   companion object : Provider<MarvelRepository>() { 
       override fun creator() = MarvelRepositoryImpl() 
   } 
} 
```

由于前面的定义，我们可以使用`MarvelRepository`的伴生对象来获取`MarvelRepository`的实例：

```kt
val marvelRepository = MarvelRepository.get()  
```

它将是 MarvelRepositoryImpl 的延迟实例，直到有人设置`testingInstance`属性的非空值为止：

```kt
MarvelRepository.get() // Returns instance of MarvelRepositoryImpl 

MarvelRepository.testingInstance= object: MarvelRepository { 
   override fun getAllCharacters(): Single<List<MarvelCharacter>>  
         = Single.just(emptyList()) 
} 

MarvelRepository.get() // returns an instance of an anonymous class in which the returned list is always empty. 
```

这样的构造对使用 Espresso 进行 UI 测试非常有用。它在项目中用于元素覆盖，并且可以在 GitHub 上找到。为了让不熟悉测试的开发人员更容易理解，本节中没有介绍它。如果你想看到它，可以在[`github.com/MarcinMoskala/MarvelGallery/blob/master/app/src/androidTest/java/com/sample/marvelgallery/MainActivityTest.kt`](https://github.com/MarcinMoskala/MarvelGallery/blob/master/app/src/androidTest/java/com/sample/marvelgallery/MainActivityTest.kt)找到。

最后让我们通过实现角色画廊显示的业务逻辑来将这个存储库与视图连接起来。

# 业务逻辑实现

我们已经实现了视图和存储库部分，现在是时候最终实现业务逻辑了。在这一点上，我们只需要获取角色列表并在用户进入屏幕或刷新时显示它。我们将使用一种称为**Model-View-Presenter**（**MVP**）的架构模式从视图实现中提取这些业务逻辑规则。以下是简化的规则：

+   **Model**：这是负责管理数据的层。模型的责任包括使用 API、缓存数据、管理数据库等。

+   **Presenter**：Presenter 是模型和视图之间的中间人，它应该包含所有的演示逻辑。Presenter 负责对用户交互做出反应，使用和更新模型和视图。

+   **View**：这负责呈现数据并将用户交互事件转发给 Presenter。

在我们实现这种模式时，我们将 Activity 视为视图，并且对于每个视图，我们需要创建一个 Presenter。编写单元测试来检查业务逻辑规则是否正确实现是一个好的实践。为了简化，我们需要将 Activity 隐藏在一个易于模拟的接口后面，该接口代表了 Presenter 与视图（Activity）的所有可能的交互。此外，我们将在 Activity 中创建所有依赖项（例如`MarvelRepository`），并通过构造函数将它们作为隐藏在接口后面的对象（例如，将`MarvelRepositoryImpl`作为`MarvelRepository`）传递给 Presenter。

在 Presenter 中，我们需要实现以下行为：

+   当 Presenter 等待响应时，显示加载动画

+   视图创建后，加载并显示角色列表

+   调用刷新方法后，加载角色列表

+   当 API 返回角色列表时，它会显示在视图上

+   当 API 返回错误时，它会显示在视图上

正如我们所看到的，Presenter 需要通过构造函数获取 View 和`MarvelRepository`，并且应该指定在视图创建或用户请求列表刷新时将调用的方法：

```kt
package com.sample.marvelgallery.presenter 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.view.main.MainView 

class MainPresenter(val view: MainView, val repository: MarvelRepository) { 

   fun onViewCreated() { 
   } 

   fun onRefresh() { 
   } 
} 
```

视图需要指定用于显示角色列表、显示错误和在视图刷新时显示进度条的方法（在`view/main`中定义，并将`MainActivity`移动到`view/main`）：

```kt
package com.sample.marvelgallery.view.main.main 

import com.sample.marvelgallery.model.MarvelCharacter 

interface MainView { 
   var refresh: Boolean 
   fun show(items: List<MarvelCharacter>) 
   fun showError(error: Throwable) 
} 
```

在向 Presenter 添加逻辑之前，让我们先定义两个单元测试：

```kt
// test source set 
package com.sample.marvelgallery 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import com.sample.marvelgallery.view.main.MainView 
import io.reactivex.Single 
import org.junit.Assert.assertEquals 
import org.junit.Assert.fail 
import org.junit.Test 

@Suppress("IllegalIdentifier") // 1 
class MainPresenterTest { 

   @Test 
   fun `After view was created, list of characters is loaded and displayed`() { 
       assertOnAction { onViewCreated() }.thereIsSameListDisplayed() 
   } 

   @Test 
   fun `New list is shown after view was refreshed`() { 
       assertOnAction { onRefresh() }.thereIsSameListDisplayed() 
   } 

   private fun assertOnAction(action: MainPresenter.() -> Unit) 
           = PresenterActionAssertion(action) 

   private class PresenterActionAssertion

   (val actionOnPresenter: MainPresenter.() -> Unit) { 

       fun thereIsSameListDisplayed() { 
           // Given 
           val exampleCharacterList = listOf(// 2 
                   MarvelCharacter("ExampleName", "ExampleImageUrl"), 
                   MarvelCharacter("Name1", "ImageUrl1"), 
                   MarvelCharacter("Name2", "ImageUrl2") 
           ) 

           var displayedList: List<MarvelCharacter>? = null 

           val view = object : MainView { //3 
               override var refresh: Boolean = false 

               override fun show(items: List<MarvelCharacter>) { 
                   displayedList = items // 4 
               } 

               override fun showError(error: Throwable) { 
                   fail() //5 
               } 
           } 
           val marvelRepository = object : MarvelRepository { // 3 
               override fun getAllCharacters(): 

                Single<List<MarvelCharacter>> 
                  = Single.just(exampleCharacterList) // 6 
           } 

           val mainPresenter = MainPresenter(view, marvelRepository) 

           // 3 

           // When 
           mainPresenter.actionOnPresenter() // 7 

           // Then 
           assertEquals(exampleCharacterList, displayedList) // 8 
       } 
   } 
} 
```

1.  Kotlin 单元测试允许使用描述性名称，但会显示警告。需要抑制此警告。

1.  定义一个要显示的示例角色列表。

1.  定义一个视图和存储库，并使用它们创建一个 Presenter。

1.  当显示元素列表时，我们应该将其设置为显示的列表。

1.  当调用`showError`时，测试失败。

1.  `getAllCharacters` 方法只是返回一个示例列表。

1.  我们在 Presenter 上调用一个定义好的动作。

1.  我们检查存储库返回的列表是否与显示的列表相同。

为了简化前面的定义，我们可以提取`BaseMarvelRepository`和`BaseMainView`，并将示例数据保存在一个单独的类中：

```kt
// test source set 
package com.sample.marvelgallery.helpers 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import io.reactivex.Single 

class BaseMarvelRepository( 
       val onGetCharacters: () -> Single<List<MarvelCharacter>> 
) : MarvelRepository { 

   override fun getAllCharacters() = onGetCharacters() 
} 

// test source set 
package com.sample.marvelgallery.helpers 

import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.view.main.MainView 

class BaseMainView( 
       var onShow: (items: List<MarvelCharacter>) -> Unit = {}, 
       val onShowError: (error: Throwable) -> Unit = {}, 
       override var refresh: Boolean = false 
) : MainView { 

   override fun show(items: List<MarvelCharacter>) { 
       onShow(items) 
   } 

   override fun showError(error: Throwable) { 
       onShowError(error) 
   } 
} 

// test source set 
package com.sample.marvelgallery.helpers 

import com.sample.marvelgallery.model.MarvelCharacter 

object Example { 
   val exampleCharacter = MarvelCharacter

   ("ExampleName", "ExampleImageUrl") 
   val exampleCharacterList = listOf( 
           exampleCharacter, 
           MarvelCharacter("Name1", "ImageUrl1"), 
           MarvelCharacter("Name2", "ImageUrl2") 
   ) 
} 
```

现在我们可以简化`PresenterActionAssertion`的定义：

```kt
package com.sample.marvelgallery 

import com.sample.marvelgallery.helpers.BaseMainView 
import com.sample.marvelgallery.helpers.BaseMarvelRepository 
import com.sample.marvelgallery.helpers.Example 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import io.reactivex.Single 
import org.junit.Assert.assertEquals 
import org.junit.Assert.fail 
import org.junit.Test 

@Suppress("IllegalIdentifier") 

class MainPresenterTest { 

   @Test 
   fun `After view was created, list of characters is loaded and displayed`() { 
       assertOnAction { onViewCreated() }.thereIsSameListDisplayed() 
   } 

   @Test 
   fun `New list is shown after view was refreshed`() { 
       assertOnAction { onRefresh() }.thereIsSameListDisplayed() 
   } 

   private fun assertOnAction(action: MainPresenter.() -> Unit) 
           = PresenterActionAssertion(action) 

   private class PresenterActionAssertion

   (val actionOnPresenter: MainPresenter.() -> Unit) { 

       fun thereIsSameListDisplayed() { 
           // Given 
           var displayedList: List<MarvelCharacter>? = null 

           val view = BaseMainView( 
                   onShow = { items -> displayedList = items }, 
                   onShowError = { fail() } 
           ) 
           val marvelRepository = BaseMarvelRepository( 
                 onGetCharacters = 

           { Single.just(Example.exampleCharacterList) } 
           ) 

           val mainPresenter = MainPresenter(view, marvelRepository) 

           // When 
           mainPresenter.actionOnPresenter() 

           // Then 
           assertEquals(Example.exampleCharacterList, displayedList) 
       } 
   } 
} 
```

我们开始测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00066.jpg)

我们会发现它们没有通过：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00067.jpg)

原因是`MainPresenter`中的功能尚未实现。满足这个单元测试的最简单的代码如下：

```kt
package com.sample.marvelgallery.presenter 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.view.main.MainView 

class MainPresenter(val view: MainView, val repository: MarvelRepository) { 

   fun onViewCreated() { 
       loadCharacters() 
   } 

   fun onRefresh() { 
       loadCharacters() 
   } 

   private fun loadCharacters() { 
       repository.getAllCharacters() 
               .subscribe({ items -> 
                   view.show(items) 
               }) 
   } 
} 
```

现在我们的测试通过了：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00068.jpg)

但是以下实现存在两个问题：

+   在 Android 中不起作用，因为`getAllCharacters`正在使用网络操作，而不能像这个例子中一样在主线程上运行

+   如果用户在加载完成之前离开应用程序，我们将会有内存泄漏

为了解决第一个问题，我们需要指定哪些操作应该在哪些线程上运行。网络请求应该在 I/O 线程上运行，我们应该在 Android 主线程上观察（因为我们在回调中改变了视图）：

```kt
repository.getAllCharacters() 
       .subscribeOn(Schedulers.io()) // 1 
       .observeOn(AndroidSchedulers.mainThread()) // 2 
       .subscribe({ items -> view.show(items) }) 
```

1.  我们指定网络请求应该在 IO 线程中运行。

1.  我们指定回调应该在主线程上启动。

虽然这些是常见的调度程序，但我们可以将它们提取到顶层扩展函数中：

```kt
// RxExt.kt 
package com.sample.marvelgallery.data 

import io.reactivex.Single 
import io.reactivex.android.schedulers.AndroidSchedulers 
import io.reactivex.schedulers.Schedulers 

fun <T> Single<T>.applySchedulers(): Single<T> = this 
       .subscribeOn(Schedulers.io()) 
       .observeOn(AndroidSchedulers.mainThread()) 

And use it in MainPresenter: 

repository.getAllCharacters() 
       .applySchedulers() 
       .subscribe({ items -> view.show(items) }) 
```

测试不允许访问 Android 主线程。因此，我们的测试将无法通过。此外，在单元测试中运行在新线程上的操作并不是我们想要的，因为我们会有问题断言同步。为了解决这些问题，我们需要在单元测试之前覆盖调度程序，使一切都在同一个线程上运行（将其添加到`MainPresenterTest`类中）：

```kt
package com.sample.marvelgallery 

import com.sample.marvelgallery.helpers.BaseMainView 
import com.sample.marvelgallery.helpers.BaseMarvelRepository 
import com.sample.marvelgallery.helpers.Example 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import io.reactivex.Single 
import io.reactivex.android.plugins.RxAndroidPlugins 
import io.reactivex.plugins.RxJavaPlugins 
import io.reactivex.schedulers.Schedulers 
import org.junit.Assert.assertEquals 
import org.junit.Assert.fail 
import org.junit.Before 
import org.junit.Test 

@Suppress("IllegalIdentifier") 

class MainPresenterTest { 

   @Before 
   fun setUp() { 
       RxAndroidPlugins.setInitMainThreadSchedulerHandler { 

           Schedulers.trampoline() } 
       RxJavaPlugins.setIoSchedulerHandler { Schedulers.trampoline() } 
       RxJavaPlugins.setComputationSchedulerHandler { 

           Schedulers.trampoline() } 
       RxJavaPlugins.setNewThreadSchedulerHandler { 

           Schedulers.trampoline() } 
   } 

   @Test 
   fun `After view was created, list of characters is loaded and 

        displayed`() { 
       assertOnAction { onViewCreated() }.thereIsSameListDisplayed() 
   } 

   @Test 
   fun `New list is shown after view was refreshed`() { 
       assertOnAction { onRefresh() }.thereIsSameListDisplayed() 
   } 
```

现在单元测试再次通过了：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00069.jpg)

另一个问题是，如果用户在我们收到服务器响应之前离开应用程序，会出现内存泄漏。一个常见的解决方案是将所有订阅保留在 composite 中，并在用户离开应用程序时将它们全部处理掉：

```kt
private var subscriptions = CompositeDisposable() 

fun onViewDestroyed() { 
   subscriptions.dispose() 
} 
```

在更大的应用程序中，大多数 Presenter 都有一些订阅。因此，收集订阅并在用户销毁视图时处理它们的功能可以被视为常见行为，并在`BasePresenter`中提取。此外，为了简化流程，我们可以创建一个`BaseActivityWithPresenter`类，它将在`Presenter`接口后面保存 Presenter，并在视图被销毁时调用`onViewDestroyed`方法。让我们在我们的应用程序中定义这个机制。以下是`Presenter`的定义：

```kt
package com.sample.marvelgallery.presenter 

interface Presenter { 
   fun onViewDestroyed() 
} 
```

以下是`BasePresenter`的定义：

```kt
package com.sample.marvelgallery.presenter 

import io.reactivex.disposables.CompositeDisposable 

abstract class BasePresenter : Presenter { 

   protected var subscriptions = CompositeDisposable() 

   override fun onViewDestroyed() { 
       subscriptions.dispose() 
   } 
} 
```

以下是`BaseActivityWithPresenter`的定义：

```kt
package com.sample.marvelgallery.view.common 

import android.support.v7.app.AppCompatActivity 
import com.sample.marvelgallery.presenter.Presenter 

abstract class BaseActivityWithPresenter : AppCompatActivity() { 

   abstract val presenter: Presenter 

   override fun onDestroy() { 
       super.onDestroy() 
       presenter.onViewDestroyed() 
   } 
} 
```

为了简化将新订阅添加到订阅中的定义，我们可以定义一个加法分配运算符：

```kt
// RxExt.ext 
package com.sample.marvelgallery.data 

import io.reactivex.Single 
import io.reactivex.android.schedulers.AndroidSchedulers 
import io.reactivex.disposables.CompositeDisposable 
import io.reactivex.disposables.Disposable 
import io.reactivex.schedulers.Schedulers 

fun <T> Single<T>.applySchedulers(): Single<T> = this 
       .subscribeOn(Schedulers.io()) 
       .observeOn(AndroidSchedulers.mainThread()) 

operator fun CompositeDisposable.plusAssign(disposable: Disposable) { 
   add(disposable) 
} 
```

我们可以使用这两种解决方案来使`MainPresenter`更安全：

```kt
package com.sample.marvelgallery.presenter 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.data.applySchedulers 
import com.sample.marvelgallery.data.plusAssign 
import com.sample.marvelgallery.view.main.MainView 

class MainPresenter( 
       val view: MainView, 
       val repository: MarvelRepository 
) : BasePresenter() { 

   fun onViewCreated() { 
       loadCharacters() 
   } 

   fun onRefresh() { 
       loadCharacters() 
   } 

   private fun loadCharacters() { 
       subscriptions += repository.getAllCharacters() 
               .applySchedulers() 
               .subscribe({ items -> 
                   view.show(items) 
               }) 
   } 
} 
```

前两个`MainPresenter`行为已经实现。现在是时候转向下一个--当 API 返回错误时，它会显示在视图上。我们可以将这个要求作为`MainPresenterTest`中的一个测试添加：

```kt
@Test 
fun `New list is shown after view was refreshed`() { 
   assertOnAction { onRefresh() }.thereIsSameListDisplayed() 
} 

@Test 
fun `When API returns error, it is displayed on view`() { 
   // Given 
   val someError = Error() 
   var errorDisplayed: Throwable? = null 
   val view = BaseMainView( 
           onShow = { _ -> fail() }, 
           onShowError = { errorDisplayed = it } 
   ) 
   val marvelRepository = BaseMarvelRepository 

   { Single.error(someError) } 
   val mainPresenter = MainPresenter(view, marvelRepository) 
   // When 
   mainPresenter.onViewCreated() 
   // Then 
   assertEquals(someError, errorDisplayed) 
} 

private fun assertOnAction(action: MainPresenter.() -> Unit) 
       = PresenterActionAssertion(action) 
```

使这个测试通过的一个简单的改变是在`MainPresenter`的订阅方法中指定错误处理程序：

```kt
subscriptions += repository.getAllCharacters() 
       .applySchedulers() 
       .subscribe({ items -> // onNext 
           view.show(items) 
       }, { // onError 
           view.showError(it) 
       }) 
```

虽然`subscribe`是 Java 方法，我们不能使用命名参数约定。这种调用并不真正描述性。这就是为什么我们将在`RxExt.kt`中定义一个名为`subscribeBy`的自定义订阅方法：

```kt
// Ext.kt

fun <T> Single<T>.applySchedulers(): Single<T> = this

       .subscribeOn(Schedulers.io())

       .observeOn(AndroidSchedulers.mainThread())

fun <T> Single<T>.subscribeBy(

       onError: ((Throwable) -> Unit)? = null,

       onSuccess: (T) -> Unit

): Disposable = subscribe(onSuccess, { onError?.invoke(it) })
```

我们将使用它而不是订阅：

```kt
subscriptions += repository.getAllCharacters()

       .applySchedulers()

       .subscribeBy(

               onSuccess = view::show,

               onError = view::showError

      )
```

`subscribeBy`的完整版本定义了不同的 RxJava 类型（如 Observable、Flowable 等），以及许多其他有用的 Kotlin 扩展到 RxJava，可以在**RxKotlin**库中找到（[`github.com/ReactiveX/RxKotlin`](https://github.com/ReactiveX/RxKotlin)）。

为了显示和隐藏列表加载，我们将定义额外的监听器来监听在处理之前和之后总是发生的事件：

```kt
subscriptions += repository.getAllCharacters()

       .applySchedulers()

       .doOnSubscribe { view.refresh = true },}

               onSuccess = view::show,

       .doFinally { view.refresh = false }

       .subscribeBy(

                     onSuccess = view::show,

                     onError = view::showError,

                onFinish = { view.refresh = false }

       )
```

测试又通过了：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00070.jpg)

`subscribe`方法变得越来越难以阅读，但我们将解决这个问题，还有另一个业务规则，其定义如下--当 Presenter 等待响应时，会显示刷新。在`MainPresenterTest`中定义其单元测试：

```kt
package com.sample.marvelgallery 

import com.sample.marvelgallery.helpers.BaseMainView 
import com.sample.marvelgallery.helpers.BaseMarvelRepository 
import com.sample.marvelgallery.helpers.Example 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import io.reactivex.Single 
import io.reactivex.android.plugins.RxAndroidPlugins 
import io.reactivex.plugins.RxJavaPlugins 
import io.reactivex.schedulers.Schedulers 
import org.junit.Assert.* 
import org.junit.Before 
import org.junit.Test 

@Suppress("IllegalIdentifier") 

class MainPresenterTest { 

   @Test 
   fun `When presenter is waiting for response, refresh is displayed`()  

   { 
       // Given 
       val view = BaseMainView(refresh = false) 
       val marvelRepository = BaseMarvelRepository( 
               onGetCharacters = { 
                   Single.fromCallable { 
                       // Then 
                       assertTrue(view.refresh) // 1 
                       Example.exampleCharacterList 
                   } 
               } 
       ) 
       val mainPresenter = MainPresenter(view, marvelRepository) 
       view.onShow = { _ -> 
           // Then 
           assertTrue(view.refresh) // 1 
       } 
       // When 
       mainPresenter.onViewCreated() 
       // Then 
       assertFalse(view.refresh) // 1 
   } 
 } 
```

1.  我们期望在网络请求期间和显示元素时刷新显示，但在处理完成后不刷新。

我们期望在网络请求期间和显示元素时刷新显示，但在处理完成后不刷新。

在 RxJava2 的这个版本中，回调内的断言不会破坏测试，而是在执行报告中显示错误：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00071.jpg)![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00072.jpg)

可能在未来的版本中，将可以添加一个处理程序，允许从回调内部使测试失败。

为了显示和隐藏列表加载，我们将定义额外的监听器来监听在处理之前和之后总是发生的事件：

```kt
subscriptions += repository.getAllCharacters()

       .applySchedulers()

       .doOnSubscribe { view.refresh = true }

       .doFinally { view.refresh = false }

       .subscribeBy(

                     onSuccess = view::show,

                     onError = view::showError

        )
```

在这些更改之后，所有测试又通过了：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00073.jpg)

现在我们有一个完全功能的 Presenter、网络和视图。是时候把它们全部连接起来，完成第一个用例的实现了。

# 把它们放在一起

我们已经准备好在项目中使用`MainPresenter`。现在我们需要在`MainActivity`中使用它：

```kt
package com.sample.marvelgallery.view.main 

import android.os.Bundle 
import android.support.v7.widget.GridLayoutManager 
import android.view.Window 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import com.sample.marvelgallery.view.common.BaseActivityWithPresenter 
import com.sample.marvelgallery.view.common.bindToSwipeRefresh 
import com.sample.marvelgallery.view.common.toast 
import kotlinx.android.synthetic.main.activity_main.* 

class MainActivity : BaseActivityWithPresenter(), MainView { // 1 

   override var refresh by bindToSwipeRefresh(R.id.swipeRefreshView) 

   // 2 
   override val presenter by lazy 

   { MainPresenter(this, MarvelRepository.get()) } // 3 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       requestWindowFeature(Window.FEATURE_NO_TITLE) 
       setContentView(R.layout.activity_main) 
       recyclerView.layoutManager = GridLayoutManager(this, 2) 
       swipeRefreshView.setOnRefreshListener 

       { presenter.onRefresh() } // 4 
       presenter.onViewCreated() // 4 
   } 

   override fun show(items: List<MarvelCharacter>) { 
       val categoryItemAdapters = items.map(::CharacterItemAdapter) 
       recyclerView.adapter = MainListAdapter(categoryItemAdapters) 
   } 

   override fun showError(error: Throwable) { 
       toast("Error: ${error.message}") // 2 
       error.printStackTrace() 
   } 
} 
```

1.  Activity 应该扩展`BaseActivityWithPresenter`并实现`MainView`。

1.  `bindToSwipeRefresh`和`toast`还没有实现。

1.  我们使 Presenter 懒惰。第一个参数是指向`MainView`接口后面的活动的引用。

1.  我们需要使用它的方法将事件传递给 Presenter。

在前面的代码中，我们使用了两个已在书中描述的函数，`toast`用于在屏幕上显示提示，`bindToSwipeRefresh`用于绑定滑动刷新的可见性属性：

```kt
// ViewExt.kt 
package com.sample.marvelgallery.view.common 

import android.app.Activity 
import android.content.Context 
import android.support.annotation.IdRes 
import android.support.v4.widget.SwipeRefreshLayout 
import android.support.v7.widget.RecyclerView 
import android.view.View 
import android.widget.ImageView 
import android.widget.Toast 
import com.bumptech.glide.Glide 
import kotlin.properties.ReadWriteProperty 
import kotlin.reflect.KProperty 

fun <T : View> RecyclerView.ViewHolder.bindView(viewId: Int) 
       = lazy { itemView.findViewById<T>(viewId) } 

fun ImageView.loadImage(photoUrl: String) { 
   Glide.with(context) 
           .load(photoUrl) 
           .into(this) 
} 

fun Context.toast(text: String, length: Int = Toast.LENGTH_LONG) { 
   Toast.makeText(this, text, length).show() 
} 

fun Activity.bindToSwipeRefresh(@IdRes swipeRefreshLayoutId: Int): ReadWriteProperty<Any?, Boolean> 
       = SwipeRefreshBinding(lazy { findViewById<SwipeRefreshLayout>(swipeRefreshLayoutId) }) 

private class SwipeRefreshBinding(lazyViewProvider: Lazy<SwipeRefreshLayout>) : ReadWriteProperty<Any?, Boolean> { 

   val view by lazyViewProvider 

   override fun getValue(thisRef: Any?, 

   property: KProperty<*>): Boolean { 
       return view.isRefreshing 
   } 

   override fun setValue(thisRef: Any?, 

   property: KProperty<*>, value: Boolean) { 
       view.isRefreshing = value 
   } 
} 
```

现在我们的应用程序应该正确显示角色列表：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00074.jpg)

我们的第一个用例已经实现。我们可以继续下一个。

# 角色搜索

我们需要实现的另一个行为是角色搜索。以下是用例定义，启动应用程序后，用户可以通过角色名称搜索角色。

为了添加它，我们将在`activity_main`布局中添加`EditText`：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  

   android:id="@+id/charactersView" 
   android:layout_width="match_parent" 
   android:layout_height="match_parent" 
   android:background="@android:color/white" 
   android:fitsSystemWindows="true"> 

<!-- Dummy item to prevent EditText from receiving 

     focus on initial load --> 
   <LinearLayout 
       android:layout_width="0px" 
       android:layout_height="0px" 
       android:focusable="true" 
       android:focusableInTouchMode="true" 
       tools:ignore="UselessLeaf" /> 

  <android.support.design.widget.TextInputLayout 
     android:id="@+id/searchViewLayout" 
     android:layout_width="match_parent" 
     android:layout_height="wrap_content" 
     android:layout_margin="@dimen/element_padding"> 

     <EditText 
         android:id="@+id/searchView" 
         android:layout_width="match_parent" 
         android:layout_height="wrap_content" 
         android:layout_centerHorizontal="true" 
         android:hint="@string/search_hint" /> 

  </android.support.design.widget.TextInputLayout> 

   <android.support.v4.widget.SwipeRefreshLayout  
       android:id="@+id/swipeRefreshView" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:layout_below="@+id/searchViewLayout" 
       app:layout_behavior="@string/appbar_scrolling_view_behavior"> 

       <android.support.v7.widget.RecyclerView 
           android:id="@+id/recyclerView" 
           android:layout_width="match_parent" 
           android:layout_height="match_parent" 
           android:scrollbars="vertical" /> 

   </android.support.v4.widget.SwipeRefreshLayout> 

   <TextView 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:layout_alignParentBottom="true" 
       android:background="@android:color/white" 
       android:gravity="center" 
       android:text="@string/marvel_copyright_notice" /> 
</RelativeLayout> 
```

我们需要添加**Android Support Design**库依赖，以允许使用`TextInputLayout`：

```kt
implementation "com.android.support:appcompat-v7:$android_support_version" 
implementation "com.android.support:design:$android_support_version" 
implementation "com.android.support:recyclerview-v7:$android_support_version" 
```

在`strings.xml`中定义了`search_hint`字符串：

```kt
<resources> 
   <string name="app_name">MarvelGallery</string> 
   <string name="search_hint">Search for character</string> 
   <string name="marvel_copyright_notice">

      Data provided by Marvel. © 2017 MARVEL

   </string> 
</resources> 
```

此外，为了在键盘打开时保持通知有关 Marvel 版权的标签，我们还需要在`AndroidManifest`中的`activity`定义中将`adjustResize`设置为`windowSoftInputMode`：

```kt
<activity 
   android:name="com.sample.marvelgallery.view.main.MainActivity" 
   android:windowSoftInputMode="adjustResize"> 
   <intent-filter> 
       <action android:name="android.intent.action.MAIN" /> 
       <category android:name="android.intent.category.LAUNCHER" /> 
   </intent-filter> 
</activity> 
```

我们应该看到以下预览：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00075.jpg)

现在我们在`MainActivity`中添加了一个搜索字段：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00076.jpg)

我们期望的行为是，每当用户更改搜索字段中的文本时，将加载新列表。我们需要在`MainPresenter`中添加一个新方法，用于通知 Presenter 文本已更改。我们将称之为`onSearchChanged`：

```kt
fun onRefresh() { 
   loadCharacters() 
} 

fun onSearchChanged(text: String) { 
   // TODO 
}

private fun loadCharacters() {

   subscriptions += repository.getAllCharacters()

           .applySchedulers()

           .doOnSubscribe { view.refresh = true }

           .doFinally { view.refresh = false }

           .subscribeBy(

               onSuccess = view::show,

               onError = view::showError

         )

   }

}
```

我们需要更改`MarvelRepository`的定义，以接受搜索查询作为`getAllCharacters`参数（记得也更新`BaseMarvelRepository`）：

```kt
interface MarvelRepository { 

   fun getAllCharacters(searchQuery: String?): 

   Single<List<MarvelCharacter>> 

   companion object : Provider<MarvelRepository>() { 
       override fun creator() = MarvelRepositoryImpl() 
   } 
} 
```

因此，我们必须更新实现：

```kt
class MarvelRepositoryImpl : MarvelRepository { 

   val api = retrofit.create(MarvelApi::class.java) 

   override fun getAllCharacters(searchQuery: String?): 

   Single<List<MarvelCharacter>> = api.getCharacters( 
           offset = 0, 
           searchQuery = searchQuery, 
           limit = elementsOnListLimit 
   ).map { it.data?.results.orEmpty().map(::MarvelCharacter) ?: 

    emptyList() } 

   companion object { 
       const val elementsOnListLimit = 50 
   } 
} 
```

我们还需要更新网络请求的定义：

```kt
interface MarvelApi { 

   @GET("characters") 
   fun getCharacters( 
           @Query("offset") offset: Int?, 
           @Query("nameStartsWith") searchQuery: String?, 
           @Query("limit") limit: Int? 
   ): Single<DataWrapper<List<CharacterMarvelDto>>> 
} 
```

为了允许代码编译，我们需要在`MainPresenter`中提供`null`作为`getAllCharacters`参数：

```kt
private fun loadCharacters() {

   subscriptions += repository.getAllCharacters(null)

           .applySchedulers()

           .doOnSubscribe { view.refresh = true }

           .doFinally { view.refresh = false }

           .subscribeBy(

                       onSuccess = view::show,

                       onError = view::showError

         )

   }

}
```

我们需要更新`BaseMarvelRepository`：

```kt
package com.sample.marvelgallery.helpers 

import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import io.reactivex.Single 

class BaseMarvelRepository( 
       val onGetCharacters: (String?) -> Single<List<MarvelCharacter>> 
) : MarvelRepository { 

   override fun getAllCharacters(searchQuery: String?) 
           = onGetCharacters(searchQuery) 
} 
```

现在我们的网络实现返回一个从查询开始的角色列表，或者如果我们没有指定任何查询，则返回一个填充列表。是时候实现 Presenter 了。让我们定义以下测试：

```kt
@file:Suppress("IllegalIdentifier") 

package com.sample.marvelgallery 

import com.sample.marvelgallery.helpers.BaseMainView 
import com.sample.marvelgallery.helpers.BaseMarvelRepository 
import com.sample.marvelgallery.presenter.MainPresenter 
import io.reactivex.Single 
import org.junit.Assert.* 
import org.junit.Test 

class MainPresenterSearchTest { 

   @Test 
   fun `When view is created, then search query is null`() { 
       assertOnAction { onViewCreated() } searchQueryIsEqualTo null 
   } 

   @Test 
   fun `When text is changed, then we are searching for new query`() { 
       for (text in listOf("KKO", "HJ HJ", "And so what?")) 
           assertOnAction { onSearchChanged(text) } 

           searchQueryIsEqualTo text 
   } 

   private fun assertOnAction(action: MainPresenter.() -> Unit)  
         = PresenterActionAssertion(action) 

   private class PresenterActionAssertion(val actionOnPresenter: 

       MainPresenter.() -> Unit) { 

       infix fun searchQueryIsEqualTo(expectedQuery: String?) { 
           var checkApplied = false 
           val view = BaseMainView(onShowError = { fail() }) 
           val marvelRepository = BaseMarvelRepository { searchQuery -> 
               assertEquals(expectedQuery, searchQuery) 
               checkApplied = true 
               Single.never() 
           } 
           val mainPresenter = MainPresenter(view, marvelRepository) 
           mainPresenter.actionOnPresenter() 
           assertTrue(checkApplied) 
       } 
   } 
} 
```

为了使以下测试通过，我们需要将搜索查询作为`MainPresenter`的`loadCharacters`方法的参数添加默认参数：

```kt
fun onSearchChanged(text: String) { 
   loadCharacters(text) 
} 

private fun loadCharacters(searchQuery: String? = null) {

   subscriptions += repository.getAllCharacters(searchQuery)

           .applySchedulers()

           .doOnSubscribe { view.refresh = true }

           .doFinally { view.refresh = false }

           .subscribeBy(

                       onSuccess = view::show,

                       onError = view::showError

         )

   }

}
```

但棘手的部分是 Marvel API 不允许将空格作为搜索查询。应该发送一个`null`。因此，如果用户删除最后一个字符，或者尝试在搜索字段中只放置空格，那么应用程序将崩溃。我们应该防止这种情况发生。这是一个测试，检查 Presenter 是否将只有空格的查询更改为`null`：

```kt
@Test 
fun `When text is changed, then we are searching for new query`() { 
   for (text in listOf("KKO", "HJ HJ", "And so what?")) 
       assertOnAction { onSearchChanged(text) } 

       searchQueryIsEqualTo text 
} 

@Test 
fun `For blank text, there is request with null query`() { 
   for (emptyText in listOf("", "   ", "       ")) 
       assertOnAction { onSearchChanged(emptyText) } 

       searchQueryIsEqualTo null 
} 

private fun assertOnAction(action: MainPresenter.() -> Unit)  
      = PresenterActionAssertion(action) 

We can implement a security mechanism in the loadCharacters method: 

private fun loadCharacters(searchQuery: String? = null) { 
   val qualifiedSearchQuery = if (searchQuery.isNullOrBlank()) null 

                              else searchQuery 
   subscriptions += repository 
           .getAllCharacters(qualifiedSearchQuery) 
           .applySchedulers() 
           .smartSubscribe( 
                   onStart = { view.refresh = true }, 
                   onSuccess = view::show, 
                   onError = view::showError, 
                   onFinish = { view.refresh = false } 
           ) 
} 
```

现在所有的测试都通过了：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00077.jpg)

我们仍然需要实现一个`Activity`功能，当文本发生变化时将调用 Presenter。我们将使用第七章中定义的可选回调类来实现：

```kt
// TextChangedListener.kt 
package com.sample.marvelgallery.view.common 

import android.text.Editable 
import android.text.TextWatcher 
import android.widget.TextView 

fun TextView.addOnTextChangedListener(config: TextWatcherConfiguration.() -> Unit) { 
   addTextChangedListener(TextWatcherConfiguration().apply { config() }
   addTextChangedListener(textWatcher) 
} 

class TextWatcherConfiguration : TextWatcher { 

   private var beforeTextChangedCallback: 

   (BeforeTextChangedFunction)? = null 
   private var onTextChangedCallback: 

   (OnTextChangedFunction)? = null 
   private var afterTextChangedCallback: 

   (AfterTextChangedFunction)? = null 

   fun beforeTextChanged(callback: BeforeTextChangedFunction) { 
       beforeTextChangedCallback = callback 
   } 

   fun onTextChanged(callback: OnTextChangedFunction) { 
       onTextChangedCallback = callback 
   } 

   fun afterTextChanged(callback: AfterTextChangedFunction) { 
       afterTextChangedCallback = callback 
   } 

   override fun beforeTextChanged(s: CharSequence, 

   start: Int, count: Int, after: Int) { 
       beforeTextChangedCallback?.invoke(s.toString(), 

       start, count, after) 
   } 

   override fun onTextChanged(s: CharSequence, start: Int, 

   before: Int, count: Int) { 
       onTextChangedCallback?.invoke(s.toString(), 

       start, before, count) 
   } 

   override fun afterTextChanged(s: Editable) { 
       afterTextChangedCallback?.invoke(s) 
   } 
} 

private typealias BeforeTextChangedFunction = 

  (text: String, start: Int, count: Int, after: Int) -> Unit 
private typealias OnTextChangedFunction = 

  (text: String, start: Int, before: Int, count: Int) -> Unit 
private typealias AfterTextChangedFunction = 

  (s: Editable) -> Unit 
```

并在`MainActivity`的`onCreate`方法中使用它：

```kt
package com.sample.marvelgallery.view.main 

import android.os.Bundle 
import android.support.v7.widget.GridLayoutManager 
import android.view.Window 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import com.sample.marvelgallery.view.common.BaseActivityWithPresenter 
import com.sample.marvelgallery.view.common.addOnTextChangedListener 
import com.sample.marvelgallery.view.common.bindToSwipeRefresh 
import com.sample.marvelgallery.view.common.toast 
import kotlinx.android.synthetic.main.activity_main.* 

class MainActivity : BaseActivityWithPresenter(), MainView { 

   override var refresh by bindToSwipeRefresh(R.id.swipeRefreshView) 
   override val presenter by lazy 

     { MainPresenter(this, MarvelRepository.get()) } 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       requestWindowFeature(Window.FEATURE_NO_TITLE) 
       setContentView(R.layout.activity_main) 
       recyclerView.layoutManager = GridLayoutManager(this, 2) 
       swipeRefreshView.setOnRefreshListener { presenter.onRefresh() } 
       searchView.addOnTextChangedListener { 
           onTextChanged { text, _, _, _ -> 
               presenter.onSearchChanged(text) 
           } 
       } 
       presenter.onViewCreated() 
   } 

   override fun show(items: List<MarvelCharacter>) { 
       val categoryItemAdapters = items.map(::CharacterItemAdapter) 
       recyclerView.adapter = MainListAdapter(categoryItemAdapters) 
   } 

   override fun showError(error: Throwable) { 
       toast("Error: ${error.message}") 
       error.printStackTrace() 
   } 
} 
```

这就是我们需要定义角色搜索功能的全部内容。现在我们可以构建应用程序并使用它来查找我们喜欢的角色：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00078.jpg)

有了一个正确工作的应用程序，我们可以继续下一个用例。

# 角色概要显示

仅仅通过角色搜索是不够的。为了使应用程序功能正常，我们应该添加角色描述显示。这是我们定义的用例--当用户点击某个角色图片时，会显示一个概要。角色概要包含角色名称、照片、描述和出现次数。

要实现这个用例，我们需要创建一个新的活动和布局，来定义这个`Activity`的外观。为此，在`com.sample.marvelgallery.view.character`包中创建一个名为`CharacterProfileActivity`的新 Activity：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00079.jpg)

我们将从布局更改（在`activity_character_profile.xml`中）开始实现它。这是我们想要实现的最终结果：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00080.jpg)

基本元素是`CoordinatorLayout`，其中`AppBar`和`CollapsingToolbarLayout`都用于实现材料设计中的折叠效果：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00081.jpg)

逐步实现折叠效果。

我们还需要用于描述和出现次数的`TextView`，这些将在下一个用例中填充数据。这是完整的`activity_character_profile`布局定义：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<android.support.design.widget.CoordinatorLayout  

   android:id="@+id/character_detail_layout" 
   android:layout_width="match_parent" 
   android:layout_height="match_parent" 
   android:background="@android:color/white"> 

   <android.support.design.widget.AppBarLayout 
       android:id="@+id/appBarLayout" 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:theme="@style/ThemeOverlay.AppCompat.ActionBar"> 

       <android.support.design.widget.CollapsingToolbarLayout 
           android:id="@+id/toolbarLayout" 
           android:layout_width="match_parent" 
           android:layout_height="match_parent" 
           app:contentScrim="?attr/colorPrimary" 
           app:expandedTitleTextAppearance="@style/ItemTitleName" 
           app:layout_scrollFlags="scroll|exitUntilCollapsed"> 

           <android.support.v7.widget.AppCompatImageView 
               android:id="@+id/headerView" 
               android:layout_width="match_parent" 
               android:layout_height="@dimen/character_header_height" 
               android:background="@color/colorPrimaryDark" 
               app:layout_collapseMode="parallax" /> 

           <android.support.v7.widget.Toolbar 
               android:id="@+id/toolbar" 
               android:layout_width="match_parent" 
               android:layout_height="?attr/actionBarSize" 
               android:background="@android:color/transparent" 
               app:layout_collapseMode="pin" 
               app:popupTheme="@style/ThemeOverlay.AppCompat.Light" /> 

       </android.support.design.widget.CollapsingToolbarLayout> 
   </android.support.design.widget.AppBarLayout> 

   <android.support.v4.widget.NestedScrollView 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" 
       android:overScrollMode="never" 
       app:layout_behavior="@string/appbar_scrolling_view_behavior"> 

       <LinearLayout 
           android:id="@+id/details_content_frame" 
           android:layout_width="match_parent" 
           android:layout_height="match_parent" 
           android:focusableInTouchMode="true" 
           android:orientation="vertical"> 

           <TextView 
               android:id="@+id/descriptionView" 
               android:layout_width="match_parent" 
               android:layout_height="wrap_content" 
               android:gravity="center" 
               android:padding="@dimen/character_description_padding" 
               android:textSize="@dimen/standard_text_size" 
               tools:text="This is some long text that will be visible as an character description." /> 

           <TextView 
               android:id="@+id/occurrencesView" 
               android:layout_width="match_parent" 
               android:layout_height="wrap_content" 
               android:padding="@dimen/character_description_padding" 
               android:textSize="@dimen/standard_text_size" 
               tools:text="He was in following comics:\n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO \n* KOKOKO " /> 
       </LinearLayout> 

   </android.support.v4.widget.NestedScrollView> 

   <TextView 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:layout_gravity="bottom" 
       android:background="@android:color/white" 
       android:gravity="bottom|center" 
       android:text="@string/marvel_copyright_notice" /> 

   <ProgressBar 
       android:id="@+id/progressView" 
       style="?android:attr/progressBarStyleLarge" 
       android:layout_width="wrap_content" 
       android:layout_height="wrap_content" 
       android:layout_gravity="center" 
       android:visibility="gone" /> 

</android.support.design.widget.CoordinatorLayout> 
```

我们还需要在`styles.xml`中添加以下样式：

```kt
<resources> 

   <!-- Base application theme. --> 
   <style name="AppTheme" 

          parent="Theme.AppCompat.Light.DarkActionBar"> 
       <!-- Customize your theme here. --> 
       <item name="colorPrimary">@color/colorPrimary</item> 
       <item name="colorPrimaryDark">@color/colorPrimaryDark</item> 
       <item name="colorAccent">@color/colorAccent</item> 
   </style> 
   <style name="AppFullScreenTheme" 

          parent="Theme.AppCompat.Light.NoActionBar"> 
       <item name="android:windowNoTitle">true</item> 
       <item name="android:windowActionBar">false</item> 
       <item name="android:windowFullscreen">true</item> 
       <item name="android:windowContentOverlay">@null</item> 
   </style> 

   <style name="ItemTitleName" 

          parent="TextAppearance.AppCompat.Headline"> 
       <item name="android:textColor">@android:color/white</item> 
       <item name="android:shadowColor">@color/colorPrimaryDark</item> 
       <item name="android:shadowRadius">3.0</item> 
   </style> 

   <style name="ItemDetailTitle" 

          parent="@style/TextAppearance.AppCompat.Small"> 
       <item name="android:textColor">@color/colorAccent</item> 
   </style> 

</resources> 
```

我们需要在`AndroidManifest`中将`AppFullScreenTheme`定义为`CharacterProfileActivity`的主题：

```kt
<activity android:name=".view.CharacterProfileActivity" 
   android:theme="@style/AppFullScreenTheme" /> 
```

这是定义的布局的预览：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00082.jpg)

这个视图将用于显示有关角色的数据，但首先我们需要从`MainActivity`中打开它。我们需要在`CharacterItemAdapter`中设置`onClickListener`，它调用构造函数提供的`clicked`回调：

```kt
package com.sample.marvelgallery.view.main 

import android.support.v7.widget.RecyclerView 
import android.view.View 
import android.widget.ImageView 
import android.widget.TextView 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.view.common.ItemAdapter 
import com.sample.marvelgallery.view.common.bindView 
import com.sample.marvelgallery.view.common.loadImage 

class CharacterItemAdapter( 
       val character: MarvelCharacter, 
       val clicked: (MarvelCharacter) -> Unit 
) : ItemAdapter<CharacterItemAdapter.ViewHolder>(R.layout.item_character) { 

   override fun onCreateViewHolder(itemView: View) = 

   ViewHolder(itemView) 

   override fun ViewHolder.onBindViewHolder() { 
       textView.text = character.name 
       imageView.loadImage(character.imageUrl) 
       itemView.setOnClickListener { clicked(character) } 
   } 

   class ViewHolder(itemView: View) : 

   RecyclerView.ViewHolder(itemView) { 
       val textView by bindView<TextView>(R.id.textView) 
       val imageView by bindView<ImageView>(R.id.imageView) 
   } 
} 
```

我们需要更新`MainActivity`：

```kt
package com.sample.marvelgallery.view.main 

import android.os.Bundle 
import android.support.v7.widget.GridLayoutManager 
import android.view.Window 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.data.MarvelRepository 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.presenter.MainPresenter 
import com.sample.marvelgallery.view.character.CharacterProfileActivity 
import com.sample.marvelgallery.view.common.BaseActivityWithPresenter 
import com.sample.marvelgallery.view.common.addOnTextChangedListener 
import com.sample.marvelgallery.view.common.bindToSwipeRefresh 
import com.sample.marvelgallery.view.common.toast 
import kotlinx.android.synthetic.main.activity_main.* 

class MainActivity : BaseActivityWithPresenter(), MainView { 

   override var refresh by bindToSwipeRefresh(R.id.swipeRefreshView) 
   override val presenter by lazy

   { MainPresenter(this, MarvelRepository.get()) } 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       requestWindowFeature(Window.FEATURE_NO_TITLE) 
       setContentView(R.layout.activity_main) 
       recyclerView.layoutManager = GridLayoutManager(this, 2) 
       swipeRefreshView.setOnRefreshListener { presenter.onRefresh() } 
       searchView.addOnTextChangedListener { 
           onTextChanged { text, _, _, _ -> 
               presenter.onSearchChanged(text) 
           } 
       } 
       presenter.onViewCreated() 
   } 

   override fun show(items: List<MarvelCharacter>) { 
       val categoryItemAdapters = 

       items.map(this::createCategoryItemAdapter) 
       recyclerView.adapter = MainListAdapter(categoryItemAdapters) 
   } 

   override fun showError(error: Throwable) { 
       toast("Error: ${error.message}") 
       error.printStackTrace() 
   } 

   private fun createCategoryItemAdapter(character: MarvelCharacter) 
           = CharacterItemAdapter(character, 

             { showHeroProfile(character) }) 

   private fun showHeroProfile(character: MarvelCharacter) { 
       CharacterProfileActivity.start(this, character) 
   } 
} 
```

在前面的实现中，我们使用了`CharacterProfileActivity`伴生对象中的一个方法来启动`CharacterProfileActivity`。我们需要将`MarvelCharacter`对象传递给这个方法。传递`MarvelCharacter`对象的最有效方式是将其作为*parcelable*传递。为了允许这样做，`MarvelCharacter`必须实现`Parcelable`接口。这就是为什么一个有用的解决方案是使用一些注解处理库，如**Parceler**，**PaperParcel**或**Smuggler**，来生成必要的元素。我们将使用项目中已经存在的 Kotlin Android 扩展解决方案。在书籍出版时，它仍然是实验性的，因此需要在`build.gradle`模块中添加以下定义：

```kt
androidExtensions {

   experimental = true

}
```

我们需要在类之前添加`Parcelize`注解，并且需要使这个类实现`Parcelable`。我们还需要添加错误抑制，以隐藏默认的 Android 警告：

```kt
package com.sample.marvelgallery.model 

import android.annotation.SuppressLint 
import android.os.Parcelable 
import com.sample.marvelgallery.data.network.dto.CharacterMarvelDto 

import kotlinx.android.parcel.Parcelize

@SuppressLint("ParcelCreator")

@Parcelize

   constructor(dto: CharacterMarvelDto) : this( 
           name = dto.name, 
           imageUrl = dto.imageUrl 
   )
} 
```

现在我们可以实现`start`函数和`character`字段，它将使用属性委托从 Intent 中获取参数值：

```kt
package com.sample.marvelgallery.view.character 

import android.content.Context 
import android.support.v7.app.AppCompatActivity 
import android.os.Bundle 
import android.view.MenuItem 
import com.sample.marvelgallery.R 
import com.sample.marvelgallery.model.MarvelCharacter 
import com.sample.marvelgallery.view.common.extra 
import com.sample.marvelgallery.view.common.getIntent 
import com.sample.marvelgallery.view.common.loadImage 
import kotlinx.android.synthetic.main.activity_character_profile.* 

class CharacterProfileActivity : AppCompatActivity() { 

   val character: MarvelCharacter by extra(CHARACTER_ARG) // 1 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       setContentView(R.layout.activity_character_profile) 
       setUpToolbar() 
       supportActionBar?.title = character.name 
       headerView.loadImage(character.imageUrl, centerCropped = true) // 1 
   } 

   override fun onOptionsItemSelected(item: MenuItem): Boolean = when { 
       item.itemId == android.R.id.home -> onBackPressed().let { true } 
       else -> super.onOptionsItemSelected(item) 
   } 

   private fun setUpToolbar() { 
       setSupportActionBar(toolbar) 
       supportActionBar?.setDisplayHomeAsUpEnabled(true) 
   } 

   companion object { 

       private const val CHARACTER_ARG = "com.sample.marvelgallery.view.character.CharacterProfileActivity.CharacterArgKey" 

       fun start(context: Context, character: MarvelCharacter) { 
           val intent = context 
                   .getIntent<CharacterProfileActivity>() // 1 
                   .apply { putExtra(CHARACTER_ARG, character) } 
           context.startActivity(intent) 
       } 
   } 
} 
```

1.  `extra`和`getIntent`扩展函数已经在书中介绍过，但在项目中尚未实现。此外，`loadImage`将显示错误，因为它需要更改。

我们需要更新`loadImage`，并将`extra`和`getIntent`定义为顶级函数：

```kt
// ViewExt.kt 
package com.sample.marvelgallery.view.common 

import android.app.Activity 
import android.content.Context 
import android.content.Intent 
import android.os.Parcelable 
import android.support.annotation.IdRes 
import android.support.v4.widget.SwipeRefreshLayout 
import android.widget.ImageView 
import android.widget.Toast 
import com.bumptech.glide.Glide 
import kotlin.properties.ReadWriteProperty 
import kotlin.reflect.KProperty 
import android.support.v7.widget.RecyclerView 
import android.view.View 

fun <T : View> RecyclerView.ViewHolder.bindView(viewId: Int)  
      = lazy { itemView.findViewById<T>(viewId) } 

fun ImageView.loadImage(photoUrl: String, centerCropped: Boolean = false) { 
   Glide.with(context) 
           .load(photoUrl) 
           .apply { if (centerCropped) centerCrop() } 
           .into(this) 
} 

fun <T : Parcelable> Activity.extra(key: String, default: T? = null): Lazy<T>  
      = lazy { intent?.extras?.getParcelable<T>(key) ?: default ?: throw Error("No value $key in extras") } 

inline fun <reified T : Activity> Context.getIntent() = Intent(this, T::class.java) 

// ...
```

我们可以使用一些库来生成这些方法，而不是定义启动 Activity 的函数。例如，我们可以使用`ActivityStarter`库。这就是`CharacterProfileActivity`将会是什么样子：

```kt
class CharacterProfileActivity : AppCompatActivity() { 

   @get:Arg val character: MarvelCharacter by argExtra() 

   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       setContentView(R.layout.activity_character_profile) 
       setUpToolbar() 
       supportActionBar?.title = character.name 
       headerView.loadImage(character.imageUrl, centerCropped = true) // 1 
   } 

   override fun onOptionsItemSelected(item: MenuItem): Boolean = when { 
       item.itemId == android.R.id.home -> onBackPressed().let { true } 
       else -> super.onOptionsItemSelected(item) 
   } 

   private fun setUpToolbar() { 
       setSupportActionBar(toolbar) 
       supportActionBar?.setDisplayHomeAsUpEnabled(true) 
   } 
} 
```

我们应该启动它或使用生成的类`CharacterProfileActivityStarter`的静态方法获取其 Intent：

```kt
CharacterProfileActivityStarter.start(context, character) 
val intent = CharacterProfileActivityStarter.getIntent(context, character) 
```

为了允许它，我们需要在模块`build.gradle`中使用**kapt**插件（用于支持 Kotlin 中的注解处理）：

```kt
apply plugin: 'kotlin-kapt' 
```

在`build.gradle`模块中的`ActivityStarter`依赖项：

```kt
implementation 'com.github.marcinmoskala.activitystarter:activitystarter:1.00' 
implementation 'com.github.marcinmoskala.activitystarter:activitystarter-kotlin:1.00' 
kapt 'com.github.marcinmoskala.activitystarter:activitystarter-compiler:1.00' 
```

经过这些更改，当我们点击`MainActivity`中的角色时，`CharacterProfileActivity`将会启动：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00083.jpg)

我们正在显示名称并展示角色照片。下一步是显示描述和事件列表。所需的数据可以在 Marvel API 中找到，我们只需要扩展 DTO 模型来获取它们。我们需要添加`ListWrapper`来保存列表：

```kt
package com.sample.marvelgallery.data.network.dto 

class ListWrapper<T> { 
   var items: List<T> = listOf() 
} 
```

我们需要定义`ComicDto`，其中包含有关事件发生的数据：

```kt
package com.sample.marvelgallery.data.network.dto 

class ComicDto { 
   lateinit var name: String 
} 
```

我们需要更新`CharacterMarvelDto`：

```kt
package com.sample.marvelgallery.data.network.dto 

class CharacterMarvelDto { 

   lateinit var name: String 
   lateinit var description: String 
   lateinit var thumbnail: ImageDto 
   var comics: ListWrapper<ComicDto> = ListWrapper() 
   var series: ListWrapper<ComicDto> = ListWrapper() 
   var stories: ListWrapper<ComicDto> = ListWrapper() 
   var events: ListWrapper<ComicDto> = ListWrapper() 

   val imageUrl: String 
       get() = thumbnail.completeImagePath 
} 
```

现在从 API 中读取数据并保存在 DTO 对象中，但为了在项目中使用它们，我们还需要更改`MarvelCharacter`类的定义，并添加一个新的构造函数：

```kt
@SuppressLint("ParcelCreator")

@Parcelize

class MarvelCharacter( 
       val name: String, 
       val imageUrl: String, 
       val description: String, 
       val comics: List<String>, 
       val series: List<String>, 
       val stories: List<String>, 
       val events: List<String> 
) : Parcelable { 

   constructor(dto: CharacterMarvelDto) : this( 
           name = dto.name, 
           imageUrl = dto.imageUrl, 
           description = dto.description, 
           comics = dto.comics.items.map { it.name }, 
           series = dto.series.items.map { it.name }, 
           stories = dto.stories.items.map { it.name }, 
           events = dto.events.items.map { it.name } 
   ) 
} 
```

现在我们可以更新`CharacterProfileActivity`来显示描述和事件列表：

```kt
class CharacterProfileActivity : AppCompatActivity() { 

   val character: MarvelCharacter by extra(CHARACTER_ARG) 
   override fun onCreate(savedInstanceState: Bundle?) { 
       super.onCreate(savedInstanceState) 
       setContentView(R.layout.activity_character_profile) 
       setUpToolbar() 
       supportActionBar?.title = character.name 
       descriptionView.text = character.description 
       occurrencesView.text = makeOccurrencesText() // 1 
       headerView.loadImage(character.imageUrl, centerCropped = true) 
   } 

   override fun onOptionsItemSelected(item: MenuItem): Boolean = when { 
       item.itemId == android.R.id.home -> onBackPressed().let { true } 
       else -> super.onOptionsItemSelected(item) 
   } 

   private fun setUpToolbar() { 
       setSupportActionBar(toolbar) 
       supportActionBar?.setDisplayHomeAsUpEnabled(true) 
   } 

   private fun makeOccurrencesText(): String = "" // 1, 2 
           .addList(R.string.occurrences_comics_list_introduction, character.comics) 
           .addList(R.string.occurrences_series_list_introduction, character.series) 
           .addList(R.string.occurrences_stories_list_introduction, character.stories) 
           .addList(R.string.occurrences_events_list_introduction, character.events) 

   private fun String.addList(introductionTextId: Int, list: List<String>): String { // 3 
       if (list.isEmpty()) return this 
       val introductionText = getString(introductionTextId) 
       val listText = list.joinToString(transform = 

           { " $bullet $it" }, separator = "\n") 
       return this + "$introductionText\n$listText\n\n" 
   } 

   companion object { 
       private const val bullet = '\u2022' // 4 
       private const val CHARACTER_ARG = "com.naxtlevelofandroiddevelopment.marvelgallery.presentation.heroprofile.CharacterArgKey" 

       fun start(context: Context, character: MarvelCharacter) { 
           val intent = context 
                   .getIntent<CharacterProfileActivity>() 
                   .apply { putExtra(CHARACTER_ARG, character) } 
           context.startActivity(intent) 
       } 
   } 
}
```

1.  出现列表的组合是一个相当复杂的任务，因此我们将其提取到函数`makeOccurrencesText`中。在那里，对于每种出现类型（漫画、系列等），我们希望在有这种类型的出现时显示介绍文本和列表。我们还希望在每个项目前加上一个项目符号。

1.  `makeOccurrencesText`是一个单表达式函数，它使用`addList`来将初始空字符串附加上我们想要显示的下一个列表。

1.  `addList`是一个成员扩展函数。如果提供的列表为空，则返回一个未更改的字符串，或者返回一个附加了介绍文本和带有项目列表的字符串。

1.  这是用作列表项目符号的角色。

我们还需要在`strings.xml`中定义字符串：

```kt
<resources> 
   <string name="app_name">Marvel Gallery</string> 
   <string name="marvel_copyright_notice">

       Data provided by Marvel. © 2017 MARVEL</string> 
   <string name="search_hint">Search for character</string> 
   <string name="occurrences_comics_list_introduction">Comics:</string> 
   <string name="occurrences_series_list_introduction">Series:</string> 
   <string name="occurrences_stories_list_introduction">Stories:</string> 
   <string name="occurrences_events_list_introduction">Events:</string> 
</resources> 
```

现在我们可以看到整个角色资料--角色名称、图片、描述以及在漫画、系列、事件和故事中的出现列表：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-dev-kt/img/Image00084.jpg)

# 摘要

应用程序已经完成，但仍然可以添加许多功能。在这个应用程序中，我们看到了 Kotlin 如何简化 Android 开发的一些示例。但仍然有很多解决方案等待发现。Kotlin 简化了 Android 开发的任何层次--从常见操作，如监听器设置或视图元素引用，到高级功能，如函数式编程或集合处理。

这本书无法涵盖关于 Kotlin 的 Android 开发的所有内容。它旨在展示足够的内容，以便每个人都可以开始自己的冒险，拥有充满想法和功能理解的行囊。下一步是打开 Android Studio，创建自己的项目，并开始享受 Kotlin 带来的乐趣。大冒险就在你面前。
