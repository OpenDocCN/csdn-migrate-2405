# Java9 和 JShell（二）

> 原文：[`zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53`](https://zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：数据的封装

在本章中，我们将学习 Java 9 中类的不同成员以及它们如何在从类生成的实例的成员中反映出来。我们将使用实例字段、类字段、setter、getter、实例方法和类方法。我们将：

+   理解 Java 9 中组成类的成员

+   声明不可变字段

+   使用 setter 和 getter

+   在 Java 9 中理解访问修饰符

+   结合 setter、getter 和相关字段

+   使用 setter 和 getter 转换值

+   使用静态字段和静态方法来创建所有类实例共享的值

# 理解组成类的成员

到目前为止，我们一直在使用一个非常简单的`Rectangle`类。我们在 JShell 中创建了许多这个类的实例，并且理解了垃圾回收的工作原理。现在，是时候深入了解 Java 9 中组成类的不同成员了。

以下列表列举了我们可以在 Java 9 类定义中包含的最常见元素类型。每个成员都包括其在其他编程语言中的等价物，以便于将我们在其他面向对象语言中的经验转化为 Java 9。我们已经使用了其中的一些成员：

+   **构造函数**：一个类可能定义一个或多个构造函数。它们等价于其他编程语言中的初始化器。

+   **类变量或类字段**：这些变量对类的所有实例都是共同的，也就是说，它们的值对所有实例都是相同的。在 Java 9 中，可以从类和其实例中访问类变量。我们不需要创建特定实例来访问类变量。类变量也被称为静态变量，因为它们在声明中使用`static`修饰符。类变量等价于其他编程语言中的类属性和类型属性。

+   **类方法**：这些方法可以使用类名调用。在 Java 9 中，可以从类和其实例中访问类方法。我们不需要创建特定实例来访问类方法。类方法也被称为静态方法，因为它们在声明中使用`static`修饰符。类方法等价于其他编程语言中的类函数和类型方法。类方法作用于整个类，并且可以访问类变量、类常量和其他类方法，但它们无法访问任何实例成员，如实例字段或方法，因为它们在类级别上操作，根本没有实例。当我们想要包含与类相关的方法并且不想生成实例来调用它们时，类方法非常有用。

+   **常量**：当我们用`final`修饰符声明类变量或类字段时，我们定义了值不可更改的常量。

+   **字段、成员变量、实例变量或实例字段**：我们在之前的例子中使用了这些。类的每个实例都有自己独特的实例字段副本，具有自己的值。实例字段等价于其他编程语言中的属性和实例属性。

+   **方法或实例方法**：这些方法需要一个实例来调用，并且它们可以访问特定实例的字段。实例方法等价于其他编程语言中的实例函数。

+   **嵌套类**：这些类在另一个类中定义。静态嵌套类使用`static`修饰符。不使用`static`修饰符的嵌套类也被称为**内部类**。嵌套类在其他编程语言中也被称为嵌套类型。

# 声明不可变字段

Pokemon Go 是一款基于位置的增强现实游戏，玩家使用移动设备的 GPS 功能来定位、捕捉、训练和让虚拟生物进行战斗。这款游戏取得了巨大的成功，并推广了基于位置和增强现实的游戏。在其巨大成功之后，想象一下我们必须开发一个 Web 服务，供类似的游戏使用，让虚拟生物进行战斗。

我们必须进入虚拟生物的世界。我们肯定会有一个`VirtualCreature`基类。每种特定类型的虚拟生物都具有独特的特征，可以参与战斗，将是`VirtualCreature`的子类。

所有虚拟生物都将有一个名字，并且它们将在特定年份出生。年龄对于它们在战斗中的表现将非常重要。因此，我们的基类将拥有`name`和`birthYear`字段，所有子类都将继承这些字段。

当我们设计类时，我们希望确保所有必要的数据对将操作这些数据的方法是可用的。因此，我们封装数据。然而，我们只希望相关信息对我们的类的用户可见，这些用户将创建实例，更改可访问字段的值，并调用可用的方法。我们希望隐藏或保护一些仅需要内部使用的数据，也就是说，对于我们的方法。我们不希望对敏感数据进行意外更改。

例如，当我们创建任何虚拟生物的新实例时，我们可以将其名字和出生年份作为构造函数的两个参数。构造函数初始化了两个属性的值：`name`和`birthYear`。以下几行显示了声明`VirtualCreature`类的示例代码。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_01.java`文件中。

```java
class VirtualCreature {
    String name;
    int birthYear;

    VirtualCreature(String name, int birthYear) {
        this.name = name;
        this.birthYear = birthYear;
    }
}
```

接下来的几行创建了两个实例，初始化了两个字段的值，然后使用`System.out.printf`方法在 JShell 中显示它们的值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_01.java`文件中。

```java
VirtualCreature beedrill = new VirtualCreature("Beedril", 2014);
System.out.printf("%s\n", beedrill.name);
System.out.printf("%d\n", beedrill.birthYear);
VirtualCreature krabby = new VirtualCreature("Krabby", 2012);
System.out.printf("%s\n", krabby.name);
System.out.printf("%d\n", krabby.birthYear);
```

以下屏幕截图显示了在 JShell 中声明类和执行先前行的结果：

![声明不可变字段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00045.jpeg)

我们不希望`VirtualCreature`类的用户能够在初始化实例后更改虚拟生物的名字，因为名字不应该改变。好吧，有些人改名字，但虚拟生物永远不会这样做。在我们之前声明的类中，有一种简单的方法可以实现这个目标。我们可以在类型（`String`）之前添加`final`关键字，以定义一个不可变的`name`字段，类型为`String`。当我们定义`birthYear`字段时，也可以在类型（`int`）之前添加`final`关键字，因为在初始化虚拟生物实例后，出生年份将永远不会改变。

以下几行显示了声明`VirtualCreature`类的新代码，其中包含两个不可变的实例字段：`name`和`birthYear`。请注意，构造函数的代码不需要更改，并且可以使用相同的代码初始化这两个不可变的实例字段。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_02.java`文件中。

```java
class VirtualCreature {
 final String name;
 final int birthYear;

    VirtualCreature(String name, int birthYear) {
        this.name = name;
        this.birthYear = birthYear;
    }
}
```

### 注意

不可变的实例字段也被称为非变异的实例字段。

接下来的几行创建了一个实例，初始化了两个不可变的实例字段的值，然后使用`System.out.printf`方法在 JShell 中显示它们的值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_02.java`文件中。

```java
VirtualCreature squirtle = new VirtualCreature("Squirtle", 2014);
System.out.printf("%s\n", squirtle.name);
System.out.printf("%d\n", squirtle.birthYear);
```

接下来的两行代码尝试为`name`和`birthYear`不可变的实例字段分配新值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_03.java`文件中。

```java
squirtle.name = "Tentacruel";
squirtle.birthYear = 2017;
```

这两行将无法成功，因为 Java 不允许我们为使用`final`修饰符声明的字段赋值，这会将其转换为不可变字段。下一张截图显示了在每行尝试为不可变字段设置新值后在 JShell 中显示的错误：

![声明不可变字段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00046.jpeg)

### 提示

当我们使用`final`关键字声明一个实例字段时，我们可以初始化该字段，但在初始化后，它将变为不可变的，也就是常量。

# 使用 setter 和 getter

到目前为止，我们一直在使用字段来封装实例中的数据。我们可以像实例的成员变量一样访问这些字段，没有任何限制。然而，有时在现实世界的情况下，需要限制以避免严重问题。有时，我们希望限制访问或将特定字段转换为只读字段。我们可以将对底层字段的访问限制与称为 setter 和 getter 的方法相结合。

**Setter**是允许我们控制如何设置值的方法；也就是说，这些方法用于改变相关字段的值。**Getter**允许我们控制在想要检索相关字段的值时返回的值。Getter 不会改变相关字段的值。

### 提示

有些框架（比如 JavaBeans）强制你使用 setter 和 getter 来让每个相关字段都可以访问，但在其他情况下，setter 和 getter 是不必要的。在接下来的例子中，我们将使用可变对象。在下一章，第五章，“可变和不可变类”，我们将同时使用可变和不可变对象。当使用不可变对象时，getter 和 setter 是无用的。

如前所述，我们不希望`VirtualCreature`类的用户能够在初始化实例后更改虚拟生物的出生年份，因为虚拟生物不会在不同日期再次出生。实际上，我们希望计算并使虚拟生物的年龄对用户可用。因为我们只考虑出生年份，所以我们将计算一个近似的年龄。我们保持示例简单，以便专注于 getter 和 setter。

我们可以定义一个名为`getAge`的 getter 方法，而不定义 setter 方法。这样，我们可以检索虚拟生物的年龄，但我们无法改变它，因为没有 setter 方法。getter 方法返回基于当前年份和`birthYear`不可变实例字段的值计算出的虚拟生物年龄的结果。

下面的行显示了具有新`getAge`方法的`VirtualCreature`类的新版本。请注意，需要导入`java.time.Year`以使用在 Java 8 中引入的`Year`类。`getAge`方法的代码在下面的行中突出显示。该方法调用`Year.now().getValue`来检索当前日期的年份组件，并返回当前年份与`birthYear`字段的值之间的差值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中，名为`example04_04.java`。

```java
import java.time.Year;

class VirtualCreature {
    final String name;
    final int birthYear;

    VirtualCreature(String name, int birthYear) {
        this.name = name;
        this.birthYear = birthYear;
    }

 int getAge() {
 return Year.now().getValue() - birthYear;
 }
}
```

下面的行创建一个实例，初始化了两个不可变实例字段的值，然后使用`System.out.printf`方法在 JShell 中显示`getAge`方法返回的值。在创建`VirtualCreature`类的新版本的代码之后输入这些行。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中，名为`example04_04.java`。 

```java
VirtualCreature arbok = new VirtualCreature("Arbok", 2008);
System.out.printf("%d\n", arbok.getAge());
VirtualCreature pidgey = new VirtualCreature("Pidgey", 2015);
System.out.printf("%d\n", pidgey.getAge());
```

下一张截图显示了在 JShell 中执行前面几行的结果：

![使用 setter 和 getter](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00047.jpeg)

在与虚拟生物专家的几次会议后，我们意识到其中一些虚拟生物会前往其他星球进化，并在进化后从蛋中再次诞生。由于进化发生在不同的星球，虚拟生物的出生年份会改变，以在地球上具有等效的出生年份。因此，有必要允许用户自定义虚拟生物的年龄或出生年份。我们将添加一个带有计算出生年份的代码的 setter 方法，并将这个值分配给`birthYear`字段。首先，我们必须在声明`birthYear`字段时删除`final`关键字，因为我们希望它成为一个可变字段。

### 提示

还有另一种处理虚拟生物进化的方法。我们可以创建另一个实例来代表进化后的虚拟生物。我们将在下一章第五章中使用这种不可变的方法，*可变和不可变的类*。在这种情况下，我们将使用一个可变对象。在了解所有可能性之后，我们可以根据我们的具体需求决定最佳选项。

下面的代码展示了带有新`setAge`方法的`VirtualCreature`类的新版本。`setAge`方法的代码在下面的代码中突出显示。该方法接收我们想要为虚拟生物设置的新年龄，并调用`Year.now().getValue`来获取当前日期的年份组件，并将当前年份与`age`参数中接收到的值之间的差值分配给`birthYear`字段。这样，`birthYear`字段将根据接收到的`age`值保存虚拟生物出生的年份。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_05.java`文件中。

```java
import java.time.Year;

class VirtualCreature {
    final String name;
 int birthYear;

    VirtualCreature(String name, int birthYear) {
        this.name = name;
        this.birthYear = birthYear;
    }

    int getAge() {
        return Year.now().getValue() - birthYear;
    }

 void setAge(final int age) {
 birthYear = Year.now().getValue() - age;
 }
}
```

下面的代码创建了`VirtualCreature`类的新版本的两个实例，调用`setAge`方法并为虚拟生物设置所需的年龄，然后使用`System.out.printf`方法在 JShell 中显示`getAge`方法返回的值和`birthYear`字段的值。在创建`VirtualCreature`类的新版本的代码之后输入这些代码。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_05.java`文件中。

```java
VirtualCreature venusaur = new VirtualCreature("Venusaur", 2000);
System.out.printf("%d\n", venusaur.getAge());
VirtualCreature caterpie = new VirtualCreature("Caterpie", 2012);
System.out.printf("%d\n", caterpie.getAge());

venusaur.setAge(2);
System.out.printf("%d\n", venusaur.getAge());
System.out.printf("%d\n", venusaur.birthYear);

venusaur.setAge(14);
System.out.printf("%d\n", caterpie.getAge());
System.out.printf("%d\n", caterpie.birthYear);
```

调用`setAge`方法并传入新的年龄值后，该方法会改变`birthYear`字段的值。根据当前年份的值，运行代码的结果将会不同。下一张截图显示了在 JShell 中执行前几行代码的结果：

![使用 setter 和 getter](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00048.jpeg)

getter 和 setter 方法都使用相同的代码来获取当前年份。我们可以添加一个新的方法来获取当前年份，并从`getAge`和`setAge`方法中调用它。在这种情况下，这只是一行代码，但是新方法为我们提供了一个示例，说明我们可以添加方法来在我们的类中使用，并帮助其他方法完成它们的工作。稍后，我们将学习如何避免从实例中调用这些方法，因为它们只用于内部使用。

下面的代码展示了带有新`getCurrentYear`方法的`SuperHero`类的新版本。`getAge`和`setAge`方法的新代码调用了新的`getCurrentYear`方法，而不是重复用于获取当前年份的代码。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_06.java`文件中。

```java
import java.time.Year;

class VirtualCreature {
    final String name;
    int birthYear;

    VirtualCreature(String name, int birthYear) {
        this.name = name;
        this.birthYear = birthYear;
    }

 int getCurrentYear() {
 return Year.now().getValue();
 }

    int getAge() {
 return getCurrentYear() - birthYear;
    }

    void setAge(final int age) {
 birthYear = getCurrentYear() - age;
    }
}
```

下面的代码创建了`VirtualCreature`类的两个实例，调用`setAge`方法设置虚拟生物的年龄，然后使用`System.out.printf`方法在 JShell 中显示`getAge`方法返回的值和`birthYear`字段的值。在创建`VirtualCreature`类的新版本的代码之后输入这些行。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_06.java`文件中。

```java
VirtualCreature persian = new VirtualCreature("Persian", 2005);
System.out.printf("%d\n", persian.getAge());
VirtualCreature arcanine = new VirtualCreature("Arcanine", 2012);
System.out.printf("%d\n", arcanine.getAge());

persian.setAge(7);
System.out.printf("%d\n", persian.getAge());
System.out.printf("%d\n", persian.birthYear);

arcanine.setAge(9);
System.out.printf("%d\n", arcanine.getAge());
System.out.printf("%d\n", arcanine.birthYear);
```

下一张截图显示了在 JShell 中执行前面几行的结果：

![使用 setter 和 getter](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00049.jpeg)

## 在 Java 9 中探索访问修饰符

先前声明的`VirtualCreature`类公开了所有成员（字段和方法），没有任何限制，因为我们声明它们时没有使用任何访问修饰符。因此，我们的类的用户可以在创建类的实例后访问任何字段并调用任何已声明的方法。

Java 9 允许我们通过使用访问级别修饰符来控制对调用成员的访问。不同的关键字允许我们控制哪些代码可以访问类的特定成员。到目前为止，我们可以在类定义内部和类声明之外访问字段和方法。

我们可以使用以下任何访问修饰符来限制对任何字段的访问，而不是`public`：

+   `protected`：Java 不允许用户在类定义之外访问成员。只有类内部或其派生类的代码才能访问字段。声明了带有`protected`访问修饰符的成员的类的任何子类都可以访问该成员。

+   `private`：Java 不允许用户在类定义之外访问字段。只有类内部的代码才能访问字段。它的派生类无法访问字段。因此，声明了带有`private`访问修饰符的成员的类的任何子类将无法访问该成员。

下一行显示了如何将`birthYear`实例字段的声明更改为`protected`字段。我们只需要在字段声明中添加`protected`关键字。

```java
protected int birthYear;
```

每当我们在字段声明中使用`protected`访问修饰符时，我们限制对该字段的访问仅限于类定义内部和子类内部编写的代码。Java 9 为标记为`protected`的字段生成了真正的保护，没有办法在解释的边界之外访问它们。

下一行显示了如何将`birthYear`受保护的实例字段的声明更改为`private`字段。我们用`private`替换了`protected`访问修饰符。

```java
private int birthYear;
```

每当我们在字段声明中使用`private`访问修饰符时，我们限制对该字段的访问仅限于类定义内部和子类内部编写的代码。Java 为标记为`private`的字段生成了真正的保护，没有办法在类定义之外访问它们。这个限制也适用于子类，因此，只有类内部编写的代码才能访问标记为私有的属性。

### 提示

我们可以对任何类型成员应用先前解释的访问修饰符，包括类变量、类方法、常量、字段、方法和嵌套类。

# 结合 setter、getter 和字段

有时，我们希望对设置到相关字段和从中检索的值有更多的控制，并且我们可以利用 getter 和 setter 来做到这一点。我们可以结合使用 getter、setter、存储计算值的相关字段以及访问保护机制，防止用户对相关字段进行更改。这样，我们将强制用户始终使用 getter 和 setter。

虚拟生物喜欢任何类型的帽子。虚拟生物的帽子可以随着时间改变。我们必须确保帽子的名称是大写字母，也就是大写的`String`。我们将定义一个`setHat`方法，始终从接收到的`String`生成一个大写的`String`并将其存储在私有的`hat`字段中。

我们将提供一个`getHat`方法来检索存储在私有`hat`字段中的值。下面的几行显示了`VirtualCreature`类的新版本，其中添加了一个`hat`私有实例字段和`getHat`和`setHat`方法。我们使用之前学到的访问修饰符来为类的不同成员设置。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中，名为`example04_07.java`。

```java
import java.time.Year;

public class VirtualCreature {
    public final String name;
    private int birthYear;
    private String hat = "NONE";

    VirtualCreature(String name, int birthYear, String hat) {
        this.name = name;
        this.birthYear = birthYear;
        setHat(hat);
    }

    private int getCurrentYear() {
        return Year.now().getValue();
    }

    public int getAge() {
        return getCurrentYear() - birthYear;
    }

    public void setAge(final int age) {
        birthYear = getCurrentYear() - age;
    }

    public String getHat() {
        return hat;
    }

    public void setHat(final String hat) {
        this.hat = hat.toUpperCase();
    }
}
```

如果你使用特定的 JDK 早期版本，在 JShell 中输入前面的代码时，你可能会看到以下警告消息：

```java
|  Warning:
|  Modifier 'public'  not permitted in top-level declarations, ignored
|  public class VirtualCreature {
|  ^----^
|  created class VirtualCreature this error is corrected:
|      Modifier 'public'  not permitted in top-level declarations, ignored
|      public class VirtualCreature {
|      ^----^

```

JShell 不允许我们在顶层声明中使用访问修饰符，比如类声明。然而，我们指定访问修饰符是因为我们希望编写的代码就好像我们是在 JShell 之外编写类声明一样。JShell 只是忽略了类的`public`访问修饰符，而一些包含 JShell 的 JDK 版本会在 REPL 中显示先前显示的警告消息。如果你看到这些消息，你应该升级已安装的 JDK 到不再显示警告消息的最新版本。

我们将`birthyear`和`hat`实例字段都声明为`private`。我们将`getCurrentYear`方法声明为`protected`。当用户创建`VirtualCreature`类的实例时，用户将无法访问这些`private`成员。这样，`private`成员将对创建`VirtualCreature`类实例的用户隐藏起来。

我们将`name`声明为`public`的不可变实例字段。我们将以下方法声明为`public`：`getAge`、`setAge`、`getHat`和`setHat`。当用户创建`VirtualCreature`类的实例时，他将能够访问所有这些`public`成员。

构造函数添加了一个新的参数，为新的`hat`字段提供了一个初始值。构造函数中的代码调用`setHat`方法，将接收到的`hat`参数作为参数，以确保从接收到的`String`生成一个大写的`String`，并将生成的`String`分配给`hat`字段。

下面的几行创建了`VirtualCreature`类的两个实例，使用`printf`方法显示`getHat`方法返回的值，调用`setHat`方法设置虚拟生物的新帽子，然后使用`System.out.printf`方法再次显示`getHat`方法返回的值。在创建`VirtualCreature`类的新版本的代码之后输入这些行。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中，名为`example04_07.java`。

```java
VirtualCreature glaceon = 
    new VirtualCreature("Glaceon", 2009, "Baseball cap");
System.out.printf(glaceon.getHat());
glaceon.setHat("Hard hat")
System.out.printf(glaceon.getHat());
VirtualCreature gliscor = 
    new VirtualCreature("Gliscor", 2015, "Cowboy hat");
System.out.printf(gliscor.getHat());
gliscor.setHat("Panama hat")
System.out.printf(gliscor.getHat());
```

下一张截图显示了在 JShell 中执行前面几行的结果：

![组合 setter、getter 和字段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00050.jpeg)

### 提示

我们可以结合 getter 和 setter 方法，以及访问保护机制和作为底层字段的相关字段，来绝对控制可变对象中的值如何被设置和检索。然而，我们必须确保初始化也必须使用 setter 方法，就像我们在构造函数中设置初始值时所做的那样。

下面的几行将尝试访问我们创建的`VirtualCreature`类实例的私有字段和私有方法。这两行都将无法编译，因为我们不能在实例中访问私有成员。第一行尝试访问`hat`实例字段，第二行尝试调用`getCurrentYear`实例方法。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中，名为`example04_08.java`。

```java
System.out.printf(gliscor.hat);
System.out.printf("%d", glaceon.getCurrentYear());
```

下一个屏幕截图显示了在 JShell 中执行前面几行时生成的错误消息。

![结合 setter、getter 和字段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00051.jpeg)

# 使用 setter 和 getter 转换值

我们可以定义一个 setter 方法，将接收到的值转换为相关字段的有效值。getter 方法只需要返回相关字段的值。用户只能使用 setter 和 getter 方法，我们的相关字段将始终具有有效值。这样，我们可以确保每当需要该值时，我们将检索到有效的值。

每个虚拟生物都有一个可见级别，确定任何人能够多容易地看到虚拟生物的身体。我们将添加一个私有的`visibilityLevel`字段，一个`setVisibility`方法和一个`getVisibility`方法。我们将更改构造函数代码，调用`setVisiblity`方法来为`visibilityLevel`字段设置初始值。

我们希望确保可见级别是一个从`0`到`100`（包括）的数字。因此，我们将编写 setter 方法来将低于`0`的值转换为`0`，将高于`100`的值转换为`100`。`setVisibility`方法保存相关私有`visibilityLevel`字段中的转换后或原始值，该值在有效范围内。

编辑过的行和新行已经高亮显示。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_09.java`文件中。

```java
import java.time.Year;

public class VirtualCreature {
    public final String name;
    private int birthYear;
    private String hat = "NONE";
 private int visibilityLevel;

 VirtualCreature(String name, 
 int birthYear, 
 String hat, 
 int visibilityLevel) {
        this.name = name;
        this.birthYear = birthYear;
        setHat(hat);
 setVisibilityLevel(visibilityLevel);
    }

    private int getCurrentYear() {
        return Year.now().getValue();
    }

    public int getAge() {
        return getCurrentYear() - birthYear;
    }

    public void setAge(final int age) {
        birthYear = getCurrentYear() - age;
    }

    public String getHat() {
        return hat;
    }

    public void setHat(final String hat) {
        this.hat = hat.toUpperCase();
    }

    public int getVisibilityLevel() {
        return visibilityLevel;
    }

 public void setVisibilityLevel(final int visibilityLevel) {
 this.visibilityLevel = 
 Math.min(Math.max(visibilityLevel, 0), 100);
 }
}
```

下面的行创建了一个`VirtualCreature`的实例，指定`150`作为`visibilityLevel`参数的值。然后，下一行使用`System.out.printf`方法在 JShell 中显示`getVisibilityLevel`方法返回的值。然后，我们调用`setVisibilityLevel`和`getVisibilityLevel`三次，设置`visibilityLevel`的值，然后检查最终设置的值。在创建`VirtualCreature`类的新版本的代码之后输入这些行。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_09.java`文件中。

```java
VirtualCreature lairon = 
    new VirtualCreature("Lairon", 2014, "Sombrero", 150);
System.out.printf("%d", lairon.getVisibilityLevel());
lairon.setVisibilityLevel(-6);
System.out.printf("%d", lairon.getVisibilityLevel());
lairon.setVisibilityLevel(320);
System.out.printf("%d", lairon.getVisibilityLevel());
lairon.setVisibilityLevel(25);
System.out.printf("%d", lairon.getVisibilityLevel());
```

构造函数调用`setVisibilityLevel`方法来为`visibilityLevel`相关的私有字段设置初始值，因此，该方法确保值在有效范围内。代码指定了`150`，但最大值是`100`，因此`setVisibilityLevel`将`100`分配给了`visibilityLevel`相关的私有字段。

在我们使用`-6`作为参数调用`setVisibilityLevel`后，我们打印了`getVisibilityLevel`返回的值，结果是`0`。在我们指定`320`后，实际打印的值是`100`。最后，在我们指定`25`后，实际打印的值是`25`。下一个屏幕截图显示了在 JShell 中执行前面几行的结果：

![使用 setter 和 getter 转换值](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00052.jpeg)

# 使用静态字段提供类级别的值

有时，类的所有成员共享相同的属性，我们不需要为每个实例设置特定的值。例如，虚拟生物类型具有以下配置值：

+   攻击力

+   防御力

+   特殊攻击力

+   特殊防御力

+   平均速度

+   捕捉率

+   增长率

对于这种情况，我们可能认为有用的第一种方法是定义以下类常量来存储所有实例共享的值：

+   `ATTACK_POWER`

+   `DEFENSE_POWER`

+   `SPECIAL_ATTACK_POWER`

+   `SPECIAL_DEFENSE_POWER`

+   `AVERAGE_SPEED`

+   `CATCH_RATE`

+   `GROWTH_RATE`

### 注意

请注意，在 Java 9 中，类常量名称使用大写字母和下划线（`_`）分隔单词。这是一种命名约定。

以下行显示了`VirtualCreature`类的新版本，该版本使用`public`访问修饰符定义了先前列出的七个类常量。请注意，`final`和`static`关键字的组合使它们成为类常量。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_10.java`文件中。

```java
import java.time.Year;

public class VirtualCreature {
 public final static int ATTACK_POWER = 45;
 public final static int DEFENSE_POWER = 85;
 public final static int SPECIAL_ATTACK_POWER = 35;
 public final static int SPECIAL_DEFENSE_POWER = 95;
 public final static int AVERAGE_SPEED = 85;
 public final static int CATCH_RATE = 25;
 public final static int GROWTH_RATE = 10;

    public final String name;
    private int birthYear;
    private String hat = "NONE";
    private int visibilityLevel;

    VirtualCreature(String name, 
        int birthYear, 
        String hat, 
        int visibilityLevel) {
        this.name = name;
        this.birthYear = birthYear;
        setHat(hat);
        setVisibilityLevel(visibilityLevel);
    }

    private int getCurrentYear() {
        return Year.now().getValue();
    }

    public int getAge() {
        return getCurrentYear() - birthYear;
    }

    public void setAge(final int age) {
        birthYear = getCurrentYear() - age;
    }

    public String getHat() {
        return hat;
    }

    public void setHat(final String hat) {
        this.hat = hat.toUpperCase();
    }

    public int getVisibilityLevel() {
        return visibilityLevel;
    }

    public void setVisibilityLevel(final int visibilityLevel) {
        this.visibilityLevel = 
            Math.min(Math.max(visibilityLevel, 0), 100);
    }
}
```

代码在同一行中初始化了每个类常量。以下行打印了先前声明的`SPECIAL_ATTACK_POWER`和`SPECIAL_DEFENSE_POWER`类常量的值。请注意，我们没有创建`VirtualCreature`类的任何实例，并且在类名和点(`.`)之后指定了类常量名称。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_10.java`文件中。

```java
System.out.printf("%d\n", VirtualCreature.SPECIAL_ATTACK_POWER);
System.out.printf("%d\n", VirtualCreature.SPECIAL_DEFENSE_POWER);
```

Java 9 允许我们从实例中访问类常量，因此，我们可以使用类名或实例来访问类常量。以下行创建了一个名为`golbat`的新版本`VirtualCreature`类的实例，并打印了从这个新实例访问的`GROWTH_RATE`类常量的值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_10.java`文件中。

```java
VirtualCreature golbat = 
    new VirtualCreature("Golbat", 2015, "Baseball cap", 75);
System.out.printf("%d\n", golbat.GROWTH_RATE);
```

下一个屏幕截图显示了在 JShell 中执行先前行的结果。

![使用静态字段提供类级值](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00053.jpeg)

# 使用静态方法提供可重写的类级值

类常量有一个很大的限制：我们不能在代表特定类型的虚拟生物的`VirtualCreature`类的未来子类中为它们提供新值。这是有道理的，因为它们是常量。这些子类需要为`ATTACK_POWER`或`AVERAGE_SPEED`设置不同的值。我们可以创建以下类方法来返回每个配置文件值的平均值，而不是使用类常量。我们将能够使这些方法在`VirtualCreature`类的子类中返回不同的值。

+   `getAttackPower`

+   `getDefensePower`

+   `getSpecialAttackPower`

+   `getSpecialDefensePower`

+   `getAverageSpeed`

+   `getCatchRate`

+   `getGrowthRate`

以下行显示了`VirtualCreature`类的新版本，该版本使用`public`访问修饰符定义了先前列出的七个类方法。请注意，方法声明中`static`关键字的使用使它们成为类方法。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_11.java`文件中。

```java
import java.time.Year;

public class VirtualCreature {
 public static int getAttackPower() {
 return 45;
 }

 public static int getDefensePower() {
 return 85;
 }

 public static int getSpecialAttackPower() {
 return 35;
 }

 public static int getSpecialDefensePower() {
 return 95;
 }

 public static int getAverageSpeed() {
 return 85;
 }

 public static int getCatchRate() {
 return 25;
 }

 public static int getGrowthRate() {
 return 10;
 }

    public final String name;
    private int birthYear;
    private String hat = "NONE";
    private int visibilityLevel;

    VirtualCreature(String name, 
        int birthYear, 
        String hat, 
        int visibilityLevel) {
        this.name = name;
        this.birthYear = birthYear;
        setHat(hat);
        setVisibilityLevel(visibilityLevel);
    }

    private int getCurrentYear() {
        return Year.now().getValue();
    }

    public int getAge() {
        return getCurrentYear() - birthYear;
    }

    public void setAge(final int age) {
        birthYear = getCurrentYear() - age;
    }

    public String getHat() {
        return hat;
    }

    public void setHat(final String hat) {
        this.hat = hat.toUpperCase();
    }

    public int getVisibilityLevel() {
        return visibilityLevel;
    }

    public void setVisibilityLevel(final int visibilityLevel) {
        this.visibilityLevel = 
            Math.min(Math.max(visibilityLevel, 0), 100);
    }
}
```

以下行打印了先前声明的`getSpecialAttackPower`和`getSpecialDefensePower`类方法返回的值。请注意，我们没有创建`VirtualCreature`类的任何实例，并且在类名和点(`.`)之后指定了类方法名称。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_11.java`文件中。

```java
System.out.printf("%d\n", VirtualCreature.getSpecialAttackPower());
System.out.printf("%d\n", VirtualCreature.getSpecialDefensePower());
```

与类常量一样，Java 9 允许我们从实例中访问类方法，因此，我们可以使用类名或实例来访问类方法。以下行创建了一个名为`vulpix`的新版本`VirtualCreature`类的实例，并打印了从这个新实例访问的`getGrowthRate`类方法返回的值。示例的代码文件包含在`java_9_oop_chapter_04_01`文件夹中的`example04_11.java`文件中。

```java
VirtualCreature vulpix = 
    new VirtualCreature("Vulpix", 2012, "Fedora", 35);
System.out.printf("%d\n", vulpix.getGrowthRate())
```

下一个屏幕截图显示了在 JShell 中执行先前行的结果：

![使用静态方法提供可重写的类级值](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00054.jpeg)

# 测试你的知识

1.  我们使用`static`关键字后跟方法声明来定义：

1.  实例方法。

1.  一个类方法。

1.  一个类常量。

1.  我们使用`final` static 关键字后跟初始化的变量声明来定义：

1.  类常量。

1.  类变量。

1.  实例常量。

1.  类常量：

1.  对于类的每个实例都有自己独立的值。

1.  对于类的所有实例具有相同的值。

1.  除非通过类名后跟一个点（`.`）和常量名来访问，否则对于类的所有实例具有相同的值。

1.  一个实例字段：

1.  对于类的每个实例都有自己独立的值。

1.  对于类的所有实例具有相同的值。

1.  除非通过类名后跟一个点（`.`）和实例字段名来访问，否则对于类的所有实例具有相同的值。

1.  在 Java 9 中，`public`、`protected`和`private`是：

1.  在`java.lang`中定义的三个不同的类。

1.  三种等效的访问修饰符。

1.  三种不同的访问修饰符。

# 总结

在本章中，您了解了 Java 9 中可以组成类声明的不同成员。我们使用实例字段、实例方法、类常量和类方法。我们使用 getter 和 setter，并利用访问修饰符来隐藏我们不希望类的用户能够访问的数据。

我们与虚拟生物一起工作。首先，我们声明了一个简单的类，然后通过添加功能使其进化。我们在 JShell 中测试了一切是如何工作的。

现在您已经了解了数据封装，可以开始在 Java 9 中使用可变和不可变版本的类，这是我们将在下一章中讨论的内容。


# 第五章：可变和不可变类

在本章中，我们将学习可变和不可变类。我们将了解它们在构建面向对象代码时的区别、优势和劣势。我们将：

+   创建可变类

+   在 JShell 中使用可变对象

+   构建不可变类

+   在 JShell 中使用不可变对象

+   了解可变和不可变对象之间的区别

+   学习在编写并发代码时不可变对象的优势

+   使用不可变`String`类的实例

# 在 Java 9 中创建可变类

当我们声明实例字段时没有使用`final`关键字时，我们创建了一个可变的实例字段，这意味着我们可以在字段初始化后为每个新创建的实例更改它们的值。当我们创建一个定义了至少一个可变字段的类的实例时，我们创建了一个可变对象，这是一个在初始化后可以改变其状态的对象。

### 注意

可变对象也称为可变对象。

例如，假设我们必须开发一个 Web 服务，渲染 3D 世界中的元素并返回高分辨率的渲染场景。这样的任务要求我们使用 3D 向量。首先，我们将使用一个可变的 3D 向量，其中有三个可变字段：`x`、`y`和`z`。可变的 3D 向量必须提供以下功能：

+   三个`double`类型的可变实例字段：`x`、`y`和`z`。

+   一个构造函数，通过提供`x`、`y`和`z`字段的初始值来创建一个实例。

+   一个构造函数，创建一个所有值都初始化为`0`的实例，即`x=0`、`y=0`和`z=0`。具有这些值的 3D 向量称为**原点向量**。

+   一个构造函数，创建一个所有值都初始化为一个公共值的实例。例如，如果我们指定`3.0`作为公共值，构造函数必须生成一个`x=3.0`、`y=3.0`和`z=3.0`的实例。

+   一个`absolute`方法，将 3D 向量的每个分量设置为其绝对值。

+   一个`negate`方法，就地否定 3D 向量的每个分量。

+   一个`add`方法，将 3D 向量的值设置为其自身与作为参数接收的 3D 向量的和。

+   一个`sub`方法，将 3D 向量的值设置为其自身与作为参数接收的 3D 向量的差。

+   `toString`方法的实现，打印 3D 向量的三个分量的值：`x`、`y`和`z`。

以下行声明了`Vector3d`类，表示 Java 中 3D 向量的可变版本。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_01.java`文件中。

```java
public class Vector3d {
    public double x;
    public double y;
    public double z;

 Vector3d(double x, double y, double z) {
 this.x = x;
 this.y = y;
 this.z = z;
 }

 Vector3d(double valueForXYZ) {
 this(valueForXYZ, valueForXYZ, valueForXYZ);
 }

 Vector3d() {
 this(0.0);
 }

    public void absolute() {
        x = Math.abs(x);
        y = Math.abs(y);
        z = Math.abs(z);
    }

    public void negate() {
        x = -x;
        y = -y;
        z = -z;
    }

    public void add(Vector3d vector) {
        x += vector.x;
        y += vector.y;
        z += vector.z;
    }

    public void sub(Vector3d vector) {
        x -= vector.x;
        y -= vector.y;
        z -= vector.z;
    }

    public String toString() {
        return String.format(
            "(x: %.2f, y: %.2f, z: %.2f)",
            x,
            y,
            z);
    }
}
```

新的`Vector3d`类声明了三个构造函数，它们的行在前面的代码列表中突出显示。第一个构造函数接收三个`double`参数`x`、`y`和`z`，并使用这些参数中接收的值初始化具有相同名称和类型的字段。

第二个构造函数接收一个`double`参数`valueForXYZ`，并使用`this`关键字调用先前解释的构造函数，将接收的参数作为三个参数的值。

### 提示

我们可以在构造函数中使用`this`关键字来调用类中定义的具有不同参数的其他构造函数。

第三个构造函数是一个无参数的构造函数，并使用`this`关键字调用先前解释的构造函数，将`0.0`作为`valueForXYZ`参数的值。这样，构造函数允许我们构建一个原点向量。

每当我们调用`absolute`、`negate`、`add`或`sub`方法时，我们将改变实例的状态，也就是说，我们将改变对象的状态。这些方法改变了我们调用它们的实例的`x`、`y`和`z`字段的值。

# 在 JShell 中使用可变对象

以下行创建了一个名为`vector1`的新`Vector3d`实例，其初始值为`x`、`y`和`z`的`10.0`、`20.0`和`30.0`。第二行创建了一个名为`vector2`的新`Vector3d`实例，其初始值为`x`、`y`和`z`的`1.0`、`2.0`和`3.0`。然后，代码调用`System.out.println`方法，参数分别为`vector1`和`vector2`。对`println`方法的两次调用将执行每个`Vector3d`实例的`toString`方法，以显示可变 3D 向量的`String`表示。然后，代码使用`vector2`作为参数调用`vector1`的`add`方法。最后一行再次调用`println`方法，参数为`vector1`，以打印调用`add`方法后`x`、`y`和`z`的新值。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_01.java`文件中。

```java
Vector3d vector1 = new Vector3d(10.0, 20.0, 30.0);
Vector3d vector2 = new Vector3d(1.0, 2.0, 3.0);
System.out.println(vector1);
System.out.println(vector2);
vector1.add(vector2);
System.out.println(vector1);
```

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![在 JShell 中使用可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00055.jpeg)

`vector1`字段的初始值分别为`10.0`、`20.0`和`30.0`。`add`方法改变了三个字段的值。因此，对象状态发生了变化：

+   `vector1.x`从`10.0`变为*10.0 + 1.0 = 11.0*

+   `vector1.y`从`20.0`变为*20.0 + 2.0 = 22.0*

+   `vector1.z`从`30.0`变为*30.0 + 3.0 = 33.0*

在调用`add`方法后，`vector1`字段的值为`11.0`、`22.0`和`33.0`。我们可以说该方法改变了对象的状态。因此，`vector1`是一个可变对象，是可变类的一个实例。

以下行使用三个可用的构造函数创建了`Vector3d`类的三个实例，分别命名为`vector3`、`vector4`和`vector5`。然后，下一行调用`System.out.println`方法，以打印对象创建后的`x`、`y`和`z`的值。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_02.java`文件中。

```java
Vector3d vector3 = new Vector3d();
Vector3d vector4 = new Vector3d(5.0);
Vector3d vector5 = new Vector3d(-15.5, -11.1, -8.8);
System.out.println(vector3);
System.out.println(vector4);
System.out.println(vector5);
```

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![在 JShell 中使用可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00056.jpeg)

接下来的行调用了先前创建的实例的许多方法。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_02.java`文件中。

```java
vector4.negate();
System.out.println(vector4);
vector3.add(vector4);
System.out.println(vector3);
vector4.absolute();
System.out.println(vector4);
vector5.sub(vector4);
System.out.println(vector5);
```

`vector4`字段的初始值为`5.0`。对`vector4.negate`方法的调用将三个字段的值改变为`-5.0`。

三个`vector3`字段（`x`、`y`和`z`）的初始值为`0.0`。对`vector3.add`方法的调用通过`vector3`和`vector4`的每个分量的和的结果改变了三个字段的值。因此，对象状态发生了变化：

+   `vector3.x`从`0.0`变为*0.0 + (-5.0) = -5.0*

+   `vector3.y`从`0.0`变为*0.0 + (-5.0) = -5.0*

+   `vector3.z`从`0.0`变为*0.0 + (-5.0) = -5.0*

`vector3`字段在调用`add`方法后被设置为`-5.0`。对`vector4.absolute`方法的调用将三个字段的值从`-5.0`改变为`5.0`。

`vector5`字段的初始值分别为`-15.5`、`-11.1`和`-8.8`。对`vector5.sub`方法的调用通过`vector5`和`vector4`的每个分量的减法结果改变了三个字段的值。因此，对象状态发生了变化：

+   `vector5.x`从`-15.5`变为*-15.5 - 5.0 = -20.5*

+   `vector5.y`从`-11.1`变为*-11.1 - 5.0 = -16.1*

+   `vector5.z`从`-8.8`变为*-8.8 - 5.0 = -13.8*

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![在 JShell 中使用可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00057.jpeg)

# 在 Java 9 中构建不可变类

到目前为止，我们一直在使用可变类和变异对象。每当我们暴露可变字段时，我们都会创建一个将生成可变实例的类。在某些情况下，我们可能更喜欢一个对象，在初始化后无法更改其状态。我们可以设计类为不可变，并生成不可更改的实例，这些实例在创建和初始化后无法更改其状态。

不可变对象非常有用的一个典型场景是在处理并发代码时。不能更改其状态的对象解决了许多典型的并发问题，并避免了可能难以检测和解决的潜在错误。因为不可变对象不能更改其状态，所以在许多不同的线程修改它时，不可能出现对象处于损坏或不一致状态的情况，而没有适当的同步机制。

### 注意

不可变对象也被称为不可变对象。

我们将创建一个不可变版本的先前编码的`Vector3d`类，以表示不可变的 3D 向量。这样，我们将注意到可变类和其不可变版本之间的区别。不可变的 3D 向量必须提供以下功能：

+   三个`double`类型的不可变实例字段：`x`、`y`和`z`。这些字段的值在实例初始化或构造后不能更改。

+   通过为`x`、`y`和`z`不可变字段提供初始值来创建实例的构造函数。

+   一个构造函数，创建一个所有值都设置为`0`的实例，即`x = 0`、`y = 0`和`z = 0`。

+   一个构造函数，创建一个所有值都初始化为公共值的实例。例如，如果我们指定`3.0`作为公共值，构造函数必须生成一个不可变实例，其中`x = 3.0`、`y = 3.0`和`z = 3.0`。

+   一个`absolute`方法，返回一个新实例，其中调用该方法的实例的每个分量的绝对值设置为该实例的每个分量的绝对值。

+   一个`negate`方法，返回一个新实例，其中调用该方法的实例的每个分量的值设置为该方法的每个分量的否定值。

+   一个`add`方法，返回一个新实例，其中调用该方法的实例的每个分量设置为该方法和作为参数接收的不可变 3D 向量的每个分量的和。

+   一个`sub`方法，返回一个新实例，其中调用该方法的实例的每个分量设置为该方法和作为参数接收的不可变 3D 向量的每个分量的差。

+   `toString`方法的实现，打印 3D 向量的三个分量的值：`x`、`y`和`z`。

以下行声明了`ImmutableVector3d`类，该类表示 Java 中 3D 向量的不可变版本。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_03.java`文件中。

```java
public class ImmutableVector3d {
    public final double x;
    public final double y;
    public final double z;

 ImmutableVector3d(double x, double y, double z) {
 this.x = x;
 this.y = y;
 this.z = z;
 }

 ImmutableVector3d(double valueForXYZ) {
 this(valueForXYZ, valueForXYZ, valueForXYZ);
 }

 ImmutableVector3d() {
 this(0.0);
 }

    public ImmutableVector3d absolute() {
        return new ImmutableVector3d(
            Math.abs(x),
            Math.abs(y),
            Math.abs(z));
    }

    public ImmutableVector3d negate() {
        return new ImmutableVector3d(
            -x,
            -y,
            -z);
    }

    public ImmutableVector3d add(ImmutableVector3d vector) {
        return new ImmutableVector3d(
            x + vector.x,
            y + vector.y,
            z + vector.z);
    }

    public ImmutableVector3d sub(ImmutableVector3d vector) {
        return new ImmutableVector3d(
            x - vector.x,
            y - vector.y,
            z - vector.z);
    }

    public String toString() {
        return String.format(
            "(x: %.2f, y: %.2f, z: %.2f)",
            x,
            y,
            z);
    }
}
```

新的`ImmutableVector3d`类通过使用`final`关键字声明了三个不可变实例字段：`x`、`y`和`z`。在此类声明的三个构造函数的行在前面的代码列表中突出显示。这些构造函数具有我们为`Vector3d`类分析的相同代码。唯一的区别在于执行，因为构造函数正在初始化不可变实例字段，这些字段在初始化后不会更改其值。

每当我们调用`absolute`、`negate`、`add`或`sub`方法时，它们的代码将返回`ImmutableVector3d`类的新实例，其中包含每个操作的结果。我们永远不会改变我们的实例；也就是说，我们不会改变对象的状态。

# 在 JShell 中使用不可变对象

以下几行创建了一个名为`vector10`的新`ImmutableVector3d`实例，其`x`、`y`和`z`的初始值分别为`100.0`、`200.0`和`300.0`。第二行创建了一个名为`vector20`的新`ImmutableVector3d`实例，其`x`、`y`和`z`的初始值分别为`11.0`、`12.0`和`13.0`。然后，代码分别使用`vector10`和`vector20`作为参数调用`System.out.println`方法。对`println`方法的两次调用将执行每个`ImmutableVector3d`实例的`toString`方法，以显示不可变 3D 向量的`String`表示。然后，代码使用`vector10`和`vector20`作为参数调用`add`方法，并将返回的`ImmutableVector3d`实例保存在`vector30`中。

最后一行使用`vector30`作为参数调用`println`方法，以打印此实例的`x`、`y`和`z`的值，该实例包含了`vector10`和`vector20`之间的加法操作的结果。在声明`ImmutableVector3d`类的代码之后输入这些行。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_03.java`文件中。

```java
ImmutableVector3d vector10 = 
    new ImmutableVector3d(100.0, 200.0, 300.0);
ImmutableVector3d vector20 = 
    new ImmutableVector3d(11.0, 12.0, 13.0);
System.out.println(vector10);
System.out.println(vector20);
ImmutableVector3d vector30 = vector10.add(vector20);
System.out.println(vector30);
```

以下屏幕截图显示了在 JShell 中执行先前代码的结果：

![在 JShell 中使用不可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00058.jpeg)

由于`add`方法的结果，我们有另一个名为`vector30`的不可变实例，其字段值为`111.0`（`x`）、`212.0`（`y`）和`313.0`（`z`）。调用每个计算操作的方法的结果，我们将得到另一个不可变实例。

以下几行使用三个可用的构造函数创建了`ImmutableVector3d`类的三个实例，分别命名为`vector40`、`vector50`和`vector60`。然后，下一行调用`System.out.println`方法，以打印对象创建后`x`、`y`和`z`的值。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_03.java`文件中。

```java
ImmutableVector3d vector40 = 
    new ImmutableVector3d();
ImmutableVector3d vector50 = 
    new ImmutableVector3d(-5.0);
ImmutableVector3d vector60 = 
    new ImmutableVector3d(8.0, 9.0, 10.0);
System.out.println(vector40);
System.out.println(vector50);
System.out.println(vector60);
```

以下屏幕截图显示了在 JShell 中执行先前代码的结果：

![在 JShell 中使用不可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00059.jpeg)

接下来的几行调用了先前创建实例的许多方法，并生成了`ImmutableVector3d`类的新实例。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_03.java`文件中。

```java
ImmutableVector3d vector70 = vector50.negate();
System.out.println(vector70);
ImmutableVector3d vector80 = vector40.add(vector70);
System.out.println(vector80);
ImmutableVector3d vector90 = vector70.absolute();
System.out.println(vector90);
ImmutableVector3d vector100 = vector60.sub(vector90);
System.out.println(vector100);
```

`vector50`字段（`x`、`y`和`z`）的初始值为`-5.0`。对`vector50.negate`方法的调用返回一个新的`ImmutableVector3d`实例，代码将其保存在`vector70`中。新实例的三个字段（`x`、`y`和`z）的值为`5.0`。

`vector40`字段（`x`、`y`和`z`）的初始值为`0`。对`vector40.add`方法使用`vector70`作为参数的调用返回一个新的`ImmutableVector3d`实例，代码将其保存在`vector80`中。新实例的三个字段（`x`、`y`和`z`）的值为`5.0`。

对`vector70.absolute`方法的调用返回一个新的`ImmutableVector3d`实例，代码将其保存在`vector90`中。新实例的三个字段（`x`、`y`和`z`）的值为`5.0`。字段的绝对值与原始值相同，但代码仍然生成了一个新实例。

`vector60`字段的初始值分别为`8.0`（`x`）、`9.0`（`y`）和`10.0`（`z`）。对`vector60.sub`方法使用`vector90`作为参数的调用返回一个新的`ImmutableVector3d`实例，代码将其保存在`vector100`中。`vector100`字段的值分别为`3.0`（`x`）、`4.0`（`y`）和`5.0`（`z`）。

以下屏幕截图显示了在 JShell 中执行先前代码的结果：

![在 JShell 中使用不可变对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00060.jpeg)

# 理解可变和不可变对象之间的区别

与可变版本相比，不可变版本增加了开销，因为调用`absolute`、`negate`、`add`或`sub`方法时需要创建类的新实例。先前分析过的可变类`Vector3D`只是改变了字段的值，不需要生成新实例。因此，不可变版本的内存占用量高于可变版本。

与可变版本相比，名为`ImmutableVector3d`的不可变类在内存和性能方面都有额外的开销。创建新实例比改变少数字段的值更昂贵。然而，正如先前解释的那样，当我们使用并发代码时，为了避免可变对象可能引起的问题，为额外的开销付费是有意义的。我们只需要确保分析优势和权衡，以决定哪种方式是编写特定类最方便的方式。

现在，我们将编写一些使用可变版本的代码，并生成不可变版本的等效代码。这样，我们就能够简单而生动地比较这两段代码之间的区别。

以下行创建了一个名为`mutableVector3d1`的新的`Vector3d`实例，初始值为`x`、`y`和`z`的值分别为`-30.5`、`-15.5`和`-12.5`。然后，代码打印了新实例的`String`表示形式，调用了`absolute`方法，并打印了变异对象的`String`表示形式。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_04.java`文件中。

```java
// Mutable version
Vector3d mutableVector3d1 = 
    new Vector3d(-30.5, -15.5, -12.5);
System.out.println(mutableVector3d1);
mutableVector3d1.absolute();
System.out.println(mutableVector3d1);
```

以下截图显示了在 JShell 中执行先前代码的结果：

![理解可变和不可变对象之间的区别](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00061.jpeg)

以下行创建了一个名为`immutableVector3d1`的新的`ImmutableVector3d`实例，初始值为`x`、`y`和`z`的值分别为`-30.5`、`-15.5`和`-12.5`。然后，代码打印了新实例的`String`表示形式，调用了`absolute`方法生成了一个名为`immutableVector3d2`的新的`ImmutableVector3d`实例，并打印了新对象的`String`表示形式。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_04.java`文件中。

```java
// Immutable version
ImmutableVector3d immutableVector3d1 = 
    new ImmutableVector3d(-30.5, -15.5, -12.5);
System.out.println(immutableVector3d1);
ImmutableVector3d immutableVector3d2 =
    immutableVector3d1.absolute();
System.out.println(immutableVector3d2);
```

以下截图显示了在 JShell 中执行先前代码的结果：

![理解可变和不可变对象之间的区别](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00062.jpeg)

可变版本使用单个`Vector3d`实例。`Vector3d`类的构造函数只执行一次。当调用`absolute`方法时，原始实例会改变其状态。

不可变版本使用两个`ImmutableVector3d`实例，因此内存占用量高于可变版本。`ImmutableVector3d`类的构造函数被执行了两次。第一个实例在调用`absolute`方法时没有改变其状态。

# 学习在编写并发代码时不可变对象的优势

现在，让我们想象我们正在编写必须访问先前创建实例的字段的并发代码。首先，我们将分析可变版本的问题，然后我们将了解使用不可变对象的优势。

假设我们有两个线程，代码中引用了保存在`mutableVector3d1`中的实例。第一个线程调用这个可变对象的`absolute`方法。`absolute`方法的第一行代码将`Math.abs`的结果作为参数赋给`x`可变字段的实际值。

在这一点上，方法还没有完成执行，下一行代码将无法访问这些值。然而，在另一个线程中运行的并发代码可能会在`absolute`方法完成执行之前访问`x`、`y`和`z`字段的值。对象处于损坏状态，因为`x`字段的值为`30.5`，`y`字段的值为`-15.5`，`z`字段的值为`-12.5`。这些值不代表`absolute`方法执行完成后我们将拥有的 3D 向量。并发运行的代码片段并且可以访问相同实例而没有任何同步机制，这会产生问题。

并发编程和线程编程是复杂的主题，值得一整本书来讨论。有同步机制可以避免前面提到的问题，并使类成为线程安全的。然而，另一个解决方案是使用生成不可变对象的不可变类。

如果我们使用不可变版本，两个线程可以引用相同的初始实例。然而，当其中一个线程调用`absolute`方法时，原始的 3D 向量不会发生变化，因此之前的问题永远不会发生。另一个线程将继续使用对原始 3D 向量的引用，保持其原始状态。调用`absolute`方法的线程将生成一个完全独立于原始实例的新实例。

再次强调，理解这个主题需要一整本书。然而，了解为什么不可变类可能在实例将参与并发代码的特定场景中是一个特殊要求是很重要的。

# 使用不可变 String 类的实例

`String`类，特别是`java.lang.String`类，表示字符字符串，是一个生成不可变对象的不可变类。因此，`String`类提供的方法不会改变对象。

例如，以下行创建了一个新的`String`，也就是`java.lang.String`类的一个新实例，名为`welcomeMessage`，初始值为`"Welcome to Virtual Creatures Land"`。然后，代码对`welcomeMessage`进行了多次调用`System.out.println`，并将不同的方法作为参数。首先，我们调用`toUpperCase`方法生成一个所有字符都转换为大写的新`String`。然后，我们调用`toLowerCase`方法生成一个所有字符都转换为小写的新`String`。然后，我们调用`replaceAll`方法生成一个将空格替换为连字符（`-`）的新`String`。最后，我们再次调用`System.out.println`方法，并将`welcomeMessage`作为参数，以检查原始`String`的值。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_05.java`文件中。

```java
String welcomeMessage = "Welcome to Virtual Creatures Land";
System.out.println(welcomeMessage);
System.out.println(welcomeMessage.toUpperCase());
System.out.println(welcomeMessage.toLowerCase());
System.out.println(welcomeMessage.replaceAll(" ", "-"));
System.out.println(welcomeMessage);
```

以下截图显示了在 JShell 中执行前面代码的结果：

![使用不可变 String 类的实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00063.jpeg)

`welcomeMessage`字符串从未改变其值。对`toUpperCase`、`toLowerCase`和`replaceAll`方法的调用为每个方法生成并返回了一个新的`String`实例。

### 提示

无论我们为`String`实例调用哪个方法，它都不会改变对象。因此，我们可以说`String`是一个不可变类。

# 创建现有可变类的不可变版本

在上一章中，我们创建了一个名为`VirtualCreature`的可变类。我们提供了 setter 方法来改变`hat`、`visibilityLevel`和`birthYear`字段的值。我们可以通过调用`setAge`方法来改变`birthYear`。

虚拟生物在进化后会改变它们的年龄、帽子和可见性级别。当它们进化时，它们会变成不同的生物，因此在这种进化发生后生成一个新实例是有意义的。因此，我们将创建`VirtualCreature`类的不可变版本，并将其称为`ImmutableVirtualCreature`。

以下行显示了新`ImmutableVirtualCreature`类的代码。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_06.java`文件中。

```java
import java.time.Year;

public class ImmutableVirtualCreature {
 public final String name;
 public final int birthYear;
 public final String hat;
 public final int visibilityLevel;

    ImmutableVirtualCreature(final String name, 
        int birthYear, 
        String hat, 
        int visibilityLevel) {
        this.name = name;
        this.birthYear = birthYear;
        this.hat = hat.toUpperCase();
        this.visibilityLevel = 
            getValidVisibilityLevel(visibilityLevel);
    }

    private int getCurrentYear() {
        return Year.now().getValue();
    }

    private int getValidVisibilityLevel(int levelToValidate) {
        return Math.min(Math.max(levelToValidate, 0), 100);
    }

    public int getAge() {
        return getCurrentYear() - birthYear;
    }

    public ImmutableVirtualCreature evolveToAge(int age) {
        int newBirthYear = getCurrentYear() - age;
        return new ImmutableVirtualCreature(
            name,
            newBirthYear,
            hat,
            visibilityLevel);
    }

    public ImmutableVirtualCreature evolveToVisibilityLevel(
        final int visibilityLevel) {
        int newVisibilityLevel =
            getValidVisibilityLevel(visibilityLevel);
        return new ImmutableVirtualCreature(
            name,
            birthYear,
            hat,
            newVisibilityLevel);
    }
}
```

`ImmutableVirtualCreature`类使用`final`关键字声明了四个公共不可变实例字段：`name`、`birthYear`、`hat`和`visibilityLevel`。在实例被初始化或构造后，我们将无法更改这些字段的任何值。

构造函数从`hat`参数中接收的`String`生成大写的`String`并将其存储在公共的不可变字段`hat`中。我们对可见性级别有特定的验证，因此构造函数调用一个名为`getValidVisibilityLevel`的新私有方法，该方法使用`visibilityLevel`参数中接收的值来为具有相同名称的不可变字段分配一个有效值。

我们不再有 setter 方法，因为在初始化后我们无法更改不可变字段的值。该类声明了以下两个新的公共方法，它们返回一个新的`ImmutableVirtualCreature`实例：

+   `evolveToAge`：此方法接收`age`参数中进化虚拟生物的期望年龄。代码根据接收到的年龄和当前年份计算出出生年份，并返回一个具有新初始化值的新`ImmutableVirtualCreature`实例。

+   `evolveToVisibilityLevel`：此方法接收`visibilityLevel`参数中进化虚拟生物的期望可见性级别。代码调用`getValidVisibilityLevel`方法根据接收到的值生成一个有效的可见性级别，并返回一个具有新初始化值的新`ImmutableVirtualCreature`实例。

以下行创建了一个名为`meowth1`的`ImmutableVirtualCreature`类的实例。然后，代码使用`3`作为`age`参数的值调用`meowth1.evolveToAge`方法，并将此方法返回的新`ImmutableVirtualCreature`实例保存在`meowth2`变量中。代码打印了`meowth2.getAge`方法返回的值。最后，代码使用`25`作为`invisibilityLevel`参数的值调用`meowth2.evolveToVisibilityLevel`方法，并将此方法返回的新`ImmutableVirtualCreature`实例保存在`meowth3`变量中。然后，代码打印了存储在`meowth3.visibilityLevel`不可变字段中的值。示例的代码文件包含在`java_9_oop_chapter_05_01`文件夹中的`example05_06.java`文件中。

```java
ImmutableVirtualCreature meowth1 =
    new ImmutableVirtualCreature(
        "Meowth", 2010, "Baseball cap", 35);
ImmutableVirtualCreature meowth2 = 
    meowth1.evolveToAge(3);
System.out.printf("%d\n", meowth2.getAge());
ImmutableVirtualCreature meowth3 = 
    meowth2.evolveToVisibilityLevel(25);
System.out.printf("%d\n", meowth3.visibilityLevel);
```

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![创建现有可变类的不可变版本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00064.jpeg)

# 测试你的知识

1.  一个暴露可变字段的类将：

1.  生成不可变实例。

1.  生成可变实例。

1.  生成可变类但不可变实例。

1.  在构造函数中使用以下哪个关键字可以调用我们类中定义的具有不同参数的其他构造函数：

1.  `self`

1.  `constructor`

1.  `this`

1.  在初始化后无法更改其状态的对象称为：

1.  一个可变对象。

1.  一个不可变对象。

1.  一个接口对象。

1.  在 Java 9 中，`java.lang.String`生成：

1.  一个不可变对象。

1.  一个可变对象。

1.  一个接口对象。

1.  如果我们为`java.lang.String`调用`toUpperCase`方法，该方法将：

1.  将现有的`String`转换为大写字符并改变其状态。

1.  返回一个新的`String`，其中包含原始`String`转换为大写字符的内容。

1.  返回一个包含原始字符串内容的新的`String`。

# 总结

在本章中，你学习了可变和不可变类之间的区别，以及它们生成的可变和不可变实例。我们在 Java 9 中声明了可变和不可变版本的 3D 向量类。

然后，我们利用 JShell 轻松地处理这些类的可变和不可变实例，并分析了改变对象状态和在需要改变其状态时返回一个新对象之间的区别。我们分析了可变和不可变类的优缺点，并理解了为什么在处理并发代码时后者是有用的。

现在你已经学习了可变和不可变类，你已经准备好学习继承、抽象、扩展和专门化，这些是我们下一章要讨论的主题。


# 第六章：继承，抽象，扩展和特殊化

在本章中，我们将学习 Java 9 中面向对象编程最重要的支柱之一：继承。我们将使用示例来学习如何创建类层次结构，覆盖和重载方法，并处理超类中定义的构造函数。我们将：

+   创建类层次结构以抽象和特殊化行为

+   理解继承

+   创建一个抽象基类

+   声明从另一个类继承的类

+   重载构造函数

+   覆盖实例方法

+   重载实例方法

# 创建类层次结构以抽象和特殊化行为

在之前的章节中，我们一直在使用 Java 9 创建类来生成现实生活中对象的蓝图。我们声明了类，然后在 JShell 中创建了这些类的实例。现在是时候利用 Java 9 中包含的许多最先进的面向对象编程特性，开始设计一个类层次结构，而不是使用孤立的类。首先，我们将根据需求设计所有需要的类，然后使用 Java 9 中可用的功能来编写设计的类。

我们使用类来表示虚拟生物。现在，让我们想象一下，我们必须开发一个复杂的 Web 服务，需要我们处理数十种虚拟动物。在项目的第一阶段，许多这些虚拟动物将类似于宠物和家畜。需求规定，我们的 Web 服务将开始处理以下四种与家畜动物物种相似的虚拟动物：

+   **马**（**Equus ferus caballus**）。不要将其与野马（Equus ferus）混淆。我们将拥有雄性和雌性马，雌性马可能怀孕。此外，我们将需要处理以下三种特定的马种：美国四分之一马，夏尔马和纯种马。

+   **鹦鹉**（**Nymphicus hollandicus**）。这种鸟也被称为鹦鹉或维罗。

+   **缅因库恩**。这是最大的家养猫品种之一（Felis silvestris catus）。

+   **家兔**（**Oryctolagus cuniculus**）。这种兔子也被称为欧洲兔。

前面的列表包括每种家畜动物物种的学名。我们肯定会使用每种物种的最常见名称，并将学名作为`String`类型的类常量。因此，我们不会有复杂的类名，比如`VirtualEquusFerusCaballus`，而是使用`VirtualHorse`。

我们的第一个需求规定，我们必须处理先前列举的四种家畜动物物种的有限数量品种。此外，将来将需要处理其他列出的家畜动物物种的其他成员，其他家畜哺乳动物，额外的家禽，特定的马种，甚至不属于家畜动物物种的爬行动物和鸟类。我们的面向对象设计必须准备好为未来的需求进行扩展，就像在现实项目中经常发生的那样。事实上，我们将使用这个例子来理解面向对象编程如何轻松地扩展现有设计以考虑未来的需求。

我们不想模拟动物王国及其分类的完整表示。我们只会创建必要的类，以便拥有一个灵活的模型，可以根据未来的需求轻松扩展。动物王国非常复杂。我们将把重点放在这个庞大家族的一些成员上。

以下示例的主要目标之一是了解面向对象编程并不会牺牲灵活性。我们将从一个简单的类层次结构开始，随着所需功能的复杂性增加以及对这些新需求的更多了解，我们将扩展它。让我们记住，需求并不是固定的，我们总是必须根据这些新需求添加新功能并对现有类进行更改。

我们将创建一个类层次结构来表示虚拟动物及其品种的复杂分类。当我们扩展一个类时，我们创建这个类的子类。以下列表列举了我们将创建的类及其描述：

+   `VirtualAnimal`：这个类概括了动物王国的所有成员。马、猫、鸟、兔子和爬行动物有一个共同点：它们都是动物。因此，创建一个类作为我们面向对象设计中可能需要表示的不同类别的虚拟动物的基线是有意义的。

+   `VirtualMammal`：这个类概括了所有哺乳动物的虚拟动物。哺乳动物与昆虫、鸟类、两栖动物和爬行动物不同。我们已经知道我们可以有母马，并且它们可以怀孕。我们还知道我们将需要对爬行动物和鸟类进行建模，因此我们创建了一个扩展`VirtualAnimal`并成为其子类的`VirtualMammal`类。

+   `VirtualBird`：这个类概括了所有鸟类。鸟类与哺乳动物、昆虫、两栖动物和爬行动物不同。我们已经知道我们还将需要对爬行动物进行建模。鹦鹉是一种鸟，因此我们将在与`VirtualMammal`同级别创建一个`VirtualBird`类。

+   `VirtualDomesticMammal`：这个类扩展了`VirtualMammal`类。让我们进行一些研究，我们会意识到老虎（Panthera tigris）是目前最大和最重的猫科动物。老虎是一种猫，但它与缅因猫完全不同，缅因猫是一种小型家养猫。最初的需求规定我们要处理虚拟家养和虚拟野生动物，因此我们将创建一个概括所有虚拟家养哺乳动物的类。将来，我们将有一个`VirtualWildMammal`子类，它将概括所有虚拟野生哺乳动物。

+   `VirtualDomesticBird`：这个类扩展了`VirtualBird`类。让我们进行一些研究，我们会意识到鸵鸟（Struthio camelus）是目前最大的活鸟。鸵鸟是一种鸟，但它与鹦鹉完全不同，鹦鹉是一种小型家养鸟。我们将处理虚拟家养和虚拟野生鸟，因此我们将创建一个概括所有虚拟家养鸟的类。将来，我们将有一个`VirtualWildBird`类，它将概括所有虚拟野生鸟。

+   `VirtualHorse`：这个类扩展了`VirtualDomesticMammal`类。我们可以继续用额外的子类专门化`VirtualDomesticMammal`类，直到达到`VirtualHorse`类。例如，我们可以创建一个`VirtualHerbivoreDomesticMammal`子类，然后让`VirtualHorse`类继承它。然而，我们需要开发的 Web 服务不需要在`VirtualDomesticMammal`和`VirtualHorse`之间有任何中间类。`VirtualHorse`类概括了我们应用程序中虚拟马所需的所有字段和方法。`VirtualHorse`类的不同子类将代表虚拟马品种的不同家族。

+   `VirtualDomesticRabbit`：这个类扩展了`VirtualDomesticMammal`类。`VirtualDomesticRabbit`类概括了我们应用程序中虚拟家养兔所需的所有字段和方法。

+   `VirtualDomesticCat`：这个类扩展了`VirtualDomesticMammal`类。`VirtualDomesticCat`类概括了我们应用程序中虚拟家养猫所需的所有字段和方法。

+   `美国四分之一马`：这个类扩展了`虚拟马`类。`美国四分之一马`类概括了属于美国四分之一马品种的虚拟马所需的所有字段和方法。

+   `ShireHorse`：这个类扩展了`虚拟马`类。`ShireHorse`类概括了属于莱茵马品种的虚拟马所需的所有字段和方法。

+   `Thoroughbred`：这个类扩展了`虚拟马`类。`Thoroughbred`类概括了属于纯种马品种的虚拟马所需的所有字段和方法。

+   `Cockatiel`：这个类扩展了`虚拟家禽`类。`Cockatiel`类概括了属于鹦鹉家族的虚拟家禽所需的所有字段和方法。

+   `MaineCoon`：这个类扩展了`虚拟家猫`类。`MaineCoon`类概括了属于缅因库恩品种的虚拟家猫所需的所有字段和方法。

以下表格显示了前述列表中的每个类及其超类、父类或超类型。

| 子类、子类或子类型 | 超类、父类或超类型 |
| --- | --- |
| `虚拟哺乳动物` | `虚拟动物` |
| `虚拟鸟` | `虚拟动物` |
| `虚拟家畜哺乳动物` | `虚拟哺乳动物` |
| `虚拟家禽` | `虚拟鸟` |
| 虚拟马 | 虚拟家畜哺乳动物 |
| `虚拟家兔` | `虚拟家畜哺乳动物` |
| `虚拟家猫` | `虚拟家畜哺乳动物` |
| `美国四分之一马` | `虚拟马` |
| `ShireHorse` | `虚拟马` |
| `Thoroughbred` | `虚拟马` |
| `Cockatiel` | `虚拟家禽` |
| `MaineCoon` | `虚拟家猫` |

以下的 UML 图显示了以类层次结构组织的前述类。使用斜体文本格式的类名表示它们是抽象类。注意图表中不包括任何成员，只有类名。我们稍后会添加成员。

![创建类层次结构以抽象和特殊化行为](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00065.jpeg)

# 理解继承

当一个类继承自另一个类时，它继承了组成父类的所有成员，这也被称为**超类**。继承元素的类被称为超类的**子类**。例如，`VirtualBird`子类继承了`VirtualAnimal`超类中定义的所有实例字段、类字段、实例方法和类方法。

### 提示

在 Java 9 中，子类不会从其超类那里继承任何构造函数。但是，可以调用超类中定义的构造函数，在下面的示例中我们将这样做。只有在超类中定义的任何构造函数中使用`private`访问修饰符才会使子类无法调用该构造函数。

`VirtualAnimal`抽象类是我们类层次结构的基线。我们说它是一个**抽象类**，因为我们不能创建`VirtualAnimal`类的实例。相反，我们必须创建`VirtualAnimal`的具体子类的实例，任何不是抽象类的子类。我们可以用来创建它们的类通常被称为**具体类**或在大多数情况下只是类。Java 9 允许我们声明类为抽象类，当它们不打算生成实例时。

### 注意

我们不能使用`new`关键字后跟类名来创建抽象类的实例。

我们要求每个`VirtualAnimal`指定它的年龄，但我们不需要为它们指定任何名字。我们只给家养动物取名字。因此，当我们创建任何`VirtualAnimal`，也就是任何`VirtualAnimal`子类的实例时，我们将不得不指定一个年龄值。该类将定义一个`age`字段，并在创建虚拟动物时打印一条消息。

但是等等；我们刚刚解释过，我们正在谈论一个抽象类，并且 Java 不允许我们创建抽象类的实例。我们不能创建`VirtualAnimal`抽象类的实例，但我们将能够创建具有`VirtualAnimal`作为超类的任何具体类的实例，这个子类最终可以调用`VirtualAnimal`抽象类中定义的构造函数。听起来有点复杂，但在我们编写类并在 JShell 中运行示例后，我们将很容易理解情况。我们将在我们定义的每个构造函数中打印消息，以便更容易理解当我们创建具有一个或多个超类的具体类的实例时会发生什么，包括一个或多个抽象超类。`VirtualAnimal`的所有子类的实例也将是`VirtualAnimal`的实例。

`VirtualAnimal`抽象类将定义抽象类方法和抽象实例方法。**抽象类方法**是声明而没有实现的类方法。**抽象实例方法**，也称为抽象方法，是声明而没有实现的实例方法。

### 提示

当我们声明任何两种类型的抽象方法时，我们只声明参数（如果有），然后放一个分号（`;`）。我们根本不使用花括号。我们只能在抽象类中声明抽象方法。任何抽象类的具体子类必须为所有继承的抽象方法提供实现，以成为我们可以使用`new`关键字创建实例的类。

`VirtualAnimal`类将声明以下七个抽象方法，满足特定家族或类型的所有成员的要求。该类只声明它们所需的参数，而不实现方法。子类将负责满足解释的要求。

+   `isAbleToFly`：返回一个布尔值，指示虚拟动物是否能飞。

+   `isRideable`：返回一个布尔值，指示虚拟动物是否可骑。可骑的动物能够被骑乘。

+   `isHerbivore`：返回一个布尔值，指示虚拟动物是否是食草动物。

+   `isCarnivore`：返回一个布尔值，指示虚拟动物是否是肉食动物。

+   `getAverageNumberOfBabies`：返回通常为虚拟动物类型一次出生的平均婴儿数量。

+   `getBaby`：返回虚拟动物类型的婴儿的`String`表示。

+   `getAsciiArt`：返回表示虚拟动物的 ASCII 艺术（基于文本的视觉艺术）的`String`。

`VirtualAnimal`类将定义以下五个方法，满足每个实例的要求。这些将是具体方法，将在`VirtualAnimal`类中编码，并由其所有子类继承。其中一些方法调用先前解释的抽象方法。我们将在稍后详细了解这是如何工作的。

+   printAsciiArt：这将打印`getAsciiArt`方法返回的`String`。

+   `isYoungerThan`：返回一个布尔值，指示`VirtualAnimal`的`age`值是否低于作为参数接收的`VirtualAnimal`实例的年龄。

+   `isOlderThan`：返回一个布尔值，指示`VirtualAnimal`类的`age`值是否大于作为参数接收的`VirtualAnimal`实例的年龄。

+   `printAge`：打印虚拟动物的`age`值。

+   `printAverageNumberOfBabies`：打印通常为虚拟动物一次出生的平均婴儿数量的表示。该方法将考虑由不同具体子类中实现的`getAverageNumberOfBabies`方法返回的值。

`VirtualMammal`类继承自`VirtualAnimal`。当创建新的`VirtualMammal`实例时，我们将不得不指定其年龄和是否怀孕。该类从`VirtualAnimal`超类继承了`age`属性，因此只需要添加一个字段来指定虚拟哺乳动物是否怀孕。请注意，我们将不会在任何时候指定性别，以保持简单。如果我们添加了性别，我们将需要验证以避免雄性怀孕。现在，我们的重点是继承。该类将在创建虚拟哺乳动物时显示一条消息；也就是说，每当执行其构造函数时。

### 提示

每个类都继承自一个类，因此，我们将定义的每个新类都只有一个超类。在这种情况下，我们将始终使用**单一继承**。在 Java 中，一个类不能从多个类继承。

`VirtualDomesticMammal`类继承自`VirtualMammal`。当创建新的`VirtualDomesticMammal`实例时，我们将不得不指定其名称和最喜欢的玩具。我们给任何家养哺乳动物都起名字，它们总是会挑选一个最喜欢的玩具。有时它们只是选择满足它们破坏欲望的物品。在许多情况下，最喜欢的玩具并不一定是我们希望它们选择的玩具（我们的鞋子、运动鞋、拖鞋或电子设备），但让我们专注于我们的类。我们无法改变名称，但可以改变最喜欢的玩具。我们永远不会改变任何家养哺乳动物的名称，但我们绝对可以强迫它改变最喜欢的玩具。该类在创建虚拟家养哺乳动物时显示一条消息。

`VirtualDomesticMammal`类将声明一个`talk`实例方法，该方法将显示一条消息，指示虚拟家养哺乳动物的名称与消息“说了些什么”的连接。每个子类必须以不同的方式让特定的家养哺乳动物说话。鹦鹉确实会说话，但我们将把马的嘶鸣和兔子的牙齿咕噜声视为它们在说话。请注意，在这种情况下，`talk`实例方法在`VirtualDomesticMammal`类中具有具体的实现，而不是抽象的实例方法。子类将能够为此方法提供不同的实现。

`VirtualHorse`类继承自`VirtualDomesticMammal`，并实现了从`VirtualAnimal`超类继承的所有抽象方法，除了`getBaby`和`getAsciiArt`。这两个方法将在`VirtualHorse`的每个子类中实现，以确定马的品种。

我们希望马能够嘶鸣和嘶鸣。因此，我们需要`neigh`和`nicker`方法。马通常在生气时嘶鸣，在快乐时嘶鸣。情况比这更复杂一些，但我们将为我们的示例保持简单。

`neigh`方法必须允许虚拟马执行以下操作：

+   只嘶鸣一次

+   特定次数的嘶鸣

+   与另一个只有一次名字的虚拟家养哺乳动物相邻

+   对另一个只有特定次数名字的虚拟家养哺乳动物嘶鸣

`nicker`方法必须允许虚拟马执行以下操作：

+   只嘶鸣一次

+   特定次数的嘶鸣

+   只对另一个只有一次名字的虚拟家养哺乳动物嘶鸣

+   对另一个只有特定次数名字的虚拟家养哺乳动物嘶鸣

此外，马可以愉快地或愤怒地嘶鸣或嘶鸣。我们可以有一个`neigh`方法，其中许多参数具有默认值，或者有许多`neigh`方法。Java 9 提供了许多机制来解决虚拟马必须能够嘶鸣的不同方式的挑战。我们将对`neigh`和`nicker`方法应用相同的解决方案。

当我们为任何虚拟马调用`talk`方法时，我们希望它开心地嘶鸣一次。我们不希望显示在`VirtualDomesticMammal`类中引入的`talk`方法中定义的消息。因此，`VirtualHorse`类必须用自己的定义覆盖继承的`talk`方法。

我们想知道虚拟马属于哪个品种。因此，我们将定义一个`getBreed`抽象方法。`VirtualHorse`的每个子类在调用此方法时必须返回适当的`String`名称。`VirtualHorse`类将定义一个名为`printBreed`的方法，该方法使用`getBreed`方法来检索名称并打印品种。

到目前为止，我们提到的所有类都是抽象类。我们不能创建它们的实例。`AmericanQuarterHorse`、`ShireHorse`和`Thoroughbred`类继承自`VirtualHorse`类，并实现了继承的`getBaby`、`getAsciiArt`和`getBreed`方法。此外，它们的构造函数将打印一条消息，指示我们正在创建相应类的实例。这三个类都是具体类，我们可以创建它们的实例。

我们将稍后使用`VirtualBird`、`VirtualDomesticBird`、`Cockatiel`、`VirtualDomesticCat`和`MaineCoon`类。首先，我们将在 Java 9 中创建基类`VirtualAnimal`抽象类，然后使用简单的继承创建子类，直到`VirtualHorse`类。我们将重写方法和重载方法以满足所有要求。我们将利用多态性，这是面向对象编程中非常重要的特性，我们将在 JShell 中使用创建的类时了解到。当然，我们将深入研究分析不同类时引入的许多主题。

以下 UML 图显示了我们将在本章中编写的所有抽象类的成员：`VirtualAnimal`、`VirtualMammal`、`VirtualDomesticMammal`和`VirtualHorse`。我们将在下一章中编写其他类，并稍后将它们的成员添加到图中。我们使用斜体文本格式表示抽象方法。请记住，公共成员以加号（**+**）作为前缀。一个类有一个受保护的成员，使用井号作为前缀（**#**）。我们将使用粗体文本格式表示覆盖超类中现有方法的方法。在这种情况下，`VirtualHorse`类覆盖了`talk()`方法。

![理解继承](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00066.jpeg)

在上一个 UML 图中，我们将注意到以下约定。我们将在包括类成员的所有 UML 图中使用这些约定。

+   构造函数与类名相同，不指定任何返回类型。它们始终是方法部分中列出的第一个方法。

+   字段的类型在字段名称之后用冒号（**：**）分隔。

+   每个方法的参数列表中的参数都用分号（**;**）分隔。

+   方法的返回类型在参数列表之后用冒号（**：**）分隔。

+   我们始终使用 Java 类型名称。

# 创建抽象基类

首先，我们将创建抽象类，该类将成为其他类的基类。以下是 Java 9 中`VirtualAnimal`抽象基类的代码。`class`之前的`abstract`关键字表示我们正在创建一个抽象类。示例的代码文件包含在`java_9_oop_chapter_06_01`文件夹中的`example06_01.java`文件中。

```java
public abstract class VirtualAnimal {
    public final int age;

    public VirtualAnimal(int age) {
        this.age = age;
        System.out.println("VirtualAnimal created.");
    }

    public abstract boolean isAbleToFly();

    public abstract boolean isRideable();

    public abstract boolean isHerbivore();

    public abstract boolean isCarnivore();

    public abstract int getAverageNumberOfBabies();

    public abstract String getBaby();

    public abstract String getAsciiArt();

    public void printAsciiArt() {
        System.out.println(getAsciiArt());
    }

    public void printAverageNumberOfBabies() {
        System.out.println(new String(
            new char[getAverageNumberOfBabies()]).replace(
                "\0", getBaby()));
    }

    public void printAge() {
        System.out.println(
            String.format("I am %d years old", age));
    }

    public boolean isYoungerThan(VirtualAnimal otherAnimal) {
        return age < otherAnimal.age; 
    }

    public boolean isOlderThan(VirtualAnimal otherAnimal) {
        return age > otherAnimal.age;
    }
}
```

前面的类声明了一个名为`age`的`int`类型的不可变字段。构造函数需要一个`age`值来创建类的实例，并打印一条消息指示创建了一个虚拟动物。该类声明了以下抽象方法，这些方法在返回类型之前包含`abstract`关键字，以便让 Java 知道我们只想声明所需的参数，并且不会为这些方法提供实现。我们已经解释了这些方法的目标，它们将在`VirtualAnimal`的子类中实现。 

+   `isAbleToFly`

+   `isRideable`

+   `isHerbivore`

+   `isCarnivore`

+   获取平均婴儿数量

+   `getBaby`

+   `getAsciiArt`

此外，该类声明了以下五个方法：

+   打印 AsciiArt：此方法调用`System.out.println`来打印`getAsciiArt`方法返回的`String`。

+   `printAverageNumberOfBabies`：此方法创建一个新的`char`数组，其元素数量等于`getAverageNumberOfBabies`方法返回的值。然后，代码创建一个初始化为`char`数组的新`String`，并调用`replace`方法来用`getBaby`方法返回的`String`替换每个`"\0"`。这样，我们生成一个`String`，其中包含`getBaby`返回的`String`的`getAverageNumberOfBabies`倍。代码调用`System.out.println`来打印生成的`String`。

+   打印年龄：此方法调用`System.out.println`来打印使用`String.format`生成的`String`，其中包括`age`不可变字段的值。

+   `isYoungerThan`：此方法在`otherAnimal`参数中接收一个`VirtualAnimal`实例，并返回在此实例的`age`字段值和`otherAnimal.age`之间应用小于运算符的结果。这样，只有当此实例的年龄小于`otherAnimal`的年龄时，该方法才会返回`true`。

+   `isOlderThan`：此方法在`otherAnimal`参数中接收一个`VirtualAnimal`实例，并返回在此实例的`age`字段值和`otherAnimal.age`之间应用大于运算符的结果。这样，只有当此实例的年龄大于`otherAnimal`的年龄时，该方法才会返回`true`。

如果我们在声明`VirtualAnimal`类之后在 JShell 中执行以下行，Java 将生成致命错误，并指出`VirtualAnimal`类是抽象的，不能被实例化。示例的代码文件包含在`java_9_oop_chapter_06_01`文件夹中的`example06_02.java`文件中。

```java
VirtualAnimal virtualAnimal1 = new VirtualAnimal(5);
```

以下屏幕截图显示了在 JShell 中执行上一个代码的结果：

![创建抽象基类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00067.jpeg)

# 声明从另一个类继承的类

现在我们将创建另一个抽象类。具体来说，我们将创建一个最近创建的`VirtualAnimal`抽象类的子类。以下行显示了扩展`VirtualAnimal`类的`VirtualMammal`抽象类的代码。请注意`abstract class`关键字后面跟着类名`VirtualMammal`，`extends`关键字和`VirtualAnimal`，即超类。

在类定义中，跟在`extends`关键字后面的类名表示新类从中继承的超类。示例的代码文件包含在`java_9_oop_chapter_06_01`文件夹中的`example06_03.java`文件中。

```java
public abstract class VirtualMammal extends VirtualAnimal {
    public boolean isPregnant;

    public VirtualMammal(int age, boolean isPregnant) {
 super(age);
        this.isPregnant = isPregnant;
        System.out.println("VirtualMammal created.");
    }

    public VirtualMammal(int age) {
        this(age, false);
    }
}
```

`VirtualMammal`抽象类继承了先前声明的`VirtualAnimal`抽象类的成员，并添加了一个名为`isPregnant`的新的`boolean`可变字段。新的抽象类声明了两个构造函数。其中一个构造函数需要一个`age`值来创建类的实例，就像`VirtualAnimal`构造函数一样。另一个构造函数需要`age`和`isPregnant`值。

如果我们只用一个 `age` 参数创建这个类的实例，Java 将使用第一个构造函数。如果我们用两个参数创建这个类的实例，一个是 `age` 的 `int` 值，一个是 `isPregnant` 的 `boolean` 值，Java 将使用第二个构造函数。

### 提示

我们已经重载了构造函数并提供了两个不同的构造函数。我们不会使用 `new` 关键字来使用这些构造函数，因为我们正在声明一个抽象类。但是，我们将能够通过使用 `super` 关键字从子类中调用这些构造函数。

需要 `isPregnant` 参数的第一个构造函数使用 `super` 关键字来调用基类或超类中的构造函数，也就是在 `VirtualAnimal` 类中定义的需要 `age` 参数的构造函数。在超类中定义的构造函数执行完毕后，代码会设置 `isPregnant` 可变字段的值，并打印一条消息，指示已创建了一个虚拟哺乳动物。

### 提示

我们使用 `super` 关键字来引用超类，并且可以使用这个关键字来调用超类中定义的任何构造函数。在 Java 9 中，子类不会继承其超类的构造函数。在其他编程语言中，子类会继承构造函数或初始化程序，因此，非常重要的是要理解在 Java 9 中这种情况并不会发生。

第二个构造函数使用 `this` 关键字来调用先前解释的构造函数，接收 `age` 和 `false` 作为 `isPregnant` 参数的值。

我们将创建另一个抽象类。具体来说，我们将创建一个最近创建的 `VirtualMammal` 抽象类的子类。以下几行显示了扩展 `VirtualMammal` 类的 `VirtualDomesticMammal` 抽象类的代码。注意 `abstract class` 关键字后面跟着类名 `VirtualDomesticMammal`，`extends` 关键字和 `VirtualMammal`，也就是超类。跟在 `extends` 关键字后面的类名指示了新类在类定义中继承的超类。示例的代码文件包含在 `java_9_oop_chapter_06_01` 文件夹中的 `example06_04.java` 文件中。

```java
public abstract class VirtualDomesticMammal extends VirtualMammal {
    public final String name;
    public String favoriteToy;

    public VirtualDomesticMammal(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
 super(age, isPregnant);
        this.name = name;
        this.favoriteToy = favoriteToy;
        System.out.println("VirtualDomesticMammal created.");
    }

    public VirtualDomesticMammal(
        int age, 
        String name, 
        String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public void talk() {
        System.out.println(
            String.format("%s: says something", name));
    }
}
```

`VirtualDomesticMammal` 抽象类继承了先前声明的 `VirtualMammal` 抽象类的成员。重要的是要理解，新类也继承了超类从其超类继承的成员，也就是从 `VirtualAnimal` 抽象类继承的成员。例如，我们的新类继承了在 `VirtualAnimal` 抽象类中声明的 `age` 不可变字段以及在这个类中声明的所有其他成员。

`VirtualDomesticMammal` 类添加了一个名为 `name` 的新的不可变字段和一个名为 `favoriteToy` 的新的可变字段。这个新的抽象类声明了两个构造函数。其中一个构造函数需要四个参数来创建类的实例：`age`、`isPregnant`、`name` 和 `favoriteToy`。另一个构造函数需要除了 `isPregnant` 之外的所有参数。

需要四个参数的第一个构造函数使用 `super` 关键字来调用基类或超类中的构造函数，也就是在 `VirtualMammal` 类中定义的需要两个参数 `age` 和 `isPregnant` 的构造函数。在超类中定义的构造函数执行完毕后，代码会设置 `name` 和 `favoriteToy` 字段的值，并打印一条消息，指示已创建了一个虚拟家养哺乳动物。

第二个构造函数使用 `this` 关键字来调用先前解释的构造函数，接收参数和 `false` 作为 `isPregnant` 参数的值。

最后，这个类声明了一个`talk`方法，显示了一个以`name`值开头，后跟一个冒号(`:`)和`says something`的消息。请注意，我们可以在`VirtualDomesticMammal`的任何子类中覆盖这个方法，因为每个虚拟家养哺乳动物都有自己不同的说话方式。

# 覆盖和重载方法

Java 允许我们多次使用相同的方法名定义不同参数的方法。这个特性被称为**方法重载**。在之前创建的抽象类中，我们重载了构造函数。

例如，我们可以利用方法重载来定义`VirtualHorse`抽象类中必须定义的`neigh`和`nicker`方法的多个版本。然而，在重载方法时，避免代码重复是非常重要的。

有时，我们在一个类中定义一个方法，我们知道子类可能需要提供一个不同版本的方法。一个明显的例子就是我们在`VirtualDomesticMammal`类中定义的`talk`方法。当一个子类提供了一个与超类中同名、参数和返回类型相同的方法的不同实现时，我们称之为**覆盖**方法。当我们覆盖一个方法时，子类中的实现会覆盖超类中提供的代码。

```java
VirtualHorse abstract class that extends the VirtualDomesticMammal class. Note the abstract class keywords followed by the class name, VirtualHorse, the extends keyword, and VirtualDomesticMammal, that is, the superclass. We will split the code for this class in many snippets to make it easier to analyze. The code file for the sample is included in the java_9_oop_chapter_06_01 folder, in the example06_05.java file.
```

```java
public abstract class VirtualHorse extends VirtualDomesticMammal {
    public VirtualHorse(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
 super(age, isPregnant, name, favoriteToy);
        System.out.println("VirtualHouse created.");        
    }

    public VirtualHorse(
        int age, 
        String name, 
        String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public boolean isAbleToFly() {
        return false;
    }

    public boolean isRideable() {
        return true;
    }

    public boolean isHerbivore() {
        return true;
    }

    public boolean isCarnivore() {
        return false;
    }

    public int getAverageNumberOfBabies() {
        return 1;
    }
```

```java
VirtualHorse abstract class that extends the VirtualDomesticMammal class. The code file for the sample is included in the java_9_oop_chapter_06_01 folder, in the example06_05.java file.
```

```java
    public abstract String getBreed();

    public void printBreed() {
        System.out.println(getBreed());
    }

    protected void printSoundInWords(
        String soundInWords, 
        int times, 
        VirtualDomesticMammal otherDomesticMammal,
        boolean isAngry) {
        String message = String.format("%s%s: %s%s",
            name,
            otherDomesticMammal == null ? 
                "" : String.format(" to %s ", otherDomesticMammal.name),
            isAngry ?
                "Angry " : "",
            new String(new char[times]).replace("\0", soundInWords));
        System.out.println(message);
    }
```

```java
VirtualHorse abstract class that extends the VirtualDomesticMammal class. The code file for the sample is included in the java_9_oop_chapter_06_01 folder, in the example06_05.java file.
```

```java
    public void printNeigh(int times, 
        VirtualDomesticMammal otherDomesticMammal,
        boolean isAngry) {
        printSoundInWords("Neigh ", times, otherDomesticMammal, isAngry);
    }

    public void neigh() {
        printNeigh(1, null, false);
    }

    public void neigh(int times) {
        printNeigh(times, null, false);
    }

    public void neigh(int times, 
        VirtualDomesticMammal otherDomesticMammal) {
        printNeigh(times, otherDomesticMammal, false);
    }

    public void neigh(int times, 
        VirtualDomesticMammal otherDomesticMammal, 
        boolean isAngry) {
        printNeigh(times, otherDomesticMammal, isAngry);
    }

    public void printNicker(int times, 
        VirtualDomesticMammal otherDomesticMammal,
        boolean isAngry) {
        printSoundInWords("Nicker ", times, otherDomesticMammal, isAngry);
    }

    public void nicker() {
        printNicker(1, null, false);
    }

    public void nicker(int times) {
        printNicker(times, null, false);
    }

    public void nicker(int times, 
        VirtualDomesticMammal otherDomesticMammal) {
        printNicker(times, otherDomesticMammal, false);
    }

    public void nicker(int times, 
        VirtualDomesticMammal otherDomesticMammal, 
        boolean isAngry) {
        printNicker(times, otherDomesticMammal, isAngry);
    }

 @Override
 public void talk() {
 nicker();
 }
}
```

`VirtualHorse`类覆盖了从`VirtualDomesticMammal`继承的`talk`方法。代码只是调用了没有参数的`nicker`方法，因为马不会说话，它们会嘶叫。这个方法不会调用其超类中同名的方法；也就是说，我们没有使用`super`关键字来调用`VirtualDomesticMammal`中定义的`talk`方法。

### 提示

我们在方法声明之前使用`@Override`注解来通知 Java 9 编译器，该方法意在覆盖在超类中声明的同名方法。当我们覆盖方法时，添加这个注解并不是强制的，但是将其包括进去是一个好习惯，我们在覆盖方法时总是会使用它，因为它有助于防止错误。例如，如果我们在方法名和参数中写成了`tak()`而不是`talk()`，使用`@Override`注解会使 Java 9 编译器生成一个错误，因为标记为`@Override`的`talk`方法未能成功覆盖其中一个超类中具有相同名称和参数的方法。

`nicker`方法被重载了四次，使用了不同的参数声明。以下几行展示了类体中包括的四个不同声明：

```java
public void nicker()
public void nicker(int times) 
public void nicker(int times, 
    VirtualDomesticMammal otherDomesticMammal) 
public void nicker(int times, 
    VirtualDomesticMammal otherDomesticMammal, 
    boolean isAngry)
```

这样，我们可以根据提供的参数调用任何定义的`nicker`方法。这四个方法最终都会调用`printNicker`公共方法，使用不同的默认值来调用具有相同名称但未在`nicker`调用中提供的参数。该方法调用`printSoundInWords`公共方法，将`"Nicker "`作为`soundInWords`参数的值，并将其他参数设置为接收到的具有相同名称的参数。这样，`printNicker`方法根据指定的次数(`times`)、可选的目标虚拟家养哺乳动物(`otherDomesticMammal`)以及马是否生气(`isAngry`)来构建并打印嘶叫消息。

`VirtualHorse`类对`neigh`方法也使用了类似的方法。这个方法也被重载了四次，使用了不同的参数声明。以下几行展示了类体中包括的四个不同声明。它们使用了我们刚刚分析过的`nicker`方法的相同参数。

```java
public void neigh()
public void neigh(int times) 
public void neigh(int times, 
    VirtualDomesticMammal otherDomesticMammal) 
public void neigh(int times, 
    VirtualDomesticMammal otherDomesticMammal, 
    boolean isAngry)
```

这样，我们可以根据提供的参数调用任何定义的`neigh`方法。这四种方法最终会使用不同的默认值调用`printNeigh`公共方法，这些默认值是与调用`nicker`时未提供的同名参数。该方法调用`printSoundInWords`公共方法，将`"Neigh "`作为`soundInWords`参数的值，并将其他参数设置为具有相同名称的接收参数。

# 测试你的知识

1.  在 Java 9 中，一个子类：

1.  继承其超类的所有构造函数。

1.  不继承任何构造函数。

1.  从其超类继承具有最大数量参数的构造函数。

1.  我们可以声明抽象方法：

1.  在任何类中。

1.  只在抽象类中。

1.  只在抽象类的具体子类中。

1.  任何抽象类的具体子类：

1.  必须为所有继承的抽象方法提供实现。

1.  必须为所有继承的构造函数提供实现。

1.  必须为所有继承的抽象字段提供实现。

1.  以下哪行声明了一个名为`Dog`的抽象类，作为`VirtualAnimal`的子类：

1.  `public abstract class Dog subclasses VirtualAnimal`

1.  `public abstract Dog subclasses VirtualAnimal`

1.  `public abstract class Dog extends VirtualAnimal`

1.  在方法声明之前指示 Java 9 编译器该方法意味着重写超类中同名方法的注解是：

1.  `@Overridden`

1.  `@OverrideMethod`

1.  `@Override`

# 总结

在本章中，您学习了抽象类和具体类之间的区别。我们学会了如何利用简单的继承来专门化基本抽象类。我们设计了许多类，从上到下使用链接的构造函数，不可变字段，可变字段和实例方法。

然后我们在 JShell 中编写了许多这些类，利用了 Java 9 提供的不同特性。我们重载了构造函数，重写和重载了实例方法，并利用了一个特殊的注解来重写方法。

现在您已经了解了继承，抽象，扩展和专门化，我们准备完成编写其他类，并了解如何使用类型转换和多态，这是我们将在下一章讨论的主题。


# 第七章：成员继承和多态

在本章中，我们将学习 Java 9 中面向对象编程最激动人心的特性之一：多态。我们将编写许多类，然后在 JShell 中使用它们的实例，以了解对象如何呈现许多不同的形式。我们将：

+   创建从抽象超类继承的具体类

+   使用子类的实例进行操作

+   理解多态。

+   控制子类是否可以覆盖成员

+   控制类是否可以被子类化

+   使用执行与不同子类实例的操作的方法

# 创建从抽象超类继承的具体类

在上一章中，我们创建了一个名为`VirtualAnimal`的抽象基类，然后编写了以下三个抽象子类：`VirtualMammal`、`VirtualDomesticMammal`和`VirtualHorse`。现在，我们将编写以下三个具体类。每个类代表不同的马种，是`VirtualHorse`抽象类的子类。

+   `AmericanQuarterHorse`: 这个类表示属于美国四分之一马品种的虚拟马。

+   `ShireHorse`: 这个类表示属于夏尔马品种的虚拟马。

+   `Thoroughbred`: 这个类表示属于纯种赛马品种的虚拟马。

这三个具体类将实现它们从抽象超类继承的以下三个抽象方法：

+   `String getAsciiArt()`: 这个抽象方法是从`VirtualAnimal`抽象类继承的。

+   `String getBaby()`: 这个抽象方法是从`VirtualAnimal`抽象类继承的。

+   `String getBreed()`: 这个抽象方法是从`VirtualHorse`抽象类继承的。

以下 UML 图表显示了我们将编写的三个具体类`AmericanQuarterHorse`、`ShireHorse`和`Thoroughbred`的成员：我们不使用粗体文本格式来表示这三个具体类将声明的三个方法，因为它们不是覆盖方法；它们是实现类继承的抽象方法。

![创建从抽象超类继承的具体类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00068.jpeg)

首先，我们将创建`AmericanQuarterHorse`具体类。以下行显示了 Java 9 中此类的代码。请注意，在`class`之前没有`abstract`关键字，因此，我们的类必须确保实现所有继承的抽象方法。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
public class AmericanQuarterHorse extends VirtualHorse {
    public AmericanQuarterHorse(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("AmericanQuarterHorse created.");
    }

    public AmericanQuarterHorse(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public String getBaby() {
        return "AQH baby ";
    }

    public String getBreed() {
        return "American Quarter Horse";
    }

    public String getAsciiArt() {
        return
            "     >>\\.\n" +
            "    /*  )`.\n" + 
            "   // _)`^)`.   _.---. _\n" +
            "  (_,' \\  `^-)''      `.\\\n" +
            "        |              | \\\n" +
            "        \\              / |\n" +
            "       / \\  /.___.'\\  (\\ (_\n" +
            "      < ,'||     \\ |`. \\`-'\n" +
            "       \\\\ ()      )|  )/\n" +
            "       |_>|>     /_] //\n" +
            "         /_]        /_]\n";
    }
}
```

现在我们将创建`ShireHorse`具体类。以下行显示了 Java 9 中此类的代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
public class ShireHorse extends VirtualHorse {
    public ShireHorse(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("ShireHorse created.");
    }

    public ShireHorse(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public String getBaby() {
        return "ShireHorse baby ";
    }

    public String getBreed() {
        return "Shire Horse";
    }

    public String getAsciiArt() {
        return
            "                        ;;\n" + 
            "                      .;;'*\\\n" + 
            "           __       .;;' ' \\\n" +
            "         /'  '\\.~~.~' \\ /'\\.)\n" +
            "      ,;(      )    /  |\n" + 
            "     ,;' \\    /-.,,(   )\n" +
            "          ) /|      ) /|\n" +    
            "          ||(_\\     ||(_\\\n" +    
            "          (_\\       (_\\\n";
    }
}
```

最后，我们将创建`Thoroughbred`具体类。以下行显示了 Java 9 中此类的代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
public class Thoroughbred extends VirtualHorse {
    public Thoroughbred(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("Thoroughbred created.");
    }

    public Thoroughbred(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public String getBaby() {
        return "Thoroughbred baby ";
    }

    public String getBreed() {
        return "Thoroughbred";
    }

    public String getAsciiArt() {
        return
            "             })\\-=--.\n" +  
            "            // *._.-'\n" +
            "   _.-=-...-'  /\n" +
            " {{|   ,       |\n" +
            " {{\\    |  \\  /_\n" +
            " }} \\ ,'---'\\___\\\n" +
            " /  )/\\\\     \\\\ >\\\n" +
            "   //  >\\     >\\`-\n" +
            "  `-   `-     `-\n";
    }
}
```

在我们编码的其他子类中发生的情况，我们为这三个具体类定义了多个构造函数。第一个构造函数需要四个参数，使用`super`关键字调用基类或超类中的构造函数，也就是在`VirtualHorse`类中定义的构造函数。在超类中定义的构造函数执行完毕后，代码会打印一条消息，指示已创建了每个具体类的实例。每个类中定义的构造函数会打印不同的消息。

第二个构造函数使用`this`关键字调用先前解释的构造函数，并使用`false`作为`isPregnant`参数的值。

每个类在`getBaby`和`getBreed`方法的实现中返回不同的`String`。此外，每个类在`getAsciiArt`方法的实现中返回虚拟马的不同 ASCII 艺术表示。

# 理解多态性

我们可以使用相同的方法，即使用相同名称和参数的方法，根据调用方法的类来引起不同的事情发生。在面向对象编程中，这个特性被称为**多态性**。多态性是对象能够呈现多种形式的能力，我们将通过使用先前编写的具体类的实例来看到它的作用。

以下几行创建了一个名为`american`的`AmericanQuarterHorse`类的新实例，并使用了一个不需要`isPregnant`参数的构造函数。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
AmericanQuarterHorse american = 
    new AmericanQuarterHorse(
        8, "American", "Equi-Spirit Ball");
american.printBreed();
```

以下几行显示了我们在 JShell 中输入前面的代码后，不同构造函数显示的消息：

```java
VirtualAnimal created.
VirtualMammal created.
VirtualDomesticMammal created.
VirtualHorse created.
AmericanQuarterHorse created.

```

`AmericanQuarterHorse`中定义的构造函数调用了其超类的构造函数，即`VirtualHorse`类。请记住，每个构造函数都调用其超类构造函数，并打印一条消息，指示创建了类的实例。我们没有五个不同的实例；我们只有一个实例，它调用了五个不同类的链接构造函数，以执行创建`AmericanQuarterHorse`实例所需的所有必要初始化。

如果我们在 JShell 中执行以下几行，它们都会显示`true`，因为`american`属于`VirtualAnimal`、`VirtualMammal`、`VirtualDomesticMammal`、`VirtualHorse`和`AmericanQuarterHorse`类。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
System.out.println(american instanceof VirtualAnimal);
System.out.println(american instanceof VirtualMammal);
System.out.println(american instanceof VirtualDomesticMammal);
System.out.println(american instanceof VirtualHorse);
System.out.println(american instanceof AmericanQuarterHorse);
```

前面几行的结果意味着`AmericanQuarterHorse`类的实例，其引用保存在类型为`AmericanQuarterHorse`的`american`变量中，可以采用以下任何一个类的实例形式：

+   虚拟动物

+   虚拟哺乳动物

+   虚拟家养哺乳动物

+   虚拟马

+   美国四分之一马

以下屏幕截图显示了在 JShell 中执行前面几行的结果：

![理解多态性](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00069.jpeg)

我们在`VirtualHorse`类中编写了`printBreed`方法，并且我们没有在任何子类中重写此方法。以下是`printBreed`方法的代码：

```java
public void printBreed() {
    System.out.println(getBreed());
}
```

代码打印了`getBreed`方法返回的`String`，在同一类中声明为抽象方法。继承自`VirtualHorse`的三个具体类实现了`getBreed`方法，它们每个都返回不同的`String`。当我们调用`american.printBreed`方法时，JShell 显示`American Quarter Horse`。

以下几行创建了一个名为`zelda`的`ShireHorse`类的实例。请注意，在这种情况下，我们使用需要`isPregnant`参数的构造函数。与创建`AmericanQuarterHorse`类的实例时一样，JShell 将显示每个执行的构造函数的消息，这是由我们编写的链接构造函数的结果。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
ShireHorse zelda =
    new ShireHorse(9, true, 
        "Zelda", "Tennis Ball");
```

接下来的几行调用了`american`（`AmericanQuarterHorse`的实例）和`zelda`（`ShireHorse`的实例）的`printAverageNumberOfBabies`和`printAsciiArt`实例方法。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
american.printAverageNumberOfBabies();
american.printAsciiArt();
zelda.printAverageNumberOfBabies();
zelda.printAsciiArt();
```

我们在`VirtualAnimal`类中编写了`printAverageNumberOfBabies`和`printAsciiArt`方法，并且没有在任何子类中对它们进行重写。因此，当我们为`american`或`Zelda`调用这些方法时，Java 将执行`VirtualAnimal`类中定义的代码。

`printAverageNumberOfBabies`方法使用`getAverageNumberOfBabies`返回的`int`值和`getBaby`方法返回的`String`来生成代表虚拟动物平均幼崽数量的`String`。`VirtualHorse`类实现了继承的`getAverageNumberOfBabies`抽象方法，其中的代码返回`1`。`AmericanQuarterHorse`和`ShireHorse`类实现了继承的`getBaby`抽象方法，其中的代码返回代表虚拟马种类的幼崽的`String`："AQH baby"和"ShireHorse baby"。因此，我们对`printAverageNumberOfBabies`方法的调用将在每个实例中产生不同的结果，因为它们属于不同的类。

`printAsciiArt`方法使用`getAsciiArt`方法返回的`String`来打印代表虚拟马的 ASCII 艺术。`AmericanQuarterHorse`和`ShireHorse`类实现了继承的`getAsciiArt`抽象方法，其中的代码返回适用于每个类所代表的虚拟马的 ASCII 艺术的`String`。因此，我们对`printAsciiArt`方法的调用将在每个实例中产生不同的结果，因为它们属于不同的类。

以下屏幕截图显示了在 JShell 中执行前几行的结果。两个实例对在`VirtualAnimal`抽象类中编写的两个方法运行相同的代码。然而，每个类为最终被调用以生成结果并导致输出差异的方法提供了不同的实现。

![理解多态性](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00070.jpeg)

以下行创建了一个名为`willow`的`Thoroughbred`类的实例，然后调用了它的`printAsciiArt`方法。与之前一样，JShell 将显示每个构造函数执行的消息，这是我们编写的链式构造函数的结果。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
Thoroughbred willow = 
    new Thoroughbred(5,
        "Willow", "Jolly Ball");
willow.printAsciiArt();
```

以下屏幕截图显示了在 JShell 中执行前几行的结果。新实例来自一个提供了`getAsciiArt`方法不同实现的类，因此，我们将看到与之前对其他实例调用相同方法时所看到的不同 ASCII 艺术。

![理解多态性](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00071.jpeg)

以下行调用了名为`willow`的实例的`neigh`方法，使用不同数量的参数。这样，我们利用了使用不同参数重载了四次的`neigh`方法。请记住，我们在`VirtualHorse`类中编写了这四个`neigh`方法，而`Thoroughbred`类通过其继承树从这个超类继承了重载的方法。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_01.java`文件中。

```java
willow.neigh();
willow.neigh(2);
willow.neigh(2, american);
willow.neigh(3, zelda, true);
american.nicker();
american.nicker(2);
american.nicker(2, willow);
american.nicker(3, willow, true);
```

以下屏幕截图显示了在 JShell 中使用不同参数调用`neigh`和`nicker`方法的结果：

![理解多态性](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00072.jpeg)

我们为名为`willow`的`Thoroughbred`实例调用了`VirtualHorse`类中定义的`neigh`方法的四个版本。调用`neigh`方法的第三行和第四行指定了类型为`VirtualDomesticMammal`的`otherDomesticMammal`参数的值。第三行指定`american`作为`otherDomesticMammal`的值，第四行指定相同参数的值为`zelda`。`AmericanQuarterHorse`和`ShireHorse`具体类都是`VirtualHorse`的子类，`VirtualHorse`是`VirtualDomesticMammal`的子类。因此，我们可以在需要`VirtualDomesticMammal`实例的地方使用`american`和`zelda`作为参数。

然后，我们为名为`american`的`AmericanQuarterHorse`实例调用了`VirtualHorse`类中定义的`nicker`方法的四个版本。调用`nicker`方法的第三行和第四行指定了类型为`VirtualDomesticMammal`的`otherDomesticMammal`参数的值为`willow`。`Thoroughbred`具体类也是`VirtualHorse`的子类，`VirtualHorse`是`VirtualDomesticMammal`的子类。因此，我们可以在需要`VirtualDomesticMammal`实例的地方使用`willow`作为参数。

# 控制子类中成员的可覆盖性

我们将编写`VirtualDomesticCat`抽象类及其具体子类：`MaineCoon`。然后，我们将编写`VirtualBird`抽象类、其`VirtualDomesticBird`抽象子类和`Cockatiel`具体子类。最后，我们将编写`VirtualDomesticRabbit`具体类。在编写这些类时，我们将使用 Java 9 的功能，允许我们决定子类是否可以覆盖特定成员。

所有虚拟家猫都必须能够说话，因此，我们将覆盖从`VirtualDomesticMammal`继承的`talk`方法，以打印代表猫叫声的单词：“`"Meow"`”。我们还希望提供一个方法来指定打印`"Meow"`的次数。因此，此时我们意识到我们可以利用在`VirtualHorse`类中声明的`printSoundInWords`方法。

我们无法在`VirtualDomesticCat`抽象类中访问此实例方法，因为它不是从`VirtualHorse`继承的。因此，我们将把这个方法从`VirtualHorse`类移动到它的超类：`VirtualDomesticMammal`。

### 提示

我们将在不希望在子类中被覆盖的方法的返回类型前使用`final`关键字。当一个方法被标记为最终方法时，子类无法覆盖该方法，如果它们尝试这样做，Java 9 编译器将显示错误。

并非所有的鸟类在现实生活中都能飞。然而，我们所有的虚拟鸟类都能飞，因此，我们将实现继承的`isAbleToFly`抽象方法作为一个返回`true`的最终方法。这样，我们确保所有继承自`VirtualBird`抽象类的类都将始终运行此代码以进行`isAbleToFly`方法，并且它们将无法对其进行覆盖。

以下 UML 图显示了我们将编写的新抽象和具体类的成员。此外，该图显示了从`VirtualHorse`抽象类移动到`VirtualDomesticMammal`抽象类的`printSoundInWords`方法。

![控制子类中成员的可覆盖性](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00073.jpeg)

首先，我们将创建`VirtualDomesticMammal`抽象类的新版本。我们将添加在`VirtualHorse`抽象类中的`printSoundInWords`方法，并使用`final`关键字指示我们不希望允许子类覆盖此方法。以下行显示了`VirtualDomesticMammal`类的新代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public abstract class VirtualDomesticMammal extends VirtualMammal {
    public final String name;
    public String favoriteToy;

    public VirtualDomesticMammal(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant);
        this.name = name;
        this.favoriteToy = favoriteToy;
        System.out.println("VirtualDomesticMammal created.");
    }

    public VirtualDomesticMammal(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

 protected final void printSoundInWords(
 String soundInWords, 
 int times, 
 VirtualDomesticMammal otherDomesticMammal,
 boolean isAngry) {
        String message = String.format("%s%s: %s%s",
            name,
            otherDomesticMammal == null ? 
                "" : String.format(" to %s ", otherDomesticMammal.name),
            isAngry ?
                "Angry " : "",
            new String(new char[times]).replace("\0", soundInWords));
        System.out.println(message);
    }

    public void talk() {
        System.out.println(
            String.format("%s: says something", name));
    }
}
```

在输入上述行后，JShell 将显示以下消息：

```java
|    update replaced class VirtualHorse which cannot be referenced until this error is corrected:
|      printSoundInWords(java.lang.String,int,VirtualDomesticMammal,boolean) in VirtualHorse cannot override printSoundInWords(java.lang.String,int,VirtualDomesticMammal,boolean) in VirtualDomesticMammal
|        overridden method is final
|          protected void printSoundInWords(String soundInWords, int times,
|          ^---------------------------------------------------------------...
|    update replaced class AmericanQuarterHorse which cannot be referenced until class VirtualHorse is declared
|    update replaced class ShireHorse which cannot be referenced until class VirtualHorse is declared
|    update replaced class Thoroughbred which cannot be referenced until class VirtualHorse is declared
|    update replaced variable american which cannot be referenced until class AmericanQuarterHorse is declared
|    update replaced variable zelda which cannot be referenced until class ShireHorse is declared
|    update replaced variable willow which cannot be referenced until class Thoroughbred is declared
|    update overwrote class VirtualDomesticMammal

```

JShell 告诉我们，`VirtualHorse`类及其子类在我们纠正该类的错误之前不能被引用。该类声明了`printSoundInWords`方法，并在`VirtualDomesticMammal`类中重写了最近添加的具有相同名称和参数的方法。我们在新声明中使用了`final`关键字，以确保任何子类都不能覆盖它，因此，Java 编译器生成了 JShell 显示的错误消息。

现在，我们将创建`VirtualHorse`抽象类的新版本。以下行显示了删除了`printSoundInWords`方法并使用`final`关键字确保许多方法不能被任何子类覆盖的新版本。在下面的行中，使用`final`关键字避免方法被覆盖的声明已经被突出显示。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public abstract class VirtualHorse extends VirtualDomesticMammal {
    public VirtualHorse(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("VirtualHorse created.");        
    }

    public VirtualHorse(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

 public final boolean isAbleToFly() {
        return false;
    }

 public final boolean isRideable() {
        return true;
    }

 public final boolean isHerbivore() {
        return true;
    }

 public final boolean isCarnivore() {
        return false;
    }

    public int getAverageNumberOfBabies() {
        return 1;
    }

    public abstract String getBreed();

 public final void printBreed() {
        System.out.println(getBreed());
    }

 public final void printNeigh(
 int times, 
 VirtualDomesticMammal otherDomesticMammal,
 boolean isAngry) {
        printSoundInWords("Neigh ", times, otherDomesticMammal, isAngry);
    }

 public final void neigh() {
        printNeigh(1, null, false);
    }

 public final void neigh(int times) {
        printNeigh(times, null, false);
    }

 public final void neigh(int times, 
 VirtualDomesticMammal otherDomesticMammal) {
        printNeigh(times, otherDomesticMammal, false);
    }

 public final void neigh(int times, 
 VirtualDomesticMammal otherDomesticMammal, 
 boolean isAngry) {
        printNeigh(times, otherDomesticMammal, isAngry);
    }

 public final void printNicker(int times, 
 VirtualDomesticMammal otherDomesticMammal,
 boolean isAngry) {
        printSoundInWords("Nicker ", times, otherDomesticMammal, isAngry);
    }

 public final void nicker() {
        printNicker(1, null, false);
    }

 public final void nicker(int times) {
        printNicker(times, null, false);
    }

 public final void nicker(int times, 
 VirtualDomesticMammal otherDomesticMammal) {
        printNicker(times, otherDomesticMammal, false);
    }

 public final void nicker(int times, 
 VirtualDomesticMammal otherDomesticMammal, 
 boolean isAngry) {
        printNicker(times, otherDomesticMammal, isAngry);
    }

 @Override
 public final void talk() {
        nicker();
    }
}
```

输入上述行后，JShell 将显示以下消息：

```java
|    update replaced class AmericanQuarterHorse
|    update replaced class ShireHorse
|    update replaced class Thoroughbred
|    update replaced variable american, reset to null
|    update replaced variable zelda, reset to null
|    update replaced variable willow, reset to null
|    update overwrote class VirtualHorse

```

我们替换了`VirtualHorse`类的定义，并且子类也已更新。重要的是要知道，在 JShell 中声明的变量，它们持有`VirtualHorse`的子类实例的引用被设置为 null。

# 控制类的子类化

`final`关键字有一个额外的用法。我们可以在类声明中的`class`关键字之前使用`final`作为修饰符，告诉 Java 我们要生成一个**final 类**，即一个不能被扩展或子类化的类。Java 9 不允许我们为 final 类创建子类。

现在，我们将创建`VirtualDomesticCat`抽象类，然后我们将声明一个名为`MaineCoon`的具体子类作为 final 类。这样，我们将确保没有人能够创建`MaineCoon`的子类。以下行显示了`VirtualDomesticCat`抽象类的代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public abstract class VirtualDomesticCat extends VirtualDomesticMammal {
    public VirtualDomesticCat(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("VirtualDomesticCat created.");        
    }

    public VirtualDomesticCat(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public final boolean isAbleToFly() {
        return false;
    }

    public final boolean isRideable() {
        return false;
    }

    public final boolean isHerbivore() {
        return false;
    }

    public final boolean isCarnivore() {
        return true;
    }

    public int getAverageNumberOfBabies() {
        return 5;
    }

    public final void printMeow(int times) {
        printSoundInWords("Meow ", times, null, false);
    }

    @Override
    public final void talk() {
        printMeow(1);
    }
}
```

`VirtualDomesticCat`抽象类将从`VirtualDomesticMammal`超类继承的许多抽象方法实现为 final 方法，并用 final 方法重写了`talk`方法。因此，我们将无法创建一个覆盖`isAbleToFly`方法返回`true`的`VirtualDomesticCat`子类。我们将无法拥有能够飞行的虚拟猫。

以下行显示了从`VirtualDomesticCat`继承的`MaineCoon`具体类的代码。我们将`MaineCoon`声明为 final 类，并且它重写了继承的`getAverageNumberOfBabies`方法以返回`6`。此外，该 final 类实现了以下继承的抽象方法：`getBaby`和`getAsciiArt`。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public final class MaineCoon extends VirtualDomesticCat {
    public MaineCoon(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("MaineCoon created.");        
    }

    public MaineCoon(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public String getBaby() {
        return "Maine Coon baby ";
    }

    @Override
    public int getAverageNumberOfBabies() {
        return 6;
    }

    public String getAsciiArt() {
        return
            "  ^_^\n" + 
            " (*.*)\n" +
            "  |-|\n" +
            " /   \\\n";
    }
}
```

### 提示

我们没有将任何方法标记为`final`，因为在 final 类中的所有方法都是隐式 final 的。

然而，当我们在 JShell 之外运行 Java 代码时，final 类将被创建，我们将无法对其进行子类化。

现在，我们将创建从`VirtualAnimal`继承的`VirtualBird`抽象类。以下行显示了`VirtualBird`抽象类的代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public abstract class VirtualBird extends VirtualAnimal {
    public String feathersColor;

    public VirtualBird(int age, String feathersColor) {
        super(age);
        this.feathersColor = feathersColor;
        System.out.println("VirtualBird created.");
    }

    public final boolean isAbleToFly() {
        // Not all birds are able to fly in real-life
        // However, all our virtual birds are able to fly
        return true;
    }

}
```

`VirtualBird`抽象类继承了先前声明的`VirtualAnimal`抽象类的成员，并添加了一个名为`feathersColor`的新的可变的`String`字段。新的抽象类声明了一个构造函数，该构造函数需要`age`和`feathersColor`的初始值来创建类的实例。构造函数使用`super`关键字调用来自基类或超类的构造函数，即在`VirtualAnimal`类中定义的构造函数，该构造函数需要`age`参数。在超类中定义的构造函数执行完毕后，代码设置了`feathersColor`可变字段的值，并打印了一条消息，指示已创建了一个虚拟鸟类。

`VirtualBird`抽象类实现了继承的`isAbleToFly`方法作为一个最终方法，返回`true`。我们希望确保我们应用程序领域中的所有虚拟鸟都能飞。

现在，我们将创建从`VirtualBird`继承的`VirtualDomesticBird`抽象类。以下行显示了`VirtualDomesticBird`抽象类的代码。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public abstract class VirtualDomesticBird extends VirtualBird {
    public final String name;

    public VirtualDomesticBird(int age, 
        String feathersColor, 
        String name) {
        super(age, feathersColor);
        this.name = name;
        System.out.println("VirtualDomesticBird created.");
    }
}
```

`VirtualDomesticBird`抽象类继承了先前声明的`VirtualBird`抽象类的成员，并添加了一个名为`name`的新的不可变的`String`字段。新的抽象类声明了一个构造函数，该构造函数需要`age`、`feathersColor`和`name`的初始值来创建类的实例。构造函数使用`super`关键字调用来自超类的构造函数，即在`VirtualBird`类中定义的构造函数，该构造函数需要`age`和`feathersColor`参数。在超类中定义的构造函数执行完毕后，代码设置了`name`不可变字段的值，并打印了一条消息，指示已创建了一个虚拟家禽。

以下行显示了从`VirtualDomesticBird`继承的`Cockatiel`具体类的代码。我们将`Cockatiel`声明为最终类，并实现以下继承的抽象方法：`isRideable`、`isHerbivore`、`isCarnivore`、`getAverageNumberOfBabies`、`getBaby`和`getAsciiArt`。如前所述，最终类中的所有方法都是隐式最终的。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public final class Cockatiel extends VirtualDomesticBird {
    public Cockatiel(int age, 
        String feathersColor, String name) {
        super(age, feathersColor, name);
        System.out.println("Cockatiel created.");
    }

    public boolean isRideable() {
        return true;
    }

    public boolean isHerbivore() {
        return true;
    }

    public boolean isCarnivore() {
        return true;
    }

    public int getAverageNumberOfBabies() {
        return 4;
    }

    public String getBaby() {
        return "Cockatiel baby ";
    }

    public String getAsciiArt() {
        return
            "     ///\n" +
            "      .////.\n" +
            "      //   //\n" +
            "      \\ (*)\\\n" +
            "      (/    \\\n" +
            "       /\\    \\\n" +
            "      ///     \\\\\n" +
            "     ///|     |\n" +
            "    ////|     |\n" +
            "   //////    /\n" +
            "  ////  \\   \\\n" +
            "  \\\\    ^    ^\n" +
            "   \\\n" +
            "    \\\n";
    }
}
```

以下行显示了从`VirtualDomesticMammal`继承的`VirtualDomesticRabbit`具体类的代码。我们将`VirtualDomesticRabbit`声明为最终类，因为我们不希望有额外的子类。我们只会在我们的应用程序领域中有一种虚拟家兔。最终类实现了以下继承的抽象方法：`isAbleToFly`、`isRideable`、`isHerbivore`、`isCarnivore`、`getAverageNumberOfBabies`、`getBaby`和`getAsciiArt`。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
public final class VirtualDomesticRabbit extends VirtualDomesticMammal {
    public VirtualDomesticRabbit(
        int age, 
        boolean isPregnant, 
        String name, 
        String favoriteToy) {
        super(age, isPregnant, name, favoriteToy);
        System.out.println("VirtualDomesticRabbit created.");        
    }

    public VirtualDomesticRabbit(
        int age, String name, String favoriteToy) {
        this(age, false, name, favoriteToy);
    }

    public final boolean isAbleToFly() {
        return false;
    }

    public final boolean isRideable() {
        return false;
    }

    public final boolean isHerbivore() {
        return true;
    }

    public final boolean isCarnivore() {
        return false;
    }

    public int getAverageNumberOfBabies() {
        return 6;
    }

    public String getBaby() {
        return "Rabbit baby ";
    }

    public String getAsciiArt() {
        return
            "   /\\ /\\\n" + 
            "   \\ V /\n" + 
            "   | **)\n" + 
            "   /  /\n" + 
            "  /  \\_\\_\n" + 
            "*(__\\_\\\n";
    }
}
```

### 注意

JShell 忽略`final`修饰符，因此，使用`final`修饰符声明的类将允许在 JShell 中存在子类。

# 创建与不同子类实例一起工作的方法

在声明所有新类之后，我们将创建以下两个方法，这两个方法接收一个`VirtualAnimal`实例作为参数，即`VirtualAnimal`实例或`VirtualAnimal`的任何子类的实例。每个方法调用`VirtualAnimal`类中定义的不同实例方法：`printAverageNumberOfBabies`和`printAsciiArg`。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
void printBabies(VirtualAnimal animal) {
    animal.printAverageNumberOfBabies();
}

void printAsciiArt(VirtualAnimal animal) {
    animal.printAsciiArt();
}
```

然后以下行创建了下列类的实例：`Cockatiel`、`VirtualDomesticRabbit`和`MaineCoon`。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
Cockatiel tweety = 
    new Cockatiel(3, "White", "Tweety");
VirtualDomesticRabbit bunny = 
    new VirtualDomesticRabbit(2, "Bunny", "Sneakers");
MaineCoon garfield = 
    new MaineCoon(3, "Garfield", "Lassagna");
```

以下截图显示了在 JShell 中执行先前行的结果。在我们输入代码创建每个实例后，我们将看到不同构造函数在 JShell 中显示的消息。这些消息将帮助我们轻松理解 Java 在创建每个实例时调用的所有链接构造函数。

![创建与不同子类实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00074.jpeg)

然后，以下行调用了`printBabies`和`printAsciiArt`方法，并将先前创建的实例作为参数传递。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
System.out.println(tweety.name);
printBabies(tweety);
printAsciiArt(tweety);

System.out.println(bunny.name);
printBabies(bunny);
printAsciiArt(bunny);

System.out.println(garfield.name);
printBabies(garfield);
printAsciiArt(garfield);
```

这三个实例成为不同方法的`VirtualAnimal`参数，即它们采用`VirtualAnimal`实例的形式。然而，字段和方法使用的值并非在`VirtualAnimal`类中声明的。对`printAverageNumberOfBabies`和`printAsciiArt`实例方法的调用考虑了所有在子类中声明的成员，因为每个实例都是`VirtualAnimal`的子类的实例：

### 提示

接受`VirtualAnimal`实例作为参数的`printBabies`和`printAsciiArt`方法只能访问为它们接收的实例在`VirtualAnimal`类中定义的成员，因为参数类型是`VirtualAnimal`。如果需要，我们可以解开接收到的`animal`参数中的`Cockatiel`、`VirtualDomesticRabbit`和`MaineCoon`实例。然而，随着我们涵盖更高级的主题，我们将在以后处理这些情景。

以下截图显示了在 JShell 中为名为`tweety`的`Cockatiel`实例执行先前行的结果。

![创建与不同子类实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00075.jpeg)

以下截图显示了在 JShell 中为名为`bunny`的`VirtualDomesticRabbit`实例执行先前行的结果。

![创建与不同子类实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00076.jpeg)

以下截图显示了在 JShell 中为名为`garfield`的`MaineCoon`实例执行先前行的结果。

![创建与不同子类实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00077.jpeg)

现在我们将创建另一个方法，该方法接收一个`VirtualDomesticMammal`实例作为参数，即`VirtualDomesticMammal`实例或`VirtualDomesticMammal`的任何子类的实例。以下函数调用了在`VirtualDomesticMammal`类中定义的`talk`实例方法。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
void makeItTalk(VirtualDomesticMammal domestic) {
    domestic.talk();
}
```

然后，以下两行调用了`makeItTalk`方法，并将`VirtualDomesticRabbit`和`MaineCoon`实例作为参数：`bunny`和`garfield`。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
makeItTalk(bunny);
makeItTalk(garfield);
```

对接收到的`VirtualDomesticMammal`实例调用相同方法会产生不同的结果。`VirtualDomesticRabbit`没有覆盖继承的`talk`方法，而`MaineCoon`类继承了在`VirtualDomesticCat`抽象类中被覆盖的`talk`方法，使家猫发出喵喵的声音。以下截图显示了在 JShell 中进行的两个方法调用的结果。

![创建与不同子类实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00078.jpeg)

`VirtualAnimal`抽象类声明了两个实例方法，允许我们确定虚拟动物是比另一个虚拟动物更年轻还是更年长：`isYoungerThan`和`isOlderThan`。这两个方法接收一个`VirtualAnimal`参数，并返回在实例的`age`值和接收实例的`age`值之间应用运算符的结果。

以下行调用`printAge`方法的三个实例：`tweety`，`bunny`和`garfield`。此方法在`VirtualAnimal`类中声明。然后，下一行调用`isOlderThan`和`isYoungerThan`方法，并将这些实例作为参数，以显示比较不同实例年龄的结果。示例的代码文件包含在`java_9_oop_chapter_07_01`文件夹中的`example07_02.java`文件中。

```java
tweety.printAge();
bunny.printAge();
garfield.printAge();
tweety.isOlderThan(bunny);
garfield.isYoungerThan(tweety);
bunny.isYoungerThan(garfield);
```

以下屏幕截图显示了在 JShell 中执行前面行的结果：

![创建可以与不同子类的实例一起工作的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00079.jpeg)

# 测试您的知识

1.  以下哪行声明了一个实例方法，不能在任何子类中被覆盖：

1.  `public void talk(): final {`

1.  `public final void talk() {`

1.  `public notOverrideable void talk() {`

1.  我们有一个名为`Shape`的抽象超类。`Circle`类是`Shape`的子类，是一个具体类。如果我们创建一个名为`circle`的`Circle`实例，这个实例也将是：

1.  `Shape`的一个实例。

1.  `Circle`的子类。

1.  `Circle`的一个抽象超类。

1.  在 UML 图中，使用斜体文本格式的类名表示它们是：

1.  具体类。

1.  覆盖了至少一个从其超类继承的成员的具体类。

1.  抽象类。

1.  以下哪行声明了一个不能被子类化的类：

1.  `public final class Dog extends VirtualAnimal {`

1.  `public final class Dog subclasses VirtualAnimal {`

1.  `public final Dog subclasses VirtualAnimal {`

1.  以下哪行声明了一个名为`Circle`的具体类，可以被子类化，其超类是`Shape`抽象类：

1.  `public final class Shape extends Circle {`

1.  `public class Shape extends Circle {`

1.  `public concrete class Shape extends Circle {`

# 总结

在本章中，我们创建了许多抽象和具体类。我们学会了控制子类是否可以覆盖成员，以及类是否可以被子类化。

我们使用了许多子类的实例，并且了解到对象可以采用许多形式。我们在 JShell 中使用了许多实例及其方法，以了解我们编写的类和方法是如何执行的。我们使用了执行与具有共同超类的不同类的实例的操作的方法。

现在您已经了解了成员继承和多态性，我们准备在 Java 9 中使用接口进行契约编程，这是我们将在下一章中讨论的主题。
