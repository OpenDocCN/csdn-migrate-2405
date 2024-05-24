# Java9 和 JShell（三）

> 原文：[`zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53`](https://zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：接口的契约编程

在本章中，我们将处理复杂的场景，在这些场景中，我们将不得不使用属于多个蓝图的实例。我们将利用接口来进行契约编程。我们将：

+   了解 Java 9 中的接口

+   了解接口与类结合的工作原理

+   在 Java 9 中声明接口

+   声明实现接口的类

+   利用接口的多重继承

+   将类继承与接口结合

# 了解接口与类结合的工作原理

假设我们必须开发一个 Web 服务，在其中我们必须处理两种不同类型的角色：漫画角色和游戏角色。

漫画角色必须在漫画中可绘制。漫画角色必须能够提供昵称并执行以下任务：

+   绘制一个带有消息的语音气泡，也称为语音气泡

+   绘制一个带有消息的思想气泡，也称为思想气泡

+   绘制带有消息的语音气泡和另一个漫画角色，在漫画中可绘制，作为目标。

游戏角色必须在游戏场景中可绘制。游戏角色必须能够提供全名和当前得分。此外，游戏角色必须能够执行以下任务：

+   将其所需的位置设置为由*x*和*y*坐标指示的特定 2D 位置

+   为其*x*坐标提供值

+   为其*y*坐标提供值

+   在当前位置绘制自身

+   检查它是否与另一个游戏角色相交，在游戏场景中可绘制

我们必须能够处理既是漫画角色又是游戏角色的对象；也就是说，它们既可以在漫画中绘制，也可以在游戏场景中绘制。然而，我们还将处理只是漫画或游戏角色的对象；也就是说，它们可以在漫画中绘制或在游戏场景中绘制。

我们不想编写执行先前描述的任务的通用方式。我们希望确保许多类能够通过一个公共接口执行这些任务。在漫画中声明自己为可绘制的每个对象必须定义与语音和思想气泡相关的任务。在游戏场景中声明自己为可绘制的每个对象必须定义如何设置其所需的 2D 位置，绘制自身，并检查它是否与另一个游戏角色相交，在游戏场景中可绘制。

**SpiderDog**是一种漫画角色，在漫画中可绘制，具有特定的绘制语音和思想气泡的方式。**WonderCat**既是漫画角色又是游戏角色，在漫画中可绘制，也在游戏场景中可绘制。因此，WonderCat 必须定义两种角色类型所需的所有任务。

WonderCat 是一个非常多才多艺的角色，它可以使用不同的服装参与游戏或漫画，并具有不同的名称。WonderCat 还可以是可隐藏的、可供能力的或可战斗的：

+   可隐藏的角色能够被隐藏。它可以提供特定数量的眼睛，并且必须能够显示和隐藏自己。

+   可供能力的角色能够被赋予能力。它可以提供一个法术能力分数值，并使用这个法术能力使一个可隐藏的角色消失。

+   可战斗的角色能够战斗。它有一把剑，并且可以提供剑的力量和重量值。此外，可战斗的角色可以在有或没有可隐藏的角色作为目标时拔出剑。

假设 Java 9 支持多重继承。我们需要基本蓝图来表示漫画角色和游戏角色。然后，代表这些类型角色的每个类都可以提供其方法的实现。在这种情况下，漫画和游戏角色非常不同，它们不执行可能导致混乱和问题的相似任务，因此多重继承不方便。因此，我们可以使用多重继承来创建一个`WonderCat`类，该类实现了漫画和游戏角色的蓝图。在某些情况下，多重继承不方便，因为相似的蓝图可能具有相同名称的方法，并且使用多重继承可能会非常令人困惑。

此外，我们可以使用多重继承将`WonderCat`类与`Hideable`、`Powerable`和`Fightable`结合在一起。这样，我们将有一个`Hideable` + `WonderCat`，一个`Powerable` + `WonderCat`，和一个`Fightable` + `WonderCat`。我们可以使用任何一个，`Hideable` + `WonderCat`，`Powerable` + `WonderCat`，或`Fightable` + `WonderCat`，作为漫画或游戏角色。

我们的目标很简单，但我们面临一个小问题：Java 9 不支持类的多重继承。相反，我们可以使用接口进行多重继承，或者将接口与类结合使用。因此，我们将使用接口和类来满足我们之前的要求。

在前几章中，我们一直在使用抽象类和具体类。当我们编写抽象类时，我们声明了构造函数、实例字段、实例方法和抽象方法。抽象类中有具体的实例方法和抽象方法。

在这种情况下，我们不需要为任何方法提供实现；我们只需要确保我们提供了具有特定名称和参数的适当方法。您可以将**接口**视为一组相关的抽象方法，类必须实现这些方法才能被视为接口名称标识的类型的成员。Java 9 不允许我们在接口中指定构造函数或实例字段的要求。还要注意接口不是类。

### 注意

在其他编程语言中，接口被称为协议。

例如，我们可以创建一个`Hideable`接口，该接口指定以下无参数方法并具有空体：

+   `getNumberOfEyes()`

+   `appear()`

+   `disappear()`

一旦我们定义了一个接口，我们就创建了一个新类型。因此，我们可以使用接口名称来指定参数的所需类型。这样，我们将使用接口作为类型，而不是使用类作为类型，并且我们可以使用实现特定接口的任何类的实例作为参数。例如，如果我们使用`Hideable`作为参数的所需类型，我们可以将实现`Hideable`接口的任何类的实例作为参数传递。

### 提示

我们可以声明继承自多个接口的接口；也就是说，接口支持多重继承。

但是，您必须考虑接口与抽象类相比的一些限制。接口不能指定构造函数或实例字段的要求，因为接口与方法和签名有关。接口可以声明对以下成员的要求：

+   类常量

+   静态方法

+   实例方法

+   默认方法

+   嵌套类型

### 注意

Java 8 增加了向接口添加默认方法的可能性。它们允许我们声明实际提供实现的方法。Java 9 保留了这一特性。

# 声明接口

现在是时候在 Java 9 中编写必要的接口了。我们将编写以下五个接口：

+   `DrawableInComic`

+   `DrawableInGame`

+   `Hideable`

+   `Powerable`

+   `Fightable`

### 提示

一些编程语言，比如 C#，使用`I`作为接口的前缀。Java 9 不使用这种接口命名约定。因此，如果你看到一个名为`IDrawableInComic`的接口，那可能是由有 C#经验的人编写的，并将命名约定转移到了 Java 领域。

以下的 UML 图表显示了我们将要编码的五个接口，其中包括在图表中的必需方法。请注意，在声明接口的每个图表中，我们在类名前包含了**<<interface>>**文本。

![声明接口](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00080.jpeg)

以下行显示了`DrawableInComic`接口的代码。`public`修饰符，后跟`interface`关键字和接口名`DrawableInComic`，构成了接口声明。与类声明一样，接口体被括在大括号（`{}`）中。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中，名为`example08_01.java`。

```java
public interface DrawableInComic {
    String getNickName();
    void drawSpeechBalloon(String message);
    void drawSpeechBalloon(DrawableInComic destination, String message);
    void drawThoughtBalloon(String message);
}
```

### 提示

接口中声明的成员具有隐式的`public`修饰符，因此不需要为每个方法声明指定`public`。

`DrawableInComic`接口声明了一个`getNickName`方法要求，两次重载的`drawSpeechBalloon`方法要求，以及一个`drawThoughtBalloon`方法要求。该接口只包括方法声明，因为实现`DrawableInComic`接口的类将负责提供`getNickName`方法、`drawThoughtBalloon`方法和`drawSpeechBalloon`方法的两个重载的实现。请注意，没有方法体，就像我们为抽象类声明抽象方法时一样。不需要使用`abstract`关键字来声明这些方法，因为它们是隐式抽象的。

以下行显示了`DrawableInGame`接口的代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中，名为`example08_01.java`。

```java
public interface DrawableInGame {
    String getFullName();
    int getScore();
    int getX();
    int getY();
    void setLocation(int x, int y);
    void draw();
    boolean isIntersectingWith(DrawableInGame otherDrawableInGame);
}
```

`DrawableInGame`接口声明包括七个方法要求：`getFullName`、`getScore`、`getX`、`getY`、`setLocation`、`draw`和`isIntersectingWith`。

以下行显示了`Hideable`接口的代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中，名为`example08_01.java`。

```java
public interface Hideable {
    int getNumberOfEyes();
    void show();
    void hide();
}
```

`Hideable`接口声明包括三个方法要求：`getNumberOfEyes`、`show`和`hide`。

以下行显示了`Powerable`接口的代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中，名为`example08_01.java`。

```java
public interface Powerable {
    int getSpellPower();
    void useSpellToHide(Hideable hideable);
}
```

`Powerable`接口声明包括两个方法要求：`getSpellPower`和`useSpellToHide`。与先前声明的接口中包含的其他方法要求一样，在方法声明中，我们使用接口名作为方法声明中参数的类型。在这种情况下，`useSpellToHide`方法声明的`hideable`参数为`Hideable`。因此，我们将能够使用任何实现`Hideable`接口的类来调用该方法。

以下行显示了`Fightable`接口的代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中，名为`example08_01.java`。

```java
public interface Fightable {
    int getSwordPower();
    int getSwordWeight();
    void unsheathSword();
    void unsheathSword(Hideable hideable);
}
```

`Fightable`接口声明包括四个方法要求：`getSwordPower`、`getSwordWeight`和`unsheathSword`方法的两个重载。

# 声明实现接口的类

现在，我们将在 JShell 中声明一个具体类，该类在其声明中指定实现`DrawableInComic`接口。类声明不包括超类，而是在类名（`SiperDog`）和`implements`关键字之后包括先前声明的`DrawableInComic`接口的名称。我们可以将类声明解读为“`SpiderDog`类实现`DrawableInComic`接口”。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_02.java`文件中。

```java
public class SpiderDog implements DrawableInComic {
}
```

Java 编译器将生成错误，因为`SpiderDog`类被声明为具体类，并且没有覆盖`DrawableInComic`接口中声明的所有抽象方法。JShell 显示以下错误，指示接口中的第一个方法声明没有被覆盖：

```java
jshell> public class SpiderDog implements DrawableInComic {
 ...> }
|  Error:
|  SpiderDog is not abstract and does not override abstract method drawThoughtBalloon(java.lang.String) in DrawableInComic

```

现在，我们将用尝试实现`DrawableInComic`接口的类替换之前声明的空`SuperDog`类，但它仍未实现其目标。以下行显示了`SuperDog`类的新代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_03.java`文件中。

```java
public class SpiderDog implements DrawableInComic {
    protected final String nickName;

    public SpiderDog(String nickName) {
        this.nickName = nickName;
    }

    protected void speak(String message) {
        System.out.println(
            String.format("%s -> %s",
                nickName,
                message));
    }

    protected void think(String message) {
        System.out.println(
            String.format("%s -> ***%s***",
                nickName,
                message));
    }

    @Override
    String getNickName() {
        return nickName;
    }

    @Override
    void drawSpeechBalloon(String message) {
        speak(message);
    }

    @Override
    void drawSpeechBalloon(DrawableInComic destination, 
        String message) {
        speak(String.format("message: %s, %s",
            destination.getNickName(),
            message));
    }

    @Override
    void drawThoughtBalloon(String message) {
        think(message);
    }
}
```

Java 编译器将生成许多错误，因为`SpiderDog`具体类没有实现`DrawableInComic`接口。JShell 显示以下错误消息，指示接口需要许多方法声明为`public`方法。

```java
|  Error:
|  drawThoughtBalloon(java.lang.String) in SpiderDog cannot implement drawThoughtBalloon(java.lang.String) in DrawableInComic
|    attempting to assign weaker access privileges; was public
|      @Override
|      ^--------...
|  Error:
|  drawSpeechBalloon(DrawableInComic,java.lang.String) in SpiderDog cannot implement drawSpeechBalloon(DrawableInComic,java.lang.String) in DrawableInComic
|    attempting to assign weaker access privileges; was public
|      @Override
|      ^--------...
|  Error:
|  drawSpeechBalloon(java.lang.String) in SpiderDog cannot implement drawSpeechBalloon(java.lang.String) in DrawableInComic
|    attempting to assign weaker access privileges; was public
|      @Override
|      ^--------...
|  Error:
|  getNickName() in SpiderDog cannot implement getNickName() in DrawableInComic
|    attempting to assign weaker access privileges; was public
|      @Override
|      ^--------...

```

公共`DrawableInComic`接口指定了隐式公共方法。因此，当我们声明一个类时，该类没有将所需成员声明为`public`时，Java 编译器会生成错误，并指出我们不能尝试分配比接口要求的更弱的访问权限。

### 注意

每当我们声明一个指定实现接口的类时，它必须满足接口中指定的所有要求。如果不满足，Java 编译器将生成错误，指示未满足哪些要求，就像在前面的示例中发生的那样。在使用接口时，Java 编译器确保实现接口的任何类都遵守其中指定的要求。

最后，我们将用真正实现`DrawableInComic`接口的类替换`SpiderDog`类的先前声明。以下行显示了`SpiderDog`类的新代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_04.java`文件中。

```java
public class SpiderDog implements DrawableInComic {
    protected final String nickName;

    public SpiderDog(String nickName) {
        this.nickName = nickName;
    }

    protected void speak(String message) {
        System.out.println(
            String.format("%s -> %s",
                nickName,
                message));
    }

    protected void think(String message) {
        System.out.println(
            String.format("%s -> ***%s***",
                nickName,
                message));
    }

    @Override
 public String getNickName() {
        return nickName;
    }

    @Override
 public void drawSpeechBalloon(String message) {
        speak(message);
    }

    @Override
 public void drawSpeechBalloon(DrawableInComic destination, 
 String message) {
        speak(String.format("message: %s, %s",
            destination.getNickName(),
            message));
    }

    @Override
 public void drawThoughtBalloon(String message) {
        think(message);
    }
}
```

`SpiderDog`类声明了一个构造函数，将所需的`nickName`参数的值分配给`nickName`不可变的受保护字段。该类实现了`getNickName`方法，该方法只返回`nickName`不可变的受保护字段。该类声明了两个版本的`drawSpeechBalloon`方法的代码。两种方法都调用受保护的`speak`方法，该方法打印一个包括`nickName`值作为前缀的特定格式的消息。此外，该类声明了`drawThoughtBalloon`方法的代码，该方法调用受保护的`think`方法，该方法也打印一个包括`nickName`值作为前缀的消息。

`SpiderDog`类实现了`DrawableInComic`接口中声明的方法。该类还声明了一个构造函数，一个`protected`的不可变字段和两个`protected`方法。

### 提示

只要我们实现了类声明中`implements`关键字后列出的接口中声明的所有成员，就可以向类添加任何所需的额外成员。

现在，我们将声明另一个类，该类实现了`SpiderDog`类实现的相同接口，即`DrawableInComic`接口。以下行显示了`WonderCat`类的代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_04.java`文件中。

```java
public class WonderCat implements DrawableInComic {
    protected final String nickName;
    protected final int age;

    public WonderCat(String nickName, int age) {
        this.nickName = nickName;
        this.age = age;
    }

    public int getAge() {
        return age;
    }

    @Override
 public String getNickName() {
        return nickName;
    }

    @Override
 public void drawSpeechBalloon(String message) {
        String meow = 
            (age > 2) ? "Meow" : "Meeoow Meeoow";
        System.out.println(
            String.format("%s -> %s",
                nickName,
                meow));
    }

    @Override
 public void drawSpeechBalloon(DrawableInComic destination, 
 String message) {
        System.out.println(
            String.format("%s ==> %s --> %s",
                destination.getNickName(),
                nickName,
                message));
    }

    @Override
 public void drawThoughtBalloon(String message) {
        System.out.println(
            String.format("%s thinks: '%s'",
                nickName,
                message));
    }
}
```

`WonderCat`类声明了一个构造函数，将所需的`nickName`和`age`参数的值分配给`nickName`和`age`不可变字段。该类声明了两个版本的`drawSpeechBalloon`方法的代码。只需要`message`参数的版本使用`age`属性的值，在`age`值大于`2`时生成不同的消息。此外，该类声明了`drawThoughtBalloon`和`getNickName`方法的代码。

`WonderCat`类实现了`DrawableInComic`接口中声明的方法。但是，该类还声明了一个额外的不可变字段`age`和一个`getAge`方法，这些并不是接口所要求的。

### 提示

Java 9 中的接口允许我们确保实现它们的类定义接口中指定的所有成员。如果没有，代码将无法编译。

# 利用接口的多重继承

Java 9 不允许我们声明具有多个超类或基类的类，因此不支持类的多重继承。子类只能继承一个类。但是，一个类可以实现一个或多个接口。此外，我们可以声明从超类继承并实现一个或多个接口的类。因此，我们可以将基于类的继承与接口的实现结合起来。

我们希望`WonderCat`类实现`DrawableInComic`和`DrawableInGame`接口。我们希望能够将任何`WonderCat`实例用作漫画角色和游戏角色。为了实现这一点，我们必须更改类声明，并将`DrawableInGame`接口添加到类实现的接口列表中，并在类中声明此添加接口中包含的所有方法。

以下行显示了新的类声明，指定`WonderCat`类实现`DrawableInComic`和`DrawableInGame`接口。类主体保持不变，因此我们不重复代码。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_05.java`文件中。

```java
public class WonderCat implements 
    DrawableInComic, DrawableInGame {
```

更改类声明后，Java 编译器将生成许多错误，因为`WonderCat`具体类的新版本没有实现`DrawableInGame`接口。JShell 显示以下错误消息。

```java
|  Error:
|  WonderCat is not abstract and does not override abstract method isIntersectingWith(DrawableInGame) in DrawableInGame
|  public class WonderCat implements
|  ^--------------------------------...

```

```java
java_9_oop_chapter_08_01 folder, in the example08_06.java file.
```

```java
public class WonderCat implements 
 DrawableInComic, DrawableInGame {
    protected final String nickName;
    protected final int age;
 protected int score;
 protected final String fullName;
 protected int x;
 protected int y;

 public WonderCat(String nickName, 
 int age, 
 String fullName, 
 int score, 
 int x, 
 int y) {
        this.nickName = nickName;
        this.age = age;
 this.fullName = fullName;
 this.score = score;
 this.x = x;
 this.y = y;
    }

    public int getAge() {
        return age;
    }

    @Override
    public String getNickName() {
        return nickName;
    }

    @Override
    public void drawSpeechBalloon(String message) {
        String meow = 
            (age > 2) ? "Meow" : "Meeoow Meeoow";
        System.out.println(
            String.format("%s -> %s",
                nickName,
                meow));
    }

    @Override
    public void drawSpeechBalloon(DrawableInComic destination, 
        String message) {
        System.out.println(
            String.format("%s ==> %s --> %s",
                destination.getNickName(),
                nickName,
                message));
    }

    @Override
    public void drawThoughtBalloon(String message) {
        System.out.println(
            String.format("%s thinks: '%s'",
                nickName,
                message));
    }

 @Override
 public String getFullName() {
 return fullName;
 }

 @Override
 public int getScore() {
 return score;
 }

 @Override
 public int getX() {
 return x;
 }

 @Override
 public int getY() {
 return y;
 }

 @Override
 public void setLocation(int x, int y) {
 this.x = x;
 this.y = y;
 System.out.println(
 String.format("Moving WonderCat %s to x:%d, y:%d",
 fullName,
 this.x,
 this.y));
 }

 @Override
 public void draw() {
 System.out.println(
 String.format("Drawing WonderCat %s at x:%d, y:%d",
 fullName,
 x,
 y));
 }

 @Override
 public boolean isIntersectingWith(
 DrawableInGame otherDrawableInGame) {
 return ((x == otherDrawableInGame.getX()) &&
 (y == otherDrawableInGame.getY()));
 }
}
```

新的构造函数将额外需要的`fullName`、`score`、`x`和`y`参数的值分配给同名的字段。因此，每当我们想要创建`AngryCat`类的实例时，我们将需要指定这些额外的参数。此外，该类添加了`DrawableInGame`接口中指定的所有方法的实现。

# 结合类继承和接口

我们可以将类继承与接口的实现结合起来。以下行显示了一个新的`HideableWonderCat`类的代码，它继承自`WonderCat`类并实现了`Hideable`接口。请注意，类声明在`extends`关键字后包括超类（`WonderCat`），在`implements`关键字后包括实现的接口（`Hideable`）。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_07.java`文件中。

```java
public class HideableWonderCat extends WonderCat implements Hideable {
    protected final int numberOfEyes;

    public HideableWonderCat(String nickName, int age, 
        String fullName, int score, 
        int x, int y, int numberOfEyes) {
        super(nickName, age, fullName, score, x, y);
        this.numberOfEyes = numberOfEyes;
    }

    @Override
    public int getNumberOfEyes() {
        return numberOfEyes;
    }

    @Override
    public void show() {
        System.out.println(
            String.format(
                "My name is %s and you can see my %d eyes.",
                getFullName(), 
                numberOfEyes));
    }

    @Override
    public void hide() {
        System.out.println(
            String.format(
                "%s is hidden.", 
                getFullName()));
    }
}
```

由于前面的代码，我们有了一个名为`HideableWonderCat`的新类，它实现了以下三个接口：

+   `DrawableInComic`：这个接口由`WonderCat`超类实现，并被`HideableWonderCat`继承

+   `DrawableInGame`：这个接口由`WonderCat`超类实现，并被`HideableWonderCat`继承

+   `Hideable`：这个接口由`HideableWonderCat`实现

`HideableWonderCat`类中定义的构造函数在构造函数中添加了一个`numberOfEyes`参数，该参数在`WonderCat`超类中声明的参数列表中。在这种情况下，构造函数使用`super`关键字调用超类中定义的构造函数，然后使用接收到的`numberOfEyes`参数初始化`numberOfEyes`不可变字段。该类实现了`Hideable`接口所需的`getNumberOfEyes`、`show`和`hide`方法。

以下几行显示了一个新的`PowerableWonderCat`类的代码，该类继承自`WonderCat`类并实现了`Powerable`接口。请注意，类声明在`extends`关键字后包括超类（`WonderCat`），在`implements`关键字后包括实现的接口（`Powerable`）。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_07.java`文件中。

```java
public class PowerableWonderCat extends WonderCat implements Powerable {
    protected final int spellPower;

    public PowerableWonderCat(String nickName, 
        int age, 
        String fullName, 
        int score, 
        int x, 
        int y, 
        int spellPower) {
        super(nickName, age, fullName, score, x, y);
        this.spellPower = spellPower;
    }

    @Override
    public int getSpellPower() {
        return spellPower;
    }

    @Override
    public void useSpellToHide(Hideable hideable) {
        System.out.println(
            String.format(
                "%s uses his %d spell power to hide the Hideable with %d eyes.",
                getFullName(),
                spellPower,
                hideable.getNumberOfEyes()));
    }
}
```

就像`HideableWonderCat`类一样，新的`PowerableWonderCat`类实现了三个接口。其中两个接口由`WonderCat`超类实现，并被`HideableWonderCat`继承：`DrawableInComic`和`DrawableInGame`。`HideableWonderCat`类添加了`Powerable`接口的实现。

`PowerableWonderCat`类中定义的构造函数在构造函数中添加了一个`spellPower`参数，该参数在`WonderCat`超类中声明的参数列表中。在这种情况下，构造函数使用`super`关键字调用超类中定义的构造函数，然后使用接收到的`spellPower`参数初始化`spellPower`不可变字段。该类实现了`Powerable`接口所需的`getSpellPower`和`useSpellToHide`方法。

`hide`方法接收一个`Hideable`作为参数。因此，任何`HideableWonderCat`的实例都可以作为该方法的参数，也就是符合`Hideable`实例的任何类的实例。

以下几行显示了一个新的`FightableWonderCat`类的代码，该类继承自`WonderCat`类并实现了`Fightable`接口。请注意，类声明在`extends`关键字后包括超类（`WonderCat`），在`implements`关键字后包括实现的接口（`Fightable`）。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_07.java`文件中。

```java
public class FightableWonderCat extends WonderCat implements Fightable {
    protected final int swordPower;
    protected final int swordWeight;

    public FightableWonderCat(String nickName, 
        int age, 
        String fullName, 
        int score, 
        int x, 
        int y, 
        int swordPower,
        int swordWeight) {
        super(nickName, age, fullName, score, x, y);
        this.swordPower = swordPower;
        this.swordWeight = swordWeight;
    }

    private void printSwordInformation() {
        System.out.println(
            String.format(
                "%s unsheaths his sword.", 
                getFullName()));
        System.out.println(
            String.format(
                "Sword power: %d. Sword weight: %d.", 
                swordPower,
                swordWeight));
    }

    @Override
    public int getSwordPower() {
        return swordPower;
    }

    @Override
    public int getSwordWeight() {
        return swordWeight;
    }

    @Override
    public void unsheathSword() {
        printSwordInformation();
    }

    @Override
    public void unsheathSword(Hideable hideable) {
        printSwordInformation();
        System.out.println(
            String.format("The sword targets a Hideable with %d eyes.",
                hideable.getNumberOfEyes()));
    }
}
```

就像之前编写的两个从`WonderCat`类继承并实现接口的类一样，新的`FightableWonderCat`类实现了三个接口。其中两个接口由`WonderCat`超类实现，并被`FightableWonderCat`继承：`DrawableInComic`和`DrawableInGame`。`FightableWonderCat`类添加了`Fightable`接口的实现。

`FightableWonderCat`类中定义的构造函数在构造函数中添加了`swordPower`和`swordWeight`参数，这些参数在`WonderCat`超类中声明的参数列表中。在这种情况下，构造函数使用`super`关键字调用超类中定义的构造函数，然后使用接收到的`swordPower`和`swordWeight`参数初始化`swordPower`和`swordWeight`不可变字段。

该类实现了`getSpellPower`、`getSwordWeight`和`Fightable`接口所需的两个版本的`unsheathSword`方法。两个版本的`unsheathSword`方法调用了受保护的`printSwordInformation`方法，而接收`Hideable`实例作为参数的重载版本则打印了一个额外的消息，该消息包含了`Hideable`实例的眼睛数量作为目标。

以下表格总结了我们创建的每个类实现的接口：

| 类名 | 实现以下接口 |
| --- | --- |
| `SpiderDog` | `DrawableInComic` |
| `WonderCat` | `DrawableInComic` 和 `DrawableInGame` |
| `HideableWonderCat` | `DrawableInComic`、`DrawableInGame` 和 `Hideable` |
| `PowerableWonderCat` | `DrawableInComic`、`DrawableInGame` 和 `Powerable` |
| `FightableWonderCat` | `DrawableInComic`、`DrawableInGame` 和 `Fightable` |

以下简化的 UML 图显示了类的层次结构树及其与接口的关系。该图表不包括任何接口和类的成员，以使其更容易理解关系。以虚线结束的带箭头的线表示类实现了箭头指示的接口。

![Combining class inheritance and interfaces](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00081.jpeg)

以下 UML 图显示了接口和类及其所有成员。请注意，我们不重复类实现的接口中声明的成员，以使图表更简单，并避免重复信息。我们可以使用该图表来理解我们将在基于这些类和先前定义的接口的使用的下一个代码示例中分析的所有内容：

![Combining class inheritance and interfaces](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00082.jpeg)

以下行创建了每个先前创建的类的一个实例。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_08.java`文件中。

```java
SpiderDog spiderDog1 = 
    new SpiderDog("Buddy");
WonderCat wonderCat1 = 
    new WonderCat("Daisy", 1, "Mrs. Daisy", 100, 15, 15);
HideableWonderCat hideableWonderCat1 =
    new HideableWonderCat("Molly", 5, "Mrs. Molly", 450, 20, 10, 3); 
PowerableWonderCat powerableWonderCat1 =
    new PowerableWonderCat("Princess", 5, "Mrs. Princess", 320, 20, 10, 7);
FightableWonderCat fightableWonderCat1 =
    new FightableWonderCat("Abby", 3, "Mrs. Abby", 1200, 40, 10, 7, 5);
```

以下表格总结了我们使用前面的代码片段创建的实例名称及其类名称：

| 实例名称 | 类名称 |
| --- | --- |
| `spiderDog1` | `SpiderDog` |
| `wonderCat1` | `WonderCat` |
| `hideableWonderCat1` | `HideableWonderCat` |
| `powerableWonderCat1` | `PowerableWonderCat` |
| `fightableWonderCat1` | `FightableWonderCat` |

现在，我们将评估许多使用`instanceof`关键字的表达式，以确定实例是指定类的实例还是实现特定接口的类的实例。请注意，所有表达式的评估结果都为`true`，因为在`instanceof`关键字后面的右侧指定的类型对于每个实例来说，都是它的主类、超类或主类实现的接口。

例如，`powerableWonderCat1` 是 `PowerableWonderCat` 的一个实例。此外，`powerableWonderCat1` 属于 `WonderCat`，因为 `WonderCat` 是 `PowerableWonderCat` 类的超类。同样，`powerableWonderCat1` 实现了三个接口：`DrawableInComic`、`DrawableInGame` 和 `Powerable`。`PowerableWonderCat` 的超类 `WonderCat` 实现了以下两个接口：`DrawableInComic` 和 `DrawableInGame`。因此，`PowerableWonderCat` 继承了接口的实现。最后，`PowerableWonderCat` 类不仅继承自 `WonderCat`，还实现了 `Powerable` 接口。

在第三章*Classes and Instances*中，我们学习了`instanceof`关键字允许我们测试对象是否是指定类型。这种类型可以是类，也可以是接口。如果我们在 JShell 中执行以下行，所有这些行的评估结果都将打印为`true`。示例的代码文件包含在`java_9_oop_chapter_08_01`文件夹中的`example08_08.java`文件中。

```java
spiderDog1 instanceof SpiderDog
spiderDog1 instanceof DrawableInComic

wonderCat1 instanceof WonderCat
wonderCat1 instanceof DrawableInComic
wonderCat1 instanceof DrawableInGame

hideableWonderCat1 instanceof WonderCat
hideableWonderCat1 instanceof HideableWonderCat
hideableWonderCat1 instanceof DrawableInComic
hideableWonderCat1 instanceof DrawableInGame
hideableWonderCat1 instanceof Hideable

powerableWonderCat1 instanceof WonderCat
powerableWonderCat1 instanceof PowerableWonderCat
powerableWonderCat1 instanceof DrawableInComic
powerableWonderCat1 instanceof DrawableInGame
powerableWonderCat1 instanceof Powerable

fightableWonderCat1 instanceof WonderCat
fightableWonderCat1 instanceof FightableWonderCat
fightableWonderCat1 instanceof DrawableInComic
fightableWonderCat1 instanceof DrawableInGame
fightableWonderCat1 instanceof Fightable
```

以下两个屏幕截图显示了在 JShell 中评估先前表达式的结果：

![Combining class inheritance and interfaces](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00083.jpeg)![Combining class inheritance and interfaces](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00084.jpeg)

# 测试你的知识

1.  一个类可以实现：

1.  只有一个接口。

1.  一个或多个接口。

1.  最多两个接口。

1.  当一个类实现一个接口：

1.  它也可以继承自一个超类。

1.  它不能从一个超类继承。

1.  它只能从抽象超类继承，而不能从具体超类继承。

1.  一个接口：

1.  可以从一个超类继承。

1.  不能继承自超类或另一个接口。

1.  可以继承另一个接口。

1.  哪一行声明了一个名为`WonderDog`的类，该类实现了`Hideable`接口：

1.  `public class WonderDog extends Hideable {`

1.  `public class WonderDog implements Hideable {`

1.  `public class WonderDog: Hideable {`

1.  接口是：

1.  一种方法。

1.  一种类型。

1.  抽象类。

# 总结

在本章中，您学习了声明和组合多个蓝图以生成单个实例。我们声明了指定所需方法的接口。然后，我们创建了许多实现单个和多个接口的类。

我们将类继承与接口实现结合在一起。我们意识到一个类可以实现多个接口。我们在 JShell 中执行代码，以了解单个实例属于类类型和接口类型。

现在您已经了解了接口和基本的契约编程知识，我们准备开始处理高级契约编程场景，这是我们将在下一章讨论的主题。


# 第九章：接口的高级契约编程

在本章中，我们将深入探讨接口的契约编程。我们将更好地理解接口作为类型的工作方式。我们将：

+   使用接口作为参数的方法

+   使用接口和类进行向下转型

+   理解装箱和拆箱

+   将接口类型的实例视为不同的子类

+   利用 Java 9 中接口的默认方法

# 使用接口作为参数的方法

在上一章中，我们创建了以下五个接口：`DrawableInComic`、`DrawableInGame`、`Hideable`、`Powerable`和`Fightable`。然后，我们创建了实现不同接口的以下类，并且其中许多类还继承自超类：`SpiderDog`、`WonderCat`、`HideableWonderCat`、`PowerableWonderCat`和`FightableWonderCat`。

在 JShell 中运行以下命令以检查我们创建的所有类型：

```java
/types

```

以下截图显示了在 JShell 中执行上一个命令的结果。JShell 列举了我们在会话中创建的五个接口和五个类。

![使用接口作为参数的方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00085.jpeg)

当我们使用接口时，我们使用它们来指定参数类型，而不是使用类名。多个类可能实现单个接口，因此，不同类的实例可能符合特定接口的参数。

现在我们将创建先前提到的类的额外实例，并调用指定其所需参数的方法，使用接口名称而不是类名。我们将了解在方法中使用接口作为参数类型时发生了什么。

在以下代码中，前两行创建了`SpiderDog`类的两个实例，分别命名为`teddy`和`winston`。然后，代码调用了`teddy`的`drawSpeechBalloon`方法的两个版本。对该方法的第二次调用将`winston`作为`DrawableInComic`参数传递，因为`winston`是`SpiderDog`的一个实例，而`SpiderDog`是实现`DrawableInComic`实例的类。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
SpiderDog teddy = new SpiderDog("Teddy");
SpiderDog winston = new SpiderDog("Winston");
teddy.drawSpeechBalloon(
    String.format("Hello, my name is %s", teddy.getNickName()));
teddy.drawSpeechBalloon(winston, "How do you do?");
winston.drawThoughtBalloon("Who are you? I think.");
```

以下代码创建了一个名为`oliver`的`WonderCat`类的实例。在构造函数中为`nickName`参数指定的值为`"Oliver"`。下一行调用了新实例的`drawSpeechBalloon`方法，介绍了`Oliver`在漫画中，然后`teddy`调用了`drawSpeechBalloon`方法，并将`oliver`作为`DrawableInComic`参数传递，因为`oliver`是`WonderCat`的一个实例，而`WonderCat`是实现`DrawableInComic`实例的类。因此，我们也可以在需要`DrawableInComic`参数时使用`WonderCat`的实例。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
WonderCat oliver = 
    new WonderCat("Oliver", 10, "Mr. Oliver", 0, 15, 25);
oliver.drawSpeechBalloon(
    String.format("Hello, my name is %s", oliver.getNickName()));
teddy.drawSpeechBalloon(oliver, 
    String.format("Hello %s", oliver.getNickName()));
```

以下代码创建了一个名为`misterHideable`的`HideableWonderCat`类的实例。在构造函数中为`nickName`参数指定的值为`"Mr. Hideable"`。下一行检查了使用`oliver`作为参数调用`isIntersectingWith`方法是否返回`true`。该方法需要一个`DrawableInComic`参数，因此我们可以使用`oliver`。该方法将返回`true`，因为两个实例的`x`和`y`字段具有相同的值。`if`块中的行调用了`misterHideable`的`setLocation`方法。然后，代码调用了`show`方法。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
HideableWonderCat misterHideable = 
    new HideableWonderCat("Mr. Hideable", 310, 
        "Mr. John Hideable", 67000, 15, 25, 3);
if (misterHideable.isIntersectingWith(oliver)) {
    misterHideable.setLocation(
        oliver.getX() + 30, oliver.getY() + 30);
}
misterHideable.show();
```

以下代码创建了一个名为`merlin`的`PowerableWonderCat`类的实例。在构造函数中为`nickName`参数指定的值是`"Merlin"`。接下来的几行调用了`setLocation`和`draw`方法。然后，代码使用`misterHideable`作为`Hideable`参数调用了`useSpellToHide`方法。该方法需要一个`Hideable`参数，因此我们可以使用`HideableWonderCat`的先前创建的实例`misterHideable`，该实例实现了`Hideable`接口。然后，对`misterHideable`的`show`方法的调用使具有三只眼睛的`Hideable`再次出现。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
PowerableWonderCat merlin = 
    new PowerableWonderCat("Merlin", 35, 
        "Mr. Merlin", 78000, 30, 40, 200);
merlin.setLocation(
    merlin.getX() + 5, merlin.getY() + 5);
merlin.draw();
merlin.useSpellToHide(misterHideable);
misterHideable.show();
```

以下代码创建了一个名为`spartan`的`FightableWonderCat`类的实例。在构造函数中为`nickName`参数指定的值是`"Spartan"`。接下来的几行调用了`setLocation`和`draw`方法。然后，代码使用`misterHideable`作为参数调用了`unsheathSword`方法。该方法需要一个`Hideable`参数，因此我们可以使用`HideableWonderCat`的先前创建的实现`Hideable`接口的实例`misterHideable`。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
FightableWonderCat spartan = 
    new FightableWonderCat("Spartan", 28, 
        "Sir Spartan", 1000000, 60, 60, 100, 50);
spartan.setLocation(
    spartan.getX() + 30, spartan.getY() + 10);
spartan.draw();
spartan.unsheathSword(misterHideable);

```

最后，代码调用了`misterHideable`的`drawThoughtBalloon`和`drawSpeechBalloon`方法。我们可以调用这些方法，因为`misterHideable`是`HideableWonderCat`的一个实例，而这个类从其超类`WonderCat`继承了`DrawableInComic`接口的实现。

对`drawSpeechBalloon`方法的调用将`spartan`作为`DrawableInComic`参数，因为`spartan`是`FightableWonderCat`的一个实例，它是一个类，也从其超类`WonderCat`继承了`DrawableInComic`接口的实现。因此，我们还可以在需要`DrawableInComic`参数时使用`FightableWonderCat`的实例，就像下面的代码中所做的那样。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_01.java`文件中。

```java
misterHideable.drawThoughtBalloon(
    "I guess I must be friendly...");
misterHideable.drawSpeechBalloon(
    spartan, "Pleased to meet you, Sir!");
```

在 JShell 中执行了前面解释的所有代码片段后，我们将看到以下文本输出：

```java
Teddy -> Hello, my name is Teddy
Teddy -> message: Winston, How do you do?
Winston -> ***Who are you? I think.***
Oliver -> Meow
Teddy -> message: Oliver, Hello Oliver
Moving WonderCat Mr. John Hideable to x:45, y:55
My name is Mr. John Hideable and you can see my 3 eyes.
Moving WonderCat Mr. Merlin to x:35, y:45
Drawing WonderCat Mr. Merlin at x:35, y:45
Mr. Merlin uses his 200 spell power to hide the Hideable with 3 eyes.
My name is Mr. John Hideable and you can see my 3 eyes.
Moving WonderCat Sir Spartan to x:90, y:70
Drawing WonderCat Sir Spartan at x:90, y:70
Sir Spartan unsheaths his sword.
Sword power: 100\. Sword weight: 50.
The sword targets a Hideable with 3 eyes.
Mr. Hideable thinks: 'I guess I must be friendly...'
Spartan ==> Mr. Hideable --> Pleased to meet you, Sir!

```

# 使用接口和类进行向下转型

`DrawableInComic`接口定义了`drawSpeechBalloon`方法的一个方法要求，其参数为`DrawableInComic`类型的`destination`，这与接口定义的类型相同。以下是我们示例代码中调用此方法的第一行：

```java
teddy.drawSpeechBalloon(winston, "How do you do?");
```

我们调用了`SpiderDog`类中实现的方法，因为`teddy`是`SpiderDog`的一个实例。我们将`SpiderDog`实例`winston`传递给`destination`参数。该方法使用`destination`参数作为实现`DrawableInComic`接口的实例。因此，每当我们引用`destination`变量时，我们只能看到`DrawableInComic`类型定义的内容。

当 Java 将类型从其原始类型向下转换为目标类型时，例如转换为类符合的接口，我们可以很容易地理解发生了什么。在这种情况下，`SpiderDog`被向下转换为`DrawableInComic`。如果我们在 JShell 中输入以下代码并按*Tab*键，JShell 将枚举名为`winston`的`SpiderDog`实例的成员：

```java
winston.
```

JShell 将显示以下成员：

```java
drawSpeechBalloon(    drawThoughtBalloon(   equals(
getClass()            getNickName()         hashCode()
nickName              notify()              notifyAll()
speak(                think(                toString()
wait(

```

每当我们要求 JShell 列出成员时，它将包括从`java.lang.Object`继承的以下成员：

```java
equals(       getClass()    hashCode()    notify()      notifyAll()
toString()    wait(

```

删除先前输入的代码（`winston.`）。如果我们在 JShell 中输入以下代码并按*Tab*键，括号中的`DrawableInComic`接口类型作为`winston`变量的前缀将强制将其降级为`DrawableInComic`接口类型。因此，JShell 将只列举`SpiderDog`实例`winston`中作为`DrawableInComic`接口所需成员：

```java
((DrawableInComic) winston).
```

JShell 将显示以下成员：

```java
drawSpeechBalloon(    drawThoughtBalloon(   equals(
getClass()            getNickName()         hashCode()
notify()              notifyAll()           toString()
wait(

```

让我们看一下当我们输入`winston.`并按*Tab*键时的结果与最新结果之间的区别。上一个列表中显示的成员不包括在`SpiderDog`类中定义但在`DrawableInComic`接口中不是必需的两个方法：`speak`和`think`。因此，当 Java 将`winston`降级为`DrawableInComic`时，我们只能使用`DrawableInComic`接口所需的成员。

### 提示

如果我们使用支持自动补全功能的任何 IDE，我们会注意到在使用自动补全功能而不是在 JShell 中按*Tab*键时，成员的枚举中存在相同的差异。

现在我们将分析另一种情况，即将一个实例降级为其实现的接口之一。`DrawableInGame`接口为`isIntersectingWith`方法定义了一个对`DrawableInGame`类型的`otherDrawableInGame`参数的要求，这与接口定义的类型相同。以下是我们调用此方法的示例代码中的第一行：

```java
if (misterHideable.isIntersectingWith(oliver)) {
```

我们调用了`WonderCat`类中定义的方法，因为`misterHideable`是`HideableWonderCat`的一个实例，它继承了`WonderCat`类中`isIntersectingWith`方法的实现。我们将`WonderCat`实例`oliver`传递给了`otherDrawableInGame`参数。该方法使用`otherDrawableInGame`参数作为一个实现了`DrawableInGame`实例的实例。因此，每当我们引用`otherDrawableInGame`变量时，我们只能看到`DrawableInGame`类型定义的内容。在这种情况下，`WonderCat`被降级为`DrawableInGame`。

如果我们在 JShell 中输入以下代码并按*Tab*键，JShell 将列举`WonderCat`实例`oliver`的成员：

```java
oliver.
```

JShell 将显示`oliver`的以下成员：

```java
age                   draw()                drawSpeechBalloon(
drawThoughtBalloon(   equals(               fullName
getAge()              getClass()            getFullName()
getNickName()         getScore()            getX()
getY()                hashCode()            isIntersectingWith(
nickName              notify()              notifyAll()
score                 setLocation(          toString()
wait(                 x                     y

```

删除先前输入的代码（`oliver.`）。如果我们在 JShell 中输入以下代码并按*Tab*键，括号中的`DrawableInGame`接口类型作为`oliver`变量的前缀将强制将其降级为`DrawableInGame`接口类型。因此，JShell 将只列举`WonderCat`实例`oliver`中作为`DrawableInGame`实例所需成员：

```java
((DrawableInComic) oliver).
```

JShell 将显示以下成员：

```java
draw()                equals(               getClass()
getFullName()         getScore()            getX()
getY()                hashCode()            isIntersectingWith(
notify()              notifyAll()           setLocation(
toString()            wait(

```

让我们看一下当我们输入`oliver.`并按*Tab*键时的结果与最新结果之间的区别。当 Java 将`oliver`降级为`DrawableInGame`时，我们只能使用`DrawableInGame`接口所需的成员。

我们可以使用类似的语法来强制将先前的表达式转换为原始类型，即`WonderCat`类型。如果我们在 JShell 中输入以下代码并按*Tab*键，JShell 将再次列举`WonderCat`实例`oliver`的所有成员：

```java
((WonderCat) ((DrawableInGame) oliver)).
```

JShell 将显示以下成员，即当我们输入`oliver.`并按*Tab*键时，JShell 列举的所有成员，而没有任何类型的强制转换：

```java
age                      draw()             drawSpeechBalloon(
drawThoughtBalloon(      equals(            fullName
getAge()                 getClass()         getFullName()
getNickName()            getScore()         getX()
getY()                   hashCode()         isIntersectingWith(
nickName                 notify()           notifyAll()
score                    setLocation(       toString()
wait(                    x                  y

```

# 将接口类型的实例视为不同的子类

在第七章中，*成员继承和多态性*，我们使用了多态性。下一个示例并不代表最佳实践，因为多态性是使其工作的方式。但是，我们将编写一些代码，这些代码并不代表最佳实践，只是为了更多地了解类型转换。

以下行创建了一个名为`doSomethingWithWonderCat`的方法在 JShell 中。我们将使用这个方法来理解如何将以接口类型接收的实例视为不同的子类。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_02.java`文件中。

```java
// The following code is just for educational purposes
// and it doesn't represent a best practice
// We should always take advantage of polymorphism instead
public void doSomethingWithWonderCat(WonderCat wonderCat) {
    if (wonderCat instanceof HideableWonderCat) {
        HideableWonderCat hideableCat = (HideableWonderCat) wonderCat;
        hideableCat.show();
    } else if (wonderCat instanceof FightableWonderCat) {
        FightableWonderCat fightableCat = (FightableWonderCat) wonderCat;
        fightableCat.unsheathSword();
    } else if (wonderCat instanceof PowerableWonderCat) {
        PowerableWonderCat powerableCat = (PowerableWonderCat) wonderCat;
        System.out.println(
            String.format("Spell power: %d", 
                powerableCat.getSpellPower()));
    } else {
        System.out.println("This WonderCat isn't cool.");
    }
}
```

`doSomethingWithWonderCat`方法在`wonderCat`参数中接收一个`WonderCat`实例。该方法评估了许多使用`instanceof`关键字的表达式，以确定`wonderCat`参数中接收的实例是否是`HideableWonderCat`、`FightableWonderCat`或`PowerableWonder`的实例。

如果`wonderCat`是`HideableWonderCat`的实例或任何潜在的`HideableWonderCat`子类的实例，则代码声明一个名为`hideableCat`的`HideableWonderCat`局部变量，以保存`wonderCat`转换为`HideableWonderCat`的引用。然后，代码调用`hideableCat.show`方法。

如果`wonderCat`不是`HideableWonderCat`的实例，则代码评估下一个表达式。如果`wonderCat`是`FightableWonderCat`的实例或任何潜在的`FightableWonderCat`子类的实例，则代码声明一个名为`fightableCat`的`FightableWonderCat`局部变量，以保存`wonderCat`转换为`FightableWonderCat`的引用。然后，代码调用`fightableCat.unsheathSword`方法。

如果`wonderCat`不是`FightableWonderCat`的实例，则代码评估下一个表达式。如果`wonderCat`是`PowerableWonderCat`的实例或任何潜在的`PowerableWonderCat`子类的实例，则代码声明一个名为`powerableCat`的`PowerableWonderCat`局部变量，以保存`wonderCat`转换为`PowerableWonderCat`的引用。然后，代码使用`powerableCat.getSpellPower()`方法返回的结果来打印咒语能量值。

最后，如果最后一个表达式评估为`false`，则表示`wonderCat`实例只属于`WonderCat`，代码将打印一条消息，指示`WonderCat`不够酷。

### 提示

如果我们必须执行类似于此方法中显示的代码的操作，我们必须利用多态性，而不是使用`instanceof`关键字基于实例所属的类来运行代码。请记住，我们使用这个示例来更多地了解类型转换。

现在我们将在 JShell 中多次调用最近编写的`doSomethingWithWonderCat`方法。我们将使用`WonderCat`及其子类的实例调用此方法，这些实例是在我们声明此方法之前创建的。我们将使用以下值调用`doSomethingWithWonderCat`方法作为`wonderCat`参数：

+   `misterHideable`：`HideableWonderCat`类的实例

+   `spartan`：`FightableWonderCat`类的实例

+   `merlin`：`PowerableWonderCat`类的实例

+   `oliver`：`WonderCat`类的实例

以下四行在 JShell 中使用先前枚举的参数调用`doSomethingWithWonderCat`方法。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_02.java`文件中。

```java
doSomethingWithWonderCat(misterHideable);
doSomethingWithWonderCat(spartan);
doSomethingWithWonderCat(merlin);
doSomethingWithWonderCat(oliver);
```

以下屏幕截图显示了 JShell 为前面的行生成的输出。每次调用都会触发不同的类型转换，并调用类型转换后的实例的方法：

![将接口类型的实例视为不同的子类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00086.jpeg)

# 利用 Java 9 中接口的默认方法

`SpiderDog`和`WonderCat`类都实现了`DrawableInComic`接口。所有继承自`WonderCat`类的类都继承了`DrawableInComic`接口的实现。假设我们需要向`DrawableInComic`接口添加一个新的方法要求，并且我们将创建实现这个新版本接口的新类。我们将添加一个新的`drawScreamBalloon`方法，用于绘制一个带有消息的尖叫气泡。

我们将在`SpiderDog`类中添加新方法的实现。但是，假设我们无法更改实现`DrawableInComic`接口的某个类的代码：`WonderCat`。这会带来一个大问题，因为一旦我们更改了`DrawableInComic`接口的代码，Java 编译器将为`WonderCat`类生成编译错误，我们将无法编译这个类及其子类。

在这种情况下，Java 8 引入的接口默认方法以及 Java 9 中也可用的接口默认方法非常有用。我们可以为`drawScreamBalloon`方法声明一个默认实现，并将其包含在`DrawableInComic`接口的新版本中。这样，`WonderCat`类及其子类将能够使用接口中提供的方法的默认实现，并且它们将符合接口中指定的要求。

以下的 UML 图显示了`DrawableInComic`接口的新版本，其中包含了名为`drawScreamBalloon`的默认方法，以及覆盖默认方法的`SpiderDog`类的新版本。请注意，`drawScreamBalloon`方法是唯一一个不使用斜体文本的方法，因为它不是一个抽象方法。

![利用 Java 9 中接口的默认方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00087.jpeg)

以下几行显示了声明`DrawableInComic`接口的新版本的代码，其中包括对`drawScreamBalloon`方法的方法要求和默认实现。请注意，在方法的返回类型之前使用`default`关键字表示我们正在声明一个默认方法。默认实现调用了每个实现接口的类将声明的`drawSpeechBalloon`方法。这样，实现这个接口的类默认情况下将在接收到绘制尖叫气泡的请求时绘制一个对话气泡。

示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_03.java`文件中。

```java
public interface DrawableInComic {
    String getNickName();
    void drawSpeechBalloon(String message);
    void drawSpeechBalloon(DrawableInComic destination, String message);
    void drawThoughtBalloon(String message);
 default void drawScreamBalloon(String message) {
 drawSpeechBalloon(message);
 }
}
```

### 提示

在我们创建接口的新版本后，JShell 将重置所有持有实现`DrawableInComic`接口的类实例引用的变量为`null`。因此，我们将无法使用我们一直在创建的实例来测试接口的更改。

以下几行显示了`SpiderDog`类的新版本的代码，其中包括新的`drawScreamBalloon`方法。新的行已经高亮显示。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_03.java`文件中。

```java
public class SpiderDog implements DrawableInComic {
    protected final String nickName;

    public SpiderDog(String nickName) {
        this.nickName = nickName;
    }

    protected void speak(String message) {
        System.out.println(
            String.format("%s -> %s",
                nickName,
                message));
    }

    protected void think(String message) {
        System.out.println(
            String.format("%s -> ***%s***",
                nickName,
                message));
    }

 protected void scream(String message) {
 System.out.println(
 String.format("%s screams +++ %s +++",
 nickName,
 message));
 }

    @Override
    public String getNickName() {
        return nickName;
    }

    @Override
    public void drawSpeechBalloon(String message) {
        speak(message);
    }

    @Override
    public void drawSpeechBalloon(DrawableInComic destination, 
        String message) {
        speak(String.format("message: %s, %s",
            destination.getNickName(),
            message));
    }

    @Override
    public void drawThoughtBalloon(String message) {
        think(message);
    }

 @Override
 public void drawScreamBalloon(String message) {
 scream(message);
 }
}
```

`SpiderDog`类覆盖了`drawScreamBalloon`方法的默认实现，使用了一个调用受保护的`scream`方法的新版本，该方法以特定格式打印接收到的`message`，并将`nickName`值作为前缀。这样，这个类将不使用`DrawableInComic`接口中声明的默认实现，而是使用自己的实现。

在下面的代码中，前几行创建了`SpiderDog`类的新版本实例`rocky`，以及`FightableWonderCat`类的新版本实例`maggie`。然后，代码调用`drawScreamBalloon`方法，并为两个创建的实例`rocky`和`maggie`传递消息。示例的代码文件包含在`java_9_oop_chapter_09_01`文件夹中的`example09_03.java`文件中。

```java
SpiderDog rocky = new SpiderDog("Rocky");
FightableWonderCat maggie = 
    new FightableWonderCat("Maggie", 2, 
        "Mrs. Maggie", 5000000, 10, 10, 80, 30);
rocky.drawScreamBalloon("I am Rocky!");
maggie.drawScreamBalloon("I am Mrs. Maggie!");
```

当我们调用`rocky.drawScreamBalloon`时，Java 执行了在`SpiderDog`类中声明的这个方法的重写实现。当我们调用`maggie.drawScreamBalloon`时，Java 执行了在`DrawableInComic`接口中声明的默认方法，因为`WonderCat`和`FightableWonderCat`类都没有重写这个方法的默认实现。不要忘记`FightableWonderCat`是`WonderCat`的子类。以下截图显示了在 JShell 中执行前面几行代码的结果：

![利用 Java 9 中接口的默认方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00088.jpeg)

# 测试你的知识

1.  默认方法允许我们声明：

1.  一个默认的构造函数，当实现接口的类没有声明构造函数时，Java 会使用这个默认构造函数。

1.  在实现接口的类的实例执行任何方法之前将被调用的方法。

1.  在接口中的一个方法的默认实现，当实现接口的类没有提供自己的方法实现时，Java 会使用这个默认实现。

1.  考虑到我们有一个现有的接口，许多类实现了这个接口，所有的类都能够编译通过而没有错误。如果我们向这个接口添加一个默认方法：

1.  实现接口的类在提供新方法要求的实现之前不会编译。

1.  实现接口的类在提供新构造函数要求的实现之前不会编译。

1.  实现接口的类将会编译。

1.  以下关键字中哪些允许我们确定一个实例是否是实现特定接口的类的实例：

1.  `instanceof`

1.  `isinterfaceimplementedby`

1.  `implementsinterface`

1.  以下哪些代码片段强制将`winston`变量向下转型为`DrawableInComic`接口：

1.  `(winston as DrawableInComic)`

1.  `((DrawableInComic) < winston)`

1.  `((DrawableInComic) winston)`

1.  以下哪些代码片段强制将`misterHideable`变量向下转型为`HideableWonderCat`类：

1.  `(misterHideable as HideableWonderCat)`

1.  `((HideableWonderCat) < misterHideable)`

1.  `((Hid``eableWonderCat) misterHideable)`

# 摘要

在本章中，你学会了当一个方法接收一个接口类型的参数时，在幕后发生了什么。我们使用了接收接口类型参数的方法，并且通过接口和类进行了向下转型。我们理解了如何将一个对象视为不同兼容类型的实例，以及当我们这样做时会发生什么。JShell 让我们能够轻松理解当我们使用类型转换时发生了什么。

我们利用了接口中的默认方法。我们可以向接口添加一个新方法并提供默认实现，以避免破坏我们无法编辑的现有代码。

现在你已经学会了在接口中使用高级场景，我们准备在 Java 9 中通过泛型最大化代码重用，这是我们将在下一章讨论的主题。 


# 第十章：通过泛型最大化代码重用

在本章中，我们将学习参数多态以及 Java 9 如何通过允许我们编写通用代码来实现这一面向对象的概念。我们将开始创建使用受限泛型类型的类。我们将：

+   理解参数多态

+   了解参数多态和鸭子类型之间的区别

+   理解 Java 9 泛型和通用代码

+   声明一个用作类型约束的接口

+   声明符合多个接口的类

+   声明继承接口实现的子类

+   创建异常类

+   声明一个使用受限泛型类型的类

+   使用一个通用类来处理多个兼容类型

# 理解参数多态、Java 9 泛型和通用代码

想象一下，我们开发了一个 Web 服务，必须使用特定野生动物聚会的组织表示。我们绝对不希望把狮子和鬣狗混在一起，因为聚会最终会以鬣狗吓唬一只孤狮而结束。我们希望一个组织有序的聚会，不希望有入侵者，比如龙或猫，出现在只有狮子应该参加的聚会中。

我们想描述启动程序、欢迎成员、组织聚会以及向聚会的不同成员道别的程序。然后，我们想在天鹅聚会中复制这些程序。因此，我们希望重用我们的程序来举办狮子聚会和天鹅聚会。将来，我们将需要使用相同的程序来举办其他野生动物和家养动物的聚会，比如狐狸、鳄鱼、猫、老虎和狗。显然，我们不希望成为鳄鱼聚会的入侵者。我们也不想参加老虎聚会。

在前几章中，第八章，“使用接口进行合同编程”，和第九章，“使用接口进行高级合同编程”，我们学习了如何在 Java 9 中使用接口。我们可以声明一个接口来指定可以参加聚会的动物的要求，然后利用 Java 9 的特性编写通用代码，可以与实现接口的任何类一起使用。

### 提示

**参数多态**允许我们编写通用和可重用的代码，可以处理值而不依赖于类型，同时保持完全的静态类型安全。

我们可以通过泛型在 Java 9 中利用参数多态，也称为通用编程。在我们声明一个指示可以参加聚会的动物要求的接口之后，我们可以创建一个可以与实现此接口的任何实例一起使用的类。这样，我们可以重用生成狮子聚会的代码，并创建天鹅、鬣狗或任何其他动物的聚会。具体来说，我们可以重用生成任何实现指定可以参加聚会的动物要求的接口的类的聚会的代码。

我们要求动物在聚会中要有社交能力，因此，我们可以创建一个名为`Sociable`的接口，来指定可以参加聚会的动物的要求。但要注意，我们将用作示例的许多野生动物并不太善于社交。

### 提示

许多现代强类型编程语言允许我们通过泛型进行参数多态。如果你有使用过 C#或 Swift，你会发现 Java 9 的语法与这些编程语言中使用的语法非常相似。C#也使用接口，但 Swift 使用协议而不是接口。

其他编程语言，如 Python、JavaScript 和 Ruby，采用一种称为**鸭子类型**的不同哲学，其中某些字段和方法的存在使对象适合于其用途作为特定的社交动物。使用鸭子类型，如果我们要求社交动物具有`getName`和`danceAlone`方法，只要对象提供了所需的方法，我们就可以将任何对象视为社交动物。因此，使用鸭子类型，任何提供所需方法的任何类型的实例都可以用作社交动物。

让我们来看一个真实的情况，以理解鸭子类型的哲学。想象一下，我们看到一只鸟，这只鸟嘎嘎叫、游泳和走路都像一只鸭子。我们肯定可以称这只鸟为鸭子，因为它满足了这只鸟被称为鸭子所需的所有条件。与鸟和鸭子相关的类似例子产生了鸭子类型的名称。我们不需要额外的信息来将这只鸟视为鸭子。Python、JavaScript 和 Ruby 是鸭子类型极为流行的语言的例子。

在 Java 9 中可以使用鸭子类型，但这不是这种编程语言的自然方式。在 Java 9 中实现鸭子类型需要许多复杂的解决方法。因此，我们将专注于学习通过泛型实现参数多态性的通用代码编写。

# 声明一个接口用作类型约束

首先，我们将创建一个`Sociable`接口，以指定类型必须满足的要求，才能被视为潜在的聚会成员，也就是我们应用领域中的社交动物。然后，我们将创建一个实现了这个接口的`SociableAnimal`抽象基类，然后，我们将在三个具体的子类中专门化这个类：`SocialLion`、`SocialParrot`和`SocialSwan`。然后，我们将创建一个`Party`类，它将能够通过泛型与实现`Sociable`接口的任何类的实例一起工作。我们将创建两个新的类，它们将代表特定的异常。我们将处理一群社交狮子、一群社交鹦鹉和一群社交天鹅。

以下的 UML 图显示了接口，实现它的抽象类，以及我们将创建的具体子类，包括所有的字段和方法：

![声明一个接口用作类型约束](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00089.jpeg)

以下几行显示了`Sociable`接口的代码。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public interface Sociable {
    String getName();
    int getAge();
    void actAlone();
    void danceAlone();
    void danceWith(Sociable partner);
    void singALyric(String lyric);
    void speak(String message);
    void welcome(Sociable other);
    void sayGoodbyeTo(Sociable other);
}
```

接口声明了以下九个方法要求：

+   `getName`：这个方法必须返回一个`String`，表示`Sociable`的名字。

+   `getAge`：这个方法必须返回一个`int`，表示`Sociable`的年龄。

+   `actAlone`：这个方法必须让`Sociable`独自行动。

+   `danceAlone`：这个方法必须让`Sociable`独自跳舞。

+   `danceWith`：这个方法必须让`Sociable`与另一个在 partner 参数中接收到的`Sociable`一起跳舞。

+   `singALyric`：这个方法必须让`Sociable`唱接收到的歌词。

+   `speak`：这个方法让`Sociable`说一条消息。

+   `welcome`：这个方法让`Sociable`向另一个在其他参数中接收到的`Sociable`说欢迎的消息。

+   `sayGoodbyeTo`：这个方法让`Sociable`向另一个在其他参数中接收到的`Sociable`说再见。

我们没有在接口声明中包含任何默认方法，因此实现`Sociable`接口的类负责实现之前列举的九个方法。

# 声明符合多个接口的类

```java
SocialAnimal abstract class. The code file for the sample is included in the java_9_oop_chapter_10_01 folder, in the example10_01.java file.
```

```java
public abstract class SocialAnimal implements Sociable, Comparable<Sociable> {
    public final String name;
    public final int age;

    public SocialAnimal(String name, int age) {
        this.name = name;
        this.age = age;
    }

    protected void printMessageWithNameAsPrefix(String message) {
        System.out.println(
            String.format("%s %s", 
                getName(), 
                message));
    }

    public abstract String getDanceRepresentation();

    public abstract String getFirstSoundInWords();

    public abstract String getSecondSoundInWords();

    public abstract String getThirdSoundInWords();

    @Override
    public String getName() {
        return name;
    }

    @Override
    public int getAge() {
        return age;
    }
```

```java
SocialAnimal class declares a constructor that assigns the value of the required name and age arguments to the immutable name and age protected fields. Then the class declares a protected printMessageWithNameAsPrefix method that receives a message and prints the name for the SocialAnimal followed by a space and this message. Many methods will call this method to easily add the name as a prefix for many messages.
SocialAnimal abstract class. The code file for the sample is included in the java_9_oop_chapter_10_01 folder, in the example10_01.java file.
```

```java
    @Override
    public void actAlone() {
        printMessageWithNameAsPrefix("to be or not to be");
    }

    @Override
    public void danceAlone() {
        printMessageWithNameAsPrefix(
            String.format("dances alone %s", 
                getDanceRepresentation()));
    }

    @Override
    public void danceWith(Sociable partner) {
        printMessageWithNameAsPrefix(
            String.format("dances with %s %s", 
                partner.getName(),
                getDanceRepresentation()));
    }

    @Override
    public void singALyric(String lyric) {
        printMessageWithNameAsPrefix(
            String.format("sings %s %s %s %s", 
                lyric,
                getFirstSoundInWords(),
                getSecondSoundInWords(),
                getThirdSoundInWords()));
    }

    @Override
    public void speak(String message) {
        printMessageWithNameAsPrefix(
            String.format("says: %s %s", 
                message,
                getDanceRepresentation()));
    }

    @Override
    public void welcome(Sociable other) {
        printMessageWithNameAsPrefix(
            String.format("welcomes %s", 
                other.getName()));
    }

    @Override
    public void sayGoodbyeTo(Sociable other) {
        printMessageWithNameAsPrefix(
            String.format("says goodbye to %s%s%s%s", 
                other.getName(),
                getFirstSoundInWords(),
                getSecondSoundInWords(),
                getThirdSoundInWords()));
    }
```

```java
 for the SocialAnimal class implements the other methods required by the Sociable interface:
```

+   `actAlone`：这个方法打印名字，后面跟着"to be or not to be"。

+   `danceAlone`：这个方法使用调用`getDanceRepresentation`方法检索到的`String`来打印名字，后面跟着指示社交动物正在跳舞的消息。

+   `danceWith`：此方法使用调用`getDanceRepresentation`方法获取的`String`来打印名称，然后是一条消息，指示社交动物正在与`Sociable`类型的 partner 参数指定的伙伴一起跳舞。消息中包括伙伴的名称。

+   `singALyric`：此方法使用调用`getFirstSoundInWords`、`getSecondSoundInWords`和`getThirdSoundInWords`获取的字符串以及作为参数接收到的歌词来打印名称，然后是一条消息，指示社交动物唱出歌词。

+   `speak`：此方法使用调用`getDanceRepresentation`获取的`String`和作为参数接收到的消息来打印名称，然后是动物说的话，再接着是它的舞蹈表示字符。

+   `welcome`：此方法打印一条消息，欢迎另一个在其他参数中接收到的`Sociable`。消息包括目的地的名称。

+   `sayGoodbyeTo`：此方法使用调用`getFirstSoundInWords`、`getSecondSoundInWords`和`getThirdSoundInWords`获取的字符串来构建并打印一条消息，向其他参数中接收到的另一个`Sociable`说再见。消息包括目的地的名称。

```java
for the SocialAnimal class overrides the compareTo method to implement the Comparable<Sociable> interface. In addition, this last code snippet for the SocialAnimal class overrides the equals method. The code file for the sample is included in the java_9_oop_chapter_10_01 folder, in the example10_01.java file.
```

```java
    @Override
    public boolean equals(Object other) {
        // Is other this object?
        if (this == other) {
            return true;
        }
        // Is other null?
        if (other == null) {
            return false;
        }
        // Does other have the same type?
        if (!getClass().equals(other.getClass())) {
            return false;
        }
        SocialAnimal otherSocialAnimal = (SocialAnimal) other;
        // Make sure both the name and age are equal
        return Objects.equals(getName(), otherSocialAnimal.getName())
        && Objects.equals(getAge(), otherSocialAnimal.getAge());
    }

    @Override
    public int compareTo(final Sociable otherSociable) {
        return Integer.compare(getAge(),otherSociable.getAge());
    }
}
```

```java
SocialAnimal class overrides the equals method inherited from java.lang.Object that receives the instance that we must compare with the actual instance in the other argument. Unluckily, we must use the Object type for the other argument in order to override the inherited method, and therefore, the code for the method has to use typecasting to cast the received instance to the SocialAnimal type.
```

首先，代码检查接收到的`Object`是否是对实际实例的引用。在这种情况下，代码返回`true`，不需要再进行其他检查。

然后，代码检查`other`的值是否等于`null`。如果方法接收到`null`，则代码返回`false`，因为实际实例不是`null`。

然后，代码检查实际实例的`getClass`方法返回的`String`是否与接收到的实例的相同方法返回的`String`匹配。如果这些值不匹配，则表示接收到的`Object`是不同类型的实例，因此不同，代码返回`false`。

此时，我们知道实际实例与接收到的实例具有相同的类型。因此，可以安全地将其他参数强制转换为`SocialAnimal`，并将转换后的引用保存在`SocialAnimal`类型的`otherSocialAnimal`局部变量中。

最后，代码返回评估当前实例和`otherSocialAnimal`的`getName`和`getAge`的`Object.equals`调用的结果是否都为`true`。

### 提示

当我们重写从`java.lang.Object`继承的`equals`方法时，遵循先前解释的步骤是一个好习惯。如果您有 C#的经验，重要的是要了解 Java 9 没有提供与`IEquatable<T>`接口等效的内容。此外，请注意，Java 不支持用户定义的运算符重载，这是其他面向对象编程语言（如 C++、C#和 Swift）中包含的功能。

`SocialAnimal`抽象类还实现了`Comparable<Sociable>`接口所需的`compareTo`方法。在这种情况下，代码非常简单，因为该方法在`otherSociable`参数中接收到一个`Sociable`实例，并返回调用`Integer.compare`方法的结果，即`java.lang.Integer`类的`compare`类方法。代码使用当前实例的`getAge`返回的`int`值和`otherSociable`作为两个参数调用此方法。`Integer.compare`方法返回以下结果：

+   如果第一个参数等于第二个参数，则为`0`。

+   如果第一个参数小于第二个参数，则小于`0`。

+   如果第一个参数大于第二个参数，则大于`0`。

所有继承自`SocialAnimal`的具体子类都将能够使用`SocialAnimal`抽象类中实现的`equals`和`compareTo`方法。

# 声明继承接口实现的子类

我们有一个抽象类`SocialAnimal`，它实现了`Sociable`和`Comparable<Sociable>`接口。我们不能创建这个抽象类的实例。现在，我们将创建`SocialAnimal`的一个具体子类，名为`SocialLion`。这个类声明了一个构造函数，最终调用了超类中定义的构造函数。该类实现了其超类中声明的四个抽象方法，以返回适合参加派对的狮子的适当值。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public class SocialLion extends SocialAnimal {
 public SocialLion(String name, int age) {
        super(name, age);
    }

    @Override
 public String getDanceRepresentation() {
        return "*-* ^\\/^ (-)";
    }

    @Override
 public String getFirstSoundInWords() {
        return "Roar";
    }

    @Override
 public String getSecondSoundInWords() {
        return "Rrooaarr";
    }

    @Override
 public String getThirdSoundInWords() {
        return "Rrrrrrrroooooaaarrrr";
    }
}
```

我们将创建另一个名为`SocialParrot`的`SocialAnimal`的具体子类。这个新的子类也实现了`SocialAnimal`超类中定义的抽象方法，但在这种情况下，返回了鹦鹉的适当值。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public class SocialParrot extends SocialAnimal {
    public SocialParrot(String name, int age) {
        super(name, age);
    }

    @Override
 public String getDanceRepresentation() {
        return "/|\\ -=- % % +=+";
    }

    @Override
 public String getFirstSoundInWords() {
        return "Yeah";
    }

    @Override
 public String getSecondSoundInWords() {
        return "Yeeaah";
    }

    @Override
 public String getThirdSoundInWords() {
        return "Yeeeaaaah";
    }
}
```

最后，我们将创建另一个名为`SocialSwan`的`SocialAnimal`的具体子类。这个新的子类也实现了`SocialAnimal`超类中定义的抽象方法，但在这种情况下，返回了天鹅的适当值。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public class SocialSwan extends SocialAnimal {
    public SocialSwan(String name, int age) {
        super(name, age);
    }

    @Override
 public String getDanceRepresentation() {
        return "^- ^- ^- -^ -^ -^";
    }

    @Override
 public String getFirstSoundInWords() {
        return "OO-OO-OO";
    }

    @Override
 public String getSecondSoundInWords() {
        return "WHO-HO WHO-HO";
    }

    @Override
 public String getThirdSoundInWords() {
        return "WHO-WHO WHO-WHO";
    }
}
```

我们有三个具体类，它们继承了两个接口的实现，这两个接口来自它们的抽象超类`SociableAnimal`。以下三个具体类都实现了`Sociable`和`Comparable<Sociable>`接口，并且它们可以使用继承的重写的`equals`方法来比较它们的实例：

+   `SocialLion`

+   `SocialParrot`

+   `SocialSwan`

# 创建异常类

我们将创建两个异常类，因为我们需要抛出 Java 9 平台中没有表示的异常类型。具体来说，我们将创建`java.lang.Exception`类的两个子类。

以下行声明了`InsufficientMembersException`类，它继承自`Exception`。当一个派对的成员数量不足以执行需要更多成员的操作时，我们将抛出这个异常。该类定义了一个不可变的`numberOfMembers`私有字段，类型为`int`，它在构造函数中初始化为接收到的值。此外，该类声明了一个`getNumberOfMembers`方法，返回这个字段的值。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public class InsufficientMembersException extends Exception {
    private final int numberOfMembers;

    public InsufficientMembersException(int numberOfMembers) {
        this.numberOfMembers = numberOfMembers;
    }

    public int getNumberOfMembers() {
        return numberOfMembers;
    }
}
```

以下行声明了`CannotRemovePartyLeaderException`类，它继承自`Exception`。当一个方法试图从派对成员列表中移除当前的派对领袖时，我们将抛出这个异常。在这种情况下，我们只声明了一个继承自`Exception`的空类，因为我们不需要额外的功能，我们只需要新的类型。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
public class CannotRemovePartyLeaderException extends Exception {
}
```

# 声明一个与受限泛型类型一起工作的类

以下行声明了一个`Party`类，利用泛型来处理多种类型。 我们导入`java.util.concurrent.ThreadLocalRandom`，因为它是一个非常有用的类，可以轻松地在范围内生成伪随机数。 类名`Party`后面跟着一个小于号(`<`)，一个标识泛型类型参数的`T`，`extends`关键字，以及`T`泛型类型参数必须实现的接口名称`Sociable`，一个和号(`&`)，以及`T`泛型类型必须实现的另一个接口名称`Comparable<Sociable>`。 大于号(`>`)结束了包含在尖括号(`<>`)中的类型约束声明。 因此，`T`泛型类型参数必须是一个既实现`Sociable`接口又实现`Comparable<Sociable>`接口的类型。 以下代码突出显示了使用`T`泛型类型参数的行。 示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
import java.util.concurrent.ThreadLocalRandom;

public class Party<T extends Sociable & Comparable<Sociable>> {
 protected final List<T> members;
 protected T partyLeader;

 public Party(T partyLeader) {
        this.partyLeader = partyLeader;
 members = new ArrayList<>();
        members.add(partyLeader);
    }

 public T getPartyLeader() {
        return partyLeader;
    }
 public void addMember(T newMember) {
        members.add(newMember);
        partyLeader.welcome(newMember);
    }

 public T removeMember(T memberToRemove) throws CannotRemovePartyLeaderException {
        if (memberToRemove.equals(partyLeader)) {
            throw new CannotRemovePartyLeaderException();
        }
        int memberIndex = members.indexOf(memberToRemove);
        if (memberIndex >= 0) {
            members.remove(memberToRemove);
            memberToRemove.sayGoodbyeTo(partyLeader);
            return memberToRemove;
        } else {
            return null;
        }
    }

    public void makeMembersAct() {
 for (T member : members) {
            member.actAlone();
        }
    }

    public void makeMembersDance() {
 for (T member : members) {
            member.danceAlone();
        }
    }

    public void makeMembersSingALyric(String lyric) {
 for (T member : members) {
            member.singALyric(lyric);
        }
    }

    public void declareNewPartyLeader() throws InsufficientMembersException {
        if (members.size() == 1) {
            throw new InsufficientMembersException(members.size());
        }
 T newPartyLeader = partyLeader;
        while (newPartyLeader.equals(partyLeader)) {
            int pseudoRandomIndex = 
                ThreadLocalRandom.current().nextInt(
                    0, 
                    members.size());
            newPartyLeader = members.get(pseudoRandomIndex);
        }
        partyLeader.speak(
            String.format("%s is our new party leader.", 
                newPartyLeader.getName()));
        newPartyLeader.danceWith(partyLeader);
        if (newPartyLeader.compareTo(partyLeader) < 0) {
            // The new party leader is younger
            newPartyLeader.danceAlone();
        }
        partyLeader = newPartyLeader;
    }
}
```

现在我们将分析许多代码片段，以了解包含在`Party<T>`类中的代码是如何工作的。 以下行开始了类体，声明了一个受保护的`List<T>`，即元素类型为`T`或实现`T`接口的元素列表。 `List`使用泛型来指定将被接受和添加到列表中的元素的类型。

```java
protected final List<T> members;
```

以下行声明了一个受保护的`partyLeader`字段，其类型为`T`：

```java
protected T partyLeader;
```

以下行声明了一个接收`partyLeader`参数的构造函数，其类型为`T`。 该参数指定了第一位党领导者，也是党的第一位成员，即添加到`membersList<T>`的第一个元素。 创建新的`ArrayList<T>`的代码利用了 Java 7 中引入的类型推断，Java 8 中改进，并在 Java 9 中保留。 我们指定`new ArrayList<>()`而不是`new` `ArrayList<T>()`，因为 Java 9 可以使用空类型参数集(`<>`)从上下文中推断出类型参数。 `members`受保护字段具有`List<T>`类型，因此，Java 的类型推断可以确定`T`是类型，并且`ArrayList<>()`意味着`ArrayList<T>()`。 最后一行将`partyLeader`添加到`members`列表中。

```java
public Party(T partyLeader) {
    this.partyLeader = partyLeader;
    members = new ArrayList<>();
    members.add(partyLeader);
}
```

### 提示

当我们使用空类型参数集调用泛型类的构造函数时，尖括号(`<>`)被称为**diamond**，并且该表示法称为**diamond notation**。

以下行声明了`getPartyLeader`方法，指定`T`作为返回类型。 该方法返回`partyLeader`。

```java
public T getPartyLeader() {
    return partyLeader;
}
```

以下行声明了`addMember`方法，该方法接收一个类型为`T`的`newMember`参数。 该代码将接收到的新成员添加到`members`列表中，并调用`partyLeader.sayWelcomeTo`方法，将`newMember`作为参数，使得党领导者欢迎新成员：

```java
public void addMember(T newMember) {
    members.add(newMember);
    partyLeader.welcome(newMember);
}
```

以下行声明了`removeMember`方法，该方法接收一个类型为`T`的`memberToRemove`参数，返回`T`，并且可能抛出`CannotRemovePartyLeaderException`异常。 方法参数后面的`throws`关键字，后跟异常名称，表示该方法可以抛出指定的异常。 代码检查要移除的成员是否与党领导者匹配，使用`equals`方法进行检查。 如果成员是党领导者，则该方法抛出`CannotRemovePartyLeaderException`异常。 代码检索列表中`memberToRemove`的索引，并在该成员是列表成员的情况下调用`members.remove`方法，参数为`memberToRemove`。 然后，代码调用成功移除成员的`sayGoodbyeTo`方法，参数为`partyLeader`。 这样，离开党的成员向党领导者道别。 如果成员被移除，则该方法返回被移除的成员。 否则，该方法返回`null`。

```java
public T removeMember(T memberToRemove) throws CannotRemovePartyLeaderException {
    if (memberToRemove.equals(partyLeader)) {
        throw new CannotRemovePartyLeaderException();
    }
    int memberIndex = members.indexOf(memberToRemove);
    if (memberIndex >= 0) {
        members.remove(memberToRemove);
        memberToRemove.sayGoodbyeTo(partyLeader);
        return memberToRemove;
    } else {
        return null;
    }
}
```

以下行声明了`makeMembersAct`方法，该方法调用`members`列表中每个成员的`actAlone`方法：

```java
public void makeMembersAct() {
    for (T member : members) {
        member.actAlone();
    }
}
```

### 注意

在接下来的章节中，我们将学习在 Java 9 中将面向对象编程与函数式编程相结合的其他编码方法，以执行列表中每个成员的操作。

以下行声明了`makeMembersDance`方法，该方法调用`members`列表中每个成员的`danceAlone`方法：

```java
public void makeMembersDance() {
    for (T member : members) {
        member.danceAlone();
    }
}
```

以下行声明了`makeMembersSingALyric`方法，该方法接收一个`lyricString`并调用`members`列表中每个成员的`singALyric`方法，参数为接收到的`lyric`：

```java
public void makeMembersSingALyric(String lyric) {
    for (T member : members) {
        member.singALyric(lyric);
    }
}
```

### 提示

请注意，方法没有标记为 final，因此，我们将能够在将来的子类中重写这些方法。

最后，以下行声明了`declareNewPartyLeader`方法，该方法可能会抛出`InsufficientMembersException`。与`removeMember`方法一样，方法参数后的`throws`关键字后跟着`InsufficientMembersException`表示该方法可能会抛出`InsufficientMembersException`异常。如果`members`列表中只有一个成员，代码将抛出`InsufficientMembersException`异常，并使用从`members.size()`返回的值创建继承自`Exception`的类的实例。请记住，此异常类使用此值初始化一个字段，调用此方法的代码将能够检索到不足的成员数量。如果至少有两个成员，代码将生成一个新的伪随机党领袖，与现有的不同。代码使用`ThreadLocalRandom.current().nextInt`生成一个伪随机的`int`范围内的数字。代码调用`speak`方法让现任领袖向其他党员解释他们有了新的党领袖。代码调用`danceWith`方法，让新领袖与前任党领袖一起跳舞。如果调用`newPartyLeader.compareTo`方法与前任党领袖作为参数返回小于`0`，则意味着新的党领袖比前任年轻，代码将调用`newPartyLeader.danceAlone`方法。最后，代码将新值设置为`partyLeader`字段。

```java
public void declareNewPartyLeader() throws InsufficientMembersException {
    if (members.size() == 1) {
        throw new InsufficientMembersException(members.size());
    }
    T newPartyLeader = partyLeader;
    while (newPartyLeader.equals(partyLeader)) {
        int pseudoRandomIndex = 
            ThreadLocalRandom.current().nextInt(
                0, 
                members.size());
        newPartyLeader = members.get(pseudoRandomIndex);
    }
    partyLeader.speak(
        String.format("%s is our new party leader.", 
            newPartyLeader.getName()));
    newPartyLeader.danceWith(partyLeader);
    if (newPartyLeader.compareTo(partyLeader) < 0) {
        // The new party leader is younger
        newPartyLeader.danceAlone();
    }
    partyLeader = newPartyLeader;
}
```

# 使用通用类处理多个兼容类型

我们可以通过将`T`通用类型参数替换为符合`Party<T>`类声明中指定的类型约束的任何类型名称来创建`Party<T>`类的实例。到目前为止，我们有三个实现了`Sociable`和`Comparable<Sociable>`接口的具体类：`SocialLion`、`SocialParrot`和`SocialSwan`。因此，我们可以使用`SocialLion`来创建`Party<SocialLion>`的实例，即`SocialLion`的派对。我们利用类型推断，并使用先前解释的菱形符号。这样，我们将创建一个狮子派对，而`Simba`是党领袖。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
SocialLion simba = new SocialLion("Simba", 10);
SocialLion mufasa = new SocialLion("Mufasa", 5);
SocialLion scar = new SocialLion("Scar", 9);
SocialLion nala = new SocialLion("Nala", 7);
Party<SocialLion> lionsParty = new Party<>(simba);
```

`lionsParty`实例将仅接受`SocialLion`实例，其中类定义使用名为`T`的通用类型参数。以下行通过调用`addMember`方法为狮子派对添加了先前创建的三个`SocialLion`实例。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
lionsParty.addMember(mufasa);
lionsParty.addMember(scar);
lionsParty.addMember(nala);
```

以下行调用`makeMembersAct`方法使所有狮子行动，调用`makeMembersDance`方法使所有狮子跳舞，使用`removeMember`方法删除不是派对领袖的成员，使用`declareNewPartyLeader`方法声明一个新领袖，最后调用`makeMembersSingALyric`方法使所有狮子唱歌。我们将在调用`removeMember`和`declareNewPartyLeader`之前添加`try`关键字，因为这些方法可能会抛出异常。在这种情况下，我们不检查`removeMember`返回的结果。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
lionsParty.makeMembersAct();
lionsParty.makeMembersDance();
try {
    lionsParty.removeMember(nala);
} catch (CannotRemovePartyLeaderException e) {
    System.out.println(
        "We cannot remove the party leader.");
}
try {
    lionsParty.declareNewPartyLeader();
} catch (InsufficientMembersException e) {
    System.out.println(
        String.format("We just have %s member",
            e.getNumberOfMembers()));
}
lionsParty.makeMembersSingALyric("Welcome to the jungle");
```

以下行显示了在 JShell 中运行前面的代码片段后的输出。但是，我们必须考虑到新派对领袖的伪随机选择，因此结果在每次执行时会有所不同：

```java
Simba welcomes Mufasa
Simba welcomes Scar
Simba welcomes Nala
Simba to be or not to be
Mufasa to be or not to be
Scar to be or not to be
Nala to be or not to be
Simba dances alone *-* ^\/^ (-)
Mufasa dances alone *-* ^\/^ (-)
Scar dances alone *-* ^\/^ (-)
Nala dances alone *-* ^\/^ (-)
Nala says goodbye to Simba RoarRrooaarrRrrrrrrroooooaaarrrr
Simba says: Scar is our new party leader. *-* ^\/^ (-)
Scar dances with Simba *-* ^\/^ (-)
Scar dances alone *-* ^\/^ (-)
Simba sings Welcome to the jungle Roar Rrooaarr Rrrrrrrroooooaaarrrr
Mufasa sings Welcome to the jungle Roar Rrooaarr Rrrrrrrroooooaaarrrr
Scar sings Welcome to the jungle Roar Rrooaarr Rrrrrrrroooooaaarrrr

```

我们可以使用`SocialParrot`创建`Party<SocialParrot>`的实例，即`SocialParrot`的`Party`。我们使用先前解释的菱形符号。这样，我们将创建一个鹦鹉派对，`Rio`是派对领袖。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
SocialParrot rio = new SocialParrot("Rio", 3);
SocialParrot thor = new SocialParrot("Thor", 6);
SocialParrot rambo = new SocialParrot("Rambo", 4);
SocialParrot woody = new SocialParrot("Woody", 5);
Party<SocialParrot> parrotsParty = new Party<>(rio);
```

`parrotsParty`实例将仅接受`SocialParrot`实例，用于类定义使用名为`T`的泛型类型参数的所有参数。以下行通过为每个实例调用`addMember`方法，将先前创建的三个`SocialParrot`实例添加到鹦鹉派对中。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
parrotsParty.addMember(thor);
parrotsParty.addMember(rambo);
parrotsParty.addMember(woody);
```

以下行调用`makeMembersDance`方法使所有鹦鹉跳舞，使用`removeMember`方法删除不是派对领袖的成员，使用`declareNewPartyLeader`方法声明一个新领袖，最后调用`makeMembersSingALyric`方法使所有鹦鹉唱歌。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_01.java`文件中。

```java
parrotsParty.makeMembersDance();
try {
    parrotsParty.removeMember(rambo);
} catch (CannotRemovePartyLeaderException e) {
    System.out.println(
        "We cannot remove the party leader.");
}
try {
    parrotsParty.declareNewPartyLeader();
} catch (InsufficientMembersException e) {
    System.out.println(
        String.format("We just have %s member",
            e.getNumberOfMembers()));
}
parrotsParty.makeMembersSingALyric("Fly like a bird");
```

以下行显示了在 JShell 中运行前面的代码片段后的输出。再次，我们必须考虑到新派对领袖的伪随机选择，因此结果在每次执行时会有所不同：

```java
Rio welcomes Thor
Rio welcomes Rambo
Rio welcomes Woody
Rio dances alone /|\ -=- % % +=+
Thor dances alone /|\ -=- % % +=+
Rambo dances alone /|\ -=- % % +=+
Woody dances alone /|\ -=- % % +=+
Rambo says goodbye to Rio YeahYeeaahYeeeaaaah
Rio says: Woody is our new party leader. /|\ -=- % % +=+
Woody dances with Rio /|\ -=- % % +=+
Rio sings Fly like a bird Yeah Yeeaah Yeeeaaaah
Thor sings Fly like a bird Yeah Yeeaah Yeeeaaaah
Woody sings Fly like a bird Yeah Yeeaah Yeeeaaaah

```

以下行将无法编译，因为我们使用了不兼容的类型。首先，我们尝试将`SocialParrot`实例`rio`添加到`Party<SocialLion>`的`lionsParty`。然后，我们尝试将`SocialLion`实例`simba`添加到`Party<SocialParrot>`的`parrotsParty`。这两行都将无法编译，并且 JShell 将显示一条消息，指示类型不兼容，它们无法转换为每个派对所需的必要类型。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_02.java`文件中。

```java
// The following lines won't compile
// and will generate errors in JShell
lionsParty.addMember(rio);
parrotsParty.addMember(simba);
```

以下屏幕截图显示了在我们尝试执行前面的行时 JShell 中显示的错误：

![使用泛型类处理多个兼容类型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00090.jpeg)

我们可以使用`SocialSwan`创建`Party<SocialSwan>`的实例，即`SocialSwan`的`Party`。这样，我们将创建一个天鹅派对，`Kevin`是派对领袖。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_03.java`文件中。

```java
SocialSwan kevin = new SocialSwan("Kevin", 3);
SocialSwan brandon = new SocialSwan("Brandon", 5);
SocialSwan nicholas = new SocialSwan("Nicholas", 6);
Party<SocialSwan> swansParty = new Party<>(kevin);
```

`swansParty`实例将仅接受`SocialSwan`实例，用于类定义使用名为`T`的泛型类型参数的所有参数。以下行通过为每个实例调用`addMember`方法，将先前创建的两个`SocialSwan`实例添加到天鹅派对中。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_03.java`文件中。

```java
swansParty.addMember(brandon);
swansParty.addMember(nicholas);
```

以下行调用`makeMembersDance`方法使所有鹦鹉跳舞，使用`removeMember`方法尝试移除党领袖，使用`declareNewPartyLeader`方法宣布新领袖，最后调用`makeMembersSingALyric`方法使所有天鹅唱歌。示例的代码文件包含在`java_9_oop_chapter_10_01`文件夹中的`example10_03.java`文件中。

```java
swansParty.makeMembersDance();
try {
    swansParty.removeMember(kevin);
} catch (CannotRemovePartyLeaderException e) {
    System.out.println(
        "We cannot remove the party leader.");
}
try {
    swansParty.declareNewPartyLeader();
} catch (InsufficientMembersException e) {
    System.out.println(
        String.format("We just have %s member",
            e.getNumberOfMembers()));
}
swansParty.makeMembersSingALyric("It will be our swan song");
```

以下行显示了在 JShell 中运行前面的代码片段后的输出。再次，我们必须考虑到新的党领袖是伪随机选择的，因此，结果在每次执行时都会有所不同：

```java
Kevin welcomes Brandon
Kevin welcomes Nicholas
Kevin dances alone ^- ^- ^- -^ -^ -^
Brandon dances alone ^- ^- ^- -^ -^ -^
Nicholas dances alone ^- ^- ^- -^ -^ -^
We cannot remove the party leader.
Kevin says: Brandon is our new party leader. ^- ^- ^- -^ -^ -^
Brandon dances with Kevin ^- ^- ^- -^ -^ -^
Kevin sings It will be our swan song OO-OO-OO WHO-HO WHO-HO WHO-WHO WHO-WHO
Brandon sings It will be our swan song OO-OO-OO WHO-HO WHO-HO WHO-WHO WHO-WHO
Nicholas sings It will be our swan song OO-OO-OO WHO-HO WHO-HO WHO-WHO WHO-WHO

```

# 测试你的知识

1.  `public class Party<T extends Sociable & Comparable<Sociable>>`行的意思是：

1.  泛型类型约束指定`T`必须实现`Sociable`或`Comparable<Sociable>`接口之一。

1.  泛型类型约束指定`T`必须实现`Sociable`和`Comparable<Sociable>`接口。

1.  该类是`Sociable`和`Comparable<Sociable>`类的子类。

1.  以下哪行与 Java 9 中的`List<SocialLion> lionsList = new ArrayList<SocialLion>();`等效：

1.  `List<SocialLion> lionsList = new ArrayList();`

1.  `List<SocialLion> lionsList = new ArrayList<>();`

1.  `var lionsList = new ArrayList<SocialLion>();`

1.  以下哪行使用了钻石符号来利用 Java 9 的类型推断：

1.  `List<SocialLion> lionsList = new ArrayList<>();`

1.  `List<SocialLion> lionsList = new ArrayList();`

1.  `var lionsList = new ArrayList<SocialLion>();`

1.  Java 9 允许我们通过以下方式使用参数多态性：

1.  鸭子打字。

1.  兔子打字。

1.  泛型。

1.  以下哪个代码片段声明了一个类，其泛型类型约束指定`T`必须实现`Sociable`和`Convertible`接口：

1.  `public class Game<T extends Sociable & Convertible>`

1.  `public class Game<T: where T is Sociable & Convertible>`

1.  `public class Game<T extends Sociable> where T: Convertible`

# 总结

在本章中，您学会了通过编写能够与不同类型的对象一起工作的代码来最大化代码重用，也就是说，能够实现特定接口的类的实例或其类层次结构包括特定超类的类的实例。我们使用了接口、泛型和受限泛型类型。

我们创建了能够使用受限泛型类型的类。我们结合了类继承和接口，以最大化代码的可重用性。我们可以使类与许多不同类型一起工作，我们能够编写一个能够被重用来创建狮子、鹦鹉和天鹅的派对行为的类。

现在您已经学会了关于参数多态性和泛型的基础知识，我们准备在 Java 9 中与泛型最大化代码重用的更高级场景一起工作，这是我们将在下一章讨论的主题。
