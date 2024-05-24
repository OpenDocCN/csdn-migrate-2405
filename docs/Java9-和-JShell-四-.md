# Java9 和 JShell（四）

> 原文：[`zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53`](https://zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：高级泛型

在本章中，我们将深入探讨参数多态性以及 Java 9 如何允许我们编写使用两个受限泛型类型的类的通用代码。我们将：

+   在更高级的场景中使用参数多态性

+   创建一个新接口，用作第二个类型参数的约束

+   声明两个实现接口以处理两个类型参数的类

+   声明一个使用两个受限泛型类型的类

+   使用具有两个泛型类型参数的泛型类

# 创建一个新接口，用作第二个类型参数的约束

到目前为止，我们一直在处理派对，其中派对成员是善于社交的动物。然而，没有一些音乐很难享受派对。善于社交的动物需要听到一些东西，以便让它们跳舞并享受他们的派对。我们想要创建一个由善于社交的动物和一些可听到的东西组成的派对。

现在，我们将创建一个新的接口，稍后在定义另一个利用两个受限泛型类型的类时将使用该接口作为约束。以下是`Hearable`接口的代码。

示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
public interface Hearable {
    void playMusic();
    void playMusicWithLyrics(String lyrics);
}
```

接口声明了两个方法要求：`playMusic`和`playMusicWithLyrics`。正如我们在之前的章节中学到的，接口只包括方法声明，因为实现`Hearable`接口的类将负责提供这两个方法的实现。

# 声明两个实现接口以处理两个类型参数

现在，我们将声明一个名为`Smartphone`的类，该类实现先前定义的`Hearable`接口。我们可以将类声明解读为“`Smartphone`类实现`Hearable`接口”。以下是新类的代码。

```java
public class Smartphone implements Hearable {
    public final String modelName;

    public Smartphone(String modelName) {
        this.modelName = modelName;
    }

    @Override
    public void playMusic() {
        System.out.println(
            String.format("%s starts playing music.",
                modelName));
        System.out.println(
            String.format("cha-cha-cha untz untz untz",
                modelName));
    }

    @Override
    public void playMusicWithLyrics(String lyrics) {
        System.out.println(
            String.format("%s starts playing music with lyrics.",
                modelName));
        System.out.println(
            String.format("untz untz untz %s untz untz",
                lyrics));
    }
}
```

`Smartphone`类声明了一个构造函数，将必需的`modelName`参数的值分配给`modelName`不可变字段。此外，该类实现了`Hearable`接口所需的两个方法：`playMusic`和`playMusicWithLyrics`。

`playMusic`方法打印一条消息，显示智能手机型号名称，并指示设备开始播放音乐。然后，该方法以文字形式打印多个声音。`playMusicWithLyrics`方法打印一条消息，显示智能手机型号名称，然后是另一条包含文字声音和作为参数接收的歌词的消息。

现在，我们将声明一个名为`AnimalMusicBand`的类，该类也实现了先前定义的`Hearable`接口。我们可以将类声明解读为“`AnimalMusicBand`类实现`Hearable`接口”。以下是新类的代码。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
public class AnimalMusicBand implements Hearable {
    public final String bandName;
    public final int numberOfMembers;

    public AnimalMusicBand(String bandName, int numberOfMembers) {
        this.bandName = bandName;
        this.numberOfMembers = numberOfMembers;
    }

    @Override
    public void playMusic() {
        System.out.println(
            String.format("Our name is %s. We are %d.",
                bandName,
                numberOfMembers));
        System.out.println(
            String.format("Meow Meow Woof Woof Meow Meow",
                bandName));
    }

    @Override
    public void playMusicWithLyrics(String lyrics) {
        System.out.println(
            String.format("%s asks you to sing together.",
                bandName));
        System.out.println(
            String.format("Meow Woof %s Woof Meow",
                lyrics));
    }
}
```

`AnimalMusicBand`类声明了一个构造函数，将必需的`bandName`和`numberOfMembers`参数的值分配给与这些参数同名的不可变字段。此外，该类实现了`Hearable`接口所需的两个方法：`playMusic`和`playMusicWithLyrics`。

`playMusic`方法打印一条消息，向观众介绍动物音乐乐队，并指出成员数量。然后，该方法以文字形式打印多个声音。`playMusicWithLyrics`方法打印一条消息，要求观众与动物音乐乐队一起唱歌，然后是另一条带有文字和作为参数接收的歌词的消息。

# 声明一个与两个受限泛型类型一起工作的类

以下行声明了一个`PartyWithHearable`子类，该子类是先前创建的`Party<T>`类的子类，利用泛型来处理两个受限类型。类型约束声明包含在尖括号(`<>`)中。在这种情况下，我们有两个泛型类型参数：`T`和`U`。名为`T`的泛型类型参数必须实现`Sociable`和`Comparable<Sociable>`接口，就像在`Party<T>`超类中一样。名为`U`的泛型类型参数必须实现`Hearable`接口。请注意，跟随类型参数的`extends`关键字允许我们向泛型类型参数添加约束，尖括号之后的相同关键字指定该类继承自`Party<T>`超类。这样，该类为`T`和`U`泛型类型参数指定了约束，并且继承自`Party<T>`。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
public class PartyWithHearable<T extends Sociable & Comparable<Sociable>, U extends Hearable> extends Party<T> {
 protected final U soundGenerator;

 public PartyWithHearable(T partyLeader, U soundGenerator) {
        super(partyLeader);
 this.soundGenerator = soundGenerator;
    }

    @Override
    public void makeMembersDance() {
 soundGenerator.playMusic();
        super.makeMembersDance();
    }

    @Override
    public void makeMembersSingALyric(String lyric) {
 soundGenerator.playMusicWithLyrics(lyric);
        super.makeMembersSingALyric(lyric);
    }
}
```

### 提示

当 Java 中的类型参数有约束时，它们也被称为**有界类型参数**。此外，类型约束也被称为有界类型参数的**上界**，因为任何实现用作上界的接口或任何指定为上界的类的子类都可以用于类型参数。

现在我们将分析许多代码片段，以了解包含在`PartyWithHearable<T, U>`类中的代码是如何工作的。以下行开始类体并声明了一个受保护的不可变的`soundGenerator`字段，其类型由`U`指定：

```java
protected final U soundGenerator;
```

以下行声明了一个初始化器，该初始化器接收两个参数，`partyLeader`和`soundGenerator`，它们的类型分别为`T`和`U`。这些参数指定了将成为派对第一领导者并成为派对第一成员的第一领导者，以及将使派对成员跳舞和唱歌的声音发生器。构造函数使用`super`关键字调用其超类中定义的构造函数，并将`partyLeader`作为参数。

```java
public PartyWithHearable(T partyLeader, U soundGenerator) {
    super(partyLeader);
    this.soundGenerator = soundGenerator;
}
```

以下行声明了一个`makeMembersDance`方法，该方法覆盖了在超类中包含的相同声明的方法。代码调用`soundGenetor.playMusic`方法，然后使用`super`关键字调用`super.makeMembersDance`方法，即在`Party<T>`超类中定义的`makeMembersDance`方法：

```java
@Override
public void makeMembersDance() {
    soundGenerator.playMusic();
    super.makeMembersDance();
}
```

### 注意

当我们在子类中覆盖一个方法时，我们可以使用`super`关键字后跟一个点(`.`)和方法名来调用在超类中定义的方法，并将所需的参数传递给该方法。使用`super`关键字允许我们调用在超类中被覆盖的实例方法。这样，我们可以向方法添加新特性，同时仍然调用基本方法。

最后，以下行声明了一个`makeMembersSingALyric`方法，该方法覆盖了在超类中包含的相同声明的方法。代码调用`soundGenerator.playMusicWithLyrics`方法，并将接收到的`lyrics`作为参数。然后，代码调用`super.makeMembersSingALyric`方法，并将接收到的`lyrics`作为参数，即在`Party<T>`超类中定义的`makeMembersSingALyric`方法：

```java
@Override
public void makeMembersSingALyric(String lyric) {
    soundGenerator.playMusicWithLyrics(lyric);
    super.makeMembersSingALyric(lyric);
}
```

以下 UML 图显示了我们将创建的接口和具体子类，包括所有字段和方法。

![声明一个与两个受限泛型类型一起工作的类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00091.jpeg)

# 使用两个泛型类型参数创建泛型类的实例

我们可以通过用符合`PartyWithHearable<T, U>`类声明中指定的约束或上界的任何类型名称替换`T`和`U`泛型类型参数来创建`PartyWithHearable<T, U>`类的实例。我们有三个具体类实现了`T`泛型类型参数所需的`Sociable`和`Comparable<Sociable>`接口：`SocialLion`、`SocialParrot`和`SocialSwan`。我们有两个实现了`U`泛型类型参数所需的`Hearable`接口的类：`Smartphone`和`AnimalMusicBand`。

我们可以使用`SocialLion`和`Smartphone`来创建`PartyWithHearable<SocialLion, Smartphone>`的实例，即社交狮和智能手机的聚会。然后，我们可以使用`SocialParrot`和`AnimalMusicBand`来创建`PartyWithHearable<SocialParrot, AnimalMusicBand>`的实例，即社交鹦鹉和动物音乐乐队的聚会。

以下行创建了一个名为`android`的`Smartphone`实例。然后，代码创建了一个名为`nalaParty`的`PartyWithHearable<SocialLion, Smartphone>`实例，并将`nala`和`android`作为参数传递。我们利用了类型推断，并使用了我们在上一章学到的菱形符号表示法，第十章, *泛型的代码重用最大化*。这样，我们创建了一个使用智能手机的社交狮聚会，其中`Nala`是聚会领袖，`Super Android Smartphone`是可听或音乐生成器。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
Smartphone android = new Smartphone("Super Android Smartphone");
PartyWithHearable<SocialLion, Smartphone> nalaParty = 
    new PartyWithHearable<>(nala, android);
```

`nalaParty`实例将只接受`SocialLion`实例，用于类定义中使用泛型类型参数`T`的所有参数。`nalaParty`实例将只接受`Smartphone`实例，用于类定义中使用泛型类型参数`U`的所有参数。以下行通过调用`addMember`方法将之前创建的三个`SocialLion`实例添加到聚会中。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
nalaParty.addMember(simba);
nalaParty.addMember(mufasa);
nalaParty.addMember(scar);
```

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![创建具有两个泛型类型参数的泛型类的实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00092.jpeg)

以下行调用`makeMembersDance`方法，使智能手机的播放列表邀请所有狮子跳舞并使它们跳舞。然后，代码调用`removeMember`方法来移除不是聚会领袖的成员，使用`declareNewPartyLeader`方法来声明一个新的领袖，最后调用`makeMembersSingALyric`方法来使智能手机的播放列表邀请所有狮子唱特定的歌词并使他们唱这个歌词。请记住，在调用`removeMember`和`declareNewPartyLeader`之前，我们在这些方法前加上`try`关键字，因为这些方法可能会抛出异常。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_01.java`文件中。

```java
nalaParty.makeMembersDance();
try {
    nalaParty.removeMember(mufasa);
} catch (CannotRemovePartyLeaderException e) {
    System.out.println(
        "We cannot remove the party leader.");
}
try {
    nalaParty.declareNewPartyLeader();
} catch (InsufficientMembersException e) {
    System.out.println(
        String.format("We just have %s member",
            e.getNumberOfMembers()));
}
nalaParty.makeMembersSingALyric("It's the eye of the tiger");
```

以下屏幕截图显示了在 JShell 中执行上述代码的结果：

![创建具有两个泛型类型参数的泛型类的实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00093.jpeg)

以下行显示了在 JShell 中运行前面代码片段后的输出。但是，我们必须考虑到新聚会领袖的伪随机选择，因此结果在每次执行时会有所不同：

```java
Nala welcomes Simba
Nala welcomes Mufasa
Nala welcomes Scar
Super Android Smartphone starts playing music.
cha-cha-cha untz untz untz
Nala dances alone *-* ^\/^ (-)
Simba dances alone *-* ^\/^ (-)
Mufasa dances alone *-* ^\/^ (-)
Scar dances alone *-* ^\/^ (-)
Mufasa says goodbye to Nala RoarRrooaarrRrrrrrrroooooaaarrrr
Nala says: Simba is our new party leader. *-* ^\/^ (-)
Simba dances with Nala *-* ^\/^ (-)
Super Android Smartphone starts playing music with lyrics.
untz untz untz It's the eye of the tiger untz untz
Nala sings It's the eye of the tiger Roar Rrooaarr Rrrrrrrroooooaaarrrr
Simba sings It's the eye of the tiger Roar Rrooaarr Rrrrrrrroooooaaarrrr
Scar sings It's the eye of the tiger Roar Rrooaarr Rrrrrrrroooooaaarrrr

```

以下行创建了一个名为`band`的`AnimalMusicBand`实例。然后，代码创建了一个名为`ramboParty`的`PartyWithHearable<SocialParrot, AnimalMusicBand>`实例，并将`rambo`和`band`作为参数传递。与之前的示例一样，我们利用了类型推断，并且使用了我们在上一章学习的菱形符号，第十章, *泛型的代码重用最大化*。这样，我们创建了一个由四只动物组成的音乐乐队的社交鹦鹉派对，其中`Rambo`是派对领袖，`Black Eyed Paws`是可听到的或音乐发生器。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_02.java`文件中。

```java
AnimalMusicBand band = new AnimalMusicBand(
    "Black Eyed Paws", 4);
PartyWithHearable<SocialParrot, AnimalMusicBand> ramboParty = 
    new PartyWithHearable<>(rambo, band);
```

`ramboParty`实例只接受`SocialParrot`实例作为类定义中使用泛型类型参数`T`的所有参数。`ramboParty`实例只接受`AnimalMusicBand`实例作为类定义中使用泛型类型参数`U`的所有参数。以下行通过调用`addMember`方法将之前创建的三个`SocialParrot`实例添加到派对中。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_02.java`文件中。

```java
ramboParty.addMember(rio);
ramboParty.addMember(woody);
ramboParty.addMember(thor);
```

以下截图显示了在 JShell 中执行上一个代码的结果。

![使用两个泛型类型参数创建泛型类的实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00094.jpeg)

以下行调用`makeMembersDance`方法，使动物音乐乐队邀请所有鹦鹉跳舞，告诉它们乐队中有四名成员并让它们跳舞。然后，代码调用`removeMember`方法来移除不是派对领袖的成员，使用`declareNewPartyLeader`方法来声明一个新的领袖，最后调用`makeMembersSingALyric`方法，使动物音乐乐队邀请所有鹦鹉唱特定的歌词并让它们唱这个歌词。请记住，在调用`removeMember`和`declareNewPartyLeader`之前我们加上了`try`关键字，因为这些方法可能会抛出异常。示例的代码文件包含在`java_9_oop_chapter_11_01`文件夹中的`example11_02.java`文件中。

```java
ramboParty.makeMembersDance();
try {
    ramboParty.removeMember(rio);
} catch (CannotRemovePartyLeaderException e) {
    System.out.println(
        "We cannot remove the party leader.");
}
try {
    ramboParty.declareNewPartyLeader();
} catch (InsufficientMembersException e) {
    System.out.println(
        String.format("We just have %s member",
            e.getNumberOfMembers()));
}
ramboParty.makeMembersSingALyric("Turn up the radio");
```

以下截图显示了在 JShell 中执行上一个代码的结果：

![使用两个泛型类型参数创建泛型类的实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00095.jpeg)

以下行显示了在 JShell 中运行前面的代码片段后的输出。但是，我们必须考虑到新派对领袖的伪随机选择，因此结果在每次执行时会有所不同：

```java
Rambo welcomes Rio
Rambo welcomes Woody
Rambo welcomes Thor
Our name is Black Eyed Paws. We are 4.
Meow Meow Woof Woof Meow Meow
Rambo dances alone /|\ -=- % % +=+
Rio dances alone /|\ -=- % % +=+
Woody dances alone /|\ -=- % % +=+
Thor dances alone /|\ -=- % % +=+
Rio says goodbye to Rambo YeahYeeaahYeeeaaaah
Rambo says: Thor is our new party leader. /|\ -=- % % +=+
Thor dances with Rambo /|\ -=- % % +=+
Black Eyed Paws asks you to sing together.
Meow Woof Turn up the radio Woof Meow
Rambo sings Turn up the radio Yeah Yeeaah Yeeeaaaah
Woody sings Turn up the radio Yeah Yeeaah Yeeeaaaah
Thor sings Turn up the radio Yeah Yeeaah Yeeeaaaah

```

# 测试你的知识

1.  `PartyWithHearable<T extends Sociable & Comparable<Sociable>, U extends Hearable>`这一行的意思是：

1.  泛型类型约束指定`T`必须实现`Sociable`或`Comparable<Sociable>`接口，`U`必须实现`Hearable`接口。

1.  该类是`Sociable`、`Comparable<Sociable>`和`Hearable`类的子类。

1.  泛型类型约束指定`T`必须实现`Sociable`和`Comparable<Sociable>`接口，`U`必须实现`Hearable`接口。

1.  以下哪一行等同于 Java 9 中的`PartyWithHearable<SocialLion, Smartphone>lionsParty = new PartyWithHearable<SocialLion, Smartphone>(nala, android);`：

1.  `PartyWithHearable<SocialLion, Smartphone> lionsParty = new PartyWithHearable<>(nala, android);`

1.  `PartyWithHearable<SocialLion, Smartphone> lionsParty = new PartyWithHearable(nala, android);`

1.  `let lionsParty = new PartyWithHearable(nala, android);`

1.  当我们在使用`extends`关键字的有界类型参数时：

1.  实现指定为上界的接口的任何类都可以用于类型参数。如果指定的名称是一个类的名称，则其子类不能用于类型参数。

1.  实现指定为上界的接口或指定为上界的类的任何子类都可以用于类型参数。

1.  指定为上界的类的任何子类都可以用于类型参数。如果指定的名称是一个接口的名称，则实现该接口的类不能用于类型参数。

1.  当 Java 中的类型参数具有约束时，它们也被称为：

1.  灵活的类型参数。

1.  无界类型参数。

1.  有界类型参数。

1.  以下哪个代码片段声明了一个类，其泛型类型约束指定`T`必须实现`Sociable`接口，`U`必须实现`Convertible`接口：

1.  `public class Game<T: where T is Sociable, U: where U is Convertible>`

1.  `public class Game<T extends Sociable> where U: Convertible`

1.  `public class Game<T extends Sociable, U extends Convertible>`

# 摘要

在本章中，您学习了通过编写能够与两个类型参数一起工作的代码来最大化代码重用。我们处理了涉及接口、泛型和具有约束的多个类型参数的更复杂的情况，也称为有界类型参数。

我们创建了一个新接口，然后声明了两个实现了这个新接口的类。然后，我们声明了一个使用了两个受限泛型类型参数的类。我们结合了类继承和接口，以最大化代码的可重用性。我们可以使类与许多不同类型一起工作，并且能够编写具有不同音乐生成器的派对的行为，然后可以重用这些行为来创建带有智能手机的狮子派对和带有动物乐队的鹦鹉派对。

Java 9 允许我们处理更复杂的情况，在这些情况下，我们可以为泛型类型参数指定更多的限制或边界。然而，大多数情况下，我们将处理本章和上一章中学到的示例所涵盖的情况。

现在您已经学会了参数多态性和泛型的高级用法，我们准备在 Java 9 中将面向对象编程和函数式编程相结合，这是我们将在下一章中讨论的主题。


# 第十二章：面向对象，函数式编程和 Lambda 表达式

在本章中，我们将讨论函数式编程以及 Java 9 如何实现许多函数式编程概念。我们将使用许多示例来演示如何将函数式编程与面向对象编程相结合。我们将：

+   将函数和方法视为一等公民

+   使用函数接口和 Lambda 表达式

+   创建数组过滤的函数版本

+   使用泛型和接口创建数据存储库

+   使用复杂条件过滤集合

+   使用 map 操作转换值

+   将 map 操作与 reduce 结合

+   使用 map 和 reduce 链式操作

+   使用不同的收集器

# 将函数和方法视为一等公民

自 Java 首次发布以来，Java 一直是一种面向对象的编程语言。从 Java 8 开始，Java 增加了对**函数式编程**范式的支持，并在 Java 9 中继续这样做。函数式编程偏爱不可变数据，因此，函数式编程避免状态更改。

### 注意

使用函数式编程风格编写的代码尽可能声明性，并且专注于它所做的事情，而不是它必须如何做。

在大多数支持函数式编程范式的编程语言中，函数是一等公民，也就是说，我们可以将函数用作其他函数或方法的参数。Java 8 引入了许多更改，以减少样板代码，并使方法成为 Java 中的一等公民变得容易，并且使得编写使用函数式编程方法的代码变得容易。我们可以通过一个简单的示例，例如过滤列表，轻松理解这个概念。但是，请注意，我们将首先编写具有方法作为一等公民的**命令式代码**，然后，我们将为此代码创建一个使用 Java 9 中的过滤操作的完整函数式方法的新版本。我们将创建许多版本的此示例，因为这将使我们能够了解在 Java 9 中如何实现函数式编程。

首先，我们将编写一些代码，考虑到我们仍然不知道 Java 9 中包含的将方法转换为一等公民的功能。然后，我们将在许多示例中使用这些功能。

以下行声明了`Testable`接口，该接口指定了一个接收`int`类型的`number`参数并返回`boolean`结果的方法要求。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
public interface Testable {
    boolean test(int number);
}
```

以下行声明了实现先前声明的`Testable`接口的`TestDivisibleBy5`具体类。该类使用包含返回`boolean`值的代码实现`test`方法，指示接收到的数字是否可以被`5`整除。如果数字和`5`之间的模运算结果等于`0`，则表示该数字可以被`5`整除。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
public class TestDivisibleBy5 implements Testable {
    @Override
    public boolean test(int number) {
        return ((number % 5) == 0);
    }
}
```

以下行声明了实现先前声明的`Testable`接口的`TestGreaterThan10`具体类。该类使用包含返回`boolean`值的代码实现`test`方法，指示接收到的数字是否大于`10`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
public class TestGreaterThan10 implements Testable {
    @Override
    public boolean test(int number) {
        return (number > 10);
    }
}
```

以下几行声明了`filterNumbersWithTestable`方法，该方法接收`numbers`参数中的`List<Integer>`和`tester`参数中的`Testable`实例。该方法使用外部的`for`循环，即命令式代码，为`numbers`中的每个`Integer`元素调用`tester.test`方法。如果`test`方法返回`true`，则代码将`Integer`元素添加到`filteredNumbersList<Integer>`中，具体来说，是一个`ArrayList<Integer>`。最后，该方法将`filteredNumbersList<Integer>`作为结果返回，其中包含满足测试条件的所有`Integer`对象。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
public List<Integer> filterNumbersWithTestable(final List<Integer> numbers,
    Testable tester) {
    List<Integer> filteredNumbers = new ArrayList<>();
    for (Integer number : numbers) {
        if (tester.test(number)) {
            filteredNumbers.add(number);
        }
    }
    return filteredNumbers; 
}
```

`filterNumbersWithTestable`方法使用两个`List<Integer>`对象，即两个`List`的`Integer`对象。我们讨论的是`Integer`而不是`int`原始类型。`Integer`是`int`原始类型的包装类。但是，我们在`Testable`接口中声明的`test`方法，然后在实现该接口的两个类中实现，接收的是`int`类型的参数，而不是`Integer`。

Java 会自动将原始值转换为相应包装类的对象。每当我们将对象作为参数传递给期望原始类型值的方法时，Java 编译器将该对象转换为相应的原始类型，这个操作称为**拆箱**。在下一行中，Java 编译器将`Integer`对象转换或拆箱为`int`类型的值。

```java
if (tester.test(number)) {
```

编译器将执行等效于调用`intValue()`方法的代码，该方法将`Integer`拆箱为`int`：

```java
if (tester.test(number.intValue())) {
```

我们不会编写`for`循环来填充`List`中的`Integer`对象。相反，我们将使用`IntStream`类，该类专门用于描述`int`原始类型的流。这些类定义在`java.util.stream`包中，因此，我们必须添加一个`import`语句才能在 JShell 中使用它。以下一行调用`IntStream.rangeClosed`方法，参数为`1`和`20`，以生成一个包含从`1`到`20`（包括）的`int`值的`IntStream`。链式调用`boxed`方法将生成的`IntStream`转换为`Stream<Integer>`，即从原始`int`值装箱成的`Integer`对象流。链式调用`collect`方法，参数为`Collectors.toList()`，将`Integer`对象流收集到`List<Integer>`中，具体来说，是一个`ArrayList<Integer>`。`Collectors`类也定义在`java.util.stream`包中。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
import java.util.stream.Collectors;
import java.util.stream.IntStream;

List<Integer> range1to20 = 
    IntStream.rangeClosed(1, 20).boxed().collect(Collectors.toList());
```

### 提示

装箱和拆箱会增加开销，并且会对性能和内存产生影响。在某些情况下，我们可能需要重写我们的代码，以避免不必要的装箱和拆箱，从而实现最佳性能。

非常重要的是要理解`collect`操作将开始处理管道以返回所需的结果，即从中间流生成的列表。在调用`collect`方法之前，中间操作不会被执行。以下屏幕截图显示了在 JShell 中执行前几行的结果。我们可以看到`range1to20`是一个包含从 1 到 20（包括）的`Integer`列表，装箱成`Integer`对象。

![理解函数和方法作为一等公民](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00096.jpeg)

以下行创建了一个名为`testDivisibleBy5`的`TestDivisibleBy5`类的实例。然后，代码使用`List<Integer> range1to20`作为`numbers`参数，使用名为`testDivisibleBy5`的`TestDivisibleBy5`实例作为`tester`参数调用了`filterNumbersWithTestable`方法。代码运行后，`List<Integer> divisibleBy5Numbers`将具有以下值：`[5, 10, 15, 20]`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
TestDivisibleBy5 testDivisibleBy5 = new TestDivisibleBy5();
List<Integer> divisibleBy5Numbers = 
filterNumbersWithTestable(range1to20, testDivisibleBy5);
System.out.println(divisibleBy5Numbers);
```

以下行创建了一个名为`testGreaterThan10`的`TestGreaterThan10`类的实例。然后，代码使用`range1to20`和`testGreaterThan10`作为参数调用了`filterNumbersWithTestable`方法。代码运行后，`List<Integer> greaterThan10Numbers`将具有以下值：`[11, 12, 13, 14, 15, 16, 17, 18, 19, 20]`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_01.java`文件中。

```java
TestGreaterThan10 testGreaterThan10 = new TestGreaterThan10();
List<Integer> greaterThan10Numbers = 
    filterNumbersWithTestable(range1to20, testGreaterThan10);
System.out.println(greaterThan10Numbers);
```

以下屏幕截图显示了在 JShell 中执行前面行的结果：

![理解函数和方法作为一等公民](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00097.jpeg)

# 使用函数接口和 Lambda 表达式

我们不得不声明一个接口和两个类，以使方法能够接收`Testable`的实例并执行每个类实现的`test`方法成为可能。幸运的是，Java 8 引入了**函数接口**，Java 9 使我们能够在代码需要函数接口时提供兼容的**Lambda 表达式**。简而言之，我们可以写更少的代码来实现相同的目标。

### 注意

函数接口是满足以下条件的接口：它具有单个抽象方法或单个方法要求。我们可以使用 Lambda 表达式、方法引用或构造函数引用创建函数接口的实例。我们将使用不同的示例来理解 Lambda 表达式、方法引用和构造函数引用，并看到它们的实际应用。

`IntPredicate`函数接口表示具有一个`int`类型参数并返回一个`boolean`结果的函数。布尔值函数称为谓词。该函数接口在`java.util.function`中定义，因此在使用之前我们必须包含一个`import`语句。

以下行声明了`filterNumbersWithPredicate`方法，该方法接收`List<Integer>`作为`numbers`参数，并接收`IntPredicate`实例作为`predicate`参数。该方法的代码与为`filterNumbersWithTestable`方法声明的代码相同，唯一的区别是，新方法接收的不是名为`tester`的`Testable`类型参数，而是名为`predicate`的`IntPredicate`类型参数。代码还调用了`test`方法，将从列表中检索的每个数字作为参数进行评估。`IntPredicate`函数接口定义了一个名为`test`的抽象方法，该方法接收一个`int`并返回一个`boolean`结果。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_02.java`文件中。

```java
import java.util.function.IntPredicate;

public List<Integer> filterNumbersWithPredicate(final List<Integer> numbers,
    IntPredicate predicate) {
    List<Integer> filteredNumbers = new ArrayList<>();
    for (Integer number : numbers) {
        if (predicate.test(number)) {
            filteredNumbers.add(number);
        }
    }
    return filteredNumbers; 
}
```

以下行声明了一个名为`divisibleBy5`的变量，类型为`IntPredicate`，并将一个 Lambda 表达式赋给它。具体来说，代码赋予了一个 Lambda 表达式，该表达式接收一个名为`n`的`int`参数，并返回一个`boolean`值，指示`n`和`5`之间的模运算（`%`）是否等于`0`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_02.java`文件中。

```java
IntPredicate divisibleBy5 = n -> n % 5 == 0;
```

Lambda 表达式由以下三个组件组成：

+   `n`：参数列表。在这种情况下，只有一个参数，因此不需要用括号括起参数列表。如果有多个参数，需要用括号括起列表。我们不必为参数指定类型。

+   `->`：箭头标记。

+   `n % 5 == 0`：主体。在这种情况下，主体是一个单一表达式，因此不需要用大括号(`{}`)括起来。此外，在表达式之前也不需要写`return`语句，因为它是一个单一表达式。

前面的代码等同于以下代码。前面的代码是最短版本，下一行是最长版本：

```java
IntPredicate divisibleBy5 = (n) ->{ return n % 5 == 0 };
```

想象一下，使用前面两个版本的任何一个代码，我们正在执行以下任务：

1.  创建一个实现`IntPredicate`接口的匿名类。

1.  在匿名类中声明一个接收`int`参数并返回`boolean`的测试方法，指定箭头标记(`->`)后的主体。

1.  创建一个匿名类的实例。

每当我们输入 lambda 表达式时，当需要`IntPredicate`时，所有这些事情都是在幕后发生的。当我们为其他函数接口使用 lambda 表达式时，类似的事情会发生，不同之处在于方法名称、参数和方法的返回类型可能会有所不同。

### 注意

Java 编译器从函数接口中推断出参数和返回类型的类型。事物保持强类型，如果我们在类型上犯了错误，编译器将生成适当的错误，代码将无法编译。

以下行调用`filterNumbersWithPredicate`方法，使用`List<Integer> range1to20`作为`numbers`参数，名为`divisibleBy5`的`IntPredicate`实例作为`predicate`参数。代码运行后，`List<Integer> divisibleBy5Numbers2`将具有以下值：`[5, 10, 15, 20]`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_02.java`文件中。

```java
List<Integer> divisibleBy5Numbers2 = 
    filterNumbersWithPredicate(range1to20, divisibleBy5);
System.out.println(divisibleBy5Numbers2);
```

以下行调用`filterNumbersWithPredicate`方法，使用`List<Integer> range1to20`作为`numbers`参数，使用 lambda 表达式作为`predicate`参数。lambda 表达式接收一个名为`n`的`int`参数，并返回一个`boolean`值，指示`n`是否大于`10`。代码运行后，`List<Integer> greaterThan10Numbers2`将具有以下值：`[11, 12, 13, 14, 15, 16, 17, 18, 19, 20]`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_02.java`文件中。

```java
List<Integer> greaterThan10Numbers2 = 
    filterNumbersWithPredicate(range1to20, n -> n > 10);
System.out.println(greaterThan10Numbers2);
```

以下截图显示了在 JShell 中执行前几行的结果。

![使用函数接口和 lambda 表达式](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00098.jpeg)

`Function<T, R>`函数接口表示一个函数，其中`T`是函数的输入类型，`R`是函数的结果类型。我们不能为`T`指定原始类型，比如`int`，因为它不是一个类，但我们可以使用装箱类型，即`Integer`。我们不能为`R`使用`boolean`，但我们可以使用装箱类型，即`Boolean`。如果我们想要与`IntPredicate`函数接口类似的行为，我们可以使用`Function<Integer, Boolean>`，即一个具有`Integer`类型的参数的函数，返回一个`Boolean`结果。这个函数接口在`java.util.function`中定义，因此在使用之前，我们必须包含一个`import`语句。

以下行声明了`filterNumbersWithFunction`方法，该方法接收`numbers`参数中的`List<Integer>`和`predicate`参数中的`Function<Integer, Boolean>`实例。该方法的代码与`filterNumbersWithCondition`方法声明的代码相同，不同之处在于新方法接收了`Function<Integer, Boolean>`类型的参数`function`，而不是接收了名为`predicate`的`IntPredicate`类型的参数。代码调用`apply`方法，并将从列表中检索到的每个数字作为参数进行评估，而不是调用`test`方法。

`Function<T, R>`功能接口定义了一个名为 apply 的抽象方法，该方法接收一个`T`并返回类型为`R`的结果。在这种情况下，apply 方法接收一个`Integer`并返回一个`Boolean`，Java 编译器将自动拆箱为`boolean`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_03.java`文件中。

```java
import java.util.function.Function;

public List<Integer> filterNumbersWithFunction(final List<Integer> numbers,
 Function<Integer, Boolean> function) {
    List<Integer> filteredNumbers = new ArrayList<>();
    for (Integer number : numbers) {
 if (function.apply(number)) {
            filteredNumbers.add(number);
        }
    }
    return filteredNumbers; 
}
```

以下行调用了`filterNumbersWithFunction`方法，将`List<Integer> range1to20`作为`numbers`参数，并将 lambda 表达式作为`function`参数。lambda 表达式接收一个名为`n`的`Integer`参数，并返回一个`Boolean`值，指示`n`和`3`之间的模运算结果是否等于`0`。Java 会自动将表达式生成的`boolean`值装箱为`Boolean`对象。代码运行后，`List<Integer> divisibleBy3Numbers`将具有以下值：`[3, 6, 9, 12, 15, 18]`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_03.java`文件中。

```java
List<Integer> divisibleBy3Numbers = 
    filterNumbersWithFunction(range1to20, n -> n % 3 == 0);
```

Java 将运行等效于以下行的代码。`intValue()`函数为`n`中接收的`Integer`实例返回一个`int`值，lambda 表达式返回表达式评估生成的`boolean`值的新`Boolean`实例。但是，请记住，装箱和拆箱是在幕后发生的。

```java
List<Integer> divisibleBy3Numbers = 
    filterNumbersWithFunction(range1to20, n -> new Boolean(n.intValue() % 3 == 0));
```

在`java.util.function`中定义了 40 多个功能接口。我们只使用了其中两个能够处理相同 lambda 表达式的接口。我们可以专门撰写一本书来详细分析所有功能接口。我们将继续专注于将面向对象与函数式编程相结合。然而，非常重要的是要知道，在声明自定义功能接口之前，我们必须检查`java.util.function`中定义的所有功能接口。

# 创建数组过滤的功能性版本

先前声明的`filterNumbersWithFunction`方法代表了使用外部`for`循环进行数组过滤的命令式版本。我们可以使用`Stream<T>`对象的`filter`方法，在这种情况下是`Stream<Integer>`对象，并以函数式方法实现相同的目标。

接下来的几行使用了一种功能性方法来生成一个`List<Integer>`，其中包含在`List<Integer> range1to20`中的能被`3`整除的数字。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_04.java`文件中。

```java
List<Integer> divisibleBy3Numbers2 = range1to20.stream().filter(n -> n % 3 == 0).collect(Collectors.toList());
```

如果我们希望先前的代码在 JShell 中运行，我们必须将所有代码输入到单行中，这对于 Java 编译器成功编译代码并不是必需的。这是 JShell、流和 lambda 表达式的一个特定问题。这使得代码有点难以理解。因此，接下来的几行展示了另一个使用多行的代码版本，这在 JShell 中不起作用，但会使代码更容易理解。只需注意，在下面的示例中，您必须将代码输入到单行中。代码文件使用单行。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_04.java`文件中。

```java
range1to20.stream()
.filter(n -> n % 3 == 0)
.collect(Collectors.toList());
```

### 提示

`stream`方法从`List<Integer>`生成一个`Stream<Integer>`。**流**是特定类型的元素序列，允许我们执行顺序或并行执行的计算或聚合操作。实际上，我们可以链接许多流操作并组成流管道。这些计算具有延迟执行，也就是说，直到有终端操作（例如请求将最终数据收集到特定类型的`List`中）之前，它们不会被计算。

`filter`方法接收一个`Predicate<Integer>`作为参数，并将其应用于`Stream<Integer>`。`filter`方法返回输入流的元素流，这些元素与指定的谓词匹配。该方法返回一个流，其中包含所有`Predicate<Integer>`评估为`true`的元素。我们将先前解释的 lambda 表达式作为`filter`方法的参数传递。

`collect`方法接收`filter`方法返回的`Stream<Integer>`。我们将`Collectors.toList()`作为`collect`方法的参数传递，以对`Stream<Integer>`的元素执行可变归约操作，并生成`List<Integer>`，即可变结果容器。代码运行后，`List<Integer> divisibleBy3Numbers2`将具有以下值：`[3, 6, 9, 12, 15, 18]`。

现在，我们希望采用功能方法来打印结果`List<Integer>`中的每个数字。`List<T>`实现了`Iterable<T>`接口，允许我们调用`forEach`方法对`Iterable`的每个元素执行指定为参数的操作，直到所有元素都被处理或操作引发异常。`forEach`方法的操作参数必须是`Consumer<T>`，因此在我们的情况下，它必须是`Consumer<Integer>`，因为我们将为结果`List<Integer>`调用`forEach`方法。

`Consumer<T>`是一个函数接口，表示访问类型为`T`的单个输入参数并返回无结果（`void`）的操作。`Consumer<T>`函数接口定义了一个名为`accept`的抽象方法，该方法接收类型为`T`的参数并返回无结果。以下行将 lambda 表达式作为`forEach`方法的参数传递。lambda 表达式生成一个`Consumer<Integer>`，打印接收到的`n`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_04.java`文件中。

```java
divisibleBy3Numbers2.forEach(n -> System.out.println(n));
```

由于上一行的结果，我们将在 JShell 中看到以下数字的打印：

```java
3
6
9
12
15
18

```

生成`Consumer<Integer>`的 lambda 表达式调用`System.out.println`方法，并将`Integer`作为参数。我们可以使用方法引用来调用现有方法，而不是使用 lambda 表达式。在这种情况下，我们可以用`System.out::println`替换先前显示的 lambda 表达式，即调用`System.out`的`println`方法的方法引用。每当我们使用方法引用时，Java 运行时都会推断方法类型参数；在这种情况下，方法类型参数是单个`Integer`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_04.java`文件中。

```java
divisibleBy3Numbers2.forEach(System.out::println);
```

该代码将产生与先前对 lambda 表达式调用`forEach`相同的结果。以下屏幕截图显示了在 JShell 中执行先前行的结果：

![创建数组过滤的功能版本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00099.jpeg)

我们可以捕获在 lambda 表达式中未定义的变量。当 lambda 从外部世界捕获变量时，我们也可以称之为闭包。例如，以下行声明了一个名为`byNumber`的`int`变量，并将`4`赋给该变量。然后，下一行使用流、过滤器和收集的新版本来生成一个`List<Integer>`，其中包含能被`byNumber`变量指定的数字整除的数字。lambda 表达式包括`byNumber`，Java 在幕后从外部世界捕获了这个变量。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_04.java`文件中。

```java
int byNumber = 4;
List<Integer> divisibleBy4Numbers =
    range1to20.stream().filter(
        n -> n % byNumber == 0).collect(
        Collectors.toList());
divisibleBy4Numbers.forEach(System.out::println);
```

由于前一行的结果，我们将在 JShell 中看到以下数字的打印：

```java
4
8
12
16
20

```

如果我们使用一个与函数式接口不匹配的 lambda 表达式，代码将无法编译，Java 编译器将生成适当的错误。例如，以下行尝试将返回`int`而不是`Boolean`或`boolean`的 lambda 表达式分配给`IntPredicate`变量。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_05.java`文件中。

```java
// The following code will generate an error
IntPredicate errorPredicate = n -> 8;
```

JShell 将显示以下错误，向我们指出`int`无法转换为`boolean`：

```java
|  Error:
|  incompatible types: bad return type in lambda expression
|      int cannot be converted to boolean
|  IntPredicate errorPredicate = n -> 8;
|                                     ^

```

# 使用泛型和接口创建数据仓库

现在我们想要创建一个仓库，为我们提供实体，以便我们可以应用 Java 9 中包含的函数式编程特性来检索和处理这些实体的数据。首先，我们将创建一个`Identifiable`接口，该接口定义了可识别实体的要求。我们希望实现此接口的任何类都提供一个`getId`方法，该方法返回一个`int`，其值为实体的唯一标识符。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
public interface Identifiable {
    int getId();
}
```

接下来的行创建了一个`Repository<E>`通用接口，该接口指定`E`必须实现最近创建的`Identifiable`接口的通用类型约束。该类声明了一个`getAll`方法，该方法返回一个`List<E>`。实现该接口的每个类都必须为此方法提供自己的实现。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
public interface Repository<E extends Identifiable> {
    List<E> getAll();
}
```

接下来的行创建了`Entity`抽象类，它是所有实体的基类。该类实现了`Identifiable`接口，并定义了一个`int`类型的不可变`id`受保护字段。构造函数接收`id`不可变字段的期望值，并使用接收到的值初始化字段。抽象类实现了`getId`方法，该方法返回`id`不可变字段的值。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
public abstract class Entity implements Identifiable {
    protected final int id;

    public Entity(int id) {
        this.id = id;
    }

    @Override
    public final int getId() {
        return id;
    }
}
```

接下来的行创建了`MobileGame`类，具体来说，是先前创建的`Entity`抽象类的子类。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
public class MobileGame extends Entity {
    protected final String separator = "; ";
    public final String name;
    public int highestScore;
    public int lowestScore;
    public int playersCount;

    public MobileGame(int id, 
        String name, 
        int highestScore, 
        int lowestScore, 
        int playersCount) {
        super(id);
        this.name = name;
        this.highestScore = highestScore;
        this.lowestScore = lowestScore;
        this.playersCount = playersCount;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Id: ");
        sb.append(getId());
        sb.append(separator);
        sb.append("Name: ");
        sb.append(name);
        sb.append(separator);
        sb.append("Highest score: ");
        sb.append(highestScore);
        sb.append(separator);
        sb.append("Lowest score: ");
        sb.append(lowestScore);
        sb.append(separator);
        sb.append("Players count: ");
        sb.append(playersCount);

        return sb.toString();
    }
}
```

该类声明了许多公共字段，它们的值在构造函数中初始化：`name`，`highestScore`，`lowestScore`和`playersCount`。该字段是不可变的，但其他三个是可变的。我们不使用 getter 或 setter 来保持事情更简单。但是，重要的是要考虑到，一些允许我们使用实体的框架要求我们对所有字段使用 getter，并且在字段不是只读时使用 setter。

此外，该类重写了从`java.lang.Object`类继承的`toString`方法，必须为实体返回一个`String`表示。此方法中声明的代码使用`java.lang.StringBuilder`类的一个实例（`sb`）以一种高效的方式附加许多字符串，最后返回调用`sb.toString`方法的结果以返回生成的`String`。此方法使用受保护的分隔符不可变字符串，该字符串确定我们在字段之间使用的分隔符。每当我们使用`MobileGame`的实例调用`System.out.println`时，`println`方法将调用重写的`toString`方法来打印该实例的`String`表示。

### 提示

我们也可以使用`String`连接（`+`）或`String.format`来编写`toString`方法的代码，因为我们将只使用`MobileGame`类的 15 个实例。然而，当我们必须连接许多字符串以生成结果并且希望确保在执行代码时具有最佳性能时，最好使用`StringBuilder`。在我们的简单示例中，任何实现都不会有任何性能问题。

以下行创建了实现`Repository<MobileGame>`接口的`MemoryMobileGameRepository`具体类。请注意，我们不说`Repository<E>`，而是指出`Repository<MobileGame>`，因为我们已经知道我们将在我们的类中实现的`E`类型参数的值。我们不是创建一个`MemoryMobileGameRepository<E extends Identifiable>`。相反，我们正在创建一个非泛型的具体类，该类实现了一个泛型接口并将参数类型`E`的值设置为`MobileGame`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
import java.util.stream.Collectors;

public class MemoryMobileGameRepository implements Repository<MobileGame> {
    @Override
    public List<MobileGame> getAll() {
        List<MobileGame> mobileGames = new ArrayList<>();
        mobileGames.add(
            new MobileGame(1, "Uncharted 4000", 5000, 10, 3800));
        mobileGames.add(
            new MobileGame(2, "Supergirl 2017", 8500, 5, 75000));
        mobileGames.add(
            new MobileGame(3, "Super Luigi Run", 32000, 300, 90000));
        mobileGames.add(
            new MobileGame(4, "Mario vs Kong III", 152000, 1500, 750000));
        mobileGames.add(
            new MobileGame(5, "Minecraft Reloaded", 6708960, 8000, 3500000));
        mobileGames.add(
            new MobileGame(6, "Pikachu vs Beedrill: The revenge", 780000, 400, 1000000));
        mobileGames.add(
            new MobileGame(7, "Jerry vs Tom vs Spike", 78000, 670, 20000));
        mobileGames.add(
            new MobileGame(8, "NBA 2017", 1500607, 20, 7000005));
        mobileGames.add(
            new MobileGame(9, "NFL 2017", 3205978, 0, 4600700));
        mobileGames.add(
            new MobileGame(10, "Nascar Remix", 785000, 0, 2600000));
        mobileGames.add(
            new MobileGame(11, "Little BIG Universe", 95000, 3, 546000));
        mobileGames.add(
            new MobileGame(12, "Plants vs Zombies Garden Warfare 3", 879059, 0, 789000));
        mobileGames.add(
            new MobileGame(13, "Final Fantasy XVII", 852325, 0, 375029));
        mobileGames.add(
            new MobileGame(14, "Watch Dogs 3", 27000, 2, 78004));
        mobileGames.add(
            new MobileGame(15, "Remember Me", 672345, 5, 252003));

        return mobileGames;
    }
}
```

该类实现了`Repository<E>`接口所需的`getAll`方法。在这种情况下，该方法返回一个`MobileGame`的`List`（`List<MobileGame>`），具体来说是一个`ArrayList<MobileGame>`。该方法创建了 15 个`MobileGame`实例，并将它们附加到一个`MobileGame`的`ArrayList`，该方法作为结果返回。

以下行创建了`MemoryMobileGameRepository`类的一个实例，并为`getAll`方法返回的`List<MobileGame>`调用`forEach`方法。`forEach`方法在列表中的每个元素上调用一个体，就像在`for`循环中一样。作为`forEach`方法参数指定的闭包调用`System.out.println`方法，并将`MobileGame`实例作为参数。这样，Java 使用`MobileGame`类中重写的`toString`方法为每个`MobileGame`实例生成一个`String`表示。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_06.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
repository.getAll().forEach(mobileGame -> System.out.println(mobileGame));
```

以下行显示在执行打印每个`MobileGame`实例的`toString()`方法返回的`String`后生成的输出：

```java
Id: 1; Name: Uncharted 4000; Highest score: 5000; Lowest score: 10; Players count: 3800
Id: 2; Name: Supergirl 2017; Highest score: 8500; Lowest score: 5; Players count: 75000
Id: 3; Name: Super Luigi Run; Highest score: 32000; Lowest score: 300; Players count: 90000
Id: 4; Name: Mario vs Kong III; Highest score: 152000; Lowest score: 1500; Players count: 750000
Id: 5; Name: Minecraft Reloaded; Highest score: 6708960; Lowest score: 8000; Players count: 3500000
Id: 6; Name: Pikachu vs Beedrill: The revenge; Highest score: 780000; Lowest score: 400; Players count: 1000000
Id: 7; Name: Jerry vs Tom vs Spike; Highest score: 78000; Lowest score: 670; Players count: 20000
Id: 8; Name: NBA 2017; Highest score: 1500607; Lowest score: 20; Players count: 7000005
Id: 9; Name: NFL 2017; Highest score: 3205978; Lowest score: 0; Players count: 4600700
Id: 10; Name: Nascar Remix; Highest score: 785000; Lowest score: 0; Players count: 2600000
Id: 11; Name: Little BIG Universe; Highest score: 95000; Lowest score: 3; Players count: 546000
Id: 12; Name: Plants vs Zombies Garden Warfare 3; Highest score: 879059; Lowest score: 0; Players count: 789000
Id: 13; Name: Final Fantasy XVII; Highest score: 852325; Lowest score: 0; Players count: 375029
Id: 14; Name: Watch Dogs 3; Highest score: 27000; Lowest score: 2; Players count: 78004
Id: 15; Name: Remember Me; Highest score: 672345; Lowest score: 5; Players count: 252003

```

```java
 the same result. The code file for the sample is included in the java_9_oop_chapter_12_01 folder, in the example12_06.java file.
```

```java
repository.getAll().forEach(System.out::println);
```

# 使用复杂条件过滤集合

我们可以使用我们的新存储库来限制从复杂数据中检索的结果。我们可以将对`getAll`方法的调用与流、过滤器和收集结合起来，以生成一个`Stream<MobileGame>`，应用一个带有 lambda 表达式作为参数的过滤器，并调用`collect`方法，并将`Collectors.toList()`作为参数，从过滤后的`Stream<MobileGame>`生成一个过滤后的`List<MobileGame>`。`filter`方法接收一个`Predicate<MobileGame>`作为参数，我们使用 lambda 表达式生成该谓词，并将该过滤器应用于`Stream<MobileGame>`。`filter`方法返回输入流的元素流，这些元素流与指定的谓词匹配。该方法返回一个流，其中所有元素的`Predicate<MobileGame>`评估为`true`。

### 注意

接下来的行显示了使用多行的代码片段，这在 JShell 中无法工作，但将使代码更易于阅读和理解。如果我们希望代码在 JShell 中运行，我们必须将所有代码输入到一行中，这对于 Java 编译器成功编译代码并不是必需的。这是 JShell、流和 lambda 表达式的一个特定问题。代码文件使用单行以与 JShell 兼容。

以下行声明了`MemoryMobileGameRepository`类的新`getWithLowestScoreGreaterThan`方法。请注意，为了避免重复，我们没有包含新类的所有代码。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_07.java`文件中。

```java
public List<MobileGame> getWithLowestScoreGreaterThan(int minimumLowestScore) {
    return getAll().stream()
        .filter(game -> game.lowestScore > minimumLowestScore)
        .collect(Collectors.toList());
}
```

以下行使用名为`repository`的`MemoryMobileGameRepository`实例调用先前添加的方法，然后链式调用`forEach`以打印所有`lowestScore`值大于`1000`的游戏：

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
repository.getWithLowestScoreGreaterThan(1000).forEach(System.out::println);
```

以下行显示了执行前面代码后生成的输出：

```java
Id: 4; Name: Mario vs Kong III; Highest score: 152000; Lowest score: 1500; Players count: 750000
Id: 5; Name: Minecraft Reloaded; Highest score: 6708960; Lowest score: 8000; Players count: 3500000

```

```java
java_9_oop_chapter_12_01 folder, in the example12_07.java file.
```

```java
public List<MobileGame> getWithLowestScoreGreaterThanV2(int minimumLowestScore) {
return getAll().stream()
 .filter((MobileGame game) -> game.lowestScore > minimumLowestScore) 
    .collect(Collectors.toList());
}
```

以下行声明了`MemoryMobileGameRepository`类的新`getStartingWith`方法。作为`filter`方法参数传递的 lambda 表达式返回调用游戏名称的`startsWith`方法的结果，该方法使用作为参数接收的前缀。在这种情况下，lambda 表达式是一个闭包，它捕获了`prefix`参数，并在 lambda 表达式体内使用它。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_08.java`文件中。

```java
public List<MobileGame> getStartingWith(String prefix) {
    return getAll().stream()
        .filter(game -> game.name.startsWith(prefix))
        .collect(Collectors.toList());
}
```

以下行使用名为`repository`的`MemoryMobileGameRepository`实例调用先前添加的方法，然后链式调用`forEach`以打印所有以`"Su"`开头的游戏的名称。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
repository.getStartingWith("Su").forEach(System.out::println);
```

以下行显示了执行前面代码后生成的输出：

```java
Id: 2; Name: Supergirl 2017; Highest score: 8500; Lowest score: 5; Players count: 75000
Id: 3; Name: Super Luigi Run; Highest score: 32000; Lowest score: 300; Players count: 90000

```

以下行声明了`MemoryMobileGameRepository`类的新`getByPlayersCountAndHighestScore`方法。该方法返回一个`Optional<MobileGame>`，即一个可能包含`MobileGame`实例的容器对象，也可能为空。如果有值，`isPresent`方法将返回`true`，我们将能够通过调用`get`方法检索`MobileGame`实例。在这种情况下，代码调用了`findFirst`方法链接到`filter`方法的调用。`findFirst`方法返回一个`Optional<T>`，在这种情况下，是由`filter`方法生成的`Stream<MobileGame>`中的第一个元素的`Optional<MobileGame>`。请注意，我们在任何时候都没有对结果进行排序。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_09.java`文件中。

```java
public Optional<MobileGame> getByPlayersCountAndHighestScore(
    int playersCount, 
    int highestScore) {
    return getAll().stream()
        .filter(game -> (game.playersCount == playersCount) && (game.highestScore == highestScore))
        .findFirst();
}
```

以下行使用名为`repository`的`MemoryMobileGameRepository`实例调用先前添加的方法。在每次调用`getByPlayersCountAndHighestScore`方法后，代码调用`isPresent`方法来确定`Optional<MobileGame>`是否有实例。如果方法返回`true`，代码将调用`get`方法从`Optional<MobileGame>`中检索`MobileGame`实例。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_09.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
Optional<MobileGame> optionalMobileGame1 = 
    repository.getByPlayersCountAndHighestScore(750000, 152000);
if (optionalMobileGame1.isPresent()) {
    MobileGame mobileGame1 = optionalMobileGame1.get();
    System.out.println(mobileGame1);
} else {
    System.out.println("No mobile game matches the specified criteria.");
}
Optional<MobileGame> optionalMobileGame2 = 
    repository.getByPlayersCountAndHighestScore(670000, 829340);
if (optionalMobileGame2.isPresent()) {
    MobileGame mobileGame2 = optionalMobileGame2.get();
    System.out.println(mobileGame2);
} else {
    System.out.println("No mobile game matches the specified criteria.");
}
```

以下行显示了执行前面代码后生成的输出。在第一次调用中，有一个符合搜索条件的移动游戏。在第二次调用中，没有符合搜索条件的`MobileGame`实例：

```java
Id: 4; Name: Mario vs Kong III; Highest score: 152000; Lowest score: 1500; Players count: 750000
No mobile game matches the specified criteria.

```

以下屏幕截图显示了在 JShell 中执行前面行的结果：

![使用复杂条件过滤集合](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00100.jpeg)

# 使用 map 操作来转换值

以下行为我们先前编写的`MemoryMobileGameRepository`类声明了一个新的`getGameNamesTransformedToUpperCase`方法。新方法执行了最简单的 map 操作之一。对`map`方法的调用将`Stream<MobileGame>`转换为`Stream<String>`。作为`map`方法参数传递的 lambda 表达式生成了一个`Function<MobileGame, String>`，即它接收一个`MobileGame`参数并返回一个`String`。对`collect`方法的调用从`map`方法返回的`Stream<String>`生成了一个`List<String>`。

示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_10.java`文件中。

```java
public List<String> getGameNamesTransformedToUpperCase() {
    return getAll().stream()
        .map(game -> game.name.toUpperCase())
        .collect(Collectors.toList());
}
```

`getGameNamesTransformedToUpperCase`方法返回一个`List<String>`。`map`方法将`Stream<MobileGame>`中的每个`MobileGame`实例转换为一个带有`name`字段转换为大写的`String`。这样，`map`方法将`Stream<MobileGame>`转换为`List<String>`。

以下行使用名为`repository`的`MemoryMobileGameRepository`实例调用先前添加的方法，并生成一个转换为大写字符串的游戏名称列表。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_10.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
repository.getGameNamesTransformedToUpperCase().forEach(System.out::println);
```

以下行显示执行先前代码后生成的输出：

```java
UNCHARTED 4000
SUPERGIRL 2017
SUPER LUIGI RUN
MARIO VS KONG III
MINECRAFT RELOADED
PIKACHU VS BEEDRILL: THE REVENGE
JERRY VS TOM VS SPIKE
NBA 2017
NFL 2017
NASCAR REMIX
LITTLE BIG UNIVERSE
PLANTS VS ZOMBIES GARDEN WARFARE 3
FINAL FANTASY XVII
WATCH DOGS 3
REMEMBER ME

```

以下代码创建了一个新的`NamesForMobileGame`类，其中包含两个构造函数。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_11.java`文件中。

```java
public class NamesForMobileGame {
    public final String upperCaseName;
    public final String lowerCaseName;

    public NamesForMobileGame(String name) {
        this.upperCaseName = name.toUpperCase();
        this.lowerCaseName = name.toLowerCase();
    }

    public NamesForMobileGame(MobileGame game) {
        this(game.name);
    }
}
```

`NamesForMobileGame`类声明了两个`String`类型的不可变字段：`upperCaseName`和`lowerCaseName`。其中一个构造函数接收一个`nameString`，并将其转换为大写保存在`upperCaseName`字段中，并将其转换为小写保存在`lowerCaseName`字段中。另一个构造函数接收一个`MobileGame`实例，并使用接收到的`MobileGame`实例的`name`字段作为参数调用先前解释的构造函数。

以下代码为我们先前编写的`MemoryMobileGameRepository`类添加了一个新的`getNamesForMobileGames`方法。新方法执行了一个 map 操作。对`map`方法的调用将`Stream<MobileGame>`转换为`Stream<NamesForMobileGame>`。作为`map`方法参数传递的 lambda 表达式生成了一个`Function<MobileGame, NamesForMobileGame>`，即它接收一个`MobileGame`参数，并通过调用接收一个`name`作为参数的构造函数返回一个`NamesForMobileGame`实例。对`collect`方法的调用从`map`方法返回的`Stream<NamesForMobileGame>`生成了一个`List<NamesForMobileGame>`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_11.java`文件中。

```java
public List<NamesForMobileGame> getNamesForMobileGames() {
    return getAll().stream()
        .map(game -> new NamesForMobileGame(game.name))
        .collect(Collectors.toList());
}
```

以下行使用名为`repository`的`MemoryMobileGameRepository`实例调用先前添加的方法。作为`forEach`方法参数传递的 lambda 表达式声明了一个用大括号括起来的主体，因为它需要多行。此主体使用`java.lang.StringBuilder`类的一个实例(`sb`)来附加许多带有大写名称、分隔符和小写名称的字符串。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_11.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository()
repository.getNamesForMobileGames().forEach(names -> {
    StringBuilder sb = new StringBuilder();
    sb.append(names.upperCaseName);
    sb.append(" - ");
    sb.append(names.lowerCaseName);
    System.out.println(sb.toString());
});
```

以下行显示执行先前代码后生成的输出：

```java
UNCHARTED 4000 - uncharted 4000
SUPERGIRL 2017 - supergirl 2017
SUPER LUIGI RUN - super luigi run
MARIO VS KONG III - mario vs kong iii
MINECRAFT RELOADED - minecraft reloaded
PIKACHU VS BEEDRILL: THE REVENGE - pikachu vs beedrill: the revenge
JERRY VS TOM VS SPIKE - jerry vs tom vs spike
NBA 2017 - nba 2017
NFL 2017 - nfl 2017
NASCAR REMIX - nascar remix
LITTLE BIG UNIVERSE - little big universe
PLANTS VS ZOMBIES GARDEN WARFARE 3 - plants vs zombies garden warfare 3
FINAL FANTASY XVII - final fantasy xvii
WATCH DOGS 3 - watch dogs 3
REMEMBER ME - remember me

```

下一行代码显示了`getNamesForMobileGames`方法的另一个版本，名为`getNamesForMobileGamesV2`，它是等效的并产生相同的结果。在这种情况下，我们用构造函数引用方法替换了生成`Function<MobileGame, NamesForMobileGame>`的 lambda 表达式：`NamesForMobileGame::new`。构造函数引用方法是指定类名后跟`::new`，将使用接收`MobileGame`实例作为参数的构造函数创建`NamesForMobileGame`的新实例。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，`example12_12.java`文件中。

```java
public List<NamesForMobileGame> getNamesForMobileGamesV2() {
    return getAll().stream()
        .map(NamesForMobileGame::new)
        .collect(Collectors.toList());
}
```

以下代码使用方法的新版本，并产生了第一个版本显示的相同结果。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，`example12_12.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository();
repository.getNamesForMobileGamesV2().forEach(names -> {
    StringBuilder sb = new StringBuilder();
    sb.append(names.upperCaseName);
    sb.append(" - ");
    sb.append(names.lowerCaseName);
    System.out.println(sb.toString());
});
```

# 结合地图操作和减少

以下行显示了一个`for`循环的命令式代码版本，用于计算移动游戏的所有`lowestScore`值的总和。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，`example12_13.java`文件中。

```java
int lowestScoreSum = 0;
for (MobileGame mobileGame : repository.getAll()) {
    lowestScoreSum += mobileGame.lowestScore;
}
System.out.println(lowestScoreSum);
```

代码非常容易理解。`lowestScoreSum`变量的初始值为`0`，`for`循环的每次迭代从`repository.getAll()`方法返回的`List<MobileGame>`中检索一个`MobileGame`实例，并增加`lowestScoreSum`变量的值与`mobileGame.lowestScore`字段的值。

我们可以将地图和减少操作结合起来，以创建先前命令式代码的功能版本，以计算移动游戏的所有`lowestScore`值的总和。下一行将`map`的调用链接到`reduce`的调用，以实现这个目标。看一下以下代码。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，`example12_14.java`文件中。

```java
int lowestScoreMapReduceSum = repository.getAll().stream().map(game -> game.lowestScore).reduce(0, (sum, lowestScore) -> sum + lowestScore);
System.out.println(lowestScoreMapReduceSum);
```

首先，代码使用调用`map`将`Stream<MobileGame>`转换为`Stream<Integer>`，其中`lowestScore`存储属性中的值被装箱为`Integer`对象。然后，代码调用`reduce`方法，该方法接收两个参数：累积值的初始值`0`和一个组合闭包，该闭包将重复调用累积值。该方法返回对组合闭包的重复调用的结果。

`reduce`方法的第二个参数中指定的闭包接收`sum`和`lowestScore`，并返回这两个值的总和。因此，闭包返回到目前为止累积的总和加上处理的`lowestScore`值。我们可以添加一个`System.out.println`语句，以显示`reduce`方法的第二个参数中指定的闭包中的`sum`和`lowestScore`的值。以下行显示了先前代码的新版本，其中添加了包含`System.out.println`语句的行，这将允许我们深入了解`reduce`操作的工作原理。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，`example12_15.java`文件中。

```java
int lowestScoreMapReduceSum2 = 
    repository.getAll().stream()
    .map(game -> game.lowestScore)
    .reduce(0, (sum, lowestScore) -> {
        StringBuilder sb = new StringBuilder();
        sb.append("sum value: ");
        sb.append(sum);
        sb.append(";lowestScore value: ");
        sb.append(lowestScore);
        System.out.println(sb.toString());

        return sum + lowestScore;
    });
System.out.println(lowestScoreMapReduceSum2);
```

以下行显示了先前行的结果，我们可以看到`sum`参数的值从`reduce`方法的第一个参数中指定的初始值（`0`）开始，并累积到目前为止的总和。最后，`lowestScoreSum2`变量保存了所有`lowestScore`值的总和。我们可以看到`sum`和`lowestScore`的最后一个值分别为`10910`和`5`。对于减少操作执行的最后一段代码计算`10910`加`5`并返回`10915`，这是保存在`lowestScoreSum2`变量中的结果。

```java
sum value: 0; lowestScore value: 10
sum value: 10; lowestScore value: 5
sum value: 15; lowestScore value: 300
sum value: 315; lowestScore value: 1500
sum value: 1815; lowestScore value: 8000
sum value: 9815; lowestScore value: 400
sum value: 10215; lowestScore value: 670
sum value: 10885; lowestScore value: 20
sum value: 10905; lowestScore value: 0
sum value: 10905; lowestScore value: 0
sum value: 10905; lowestScore value: 3
sum value: 10908; lowestScore value: 0
sum value: 10908; lowestScore value: 0
sum value: 10908; lowestScore value: 2
sum value: 10910; lowestScore value: 5
lowestScoreMapReduceSum2 ==> 10915
10915

```

在前面的例子中，我们结合使用 map 和 reduce 来执行求和。我们可以利用 Java 9 提供的简化代码来实现相同的目标。在下面的代码中，我们利用`mapToInt`生成一个`IntStream`；sum 使用`int`值工作，不需要将`Integer`转换为`int`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，名为`example12_16.java`。

```java
int lowestScoreMapReduceSum3 =
    repository.getAll().stream()
    .mapToInt(game -> game.lowestScore).sum();
System.out.println(lowestScoreMapReduceSum3);
```

接下来的行也使用了不太高效的不同管道产生相同的结果。`map`方法必须将返回的`int`装箱为`Integer`并返回一个`Stream<Integer>`。然后，对`collect`方法的调用指定了对`Collectors.summingInt`的调用作为参数。`Collectors.summingInt`需要`int`值来计算总和，因此，我们传递了一个方法引用来调用`Stream<Integer>`中每个`Integer`的`intValue`方法。以下行使用`Collectors.summingInt`收集器来执行`int`值的求和。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，名为`example12_17.java`。

```java
int lowestScoreMapReduceSum4 = 
    repository.getAll().stream()
.map(game -> game.lowestScore)
.collect(Collectors.summingInt(Integer::intValue));
System.out.println(lowestScoreMapReduceSum4);
```

在这种情况下，我们知道`Integer.MAX_VALUE`将允许我们保存准确的求和结果。然而，在某些情况下，我们必须使用`long`类型。下面的代码使用`mapToLong`方法来使用`long`来累积值。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，名为`example12_18.java`。

```java
long lowestScoreMapReduceSum5 =
    repository.getAll().stream()
    .mapToLong(game -> game.lowestScore).sum();
System.out.println(lowestScoreMapReduceSum6);
```

### 提示

Java 9 提供了许多归约方法，也称为聚合操作。在编写自己的代码执行诸如计数、平均值和求和等操作之前，请确保考虑它们。我们可以使用它们在流上执行算术操作并获得数字结果。

# 使用 map 和 reduce 链接多个操作

我们可以链接`filter`、`map`和`reduce`操作。以下代码向`MemoryMobileGameRepository`类添加了一个新的`getHighestScoreSumForMinPlayersCount`方法。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，名为`example12_19.java`。

```java
public long getHighestScoreSumForMinPlayersCount(int minPlayersCount) {
    return getAll().stream()
        .filter(game -> (game.playersCount >= minPlayersCount))
        .mapToLong(game -> game.highestScore)
        .reduce(0, (sum, highestScore) -> sum + highestScore);
}
```

新方法执行了一个`filter`，链接了一个`mapToLong`，最后是一个`reduce`操作。对`filter`的调用生成了一个`Stream<MobileGame>`，其中包含`playersCount`值等于或大于作为参数接收的`minPlayersCount`值的`MobileGame`实例。`mapToLong`方法返回一个`LongStream`，即描述`long`原始类型流的专门化`Stream<T>`。对`mapToLong`的调用接收了每个经过筛选的`MobileGame`实例的`int`类型的`highestScore`值，并将此值转换为`long`返回。

`reduce`方法从处理管道中接收一个`LongStream`。`reduce`操作的累积值的初始值被指定为第一个参数`0`，第二个参数是一个带有组合操作的 lambda 表达式，该操作将重复调用累积值。该方法返回重复调用组合操作的结果。

`reduce`方法的第二个参数中指定的 lambda 表达式接收`sum`和`highestScore`，并返回这两个值的和。因此，lambda 表达式返回到目前为止累积的总和，接收到`sum`参数，加上正在处理的`highestScore`值。

接下来的行使用了先前创建的方法。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中，名为`example12_19.java`。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository();
System.out.println(repository.getHighestScoreSumForMinPlayersCount(150000));
```

JShell 将显示以下值作为结果：

```java
15631274

```

正如我们从前面的示例中学到的，我们可以使用`sum`方法而不是编写`reduce`方法的代码。下一行代码显示了`getHighestScoreSumForMinPlayersCount`方法的另一个版本，名为`getHighestScoreSumForMinPlayersCountV2`，它是等效的并产生相同的结果。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_20.java`文件中。

```java
public long getHighestScoreSumForMinPlayersCountV2(int minPlayersCount) {
    return getAll().stream()
        .filter(game -> (game.playersCount >= minPlayersCount))
        .mapToLong(game -> game.highestScore)
        .sum();
}
```

以下代码使用方法的新版本，并产生了与第一个版本显示的相同结果。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_20.java`文件中。

```java
MemoryMobileGameRepository repository = new MemoryMobileGameRepository();
System.out.println(repository.getHighestScoreSumForMinPlayersCountV2(150000));
```

# 使用不同的收集器

我们可以遵循函数式方法，并使用 Java 9 提供的各种收集器来解决不同类型的算法，即`java.util.stream.Collectors`类提供的各种静态方法。在接下来的示例中，我们将为`collect`方法使用不同的参数。

以下行将所有`MobileGame`实例的名称连接起来，生成一个用分隔符(`"; "`)分隔的单个`String`。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_21.java`文件中。

```java
repository.getAll().stream()
.map(game -> game.name.toUpperCase())
.collect(Collectors.joining("; "));
```

该代码将`Collectors.joining(";" )`作为参数传递给`collect`方法。`joining`静态方法返回一个`Collector`，它将输入元素连接成一个由作为参数接收的分隔符分隔的`String`。以下显示了在 JShell 中执行前面行的结果。

```java
UNCHARTED 4000; SUPERGIRL 2017; SUPER LUIGI RUN; MARIO VS KONG III; MINECRAFT RELOADED; PIKACHU VS BEEDRILL: THE REVENGE; JERRY VS TOM VS SPIKE; NBA 2017; NFL 2017; NASCAR REMIX; LITTLE BIG UNIVERSE; PLANTS VS ZOMBIES GARDEN WARFARE 3; FINAL FANTASY XVII; WATCH DOGS 3; REMEMBER ME

```

```java
java_9_oop_chapter_12_01 folder, in the example12_22.java file.
```

```java
repository.getAll().stream().sorted(Comparator.comparing(game -> game.name)).map(game -> game.name.toUpperCase()).collect(Collectors.joining("; "));
```

该代码将`Comparator.comparing(game -> game.name)`作为参数传递给`sorted`方法。`comparing`静态方法接收一个函数，从`MobileGame`中提取所需的排序键，并返回一个`Comparator<MobileGame>`，使用指定的比较器比较此排序键。代码将一个 lambda 表达式作为参数传递给`comparing`静态方法，以指定名称为`MobileGame`实例的所需排序键。sorted 方法接收一个`Stream<MobileGame>`，并返回一个根据提供的`Comparator<MobileGame>`对`MobileGame`实例进行排序的`Stream<MobileGame>`。以下显示了在 JShell 中执行前面行的结果：

```java
FINAL FANTASY XVII; JERRY VS TOM VS SPIKE; LITTLE BIG UNIVERSE; MARIO VS KONG III; MINECRAFT RELOADED; NBA 2017; NFL 2017; NASCAR REMIX; PIKACHU VS BEEDRILL: THE REVENGE; PLANTS VS ZOMBIES GARDEN WARFARE 3; REMEMBER ME; SUPER LUIGI RUN; SUPERGIRL 2017; UNCHARTED 4000; WATCH DOGS 3

```

现在我们想要检查玩家数量等于或高于指定阈值的游戏。我们想要检查通过和未通过的游戏。以下行生成一个`Map<Boolean, List<MobileGame>`，其键指定移动游戏是否通过，值包括通过或未通过的`List<MobileGame>`。然后，代码调用`forEach`方法来显示结果。示例的代码文件包含在`java_9_oop_chapter_12_01`文件夹中的`example12_23.java`文件中。

```java
Map<Boolean, List<MobileGame>> map1 = 
repository.getAll().stream()
.collect(Collectors.partitioningBy(g -> g.playersCount >= 100000));
map1.forEach((passed, mobileGames) -> {
    System.out.println(
        String.format("Mobile games that %s:",
            passed ? "passed" : "didn't pass"));
    mobileGames.forEach(System.out::println);
});
```

该代码将`Collectors.partitioningBy(g -> g.playersCount >= 100000)`作为参数传递给`collect`方法。`partitioningBy`静态方法接收一个`Predicate<MobileGame>`。代码将一个 lambda 表达式作为参数传递给`partitioningBy`静态方法，以指定输入元素必须基于`playersCount`字段是否大于或等于`100000`进行分区。返回的`Collector<MobileGame>`将`Stream<MobileGame>`分区并将其组织成`Map<Boolean, List<MobileGame>>`，执行下游归约。

然后，代码调用`forEach`方法，其中 lambda 表达式作为参数接收来自`Map<Boolean, List<MobileGame>`中的`passed`和`mobileGames`参数的键和值。以下显示了在 JShell 中执行前面行的结果：

```java
Mobile games that didn't pass:
Id: 1; Name: Uncharted 4000; Highest score: 5000; Lowest score: 10; Players count: 3800
Id: 2; Name: Supergirl 2017; Highest score: 8500; Lowest score: 5; Players count: 75000
Id: 3; Name: Super Luigi Run; Highest score: 32000; Lowest score: 300; Players count: 90000
Id: 7; Name: Jerry vs Tom vs Spike; Highest score: 78000; Lowest score: 670; Players count: 20000
Id: 14; Name: Watch Dogs 3; Highest score: 27000; Lowest score: 2; Players count: 78004
Mobile games that passed:
Id: 4; Name: Mario vs Kong III; Highest score: 152000; Lowest score: 1500; Players count: 750000
Id: 5; Name: Minecraft Reloaded; Highest score: 6708960; Lowest score: 8000; Players count: 3500000
Id: 6; Name: Pikachu vs Beedrill: The revenge; Highest score: 780000; Lowest score: 400; Players count: 1000000
Id: 8; Name: NBA 2017; Highest score: 1500607; Lowest score: 20; Players count: 7000005
Id: 9; Name: NFL 2017; Highest score: 3205978; Lowest score: 0; Players count: 4600700
Id: 10; Name: Nascar Remix; Highest score: 785000; Lowest score: 0; Players count: 2600000
Id: 11; Name: Little BIG Universe; Highest score: 95000; Lowest score: 3; Players count: 546000
Id: 12; Name: Plants vs Zombies Garden Warfare 3; Highest score: 879059; Lowest score: 0; Players count: 789000
Id: 13; Name: Final Fantasy XVII; Highest score: 852325; Lowest score: 0; Players count: 375029
Id: 15; Name: Remember Me; Highest score: 672345; Lowest score: 5; Players count: 252003

```

```java
java_9_oop_chapter_12_01 folder, in the example12_24.java file.
```

```java
Map<Boolean, List<MobileGame>> map1 =
repository.getAll().stream()
.sorted(Comparator.comparing(game -> game.name))
.collect(Collectors.partitioningBy(g -> g.playersCount >= 100000));
map1.forEach((passed, mobileGames) -> {
    System.out.println(
        String.format("Mobile games that %s:",
            passed ? "passed" : "didn't pass"));
    mobileGames.forEach(System.out::println); });
```

以下显示了在 JShell 中执行前面行的结果：

```java
Mobile games that didn't pass:
Id: 7; Name: Jerry vs Tom vs Spike; Highest score: 78000; Lowest score: 670; Players count: 20000
Id: 3; Name: Super Luigi Run; Highest score: 32000; Lowest score: 300; Players count: 90000
Id: 2; Name: Supergirl 2017; Highest score: 8500; Lowest score: 5; Players count: 75000
Id: 1; Name: Uncharted 4000; Highest score: 5000; Lowest score: 10; Players count: 3800
Id: 14; Name: Watch Dogs 3; Highest score: 27000; Lowest score: 2; Players count: 78004
Mobile games that passed:
Id: 13; Name: Final Fantasy XVII; Highest score: 852325; Lowest score: 0; Players count: 375029
Id: 11; Name: Little BIG Universe; Highest score: 95000; Lowest score: 3; Players count: 546000
Id: 4; Name: Mario vs Kong III; Highest score: 152000; Lowest score: 1500; Players count: 750000
Id: 5; Name: Minecraft Reloaded; Highest score: 6708960; Lowest score: 8000; Players count: 3500000
Id: 8; Name: NBA 2017; Highest score: 1500607; Lowest score: 20; Players count: 7000005
Id: 9; Name: NFL 2017; Highest score: 3205978; Lowest score: 0; Players count: 4600700
Id: 10; Name: Nascar Remix; Highest score: 785000; Lowest score: 0; Players count: 2600000
Id: 6; Name: Pikachu vs Beedrill: The revenge; Highest score: 780000; Lowest score: 400; Players count: 1000000
Id: 12; Name: Plants vs Zombies Garden Warfare 3; Highest score: 879059; Lowest score: 0; Players count: 789000
Id: 15; Name: Remember Me; Highest score: 672345; Lowest score: 5; Players count: 252003

```

# 测试你的知识

1.  函数接口是满足以下条件的接口：

1.  它在其默认方法中使用了一个 lambda 表达式。

1.  它具有单个抽象方法或单个方法要求。

1.  它实现了`Lambda<T, U>`接口。

1.  您可以使用以下哪个代码片段创建函数式接口的实例：

1.  Lambda 表达式、方法引用或构造函数引用。

1.  只有 lambda 表达式。方法引用和构造函数引用只能与`Predicate<T>`一起使用。

1.  方法引用和构造函数引用。Lambda 表达式只能与`Predicate<T>`一起使用。

1.  `IntPredicate`函数式接口表示一个带有：

1.  `int`类型的一个参数，返回`void`类型。

1.  `int`类型的一个参数，返回`Integer`类型的结果。

1.  `int`类型的一个参数，返回`boolean`类型的结果。

1.  当我们对`Stream<T>`应用`filter`方法时，该方法返回：

1.  `Stream<T>`。

1.  `List<T>`。

1.  `Map<T, List<T>>`。

1.  以下哪个代码片段等同于`numbers.forEach(n -> System.out.println(n));`：

1.  `numbers.forEach(n::System.out.println);`

1.  `numbers.forEach(System.out::println);`

1.  `numbers.forEach(n ->System.out.println);`

# 总结

在本章中，我们使用了 Java 9 中包含的许多函数式编程特性，并将它们与我们之前讨论的面向对象编程的所有内容结合起来。我们分析了许多算法的命令式代码和函数式编程方法之间的差异。

我们使用了函数式接口和 lambda 表达式。我们理解了方法引用和构造函数引用。我们使用泛型和接口创建了一个数据仓库，并用它来处理过滤、映射操作、归约、聚合函数、排序和分区。我们使用了不同的流处理管道。

现在您已经了解了函数式编程，我们准备利用 Java 9 中的模块化功能，这是我们将在下一章中讨论的主题。


# 第十三章：Java 9 中的模块化

在本章中，我们将利用 Java 9 添加的新功能之一，使我们能够将源代码模块化并轻松管理依赖关系。我们将：

+   重构现有代码以利用面向对象编程

+   在 Java 9 中使用新的模块化组织面向对象的代码

+   在 Java 9 中创建模块化源代码

+   使用 Java 9 编译器编译多个模块

+   使用 Java 9 运行模块化代码

# 重构现有代码以利用面向对象编程

如果我们从头开始编写面向对象的代码，我们可以利用我们在前几章学到的一切以及 Java 9 中包含的所有功能。随着需求的演变，我们将不得不对接口和类进行更改，进一步泛化或专门化它们，编辑它们，并创建新的接口和类。我们以面向对象的方式开始项目的事实将使我们能够轻松地对代码进行必要的调整。

有时，我们非常幸运，有机会在启动项目时就遵循最佳实践。然而，很多时候我们并不那么幸运，不得不处理未遵循最佳实践的项目。在这些情况下，我们可以利用我们喜爱的 IDE 提供的功能和额外的辅助工具来重构现有代码，生成促进代码重用并允许我们减少维护工作的面向对象代码，而不是遵循生成容易出错、重复且难以维护的代码的相同不良实践。

例如，假设我们需要开发一个 Web 服务，允许我们处理 3D 模型并在具有特定分辨率的 2D 图像上渲染它们。需求指定我们将使用我们的 Web 服务渲染的前两个 3D 模型是一个球体和一个立方体。Web 服务必须允许我们更改透视摄像机的以下参数，以便我们可以在 2D 屏幕上看到渲染的 3D 世界的特定部分：

+   位置（*X*、*Y*和*Z*值）

+   方向（*X*、*Y*和*Z*值）

+   上向量（*X*、*Y*和*Z*值）

+   透视视野（以度为单位）

+   近裁剪平面

+   远裁剪平面

假设其他开发人员开始在项目上工作，并生成了一个包含声明两个静态方法的类包装器的单个 Java 文件。其中一个方法渲染一个立方体，另一个方法渲染一个球体。这些方法接收渲染每个 3D 图形所需的所有参数，包括确定 3D 图形位置和大小以及配置透视摄像机和定向光的所有必要参数。

以下几行展示了一个名为`Renderer`的类的声明示例，其中包含两个静态方法：`renderCube`和`renderSphere`。第一个方法设置并渲染一个立方体，第二个方法设置并渲染一个球体。非常重要的是要理解，示例代码并不遵循最佳实践，我们将对其进行重构。请注意，这两个静态方法有很多共同的代码。示例的代码文件包含在`java_9_oop_chapter_13_01`文件夹中的`example13_01.java`文件中。

```java
// The following code doesn't follow best practices
// Please, do not use this code as a baseline
// We will refactor it to generate object-oriented code
public class Renderer {
    public static void renderCube(int x, int y, int z, int edgeLength,
        int cameraX, int cameraY, int cameraZ,
        int cameraDirectionX, int cameraDirectionY, int cameraDirectionZ,
        int cameraVectorX, int cameraVectorY, int cameraVectorZ,
        int cameraPerspectiveFieldOfView,
        int cameraNearClippingPlane,
        int cameraFarClippingPlane,
        int directionalLightX, int directionalLightY, int directionalLightZ,
        String directionalLightColor) {
            System.out.println(
                String.format("Created camera at (x:%d, y:%d, z:%d)",
                    cameraX, cameraY, cameraZ));
            System.out.println(
                String.format("Set camera direction to (x:%d, y:%d, z:%d)",
                    cameraDirectionX, cameraDirectionY, cameraDirectionZ));
            System.out.println(
                String.format("Set camera vector to (x:%d, y:%d, z:%d)",
                    cameraVectorX, cameraVectorY, cameraVectorZ));
            System.out.println(
                String.format("Set camera perspective field of view to: %d",
                    cameraPerspectiveFieldOfView));
            System.out.println(
                String.format("Set camera near clipping plane to: %d", 
                    cameraNearClippingPlane));
            System.out.println(
                String.format("Set camera far clipping plane to: %d",
                    cameraFarClippingPlane));
            System.out.println(
                String.format("Created directional light at (x:%d, y:%d, z:%d)",
                    directionalLightX, directionalLightY, directionalLightZ));
            System.out.println(
                String.format("Set light color to %s",
                    directionalLightColor));
            System.out.println(
                String.format("Drew cube at (x:%d, y:%d, z:%d) with edge length equal to %d" +
                    "considering light at (x:%d, y:%d, z:%d) " +
                    "and light's color equal to %s", 
                    x, y, z, edgeLength,
                    directionalLightX, directionalLightY, directionalLightZ,
                    directionalLightColor));
    }

    public static void renderSphere(int x, int y, int z, int radius,
        int cameraX, int cameraY, int cameraZ,
        int cameraDirectionX, int cameraDirectionY, 
        int cameraDirectionZ,
        int cameraVectorX, int cameraVectorY, int cameraVectorZ,
        int cameraPerspectiveFieldOfView,
        int cameraNearClippingPlane,
        int cameraFarClippingPlane,
        int directionalLightX, int directionalLightY, 
        int directionalLightZ,
        String directionalLightColor) {
            System.out.println(
                String.format("Created camera at (x:%d, y:%d, z:%d)",
                    cameraX, cameraY, cameraZ));
            System.out.println(
                String.format("Set camera direction to (x:%d, y:%d, z:%d)",
                    cameraDirectionX, cameraDirectionY, cameraDirectionZ));
            System.out.println(
                String.format("Set camera vector to (x:%d, y:%d, z:%d)",
                    cameraVectorX, cameraVectorY, cameraVectorZ));
            System.out.println(
                String.format("Set camera perspective field of view to: %d",
                    cameraPerspectiveFieldOfView));
            System.out.println(
                String.format("Set camera near clipping plane to: %d", 
                    cameraNearClippingPlane));
            System.out.println(
                String.format("Set camera far clipping plane to: %d",
                    cameraFarClippingPlane));
            System.out.println(
                String.format("Created directional light at (x:%d, y:%d, z:%d)",
                    directionalLightX, directionalLightY, directionalLightZ));
            System.out.println(
                String.format("Set light color to %s",
                    directionalLightColor));
            // Render the sphere
            System.out.println(
                String.format("Drew sphere at (x:%d, y:%d z:%d) with radius equal to %d",
                    x, y, z, radius));
            System.out.println(
                String.format("considering light at (x:%d, y:%d, z:%d)",
                    directionalLightX, directionalLightY, directionalLightZ));
            System.out.println(
                String.format("and the light's color equal to %s",
                    directionalLightColor));
    }
}
```

每个静态方法都需要大量的参数。现在，让我们想象一下我们对我们的 Web 服务有新的要求。我们必须添加代码来渲染额外的形状，并添加不同类型的摄像机和灯光。此外，我们必须在一个**IoT**（**物联网**）项目中工作，在这个项目中，我们必须在计算机视觉应用程序中重用形状，因此，我们希望利用我们为 Web 服务编写的代码，并与这个新项目共享代码库。此外，我们必须在另一个项目上工作，这个项目将在一块强大的 IoT 板上运行，具体来说，是英特尔 Joule 系列的一员，它将运行一个渲染服务，并利用其 4K 视频输出功能来显示生成的图形。我们将使用这块板载的强大四核 CPU 来运行本地渲染服务，在这种情况下，我们不会调用 Web 服务。

许多应用程序必须共享许多代码片段，我们的代码必须为新的形状、摄像机和灯光做好准备。代码很容易变得非常混乱、重复，并且难以维护。当然，先前显示的代码已经很难维护了。因此，我们将重构现有的代码，并创建许多接口和类来创建一个面向对象的版本，我们将能够根据新的要求进行扩展，并在不同的应用程序中重用。

到目前为止，我们一直在使用 JShell 来运行我们的代码示例。这一次，我们将为每个接口或类创建一个 Java 源代码文件。此外，我们将把这些文件组织到 Java 9 中引入的新模块中。最后，我们将编译这些模块并运行一个控制台应用程序。您可以使用您喜欢的编辑器或 IDE 来创建不同的代码文件。请记住，您可以下载指定的代码文件，而不必输入任何代码。

我们将创建以下公共接口、抽象类和具体类：

+   `Vector3d`：这个具体类表示一个可变的 3D 向量，具有`x`、`y`和`z`的`int`值。

+   `可渲染`：这个接口指定了具有位置并且可以被渲染的元素的要求。

+   `场景元素`：这个抽象类实现了`可渲染`接口，表示任何具有位置并且可以被渲染的元素。所有的场景元素都将继承自这个抽象类。

+   `灯光`：这个抽象类继承自`场景元素`，表示场景中的灯光，必须提供其属性的描述。

+   `定向光`：这个具体类继承自`灯光`，表示具有特定颜色的定向光。

+   `摄像机`：这个抽象类继承自`场景元素`，表示场景中的摄像机。

+   `透视摄像机`：这个具体类继承自`摄像机`，表示具有方向、上向量、视野、近裁剪平面和远裁剪平面的透视摄像机。

+   `形状`：这个抽象类继承自`场景元素`，表示场景中可以使用活动摄像机渲染并接收多个灯光的形状。

+   `球体`：这个具体类继承自`形状`，表示一个球体。

+   `立方体`：这个具体类继承自`形状`，表示一个立方体。

+   `场景`：这个具体类表示具有活动摄像机、形状和灯光的场景。我们可以使用这个类的实例来组合一个场景并渲染它。

+   `示例 01`：这个具体类将声明一个主静态方法，该方法将使用`透视摄像机`、`球体`、`立方体`和`定向光`来创建一个`场景`实例并调用其渲染方法。

我们将在一个扩展名为`.java`的文件中声明之前列举的每个接口、抽象类和具体类，并且文件名与我们声明的类型相同。例如，我们将在名为`Vector3d.java`的文件中声明`Vector3d`类，也就是 Java 源文件。

### 提示

在 Java 源文件中，声明与类型相同名称的单个公共接口或类是一种良好的实践和常见约定。如果我们在 Java 源文件中声明了多个公共类型，Java 编译器将生成错误。

# 使用 Java 9 中的新模块化组织面向对象的代码

当我们只有一些接口和类时，数百行面向对象的代码很容易组织和维护。然而，随着类型和代码行数的增加，有必要遵循一些规则来组织代码并使其易于维护。

一个非常好的面向对象的代码如果没有以有效的方式组织，就会产生维护上的头疼。我们不应该忘记，一个良好编写的面向对象的代码促进了代码重用。

在我们的示例中，我们只会有一些接口、抽象类和具体类。然而，我们必须想象我们将有大量额外的类型来支持额外的需求。因此，我们最终将拥有数十个与渲染场景组成元素所需的数学运算相关的类，额外类型的灯光，新类型的摄像机，与这些新灯光和摄像机相关的类，以及数十个额外的形状及其相关的类。

我们将创建许多模块，以便我们可以创建具有名称、需要其他模块并导出其他模块可用和可访问的公共 API 的软件单元。当一个模块需要其他模块时，这意味着该模块依赖于列出的模块。每个模块的名称将遵循我们通常在 Java 中使用的包的相同约定。

### 提示

其他模块只能访问模块导出的公共类型。如果我们在模块内声明了一个公共类型，但没有将其包含在导出的 API 中，那么我们将无法在模块外部访问它。在创建模块依赖关系时，我们必须避免循环依赖。

我们将创建以下八个模块：

+   `com.renderer.math`

+   `com.renderer.sceneelements`

+   `com.renderer.lights`

+   `com.renderer.cameras`

+   `com.renderer.shapes`

+   `com.renderer.shapes.curvededges`

+   `com.renderer.shapes.polyhedrons`

+   `com.renderer`

现在，每当我们需要处理灯光时，我们将探索`com.renderer.lights`模块中声明的类型。每当我们需要处理具有曲边的 3D 形状时，我们将探索`com.renderer.shapes.curvededges`模块中声明的类型。

每个模块将在与模块名称相同的包中声明类和接口。例如，`com.renderer.cameras`模块将在`com.renderer.cameras`包中声明类。**包**是相关类型的分组。每个包生成一个声明范围的命名空间。因此，我们将与模块结合使用包。

以下表格总结了我们将创建的模块，以及我们将在每个模块中声明的接口、抽象类和具体接口。此外，表格还指定了每个模块所需的模块列表。

| 模块名称 | 声明的公共类型 | 模块要求 |
| --- | --- | --- |
| `com.renderer.math` | `Vector3d` | `-` |
| `com.renderer.sceneelements` | `Rendereable``SceneElement` | `com.renderer.math` |
| `com.renderer.lights` | `Light``DirectionalLight` | `com.renderer.math``com.renderer.sceneelements` |
| `com.renderer.cameras` | `Camera``PerspectiveCamera` | `com.renderer.math``com.renderer.sceneelements` |
| `com.renderer.shapes` | `Shape` | `com.renderer.math``com.renderer.sceneelements``com.renderer.lights``com.renderer.cameras` |
| `com.renderer.shapes.curvededges` | `Sphere` | `com.renderer.math``com.renderer.lights``co` `m.renderer.shapes` |
| `com.renderer.shapes.polyhedrons` | `Cube` | `com.renderer.math``com.renderer.lights``com.renderer.shapes` |
| `com.renderer` | `Scene``Example01` | `com.renderer.math``com.renderer.cameras``com.renderer.lights``com.renderer.shapes``com.renderer.shapes.curvededges``com.renderer.shapes.polyhedrons` |

非常重要的是要注意，所有模块还需要`java.base`模块，该模块导出所有平台的核心包，如`java.io`、`java.lang`、`java.math`、`java.net`和`java.util`等。然而，每个模块都隐式依赖于`java.base`模块，因此，在声明新模块并指定其所需模块时，无需将其包含在依赖列表中。

下一个图表显示了模块图，其中模块是节点，一个模块对另一个模块的依赖是一个有向边。我们不在模块图中包括`java.lang`。

![使用 Java 9 中的新模块化组织面向对象的代码](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00101.jpeg)

我们不会使用任何特定的 IDE 来创建所有模块。这样，我们将了解目录结构和所有必需的文件。然后，我们可以利用我们喜欢的 IDE 中包含的功能轻松创建新模块及其必需的目录结构。

有一个约定规定，模块的源代码必须位于与模块名称相同的目录中。例如，名为`com.renderer.math`的模块必须位于名为`com.renderer.math`的目录中。我们必须为每个所需的模块创建一个模块描述符，即在模块的根文件夹中创建一个名为`module-info.java`的源代码文件。该文件指定了模块名称、所需的模块和模块导出的包。导出的包将被需要该模块的模块看到。

然后，需要为模块名称中由点（`.`）分隔的每个名称创建子目录。例如，我们将在`com.renderer.math`目录中创建`com/renderer/math`目录（在 Windows 中为`com\renderer\math`子文件夹）。声明每个模块的接口、抽象类和具体类的 Java 源文件将位于这些子文件夹中。

我们将创建一个名为`Renderer`的基本目录，其中包含一个名为`src`的子文件夹，其中包含我们所有模块的源代码。因此，我们将`Renderer/src`（在 Windows 中为`Renderer\src`）作为我们的源代码基本目录。然后，我们将为每个模块创建一个文件夹，其中包含`module-info.java`文件和 Java 源代码文件的子文件夹。以下目录结构显示了我们将在`Renderer/src`（在 Windows 中为`Renderer\src`）目录中拥有的最终内容。文件名已突出显示。

```java
├───com.renderer
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│               Example01.java
│               Scene.java
│
├───com.renderer.cameras
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───cameras
│                   Camera.java
│                   PerspectiveCamera.java
│
├───com.renderer.lights
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───lights
│                   DirectionalLight.java
│                   Light.java
│
├───com.renderer.math
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───math
│                   Vector3d.java
│
├───com.renderer.sceneelements
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───sceneelements
│                   Rendereable.java
│                   SceneElement.java
│
├───com.renderer.shapes
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───shapes
│                   Shape.java
│
├───com.renderer.shapes.curvededges
│   │   module-info.java
│   │
│   └───com
│       └───renderer
│           └───shapes
│               └───curvededges
│                       Sphere.java
│
└───com.renderer.shapes.polyhedrons
 │   module-info.java
    │
    └───com
        └───renderer
            └───shapes
                └───polyhedrons
 Cube.java

```

# 创建模块化源代码。

现在是时候开始创建必要的目录结构，并为每个模块编写`module-info.java`文件和源 Java 文件的代码了。我们将创建`com.renderer.math`模块。

创建一个名为`Renderer`的目录和一个`src`子目录。我们将使用`Renderer/src`（在 Windows 中为`Renderer\src`）作为我们的源代码基本目录。但是，请注意，如果您下载源代码，则无需创建任何文件夹。

现在在`Renderer/src`（在 Windows 中为`Renderer\src`）中创建`com.renderer.math`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。下面的行组成了名为`com.renderer.math`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.math`子文件夹中的`module-info.java`文件中。

```java
module com.renderer.math {
    exports com.renderer.math;
}
```

`module`关键字后跟模块名称`com.renderer.math`开始模块声明。花括号中包含的行指定了模块主体。`exports`关键字后跟包名`com.renderer.math`表示该模块导出`com.renderer.math`包中声明的所有公共类型。

在`Renderer/src`（在 Windows 中为`Renderer\src`）中创建`com/renderer/math`（在 Windows 中为`com\renderer\math`）文件夹。将以下行添加到名为`Vector3d.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Vector3d`具体类，作为`com.renderer.math`包的成员。我们将使用`Vector3d`类，而不是使用`x`、`y`和`z`的单独值。`package`关键字后面跟着包名，表示类将被包含在其中的包。

示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.math/com/renderer/math`子文件夹中，名为`Vector3d.java`。

```java
package com.renderer.math;

public class Vector3d {
    public int x;
    public int y;
    public int z;

    public Vector3d(int x, 
        int y, 
        int z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public Vector3d(int valueForXYZ) {
        this(valueForXYZ, valueForXYZ, valueForXYZ);
    }

    public Vector3d() {
        this(0);
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
            "(x: %d, y: %d, z: %d)",
            x,
            y,
            z);
    }
}
```

现在在`Renderer/src`（在 Windows 中为`Renderer\src`）中创建`com.renderer.sceneelements`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.sceneelements`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.sceneelements`子文件夹中，名为`module-info.java`。

```java
module com.renderer.sceneelements {
    requires com.renderer.math;
    exports com.renderer.sceneelements;
}
```

`module`关键字后面跟着模块名`com.renderer.sceneelements`开始模块声明。花括号内包含的行指定了模块主体。`requires`关键字后面跟着模块名`com.renderer.math`，表示该模块需要先前声明的`com.renderer.math`模块中导出的类型。`exports`关键字后面跟着包名`com.renderer.sceneelements`，表示该模块导出`com.renderer.sceneelements`包中声明的所有公共类型。

在`Renderer/src`（在 Windows 中为`Renderer\src`）中创建`com/renderer/sceneelements`（在 Windows 中为`com\renderer\sceneelements`）文件夹。将以下行添加到名为`Rendereable.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Rendereable`接口，作为`com.renderer.sceneelements`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.sceneeelements/com/renderer/sceneelements`子文件夹中，名为`Rendereable.java`。

```java
package com.renderer.sceneelements;

import com.renderer.math.Vector3d;

public interface Rendereable {
    Vector3d getLocation();
    void setLocation(Vector3d newLocation);
    void render();
}
```

将以下行添加到名为`SceneElement.java`的文件中。接下来的行声明了公共`SceneElement`抽象类，作为`com.renderer.sceneelements`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.sceneelements/com/renderer/sceneelements`子文件夹中，名为`SceneElement.java`。

```java
package com.renderer.sceneelements;

import com.renderer.math.Vector3d;

public abstract class SceneElement implements Rendereable {
    protected Vector3d location;

    public SceneElement(Vector3d location) {
        this.location = location;
    }

    public Vector3d getLocation() {
        return location;
    }

    public void setLocation(Vector3d newLocation) {
        location = newLocation;
    }
}
```

`SceneElement`抽象类实现了先前定义的`Rendereable`接口。该类表示场景中的 3D 元素，并具有使用`Vector3d`指定的位置。该类是所有需要在 3D 空间中具有位置的场景元素的基类。

现在在`Renderer/src`（在 Windows 中为`Renderer\src`）中创建`com.renderer.lights`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.lights`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.lights`子文件夹中，名为`module-info.java`。

```java
module com.renderer.lights {
    requires com.renderer.math;
    requires com.renderer.sceneelements;
    exports com.renderer.lights;
}
```

前面的行声明了`com.renderer.lights`模块，并指定该模块需要两个模块：`com.renderer.math`和`com.renderer.sceneelements`。`exports`关键字后面跟着包名`com.renderer.lights`，表示该模块导出`com.renderer.lights`包中声明的所有公共类型。

在`Renderer/src`中创建`com/renderer/lights`（在 Windows 中为`com\renderer\lights`）文件夹。将以下行添加到名为`Light.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Light`抽象类作为`com.renderer.lights`包的成员。该类继承自`SceneElement`类，并声明了一个必须返回`String`类型的描述所有灯光属性的抽象`getPropertiesDescription`方法。从`Light`类继承的具体类将负责为此方法提供实现。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.lights/com/renderer/lights`子文件夹中的`Light.java`文件中。

```java
package com.renderer.lights;

import com.renderer.sceneelements.SceneElement;
import com.renderer.math.Vector3d;

public abstract class Light extends SceneElement {
    public Light(Vector3d location) {
        super(location);
    }

    public abstract String getPropertiesDescription();
}
```

将以下行添加到名为`DirectionalLight.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`DirectionalLight`具体类作为`com.renderer.lights`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.lights/com/renderer/lights`子文件夹中的`DirectionalLight.java`文件中。

```java
package com.renderer.lights;

import com.renderer.math.Vector3d;

public class DirectionalLight extends Light {
    public final String color;

    public DirectionalLight(Vector3d location, 
        String color) {
        super(location);
        this.color = color;
    }

    @Override
    public void render() {
        System.out.println(
            String.format("Created directional light at %s",
                location));
        System.out.println(
            String.format("Set light color to %s",
                color));
    }

    @Override
    public String getPropertiesDescription() {
        return String.format(
            "light's color equal to %s",
            color);
    }
}
```

`DirectionalLight`具体类继承自先前定义的`Light`抽象类。`DirectionalLight`类表示定向光，并为`render`和`getPropertiesDescription`方法提供实现。

现在在`Renderer/src`中创建`com.renderer.cameras`目录（在 Windows 中为`Renderer\src`）。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.cameras`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.cameras`子文件夹中的`module-info.java`文件中。

```java
module com.renderer.cameras {
    requires com.renderer.math;
    requires com.renderer.sceneelements;
    exports com.renderer.cameras;
}
```

前面的行声明了`com.renderer.cameras`模块，并指定该模块需要两个模块：`com.renderer.math`和`com.renderer.sceneelements`。`exports`关键字后跟包名`com.renderer.cameras`，表示该模块导出`com.renderer.cameras`包中声明的所有公共类型。

在`Renderer/src`中创建`com/renderer/cameras`（在 Windows 中为`com\renderer\cameras`）文件夹。将以下行添加到名为`Camera.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Camera`抽象类作为`com.renderer.cameras`包的成员。该类继承自`SceneElement`类。该类表示 3D 相机。这是所有相机的基类。在这种情况下，类声明为空，我们只声明它是因为我们知道将会有许多类型的相机。此外，我们希望能够在将来概括所有类型相机的共同要求，就像我们为灯光做的那样。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.cameras/com/renderer/cameras`子文件夹中的`Camera.java`文件中。

```java
package com.renderer.cameras;

import com.renderer.math.Vector3d;
import com.renderer.sceneelements.SceneElement;

public abstract class Camera extends SceneElement {
    public Camera(Vector3d location) {
        super(location);
    }
}
```

将以下行添加到名为`PerspectiveCamera.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`PerspectiveCamera`具体类作为`com.renderer.cameras`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.cameras/com/renderer/cameras`子文件夹中的`PerspectiveCamera.java`文件中。

```java
package com.renderer.cameras;

import com.renderer.math.Vector3d;

public class PerspectiveCamera extends Camera {
    protected Vector3d direction;
    protected Vector3d vector;
    protected int fieldOfView;
    protected int nearClippingPlane;
    protected int farClippingPlane;

    public Vector3d getDirection() {
        return direction;
    }

    public void setDirection(Vector3d newDirection) {
        direction = newDirection;
    }

    public Vector3d getVector() {
        return vector;
    }

    public void setVector(Vector3d newVector) {
        vector = newVector;
    }

    public int getFieldOfView() {
        return fieldOfView;
    }

    public void setFieldOfView(int newFieldOfView) {
        fieldOfView = newFieldOfView;
    }

    public int nearClippingPlane() {
        return nearClippingPlane;
    }

    public void setNearClippingPlane(int newNearClippingPlane) {
        this.nearClippingPlane = newNearClippingPlane;
    }

    public int farClippingPlane() {
        return farClippingPlane;
    }

    public void setFarClippingPlane(int newFarClippingPlane) {
        this.farClippingPlane = newFarClippingPlane;
    }

    public PerspectiveCamera(Vector3d location, 
        Vector3d direction, 
        Vector3d vector, 
        int fieldOfView, 
        int nearClippingPlane, 
        int farClippingPlane) {
        super(location);
        this.direction = direction;
        this.vector = vector;
        this.fieldOfView = fieldOfView;
        this.nearClippingPlane = nearClippingPlane;
        this.farClippingPlane = farClippingPlane;
    }

    @Override
    public void render() {
        System.out.println(
            String.format("Created camera at %s",
                location));
        System.out.println(
            String.format("Set camera direction to %s",
                direction));
        System.out.println(
            String.format("Set camera vector to %s",
                vector));
        System.out.println(
            String.format("Set camera perspective field of view to: %d",
                fieldOfView));
        System.out.println(
            String.format("Set camera near clipping plane to: %d", 
                nearClippingPlane));
        System.out.println(
            String.format("Set camera far clipping plane to: %d",
                farClippingPlane));
    }
}
```

`PerspectiveCamera`具体类继承自先前定义的`Camera`抽象类。`PerspectiveCamera`类表示具有许多获取器和设置器方法的透视相机的实现。该类为`render`方法提供了一个显示所创建相机的所有细节和其不同属性值的实现。

现在在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com.renderer.shapes`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.shapes`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.shapes`子文件夹中的`module-info.java`文件中。

```java
module com.renderer.shapes {
    requires com.renderer.math;
    requires com.renderer.sceneelements;
    requires com.renderer.lights;
    requires com.renderer.cameras;
    exports com.renderer.shapes;
}
```

前面的行声明了`com.renderer.shapes`模块，并指定该模块需要四个模块：`com.renderer.math`、`com.renderer.sceneelements`、`com.renderer.lights`和`com.renderer.cameras`。`exports`关键字后跟包名`com.renderer.shapes`，表示该模块导出了`com.renderer.shapes`包中声明的所有公共类型。

在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com/renderer/shapes`（Windows 中为`com\renderer\shapes`）文件夹。将以下行添加到名为`Shape.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Shape`抽象类作为`com.renderer.shapes`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.shapes/com/renderer/shapes`子文件夹中的`Shape.java`文件中。

```java
package com.renderer.shapes;

import com.renderer.math.Vector3d;
import com.renderer.sceneelements.SceneElement;
import com.renderer.lights.Light;
import com.renderer.cameras.Camera;
import java.util.*;
import java.util.stream.Collectors;

public abstract class Shape extends SceneElement {
    protected Camera activeCamera;
    protected List<Light> lights;

    public Shape(Vector3d location) {
        super(location);
        lights = new ArrayList<>();
    }

    public void setActiveCamera(Camera activeCamera) {
        this.activeCamera = activeCamera;
    }

    public void setLights(List<Light> lights) {
        this.lights = lights;
    }

    protected boolean isValidForRender() {
        return !((activeCamera == null) && lights.isEmpty());
    }

    protected String generateConsideringLights() {
        return lights.stream()
            .map(light -> String.format(
                "considering light at %s\nand %s",
                    light.getLocation(), 
                    light.getPropertiesDescription()))
            .collect(Collectors.joining());
    }
}
```

`Shape`类继承自`SceneElement`类。该类表示一个 3D 形状，是所有 3D 形状的基类。该类定义了以下方法：

+   `setActiveCamera`：这个公共方法接收一个`Camera`实例并将其保存为活动摄像机。

+   `setLights`：这个公共方法接收一个`List<Light>`并将其保存为必须考虑以渲染形状的灯光列表。

+   `isValidForRender`：这个受保护的方法返回一个`boolean`值，指示形状是否具有活动摄像机和至少一个灯光。否则，该形状不适合被渲染。

+   `generateConsideringLights`：这个受保护的方法返回一个带有正在考虑渲染形状的灯光、它们的位置和属性描述的`String`。

`Shape`类的每个子类，代表特定的 3D 形状，将为`render`方法提供实现。我们将在另外两个模块中编写这些子类。

现在在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com.renderer.shapes.curvededges`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.curvededges`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.curvededges`子文件夹中的`module-info.java`文件中。

```java
module com.renderer.shapes.curvededges {
    requires com.renderer.math;
    requires com.renderer.lights;
    requires com.renderer.shapes;
    exports com.renderer.shapes.curvededges;
}
```

前面的行声明了`com.renderer.shapes`模块，并指定该模块需要三个模块：`com.renderer.math`、`com.renderer.lights`和`com.renderer.shapes`。`exports`关键字后跟包名`com.renderer.shapes.curvededges`，表示该模块导出了`com.renderer.shapes.curvededges`包中声明的所有公共类型。

在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com/renderer/shapes/curvededges`（Windows 中为`com\renderer\shapes\curvededges`）文件夹。将以下行添加到名为`Sphere.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Sphere`具体类作为`com.renderer.shapes.curvededges`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.shapes.curvededges/com/renderer/shapes/curvededges`子文件夹中的`Sphere.java`文件中。

```java
package com.renderer.shapes.curvededges;

import com.renderer.math.Vector3d;
import com.renderer.shapes.Shape;
import com.renderer.lights.Light;

public class Sphere extends Shape {
    protected int radius;

    public Sphere(Vector3d location, int radius) {
        super(location);
        this.radius = radius;
    }

    public int getRadius() {
        return radius;
    }

    public void setRadius(int newRadius) { 
        radius = newRadius;
    }

    @Override
    public void render() {
        if (!isValidForRender()) {
            System.out.println(
                "Setup wasn't completed to render the sphere.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(
            "Drew sphere at %s with radius equal to %d\n",
            location, 
            radius));
        String consideringLights = 
            generateConsideringLights();
        sb.append(consideringLights);
        System.out.println(sb.toString());
    }
}
```

`Sphere`类继承自`Shape`类，并在构造函数中需要一个半径值，除了指定球体位置的`Vector3d`实例。该类提供了`render`方法的实现，该方法检查`isValidForRender`方法返回的值。如果该方法返回`true`，则球体可以被渲染，并且代码将使用球体半径、位置以及在渲染球体时考虑的灯光构建消息。代码调用`generateConsideringLights`方法来构建消息。

现在在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com.renderer.shapes.polyhedrons`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer.polyhedrons`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.polyhedrons`子文件夹中的`module-info.java`文件中。

```java
module com.renderer.shapes.polyhedrons {
    requires com.renderer.math;
    requires com.renderer.lights;
    requires com.renderer.shapes;
    exports com.renderer.shapes.polyhedrons;
}
```

前面的行声明了`com.renderer.polyhedrons`模块，并指定该模块需要三个模块：`com.renderer.math`、`com.renderer.lights`和`com.renderer.shapes`。`exports`关键字后跟包名`com.renderer.shapes.polyhedrons`，表示该模块导出`com.renderer.shapes.polyhedrons`包中声明的所有公共类型。

在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com/renderer/shapes/polyhedrons`（Windows 中为`com\renderer\shapes\polyhedrons`）文件夹。将以下行添加到名为`Cube.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Cube`具体类作为`com.renderer.shapes.polyhedrons`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer.shapes.polyhedrons/com/renderer/shapes/polyhedrons`子文件夹中的`Cube.java`文件中。

```java
package com.renderer.shapes.polyhedrons;

import com.renderer.math.Vector3d;
import com.renderer.shapes.Shape;
import com.renderer.lights.Light;
import java.util.stream.Collectors;

public class Cube extends Shape {
    protected int edgeLength;

    public Cube(Vector3d location, int edgeLength) {
        super(location);
        this.edgeLength = edgeLength;
    }

    public int getEdgeLength() {
        return edgeLength;
    }

    public void setEdgeLength(int newEdgeLength) { 
        edgeLength = newEdgeLength;
    }

    @Override
    public void render() {
        if (!isValidForRender()) {
            System.out.println(
                "Setup wasn't completed to render the cube.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(
            "Drew cube at %s with edge length equal to %d\n",
            location,
            edgeLength));
        String consideringLights = 
            generateConsideringLights();
        sb.append(consideringLights);
        System.out.println(sb.toString());
    }
}
```

`Cube`类继承自`Shape`类，并在构造函数中需要一个`edgeLength`值，除了指定立方体位置的`Vector3d`。该类提供了`render`方法的实现，该方法检查`isValidForRender`方法返回的值。如果该方法返回`true`，则立方体可以被渲染，并且代码将使用立方体的边长、位置以及在渲染立方体时考虑的灯光构建消息。代码调用`generateConsideringLights`方法来构建消息。

现在在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com.renderer`目录。将以下行添加到名为`module-info.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行组成了名为`com.renderer`的模块描述符。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer`子文件夹中的`module-info.java`文件中。

```java
module com.renderer {
    exports com.renderer;
    requires com.renderer.math;
    requires com.renderer.cameras;
    requires com.renderer.lights;
    requires com.renderer.shapes;
    requires com.renderer.shapes.curvededges;
    requires com.renderer.shapes.polyhedrons;
}
```

前面的行声明了`com.renderer`模块，并指定该模块需要六个模块：`com.renderer.math`、`com.renderer.cameras`、`com.renderer.lights`、`com.renderer.shapes`、`com.renderer.shapes.curvededges`和`com.renderer.shapes.polyhedrons`。`exports`关键字后跟包名`com.renderer`，表示该模块导出`com.renderer`包中声明的所有公共类型。

在`Renderer/src`（Windows 中为`Renderer\src`）中创建`com/renderer`（Windows 中为`com\renderer`）文件夹。将以下行添加到名为`Scene.java`的文件中，该文件位于最近创建的子文件夹中。接下来的行声明了公共`Scene`具体类作为`com.renderer`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer/com/renderer`子文件夹中的`Scene.java`文件中。

```java
package com.renderer;

import com.renderer.math.Vector3d;
import com.renderer.cameras.Camera;
import com.renderer.lights.Light;
import com.renderer.shapes.Shape;
import java.util.*;

public class Scene {
    protected List<Light> lights;
    protected List<Shape> shapes;
    protected Camera activeCamera;

    public Scene(Camera activeCamera) {
        this.activeCamera = activeCamera;
        this.lights = new ArrayList<>();
        this.shapes = new ArrayList<>();
    }

    public void addLight(Light light) {
        this.lights.add(light);
    }

    public void addShape(Shape shape) {
        this.shapes.add(shape);
    }

    public void render() {
        activeCamera.render();
        lights.forEach(Light::render);
        shapes.forEach(shape -> {
            shape.setActiveCamera(activeCamera);
            shape.setLights(lights);
            shape.render();
        });
    }
}
```

`Scene`类表示要渲染的场景。该类声明了一个`activateCamera`受保护字段，其中包含一个`Camera`实例。`lights`受保护字段是`Light`实例的`List`，`shapes`受保护字段是组成场景的`Shape`实例的`List`。`addLight`方法将接收到的`Light`实例添加到`List<Light>lights`中。`addShape`方法将接收到的`Shape`实例添加到`List<Shape> shapes`中。

`render`方法调用活动摄像机和所有灯光的渲染方法。然后，代码对每个形状执行以下操作：设置其活动摄像机，设置灯光，并调用`render`方法。

最后，将以下行添加到名为`Example01.java`的文件中。接下来的行声明了公共`Example01`具体类作为`com.renderer`包的成员。示例的代码文件包含在`java_9_oop_chapter_13_01/Renderer/src/com.renderer/com/renderer`子文件夹中的`Example01.java`文件中。

```java
package com.renderer;

import com.renderer.math.Vector3d;
import com.renderer.cameras.PerspectiveCamera;
import com.renderer.lights.DirectionalLight;
import com.renderer.shapes.curvededges.Sphere;
import com.renderer.shapes.polyhedrons.Cube;

public class Example01 {
    public static void main(String[] args){
        PerspectiveCamera camera = new PerspectiveCamera(
            new Vector3d(30),
            new Vector3d(50, 0, 0),
            new Vector3d(4, 5, 2),
            90,
            20,
            40);
        Sphere sphere = new Sphere(new Vector3d(20), 8);
        Cube cube = new Cube(new Vector3d(10), 5);
        DirectionalLight light = new DirectionalLight(
            new Vector3d(2, 2, 5), "Cornflower blue");
        Scene scene = new Scene(camera);
        scene.addShape(sphere);
        scene.addShape(cube);
        scene.addLight(light);
        scene.render();
    }
}
```

`Example01`类是我们测试应用程序的主类。该类只声明了一个名为`main`的`static`方法，该方法接收一个名为`args`的`String`数组作为参数。当我们执行应用程序时，Java 将调用此方法，并将参数传递给`args`参数。在这种情况下，`main`方法中的代码不考虑任何指定的参数。

主要方法创建一个具有必要参数的`PerspectiveCamera`实例，然后创建一个名为`shape`和`cube`的`Shape`和`Cube`。然后，代码创建一个名为`light`的`DirectionalLight`实例。

下一行创建一个具有`camera`作为`activeCamera`参数值的`Scene`实例。然后，代码两次调用`scene.addShape`方法，参数分别为`sphere`和`cube`。最后，代码调用`scene.addLight`，参数为`light`，并调用`scene.render`方法来显示模拟渲染过程生成的消息。

# 使用 Java 9 编译器编译多个模块

在名为`Renderer`的基本目录中创建一个名为`mods`的子文件夹。这个新的子文件夹将复制我们在`Renderer/src`（Windows 中的`Renderer\src`）文件夹中创建的目录结构。我们将运行 Java 编译器为每个 Java 源文件生成一个 Java 类文件。Java 类文件将包含可以在**Java 虚拟机**上执行的 Java 字节码，也称为**JVM**。对于每个具有`.java`扩展名的 Java 源文件，包括模块描述符，我们将有一个具有`.class`扩展名的文件。例如，当我们成功使用 Java 编译器编译`Renderer/src/com.renderer.math/com/renderer/math/Vector3d.java`源文件时，编译器将生成一个`Renderer/mods/com.renderer.math/com/renderer/math/Vector3d.class`文件，其中包含 Java 字节码（称为 Java 类文件）。在 Windows 中，我们必须使用反斜杠（`\`）作为路径分隔符，而不是斜杠（`/`）。

现在，在 macOS 或 Linux 上打开一个终端窗口，或者在 Windows 上打开命令提示符，并转到`Renderer`文件夹。确保`javac`命令包含在路径中，并且它是 Java 9 的 Java 编译器，而不是之前版本的 Java 编译器，这些版本不兼容 Java 9 中引入的模块。

在 macOS 或 Linux 中，运行以下命令来编译我们最近创建的所有模块，并将生成的 Java 类文件放在`mods`文件夹中的目录结构中。`-d`选项指定了生成类文件的位置，`--module-source-path`选项指示了多个模块的输入源文件的位置。

```java
javac -d mods --module-source-path src src/com.renderer.math/module-info.java src/com.renderer.math/com/renderer/math/Vector3d.java src/com.renderer.sceneelements/module-info.java src/com.renderer.sceneelements/com/renderer/sceneelements/Rendereable.java src/com.renderer.sceneelements/com/renderer/sceneelements/SceneElement.java src/com.renderer.cameras/module-info.java src/com.renderer.cameras/com/renderer/cameras/Camera.java src/com.renderer.cameras/com/renderer/cameras/PerspectiveCamera.java src/com.renderer.lights/module-info.java src/com.renderer.lights/com/renderer/lights/DirectionalLight.java src/com.renderer.lights/com/renderer/lights/Light.java src/com.renderer.shapes/module-info.java src/com.renderer.shapes/com/renderer/shapes/Shape.java src/com.renderer.shapes.curvededges/module-info.java src/com.renderer.shapes.curvededges/com/renderer/shapes/curvededges/Sphere.java src/com.renderer.shapes.polyhedrons/module-info.java src/com.renderer.shapes.polyhedrons/com/renderer/shapes/polyhedrons/Cube.java src/com.renderer/module-info.java src/com.renderer/com/renderer/Example01.java src/com.renderer/com/renderer/Scene.java

```

在 Windows 中，运行以下命令以实现相同的目标：

```java
javac -d mods --module-source-path src src\com.renderer.math\module-info.java src\com.renderer.math\com\renderer\math\Vector3d.java src\com.renderer.sceneelements\module-info.java src\com.renderer.sceneelements\com\renderer\sceneelements\Rendereable.java src\com.renderer.sceneelements\com\renderer\sceneelements\SceneElement.java src\com.renderer.cameras\module-info.java src\com.renderer.cameras\com\renderer\cameras\Camera.java src\com.renderer.cameras\com\renderer\cameras\PerspectiveCamera.java src\com.renderer.lights\module-info.java src\com.renderer.lights\com\renderer\lights\DirectionalLight.java src\com.renderer.lights\com\renderer\lights\Light.java src\com.renderer.shapes\module-info.java src\com.renderer.shapes\com\renderer\shapes\Shape.java src\com.renderer.shapes.curvededges\module-info.java src\com.renderer.shapes.curvededges\com\renderer\shapes\curvededges\Sphere.java src\com.renderer.shapes.polyhedrons\module-info.java src\com.renderer.shapes.polyhedrons\com\renderer\shapes\polyhedrons\Cube.java src\com.renderer\module-info.java src\com.renderer\com\renderer\Example01.java src\com.renderer\com\renderer\Scene.java

```

以下目录结构显示了我们将在`Renderer/mods`（Windows 中的`Renderer\mods`）目录中拥有的最终内容。Java 编译器生成的 Java 类文件已经高亮显示。

```java
├───com.renderer
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│               Example01.class
│               Scene.class
│
├───com.renderer.cameras
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───cameras
│                   Camera.class
│                   PerspectiveCamera.class
│
├───com.renderer.lights
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───lights
│                   DirectionalLight.class
│                   Light.class
│
├───com.renderer.math
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───math
│                   Vector3d.class
│
├───com.renderer.sceneelements
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───sceneelements
│                   Rendereable.class
│                   SceneElement.class
│
├───com.renderer.shapes
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───shapes
│                   Shape.class
│
├───com.renderer.shapes.curvededges
│   │   module-info.class
│   │
│   └───com
│       └───renderer
│           └───shapes
│               └───curvededges
│                       Sphere.class
│
└───com.renderer.shapes.polyhedrons
 │   module-info.class
    │
    └───com
        └───renderer
            └───shapes
                └───polyhedrons
 Cube.class

```

# 使用 Java 9 运行模块化代码

最后，我们可以使用 `java` 命令启动 Java 应用程序。返回 macOS 或 Linux 上的终端窗口，或者 Windows 上的命令提示符，并确保你在 `Renderer` 文件夹中。确保 `java` 命令包含在路径中，并且它是 Java 9 的 `java` 命令，而不是不兼容 Java 9 中引入的模块的先前 Java 版本的 `java` 命令。

在 macOS、Linux 或 Windows 中，运行以下命令来加载已编译的模块，解析 `com.renderer` 模块，并运行 `com.renderer` 包中声明的 `Example01` 类的 `main` 静态方法。`--module-path` 选项指定可以找到模块的目录。在这种情况下，我们只指定 `mods` 文件夹。但是，我们可以包括许多由分号 (`;`) 分隔的目录。`-m` 选项指定要解析的初始模块名称，后面跟着一个斜杠 (`/`) 和要执行的主类的名称。

```java
java --module-path mods -m com.renderer/com.renderer.Example01

```

以下行显示了执行先前命令后运行 `Example01` 类的 `main` 静态方法后生成的输出。

```java
Created camera at (x: 30, y: 30, z: 30)
Set camera direction to (x: 50, y: 0, z: 0)
Set camera vector to (x: 4, y: 5, z: 2)
Set camera perspective field of view to: 90
Set camera near clipping plane to: 20
Set camera far clipping plane to: 40
Created directional light at (x: 2, y: 2, z: 5)
Set light color to Cornflower blue
Drew sphere at (x: 20, y: 20, z: 20) with radius equal to 8
considering light at (x: 2, y: 2, z: 5)
and light's color equal to Cornflower blue
Drew cube at (x: 10, y: 10, z: 10) with edge length equal to 5
considering light at (x: 2, y: 2, z: 5)
and light's color equal to Cornflower blue

```

在以前的 Java 版本中，我们可以将许多 Java 类文件及其关联的元数据和资源聚合到一个名为 **JAR**（**Java 存档**）文件的压缩文件中。我们还可以将模块打包为包含 `module-info.class` 文件的模块化 JAR，该文件在顶层文件夹中的压缩文件中。

此外，我们可以使用 Java 链接工具 (`jlink`) 创建一个定制的运行时映像，其中只包括我们应用程序所需的模块。这样，我们可以利用整体程序优化，并生成一个在 JVM 之上运行的自定义运行时映像。

# 测试你的知识

1.  默认情况下，模块需要：

1.  `java.base` 模块。

1.  `java.lang` 模块。

1.  `java.util` 模块。

1.  有一个约定规定，Java 9 模块的源代码必须位于一个具有以下内容的目录中：

1.  与模块导出的主类相同的名称。

1.  与模块名称相同的名称。

1.  与模块导出的主类型相同的名称。

1.  以下哪个源代码文件是模块描述符：

1.  `module-def.java`

1.  `module-info.java`

1.  `module-data.java`

1.  以下是模块描述符中必须跟随模块名称的关键字：

1.  `name`

1.  `module-name`

1.  `module`

1.  模块描述符中的 `exports` 关键字后跟包名表示模块导出：

1.  包中声明的所有类。

1.  包中声明的所有类型。

1.  包中声明的所有公共类型。

# 总结

在本章中，我们学会了重构现有代码，充分利用 Java 9 的面向对象代码。我们已经为未来的需求准备好了代码，减少了维护成本，并最大程度地重用了代码。

我们学会了组织面向对象的代码。我们创建了许多 Java 源文件。我们在不同的 Java 源文件中声明了接口、抽象类和具体类。我们利用了 Java 9 中包含的新模块化特性，创建了许多具有对不同模块的依赖关系并导出特定类型的模块。我们学会了声明模块，将它们编译成 Java 字节码，并在 JShell 之外启动应用程序。

现在你已经学会在 Java 9 中编写面向对象的代码，你可以在真实的桌面应用程序、移动应用、企业应用程序、Web 服务和 Web 应用程序中使用你学到的一切。这些应用程序将最大程度地重用代码，简化维护，并且始终为未来的需求做好准备。你可以使用 JShell 轻松地原型化新的接口和类，这将提高你作为面向对象的 Java 9 开发人员的生产力。
