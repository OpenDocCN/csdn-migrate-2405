# Java 测试驱动开发（二）

> 原文：[`zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930`](https://zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：单元测试-关注您正在做的事情，而不是已经完成的事情

“要创造出非凡的东西，你的心态必须专注于最小的细节。”

-乔治·阿玛尼

正如承诺的那样，每一章都将探讨不同的 Java 测试框架，这一章也不例外。我们将使用 TestNG 来构建我们的规范。

在之前的第三章中，我们练习了红-绿-重构的过程。我们使用了单元测试，但并没有深入探讨单元测试在 TDD 背景下的工作原理。我们将在上一章的知识基础上进行更详细的讨论，试图解释单元测试到底是什么，以及它们如何适用于 TDD 构建软件的方法。

本章的目标是学习如何专注于我们当前正在处理的单元，并学会忽略或隔离那些已经完成的单元。

一旦我们熟悉了 TestNG 和单元测试，我们将立即开始进入下一个应用程序的需求并开始编码。

本章将涵盖以下主题：

+   单元测试

+   使用 TDD 进行单元测试

+   TestNG

+   遥控船的要求

+   开发遥控船

# 单元测试

频繁的手动测试对于除了最小的系统之外都太不切实际了。唯一的解决办法是使用自动化测试。它们是减少构建、部署和维护应用程序的时间和成本的唯一有效方法。为了有效地管理应用程序，实施和测试代码尽可能简单至关重要。简单是**极限编程**（**XP**）价值观之一（[`www.extremeprogramming.org/rules/simple.html`](http://www.extremeprogramming.org/rules/simple.html)），也是 TDD 和编程的关键。这通常是通过分成小单元来实现的。在 Java 中，单元是方法。作为最小的单元，它们提供的反馈循环是最快的，因此我们大部分时间都在思考和处理它们。作为实施方法的对应物，单元测试应该占所有测试的绝大部分比例。

# 什么是单元测试？

**单元测试**是一种实践，它迫使我们测试小的、独立的、孤立的代码单元。它们通常是方法，尽管在某些情况下，类甚至整个应用程序也可以被视为单元。为了编写单元测试，需要将测试代码与应用程序的其余部分隔离开来。最好是代码中已经融入了这种隔离，或者可以通过使用**模拟对象**来实现（有关模拟对象的更多内容将在第六章中介绍，*模拟-消除外部依赖*）。如果特定方法的单元测试跨越了该单元的边界，那么它们就变成了集成测试。这样一来，测试的范围就变得不那么清晰了。在出现故障的情况下，问题的范围突然增加，找到原因变得更加费力。

# 为什么进行单元测试？

一个常见的问题，特别是在严重依赖手动测试的组织中，是*为什么我们应该使用单元测试而不是功能和集成测试？*这个问题本身是有缺陷的。单元测试并不取代其他类型的测试。相反，单元测试减少了其他类型测试的范围。由于其性质，单元测试比任何其他类型的测试更容易和更快地编写，从而降低了成本和**上市时间**（**TTM**）。由于编写和运行它们的时间减少，它们往往更早地检测到问题。我们越快地检测到问题，修复问题的成本就越低。在创建后几分钟就被检测到的错误比在创建后几天、几周甚至几个月后被发现的错误要容易得多。

# 代码重构

**代码重构**是在不改变现有代码的外部行为的情况下改变现有代码结构的过程。重构的目的是改进现有的代码。这种改进可以出于许多不同的原因。我们可能希望使代码更易读，更简单，更易于维护，更廉价扩展等等。无论重构的原因是什么，最终目标总是以某种方式使其更好。这个目标的效果是减少技术债务；减少由于次优设计、架构或编码而需要完成的未决工作。

通常，我们通过应用一系列小的更改来进行重构，而不修改预期的行为。减少重构变化的范围允许我们持续确认这些变化没有破坏任何现有功能。有效获得这种确认的唯一方法是通过使用自动化测试。

单元测试的一个巨大好处是它们是最好的重构促进者。当没有自动化测试来确认应用程序仍然按预期行为时，重构就太冒险了。虽然任何类型的测试都可以用来提供重构所需的代码覆盖率，但在大多数情况下，只有单元测试可以提供所需的细节级别。

# 为什么不只使用单元测试？

此刻，你可能会想知道单元测试是否能够满足你所有的测试需求。不幸的是，情况并非如此。虽然单元测试通常涵盖了大部分的测试需求，但功能测试和集成测试应该是测试工具箱的一个重要部分。

我们将在后面的章节中更详细地介绍其他类型的测试。目前，它们之间的一些重要区别如下：

+   单元测试试图验证小的功能单元。在 Java 世界中，这些单元是方法。所有外部依赖，如调用其他类和方法或数据库调用，应该在内存中使用模拟、存根、间谍、伪造和虚拟对象来完成。Gerard Meszaros 创造了一个更一般的术语，**测试替身**，它包括了所有这些（[`en.wikipedia.org/wiki/Test_double`](http://en.wikipedia.org/wiki/Test_double)）。单元测试简单易写，运行速度快。它们通常是测试套件中最大的部分。

+   **功能**和**验收**测试的工作是验证我们正在构建的应用程序作为一个整体是否按预期工作。虽然这两者在目的上有所不同，但都有一个相似的目标。与验证代码的内部质量的单元测试不同，功能和验收测试试图确保系统从客户或用户的角度正确地工作。由于编写和运行这些测试所需的成本和工作量，这些测试通常比单元测试少。

+   **集成**测试旨在验证单独的单元、模块、应用程序，甚至整个系统是否正确地相互集成。你可能有一个使用后端 API 的前端应用程序，而这些 API 又与数据库进行通信。集成测试的工作就是验证系统的这三个独立组件确实是集成的，并且能够相互通信。由于我们已经知道所有的单元都在工作，所有功能和验收测试都通过了，集成测试通常是这三种测试中最小的，因为它们的工作只是确认所有的部件能够良好地协同工作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/a224c9c4-bee4-445c-9b8f-4c353dc040d6.png)

测试金字塔表明，你应该有比高级测试（UI 测试，集成测试等）更多的单元测试。为什么呢？单元测试的编写成本更低，运行速度更快，并且同时提供更大的覆盖范围。以注册功能为例。我们应该测试当用户名为空时会发生什么，当密码为空时会发生什么，当用户名或密码不符合正确格式时会发生什么，当用户已经存在时会发生什么，等等。仅针对这个单一功能，可能会有数十甚至数百个测试。从 UI 编写并运行所有这些测试可能非常昂贵（编写耗时且运行缓慢）。另一方面，对执行此验证的方法进行单元测试很容易，编写快速，运行迅速。如果所有这些情况都通过单元测试覆盖，我们可以满意地进行单一集成测试，检查我们的 UI 是否在后端调用了正确的方法。如果是的话，从集成的角度来看，细节是无关紧要的，因为我们知道所有情况已经在单元级别上得到了覆盖。

# 使用 TDD 的单元测试

在 TDD 的环境中，我们编写单元测试的方式有何不同？主要的区别在于*何时*。传统上，单元测试是在实现代码完成后编写的，而在 TDD 中，我们在此之前编写测试—事情的顺序被颠倒了。没有 TDD，单元测试的目的是验证现有代码。TDD 教导我们，单元测试应该驱动我们的开发和设计。它们应该定义最小可能单元的行为。它们是待开发的微需求。一个测试告诉你接下来该做什么，以及何时完成它。根据测试的类型（单元测试、功能测试、集成测试等），下一步应该做什么的范围不同。在使用 TDD 进行单元测试的情况下，这个范围是最小可能的，意味着一个方法或者更常见的是其中的一部分。此外，通过由单元测试驱动的 TDD，我们被迫遵守一些设计原则，比如**保持简单，愚蠢**（**KISS**）。通过编写简单的测试，范围很小，这些测试的实现也往往很简单。通过强制测试不使用外部依赖，我们迫使实现代码具有良好设计的关注点分离。TDD 如何帮助我们编写更好的代码还有许多其他例子。这些好处无法仅通过单元测试实现。没有 TDD，单元测试被迫使用现有代码，并且对设计没有影响。

总之，没有 TDD 的单元测试的主要目标是验证现有代码。使用 TDD 程序提前编写的单元测试的主要目标是规范和设计，验证只是一个附带产品。这个附带产品通常比在实现之后编写测试时的质量要高。

TDD 迫使我们深思熟虑我们的需求和设计，编写能够运行的干净代码，创建可执行的需求，并安全而频繁地进行重构。最重要的是，我们最终得到了高测试代码覆盖率，用于在引入变更时对我们的所有代码进行回归测试。没有 TDD 的单元测试只给我们测试，而且通常质量存疑。

# TestNG

JUnit 和 TestNG 是两个主要的 Java 测试框架。在上一章中，您已经使用 JUnit 编写了测试，*Red-Green-Refactor – 从失败到成功直至完美*，并且希望您对其工作原理有了很好的理解。那 TestNG 呢？它诞生于对 JUnit 进行改进的愿望。事实上，它包含了一些 JUnit 没有的功能。

以下小节总结了它们之间的一些区别。我们不仅会尝试解释这些区别，还会在 TDD 的单元测试环境中对它们进行评估。

# @Test 注释

JUnit 和 TestNG 都使用`@Test`注释来指定哪个方法被视为测试。与 JUnit 不同，后者要求每个方法都要有`@Test`注释，而 TestNG 允许我们在类级别上使用这个注释。当以这种方式使用时，除非另有规定，否则所有公共方法都被视为测试：

```java
@Test
public class DirectionSpec {
  public void whenGetFromShortNameNThenReturnDirectionN() {
    Direction direction = Direction.getFromShortName('N');
    assertEquals(direction, Direction.NORTH);
  }

  public void whenGetFromShortNameWThenReturnDirectionW() { 
    Direction direction = Direction.getFromShortName('W'); 
    assertEquals(direction, Direction.WEST); 
  } 
} 
```

在这个例子中，我们将`@Test`注释放在`DirectionSpec`类的上面。结果，`whenGetFromShortNameNThenReturnDirectionN`和`whenGetFromShortNameWThenReturnDirectionW`方法都被视为测试。

如果该代码是使用 JUnit 编写的，那么这两个方法都需要有`@Test`注释。

# @BeforeSuite，@BeforeTest，@BeforeGroups，@AfterGroups，@AfterTest 和@AfterSuite 注释

这六个注释在 JUnit 中没有对应的。TestNG 可以使用 XML 配置将测试分组为套件。使用`@BeforeSuite`和`@AfterSuite`注释的方法在指定套件中的所有测试运行之前和之后运行。类似地，使用`@BeforeTest`和`@AfterTest`注释的方法在测试类的任何测试方法运行之前运行。最后，TestNG 测试可以组织成组。`@BeforeGroups`和`@AfterGroups`注释允许我们在指定组中的第一个测试之前和最后一个测试之后运行方法。

虽然这些注释在编写实现代码后的测试时可能非常有用，但在 TDD 的上下文中并没有太多用处。与通常的测试不同，通常是计划并作为一个独立项目编写的，TDD 教导我们一次编写一个测试并保持一切简单。最重要的是，单元测试应该快速运行，因此没有必要将它们分组到套件或组中。当测试快速运行时，运行除了全部之外的任何内容都是浪费。例如，如果所有测试在 15 秒内运行完毕，就没有必要只运行其中的一部分。另一方面，当测试很慢时，通常是外部依赖没有被隔离的迹象。无论慢测试背后的原因是什么，解决方案都不是只运行其中的一部分，而是解决问题。

此外，功能和集成测试往往会更慢，并且需要我们进行某种分离。然而，最好是在`build.gradle`中将它们分开，以便每种类型的测试作为单独的任务运行。

# @BeforeClass 和@AfterClass 注释

这些注释在 JUnit 和 TestNG 中具有相同的功能。在当前类中的第一个测试之前和最后一个测试之后运行带注释的方法。唯一的区别是 TestNG 不要求这些方法是静态的。这背后的原因可以在这两个框架运行测试方法时采取的不同方法中找到。JUnit 将每个测试隔离到其自己的测试类实例中，迫使我们将这些方法定义为静态的，因此可以在所有测试运行中重复使用。另一方面，TestNG 在单个测试类实例的上下文中执行所有测试方法，消除了这些方法必须是静态的需要。

# @BeforeMethod 和@AfterMethod 注释

`@Before`和`@After`注释等同于 JUnit。带注释的方法在每个测试方法之前和之后运行。

# @Test(enable = false)注释参数

JUnit 和 TestNG 都可以禁用测试。虽然 JUnit 使用单独的`@Ignore`注释，但 TestNG 使用`@Test`注释的布尔参数`enable`。在功能上，两者的工作方式相同，区别只在于我们编写它们的方式。

# @Test(expectedExceptions = SomeClass.class)注释参数

这是 JUnit 占优势的情况。虽然两者都提供了相同的指定预期异常的方式（在 JUnit 的情况下，参数简单地称为`expected`），JUnit 引入了规则，这是一种更优雅的测试异常的方式（我们在第二章，*工具、框架和环境*中已经使用过它们）。

# TestNG 与 JUnit 的总结

这两个框架之间还有许多其他的区别。为了简洁起见，我们在本书中没有涵盖所有内容。请查阅它们的文档以获取更多信息。

关于 JUnit 和 TestNG 的更多信息可以在[`junit.org/`](http://junit.org/)和[`testng.org/`](http://testng.org/)找到。

TestNG 提供了比 JUnit 更多的功能和更先进的功能。我们将在本章节中使用 TestNG，并且你会更好地了解它。你会注意到的一件事是，我们不会使用任何那些高级功能。原因是，在使用 TDD 时，当进行单元测试时，我们很少需要它们。功能和集成测试是不同类型的，它们会更好地展示 TestNG 的优势。然而，有一些工具更适合这些类型的测试，你会在接下来的章节中看到。

你应该使用哪一个？这个选择留给你。当你完成本章时，你将对 JUnit 和 TestNG 有实际的了解。

# 远程控制船只的要求

我们将在一个名为**Mars Rover**的著名 kata 的变体上进行工作，最初发表在*达拉斯黑客俱乐部*（[`dallashackclub.com/rover`](http://dallashackclub.com/rover)）。

想象一艘海军舰船被放置在地球的某个海域。由于这是 21 世纪，我们可以远程控制那艘船。

我们的工作是创建一个可以在海上移动船只的程序。

由于这是一本 TDD 书籍，本章的主题是单元测试，我们将使用 TDD 方法开发一个应用程序，重点放在单元测试上。在上一章中，第三章，*红-绿-重构-从失败到成功直至完美*，你学习了理论并且有了红-绿-重构过程的实际经验。我们将在此基础上继续，并尝试学习如何有效地使用单元测试。具体来说，我们将尝试集中精力在我们正在开发的一个单元上，并学习如何隔离和忽略一个单元可能使用的依赖项。不仅如此，我们还将尝试集中精力解决一个需求。因此，你只被呈现了高层次的需求；我们应该能够移动位于地球某处的远程控制船只。

为了简化，所有支持类已经被创建和测试过。这将使我们能够集中精力处理手头的主要任务，并且同时保持这个练习简洁。

# 开发远程控制船只

让我们从导入现有的 Git 存储库开始。

# 项目设置

让我们开始设置项目：

1.  打开 IntelliJ IDEA。如果已经打开了现有项目，请选择文件|关闭项目。

1.  你将看到一个类似于以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/8b78ff11-66a4-4ad7-8a8e-bb57a01a0e65.png)

1.  要从 Git 存储库导入项目，请点击从版本控制检出，然后选择 Git。在 Git 存储库 URL 字段中输入`https://bitbucket.org/vfarcic/tdd-java-ch04-ship.git`，然后点击克隆：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/fdadac00-35ba-452f-af9b-18e0d3ea84d9.png)

1.  当被问及是否要打开项目时，请选择是。

接下来，你将看到导入 Gradle 对话框。点击确定：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/ed6a55a5-96b3-4dca-8d65-00ef75210725.png)

1.  IDEA 需要一些时间来下载`build.gradle`文件中指定的依赖项。一旦完成，你会看到一些类和相应的测试已经创建：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/75ac992a-edaf-42a6-a088-3dd628a59ce9.png)

# 辅助类

假设你的一个同事开始了这个项目的工作。他是一个优秀的程序员和 TDD 实践者，你相信他有良好的测试代码覆盖率。换句话说，你可以依赖他的工作。然而，这位同事在离开度假之前没有完成应用程序，现在轮到你继续他停下的地方。他创建了所有的辅助类：`Direction`、`Location`、`Planet`和`Point`。你会注意到相应的测试类也在那里。它们的名称与它们测试的类相同，都带有`Spec`后缀（即`DirectionSpec`）。使用这个后缀的原因是为了明确测试不仅用于验证代码，还用作可执行规范。

在辅助类的顶部，你会找到`Ship`（实现）和`ShipSpec`（规范/测试）类。我们将在这两个类中花费大部分时间。我们将在`ShipSpec`中编写测试，然后在`Ship`类中编写实现代码（就像以前一样）。

由于我们已经学到了测试不仅用作验证代码的方式，还可以作为可执行文档，从现在开始，我们将使用规范或规范代替测试。

每当我们完成编写规范或实现它的代码时，我们都会从命令提示符中运行`gradle test`，或者使用 Gradle 项目 IDEA 工具窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/f2f9ca0b-3bb2-4db0-a208-d913811f1e0a.png)

项目设置好后，我们就可以开始进行第一个需求了。

# 需求-起点和方向

我们需要知道船的当前位置，以便能够移动它。此外，我们还应该知道它面向的方向：北、南、东或西。因此，第一个需求如下：

你已经得到了船的初始起点（*x*，*y*）和它所面对的方向（*N*，*S*，*E*，或*W*）。

在我们开始处理这个需求之前，让我们先看看可以使用的辅助类。`Point`类保存了`x`和`y`坐标。它有以下构造函数：

```java
public Point(int x, int y) {
  this.x = x;
  this.y = y;
}
```

同样，我们有`Direction enum`类，其中包含以下值：

```java
public enum Direction {
  NORTH(0, 'N),
  EAST(1, 'E'),
  SOUTH(2, 'S'),
  WEST(3, 'W'), 
  NONE(4, 'X');
}
```

最后，有一个`Location`类，需要将这两个类作为构造函数参数传递：

```java
public Location(Point point, Direction direction) {
  this.point = point;
  this.direction = direction;
}
```

知道这一点，应该很容易为这个第一个需求编写测试。我们应该以与上一章相同的方式工作，第三章，*红-绿-重构-从失败到成功直至完美*。

尝试自己编写规范。完成后，将其与本书中的解决方案进行比较。然后用实现规范的代码进行相同的过程。尝试自己编写，完成后再与我们提出的解决方案进行比较。

# 规范-保持位置和方向在内存中

这个需求的规范可以是以下内容：

```java
@Test
public class ShipSpec {
  public void whenInstantiatedThenLocationIsSet() {
    Location location = new Location(new Point(21, 13), Direction.NORTH);
    Ship ship = new Ship(location);
    assertEquals(ship.getLocation(), location);
  } 
} 
```

这很容易。我们只是检查我们作为`Ship`构造函数传递的`Location`对象是否被存储，并且可以通过`location` getter 进行访问。

`@Test`注解-当 TestNG 在类级别上设置了`@Test`注解时，不需要指定哪些方法应该用作测试。在这种情况下，所有公共方法都被认为是 TestNG 测试。

# 实现

这个规范的实现应该相当容易。我们所需要做的就是将构造函数参数设置为`location`变量：

```java
public class Ship {
  private final Location location;

  public Ship(Location location) {
    this.location = location; 
  }

  public Location getLocation() {
    return location;
  } 
}
```

完整的源代码可以在`tdd-java-ch04-ship`存储库的`req01-location`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req01-location`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req01-location)）。

# 重构

我们知道我们需要为每个规范实例化`Ship`，所以我们可以通过添加`@BeforeMethod`注解来重构规范类。代码可以如下：

```java
@Test
public class ShipSpec {

  private Ship ship;
  private Location location;

  @BeforeMethod
  public void beforeTest() {
    Location location = new Location(new Point(21, 13), Direction.NORTH);
    ship = new Ship(location);
  } 

  public void whenInstantiatedThenLocationIsSet() { 
    // Location location = new Location(new Point(21, 13), Direction.NORTH); 
    // Ship ship = new Ship(location); 
    assertEquals(ship.getLocation(), location); 
    } 
} 
```

没有引入新的行为。我们只是将代码的一部分移动到`@BeforeMethod`注解中，以避免重复，这将由我们即将编写的其余规范产生。现在，每次运行测试时，`ship`对象将以`location`作为参数实例化。

# 要求-向前和向后移动

现在我们知道了我们的飞船在哪里，让我们试着移动它。首先，我们应该能够向前和向后移动。

实现将飞船向前和向后移动的命令（*f*和*b*）。

“位置”辅助类已经有了实现这一功能的“向前”和“向后”方法：

```java
public boolean forward() {
  ...
}
```

# 规范-向前移动

例如，当我们面向北方并向前移动飞船时，它在*y*轴上的位置应该减少。另一个例子是，当飞船面向东方时，它应该将*x*轴位置增加 1。

第一个反应可能是编写类似以下两个规范：

```java
public void givenNorthWhenMoveForwardThenYDecreases() {
  ship.moveForward();
  assertEquals(ship.getLocation().getPoint().getY(), 12);
}

public void givenEastWhenMoveForwardThenXIncreases() {
  ship.getLocation().setDirection(Direction.EAST);
  ship.moveForward();
  assertEquals(ship.getLocation().getPoint().getX(), 22);
}
```

我们应该创建至少另外两个与飞船面向南方和西方的情况相关的规范。

然而，这不是编写单元测试的方式。大多数刚开始进行单元测试的人会陷入指定需要了解方法、类和库的内部工作知识的最终结果的陷阱。这种方法在许多层面上都存在问题。

在将外部代码包含在被指定的单元中时，我们应该考虑到，至少在我们的情况下，外部代码已经经过测试。我们知道它是有效的，因为我们每次对代码进行更改时都会运行所有测试。

每次实现代码更改时重新运行所有测试。

这确保了代码更改不会引起意外的副作用。

每当实现代码的任何部分发生更改时，都应该运行所有测试。理想情况下，测试执行速度快，可以由开发人员在本地运行。一旦代码提交到版本控制，应该再次运行所有测试，以确保由于代码合并而出现问题。当有多个开发人员在代码上工作时，这一点尤为重要。CI 工具，如 Jenkins、Hudson、Travind、Bamboo 和 Go-CD，应该用于从存储库中拉取代码、编译代码并运行测试。

这种方法的另一个问题是，如果外部代码发生更改，将有更多的规范需要更改。理想情况下，我们应该只被迫更改与将要修改的单元直接相关的规范。搜索所有其他调用该单元的地方可能非常耗时且容易出错。

为此要求编写规范的另一个更简单、更快、更好的方法是：

```java
public void whenMoveForwardThenForward() {
  Location expected = location.copy();
  expected.forward();
  ship.moveForward();
  assertEquals(ship.getLocation(), expected);
}
```

由于“位置”已经有“向前”方法，我们只需要确保执行该方法的适当调用。我们创建了一个名为`expected`的新“位置”对象，调用了“向前”方法，并将该对象与飞船在调用其`moveForward`方法后的位置进行了比较。

请注意，规范不仅用于验证代码，而且还用作可执行文档，更重要的是，作为一种思考和设计的方式。这第二次尝试更清楚地指定了其背后的意图。我们应该在`Ship`类内创建一个`moveForward`方法，并确保调用`location.forward`。

# 实施

有了这样一个小而明确定义的规范，编写实现它的代码应该相当容易：

```java
public boolean moveForward() { 
  return location.forward(); 
} 
```

# 规范-向后移动

现在我们已经指定并实现了向前移动，向后移动应该几乎相同：

```java
public void whenMoveBackwardThenBackward() {
  Location expected = location.copy();
  expected.backward();
  ship.moveBackward();
  assertEquals(ship.getLocation(), expected);
}
```

# 实施

与规范一样，向后移动的实现同样简单：

```java
public boolean moveBackward() {
  return location.backward();
}
```

此要求的完整源代码可以在`tdd-java-ch04-ship`存储库的`req02-forward-backward`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req02-forward-backward`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req02-forward-backward)）。

# 要求 - 旋转船只

只是前后移动船只不会让我们走得太远。我们应该能够通过将船只向左或向右旋转来改变方向。

实现转向左和右的命令（*l*和*r*）。

在实现了前面的要求之后，这个要求应该很容易，因为它可以遵循相同的逻辑。`Location`辅助类已经包含了执行这个要求所需的`turnLeft`和`turnRight`方法。我们需要做的就是将它们整合到`Ship`类中。

# 规范 - 向左转

使用迄今为止我们所使用的相同指导方针，向左转的规范可以是以下内容：

```java
public void whenTurnLeftThenLeft() {
  Location expected = location.copy();
  expected.turnLeft();
  ship.turnLeft();
  assertEquals(ship.getLocation(), expected);
}
```

# 实施

你可能没有问题编写代码来通过先前的规范：

```java
public void turnLeft() {
  location.turnLeft();
}
```

# 规范 - 向右转

向右转应该几乎与向左转相同：

```java
public void whenTurnRightThenRight() {
  Location expected = location.copy();
  expected.turnRight();
  ship.turnRight();
  assertEquals(ship.getLocation(), expected);
}
```

# 实施

最后，让我们通过实现向右转的规范来完成这个要求：

```java
public void turnRight() {
  location.turnRight();
}
```

此要求的完整源代码可以在`tdd-java-ch04-ship`存储库的`req03-left-right`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req03-left-right`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req03-left-right)）。

# 要求 - 命令

到目前为止，我们所做的一切都相当容易，因为有提供所有功能的辅助类。这个练习是为了学习如何停止尝试测试最终结果，而是专注于我们正在处理的一个单元。我们正在建立信任；我们必须相信其他人编写的代码（辅助类）。

从这个要求开始，你将不得不相信你自己写的代码。我们将以同样的方式继续。我们将编写规范，运行测试，看到它们失败；我们将编写实现，运行测试，看到它们成功；最后，如果我们认为代码可以改进，我们将进行重构。继续思考如何测试一个单元（方法）而不深入到单元将要调用的方法或类中。

现在我们已经实现了单独的命令（向前、向后、向左和向右），是时候把它们全部联系起来了。我们应该创建一个方法，允许我们将任意数量的命令作为单个字符串传递。每个命令都应该是一个字符，*f*表示向前，*b*表示向后，*l*表示向左，*r*表示向右。

船只可以接收一个包含命令的字符串（`lrfb`，它们分别等同于左、右、向前和向后）。

# 规范 - 单个命令

让我们从只有`f`（向前）字符的命令参数开始：

```java
public void whenReceiveCommandsFThenForward() {
  Location expected = location.copy();
  expected.forward();
  ship.receiveCommands("f");
  assertEquals(ship.getLocation(), expected);
}
```

这个规范几乎与`whenMoveForwardThenForward`规范相同，只是这一次，我们调用了`ship.receiveCommands("f")`方法。

# 实施

我们已经谈到了编写尽可能简单的代码以通过规范的重要性。

编写最简单的代码来通过测试。这确保了更清洁和更清晰的设计，并避免了不必要的功能。

这个想法是，实现越简单，产品就越好、维护就越容易。这个想法符合 KISS 原则。它指出，大多数系统如果保持简单而不是复杂，就能发挥最佳作用；因此，在设计中，简单性应该是一个关键目标，不必要的复杂性应该被避免。

这是一个应用这一规则的好机会。你可能倾向于编写类似以下的代码：

```java
public void receiveCommands(String commands) {
  if (commands.charAt(0) == 'f') {
    moveForward();
  }
}
```

在这个示例代码中，我们正在验证第一个字符是否为`f`，如果是的话，就调用`moveForward`方法。我们还可以做很多其他变化。然而，如果我们坚持简单原则，一个更好的解决方案是以下内容：

```java
public void receiveCommands(String command) {
  moveForward();
}
```

这是最简单和最短的可能使规范通过的代码。以后，我们可能会得到与代码的第一个版本更接近的东西；当事情变得更加复杂时，我们可能会使用某种循环或想出其他解决方案。就目前而言，我们只专注于一次规范，并试图使事情简单化。我们试图通过只专注于手头的任务来清空我们的头脑。

为了简洁起见，其余组合（`b`，`l`和`r`）在这里没有呈现（继续自己实现它们）。相反，我们将跳到此需求的最后一个规范。

# 规范-组合命令

现在我们能够处理一个命令（无论命令是什么），是时候添加发送一系列命令的选项了。规范可以是以下内容：

```java
public void whenReceiveCommandsThenAllAreExecuted() {
  Location expected = location.copy();
  expected.turnRight();
  expected.forward();
  expected.turnLeft();
  expected.backward();
  ship.receiveCommands("rflb");
  assertEquals(ship.getLocation(), expected);
}
```

这有点长，但仍然不是一个过于复杂的规范。我们传递命令`rflb`（右，前进，左，后退），并期望`Location`相应地改变。与以前一样，我们不验证最终结果（看坐标是否已更改），而是检查我们是否调用了正确的辅助方法。

# 实施

最终结果可能是以下内容：

```java
public void receiveCommands(String commands) {
  for (char command : commands.toCharArray()) {
    switch(command) {
      case 'f':
        moveForward();
        break;
      case 'b':
        moveBackward();
        break;
      case 'l':
        turnLeft();
        break;
      case 'r':
        turnRight();
        break;
    }
  }
}
```

如果您尝试自己编写规范和实施，并且遵循简单规则，您可能不得不多次重构代码才能得到最终解决方案。简单是关键，重构通常是一个受欢迎的必要性。重构时，请记住所有规范必须始终通过。

只有在所有测试都通过之后才进行重构。

好处：重构是安全的。

如果所有可能受到影响的实施代码都经过测试，并且它们都通过了，那么重构是相对安全的。在大多数情况下，不需要新的测试；对现有测试的小修改应该足够了。重构的预期结果是在修改代码之前和之后都使所有测试通过。

这个需求的完整源代码可以在`tdd-java-ch04-ship`存储库的`req04-commands`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req04-commands`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req04-commands)）。

# 需求-表示球形地图

地球是一个球体，就像任何其他行星一样。当地球被呈现为地图时，到达一个边缘会将我们包装到另一个边缘；例如，当我们向东移动并到达太平洋的最远点时，我们被包装到地图的西侧，然后继续向美洲移动。此外，为了使移动更容易，我们可以将地图定义为一个网格。该网格的长度和高度应该表示为*x*轴和*y*轴。该网格应该具有最大长度（x）和高度（y）。

实现从网格的一边包装到另一边。

# 规范-行星信息

我们可以做的第一件事是将最大`X`和`Y`轴坐标的`Planet`对象传递给`Ship`构造函数。幸运的是，`Planet`是另一个已经制作（并测试过）的辅助类。我们需要做的就是实例化它并将其传递给`Ship`构造函数：

```java
public void whenInstantiatedThenPlanetIsStored() {
  Point max = new Point(50, 50);
  Planet planet = new Planet(max);
  ship = new Ship(location, planet);
  assertEquals(ship.getPlanet(), planet);
}
```

我们将行星的大小定义为 50 x 50，并将其传递给`Planet`类。然后，该类随后传递给`Ship`构造函数。您可能已经注意到构造函数需要一个额外的参数。在当前代码中，我们的构造函数只需要`location`。为了实现这个规范，它应该接受`planet`。

您如何在不违反任何现有规范的情况下实施此规范？

# 实施

让我们采取自下而上的方法。一个`assert`要求我们有一个`planet`的 getter：

```java
private Planet planet;
public Planet getPlanet() {
  return planet;
}
```

接下来，构造函数应该接受`Planet`作为第二个参数，并将其分配给先前添加的`planet`变量。第一次尝试可能是将其添加到现有的构造函数中，但这将破坏许多使用单参数构造函数的现有规范。这让我们只有一个选择 - 第二个构造函数：

```java
public Ship(Location location) {
  this.location = location;
}
public Ship(Location location, Planet planet) {
  this.location = location;
  this.planet = planet;
}
```

运行所有的规范，并确认它们都成功。

# 重构

我们的规范迫使我们创建第二个构造函数，因为改变原始构造函数会破坏现有的测试。然而，现在一切都是绿色的，我们可以进行一些重构，并摆脱单参数构造函数。规范类已经有了`beforeTest`方法，它在每个测试之前运行。我们可以将除了`assert`本身之外的所有内容都移到这个方法中：

```java
public class ShipSpec {
...
  private Planet planet;

  @BeforeMethod
  public void beforeTest() {
    Point max = new Point(50, 50);
    location = new Location(new Point(21, 13), Direction.NORTH);
    planet = new Planet(max);
    // ship = new Ship(location);
    ship = new Ship(location, planet);
  }

  public void whenInstantiatedThenPlanetIsStored() {
    // Point max = new Point(50, 50);
    // Planet planet = new Planet(max);
    // ship = new Ship(location, planet);
    assertEquals(ship.getPlanet(), planet);
  }
}
```

通过这个改变，我们有效地移除了`Ship`的单参数构造函数的使用。通过运行所有的规范，我们应该确认这个改变是有效的。

现在，由于不再使用单参数构造函数，我们可以将其从实现类中删除：

```java
public class Ship {
...
  // public Ship(Location location) {
  //   this.location = location;
  // }
  public Ship(Location location, Planet planet) {
    this.location = location;
    this.planet = planet;
  }
...
}
```

通过使用这种方法，所有的规范一直都是绿色的。重构没有改变任何现有功能，没有出现任何问题，整个过程进行得很快。

现在，让我们进入包装本身。

# 规范 - 处理地图边界

和其他情况一样，辅助类已经提供了我们需要的所有功能。到目前为止，我们使用了没有参数的`location.forward`方法。为了实现包装，有重载的`location.forward(Point max)`方法，当我们到达网格的末端时会包装位置。通过之前的规范，我们确保`Planet`被传递给`Ship`类，并且它包含`Point max`。我们的工作是确保在向前移动时使用`max`。规范可以是以下内容：

```java
public void whenOverpassingEastBoundaryThenPositionIsReset() {
  location.setDirection(Direction.EAST);
  location.getPoint().setX(planet.getMax().getX());
  ship.receiveCommands("f");
  assertEquals(location.getX(), 1);
}
```

# 实现

到目前为止，你应该已经习惯了一次只关注一个单位，并相信之前完成的工作都按预期工作。这个实现应该也不例外。我们只需要确保在调用`location.forward`方法时使用最大坐标：

```java
public boolean moveForward() {
  // return location.forward();
  return location.forward(planet.getMax());
}
```

对于`backward`方法，应该做相同的规范和实现。出于简洁起见，它被排除在本书之外，但可以在源代码中找到。

这个需求的完整源代码可以在`tdd-java-ch04-ship`仓库的`req05-wrap`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req05-wrap`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req05-wrap)）。

# 需求 - 检测障碍物

我们几乎完成了。这是最后一个需求。

尽管地球大部分被水覆盖（约 70%），但也有大陆和岛屿可以被视为我们远程控制船只的障碍物。我们应该有一种方法来检测下一步移动是否会碰到这些障碍物。如果发生这种情况，移动应该被中止，船只应该停留在当前位置并报告障碍物。

在每次移动到新位置之前实现表面检测。如果命令遇到表面，船只将中止移动，停留在当前位置，并报告障碍物。

这个需求的规范和实现与我们之前做的非常相似，我们将留给你来完成。

以下是一些可能有用的提示：

+   `Planet`对象有一个接受障碍物列表的构造函数。

每个障碍物都是`Point`类的一个实例。

+   `location.foward`和`location.backward`方法有重载版本，接受障碍物列表。如果移动成功则返回`true`，失败则返回`false`。使用这个布尔值来构建`Ship.receiveCommands`方法所需的状态报告。

+   `receiveCommands` 方法应返回一个包含每个命令状态的字符串。`0` 可以表示 OK，`X` 可以表示移动失败（`00X0` = OK, OK, 失败, OK）。

此要求的完整源代码可以在 `tdd-java-ch04-ship` 仓库的 `req06-obstacles` 分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req06-obstacles`](https://bitbucket.org/vfarcic/tdd-java-ch04-ship/branch/req06-obstacles)）。

# 摘要

在本章中，我们选择了 TestNG 作为我们的测试框架。与 JUnit 相比，没有太大的区别，因为我们没有使用 TestNG 的更高级功能（例如数据提供者、工厂等）。在 TDD 中，我们是否真的需要这些功能是值得怀疑的。

访问 [`testng.org/`](http://testng.org/)，探索它，并自行决定哪个框架最适合您的需求。

本章的主要目标是学习如何一次只专注于一个单元。我们已经有了许多辅助类，并且我们尽力忽略它们的内部工作。在许多情况下，我们并没有编写验证最终结果是否正确的规范，但我们检查了我们正在处理的方法是否调用了这些辅助类的正确方法。在现实世界中，您将与其他团队成员一起工作在项目上，学会专注于自己的任务并相信其他人的工作符合预期是很重要的。对于第三方库也是一样的。测试所有内部过程的成本太高了。有其他类型的测试将尝试覆盖这些可能性。在进行单元测试时，焦点应该只放在我们当前正在处理的单元上。

现在您对如何在 TDD 的上下文中有效使用单元测试有了更好的理解，是时候深入了解 TDD 提供的其他优势了。具体来说，我们将探讨如何更好地设计我们的应用程序。


# 第五章：设计-如果不能进行测试，那就不是设计良好

“简单是终极的复杂。”

- 列奥纳多·达·芬奇

过去，软件行业专注于以高速开发软件，只考虑成本和时间。质量是次要目标，人们错误地认为客户对此不感兴趣。

如今，随着各种平台和设备的连接性不断增加，质量已成为客户需求中的一等公民。良好的应用程序在合理的响应时间内提供良好的服务，而不会受到许多用户的大量并发请求的影响。

在质量方面，良好的应用程序是那些经过良好设计的。良好的设计意味着可扩展性、安全性、可维护性和许多其他期望的属性。

在本章中，我们将探讨 TDD 如何通过使用传统和 TDD 方法来实现相同的应用程序，从而引导开发人员走向良好的设计和最佳实践。

本章将涵盖以下主题：

+   我们为什么要关心设计？

+   设计考虑和原则

+   传统的开发过程

+   使用 Hamcrest 的 TDD 方法

# 我们为什么要关心设计？

在软件开发中，无论您是专家还是初学者，都会遇到一些代码看起来不自然的情况。在阅读时，您无法避免感觉到代码有问题。有时，您甚至会想知道为什么以前的程序员以这种扭曲的方式实现了特定的方法或类。这是因为相同的功能可以以大量不同的方式实现，每种方式都是独一无二的。在如此多的可能性中，哪一个是最好的？什么定义了一个好的解决方案？为什么一个比其他的更好？事实是，只要达到目标，所有这些都是有效的。然而，选择正确解决方案时应考虑一些方面。这就是解决方案的设计变得相关的地方。

# 设计原则

**软件设计原则**是软件开发人员的指导原则，推动他们朝着智能和可维护的解决方案前进。换句话说，设计原则是代码必须满足的条件，以便被认为是客观良好设计的。

大多数资深开发人员和经验丰富的程序员都了解软件设计原则，很可能无论他们是否实践 TDD，他们都在日常工作中应用这些原则。TDD 哲学鼓励程序员-甚至是初学者-遵循一些原则和良好实践，使代码更清晰、更可读。这些实践是由红-绿-重构周期强制执行的。

红-绿-重构周期倡导通过一次引入一个失败的测试来实现小的功能增量。程序员添加尽可能简洁和短小的代码片段，以便新的测试或旧的测试都不再失败。最终，他们重构代码，包括清理和改进任务，如去除重复或优化代码。

作为过程的结果，代码变得更容易理解，并且在将来修改时更安全。让我们来看一些最流行的软件设计原则。

# 你不会需要它

**YAGNI**是**You Ain't Gonna Need It**原则的缩写。它旨在消除所有不必要的代码，专注于当前的功能，而不是未来的功能。您的代码越少，您需要维护的代码就越少，引入错误的可能性就越低。

有关 YAGNI 的更多信息，请访问 Martin Fowler 的文章，网址为[`martinfowler.com/bliki/Yagni.html`](http://martinfowler.com/bliki/Yagni.html)。

# 不要重复自己

**不要重复自己**（DRY）原则的理念是重用之前编写的代码，而不是重复它。好处是减少需要维护的代码，使用已知可行的代码，这是一件好事。它可以帮助你发现代码中的新抽象层级。

欲了解更多信息，请访问[`en.wikipedia.org/wiki/Don%27t_repeat_yourself`](http://en.wikipedia.org/wiki/Don%27t_repeat_yourself)。

# 保持简单，愚蠢

这个原则有一个令人困惑的缩写**保持简单，愚蠢**（KISS），并且陈述了事物如果保持简单而不是复杂，它们会更好地发挥功能。这是由凯利·约翰逊创造的。

要了解这个原则背后的故事，请访问[`en.wikipedia.org/wiki/KISS_principle`](http://en.wikipedia.org/wiki/KISS_principle)。

# 奥卡姆剃刀

尽管**奥卡姆剃刀**是一个哲学原则，而不是软件工程原则，但它仍然适用于我们的工作。它与前一个原则非常相似，主要陈述如下：

“当你有两种竞争解决同一个问题的方案时，简单的那个更好。”

– 奥卡姆的威廉

欲了解更多奥卡姆剃刀原理，请访问[`en.wikipedia.org/wiki/Occam%27s_razor`](http://en.wikipedia.org/wiki/Occam%27s_razor)。

# SOLID 原则

**SOLID**这个词是罗伯特·C·马丁为面向对象编程的五个基本原则创造的缩写。通过遵循这五个原则，开发人员更有可能创建一个出色、耐用和易于维护的应用程序：

+   **单一职责原则**：一个类应该只有一个改变的原因。

+   **开闭原则**：一个类应该对扩展开放，对修改关闭。这被归因于贝尔特兰·梅耶。

+   **里氏替换原则**：这是由芭芭拉·里斯科夫创建的，她说*一个类应该可以被扩展该类的其他类替换*。

+   **接口隔离原则**：几个特定的接口比一个通用接口更可取。

+   **依赖反转原则**：一个类应该依赖于抽象而不是实现。这意味着类的依赖必须专注于做什么，而忘记了如何做。

欲了解更多关于 SOLID 或其他相关原则的信息，请访问[`butunclebob.com/ArticleS.UncleBob.PrinciplesOfOod`](http://butunclebob.com/ArticleS.UncleBob.PrinciplesOfOod)。

前四个原则是 TDD 思想的核心部分，因为它们旨在简化我们编写的代码。最后一个原则侧重于应用程序组装过程中的类构建和依赖关系。

所有这些原则在测试驱动开发和非测试驱动开发中都是适用且可取的，因为除了其他好处外，它们使我们的代码更易于维护。它们的正确实际应用值得一整本书来讨论。虽然我们没有时间深入研究，但我们鼓励你进一步调查。

在本章中，我们将看到 TDD 如何使开发人员轻松地将这些原则付诸实践。我们将使用 TDD 和非 TDD 方法实现一个小型但完全功能的四子连线游戏版本。请注意，重复的部分，如 Gradle 项目创建等，被省略了，因为它们不被认为与本章的目的相关。

# 四子连线

四子连线是一款受欢迎、易于玩的棋盘游戏。规则有限且简单。

四子连线是一款双人对战的连接游戏，玩家首先选择一种颜色，然后轮流将有颜色的圆盘从顶部放入一个七列六行的垂直悬挂网格中。棋子直接下落，占据列中的下一个可用空间。游戏的目标是在对手连接四个自己颜色的圆盘之前，垂直、水平或对角线连接四个相同颜色的圆盘。

有关游戏的更多信息，请访问维基百科（[`en.wikipedia.org/wiki/Connect_Four`](http://en.wikipedia.org/wiki/Connect_Four)）。

# 要求

为了编写 Connect 4 的两种实现，游戏规则被转录为以下需求的形式。这些需求是两种开发的起点。我们将通过一些解释来查看代码，并在最后比较两种实现：

1.  棋盘由七列和六行组成；所有位置都是空的。

1.  玩家在列的顶部放入圆盘。如果列为空，则放入的圆盘会下落到棋盘上。将来在同一列中放入的圆盘将堆叠在之前的圆盘上。

1.  这是一个双人游戏，所以每个玩家都有一个颜色。一个玩家使用红色（*R*），另一个使用绿色（*G*）。玩家轮流进行，每次插入一个圆盘。

1.  我们希望在游戏中发生事件或错误时得到反馈。输出显示每次移动后棋盘的状态。

1.  当不能再插入圆盘时，游戏结束，被视为平局。

1.  如果玩家插入一个圆盘并连接了三个以上的同色圆盘，那么该玩家就赢了。

1.  在水平线方向上也是一样的。

1.  在对角线方向上也是一样的。

# Connect 4 的测试后实现

这是传统的方法，侧重于解决问题的代码，而不是测试。一些人和公司忘记了自动化测试的价值，并依赖于用户所谓的**用户验收测试**。

这种用户验收测试包括在一个受控环境中重新创建真实世界的场景，理想情况下与生产环境完全相同。一些用户执行许多不同的任务来验证应用程序的正确性。如果这些操作中的任何一个失败，那么代码就不会被接受，因为它破坏了某些功能或者不符合预期的工作。

此外，许多这些公司还使用单元测试作为进行早期回归检查的一种方式。这些单元测试是在开发过程之后创建的，并试图尽可能多地覆盖代码。最后，执行代码覆盖率分析以获得这些单元测试实际覆盖的内容。这些公司遵循一个简单的经验法则：代码覆盖率越高，交付的质量就越好。

这种方法的主要问题是事后编写测试只能证明代码的行为方式是按照程序编写的方式，这未必是代码预期行为的方式。此外，专注于代码覆盖率会导致糟糕的测试，将我们的生产代码变成不可变的实体。我们可能想要添加的每个修改都可能导致代码中不相关部分的多个测试失败。这意味着引入更改的成本变得非常高，进行任何轻微的修改可能会变成一场噩梦，非常昂贵。

为了演示前面描述的一些要点，让我们使用 TDD 和非 TDD 方法来实现 Connect 4 游戏。随着我们进一步进行，每个确定需求的相关代码将被呈现出来。这些代码并非是逐步编写的，因此一些代码片段可能包含一些与所提到的需求无关的代码行。

# 需求 1 - 游戏的棋盘

让我们从第一个需求开始。

棋盘由七个水平和六个垂直的空位置组成。

这个需求的实现非常直接。我们只需要表示一个空位置和保存游戏的数据结构。请注意，玩家使用的颜色也已经定义：

```java
public class Connect4 {
  public enum Color {
    RED('R'), GREEN('G'), EMPTY(' ');

    private final char value;

    Color(char value) { this.value = value; }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
  }

  public static final int COLUMNS = 7;

  public static final int ROWS = 6;

  private Color[][] board = new Color[COLUMNS][ROWS];

  public Connect4() {
    for (Color[] column : board) {
      Arrays.fill(column, Color.EMPTY);
    }
  }
}
```

# 需求 2 - 插入圆盘

这个需求介绍了游戏的一部分逻辑。

玩家在列的顶部放入圆盘。如果列为空，则放入的圆盘会下落到棋盘上。将来在同一列中放入的圆盘将堆叠在之前的圆盘上。

在这一部分，棋盘边界变得相关。我们需要标记哪些位置已经被占据，使用`Color.RED`来指示它们。最后，创建了第一个`private`方法。这是一个帮助方法，用于计算在给定列中插入的圆盘数量：

```java
public void putDisc(int column) {
  if (column > 0 && column <= COLUMNS) {
    int numOfDiscs = getNumberOfDiscsInColumn(column - 1);
    if (numOfDiscs < ROWS) {
      board[column - 1][numOfDiscs] = Color.RED;
    }
  }
}

private int getNumberOfDiscsInColumn(int column) {
  if (column >= 0 && column < COLUMNS) {
    int row;
    for (row = 0; row < ROWS; row++) {
      if (Color.EMPTY == board[column][row]) {
        return row;
      }
    }
    return row;
  }
  return -1;
}
```

# 要求 3 - 玩家轮换

这个要求引入了更多的游戏逻辑。

这是一个双人游戏，所以每个玩家有一种颜色。一个玩家使用红色（*R*），另一个使用绿色（*G*）。玩家轮流进行，每次插入一个圆盘。

我们需要保存当前玩家以确定哪个玩家在进行这一轮。我们还需要一个函数来切换玩家以重新创建轮换的逻辑。在`putDisc`函数中，一些代码变得相关。具体来说，使用当前玩家进行棋盘位置分配，并且按照游戏规则在每次移动后进行切换：

```java
...
private Color currentPlayer = Color.RED;

private void switchPlayer() {
  if (Color.RED == currentPlayer) {
    currentPlayer = Color.GREEN;
  } else {
    currentPlayer = Color.RED;
  }
}

public void putDisc(int column) {
  if (column > 0 && column <= COLUMNS) {
    int numOfDiscs = getNumberOfDiscsInColumn(column - 1);
    if (numOfDiscs < ROWS) {
      board[column - 1][numOfDiscs] = currentPlayer;
      switchPlayer();
    }
  }
}
...
```

# 要求 4 - 游戏的输出

应该添加一些输出，让玩家知道游戏的当前状态。

我们希望在游戏中发生事件或错误时得到反馈。输出显示每次移动后棋盘的状态。

没有指定输出通道。为了更容易，我们决定使用系统标准输出来在事件发生时打印事件。在每个动作上添加了几行代码，以便让用户了解游戏的状态：

```java
... 
private static final String DELIMITER = "|";

private void switchPlayer() {
  if (Color.RED == currentPlayer) {
    currentPlayer = Color.GREEN;
  } else {
    currentPlayer = Color.RED;
  }
  System.out.println("Current turn: " + currentPlayer);
}

public void printBoard() {
  for (int row = ROWS - 1; row >= 0; --row) {
    StringJoiner stringJoiner =
      new StringJoiner(DELIMITER, DELIMITER, DELIMITER);
    for (int col = 0; col < COLUMNS; ++col) {
      stringJoiner.add(board[col][row].toString());
    }
    System.out.println(stringJoiner.toString());
  }
}

public void putDisc(int column) {
  if (column > 0 && column <= COLUMNS) {
    int numOfDiscs = getNumberOfDiscsInColumn(column - 1); 
    if (numOfDiscs < ROWS) { 
      board[column - 1][numOfDiscs] = currentPlayer; 
      printBoard();
      switchPlayer();
    } else {
      System.out.println(numOfDiscs); 
      System.out.println("There's no room " + 
        "for a new disc in this column"); 
      printBoard(); 
    } 
  } else { 
    System.out.println("Column out of bounds"); 
    printBoard(); 
  } 
}
... 
```

# 要求 5 - 胜利条件（I）

第一局游戏有一个结束条件。

当不能再插入圆盘时，游戏结束并被视为平局。

以下代码显示了可能的一种实现：

```java
...
public boolean isFinished() {
  int numOfDiscs = 0;
  for (int col = 0; col < COLUMNS; ++col) {
    numOfDiscs += getNumberOfDiscsInColumn(col);
  }
  if (numOfDiscs >= COLUMNS * ROWS) {
    System.out.println("It's a draw");
    return true;
  }
  return false;
}
...
```

# 要求 6 - 胜利条件（II）

第一个胜利条件。

如果一个玩家插入一个圆盘并连接了三个以上的同色圆盘，那么该玩家获胜。

`checkWinCondition`私有方法通过扫描最后一步是否是获胜来实现这一规则：

```java
... 
private Color winner;

public static final int DISCS_FOR_WIN = 4;

public void putDisc(int column) {
  ...
  if (numOfDiscs < ROWS) {
    board[column - 1][numOfDiscs] = currentPlayer;
    printBoard();
    checkWinCondition(column - 1, numOfDiscs);
    switchPlayer();
    ...
}

private void checkWinCondition(int col, int row) {
  Pattern winPattern = Pattern.compile(".*" +
    currentPlayer + "{" + DISCS_FOR_WIN + "}.*");

  // Vertical check
  StringJoiner stringJoiner = new StringJoiner("");
  for (int auxRow = 0; auxRow < ROWS; ++auxRow) {
    stringJoiner.add(board[col][auxRow].toString());
  }
  if (winPattern.matcher(stringJoiner.toString()).matches()) {
    winner = currentPlayer;
    System.out.println(currentPlayer + " wins");
  }
}

public boolean isFinished() {
  if (winner != null) return true;
  ...
}
...
```

# 要求 7 - 胜利条件（III）

这是相同的胜利条件，但是在不同的方向上。

如果一个玩家插入一个圆盘并连接了三个以上的同色圆盘，那么该玩家获胜。

实现这一规则的几行代码如下：

```java
...
private void checkWinCondition(int col, int row) {
  ...
  // Horizontal check
  stringJoiner = new StringJoiner("");
  for (int column = 0; column < COLUMNS; ++column) {
    stringJoiner.add(board[column][row].toString());
  }
  if (winPattern.matcher(stringJoiner.toString()).matches()) { 
    winner = currentPlayer;
    System.out.println(currentPlayer + " wins");
    return;
  }
  ...
}
...
```

# 要求 8 - 胜利条件（IV）

最后一个要求是最后的胜利条件。这与前两个非常相似；在这种情况下，是在对角线方向上。

如果一个玩家插入一个圆盘并连接了三个以上的同色圆盘，那么该玩家获胜。

这是对最后一个要求的一个可能的实现。这段代码与其他胜利条件非常相似，因为必须满足相同的条件：

```java
...
private void checkWinCondition(int col, int row) {
  ...
  // Diagonal checks
  int startOffset = Math.min(col, row);
  int column = col - startOffset, auxRow = row - startOffset; 
  stringJoiner = new StringJoiner("");
  do {
    stringJoiner.add(board[column++][auxRow++].toString());
  } while (column < COLUMNS && auxRow < ROWS);

  if (winPattern.matcher(stringJoiner.toString()).matches()) {
    winner = currentPlayer;
    System.out.println(currentPlayer + " wins");
    return;
  }

  startOffset = Math.min(col, ROWS - 1 - row);
  column = col - startOffset;
  auxRow = row + startOffset;
  stringJoiner = new StringJoiner("");
  do {
    stringJoiner.add(board[column++][auxRow--].toString());
  } while (column < COLUMNS && auxRow >= 0);

  if (winPattern.matcher(stringJoiner.toString()).matches()) {
    winner = currentPlayer;
    System.out.println(currentPlayer + " wins");
  }
}
...
```

我们得到了一个带有一个构造函数、三个公共方法和三个私有方法的类。应用程序的逻辑分布在所有方法中。这里最大的缺陷是这个类非常难以维护。关键的方法，比如`checkWinCondition`，都是非平凡的，有潜在的 bug 可能在未来的修改中出现。

如果你想查看完整的代码，你可以在[`bitbucket.org/vfarcic/tdd-java-ch05-design.git`](https://bitbucket.org/vfarcic/tdd-java-ch05-design.git)存储库中找到。

我们制作了这个小例子来演示这种方法的常见问题。像 SOLID 原则这样的主题需要一个更大的项目来更具说明性。

在拥有数百个类的大型项目中，问题变成了在一种类似手术的开发中浪费了数小时。开发人员花费大量时间调查棘手的代码并理解其工作原理，而不是创建新功能。

# TDD 或先测试的实现

此时，我们知道 TDD 是如何工作的——在测试之前编写测试，然后实现测试，最后进行重构。我们将通过这个过程，只展示每个要求的最终结果。剩下的就是让你去理解迭代的红绿重构过程。如果可能的话，让我们在测试中使用 Hamcrest 框架，让这更有趣。

# Hamcrest

如第二章所述，*工具、框架和环境*，Hamcrest 提高了我们测试的可读性。它使断言更有语义和全面性，通过使用**匹配器**减少了复杂性。当测试失败时，通过解释断言中使用的匹配器，显示的错误更具表现力。开发人员还可以添加消息。

`Hamcrest`库中充满了不同类型对象和集合的不同匹配器。让我们开始编码，尝试一下。

# 要求 1 - 游戏的棋盘

我们将从第一个要求开始。

棋盘由七个水平和六个垂直的空位置组成。

这个要求没有太大的挑战。棋盘边界已经指定，但在其中没有描述行为；只是在游戏开始时考虑了一个空棋盘。这意味着游戏开始时没有圆盘。然而，这个要求以后必须考虑。

这是针对此要求的测试类的外观。有一个方法来初始化`tested`类，以便在每个测试中使用一个完全新的对象。还有第一个测试来验证游戏开始时没有圆盘，这意味着所有的棋盘位置都是空的：

```java
public class Connect4TDDSpec {
  private Connect4TDD tested;

  @Before
  public void beforeEachTest() {
    tested = new Connect4TDD();
  }
  @Test
  public void whenTheGameIsStartedTheBoardIsEmpty() {
    assertThat(tested.getNumberOfDiscs(), is(0));
  }
}
```

这是前述规范的 TDD 实现。观察给出的解决方案对于这个第一个要求的简单方法，一个简单的方法在一行中返回结果：

```java
public class Connect4TDD {
  public int getNumberOfDiscs() {
    return 0;
  }
}
```

# 要求 2 - 引入圆盘

这是第二个要求的实现。

玩家在列的顶部放入圆盘。如果列为空，则放入的圆盘会下落到棋盘上。未来放入同一列的圆盘将堆叠在前面的圆盘上。

我们可以将此要求分为以下测试：

+   当一个圆盘插入到一个空列中时，它的位置是`0`

+   当第二个圆盘插入到同一列时，它的位置是`1`

+   当一个圆盘插入到棋盘上时，圆盘的总数增加

+   当一个圆盘放在边界外时，会抛出`Runtime Exception`

+   当一个圆盘插入到一列中，没有可用的空间时，就会抛出`Runtime Exception`

此外，这些其他测试源自第一个要求。它们与棋盘限制或棋盘行为有关。

上述测试的 Java 实现如下：

```java
@Test 
public void whenDiscOutsideBoardThenRuntimeException() {
  int column = -1;
  exception.expect(RuntimeException.class);
  exception.expectMessage("Invalid column " + column);
  tested.putDiscInColumn(column);
}

@Test
public void whenFirstDiscInsertedInColumnThenPositionIsZero() {
  int column = 1;
  assertThat(tested.putDiscInColumn(column),  is(0));
}

@Test
public void whenSecondDiscInsertedInColumnThenPositionIsOne() {
  int column = 1;
  tested.putDiscInColumn(column);
  assertThat(tested.putDiscInColumn(column), is(1));
}

@Test
public void whenDiscInsertedThenNumberOfDiscsIncreases() {
  int column = 1;
  tested.putDiscInColumn(column);
  assertThat(tested.getNumberOfDiscs(), is(1));
}

@Test 
public void whenNoMoreRoomInColumnThenRuntimeException() {
  int column = 1;
  int maxDiscsInColumn = 6; // the number of rows
  for (int times = 0; times < maxDiscsInColumn; ++times) {
    tested.putDiscInColumn(column);
  }
  exception.expect(RuntimeException.class);
  exception.expectMessage("No more room in column " + column);
  tested.putDiscInColumn(column);
}
```

这是满足测试的必要代码：

```java
private static final int ROWS = 6;

private static final int COLUMNS = 7;

private static final String EMPTY = " ";

private String[][] board = new String[ROWS][COLUMNS];

public Connect4TDD() {
  for (String[] row : board) Arrays.fill(row, EMPTY);
}

public int getNumberOfDiscs() {
  return IntStream
           .range(0, COLUMNS)
           .map(this::getNumberOfDiscsInColumn)
           .sum(); 
} 

private int getNumberOfDiscsInColumn(int column) {
  return (int) IntStream
                 .range(0, ROWS)
                 .filter(row -> !EMPTY.equals(board[row][column]))
                 .count();
}

public int putDiscInColumn(int column) {
  checkColumn(column);
  int row = getNumberOfDiscsInColumn(column);
  checkPositionToInsert(row, column);
  board[row][column] = "X";
  return row;
}

private void checkColumn(int column) {
  if (column < 0 || column >= COLUMNS)
    throw new RuntimeException("Invalid column " + column);
}

private void checkPositionToInsert(int row, int column) {
  if (row == ROWS)
    throw new RuntimeException("No more room in column " + column); 
} 
```

# 要求 3 - 玩家轮换

第三个要求涉及游戏逻辑。

这是一个双人游戏，所以每个玩家都有一个颜色。一个玩家使用红色（*R*），另一个玩家使用绿色（*G*）。玩家轮流进行，每次插入一个圆盘。

这些测试涵盖了新功能的验证。为了简单起见，红色玩家将始终开始游戏：

```java
@Test
public void whenFirstPlayerPlaysThenDiscColorIsRed() {
  assertThat(tested.getCurrentPlayer(), is("R"));
}

@Test
public void whenSecondPlayerPlaysThenDiscColorIsRed() {
  int column = 1;
  tested.putDiscInColumn(column);
  assertThat(tested.getCurrentPlayer(), is("G"));
}
```

需要创建一些方法来覆盖这个功能。在`putDiscInColumn`方法中返回行之前调用`switchPlayer`方法：

```java
private static final String RED = "R";

private static final String GREEN = "G";

private String currentPlayer = RED;

public Connect4TDD() {
  for (String[] row : board) Arrays.fill(row, EMPTY);
}

public String getCurrentPlayer() {
  return currentPlayer;
}

private void switchPlayer() {
  if (RED.equals(currentPlayer)) currentPlayer = GREEN;
  else currentPlayer = RED;
}

public int putDiscInColumn(int column) {
  ...
  switchPlayer();
  return row;
}
```

# 要求 4 - 游戏输出

接下来，我们应该让玩家知道游戏的状态。

我们希望在游戏中发生事件或错误时得到反馈。输出显示每次移动时棋盘的状态。

当发生错误时我们抛出异常，这已经涵盖了，所以我们只需要实现这两个测试。此外，为了便于测试，我们需要在构造函数中引入一个参数。通过引入这个参数，输出变得更容易测试：

```java
private OutputStream output;

@Before
public void beforeEachTest() {
  output = new ByteArrayOutputStream(); 
  tested = new Connect4TDD(new PrintStream(output)); 
}

@Test
public void whenAskedForCurrentPlayerTheOutputNotice() {
  tested.getCurrentPlayer();
  assertThat(output.toString(), containsString("Player R turn")); 
}

@Test
public void whenADiscIsIntroducedTheBoardIsPrinted() {
  int column = 1;
  tested.putDiscInColumn(column);
  assertThat(output.toString(), containsString("| |R| | | | | |"));
}
```

一种可能的实现是通过前面的测试。如您所见，类构造函数现在有一个参数。这个参数在几个方法中用于打印事件或动作描述：

```java
private static final String DELIMITER = "|";

public Connect4TDD(PrintStream out) {
  outputChannel = out;
  for (String[] row : board) Arrays.fill(row, EMPTY); 
}

public String getCurrentPlayer() {
  outputChannel.printf("Player %s turn%n", currentPlayer);
  return currentPlayer;
}

private void printBoard() {
  for (int row = ROWS - 1; row >= 0; row--) {
    StringJoiner stringJoiner = new StringJoiner(DELIMITER, DELIMITER, DELIMITER); 
    Stream.of(board[row]).forEachOrdered(stringJoiner::add); 
    outputChannel.println(stringJoiner.toString()); 
  }
}

public int putDiscInColumn(int column) {
  ... 
  printBoard();
  switchPlayer();
  return row;
} 
```

# 要求 5 - 胜利条件（I）

此要求告诉系统游戏是否结束。

当不能再插入圆盘时，游戏结束，被视为平局。

有两个条件需要测试。第一个条件是新游戏必须未完成；第二个条件是完整的棋盘游戏必须完成：

```java
@Test
public void whenTheGameStartsItIsNotFinished() {
  assertFalse("The game must not be finished", tested.isFinished()); 
} 

@Test 
public void whenNoDiscCanBeIntroducedTheGamesIsFinished() { 
  for (int row = 0; row < 6; row++)
    for (int column = 0; column < 7; column++)
      tested.putDiscInColumn(column);
    assertTrue("The game must be finished", tested.isFinished()); 
}
```

这两个测试的一个简单解决方案如下：

```java
public boolean isFinished() {
  return getNumberOfDiscs() == ROWS * COLUMNS;
}
```

# 需求 6 - 获胜条件（II）

这是玩家的第一个获胜条件要求。

如果玩家插入一个圆盘并连接他的颜色超过三个圆盘成一条垂直直线，那么该玩家获胜。

实际上，这只需要一次检查。如果当前插入的圆盘连接其他三个圆盘成一条垂直线，当前玩家就赢得了比赛：

```java
@Test
public void when4VerticalDiscsAreConnectedThenPlayerWins() {
  for (int row = 0; row < 3; row++) {
    tested.putDiscInColumn(1); // R
    tested.putDiscInColumn(2); // G
  }
  assertThat(tested.getWinner(), isEmptyString());
  tested.putDiscInColumn(1); // R
  assertThat(tested.getWinner(), is("R"));
}
```

`putDiscInColumn`方法有一些改变。还创建了一个名为`checkWinner`的新方法：

```java
private static final int DISCS_TO_WIN = 4;

private String winner = "";

private void checkWinner(int row, int column) {
  if (winner.isEmpty()) {
    String colour = board[row][column];
    Pattern winPattern =
      Pattern.compile(".*" + colour + "{" +
           DISCS_TO_WIN + "}.*");

    String vertical = IntStream
                       .range(0, ROWS)
                       .mapToObj(r -> board[r][column])
                       .reduce(String::concat).get();
    if (winPattern.matcher(vertical).matches()) 
      winner = colour;
  }
}
```

# 需求 7 - 获胜条件（III）

这是第二个获胜条件，与前一个条件非常相似。

如果玩家插入一个圆盘并连接他的颜色超过三个圆盘成一条水平直线，那么该玩家获胜。

这一次，我们试图通过将圆盘插入相邻的列来赢得比赛：

```java
@Test
public void when4HorizontalDiscsAreConnectedThenPlayerWins() {
  int column;
  for (column = 0; column < 3; column++) {
    tested.putDiscInColumn(column); // R
    tested.putDiscInColumn(column); // G
  }
  assertThat(tested.getWinner(), isEmptyString());
  tested.putDiscInColumn(column); // R
  assertThat(tested.getWinner(), is("R"));
}
```

通过这个测试的代码被放入了`checkWinners`方法中：

```java
  if (winner.isEmpty()) { 
    String horizontal = Stream
                         .of(board[row])
                         .reduce(String::concat).get();
    if (winPattern.matcher(horizontal).matches())
      winner = colour; 
  }
```

# 需求 8 - 获胜条件（IV）

最后的要求是最后的获胜条件。

如果玩家插入一个圆盘并连接他的颜色超过三个圆盘成一条对角线，那么该玩家获胜。

我们需要执行有效的游戏动作来实现这个条件。在这种情况下，我们需要测试整个棋盘上的对角线：从右上到左下，从右下到左上。以下测试使用列的列表来重新创建一个完整的游戏，以重现测试场景：

```java
@Test
public void when4Diagonal1DiscsAreConnectedThenThatPlayerWins() {
  int[] gameplay = new int[] {1, 2, 2, 3, 4, 3, 3, 4, 4, 5, 4};
  for (int column : gameplay) {
    tested.putDiscInColumn(column);
  }
  assertThat(tested.getWinner(), is("R"));
}

@Test
public void when4Diagonal2DiscsAreConnectedThenThatPlayerWins() { 
  int[] gameplay = new int[] {3, 4, 2, 3, 2, 2, 1, 1, 1, 1};
  for (int column : gameplay) {
    tested.putDiscInColumn(column);
  }
  assertThat(tested.getWinner(), is("G"));
}
```

再次，`checkWinner`方法需要修改，添加新的棋盘验证：

```java
    if (winner.isEmpty()) { 
      int startOffset = Math.min(column, row); 
      int myColumn = column - startOffset, 
        myRow = row - startOffset; 
      StringJoiner stringJoiner = new StringJoiner(""); 
      do { 
        stringJoiner .add(board[myRow++][myColumn++]); 
      } while (myColumn < COLUMNS && myRow < ROWS); 
      if (winPattern .matcher(stringJoiner.toString()).matches()) 
        winner = currentPlayer; 
    } 

    if (winner.isEmpty()) {
      int startOffset = Math.min(column, ROWS - 1 - row);
      int myColumn = column - startOffset,
        myRow = row + startOffset;
      StringJoiner stringJoiner = new StringJoiner("");
      do {
        stringJoiner.add(board[myRow--][myColumn++]);
      } while (myColumn < COLUMNS && myRow >= 0);
      if (winPattern.matcher(stringJoiner.toString()).matches())
        winner = currentPlayer; 
    } 
```

# 最后的考虑

使用 TDD，我们得到了一个构造函数，五个公共方法和六个私有方法的类。总的来说，所有方法看起来都很简单易懂。在这种方法中，我们还得到了一个检查获胜条件的大方法：`checkWinner`。优点是，通过这种方法，我们得到了一堆有用的测试，以确保未来的修改不会意外地改变方法的行为，从而可以轻松引入新的更改。代码覆盖率不是目标，但我们得到了一个非常高的百分比。

另外，为了测试目的，我们重构了类的构造函数，接受输出通道作为参数（依赖注入）。如果我们需要修改游戏状态的打印方式，这种方式将比传统方式更容易。因此，它更具可扩展性。在测试后的方法中，我们一直在滥用`System.println`方法，如果我们决定更改所有出现的内容，这将是一个非常繁琐的任务。

在大型项目中，当您发现必须为单个类创建大量测试时，这使您能够遵循单一职责原则来拆分类。由于输出打印被委托给了一个在初始化参数中传递的外部类，一个更优雅的解决方案是创建一个具有高级打印方法的类。这将使打印逻辑与游戏逻辑分离。就像下图所示的大量代码覆盖率一样，这些都是使用 TDD 进行良好设计的好处的几个例子：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/e3d0f91a-75fd-4966-9fb6-643ac5ea040c.png)

这种方法的代码可在[`bitbucket.org/vfarcic/tdd-java-ch05-design.git`](https://bitbucket.org/vfarcic/tdd-java-ch05-design.git)找到。

# 总结

在本章中，我们简要讨论了软件设计和一些基本的设计原则。我们使用了传统和 TDD 两种方法来实现了一个完全功能的连四棋盘游戏。

我们分析了两种解决方案的优缺点，并使用 Hamcrest 框架来增强我们的测试。

最后，我们得出结论，良好的设计和良好的实践可以通过两种方法来实现，但 TDD 是更好的方法。

关于本章涵盖的主题的更多信息，请参考罗伯特·C·马丁所著的两本高度推荐的书籍：《代码整洁之道：敏捷软件工艺》和《敏捷软件开发：原则、模式和实践》。


# 第六章：模拟 - 消除外部依赖

“空谈是廉价的。给我看代码。”

- Linus Torvalds

TDD 是关于速度的。我们希望快速证明一个想法、概念或实现是否有效。此外，我们希望快速运行所有测试。这种速度的主要瓶颈是外部依赖关系。设置测试所需的数据库数据可能是耗时的。执行验证使用第三方 API 的代码的测试可能会很慢。最重要的是，编写满足所有外部依赖关系的测试可能会变得太复杂，不值得。模拟内部和外部依赖关系有助于解决这些问题。

我们将在第三章中构建*红-绿-重构 - 从失败到成功直至完美*中所做的工作。我们将扩展井字棋以使用 MongoDB 作为数据存储。我们的单元测试实际上不会使用 MongoDB，因为所有通信都将被模拟。最后，我们将创建一个集成测试，验证我们的代码和 MongoDB 确实集成在一起。

本章将涵盖以下主题：

+   模拟

+   Mockito

+   井字棋 v2 的要求

+   开发井字棋 v2

+   集成测试

# 模拟

每个做过比*Hello World*更复杂的应用程序的人都知道，Java 代码充满了依赖关系。可能有团队其他成员编写的类和方法、第三方库或我们与之通信的外部系统。甚至 JDK 内部的库也是依赖关系。我们可能有一个业务层，它与数据访问层通信，后者又使用数据库驱动程序来获取数据。在进行单元测试时，我们进一步考虑所有公共和受保护的方法（甚至是我们正在工作的类内部的方法）都是应该被隔离的依赖关系。

在单元测试级别进行 TDD 时，创建考虑所有这些依赖关系的规范可能会非常复杂，以至于测试本身会成为瓶颈。它们的开发时间可能会增加到 TDD 带来的好处很快被不断增加的成本所掩盖。更重要的是，这些依赖关系往往会创建非常复杂的测试，这些测试包含的错误比实际实现本身还要多。

单元测试的想法（特别是与 TDD 结合在一起时）是编写验证单个单元代码是否有效的规范，而不考虑依赖关系。当依赖关系是内部的时，它们已经经过测试，我们知道它们会按我们的期望工作。另一方面，外部依赖关系需要信任。我们必须相信它们能正确工作。即使我们不相信，对 JDK `java.nio`类进行深度测试的任务对大多数人来说太大了。此外，这些潜在问题将在运行功能和集成测试时出现。

在专注于单元时，我们必须尽量消除单元可能使用的所有依赖关系。通过设计和模拟的组合来实现这些依赖关系的消除。

使用模拟的好处包括减少代码依赖性和更快的文本执行。

模拟是测试快速执行和集中在单个功能单元上的能力的先决条件。通过模拟被测试方法外部的依赖关系，开发人员能够专注于手头的任务，而不必花时间设置它们。在更大的团队或多个团队一起工作的情况下，这些依赖关系甚至可能尚未开发。此外，没有模拟的测试执行往往会很慢。模拟的良好候选对象包括数据库、其他产品、服务等。

在我们深入研究模拟之前，让我们先看看为什么有人会首先使用它们。

# 为什么要使用模拟？

以下列表列出了我们使用模拟对象的一些原因：

+   对象生成不确定的结果。例如，`java.util.Date()`每次实例化时都会提供不同的结果。我们无法测试其结果是否符合预期：

```java
java.util.Date date = new java.util.Date(); 
date.getTime(); // What is the result this method returns?
```

+   对象尚不存在。例如，我们可能创建一个接口并针对其进行测试。在我们测试使用该接口的代码时，实现该接口的对象可能尚未编写。

+   对象速度慢，需要时间来处理。最常见的例子是数据库。我们可能有一个检索所有记录并生成报告的代码。这个操作可能持续几分钟、几小时，甚至在某些情况下可能持续几天。

在支持模拟对象的前述原因适用于任何类型的测试。然而，在单元测试的情况下，尤其是在 TDD 的背景下，还有一个原因，也许比其他原因更重要。模拟允许我们隔离当前正在工作的方法使用的所有依赖项。这使我们能够集中精力在单个单元上，并忽略该单元调用的代码的内部工作。

# 术语

术语可能有点令人困惑，特别是因为不同的人对同一件事使用不同的名称。更让事情变得更加复杂的是，模拟框架在命名其方法时往往不一致。

在我们继续之前，让我们简要介绍一下术语。

**测试替身**是以下所有类型的通用名称：

+   虚拟对象的目的是充当真实方法参数的替代品

+   测试存根可用于使用特定于测试的对象替换真实对象，向被测系统提供所需的间接输入

+   **测试间谍**捕获了**被测系统**（**SUT**）间接输出给另一个组件的调用，以便后续由测试进行验证

+   模拟对象替换了 SUT 依赖的对象，使用一个特定于测试的对象来验证 SUT 是否正确使用它

+   虚拟对象用更轻量级的实现替换了 SUT 依赖的组件

如果您感到困惑，知道您并不是唯一一个可能会有帮助。事情比这更复杂，因为在框架或作者之间没有明确的协议，也没有命名标准。术语令人困惑且不一致，前面提到的术语绝不是所有人都接受的。

为了简化事情，在本书中我们将使用 Mockito（我们选择的框架）使用相同的命名。这样，您将使用的方法将与您将在后面阅读的术语对应。我们将继续使用模拟作为其他人可能称为**测试替身**的通用术语。此外，我们将使用模拟或间谍术语来指代`Mockito`方法。

# 模拟对象

模拟对象模拟了真实（通常是复杂的）对象的行为。它允许我们创建一个将替换实现代码中使用的真实对象的对象。模拟对象将期望一个定义的方法和定义的参数返回期望的结果。它预先知道应该发生什么以及我们期望它如何反应。

让我们看一个简单的例子：

```java
TicTacToeCollection collection = mock(TicTacToeCollection.class); 
assertThat(collection.drop()).isFalse();
doReturn(true).when(collection).drop(); 

assertThat(collection.drop()).isTrue();
```

首先，我们定义`collection`为`TicTacToeCollection`的`mock`。此时，来自该模拟对象的所有方法都是虚假的，并且在 Mockito 的情况下返回默认值。这在第二行得到了确认，我们`assert`了`drop`方法返回`false`。接着，我们指定我们的模拟对象`collection`在调用`drop`方法时应返回`true`。最后，我们`assert`了`drop`方法返回`true`。

我们创建了一个模拟对象，它返回默认值，并且对其方法之一定义了应该返回的值。在任何时候都没有使用真实对象。

稍后，我们将使用具有此逻辑反转的间谍；一个对象使用真实方法，除非另有规定。当我们开始扩展我们的井字棋应用程序时，我们将很快看到并学到更多关于模拟的知识。现在，让我们先看看一个名为 Mockito 的 Java 模拟框架。

# Mockito

Mockito 是一个具有清晰简洁 API 的模拟框架。使用 Mockito 生成的测试可读性强，易于编写，直观。它包含三个主要的静态方法：

+   `mock()`: 用于创建模拟。可选地，我们可以使用`when()`和`given()`指定这些模拟的行为。

+   `spy()`: 这可以用于部分模拟。间谍对象调用真实方法，除非我们另有规定。与`mock()`一样，行为可以针对每个公共或受保护的方法进行设置（不包括静态方法）。主要区别在于`mock()`创建整个对象的伪造，而`spy()`使用真实对象。

+   `verify()`: 用于检查是否使用给定参数调用了方法。这是一种断言形式。

一旦我们开始编写井字棋 v2 应用程序，我们将深入研究 Mockito。然而，首先让我们快速浏览一组新的需求。

# 井字棋 v2 需求

我们的井字棋 v2 应用程序的需求很简单。我们应该添加一个持久存储，以便玩家可以在以后的某个时间继续玩游戏。我们将使用 MongoDB 来实现这一目的。

将 MongoDB 持久存储添加到应用程序中。

# 开发井字棋 v2

我们将在第三章中继续进行井字棋的工作，*红-绿-重构 - 从失败到成功直至完美*。到目前为止，已开发的应用程序的完整源代码可以在[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo.git`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo.git)找到。使用 IntelliJ IDEA 的 VCS|从版本控制|Git 选项来克隆代码。与任何其他项目一样，我们需要做的第一件事是将依赖项添加到`build.gradle`中：

```java
dependencies { 
    compile 'org.jongo:jongo:1.1' 
    compile 'org.mongodb:mongo-java-driver:2.+' 
    testCompile 'junit:junit:4.12' 
    testCompile 'org.mockito:mockito-all:1.+' 
} 
```

导入 MongoDB 驱动程序应该是不言自明的。Jongo 是一组非常有用的实用方法，使得使用 Java 代码更类似于 Mongo 查询语言。对于测试部分，我们将继续使用 JUnit，并添加 Mockito 的模拟、间谍和验证功能。

您会注意到，我们直到最后才会安装 MongoDB。使用 Mockito，我们将不需要它，因为我们所有的 Mongo 依赖项都将被模拟。

一旦指定了依赖项，请记得在 IDEA Gradle 项目对话框中刷新它们。

源代码可以在`tdd-java-ch06-tic-tac-toe-mongo` Git 存储库的`00-prerequisites`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/00-prerequisites`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/00-prerequisites)）。

现在我们已经设置了先决条件，让我们开始处理第一个需求。

# 需求 1 - 存储移动

我们应该能够将每个移动保存到数据库中。由于我们已经实现了所有的游戏逻辑，这应该很容易做到。尽管如此，这将是模拟使用的一个非常好的例子。

实现一个选项，可以保存单个移动与轮数、*x*和*y*轴位置以及玩家（`X`或`O`）。

我们应该首先定义代表我们数据存储模式的 Java bean。这没有什么特别的，所以我们将跳过这一部分，只有一个注释。

不要花太多时间为 Java 样板代码定义规范。我们的 bean 实现包含重写的`equals`和`hashCode`。这两者都是由 IDEA 自动生成的，除了满足比较相同类型的两个对象的需求之外，它们并没有提供真正的价值（我们稍后将在规范中使用该比较）。TDD 应该帮助我们设计更好的代码。编写 15-20 个规范来定义可以由 IDE 自动编写的样板代码（如`equals`方法）并不会帮助我们实现这些目标。精通 TDD 不仅意味着学会如何编写规范，还意味着知道何时不值得。

也就是说，查看源代码以查看 bean 规范和实现的全部内容。

源代码可以在`tdd-java-ch06-tic-tac-toe-mongo` Git 存储库的`01-bean`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/01-bean`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/01-bean)）。特定的类是`TicTacToeBeanSpec`和`TicTacToeBean`。

现在，让我们来到一个更有趣的部分（但仍然没有模拟、间谍和验证）。让我们编写与将数据保存到 MongoDB 相关的规范。

对于这个要求，我们将在`com.packtpublishing.tddjava.ch03tictactoe.mongo`包内创建两个新类：

+   `TicTacToeCollectionSpec`（在`src/test/java`内）

+   `TicTacToeCollection`（在`src/main/java`内）

# 规范-数据库名称

我们应该指定我们将使用的数据库的名称：

```java
@Test 
public void whenInstantiatedThenMongoHasDbNameTicTacToe() { 
  TicTacToeCollection collection = new TicTacToeCollection(); 
  assertEquals(
     "tic-tac-toe",
     collection.getMongoCollection().getDBCollection().getDB().getName()); 
} 
```

我们正在实例化一个新的`TicTacToeCollection`类，并验证 DB 名称是否符合我们的预期。

# 实施

实施非常简单，如下所示：

```java
private MongoCollection mongoCollection; 
protected MongoCollection getMongoCollection() { 
  return mongoCollection; 
}
public TicTacToeCollection() throws UnknownHostException { 
  DB db = new MongoClient().getDB("tic-tac-toe"); 
  mongoCollection = new Jongo(db).getCollection("bla"); 
} 
```

在实例化`TicTacToeCollection`类时，我们正在创建一个新的`MongoCollection`，并将指定的 DB 名称（`tic-tac-toe`）分配给局部变量。

请耐心等待。在我们使用模拟和间谍的有趣部分之前，只剩下一个规范了。

# 规范-用于 Mongo 集合的名称

在先前的实现中，我们使用`bla`作为集合的名称，因为`Jongo`强制我们放一些字符串。让我们创建一个规范，来定义我们将使用的 Mongo 集合的名称：

```java
@Test 
public void whenInstantiatedThenMongoCollectionHasNameGame() {
  TicTacToeCollection collection = new TicTacToeCollection(); 
  assertEquals( 
            "game", 
            collection.getMongoCollection().getName()); 
} 
```

这个规范几乎与上一个规范相同，可能是不言自明的。

# 实施

我们要做的就是改变我们用来设置集合名称的字符串：

```java
public TicTacToeCollection() throws UnknownHostException { 
  DB db = new MongoClient().getDB("tic-tac-toe"); 
  mongoCollection = new Jongo(db).getCollection("game"); 
} 
```

# 重构

您可能会有这样的印象，即重构仅适用于实现代码。然而，当我们看重构背后的目标（更易读、更优化和更快的代码）时，它们与规范代码一样适用于实现代码。

最后两个规范重复了`TicTacToeCollection`类的实例化。我们可以将其移动到一个用`@Before`注释的方法中。效果将是相同的（在运行用`@Test`注释的方法之前，类将被实例化），并且我们将删除重复的代码。由于在后续规范中将需要相同的实例化，现在删除重复将在以后提供更多的好处。同时，我们将免去一遍又一遍地抛出`UnknownHostException`的麻烦：

```java
TicTacToeCollection collection; 

@Before 
public void before() throws UnknownHostException { 
  collection = new TicTacToeCollection(); 
} 
@Test 
public void whenInstantiatedThenMongoHasDbNameTicTacToe() { 
//        throws UnknownHostException { 
//  TicTacToeCollection collection = new TicTacToeCollection(); 
  assertEquals(
    "tic-tac-toe", 
    collection.getMongoCollection().getDBCollection().getDB().getName()); 
} 

@Test 
public void whenInstantiatedThenMongoHasNameGame() { 
//        throws UnknownHostException { 
//  TicTacToeCollection collection = new TicTacToeCollection(); 
  assertEquals(
    "game",  
    collection.getMongoCollection().getName()); 
} 
```

使用设置和拆卸方法。这些方法的好处允许在类或每个测试方法之前和之后执行准备或设置和处理或拆卸代码。

在许多情况下，一些代码需要在测试类或类中的每个方法之前执行。为此，JUnit 有`@BeforeClass`和`@Before`注解，应该在设置阶段使用。`@BeforeClass`在类加载之前（在第一个测试方法运行之前）执行相关方法。`@Before`在每次测试运行之前执行相关方法。当测试需要特定的前提条件时，应该使用这两个。最常见的例子是在（希望是内存中的）数据库中设置测试数据。相反的是`@After`和`@AfterClass`注解，应该用作拆卸阶段。它们的主要目的是销毁在设置阶段或测试本身创建的数据或状态。每个测试应该独立于其他测试。此外，没有测试应该受到其他测试的影响。拆卸阶段有助于保持系统，就好像以前没有执行任何测试一样。

现在让我们进行一些模拟、监听和验证！

# 规范-向 Mongo 集合添加项目

我们应该创建一个保存数据到 MongoDB 的方法。在研究 Jongo 文档之后，我们发现了`MongoCollection.save`方法，它正是我们需要的。它接受任何对象作为方法参数，并将其（使用 Jackson）转换为 JSON，这在 MongoDB 中是原生使用的。重点是，在使用 Jongo 玩耍后，我们决定使用并且更重要的是信任这个库。

我们可以以两种方式编写 Mongo 规范。一种更传统的方式，适合**端到端**（E2E）或集成测试，是启动一个 MongoDB 实例，调用 Jongo 的保存方法，查询数据库，并确认数据确实已经保存。这还没有结束，因为我们需要在每个测试之前清理数据库，以始终保证相同的状态不受先前测试的执行而污染。最后，一旦所有测试执行完毕，我们可能希望停止 MongoDB 实例，并为其他任务释放服务器资源。

你可能已经猜到，以这种方式编写单个测试涉及相当多的工作。而且，不仅仅是需要投入编写这些测试的工作。执行时间会大大增加。运行一个与数据库通信的测试不需要很长时间。通常运行十个测试仍然很快。运行数百或数千个测试可能需要很长时间。当运行所有单元测试需要很长时间时会发生什么？人们会失去耐心，开始将它们分成组，或者完全放弃 TDD。将测试分成组意味着我们失去了对没有任何东西被破坏的信心，因为我们不断地只测试它的部分。放弃 TDD...好吧，这不是我们试图实现的目标。然而，如果运行测试需要很长时间，可以合理地期望开发人员不愿意等待它们完成后再转移到下一个规范，这就是我们停止进行 TDD 的时候。允许我们的单元测试运行的合理时间是多久？没有一个适用于所有的规则来定义这一点；然而，作为一个经验法则，如果时间超过 10-15 秒，我们应该开始担心，并且花时间来优化它们。

测试应该快速运行。好处是测试经常被使用。

如果运行测试需要很长时间，开发人员将停止使用它们，或者只运行与他们正在进行的更改相关的一个小子集。快速测试的一个好处，除了促进它们的使用，就是快速反馈。问题被检测到的越早，修复起来就越容易。对产生问题的代码的了解仍然很新鲜。如果开发人员在等待测试执行完成时已经开始了下一个功能的工作，他们可能会决定推迟修复问题，直到开发了新功能。另一方面，如果他们放弃当前的工作来修复错误，那么在上下文切换中就会浪费时间。

如果使用实时数据库来运行单元测试不是一个好选择，那么还有什么选择？模拟和监视！在我们的例子中，我们知道应该调用第三方库的哪个方法。我们还投入了足够的时间来信任这个库（除了以后要执行的集成测试）。一旦我们知道如何使用这个库，我们就可以将我们的工作限制在验证该库的正确调用上。

让我们试一试。

首先，我们应该修改我们现有的代码，并将我们对`TicTacToeCollection`的实例化转换为`spy`：

```java
import static org.mockito.Mockito.*; 
... 
@Before 
public void before() throws UnknownHostException { 
  collection = spy(new TicTacToeCollection()); 
} 
```

对一个类进行**部分**模拟被称为监视。应用后，该类的行为将与正常实例化时完全相同。主要区别在于我们可以应用部分模拟并用模拟替换一个或多个方法。一般规则是，我们倾向于在我们正在工作的类上使用监视。我们希望保留我们为其编写规范的类的所有功能，但在需要时，可以模拟其中的一部分。

现在让我们编写规范本身。它可能是以下内容：

```java
@Test
public void whenSaveMoveThenInvokeMongoCollectionSave() {
  TicTacToeBean bean = new TicTacToeBean(3, 2, 1, 'Y');
  MongoCollection mongoCollection = mock(MongoCollection.class);
  doReturn(mongoCollection).when(collection).getMongoCollection();

  collection.saveMove(bean);

  verify(mongoCollection, times(1)).save(bean);
}
```

静态方法，比如`mock`、`doReturn`和`verify`，都来自`org.mockito.Mockito`类。

首先，我们创建一个新的`TicTacToeBean`。没有什么特别的。接下来，我们将`MongoCollection`创建为一个`mock`对象。由于我们已经确定，在单元级别工作时，我们希望避免与数据库直接通信，模拟这种依赖关系将为我们提供这种功能。它将把一个真实的类转换成一个模拟的类。对于使用`mongoCollection`的类来说，它看起来像是一个真实的类；然而，在幕后，它的所有方法都是浅层的，实际上并不执行任何操作。这就像覆盖该类并用空方法替换所有方法一样：

```java
MongoCollection mongoCollection = mock(MongoCollection.class);
```

接下来，我们告诉一个模拟的`mongoCollection`应该在我们调用集合监视类的`getMongoCollection`方法时返回。换句话说，我们告诉我们的类使用一个假的集合而不是真实的集合：

```java
doReturn(mongoCollection).when(collection).getMongoCollection(); 
```

然后，我们调用我们正在工作的方法：

```java
collection.saveMove(bean); 
```

最后，我们应该验证`Jongo`库的正确调用是否执行了一次：

```java
verify(mongoCollection, times(1)).save(bean);
```

让我们试着实现这个规范。

# 实现

为了更好地理解我们刚刚编写的规范，让我们只进行部分实现。我们将创建一个空方法`saveMove`。这将允许我们的代码在不实现规范的情况下编译：

```java
public void saveMove(TicTacToeBean bean) { 
} 
```

当我们运行我们的规范（`gradle test`）时，结果如下：

```java
Wanted but not invoked: 
mongoCollection.save(Turn: 3; X: 2; Y: 1; Player: Y); 
```

Mockito 告诉我们，根据我们的规范，我们期望调用`mongoCollection.save`方法，但这个期望没有实现。由于测试仍然失败，我们需要回去完成实现。在 TDD 中最大的罪过之一就是有一个失败的测试然后转移到其他事情上。

在编写新测试之前，所有测试都应该通过。这样做的好处是，它可以保持对一个小单位的工作的关注，并且实现代码（几乎）总是处于工作状态。

有时候在实际实现之前编写多个测试是很诱人的。在其他情况下，开发人员会忽略现有测试检测到的问题，转向新功能。尽可能避免这种情况。在大多数情况下，违反这个规则只会引入技术债务，需要付出利息来偿还。TDD 的一个目标是确保实现代码（几乎）总是按预期工作。一些项目由于压力要达到交付日期或维持预算，违反这个规则并将时间用于新功能，留下与失败测试相关的代码修复以后再做。这些项目通常最终推迟了不可避免的事情。

让我们也修改实现，例如，以下内容：

```java
public void saveMove(TicTacToeBean bean) { 
  getMongoCollection().save(null); 
} 
```

如果我们再次运行我们的规范，结果如下：

```java
Argument(s) are different! Wanted: 
mongoCollection.save(Turn: 3; X: 2; Y: 1; Player: Y); 
```

这一次我们调用了期望的方法，但是我们传递给它的参数并不是我们希望的。在规范中，我们将期望设置为一个 bean（新的`TicTacToeBean(3, 2, 1, 'Y')`），而在实现中，我们传递了 null。不仅如此，Mockito 的验证可以告诉我们是否调用了正确的方法，以及传递给该方法的参数是否正确。

规范的正确实现如下：

```java
public void saveMove(TicTacToeBean bean) { 
  getMongoCollection().save(bean); 
} 
```

这一次所有的规范都应该通过，我们可以愉快地继续下一个。

# 规范-添加操作反馈

让我们将`saveMove`方法的返回类型更改为`boolean`：

```java
@Test 
public void whenSaveMoveThenReturnTrue() {
  TicTacToeBean bean = new TicTacToeBean(3, 2, 1, 'Y');
  MongoCollection mongoCollection = mock(MongoCollection.class);
  doReturn(mongoCollection).when(collection).getMongoCollection();
  assertTrue(collection.saveMove(bean));
}
```

# 实施

这个实现非常直接。我们应该改变方法的返回类型。记住 TDD 的一个规则是使用最简单的解决方案。最简单的解决方案是返回`true`，就像下面的例子一样：

```java
public boolean saveMove(TicTacToeBean bean) {
  getMongoCollection().save(bean);
  return true;
}
```

# 重构

你可能已经注意到最后两个规范有前两行重复。我们可以通过将它们移到用`@Before`注释的方法中来重构规范代码：

```java
TicTacToeCollection collection;
TicTacToeBean bean;
MongoCollection mongoCollection;

@Before
public void before() throws UnknownHostException {
  collection = spy(new TicTacToeCollection());
  bean = new TicTacToeBean(3, 2, 1, 'Y');
  mongoCollection = mock(MongoCollection.class);
} 
... 
@Test
public void whenSaveMoveThenInvokeMongoCollectionSave() {
// TicTacToeBean bean = new TicTacToeBean(3, 2, 1, 'Y'); 
// MongoCollection mongoCollection = mock(MongoCollection.class); 
  doReturn(mongoCollection).when(collection).getMongoCollection(); 
  collection.saveMove(bean); 
  verify(mongoCollection, times(1)).save(bean); 
} 

@Test 
public void whenSaveMoveThenReturnTrue() { 
// TicTacToeBean bean = new TicTacToeBean(3, 2, 1, 'Y'); 
// MongoCollection mongoCollection = mock(MongoCollection.class); 
   doReturn(mongoCollection).when(collection).getMongoCollection(); 
   assertTrue(collection.saveMove(bean)); 
} 
```

# 规范-错误处理

现在让我们考虑一下在使用 MongoDB 时可能出现问题的选项。例如，当抛出异常时，我们可能希望从我们的`saveMove`方法中返回`false`：

```java
@Test
public void givenExceptionWhenSaveMoveThenReturnFalse() {
  doThrow(new MongoException("Bla"))
    .when(mongoCollection).save(any(TicTacToeBean.class));
  doReturn(mongoCollection).when(collection).getMongoCollection();
  assertFalse(collection.saveMove(bean));
} 
```

在这里，我们介绍了另一个 Mockito 方法：`doThrow`。它的作用方式类似于`doReturn`，当设置条件满足时抛出一个`Exception`。规范将在调用`mongoCollection`类内部的`save`方法时抛出`MongoException`。这使我们能够`assert`我们的`saveMove`方法在抛出异常时返回`false`。

# 实施

实现可以简单到添加一个`try`/`catch`块：

```java
public boolean saveMove(TicTacToeBean bean) {
  try {
    getMongoCollection().save(bean);
    return true;
  } catch (Exception e) {
    return false;
  }
}
```

# 规范-在游戏之间清除状态

这是一个非常简单的应用程序，至少在这一刻，它只能存储一个游戏会话。每当创建一个新实例时，我们应该重新开始并删除数据库中存储的所有数据。这样做的最简单方法就是简单地删除 MongoDB 集合。Jongo 有`MongoCollection.drop()`方法可以用于这个目的。我们将创建一个新的方法`drop`，它将以类似于`saveMove`的方式工作。

如果你没有使用 Mockito、MongoDB 和/或 Jongo 工作过，那么你可能无法自己完成本章的练习，只能决定按照我们提供的解决方案进行。如果是这种情况，那么现在可能是你想要改变方向，尝试自己编写规范和实现的时候了。

我们应该验证`MongoCollection.drop()`是否从我们自己的`drop()`方法内部的`TicTacToeCollection`类中调用。在查看以下代码之前，请自己尝试一下。这几乎与我们对`save`方法所做的事情相同：

```java
@Test
public void whenDropThenInvokeMongoCollectionDrop() {
  doReturn(mongoCollection).when(collection).getMongoCollection();
  collection.drop();
  verify(mongoCollection).drop();
}
```

# 实施

由于这是一个包装方法，实现这个规范应该相当容易：

```java
public void drop() { 
  getMongoCollection().drop(); 
} 
```

# 规范-删除操作反馈

我们几乎完成了这个类。只剩下两个规范。

让我们确保在正常情况下返回`true`：

```java
@Test 
public void whenDropThenReturnTrue() { 
  doReturn(mongoCollection).when(collection).getMongoCollection();
  assertTrue(collection.drop()); 
}
```

# 实施

如果使用 TDD 看起来太容易了，那是有意为之的。我们将任务分解成如此小的实体，以至于在大多数情况下，实现规范都是小菜一碟。这个也不例外：

```java
public boolean drop() { 
  getMongoCollection().drop(); 
  return true; 
} 
```

# 规范-错误处理

最后，让我们确保`drop`方法在出现`异常`时返回`false`：

```java
@Test 
public void givenExceptionWhenDropThenReturnFalse() {
  doThrow(new MongoException("Bla")).when(mongoCollection).drop(); 
  doReturn(mongoCollection).when(collection).getMongoCollection(); 
  assertFalse(collection.drop()); 
} 
```

# 实施

让我们添加一个`try`/`catch`块：

```java
public boolean drop() { 
  try { 
    getMongoCollection().drop();
    return true; 
  } catch (Exception e) {
    return false; 
  } 
} 
```

通过这个实现，我们完成了`TicTacToeCollection`类，它充当了我们的`main`类和 MongoDB 之间的层。

源代码可以在`tdd-java-ch06-tic-tac-toe-mongo` Git 存储库的`02-save-move`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/02-save-move`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/02-save-move)）。特别的类是`TicTacToeCollectionSpec`和`TicTacToeCollection`。

# 需求 2-存储每一步

让我们在我们的主类`TicTacToe`中使用`TicTacToeCollection`方法。每当玩家成功玩一个回合时，我们应该将其保存到数据库中。此外，我们应该在实例化新类时删除集合，以防新游戏与旧游戏重叠。我们可以把它做得更复杂；然而，对于本章的目的和学习如何使用模拟，这个要求现在就足够了。

将每一步保存到数据库，并确保新会话清除旧数据。

让我们先做一些设置。

# 规范-创建新的集合

由于我们将用于与 MongoDB 通信的所有方法都在`TicTacToeCollection`类中，我们应该确保它被实例化。规范可能如下：

```java
@Test 
public void whenInstantiatedThenSetCollection() {
  assertNotNull(ticTacToe.getTicTacToeCollection());
} 
```

`TicTacToe`的实例化已经在用`@Before`注解的方法中完成了。通过这个规范，我们确保集合也被实例化。

# 实施

这个实现没有什么特别之处。我们应该简单地重写默认构造函数，并将一个新实例分配给`ticTacToeCollection`变量。

首先，我们应该添加一个本地变量和一个`TicTacToeCollection`的 getter：

```java
private TicTacToeCollection ticTacToeCollection;

protected TicTacToeCollection getTicTacToeCollection() {
  return ticTacToeCollection;
} 
```

现在剩下的就是实例化一个新的`collection`并在`main`类实例化时将其分配给变量：

```java
public TicTacToe() throws UnknownHostException {
  this(new TicTacToeCollection()); 
}
protected TicTacToe(TicTacToeCollection collection) {
  ticTacToeCollection = collection; 
} 
```

我们还创建了另一种通过传递`TicTacToeCollection`作为参数来实例化类的方法。这在规范中作为传递模拟集合的简单方法会很方便。

现在让我们回到规范类，并利用这个新的构造函数。

# 规范重构

为了利用新创建的`TicTacToe`构造函数，我们可以做一些类似以下的事情：

```java
private TicTacToeCollection collection; 

@Before 
public final void before() throws UnknownHostException {
  collection = mock(TicTacToeCollection.class);
// ticTacToe = new TicTacToe();
  ticTacToe = new TicTacToe(collection);
} 
```

现在我们所有的规范都将使用`TicTacToeCollection`的模拟版本。还有其他注入模拟依赖的方法（例如，使用 Spring）；然而，可能的话，我们觉得简单胜过复杂的框架。

# 规范-存储当前移动

每当我们玩一个回合，它都应该保存到数据库中。规范可以是以下内容：

```java
@Test 
public void whenPlayThenSaveMoveIsInvoked() {
  TicTacToeBean move = new TicTacToeBean(1, 1, 3, 'X');
  ticTacToe.play(move.getX(), move.getY());
  verify(collection).saveMove(move);
}
```

到目前为止，你应该对 Mockito 很熟悉了，但让我们通过代码来复习一下：

1.  首先，我们实例化一个`TicTacToeBean`，因为它包含了我们的集合所期望的数据：

```java
TicTacToeBean move = new TicTacToeBean(1, 1, 3, 'X'); 
```

1.  接下来，是时候玩一个真正的回合了：

```java
ticTacToe.play(move.getX(), move.getY()); 
```

1.  最后，我们需要验证`saveMove`方法是否真的被调用了：

```java
verify(collection, times(1)).saveMove(move); 
```

正如我们在本章中所做的那样，我们隔离了所有外部调用，只专注于我们正在处理的单元(`play`)。请记住，这种隔离仅限于公共和受保护的方法。当涉及到实际的实现时，我们可能选择将`saveMove`调用添加到`play`公共方法或我们之前重构的一个私有方法中。

# 实施

这个规范提出了一些挑战。首先，我们应该在哪里调用`saveMove`方法？`setBox`私有方法看起来是一个不错的地方。那里我们正在验证轮次是否有效，如果有效，我们可以调用`saveMove`方法。然而，该方法期望一个`bean`而不是当前正在使用的变量`x`，`y`和`lastPlayer`，所以我们可能需要更改`setBox`方法的签名。

这是该方法现在的样子：

```java
private void setBox(int x, int y, char lastPlayer) {
  if (board[x - 1][y - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[x - 1][y - 1] = lastPlayer;
  }
}
```

这是在必要的更改应用后的外观：

```java
private void setBox(TicTacToeBean bean) {
  if (board[bean.getX() - 1][bean.getY() - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[bean.getX() - 1][bean.getY() - 1] = lastPlayer;
    getTicTacToeCollection().saveMove(bean);
  }
}
```

`setBox`签名的更改触发了一些其他更改。由于它是从`play`方法中调用的，我们需要在那里实例化`bean`：

```java
public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  lastPlayer = nextPlayer();
// setBox(x, y, lastPlayer);
  setBox(new TicTacToeBean(1, x, y, lastPlayer));
  if (isWin(x, y)) {
    return lastPlayer + " is the winner";
  } else if (isDraw()) {
    return RESULT_DRAW;
  } else {
    return NO_WINNER;
  }
}
```

您可能已经注意到我们使用常量值`1`作为轮次。仍然没有规范表明否则，所以我们采取了一种捷径。我们以后再处理它。

所有这些更改仍然非常简单，并且实施它们所花费的时间相当短。如果更改更大，我们可能会选择不同的路径；并进行简单的更改以通过重构最终解决方案。记住速度是关键。您不希望长时间无法通过测试的实现。

# 规范-错误处理

如果移动无法保存会发生什么？我们的辅助方法`saveMove`根据 MongoDB 操作结果返回`true`或`false`。当它返回`false`时，我们可能希望抛出异常。

首先：我们应该更改`before`方法的实现，并确保默认情况下`saveMove`返回`true`：

```java
@Before
public final void before() throws UnknownHostException {
  collection = mock(TicTacToeCollection.class);
  doReturn(true).when(collection).saveMove(any(TicTacToeBean.class));
  ticTacToe = new TicTacToe(collection);
}
```

现在我们已经用我们认为是默认行为（在调用`saveMove`时返回`true`）对模拟集合进行了存根处理，我们可以继续编写规范：

```java
@Test
public void whenPlayAndSaveReturnsFalseThenThrowException() {
  doReturn(false).when(collection).saveMove(any(TicTacToeBean.class));
  TicTacToeBean move = new TicTacToeBean(1, 1, 3, 'X');
  exception.expect(RuntimeException.class);
  ticTacToe.play(move.getX(), move.getY());
}
```

当调用`saveMove`时，我们使用 Mockito 返回`false`。在这种情况下，我们不关心`saveMove`的特定调用，所以我们使用`any(TicTacToeBean.class)`作为方法参数。这是 Mockito 的另一个静态方法。

一切就绪后，我们将像在第三章中一样使用 JUnit 期望，*从失败到成功再到完美的红绿重构*。

# 实施

让我们做一个简单的`if`，当结果不符合预期时抛出`RuntimeException`：

```java
private void setBox(TicTacToeBean bean) {
  if (board[bean.getX() - 1][bean.getY() - 1] != '\0') {
    throw new RuntimeException("Box is occupied");
  } else {
    board[bean.getX() - 1][bean.getY() - 1] = lastPlayer;
//  getTicTacToeCollection().saveMove(bean);
    if (!getTicTacToeCollection().saveMove(bean)) {
      throw new RuntimeException("Saving to DB failed");
    }
  }
}
```

# 规范-交替玩家

您还记得我们硬编码为始终为`1`的轮次吗？让我们修复这个行为。

我们可以调用`play`方法两次并验证轮次从`1`变为`2`：

```java
@Test 
public void whenPlayInvokedMultipleTimesThenTurnIncreases() {
  TicTacToeBean move1 = new TicTacToeBean(1, 1, 1, 'X'); 
  ticTacToe.play(move1.getX(), move1.getY()); 
  verify(collection, times(1)).saveMove(move1);
  TicTacToeBean move2 = new TicTacToeBean(2, 1, 2, 'O'); 
  ticTacToe.play(move2.getX(), move2.getY()); 
  verify(collection, times(1)).saveMove(move2); 
} 
```

# 实施

与几乎所有其他以 TDD 方式完成的工作一样，实施起来相当容易：

```java
private int turn = 0;
...
public String play(int x, int y) {
  checkAxis(x);
  checkAxis(y);
  lastPlayer = nextPlayer();
  setBox(new TicTacToeBean(++turn, x, y, lastPlayer));
  if (isWin(x, y)) {
    return lastPlayer + " is the winner";
  } else if (isDraw()) {
    return RESULT_DRAW;
  } else {
    return NO_WINNER;
  }
}
```

# 练习

还有一些规范及其实施尚未完成。我们应该在我们的`TicTacToe`类实例化时调用`drop()`方法。我们还应该确保在`drop()`返回`false`时抛出`RuntimeException`。我们将把这些规范及其实施留给您作为练习。

源代码可以在`tdd-java-ch06-tic-tac-toe-mongo` Git 存储库的`03-mongo`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/03-mongo`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/03-mongo)）。特别的类是`TicTacToeSpec`和`TicTacToe`。

# 集成测试

我们做了很多单元测试。我们非常依赖信任。一个接一个地指定和实现单元。在编写规范时，我们隔离了除了我们正在处理的单元之外的一切，并验证一个单元是否正确调用了另一个单元。然而，现在是时候验证所有这些单元是否真的能够与 MongoDB 通信了。我们可能犯了一个错误，或者更重要的是，我们可能没有将 MongoDB 启动和运行。发现，例如，我们部署了我们的应用程序，但忘记启动数据库，或者配置（IP、端口等）没有设置正确，这将是一场灾难。

集成测试的目标是验证，正如你可能已经猜到的那样，独立组件、应用程序、系统等的集成。如果你记得测试金字塔，它指出单元测试是最容易编写和最快运行的，因此我们应该将其他类型的测试限制在单元测试未覆盖的范围内。

我们应该以一种可以偶尔运行的方式隔离我们的集成测试（在将代码推送到存储库之前，或作为我们的持续集成（CI）过程的一部分），并将单元测试作为持续反馈循环。

# 测试分离

如果我们遵循某种约定，那么在 Gradle 中分离测试就会相当容易。我们可以将测试放在不同的目录和不同的包中，或者，例如，使用不同的文件后缀。在这种情况下，我们选择了后者。我们所有的规范类都以`Spec`后缀命名（即`TicTacToeSpec`）。我们可以制定一个规则，即所有集成测试都具有`Integ`后缀。

考虑到这一点，让我们修改我们的`build.gradle`文件。

首先，我们将告诉 Gradle 只有以`Spec`结尾的类才应该被`test`任务使用：

```java
test { 
    include '**/*Spec.class' 
} 
```

接下来，我们可以创建一个新任务`testInteg`：

```java
task testInteg(type: Test) { 
    include '**/*Integ.class' 
} 
```

通过这两个对`build.gradle`的添加，我们继续使用本书中大量使用的测试任务；然而，这一次，它们仅限于规范（单元测试）。此外，所有集成测试都可以通过从 Gradle 项目 IDEA 窗口点击`testInteg`任务或从命令提示符运行以下命令来运行：

```java
gradle testInteg

```

让我们写一个简单的集成测试。

# 集成测试

我们将在`src/test/java`目录中的`com.packtpublishing.tddjava.ch03tictactoe`包内创建一个`TicTacToeInteg`类。由于我们知道 Jongo 如果无法连接到数据库会抛出异常，所以测试类可以简单如下：

```java
import org.junit.Test;
import java.net.UnknownHostException;
import static org.junit.Assert.*;

public class TicTacToeInteg {

  @Test
  public void givenMongoDbIsRunningWhenPlayThenNoException()
        throws UnknownHostException {
    TicTacToe ticTacToe = new TicTacToe();
    assertEquals(TicTacToe.NO_WINNER, ticTacToe.play(1, 1));
  }
}
```

`assertEquals`的调用只是作为一种预防措施。这个测试的真正目的是确保没有抛出`Exception`。由于我们没有启动 MongoDB（除非你非常主动并且自己启动了它，在这种情况下你应该停止它），`test`应该失败：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/43e8e2b6-439a-45e2-ac2a-206f307010a9.png)

现在我们知道集成测试是有效的，或者换句话说，当 MongoDB 没有启动和运行时，它确实会失败，让我们再次尝试一下，看看数据库启动后的情况。为了启动 MongoDB，我们将使用 Vagrant 创建一个带有 Ubuntu 操作系统的虚拟机。MongoDB 将作为 Docker 运行。

确保检出了 04-integration 分支：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/c0e5e0fa-4005-4021-9cd1-e2dc393f35fe.png)

从命令提示符运行以下命令：

```java
$ vagrant up

```

请耐心等待 VM 启动和运行（当第一次执行时可能需要一段时间，特别是在较慢的带宽上）。完成后，重新运行集成测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/60c4a316-d999-4143-9697-359e4df6e661.png)

它起作用了，现在我们确信我们确实与 MongoDB 集成了。

这是一个非常简单的集成测试，在现实世界中，我们会做更多的工作而不仅仅是这一个测试。例如，我们可以查询数据库并确认数据是否被正确存储。然而，本章的目的是学习如何模拟以及我们不应该仅依赖单元测试。下一章将更深入地探讨集成和功能测试。

源代码可以在`tdd-java-ch06-tic-tac-toe-mongo` Git 存储库的`04-integration`分支中找到（[`bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/04-integration`](https://bitbucket.org/vfarcic/tdd-java-ch06-tic-tac-toe-mongo/branch/04-integration)）。

# 总结

模拟和间谍技术被用来隔离代码或第三方库的不同部分。它们是必不可少的，如果我们要以极快的速度进行，不仅在编码时，而且在运行测试时也是如此。没有模拟的测试通常太复杂，写起来很慢，随着时间的推移，TDD 往往变得几乎不可能。慢速测试意味着我们将无法在每次编写新规范时运行所有测试。这本身就导致我们对测试的信心下降，因为只有其中的一部分被运行。

模拟不仅作为隔离外部依赖的一种方式，还作为隔离我们自己正在处理的单元的一种方式。

在本章中，我们将 Mockito 作为我们认为在功能和易用性之间具有最佳平衡的框架进行介绍。我们邀请您更详细地调查其文档（[`mockito.org/`](http://mockito.org/)），以及其他专门用于模拟的 Java 框架。EasyMock（[`easymock.org/`](http://easymock.org/)）、JMock（[`www.jmock.org/`](http://www.jmock.org/)）和 PowerMock（[`code.google.com/p/powermock/`](https://code.google.com/p/powermock/)）是一些最受欢迎的框架。

在下一章中，我们将介绍一些函数式编程概念以及应用于它们的一些 TDD 概念。为此，将介绍 Java 函数式 API 的一部分。
