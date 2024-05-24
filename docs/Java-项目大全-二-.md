# Java 项目大全（二）

> 原文：[JAVA PROJECTS](https://libgen.rs/book/index.php?md5=C751311C3F308045737DA4CD071BA359)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 三、优化排序代码

在本章中，我们将开发排序代码并使其更通用。我们希望对更一般的内容进行排序，而不仅仅是字符串数组。基本上，我们将编写一个程序，可以排序任何可排序的。通过这种方式，我们将充分利用 Java 的一个主要优势——*抽象*。

然而，抽象并不是没有价格标签的。当您有一个对字符串进行排序的类，并且您不小心将一个整数或其他非字符串的内容混合到可排序数据中时，编译器将对此进行抱怨。Java 不允许将`int`放入`String`数组。当代码更抽象时，这样的编程错误可能会溜进来。我们将研究如何通过捕获和抛出异常来处理此类异常情况。稍后，我们还将研究泛型，这是 Java 的一个特性，可以帮助在编译时捕获此类编程错误。

为了识别 bug，我们将使用单元测试，应用行业标准 JUnitVersion4。由于 JUnit 大量使用注释，而且由于注释很重要，我们还将了解一些注释。

之后，我们将修改代码以使用 Java 的泛型特性，该特性是在版本 5 中引入到语言中的。使用它，我们将捕获编译期间的编码错误。这比在运行时处理异常要好得多。越早发现 bug，修复的成本就越低。

对于构建，我们仍将使用 Maven，但这一次，我们将把代码分成几个小模块。因此，我们将有一个多模块的项目。对于排序模块的定义和不同的实现，我们将有单独的模块。这样，我们将了解类如何相互扩展和实现接口，通常，我们将真正开始以面向对象的方式编程。

我们还将讨论**测试驱动开发**（**TDD**），在本节的最后，我们将开始使用版本 9 模块支持中引入的全新特性 Java。

在本章中，我们将介绍以下主题：

*   面向对象编程原理
*   单元测试实践
*   算法复杂性与快速排序
*   异常处理
*   递归方法
*   模块支持

# 通用排序程序

在上一章中，我们实现了一个简单的排序算法。代码可以对`String`数组的元素进行排序。我们这样做是为了学习。在实际应用中，JDK 中有一个现成的排序解决方案，可以对`Collection`对象中可比较的成员进行排序。

JDK 包含一个名为`Collections`的工具类，它本身包含一个静态方法`Collections.sort`。此方法可以对具有成员为`Comparable`的任何`List`进行排序（更准确地说，成员是实现`Comparable`接口的类的实例）。`List`和`Comparable`是在 JDK 中定义的接口。因此，如果我们要对`Strings`列表进行排序，最简单的解决方案如下：

```java
public class SimplestStringListSortTest {
    @Test
    public void canSortStrings() {
        var actualNames = new ArrayList(Arrays.asList(
                "Johnson", "Wilson",
                "Wilkinson", "Abraham", "Dagobert"
        ));
        Collections.sort(actualNames);
        Assert.assertEquals(new ArrayList<>(Arrays.asList(
                "Abraham", "Dagobert",
                "Johnson", "Wilkinson", "Wilson")),
                actualNames);
    }
}
```

这个代码片段来自一个示例 JUnit 测试，这就是我们在方法前面有`@Test`注解的原因。我们稍后将详细讨论。要执行该测试，我们可以发出以下命令：

```java
$ mvn -Dtest=SimplestStringListSortTest test
```

然而，这种实现并不能满足我们的需要。主要原因是我们想学些新东西。使用 JDK 的`sort()`方法并没有教给您任何新的东西，除了该方法前面的`@Test`注解。

如果在前面的代码中有一些您无法理解的内容，那么您可以在本书中翻回一些页面，并查阅 JDK 的 [Oracle 在线文档](https://docs.oracle.com/javase/9/docs/api/)，但仅此而已。你已经知道这些事情了。

您可能想知道为什么我要将 JavaVersion9API 的 URL 写到链接中。好吧，现在是我写这本书时诚实和真实的时刻，Java11JDK 还没有最终的版本。事实上，甚至 Java10JDK 也只是预发布的。在第一版中，我在 MacBook 上使用 Java8 创建了大多数示例，后来我只测试了 Java10、10 或 11 特定的特性。当您阅读本书时，Java8 将可用，因此您可以尝试将 URL 中的一个数字从 9 改为 11，并获得版本 11 的文档。目前，我得到 HTTP 错误 404。有时，您可能需要旧版本的文档。您可以在 URL 中使用 3、4、5、6、7、8 或 9 而不是 11。3 和 4 的文档不能在线阅读，但可以下载。希望你永远都不需要。也许是第五版。第 6 版在本书第一版出版时仍被大公司广泛使用，自那以后没有太大变化。

尽管您可以从阅读其他程序员编写的代码中学到很多，但我不建议您在学习的早期阶段尝试从 JDK 源代码中学习。这些代码块经过了大量优化，不是教程代码，而且它们很旧。它们不会生锈，但是它们没有被重构以遵循 Java 成熟时更新的编码风格。在某些地方，您可以在 JDK 中找到一些非常难看的代码。

好吧，说我们需要开发一个新的，因为我们可以从中学习，这有点自作主张。我们需要一个排序实现的真正原因是我们想要的东西不仅可以对`List`数据类型和实现`Comparable`接口的东西进行排序，我们想要对一组对象进行排序。我们所需要的是，包含对象的*束*提供了简单的方法，这些方法足以对它们进行排序，并有一个已排序的*束*。

最初我想用单词*集合*来代替*束*，但是 Java 中有一个`Collection`接口，我想强调的是，我们不是在讨论对象的`java.util.Collection`。

我们也不希望对象实现`Comparable`接口。如果我们要求对象实现`Comparable`接口，可能违反**单一责任原则**（**SRP**）。

当我们设计一个类时，它应该对现实世界中的某个对象类进行建模。我们将用类来建模问题空间。类应该实现表示它所建模的对象行为的特性。如果我们看第二章学生的例子，那么一个`Student`类应该代表所有学生共享的特征，从建模的角度来看是*重要的*。一个`Student`对象应该能够说出学生的名字、年龄、去年的平均分数等等。但是，我们应该关注与我们的编程需求相关的特性。例如，所有学生都有脚，当然，每只脚都有一个大小，所以我们可能认为一个`Student`类也应该实现一个返回学生脚大小的方法。为了突出荒谬之处，我们可以实现数据结构和 API，为左脚注册一个大小，为右脚注册一个不同的大小。我们没有，因为脚的大小与模型的观点无关。

但是，如果我们想要对包含`Student`对象的列表进行排序，`Student`类必须实现`Comparable`接口。但是等等！你如何比较两个学生？按姓名、年龄或平均分数？

把一个学生和另一个学生作比较并不是这个类的基本特征。每个类或包、库或编程单元都应该有一个职责，它应该只实现这个职责，而不实现其他职责。这并不确切。这不是数学。有时，很难判断一个特性是否适合这个职责。可比性可能是某些数据类型的固有特征，例如`Integer`或`Double`。其他类没有这种固有的比较特性。

有一些简单的技术可以确定特性是否应该是类的一部分。例如，对于一个学生，你可以问真人他们的名字和年龄，他们也可以告诉你他们的平均分。如果你让他们中的一个去`compareTo`（另一个学生），因为`Comparable`接口需要这个方法，他们很可能会问，“用什么属性或者怎么做？”如果他们不是有礼貌的类型，他们可以简单地回答“什么？”（更不用说缩写 WTF，它代表一周的最后三个工作日，在这种情况下很流行。）在这种情况下，您可能会怀疑实现该特性可能不在该类及其关注的领域；比较应该与原始类的实现分离开来。这也称为**关注点分离**，与 SRP 密切相关。

JDK 开发人员知道这一点。对`Comparable`元素中的`List`进行排序的`Collections.sort`并不是此类中唯一的排序方法。另一种方法是，如果传递第二个参数，则对任何`List`进行排序，该参数应该是实现`Comparator`接口的对象，并且能够比较`List`的两个元素。这是分离关注点的干净模式。在某些情况下，不需要分离比较。在其他情况下，这是可取的。`Comparator`接口声明了实现类必须提供的一个方法—`compare`。如果两个参数相等，则方法返回`0`。如果它们不同，它应该返回一个否定或肯定的`int`，这取决于哪个参数在另一个参数之前。

JDK 类`java.util.Arrays`中还有`sort`方法。它们对数组排序或仅对数组的一部分排序。该方法是方法重载的一个很好的例子。有一些方法具有相同的名称，但参数不同，可以对每个原始类型的整个数组进行排序，也可以对每个原始类型的片进行排序，还有两个方法用于实现`Comparable`接口的对象数组，还可以用于使用`Comparator`进行排序的对象数组。如您所见，JDK 中提供了一系列排序实现，在 99% 的情况下，您不需要自己实现排序。排序使用相同的算法，一个稳定的合并排序和一些优化。

我们要实现的是一种通用的方法，它可以用来排序列表、数组，或者任何有元素的东西，我们可以在比较器的帮助下进行比较，并且可以交换任意两个元素。我们将实现可用于这些接口的不同排序算法。

# 各种排序算法的简要概述

有许多不同的排序算法。正如我所说，有更简单和更复杂的算法，在许多情况下，更复杂的算法运行得更快。（毕竟，如果更高复杂度的算法运行得更慢，它会有什么好处？）在本章中，我们将实现冒泡排序和快速排序。在上一章中，我们已经实现了字符串的冒泡排序，因此在本例中，实现将主要集中在一般可排序对象排序的编码上。实现快速排序需要一些算法方面的兴趣。

请注意，本节只是让您体验一下算法的复杂性。这是远远不够精确，我在徒劳的希望，没有数学家阅读这一点，并把诅咒我。有些解释含糊不清。如果你想深入学习计算机科学，那么在读完这本书之后，找一些其他的书或者访问在线课程。

当我们讨论一般排序问题时，我们考虑的是一些对象的一般有序集合，其中任意两个对象可以在排序时进行比较和交换。我们还假设这是一种原地排序。这意味着我们不会创建另一个列表或数组来按排序顺序收集原始对象。当我们谈论算法的速度时，我们谈论的是一些抽象的东西，而不是毫秒。当我们想谈论毫秒时，实际的持续时间，我们应该已经有了一个在真实计算机上运行的编程语言的实现。

没有实现的抽象形式的算法不会这样做。不过，一个算法的时间和内存需求还是值得讨论的。当我们这样做的时候，我们通常会研究算法对于大量数据的行为。对于一小部分数据，大多数算法都很快。排序两个数字通常不是问题，是吗？

在排序的情况下，我们通常检查需要多少比较来对`n`个元素的集合进行排序。冒泡排序大约需要`n²`（`n`乘`n`次）比较。我们不能说这就是`n²`，因为在`n=2`的情况下，结果是 1，`n=3`是 3，`n=4`是 6，依此类推。然而，随着`n`开始变大，实际需要的比较次数和`n²`将逐渐地具有相同的值。我们说冒泡排序的算法复杂度是`O(n²)`。这也称为大 O 表示法。如果你有一个算法是`O(n²)`，它只适用于 1000 个元素，在一秒钟内完成，那么你应该期望同样的算法在大约 10 天到一个月内完成 100 万个元素。如果算法是线性的，比如说`O(n)`，那么在一秒钟内完成 1000 个元素应该会让你期望在 1000 秒内完成 100 万个元素。这比喝咖啡的时间长一点，但午餐时间太短了。

这使得如果我们想要一些严肃的业务排序对象，我们需要比冒泡排序更好的东西成为可能。许多不必要的比较不仅浪费了我们的时间，而且浪费了 CPU 的能量，消耗了能源，污染了环境。

然而，问题是排序的速度有多快？有没有一个可以证明的最低限度，我们不能减少？

答案是肯定的，有一个可证明的最低限度。这一点的基础非常有趣，在我看来，每个 IT 工程师不仅应该知道实际答案，而且还应该知道背后的原因。毕竟，必要最小值的证明，只不过是纯粹的信息。下面，再次，不是一个数学证明，只是一种模糊的解释。

当我们实现任何排序算法时，实现将执行比较和元素交换。这是对对象集合进行排序的唯一方法，或者至少所有其他可能的方法都可以简化为以下步骤。比较的结果可以有两个值。假设这些值是`0`或`1`。这是一点信息。如果比较结果为`1`，则我们交换；如果比较结果为`0`，则我们不交换。

在开始比较之前，我们可以将对象按不同的顺序排列，不同的顺序数是`n!`（`n`阶乘），即数字从 1 乘到`n`，换言之，`n! = 1 x 2 x 3 x ... x (n - 1) x n`。

假设我们将单个比较的结果存储在一个数字中，作为排序中每个可能输入的一系列位。现在，如果我们反转排序的执行，从排序后的集合开始运行算法，用描述比较结果的位来控制交换，用另一种方式来控制交换，先进行最后一次交换，再进行排序时首先进行的交换，我们应该恢复物品原来的顺序。这样，每个原始顺序都与一个表示为位数组的数字唯一关联。

现在，我们可以用这种方式来表达最初的问题，描述`n`阶乘不同的数需要多少位？这正是我们需要对`n`元素进行排序的比较数。

要区分`n!`的位数，数字`log2(n!)`。用一些数学，我们会知道`log2(n!)`等于`log2(1) + log2(2) + ... + log2(n)`。如果我们看这个表达式的渐近值，那么我们可以说这与`O(n * logn)`一样的。我们不应该期望任何通用的排序算法更快。

对于特殊情况，有更快的算法。例如，如果我们要对 100 万个数字进行排序，每个数字都在 1 到 10 之间，那么我们只需要对不同的数字进行计数，然后创建一个包含那么多个 1、2 等等的集合。这是一个`O(n)`算法，但并不普遍适用。

同样，这不是一个正式的数学证明。

# 快速排序

查尔斯·安东尼·理查德·霍尔爵士于 1959 年开发了快速排序算法。它是一种典型的分治算法。事情是这样的。

要对长数组进行排序，请从数组中选择一个元素，该元素将成为所谓的枢轴元素。然后，对数组进行分区，使左侧包含所有小于轴的元素，右侧包含所有大于或等于轴的元素。当我们开始分区时，我们不知道左边会有多长，右边会从哪里开始。我们解决这个问题的精确方法将很快解释。现在，重要的是我们要将一个数组进行划分，以便从数组开始到某个索引的元素都小于轴，从那里到数组结束的元素都大于轴。这还有一个简单的结果，左边的元素都比右边的任何元素都小。这已经是偏序了。因为枢轴是从数组中选择的，所以可以保证任何一方都不能包含整个原始数组，使另一方成为空数组。

完成此操作后，可以通过递归调用排序来排序数组的左右两侧。在这些调用中，子数组的长度总是小于上一级的整个数组。当我们要排序的实际级别的数组段中有一个元素时，我们停止递归。在这种情况下，我们可以从递归调用返回，而不需要比较或重新排序；显然，一个元素总是排序的。

当算法部分地使用自身定义时，我们讨论递归算法。最著名的递归定义是斐波那契级数，0 和 1 表示前两个元素，而对于所有后续元素，第`n`个元素是第`n-1`和第`n-2`个元素的总和。递归算法通常在现代编程语言中实现，实现的方法进行一些计算，但有时会调用自身。在设计递归算法时，最重要的是要有停止递归调用的东西；否则，递归实现将为程序栈分配所有可用内存，当内存耗尽时，它将以错误停止程序。

算法的分区部分按照以下方式进行：我们将开始使用从开始到结束的两个索引来读取数组。我们将首先从一个小的索引开始，然后增加索引，直到它小于大的索引，或者直到找到一个大于或等于轴的元素。在此之后，我们将开始减少较大的索引，只要它大于较小的索引，并且索引的元素大于或等于轴。当我们停止时，我们交换两个索引所指向的两个元素。如果指数不一样，我们开始分别增加和减少小指数和大指数。如果索引是相同的，那么我们就完成了分区。数组的左侧是从开始到索引相接处的索引减 1；右侧是从要排序的数组末尾的索引结束处开始。

这种快速排序算法通常消耗`O(n logn)`时间，但在某些情况下，它可以退化为`O(n²)`，具体取决于如何选择枢轴。例如，如果我们选择数组段的第一个元素作为轴心，并且数组已经排序，那么这种快速排序算法将退化为简单的冒泡排序。为了修正这一点，有不同的方法来选择轴心。在本书中，我们将使用最简单的方法选择可排序集合的第一个元素作为轴心。

# 项目结构和构建工具

这次的项目将包含许多模块。在本章中，我们仍将使用 Maven。我们将在 Maven 中建立一个所谓的多模块项目。在这样的项目中，目录包含了模块和`pom.xml`的目录。此顶级目录中没有源代码。此目录中的`pom.xml`文件有以下两个用途：

*   它引用模块，可以用来编译、安装和部署所有模块
*   它为所有模块定义相同的参数

每个`pom.xml`都有一个父级，这个`pom.xml`是模块目录中`pom.xml`文件的父级。为了定义模块，`pom.xml`文件包含以下行：

```java
<modules>
    <module>SortSupportClasses</module>
    <module>SortInterface</module>
    <module>bubble</module>
    <module>quick</module>
    <module>Main</module>
</modules>
```

这些是模块的名称。这些名称用作目录名，在`pom.xml`模块中也用作`artifactId`。此设置中的目录如下所示：

```java
$ tree
   |-SortInterface
   |---src/main/java/packt/java189fundamentals/ch03
   |-bubble
   |---src
   |-----main/java/packt/java189fundamentals/ch03/bubble
   |-----test/java/packt/java189fundamentals/ch03/bubble
   |-quick/src/
   |-----main/java
   |-----test/java
```

# Maven 依赖关系管理

依赖项在 POM 文件中也扮演着重要的角色。上一个项目没有任何依赖项。这次我们将使用 JUnit，所以我们依赖于 JUnit。依赖项在`pom.xml`文件中使用`dependencies`标记定义。例如，冒泡排序模块包含以下代码：

```java
<dependencies>
    <dependency>
        <groupId>packt.java189fundamentals</groupId>
        <artifactId>SortInterface</artifactId>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
    </dependency>
</dependencies>
```

您可以下载的代码集中的实际`pom.xml`将包含比这个更多的代码。在印刷品中，我们通常会呈现一个版本或只是一小部分，有助于理解我们当时讨论的主题。

它告诉 Maven 模块代码使用类、接口和`enum`类型，这些类型是在存储库中可用的模块或库中定义的。

使用 Maven 编译代码时，代码使用的库可以从存储库中获得。当 Ant 被开发出来时，存储库的概念还没有被发明出来。当时，开发人员将库的版本复制到源代码结构中的文件夹中。通常，`lib`目录用于此目的。

这种方法有两个问题：一个是源代码存储库的大小。例如，如果 100 个不同的项目使用 JUnit，那么 JUnit 库的 JAR 文件被复制了 100 次。另一个问题是收集所有的库。当一个库使用另一个库时，开发人员必须阅读该库的文档，这些文档描述了使用该库所需的其他库。这往往是过时和不准确的。这些库必须以同样的方式下载和安装。这既耗时又容易出错。当库丢失而开发人员没有注意到它时，错误就会在编译时出现。如果依赖关系只能在运行时检测到，那么 JVM 就无法加载类。

为了解决这个问题，Maven 提供了一个内置的仓库管理器客户端。存储库是包含库的存储。由于存储库中可能有其他类型的文件，而不仅仅是库，Maven 术语是*工件*。`groupId`、`artifactId`和`version`数字标识伪影。有一个非常严格的要求，工件只能放入存储库一次。即使在发布过程中有一个错误在错误的发布被上传后被识别，工件也不能被覆盖。对于相同的`groupId`、`artifactId`和`version`，只能有一个永远不会更改的文件。如果存在错误，则使用新版本号创建一个新工件，并且可以删除错误工件，但永远不会替换。

如果版本号以`-SNAPSHOT`结尾，则不保证或要求此唯一性。快照通常存储在单独的存储库中，不会发布到世界。

存储库包含以定义的方式组织的目录中的工件。当 Maven 运行时，它可以使用`https`协议访问不同的存储库。

以前，也使用了`http`协议。对于非付费客户，如自由／开源软件开发者，中央存储库只能通过`http`使用。然而，人们发现从存储库下载的模块可能会成为中间人安全攻击的目标，因此 [Sonatype](http://www.sonatype.com) 将策略更改为仅使用`https`协议。千万不要配置或使用具有`https`协议的存储库，也不要信任通过 HTTP 下载的文件。

开发人员的机器上有一个本地存储库，通常位于`~/.m2/repository`目录中。在 Windows 上，用户的主目录通常是`C:\Users\your_username`。在 Unix 操作系统上，Shell 类似于 Windows 命令提示符应用，它使用`~`字符来引用这个目录。当您发出`mvn install`命令时，Maven 将创建的工件存储在这里。Maven 还通过 **HTTPS** 从存储库下载工件时，将其存储在此处。这样，后续的编译就不需要到网络上查找工件了。

公司通常会建立自己的存储库管理器。这些应用可以配置为与其他几个存储库通信，并根据需要从那里收集工件，基本上实现代理功能。工件以层次结构从远端存储库到更近的构建，到本地回购，如果项目的包装类型为`war`、`ear`，或者包含相关工件的其他格式，则构件将从更近的存储库转移到本地回购，实质上也会传递到最终工件。这基本上是文件缓存，不需要重新验证和缓存驱逐。这可以做到，因为工件永远不会被替换。

如果`bubble`项目是一个独立的项目，而不是多模块项目的一部分，那么依赖关系如下所示：

```java
<dependencies>
    <dependency>
        <groupId>packt.java189fundamentals</groupId>
        <artifactId>SortInterface</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.12</version>
    </dependency>
</dependencies>
```

如果没有为依赖项定义`version`，Maven 将无法识别要使用的工件。如果是多模块项目，`version`可以在父级定义，模块继承版本。因为父对象不依赖于实际的工件，所以它应该只定义附加到`groupId`和`artifactId`的版本。因此，XML 标记不是`dependencies`，而是顶层`project`标记中的`ddependencyManagement/dependencies`，如下例所示：

```java
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>packt.java189fundamentals</groupId>
            <artifactId>SortSupportClasses</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>packt.java189fundamentals</groupId>
            <artifactId>SortInterface</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>packt.java189fundamentals</groupId>
            <artifactId>quick</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

当模块要使用`junit`时，不需要指定版本。他们将从定义为 4.12 的父项目中获得它，这是 *junit4* 中的最新版本。如果有一个新版本，4.12.1，修复了一些严重的错误，那么修改版本号的唯一地方就是父 POM，当 Maven 执行下一步时，模块将使用新版本。

然而，当项目开发人员决定使用新的 *JUnit 5* 版本时，所有的模块都会被修改，因为 *JUnit 5* 不仅仅是一个新版本。*junit5* 与老版本 4 有很大的不同，它被分成几个模块。这样，`groupId`和`artifactId`也会改变。

还值得注意的是，实现来自`SortInterface`模块的接口的模块最终依赖于该模块。在这种情况下，版本定义如下：

```java
<version>${project.version}</version>
```

这似乎有点重复（实际上是）。`${project.version}`属性是项目的版本，`SortInterface`模块继承这个值。这是其他模块所依赖的工件的版本。换句话说，模块总是依赖于我们当前开发的版本。

# 编写排序

为了实现排序，首先，我们将定义库应该实现的接口。在实际编码之前定义接口是一种很好的做法。当有许多实现时，有时建议首先创建一个简单的实现并开始使用它，这样接口就可以在这个开发阶段发展，当更复杂的实现到期时，接口就已经固定了。实际上，没有什么是固定的，因为编程中没有阿基米德点。

# 创建接口

本例中的接口非常简单：

```java
public interface Sort {
    void sort(Sortable collection);
}
```

接口应该只做一件事，对可排序的内容进行排序。因此，我们定义了一个接口，实现这个接口的任何类都将是`Sortable`：

```java
public interface Sortable {
}
```

# 创建冒泡排序

现在，我们可以开始创建实现`Sort`接口的冒泡排序：

```java
 ...
import java.util.Comparator;

public class BubbleSort implements Sort, SortSupport {
    @Override
    public void sort(Sortable collection) {
        var n = collection.size();
        while (n > 1) {
            for (int j = 0; j < n - 1; j++) {
                if (comparator.compare(collection.get(j),
                        collection.get(j + 1)) > 0) {
                    swapper.swap(j, j + 1);
                }
            }
            n--;
        }
    }
 ...
```

通常，算法需要两个操作。我们实现了一个比较两个元素并交换两个元素的数组。然而，这次排序实现本身并不知道应该对什么类型进行排序。它也不知道元素是如何存储的。它可以是数组、列表或其他一些。它知道它可以比较元素，而且它还可以交换两个元素。如果提供了这些，那么排序工作。

在 Java 术语中，它需要一个能够比较两个元素的`comparator`对象，需要一个能够交换集合中两个元素的`swapper`对象。

排序对象应该可以访问这些对象。拥有两个引用这些对象的字段是完美的解决方案。唯一的问题是字段如何获得对比较和交换对象的引用。我们现在遵循的解决方案是，我们提供了可以用来将这些依赖项注入排序对象的设置器。

这些设置器并不特定于冒泡排序算法。这些是相当一般的；因此，定义一个冒泡排序可以实现的接口是有意义的：

```java
public interface SortSupport {
    void setSwapper(Swapper swap);

    void setComparator(Comparator compare);
}
```

而`BubbleSort`类中的实现只是以下代码：

```java
    private Comparator comparator = null;

    @Override
    public void setComparator(Comparator comparator) {
        this.comparator = comparator;
    }

    private Swapper swapper = null;

    @Override
    public void setSwapper(Swapper swapper) {
        this.swapper = swapper;
    }
```

`@Override`注解向 Java 编译器发出信号，表示该方法正在覆盖父类的方法，或者在本例中覆盖接口的方法。方法可以覆盖没有此注释的父方法；但是，如果使用注释，如果方法没有覆盖，编译将失败。这有助于您在编译时发现父类或接口中发生了更改，而我们在实现中没有遵循该更改，或者我们只是犯了一个错误，认为我们将覆盖一个方法，而实际上我们没有这样做。由于注释在单元测试中大量使用，我们将在后面更详细地讨论注释。

这也意味着我们需要两个新接口-`Swapper`和`Comparator`。我们很幸运，Java 运行时已经定义了一个正好符合目的的`Comparator`接口。您可能已经从下面的`import`语句中猜到了：

```java
import java.util.Comparator;
```

当您需要一些非常基本的东西时，比如一个`Comparator`接口，它很可能是在运行时定义的。在编写自己的版本之前，最好先查阅运行时。但是，`Swapper`接口必须创建：

```java
public interface Swapper {
    void swap(int i, int j);
}
```

由于它用于交换`Sortable`中索引指定的两个元素，因此有一种方法非常明显地命名为`swap`。但我们还没有准备好。如果您试图编译前面的代码，编译器会抱怨`get`和`get`方法。算法需要它们来实现排序，但它们本身并不是排序本身的一部分。这是不应在排序中实现的功能。由于我们不知道将对哪种类型的集合进行排序，因此在排序中实现这些方法不仅是不可取的，而且也是不可能的。看来我们什么都分类不了。我们必须设置一些限制。排序算法必须知道我们排序的集合的大小，并且还应该通过索引访问元素，以便它可以将其传递给比较器。这些似乎是我们通常可以接受的相当合理的限制。

这些限制在`Sortable`接口中表示，我们刚刚将其留空，在第一个排序实现之前不知道需要什么：

```java
public interface Sortable {
    Object get(int i);
    int size();
}
```

现在，我们已经准备好了接口和实现，可以继续测试代码了。但是，在此之前，我们将简要重申我们所做的以及我们为什么这样做。

# 架构考虑

我们创建了一个接口和一个简单的实现。在实现过程中，我们发现该接口需要支持该算法的其他接口和方法。这通常发生在代码的架构设计期间，在实现之前。出于说教的原因，我在开发代码时遵循了接口的构建。在现实生活中，当我创建接口时，我一步就创建了它们，因为我有足够的经验。我在 1983 年左右用 FORTRAN 编写了第一个快速排序代码。然而，这并不意味着我只是用任何问题来击中靶心，并给出最终的解决方案。碰巧这类问题太有名了。如果在开发过程中需要修改接口或设计的其他方面，请不要感到尴尬。这是一个自然的结果，也是一个证明，随着时间的推移，你对事物的理解会越来越好。如果架构需要更改，那么最好是这样做，而且越快越好。在实际的企业环境中，我们设计接口只是为了在开发过程中了解一些我们忘记的方面。它们的操作比排序集合要复杂一些。

在排序问题的例子中，我们抽象了我们想要排序到最可能的极限的东西。Java 内置的排序可以对数组或列表进行排序。如果要对不是列表或数组的对象进行排序，则必须创建一个类来实现`java.util.List`接口，该接口包含 24 个以上的方法，这些方法用于包装可排序对象，使其可以通过 JDK 排序。24 种方法似乎有很多，只是为了让我们的*变得有点*可分性。老实说，这并不是太多，在一个真实的项目中，我会把它作为一个选择。

我们不知道，也不知道，内置排序使用什么接口方法。那些应该在功能上实现的语句被使用，而那些语句可以包含一个简单的`return`语句，因为它们从未被调用，所以没有被使用。开发人员可以查阅 JDK 的源代码并查看实际使用的方法，但这不是搜索实现的契约。不能保证新版本仍然只使用这些方法。如果一个新版本开始使用我们用一个`return`语句实现的方法，排序将神奇地失败。

另外一个有趣的性能问题是，如何通过只使用`List`接口的搜索来实现两个元素的交换。`List`接口中没有`put(int, Object)`方法。有`add(int, Object)`，但它插入了一个新元素，如果对象存储在磁盘上，那么将列表中的所有元素向上推可能会非常昂贵（消耗 CPU、磁盘、能量）。此外，下一步可能是删除我们刚刚插入的元素之后的元素，再次移动列表尾部的代价高昂。这就是`put(int, Object)`的琐碎实现。排序可能跟在后面，也可能跟不上。同样，这是不应该假设的。

当您使用来自 JDK、开源或商业库的库、类和方法时，您可以参考源代码，但不应依赖于实现。您应该只依赖于该库附带的 API 的契约和定义。当您从某个外部库实现一个接口时，您不需要实现它的某些部分，也不需要创建一些虚拟方法，您会感到危险。这是埋伏。很可能是库质量不好，或者你不知道如何使用它。我不知道哪个更糟。

在我们的例子中，我们将交换和比较与排序分开。集合应该实现这些操作并为排序提供它们。契约就是接口，要使用排序，必须实现我们定义的接口的所有方法。

`SortSupport`的接口定义了设置`Swapper`和`Comparator`的设置器。以这种方式设置依赖项可能会导致代码创建实现`Sort`和`SortSupport`接口的类的新实例，但在调用`Sort`之前不设置`Swapper`和`Comparator`。这将导致在第一次调用`Comparator`时调用`NullPointerException`（或者在实现首先调用`Swapper`时调用`Swapper`，这不太可能，但可能）。调用方法应该在使用类之前注入依赖项。通过设定器进行时，称为**设置器注入**。当我们使用诸如 Spring、Guice 或其他容器之类的框架时，大量使用这个术语。创建这些服务类并将实例注入到我们的类中一直是相当相似的。

容器实现以一般方式包含功能，并提供配置选项来配置要注入到其他对象中的实例。通常，这会导致代码更短、更灵活、更可读。然而，依赖注入并不是容器独有的。当我们在下一节中编写测试代码并调用设置器时，实际上是手动执行依赖注入。

还有另一种依赖注入方法可以避免未设置依赖的问题。这叫做**构造器注入**。在这种情况下，依赖项通常是没有值的`final private`字段。请记住，这些字段应在对象完全创建时获得其最终值。构造器注入将注入的值作为参数传递给构造器，构造器设置字段。这样，就可以保证在构建对象时设置字段。但是，这种注入不能在接口中定义，这在某些应用中可能是问题，也可能不是问题。

现在，我们已经有了代码，并且我们知道如何创建接口。是时候做些测试了。

# 创建单元测试

当我们编写代码时，我们应该测试它。至少在进行一些测试运行之前，还没有任何代码进入生产环境。（承认讽刺！）不同级别的测试有不同的目标、技术、行业实践和名称。

顾名思义，单元测试测试一个代码单元。集成测试测试单元如何集成在一起。冒烟测试测试一组有限的特性，只是为了看看代码是否完全被破坏。还有其他的测试，直到最后的测试，这是用户验收测试工作的证明。布丁的证据就在吃的时候。如果用户接受代码，那么代码就是好的。

很多时候，我告诉年轻人，名称“用户验收测试”有点误导，因为接受项目结果的不是用户，而是客户。顾名思义，顾客就是付账的人。专业发展是有报酬的，否则就不专业了。然而，术语是用户验收测试。碰巧的是，只有用户能够使用这个程序，客户才会接受这个项目。

当我们用 Java 开发时，单元测试测试独立类。换句话说，在 Java 开发中，当我们讨论单元测试时，单元是一个类。为了提供单元测试，我们通常使用 JUnit 库。还有其他的库，比如 TestNG，但是 JUnit 是使用最广泛的库，所以我们将使用 *JUnit*。要将它用作库，首先，我们必须将它作为依赖项添加到 Maven POM 中。

# 添加 JUnit 作为依赖项

回想一下，我们有一个多模块项目，依赖版本在父 POM 中的`dependencyManagement`标记中维护：

```java
<dependencyManagement>
    <dependencies>
        ...
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

依赖关系的范围是`test`，这意味着只有在编译测试代码和执行测试时才需要这个库。JUnit 库不会进入最终发布的产品；不需要它。如果在已部署的生产 **Web 存档**（**WAR**）或**企业存档**（**EAR**）文件中发现 JUnit 库，请怀疑有人没有正确管理库的范围。

Maven 支持在项目生命周期中编译和执行 JUnit 测试。如果我们只想执行测试，我们应该发出`mvn test`命令。IDEs 还支持执行单元测试。通常，可以使用相同的菜单项来执行具有`public static main()`方法的类。如果该类是一个使用 JUnit 的单元测试，IDE 将识别它并执行测试，并且通常给出图形化的反馈，说明哪些测试执行得很好，哪些测试失败，以及如何执行。

# 编写`BubbleSortTest`类

测试类与生产类分开。他们进入`src/test/java`目录。当我们有一个名为`BubbleSort`的类时，那么测试将被命名为`BubbleSortTest`。此约定有助于执行环境将测试与不包含测试但执行测试所需的类分开。为了测试我们刚刚创建的排序实现，我们可以提供一个类，该类目前只包含一个`canSortStrings`方法。

单元测试方法名称用于记录正在测试的功能。由于 JUnit 框架调用每个具有`@Test`注解的方法，因此测试的名称在我们的代码中不会被引用。我们可以大胆地使用任意长的方法名；它不会妨碍调用方法的地方的可读性：

```java
package packt.java189fundamentals.ch03.main.bubble.simple;

// import statements are deleted from the print for brevity

public class BubbleSortTest {
    @Test
    public void canSortStrings() {
        var actualNames = new ArrayList(Arrays.asList(
            "Johnson", "Wilson",
            "Wilkinson", "Abraham", "Dagobert"
        ));
```

该方法包含一个`ArrayList`，其中包含我们已经熟悉的实际名称。由于我们有一个需要`Sortable`的排序实现和接口，我们将创建一个由`ArrayList`备份的排序实现和接口：

```java
var names = new Sortable() {
    @Override
    public Object get(int i) {
        return actualNames.get(i);
    }
    @Override
    public int size() {
        return actualNames.size();
    }
};
```

我们声明了一个新对象，它具有`Sortable`类型，它是一个接口。要实例化实现`Sortable`的东西，我们需要一个类。我们无法实例化接口。在这种情况下，在实例化的位置定义类。这在 Java 中称为匿名类。名称来自于源代码中未定义新类的名称。Java 编译器将自动为新类创建一个名称，但这对程序员来说并不有趣。我们只需写`new Sortable()`并在`{`到`}`之间立即提供所需的实现。在方法中定义这个匿名类非常方便，这样，它可以访问`ArrayList`，而不需要在类中传递对`ArrayList`的引用。

事实上，引用是需要的，但是 Java 编译器会自动补全这项工作。在本例中，Java 编译器还注意到，以这种方式传递的自动引用只能使用初始化的变量来完成，并且在匿名类实例化之后的代码执行期间不会更改。`actualNames`变量已设置，以后方法中不应更改。事实上，我们甚至可以将`actualNames`定义为`final`，如果我们使用 Java1.7 或更早版本，这将是一个要求。从 1.8 开始，要求变量实际上是`final`，我们可以跳过`final`声明。

接下来我们需要的是`ArrayList`的`Swapper`实现。在这种情况下，我们将在方法中定义一个完整的类。它也可以是一个匿名类，但这次我决定使用一个命名类来演示一个类可以在一个方法中定义。通常，我们在生产项目中不会这样做：

```java
class SwapActualNamesArrayElements implements Swapper {
    @Override
    public void swap(int i, int j) {
        final Object tmp = actualNames.get(i);
        actualNames.set(i, actualNames.get(j));
        actualNames.set(j, tmp);
    }
}
;
```

最后，但并非最不重要的是，在调用排序之前，我们需要一个比较器。正如我们有`String`要比较的，这是简单而直接的：

```java
Comparator stringCompare = new Comparator() {
    @Override
    public int compare(Object first, Object second) {
        final String f = (String) first;
        final String s = (String) second;
        return f.compareTo(s);
    }
};
```

在为排序做了一切准备之后，我们最终需要一个`Sort`实现的实例。我们必须设置`Sort`和`Sort`，最后调用`sort`：

```java
var sort = new BubbleSort();
sort.setComparator(stringCompare);
sort.setSwapper(new SwapActualNamesArrayElements());
sort.sort(names);
```

测试的最后但最重要的部分是断言结果是我们期望的结果。JUnit 在`Assert`类的帮助下帮助我们做到这一点：

```java
Assert.assertEquals(List.of(
    "Abraham", "Dagobert",
    "Johnson", "Wilkinson", "Wilson"
), actualNames);
```

对`assertEquals`的调用检查第一个参数，即预期结果，是否等于第二个参数，即排序后的`actualNames`。如果它们不同，则抛出一个`AssertionError`，否则，测试就可以结束了。

# 良好的单元测试

这是一个好的单元测试吗？如果你在这样一本教程里读到它，那一定是。其实不是。这是一个很好的代码来演示 JUnit 提供的一些工具和一些 Java 语言特性，但我不会在专业项目中使用它。

什么使单元测试好？为了回答这个问题，我们必须定义单元测试的用途。单元测试有两个目的。单元测试的目的是验证单元的正确功能并记录它。

单元测试不用于发现 bug。开发人员最终会在调试会话期间使用单元测试，但很多时候，为调试创建的测试代码是临时的。当 bug 修复后，用于查找它的代码将不会进入源代码存储库。对于每一个新的 bug，都应该创建一个新的测试来覆盖不能正常工作的功能，但是很难使用测试代码来查找 bug。这是因为单元测试主要用于文档。您可以使用 *JavaDoc* 对类进行文档化，但经验表明，文档化常常会过时。开发人员修改代码，但不修改文档。文件变得过时和具有误导性。然而，单元测试是由构建系统执行的，如果**持续集成**（**CI**）正在使用（在专业环境中应该是这样），那么如果测试失败，构建将被破坏。所有的开发人员都会收到一封关于它的邮件通知，它会促使开发人员破坏构建来修复代码或测试。通过这种方式，测试在持续集成过程中验证代码没有被破坏，至少，没有使用单元测试可以发现的东西。

# 一个好的单元测试是可读的

我们的测试远没有可读性。一个测试用例是可读的，如果你看它，在 15 秒内你可以告诉它做什么。当然，它假设读者有一些 Java 方面的经验，但你明白这一点。我们的测试充斥着不是测试核心的支持类。

我们的测试也很难验证代码是否正常工作。实际上没有。其中有一些我故意放在那里的 bug，我们将在下面几节中找到并消除它们。对单个`String`数组进行排序的单个测试远远不能验证排序实现。如果我要将这个测试扩展到一个真实世界的测试，我们需要名称为`canSortEmptyCollection`、`canSortOneElementCollection`、`canSortTwoElements`、`canSortReverseOrder`或`canSortAlreadySorted`的方法。如果你看这些名字，你就会知道我们需要什么样的测试。由于排序问题的性质，实现可能对这些特殊情况下的错误相当敏感。

除了作为一个可接受的演示工具之外，我们的单元测试还有哪些优点？

# 单元测试很快

我们的单元测试运行得很快。当我们每次执行单元测试时，CI 启动一个构建，测试的执行不会持续太久。您不应该创建一个对数十亿个元素进行排序的单元测试。这是一种稳定性试验或负荷试验。它们应该在单独的测试期间运行，而不是每次构建运行时都运行。我们的单元测试对五个元素进行排序，这是合理的。

# 单元测试是确定性的

我们的单元测试是确定性的。不确定性单元测试是开发人员的噩梦。如果您所在的组中有一些构建在 CI 服务器上中断，而当一个构建中断时，您的开发伙伴会说您只需再试一次；不可能！如果单元测试运行，它应该一直运行。如果失败了，不管你启动它多少次，它都应该失败。在我们的例子中，一个不确定的单元测试是呈现随机数并对它们进行排序。它最终会在每个测试运行中使用不同的数组，并且，如果代码中出现了一些针对某个数组的 bug，我们将无法重现它。更不用说确保代码正常运行的断言也很难产生。

如果我们在单元测试中对一个随机数组进行排序（我们没有这样做），我们可以假设，断言该数组已排序，逐个比较元素，检查它们是否按升序排列。这也是完全错误的做法。

# 断言应该尽可能简单

如果断言很复杂，那么在断言中引入 bug 的风险会更高。断言越复杂，风险就越高。我们编写单元测试以简化我们的生活，而不是有更多的代码需要调试。

另外，一个测试应该只断言一件事。这个断言可以用多个`Assert`类方法进行编码，一个接着一个。尽管如此，这些功能的目的是维护单元的一个单一特性的正确性。

记住 SRP 一个测试，一个特性。一个好的测试就像一个好的狙击手一枪一杀。

# 单元测试是孤立的

当我们测试一个单元`a`时，另一个单元`B`中的任何更改或不同单元中的错误都不应影响我们对该单元`a`的单元测试。在我们的情况下，这很容易，因为我们只有一个单位。稍后，当我们为快速排序开发测试时，我们将看到这种分离并不是那么简单。

如果单元测试正确地分开，那么失败的单元测试会清楚地指出问题所在。在单元测试失败的单元中。如果测试没有将单元分开，那么一个测试中的失败可能是由不同单元中的 bug 引起的。在这种情况下，这些测试并不是真正的单元测试。

在实践中，你应该保持平衡。如果单元的隔离成本太高，您可以决定创建集成测试；如果它们仍然运行得很快，则由 *CI 系统*执行它们。同时，你也应该试着找出为什么隔离很难。如果在测试中不能很容易地隔离单元，则意味着单元之间的耦合太强，这可能不是一个好的设计。

# 单元测试涵盖了代码

单元测试应该测试功能的所有常规和特殊情况。如果有一种特殊情况的代码没有被单元测试覆盖，那么代码就处于危险之中。在排序实现的情况下，一般情况是排序，比如说，五个元素。特殊情况通常要多得多。如果只有一个元素或者没有元素，我们的代码是如何工作的？如果有两个呢？如果元素的顺序相反呢？如果已经分类了呢？

通常，规范中没有定义特殊情况。程序员在编写代码之前必须考虑这个问题，在编写代码的过程中会发现一些特殊的情况。困难的是，你只是无法判断你是否涵盖了所有的特殊情况和代码的功能。

您可以判断的是是否所有的代码行都是在测试期间执行的。如果 90% 的代码行是在测试期间执行的，那么代码覆盖率是 90%，这在现实生活中是相当好的，但是您永远不应该满足于任何低于 100% 的内容。

代码覆盖率与功能覆盖不相同，但存在相关性。如果代码覆盖率小于 100%，则以下两个语句中至少有一条为真：

*   功能覆盖率不是 100%。
*   测试单元中有一个未使用的代码，可以直接删除。

代码覆盖率可以测量，但功能覆盖率却无法合理地进行测量。工具和 IDE 支持代码覆盖率测量。这些测量值集成到编辑器中，这样您不仅可以获得覆盖率，而且编辑器将精确地显示覆盖着色行（例如 Eclipse 中）或编辑器窗口左侧的边沟（IntelliJ）中未覆盖哪些行。以下截图显示，在 IntelliJ 中，测试覆盖了檐沟上绿色指示的线条（在打印版本中，这只是一个灰色矩形）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/fa86348e-53d3-4375-a989-902a07ae18cb.png)

# 重构测试

现在我们已经讨论了什么是好的单元测试，让我们改进一下测试。第一件事是将支持类移动到单独的文件中。我们将创建`ArrayListSortable`：

```java
package packt.java189fundamentals.ch03.main.bubble.simple;

import packt.java189fundamentals.ch03.Sortable;

import java.util.ArrayList;

public class ArrayListSortable implements Sortable {
    final private ArrayList actualNames;

    ArrayListSortable(ArrayList actualNames) {
        this.actualNames = actualNames;
    }

    @Override
    public Object get(int i) {
        return actualNames.get(i);
    }

    @Override
    public int size() {
        return actualNames.size();
    }
}
```

这个类封装了`ArrayList`，然后实现了`gets`和`size`方法对`ArrayList`的访问。`ArrayList`本身声明为`final`。回想一下，`final`字段必须在构造器完成时定义。这保证了当我们开始使用对象时字段就在那里，并且在对象生存期内它不会改变。然而，注意，对象的内容，在这种情况下，`ArrayList`的元素可以改变。如果不是这样的话，我们就无法整理它。

下一个类是`StringComparator`。这非常简单，我不在这里列出它；我将把它留给您来实现可以比较两个`Strings`的`java.util.Comparator`接口。这应该不难，特别是因为这个类已经是以前版本的`BubbleSortTest`类的一部分（提示这是一个匿名类，我们存储在名为`stringCompare`的变量中）。

我们还必须实现`ArrayListSwapper`，这也不应该是一个很大的惊喜：

```java
package packt.java189fundamentals.ch03.main.bubble.simple;

import packt.java189fundamentals.ch03.Swapper;

import java.util.ArrayList;

public class ArrayListSwapper implements Swapper {
    final private ArrayList actualNames;

    ArrayListSwapper(ArrayList actualNames) {
        this.actualNames = actualNames;
    }

    @Override
    public void swap(int i, int j) {
        Object tmp = actualNames.get(i);
        actualNames.set(i, actualNames.get(j));
        actualNames.set(j, tmp);
    }
}
```

最后，我们的测试如下：

```java
@Test
public void canSortStrings2() {
    var actualNames = new ArrayList(List.of(
        "Johnson", "Wilson",
        "Wilkinson", "Abraham", "Dagobert"
    ));
    var expectedResult = List.of(
        "Abraham", "Dagobert",
        "Johnson", "Wilkinson", "Wilson"
    );
    var names = new ArrayListSortable(actualNames);
    var sort = new BubbleSort();
    sort.setComparator(new StringComparator());
    sort.setSwapper(new ArrayListSwapper(actualNames));
    sort.sort(names);
    Assert.assertEquals(expectedResult, actualNames);
}
```

现在，这已经是一个可以在 15 秒内理解的测试了。它很好地记录了如何使用我们定义的某种实现。到目前为止，它仍在运行，没有发现任何 bug。

# 包含错误元素的集合

bug 并不简单，而且与往常一样，这不是算法的实现，而是在定义上，或者缺少它。如果我们排序的集合中不仅有字符串，程序应该怎么做？

如果我创建一个以以下行开始的新测试，它将抛出`ClassCastException`：

```java
@Test(expected = ClassCastException.class)
public void canNotSortMixedElements() {
    var actualNames = new ArrayList(Arrays.asList(
        42, "Wilson",
        "Wilkinson", "Abraham", "Dagobert"
    ));
    //... the rest of the code is the same as the previous test
```

这里的问题是 Java 集合可以包含任何类型的元素。您永远无法确定一个集合，例如`ArrayList`，只包含您期望的类型。即使您使用泛型（我们将在本章中了解），出现此类错误的可能性也较小，但它仍然存在。别问我怎么做，我不能告诉你。这就是虫子的本质，除非你消灭它们，否则你无法知道它们是如何工作的。问题是你必须为这种特殊情况做好准备。

# 异常处理

异常情况应该使用异常在 Java 中处理。`ClassCastException`在那里，当排序尝试使用`StringComparator`比较`String`和`Integer`时，就会发生这种情况，为此，它尝试将`Integer`转换为`String`。

当程序使用`throw`命令或 Java 运行时抛出异常时，程序的执行将在该点停止，而不是执行下一个命令，而是在捕获异常的地方继续。它可以在同一个方法中，也可以在调用链中的某个调用方法中。要捕获异常，抛出异常的代码应该在一个`try`块中，`try`块后面的`catch`语句应该指定一个与抛出的异常兼容的异常。

如果没有捕获到异常，那么 Java 运行时将打印出异常消息以及栈跟踪，该跟踪将包含异常发生时调用栈上的所有类、方法和行号。在我们的例子中，如果我们移除`@Test`注解的`(expected = ClassCastException.class)`参数，测试执行将在输出中产生以下跟踪：

```java
packt.java189fundamentals.ch03.main.bubble.simple.NonStringElementInCollectionException: There are mixed elements in the collection.

        at packt.java189fundamentals.ch03.main.bubble.simple.StringComparator.compare(StringComparator.java:13)
        at packt.java189fundamentals.ch03.main.bubble.BubbleSort.sort(BubbleSort.java:17)
        at packt.java189fundamentals.ch03.main.bubble.simple.BubbleSortTest.canNotSortMixedElements(BubbleSortTest.java:108)
        at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.base/java.lang.reflect.Method.invoke(Method.java:564)
        at org.junit.runners.model.FrameworkMethod$1.runReflectiveCall(FrameworkMethod.java:50)
        at org.junit.internal.runners.model.ReflectiveCallable.run(ReflectiveCallable.java:12)
        at org.junit.runners.model.FrameworkMethod.invokeExplosively(FrameworkMethod.java:47)
        at org.junit.internal.runners.statements.InvokeMethod.evaluate(InvokeMethod.java:17)
        at org.junit.runners.ParentRunner.runLeaf(ParentRunner.java:325)
        at org.junit.runners.BlockJUnit4ClassRunner.runChild(BlockJUnit4ClassRunner.java:78)
        at org.junit.runners.BlockJUnit4ClassRunner.runChild(BlockJUnit4ClassRunner.java:57)
        at org.junit.runners.ParentRunner$3.run(ParentRunner.java:290)
        at org.junit.runners.ParentRunner$1.schedule(ParentRunner.java:71)
        at org.junit.runners.ParentRunner.runChildren(ParentRunner.java:288)
        at org.junit.runners.ParentRunner.access$000(ParentRunner.java:58)
        at org.junit.runners.ParentRunner$2.evaluate(ParentRunner.java:268)
        at org.junit.runners.ParentRunner.run(ParentRunner.java:363)
        at org.junit.runner.JUnitCore.run(JUnitCore.java:137)
        at com.intellij.junit4.JUnit4IdeaTestRunner.startRunnerWithArgs(JUnit4IdeaTestRunner.java:68)
        at com.intellij.rt.execution.junit.IdeaTestRunner$Repeater.startRunnerWithArgs(IdeaTestRunner.java:47)
        at com.intellij.rt.execution.junit.JUnitStarter.prepareStreamsAndStart(JUnitStarter.java:242)
        at com.intellij.rt.execution.junit.JUnitStarter.main(JUnitStarter.java:70)
Caused by: java.lang.ClassCastException: java.base/java.lang.Integer cannot be cast to java.base/java.lang.String
        at packt.java189fundamentals.ch03.main.bubble.simple.StringComparator.compare(StringComparator.java:9)
        ... 24 more
```

这个栈跟踪实际上并不长。在生产环境中，在应用服务器上运行的应用中，栈跟踪可能包含几百个元素。在这个跟踪中，您可以看到 IntelliJ 正在启动涉及 JUnitRunner 的测试执行，直到我们完成了对比较器的测试，在那里抛出了实际的异常。

这种方法的问题是，真正的问题不是类铸造失败。真正的问题是集合包含混合元素。只有当 Java 运行时试图强制转换两个不兼容的类时，它才能实现。我们的代码可以更智能。我们可以修改比较器：

```java
public class StringComparator implements Comparator {

    @Override
    public int compare(Object first, Object second) {
        try {
            final String f = (String) first;
            final String s = (String) second;
            return f.compareTo(s);
        } catch (ClassCastException cce) {
            throw new NonStringElementInCollectionException(
                "There are mixed elements in the collection.", cce);
        }
    }
}
```

此代码捕获`ClassCastException`并抛出一个新的。抛出一个新异常的好处是，您可以确定这个异常是从比较器抛出的，问题是集合中确实存在混合元素。类转换问题也可能发生在代码的其他地方。一些应用代码可能希望捕获异常并处理该情况；例如，发送特定于应用的错误消息，而不是仅向用户转储栈跟踪。此代码也可以捕获`ClassCastException`，但无法确定异常的真正原因是什么。另一方面，`NonStringElementInCollectionException`是确定的。

`NonStringElementInCollectionException`是 JDK 中不存在的异常。我们必须创造它。异常是 Java 类，我们的异常如下：

```java
package packt.java189fundamentals.ch03.main.bubble.simple;

public class NonStringElementInCollectionException extends RuntimeException {
    public NonStringElementInCollectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

Java 有检查异常的概念。这意味着任何不扩展`RuntimeException`（直接或间接）的异常都应该在方法定义中声明。假设我们的异常声明如下：

```java
package packt.java189fundamentals.ch03.main.bubble.simple;

public class NonStringElementInCollectionException extends Exception {
    public NonStringElementInCollectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

然后，我们可以声明`compare`方法如下：

```java
public int compare(Object first, Object second) throws NonStringElementInCollectionException
```

问题是方法抛出的异常是方法签名的一部分，这样，`compare`就不会覆盖接口的`compare`方法，这样类就不会实现`Comparator`接口。因此，我们的异常必须是运行时异常。

应用中可能有一个异常层次结构，新手程序员通常会创建它们的巨大层次结构。如果你有什么可以做的，并不意味着你应该做。层次结构应该尽可能保持平坦，对于异常情况尤其如此。如果 JDK 中有一个异常描述了您的异常情况，那么使用现成的异常。如果它已经准备好，那么它也同样适用于任何其他类，不要再次实现它。

同样重要的是要注意，抛出异常只能在异常情况下进行。它不是用来表示一些正常的操作条件。这样做会妨碍代码的可读性，也会消耗 CPU。对于 JVM 来说，抛出异常不是一件容易的事情。

它不仅仅是一个可以抛出的异常。`throw`命令可以抛出，`catch`命令可以捕获扩展`Throwable`类的任何内容。`Throwable`-`Error`和`Exception`有两个子类。如果在 Java 代码执行过程中发生错误，则抛出一个`Error`。最臭名昭著的两个错误是`OutOfMemoryError`和`StackOverflowError`。如果其中任何一个发生了，你就不能可靠地抓住他们。

JVM 中也有`InternalError`和`UnknownError`，但是由于 JVM 相当稳定，您几乎不会遇到这些错误。

通过这种方式，当一些程序员意外地在名称中写入 42 个时，我们处理了这种特殊情况，但是如果在编译时识别错误会更好吗？为此，我们将引入泛型。

在我们去那里之前最后一个想法。我们用`canNotSortMixedElements`单元测试测试什么样的类行为？测试在`BubbleSortTest`测试类中，但功能在比较器实现`StringComparator`中。此测试检查超出单元测试类范围的内容。我可以用它来演示，但这不是一个单元测试。排序实现的真正功能可以用这种方式形式化，无论排序实现抛出什么样的异常，比较器都会抛出什么样的异常。您可以尝试编写这个单元测试，或者继续阅读；我们将在下一节中介绍它。

`StringComparator`类没有测试类，因为`StringComparator`是测试的一部分，我们永远不会为测试编写测试。否则，我们将陷入一个无尽的兔子洞。

# 泛型

泛型特性在版本 5 中被引入到 Java 中。从一个例子开始，到目前为止，我们的`Sortable`接口是这样的：

```java
public interface Sortable {
    Object get(int i);
    int size();
}
```

在引入泛型之后，它将如下所示：

```java
package packt.java189fundamentals.ch03.generic;

public interface Sortable<E> {
    E get(int i);
    int size();
}
```

`E`标识符表示一种类型。它可以是任何类型。如果类实现了接口，即两个方法-`size`和`get`，那么它就是一个可排序的集合。`get`方法应该返回`E`类型的内容，不管`E`是什么。到目前为止，这可能还不太合理，但你很快就会明白重点。毕竟，泛型是一个困难的话题。

`Sort`接口如下：

```java
package packt.java189fundamentals.ch03.generic;

public interface Sort<E> {
    void sort(Sortable<E> collection);
}
```

`SortSupport`变为：

```java
package packt.java189fundamentals.ch03.generic;

import packt.java189fundamentals.ch03.Swapper;

import java.util.Comparator;

public interface SortSupport<E> {
    void setSwapper(Swapper swap);

    void setComparator(Comparator<E> compare);
}
```

这仍然没有提供比没有泛型的前一个版本更多的澄清，但是，至少，它做了一些事情。在实现`Sort`接口的实际类中，`Comparator`应该接受`Sortable`使用的相同类型。不可能`Sortable`对`Strings`起作用，我们为`Integers`注入了一个比较器。

`BubbleSort`的实现如下：

```java
package packt.java189fundamentals.ch03.main.bubble.generic;

// ... imports were removed from printout ...

public class BubbleSort<E> implements Sort<E>, SortSupport<E> {
    private Comparator<E> comparator = null;
    private Swapper swapper = null;

    @Override
    public void sort(Sortable<E> collection) {
        var n = collection.size();
        while (n > 1) {
            for (int j = 0; j < n - 1; j++) {
                if (comparator.compare(collection.get(j),
                        collection.get(j + 1)) > 0) {
                    swapper.swap(j, j + 1);
                }
            }
            n--;
        }
    }

    @Override
    public void setComparator(Comparator<E> comparator) {
        this.comparator = comparator;
    }

    @Override
    public void setSwapper(Swapper swapper) {
        this.swapper = swapper;
    }
}
```

泛型的真正威力将在我们编写测试时显现。第一个测试没有太大变化，不过，对于泛型，它更明确：

```java
    @Test
    public void canSortStrings() {
        var actualNames = new ArrayList<>(List.of(
            "Johnson", "Wilson",
            "Wilkinson", "Abraham", "Dagobert"
        ));
        var expectedResult = List.of(
            "Abraham", "Dagobert",
            "Johnson", "Wilkinson", "Wilson"
        );
        Sortable<String> names =
            new ArrayListSortable<>(actualNames);
        var sort = new BubbleSort<String>();
        sort.setComparator(String::compareTo);
        sort.setSwapper(new ArrayListSwapper<>
        (actualNames));
        sort.sort(names);
        Assert.assertEquals(expectedResult, 
        actualNames);
    }
```

当我们定义`ArrayList`时，我们还将声明列表中的元素将是字符串。当我们分配新的`ArrayList`时，不需要再次指定元素是字符串，因为它来自那里的实际元素。每一个字符都是一个字符串；因此，编译器知道唯一可以位于`<`和`<`字符之间的是`String`。

两个字符`<`和`<`之间没有类型定义，称为**菱形运算符**。类型是推断的。如果您习惯了泛型，那么这段代码将为您带来有关集合所处理的类型的更多信息，代码的可读性也将提高。可读性和额外的信息不是唯一的问题。

我们知道，`Comparator`参数现在是`Comparator<String>`，我们可以利用自 Java8 以来 Java 的高级特性，将`String::compareTo`方法引用传递给比较器设置器。

第二个测试对我们现在来说很重要。这是确保`Sort`不干扰比较器抛出的异常的测试：

```java
 1\. @Test
 2\. public void throwsWhateverComparatorDoes() {
 3\.     final ArrayList<String> actualNames =
 4\.         new ArrayList<>(List.of(
 5\.             42, "Wilson"
 6\.         ));
 7\.     final var names = new ArrayListSortable<>
        (actualNames);
 8\.     final var sort = new BubbleSort<>();
 9\.     final var exception = new RuntimeException();
10\.     sort.setComparator((a, b) -> {
11\.         throw exception;
12\.     });
13\.     final Swapper neverInvoked = null;
14\.     sort.setSwapper(neverInvoked);
15\.     try {
16\.         sort.sort(names);
17\.     } catch (Exception e) {
18\.         Assert.assertSame(exception, e);
19\.         return;
20\.     }
21\.     Assert.fail();
22\. }
```

问题是，它甚至不编译。编译器说它不能推断第四行的`ArrayList<>`类型。当`asList`方法的所有参数都是字符串时，该方法返回一个`String`元素列表，因此新操作符生成`ArrayList<String>`。这一次，有一个整数，因此编译器无法推断出`ArrayList<>`是针对`String`元素的。

将类型定义从`ArrayList<>`更改为`ArrayList<String>`并不是解决方法。在这种情况下，编译器将抱怨值`42`。这就是泛型的力量。当您使用具有类型参数的类时，编译器可以检测您何时提供了错误类型的值。要将值放入`ArrayList`以检查实现是否真的抛出异常，我们必须将值放入其中。我们可以尝试用一个空的`String`替换值`42`，然后添加下面的行，它仍然不会编译：

```java
actualNames.set(0,42);
```

编译器仍然会知道您要在`ArrayList`中设置的值应该是`String`。要获得带有`Integer`元素的数组，你必须明确地解锁安全手柄并扣动扳机，射击自己：

```java
((ArrayList)actualNames).set(0,42);
```

我们不这样做，即使是为了考试。我们不想测试 JVM 是否识别出一个`Integer`不能转换为一个`String`。该测试由不同的 Java 实现完成。我们真正测试的是，无论比较器抛出什么异常，`sort`都会抛出相同的异常。

现在，测试如下：

```java
@Test
public void throwsWhateverComparatorDoes() {
    final var actualNames =
        new ArrayList<>(List.of(
            "", "Wilson"
        ));
    final var names = new ArrayListSortable<>(actualNames);
    final var sort = new BubbleSort<>();
    final var exception = new RuntimeException();
    sort.setComparator((a, b) -> {
        throw exception;
    });
    final Swapper neverInvoked = null;
    sort.setSwapper(neverInvoked);
    try {
        sort.sort(names);
    } catch (Exception e) {
        Assert.assertSame(exception, e);
        return;
    }
    Assert.fail();
}
```

现在，我们将变量`actualNames`的声明更改为`var`，以便从右侧表达式推断类型。在这种情况下，它是`ArrayList<String>`，泛型`String`参数是从调用`List.of()`创建的列表中推断出来的。此方法也有泛型参数，因此我们可以编写`List.<String>of()`。但是，在这个调用中，这个泛型参数是从参数中推断出来的。所有参数都是字符串，因此返回的列表是`List<String>`。在上一个未编译的示例中，创建的列表具有类型`List<Object>`。这与左侧的声明不兼容，编译器对此表示不满。如果我们使用`var`作为变量声明，编译器此时无法检测到此错误，我们将使用`List<Object>`变量而不是`List<String>`。

我们将交换程序设置为`null`，因为它从未被调用。当我第一次写这段代码的时候，这对我来说是显而易见的。几天后，我读了代码，就停了下来。“为什么交换器为空？”过了一两秒钟我就想起来了。但是任何时候，当阅读和理解代码时，我都倾向于考虑重构。我可以在一行中添加一条注释，上面写着`//never invoked`，但注释往往会保留在那里，即使功能发生了变化。我在 2006 年艰难地学会了这一点，当时一个错误的注释使我无法看到代码是如何执行的。我是在调试时阅读注释的，而不是代码，在系统关闭时修复错误花了两天时间。我倾向于使用使代码表达所发生的事情的结构，而不是注释。额外的变量可能会使类文件变大几个字节，但它是由 JIT 编译器优化的，因此最终的代码不会运行得较慢。

抛出异常的比较器是作为 Lambda 表达式提供的。Lambda 表达式可以用于匿名类或命名类只有一个简单方法的情况。Lambda 表达式是匿名方法，存储在变量中或传入参数以供以后调用。我们将在第 8 章中讨论 Lambda 表达式的细节，“扩展我们的电子商务应用”。

现在，我们将继续实现`QuickSort`，为此，我们将使用 TDD 方法。

# 测试驱动开发

TDD 是一种代码编写方法，开发人员首先根据规范编写测试，然后编写代码。这与开发者社区所习惯的恰恰相反。我们遵循的传统方法是编写代码，然后为其编写测试。老实说，真正的做法是编写代码并用临时测试进行测试，而根本不使用单元测试。作为一个专业人士，你永远不会那么做，顺便说一句。你总是写测试。（现在，把它写一百遍——我会一直写测试。）

TDD 的优点之一是测试不依赖于代码。由于代码在创建测试时不存在，开发人员不能依赖单元的实现，因此，它不能影响测试创建过程。这通常是好的。单元测试应该尽可能采用黑盒测试。

黑盒测试是不考虑被测系统实现的测试。如果一个系统被重构，以不同的方式实现，但是它提供给外部世界的接口是相同的，那么黑盒测试应该可以正常运行。白盒测试取决于被测系统的内部工作情况。当代码更改白盒测试时，可能还需要对代码进行调优以跟踪更改。白盒测试的优点是测试代码更简单。不总是这样。灰盒测试是两者的混合。

单元测试应该是黑盒测试，但是，很多时候，编写黑盒测试并不简单。开发人员会编写一个他们认为是黑匣子的测试，但很多时候，这种想法被证明是错误的。当实现发生变化时，一些东西被重构，测试不再工作，需要进行纠正。开发人员，尤其是编写单元的开发人员，在了解实现的情况下，会编写一个依赖于代码内部工作的测试。在编写代码之前编写测试是防止这种情况的一种工具。如果没有代码，就不能依赖它。

TDD 还说开发应该是一种迭代的方法。一开始只写一个测试。如果你跑，它就会失败。当然，它失败了！由于还没有代码，它必须失败。然后，您将编写完成此测试的代码。没有更多，只有使这个测试通过的代码。然后，您将继续为规范的另一部分编写新的测试。你将运行它，但它失败了。这证明新的测试测试了一些尚未开发的东西。然后，您将开发代码以满足新的测试，并且可能还将修改在以前的迭代中已经编写的代码块。当代码准备就绪时，测试将通过。

很多时候，开发人员不愿意修改代码。这是因为他们害怕打破已经在工作的东西。当你遵循 TDD，你不应该，同时，你不必害怕这一点。所有已经开发的特性都有测试。如果某些代码修改破坏了某些功能，测试将立即发出错误信号。关键是在修改代码时尽可能频繁地运行测试。

# 实现快速排序

正如我们已经讨论过的，快速排序由两个主要部分组成。一个是分区，另一个是递归地进行分区，直到整个数组被排序。为了使我们的代码模块化并准备好演示 JPMS 模块处理特性，我们将把分区和递归排序开发成单独的类和单独的包。代码的复杂性不能证明这种分离是合理的。

# 分区类

分区类应该提供一个基于枢轴元素移动集合元素的方法，我们需要在方法完成后知道枢轴元素的位置。方法的签名应如下所示：

```java
public int partition(Sortable<E> sortable, int start, int end, E pivot);
```

该类还应该可以访问`Swapper`和`Comparator`。在本例中，我们定义了一个类而不是一个接口；因此，我们将使用构造器注入。

这些构造，如设置器和构造器注入器，是如此的常见和频繁，以至于 IDE 支持这些构造的生成。您需要在代码中创建`final`字段，并使用*代码生成*菜单来创建构造器。

分区类将如下所示：

```java
public class Partitioner<E> {

    private final Comparator<E> comparator;
    private final Swapper swapper;

    public Partitioner(Comparator<E> comparator, Swapper swapper) {
        this.comparator = comparator;
        this.swapper = swapper;
    }

    public int partition(Sortable<E> sortable, int start, int end, E pivot) {
        return 0;
    }
}
```

这段代码什么也不做，但 TDD 就是这样开始的。我们将创建需求的定义，提供代码的框架和调用它的测试。要做到这一点，我们需要一些我们可以分割的东西。最简单的选择是一个`Integer`数组。`partition`方法需要一个`Sortable<E>`类型的对象，我们需要一些包装数组并实现这个接口的东西。我们把那个类命名为`ArrayWrapper`。这是一个通用类。这不仅仅是为了考试。因此，我们将其创建为生产代码，因此，我们将其放在`main`目录中，而不是`test`目录中。因为这个包装器独立于`Sort`的实现，所以这个类的正确位置是在一个新的`SortSupportClasses`模块中。我们将创建新模块，因为它不是接口的一部分。实现依赖于接口，而不依赖于支持类。也可能有一些应用使用我们的库，可能需要接口模块和一些实现，但当它们自己提供包装功能时仍然不需要支持类。毕竟，我们不能实现所有可能的包装功能。SRP 也适用于模块。

Java 库往往包含不相关的功能实现。这不好。就短期而言，它使库的使用更简单。您只需要在 POM 文件中指定一个依赖项，就可以拥有所需的所有类和 API。从长远来看，应用变得越来越大，携带了许多属于某些库的类，但应用从不使用它们。

要添加新模块，必须创建模块目录以及源目录和 POM 文件。该模块必须添加到父 POM 中，并且还必须添加到`dependencyManagement`部分，以便`QuickSort`模块的测试代码可以使用它而不指定版本。新模块依赖于接口模块，因此必须将此依赖关系添加到支持类的 POM 中。

`ArrayWrapper`类简单而通用：

```java
package packt.java189fundamentals.ch03.support;

import packt.java189fundamentals.ch03.generic.Sortable;

public class ArrayWrapper<E> implements Sortable<E> {
    private final E[] array;

    public ArrayWrapper(E[] array) {
        this.array = array;
    }

    public E[] getArray() {
        return array;
    }

    @Override
    public E get(int i) {
        return array[i];
    }

    @Override
    public int size() {
        return array.length;
    }
}
```

我们也需要的`ArraySwapper`类进入同一个模块。它和包装器一样简单：

```java
package packt.java189fundamentals.ch03.support;

import packt.java189fundamentals.ch03.Swapper;

public class ArraySwapper<E> implements Swapper {
    private final E[] array;

    public ArraySwapper(E[] array) {
        this.array = array;
    }

    @Override
    public void swap(int k, int r) {
        final E tmp = array[k];
        array[k] = array[r];
        array[r] = tmp;
    }
}
```

有了这些类，我们可以创建第一个测试：

```java
package packt.java189fundamentals.ch03.qsort.phase1;

// ... imports deleted from print ...

public class PartitionerTest {
```

在创建`@Test`方法之前，我们需要两个辅助方法来进行断言。断言并不总是简单的，在某些情况下，它们可能涉及一些编码。一般规则是，测试和其中的断言应该尽可能简单；否则，它们只是编程错误的一个可能来源。此外，我们创建它们是为了避免编程错误，而不是创建新的错误。

`assertSmallElements`方法认为`cutIndex `之前的所有元素都小于`pivot`：

```java
private void assertSmallElements(Integer[] array, int cutIndex, Integer pivot) {
    for (int i = 0; i < cutIndex; i++) {
        Assert.assertTrue(array[i] < pivot);
    }
}
```

`assertLargeElements`方法确保`cutIndex`之后的所有元素至少与`pivot`一样大：

```java
private void assertLargeElements(Integer[] array, int cutIndex, Integer pivot) {
    for (int i = cutIndex; i < array.length; i++) {
        Assert.assertTrue(pivot <= array[i]);
    }
}
```

该测试使用一个常量数组`Integers`并将其包装到一个`ArrayWrapper`类中：

```java
@Test
public void partitionsIntArray() {
    final var partitionThis = new Integer[]{0, 7, 6};
    final var swapper = new ArraySwapper<> \   
    (partitionThis);
    final var partitioner =
            new Partitioner<Integer>(
                  (a, b) -> a < b ? -1 : a > b ? +1 : 0,
                    swapper);
    final Integer pivot = 6;
    final int cutIndex = partitioner.partition(
       new ArrayWrapper<>(partitionThis), 0, 2, pivot);
    Assert.assertEquals(1, cutIndex);
    assertSmallElements(partitionThis, cutIndex, pivot);
    assertLargeElements(partitionThis, cutIndex, pivot);
}
```

在 JDK 中，`Integer`类型没有`Comparator`，但是很容易将其定义为 Lambda 函数。现在，我们可以编写`partition`方法，如下所示：

```java
 1\. public int partition(Sortable<E> sortable,
 2\.                      int start,
 3\.                      int end,
 4\.                      E pivot) {
 5\.     var small = start;
 6\.     var large = end;
 7\.     while (large > small) {
 8\.         while(comparator.compare(sortable.get(small), pivot) < 0
 9\.                 && small < large) {
10\.             small++;
11\.         }
12\.         while(comparator.compare(sortable.get(large), pivot) >= 0
13\.                 && small < large) {
14\.             large--;
15\.         }
16\.         if (small < large) {
17\.             swapper.swap(small, large);
18\.         }
19\.     }
20\.     return large;
21\. }
```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/97faa5a5-07f1-4524-b339-36a4bb2c0d5c.png)

如果我们运行测试，它运行良好。然而，如果我们用覆盖率运行测试，那么 IDE 告诉我们覆盖率只有 92%。这个测试只覆盖了`partition`方法 14 行中的 13 行。

在`17`行的天沟上有一个红色矩形。这是因为测试数组已经分区。当枢轴值为`6`时，不需要交换其中的任何元素。这意味着我们的测试很好，但还不够好。如果那条线上有错误怎么办？

为了修正这个问题，我们将扩展测试，将测试数组从`{0, 7, 6 }`改为`{0, 7, 6, 2}`。运行测试，它将失败。为什么？经过调试，我们将发现调用方法`partition`，并将固定参数`2`作为数组的最后一个索引。但是，我们把数组做得更长。为什么我们首先在那里写一个常数？这是一个坏做法。让我们用`partitionThis.length-1`替换。现在，它说`cutIndex`是`2`，但我们期望`1`。我们忘记将断言调整为新数组。我们来修吧。现在它有效了。

最后一件事是重新考虑这些断言。代码越少越好。断言方法非常通用，我们将对单个测试数组使用它。断言方法非常复杂，它们值得自己测试。但是，我们不编写测试代码。相反，我们可以简单地删除这些方法，并将测试的最终版本如下所示：

```java
@Test
public void partitionsIntArray() {
    final var partitionThis = new Integer[]{0, 7, 6, 2};
    final var swapper = new ArraySwapper<>(partitionThis);
    final var partitioner =
            new Partitioner<Integer>(
        (a, b) -> a < b ? -1 : a > b ? +1 : 0, swapper);
    final var pivot = 6;
    final var cutIndex = partitioner.partition(
            new ArrayWrapper<>(partitionThis),
            0,
            partitionThis.length - 1,
            pivot);
    Assert.assertEquals(2, cutIndex);
    final var expected = new Integer[]{0, 2, 6, 7};
    Assert.assertArrayEquals(expected, partitionThis);
}
```

再说一遍，这是黑箱测试吗？如果分区返回`{2, 1, 7, 6}`呢？这符合定义。我们可以创建更复杂的测试来覆盖这些情况。但是更复杂的测试本身也可能有一个 bug。作为一种不同的方法，我们可以创建可能更简单但依赖于实现的内部结构的测试。这些不是黑盒测试，因此也不是理想的单元测试。我会选择第二个，但如果有人选择另一个，我不会争辩。

# 递归排序

我们将使用`qsort`包中的一个额外类和分区类来实现快速排序，如下所示：

```java
package packt.java189fundamentals.ch03.qsort;

// ... imports are deleted from print ...
public class Qsort<E> {
    final private Comparator<E> comparator;
    final private Swapper swapper;
// ... constructor setting fields deleted from print ...
    public void qsort(Sortable<E> sortable, int start, int end) {
        if (start < end) {
            final var pivot = sortable.get(start);
            final var partitioner = new Partitioner<E>(comparator, swapper);
            var cutIndex = partitioner.partition(sortable, start, end, pivot);
            if (cutIndex == start) {
                cutIndex++;
            }
            qsort(sortable, start, cutIndex - 1);
            qsort(sortable, cutIndex, end);
        }
    }
}
```

该方法得到`Sortable<E>`和两个指标参数。它不会对整个集合进行排序；它只对`start`和`end`索引之间的元素进行排序。

非常精确的索引总是很重要的。通常，Java 中的起始索引没有问题，但是很多错误源于如何解释`end`索引。在这种方法中，`end`的值可能意味着索引已经不是待排序区间的一部分。在这种情况下，应该使用`end-1`调用`partition`方法，并使用`end-1`作为最后一个参数调用第一个递归调用。这是品味的问题。重要的是要精确定义指标参数的解释。

如果只有一个`(start == end)`元素，则没有要排序的内容，方法返回。这是递归的结束标准。该方法还假设`end`指数从不小于`start`指数。由于这种方法只在我们目前正在开发的库中使用，所以这样的假设不太冒险。

如果有要排序的内容，则该方法将要排序的间隔的第一个元素作为轴心并调用`partition`方法。当分区完成时，该方法递归地调用自己的两部分。

这个算法是递归的。这意味着该方法调用自身。当一个方法调用被执行时，处理器在一个名为**栈**的区域中分配一些内存，并在那里存储局部变量。这个属于栈中方法的区域称为**栈帧**。当方法返回时，释放此区域并恢复栈，只需将栈指针移动到调用之前的位置。这样，一个方法可以在调用另一个方法后继续执行；局部变量就在那里。

当一个方法调用它自己时，它没有什么不同。局部变量是方法实际调用的局部变量。当方法调用自身时，它会在栈上再次为局部变量分配空间。换句话说，这些是局部变量的新实例。

我们在 Java 中使用递归方法，在其他编程语言中，当算法的定义是递归的时，非常重要的是要理解当处理器代码运行时，它不再递归。在这一级别上，有指令、寄存器和内存加载和跳跃。没有什么比函数或方法更像，因此，在这个级别上，没有什么比递归更重要的了。

如果你明白了，很容易理解任何递归都可以被编码成循环。

事实上，在每个循环周围，也可以用递归的方式进行编码，但在开始函数编程之前，这并不真正有趣。

在 Java 和许多其他编程语言中，递归的问题是它可能会耗尽栈空间。对于快速排序，情况并非如此。您可以安全地假设 Java 中方法调用的栈只有几百层。快速排序需要一个深度约为`log2(n)`的栈，其中`n`是要排序的元素数。在 10 亿元素的情况下，这是 30，应该正好合适。

为什么栈没有移动或调整大小？这是因为耗尽栈空间的代码通常是糟糕的样式。它们可以以某种循环的形式以更可读的形式表示。一个更加健壮的栈实现只会吸引新手程序员去做一些可读性较差的递归编码。

递归有一个特例，叫做尾部递归。尾部递归方法将自己作为方法的最后一条指令调用。当递归调用返回代码时，调用方法只释放用于此方法调用的栈帧。换句话说，我们将在递归调用期间保留栈帧，以便在调用之后立即丢弃它。为什么不在电话前把它扔掉呢？在这种情况下，实际帧将被重新分配，因为这与保留的方法相同，并且递归调用被转换为跳转指令。这是一个 Java 没有做的优化。函数式语言正在这样做，但 Java 并不是真正的函数式语言，因此应该避免使用尾部递归函数，并将其转换为 Java 源代码级别的循环。

# 非递归排序

为了证明即使是非尾部递归方法也可以用非递归的方式来表示，这里有一个这样的快速排序：

```java
 1\. public class NonRecursiveQuickSort<E> {
 2\. // ... same fields and constructor as in Qsort are  
    deleted from print ...
 3\. 
 4\.     private static class StackElement {
 5\.         final int begin;
 6\.         final int fin;
 7\. 
 8\.         public StackElement(int begin, int fin) {
 9\.             this.begin = begin;
10\.             this.fin = fin;
11\.         }
12\.     }
13\. 
14\.     public void qsort(Sortable<E> sortable, int  
        start, int end) {
15\.         final var stack = new  
        LinkedList<StackElement>();
16\.         final var partitioner = new Partitioner<E> 
            (comparator, swapper);
17\.         stack.add(new StackElement(start, end));
18\.         var i = 1;
19\.         while (!stack.isEmpty()) {
20\.             var it = stack.remove(0);
21\.             if (it.begin < it.fin) {
22\.                 final E pivot =  
                    sortable.get(it.begin);
23\.                 var cutIndex = 
              partitioner.partition(sortable, it.begin, 
              it.fin, pivot);
24\.                 if( cutIndex == it.begin ){
25\.                     cutIndex++;
26\.                 }
27\.                 stack.add(new StackElement(it.begin, 
                     cutIndex - 1));
28\.                 stack.add(new StackElement(cutIndex, 
                     it.fin));
29\.             }
30\.         }
31\.     }
32\. }
```

这段代码在 Java 级别实现了一个栈。虽然在`stack`中似乎还有一些被安排排序的内容，但它从栈中取出它并进行排序分区，并安排这两部分进行排序。

这段代码比前一段代码更复杂，您必须了解`StackElement`类的角色及其工作方式。另一方面，程序只使用一个`Partitioner`类实例，也可以使用线程池来安排后续排序，而不是在单个进程中处理任务。在多 CPU 机器上执行排序时，这可能会加快排序速度。但是，这是一个更复杂的任务，本章包含了许多没有多任务处理的新事物；因此，我们将在后面的两章中介绍多线程代码。

在排序的第一个版本中，我对它进行了编码，没有三行代码将`cutIndex`与间隔起始进行比较，并在`if`分支中增加它（第 24-26 行）。这是非常需要的。但是，我们在本书中创建的单元测试如果错过了这些行，就不会发现 bug。我建议您删除这些行并尝试编写一些失败的单元测试。然后，试着理解当这些行非常重要时的特殊情况是什么，并试着修改单元测试，以便尽可能简单地发现 bug。（最后，将四行放回原处，看看代码是否有效。）另外，找出一些不将此修改放在方法`partition`中的架构原因。在`large == start`的情况下，该方法只能返回`large+1`。

# 实现 API 类

完成所有这些之后，我们最不需要的就是把`QuickSort`作为一个简单的类（所有真正的工作都已经在不同的类中完成了）：

```java
public class QuickSort<E> extends AbstractSort<E> {
    public void sort(Sortable<E> sortable) {
        final var n = sortable.size();
        final var qsort = new Qsort<E>(comparator,swapper);
        qsort.qsort(sortable, 0, n-1);
    }
}
```

别忘了我们还需要一个测试！但是，在这种情况下，这与`BubbleSort`没有太大区别：

```java
    @Test
    public void canSortStrings() {
        final var actualNames = new String[]{
                "Johnson", "Wilson",
                "Wilkinson", "Abraham", "Dagobert"
        };
        final var expected = new String[]{"Abraham",
                "Dagobert", "Johnson", "Wilkinson", "Wilson"};
        var sort = new QuickSort<String>();
        sort.setComparator(String::compareTo);
        sort.setSwapper(new ArraySwapper<>(actualNames));
        sort.sort(new ArrayWrapper<>(actualNames));
        Assert.assertArrayEquals(expected, actualNames);
    }
```

这次我们用了`String`数组而不是`ArrayList`。这使得这个测试更简单，而且，这一次，我们已经有了支持类。

您可能认识到这不是单元测试。在`BubbleSort`的情况下，算法是在单个类中实现的。测试单个类是一个单元测试。在`QuickSort`的例子中，我们将函数划分为不同的类，甚至是不同的包。对`QuickSort`类的真正单元测试将揭示该类对其他类的依赖性。当这个测试运行时，它涉及到`Partitioner`和`Qsort`的执行，因此，它不是一个真正的单元测试。

我们应该为此烦恼吗？不是真的。我们希望创建涉及单个单元的单元测试，以便在单元测试失败时知道问题所在。如果只有集成测试，一个失败的测试用例将无助于指出问题所在。它只说明测试中涉及的类中存在一些问题。在本例中，只有有限数量的类（三个）参与了这个测试，并且它们被绑定在一起。它们实际上是紧密联系在一起的，而且彼此之间的联系如此紧密，以至于在实际的生产代码中，我可以在单个模块中实现它们。我在这里将它们分开，以演示如何测试单个单元，并演示 Java 模块支持，它需要的不仅仅是 JAR 文件中的单个类。

# 创建模块

模块处理，也称为项目 **Jigsaw** 或 **JPMS**，是仅在 Java9 中提供的特性。这是一个计划已久的专题。首先，它是为 Java7 设计的，但是它太复杂了，所以被推迟到 Java8，然后是 Java9。最后，JPMS 被包含在 Java 的 Release9 中。与此同时，Oracle 引入了长期和短期支持发布的概念。只有在该语言的下一个版本发布之前，才支持短期版本。另一方面，长期版本的支持时间更长，很多次甚至在新版本甚至新的长期支持版本发布后的几年。在 Java9 之前，所有版本都是长期支持版本。如果有任何影响应用稳定性或安全性的重大缺陷，Oracle 正在创建新的次要版本。当 Java1.8 可用时，甚至还为 Java1.6 创建了新版本。

当时 ORACLE 宣布 Java9 和 Java9 将不再是长期受支持的版本。然而，根据新的版本控制方案编号的 Java9 或 Java18.9 是一个长期支持版本，因此，它是第一个实现了 **JPMS** 的长期支持版本。

# 为什么需要模块

我们已经看到 Java 中有四种访问级别。当类内部没有提供修饰符时，方法或字段可以是`private`、`protected`、`public`或`default`（也称为包私有）。当您开发一个用于多个项目的复杂库时，库本身将在许多包中包含许多类。当然会有一些类和方法，这些类和方法中的字段应该只在库中由来自不同包的其他类使用。这些类不能被库外的代码使用。使它们比`public`更不可见会使它们在库中无法使用。制造它们`public`将使它们从外面可见。这不好。

在我们的代码中，编译成 JAR 的 Maven 模块`quick`只有在`sort`方法可以调用`qsort`的情况下才能使用。但是，我们不希望`qsort`直接从外部使用。在下一个版本中，我们可能希望开发一个使用来自`NonRecursiveQuickSort`类的`qsort`的版本，我们不希望客户抱怨他们的代码由于库的小升级而无法编译或工作。我们可以证明，内部方法和类是公共的，它们不是用来使用的，而是徒劳的。使用我们库的开发人员不阅读文档。这也是为什么我们不写过多的注释。没有人会读它，甚至执行代码的处理器也不会。

# 什么是 Java 模块？

Java 模块是 JAR 或目录中类的集合，其中还包含一个名为`module-info`的特殊类。如果 JAR 或目录中有这个文件，那么它就是一个模块，否则，它只是`classpath`上的类的集合（或者不是）。Java8 和早期版本只会忽略该类，因为它从未用作代码。这样，使用较旧的 Java 不会造成伤害，并且保持了向后兼容性。

创建这样一个罐子有点棘手。`module-info.class`文件应具有符合 Java9 字节码或更高版本的字节码，但其他类应包含较旧版本的字节码。

模块信息定义了模块导出的内容及其所需的内容。它有一种特殊的格式。例如，我们可以将`module-info.java`放在我们的`SortInterface`Maven 模块中：

```java
module packt.java189fundamentals.SortInterface{
    exports packt.java189fundamentals.ch03;
    exports packt.java189fundamentals.ch03.generic;
}
```

这意味着可以从外部使用`public`和`packt.java189fundamentals.ch03`包内部的任何类。这个包是从模块导出的，但是从模块外部看不到其他包中的其他类，即使它们是`public`。命名要求与包的情况相同，应该有一个不可能与其他模块名称冲突的名称。反向域名是一个很好的选择，但它不是必须的，你可以在这本书中看到。还没有顶级域`packt`。

我们还应该修改父 POM，以确保我们使用的编译器是 Java9 或更高版本，在`project/build/plugins/`处配置 Maven 编译器插件：

```java
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <version>3.7.0</version>
    <configuration>
        <source>1.10</source>
        <target>1.10</target>
    </configuration>
    <dependencies>
        <dependency>
            <groupId>org.ow2.asm</groupId>
            <artifactId>asm</artifactId>
            <version>6.1.1</version> 
        </dependency>
    </dependencies>
</plugin>
```

旧版本会与`module-info.java`文件混淆。（顺便说一句，即使是我在本书第一版中使用的 Java9 的早期访问版本有时也会给我带来困难。）

我们还在 Maven 模块中创建了一个`module-info.java`文件`quick`，如下所示：

```java
module packt.java189fundamentals.quick {
    exports packt.java189fundamentals.ch03.quick;
    requires packt.java189fundamentals.SortInterface;
    }
```

这个模块导出另一个包，需要我们刚刚创建的`packt.java189fundamentals.SortInterface`模块。现在，我们可以编译模块，`./quick/target`和`./SortInterface/target`目录中创建的 Jar 现在是 Java 模块。

为了测试模块支持的功能，我们将创建另一个名为`Main`的 Maven 模块。它只有一个类，叫做`Main`，有一个`public static void main`方法：

```java
package packt.java189fundamentals.ch03.main;

// ... imports are deleted from print ...

public class Main {
    public static void main(String[] args) throws IOException {
        final var fileName = args[0];
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(fileName))));
            final var lines = new LinkedList<String>();
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
            String[] lineArray = lines.toArray(new String[0]);
            var sort = new FQuickSort<String>();
            sort.setComparator((a, b) -> ((String) a).compareTo((String) b));
            sort.setSwapper(new ArraySwapper<>(lineArray));
            sort.sort(new ArrayWrapper<>(lineArray));
            for (final String outLine : lineArray) {
                System.out.println(outLine);
            }
        } finally {
            if (br != null) {
                br.close();
            }
        }
    }
}
```

它接受第一个参数（不检查是否有一个参数，我们不应该在生产代码中使用它）并将其用作文件名。然后，它将文件的行读入一个`String`数组，对其排序，并将其打印到标准输出。

由于模块支持只对模块起作用，这个 Maven 模块也必须是 Java 模块，并且有一个`module-info.java`文件：

```java
module packt.java189fundamentals.Main{
    requires packt.java189fundamentals.quick;
    requires packt.java189fundamentals.SortInterface;
    requires packt.java189fundamentals.SortSupportClasses;
}
```

此外，我们必须为支持模块创建一个`module-info.java`文件；否则，我们将无法从我们的模块中使用它。

在使用`mvn install`编译模块之后，我们可以运行它来打印已排序文件的行。例如，我们可以打印出排序后的父 POM 的行，这没有多大意义，但很有趣。下面是启动 Java 代码的 Windows 命令文件：

```java
set MODULE_PATH=Main/target/Main-1.0.0-SNAPSHOT.jar;
set MODULE_PATH=%MODULE_PATH%SortInterface/target/SortInterface-1.0.0-SNAPSHOT.jar;
set MODULE_PATH=%MODULE_PATH%quick/target/quick-1.0.0-SNAPSHOT.jar;
set MODULE_PATH=%MODULE_PATH%SortSupportClasses/target/SortSupportClasses-1.0.0-SNAPSHOT.jar
java -p %MODULE_PATH% -m packt.java189fundamentals.Main/packt.java189fundamentals.ch03.main.Main pom.xml
```

JAR 文件位于模块路径上，该路径通过命令行选项`-p`提供给 Java 执行。要启动模块中类的`public static void main()`方法，仅指定类的完全限定名是不够的。我们必须使用`-m`选项，后跟模块和类的`module/class`格式规范。

现在，如果我们尝试直接访问`Qsort`，将下面的行`Qsort<String> qsort = new Qsort<>(String::compareTo,new ArraySwapper<>(lineArray));`插入`main`方法，Maven 会抱怨，因为模块系统对我们的`Main`类隐藏了它。

模块系统还支持基于`java.util.ServiceLoader`的类加载机制，这在本书中我们将不讨论。当使用 Spring、Guice 或其他依赖注入框架时，这是一种很少在企业环境中使用的老技术。如果您看到一个包含`uses`和`provides`关键字的`module-info.java`文件，那么请首先查阅 Java 文档中关于[`ServiceLoader`类](http://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html)的文档，[然后是关于模块支持的 Java9 语言文档](http://openjdk.java.net/projects/jigsaw/quick-start)。

# 总结

在本章中，我们开发了一个实现快速排序的通用排序算法。我们将项目修改为多模块 Maven 项目，并使用 Java 模块定义。我们使用 JUnit 开发单元测试，并使用 TDD 开发代码。我们使用泛型将代码从旧式 Java 转换为新的，并使用异常处理。在接下来的章节中，我们将开发一个猜谜游戏，这些是需要的基本工具。首先，我们将开发一个更简单的版本，在下一章中，我们将开发一个使用并行计算和多处理器的版本。

# 四、Mastermind-创造游戏

在本章中，我们将开始开发一个简单的游戏。游戏是主谋，两个玩家。玩家一从六种可能的颜色中选择四种不同颜色的别针，并将它们排列在一个棋盘上，对另一个玩家隐藏起来。另一个玩家试着猜别针的颜色和位置。在每一次猜测中，玩家一猜匹配颜色的数量以及匹配颜色和位置的针脚。该程序将同时充当播放器 1 和播放器 2。我们的代码将单独运行。然而，留给我们玩的是最重要的代码。

这个例子非常复杂，足以深化**面向对象**（**OO**）原则，以及我们如何设计类和建模现实世界。我们已经使用了 Java 运行时中提供的类。这次，我们将使用集合并讨论这一重要领域。这些类和接口在 JDK 中广泛使用和可用，对于专业 Java 开发人员来说，它们和语言本身一样重要。

这次的构建工具是 Gradle。

在本章中，我们将介绍以下内容：

*   Java 集合
*   依赖注入
*   如何注释代码和创建 JavaDoc 文档
*   如何创建集成测试

# 游戏

[策划人](https://en.wikipedia.org/wiki/Mastermind_(board_game))是一个古老的游戏。在每个有孩子的房子里随处可见的塑料版本是 1970 年发明的。我在 1980 年得到了一块棋盘作为圣诞礼物，一个用 BASIC 语言解决游戏难题的程序是我在 1984 年左右创建的第一个程序之一。

游戏板上有四列几行的洞。有六种不同颜色的塑料别针可以插入孔中。每个针都有一种颜色。它们通常是红色、绿色、蓝色、黄色、黑色和白色。有一个特殊的行对其中一个玩家（猜测者）隐藏。

要玩这个游戏，其中一个玩家（hider）必须从一组别针中选择四个别针。所选管脚应具有不同的颜色。这些插针被一个接一个地放置在隐藏的行中，每个插针都处于一个位置。

猜测者试图找出什么颜色在哪个位置，猜测。每个猜测选择四个管脚并将它们排成一行。隐藏者告诉猜测者有多少针脚在正确的位置，有多少针脚的颜色在桌子上，但不在正确的位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/491c2b6a-34cb-49d3-88ca-fd98d2a67a51.png)

示例剧本可能是这样的：

1.  隐藏者隐藏了四个针脚，分别是蓝色、黄色、白色和黑色。
2.  猜测者猜测黄色、蓝色、绿色和红色。

3.  隐藏者告诉猜测者有两种颜色匹配，但没有一种颜色在隐藏行中的正确位置。隐藏者这样说是因为黄色和蓝色在隐藏行中，而不是在猜测者猜测的位置。它们实际上是交换的，但是这个信息隐藏者是保密的。他们只说有两种颜色匹配，没有一种在正确的位置。
4.  下一个猜测是。。。

当猜猜者找到正确的颜色以正确的顺序时，游戏结束。同样的游戏也可以用文字符号来描述-`B`表示蓝色，`Y`表示黄色，`G`表示绿色，`W`表示白色，`R`表示红色，`b`表示黑色（幸运的是，计算机上有上下小写字母）：

```java
RGBY 0/0

GRWb 0/2
YBbW 0/2
BYGR 0/4
RGYB 2/2
RGBY 4/0
```

你猜怎么着！这是我们将在本章中开发的程序的实际输出。

我们也玩了这个游戏，允许一个位置是空的。这与第七种颜色基本相同。当我们发现游戏太简单，即使有七种颜色，我们改变了规则，允许颜色出现在不同的位置。这些都是游戏的有效变体。

在本章中，我们将使用六种颜色，在隐藏行中不使用颜色重复。游戏的其他版本编程起来有点复杂，但它们本质上是相同的，解决这些变化不会增加我们的学习经验。

# 游戏的模型

当我们用面向对象的思想开发一段代码时，我们会尝试对真实世界建模，并将真实世界的对象映射到程序中的对象。你肯定听过面向对象的解释，用非常典型的几何物体的例子，或者用汽车和马达的东西来解释组成。就我个人而言，我认为这些例子太简单了，无法得到很好的理解。他们可能是好的开始，但我们已经在这本书的第四章。策划者的游戏好多了。它比矩形和三角形要复杂一些，但没有电信计费应用或原子能发电厂控制那么复杂。

在这个游戏中，我们有哪些真实世界的物体？我们有一张桌子，我们有不同颜色的别针。我们当然需要两个 Java 类。桌子里有什么？每行有四个位置。也许我们需要一个类。表将有行。我们还需要一些隐藏秘密的东西。这也可以是一行，并且每行还可以保存关于有多少位置和多少颜色匹配的信息。在秘密行的情况下，这个信息是明显的 -4 和 0。

什么是别针？每个别针都有一种颜色，通常就是它。除了可以插入桌子上的孔之外，没有其他的销钉的特性，但这是我们不会建模的真实特性。基本上，别针是一种颜色，而不是别的。这样，我们可以在早期就从模型中消除别针类，甚至在我们用 Java 创建别针类之前。相反，我们有颜色。

什么是颜色？这可能是第一次很难理解的。我们都很清楚什么是颜色。它是不同频率光的混合物，正如我们的眼睛所感知的那样。我们可以有不同颜色的油漆和印刷品，等等。在这个程序中有很多东西我们没有建模。在我们的代码中，很难判断我们对颜色的模型是什么，因为这些特性非常明显，在现实生活中我们认为这是理所当然的；我们可以分辨出两种颜色是不同的。这是我们唯一需要的功能。为此，可以使用最简单的 Java 类：

```java
public class Color {
}
```

如果您有两个类型为`Color`的变量，您可以判断它们是否相同。可以使用表达式`a == b`比较`a`和`b`的对象标识，也可以使用继承自`Object`类`a.equals(b)`的`equals()`方法。用字母来编码颜色或用`String`常数来表示它们是很诱人的。首先可能比较容易，但之后会有严重的缺点。当代码变得复杂时，它会导致 bug；传递同样编码为`String`而不是颜色的东西很容易，而且只有单元测试可以节省时间。这比编译器在 IDE 中输入错误参数时发出的抱怨要好。

当我们玩游戏时，别针在小盒子里。我们从盒子里拔出别针。我们如何在程序中获得颜色？我们需要一些东西，从那里我们可以得到颜色。或者换个角度看，我们需要一些能给我们颜色的东西。我们称之为`ColorManager`。现在，`ColorManager`知道我们有多少种不同的颜色，任何时候我们需要一种颜色，我们都可以要求它。

同样，有一种设计`ColorManager`的诱惑，它可以通过序列号来提供颜色。如果我们有四种颜色，我们可以要求颜色数字 0，1，2，或 3。但话说回来，它只是将颜色隐式编码为整数，我们同意不这样做。我们应该找到最基本的功能，我们将需要模型的游戏。

为了描述类的结构，专业开发人员通常使用**统一建模语言**（**UML**）类图。UML 是一种标准化的图表符号，几乎只用于可视化软件架构。UML 中有许多图表类型来描述程序的静态结构和动态行为。这一次，我们将看到一个非常简化的类图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/181e84d0-fc07-4a7d-bdb9-07ace7116fe2.png)

我们没有空间去深入了解 UML 类图的细节。矩形表示类，法线箭头表示类具有另一类类型的字段时的关系，三角形箭头表示类扩展另一类。箭头指向要扩展的类的方向。

一个`Game`类包含一个秘密`Row`类和一个`Table`类。`Table`有`ColorManager`类和`Row`类的`List<>`。`ColorManager`具有第一颜色，并且具有`Color`类的`Map<>`。我们还没有讨论为什么会有这样的设计；我们将到达那里，图表帮助我们做到这一点。一个`Row`类本质上是一个`Color`类的数组。

玩家有一个功能，他们必须猜很多次，直到他们找到隐藏的秘密。为了得到`ColorManager`的模型，我们需要设计`Guesser`的算法。

当玩家做出第一个猜测时，任何颜色的组合都和其他颜色一样好。稍后，猜测应该考虑之前猜测的回答。这是一个合理的方法，只尝试颜色的变化，可以是真正的秘密。玩家选择一个变体并查看所有先前的猜测，假设所选变体是秘密。如果对他们已经做出的行的响应与对游戏中未知秘密的响应相同，那么尝试这种变化是合理的。如果在反应中有任何差异，那么这种变化肯定不是隐藏的变化。

有更复杂的方法，这个游戏有一个特殊的策略，选择一个颜色变化从一组可能的猜测匹配的答案。我们这里不讨论这些算法。当我们找到一个颜色变化，可以解决，我们将使用这个。

为了遵循这种方法，猜测者必须一个接一个地生成所有可能的颜色变化，并将它们与表格进行比较。猜测代码不会创建和存储所有可能的变体。它必须知道它在哪里，并且能够计算出下一个变化。这假定了变化的顺序。暂时，让我们忘记没有颜色可能会出现两次的变化。一个简单的排序方法可以和我们对十进制数排序的方法一样。如果我们有一个三位数的数字，那么第一个是 000，下一个是 001，依此类推直到 009，总是取最后一个位置的下一个数字。之后，010 来了。我们在最后一个数字旁边增加了一个数字，然后又将最后一个数字设为 0。现在，我们有 011012，等等。你知道，我们是怎么数数的。现在，把数字换成颜色，我们只有六个而不是十个。或者，当我们实例化一个`ColorManager`对象时，我们有我们想要的任何数量。

这就产生了`ColorManager`的功能。它必须做以下两件事：

*   给调用者第一种颜色
*   给出给定颜色后面的下一种颜色（我们将方法命名为`nextColor`）

后一种功能也应该在没有下一种颜色时发出信号。这将使用另一个名为`thereIsNextColor`的方法来实现。

这是一个惯例，以返回布尔值的方法名开始使用`is`。这将导致这个约定后面的名称-`isThereNextColor`；或者这个名称-`isNextColor`。这两个名称中的任何一个都解释了方法的功能。如果我问问题`isThereNextColor`，方法会回答我`true`或`false`。但是，这不是我们将如何使用的方法。我们将用简单的句子交谈。我们将使用短句。我们将避免不必要的、胡言乱语的表达。我们也将以这种方式编程。调用者很可能会在`if`语句中使用此方法。他们将写下：

```java
 if( thereIsNextColor(currentColor)){...}
```

They will not write this:

```java
 if( isThereNextColor(currentColor)){...}
```

我认为第一个版本更具可读性，可读性是第一位的。最后，但并非最不重要的一点是，如果你遵循旧的惯例，没有人会责怪你，如果这是公司的标准，你无论如何都必须这样做。

要做到这一切，`ColorManager`还必须创建颜色对象，并将它们存储在有助于执行操作的结构中：

```java
 1\. package packt.java189fundamentals.example.mastermind;
 2\. 
 3\. import java.util.HashMap;
 4\. import java.util.Map;
 5\. 
 6\. public class ColorManager {
 7\.     final protected int nrColors;
 8\.     final protected Map<Color, Color> successor = new HashMap<>();
 9\.     private Color first;
10\. 
11\.     public ColorManager(int nrColors) {
12\.         this.nrColors = nrColors;
13\.         createOrdering();
14\.     }
15\. 
16\.     protected Color newColor(){
17\.         return new Color();
18\.     }
19\. 
20\.     private Color[] createColors() {
21\.         Color[] colors = new Color[nrColors];
22\.         for (int i = 0; i < colors.length; i++) {
23\.             colors[i] = newColor();
24\.         }
25\.         return colors;
26\.     }
27\. 
28\.     private void createOrdering() {
29\.         Color[] colors = createColors();
30\.         first = colors[0];
31\.         for (int i = 0; i < nrColors - 1; i++) {
32\.             successor.put(colors[i], colors[i + 1]);
33\.         }
34\.     }
35\.     public Color firstColor() {
36\.         return first;
37\.     }
38\. 
39\.     boolean thereIsNextColor(Color color) {
40\.         return successor.containsKey(color);
41\.     }
42\. 
43\.     public Color nextColor(Color color) {
44\.         return successor.get(color);
45\.     }
46\. }
```

我们使用的结构是一个`Map`。现在，`Map`是 Java 运行时中定义的一个接口，从 Java 的早期版本开始就可以使用。`Map`有键和值，对于任何键，您都可以轻松地检索分配给键的值。

您可以在第 8 行看到，`successor`变量的定义，我们将变量的类型定义为接口，但值是类的实例。显然，该值不能是接口的实例，因为这样的对象不存在。但是，为什么我们要将变量定义为接口呢？原因是抽象和编码实践。如果出于某种原因需要更改所使用的实现，那么变量类型可能仍然保持不变，不需要在其他地方更改代码。将变量声明为接口也是一种很好的做法，这样我们就不会因为方便而使用接口中不可用的实现的某些特殊 API。当确实需要时，我们可以更改变量的类型并使用特殊的 API。毕竟，API 的存在是有原因的，但是仅仅因为 API 存在而使用某些特殊事物的诱惑是受到阻碍的。这有助于编写更简单、更干净的程序。

`Map`只是 Java 运行时中定义的属于 Java 集合的接口之一。还有许多其他接口和类。尽管 JDK 和所有的类都很多，而且几乎没有人知道其中的所有类，但是集合是一个专业开发人员应该了解的特殊领域。在详细说明此代码中使用`HashMap`的原因之前，我们将对集合类和接口进行概述。这将有助于我们了解本程序中使用的其他集合。

# Java 集合

集合是帮助我们存储多个对象的接口和类。我们已经看到了数组，它可以做到这一点。我们在前面的章节中也看到了`ArrayList`。我们没有详细讨论 JDK 中还有哪些其他可能性。在这里，我们将更详细地讨论，但将流和函数方法留给后面的章节，我们也将避免讨论细节。那是一本参考书的任务。

使用集合类和接口的实现可以减少编程工作。首先，您不需要编写已经存在的程序。其次，这些类在实现和特性上都进行了高度优化。他们有非常好的设计 API 和代码是快速的，并使用小内存占用。但是，他们的代码是很久以前写的，风格不好，很难阅读和理解。

当您使用来自 JDK 的集合时，更有可能与某些库进行互操作。如果你自己制作一个链表，你不可能找到一个现成的解决方案来排序你的列表。如果您使用 JDK 标准类库中的`LinkedList`类，您将从`Collections`类获得现成的解决方案，就在 JDK 中。还值得一提的是，Java 语言本身支持这些类。例如，您可以使用`for`命令的缩短的特殊语法轻松地遍历`Collection`的元素。

JDK 中的集合包含定义不同集合类型、实现类和执行某些操作（如排序）的算法的行为的接口。很多时候，这些算法在不同的实现版本上工作，得到相同的结果，但是针对特定于实现的类进行了优化。

您可以使用接口提供的 API，如果您在代码中更改实现，您将获得适合实现的优化版本。

下图显示了不同`Collection`接口之间的关系：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/4b14cf4f-4c4d-4700-ba33-2fa58845876c.png)

`Collection`接口可分为两类。一个包包含扩展`Collection`接口的接口，另一个包包含`Map`和扩展`Map`的`SortedMap`。这样，`Map`就不是一个真正的集合，因为它不仅仅包含其他对象，而是成对的值和键。

# `Collection`接口

`Collection`是接口层次结构的顶层。这个接口定义了所有实现应该提供的方法，不管它们是直接实现`Set`、`SortedSet`、`List`、`Queue`还是`Deque`接口。正如`Collection`简单地说，实现`Collection`接口的对象只是一个将其他对象集合在一起的对象，它定义的方法就像向集合中添加一个新对象，清除其中的所有元素，检查一个对象是否已经是集合的成员，并遍历这些元素。

有关接口的最新定义，请参阅 [Java API 文档](https://download.java.net/java/early_access/JDK11/docs/api/)。您可以随时查阅在线 API，建议您这样做。

Java 语言本身直接支持接口。您可以使用增强的`for`循环语法遍历`Collection`的元素，就像您可以迭代数组中的元素一样，在数组中集合应该是表达式，从而导致实现`Collection`接口的对象：

```java
for( E element : collection ){...}
```

在前面的代码中，`E`要么是对象，要么是`Collection`元素的泛型类型。

JDK 中没有直接实现`Collection`接口。类实现了`Collection`的一个子接口。

# `Set`

`Set`是一个特殊的集合，不能包含重复的元素。当您想将一个对象添加到一个已经有该对象或一个与实际对象相等的对象集时，`add`方法将不会添加实际对象。`add`方法返回`false`，表示失败。

当您需要一个唯一元素的集合时，您可以在程序中使用`Set`，您只需要检查一个元素是否是一个集合的成员，一个对象是否属于某个组。

当我们返回到我们的程序代码时，我们将看到`UniqueGuesser`类必须实现一个算法来检查猜测中的颜色只存在一次。此算法是使用`Set`的理想候选者：

```java
    private boolean isNotUnique(Color[] guess) {
        final var alreadyPresent = new HashSet<Color>();
        for (final var color : guess) {
            if (alreadyPresent.contains(color)) {
                return true;
            }
            alreadyPresent.add(color);
        }
        return false;
    }
```

代码创建一个集合，当方法启动时该集合为空。之后，它检查每种颜色（注意数组元素上增强的`for`循环），如果它以前已经存在的话。为此，代码检查`color`是否已经在集合中。如果有，猜测是不是唯一的，因为我们已经发现了一种颜色，是目前至少两次。如果`color`不在场景中，那么猜测的颜色仍然是唯一的。为了以后能够检测到，代码将颜色放入集合中。

我们使用的`Set`的实际实现是`HashSet`。在 JDK 中，有许多类实现了`Set`接口。使用最广泛的是`HashSet`。值得一提的还有`EnumSet`、`LinkedHashSet`和`TreeSet`。最后一个还实现了`SortedSet`接口，我们将在这里详细介绍。

为了理解什么是`HashSet`（以及后面的`HashMap`）以及它们是如何工作的，我们必须讨论什么是散列。它们在许多应用中起着非常重要的核心作用。他们在 JDK 中秘密地工作，但是程序员必须遵循一些非常重要的限制，否则真的很奇怪而且很难找到 bug 会让他们的生活很悲惨。我敢说，违反了`HashSet`和`HashMap`中的哈希约定，是继多线程问题之后第二个最难发现的 bug 的原因。

因此，在继续不同的集合实现之前，我们将访问这个主题。在本次讨论集合的绕道中，我们的示例已经深入了一个层次，现在我们将更深入一个层次。我保证这是最后一次深入的迂回。

# 散列函数

散列是一个数学函数，它为一个元素赋值。听起来很可怕，不是吗？假设你是一名大学行政人员，你必须判断威尔金森是否是你班的学生。你可以把名字放在信封里的小纸上，每封信一个。不用搜索 10000 名学生，你可以查看信封中标题为 W 的论文。这个非常简单的哈希函数将名字的第一个字母指定给名字（或者字母的序数，正如我们所说的哈希函数产生一个数字）。这实际上不是一个好的散列函数，因为它只将一些元素（如果有的话）放入表示为 X 的信封中，而将许多元素放入 A 中。

好的散列函数以相似的概率返回每个可能的序数。在哈希表中，我们通常拥有比要存储的元素数量更多的桶（在上一个示例中是信封）。因此，当搜索一个元素时，很可能只有一个元素。至少这是我们想要的。如果一个桶中有多个元素，则称为碰撞。一个好的哈希函数有尽可能少的冲突。

为了向后兼容，JDK 中有一个`Hashtable`类。这是第一个版本中第一个用 Java 实现的哈希表，因为 Java 是向后兼容的，所以它没有被丢弃。`Map`接口仅在版本 1.2 中引入。`Hashtable`有很多缺点，不推荐使用。（甚至名称也违反了 Java 命名约定）本书中我们不讨论这个类。每当我们谈论哈希表时，我们指的是`HashSet`、`HashMap`实现中的实际数组，或者使用哈希索引表的任何其他集合。

哈希表是使用哈希函数的结果对数组进行索引的数组。数组元素称为桶。哈希表实现试图避免在同一个桶中有多个元素的情况。要做到这一点，当桶满了超过某个限制时，表会不时地调整大小。当超过 70% 的桶已经包含一个元素时，表的大小将增加一倍。即使有这样一个阈值和调整数组的大小，也不能保证在一个桶中永远不会有多个元素。因此，实现通常不在桶中存储单个元素，而是存储元素的链表。大多数情况下，列表将只包含一个元素，但当发生冲突时，两个或多个元素具有相同的哈希值，然后列表可以存储这些元素。

调整桶数组的大小时，必须再次放置每个元素。此操作可能需要相当长的时间，在此期间，单个元件在铲斗之间移动。

在此操作期间，无法可靠地使用哈希表，这可能是多线程环境中的一些问题源。在单线程代码中，您不会遇到这个问题。当您调用`add()`方法时，哈希表（集合或映射）决定必须调整表的大小。`add()`方法调用调整大小的方法，直到完成后才返回。单线程代码在此期间不可能使用哈希表—单线程正在执行调整大小。在多线程环境中，可能会发生这样的情况：一个线程调用开始调整大小的`add()`，而另一个线程也在重新组织哈希表时调用`add()`。在这种情况下，JDK 中的哈希表实现将抛出`ConcurrentModificationException`。

`HashSet`和`HashMap`使用集合中存储的`Object`提供的哈希函数。`Object`类实现了`hashCode()`和`equals()`方法。你可以覆盖它们，如果你这样做了，你应该以一致的方式覆盖它们。首先，我们将看到它们是什么，然后如何一致地覆盖它们。

# `equals()`方法

`Set`的文件中，集中不含`e1`和`e2`两个元素，使`e1.equals`（`e2`。`equals()`方法返回`true`如果`e1`和`e2`在某种程度上相等。它可能与两个对象相同。可以有两个不同的对象是相等的。例如，我们可以有一个颜色实现，该颜色实现的名称为属性，两个颜色对象可以返回`true`，在其中一个对象上调用`equals()`方法，当两个字符串相等时，将参数作为另一个传递。`equals()`方法默认实现在`Object`类的代码中，如果且仅当`e1`和`e2`完全相同且单一对象时，返回`true`。

这似乎是显而易见的，但我的经验表明，在一个对象中实现`equals()`必须如下，这一点再怎么强调也不为过：

*   **自反**：意思是对象总是等于它自己
*   **对称**（可交换）：这意味着如果`e1.equals(e2)`是`true`，那么`e2.equals(e1)`也应该是`true`
*   **传递**：表示如果`e1.equals(e2)`和`e2.equals(e3)`，那么`e1.equals(e3)`
*   **一致**：这意味着如果两次调用之间对象没有改变，返回值就不应该改变

# `hashCode`方法

`hashCode()`方法返回一个`int`。文档中说，任何重新定义此方法的类都应该提供以下实现：

*   如果未修改对象，则始终返回相同的值
*   结果相等的两个对象有相同的`int`值（`equals()`方法返回`true`）

文档还提到，这不是对不相等对象产生不同的`int`值的要求，但希望支持哈希实现集合的性能。

如果在实现`equals()`和`hashCode()`时违反了这些规则中的任何一个，那么使用它们的 JDK 类可能会失败。您可以确定，`HashSet`、`HashMap`和类似的类已经过充分的调试，看到您向一个集合添加了一个对象，然后集合报告如果它不在那里，将是一个令人困惑的体验。但是，只有在您发现集合中存储的两个相等的对象具有不同的`hashCode()`值之前，`HashSet`和`HashMap`才会在由`hashCode()`值索引的桶中查找该对象。

将对象存储在`HashSet`或`HashMap`中，然后对其进行修改也是一个常见的错误。对象在集合中，但找不到它，因为`hashCode()`返回的值不同，因为它已被修改。除非您知道自己在做什么，否则不应修改存储在集合中的对象。

很多时候，对象包含的字段从平等的角度看是不有趣的。`hashCode()`和`equals()`方法对这些字段都是幂等的，即使将对象存储在`HashSet`或`HashMap`中，也可以对这些字段进行修改。（幂等表示可以随意更改这些字段的值，并且方法的结果不会更改。）

例如，可以管理对象中的三角形，以保持顶点的坐标和三角形的颜色。但是，您并不关心颜色是否相等，只关心两个三角形在空间中处于完全相同的位置。在这种情况下，`equals()`和`hashCode()`方法不应考虑字段颜色。这样，我们就可以画出我们的三角形；不管颜色场是什么，它们仍然会出现在`HashSet`或`HashMap`中。

# 实现`equals`和`hashCode`

实现这些方法相当简单。由于这是一项非常常见的任务，IDE 支持生成这些方法。这些方法紧密地联系在一起，以至于 IDE 中的菜单项不是独立的；它们允许您一次生成这些方法。

要求 IDE 生成`equals()`方法将产生如下代码：

```java
@Override 
public boolean equals(Object o) { 
  if (this == o) return true; 
  if (o == null || getClass() != o.getClass()) return false;   
  MyObjectJava7 that = (MyObjectJava7) o;
  return Objects.equals(field1, that.field1) && 
  Objects.equals(field2, that.field2) && 
  Objects.equals(field3, that.field3); 
}
```

对于这个示例，我们有三个名为`field1`、`field2`和`field3`的`Object`字段。与任何其他类型和字段的代码看起来都非常相似。

首先，该方法检查对象标识。一个`Object`总是`equals()`本身。如果作为参数传递的引用是`null`而不是对象，或者它们属于不同的类，那么这个生成的方法将返回`false`。在其他情况下，`Objects`类的静态方法（注意复数形式）将用于比较每个字段。

`Objects`工具类是在 Java7 中引入的。静态方法`equals()`和`hash()`支持`Object equals`和`hashCode()`方法的覆盖。`hashCode()`在 Java7 之前的创建是相当复杂的，需要用一些幻数实现模运算，这些幻数很难解释，仅仅看代码而不知道背后的数学。

这种复杂性现在隐藏在以下`Objects.hash`方法背后：

```java
@Override 
 public int hashCode() { 
     return Objects.hash(field1, field2, field3); 
 }
```

生成的方法只是调用`Objects::hash`方法，将重要字段作为参数传递。

# `HashSet`（哈希集）

现在，我们基本上知道了很多关于散列的事情，所以我们可以勇敢地讨论`HashSet`类。`HashSet`是`Set`接口的一个实现，它在内部使用哈希表。一般来说，就是这样。将对象存储在那里，可以查看对象是否已经存在。当需要一个`Set`实现时，几乎总是选择`HashSet`。几乎。。。

# `EnumSet`（枚举集）

`EnumSet`可以包含某个枚举中的元素。回想一下，枚举是一些类，它们修复了`enum`本身中声明的大量实例。由于这限制了不同对象实例的数量，并且这个数量在编译时是已知的，`EnumSet`代码的实现是相当优化的。在内部，`EnumSet`被实现为一个位域，是一个很好的选择，如果我们用低级语言编程，位域操作将是一个选择。

# `LinkedHashSet`（链接哈希集）

`LinkedHashSet`是一个`HashSet`，它还维护它所持有的元素的双链表。当我们迭代一个`HashSet`时，元素没有保证的顺序。当`HashSet`被修改时，新元素被插入到其中一个桶中，并且哈希表可能被调整大小。这意味着元素被重新排列并进入完全不同的桶中。对`HashSet`中的元素的迭代只是将桶和其中的元素按某种顺序进行，从调用者的角度来看，这种顺序是任意的。

然而，`LinkedHashSet`使用它维护的链表对元素进行迭代，并且迭代保证按照元素插入的顺序进行。这样，`LinkedHashSet`就是一个复合数据结构，同时是一个`HashSet`和一个`LinkedList`。

# `SortedSet`（有序集）

`SortedSet`是一个接口，它保证实现它的类将按排序顺序遍历集合。如果对象实现了`Comparable`接口，则顺序可以是对象的自然顺序，或者`Comparator`对象可以驱动它。这个对象应该在实现`SortedSet`的类的实例被创建时可用；换句话说，它必须是一个构造器参数。

# `NavigableSet`（可导航集）

`NavigableSet`使用方法扩展`SortedSet`接口，这些方法允许您在集合中进行邻近搜索。这基本上允许您搜索搜索中的元素，该元素可以是以下任一元素：

*   小于搜索对象
*   小于或等于搜索元素
*   大于或等于搜索对象

# `TreeSet`（树集）

`TreeSet`是`NavigableSet`的实现，也是`SortedSet`的实现，事实上，它也是`Set`，因为`SortableSet`文档暗示有两种类型的构造器，每种都有多个版本。一个需要一些`Comparator`，而另一个则依赖于元素的自然顺序。

# `List`（列表）

`List`是一个要求实现类跟踪元素顺序的接口。还有一些方法通过索引和`Collection`接口定义的迭代来访问元素，这些接口保证元素的顺序。接口还定义了`listIterator`方法，该方法返回一个也实现了`ListIterator`接口的`Iterator`。这个接口提供了一些方法，让调用者在遍历列表的同时将元素插入到列表中，并在迭代中来回执行。也可以在`List`中搜索某个元素，但大多数接口实现的性能较差，而搜索只是遍历所有元素，直到找到所搜索的元素。JDK 中有许多类实现这个接口。在这里，我们将提到两个。

# `LinkedList`（链表）

这是一个`List`接口的双链表实现，该接口引用了前面的元素，并且也引用了列表中每个元素的下一个元素。类还实现了`Deque`接口。从列表中插入或删除元素是相当便宜的，因为它只需要调整很少的引用。另一方面，按索引访问元素需要从列表的开始或列表末尾进行迭代；以更接近指定索引元素的为准。

# `ArrayList`（数组列表）

这个类是`List`接口的一个实现，该接口保持对数组中元素的引用。这样，通过索引访问元素就相当快了。另一方面，在`ArrayList`中插入一个元素可能代价高昂。它需要将插入元素上方的所有引用移到一个更高的索引，并且可能还需要调整背景数组的大小，以防原始数组中没有空间存储新元素。本质上，这意味着分配一个新数组并复制对它的所有引用。

如果我们知道数组将增长多大并调用`ensureCapacity()`方法，那么可以优化数组的重新分配。这会将数组调整为作为参数提供的大小，即使当前使用的插槽编号较少。

我的经验是，新手程序员在需要列表时使用`ArrayList`，而不考虑不同实现的算法性能。我真的不知道为什么`ArrayList`会这么流行。在程序中使用的实际实现应该基于正确的决定而不是习惯。

# `Queue`（队列）

`Queue`是一个集合，通常存储元素供以后使用。您可以将元素放入队列中，然后将它们拉出。一个实现可以指定给定的顺序，可以是**先进先出**（**FIFO**）或**后进先出**（**LIFO**），或者一些基于优先级的顺序。

在队列中，您可以调用`add()`方法添加元素，`remove()`方法删除头元素，`element()`方法访问头元素而不将其从队列中删除。当存在容量问题且无法将元素添加到队列时，`add()`方法将引发异常。当队列为空且没有头元素时，`element()`和`remove()`方法抛出异常。

由于异常只能在异常情况下使用，并且调用程序可以在正常的代码过程中处理这些情况，因此所有这些方法都有一个版本，该版本只返回一些特殊的值来表示这种情况。调用者可以调用`offer()`来代替`add()`，以提供用于存储的元素。如果队列不能存储元素，则返回`false`。同样地，`peek()`会尝试接近头部元件，如果没有，则返回`null`，如果没有，`poll()`会移除并返回头部元件，如果没有，则返回`null`。

请注意，这些返回`null`的方法只是在实现（如`LinkedList`允许`null`元素）时使情况变得模糊。永远不要在队列中存储一个`null`元素，否则您将无法判断队列是空的还是只有第一个元素是`null`。

# `Deque`（双端队列）

`Deque`是一个双端队列接口。它使用允许访问队列两端的方法来扩展`Queue`接口，以便从队列两端添加、查看和删除元素。

对于`Queue`接口，我们需要六种方法。`Dequeue`有两个可管理的端，需要 12 种方法。我们有`addFirst()`和`addLast()`，而不是`add()`。同样，我们可以使用`offerFirst()`和`offerLast()`、`peekFirst()`和`peekLast()`、`pollFirst()`和`pollLast()`。由于某种原因，在`Queue`接口中实现`element()`方法功能的方法在`Dequeue`接口中被命名为`getFirst()`和`getLast()`。

因为这个接口扩展了`Queue`接口，所以这里定义的方法也可以用来访问队列的头部。除此之外，此接口还定义了`removeFirstOccurrence()`和`removeLastOccurrence()`方法，可用于移除队列中的特定元素。我们不能指定要删除的元素的索引，也不能基于索引访问元素。`removeFirst()`/`LastOccurrence()`方法的参数是要删除的对象。如果我们需要这个功能，我们可以使用`Deque`，即使我们在队列的一端添加和删除元素。

为什么`Deque`中有这些方法而`Queue`中没有？这些方法与`Deque`的双头性无关。原因是方法在发布后无法添加到接口。如果我们向接口添加一个方法，就会破坏向后兼容性，因为实现该接口的所有类都必须实现新方法。Java8 引入了默认方法来减轻这个限制，但是在 Java1.5 中定义了`Queue`接口，在 Java1.6 中定义了`Deque`接口。当时没有办法将新方法添加到已经存在的接口中。

# `Map`（映射）

`Map`将键和值配对。如果我们想从`Collection`的角度接近`Map`，那么`Map`就是一组键/值对。您可以将键/值对放入一个`Map`中，并可以基于一个键获得一个值。键与`Set`中的元素具有相同的唯一性。如果您查看`Set`接口的不同实现的源代码，您可能会发现其中一些实现是作为`Map`实现的包装器实现的，其中的值被简单地丢弃。

接口定义了很多方法。两种最重要的方法是`put()`和`get()`。`put(key,value)`方法可用于在映射中存储键/值对。如果有一对有一个键，我们想在对中设置的键`equals()`，那么旧值将被替换。此时，`put()`的返回值为旧对象，否则返回`null`。注意，返回的`null`值也可能表示与该键相关的值为`null`。

`get(key)`方法返回用指定键存储的值。同样，方法`equals()`用于检查所提供的键与映射中使用的键是否相等。如果映射没有任何与作为参数提供的键相关联的值，则此方法返回`null`。这也可能意味着与键相关联的实际值是`null`引用。

为了区分给定键没有存储值和存储值为`null`的两种情况，有另一种方法称为`contains()`。如果此映射包含指定键的映射，则此方法返回`true`。

您可以在 JDK 的 JavaDoc 文档中找到`Map`接口中的许多其他方法。

使用`Map`简单，诱人。许多语言（如 Python、Go、JavaScript 和 Perl）在语言级别上支持这种数据结构。然而，当数组足够时使用`Map`是一种我见过很多次的糟糕做法，尤其是在脚本语言中。Java 不容易出现新手程序员的错误，但是当你想使用一个`Map`的时候，你仍然会发现你自己处于这样的境地，而且，还有一个更好的解决方案。一般来说，应该使用最简单的数据结构来实现算法。

# `HashMap`（哈希映射）

`HashMap`是基于哈希表的`Map`接口实现。因为实现使用哈希表，`get()`和`put()`方法通常执行速度非常快、恒定，并且与映射中的实际元素数无关。如果映射大小增加，并且表元素的数量不足以以符合人体工程学的方式存储元素，那么将新元素放入这种类型的映射可能会迫使实现调整底层数组的大小。在这种情况下，数组中已经存在的每个元素都必须重新放置在新的、增大的数组中。在这些情况下，`put()`操作可能消耗大量时间，与映射中元素的数量成比例。

当一个元素要存储在这个映射中时，对键对象调用`hashCode()`方法，返回值用来决定底层哈希表的哪个桶应该存储这个新元素。桶包含一个简单的二叉树结构。如果桶是空的，在这个结构中存储元素就像元素直接存储在桶中一样简单。另一方面，当两个或多个元素具有相同的`hashCode()`值时，它们也可以存储在同一个存储桶中的映射中，尽管效率有点下降。

由于`hashCode()`值可能发生冲突，`get()`或`put()`方法调用所需的时间可能比其他方法长一点点。

`Map`接口的实现是 Java 程序中使用最频繁的一种，实现经过微调，使用可以配置。最简单的方法是创建一个调用默认构造器的`HashMap`。如果我们碰巧知道映射上有多少元素，那么我们可以指定它，并将`int`传递给构造器。在这种情况下，构造器将分配一个数组，数组的大小不小于我们所需的容量，大小是两个幂。

还有第三个构造器，我们可以在其中定义一个`float`负载因子。负荷系数的默认值为`0.75`。当映射中的元素数大于哈希表大小乘以加载因子的大小时，下一个`put()`调用将使基础哈希表的大小加倍。这种提前调整大小的方法试图避免`hashCode()`碰撞变得过于频繁。如果我们将某个特殊类的实例存储在我们确信`hashCode()`非常好的地方，那么我们可以将负载因子设置得更接近`1.0`。如果我们不太在意速度，也不希望底层哈希表增加太多，我们甚至可以使用大于`1.0`的值。不过，在这种情况下，我会考虑使用一些不同的数据结构。

在大多数情况下，我们需要`Map`时的选择是`HashMap`。通常，我们不应该太过担心这些实现细节。然而，在一些罕见的情况下，当内存使用或性能下降时，我们应该知道我们使用的映射的实现复杂性。

# `IdentityHashMap`（身份哈希映射）

`IdentityHashMap`是实现`Map`接口本身的特殊`Map`，但事实上，该实现违反了文档定义的`Map`接口的约定。它这样做是有充分理由的。实现使用的哈希表与`HashMap`相同，但是为了确定桶中找到的键与`get`方法的参数键元素的相等性，它使用了`Object`引用（`==`运算符），而不是`Map`接口文档要求的方法`equals()`。

当我们想将不同的`Object`实例区分为键时，使用此实现是合理的，否则是相等的。出于性能原因使用此实现几乎肯定是错误的决定。另外，注意，JDK 中没有`IdentityHashSet`实现。很可能，这样的集合很少使用，以至于它在 JDK 中的存在会造成比好的更大的危害，这会引诱新手程序员误用。

# 依赖注入

在上一章中，我们已经简要讨论了**依赖注入**（**DI**）。在继续我们的示例之前，我们将更详细地研究它。我们之所以这样做，是因为我们将创建的编程结构在很大程度上建立在这个原则之上。

对象通常不会自己工作。大多数时候，实现依赖于其他类的服务。例如，当我们想向控制台写入内容时，我们使用`System`类，并通过该对象使用`final`字段`out`和`println()`方法。另一个例子是，当我们管理猜测表时，我们需要`Color`对象和`ColorManager`。

在写入控制台时，我们可能没有意识到依赖性，因为类作为 JDK 类库的一部分，一直都是可用的，我们需要做的就是写入`System.out.println()`。因为我们有腿，所以这可能和能走路一样明显。无论这看起来多么简单，我们都依赖于我们的腿来行走，同样地，当我们要向控制台写入数据时，我们也依赖于`System`类。

当我们刚刚编写`System.out.println()`时，依赖关系就被连接到了代码中。除非修改代码，否则无法将输出发送到其他地方。这不是很灵活，而且在许多情况下，我们需要一个能够处理不同输出、不同颜色管理器或不同类型的代码所依赖的服务的解决方案。

第一步是使用一个字段来引用为类提供服务的对象。在输出的情况下，字段的类型可以是`OutputStream`类型。如果我们在代码中使用这个字段，而不是直接连接到代码中的内容，那么我们就有可能使用不同的依赖关系。例如，我们可以将输出发送到文件而不是控制台。我们不需要更改编写代码的地方。我们所要做的就是在对象创建过程中为引用`OutputStream`的字段指定一个不同的值。

这已经是下一步了，即该字段如何获取值。

解决方案之一是使用 DI。在这种方法中，一些外部代码准备依赖项并将它们注入到对象中。当发出对类的方法的第一个调用时，所有依赖项都已填充并准备好使用。

在这个结构中，我们有四个不同的参与者：

*   `client`对象是在该过程中获取注入的`service`对象的对象
*   `service`对象被注入`client`对象
*   注入器是执行注入的代码
*   接口定义客户端需要的服务

如果我们从客户端代码中移动创建`service`对象的逻辑，代码就会变得更短、更干净。`client`类的实际能力几乎不应涵盖`service`对象的创建。例如，`Game`类包含`Table`实例，但游戏不负责创建`Table`。它被赋予与它一起工作，就像我们在现实生活中建模一样。

创建`service`对象有时就像发出`new`操作符一样简单。有时，`service`对象也依赖于其他`service`对象，并且在 DI 过程中充当客户端。在这种情况下，`service`对象的创建可能需要很多行。依赖关系的结构可以用一种声明性的方式来表示，它描述了哪个`service`对象需要其他`service`对象，以及要使用的服务接口的实现。DI 注入器使用这种声明性描述。当需要一个需要`service`对象的对象本身需要其他`service`对象时，注入器使用与声明性描述匹配的实现以适当的顺序创建服务实例。注入器以传递方式发现所有依赖项，并创建依赖项的传递闭包图。

对所需依赖项的声明性描述可以是 XML，或者是专门为 DI 开发的一种特殊语言，甚至可以是 Java 本身，使用一个专门设计的 [Fluent API](https://blog.jooq.org/2012/01/05/the-java-fluent-api-designer-crash-course/)。XML 最早是在 DI 中使用的。后来，基于 **Groovy** 的[**领域专用语言**](https://martinfowler.com/books/dsl.html)是作为一种 Java Fluent API 方法出现的。我们将只使用最后一个，因为它是最现代的，我们将使用 **Spring** 和 **Guice** **DI** 容器，因为它们是最著名的注入器实现。

# 实现游戏

没有例子的集合很无聊。幸运的是，在我们的游戏中，我们使用了一些集合类，以及我们将在本章中研究的其他方面。

# 色彩管理

我们跳进了池中，池中充满了实现`ColorManager`类的集合类。让我们用类中我们感兴趣的部分来刷新我们的记忆，现在是构造器：

```java
package packt.java189fundamentals.example.mastermind;

import java.util.HashMap;
import java.util.Map;

public class ColorManager {
    final protected int nrColors;
    final protected Map<Color, Color> successor = new HashMap<>();
    private Color first;

    public ColorManager(int nrColors) {
        this.nrColors = nrColors;
        createOrdering();
    }

    protected Color newColor(){
        return new Color();
    }

    private Color[] createColors() {
        Color[] colors = new Color[nrColors];
        for (int i = 0; i < colors.length; i++) {
            colors[i] = newColor();
        }
        return colors;
    }

    private void createOrdering() {
        Color[] colors = createColors();
        first = colors[0];
        for (int i = 0; i < nrColors - 1; i++) {
            successor.put(colors[i], colors[i + 1]);
        }
    }
    // ...
}
```

我们用`HashMap`来保持颜色在一个有序的列表中。一开始，选择`HashMap`似乎很奇怪。的确，在`ColorManager`的编码过程中，我也考虑了`List`，这似乎是一个比较明显的选择。如果我们有一个`List<Color> colors`变量，那么`nextColor`方法是这样的：

```java
public Color nextColor(Color color) { 
     if (color == Color.none) 
         return null; 
     else 
         return colors.get(colors.indexOf(color) + 1); 
 }
```

构造器将更简单，如以下代码所示：

```java
final List<Color> colors = new ArrayList<>(); 

     public ColorManager(int nrColors) { 
         this.nrColors = nrColors; 
         for (int i = 0; i < nrColors; i++) { 
             colors.add(new Color()); 
         } 
         colors.add(Color.none); 
     } 

     public Color firstColor() { 
         return colors.get(0); 
     }
```

为什么我要选择更复杂的解决方案和更复杂的数据结构？原因是性能。调用`nextColor()`方法时，列表实现首先找到检查列表中所有元素的元素，然后获取下一个元素。时间与颜色的数量成正比。当我们的颜色数量增加时，时间也会增加到下一个颜色有一个。

同时，如果我们关注我们想要实现的实际方法`nextColor(Color)`，而不是我们想要解决的任务的口头表达（以排序顺序获得颜色），那么我们很容易得出`Map`更合理的结论。我们需要的正是一个`Map`元素，我们想要另一个与我们有关联的元素。键和值也是`Color`。使用`HashMap`获取下一个元素实际上是恒定时间。这种实现可能比基于`ArrayList`的实现更快。

问题是它只可能更快。当您考虑重构代码以获得更好的性能时，您的决策应该始终基于度量。实践表明，如果你实现了你认为更快的代码，你就会失败。在最好的情况下，您将优化代码，使其速度极快，并在应用服务器安装期间运行。同时，优化后的代码通常可读性较差。为了某样东西。决不能过早地进行优化。代码的可读性第一。然后，评估性能，如果性能有问题，分析执行情况并优化对整体性能影响最大的代码。微优化也无济于事。我是否做了过早的优化选择`HashMap`实现而不是`List`？如果我真的用`List`实现了代码，然后重构了它，那么是的。如果我在考虑`List`解决方案，然后我发现`Map`解决方案在没有事先编码的情况下更好，那么我没有。随着你积累更多的经验，这样的考虑会变得更容易。

# `Color`类

我们已经研究了类代码的代码，它是世界上最简单的类。实际上，由于它位于 Packt 代码存储库中，代码更复杂：

```java
/**
 * Represents a color in the MasterMind table.
 */
public class Color {
    /**
     * A special object that represents a
     * value that is not a valid color.
     */
    public static final Color none = new Color();
}
```

我们有一个名为`none`的特殊颜色常数，用来表示一个类型为`Color`但不是有效的`Color`的引用。在专业发展中，我们长期使用`null`值来表示无效引用，因为我们向后兼容，所以我们仍然使用它。但是，建议尽可能避免引用`null`。

[托尼·霍尔](https://en.wikipedia.org/wiki/Tony_Hoare)，曾经承认这是一个错误，在 IT 行业花费了数十亿美元。

`null`值的问题是它将控件从类中移除，从而打开了封装。如果某个方法在某种情况下返回`null`，则严格要求调用方检查空值并据此进行操作。例如，您不能在`null`引用上调用方法（至少在 Java 中不能这样做），也不能访问任何字段。如果方法返回一个对象的特殊实例，这些问题就不那么严重了。如果调用方忘记检查特殊返回值并调用特殊实例上的方法，则调用的方法仍有可能实现某些异常或错误处理。该类封装了控件，并可以引发一个特殊异常，该异常可能会提供有关调用方未检查特殊值的编程错误所导致的错误的更多信息。

# JavaDoc 和代码注释

我们前面介绍的内容和清单之间还有另一个区别。这是代码的注释。代码注释是程序的一部分，被编译器忽略并过滤掉。这些注释仅适用于维护或使用代码的人员。

在 Java 中，有两种不同的注释。`/*`和`*/`之间的代码是注释。注释的开头和结尾不必在同一行。另一种类型的注释以`//`字符开始，并在行尾结束。

为了记录代码，可以使用 JavaDoc 工具。JavaDoc 是 JDK 的一部分，它是一个特殊的工具，可以读取源代码并提取有关类、方法、字段和其他实体的 HTML 文档，这些实体的注释以`/**`字符开头。文档将以格式化的方式包含 JavaDoc 注释以及从程序代码中提取的信息。

当您将鼠标移到方法调用或类名（如果有）上时，文档也会显示为 IDE 中的联机帮助。JavaDoc 注释可以包含 HTML 代码，但通常不应该包含。如果真的需要，可以使用`<p>`开始一个新段落或`<pre>`标签，将一些预先格式化的代码样本包含到文档中，但没有什么能带来真正的好处。文档应尽可能短，并包含尽可能少的格式。

JavaDoc 文档中可以出现一些特殊的标记。当您开始将 JavaDoc 键入为`/**`，然后按`Enter`时，IDE 会预先填充这些内容。这些都在注释中，以`@`字符开头。有一组预定义的标签-`@author`、`@version`、`@param`、`@return`、`@exception`、`@see`、`@since`、`@serial`和`@deprecated`。最重要的标签是`@param`和`@return`。它们用于描述方法参数和返回值。虽然我们还没有到，但是让我们先看看`Guesser`类中的`guessMatch`方法：

```java
/**
 * A guess matches if all rows in the table matches the guess.
 *
 * @param guess to match against the rows
 * @return true if all rows match
 */
private boolean guessMatch(Color[] guess) {
    for (Row row : table.rows) {
        if (!row.guessMatches(guess)) {
            return false;
        }
    }
    return true;
}
```

参数的名称由 IDE 自动生成。当你创建文档时，写一些有意义的东西，而不是重复。很多时候，新手程序员都有编写 JavaDoc 的冲动，必须编写一些关于参数的内容。他们创建如下文档：

```java
* @param guess is the guess
```

真正地？我怎么也猜不到。如果您不知道在那里写什么来记录参数，那么可能是您选择了参数的名称。

我们前面示例的文档如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/702fd60b-15cf-4d7c-a4fd-dd4b2b6add2d.png)

关注方法、类和接口的作用以及如何使用 JavaDoc。不要解释它是如何在内部工作的。JavaDoc 不是解释算法或编码的地方。它的目的是帮助使用代码。然而，如果有人碰巧解释了一个方法是如何工作的，那就不是灾难了。注释很容易被删除。

然而，有一条注释比什么都没有更糟糕：过时的文档不再有效。当元素的约定发生了更改，但文档没有遵循更改，并且误导了希望调用方法、接口或类的用户时，它将面临严重的错误，并且将不知所措。

从现在起，JavaDoc 注释将不会以打印的形式列出以保存树，电子版也不会列出，但它们在存储库中，可以检查。

# `Row`

现在，我们有一个`Color`类，甚至当我们需要一个`ColorManager`时还有实例。这是在`Row`对象中存储`Color`对象的时间。`Row`类稍长，但不太复杂。在本节中，我们将以小片段的形式查看代码，并在其中进行解释：

```java
package packt.java189fundamentals.example.mastermind;

public class Row {
    final Color[] positions;
    protected int matchedPositions;
    protected int matchedColors;
```

`Row`包含三个字段。一种是`positions`数组。数组的每个元素都是一个`Color`。`matchedPositions`是匹配的位置数，`matchedColors`是匹配隐藏行中某一颜色但不在隐藏行中相同位置的颜色数：

```java
public static final Row none = new Row(Guesser.none);
```

`none`是一个常量，它包含一个特殊的`Row`实例，我们将在任何地方使用`null`。构造器获取数组中应位于行中的颜色：

```java
public Row(Color[] positions) {
    this.positions = Arrays.copyOf(positions, positions.length);
}
```

构造器复制原始数组。这是一段重要的代码，我们将稍微研究一下。让我们重申一下，Java 通过值传递参数。这意味着当您将一个数组传递给一个方法时，您将传递保存该数组的变量的值。然而，Java 中的数组是一个对象，就像其他任何东西一样（除了像`int`这样的原始类型）。因此，变量所包含的是对恰好是数组的对象的引用。如果更改数组的元素，实际上就是更改原始数组的元素。参数通过时复制数组引用，但数组本身和元素不通过。

`java.util.Arrays`实用类提供了很多有用的工具。我们可以很容易地用 Java 编写数组复制代码，但是为什么要重新设计这个轮子呢？此外，数组是一个连续的内存区域，可以使用低级机器代码非常有效地从一个地方复制到另一个位置。我们调用的`copyOf`方法调用了`System.arraycopy`方法，它是一个本地方法，因此执行本机代码。

请注意，不能保证`Arrays.copyOf`调用本机实现，并且在大型数组的情况下这将非常快。我正在测试和调试的版本就是这样做的，我们可以假设一个好的 JDK 做了类似的、有效的和快速的事情。

在我们复制了数组之后，如果调用方修改了传递给构造器的数组，这就不是问题了。该类将引用一个包含相同元素的副本。但是，请注意，如果调用者更改了存储在数组中的任何对象（不是数组中的引用，而是数组元素引用的对象本身），则会修改同一对象。`Arrays.copyOf`不复制数组引用的对象，只复制数组元素。在我们的例子中，数组中有`Color`个实例，因为这个类根本没有字段，所以它本质上是不可变的，没有可以更改的实例。

该行与颜色一起创建，因此我们为名为`positions`的`Color`数组使用了一个`final`字段。但是，当创建一行时，无法知道匹配项；因此，它们不能是`final`。其中一个玩家创建了`Row`，然后，另一个玩家稍后会告诉你这两个`int`值。我们需要一个设置器来设置这些字段。但是，我们不会为这两个值创建两个设置器，因为它们在游戏中总是同时定义在一起：

```java
public void setMatch(int matchedPositions, int matchedColors) {
    if (matchedColors + matchedPositions > positions.length) {
        throw new IllegalArgumentException(
                "Number of matches can not be more that the position.");
    }
    this.matchedColors = matchedColors;
    this.matchedPositions = matchedPositions;
}
```

`setMatch`方法不仅设置值，而且检查值是否一致。两个值之和不能超过列数。此检查确保使用`Row`类 API 的调用方不会不一致地使用它。如果这个 API 只在我们的代码中使用，那么这个断言不应该是代码的一部分。在这种情况下，良好的编码风格将确保使用单元测试时不会不一致地调用该方法。当我们在无法控制的情况下创建要使用的 API 时，我们应该检查使用是否一致。如果不这样做，我们的代码在不一致地使用时可能会表现得很奇怪。当调用者将匹配设置为与任何可能的猜测都不匹配的值时，游戏可能永远不会结束，调用者可能很难弄清楚到底发生了什么。这可能需要我们代码的调试执行。这不是库用户的任务。始终尝试创建不需要从 API 使用者处调试的代码。

如果我们在这种情况下抛出异常，程序将在错误所在的位置停止。不需要调试库。

以下方法决定作为参数给出的猜测是否与实际行匹配：

```java
public boolean guessMatches(Color[] guess) {
    return nrMatchingColors(guess) == matchedColors &&
            nrMatchingPositions(guess) == matchedPositions;
}
```

如果当前猜测在隐藏行中，此方法检查行中猜测的答案是否有效。实现相当简短。如果匹配的颜色数和匹配的位置数与行中给定的数字相同，则猜测匹配一行。当然，在`nrMatchingColors()`和`nrMatchingPositions()`方法的实现中有一些额外的代码，但是这个方法确实很简单。不要羞于写简短的方法！不要认为本质上只包含一条语句的单行方法是无用的。无论在哪里使用这个方法，我们都可以编写表达式，它就在`return`语句的后面，但是我们不这样做有两个原因。第一个也是最重要的原因是，决定行与猜测匹配的算法属于类`Row`的实现。如果实现发生了任何变化，那么要更改代码的唯一位置就是这里。另一个原因也很重要，那就是可读性。在我们的代码库中，我们从`abstract class Guesser`调用这个方法。它包含一个具有以下表达式的`if`语句：

```java
if (!row.guessMatches(guess)) {
```

下面的方式会更容易阅读吗？

```java
if( !(nrMatchingColors(guess) == matchedColors && nrMatchingPositions(guess) ==
matchedPositions)) {
```

我确信大多数程序员更容易理解第一个版本的意图。我甚至建议实现`doesNotMatchGuess`方法来进一步提高代码的可读性：

```java
public int nrMatchingColors(Color[] guess) {
    int count = 0;
    for (int i = 0; i < guess.length; i++) {
        for (int j = 0; j < positions.length; j++) {
            if (i != j && guess[i] == positions[j]) {
                count++;
            }
        }
    }
    return count;
}
```

匹配颜色的数量是行中和猜测中出现的颜色的数量，但不在同一位置。如果隐藏行中不能出现两次颜色，那么定义以及如何计算它是相当简单和明确的。如果颜色可能在隐藏行中多次出现，则此实现将将猜测中该颜色的所有出现次数计算为人工时间，因为它显示在隐藏行中。例如，如果我们有一个隐藏的`RRGB`行，并且猜测是`bYRR`，计算将是 4。这是球员之间的一致性问题，他们在这个案子中的计数方式。重要的方面是，他们使用的算法是相同的，在我们的例子中应该是正确的，因为我们会要求程序同时播放两个播放器，而且因为我们在本章开头定义，在隐藏行中没有颜色可以出现不止一次。

因为我们自己会编写代码，所以我们可以相信它不会作弊。

计算好的颜色，以及它们应该在的位置，就更简单了：

```java
public int nrMatchingPositions(Color[] guess) {
    int count = 0;
    for (int i = 0; i < guess.length; i++) {
        if (guess[i] == positions[i]) {
            count++;
        }
    }
    return count;
}
```

此类中的最后一个方法是返回列数的方法：

```java
public int nrOfColumns() {
    return positions.length;
}
```

此方法告知`Row`中的列数。在控制整个游戏流程的`Game`类中需要此方法。由于该类与`Row`在同一个包中，因此可以访问字段位置。我创建了代码以获得列数作为`row.positions.length`。但是第二天，我在看代码的时候告诉自己这太难看了！这里我感兴趣的不是一些神秘位置的长度，而是列的数量。列的数量是`Row`类的责任，而不是任何其他类的业务。如果我开始将位置存储在一个`List`中，它没有`length`（它有方法`size()`），这是`Row`的唯一责任，不应影响任何其他代码。因此，我创建了`nrOfColumns()`方法来改进代码并进行适当的封装。

`Row`类有另一个从另一行克隆行的构造器：

```java
protected Row(Row cloneFrom) {
    this(cloneFrom.positions);
    setMatch(cloneFrom.matchedPositions, cloneFrom.matchedColors);
}
```

这是通过扩展`PrintableRow`类来使用的。这个类使得在测试运行期间，我们可以打印出表、猜测以及游戏的一般运行方式。

`PrintableRow`类如下：

```java
package packt.java189fundamentals.example.mastermind;

public class PrintableRow extends Row {
    public PrintableRow(Row row) {
        super(row);
    }

    public Color position(int i) {
        return positions[i];
    }

    public int matchedPositions() {
        return matchedPositions;
    }

    public int matchedColors() {
        return matchedColors;
    }
}
```

这些方法的第一个版本在`Row`类中，然后转移到新的`PrintableRow`类中。在重构过程中，我经常剪切和粘贴 IDE 的功能。我还可以使用重构支持将方法直接从一个类移动到另一个类。有一个 IDE 功能不应该用于复制和粘贴。

在编写代码时，请不要使用复制和粘贴。您可以使用剪切和粘贴来移动代码片段。危险在于复制粘贴的使用。许多开发人员声称他们实际使用的复制和粘贴并不是复制粘贴编程。他们的理由是，他们更改粘贴的代码太多，几乎与原始代码没有任何关系。真正地？在这种情况下，为什么在开始修改时需要复制的代码？为什么不从头开始呢？这是因为如果您使用 IDE 的复制和粘贴功能，那么不管怎样，您都要进行复制粘贴编程。面对现实，不要试图欺骗自己。

`PrintableRow`非常简洁，将输出关注点与核心功能分开。当你需要一个实例时，你手头已经有一个`Row`实例不是问题。构造器将基本上克隆原始类并返回可打印的版本，调用父类中定义的克隆构造器。在这个类的开发过程中，我在`PrintableRow`类中创建了克隆代码。但是，这种功能放置违反了封装。即使`PrintableRow`扩展了`Row`类，因此，了解父类的内部工作并不是永恒的罪恶，如果可能的话，最好不要依赖它。因此，新的`protected`构造器是在父类中创建的，并从子类调用。

一段代码永远不会完成，也永远不会完美。在专业环境中，程序员往往会在代码足够好的时候完成抛光。没有任何代码是无法改进的，但是有一个最后期限。软件必须传递给测试人员和用户，并且必须用来帮助节约。毕竟，拥有支持业务的代码是专业开发人员的最终目标。从不运行的代码一文不值。我不想让你认为我在这里提供的例子是在前面完美地创造出来的。在这本书的第二版中，我甚至不敢说它们是完美的。原因是（你仔细阅读了吗？）因为它们并不完美。正如我所说，代码永远都不是完美的。当我第一次创建`Row`时，它包含了一个内部类中的打印方法。我不喜欢它。密码很臭。所以，我决定将功能移到`Row`类。不过，我还是不喜欢这个解决方案。然后，我上床睡觉，工作，几天后又回来了。我前一天无法创建的东西现在看来很明显，这些方法必须移动到一个子类中。现在又出现了另一个困境。我应该给出这个最终的解决方案还是应该在这里有不同的版本？在某些情况下，我将只介绍最终版本。在其他情况下，像这样，从开发步骤中可以学到一些东西。在这些案例中，我不仅介绍了代码，而且还介绍了代码的一部分演变过程。我承认，有时候，我创建的代码甚至让我一天后自己也会捂脸。谁不呢？

# `Table`

Mastermind 表是一个简单的类，它只有一个非常简单的功能：

```java
public class Table {
    final ColorManager manager;
    final int nrColumns;
    final List<Row> rows;
    public Table(int nrColumns, ColorManager manager) {
        this.nrColumns = nrColumns;
        this.rows = new LinkedList<>();
        this.manager = manager;
    }
    public void addRow(Row row) {
        rows.add(row);
    }
}
```

有一件事要提，这不是什么新鲜事，但值得重复。`rows`变量被声明为`final`，并在构造器中获取值。这是一个`List<Row>`型变量。它是`final`这一事实意味着它将在其生存期内持有相同的列表对象。列表的长度、成员和其他特性可能会改变，也将改变。我们将向该列表添加新行。最终对象变量引用一个对象，但不能保证对象本身是不可变的。只有变量不变。

当你做一个代码回顾并向你的同事解释一个类是做什么的时候，你发现自己开始*非常简单*地解释这个类很多次，这意味着代码是好的。好吧，它在其他方面可能仍然是错误的，但至少类的粒度似乎是好的。

# `Guesser`

`Guesser`抽象类和`UniqueGuesser`和`GeneralGuesser`子类是程序中最有趣的类。他们实际执行的任务是游戏的核心。给定一个带有隐藏行的`Table`，猜测者必须创建新的猜测。

为此，`Guesser`需要在创建时获得`Table`。这是作为构造器参数传递的。它应该实现的唯一方法是`guess`，它根据表和它的实际状态返回一个新的猜测。

我们要实现一个猜测器，它假设隐藏行中的所有颜色都是不同的，同时也要实现一个不做此假设的猜测器；我们将实现三个类来实现这一点。`Guesser`是一个抽象类，它只实现独立于假设的逻辑。这些方法将被两个实际实现继承，`UniqueGuesser`和`GeneralGuesser`，如果每种颜色在一行中是唯一的或不是唯一的，它们将分别实现猜测功能。

让我们看看这个类的实际代码：

```java
package packt.java189fundamentals.example.mastermind;

public abstract class Guesser {
    protected final Table table;
    private final ColorManager manager;
    protected final Color[] lastGuess;
    public static final Color[] none = new Color[]{Color.none};

    public Guesser(Table table) {
        this.table = table;
        this.lastGuess = new Color[table.nrColumns];
        this.manager = table.manager;
    }
```

猜测者的状态是最后一次猜测。虽然这是表的最后一行，但更多的是猜测者的内部问题。猜测者拥有所有可能的猜测，一个接一个；`lastGuess`是它上次停止的地方，当它再次被调用时，应该从那里继续。

在这个类中，`none`只是一个对象，当我们需要返回某个对`Guess`的引用但不是真正的猜测时，我们尝试使用它来代替`null`。

设置第一个猜测在很大程度上取决于颜色唯一性的假设：

```java
abstract protected void setFirstGuess();
```

如果隐藏行不允许包含任何颜色，则第一个猜测不应包含重复的颜色，因此此类中的方法是抽象的。

下一个方法是在具体类中覆盖的内部方法：

```java
protected Color[] nextGuess() {
    if (lastGuess[0] == null) {
        setFirstGuess();
        return lastGuess;
    } else {
        return nextNonFirstGuess();
    }
}
```

`nextGuess`方法是一个内部的方法，它生成下一个猜测，它正好在我们排序可能的猜测时出现。它不检查任何与`Table`相对的东西；它几乎不经过思考只生成下一个猜测。如何进行第一次猜测和如何进行连续猜测的实现是不同的。因此，我们用不同的方法实现这些算法，并从这里调用它们。

`nextNonFirstGuess`方法表示在特殊情况下，当猜测不是第一个猜测时的下一个猜测：

```java
private Color[] nextNonFirstGuess() {
    int i = 0;
    boolean guessFound = false;
    while (i < table.nrColumns && !guessFound) {
        if (manager.thereIsNextColor(lastGuess[i])) {
            lastGuess[i] = manager.nextColor(lastGuess[i]);
            guessFound = true;
        } else {
            lastGuess[i] = manager.firstColor();
            i++;
        }
    }
    if (guessFound) {
        return lastGuess;
    } else {
        return none;
    }
}
```

回顾几页我们详细介绍了算法的工作原理。我们说过，这种工作方式很像我们用十进制数计算的方式。到目前为止，您已经有足够的 Java 知识和编程技能来理解该方法的功能。更有趣的是知道为什么它是这样编码的。

一如既往地暗示，要可读。

有消除`guessFound`变量的诱惑。当我们发现幸运的猜测时，从方法的中间返回不是更简单吗？如果我们这样做了，在返回`none`值之前就不需要检查`guessFound`值。如果我们从循环中间返回，代码就不会到达那里。

是的，写起来会更简单。但是，我们创建的代码是可读的，而不是可写的。你可以说*是的，但是代码越少可读性越强*。在这种情况下不行！从循环返回会降低可读性。更不用说，`return`语句分散在方法的不同执行阶段。

此外，从循环返回表示循环的隐式结束条件。在我们的例子中，循环的头清楚地说明了我们在循环中迭代了多长时间，直到我们在计算表的总宽度或者我们找到了一个猜测。

当有人以这种方式编写优化的代码时，就像一个蹒跚学步的孩子迈出第一步，然后骄傲地看着他/她的母亲。好吧，男孩/女孩，你很棒。现在，继续走吧。当你是邮递员时，走路会很无聊。那将是你的职业。所以，把骄傲放在一边，写一些无聊的代码。专业人士编写枯燥的代码。不会很慢吧？

不！不会慢的。首先，在探查器证明代码不满足业务需求之前，它并不慢。如果是这样的话，它就足够快了，不管它有多慢。慢是好的，只要它是好的业务。毕竟，实时编译器（JIT）应该有一些任务来优化要运行的代码。

下面的方法检查猜测是否与之前的猜测及其在`Table`上的结果相匹配：

```java
private boolean guessMatch(Color[] guess) {
    for (Row row : table.rows) {
        if (!row.guessMatches(guess)) {
            return false;
        }
    }
    return true;
}
```

因为我们已经在类`Row`中实现了猜测匹配，所以我们所要做的就是为表中的每一行调用该方法。如果所有行都匹配，那么猜测可能对表有利。如果前面的任何猜测都不匹配，那么这个猜测就泡汤了。

在检查匹配的否定表达式时，我们创建了否定方法的英文版本。

在这种情况下，创建方法的`guessDoesNotMatch`版本就足够了。但是，如果方法没有被求反，那么代码的逻辑执行更具可读性。因此，单独编写`guessDoesNotMatch`方法更容易出错。相反，我们将实现原始的、可读的版本，并且 aux 方法只不过是一个否定。

在所有 aux 方法之后，我们要实现的下一个也是最后一个方法是`public`方法，`guess()`：

```java
public Row guess() {
    Color[] guess = nextGuess();
    while (guess != none && guessDoesNotMatch(guess)) {
        guess = nextGuess();
    }
    if (guess == none) {
        return Row.none;
    } else {
        return new Row(guess);
    }
}
```

它只是一次又一次地调用`nextGuess()`，直到找到一个与隐藏行匹配的猜测，或者没有更多的猜测。如果它找到一个正确的猜测，它会将它封装到一个`Row`对象中，并返回它，以便以后可以由`Game`类将它添加到`Table`中。这种算法在两种情况下是相同的，在一行中有唯一和非唯一的颜色。

# `UniqueGuesser`

`UniqueGuesser`类必须实现`setFirstGuess`（所有扩展抽象类的具体类都应该实现父类的抽象方法），它可以并且将覆盖受保护的`nextGuess`方法：

```java
package packt.java189fundamentals.example.mastermind;

import java.util.HashSet;

public class UniqueGuesser extends Guesser {

    public UniqueGuesser(Table table) {
        super(table);
    }

    @Override
    protected void setFirstGuess() {
        int i = lastGuess.length - 1;
        for (var color = table.manager.firstColor();
             i >= 0;
             color = table.manager.nextColor(color)) {
            lastGuess[i--] = color;
        }
    }
```

`setFirstGuess`方法选择第一个猜测的方式是，如果我们遵循算法，在第一个猜测之后出现的任何可能的颜色变化都会一个接一个地产生猜测。

如果猜测包含重复的颜色，`isNotUnique` aux 方法返回`true`。看多少不有趣。如果所有颜色都相同，或者只有一种颜色出现两次，则无所谓。这个猜测并不独特，不适合我们的猜测者。这个方法告诉我们。

注意，在讨论`Set`JDK 接口时，已经列出了此方法：

```java
private boolean isNotUnique(Color[] guess) {
    final var alreadyPresent = new HashSet<Color>();
    for (final var color : guess) {
        if (alreadyPresent.contains(color)) {
            return true;
        }
        alreadyPresent.add(color);
    }
    return false;
}
```

为此，它使用一个`Set`，并且每当在`guess`数组中发现新颜色时，该颜色就存储在集合中。如果在数组中找到该颜色时，该集包含该颜色，则表示该颜色以前已经使用过；猜测不是唯一的。

另外，请注意，在本例中，我以从循环中间返回的方式对循环进行了编码。*不要从循环/方法中间返回*规则不是一成不变的。在这种情况下，我觉得从循环的中间返回会提供更好的可读性，而不是引入一个新的`boolean`。循环很短，无论谁读代码，都可以很容易地发现循环头下面的两行。

我们必须在这个具体类中实现的最后一个方法是`nextGuess()`：

```java
@Override
protected Color[] nextGuess() {
    Color[] guess = super.nextGuess();
    while (isNotUnique(guess)) {
        guess = super.nextGuess();
    }
    return guess;
}
```

覆盖的`nextGuess()`方法很简单。它要求超类的`nextGuess()`实现进行猜测，但丢弃了它不喜欢的猜测。

# `GeneralGuesser`

`GeneralGuesser`类还必须实现构造器和`setFirstGuess`，但一般来说就是这样。它不需要做任何其他事情：

```java
package packt.java189fundamentals.example.mastermind;

public class GeneralGuesser extends Guesser {

    public GeneralGuesser(Table table) {
        super(table);
    }

    @Override
    protected void setFirstGuess() {
        int i = 0;
        for (Color color = table.manager.firstColor();
             i < lastGuess.length;
            ) {
            lastGuess[i++] = color;
        }
    }
}
```

算法非常简单。它只是将第一种颜色放入`lastGuess`数组的每一列。`Guess`再简单不过了。其他一切都是从`abstract class Guesser`继承的。

# `Game`类

`Game`类的实例包含保存秘密颜色值的`Row`，还包含`Table`。当有新的猜测时，`Game`实例将猜测存储到`Table`中，并设置与秘密行匹配的位置数和颜色数：

```java
package packt.java189fundamentals.example.mastermind;

public class Game {

    final Table table;
    final private Row secretRow;
    boolean finished = false;
    final int nrOfColumns;

    public Game(Table table, Color[] secret) {
        this.table = table;
        this.secretRow = new Row(secret);
        this.nrOfColumns = secretRow.nrOfColumns();
    }

    public void addNewGuess(Row row) {
        if (isFinished()) {
            throw new IllegalArgumentException(
                "You can not guess on a finished game.");
        }
        final int positionMatch =
            secretRow.nrMatchingPositions(row.positions);
        final int colorMatch =
            secretRow.nrMatchingColors(row.positions);
        row.setMatch(positionMatch, colorMatch);
        table.addRow(row);
        if (positionMatch == nrOfColumns) {
            finished = true;
        }
    }

    public boolean isFinished() {
        return finished;
    }
}
```

想想我之前写的简短方法。当您从 Packt 存储库下载代码来使用它时，请尝试使它看起来更可读。您也许可以创建并使用一个名为`boolean itWasAWinningGuess(int positionMatch)`的方法。

# 创建集成测试

我们已经在上一章中创建了单元测试，并且在本章的类中也有实现功能的单元测试。我们不会在这里打印这些单元测试，但是您可以在 Packt 代码库中找到它们。我们将看一个集成测试，而不是列出单元测试。

集成测试需要调用许多协同工作的类。它们检查功能是否可以由整个应用交付，或者至少是由应用的较大部分交付，而不是集中在单个单元上。它们被称为集成测试，因为它们测试类之间的集成。光上课都可以。他们不应该有任何问题，因为它已经被单元测试验证了。集成的重点是它们如何协同工作。

如果我们想测试`Game`类，我们要么创建模仿其他`Game`类行为的模拟，要么编写一个集成测试。从技术上讲，集成测试与单元测试非常相似。在大多数情况下，使用完全相同的 JUnit 框架来执行集成测试。这个游戏的集成测试就是这样。

但是，构建工具需要配置为仅在需要时执行集成测试。通常，集成测试的执行需要更多的时间，有时还需要更多的资源，例如外部数据库，这些资源可能不在每个开发人员的桌面上都可用。每次编译应用时都会运行单元测试，所以它们必须很快。为了将单元测试和集成测试分开，有不同的技术和配置选项，但实际上没有这样的标准，比如 Maven 引入的目录结构（后来由 Gradle 改编）。

在我们的例子中，集成测试不需要任何额外的资源，也不需要花费大量的时间来运行。它从头到尾都是一场比赛，扮演着双方球员的角色。这很像一个人和自己下棋，迈出一步，然后转身。在那些比赛中谁赢是一个有趣的问题。

这段代码有两个目的。一方面，我们希望看到代码运行并执行整个游戏。如果比赛结束了，那就没事了。这是一个非常弱的断言，而真正的集成测试执行很多断言（尽管一个测试只测试一个断言）。我们将集中在另一个目标，提供一些乐趣和可视化的游戏控制台上的文本格式，使读者不会感到无聊。

为此，我们将创建一个工具类，该类打印出一种颜色，并动态地将字母分配给`Color`实例。

警告：这个类中有几个限制，我们必须在查看代码后讨论。我想说这段代码在这里只是为了演示*不要做*什么，为下一章建立一些推理，以及为什么我们需要重构我们在这一章中创建的代码。仔细阅读！

这是`PrettyPrintRow`类：

```java
package packt.java189fundamentals.example.mastermind;

import java.util.HashMap;
import java.util.Map;

public class PrettyPrintRow {

    private static final Map<Color, Character>
            letterMapping = new HashMap<>();
    private static final String letters = "RGBYWb";
    private static int counter = 0;

    private static char colorToChar(Color color) {
        if (!letterMapping.containsKey(color)) {
            letterMapping.put(color, letters.charAt(counter));
            counter++;

        }
        return letterMapping.get(color);
    }
```

这是这个类的核心。当一种颜色要打印时，它会得到一个指定的字母，除非它已经有了一个。由于在 JVM 中运行的每个游戏中包含分配的`Map`将使用相同的映射，因此新的`Game`被启动。它分配新的`Color`对象，很快就会用完我们在`String`常量中分配的六个字符。

如果`Game`实例并行运行，那么我们的麻烦就更大了。这个类根本不是线程安全的。如果两个线程同时调用同一个`Color`实例的`colorToChar`方法（这不太可能，因为每个`Game`都使用自己的颜色，但请注意，编程中的**不太可能**非常像墓碑上有名的最后一句话），那么两个线程可能都会看到此时没有为颜色分配字母同时，两者都会指定字母（相同的字母或两个不同的字母，取决于运气）并增加计数器一到两次。至少，我们可以说，执行是不确定的。

您可能还记得，我说过违反哈希约定是继多线程问题之后第二难发现的 bug。这种不确定的代码正是多线程问题。找到最难的虫子是没有奖赏的。当应用不运行，并且一个 bug 影响生产系统达数小时或数天时，没有任何业务人员会感到高兴，在您发现 bug 之后，他们也不会感到惊讶。这可能是一个智力上的挑战，许多程序员都经历过类似的调试，但真正的价值并不是一开始就产生 bug。

总之，这个代码只能在一个 JVM 中（在同一个类加载器下）由一个线程使用一次。对于这一章来说，它是好的，虽然是一个难闻和可耻的代码。稍后，这将是下一章的一个很好的例子，在下一章中，我们将看到如何重构应用，以便它不需要这样的黑客来打印颜色。

根据 [Martin Fowler](http://martinfowler.com/bliki/CodeSmell.html) 的说法，代码气味是 Kent Back 创造的一个术语。这意味着有些代码看起来不好，也不明显不好，但是有些构造让开发人员觉得可能不好。正如在网页上定义的那样，*代码气味是一种表面指示，通常对应于系统中更深层的问题*。这个术语被广泛接受，并在过去的 10 年中用于软件开发。

其余代码简单明了：

```java
    public static String pprint(Row row) {
        var string = "";
        final var pRow = new PrintableRow(row);
        for (int i = 0; i < pRow.nrOfColumns(); i++) {
            string += colorToChar(pRow.position(i));
        }
        string += " ";
        string += pRow.matchedPositions();
        string += "/";
        string += pRow.matchedColors();
        return string;
    }
}
```

集成测试，或者更确切地说，演示代码（因为它不包含任何断言，除了它运行之外，它无一例外地运行），定义了六种颜色和四列。这是原来游戏的大小。它创建颜色管理器，然后创建一个表和一个秘密。这个秘密可能只是从可用的六种颜色中随机选择颜色（在 Packt 代码库中的`UniqueGuesserTest`单元测试中有 360 种不同的可能性进行测试）。我们知道`Guesser`实现从颜色集的一端开始，系统地创建新的猜测，我们希望设置一个秘密，它将持续猜测。这不是因为我们是邪恶的，而是因为我们希望看到我们的代码确实有效。

代码的目录结构与我们在 Maven 构建工具中使用的目录结构非常相似，如在 Windows 机器上创建的以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/1ad2d114-82f2-4124-aa93-b3ff3944c806.png)

源代码位于`src`目录下，`main`和`test`源代码文件分为两个子目录结构。编译后的文件在`build`目录下使用 Gradle 时生成。

集成测试类的代码如下：

```java
package packt.java189fundamentals.example.mastermind.integration;

import org.junit.Assert;
import org.junit.Test;
import packt.java189fundamentals.example.mastermind.*;

public class IntegrationTest {

    final int nrColors = 6;
    final int nrColumns = 4;
    final ColorManager manager = new ColorManager(nrColors);

    private Color[] createSecret() {
        Color[] secret = new Color[nrColumns];
        int count = 0;
        Color color = manager.firstColor();
        while (count < nrColors - nrColumns) {
            color = manager.nextColor(color);
            count++;
        }
        for (int i = 0; i < nrColumns; i++) {
            secret[i] = color;
            color = manager.nextColor(color);
        }
        return secret;
    }

    @Test
    public void testSimpleGame() {
        Table table = new Table(nrColumns, manager);
        Color[] secret = createSecret();
        System.out.println(PrettyPrintRow.pprint(new Row(secret)));
        System.out.println();
        Game game = new Game(table, secret);

        Guesser guesser = new UniqueGuesser(table);
        while (!game.isFinished()) {
            Row guess = guesser.guess();
            if (guess == Row.none) {
                Assert.fail();
            }
            game.addNewGuess(guess);
            System.out.println(PrettyPrintRow.pprint(guess));
        }
    }
}
```

运行测试的最简单方法是从 IDE 内部启动测试。IDE 根据生成文件导入项目时，无论是 Maven`pom.xml`还是 Gradle`build.gradle`，IDE 通常提供一个运行按钮或菜单来启动代码。运行游戏将打印出我们在本章中努力工作的以下代码：

```java
RGBY 0/0

GRWb 0/2
YBbW 0/2
BYGR 0/4
RGYB 2/2
RGBY 4/0
```

# 总结

在这一章中，我们编写了一个桌游策划。我们不仅编写了游戏的模型，还创建了一个可以猜测的算法。我们重温了一些面向对象的原则，并讨论了为什么模型是这样创建的。我们创建了游戏模型，同时学习了 Java 集合、集成测试和 JavaDoc。在下一章中，我们将以这些知识为基础，增强游戏在多个处理器上运行的能力。