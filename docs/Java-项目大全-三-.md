# Java 项目大全（三）

> 原文：[JAVA PROJECTS](https://libgen.rs/book/index.php?md5=C751311C3F308045737DA4CD071BA359)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 五、扩展游戏-跑得并行，跑得更快

在本章中，我们将扩展主谋游戏。就像现在这样，它能猜出隐藏的秘密，也能藏起钉子。测试代码甚至可以同时做这两件事。它可以与自己作对，只留给我们编程的乐趣。它不能做的是利用我们今天笔记本和服务器上的所有处理器。代码同步运行，只使用一个处理器内核。

我们将修改扩展猜测算法的代码，以便将猜测分割成子任务并并行执行代码。这样，我们将熟悉 Java 并发编程。这将是一个巨大的话题，许多微妙的曲折潜伏在阴影中。我们将深入了解这些最重要的细节，并为您需要并行程序时的进一步学习奠定坚实的基础。

由于比赛的结果和以前一样，只是速度更快，我们必须评估什么是更快。为此，我们将利用 Java9 中引入的一个新特性——微基准测试工具。

在本章中，我们将介绍以下主题：

*   进程、线程和纤程的含义
*   Java 中的多线程技术
*   多线程编程的问题及避免方法
*   锁定、同步和阻塞队列
*   微基准

# 如何让 Mastermind 并行

旧的算法是遍历所有的变化，并试图找到与表的当前状态相匹配的猜测。假设当前检查的猜测是秘密，我们会得到与实际答案相同的答案吗？如果是的话，那么当前的猜测就是秘密，它和其他猜测一样好。

更复杂的方法可以实现 [min-max 算法](https://en.wikipedia.org/wiki/Minimax)。这个算法不只是简单地得到下一个可能的猜测，而是查看所有可能的猜测，并选择一个最缩短游戏结果的猜测。如果有一个猜测在最坏的情况下可以再进行三次猜测，而另一个猜测的数字只有两次，那么 minmax 将选择后者。对于那些感兴趣的读者来说，实现 minmax 算法是一个很好的练习。在六种颜色和四列的情况下，最小-最大算法在不超过五个步骤的情况下解决游戏。我们实现的简单算法也分五步求解游戏。然而，我们没有朝这个方向走。

相反，我们希望有一个版本的游戏，利用一个以上的处理器。如何将算法转换为并行算法？这个问题没有简单的答案。当你有一个算法，你可以分析计算和部分算法，你可以尝试找到依赖关系。如果有一个计算，`B`需要数据，这是另一个计算，`a`的结果，那么很明显，`a`只能在`B`准备就绪时执行。如果算法的某些部分不依赖于其他部分的结果，那么它们可以并行执行。

例如，快速排序有两个主要任务，分别对这两个部分进行分区和排序。很明显，在我们开始对两个分区的部分进行排序之前，分区必须完成。但是，这两部分的排序任务并不相互依赖，它们可以独立完成。你可以给他们两个不同的处理器。一个会很高兴地将包含较小元素的部分分类，而另一个会携带较大的元素。

如果我们回想一下非递归快速排序实现，您可以看到我们将排序任务安排到一个栈中，然后通过在一个`while`循环中从栈中获取元素来执行排序：

```java
public class NonRecursiveQuickSort<E> {
// ... same fields and constructor as in Qsort are deleted from print ...

    private static class StackElement {
        final int begin;
        final int fin;

        public StackElement(int begin, int fin) {
            this.begin = begin;
            this.fin = fin;
        }
    }

    public void qsort(Sortable<E> sortable, int start, int end) {
        final var stack = new LinkedList<StackElement>();
        final var partitioner = new Partitioner<E>(comparator, swapper);
        stack.add(new StackElement(start, end));
        var i = 1;
        while (!stack.isEmpty()) {
            var it = stack.remove(0);
            if (it.begin < it.fin) {
                final E pivot = sortable.get(it.begin);
                var cutIndex = partitioner.partition(sortable, it.begin, it.fin, pivot);
                if( cutIndex == it.begin ){
                    cutIndex++;
                }
                stack.add(new StackElement(it.begin, cutIndex - 1));
                stack.add(new StackElement(cutIndex, it.fin));
            }
        }
    }
}
```

我们可以将任务传递给异步线程来执行排序，然后返回到下一个等待的任务，而不是在循环的核心执行排序。我们只是不知道怎么做。但是。这就是我们在这一章的原因。

处理器、线程和进程是复杂而抽象的东西，它们很难想象。不同的程序员有不同的技术来想象并行处理和算法。我可以告诉你我是怎么做的。这不能保证对你有用。其他人的头脑中可能有不同的技巧。事实上，我刚刚意识到，在我写这篇文章的时候，我从来没有告诉过任何人。这可能看起来很幼稚，但不管怎样，还是来了。

当我想象算法时，我想象人。一个处理器就是一个人。这有助于我克服一个奇怪的事实，即一个处理器可以在一秒钟内执行数十亿次计算。我真的想象一个穿棕色西装的官僚在做计算。当我为一个并行算法创建一个代码时，我想象他们中的许多人在办公桌后面工作。他们一个人工作，不说话。重要的是他们不要互相交谈。他们非常正式。当需要交换信息时，他们会拿着一张纸站起来，上面写着什么，然后把它带给对方。有时，他们的工作需要一张纸。然后，他们站起来，走到放报纸的地方，拿着它，把它带回办公桌，继续工作。准备好后，他们回去把报纸拿回来。如果他们需要的时候报纸不在那里，他们就会排队等候，直到有人把报纸带来。

这对主谋游戏有什么帮助？

我想象一个老板对猜测负责。办公室的墙上有一张桌子，上面有以前的猜测和每行的结果。老板懒得提出新的猜测，所以他把这个任务交给下属。当下属提出猜测时，老板会检查猜测是否有效。他不信任下属，如果猜得好，他就把它当成官方的猜测，和结果一起放在桌子上。

下属把猜测写在小便笺上，然后放在老板桌上的盒子里。老板时不时地看盒子，如果有纸条，老板就收了。如果箱子满了，下属想把一张纸放在那里，他就会停下来，等老板至少记下一张纸条，这样箱子里就有地方放新纸条了。如果下属们排队把猜词放进盒子里，他们都会等着轮到他们。

下属之间要协调，否则，他们也会有同样的猜测。他们每个人都应该有一段时间的猜测。例如，如果我们用数字表示颜色，第一个应该检查从 1234 到 2134 的猜测，第二个应该检查从 2134 到 3124 的猜测，依此类推。

这个结构能用吗？常识告诉我们会的。然而，在这种情况下，官僚是隐喻，隐喻并不确切。官僚主义者是人，即使他们看起来不是人，也远比线程或处理器更像人。他们有时行为异常，做正常人不常做的事情。然而，如果这个比喻有助于我们想象并行算法是如何工作的，我们仍然可以使用它。

我们可以想象，老板去度假，不碰桌上堆积如山的一堆纸。我们可以想象，有些工人比其他工人生产的结果快得多。因为这只是想象，所以加速可以是 1000 倍（想想一个延时视频）。想象这些情况可以帮助我们发现很少发生的特殊行为，但这可能会导致问题。当线程并行工作时，大量细微的差异可能会极大地影响一般行为。

在早期版本中，当我编写并行主谋算法时，官僚们开始工作，在老板把它们中的任何一个都摆在桌子上之前，他们就开始用猜测填满老板的盒子。由于桌上没有猜测，官僚们只是发现了他们的间隔中可能出现的所有可能的变化，这可能构成了一个很好的猜测。老板在并行助手的帮助下什么也没有得到；老板必须从所有可能的猜测中选择正确的，而猜测者只是闲着。

还有一次，当老板在猜测的时候，官僚们正在对照桌子核对猜测。按照我们的比喻，一些官僚吓了一跳，说如果有人在换桌子，就不可能对照桌子来核对猜测。更准确地说，在官僚线程中执行代码时，当表的`List`被修改时抛出`ConcurrentModificationException`。

另一次，我试图避免官僚们过于迅速的工作，我限制了他们可以把包含猜测的文件放在盒子里的大小。当老板终于发现了这个秘密，游戏结束后，老板告诉官僚们可以回家了。老板是这样做的，他写了一份小报告，上面写着指示，你可以回家把它放在官僚们的桌子上。官僚们做了什么？他们一直等着箱子有地方放报纸，因为在那儿等的时候，他们没有在看桌子上的零钱！（直到进程被终止。这在 MacOS 和 Linux 上相当于从 Windows 上的任务管理器结束进程。）

这样的编码错误时有发生，为了尽可能避免，我们至少要做两件事。首先，我们必须了解 Java 多线程是如何工作的，其次，要有一个尽可能干净的代码。第二，我们将进一步清理代码，然后我们将研究如何在 Java 中实现前面描述的并行算法，在 JVM 上运行，而不是使用官僚程序。

# 重构

当我们完成上一章的时候，我们用一种完美的面向对象的方式设计和编码了 Mastermind 游戏的类，这种方式没有破坏任何一个 *OO* 原则。是吗？荒谬的。除了一些微不足道的例子外，没有任何代码是不能让它看起来更好或更好的。通常，当我们开发代码并完成编码时，它看起来很棒。它工作了，测试都运行了，文档也准备好了。从专业的角度来看，它确实是完美的。好吧，够了。我们尚未测试的最大问题是可维护性。修改代码的成本是多少？

这不是一个容易的问题，特别是因为它不是一个确定的问题。改成什么？我们要做什么修改？当我们首先创建代码时，我们不知道这一点。如果修改是为了修复一个 bug，那么很明显我们事先并不知道这一点。如果我们知道的话，我们一开始就不会引入这个 bug。如果这是一个新特性，那么就有可能预见到该功能。然而，通常情况并非如此。当开发人员试图预测未来，以及程序将来需要什么特性时，通常都会失败。了解业务是客户的任务。在专业软件开发的情况下，需要的特性是由业务驱动的。毕竟，这就是专业的含义。

尽管我们不知道代码后面需要修改什么，但是有些东西可能会给有经验的软件开发人员一些提示。通常情况下，*OO* 代码比*即兴*代码更容易维护，并且有一种可以检测的代码香气。例如，请查看以下代码行：

```java
while (guesser.guess() != Row.none) {
. . .
while (guesser.nextGuess() != Guesser.none) {
. . .
public void addNewGuess(Row row) {
. . .
Color[] guess = super.nextGuess();
```

我们可能感觉到某种奇怪的气味。（每一行都在我们在第 4 章、“策划者-创建游戏”中完成的应用代码中。）`guess()`方法的返回值与`Row.none`进行比较，后者是一个`Row`。在下一个示例行中，我们将`nextGuess()`方法的返回值与`Guesser.none`进行比较，后者应该是猜测，而不是`Guesser`。当我们在下一个示例行中添加新的猜测时，我们实际上添加了一个`Row`。最后，我们可以意识到方法`nextGuess()`返回的猜测不是一个有自己声明类的*对象*。猜测只是`Colors`的一个数组。这些东西乱七八糟。我们如何提高代码的质量？

我们应该引入另一层抽象来创建一个`Guess`类吗？它会使代码更易于维护吗？还是只会让代码更复杂？通常情况下，代码行越少，出现错误的可能性就越小。然而，有时缺乏抽象会使代码变得复杂和纠结。在这种情况下是什么情况？一般的决定方法是什么？

你的经验越多，你就越容易通过看代码和敏锐地知道你想要做什么修改来判断。很多时候，您不会费心让代码更抽象，而很多时候，您会毫不犹豫地创建新的类。当有疑问时，创建新类并查看结果。重要的是不要破坏已经存在的功能。只有在有足够的单元测试的情况下才能这样做。

当您想引入一些新功能或修复一个 bug，但代码不合适时，您必须首先修改它。当您修改代码以使功能不改变时，这个过程被命名为**重构**。在有限的时间内更改一小部分代码，然后构建它。如果它编译并运行所有单元测试，那么您可以继续。提示是要经常运行构建。这就像在现有道路附近修建一条新道路。每隔几英里，你就会遇到一条旧路线。如果做不到这一点，你最终会在沙漠中的某个地方走上完全错误的方向，你所能做的就是回到你要重构的旧代码的起点。努力白费了。

迫使我们频繁运行构建的不仅是安全性，还有时间限制。重构并不能直接带来收益。该计划的功能直接与收入挂钩。没有人会为无限的重构工作付钱给我们。重构必须在某个时候停止，而且通常不再是什么都不需要重构的时候。代码永远不会是完美的，但是当它足够好的时候你可以停下来。而且，很多时候，程序员对代码的质量并不满意，当他们被一些外部因素（通常称为项目经理）强迫停止时，应该编译代码并运行测试，以便在实际的代码基础上执行新特性和错误修复。

重构是一个巨大的主题，在这样的活动中可以遵循许多技术。[它是如此的复杂以至于有一整本马丁·福勒的书](http://martinfowler.com/books/refactoring.html)，很快就会有第二版。

在我们的例子中，我们希望对代码进行的修改是实现一个并行算法。首先要修改的是`ColorManager`。当我们想在终端上打印猜测和行时，我们使用了一些糟糕的技巧来实现它。为什么没有可以打印的颜色实现？我们可以有一个扩展原始`Color`类的类，并有一个返回表示该颜色的内容的方法。你有那种方法的候选名称吗？这是`toString()`方法。它在`Object`类中实现，任何类都可以自由覆盖它。当您将一个对象连接到一个字符串时，自动类型转换将调用此方法将该对象转换为`String`。顺便说一下，使用`""+object`而不是`object.toString()`来避免`null`指针异常是一个老把戏。不用说，我们不使用诡计。

当调试器想要显示某个对象的值时，`toString()`方法也会被 IDE 调用，因此如果没有其他原因，那么为了便于开发，通常建议实现`toString()`。如果我们有一个实现了`toString()`的`Color`类，那么`PrettyPrintRow`类就变得相当简单，欺骗性更小：

```java
public class PrettyPrintRow {

    public static String pprint(Row row) {
        var string = "";
        var pRow = new PrintableRow(row);
        for (int i = 0; i < pRow.nrOfColumns(); i++) {
            string += pRow.pos(i);
        }
        string += " ";
        string += pRow.full();
        string += "/";
        string += pRow.partial();
        return string;
    }
}
```

我们从打印类中删除了这个问题，但是您可能会认为问题仍然存在，您是对的。通常，当类设计中出现问题时，解决问题的方法是将问题从一个类转移到另一个类。如果它仍然是一个问题，那么你可能会越来越分裂的设计，在最后阶段，你会意识到你所拥有的是一个问题，而不是一个问题。

实现一个`LetteredColor`类也很简单：

```java
package packt.java189fundamentals.mastermind.lettered;

import packt.java189fundamentals.mastermind.Color;

public class LetteredColor extends Color {

    private final String letter;
    public LetteredColor(String letter){
        this.letter = letter;
    }

    @Override
    public String toString(){
        return letter;
    }
}
```

问题再次被推进。但实际上，这不是问题。这是一个*OO*设计。印刷不负责为颜色指定一个`String`来表示颜色。而颜色实现本身也不对此负责。必须在生成颜色的地方执行赋值，然后必须将`String`传递给`LetteredColor`类的构造器。`color`实例是在`ColorManager`中创建的，所以必须在`ColorManager`类中实现。还是不？`ColorManager`做什么？它创造了颜色和。。。

当您对列出功能的类进行解释或描述时，您可能会立即看到违反了**单一责任原则**。`ColorManager`应该管理颜色。管理就是提供一种方法，使颜色按一定的顺序排列，当我们知道一种颜色时，得到第一种和第二种颜色。我们应该在一个单独的类中实现另一个职责，即创建颜色。

只有创建另一个类实例的功能的类称为`factory`。这与使用`new`运算符几乎相同，但与`new`不同的是，工厂可以以更灵活的方式使用。我们马上就会看到。`ColorFactory`接口包含一个方法，如下所示：

```java
package packt.java189fundamentals.mastermind;

public interface ColorFactory {
    Color newColor();
}
```

只定义一个方法的接口称为函数式接口，因为它们的实现可以作为 Lambda 表达式提供，也可以作为方法引用提供，方法引用位于您要使用的对象的位置，对象是实现函数式接口的类的实例。例如，`SimpleColorFactory`实现创建以下`Color`对象：

```java
package packt.java189fundamentals.mastermind;

public class SimpleColorFactory implements ColorFactory {
    @Override
    public Color newColor() {
        return new Color();
    }
}
```

在代码中使用`new SimpleColorFactory()`的地方，我们也可以编写`Color::new`或`() -> new Color()`。

这很像我们如何创建一个接口，然后创建一个实现，而不是仅仅在`ColorManager`中的代码中编写`new Color()`。`LetteredColorFactory`更有趣一点：

```java
package packt.java189fundamentals.mastermind.lettered;

import packt.java189fundamentals.mastermind.Color;
import packt.java189fundamentals.mastermind.ColorFactory;

public class LetteredColorFactory implements ColorFactory {

    private static final String letters = "0123456789ABCDEFGHIJKLMNOPQRSTVWXYZabcdefghijklmnopqrstvwxzy";
    private int counter = 0;

    @Override
    public Color newColor() {
        Color color = new LetteredColor(letters.substring(counter, counter + 1));
        counter++;
        return color;
    }
}
```

现在，在这里，我们有一个功能，当`String`对象被创建时，将它们分配给`Color`对象。非常重要的是，跟踪已经创建的颜色的`counter`变量不是`static`。上一章中的类似变量是`static`，这意味着每当较新的`ColorManager`对象创建太多颜色时，它可能会用完字符。当每个测试创建`ColorManager`对象和新的`Color`实例时，它确实发生在单元测试执行期间。印刷代码试图将新字母分配给新颜色。这些测试运行在同一个 JVM 中的同一个类加载器下，不幸的`static`变量不知道什么时候可以从零开始计算新的测试。

另一方面，这种工厂解决方案的缺点是，某个地方的某个人必须实例化工厂，而它不是`ColorManager`。`ColorManager`已经有责任了，不是要创建一个色彩工厂。`ColorManager`必须在其构造器中获得`ColorFactory`：

```java
package packt.java189fundamentals.mastermind;

import java.util.HashMap;
import java.util.Map;

public class ColorManager {
    protected final int nrColors;
    protected final Map<Color, Color> successor = new HashMap<>();
    private final ColorFactory factory;
    private Color first;

    public ColorManager(int nrColors, ColorFactory factory) {
        this.nrColors = nrColors;
        this.factory = factory;
        createOrdering();
    }

    private Color[] createColors() {
        var colors = new Color[nrColors];
        for (int i = 0; i < colors.length; i++) {
            colors[i] = factory.newColor();
        }
        return colors;
    }

    private void createOrdering() {
        var colors = createColors();
        first = colors[0];
        for (int i = 0; i < nrColors - 1; i++) {
            successor.put(colors[i], colors[i + 1]);
        }
    }

    public Color firstColor() {
        return first;
    }

    public boolean thereIsNextColor(Color color) {
        return successor.containsKey(color);
    }

    public Color nextColor(Color color) {
        return successor.get(color);
    }

    public int getNrColors() {
        return nrColors;
    }
}
```

您可能还注意到，我忍不住将`createColors`方法重构为两种方法，以遵循单一责任原则。

现在，创建`ColorManager`的代码必须创建一个工厂并将其传递给构造器。例如，单元测试的`ColorManagerTest`类将包含以下方法：

```java
@Test
public void thereIsAFirstColor() {
    var manager = new ColorManager(NR_COLORS, Color::new);
    Assert.assertNotNull(manager.firstColor());
}
```

这是实现由函数式接口定义的工厂的最简单方法。只需命名类并引用`new`操作符，就好像它是通过创建方法引用的方法一样。

接下来我们要重构的是`Guess`类，实际上，到目前为止我们还没有这个类。`Guess`类包含猜测的标记，可以计算完全匹配（颜色和位置）和部分匹配（颜色存在但位置错误）的数量。它还可以计算出这个猜测之后的下一个`Guess`。到目前为止，这个功能是在`Guesser`类中实现的，但是这并不是我们在检查表上已经做出的猜测时如何选择猜测的功能。如果我们遵循为颜色设置的模式，我们可以在一个名为`GuessManager`的单独类中实现这个功能，但是，到目前为止，还不需要它。同样，所需的抽象层次在很大程度上是一个品味的问题；这个东西不是黑的也不是白的。

需要注意的是，`Guess`对象只能一次生成。如果放在桌上，球员就不能换。如果我们有一个`Guess`还没有出现在桌子上，它仍然只是一个`Guess`，通过钉子的颜色和顺序来识别。`Guess`对象在创建后不会更改。这样的对象很容易在多线程程序中使用，被称为不可变对象。因为这是一个相对较长的类，所以我们将在本书的各个部分中研究代码：

```java
package packt.java189fundamentals.mastermind;

import java.util.Arrays;
import java.util.HashSet;

public class Guess {
    public final static Guess none = new Guess(new Color[0]);
    private final Color[] colors;
    private boolean uniquenessWasNotCalculated = true;
    private boolean unique;

    public Guess(Color[] colors) {
        this.colors = Arrays.copyOf(colors, colors.length);
    }
```

构造器正在创建作为参数传递的颜色数组的副本。因为`Guess`是不可变的，所以这是非常重要的。如果我们只保留原始数组，那么`Guess`类之外的任何代码都可能改变数组的元素，实质上改变了不应该改变的`Guess`的内容。

代码的下一部分是两个简单的获取器：

```java
public Color getColor(int i) {
    return colors[i];
}

public int nrOfColumns() {
    return colors.length;
}
```

下一种方法是计算`nextGuess`：

```java
public Guess nextGuess(ColorManager manager) {
    final var colors = Arrays.copyOf(this.colors, nrOfColumns());

    int i = 0;
    var guessFound = false;
    while (i < colors.length && !guessFound) {
        if (manager.thereIsNextColor(getColor(i))) {
            colors[i] = manager.nextColor(colors[i]);
            guessFound = true;
        } else {
            colors[i] = manager.firstColor();
            i++;
        }
    }
    if (guessFound) {
        return new Guess(colors);
    } else {
        return Guess.none;
    }
}
```

在这种方法中，我们从实际对象中包含的颜色数组开始计算`nextGuess`。我们需要一个工作数组，它被修改了，所以我们将复制原始数组。最后一个新对象可以使用我们在计算过程中使用的数组。为了实现这一点，我们需要一个独立的构造器，它不会创建`Color`数组的副本。这是一个可能的额外代码。只有当我们看到这是代码中的瓶颈并且对实际性能不满意时，我们才应该考虑创建它。在这个应用中，它也不是瓶颈，我们对性能感到满意，您将在稍后讨论基准测试时看到这一点。

下一种方法只是检查通过的`Guess`是否与实际的颜色数相同：

```java
private void assertCompatibility(Guess guess) {
    if (nrOfColumns() != guess.nrOfColumns()) {
        throw new IllegalArgumentException("Can not compare different length guesses");
    }
}
```

这只是计算匹配的下两种方法使用的安全检查：

```java
public int nrOfPartialMatches(Guess guess) {
    assertCompatibility(guess);
    int count = 0;
    for (int i = 0; i < nrOfColumns(); i++) {
        for (int j = 0; j < nrOfColumns(); j++) {
            if (i != j &&
                    guess.getColor(i) == this.getColor(j)) {
                count++;
            }
        }
    }
    return count;
}

public int nrOfFullMatches(Guess guess) {
    assertCompatibility(guess);
    int count = 0;
    for (int i = 0; i < nrOfColumns(); i++) {
        if (guess.getColor(i) == this.getColor(i)) {
            count++;
        }
    }
    return count;
}
```

下一个`isUnique()`方法检查`Guess`中是否有不止一次的颜色。因为`Guess`是不可变的，所以`Guess`在某一时刻是唯一的，而在另一时刻不是唯一的。无论何时对特定对象调用此方法，都应返回相同的结果。因此，可以缓存结果。此方法执行此操作，将返回值保存到实例变量。

你可能会说这是过早的优化。是的，是的。我决定这么做有一个原因。它演示了一个本地保存的结果，在此基础上，您可以尝试修改`nextGuess()`方法来执行相同的操作。`isUnique()`方法如下：

```java
public boolean isUnique() {
    if (uniquenessWasNotCalculated) {
        final var alreadyPresent = new HashSet<Color>();
        unique = true;
        for (final var color : colors) {
            if (alreadyPresent.contains(color)) {
                unique = false;
                break;
            }
            alreadyPresent.add(color);
        }
        uniquenessWasNotCalculated = false;
    }
    return unique;
}
```

对于相同的参数返回相同结果的方法称为幂等。如果该方法被多次调用并且计算占用大量资源，那么缓存该方法的返回值可能非常重要。当方法有参数时，缓存结果并不简单。`object`方法必须记住已计算的所有参数的结果，并且该存储必须有效。如果查找存储的结果比计算结果需要更多的资源，那么使用缓存不仅会占用更多的内存，而且会降低程序的速度。如果在对象的生存期内为多个参数调用了该方法，那么存储内存可能会变得太大。不再需要的元素必须清除。但是，我们无法知道缓存的哪些元素以后不需要。我们不是算命的，所以我们得猜。（就像算命师一样）

如您所见，缓存可能会变得复杂。要专业地做到这一点，最好使用一些现成的缓存实现。我们在这里使用的缓存只是冰山一角。或者，它甚至只是在它身上瞥见的阳光。

其余的类都相当标准，我们已经详细讨论了一些内容——对您的知识的一个很好的检查就是理解`equals()`、`hashCode()`和`toString()`方法是如何以这种方式实现的。我实现了`toString()`方法来帮助我进行调试，但它也被用于接下来的示例输出中。方法如下：

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || !(o instanceof Guess)) return false;
    var guess = (Guess) o;
    return Arrays.equals(colors, guess.colors);
}

@Override
public int hashCode() {
    return Arrays.hashCode(colors);
}

@Override
public String toString() {
    if (this == none) {
        return "none";
    } else {
        String s = "";
        for (int i = colors.length - 1; i >= 0; i--) {
            s += colors[i];
        }
        return s;
    }
}
```

主要地，这是我在开发并行算法时所需要的所有修改。在这些更改之后，代码看起来更好了，并且很好地描述了功能，因此我们可以关注本章的主要主题如何在 Java 中并行执行代码。

Java 中代码的并行执行是在线程中完成的。您可能知道 Java 运行时中有一个`Thread`对象，但如果不了解计算机中的线程是什么，就没有意义了。在下面的小节中，我们将学习这些线程是什么，如何启动一个新线程，如何同步线程之间的数据交换，最后，将所有这些放在一起并实现 Mastermind 游戏并行猜测算法。

# 进程

打开计算机电源后，启动的程序是操作系统（OS）。操作系统控制机器硬件和可以在机器上运行的程序。当你启动一个程序时，操作系统会创建一个新的进程。这意味着操作系统在一个表（数组）中分配一个新的条目，在这个表（数组）中它管理进程，并填充它知道的和需要知道的有关进程的参数。例如，它注册允许进程使用的内存段、进程的 ID、启动它的用户以及启动它的其他进程。你不能凭空开始一个进程。当你双击一个 EXE 文件时，你实际上告诉文件管理器（一个作为进程运行的程序）把 EXE 文件作为一个单独的进程启动。浏览器通过一个 API 调用系统，并请求操作系统这样做。操作系统将把资源管理器进程注册为新进程的父进程。此时操作系统实际上并不启动进程，而是创建它随后启动进程所需的所有数据，当有一些空闲的 CPU 资源时，进程启动，然后很快暂停，重新启动，然后暂停，依此类推。您不会注意到它，因为操作系统会一次又一次地启动它，并且总是反复暂停进程。它需要这样做才能为所有进程提供运行的可能性。这样，我们可以体验到所有进程同时运行。实际上，进程不会在单个处理器上同时运行，但它们经常会有时间段运行，因此我们感觉它们一直在运行。

如果计算机中有多个 CPU，那么进程实际上可以与有 CPU 的多个进程同时运行。随着集成的日益高级，台式计算机拥有包含多个核心的 CPU，它们几乎与单独的 CPU 一样运行。在我的机器上，我有四个内核，每个内核都能同时执行两个线程；所以，我的 MacOS 几乎就像一台 8 CPU 机器。当我开始工作时，一台 8 CPU 的电脑是一台价值百万美元的机器。

进程有不同的记忆。允许它们使用内存的一部分，如果进程试图使用不属于它的部分，处理器将停止这样做。操作系统将终止进程。

试想一下，最初的 Unix 开发人员将停止进程的程序命名为`kill`，他们一定很沮丧。停止一个进程叫做终止它。就像中世纪，他们砍掉了一个重罪犯的手。你碰错了记忆的一部分，就死定了。我不想成为一个过程。

操作系统的内存处理非常复杂，除了将进程彼此分离之外。当内存不足时，操作系统会将内存的一部分写入磁盘，释放内存，并在需要时重新加载该部分。这是一个非常复杂、低层次实现和高度优化的算法，由特殊的硬件操作支持。这是操作系统的责任。

# 线程

当我说操作系统在时隙中执行进程时，我简化了这种情况的实际发生方式。每个进程都有一个或多个线程，线程被执行。线程是由*外部*调度器管理的最小执行。较旧的操作系统没有线程的概念，正在执行进程。事实上，第一个线程实现只是共享内存的进程的副本。

如果你读一些旧的东西，你可能会听到术语*轻量级进程*。意思是一根线。

重要的是线程没有自己的内存。他们利用记忆的过程。换句话说，在同一进程中运行的线程对同一内存段具有不可区分的访问权限。

实现并行算法的可能性，该算法在机器中使用多个核非常强大，但同时，它可能会导致错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/c051a9af-b577-4087-8b0e-e3138e17a710.png)

假设两个线程递增相同的长变量。增量首先计算低 32 位的增量值，如果有溢出位，则计算高 32 位的增量值。这是操作系统可能中断的两个或多个步骤。一个线程可能会增加低 32 位，它会记住对高 32 位有一些操作，开始计算，但在中断之前没有时间存储结果。然后，另一个线程增加低 32 位，高 32 位，然后第一个线程只保存它计算的高 32 位。结果变得混乱。在旧的 32 位 Java 实现上，演示这种效果非常容易。在 64 位 Java 实现中，所有的 64 位都加载到寄存器中，并在一个步骤中保存回内存，因此演示这个多线程不是那么容易，但并不意味着没有多线程。

当一个线程暂停而另一个线程启动时，操作系统必须执行上下文切换。这意味着，除其他外，必须保存 CPU 寄存器，然后将其设置为其他线程应有的值。上下文切换总是保存线程的状态，并加载要启动的线程先前保存的状态。这是一个 CPU 寄存器级别。这种上下文切换非常耗时；因此，上下文切换越多，用于线程管理的 CPU 资源就越多，而不是让它们运行。另一方面，如果没有足够的开关，一些线程可能没有足够的时间执行，程序就会挂起。

# 纤程

Java 版本 11 没有纤程，但是有一些库支持有限的纤程处理，[还有一个 JDK 项目](http://openjdk.java.net/projects/loom/)，其目标是拥有支持纤程的更高版本的 JVM。因此，我们迟早会有 Java 中的纤程，因此，理解和了解它们是什么很重要。

纤程是比线更细的单位。在线程中执行的程序代码可能会决定放弃执行，并告诉纤程管理器只执行其他纤程。有什么意义？为什么它比使用另一个线程更好？原因是这样，纤程可以避免部分上下文切换。上下文切换不能完全避免，因为开始执行它的代码的不同部分可能以完全不同的方式使用 CPU 寄存器。因为是同一个线程，所以上下文切换不是操作系统的任务，而是应用的任务。

操作系统不知道是否使用了寄存器的值。寄存器中有位，只有看到处理器的状态，没有人能分辨出这些位是与当前代码执行相关，还是恰好以这种方式存在。编译器生成的程序确实知道哪些寄存器很重要，哪些寄存器可以忽略。这些信息在代码中的位置不同，但当需要交换机时，纤程会将需要在该点进行切换的信息传递给进行切换的代码。

编译器计算这些信息，但 Java 在当前版本中不支持纤程。在 Java 中实现纤程的工具在编译阶段之后会分析和修改类的字节码。

Golang 的 GoRoutine 是纤程类型，这就是为什么您可以轻松地在 Go 中启动数千个，甚至数百万个 GoRoutine 的原因，但是建议您将 Java 中的线程数限制为较低的数目。他们不是一回事。

尽管术语*轻量线程*正在慢慢消失，被越来越少的人使用，但纤程仍然经常被称为轻量线。

# `Java.lang.Thread`线程

Java 中的一切（几乎）都是一个对象。如果我们想启动一个新线程，我们将需要一个对象，因此，一个代表线程的类。这个类是`java.lang.Thread`，它内置在 JDK 中。当您启动 Java 代码时，JVM 会自动创建一些`Thread`对象，并使用它们来运行它所需要的不同任务。如果您启动了 **VisualVM**，您可以选择任何 JVM 进程的线程选项卡，并查看 JVM 中的实际线程。例如，我启动的 VisualVM 有 29 个活动线程。其中一个是名为`main`的线程。这是一个开始执行`main`方法的方法（惊喜！）。`main`线程启动了大多数其他线程。当我们要编写一个多线程应用时，我们必须创建新的`Thread`对象并启动它们。最简单的方法是启动`new Thread()`，然后在线程上调用`start()`方法。它将开始一个新的`Thread`，它将立即结束，因为我们没有给它任何事情做。在 JDK 中，`Thread`类不执行我们的业务逻辑。以下是指定业务逻辑的两种方法：

*   创建实现`Runnable`接口的类并将其实例传递给`Thread`对象
*   创建扩展`Thread`类并覆盖`run`方法的类

下面的代码块是一个非常简单的演示程序：

```java
package packt.java189fundamentals.thread;

public class SimpleThreadIntermingling {
    public static void main(String[] args) {
        Thread t1 = new MyThread("t1");
        Thread t2 = new MyThread("t2");
        t1.start();
        t2.start();
        System.out.print("started ");

    }

    static class MyThread extends Thread {
        private final String name;

        MyThread(String name) {
            this.name = name;
        }

        @Override
        public void run() {
            for (int i = 1; i < 1000; i++) {
                System.out.print(name + " " + i + ", ");
            }
        }
    }
}
```

前面的代码创建两个线程，然后一个接一个地启动它们。当调用`start`方法时，它调度要执行的线程对象，然后返回。因此，当调用线程继续执行时，新线程将很快开始异步执行。在下面的示例中，两个线程和`main`线程并行运行，并创建如下输出：

```java
started t2 1, t2 2, t2 3, t2 4, t2 5, t2 6, t2 7, t2 8, t1 1, t2 9, t2 10, t2 11, t2 12,...
```

实际输出随运行而变化。没有明确的执行顺序，或者线程如何访问单屏幕输出。甚至不能保证在每次执行中，消息`started`都是在任何线程消息之前打印的。

为了更好地理解这一点，我们查看线程的状态图。Java 线程可以处于以下状态之一：

*   `NEW`
*   `RUNNABLE`
*   `BLOCKED`
*   `WAITING`
*   `TIMED_WAITING`
*   `TERMINATED`

这些状态在`enumThread.State`中定义。创建新线程对象时，它处于`NEW`状态。此时，线程并没有什么特别之处，它只是一个对象，但操作系统的执行调度并不知道它。在某种意义上，它只是 JVM 分配的一块内存。

当启动方法被调用时，关于线程的信息被传递给操作系统，操作系统对线程进行调度，以便在有适当的时隙时可以由它执行。这样做是一种足智多谋的行为，这就是为什么我们不创建，尤其是不在需要时才开始新的`Thread`对象的原因。我们不会创建新的`Threads`，而是将现有的线程保留一段时间，即使目前不需要，如果有合适的线程，也会重用现有的线程。

当操作系统调度和执行线程时，操作系统中的线程也可以处于运行状态，也可以处于可运行状态。目前，Java JDK API 没有很好的理由将两者区分开来。那就没用了。当一个线程处于`RUNNABLE`状态时，从线程内部询问它是否真的在运行，如果代码刚从`Thread`类中实现的`getState()`方法返回，那么它就会运行。如果它没有运行，它本来就不会从调用中返回。更进一步说，在未运行的`Thread`中调用方法`getState()`也是不可能的。如果`getState()`方法是从另一个线程调用的，那么在该方法返回时与另一个线程相关的结果将是无意义的。到那时，操作系统可能已经多次停止或启动被查询的线程。

当线程中执行的代码试图访问当前不可用的资源时，线程处于`BLOCKED`状态。为了避免资源的不断轮询，操作系统提供了一种有效的通知机制，以便线程在需要的资源可用时返回到`RUNNABLE`状态。

线程在等待其他线程或锁时处于`WAIT`或`TIMED_WAITING`状态。`TIMED_WAITING`等待开始时的状态，调用有超时的方法版本。

最后，当线程完成执行后，达到`TERMINATED`状态。如果在前面示例的末尾附加以下行，则将得到一个`TERMINATED`打印输出，并向屏幕抛出异常，抱怨线程状态非法，这是因为您无法启动已终止的线程：

```java
System.out.println(); 
System.out.println(t1.getState()); 
System.out.println(); 
t1.start();
```

我们可以创建一个实现`Runnable`接口的类，而不是扩展`Thread`类来定义异步执行什么，这样做与*OO*编程方法更为一致。我们在类中实现的东西不是线程的功能。它更像是一种可以执行的东西。这是一个可以运行的东西。

如果在不同的线程中执行是异步的，或者在调用`run`方法的同一个线程中执行，那么这是一个需要分离的不同关注点。如果这样做的话，我们可以将类作为构造器参数传递给一个`Thread`对象。对`Thread`对象调用`start`将启动我们传递的对象的`run`方法。这不是收益。好处是我们还可以将`Runnable`对象传递给`Executor`（可怕的名字，哈！）。`Executor`是一个接口，实现以高效的方式在`Thread`对象中执行`Runnable`（还有`Callable`，见下文）对象。执行者通常有一个准备就绪并处于`BLOCKED`状态的`Thread`对象池。当`Executor`有一个新任务要执行时，它将它交给`Thread`对象之一，并释放阻塞线程的锁。`Thread`进入`RUNNABLE`状态，执行`Runnable`，再次被阻塞。它不会终止，因此，可以在以后重用它来执行另一个`Runnable`。这样，`Executor`实现就避免了操作系统中线程注册的资源消耗过程。

专业应用代码从不创建新的`Thread`。应用代码使用框架来处理代码的并行执行，或者使用一些`ExecutorService`提供的`Executor`实现来启动`Runnable`或`Callable`对象。

# 陷阱

我们已经讨论了在开发并行程序时可能遇到的许多问题。在本节中，我们将用解决问题的常用术语对它们进行总结。术语不仅有趣，而且在与同事交谈时也很重要，这样你们就可以互相理解了。

# 死锁

死锁是最臭名昭著的并行编程陷阱，因此，我们将从这个开始。为了描述这种情况，我们将采用官僚的比喻。

官僚必须在纸上盖章。为此，他需要邮票和纸张。首先，他走到放邮票的抽屉里拿了邮票。然后，他走向放纸的抽屉，拿起纸。他在邮票上涂上墨水，然后在纸上按。然后，他把邮票和纸放回原处。一切都是桃色的；我们在云端 9。

如果另一个官僚先拿报纸，然后再拿邮票，会怎么样？他们很快就会变成一个拿着邮票等着报纸的官僚，一个拿着报纸等着邮票的官僚。而且，他们可能只是呆在那里，永远冻结，然后越来越多的人开始等待这些锁，纸张永远不会被盖章，整个系统陷入冻结的无政府状态。

为了避免这种情况，必须对锁进行排序，并且应该始终以相同的顺序获取锁。在前面的示例中，首先获取墨垫，然后获取戳记的简单约定解决了问题。无论是谁得到了邮票，都可以肯定墨水垫是免费的，或者很快就会免费的。

# 竞态条件

我们讨论竞态条件，当计算结果可能基于不同并行运行线程的速度和 CPU 访问而不同时。我们来看看以下两种方法：

```java
   void method1(){
1       a = b; 
2       b = a+1; 
        } 
    void method2(){ 
3       c = b; 
4       b = c+2; 
        }
```

线路的顺序可以是 1234、1324、1342、3412、3142 或 3142。四行执行顺序，可保证`1`在`2`和`3`运行前`4`前运行，但无其他限制。假设`b`的值在开始时为零，则`b`的值在段执行结束时为 1 或`2£`。这几乎是我们永远不想要的。我们更喜欢我们的程序的行为不是随机的，除非，也许在实现随机生成器时。

注意，并行主谋游戏的实现也面临着一种种族条件。实际猜测很大程度上取决于不同线程的速度，但从最终结果的角度来看，这与此无关。我们可能在不同的运行中有不同的猜测，这样，算法就不确定了。我们所保证的是我们找到了最终的解决方案。

# 过度使用的锁

在许多情况下，可能会发生线程在等待锁，锁保护资源不受并发访问的影响。如果资源不能同时被多个线程使用，并且线程数较多，则线程将处于饥饿状态。然而，在许多情况下，资源可以以某种方式组织，以便线程能够访问资源提供的某些服务，并且锁结构可以更少地限制。在这种情况下，锁被过度使用，并且可以修复这种情况，而不为线程分配更多资源。可以使用多个锁来控制对资源不同功能的访问。

# 饥饿

饥饿是指多个线程等待一个资源试图获取锁，而一些线程只有在很长一段时间后才能访问该锁，或者从来没有访问过该锁。当锁被释放并且有线程在等待它时，其中一个线程就可以获得锁。如果线程等待的时间足够长，通常无法保证它能获得锁。这样的机制需要对线程进行密集的管理，在等待队列中对线程进行排序。由于锁定应该是一种低延迟和高性能的操作，因此即使只有几个 CPU 时钟周期也很重要；因此，默认情况下，锁不提供这种类型的公平访问。如果锁只有一个线程在等待，那么在线程调度中不浪费时间和公平性是一个很好的方法。锁的主要目标不是调度等待的线程，而是阻止对资源的并行访问。

它就像一家商店。如果有人在收银台，你就等着。它是隐式内置的锁。如果人们不排队等候收银台，只要几乎总是有一个免费的就没有问题。然而，当有几个人在收银台前等候时，如果没有排队和等待顺序，肯定会导致缓慢进入收银台的人等待很长时间。通常，公平性和创建等待线程（客户）队列的解决方案不是一个好的解决方案。好的解决办法是消除导致排队等候的情况。你可以雇佣更多的收银员，或者你可以做一些完全不同的事情，使峰值负荷更小。在商店里，你可以给在非高峰时间开车来的顾客打折。在编程中，通常可以应用几种技术，这取决于我们编写的实际业务，而锁的公平调度通常是一种解决方法。

# `ExecutorService`

`ExecutorService`是 JDK 中的一个接口。接口的实现可以异步执行一个`Runnable`或`Callable`类。接口只定义实现的 API，不要求调用是异步的。实际上，这就是为什么我们使用这样的服务。以同步方式调用`Runnable`接口的`run`方法只是调用一个方法。我们不需要特殊的类。

`Runnable`接口定义了一个`run`方法。它没有参数，不返回值，也不引发异常。`Callable`接口是参数化的，它定义的唯一方法`call`没有参数，但返回泛型值，还可能抛出`Exception`。在代码中，如果我们只想运行某个东西，我们就实现了`Runnable`，如果我们想返回某个东西，我们就实现了`Callable`。这两个接口都是函数式接口；因此，它们是使用 Lambda 实现的很好的候选接口。

为了获得一个`ExecutorService`实现的实例，我们可以使用实用类`Executors`。通常，当 JDK 中有一个`XYZ`接口时，可以有一个`XYZs`（复数）工具类，为接口的实现提供工厂。如果我们想多次启动`t1`任务，我们可以不创建新的`Thread`就这样做。我们应该使用以下执行器服务：

```java
public class ThreadIntermingling {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        final var es = Executors.newFixedThreadPool(2);
        final var t1 = new MyRunnable("t1");
        final var t2 = new MyRunnable("t2");
        final Future<?> f1 = es.submit(t1);
        final Future<?> f2 = es.submit(t2);
        System.out.print("started ");
        var o = f1.get();
        System.out.println("object returned " + o);
        f2.get();
        System.out.println();
        es.submit(t1);
        es.shutdown();
    }

    static class MyRunnable implements Runnable {
        private final String name;

        MyRunnable(String name) {
            this.name = name;
        }

        @Override
        public void run() {
            for (int i = 1; i < 10; i++) {
                System.out.print(name + " " + i + ", ");
            }
        }
    }
}
```

这次，我们第二次提交任务时没有异常。在本例中，我们使用的是一个固定大小的线程池，该线程池有两个`Thread`插槽。因为我们只想同时启动两个线程，这就足够了。有些实现动态地扩展和缩小池的大小。当我们想要限制线程数量或从其他信息源中*事先*知道线程数时，应该使用固定大小的池。在这种情况下，将池的大小更改为一个是一个好的实验，并且在这种情况下，第二个任务在第一个任务完成之前不会开始。服务将没有另一个线程用于`t2`，并且必须等到池中的一个线程和唯一的`Thread`可用。

当我们将任务提交给服务时，即使任务当前无法执行，它也会返回。这些任务被放入队列中，一旦有足够的资源启动它们，它们就会立即开始执行。`submit`方法返回一个`Future<?>`对象，正如我们在前面的示例中看到的那样。

它就像一张服务票。你把车交给修理工，然后你就得到了一张罚单。在汽车修好之前，你不需要呆在那里，但是，你可以随时询问汽车是否准备好了。你只需要一张票。你也可以决定等到车子准备好。物体是类似的东西。你没有得到你需要的值。它将异步计算。然而，有一个`Future`承诺它会在那里，而您访问所需对象的票证就是`Future`对象。

当您有一个`Future`对象时，您可以调用`isDone()`方法来查看它是否准备就绪。您可以开始等待它在有或没有超时的情况下调用`get()`。您也可以取消执行它的任务，但是，在这种情况下，结果可能是有问题的。就像，在你的车的情况下，如果你决定取消任务，你可能会得到你的车与电机拆解。类似地，取消一个没有准备好的任务可能会导致资源丢失、数据库连接被打开和无法访问（这对我来说是一个痛苦的记忆，即使 10 年之后），或者只是一个乱七八糟的不可用对象。准备要取消的任务或不要取消它们。

在前面的示例中，由于我们提交了`Runnable`对象，而不是`Callable`对象，所以`Future`没有返回值。在这种情况下，不使用传递给`Future`的值。通常是`null`，但这并不是什么可依赖的。

最后也是最重要的一件事，许多开发人员都错过了，即使是我，在多年没有使用代码编写多线程 JavaAPI 之后，就是关闭了`ExecutorService`。创建了`ExecutorService`，它有`Thread`个元素。当所有非守护线程停止时，JVM 将停止。”直到胖女人唱歌，一切才结束。”

如果线程在启动前被设置为守护进程（调用`setDaemon(true)`），那么它就是守护线程。一个自动成为启动它的守护线程的线程也是守护线程。当所有其他线程都完成并且 JVM 想要完成时，守护线程被 JVM 停止。JVM 本身执行的一些线程是守护线程，但是在应用中创建守护线程可能没有实际用途。

不关闭服务只会阻止 JVM 停止。在`main`方法完成后，代码将挂起。为了告诉`ExecutorService`不需要它拥有的线程，我们必须`shutdown`服务。调用只会启动关机并立即返回。在这种情况下，我们不想等待。无论如何，JVM 都会这样做。如果我们需要等待，我们将不得不调用`awaitTermination`。

# `CompletableFuture`

Java 版本 1.8 引入了接口`Future`—`CompletableFuture`的新实现。`java.util.concurrent.CompletableFuture`类可用于异步执行定义回调的程序以处理结果。由于 Java1.8 还引入了 Lambda 表达式，因此可以使用它们来描述回调：

```java
public static void main(String[] args) throws ExecutionException, InterruptedException {
    var future = CompletableFuture.supplyAsync(() ->
            {
                var negative = true;
                var pi = 0.0;
                for (int i = 3; i < 100000; i += 2) {
                    if (negative)
                        pi -= (1.0 / i);
                    else
                        pi += (1.0 / i);
                    negative = !negative;
                }
                pi += 1.0;
                pi *= 4.0;
                return pi;
            }
    ).thenAcceptAsync(piCalculated -> System.out.println("pi is " + piCalculated));
    System.out.println("All is scheduled");
    future.get();
}
```

completable future 类实现了`Future`接口，但它还提供了其他方法，当我们需要描述异步代码的执行时，它也提供了其他方便的方法。额外的方法在`CompletionStage`接口中定义，起初这个名字有点奇怪，但我们很快就会理解它的真正含义。

我们已经看到了在这个接口中定义的许多方法之一-`thenAcceptAsync()`。前面的代码创建了一个由 Lambda 表达式定义的完全`Future`。静态方法`supplyAsync()`接受`Supplier`作为参数。Java 的线程系统稍后会调用这个供应器。此方法的返回值是一个`CompletableFuture`，用于使用`thenAcceptAsync()`方法创建另一个`CompletableFuture`。第二个`CompletableFuture`与第一个`CompletableFuture`相连。只有当第一个完成时，它才会开始。`thenAcceptAsync()`的参数是一个消费者，它将消费`Supplier`提供的第一个`CompletableFuture`的结果。代码的结构可以用以下伪代码来描述：

```java
CompletableFuture.supplyAsync( supply_value ).thenAcceptAsync( consume_the_value )
```

它说启动由`supply_value`表示的`Supplier`，当它完成时，将这个值提供给由`consume_the_value`表示的消费者。示例代码计算 PI 的值并提供该值。`consume_the_value`部分将值打印到输出。当我们运行代码时，文本`All is scheduled`可能会首先打印到输出中，然后才打印 PI 的计算值。

类还实现了许多其他方法。当`CompletableFuture`不产生任何值或者我们不需要消耗值时，我们应该使用`thenRunAsync(Runnable r)`方法。

如果我们想消费值，同时又想从中创造新的值，那么我们应该使用`thenApplyAsync()`方法。此方法的参数是一个`Function`，它获取运行后`CompletableFuture`的结果，结果是`CompletableFuture thenApplyAsync()`返回的值。

在`CompletableFuture`完成之后，还有许多其他方法执行代码。所有这些都用于在第一个可完成的将来完成后指定某个回调。`CompletableFuture`代码的执行可能引发异常。在这种情况下，`CompletableFuture`就完成了；它不会抛出异常。异常被捕获并存储在`CompletableFuture`对象中，只有当我们想访问调用`get()`方法的结果时才会抛出异常。方法`get()`抛出一个封装原始异常的`ExecutionException`。`join()`方法抛出原始异常。

像`thenAcceptAsync()`这样的方法有它们的同步对，例如`thenAccept()`。如果调用此函数，则将执行传递的代码：

*   如果此代码所依赖的`CompletableFuture`尚未完成，则使用用于执行原始`CompletableFuture`的同一线程；或者
*   如果`CompletableFuture`已经完成，则使用普通调用线程

换句话说，如果我们再看看伪代码：

```java
var cf = CompletableFuture.supplyAsync( supply_value );
cf.thenAccept( consume_the_value )
```

但这次是`thenAccept()`而不是`thenAcceptAsync()`，所以执行`supply_value`表示的代码的线程在完成`supply_value`后继续执行`consume_the_value`，或者，如果调用方法`thenAccept()`时`supply_value`的执行已经完成，则只执行如下：

```java
consume_the_value( cf.get() )
```

在本例中，代码`consume_the_value`只是同步执行。（请注意，如果发生异常，它将被存储，而不是直接抛出。）

使用`CompletableFuture`的最佳用例是当我们进行异步计算并且需要回调方法来处理结果时。

# `ForkJoinPool`

`ForkJoinPool`是一个特殊的`ExecutorService`，它有执行`ForkJoinTask`对象的方法。当我们要执行的任务可以被分解成许多小任务，然后当结果可用时，这些类非常方便。使用这个执行器，我们不需要关心线程池的大小和关闭执行器。线程池的大小根据给定机器上的处理器数量进行调整，以获得最佳性能。因为`ForkJoinPool`是一个特殊的`ExecutorService`是为短期运行的任务而设计的，所以它不希望有任何任务在那里停留更长的时间，也不希望在没有更多任务要运行时需要任何任务。因此，它作为守护线程执行；当 JVM 关闭时，`ForkJoinPool`自动停止。

为了创建任务，程序员应该扩展`java.util.concurrent.RecursiveTask`或`java.util.concurrent.RecursiveAction`。第一个是在任务有返回值时使用的，第二个是在没有返回计算值时使用的。它们之所以被称为递归的，是因为很多时候，这些任务会分解它们必须解决的问题，并通过 Fork/Join API 异步调用这些任务。

使用此 API 要解决的一个典型问题是快速排序。在第 3 章“优化专业排序代码”中，我们创建了两个版本的快速排序算法，一个使用递归调用，一个不使用递归调用。我们还可以创建一个新的任务，它不是递归地调用自己，而是将任务调度到另一个处理器执行。调度是`ForkJoinPool`实现`ExecutorService`的任务。

您可以重温第 3 章中的`Qsort.java`代码，“优化专业排序代码”。以下是使用`ForkJoinPool`的版本，没有一些明显的代码，包括构造器和`final`字段定义：

```java
public void qsort(Sortable<E> sortable, int start, int end) {
    ForkJoinPool pool = new ForkJoinPool();
    pool.invoke(new RASort(sortable, start, end));
}

private class RASort extends RecursiveAction {

    final Sortable<E> sortable;
    final int start, end;

    public RASort(Sortable<E> sortable, int start, int end) {
        this.sortable = sortable;
        this.start = start;
        this.end = end;
    }

    public void compute() {
        if (start < end) {
            final E pivot = sortable.get(start);
            int cutIndex = partitioner.partition(sortable, start, end, pivot);
            if (cutIndex == start) {
                cutIndex++;
            }
            RecursiveAction left = new RASort(sortable, start, cutIndex - 1);
            RecursiveAction right = new RASort(sortable, cutIndex, end);
            invokeAll(left, right);
            left.join();
            right.join();
        }
    }
}
```

数组被枢轴元素拆分后，创建两个`RecursiveAction`对象。它们存储对数组的左侧和右侧进行排序所需的所有信息。当`invokeAll()`被调用时，这些操作被安排。`invokeAll()`方法由前面的代码通过`RecursiveAction`从`ForkJoinClass`类继承，而`RecursiveAction`本身在该代码中进行了扩展。

API 和 Oracle 的 Javadoc 文档的应用上都有很好的阅读材料。

# 变量访问

既然我们可以启动线程并创建并行运行的代码，现在是时候谈谈这些线程如何在彼此之间交换数据了。乍一看，这似乎相当简单。线程使用相同的共享内存；因此，它们可以读取和写入 Java 访问保护允许它们的所有变量。这是正确的，只是有些线程可能只是决定不读取内存。毕竟，如果他们最近刚刚读取了一个特定变量的值，如果没有修改，为什么还要从内存中再次读取到寄存器中呢？谁会修改它？下面是一个简短的例子：

```java
package packt.java189fundamentals.thread;

public class VolatileDemonstration implements Runnable {
    private final Object o;
    private static final Object NON_NULL = new Object();
    @Override
    public void run() {
        while( o == null );
        System.out.println("o is not null");
    }

    public VolatileDemonstration() throws InterruptedException {
        new Thread(this).start();
        Thread.sleep(1000);
        this.o = NON_NULL;
    }

    public static void main(String[] args) throws InterruptedException {
        VolatileDemonstration me = new VolatileDemonstration();
    }
}
```

会发生什么？您可能期望代码启动，启动新线程，然后，当`main`线程将对象设置为非`null`的对象时，它会停止吗？不会的。

它可能会在一些 Java 实现上停止，但在大多数实现中，它只会继续旋转。原因是 JIT 编译器优化了代码。它看到循环什么也不做，而且变量永远不会是非空的。允许假设因为没有声明为`volatile`的变量不应该被不同的线程修改，所以 JIT 可以进行优化。如果我们将`Object o`变量声明为`volatile`，那么代码将停止。您还必须删除`final`关键字，因为变量不能同时是`final`和`volatile`。

如果您试图删除对`sleep`的调用，代码也将停止。然而，这并不能解决这个问题。原因是 JIT 优化只在大约 5000 次代码执行循环之后才开始。在此之前，代码运行简单，并在优化之前停止，这将消除对非易失性变量的额外访问（通常不需要）。

如果这是如此可怕，那么为什么我们不声明所有变量都是易变的呢？为什么 Java 不能为我们做到这一点？答案是速度。为了更深入地理解这一点，我们将用办公室和官僚来比喻。

# CPU 心跳

现在，CPU 在 2 到 4GHz 频率的处理器上运行。这意味着处理器每秒得到 2 到 4 倍于`10**9`的时钟信号来做某事。处理器不能执行比这更快的任何原子操作，而且也没有理由创建一个比处理器可以遵循的更快的时钟。这意味着 CPU 在半纳秒或四分之一纳秒内执行一个简单的操作，例如递增寄存器。这是处理器的心跳，如果我们认为官僚是人，他们是谁，那么它相当于一秒钟，大约，他们的心跳。在我们的想象中，这会将计算机的运行速度减慢到可以理解的速度。

处理器在芯片上有不同级别的寄存器和高速缓存；L1、L2，有时还有 L3；还有存储器、SSD、磁盘、磁盘、网络和磁带，可能需要它们来检索数据。

访问一级缓存中的数据大约需要 0.5 ns。你可以抓起你桌上半秒钟的一张纸。访问二级缓存中的数据需要 7 ns。这是抽屉里的一张纸。你得把椅子往后推一点，弯曲成坐姿，拉出抽屉，拿着纸，把抽屉往后推，把纸抬起来放在桌子上；这需要 10 秒钟，左右。

主存读取为 100ns。官僚站起来，走到靠墙的共享文件库，等着其他官僚把文件拿出来或放回去，选择抽屉，把它拿出来，拿着文件，走回办公桌。这需要两分钟。这是一种易变的变量访问，每次你在一个文档上写一个单词，它必须做两次，一次读，一次写，即使你碰巧知道下一件事就是在同一张纸上填写表单的另一个字段。

现代架构没有多个 cpu，而是有多个核的单个 cpu，速度要快一些。一个内核可以检查另一个内核的缓存，以查看是否对同一变量进行了任何修改。这将易变访问加速到 20ns 左右，这仍然比非易变慢一个数量级。

尽管其余部分不太关注多线程编程，但这里值得一提，因为它很好地理解了不同的时间量级。

从 SSD 读取一个块（通常为 4k 块）需要 150000ns。以人类的速度，这比 5 天多一点。在 Gb 本地以太网上通过网络向服务器读取或发送数据需要 0.5 毫秒，这就好像是在等一个月的时间。如果网络上的数据是在一个旋转的磁盘上，那么寻道时间加起来（直到磁盘旋转以使磁表面的一部分进入读取头下的时间）为 20ms。对于在我们的计算环境中来回运行的想象中的小官僚来说，这大约是一年。

如果我们在互联网上通过大西洋发送一个网络数据包，大约需要 150 毫秒。这就像 14 年，而这仅仅是一个数据包；如果我们要通过海洋发送数据，这将构成数千年的历史。如果我们计算一台机器启动一分钟，它相当于我们整个文明的时间跨度。

当我们想了解 CPU 大部分时间在做什么时，我们应该考虑这些数字。它等待着。此外，当你想到现实生活中官僚的速度时，这个比喻也有助于安抚你的神经。如果我们考虑他们的心跳，他们毕竟没有那么慢，这意味着他们有心脏。然而，让我们回到现实生活中，CPU，L1 和 L2 缓存，以及易失性变量。

# 易变变量

让我们在示例代码中修改`o`变量的声明，如下所示：

```java
private volatile Object o = null;
```

前面的代码运行良好，大约一秒钟后停止。任何 Java 实现都必须保证多个线程可以访问`volatile`字段，并且该字段的值是一致更新的。这并不意味着`volatile`声明将解决所有的同步问题，而是保证不同的变量及其值变化关系是一致的。例如，让我们考虑在一个方法中增加以下两个字段：

```java
private int i=0,j=0; 

 public void method(){ 
     i++; j++; 
 }
```

在前面的代码中，在不同的线程中读取`i`和`j`可能永远不会产生`i>j`。如果没有`volatile`声明，编译器可以自由地重新组织增量操作的执行，因此，它不能保证异步线程读取一致的值。

# 同步块

声明变量不是确保线程之间一致性的唯一工具。Java 语言中还有其他工具，其中一个是同步块。`synchronized`关键字是语言的一部分，它可以在方法或程序块前面使用，该方法、构造器或初始化器块中。

Java 程序中的每个对象都有一个监视器，可以被任何正在运行的线程锁定和解锁。当一个线程锁定一个监视器时，据说该线程持有该锁，并且没有两个线程可以同时持有一个监视器的锁。如果一个线程试图锁定一个已经被锁定的监视器，它会得到`BLOCKED`，直到监视器被释放。同步块以`synchronized`关键字开始，然后在括号之间指定一个对象实例，然后发生阻塞。下面的小程序演示了`synchronized`块：

```java
package packt.java189fundamentals.thread;

public class SynchronizedDemo implements Runnable {
    public static final int N = 1000;
    public static final int MAX_TRY = 1_000_000;

    private final char threadChar;
    private final StringBuffer sb;

    public SynchronizedDemo(char threadChar, StringBuffer sb) {
        this.threadChar = threadChar;
        this.sb = sb;
    }

    @Override
    public void run() {
        for (int i = 0; i < N; i++) {
            synchronized (sb) {
                sb.append(threadChar);
                sleep();
                sb.append(threadChar);
            }
        }
    }

    private void sleep() {
        try {
            Thread.sleep(1);
        } catch (InterruptedException ignored) {
        }
    }

    public static void main(String[] args) {
        boolean failed = false;
        int tries = 0;
        while (!failed && tries < MAX_TRY) {
            tries++;
            StringBuffer sb = new StringBuffer(4 * N);
            new Thread(new SynchronizedDemo('a', sb)).start();
            new Thread(new SynchronizedDemo('b', sb)).start();
            failed = sb.indexOf("aba") != -1 || sb.indexOf("bab") != -1;
        }
        System.out.println(failed ? "failed after " + tries + " tries" : "not failed");
    }
}
```

代码从两个不同的线程开始。其中一个线程将`aa`附加到名为`sb`的`StringBuffer`上。另一个附加`bb`。这个附加操作分两个阶段进行，中间是睡眠。睡眠是为了避免 JIT 将两个单独的步骤优化为一个步骤。每个线程执行`append`1000 次，每次追加`a`或`b`两次。由于两个`append`一个接一个，并且它们在`synchronized`块内，所以`aba`或`bab`序列不可能进入`StringBuffer`中。当一个线程执行同步块时，另一个线程不能执行它。

如果我删除`synchronized`块，那么我用来测试 Java HotSpot（TM）64 位服务器 VM 的 JVM（对于本书的第二版，构建 9-ea+121，混合模式和 18.3 b 构建 10+46，混合模式）打印出失败，尝试数量大约为几百次。（看看 Packt 提供的代码库中的`SynchronizedDemoFailing`类。）

它清楚地说明了同步意味着什么，但它也将我们的注意力吸引到另一个重要的现象上。错误只发生在大约每几十万次执行中。这是极为罕见的，即使这个例子是用来证明这样的灾难。如果一个 bug 很少出现，那么很难重现，甚至更难调试和修复。大多数同步错误都以神秘的方式表现出来，修复它们通常是仔细检查代码而不是调试的结果。因此，在启动商业多线程应用之前，清楚地了解 Java 多线程行为的真正本质是非常重要的。

`synchronized`关键字也可以用在方法前面。在这种情况下，获取锁的对象是`this`对象。在`static`方法的情况下，对整个类执行同步。

# 等待和通知

在`Object`类中实现了五个方法，可以用来获得进一步的同步功能—`wait`，其中有三个不同的超时参数签名`notify`和`notifyAll`。要调用`wait`，调用线程应该拥有调用`wait`的`Object`的锁。这意味着您只能从同步块内部调用`wait`，当调用它时，线程得到`BLOCKED`并释放锁。当另一个线程对同一个`Object`调用`notifyAll`时，该线程进入`RUNNABLE`状态。它无法立即继续执行，因为它无法获得对象上的锁。此时锁被刚才称为`notifyAll`的线程所持有。然而，在另一个线程释放锁之后的某个时候，换句话说，它从`synchronized`块中出来，等待的线程可以获取它并继续执行。

如果有更多线程在等待一个对象，那么所有线程都会脱离`BLOCKED`状态。`notify`方法只唤醒一个等待的线程。不能保证哪根线被唤醒。

`wait`、`notify`和`notifyAll`的典型用法是当一个或多个线程正在创建被另一个或多个线程使用的对象时。对象在线程之间移动的存储是一种队列。使用者等待，直到队列中有要读取的内容，生产者将对象一个接一个地放入队列。生产者在队列中放入内容时通知消费者。如果队列中没有剩余的空间，生产者必须停止并等待，直到队列有一些空间。在这种情况下，生产者调用`wait`方法。为了唤醒生产者，消费者在读到某样东西时会打电话给`notifyAll`。

使用者在循环中使用队列中的对象，并且只有在队列中没有可读取的内容时才调用`wait`。当生产者调用`notifyAll`时，没有消费者等待，通知被忽略。它飞走了，但这不是问题；消费者没有等待。当消费者消费了一个对象并调用了`notifyAll`，并且没有生产者等待时，情况也是一样的。这不是问题。

消费者消费，调用`notifyAll`，在通知悬而未决后，找不到等待的生产者，生产者就开始等待，这是不可能发生的。这不可能发生，因为整个代码都在一个`synchronized`块中，它确保没有生产者在关键部分。这就是为什么只有在获取`Object`类的锁时才能调用`wait`、`notify`和`notifyAll`的原因。

如果有许多使用者执行相同的代码，并且他们同样擅长使用对象，那么调用`notify`而不是`notifyAll`就是一种优化。在这种情况下，`notifyAll`只会唤醒所有使用者线程。然而，只有幸运的人才会意识到他们被吵醒了；其他人会看到其他人已经逃脱了诱饵。

我建议您至少练习一次，以实现可用于在线程之间传递对象的阻塞队列。只作为实践来做，不要在生产中使用实践代码。从 Java1.5 开始，有`BlockingQueue`接口的实现。用一个适合你需要的。在我们的示例代码中，我们也将这样做。

幸运的是你能用 Java11 编写代码。我在 Java1.4 的时候就开始专业地使用它，有一次，我不得不实现一个阻塞队列。有了 Java，生活变得越来越美好和轻松。

在专业代码中，我们通常避免使用`synchronized`方法或块和`volatile`字段以及`wait`和`notify`方法，如果可能的话，还可以使用`notifyAll`。我们可以在线程之间使用异步通信，也可以将整个多线程过程传递给框架进行处理。在某些特殊情况下，当代码的性能很重要时，`synchronized`和`volatile`关键字是不可避免的，或者我们找不到更好的构造。有时，特定代码和数据结构的直接同步比 JDK 类提供的方法更有效。但是，应该注意的是，这些类也使用这些低级同步结构，因此它们的工作方式并不神奇。要从专业代码中学习，可以在实现自己的版本之前查看 JDK 类的代码。您将认识到，实现这些队列并不是那么简单；没有充分的理由，类的代码并不复杂。如果你觉得代码很简单，那就意味着你有足够的资历去知道哪些东西不能重新实现。或者，你甚至不知道你读了什么代码。

# 锁

锁包含在 Java 中；每个`Object`都有一个锁，线程在进入`synchronized`块时可以获得该锁。我们已经讨论过了。在某些编程代码中，这种结构有时不是最优的。

在某些情况下，可以排列锁的结构以避免死锁。可能需要在`B`之前获取锁`A`，在`C`之前获取`B`。但是，`A`应该尽快释放，以允许访问受锁`D`保护的资源，也需要先锁`A`。在复杂且高度并行的结构中，锁通常被构造为树。一个线程应该沿着树向下爬到一个表示获取锁的资源的叶子上。在攀爬的过程中，线程先抓住一个节点上的锁，然后抓住它下面的一个节点上的锁，然后释放上面的锁，就像一个真正的攀爬者在下降一样（或者攀爬，如果你想象树的叶子在顶部，这更真实；然而，图形通常显示树是颠倒的）。

你不能留下一个`synchronized`块留在第一个街区内的另一个。同步块嵌套。`java.util.concurrent.Lock`接口定义了处理这种情况的方法，并且在我们的代码中使用的 JDK 中也有实现。有锁时，可以调用`lock()`和`unlock()`方法，实际顺序在手中，可以写下一行代码，得到锁顺序：

```java
a.lock(); b.lock(); a.unlock(); c.lock()
```

然而，伴随着巨大的自由，也伴随着巨大的责任。与同步块的情况不同，锁定和解锁并不与代码的执行序列相关联，在某些情况下，创建代码可能非常容易，因为在某些情况下，它只是丢失了一个锁而没有解锁，从而导致一些资源无法使用。这种情况类似于内存泄漏。你会分配（锁定）一些东西而忘记释放（解锁）它。一段时间后，程序将耗尽资源。

我个人的建议是尽可能避免使用锁，而是在线程之间使用更高级别的构造和异步通信，比如阻塞队列。

# 条件

`java.util.concurrent.Condition`接口在功能上与内置的`wait()`、`notify()`和`notifyAll()`对象类似。任何`Lock`的实现都应该创建新的`Condition`对象，并将它们作为`newCondition()`方法调用的结果返回。当线程有一个`Condition`时，当线程有创建条件对象的锁时，它可以调用`await()`、`signal()`和`signalAll()`。

其功能与前面提到的`Object`方法非常相似。最大的区别是，你可以为一个`Lock`创建许多`Condition`对象，它们彼此独立地工作，而不是独立于`Lock`。

# 重入锁

`ReentrantLock`是 JDK 中`Lock`接口的最简单实现。创建这种类型的锁有两种方法，一种是使用公平策略，另一种是不使用公平策略。如果以`true`作为参数调用`ReentrantLock(Boolean fair)`构造器，那么在有多个线程等待的情况下，锁将被分配给等待锁时间最长的线程。这将避免线程等待过多的时间和饥饿。另一方面，以这种方式处理锁需要更多的来自`ReentrantLock`代码的管理，并且运行速度较慢。（在测量代码之前，不要害怕代码太慢。）

# 重入读写锁

这个类是`ReadWriteLock`的一个实现。`ReadWriteLock`是一种可用于并行读访问和独占写访问的锁。这意味着多个线程可以读取受锁保护的资源，但是当一个线程写入资源时，没有其他线程可以访问它，甚至在此期间也不能读取它。`ReadWriteLock`只是`readLock()`和`writeLock()`方法返回的两个`Lock`对象。为了获得对`ReadWriteLock`的读访问权，代码必须调用`myLock.readLock().lock()`，并获得对写锁`myLock.writeLock().lock()`的访问权。获取其中一个锁并在实现中释放它与另一个锁是耦合的。例如，要获取写锁，任何线程都不应该具有活动的读锁。

使用不同的锁有几个复杂的地方。例如，可以获取读锁，但只要具有读锁，就无法获取写锁。必须先释放读锁才能获得写锁。这只是一个简单的细节，但这是一个新手程序员有很多次麻烦。为什么要这样实现？为什么程序要获得一个写锁，当它仍然不确定是否要写入资源时，从锁定其他线程的概率更高的意义上讲，写锁的成本更高？代码想要读取它，并且基于内容，它可能稍后决定要编写它。

问题不在于执行。库的开发人员决定了这个规则，并不是因为他们喜欢这样，也不是因为他们知道并行算法和死锁的可能性。当两个线程有`readLock`并且每个线程都决定将锁升级到`writeLock`时，它们本质上会创建死锁。每个人都会在等待`writeLock`的时候拿着`readLock`，没有人会得到它。

另一方面，您可以将`writeLock`降级为`readLock`，而无需冒风险，同时，有人获得`writeLock`并修改资源。

# 原子变量

原子类将原始类型值封装到对象中，并对其提供原子操作。我们讨论了竞争条件和可变变量。例如，如果我们有一个`int`变量用作计数器，并且我们想为我们处理的对象分配一个唯一的值，我们可以增加该值并将结果用作唯一的 ID。但是，当多个线程使用同一代码时，我们不能确定在增加后读取的值。同时，另一个线程也可能增加该值。为了避免这种情况，我们必须将增量括起来，并将增量值赋给`synchronized`块中的对象。这也可以使用`AtomicInteger`来完成。

如果我们有一个变量`AtomicInteger`，那么调用`incrementAndGet`会增加类中包含的`int`的值，并返回增加的值。为什么不使用同步块而使用它呢？第一个答案是，如果功能在 JDK 中，那么使用它会比再次实现它产生更少的代码行。维护您创建的代码的开发人员应该了解 JDK 库。另一方面，为他们学习代码需要时间，时间就是金钱。

另一个原因是，这些类经过了高度优化，而且它们通常使用特定于平台的本机代码来实现特性，这大大优于我们可以使用同步块实现的版本。过早地担心性能是不好的，但是当性能至关重要时，通常使用并行算法和线程之间的同步；因此，使用原子类的代码的性能很有可能是重要的。尽管如此，主要原因仍然是可读性和简单性。

`java.util.concurrent.atomic`包中有`AtomicInteger`、`AtomicBoolean`、`AtomicLong`、`AtomicReference`等几种类别。它们都提供了特定于封装值的方法。

`compareAndSet()`方法由每个原子类实现。这是具有以下格式的条件值设置操作：

```java
boolean compareAndSet(expectedValue, updateValue);
```

当它应用于一个原子类时，它将实际值与一个`expectedValue`进行比较，如果它们相同，则将值设置为`updateValue`。如果值被更新，方法返回`true`，并在原子操作中完成所有这一切。不用说，如果条件不成立并且没有执行更新，则返回值为`false`。

你可能会问这样一个问题：如果这个方法在所有这些类中，为什么没有`Interface`定义这个方法？原因是参数类型根据封装的类型不同而不同，这些类型是原始类型。由于原始类型还不能用作泛型类型，因此无法定义接口。

在`AtomicXXXArray`的情况下，方法有一个额外的第一个参数，它是调用中处理的数组元素的索引。

就运行在不同处理器内核上的多个线程的重新排序和访问而言，封装的变量的处理方式与`volatile`相同。原子类的实际实现可能使用特殊的硬件代码，这些代码可以提供比 Java 中的原始实现更好的性能，因此原子类可能比使用易失性变量和同步块的普通 Java 代码中实现的相同功能具有更好的性能。

一般的建议是，如果有可用的原子类，可以考虑使用原子类，您将发现自己正在为检查和设置、原子增量或加法操作创建一个同步块。

# `BlockingQueue`

`BlockingQueue`是一个用适合多线程应用使用的方法扩展标准`Queue`接口的接口。此接口的任何实现都提供了允许不同线程将元素放入队列、从队列中拉出元素并等待队列中的元素的方法。

当队列中要存储新元素时，您可以`add()`它、`offer()`它或`put()`它。这些是存储元素的方法的名称，它们做同样的事情，只是有点不同。如果队列已满且元素没有空间，`add()`方法抛出异常。`offer()`方法不抛出异常，而是根据操作是否成功返回`true`或`false`。如果可以将元素存储在队列中，则返回`true`。还有一个版本的`offer()`指定超时。如果在此期间无法将值存储在队列中，则该版本的方法将等待并仅返回`false`。`put()`方法是最简单的版本；它会等到它能完成它的工作。

当谈到队列中的可用空间时，不要感到困惑，不要把它与一般的 Java 内存管理混淆起来。如果没有更多的内存，垃圾收集器也无法释放任何内存，您肯定会得到一个`OutOfMemoryError`。异常由`add()`抛出，当达到队列限制时`false`值由`offer()`返回。一些`BlockingQueue`实现可以限制可以同时存储在队列中的元素的数量。如果达到该限制，则队列已满，无法接受更多元素。

从`BlockingQueue`实现中获取元素有四种不同的方法。在这个方向上，特殊情况是队列为空。在这种情况下，`remove()`方法抛出异常而不是返回元素，`poll()`方法返回`null`如果没有元素，`take()`方法只是等待它可以返回元素。

最后，有两个继承自`Queues`接口的方法不使用队列中的元素，而只是*查看*它。`element()`方法返回队列的头，如果队列为空，则抛出异常。如果队列中没有元素，`peek()`方法返回`null`。下表总结了从接口文档中借用的操作：

|  | **抛出异常** | **特殊值** | **阻塞** | **超时** |
| --- | --- | --- |
| **插入** | `add(e)` | `offer(e)` | `put(e)` | `offer(e, time, unit)` |
| **弹出** | `remove()` | `poll()` | `take()` | `poll(time, unit)` |
| **检查** | `element()` | `peek()` | `not applicable` | `not applicable` |

# `LinkedBlockingQueue`

这是`BlockingQueue`接口的一个实现，它由一个链表备份。默认情况下，队列的大小不受限制（准确地说，它是`Integer.MAX_VALUE`），但是可以选择在构造器参数中进行限制。在这个实现中限制大小的原因是，当并行算法在有限大小的队列中执行得更好时，可以帮助使用。实现本身对大小没有任何限制，只有`Integer.MAX_VALUE`比较大。

# `LinkedBlockingDeque`

这是`BlockingQueue`及其`BlockingDeque`子接口的最简单实现，如前一章所述，`Deque`是一个双端队列，具有`add`、`remove`、`offer`等方法类型，以`xxxFirst`和`xxxLast`的形式与队列的一端或另一端执行动作。`Deque`接口定义了`getFirst`和`getLast`，而不是一致地命名`elementFirst`和`elementLast`，所以这是你应该习惯的。毕竟，IDE 有助于自动补全代码，所以这应该不是什么大问题。

# `ArrayBlockingQueue`

`ArrayBlockingQueue`实现`BlockingQueue`接口，因此实现`Queue`接口。此实现管理具有固定大小元素的队列。实现中的存储是一个数组，元素以先进先出的方式进行处理。这是一个类，我们也将在“策划”的并行实现中使用，用于老板和下属官僚之间的沟通。

# `LinkedTransferQueue`

`TransferQueue`接口正在扩展`BlockingQueue`，在 JDK 中它的唯一实现是`LinkedTransferQueue`。当一个线程想要将一些数据移交给另一个线程，并且需要确保另一个线程接受元素时，`TransferQueue`就很有用了。这个`TransferQueue`有一个`transfer()`方法，它将一个元素放在队列中，但是直到其他线程调用`remove()`之后才返回，从而删除它（或者调用`poll()`，从而轮询它）。这样，生产线程就可以确保放入队列的对象在另一个处理线程手中，而不是在队列中等待。`transfer()`方法还有一种格式`tryTransfer()`，您可以在其中指定超时值。如果方法超时，则元素不会放入队列。

# `IntervalGuesser`

我们讨论了可用于实现并行算法的不同 Java 语言元素和 JDK 类。现在，我们将看到如何使用这些方法来实现主谋游戏的并行猜测器。

在我们开始之前，我必须承认这个任务不是一个典型的并行编程教程任务。讨论并发编程技术的教程倾向于选择易于使用并行代码解决且可扩展性好的问题作为示例。如果在`N`处理器上运行的并行算法实际运行的速度是非并行解的`N`倍，那么问题就可以很好地扩展。我个人的看法是，这些例子描绘的天空蓝色没有风暴云。然而，当你面对现实生活中的并发编程时，那些云彩就在那里，你会看到雷声和闪电，如果你没有经验，你会大惊小怪的。

现实生活中的问题往往规模不理想。我们已经访问了一个扩展性很好的示例，尽管它不是理想的快速排序。这一次，我们将为更接近现实问题的问题开发一个并行算法。在`N`个处理器上解算 Mastermind 游戏不会使解算速度提高`N`倍，而且代码也不平凡。这个例子将向您展示现实生活中的问题是什么样子的，尽管它不会教您所有可能的问题，但是当您在商业环境中第一次看到其中一个问题时，您不会感到震惊。

这个解决方案中最重要的类之一是`IntervalGuesser`。这是影响创建猜测的类。它在开始猜测和结束猜测之间创建猜测，并将它们发送到`BlockingQueue`。类实现了`Runnable`，因此可以在单独的`Thread`中运行。纯粹主义的实现将`Runnable`功能与区间猜测分开，但是，由于整个类几乎不超过 50 行，在单个类中实现这两个功能是可以原谅的错误：

```java
public class IntervalGuesser extends UniqueGuesser implements Runnable {
    private final Guess start;

    private final Guess end;
    private Guess lastGuess;
    private final BlockingQueue<Guess> guessQueue;

    public IntervalGuesser(Table table,
                           Guess start,
                           Guess end,
                           BlockingQueue<Guess> guessQueue) {
        super(table);
        this.start = start;
        this.end = end;
        this.lastGuess = start;
        this.guessQueue = guessQueue;
        nextGuess = start;
    }

    @Override
    public void run() {
        Thread.currentThread()
            .setName("guesser [" + start + "," + end + "]");
        var guess = guess();
        try {
            while (guess != Guess.none) {
                guessQueue.put(guess);
                guess = guess();
            }
        } catch (InterruptedException ignored) {
        }
    }

    @Override
    protected Guess nextGuess() {
        var guess = super.nextGuess();
        if (guess.equals(end)) {
            guess = Guess.none;
        }
        lastGuess = guess;
        return guess;
    }

    public String toString() {
        return "[" + start + "," + end + "]";
    }
}
```

实现非常简单，因为大多数功能已经在抽象的`Guesser`类中实现了。更有趣的代码是调用`IntervalGuesser`的代码。

# `ParallelGamePlayer`

`ParallelGamePlayer`类实现定义`play`方法的`Player`接口：

```java
@Override
public void play() {
    final var table = new Table(NR_COLUMNS, colorManager);
    final var secret = new RandomSecret(colorManager);
    final var secretGuess = secret.createSecret(NR_COLUMNS);
    final var game = new Game(table, secretGuess);
    final var guessers = createGuessers(table);
    final var finalCheckGuesser = new UniqueGuesser(table);
    startAsynchronousGuessers(guessers);
    try {
        while (!game.isFinished()) {
            final var guess = guessQueue.take();
            if (finalCheckGuesser.guessMatch(guess)) {
                game.addNewGuess(guess);
            }
        }
    } catch (InterruptedException ie) {

    } finally {
        stopAsynchronousGuessers(guessers);
    }
}
```

此方法创建一个`Table`、一个以随机方式创建用作秘密的猜测的`RandomSecret`、一个`Game`对象、`IntervalGuesser`对象和一个`UniqueGuesser`。

`IntervalGuesser`对象是官僚；`UniqueGuesser`对象是老板，他交叉检查`IntervalGuesser`对象产生的猜测。我们用一个单独的方法创建区间猜测器，`createGuessers()`：

```java
private IntervalGuesser[] createGuessers(Table table) {
    final var colors = new Color[NR_COLUMNS];
    var start = firstIntervalStart(colors);
    final IntervalGuesser[] guessers = new IntervalGuesser[nrThreads];
    for (int i = 0; i < nrThreads - 1; i++) {
        Guess end = nextIntervalStart(colors);
        guessers[i] = new IntervalGuesser(table, start, end, guessQueue);
        start = end;
    }
    guessers[nrThreads - 1] = new IntervalGuesser(table, start, Guess.none, guessQueue);
    return guessers;
}

private Guess firstIntervalStart(Color[] colors) {
    for (int i = 0; i < colors.length; i++) {
        colors[i] = colorManager.firstColor();
    }
    return new Guess(colors);
}

private Guess nextIntervalStart(Color[] colors) {
    final int index = colors.length - 1;
    int step = NR_COLORS / nrThreads;
    if (step == 0) {
        step = 1;
    }
    while (step > 0) {
        if (colorManager.thereIsNextColor(colors[index])) {
            colors[index] = colorManager.nextColor(colors[index]);
            step--;
        } else {
            return Guess.none;
        }
    }
    Guess guess = new Guess(colors);
    while (!guess.isUnique()) {
        guess = guess.nextGuess(colorManager);
    }
    return guess;
}
```

间隔猜测器的创建方式是，每种颜色都有其独特的颜色变化范围，因此，它们一起涵盖了所有可能的颜色猜测。`firstIntervalStart()`方法返回在所有位置包含*第一个*颜色的猜测。`nextIntervalStart()`方法返回开始下一个范围的颜色集，推进颜色，以便每个猜测者在结束时有相同数量的猜测要检查（加或减一）。

`startAsynchronousGuessers()`方法启动异步猜测器，然后从它们那里读取循环中的猜测，如果它们正常的话，就把它们放在桌子上，直到游戏结束。在方法的末尾，在`finally`块中，异步猜测器停止。

异步猜测器的启动和停止方法采用`ExecutorService`：

```java
private void startAsynchronousGuessers(IntervalGuesser[] guessers) {
    executorService = Executors.newFixedThreadPool(nrThreads);
    for (IntervalGuesser guesser : guessers) {
        executorService.execute(guesser);
    }
}

private void stopAsynchronousGuessers(IntervalGuesser[] guessers) {
    executorService.shutdown();
    guessQueue.drainTo(new LinkedList<>());
}
```

代码非常简单。唯一需要解释的是`drainTo()`电话。这个方法将工作线程仍然拥有的未使用的猜测排出到一个我们立即丢弃的链表中（我们不保留对它的任何引用）。这是必要的，以帮助任何`IntervalGuesser`，这可能是等待与建议猜测在手，试图把它放入队列。当我们排空队列时，猜测线程从`IntervalGuesser`中`guessQueue.put(guess);`行的`put()`方法返回，并可以捕获中断。代码的其余部分不包含任何与我们已经看到的完全不同的内容。

在本章中，我们仍然要讨论的最后一个问题是，通过使代码并行，我们获得了多少时间？

# 微基准

微基准是衡量一个小代码片段的性能。当我们想要优化我们的代码时，我们必须对它进行度量。没有度量，代码优化就像蒙着眼睛射击。你不会击中目标，但很可能会射杀其他人。

射击是一个很好的比喻，因为你通常不应该这样做，但当你真的必须这样做，那么你就别无选择。如果没有性能问题，并且软件满足要求，那么任何优化，包括速度测量，都是浪费金钱。这并不意味着鼓励您编写慢而草率的代码。当我们衡量性能时，我们会将其与需求进行比较，而需求通常在用户级别，类似于“应用的响应时间应该少于 2 秒”。为了进行这样的度量，我们通常在一个测试环境中创建负载测试，并使用不同的分析工具，以防度量的性能不令人满意，这些工具告诉我们什么是最耗时的，以及我们应该在哪里进行优化。很多时候，不仅仅是 Java 代码，还有配置优化，使用更大的数据库连接池、更多的内存等等。

微基准是另一回事。它是关于一个小的 Java 代码片段的性能，因此更接近于 Java 编程。

它很少使用，在开始为实际商业环境执行微基准之前，我们必须三思而后行。MicroBenchmark 是一个诱人的工具，可以在不知道是否值得优化代码的情况下优化一些小东西。当我们有一个在多个服务器上运行多个模块的大型应用时，我们如何确保改进应用的某个特殊部分能够显著提高性能？它是否会回报增加的收入，产生如此多的利润，以弥补性能测试和开发中产生的成本？从统计学上讲，你几乎可以肯定，这样的优化，包括微基准，不会有回报。

我曾经维护过一位资深同事的密码。他创建了一个高度优化的代码来识别文件中存在的配置关键字。他创建了一个程序结构，它表示基于键字符串中的字符的决策树。如果配置文件中有一个关键字拼写错误，代码会在第一个字符处抛出异常，从而确定关键字不正确。要插入一个新的关键字，它需要通过代码结构来找到新关键字最初与已有关键字不同的地方，并扩展深度嵌套的`if/else`结构。阅读关键字列表处理是可能的，从注释中列出了所有的关键字，他没有忘记文件。代码运行速度惊人，可能节省了 Servlet 应用几毫秒的启动时间。应用仅在每隔几天进行一次系统维护之后才启动几个月。你呢感受一下讽刺吧？资历并不总是年数。那些更幸运的人可以拯救他们内心的孩子。

那么，什么时候应该使用微基准呢？我可以看到两个方面：

*   您已经确定了消耗应用中大部分资源的代码段，可以通过微基准测试改进
*   您无法识别将消耗应用中大部分资源的代码段，但您可能会怀疑它

第一种是通常情况。第二种情况是，当您开发一个库时，您并不知道将使用它的所有应用。在这种情况下，您将尝试优化您认为对大多数想象中的可疑应用最关键的部分。即使在这种情况下，最好还是采集一些由库用户创建的示例应用，并收集一些有关使用情况的统计信息。

为什么我们要详细讨论微基准？陷阱是什么？基准测试是一个实验。我写的第一个程序是一个 TI 计算器代码，我只需计算程序将两个大素数（当时 10 位是大素数）分解的步数。即使在那个时候，我也在用一块老式的俄罗斯机械秒表测量时间，懒得计算步数。实验和测量更容易。

现在，即使您想手动计算 CPU 的步数，也无法手动计算。有太多的小因素可能会改变程序员无法控制的应用的性能，这使得计算步骤变得不可能。我们还有度量，我们将获得与度量相关的所有问题。

最大的问题是什么？我们对某物感兴趣，比如说`X`，我们通常无法测量它。因此，我们将测量`Y`，并希望`Y`和`X`的值耦合在一起。我们想测量房间的长度，但我们测量的是激光束从一端传输到另一端所需的时间。在这种情况下，长度，`X`和时间，`Y`是强耦合的。很多时候，`X`和`Y`只是或多或少的相关。大多数情况下，当一个人进行测量时，`X`和`Y`值根本没有关系。尽管如此，人们还是把自己的房子，甚至更多的钱，押在有这些衡量标准支持的决策上。

微基准也不例外。第一个问题是，我们如何衡量执行时间？小代码运行的时间很短，`System.currentTimeMillis()`可能只是在测量开始和结束时返回相同的值，因为我们仍然在同一毫秒内。即使执行时间为 10ms，测量误差仍至少为 10%，这纯粹是因为我们测量的时间被量化了。幸运的是，有`System.nanoTime()`。但是有吗？仅仅因为它的名字说它从一个特定的开始时间返回纳秒数并不一定意味着它真的可以。

这在很大程度上取决于硬件和方法在 JDK 中的实现。它被称为纳米，因为这是我们无法达到的精度。如果是微秒，那么一些实现可能会受到定义的限制，即使在特定的硬件上有更精确的时钟。然而，这不仅关系到可用硬件时钟的精度水平，还关系到硬件的精度。

让我们记住官僚们的心跳，以及从记忆中读东西所需要的时间。打电话给一个方法，比如`System.nanoTime(),`，就像让酒店的行李员从二楼跑到大堂，往外看一眼路对面塔楼上的钟，回来，准确地告诉我们询问的时间。胡说。我们应该知道塔台上的钟的精确度，以及行李员从地板到大堂和大厅的速度。这不仅仅是打电话给`System.nanoTime()`。这就是微型标记装置为我们所做的。

**Java 微基准线束**（**JMH**）作为库提供了一段时间。它是由 Oracle 开发的，用于调整几个核心 JDK 类的性能。这对那些为新硬件开发 Java 平台的人来说是个好消息，但对开发人员来说也是个好消息，因为这意味着 JMH 现在和将来都会受到 Oracle 的支持。

“JMH 是一个 Java 工具，用于构建、运行和分析以 Java 编写的 nano/micro/mili/macro 基准，以及其他针对 JVM 的语言。”

（引自 [JMH 官方网站](http://openjdk.java.net/projects/code-tools/jmh/)）。

您可以独立于您测量的实际项目作为单独的项目运行`jmh`，或者您可以将测量代码存储在单独的目录中。线束将根据生产类文件编译，并将执行基准。我看到的最简单的方法是使用 Gradle 插件来执行 JMH。可以将基准代码存储在一个名为`jmh`（与`main`和`test`相同级别）的目录中，创建一个可以启动基准的`main`类。

Gradle 构建脚本已扩展为包含以下行：

```java
buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath "me.champeau.gradle:jmh-gradle-plugin:0.2.0"
    }
}
apply plugin: "me.champeau.gradle.jmh"

jmh {
    jmhVersion = '1.13'
    includeTests = true
}
```

`MicroBenchmark`类如下：

```java
public class MicroBenchmark {

    public static void main(String... args)
        throws RunnerException {
        var opt = new OptionsBuilder()
            .include(MicroBenchmark.class.getSimpleName())
            .forks(1)
            .build();

        new Runner(opt).run();
    }

    @Benchmark
    @Fork(1)
    public void playParallel(ThreadsAndQueueSizes t3qs) {
        int nrThreads = Integer.valueOf(t3qs.nrThreads);
        int queueSize = Integer.valueOf(t3qs.queueSize);
        new ParallelGamePlayer(nrThreads, queueSize).play();
    }

    @Benchmark
    @Fork(1)
    public void playSimple() {
        new SimpleGamePlayer().play();
    }

    @State(Scope.Benchmark)
    public static class ThreadsAndQueueSizes {
        @Param(value = {"1", "4", "8"})
        String nrThreads;
        @Param(value = {"-1", "1", "10", "100", "1000000"})
        String queueSize;
    }
}
```

创建`ParallelGamePlayer`是为了用 -1、1、4 和 8`IntervalGuesser`线程玩游戏，在每种情况下，都有一个测试运行，队列长度分别为 1、10、100 和 100 万。这是 16 个测试执行。当线程数为负数时，构造器使用`LinkedBlockingDeque`。还有另一个单独的测量方法来测量非并行玩家。测试是用独特的猜测和秘密（没有颜色使用超过一次）、十种颜色和六列来执行的。

当线束启动时，它会自动执行所有校准，并运行多次迭代的测试，以让 JVM 启动。您可能会想起从未停止过的代码，除非我们对用于向代码发出停止信号的变量使用了`volatile`修饰符。这是因为 JIT 编译器优化了代码。只有当代码已经运行了几千次时，才会这样做。线束执行这些执行是为了预热代码，并确保在 JVM 已经全速运行时完成测量。

在我的机器上运行这个基准测试大约需要 15 分钟。在执行过程中，建议停止所有其他进程，并让基准使用所有可用资源。如果在测量过程中有任何使用资源的情况，则会反映在结果中：

```java
Benchmark      (nrThreads) (queueSize)  Score    Error
playParallel            1         -1   15,636  ± 1,905
playParallel            1          1   15,316  ± 1,237
playParallel            1         10   15,425  ± 1,673
playParallel            1        100   16,580  ± 1,133
playParallel            1    1000000   15,035  ± 1,148
playParallel            4         -1   25,945  ± 0,939
playParallel            4          1   25,559  ± 1,250
playParallel            4         10   25,034  ± 1,414
playParallel            4        100   24,971  ± 1,010
playParallel            4    1000000   20,584  ± 0,655
playParallel            8         -1   24,713  ± 0,687
playParallel            8          1   24,265  ± 1,022
playParallel            8         10   24,475  ± 1,137
playParallel            8        100   24,514  ± 0,836
playParallel            8    1000000   16,595  ± 0,739
playSimple            N/A       N/A   18,613   ± 2,040
```

程序的实际输出要详细一些；它是为了打印而编辑的。`Score`列显示了基准测试在一秒钟内可以运行多少次。`Error`列显示测量值的散射小于 10%。

我们拥有的最快性能是算法在 8 个线程上运行时，这是处理器在我的机器上可以独立处理的线程数。有趣的是，限制队列的大小并没有提高性能。我真的以为会不一样。使用一个一百万长度的数组作为阻塞队列有着巨大的开销，在这种情况下，执行速度比队列中只有 100 个元素时要慢也就不足为奇了。另一方面，具有无限链接的基于列表的队列处理速度相当快，并且清楚地表明，对于 100 个元素的有限队列，额外的速度并不是因为限制防止了`IntervalThreads`跑得太远。

当我们启动一个线程时，我们期望得到与运行串行算法时类似的结果。串行算法胜过在一个线程上运行的并行算法这一事实并不奇怪。线程的创建以及主线程和额外的单线程之间的通信都有开销。开销很大，特别是当队列不必要的大时。

# 总结

在这一章中，我们学到了很多东西。首先，我们重构了代码，为使用并行猜测的进一步开发做好准备。我们熟悉了进程和线程，甚至还提到了纤程。之后，我们研究了 Java 如何实现线程以及如何创建在多个线程上运行的代码。此外，我们还看到了 Java 为需要并行程序、启动线程或只是在现有线程中启动任务的程序员提供的不同方法。

也许这一章最重要的部分你应该记住的是官僚和不同速度的隐喻。当您想了解并发应用的性能时，这一点非常重要。我希望这是一幅引人入胜的图画，一幅容易记住的图画。

关于 Java 提供的不同同步方式有一个很大的话题，您还了解了程序员在编写并发应用时可能遇到的陷阱。

最后，但并非最不重要的是，我们创建了 Mastermind 猜测器的并发版本，并且还测量了它确实比只使用一个处理器的版本（至少在我的机器上）要快。我们在 Gradle 构建工具中使用了 JavaMicroBenchmark 工具，并讨论了如何执行微基准。

这是一个漫长的章节，并不容易。我可能倾向于认为这是最复杂和理论的一章。如果你一开始就理解了一半，你会感到骄傲的。另一方面，请注意，这仅仅是一个坚实的基础，可以从中开始试验并发编程，在被公认为该领域的经验丰富和专业人士之前，还有很长的路要走。而且，这一章也不容易。但是，首先，在这一章的结尾，要为自己感到骄傲。

在接下来的章节中，我们将学习更多关于 Web 和 Web 编程的知识。在下一章中，我们将开发我们的小游戏，这样它就可以在服务器上运行，玩家可以使用 Web 浏览器玩它。这将为网络编程奠定基础知识。稍后，我们将在此基础上开发基于 Web 的服务应用、反应式编程，以及使您成为专业 Java 开发人员的所有工具和领域。

# 六、使我们的游戏专业化-将其作为 Web 应用

在本章中，我们将编写一个 Web 应用。我们将建立在我们已经取得的成就和创造一个网络版的策划游戏。这一次，它不仅会单独运行，猜测并回答位置的个数和匹配的颜色，还会与用户进行交流，询问猜测的答案。这将是一个真正的游戏，你可以玩。Web 编程对于 Java 开发人员来说非常重要。大多数程序都是 Web 应用。互联网上可用的通用客户端是 Web 浏览器。瘦客户端、基于 Web 浏览器的架构也被企业广泛接受。当架构与 Web 客户端不同时，只有少数例外。如果你想成为一名专业的 Java 开发人员，你必须熟悉 Web 编程。而且也很有趣！

在开发过程中，我们将访问许多技术主题。首先，我们将讨论网络和 Web 架构。这是整栋楼的混凝土底座。它不是太性感，就像你建造一座建筑物。你花了很多钱和精力挖壕沟，然后你埋了混凝土，最后，在这个阶段结束时，你似乎有平坦的地面之前，除了有基础。如果没有这个基础，房子可能会在建造后不久或建造过程中倒塌。网络对于网络编程同样重要。有很多话题似乎与编程无关。尽管如此，它仍然是构建的基础，当您编写 Web 应用时，您还将发现它的有趣之处。

我们还将讨论一些 HTML、CSS 和 JavaScript，但不会太多。我们无法避免它们，因为它们对 Web 编程也很重要，但它们也是您可以从其他地方学习的主题。如果您不是这些领域的专家，那么企业项目团队中通常还有其他专家可以扩展您的知识。除此之外，JavaScript 是一个如此复杂和庞大的主题，它值得一本完整的书作为开始。只有极少数的专家对 Java 和 JavaScript 都有深刻的理解。我了解该语言的总体结构和运行环境，但我无法跟上这些天每周发布的新框架，就像我关注其他领域一样。

您将学习如何创建在应用服务器上运行的 Java 应用，这次是在 Jetty 中，我们将看到 Servlet 是什么。为了快速启动，我们将创建一个 HelloWorld Web 应用。然后，我们将创建 Mastermind 的 Servlet 版本。请注意，如果没有一个框架的帮助，我们几乎不会直接编写 Servlet，这个框架实现了处理参数、认证和许多其他非特定于应用的事情的代码。在本章中，我们仍将坚持使用裸 Servlet，因为如果不首先了解 Servlet 是什么，就不可能有效地使用 Spring 之类的框架。要成为一名工程师，你必须先把手弄脏。Spring 将在下一章到来。

我们将提到 **JavaServer Pages**（**JSP**），只是因为您可能会遇到一些遗留应用，这些应用是使用该技术开发的，但是现代 Web 应用不使用 JSP。尽管如此，JSP 还是 Servlet 标准的一部分，可以使用。还有其他一些技术是在最近的过去发展起来的，但现在似乎还不能证明未来。它们仍然可用，但只出现在遗留应用中，选择它们用于新项目是相当值得怀疑的。我们将在单独的一节中讨论这些技术。

在本章结束时，您将了解基本的 Web 技术是如何工作的以及主要的架构元素是什么，并且您将能够创建简单的 Web 应用。这还不足以成为一名专业的 Java Web 开发人员，但将为下一章打下良好的基础，在下一章中，我们将了解当今企业中用于实际应用开发的专业框架。

# Web 和网络

程序在计算机上运行，计算机连接到互联网。这个网络是在过去的 60 年里发展起来的，最初是为了提供能够抵御火箭攻击的军事数据通信，后来被扩展为学术网络，后来成为任何人都可以使用的商业网络，几乎遍布世界各地。

该网络的设计和研究始于 60 年代加加林绕地球运行的反应。把加加林送上太空并环绕地球运行，证明了俄罗斯可以在全球任何地方发射火箭，可能带有原子弹爆炸物。这意味着任何需要中央控制的数据网络都无法抵御这种攻击。将中心位置作为单一故障点的网络是不可行的。因此，人们开始研究建立一个网络，即使网络的任何一部分被关闭，也能继续运行。

# IP

网络在连接到它的任何两台计算机之间传送数据包。网络上使用的协议是 IP，它只是互联网协议的缩写。使用 IP，一台计算机可以向另一台计算机发送数据包。包包含一个头和数据内容。标头包含发件人和目标计算机的互联网地址、其他标志以及有关包的信息。由于机器之间没有直接连接，路由器转发数据包。这就像邮局互相寄信，直到他们交到你认识的邮递员手里，邮递员可以直接把信送到你的邮箱。为此，路由器使用标头中的信息。路由器如何交互的算法和组织是复杂的，我们不需要知道一些东西，就可以成为 Java 专业人士。

如果您需要编程才能直接发送 IP 包，则应查看`java.net.DatagramPacket`，因为其余的都是在 JDK、操作系统和网卡固件中实现的。您可以创建数据包；发送数据包并更改网卡上的调制电压或向纤程发射光子不是您关心的问题。

IP 目前有两个版本。仍在使用的旧版本是 IPv4。与旧版本共存的新版本是 IPv6，即 IPng（*ng* 代表*新一代*）。Java 开发人员可能关心的主要区别是版本 4 使用 32 位地址，版本 6 使用 128 位地址。当您看到版本 4 的地址时，您将看到类似于`192.168.1.110`的内容，其中包含由点分隔的十进制格式的四个字节。IPv6 地址表示为`2001:db8:0:0:0:0:2:1`，八个 16 位数字以十六进制表示，用冒号分隔。

网络比发送数据包要复杂一些。如果发送数据包类似于发送一页的信件，那么网页下载就像在纸上邮件中讨论合同。在合同签订之前，在最初的纸质邮件中应该有一个关于发送什么、回复什么等的协议。在互联网上，该协议被称为**传输控制协议**（**TCP**）。虽然作为一名 Java 开发人员，您很可能会遇到 IP 路由问题，但您肯定会面临 TCP 编程。因此，我们将简要介绍 TCP 的工作原理。请注意，这是非常简短的。真正地。在阅读下一节内容时，您不会成为 TCP 专家，但您将看到影响 Web 编程的最重要问题。

# TCP/IP 协议

TCP 协议是在操作系统中实现的，它提供了比 IP 更高级别的接口。编写 TCP 时，不处理数据报。相反，您有一个字节流通道，您可以将要传递到另一台计算机的字节放入其中，并且可以从另一台计算机发送的通道中读取字节，完全按照它们发送的顺序。这是两台计算机之间的连接，更重要的是，两个程序之间的连接。

还有其他协议是通过 IP 实现的，并且不是面向连接的。其中一个是**用户数据报协议**（**UDP**）。当不需要连接时，它用于服务。它还用于数据可能丢失时，并且数据及时到达目的地比不丢失任何数据包（视频流、电话）更重要。该协议的另一个应用是当数据量较小且丢失时可以再次请求；再次请求的成本比使用更复杂的 TCP 协议要便宜。最后一种使用的典型示例是 DNS 请求，我们将在下一节中详细介绍。

在操作系统中实现的 TCP 软件层处理复杂的数据包处理。重新发送丢失的包、重新排序以不同于最初预期的顺序到达的包，以及删除可能多次到达的额外包，都是由该层自动补全的。这一层通常被称为 **TCP 栈**。

由于 TCP 是一个连接协议，所以需要告诉 TCP 栈当数据报到达时属于哪个流。流由两个端口标识。端口是 16 位整数。一个程序标识启动连接的程序，称为源端口。另一个程序标识目标程序目标端口。这些包含在每个和每个传输的 TCP 包中。当机器运行**安全外壳**（**SSH**）服务器和 Web 服务器时，这些应用使用不同的端口。这些端口通常为`22`和`80`。当 TCP 头中包含目标端口号`22`的包出现时，TCP 栈知道数据包中的数据属于 SSH 服务器处理的流。同样，如果目标端口为`80`，则数据将被发送到 Web 服务器。

在编写服务器程序时，通常必须定义端口号；否则，客户端将找不到服务器程序。Web 服务器通常监听端口`80`，客户端尝试连接到该端口。客户端端口通常不重要，也不指定；它由 TCP 栈自动分配。

从客户端代码连接到服务器很容易，这只需要几行代码。有时，它只是一行代码。然而，在后台，TCP 栈做了很多我们应该关心的工作，因为建立 TCP 连接需要时间，而且它会极大地影响应用的性能。

为了建立连接，TCP 栈向目的地发送一个数据报。这还不足以建立连接，但这是建立连接的第一步。这个包是空的，它的名字是 SYN。发送此数据包后，客户端开始等待服务器应答。如果没有服务器，或者服务器太忙而无法应答，或者由于任何原因无法向该特定客户端提供应答，那么发送任何进一步的包都将是网络流量浪费。

当服务器接收到 SYN 包时，它会用 SYN-ACK 包进行回复。最后，在接收到 SYN-ACK 包之后，客户端发送一个名为 ACK 的包。如果数据包通过大西洋，每个数据包大约需要 45 毫秒，相当于 4500 万秒的官僚时间。这差不多是一年半了。我们需要其中三个来建立连接，这只是连接的建立；到目前为止，我们还没有发送任何数据。

当建立 TCP 连接时，客户端不会在没有自我控制的情况下开始发送数据。它只发送几个包，然后等待查看发生了什么。如果包到达并且服务器承认这些包，则发送更多，一旦看到连接和服务器能够接受更大的包量，则会增加此卷。发送服务器未准备好、无法处理的数据，不仅无用，而且会浪费网络资源。TCP 是为了优化网络使用率而设计的。客户端发送一些数据，然后等待确认。TCP 栈自动管理此操作。如果确认到达，它会发送更多的数据包。如果精心设计的优化算法，在 TCP 栈中实现，认为发送更多是好的，那么它发送的数据比第一步多一些。如果有负面的确认告诉客户端服务器无法接受某些数据，并且必须将其丢弃，那么客户端将减少它在没有确认的情况下发送的数据包数。但首先，它开始缓慢谨慎。

这就是所谓的 TCP 慢启动，我们必须意识到这一点。尽管这是一个低级的网络特性，但它会产生一些后果，我们必须在 Java 代码中考虑到这一点：我们使用数据库连接池，而不是在每次需要一些数据时创建到数据库的新连接；我们尝试尽可能少地连接到 Web 服务器，使用 *keep-alive*、*SPDY* 协议或 *http/2* 等技术（也代替 SPDY）。

就目前而言，TCP 是面向连接的，即建立到服务器的连接，发送和接收字节，最后关闭连接就足够了。当您遇到网络性能问题时，您必须查看我之前详述的问题（并询问网络专家）。

# DNS

TCP 协议使用机器的 IP 地址创建一个通道。在浏览器中键入 URL 时，它通常不包含 IP 号码。它包含机器名。使用名为**域名系统**（**DNS**）的分布式数据库将名称转换为 IP 号码。这个数据库是分布式的，当一个程序需要将一个名称转换成一个地址时，它会将一个 DNS 请求发送到它所知道的一个 DNS 服务器。这些服务器相互发送查询，或者告诉客户端询问谁，直到客户端知道分配给该名称的 IP 地址。服务器和客户端还缓存最近请求的名称，因此应答很快。另一方面，当服务器的 IP 地址更改这个名称时，并不是所有的客户端都能立即在全球范围内看到地址分配。DNS 查找可以很容易地编程，JDK 中有一些类和方法支持这一点，但是通常，我们不需要担心这一点；当我们编程时，它是在 Web 编程中自动补全的。

# HTTP 协议

**超文本传输协议**（**HTTP**）建立在 TCP 之上。在浏览器中键入 URL 时，浏览器会打开一个到服务器的 TCP 通道（当然，在 DNS 查找之后），并向 Web 服务器发送一个 HTTP 请求。服务器在接收到请求后，生成一个响应并将其发送给客户端。之后，TCP 通道可能会被关闭或保持活动状态，以供进一步的 HTTP 请求-响应对使用。

请求和响应都包含头和可选（可能为零长度）正文。标题采用文本格式，并用空行与正文分开。

更准确地说，头部和主体由四个字节分隔-`0x0D`、`0x0A`、`0x0D`和`0x0A`，这是两个`CR`、`LF`行分隔符。HTTP 协议使用回车符和换行符来终止标头中的行，因此，一个空行是两个`CRLF`紧随其后。

标题的开头是一个状态行加上标题字段。以下是 HTTP 请求示例：

```java
GET /html/rfc7230 HTTP/1.1
Host: tools.ietf.org
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
DNT: 1
Referer: https://en.wikipedia.org/
Accept-Encoding: gzip, deflate, sdch, br
Accept-Language: en,hu;q=0.8,en-US;q=0.6,de;q=0.4,en-GB;q=0.2
```

这就是答案：

```java
HTTP/1.1 200 OK
Date: Tue, 04 Oct 2016 13:06:51 GMT
Server: Apache/2.2.22 (Debian)
Content-Location: rfc7230.html
Vary: negotiate,Accept-Encoding
TCN: choice
Last-Modified: Sun, 02 Oct 2016 07:11:54 GMT
ETag: "225d69b-418c0-53ddc8ad0a7b4;53e09bba89b1f"
Accept-Ranges: bytes
Cache-Control: max-age=604800
Expires: Tue, 11 Oct 2016 13:06:51 GMT
Content-Encoding: gzip
Strict-Transport-Security: max-age=3600
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  xml:lang="en" lang="en">
<head profile="http://dublincore.org/documents/2008/08/04/dc-html/">
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="robots" content="index,follow" />
```

请求不包含正文。状态行如下：

```java
GET /html/rfc7230 HTTP/1.1
```

它包含所谓的请求方法、请求的对象以及请求使用的协议版本。标头请求的其余部分包含格式为`label: value`的标头字段。有些行被包装在印刷版本中，但是在标题行中没有换行符。

响应指定它使用的协议（通常与请求相同）、状态代码和状态的消息格式：

```java
HTTP/1.1 200 OK
```

之后，响应头字段的语法与请求中的相同。一个重要的标题字段是内容类型：

```java
Content-Type: text/html; charset=UTF-8
```

它指定响应体（在打印输出中截断）是 HTML 文本。

实际请求发送到[这个页面](https://tools.ietf.org/html/rfc7230)，定义 HTTP 1.1 版本的标准。您可以自己轻松地查看通信，启动浏览器并打开开发人员工具。现在每个浏览器都内置了这样的工具。通过查看字节级别上的实际 HTTP 请求和响应，可以使用它在网络应用级别上调试程序行为。以下屏幕截图显示了开发人员工具如何显示此通信：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/cb519a47-a096-4844-a57b-ec20d735e182.png)

# HTTP 方法

作为请求状态行中第一个单词的方法告诉服务器如何处理请求。本标准定义了不同的方法，如`GET`、`HEAD`、`POST`、`PUT`、`DELETE`等。

当客户端想要获取资源的内容时，它使用`GET`方法。在`GET`请求的情况下，请求的主体是空的。这是我们下载网页时浏览器使用的方法。当 JavaScript 程序想从服务器获取一些信息，但又不想向服务器发送太多信息时，会多次使用这种方法。

当客户端使用`POST`时，目的通常是向服务器发送数据。服务器回复，而且通常在回复中还有一个主体。但是，请求/应答通信的主要目的是将信息从客户端发送到服务器。这在某种程度上与`GET`方法相反。

`GET`和`POST`方法是最常用的方法。虽然使用`GET`检索数据和`POST`向服务器发送数据有一个通用的指导原则，但这只是一个建议，并没有将这两种情况完全分开。很多时候，`GET`被用来向服务器发送数据。毕竟，它是一个带有状态行和头字段的 HTTP 请求，尽管请求中没有正文，但是状态行中方法后面的对象（URL 的一部分）仍然能够传递参数。通常，测试响应`GET`请求的服务也很容易，因为您只需要浏览器键入带有参数的 URL，然后在浏览器开发工具中查看响应。

如果您看到一个应用使用`GET`请求来执行修改 Web 服务器状态的操作，您应该不会感到惊讶。然而，不感到惊讶并不意味着赞同。你应该知道，在大多数情况下，这些都不是好的做法。当我们使用`GET`请求发送敏感信息时，URL 中的参数在浏览器的地址行中对客户端可用。当我们使用`POST`发送时，客户端仍然可以访问参数（毕竟，客户端发送的信息是由客户端生成的，因此不能不可用），但是对于一个简单的不知道安全性的用户来说，复制和粘贴信息然后转发给恶意的第三方并不是那么容易。使用`GET`和`POST`之间的决定应始终考虑实用性和安全性问题。

`HEAD`方法与`GET`请求相同，但响应不包含正文。当客户端对实际响应不感兴趣时，使用此选项。可能发生的情况是，客户端已经拥有该对象，并希望查看该对象是否已更改。`Last-Modified`头将包含上次更改资源的时间，客户端可以决定是否有更新的资源或需要在新请求中请求资源。

当客户端想要在服务器上存储某些内容时，使用`PUT`方法；当客户端想要擦除某些资源时，使用`DELETE`方法。这些方法仅由通常用 JavaScript 编写的应用使用，而不是由浏览器直接使用。

标准中还定义了其他方法，但这些方法是最重要和最常用的方法。

# 状态代码

响应以状态代码开始。还定义了这些代码，并且在响应中可用的代码数量有限。最重要的是`200`，表示一切正常；响应包含请求所需的内容。代码总是在`100`到`599`之间，包含三位数字。它们按照第一个数字分组如下：

*   `1xx`：这些代码是信息代码。它们很少使用，但在某些情况下非常重要。例如，`100`表示继续。当一个服务器收到一个`POST`请求时，它可以发送这个代码，并且服务器想要向客户端发送请求的主体，因为它可以处理它。如果在服务器和客户端上正确实现，那么使用此代码并等待此代码的客户端可以节省大量带宽。
*   `2xx`：这些代码意味着成功。请求得到正确响应，或者请求的服务已实现。标准中定义了`200`、`201`、`202`等代码，并对何时使用其中一种进行了说明。
*   `3xx`：这些代码表示重定向。当服务器不能直接为请求提供服务，但知道可以提供服务的 URL 时，会发送其中一个代码。实际的代码可以区分永久重定向（当知道所有将来的请求都应该发送到新的 URL 时）和临时重定向（当任何以后的请求都应该发送到这里并且可能被服务或重定向时），但是决定权在服务器端。
*   `4xx`：这些是错误代码。最著名的代码是`404`，意思是找不到，也就是说服务器因为找不到资源而无法响应请求。`401`表示服务于请求的资源可能是可用的，但它需要认证。`403`表示请求有效，但仍被服务器拒绝的代码。
*   `5xx`：这些代码是服务器错误代码。当响应包含这些错误代码中的一个时，意味着服务器上存在错误。此错误可能是暂时的，例如，当服务器正在处理太多的请求，并且无法以计算密集型响应响应（这通常由错误代码`503`发出信号）响应新请求时，或者当功能未实现时（代码`501`）。一般错误代码`500`被解释为内部错误，这意味着没有任何关于服务器上发生了什么错误的信息，但是它运行得不好，因此没有任何有意义的响应。

# HTTP/2 协议

自上次发布 HTTP 以来，经过近 20 年的时间，最新版本的 HTTP 于 2015 年发布。这个新版本的协议与以前的版本相比有一些增强。其中一些增强也会影响服务器应用的开发方式。

第一个也是最重要的增强是，新协议将使在单个 TCP 连接中并行发送多个资源成为可能。`Keep-Alive`标志已经可以用来避免重新创建 TCP 通道，但是当响应创建缓慢时，它没有帮助。在新协议中，其他资源也可以在同一个 TCP 通道中传递，甚至在请求得到完全服务之前。这需要协议中复杂的包处理。这对服务器程序员和浏览器程序员都是隐藏的。应用服务器、Servlet 容器和浏览器透明地实现了这一点。

HTTP/2 将始终加密。因此，在浏览器 URL 中不可能使用`http`作为协议。永远是`https`。

需要更改 Servlet 编程以利用新版本协议的优势的特性是服务器推送。Servlet 规范的 4.0 版本包括对 HTTP/2 的支持。规范可从[这个页面](https://javaee.github.io/servlet-spec/downloads/servlet-4.0/servlet-4_0_FINAL.pdf)获得。

服务器推送是对将来将出现的请求的 HTTP 响应。服务器如何回答一个甚至没有发出的请求？好吧，服务器已经预料到了。例如，应用发送一个 HTML 页面，其中引用了许多小图片和图标。客户端下载 HTML 页面，构建 DOM 结构，进行分析，实现所需图片，并发送图片请求。程序员知道那里有什么图片，甚至在浏览器请求图片之前就可以编写代码让服务器发送这些图片。每一个这种性质的响应都包含一个该响应所针对的 URL。当浏览器需要资源时，它会意识到资源已经存在，并且不会发出新的请求。在`HttpServlet`中，程序应该通过请求的新`getPushBuilder()`方法访问`PushBuilder`，并使用该方法将资源下推到客户端。

# Cookie

Cookie 由浏览器维护，并通过使用`Cookie`头字段在 HTTP 请求头中发送。每个 Cookie 都有一个名称、值、域、路径、过期时间和一些其他参数。当请求被发送到与域（未过期 Cookie 的路径）匹配的 URL 时，客户端将 Cookie 发送到服务器。Cookies 通常通过浏览器存储在客户端的小文件中，或者存储在本地数据库中。实际的实现是浏览器的业务，我们不必担心。它只是文本信息，而不是由客户端执行。只有当某些规则（主要是域和路径）匹配时，才会将其发送回服务器。Cookie 由服务器创建，并使用`Set-Cookie`头字段在 HTTP 响应中发送给客户端。因此，本质上，服务器告诉客户端，“嘿，这是 Cookie，下次你来找我时，给我看这段信息，这样我就知道是你了”。Cookies 也可以通过 JavaScript 客户端代码创建。但是，由于 JavaScript 代码也来自服务器，因此这些 Cookie 也可以被视为来自服务器。

Cookies 通常是用来记住客户的。广告商和在线商店需要记住他们在和谁交谈，他们大量使用它。但这不是唯一的用途。现在，任何维护用户会话的应用都使用 Cookie 来链接来自同一用户的 HTTP 请求。当您登录到应用时，用于标识自己的用户名和密码只发送到服务器一次，并且在随后的请求中，只向服务器发送一个特殊的 Cookie 来标识已登录的用户。Cookie 的这种用法强调了为什么使用不容易猜测的 Cookie 值很重要。如果用来识别用户的 Cookie 很容易猜测，那么攻击者就可以创建一个 Cookie 并模仿其他用户将其发送到服务器。为此，Cookie 值通常是长的随机字符串。

Cookie 并不总是发送回它们发源的服务器。发送 Cookie 时，服务器指定应将 Cookie 发送回的 URL 的域。当与提供需要认证的服务的服务器不同的服务器执行用户认证时，将使用此选项。

应用有时将值编码到 Cookie 中。这并不一定是坏的，尽管在大多数实际情况下，它是坏的。在将某些内容编码到 Cookie 中时，我们应该始终考虑 Cookie 在网络中传播的事实。随着越来越多的数据被编码到 Cookie 中，带有编码数据的 Cookie 会变得越来越大。它们会给网络带来不必要的负担。通常，最好只发送一个唯一的、否则没有意义的随机键，并将值存储在数据库中，无论是磁盘上还是内存中。

# 客户端-服务器和 Web 架构

到目前为止，我们开发的应用运行在一个 JVM 上。我们已经有了一些并发编程的经验，这是一些现在会派上用场的东西。当我们编写一个 Web 应用时，一部分代码将在服务器上运行，一部分应用逻辑将在浏览器中执行。服务器部分将用 Java 编写，浏览器部分将用 HTML、CSS 和 JavaScript 实现。因为这是一本 Java 书籍，所以我们将主要关注服务器部分，但是我们仍然应该意识到这样一个事实：许多功能可以而且应该实现为在浏览器中运行。这两个程序通过 IP 网络（即互联网）或公司网络（如果是企业内部应用）相互通信。

如今，浏览器可以执行用 JavaScript 实现的强大应用。新的浏览器版本也支持 WebAssembly。这种技术在具有实时编译器的虚拟机中执行代码，就像 Java 虚拟机一样，因此，代码执行速度与本地应用一样快。在浏览器中运行的图形游戏已经有了展示安装。诸如 C、Rust 和 GO 之类的语言可以编译到 WebAssembly，我们可以预期其他语言也可以使用。这意味着浏览器的编程方法将被取代，越来越多的功能将在客户端应用中实现。这样，应用将变得越来越像传统的旧客户端-服务器应用，区别在于客户端将在浏览器的沙盒中运行，并且通信是 HTTP 协议。

几年前，这种应用需要客户端应用在 Delphi、C++ 或 Java 中实现，使用客户端操作系统的窗口能力。

最初，客户端-服务器架构意味着应用的功能是在客户端上实现的，程序只使用来自服务器的常规服务。服务器提供了数据库访问和文件存储，但仅此而已。后来，三层架构将业务功能放在使用其他服务器进行数据库和其他常规服务的服务器上，客户端应用实现了用户界面和有限的业务功能。

当 Web 技术开始渗透到企业计算时，Web 浏览器开始在许多用例中取代客户端应用。以前，浏览器不能运行复杂的 JavaScript 应用。应用在 Web 服务器上执行，客户端显示服务器创建的 HTML 作为应用逻辑的一部分。每次用户界面上发生更改时，浏览器都会启动与服务器的通信，并且在 HTTP 请求-响应对中，浏览器内容会被替换。Web 应用本质上是一系列表单填充和表单数据发送操作，服务器用 HTML 格式的页面进行响应，可能包含新表单。

JavaScript 解释器得到了发展，变得越来越有效和标准化。如今，现代 Web 应用包含 HTML（这是客户端代码的一部分，不是由服务器动态生成）、CSS 和 JavaScript。当代码从 Web 服务器下载时，JavaScript 开始执行并与服务器通信。它仍然是 HTTP 请求和响应，但是响应不包含 HTML 代码。它包含纯数据，通常是 JSON 格式。这些数据由 JavaScript 代码使用，一些数据（如果需要）显示在 Web 浏览器的显示屏上，也由 JavaScript 控制。这在功能上相当于三层架构，有几个很小但非常重要的区别。

第一个区别是，客户端上没有安装代码。客户端从 Web 服务器下载应用，唯一安装的是现代浏览器。这就消除了许多企业维护负担和成本。

第二个区别是客户端不能访问客户端机器的资源，或者只有有限的访问权限。厚客户端应用可以将任何内容保存在本地文件中或访问本地数据库。对于浏览器应用，出于安全原因，这是非常有限的。同时，这是一个方便的限制，因为客户端不是，也不应该是架构的可信部分。客户端计算机中的磁盘备份成本很高。它可以用笔记本偷走，加密是昂贵的。有一些工具可以保护客户端存储，但大多数情况下，仅将数据存储在服务器上是一种更可行的解决方案。

信任客户端应用也是常见的程序设计错误。客户端在物理上控制客户端计算机，尽管这在技术上非常困难，但是客户端仍然可以克服客户端设备和客户端代码的安全限制。如果只有客户端应用检查某些功能或数据的有效性，则不使用服务器的物理控件提供的物理安全性。每当数据从客户端发送到服务器时，无论客户端应用是什么，都必须检查数据的有效性。实际上，由于客户端应用是可以更改的，我们只是不知道客户端应用到底是什么。

在本章中，事实上，在本书中，我们主要关注 Java 技术；因此，示例应用几乎不包含任何客户端技术。我忍不住创建了一些 CSS。另一方面，我绝对避免使用 JavaScript。因此，我必须再次强调，这个示例旨在演示服务器端的编程，并且仍然提供一些真正有效的东西。现代应用将使用 REST 和 JSON 通信，不会在服务器端动态创建 HTML。最初，我想创建一个 JavaScript 客户端和 REST 服务器应用，但是重点从服务器端 Java 编程转移了太多，所以我放弃了这个想法。另一方面，您可以将应用扩展为这样的应用。

# 编写 Servlet

Servlet 是在实现 Servlet 容器环境的 Web 服务器中执行的 Java 类。最初的 Web 服务器只能向浏览器提供静态 HTML 文件。对于每个 URL，Web 服务器上都有一个 HTML 页面，服务器根据浏览器发送的请求传递该文件的内容。很快，就需要扩展 Web 服务器，以便能够启动一个程序，在处理请求时动态地计算响应的内容。

第一个这样做的标准是定义的**公共网关接口**（**CGI**）。它启动了一个新的进程来响应请求。新进程获得了对其标准输入的请求，并将标准输出发送回客户端。这种方法浪费了大量资源。正如您在上一章中了解到的那样，启动一个新的进程对于响应一个 HTTP 请求来说代价太高了。即使开始一个新的线程似乎是没有必要的，但有了它，我们就有点超前了。

下一种方法是 FastCGI，它不断地执行外部进程并重用它。FastCGI 后面的方法都使用进程中扩展。在这些情况下，计算响应的代码运行在与 Web 服务器相同的进程中。这些标准或扩展接口是针对 Microsoft IIS 服务器的 ISAPI、Netscape 服务器的 NSASPI 和 Apache 模块接口。这些都使得在 Windows 上创建一个动态加载库（**DLL**），或在 Unix 系统上加载共享对象（**SO**），并映射这些库中实现的代码处理的某些请求。

例如，当有人编写 PHP 时，Apache 模块扩展就是 PHP 解释器，它读取 PHP 代码并对其执行操作。当有人为 NicrosoftIIS 编写 ASP 页面时，将执行实现 ASP 页面解释器的 ISAPI 扩展（好吧，这有点草率，说起来过于简单，但可以作为一个例子）。

对于 Java 来说，接口定义是 JSR369 中从 4.0 版开始定义的 Servlet。

JSR 代表 Java 规范请求。这些是对 Java 语言、库接口和其他组件的修改请求。这些请求经过一个评估过程，当它们被接受时，它们就成为一个标准。这个过程由 Java 社区流程（JCP）定义。JCP 也有文档记录，有不同的版本。当前版本为 2.10，可在[这个页面](https://jcp.org/en/procedures/overview)找到。

Servlet 程序实现 Servlet 接口。通常，这会受到扩展`HttpServlet`类的影响，这个类是`Servlet`接口的抽象实现。这个抽象类实现了`doGet()`、`doPost()`、`doPut()`、`doDelete()`、`doHead()`、`doOption()`、`doTrace()`等方法，可以被扩展它的实际类自由覆盖。如果 Servlet 类没有覆盖其中一个方法，则发送相应的 HTTP 方法`GET`、`POST`等，将返回`405 Not Allowed`状态码。

# HelloWorld Servlet

在进入技术细节之前，让我们创建一个非常简单的 HelloWorld Servlet。为此，我们将建立一个 Gradle 项目，其中包含构建文件`build.gradle`，即`src/main/java/packt/java9/by/example/mastermind/servlet/HelloWorld.java`文件中的 Servlet 类，最后但同样重要的是，我们必须创建文件`src/main/webapp/WEB-INF/web.xml`。`gradle.build`文件如下所示：

```java
apply plugin: 'java'
apply plugin: 'war'
apply from: 'https://raw.github.com/gretty-gradle-plugin/gretty/master/pluginScripts/gretty.plugin'

repositories {
    jcenter()
}
targetCompatibility = "1.10"
sourceCompatibility = "1.10"
dependencies {
    providedCompile "javax.servlet:javax.servlet-api:3.1.0"
    testCompile 'junit:junit:4.12'
    compile 'org.slf4j:slf4j-api:1.7.7'
    compile 'ch.qos.logback:logback-classic:1.0.11'
    compile 'com.google.inject:guice:4.1.0'
}
```

Gradle 构建文件使用两个插件，`java`和`gretty`。我们已经在上一章中使用了`java`插件。`gretty`插件添加了`appRun`之类的任务，用于加载 Jetty Servlet 容器并启动应用。`gretty`插件还使用`war`插件，它将 Web 应用编译成 Web 归档（WAR）打包格式。

WAR 打包格式实际上与 JAR 相同；它是一个 zip 文件，包含一个包含 Web 应用所依赖的所有 JAR 文件的目录。应用的类在目录`WEB-INF/classes`中，有一个描述 Servlet URL 映射的`WEB-INF/web.xml`文件，我们将很快详细探讨这个文件。

因为我们想开发一个非常简单的 Servlet，所以我们将 Servlet API 作为依赖项添加到项目中。然而，这不是一种依赖关系。当 Servlet 在容器中运行时，API 可用。但是，它必须在编译器编译我们的代码时可用；因此，*伪*实现是由指定为`providedCompile`的工件提供的。因为是这样指定的，所以构建过程不会将库打包到生成的 WAR 文件中。生成的文件将不包含任何特定于 Jetty 或任何其他 Servlet 容器的内容。

Servlet 容器将提供 Servlet 库的实际实现。当应用在 Jetty 中部署和启动时，Servlet 库的 Jetty 特定实现将在类路径上可用。当应用部署到 Tomcat 时，特定于 Tomcat 的实现将可用。

我们在项目中创建了一个类，如下所示：

```java
package packt.java11.mastermind.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class HelloWorld extends HttpServlet {

    private String message;

    public void init() throws ServletException {
        message = "Hello World";
    }

    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<h1>" + message + "</h1>");
    }

    public void destroy() {
    }
}
```

当 Servlet 启动时，`init`方法被调用。当 Servlet 停止服务时，调用`destroy`方法。可以覆盖这些方法，以提供比构造器和其他终结可能性更细粒度的控制。一个 Servlet 对象可以多次投入使用，调用`destroy`后，Servlet 容器可以再次调用`init`，因此这个周期与对象的生命周期没有严格的联系。通常，我们在这些方法中做的并不多，但有时，您可能需要在其中编写一些代码。

另外，请注意，一个 Servlet 对象可以用于服务多个请求，甚至可以同时服务；因此，其中的 Servlet 类和方法应该是线程安全的。该规范要求 Servlet 容器仅使用一个 Servlet 实例，以防容器在非分布式环境中运行。如果容器在同一台机器上的多个进程中运行，每个进程执行一个 JVM，甚至在不同的机器上运行，那么可以有许多 Servlet 实例来处理请求。一般来说，Servlet 类的设计应该使它们不假设只有一个线程在执行它们，但是，同时，它们也不应该假设不同请求的实例是相同的。我们根本不知道。

这在实践中意味着什么？您不应该使用特定于某个请求的实例字段。在前面的示例中，初始化为保存消息的字段为每个请求保存相同的值；实际上，变量几乎是一个最终常量。它仅用于演示`init`方法的一些功能。

当 Servlet 容器通过`GET`方法获得 HTTP 请求时，`doGet`方法被调用。该方法有两个参数。第一个代表请求，第二个代表响应。`request`可以用来收集请求中的所有信息。在前面的例子中，没有这样的。我们不使用任何输入。如果一个请求到达我们的 Servlet，那么不管发生什么，我们都会回答`Hello, World`字符串。稍后，我们将看到从请求中读取参数的示例。`response`给出了可以用来处理输出的方法。

在本例中，我们获取`PrintWriter`，它将用于向 HTTP 响应的主体发送字符。这是显示在浏览器中的内容。我们发送的 MIME 类型是`text/html`，这是通过调用`setContentType`方法来设置的。这将进入 HTTP 头字段`Content-Type`。这些类的标准和 JavaDoc 文档定义了可以使用的所有方法，以及应该如何使用这些方法。

最后，我们有一个`web.xml`文件，它声明了代码中实现的 Servlet。正如文件名所示，这是一个 XML 文件。它声明性地定义了存档中包含的所有 Servlet 以及其他参数。在下面的示例中，没有定义参数，只有 Servlet 和到 URL 的映射。因为在这个例子中我们只有一个 Servlet，WAR 文件，所以它被映射到根上下文。到达 Servlet 容器和此存档的每个`GET`请求都将由此 Servlet 提供服务：

```java
<web-app version="2.5" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd">

    <servlet>
        <display-name>HelloWorldServlet</display-name>
        <servlet-name>HelloWorldServlet</servlet-name>
        <servlet-class>packt.java11.mastermind.servlet.HelloWorld</servlet-class>
    </servlet>
    <servlet>
        <display-name>Mastermind</display-name>
        <servlet-name>Mastermind</servlet-name>
        <servlet-class>packt.java11.mastermind.servlet.Mastermind</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>HelloWorldServlet</servlet-name>
        <url-pattern>/hello</url-pattern>
    </servlet-mapping>
    <servlet-mapping>
        <servlet-name>Mastermind</servlet-name>
        <url-pattern>/master</url-pattern>
    </servlet-mapping>

</web-app>
```

# Java 服务器页面

我答应过你，我不会让你厌烦 JavaServerPages（JSP），因为这是过去的技术。尽管它已经成为过去，但它仍然不是历史，因为仍有许多运行的程序使用 JSP。

JSP 页面是包含 HTML 和 Java 代码组合的 Web 页面。当 JSP 页面提供 HTTP 请求时，Servlet 容器读取 JSP 页面，执行 Java 部分，将 HTML 部分保持原样，并以这种方式将两者混合在一起，创建一个发送到浏览器的 HTML 页面：

```java
<%@ page language="java"
         contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<html>
<body>
<% for( int i = 0 ; i < 5 ; i ++ ){ %>
  hallo<br/>
<% } %>
</body>
</html>
```

前面的页面将创建一个 HTML 页面，其中包含五次文本`hallo`，每一次都在一个新行中，由标记`br`分隔。在幕后，Servlet 容器将 JSP 页转换为 JavaServlet，然后使用 Java 编译器编译 Servlet，然后运行 Servlet。每次对源 JSP 文件进行更改时，它都会这样做；因此，使用 JSP 以增量方式编写一些简单的代码非常容易。从前面的 JSP 文件生成的代码有 138 行长（在 tomcat8.5.5 版本上），这里列出的代码很长，也很无聊，但是帮助理解 Java 文件生成工作原理的部分只有几行。

如果您想查看生成的 Servlet 类的所有行，可以将应用部署到 Tomcat 服务器中，并查看`work/Catalina/localhost/hello/org/apache/jsp/`目录，开发人员不知道这个代码实际上保存到磁盘上并且可用。当您需要调试一些 JSP 页面时，它偶尔会有所帮助。

下面是由前面的代码生成的几行有趣的代码：

```java
out.write("n");
      out.write("<html>n");
      out.write("<body>n");
 for( int i = 0 ; i < 5 ; i ++ ){
      out.write("n");
      out.write("  hallo<br/>n");
 }
      out.write("n");
      out.write("</body>n");
      out.write("</html>n");
```

JSP 编译器将 JSP 代码的内部向外移动，外部向内移动。在 JSP 代码中，Java 被 HTML 包围，在生成的 Servlet Java 源代码中，HTML 被 Java 包围。就像你要修补衣服一样：第一件事就是把衣服翻过来。

不仅可以将 Java 代码混合到 JSP 页面中的 HTML 中，还可以使用所谓的标记。标记被收集到标记库中，用 Java 实现，并打包到 JAR 文件中，它们应该在要使用的类路径上可用。使用特定库中标记的 JSP 页面应声明用途：

```java
<%@ taglib prefix="c"
           uri="http://java.sun.com/jsp/jstl/core" %>
```

这些标记看起来像 HTML 标记，但它们由 JSP 编译器处理，并由`taglib`库中实现的代码执行。JSP 还可以引用 JSP 范围内可用的 Java 对象的值。为了在 HTML 页面中实现这一点，可以使用 JSP 表达式语言。

JSP 最初是为了方便 Web 应用的开发而创建的。其主要优势是开发的快速启动。开发过程中不需要繁琐的配置、设置和其他辅助任务，当 JSP 页面发生任何更改时，无需再次编译整个应用 Servlet 容器生成 Java 代码，将其编译到类文件中，将代码加载到内存中并执行。JSP 是 MicrosoftASP 页面的竞争对手，它将 HTML 和 VisualBasic 代码混合在一起。

随着应用开始扩展，使用 JSP 技术带来的问题比解决的问题还多。混合了业务逻辑和应用视图的代码，以及在浏览器中的呈现方式，变得杂乱无章。开发 JSP 需要前端技术知识。Java 开发人员应该了解一些前端技术，但很少是设计专家和 CSS 专家。现代的代码还包含 JavaScript，很多次嵌入到 HTML 页面中。毕竟，JSP 的最大优势在于它包含在服务器和客户端代码上运行的代码。开发人员多次遵循这种模式，因此看到一些包含 Java、HTML、CSS 和 JavaScript 的遗留代码都混合在 JSP 文件中，不要感到惊讶。由于 Java 和 JavaScript 有时在语法上是相似的，所以在服务器上执行什么和在客户端上执行什么并不明显。我甚至在 JSP 文件中看到过从 Java 代码创建 JavaScript 代码的代码。这是一个完全混合了不同的责任和混乱，几乎是不可能维持。这导致了到今天为止 JSP 的完全不受欢迎。

JSP 的贬损不是官方的。这是我的专家意见。您可能会遇到一些仍然热爱 JSP 的有经验的开发人员，并且您可能会发现自己正处于需要用 JSP 开发程序的项目中。那样做并不可耻。有些人为了钱做得更糟。

为了改善这种混乱的局面，有越来越多的技术主张将服务器代码和客户端功能分离。这些技术包括 Wicket、Vaadin、JSF 和不同的 Java 模板引擎，如 Freemarker、ApacheVelocity 和 Thymeleaf。当您从 Java 生成文本输出时，后一种技术也很有趣，即使代码与 Web 完全无关。

这些技术，加上规程，帮助控制了中型和大型 Web 项目的开发和维护成本，但是架构的基本问题仍然存在：没有明确的关注点分离。

今天，现代应用在不同的项目中实现 Web 应用的代码：一个用于客户端，使用 HTML、CSS 和 JavaScript，另一个用于在 Java 中实现服务器功能（或在其他方面，但我们在这里重点讨论 Java）。两者之间的通信是 REST 协议，我们将在后面的章节中介绍。

# HTML、CSS 和 JavaScript

HTML、CSS 和 JavaScript 是客户端技术。这些对于 Web 应用非常重要，一个专业的 Java 开发人员应该对它们有所了解。如今，这两个领域的专家级开发人员被称为全栈开发人员，尽管我觉得这个名字有点误导。一定的理解是不可避免的。

HTML 是结构化文本的文本表示。文本以字符形式给出，就像在任何文本文件中一样。标记表示结构。开始标记以一个`<`字符开始，然后是标记的名称，然后可选地是`name="value"`属性，最后是结束符`>`。结束标记以`</`开始，然后是标记的名称，然后是`>`。标记包含在层次结构中；因此，您不应该比稍后打开的标记更早关闭标记。首先，必须关闭上一个打开的标签，然后关闭下一个，依此类推。这样，HTML 中的任何实际标记都有一个级别，所有介于开始标记和结束标记之间的标记都在该标记之下。一些不能包含其他标记或文本的标记没有结束标记，它们自己独立存在。考虑以下示例：

```java
<html>
  <head>
    <title>this is the title</title>
  </head>
</html>
```

标签`head`在`html`下，`title`在`head`下。可以将其结构化为树，如下所示：

```java
html
+ head
  + title
    + "this is the title"
```

浏览器以树形结构存储 HTML 文本，此树是网页文档的对象模型，因此命名为**文档对象模型**（**DOM**）树。

最初的 HTML 概念混合了格式和结构，即使使用当前版本的 HTML5，我们仍然有像`b`、`i`和`tt`这样的标签，它们建议浏览器分别以粗体、斜体和电传显示开始和结束标签之间的文本。

正如代表超文本标记语言（HyperTextMarkupLanguage）的名称 HTML 所暗示的那样，文本可以以超链接的形式包含对其他网页的引用。这些链接被分配给使用`a`标签（代表锚定）的文本或可能由不同字段组成的某个表单，当按下表单的提交按钮时，字段的内容将在`POST`请求中发送给服务器。发送表单时，字段的内容以所谓的`application/x-www-form-urlencoded`形式编码。

HTML 结构总是试图促进结构和格式的分离。为此，格式被移动到样式。**层叠样式表**（**CSS**）中定义的样式为格式化提供了比 HTML 更大的灵活性；CSS 的格式对格式化更有效。创建 CSS 的目的是使设计与文本结构分离。

如果我必须从这三个选项中选择一个，我会选择 CSS 作为对 Java 服务器端 Web 开发人员最不重要的选项，同时也是对用户最重要的选项（事情看起来应该不错）。

JavaScript 是客户端技术的第三大支柱。JavaScript 是一种由浏览器执行的全功能、解释性编程语言。它可以访问 DOM 树，并读取和修改它。修改 DOM 树时，浏览器会自动显示修改后的页面。可以计划和注册 JavaScript 函数，以便在事件发生时调用。例如，您可以注册一个函数，以便在文档完全加载、用户按下按钮、单击链接或将鼠标悬停在某个节上时调用。尽管 JavaScript 最初只用于在浏览器上创建有趣的动画，但今天，使用浏览器的功能对功能齐全的客户端进行编程是可能的，这也是标准做法。有很多用 JavaScript 编写的强大程序，甚至像 PC 仿真器这样的耗电应用。

最后，但并非最不重要的一点是，美国 Java 开发人员必须关注我前面描述的新 WebAssembly 技术。

在本书中，我们将重点介绍 Java，并尽可能多地使用演示技术所需的客户端技术。然而，作为一名 Java Web 开发人员专业人员，您还必须学习这些技术，至少在某种程度上，这样才能理解客户端可以做什么，并能够与负责前端技术的专业人员合作。

# Mastermind Servlet

通过网络玩 Mastermind 游戏和以前有点不同。到目前为止，我们还没有任何用户交互，我们的类也相应地进行了设计。例如，我们可以向表中添加一个新的猜测，以及程序计算的部分匹配和完全匹配。现在，我们必须分开创建一个新的猜测，将其添加到游戏中，并设置完全匹配和部分匹配。这一次，我们必须首先显示表，用户必须计算并提供匹配数。

我们必须修改一些类才能做到这一点。我们需要在`Game.java`中添加一个新方法：

```java
public Row addGuess(Guess guess, int full, int partial) {
    assertNotFinished();
    final Row row = new Row(guess, full, partial);
    table.addRow(row);
    if (itWasAWinningGuess(full)) {
        finished = true;
    }
    return row;
}
```

到目前为止，我们只有一种方法是添加一个新的猜测，由于程序知道了这个秘密，它立即计算出了`full`和`partial`的值。方法的名称可以是`addNewGuess`，重载了原始方法，但这次，该方法不仅用于添加新的猜测，还用于添加旧的猜测以重建表。这是因为每次玩家给出下一个猜测的答案时，我们都会根据浏览器发送给服务器的信息来重建游戏的实际状态。游戏的状态存储在客户端中，并通过 HTTP 请求发送到服务器。

程序启动时，没有猜测。程序创建了一个，第一个。之后，当用户告诉程序完全匹配和部分匹配时，程序需要使用包含有`Guess`对象和`full`与`partial`匹配值的`Game`结构和`Table`与`Row`对象。这些已经可用了，但是当新的 HTTP 命中时，我们必须从某个地方获取它。编写 Servlet 时，我们必须将游戏的状态存储在某个地方，并在新的 HTTP 请求到达服务器时还原它。

# 存储状态

存储状态可以在两个地方完成。我们将在代码中首先做的一个地方是客户端。当程序创建一个新的猜测时，它会将其添加到表中，并发送一个 HTML 页面，该页面不仅包含新的猜测，还包含所有以前的猜测以及用户为每一行提供的匹配值。要将数据发送到服务器，值存储在窗体的字段中。提交表单时，浏览器收集字段中的信息，根据字段内容创建编码字符串，并将内容放入`POST`请求的主体中。

存储实际状态的另一种可能性是在服务器上。服务器可以存储游戏的状态，并且在创建新的猜测时可以重建结构。在这种情况下，问题是知道使用哪种游戏。如果状态存储在服务器上，那么它应该存储许多游戏，每个用户至少一个。用户可以同时使用应用。它并不一定意味着我们在上一章中所研究的内容具有很强的并发性。

即使用户不是在多个线程中同时服务的，也可能存在活动的游戏。可以有多个用户在玩多个游戏，在服务一个 HTTP 请求时，我们应该知道我们在服务哪个用户。

Servlet 维护可用于此目的的会话，我们将在下一节中看到。

决定在哪里存储应用的状态是一个重要的架构问题。在做决定时，你应该考虑可靠性，信任，安全性，这本身也取决于信任，性能，以及其他可能的因素。

# HTTP 会话

当客户端从同一个浏览器向同一个 Servlet 发送请求时，这一系列请求属于一个会话。为了知道请求属于同一个会话，Servlet 容器自动向客户端发送一个名为`JSESSIONID`的 Cookie，这个 Cookie 有一个长的、随机的、难以猜测的值（`tkojxpz9qk9xo7124pvanc1z`，因为我在 Jetty 中运行应用）。Servlet 维护一个包含`HttpSession`实例的会话存储。在`JSESSIONID`Cookie 的值中传递的键字符串标识实例。当 HTTP 请求到达 Servlet 时，容器将会话附加到存储区中的请求对象。如果键没有会话，则创建一个会话，代码可以通过调用`request.getSession()`方法访问会话对象。

`HttpSession`对象可以存储属性。程序可以调用`setAttribute(String,Object)`、`getAttribute(String)`和`removeAttribute(String)`方法来存储、检索或删除属性对象。每个属性都分配给一个`String`，可以是任何`Object`。

尽管会话属性存储本质上看起来像一个`Map<String,?>`对象一样简单，但事实并非如此。当 Servlet 容器在集群或其他分布式环境中运行时，存储在会话中的值可以从一个节点移动到另一个节点。为此，值被序列化；因此，会话中存储的值应该是`Serializable`。不这样做是一个非常常见的新手错误。在开发过程中，在简单的开发 Tomcat 或 Jetty 容器中执行代码实际上从来不会将会话序列化到磁盘，也不会从序列化的表单中加载它。这意味着使用`setAttribute`设置的值将通过调用`getAttribute`可用。当应用第一次安装在集群环境中时，我们就遇到了麻烦。一旦 HTTP 请求到达不同的节点，`getAttribute`可能返回`null`。方法`setAttribute`在一个节点上被调用，并且在处理下一个请求的过程中，不同节点上的`getAttribute`无法从节点之间共享的磁盘反序列化属性值。不幸的是，这通常是生产环境。

尽管目前会话只能可靠地存储实现`Serializable`接口的类的对象，但是我们应该知道 Java 序列化在将来的某个时候会发生变化。序列化是一种低级功能，在创建 Java 时将其连接到一种语言并不是一个好的决定。至少现在看来不是这样。在 Servlet 标准和实现方面没有什么可怕的，它们将正确地处理这种情况。另一方面，在框架提供的代码之外的代码中使用序列化是违反直觉的。

作为一名开发人员，您还应该意识到，序列化和反序列化对象是一项耗费数个 CPU 周期的繁重操作。如果应用的结构仅使用服务于大多数 HTTP 请求的客户端状态的一部分，那么从序列化窗体在内存中创建整个状态，然后再次序列化它，这是对 CPU 的浪费。在这种情况下，更可取的做法是只在会话中存储一个键，并使用一些数据库（SQL 或 NoSQL）或其他服务来存储该键引用的实际数据。企业应用几乎完全使用这种结构。

# 在客户端上存储状态

首先，我们将通过在客户端上存储状态来开发代码。发送用户输入和新的完全匹配和部分匹配的数量所需的表单还包含用户当时给出的所有猜测和答案的所有以前的颜色。为此，我们创建一个新的辅助类来格式化 HTML 代码。这是在现代企业环境中使用模板、JSP 文件完成的，或者完全避免在企业环境中使用纯 REST 和单页应用。然而，在这里，我们将使用旧技术来演示在现代发动机罩下旋转的齿轮：

```java
package packt.java11.mastermind.servlet;

import packt.java11.mastermind.Color;
import packt.java11.mastermind.Table;

import javax.inject.Inject;
import javax.inject.Named;

public class HtmlTools {
    @Inject
    Table table;

    @Inject
    @Named("nrColumns")
    private int NR_COLUMNS;

    public String tag(String tagName, String... attributes) {
        StringBuilder sb = new StringBuilder();
        sb.append("<").append((tagName));
        for (int i = 0; i < attributes.length; i += 2) {
            sb.append(" ").
                    append(attributes[i]).
                    append("=\"").
                    append(attributes[i + 1]).
                    append("\"");
        }
        sb.append(">");
        return sb.toString();
    }

    public String inputBox(String name, String value) {
        return tag("input", "type",
                "text", "name", name, "value", value, "size", "1");
    }

    public String colorToHtml(Color color, int row, int column) {
        return tag("div",
                "class", "color" + color) +
                tag("/div") +
                tag("div",
                        "class", "spacer") +
                tag("/div");
    }

    public String paramNameFull(int row) {
        return "full" + row;
    }

    public String paramNamePartial(int row) {
        return "partial" + row;
    }

    public String paramNameGuess(int row, int column) {
        return "guess" + row + column;
    }

    public String tableToHtml() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><head>");
        sb.append("<link rel=\"stylesheet\"")
                .append(" type=\"text/css\" href=\"colors.css\">");
        sb.append("<title>Mastermind guessing</title>");
        sb.append("<body>");
        sb.append(tag("form",
                "method", "POST",
                "action", "master"));

        for (int row = 0; row < table.nrOfRows(); row++) {
            for (int column = 0; column < NR_COLUMNS; column++) {
                final String html =
                        colorToHtml(table.getColor(row, column),
                                row, column);
                sb.append(html);
            }
            if (row < table.nrOfRows() - 1) {
                sb.append("" + table.getFull(row));
                sb.append(tag("div", "class", "spacer"))
                        .append(tag("/div"));
                sb.append("" + table.getPartial(row));
            } else {
                sb.append(inputBox(paramNameFull(row), "" + table.getFull(row)));
                sb.append(inputBox(paramNamePartial(row), "" + table.getPartial(row)));
            }
            sb.append("<p>");
        }
        return sb.toString();
    }
}
```

除了`@Inject`注解，其余代码都简单明了。我们将在不久的将来关注`@Inject`。我们必须关注的是代码生成的 HTML 结构。生成的页面如下所示：

```java
<html>
    <head>
        <link rel="stylesheet" type="text/css" href="colors.css">
        <title>Mastermind guessing</title>
        <body>
            <form method="POST" action="master">
                <input type="hidden" name="guess00" value="3">
                <div class="color3"></div>

                <div class="spacer"></div>

                <input type="hidden" name="guess01" value="2">
                <div class="color2"></div>

                <div class="spacer"></div>

                <input type="hidden" name="guess02" value="1">
                <div class="color1"></div>

                <div class="spacer"></div>

                <input type="hidden" name="guess03" value="0">
                <div class="color0"></div>

                <div class="spacer"></div>

                <input type="text"
                       name="full0" value="0" size="1">
                <input type="text"
                       name="partial0" value="2" size="1">

                <input type="hidden" name="guess10" value="5">
                <div class="color5"></div>

...deleted content that just looks almost the same...

                <input type="submit" value="submit">
            </form>
        </body>
    </head>
</html>
```

表单包含`div`标签中的颜色，还包含隐藏字段中颜色的*字母*。这些输入字段在表单提交时发送到服务器，就像其他任何字段一样，但它们不会出现在屏幕上，用户无法编辑它们。完全匹配和部分匹配显示在文本输入字段中。由于无法在 HTML 文本中显示`Color`对象，因此我们使用`LetteredColor`和`LetteredColorFactory`，它们将单个字母指定给颜色。前六种颜色简单地编号为`0`、`1`、`2`、`3`、`4`和`5`。CSS 文件可以控制颜色在浏览器窗口中的显示方式。

您可能还记得，我们讨论了如何以及在何处实现单个颜色的显示。首先，我们创建了一个特殊的打印类，它将字母分配给已经存在的颜色，但这只能在非常有限的环境中使用（主要是单元测试）。现在，问题又来了。我们有字母颜色，但现在我们需要真正的颜色，因为这一次，我们有一个客户端显示，能够显示颜色。

现代网络技术的真正力量在这里闪耀。内容和格式可以相互分离。不同颜色的夹子在 HTML 中被列为`div`标记。它们有一个格式化类，但实际的外观是在一个 CSS 文件中定义的，该文件只负责外观：

```java
.color0 {
    background: red;
    width : 20px;
    height: 20px;
    float:left
}
.color1 {
    background-color: green;
    width : 20px;
    height: 20px;
    float:left
}
... .color2 to .color5 is deleted, content is the same except different colors ...

.spacer {
    background-color: white;
    width : 10px;
    height: 20px;
    float:left
}
```

# Guice 依赖注入

Servlet 类非常简单，如以下代码所示：

```java
package packt.java11.mastermind.servlet;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Mastermind extends HttpServlet {
    private static final Logger log =
            LoggerFactory.getLogger(Mastermind.class);

    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
            throws ServletException, IOException {
        Injector injector =
                Guice.createInjector(new MastermindModule());
        MastermindHandler handler =
                injector.getInstance(MastermindHandler.class);
        handler.handle(request, response);
    }
}
```

因为许多线程同时使用 Servlet，因此我们不能使用实例字段来保存一次命中的数据，Servlet 类只会创建一个新的`MastermindHandler`类实例并调用其`handle`方法。因为每个请求都有一个新的`MastermindHandler`实例，所以它可以将对象存储在特定于请求的字段中。为了创建处理器，我们使用 Google 创建的 Guice 库。

我们已经讨论过依赖注入。处理器需要一个`Table`对象来播放，一个`ColorManager`对象来管理颜色，一个`Guesser`对象来创建一个新的猜测，但是创建这些或者从某处获取一些预制的实例并不是处理器的核心功能。处理器必须做一件事来处理请求；执行此操作所需的实例应该从外部注入。这是由一个`Guice`喷射器完成的。

要使用 Guice，我们必须在`build.gradle`中列出依赖项中的库。文件的实际内容已经列在`HelloWorld`Servlet 之前。

然后，我们必须创建一个`injector`实例来执行注入。使用 Servlet 中的以下行创建注入器：

```java
Injector injector = Guice.createInjector(new MastermindModule());
```

`MastermindModule`的实例指定在何处注入什么。这实际上是一个 Java 格式的配置文件。其他依赖注入框架使用并继续使用 XML 和注解来描述注入绑定和注入内容，但是 Guice 只使用 Java 代码。以下是 DI 配置代码：

```java
public class MastermindModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(int.class)
                .annotatedWith(Names.named("nrColors"))
                .toInstance(6);
        bind(int.class)
                .annotatedWith(Names.named("nrColumns"))
                .toInstance(4);
        bind(ColorFactory.class)
                .to(LetteredColorFactory.class);
        bind(Guesser.class)
                .to(UniqueGuesser.class);
    }
```

`configure`方法中使用的方法是以 Fluent API 的方式创建的，这样方法就可以一个接一个地链接起来，这样代码就可以像英语句子一样阅读。有关 Fluent API 的详细介绍，请访问[这个页面](https://blog.jooq.org/2012/01/05/the-java-fluent-api-designer-crash-course/)。例如，第一个配置行可以用英语读作：

“绑定到带有`"nrColor"`值为 6 的`@Name`的注解`int`类” 

`MastermindHandler`类包含用`@Inject`注解注解的字段：

```java
@Inject
@Named("nrColors")
private int NR_COLORS;
@Inject
@Named("nrColumns")
private int NR_COLUMNS;
@Inject
private HtmlTools html;
@Inject
Table table;
@Inject
ColorManager manager;
@Inject
Guesser guesser;
```

此注解不是特定于 Guice 的。`@Inject`是`javax.inject`包的一部分，是 JDK 的标准部件。JDK 不提供**依赖注入**（**DI**）框架，但支持不同的框架，以便它们可以使用标准的 JDK 注解，如果 DI 框架被替换，注解可以保持不变，而不是特定于框架。

当调用注入器来创建一个`MastermindHandler`实例时，它查看类，发现它有一个`int`字段，用`@Inject`和`@Named("nrColors")`注解，并在配置中发现这样一个字段的值应该是 6。它在返回`MastermindHandler`对象之前将值注入字段。类似地，它还将值注入其他字段，如果需要创建任何要注入的对象，它也会这样做。如果这些对象中有字段，那么它们也是通过注入其他对象等方式创建的。

这样，DI 框架就免除了程序员创建实例的负担。这是一件相当无聊的事情，而且无论如何也不是类的核心特性。相反，它创建了所有需要有一个函数式的`MastermindHandler`的对象，并通过 Java 对象引用将它们链接在一起。这样，不同对象的依赖关系（`MastermindHandler`需要`Guesser`、`ColorManager`、`Table`；`ColorManager`需要`ColorFactory`、`Table`也需要`ColorManager`等等）就变成了一个声明，通过字段上的注解来指定。这些声明在类的代码中，是它们的正确位置。除了类本身之外，我们还能在哪里指定类需要什么才能正常运行呢？

我们示例中的配置指定，无论哪里需要`ColorFactory`，我们都将使用`LetteredColorFactory`，无论哪里需要`Guesser`，我们都将使用`UniqueGuesser`。这是从代码中分离出来的，必须是这样。如果我们想改变猜测策略，我们将替换配置，代码应该在不修改使用猜测器的类的情况下工作。

Guice 足够聪明，您不必指定任何需要`Table`的地方，我们都将使用`Table`——没有`bind(Table.class).to(Table.class)`。首先，我在配置中创建了一行这样的代码，但是 Guice 给了我一条错误消息，现在，用纯英语再写一遍，我觉得自己真的很愚蠢。如果我需要一张桌子，我需要一张桌子。真的？

当使用 Java9 或更高版本并且我们的代码使用 JPMS 时，我们必须向我们使用的框架打开我们的代码库。模块不允许来自外部的代码使用反射操作私有类或对象成员。如果我们不在模块定义文件中声明我们想要使用 Guice，并且我们允许 Guice 访问私有字段，它将无法做到这一点，这样，它将无法工作。要将我们的模块打开到 Guice，我们必须编辑`module_info.java`文件并插入`opens`关键字，指定需要注入的类所在的包。

# `MastermindHandler`类

我们已经开始列出`MastermindHandler`类，因为这个类有一百多行，所以我不把它作为一个整体包括在这里。这个类最重要的方法是`handle`：

```java
public void handle(HttpServletRequest request,
                   HttpServletResponse response)
        throws ServletException, IOException {

    Game game = buildGameFromRequest(request);
    Guess newGuess = guesser.guess();
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    if (game.isFinished() || newGuess == Guess.none) {
        displayGameOver(out);
    } else {
        log.debug("Adding new guess {} to the game", newGuess);
        game.addGuess(newGuess, 0, 0);
        displayGame(out);
    }
    bodyEnd(out);
}
```

我们执行三个步骤。第一步是创建表，我们从请求开始创建。如果这不是游戏的开始，那么就已经有了一个表，HTML 表单包含了所有先前的猜测颜色和这些颜色的答案。然后，作为第二步，我们在此基础上创建一个新的猜测。第 3 步是将新的 HTML 页面发送到客户端。

同样，这不是一种现代的方法，在 Servlet 代码上创建 HTML，但是用 REST、JSON 和 JavaScript 以及一些框架演示纯 Servlet 功能，仅此一章就有几百页的篇幅，而且它肯定会转移我们对 Java 的注意力。

在本书中，将 HTML 文本打印到`PrintWriter`对您来说并不是什么新鲜事；因此，我们将不在这里列出这些代码。您可以从 Packt GitHub 存储库下载工作示例。我们将重点讨论 Servlet 参数处理，而不是打印。

请求参数可通过返回参数字符串值的`getParameter()`方法获得。此方法假设任何参数，无论是`GET`还是`POST`，在请求中只出现一次。如果存在多次出现的参数，则该值应该是一个`String`数组。在这种情况下，我们应该使用`getParameterMap()`，它返回带有`String`键和`String[]`值的整个映射。即使我们这次没有任何键的多个值，并且我们也知道键的值作为`POST`参数，我们仍然将使用后一种方法。这样做的原因是我们稍后将使用会话来存储这些值，并且我们希望在这种情况下有一个可重用的方法。

为了到达该阶段，我们将请求的`Map<String,String[]>`转换为`Map<String,String>`：

```java
private Game buildGameFromRequest(HttpServletRequest request) {
    return buildGameFromMap(toMap(request));
}

private Map<String, String> toMap(HttpServletRequest request) {
    log.debug("converting request to map");
    return request.getParameterMap().entrySet().
            stream().collect(
            Collectors.toMap(
                    Map.Entry::getKey,
                    e -> e.getValue()[0]));
}
```

然后，我们用那个映射来重现游戏：

```java
private Game buildGameFromMap(Map<String, String> params) {
    var secret = new Guess(new Color[NR_COLUMNS]);
    var game = new Game(table, secret);
    for (int row = 0;
         params.containsKey(html.paramNameGuess(row, 0));
         row++) {
        Color[] colors = getRowColors(params, row);
        Guess guess = new Guess(colors);
        var full = Integer.parseInt(params.get(html.paramNameFull(row)));
        var partial = Integer.parseInt(params.get(html.paramNamePartial(row)));
        log.debug("Adding guess to game");
        game.addGuess(guess, full, partial);
    }
    return game;
}
```

从`String`到`int`的转换是通过`parseInt()`方法完成的。当输入不是数字时，此方法抛出`NumberFormatException`。试着运行游戏，使用浏览器，看看当 Servlet 抛出异常时 Jetty 是如何处理的。你在浏览器中看到多少有价值的信息可以被潜在的黑客使用？修复代码，以便它再次询问用户是否有任何数字格式不正确！

# 在服务器上存储状态

应用状态通常不应保存在客户端上。除了编写教育代码并希望演示如何不这样做之外，可能还有一些特殊情况。通常，与实际使用相关的应用状态存储在会话对象或某个数据库中。当应用要求用户输入大量数据，并且不希望用户在客户端计算机出现故障时丢失工作时，这一点尤为重要。

你花了很多时间在网店里挑选合适的商品，选择合适的可以协同工作的商品，创建新模型飞机的配置，突然，家里停电了。如果状态存储在客户端上，则必须从头开始。如果该状态存储在服务器上，则该状态将保存到磁盘；服务器将被复制，由电池供电，当您重新启动客户端计算机时，电源将回到您的家中，您登录，奇迹般地，这些项目都在您的购物篮中。嗯，这不是奇迹，而是网络编程。

在我们的例子中，第二个版本将在会话中存储游戏的状态。这将允许用户恢复游戏，只要会话还在。如果用户退出并重新启动浏览器，会话将丢失，新游戏可以开始。

由于这次不需要在隐藏字段中发送实际的颜色和匹配，因此 HTML 生成会稍微修改，生成的 HTML 也会更简单：

```java
<html>
<head>
    <link rel="stylesheet" type="text/css" href="colors.css">
    <title>Mastermind guessing</title>
<body>
<form method="POST" action="master">
    <div class="color3"></div>
    <div class="spacer"></div>
    <div class="color2"></div>
    <div class="spacer"></div>
    <div class="color1"></div>
    <div class="spacer"></div>
    <div class="color0"></div>
    <div class="spacer"></div>
0
    <div class="spacer"></div>
2
    <div class="color5"></div>
...
    <div class="spacer"></div>
    <div class="color1"></div>
    <div class="spacer"></div>
    <input type="text" name="full2" value="0" size="1">
    <input type="text" name="partial2" value="0" size="1">
    <input type="submit" value="submit">
</form></body></head></html>
```

完全匹配和部分匹配的颜色数显示为一个简单的数字，因此此版本不允许*欺骗*或修改以前的结果。（这些是 CSS 类`spacer`的`div`标记后面的数字`0`和`2`。）

`MastermindHandler`中的`handle`方法也发生了变化，如下代码所示：

```java
public void handle(HttpServletRequest request,
                   HttpServletResponse response)
        throws ServletException, IOException {

    Game game = buildGameFromSessionAndRequest(request);
    Guess newGuess = guesser.guess();
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    if (game.isFinished() || newGuess == Guess.none) {
        displayGameOver(out);
    } else {
        log.debug("Adding new guess {} to the game", newGuess);
        game.addGuess(newGuess, 0, 0);
        sessionSaver.save(request.getSession()); // note the added line
        displayGame(out);
    }
    bodyEnd(out);
}
```

变量`sessionSaver`是一个类型为`SessionSaver`的字段，它由 Guice 注入器注入到类中。`SessionSaver`是我们创建的一个类。这个类将当前的`Table`转换成存储在会话中的内容，并且它还根据存储在会话中的数据重新创建表。`handle`方法使用`buildGameFromSessionAndRequest`方法来恢复表，并添加用户刚刚在请求中给出的全部和部分匹配答案。当该方法创建新的猜测并将其填充到表中，并在响应中将其发送给客户端时，它通过`sessionSaver`对象调用`save()`方法来保存会话中的状态。

`buildGameFromSessionAndRequest`方法取代了另一个版本，我们称之为`buildGameFromRequest`：

```java
private Game buildGameFromSessionAndRequest(HttpServletRequest request) {
    var game = buildGameFromMap(sessionSaver.restore(request.getSession()));
    var params = toMap(request);
    int row = getLastRowIndex(params);
    log.debug("last row is {}", row);
    if (row >= 0) {
        var full = Integer.parseInt(params.get(html.paramNameFull(row)));
        var partial = Integer.parseInt(params.get(html.paramNamePartial(row)));
        log.debug("setting full {} and partial {} for row {}", full, partial, row);
        table.setPartial(row, partial);
        table.setFull(row, full);
        if (full == table.nrOfColumns()) {
            game.setFinished();
        }
    }
    return game;
}
```

请注意，这个版本与使用 JDK 中的`Integer`类中的`parseInt()`方法有相同的问题，该方法会引发异常。

# `GameSessionSaver`类

此类有三个公共方法：

*   `save()`：将表保存到用户会话
*   `restore()`：从用户会话中获取表
*   `reset()`：删除会话中可能存在的任何表

该类代码如下：

```java
public class GameSessionSaver {
    private static final String STATE_NAME = "GAME_STATE";
    @Inject
    private HtmlTools html;
    @Inject
    Table table;
    @Inject
    ColorManager manager;

    public void save(HttpSession session) {
        var params = convertTableToMap();
        session.setAttribute(STATE_NAME, params);
    }

    public void reset(HttpSession session) {
        session.removeAttribute(STATE_NAME);
    }

    public Map<String, String> restore(HttpSession session) {
        return (Map<String, String>)
                Optional.ofNullable(session.getAttribute(STATE_NAME))
                        .orElse(new HashMap<>());
    }

    private Map<String, String> convertTableToMap() {
        var params = new HashMap<String, String>();
        for (int row = 0; row < table.nrOfRows(); row++) {
            for (int column = 0;
                 column < table.nrOfColumns();
                 column++) {
                params.put(html.paramNameGuess(row, column),
                        table.getColor(row, column).toString());
            }
            params.put(html.paramNameFull(row),
                    "" + table.getFull(row));
            params.put(html.paramNamePartial(row),
                    "" + table.getPartial(row));
        }
        return params;
    }
}
```

当我们保存会话并将表转换为映射时，我们使用一个`HashMap`。在这种情况下，实现是重要的。`HashMap`类实现了`Serializable`接口；因此，我们可以安全地将其放入会话中。仅此一点并不能保证`HashMap`中的所有内容都是`Serializable`。本例中的键和值是字符串，幸运的是，`String`类还实现了`Serializable`接口。这样，转换后的`HashMap`对象可以安全地存储在会话中。

还要注意的是，尽管序列化可能很慢，但是在会话中存储`HashMap`是如此频繁，以至于它实现了自己的序列化机制。此实现经过优化，避免了序列化依赖于映射的内部结构。

现在是时候想想为什么我们在这个类中有`convertTableToMap()`方法，而在`MastermindHandler`类中有`buildGameFromMap()`方法了。将游戏和其中的表转换为一个`Map`和另一个回合应该一起实现。它们只是同一转换的两个方向。另一方面，`Table`到`Map`方向的实现应该使用`Map`版本，即`Serializable`。这与会话处理密切相关。一般来说，将一个`Map`对象转换为`Table`对象要高一级，即从客户端、会话、数据库或云中存储表的任何位置恢复表。会话存储只是一种可能的实现，方法应该在满足抽象级别的类中实现。最好的解决方案是在一个单独的类中实现这些。你有作业！

`reset()`方法未从处理器中使用。这是从`Mastermind`类调用的，也就是说，Servlet 类，在我们启动游戏时重置游戏：

```java
public void doGet(HttpServletRequest request,
                  HttpServletResponse response)
        throws ServletException, IOException {
    var sessionSaver = new GameSessionSaver();
    sessionSaver.reset(request.getSession());
    doPost(request, response);
}
```

如果没有这一点，在机器上玩一次游戏，每次我们想重新启动它时，只会显示完成的游戏，直到我们退出浏览器并重新启动它，或者明确删除浏览器高级菜单中某个地方的`JSESSIONID` Cookie。调用`reset`不会删除会话。会话保持不变，因此`JSESSIONID`Cookie 的值也保持不变，但是游戏将从 Servlet 容器维护的会话对象中删除。

# 运行 Jetty WebServlet

因为我们已经在 Gradle 构建中包含了 Jetty 插件，所以插件的目标是可用的。要启动 Jetty，只需键入以下内容：

```java
gradle appRun
```

这将编译代码，构建 WAR 文件，并启动 JettyServlet 容器。为了帮助我们记住，它还会在命令行上打印以下内容：

```java
Running at http://localhost:8080//hello
```

我们可以打开这个 URL，然后看到游戏的打开屏幕，其中的颜色是程序创建的第一个猜测：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/49fa4e7c-64d8-4ba6-8a91-73604503f2c4.png)

现在，是时候找点乐子玩我们的游戏了，给程序答案。不要让代码变得简单！请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/05bcf6ca-8690-432d-b48b-6167ae468a68.png)

同时，如果您在控制台中输入`gradle appRun`，您会看到代码正在打印日志消息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-proj/img/744ce854-5a85-43ed-aa4b-879982a3e3c9.png)

这些打印输出通过我们代码中的记录器。在前面的章节中，我们使用`System.out.println()`方法调用向控制台发送信息性消息。这是一种实践，在任何比 HelloWorld 更复杂的程序中都不应该遵循。

# 日志

Java 有几种可用的日志框架，每种都有优点和缺点。`java.util.logging`包中的 JDK 中内置了一个，并且`System.Logger`和`System.LoggerFinder`类中的`System.getLogger()`方法支持对记录器的访问。尽管自从 JDK1.4 以来，`java.util.logging`已经在 Java 中可用，但是很多程序使用其他日志解决方案。除了内置的日志记录之外，我们还要提到`log4j`、`slf4j`和 ApacheCommons 日志记录。在深入了解不同框架的细节之前，让我们先讨论一下为什么使用日志记录而不是仅仅打印到标准输出中是很重要的。

# 可配置性

最重要的原因是可配置性和易用性。我们使用日志记录有关代码操作的信息。这不是应用的核心功能，但是不可避免地需要一个可以操作的程序。我们在日志中打印了一些信息，操作人员可以使用这些信息来识别环境问题。例如，当抛出一个`IOException`并将其记录下来时，操作可能会查看日志并确定磁盘已满。他们可以删除文件，或者添加新磁盘并扩展分区。如果没有日志，唯一的信息就是程序无法运行。

这些日志也被多次用来搜寻虫子。有些 bug 在测试环境中没有表现出来，很难重现。在这种情况下，打印有关代码执行的详细信息的日志是查找某些错误的根本原因的唯一来源。

由于日志记录需要 CPU、IO 带宽和其他资源，因此应该仔细检查日志记录的内容和时间。这个检查和决策可以在编程过程中完成，事实上，如果我们使用`System.out.println`进行日志记录，这是唯一的可能性。如果我们需要找到一个错误，我们应该记录很多。如果我们记录太多，系统的性能就会下降。结论是，我们应该只在需要时记录。如果系统中存在无法复制的 bug，开发人员会要求操作在短时间内打开调试日志记录。当使用`System.out.println`时，无法打开和关闭日志的不同部分。当调试级别日志打开时，性能可能会下降一段时间，但与此同时，日志可用于分析。

同时，如果有一个小的（几百兆字节）日志文件而不是大量的 2GB 压缩日志文件来查找相关的日志行，那么当我们必须找到相关的日志行（并且您事先不知道哪些相关）时，分析就更简单了。

使用日志框架，可以定义标识日志消息源和日志级别的记录器。字符串通常标识记录器，通常使用从中创建日志消息的类的名称。这是一种常见的做法，不同的日志框架提供工厂类，这些工厂类获取类本身（而不是其名称）来获取记录器。

在不同的日志框架中，可能的日志级别略有不同，但最重要的级别如下：

*   `FATAL`：当日志消息涉及阻止程序继续执行的错误时使用。
*   `ERROR`：当出现严重错误时使用，但程序仍然可以继续运行，即使很可能以有限的方式运行。
*   `WARNING`：当有一个条件不是直接的问题，但如果不注意可能会导致错误时使用；例如，程序识别出一个磁盘已接近满，一些数据库连接在限制内应答，但接近超时值，以及类似的情况。
*   `INFO`：用于创建关于正常操作的消息，这些消息可能对操作很有意义，而不是错误或警告。这些消息可能有助于操作调试操作环境设置。
*   `DEBUG`：用于记录程序的信息，这些信息（希望）足够详细，以在代码中找到错误。诀窍是，当我们将日志语句放入代码中时，我们不知道它可能是什么 bug。如果我们知道，最好是修一下。
*   `TRACE`：这是关于代码执行的更详细的信息。

日志框架通常使用配置文件进行配置。配置可能会限制日志记录，关闭某些级别。在正常的操作环境中，前三级通常是开启的，`INFO`、`DEBUG`和`TRACE`在真正需要时开启。也可以只为某些记录器打开和关闭某些级别。如果我们知道错误肯定在`GameSessionSaver`类中，那么我们可以为该类打开`DEBUG`级别。

日志文件还可能包含我们没有直接编码的其他信息，打印到标准输出时会非常麻烦。通常，每条日志消息都包含创建消息的精确时间、记录器的名称，在许多情况下，还包含线程的标识符。想象一下，如果你被迫把所有这些都放到每一个参数中，你很可能很快就会写一些额外的类来做这件事。不要！它已经做了专业它是记录器框架。

记录器还可以配置为将消息发送到不同的位置。登录到控制台只是一种可能性。日志框架准备将消息发送到文件、数据库、Windows 事件记录器、SysLog 服务或任何其他目标。这种灵活性，即打印哪条消息、打印哪些额外信息以及打印到哪里，是通过按照单一责任原则将记录器框架执行的不同任务分为几个类来实现的。

记录器框架通常包含创建日志的记录器、格式化原始日志信息的消息格式器、经常添加诸如线程 ID 和时间戳等信息的记录器，以及将格式化消息附加到目标的附加程序。这些类实现了日志框架中定义的接口，除了书的大小之外，其他任何东西都无法阻止我们创建自己的格式化程序和附加程序。

配置日志时，将根据实现附加程序和格式化程序的类来配置附加程序和格式化程序。因此，当您想将一些日志发送到一个特殊的目的地时，您并不局限于框架作者提供的附加器。有许多针对不同日志框架的独立开源项目为不同的目标提供了附加器。

# 性能

使用日志框架的第二个原因是性能。虽然在我们分析代码之前优化性能（过早优化）是不好的，但是使用一种已知速度慢的方法并在性能关键代码中插入几行代码，调用慢方法也不是真正专业的。以一种行业最佳实践的方式使用一个完善的、高度优化的框架应该是无可置疑的。

使用`System.out.println()`将消息发送到流，并且仅在 IO 操作完成时返回。使用真实日志将信息处理到记录器，并允许记录器异步地进行日志记录，而不等待完成。

如果出现系统故障，日志信息可能会丢失，这确实是一个缺点，但考虑到这种情况很少发生以及性能的另一方面，这通常不是一个严重的问题。如果磁盘已满时缺少调试日志行，导致系统在任何情况下都不可用，我们会损失什么？

当出于法律原因必须保存有关系统事务的某些日志信息以便可以审核操作和实际事务时，此审核日志记录有一个例外。在这种情况下，以事务方式保存日志信息，使日志成为事务的一部分。因为这是一种完全不同的需求类型，审计日志记录通常不使用这些框架中的任何一个来完成。

而且，`System.out.println()`是不同步的，因此，不同的线程可能只会使输出混乱。日志框架关注这个问题。

# 日志框架

使用最广泛的日志框架是 **Apache log4j**。它目前有一个第二个版本，完全重写了第一个版本。它是非常多功能的，有许多附加程序和格式化程序。log4j 的配置可以是 XML 或属性文件格式，也可以通过 API 进行配置。

log4j 版本 1 的作者创建了一个新的日志框架-**slf4j**。这个日志库本质上是一个外观，可以与任何其他日志框架一起使用。因此，当您在开发的库中使用 slf4j，并且您的代码作为使用不同日志框架的依赖项添加到程序中时，很容易将 slf4j 配置为将日志发送到另一个框架的日志记录器。因此，日志将一起处理，而不是在单独的文件中，这对于降低操作成本是可取的。在开发库代码或使用 slf4j 的应用时，无需选择其他日志框架来创建 slf4j，它有自己的简单实现，称为 backlog。

ApacheCommons 日志记录也是一个有自己日志实现的立面，如果没有其他任何事情失败。与 slf4j 的主要区别在于它在配置和底层日志记录使用上更灵活，并且实现了一个运行时算法，以发现哪些日志框架可用，哪些日志框架将被使用。行业最佳实践表明，这种灵活性也具有更高的复杂性和成本，是不需要的。

# Java 日志记录

自版本 9 以来的 Java 包括一个用于日志记录的外观实现。它的应用非常简单，我们可以预期日志框架将很快开始支持这个外观。事实上，该立面内置于 JDK 中有两个主要优点：

*   想要记录的库不再需要依赖于任何日志框架或日志外观。唯一的依赖关系是 JDK 日志外观，它无论如何都在那里。
*   记录自己的 JDK 库使用这个外观，因此，它们将与应用登录到同一个日志文件中。

如果我们使用 JDK 提供的日志外观，`ColorManager`类的开头将更改为：

```java
package packt.java11.mastermind;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;
import java.lang.System.Logger;

import static java.lang.System.Logger.Level.DEBUG;

@Singleton
public class ColorManager {
    protected final int nrColors;
    protected final Map<Color, Color> successor = new HashMap<>();
    private Color first;
    private final ColorFactory factory;
    private static final Logger log
            = System.getLogger(ColorManager.class.getName());

    @Inject
    public ColorManager(@Named("nrColors") int nrColors,
                        ColorFactory factory) {
        log.log(DEBUG, "creating colorManager for {0} colors", nrColors);
        this.nrColors = nrColors;
        this.factory = factory;
        createOrdering();
    }

    private Color[] createColors() {
        var colors = new Color[nrColors];
        for (int i = 0; i < colors.length; i++) {
            colors[i] = factory.newColor();
        }
        return colors;
    }

    private void createOrdering() {
        var colors = createColors();
        first = colors[0];
        for (int i = 0; i < nrColors - 1; i++) {
            successor.put(colors[i], colors[i + 1]);
        }
    }

    public Color firstColor() {
        return first;
    }

    public boolean thereIsNextColor(Color color) {
        return successor.containsKey(color);
    }

    public Color nextColor(Color color) {
        return successor.get(color);
    }
}
```

在这个版本中，我们不导入 slf4j 类。相反，我们导入`java.lang.System.Logger`类。

注意，我们不需要导入系统类，因为来自`java.lang`包的类是自动导入的。对于在`System`类中嵌套的类，这是不正确的。

为了访问记录器，调用静态方法`System.getLogger()`。此方法查找可用的实际记录器，并为作为参数传递的名称返回一个记录器。`getLogger()`方法没有接受类作为参数的版本。如果我们想遵守约定，那么我们必须编写`ColorManager.class.getName()`来获取类的名称，或者我们可以在那里将类的名称写成一个字符串。第二种方法的缺点是它不跟随类名的更改。智能 IDE，如 IntelliJ、Eclipse 或 Netbeans，会自动重命名对类的引用，但是当在字符串中使用类名时，它们会遇到困难。

`System.Logger`接口没有声明方便方法`error`、`debug`、`warning`等，这些方法是其他日志框架和外观所熟悉的。只有一个方法名为`log()`，这个方法的第一个参数是我们发布的实际日志的级别。定义了八个级别-`ALL`、`TRACE`、`DEBUG`、`INFO`、`WARNING`、`ERROR,`和`OFF`。创建日志消息时，我们应该使用中间六个级别中的一个。`ALL`和`OFF`仅传递给`isLoggable()`方法。此方法可用于检查是否记录了实际日志记录级别。例如，如果级别设置为`INFO`，则不打印用`DEBUG`或`TRACE`发送的消息。

实际实现由 JDK 使用服务加载器功能定位。日志实现必须位于通过某种实现提供`java.lang.System.LoggerFinder`接口的模块中。换句话说，模块应该有一个实现`LoggerFinder`接口的类，`module-info.java`应该声明哪个类在使用代码：

```java
provides java.lang.System.LoggerFinder with
                            packt.java11.MyLoggerFinder;
```

`MyLoggerFinder`类必须用`getLogger()`方法扩展`LoggerFinder`抽象类。

# 日志实践

日志的实践非常简单。如果您不想花太多时间尝试不同的日志记录解决方案，并且没有特定的需求，那么只需使用 slf4j，将 JAR 作为编译依赖项添加到依赖项列表中，并开始在源代码中使用日志记录。

由于日志记录不是特定于实例的，并且日志记录器实现线程安全，所以我们通常使用的日志对象存储在一个`static`字段中，并且只要使用类，就使用它们，所以该字段也是`final`。例如，使用 slf4j 外观，我们可以使用以下命令获取记录器：

```java
private static final Logger log =
           LoggerFactory.getLogger(MastermindHandler.class);
```

要获取记录器，使用记录器工厂，它只创建记录器或返回已经可用的记录器。

变量的名称通常是`log`或`logger,`，但如果您看到`LOG`或`LOGGER`，请不要感到惊讶。将变量名大写的原因是，某些静态代码分析检查器将`static final`变量视为常量，因为它们实际上是常量，Java 社区的惯例是对这些变量使用大写名称。这是一个品味的问题；通常情况下，`log`和`logger`用小写。

为了创建日志项，`trace()`、`debug()`、`info()`、`warn()`和`error()`方法创建了一条消息，其级别如名称所示。例如，考虑以下代码行：

```java
log.debug("Adding new guess {} to the game", newGuess);
```

它创建一个调试消息。Slf4j 支持在字符串中使用`{}`文本进行格式化。这样，就不需要从小部分追加字符串，而且如果实际的日志项没有发送到日志目标，则不会执行格式化。如果我们以任何形式使用`String`连接来传递一个字符串作为参数，那么格式化就会发生，即使根据示例不需要调试日志记录。

日志记录方法的版本也只有两个参数，`String`消息和`Throwable`。在这种情况下，日志框架将负责异常的输出和栈跟踪。如果您在异常处理代码中记录了一些内容，请记录异常并让记录器格式化它。

# 其他技术

我们讨论了 Servlet 技术，一些 JavaScript、HTML 和 CSS。在真正的专业环境中编程时，通常使用这些技术。然而，应用用户界面的创建并不总是基于这些技术。较旧的操作系统本机 GUI 应用以及 Swing、AWT 和 SWT 使用不同的方法来创建 UI。它们从程序代码构建面向用户的 UI，UI 构建为组件的层次结构。当 Web 编程开始时，Java 开发人员有过类似的技术经验，项目创建的框架试图隐藏 Web 技术层。

值得一提的一项技术是 GoogleWebToolkit，它用 Java 实现服务器和浏览器代码，但由于浏览器中没有实现 Java 环境，因此它将代码的客户端部分从 Java 传输（转换）到 JavaScript。该工具包的最新版本创建于两年前的 2014 年，此后，谷歌发布了其他类型的网络编程工具包，支持原生 JavaScript、HTML 和 CSS 客户端开发。

**Vaadin** 也是你可能会遇到的工具箱。它允许您在服务器上用 Java 编写 GUI 代码。它是建立在 GWT 之上的，有商业支持。如果有开发人员在 Java 开发 GUI 方面有经验，但在 Web 原生技术方面没有经验，并且应用不需要在客户端进行特殊的可用性调优，那么这可能是一个很好的选择。典型的企业内部网应用可以选择它作为一种技术。

**JavaServer Faces**（**JSF**）是一种技术，它试图将应用的客户端开发从提供可供使用的小部件的开发人员和服务器端卸载。它是几个 **Java 规范请求**（**JSR**）的集合，有几个实现。组件及其关系在 XML 文件中配置，服务器创建客户端本机代码。在这种技术中，没有从 Java 到 JavaScript 的转换。它更像是使用一组有限但庞大的小部件，只使用那些小部件，而放弃对 Web 浏览器的直接编程。但是，如果他们有经验和知识，他们可以用 HTML、CSS 和 JavaScript 创建新的小部件。

还有许多其他技术是为支持 Java 中的 Web 应用而开发的。大多数大公司提倡的现代方法是使用单独的工具集和方法开发服务器端和客户端，并使用 REST 通信将两者连接起来。

# 总结

在本章中，您了解了 Web 编程的结构。如果不了解 TCP/IP 网络的基本知识，这是互联网的协议，这是不可能的。在此之上的应用级协议是 HTTP，目前处于非常新的版本 2.0 中，Servlet 标准版本 4.0 已经支持该协议。我们创建了一个版本的 Master 游戏，这次，可以真正使用浏览器播放，我们使用 Jetty 在开发环境中启动它。我们研究了如何存储游戏状态并实现了两个版本。最后，我们学习了日志的基本知识，并研究了其他技术。同时，我们还研究了 Google 的依赖注入实现 GUI，并研究了它在引擎盖下的工作原理，以及为什么和如何使用它。

在本章之后，您将能够开始用 Java 开发 Web 应用，并了解此类程序的架构。当您开始学习如何使用 Spring 框架来编写 Web 应用时，您将了解其中的秘密，Spring 框架隐藏了 Web 编程的许多复杂性。