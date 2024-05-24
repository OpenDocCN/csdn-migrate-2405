# Java 代码面试完全指南（二）

> 原文：[`zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36`](https://zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：算法的大 O 分析

本章将涵盖分析算法效率和可扩展性的最流行的度量标准——大 O 符号——在技术面试的背景下。

有很多文章专门讨论这个话题。其中一些是纯数学的（学术性的），而其他一些则试图以更友好的方式解释它。纯数学的方法很难理解，在面试中也不太有用，所以我们将采用更友好的方法，这将更加熟悉于面试官和开发人员。

即使如此，这并不是一项容易的任务，因为除了是衡量算法效率和可扩展性的最流行的度量标准外，大 O 符号通常也是你从未有动力学习的东西，尽管你知道它会出现在每一次面试中。从初级到高级的战士，大 O 符号可能是每个人最大的软肋。然而，让我们努力将这个软肋变成我们面试的一个强项。

我们将快速介绍大 O 符号，并强调最重要的事情。接下来，我们将深入研究精心设计的示例，涵盖各种问题，因此在本章结束时，你将能够确定并表达几乎任何给定代码的大 O。我们的议程包括以下内容：

+   类比

+   大 O 复杂度时间

+   最佳情况、最坏情况和预期情况

+   大 O 示例

所以，让我们开始我们的大 O 之旅！

# 类比

想象一种情景，你在互联网上找到了自己喜欢的电影之一。你可以订购或下载它。由于你想尽快看到它，最好的方法是什么？如果你订购，那么需要一天才能送到。如果你下载，那么需要半天的时间。所以，下载更快。这就是要走的路！

但等等！就在你准备下载时，你发现了*指环王大师收藏*，价格很优惠，所以你也考虑下载它。只是这一次，下载需要 2 天的时间。然而，如果你下订单，仍然只需要一天。所以，下订单更快！

现在，我们可以得出结论，无论我们订购多少物品，运输时间都保持不变。我们称之为 O(1)。这是一个恒定的运行时间。

此外，我们得出结论，下载时间与文件大小成正比。我们称之为 O(n)。这是一种渐近运行时间。

从日常观察中，我们还可以得出结论，网上订购比网上下载更具扩展性。

**这正是大 O 时间的含义：渐近运行时间测量或渐近函数。**

作为一种渐近测量，我们谈论的是大 O 复杂度时间（这也可以是复杂度空间）。

# 大 O 复杂度时间

以下图表显示，在某个时间点，O(n)超过了 O(1)。因此，在 O(n)超过 O(1)之前，我们可以说 O(n)的性能优于 O(1)：

![图 7.1 – 渐近运行时间（大 O 时间）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.1_B15403.jpg)

图 7.1 – 渐近运行时间（大 O 时间）

除了 O(1)——常数时间——和 O(n)——线性时间运行时间——我们还有许多其他运行时间，比如 O(log n)、O(n log n)——对数时间——O(n2)——二次时间，O(2n)——指数时间，以及 O(n!)——阶乘时间。这些是最常见的运行时间，但还有许多其他存在。

以下图表代表了大 O 复杂度图表：

![图 7.2 – 大 O 复杂度图表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.2_B15403.jpg)

图 7.2 – 大 O 复杂度图表

正如你所看到的，并非所有的 O 时间表现都相同。O(n!)、O(2n)和 O(n2)被认为是**可怕的**，我们应该努力编写超出这个范围的算法。O(n log n)比 O(n!)更好，但仍然**糟糕**。O(n)被认为是**公平的**，而 O(log n)和 O(1)被认为是**好的**。

有时，我们需要多个变量来表示运行时性能。例如，修剪足球场草坪的时间可以表示为 O（wl），其中 w 是足球场的宽度，l 是足球场的长度。或者，如果你必须修剪 p 个足球场，那么你可以表示为 O（wlp）。

然而，这并不全是关于时间。我们也关心空间。例如，构建一个包含*n*个元素的数组需要 O（n）的空间。构建一个*n* x *n*元素的矩阵需要 O（n2）的空间。

# 最佳情况、最坏情况和预期情况

如果我们简化事情，我们可以考虑算法的效率，以*最佳情况*、*最坏情况*和*预期情况*来衡量。最佳情况是当我们的算法的输入满足一些特殊条件，使其表现最佳。最坏情况是在另一个极端，输入处于不利的状态，使我们的算法表现最差。然而，通常这些惊人或可怕的情况不会发生。因此，我们引入了预期性能。

大多数情况下，我们关心最坏和预期情况，对于大多数算法来说，它们通常是相同的。最佳情况是理想的性能，因此它仍然是理想的。主要是，对于几乎任何算法，我们都可以找到一个特殊的输入，导致 O（1）的最佳情况性能。

有关 Big O 的更多细节，我强烈建议您阅读 Big O 速查表（[`www.bigocheatsheet.com/`](https://www.bigocheatsheet.com/)）。

现在，让我们来解决一堆例子。

# 大 O 的例子

我们将尝试确定不同代码片段的 Big O，就像你在面试中看到的那样，我们将经历需要学习的几个相关课程。换句话说，让我们采用*以例子学习*的方法。

前六个例子将突出 Big O 的基本规则，列举如下：

+   去掉常数

+   去掉非主导项

+   不同的输入意味着不同的变量

+   不同的步骤被求和或相乘

让我们开始尝试一些例子。

## 例 1 - O（1）

考虑以下三个代码片段并计算它们的 Big O：

```java
// snippet 1
return 23;
```

由于这段代码返回一个常数，Big O 是 O（1）。无论代码的其余部分做什么，这行代码都会以恒定的速度执行：

```java
// snippet 2 - 'cars' is an array 
int thirdCar = cars[3];
```

通过索引访问数组是以 O（1）完成的。无论数组中有多少元素，从特定索引获取元素都是一个恒定的操作：

```java
// snippet 3 - 'cars' is a 'java.util.Queue'
Car car = cars.peek();
```

`Queue#peek()`方法检索但不删除队列的头（第一个元素）。不管头部后面有多少元素，通过`peek()`方法检索头部的时间都是 O（1）。

因此，前面代码块中的所有三个代码片段都具有 O（1）的复杂度时间。同样，从队列中插入和删除，从栈中推送和弹出，插入链表中的节点，以及从数组中检索节点的左/右子节点也是 O（1）时间的情况。

## 例 2 - O（n），线性时间算法

考虑以下代码片段并计算 Big O：

```java
// snippet 1 - 'a' is an array
for (int i = 0; i < a.length; i++) {
    System.out.println(a[i]);
}
```

为了确定这段代码的 Big O 值，我们必须回答以下问题：*这个* `for` *循环迭代了多少次？*答案是`a.length`次。我们无法准确地说这意味着多少时间，但我们可以说随着给定数组的大小（表示输入），时间会线性增长。因此，这段代码将具有 O（`a.length`）时间，被称为线性时间。它表示为 O（n）。

## 例 3 - O（n），去掉常数

考虑以下代码片段并计算 Big O：

```java
// snippet 1 - 'a' is an array
for (int i = 0; i < a.length; i++) {
    System.out.println("Current element:");
    System.out.println(a[i]);
    System.out.println("Current element + 1:");
    System.out.println(a[i] + 1);
}
```

即使我们在循环中添加了更多的指令，我们仍然会像*例 2*中一样具有相同的运行时间。运行时间仍然会随着其输入`a.length`的大小呈线性增长。就像*例 2*中我们在循环中有一行代码，而在这里我们在循环中有四行代码，你可能期望大 O 是 O(n + 4)或类似的。然而，这种推理不准确或准确 - 它是错误的！这里的大 O 仍然是 O(n)。

重要说明

请记住，大 O 不取决于代码行数。它取决于运行时间的增长率，这不会被常数时间操作修改。

为了加强这种情况，让我们考虑以下两个代码片段，它们计算给定数组`a`的最小值和最大值：

![7.3 - 代码比较](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.3_B15403.jpg)

7.3 - 代码比较

那么，这两个代码片段中哪一个运行得更快？

第一个代码片段使用了一个循环，但有两个`if`语句，而第二个代码片段使用了两个循环，但每个循环中有一个`if`语句。

这样的思考方式会让人发疯！计算语句可以继续深入。例如，我们可以继续在编译器级别计算语句（操作），或者我们可能想要考虑编译器优化。嗯，这不是大 O 的意义所在！

重要说明

大 O 不是关于计算代码语句的。它的目标是表达输入大小的运行时间增长，并表达运行时间的规模。简而言之，大 O 只是描述运行时间的增长率。

此外，不要陷入这样的陷阱，认为因为第一个片段有一个循环，所以大 O 是 O(n)，而在第二个片段的情况下，因为它有两个循环，所以大 O 是 O(2n)。只需去掉 2*n*中的 2，因为 2 是一个常数！

重要说明

按照经验法则，当你表达大 O 时，去掉运行时间中的常数。

因此，前面两个代码片段都有一个大 O 值为 O(n)。

例 4 - 去掉非主导项

考虑以下代码片段并计算大 O（`a`是一个数组）：

![7.4 - 在 O(n)中执行的代码片段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.4_B15403.jpg)

7.4 - 在 O(n)中执行的代码片段

第一个`for`循环的执行时间是 O(n)，而第二个`for`循环的执行时间是 O(n2)。所以，我们可能会认为这个问题的答案是 O(n) + O(n2) = O(n + n2)。但这是不正确的！增长率由*n*2 给出，而*n*是一个非主导项。如果数组的大小增加，那么*n*2 对增长率的影响要比*n*大得多，所以*n*不相关。考虑一些更多的例子：

+   O(2n + 2n) -> 去掉常数和非主导项 -> O(2n)。

+   O(n + log n) -> 去掉非主导项 -> O(n)。

+   O(3*n2 + n + 2*n) -> 去掉常数和非主导项 -> O(n2)。

重要说明

按照经验法则，当你表达大 O 时，去掉非主导项。

接下来，让我们专注于两个常让候选人感到困惑的例子。

例 5 - 不同的输入意味着不同的变量

考虑以下两个代码片段（`a`和`b`是数组）。应该使用多少变量来表达大 O？

![7.5 - 代码片段 1 和 2](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.5_B15403.jpg)

7.5 - 代码片段 1 和 2

在第一个片段中，我们有两个`for`循环，循环同一个数组`a`（我们对两个循环都有相同的输入），所以大 O 可以表示为 O(n)，其中*n*指的是`a`。在第二个代码片段中，我们也有两个`for`循环，但它们循环不同的数组（我们有两个输入，`a`和`b`）。这次，大 O 不是 O(n)！*n*指的是`a`还是`b`？假设*n*指的是`a`。如果我们增加`b`的大小，那么 O(n)就不能反映运行时间的增长率。因此，大 O 是这两个运行时间的总和（`a`的运行时间加上`b`的运行时间）。这意味着大 O 必须指代这两个运行时间。为此，我们可以使用两个变量分别指代`a`和`b`。因此，大 O 表示为 O(a + b)。这次，如果我们增加`a`和/或`b`的大小，那么 O(a + b)就能捕捉到运行时间的增长率。

重要提示

作为一个经验法则，不同的输入意味着不同的变量。

接下来，让我们看看在添加和乘以算法步骤时会发生什么。

## 示例 6 - 不同步骤是求和还是乘积

考虑以下两个代码片段（`a`和`b`是数组）。如何为这两个片段中的每一个表达大 O？

![7.6 - 代码片段 a 和 b](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.6_B15403.jpg)

7.6 - 代码片段 a 和 b

我们已经从前面的例子中知道，在第一个片段的情况下，大 O 是 O(a + b)。我们对运行时间求和，因为它们的工作不像第二个片段那样交织在一起。所以，在第二个片段中，我们不能对运行时间求和，因为对于每个`a[i]`的情况，代码都会循环`b`数组，所以大 O 是 O(a * b)。

在决定对运行时间求和还是乘积之前三思。这是面试中常见的错误。而且，很常见的是没有注意到有多个输入（这里有两个），并错误地使用单个变量表示大 O。那是错误的！一定要注意有多少个输入。对于每个影响运行时间增长率的输入，你应该有一个单独的变量（参见*示例 5*）。

重要提示

作为一个经验法则，不同的步骤可以求和或相乘。根据以下两个陈述，运行时间应该求和或相乘：

如果你描述你的算法为**它 foos，当它完成时，它就 buzzes**，那么就对运行时间求和。

如果你描述你的算法为**每次它 foos，它就 buzzes**，那么就乘以运行时间。

现在，让我们讨论*log n*的运行时间。

## 示例 7 - 对数 n 运行时间

写一个大 O 为 O(log n)的伪代码片段。

为了理解 O(log n)的运行时间，让我们从二分搜索算法开始。二分搜索算法的详细信息和实现在*第十四章*，*排序和搜索*中可用。这个算法描述了在数组`a`中查找元素`x`的步骤。考虑一个有 16 个元素的有序数组`a`，如下所示：

![图 7.7 - 16 个元素的有序数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.7_B15403.jpg)

图 7.7 - 16 个元素的有序数组

首先，我们将`x`与数组`p`的中点进行比较。如果它们相等，那么我们将返回相应的数组索引作为最终结果。如果`x > p`，那么我们在数组的右侧搜索。如果`x < p`，那么我们在数组的左侧搜索。以下是用于查找数字 17 的二分搜索算法的图形表示：

![图 7.8 - 二分搜索算法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.8_B15403.jpg)

图 7.8 - 二分搜索算法

注意，我们从 16 个元素开始，最后剩下 1 个。第一步之后，我们剩下 16/2 = 8 个元素。第二步，我们剩下 8/2 = 4 个元素。第三步，我们剩下 4/2 = 2 个元素。然后，在最后一步，我们找到了搜索的数字 17。如果我们将这个算法转换成伪代码，那么我们得到如下内容：

```java
search 17 in {1, 4, 5, 7, 10, 16, 17, 18, 20, 
              23, 24, 25, 26, 30, 31, 33}
    compare 17 to 18 -> 17 < 18
    search 17 in {1, 4, 5, 7, 10, 16, 17, 18}
        compare 17 to 7 -> 17 > 7
        search 17 in {7, 10, 16, 17}
            compare 17 to 16 -> 17 > 16
            search 17 in {16, 17}
                compare 17 to 17
                return
```

现在，让我们为这个伪代码表示大 O。我们可以观察到，该算法由数组的连续半衰期组成，直到只剩下一个元素。因此，总运行时间取决于我们需要多少步才能在数组中找到某个数字。

在我们的例子中，我们有四步（我们将数组减半了 4 次），可以表示为以下形式：

![图 7.9 - 一般情况表达](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/01.jpg)

或者，如果我们压缩它，我们得到：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/7.09_-_02.jpg)

再进一步，我们可以将其表示为一般情况（*n*是数组的大小，*k*是达到解决方案所需的步数）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/7.09_-_03.jpg)

但是，2k = n 正是对数的意思 - *表示必须提高一个固定数字（底数）的幂以产生给定数字的数量*。因此，我们可以写成如下形式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/7.09_-_04.jpg)

在我们的情况下，2k = *n*意味着 24 = 16，即 log216 = 4。

因此，二分搜索算法的大 O 是 O(log n)。然而，对数的底在哪里？简短的答案是，对数的底不需要用于表示大 O，因为不同底数的对数只相差一个常数因子。

重要说明

作为一个经验法则，当你必须为一个在每一步/迭代中将其输入减半的算法表示大 O 时，它很有可能是 O(log n)的情况。

接下来，让我们谈谈递归运行时间的大 O 评估。

示例 8 - 递归运行时间

以下是代码片段的大 O 是多少？

```java
int fibonacci(int k) {
    if (k <= 1) {
        return k;
    }
    return fibonacci(k - 2) + fibonacci(k - 1);
}
```

在我们的第一印象中，我们可能将大 O 表示为 O(n2)。很可能，我们会得出这个结果，因为我们被`return`中`fibonacci()`方法的两次调用所误导。然而，让我们给*k*赋值并快速勾画运行时。例如，如果我们调用`fibonacci(7)`并将递归调用表示为一棵树，那么我们会得到以下图表：

![图 7.9 - 调用树](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.10_B15403.jpg)

图 7.9 - 调用树

我们几乎立即注意到这棵树的深度等于 7，因此一般树的深度等于*k*。此外，除了终端级别外，每个节点都有两个子节点，因此几乎每个级别的调用数量都是上面一个级别的两倍。这意味着我们可以将大 O 表示为 O(分支深度)。在我们的情况下，这是 O(2k)，表示为 O(2n)。

在面试中，只说 O(2n)应该是可以接受的答案。如果我们想更准确，那么我们应该考虑终端级别，特别是最后一级（或调用堆栈的底部），有时可能只包含一个调用。这意味着我们并不总是有两个分支。更准确的答案应该是 O(1.6n)。提到实际值小于 2 应该足够让任何面试官满意。

如果我们想以空间复杂度的术语来表示大 O，那么我们得到 O(n)。不要被运行时复杂度为 O(2n)所迷惑。在任何时刻，我们不能有超过*k*个数字。如果我们看看前面的树，我们只能看到从 1 到 7 的数字。

## 示例 9 - 二叉树的中序遍历

考虑一个给定的完美二叉搜索树。如果你需要快速回顾二叉树，那么请考虑*第十三章**,* *树和图*的*概要*部分。以下是代码片段的大 O 是多少？

```java
void printInOrder(Node node) {
    if (node != null) {
       printInOrder(node.left);
       System.out.print(" " + node.element);
       printInOrder(node.right);
    }
}
```

完美的二叉搜索树是一棵二叉搜索树，其内部节点恰好有两个子节点，所有叶节点都在同一级别或深度上。在下面的图表中，我们有一棵典型的完美二叉搜索树（再次，可视化运行时输入非常有用）：

![图 7.10 - 高度平衡的二叉搜索树](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.11_B15403.jpg)

图 7.10 - 高度平衡的二叉搜索树

我们从经验中知道（更确切地说，从前面的例子中知道），当我们面对一个具有分支的递归问题时，我们可能会有一个 O(分支深度)的情况。在我们的情况下，我们有两个分支（每个节点有两个子节点），因此我们有 O(2 深度)。指数时间看起来很奇怪，但让我们看看节点数量和深度之间的关系。在前面的图表中，我们有 15 个节点，深度为 4。如果我们有 7 个节点，那么深度将是 3，如果我们有 31 个节点，那么深度将是 5。现在，如果我们不知道理论上完美二叉树的深度是对数的，那么也许我们可以观察以下内容：

+   对于 15 个节点，我们有 4 层深度；因此，我们有 24 = 16，相当于 log216 = 4。

+   对于 7 个节点，我们有 3 层深度；因此，我们有 23 = 8，相当于 log28 = 3。

+   对于 31 个节点，我们有 5 层深度；因此，我们有 25 = 32，相当于 log232 = 5。

根据前面的观察，我们可以得出结论，我们可以将大 O 表示为 O(2log n)，因为深度大约是*log n*。因此，我们可以写成以下形式：

![图 7.11 – 大 O 表达式](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/7-3.jpg)

图 7.11 – 大 O 表达式

因此，在这种情况下，大 O 是 O(n)。如果我们意识到这段代码实际上是二叉树的中序遍历，我们也可以得出相同的结论，在这种遍历中（正如前序遍历和后序遍历一样），每个节点只被访问一次。此外，对于每个遍历的节点，有一个恒定的工作量，因此大 O 是 O(n)。

## 示例 10 – n 可能变化

以下代码片段的大 O 是多少？

```java
void printFibonacci(int k) {
    for (int i = 0; i < k; i++) {
        System.out.println(i + ": " + fibonacci(i));
    }
}
int fibonacci(int k) {
    if (k <= 1) {
        return k;
    }
    return fibonacci(k - 2) + fibonacci(k - 1);
}
```

从*示例 8*中，我们已经知道`fibonacci()`方法的大 O 值为 O(2n)。`printFibonacci()`调用`fibonacci()`*n*次，因此很容易将总的大 O 值表示为 O(n)*O(2n) = O(n2n)。然而，这是真的吗，还是我们匆忙给出了一个表面上容易的答案？

嗯，这里的诀窍是*n*是变化的。例如，让我们来可视化运行时间：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.11.1_B15403.jpg)

我们不能说我们执行相同的代码*n*次，因此这是 O(2n)。

## 示例 11 – 记忆化

以下代码片段的大 O 是多少？

```java
void printFibonacci(int k) {
    int[] cache = new int[k];
    for (int i = 0; i < k; i++) {
        System.out.println(i + ": " + fibonacci(i, cache));
    }
}
int fibonacci(int k, int[] cache) {
    if (k <= 1) {
        return k;
    } else if (cache[k] > 0) {
        return cache[k];
    }
    cache[k] = fibonacci(k - 2, cache) 
        + fibonacci(k - 1, cache);
    return cache[k];
}
```

这段代码通过递归计算斐波那契数。然而，这段代码使用了一种称为*记忆化*的技术。主要思想是缓存返回值并使用它来减少递归调用。我们已经从*示例 8*中知道`fibonacci()`方法的大 O 是 O(2n)。由于*记忆化*应该减少递归调用（它引入了一种优化），我们可以猜测这段代码的大 O 应该比 O(2n)好。然而，这只是一种直觉，所以让我们来可视化*k* = 7 的运行时间：

```java
Calling fibonacci(0):
Result of fibonacci(0) is 0
Calling fibonacci(1):
Result of fibonacci(1) is 1
Calling fibonacci(2):
 fibonacci(0)
 fibonacci(1)
 fibonacci(2) is computed and cached at cache[2]
Result of fibonacci(2) is 1
Calling fibonacci(3):
 fibonacci(1)
 fibonacci(2) is fetched from cache[2] as: 1
 fibonacci(3) is computed and cached at cache[3]
Result of fibonacci(3) is 2
Calling fibonacci(4):
 fibonacci(2) is fetched from cache[2] as: 1
 fibonacci(3) is fetched from cache[3] as: 2
 fibonacci(4) is computed and cached at cache[4]
Result of fibonacci(4) is 3
Calling fibonacci(5):
 fibonacci(3) is fetched from cache[3] as: 2
 fibonacci(4) is fetched from cache[4] as: 3
 fibonacci(5) is computed and cached at cache[5]
Result of fibonacci(5) is 5
Calling fibonacci(6):
 fibonacci(4) is fetched from cache[4] as: 3
 fibonacci(5) is fetched from cache[5] as: 5
 fibonacci(6) is computed and cached at cache[6]
Result of fibonacci(6) is 8
```

每个`fibonacci(k)`方法都是从缓存的`fibonacci(k-1)`和`fibonacci(k-2)`方法计算出来的。从缓存中获取计算出的值并对它们求和是一个恒定的工作量。由于我们这样做了*k*次，这意味着大 O 可以表示为 O(n)。

除了*记忆化*，我们还可以使用另一种方法，称为*表格法*。更多细节请参阅*第八章*，*递归和动态规划*。

示例 12 – 循环矩阵的一半

以下两个代码片段（`a`是一个数组）的大 O 是多少？

![7.12 – 大 O 的代码片段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.12_B15403.jpg)

7.12 – 大 O 的代码片段

这些代码片段几乎是相同的，只是在第一个片段中，`j`从`0`开始，而在第二个片段中，它从`i+1`开始。

我们可以很容易地给出数组大小的值，并可视化这两个代码片段的运行时间。例如，让我们假设数组大小为 5。左侧矩阵是第一个代码片段的运行时间，而右侧矩阵对应于第二个代码片段的运行时间：

![图 7.13 – 可视化运行时间](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.14_B15403.jpg)

图 7.13 – 可视化运行时间

与第一段代码对应的矩阵显示了一个*n*n*大小，而与第二段代码对应的矩阵大致显示了一个*n*n*/2 大小。因此，我们可以写成以下形式：

+   代码段 1 的运行时间是：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Snippets_01.png)。

+   代码段 2 的运行时间是：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Snippets_02.png) 因为我们消除了常数。

因此，这两段代码的时间复杂度都是 O(n2)。

或者，你可以这样想：

+   对于第一个代码段，内部循环不做任何工作，外部循环运行了*n*次，所以*n*n = n*2，结果是 O(n2)。

+   对于第二段代码，内部循环大致做了*n*/2 的工作，并且外部循环运行了*n*次，所以*n*n*/2 = *n*2/2 = *n*2 * 1/2，去除常数后得到 O(n2)。

## 示例 13 - 识别 O(1)循环

以下代码段的大 O 是多少（`a`是一个数组）？

```java
for (int i = 0; i < a.length; i++) {
    for (int j = 0; j < a.length; j++) {
        for (int q = 0; q < 1_000_000; q++) {
            System.out.println(a[i] + a[j]);
        }
    }
}
```

如果我们忽略第三个循环（`q`循环），那么我们已经知道大 O 是 O(n2)。那么第三个循环如何影响总的大 O 值呢？第三个循环独立于数组大小，迭代从 0 到 100 万，因此这个循环的大 O 是 O(1)，是一个常数。由于第三个循环不依赖于输入大小的变化，我们可以写成以下形式：

```java
for (int i = 0; i < a.length; i++) {
    for (int j = 0; j < a.length; j++) {
        // O(1)  
    }
}
```

现在，很明显这个例子的大 O 是 O(n2)。

## 示例 14 - 循环数组的一半

以下代码段的大 O 是多少（`a`是一个数组）？

```java
for (int i = 0; i < a.length / 2; i++) {
    System.out.println(a[i]);
}
```

这里可能会引起混淆，因为这段代码只循环了数组的一半。不要犯将大 O 表达为 O(n/2)的常见错误。记住常数应该被去除，所以大 O 是 O(n)。只迭代数组的一半不会影响大 O 时间。

## 示例 15 - 减少大 O 表达式

以下哪个可以表示为 O(n)？

+   O(n + p)

+   O(n + log n)

答案是 O(n + log n)可以简化为 O(n)，因为*log* *n*是一个非主导项，可以被去除。另一方面，O(n + p)不能简化为 O(n)，因为我们不知道*p*的情况。在我们确定*p*是什么以及*n*和*p*之间的关系之前，我们必须保留它们两个。

## 示例 16 - 具有 O(log n)的循环

以下代码段的大 O 是多少（`a`是一个数组）？

```java
for (int i = 0; i < a.length; i++) {
    for (int j = a.length; j > 0; j /= 2) {
        System.out.println(a[i] + ", " + j);
    }
}
```

让我们只关注外部循环。根据之前示例的经验，我们可以迅速将大 O 表达为 O(n)。

内部循环呢？我们可以注意到`j`从数组长度开始，并且在每次迭代时减半。记住*示例 7*中的重要说明：*当你必须为每一步减半的算法表达大 O 时，很可能是 O(log n)的情况*。

重要说明

每当你认为这很可能是 O(log n)的情况时，建议使用除数的幂的测试数字。如果输入被除以 2（被减半），那么使用除数的幂的数字（例如，23 = 8，24 = 16，25 = 32 等）。如果输入被除以 3，那么使用除数的幂的数字（例如，32 = 9，33 = 27 等）。这样，很容易计算除法的次数。

因此，让我们给`a.length`赋值并可视化运行时间。假设`a.length`是 16。这意味着`j`将取 12、8、4、2 和 1 的值。我们已经将`j`除以 2 四次，所以有以下结果：

![图 7.14 - 具有 O(log n)的循环](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.15_Loop_with_O_(log_n).jpg)

图 7.14 - 具有 O(log n)的循环

因此，内部循环的大 O 是 O(log n)。为了计算总的大 O，我们考虑外部循环执行了*n*次，在这个循环内，另一个循环执行了*log* *n*次。因此，总的大 O 结果是 O(n)* O (log n) = O(n log n)。

作为提示，许多排序算法（例如，归并排序和堆排序）具有 O(n log n)的运行时间。 此外，许多 O(n log n)算法是递归的。 一般来说，属于**分而治之**（**D&C**）类别的算法是 O(n log n)。 希望记住这些提示在面试中会非常有用。

## 示例 17 – 字符串比较

以下代码片段的大 O 是多少？（注意`a`是一个数组，请仔细阅读注释）：

```java
String[] sortArrayOfString(String[] a) {
    for (int i = 0; i < a.length; i++) {
        // sort each string via O(n log n) algorithm           
    }
    // sort the array itself via O(n log n) algorithm               
    return a;
}
```

`sortArrayOfString()`接收一个`String`数组并执行两个主要操作。 它对该数组中的每个字符串和数组本身进行排序。 这两种排序都是通过运行时表达为 O(n log n)的算法完成的。

现在，让我们专注于`for`循环，并看看候选人通常给出的错误答案。 我们已经知道对单个字符串进行排序会给我们带来 O(n log n)。 对每个字符串进行这样的操作意味着 O(n) * (n log n) = O(n*n log n) = O(n2 log n)。 接下来，我们对数组本身进行排序，这也表示为 O(n log n)。 将所有结果放在一起，总的大 O 值是 O(n2 log n) + O(n log n) = O(n2 log n + n log n)，这是 O(n2 log n)，因为*n* *log* *n*是一个非主导项。 但是，这是正确的吗？ 简短的答案是否定的！ 但为什么不是呢？ 我们犯了两个主要错误：我们使用*n*来表示两个东西（数组的大小和字符串的长度），并且我们假设比较`String`需要一个常数时间，就像对于固定宽度的整数一样。

让我们详细说明第一个问题。 因此，对单个字符串进行排序会给我们带来 O(n log n)，其中*n*代表该字符串的长度。 我们对`a.length`个字符串进行排序，所以*n*现在代表数组的大小。 这就是混淆的原因，因为当我们说`for`循环是 O(n2 log n)时，我们指的是哪个*n*？ 由于我们正在处理两个变量，我们需要以不同的方式表示它们。 例如，我们可以考虑以下内容：

+   *s*：最长`String`的长度。

+   *p*：`String`数组的大小。

用这些术语来说，对单个字符串进行排序是 O(s log s)，这样做*p*次的结果是 O(p)*O(s log s) = O(p*s log s)。

现在，让我们解决第二个问题。 用我们的新术语来说，对数组进行排序是 O(p log p) – 我刚刚用*p*替换了*n*。 但是，`String`的比较是否需要像固定宽度整数一样的常数时间呢？ 答案是否定的！ `String`排序改变了 O(p log p)，因为`String`比较本身具有可变成本。 `String`的长度是变化的，因此比较时间也是变化的。 因此，在我们的情况下，每个`String`比较都需要 O(s)，由于我们有 O(p log p)次比较，结果是对字符串数组进行排序是 O(s) * O(p log p) = O(s*p log p)。

最后，我们必须将 O(p*s log s)加到 O(s*p log p)上= O(s*p(log s + log p))。 完成！

## 示例 18 – 阶乘的大 O

以下代码片段的大 O 是多少？

```java
long factorial(int num) {
    if (num >= 1) {
        return num * factorial(num - 1);
    } else {
        return 1;
    }
}
```

很明显，这段代码是计算阶乘的递归实现。 不要犯认为大 O 是 O(n!)的常见错误。 这是不正确的！ 要仔细分析代码，不要提前假设。

递归过程遍历序列*n*–1，*n*–2，... 1 次；因此，这是 O(n)。

## 示例 19 – 谨慎使用 n 符号

以下两个代码片段的大 O 是多少？

![7.15 – 代码片段](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_7.15_B15403.jpg)

7.15 – 代码片段

左侧的第一个代码片段对`y`次进行了常量工作。 `x`输入不会影响运行时间的增长速度，因此大 O 可以表示为 O(y)。 请注意，我们不说 O(n)，因为*n*也可能与`x`混淆。

第二个代码片段（在右侧）递归遍历`y`-1、`y`-2、...、0。每个`y`输入只遍历一次，因此大 O 可以表示为 O（y）。再次强调，`x`输入不会影响运行时间的增长率。此外，我们避免说 O（n），因为有多个输入，O（n）会引起混淆。

例 20 - 总和和计数

以下代码片段的大 O 是多少（`x`和`y`为正数）？

```java
int div(int x, int y) {
    int count = 0;
    int sum = y;
    while (sum <= x) {
       sum += y;
       count++;
    }
    return count;
}
```

让我们给`x`和`y`赋值，并观察`count`变量，该变量计算迭代次数。考虑`x`=10 和`y`=2。对于这种情况，`count`将为 5（10/2 = 5）。按照相同的逻辑，我们有`x`=14，`y`=4，`count`=3（14/4 = 3.5），或`x`=22，`y`=3，或`count`=7（22/3 = 7.3）。我们可以注意到，在最坏的情况下，`count`是`x`/`y`，因此大 O 可以表示为 O（x/y）。

## 示例 21 - 大 O 中的迭代计数

以下代码片段尝试猜测一个数字的平方根。大 O 是多少？

```java
int sqrt(int n) {
    for (int guess = 1; guess * guess <= n; guess++) {
        if (guess * guess == n) {
            return guess;
        }
    }
    return -1;
}
```

让我们假设数字（`n`）是一个完全平方根，例如 144，我们已经知道 sqrt（144）= 12。由于`guess`变量从 1 开始，并在`guess*guess <= n`时停止，步长为 1，因此很容易计算出`guess`将取值 1、2、3、...，12。当`guess`为 12 时，我们有 12*12 = 144，循环停止。因此，我们有 12 次迭代，这恰好是 sqrt（144）。

我们对非完全平方根采用相同的逻辑。假设`n`是 15。这次，`guess`将取 1、2 和 3 的值。当`guess`=4 时，我们有 4*4 > 15，循环停止。返回值为-1。因此，我们有 3 次迭代。

总之，我们有 sqrt（`n`）次迭代，因此大 O 可以表示为 O（sqrt（n））。

## 示例 22 - 数字

以下代码片段总结了整数的数字。大 O 是多少？

```java
int sumDigits(int n) {
    int result = 0;
    while (n > 0) {
        result += n % 10;
        n /= 10;
    }
    return result;
}
```

在每次迭代中，`n`被 10 除。这样，代码会将数字的右侧孤立出来（例如，56643/10 = 5664.3）。为了遍历所有数字，`while`循环需要的迭代次数等于数字的位数（例如，对于 56,643，它需要 5 次迭代来孤立 3、4、6、6 和 5）。

然而，一个有 5 位数字的数字可以达到 105 = 100,000，这意味着 99,999 次迭代。一般来说，这意味着一个具有*d*位数的数字（`n`）可以达到 10d。因此，我们可以说以下内容：

![图 7.16 - 数字关系](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/7-2.jpg)

图 7.16 - 数字关系

## 示例 23 - 排序

以下代码片段的大 O 是多少？

```java
boolean matching(int[] x, int[] y) {
    mergesort(y);
    for (int i : x) {
        if (binarySearch(y, i) >= 0) {
            return true;
        }
    }
    return false;
}
```

在*示例 16*中，我们说很多排序算法（包括归并排序）的运行时间为 O（n log n）。这意味着`mergesort(y)`的运行时间为 O（y log y）。

在*E**xample 7*中，我们说二分搜索算法的运行时间为 O（log n）。这意味着`binarySearch(y, i)`的运行时间为 O（log y）。在最坏的情况下，`for`循环将遍历整个`x`数组，因此二分搜索算法将被执行`x.length`次。`for`循环的运行时间为 O（x log y）。

因此，总的大 O 值可以表示为 O（y log y）+ O（x log y）= O（y log y + x log y）。

完成！这是这里介绍的最后一个示例。接下来，让我们尝试提取几个关键提示，这些提示可以帮助你在面试中确定和表达大 O。

# 面试中要寻找的关键提示

在面试中，时间和压力是可以影响集中力的严重因素。具有识别模板、识别特定情况、猜测正确答案等能力会给你带来重大优势。正如我们在*第五章*中所述，*如何应对编码挑战*，在*图 5.2*中，构建示例（或用例）是应对编码挑战的第二步。即使面试官提供了代码，构建示例对于确定大 O 仍然非常有用。

您可能已经注意到，在我们涵盖的几乎每个非平凡示例中，我们更喜欢为一个或多个具体案例可视化运行时间。这样，您可以真正理解代码的细节，识别输入，确定代码的静态（常数）和动态（变量）部分，并对代码的工作方式有一个总体了解。

以下是一些关键提示的非尽事项清单，可以帮助您在面试中：

+   `x`，`y`和`w`，并进行一些计算，比如`x-y`和`y*w`）。在某些情况下，为了制造混淆，它还会添加重复的语句（例如，计算是在`for(int i=0; i<10; i++)`中完成的）。因此，从一开始就确定算法的输入是否影响其运行时间非常重要。

+   `for(int i=0; i<a.length; i++)`，其中`a`是一个数组）。通常，这些结构的运行时间为 O(n)。在某些情况下，为了制造混淆，重复的结构会添加一个验证`break`语句的条件。请记住，大 O 是关于最坏情况的，因此您应该评估运行时间时要牢记验证`break`语句的条件可能永远不会发生，而大 O 仍然是 O(n)。

+   **如果在每次迭代中，算法将输入数据减半，则总体大 O 值可能涉及 O(log n)**：正如您在*示例 7*中看到的，二分查找算法是 O(log n)的著名案例。通常，您可以通过尝试可视化运行时间来识别类似的情况。

+   **具有分支的递归问题是 O(分支**深度**)可能是总体大 O 值的一个很好的信号**：O(2^深度)遇到的最常见情况是在操纵二叉树的代码片段中。还要注意如何确定*深度*。正如您在*示例 9*中看到的，*深度*可以影响最终结果。在那种情况下，O(2log n)被降低为 O(n)。

+   **使用记忆化或表格法的递归算法是具有 O(n)作为其总体大 O 值的良好候选**：通常，递归算法暴露出指数运行时间（例如，O(2^n)），但是优化，如*记忆化*和*表格法*可以将运行时间降低到 O(n)。

+   **排序算法通常在总体大 O 值中引入 O(n log n)**：请记住，许多排序算法（例如，堆排序，归并排序等）的运行时间为 O(n log n)。

希望这些提示能帮助您，因为我们已经涵盖了一些经过充分验证的例子。

# 总结

在本章中，我们涵盖了面试中最主要的话题之一，即大 O。有时，您将不得不确定给定代码的大 O，而其他时候，您将不得不确定自己的代码的大 O。换句话说，在面试中几乎没有绕过大 O 的机会。无论您如何努力训练，大 O 始终是一个难题，即使是最优秀的开发人员也可能遇到困难。幸运的是，这里涵盖的情况是面试中最受欢迎的，并且它们代表了许多派生问题的完美模板。

在下一章中，我们将解决面试中其他受欢迎的话题：递归和动态规划。


# 第八章：递归和动态规划

本章涵盖了面试官最喜欢的主题之一：递归和动态规划。两者密切相关，因此您必须能够同时掌握两者。通常，面试官希望看到纯递归解决方案。但是，他们可能要求您提供一些优化提示，甚至编写代码的优化版本。换句话说，您的面试官希望看到动态规划的工作。

在本章中，我们将涵盖以下主题：

+   简而言之，递归

+   简而言之，动态规划

+   编码挑战

本章结束时，您将能够实现各种递归算法。您将拥有大量递归模式和方法，可以在几分钟内识别和实现递归算法。让我们从我们议程的第一个主题开始：递归。

# 技术要求

您可以在 GitHub 上找到本章中提供的所有代码[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter08`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter08)。

# 简而言之，递归

直接/间接调用自身的方法称为递归。这种方法称为递归方法。著名的斐波那契数问题可以按照以下方式进行递归实现：

```java
int fibonacci(int k) {
    // base case
    if (k <= 1) {
        return k;
    }
    // recursive call
    return fibonacci(k - 2) + fibonacci(k - 1);
}
```

这段代码中有两个重要部分：

+   **基本情况**：在没有后续递归调用的情况下返回一个值。对于特殊的输入，函数可以在没有递归的情况下进行评估。

+   `fibonacci()`方法调用自身，我们有一个递归方法。

## 识别递归问题

在尝试通过递归算法解决问题之前，我们必须将其识别为适合这种算法的良好候选。面试中使用的大多数递归问题都很有名，因此我们可以通过名称来识别它们。例如，斐波那契数、对列表中的数字求和、最大公约数、阶乘、递归二分查找、字符串反转等问题都是众所周知的递归问题。

但是，所有这些问题有什么共同之处呢？一旦我们知道了这个问题的答案，我们将能够识别其他递归问题。答案非常简单：所有这些问题都可以建立在子问题的基础上。换句话说，我们可以说我们可以用方法返回的其他值来表示方法返回的值。

重要提示

当问题可以建立在子问题的基础上时，它是适合递归解决的良好候选。通常，这类问题包括诸如*列出前/后 n 个...，计算第 n 个...或所有...，计算所有解...，生成所有情况...*等词语。为了计算*第 n 个*...，我们必须计算*f(n-1)*、*f(n-2)*等，以便将问题分解为子问题。换句话说，计算*f(n)*需要计算*f(n-1)*、*f(n-2)*等。*练习*是识别和解决递归问题的关键词。解决大量递归问题将帮助您像眨眼一样轻松地识别它们。

接下来，我们将重点介绍动态规划的主要方面，并学习如何通过动态规划优化纯递归。

# 简而言之，动态规划

当我们谈论优化递归时，我们谈论动态规划。这意味着可以使用纯递归算法或动态规划来解决递归问题。

现在，让我们将动态规划应用于斐波那契数，从简单的递归算法开始：

```java
int fibonacci(int k) {
    if (k <= 1) {
        return k;
    }
    return fibonacci(k - 2) + fibonacci(k - 1);
}
```

斐波那契数的纯递归算法的运行时间为 O(2n)，空间复杂度为 O(n) - 您可以在*第七章**，算法的大 O 分析*中找到解释。如果我们设置*k*=7，并将调用堆栈表示为调用树，则我们将获得以下图表：

![图 8.1 - 调用树（纯递归）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.1_B15403.jpg)

图 8.1 - 调用树（普通递归）

如果我们检查*第七章**，算法的大 O 分析*中的大 O 图表，我们会注意到 O(2n)远非高效。指数运行时间适合大 O 图表的**可怕**区域。我们能做得更好吗？是的，通过*备忘录*方法。

## 备忘录（或自顶向下的动态规划）

当一个递归算法对相同的输入进行重复调用时，这表明它执行了重复的工作。换句话说，递归问题可能存在重叠子问题，因此解决方案的路径涉及多次解决相同的子问题。例如，如果我们重新绘制斐波那契数的调用树，并突出显示重叠的问题，那么我们会得到以下图表：

![图 8.2 - 调用树（重复工作）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.2_B15403.jpg)

图 8.2 - 调用树（重复工作）

很明显，超过一半的调用是重复的调用。

*备忘录*是一种用于消除方法中重复工作的技术。它保证一个方法只对相同的输入调用一次。为了实现这一点，*备忘录*缓存了给定输入的结果。这意味着，当方法应该被调用来计算已经计算过的输入时，*备忘录*将通过从缓存中返回结果来避免这次调用。

以下代码使用*备忘录*来优化斐波那契数的普通递归算法（缓存由`cache`数组表示）：

```java
int fibonacci(int k) {
    return fibonacci(k, new int[k + 1]);
}
int fibonacci(int k, int[] cache) {
    if (k <= 1) {
        return k;
    } else if (cache[k] > 0) {
        return cache[k];
    }
    cache[k] = fibonacci(k - 2, cache) 
        + fibonacci(k - 1, cache);
    return cache[k];
}
```

如果我们重新绘制前面代码的调用树，那么我们会得到以下图表：

![图 8.3 - 调用树（备忘录）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.3_B15403.jpg)

图 8.3 - 调用树（备忘录）

在这里，很明显*备忘录*大大减少了递归调用的次数。这次，`fibonacci()`方法利用了缓存的结果。运行时间从 O(2n)降低到 O(n)，因此从指数降低到多项式。

重要说明

*备忘录*也被称为*自顶向下*方法。*自顶向下*方法并不直观，因为我们立即开始开发最终解决方案，解释我们如何从较小的解决方案中开发它。这就像说以下内容：

*我写了一本书。怎么写的？我写了它的章节。怎么写的？我写了每个章节的部分。怎么写的？我写了每个部分的段落*。

空间复杂度仍然是 O(n)。我们能改进吗？是的，通过*Tabulation*方法。

## Tabulation（或自底向上的动态规划）

*Tabulation*，或*自底向上*方法，比*自顶向下*更直观。基本上，递归算法（通常）从末尾开始向后工作，而*自底向上*算法从一开始就开始。*自底向上*方法避免了递归并改进了空间复杂度。

**重要说明**

*Tabulation*通常被称为*自底向上*方法。自底向上是一种避免递归并且相当自然的方法。就像说以下内容：

*我写了每个部分的段落。然后呢？然后我写了每个章节的部分。然后呢？然后我写了所有的章节。然后呢？然后我写了一本书。*

*自底向上*减少了递归构建调用栈时所施加的内存成本，这意味着*自底向上*消除了发生堆栈溢出错误的脆弱性。如果调用栈变得太大并且空间不足，就可能发生这种情况。

例如，当我们通过递归方法计算`fibonacci(k)`时，我们从*k*开始，然后继续到*k*-1，*k*-2，依此类推直到 0。通过*自底向上*方法，我们从 0 开始，然后继续到 1，2 等，直到*k*。如下代码所示，这是一种迭代方法：

```java
int fibonacci(int k) {
    if (k <= 1) {
        return k;
    }
    int first = 1;
    int second = 0;
    int result = 0;
    for (int i = 1; i < k; i++) {
        result = first + second;
        second = first;
        first = result;
    }
    return result;
}
```

该算法的运行时间仍然是 O(n)，但空间复杂度已从 O(n)降低到 O(1)。因此，总结斐波那契数算法，我们有以下内容：

+   普通递归算法的运行时间为 O(2n)，空间复杂度为 O(n)。

+   备忘录递归算法的运行时间为 O(n)，空间复杂度为 O(n)。

+   制表法算法的运行时间为 O(n)，空间复杂度为 O(1)。

现在，是时候练习一些编码挑战了。

# 编码挑战

在接下来的 15 个编码挑战中，我们将利用递归和动态规划。这些问题经过精心设计，旨在帮助您理解和解决这一类别中的各种问题。在本编码挑战会话结束时，您应该能够在面试环境中识别和解决递归问题。

## 编码挑战 1 - 机器人网格（I）

Adobe，Microsoft

问题：我们有一个*m* x *n*网格。一个机器人被放置在这个网格的左上角。机器人只能在任何时候向右或向下移动，但不允许移动到某些单元格。机器人的目标是找到从网格的左上角到右下角的路径。

解决方案：首先，我们需要设置*m* x *n*网格的一些约定。假设右下角的坐标为(0, 0)，而左上角的坐标为(*m, n*)，其中*m*是网格的行，*n*是网格的列。因此，机器人从(*m, n*)开始，必须找到一条到(0, 0)的路径。如果我们尝试为一个 6x6 网格绘制一个示例，那么我们可以得到如下的东西：

![图 8.4 - 确定移动模式](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.4_B15403.jpg)

图 8.4 - 确定移动模式

在这里，我们可以看到机器人可以从一个单元格(*m, n*)到相邻的单元格，可以是(*m*-1*, n*)或(*m, n*-1)。例如，如果机器人放置在(5, 5)，那么它可以到达(4, 5)或(5, 4)。此外，从(4, 5)，它可以到达(3, 5)或(4, 4)，而从(5, 4)，它可以到达(5, 3)或(4, 4)。

所以，我们有一个可以分解成子问题的问题。我们必须找到单元格的最终路径（问题），如果我们能找到到相邻单元格的路径（子问题），我们就可以做到这一点。这听起来像是一个递归算法。在递归中，我们从上到下解决问题，所以我们从(*m, n*)开始，然后回到原点(0, 0)，如前面的图表所示。这意味着从单元格(*m, n*)，我们尝试进入(*m, n*-1)或(*m*-1*, n*)。

将这个问题转化为代码可以这样做（`maze[][]`矩阵是一个`boolean`矩阵，对于我们不允许进入的单元格具有`true`的值 - 例如，`maze[3][1] = true`表示我们不允许进入单元格(3,1)）：

```java
public static boolean computePath(int m, int n, 
      boolean[][] maze, Set<Point> path) {
    // we fell off the grid so we return
    if (m < 0 || n < 0) {
        return false;
    }
    // we cannot step at this cell
    if (maze[m][n]) {
        return false;
    }
    // we reached the target 
    // (this is the bottom-right corner)    
    if (((m == 0) && (n == 0))                  
       // or, try to go to the right     
       || computePath(m, n - 1, maze, path)    
       // or, try to go to down
       || computePath(m - 1, n, maze, path)) { 
        // we add the cell to the path
        path.add(new Point(m, n));
        return true;
    }
    return false;
}
```

返回的路径存储为`LinkedHashSet<Point>`。每条路径包含*m+n*步，每一步我们只能做两个有效的选择；因此，运行时间为 O(2m+n)。但是，如果我们缓存了失败的单元格（返回`false`），我们可以将这个运行时间减少到 O(mn)。这样，*备忘录*方法可以避免机器人多次尝试进入一个失败的单元格。完整的应用程序称为*RobotGridMaze*。它还包含了*备忘录*代码。

使用机器人的另一个流行问题如下。假设我们有一个*m* x *n*网格。一个机器人被放置在这个网格的左上角。机器人只能在任何时候向右或向下移动。机器人的目标是找到从网格的左上角到右下角的所有唯一路径。

普通递归解决方案和自底向上方法都包含在*RobotGridAllPaths*应用程序中。

编码挑战 2 - 汉诺塔

**问题**：这是一个经典问题，可能随时在面试中出现。汉诺塔是一个有三根杆（*A*，*B*和*C*）和*n*个磁盘的问题。最初，所有的磁盘都按升序放置在一个杆上（最大的磁盘在底部（磁盘*n*），一个较小的磁盘放在它上面（*n*-1），依此类推（*n*-2，*n*-3，...）直到最小的磁盘在顶部（磁盘 1）。目标是将所有的磁盘从这根杆移动到另一根杆，同时遵守以下规则：

+   一次只能移动一个磁盘。

+   一次移动意味着将顶部的磁盘从一个杆滑动到另一个杆。

+   一个磁盘不能放在比它更小的磁盘上。

**解决方案**：尝试解决这样的问题意味着我们需要可视化一些情况。让我们假设我们想要将磁盘从杆*A*移动到杆*C*。现在，让我们在杆*A*上放置*n*个磁盘：

对于*n=*1：有一个单独的磁盘，我们需要将一个磁盘从杆*A*移动到*C*。

对于*n=*2：我们知道如何移动一个单独的磁盘。为了移动两个磁盘，我们需要完成以下步骤：

1.  将磁盘 1 从*A*移动到*B*（杆*B*作为磁盘 1 的中间杆）。

1.  将磁盘 2 从*A*移动到*C*（磁盘 2 直接移动到最终位置）。

1.  将磁盘 1 从*B*移动到*C*（磁盘 1 可以移动到杆*C*上的磁盘 2 上）。

对于*n=*3：让我们从以下图表中获得一些帮助：

![图 8.5 - 汉诺塔（三个磁盘）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.5_B15403.jpg)

图 8.5 - 汉诺塔（三个磁盘）

由于*n=*2，我们知道如何将顶部两个磁盘从*A*（起点）移动到*C*（目标）。换句话说，我们知道如何将顶部两个磁盘从一个杆移动到另一个杆。让我们将它们从*A*移动到*B*，如下所示：

1.  将磁盘 1 从*A*移动到*C*（这次我们使用*C*作为中间杆）。

1.  将磁盘 2 从*A*移动到*B*。

1.  将磁盘 1 从*C*移动到*B*。

好的，这是我们以前做过的事情。接下来，我们可以将磁盘 2 和 3 移动到*C*，如下所示：

1.  将磁盘 3 从*A*移动到*C*。

1.  将磁盘 1 从*B*移动到*A*（我们使用*A*作为中间杆）。

1.  将磁盘 2 从*B*移动到*C*。

1.  最后，将磁盘 3 从*A*移动到*C*。

继续这种逻辑，我们可以直观地得出我们可以移动四个磁盘，因为我们知道如何移动三个，我们可以移动五个磁盘，因为我们知道如何移动四个，依此类推。以杆*A*为起点，杆*B*为中间杆，杆*C*为目标杆，我们可以得出我们可以通过以下步骤移动*n*个磁盘：

+   将顶部的*n* - 1 个磁盘从起点移动到中间杆，使用目标杆作为中间杆。

+   将顶部的*n* - 1 个磁盘从中间杆移动到目标杆，使用起点作为中间杆。

在这一点上，很明显我们有一个可以分解为子问题的问题。基于前面两个项目符号，我们可以编写代码如下：

```java
public static void moveDisks(int n, char origin, 
    char target, char intermediate) {
    if (n <= 0) {
        return;
    }
    if (n == 1) {
        System.out.println("Move disk 1 from rod " 
          + origin + " to rod " + target);
        return;
    }
    // move top n - 1 disks from origin to intermediate, 
    // using target as a intermediate
    moveDisks(n - 1, origin, intermediate, target);
    System.out.println("Move disk " + n + " from rod " 
            + origin + " to rod " + target);
    // move top n - 1 disks from intermediate to target, 
    // using origin as an intermediate
    moveDisks(n - 1, intermediate, target, origin);
}
```

完整的应用程序称为*HanoiTowers*。

## 编码挑战 3 - Josephus

亚马逊，谷歌，Adobe，微软，Flipkart

**问题**：考虑一个排成圆圈的*n*个人（1，2，3，...，*n*）。每隔*k*个人将在圆圈中被杀，直到只剩下一个幸存者。编写一个算法，找到这个幸存者的*k*位置。这就是所谓的 Josephus 问题。

**解决方案**：记住我们之前有一个注释，当一个问题包含*计算第 n 个*之类的表达时，它可能是递归解决的一个很好的候选。在这里，我们有*找到第 k 个位置*，这是一个可以分解为子问题并通过递归解决的问题。

让我们考虑*n*=15 和*k*=3。所以，有 15 个人，每三个人中的一个将在圆圈中被淘汰，直到只剩下一个人。让我们通过以下图表来可视化这一点（这对于找出杀人的模式非常有用）：

![图 8.6 - n=15 和 k=3 的 Josephus](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.6_B15403.jpg)

图 8.6 - n=15 和 k=3 的 Josephus

所以，我们需要进行五轮，直到找到幸存者，如下所示：

+   第 1 轮：第一个淘汰的是位置 3；接下来是 6，9，12 和 15。

+   第 2 轮：第一个淘汰的是位置 4（1 和 2 被跳过，因为位置 15 是第 1 轮最后被淘汰的）；接下来，淘汰 8 和 13。

+   第 3 轮：第一个淘汰的是位置 2（14 和 1 被跳过，因为位置 13 是第 2 轮最后被淘汰的）；接下来，淘汰 10 和 1。

+   第 4 轮：第一个淘汰的位置是 11，接着是位置 7。

+   第 5 轮：淘汰 14，5 是幸存者。

尝试识别模式或递归调用可以基于以下观察来完成。在第一个人（*k*个）被淘汰后，剩下*n*-1 个人。这意味着我们调用`josephus(n – 1, k)`来得到第*n*-1 个人的位置。然而，请注意，`josephus(n – 1, k)`返回的位置将考虑从*k%n* + 1 开始的位置。换句话说，我们必须调整`josephus(n – 1, k)`返回的位置以获得(`josephus(n - 1, k) + k - 1) % n + 1`。递归方法如下所示：

```java
public static int josephus(int n, int k) {
    if (n == 1) {
        return 1;
    } else {
        return (josephus(n - 1, k) + k - 1) % n + 1;
    }
}
```

如果您觉得这种方法非常棘手，那么您可以尝试基于队列的迭代方法。首先，用*n*个人填充队列。接下来，循环队列，并且对于每个人，检索并删除此队列的头部（`poll()`）。如果检索到的人不是第*k*个，则将此人重新插入队列（`add()`）。如果这是第*k*个人，则中断循环，并重复此过程，直到队列的大小为 1。这个代码如下：

```java
public static void printJosephus(int n, int k) {
    Queue<Integer> circle = new ArrayDeque<>();
    for (int i = 1; i <= n; i++) {
        circle.add(i);
    }
    while (circle.size() != 1) {
        for (int i = 1; i <= k; i++) {
            int eliminated = circle.poll();
            if (i == k) {
               System.out.println("Eliminated: " 
                   + eliminated);
               break;
            }
            circle.add(eliminated);
        }
    }
    System.out.println("Using queue! Survivor: " 
        + circle.peek());
}
```

完整的应用程序称为*Josephus*。

编码挑战 4-彩色斑点

亚马逊，谷歌，Adobe，微软，Flipkart

**问题**：考虑一个*r* x *c*网格，其中*r*代表行，*c*代表列。每个单元格都有一个用数字*k*表示的颜色（例如，对于三种颜色，*k*=3）。我们将单元格的连接集（或颜色斑点）定义为我们可以通过对行或列的连续位移从相应单元格到达的总单元格数，从而保持颜色。目标是确定最大连接集的颜色和单元格数。换句话说，我们需要确定最大的颜色斑点。

**解决方案**：让我们考虑一个 5x5 的网格和三种颜色，其中*r=c=*5，*k=*3。接下来，让我们按照以下图示来表示网格：

![图 8.7-最大颜色斑点（a）-初始网格，（b）-解决网格）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.7_B15403.jpg)

图 8.7-最大颜色斑点（a）-初始网格，（b）-解决网格

让我们专注于图像（a）。在这里，我们可以看到从一个单元格移动到另一个单元格最多可以有四个方向（上，下，左，右）。这意味着，从一个单元格（*r，c*）到另一个单元格（*r*-1，*c*），（*r*+1，*c*），（*r*，*c*-1），和（*r*，*c*+1）。如果我们冒着从网格上掉下来的风险，或者目标单元格的颜色与当前单元格不同，我们就不能进行移动。因此，通过迭代每个单元格（（0，0），（0，1），...（*r，c*）），我们可以通过访问每个允许的单元格并计数来确定该单元格的连接集的大小（颜色斑点的大小）。在图像（a）中，我们有四个颜色为 1 的斑点，它们的大小分别为 1、1、1 和 2。我们还有六个颜色为 2 的斑点，它们的大小分别为 1、1、2、1、1 和 1。最后，我们有三个颜色为 3 的斑点，它们的大小分别为 11、1 和 1。

从这里，我们可以得出最大的颜色斑点大小为 11，颜色为 3。主要的是，我们可以认为第一个单元格的颜色斑点是最大的，每当我们找到一个比这个更大的颜色斑点时，我们就用我们找到的那个来替换这个。

现在，让我们专注于图像（b）。为什么我们有负值？因为当我们访问一个单元格时，我们将其*颜色*值切换为*-颜色*。这是一个方便的约定，用于避免多次计算单元格的相同连接集。这就像是说我们标记了这个单元格已被访问。按照约定，我们不能移动到具有颜色的负值的单元格，因此我们不会计算相同颜色斑点的大小两次。

现在，将这些观察结果组合成一个递归方法，得到以下代码：

```java
public class BiggestColorSpot {
    private int currentColorSpot;
    void determineBiggestColorSpot(int cols, 
          int rows, int a[][]) {
      ...
    }  
    private void computeColorSpot(int i, int j, 
            int cols, int rows, int a[][], int color) {
        a[i][j] = -a[i][j];
        currentColorSpot++;
        if (i > 1 && a[i - 1][j] == color) {
            computeColorSpot(i - 1, j, cols, 
                rows, a, color);
        }
        if ((i + 1) < rows && a[i + 1][j] == color) {
           computeColorSpot(i + 1, j, cols, rows, a, color);
        }
        if (j > 1 && a[i][j - 1] == color) {
            computeColorSpot(i, j - 1, cols, 
                rows, a, color);
        }
        if ((j + 1) < cols && a[i][j + 1] == color) {
            computeColorSpot(i, j + 1, cols, 
                rows, a, color);
        }
    }
}
```

在给定单元格开始时，前面的递归方法`computeColorSpot()`可以计算颜色斑点的大小，而以下方法确定了最大的颜色斑点：

```java
void determineBiggestColorSpot(int cols, 
      int rows, int a[][]) {
    int biggestColorSpot = 0;
    int color = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (a[i][j] > 0) {
               currentColorSpot = 0;
               computeColorSpot(i, j, cols, 
                 rows, a, a[i][j]);
               if (currentColorSpot > biggestColorSpot) {
                   biggestColorSpot = currentColorSpot;
                   color = a[i][j] * (-1);
               }
            }
        }
    }
    System.out.println("\nColor: " + color 
        + " Biggest spot: " + biggestColorSpot);
}
```

完整的应用程序称为*BiggestColorSpot*。

编码挑战 5 - 硬币

**Google**，**Adobe**，**Microsoft**

**问题**：考虑 n 美分的金额。计算您可以使用任意数量的 25 美分，10 美分，5 美分和 1 美分来更改此金额的方式。

**解决方案**：假设我们必须更改 50 美分。从一开始，我们就可以看到更改 50 美分是一个可以通过子问题解决的问题。例如，我们可以使用 0、1 或 2 个 25 美分来更改 50 美分。或者我们可以使用 0、1、2、3、4 或 5 个 10 美分来做到这一点。我们还可以使用 0、1、2、3、4、5、6、7、8、9 或 10 个 5 美分。最后，我们可以使用 0、1、2、3、...、50 个 1 美分。假设我们有 1 个 25 美分，1 个 10 美分，2 个 5 美分和 5 个 1 美分。我们可以使用我们的 25 美分来说以下内容：

*calculateChange***(50) = 1 个 25 美分 + ...**

但这就像说以下内容：

*calculateChange***(25) = 0 个 25 美分 + ...**

我们没有更多的 25 美分；因此，我们添加一个 10 美分：

*calculateChange***(25) = 0 个 25 美分 + 1 个 10 美分 + ...**

这可以简化如下：

*calculateChange***(15) = 0 个 25 美分 + 0 个 10 美分 + ...**

我们没有更多的 10 美分。我们添加了 5 美分：

*calculateChange***(15) = 0 个 25 美分 + 0 个 10 美分 + 2 个 5 美分 + ...**

这可以简化为以下内容：

*calculateChange***(5) = 0 个 25 美分 + 0 个 10 美分 + 0 个 5 美分 + ...**

最后，由于我们没有更多的 5 美分，我们添加了 1 美分：

*calculateChange***(5) = 0 个 25 美分 + 0 个 10 美分 + 0 个 5 美分 + 5 个 1 美分**

这可以简化为以下内容：

*calculateChange***(0) = 0 个 25 美分 + 0 个 10 美分 + 0 个 5 美分 + 0 个 1 美分**

如果我们试图表示所有可能的减少，我们得到以下图表：

![图 8.8 - 将 n 美分换成 25 美分，10 美分，5 美分和 1 美分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.8_B15403.jpg)

图 8.8 - 将 n 美分换成 25 美分，10 美分，5 美分和 1 美分

通过递归实现这种可简化的算法，如下代码所示。请注意，我们使用*Memoization*来避免多次更改相同的金额：

```java
public static int calculateChangeMemoization(int n) {
    int[] coins = {25, 10, 5, 1};
    int[][] cache = new int[n + 1][coins.length];
    return calculateChangeMemoization(n, coins, 0, cache);
}
private static int calculateChangeMemoization(int amount, 
      int[] coins, int position, int[][] cache) {
    if (cache[amount][position] > 0) {
        return cache[amount][position];
    }
    if (position >= coins.length - 1) {
        return 1;
    }
    int coin = coins[position];
    int count = 0;
    for (int i = 0; i * coin <= amount; i++) {
        int remaining = amount - i * coin;
        count += calculateChangeMemoization(remaining, 
            coins, position + 1, cache);
    }
    cache[amount][position] = count;
    return count;
}
```

完整的应用程序称为*Coins*。它还包含了纯递归方法（不包括*Memoization*）。

## 编码挑战 6 - 五座塔

**问题**：考虑一个 5x5 的网格，网格上分布着五座防御塔。为了为网格提供最佳防御，我们必须在网格的每一行上建造一座塔。找出建造这些塔的所有解决方案，以便它们没有共享相同的列和对角线。

**解决方案**：我们知道，在每一行上，我们必须建造一座塔，并且在网格上建造它们的顺序并不重要。让我们草拟一个解决方案和一个失败，如下所示：

![图 8.9(a) - 失败和解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.9(a)_B15403.jpg)

图 8.9(a) - 失败和解决方案

让我们专注于解决方案，并从第一行开始：第 0 行。我们可以在任何列上的这一行上建造一座塔；因此，我们可以说以下内容：

![图 8.9(b)：构建塔的逻辑的第一部分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.9(b)_B15403.jpg)

图 8.9(b)：构建塔的逻辑的第一部分

如果我们继续使用相同的逻辑，那么我们可以说以下内容：

![图 8.9(c)：构建塔的逻辑的第二部分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.9(c)_B15403.jpg)

图 8.9(c)：构建塔的逻辑的第二部分

因此，我们从第一行开始，在(0,0)处建立第一个塔。我们转到第二行，并尝试建立第二个塔，以便不与第一个塔共享列或对角线。我们转到第三行，并尝试建立第三个塔，以便不与前两个塔共享列或对角线。我们对第四和第五个塔采用相同的逻辑。这是我们的解决方案。现在，我们重复此逻辑-我们在(0,1)处建立第一个塔，并继续建立，直到找到第二个解决方案。接下来，我们在(0,2)、(0,3)和最后在(0,4)处建立第一个塔，同时重复这个过程。我们可以将这个递归算法写成如下：

```java
protected static final int GRID_SIZE = 5; // (5x5)
public static void buildTowers(int row, Integer[] columns, 
        Set<Integer[]> solutions) {
    if (row == GRID_SIZE) {
        solutions.add(columns.clone());
    } else {
        for (int col = 0; col < GRID_SIZE; col++) {
            if (canBuild(columns, row, col)) {
                // build this tower
                columns[row] = col;
                // go to the next row
                buildTowers(row + 1, columns, solutions);
            }
        }
    }
}
private static boolean canBuild(Integer[] columns, 
    int nextRow, int nextColumn) {
    for (int currentRow=0; currentRow<nextRow; 
            currentRow++) {
        int currentColumn = columns[currentRow];
        // cannot build on the same column
        if (currentColumn == nextColumn) {
            return false;
        }
        int columnsDistance
            = Math.abs(currentColumn - nextColumn);
        int rowsDistance = nextRow - currentRow;
        // cannot build on the same diagonal
        if (columnsDistance == rowsDistance) {
            return false;
        }
    }
    return true;
}
```

完整的应用程序称为*FiveTowers*。

编码挑战 7-魔术索引

Adobe，Microsoft

**问题**：考虑一个允许重复的*n*个元素的排序数组。如果*array*[*k*] = *k*，则索引*k*是魔术索引。编写一个递归算法，找到第一个魔术索引。

**解决方案**：首先，让我们快速绘制包含 18 个元素的两个排序数组，如下图所示。图像顶部的数组不包含重复项，而图像底部的数组包含重复项。这样，我们可以观察到这些重复项的影响：

![图 8.10-18 个元素的排序数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.10_B15403.jpg)

图 8.10-18 个元素的排序数组

如果我们将不包含重复项的数组减半，那么我们可以得出结论，魔术索引必须在右侧，因为*array*[8] < 8。这是正确的，因为魔术索引是 11，所以*array*[11] = 11。

如果我们将包含重复项的数组减半，我们无法得出与之前相同的结论。魔术索引可以在两侧。在这里，我们有*array*[5] = 5 和*array*[12] = 12。我们必须找到第一个魔术索引，所以我们应该首先搜索左侧。

但是我们如何找到它呢？最明显的方法是循环数组并检查*array*[i] = *i*。虽然这对于任何有序数组都有效，但它不会给面试官留下深刻印象，因为它不是递归的，所以我们需要另一种方法。

在*第七章**，算法的大 O 分析*中，您看到了通过二分搜索算法在排序数组中搜索的示例。由于在每一步中，我们都将前一个数组减半并创建一个子问题，因此可以通过递归实现此算法。由于数组的索引是有序的，我们可以调整二分搜索算法。我们面临的主要问题是重复元素使搜索变得复杂。当我们将数组减半时，我们无法说魔术索引在左侧还是右侧，因此我们必须在两个方向搜索，如下面的代码所示（首先，我们搜索左侧）：

```java
public static int find(int[] arr) {
    return find(arr, 0, arr.length - 1);
}
private static int find(int[] arr, 
        int startIndex, int endIndex) {
    if (startIndex > endIndex) {
        return -1; // return an invalid index
    }
    // halved the indexes
    int middleIndex = (startIndex + endIndex) / 2;
    // value (element) of middle index
    int value = arr[middleIndex];
    // check if this is a magic index
    if (value == middleIndex) {                                     
        return middleIndex;
    }
    // search from middle of the array to the left       
    int leftIndex = find(arr, startIndex, 
            Math.min(middleIndex - 1, value));
    if (leftIndex >= 0) {
        return leftIndex;
    }
    // search from middle of the array to the right               
    return find(arr,  Math.max(middleIndex + 1, 
          value), endIndex);
    }
}
```

完整的应用程序称为*MagicIndex*。

## 编码挑战 8-下落的球

**问题**：考虑一个*m* x *n*的网格，其中每个(*m, n*)单元格的高程由 1 到 5 之间的数字表示（5 是最高的高程）。一个球放在网格的一个单元格中。只要该单元格的高程小于球单元格，球就可以掉落到另一个单元格。球可以向四个方向掉落：北、西、东和南。显示初始网格，以及球在所有可能路径上掉落后的网格。用 0 标记路径。

**解决方案**：始终注意问题的要求。注意我们必须显示解决的网格，而不是列出路径或计数。显示网格的最简单方法是使用两个循环，如下面的代码所示：

```java
for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
        System.out.format("%2s", elevations[i][j]);
    }
    System.out.println();
}
```

现在，让我们勾画一个 5x5 的网格，并查看一个输入及其输出。下图显示了初始网格的 3D 模型形式，以及可能的路径和解决的网格：

![图 8.11-下落的球](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.11_B15403.jpg)

图 8.11-下落的球

我认为我们有足够的经验来直觉地认为这个问题可以通过递归来解决。主要是，我们将球移动到所有可接受的方向，并用 0 标记每个访问的单元格。当我们将球放在(*i, j*)单元格中时，我们可以朝着(*i*-1*, j*)，(*i+*1*, j*)，(*i, j*-1)和(*i, j+*1*)的方向前进，只要这些单元格的高度较小。在代码方面，我们有以下内容：

```java
public static void computePath(
      int prevElevation, int i, int j, 
      int rows, int cols, int[][] elevations) {
    // ensure the ball is still on the grid
    if (i >= 0 && i <= (rows-1) && j >= 0 && j <= (cols-1)) {
        int currentElevation = elevations[i][j];
        // check if the ball can fall
        if (prevElevation >= currentElevation
                && currentElevation > 0) {
            // store the current elevation                       
            prevElevation = currentElevation;
            // mark this cell as visited
            elevations[i][j] = 0;
            // try to move the ball 
            computePath(prevElevation,i,j-1,
              rows,cols,elevations);
            computePath(prevElevation,i-1,   
              j,rows,cols,elevations);              
            computePath(prevElevation,i,j+1,
              rows,cols,elevations);              
            computePath(prevElevation,i+1,j,
              rows,cols,elevations);
        }
    }
}
```

完整的应用程序称为*TheFallingBall*。

## 编程挑战 9 - 最高彩色塔

**Adobe**，**Microsoft**，**Flipkart**

**问题**：考虑不同宽度（*w*1...n）、高度（*h*1...n）和颜色（*c*1...n）的*n*个盒子。找到符合以下条件的最高的盒子塔：

+   你不能旋转盒子。

+   你不能连续放置两个相同颜色的盒子。

+   每个盒子在宽度和高度上都严格大于它上面的盒子。

**解决方案**：让我们试着将这个可视化，如下所示：

![图 8.12(a) - 最高的彩色塔](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.12_B15403.jpg)

图 8.12(a) - 最高的彩色塔

我们有七个不同尺寸和颜色的盒子。我们可以想象最高的塔将包含所有这些盒子，*b*1...*b*7。但是我们有一些约束条件，不允许我们简单地堆叠这些盒子。我们可以选择一个盒子作为基础盒子，并将另一个允许的盒子放在其顶部，如下所示：

![图 8.12(b) 选择盒子建造最高塔的逻辑](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.12(b)_ 选择盒子建造最高塔的逻辑.jpg)

图 8.12(b) 选择盒子建造最高塔的逻辑

因此，我们找到了一个模式。我们选择一个盒子作为基础，然后尝试看看剩下的盒子中哪个可以作为第二层放在顶部。我们对第三层也是同样的操作。当我们完成时（不能再添加盒子或没有剩余的盒子时），我们存储最高塔的大小。接下来，我们用另一个基础盒子重复这种情况。

由于每个盒子在宽度和高度上都必须大于上面的盒子，我们可以按宽度或高度按降序对盒子进行排序（选择哪一个并不重要）。这样，对于*k < n*的盒子的任何塔，我们可以通过搜索*b*k+1...*n*区间来找到下一个有效的盒子。

此外，我们可以通过*记忆化*来避免为相同的基础盒子重新计算最佳解决方案：

```java
// Memoization
public static int buildViaMemoization(List<Box> boxes) {
    // sorting boxes by width (you can do it by height as well)
    Collections.sort(boxes, new Comparator<Box>() {
        @Override
        public int compare(Box b1, Box b2) {
            return Integer.compare(b2.getWidth(), 
                b1.getWidth());
        }
    });
    // place each box as the base (bottom box) and
    // try to arrange the rest of the boxes
    int highest = 0;
    int[] cache = new int[boxes.size()];
    for (int i = 0; i < boxes.size(); i++) {
        int height = buildMemoization(boxes, i, cache);
        highest = Math.max(highest, height);
    }
    return highest;
}
// Memoization
private static int buildMemoization(List<Box> boxes, 
      int base, int[] cache) {
    if (base < boxes.size() && cache[base] > 0) {
        return cache[base];
    }
    Box current = boxes.get(base);
    int highest = 0;
    // since the boxes are sorted we don’t 
    // look in [0, base + 1)
    for (int i = base + 1; i < boxes.size(); i++) {
        if (boxes.get(i).canBeNext(current)) {
            int height = buildMemoization(boxes, i, cache);
            highest = Math.max(height, highest);
        }
    }
    highest = highest + current.getHeight();
    cache[base] = highest;
    return highest;
}
```

完整的应用程序称为*HighestColoredTower*。代码还包含了这个问题的纯递归方法（没有*记忆化*）。

## 编程挑战 10 - 字符串排列

**Amazon**，**Google**，**Adobe**，**Microsoft**，**Flipkart**

**问题**：编写一个算法，计算字符串的所有排列，并满足以下两个条件：

+   给定的字符串可以包含重复项。

+   返回的排列列表不应包含重复项。

**解决方案**：就像在任何递归问题中一样，关键在于识别不同子问题之间的关系和模式。我们立刻就能直观地感觉到，对具有重复字符的字符串进行排列应该比对具有唯一字符的字符串进行排列更复杂。这意味着我们必须先理解具有唯一字符的字符串的排列。

对字符串的字符进行排列的最自然的方式可以遵循一个简单的模式：字符串的每个字符将成为字符串的第一个字符（交换它们的位置），然后使用递归调用对所有剩余的字母进行排列。让我们深入研究一般情况。对于包含单个字符的字符串，我们有一个排列：

P(*c*1) = *c*1

如果我们添加另一个字符，那么我们可以按如下方式表示排列：

P(*c*1*c*2) = *c*1*c*2 和 *c*2*c*1

如果我们添加另一个字符，那么我们必须使用*c*1*c*2 来表示排列。每个*c*1*c*2*c*3 的排列代表了*c*1*c*2 的顺序，如下所示：

*c*1*c*2 -> *c*1*c*2*c*3,*c*1*c*3*c*2,*c*3*c*1*c*2

*c*2*c*1 -> *c*2*c*1*c*3,*c*2*c*3*c*1,*c*3*c*2*c*1

让我们用 ABC 替换*c*1*c*2*c*3。接下来，我们将 P(ABC)表示为图表：

![图 8.13 – 对 ABC 进行排列](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.13_B15403.jpg)

图 8.13 – 对 ABC 进行排列

如果我们添加另一个字符，那么我们必须使用*c*1*c*2*c*3*c*4 来表示排列。*c*1*c*2*c*3*c*4 的每个排列代表*c*1*c*2*c*3 的排序，如下所示：

*c*1*c*2*c*3 -> *c*1*c*2*c*3*c*4,*c*1*c*2*c*4*c*3,*c*1*c*4*c*2*c*3,*c*4*c*1*c*2*c*3

*c*1*c*3*c*2 -> *c*1*c*3*c*2*c*4,*c*1*c*3*c*4*c*2,*c*1*c*4*c*3*c*2,*c*4*c*1*c*3*c*2

*c*3*c*1*c*2 -> *c*3*c*1*c*2*c*4,*c*3*c*1*c*4*c*2,*c*3*c*4*c*1*c*2,*c*4*c*3*c*1*c*2

*c*2c1*c*3 -> *c*2*c*1*c*3*c*4,*c*2*c*1*c*4*c*3,*c*2*c*4*c*1*c*3,*c*4*c*2*c*1*c*3

*c*2*c*3*c*1 -> *c*2*c*3*c*1*c*4,*c*2*c*3*c*4*c*1,*c*2*c*4*c*3*c*1,*c*4*c*2*c*3*c*1

*c*3*c*2*c*1 -> *c*3*c*2*c*1*c*4,*c*3*c*2*c*4*c*1,*c*3*c*4*c*2*c*1,*c*4*c*3*c*2*c*1

我们可以一直这样继续下去，但我认为可以很清楚地知道可以用什么模式来生成*P*(*c*1, *c*2, ..., *c*n)。

因此，现在是时候进一步推进我们的逻辑了。现在，是时候问以下问题了：如果我们知道如何计算*k*-1 个字符的字符串的所有排列（*c*1*c*2...*c*k-1），那么我们如何使用这些信息来计算*k*个字符的字符串的所有排列（*c*1*c*2...*c*k-1*c*k）？例如，如果我们知道如何计算*c*1*c*2*c*3 字符串的所有排列，那么我们如何使用*c*1*c*2*c*3 的排列来表示*c*1*c*2*c*3*c*4 字符串的所有排列？答案是从*c*1*c*2...*c*k 字符串中取出每个字符，并将*c*1*c*2...*c*k-1 排列附加到它，如下所示：

P(*c*1*c*2*c*3*c*4) = [*c*1 + P(*c*2*c*3*c*4)] + [*c*2 + P(*c*1*c*3*c*4)] + [*c*3 + P(*c*1*c*2*c*4)] + [*c*4 + P(*c*1*c*2*c*3)]

[*c*1 + P(*c*2*c*3*c*4)] -> *c*1*c*2*c*3*c*4,*c*1*c*2*c*4*c*3,*c*1*c*3*c*2*c*4,*c*1*c*3*c*4*c*2,*c*1*c*4*c*2*c*3,*c*1*c*4*c*3*c*2

[*c*2 + P(*c*1*c*3*c*4)] -> *c*2*c*1*c*3*c*4,*c*2*c*1*c*4*c*3,*c*2*c*3*c*1*c*4,*c*2*c*3*c*4*c*1,*c*2*c*4*c*1*c*3,*c*2*c*4*c*3*c*1

[*c*3 + P(*c*1*c*2*c*4)] -> *c*3*c*1*c*2*c*4,*c*3*c*1*c*4*c*2,*c*3*c*2*c*1*c*4,*c*3*c*2*c*4*c*1,*c*3*c*4*c*1*c*2,*c*3*c*4*c*2*c*1

[*c*4 + P(*c*1*c*2*c*3)] -> *c*4*c*1*c*2*c*3,*c*4*c*1*c*3*c*2,*c*4*c*2*c*1*c*3,*c*4*c*2*c*3*c*1,*c*4*c*3*c*1*c*2,*c*4*c*3*c*2*c*1

我们可以继续添加另一个字符并重复此逻辑，以便我们有一个可以用代码表示的递归模式，如下所示：

```java
public static Set<String> permute(String str) {        
    return permute("", str);
}
private static Set<String> permute(String prefix, String str) {
    Set<String> permutations = new HashSet<>();
    int n = str.length();
    if (n == 0) {
        permutations.add(prefix);
    } else {
        for (int i = 0; i < n; i++) {
            permutations.addAll(permute(prefix + str.charAt(i),
            str.substring(i + 1, n) + str.substring(0, i)));
        }
    }
    return permutations;
}
```

这段代码将正常工作。因为我们使用的是`Set`（而不是`List`），我们遵守了*返回的排列列表不应包含重复项*的要求。但是，我们确实生成了重复项。例如，如果给定的字符串是*aaa*，那么我们生成了六个相同的排列，即使只有一个。唯一的区别是它们没有被添加到结果中，因为`Set`不接受重复项。这远非高效。

我们可以通过多种方式避免生成重复项。一种方法是通过计算字符串的字符数并将其存储在映射中。例如，对于给定的字符串*abcabcaa*，键值映射可以是*a*=4，*b*=2，*c*=2。我们可以通过一个简单的辅助方法来实现这一点，如下所示：

```java
private static Map<Character, Integer> charactersMap(
                 String str) {
    Map<Character, Integer> characters = new HashMap<>();
    BiFunction<Character, Integer, Integer> count = (k, v)
          -> ((v == null) ? 1 : ++v);
    for (char c : str.toCharArray()) {
        characters.compute(c, count);
    }
    return characters;
}
```

接下来，我们选择其中一个字符作为第一个字符，并找到其余字符的所有排列。我们可以表示如下：

P(*a=*4*,b=*2*,c=*2) *=* [*a +* P(*a=*3*,b=*2*,c=*2)] *+* [*b +* P(*a=*4*,b=*1*,c=*1)] *+* [*c +* P(*a=*4*,b=*2*,c=*1)]

P(*a=*3*,b=*2*,c=*2) *=* [*a +* P(*a=*2*,b=*2*,c=*2)] *+* [*b +* P(*a=*3*,b=*1*,c=*1)] *+* [*c +* P(*a=*3*,b=*2*,c=*1)]

P(*a=*4*,b=*1*,c=*1*) =* [*a +* P(*a=*3*,b=*1*,c=*1)] *+* [*b +* P(*a=*4*,b=*0*,c=*1)] *+* [*c +* P(*a=*4*,b=*1*,c=*0)]

P(*a=*4*,b=*2*,c=*1*) =* [*a +* P(*a=*3*,b=*2*,c=*1)] *+* [*b +* P(*a=*4*,b=*1*,c=*1)] *+* [*c +* P(*a=*4*,b=*2*,c=*0)]

P(*a=*2*,b=*2*,c=*2) *=* [*a +* P(*a=*1*,b=*2*,c=*2)] *+* [*b +* P(*a=*2*,b=*1*,c=*2)] *+* [*c +* P(*a=*2*,b=*2*,c=*1)]

P（* a = * 3 *，b = * 1 *，c = * 1）* = ...*

我们可以继续写，直到没有剩余字符。现在，将这些放入代码行应该相当简单：

```java
public static List<String> permute(String str) {      
    return permute("", str.length(), charactersMap(str));
}
private static List<String> permute(String prefix, 
        int strlength, Map<Character, Integer> characters) {
    List<String> permutations = new ArrayList<>();
    if (strlength == 0) {
        permutations.add(prefix);
    } else {
        // fetch next char and generate remaining permutations
        for (Character c : characters.keySet()) {
            int count = characters.get(c);
            if (count > 0) {
                characters.put(c, count - 1);
                permutations.addAll(permute(prefix + c, 
                    strlength - 1, characters));
                characters.put(c, count);
            }
        }
    }
    return permutations;
}
```

完整的应用程序称为*排列*。

## 编码挑战 11 - 骑士之旅

**亚马逊**，**谷歌**

问题：考虑一个棋盘（8x8 网格）。在这个棋盘上放一个骑士，并打印出它所有独特的移动。

**解决方案**：正如您已经看到的，解决这类问题的最佳方法是拿出一张纸和一支笔，勾画出情景。一幅图胜过千言万语：

![图 8.14 - 骑士之旅](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.14_B15403.jpg)

图 8.14 - 骑士之旅

正如我们所看到的，骑士可以从一个（*r*，*c*）单元格移动到最多八个其他有效单元格；也就是说，（*r*+2，*c*+1），（*r*+1，*c*+2），（*r*-1，*c*+2），（*r*-2，*c*+1），（*r*-2，*c*-1），（*r*-1，*c*-2），（*r*+1，*c*-2），和（*r*+2，*c*-1）。因此，为了获得从 1 到 64 的路径（如前图右侧所示），我们可以从给定位置开始，并递归地尝试访问每个有效的移动。如果当前路径不代表一个解决方案，或者我们已经尝试了所有八个单元格，那么我们就会回溯。

为了尽可能高效，我们考虑以下几个方面：

+   我们从棋盘的一个角开始：这样，骑士最初只能朝两个方向走，而不是八个。

+   我们按照固定顺序检查有效单元格：保持循环路径将帮助我们比随机选择更快地找到新的移动。从（*r*，*c*）的逆时针循环路径是（*r*+2，*c*+1），（*r*+1，*c*+2），（*r*-1，*c*+2），（*r*-2，*c*+1），（*r*-2，*c*-1），（*r*-1，*c*-2），（*r*+1，*c*-2），和（*r*+2，*c*-1）。

+   我们使用两个数组计算循环路径：我们可以从（*r*，*c*）移动到（*r* + *ROW*[*i*]，c + COL*[*i*]）其中*i*在[0, 7]：

*COL*[] = {1,2,2,1,-1,-2,-2,-1,1};

*ROW*[] = {2,1,-1,-2,-2,-1,1,2,2};

+   我们通过在一个*r* x *c*矩阵中存储访问的单元格来避免路径中的循环和重复工作（例如，多次访问相同的单元格）。

通过将所有内容粘合在代码方面，我们得到以下递归方法：

```java
public class KnightTour {
    private final int n;
    // constructor omitted for brevity
    // all 8 possible movements for a knight
    public static final int COL[] 
        = {1,2,2,1,-1,-2,-2,-1,1};
    public static final int ROW[] 
        = {2,1,-1,-2,-2,-1,1,2,2};
    public void knightTour(int r, int c, 
            int cell, int visited[][]) {

        // mark current cell as visited
        visited[r][c] = cell;
        // we have a solution
        if (cell >= n * n) {
            print(visited);
            // backtrack before returning
            visited[r][c] = 0;
            return;
        }
        // check for all possible movements (8) 
        // and recur for each valid movement
        for (int i = 0; i < (ROW.length - 1); i++) {
            int newR = r + ROW[i];
            int newC = c + COL[i];
            // check if the new position is valid un-visited
            if (isValid(newR, newC) 
                  && visited[newR][newC] == 0) { 
                knightTour(newR, newC, cell + 1, visited);
            }
        }

        // backtrack from current cell
        // and remove it from current path
        visited[r][c] = 0;
    }
    // check if (r, c) is valid chess board coordinates    
    private boolean isValid(int r, int c) {        
        return !(r < 0 || c < 0 || r >= n || c >= n);
    }
    // print the solution as a board
    private void print(int[][] visited) {
    ...   
    }
}
```

完整的应用程序称为*KnightTour*。

## 编码挑战 12 - 大括号

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

问题：打印出*n*对大括号的所有有效组合。当大括号正确打开和关闭时，才是有效组合。对于*n*=3，有效组合如下：

{{{}}},{{}{}},{{}}{},{}{{}},{}{}{}

**解决方案**：*n*=1 的有效组合是{}。

对于*n=2*，我们立即看到组合为{}{}。然而，另一个组合包括在前一个组合中添加一对大括号；也就是说，{{}}。

再进一步，对于*n*=3，我们有平凡的组合{}{}{}。按照相同的逻辑，我们可以为*n*=2 的组合添加一对大括号，因此我们得到{{{}}}, {{}}{}, {}{{}}, {{}{}}。

实际上，这是我们在删除或忽略重复后得到的结果。让我们根据*n*=2 来勾画*n*=3 的情况，如下所示：

![图 8.15 - 大括号重复对](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.15_B15403.jpg)

图 8.15 - 大括号重复对

因此，如果我们在每个现有的大括号中添加一对大括号，并且我们添加平凡的情况（{}{}...{}），那么我们就会得到一个可以通过递归实现的模式。然而，我们必须处理大量重复对，因此我们需要额外的检查来避免最终结果中出现重复。

因此，让我们考虑另一种方法，从一个简单的观察开始。对于任何给定的 n，一个组合将有 2**n 个花括号（不是一对！）。例如，对于 n=3，我们有六个花括号（三个左花括号（{{{）和三个右花括号（}}}}）以不同的有效组合排列。这意味着我们可以尝试通过从零花括号开始并向其添加左/右花括号来构建解决方案，只要我们有一个有效的表达式。当然，我们要跟踪添加的花括号的数量，以便不超过最大数量 2**n。我们必须遵循的规则如下：

+   我们以递归方式添加所有左花括号。

+   我们以递归方式添加右花括号，只要右花括号的数量不超过左花括号的数量。

换句话说，这种方法的关键是跟踪允许的左花括号和右花括号的数量。只要我们有左花括号，我们就插入一个左花括号并再次调用该方法（递归）。如果剩下的右花括号比左花括号多，那么我们就插入一个右花括号并调用该方法（递归）。所以，让我们开始编码：

```java
public static List<String> embrace(int nr) {
    List<String> results = new ArrayList<>();
    embrace(nr, nr, new char[nr * 2], 0, results);
    return results;
}
private static void embrace(int leftHand, int rightHand, 
      char[] str, int index, List<String> results) {
    if (rightHand < leftHand || leftHand < 0) {
        return;
    }
    if (leftHand == 0 && rightHand == 0) {
        // result found, so store it
        results.add(String.valueOf(str));
    } else {
        // add left brace
        str[index] = '{';
        embrace(leftHand - 1, rightHand, str, index + 1, 
            results);
        // add right brace
        str[index] = '}';
        embrace(leftHand, rightHand - 1, str, index + 1, 
            results);
    }
}
```

完整的应用程序称为*Braces*。

## 编码挑战 13 - 楼梯

**亚马逊**，**Adobe**，**微软**

**问题**：一个人走上楼梯。他们可以一次跳一步、两步或三步。计算他们可以到达楼梯顶部的可能方式的数量。

**解决方案**：首先，让我们设定一步、两步或三步跳的含义。考虑到一步跳意味着一步一步地上楼梯（我们每步都着陆）。跳两步意味着跳过一步并着陆在下一步。最后，跳三步意味着跳过两步并着陆在第三步。

例如，如果我们考虑一个有三个台阶的楼梯，那么我们可以以四种方式从第 0 步（或者，没有步骤）到第 3 步：一步一步（我们每步都着陆），我们跳过第 1 步并着陆在第 2 步上并走在第 3 步上，我们走在第 1 步上并跳过第 2 步，从而着陆在第 3 步上，或者我们直接跳到第 3 步，如下图所示：

![图 8.16 - 楼梯（如何到达第 3 步）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.16_B15403.jpg)

图 8.16 - 楼梯（如何到达第 3 步）

通过进一步推理，我们可以问自己如何到达第 n 步。主要是，如果我们按照以下步骤，就可以到达第 n 步：

+   n-1 步和跳 1 步

+   n-2 步和跳 2 步

+   n-3 步和跳 3 步

然而，只要我们遵循前面的要点，就可以到达这些步骤中的任何一个 - n-1、n-2 或 n-3。例如，如果我们在 n-2 上并跳 1 步，我们在 n-3 上并跳 2 步，或者我们在 n-4 上并跳 3 步，我们就可以到达 n-1 步。

因此，要达到第 n 步，我们有三条可能的路径。要达到第 n-1 步，我们也有三条可能的路径。因此，要达到这两个步骤，我们必须有 3+3=6 条路径。不要说 3*3=9 条路径！这是错误的！

现在，我们可以得出结论，以递归方式添加所有路径应该给我们预期的答案。此外，我们还可以利用我们的经验来添加*记忆化*。这样，我们就避免了多次使用相同输入调用该方法（就像斐波那契数的情况一样）：

```java
public static int countViaMemoization(int n) {
    int[] cache = new int[n + 1];  
    return count(n, cache);
}
private static int count(int n, int[] cache) {
    if (n == 0) {
        return 1;
    } else if (n < 0) {
        return 0;
    } else if (cache[n] > 0) {
        return cache[n];
    }
    cache[n] = count(n - 1, cache) 
        + count(n - 2, cache) + count(n - 3, cache);
    return cache[n];
}
```

完整的应用程序称为*Staircase*。它还包含了纯递归方法（没有*记忆化*）。

## 编码挑战 14 - 子集和

**亚马逊**，**Adobe**，**微软**，**Flipkart**

**问题**：考虑一个给定的正整数集合（*arr*）和一个值*s*。编写一小段代码，找出数组中是否存在一个子集，其总和等于给定的*s*。

**解决方案**：让我们考虑数组*arr* = {3, 2, 7, 4, 5, 1, 6, 7, 9}。如果*s*=7，那么一个子集可以包含元素 2、4 和 1，如下图所示：

![图 8.17 - 和为 7 的子集](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.17_B15403.jpg)

图 8.17 - 和为 7 的子集

包含元素 2、4 和 1 的子集只是可能子集中的一个。所有可能的子集包括（3, 4）、（2, 4, 1）、（2, 5）、（7）、（1, 6）和（7）。

### 递归方法

让我们尝试通过递归找到一个解决方案。如果我们添加子集*arr*[0]=3，那么我们必须找到和为*s* = *s-arr*[0] = 7-3 = 4 的子集。找到和为*s*=4 的子集是一个可以基于相同逻辑解决的子问题，这意味着我们可以将*arr*[1]=2 添加到子集中，下一个子问题将包括找到和为*s* = *s*-*arr*[1] = 4-2 = 2 的子集。

或者，我们可以这样思考：从*sum*=0 开始。我们将*arr*[0]=3 加到这个*sum*上，得到*sum*=*sum+arr*[0] = 3。接下来，我们检查*sum* = *s*（例如，如果 3 = 7）。如果是，我们找到了一个子集。如果不是，我们将下一个元素*arr*[1]=2 加到*sum*上，得到*sum = sum+arr*[1] = 3+2 =5。我们递归地继续重复这个过程，直到没有更多的元素可以添加。在这一点上，我们递归地从*sum*中移除元素，并在每次移除时检查*sum = s*。换句话说，我们构建了每个可能的子集，并检查它的*sum*是否等于*s*。当我们有这个相等时，我们打印当前的子集。

到目前为止，很明显，如果我们递归地解决每一个子问题，那么它会引导我们得到结果。对于*arr*中的每个元素，我们必须做出一个决定。主要的是，我们有两个选择：将当前元素包含在子集中或者不包含它。基于这些陈述，我们可以创建以下算法：

1.  将子集定义为与给定*arr*长度相同的数组。这个数组只取值 1 和 0。

1.  通过在*arr*中递归地添加每个元素到子集中，将该特定索引处的值设置为 1。检查解决方案（*当前和=给定和*）。

1.  通过在特定索引处将子集中的每个元素递归地移除，将该值设置为 0。检查解决方案（*当前和=给定和*）。

让我们看看代码：

```java
/* Recursive approach */
public static void findSumRecursive(int[] arr, int index,
      int currentSum, int givenSum, int[] subset) {
    if (currentSum == givenSum) {
        System.out.print("\nSubset found: ");
        for (int i = 0; i < subset.length; i++) {
            if (subset[i] == 1) {
                System.out.print(arr[i] + " ");
            }
        }
    } else if (index != arr.length) {
        subset[index] = 1;
        currentSum += arr[index];
        findSumRecursive(arr, index + 1, 
                currentSum, givenSum, subset);
        currentSum -= arr[index];
        subset[index] = 0;
        findSumRecursive(arr, index + 1, 
                currentSum, givenSum, subset);
    }
}
```

这段代码的时间复杂度是 O(n2n)，因此远非高效。现在，让我们尝试通过动态规划的迭代方法。这样，我们就避免了重复解决同一个问题。

### 动态规划方法

通过动态规划，我们可以在 O(s*n)的时间内解决这个问题。更确切地说，我们可以依赖*自底向上*的方法和一个维度为(*n*+1) x (*s*+1)的`boolean`二维矩阵，其中*n*是集合*arr*的大小。

要理解这个实现，你必须理解这个矩阵是如何填充和读取的。如果我们考虑给定的*arr*是{5, 1, 6, 10, 7, 11, 2}，*s*=9，那么这个`boolean`矩阵从一个初始状态开始，如下图所示：

![图 8.18 – 初始矩阵](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.18_B15403.jpg)

图 8.18 – 初始矩阵

因此，我们有*s*+1 = 9+1 = 10 列和*n*+1 = 7+1 = 8 行。你可以看到，我们已经填满了第 0 行和第 0 列。这些是*基本情况*，可以解释如下：

+   初始化矩阵的第一行（row 0）（*matrix*[0][]）为 0（或`false`，F），除了*matrix*[0][0]，它初始化为 1（或`true`，T）。换句话说，如果给定的和不是 0，那么就没有子集可以满足这个和。然而，如果给定的和是 0，那么就有一个只包含 0 的子集。因此，包含 0 的子集可以形成一个和为 0 的单一子集。

+   将矩阵的第一列（column 0）（*matrix*[][0]）初始化为 1（或`true`，T），因为对于任何集合，都可以有一个和为 0 的子集。

接下来，我们取每一行（5, 1, 6, ...）并尝试用 F 或 T 填充它。让我们考虑包含元素 5 的第二行。现在，对于每一列，让我们回答以下问题：我们能用 5 形成和为*列号*的子集吗？让我们看一下输出：

![图 8.19 – 填充第二行](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.19_B15403.jpg)

图 8.19 – 填充第二行

+   我们能用 5 形成和为 1 的子集吗？不能，所以是 false（F）。

+   我们能用 5 形成和为 2 的子集吗？不能，所以是 false（F）。

...

+   我们能用 5 形成和为 5 的子集吗？能，所以是 true（T）。

+   我们能够用 5 组成和为 6 的子集吗？不行，所以为假（F）。

...

+   我们能够用 5 组成和为 9 的子集吗？不行，所以为假（F）。

我们可以尝试将这个问题应用到剩下的每一行，但是我们前进得越多，问题就会变得越困难。此外，我们没有算法无法在代码中实现这个问题。幸运的是，我们可以使用一个可以应用于每个（*row, column*）单元格的算法。这个算法包含以下步骤：

1.  当当前行（*i*）的元素大于当前列（*j*）的值时，我们只需复制前一个值（*i*-1, *j*），填入当前的（*i, j*）单元格中。

1.  如果当前行（*i*）的元素小于或等于当前列（*j*）的值，则我们查看（*i*-1, *j*）单元格，并执行以下操作：

a. 如果单元格（*i*-1, *j*）是 T，则我们也在（*i, j*）单元格中填入 T。

b. 如果单元格（*i*-1, *j*）是 F，则我们在（*i, j*）单元格中填入（*i*-1, *j-element_at_this_row*）的值。

如果我们将这个算法应用于第二行（包含元素 5），那么我们将得到以下图表中显示的相同结果：

![图 8.20 – 将算法应用于第二行](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.20_B15403.jpg)

图 8.20 – 将算法应用于第二行

根据*步骤 1*，对于 5 < 1，5 < 2，5 < 3 和 5 < 4，我们复制前一个单元格的值。当我们到达单元格（1, 5）时，我们有 5=5，所以我们需要应用*步骤 2*。更确切地说，我们应用*步骤 2b*。单元格（1-1, 5-5）是单元格（0, 0），其值为 T。因此，单元格（1, 5）被填入 T。相同的逻辑适用于其余的单元格。例如，单元格（1, 6）被填入 F，因为 F 是（0, 5）的值；单元格（1, 7）被填入 F，因为 F 是（0, 6）的值，依此类推。

如果我们将这个算法应用于所有行，那么我们将得到以下填充的矩阵：

![图 8.21 – 完整矩阵](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.21_B15403.jpg)

图 8.21 – 完整矩阵

请注意，我们突出显示了最后一个单元格（7, 9）。如果右下角的单元格的值为 T，则表示至少存在一个满足给定和的子集。如果为 F，则表示没有这样的子集。

因此，在这种情况下，存在一个子集，其和等于 9。我们能够识别它吗？是的，我们可以，通过以下算法：

1.  从右下角的单元格开始，即 T（假设这个单元格是（*i*, *j*））。

a. 如果这个单元格上面的单元格（*i*-1, *j*）是 F，则写下这一行的元素（这个元素是子集的一部分），并前往单元格（*i*-1, *j*-*element_at_this_row*）。

b. 当上方的单元格（*i*-1, *j*）是 T 时，我们向上移动到单元格（*i*-1, *j*）。

c. 重复*步骤 1a*，直到整个子集都被写下。

让我们画出我们这种情况下的子集路径：

![图 8.22 – 子集解决路径](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_8.22_B15403.jpg)

图 8.22 – 子集解决路径

因此，我们从右下角的单元格开始，即（7, 9），其值为 T。因为这个单元格是 T，我们可以尝试找到和为 9 的子集。接下来，我们应用*步骤 1a*，所以我们写下第 7 行的元素（即 2），并前往单元格（7-1, 9-2）=（6, 7）。到目前为止，子集为{2}。

接下来，我们应用*步骤 1b*，所以我们来到单元格（3, 7）。单元格上方的单元格（3, 7）的值为 F，所以我们应用*步骤 1a*。首先，我们写下第 3 行的元素，即 6。然后，我们前往单元格（3-1, 7-6）=（2, 1）。到目前为止，子集为{2, 6}。

上方的单元格（2, 1）的值为 F，所以我们应用*步骤 1a*。首先，我们写下第 2 行的元素，即 1。然后，我们前往单元格（2-1, 1-1）=（1, 0）。在（1,0）单元格上方，我们只有 T，所以我们停止。当前和最终的子集为{2, 6, 1}。显然，2+6+1=9。

以下代码将澄清任何其他细节（这段代码可以告诉我们给定的和至少有一个对应的子集）：

```java
/* Dynamic Programming (Bottom-Up) */
public static boolean findSumDP(int[] arr, int givenSum) {
    boolean[][] matrix 
          = new boolean[arr.length + 1][givenSum + 1];
    // prepare the first row
    for (int i = 1; i <= givenSum; i++) {
        matrix[0][i] = false;
    }
    // prepare the first column
    for (int i = 0; i <= arr.length; i++) {
        matrix[i][0] = true;
    }
    for (int i = 1; i <= arr.length; i++) {
        for (int j = 1; j <= givenSum; j++) {
            // first, copy the data from the above row
            matrix[i][j] = matrix[i - 1][j];
            // if matrix[i][j] = false compute 
            // if the value should be F or T
            if (matrix[i][j] == false && j >= arr[i – 1]) {
                matrix[i][j] = matrix[i][j] 
                  || matrix[i - 1][j - arr[i - 1]];
            }
        }
    }
    printSubsetMatrix(arr, givenSum, matrix);
    printOneSubset(matrix, arr, arr.length, givenSum);
    return matrix[arr.length][givenSum];
}
```

`printSubsetMatrix()`和`printOneSubset()`方法可以在名为*SubsetSum*的完整代码中找到。

## 编码挑战 15 – 单词拆分（这是一个著名的谷歌问题）

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

如果给定的字符串（*str*）可以分割成一个以空格分隔的字典单词序列，则返回`true`。

**解决方案**：这个问题在谷歌和亚马逊中很常见，在撰写本文时，它被许多中大型公司采用。如果我们在谷歌中输入一个毫无意义的字符串，那么谷歌会尝试将其分解为单词，并问我们是否这实际上是我们想要输入的。例如，如果我们输入"thisisafamousproblem"，那么谷歌会问我们是否想要输入"this is a famous problem"。

### 基于纯递归的解决方案

因此，如果我们假设给定的字符串是*str*`="`thisisafamousproblem"，给定的字典是`{`"this" "is" "a" "famous" "problem"`}`，那么我们可以得到结果；即"this is a famous problem"。

那么，我们如何做到这一点呢？我们如何检查给定的字符串是否可以分割成一个以空格分隔的字典单词序列？

让我们从一个观察开始。如果我们从给定字符串的第一个字符开始，那么我们会注意到"t"不是给定字典中的一个单词。我们可以继续将第二个字符附加到"t"，这样我们得到"th"。由于"th"不是给定字典中的一个单词，我们可以附加第三个字符"i"。显然，"thi"不是字典中的一个单词，所以我们附加第四个字符"s"。这一次，我们找到了一个单词，因为"this"是字典中的一个单词。这个单词成为结果的一部分。

进一步推理，如果我们找到了"this"，那么最初的问题就被减小为一个更小的问题，即找到剩下的单词。因此，通过添加每个字符，问题就会减小为一个更小的问题，但本质上仍然是相同的。这听起来像是递归实现的理想案例。

如果我们详细说明递归算法，那么我们必须执行以下步骤：

1.  从第一个字符（*索引*0）开始迭代给定字符串*str*。

1.  从给定字符串（通过子字符串，我们理解为从*索引*到 1 的子字符串，从*索引*到 2 的子字符串，...从*索引*到*str.length*的子字符串）中取出每个子字符串。换句话说，只要当前子字符串不是给定字典中的一个单词，我们就继续从给定字符串*str*中添加一个字符。

1.  如果当前子字符串是给定字典中的一个单词，那么我们更新索引，使其成为这个子字符串的长度，并依靠递归来检查从*索引*到*str.length*的剩余字符串。

1.  如果*索引*达到字符串的长度，我们返回`true`；否则，我们返回`false`。

这段代码如下：

```java
private static boolean breakItPlainRecursive(
      Set<String> dictionary, String str, int index) {
    if (index == str.length()) {
        return true;
    }
    boolean canBreak = false;
    for (int i = index; i < str.length(); i++) {
        canBreak = canBreak
          || dictionary.contains(str.substring(index, i + 1))
          && breakItPlainRecursive(dictionary, str, i + 1);
    }
    return canBreak;
}
```

这段代码的运行时间并不奇怪是指数级的。现在，是时候部署动态规划了。

### 自底向上的解决方案

我们可以避免递归，而是部署动态规划。更确切地说，我们可以使用这里显示的*自底向上*解决方案：

```java
public static boolean breakItBottomUp(
           Set<String> dictionary, String str) {
  boolean[] table = new boolean[str.length() + 1];
  table[0] = true;
  for (int i = 0; i < str.length(); i++) {
    for (int j = i + 1; table[i] && j <= str.length(); j++) {
      if (dictionary.contains(str.substring(i, j))) {
        table[j] = true;
      }
    }
  }
  return table[str.length()];
}
```

这段代码仍然以指数时间 O(n2)运行。

基于 Trie 的解决方案

解决这个问题的最有效方法依赖于动态规划和 Trie 数据结构，因为它提供了最佳的时间复杂度。您可以在书籍*Java 编程问题*中找到 Trie 数据结构的详细实现：([`www.amazon.com/gp/product/B07Y9BPV4W/`](https://www.amazon.com/gp/product/B07Y9BPV4W/))。

让我们考虑将给定字符串分解为表示其单词的一组组件的问题。如果*p*是*str*的前缀，*q*是*str*的后缀（剩余的字符），那么*pq*就是*str*（*p*与*q*的连接就是*str*）。如果我们可以通过递归将*p*和*q*分解为单词，那么我们可以通过合并两组单词来分解*pq=str*。

现在，让我们在给定单词字典的 Trie 的上下文中继续这种逻辑。我们可以假设*p*是字典中的一个单词，我们必须找到一种构造它的方法。这正是 Trie 派上用场的地方。因为*p*被认为是字典中的一个单词，*p*是*str*的前缀，我们可以说*p*必须通过由*str*的前几个字母组成的路径在 Trie 中找到。为了通过动态规划实现这一点，我们使用一个数组，让我们将其表示为*table*。每当我们找到一个合适的*q*时，我们通过在*table*数组中设置一个解决方案来表示它，解决方案在|*p*|+1 处，其中|*p*|是前缀*p*的长度。这意味着我们可以通过检查最后一个条目来确定整个字符串是否可以被分解。让我们看看这段代码：

```java
public class Trie {
    // characters 'a'-'z'
    private static final int CHAR_SIZE = 26;
    private final Node head;
    public Trie() {
        this.head = new Node();
    }
    // Trie node
    private static class Node {
        private boolean leaf;
        private final Node[] next;
        private Node() {
            this.leaf = false;
            this.next = new Node[CHAR_SIZE];
        }
    };
    // insert a string in Trie
    public void insertTrie(String str) {
        Node node = head;
        for (int i = 0; i < str.length(); i++) {
            if (node.next[str.charAt(i) - 'a'] == null) {
                node.next[str.charAt(i) - 'a'] = new Node();
            }
            node = node.next[str.charAt(i) - 'a'];
        }
        node.leaf = true;
    }
    // Method to determine if the given string can be 
    // segmented into a space-separated sequence of one or 
    // more dictionary words
    public boolean breakIt(String str) {
        // table[i] is true if the first i
        // characters of str can be segmented
        boolean[] table = new boolean[str.length() + 1];
        table[0] = true;
        for (int i = 0; i < str.length(); i++) {
            if (table[i]) {
                Node node = head;
                for (int j = i; j < str.length(); j++) {
                    if (node == null) {
                        break;
                    }
                    node = node.next[str.charAt(j) - 'a'];
                    // [0, i]: use our known decomposition
                    // [i+1, j]: use this String in the Trie
                    if (node != null && node.leaf) {
                        table[j + 1] = true;
                    }
                }
            }
        }
        // table[n] would be true if 
        // all characters of str can be segmented
        return table[str.length()];
    }
}
```

显然，因为我们有两个嵌套循环，所以这个解决方案的运行时间是 O(n2)。实际上，内部循环在节点为`null`时会中断。在最坏的情况下，这发生在*k*步之后，其中*k*是 Trie 中最深路径。因此，对于包含大小为*z*的最长单词的字典，我们有*k*=*z*+1。这意味着内部循环的时间复杂度是 O(z)，总时间复杂度是 O(nz)。额外空间是 O(*Trie 的空间+str.length*)。

完整的应用程序称为*WordBreak*。该应用程序还包含一个打印可以为给定字符串生成的所有字符串的方法。例如，如果给定的字符串是"thisisafamousproblem"，字典是`{"`this", "th", "is", "a", "famous", "f", "a", "m", "o", "u", "s", "problem"`}`，那么输出将包含四个序列：

+   这是一个著名的问题

+   这是一个著名的问题

+   这是一个著名的问题

+   这是一个著名的问题

完成！现在是时候总结本章了。

总结

在本章中，我们涵盖了面试中最流行的话题之一：递归和动态规划。掌握这个话题需要大量的练习。幸运的是，本章提供了一套全面的问题，涵盖了最常见的递归模式。从排列到基于网格的问题，从经典问题如汉诺塔到棘手的问题如生成花括号，本章涵盖了广泛的递归案例。

不要忘记解决递归问题的关键在于绘制有意义的草图并练习多种情况。这样，您可以识别模式和递归调用。

在下一章中，我们将讨论需要位操作的问题。
