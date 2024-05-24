# 构建大规模 Angular Web 应用（四）

> 原文：[`zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43`](https://zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：函数式响应式编程

根据维基百科，**函数式响应式编程** (**FRP**) 是用于响应式编程的一种编程范式，它使用函数式编程的构建模块。好的，这听起来挺高大尚的，但是它是什么意思呢？要理解整个句子，我们需要把它拆开来。让我们试着定义以下内容：

+   **编程范式** 是围绕程序应该如何组织和结构化的总体理论或工作方式。面向对象编程和函数式编程就是编程范式的例子。

+   **响应式编程** 简单来说是利用异步数据流进行编程。异步数据流是值可以在任何时间到达的数据流。

+   **函数式编程** 是一种采用更数学化方法的编程范式，它将函数调用视为数学计算，从而避免更改状态或处理可变数据。

总的来说，我们的维基百科定义意味着我们对可能在任何时间到达的值采取了一种函数式编程方法。这并不意味着太多，但希望在本章结束时事情会有所明朗。

在本章中，我们将学习以下内容：

+   异步数据流

+   如何操作这些流

# 递归

“要理解递归这个词，请参见递归这个词。”

这在大多数工程学校都是一个笑话，并且以一种非常简短的方式解释了这是什么。递归是一个数学概念。让我们稍微解释一下。官方定义如下：

当过程的一个步骤涉及到调用过程本身时，递归是过程通过的过程。进行递归的过程被称为“递归的”。

好的，那用人话怎么说？这意味着在运行我们的函数的某个时刻，我们会调用自己。这意味着我们有一个看起来像这样的函数：

```ts
function something() {
  statement;
  statement;
  if(condition) {
    something();
  }
  return someValue;
}
```

我们可以看到函数`something()` 在其体内的某个时刻调用了自身。递归函数应该遵守以下规则：

+   应该调用自身

+   最终应该满足退出条件

如果递归函数没有退出条件，我们将耗尽内存，因为函数将永远调用自身。有某些类型的问题比其他更适合应用递归编程。这些类型的问题的例子有：

+   遍历树结构

+   编译代码

+   为压缩编写算法

+   对列表进行排序

还有许多其他例子，但重要的是要记住，尽管递归是一个很好的工具，但不应该随处使用。让我们看一个递归真正闪耀的例子。我们的例子是一个链接列表。链接列表由了解他们连接到的节点的节点组成。`Node`结构的代码如下：

```ts
class Node {
  constructor(
    public left, 
    public value
  ) {}
}
```

使用`Node`这样的结构，我们可以构建一个由几个链接节点组成的链表。我们可以以以下方式连接一组节点实例：

```ts
const head = new Node(null, 1);
const firstNode = new Node(head, 2);
const secondNode = new Node(firstNode, 3);
```

上述代码的图形表示将如下图所示。在这里，我们可以清楚地看到我们的节点由什么组成以及它们如何连接：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/f652d7d8-c911-4829-89a2-05694b6a39b1.png)

这里，我们有一个链表，其中有三个相连的节点实例。头节点与左侧节点不相连。然而第二个节点连接到第一个节点，而第一个节点连接到头节点。对列表进行以下类型的操作可能会很有趣：

+   给定列表中的任意节点，找到头节点

+   在列表中的特定位置插入一个节点

+   从列表中的给定位置移除一个节点

让我们看看如何解决第一个要点。首先，我们将使用命令式方法，然后我们将使用递归方法来看看它们如何不同。更重要的是，让我们讨论为什么递归方法可能更受欢迎：

```ts
// demo of how to find the head node, imperative style

const head = new Node(null, 1);
const firstNode = new Node(head, 2);
const secondNode = new Node(firstNode, 3); 

function findHeadImperative (startNode)  {
  while (startNode.left !== null) {
    startNode = startNode.left;
  }
  return startNode;
}

const foundImp = findHeadImperative(secondNode);
console.log('found', foundImp);
console.log(foundImp === head);

```

正如我们在这里所见，我们使用`while`循环来遍历列表，直到找到其`left`属性为 null 的节点实例。现在，让我们展示递归方法：

```ts
// demo of how to find head node, declarative style using recursion

const head = new Node(null, 1);
const firstNode = new Node(head, 2);
const secondNode = new Node(firstNode, 3); 

function findHeadRecursive(startNode) {
  if(startNode.left !== null) {
    return findHeadRecursive(startNode.left);
  } else {
    return startNode;
  }
}

const found = findHeadRecursive(secondNode);
console.log('found', found);
console.log(found === head);

```

在上面的代码中，我们检查`startNode.left`是否为 null。如果是这种情况，我们已经到达了我们的退出条件。如果我们尚未达到退出条件，我们继续调用自己。

好的，我们有一个命令式方法和一个递归方法。为什么后者更好？嗯，使用递归方法，我们从一个长列表开始，每次调用自己的时候都使列表变短：有点*分而治之*的方法。递归方法显著突出的一点是，我们通过说不，我们的退出条件还没有满足，继续处理。继续处理意味着我们像在我们的`if`子句中那样调用自己。递归编程的要点是我们能减少代码行数吗？嗯，这可能是结果，但更重要的是：它改变了我们解决问题的思维方式。在命令式编程中，我们有一种*从上到下解决问题*的思维方式，而在递归编程中，我们的思维方式更多地是定义我们何时完成并将问题分解为更容易处理的部分。在上述情况下，我们舍弃了不再感兴趣的部分链表。

# 不再使用循环

当开始以更功能化的方式编码时，其中一个更显著的变化是我们摆脱了`for`循环。现在我们已经了解了递归，我们可以使用它代替。让我们看一个简单的命令式代码片段，用于打印一个数组：

```ts
// demo of printing an array, imperative style

let array = [1, 2, 3, 4, 5];

function print(arr) {
  for(var i = 0, i < arr.length; i++) {
    console.log(arr[i]); 
  }
}

print(arr);
```

使用递归的相应代码如下：

```ts
// print.js, printing an array using recursion

let array = [1, 2, 3, 4, 5];

function print(arr, pos, len) {
  if (pos < len) {
    console.log(arr[pos]);
    print(arr, pos + 1, len);
  }
  return;
}

print(array, 0, array.length);
```

如我们所见，我们的命令式代码仍在那里。我们依然从`0`开始。此外，我们一直持续到我们到达数组的最后位置。一旦我们达到我们的中断条件，我们就退出方法。

# 重复模式

到目前为止，我们还没有完全说明递归的概念。我们可能有点理解，但可能还不确定为什么不能使用老式的`while`或`for`循环来代替。递归在解决看起来像重复模式的问题时才会显现。一个例子是树。树有一些类似的概念，例如由节点组成。一个没有子节点连接的节点称为叶子。具有子节点但与上游节点没有连接的节点称为根节点。让我们用图示说明这一点：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/15dea50b-92d5-4552-a346-f62c97b2c3dd.png)

有一些我们想要在树上进行的有趣操作：

+   总结节点值

+   计算节点数

+   计算宽度

+   计算深度

为了尝试解决这个问题，我们需要考虑如何将树以数据结构的形式存储。最常见的建模方式是创建一个表示节点具有值、`left`属性和`right`属性的表示方法，然后这两个属性分别指向节点。因此，上述 Node 类的代码可能如下：

```ts
class NodeClass {
  constructor(left, right, value) {
    this.left = left;
    this.right = right;
    this.value = value;
  }
}
```

下一步是考虑如何创建树本身。此代码展示了我们如何创建一个具有根节点和两个子节点的树，以及如何将它们绑定在一起：

```ts
// tree.js

class NodeClass {
  constructor(left, right, value) {
    this.left = left;
    this.right = right;
    this.value = value;
  }
}

const leftLeftLeftChild = new NodeClass(null, null, 7);
const leftLeftChild = new NodeClass(leftLeftLeftChild, null, 1);
const leftRightChild = new NodeClass(null, null, 2);
const rightLeftChild = new NodeClass(null, null, 4);
const rightRightChild = new NodeClass(null, null, 2);
const left = new NodeClass(leftLeftChild, leftRightChild, 3);
const right = new NodeClass(rightLeftChild, rightRightChild, 5);
const root = new NodeClass(left, right, 2);

module.exports = root;

```

值得强调的是实例`left`和`right`没有子节点。这是因为我们在创建时将它们的值设置为`null`。另一方面，我们的根节点有`left`和`right`对象实例作为子节点。

# 总结

之后，我们需要考虑如何总结节点。看着它，似乎我们应该总结顶部节点及其两个子节点。因此，代码实现将开始如下：

```ts
// tree-sum.js

const root = require('./tree');

function summarise(node) {
  return node.value + node.left.value + node.right.value;
}

console.log(summarise(root)) // 10
```

如果我们的树增长并突然变成这样时会发生什么：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/55827453-fc7c-48d9-adec-c64752c69d31.png)

让我们添加到前面的代码，使其看起来像这样：

```ts
// example of a non recursive code

function summarise(node) {
  return node.value + 
    node.left.value + 
    node.right.value +
    node.right.left.value +
    node.right.right.value + 
    node.left.left.value + 
    node.left.right.value;
}

console.log(summarise(root)) // 19
```

这在技术上是可工作的代码，但还可以改善。在这一点上，从树的角度看，我们应该看到树中的重复模式。我们有以下三角形：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2dca4bd2-7346-45d3-9a0f-22b956b7e5b4.png)

一个三角形由**2**，**3**，**5**组成，另一个由**3**，**1**，**2**组成，最后一个由**5**，**4**，**2**组成。每个三角形通过取节点本身及其左子节点和右子节点来计算其总和。递归就是这样的：发现重复模式并对其进行编码。现在我们可以使用递归来实现我们的`summarise()`函数，如下所示：

```ts
function summarise(node) {
  if(node === null) {
    return 0;
  }
  return node.value + summarise(node.left) + summarise(left.right);
}
```

我们在这里做的是将我们的重复模式表示为*节点 + 左节点 + 右节点*。当我们调用`summarise(node.left)`时，我们简单地再次运行`summarise()`以获得该节点。前面的实现简短而优雅，并能遍历整个树。一旦你发现问题可以看作是一个重复模式时，递归真是优雅。完整的代码看起来像这样：

```ts
// tree.js

class NodeClass {
  constructor(left, right, value) {
    this.left = left;
    this.right = right;
    this.value = value;
  }
}

const leftLeftLeftChild = new NodeClass(null, null, 7);
const leftLeftChild = new NodeClass(leftLeftLeftChild, null, 1);
const leftRightChild = new NodeClass(null, null, 2);
const rightLeftChild = new NodeClass(null, null, 4);
const rightRightChild = new NodeClass(null, null, 2);
const left = new NodeClass(leftLeftChild, leftRightChild, 3);
const right = new NodeClass(rightLeftChild, rightRightChild, 5);
const root = new NodeClass(left, right, 2);

module.exports = root;

// tree-sum.js

const root = require("./tree");

function sum(node) {
  if (node === null) {
    return 0;
  }
  return node.value + sum(node.left) + sum(node.right);
}

console.log("sum", sum(root));
```

# 计数

现在，实现一个用于计算树中所有节点的函数变得非常简单，因为我们开始理解递归的本质。我们可以重新使用以前的总结函数，并将每个非空节点简单地计为`1`，空节点计为`0`。因此，我们可以简单地修改现有的总结函数如下：

```ts
//tree-count.js

const root = require("./tree");

function count(node) {
  if (node === null) {
    return 0;
  } else {
    return 1 + count(node.left) + count(node.right);
  }
}

console.log("count", count(root));
```

上述代码确保我们成功遍历每个节点。我们的退出条件是当我们达到 null。也就是说，我们正在从一个节点尝试去到其不存在的子节点之一。

# 宽度

要创建一个宽度函数，我们首先需要定义宽度是什么意思。让我们再次看看我们的树：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/037af05f-c033-4f06-b319-13b1ccabd7ba.png)

这棵树的宽度是**4**。为什么呢？对于树中每走一步，我们的节点向左和向右各扩展一步。这意味着为了正确计算宽度，我们需要遍历树的边缘。每当我们需要遍历一个节点向左或向右时，我们就增加宽度。从计算的角度来看，我们感兴趣的是这样遍历这棵树：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b6f53eb4-fe4a-4426-bd82-1d109f03ff20.png)

因此，代码应反映这一事实。我们可以这样实现：

```ts
// tree-width.js

const root = require("./tree");

function calc(node, direction) {
  if (node === null) {
    return 0;
  } else {
    return (
      1 + (direction === "left" ? 
      calc(node.left, direction) : 
      calc(node.right, direction))
    );
  }
}

function calcWidth(node) {
  return calc(node.left, "left") + calc(node.right, "right");
}

console.log("width", calcWidth(root));
```

特别注意，在`calcWidth()`函数中，我们分别用`node.left`和`node.right`作为参数调用`calc()`。我们还添加了`left`和`right`参数，这在`calc()`方法中意味着我们将沿着那个方向继续前进。我们的退出条件是最终碰到 null。

# 异步数据流

异步数据流是一种数据流，在延迟后一个接着一个地发出值。异步一词意味着发出的数据可能在任何时候出现，可能在一秒后或甚至在两分钟后出现。对于模拟异步流的一种方法是在时间轴上放置发出的值，就像这样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/1a0a21dc-1d98-4f8d-a994-e90bdcf480e2.png)

有很多事情可能被视为异步。其中一个是通过 AJAX 获取数据。数据到达的时间取决于许多因素，比如：

+   您的连接速度

+   后端 API 的响应速度

+   数据的大小，以及更多的因素。

这一点是数据并非在这一刻就到达。

其他可能被视为异步的事物包括用户发起的事件，比如滚动或鼠标点击。这些是可以在任何时间发生的事件，取决于用户的交互。因此，我们可以将这些用户界面事件视为时间轴上的连续数据流。以下图表描述了代表用户多次点击的数据流。每次点击会触发一个点击事件**c**，其在时间轴上的位置如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/834c40dd-9c02-4f1b-85de-68436e9ffe17.png)

乍一看，我们的图表显示了四次点击事件。仔细观察，我们可以看到这些点击事件似乎被分组了。上面的图表包含了两条信息：

+   已发生多次点击事件

+   点击事件之间存在一定的延迟

在这里，我们可以看到前两次点击事件发生的时间非常接近；当两个事件发生的时间非常接近时，这将被解释为双击。因此，上面的图告诉我们发生的事件；它还告诉我们发生的时间和频率。通过查看前面的图表，很容易区分单击和双击。

我们可以为每种点击行为分配不同的动作。双击可能意味着我们想要放大，而单击可能意味着我们想要选择某些内容；确切的行为取决于您正在编写的应用程序。

第三个例子是输入。如果我们遇到一种情况，用户正在输入并在一段时间后停止了输入呢？在一定时间过去后，用户期望 UI 有所反应。这就是搜索字段的情况。在这种情况下，用户可能会在搜索字段中输入内容，并且在完成后按下搜索按钮。在 UI 中模拟这种情况的另一种方法是仅提供一个搜索字段，并等待用户停止输入，作为何时开始搜索用户想要的内容的信号。最后的例子被称为**自动完成**行为。可以以以下方式对其进行模拟：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7aa371c4-cb52-409d-8c11-fbc31f79ad3c.png)

输入的前三个字符似乎属于同一个搜索查询，而输入的第四个字符则出现得晚得多，可能属于另一个查询。

本节的重点在于突出不同事物适合被建模为流，并且时间轴以及发出值的放置在时间轴上的意义。

# 将列表与异步流进行比较 - 为使用 RxJS 做准备

到目前为止，我们已经讨论了如何将异步事件建模为时间轴上的连续数据流，或者说是流建模。事件可以是 AJAX 数据，鼠标点击，或其他类型的事件。通过这种方式对事物进行建模，会产生一种有趣的视角，但是，例如，仅仅看双击的情况，并不能让我们深入了解这个数据。还有另一种情况，我们需要过滤掉一些数据。我们在这里讨论的是如何操作数据流。如果没有这个能力，流建模本身就没有实际价值。

有不同的方法来操作数据：有时我们想要将发出的数据更改为其他数据，有时我们可能想更改将数据发送给监听器的频率。有时，我们希望我们的数据流变成完全不同的流。我们将尝试模拟以下情况：

+   **投影**：改变正在发出的值的数据

+   **过滤**：改变发出的内容

# 将函数式编程范式与流相结合

本章涵盖了函数式编程和异步数据流。使用 RxJS 并不需要对函数式编程有深入的理解，但是你需要理解声明式的意思，以期聚焦在正确的事情上。你的重点应该是要做什么，而不是如何做。作为一个库，RxJS 会负责如何实现需要的功能。

这两个可能看起来像是两个不同的主题。但是，将它们结合起来，我们就能够操纵流了。流可以被看作是一系列数据的列表，其中数据在某个时间点可用。如果我们开始将我们的流视为列表，特别是不可变的列表，那么就会有一些随列表一起的操作来通过对其应用操作符来操纵列表。操纵的结果是一个新的列表，而不是一个变异的列表。因此，让我们开始将我们的列表哲学及其操作符应用到以下情况中。

# 投影

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/fd4ecfc2-02b0-436b-946e-0e42628f3d38.png)

在这里，我们可以看到我们的流正在发出值 **1**、**2**、**3** 和 **4**，然后进行了一次变换，将每个值增加了一。这是一个相当简单的情况。如果我们将其视为一个列表，我们可以看到这里所做的只是一个简单的投影，我们会将其编码为：

```ts
let newList = list.map(value => value + 1)
```

# 过滤

列表中可能存在一些项，以及流中可能存在一些你不想要的项。为了解决这个问题，你需要创建一个过滤器来过滤掉不想要的数据。模拟我们初始的数组，经过处理和得到的数组，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/ce0ec1ee-e3f3-4327-879c-80d0a271abd2.png)

在 JavaScript 中，我们可以通过编写以下代码来实现这一点：

```ts
let array = [1,2,3];
let filtered = array.filter(data => data % 2 === 0);
```

# 结合心态

那么，我们在这一节想要表达什么呢。显然，我们已经展示了如何操纵列表的例子。好吧，我们所做的是展示我们如何在轴上显示项。从这个意义上说，我们可以看到，以图形方式将异步事件和值列表想成一样的方式，这样思考起来是很容易的。问题是，为什么我们要这样做呢？原因是这是 RxJS 库希望你在开始操纵和构建流时拥有的心态。

# 摘要

本章已经建立了我们可以将异步事件建模为时间轴上的值。我们介绍了将这些流与列表进行比较的想法，并因此对它们应用不会改变列表本身而只会创建一个新列表的函数方法。应用函数范式的好处是，我们可以专注于想要*实现*的内容，而不是如何实现它，从而采用了一种声明式方法。我们意识到要将异步和列表组合，从中创建可读的代码并不容易。幸运的是，这正是 RxJS 库为我们做的事情。

这一认识让我们为第八章做准备，*RxJS 高级*，将涵盖更多的操作符和一些更高级的概念。


# 第七章：操纵流及其值

操作符是我们可以在流上调用的函数，以多种不同的方式执行操作。操作符是不可变的，这使得流易于推理，并且也很容易测试。正如你将在本章中看到的，我们很少处理一个流，而是处理许多流，理解如何塑造和控制这些流，让你能够从认为这是*黑魔法*转变为在需要时真正应用 RxJS。

在本章中，我们将涵盖：

+   如何使用基本操作符

+   使用操作符以及现有工具调试流

+   深入了解不同的操作符类别

+   以 Rx 的方式培养解决问题的思维方式

# 初始阶段

你几乎总是从创建一组静态值的 RxJS 开始编码。为什么要使用静态值？嗯，没有必要使它过于复杂，你真正需要开始推理的只是一个`Observable`。

然后你开始考虑你想达到什么目标。这让你考虑到你可能需要哪些操作符，以及你需要以哪种顺序应用它们。你可能还会思考如何划分你的问题；这通常意味着创建多个流，每个流解决一个与你尝试解决的更大问题相关的特定问题。

让我们从流创建开始，看看我们如何开始使用流的第一步。

以下代码创建一组静态值的流：

```ts
const staticValuesStream$ = Rx.Observable.of(1, 2, 3, 4);

staticValuesStream$.subscribe(data => console.log(data)); 
// emits 1, 2, 3, 4
```

这是一个非常基本的示例，展示了我们如何创建一个流。我们使用了 `of()` 创建操作符，它接受任意数量的参数。只要有订阅者，所有参数都会一个接一个地被发射出来。在上述代码中，我们还通过调用`subscribe()`方法并传递一个以发射的值作为参数的函数来订阅`staticValuesStream$`。

让我们介绍一个操作符，`map()`，它像一个投影，允许你改变正在发射的值。在发射之前，`map()`操作符针对流中的每个值都会被调用。

你可以通过提供一个函数并进行投影来使用`map()`操作符：

```ts
const staticValuesStream$ = 
Rx.Observable
  .of(1, 2, 3, 4)
  .map(data => data + 1); 

staticValuesStream$.subscribe(data => console.log(data))
// emits 2, 3, 4, 5
```

在上述代码中，我们已将`map()`操作符追加到`staticValuesStream$`上，并在发射每个值之前应用它，并将其递增一个。因此，生成的数据已经发生改变。这就是如何将操作符追加到流中的：简单地创建流，或者获取现有的流，并逐个追加操作符。

让我们再添加另一个运算符 `filter()`，以确保我们真正理解如何使用运算符。`filter()` 做什么？嗯，就像 `map()` 运算符一样，它被应用于每个值，但不是创建一个投影，而是决定哪些值将被发出。 `filter()` 接受一个布尔值。任何评估为 `true` 的表达式意味着该值将被发出；如果为 `false`，该表达式将不会被发出。

您可以如下使用 `filter()` 运算符：

```ts
const staticValuesStream$ = 
Rx.Observable
  .of(1, 2, 3, 4)
  .map(data => data + 1)
  .filter(data => data % 2 === 0 ); 

staticValuesStream$.subscribe(data => console.log(data));
// emits 2, 4
```

我们将 `filter()` 运算符添加到现有的 `map()` 运算符中。我们给 `filter()` 运算符的条件是只返回能被 `2` 整除的 `true` 值，这就是模运算符的功能。我们知道，仅有 `map()` 运算符本身可以确保值 `2`、`3`、`4` 和 `5` 被发出。这些值现在正在被 `filter()` 运算符评估。在这四个值中，只有 `2` 和 `4` 符合 `filter()` 运算符设定的条件。

当在流上工作并应用运算符时，事情可能并不总是像前面的代码那样简单。也许无法准确预测哪些内容被发出。针对这些场合，我们有一些可以使用的技巧。其中之一是使用 `do()` 运算符，它将允许我们检查每个值而不更改它。这为我们提供了充分的机会将其用于调试目的。根据我们在流中所处的位置，`do()` 运算符将输出不同的值。让我们看看应用 `do()` 运算符的地方很重要的不同情况：

```ts
const staticValuesStream$ = 
Rx.Observable.of(1, 2, 3, 4)
  .do(data => console.log(data)) // 1, 2, 3, 4 
  .map(data => data + 1)
  .do(data => console.log(data)) // 2, 3, 4, 5
  .filter(data => data % 2 === 0 )
  .do(data => console.log(data)); // 2, 4 

// emits 2, 4
staticValuesStream$.subscribe(data => console.log(data))
```

通过使用 `do()` 运算符，您可以看到，当我们的流变得越来越复杂时，我们有一种很好的方式来调试我们的流。

# 理解运算符

到目前为止，我们展示了如何创建一个流并在其上使用一些非常基本的运算符来更改发出的值。我们还介绍了如何使用 `do()` 运算符来检查您的流而不更改它。并不是所有运算符都像 `map()`、`filter()` 和 `do()` 运算符那样容易理解。有不同的策略可以尝试理解每个运算符的功能，以便知道何时使用它们。使用 `do()` 运算符是一种方法，但您还可以采取图形方法。这种方法被称为大理石图。它由表示时间从左向右流逝的箭头组成。在这个箭头上有圆圈或大理石，代表已发出的值。大理石上有一个值，但大理石之间的距离也可以描述随时间发生的情况。大理石图通常由至少两个带有大理石的箭头组成，以及一个运算符。其目的是表示在应用运算符时流发生了什么。第二个箭头通常代表产生的流。

这是一个示例的大理石图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2dd33126-5938-4564-886a-9e438aff2bd5.png)

RxJS 中的大多数操作符都在 RxMarbles 网站上通过弹图表进行描述：[`rxmarbles.com/`](http://rxmarbles.com/)。这是一个快速理解操作符作用的绝妙资源。然而，要真正理解 RxJS，你需要编写代码；这个绕不过去。当然可以用不同的方法。你可以轻松地搭建自己的项目，并从 NPM 安装 RxJS，通过 CDN 链接引用它，或者使用类似 JS Bin（[www.jsbin.com](http://www.jsbin.com)）这样的页面，可以方便地将 RxJS 作为库添加，并立即开始编写代码。效果看起来有点像这样：

![图片](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/8e925f0d-1dd4-4302-8c65-5b5cda1a65ff.png)

JS Bin 让启动变得容易，但如果我们可以将拱形图表和 JS Bin 结合起来，当你编写代码时得到代码的图形表示这岂不是很棒？通过 RxFiddle，你可以做到这一点：[`rxfiddle.net/`](http://rxfiddle.net/)。你可以输入代码，点击运行，就会显示你刚刚编写的拱形图表，看起来是这样的：

![图片](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/66aadd7c-2b3c-4255-9a7a-13f5a6bc64d6.png)

# 流中的流

我们一直在研究改变被发出的值的不同操作符。流的另一个不同方面是：如果你需要从现有流中创建新流怎么办？这种情况通常会发生在什么时候？有很多情况，比如：

+   基于一个键盘按键弹起事件的流，进行 AJAX 调用。

+   统计点击次数，并确定用户是否单击、双击或三击。

你明白了吧；我们开始于一种类型的流，需要转换成另一种类型的流。

让我们先来看看创建一个流，并观察使用操作符创建流的结果时会发生什么：

```ts
let stream$ = Rx.Observable.of(1,2,3)
  .map(data => Rx.Observable.of(data));

// Observable, Observable, Observable
stream$.subscribe(data => console.log(data));
```

此时，通过`map()`操作符传递的每个值都会产生一个新的`Observable`。当你订阅`stream$`时，每个发出的值都将是一个流。你的第一反应可能是对每个值附加一个`subscribe()`，像这样：

```ts
let stream$ = Rx.Observable
  .of(1,2,3)
  .map(data => Rx.Observable.of(data))

stream$.subscribe(data => {
  data.subscribe(val => console.log(val))
});

// 1, 2, 3
```

抵制这种冲动。这样只会创建难以维护的代码。你想要的是将所有这些流合并成一个，这样你只需要一个`subscribe()`。这里有一个专门用于此目的的操作符，叫做`flatMap()`。`flatMap()`的作用是将你的一系列流转换成一个流，一个元流。

它的使用方式如下：

```ts
let stream$ = Rx.Observable.of(1,2,3)
  .flatMap(data => Rx.Observable.of(data))

stream$.subscribe(data => {
  console.log(val);
});

// 1, 2, 3
```

好吧，我们明白了，我们不想要一系列的 Observables，而是要一系列的值。这个操作符看起来确实很棒。但我们仍不太确定何时使用。让我们使这更具体一点。想象一下，你有一个界面由一个输入字段组成。用户在那个输入字段中输入字符。假设你想要对输入一个或多个字符做出反应，并且，例如，根据输入的字符执行一个 AJAX 请求的结果。我们在这里关注两件事：如何收集输入的字符，以及如何执行 AJAX 请求。

让我们从第一件事开始，捕捉输入字段中输入的字符。为此，我们需要一个 HTML 页面和一个 JavaScript 页面。让我们从 HTML 页面开始：

```ts
<html>
  <body>
    <input id="input" type="text">
    <script src="img/Rx.min.js"></script>
    <script src="img/app.js"></script>
  </body>
</html>

```

这描述了我们的输入元素和对 RxJS 的脚本引用，以及对`app.js`文件的引用。然后我们有`app.js`文件，在这里我们获取输入元素的引用，并开始监听一旦它们输入的按键：

```ts
let elem = document.getElementById('input');
let keyStream$ = Rx.Observable
  .fromEvent(elem, 'keyup')
  .map( ev => ev.key);

keyStream$.subscribe( key => console.log(key));

// emits entered key chars
```

值得强调的是，我们开始监听通过调用`fromEvent()`创建操作符发出的`keyup`事件。然后，我们应用`map()`操作符来提取存储在`ev.key`上的字符值。最后，我们订阅这个流。预期地，运行这段代码将导致字符在 HTML 页面输入值后立即在控制台中键入。

让我们通过所输入的内容来做一个基于 AJAX 请求更具体些。为此，我们将使用`fetch()`API 和名为 swapi（swapi.com）的在线 API，其中包含了有关星球大战电影信息的一系列 API。首先定义我们的 AJAX 调用，然后看看它如何适应我们现有的按键流。

我们说我们将使用`fetch()`。它让我们可以简单地构建一个 GET 请求如下所示：

```ts
fetch('https://swapi.co/api/people/1')
  .then(data => data.json())
  .then(data => console.log('data', data));
```

当然，我们希望将这个请求转换成一个`Observable`，这样它就可以很好地与我们的`keyStream$`配合使用。幸运的是，通过使用`from()`操作符，我们很容易就可以做到这一点。然而，首先让我们将我们的`fetch()`调用重写成一个更容易使用的方法。重写的结果如下：

```ts
function getStarwarsCharacterStream(id) {
  return fetch('https://swapi.co/api/people/' + id)
    .then(data => data.json());
}

```

这段代码允许我们提供一个用于构建 URL 的参数，然后我们可以使用它来进行 AJAX 请求获取一些数据。在这一点上，我们准备将我们的函数连接到我们现有的流。我们通过输入以下内容来做到这一点：

```ts
let keyStream$ = Rx.Observable.fromEvent(elem, 'keyup')
  .map(ev => ev.key)
  .filter(key => key !== 'Backspace')
 .flatMap( key =>
    Rx.Observable
      .from(getStarwarsCharacterStream(key))
  );

```

我们用粗体突出了`flatmap()`操作符的使用，使用了我们的`from()`转换操作符。最后提到的操作符将我们的`getStarwarsCharacterStream()`函数作为参数。`from()`操作符将该函数转换为一个流。

在这里，我们学会了如何连接两个不同的流，同时也学会了如何将`Promise`转换成一个流。尽管这种方法在纸上看起来很不错，但使用`flatMap()`是有局限性的，重要的是要理解它们是什么。因此，让我们讨论下一个`switchMap()`操作符。当我们执行长时间运行的任务时，使用`switchMap()`操作符的好处将变得更加明显。为了论证起见，让我们定义这样一个任务，如下所示：

```ts
function longRunningTask(input) {
  return new Promise(resolve => {
    setTimeout(() => {
      resolve('response based on ' + input);
    }, 5000);
  });
}
```

在这段代码中，我们有一个需要 5 秒才能执行完的函数；足够长的时间来展示我们想要说明的问题。接下来，让我们看看在以下代码中继续使用`flatMap()`操作符会有什么影响：

```ts
let longRunningStream$ = keyStream$
  .map(ev => ev.key)
  .filter(key => elem.value.length >3)
  .filter( key => key !== 'Backspace')
  .flatMap( key =>
    Rx.Observable
      .from(longRunningTask(elem.value))
  );

longRunningStream$.subscribe(data => console.log(data));
```

前面的代码工作方式是：每次敲击键盘都会生成一个事件。然而，我们放置了一个`.filter()`操作符来确保只有在输入至少四个键后才会生成一个事件，`filter(key => elem.value.length >3)`。现在让我们来谈谈用户此时的期望。如果用户在输入控件中输入字符，他们很可能希望在输入完成时进行请求。用户将“完成”定义为输入一些字符，并且应该能够在输入错误时删除字符。因此，我们可以假设以下输入序列：

```ts
// enters abcde
abcde
// removes 'e'
```

此时，他们已经输入了字符，并且，在一个合理的时间内，编辑了他们的答案。用户期望基于`abcd`接收到一个答案。然而使用`flatMap()`操作符意味着用户将会收到两个答案，因为实际上他们输入了`abcde`和`abcd`。想象一下根据这两个输入得到一个结果列表；很可能会是两个看起来有些不同的列表。根据我们的代码得到的响应如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3938298b-e064-4bb3-8144-209f7a6a3ca8.png)

我们的代码很可能能够处理描述的情况，即在新响应到达时立即重新渲染结果列表。但是这样做有两个问题：首先，我们对`abcde`进行了不必要的网络请求；其次，如果后端响应速度足够快，我们将在 UI 中看到闪烁，因为结果列表首先被渲染一次，然后不久之后基于第二个响应再次被渲染。这并不好，我们希望出现这样的情况：一直输入时第一个请求将被放弃。这就是`switchMap()`操作符的用处，它确实可以做到这一点。因此，让我们修改前面的代码如下：

```ts
let longRunningStream$ = keyStream$
  .map(ev => ev.key)
  .filter(key => elem.value.length >3)
  .filter( key => key !== 'Backspace')
  .switchMap( key =>
    Rx.Observable
    .from(longRunningTask(elem.value))
  );
```

在这段代码中，我们简单地将我们的`flatMap()`切换到了`switchMap()`。当我们以完全相同的方式执行代码，也就是，用户首先输入`12345`，然后很快将其改为`1234`时，最终结果是：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b72340e6-3015-478b-9f37-7b674949fcb8.png)

正如我们所看到的，我们只收到了一个请求。原因是当新事件发生时，前一个事件被中止了——`switchMap()`发挥了它的魔力。用户很高兴，我们也很满意。

# AJAX

我们已经提及了如何进行 AJAX 请求的话题。有许多方式可以进行 AJAX 请求；最常见的两种方法是：

+   使用 fetch API；fetch API 是 Web 标准，因此内置在大多数浏览器中

+   使用`ajax()`方法，现在内置到 RxJS 库中；它曾经存在于一个名为 Rx.Dom 的库中

# fetch()

`fetch()`API 是一种 Web 标准。你可以在以下链接找到官方文档：[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)。`fetch()`API 是基于`Promise`的，这意味着我们需要在使用之前将其转换为`Observable`。该 API 公开了一个`fetch()`方法，该方法将 URL 作为第一个参数传入，第二个参数是一个可选对象，允许您控制要发送什么主体，如果有的话，要使用哪个 HTTP 动词等等。

我们已经提到了如何在 RxJS 的上下文中最好地处理它。但值得再次重申一下。然而，把我们的 fetch 放入`from()`操作符并不像简单。让我们写一些代码看看为什么：

```ts
let convertedStream$ = 
Rx.Observable.from(fetch('some url'));

convertedStream$.subscribe(data => 'my data?', data);
```

我们得到了我们的数据对吧？抱歉，不对，我们得到了一个`Response`对象。但这很简单，只需在`map()`操作符中调用`json()`方法，那么我们就有了我们的数据？再次抱歉，不对，当你键入以下内容时，`json()`方法会返回一个`Promise`：

```ts
let convertedStream$ = Rx.Observable.from(fetch('some url'))
  .map( r=> r.json());

// returns PromiseObservable
convertedStream$.subscribe(data => 'my data?', data);
```

在前一节中，我们已经展示了一种可能的解决方案，即以下结构：

```ts
getData() {
  return fetch('some url')
    .then(r => r.json());
}

let convertedStream$ = Rx.Observable.from(getData());
convertedStream$.subscribe(data => console.log('data', data));
```

在这段代码中，我们只是简单地处理了将数据从`from()`操作符传递出来之前挖掘出来的工作。用 Promise 玩耍并不太像 RxJS。你可以采取更多基于流的方法；我们几乎就快到达目的地了，我们只需要做一个小调整：

```ts
let convertedStream$ = Rx.Observable.from(fetch('some url'))
  .flatMap( r => Rx.Observable.from(r.json()));

// returns data
convertedStream$.subscribe(data => console.log('data'), data);
```

就是这样：我们的`fetch()`调用现在提供了像流一样的数据。那我们做了什么呢？我们将我们的`map()`调用更改为`flatMap()`调用。原因是当我们调用`r.json()`时，我们得到了一个`Promise`。我们通过将其包装在`from()`调用中`Rx.Observable.from(r.json())`解决了这个问题。这将使流发出一个`PromiseObservable`，除非我们从`map()`改为`flatMap()`。正如我们在前一节中学到的，如果我们冒着在流内部创建一个流的风险，我们需要`flatMap()`来拯救我们，而它也确实做到了。

# ajax()操作符

与基于`Promise`的`fetch()`API 不同，`ajax()`方法实际上是基于`Observable`的，这让我们的工作变得有点更容易。使用它非常简单，就像这样：

```ts
Rx.Observable
  .ajax('https://swapi.co/api/people/1')
  .map(r => r.response)
  .subscribe(data => console.log('from ajax()', data));
```

如我们所见，前面的代码调用`ajax()`操作符，并将 URL 作为参数。值得一提的是调用`map()`操作符，它从`response`属性中挖出我们的数据。因为它是一个`Observable`，我们只需像往常一样调用`subscribe()`方法并提供监听函数作为参数来订阅它。

这涵盖的是在你想要使用 HTTP 动词`GET`获取数据的简单情况。幸运的是，我们可以很容易地通过使用`ajax()`的重载版本来创建、更新或删除数据，这个版本接受一个`AjaxRequest`对象实例，其中包括以下字段：

```ts
url?: string;
body?: any;
user?: string;
async?: boolean;
method?: string;
headers?: Object;
timeout?: number;
password?: string;
hasContent?: boolean;
crossDomain?: boolean;
withCredentials?: boolean;
createXHR?: () => XMLHttpRequest;
progressSubscriber?: Subscriber<any>;
responseType?: string;
```

这个对象规范中所列的所有字段都是可选的，并且我们可以通过请求配置相当多的内容，比如`headers`、`timeout`、`user`、`crossDomain`，等等；基本上，这就是我们对一个很好的 AJAX 包装功能所期望的。 除了重载的`ajax()`操作符外，还存在一些简化选项：

+   `get()`: 使用`GET`动词获取数据

+   `put()`: 使用`PUT`动词更新数据

+   `post()`: 使用`POST`动词创建数据

+   `patch()`: 使用`PATCH`动词的想法是更新一个部分资源

+   `delete()`: 使用`DELETE`动词删除数据

+   `getJSON()`: 使用`GET`动词获取数据，并将响应类型设置为`application/json`

# 级联调用

到目前为止，我们已经覆盖了你将使用 AJAX 发送或接收数据的两种主要方法。当涉及到接收数据时，通常是不能简单地获取数据并渲染它的。事实上，你很可能需要在何时获取哪些数据上有依赖。 典型的例子是需要在获取剩余数据之前执行登录调用。在某些情况下，可能需要首先登录，然后获取已登录用户的数据，一旦你获得了这些数据，你就可以获取消息、订单或任何特定于某个用户的数据。这种以这种方式获取数据的整个现象被称为级联调用。

让我们看看我们如何使用 promise 进行级联调用，并逐渐学习如何在 RxJS 中做同样的事情。我们会做这个小的跳跃，因为我们假设大部分正在读这本书的人都对 promise 很熟悉。

让我们首先看一下我们之前提到的依赖情况，我们需要按照这个顺序执行以下步骤：

1.  用户首先登录到系统

1.  然后我们获取用户的信息

1.  然后我们获取用户订单的信息

使用 promise，代码看起来应该像这样：

```ts
// cascading/cascading-promises.js

login()
  .then(getUser)
  .then(getOrders);

// we collect username and password from a form
const login = (username, password) => {
  return fetch("/login", {
    method: "POST",
    body: { username, password }
  })
  .then(r => r.json())
  .then(token => {
    localStorage.setItem("auth", token);
  });
};

const getUser = () => {
  return fetch("/users", {
    headers: {
      Authorization: "Bearer " + localStorage.getToken("auth")
    }
  }).then(r => r.json());
};

const getOrders = user => {
  return fetch(`/orders/user/${user.id}`, {
    headers: {
      Authorization: "Bearer " + localStorage.getToken("auth")
    }
  }).then(r => r.json());
};
```

这段代码描述了我们如何首先调用`login()`方法登录系统，并获得一个 token。我们在未来的任何调用中都使用这个 token 来确保我们进行了经过身份验证的调用。然后我们看到我们如何执行`getUser()`调用并获得一个用户实例。我们使用相同的用户实例来执行我们的最后一个调用，`getOrders()`，其中用户 ID 被用作路由参数：``/orders/user/${user.id}``。

我们已经展示了如何使用 promises 执行级联调用；我们这样做是为了建立我们正在尝试解决的问题的一个共同基础。RxJS 的方法非常相似：我们已经展示了`ajax()`操作符的存在，并且在处理 AJAX 调用时让我们的生活更轻松。要使用 RxJS 实现级联调用效果，我们只需要使用`switchMap()`操作符。这将使我们的代码看起来像这样：

```ts
// cascading/cascading-rxjs.js

let user = "user";
let password = "password";

login(user, password)
  .switchMap(getUser)
  .switchMap(getOrders);

// we collect username and password from a form
const login = (username, password) => {
  return Rx.Observable.ajax("/login", {
    method: "POST",
    body: { username, password }
  })
  .map(r => r.response)
  .do(token => {
    localStorage.setItem("auth", token);
  });
};

const getUser = () => {
  return Rx.Observable.ajax("/users", {
    headers: {
      Authorization: "Bearer " + localStorage.getToken("auth")
    }
  }).map(r => r.response);
};

const getOrders = user => {
  return Rx.Observable.json(`/orders/user/${user.id}`, {
    headers: {
      Authorization: "Bearer " + localStorage.getToken("auth")
    }
  }).map(r => r.response);
};
```

我们在上述代码中需要更改的部分已用高亮标出。简而言之，更改如下：

+   `fetch()`被`ajax()`操作符替换

+   我们调用`.map(r => r.response)`而不是`.then(r => r.json())`

+   对于每个级联调用，我们使用`.switchMap()`而不是`.then(getOrders)`

还有一个有趣的方面需要我们来讨论，即并行调用。当我们获取用户和订单时，我们在启动下一个调用之前等待前一个调用完全完成。在许多情况下，这可能并不是严格必需的。想象一下，我们有一个与前一个类似的情况，但是围绕用户有很多有趣的信息我们想要获取。除了仅仅获取订单之外，用户可能有一系列朋友或消息。获取这些数据的前提条件只是我们获取了用户，因此我们知道应该查询哪些朋友和我们需要哪些消息。在 Promise 世界中，我们会使用`Promise.all()`构造来实现并行化。有了这个想法，我们更新我们的`Promise`代码如下：

```ts
// parallell/parallell-promise.js

// we collect username and password from a form
login(username, password) {
  return new Promise(resolve => {
    resolve('logged in');
  });
}

getUsersData(user) {
  return Promise.all([
    getOrders(user),
    getMessages(user),
    getFriends(user) 
    // not implemented but you get the idea, another call in parallell
  ])
}

getUser() {
  // same as before
}

getOrders(user) {
  // same as before
}

login()
  .then(getUser)
  .then(getUsersData);
```

如我们从上面代码中看到的，我们引入了新的`getUsersData()`方法，它并行获取订单、消息和朋友集合，这样可以使我们的应用程序更早地响应，因为数据将会比我们依次获取它们时更早到达。

通过引入`forkJoin()`操作符，我们可以很容易地在 RxJS 中实现相同的效果。它接受一个流的列表，并并行获取所有内容。因此，我们更新我们的 RxJS 代码如下：

```ts
// parallell/parallell-rxjs.js

import Rx from 'rxjs/Rx';
// imagine we collected these from a form
let user = 'user';
let password = 'password';

login(user, password)
  .switchMap(getUser)
  .switchMap(getUsersData)

// we collect username and password from a form
login(username, password) {
  // same as before
}

getUsersData(user) {
  return Rx.Observable.forkJoin([
    getOrders(),
    getMessages(),
    getFriends()
  ])
}

getUser() {
  // same as before
}

getOrders(user) {
  // same as before
}

login()
  .then(getUser)
  .then(getUsersData);
```

# 深入了解

到目前为止，我们已经看过了一些操作符，让你可以创建流或者用`map()`和`filter()`操作符改变流，我们已经学会了如何管理不同的 AJAX 场景等等。基础知识都在这里，但我们还没有以一种结构化的方式来接触操作符这个主题。我们的意思是什么？嗯，操作符可以被认为属于不同的类别。我们可以使用的操作符数量令人震惊地超过 60 个。如果我们有幸可以学会所有这些操作符，这将需要时间。不过这里有个问题：我们只需要知道存在哪些不同类型的操作符，以便我们可以在适当的地方应用它们。这样可以减少我们的认知负担和我们的记忆负担。一旦我们知道我们有哪些类别，我们只需要深入研究，很可能我们最终只会知道总共 10-15 个操作符，其余的我们需要它们时再查阅即可。

目前，我们有以下几种类别：

+   **创建操作符**：这些操作符帮助我们首先创建流。几乎任何东西都可以通过这些操作符转换为一个流。

+   **组合操作符**：这些操作符帮助我们结合值和流。

+   **数学操作符**：这些操作符对发出的值进行数学计算。

+   **基于时间的操作符**：这些操作符改变值发出的速度。

+   **分组操作符**：这些操作符的概念是对一组值进行操作，而不是单个值。

# 创建操作符

我们使用创建操作符来创建流本身，因为让我们面对现实：我们需要转换为流的东西并不总是流，但通过将其转换为流，它将不得不与其他流友好相处，并且最重要的是，将能够充分利用使用操作符的全部功能来发挥其全部潜力。

那么，这些其他非流由什么组成呢？嗯，它们可以是任何异步或同步的东西。重要的是它是需要在某个时刻发出的数据。因此，存在一系列的创建操作符。在接下来的子章节中，我们将介绍其中的一部分，足够让您意识到将任何东西转换为流的强大功能。

# of() 操作符

我们已经有几次使用了这个操作符。它接受未知数量的逗号分隔参数，可以是整数、字符串或对象。如果您只想发出一组有限的值，那么这是一个您想要使用的操作符。要使用它，只需键入：

```ts
// creation-operators/of.js

const numberStream$ = Rx.Observable.of(1,2, 3);
const objectStream$ = Rx.Observable.of({ age: 37 }, { name: "chris" });

// emits 1 2 3
numberStream$.subscribe(data => console.log(data));

// emits { age: 37 }, { name: 'chris' }
objectStream$.subscribe(data => console.log(data));
```

从代码中可以看出，我们在`of()`操作符中放置了什么并不重要，它总是能够发出它。

# from() 操作符

该操作符可以接受数组或`Promise`作为输入，并将它们转换为流。要使用它，只需像这样调用它：

```ts
// creation-operators/from.js

const promiseStream$ = Rx.Observable.from(
  new Promise(resolve => setTimeout(() => resolve("data"),3000))
);

const arrayStream$ = Rx.Observable.from([1, 2, 3, 4]);

promiseStream$.subscribe(data => console.log("data", data));
// emits data after 3 seconds

arrayStream$.subscribe(data => console.log(data));
// emits 1, 2, 3, 4
```

这样一来，我们就不必处理不同类型的异步调用，从而省去了很多麻烦。

# range() 操作符

该操作符允许您指定一个范围，一个起始数和一个结束数。这是一个快捷方式，可以快速让您创建一个具有一定范围的数值流。要使用它，只需键入：

```ts
// creation-operators/range.js

const stream$ = Rx.Observable.range(1,99);

stream$.subscribe(data => console.log(data));
// emits 1... 99 
```

# fromEvent() 操作符

现在变得非常有趣了。`fromEvent()`操作符允许我们混合 UI 事件，比如`click`或`scroll`事件，并将其转换为一个流。到目前为止，我们认为异步调用只与 AJAX 调用有关。这个想法完全不正确。我们可以将 UI 事件与任何类型的异步调用混合，这创造了一个非常有趣的情况，使我们能够编写非常强大、表现力强的代码。我们将在接下来的章节中进一步讨论这个话题，*以流思考*。

要使用此操作符，您需要为它提供两个参数：一个 DOM 元素和事件的名称，如下所示：

```ts
// creation-operators/fromEvent.js

// we imagine we have an element in our DOM looking like this <input id="id" />
const elem = document.getElementById("input");
const eventStream$ = Rx.Observable
  .fromEvent(elem, "click")
  .map(ev => ev.key);

// outputs the typed key
eventStream$.subscribe(data => console.log(data));
```

# 组合

组合操作符是用于组合来自不同流的值。我们有几个可供使用的操作符可以帮助我们。当我们因某种原因没有所有数据在一个地方，但需要从多个地方获取时，这种类型的操作符是有意义的。如果不是因为即将描述的强大操作符，从不同来源组合数据结构可能是费时且容易出错的工作。

# merge()操作符

`merge()`操作符从不同的流中获取数据并将其组合。然而，这些流可以是任何类型的，只要它们是`Observable`类型。这意味着我们可以从定时操作、Promise、`of()`操作符中获取的静态数据等结合数据。合并的作用是交替发出数据。这意味着它将在以下示例中同时从两个流中发出。该操作符有两种用法，作为静态方法，也可以作为实例方法：

```ts
// combination/merge.js

let promiseStream = Rx.Observable
.from(new Promise(resolve => resolve("data")))

let stream = Rx.Observable.interval(500).take(3);
let stream2 = Rx.Observable.interval(500).take(5);

// instance method version of merge(), emits 0,0, 1,1 2,2 3, 4
stream.merge(stream2)
  .subscribe(data => console.log("merged", data));

// static version of merge(), emits 0,0, 1,1, 2, 2, 3, 4 and 'data'
Rx.Observable.merge(
  stream,
  stream2,
  promiseStream
)
.subscribe(data => console.log("merged static", data));
```

这里的要点是，如果你只需要将一个流与另一个流结合，那么使用此操作符的实例方法版本，但如果你有多个流，则使用静态版本。此外，指定流的顺序是重要的。

# combineLatest()

想象一下你面临的情况是，你已经与几个端点建立了连接，并且这些端点为你提供了数据。你关心的是每个端点最新发出的数据。也许有一个或多个端点在一段时间后停止发送数据，而你想知道最后发生的事情是什么。在这种情况下，我们希望能够结合所有相关端点的最新值的能力。这就是`combineLatest()`操作符发挥作用的地方。你可以在以下方式使用它：

```ts
// combination/combineLatest.js

let firstStream$ = Rx.Observable
  .interval(500)
  .take(3);

let secondStream$ = Rx.Observable
  .interval(500)
  .take(5);

let combinedStream$ = Rx.Observable.combineLatest(
  firstStream$,
  secondStream$
)

// emits [0, 0] [1,1] [2,2] [2,3] [2,4] [2,5]
combinedStream$.subscribe(data => console.log(data));
```

我们在这里看到的是`firstStream$`在一段时间后因为`take()`操作符的限制发出的值停止了。然而，`combineLatest()`操作符确保我们仍然获得了`firstStream$`发出的最后一个值。

# zip()

这个操作符的作用是尽可能多地将值拼接在一起。我们可能会处理连续的流，但也可能会处理具有发射值限制的流。你可以在以下方式使用该操作符：

```ts
// combination/zip.js

let stream$ = Rx.Observable.of(1, 2, 3, 4);
let secondStream$ = Rx.Observable.of(5, 6, 7, 8);
let thirdStream$ = Rx.Observable.of(9, 10); 

let zippedStream$ = Rx.Observable.zip(
  stream$,
  secondStream$,
  thirdStream$
)

// [1, 5, 9] [2, 6, 10]
zippedStream$.subscribe(data => console.log(data))
```

如我们所看到的，这里我们在垂直方向上将值拼接在一起，并且取最少发射值的`thirdStream$`是最短的，计算发出的值的数量。这意味着我们将从左到右取值并将它们合并在一起。由于`thirdStream$`只有两个值，我们最终只得到了两个发射。

# concat()

乍一看，`concat()`操作符看起来像是另一个`merge()`操作符，但这并不完全正确。区别在于`concat()`会等待其他流完成后才从顺序中的下一个流中发出流。你如何安排你的流在调用`concat()`中很重要。该操作符的使用方式如下：

```ts
// combination/concat.js

let firstStream$ = Rx.Observable.of(1,2,3,4);
let secondStream$ = Rx.Observable.of(5,6,7,8);

let concatStream$ = Rx.Observable.concat(
  firstStream$,
  secondStream$
);

concatStream$.subscribe(data => console.log(data));
```

# 数学

数学操作符只是在值上执行数学操作的操作符，比如找到最大或最小值，汇总所有值等。

# 最大值

`max()` 操作符用于找到最大值。它有两种用法：一种是直接调用`max()` 操作符，不带参数；另一种是给它传递一个`compare`函数。`compare`函数决定某个值是大于、小于还是等于被发出的值。让我们看看这两种不同的版本：

```ts
// mathematical/max.js

let streamWithNumbers$ = Rx.Observable
  .of(1,2,3,4)
  .max();

// 4
streamWithNumbers$.subscribe(data => console.log(data)); 

function comparePeople(firstPerson, secondPerson) {
  if (firstPerson.age > secondPerson.age) {
    return 1; 
  } else if (firstPerson.age < secondPerson.age) {
    return -1;
  } 
  return 0;
}

let streamOfObjects$ = Rx.Observable
  .of({
    name : "Yoda",
    age: 999
  }, {
    name : "Chris",
    age: 38 
  })
  .max(comparePeople);

// { name: 'Yoda', age : 999 }
streamOfObjects$.subscribe(data => console.log(data));
```

如我们在上面的代码中所见，我们得到了一个结果，它是最大的一个。

# 最小值

`min()` 操作符与 `max()` 操作符基本相反；也有两种用法：带参数和不带参数。它的任务是找到最小值。使用方法如下：

```ts
// mathematical/min.js

let streamOfValues$ = Rx.Observable
  .of(1, 2, 3, 4)
  .min();

// emits 1
streamOfValues$.subscribe(data => console.log(data));

```

# 总和

以前有一个叫做 `sum()` 的操作符，但已经在多个版本中删除了。现在用的是 `.reduce()` 。使用 `reduce()` 操作符，我们可以很容易地实现相同的功能。下面是使用 `reduce()` 编写 `sum()` 操作符的方式：

```ts
// mathematical/sum.js

let stream = Rx.Observable.of(1, 2, 3, 4)
  .reduce((acc, curr) => acc + curr);

// emits 10
stream.subscribe(data => console.log(data));
```

这个操作是遍历所有的发出值并将结果相加。所以，本质上，它将所有值相加。当然，这种操作符不仅可以应用于数字，还可以应用于对象。不同之处在于如何执行 `reduce()` 操作。下面的例子涵盖了这样的场景：

```ts
let stream = Rx.Observable.of({ name : "chris" }, { age: 38 })
  .reduce((acc, curr) => Object.assign({},acc, curr));

// { name: 'chris', age: 38 }
stream.subscribe(data => console.log(data)); 
```

如你从前面的代码中所见，`reduce()` 操作符确保所有对象的属性都被合并到一个对象中。

# 时间

时间在讨论流时是一个非常重要的概念。想象一下，你有多个有不同带宽的流，或者一个流比另一个流快，或者你有想在特定时间间隔内重试一个 AJAX 调用的场景。在所有这些情况下，我们需要控制数据发出的速度，时间在所有这些情况下都起着重要的作用。我们有一大堆的操作符，像魔术师一样，让我们能够随心所欲地制定和控制我们的值。

# 时间间隔（interval()）操作符

在 JavaScript 中，有一个 `setInterval()` 函数，它可以让你以固定的时间间隔执行代码，直到你选择停止它。RxJS 有一个行为类似的操作符，就是 `interval()` 操作符。它需要一个参数：通常是发出值之间的毫秒数。使用方法如下：

```ts
// time/interval.js

let stream$ = Rx.Observable.interval(1000);

// emits 0, 1, 2, 3 ... n with 1 second in between emits, till the end of time
stream$.subscribe(data => console.log(data));
```

需要注意的是，该操作符将一直发出值，直到你停止它。最好的方法是将其与 `take()` 操作符组合使用。 `take()` 操作符需要一个参数，指定在停止之前它要发出多少个值。更新后的代码如下：

```ts
// time/interval-take.js

let stream$ = Rx.Observable.interval(1000)
  .take(2);

// emits 0, 1, stops emitting thanks to take() operator
stream$.subscribe(data => console.log(data));
```

# 计时器（timer()）操作符

`timer()` 操作符的工作是在一定时间后发出值。它有两种形式：一种是在一定毫秒数后发出一个值，另一种是在它们之间有一定延迟的情况下继续发出值。让我们看看有哪两种不同的形式可用：

```ts
// time/timer.js

let stream$ = Rx.Observable.timer(1000);

// delay with 500 milliseconds
let streamWithDelay$ = Rx.Observable.timer(1000, 500) 

// emits 0 after 1000 milliseconds, then no more
stream$.subscribe(data => console.log(data));

streamWithDelay$.subscribe(data => console.log(data));
```

# delay() 操作符

`delay()` 操作符延迟所有被发出的值，并且使用以下方式：

```ts
// time/delay.js

let stream$ = Rx.Observable
.interval(100)
.take(3)
.delay(500);

// 0 after 600 ms, 1 after 1200 ms, 2 after 1800 ms
stream.subscribe(data => console.log(data));
```

# sampleTime() 操作符

`sampleTime()` 操作符用于在样本期过去后只发出值。这样做的一个很好的用例是当你想要有冷却功能时。想象一下，你有用户太频繁地按下保存按钮。保存可能需要几秒钟的时间才能完成。一种方法是在保存时禁用保存按钮。另一种有效的方法是简单地忽略按钮的任何按下，直到操作有机会完成。以下代码就是这样做的：

```ts
// time/sampleTime.js

let elem = document.getElementById("btn");
let stream$ = Rx.Observable
  .fromEvent(elem, "click")
  .sampleTime(8000);

// emits values every 8th second
stream$.subscribe(data => console.log("mouse clicks",data));

```

# debounceTime() 操作符

`sampleTime()` 操作符能够在一定时间内忽略用户，但 `debounceTime()` 操作符采取了不同的方式。数据防抖是一个概念，意味着我们在发出值之前等待事情平静下来。想象一下，用户输入的输入元素。用户最终会停止输入。我们想要确保用户实际上已经停止了，所以我们在实际执行操作前等待一段时间。这就是 `debounceTime()` 操作符为我们所做的。以下示例显示了我们如何监听用户在输入元素中输入，等待用户停止输入，最后执行 AJAX 调用：

```ts
// time/debounceTime.js
const elem = document.getElementById("input");

let stream$ = Rx.Observable.fromEvent(elem, "keyup")
  .map( ev => ev.key)
  .filter(key => key !== "Backspace")
  .debounceTime(2000)
  .switchMap( x => {
    return new Rx.Observable.ajax(`https://swapi.co/api/people/${elem.value}`);
  })
  .map(r => r.response);

stream$.subscribe(data => console.log(data));
```

用户输入数字后，在文本框中输入不活动 2 秒后，将进行一个 AJAX 呼叫，使用我们的文本框输入。

# 分组

分组操作符允许我们对收集到的一组事件进行操作，而不是一次发出一个事件。

# buffer() 操作符

`buffer()` 操作符的想法是我们可以收集一堆事件，而不会立即发出。操作符本身接受一个参数，一个定义何时停止收集事件的 `Observable`。在那个时刻，我们可以选择如何处理这些事件。以下是你可以使用这个操作符的方法：

```ts
// grouping/buffer.js

const elem = document.getElementById("input");

let keyStream$ = Rx.Observable.fromEvent(elem,"keyup");
let breakStream$ = keyStream$.debounceTime(2000);
let chatStream$ = keyStream$
  .map(ev => ev.key)
  .filter(key => key !== "Backspace")
  .buffer(breakStream$)
  .switchMap(newContent => Rx.Observable.of("send text as I type", newContent));

chatStream$.subscribe(data=> console.log(data));

```

这样做的作用是收集事件，直到出现了 2 秒的非活动时间。在那时，我们释放了所有缓冲的按键事件。当我们释放所有这些事件时，我们可以，例如，通过 AJAX 发送它们到某个地方。这在聊天应用程序中是一个典型的场景。使用上述代码，我们可以始终发送最新输入的字符。

# bufferTime() 操作符

与 `buffer()` 非常相似的一个操作符是 `bufferTime()`。这个操作符让我们指定要缓冲事件的时间长度。它比 `buffer()` 稍微不那么灵活，但仍然非常有用。

# 思考流

到目前为止，我们已经经历了一堆场景，向我们展示了我们可以支配哪些操作符，以及它们如何可以被连接。我们也看到了像 `flatMap()` 和 `switchMap()` 这样的操作符，在从一个类型的 Observable 到另一个类型时是如何改变事情的。那么，当使用 Observables 时，应该采取哪种方法？显然，我们需要使用操作符来表达算法，但我们应该从哪里开始呢？我们需要做的第一件事就是思考起点和终点。我们想要捕获哪些类型的事件，最终结果应该是什么样的？这已经给了我们一个提示，要进行多少次转换才能达到那个目标。如果我们只想要转换数据，那么我们可能只需要一个 `map()` 操作符和一个 `filter()` 操作符。如果我们想要从一个 `Observable` 转换到另一个 `Observable`，那么我们就需要一个 `flatMap()` 或 `switchMap()`。我们是否有特定的行为，比如等待用户停止输入？如果有的话，那么我们需要查看 `debounceTime()` 或类似的操作符。这和所有问题其实是一样的：把它分解，看看你有哪些部分，然后征服。不过，让我们尝试将这件事分解成一系列步骤：

+   输入是什么？UI 事件还是其他东西？

+   输出是什么？最终结果是什么？

+   鉴于第二条，我需要哪些转换才能达到目标？

+   我是否需要处理多个流？

+   我需要处理错误吗，如果需要，如何处理？

希望这让您了解如何思考流。记住，从小处开始，朝着目标努力。

# 总结

我们开始学习更多关于基本操作符的知识。在这样做的过程中，我们遇到了 `map()` 和 `filter()` 操作符，它们让我们能够控制发出的内容。了解 `do()` 操作符让我们有办法调试我们的流。此外，我们还了解了像 JS Bin 和 RxFiddle 这样的沙盒环境的存在，以及它们如何帮助我们快速开始使用 RxJS。AJAX 是我们之后深入了解的一个主题，并且我们建立了对可能发生的不同场景的理解。深入了解 RxJS，我们看了不同的操作符类别。虽然我们对其中的内容只是浅尚的涉猎，但这给了我们一个方法去学习库中有哪些类型的操作符。最后，我们通过思考流的方式来改变和发展我们的思维方式，来结束这一章。

这些所获得的知识使我们现在已经准备好进入下一章中更高级的 Rx 主题。我们知道了基础知识，现在是时候将它们掌握了。


# 第八章：RxJS 高级

我们完成了上一章，更多地教会了我们存在哪些操作符以及如何有效利用它们。拥有了这些知识，我们现在将更深入地涉足这个主题。我们将从了解存在哪些各个部分，到真正理解 RxJS 的本质。了解 RxJS 的本质就意味着更多地了解其运作机制。为了揭示这一点，我们需要涵盖诸如热、温和和冷 Observables 之间的区别是什么；了解 Subjects 以及它们适用的场景；以及有时被忽视的调度器等主题。

我们还有其他与处理 Observables 相关的方面要讨论，即，如何处理错误以及如何测试你的 Observables。

在这一章中，你将学到：

+   热、冷和温和的 Observables

+   Subject：它们与 Observables 的区别以及何时使用它们

+   可管道的操作符，RxJS 库的最新添加，以及它们对组合 Observables 的影响

+   弹珠测试，有助于测试你的 Observables 的测试机制

# 热、冷和温和的 Observables

有热、冷和温和的 Observables。我们到底是什么意思呢？首先，让我们说你将处理的大多数事情都是冷 Observables。还是不明白？如果我们说冷 Observables 是懒惰的，这样有帮助吗？不？好吧，让我们先来谈谈 Promise。Promise 是热的。当我们执行它们的代码时，它们立刻就会执行。让我们来看一个例子：

```ts
// hot-cold-warm/promise.js

function getData() {
  return new Promise(resolve => {
    console.log("this will be printed straight away");
    setTimeout(() => resolve("some data"), 3000); 
  });
}

// emits 'some data' after 3 seconds
getData().then(data => console.log("3 seconds later", data));
```

如果你来自非 RxJS 背景，你可能在这一点上会想：好吧，是的，这是我预期的。尽管如此，我们要说明的是：调用 `getData()` 会使你的代码立即运行。这与 RxJS 不同，因为类似的 RxJS 代码实际上不会运行，直到有一个关心结果的监听器/订阅者。RxJS 回答了一个古老的哲学问题：如果有人不在那里听，树在森林中倒下时会不会发出声音？在 Promise 的情况下，会。在 Observable 的情况下，不会。让我们用一个类似的 RxJS 和 Observables 的代码例子来澄清我们刚才说的话：

```ts
// hot-cold-warm/observer.js

const Rx = require("rxjs/Rx");

function getData() {
  return Rx.Observable(observer => {
    console.log("this won't be printed until a subscriber exists");
    setTimeout(() => {
      observer.next("some data");
      observer.complete();
    }, 3000);
  });
}

// nothing happens
getData();
```

在 RxJS 中，像这样的代码被认为是冷，或者懒的。我们需要一个订阅者才能真正发生一些事情。我们可以像这样添加一个订阅者：

```ts
// hot-cold-warm/observer-with-subscriber

const Rx = require("rxjs/Rx");

function getData() {
  return Rx.Observable.create(observer => {
    console.log("this won't be printed until a subscriber exists");

    setTimeout(() => {
      observer.next("some data");
      observer.complete();
    }, 3000);
  });
}

const stream$ = getData();
stream$.subscribe(data => console.log("data from observer", data));
```

这是 Observable 与 Promises 的行为差异的一个重大区别，这一点非常重要。这是一个冷 Observable；那么，什么是热 Observable 呢？此时很容易认为，热 Observable 是立即执行的东西；然而，实际情况并非如此。关于热 Observable 的一个官方解释是，任何订阅它的东西都将与其他订阅者分享生产者。生产者就是在 Observable 内部内部喷出值的东西。这意味着数据被共享。让我们来看看冷 Observable 订阅方案，并将其与热 Observable 订阅方案进行对比。我们将从冷情况开始：

```ts
// hot-cold-warm/cold-observable.js
const Rx = require("rxjs/Rx");

const stream$ = Rx.Observable.interval(1000).take(3);

// subscriber 1 emits 0, 1, 2
stream$.subscribe(data => console.log(data));

// subscriber 2, emits 0, 1, 2
stream$.subscribe(data => console.log(data));

// subscriber 3, emits 0, 1, 2, after 2 seconds
setTimeout(() => {
  stream$.subscribe(data => console.log(data)); 
}, 3000);
```

在上述代码中，我们有三个不同的订阅者，它们各自接收到发出的值的副本。每次添加新的订阅者时，值都从头开始。当我们看前两个订阅者时可能会预料到这一点。至于第三个订阅者，它是在两秒后添加的。是的，即使该订阅者也会收到自己的一组值。解释是每个订阅者在订阅时都会收到自己的生产者。

对于热 Observable，只有一个生产者，这意味着上述情况会有所不同。让我们写一个热 Observable 场景的代码：

```ts
// hot observable scenario

// subscriber 1 emits 0, 1, 2
hotStream$.subscribe(data => console.log(data));

// subscriber 2, emits 0, 1, 2
hotStream$.subscribe(data => console.log(data));

// subscriber 3, emits 2, after 2 seconds
setTimeout(() => {
  hotStream$.subscribe(data => console.log(data)); 
}, 3000);
```

第三个订阅者仅输出值`2`的原因是其他值已经被发出。第三个订阅者并没有看到这一情况发生。在第三个值发出时，它出现了，这就是它收到值`2`的原因。

# 使一个流变热

这个`hotStream$`，它是如何创建的呢？你曾经说过大多数流都是冷的？实际上，我们有一个操作符来做到这一点，或者说实际上有两个操作符。我们可以使用操作符`publish()`和`connect()`使流从冷变热。让我们从冷 Observable 开始，然后添加上述操作符，就像这样：

```ts
// hot-cold-warm/hot-observable.js

const Rx = require("rxjs/Rx");

let start = new Date();
let stream = Rx.Observable
  .interval(1000)
  .take(5)
  .publish();

setTimeout(() => {
  stream.subscribe(data => {
    console.log(`subscriber 1 ${new Date() - start}`, data);
  });
}, 2000);

setTimeout(() => {
  stream.subscribe(data => {
    console.log(`subscriber 2 ${new Date() - start}`, data)
  });
}, 3000);

stream.connect();
stream.subscribe(
  data => console.log(
    `subscriber 0 - I was here first ${new Date() - start}`, 
    data
  )
);
```

从上述代码中我们可以看到，我们创建了 Observable，并指示其发出值，每秒一个值。此外，应该在发出五个值后停止。然后我们调用操作符`publish()`。这将使我们处于就绪模式。然后我们设置了几个订阅分别在两秒后和三秒后发生。接着我们在流上调用`connect()`。这将使流从热到冷。因此，我们的流开始发出值，每当它开始订阅时，任何订阅者将与任何未来的订阅者共享一个生产者。最后，我们在调用`connect()`后立即添加了一个订阅者。让我们看看以下屏幕截图的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/a082e1cf-166a-438d-b3ee-2e08ec543b11.png)

我们的第一个订阅者在一秒后开始发出数值。第二个订阅者又在另一秒后开始发出数值。这时它的值是`1`；它错过了第一个值。又过了一秒，第三个订阅者被添加了进来。这个订阅者发出的第一个值是`2`；它错过了前两个值。我们清楚地看到了`publish()`和`connect()`操作符是如何帮助我们创建热 Observable 的，以及订阅热 Observable 的时间是多么重要。

到底为什么我想要一个热 Observable？应用领域是什么？嗯，想象一下你有一个直播流，一个足球比赛，你把它流到很多订阅者/观众那里。他们不想看到比赛的第一分钟发生了什么，因为他们来晚了，而是想要看到比赛现在的情况，也就是订阅时的情况（当他们坐在电视机前）。所以，肯定存在热 Observable 适用的情况。

# 温和的流

迄今为止，我们一直在描述和讨论冷 Observable 和热 Observable，但还有第三种：温和的 Observable。温 Observable 可以被认为是作为冷 Observable 创建的，但在某些条件下变成了热 Observable。让我们通过介绍`refCount()`操作符来看一个这样的案例：

```ts
// hot-cold-warm/warm-observer.js

const Rx = require("rxjs/Rx");

let warmStream = Rx.Observable.interval(1000).take(3).publish().refCount();
let start = new Date();

setTimeout(() => {
  warmStream.subscribe(data => {
    console.log(`subscriber 1 - ${new Date() - start}`,data);
  });
}, 2000);
```

好，所以我们开始使用操作符`publish()`，看起来我们即将使用`connect()`操作符并且我们有了热 Observable，对吗？是的，但是我们没有调用`connect()`，而是调用了`refCount()`。这个操作符会让我们的 Observable 变得温和，这样当第一个订阅者到来时，它将表现得像一个冷 Observable。明白吗？那听起来就像一个冷 Observable，对吗？让我们先看一下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/36b34610-a52e-40ab-af36-aa2922f4d198.png)

回答前面的问题，是的，它确实就像一个冷 Observable；我们不会错过任何已发出的数值。有趣的是当我们加入第二个订阅者时会发生什么。我们来添加第二个订阅者，并看看效果如何：

```ts
// hot-cold-warm/warm-observable-subscribers.js

const Rx = require("rxjs/Rx");

let warmStream = Rx.Observable.interval(1000).take(3).publish().refCount();
let start = new Date();

setTimeout(() => {
  warmStream.subscribe(data => {
    console.log(`subscriber 1 - ${new Date() - start}`,data);
  });
}, 1000);

setTimeout(() => {
  warmStream.subscribe(data => {
    console.log(`subscriber 2 - ${new Date() - start}`,data);
  });
}, 3000);
```

我们添加了第二个订阅者；现在，我们来看一下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/ba5c64f7-982a-4e83-9d58-f52164b99678.png)

从上面的结果中，我们可以看到第一个订阅者独自接收了数值`0`。当第二个订阅者到来时，它的第一个值是`1`，证明了这个流已经从表现得像冷 Observable 变成了热 Observable。

还有另一种方式可以创建温和的 Observable，那就是使用`share()`操作符。`share()`操作符可以被看作是一个更加智能的操作符，根据情况允许我们的 Observable 从冷到热转变。在某些情况下，这可能是一个非常好的主意。所以，观察到以下关于 Observable 的情况：

+   作为热 Observable 创建；流没有完成，且没有订阅者超过一个

+   回退为冷 Observable；在新的订阅到来之前，任何先前的订阅都已经结束

+   作为一个冷 Observable 创建；Observable 本身在订阅发生之前已经完成

让我们尝试用代码展示第一个要点是如何发生的：

```ts
// hot-cold-warm/warm-observable-share.js

const Rx = require("rxjs/Rx");

let stream$ = Rx.Observable.create((observer) => {
  let i = 0;
  let id = setInterval(() => {
    observer.next(i++);
  }, 400);

  return () => {
    clearInterval(id);
  };
}).share();

let sub0, sub;

// first subscription happens immediately
sub0 = stream$.subscribe(
  (data) => console.log("subscriber 0", data),
  err => console.error(err),
  () => console.log("completed"));

// second subscription happens after 1 second
setTimeout(() => {
  sub = stream$.subscribe(
  (data) => console.log("subscriber 1", data),
  err => console.error(err),
  () => console.log("completed"));
}, 1000);

// everything is unscubscribed after 2 seconds
setTimeout(() => {
  sub0.unsubscribe();
  sub.unsubscribe();
}, 2000);
```

上述代码描述了这样一种情况：我们定义了一个立即发生订阅的流。第二个订阅将在一秒之后发生。现在，根据 `share()` 操作符的定义，这意味着该流将被创建为冷 Observable，但在第二个订阅者出现时，将成为热 Observable，因为存在先前的订阅者，且流尚未完成。让我们检查我们的输出，验证是否是这种情况：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/0c775f85-2d7d-4277-baee-b245cf676176.png)

第一个订阅者似乎显然独自获取值。当第二个订阅者到来时，它似乎与生产者共享，因为它不是从零开始，而是从第一个订阅者开始监听。

# 主题

我们习惯以某种方式使用 Observable。我们从某处构造它们并开始监听它们发出的值。通常我们几乎无法在创建之后影响正在发出的数据。当然，我们可以更改和过滤它，但除非与另一个流合并，否则在 Observable 中几乎不可能添加更多内容。让我们看看当我们真正控制正在发出的内容时，使用 `create()` 操作符何时适用于 Observable：

```ts
let stream$ = Rx.Observable.create(observer => {
  observer.next(1);
  observer.next(2);
});

stream$.subscribe(data => console.log(data));
```

我们看到 Observable 充当着一个包装器，围绕着真正发出值的对象 Observer。在我们的 Observer 实例中，Observer 调用 `next()`，带着一个参数来发出值，这些值我们在 `subscribe()` 方法中监听到。

本节是关于 Subject 的。Subject 与 Observable 的不同之处在于它可以在创建后影响流的内容。让我们用下面这段代码具体看一下：

```ts
// subjects/subject.js

const Rx = require("rxjs/Rx");

let subject = new Rx.Subject();

// emits 1
subject.subscribe(data => console.log(data));

subject.next(1);
```

我们注意到的第一件事是，我们只需调用构造函数，而不是像在 Observable 中那样使用工厂方法如 `create()` 或 `from()` 或类似的方法。我们注意到的第二件事是我们在第二行订阅它，并且只有在最后一行调用 `next()` 才会发出值。为什么代码要按照这个顺序编写呢？嗯，如果我们不按照这种方式编写代码，并且在第二个调用 `next()` 的时候发生，我们的订阅变量将不存在，值会立即被发出。尽管我们确定了两件事：我们调用了 `next()`，我们调用了 `subscribe()`，这使 `Subject` 具有双重性质。我们确实提到了 `Subject` 能够完成另一件事情：在创建后改变流。我们的调用 `next()` 就是在做这件事。让我们再增加一些调用，以确保我们真正理解这个概念：

```ts
// subjects/subjectII.js

const Rx = require("rxjs/Rx");

let subject = new Rx.Subject();

// emits 10 and 100 2 seconds after
subject.subscribe(data => console.log(data));
subject.next(10);

setTimeout(() => {
  subject.next(100);
}, 2000);
```

正如我们之前所述，我们对`next()`方法的所有调用都使我们能够影响流；在我们的`subscribe()`方法中，我们看到对`next()`的每次调用都会导致`subscribe()`被调用，或者说，技术上来说，我们传递给它的第一个函数被调用。

# 使用主题（Subject）来进行级联列表操作

那么，问题是什么？为什么我们应该使用主题而不是可观察对象？这实际上是一个相当深奥的问题。对于大多数与流相关的问题，有许多解决方法；那些诱人使用主题的问题通常可以通过其他方式解决。不过，让我们看看你可以使用它来做什么。让我们谈谈级联下拉列表。我们所说的是，我们想知道一个城市中存在哪些餐馆。因此，想象一下，我们有一个下拉列表，允许我们选择我们感兴趣的国家。一旦我们选择了一个国家，我们应该从城市下拉列表中选择我们感兴趣的城市。此后，我们可以从餐馆列表中选择，并最终选择我们感兴趣的餐馆。在标记中，它很可能看起来像这样：

```ts
// subjects/cascading.html

<html>
<body>
  <select id="countries"></select>
  <select id="cities"></select>
  <select id="restaurants"></select>

  <script src="img/Rx.min.js"></script>
  <script src="img/cascadingIV.js"></script>
</body>
</html>

```

应用程序开始时，我们还没有选择任何内容，唯一被选择的下拉列表是第一个，其中填充了国家。假设我们因此在 JavaScript 中设置了以下代码：

```ts
// subjects/cascadingI.js

let countriesElem = document.getElementById("countries");
let citiesElem = document.getElementBtyId("cities");
let restaurantsElem = document.getElementById("restaurants");

// talk to /cities/country/:country, get us cities by selected country
let countriesStream = Rx.Observable.fromEvent(countriesElem, "select");

// talk to /restaurants/city/:city, get us restaurants by selected restaurant
let citiesStream = Rx.Observable.fromEvent(citiesElem, "select");

// talk to /book/restaurant/:restaurant, book selected restaurant
let restaurantsElem = Rx.Observable.fromEvent(restaurantsElem, "select");

```

到此为止，我们已经确定我们想要监听每个下拉列表的选定事件，并且在国家或城市下拉列表的情况下，我们想要筛选即将出现的下拉列表。假设我们选择了一个特定的国家，那么我们想要重新填充/筛选城市下拉列表，以便它只显示选定国家的城市。对于餐厅下拉列表，我们想要根据我们选择的餐厅进行预订。听起来相当简单，对吧？我们需要一些订阅者。城市下拉列表需要监听国家下拉列表的变化。因此，我们将其添加到我们的代码中：

```ts
// subjects/cascadingII.js

let countriesElem = document.getElementById("countries");
let citiesElem = document.getElementBtyId("cities");
let restaurantsElem = document.getElementById("restaurants");

fetchCountries();

function buildList(list, items) {
  list.innerHTML ="";
  items.forEach(item => {
    let elem = document.createElement("option");
    elem.innerHTML = item;
    list.appendChild(elem);
  });
}

function fetchCountries() {
  return Rx.Observable.ajax("countries.json")
    .map(r => r.response)
    .subscribe(countries => buildList(countriesElem, countries.data));
}

function populateCountries() {
  fetchCountries()
    .map(r => r.response)
    .subscribe(countries => buildDropList(countriesElem, countries));
}

let cities$ = new Subject();
cities$.subscribe(cities => buildList(citiesElem, cities));

Rx.Observable.fromEvent(countriesElem, "change")
  .map(ev => ev.target.value)
  .do(val => clearSelections())
  .switchMap(selectedCountry => fetchBy(selectedCountry))
  .subscribe( cities => cities$.next(cities.data));

Rx.Observable.from(citiesElem, "select");

Rx.Observable.from(restaurantsElem, "select");
```

因此，在这里，我们有一个在选择国家时执行 AJAX 请求的行为；我们获得一个经过筛选的城市列表，并引入新的主题实例`cities$`。我们对其调用`next()`方法，并将我们筛选后的城市作为参数传递。最后，通过在流上调用`subscribe()`方法来监听对`cities$`流的更改。正如你所见，当数据到达时，我们在那里重建我们的城市下拉列表。

我们意识到我们的下一步是要对我们在城市下拉列表中进行选择的变化做出反应。所以，让我们设置好：

```ts
// subjects/cascadingIII.js

let countriesElem = document.getElementById("countries");
let citiesElem = document.getElementBtyId("cities");
let restaurantsElem = document.getElementById("restaurants");

fetchCountries();

function buildList(list, items) {
  list.innerHTML = "";
  items.forEach(item => {
    let elem = document.createElement("option");
    elem.innerHTML = item;
    list.appendChild(elem);
  });
}

function fetchCountries() {
  return Rx.Observable.ajax("countries.json")
    .map(r => r.response)
    .subscribe(countries => buildList(countriesElem, countries.data));
}

function populateCountries() {
  fetchCountries()
    .map(r => r.response)
    .subscribe(countries => buildDropList(countriesElem, countries));
}

let cities$ = new Subject();
cities$.subscribe(cities => buildList(citiesElem, cities));

let restaurants$ = new Rx.Subject();
restaurants$.subscribe(restaurants => buildList(restaurantsElem, restaurants));

Rx.Observable.fromEvent(countriesElem, "change")
  .map(ev => ev.target.value)
  .do( val => clearSelections())
  .switchMap(selectedCountry => fetchBy(selectedCountry))
  .subscribe( cities => cities$.next(cities.data));

Rx.Observable.from(citiesElem, "select")
 .map(ev => ev.target.value)
  .switchMap(selectedCity => fetchBy(selectedCity))
  .subscribe( restaurants => restaurants$.next(restaurants.data)); // talk to /book/restaurant/:restaurant, book selected restaurant
Rx.Observable.from(restaurantsElem, "select");
```

在上述代码中，我们添加了一些代码来反应我们在城市下拉列表中做出选择。我们还添加了一些代码来监听`restaurants$`流的变化，最终导致我们的餐馆下拉列表重新填充。最后一步是监听我们在餐馆下拉列表中选择餐馆时的变化。在这里应该发生的事情由你来决定，亲爱的读者。建议是我们为所选餐厅的营业时间或菜单查询一些 API。发挥你的创造力。不过，我们将留给你一些最终的订阅代码：

```ts
// subjects/cascadingIV.js

let cities$ = new Rx.Subject();
cities$.subscribe(cities => buildList(citiesElem, cities));

let restaurants$ = new Rx.Subject();
restaurants$.subscribe(restaurants => buildList(restaurantsElem, restaurants));

function buildList(list, items) {
  list.innerHTML = "";
  items.forEach(item => {
    let elem = document.createElement("option");
    elem.innerHTML = item;
    list.appendChild(elem);
  });
}

function fetchCountries() {
  return Rx.Observable.ajax("countries.json")
    .map(r => r.response)
    .subscribe(countries => buildList(countriesElem, countries.data));
}

function fetchBy(by) {
  return Rx.Observable.ajax(`${by}.json`)
  .map(r=> r.response);
}

function clearSelections() {
  citiesElem.innerHTML = "";
  restaurantsElem.innerHTML = "";
}

let countriesElem = document.getElementById("countries");
let citiesElem = document.getElementById("cities");
let restaurantsElem = document.getElementById("restaurants");

fetchCountries();

Rx.Observable.fromEvent(countriesElem, "change")
  .map(ev => ev.target.value)
  .do(val => clearSelections())
  .switchMap(selectedCountry => fetchBy(selectedCountry))
  .subscribe(cities => cities$.next(cities.data));

Rx.Observable.fromEvent(citiesElem, "change")
  .map(ev => ev.target.value)
  .switchMap(selectedCity => fetchBy(selectedCity))
  .subscribe(restaurants => restaurants$.next(restaurants.data));

Rx.Observable.fromEvent(restaurantsElem, "change")
  .map(ev => ev.target.value)
  .subscribe(selectedRestaurant => console.log("selected restaurant", selectedRestaurant));
```

这变成了一个相当长的代码示例，应该说这不是解决这个问题的最佳方式，但它确实演示了 Subject 的工作原理：它可以在需要时向流中添加值，并且可以被订阅。

# BehaviorSubject

到目前为止，我们一直在研究默认类型的 Subject，并揭示了一点它的秘密。然而，还有许多种类型的 Subject。其中一种有趣的类型是`BehaviorSubject`。所以，我们为什么需要`BehaviorSubject`，以及用来做什么呢？嗯，当处理默认的 Subject 时，我们能够向流中添加值，并且订阅该流。`BehaviorSubject`在形式上给了我们一些额外的能力，例如：

+   一个初始值，如果我们能够在等待 AJAX 调用完成时向 UI 展示一些内容，那就太棒了

+   我们可以查询最新的数值；在某些情况下，了解上次发出的值是很有意思的。

要解决第一点，让我们写一些代码来展示这种能力：

```ts
// subjects/behavior-subject.js

let behaviorSubject = new Rx.BehaviorSubject("default value");

// will emit 'default value'
behaviorSubject.subscribe(data => console.log(data));

// long running AJAX scenario
setTimeout(() => {
  return Rx.Observable.ajax("data.json")
    .map(r => r.response)
    .subscribe(data => behaviorSubject.next(data));
}, 12000);
```

# ReplaySubject

对于普通的 Subject，我们订阅开始的时机很重要。如果我们在设置订阅之前开始发出值，那些值就会被简单地丢失。如果我们有`BehaviorSubject`，情况会稍微好一些。即使我们在订阅之后才开始发出值，最后发出的值仍然可以获取。然后，接下来的问题是：如果在订阅之前发出了两个或更多个值，并且我们关心这些值 - 那么怎么办呢？

让我们来说明这种情况，并分别看看 Subject 和`BehaviorSubject`会发生什么：

```ts
// example of emitting values before subscription

const Rx = require("rxjs/Rx");

let subject = new Rx.Subject();
subject.next("subject first value");

// emits 'subject second value'
subject.subscribe(data => console.log("subscribe - subject", data));
subject.next("subject second value");

let behaviourSubject = new Rx.BehaviorSubject("behaviorsubject initial value");
behaviourSubject.next("behaviorsubject first value");
behaviourSubject.next("behaviorsubject second value");

// emits 'behaviorsubject second value', 'behaviorsubject third value' 
behaviourSubject.subscribe(data =>
  console.log("subscribe - behaviorsubject", data)
);

behaviourSubject.next("behaviorsubject third value");
```

从上述代码中可以看到，如果我们关心订阅之前的值，Subject 并不是一个好的选择。`BehaviorSubject`构造函数在这种情况下略微好一些，但如果我们真的关心之前的值，并且有很多值，那么我们应该看看`ReplaySubject`。`ReplaySubject`有能力指定两件事：缓冲区大小和窗口大小。缓冲区大小简单地表示它应该记住过去的值的数量，窗口大小指定它应该记住它们多久。让我们在代码中演示一下：

```ts
// subjects/replay-subject.js

const Rx = require("rxjs/Rx");

let replaySubject = new Rx.ReplaySubject(2);

replaySubject.next(1);
replaySubject.next(2);
replaySubject.next(3);

// emitting 2 and 3
replaySubject.subscribe(data => console.log(data));
```

在前面的代码中，我们可以看到我们发出了`2`和`3`，也就是最近发出的两个值。这是因为我们在`ReplaySubject`构造函数中指定了缓冲区大小为 2。我们唯一丢失的值是`1`。反之，如果我们在构造函数中指定了一个 3，所有三个值都将到达订阅者。这就是缓冲区大小及其工作方式；那么窗口大小属性又是如何工作的呢？让我们用以下代码来说明它的工作方式：

```ts
// subjects/replay-subject-window-size.js

const Rx = require("rxjs/Rx");

let replaySubjectWithWindow = new Rx.ReplaySubject(2, 2000);
replaySubjectWithWindow.next(1);
replaySubjectWithWindow.next(2);
replaySubjectWithWindow.next(3);

setTimeout(() => {
  replaySubjectWithWindow.subscribe(data =>
    console.log("replay with buffer and window size", data));
  }, 
2010);
```

在这里，我们将窗口大小指定为 2,000 毫秒；这就是值应该保留在缓冲区中的时间。我们可以看到在 2,010 毫秒后我们延迟了订阅的创建。这样做的最终结果是在订阅发生之前不会发出任何值，因为缓冲区在订阅发生之前就已经被清空了。增加窗口大小的值会解决这个问题。

# AsyncSubject

`AsyncSubject` 的容量为 1，这意味着我们可以发出大量的值，但只有最新的值是被存储的。它并不是真的丢失了，但除非您完成流，否则您看不到它。让我们看一个说明这种情况的代码片段：

```ts
// subjects/async-subject.js

let asyncSubject = new Rx.AsyncSubject();
asyncSubject.next(1);
asyncSubject.next(2);
asyncSubject.next(3);
asyncSubject.next(4);

asyncSubject.subscribe(data => console.log(data), err => console.error(err));

```

早些时候，我们发出了四个值，但似乎没有到达订阅者。在这一点上，我们不知道这是因为它只是像一个主题一样丢弃在订阅之前发出的所有值，还是因为其他原因。因此，让我们调用`complete()`方法并看看它的表现是如何的：

```ts
// subjects/async-subject-complete.js

let asyncSubject = new Rx.AsyncSubject();
asyncSubject.next(1);
asyncSubject.next(2);
asyncSubject.next(3);
asyncSubject.next(4);

// emits 4
asyncSubject.subscribe(data => console.log(data), err => console.error(err));
asyncSubject.complete();

```

这将会发出一个`4`，因为`AsyncSubject`只会记住最后一个值，并且我们调用了`complete()`方法，从而表示流的结束。

# 错误处理

错误处理是一个非常重要的话题。这是一个容易被忽视的领域。通常在编码时，我们可能会认为我们只需要做一些事情，比如确保我们没有语法错误或运行时错误。对于流，我们大多数时候会考虑运行时错误。问题是，当出现错误时我们应该如何处理呢？我们是应该假装像下雨一样把错误抛开吗？还是我们应该希望在未来的某个时候尝试相同的代码会得到不同的结果，或者当某种类型的错误存在时我们应该放弃？让我们试着集中我们的思想，并看看在 RxJS 中存在的不同错误处理方法。

# 捕获并继续

迟早会有一个流会抛出一个错误。让我们看看可能是什么样子：

```ts
// example of a stream with an error

let stream$ = Rx.Observable.create(observer => {
  observer.next(1);
  observer.error('an error is thrown');  
  observer.next(2);
});

stream$.subscribe(
  data => console.log(data), // 1 
  error => console.error(error) // 'error is thrown'
);
```

在前面的代码中，我们设置了一个场景，我们首先发出一个值，然后发出一个错误。第一个值被我们的订阅方法的第一个回调捕获了。第二个发出的东西，也就是错误，被我们的错误回调捕获了。第三个发出的值没有传递给我们的订阅者，因为我们的流已经被错误中断。在这里我们可以做一些事情，那就是使用`catch()`运算符。让我们将它应用到我们的流上并看看会发生什么：

```ts
// error-handling/error-catch.js
const Rx = require("rxjs/Rx");

let stream$ = Rx.Observable.create(observer => {
  observer.next(1);
  observer.error("an error is thrown");
  observer.next(2);
}).catch(err => Rx.Observable.of(err));

stream$.subscribe(
  data => console.log(data), // emits 1 and 'error is thrown'
  error => console.error(error)
);

```

在这里，我们用 `catch()` 运算符捕获了我们的错误。在 `catch()` 运算符中，我们获取我们的错误并使用 `of()` 运算符将其作为普通 Observable 发出。然而我们发出的 `2` 发生了什么？对于这个，还是没有运气。`catch()` 运算符能够获取我们的错误并将其转换为正常发出的值；而不是一个错误，我们从流中并未获取到所有的值。

让我们看一个处理多个流的场景：

```ts
// example of merging several streams

let merged$ = Rx.Observable.merge(
  Rx.Observable.of(1),
  Rx.Observable.throw("err"),
  Rx.Observable.of(2)
);

merged$.subscribe(data => console.log("merged", data));
```

在上面的场景中，我们合并了三个流。第一个流发出数字`1`，没有其他内容被发出。这是因为我们的第二个流将所有内容破坏，因为它发出了一个错误。让我们尝试应用我们新发现的 `catch()` 运算符并看看会发生什么：

```ts
// error-handling/error-merge-catch.js

const Rx = require("rxjs/Rx");

let merged$ = Rx.Observable.merge(
  Rx.Observable.of(1),
  Rx.Observable.throw("err").catch(err => Rx.Observable.of(err)),
  Rx.Observable.of(2)
);

merged$.subscribe(data => console.log("merged", data));
```

我们运行上面的代码，注意到 `1` 被发出，错误被作为正常值发出，最后，甚至 `2` 也被发出了。我们的结论是在将我们的流与其他流合并之前，应用 `catch()` 运算符是一个好主意。

与之前一样，我们也可以得出结论，`catch()` 运算符能够阻止流仅仅出错，但是在错误之后会发出的其他值实际上是丢失的。

# 忽略错误

正如我们在前面的部分看到的，`catch()` 运算符很好地确保了出错的流在与另一个流合并时不会造成任何问题。`catch()` 运算符使我们能够获取错误，调查它，并创建一个新的 Observable ，它将发出一个值，就好像什么都没发生一样。然而，有时候，您甚至不想使用出错的流。对于这种情况，有一个名为 `onErrorResumeNext()` 的不同运算符：

```ts
// error-handling/error-ignore.js
const Rx = require("rxjs/Rx");

let mergedIgnore$ = Rx.Observable.onErrorResumeNext(
  Rx.Observable.of(1),
  Rx.Observable.throw("err"),
  Rx.Observable.of(2)
);

mergedIgnore$.subscribe(data => console.log("merge ignore", data));
```

使用`onErrorResumeNext()` 运算符的含义是第二个流，即发出错误的流，完全被忽略，发出值`1`和`2`。如果您的场景仅涉及不出错的流，这是一个非常好的运算符。

# 重试

有不同的原因，你会想要重试一个流。如果您的流处理 AJAX 调用，你就更容易想象为什么要这样做。有时候，局域网上的网络连接可能不可靠，或者您尝试访问的服务可能因某些原因暂时不可用。无论原因如何，您都会遇到这样一种情况，即 hitting 那个端点有时候会回答一个答案，有时候会返回一个 401 错误。我们在这里描述的是向您的流添加重试逻辑的业务场景。让我们看一个设计为失败的流：

```ts
// error-handling/error-retry.js
const Rx = require("rxjs/Rx");

let stream$ = Rx.Observable.create(observer => {
  observer.next(1);
  observer.error("err");
})
.retry(3);

// emits 1 1 1 1 err
stream$
  .subscribe(data => console.log(data));
```

以上代码的输出是值`1`被发出了四次，然后是我们的错误。发生的情况是我们的流值在订阅中错误回调被命中之前重试了三次。使用`retry()`操作符延迟了什么时候错误实际被视为错误。然而，上面的例子不合理的地方在于重试是没有意义的，因为错误总是会发生。因此，让我们举个更好的例子 – 一个网络连接可能出现忽然消失的 AJAX 调用：

```ts
// example of using a retry with AJAX

let ajaxStream$ = Rx.Observable.ajax("UK1.json")
  .map(r => r.response)
  .retry(3);

ajaxStream$.subscribe(
  data => console.log("ajax result", data),
  err => console.error("ajax error", err)
);
```

在这里，我们正在尝试向一个似乎不存在的文件发送一个 AJAX 请求。看看控制台，我们面临以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/e4df4109-8dd2-41ee-bbf7-5a7a99832bd4.png)

在上述日志中我们看到了四次失败的 AJAX 请求，导致了一个错误。我们基本上仅仅是将我们的简单流切换为了一个更可信的 AJAX 请求流，具有相同的行为。如果文件突然开始存在，可能会出现两次失败尝试和一次成功尝试的情况。然而，我们的方法有一个缺陷：我们进行 AJAX 尝试的次数太多了。如果我们实际上正在处理间歇性的网络连接，我们需要在尝试之间设置一定的延迟。合理的做法是在尝试之间设置至少 30 秒或更长的延迟。我们可以通过使用一种稍微不同的重试操作符来实现这一点，它以毫秒而不是尝试次数作为参数。它看起来像下面这样：

```ts
// retry with a delay

let ajaxStream$ = Rx.Observable.ajax("UK1.json")
  .do(r => console.log("emitted"))
  .map(r => r.response)
  .retryWhen(err => {
    return err.delay(3000);
  });
```

这里我们使用了操作符`retryWhen()`。`retryWhen()`操作符的使命是返回一个流。在这一点上，你可以通过添加一个`.delay()`操作符来延迟它返回的流，以便能够操纵它。这样做的结果是，它将永远重试 AJAX 调用，这可能不是你想要的。

# 高级重试

我们最有可能想要的是将重试尝试之间的延迟与能够指定我们想要重试流的次数结合起来。让我们看看如何实现这一点：

```ts
// error-handling/error-retry-advanced.js

const Rx = require("rxjs/Rx");

let ajaxStream$ = Rx.Observable.ajax("UK1.json")
  .do(r => console.log("emitted"))
  .map(r => r.response)
  .retryWhen(err => {
    return err
    .delay(3000)
    .take(3);
});

```

这里有趣的部分是我们使用了操作符`.take()`。我们指定了我们想要从这个内部 Observable 中发出的值的数量。我们现在实现了一种不错的方法，可以控制重试次数和重试之间的延迟。还有一个方面我们还没有尝试到，即当最终放弃时我们想要重试全部重试的方式。在之前的代码中，当流在尝试了*x*次后没有成功结果时，流就会直接完成。然而，我们可能希望流出现错误。我们只需在代码中添加一个操作符，就可以实现这一点，像这样：

```ts
// error-handling/error-retry-advanced-fail.js

let ajaxStream$ = Rx.Observable.ajax("UK1.json")
  .do(r => console.log("emitted"))
  .map(r => r.response)
  .retryWhen(err => {
    return err
    .delay(3000)
    .take(3)
    .concat(Rx.Observable.throw("giving up"));
});
```

在这里，我们添加了一个`concat()`操作符，它将一个仅仅会失败的流添加进来。因此，在三次失败尝试之后一定会发生一个错误。这通常比在*x*次失败尝试之后默默地完成流更好。

不过这并不是一个完美的方法；想象一下你想调查你得到了什么类型的错误。对于进行的 AJAX 请求的情况来说，获得一个以 400 开头的错误和以 500 开头的错误作为 HTTP 状态码是有关系的。它们有不同的含义。500 错误意味着后端出了非常严重的问题，我们可能要立即放弃。然而，404 错误意味着资源不存在，但在与断断续续的网络连接的情况下，这意味着由于我们的连接离线而无法到达资源。因此，重新尝试 404 错误可能是值得的。为了在代码中解决这个问题，我们需要检查发出的值以确定要做什么。我们可以使用`do()`操作符来检查值。

在下面的代码中，我们调查响应的 HTTP 状态类型并确定如何处理它：

```ts
// error-handling/error-retry-errorcodes.js

const Rx = require("rxjs/Rx");

function isOkError(errorCode) {
  return errorCode >= 400 && errorCode < 500;
}

let ajaxStream$ = Rx.Observable.ajax("UK1.json")
  .do(r => console.log("emitted"))
  .map(r => r.response)
  .retryWhen(err => {
    return err
      .do(val => {
        if (!isOkError(val.status) || timesToRetry === 0) {
          throw "give up";
        }
      })
      .delay(3000);
  });
```

# 大理石测试

测试异步代码可能是具有挑战性的。首先，我们有时间因素。我们指定用于我们精心设计的算法的操作符的方式导致算法执行的时间从 2 秒到 30 分钟不等。因此，一开始会感觉没有必要进行测试，因为在合理的时间内无法完成。不过，我们有一种测试 RxJS 的方法；它被称为大理石测试，它允许我们控制时间的流逝速度，这样我们就可以在毫秒内执行测试。

大理石的概念为我们所知。我们可以表示一个或多个流以及操作符对两个或多个流产生的影响。我们通过在线上画出流并将值表示为线上的圆圈来做到这一点。操作符显示为输入流下面的动词。操作符后面是第三个流，这是取得输入流并应用操作符得到的结果，即所谓的大理石图。线表示一个连续的时间线。我们将这个概念带到测试中。这意味着我们可以将我们的传入值表示为一个图形表达，并对其应用我们的算法，然后对结果进行断言。

# 设置

让我们正确设置环境，以便我们可以编写大理石测试。我们需要以下内容：

+   NPM 库 jasmine-marbles

+   一个已经脚手架化的 Angular 应用

有了这些，我们脚手架化我们的 Angular 项目，就像这样：

```ts
ng new MarbleTesting
```

项目脚手架完成后，现在是时候添加我们的 NPM 库了，就像这样：

```ts
cd MarbleTesting
npm install jasmine-marbles --save
```

现在我们已经完成了设置，所以是时候编写测试了。

# 编写你的第一个大理石测试

让我们创建一个新的文件`marble-testing.spec.ts`。它应该看起来像这样：

```ts
// marble-testing\MarbleTesting\src\app\marble-testing.spec.ts

import { cold } from "jasmine-marbles";
import "rxjs/add/operator/map";

describe("marble tests", () => {
  it("map - should increase by 1", () => {
    const one$ = cold("x-x|", { x: 1 });
    expect(one$.map(x => x + 1)).toBeObservable(cold("x-x|", { x: 2 }));
  });
});
```

这里发生了很多有趣的事情。我们从 NPM 库 marble-testing 中导入`cold()`函数。然后我们通过调用`describe()`来设置一个测试套件，接着通过调用`it()`来设置一个测试规范。然后我们调用我们的`cold()`函数并提供一个字符串。让我们仔细看看那个函数调用：

```ts
const stream$ = cold("x-x|", { x: 1 });
```

上面的代码设置了一个流，期望在流结束前发出两个值。我们怎么知道呢？现在该解释`x-x|`的含义了。`x`只是任意值，短横线`-`表示时间过去了。竖线`|`表示我们的流已结束。冷函数中的第二个参数是一个映射对象，告诉我们 x 代表什么。在这种情况下，它意味着值是 1。

接下来，让我们看一下下一行：

```ts
expect(stream$.map(x => x + 1)).toBeObservable(cold("x-x|", { x: 2 }));
```

上述代码应用了`.map()`运算符，并且对流中发出的每个值加了一。然后，我们调用了`.toBeObservable()`辅助方法并根据预期条件进行验证，

```ts
cold("x-x|", { x: 2 })
```

前面的条件说明我们期望流应该发出两个值，但这些值应该有数字 2。这是有道理的，因为我们的`map()`函数就是做这个。

# 补充更多测试

让我们再写一个测试。这次我们将测试`filter()`运算符。这个很有意思，因为它过滤掉不满足特定条件的值。我们的测试文件现在应该看起来像这样：

```ts
import { cold } from "jasmine-marbles";
import "rxjs/add/operator/map";
import "rxjs/add/operator/filter";

describe("marble testing", () => {
  it("map - should increase by 1", () => {
    const one$ = cold("x-x|", { x: 1 });
    expect(one$.map(x => x + 1)).toBeObservable(cold("x-x|", { x: 2 }));
  });

  it("filter - should remove values", () => {
    const stream$ = cold("x-y|", { x: 1, y: 2 });
    expect(stream$.filter(x => x > 1)).toBeObservable(cold("--y|", { y: 2 }));
  });
});
```

这个测试设置方式几乎和我们的第一个测试一样。这次我们使用`filter()`运算符，但值得注意的是我们的预期流：

```ts
cold("--y|", { y: 2 })
```

`--y`，表示我们的第一个值被移除了。根据过滤条件的定义，我们不感到意外。然而，双短横线`-`的原因是时间仍在流逝，但是一个短横线取代了一个发出的值。

要了解更多关于 Marble 测试的信息，请查看官方文档中的以下链接，[`github.com/ReactiveX/rxjs/blob/master/doc/writing-marble-tests.md`](https://github.com/ReactiveX/rxjs/blob/master/doc/writing-marble-tests.md)

# 可管道的运算符

到目前为止，我们没有提及太多，但是当在应用中使用 RxJS 库时，它会占据相当大的空间。在如今的移动优先世界中，每个库在你的应用中包含的千字节都很重要。这很重要，因为用户可能在 3G 连接上，如果加载时间过长，用户可能离开，或者可能不喜欢你的应用，因为它感觉加载很慢，这可能导致你得到不好的评论或失去用户。到目前为止，我们已经使用了两种不同的导入 RxJS 的方式：

+   导入整个库；这在体积上是相当昂贵的

+   只导入我们需要的运算符；这可以显著减少捆绑包的大小

不同的选项看起来像这样，导入整个库和所有它的运算符：

```ts
import Rx from "rxjs/Rx";
```

或者这样，只导入我们需要的内容：

```ts
import { Observable } from 'rxjs/Observable';
import "rxjs/add/operator/map";
import "rxjs/add/operator/take";

let stream = Observable.interval(1000)
  .map(x => x +1)
  .take(2)
```

这看起来不错，是吗？是的，但这是一个有缺陷的方法。让我们解释一下当你输入时会发生什么：

```ts
import "rxjs/add/operator/map";
```

通过输入上述内容，我们会添加到`Observable`的原型中。查看 RxJS 的源代码，它是这样的：

```ts
var Observable_1 = require('../../Observable');
var map_1 = require('../../operator/map');

Observable_1.Observable.prototype.map = map_1.map;
```

从上面的代码中可以看出，我们导入了`Observable`以及相关的操作符，并且通过将它们分配到原型的`map`属性上，将操作符添加到了原型上。你可能会想这有什么毛病？问题在于摇树优化，这是我们用来摆脱未使用代码的过程。摇树优化在确定你使用和不使用的代码时会出现问题。事实上，你可能导入了一个`map()`操作符并将其添加到 Observable 上。随着代码随着时间的推移而改变，你可能最终不再使用它。你可能会争辩说此刻应该移除导入，但你可能的代码量很大，很容易忽略。最好的方式应该是只有使用的操作符包含在最终的包中。正如我们之前提到的，摇树优化的过程很难知道当前方法中使用了什么，没有使用什么。因此，在 RxJS 中进行了一次大规模的重写，添加了一种称为可管道化操作符的东西，它帮助我们解决了上述问题。对原型进行补丁还有另一个不足之处，那就是它创建了一个依赖。如果库发生改变并且我们在进行补丁时不再添加操作符（调用导入），那么我们就有了一个问题。我们只有在运行时才会发现这个问题。我们宁愿得到一个消息，告诉我们操作符已经过我们导入和明确使用，就像这样：

```ts
import { operator } from 'some/path';

operator();
```

# 使用 `let()` 创建可重用的操作符

`let()`操作符允许你拥有整个操作符并对其进行操作，而不仅仅像`map()`操作符那样操作值。使用`let()`操作符可能像这样：

```ts
import Rx from "rxjs/Rx";

let stream = Rx.Observable.of(0,1,2);
let addAndFilter = obs => obs.map( x => x * 10).filter(x => x % 10 === 0);
let sub3 = obs => obs.map(x => x - 3);

stream
  .let(addAndFilter)
  .let(sub3)
  .subscribe(x => console.log('let', x));

```

在上面的例子中，我们能够定义一组操作符，比如`addAndFilter`和`sub3`，并且使用`let()`操作符在流上使用它们。这使我们能够创建可组合和可重用的操作符。正是基于这种知识，我们现在转向可管道化操作符的概念。

# 转向可管道化操作符

正如我们之前提到的，可管道化操作符已经出现了，通过从`rxjs/operators`目录中导入相应的操作符，你就能找到它们，就像这样：

```ts
import { map } from "rxjs/operators/map";
import { filter } from "rxjs/operators/filter";
```

要使用它，我们现在依赖于`pipe()`操作符，它就像父操作符一样。因此，使用上述操作符将如下所示：

```ts
import { map } from "rxjs/operators/map";
import { filter } from "rxjs/operators";
import { of } from "rxjs/observable/of";
import { Observable } from "rxjs/Observable";

let stream = of(1,2);
stream.pipe(
  map(x => x + 1),
  filter(x => x > 1)
)
.subscribe(x => console.log("piped", x)); // emits 2 and 3
```

# 总结

本章内容深入介绍了 RxJS，涉及了诸如热、冷、温暖的 Observables 等主题，并且解释了在何时订阅流以及在特定条件下它们如何共享生产者的含义。接下来，我们介绍了 Subject，并且 Observable 并不是你唯一可以订阅的东西。Subject 也允许我们随时向流中添加值，并且我们也了解到根据具体情况存在不同类型的 Subject。

我们深入探讨了一个重要的主题，测试，并试图解释测试异步代码的困难。我们谈到了测试情况的当前状态，以及在这里和现在用什么库进行测试场景。最后，我们介绍了管道操作符，以及我们新的首选导入和组合操作符的方式，以确保我们最终得到尽可能小的捆绑包大小。

在下一章中，您将利用 Waffle 使用看板，按照全栈架构构建一个简单的 Web 应用，并了解使用 RxJS 进行响应式编程。
