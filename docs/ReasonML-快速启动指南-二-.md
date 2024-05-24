# ReasonML 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/EBC7126C5733D51726286A656704EE51`](https://zh.annas-archive.org/md5/EBC7126C5733D51726286A656704EE51)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：BuckleScript，Belt 和互操作性

在本章中，我们将更仔细地了解 BuckleScript 特定的功能。我们还将学习递归和递归数据结构。到本章结束时，我们将在 Reason 及其生态系统的介绍中完成一个完整的循环。在这样做的过程中，我们将完成以下工作：

+   更多了解 Reason 的模块系统

+   探索了 Reason 的原始数据结构（数组和列表）

+   看到各种管道运算符如何使代码更易读

+   熟悉 Reason 和 Belt 标准库

+   为在 Reason 中使用而创建了对 JavaScript 模块的绑定

+   通过绑定到 React Transition Group 组件为我们的应用程序添加路由转换

要跟进，请使用您希望的任何环境。我们将要做的大部分工作与 ReasonReact 无关。在本章末尾，我们将继续构建我们的 ReasonReact 应用程序。

# 模块范围

正如您现在所知，所有`.re`文件都是模块，所有模块都是全局可用的，包括嵌套的模块。默认情况下，可以通过提供命名空间从任何地方访问所有类型和绑定。然而，一遍又一遍地这样做很快变得乏味。幸运的是，我们有几种方法可以使这更加愉快：

```js
/* Foo.re */
type fromFoo =
  | Add(int, int)
  | Multiply(int, int);

let a = 1;
let b = 2;
```

接下来，我们将以不同的方式在另一个模块中使用`Foo`模块的`fromFoo`类型以及它的绑定：

+   **选项 1**：不使用任何语法糖：

```js
/* Bar.re */
let fromFoo = Foo.Add(Foo.a, Foo.b);
```

+   **选项 2**：将模块别名为更短的名称。例如，我们可以声明一个新模块`F`并将其绑定到现有模块`Foo`：

```js
/* Bar.re */
module F = Foo;
let fromFoo = F.Add(F.a, F.b);
```

+   **选项 3**：使用`Module.()`语法在本地打开模块。此语法仅适用于单个表达式：

```js
/* Bar.re */
let fromFoo = Foo.(Add(a, b));
```

+   **选项 4**：在面向对象编程意义上，使用`include`使`Bar`扩展`Foo`：

```js
/* Bar.re */
include Foo;
let a = 4; /* override Foo.a */
let fromFoo = Add(a, b);
```

+   **选项 5**：全局`open`模块。在大范围内谨慎使用`open`，因为很难知道哪些类型和绑定属于哪些模块：

```js
/* Bar.re */
open Foo;
let fromFoo = Add(a, b);
```

在本地范围内最好使用`open`：

```js
/* Bar.re */
let fromFoo = {
  open Foo;
  Add(a, b);
};
```

前面的语法将通过`refmt`重新格式化为选项 3 的语法，但请记住，选项 3 的语法仅适用于单个表达式。例如，以下内容无法转换为选项 3 的语法：

```js
/* Bar.re */
let fromFoo = {
  open Foo;
  Js.log("foo");
  let result = Add(a, b);
};
```

Reason 标准库包含在我们已经可以使用的各种模块中。例如，Reason 的标准库包括一个`Array`模块，我们可以使用点表示法（即`Array.length`）访问其函数。

在第五章中，*Effective ML*，我们将学习如何隐藏模块的类型和绑定，以便在不希望它们全局可用时不让它们全局可用。

# 数据结构

我们已经看到了 Reason 的几种原始数据结构，包括字符串、整数、浮点数、元组、记录和变体。让我们再探索一些。

# 数组

Reason 数组编译为常规的 JavaScript 数组。Reason 数组如下：

+   同种（所有元素必须是相同类型）

+   可变的

+   快速随机访问和更新

它们看起来像这样：

```js
let array = [|"first", "second", "third"|];
```

访问和更新数组的元素与 JavaScript 中的操作相同：

```js
array[0] = "updated";
```

在 JavaScript 中，我们对数组进行映射，如下所示：

```js
/* JavaScript */
array.map(e => e + "-mapped")
```

在 Reason 中执行相同操作时，我们有几种不同的选择。

# 使用 Reason 标准库

Reason 标准库的`Array`模块包含几个函数，但并非您从 JavaScript 中期望的所有函数。但它确实有一个`map`函数：

```js
/* Reason standard library */
let array = [|"first", "second", "third"|];
Array.map(e => e ++ "-mapped", array);
```

`Array.map`的类型如下：

```js
('a => 'b, array('a)) => array('b);
```

类型签名表示`map`接受类型为`'a => 'b`的函数，类型为`'a`的数组，并返回类型为`'b`的数组。请注意，`'a`和`'b`是**类型变量**。类型变量类似于普通变量，只不过是类型。在前面的示例中，`map`的类型为：

```js
(string => string, array(string)) => array(string);
```

这是因为`'a`和`'b`类型变量都被一致地替换为具体的`string`类型。

请注意，使用`Array.map`时，编译输出不会编译为 JavaScript 的`Array.prototype.map`——它有自己的实现：

```js
/* in the compiled output */
...
require("./stdlib/array.js");
...
```

Reason 标准库文档可以在这里找到：

[`reasonml.github.io/api`](https://reasonml.github.io/api)

# 使用 Belt 标准库

Reason 标准库实际上是 OCaml 标准库。它并不是为 JavaScript 而创建的。Belt 标准库是由创建 BuckleScript 的同一个人——张宏波——创建的，并且随 BuckleScript 一起发布。Belt 是为 JavaScript 而创建的，尤其以其性能而闻名。Belt 标准库通过`Belt`模块访问：

```js
/* Belt standard library */
let array = [|"first", "second", "third"|];
Belt.Array.map(array, e => e ++ "-mapped");
```

Belt 标准库文档可以在这里找到：

[`bucklescript.github.io/bucklescript/api/Belt.html`](https://bucklescript.github.io/bucklescript/api/Belt.html)

# 使用 BuckleScript 内置的 JavaScript 绑定

另一个很好的选择是使用 BuckleScript 内置的 JavaScript 绑定，可以在`Js`模块中找到：

```js
/* BuckleScript's JavaScript bindings */
let array = [|"first", "second", "third"|];
Js.Array.map(e => e ++ "-mapped", array);
```

这个选项的优势是在编译输出中不需要任何依赖项。它还具有非常熟悉的 API。但是，由于并非所有 Reason 数据结构都存在于 JavaScript 中，您可能会使用标准库。如果是这样，请优先选择 Belt。

BuckleScript 的绑定文档可以在这里找到：

[`bucklescript.github.io/bucklescript/api/Js.html`](https://bucklescript.github.io/bucklescript/api/Js.html)

# 使用自定义绑定

你可以自己编写自定义绑定：

```js
[@bs.send] external map: (array('a), 'a => 'b) => array('b) = "";
let array = [|"first", "second", "third"|];
map(array, e => e ++ "-mapped")
```

当然，你应该更倾向于使用`Js`模块中的内置绑定。我们将在本章后面探讨更多自定义绑定。

# 使用原始 JavaScript

最后的选择是在 Reason 中使用实际的 JavaScript：

```js
let array = [|"first", "second", "third"|];
let map = [%raw {|
  function(f, array) {
    return array.map(f)
  }
|}];
map(e => e ++ "-mapped", array)
```

BuckleScript 让我们以原始 JavaScript 的方式保持高效学习。当然，这样做时，我们放弃了 Reason 提供的安全性。因此，一旦准备好，将任何原始 JavaScript 代码转换回更符合惯例的 Reason。

在使用原始 JavaScript 时，对于表达式使用`%`，对于语句使用`%%`。记住，`{| |}`是 Reason 的多行字符串语法：

```js
let array = [%raw "['first', 'second', 'third']"];
[%%raw {|
  array = array.map(e => e + "-mapped");
|}];
```

使用原始表达式语法，我们还可以注释类型：

```js
let array: array(string) = [%raw "['first', 'second', 'third']"];
```

我们甚至可以注释函数类型：

```js
let random: unit => float = [%raw
  {|
    function() {
     return Math.random();
    }
  |}
];
```

尽管从 JavaScript 中来时数组很熟悉，但您可能会发现自己使用列表，因为它们在函数式编程中是无处不在的。列表既是**不可变的**又是**递归的**。现在让我们看看如何使用这种递归数据结构。

# 列表

Reason 列表如下：

+   同质的

+   不可变的

+   在列表的头部快速添加和访问

它们看起来像这样：

```js
let list = ["first", "second", "third"];
```

列表的头，在这种情况下，是`"first"`。到目前为止，我们已经看到使用不可变数据结构并不困难。我们不是进行突变，而是创建更新后的副本。

在处理列表时，我们不能直接使用 JavaScript 绑定，因为列表在 JavaScript 中并不作为原始数据结构存在。但是，我们可以将列表转换为数组，反之亦然：

```js
/* Belt standard library */
let list = ["first", "second", "third"];
let array = Belt.List.toArray(list);

let array = [|"first", "second", "third"|];
let list = Belt.List.fromArray(array);

/* Reason standard library */
let list = ["first", "second", "third"];
let array = Array.of_list(list);

let array = [|"first", "second", "third"|];
let list = Array.to_list(array);
```

但我们也可以直接映射列表：

```js
/* Belt standard library */
let list = ["first", "second", "third"];
Belt.List.map(list, e => e ++ "-mapped");

/* Reason standard library */
let list = ["first", "second", "third"];
List.map(e => e ++ "-mapped", list);
```

将`list`记录到控制台显示，列表在 JavaScript 中表示为嵌套数组，其中每个数组始终有两个元素：

```js
["first", ["second", ["third", 0]]]
```

在理解列表是一个递归数据结构之后，这是有意义的。Reason 列表是**单向链表**。列表中的每个元素要么是**空**（在 JavaScript 中表示为`0`），要么是值和另一个列表的**组合**。

`list`的示例类型定义显示`list`是一个变体：

```js
type list('a) = Empty | Head('a, list('a));
```

注意：类型定义可以是递归的。

Reason 提供了一些语法糖，简化了更冗长的版本：

```js
Head("first", Head("second", Head("third", Empty)));
```

# 递归

由于列表是一个递归数据结构，我们通常在处理它时使用递归。

为了热身，让我们编写一个（天真的）函数，对整数列表求和：

```js
let rec sum = list => switch(list) {
  | [] => 0
  | [hd, ...tl] => hd + sum(tl)
};
```

+   这是一个递归函数，因此需要`rec`关键字（即`let rec`而不仅仅是`let`）

+   我们可以对列表进行模式匹配（就像任何其他变体和许多其他数据结构一样）

+   从示例类型定义中，`Empty`表示为`[]`，`Head`表示为`[hd, ...tl]`，其中`hd`是列表的**头部**，`tl`是剩余部分（即列表的**尾部**）

+   `tl`可能是`[]`（即`Empty`），当它是这样时，递归停止

传入`sum`函数的列表`[1, 2, 3]`会产生以下步骤：

```js
sum([1, 2, 3])
1 + sum([2, 3])
1 + 2 + sum([3])
1 + 2 + 3
6
```

让我们通过分析另一个（朴素的）反转列表的函数，更加熟悉列表和递归：

```js
let rec reverse = list => switch(list) {
  | [] => []
  | [hd, ...tl] => reverse(tl) @ [hd]
};
```

+   同样，我们使用`rec`来定义一个递归函数

+   同样，我们在列表上使用模式匹配——如果它为空，则停止递归；否则，继续使用较小的列表

+   `@`操作符将第二个列表附加到第一个列表的末尾

传入先前定义的列表(`["first", "second", "third"]`)会产生以下步骤：

```js
reverse(["first", "second", "third"])
reverse(["second", "third"]) @ ["first"]
reverse(["third"]) @ ["second"] @ ["first"]
reverse([]) @ ["third"] @ ["second"] @ ["first"]
[] @ ["third"] @ ["second"] @ ["first"]
["third", "second", "first"]
```

这个 reverse 的实现方法有两个问题：

+   它不是尾调用优化的（我们的`sum`函数也不是）

+   它使用`append`（`@`），这比`prepend`慢

更好的实现方法是使用一个带有累加器的本地辅助函数：

```js
let reverse = list => {
  let rec aux = (list, acc) => switch(list) {
    | [] => acc
    | [hd, ...tl] => aux(tl, [hd, ...acc])
  };
  aux(list, []);
};
```

现在，它的尾调用已经优化，并且它使用 prepend 而不是 append。在 Reason 中，您可以使用`...`语法向列表前置：

```js
let list = ["first", "second", "third"];
let list = ["prepended", ...list];
```

传入列表(`["first", "second", "third"]`)大致会产生以下步骤：

```js
reverse(["first", "second", "third"])
aux(["first", "second", "third"], [])
aux(["second", "third"], ["first"])
aux(["third"], ["second", "first"])
aux([], ["third", "second", "first"])
["third", "second", "first"]
```

请注意，在非尾递归版本中，Reason 无法创建列表直到递归完成。在尾递归版本中，累加器（即`aux`的第二个参数）在每次迭代后更新。

尾递归（即尾调用优化）函数的好处在于能够重用当前的堆栈帧。因此，尾递归函数永远不会发生堆栈溢出，但非尾递归函数在足够的迭代次数后可能会发生堆栈溢出。

# 管道操作符

Reason 有两个管道操作符：

```js
|> (pipe)
-> (fast pipe)
```

两个管道操作符都将参数传递给函数。`|>`管道操作符将参数传递给函数的最后一个参数，而`->`快速管道操作符将参数传递给函数的第一个参数。

看一下这些：

```js
three |> f(one, two)
one -> f(two, three)
```

它们等价于这个：

```js
f(one, two, three)
```

如果函数只接受一个参数，那么两个管道的工作方式是相同的，因为函数的第一个参数也是函数的最后一个参数。

使用这些管道操作符非常流行，因为一旦你掌握了它，代码会变得更加可读。

我们不需要使用这个：

```js
Belt.List.(reduce(map([1, 2, 3], e => e + 1), 0, (+)))
```

我们可以以一种不需要读者从内到外阅读的方式来编写它：

```js
Belt.List.(
 [1, 2, 3]
 ->map(e => e + 1)
 ->reduce(0, (+))
);
```

正如你所看到的，使用快速管道看起来类似于 JavaScript 中的链式调用。与 JavaScript 不同的是，我们可以传递`+`函数，因为它只是一个接受两个参数并将它们相加的普通函数。括号是必要的，告诉 Reason 将中缀操作符`（+）`视为标识符。

# 使用 Belt

让我们利用本章学到的知识来编写一个小程序，创建一副牌，洗牌，并从牌堆顶部抽取五张牌。为此，我们将使用 Belt 的`Option`和`List`模块，以及快速管道操作符。

# Option 模块

Belt 的`Option`模块是用于处理`option`类型的实用函数集合。例如，要解包一个选项，并在选项的值为`None`时抛出运行时异常，我们可以使用`getExn`：

```js
let foo = Some(3)->Belt.Option.getExn;
Js.log(foo); /* 3 */

let foo = None->Belt.Option.getExn;
Js.log(foo); /* raises getExn exception */
```

能够抛出运行时异常的 Belt 函数总是带有`Exn`后缀。

另一个解包选项的替代函数是`getWithDefault`，它不能抛出运行时异常：

```js
let foo = None->Belt.Option.getWithDefault(0);
Js.log(foo); /* 0 */
```

`Option`模块还提供了其他几个函数，如`isSome`、`isNone`、`map`、`mapWithDefault`等。查看文档以获取详细信息。

Belt Option 模块的文档可以在这里找到：

[`bucklescript.github.io/bucklescript/api/Belt.Option.html`](https://bucklescript.github.io/bucklescript/api/Belt.Option.html)

# List 模块

List 模块是用于列表数据类型的实用程序。要查看 Belt 提供的用于处理列表的函数，请检查 Belt 的`List`模块文档。

Belt List 模块的文档可以在这里找到：

[`bucklescript.github.io/bucklescript/api/Belt.List.html`](https://bucklescript.github.io/bucklescript/api/Belt.List.html)

让我们专注于其中的一些。

# make

`make` 函数用于创建一个填充列表。它接受一个整数作为列表的长度，以及列表中每个项目的值。它的类型如下：

```js
(int, 'a) => Belt.List.t('a)
```

`Belt.List.t` 被公开为 `list` 类型的别名，因此我们可以说 `Belt.List.make` 的类型如下：

```js
(int, 'a) => list('a)
```

我们可以用它来创建一个包含十个字符串的列表，就像这样：

```js
let list = Belt.List.make(10, "string");
```

在第五章 *Effective ML* 中，我们将学习如何显式地从模块中公开或隐藏类型和绑定。

# makeBy

`makeBy` 函数类似于 `make` 函数，但它接受一个用于确定每个项目的值的函数，给定项目的索引。

`makeBy` 函数的类型如下：

```js
(int, int => 'a) => Belt.List.t('a)
```

我们可以用它来创建一个包含十个项目的列表，其中每个项目都等于它的索引：

```js
let list = Belt.List.makeBy(10, i => i);
```

# shuffle

`shuffle` 函数会随机洗牌一个列表。它的类型是：

```js
Belt.List.t('a) => Belt.List.t('a)
```

它接受一个列表并返回一个新列表。让我们用它来洗牌我们的整数列表：

```js
let list = Belt.List.(makeBy(10, i => i)->shuffle);
```

# take

`take` 函数接受一个列表和一个长度，并返回从列表头部开始的长度等于请求长度的子集。由于子集的请求长度可能超过原始列表的长度，结果被包装在一个选项中。它的类型如下：

```js
(Belt.List.t('a), int) => option(Belt.List.t('a))
```

我们可以从洗牌后的列表中取出前两个项目，就像这样：

```js
let list = Belt.List.(makeBy(10, i => i)->shuffle->take(2));
```

# 卡牌组示例

现在，我们准备将这个与我们从前几章学到的内容结合起来。你会如何编写一个创建一副卡牌、洗牌并抽取前五张卡的程序？在看下面的例子之前，自己试一试。

```js
type suit =
  | Hearts
  | Diamonds
  | Spades
  | Clubs;

type card = {
  suit,
  rank: int,
};

Belt.List.(
  makeBy(52, i =>
    switch (i / 13, i mod 13) {
    | (0, rank) => {suit: Hearts, rank: rank + 1}
    | (1, rank) => {suit: Diamonds, rank: rank + 1}
    | (2, rank) => {suit: Spades, rank: rank + 1}
    | (3, rank) => {suit: Clubs, rank: rank + 1}
    | _ => assert(false)
    }
  )
  ->shuffle
  ->take(5)
  ->Belt.Option.getExn
  ->(
      cards => {
        let rankToString = rank =>
          switch (rank) {
          | 1 => "Ace"
          | 13 => "King"
          | 12 => "Queen"
          | 11 => "Jack"
          | rank => string_of_int(rank)
          };

        let suitToString = suit =>
          switch (suit) {
          | Hearts => "Hearts"
          | Diamonds => "Diamonds"
          | Spades => "Spades"
          | Clubs => "Clubs"
          };

        map(cards, ({rank, suit}) =>
          rankToString(rank) ++ " of " ++ suitToString(suit)
        );
      }
    )
  ->toArray
  ->Js.log
);
```

这会以字符串格式随机产生五张卡牌的数组：

```js
[
  "Queen of Clubs",
  "4 of Clubs",
  "King of Spades",
  "Ace of Hearts",
  "9 of Spades"
]
```

# 柯里化

Belt 标准库的一些函数带有 *U* 后缀，比如这个：

```js
Belt.List.makeBy
```

你可以在这里看到后缀：

```js
Belt.List.makeByU
```

*U* 后缀代表 *uncurried*。在继续之前，让我们定义一下柯里化。

在 Reason 中，每个函数都只接受一个参数。这似乎与我们之前的许多例子相矛盾：

```js
let add = (a, b) => a + b;
```

前述的 `add` 函数看起来好像接受两个参数，但实际上只是以下的语法糖：

```js
let add = a => b => a + b;
```

`add` 函数接受一个参数 `a`，返回一个接受一个参数 `b` 的函数，然后返回 `a + b` 的结果。

在 Reason 中，两个版本都是有效的，并且具有相同的编译输出。在 JavaScript 中，前述两个版本都是有效的，但它们并不相同；它们需要以不同的方式使用才能获得相同的结果。第二个需要这样调用：

```js
add(2)(3);
```

这是因为 `add` 返回一个需要再次调用的函数，因此有两组括号。Reason 可以接受任何一种用法：

```js
add(2, 3);
add(2)(3);
```

柯里化的好处在于它使得组合函数更容易。你可以轻松地创建一个部分应用的函数 `addOne`：

```js
let addOne = add(1);
```

然后可以将这个 `addOne` 函数传递给其他函数，比如 `map`。也许你想使用这个功能将一个函数部分应用到 ReasonReact 子组件，而父组件的 `self` 部分应用。

令人困惑的是，`add` 的任一版本的编译输出如下：

```js
function add(a, b) {
  return a + b | 0;
}
```

中间函数在哪里？在可能的情况下，BuckleScript 优化编译输出，以避免不必要的函数分配，从而提高性能。

请记住，由于 Reason 的中缀运算符只是普通函数，我们可以这样做：

```js
let addOne = (+)(1);
```

# 柯里化的函数

由于 JavaScript 的动态特性，BuckleScript 不能总是优化编译输出以删除中间函数。但是，你可以告诉 BuckleScript 使用以下语法对函数进行 uncurry：

```js
let add = (. a, b) => a + b;
```

uncurry 语法是参数列表中的点。它需要在声明和调用站点都存在：

```js
let result = add(. 2, 3); /* 5 */
```

如果调用站点没有使用 uncurry 语法，BuckleScript 将抛出编译时错误：

```js
let result = add(2, 3);

We've found a bug for you!

This is an uncurried BuckleScript function. It must be applied with a dot.

Like this: foo(. a, b)
Not like this: foo(a, b)
```

此外，如果在调用站点缺少某些函数的参数，则会抛出编译时错误：

```js
let result = add(. 2);

We've found a bug for you!

Found uncurried application [@bs] with arity 2, where arity 1 was expected.
```

术语`arity`指的是函数接受的参数数量。

# makeByU

如果我们取消`makeBy`的第二个参数的柯里化，可以用`makeByU`替换它。这将提高性能（在我们的示例中可以忽略不计）：

```js
...
makeByU(52, (. i) =>
  switch (i / 13, i mod 13) {
  | (0, rank) => {suit: Hearts, rank: rank + 1}
  | (1, rank) => {suit: Diamonds, rank: rank + 1}
  | (2, rank) => {suit: Spades, rank: rank + 1}
  | (3, rank) => {suit: Clubs, rank: rank + 1}
  | _ => assert(false)
  }
)
...
```

点语法需要在`i`周围加括号。

# JavaScript 互操作性

术语**互操作性**指的是 Reason 程序在 Reason 中使用现有 JavaScript 的能力。BuckleScript 提供了一个出色的系统，用于在 Reason 中使用现有的 JavaScript 代码，并且还可以轻松地在 JavaScript 中使用 Reason 代码。

# 在 Reason 中使用 JavaScript

我们已经看到了如何在 Reason 中使用原始 JavaScript。现在让我们专注于如何绑定到现有的 JavaScript。要将值绑定到命名引用，通常使用`let`。然后可以在后续代码中使用该绑定。当我们要绑定的值位于 JavaScript 中时，我们使用`external`。`external`绑定类似于`let`，因为它可以在后续代码中使用。与`let`不同，`external`通常伴有 BuckleScript 装饰器，如`[@bs.val]`。

# 理解[@bs.val]装饰器

我们可以使用`[@bs.val]`绑定全局值和函数。一般来说，语法如下：

```js
[@bs.val] external alert: string => unit = "alert";
```

+   BuckleScript 的一个或多个装饰器（即`[@bs.val]`）

+   `external`关键字

+   绑定的命名引用

+   类型声明

+   等号

+   一个字符串

`external`关键字将`alert`绑定到类型为`string => unit`的值，并绑定到字符串`alert`。字符串`alert`是上述外部声明的值，也是编译输出中要使用的值。当外部绑定的名称等于其字符串值时，字符串可以留空：

```js
[@bs.val] external alert: string => unit = "";
```

使用绑定就像使用任何其他绑定一样：

```js
alert("hi!");
```

# 理解[@bs.scope]装饰器

要绑定到`window.location.pathname`，我们使用`[@bs.scope]`添加一个作用域。这为`[@bs.val]`定义了作用域。例如，如果要绑定到`window.location`的`pathname`属性，可以指定作用域为`[@bs.scope ("window", "location")]`：

```js
[@bs.val] [@bs.scope ("window", "location")] external pathname: string = "";
```

或者，我们可以只使用`[@bs.val]`在字符串中包含作用域：

```js
[@bs.val] external pathname: string = "window.location.pathname";
```

# 理解[@bs.send]装饰器

`[@bs.send]`装饰器用于绑定对象的方法和属性。使用`[@bs.send]`时，第一个参数始终是对象。如果有剩余的参数，它们将被应用于对象的方法：

```js
[@bs.val] external document: Dom.document = "";
[@bs.send] external getElementById: (Dom.document, string) => Dom.element = "";
let element = getElementById(document, "root");
```

`Dom`模块也由 BuckleScript 提供，并为 DOM 提供类型声明。

Dom 模块文档可以在这里找到：

[`bucklescript.github.io/bucklescript/api/Dom.html`](https://bucklescript.github.io/bucklescript/api/Dom.html)

还有一个用于 Node.js 的 Node 模块：

[`bucklescript.github.io/bucklescript/api/Node.html`](https://bucklescript.github.io/bucklescript/api/Node.html)

在编写外部声明时要小心，因为您可能会意外地欺骗类型系统，这可能导致运行时类型错误。例如，我们告诉 Reason 我们的`getElementById`绑定总是返回`Dom.element`，但是当 DOM 找不到提供的 ID 的元素时，它返回`undefined`。更正确的绑定应该是这样的：

```js
[@bs.send] external getElementById: (Dom.document, string) => option(Dom.element) = "";
```

# 理解[@bs.module]装饰器

要导入一个节点模块，使用`[@bs.module]`。编译输出取决于`bsconfig.json`中使用的`package-specs`配置。我们使用`es6`作为模块格式。

```js
[@bs.module] external leftPad: (string, int) => string = "left-pad";
let result = leftPad("foo", 6);
```

这编译成以下内容：

```js
import * as LeftPad from "left-pad";

var result = LeftPad("foo", 6);

export {
  result ,
}
```

将模块格式设置为`commonjs`会产生以下编译输出：

```js
var LeftPad = require("left-pad");

var result = LeftPad("foo", 6);

exports.result = result;
```

当`[@bs.module]`没有字符串参数时，默认值被导入。

# 合理的 API

在绑定到现有的 JavaScript API 时，考虑一下你想在 Reason 中如何使用 API。即使是依赖于 JavaScript 动态类型的现有 JavaScript API 也可以在 Reason 中使用。BuckleScript 利用了高级类型系统技术，让我们能够利用 Reason 的类型系统来使用这样的 API。

从 BuckleScript 文档中，看一下以下 JavaScript 函数：

```js
function padLeft(value, padding) {
  if (typeof padding === "number") {
    return Array(padding + 1).join(" ") + value;
  }
  if (typeof padding === "string") {
    return padding + value;
  }
  throw new Error(`Expected string or number, got '${padding}'.`);
}
```

如果我们要在 Reason 中绑定到这个函数，最好使用`padding`作为一个变体。这是我们将如何做到这一点：

```js
[@bs.val]
external padLeft: (
  string,
  [@bs.unwrap] [
    | `Str(string)
    | `Int(int)
  ])
  => string = "";

padLeft("Hello World", `Int(4));
padLeft("Hello World", `Str("Message: "));
```

这编译成了以下内容：

```js
padLeft("Hello World", 4);
padLeft("Hello World", "Message: ");
```

`padLeft`的类型是`(string, some_variant) => string`，其中`some_variant`使用了一个称为**多态变体**的高级类型系统特性，它使用`[@bs.unwrap]`来转换为 JavaScript 可以理解的内容。我们将在第五章中了解更多关于多态变体的知识，*Effective ML*。

# BuckleScript 文档

虽然这只是一个简短的介绍，但你可以看到 BuckleScript 有很多工具可以帮助我们与惯用的 JavaScript 进行交流。我强烈建议你阅读 BuckleScript 文档，以了解更多关于 JavaScript 互操作性的知识。

BuckleScript 文档可以在这里找到：

[`bucklescript.github.io/docs/interop-overview`](https://bucklescript.github.io/docs/interop-overview)

# 绑定到现有的 ReactJS 组件

ReactJS 组件不是 Reason 组件。要使用现有的 ReactJS 组件，我们使用`[@bs.module]`来导入节点模块，然后使用`ReasonReact.wrapJsForReason`辅助函数将 ReactJS 组件转换为 Reason 组件。还有一个`ReasonReact.wrapReasonForJs`辅助函数用于在 ReactJS 中使用 Reason。

让我们从第三章离开的地方继续构建我们的应用程序，*创建 ReasonReact 组件*：

```js
git clone https://github.com/PacktPublishing/ReasonML-Quick-Start-Guide.git
cd ReasonML-Quick-Start-Guide
cd Chapter03/app-end
npm install
```

在这里，我们通过绑定到现有的 React Transition Group 组件来添加路由转换：

React Transition Group 文档可以在这里找到：

[`reactcommunity.org/react-transition-group/`](https://reactcommunity.org/react-transition-group/)

# 导入依赖项

运行`npm install --save react-transition-group`来安装依赖。

让我们创建一个名为`ReactTransitionGroup.re`的新文件来存放这些绑定。在这个文件中，我们将绑定到`TransitionGroup`和`CSSTransition`组件：

```js
[@bs.module "react-transition-group"]
external transitionGroup: ReasonReact.reactClass = "TransitionGroup";

[@bs.module "react-transition-group"]
external cssTransition: ReasonReact.reactClass = "CSSTransition";
```

# 创建 make 函数

接下来，我们创建组件所需的`make`函数。这是我们使用`ReasonReact.wrapJsForReason`辅助函数的地方。

对于`TransitionGroup`，我们不需要任何 props。由于`~props`参数是必需的，我们传递`Js.Obj.empty()`。`~reactClass`参数传递了我们在上一步中创建的外部绑定：

```js
module TransitionGroup = {
  let make = children =>
    ReasonReact.wrapJsForReason(
      ~reactClass=transitionGroup,
      ~props=Js.Obj.empty(),
      children,
    );
};
```

现在，`ReactTransitionGroup.TransitionGroup`是一个可以在我们的应用程序中使用的 ReasonReact 组件。

# 使用[@bs.deriving abstract]

`CSSTransitionGroup`将需要以下 props：

+   `_in`

+   `timeout`

+   `classNames`

由于`in`是 Reason 中的保留字，惯例是在 Reason 中使用`_in`，并让 BuckleScript 将其编译为 JavaScript 中的`in`，使用`[@bs.as "in"]`。

BuckleScript 提供了`[@bs.deriving abstract]`，可以轻松地处理某些类型的 JavaScript 对象。我们可以直接使用 BuckleScript 创建对象，而不是在 JavaScript 中创建对象并绑定到该对象：

```js
[@bs.deriving abstract]
type cssTransitionProps = {
  [@bs.as "in"] _in: bool,
  timeout: int,
  classNames: string,
};
```

注意：`cssTransitionProps`不是一个记录类型，它只是看起来像一个。

当使用`[@bs.deriving abstract]`时，会自动提供一个辅助函数来创建具有该形状的 JavaScript 对象。这个辅助函数也被命名为`cssTransitionProps`。我们在组件的`make`函数中使用这个辅助函数来创建组件的 props：

```js
module CSSTransition = {
  let make = (~_in: bool, ~timeout: int, ~classNames: string, children) =>
    ReasonReact.wrapJsForReason(
      ~reactClass=cssTransition,
      ~props=cssTransitionProps(~_in, ~timeout, ~classNames),
      children,
    );
};
```

# 使用组件

现在，在`App.re`中，我们可以改变渲染函数来使用这些组件。我们将改变这个：

```js
<main> {currentRoute.component} </main>
```

现在它看起来是这样的：

```js
<main>
  ReactTransitionGroup.(
    <TransitionGroup>
      <CSSTransition
        key={currentRoute.title} _in=true timeout=900 classNames="routeTransition">
        {currentRoute.component}
      </CSSTransition>
    </TransitionGroup>
  )
</main>
```

注意：key 属性是一个特殊的 ReactJS 属性，不应该是组件 props 参数的一部分在`ReasonReact.wrapJsForReason`中。对于特殊的 ReactJS ref 属性也是如此。

为了完整起见，以下是相应的 CSS，可以在`ReactTransitionGroup.scss`中找到：

```js
@keyframes enter {
  from {
    opacity: 0;
    transform: translateY(50px);
  }
}

@keyframes exit {
  to {
    opacity: 0;
    transform: translateY(50px);
  }
}

.routeTransition-enter.routeTransition-enter-active {
  animation: enter 500ms ease 400ms both;
}

.routeTransition-exit.routeTransition-exit-active {
  animation: exit 400ms ease both;
}
```

请确保在`ReactTransitionGroup.re`中要求前述内容：

```js
/* ReactTransitionGroup.re */
[@bs.val] external require: string => string = "";
require("../../../src/ReactTransitionGroup.scss");
```

现在，当改变路由时，旧路由的内容会向下动画并淡出，然后新路由的内容会向上动画并淡入。

# 摘要

BuckleScript 非常强大，因为它让我们以一种非常愉快的方式与惯用的 JavaScript 进行交互。它还提供了 Belt 标准库，这是为 JavaScript 而创建的。我们学习了数组和列表，看到了在 Reason 中如何轻松地使用现有的 ReactJS 组件。

在第五章 *Effective ML*中，我们将学习如何使用模块签名来隐藏组件的实现细节，同时构建一个自动完成输入组件。我们将首先使用硬编码数据，然后在第六章 *CSS-in-JS (in Reason)*中，我们将把数据移到`localStorage`（客户端 Web 存储）。


# 第五章：有效的 ML

到目前为止，我们已经学习了 Reason 的基础知识。我们已经看到，拥有健壮的类型系统可以使重构变得更加安全，减轻压力。在更改实现细节时，类型系统会有用地提醒我们需要更新代码库的其他部分。在本章中，我们将学习如何隐藏实现细节，使重构变得更加容易。通过隐藏实现细节，我们保证更改它们不会影响代码库的其他部分。

我们还将学习类型系统如何帮助我们在应用程序中强制执行业务规则。隐藏实现细节还为我们提供了一种通过保证模块不被用户滥用来强制执行业务规则的好方法。我们将通过本章中包含在本书的 GitHub 存储库中的简单代码示例来阐明这一点。

要跟着做，请从`Chapter05/app-start`开始。这些示例与我们一直在构建的应用程序隔离开来。

您可以使用以下方式转到本书的 GitHub 存储库：

```js
git clone https://github.com/PacktPublishing/ReasonML-Quick-Start-Guide.git
cd ReasonML-Quick-Start-Guide
cd Chapter05/app-start
npm install
```

记住，所有模块都是全局的，模块的所有类型和绑定默认情况下都是公开的。正如我们将很快看到的，模块签名可以用来隐藏模块的类型和/或绑定，使其对其他模块不可见。在本章中，我们还将学习高级类型系统功能，包括以下内容：

+   抽象类型

+   幻影类型

+   多态变体

# 模块签名

模块签名约束模块的方式类似于接口约束面向对象编程中的类。模块签名可以要求模块实现特定类型和绑定，还可以用于隐藏实现细节。假设我们有一个名为`Foo`的模块，在`Foo.re`中定义。它的签名可以在`Foo.rei`中定义。如果模块签名存在并且该类型或绑定不在模块签名中，则模块中列出的任何类型或绑定都将被隐藏。在`Foo.re`中有一个绑定`let foo = "foo";`，该绑定可以通过其模块签名要求和暴露，方法是在`Foo.rei`中包括`let foo: string;`：

```js
/* Foo.re */
let foo = "foo";

/* Foo.rei */
let foo: string;

/* Bar.re */
Js.log(Foo.foo);
```

在这里，`Foo.rei`要求`Foo.re`有一个名为`foo`的`string`类型的`let`绑定。

如果模块的`.rei`文件存在且为空，则模块中的所有内容都被隐藏，如下面的代码所示：

```js
/* Foo.rei */
/* this is intentionally empty */

/* Bar.re */
Js.log(Foo.foo); /* Compilation error: The value foo can't be found in Foo */
```

模块的签名要求模块包括签名中列出的任何类型和/或绑定，如下面的代码所示：

```js
/* Foo.re */
let foo = "foo";

/* Foo.rei */
let foo: string;
let bar: string;
```

这导致以下编译错误，因为模块签名要求`bar`绑定为`string`类型，而模块中未定义：

```js
The implementation src/Foo.re does not match the interface src/Foo.rei:
The value `bar' is required but not provided
```

# 模块类型

模块签名也可以使用`module type`关键字来定义，而不是使用单独的`.rei`文件。模块类型必须以大写字母开头。一旦定义，模块可以使用`module <Name> : <Type>`语法来受模块类型的约束，如下所示：

```js
module type FooT {
  let foo: (~a: int, ~b: int) => int;
};

module Foo: FooT {
  let foo = (~a, ~b) => a + b;
};
```

相同的模块类型可以用于多个模块，如下所示：

```js
module Bar: FooT {
  let bar = (~a, ~b) => a - b;
};
```

我们可以将模块签名视为面向对象意义上的接口。接口定义了模块必须定义的属性和方法。然而，在 Reason 中，模块签名还隐藏了绑定和类型。但模块签名最有用的功能之一可能是暴露抽象类型的能力。

# 抽象类型

抽象类型是没有定义的类型声明。让我们探讨一下为什么这会有用。除了绑定，模块签名还可以包括类型。在下面的代码中，您会注意到`Foo`的模块签名包括一个`person`类型，现在`Foo`必须包括这个`type`声明：

```js
/* Foo.re */
type person = {
  firstName: string,
  lastName: string
};

/* Foo.rei */
type person = {
  firstName: string,
  lastName: string
};
```

`person`类型的暴露方式与没有定义模块签名时的方式相同。正如你所期望的，如果定义了签名并且类型未列出，那么该类型不会暴露给其他模块。还有将类型保持抽象的选项。我们只保留等号后面的部分。让我们看看下面的代码：

```js
/* Foo.rei */
type person;
```

现在，`person`类型对其他模块是可见的，但没有其他模块可以直接创建或操纵`person`类型的值。`person`类型需要在`Foo`中定义，但可以有任何定义。这意味着`person`类型可以随时间改变，而`Foo`之外的模块永远不会知道这一点。

让我们在下一节进一步探讨抽象类型。

# 使用模块签名

假设我们正在构建一个发票管理系统，我们有一个`Invoice`模块，定义了一个`invoice`类型以及其他模块可以使用的函数来创建该类型的值。这种安排如下所示：

```js
/* Invoice.re */
type t = {
  name: string,
  email: string,
  date: Js.Date.t,
  total: float
};

let make = (~name, ~email, ~date, ~total) => {
  name,
  email,
  date,
  total
};
```

假设我们还有另一个模块负责向客户发送电子邮件，如下面的代码所示：

```js
/* Email.re */
let send = invoice: Invoice.t => ...
let invoice =
  Invoice.make(
    ~name="Raphael",
    ~email="persianturtle@gmail.com",
    ~date=Js.Date.make(),
    ~total=15.0,
  );
send(invoice);
```

由于`Invoice.t`类型是公开的，所以发票可以被`Email`操纵，如下面的代码所示：

```js
/* Email.re */
let invoice =
  Invoice.make(
    ~name="Raphael",
    ~email="persianturtle@gmail.com",
    ~date=Js.Date.make(),
    ~total=15.0,
  );
let invoice = {...invoice, total: invoice.total *. 0.8};
Js.log(invoice);
```

尽管`Invoice.t`类型是不可变的，但没有阻止`Email`用一些改变的字段来遮蔽发票绑定。然而，如果我们将`Invoice.t`类型设为抽象，这将是不可能的，因为`Email`将无法操纵抽象类型。`Email`模块可以访问的任何函数都无法与`Invoice.t`类型一起使用。

```js
/* Invoice.rei */
type t;
let make:
 (~name: string, ~email: string, ~date: Js.Date.t, ~total: float) => t;
```

现在，编译给我们带来了以下错误：

```js
8 │ let invoice = {...invoice, total: invoice.total *. 0.8};
9 │ Js.log(invoice);

The record field total can't be found.
```

如果我们决定允许其他模块向发票添加折扣，我们需要创建一个函数并将其包含在`Invoice`的模块签名中。假设我们只想允许每张发票只有一个折扣，并且还限制折扣金额为十、十五或二十个百分比。我们可以以以下方式实现这一点：

```js
/* Invoice.re */
type t = {
 name: string,
 email: string,
 date: Js.Date.t,
 total: float,
 isDiscounted: bool,
};

type discount =
 | Ten
 | Fifteen
 | Twenty;

let make = (~name, ~email, ~date, ~total) => {
 name,
 email,
 date,
 total,
 isDiscounted: false,
};

let discount = (~invoice, ~discount) =>
 if (invoice.isDiscounted) {
 invoice;
 } else {
 {
 ...invoice,
 isDiscounted: true,
 total:
 invoice.total
 *. (
 switch (discount) {
 | Ten => 0.9
 | Fifteen => 0.85
 | Twenty => 0.8
 }
 ),
 };
 };

/* Invoice.rei */
type t;

type discount =
 | Ten
 | Fifteen
 | Twenty;

let make:
 (~name: string, ~email: string, ~date: Js.Date.t, ~total: float) => t;

let discount: (~invoice: t, ~discount: discount) => t;

/* Email.re */
let invoice =
 Invoice.make(
 ~name="Raphael",
 ~email="persianturtle@gmail.com",
 ~date=Js.Date.make(),
 ~total=15.0,
 );
Js.log(invoice);
```

现在，只要`Invoice`模块的公共 API（或模块签名）不改变，我们就可以自由地重构`Invoice`模块，而不需要担心在其他模块中破坏代码。为了证明这一点，让我们将`Invoice.t`重构为元组而不是记录，如下面的代码所示。只要我们不改变模块签名，`Email`模块就不需要做任何改变：

```js
/* Invoice.re */
type t = (string, string, Js.Date.t, float, bool);

type discount =
  | Ten
  | Fifteen
  | Twenty;

let make = (~name, ~email, ~date, ~total) => (
  name,
  email,
  date,
  total,
  false,
);

let discount = (~invoice, ~discount) => {
  let (name, email, date, total, isDiscounted) = invoice;
  if (isDiscounted) {
    invoice;
  } else {
    (
      name,
      email,
      date,
      total
      *. (
        switch (discount) {
        | Ten => 0.9
        | Fifteen => 0.85
        | Twenty => 0.8
        }
      ),
      true,
    );
  };
};

/* Invoice.rei */
type t;

type discount =
  | Ten
  | Fifteen
  | Twenty;

let make:
  (~name: string, ~email: string, ~date: Js.Date.t, ~total: float) => t;

let discount: (~invoice: t, ~discount: discount) => t;

/* Email.re */
let invoice =
  Invoice.make(
    ~name="Raphael",
    ~email="persianturtle@gmail.com",
    ~date=Js.Date.make(),
    ~total=15.0,
  );
let invoice = Invoice.(discount(~invoice, ~discount=Ten));
Js.log(invoice);
```

另外，由于`Invoice.t`抽象类型，我们保证发票只能打折一次，并且只能按指定的百分比打折。我们可以通过要求对发票的所有更改都进行日志记录来进一步举例。传统上，这种要求会通过在数据库事务之后添加副作用来解决，因为在 JavaScript 中，我们无法确定是否会记录所有对发票的更改。使用模块签名，我们可以选择在应用层解决这些要求。

# 幻影类型

看看我们之前的实现，如果我们不必在运行时检查发票是否已经打折，那将是很好的。有没有一种方法可以在编译时检查发票是否已经打折？使用幻影类型，我们可以。

幻影类型是具有类型变量的类型，但这个类型变量在其定义中没有被使用。为了更好地理解，让我们再次看看`option`类型，如下面的代码所示：

```js
type option('a) =
  | None
  | Some('a);
```

`option`类型有一个类型变量`'a`，并且类型变量在其定义中被使用。正如我们已经学到的，`option`是一种多态类型，因为它有一个类型变量。另一方面，幻影类型在其定义中不使用类型变量。让我们看看这在我们的发票管理示例中是如何有用的。

让我们将`Invoice`模块的签名更改为使用幻影类型，如下所示：

```js
/* Invoice.rei */
type t('a);

type discounted;
type undiscounted;

type discount =
  | Ten
  | Fifteen
  | Twenty;

let make:
  (~name: string, ~email: string, ~date: Js.Date.t, ~total: float) =>
  t(undiscounted);

let discount:
  (~invoice: t(undiscounted), ~discount: discount) => t(discounted);
```

抽象类型`t`现在是`type t('a)`。我们还有两个更多的抽象类型，如下面的代码所示：

```js
type discounted;
type undiscounted;
```

还要注意，`make`函数现在返回`t(undiscounted)`（而不仅仅是`t`），`discount`函数现在接受`t(undiscounted)`并返回`t(discounted)`。记住，抽象`t('a)`接受一个`type`变量，而`type`变量恰好是`discounted`类型或`undiscounted`类型。

在实现中，我们现在可以摆脱之前的运行时检查，如下面的代码所示：

```js
if (isDiscounted) {
  ...
} else {
  ...
}
```

现在，这个检查是在编译时进行的，因为`discount`函数只接受`undiscounted`发票，如下面的代码所示：

```js
/* Invoice.re */
type t('a) = {
  name: string,
  email: string,
  date: Js.Date.t,
  total: float,
};

type discount =
  | Ten
  | Fifteen
  | Twenty;

let make = (~name, ~email, ~date, ~total) => {name, email, date, total};

let discount = (~invoice, ~discount) => {
  ...invoice,
  total:
    invoice.total
    *. (
      switch (discount) {
      | Ten => 0.9
      | Fifteen => 0.85
      | Twenty => 0.8
      }
    ),
};
```

这只是类型系统可以帮助我们更多地关注逻辑而不是错误处理的另一种方式。以前，尝试两次打折发票只会返回原始发票。现在，让我们尝试在`Email.re`中两次打折发票，使用以下代码：

```js
/* Email.re */
let invoice =
  Invoice.make(
    ~name="Raphael",
    ~email="persianturtle@gmail.com",
    ~date=Js.Date.make(),
    ~total=15.0,
  );
let invoice = Invoice.(discount(~invoice, ~discount=Ten));
let invoice = Invoice.(discount(~invoice, ~discount=Ten)); /* discounted twice */
Js.log(invoice);
```

现在，尝试两次打折发票将导致一个可爱的编译时错误，如下所示：

```js
We've found a bug for you!

   7 │ );
   8 │ let invoice = Invoice.(discount(~invoice, ~discount=Ten));
   9 │ let invoice = Invoice.(discount(~invoice, ~discount=Ten));
  10 │ Js.log(invoice);

  This has type:
    Invoice.t(Invoice.discounted)
  But somewhere wanted:
    Invoice.t(Invoice.undiscounted)
```

这绝对美丽。然而，假设你想能够给任何发票发送电子邮件，无论是否打折。我们使用幻影类型会导致问题吗？我们如何编写一个接受任何发票类型的函数？我们的发票类型是`Invoice.t('a)`，如果我们想接受任何发票，我们保留类型参数，如下面的代码所示：

```js
/* Email.re */
let invoice =
  Invoice.make(
    ~name="Raphael",
    ~email="persianturtle@gmail.com",
    ~date=Js.Date.make(),
    ~total=15.0,
  );

let send: Invoice.t('a) => unit = invoice => {
 /* send invoice email */
 Js.log(invoice);
};

send(invoice);
```

所以我们可以两全其美。

# 多态变体

我们已经在上一章简要地看过多态变体。简而言之，我们在使用`[@bs.unwrap]`装饰器绑定到一些现有的 JavaScript 时学到了它们。这个想法是`[@bs.unwrap]`可以用于绑定到现有的 JavaScript 函数，其中它的参数可以是不同的类型。例如，假设我们想绑定到以下函数：

```js
function dynamic(a) {
  switch (typeof a) {
    case "string":
      return "String: " + a;
    case "number":
      return "Number: " + a;
  }
}
```

假设这个函数只接受`string`类型或`int`类型的参数，不接受其他类型。我们可以这样绑定这个示例函数：

```js
[@bs.val] external dynamic : 'a => string = "";
```

然而，我们的绑定将允许无效的参数类型（如`bool`）。如果我们的编译器能够通过阻止无效的参数类型来帮助我们，那将更好。其中一种方法是使用多态变体与`[@bs.unwrap]`。我们的绑定将如下所示：

```js
[@bs.val] external dynamic : ([@bs.unwrap] [
  | `Str(string)
  | `Int(int)
]) => string = "";
```

我们会这样使用绑定：

```js
dynamic(`Int(42));
dynamic(`Str("foo"));
```

现在，如果我们尝试传递无效的参数类型，编译器会让我们知道，如下面的代码所示：

```js
dynamic(42);

/*
We've found a bug for you!

This has type:
  int
But somewhere wanted:
  [ `Int of int | `Str of string ]
*/
```

这里的折衷是我们需要通过将参数包装在多态变体构造函数中而不是直接传递参数。

一开始，你会注意到普通变体和多态变体之间的以下两个不同之处：

1.  我们不需要显式声明多态变体的类型

1.  多态变体以反引号字符（`` ` ``）

每当您看到一个以反勾号字符为前缀的构造函数时，您就知道它是一个多态变体构造函数。可能有也可能没有与多态变体构造函数相关联的类型声明。

# 这对正常变体有效吗？

让我们试着用普通变体来做这件事，看看会发生什么:

```js
type validArgs = 
  | Int(int)
  | Str(string);

[@bs.val] external dynamic : validArgs => string = "";

dynamic(Int(1));
```

前面实现的问题是`Int(1)`不会编译为 JavaScript 数字。普通变体编译为`array`，我们的`dynamic`函数返回`undefined`而不是`"Number: 42"`。函数返回`undefined`是因为在 switch 语句上没有匹配到任何情况。

使用多态变体，BuckleScript 将`dynamic(`Int(42))`编译为`dynamic(42)`，函数按预期工作。

# 高级类型系统特性

Reason 的类型系统非常全面，并在过去的几十年中得到了完善。到目前为止，我们所看到的只是对 Reason 类型系统的介绍。在我看来，你应该在继续学习更高级的类型系统功能之前熟悉基础知识。没有经历过合理的类型系统本应阻止的错误，很难欣赏诸如类型安全之类的东西。没有对到目前为止在本书中学到的内容感到略微沮丧，很难欣赏高级类型系统功能。本书的范围不包括对高级类型系统功能进行过多详细讨论，但我想确保那些正在评估 Reason 作为一个选项的人知道它的类型系统还有更多内容。

除了幻影类型和多态变体之外，Reason 还具有**广义代数数据类型**（**GADTs**）。模块可以使用函数器（即，在编译时和运行时之间操作的模块函数）动态创建。Reason 还具有类和对象——OCaml 中的 O 代表 objective。OCaml 的前身是一种称为 Caml 的语言，最早出现在 20 世纪 80 年代中期。到目前为止，在本书中学到的东西在典型的 React 应用程序的上下文中特别有用。就我个人而言，我喜欢 Reason 是一种我可以在其中不断成长并保持高效的语言。

如果你发现自己对类型系统感到沮丧，那么可以在 Discord 频道上寻求专家的帮助，有人很可能会帮助你解决问题。我对社区的乐于助人感到不断惊讶。而且不要忘记，如果你只是想继续前进，你总是可以转到原始的 JavaScript，如果需要的话，等你准备好了再回来解决问题。

你可以在这里找到 Reason 的 Discord 频道：

[`discord.gg/reasonml`](https://discord.gg/reasonml)

不使用 Reason 类型系统的更高级功能也是完全有效的。到目前为止，我们所学到的内容在为我们的 React 应用程序添加类型安全方面提供了很大的价值。

# 总结

到目前为止，我们已经看到 Reason 如何帮助我们使用其类型系统构建更安全、更易维护的代码库。变体允许我们使无效状态不可表示。类型系统有助于使重构过程变得不那么可怕、不那么痛苦。模块签名可以帮助我们强制执行应用程序中的业务规则。模块签名还可以作为基本文档，列出模块公开的内容，并根据公开的函数名称和其参数类型以及公开的类型，给出模块的基本使用方式的概念。

在第六章中，*CSS-in-JS（在 Reason 中）*，我们将看看如何使用 Reason 的类型系统来强制执行有效的 CSS，使用一个包装 Emotion（[`emotion.sh`](https://emotion.sh)）的 CSS-in-Reason 库，名为`bs-css`。


# 第六章：CSS-in-JS（在 Reason 中）

React 的一个很棒的特性是它让我们将组件的标记、行为和样式放在一个文件中。这种集合对开发人员的体验、版本控制和代码质量有着连锁反应（无意冒犯）。在本章中，我们将简要探讨 CSS-in-JS 是什么，以及我们如何在 Reason 中处理 CSS-in-JS。当然，如果您喜欢的话，可以完全将组件分开放在不同的文件中，或者使用更传统的 CSS 解决方案。

在本章中，我们将讨论以下主题：

+   什么是 CSS-in-JS？

+   使用`styled-components`

+   使用`bs-css`

# 什么是 CSS-in-JS？

定义 CSS-in-JS 目前是 JavaScript 社区中一个极具争议的话题。CSS-in-JS 诞生于组件时代。现代 Web 主要是基于组件模型构建的。几乎所有的 JavaScript 框架都已经接受了它。随着它的采用增加，越来越多的团队开始同时在同一个项目的各个组件上工作。想象一下，您正在一个分布式团队中开发一个大型应用程序，每个团队都在并行开发一个组件。如果没有团队统一 CSS 约定，您将遇到 CSS 作用域问题。如果没有某种类型的标准化的 CSS 样式指南，多个团队很容易会为一个类名设置样式，从而影响其他意外的组件。随着时间的推移，出现了许多解决这个问题和其他与规模有关的 CSS 问题的解决方案。

# 简史

一些流行的 CSS 约定包括 BEM、SMACSS 和 OOCSS。这些解决方案都要求开发人员学习约定并正确应用它们；否则，仍然可能出现令人沮丧的作用域问题。

CSS 模块成为了一个更安全的选择，开发人员可以将 CSS 导入到 JavaScript 模块中，构建步骤会自动将 CSS 局部范围限制在该 JavaScript 模块中。CSS 本身仍然是在普通的 CSS（或 SASS）文件中编写的。

CSS-in-JS 更进一步，允许您直接在 JavaScript 模块中编写 CSS，并自动将 CSS 局部范围限制在组件中。这对许多开发人员来说是正确的；其他人从一开始就不喜欢它。一些 CSS-in-JS 解决方案，如`styled-components`，允许开发人员直接将 CSS 与组件耦合在一起。您可以使用`<Header />`而不是`<header className="..." />`，其中`Header`组件是使用`styled-components`定义的，以及其 CSS，如下面的代码所示：

```js
import React from 'react';
import styled from 'styled-components';

const Header = styled.header`
  font-size: 1.5em;
  text-align: center;
  color: dodgerblue;
`;
```

曾经`styled-components`存在性能问题，因为 JavaScript 包必须在库能够在 DOM 中动态创建样式表之前下载、编译和执行。这些问题现在在很大程度上得到了解决，这要归功于服务器端渲染的支持。那么，在 Reason 中我们能做到这一点吗？让我们来看看！

# 使用 styled-components

`styled-components`最受欢迎的功能之一是根据组件的 props 动态创建 CSS 的能力。使用此功能的一个原因是创建组件的备用版本。然后这些备用版本将被封装在样式化组件本身内。以下是一个`<Title />`的示例，其中文本可以居中或左对齐，也可以选择是否加下划线。

```js
const Title = styled.h1`
  text-align: ${props => props.center ? "center" : "left"};
  text-decoration: ${props => props.underline ? "underline" : "none"};
  color: white;
  background-color: coral;
`;

render(
  <div>
    <Title>I'm Left Aligned</Title>
    <Title center>I'm Centered!</Title>
    <Title center underline>I'm Centered & Underlined!</Title>
  </div>
);
```

在 Reason 的背景下，挑战在于通过`style-components`API 创建一个可以动态处理 props 的组件。考虑`styled.h1`函数的以下绑定和我们的`<Title />`组件。

```js
/* StyledComponents.re */
[@bs.module "styled-components"] [@bs.scope "default"] [@bs.variadic]
external h1: (array(string), array('a)) => ReasonReact.reactClass = "h1";

module Title = {
  let title =
    h1(
      [|
        "text-align: ",
        "; text-decoration: ",
        "; color: white; background-color: coral;",
      |],
      [|
        props => props##center ? "center" : "left",
        props => props##underline ? "underline" : "none",
      |],
    );

  [@bs.deriving abstract]
  type jsProps = {
    center: bool,
    underline: bool,
  };

  let make = (~center=false, ~underline=false, children) =>
    ReasonReact.wrapJsForReason(
      ~reactClass=title,
      ~props=jsProps(~center, ~underline),
      children,
    );
};
```

`h1`函数接受一个字符串数组作为其第一个参数，以及一个表达式数组作为其第二个参数。这是因为这是 ES6 标记模板字面量的 ES5 表示。在`h1`函数的情况下，表达式数组是传递给 React 组件的 props 的函数。

我们使用 `[@bs.variadic]` 装饰器来允许任意数量的参数。在 Reason 中，我们使用数组，在 JavaScript 中，该数组会被扩展为任意数量的参数。

# 使用 [@bs.variadic]

让我们稍微偏离一下，进一步探索 `[@bs.variadic]`。假设你想要绑定 `Math.max()`，它可以接受一个或多个参数：

```js
/* JavaScript */
Math.max(1, 2);
Math.max(1, 2, 3, 4);
```

这是 `[@bs.variadic]` 的一个完美案例。我们在 Reason 中使用数组来保存参数，并且该数组将会被扩展以匹配 JavaScript 中的上述语法。

```js
/* Reason */
[@bs.scope "Math"][@bs.val][@bs.variadic] external max: array('a) => unit = "";
max([|1, 2|]);
max([|1, 2, 3, 4|]);
```

好的，我们回到了 `styled-components` 的例子。我们可以像下面这样使用 `<Title />` 组件：

```js
/* Home.re */
let component = ReasonReact.statelessComponent("Home");

let make = _children => {
  ...component,
  render: _self =>
    <StyledComponents.Title center=true underline=true>
 {ReasonReact.string("Page1")}
 </StyledComponents.Title>,
};
```

上面的代码是一个带有样式的 ReasonReact 组件，它渲染了一个带有一些 CSS 的 `h1`。CSS 在之前在 `StyledComponents.Title` 模块中定义。`<Title />` 组件有两个属性——center 和 underline——默认值都是 `false`。

当然，这不是编写样式组件的优雅方式，但在功能上与 JavaScript 版本相似。另一个选择是回到原始的 JavaScript 中，以利用熟悉的标记模板文字语法。让我们在 `Title.re` 中举个例子。

```js
/* Title.re */
%bs.raw
{|const styled = require("styled-components").default|};

let title = [%bs.raw
  {|
     styled.h1`
       text-align: ${props => props.center ? "center" : "left"};
       text-decoration: ${props => props.underline ? "underline" : "none"};
       color: white;
       background-color: coral;
     `
   |}
];

[@bs.deriving abstract]
type jsProps = {
  center: bool,
  underline: bool,
};

let make = (~center=false, ~underline=false, children) =>
  ReasonReact.wrapJsForReason(
    ~reactClass=title,
    ~props=jsProps(~center, ~underline),
    children,
  );
```

使用方式类似，只是现在 `<Title />` 组件不再是 `StyledComponents` 的子模块。

```js
/* Home.re */
let component = ReasonReact.statelessComponent("Home");

let make = _children => {
  ...component,
  render: _self =>
    <Title center=true underline=true> {ReasonReact.string("Page1")} </Title>,
};
```

就我个人而言，我喜欢使用 `[%bs.raw]` 版本时的开发体验。我想要为 Adam Coll（`@acoll1`）提供的 `styled-components` 绑定的两个版本鼓掌。我也很期待看看社区会有什么新的东西。

现在让我们来探索社区中最受欢迎的 CSS-in-JS 解决方案：`bs-css`。

# 使用 bs-css

虽然 Reason 团队没有对 CSS-in-JS 解决方案做出官方推荐，但目前许多人正在使用一个名为 `bs-css` 的库，它包装了 emotion CSS-in-JS 库（版本 9）。`bs-css` 库为在 Reason 中使用提供了类型安全的 API。通过这种方式，我们可以让编译器检查我们的 CSS。我们将通过转换我们在第三章中创建的 `App.scss` 来感受一下这个库。

要跟着做，克隆本书的 GitHub 仓库，并从 `Chapter06/app-start` 开始使用以下代码：

```js
git clone https://github.com/PacktPublishing/ReasonML-Quick-Start-Guide.git
cd ReasonML-Quick-Start-Guide
cd Chapter06/app-start
npm install
```

要开始使用 `bs-css`，我们将在 `package.json` 和 `bsconfig.json` 中将其包含为依赖项，如下所示：

```js
/* bsconfig.json */
...
"bs-dependencies": ["reason-react", "bs-css"],
...
```

通过 npm 安装 `bs-css` 并配置 `bsconfig.json` 后，我们将可以访问库提供的 `Css` 模块。通常的做法是定义自己的子模块叫做 `Styles`，在那里我们打开 `Css` 模块并编写所有的 CSS-in-Reason。由于我们将要转换 `App.scss`，我们将在 `App.re` 中声明一个 `Styles` 子模块，如下所示：

```js
/* App.re */

...
let component = ReasonReact.reducerComponent("App");

module Styles = {
  open Css;
};
...
```

现在，让我们转换以下的 Sass：

```js
.App {
  min-height: 100vh;

  &:after {
    content: "";
    transition: opacity 450ms cubic-bezier(0.23, 1, 0.32, 1),
      transform 0ms cubic-bezier(0.23, 1, 0.32, 1) 450ms;
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    background-color: rgba(0, 0, 0, 0.33);
    transform: translateX(-100%);
    opacity: 0;
    z-index: 1;
  }

  &.overlay {
    &:after {
      transition: opacity 450ms cubic-bezier(0.23, 1, 0.32, 1);
      transform: translateX(0%);
      opacity: 1;
    }
  }
}
```

在 `Styles` 中，我们声明了一个叫做 `app` 的绑定，它将在 `<App />` 组件的 `className` 属性中使用。我们将绑定到一个叫做 `style` 的 `bs-css` 函数的结果。`style` 函数接受一系列 CSS 规则。让我们使用以下代码来探索语法：

```js
module Styles = {
  open Css;

  let app = style([
    minHeight(vh(100.)),
  ]);
};
```

一开始有点奇怪，但你使用得越多，它就会感觉越好。所有的 CSS 属性和单位都是函数。这些函数有类型。如果类型不匹配，编译器会报错。考虑以下无效的 CSS：

```js
min-height: red;
```

这在 CSS、Sass 甚至 `styled-components` 中都会悄悄失败。使用 `bs-css`，我们至少可以防止大量无效的 CSS。编译器还会通知我们任何未使用的绑定，这有助于我们维护 CSS 样式表，而且通常我们还有完整的智能感知，这有助于我们在学习 API 的过程中。

就我个人而言，我非常喜欢通过 Sass 嵌套 CSS，并且我很高兴我们可以用`bs-css`做同样的事情。为了嵌套`:after`伪选择器，我们使用`after`函数。为了嵌套`.overlay`选择器，我们使用`selector`函数。就像在 Sass 中一样，我们使用`&`符号来引用父元素，如下面的代码所示：

```js
module Styles = {
  open Css;

  let app =
    style([
      minHeight(vh(100.)),

      after([
 contentRule(""),
 transitions([
 `transition("opacity 450ms cubic-bezier(0.23, 1, 0.32, 1)"),
 `transition("transform 0ms cubic-bezier(0.23, 1, 0.32, 1) 450ms"),
 ]),
        position(fixed),
        top(zero),
        right(zero),
        bottom(zero),
        left(zero),
        backgroundColor(rgba(0, 0, 0, 0.33)),
        transform(translateX(pct(-100.))),
        opacity(0.),
        zIndex(1),
      ]),

      selector(
        "&.overlay",
        [ 
          after([
            `transition("opacity 450ms cubic-bezier(0.23, 1, 0.32, 1)"),
            transform(translateX(zero))),
            opacity(1.),
          ]),
        ],
      )
    ]);
};
```

请注意，我们正在使用多态变体``transition`来表示过渡字符串。否则过渡是无效的。

您可以在 GitHub 存储库的`Chapter06/app-end/src/App.re`文件中找到其余的转换。现在剩下的就是将样式应用到`<App />`组件的`className`属性，如下面的代码所示：

```js
/* App.re */
...
render: self =>
  <div
    className={"App " ++ Styles.app ++ (self.state.isOpen ? " overlay" : "")}
...
```

删除`App.scss`后，一切看起来基本相同。太棒了！唯一的例外是`nav > ul > li:after`选择器。在以前的章节中，我们使用内容属性来渲染图像，就像这样：

```js
content: url(./img/icon/chevron.svg);
```

根据`Css.rei`，`contentRule`函数接受一个字符串。因此，使用`url`函数不会通过类型检查，如下面的代码所示：

```js
contentRule(url("./img/icon/chevron.svg")) /* type error */
```

作为一种逃逸路线，`bs-css`提供了`unsafe`函数（如下面的代码所示），可以绕过这个问题：

```js
unsafe("content", "url('./img/icon/chevron.svg')")
```

然而，尽管我们的 webpack 配置以前将前面的图像作为依赖项引入，但在使用`bs-css`时不再这样做。

# 权衡

在 Reason 中使用 CSS-in-JS 显然是一种权衡。一方面，我们可以获得类型安全的、本地范围的 CSS，并且可以将我们的 CSS 与组件一起放置。另一方面，语法有点冗长，可能会有一些奇怪的边缘情况。选择 Sass 而不是 CSS-in-JS 解决方案是完全合理的，因为在这里没有明显的赢家。

# 其他库

我鼓励您尝试其他 CSS-in-JS Reason 库。每当您寻找 Reason 库时，您的第一站应该是 Redex (**Re**ason Package In**dex**)。

您可以在 Redex (**Re**ason Package In**dex**)找到：

[`redex.github.io/`](https://redex.github.io/)

另一个有用的资源是 Reason Discord 频道。这是一个很好的地方，可以询问各种 CSS-in-JS 解决方案及其权衡。

您可以在 Reason Discord 频道找到：

[`discord.gg/reasonml`](https://discord.gg/reasonml)

# 摘要

CSS-in-JS 仍然是相当新的，在不久的将来 Reason 社区将对其进行大量实验。在本章中，我们了解了 CSS-in-JS（在 Reason 中）的一些好处和挑战。你站在哪一边？

在第七章中，*Reason 中的 JSON*，我们将学习如何在 Reason 中处理 JSON，并了解 GraphQL 如何帮助减少样板代码，同时实现一些非常引人注目的保证。
