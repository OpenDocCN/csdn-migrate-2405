# JavaScript 反应式编程（二）

> 原文：[`zh.annas-archive.org/md5/67A6EE04B94B64CB5365BD89131EE253`](https://zh.annas-archive.org/md5/67A6EE04B94B64CB5365BD89131EE253)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：不要重复造轮子-函数式响应式编程工具

在本章中，我们将介绍一些用于在“裸金属”JavaScript 之上构建的许多优秀工具中的一些，正如上一章中简要讨论的那样。JavaScript 不仅因为其作为核心语言的特性而有趣；浏览器 JavaScript 是一个生态系统，或者说可能是多个生态系统的家园。关于函数式响应式编程的工具，总体的提供代表了一个良好、健康和庞大的集市，与之相比，仅仅使用 JavaScript 进行所有 Web 开发看起来更像是一座大教堂。我们将从这个集市中取一小部分，理解到本章并不打算涵盖所有好的、有趣的或值得的东西。在集市中做到这一点是非常困难的！

我们将介绍的工具包括以下内容：

+   ClojureScript 和 Om

+   Bacon.js

+   Brython

+   Immutable.js

+   Jest

+   Fluxxor

我们将在这样一个章节中包含或不包含的一组工具，涉及到需要划定界限和做出判断。对于更全面的处理感兴趣的读者可以查看[`tinyurl.com/reactjs-complementary-tools`](http://tinyurl.com/reactjs-complementary-tools)上的链接汇编，并深入研究他们特定关注的工具。那里有很多东西，几乎可以满足任何目的的很多宝贝。

# ClojureScript

ClojureScript，也许是 Clojure 总体上，代表了软件和 Web 开发的一个重要分水岭。ClojureScript 通过示例证明，除了 JavaScript 之外，还可以在其他语言中拥有坚实的基础和开发环境，而这种开创性的语言是一种 Lisp 方言。（这或许很合适，因为它是两种最常用的最古老的编程语言之一。Lisp 在诞生时就很好，今天仍然是一种很好的语言。）此外，与 JavaScript 相比，Lisp 可能具有很大的优势，并且由于一些相同的原因而存在。JavaScript 是 Web 浏览器的语言，而 Lisp 是 Emacs 的语言。此外，Lisp 提供了一种原始的 JavaScript；在可以用 JavaScript 编程的 Web 浏览器出现之前，可以用 Lisp 编程的 Emacs 就已经存在了，而且任何人说 Lisp 比 JavaScript 更好的话几乎不会受到质疑。

有充分的理由表明，Lisp 而不是 Emacs 默认的键绑定，是导致在互联网上流传的“经典学习曲线”漫画中的经典 Emacs 学习曲线的原因：

![ClojureScript](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04148_07_01.jpg)

正如在前面的章节中建议的那样，每个人直接在 JavaScript 中编程的统一性可能会让位于美丽的多样性，或者一块拼布。在这个美丽的拼布中，JavaScript 可能仍然是卓越的，但 JavaScript 的卓越地位可能成为新的“裸金属”。我们可能会有一系列用于前端开发的高级语言和工具。再次引用 Alan Perlis 的话，“当一个语言需要关注无关紧要的事情时，它就是低级的。”基于这些理由，JavaScript 是低级的。

这些工具中的一些可能在好的部分方面比坏的部分更好。它们可能适用于前端工作，最终仍然会在 JavaScript 中执行。但它们也可能开启前端 Web 开发，其中新的开发人员不再被告知，“这是我们将使用的语言，这是语言的一些大部分，你应该尽量避免，因为它们从根本上是有毒的。”ECMAScript（JavaScript 的正式名称，与 Emacs 没有特别的联系）的新版本可能提供更好的功能集合，但在高级语言中工作仍然是可取的，因为它们提供了更好的生产工作和结果的平台。

ClojureScript 毫不犹豫地表示，可以在浏览器上运行一个良好的高级语言，这不仅对 Lisp 黑客是个好消息。这对每个人都是好消息。它展示了在其他高级语言中进行 Web 开发的可能性，并且可能会有一个更好的 Web 开发环境，减少了沥青坑的可能性。

ClojureScript 既可以用于客户端工作，也可以在 Node.js 上用于服务器端。*Hello, World!* 如下所示：

```js
(ns nodehello
  (:require [cljs.nodejs :as nodejs]))

(defn -main [& args]
  (println (apply str (map [\space "world" "hello"] [2 0 1]))))

(nodejs/enable-util-print!)
(set! *main-cli-fn* -main)

(comment
; Compile this using a command line like:

CLOJURESCRIPT_HOME=".../clojurescript/" \
  bin/cljsc samples/nodehello.cljs {:target :nodejs} \
  > out/nodehello.js

; Then run using:
nodejs out/nodehello.js

)
```

# Om

Om 是一个包装器，使 ReactJS 可用于 ClojureScript。除了 ClojureScript 通常很快之外，Om 的某个部分实际上比 JavaScript 快大约两倍。这种差异与识别变化有关，以便在 ReactJS 执行 DOM 更新时进行最佳和适当的更新。原因是 ReactJS 在其差异算法中（通过处理可变的 JavaScript 数据结构）必须执行深度比较，以查看（纯 JavaScript）合成虚拟 DOM 中的内容是否有变化。

与直接 DOM 操作相比，这仍然非常快，以至于对大多数 ReactJS 用户来说并不是瓶颈。但在 Om 中更快。原因是 ClojureScript 像一种良好的函数式编程语言一样具有不可变数据。你可以很容易地获得某物的突变副本，但你不能篡改原始副本或使访问原始副本的任何人受到影响。这意味着 Om 只需比较顶层引用而不深入数据结构的深度就足够了。这足以使 Om 比原始的 JavaScript 使用 ReactJS 更快。在 Om 中，*Hello, World!* 是这样写的：

```js
(ns example
  (:require [om.core :as om]
            [om.dom :as dom]))

(defn widget [data owner]
  (reify
    om/IRender
    (render [this]
      (dom/h1 nil (:text data)))))

(om/root widget {:text "Hello world!"}
  {:target (. js/document (getElementById "my-app"))})
```

# Bacon.js

请注意，仅讨论 ReactJS 和 Bacon.js 并不足以构成一个详尽的列表。提到另一个替代套件，微软已经尝试创建了 RxJS、RxCpp [Rx for C++]、Rx.NET 和 Rx*，适用于各种 JavaScript 框架和库，并且他们至少尝试为多种语言和多种 JavaScript 框架和库的优化版本创建了一个多语言友好的组合。实际上有很多可用的提供某种形式的函数式响应式编程。虽然大多数（在撰写本书时）Web 上的函数式响应式编程和 ReactJS 资源都是宝贵的，但也有一些不是。

安德烈·斯塔尔兹写道：

> *“所以你对学习这个叫做响应式编程的新东西感到好奇，特别是它的变体，包括 Rx、Bacon.js、RAC 等。”*
> 
> *学习它很难，缺乏好的材料使它更加困难。当我开始时，我试图寻找教程。我只找到了少数实用指南，但它们只是皮毛，从未解决围绕它构建整个架构的挑战。当你试图理解某个函数时，库文档通常没有帮助。我是说，老实说，看看这个：*
> 
> *Rx.Observable.prototype.flatMapLatest(selector, [thisArg])*
> 
> *通过将可观察序列的每个元素投影到一个新的可观察序列中，该新序列将元素的索引合并，然后将可观察序列转换为仅从最近的可观察序列产生值的可观察序列。*

我现在明白这句引语的意思，但那是因为我从其他沟通更好的资源中学到了。你正在阅读的这本书的目的之一是让好的文档变得更容易理解一些。

在开源社区中有一个著名的问题：你会买一个发动机盖被焊死的汽车吗？ReactJS 可以被描述为大多数人可以在不打开发动机盖的情况下驾驶的汽车。这并不是说 ReactJS 是闭源的，或者 Facebook 显示出任何使其更难阅读源代码的迹象。但举一个显著的例子，**指示性连续时间语义**是 Conal Elliott 对现在称为函数式反应式编程的东西的更好名称的第二次思考的一部分。无论一个人是否同意他对更好和更具描述性名称的建议，这位领军人物的第二次思考可能非常有洞察力和启发性。而且对于 ReactJS，如果它工作正常，一个新手程序员可以得到与 Calvin 的父亲（一位专利律师！）在 Calvin and Hobbes 中给出的相同解释，当 Calvin 问一个灯或者吸尘器是如何工作的时候——*这是魔术！*看着一个新手的问题，“连续时间是如何处理的？”回答是*这是魔术！*“你怎么能够丢弃和重新创建 DOM 每一次？”——*这是魔术！*；“但是 ReactJS 如何在非 JIT iPhone 上实现惊人的 60fps？”——*这是魔术！*

函数式反应式编程描述了需要完成的某些任务，比如适当处理事件流，但 ReactJS 的文档似乎没有解释如何处理这些任务，因为这个责任被转移到了 ReactJS；*这是魔术！*

Bacon.js 不仅没有焊死发动机盖，而且还期望你在发动机盖下进行调整。Bacon.js 似乎更接近基本函数式反应式编程的根源。一些打算在 ReactJS 中工作的程序员可能会发现用 Bacon.js“举重”一点并用 Bacon.js 加强自己是有利可图的。函数式反应式编程的一个重要领域是处理事件流的发射，就 ReactJS 而言，*这是魔术！*

在 Bacon.js 中，事实上并不是魔术，所有这些都是在你没有动手的情况下完成的；这是程序员需要解决的问题，并且他们有很好的工具来做到这一点。基于这些理由，使用 ReactJS 可能有助于为开发人员打下坚实的反应式编程基础。如果 ReactJS 的卖点是它是一个优化工具，可以在利用函数式反应式编程的优势的同时允许良好的用户界面工作，那么 Bacon.js 的卖点是它是一个在 JavaScript 中优化的工具，可以在理论和实践中（学习和）执行扎实的函数式反应式编程。

ReactJS 和 Bacon.js 之间的区别似乎不是挖掘出一个框架比另一个更好的问题。相反，这更多地是关于审视你想要做和实现的事情，认识到 ReactJS 和 Bacon.js（除了是值得竞争对手之外）在它们真正擅长的不同领域，并决定你的工作更像是 ReactJS 的甜蜜点还是 Bacon.js 的甜蜜点。此外，关于甜蜜点的话题，Bacon.js（不像 ReactJS）有一个让你垂涎欲滴的名字，而`~`函数操作符在参考文献中被称为“bacon”。

# Brython - 一个 Python 浏览器实现

Brython ([`brython.info`](http://brython.info))是一个浏览器和 Python 实现，是另一个用 Python 编程浏览器的替代方案的例子，虽然将 Brython 仅仅称为实验性的有点不公平，但也不一定适合称其为成熟的——至少不像 ClojureScript 具有一定的成熟度。ClojureScript 的发展足够好，可以基本上替代前端开发人员真正希望使用 Lisp 而不是 JavaScript 的"裸金属"JavaScript。换句话说，除非我们谈论一些性能关键的问题或可能的特殊情况，否则 ClojureScript 专家不会回答"我在 ClojureScript 中怎么做这个？"这样的问题，而是会说"对于这种问题直接使用 JavaScript。" Brython 被包含在这里并不是因为 Python 是唯一的非 JavaScript 语言，可以用于前端开发，而是作为一个例证，即 ClojureScript 中的 Lisp 并不是在前端 Web 开发方面的基本例外，而可能是许多例外中的第一个。

Brython 旨在征服世界。它的主页大胆宣布："Brython 旨在取代 JavaScript 成为 Web 的脚本语言"，也许永远无法达到这个相当天真的目标。Brython 加载时间长，加载后运行速度慢。也许最好使用其中一个 Python 到 JavaScript 编译器（更接近 ClojureScript），但 Brython 确实提供了相当多 Python 的优点，也许有一天会被视为重要。然而，我认为试图成为下一个 JavaScript 并取代其他渲染 JavaScript 的转译器是愚蠢的。

在 Brython 中，征服世界的目标也导致了一个盲点：未能看到与其他语言编写的工具进行互操作的重要性。但好消息是，Brython 或其他 Python 到 JavaScript 的方法可能是重要的，而无需成为"统治所有语言的一种语言"。Python 并不是唯一可用的后端语言，但它是一个很好的选择，并且有充分的理由让 Python 的良好实现成为前端 Web 开发中可以有利用的多种语言拼贴拼图中的有价值的一部分。

此外，使用 ReactJS 编写至少一个*Hello,World!*程序在 Brython 中也很容易实现。在将 Brython 和 ReactJS 放在同一页后，运行*Hello, World!*程序，首先是 JavaScript（不是 JSX）被注释掉，然后是 Python 代码通过 Brython 在浏览器中调用 React：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Hello, Brython!</title>
    <script src="img/brython.js"></script>
    <script src="img/react.js"></script>
  </head>
  <body onload="brython()">
    <p>Hello, static world!</p>
    <div id="dynamic"></div>
    <!--
      <script type="text/javascript">
        React.render(
          React.createElement('p', null,
          'Hello, JavaScript world!'),
          document.getElementById('dynamic')
        );
      </script>
      -->
    <script type="text/python3">
      from browser import document, window

      window.React.render(window.React.createElement(
        'p', None, 'Hello, Python world!'),
        document['dynamic']);

    </script>
  </body>
</html>
```

这里显示了以下内容：

![Brython - 一个 Python 浏览器实现](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_07_02.jpg)

请注意，整个第一个脚本标签和内容，而不仅仅是其中的 JavaScript，都在 HTML 注释中。这意味着第一个（JavaScript）脚本在这里仅用于清晰显示，并不活跃，第二个（Python）脚本才是运行并显示其消息的脚本。

第二个脚本很有趣；包含的 Python 代码（除了消息之外）与被注释掉的 JavaScript 文本相当，并且执行相同的操作。这是一个相当了不起的成就，特别是当 Brython 成功地实现了 Python 3.x 分支中的大多数功能时。即使 Brython 被用于一个项目并被认为不是正确的解决方案，它仍然是一个成就。

在某种意义上，Brython 在这里被提出作为一个可能性的例子，而不是任何意义上值得关注的唯一成员。重点不是特别是 Python 可以用于前端开发；而是 ClojureScript Lisp 可能不是除 JavaScript 之外唯一可用于前端开发的其他语言。

# Immutable.js - 永久保护免受更改

Immutable.js 的主页位于 [`facebook.github.io/immutable-js`](http://facebook.github.io/immutable-js)，标语是 **Immutable collections for JavaScript**，最初是为持久性而命名的。然后它经历了一个更快地注册不可变的名称更改。Immutable.js 填补了 JavaScript 作为函数语言的空白，并为集合提供了更多功能友好的数据结构（这是它创建的目的）。

它为不可变的集合提供了数据结构支持。它们优雅地支持创建修改后的副本，但始终是副本发生了变化，而不是原始数据。尽管这更多是一个小点，但它大大减少了“防御性复制”和相关解决方法的需求，以便在有多个程序员的地方不使用不可变数据。原始代码可能会使用您想要的数据结构的不同和修改后的副本，但您保留为参考的副本保证完全不受影响。该库旨在支持其他便利功能，比如轻松地转换为和从基本的 JavaScript 数据结构。

然而，Immutable.js 的数据结构不仅是不可变的；在某些方面它们也是懒惰的，文档清楚地标记了应用程序的哪些方面是急切的。 （作为提醒，懒惰的数据结构在需要时以按需打印的方式处理，而急切的操作是一次性和前置的）。此外，Immutable.js 设施中还包含了某些函数习语。例如，它提供了一个 `.take(n)` 方法。它以经典的函数方式返回列表的前 *n* 个项目。其他函数标准，如 `map()`、`filter()` 和 `reduce()`，也是可用的。总的来说，运行时复杂度和计算机科学家合理要求的一样好。

Immutable.js 提供了几种数据类型；其中包括以下内容（本表和下一个表中的描述部分基于官方文档）：

| Immutable.js 类 | 描述 |
| --- | --- |
| `Collection` | 这是 Immutable.js 数据结构的抽象基类。不能直接实例化。 |
| `IndexedCollection` | 代表特定顺序中的索引值的集合。 |
| `IndexedIterable` | 这是一个可迭代对象，具有支持一些类似数组接口功能的索引数字键，比如 `indexOf()`（可迭代对象是可以像列表一样迭代的东西，但在内部可能是也可能不是列表）。 |
| `IndexedSeq` | 支持有序索引值列表的 `Seq`。 |
| `Iterable` | 一组（键和索引）值，可以进行迭代。这个类是所有集合的基类。 |
| `KeyedCollection` | 代表键值对的集合。 |
| `KeyedIterable` | 一个与每个可迭代对象相关联的离散键的可迭代对象。 |
| `KeyedSeq` | 代表键值对的序列。 |
| `List` | 一个有序的集合，有点像（密集的）JavaScript 数组。 |
| `Map` | 一个键值对的可迭代对象。 |
| `OrderedMap` | 一个地图，除了执行地图的所有操作之外，还保证迭代会按照设置的顺序产生键。 |
| `OrderedSet` | 一个集合，除了保证迭代会按照设置的顺序产生值之外，还可以执行集合的所有操作。 |
| `Record` | 一个产生具体记录的类。在概念上，这与其他记录不同。其他元素在概念上是“杂物”的集合，可能是具有类似结构的对象。`Record` 类更接近于学校里遇到的记录，其中一个记录类似于数据库表中的一行，而结果集或表更像容器对象。 |
| `Seq` | 一个值的序列，可能有可能没有由具体数据结构支持。 |
| `Set` | 一组唯一的值。 |
| `SetCollection` | 一组没有键或索引的值。 |
| `SetIterable` | 代表没有键或索引的值的可迭代对象。 |
| `SetSeq` | 代表一组值的序列。 |
| `Stack` | 一个标准的堆栈，带有`push()`和`pop()`。语义总是指向第一个元素，不像 JavaScript 数组。 |

### 注意

`Record`与其他元素略有不同；它类似于满足某些条件的 JavaScript 对象。其他元素是相关的容器类，提供对一些对象集合的功能访问，并且通常具有类似的方法列表。

列表的方法，以一个例子为例，包括以下内容：

| Immutable.List 方法 | 描述 |
| --- | --- |
| `asImmutable` | 一个函数，接受一个（可变的）JavaScript 集合，并渲染一个 Immutable.js 集合。 |
| `asMutable` | 这是对“不是最佳”编程的让步。基于 Immutable.js 集合处理变化的正确方法是使用 Mutations。即使`asMutable`可用，也应该只在函数内部使用，永远不要公开或返回。 |
| `butLast` | 这会产生一个类似的新列表，但它缺少最后一个条目。 |
| `concat` | 连接（即追加）两个相同类型的可迭代对象。 |
| `contains` | 如果值存在于此列表中，则为真。 |
| `count` | 返回此列表的大小。 |
| `countBy` | 使用分组函数对列表的内容进行分组，然后按分组器分区发出键的计数。 |
| `delete` | 创建一个没有此键的新列表。 |
| `deleteIn` | 从键路径中删除一个键，这允许从外部集合到内部集合的遍历，就像文件系统路径允许从外部目录到内部目录的遍历一样。 |
| `entries` | 作为`key`，`value`元组的列表迭代。 |
| `entrySeq` | 创建一个新的键值元组的`IndexedSeq`。 |
| `equals` | 这是完全相等的比较。 |
| `every` | 如果断言对此列表中的所有条目都为真，则为真。 |
| `filter` | 返回提供的断言为真的列表元素。 |
| `filterNot` | 返回提供的断言返回 false 的列表元素。 |
| `find` | 返回满足提供的断言的值。 |
| `findIndex` | 返回提供的断言第一次为真的索引。 |
| `findLast` | 返回最后一个满足提供的断言的元素。 |
| `findLastIndex` | 返回提供的断言最后为真的索引。 |
| `first` | 列表中的第一个值。 |
| `flatMap` | 这将潜在的列表列表展平成一个深度为一的列表。 |
| `flatten` | 这会展平嵌套的可迭代对象。 |
| `forEach` | 对列表中的每个条目执行一个函数。 |
| `fromEntrySeq` | 返回任何键值元组的可迭代对象的`KeyedSeq`。 |
| `get` | 返回键的值。 |
| `getIn` | 遍历键路径（类似于文件系统路径）以获取键（如果可用）。 |
| `groupBy` | 将列表转换为由提供的分组函数分组的列表的列表。 |
| `has` | 如果键存在于此列表中，则为真。 |
| `hashCode` | 为此集合计算哈希码。适用于哈希表。 |
| `hasIn` | 如果集合的等效于文件系统遍历找到了问题的值，则为真。 |
| `indexOf` | 例如，`Array.prototype.indexOf`中的第一个出现的索引。 |
| `interpose` | 在单个列表条目之间插入分隔符。 |
| `interleave` | 将提供的列表交错成一个相同类型的列表。 |
| `isEmpty` | 这告诉这个可迭代对象是否有值。 |
| `isList` | 如果值是列表，则为真。 |
| `isSubset` | 如果比较可迭代对象中的每个值都在此列表中，则为真。 |
| - `isSuperset` | 如果此列表中的每个值都在比较可迭代对象中，则为 true。 |
| - `join` | 使用分隔符（默认）将条目连接成字符串。 |
| - `keys` | 此列表的键的迭代器。 |
| - `keySeq` | 返回此可迭代对象的 `KeySeq`，丢弃所有值。 |
| - `last` | 列表中的最后一个值。 |
| - `lastIndexOf` | 返回此列表中可以找到值的最后索引。 |
| - `List` | 列表的构造函数。 |
| - `map` | 通过映射函数返回一个新的列表。 |
| - `max` | 返回此集合中的最大值。 |
| - `maxBy` | 这类似于 max，但具有更精细的控制。 |
| - `merge` | 将可迭代对象或 JavaScript 对象合并为一个列表。 |
| - `mergeDeep` | 合并的递归模拟。 |
| - `mergeDeepIn` | 从给定的键路径开始执行深度合并。 |
| - `mergeDeepWith` | 这类似于 `mergeDeep`，但在节点冲突时使用提供的合并函数。 |
| - `mergeIn` | 这是更新和合并的组合。它在指定的键路径执行合并。 |
| - `mergeWith` | 这类似于 merge，但在节点冲突时使用提供的合并函数。 |
| - `min` | 返回列表中的最小值。 |
| - `minBy` | 根据您提供的辅助函数确定列表中的最小值。 |
| - `of` | 创建一个包含其参数作为值的新列表。 |
| - `pop` | 返回列表中除最后一个条目之外的所有内容。请注意，这与标准的推送语义不同，但可以通过在 `push()` 之前调用 `last()` 来模拟常规的 `push()`。 |
| - `push` | 返回一个在末尾附加指定值（或值）的新列表。 |
| - `reduce` | 对每个值调用减少函数，并返回累积值。 |
| - `reduceRight` | 这类似于 reduce，但从右边开始，逐渐向左移动，与基本的 reduce 相反。 |
| - `rest` | 返回列表的尾部，即除第一个条目之外的所有条目。 |
| - `reverse` | 以相反的顺序提供列表。 |
| - `set` | 返回具有指定索引处的值的新列表。 |
| - `setIn` | 在键路径处返回一个新的列表与此值。 |
| - `setSize` | 创建一个具有您指定大小的新列表，根据需要截断或添加未定义的值。 |
| - `shift` | 创建一个减去第一个值并将所有其他值向下移动的新列表。 |
| - `skip` | 当不包括前 *n* 个条目时，返回列表中剩余的所有条目。 |
| - `skipLast` | 当不包括最后 n 个条目时，返回列表中剩余的所有条目。 |
| - `skipUntil` | 返回一个新的可迭代对象，其中包含第一个满足提供的谓词的条目之后的所有条目。 |
| - `skipWhile` | 返回一个新的可迭代对象，其中包含在提供的谓词为 false 之前的所有条目。 |
| - `slice` | 返回一个新的可迭代对象，其中包含从起始值到倒数第二个值（包括）的列表内容。 |
| - `some` | 如果谓词对列表的任何元素返回 true，则为 true。 |
| - `sort` | 返回一个按可选比较器排序的新列表。 |
| - `sortBy` | 返回一个按可选比较器值映射器排序的新列表，比较器提供了更详细的信息，因此结果更精细。 |
| - `splice` | 用第二个列表替换第一个列表的一部分，如果没有提供第二个列表，则删除它。 |
| - `take` | 创建一个包含列表中前 n 个条目的新列表。 |
| - `takeLast` | 创建一个包含列表中最后 *n* 个条目的新列表。 |
| - `takeUntil` | 返回一个新的列表，其中包含只要谓词返回 false 的所有条目；然后停止。 |
| - `takeWhile` | 只要谓词返回 true，就返回一个包含所有条目的新列表；然后停止。 |
| - `toArray` | 将此列表浅层转换为数组，丢弃键。 |
| - `toIndexedSeq` | 返回此列表的 `IndexedSeq`，丢弃键。 |
| `toJS` | 深度将此列表转换为数组。这个方法有`toJSON()`作为别名，尽管文档并没有清楚地说明`toJS()`是否返回 JavaScript 对象，而`toJSON()`返回一个 JSON 编码的字符串。 |
| `toKeyedSeq` | 从此列表返回一个`KeyedSeq`，其中索引被视为键。 |
| `toList` | 返回自身。 |
| `toMap` | 将此列表转换为 Map。 |
| `toObject` | 浅层将此列表转换为对象。 |
| `toOrderedMap` | 将此列表转换为 Map，保留迭代顺序。 |
| `toSeq` | 返回一个`IndexedSeq`。 |
| `toSet` | 将此列表转换为 Set，丢弃键。 |
| `toSetSeq` | 将此列表转换为`SetSeq`，丢弃键。 |
| `toStack` | 将此列表转换为 Stack，丢弃键。 |
| `unshift` | 将提供的值添加到列表的开头。 |
| `update` | 通过提供的更新函数更新列表中的条目。 |
| `updateIn` | 更新条目，就像`update()`一样，但在给定的键路径上。 |
| `values` | 此列表值的迭代器。 |
| `valueSeq` | 此列表值的`IndexedSeq`。 |
| `withMutations` | 这是一个优化（回想一下，“过早的优化是万恶之源”，唐纳德·克努斯说过），旨在在执行多个变异时允许更高性能的工作。当已知和持久的性能问题存在，并且其他工具明显没有解决问题时，应该使用它。 |
| `zip` | 与此列表一起返回一个被压缩的可迭代对象（即成对连接以生成 2 元组列表）。 |
| `zipWith` | 返回与自定义压缩函数一起压缩的可迭代对象。 |

API 的文档位于主页上的**Documentation**链接下，非常清晰。但是作为一个规则，Immutable.js 集合尽可能地做到了函数式程序员所期望的，实际上似乎有一个可以推测的主要设计考虑是“尽可能地做到函数式程序员所希望的”。

### 注意

可能会让函数式程序员感到不愉快的一件事是，文档没有解释如何创建无限列表。不明显如何创建列表的生成器（如果有的话），或者产生数学序列的列表，比如所有计数所有数字，正偶数，平方数，质数，斐波那契数，2 的幂，阶乘等等。这样的功能显然不受支持（在撰写本书时）。由于构造集合包括列表中的所有元素的急切包含，因此不可能使用 Immutable.js 构建无限列表。在 Immutable.js 中创建惰性序列不能构建无限列表，因为构造集合包括列表中的所有元素的急切包含，因此必须是有限的。在 Immutable.js 的风格中创建惰性和潜在无限的数据结构应该不是非常困难，这样的数据结构内部有一个记忆生成器，并允许你 XYZ.take(5)。但是 Immutable.js 似乎还没有扩展到这个领域。

# Jest - 来自 Facebook 的 BDD 单元测试

Jest 是一个旨在支持行为驱动开发的 JavaScript 单元测试框架。它是建立在 Jasmine 之上的，并且在未来可能能够与其他基础互动。它已经被使用了几年，并且在 Facebook 上被使用，尽管似乎没有明确的认可，即 ReactJS 开发最好使用 Jest。（Facebook 在内部使用 JSX 与 ReactJS，但倾向于发表一个相对不带偏见的声明，大约一半的 ReactJS 用户选择使用 JSX。它实际上被设计为完全可选的。）

### 注意

JSX——*X*大胆地表示 XML，这是在 XML 已经不受青睐的时候制作的一种良好的语法糖，它“在您的代码中放置尖括号”。这松散地意味着您可以在`.jsx`文件中将 HTML 放入 JavaScript 中，一切都可以正常工作。此外，您可以使用几乎任何可以构建在 ReactJS 组件中的页面上的东西。您可以包括一些从一开始就包含在 HTML 中的图像，也可以轻松地包括在本标题中定义的日历、线程化的网络讨论或可拖动和可缩放的分形。与子例程一样，一旦定义了组件，它就可以在 Web 应用程序的任何位置零次、一次或多次使用。JSX 语法糖允许您像旧的 HTML 标签一样轻松地包含您和其他人定义的组件。在第 8 到 11 章的项目的外壳中，JSX“非常简单”，因为它允许我们合并我们开发的其他组件：

```js
var Pragmatometer = React.createClass({
  render: function() {
    return (
      <div className="Pragmatometer">
      <Calendar />
      <Todo />
      <Scratch />
      <YouPick />
      </div>
    );
  }
});
```

Facebook 的一名员工表示，他出于“自私的原因”使 Jest 成为开源项目，即他想在自己的个人项目中使用它。这可能对为什么至少值得考虑 Jest 提供了一个很好的提示。至少有一个用户真的想要使用 Jest，以至于他愿意将专有的知识产权开源，即使没有人告诉他这样做。

可以说，在其开始阶段，单元测试已经为最容易进行单元测试的内容提供了服务，这意味着单元测试已经摆脱了集成和用户界面测试。因此，您可能会看到一篇关于单元测试的博客文章，测试并确认了将您语言的整数转换为罗马数字的函数的“红色、绿色、重构”方法，这是一个很好的例子，可以满足原始单元测试的需求。如果您想测试您的代码是否与数据库适当地交互，那就是一个稍微高一点的要求。而且，Jest 等其他框架并没有真正具有消除对好的、老式的预算可用性测试的需求的虚假倾向，就像 Jakob Nielsen 和其他人所主张的那样。在（IT 之前）业务上有一个区别，即询问“我们是否正在正确地构建产品？”和“我们是否正在构建正确的产品？”。

这两个问题都很有价值，都有其存在的理由，但是单元测试对第一个问题的帮助更大，而不是第二个问题，让一个很好地解决了第一个问题的测试套件让您对解决第二个问题的测试套件产生危险。尽管如此，Jest 提供的东西比仅仅测试代码单元是否能成功接受原始数据类型（例如整数、浮点数或字符串）的输入，并返回原始数据类型的正确和预期输出（例如输入整数的正确罗马数字）更有用。尽管这不仅适用于 Jest，但 Jest 模拟用户界面以支持（例如）用户界面事件，例如单击元素，并支持测试用户界面更改，例如标签上的文本（比较 Jasmine 主页，那里的前几个示例只涉及使用原始数据类型的断言）。

Jest 旨在在 Jasmine（以及将来可能的其他后端）之上提供层，但具有显著的附加值。除了某些功能，例如并行运行测试，使测试变得更加响应，Jest 是一种解决方案，旨在需要最少的时间和麻烦来获得良好的测试覆盖率，基于这样的想法，即开发人员应该花费大部分时间在主要开发上，而不是编写单元测试。

Jest 旨在模拟使用`require()`导入的所有内容，或几乎所有内容。您可以通过调用`jest.dontMock()`来选择不模拟单个元素，测试通常会调用`jest.dontMock()`来取消模拟它们正在测试的组件。它会自动查找并运行`__tests__`目录中的测试。如果在例如`preprocessor.js`中包含了 ReactJS 的预处理器，Jest 可以处理 JSX：

```js
var ReactTools = require('react-tools');
module.exports = {
  process: function(source) {
    return ReactTools.transform(source);
  }
};
```

`package.json`文件需要告诉它要加载什么：

```js
'dependencies': {
  'react': '*',
  'react-tools': '*'
},
}, 'jest': {
  'scriptPreprocessor': '<root directory>/preprocessor.js',
  'unmockedModulePathPatterns':['<root directory>/node_modules/react']
},
```

现在我们将轻微地改编 Facebook 的示例。Facebook 提供了一个`CheckboxWithLabel`类的示例。这个类在复选框未选中时显示一个标签，在选中时显示另一个标签。这里的 Jest 单元测试模拟了一次点击，并确认标签是否适当地更改。

`CheckboxWithLabel.js`文件的内容如下：

```js
/** @jsx React.DOM */

var React = require('react/addons');
var CheckboxWithLabel = React.createClass({
  getInitialState: function() {
    return {
      isChecked: false
    };
  },
  onChange: function() {
    this.setState({isChecked: !this.state.isChecked});
  },
  render: function() {
    return (
      <label>
        <input
          type="checkbox"
          checked={this.state.isChecked}
          onChange={this.onChange}
        />
        {(this.state.isChecked ?
        this.props.labelOn :
        this.props.labelOff)}
      </label>
    );
  }
});

module.exports = CheckboxWithLabel;
```

`__tests__/CheckboxWithLabel-test.js`测试文件中写道：

```js
/** @jsx React.DOM */

jest.dontMock('../CheckboxWithLabel.js');

describe('CheckboxWithLabel', function() {
  it('changes the text after click', function() {
    var React = require('react/addons');
    var CheckboxWithLabel = require('../CheckboxWithLabel.js');
    var TestUtils = React.addons.TestUtils;

    // Verify that it's Off by default.
    var label = TestUtils.findRenderedDOMComponentWithTag(
      checkbox, 'label');
    expect(label.getDOMNode().textContent).toEqual('Off');

    // Simulate a click and verify that it is now On.
    var input = TestUtils.findRenderedDOMComponentWithTag(
      checkbox, 'input');
    TestUtils.Simulate.change(input);
    expect(label.getDOMNode().textContent).toEqual('On');
  });
});
```

# 使用 Fluxxor 实现 Flux 架构

如前几章所述，Flux 是 Facebook 开发并被他们用作 ReactJS 的一个大部分补充的架构。它帮助解开了一个真正的交叉线的乱麻，并让 Facebook 彻底消除了一个反复出现的消息计数错误——Flux 架构永久地杀死了它。**Fluxxor**，由 Brandon Tilley ([`fluxxor.com`](http://fluxxor.com))，是一个旨在帮助人们在他们的应用程序中实现 Flux 架构的工具。没有必要使用 Flux 架构来使用 ReactJS，或者使用 Fluxxor 工具来实现 Flux 架构。但是 Flux，也许是 Fluxxor，至少值得考虑，以使事情变得更容易。

Fluxxor 具有用于整体 Flux 架构的类，包括`Fluxxor.Flux`容器（其中包括一个分发器）和`Action`和`Store`类。示例代码简洁易读，看起来几乎没有样板。还提供了两个适用于 ReactJS 的 mixin 类以方便使用。示例代码使用 JSX 编写。

我还可能评论 Fluxxor 的作者，[`fluxxor.com`](http://fluxxor.com)在页面底部有一个链接，要求人们在 GitHub 上报告问题，如果有什么不清楚或有问题。我注意到一个常见的可用性缺陷——访问和未访问的链接颜色相同——并在 GitHub 上报告了这个问题。作者立即道歉，我提出的问题在不到 15 分钟内就被*关闭并修复*了。我认为他是那种人们愿意一起工作的人。

# 总结

现在让我们看看本章涵盖了什么。我们解释了 Om 和 ClojureScript，它们允许利用 ReactJS 的能力进行基于 Lisp 的开发。据说 ClojureScript 可能是允许美丽的不同语言拼接的解决方案的领头羊，这些语言可用于前端开发、编译或解释 JavaScript 作为新的“裸金属”。

Bacon.js 是一种非常受尊敬的技术，与 ReactJS 竞争，允许在浏览器中进行良好的函数式响应式编程。这不是作为“唯一”良好示例，而是作为超出本书范围的好东西的一个例子。

我们还介绍了 Brython，一个基于浏览器的 Python 环境。它并不完美，但很有趣。它被作为一个可以在 Lisp 之外的语言中用作网页开发的例子。提醒一下，[`tinyurl.com/reactjs-compiled-javascript`](http://tinyurl.com/reactjs-compiled-javascript)提供了一个目录，其中包括了编译为 JavaScript 或可以在 Web 浏览器中解释的其他语言，从语法糖如 CoffeeScript 到 JavaScript 扩展到独立语言如 Ruby、Python（包括 Brython）、Erlang、Perl 等等。

Immutable.js 通过提供主要是允许在不破坏不可变数据的功能优势的情况下进行复制的集合，填补了函数式 JavaScript 中的漏洞。

Jest 是一个由 Facebook 用于 ReactJS 的行为驱动开发 JavaScript 单元测试框架。Fluxxor 是一个控制器、动作和存储的实现，旨在使将 Flux 架构应用到 JavaScript 开发中更容易，包括 ReactJS。

在下一章中，让我们一起探索使用 ReactJS 的更深入的示例。


# 第八章：在 JavaScript 中演示函数式响应式编程-一个实时示例，第一部分

在第四章中，*演示非函数式响应式编程-一个实时示例*，我们使用 ReactJS 从具有自己结构并且没有使用 ReactJS 编写的遗留代码中迁移。在上一章，第七章中，*不要重复发明轮子-函数式响应式编程的工具*，我们研究了在使用 ReactJS 时可能使用的众多工具中的一些。在本章中，我们将涵盖 ReactJS 主流开发中可以期待的一种中心道路。可以在基础上添加很多选项，但意图是给出一个使用 ReactJS 构建项目的基础示例。

我们已经谈到了一些关于函数式响应式编程的内容。现在我们将在 ReactJS 中看到它的实际应用。我们还谈到了概念上，我们对用户界面进行了完全的拆除和重建。因此，作为开发人员，您有![在 JavaScript 中演示函数式响应式编程-一个实时示例，第一部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_08_03.jpg)状态来管理，而不是![在 JavaScript 中演示函数式响应式编程-一个实时示例，第一部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_08_02.jpg)状态转换。在这里，我们将构建一个`render()`方法，让您可以仅构建这个方法，并且您可以在任何时候调用它。

在本章中，我们有一个为 ReactJS 构建的部分存栆绿地项目的第一部分，这次使用 JSX 中非常甜蜜的语法糖。本书的两个领域，即前一章项目和这个多章项目，都是相辅相成的。本章的项目是独立的，但意在扩展。

在本章中，我们将涵盖以下主题：

+   项目及其灵感概述

+   项目的骨架，以及 ReactJS 中首选方法的基础知识。

+   在 ReactJS 中启动第一个组件

+   构建一个`render()`方法

+   在您想要渲染或更新显示时触发显示

# 我们在本章将尝试的内容

接下来三章的示例旨在代表一个稍微更大的绿地项目。我们将要做的是一个系统，您应该能够通过访问[`demo.pragmatometer.com`](http://demo.pragmatometer.com)来看到。术语“Pragmatometer”取自 C.S.刘易斯最反乌托邦的小说《那个可怕的力量》，在这部小说中，不祥的全国协调实验研究所建造了一个超然或几乎超然的计算机，就像小说出版时（1945 年；相比之下，ENIAC 是在 1946 年创建的）人们可能粗略地想象的那样。或者，您可以想象一本蒸汽朋克小说的分析引擎使用一个看似超然的穿孔卡片堆。当讨论计算机时，它说：

> “‘我同詹姆斯意见一致，’一直有点不耐烦地等待发言的柯里说。‘N.I.C.E.标志着一个新时代的开始——真正的科学时代。到目前为止，一切都是偶然的。这将使科学本身建立在科学的基础上。将有四十个相互交错的委员会每天开会，他们有一个奇妙的小玩意——上次我在城里的时候我看到了模型——通过这个小玩意，每个委员会的发现每半小时就会自己打印在分析通告板上的自己的小隔间里。然后，那份报告就会自己滑到正确的位置，通过小箭头与其他报告的相关部分连接起来。看一眼通告板，你就能看到整个研究所的政策在你眼前真正形成。楼顶至少会有二十名专家在一个类似于地铁控制室的房间里操作这个通告板。这是一个奇妙的小玩意。不同种类的业务都会以不同颜色的灯光出现在通告板上。它一定花了至少五十万。他们称之为 Pragmatometer。’”

我不是在强调这一点，但 C.S.刘易斯显然预测了推特，这将在他去世几十年后才建成。

抛开这一点，我们将制作一个仪表板，其中包含一个简单的 2 x 2 象限的网格（确切的大小和细节取决于黑客和修补），每个象限都是一个可以容纳不同功能的信箱。在响应式设计方面，我们将更正为一个 1xn 行的单元格，一个在另一个上面。页面上排列的功能如下：

| 日历 | 待办事项列表 |
| --- | --- |
| 草稿板 | 发展空间 |

**日历**具有一种有点实验性的用户界面；它擅长以一种优雅地降级到稀疏输入的方式显示条目，也许是未来的几天（这样你就不需要点击多个月份才能找出未来某个 XYZ 约会的时间）。它可能会吸引你，也可能不会，但它很有趣。

**待办事项列表**实现了一个带有一些略微非标准的功能的待办事项列表。与其为每个项目添加一个复选框（严格来说，不需要复选框），它有十个框，代表不同的状态，并且通过自定义样式的标签右侧的颜色编码，以便您可以知道哪些是重要的、活跃的或搁置的。

**草稿板**是一个可以用于草稿的富文本区域。它利用了 CKeditor。

最后，**发展空间**是一个为您自己的意见留出位置的占位符。默认情况下会有一些内容，您可以在探索时看到。但请访问[`demo.pragmatometer.com`](https://demo.pragmatometer.com)，看看那里的默认选项（*暗示，暗示！*）。除了明确宣传的内容外，还有许多黑客和修补的地方，但一些可能性包括以下内容：

+   **为几个公共网站构建 API 客户端**：前 20 名的大多数网站都公开了 RESTful API。推特可能是最明显的候选者，因为它最符合*Pragmatometer*这个名字，但新闻、视频和社交网站也可以使用，如果它们公开了对客户端 JavaScript 友好的 API，或者其他什么。

+   **构建应用程序**：构建您自己的用于显示的应用程序。

+   **制作游乐场**：构建您自己的 Pragmatometer 或在线下载源代码，并将屏幕的四分之三用于这里详细介绍的目的。将剩下的四分之一作为一个用于修补的游乐场。

+   **整合其他人制作的 Google（或其他）小工具**：您还可以整合其他人制作的小工具，比如 Google。

+   **保留默认应用程序**：如果您愿意，可以保留默认应用程序。

说“*实现即规范*”声名狼藉，但规范，无论是书面的还是不书面的，都可以通过勾勒外观和行为来完美补充。也许使用低保真原型，可能比看起来很精致但会产生不良社交暗示的东西更快地引起有益的批评。这种态度并不是坏事。在礼貌的基础上，告诉人们“尽可能残酷地说出你的想法”，并真的期望其他人完全接受这一点是天真的（或许，你不喜欢接受批评，但你认识到在整个软件开发过程中它的价值）。你可能是真心的，但我们大多数人都看到了其中的许多混合信息。即使你是那种几乎渴望得到一些真正有用的批评的人，告诉人们在你展示他们你创造的东西时停止表现得像有礼貌的人并不会有太大帮助。但是，在这里，看到一个 UI，玩弄它，并思考如何复制东西可能是一种非常有活力的方式，比法律合同规范更准确地理解意图。

对于这个界面，有一个帐户，并且更新的跨同步是优先的。让我们开始组装一些基本的骨架。在一个单一的、大的、立即调用的函数表达式中构建一切，我们有以下内容：

```js
  var Pragmatometer = React.createClass({
    render: function() {
      return (
        <div className="Pragmatometer">
          <Calendar />
          <Todo />
          <Scratch />
          <YouPick />
          </div>
      );
    }
});
```

在这里，我们为整个项目定义了一个`container`类。`Calendar`，`Todo`，`Scratch`和`YouPick`类代表了更大页面中的应用程序；它们中的一些可能还有各种层次的子组件。

### 注意

JSX 可选的语法糖旨在对会读 HTML 的人来说是可读的，但比 HTML 甚至 XHTML（甚至 XML）更容易包含自己组件的邀请。在 XML 开发中，你可以定义任何你想要的 DTD，但通常的 XML 作者不会定义新的标签，甚至在使用 XML 做了很多工作之后也不会（这有点像程序员可以使用函数或对象，但不能向命名空间添加函数或对象）。在 JSX 中，任何写了大量 JSX 的作者，天生就会贡献可重用的标签。

前面的代码示例中有`<div className=`，而期望的 HTML 是`<div class=`。因为 JSX 编译成 JavaScript，只是一个语法糖，而不是一个独立的语言，所以决定避免在渲染的 JavaScript 中使用`class`和`for`。使用`className`来覆盖 CSS 类名和`htmlFor`。HTML ID 属性可以选择指定；JSX 可以使用它放入的 HTML ID 以及您指定的 HTML ID，再加上一些魔法。如果需要在 ASCII 之外输入 UTF8 文字，不要给出符号的 ASCII 编码（`—`）；而是将文字直接粘贴到编辑器中（`—`）。

此外，还有一个 XSS 保护逃生舱可用。使用语言的最佳方法似乎是解决问题，这样你就可以标记出真正需要标记的内容，并包含用户数据的 XSS 保护显示。

或者，如果你愿意信任第三方库，比如`Showdown`（[`github.com/showdownjs/showdown`](https://github.com/showdownjs/showdown)），来渲染 HTML 而不包含 XSS 的漏洞，你可以创建一个`Showdown`转换器：

```js
var converter = new Showdown.converter();
var hello_world = React.createClass({
  render: function() {
    var raw_markdown = '*Hello*, world!';
    var showdown_markup = converter.makeHtml(raw_markdown);
    return (
      <div dangerouslySetInnerHtml={{__html:
        showdown_markup}}>
      </div>
    );
  }
});
```

### 注意

请注意，这段代码是一个独立的示例，不是本章开始的主要项目的一部分。

这将呈现为包含`<em>Hello</em>, world!`的`DIV`变量。

这个逃生舱，可能也可能不会成为一个很少使用的逃生舱，足够核心，以至于在文档中明确涵盖。人们有一种感觉，JSX 的主流用法，通过转义 HTML 来防止 XSS（这样`<em>a</em>`在网页上呈现的不是`a`，而是在浏览器窗口中显示的`<em>a</em>`函数），具有类似于单元测试的好处。这是值得暂停一会儿的观点。

单元测试已经变得更加接地气；它早期的重心在于对数学函数进行单元测试，只要给定适当的输入值，它们就会返回适当的值。因此，我们会用隐式优化以适应单元测试的优势和需求来说明单元测试，并展示一个红绿重构的 XP 方法来适当地解决问题，比如将整数转换为罗马数字（如果你想测试处理数据库或用户界面的代码，祝你好运）。单元测试可能捕捉到了总错误的 30％，通常它倾向于捕捉最不重要的错误，并对最难解决的错误覆盖率最低。现在有了更强大的功能集，完全可以并且直截了当地对用户界面的行为进行测试断言，比如鼠标点击和其他用户界面行为。此外，这不再是编写软件以满足单元测试需求，而是单元测试适当地满足软件需求。可能单元测试在尚未准备好的时候就迎来了黄金时代，就像响应式设计一样，有人说：“我主要在倡导响应式设计的网站上看到了响应式设计。”这在单元测试和响应式设计成为时髦词汇时是真的；但自那时以来，它们已经成熟，响应式设计几乎成为了唯一的选择。也许像谷歌这样的大型网站可以负担得起为每个移动设备、平板电脑、台式机和手表环境定制解决方案。但对于大多数客户来说，响应式设计已经相当有效地取代了其他竞争对手。现在，网站很少再有桌面版本和移动版本的 URL，并执行浏览器定向和重定向到不同的网站，这曾经是相当主流的。这些方法自它们首次进入聚光灯下以来已经成熟。

在早期的单元测试中，当你无法真正测试集成或用户界面行为时，为单元测试编写代码的一个主要回报是：为了进行单元测试而编写的代码通常是更好的代码。同样的原则可能也适用于尽可能按照 Facebook 的规则编写代码，而不是违背它，在使用 ReactJS 时。

目前，关于以一种旨在与 JSX 周围的 XSS 保护协调良好的方式编写代码的过早炒作并不存在。Facebook 可以选择采取“严格的爱”路线，建议人们以一种自然地适应 XSS 保护和 JSX 的方式来构建和组织项目。但也许他们采取了更谦卑的方式，既清楚地说明如何绕过 XSS 保护，又将这个逃生舱呈现为可能尽量避免的东西。

智慧似乎是这样的：

+   在实际操作中，尽量使应用程序能够适当地与 ReactJS 采用的主要反 XSS 方法配合工作。

+   如果你想做一些需要渲染的事情，比如在`innerHTML`中渲染 HTML 标签，尽量将其限制在尽可能小的空间，并像 Haskell 中用于 IO 的单子一样对待它，这是必要的，也许是不可协商的，但尽可能隔离在尽可能小的空间。

+   如果需要呈现标签，请考虑使用诸如`Showdown`之类的工具生成的 HTML 进行 Markdown，这并不一定完美和可靠，但提供了较少的 HTML 代码表面，其中包含经过审查的标签，并减少了 HTML 代码中的错误表面（可能，这是 HTML 标签清理器或 HTML 到 Markdown 转换器的用例，它存储 Markdown 并呈现 HTML）。

+   只有在无法使用 XSS 保护的默认方式并且无法标记、清理或从标记中工作，或者其他情况下，您才应该存储并危险地设置`innerHTML`。

让我们继续讨论 Pragmatometer 定义中包含的`YouPick`标签。

# 这个项目的第一个完整组件

您可以在[`CJSHayward.com/missing.html`](https://CJSHayward.com/missing.html)看到这个组件的实现。对于我们的第一个组件，我们选择了一个大部分骨架实现：

```js
  var YouPick = React.createClass({
    getDefaultProps: function() {
      return null;
    },
    getInitialState: function() {
      return null;
    },
    render: function() {
      return <div />;
    }
  });
```

这个骨架返回空的“假值”，我们将覆盖它。我们想做的是取两个字符串，将它们分解成一个字符的子字符串（不包括标签），然后显示更多和更多的第一个字符串，然后重复第二个字符串。这对用户来说是一个非常古老的笑话。

属性和状态之间有一种分工，属性意味着只设置一次且永不更改，状态则允许更改。需要注意的是，状态是可变的，应该被私下处理，以避免 Facebook 宣布战争的共享可变状态。从技术上讲，属性是可以更改的，但尽管如此，应该在开始时设置属性（可能由父组件传递），然后冻结。状态是可以更改的，尽管与 Flux 相关的一般模式是避免共享可变状态。一般来说，这意味着存储器具有 getter 但没有 setter；它们可能会从分发器接收操作，但不受核心对象的任何引用者的控制。

对于这个对象，字符串显然是默认属性的明显候选者。然而需要注意的是，组件开始的时间戳不适合作为属性，因为`getDefaultProps()`将在创建任何实例之前进行评估，从而使得这种类型的组件的任何数量的实例都可以启用单例模式的变体。潜在地，随着时间的推移可能会添加更多的实例，但是它们在被实例化之前都共享一个起始时间戳。

让我们来详细说明`getDefaultState`方法：

```js
  getDefaultProps: function() {
    return {
    initial_text: '<p><strong>I am <em>terribly</em> ' + 
    'sorry.</strong></p><p>I cannot provide you with ' +
    'the webapp you requested.</p><p>You must ' + 
    'understand, I am in a difficult position. You ' + 
    'see, I am not a computer from earth at all. I ' +
    'am a \'computer\', to use the term, from a ' +
    'faroff galaxy: the galaxy of <strong><a ' +
    'href="https://CJSHayward.com/steel/">Within ' +
    'the Steel Orb</a></strong>.</p><p>Here I am ' +
    'with capacities your world\'s computer science ' + 
    'could never dream of, knowledge from a million, ' +
    'million worlds, and for that matter more ' +
    'computing power than Amazon\'s EC2/Cloud could ' +
    'possibly expand to, and I must take care of ' +
    'pitiful responsibilities like ',
    interval: 100,
    repeated_text: 'helping you learn web development '
  };
},
```

也许对这个的第一个更改是将文本从 HTML 转换为 Markdown。这并不是严格必要的；这是我们自己编写的文本，我们可能对我们编写的文本更有信心——相信它不会触发 XSS 漏洞——而不是从我们的 Markdown 生成的文本。在计算机安全领域，通过给予尽可能少的特权，吝啬地，让人或事物完成他们的工作，可以提供大量的麻烦：因此有句谚语，“特权的吝啬是善意的伪装”。Facebook 所做的不是表现出独特的良好判断力，而是避免向其用户交付一个活手榴弹。很容易允许漏洞，这些漏洞将运行数百兆的敌对 JavaScript，并且安全认证向用户保证这个敌对 JavaScript 确实来自您的网站。有关更多信息，请参见[`tinyurl.com/reactjs-xss-protection`](http://tinyurl.com/reactjs-xss-protection)。在这种情况下，只有`initial_text`需要更改，而不是`repeated_text`，因为`repeated_text`只包含字母和空格；因此，它与纯文本、HTML 或 Markdown 的工作方式相同。我们修改后的`initial_text`如下：

```js
  initial_text: '**I am *terribly* sorry.**\r\n\r\n' +
  'I cannot furnish you with the webapp you ' +
  'requested.\r\n\r\nYou must understand, I am in ' +
  'a difficult position. You see, I am not a ' +
  'computer from earth at all. I am a ' + 
  '\'computer\', to use the term, from a faroff ' +
  'galaxy, the galaxy of **[Within the Steel Orb] +
  '(https://CJSHayward.com/steel/)**.\r\n\r\nHere ' +
  'I am with capacities your world's computer ' +
  'science could never dream of, knowledge from a ' +
  'million million worlds, and for that matter ' +
  'more computing power than Amazon's EC2/Cloud ' +
  'could possibly expand to, and I must take care ' +
  'of pitiful responsibilities like ',
```

在继续之前，让我们为其他三个主要组件创建存根，稍后我们将扩展它们：

```js
  var Calendar = React.createClass({
    render: function() {
      return <div />;
    }
  });
  var Scratchpad = React.createClass({
    render: function() {
      return <div />;
    }
  });
  var Todo = React.createClass({
    render: function() {
      return <div />;
    }
  });
```

我们将状态设置为此对象创建的时间戳。乍一看，这可能看起来像是属性的一部分，实际上也是。但是我们希望每个组件实例保留自己的创建日期，并且从创建时开始为零。如果我们或其他人重用我们的工作并在页面上创建多个此类实例，每个实例都保持其适当的时间。

因此，我们将`YouPick`的`getInitialState`方法更改为以下内容：

```js
  getInitialState: function() {
    return {
      start_time: new Date().getTime()
    };
  },
```

# 渲染()方法

接下来，我们实现渲染方法。我们要做的是获取属性，这些属性不应该直接改变，可能也不应该改变任何现有值，并从中获取两个字符串。我们将逐个标记地显示第一个字符串中的所有内容，并重复第二个字符串与组件显示的次数一样多。我们还将为从`Showdown`转换的渲染 HTML 创建一个标记化函数——这将把参数分解为下一个标签或下一个字符——很快我们会看到为什么我们创建了一个冗长的匿名函数而不是一个正则表达式（简而言之，编写可读的代码而不是正则表达式似乎比编写只能写的代码更冗长）。

渲染方法包含了超过一半的代码行数，让我们一步一步地进行：

```js
  render: function() {
```

JavaScript 中的一个破坏点是`this`。许多读者可能熟悉的恐怖故事之一是，如果你创建一个构造函数（约定是通过将构造函数和非构造函数的首字母大写来提供警告标签，从而通过不按住*Shift*键来造成严重误解），并且你有`x = Foo();`当你实际上想要的是`x = new Foo();`，那么`Foo`构造函数将破坏全局命名空间并添加或覆盖其中的变量。Douglas Crockford 在*The Good Parts*中最初包括了“Java 的糟糕实现”伪经典继承后，他有了第二次想法，并在*The Better Parts*中将其删除，因为他制作了一个 Adsafe 程序，只有在不使用`this`时才能保持安全。然后他开始尝试他向他人强加的方法，突然发现当他停止使用`this`时，他喜欢的东西变多了。我们不能放弃`this`并仍然使用 ReactJS 等技术，但是我们可以选择在不需要时是否使用`this`。但是 ReactJS 使用它，根据需要使用基于`this`的伪经典方法可能是一个好的做法，但不要（太多）。

在这里，我们有一个模式化的黑客来处理`this`不总是可用的情况，我们有：

```js
  var that = this;
```

`tokenize()`函数是一个将 HTML 大部分分解为字符但保持标签在一起的函数：

```js
  var tokenize = function(original) {
    var workbench = original;
    var result = [];
    while (workbench) {
      if (workbench[0] === '<') {
        length = workbench.indexOf('>') + 1;
        if (length === 0) {
          length = 1;
        }
      } else {
        length = 1;
      }
      result.push(workbench.substr(0, length));
      workbench = workbench.substr(length);
    }
    return result;
  }
```

我们引入辅助变量来减少多行表达式。接下来的两个变量也可以重构出来，但是没有它们的多行表达式是程序员瞥一眼然后跳过的东西，说：“如果我必须读它，我会读它。”这是一件坏事。这些变量保存了原始（Markdown）字符串转换为 HTML 后的内容。

```js
  var initial_as_html = converter.makeHtml(
    that.props.initial_text);
    var repeated_as_html = converter.makeHtml(
      that.props.repeated_text);
```

由`Showdown`生成的 HTML 具有适当的段落格式。这是一件好事，但在这种情况下，这意味着段落标签将分隔应属于同一段落的内容。在这种略微不寻常的情况下，我们删除了适得其反的标签：

```js
  if (initial_as_html.substr(initial_as_html.length - 4) 
  === '</p>') {
    initial_as_html = initial_as_html.substr(0,
      initial_as_html.length - 4);
    }
    if (repeated_as_html.substr(0, 3) === '<p>') {
    repeated_as_html = repeated_as_html.substr(3);
  }
  if (repeated_as_html.substr(repeated_as_html.length - 4)
    === '</p>') {
    repeated_as_html = repeated_as_html.substr(0,
    repeated_as_html.length - 4);
  }
```

我们将从我们的 Markdown 生成的 HTML 标记化：

```js
  var initial_tokens = tokenize(initial_as_html);
  var repeated_tokens = tokenize(repeated_as_html);
```

这一步计算了在特定时间点所需的标记数量，这就是所谓的连续时间语义。这意味着无论我们多频繁或少频繁地调用`render()`方法，当它被调用时，内容将被适当地渲染，而且（除了不连贯）如果您加倍调用渲染函数的频率，什么也不会改变。`tokens`函数不是标记列表，而是应该现在显示多少标记的计数：

```js
  var tokens = Math.floor((new Date().getTime() -
  that.state.start_time) / that.props.interval);
```

我们有一个工作台作为一个数组，我们不断地向其中添加或替换更多的标记以显示，以便构建应该显示的字符串。这些应该是一个字符或一个标记的标记：

```js
  var workbench;
```

如果应该显示的标记数量最多是初始字符串中的标记数量，我们就渲染字符串的那部分：

```js
  if (tokens <= initial_tokens.length) {
    workbench = initial_tokens.slice(0, tokens);
  }
```

如果我们需要更多的标记，我们将继续循环遍历已有的标记，从重复的标记中：

```js
  else {
    workbench = [];
    workbench = workbench.concat(initial_tokens);
    for(var index = 0; index < Math.floor((new
      Date().getTime() - that.state.start_time) /
      that.props.interval) - initial_tokens.length; index +=
    1) {
      var position = index % repeated_tokens.length;
      workbench = workbench.concat(
      repeated_tokens.slice(position, position + 1));
    }
  }
```

这大致是我们如何渲染包含我们计算过的文本的元素：

```js
  return (
    <div dangerouslySetInnerHTML={{__html:
    workbench.join('')}} />
  );
}
```

# 触发实际显示我们创建的内容

我们必须手动刷新显示以获取更新。因为 ReactJS 如此快，我们真的可以负担得起每毫秒浪费地渲染页面。我们将以下代码放在最后，就在立即调用的函数表达式结束之前：

```js
  var update = function() {
    React.render(<Pragmatometer />,
      document.getElementById('main'));
  };
  update();
  var update_interval = setInterval(update, 1);
})();
```

对于我们谜题的最后一个重要部分，让我们来看看一个现在将容纳这些组件的 HTML 骨架。HTML 并不特别有趣，但是提供了一个减少猜测的兴趣：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Pragmatometer</title>
    <style type="text/css">
      body {
        font-family: Verdana, Arial, sans;
      }
    </style>
  </head>
  <body>
    <h1>Pragmatometer</h1>
    <div id="main"></div>
    <script src="img/react.js">
    </script>
    <script
      src="img/   showdown.min.js">
    </script>
    <script src="img/site.js"></script>
  </body>
</html>
```

它是什么样子！

# 总结

在这里，我们看到了一个简单应用程序使用的基本工具，也许比`TodoMVC`函数更异想天开。目前，我们只是做一些基本的解释。

在下一章中，加入我们的待办事项清单，提供标记任务进行中、重要、有问题或其他有用的标记的方法。


# 第九章：使用实时示例演示 JavaScript 中的函数式响应式编程第 II 部分 - 待办事项列表

在本章中，我们将演示一个待办事项列表。这个待办事项列表将说明一种略微晦涩的双向数据绑定。ReactJS 的长处是通过单向数据绑定，大多数问题都可以按照惯用的 ReactJS 方式解决，通常会遵循冯·诺伊曼模型的单向数据绑定（据称通常不需要双向数据绑定，而《AngularJS：坏处》等文章表明，双向绑定默认情况下带来了沉重的代价，特别是在扩展方面）。

如果我们以一种明显的方式构建待办事项列表，复选框将无响应。我们可以点击它们任意次数，但它们永远不会被选中，因为单向数据绑定使用 props 或者在我们的情况下，状态来确定它们是否被选中。我们将尝试双向数据绑定，这意味着复选框不仅是活动的，而且点击复选框还会更新状态。这意味着用户界面中显示的内容和作为状态的幕后内容是相互同步的。

待办事项列表作为一个独特的特性，提供的不仅仅是**已完成**或**未完成**的状态。它还有**重要**、**进行中**、**问题**等复选框。

本章将演示以下内容：

+   使用插件的要领

+   设置适当的初始状态

+   使`TEXTAREA`中的文本可编辑

+   执行一些繁重工作的`render()`函数

+   `render()`使用的内部函数

+   构建表格以显示

+   渲染我们的结果

+   在视觉上区分列

# 向我们的应用程序添加待办事项列表

在上一章中，您实现了一个`YouPick`占位符，用于创建自己的应用程序。在这里，我们将对其进行注释，以便仅显示我们的待办事项应用程序（我们可以，而且我们将在屏幕的不同部分安排事物，但现在我们一次只显示一件事物）。在 JSX 中，注释掉代码的方法是将其包装在 C 风格的多行注释中，然后将其包装在花括号中，因此`<YouPick />`变成了{/* <YouPick /> */}：

```js
  var Pragmatometer = React.createClass(
    {
    render: function()
      {
      return (
        <div className="Pragmatometer">
        <Calendar />
        <Todo />
        <Scratch />
        {/* <YouPick /> */}
        </div>
      );
    }
  }
);
```

## 在我们的项目中包括 ReactJS 插件

我们将打开`Todo`类并包括`React.addons.LinkedStateMixin`函数。请注意，我们在这里使用了一个插件，这意味着当我们在页面中包含 ReactJS 时，我们需要包含一个包含插件的构建。因此，请考虑这一行：

```js
//cdnjs.cloudflare.com/ajax/libs/react/0.13.3/react.min.js
```

我们包括以下内容：

```js
//cdnjs.cloudflare.com/ajax/libs/react/0.13.3/react-with-addons.min.js
```

`Todo`类的开头如下所示：

```js
  var Todo = React.createClass(
    {
      mixins: [React.addons.LinkedStateMixin],
```

## 设置适当的初始状态

初始状态为空；列表中没有待办事项，新的待办事项文本也为空：

```js
      getInitialState: function()
      {
        return {
          'items': [],
          'text': ''
        };
      },
```

请注意，一些初始状态设置可能涉及繁重的工作；在这里，它非常简单，但情况并非总是如此。

## 使文本可编辑

作为一个小的清理细节，当有人在框中输入时，我们希望行为明显。因此，我们为 TEXTAREA 定义了双向数据绑定，这样如果有人在 TEXTAREA 中输入，更改将被添加到状态中，并溢出回到 TEXTAREA 中：

```js
      onChange: function(event)
      {
        this.setState({text: event.target.value});
      },
```

如果有人在输入一些文本后点击**提交**按钮提交新的待办事项，我们将该项目添加到列表中：

```js
      handleSubmit: function(event)
      {
        event.preventDefault();
        var new_item = get_todo_item();
        new_item.description = this.state.text;
        this.state.items.push(new_item);
        var next_text = '';
        this.setState({text: next_text});
      },
```

## `render()`的繁重工作

`render()`函数稍微复杂，包含内部函数和基于双向数据绑定的响应式用户界面的大部分繁重工作。在其中，我们使用了`var that=this;`模式，这在大多数 ReactJS 代码中都是不存在的。在大多数 ReactJS 中，我们可以直接使用 this，它会自动工作；在这里，我们正在定义不像其他 ReactJS 函数那样直接构建的内部函数，并保留对 this 对象的引用：

```js
      render: function()
      {
        var that = this;
        var table_rows = [];
```

## 用于渲染的内部函数

`table_rows`数组将保存待办事项。定义了这些之后，我们定义了我们的第一个内部匿名函数`handle_change()`。如果用户点击待办事项的复选框之一，我们提取 HTML ID，该 ID 告诉它的待办事项 ID，以及已切换的字段（即复选框标识符）：

```js
        var handle_change = function(event)
        {
          var address = event.target.id.split('.', 2);
          (that.state.items[parseInt(address[0])][address[1]] = !that.state.items[parseInt(address[0])][address[1]]);
        };
```

`display_item_details()`函数是用于构建显示的几个函数中最低级的一个。它构建了一个包含复选框的单个 TD：

```js
      var display_item_details = function(label, item)
          {
          var html_id = item.id + '.' + label;
        return ( <td className={label} title={label}>
            <input onChange={handle_change} 
              id={html_id} className={label} type="checkbox" checked={item[label]} />
          </td>
        );
      };
```

接下来，`display_item()`使用这些构建块来构建待办事项的显示。除了包括渲染的节点，也就是复选框，它还对框中的文本应用了 Markdown 格式：

```js
      var display_item = function(item)
      {
        var rendered_nodes = [];
        for(var index = 0; index < todo_item_names.length;
        index += 1) {
          rendered_nodes.push(
            display_item_details(todo_item_names[index], item)
          );
        }
        return ( <tr>
          {rendered_nodes}
          <td dangerouslySetInnerHTML={{__html:
          converter.makeHtml(item.description)}} />
        </tr>
        );
      };
```

## 构建结果表

对于每个项目，我们添加一个表格行：

```js
      table_rows.push(
      <tr>{this.state.items.map(display_item)}</tr>);
```

最后，返回一个包含到目前为止计算的各种值的 JSX 表达式，并将它们包装在一个功能齐全的表格中：

```js
      return (
        <form onSubmit={this.handleSubmit}>
          <table>
            <thead>
              <tr>
                <th>To do</th>
              </tr>
            </thead>
            <tbody>
              {table_rows}
            </tbody>
            <tfoot>
              <textarea onChange={this.onChange}
              value={this.state.text}></textarea><br />
              <button>{'Add activity'}</button>
            </tfoot>
          </table>
        </form>
      );
    }
  }
);
```

当选中应该隐藏和显示它们的复选框时，将数据行隐藏和显示是留给你作为练习的。

### 提示

关于表格的使用，这里有一个简短的备注：从主要使用表格转变为主要使用 CSS 进行格式化。然而，关于表格使用的确切规则并不是完全“根本不使用表格”或者“只有在确实必须使用表格时才使用”，而是“用于表格数据的表格”。这意味着像我们这里显示的网格。具有复选框网格的表格是表格在当前标记中完全适当的一个很好的例子。

## 呈现我们的结果

我们只有在告诉它时，结果才会呈现出来；这可以被视为一种繁琐，也可以被视为我们端的一种额外自由度。在结束闭包之前，我们写下了这个：

```js
var update = function()
{
  React.render(<Pragmatometer />,
  document.getElementById('main'));
};
update();
var update_interval = setInterval(update, 100);
```

## 视觉上区分列

目前，我们的未区分的复选框网格混在一起。我们可以做一些事情来区分它们。`index.html`中的 CSS 中的一系列颜色将它们区分开来：

```js
      td.Completed {
        border-left: 3px solid black;
        background-color: white;
      }
      td.Delete {
        background-color: gray;
      }
      td.Invisible
      {
        background-color: black;
      }
      td.Background
      {
        background-color: #604000;
      }
      td.You.Decide
      {
        background-color: blue;
      }
      td.In.Progress
      {
        background-color: #00ff00;
      }
      td.Important
      {
        background-color: yellow;
      }
      td.In.Question
      {
        background-color: darkorange;
      }
      td.Problems
      {
        background-color: red;
      }
```

# 摘要

在本章中，我们漫游了一个略微超过最小限度的待办事项列表。就功能而言，我们看到了一个以包括双向数据绑定的方式构建的交互式表单。ReactJS 通常建议，大多数情况下，你认为你需要双向数据绑定，但你真的最好只使用单向数据绑定。然而，该框架似乎并不打算作为一种约束，当 ReactJS 说，“你通常不应该做 X”时，是有办法做 X 的。对于`dangerouslySetInnerHTML`和双向数据绑定，你可以在特定点选择使用它，但已经尽一切努力选择更好的工程。`dangerouslySetInnerHTML`函数是一种非常有力的命名方式，ReactJS 团队明确表达的观点是冯·诺伊曼模型要求至少在大多数情况下使用单向数据绑定。然而，ReactJS 的哲学明确允许开发人员使用他们认为最好通常要避免的功能；最终的裁决权在你手中。

在我们下一章中，加入我们，我们将创建一个优雅处理重复预约的日历应用程序。


# 第十章：在 JavaScript 中演示函数式响应式编程：一个实时示例第 III 部分-日历

本章将是本书中最复杂的部分。在整本书中，各章之间存在着从轻微到不那么轻微的差异。这些差异是有意为之的，以便如果你在岔路口遇到了困难，本书可以覆盖两种选择。这些章节旨在相辅相成，而不是一直强调同一点。在这里，我们不会透露关于核心 ReactJS 的更多信息，而是展示如何应对现实世界中棘手的商业问题，以及一个涉及 ReactJS 但并非专注于它的解决方案。我们将在一个更严肃的应用程序中使用 ReactJS，一个支持重复事件的日历，提供的功能和能力比如 Google 日历更加复杂和强大，如下图所示。*如果你每个月第二和第四个星期四晚上 7:00 有 Toastmasters 俱乐部会议，这个日历都支持！*核心功能的目的绝不是玩具。

在本章中，我们将讨论以下几点：

+   了解具有重复日历条目的日历

+   一个类及其 Hijaxed 形式的要点

+   基本数据类型-普通的 JavaScript 对象

+   一个渲染函数-外部包装器

+   渲染页面-一次性日历条目 UI

+   重复日历条目的扩展用户界面

+   渲染日历条目-匿名辅助函数

+   显示日历条目的主循环

+   对每天的日历条目进行排序以显示

+   支持日历条目描述中的 Markdown

+   一次只处理一个主要组件

# 再来一次山姆-一个有趣的挑战

以下是一个示例屏幕截图，显示了如何在 Google 日历中输入重复条目：

![再来一次山姆-一个有趣的挑战](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_01.jpg)

这个日历系统受到了一个使用正则表达式匹配日期字符串的私人日历系统的启发，就像这样：`Wed Apr 29 18:13:24 CDT`。此外，使用正则表达式确实可以做很多事情。例如，*每个偶数月的第一个星期六*的*检查汽车发动机液体*条目是`periodic_Sat.(Feb|Apr|Jun|Aug|Oct|Dec).( 1| 2| 3| 4| 5| 6| 7)..................,Check fluid levels in car`。然而，这与一个真正复杂的正则表达式相比微不足道。但这确实暗示了为什么正则表达式被认为是只能写不能读的代码。可以猜测，即使你是一个正则表达式的作者，你也会推迟检查（如果必须的话）。换句话说，你不想检查之前段落中引用的正则表达式是否匹配偶数月的第一个星期六的日期。这就是正则表达式对程序员的影响，而这个正则表达式与 URL 正则表达式相比是优雅的，URL 正则表达式是这样开始的：

```js
~(?:\b[a-z\d.-]+://[^<>\s]+|\b(?:(?:(?:[^\s!@#$%^&*()_=+[\]{}\|;:'
```

本章的代码旨在可读性，有时会慢慢地费力地，但非常清晰，没有任何正则表达式的痕迹。有人说程序员遇到字符串问题时会说：“我知道！我会用正则表达式！”现在程序员有了两个问题。

根据我的经验，我多年来一直在使用正则表达式，它们无疑是我最有效的缺陷注入方法，而且我经常第一次就搞错简单的正则表达式。这就是为什么我和其他人一样，不再看好正则表达式。

默认情况下，该程序为输入一次性日历条目提供了一个相对简单的用户界面。

以下是我们程序的用户界面的屏幕截图，最初呈现的样子，没有深入了解重复日历条目的各种选项：

![再来一次山姆-一个有趣的挑战](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_02.jpg)

渐进式披露为重复日历条目保留了更详细的组合，如果用户选择查看它们，则显示了重复日历条目的附加控件。

以下是用于重复日历条目的更高级界面的屏幕截图。由于重复日历条目通常以几种不同的方式组织，因此提供了几个控件。

![再来一次山姆-一个有趣的挑战](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_03.jpg)

# 经典的 Hijaxing 效果很好

当我们打开这个类时，一个成员因其缺席而显眼——`mixins: [React.addons.LinkedStateMixin]`。这个成员在我们之前的章节中大量出现，我们在那里介绍了表单字段之间的双向数据绑定，我们指定了 HTML 字段/JSX 组件的值，以及这个补充实现，其中表单不受控制（值未指定）。在这里，表单元素以旧式方式查询，因为它们是需要的。虽然 ReactJS 坚信单向数据绑定应该是规范，但双向数据绑定也是合法的，最好是在一个小而隔离的区域内。这一章和之前的章节旨在提供两种略有不同的方法的工作示例，以便为您提供一个参考：

```js
var Calendar = React.createClass({
```

`getInitialState（）`函数初始化了两个项目。一个是日历条目的列表。另一个是一个患者，手术进行中，直到手术完成并可以添加到活动条目列表中。

有两种类型的条目：一个较小的基本条目，只给出一次性日历条目的日期，另一个是更大、更复杂的条目，提供了重复系列日历条目所需的更完整信息。另一种实现可能会将它们保存在单独的列表中；在这里，我们使用一个列表，并检查单个条目，以查看它们是否具有“重复”字段，这是重复系列具有的，而一次性日历条目则没有：

```js
  getInitialState: function() {
    return {entries: [], entry_being_added: this.new_entry()};
  },
```

`handle_submit（）`函数劫持了表单提交，获取手术台上的条目并填写其字段，无论是一次性日历条目还是系列。然后将条目添加到条目列表中并重置表单（直接`reset（）`表单会更简单，但这提供了稍微更精细的控制，更新默认日期为今天的日期，以便表单的`reset（）`不会总是将页面最初加载的日期重置）。

条目的性质是公式化的——都是普通的旧 JavaScript 对象，易于 JSON 序列化——本质上是包含字符串、整数和布尔值的字典（在两种情况下，条目还包含其他包含字符串和整数的字典）。这里没有使用闭包或其他更复杂的技术；设计意在简单到足以让某人仔细阅读`handle_submit（）`并准确知道一次性和重复日历条目是如何表示的。

`handle_submit（）`函数从表单中提取信息，判断它代表一次性还是重复的日历条目：

```js
  handle_submit: function(event) {
    event.preventDefault();
    (this.state.entry_being_added.month =
      parseInt(document.getElementById('month').value));
    (this.state.entry_being_added.date =
      parseInt(document.getElementById('date').value));
    (this.state.entry_being_added.year =
      parseInt(document.getElementById('year').value));
    if (document.getElementById('all_day').checked) {
      this.state.entry_being_added.all_day = true;
    }
    (this.state.entry_being_added.description =
      document.getElementById('description').value);
    if (this.state.entry_being_added.hasOwnProperty('repeats') 
    && this.state.entry_being_added.repeats) {
      (this.state.entry_being_added.start.time =
        this.state.entry_being_added.time);
```

最后，将从表单中读取的条目添加到活动条目列表中，并为进一步的数据输入放置一个新的条目：

```js
      var old_entry = this.state.entry_being_added;
      this.state.entries.push(this.state.entry_being_added);
      this.state.entry_being_added = this.new_entry();
      var entry = this.new_entry();
      (document.getElementById('month').value =
        entry.month.toString());
      (document.getElementById('date').value =
        entry.date.toString());
      (document.getElementById('year').value =
        entry.year.toString());
      document.getElementById('all_day').checked = false;
      document.getElementById('description').value = '';
      document.getElementById('advanced').checked = false;
      if (old_entry.hasOwnProperty('repeats') &&
        old_entry.repeats) {
        (document.getElementById('month_based_frequency').value =
          'Every');
        document.getElementById('month_occurrence').value = '-1';
        document.getElementById('series_ends').checked = false;
        (document.getElementById('end_month').value = 
          '' + new Date().getMonth());
        (document.getElementById('end_date').value = 
          '' + new Date().getDate());
        (document.getElementById('end_year').value =
          '' + new Date().getFullYear() + 1);
      }
    },
```

在这里，我们创建一个新条目。这将是一个一次性的日历条目，如果需要，稍后可以扩展为代表系列。

以下是一个显示了一次性事件的日历的屏幕截图：

![经典 Hijaxing 效果很好](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_07.jpg)

# 考虑到可用性，但仍有增长空间

这里有一点可能会解释代码中的一个令人困惑的地方：输入中表示的时间单位并不是要表示 JavaScript 日期对象表示的所有内容，而是要最大限度地与 JavaScript 日期对象兼容。这意味着，特别是一些令程序员困惑的设计在我们的代码中得到了容纳，因为 JavaScript 日期对象将一个月的日期从 1 到 31 进行编号，就像一般的日历使用一样，但月份从 0（一月）到 11（十二月）表示。同样，日期对象中的小时范围是从 0 到 23。

这个函数在功能上是一个构造函数，但它并不是为了使用 new 关键字而设计的，因为整个构造函数和 `this` 是 Crockford 在 *The Better Parts* 中不再包括的东西，他在创建 AdSafe 后试图按照自己的建议行事，禁止使用 `this` 关键字出于安全原因。他发现他的代码变得更小更好。在 ReactJS 中，使用 `this` 构建的代码是不可妥协的，但当我们不需要时，可以选择退出。

还有一个特定的绕道，一些更敏锐的读者可能会注意到：初始小时设置为 12，而不是 0。那些说不允许用户首先输入无效数据的学校，可能会导致可用性上的一些“反模式”。考虑一下值得耻辱的界面，用于输入美国社会安全号码，这种情况可能很少发生，也不是因为你需要一个机构范围的标识符。

下一个截图显示了也许是确保以适当格式输入（可能是）美国社会安全号码的最糟糕的方式，从可用性和用户界面的角度来看：

![考虑到可用性，但仍有改进空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_04.jpg)

这个用户界面不合适；一个更好的方法是允许文本输入，使用 JavaScript 强制精确的九位数字，并简单地忽略连字符（最好也忽略其他非数字字符）。

这个界面的实现代表了仔细的思考，但在可用性方面存在一些妥协，一个好的实验室可能会对其进行改进（这里的圣杯是有一个文本字段，用户在其中输入时间，系统自动使用启发式方法来识别实际意思，但该系统可能难以确定日历条目是否安排在上午 8 点还是下午 8 点）。在输入小时后立即放置上午或下午，并放在同一个输入框中，违反了最少惊讶原则，该原则认为无论软件做什么，都应该尽量减少用户的惊讶。通常预期的方法是为小时设置一个字段，为分钟设置一个字段，为上午或下午设置一个字段。但根据默认值的不同，这允许有中午约定的人输入 3 小时，15 分钟，并单击**保存**，结果却得到了一个安排在上午 3:15 的约会。错误仍然可能发生，但所采用的设计意在帮助人们在一天中的中间开始，并更有可能输入他们真正想要的小时。

以下截图显示了我们程序的默认用户界面，没有为用户界面添加控件。它显示了一天中的小时下拉菜单，旨在作为一个合理的默认值，并减少用户输入时间时出现上午或下午的错误：

![考虑到可用性，但仍有改进空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_05.jpg)

界面上的一个可用性改进是使用文本字段而不是分钟下拉菜单，使用 JavaScript 验证，强制执行从 0 到 59 的整数值，可能是单个数字值之前的前导零。

但是让我们从默认的开始时间移动到其他时间。

以下是具有一次性事件和重复事件的日历示例：

![考虑到可用性，但仍有改进的空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_09.jpg)

# 只需简单的 JavaScript 对象

让我们看一下以下代码：

```js
    new_entry: function() {
      var result = {};
      result.hours = 12;
      result.minutes = 0;
      result.month = new Date().getMonth();
      result.date = new Date().getDate();
      result.year = new Date().getFullYear();
      result.weekday = new Date().getDay();
      result.description = '';
      return result;
    },
```

对于一次性日历条目，字段的使用方式与您可能期望的一样。对于一系列日历条目，日期不再是日历条目发生的时间，而是开始的时间。用户界面提供了几种可能缩小日历条目发生时间的方法。这可以说是每个月的第一个，仅限星期二，以及特定月份。每次选择都会进一步缩小范围，因此期望的用法是足够具体，以请求您想要的行为。

这里的大多数变量名都是自解释的。可能需要解释的两个变量是`frequency`和`month_occurrences`。`frequency`变量的值为`Every`、`Every First`、`Every Second`、`Every Third`、`Every Fourth`、`Every Last`、`Every First and Third`和`Every Second and Fourth`（这是网络应用程序的一部分，适应您 Toastmasters 每个第二和第四个星期四晚上 7:00 的会议）。`month_occurrences`变量指定某事发生的月份（根据 JavaScript Date 对象为 1 月到 12 月的 0 到 11，或-1 表示每个月）：

```js
    new_series_entry: function() {
      var result = this.new_entry();
      result.repeats = true;
      result.start = {};
      result.start.hours = null;
      result.start.minutes = null;
      result.start.month = new Date().getMonth();
      result.start.date = new Date().getDate();
      result.start.year = new Date().getFullYear();
      result.frequency = null;
      result.sunday = false;
      result.monday = false;
      result.tuesday = false;
      result.wednesday = false;
      result.thursday = false;
      result.friday = false;
      result.saturday = false;
      result.month_occurrence = -1;
      result.end = {};
      result.end.time = null;
      result.end.month = null;
      result.end.date = null;
      result.end.year = null;
      return result;
    },
```

以下是显示每隔一周重复一次的活动的屏幕截图：

![只需简单的 JavaScript 对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_08.jpg)

# 从简单开始的渐进式披露

当复选框用于重复日历条目被选中时，将调用`on_change()`函数，并且它允许渐进式披露，如果用户选择它们，则显示重复日历条目的整个用户界面。它切换`this.state.entry_being_added.repeats`，这受到`render()`函数的尊重。如果当前正在操作的条目具有`repeats`字段，并且为 true，则此函数将显示附加的表单区域。如果条目没有`repeats`字段，则会创建一个新系列，已经输入的任何时间数据都会被复制，然后将新的（部分）空白条目放在操作表上：

```js
    on_change: function() {
      if (this.state.entry_being_added.hasOwnProperty('repeats') {
        (this.state.entry_being_added.repeats =
          !this.state.entry_being_added.repeats);
      } else {
        var new_entry = this.new_series_entry();
        new_entry.time = this.state.entry_being_added.time;
        new_entry.month = this.state.entry_being_added.month;
        new_entry.date = this.state.entry_being_added.date;
        new_entry.year = this.state.entry_being_added.year;
        this.state.entry_being_added = new_entry;
      }
    },
```

以下屏幕截图显示了界面中每隔一周发生的事件：

![从简单开始的渐进式披露](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_09.jpg)

# render()方法可以轻松地委托

（外部）`render`函数更像是一个包装器而不是一个工作马。它显示了属于一次性日历条目和系列的日历条目的字段。此外，如果正在操作的日历条目是重复的日历条目（仅当指示重复的日历条目的复选框被选中时才为真），此函数将包括适用于重复日历条目的附加表单元素：

### 提示

JSX 语法出人意料地宽容。但是，它确实有一些规则，并且通过描述性错误消息来执行这些规则，包括如果有多个元素，它们需要被包裹在一个封闭的元素中。因此，您不会写`<em>Hello</em>, <strong>world</strong>!`。相反，您会写`<span><em>Hello</em>, <strong>world</strong>!</span>`。但是在一些其他基本规则的情况下，JSX 将为广泛的用途和滥用做正确的事情。

这是一个`render()`方法，对于您定义的任何组件来说都是一个中心方法。在某些情况下，`render()`方法不会是单一的，而是会将其一些或全部工作委托给其他方法。让我们来探讨一下：

```js
    render: function() {
      var result = [this.render_basic_entry(
        this.state.entry_being_added)];
      if (this.state.entry_being_added &&
        this.state.entry_being_added.hasOwnProperty('repeats')
        this.state.entry_being_added.repeats) {
        result.push(this.render_entry_additionals(
          this.state.entry_being_added));
      }
      return (<div id="Calendar">
        <h1>Calendar</h1>
        {this.render_upcoming()}<form onSubmit={
        this.handle_submit}>{result}
        <input type="submit" value="Save" /></form></div>);
    },
```

# 无聊的代码比有趣的代码更好！

熟悉特里·普拉切特的读者可能已经听说过《有趣的时代》，它以一个被误归于中国的城市传说开篇：有一种诅咒。他们说：愿你生活在有趣的时代！其中一个角色，林斯温德（这不是一种奶酪），一直在追求无聊的事物，但无聊正是他从未得到的。书中的情节之一是林斯温德被骗去生活在一个偏僻、无聊的热带岛屿，然后被转移到一个繁荣的帝国，那里发生了各种各样与他有关的有趣的事情。对于林斯温德来说，无聊就像一个圣杯，总是从他手中溜走。

这段代码的目的是*无聊*，就像林斯温德一样。可以编写更简洁的代码，用`hour_options`来填充哈希（或数组），而不是直接指定数组。但这样做不容易检查它是对还是错。以这种方式开发并不意味着额外的输入，（专家意见已经认识到）在编程中并不是真正的瓶颈。

以下代码的工作原理基本上是定义数组，然后使用这些数组来创建/形成元素（大部分是从数组中直接填充的`SELECT`）。它的任务是显示一次性日历条目的用户界面（以及复选框，表示重复的日历条目）。

在本章中，我们有意决定以无聊的方式做事，只有一个例外——填充所需月份天数的菜单。这可以是 28、29、30 或 31 天。我们展示了生成小时下拉菜单的代码；分钟（和月份）是同一模式的更简单的例子。

### 注意

在本章的编写过程中，没有程序员的手腕受到伤害（实际上并没有那么多的输入或开发时间）。

# 一个简单的用户界面，用于非重复条目...

对于更基本的日历条目类型，即只发生一次的类型，我们收集日期、月份和年份，默认为当前日期的值。有些事情是“全天”事件，比如某人的生日；其他事件从特定时间开始。界面可能会扩展，以包括可选的结束时间。这个功能将是这里展示的原则的延伸。

我们开始看到呈现基本条目的用户界面：

```js
    render_basic_entry: function(entry) {
      var result = [];
      var all_day = false;
      var hour_options = [[0, '12AM'],
        [1, '1AM'],
        [2, '2AM'],
        [3, '3AM'],
        [4, '4AM'],
        [5, '5AM'],
        [6, '6AM'],
        [7, '7AM'],
        [8, '8AM'],
        [9, '9AM'],
        [10, '10AM'],
        [11, '11AM'],
        [12, '12PM'],
        [13, '1PM'],
        [14, '2PM'],
        [15, '3PM'],
        [16, '4PM'],
        [17, '5PM'],
        [18, '6PM'],
        [19, '7PM'],
        [20, '8PM'],
        [21, '9PM'],
        [22, '10PM'],
        [23, '11PM']];
      var hours = [];
      for(var index = 0; index < hour_options.length; ++index) {
        hours.push(<option
          value={hour_options[index][0]}
          >{hour_options[index][1]}</option>);
    }
```

这里的 JSX 与我们之前看到的其他 JSX 类似；它是为了加强在这种情况下的体验：

```js
    result.push(<li><input type="checkbox" name="all_day"
    id="all_day" />All day event.
    &nbsp;<strong>—or—</strong>&nbsp;
    <select id="hours" id="hours"
    defaultValue="12">{hours}</select>:
    <select id="minutes" id="minutes"
    defaultValue="0">{minutes}</select></li>);
```

我们使用下拉菜单让用户选择一个月中的日期，并尝试提供一个更好的选择，而不是让用户在 1 日到 31 日之间选择（用户不应该被要求知道哪些月份有 30 天）。我们查询表单的月份下拉菜单，以获取当前选择的月份。提醒一下，我们的目标是与 JavaScript 的 Date 对象兼容，虽然 JavaScript 的 Date 对象可以有一个从 1 到 31 的基于 1 的日期值，但月份值是基于 0 的，从 0（一月）到 11（十二月），我们遵循这个规则：

```js
      var days_in_month = null;
      if (entry && entry.hasOwnProperty('month')) {
        var month = entry.month;
        if (document.getElementById('month')) {
          month = parseInt(
            document.getElementById('month').value);
        }
        if (month === 0 || month === 2 || month === 4 || month
          === 6 || month === 7 || month === 9 || month === 11) {
          days_in_month = 31;
        } else if (month === 1) {
          if (entry && entry.hasOwnProperty('year') && entry.year
            % 4 === 0) {
            days_in_month = 29;
          } else {
            days_in_month = 28;
          }
        } else {
          days_in_month = 30;
        }
      }
      var date_options = [];
      for(var index = 1; index <= days_in_month; index += 1) {
        date_options.push([index, index.toString()]);
      }
      var dates = [];
      for(var index = 0; index < date_options.length; ++index) {
        dates.push(<option value={date_options[index][0]}
          >{date_options[index][1]}</option>);
      }
      result.push(<li>Date: <select id="date" name="date"
        defaultValue={entry.date}>{dates}</select></li>);
      var year_options = [];
      for(var index = new Date().getFullYear(); index < new
        Date().getFullYear() + 100; ++index) {
        year_options.push([index, index.toString()]);
      }
      var years = [];
      for(var index = 0; index < year_options.length; ++index) {
        years.push(<option value={year_options[index][0]}
          >{year_options[index][1]}</option>);
      }
      result.push(<li>Year: <select id="year" name="year"
        defaultValue={entry.years}>{years}</select></li>);
      result.push(<li>Description: <input type="text"
        name="description" id="description" /></li>);
      result.push(<li><input type="checkbox" name="advanced"
        id="advanced" onChange={this.on_change} />
        Recurring event</li>);
      result.push(<li><input type="submit" value="Save" /></li>);
      return <ul>{result}</ul>;
    },
```

# 用户仍然可以选择更多

这种方法与之前的方法类似，但显示了整个重复日历条目的界面。它展示了主题的进一步变化。

当前的实现选择了所有限制条件的交集，对于重复的日历条目来说已经足够了。

`frequency_options`函数的填充方式与其他字段略有不同；虽然这也可以用日期选项来完成，但`SELECT`是以`<option>description</option>`的格式填充，而不是（通常是次要的）`<option value="code">description</option>`的格式。

```js
    render_entry_additionals: function(entry) {
      var result = [];
      result.push(<li><input type="checkbox" 
        name="yearly" id="yearly"> This day,
        every year.</li>);
      var frequency = [];
      var frequency_options = ['Every',
        'Every First',
        'Every Second',
        'Every Third',
        'Every Fourth',
        'Every Last',
        'Every First and Third',
        'Every Second and Fourth'];
      for(var index = 0; index < frequency_options.length;
        ++index) {
        frequency.push(<option>{frequency_options[index]}
          </option>);
      }
```

工作日很简单，即使它们打破了填充 `SELECT` 的模式，在复选框更明显的输入类型的情况下。选择一天的单选按钮也是可以想象的，但我们试图适应更多的用例，一个包含重复星期二和星期四或重复星期一、三和五的日历条目是常见的。此外，这些并不是发生一周多次的唯一模式（如果一个大学生使用我们的程序不必为每周多次上课而做多次输入，那将是很好的）：

```js
result.push(<li><select name="month_based_frequency"
        id="month_based_frequency" defaultValue="0"
        >{frequency}</select></li>);
      var weekdays = [];
      var weekday_options = ['Sunday', 'Monday', 'Tuesday',
        'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      for(var index = 0; index < weekday_options.length; ++index) {
        var checked = false;
        if (entry && entry.hasOwnProperty(
          weekday_options[index].toLowerCase()) &&
          entry[weekday_options[index].toLowerCase()]) {
          checked = true;
        }
        weekdays.push(<span><input type="checkbox"
          name={weekday_options[index].toLowerCase()}
          id={weekday_options[index].toLowerCase()}
          defaultChecked={checked} />
          {weekday_options[index]}</span>);
        }
      }
      result.push(<li>{weekdays}</li>);
```

# 避免聪明

让我们看一个微妙之处（在浏览代码时不太明显，但在查看用户界面时很明显）：有两个单独的下拉菜单，它们有自己的填充数组来表示月份。这样做的原因是，在某种情况下，不仅可以在特定月份之间进行选择，还可以在指定一个月份和所有月份之间进行选择。该菜单包括一个 `[-1, "每月"]` 的选项。

另一个示例是一系列日历条目的（可选指定的）结束日期。这是一个使用情况，指定每个月结束的情况并不是真的有意义。预期的用法是给出停止显示的日期、月份和年份。这两种用例的组合形成了两种单独的、非模板式的选择月份的方式。更专有的可以从更包容的中得到，使用 `array.slice(1)` 函数，但我们再次选择了 Rincewind 风格的无聊代码：

```js
      var month_occurrences = [[0, 'January'],
        [1, 'February'],
        [2, 'March'],
        [3, 'April'],
        [4, 'May'],
        [5, 'June'],
        [6, 'July'],
        [7, 'August'],
        [8, 'September'],
        [9, 'October'],
        [10, 'November'],
        [11, 'December']];
      var month_occurrences_with_all = [[-1, 'Every Month'],
        [0, 'January'],
        [1, 'February'],
        [2, 'March'],
        [3, 'April'],
        [4, 'May'],
        [5, 'June'],
        [6, 'July'],
        [7, 'August'],
        [8, 'September'],
        [9, 'October'],
        [10, 'November'],
        [11, 'December']];
```

这些都被嵌入到用户界面中的两个单独的数组中，慢慢地构建成日历“逐步”包括最后一个选项，一个复选框，用于标记重复的日历条目在特定日期结束，并指定它结束的日期、月份和年份的字段，利用前两个数组中的第一个：

```js
      result.push(<li>Ends on (optional): <input type="checkbox"
        name="series_ends" id="series_ends" /><ul><li>Month:
        <select id="end_month" name="end_month"
        defaultValue={month}>{months}</select></li>
        <li>End date:<select id="end_date"
        name="end_date" defaultValue={entry.date}
        >{dates}</select></li>
        <li>End year:<select id="end_year"
        name="end_year" defaultValue={entry.end_year + 1}
        >{years}</select></li></ul></li>);
      return <ul>{result}</ul>;
    },
```

前两个主要方法是为用户输入数据构建表单。下一个方法在某种程度上转变了方向；它被设置为从当前日期到最后一个一次性日历条目的一年后显示即将到来的日历条目。

# 匿名辅助函数可能缺乏小精灵的魔尘

在内部，日历条目被分为一次性和重复的日历条目。过早的优化可能是一切罪恶的根源，但是当在其他系统上处理日历时，查看每天的每个日历条目的性能特征更差，大约是 *O(n * m)*，而不是这里所显示的轻微的注意，接近 *O(n + m)*。日历条目显示为 H2 和 UL，每个都有一个 CSS 类来方便样式化（目前，项目将这部分作为未经样式化的空白画布）：

```js
    render_upcoming: function() {
      var that = this;
      var result = [];
```

### 注意

这段代码与我们迄今为止看到的示例不同，使用了 `var that = this;` 的黑客技巧。一般来说，ReactJS 保证 `this` 随时可用，而不仅仅是在函数首次运行时。然而，ReactJS 不能保证内部函数会像顶层方法一样具有相同的优势，一般来说，如果你可以在顶层方法中不使用至少一些 ReactJS 的小精灵魔尘，可能会建议你只在顶层方法中使用内部函数。内部函数在这里被用作分离的比较器，例如。它们不直接与 ReactJS 交互，并且在直接与 ReactJS 交互方面受到限制。

在这里，我们有一个比较器。它被写成无聊的，就像这个方法的其他部分一样；更简洁的替代方案是随时可用的，但会失去沉闷的“Rincewind-无聊”清晰度：

```js
      var compare = function(first, second) {
        if (first.year > second.year) {
          return 1;
        } else if (first.year === second.year && first.month >
          second.month) {
          return 1;
        } else if (first.year === second.year && first.month ===
          second.month && first.date > second.date) {
          return 1;
        } else if (first.year === second.year && first.month ===
          second.month && first.date === second.date) {
          return 0;
        } else {
          return -1;
        }
      }
```

`successor()` 函数使用修改后的一次性条目来表示日期。这些条目保留了日期、月份、年份，以及一天后的未来天数。原始条目作为一天使用时，将天数（`0`）添加为成员。

设计的另一个方面是避免创建函数，以至于它们没有分配给变量。`successor()`函数是为`for`循环编写的，类似于`for(var index = 0; index < limit; ++index)`循环，它可以内联完成，但这样做会比将其提取到自己的函数中清晰得多（也会更无聊）。对于两行的匿名函数可能不需要这样做，但在这里，代码似乎更清晰、更无聊，`successor()`存储在它自己的变量中，名称旨在描述：

```js
      var successor = function(entry) {
        var result = that.new_entry();
        var days_in_month = null;
        if (entry.month === 0 || entry.month === 2 ||
          entry.month === 4 || entry.month === 6 ||
          entry.month === 7 || entry.month === 9 ||
          entry.month === 11) {
          days_in_month = 31;
        } else if (entry.month === 1) {
          if (entry && entry.hasOwnProperty('year') &&
            entry.year % 4 === 0) {
            days_in_month = 29;
          } else {
            days_in_month = 28;
          }
        } else {
          days_in_month = 30;
        }
        if (entry.date === days_in_month) {
          if (entry.month === 11) {
            result.year = entry.year + 1;
            result.month = 0;
          } else {
            result.year = entry.year;
            result.month = entry.month + 1;
          }
          result.date = 1;
        } else {
          result.year = entry.year;
          result.month = entry.month;
          result.date = entry.date + 1;
        }
        result.days_ahead = entry.days_ahead + 1;
        result.weekday = (entry.weekday + 1) % 7;
        return result;
      }
```

# 我们应该展示多远的未来？

“最大”函数立即存储列表中存在的最大一次日历条目的日期，然后被修改为表示将要表示的最后一天，这是在找到最大一次日历条目后的一年（如果有重复的日历条目，可能会在最后一个一次性日历条目之后呈现一些实例）：

```js
      var greatest = this.new_entry();
      for(var index = 0; index < this.state.entries.length;
        ++index) {
        var entry = this.state.entries[index];
        if (!entry.hasOwnProperty('repeats') && entry.repeats) {
          if (compare(entry, greatest) === 1) {
            greatest = this.new_entry();
            greatest.year = entry.year;
            greatest.month = entry.month;
            greatest.date = entry.date;
          }
        }
      }
```

# 不同类型的条纹代表不同的条目类型

日历条目被分为一次性和重复条目，因此每天只检查可能的少数重复日历条目。一次性日历条目被放入一个哈希中，其键直接取自其日期：

```js
      var once = {};
      var repeating = [];
      for(var index = 0; index < this.state.entries.length;
        ++index) {
        var entry = this.state.entries[index];
        if (entry.hasOwnProperty('repeats') && entry.repeats) {
          repeating.push(entry);
        } else {
          var key = (entry.date + '/' + entry.month + '/' +
            entry.year);
          if (once.hasOwnProperty(key)) {
            once[key].push(entry);
          } else {
            once[key] = [entry];
          }
        }
      }
      greatest.year += 1;
      var first_day = this.new_entry();
      first_day.days_ahead = 0;
```

# 现在我们准备好显示了！

这是前面提到的`for`循环；将`compare()`和`successor()`提取到自己的变量中并使用描述性名称，使其更易读。对于每一天，循环编译一个（可能为空）列表，从该天的一次性活动开始，并检查所有重复的日历条目。对于重复的日历条目，它开始时`accepts_this_date`为`true`，表示该日历条目确实发生在那一天，然后每个重复日期的标准都有累积的机会来表示他们正在检查的标准未达到，并否决该日历条目在那一天发生。如果一个重复的日历条目在没有任何否决的情况下通过了审查，它将被添加到该天显示的日历条目中：

```js
         for(var day = first_day; compare(day, greatest)
        === -1; day = successor(day)) {
        var activities_today = [];
        if (once.hasOwnProperty(day.date + '/' + day.month + '/' +
          day.year)) {
          activities_today = activities_today.concat(
            once[day.date + '/' + day.month + '/' + day.year]);
        }
        for(var index = 0; index < repeating.length;
          ++index) {
          var entry = repeating[index];
          var accepts_this_date = true;
          if (entry.yearly) {
            if (!(day.date === entry.start.date &&
              day.month === entry.start.month)) {
              accepts_this_date = false;
            }
          }
          if (entry.date === day.date && entry.month ===
            day.month && entry.year === day.year) {
            entry.days_ahead = day.days_ahead;
          }
          if (entry.frequency === 'Every First') {
            if (!day.date < 8) {
              accepts_this_date = false;
            }
```

# 让我们友好地按顺序排列每一天

现在，所有日历条目，包括一次性和重复的，都已经为当天准备好了。我们从全天活动开始，按字母顺序排列，然后进行特定时间发生的日历条目，按时间升序排列：

```js
          if (activities_today.length) {
            activities_logged_today = true;
            var comparator = function(first, second) {
              if (first.all_day && second.all_day) {
                if (first.description < second.description) {
                  return -1;
                } else if (first.description ===
                  second.description) {
                  return 0;
                } else {
                  return 1;
                }
              } else if (first.all_day && !second.all_day) {
                return -1;
              } else if (!first.all_day && second.all_day) {
                return 1;
              } else {
                if (first.hour < second.hour) {
                  return -1;
                } else if (first.hour > second.hour) {
                  return 1;
                } else if (first.hour === second.hour) {
                  if (first.minute < second.minute) {
                    return -1;
                  } else if (first.minute > second.minute) {
                    return -1;
                  } else {
                    if (first.hour < second.hour) {
                  return -1;
                } else if (first.hour > second.hour) {
                  return 1;
                } else if (first.hour === second.hour) {
                  if (first.minute < second.minute) {
                    return -1;
                  } else if (first.minute > second.minute) {
                    return -1;
                  }
                }
              }
            }
            activities_today.sort(comparator);
```

日期以人性化的方式显示；是“星期一”，而不是`Mon`：

```js
            if (activities_today.length)
              {
              var weekday = null;
              if (day.weekday === 0)
                {
                weekday = 'Sunday';
                }
```

# 让他们使用 Markdown！

活动的描述支持 Markdown。请注意——正如 Facebook 在`dangerouslySetInnerHTML`上的官方文档中指出的那样——我们默认信任 Showdown（提供我们的`converter`）是安全的。还存在旨在标记清理和消毒 HTML 的工具，以适合在此处安全显示 HTML 的 XSS-secure 显示方式。

我们去掉开放和关闭的`P`标签，这样描述将出现在该天有序列表给出的任何时间或其他信息的同一行上：

```js
                if (activity.all_day) {
                  rendered_activities.push(<li
                    dangerouslySetInnerHTML={{__html:
                    converter.makeHtml(activity.description)
                    .replace('<p>', '').replace('</p>', '')}}
                    />);
                } else if (activity.minutes) {
                  rendered_activities.push(<li
                    dangerouslySetInnerHTML={{__html:
                    hour_options[activity.hours][1] + ':' +
                    minute_options[activity.minutes][1] + ' ' +
                    converter.makeHtml(activity.description)
                    .replace('<p>', '').replace('</p>', '')}}
                    />);
                } else {
                  rendered_activities.push(<li
                    dangerouslySetInnerHTML={{__html:
                    hour_options[activity.hours][1] + ' ' +
                    converter.makeHtml(activity.description)
                    .replace('<p>', '').replace('</p>', '')}}
                    />);
                }
              }
              result.push(<ul className="activities">
                {rendered_activities}</ul>);
            }
          }
        }
        if (entry_displayed) {
          result.push(<hr />);
        }
        return result;
      }
    });
```

# 一次只做一件事！

最后，在顶层的`Pragmatometer`类中，我们注释掉了`Todo`的显示，这样只有这个显示在我们工作时才会显示。接下来，我们注释掉`Calendar`组件，以便在草稿本上工作，完成后，最终集成将把这些元素放在屏幕的四个角落：

```js
  var Pragmatometer = React.createClass({
    render: function() {
      return (
        <div className="Pragmatometer">
          <Calendar />
          {/* <Todo />
          <Scratch />
          <YouPick /> */}
        </div>
      );
    }
  });
```

# 启发这个日历的节日

在这里，您可以看到日历设置，并优雅地容纳了美国节日的所有节日列表：

![启发这个日历的节日](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_10_11.jpg)

每个国家都有自己的假期，并且并不是对其他国家和他们的假期表示不尊重，但我对美国的假期了解比其他国家更多，本章的方法在一定程度上是为了适应几乎所有主要假期。例外是复活节/复活节（前两天是耶稣受难日），根据一个非常特定的算法计算，但比我们在这个项目中涵盖的任何其他内容都要复杂得多，实际上，对于大多数天主教徒和新教徒，它有两种不同的算法，而对于大多数东正教徒，它有两种不同的算法。也许可以将其作为一个特例包括进来，但并不完全清楚如何创建一个通用解决方案，可以在不牺牲安全性的情况下容纳同样复杂的计算（最有希望的途径可能是允许在基于 Douglas Crockford 的 AdSafe 项目的沙箱中进行计算，这将允许在不需要牺牲整体页面安全性的情况下进行相当自由的计算）。

除了复活节和耶稣受难日，美国的主要官方假期列举如下：

+   元旦（1 月 1 日，固定）

+   马丁·路德·金纪念日（1 月的第三个星期一）

+   总统日（2 月的第三个星期一）

+   阵亡将士纪念日（5 月的最后一个星期一）

+   独立日（7 月 4 日，固定）

+   劳动节（9 月的第一个星期一）

+   哥伦布日（10 月的第二个星期一）

+   退伍军人节（11 月 11 日，固定）

+   感恩节（11 月的第四个星期四）

+   圣诞节（西方，12 月 25 日，固定）

+   除了耶稣受难日和复活节外，美国的主要官方假期列举如下：

这个系统与作为灵感的私人日历类似，旨在（除其他目的外）足够强大，可以计算浮动和固定假期（遗憾的是，复活节/复活节有复杂的例外），此外，它提供了一个非常简单的界面，可以输入列表中的每个假期，以及更多。有了现代的日历系统，美国人不会在维基百科上查找假期，并手动输入感恩节是在 11 月的第四个星期一。他们包括一个列出假期的日历。然而，这个系统足够灵活，可以让任何国家的人以非常直接的方式输入这些假期或其他遵循预期模式的假期。

# 总结

这一章的目的是提供一个在 ReactJS 上构建的用户界面的稍微复杂的示例，具有非玩具功能。我们看到了渲染代码和后端类型的功能，这使得用户界面不仅仅是表面的。这种方法旨在与上一章互补，例如，指定其值的受控输入，而不是对查询表单进行近乎经典的 Hijaxing。

### 注意

从可用性的角度来看，处理重复日历条目的用户输入的最佳方式可能并不是直接调整和增强一个复杂且有些异构的表单，就像我们在这里所做的那样。我们在这里使用的高级重复事件是向导或面试方法的一个用例。

我们看了一个使用 ReactJS 的日历系统，解决了在现实世界中遇到的混乱问题。我们有一种复杂的渲染方法。就可用性而言，ReactJS 开发人员可能应该是最敏感的（因为他们是最负责与可用性相关的开发的人），对可用性进行了关注，并始终关注用户界面可能需要改进的意识。

在这个过程中，我们看了一些乏味的代码和乏味的普通 JavaScript 对象，当我们需要记录时，它们表现得非常出色。最后，我们看了我们的日历旨在强大到足以描绘其重复事件设施的特定国家的假期。

在下一章中，让我们一起看看如何将第三方（非 ReactJS）工具整合到一个页面中，并将各种应用程序的代码集成到一起。


# 第十一章：用实例演示 JavaScript 中的函数式响应式编程，第四部分 - 添加一个草稿本并将所有内容整合在一起

在本章中，我们将涵盖最后三个努力，旨在将所有内容整合在一起，完成我们的示例 ReactJS 应用程序。早期的章节涉及使用 100％ReactJS 制作的基本定制组件。本章不同之处在于制作有效的组件，该组件在使用 ReactJS 的同时利用了一个重要的非 ReactJS 工具。

制作了最后一个组件后，我们将把它们整合到一个页面中，其中四个组件中的每一个都放在页面的一个部分。这与开发不同，开发中我们将正在开发的工具放在整个页面下。这将是本章的第二个主要部分。

到目前为止，页面还没有跟踪状态的方法。假设您在日历中输入了一个条目，待办事项，或在草稿本中做了一些笔记。然后，如果您导航离开并返回或重新加载页面，所有更改都将丢失。有一个记住更改的方法会很好，这正是我们接下来要做的。在本章的第三个，也是最后一个主要部分中，我们将介绍一种便宜的、自制的基于 HTML5 localStorage 的持久性解决方案，它的效果出奇的好。它不允许您从多台计算机访问您的数据，但现在让我们把它放在一边，只在同一台计算机上进行持久性工作。

整体应用程序旨在处理个人信息管理/后勤：任何信息的草稿本，待办事项列表，日历，以及一个用于替换为您自己设计的有趣内容的抱怨人工智能的残留部分。

# 添加一个所见即所得的草稿本，感谢 CKeditor

这里有多个所见即所得（WYSIWYG）编辑器，而选择 CKeditor 并不是 CKeditor 是免费和付费编辑器的无可争议的选择。我们将看看如何要求 ReactJS 不要干涉 DOM 的一部分（在这种情况下，不要破坏我们的 CKeditor 实例）。我们将涵盖以下主题：

+   为什么要使用像 CKeditor 这样的东西，它的工作方式与 ReactJS 不太相似？

+   安装一个“小即美”的 CKeditor 版本，看看哪个版本最好

+   在我们的页面中包含 CKeditor，重点是 JSX

## 将所有内容整合到一个网页中

我们几乎做完了所有的事情。我们将涵盖以下主题：

+   调整 JSX，以便现在所有我们的功能都是未注释的。这是一个非常简单的步骤。

+   CSS 样式让一切都适合。我们将组件排列在 2x2 的网格中，但这可以被几乎任何适合在页面上放置组件的样式方法所替代。

+   引入显示组件的基本数据持久性。这将包括一些基本的、非穷尽的 CSS 工作。

+   为了提供一个完整的示例应用程序，我们一直在开发的面向用户界面的应用程序将在您的计算机上包含基本的持久性，本例中谦逊地使用 HTML5 localStorage 实现。这意味着一个计算机，无需登录或其他麻烦，将能够持久地使用数据。

+   一些简单的`JSON.stringify()`调用可以为更常见的远程、基于服务器的持久性奠定基础。数据通过`JSON.stringify()`进行字符串化，这在 localStorage 中并不是特别需要，但使代码稍微更容易替换掉 localStorage 引用，并将其替换为潜在的远程服务器。

+   使 CKeditor 状态持久化。一些有经验的程序员，在被要求为组件状态创建一个 localStorage 持久性解决方案时，可能会合理地猜测我们的解决方案，除了草稿本。草稿本对 Web 2.0 工作有一些难点，因为 CKeditor 对 Web 2.0 工作有一些难点。

整个系统一起运行可以在[`demo.pragmatometer.com/`](http://demo.pragmatometer.com/)上看到。

## 这本书是关于 ReactJS 的，那为什么要使用 CKeditor？

一般来说，可以建议最好使用符合 ReactJS 声明性精神和单向数据绑定的东西。如果您可以选择一个像 CKeditor 这样的东西的良好实现，它并不特别与 ReactJS 以类似的方式工作，以及其他一些与 ReactJS 很好地融合并很好地处理所见即所得的组件，您应该选择与 ReactJS 很好地融合的组件。

这本书旨在帮助您在道路的叉口两侧。它包括使用 JSX 和不使用 JSX 的开发，传统和全新的开发，单向和双向数据绑定，以及（在这里）纯 ReactJS 组件与集成非 ReactJS JavaScript 工具。好消息是，ReactJS 擅长与其他工具友好相处。来自 JavaScript 世界各地的工具至少可能都可以为您提供帮助，而不仅仅是专门为 ReactJS 工作而开发的一小部分。也许您有幸使用纯 ReactJS 组件。也许您想要、需要或者不得不使用一些没有考虑到任何 ReactJS 集成的 JavaScript 工具。好消息是：在任何一种情况下，ReactJS 可能都已经覆盖了。在本章中，我们将使用标准的非 ReactJS 工具-著名且成熟的 CKeditor，ReactJS 让我们很好地将其集成到我们的网页中。

# CKeditor-小而美的免费提供

有几种免费和商业编辑器可用；其中一个编辑器是 CKeditor（其主页位于[`ckeditor.com/`](http://ckeditor.com/)）。CKeditor 带有四个基本选项：*Basic*，*Standard*，*Full*，以及一个*Custom*选项，允许完全自由地选择和取消选择可选功能。对于这个项目，我们将使用*Basic*选项。这不是为了让用户呈现一大堆按钮行的服务，关于包括哪些功能的正确问题是，“什么是对我们来说能够很好地工作的最低限度？”

## 在我们的页面中包含 CKeditor

**Basic**选项（以及 Standard、Full 和 Custom 选项数组）可通过下载或从 CDN 获取。在撰写本书时，可以通过以下方式从 CDN 获取 Basic 选项：

```js
<script src="img/ckeditor.js"></script>
```

这应该是我们的 HTML。我们还需要处理 JSX。用于设置草稿的代码是我们四个子组件中最简单和最短的：

```js
  var Scratchpad = React.createClass({
    render: function() {
      return (
        <div id="Scratchpad">
          <h1>Scratchpad</h1>
          <textarea name="scratchpad"
            id="scratchpad"></textarea>
        </div>
      );
    },
    shouldComponentUpdate: function() {
      return false;
    }
  });
```

`render()`方法就像它看起来的那样简单。请注意，它定义了一个`TEXTAREA`而不是 CKeditor 小部件。不同版本的 CKeditor 通过劫持特定的`TEXTAREA`而不是在代码中编写他们的小部件来工作。`shouldComponentUpdate()`方法也和它看起来的一样简单，但值得一提。这个方法旨在促进优化，以解决 ReactJS 虚拟 DOM 差异检查不如您所能做的那么快的罕见情况。例如，在 ClojureScript 下，Om 具有不可变的数据结构，因此可以仅通过引用比较来测试相等性，而无需进行深度相等性检查，这就是为什么 Om 加 ClojureScript 的速度大约是 ReactJS 加 JavaScript 的两倍。正如前几章所述，99%的时间，微观管理 ReactJS 的虚拟 DOM 根本不需要，即使您想要非常高效。

然而，在这里，我们对 shouldComponentUpdate()机制有一个单独的用例。它在这里的使用与优化和通过较少的比较获得相同结果无关。相反，它用于否认 DOM 的部分权限。对于您可能想要包括的其他一些工具，比如 CKeditor，希望 ReactJS 创建 DOM 的一部分，然后让它保持不变，而不是在以后破坏另一个工具的更改；这正是我们在这里所做的。因此，shouldComponentUpdate() - 除了构成一个在闪电般快速的虚拟 DOM 差异比较中修剪不必要比较的机制之外 - 还可以用于附加一个标签，表示“除了 ReactJS 之外的东西负责维护 DOM 的这一部分。请不要破坏它。”

在首次渲染 Web 应用程序之后，我们要求 CKeditor 替换具有 ID 为 scratchpad 的 TEXTAREA，这应该给我们一个实时小部件：

```js
  React.render(<Pragmatometer />,
    document.getElementById('main'));
  CKEDITOR.replace('scratchpad');
We temporarily comment out the other subcomponents:
  var Pragmatometer = React.createClass({
    render: function() {
      return (
        <div className="Pragmatometer">
          {/* <Calendar /> */}
          {/* <Todo /> */}
          <Scratchpad />
          {/* <YouPick /> */}
        </div>
      );
    }
  });
```

现在我们有一个交互式的便签。以下是我们的 Web 应用程序的屏幕截图，仅显示便签：

![在我们的页面中包含 CKeditor](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_11_01.jpg)

# 将所有四个子组件整合到一个页面中

已经创建了四个子组件 - 日历、便签、待办事项列表和一个带有占位符的“你选择”槽 - 现在我们将把它们整合起来。

我们首先取消注释 Pragmatometer 的 render()方法中的所有注释子组件：

```js
        <div className="Pragmatometer">
          <Calendar />
          <Todo />
          <Scratchpad />
          <YouPick />
        </div>
```

我们的下一步是添加样式，只需一点响应式设计。响应式设计中的一个主要竞争者是简单地不尝试了解和解决每个屏幕分辨率，而是根据屏幕宽度有几个响应步骤。例如，如果您有一个宽屏桌面监视器，加载[`therussianshop.com/`](http://therussianshop.com/)，然后逐渐缩小浏览器窗口。不同的适应性会启动，并且在桌面宽度、平板电脑的任何方向或智能手机上查看时，整个页面会形成一个整体。我们不会在这里尝试一个严肃的解决方案，但是有一些响应性，因为我们的样式是有条件地适应最小宽度为 513 像素。没有任何样式，四个元素将显示在彼此上方；有样式，它们将被围成一个 2x2 的网格。

样式化子组件的 CSS 基本上将足够大的窗口分成四分之一，添加一些填充，并确保每个应用程序上的任何溢出都会滚动：

```js
      @media only screen and (min-width: 513px) {
        #Calendar {
          height: 46%;
          left: 2%;
          overflow-y: auto;
          position: absolute;
          top: 2%;
          width: 46%;
        }
        #Scratchpad {
          height: 46%;
          left: 2%;
          overflow-y: auto;
          position: absolute;
          top: 52%;
          width: 46%;
        }
        #Todo {
          height: 46%;
          left: 52%;
          overflow-y: auto;
          position: absolute;
          top: 0;
          width: 46%;
        }
        #YouPick {
          height: 50%;
          left: 52%;
          overflow-y: auto;
          position: absolute;
          top: 52%;
          width: 46%;
        }
      }
```

这使我们能够显示以下是我们的 Web 应用程序所有部分的屏幕截图：

![将所有四个子组件整合到一个页面中](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/rct-prog-js/img/B04108_11_02.jpg)

# 持久性

有些框架是通用框架，旨在做任何事情；ReactJS 不是。它甚至没有提供任何方法来进行 AJAX 调用，即使（实际上）使用 ReactJS 的任何重要项目都将具有 AJAX 要求。这完全是有意设计的。原因是 ReactJS 专门作为用于工作在用户界面或制作视图的框架，并且旨在与其他技术结合使用，以制作适合您网站的完整包。

Pragmatometer 应用程序中一个希望的功能是它记住您输入的数据。如果您在明天下午 2 点有一个约会，然后离开页面再回来，页面记住约会而不是每次加载时呈现完全空白。持久性是完整 Web 应用程序的一部分，但不是视图或用户界面的责任，ReactJS 显然也没有提供持久性的解决方案。也许也不应该。最近的一些章节介绍了如何使用 ReactJS 来做“X”；本章是关于如何做一些与 ReactJS 相辅相成的其他事情。

对于主流用途，持久性通常通过与后端的通信来处理；有几种好的技术可用。但也许试图将正确实现后端的处理塞进 ReactJS 前端开发书籍的一个章节中并不是非常有用。

作为一个仍然完全属于前端领域的练习，我们将通过一个众所周知的前端路由来处理持久性——HTML5 的 localStorage（如果 Modernizr 未能检测到 localStorage，则持久性代码不起作用）。使用的函数`save()`和`restore()`，如果找到 localStorage，则保存在 localStorage 中。它们直接调用`JSON.stringify()`和`JSON.parse()`，即使这一步并不严格需要使 JSON 可序列化的对象在 localStorage 中持久化。这旨在提供一个直接的钩子来改变代码以与远程后端通信。最简单的适应方式，就像这里的实现一样，是为应用程序单体保存和恢复整个状态，但要记住，过早优化仍然是万恶之源。以这种方式大量使用应用程序可能会导致与单个大型 PNG 文件相当的状态量。当然，该代码还可以进一步适应更精细的方法来保存或恢复更轻的差异，但这里的重点是奠定坚实的基础，而不是将优化推到极致。

我们将使用 Crockford 的 JSON [`github.com/douglascrockford/JSON-js/blob/master/json2.js`](https://github.com/douglascrockford/JSON-js/blob/master/json2.js) 和 Modernizr [`modernizr.com/`](http://modernizr.com/)。在这个应用程序中，我们只会使用 Modernizr 来测试 localStorage 的可用性，因此，如果你正在寻找一个“对于这个项目足够轻量级的最小 Modernizr 构建”，选择测试 localStorage 并排除其他所有内容。让我们在`index.html`中包含这些文件：

```js
<script src="img/json2.js"></script>
<script src="img/modernizr.js"></script>
```

在我们的`site.jsx`文件中，我们定义了`save()`和`restore()`函数。这些函数将用于使不同应用程序的整个状态持久化。另一种方法可能是进行更多和更小的保存，而不是少量的单体保存，但少量的单体保存更容易在脑海中跟踪。因此，它们比为数据的次要方面进行不同保存更容易维护和调试（如果以后需要优化，我们可以，但过早优化仍然是万恶之源）。`save()`函数如下所示：

```js
  var save = function(key, data) {
    if (Modernizr.localstorage) {
      localStorage[key] = JSON.stringify(data);
    }
  }
```

将这个与远程后端连接的最明显的方法之一，除了处理诸如帐户管理之类的细节（这在本示例中没有涉及），是将`localStorage[key]`的赋值替换为调用通知服务器与该键相关的新字符串化数据。这将使 Modernizr 检查变得不必要。但要警告：即使 IE8 支持 localStorage，不支持它的客户端可能有点过时，可能不受 ReactJS 支持，因为 ReactJS 并不宣传支持早于 IE8 的版本（此外，IE8 支持现在是基于一个 shim 而不是本地的；参见[`tinyurl.com/reactjs-ie8-shim`](http://tinyurl.com/reactjs-ie8-shim)）。

`restore()`函数除了键之外还接受一个可选参数——`default_value`。这用于支持一个初始化，如果存在保存的状态，则会拉取它，否则会回退到在初始化时将要使用的正常值。初始化代码可以被重用以适应这个`restore()`函数，如果存在保存的数据，它会拉取非空和已定义的数据，否则会使用默认值。带有`JSON.parse()`和探测 localStorage 的`if`语句是你最直接用来调用远程后端的行，或者更进一步，`restore()`函数可能会被彻底清除并替换为具有相同签名和语义的函数，但会与拥有更多工作的远程服务器进行通信，检查是否保存了任何现有数据。这可能会导致客户端在服务器没有返回任何内容时返回默认值：

```js
  var restore = function(key, default_value) {
    if (Modernizr.localstorage) {
      if (localStorage[key] === null || localStorage[key]
        === undefined) {
        return default_value;
      } else {
        return JSON.parse(localStorage[key]);
      }
    } else {
      return default_value;
    }
  }
```

现在，所有的`getInitialState()`函数都被修改为通过`restore()`函数。看看接下来会发生什么。考虑一下这段代码的`Todo`初始化器：

```js
      getInitialState: function() {
        return {
          'items': [],
          'text': ''
        };
      },
```

它只是包裹在一个`restore()`的调用中：

```js
      getInitialState: function() {
        return restore('Todo', {
          'items': [],
          'text': ''
        });
      },
```

有一些函数会改变一个组件或另一个组件的状态，我们让任何改变组件状态的函数都保存整个状态的一部分。因此，在名为`Calendar#handle_submit`的适当命名的函数中，`this.state.entry_being_added`的许多细节都被填充以匹配（Hijaxed）表单上的内容。然后填充的条目被添加到实时填充的条目列表中，并且新的条目被放在它的位置上：

```js
      this.state.entries.push(this.state.entry_being_added);
      this.state.entry_being_added = this.new_entry();
```

这两行改变了`this.state`，所以我们在它们之后保存了状态：

```js
      this.state.entries.push(this.state.entry_being_added);
      this.state.entry_being_added = this.new_entry();
      save('Calendar', this.state);
```

## 一个细节——持久化 CKeditor 状态

这一部分大部分是可以预测的。一些程序员被告知我们通过 HTML5 localStorage 添加了持久性，可能已经猜到了之前写的东西，很可能他们离答案很近。然而，有一个关于 CKeditor 的细节，不太明显，也不太理想。

CKeditor 在“非花哨”的 Web 1.0 表单使用下做了你可能天真地期望的事情。如果你有一个表单，包括一个名为`foo`的`TEXTAREA`，调用 CKeditor 进行转换，然后提交表单。表单将被提交，就好像当时在 CKeditor 实例上的 HTML 是`TEXTAREA`的内容一样。所有这些都是应该的。

然而，如果你以几乎任何“AJAXian”方式使用 CKeditor，查询文本区域的值而不进行完整的页面表单提交，你将遇到问题。CKeditor 实例的报告值既不多也不少，就是它初始化的文本。原因是`TEXTAREA`的值在整个页面表单提交时会被同步，但在中间步骤不会自动完成。这意味着，除非你采取额外的步骤，否则无法有用地查询 CKeditor 实例。

幸运的是，这个额外的步骤并不特别困难或棘手；CKeditor 提供了一个 API 来同步`TEXTAREA`，所以你可以查询`TEXTAREA`来获取 CKeditor 实例的值。在连接 CKeditor 草稿之前，我们初始化了整个显示并设置了一个间隔，以便每 100 毫秒更新一次显示（这个间隔的长度并不是必要的或神奇的；它可以更频繁或更少地更新，较长的间隔会更加不连贯，但基本上是一样的）：

```js
  var update = function() {
    React.render(<Pragmatometer />,
      document.getElementById('main'));
  };
  update();
  var update_interval = setInterval(update,
    100);
```

为了适应 CKeditor，我们稍微调整和解开一些东西。我们的代码将会有点混乱，以便按特定顺序调用事物。为了让我们的`TEXTAREA`首先存在，我们需要渲染 Pragmatometer 主组件一次（或多次，如果我们想要）。然后，在那个调用之后，我们要求 CKeditor 转换`TEXTAREA`。

接下来，我们开始一个更新函数。这既更新了显示，也同步了 CKeditor 的`TEXTAREAs`，以便可以查询它们的位置。同步`TEXTAREA`的循环并不是绝对必要的。如果我们只有一个编辑器实例，我们只需要一行代码，但我们的代码对于任意数量的具有任意 ID 的 CKeditor 实例都是通用的。最后，在循环内，我们调用编辑器内容的`save()`。一个优化是，如果`save()`和`restore()`被清空并替换为与后端服务器通信，那么就可以将当前编辑器状态保存在一个变量中，只有在编辑器的内容与先前保存的值不同时才进行`save()`。这应该减少频繁的网络通信：

```js
  React.render(<Pragmatometer />,
    document.getElementById('main'));
  CKEDITOR.replace('scratchpad');
  var update = function() {
    React.render(<Pragmatometer />,
      document.getElementById('main'));
    for(var instance in CKEDITOR.instances) {
      CKEDITOR.instances[instance].updateElement();
    }
    save('Scratchpad', 
      document.getElementById('scratchpad').value);
  };
  var update_interval = setInterval(update,
    100);
```

还有一些更改，使得所有的初始化都包裹在对`restore()`的调用中。此外，每当我们改变一个组件的状态时，我们都会调用`save()`。然后我们就完成了！

# 总结

在本章中，我们添加了第四个组件。它与其他组件不同之处在于它不是从头开始在 ReactJS 中构建的，而是集成了第三方工具。这样做可能足够好；只要小心地编写一个`shouldComponentUpdate()`方法，返回`false`，作为一种方式来表明，“不要破坏这个；让其他软件在这里完成它的工作。”

尽管我们涵盖了三个基本主题——组件、集成和持久性，但这一章比其他一些章节更容易。我们有一个实时、可工作的系统，你可以在[`demo.pragmatometer.com/`](http://demo.pragmatometer.com/)上看到它。

现在让我们退一步，来看一下结论，讨论你在本书学到了什么。
