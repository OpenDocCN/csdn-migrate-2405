# 精通 JavaScript 设计模式（二）

> 原文：[`zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90`](https://zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：行为模式

在上一章中，我们看了描述对象如何构建以便简化交互的结构模式。

在本章中，我们将看一下 GoF 模式的最后一个，也是最大的分组：行为模式。这些模式提供了关于对象如何共享数据或者从不同的角度来看，数据如何在对象之间流动的指导。

我们将要看的模式如下：

+   责任链

+   命令

+   解释器

+   迭代器

+   中介者

+   备忘录

+   观察者

+   状态

+   策略

+   模板方法

+   访问者

再次，有许多最近确定的模式可能很好地被归类为行为模式。我们将推迟到以后的章节再来看这些模式，而是继续使用 GoF 模式。

# 责任链

我们可以将对象上的函数调用看作是向该对象发送消息。事实上，这种消息传递的思维方式可以追溯到 Smalltalk 的时代。责任链模式描述了一种方法，其中消息从一个类传递到另一个类。一个类可以对消息进行操作，也可以将其传递给链中的下一个成员。根据实现，可以对消息传递应用一些不同的规则。在某些情况下，只允许链中的第一个匹配链接对消息进行操作。在其他情况下，每个匹配的链接都对消息进行操作。有时允许链接停止处理，甚至在消息继续传递下去时改变消息：

![责任链](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00020.jpg)

让我们看看我们常用的例子中是否能找到这种模式的一个很好的例子：维斯特洛大陆。

## 实现

在维斯特洛大陆，法律制度几乎不存在。当然有法律，甚至有执行它们的城市警卫，但司法系统很少。这片土地的法律实际上是由国王和他的顾问决定的。有时间和金钱的人可以向国王请愿，国王会听取他们的投诉并作出裁决。这个裁决就是法律。当然，任何整天听农民的投诉的国王都会发疯。因此，许多案件在传到国王耳朵之前就被他的顾问们抓住并解决了。

为了在代码中表示这一点，我们需要首先考虑责任链将如何工作。投诉进来，从能够解决问题的最低可能的人开始。如果那个人不能或不愿解决问题，它就会上升到统治阶级的更高级成员。最终问题会达到国王，他是争端的最终仲裁者。我们可以把他看作是默认的争端解决者，当一切都失败时才会被召唤。责任链在下图中可见：

![实施](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00021.jpg)

我们将从一个描述可能听取投诉的接口开始：

```js
export interface ComplaintListener{
  IsAbleToResolveComplaint(complaint: Complaint): boolean;
  ListenToComplaint(complaint: Complaint): string;
}
```

接口需要两个方法。第一个是一个简单的检查，看看类是否能够解决给定的投诉。第二个是听取和解决投诉。接下来，我们需要描述什么构成了投诉：

```js
var Complaint = (function () {
  function Complaint() {
    this.ComplainingParty = "";
    this.ComplaintAbout = "";
    this.Complaint = "";
  }
  return Complaint;
})();
```

接下来，我们需要一些不同的类来实现`ComplaintListener`，并且能够解决投诉：

```js
class ClerkOfTheCourt {
  IsInterestedInComplaint(complaint) {
    //decide if this is a complaint which can be solved by the clerk
    if(isInterested())
      return true;
    return false;
  }
  ListenToComplaint(complaint) {
    //perform some operation
    //return solution to the complaint
    return "";
  }
}
JudicialSystem.ClerkOfTheCourt = ClerkOfTheCourt;
class King {
  IsInterestedInComplaint(complaint) {
    return true;//king is the final member in the chain so must return true
  }
  ListenToComplaint(complaint) {
    //perform some operation
    //return solution to the complaint
    return "";
  }
}
JudicialSystem.King = King;
```

这些类中的每一个都实现了解决投诉的不同方法。我们需要将它们链接在一起，确保国王处于默认位置。这可以在这段代码中看到：

```js
class ComplaintResolver {
  constructor() {
    this.complaintListeners = new Array();
     this.complaintListeners.push(new ClerkOfTheCourt());
     this.complaintListeners.push(new King());
  }
  ResolveComplaint(complaint) {
    for (var i = 0; i < this.complaintListeners.length; i++) {
      if         (this.complaintListeners[i].IsInterestedInComplaint(complaint)) {
        return this.complaintListeners[i].ListenToComplaint(complaint);
      }
    }
  }
}
```

这段代码将逐个遍历每个监听器，直到找到一个对听取投诉感兴趣的监听器。在这个版本中，结果会立即返回，停止任何进一步的处理。这种模式有多种变体，其中多个监听器可以触发，甚至允许监听器改变下一个监听器的参数。以下图表显示了多个配置的监听器：

![实施](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00022.jpg)

责任链在 JavaScript 中是一个非常有用的模式。在基于浏览器的 JavaScript 中，触发的事件会经过一条责任链。例如，您可以将多个监听器附加到链接的单击事件上，每个监听器都会触发，最后是默认的导航监听器。很可能您在大部分代码中都在使用责任链，甚至自己都不知道。

# 命令

命令模式是一种封装方法参数、当前对象状态以及要调用的方法的方法。实际上，命令模式将调用方法所需的一切打包到一个很好的包中，可以在以后的某个日期调用。使用这种方法，可以发出命令，并等到以后再决定哪段代码将执行该命令。然后可以将此包排队或甚至序列化以供以后执行。具有单一的命令执行点还允许轻松添加功能，如撤消或命令记录。

这种模式可能有点难以想象，所以让我们把它分解成其组成部分：

![命令](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00023.jpg)

## 命令消息

命令模式的第一个组件是，可预测地，命令本身。正如我提到的，命令封装了调用方法所需的一切。这包括方法名、参数和任何全局状态。可以想象，在每个命令中跟踪全局状态是非常困难的。如果全局状态在命令创建后发生变化会发生什么？这个困境是使用全局状态的另一个原因，它是有问题的，应该避免使用。

设置命令有几种选择。在简单的一端，只需要跟踪一个函数和一组参数。因为 JavaScript 中函数是一等对象，它们可以很容易地保存到对象中。我们还可以将函数的参数保存到一个简单的数组中。让我们使用这种非常简单的方法构建一个命令。

命令的延迟性质在维斯特洛大陆中有一个明显的隐喻。在维斯特洛大陆中没有快速通信的方法。最好的方法是将小消息附加到鸟上并释放它们。这些鸟倾向于想要返回自己的家，因此每个领主在自己的家中饲养一些鸟，当它们成年时，将它们发送给其他可能希望与他们交流的领主。领主们保留一群鸟并记录哪只鸟将飞往哪个其他领主。维斯特洛国王通过这种方法向他忠诚的领主发送了许多命令。

国王发送的命令包含了领主所需的所有指令。命令可能是像带领你的部队这样的东西，而该命令的参数可能是部队的数量、位置和命令必须执行的日期。

在 JavaScript 中，最简单的表示方法是通过数组：

```js
var simpleCommand = new Array();
simpleCommand.push(new LordInstructions().BringTroops);
simpleCommand.push("King's Landing");
simpleCommand.push(500);
simpleCommand.push(new Date());
```

这个数组可以随意传递和调用。要调用它，可以使用一个通用函数：

```js
simpleCommand0;
```

如您所见，这个函数只适用于具有三个参数的命令。当然，您可以将其扩展到任意数量：

```js
simpleCommand0;
```

附加参数是未定义的，但函数不使用它们，因此没有任何不良影响。当然，这绝不是一个优雅的解决方案。

为每种类型的命令构建一个类是可取的。这样可以确保正确的参数已被提供，并且可以轻松区分集合中的不同类型的命令。通常，命令使用祈使句命名，因为它们是指令。例如，BringTroops、Surrender、SendSupplies 等。

让我们将我们丑陋的简单命令转换成一个合适的类：

```js
class BringTroopsCommand {
  constructor(location, numberOfTroops, when) {
    this._location = location;
    this._numberOfTroops = numberOfTroops;
    this._when = when;
  }
  Execute() {
    var receiver = new LordInstructions();
    receiver.BringTroops(this._location, this._numberOfTroops, this._when);
  }
}
```

我们可能希望实现一些逻辑来确保传递给构造函数的参数是正确的。这将确保命令在创建时失败，而不是在执行时失败。在执行期间可能会延迟，甚至可能延迟几天。验证可能不完美，但即使它只能捕捉到一小部分错误，也是有帮助的。

正如前面提到的，这些命令可以保存在内存中以供以后使用，甚至可以写入磁盘。

## 调用者

调用者是命令模式的一部分，指示命令执行其指令。调用者实际上可以是任何东西：定时事件，用户交互，或者只是流程中的下一步都可能触发调用。在前面的部分中执行`simpleCommand`命令时，我们在扮演调用者的角色。在更严格的命令中，调用者可能看起来像下面这样：

```js
command.Execute()
```

如您所见，调用命令非常容易。命令可以立即调用，也可以在以后的某个时间调用。一种流行的方法是将命令的执行推迟到事件循环的末尾。这可以在节点中完成：

```js
process.nextTick(function(){command.Execute();});
```

函数`process.nextTick`将命令的执行推迟到事件循环的末尾，以便在下次进程没有事情可做时执行。

## 接收者

命令模式中的最后一个组件是接收者。这是命令执行的目标。在我们的例子中，我们创建了一个名为`LordInstructions`的接收者：

```js
class LordInstructions {
  BringTroops(location, numberOfTroops, when) {
    console.log(`You have been instructed to bring ${numberOfTroops} troops to ${location} by ${when}`);
  }
}
```

接收者知道如何执行命令推迟的操作。实际上，接收者可能是任何类，而不必有任何特殊之处。

这些组件共同构成了命令模式。客户端将生成一个命令，将其传递给一个调用者，该调用者可以延迟命令的执行或立即执行，然后命令将作用于接收者。

在构建撤销堆栈的情况下，命令是特殊的，因为它们既有`Execute`方法，也有`Undo`方法。一个将应用程序状态推进，另一个将其推回。要执行撤销，只需从撤销堆栈中弹出命令，执行`Undo`函数，并将其推到重做堆栈上。对于重做，从重做中弹出，执行`Execute`，并推到撤销堆栈上。就是这么简单，尽管必须确保所有状态变化都是通过命令执行的。

《设计模式》一书概述了命令模式的一组稍微复杂的玩家。这在很大程度上是由于我们在 JavaScript 中避免了接口的依赖。由于 JavaScript 中的原型继承模型，该模式变得简单得多。

命令模式是一个非常有用的模式，用于推迟执行某段代码。我们将在《第十章 消息模式》中实际探讨命令模式和一些有用的伴生模式。

# 解释器

解释器模式是一种有趣的模式，因为它允许你创建自己的语言。这可能听起来有点疯狂，我们已经在写 JavaScript 了，为什么还要创建一个新的语言？自《设计模式》一书以来，领域特定语言（DSL）已经有了一些复兴。有些情况下，创建一个特定于某一需求的语言是非常有用的。例如，结构化查询语言（SQL）非常擅长描述对关系数据库的查询。同样，正则表达式已被证明在解析和操作文本方面非常有效。

有许多情况下，能够创建一个简单的语言是有用的。这才是关键：一个简单的语言。一旦语言变得更加复杂，优势很快就会因为创建实际上是一个编译器的困难而丧失。

这种模式与我们到目前为止看到的模式不同，因为它没有真正由模式定义的类结构。你可以按照自己的意愿设计你的语言解释器。

## 示例

对于我们的示例，让我们定义一种语言，用于描述维斯特洛大陆上的历史战斗。这种语言必须简单易懂，便于文职人员编写。我们将从创建一个简单的语法开始：

```js
(aggressor -> battle ground <- defender) -> victor
```

在这里，你可以看到我们只是写出了一个相当不错的语法，让人们描述战斗。罗伯特·拜拉席恩和雷加·坦格利安在三叉戟河之间的战斗将如下所示：

```js
(Robert Baratheon -> River Trident <- RhaegarTargaryen) -> Robert Baratheon
```

使用这种语法，我们希望构建一些能够查询战斗列表的代码。为了做到这一点，我们将依赖于正则表达式。对于大多数语言来说，这不是一个好的方法，因为语法太复杂。在这种情况下，人们可能希望创建一个词法分析器和一个解析器，并构建语法树，然而，到了那个时候，你可能会希望重新审视一下是否创建 DSL 真的是一个好主意。对于我们的语言，语法非常简单，所以我们可以使用正则表达式。

## 实现

我们首先为战斗建立一个 JavaScript 数据模型，如下所示：

```js
class Battle {
  constructor(battleGround, agressor, defender, victor) {
    this.battleGround = battleGround;
    this.agressor = agressor;
    this.defender = defender;
    this.victor = victor;
  }
}
```

接下来我们需要一个解析器：

```js
class Parser {
  constructor(battleText) {
    this.battleText = battleText;
    this.currentIndex = 0;
    this.battleList = battleText.split("\n");
  }
  nextBattle() {
   if (!this.battleList[0])
     return null;
    var segments = this.battleList[0].match(/\((.+?)\s?->\s?(.+?)\s?<-\s?(.+?)\s?->\s?(.+)/);
    return new Battle(segments[2], segments[1], segments[3], segments[4]);
  }
}
```

最好不要太在意那个正则表达式。然而，这个类确实接受一系列战斗（每行一个），并使用`next Battle`，允许解析它们。要使用这个类，我们只需要做以下操作：

```js
var text = "(Robert Baratheon -> River Trident <- RhaegarTargaryen) -> Robert Baratheon";
var p = new Parser(text);
p.nextBattle()
```

这将是输出：

```js
{
  battleGround: 'River Trident',
  agressor: 'Robert Baratheon',
  defender: 'RhaegarTargaryen)',
  victor: 'Robert Baratheon'
}
```

现在可以像查询 JavaScript 中的任何其他结构一样查询这个数据结构了。

正如我之前提到的，实现这种模式没有固定的方式，因此在前面的代码中所做的实现只是提供了一个例子。你的实现很可能会看起来非常不同，这也是可以的。

解释器在 JavaScript 中可能是一个有用的模式。然而，在大多数情况下，这是一个相当少用的模式。JavaScript 中解释的最佳示例是编译为 CSS 的语言。

# 迭代器

遍历对象集合是一个非常常见的问题。以至于许多语言都提供了专门的构造来遍历集合。例如，C#有`foreach`循环，Python 有`for x in`。这些循环构造经常建立在迭代器之上。迭代器是一种模式，提供了一种简单的方法，按顺序选择集合中的下一个项目。

迭代器的接口如下：

```js
interface Iterator{
  next();
}
```

## 实现

在维斯特洛大陆，有一个众所周知的人们排队等候王位的序列，以备国王不幸去世的情况。我们可以在这个集合上设置一个方便的迭代器，如果统治者去世，只需简单地调用`next`：

```js
class KingSuccession {
  constructor(inLineForThrone) {
    this.inLineForThrone = inLineForThrone;
    this.pointer = 0;
  }
  next() {
    return this.inLineForThrone[this.pointer++];
  }
}
```

这是用一个数组初始化的，然后我们可以调用它：

```js
var king = new KingSuccession(["Robert Baratheon" ,"JofferyBaratheon", "TommenBaratheon"]);
king.next() //'Robert Baratheon'
king.next() //'JofferyBaratheon'
king.next() //'TommenBaratheon'
```

迭代器的一个有趣的应用是不仅仅迭代一个固定的集合。例如，迭代器可以用来生成无限集合的顺序成员，比如斐波那契序列：

```js
class FibonacciIterator {
  constructor() {
    this.previous = 1;
    this.beforePrevious = 1;
  }
  next() {
    var current = this.previous + this.beforePrevious;
    this.beforePrevious = this.previous;
    this.previous = current;
    return current;
  }
}
```

这样使用：

```js
var fib = new FibonacciIterator()
fib.next() //2
fib.next() //3
fib.next() //5
fib.next() //8
fib.next() //13
fib.next() //21
```

迭代器是方便的构造，允许探索不仅仅是数组，而且是任何集合，甚至是任何生成的列表。有很多地方可以大量使用这个。

## ECMAScript 2015 迭代器

迭代器是如此有用，以至于它们实际上是 JavaScript 下一代的一部分。ECMAScript 2015 中使用的迭代器模式是一个返回包含`done`和`value`的对象的单个方法。当迭代器在集合的末尾时，`done`为`true`。ECMAScript 2015 迭代器的好处是 JavaScript 中的数组集合将支持迭代器。这开辟了一种新的语法，可以在很大程度上取代`for`循环：

```js
var kings = new KingSuccession(["Robert Baratheon" ,"JofferyBaratheon", "TommenBaratheon"]);
for(var king of kings){
  //act on members of kings
}
```

迭代器是 JavaScript 长期以来一直缺少的一种语法上的美好。ECMAScript-2015 的另一个很棒的特性是生成器。这实际上是一个内置的迭代器工厂。我们的斐波那契序列可以重写如下：

```js
function* FibonacciGenerator (){
  var previous = 1;
  var beforePrevious = 1;
  while(true){
    var current = previous + beforePrevious;
    beforePrevious = previous;
    previous = current;
    yield current;
  }
}
```

这样使用：

```js
var fib = new FibonacciGenerator()
fib.next().value //2
fib.next().value //3
fib.next().value //5
fib.next().value //8
fib.next().value //13
fib.next().value //21
```

# 中介者

在类中管理多对多关系可能是一个复杂的前景。让我们考虑一个包含多个控件的表单，每个控件都想在执行操作之前知道页面上的其他控件是否有效。不幸的是，让每个控件都知道其他控件会创建一个维护噩梦。每次添加一个新控件，都需要修改每个其他控件。

中介者将坐在各种组件之间，并作为一个单一的地方，可以进行消息路由的更改。通过这样做，中介者简化了维护代码所需的复杂工作。在表单控件的情况下，中介者很可能是表单本身。中介者的作用很像现实生活中的中介者，澄清和路由各方之间的信息交流：

![中介者](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00024.jpg)

## 实现

在维斯特洛大陆，经常需要中介者。中介者经常会死去，但我相信这不会发生在我们的例子中。

在维斯特洛大陆有许多伟大的家族拥有大城堡和广阔的土地。次要领主们向大家族宣誓效忠，形成联盟，经常通过婚姻得到支持。

在协调各家族的时候，大领主将充当中介者，来回传递信息并解决他们之间可能发生的任何争端。

在这个例子中，我们将大大简化各家之间的通信，并说所有消息都通过大领主传递。在这种情况下，我们将使用史塔克家作为我们的大领主。他们有许多其他家族与他们交谈。每个家族看起来大致如下：

```js
class Karstark {
  constructor(greatLord) {
    this.greatLord = greatLord;
  }
  receiveMessage(message) {
  }
  sendMessage(message) {
    this.greatLord.routeMessage(message);
  }
}
```

它们有两个函数，一个接收来自第三方的消息，一个发送消息给他们的大领主，这是在实例化时设置的。`HouseStark`类如下所示：

```js
class HouseStark {
  constructor() {
    this.karstark = new Karstark(this);
    this.bolton = new Bolton(this);
    this.frey = new Frey(this);
    this.umber = new Umber(this);
  }
  routeMessage(message) {
  }
}
```

通过`HouseStark`类传递所有消息，其他各个家族不需要关心它们的消息是如何路由的。这个责任被交给了`HouseStark`，它充当了中介。

中介者最适合用于通信既复杂又明确定义的情况。如果通信不复杂，那么中介者会增加额外的复杂性。如果通信不明确定义，那么在一个地方对通信规则进行编码就变得困难。

在 JavaScript 中，简化多对多对象之间的通信肯定是有用的。我实际上认为在许多方面，jQuery 充当了中介者。在页面上操作一组项目时，它通过抽象掉代码需要准确知道页面上哪些对象正在被更改来简化通信。例如：

```js
$(".error").slideToggle();
```

jQuery 是切换页面上所有具有`error`类的元素的可见性的简写吗？

# 备忘录

在命令模式的部分，我们简要讨论了撤销操作的能力。创建可逆命令并非总是可能的。对于许多操作，没有明显的逆向操作可以恢复原始状态。例如，想象一下对一个数字进行平方的代码：

```js
class SquareCommand {
  constructor(numberToSquare) {
    this.numberToSquare = numberToSquare;
  }
  Execute() {
    this.numberToSquare *= this.numberToSquare;
  }
}
```

给这段代码-9 将得到 81，但给它 9 也将得到 81。没有办法在没有额外信息的情况下撤销这个命令。

备忘录模式提供了一种恢复对象状态到先前状态的方法。备忘录记录了变量先前的值，并提供了恢复它们的功能。为每个命令保留一个备忘录可以轻松恢复不可逆转的命令。

除了撤销堆栈之外，还有许多情况下，具有回滚对象状态的能力是有用的。例如，进行假设分析需要对状态进行一些假设性的更改，然后观察事物如何变化。这些更改通常不是永久性的，因此可以使用备忘录模式进行回滚，或者如果项目是可取的，可以保留下来。备忘录模式的图表可以在这里看到：

![备忘录](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00025.jpg)

典型的备忘录实现涉及三个角色：

+   **原始对象**：原始对象保存某种状态并提供生成新备忘录的接口。

+   **看护者**：这是模式的客户端，它请求获取新备忘录并管理何时进行恢复。

+   **备忘录**：这是原始对象保存状态的表示。这可以持久化到存储中以便进行回滚。

将备忘录模式的成员想象成老板和秘书做笔记可能会有所帮助。老板（看护者）向秘书（原始对象）口述备忘录，秘书在记事本（备忘录）上写下笔记。偶尔老板可能会要求秘书划掉他刚刚写的内容。

与备忘录模式相关的看护者的参与可以有所不同。在某些实现中，原始对象在其状态发生变化时会生成一个新的备忘录。这通常被称为写时复制，因为会创建状态的新副本并应用变化。旧版本可以保存到备忘录中。

## 实施

在维斯特洛大陆上有许多预言者，他们是未来的预言者。他们通过使用魔法来窥视未来，并检查当前的某些变化将如何在未来发挥作用。通常需要进行许多略有不同起始条件的预测。在设置起始条件时，备忘录模式是非常宝贵的。

我们从一个世界状态开始，它提供了某个特定起点的世界状态信息：

```js
class WorldState {
  constructor(numberOfKings, currentKingInKingsLanding, season) {
    this.numberOfKings = numberOfKings;
    this.currentKingInKingsLanding = currentKingInKingsLanding;
    this.season = season;
  }
}
```

这个`WorldState`类负责跟踪构成世界的所有条件。每当对起始条件进行更改时，应用程序都会修改它。因为这个世界状态包含了应用程序的所有状态，所以它可以被用作备忘录。我们可以将这个对象序列化并保存到磁盘上，或者发送回某个历史服务器。

接下来我们需要一个类，它提供与备忘录相同的状态，并允许创建和恢复备忘录。在我们的示例中，我们将其称为`WorldStateProvider`：

```js
class WorldStateProvider {
  saveMemento() {
    return new WorldState(this.numberOfKings, this.currentKingInKingsLanding, this.season);
  }
  restoreMemento(memento) {
    this.numberOfKings = memento.numberOfKings;
    this.currentKingInKingsLanding = memento.currentKingInKingsLanding;
    this.season = memento.season;
  }
}
```

最后，我们需要一个预言者的客户端，我们将称之为`Soothsayer`：

```js
class Soothsayer {
  constructor() {
    this.startingPoints = [];
    this.currentState = new WorldStateProvider();
  }
  setInitialConditions(numberOfKings, currentKingInKingsLanding, season) {
    this.currentState.numberOfKings = numberOfKings;
    this.currentState.currentKingInKingsLanding = currentKingInKingsLanding;
    this.currentState.season = season;
  }
  alterNumberOfKingsAndForetell(numberOfKings) {
    this.startingPoints.push(this.currentState.saveMemento());
    this.currentState.numberOfKings = numberOfKings;
  }
  alterSeasonAndForetell(season) {
    this.startingPoints.push(this.currentState.saveMemento());
    this.currentState.season = season;
  }
  alterCurrentKingInKingsLandingAndForetell(currentKingInKingsLanding) {
    this.startingPoints.push(this.currentState.saveMemento());
    this.currentState.currentKingInKingsLanding = currentKingInKingsLanding;
    //run some sort of prediction
  }
  tryADifferentChange() {
    this.currentState.restoreMemento(this.startingPoints.pop());
  }
}
```

这个类提供了一些方便的方法，它们改变了世界的状态，然后运行了一个预言。这些方法中的每一个都将先前的状态推入历史数组`startingPoints`。还有一个方法`tryADifferentChange`，它撤销了先前的状态更改，准备运行另一个预言。撤销是通过加载存储在数组中的备忘录来执行的。

尽管客户端 JavaScript 应用有很高的血统，但提供撤销功能却非常罕见。我相信这其中有各种原因，但大部分原因可能是人们并不期望有这样的功能。然而，在大多数桌面应用程序中，撤销功能是被期望的。我想，随着客户端应用程序在功能上不断增强，撤销功能将变得更加重要。当这种情况发生时，备忘录模式是实现撤销堆栈的一种绝妙方式。

# 观察者

观察者模式可能是 JavaScript 世界中使用最多的模式。这种模式特别在现代单页应用程序中使用；它是提供**模型视图视图模型**（**MVVM**）功能的各种库的重要组成部分。我们将在第七章中详细探讨这些模式，*响应式编程*。

经常有必要知道对象的值何时发生了变化。为了做到这一点，您可以用 getter 和 setter 包装感兴趣的属性：

```js
class GetterSetter {
  GetProperty() {
    return this._property;
  }
  SetProperty(value) {
    this._property = value;
  }
}
```

setter 函数现在可以增加对其他对值发生变化感兴趣的对象的调用：

```js
SetProperty(value) {
  var temp = this._property;
  this._property = value;
  this._listener.Event(value, temp);
}
```

现在，这个 setter 将通知监听器属性已发生变化。在这种情况下，旧值和新值都已包括在内。这并不是必要的，因为监听器可以负责跟踪先前的值。

观察者模式概括和规范了这个想法。观察者模式允许感兴趣的各方订阅变化通知，而不是只有一个调用监听器的单个调用。多个订阅者可以在下图中看到：

![Observer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00026.jpg)

## 实施

维斯特洛的法庭是一个充满阴谋和诡计的地方。控制谁坐在王位上，以及他们的行动，是一个复杂的游戏。权力的游戏中的许多玩家雇佣了许多间谍来发现其他人的行动。这些间谍经常被多个玩家雇佣，并必须向所有玩家报告他们所发现的情况。

间谍是使用观察者模式的理想场所。在我们的特定示例中，被雇佣的间谍是国王的官方医生，玩家们非常关心给这位患病的国王开了多少止痛药。知道这一点可以让玩家提前知道国王可能何时去世 - 这是一个非常有用的信息。

间谍看起来像下面这样：

```js
class Spy {
  constructor() {
    this._partiesToNotify = [];
  }
  Subscribe(subscriber) {
    this._partiesToNotify.push(subscriber);
  }
  Unsubscribe(subscriber) {
    this._partiesToNotify.remove(subscriber);
  }
  SetPainKillers(painKillers) {
    this._painKillers = painKillers;
    for (var i = 0; i < this._partiesToNotify.length; i++) {
      this._partiesToNotifyi;
    }
  }
}
```

在其他语言中，订阅者通常必须遵守某个接口，观察者只会调用接口方法。这种负担在 JavaScript 中不存在，事实上，我们只给`Spy`类一个函数。这意味着订阅者不需要严格的接口。这是一个例子：

```js
class Player {
  OnKingPainKillerChange(newPainKillerAmount) {
    //perform some action
  }
}
```

可以这样使用：

```js
let s = new Spy();
let p = new Player();
s.Subscribe(p.OnKingPainKillerChange); //p is now a subscriber
s.SetPainKillers(12); //s will notify all subscribers
```

这提供了一种非常简单和高效的构建观察者的方法。订阅者使订阅者与可观察对象解耦。

观察者模式也可以应用于方法和属性。通过这样做，可以提供用于发生附加行为的钩子。这是为 JavaScript 库提供插件基础设施的常见方法。

在浏览器中，DOM 中各种项目上的所有事件监听器都是使用观察者模式实现的。例如，使用流行的 jQuery 库，可以通过以下方式订阅页面上所有按钮的`click`事件：

```js
$("body").on("click", "button", function(){/*do something*/})
```

即使在纯 JavaScript 中，相同的模式也适用：

```js
let buttons = document.getElementsByTagName("button");
for(let i =0; i< buttons.length; i++)
{
  buttons[i].onclick = function(){/*do something*/}
}
```

显然，观察者模式在处理 JavaScript 时非常有用。没有必要以任何重大方式改变模式。

# 状态

状态机在计算机编程中是一个非常有用的设备。不幸的是，大多数程序员并不经常使用它们。我相信对状态机的一些反对意见至少部分是因为许多人将它们实现为一个巨大的`if`语句，如下所示：

```js
function (action, amount) {
  if (this.state == "overdrawn" && action == "withdraw") {
    this.state = "on hold";
  }
  if (this.state == "on hold" && action != "deposit") {
    this.state = "on hold";
  }
  if (this.state == "good standing" && action == "withdraw" && amount <= this.balance) {
    this.balance -= amount;
  }
  if (this.state == "good standing" && action == "withdraw" && amount >this.balance) {
    this.balance -= amount;
    this.state = "overdrawn";
  }
};
```

这只是一个可能更长的示例。这样长的`if`语句很难调试，而且容易出错。只需翻转一个大于号就足以大大改变`if`语句的工作方式。

不要使用单个巨大的`if`语句块，我们可以利用状态模式。状态模式的特点是有一个状态管理器，它抽象了内部状态，并将消息代理到适当的状态，该状态实现为一个类。所有状态内部的逻辑和状态转换的控制都由各个状态类管理。状态管理器模式可以在以下图表中看到：

![State](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00027.jpg)

将状态分为每个状态一个类允许更小的代码块进行调试，并且使测试变得更容易。

状态管理器的接口非常简单，通常只提供与各个状态通信所需的方法。管理器还可以包含一些共享状态变量。

## 实施

正如在`if`语句示例中所暗示的，维斯特洛有一个银行系统。其中大部分集中在布拉沃斯岛上。那里的银行业务与这里的银行业务基本相同，包括账户、存款和取款。管理银行账户的状态涉及监视所有交易并根据交易改变银行账户的状态。

让我们来看看管理布拉沃斯银行账户所需的一些代码。首先是状态管理器：

```js
class BankAccountManager {
  constructor() {
    this.currentState = new GoodStandingState(this);
  }
  Deposit(amount) {
    this.currentState.Deposit(amount);
  }
  Withdraw(amount) {
    this.currentState.Withdraw(amount);
  }
  addToBalance(amount) {
    this.balance += amount;
  }
  getBalance() {
    return this.balance;
  }
  moveToState(newState) {
    this.currentState = newState;
  }
}
```

`BankAccountManager`类提供了当前余额和当前状态的状态。为了保护余额，它提供了一个用于读取余额的辅助工具，另一个用于增加余额。在真实的银行应用程序中，我更希望设置余额的功能比这个更有保护性。在这个`BankManager`版本中，操作当前状态的能力对状态是可访问的。它们有责任改变状态。这个功能可以集中在管理器中，但这会增加添加新状态的复杂性。

我们已经为银行账户确定了三种简单的状态：`Overdrawn`，`OnHold`和`GoodStanding`。每个状态在该状态下负责处理取款和存款。`GoodStandingstate`类如下所示：

```js
class GoodStandingState {
  constructor(manager) {
    this.manager = manager;
  }
  Deposit(amount) {
    this.manager.addToBalance(amount);
  }
  Withdraw(amount) {
    if (this.manager.getBalance() < amount) {
      this.manager.moveToState(new OverdrawnState(this.manager));
    }
    this.manager.addToBalance(-1 * amount);
  }
}
```

`OverdrawnState`类如下所示：

```js
class OverdrawnState {
  constructor(manager) {
    this.manager = manager;
  }
  Deposit(amount) {
    this.manager.addToBalance(amount);
    if (this.manager.getBalance() > 0) {
      this.manager.moveToState(new GoodStandingState(this.manager));
    }
  }
  Withdraw(amount) {
    this.manager.moveToState(new OnHold(this.manager));
    throw "Cannot withdraw money from an already overdrawn bank account";
  }
}
```

最后，`OnHold`状态如下所示：

```js
class OnHold {
  constructor(manager) {
    this.manager = manager;
  }
  Deposit(amount) {
    this.manager.addToBalance(amount);
    throw "Your account is on hold and you must attend the bank to resolve the issue";
  }
  Withdraw(amount) {
    throw "Your account is on hold and you must attend the bank to resolve the issue";
  }
}
```

您可以看到，我们已经成功地将混乱的`if`语句的所有逻辑重现在一些简单的类中。这里的代码量看起来比`if`语句要多得多，但从长远来看，将代码封装到单独的类中将会得到回报。

在 JavaScript 中有很多机会可以利用这种模式。跟踪状态是大多数应用程序中的典型问题。当状态之间的转换很复杂时，将其封装在状态模式中是简化事情的一种方法。还可以通过按顺序注册事件来构建简单的工作流程。这样做的一个好接口可能是流畅的，这样你就可以注册以下状态：

```js
goodStandingState
.on("withdraw")
.when(function(manager){return manager.balance > 0;})
  .transitionTo("goodStanding")
.when(function(manager){return mangaer.balance <=0;})
  .transitionTo("overdrawn");
```

# 策略

有人说过有很多种方法可以剥猫皮。我明智地从未研究过有多少种方法。在计算机编程中，算法也经常如此。通常有许多版本的算法，它们在内存使用和 CPU 使用之间进行权衡。有时会有不同的方法提供不同级别的保真度。例如，在智能手机上执行地理定位通常使用三种不同的数据来源之一：

+   GPS 芯片

+   手机三角定位

+   附近的 WiFi 点

使用 GPS 芯片提供了最高级别的保真度，但也是最慢的，需要最多的电池。查看附近的 WiFi 点需要非常少的能量，速度非常快，但提供的保真度较低。

策略模式提供了一种以透明方式交换这些策略的方法。在传统的继承模型中，每个策略都会实现相同的接口，这将允许任何策略进行交换。下图显示了可以进行交换的多个策略：

![策略](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00028.jpg)

选择正确的策略可以通过多种不同的方式来完成。最简单的方法是静态选择策略。这可以通过配置变量或甚至硬编码来完成。这种方法最适合策略变化不频繁或特定于单个客户或用户的情况。

或者可以对要运行策略的数据集进行分析，然后选择合适的策略。如果已知策略 A 在数据传入时比策略 B 更好，那么可以首先运行一个快速的分析传播的算法，然后选择适当的策略。

如果特定算法在某种类型的数据上失败，这也可以在选择策略时考虑进去。在 Web 应用程序中，这可以用于根据数据的形状调用不同的 API。它还可以用于在 API 端点之一宕机时提供备用机制。

另一种有趣的方法是使用渐进增强。首先运行最快且最不准确的算法以提供快速的用户反馈。同时也运行一个较慢的算法，当它完成时，优越的结果将用于替换现有的结果。这种方法经常用于上面概述的 GPS 情况。您可能会注意到，在移动设备上使用地图时，地图加载后一会儿您的位置会更新；这是渐进增强的一个例子。

最后，策略可以完全随机选择。这听起来像是一种奇怪的方法，但在比较两种不同策略的性能时可能会有用。在这种情况下，将收集关于每种方法的表现如何的统计数据，并进行分析以选择最佳策略。策略模式可以成为 A/B 测试的基础。

选择要使用的策略可以是应用工厂模式的绝佳地方。

## 实施

在维斯特洛大陆，没有飞机、火车或汽车，但仍然有各种不同的旅行方式。人们可以步行、骑马、乘船航行，甚至可以坐船沿河而下。每种方式都有不同的优点和缺点，但最终它们都能把一个人从 A 点带到 B 点。接口可能看起来像下面这样：

```js
export interface ITravelMethod{
  Travel(source: string, destination: string) : TravelResult;
}
```

旅行结果向调用者传达了一些关于旅行方式的信息。在我们的情况下，我们追踪旅行需要多长时间，风险是什么，以及费用是多少：

```js
class TravelResult {
  constructor(durationInDays, probabilityOfDeath, cost) {
    this.durationInDays = durationInDays;
    this.probabilityOfDeath = probabilityOfDeath;
    this.cost = cost;
  }
}
```

在这种情况下，我们可能希望有一个额外的方法来预测一些风险，以便自动选择策略。

实现策略就像下面这样简单：

```js
class SeaGoingVessel {
  Travel(source, destination) {
    return new TravelResult(15, .25, 500);
  }
}

class Horse {
  Travel(source, destination) {
    return new TravelResult(30, .25, 50);
  }
}

class Walk {
  Travel(source, destination) {
    return new TravelResult(150, .55, 0);
  }
}
```

在策略模式的传统实现中，每个策略的方法签名应该相同。在 JavaScript 中，函数的多余参数会被忽略，缺少的参数可以给出默认值，因此有更多的灵活性。

显然，实际实现中风险、成本和持续时间的实际计算不会硬编码。要使用这些方法，只需要做以下操作：

```js
var currentMoney = getCurrentMoney();
var strat;
if (currentMoney> 500)
  strat = new SeaGoingVessel();
else if (currentMoney> 50)
  strat = new Horse();
else
  strat = new Walk();
var travelResult = strat.Travel();
```

为了提高这种策略的抽象级别，我们可以用更一般的名称替换具体的策略，描述我们要优化的内容：

```js
var currentMoney = getCurrentMoney();
var strat;
if (currentMoney> 500)
  strat = new FavorFastestAndSafestStrategy();
else
  strat = new FavorCheapest();
var travelResult = strat.Travel();
```

策略模式在 JavaScript 中是一个非常有用的模式。我们能够使这种方法比在不使用原型继承的语言中更简单：不需要接口。我们不需要从不同的策略中返回相同形状的对象。只要调用者有点意识到返回的对象可能有额外的字段，这是一个完全合理的，虽然难以维护的方法。

# 模板方法

策略模式允许用一个互补的算法替换整个算法。经常替换整个算法是过度的：绝大部分算法在每个策略中仍然保持相同，只有特定部分有轻微的变化。

模板方法模式是一种方法，允许共享算法的一些部分，并使用不同的方法实现其他部分。这些外包部分可以由方法家族中的任何一个方法来实现：

![模板方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00029.jpg)

模板类实现了算法的部分，并将其他部分留作抽象，以便稍后由扩展它的类来覆盖。继承层次结构可以有几层深，每个级别都实现了模板类的更多部分。

### 提示

抽象类是包含抽象方法的类。抽象方法只是没有方法体的方法。抽象类不能直接使用，必须由另一个实现抽象方法的类来扩展。抽象类可以扩展另一个抽象类，以便不需要所有方法都由扩展类实现。

这种方法将渐进增强的原则应用到算法中。我们越来越接近一个完全实现的算法，同时建立一个有趣的继承树。模板方法有助于将相同的代码保持在一个位置，同时允许一些偏差。部分实现的链可以在下图中看到：

![模板方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00030.jpg)

重写留作抽象的方法是面向对象编程的一个典型部分。很可能你经常使用这种模式，甚至没有意识到它有一个名字。

## 实现

我已经被知情人告知，有许多不同的酿造啤酒的方法。这些啤酒在选择原料和生产方法上有所不同。事实上，啤酒甚至不需要含有啤酒花 - 它可以由任意数量的谷物制成。然而，所有啤酒之间都存在相似之处。它们都是通过发酵过程制作的，所有合格的啤酒都含有一定的酒精含量。

在维斯特洛有许多自豪地制作顶级啤酒的工匠。我们想将他们的工艺描述为一组类，每个类描述一种不同的酿造啤酒的方法。我们从一个简化的酿造啤酒的实现开始：

```js
class BasicBeer {
  Create() {
    this.AddIngredients();
    this.Stir();
    this.Ferment();
    this.Test();
    if (this.TestingPassed()) {
      this.Distribute();
    }
  }
  AddIngredients() {
    throw "Add ingredients needs to be implemented";
  }
  Stir() {
    //stir 15 times with a wooden spoon
  }
  Ferment() {
    //let stand for 30 days
  }
  Test() {
    //draw off a cup of beer and taste it
  }
  TestingPassed() {
    throw "Conditions to pass a test must be implemented";
  }
  Distribute() {
    //place beer in 50L casks
  }
}
```

由于 JavaScript 中没有抽象的概念，我们已经为必须被覆盖的各种方法添加了异常。剩下的方法可以更改，但不是必须的。树莓啤酒的实现如下所示：

```js
class RaspberryBeer extends BasicBeer {
  AddIngredients() {
    **//add ingredients, probably including raspberries** 

  }
  TestingPassed() {
    **//beer must be reddish and taste of raspberries** 

  }
}
```

在这个阶段可能会进行更具体的树莓啤酒的子类化。

在 JavaScript 中，模板方法仍然是一个相当有用的模式。在创建类时有一些额外的语法糖，但这并不是我们在之前章节中没有见过的。我唯一要提醒的是，模板方法使用继承，因此将继承类与父类紧密耦合。这通常不是一种理想的状态。

# 访问者

本节中的最后一个模式是访问者模式。访问者提供了一种将算法与其操作的对象结构解耦的方法。如果我们想对不同类型的对象集合执行某些操作，并且根据对象类型执行不同的操作，通常需要使用大量的`if`语句。

让我们立刻在维斯特洛进行一个示例。一个军队由几个不同类别的战斗人员组成（重要的是我们要政治正确，因为维斯特洛有许多著名的女战士）。然而，军队的每个成员都实现了一个名为`IMemberOfArmy`的假设接口：

```js
interface IMemberOfArmy{
  printName();
}
```

这个的简单实现可能是这样的：

```js
class Knight {
  constructor() {
    this._type = "Westeros.Army.Knight";
  }
  printName() {
    console.log("Knight");
  }
  visit(visitor) {
    visitor.visit(this);
  }
}
```

现在我们有了这些不同类型的集合，我们可以使用`if`语句只在骑士上调用`printName`函数：

```js
var collection = [];
collection.push(new Knight());
collection.push(new FootSoldier());
collection.push(new Lord());
collection.push(new Archer());

for (let i = 0; i<collection.length; i++) {
  if (typeof (collection[i]) == 'Knight')
    collection[i].printName();
  else
    console.log("Not a knight");
}
```

除非你运行这段代码，你实际上会发现我们得到的只是以下内容：

```js
Not a knight
Not a knight
Not a knight
Not a knight
```

这是因为，尽管一个对象是骑士，但它仍然是一个对象，`typeof`在所有情况下都会返回对象。

另一种方法是使用`instanceof`而不是`typeof`：

```js
var collection = [];
collection.push(new Knight());
collection.push(new FootSoldier());
collection.push(new Lord());
collection.push(new Archer());

for (var i = 0; i < collection.length; i++) {
  if (collection[i] instanceof Knight)
    collection[i].printName();
  else
    console.log("No match");
}
```

实例方法的方法在遇到使用`Object.create`语法的人时效果很好：

```js
collection.push(Object.create(Knight));
```

尽管是骑士，当被问及是否是`Knight`的实例时，它将返回`false`。

这对我们来说是一个问题。访问者模式使问题变得更加严重，因为它要求语言支持方法重载。JavaScript 实际上并不支持这一点。可以使用各种技巧来使 JavaScript 在某种程度上意识到重载的方法，但通常的建议是根本不要费心，而是创建具有不同名称的方法。

然而，我们还不要放弃这种模式；它是一个有用的模式。我们需要一种可靠地区分一种类型和另一种类型的方法。最简单的方法是在类上定义一个表示其类型的变量：

```js
var Knight = (function () {
  function Knight() {
    this._type = "Knight";
  }
  Knight.prototype.printName = function () {
    console.log("Knight");
  };
  return Knight;
})();
```

有了新的`_type`变量，我们现在可以伪造真正的方法覆盖：

```js
var collection = [];
collection.push(new Knight());
collection.push(new FootSoldier());
collection.push(new Lord());
collection.push(new Archer());

for (vari = 0; i<collection.length; i++) {
  if (collection[i]._type == 'Knight')
    collection[i].printName();
  else
    console.log("No match");
}
```

有了这种方法，我们现在可以实现一个访问者。第一步是扩展我们军队的各种成员，使其具有一个接受访问者并应用它的通用方法：

```js
var Knight = (function () {
  function Knight() {
    this._type = "Knight";
  }
  Knight.prototype.printName = function () {
    console.log("Knight");
  };
  **Knight.prototype.visit = function (visitor) {** 

 **visitor.visit(this);** 

 **};** 

  return Knight;
})();
```

现在我们需要构建一个访问者。这段代码近似于我们在前面的代码中的`if`语句：

```js
varSelectiveNamePrinterVisitor = (function () {
  function SelectiveNamePrinterVisitor() {
  }
  SelectiveNamePrinterVisitor.prototype.Visit = function (memberOfArmy) {
    if (memberOfArmy._type == "Knight") {
      this.VisitKnight(memberOfArmy);
    } else {
      console.log("Not a knight");
    }
  };

  SelectiveNamePrinterVisitor.prototype.VisitKnight = function (memberOfArmy) {
    memberOfArmy.printName();
  };
  return SelectiveNamePrinterVisitor;
})();
```

这个访问者将被用作下面这样：

```js
var collection = [];
collection.push(new Knight());
collection.push(new FootSoldier());
collection.push(new Lord());
collection.push(new Archer());
var visitor = new SelectiveNamePrinterVisitor();
for (vari = 0; i<collection.length; i++) {
  collection[i].visit(visitor);
}
```

正如您所看到的，我们已经将集合中项目的类型的决定推迟到了访问者。这将项目本身与访问者解耦，如下图所示：

![Visitor](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00031.jpg)

如果我们允许访问者决定对访问对象调用哪些方法，那么就需要一些技巧。如果我们可以为访问对象提供一个恒定的接口，那么访问者只需要调用接口方法。然而，这将逻辑从访问者移到被访问的对象中，这与对象不应该知道自己是访问者的一部分的想法相矛盾。

是否值得忍受这种欺诈行为，这实际上是一个练习。就我个人而言，我倾向于避免在 JavaScript 中使用访问者模式，因为使其工作的要求很复杂且不明显。

# 提示和技巧

以下是一些关于本章中一些模式的简短提示：

+   在实现解释器模式时，您可能会被诱惑使用 JavaScript 本身作为您的 DSL，然后使用`eval`函数来执行代码。这实际上是一个非常危险的想法，因为`eval`会带来整个安全问题的世界。在 JavaScript 中使用`eval`通常被认为是非常不好的做法。

+   如果您发现自己需要审计项目中的数据更改，则可以轻松地修改备忘录模式以适应。您不仅可以跟踪状态更改，还可以跟踪更改的时间和更改者。将这些备忘录保存到磁盘的某个地方，可以让您回溯并快速构建指向更改对象的审计日志。

+   观察者模式因为监听器没有正确注销而导致内存泄漏而臭名昭著。即使在 JavaScript 这样的内存管理环境中，这种情况也可能发生。要警惕未能取消观察者。

# 总结

在本章中，我们已经看过了一堆行为模式。其中一些模式，比如观察者和迭代器，几乎每天都会用到，而另一些模式，比如解释器，你可能在整个职业生涯中只会用到几次。了解这些模式应该有助于您找到常见问题的明确定义解决方案。

大多数模式都直接适用于 JavaScript，其中一些模式，比如策略模式，在动态语言中变得更加强大。我们发现的唯一有一些限制的模式是访问者模式。缺乏静态类和多态性使得这个模式难以实现，而不破坏适当的关注点分离。

这些并不是存在的所有行为模式。编程社区在过去的二十年里一直在基于 GoF 书中的思想并识别新的模式。本书的其余部分致力于这些新识别的模式。解决方案可能是非常古老的，但直到最近才被普遍认为是常见解决方案。就我而言，这是书开始变得非常有趣的地方，因为我们开始研究不太知名和更具 JavaScript 特色的模式。


# 第二部分。其他模式

函数式编程

响应式编程

应用程序模式

Web 模式

消息模式

微服务

测试模式

高级模式

ECMAScript-2015/2016 解决方案今天

在第一部分中，我们专注于 GoF 书中最初确定的模式，这些模式是软件设计模式背后的最初动力。在本书的这一部分中，我们将超越这些模式，看看与函数式编程相关的模式，用于构建整个应用程序的大规模模式，专门用于 Web 的模式以及消息模式。此外，我们将研究测试模式和一些非常有趣的高级模式。最后，我们将看看如何在今天就能获得 JavaScript 下一个版本的许多功能。



# 第六章：函数式编程

函数式编程是一种与我们迄今为止专注的重度面向对象方法不同的开发方法。面向对象编程是解决许多问题的绝佳工具，但也存在一些问题。在面向对象的上下文中进行并行编程是困难的，因为状态可能会被不同的线程改变，产生未知的副作用。函数式编程不允许状态或可变变量。函数在函数式编程中充当主要的构建块。在过去可能使用变量的地方现在将使用函数。

即使在单线程程序中，函数也可能具有改变全局状态的副作用。这意味着，当调用一个未知的函数时，它可能改变程序的整个流程。这使得调试程序变得非常困难。

JavaScript 并不是一种函数式编程语言，但我们仍然可以将一些函数式原则应用到我们的代码中。我们将研究函数式空间中的许多模式：

+   函数传递

+   过滤器和管道

+   累加器

+   备忘录

+   不可变性

+   延迟实例化

# 函数式函数是无副作用的

函数式编程的核心原则之一是函数不应改变状态。函数内部的局部值可以被设置，但函数外部的任何东西都不可以改变。这种方法对于使代码更易维护非常有用。不再需要担心将数组传递给函数会对其内容造成混乱。特别是在使用不受控制的库时，这是一个问题。

JavaScript 内部没有机制可以阻止您改变全局状态。相反，您必须依赖开发人员编写无副作用的函数。这可能很困难，也可能不是，这取决于团队的成熟度。

也许并不希望将应用程序中的所有代码都放入函数中，但尽可能地分离是可取的。有一种称为命令查询分离的模式建议方法应该分为两类。要么是读取值的函数，要么是设置值的命令。二者不可兼得。保持方法按此分类有助于调试和代码重用。

无副作用函数的一个结果是，它们可以使用相同的输入被调用任意次数，结果都将是相同的。此外，由于没有状态的改变，多次调用函数不会产生任何不良副作用，除了使其运行速度变慢。

# 函数传递

在函数式编程语言中，函数是一等公民。函数可以赋值给变量并像处理其他变量一样传递。这并不是完全陌生的概念。即使像 C 这样的语言也有可以像其他变量一样处理的函数指针。C#有委托，在更近期的版本中有 lambda。最新版本的 Java 也添加了对 lambda 的支持，因为它们被证明非常有用。

JavaScript 允许将函数视为变量，甚至作为对象和字符串。这样，JavaScript 在本质上是函数式的。

由于 JavaScript 的单线程特性，回调是一种常见的约定，你几乎可以在任何地方找到它们。考虑在网页上的稍后时间调用一个函数。这是通过在 window 对象上设置超时来实现的，就像这样：

```js
setTimeout(function(){alert("Hello from the past")}, 5 * 1000);
```

设置超时函数的参数是要调用的函数和以毫秒为单位的延迟时间。

无论您在哪种 JavaScript 环境中工作，几乎不可能避免以回调函数的形式使用函数。Node.js 的异步处理模型高度依赖于能够调用函数并传递一些内容以便在以后的某个日期完成。在浏览器中调用外部资源也依赖于回调来通知调用者某些异步操作已完成。在基本的 JavaScript 中，这看起来像这样：

```js
let xmlhttp = new XMLHttpRequest()
xmlhttp.onreadystatechange = function()
if (xmlhttp.readyState==4 && xmlhttp.status==200){
  //process returned data
}
};
xmlhttp.open("GET", http://some.external.resource, true);
xmlhttp.send();
```

您可能会注意到我们在发送请求之前就分配了`onreadystatechange`函数。这是因为稍后分配可能会导致服务器在函数附加到准备状态更改之前做出响应的竞争条件。在这种情况下，我们使用内联函数来处理返回的数据。因为函数是一等公民，我们可以将其更改为以下形式：

```js
let xmlhttp;
function requestData(){
  xmlhttp = new XMLHttpRequest()
  xmlhttp.onreadystatechange=processData;
  xmlhttp.open("GET", http://some.external.resource, true);
  xmlhttp.send();
}

function processData(){
  if (xmlhttp.readyState==4 &&xmlhttp.status==200){
    //process returned data
  }
}
```

这通常是一种更清晰的方法，避免在另一个函数中执行复杂的处理。

但是，您可能更熟悉 jQuery 版本，它看起来像这样：

```js
$.getJSON('http://some.external.resource', function(json){
  //process returned data
});
```

在这种情况下，处理准备状态变化的模板已经为您处理了。如果请求数据失败，甚至还为您提供了便利：

```js
$.ajax('http://some.external.resource',
  { success: function(json){
      //process returned data
    },
    error: function(){
      //process failure
    },
    dataType: "json"
});
```

在这种情况下，我们将一个对象传递给`ajax`调用，该对象定义了许多属性。在这些属性中，成功和失败的函数回调是其中之一。将多个函数传递到另一个函数中的这种方法表明了为类提供扩展点的一种很好的方式。

很可能您以前已经看到过这种模式的使用，甚至没有意识到。将函数作为选项对象的一部分传递给构造函数是 JavaScript 库中提供扩展挂钩的常用方法。在上一章中，第五章，*行为模式*中，我们看到了对函数的一些处理，当将函数传递给观察者时。

## 实施

在维斯特洛，旅游业几乎不存在。有很多困难，如强盗杀害游客和游客卷入地区冲突。尽管如此，一些有远见的人已经开始宣传维斯特洛斯的大巡回之旅，他们将带领有能力的人游览所有主要景点。从国王之地到艾利，再到多恩的巨大山脉-这次旅行将覆盖一切。事实上，旅游局中一个相当数学倾向的成员已经开始称其为哈密顿之旅，因为它到达每个地方一次。

`HamiltonianTour`类提供了一个选项对象，允许定义一个选项对象。该对象包含可以附加回调的各种位置。在我们的情况下，它的接口看起来可能是以下样子：

```js
export class HamiltonianTourOptions{
  onTourStart: Function;
  onEntryToAttraction: Function;
  onExitFromAttraction: Function;
  onTourCompletion: Function;
}
```

完整的`HamiltonianTour`类如下所示：

```js
class HamiltonianTour {
  constructor(options) {
    this.options = options;
  }
  StartTour() {
    if (this.options.onTourStart && typeof (this.options.onTourStart) === "function")
      this.options.onTourStart();
      this.VisitAttraction("King's Landing");
      this.VisitAttraction("Winterfell");
      this.VisitAttraction("Mountains of Dorne");
      this.VisitAttraction("Eyrie");
    if (this.options.onTourCompletion && typeof (this.options.onTourCompletion) === "function")
      this.options.onTourCompletion();
  }
  VisitAttraction(AttractionName) {
    if (this.options.onEntryToAttraction && typeof (this.options.onEntryToAttraction) === "function")
      this.options.onEntryToAttraction(AttractionName);
      //do whatever one does in a Attraction
    if (this.options.onExitFromAttraction && typeof (this.options.onExitFromAttraction) === "function")
      this.options.onExitFromAttraction(AttractionName);
  }
}
```

您可以在突出显示的代码中看到我们如何检查选项，然后根据需要执行回调。只需简单地执行以下操作即可使用：

```js
var tour = new HamiltonianTour({
  onEntryToAttraction: function(cityname){console.log("I'm delighted to be in " + cityname)}});
      tour.StartTour();
```

运行此代码的输出将如下所示：

```js
I'm delighted to be in King's Landing
I'm delighted to be in Winterfell
I'm delighted to be in Mountains of Dorne
I'm delighted to be in Eyrie
```

在 JavaScript 中传递函数是解决许多问题的好方法，并且在 jQuery 等库和 express 等框架中被广泛使用。它是如此普遍地被采用，以至于使用它会增加代码的可读性障碍。

# 过滤器和管道

如果您对 Unix 命令行或者在较小程度上对 Windows 命令行有所了解，那么您可能已经使用过管道。管道由`|`字符表示，它是“获取程序 A 的输出并将其放入程序 B”的简写。这个相对简单的想法使得 Unix 命令行非常强大。例如，如果您想要列出目录中的所有文件，然后对它们进行排序并过滤出以字母`b`或`g`开头并以`f`结尾的文件，那么命令可能如下所示：

```js
ls|sort|grep "^[gb].*f$"
```

`ls`命令列出所有文件和目录，`sort`命令对它们进行排序，`grep`命令匹配文件名与正则表达式。在 Ubuntu 的`/etc`目录中运行这个命令会得到类似以下的结果：

```js
 **stimms@ubuntu1:/etc$ ls|sort|grep "^[gb].*f$"** 

blkid.conf
bogofilter.cf
brltty.conf
gai.conf
gconf
groff
gssapi_mech.conf
```

一些函数式编程语言，如 F#，提供了在函数之间进行管道传递的特殊语法。在 F#中，可以通过以下方式对列表进行偶数过滤：

```js
[1..10] |>List.filter (fun n -> n% 2 = 0);;
```

这种语法看起来非常漂亮，特别是在长链式函数中使用时。例如，将一个数字转换为浮点数，然后对其进行平方根运算，最后四舍五入，看起来会像下面这样：

```js
10.5 |> float |>Math.Sqrt |>Math.Round
```

这比 C 风格的语法更清晰，后者看起来会像下面这样：

```js
Math.Round(Math.Sqrt((float)10.5))
```

不幸的是，JavaScript 没有使用巧妙的 F#风格语法编写管道的能力，但是我们仍然可以通过方法链接来改进前面代码中显示的普通方法。

JavaScript 中的所有内容都是对象，这意味着我们可以通过向现有对象添加功能来改进它们的外观。对对象集合进行操作是函数式编程提供一些强大功能的领域。让我们首先向数组对象添加一个简单的过滤方法。您可以将这些查询视为以函数式方式编写的 SQL 数据库查询。

## 实现

我们希望提供一个对数组的每个成员进行匹配并返回一组结果的函数：

```js
Array.prototype.where = function (inclusionTest) {
  let results = [];
  for (let i = 0; i<this.length; i++) {
    if (inclusionTest(this[i]))
      results.push(this[i]);
  }
  return results;
};
```

这个看起来相当简单的函数允许我们快速过滤一个数组：

```js
var items = [1,2,3,4,5,6,7,8,9,10];
items.where(function(thing){ return thing % 2 ==0;});
```

我们返回的也是一个对象，这种情况下是一个数组对象。我们可以继续像下面这样链式调用方法：

```js
items.where(function(thing){ return thing % 2 ==0;})
  .where(function(thing){ return thing % 3 == 0;});
```

结果是一个只包含数字 6 的数组，因为它是 1 到 10 之间唯一既是偶数又可被三整除的数字。返回原始对象的修改版本而不改变原始对象的方法称为流畅接口。通过不改变原始的项目数组，我们为变量引入了一定程度的不可变性。

如果我们向数组扩展库添加另一个函数，我们就可以开始看到这些管道有多么有用：

```js
Array.prototype.select=function(projection){
  let results = [];
  for(let i = 0; i<this.length;i++){
    results.push(projection(this[i]));
  }
  return results;
};
```

这个扩展允许根据任意投影函数对原始项目进行投影。给定一组包含 ID 和名称的对象，我们可以使用我们的流畅扩展到数组来执行复杂的操作：

```js
let children = [{ id: 1, Name: "Rob" },
{ id: 2, Name: "Sansa" },
{ id: 3, Name: "Arya" },
{ id: 4, Name: "Brandon" },
{ id: 5, Name: "Rickon" }];
let filteredChildren = children.where(function (x) {
  return x.id % 2 == 0;
}).select(function (x) {
  return x.Name;
});
```

这段代码将构建一个新数组，其中只包含具有偶数 ID 的子项，而不是完整的对象，数组将只包含它们的名称：`Sansa`和`Brandon`。对于熟悉.Net 的人来说，这些函数可能看起来非常熟悉。.Net 上的**语言集成查询**（**LINQ**）库提供了类似命名的受函数启发的函数，用于操作集合。

以这种方式链接函数既更容易理解，也更容易构建，因为避免了临时变量，代码更加简洁。考虑使用循环和临时变量重新实现前面的示例：

```js
let children = [{ id: 1, Name: "Rob" },
{ id: 2, Name: "Sansa" },
{ id: 3, Name: "Arya" },
{ id: 4, Name: "Brandon" },
{ id: 5, Name: "Rickon" }];
let evenIds = [];
for(let i=0; i<children.length;i++)
{
  if(children[i].id%2==0)
    evenIds.push(children[i]);
}
let names = [];
for(let i=0; i< evenIds.length;i++)
{
  names.push(evenIds[i].name);
}
```

许多 JavaScript 库，比如 d3，都是为了鼓励这种编程方式而构建的。起初，遵循这种约定创建的代码似乎很糟糕，因为行长非常长。我认为这是行长不是一个很好的衡量复杂性的工具，而不是这种方法的实际问题。

# 累加器

我们已经研究了一些简单的数组函数，它们为数组添加了过滤和管道。另一个有用的工具是累加器。累加器通过对集合进行迭代来帮助构建单个结果。许多常见的操作，比如对数组元素求和，都可以使用累加器来实现，而不是使用循环。

递归在函数式编程语言中很受欢迎，其中许多语言实际上提供了一种称为“尾递归优化”的优化。支持这一点的语言为使用递归的函数提供了优化，其中堆栈帧被重用。这是非常高效的，可以轻松地替代大多数循环。关于 JavaScript 解释器是否支持尾递归优化的细节还不清楚。在大多数情况下，似乎并不支持，但我们仍然可以利用递归。

`for`循环的问题在于循环中的控制流是可变的。考虑这个相当容易犯的错误：

```js
let result = "";
let multiArray = [[1,2,3], ["a", "b", "c"]];
for(vari=0; i<multiArray.length; i++)
  for(var j=0; i<multiArray[i].length; j++)
    result += multiArray[i][j];
```

你发现错误了吗？我尝试了几次才得到一个可行的版本，我才发现了问题。问题在于第二个循环中的循环计数器，它应该是这样的：

```js
let result = "";
let multiArray = [[1,2,3], ["a", "b", "c"]];
for(let i=0; i<multiArray.length; i++)
  for(let j=0; j<multiArray[i].length; j++)
    result +=multiArray[i][j];
```

显然，通过更好的变量命名可以在一定程度上缓解这个问题，但我们希望完全避免这个问题。

相反，我们可以利用累加器，这是一个将集合中的多个值组合成单个值的工具。我们错过了 Westeros 的一些模式，所以让我们回到我们的神话般的例子。战争花费了大量的金钱，但幸运的是有大量的农民来交税，为领主们的王位之争提供资金。

## 实施

我们的农民由一个简单的模型代表，看起来像下面这样：

```js
let peasants = [
  {name: "Jory Cassel", taxesOwed: 11, bankBalance: 50},
  {name: "VardisEgen", taxesOwed: 15, bankBalance: 20}];
```

在这组农民中，我们有一个看起来像下面这样的累加器：

```js
TaxCollector.prototype.collect = function (items, value, projection) {
  if (items.length> 1)
    return projection(items[0]) + this.collect(items.slice(1), value, projection);
  return projection(items[0]);
};
```

这段代码接受一个项目列表，一个累加器值，以及一个将值投影到累加中的函数。

投影函数看起来像下面这样：

```js
function (item) {
  return Math.min(item.moneyOwed, item.bankBalance);
}
```

为了激活这个函数，我们只需要传入一个累加器的初始值以及数组和投影。激活值会有所不同，但往往是一个身份；在字符串累加器的情况下是一个空字符串，在数学累加器的情况下是 0 或 1。

每次通过累加器，我们都会缩小我们操作的数组的大小。所有这些都是在没有一个可变变量的情况下完成的。

内部累积可以是任何你喜欢的函数：字符串追加，加法，或者更复杂的东西。累加器有点像访问者模式，只是在累加器内部修改集合中的值是不被赞同的。记住，函数式编程是无副作用的。

# 记忆化

不要与记忆混淆，记忆化是一个特定术语，用于保留函数中先前计算的值。

正如我们之前看到的，无副作用的函数可以被多次调用而不会引起问题。与此相对的是，函数也可以被调用的次数少于需要的次数。考虑一个复杂或者至少耗时的数学运算的昂贵函数。我们知道函数的结果完全取决于函数的输入。因此，相同的输入将始终产生相同的输出。那么，为什么我们需要多次调用函数呢？如果我们保存函数的输出，我们可以检索到它，而不是重新进行耗时的数学运算。

以空间换时间是一个经典的计算科学问题。通过缓存结果，我们可以使应用程序更快，但会消耗更多的内存。决定何时进行缓存，何时简单地重新计算结果是一个困难的问题。

## 实施

在维斯特洛大陆，被称为大师的学者们长期以来对一个数字序列产生了浓厚的兴趣，这个序列似乎在自然界中频繁出现。一个奇怪的巧合是，他们称这个序列为斐波那契数列。它的定义是将序列中的前两个项相加以得到下一个项。这个序列的起始项被定义为 0、1、1。所以要得到下一个项，我们只需将 1 和 1 相加得到 2。下一个项将 2 和 1 相加得到 3，依此类推。找到序列的任意成员需要找到前两个成员，因此可能需要进行一些计算。

在我们的世界中，我们已经发现了一个避免大部分计算的封闭形式，但在维斯特洛还没有做出这样的发现。

一个朴素的方法是简单地计算每个项，如下所示：

```js
let Fibonacci = (function () {
  function Fibonacci() {
  }
  Fibonacci.prototype.NaieveFib = function (n) {
    if (n == 0)
      return 0;
    if (n <= 2)
      return 1;
    return this.NaieveFib(n - 1) + this.NaieveFib(n - 2);
  };
  return Fibonacci;
})();
```

这个解决方案对于小数字（比如 10）非常快。然而，对于更大的数字，比如大于 40，速度会明显变慢。这是因为基本情况被调用了 102,334,155 次。

让我们看看是否可以通过备忘录一些值来改善情况：

```js
let Fibonacci = (function () {
  function Fibonacci() {
    this.memoizedValues = [];
  }

  Fibonacci.prototype.MemetoFib = function (n) {
    if (n == 0)
      return 0;
    if (n <= 2)
      return 1;
    if (!this. memoizedValues[n])
      this. memoizedValues[n] = this.MemetoFib(n - 1) + this.MemetoFib(n - 2);
    return this. memoizedValues[n];
  };
  return Fibonacci;
})();
```

我们刚刚对我们遇到的每个项目进行了备忘录。事实证明，对于这个算法，我们存储了*n+1*个项目，这是一个相当不错的折衷。没有备忘录，计算第 40 个斐波那契数需要 963 毫秒，而备忘录版本只需要 11 毫秒。当函数变得更复杂时，差异会更加明显。备忘录版本的斐波那契数列 140 只需要 12 毫秒，而朴素版本……嗯，已经过了一天，它还在运行。

备忘录的最大优点是，对具有相同参数的函数的后续调用将非常快，因为结果已经计算过了。

在我们的例子中，只需要一个非常小的缓存。在更复杂的例子中，很难知道缓存应该有多大，或者一个值需要重新计算的频率。理想情况下，您的缓存应该足够大，以至于总是有足够的空间来放更多的结果。然而，这可能并不现实，需要做出艰难的决定，即哪些缓存成员应该被移除以节省空间。有很多方法可以执行缓存失效。有人说，缓存失效是计算科学中最棘手的问题之一，原因是我们实际上在试图预测未来。如果有人完善了一种预测未来的方法，那么他们很可能会将自己的技能应用于比缓存失效更重要的领域。两个选择是依赖于最近最少使用的缓存成员或最不经常使用的成员。问题的形状可能决定了更好的策略。

备忘录是加速需要多次执行的计算或者有共同子计算的计算的一个奇妙工具。人们可以将备忘录视为缓存的一种特殊情况，这是在构建网络服务器或浏览器时常用的技术。在更复杂的 JavaScript 应用程序中探索备忘录是值得的。

# 不变性

函数式编程的基石之一是所谓的变量只能被赋值一次。这就是不变性。ECMAScript 2015 支持一个新关键字，`const`。`const`关键字可以像`var`一样使用，只是用`const`赋值的变量将是不可变的。例如，以下代码显示了一个变量和一个常量，它们都以相同的方式被操作：

```js
let numberOfQueens = 1;
const numberOfKings = 1;
numberOfQueens++;
numberOfKings++;
console.log(numberOfQueens);
console.log(numberOfKings);
```

运行的输出如下：

```js
2
1
```

正如你所看到的，常数和变量的结果是不同的。

如果您使用的是不支持`const`的旧浏览器，那么`const`对您来说将不可用。一个可能的解决方法是使用更广泛采用的`Object.freeze`功能：

```js
let consts = Object.freeze({ pi : 3.141});
consts.pi = 7;
console.log(consts.pi);//outputs 3.141
```

正如您所看到的，这里的语法并不是很用户友好。另一个问题是，尝试对已分配的`const`进行赋值只会静默失败，而不是抛出错误。以这种方式静默失败绝对不是一种理想的行为；应该抛出完整的异常。如果启用了严格模式，ECMAScript 5 中添加了更严格的解析模式，并且实际上会抛出异常：

```js
"use strict";
var consts = Object.freeze({ pi : 3.141});
consts.pi = 7;
```

前面的代码将抛出以下错误：

```js
consts.pi = 7;
          ^
TypeError: Cannot assign to read only property 'pi' of #<Object>
```

另一种方法是我们之前提到的`object.Create`语法。在创建对象的属性时，可以指定`writable: false`来使属性不可变：

```js
var t = Object.create(Object.prototype,
{ value: { writable: false,
  value: 10}
});
t.value = 7;
console.log(t.value);//prints 10
```

然而，即使在严格模式下，当尝试写入不可写属性时也不会抛出异常。因此，我认为`const`关键字并不完美地实现了不可变对象。最好使用 freeze。

# 延迟实例化

如果您进入一个高端咖啡店并点一杯过于复杂的饮料（大杯奶茶拿铁，3 泵，脱脂牛奶，少水，无泡沫，超热，有人吗？），那么这种饮料将是临时制作的，而不是提前制作的。即使咖啡店知道当天会有哪些订单，他们也不会提前制作所有的饮料。首先，因为这会导致大量的毁坏、冷却的饮料，其次，如果他们必须等待当天所有订单完成，第一个顾客要等很长时间才能拿到他们的订单。

咖啡店遵循按需制作饮料的方法。他们在点单时制作饮料。我们可以通过使用一种称为延迟实例化或延迟初始化的技术来将类似的方法应用到我们的代码中。

考虑一个昂贵的创建对象；也就是说，创建对象需要很长时间。如果我们不确定对象的值是否需要，我们可以推迟到以后再完全创建它。

## 实施

让我们来看一个例子。Westeros 并不是很喜欢昂贵的咖啡店，但他们确实喜欢好的面包店。这家面包店提前接受不同种类的面包请求，然后一旦有订单，就会一次性烘烤所有面包。然而，创建面包对象是一个昂贵的操作，所以我们希望推迟到有人来取面包时再进行：

```js
class Bakery {
  constructor() {
    this.requiredBreads = [];
  }
  orderBreadType(breadType) {
    this.requiredBreads.push(breadType);
  }
}
```

首先，我们创建一个要根据需要创建的面包类型列表。通过订购面包类型，这个列表会被追加：

```js
var Bakery = (function () {
  function Bakery() {
    this.requiredBreads = [];
  }
  Bakery.prototype.orderBreadType = function (breadType) {
    this.requiredBreads.push(breadType);
  };
```

这样就可以快速地将面包添加到所需的面包列表中，而不必为每个面包的创建付出代价。

现在当调用`pickUpBread`时，我们将实际创建面包：

```js
pickUpBread(breadType) {
  console.log("Picup of bread " + breadType + " requested");
  if (!this.breads) {
    this.createBreads();
  }
  for (var i = 0; i < this.breads.length; i++) {
    if (this.breads[i].breadType == breadType)
      return this.breads[i];
  }
}
createBreads() {
  this.breads = [];
  for (var i = 0; i < this.requiredBreads.length; i++) {
    this.breads.push(new Bread(this.requiredBreads[i]));
  }
}
```

在这里，我们调用了一系列操作：

```js
let bakery = new Westeros.FoodSuppliers.Bakery();
bakery.orderBreadType("Brioche");
bakery.orderBreadType("Anadama bread");
bakery.orderBreadType("Chapati");
bakery.orderBreadType("Focaccia");

console.log(bakery.pickUpBread("Brioche").breadType + "picked up");
```

这将导致以下结果：

```js
Pickup of bread Brioche requested.
Bread Brioche created.
Bread Anadama bread created.
Bread Chapati created.
Bread Focaccia created.
Brioche picked up
```

您可以看到实际面包的收集是在取货后进行的。

延迟实例化可以用来简化异步编程。Promise 是简化 JavaScript 中常见的回调的一种方法。Promise 是一个包含状态和结果的对象。首次调用时，promise 处于未解决状态；一旦`async`操作完成，状态就会更新为完成，并填充结果。您可以将结果视为延迟实例化。我们将在第九章 *Web Patterns*中更详细地讨论 promise 和 promise 库。

懒惰可以节省大量时间，因为创建昂贵的对象最终可能根本不会被使用。

# 提示和技巧

尽管回调是处理 JavaScript 中异步方法的标准方式，但它们很容易变得混乱。有许多方法可以解决这种混乱的代码：promise 库提供了一种更流畅的处理回调的方式，未来版本的 JavaScript 可能会采用类似于 C# `async/await`语法的方法。

我真的很喜欢累加器，但它们在内存使用方面可能效率低下。缺乏尾递归意味着每次通过都会增加另一个堆栈帧，因此这种方法可能会导致内存压力。在这种情况下，所有事情都是在内存和代码可维护性之间进行权衡。

# 总结

JavaScript 不是一种函数式编程语言。这并不是说不可能将一些函数式编程的思想应用到它上面。这些方法可以使代码更清晰、更易于调试。有些人甚至可能会认为问题的数量会减少，尽管我从未见过任何令人信服的研究。

在本章中，我们研究了六种不同的模式。延迟实例化、记忆化和不可变性都是创建模式。函数传递既是结构模式，也是行为模式。累加器也是行为模式。过滤器和管道实际上并不属于 GoF 的任何一类，因此可以将它们视为一种样式模式。

在下一章中，我们将研究一些在应用程序中划分逻辑和呈现的模式。随着 JavaScript 应用程序的增长，这些模式变得更加重要。



# 第七章：响应式编程

我曾经读过一本书，书中提到牛顿在观察芦苇周围的河流时想出了微积分的概念。我从未能找到其他支持这一说法的来源。然而，这是一个很好的形象。微积分涉及理解系统随时间变化的状态。大多数开发人员在日常工作中很少需要处理微积分。然而，他们必须处理系统的变化。毕竟，一个完全不变的系统是相当无聊的。

在过去几年中，关于将变化视为一系列事件的不同想法已经出现 - 就像牛顿所观察到的那条河流一样。给定一个起始位置和一系列事件，应该可以找出系统的状态。事实上，这就是使用事件存储的想法。我们不是将聚合的最终状态保存在数据库中，而是跟踪已应用于该聚合的所有事件。通过重放这一系列事件，我们可以重新创建聚合的当前状态。这似乎是一种存储对象状态的绕圈方式，但实际上对于许多情况非常有用。例如，一个断开连接的系统，比如手机应用程序在手机未连接到网络时，使用事件存储可以更容易地与其他事件合并，而不仅仅是保留最终状态。对于审计场景，它也非常有用，因为可以通过简单地在时间索引处停止重放来将系统拉回到任何时间点的状态。你有多少次被问到，“为什么系统处于这种状态？”，而你无法回答？有了事件存储，答案应该很容易确定。

在本章中，我们将涵盖以下主题：

+   应用状态变化

+   流

+   过滤流

+   合并流

+   用于多路复用的流

# 应用状态变化

在应用程序中，我们可以将所有事件发生的事情视为类似的事件流。用户点击按钮？事件。用户的鼠标进入某个区域？事件。时钟滴答？事件。在前端和后端应用程序中，事件是触发状态变化的事物。你可能已经在使用事件监听器进行事件处理。考虑将点击处理程序附加到按钮上：

```js
var item = document.getElementById("item1");
item. addEventListener("click", function(event){ /*do something */ });
```

在这段代码中，我们已经将处理程序附加到了`click`事件上。这是相当简单的代码，但是想象一下当我们添加条件时，这段代码的复杂性会如何迅速增加，比如“在点击后忽略 500 毫秒内的额外点击，以防止人们双击”和“如果按住*Ctrl*键时点击按钮，则触发不同的事件”。响应式编程或函数式响应式编程通过使用流提供了这些复杂交互场景的简单解决方案。让我们探讨一下你的代码如何从利用响应式编程中受益。

# 流

想要简单地思考事件流的最简单方法不是考虑你以前在编程中可能使用过的流，而是考虑数组。假设你有一个包含一系列数字的数组：

```js
[1, 4, 6, 9, 34, 56, 77, 1, 2, 3, 6, 10]
```

现在你想要过滤这个数组，只显示偶数。在现代 JavaScript 中，可以通过数组的`filter`函数轻松实现这一点：

```js
[1, 4, 6, 9, 34, 56, 77, 1, 2, 3, 6, 10].filter((x)=>x%2==0) =>
[4, 6, 34, 56, 2, 6, 10]
```

可以在这里看到一个图形表示：

![流](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00032.jpg)

这里的过滤功能保持不变，无论数组中有十个项目还是一万个项目。现在，如果源数组不断添加新项目，我们希望通过将任何新的偶数项目插入到依赖数组中来保持其最新状态。为此，我们可以使用类似装饰器的模式来钩入数组的`add`函数。使用装饰器，我们可以调用过滤方法，如果找到匹配项，就将其添加到过滤后的数组中。

实际上，流是对未来事件集合的可观察对象。可以使用流操作解决许多有趣的问题。让我们从一个简单的问题开始：处理点击。这个问题非常简单，表面上似乎没有使用流的优势。别担心，随着我们的深入，我们会让它变得更加困难。

在大部分情况下，本书避免使用任何特定的 JavaScript 库。这是因为模式应该能够在不需要太多仪式的情况下轻松实现。然而，在这种情况下，我们实际上要使用一个库，因为流的实现有一些细微之处，我们希望有一些语法上的美感。如果你想看看如何实现基本的流，那么你可以基于第五章中概述的观察者模式进行实现。

JavaScript 中有许多流库，如 Reactive.js、Bacon.js 和 RxJS 等。每个库都有各种优点和缺点，但具体细节超出了本书的范围。在本书中，我们将使用 JavaScript 的 Reactive Extensions，其源代码可以在 GitHub 上找到[`github.com/Reactive-Extensions/RxJS`](https://github.com/Reactive-Extensions/RxJS)。

让我们从一个简短的 HTML 代码开始：

```js
<body>
  <button id="button"> Click Me!</button>
  <span id="output"></span>
</body>
```

接下来，让我们添加一个快速的点击计数器：

```js
<script>
  var counter = 0;
  var button = document.getElementById('button');
  var source = Rx.Observable.fromEvent(button, 'click');
  var subscription = source.subscribe(function (e) {
    counter++;
    output.innerHTML = "Clicked " + counter + " time" + (counter > 1 ? "s" : "");
  });
</script>
```

在这里，你可以看到我们正在从按钮的`click`事件创建一个新的事件流。新创建的流通常被称为元流。每当从源流中发出事件时，它会自动被操作和发布到元流中。我们订阅了这个流并增加一个计数器。如果我们只想对偶数事件做出反应，我们可以通过向流订阅第二个函数来实现：

```js
var incrementSubscription = source.subscribe(() => counter++);
var subscription = source.filter(x=>counter%2==0).subscribe(function (e) {
  output.innerHTML = "Clicked " + counter + " time" +(counter > 1 ? "s" : "");
});
```

在这里，你可以看到我们正在对流应用过滤器，以使计数器与更新屏幕的函数不同。但是，将计数器保留在流之外感觉有些不好，对吧？很可能，每隔一次点击增加一次并不是这个函数的目标。更有可能的是，我们只想在双击时运行一个函数。

这是用传统方法很难做到的，然而这些复杂的交互可以很容易地通过流来实现。您可以看到我们如何在这段代码中解决这个问题：

```js
source.buffer(() => source.debounce(250))
.map((list) => list.length)
.filter((x) => x >= 2)
.subscribe((x)=> {
  counter++;
  output.innerHTML = "Clicked " + counter + " time" + (counter > 1 ? "s" : "");
});
```

在这里，我们获取点击流并使用防抖动来缓冲流以生成缓冲区的边界。防抖动是硬件世界的一个术语，意味着我们将一个嘈杂的信号清理成一个单一的事件。当按下物理按钮时，通常会有一些额外的高或低信号，而不是我们想要的单点信号。实际上，我们消除了在一个窗口内发生的重复信号。在这种情况下，我们等待`250`毫秒，然后触发一个事件以移动到一个新的缓冲区。缓冲区包含在防抖期间触发的所有事件，并将它们的列表传递给链中的下一个函数。map 函数生成一个以列表长度为内容的新流。接下来，我们过滤流，只显示值为 2 或更多的事件，即两次点击或更多。事件流看起来像下面的图表：

![Streams](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00033.jpg)

使用传统的事件监听器和回调执行相同的逻辑将会非常困难。人们很容易想象出一个更复杂的工作流程，这将失控。FRP 允许更简化的方式来处理事件。

# 过滤流

正如我们在前面的部分中看到的，可以过滤事件流，并从中产生一个新的事件流。您可能熟悉能够过滤数组中的项目。ES5 引入了一些新的数组运算符，如**filter**和**some**。其中的第一个产生一个只包含符合过滤规则的元素的新数组。`Some`是一个类似的函数，如果数组的任何元素匹配，则简单返回`true`。这些相同类型的函数也支持在流上，以及您可能熟悉的来自函数式语言的函数，如 First 和 Last。除了对数组有意义的函数之外，还有许多基于时间序列的函数，当您考虑到流存在于时间中时，这些函数更有意义。

我们已经看到了防抖动，这是一个基于时间的过滤器的例子。防抖动的另一个非常简单的应用是防止用户双击提交按钮的恼人错误。考虑一下使用流的代码有多简单：

```js
Rx.Observable.FromEvent(button, "click")
.debounce(1000).subscribe((x)=>doSomething());
```

您可能还会发现像 Sample 这样的函数，它从时间窗口生成一组事件。当我们处理可能产生大量事件的可观察对象时，这是一个非常方便的函数。考虑一下我们维斯特洛斯的示例。

不幸的是，维斯特洛是一个相当暴力的地方，人们似乎以不愉快的方式死去。有这么多人死去，我们不可能每个人都关注，所以我们只想对数据进行抽样并收集一些死因。

为了模拟这个传入的流，我们将从一个数组开始，类似于以下内容：

```js
var deaths = 
  {
    Name:"Stannis",
    Cause: "Cold"
  },
  {
    Name: "Tyrion",
    Cause: "Stabbing"
  },
…
}
```

### 提示

您可以看到我们正在使用数组来模拟事件流。这可以用任何流来完成，并且是一个非常简单的测试复杂代码的方法。您可以在数组中构建一个事件流，然后以适当的延迟发布它们，从而准确地表示从文件系统到用户交互的事件流的任何内容。

现在我们需要将我们的数组转换为事件流。幸运的是，有一些使用`from`方法的快捷方式可以做到这一点。这将简单地返回一个立即执行的流。我们希望假装我们有一个定期分布的事件流，或者在我们相当阴郁的情况下，死亡。这可以通过使用 RxJS 的两种方法来实现：`interval`和`zip`。`interval`创建一个定期间隔的事件流。`zip`匹配来自两个流的事件对。这两种方法一起将以定期间隔发出新的事件流：

```js
function generateDeathsStream(deaths) {
  return Rx.Observable.from(deaths).zip(Rx.Observable.interval(500), (death,_)=>death);
}
```

在这段代码中，我们将死亡数组与每`500`毫秒触发一次的间隔流进行了合并。因为我们对间隔事件不是特别感兴趣，所以我们简单地丢弃了它，并将数组中的项目进行了投影。

现在我们可以通过简单地取样本然后订阅它来对这个流进行取样。在这里，我们每`1500`毫秒取样一次：

```js
generateDeathsStream(deaths).sample(1500).subscribe((item) => { /*do something */ });
```

你可以有任意多个订阅者订阅一个流，所以如果你想进行一些取样，以及可能一些聚合函数，比如简单地计算事件的数量，你可以通过有几个订阅者来实现。

```js
Var counter = 0;
generateDeathsStream(deaths).subscribe((item) => { counter++ });
```

# 合并流

我们已经看到了`zip`函数，它将事件一对一地合并以创建一个新的流，但还有许多其他合并流的方法。一个非常简单的例子可能是一个页面，它有几个代码路径，它们都想执行类似的操作。也许我们有几个动作，所有这些动作都会导致状态消息被更新：

```js
var button1 = document.getElementById("button1");
var button2 = document.getElementById("button2");
var button3 = document.getElementById("button3");
var button1Stream = Rx.Observable.fromEvent(button1, 'click');
var button2Stream = Rx.Observable.fromEvent(button2, 'click');
var button3Stream = Rx.Observable.fromEvent(button3, 'click');
var messageStream = Rx.Observable.merge(button1Stream, button2Stream, button3Stream);
messageStream.subscribe(function (x) { return console.log(x.type + " on " + x.srcElement.id); });
```

在这段代码中，你可以看到各种流被传递到合并函数中，然后产生了合并后的流：

![流](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00034.jpg)
  
合并流虽然有用，但这段代码似乎并不比直接调用事件处理程序更好，实际上它比必要的代码还要长。然而，考虑到状态消息的来源不仅仅是按钮推送。我们可能还希望异步事件也写出信息。例如，向服务器发送请求可能还想添加状态信息。另一个很棒的应用可能是使用在后台运行并使用消息与主线程通信的 web worker。对于基于 web 的 JavaScript 应用程序，这是我们实现多线程应用程序的方式。让我们看看它是什么样子。

首先，我们可以从 worker 角色创建一个流。在我们的示例中，worker 只是计算斐波那契数列。我们在页面上添加了第四个按钮，并触发了 worker 进程：

```js
var worker = Rx.DOM.fromWorker("worker.js");
button4Stream.subscribe(function (_) {  
  worker.onNext({ cmd: "start", number: 35 });
});
```

现在我们可以订阅合并后的流，并将其与所有先前的流结合起来：

```js
var messageStream = Rx.Observable.merge(button1Stream, button2Stream, button3Stream, worker);
messageStream.subscribe(function (x) {  
  appendToOutput(x.type + (x.srcElement.id === undefined ? " with " + x.data : " on " + x.srcElement.id));
}, function (err) { return appendToOutput(err, true); });
```

这一切看起来非常好，但我们不想一次给用户提供数十个通知。我们可以通过使用与之前看到的相同的间隔 zip 模式来限制事件流，以便一次只显示一个 toast。在这段代码中，我们用调用 toast 显示库来替换我们的`appendToOutput`方法：

```js
var messageStream = Rx.Observable.merge(button1Stream, button2Stream, button3Stream, worker);
var intervalStream = Rx.Observable.interval(5000);
messageStream.zip(intervalStream, function (x, _) { return x;})
  .subscribe(function (x) {  
    toastr.info(x.type + (x.srcElement.id === undefined ? " with " + x.data : " on " + x.srcElement.id));
  }, function (err) { return toastr.error(err); });
```

正如你所看到的，这个功能的代码很简短，易于理解，但包含了大量的功能。# 多路复用流在 Westeros 国王的议会中，没有人能够在权力地位上升到一定程度而不擅长建立间谍网络。通常，最好的间谍是那些能够最快做出反应的人。同样，我们可能有一些代码可以选择调用许多不同的服务中的一个来完成相同的任务。一个很好的例子是信用卡处理器：我们使用哪个处理器并不重要，因为它们几乎都是一样的。

为了实现这一点，我们可以启动多个 HTTP 请求到每个服务。如果我们将每个请求放入一个流中，我们可以使用它来选择最快响应的处理器，然后使用该处理器执行其余的操作。使用 RxJS，这看起来像下面这样：

```js
var processors = Rx.Observable.amb(processorStream1, processorStream2);
```

甚至可以在`amb`调用中包含一个超时，以处理处理器没有及时响应的情况。# 提示和技巧可以应用于流的不同函数有很多。如果你决定在 JavaScript 中使用 RxJS 库进行 FRP 需求，许多常见的函数已经为你实现了。更复杂的函数通常可以编写为包含函数链，因此在编写自己的函数之前，尝试想出一种通过链式调用来创建所需功能的方法。

在 JavaScript 中，经常会出现跨网络的异步调用失败。网络是不可靠的，移动网络尤其如此。在大多数情况下，当网络失败时，我们的应用程序也会失败。流提供了一个简单的解决方法，允许您轻松重试失败的订阅。在 RxJS 中，这种方法被称为“重试”。将其插入到任何可观察链中，可以使其更具抗网络故障的能力。

# 总结

函数式响应式编程在服务器端和客户端的不同应用中有许多用途。在客户端，它可以用于将大量事件整合成数据流，实现复杂的交互。它也可以用于最简单的事情，比如防止用户双击按钮。仅仅使用流来处理所有数据变化并没有太大的成本。它们非常易于测试，并且对性能影响很小。

FRP 最美好的一点也许是它提高了抽象级别。您不必处理繁琐的流程代码，而是可以专注于应用程序的逻辑流。