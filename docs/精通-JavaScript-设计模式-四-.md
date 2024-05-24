# 精通 JavaScript 设计模式（四）

> 原文：[`zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90`](https://zh.annas-archive.org/md5/C01E768309CC6F31A9A1148399C85D90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：高级模式

当我给这一章命名时，我犹豫不决，*高级模式*。这并不是关于比其他模式更复杂或复杂的模式。这是关于你不经常使用的模式。坦率地说，来自静态编程语言背景的一些模式看起来有些疯狂。尽管如此，它们是完全有效的模式，并且在各大项目中都在使用。

在本章中，我们将讨论以下主题：

+   依赖注入

+   实时后处理

+   面向方面的编程

+   宏

# 依赖注入

我们在本书中一直在讨论的一个主题是使你的代码模块化的重要性。小类更容易测试，提供更好的重用，并促进团队更好的协作。模块化，松散耦合的代码更容易维护，因为变更可以受限。你可能还记得我们之前使用的一个 ripstop 的例子。

在这种模块化代码中，我们看到了很多控制反转。类通过创建者传递额外的类来插入功能。这将一些子类的工作责任移交给了父类。对于小项目来说，这是一个相当合理的方法。随着项目变得更加复杂和依赖图变得更加复杂，手动注入功能变得越来越困难。我们仍然在整个代码库中创建对象，将它们传递给创建的对象，因此耦合问题仍然存在，我们只是将它提升到了更高的级别。

如果我们将对象创建视为一项服务，那么这个问题的解决方案就呈现出来了。我们可以将对象创建推迟到一个中心位置。这使我们能够在一个地方简单轻松地更改给定接口的实现。它还允许我们控制对象的生命周期，以便我们可以重用对象或在每次使用时重新创建它们。如果我们需要用另一个实现替换接口的一个实现，那么我们可以确信只需要在一个位置进行更改。因为新的实现仍然满足合同，也就是接口，那么使用接口的所有类都可以对更改保持无知。

更重要的是，通过集中对象创建，更容易构造依赖于其他对象的对象。如果我们查看诸如`UserManager`变量的模块的依赖图，很明显它有许多依赖关系。这些依赖关系可能还有其他依赖关系等等。要构建一个`UserManager`变量，我们不仅需要传递数据库，还需要`ConnectionStringProvider`，`CredentialProvider`和`ConfigFileConnectionStringReader`。天哪，要创建所有这些实例将是一项艰巨的工作。相反，我们可以在注册表中注册每个接口的实现，然后只需去注册表查找如何创建它们。这可以自动化，依赖关系会自动注入到所有依赖项中，无需显式创建任何依赖项。这种解决依赖关系的方法通常被称为“解决传递闭包”。

依赖注入框架处理构造对象的责任。在应用程序设置时，依赖注入框架使用名称和对象的组合进行初始化。从这个组合中，它创建一个注册表或容器。通过容器构造对象时，容器查看构造函数的签名，并尝试满足构造函数中的参数。以下是依赖图的示例：

![依赖注入](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00064.jpg)

在诸如 C#或 Java 等更静态类型的语言中，依赖注入框架很常见。它们通常通过使用反射来工作，反射是一种使用代码从其他代码中提取结构信息的方法。在构建容器时，我们指定一个接口和一个或多个可以满足该接口的具体类。当然，使用接口和反射执行依赖注入需要语言支持接口和内省。

在 JavaScript 中无法做到这一点。JavaScript 既没有直接的内省，也没有传统的对象继承模型。一种常见的方法是使用变量名来解决依赖问题。考虑一个具有以下构造函数的类：

```js
var UserManager = (function () {
  function UserManager(database, userEmailer) {
    this.database = database;
    this.userEmailer = userEmailer;
  }
  return UserManager;
})();
```

构造函数接受两个非常具体命名的参数。当我们通过依赖注入构造这个类时，这两个参数通过查看容器中注册的名称并将它们传递到构造函数中来满足。然而，没有内省，我们如何提取参数的名称，以便知道传递到构造函数中的内容呢？

解决方案实际上非常简单。在 JavaScript 中，任何函数的原始文本都可以通过简单地调用`toString`来获得。因此，对于前面代码中给出的构造函数，我们可以这样做：

```js
UserManager.toString()
```

现在我们可以解析返回的字符串以提取参数的名称。必须小心地解析文本，但这是可能的。流行的 JavaScript 框架 Angular 实际上使用这种方法来进行其依赖注入。结果仍然相对预格式。解析实际上只需要进行一次，并且结果被缓存，因此不会产生额外的开销。

我不会详细介绍如何实际实现依赖注入，因为这相当乏味。在解析函数时，你可以使用字符串匹配算法进行解析，也可以为 JavaScript 语法构建词法分析器和解析器。第一种解决方案似乎更容易，但更好的决定可能是尝试为代码构建一个简单的语法树，然后进行注入。幸运的是，整个方法体可以被视为一个单一的标记，因此比构建一个完全成熟的解析器要容易得多。

如果你愿意对依赖注入框架的用户施加不同的语法，甚至可以创建自己的语法。Angular 2.0 依赖注入框架`di.js`支持自定义语法，用于表示应该注入对象的位置以及表示哪些对象满足某些要求。

将其用作需要注入一些代码的类，看起来像这段代码，取自`di.js`示例页面：

```js
@Inject(CoffeeMaker, Skillet, Stove, Fridge, Dishwasher)
export class Kitchen {
  constructor(coffeeMaker, skillet, stove, fridge, dishwasher) {
    this.coffeeMaker = coffeeMaker;
    this.skillet = skillet;
    this.stove = stove;
    this.fridge = fridge;
    this.dishwasher = dishwasher;
  }
}
```

`CoffeeMaker`实例可能看起来像以下代码：

```js
@Provide(CoffeeMaker)
@Inject(Filter, Container)
export class BodumCoffeeMaker{
  constructor(filter, container){
  …
  }
}
```

你可能也注意到了，这个例子使用了`class`关键字。这是因为该项目非常前瞻，需要使用`traceur.js`来提供 ES6 类支持。我们将在下一章学习`traceur.js`文件。

# 实时后处理

现在应该明显了，在 JavaScript 中运行`toString`函数是执行任务的有效方式。这似乎很奇怪，但实际上，编写发出其他代码的代码与 Lisp 一样古老，甚至可能更古老。当我第一次了解 AngularJS 中依赖注入的工作原理时，我对这种 hack 感到恶心，但对解决方案的创造力印象深刻。

如果可以通过解释代码来进行依赖注入，那么我们还能做些什么呢？答案是：相当多。首先想到的是，你可以编写特定领域的语言。

我们在第五章中讨论了 DSL，*行为模式*，甚至创建了一个非常简单的 DSL。通过加载和重写 JavaScript 的能力，我们可以利用接近 JavaScript 但不完全兼容的语法。在解释 DSL 时，我们的解释器会写出转换代码为实际 JavaScript 所需的额外标记。

我一直喜欢 TypeScript 的一个很好的特性是，标记为 public 的构造函数参数会自动转换为对象的属性。例如，以下是 TypeScript 代码：

```js
class Axe{
  constructor(public handleLength, public headHeight){}
}
```

编译为以下代码：

```js
var Axe = (function () {
  function Axe(handleLength, headHeight) {
    this.handleLength = handleLength;
    this.headHeight = headHeight;
  }
  return Axe;
})();
```

我们可以在我们的 DSL 中做类似的事情。从以下`Axe`定义开始：

```js
class Axe{
  constructor(handleLength, /*public*/ headHeight){}
}
```

我们在这里使用了注释来表示`headHeight`应该是公共的。与 TypeScript 版本不同，我们希望我们的源代码是有效的 JavaScript。因为注释包含在`toString`函数中，这样做完全没问题。

接下来要做的事情是实际上从中发出新的 JavaScript。我采取了一种天真的方法，并使用了正则表达式。这种方法很快就会失控，可能只适用于`Axe`类中格式良好的 JavaScript：

```js
function publicParameters(func){
  var stringRepresentation = func.toString();
  var parameterString = stringRepresentation.match(/^function .*\((.*)\)/)[1];
  var parameters = parameterString.split(",");
  var setterString = "";
  for(var i = 0; i < parameters.length; i++){
    if(parameters[i].indexOf("public") >= 0){
      var parameterName = parameters[i].split('/')[parameters[i].split('/').length-1].trim();
      setterString += "this." +  parameterName + " = " + parameterName + ";\n";
    }
  }
  var functionParts = stringRepresentation.match(/(^.*{)([\s\S]*)/);
  return functionParts[1] + setterString + functionParts[2];
}

console.log(publicParameters(Axe));
```

在这里，我们提取函数的参数并检查具有`public`注释的参数。此函数的结果可以传回到 eval 中，用于当前对象的使用，或者如果我们在预处理器中使用此函数，则可以写入文件。通常不鼓励在 JavaScript 中使用 eval。

使用这种处理方式可以做很多不同的事情。即使没有字符串后处理，我们也可以通过包装方法来探索一些有趣的编程概念。

# 面向方面的编程

软件的模块化是一个很好的特性，本书的大部分内容都是关于模块化及其优势。然而，软件还有一些跨整个系统的特性。安全性就是一个很好的例子。

我们希望在应用程序的所有模块中都有类似的安全代码，以检查人们是否实际上被授权执行某些操作。所以如果我们有这样的一个函数：

```js
var GoldTransfer = (function () {
  function GoldTransfer() {
  }
  GoldTransfer.prototype.SendPaymentOfGold = function (amountOfGold, destination) {
    var user = Security.GetCurrentUser();
    if (Security.IsAuthorized(user, "SendPaymentOfGold")) {
      //send actual payment
    } else {
      return { success: 0, message: "Unauthorized" };
    }
  };
  return GoldTransfer;
})();
```

我们可以看到有相当多的代码来检查用户是否被授权。这个相同的样板代码在应用程序的其他地方也被使用。事实上，由于这是一个高安全性的应用程序，安全检查在每个公共函数中都有。一切都很好，直到我们需要对常见的安全代码进行更改。这个更改需要在应用程序的每一个公共函数中进行。我们可以重构我们的应用程序，但事实仍然存在：我们需要在每个公共方法中至少有一些代码来执行安全检查。这被称为横切关注点。

在大多数大型应用程序中，还存在其他横切关注点。日志记录是一个很好的例子，数据库访问和性能检测也是如此。**面向方面的编程**（**AOP**）提供了一种通过**编织**过程来最小化重复代码的方式。

方面是一段可以拦截方法调用并改变它们的代码。在.Net 平台上有一个叫做 PostSharp 的工具可以进行方面编织，在 Java 平台上有一个叫做 AspectJ 的工具。这些工具可以钩入构建管道，并在代码被转换为指令后修改代码。这允许在需要的地方注入代码。源代码看起来没有改变，但编译输出现在包括对方面的调用。方面通过被注入到现有代码中来解决横切关注点。在这里，你可以看到通过编织器将一个方面应用到一个方法：

![面向方面的编程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-dsn-ptn/img/Image00065.jpg)

当然，在大多数 JavaScript 工作流程中，我们没有设计时编译步骤的奢侈。幸运的是，我们已经看到了一些方法，可以让我们使用 JavaScript 实现横切。我们需要的第一件事是包装我们在测试章节中看到的方法。第二个是本章前面提到的`tostring`能力。

对于 JavaScript 已经存在一些 AOP 库，可能是一个值得探索的好选择。然而，我们可以在这里实现一个简单的拦截器。首先让我们决定请求注入的语法。我们将使用之前的注释的想法来表示需要拦截的方法。我们只需要将方法中的第一行作为注释，写上`aspect(<aspect 的名称>)`。

首先，我们将采用稍微修改过的与之前相同的`GoldTransfer`类的版本：

```js
class GoldTransfer {
  SendPaymentOfGold(amountOfGold, destination) {
    var user = Security.GetCurrentUser();
    if (Security.IsAuthorized(user, "SendPaymentOfGold")) {
    }
    else {
     return { success: 0, message: "Unauthorized" };
    }
  }
}
```

我们已经剥离了以前存在的所有安全性内容，并添加了一个控制台日志，以便我们可以看到它实际上是如何工作的。接下来，我们需要一个方面来编织进去：

```js
class ToWeaveIn {
   BeforeCall() {
    console.log("Before!");
  }
  AfterCall() {
    console.log("After!");
  }
}
```

为此，我们使用一个简单的类，其中有一个`BeforeCall`和一个`AfterCall`方法，一个在原始方法之前调用，一个在原始方法之后调用。在这种情况下，我们不需要使用 eval，所以拦截更安全：

```js
function weave(toWeave, toWeaveIn, toWeaveInName) {
  for (var property in toWeave.prototype) {
    var stringRepresentation = toWeave.prototype[property].toString();
    console.log(stringRepresentation);
    if (stringRepresentation.indexOf("@aspect(" + toWeaveInName + ")")>= 0) {
      toWeave.prototype[property + "_wrapped"] = toWeave.prototype[property];
      toWeave.prototype[property] = function () {
      toWeaveIn.BeforeCall();
      toWeave.prototype[property + "_wrapped"]();
      toWeaveIn.AfterCall();
    };
    }
  }
}
```

这个拦截器可以很容易地修改为一个快捷方式，并在调用主方法体之前返回一些内容。它也可以被改变，以便通过简单跟踪包装方法的输出，然后在`AfterCall`方法中修改函数的输出。

这是一个相当轻量级的 AOP 示例。对于 JavaScript AOP 已经存在一些框架，但也许最好的方法是利用预编译器或宏语言。

# 混入

正如我们在本书的早期看到的那样，JavaScript 的继承模式与 C＃和 Java 等语言中典型的模式不同。JavaScript 使用原型继承，允许轻松地向类添加函数，并且可以从多个来源添加。原型继承允许以类似于备受诟病的多重继承的方式从多个来源添加方法。多重继承的主要批评是很难理解在某种情况下将调用哪个方法的重载。在原型继承模型中，这个问题在一定程度上得到了缓解。因此，我们可以放心地使用从多个来源添加功能的方法，这被称为 mixin。

Mixin 是一段代码，可以添加到现有类中以扩展其功能。它们在需要在不同的类之间共享函数的场景中最有意义，其中继承关系过于强大。

让我们想象一种情景，这种功能会很方便。在维斯特洛大陆，死亡并不总是像我们的世界那样永久。然而，那些从死者中复活的人可能并不完全与他们活着时一样。虽然`Person`和`ReanimatedPerson`之间共享了很多功能，但它们之间并没有足够的继承关系。在这段代码中，您可以看到 underscore 的`extend`函数用于向我们的两个人类添加 mixin。虽然可以在没有`underscore`的情况下做到这一点，但正如前面提到的，使用库会使一些复杂的边缘情况变得方便：

```js
var _ = require("underscore");
export class Person{
}
export class ReanimatedPerson{
}
export class RideHorseMixin{
  public Ride(){
    console.log("I'm on a horse!");
  }
}

var person = new Person();
var reanimatedPerson = new ReanimatedPerson();
_.extend(person, new RideHorseMixin());
_.extend(reanimatedPerson, new RideHorseMixin());

person.Ride();
reanimatedPerson.Ride();
```

Mixin 提供了一个在不同对象之间共享功能的机制，但会污染原型结构。

# 宏

通过宏预处理代码并不是一个新的想法。对于 C 和 C++来说，这是非常流行的。事实上，如果你看一下 Linux 的 Gnu 工具的一些源代码，它们几乎完全是用宏编写的。宏因难以理解和调试而臭名昭著。有一段时间，像 Java 和 C＃这样的新创建的语言之所以不支持宏，正是因为这个原因。

话虽如此，甚至像 Rust 和 Julia 这样的最新语言也重新引入了宏的概念。这些语言受到了 Scheme 语言的宏的影响，Scheme 是 Lisp 的一个方言。C 宏和 Lisp/Scheme 宏的区别在于，C 版本是文本的，而 Lisp/Scheme 版本是结构的。这意味着 C 宏只是被赞美的查找/替换工具，而 Scheme 宏则意识到它们周围的**抽象语法树**（**AST**），使它们更加强大。

Scheme 的 AST 比 JavaScript 的简单得多。尽管如此，有一个非常有趣的项目叫做`Sweet.js`，它试图为 JavaScript 创建结构宏。

`Sweet.js`插入到 JavaScript 构建管道中，并使用一个或多个宏修改 JavaScript 源代码。有许多完整的 JavaScript 转译器，即生成 JavaScript 的编译器。这些编译器在多个项目之间共享代码时存在问题。它们的代码差异很大，几乎没有真正的共享方式。`Sweet.js`支持在单个步骤中扩展多个宏。这允许更好地共享代码。可重用的部分更小，更容易一起运行。

`Sweet.js`的一个简单示例如下：

```js
let var = macro {
  rule { [$var (,) ...] = $obj:expr } => {
    var i = 0;
    var arr = $obj;
    $(var $var = arr[i++]) (;) ...
  }

  rule { $id } => {
    var $id
  }
}
```

这里的宏提供了 ECMAScript-2015 风格的解构器，将数组分割成三个字段。该宏匹配数组赋值和常规赋值。对于常规赋值，宏只是返回标识，而对于数组的赋值，它将分解文本并替换它。

例如，如果您在以下内容上运行它：

```js
var [foo, bar, baz] = arr;
```

然后，结果将是以下内容：

```js
var i = 0;
var arr$2 = arr;
var foo = arr$2[i++];
var bar = arr$2[i++];
var baz = arr$2[i++];
```

这只是一个宏的例子。宏的威力真的非常壮观。宏可以创建一个全新的语言或改变非常微小的东西。它们可以很容易地插入以适应任何需求。

# 技巧和窍门

使用基于名称的依赖注入允许名称之间发生冲突。为了避免冲突，值得在注入的参数前加上特殊字符。例如，AngularJS 使用`$`符号来表示一个注入的术语。

在本章中，我多次提到了 JavaScript 构建流水线。我们不得不构建一种解释性语言可能看起来有些奇怪。然而，从构建 JavaScript 可能会产生某些优化和流程改进。有许多工具可以用于帮助构建 JavaScript。像 Grunt 和 Gulp 这样的工具专门设计用于执行 JavaScript 和 Web 任务，但您也可以利用传统的构建工具，如 Rake、Ant，甚至是 Make。 

# 总结

在本章中，我们涵盖了许多高级 JavaScript 模式。在这些模式中，我相信依赖注入和宏对我们最有用。您可能并不一定希望在每个项目中都使用它们。当面对问题时，仅仅意识到可能的解决方案可能会改变您对问题的处理方式。

在本书中，我广泛讨论了 JavaScript 的下一个版本。然而，您不需要等到将来才能使用这些工具。今天，有方法可以将较新版本的 JavaScript 编译成当前版本的 JavaScript。最后一章将探讨一些这样的工具和技术。



# 第十四章：ECMAScript-2015/2016 今天的解决方案

在本书中，我无法计算提到 JavaScript 即将推出的版本的次数，可以放心，这个数字很大。令人有些沮丧的是，语言没有跟上应用程序开发人员的要求。我们讨论过的许多方法在 JavaScript 的新版本中变得不再必要。然而，有一些方法可以让下一个版本的 JavaScript 在今天就能运行。

在本章中，我们将重点讨论其中的一些：

+   TypeScript

+   BabelJS

# TypeScript

编译成 JavaScript 的语言并不少。CoffeeScript 可能是这些语言中最知名的一个例子，尽管将 Java 编译成 JavaScript 的 Google Web Toolkit 也曾经非常流行。微软在 2012 年发布了一种名为 TypeScript 的语言，以设计成 JavaScript 的超集，就像 C++是 C 的超集一样。这意味着所有语法上有效的 JavaScript 代码也是 TypeScript 代码。

微软自身在一些较大的网络属性中大量使用 TypeScript。Office 365 和 Visual Studio Online 都有大量用 TypeScript 编写的代码库。这些项目实际上早于 TypeScript 很长时间。据报道，从 JavaScript 过渡到 TypeScript 相当容易，因为它是 JavaScript 的超集。

TypeScript 的设计目标之一是尽可能与 ECMAScript-2015 和未来版本兼容。这意味着 TypeScript 支持 ECMAScript-2016 的一些特性，尽管当然不是全部，以及 ECMAScript-2015 的大部分特性。TypeScript 部分支持的 ECMAScript-2016 的两个重要特性是装饰器和 async/await。

## 装饰器

在早些章节中，我们探讨了**面向方面的编程**（**AOP**）。使用 AOP，我们用拦截器包装函数。装饰器提供了一种简单的方法来做到这一点。假设我们有一个在维斯特洛传递消息的类。显然，那里没有电话或互联网，因此消息是通过乌鸦传递的。如果我们能监视这些消息将会非常有帮助。我们的`CrowMessenger`类看起来像下面这样：

```js
class CrowMessenger {
  @spy
  public SendMessage(message: string) {
    console.log(`Send message is ${message}`);
  }
}
var c = new CrowMessenger();
var r = c.SendMessage("Attack at dawn");
```

您可能会注意到`SendMessage`方法上的`@spy`注释。这只是另一个拦截和包装函数的函数。在 spy 内部，我们可以访问函数描述符。正如您在以下代码中所看到的，我们获取描述符并操纵它以捕获发送到`CrowMessenger`类的参数：

```js
function spy(target: any, key: string, descriptor?: any) {
  if(descriptor === undefined) {
    descriptor = Object.getOwnPropertyDescriptor(target, key);
  }
  var originalMethod = descriptor.value;

  descriptor.value =  function (...args: any[]) {
    var arguments = args.map(a => JSON.stringify(a)).join();
    var result = originalMethod.apply(this, args);
    console.log(`Message sent was: ${arguments}`);
    return result;
  }
  return descriptor;
}
```

间谍显然对于测试函数非常有用。我们不仅可以在这里监视值，还可以替换函数的输入和输出。考虑以下内容：

```js
descriptor.value =  function (...args: any[]) {
  var arguments = args.map(a => JSON.stringify(a)).join();
  **var result = "Retreat at once";** 

  console.log(`Message sent was: ${arguments}`);
  return result;
}
```

装饰器可以用于除 AOP 之外的其他目的。例如，您可以将对象的属性注释为可序列化，并使用注释来控制自定义 JSON 序列化。我怀疑随着装饰器的支持，装饰器将变得更加有用和强大。已经有 Angular 2.0 在大量使用装饰器。

## 异步/等待

在第七章中，*反应式编程*，我们谈到了 JavaScript 编程的回调性质使代码非常混乱。尝试将一系列异步事件链接在一起时，这一点表现得更加明显。我们很快陷入了一个看起来像下面这样的代码陷阱：

```js
$.post("someurl", function(){
  $.post("someotherurl", function(){
    $.get("yetanotherurl", function(){
      navigator.geolocation.getCurrentPosition(function(location){
        ...
      })
    })
  })
})
```

这段代码不仅难以阅读，而且几乎不可能理解。从 C#借鉴的异步/等待语法允许以更简洁的方式编写代码。在幕后，使用（或滥用，如果您愿意）生成器来创建真正的异步/等待的印象。让我们看一个例子。在前面的代码中，我们使用了返回客户端位置的地理位置 API。它是异步的，因为它与用户的机器进行一些 IO 以获取真实世界的位置。我们的规范要求我们获取用户的位置，将其发送回服务器，然后获取图像：

```js
navigator.geolocation.getCurrentPosition(function(location){
  $.post("/post/url", function(result){
    $.get("/get/url", function(){
   });
  });
});
```

如果我们现在引入异步/等待，代码可以变成以下形式：

```js
async function getPosition(){
  return await navigator.geolocation.getCurrentPosition();
}
async function postUrl(geoLocationResult){
  return await $.post("/post/url");
}
async function getUrl(postResult){
  return await $.get("/get/url");
}
async function performAction(){
  var position = await getPosition();
  var postResult = await postUrl(position);
  var getResult = await getUrl(postResult);
}
```

这段代码假设所有`async`响应都返回包含状态和结果的 promise 构造。事实上，大多数`async`操作并不返回 promise，但有库和工具可以将回调转换为 promise。正如您所看到的，这种语法比回调混乱要清晰得多，更容易理解。

## 类型

除了我们在前一节中提到的 ECMAScript-2016 功能之外，TypeScript 还具有一个非常有趣的类型系统。JavaScript 最好的部分之一是它是一种动态类型语言。我们反复看到，不受类型负担的好处节省了我们的时间和代码。TypeScript 中的类型系统允许您根据需要使用尽可能多或尽可能少的类型。您可以使用以下语法声明变量的类型：

```js
var a_number: number;
var a_string: string;
var an_html_element: HTMLElement;
```

一旦变量被分配了一个类型，TypeScript 编译器将使用它不仅来检查该变量的使用情况，还将推断出可能从该类派生的其他类型。例如，考虑以下代码：

```js
var numbers: Array<number> = [];
numbers.push(7);
numbers.push(9);
var unknown = numbers.pop();
```

在这里，TypeScript 编译器将知道`unknown`是一个数字。如果您尝试将其用作其他类型，比如以下字符串：

```js
console.log(unknown.substr(0,1));
```

然后编译器会抛出一个错误。然而，你不需要为任何变量分配类型。这意味着你可以调整类型检查的程度。虽然听起来很奇怪，但实际上这是一个很好的解决方案，可以在不失去 JavaScript 的灵活性的情况下引入类型检查的严谨性。类型只在编译期间强制执行，一旦代码编译成 JavaScript，与字段相关的类型信息的任何提示都会消失。因此，生成的 JavaScript 实际上非常干净。

如果你对类型系统感兴趣，知道逆变等词汇，并且可以讨论逐渐类型的各个层次，那么 TypeScript 的类型系统可能值得你花时间去研究。

本书中的所有示例最初都是用 TypeScript 编写的，然后编译成 JavaScript。这样做是为了提高代码的准确性，通常也是为了让我不那么频繁地搞砸。我非常偏袒，但我认为 TypeScript 做得非常好，肯定比纯 JavaScript 写得好。

未来版本的 JavaScript 中不支持类型。因此，即使未来版本的 JavaScript 带来了许多变化，我仍然相信 TypeScript 在提供编译时类型检查方面有其存在的价值。每当我写 TypeScript 时，类型检查器总是让我惊讶，因为它多次帮我避免了愚蠢的错误。

# BabelJS

TypeScript 的另一种选择是使用 BabelJS 编译器。这是一个开源项目，用于将 ECMAScript-2015 及更高版本转换为等效的 ECMAScript 5 JavaScript。ECMAScript-2015 中的许多更改都是语法上的美化，因此它们实际上可以表示为 ECMAScript 5 JavaScript，尽管不像那么简洁或令人愉悦。我们已经看到在 ES 5 中使用类似类的结构。BabelJS 是用 JavaScript 编写的，这意味着可以直接在网页上从 ECMAScript-2015 编译到 ES 5。当然，与编译器的趋势一样，BabelJS 的源代码使用了 ES 6 构造，因此必须使用 BabelJS 来编译 BabelJS。

在撰写本文时，BabelJS 支持的 ES6 函数列表非常广泛：

+   箭头函数

+   类

+   计算属性名称

+   默认参数

+   解构赋值

+   迭代器和 for of

+   生成器理解

+   生成器

+   模块

+   数字文字

+   属性方法赋值

+   对象初始化程序简写

+   剩余参数

+   扩展

+   模板文字

+   承诺

BabelJS 是一个多用途的 JavaScript 编译器，因此编译 ES-2015 代码只是它可以做的许多事情之一。有许多插件提供各种有趣的功能。例如，“内联环境变量”插件插入编译时变量，允许根据环境进行条件编译。

已经有大量关于这些功能如何工作的文档可用，因此我们不会详细介绍它们。

如果您已经安装了 node 和 npm，那么设置 Babel JS 就是一个相当简单的练习：

```js
 **npm install –g babel-cli** 

```

这将创建一个 BabelJS 二进制文件，可以进行编译，如下所示：

```js
 **babel  input.js --o output.js** 

```

对于大多数用例，您将希望使用构建工具，如 Gulp 或 Grunt，它们可以一次编译多个文件，并执行任意数量的后编译步骤。

## 类

到目前为止，你应该已经厌倦了阅读关于在 JavaScript 中创建类的不同方法。不幸的是，你是我写这本书的人，所以让我们看一个最后的例子。我们将使用之前的城堡例子。

BabelJS 不支持文件内的模块。相反，文件被视为模块，这允许以一种类似于`require.js`的方式动态加载模块。因此，我们将从我们的堡垒中删除模块定义，只使用类。TypeScript 中存在但 ES 6 中不存在的另一个功能是使用`public`作为参数前缀，使其成为类的公共属性。相反，我们使用`export`指令。

一旦我们做出了这些更改，源 ES6 文件看起来像这样：

```js
export class BaseStructure {
  constructor() {
    console.log("Structure built");
  }
}

export class Castle extends BaseStructure {
  constructor(name){
    this.name = name;
    super();
  }
  Build(){
    console.log("Castle built: " + this.name);
  }
}
```

生成的 ES 5 JavaScript 看起来像这样：

```js
"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

Object.defineProperty(exports, "__esModule", {
  value: true
});

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeofcall === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var BaseStructure = exports.BaseStructure = function BaseStructure() {
  _classCallCheck(this, BaseStructure);
  console.log("Structure built");
};

var Castle = exports.Castle = function (_BaseStructure) {
  _inherits(Castle, _BaseStructure);
  function Castle(name) {
    _classCallCheck(this, Castle);
    var _this = _possibleConstructorReturn(this, Object.getPrototypeOf(Castle).call(this));
    _this.name = name;
    return _this;
  }
  _createClass(Castle, [{
    key: "Build",
    value: function Build() {
      console.log("Castle built: " + this.name);
    }
  }]);
  return Castle;
}(BaseStructure);
```

立即就会发现，BabelJS 生成的代码不如 TypeScript 中的代码干净。您可能还注意到有一些辅助函数用于处理继承场景。还有许多提到`"use strict";`。这是对 JavaScript 引擎的指示，它应该以严格模式运行。

严格模式阻止了许多危险的 JavaScript 实践。例如，在一些 JavaScript 解释器中，可以在不事先声明变量的情况下使用它是合法的：

```js
x = 22;
```

如果`x`之前未声明，这将抛出错误：

```js
var x = 22;
```

不允许在对象中复制属性，也不允许重复声明参数。还有许多其他实践方法，`"use strict";`会将其视为错误。我认为`"use strict";`类似于将所有警告视为错误。它可能不像 GCC 中的`-Werror`那样完整，但在新的 JavaScript 代码库中使用严格模式仍然是一个好主意。BabelJS 只是为您强制执行这一点。

## 默认参数

ES 6 中一个不是很重要但确实很好的功能是默认参数的引入。在 JavaScript 中一直可以调用函数而不指定所有参数。参数只是从左到右填充，直到没有更多的值，并且所有剩余的参数都被赋予 undefined。

默认参数允许为未填充的参数设置一个值，而不是 undefined：

```js
function CreateFeast(meat, drink = "wine"){
  console.log("The meat is: " + meat);
  console.log("The drink is: " + drink);
}
CreateFeast("Boar", "Beer");
CreateFeast("Venison");
```

这将输出以下内容：

```js
The meat is: Boar
The drink is: Beer
The meat is: Venison
The drink is: wine
```

生成的 JavaScript 代码实际上非常简单：

```js
"use strict";
function CreateFeast(meat) {
  var drink = arguments.length <= 1 || arguments[1] === undefined ? "wine" : arguments[1];
  console.log("The meat is: " + meat);
  console.log("The drink is: " + drink);
}
CreateFeast("Boar", "Beer");
CreateFeast("Venison");
```

## 模板文字

表面上看，模板文字似乎是解决 JavaScript 中缺乏字符串插值的解决方案。在某些语言中，比如 Ruby 和 Python，您可以直接将周围代码中的替换插入到字符串中，而无需将它们传递给某种字符串格式化函数。例如，在 Ruby 中，您可以执行以下操作：

```js
name= "Stannis";
print "The one true king is ${name}"
```

这将把`${name}`参数绑定到周围范围内的名称。

ES6 支持模板文字，允许在 JavaScript 中实现类似的功能：

```js
var name = "Stannis";
console.log(`The one true king is ${name}`);
```

可能很难看到，但该字符串实际上是用反引号而不是引号括起来的。要绑定到作用域的标记由`${}`表示。在大括号内，您可以放置复杂的表达式，例如：

```js
var army1Size = 5000;
var army2Size = 3578;
console.log(`The surviving army will be ${army1Size > army2Size ? "Army 1": "Army 2"}`);
```

这段代码的 BabelJS 编译版本只是简单地用字符串拼接来替代字符串插值：

```js
var army1Size = 5000;
var army2Size = 3578;
console.log(("The surviving army will be " + (army1Size > army2Size ? "Army 1" : "Army 2")));
```

模板文字还解决了许多其他问题。模板文字内部的换行符是合法的，这意味着您可以使用模板文字来创建多行字符串。

考虑到多行字符串的想法，模板文字似乎对构建特定领域语言很有用：这是我们已经多次看到的一个主题。DSL 可以嵌入到模板文字中，然后从外部插入值。例如，可以使用它来保存 HTML 字符串（当然是 DSL）并从模型中插入值。这些可能取代今天使用的一些模板工具。

## 使用 let 进行块绑定

JavaScript 中的变量作用域很奇怪。如果在块内定义变量，比如在`if`语句内部，那么该变量仍然可以在块外部使用。例如，看下面的代码：

```js
if(true)
{
  var outside = 9;
}
console.log(outside);
```

这段代码将打印`9`，即使外部变量显然超出了范围。至少如果你假设 JavaScript 像其他 C 语法语言一样支持块级作用域，那么它就超出了范围。JavaScript 中的作用域实际上是函数级的。在`if`和`for`循环语句附加的代码块中声明的变量被提升到函数的开头。这意味着它们在整个函数的范围内保持有效。

ES 6 引入了一个新关键字`let`，它将变量的作用域限制在块级。这种类型的变量非常适合在循环中使用，或者在`if`语句中保持正确的变量值。Traceur 实现了对块级作用域变量的支持。然而，由于性能影响，目前该支持是实验性的。

考虑以下代码：

```js
if(true)
{
  var outside = 9;
  et inside = 7;
}
console.log(outside);
console.log(inside);
```

这将编译为以下内容：

```js
var inside$__0;
if (true) {
  var outside = 9;
  inside$__0 = 7;
}
console.log(outside);
console.log(inside);
```

您可以看到内部变量被替换为重命名的变量。一旦离开代码块，变量就不再被替换。运行这段代码时，当`console.log`方法发生时，内部变量将报告为未定义。

## 在生产中

BabelJS 是一个非常强大的工具，可以在今天复制下一个版本的 JavaScript 的许多结构和特性。然而，生成的代码永远不会像原生支持这些结构那样高效。值得对生成的代码进行基准测试，以确保它继续满足项目的性能要求。

# 技巧和窍门

JavaScript 中有两个优秀的库可以在集合功能上进行函数式操作：Underscore.js 和 Lo-Dash。与 TypeScript 或 BabelJS 结合使用时，它们具有非常愉快的语法，并提供了巨大的功能。

例如，使用 Underscore 查找满足条件的集合成员的所有成员看起来像下面这样：

```js
_.filter(collection, (item) => item.Id > 3);
```

这段代码将找到所有 ID 大于`3`的项目。

这两个库中的任何一个都是我在新项目中添加的第一件事。Underscore 实际上已经与 backbone.js 捆绑在一起，这是一个 MVVM 框架。

Grunt 和 Gulp 的任务用于编译用 TypeScript 或 BabelJS 编写的代码。当然，微软的开发工具链中也对 TypeScript 有很好的支持，尽管 BabelJS 目前没有直接支持。

# 总结

随着 JavaScript 功能的扩展，对第三方框架甚至转译器的需求开始减少。语言本身取代了许多这些工具。像 jQuery 这样的工具的最终目标是它们不再需要，因为它们已经被吸收到生态系统中。多年来，Web 浏览器的速度一直无法跟上人们愿望变化的速度。

AngularJS 的下一个版本背后有很大的努力，但正在努力使新组件与即将到来的 Web 组件标准保持一致。Web 组件不会完全取代 AngularJS，但 Angular 最终将简单地增强 Web 组件。

当然，认为不需要任何框架或工具的想法是荒谬的。总会有新的解决问题的方法和新的库和框架出现。人们对如何解决问题的看法也会有所不同。这就是为什么市场上存在各种各样的 MVVM 框架的原因。

如果您使用 ES6 构造来处理 JavaScript，那么工作将会更加愉快。有几种可能的方法来做到这一点，哪种方法最适合您的具体问题是需要更仔细调查的问题。
