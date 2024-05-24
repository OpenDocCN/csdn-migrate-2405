# JavaScript 代码整洁指南（三）

> 原文：[`zh.annas-archive.org/md5/EBCF13D1CBE3CB1395B520B840516EFC`](https://zh.annas-archive.org/md5/EBCF13D1CBE3CB1395B520B840516EFC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：动态类型化

在上一章中，我们探讨了 JavaScript 的内置值和类型，并涉及了在使用它们时涉及的一些挑战。接下来自然的步骤是探索 JavaScript 的动态系统在现实世界中是如何发挥作用的。由于 JavaScript 是一种动态类型的语言，代码中的变量在所引用的值的类型方面没有限制。这给清洁的编码者带来了巨大的挑战。由于我们的类型不确定，我们的代码可能以意想不到的方式中断，并且可能变得非常脆弱。这种脆弱性可以很简单地解释为想象一个嵌入在字符串中的数值：

```js
const possiblyNumeric = '203.45';
```

在这里，我们可以看到该值是数值，但它已被包装在一个字符串文字中，因此在 JavaScript 看来，它只是一个普通的字符串。但由于 JavaScript 是动态的，我们可以自由地将这个值传递给任何函数，甚至是一个期望一个数字的函数：

```js
setWidth('203.45');

function setWidth(width) {
  width += 20;       // Add margins
  applyWidth(width); // Apply the width
}
```

该函数通过`+=`运算符向数字添加了一个边距值。正如我们将在本章后面学到的那样，这个运算符是操作`a = a + b`的别名，而这里的`+`运算符，在任一操作数为`String`类型的情况下，将简单地将这两个字符串连接在一起。有趣的是，这个简单而无辜的实现细节是世界各地在不同时间发生的数百万次令人筋疲力尽的调试会话的关键。幸运的是，了解这个运算符及其确切的行为将为你节省无数个小时的痛苦和筋疲力尽，并且会牢固地铭记在你的脑海中，即避免我们已经陷入的`possiblyNumeric`值的陷阱的代码的重要性。

在本章中，我们将涵盖以下主题：

+   检测

+   转换、强制转换和转型

能够更轻松地处理我们的类型的第一个关键步骤是学习检测，即能够以最简单的方式辨别你正在处理的类型或类型的技能。

# 检测

检测是指确定值的类型的实践。通常，这将是为了使用确定的类型来执行特定的行为，比如回退到默认值或在误用的情况下抛出错误。

由于 JavaScript 的动态特性，检测类型是一种重要的实践，通常可以帮助其他程序员。如果你可以在某人错误地使用接口时有用地抛出错误或警告，那么对于他们来说，这意味着开发流程更加流畅和迅速。如果你可以有用地用智能默认值填充`undefined`、`null`或空值，那么它将允许你提供一个更无缝和直观的接口。

不幸的是，由于 JavaScript 中的遗留问题和设计中的一些选择，检测类型可能是具有挑战性的。使用了许多不被认为是最佳实践的不同方法。我们将在本节中讨论所有这些实践。然而，首先值得讨论一个关于检测的基本问题：**你究竟想要检测什么**？

我们经常认为我们需要特定的类型才能执行某些操作，但由于 JavaScript 的动态特性，我们可能并不需要这样做。事实上，这样做可能导致我们创建不必要的限制性或僵化的代码。

考虑一个接受`people`对象数组的函数，如下所示：

```js
registerPeopleForMarathon([
  new Person({ id: 1, name: 'Marcus Wu' }),
  new Person({ id: 2, name: 'Susan Smith' }),
  new Person({ id: 3, name: 'Sofia Polat' })
]);
```

在我们的`registerPeopleForMarathon`中，我们可能会想要实现某种检查，以确保传递的参数是预期的类型和结构：

```js
function registerPeopleForMarathon(people) {
  if (Array.isArray(people)) {
    throw new Error('People is not an array');
  }
  for (let person in people) {
    if (!(person instanceof Person)) {
      throw new Error('Each person should be an instance of Person');
    }
    registerForMarathon(person.id, person.name);
  }
}
```

这些检查有必要吗？你可能倾向于说有，因为它们确保我们的代码对潜在的错误情况具有弹性（或防御性），因此更可靠。但是如果我们仔细考虑一下，我们的这些检查都不是必要的，以确保我们寻求的可靠性。我们检查的意图，大概是为了防止错误类型或结构传递给我们的函数时产生下游错误，但是如果我们仔细观察前面的代码，我们担心的类型并没有下游错误的风险。

我们进行的第一个检查是`Array.isArray(people)`，以确定`people`值是否确实是一个数组。我们这样做，表面上是为了安全地遍历数组。但是，正如我们在前一章中发现的那样，`for...of`迭代风格并不依赖于`of {...}`值是一个数组。它只关心值是否可迭代。一个例子如下：

```js
function* marathonPeopleGenerator() {
  yield new Person({ id: 1, name: 'Marcus Wu' });
  yield new Person({ id: 2, name: 'Susan Smith' });
  yield new Person({ id: 3, name: 'Sofia Polat' });
}

for (let person of marathonPeopleGenerator()) {
 console.log(person.name);
}

// Logged => "Marcus Wu"
// Logged => "Susan Smith"
// Logged => "Sofia Polat"
```

在这里，我们使用生成器作为我们的可迭代对象。这将像数组一样在`for...of`中被迭代，因此，从技术上讲，我们可以说我们的`registerPeopleForMarathon`函数应该接受这样的值：

```js
// Should we allow this?
registerPeopleForMarathon(
  marathonPeopleGenerator()
);
```

到目前为止，我们进行的检查会拒绝这个值，因为它不是一个数组。这有意义吗？你还记得抽象原则以及我们应该关注接口而不是实现吗？从这个角度来看，可以说我们的`registerPeopleForMarathon`函数不需要知道传递值的类型的实现细节。它只关心值是否按照它的需求执行。在这种情况下，它需要通过`for...of`循环遍历值，因此任何可迭代对象都是合适的。为了检查可迭代性，我们可以使用这样的辅助函数：

```js
function isIterable(obj) {
  return obj != null &&
 typeof obj[Symbol.iterator] === 'function';
}

isIterable([1, 2, 3]); // => true
isIterable(marathonPeopleGenerator()); // => true
```

另外，要考虑的是，我们目前正在检查所有`person`值是否是`Person`构造函数的实例：

```js
// ...
if (!(person instanceof Person)) {
  throw new Error('Each person should be an instance of Person');
}
```

我们是否有必要以这种方式明确检查实例？相反，我们是否可以简单地检查我们希望访问的属性？也许我们需要断言的是属性不是假值（空字符串、null、undefined、零等）：

```js
// ...
if (!person || !person.name || !person.id) {
  throw new Error('Each person should have a name and id');
}
```

这个检查可能更符合我们真正的需求。这样的检查通常被称为**鸭子类型**，即*如果它走起来像鸭子，叫起来像鸭子，那么它一定是鸭子*。我们并不总是需要检查特定类型；我们可以检查我们真正依赖的属性、方法和特征。通过这样做，我们创建的代码更加灵活。

我们的新检查，当集成到我们的函数中时，会看起来像这样：

```js
function registerPeopleForMarathon(people) {
  if (isIterable(people)) {
    throw new Error('People is not iterable');
  }
  for (let person in people) {
    if (!person || !person.name || !person.id) {
      throw new Error('Each person should have a name and id');
    }
    registerForMarathon(person.id, person.name);
  }
}
```

通过使用更灵活的`isIterable`检查，并在我们的`person`对象上使用*鸭子类型*，我们的`registerPeopleForMarathon`函数现在可以被传递；例如，在这里，我们有一个生成器产生普通对象：

```js
function* marathonPeopleGenerator() {
  yield { id: 1, name: 'Marcus Wu' };
  yield { id: 2, name: 'Susan Smith' };
  yield { id: 3, name: 'Sofia Polat' };
}

registerPeopleForMarathon(
  marathonPeopleGenerator()
);
```

如果我们一直坚持严格的类型检查，这种灵活性是不可能的。更严格的检查通常会创建更严格的代码，并且不必要地限制灵活性。然而，这里需要取得平衡。我们不能无限制地灵活。甚至可能严格的类型检查提供的严谨性和确定性能够确保长期更清晰的代码。但相反的情况也可能成立。灵活性与严谨性的平衡是你应该不断考虑的。

一般来说，接口的期望应该尽可能接近实现的需求。也就是说，除非检查确实能够防止我们的实现中出现错误，否则我们不应该执行检测或其他检查。过度检查可能看起来更安全，但可能只意味着未来的需求和用例更难以适应。

现在我们已经解决了为什么我们要检测事物并且暴露了一些用例的问题，我们可以开始学习 JavaScript 提供给我们的检测技术。我们将从`typeof`运算符开始。

# typeof 运算符

当你第一次尝试在 JavaScript 中检测类型时，你通常会接触到的第一件事是`typeof`运算符：

```js
typeof 1; // => number
```

`typeof`运算符接受一个操作数，位于其右侧，并将根据传递的值之一求值为八种可能的字符串值之一：

```js
typeof 1; // => "number"
typeof ''; // => "string"
typeof {}; // => "object"
typeof function(){}; // => "function"
typeof undefined; // => "undefined"
typeof Symbol(); // => "symbol"
typeof 0n; // => "bigint"
typeof true; // => boolean
```

如果你的操作数是一个没有绑定的标识符，也就是一个未声明的变量，那么`typeof`将有用地返回`"undefined"`，而不是像对该变量的任何其他引用一样抛出`ReferenceError`：

```js
typeof somethingNotYetDeclared; // => "undefined"
```

`typeof`是 JavaScript 语言中唯一执行此操作的运算符。如果尚未声明该值，那么任何其他运算符和引用值的方式都会抛出错误。

除了检测未声明的变量外，`typeof`在确定原始类型时真的只有用处——即使这太宽泛了，因为并非所有原始类型都是可检测的。例如，当传递给`typeof`时，`null`值将求值为一个相当无用的`"object"`：

```js
typeof null; // => "object"
```

这是 JavaScript 语言的一个不幸且无法修复的遗留问题。它可能永远不会被修复。要检查`null`，最好明确检查值本身：

```js
let someValue = null;
someValue === null; // => true
```

`typeof`运算符在不是函数的不同类型的对象之间没有区别，除了函数。JavaScript 中的所有非函数对象都会返回简单的`"object"`：

```js
typeof [];         // => "object"
typeof RegExp(''); // => "object"
typeof {};         // => "object"
```

所有函数，无论是通过类定义、方法定义还是普通函数表达式声明的，都将求值为`"function"`：

```js
typeof () => {};          // => "function"
typeof function() {};     // => "function"
typeof class {};          // => "function"
typeof ({ foo(){} }).foo; // => "function"
```

如果`typeof class {}`求值为`"function"`让你感到困惑，那么请考虑我们所学到的，所有类都只是具有准备好的原型的构造函数（这将稍后确定任何生成实例的`[[Prototype]]`）。它们没有什么特别之处。类不是 JavaScript 中的独特类型或实体。

在比较`typeof`的结果与给定字符串时，我们可以使用严格相等(`===`)或抽象相等(`==`)运算符。由于`typeof`始终返回一个字符串，我们不必担心任何差异，所以你可以选择使用严格相等还是抽象相等检查。从技术上讲，这两种方法都可以：

```js
if (typeof 123 == 'number') {...}
if (typeof 123 === 'number') {...}
```

严格相等和抽象相等运算符（双等号和三等号）的行为略有不同，尽管当运算符两侧的值是相同类型时，它们的行为是相同的。请跳转到*运算符*部分，了解它们的区别。一般来说，最好优先使用`===`而不是`==`。

总之，`typeof`运算符只是一个晴天朋友。我们不能在所有情况下依赖它。有时，我们需要使用其他类型检测技术。

# 类型检测技术

考虑到`typeof`运算符对于检测多种类型的不适用性，特别是对象，我们必须依赖于许多不同的方法，具体取决于我们想要检查的确切内容。有时，我们可能想要检测特征而不是类型，例如，一个对象是否是构造函数的实例，或者它只是一个普通对象。在本节中，我们将探讨一些常见的检测需求及其解决方案。

# 检测布尔值

布尔值检测起来非常简单。`typeof`运算符对`true`和`false`的值正确地求值为`"boolean"`：

```js
typeof true;  // => "boolean"
typeof false; // => "boolean"
```

不过，我们很少会想要这样做。通常，当你接收到一个`Boolean`值时，你最感兴趣的是检查它的真实性而不是它的类型。

当将布尔值放置在布尔上下文中时，比如条件语句，我们隐含地依赖于它的真实性或虚假性。例如，看下面的检查：

```js
function process(isEnabled) {
  if (isEnabled) {
    // ... do things
  }
}
```

这个检查并不能确定`isEnabled`值是否真正是布尔值。它只是检查它是否评估为真值。`isEnabled`可能的所有可能值是什么？是否有所有这些真值的列表？这些值几乎是无限的，所以没有列表。我们只能说关于真值的是它们不是假值。而且我们知道，只有七个假值。如果我们希望观察特定值的真假，我们总是可以通过将`Boolean`构造函数作为函数调用来转换为`Boolean`：

```js
Boolean(true); // => true
Boolean(1); // => true
Boolean(42); // => true
Boolean([]); // => true
Boolean('False'); // => true
Boolean(0.0001); // => true
```

在大多数情况下，对`Boolean`的隐式强制转换是足够的，不会对我们造成影响，但是如果我们希望绝对确定一个值既是`Boolean`又是特定的`true`或`false`，我们可以使用严格相等运算符进行比较，如下所示：

```js
if (isEnabled === true) {...}
if (isEnabled === false) {...}
```

由于 JavaScript 的动态特性，一些人更喜欢这种确定性，但通常并不是必要的。如果我们要检查的值显然是一个`Boolean`值，那么我们可以直接使用它。通常情况下，通过`typeof`或严格相等来检查它的类型是不必要的，除非有可能该值不是`Boolean`。

# 检测数字

在`Number`的情况下，我们可以依赖`typeof`运算符正确地评估为`"number"`：

```js
typeof 555; // => "number"
```

然而，在`NaN`、`Infinity`和`-Infinity`的情况下，它也会评估为`"number"`：

```js
typeof Infinity;  // => "number"
typeof -Infinity; // => "number"
typeof NaN;       // => "number"
```

因此，我们可能希望进行额外的检查，以确定一个数字不是这些值中的任何一个。幸运的是，JavaScript 为这种情况提供了本地辅助工具：

+   `isFinite(n)`: 如果`Number(n)`不是`Infinity`、`-Infinity`或`NaN`，则返回`true`

+   `isNaN(n)`: 如果`Number(n)`不是`NaN`，则返回`true`

+   `Number.isNaN(n)`: 如果`n`不是`NaN`，则返回`true`

+   `Number.isFinite(n)`: 如果`n`不是`Infinity`、`-Infinity`或`NaN`，则返回`true`

全局变量的两个变体是语言的较早部分，正如您所看到的，它们与它们的`Number.*`等效部分略有不同。全局的`isFinite`和`isNaN`通过`Number(n)`将它们的值转换为数字，而等效的`Number.*`方法则不这样做。这种差异的原因主要是遗留问题。

最近添加的`Number.isNaN`和`Number.isFinite`是为了实现更明确的检查而引入的，而不依赖于转换：

```js
isNaN(NaN)   // => true
isNaN('foo') // => true

Number.isNaN(NaN);   // => true
Number.isNaN('foo'); // => false
```

如您所见，`Number.isNaN`更为严格，因为它在检查`NaN`之前不会将值转换为`Number`。对于字符串`'foo'`，我们需要将其转换为`Number`（因此评估为`NaN`）才能通过：

```js
const string = 'foo';
const nan = Number(string);
Number.isNaN(nan); // => true
```

全局的`isFinite`函数的工作方式也是一样的，即在检查有限性之前将其值转换为数字，而`Number.isFinite`方法则不进行任何转换：

```js
isFinite(42)   // => true
isFinite('42') // => true

Number.isFinite(42);   // => true
Number.isFinite('42'); // => false
```

如果您确信您的值已经是一个数字，那么您可以使用更简洁的`isNaN`和`isFinite`，因为它们的隐式转换对您没有影响。如果您希望 JavaScript 尝试将您的非`Number`值转换为`Number`，那么您应该再次使用`isNaN`和`isFinite`。然而，如果出于某种原因您需要明确检查，那么您应该使用`Number.isNaN`和`Number.isFinite`。

结合所有这些讨论过的检查，我们能够通过使用`typeof`结合全局的`isFinite`来自信地检测一个既不是`NaN`也不是`Infinity`的数字。正如我们之前提到的，`isFinite`将检查`NaN`本身，所以我们不需要额外的`isNaN`检查：

```js
function isNormalNumber(n) {
  return typeof n === 'number' && isFinite(n);
}
```

在检测方面，你的需求应该由你的代码上下文驱动。例如，如果你嵌入在一个可以安全假定数字是有限的代码片段中，那么可能不需要检查有限数字。但如果你正在构建一个更公共的 API，那么在将这些值发送到你的内部接口之前，你可能希望进行这样的检查，以减少错误的可能性，并为你的用户提供有用和明智的错误或警告。

# 检测字符串

检测字符串是愉快的简单。我们只需要`typeof`运算符：

```js
typeof 'hello'; // => "string"
```

为了检查给定`String`的长度，我们可以简单地使用`length`属性：

```js
'hello'.length; // => 5
```

如果我们需要检查一个`String`的长度是否大于 0，我们可以通过`length`显式地这样做，或者依赖于长度为 0 的假值，甚至依赖于空`string`本身的假值：

```js
const string = '';

Boolean(string);            // => false
Boolean(string.length);     // => false
Boolean(string.length > 0); // => false

// Since an empty String is falsy we can just check `string` directly:
if (string) { }

// Or we can be more explicit:
if (string.length) { }

// Or we can be maximally explicit:
if (string.length > 0) { }
```

如果我们只是检查一个值的真实性，那么我们也可能检测到所有潜在的真值，包括非零数字和对象。要完全确定你有一个`String`并且它不是空的，最简洁的技术如下：

```js
if (typeof myString === 'string' && myString) {
  // ...
}
```

然而，仅仅空白可能并不是我们感兴趣的全部。我们可能希望检测一个字符串是否包含实际内容。在大多数情况下，*实际内容*从`String`的开头开始，直到`String`的结尾结束，但在某些情况下，它可能嵌入在两侧的空白中。为了解决这个问题，我们可以修剪`String`，然后确认它是否为空：

```js
function isNonEmptyString(string) {
  return typeof string === 'string' && string.trim().length > 0;
}

isNonEmptyString('hi');  // => true
isNonEmptyString('');    // => false
isNonEmptyString(' ');   // => false
isNonEmptyString(' \n'); // => false
```

请注意，我们的函数`isNonEmptyString`是在修剪后的字符串上使用`length > 0`检查，而不仅仅依赖于它作为空字符串的假值。这样我们就可以安全而自信地知道我们的`isNonEmptyString`函数将始终返回一个布尔值。即使在 99%的情况下，它将被用在布尔上下文中，比如`if (isNonEmptyString(...))`，我们仍然应该确保我们的函数具有直观和一致的约定。

逻辑`AND`运算符（`a && b`）将在其左侧为真时返回其右侧。因此，诸如`typeof str === "string" && str`的表达式并不总是保证返回一个布尔值。有关更多信息，请参阅第八章的*运算符-逻辑运算符-逻辑 AND 运算符*部分。

检测字符串是简单的，但正如我们在上一章中提到的，由于 Unicode，与它们一起工作可能是一个挑战。因此，要记住，虽然检测字符串可能会给我们一些确定性，但它并不告诉我们字符串内部的内容以及它是否是我们期望的值。如果你的检测意图是为那些使用你的接口的人提供指南或警告，你可能最好通过明确检查值的内容来服务。

# 检测 undefined

`undefined`类型可以通过引用其全局可用值直接使用严格相等运算符进行检查：

```js
if (value === undefined) {
  // ...
}
```

然而，不幸的是，由于`undefined`可以在非全局范围内被覆盖（取决于你的精确设置和环境），这种方法可能会有问题。从历史上看，`undefined`可以在全局范围内被覆盖。这意味着这样的事情是可能的：

```js
let value = void 0;  // <- actually undefined
let undefined = 123; // <- cheeky override

if (value === undefined) {
  // Does not occur
}
```

`void`运算符，正如我们将在后面探讨的那样，将一个操作数取到其右侧（`void foo`），并且将始终计算为`undefined`。因此，`void 0`已经成为`undefined`的同义词，并且作为替代是有用的。因此，如果你对`undefined`值没有信心，那么你可以简单地检查`void 0`，就像这样：

```js
if (value === void 0) {
  // value is undefined
}
```

出现了各种其他方法来确保可靠的`undefined`值。例如，一个方法是简单地声明一个未赋值的变量（它将始终默认为`undefined`），然后在范围内使用它：

```js
function myModule() {
  // My local `undefined`:
  const undef;

  void 0 === undef; // => true

  if (someValue === undef) {
    // Instead of `VALUE === undefined` I can
    // use `VALUE === undef` within this scope
  }
}
```

随着时间的推移，`undefined`值的可变性已经被锁定。*ECMAScript 2015*禁止了全局修改，但奇怪的是仍然允许本地修改。

值得庆幸的是，始终可以通过简单的`typeof`运算符来检查`undefined`：

```js
typeof undefined; // => "undefined"
```

使用`typeof`这种方式比依赖`undefined`作为字面值要少风险得多，尽管随着 linting 工具的出现，直接检查`undefined`通常是安全的。

我们将在第十五章中探讨 ESLint，这是一个流行的 JavaScript linting 工具，*更干净代码的工具*。在本地范围覆盖`undefined`的情况下，这绝对是一件坏事，它会友好地给我们一个警告。这样的警告可以让我们更有信心，可以安全地使用语言中以前风险较高的方面。

# 检测 null

正如我们所见，`typeof null`评估为`"object"`。这是语言的一个奇怪的遗留。不幸的是，这意味着我们不能依赖`typeof`来检测`null`。相反，我们必须直接比较字面值`null`，使用严格的相等运算符，如下所示：

```js
if (someValue === null) {
  // someValue is null...
}
```

与`undefined`不同，`null`在语言的任何版本和任何环境中都不能被覆盖，因此在使用上不会带来任何麻烦。

# 检测 null 或 undefined

到目前为止，我们已经介绍了如何独立检查`undefined`和`null`，但我们可能希望同时检查两者。例如，一个函数签名通常有一个可选参数。如果未传递该参数或明确设置为`null`，通常会返回到一些默认值。可以通过明确检查`null`和`undefined`来实现这一点，如下所示：

```js
function printHello(name, message) {
  if (message === null || message === undefined) {
    // Default to a hello message:
    message = 'Hello!';
  }
  console.log(`${name} says: ${message}`);
}
```

通常，由于`null`和`undefined`都是假值，通过检查给定值的假值来暗示它们的存在是非常正常的：

```js
if (!value) {
  // Value is definitely not null and definitely not undefined
}
```

然而，这也将检查值是否为其他假值之一（包括`false`，`NaN`，0 等）。因此，如果我们想确认一个值是否特别是`null`或`undefined`，而不是其他假值，那么我们应该坚持使用明确的变体：

```js
if (value === null || value === undefined) //...
```

更简洁的是，我们可以采用抽象（非严格）相等运算符来检查`null`或`undefined`，因为它认为这些值是相等的：

```js
if (value == null) {
  // value is either null or undefined
}
```

尽管这利用了通常被指责的抽象相等运算符（我们将在本章后面探讨），但这仍然是检查`undefined`和`null`的一种流行方式。这是因为它的简洁性。然而，采用这种更简洁的检查会使代码不太明显。甚至可能给人留下作者只是想检查`null`的印象。这种意图的模糊性应该让我们对其干净度产生怀疑。因此，在大多数情况下，我们应该选择更明确和严格的检查。

# 检测数组

在 JavaScript 中检测数组非常简单，因为有`Array.isArray`方法：

```js
if (Array.isArray(value)) {
 // ...
}
```

这种方法告诉我们，传递的值是通过数组构造函数或数组文字构造的。但它不检查值的`[[Prototype]]`，因此完全有可能（尽管不太可能）该值，尽管看起来像一个数组，但可能没有您所期望的特征。

当我们认为需要检查一个值是否是数组时，重要的是问问自己我们真正想要检测什么。也许我们可以检查我们所期望的特征，而不是类型本身。考虑我们将如何处理这个值是至关重要的。如果我们打算通过`for...of`循环遍历它，那么检查其可迭代性可能更适合我们，而不是检查其数组性。正如我们之前提到的，我们可以使用这样的辅助程序来做到这一点：

```js
function isIterable(obj) {
  return obj != null &&
    typeof obj[Symbol.iterator] === 'function';
}

const foo = [1,2,3];
if (isIterable(foo)) {
  for (let f in foo) {
    console.log(f);
  }
}

// Logs: 1, 2, 3
```

另外，如果我们想使用特定的数组方法，比如`forEach`或`map`，那么最好通过`isArray`进行检查，因为这将给我们一个合理的信心，这些方法存在：

```js
if (Array.isArray(someValue)) {
  // Using Array methods
  someValue.forEach(v => {/*...*/});
  someValue.sort((a, b) => {/*...*/});
}
```

如果我们倾向于非常彻底，我们还可以逐个检查特定方法，或者甚至强制将值转换为我们自己的数组，以便我们可以自由地对其进行操作，同时知道该值确实是一个数组：

```js
const myArrayCopy = [...myArray];
```

请注意，通过扩展语法（`[...value]`）复制类似数组的值只有在该值可迭代时才有效。使用`[...value]`的一个适当的例子是在操作从 DOM API 返回的`NodeLists`时：

```js
const arrayOfParagraphElements = [...document.querySelectorAll('p')];
```

`NodeList` 不是真正的`Array`，因此它不提供对原生数组方法的访问。因此，创建并使用一个真正的`Array`的副本是有用的。

总的来说，采用和依赖`Array.isArray`是安全的，但重要的是要考虑是否需要检查`Array`，是否更适合检查值是否可迭代，甚至是否具有特定的方法或属性。与所有其他检查一样，我们应该努力使我们的意图明显。如果我们使用的检查比`Array.isArray`更隐晦，那么最好添加注释或使用一个描述性命名的函数来抽象操作。

# 检测实例

要检测一个对象是否是构造函数的实例，我们可以简单地使用`instanceof`运算符：

```js
const component = new Component();
component instanceof Component; 
```

`instanceof` 运算符将在第八章*，运算符*中更详细地介绍。

# 检测普通对象

当我们说“普通”对象时，我们通常指的是通过`Object`字面量或通过`Object`构造函数构造的对象：

```js
const plainObject = {
  name: 'Pikachu',
  species: 'Pokémon'
};

const anotherPlainObject = new Object();
anotherPlainObject.name = 'Pikachu';
anotherPlainObject.species = 'Pokémon';
```

这与其他对象形成对比，比如语言本身提供的对象（例如数组）和我们通过实例化构造函数自己构造的对象（例如`new Pokemon()`）：

```js
function Pokemon() {}
new Pokemon(); // => A non-plain object
```

检测普通对象的最简单方法是询问它的`[[Prototype]]`。如果它的`[[Prototype]]`等于`Object.prototype`，那么我们可以说它是普通的：

```js
function isPlainObject(object) {
  return Object.getPrototypeOf(object) === Object.prototype;
}

isPlainObject([]);            // => false
isPlainObject(123);           // => false
isPlainObject(new String);    // => false
isPlainObject(new Pokemon()); // => false

isPlainObject(new Object());  // => true
isPlainObject({});            // => true
```

我们为什么需要知道一个值是否是一个普通对象？例如，当创建一个接受配置对象以及更复杂的对象类型的接口或函数时，区分普通对象和非普通对象可能是有用的。

在大多数情况下，我们需要明确检测普通对象。相反，我们应该只依赖它提供给我们的接口或数据。如果我们的抽象的用户希望向我们传递一个非普通对象，但它仍然具有我们需要的属性，那么我们又有什么好抱怨的呢？

# 转换、强制转换和类型转换

到目前为止，我们已经学会了如何使用检测来区分 JavaScript 中的各种类型和特征。正如我们所见，当需要在出现意外或不兼容的值时提供替代值或警告时，检测是有用的。然而，处理这些值的另一个机制是：我们可以将它们从我们不希望的值转换为我们希望的值。

为了转换一个值，我们使用一种称为**类型转换**的机制。类型转换是有意和明确地从一种类型派生另一种类型。与类型转换相反，还有**强制转换**。强制转换是 JavaScript 在使用需要特定类型的运算符或语言结构时隐式和内部进行的转换过程。一个例子是将`String`值传递给乘法运算符。运算符将自然地将其`String`操作数强制转换为数字，以便它可以尝试将它们相乘：

```js
'5' * '2'; // => 10 (Number)
```

*强制转换*和*隐式转换*的基本机制是相同的。它们都是转换的机制。但是我们如何访问这些底层行为是关键的。如果我们明确地这样做，清晰地传达我们的意图，那么我们的代码读者将会有更好的体验。

考虑以下代码，其中包含将`String`转换为`Number`的两种不同机制：

```js
Number('123'); // => 123
+'123'; // => 123
```

在这里，我们使用了两种不同的技术来强制将值从`String`转换为`Number`。当作为函数调用时，`Number()`构造函数将内部将传递的值转换为`Number`原始值。一元`+`运算符也会做同样的事情，尽管它可能不够清晰。强制转换甚至不够清晰，因为它经常似乎是作为某些其他操作的副作用而发生的。以下是一些此类的例子：

```js
1 + '123'; // => "1234"
[2] * [3]; // => 6
'22' / 2;  // => 11
```

当操作数中的一个是字符串时，`+`运算符将强制转换另一个操作数为字符串，然后将它们连接在一起。当给定数组时，`*`运算符将在它们上调用`toString()`，然后将结果的`String`强制转换为`Number`，这意味着`[2] * [3]`等于`2 * 3`。此外，除法运算符在对它们进行操作之前会将它们强制转换为数字。所有这些强制行为都是隐式发生的。

*强制转换*和*显式转换*之间的界限并不是一成不变的。例如，可以通过强制性的副作用明确和有意地转换类型。考虑表达式`someString * 1`，它可以用来将字符串*强制转换*为数字，使用强制转换来实现。在我们的转换中，至关重要的是我们**清楚地传达我们的意图**。

由于强制转换是隐式发生的，它可能是许多错误和意外行为的原因。为了避免这种陷阱，我们应该始终对操作数的类型有很强的信心。然而，强制转换是完全有意的，可以帮助创建更可靠的代码库。在接口的更公共或暴露的一侧，通常会预先将类型转换为所需的类型，以防接收到的类型不正确。

在这里观察一下，我们如何明确地将`haystack`和`needle`的值都转换为`String`类型：

```js
function countOccurrences(haystack, needle) {

  haystack = String(haystack);
  needle = String(needle);

  let count = 0;

  for (let i = 0; i < haystack.length; count++, i += needle.length) {
    i = haystack.indexOf(needle, i);
    if (i === -1) break;
  }

  return count;
}

countOccurrences('What apple is the best type of apple?', 'apple'); // => 2
countOccurrences('ABC ABC ABC', 'A'); // => 3
```

由于我们依赖于`haystack`字符串上的`indexOf()`方法，根据我们所期望的防御级别，将`haystack`转换为字符串是有意义的，这样我们就可以确保它具有可用的方法。将`needle`转换为字符串也会编码更高级别的确定性，这样我们和其他程序员就可以感到放心。

当我们正在创建可重用的实用程序、面向公众的 API 或以降低对接收到的类型的信心的方式消耗的任何接口时，预先将值转换为布尔值以防止不良类型的防御性方法是最佳的。

像 JavaScript 这样的动态类型语言被许多人视为混乱的邀请。这些人可能习惯于严格类型的语言提供的舒适和确定性。事实上，如果充分并谨慎地使用，动态语言可以使我们的代码更加深思熟虑，并且更能适应用户不断变化的需求。在本节的其余部分，我们将讨论转换为各种类型，包括我们可以利用的显式转换机制以及语言内部采用的各种强制行为。我们将首先看一下布尔转换。

# 转换为布尔值

JavaScript 中的所有值在转换为布尔值时，除非它们是七个假值原始值（`false`、`null`、`undefined`、`0n`、`0`、`""`和`NaN`），否则都将返回`true`。

要将值转换为布尔值，我们可以简单地将该值传递给布尔构造函数，将其作为函数调用：

```js
Boolean(0); // => false
Boolean(1); // => true
```

当值存在于布尔上下文中时，语言会将值强制转换为布尔值。以下是一些此类上下文的示例（每个都标有`HERE`）：

+   `if ( HERE ) {...}`

+   `do {...} while (HERE)`

+   `while (HERE) {...}`

+   `for (...; HERE; ...) {...}`

+   `[...].filter(function() { return HERE })`

+   `[...].some(function() { return HERE })`

这个列表并不详尽。我们的值将被强制转换为布尔值的情况还有很多。通常很容易判断。如果一个语言结构或本地提供的函数或方法允许您指定两种可能的路径（也就是*如果 X 那么做这个，否则做那个*），那么它将在内部强制转换您表达的任何值为布尔值。

将值转换为布尔值的常见习语，除了更明确地调用`Boolean()`之外，还有*双感叹号*，即一元逻辑`NOT`运算符（`!`）重复两次：

```js
!!1;  // => true
!![]; // => true
!!0;  // => false
!!""; // => false
```

两次重复逻辑`NOT`运算符将两次反转值的布尔表示。通过将其括起来，更容易理解*双感叹号*的语义：

```js
!( !( value ) )
```

这实际上做了四件事：

+   将值转换为布尔值（`Boolean(value)`）。

+   如果值为`true`，则将其变为`false`。如果值为`false`，则返回`true`。

+   将结果值转换为布尔值（`Boolean(value)`）。

+   如果值为`true`，则将其变为`false`。如果值为`false`，则返回`true`。

换句话说：这做了一个逻辑非，然后又做了一个，结果是原始值本身的布尔表示。

当您创建一个必须返回布尔值的函数或方法，但处理的值不是布尔值时，显式地将值转换为布尔值是特别有用的。例如，我可能希望创建一个`isNamePopulated`函数，如果名称变量不是一个填充的字符串或是`null`或`undefined`，则返回`false`：

```js
function isNamePopulated(name) {
  return !!name;
}
```

如果`name`是一个空的`String`、`null`或`undefined`，这将有助于返回`false`：

```js
isNamePopulated('');        // => false
isNamePopulated(null);      // => false
isNamePopulated(undefined); // => false

isNamePopulated('Sandra');  // => true
```

如果`name`是任何其他假值（例如 0），它也会偶然返回`false`，如果`name`是任何真值，它会返回`true`：

```js
isNamePopulated(0); // => false
isNamePopulated(1); // => true
```

这可能看起来完全不可取，但在这种情况下，这可能是可以接受的，因为我们已经假设`name`是一个`String`、`null`或`undefined`，所以我们只关心函数在这些值方面是否履行了它的合同。您对此的舒适程度完全取决于您具体的实现和它提供的接口。

# 转换为字符串

通过调用`String`构造函数作为常规函数（即不作为构造函数）来实现将值转换为`String`：

```js
String(456); // => "456"
String(true); // => "true"
String(null); // => "null"
String(NaN); // => NaN
String([1, 2, 3]); // => "1,2,3"
String({ foo: 1 }); // => "[object Object]"
String(function(){ return 'wow' }); // => "function(){ return 'wow' }"
```

使用您的值调用`String()`是将值转换为`String`的最明确和清晰的方法，尽管有时会使用更简洁的模式：

```js
'' + 1234; // => "1234"
`${1234}`; // => "1234"
```

这两个表达式可能看起来是等价的，对于许多值来说确实如此。但是，在内部，它们的工作方式是不同的。正如我们将在后面看到的，`+`运算符将通过调用其内部的`ToPrimitive`机制来区分给定操作数是否为`String`，这样操作数的`valueOf`（如果有）将在其`toString`实现之前被查询。然而，当使用模板文字（例如``${value}``）时，任何插入的值都将直接转换为字符串（而不经过`ToPrimitive`）。值的`valueOf`和`toString`方法提供不同的值的可能性总是存在的。看看下面的例子，它展示了如何通过定义我们自己的`toString`和`valueOf`实现来操纵两个看似等价表达式的返回值：

```js
const myFavoriteNumber = {
  name: 'Forty Two',
  number: 42,
  valueOf() { return number; },
  toString() { return name; }
};

`${myFavoriteNumber}`; // => "Forty Two"
'' + myFavoriteNumber; // => 42
```

这可能是一个罕见的情况，但仍然值得考虑。通常，我们假设我们可以轻松地将*任何*值可靠地转换为字符串，但情况并非总是如此。

传统上，很常见依赖于值的`toString()`方法并直接调用它：

```js
(123).toString(); // => 123
```

但是，如果值为`null`或`undefined`，那么您将收到一个`TypeError`：

```js
null.toString();      // ! TypeError: Cannot read property 'toString' of null
undefined.toString(); // ! TypeError: Cannot read property 'toString' of undefined
```

此外，`toString`方法不能保证返回`string`。请注意，我们可以实现自己的`toString`方法，返回`Array`：

```js
({
  toString() { return ['not', 'a', 'string'] }
}).toString(); // => ["not", "a", "string"]
```

因此，最好总是通过非常明确和清晰的`String(...)`进行`string`转换。使用间接的强制形式、副作用或盲目依赖`toString`可能会产生意想不到的结果。请记住，即使您对这些机制有很好的了解并且感到舒适使用它们，也不意味着其他程序员会这样做。

# 转换为数字

通过调用`Number`构造函数作为常规函数，可以将值转换为`Number`：

```js
Number('10e3');     // => 10000
Number(' 4.6');     // => 4.6
Number('Infinity'); // => Infinity
Number('wat');      // => NaN
Number(false);      // => 0
Number('');         // => 0
```

此外，还有一元加号`+`运算符，它基本上做了相同的事情：

```js
+'Infinity'; // => Infinity
+'55.66';    // => 55.66
+'foo';      // => NaN
```

这是将非`Number`转换为`Number`类型的唯一两种方法，但 JavaScript 还提供了其他从字符串中提取数值的技术。其中一种技术是`parseInt`，它是一个全局可用的原生函数，接受一个`String`和一个可选的`radix`参数（默认为*base 10*，即十进制）。如果第一个参数不是`String`，它将自然地将其转换为`String`，然后尝试从`String`中提取指定`radix`的第一个整数。通过这样做，您可以实现以下结果：

```js
parseInt('1000');   // => 1000
parseInt('100', 8); // => 64 (i.e. octal to decimal)
parseInt('AA', 12); // => 130 (i.e. hexadecimal to decimal)
```

如果字符串以`0x`或`0X`为前缀，则`parseInt`将假定`radix`为`16`（*十六进制*）：

```js
parseInt('0x10'); // => 16
```

一些浏览器和其他环境也可能将`0`的前缀视为八进制`radix`的指示符。

```js
// (In **some** environments)
parseInt('023'); // => 19 (assumed octal -> decimal)
```

`parseInt()`还将有效地修剪`String`，忽略任何初始空格，并忽略`String`中第一个找到的整数之后的所有内容：

```js
parseInt(' 111 222 333'); // => 111
parseInt('\t\n0xFF');     // => 255
```

`parseInt`通常不受欢迎，因为它从`String`中提取整数的机制是晦涩的，并且如果没有提供`radix`，它可能会动态选择自己的`radix`。如果必须使用`parseInt`，请谨慎使用，并充分了解其操作方式。并始终提供`radix`参数。

与`parseInt`类似，还有一个原生的`parseFloat`函数，它将尝试从给定的`String`中提取*float*（即*浮点数*）：

```js
parseFloat('42.01');  // => 42.01
parseFloat('\n1e-3'); // => 0.001
```

`parseFloat`将修剪字符串，然后查找从*0^(th)*字符开始的可以被语言自然解析的最长字符集，就像可以解析数字文字一样。因此，它可以很好地处理包含可解析数字序列之外的非数字字符的字符串：

```js
parseFloat('   123 ... rubbish here...'); // => 123
```

如果我们将这样的字符串传递给`Number(...)`，将导致`NaN`被评估。因此，在一些罕见的情况下，`parseFloat`可能对您更有用。

`parseFloat`和`parseInt`都会在尝试提取之前将其初始参数转换为`String`。因此，如果您的第一个参数是对象，则应该注意它可能如何自然地强制转换为字符串。如果您的对象实现了不同的`toString`和`valueOf`方法，则应该期望`parseInt`和`parseFloat`只使用`toString`（除非还实现了`[Symbol.toPrimitive]()`）。这与`Number(...)`相反，后者将尝试直接将其参数转换为`Number`（而不是首先将其转换为`String`），因此将优先考虑`valueOf`而不是`toString`：

```js
const rareSituation = {
  valueOf() { return "111"; },
  toString() { return "999"; }
};

Number(rareSituation); // => 111
parseFloat(rareSituation); // => 999
parseFloat(rareSituation); // => 999
```

在大多数情况下，将任何值转换为`Number`应该通过`Number`或一元加号`+`运算符尝试。只有在需要使用它们的数值提取算法时，才应该使用`parseFloat`或`parseInt`。

# 转换为原始类型

将值转换为其原始表示形式并不是我们可以直接做的事情，但是在许多不同的情况下，语言会隐式地（即*强制性地）进行转换，比如当您尝试使用抽象相等运算符`==`来比较`String`，`Number`或`Symbol`与`Object`的值时。在这种情况下，`Object`将通过一个名为`ToPrimitive`的内部过程转换为其原始表示形式，该过程总结如下：

1.  如果`object[Symbol.toPrimitive]`存在，并且在调用时返回一个原始值，则使用它

1.  如果`object.valueOf`存在，并且返回一个原始值（非`Object`），则使用它的返回值

1.  如果`object.toString`存在，则使用它的返回值

如果我们尝试使用`==`进行比较，我们可以看到`ToPrimitive`的作用：

```js
function toPrimitive() { return 1; }
function valueOf() { return 2; }
function toString() { return 3; }

const one = { [Symbol.toPrimitive]: toPrimitive, valueOf, toString };
const two = { valueOf, toString };
const three = { toString };

1 == one; // => true
2 == two; // => true
3 == three; // => true
```

如您所见，如果一个对象有所有三种方法（`[Symbol.toPrimitive]`，`valueOf`和`toString`），那么将使用`[Symbol.toPrimitive]`。如果只有`valueOf`和`toString`，那么将使用`valueOf`。当然，如果只有`toString`，那么将使用它。

如果使用`String`的提示调用`ToPrimitive`（这意味着它已被指示尝试强制转换为`String`而不是任何原始类型），则该过程中的`*2*`和`*3*`可能会交换。这种情况的一个例子是当您使用计算成员访问运算符（`object[something]`）时，如果`something`是一个对象，则它将通过`ToPrimitive`使用`String`的提示转换为`String`，这意味着在`valueOf()`之前将尝试`toString()`。我们可以在这里看到这一点：

```js
const object = { foo: 123 };
const something = {
  valueOf() { return 'baz'; },
  toString() { return 'foo'; }
};

object[something]; // => 123
```

我们在`something`上定义了`toString`和`valueOf`，但只使用`toString`来确定在`object`上访问哪个属性。

如果我们没有定义自己的方法，比如`valueOf`和`toString`，那么将使用我们使用的任何对象的`[[Prototype]]`上可用的默认方法。例如，数组的原始表示形式是由`Array.prototype.toString`定义的，它将简单地使用逗号作为分隔符将其元素连接在一起：

```js
[1, 2, 3].toString(); // => "1,2,3"
```

所有类型都有自己本地提供的`valueOf`和`toString`方法，因此，如果我们希望强制`ToPrimitive`内部过程使用我们自己的方法，那么我们将需要通过直接提供我们的对象的方法或从`[[Prototype]]`继承来覆盖本地方法。例如，如果您希望提供一个具有自己的原始转换行为的自定义数组抽象，那么您可以通过扩展`Array`构造函数来实现：

```js
class CustomArray extends Array {
  toString() {
    return this.join('|');
  }
}
```

然后，您可以依赖于`CustomArray`实例以其自己独特的方式被`ToPrimitive`过程处理：

```js
String(new CustomArray(1, 2, 3));    // => 1|2|3
new CustomArray(1, 2, 3) == '1|2|3'; // => true
```

所有运算符和本地语言结构的强制行为都会有所不同。每当您将一个值传递给期望原始类型（通常是字符串或数字）的语言结构或运算符时，它可能会通过`ToPrimitive`。因此，了解这个内部过程是很有用的。当我们开始详细探索 JavaScript 的所有运算符时，我们也会参考这一部分。

# 总结

在本章中，我们继续探索 JavaScript 的内部机制，涵盖了语言的动态特性。我们已经看到了如何检测各种类型以及强制和转换的微妙复杂性。这些主题很难掌握，但它们将是有用的。JavaScript 代码中出现的许多反模式都归结于对语言结构和机制的基本误解，因此对这些主题有深入的了解将极大地帮助我们写出干净的代码。

在下一章中，我们将继续探讨类型，通过探索 JavaScript 的运算符。你可能已经对其中许多内容有很好的了解，但由于 JavaScript 的动态特性，它们的使用有时会产生意想不到的结果。因此，下一章将全力以赴地仔细探索语言的运算符。


# 第八章：运算符

在前一章关于*动态类型*的章节中，我们探讨了类型强制转换和检测等主题；我们还涵盖了几个运算符。在本章中，我们将继续探讨 JavaScript 语言提供的每个运算符。对 JavaScript 运算符的深入理解将使我们在这种有时看起来令人困惑的语言中感到非常有力。遗憾的是，理解 JavaScript 没有捷径，但当您开始探索它的运算符时，您会看到模式出现。例如，许多乘法运算符的工作方式相似，逻辑运算符也是如此。一旦您熟悉了主要运算符，您将开始看到其中有一种优雅的复杂性。

如果你时间紧迫，将这一章视为参考可能会有所帮助。不要觉得你需要详尽地记住每个运算符行为的每个细节。

在本章中，我们将涵盖以下主题：

+   什么是运算符？

+   算术和数值运算符

+   逻辑运算符

+   比较运算符

+   赋值运算符

+   属性访问运算符

+   其他运算符和语法

+   位运算符

现在我们准备好深入研究了，我们需要问自己的第一个问题是：什么是运算符？

# 什么是运算符？

在 JavaScript 中，运算符是一个独立的语法部分，形成一个*表达式*，通常用于从一组输入（称为**操作数**）中推导出某些东西或计算逻辑或数学输出。

在这里，我们可以看到一个包含一个运算符（`+`）和两个操作数（`3`和`5`）的表达式：

```js
3 + 5
```

任何运算符都可以说有四个特征：

+   **它的 arity**：运算符接受多少个操作数

+   **它的功能**：运算符如何处理它的操作数以及它的计算结果

+   **它的优先级**：当与其他运算符组合使用时，运算符将如何分组

+   **它的结合性**：当与相同优先级的运算符相邻时，运算符将如何行为

了解这些基本特征非常重要，因为它将极大地帮助您在 JavaScript 中使用运算符。

# 运算符的 arity

Arity 指的是一个运算符可以接收多少个操作数（或输入）。*操作数*是一个正式术语，用于指代您可以给予或传递给运算符的值。

如果我们考虑大于运算符（`>`），它接收两个操作数：

```js
a > b
```

在这个例子中，`a`是它的第一个操作数（或左侧操作数）。而`b`是它的第二个（或右侧操作数）。由于它接收两个操作数，所以大于运算符被认为是一个二元运算符。在 JavaScript 中，我们有一元、二元和三元运算符：

```js
// Unary operator examples (one operand)
-a
!a

// Binary operator examples (two operands)
a == b
a >= b

// Ternary operator examples (three operands)
a ? b : c
```

在 JavaScript 中只有一个三元运算符，即条件运算符（`a ? b : c`）。由于它是唯一的三元运算符，有时它被简单地称为三元运算符，而不是它的正式名称。

了解给定运算符的 arity 是至关重要的——就像知道要传递给函数多少个参数一样重要。在组合操作时，考虑我们如何传达我们的意图也很重要。由于操作可以连续出现，有时可能不清楚哪个运算符指的是哪个操作数。考虑这个令人困惑的表达式：

```js
foo + + baz - - bar
```

为了避免对这样的操作产生困惑，通常将一元运算符靠近它们的操作数，并且甚至使用括号来使意图绝对清晰：

```js
foo + (+baz) - (-bar)
```

与代码的所有部分一样，运算符必须小心使用，并关心将来将不得不遇到、理解和维护代码的个人或个人（包括您未来的自己）。

# 运算符功能

运算符的功能就是它做什么以及它的计算结果。我们将逐个讨论每个运算符，因此在这里除了一些基本的假设之外，没有太多要说的。

在 JavaScript 中，每个运算符都是独立的实体，不与其操作的操作数类型绑定。这与其他一些语言相反，在其他语言中，运算符被映射到可重写的函数，或者以某种方式附加到操作数本身。在 JavaScript 中，运算符是它们自己的语法实体，并具有不可重写的功能。但是，在某些情况下，它们的功能是可扩展的。

在使用以下类型的运算符时，语言将在内部尝试强制转换：

+   算术运算符（即`+`、`*`、`/`、`-`等）

+   递增运算符（即`++`和`--`）

+   位运算符（即`~`、`<<`、`|`等）

+   计算成员访问运算符（即`...[...]`）

+   非严格比较运算符（即`>`、`<`、`>=`、`<=`和`==`）

为了明确地覆盖这些强制转换机制，您可以为您打算用作操作数的任何对象提供`valueOf()`、`toString()`或`[Symbol.toPrimitive]()`方法：

```js
const a = { valueOf() { return 3; } };
const b = { valueOf() { return 5; } };

a + b; // => 8
a * b; // => 15
```

正如我们在上一章的*转换为原始值*部分中所介绍的，这些方法将根据使用的确切运算符或语言构造以特定顺序调用。例如，在所有算术运算符的情况下，`valueOf`将在`toString`之前尝试。

# 运算符优先级和结合性

在组合使用多个运算符时，操作的顺序由两种机制定义：*优先级*和*结合性*。运算符的优先级是从`1`到`20`的数字，并定义了一系列运算符的运行顺序。一些运算符共享相同的优先级。结合性定义了具有相同优先级的运算符将被操作的顺序（从左到右或从右到左）。

考虑以下操作：

```js
1 + 2 * 3 / 4 - 5;
```

在 JavaScript 中，这些特定的数学运算符具有以下优先级：

+   加法运算符（`+`）的优先级为`13`

+   乘法运算符（`*`）的优先级为`14`

+   除法运算符（`/`）的优先级为`14`

+   减法运算符（`-`）的优先级为`13`

它们都具有*从左到右*的结合性。由于优先级更高的运算符首先出现，并且具有相同优先级的运算符将根据它们的结合性出现，我们可以说我们的示例操作按以下顺序进行：

1.  乘法（具有优先级`14`中最左边的）

1.  除法（具有优先级`14`中最左边的）

1.  加法（具有优先级`13`中最左边的）

1.  减法（具有优先级`13`中下一个最左边的）

如果我们要使用括号明确地对我们的操作进行分组，那么它看起来会像这样：

```js
(
  1 +
  (
    (2 * 3)
    / 4
  )
) - 5;
```

每个运算符，甚至非数学运算符，都有特定的优先级和结合性。例如，`typeof`运算符的优先级为`16`。如果您将它与优先级较低的运算符结合使用，这可能会引起头痛：

```js
typeof 1 + 2; // => "number2"
```

由于`+`运算符的优先级低于`typeof`，JavaScript 将在内部按以下方式运行此操作：

```js
(typeof 1) + 2;
```

因此，结果是`typeof 1`（即`"number"`）与`2`连接（产生`"number2"`）。为了避免这种情况，我们必须使用自己的括号来强制顺序：

```js
typeof (1 + 2); // => "number"
```

顺便说一句，这就是为什么您经常会看到带括号的`typeof`（`typeof(...)`），这样看起来就像是在调用函数。然而，它实际上是一个运算符，括号只是为了强制特定的操作顺序。

你可以通过阅读 ECMAScript 规范或在网上搜索“JavaScript 运算符优先级”来发现每个运算符的确切优先级。请注意，用于指示优先级的数字在 1 和 20 之间，并不是来自 ECMAScript 规范本身，而只是一种理解优先级的有用方式。

知道每个运算符的优先级和结合性并不是我们应该期望我们的同事知道的事情。假设他们知道一些基本数学运算符的优先级可能是合理的，但不应该认为他们知道更多。因此，通常需要通过使用括号来提供清晰度，即使在可能不严格需要的情况下。这在复杂的操作中尤为重要，其中有大量连续的运算符，就像这个例子中一样：

```js
function calculateRenderedWidth(width, horizontalPadding, scale) {
  return (width + (2 * horizontalPadding)) * scale;
}
```

在这里，包裹`(2 * horizontalPadding)`的括号在技术上是不必要的，因为乘法运算符自然比加法运算符具有更高的优先级。然而，提供额外的清晰度是有用的。阅读这段代码的程序员会感激地花费更少的认知能量来辨别操作的确切顺序。然而，像许多本意良好的事情一样，这可能会走得太远。不应该包括既不提供清晰度也不强制不同操作顺序的括号。这种多余的例子可能是在额外的括号中包裹整个`return`表达式：

```js
function calculateRenderedWidth(width, horizontalPadding, scale) {
  return ((width + (2 * horizontalPadding)) * scale);
}
```

最好避免这样做，因为如果走得太远，它可能会给代码的读者增加额外的认知负担。对于这种情况的一个很好的指导是，如果你倾向于添加额外的括号以提高清晰度，你可能应该将操作拆分成多行：

```js
function calculateRenderedWidth(width, horizontalPadding, scale) {
  const leftAndRightPadding = 2 * horizontalPadding;
  const widthWithPadding = width + leftAndRightPadding;
  const scaledWidth = widthWithPadding * scale;
  return scaledWidth;
}
```

这些额外的行不仅提供了关于操作顺序的清晰度，还通过有用地将每个操作分配给一个描述性变量，提供了每个单独操作的目的。

知道每个运算符的优先级和结合性并不一定是至关重要的，但知道这些机制如何支持每个操作是非常有用的。大多数情况下，正如你所看到的，最好将操作分成自包含的行或组，以便清晰，即使我们的运算符的内部优先级或结合性并不要求这样做。最重要的是，我们必须始终考虑我们是否清楚地传达了我们代码的意图给读者。

普通的 JavaScript 程序员不会对 ECMAScript 规范有百科全书式的了解，因此，我们不应该要求这样的知识来理解我们编写的代码。

了解运算符背后的机制为我们探索 JavaScript 中的各个运算符铺平了道路。我们将从探索算术和数字运算符开始。

# 算术和数字运算符

JavaScript 中有八个算术或数字运算符：

+   **加法**：`a + b`

+   **减法**：`a - b`

+   **除法**：`a / b`

+   **乘法**：`a * b`

+   **取余**：`a % b`

+   **指数运算**：`a ** b`

+   **一元加**：`+a`

+   **一元减**：`-a`

算术和数字运算符通常会将它们的操作数强制转换为数字。唯一的例外是`+`加法运算符，如果传递了一个非数字的操作数，它将假定字符串连接的功能而不是加法。

所有这些操作的一个保证的结果是值得事先了解的。`NaN`的输入保证了`NaN`的输出：

```js
1 + NaN; // => NaN
1 / NaN; // => NaN
1 * NaN; // => NaN
-NaN;    // => NaN
+NaN;    // => NaN
// etc.
```

除了这个基本假设之外，每个运算符的行为都略有不同，因此值得逐个讨论。

# 加法运算符

加法运算符是一个双重用途运算符：

+   如果任一操作数是`String`，那么它将连接两个操作数。

+   如果没有操作数是`String`，那么它将把两个操作数都作为数字相加

为了实现它的双重目的，`+`运算符首先需要确定你传递的操作数是否可以被视为字符串。显然，原始的`String`值显然是一个字符串，但对于非原始值，`+`运算符将尝试通过依赖我们在上一章中详细介绍的内部`ToPrimitive`过程将你的操作数转换为它们的原始表示。如果`+`操作数的`ToPrimitive`的输出是一个字符串，那么它将把两个操作数连接为字符串。否则，它将把它们作为数字相加。

`+`运算符既可以进行数字相加，也可以进行连接，这使得它相当复杂，因此我们通过几个例子来帮助我们理解。

# 两个操作数都是数字

**解释**：当两个操作数都是原始数字时，`+`运算符非常简单地将它们相加：

```js
1 + 2; // => 3
```

# 两个操作数都是字符串

**解释**：当两个操作数都是原始字符串时，`+`运算符非常简单地将它们连接在一起：

```js
'a' + 'b'; // => "ab"
```

# 一个操作数是字符串

**解释**：当只有一个操作数是原始字符串时，`+`运算符将强制转换另一个为`String`，然后将两个结果字符串连接在一起：

```js
123 + 'abc'; => "123abc"
'abc' + 123; => "abc123"
```

# 一个操作数是非原始值

**解释**：当任一操作数是非原始时，`+`运算符将把它转换为原始值，然后按照新的原始表示进行操作。这里有一个例子：

```js
[123] + 123; // => "123123"
```

在这种情况下，JavaScript 将通过使用`[123].toString()`的返回值（即`"123"）将`[123]`转换为它的原始值。由于数组的原始表示是它的`String`表示，`+`运算符将操作，就好像我们只是在做`"123" + 123`一样，我们知道结果是`"123123"`。

# 结论-了解你的操作数！

在使用`+`运算符时，特别重要的是要知道你正在处理的操作数是什么。如果不知道，那么你的操作结果可能会出乎意料。`+`运算符可能是最复杂的运算符之一，因为它具有双重目的。大多数运算符都不那么复杂。接下来我们将探讨的减法运算符则幸运地简单得多。

# 减法运算符

减法运算符（`-`）就像它的名字一样。它接受两个操作数，从左操作数中减去右操作数：

```js
555 - 100; // => 455
```

如果任一操作数不是数字，它将被强制转换为数字：

```js
'5' - '3'; // => 2
'5' - 3;   // => 2
5 - '3';   // => 2
```

这也包括非原始类型：

```js
[5] - [3]; // => 2
```

在这里，我们看到两个数组，每个数组都有一个元素，相互相减。这似乎毫无意义，直到我们想起数组的原始表示是其连接元素作为字符串，即分别是`"5"`和`"3"`：

```js
String([5]); // => "5"
String([3]); // => "3"
```

然后，它们将通过等同于以下操作的方式转换为它们的数字表示，即`5`和`3`：

```js
Number("5"); // => 5
Number("3"); // => 3
```

因此，我们得到了直观的操作`5`减去`3`，我们知道结果是`2`。

# 除法运算符

除法运算符，就像减法运算符一样，接受两个它将强制转换为数字的操作数。它将用左操作数除以右操作数：

```js
10 / 2; // => 5
```

这两个操作数正式称为被除数和除数（`被除数/除数`），并且将始终根据浮点数运算进行评估。在 JavaScript 中不存在整数除法，这意味着你的除法结果可能总是包含小数点，并且可能会受到`Number.EPSILON`的误差范围的影响。

当除以零时要小心，因为你可能会得到`NaN`（当零除以零时）或`Infinity`（当非零数除以零时）：

```js
10 / 0;  // => Infinity
10 / -0; // => -Infinity
0 / 0;   // => NaN
```

如果你的除数是`Infinity`，你的除法结果将始终评估为零（`0`或`-0`），除非你的被除数也是`Infinity`，在这种情况下，你将收到`NaN`：

```js
1000 / Infinity; // => 0
-1000 / Infinity; // => -0
Infinity / Infinity; // => NaN
```

在预期除数或被除数为零、`NaN`或`Infinity`的情况下，最好是谨慎处理，并在操作之前或之后明确检查这些值，如下所示：

```js
function safeDivision(a, b) {
  const result = a / b;
  if (!isFinite(result)) {
    throw Error(`Division of ${a} by ${b} is unsafe`);
  }
  return result;
}

safeDivision(1, 0); // ! Throws "Division of 1 by 0 is unsafe"
safeDivision(6, 2); // => 3
```

除法的边缘情况可能看起来吓人，但在日常应用中并不经常遇到。然而，如果我们编写医疗或金融程序，那么仔细考虑我们操作的潜在错误状态就是绝对必要的。

# 乘法运算符

乘法运算符的行为与除法运算符类似，除了它执行乘法的明显事实之外：

```js
5 * 25; // => 125
```

需要注意强制转换的影响以及其中一个操作数是`NaN`或`Infinity`的情况。相当直观地，任何非零有限值乘以`Infinity`将始终导致`Infinity`（带有适当的符号）：

```js
100 * Infinity; // => Infinity
-100 * Infinity; // => -Infinity
```

然而，将零乘以`Infinity`将始终导致`NaN`：

```js
0 * Infinity; // => NaN
-Infinity * -0; // => NaN
```

除了这些情况外，大多数乘法运算符的用法都是相当直观的。

# 余数运算符

余数运算符（`%`），也称为**模运算符**，类似于除法运算符。它接受两个操作数：左侧的被除数和右侧的除数。它将返回隐含除法操作后的余数：

```js
10 % 5; // => 0
10 % 4; // => 2
10 % 3; // => 1
10 % 2; // => 0
```

如果除数为零，被除数为`Infinity`，或者任一操作数为`NaN`，则操作将评估为`NaN`：

```js
Infinity % Infinity; // => NaN
Infinity % 2; // => NaN
NaN % 1; // => NaN
1000 % 0; // => NaN
```

如果除数为`Infinity`，则结果将等于被除数：

```js
1000 % Infinity; // => 1000
0.03 % Infinity; // => 0.03
```

模运算符在希望知道一个数是否可以被另一个数整除的情况下非常有用，比如在希望确定整数的*偶数性*或*奇数性*时：

```js
function isEvenNumber(number) {
  return number % 2 === 0;
}

isEvenNumber(0); // => true
isEvenNumber(1); // => false
isEvenNumber(2); // => true
isEvenNumber(3); // => false
```

与所有其他算术运算符一样，了解操作数的强制转换方式是有用的。大多数情况下，余数运算符的用法很直观，因此除了其强制转换行为和对`NaN`和`Infinity`的处理之外，你应该会发现它的行为是直观的。

# 指数运算符

指数运算符（`**`）接受两个操作数，左侧是基数，右侧是指数。它将评估为基数的指数幂：

```js
10 ** 2; // => 100
10 ** 3; // => 1,000
10 ** 4; // => 10,000
```

它在功能上与使用`Math.pow(a, b)`操作相同，尽管更简洁。与其他算术运算一样，它将内部强制转换其操作数为`Number`类型，并传入任何`NaN`、`Infinity`或零的操作数将导致可能意外的结果，因此你应该尽量避免这种情况。

值得一提的一个奇怪情况是，如果指数为零，那么结果将始终为`1`，无论基数是什么。因此，基数甚至可以是`Infinity`、`NaN`或其他任何值，结果仍然是`1`：

```js
1000 ** 0;     // => 1
0 ** 0;        // => 1
Infinity ** 0; // => 1
NaN ** 0;      // => 1
```

如果操作数中有一个是`NaN`，则所有其他算术运算符的行为将评估为`NaN`，因此这里的`**`的行为是非常独特的。另一个独特的行为是，如果你的第一个操作数本身是一个一元操作，它将抛出`SyntaxError`：

```js
+2 ** 2;
// SyntaxError: Unary operator used immediately
// before exponentiation expression. Parenthesis
// must be used to disambiguate operator precedence
```

这是为了防止程序员的歧义。根据他们之前接触的其他语言（或严格的数学符号），他们可能期望诸如`-2 ** 2`的情况要么是`4`要么是`-4`。因此，在这些情况下，JavaScript 会抛出异常，因此迫使你更加明确地使用`(-2) ** 2`或`-(2 ** 2)`。

除了这些独特的特点外，指数运算符可以被认为与其他二元（双操作数）算术运算符类似。一如既往：要注意你的操作数类型以及它们可能被强制转换的方式！

# 一元加运算符

一元加运算符（`+...`）将其操作数转换为`Number`，就好像它被传递给`Number(...)`一样：

```js
+'42'; // => 42
+({ valueOf() { return 42; } });
```

为此，我们珍爱的内部`ToPrimitive`过程将被使用，如上一章节中讨论的*转换为原始值*部分。其结果将被重新强制转换为`Number`，如果它不已经是`Number`。因此，如果`ToPrimitive`返回`String`，那么该`String`将被转换为`Number`，这意味着非数字字符串将导致`NaN`：

```js
+({ toString() { return 'not a number'; } }); // => NaN
```

自然地，如果`ToPrimitive`中的`String`可以转换为`Number`，那么一元`+`运算符将评估为：

```js
+({ toString() { return '12345'; } }); // => 12345
```

当通过`+`强制转换数组时，更容易观察到这一点：

```js
+['5e3']; // => 5000

// Equivalent to:
Number(String(['5e3'])); // => 5000
```

一元`+`运算符通常用于程序员希望将类似数字的对象转换为`Number`以便随后与其他数字操作一起使用的地方。然而，通常最好明确使用`Number(...)`，因为这样更清楚意图是什么。

一元`+`运算符有时可能会与其他操作混淆。考虑以下情况：

```js
number + +someObject
```

对于不熟悉一元加号或不经常看到它的人来说，这段代码可能看起来像是包含了一个错别字。我们可以潜在地将整个一元操作包装在自己的括号中，以使其更清晰：

```js
number + (+someObject)
```

或者我们可以使用更清晰的`Number(...)`函数：

```js
number + Number(someObject)
```

总之，一元`+`运算符是`Number(...)`的便捷快捷方式。它很有用，尽管在大多数情况下，我们应该更清楚地表达我们的意图。

# 一元减号运算符

一元减号运算符（`-...`）将首先将其操作数转换为`Number`，方式与上一节中详细介绍的一元`+`运算符相同，然后对其取反：

```js
-55;    // => -55
-(-55); // => 55
-'55';  // => -55
```

它的使用非常简单直观，尽管与一元`+`一样，有用的是消除一元运算符与其二元运算符对应物相邻的情况。这些情况可能会令人困惑：

```js
number - -otherNumber
```

在这些情况下，最好用括号明确表达清晰：

```js
number - (-otherNumber)
```

一元减号运算符通常只与文字数字操作数一起直接使用，以指定负值。与所有其他算术运算符一样，我们应确保我们的意图清晰，并且不要用长或令人困惑的表达式使人困惑。

现在我们已经探讨了算术运算符，我们可以开始研究逻辑运算符了。

# 逻辑运算符

逻辑运算符通常用于构建逻辑表达式，其中表达式的结果通知某些动作或不动作。JavaScript 中有三个逻辑运算符：

+   NOT 运算符（`!a`）

+   AND 运算符（`a && b`）

+   OR 运算符（`a || b`）

与大多数其他运算符一样，它们可以接受各种类型并根据需要进行强制转换。AND 和 OR 运算符不同寻常地并不总是评估为`Boolean`值，并且都利用一种称为**短路评估**的机制，只有在满足某些条件时才执行两个操作数。当我们探索每个单独的逻辑运算符时，我们将更多地了解这一点。

# 逻辑 NOT 运算符

NOT 运算符是一元运算符。它只接受一个操作数并将该操作数转换为其布尔表示形式，然后取反，因此真值项目变为`false`，假值项目变为`true`：

```js
!1;    // => false
!true; // => false
!'hi;  // => false

!0;    // => true
!'';   // => true
!true; // => false
```

在内部，NOT 运算符将执行以下操作：

1.  将操作数转换为布尔值（`Boolean(operand)`）

1.  如果结果值为`true`，则返回`false`；否则返回`true`

如上一章节中*转换为布尔值*部分所讨论的，将值转换为其布尔表示形式的典型习语是双重 NOT（即`!!value`），因为这实际上两次颠倒了值的真实性或虚假性，并评估为`Boolean`。更明确且稍微更受欢迎的习语是使用`Boolean(value)`，因为意图比`!!`更清晰。

由于 JavaScript 中只有七个假值，因此 NOT 运算符只能在以下七种情况下评估为`true`：

```js
!false;     // => true
!'';        // => true
!null;      // => true
!undefined; // => true
!NaN;       // => true
!0n;        // => true
!0;         // => true
```

JavaScript 对假值和真值的严格定义是令人放心的。这意味着即使有人构造了一个具有各种原始表示的对象（想象一个具有返回假值的`valueOf()`的对象），所有内部布尔强制转换仍然只会对七个假值返回`false`，而不会返回其他任何值。这意味着我们只需要担心这七个值（*情况可能会更糟……*）。

总的来说，逻辑非运算符的使用非常简单。它是跨编程语言具有清晰语义的众所周知的语法。因此，在*最佳实践*方面并没有太多需要考虑的。至少，最好避免在代码中使用太多双重否定。双重否定是指将已经带有否定意义的变量应用于非运算符，如下所示：

```js
if (!isNotEnabled) {
  // ...
}
```

对于阅读您的代码的人来说，这在认知上是昂贵的，因此容易产生误解。最好使用名称明确的布尔变量名称，以便使用它们的任何逻辑操作都容易理解。在这种情况下，我们只需重新命名变量并反转操作，如下所示：

```js
if (isEnabled) {
  // ...
}
```

逻辑非运算符总的来说，在布尔上下文中最有用，比如`if()`和`while()`，尽管在双非`!!`操作中也有习惯用法。从技术上讲，它是 JavaScript 中唯一保证返回`Boolean`值的运算符，无论其操作数的类型如何。接下来，我们将探讨与运算符。

# 逻辑与运算符

JavaScript 中的逻辑与运算符(`&&`)接受两个操作数。如果其*左侧*操作数为真值，则它将评估并返回*右侧*操作数；否则，它将返回*左侧*操作数：

```js
0 && 1; // => 0
1 && 2; // => 2
```

对许多人来说，它可能是一个令人困惑的运算符，因为他们错误地认为它等同于问题“A 和 B 都是真的吗？”实际上，它更类似于“如果 A 是真的，那么给我 B；否则，我会接受 A”。人们可能会假设 JavaScript 会评估两个操作数，但实际上，如果左侧操作数为真，它只会评估右侧操作数。这被称为**短路评估**。JavaScript 不会将操作的结果值转换为`Boolean`：相反，它只会将该值返回，不变。如果我们要自己实现该操作，它可能看起来像这样：

```js
function and(a, b) {
  if (a) return b;
  return a;
}
```

对于简单的操作，比如使一个`if(...)`语句依赖于两个值都为真，`&&`运算符将以一种完全令人满意和预期的方式行事：

```js
if (true && 1) {
  // Both `true` and `1` are truthy!
}
```

然而，`&&`运算符也可以以更有趣的方式使用，比如当需要返回一个值，但只有在满足某些先决条件时：

```js
function getFavoriteDrink(user) {
  return user && user.favoriteDrink;
}
```

在这里，`&&`运算符被用在一个非布尔上下文中，其结果不会发生强制转换。在这种情况下，如果其左侧操作数为假值（即，如果`user`为假），那么它将返回该值；否则，它将返回右侧操作数（即，`user.favoriteDrink`）：

```js
getFavoriteDrink({ favoriteDrink: 'Coffee' }); // => 'Coffee'
getFavoriteDrink({ favoriteDrink: null }); // => null
getFavoriteDrink(null); // => null
```

`getFavoriteDrink`函数的行为方式符合基本约定，如果`user`对象可用并且该对象上出现了`favoriteDrink`属性，则返回`favoriteDrink`，尽管其实际功能有点混乱：

```js
getFavoriteDrink({ favoriteDrink: 0 }); // => 0
getFavoriteDrink(0); // => 0
getFavoriteDrink(NaN); // => NaN
```

我们的`getFavoriteDrink`函数并不对用户或`favoriteDrink`的特定性质进行任何考虑；它只是盲目地屈从于`&&`运算符，返回其左侧或右侧的操作数。如果我们对操作数的潜在值有信心，那么这种方法可能是可以的。

重要的是要花时间考虑`&&`将如何评估您提供的操作数的可能方式。要考虑的是，它不能保证返回`Boolean`，甚至不能保证评估右侧操作数。

`&&`运算符，由于其短路特性，也可以用于表达控制流。假设我们希望在`isFeatureEnabled`布尔值为真时调用`renderFeature()`。传统上，我们可能会使用`if`语句来实现：

```js
if (isFeatureEnabled) {
  renderFeature();
}
```

但我们也可以使用`&&`：

```js
isFeatureEnabled && renderFeature();
```

这种以及其他不寻常的`&&`用法通常不被赞同，因为它们可能会掩盖程序员的意图，并对代码的读者造成困惑，这些读者可能对 JavaScript 中`&&`的操作方式了解不够透彻。尽管如此，`&&`运算符确实非常强大，应该在适当的情况下使用。你应该自由地使用它，但始终要意识到代码的典型读者可能如何看待这个操作，并始终考虑操作可能产生的潜在值。

# 逻辑或运算符

JavaScript 中的逻辑或运算符（`||`）接受两个操作数。如果其左侧操作数为真值，则它将立即返回该值；否则，它将评估并返回右侧操作数：

```js
0 || 1; // => 1
2 || 0; // => 2
3 || 4; // => 3
```

与`&&`运算符类似，`||`运算符也具有灵活性，它不会将返回值转换为布尔值，并且以短路方式进行评估，这意味着只有在左侧操作数满足条件时才会评估右侧操作数，即在这种情况下，如果右侧操作数为假：

```js
true || thisWillNotExecute();
false || thisWillExecute();
```

传统上，程序员可能会假设逻辑或运算符类似于问题“A 或 B 是否为真？”，但在 JavaScript 中，它更类似于：“如果 A 为假，则给我 B；否则，我会接受 A”。如果我们自己实现这个操作，它可能看起来像这样：

```js
function or(a, b) {
  if (a) return a;
  return b;
}
```

与`&&`一样，这意味着`||`可以灵活使用以提供控制流或有条件地评估特定表达式：

```js
const nameOfUser = user.getName() || user.getSurname() || "Unknown";
```

因此，应该谨慎使用它，考虑代码读者熟悉的内容，以及考虑所有潜在的操作数和操作结果值。

# 比较运算符

比较运算符是一组二元运算符，始终返回从两个操作数之间的比较派生的布尔值：

+   抽象相等（`a == b`）

+   抽象不相等（`a != b`）

+   严格相等（`a === b`）

+   严格不相等（`a !== b`）

+   大于（`a > b`）

+   大于或等于（`a >= b`）

+   小于（`a < b`）

+   小于或等于（`a <= b`）

+   实例（`a instanceof b`）

+   在（`a in b`）

这些运算符每个都有稍微不同的功能和强制行为，因此逐个地了解它们是很有用的。

# 抽象相等和不相等

抽象相等（`==`）和不相等（`!=`）运算符在内部依赖于相同的算法，该算法负责确定两个值是否可以被视为相等。在本节中，我们的示例只会探讨`==`，但请放心，`!=`总是`==`的相反。

在绝大多数情况下，不建议依赖抽象相等，因为它的机制可能会产生意想不到的结果。大多数情况下，你会选择严格相等（即`===`或`!==`）。

当左侧和右侧操作数都是相同类型时，机制非常简单——运算符将检查这两个操作数是否是相同的值：

```js
100 == 100;     // => true
null == null;   // => true
'abc' == 'abc'; // => true
123n == 123n;   // => true
```

当两个操作数都是相同类型时，抽象相等（`==`）与严格相等（`===`）完全相同。

由于 JavaScript 中所有非原始值都是相同类型（`Object`），抽象相等（`==`）如果你尝试比较两个非原始值（两个对象）并且它们不引用完全相同的对象，将始终返回`false`：

```js
[123] == [123]; // => false
/123/ == /123/; // => false
({}) == ({});   // => false
```

然而，当两个操作数的类型不同时，例如当你比较一个`Number`类型和一个`String`类型，或者一个`Object`类型和一个`Boolean`类型时，抽象相等的确切行为将取决于操作数本身。

如果其中一个操作数是`Number`，另一个是`String`，那么`a == b`操作等同于以下操作：

```js
Number(a) === Number(b)
```

以下是一些示例：

```js
123 == '123';  // => true
'123' == 123;  // => true
'1e3' == 1000; // => true
```

请注意，正如上一章中*转换为数字*部分所讨论的，字符串`"1e3"`将被内部转换为数字`1000`。

继续深入研究——如果`==`运算符的操作数之一是`Boolean`，那么该操作再次等同于`Number(a) === Number(b)`：

```js
false == ''; // => true
// Explanation: Number(false) is `0` and Number('') is `0`

true == '1'; // => true
// Explanation: Number(true) is `1` and Number('1') is `1`

true == 'hello'; // => false
// Explanation: Number(true) is `1` and Number('hello') is `NaN`

false == 'hello'; // => false
// Explanation: Number(false) is `0` and Number('hello') is `NaN`
```

最后，如果不满足前面的条件，并且其中一个操作数是`Object`（而不是原始值），那么它将比较该对象的原始表示与另一个操作数。正如上一章中讨论的那样，在*转换为原始值*部分，这将尝试调用`[Symbol.toPrimitive]()`、`valueOf()`，然后是`toString()`方法来建立原始值。我们可以在这里看到它的运作方式：

```js
new Number(1) == 1; // => true
new Number().valueOf(); // => 1
({ valueOf() { return 555; }) == 555; // => true
```

由于它们复杂的强制行为，最好避免使用*抽象相等*和*不相等*运算符。任何阅读到充斥着这些运算符的代码的人都无法对程序的条件和控制流程有很高的信心，因为抽象相等可能会有太多奇怪的边缘情况。

如果您发现自己想要使用抽象相等，例如，当一个操作数是数字，另一个是字符串时，考虑是否使用更严格的检查的组合或明确地转换您的值以获得更清晰和更少出错的结果；例如，不要使用`aNumber == aNumericString`，而是使用`aNumber === Number(aNumericString)`。

# 严格相等和不相等

JavaScript 中的*严格相等*（`===`）和*严格不相等*（`!==`）运算符是清晰代码的重要组成部分。与其抽象相等的表亲不同，它们在处理操作数的方式上提供了确定性和简单性。

`===`运算符只有在其两个操作数完全相同时才会返回`true`：

```js
1 === 1;       // => true
null === null; // => true
'hi' === 'hi'; // => true
```

唯一的例外是当其中一个操作数是`NaN`时，此时它将返回`false`：

```js
NaN === NaN; // => false
```

严格相等不会进行任何内部强制转换，因此即使您有两个可以强制转换为相同数字的原始值，它们仍将被视为不相等：

```js
'123' === 123; // => false
```

对于非原始值，两个操作数必须引用完全相同的对象：

```js
const me = { name: 'James' };
me === me; // => true
me !== me; // => false
```

即使对象具有相同的结构或共享其他特征，如果它不是对同一对象的引用，它将返回`false`。我们可以通过尝试将包装的`Number`实例与值为`3`的数值文字`3`进行比较来说明这一点：

```js
new Number(3) === 3; // => false
```

在这种情况下，抽象相等运算符（`==`）将评估为 true。您可能认为将`new Number(3)`强制转换为`3`更可取，但最好在比较之前明确设置操作数，使它们具有所需的类型。因此，在包含我们希望与`Number`进行比较的数值的`String`的示例中，最好首先通过`Number()`明确转换它：

```js
Number('123') === 123; // => true
```

建议始终使用严格相等而不是抽象相等。它在每次操作的结果中提供了更多的确定性和可靠性，并且可以让您从抽象相等所涉及的多种强制行为中解脱出来。

# 大于和小于

*大于*（`>`）、*小于*（`<`）、*大于或等于*（`>=`）和*小于或等于*（`<=`）运算符都以类似的方式运行。它们遵循类似于抽象相等的算法，尽管值的强制转换方式略有不同。

首先要注意的是，这些运算符的所有操作数都将首先被强制转换为它们的原始表示。接下来，如果它们的原始表示都是字符串，那么它们将被词典顺序比较。如果它们的原始表示不都是字符串，那么它们将被从它们当前的类型转换为数字，然后再进行比较。这意味着即使你的操作数中只有一个是字符串，它们都将被数值比较。

# 词典比较

词典比较发生在两个操作数都是字符串时，并涉及每个字符串的逐个字符比较。广义上，*更大*的字符串是那些在字典中出现在后面的字符串。因此，*banana*在词典排序中将大于*apple*。

正如我们在第六章中发现的那样，*原始和内置类型*，JavaScript 使用 UTF-16 来编码字符串，因此每个代码单元都是一个 16 位整数。UTF-16 代码单元从`65`（`U+0041`）到`122`（`U+007A`）如下：

```js
ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz
```

后面出现的字符由更大的 UTF-16 整数表示。要比较任意两个给定的代码单元，JavaScript 将简单地比较它们的整数值。比如比较`B`和`A`，可能会像这样：

```js
const intA = 'A'.charCodeAt(0); // => 65
const intB = 'B'.charCodeAt(0); // => 66
intB > intA; // => true
```

每个操作数字符串中的每个字符都必须进行比较。为了做到这一点，JavaScript 将逐个代码单元地进行比较。在每个字符串的每个索引处，如果代码单元不同，较大的代码单元将被认为是更大的，因此该字符串将被认为比另一个字符串更大。

```js
"AAA" > "AAB"
"AAB" > "AAC"
```

如果一个操作数等于另一个操作数的前缀，那么它将始终被认为是*小于*，如下所示：

```js
'coff' < 'coffee'; // => true
```

正如你可能已经注意到的那样，小写的英文字母占据了比大写字母更高的 UTF-16 整数。这意味着大写字母被认为比小写字母小，因此在词典排序中会出现在它的前面。

```js
'A' < 'a'; // => true
'Z' < 'z'; // => true
'Adam' < 'adam'; // => true
```

你还会注意到从`91`到`96`的代码单元包括标点符号，`[\]^_``。这也会影响我们的词典比较。

```js
'[' < ']'; // => true
'_' < 'a'; // => true
```

Unicode 往往以一种方式排列，使得任何给定语言的字符在词典排序中自然排序，以便语言字母表中的第一个符号由比后面符号更低的 16 位整数表示。例如，在这里，我们看到泰语中“鸡”的单词（"ไก่"）在词典排序中小于“蛋”的单词（"ไข่"），因为`ก`字符在泰语字母表中出现在`ข`之前。

```js
'ไก่' < 'ไข่'; // => true ("chicken" comes before "egg")
'ก'.charCodeAt(0); // => 3585
'ข'.charCodeAt(0); // => 3586
```

Unicode 的自然顺序可能并不总是产生合理的词典顺序。正如我们在上一章中学到的，复杂的符号可以通过将多个代码单元组合成组合字符对、代理对（创建*代码点*）或甚至是图形簇来表达。这可能会产生各种困难。一个例子是下面的情况，其中给定的符号，即*带抑扬符的拉丁大写字母 A*，可以通过单一的 Unicode 代码点`U+00C2`或通过将大写字母`"A"`（`U+0041`）与*组合字符 ACCEN**T*（`U+0302`）组合来表达。在符号上和语义上，它们是相同的：

```js
'Â'; // => Â
'A\u0302'; // => Â
```

然而，由于`U+00C2`（十进制：`194`）在技术上大于`U+0041`（十进制：`65`），在词典比较中它将被认为是*大于*，即使它们在符号上和语义上是相同的。

```js
'Â' > 'A\u0302'; // => true
```

有成千上万这样的潜在差异需要注意，因此如果你发现自己需要进行词典排序，要注意 JavaScript 的*大于*和*小于*运算符将受到 Unicode 固有排序的限制。

# 数值比较

使用 JavaScript 的大于和小于运算符进行数字比较是相当直观的。如前所述，你的操作数首先会被强制转换为它们的原始表示形式，然后再次被显式地强制转换为数字。对于两个操作数都是数字的情况，结果是完全直观的：

```js
123 < 456; // => true
```

对于`NaN`和`Infinity`，可以做出以下断言：

```js
Infinity > 123; // => true
Infinity >= Infinity; // => true
Infinity > Infinity; // => false

NaN >= NaN; // => false
NaN > 3; // => false
NaN < 3; // => false
```

如果一个操作数具有不是`Number`的原始表示形式，则在比较之前将其强制转换为`Number`。如果你意外地将`Array`作为`>`的操作数传递，那么它首先会将其强制转换为其原始表示形式，对于数组来说，它是用逗号连接的所有单个强制转换元素的`String`，然后尝试将其强制转换为`Number`：

```js
// Therefore this:
[123] < 456;

// Is equivalent to this:
Number(String([123])) < 456
```

由于可能发生的复杂强制转换，最好始终将相同类型的操作数传递给`>`、`<`、`>=`和`<=`。

# instanceof 运算符

JavaScript 中的`instanceof`运算符允许你检测一个对象是否是构造函数的实例：

```js
const component = new Component();
component instanceof Component; 
```

此操作将遍历其左侧操作数的`[[Prototype]]`链，寻找特定的`constructor`函数。然后它将检查这个构造函数是否等于右侧操作数。

由于它会遍历`[[Prototype]]`链，因此它可以安全地处理多重继承：

```js
class Super {}
class Child extends Super {}

new Super() instanceof Super; // => true
new Child() instanceof Child; // => true
new Child() instanceof Super; // => true
```

如果*右侧*操作数不是函数（即不可调用为构造函数），那么将抛出 TypeError：

```js
1 instanceof {}; // => TypeError: Right-hand side of 'instanceof' is not callable
```

`instanceof`运算符有时在区分原生类型方面很有用，比如判断一个对象是否是数组：

```js
[1, 2, 3] instanceof Array; // => true
```

然而，这种用法已经在很大程度上被`Array.isArray()`取代，后者通常更可靠，因为它在`Array`被从另一个原生上下文（例如浏览器中的帧）传递给你的罕见情况下会正确工作。

# in 运算符

如果在对象中找到属性，则`in`运算符将返回`true`：

```js
'foo' in { foo: 123 }; // => true
```

*左侧*操作数将被强制转换为其原始表示形式，如果不是`Symbol`，它将被强制转换为`String`。在这里，我们可以看到`Array`作为左侧操作数将被强制转换为其内容的逗号分隔序列（这是数组被强制转换为原始值的本机和默认方式，感谢`Array.prototype.toString`）：

```js
const object = {
  'Array,coerced,into,String': 123
};

['Array', 'coerced', 'into', 'String'] in object; // => true
```

在 JavaScript 中，所有看似是数字的属性名称都以字符串形式存储，因此访问`someArray[0]`等同于`someArray["0"]`，因此询问对象是否具有数字属性时，`in`也将同样考虑`0`和`"0"`：

```js
'0' in [1]; // => true
0 in { '0': 'foo' }; // => true
```

在确定给定对象中是否存在属性时，`in`运算符将遍历整个`[[Prototype]]`链，因此对链中所有级别的可访问方法和属性都返回`true`：

```js
'map' in [];     // => true
'forEach' in []; // => true
'concat' in [];  // => true
```

这意味着如果你想区分*具有属性*和*具有自身属性*的概念，你应该使用`hasOwnProperty`，这是从`Object.prototype`继承的方法，它只会检查对象本身：

```js
['wow'].hasOwnProperty('map'); // => false
['wow'].hasOwnProperty(0);     // => true
['wow'].hasOwnProperty('0');   // => true
```

总的来说，最好只在你确信不会与你期望使用的属性名称和对象的[[Prototype]]链提供的属性发生冲突时才使用`in`。即使你只是使用普通对象，你仍然需要担心原生原型。如果它以任何方式被修改（例如通过实用程序库），那么你就不能再对你的`in`操作的结果有很高的信任度，因此应该使用`hasOwnProperty`。

在旧的库代码中，甚至可能会发现选择不依赖于被查询对象的`hasOwnProperty`的代码，因为害怕它可能已被覆盖。相反，它将选择直接使用`Object.prototype.hasOwnProperty`方法，并以该对象作为其执行上下文调用它：

```js
function cautiousHasOwnProperty(object, property) {
  return Object.prototype.hasOwnProperty.call(object, property);
}
```

尽管如此，这可能过于谨慎了。在大多数代码库和环境中，使用继承的`hasOwnProperty`是足够安全的。同样，如果你考虑了风险，`in`运算符通常也是足够安全的。

# 赋值运算符

赋值运算符将其右侧操作数的值赋给其左侧操作数，并返回新赋的值。赋值操作的左侧操作数必须始终是可分配的有效标识符或属性。例如：

```js
value = 1;
value.property = 1;
value['property'] = 1;
```

此外，您还可以使用*解构赋值*，它使您能够将*左侧*操作数声明为类似对象文字或数组的结构，指定您希望分配的标识符和您希望分配的值：

```js
[name, hobby] = ['Pikachu', 'Eating Ketchup'];
name;  // => "Pikachu"
hobby: // => "Eating Ketchup"
```

我们将稍后进一步探讨*解构赋值*。现在，重要的是要知道它，以及常规标识符（`foo=...`）和属性访问器（`foo.baz = ...`，`foo[baz] = ...`），都可以用作赋值运算符的左侧操作数。

从技术上讲，JavaScript 中有大量的赋值运算符，因为它将常规运算符与基本赋值运算符结合起来，以在常见情况下需要改变现有变量或属性所引用的值时创建更简洁的赋值操作。JavaScript 中的赋值运算符如下：

+   直接赋值：`=`

+   加法赋值：`+=`

+   减法赋值：`-=`

+   乘法赋值：`*=`

+   除法赋值：`/=`

+   余数赋值：`%=`

+   按位左移赋值：`<<=`

+   按位右移赋值：`>>=`

+   按位无符号右移赋值：`>>>=`

+   按位与赋值：`&=`

+   按位异或赋值：`^=`

+   按位或赋值：`|=`

除了直接赋值`=`运算符外，所有赋值运算符都会执行`=`之前指示的操作。因此，在`+=`的情况下，`+`运算符将应用于左右操作数，然后将结果分配给左侧操作数。因此，考虑以下语句：

```js
value += 5
```

它将等同于：

```js
value = value + 5
```

对于所有其他组合类型的赋值运算符也是一样的。我们可以依靠这一点和其他已有的知识来了解这些运算符与赋值结合时的工作方式。因此，我们不需要单独探索所有这些赋值运算符的变体。

赋值通常发生在单行的上下文中。通常会看到一个赋值语句单独出现，并以分号结束：

```js
someValue = someOtherValue;
```

但赋值运算符并没有隐含要求这样做。事实上，你可以在语言中任何可以嵌入任何表达式的地方嵌入赋值。例如，以下语法是完全合法的：

```js
processStep(nextValue += currentValue);
```

这是进行加法和赋值，然后将结果值传递给`processStep`函数。这与以下代码完全等效：

```js
nextValue += currentValue;
processStep(nextValue);
```

请注意这里传递给`processStep`的是`nextValue`。赋值操作表达式的结果始终是被赋的值：

```js
let a;
(a = 1); // => 1
(a += 2); // => 3
(a *= 2); // => 6
```

在`for`和`while`循环的上下文中经常看到赋值的情况：

```js
for (let i = 0, l = arr.length; i < l; i += 1) { }
//       \___/  \____________/         \____/
//         |          |                  |
//    Assignment  Assignment       Additive Assignment
```

这和其他赋值模式都是完全可以接受的，因为它们被广泛使用，已经成为 JavaScript 的习惯用法。但在大多数其他情况下，最好不要在其他语言结构中嵌入赋值。例如`fn(a += b)`这样的代码对一些人来说可能不直观，因为可能不清楚实际传递给`fn()`的值是什么。

在编写干净的代码方面，我们在分配值时唯一需要问自己的问题是，我们的代码的读者（包括我们自己！）是否会发现分配正在发生，以及他们是否会理解正在分配的*是什么*。

# 增量和减量（前缀和后缀）运算符

这四个运算符在技术上属于赋值的范畴，但它们足够独特，值得有自己的部分：

+   后缀增量运算符（`value++`）

+   后缀减量运算符（`value--`）

+   前缀增量运算符（`++value`）

+   前缀减量运算符（`--value`）

这些将简单地增加或减少`1`的值。它们通常出现在迭代上下文中，例如`for`或`while`循环中。最好将它们视为对加法和减法赋值的简洁替代方法（即`value += 1`或`value -= 1`）。然而，它们有一些独特的特点值得探讨。

# 前缀增量/减量

前缀增量和减量运算符允许您增加或减少任何给定的值，并将评估为新增的值：

```js
let n = 0;

++n; // => 1 (the newly incremented value)
n;   // => 1 (the newly incremented value)

--n; // => 0 (the newly decremented value)
n;   // => 0 (the newly decremented value)
```

`++n`在技术上等同于以下的加法赋值：

```js
n += Number(n);
```

注意当前的`n`值首先被转换为`Number`。这就是增量和减量运算符的性质：它们严格作用于数字。因此，如果`n`是`String`，那么无法成功强制转换，那么`n`的新增值或减量值将是`NaN`：

```js
let n = 'foo';
++n; // => NaN
n;   // => NaN
```

在这里，我们可以观察到，由于将`foo`强制转换为`Number`失败，因此对其尝试增加也失败，返回`NaN`。

# 后缀增量/减量

增量和减量运算符的后缀变体与前缀变体相同，只有一个区别：后缀变体将评估为*旧*值，而不是新增/减量后的值：

```js
let n = 0;

n++; // => 0 (the old value)
n;   // => 1 (the newly incremented value)

n--; // => 1 (the old value)
n;   // => 0 (the newly decremented value)
```

这是至关重要的，如果不是有意使用，可能会导致不希望的错误。增量和减量运算符通常用于在这种差异无关紧要的情况下。例如，在`for (_;_;_)`语句的最后一个表达式中使用时，返回值在任何地方都没有使用，因此我们在以下两种方法之间看不到任何区别：

```js
for (let i = 0; i < array.length; i++) { ...}
for (let i = 0; i < array.length; ++i) { ...}
```

然而，在其他情况下，评估的值是非常关键的。例如，在下面的`while`循环中，`++i < array.length`表达式在每次迭代时都会被评估，这意味着新增的值将与`array.length`进行比较。如果我们将其替换为`i++ < array.length`，那么你将比较增量之前的值，这意味着它会少一个，因此我们会得到额外的（不需要的！）迭代。你可以在这里观察到区别：

```js
const array = ['a', 'b', 'c'];

let i = -1;
while (++i < array.length) { console.log(i); } Logs: 0, 1, 2

let x = -1;
while (x++ < array.length) { console.log(x); } // Logs: 0, 1, 2, 3
```

这是相当罕见的情况，特别是在语言中提供了更现代的迭代技术。但是增量和减量运算符在其他情境中仍然非常受欢迎，因此了解它们的前缀和后缀变体之间的区别是很有用的。

# 解构赋值

如前所述，赋值运算符（`... =`）的左操作数可以指定为解构对象或数组模式，如下所示：

```js
let position = { x: 123, y: 456 };
let { x, y } = position;
x; // => 123
y; // => 456
```

这些模式通常看起来像`Object`或`Array`字面量，因为它们分别以`{}`和`[]`开头和结尾。但它们有些微的不同。

在解构对象模式中，当你想要声明要分配的标识符或属性时，你必须将它放置在对象字面量中的值的位置。也就是说，`{ foo: bar }`通常意味着将`bar`分配给`foo`，在*解构模式*中，它意味着*将`foo`的值分配给标识符`bar`。它是相反的。当你希望访问的值的属性名称与你希望在本地范围内分配的名称匹配时，你可以使用更短的语法，如`{ foo }`，如下所示：

```js
let message = { body: 'Dear Customer...' };

// Accessing `body` and assigning to a different name (`theBody`): 
const { body: theBody } = message;
theBody; // => "Dear Customer..."

// Accessing `body` and assigning to the same name (`body`):
const { body } = message;
body; // => "Dear Customer..."
```

对于数组，通常用于指定值的语法槽（即`[这里，这里和这里]`）用于指定要分配值的标识符，因此序列中的每个标识符与数组中的相同索引元素相关联：

```js
let [a, b, c] = [1, 2, 3];
a; // => 1
b; // => 2
c; // => 3
```

你还可以使用剩余运算符（`...foo`）指示 JavaScript 将*剩余*的属性分配给给定的标识符。以下是在*解构数组模式*中使用它的示例：

```js
let [a, b, c, ...others] = [1, 2, 3, 4, 5, 6, 7];
others; // => [4, 5, 6, 7];
```

以下是在*解构对象模式*中使用它的示例：

```js
let { name, ...otherThings } = {
 name: 'James', hobby: 'JS', location: 'Europe'
};
name; // => "James"
otherThings; // => { hobby: "JS", location: "Europe" }
```

只有在提供*真正*增加可读性和简单性时才解构你的赋值。

解构也可以发生在涉及多层次层次结构的对象结构中：

```js
let city = {
  suburb: {
    inhabitants: ['alice', 'steve', 'claire']
  }
};
```

如果我们希望提取`inhabitants`数组并将其赋值给同名变量，那么可以这样做：

```js
let { suburb: { inhabitants } } = city;
inhabitants; // => ["alice", ...]
```

*解构数组模式*可以嵌套在*解构对象模式*中，反之亦然：

```js
let {
  suburb: {
    inhabitants: [firstInhabitant, ...otherInhabitants]
  }
} = city;

firstInhabitant; // => "alice"
otherInhabitants: // => ["steve", "claire"]
```

解构赋值非常有用，可以避免像这样的冗长赋值：

```js
let firstInhabitant = city.suburb.inhabitants[0];
```

但是，应该谨慎使用它，因为它有时会使阅读您的代码的人感到困惑。虽然在第一次编写时可能看起来直观，但*解构赋值*通常很难理清。考虑以下声明：

```js
const [{someProperty:{someOtherProperty:[{foo:baz}]}}] = X;
```

这在认知上是昂贵的。也许，用传统方式表达这个逻辑会更直观：

```js
const baz = X[0].someProperty.someOtherProperty[0].foo;
```

总的来说，*解构赋值*是 JavaScript 语言中一个令人兴奋和有用的特性，但应该以谨慎的方式使用，考虑到它可能引起混淆的可能性。

# 属性访问运算符

通过使用两种运算符之一来实现 JavaScript 中的属性访问：

+   直接属性访问：`obj.property`

+   **计算属性访问**：`obj[property]`

# 直接属性访问

直接访问属性的语法是一个单独的句点字符，左侧操作数是你希望访问的对象，右侧操作数是你希望访问的属性名称：

```js
const street = {
  name: 'Marshal St.'
};

street.name; // => "Marshal St."
```

*右侧*操作数必须是有效的 JavaScript 标识符，因此不能以数字开头，不能包含空格，并且一般情况下不能包含 JavaScript 规范中其他地方存在的任何标点符号字符。但是，你可以拥有以所谓的外来 Unicode 字符命名的属性，例如π（`PI`）：

```js
const myMathConstants = { π: Math.PI };
myMathConstants.π; // => 3.14...
```

这是一种不寻常的做法，通常只在新颖的设置中使用。然而，在嵌入了存在现有含义的合法外来符号（*数学*、*物理*等）的问题域中，它可能确实有用。

# 计算属性访问

在无法通过*直接属性访问*直接访问属性的情况下，可以计算要访问的属性名称，并用方括号括起来：

```js
someObject["somePropertyName"]
```

它是任何表达式的*右侧*操作数，这意味着你可以自由计算一些值，然后将其强制转换为字符串（如果它还不是字符串），并用作要访问的对象的属性名称：

```js
someObject[ computeSomethingHere() ]
```

通常用于访问包含使它们无效的字符的属性名称，因此无法与*直接属性访问*运算符一起使用。这包括数字属性名称（例如在数组中找到的属性名称）、带有空格的名称或在语言中其他地方存在标点符号或关键字的名称：

```js
object[1];
object['a property name with whitespace'];
object['{[property.name.with.odd.punctuation]}'];
```

最好只在没有其他选择的情况下依赖计算属性访问。如果可能直接访问属性（即`object.property`），那么应该优先考虑这种方式。同样，如果你正在决定对象可能包含的属性，最好使用语言内有效的标识符名称，这样可以方便直接访问。

# 其他运算符和语法

还有一些剩下的运算符和语法要探讨，它们不属于任何其他运算符类别：

+   **删除操作符**：`delete VALUE`

+   **void 操作符**：`void VALUE`

+   **new 操作符**：`new VALUE`

+   **展开语法**：`... VALUE`

+   **分组**：`(VALUE)`

+   **逗号操作符**：`VALUE, VALUE, ...`

# 删除操作符

`delete`操作符可以用来从对象中删除属性，因此它的唯一操作数通常采用属性访问器的形式，如下所示：

```js
delete object.property;
delete object[property];
```

只有被视为可配置的属性才能以这种方式被删除。所有传统添加的属性默认都是可配置的，因此可以被删除：

```js
const foo = { baz: 123; };

foo.baz;        // => 123
delete foo.baz; // => true
foo.baz;        // => undefined
'baz' in foo;   // => undefined
```

但是，如果属性是通过`defineProperty`添加的，并且`configurable`设置为`false`，那么它将无法被删除：

```js
const foo = {};
Object.defineProperty(foo, 'baz', {
  value: 123,
  configurable: false
});

foo.baz; // => 123
delete foo.baz; // => false
foo.baz; // => 123
'baz' in foo; // => true
```

正如你所看到的，`delete`操作符根据属性是否成功删除而评估为`true`或`false`。在成功删除后，属性不仅仅被设置为`undefined`或`null`，而是完全从对象中删除，因此通过`in`检查其存在性将返回`false`。

`delete`操作符在技术上可以用来删除任何变量（或者内部所谓的*环境记录绑定*），但尝试这样做被认为是不推荐的行为，并且在严格模式下会产生`SyntaxError`：

```js
'use strict';
let foo = 1;
delete foo; // ! SyntaxError
```

`delete`操作符在 JavaScript 实现之间历史上存在许多不一致，尤其是在不同的浏览器之间。因此，只有在对象上删除属性的常规用法是可取的。

# void 操作符

`void`操作符将评估为`undefined`，无论其操作数是什么。它的操作数可以是任何有效的引用或表达式：

```js
void 1; // => undefined
void null; // => undefined
void [1, 2, 3]; // => undefined
```

它现在用途不多，尽管`void 0`有时被用作`undefined`的习语，要么是为了简洁，要么是为了避免在旧环境中`undefined`是一个不受信任的可变值的问题。

# 新操作符

`new`操作符用于从构造函数形成一个实例。它的*右侧*操作数必须是一个有效的构造函数，可以是语言提供的（例如`new String()`）或者自己提供的：

```js
function Thing() {} 
new Thing(); // => Instance of Thing
```

通过*实例*，我们真正的意思是一个对象，它的`[[Prototype]]`等于构造函数的`prototype`属性，并且已经作为它的`this`绑定传递给构造函数，以便构造函数可以完全准备好它的目的。请注意，无论我们是通过类定义还是传统语法定义构造函数，我们都可以对产生的实例做出相同的断言：

```js
// Conventional Constructor Definition:
function Example1() {
  this.value = 123;
}

Example1.prototype.constructor === Example1; // => true
Object.getPrototypeOf(new Example1()) === Example1.prototype; // => true
new Example1().value === 123; // => true

// Class Definition:
class Example2 {
  constructor() { this.value = 123; }
}

Example2.prototype.constructor === Example2; // => true
Object.getPrototypeOf(new Example2()) === Example2.prototype; // => true
new Example2().value === 123; // => true
```

`new`操作符只关心它的*右侧*操作数是否可构造。这意味着它不能是由箭头函数形成的函数，就像这个例子：

```js
const Thing = () => {};
new Thing(); // ! TypeError: Thing is not a constructor
```

只要你使用函数表达式或声明定义了构造函数，它就可以正常工作。如果你愿意，甚至可以实例化一个匿名内联构造函数：

```js
const thing = new (function() {
  this.name = 'Anonymous';
});

thing.name; // => "Anonymous"
```

`new`操作符不正式需要调用括号。只有在你传递参数给构造函数时才需要包括它们：

```js
// Both equivalent:
new Thing;
new Thing();
```

然而，当你希望实例化某些东西然后立即访问属性或方法时，你需要通过提供调用括号来消除歧义，*然后*在其后访问属性；否则，你会收到`TypeError`：

```js
function Component() {
  this.width = 200;
  this.height = 200;
}

new Component().width; // => 200
new Component.width; // => ! TypeError: Component.width is not a constructor
(new Component).width; // => 200
```

`new`操作符的使用通常非常简单。从语义上讲，它被理解为与实例的构造有关，因此理想情况下只应该用于这个目的。因此，假定`new`的*右侧*操作数引用的任何东西都以大写字母开头并且是一个名词。这些命名约定表明它是一个构造函数，为希望使用它的任何程序员提供了有用的提示。以下是一些好的和坏的构造函数名称的示例：

```js
// Bad (non-idiomatic) names for Constructors:
new dropdownComponent;
new the_dropdown_component;
new componentDropdown;
new CreateDropdownComponent;

// Good (idiomatic) names for Constructors:
new Dropdown;
new DropdownComponent;
```

正确命名构造函数至关重要。它使我们的同行程序员立即意识到特定抽象满足的*合同*是什么。如果我们命名一个构造函数，使其看起来像一个常规函数，那么我们的同事可能会尝试不正确地调用它，并因此遭受可能的错误。因此，利用名称传达*合同*的能力是完全有道理的，正如在前一章关于命名的讨论中所述（第五章，*命名很难*）。

# 展开语法

*展开语法*（也称为*rest 语法*）由三个点组成，后面跟着一个操作数表达式（`...expression`）。它允许在需要多个参数或多个数组元素的地方展开表达式。它在语言的五个不同领域中存在：

+   在*数组文字*中，形式为`array = [a, b, c, ...otherArray]`

+   在*对象文字*中，形式为`object = {a, b, c, ...otherObject}`

+   在*函数参数列表*中，形式为`function(a, b,  c, ...otherArguments) {}`

+   在*解构数组模式*中，形式为`[a, b, c, ...others] = array`

+   在*解构对象模式*中，形式为`{a, b, c, ,,,otherProps} = object`

在*函数参数列表*的上下文中，*展开语法*必须是最后一个参数，并且表示您希望从那时起传递给函数的所有参数都被收集到一个由指定名称的单一数组中。

```js
function addPersonWithHobbies(name, ...hobbies) {
  name; // => "Kirk"
  hobbies; // => ["Collecting Antiques", "Playing Chess", "Drinking"]
}

addPersonWithHobbies(
 'Kirk',
 'Collecting Antiques',
 'Playing Chess',
 'Drinking'
);
```

如果您尝试在其他参数中使用它，那么您将收到`SyntaxError`：

```js
function doThings(a, ...things, c, d, e) {}
// ! SyntaxError: Rest parameter must be last formal parameter
```

在*数组文字*或*解构数组模式*的上下文中，*展开语法*同样用于指示所引用的值应该展开。最好将这两者看作是两种相反的操作，*解构*和*重构：

```js
// Deconstruction:
let [a, b, c, ...otherLetters] = ['a', 'b', 'c', 'd', 'e', 'f'];
a; // => "a"
b; // => "b"
c; // => "c"
otherLetters; // => ["d", "e", "f"]

// Reconstruction:
let reconstructedArray = [a, b, c, ...otherLetters];
reconstructedArray; // => ["a", "b", "c", "d", "e", "f"]
```

当在*数组文字*或*解构数组模式*的上下文中使用时，*展开语法*必须指向可迭代的值。这不一定是一个数组。例如，字符串是可迭代的，所以下面的也可以工作：

```js
let [...characters] = 'Hello';
characters; // => ["H", "e", "l", "l", "o"]
```

在*对象文字*或*d**estructuring 对象模式*的上下文中，*展开语法*同样用于将任何给定对象的所有属性展开到接收对象中。再次，我们可以将这看作是*解构*和*重构*的过程：

```js
// Deconstruction:
const {name, ...attributes} = {
  name: 'Nissan Skyline',
  engineSize: '2500cc',
  year: 2009
};
name; // => "Nissan Skyline"
attributes; // => { engineSize: "2500cc", year: 2009 }

// Reconstruction:
const skyline = {name, ...attributes};
skyline; // => { name: "Nissan Skyline", engineSize: "2500cc", year: 2009 }
```

在这种情况下使用*展开语法*的右侧值必须是一个对象或可以包装为对象的原始值（例如，`Number`或`String`）。这意味着 JavaScript 中的所有值都是允许的，除了`null`和`undefined`，我们知道这两者都不能被包装为对象：

```js
let {...stuff} = null; // => TypeError
```

因此，最好只在对象上下文中使用*展开语法*，当您确信该值是一个对象时。

总之，正如我们所看到的，*展开语法*在各种不同的情况下都非常有用。它的主要优势在于它减少了提取和指定值所需的语法量。

# 逗号运算符

逗号运算符（`a, b`）接受左侧和右侧操作数，并始终计算为其右侧操作数。有时它不被认为是一个运算符，因为它在技术上不对其操作数进行操作。它也非常罕见。

逗号运算符不应与我们在声明或调用函数时用来分隔参数的逗号（例如`fn(a,b,c)`），在创建数组文字和对象文字时使用的逗号（例如`[a, b, c]`），或者在声明变量时使用的逗号（例如`let a, b, c;`）混淆。逗号运算符与所有这些都不同。

它最常见于`for(;;)`循环的迭代语句部分：

```js
for (let i = 0; i < length; i++, x++, y++) {
  // ...
}
```

请注意第三个语句中发生的三次递增操作（在传统的`for(;;)`语句的每次迭代结束时发生），它们之间都用逗号分隔。在这种情况下，逗号仅用于确保所有这些单独的操作将在一个单一语句的上下文中发生，而不受彼此的影响。在`for(;;)`语句之外的常规代码中，你可能只会将它们分别放在自己的行和语句中，如下所示：

```js
i++;
x++;
y++;
```

然而，由于`for(;;)`语法的限制，它们必须存在于一个单一的语句中，因此逗号操作符变得必要。

逗号操作符评估其*右侧*操作数在这种情况下并不重要，但在其他情境中可能很重要：

```js
const processThings = () => (firstThing(), secondThing());
```

在这里，当调用`processThings`时，将首先调用`firstThing`，然后调用`secondThing`，并返回`secondThing`返回的任何内容。因此，它等同于以下内容：

```js
const processThings = () => {
  firstThing();
  return secondThing();
};
```

在 JavaScript 中很少见到逗号操作符的使用，即使在这样的情况下，它也往往会使本来可以更清晰表达的代码变得不必要地复杂。了解它的存在和行为是有用的，但我们不应该期望它成为一个日常操作符。

# 分组

*分组*，或者用括号括起来，是通过使用常规括号（`(...)`）来实现的。这不应该被误解为其他使用括号的语法，比如函数调用（`fn(...)`）。

分组括号可以被视为一个操作符，就像我们学过的所有其他操作符一样。它们接受一个操作数——任何形式的表达式，并且将评估其中的内容：

```js
(1);             // => 1
([1, 2, 3]);     // => [1, 2, 3]
(false && true); // => false
((1 + 2) * 3);   // => 9
(()=>{});        // => (A function)
```

因为它只是评估其内容，你可能会想知道分组的目的是什么。早些时候，我们讨论了操作符优先级和结合性的概念。有时，如果你正在使用一系列操作符，并希望强制特定的操作顺序，那么唯一的方法就是将它们包裹在一个分组中，这样在与其他操作符一起使用时，它具有最高的优先级：

```js
// The order of operations is dictated
// by each operator's precedence:
1 + 2 * 3 - 5; 

// Here, we are forcing the order:
(1 + 2) * (3 - 5);
```

当操作顺序不是你所期望的，或者可能对代码的读者不清晰时，使用分组是明智的。例如，有时常见的做法是将从函数返回的项目包装在一个分组中，以提供美观的容纳和清晰度：

```js
function getComponentWidth(component) {
  return (
    component.getInnerWidth() +
    component.getLeftPadding() +
    component.getRightPadding()
  );
}
```

另一个明显的解决方案可能只是缩进你希望包含的项目，但这样做的问题是 JavaScript 的`return`语句将不知道在其自己的行之外寻找表达式或值的开始：

```js
// WARNING: this won't work
return
  component.getInnerWidth() +
  component.getLeftPadding() +
  component.getRightPadding();
```

在前面的代码中，`return`语句在解析器观察到同一行上没有值或表达式时，会有效地用分号终止自身。这被称为**自动分号插入**（**ASI**），它的存在意味着我们经常需要使用分组来明确告诉解析器我们的意图是什么：

```js
// Clear to humans; clear to the parser:
return (
  component.getInnerWidth() +
  component.getLeftPadding() +
  component.getRightPadding()
);
```

总之，*分组*是一个用于容纳和重新排序操作的有用工具，它是一种增加表达式的清晰度和可读性的廉价且简单的方法。

# 按位操作符

JavaScript 有七个按位操作符。这里的*按位*意味着*对二进制数进行操作*。这些操作符很少被使用，但了解它们仍然是有用的：

+   **按位无符号右移操作符**：`>>>`

+   **按位左移操作符**：`<<`

+   **按位右移操作符**：`>>`

+   **按位或**：`|`

+   **按位与**：`&`

+   **按位异或**：`^`

+   **按位非**：`~`（一元操作符）

在 JavaScript 中，按位操作非常罕见，因为通常处理的是高级位序列，如字符串或数字。然而，值得至少对按位操作有一定的了解，这样如果遇到需要，你就能应对。

JavaScript 中的所有位运算符都将首先将它们的操作数（或者在位运算 NOT `~`的情况下是单个操作数）强制转换为 32 位整数表示。这意味着，内部上，数字如`250`将被表现为如下：

```js
00000000 00000000 00000000 11111010
```

在这种情况下，即`250`的最后八位包含有关数字的所有信息：

```js
1 1 1 1 1 0 1 0
+ + + + + + + +
| | | | | | | +---> 0 * 001 = 000
| | | | | | +-----> 1 * 002 = 002
| | | | | +-------> 0 * 004 = 000
| | | | +---------> 1 * 008 = 008
| | | +-----------> 1 * 016 = 016 
| | +-------------> 1 * 032 = 032
| +---------------> 1 * 064 = 064
+-----------------> 1 * 128 = 128
=================================
                        SUM = 250
```

将所有位相加将得到一个十进制整数值为`250`。

每个可用的位运算符都将对这些位进行操作并得出一个新值。例如，位 AND 操作将为每对同时处于*on*状态的位产生一个位值为`1`。

```js
const a = 250;  // 11111010
const b = 20;   // 00010100
a & b; // => 16 // 00010000
```

我们可以看到，从右边数起的第五位（即`16`）在`250`和`20`中都是*on*，因此 AND 操作将导致只有这一位保持 on 状态。

只有在进行二进制数学运算时，才应该使用位运算符。除此之外，任何位运算符的使用（例如，用于副作用）都应该避免，因为它会极大地限制我们代码的清晰度和可理解性。

曾经在 JavaScript 中经常看到位运算符如`~`和`|`的使用，因为它们在简洁地得出一个数字的整数部分方面很受欢迎（例如，`~34.6789 === 34`）。毫无疑问，这种方法虽然聪明且令人自豪，但却创建了难以阅读和陌生的代码。使用更明确的技术仍然更可取。在取整的情况下，使用`Math.floor()`是理想的。

# 总结

在本章中，我们详尽地介绍了 JavaScript 中可用的运算符。总的来说，过去的三章使我们对 JavaScript 语法有了非常坚实的基础理解，使我们在构建表达式时感到非常舒适。

在下一章中，我们将继续通过应用我们对类型和运算符的现有知识来探索语言的声明和控制流。我们将探讨如何使用更大的语言结构来编写清晰的代码，并将讨论这些结构中存在的许多陷阱和特殊之处。
