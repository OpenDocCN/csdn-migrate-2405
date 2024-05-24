# 精通 JavaScript 函数式编程（四）

> 原文：[`zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410`](https://zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：确保纯度-不可变性

在第四章的*行为良好-纯函数*中，当我们考虑纯函数及其优点时，我们看到修改接收到的参数或全局变量等副作用经常导致不纯。现在，在处理 FP 的许多方面和工具的几章之后，让我们来看看*不可变性*的概念：如何以这样一种方式处理对象，使得意外修改它们变得更加困难，甚至更好的是不可能。

我们无法强迫开发人员以安全、受保护的方式工作，但如果我们找到某种方法使数据结构不可变（意味着除了通过一些永远不允许修改原始数据但产生新对象的接口之外，它们不能直接更改），那么我们将有一个可执行的解决方案。在本章中，我们将看到两种处理这种不可变对象和数据结构的不同方法：

+   基本的 JS 方法，如冻结对象，以及克隆来创建新对象，而不是修改现有对象

+   持久数据结构，具有允许更新它们而不更改原始数据且无需克隆所有内容的方法，以获得更高的性能

警告：本章中的代码不适合生产；我想专注于主要观点，而不是所有与属性、getter、setter、原型等有关的无数细节，这些细节应该考虑到一个完整、牢固的解决方案。对于实际开发，我非常建议使用第三方库，但在确认它确实适用于您的情况之后。我们将推荐几个这样的库，但当然还有许多其他库可供使用。

# 直接的 JS 方式

副作用的最大原因之一是函数可能修改全局对象或其参数本身。所有非原始对象都作为引用传递，因此当/如果您修改它们时，原始对象将被更改。如果我们想要阻止这种情况（而不仅仅依赖开发人员的善意和清洁编码），我们可能需要考虑一些直接的 JS 技术来禁止这些副作用。

# 修改器函数

意外问题的一个常见来源是几个 JS 方法实际上修改了底层对象。在这种情况下，仅仅使用它们就会导致副作用，甚至您可能都意识不到。数组是问题的基本来源，令人头痛的方法列表并不短。（有关每种方法的更多信息，请参见[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array#Mutator_methods`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array#Mutator_methods)。）

+   `.copyWithin()` 允许您在数组内复制元素

+   `.fill()` 用给定值填充数组

+   `.push()` 和 `.pop()` 允许您在数组末尾添加或删除元素

+   `.shift()` 和 `.unshift()` 以相同的方式工作，但在数组的开头

+   `.splice()` 允许您在数组中的任何位置添加或删除元素

+   `.reverse()` 和 `.sort()` 在原地修改数组，颠倒其元素或对其进行排序

对于其中一些操作，您可能会生成数组的副本，然后使用它。在第四章的*参数突变*部分，*行为良好-纯函数*，我们就是用了展开运算符；我们也可以使用`.slice()`：

```js
const maxStrings2 = a => [...a].sort().pop();
const maxStrings3 = a => a.slice().sort().pop();

let countries = ["Argentina", "Uruguay", "Brasil", "Paraguay"];
console.log(maxStrings3(countries)); // *"Uruguay"*
console.log(countries); // *["Argentina", "Uruguay", "Brasil", "Paraguay"] - unchanged*
```

Setter 方法也是修改器，逻辑上会产生副作用，因为它们可以做任何事情。如果是这种情况，您将不得不选择稍后描述的其他解决方案之一。

# 常量

如果突变不是因为使用某些 JS 方法而发生的，那么我们可能希望尝试使用`const`定义，但那只是行不通的。在 JS 中，const 定义只意味着对象或数组的*引用*不能更改（因此您不能将不同的对象分配给它），但您仍然可以修改对象本身的属性。

```js
const myObj = {d: 22, m: 9};
console.log(myObj);
// {d: 22, m: 9}

myObj = {d: 12, m: 4};
// ***Uncaught TypeError: Assignment to constant variable.***

myObj.d = 12; // *but this is fine!*
myObj.m = 4;
console.log(myObj);
// {d: 12, m: 4}
```

因此，如果您决定在任何地方都使用`const`，那么您只能安全地防止对对象和数组的直接赋值。更为温和的副作用，例如更改属性或数组元素，仍然是可能的，因此这不是一个解决方案。

可以工作的是使用*冻结*来提供不可修改的结构和*克隆*来生成修改后的新结构。这可能不是禁止对象被更改的最佳方法，但可以用作权宜之计。让我们详细讨论一下这两种方法。

# 冻结

如果我们想要避免程序员意外或故意修改对象的可能性，冻结它是一个有效的解决方案。在对象被冻结之后，任何修改它的尝试都将悄无声息地失败。

```js
const myObj = { d: 22, m: 9 };
Object.freeze(myObj);

myObj.d = 12; // *won't have effect...*
console.log(myObj);
// Object {d: 22, m: 9}
```

不要将冻结与密封混淆：`Object.seal()`应用于对象，禁止向其添加或删除属性，因此对象的结构是不可变的，但属性本身可以更改。`Object.freeze()`不仅包括密封属性，还使它们不可更改。有关更多信息，请参阅[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/seal`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/seal)和[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/freeze)。

这种解决方案只有一个问题：冻结对象是一个*浅*操作，它类似于`const`声明，冻结属性本身。如果任何属性本身是对象或数组，并且具有进一步的对象或数组作为属性，依此类推，它们仍然可以被修改。在这里我们只考虑数据；您可能还想要冻结函数，但对于大多数用例，您想要保护的是数据。

```js
let myObj3 = {
 d: 22,
 m: 9,
 o: {c: "MVD", i: "UY", f: {a: 56}}
};
Object.freeze(myObj3);
console.log(myObj3);
// *{d:22, m:9, o:{c:"MVD", i:"UY", f:{ a:56}}}*
```

这只是部分成功，如我们所见：

```js
myObj3.d = 8888;          // *wont' work*
myObj3.o.f.a = 9999; // *oops, does work!!*
console.log(myObj3);
// *{d:22, m:9, o:{c:"MVD", i:"UY", f:{ **a:9999** }}}*
```

如果我们想要实现对象的真正不可变性，我们需要编写一个冻结对象所有级别的例程。幸运的是，通过递归很容易实现这一点。主要的想法是首先冻结对象本身，然后递归地冻结其每个属性。我们必须确保只冻结对象自己的属性；例如，我们不应该干扰对象的原型：

```js
const deepFreeze = obj => {
 if (obj && typeof obj === "object" && !Object.isFrozen(obj)) {
        Object.freeze(obj);
 Object.getOwnPropertyNames(obj).forEach(prop =>
            deepFreeze(obj[prop])
 );
 }
 return obj;
};
```

请注意，与`Object.freeze()`的工作方式相同，`deepFreeze()`也会*原地*冻结对象。我希望保持操作的原始语义，因此返回的对象将始终是原始对象。如果我们想以更纯粹的方式工作，我们应该首先复制原始对象（我们将在下一节中看到如何做到这一点），然后再冻结它。

仍然存在一个小的可能问题，但结果非常糟糕：如果对象包含对自身的引用，那么会发生什么？如果我们跳过已经冻结的对象进行冻结，我们可以避免这种情况：因为对象所引用的对象已经被冻结，所以会忽略向后的循环引用。因此，我们编写的逻辑已经解决了这个问题，没有更多需要做的了！

如果我们对一个对象应用`deepFreeze()`，我们可以安全地将其传递给任何函数，知道它根本不可能被修改。您还可以使用此属性来测试函数是否修改其参数：深度冻结它们，调用函数，如果函数依赖于修改其参数，它将无法工作，因为更改将被悄悄忽略。但是，那么，我们如何从函数中返回结果，如果它涉及到一个接收到的对象？这可以通过许多方式解决，一个简单的方法使用克隆，我们将看到。

在本章末尾的*问题*部分中，查看另一种通过代理冻结对象的方式。

# 克隆和变异。

如果不允许改变对象，则必须创建一个新对象。例如，如果你使用 Redux，reducer 是一个函数，它接收当前状态和一个动作（本质上是一个带有新数据的对象），并产生新状态。修改当前状态是完全禁止的，我们可以通过始终使用冻结对象来避免这种错误，就像我们在前一节中看到的那样。因此，为了满足 reducer 的要求，我们将需要能够克隆原始状态，然后根据接收到的动作进行相应的改变，然后得到的对象将成为新状态。

您可能希望重新查看第五章的*更一般的循环*部分，即*声明式编程 - 更好的风格*，在那里我们编写了一个基本的`objCopy()`函数，提供了与此处所示的不同方法。

最后，我们还应该冻结返回的对象，就像我们对原始状态做的那样。但让我们从头开始：我们如何克隆一个对象？当然，你总是可以手工做，但当处理大型复杂对象时，这不是你真正想考虑的事情。

```js
let oldObject = {
 d: 22,
 m: 9,
 o: {c: "MVD", i: "UY", f: {a: 56}}
};

let newObject = {
 d: oldObject.d,
 m: oldObject.m,
 o: {c: oldObject.o.c, i: oldObject.o.i, f: {a: oldObject.o.f.a}}
};
```

现在，寻找更自动化的解决方案，有几种简单的 JS 数组或对象复制方式，但它们都有相同的*浅显性*问题。

```js
let newObject1 = Object.assign({}, myObj);
let newObject2 = {...myObj};

let myArray = [1, 2, 3, 4];
let newArray1 = myArray.slice();
let newArray2 = [...myArray];
```

如果一个对象或数组包含对象（它们自己可能包含对象，依此类推），我们会遇到与冻结相同的问题：对象是通过引用复制的，这意味着新对象的更改也将意味着更改旧对象。

```js
let oldObject = {
 d: 22,
 m: 9,
 o: { c: "MVD", i: "UY", f: { a: 56 } }
};
let newObject = Object.assign({}, oldObject);

newObject.d = 8888;
newObject.o.f.a = 9999; 
console.log(newObject);
// {d:8888, m:9, o: {c:"MVD", i:"UY", f: {a:9999}}} -*- ok*

console.log(oldObject);
// {d:22, m:9, o: {c:"MVD", i:"UY", f: {a:9999}}} -- *oops!!*
```

有一个简单的解决方案，基于 JSON。如果我们`stringify()`原始对象，然后`parse()`结果，我们将得到一个新对象，但它与旧对象完全分离。

```js
const jsonCopy = obj => JSON.parse(JSON.stringify(obj));
```

这适用于数组和对象，但无论如何都存在一个问题。如果对象的任何属性具有构造函数，它将不会被调用：结果将始终由普通 JS 对象组成。我们可以通过`Date()`非常简单地看到这一点。

```js
let myDate = new Date();
let newDate = jsonCopy(myDate);
console.log(typeof myDate, typeof newDate); // ***object string***
```

我们可以采用递归解决方案，就像深度冻结一样，逻辑是相当相似的。每当我们发现一个真正是对象的属性时，我们调用适当的构造函数。

```js
const deepCopy = obj => {
 let aux = obj;
 if (obj && typeof obj === "object") {
        aux = new obj.constructor();
 Object.getOwnPropertyNames(obj).forEach(
 prop => (aux[prop] = deepCopy(obj[prop]))
 );
 }
 return aux;
};
```

这解决了我们在日期或者实际上任何对象中发现的问题！如果我们运行上面的代码，但使用`deepCopy()`而不是`jsonCopy()`，我们将得到`object object`作为输出，这正是应该的。如果我们检查类型和构造函数，一切都将匹配。此外，数据更改实验现在也将正常工作。

```js
let oldObject = {
 d: 22,
 m: 9,
 o: { c: "MVD", i: "UY", f: { a: 56 } }
};

let newObject = deepCopy(oldObject);
newObject.d = 8888;
newObject.o.f.a = 9999;
console.log(newObject);
// {d:8888, m:9, o:{c:"MVD", i:"UY", f:{a:9999}}}
console.log(oldObject);
// {d:22, m:9, o:{c:"MVD", i:"UY", f:{a:56}}} -- *unchanged!*
```

现在我们知道如何复制一个对象，我们可以这样工作：

1.  接收一个（冻结的）对象作为参数。

1.  制作一个不会被冻结的副本。

1.  从该副本中获取值，以在您的代码中使用。

1.  随意修改副本。

1.  冻结它。

1.  将其作为函数的结果返回。

尽管有些麻烦，但所有这些都是可行的。因此，让我们添加一些函数，帮助将所有内容整合在一起。

# 获取器和设置器

在上一节末尾列出的所有工作中，每次你想要更新一个字段，都会变得麻烦，并容易出错。让我们添加一对函数，以便能够从冻结的对象中获取值，但解冻它们以便你可以使用，并允许修改对象的任何属性，创建它的新副本，这样原始对象就不会被实际修改。

# 获取属性

回到第六章中的*从对象中获取属性*部分，*生成函数 - 高阶函数*，我们编写了一个简单的`getField()`函数，可以处理从对象中获取单个属性。

```js
const getField = attr => obj => obj[attr];
```

我们可以通过组合一系列`getField()`调用来从对象中获取深层属性，但这样做会相当麻烦。相反，让我们编写一个函数，它将接收一个*路径* - 一个字段名称的数组 - 并返回对象的相应部分，如果路径不存在则返回 undefined。使用递归非常合适，简化了编码！

```js
const getByPath = (arr, obj) => {
 if (arr[0] in obj) {
 return arr.length > 1
 ? getByPath(arr.slice(1), obj[arr[0]])
 : deepCopy(obj[arr[0]]);
 } else {
 return undefined;
 }
};
```

一旦对象被冻结，就无法*解冻*它，所以我们必须求助于制作它的新副本；`deepCopy()`非常适合这个任务。让我们尝试一下我们的新函数：

```js
let myObj3 = {
 d: 22,
 m: 9,
 o: {c: "MVD", i: "UY", f: {a: 56}}
};
deepFreeze(myObj3);

console.log(getByPath(["d"], myObj3)); // 22
console.log(getByPath(["o"], myObj3)); // {c: "MVD", i: "UY", f: {a: 56}}
console.log(getByPath(["o", "c"], myObj3)); // "MVD"
console.log(getByPath(["o", "f", "a"], myObj3)); // 56
```

我们还可以检查返回的对象是否被冻结。

```js
let fObj = getByPath(["o", "f"], myObj3);
console.log(fObj); // {a: 56}
fObj.a = 9999;
console.log(fObj); // {a: 9999} *-- it's not frozen*
```

# 按路径设置属性

现在我们写了这个，我们可以编写一个类似的`setByPath()`函数，它将接受一个路径、一个值和一个对象，并更新一个对象。

```js
const setByPath = (arr, value, obj) => {
 if (!(arr[0] in obj)) {
 obj[arr[0]] =
 arr.length === 1 ? null : Number.isInteger(arr[1]) ? [] : {};
 }

 if (arr.length > 1) {
 return setByPath(arr.slice(1), value, obj[arr[0]]);
 } else {
 obj[arr[0]] = value;
 return obj;
 }
};
```

我们在这里使用递归来进入对象，如果需要的话创建新属性，直到我们遍历完路径的全部长度。一个重要的细节是，在创建属性时，我们是否需要一个数组还是一个对象。我们可以通过检查路径中的下一个元素来确定：如果它是一个数字，那么我们需要一个数组；否则，一个对象就可以了。当我们到达路径的末尾时，我们简单地赋予新给定的值。

如果你喜欢这种做事情的方式，你应该看看*seamless-immutable*库，它正是以这种方式工作。名称中的*seamless*部分指的是你仍然可以使用正常的对象，尽管是冻结的！所以你可以使用`.map()`、`.reduce()`等方法。在[`github.com/rtfeldman/seamless-immutable`](https://github.com/rtfeldman/seamless-immutable)了解更多。

然后我们可以编写一个函数，它将能够接受一个冻结的对象，并更新其中的属性，返回一个新的，同样被冻结的对象。

```js
const updateObject = (arr, obj, value) => {
 let newObj = deepCopy(obj);
 setByPath(arr, value, newObj);
 return deepFreeze(newObj);
};
```

我们可以看看它是如何工作的：让我们对我们一直在使用的`myObj3`对象运行几次更新。

```js
let new1 = updateObject(["m"], myObj3, "sep");
// {d: 22, m: "sep", o: {c: "MVD", i: "UY", f: {a: 56}}};

let new2 =updateObject(["b"], myObj3, 220960);
// {d: 22, m: 9, o: {c: "MVD", i: "UY", f: {a: 56}}, b: 220960};

let new3 =updateObject(["o", "f", "a"], myObj3, 9999);
// {d: 22, m: 9, o: {c: "MVD", i: "UY", f: {a: 9999}}};

let new4 =updateObject(["o", "f", "j", "k", "l"], myObj3, "deep");
// {d: 22, m: 9, o: {c: "MVD", i: "UY", f: {a: 56, j: {k: "deep"}}}};
```

有了这一对函数，我们终于找到了保持不可变性的方法：

+   对象必须从一开始就被冻结

+   从对象中获取数据是通过`getByPath()`完成的

+   使用`updateObject()`来设置数据，它在内部使用`setByPath()`

如果你想看另一种使用 setter 和 getter 来实现对对象的功能访问和更新的方法，请查看 lenses，它由 Ramda 等库提供。Lenses 可以被看作是一种功能性的方式，不仅可以获取和设置变量，还可以以可组合的方式对其运行函数：一种*某物*，让你专注于数据结构的特定部分，访问它，并可能也改变它或对其应用函数。从[`ramdajs.com/docs/#lens.`](http://ramdajs.com/docs/#lens.)开始了解更多。

# 持久数据结构

如果每次你想要改变数据结构中的某些东西，你都去改变它，你的代码将充满副作用。另一方面，每次复制完整的结构都是浪费时间和空间。有一种中间方法，使用持久数据结构，如果处理正确，可以让你在创建新结构的同时应用更改，以一种高效的方式。

# 使用列表

考虑一个简单的过程：假设你有一个列表，你想要向其中添加一个新元素。你会怎么做？我们可以假设每个节点都是一个`NodeList`对象。

```js
class ListNode {
 constructor(value, next = null) {
 this.value = value;
 this.next = next;
 }
}
```

可能的列表如下，其中`list`变量将指向第一个元素。见图 10.1：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/6de96866-8506-4eae-9ad7-54d464e40287.jpg)图 10.1。初始列表。（你能告诉这个列表缺少什么，以及缺少的部分在哪里吗？）

如果你想在 B 和 F 之间添加 D（这是音乐家会理解的：我们这里有“三度圈”，但缺少了 D），最简单的解决方案就是添加一个新节点并更改一个现有节点，得到以下结果。见图 10.2：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/ba086145-a541-4238-9230-c876d1014ef7.jpg)图 10.2。列表现在有一个新元素：我们不得不修改一个现有的元素来进行添加。

然而，以这种方式工作显然是非功能性的，很明显我们正在修改数据。有一种不同的工作方式，即创建一个持久的数据结构，在这种结构中，所有的改动（插入、删除和修改）都是分开进行的，小心不要修改现有的数据。另一方面，如果结构的某些部分可以被重复使用，那么就会为了性能而这样做。进行持久更新将返回一个新的列表，其中一些节点是之前的一些节点的副本，但原始列表完全没有任何改变。见图 10.3：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/aeff7170-298f-418b-8481-93d246c2778d.jpg)图 10.3。虚线元素显示了新返回的列表：一些元素必须被复制以避免修改原始结构。旧列表指的是原始结构，新列表指的是插入的结果。

当然，我们还将处理更新或删除。再次从图 10.4 中的列表开始，如果我们想要更新它的第四个元素，解决方案将涉及创建列表的一个新子集，直到并包括第四个元素，同时保持其余部分不变。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/ecbdcf64-6a9b-4bd1-9b30-169c7d25f790.jpg)图 10.4。我们的列表，有一个改变的元素。

删除一个元素也是类似的。让我们在原始列表中去掉第三个元素 F。见图 10.5：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/1a66ce0d-d5f3-435f-b687-4ee1e7a8c798.jpg)图 10.5。在持久的方式下删除第 3 个元素后的原始列表。

使用列表或其他结构始终可以解决数据持久性的问题。但是，现在让我们专注于对我们来说可能是最重要的工作：处理简单的 JS 对象。毕竟，所有的数据结构都是 JS 对象，所以如果我们可以处理任何对象，我们就可以处理其他结构。

# 更新对象

这种方法也可以应用于更常见的需求，比如修改一个对象。这对于 Redux 用户来说是一个非常好的主意：可以编写一个 reducer，它将接收旧状态作为参数，并生成一个带有最小必要更改的更新版本，而不会以任何方式改变原始状态。

想象你有一个如下的对象：

```js
myObj = {
 a: ...,
 b: ...,
 c: ...,
    d: {
 e: ...,
        f: ...,
 g: {
 h: ...,
 i: ...
 }
 }
};
```

如果你想修改`myObj.d.f`，并且想以持久的方式进行，你将创建一个新对象，它将与之前的对象有几个共同的属性，但将为修改的属性定义新的属性。见图 10.6：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/c62a4319-a79b-45fa-9e71-35bdcf5666ac.jpg)图 10.6。通过创建一个具有一些共享属性和一些新属性的新对象，以持久的方式编辑对象。

如果你想手动完成这个操作，你将不得不以非常繁琐的方式编写类似下面的内容。大多数属性都来自原始对象，但`d`和`d.f`是新的：

```js
newObj = {
 a: myObj.a,
 b: myObj.b,
 c: myObj.c,
 d: {
 e: myObj.d.e,
 f: *the new value*,
 g: myObj.d.g
 }
};
```

我们在本章的早些时候已经看到了类似的代码，当时我们决定要编写一个克隆函数，但现在让我们选择一种不同类型的解决方案。事实上，这种更新可以自动完成。

```js
const setIn = (arr, val, obj) => {
 const newObj = Number.isInteger(arr[0]) ? [] : {};

 Object.keys(obj).forEach(k => {
 newObj[k] = k !== arr[0] ? obj[k] : null;
 });

 newObj[arr[0]] =
 arr.length > 1 ? setIn(arr.slice(1), val, obj[arr[0]]) : val;
 return newObj;
};
```

逻辑是递归的，但并不太复杂。首先，我们在当前级别确定我们需要什么样的对象：数组还是对象。然后，我们将所有属性从原始对象复制到新对象，除了我们正在更改的属性。最后，我们将该属性设置为给定值（如果我们已经完成了属性名称的路径），或者我们使用递归来深入复制。

注意参数的顺序：首先是路径，然后是值，最后是对象。我们应用了将最*稳定*的参数放在前面，最可变的参数放在最后的概念。如果你对这个函数进行柯里化，你可以将相同的路径应用到几个不同的值和对象上，如果你固定路径和值，你仍然可以使用不同的对象来使用该函数。

我们可以尝试这种逻辑。让我们从一个毫无意义的对象开始，但是有几个级别，甚至有一个对象数组，以增加变化。

```js
let myObj1 = {
 a: 111,
 b: 222,
 c: 333,
 d: {
 e: 444,
 f: 555,
 g: {
 h: 666,
 i: 777
 },
 j: [{k: 100}, {k: 200}, {k: 300}]
 }
};
```

我们可以测试将`myObj.d.f`更改为一个新值：

```js
let myObj2 = setIn(["d", "f"], 88888, myObj1);
/*
{
 a: 111,
 b: 222,
 c: 333,
 d: {
 e: 444,
 f: 88888,
 g: {h: 666, i: 777},
 j: [{k: 100}, {k: 200}, {k: 300}]
 }
}
*/

console.log(myObj.d === myObj2.d);     // *false*
console.log(myObj.d.f === myObj2.d.f); // *false*
console.log(myObj.d.g === myObj2.d.g); // *true*
```

底部的日志验证了算法是否正确运行：`myObj2.d`是一个新对象，但`myObj2.d.g`重用了`myObj`中的值。

在第二个对象中进一步更新数组让我们也能测试逻辑在这些情况下是如何工作的。

```js
let myObj3 = setIn(["d", "j", 1, "k"], 99999, myObj2);
/*
{
 a: 111,
 b: 222,
 c: 333,
 d: {
 e: 444,
 f: 88888,
 g: {h: 666, i: 777},
 j: [{k: 100}, {k: 99999}, {k: 300}]
 }
}
*/
console.log(myObj.d.j === myObj3.d.j);       // *false*
console.log(myObj.d.j[0] === myObj3.d.j[0]); // *true*
console.log(myObj.d.j[1] === myObj3.d.j[1]); // *false*
console.log(myObj.d.j[2] === myObj3.d.j[2]); // *true*
```

我们可以将`myObj.d.j`数组中的元素与新创建的对象中的元素进行比较，你会发现数组是一个新数组，但两个元素（没有更新的元素）仍然是与`myObj`中相同的对象。

这显然还不够。我们的逻辑可以更新现有字段，甚至在没有的情况下添加它，但你还需要可能消除一些属性的可能性。通常库提供了更多的功能，但至少让我们来看看如何删除一个属性，以查看对象中的其他重要结构变化。

```js
const deleteIn = (arr, obj) => {
 const newObj = Number.isInteger(arr[0]) ? [] : {};

 Object.keys(obj).forEach(k => {
 if (k !== arr[0]) {
 newObj[k] = obj[k];
 }
 });

 if (arr.length > 1) {
 newObj[arr[0]] = deleteIn(arr.slice(1), obj[arr[0]]);
 }
 return newObj;
};
```

这个逻辑类似于`setIn()`的逻辑。不同之处在于我们并不总是将所有属性从原始对象复制到新对象：只有在我们还没有到达路径属性数组的末尾时才这样做。在更新后继续测试系列之后，我们得到了以下结果：

```js
myObj4 = deleteIn(["d", "g"], myObj3);
myObj5 = deleteIn(["d", "j"], myObj4);

// {a: 111, b: 222, c: 333, d: {e: 444, f: 88888}};
```

有了这一对函数，我们可以管理持久对象的工作，以一种高效的方式进行更改、添加和删除，而不会不必要地创建新对象。

可能最著名的用于处理不可变对象的库是名为*immutable.js*的库，网址为[`facebook.github.io/immutable-js/`](https://facebook.github.io/immutable-js/)。唯一的弱点是其臭名昭著的晦涩文档。然而，对此有一个简单的解决方案：查看[`untangled.io/the-missing-immutable-js-manual/`](http://untangled.io/the-missing-immutable-js-manual/)上的*The Missing Immutable.js Manual With All The Examples You’ll Ever Need*，你就不会有任何麻烦了！

# 最后的警告

使用持久数据结构需要一些克隆，但你如何实现一个持久数组？如果你考虑一下，你会意识到，在这种情况下，除了在每次操作后克隆整个数组之外，没有其他办法。这意味着像更新数组中的元素这样的操作，它本来只需要基本恒定的时间，现在将需要与数组大小成比例的时间。

在算法复杂度方面，我们会说更新从 O(1)操作变为 O(n)操作。同样，访问一个元素可能会变成 O(log n)操作，其他操作也可能出现类似的减速，比如映射、减少等。

我们如何避免这种情况？没有简单的解决方案。例如，你可能会发现数组在内部被表示为二叉搜索树（甚至更复杂的数据结构），并且持久库提供了所需的接口，这样你仍然可以将其用作数组，而不会注意到内部的差异。

当使用这种类型的库时，具有不可变更新而无需克隆的优势可能部分地被一些操作所抵消，这些操作可能变得更慢。如果这成为应用程序的瓶颈，甚至可能需要改变实现不可变性的方式，甚至想出一些改变基本数据结构的方法来避免时间损失，或者至少将其最小化。

# 问题

10.1\. **通过代理进行冻结**。在第八章的*链接函数 - 管道和组合*部分，我们使用代理来获取操作，以便提供自动链接。通过使用代理进行*设置*和*删除*操作，您可以自行进行*冻结*（如果您不想设置对象的属性，而是宁愿抛出异常）。实现一个`freezeByProxy(obj)`函数，将这个想法应用到禁止所有类型的更新（添加、修改或删除属性）的对象上。记得要递归地工作，以防一个对象具有其他对象作为属性！

10.2\. **持久地插入到列表中**。在*使用列表*部分，我们描述了一种算法如何以持久的方式向列表中添加一个新节点，通过创建一个新的列表，就像我们之前描述的那样。实现一个`insertAfter(list, newKey, oldKey)`函数，它将创建一个新的列表，但在具有键`oldKey`的节点之后添加一个具有键`newKey`的新节点。您可以假设列表的节点是通过以下逻辑创建的：

```js
class Node {
 constructor(key, next = null) {
 this.key = key;
 this.next = next;
 }
}

const node = (key, next) => new Node(key, next);

let c3 = node("G", node("B", node("F", node("A", node("C", node("E"))))));

```

# 总结

在本章中，我们已经看到了两种不同的方法（实际上是常见的不可变性库使用的方法），通过使用不可变对象和数据结构来避免副作用：一种是基于使用 JavaScript 的*对象冻结*加上一些特殊逻辑来克隆，另一种是应用持久数据结构的概念，其中的方法允许进行各种更新，而不会改变原始对象或需要完全克隆。

在第十一章*实现设计模式 - 函数式方法*中，我们将专注于面向对象程序员经常问的一个问题：设计模式在 FP 中如何使用？它们是否必需、可用或可用？它们是否仍然被实践，但关注点转移到了函数而不是对象？我们将通过几个示例来回答这些问题，展示它们在哪里以及如何它们与通常的 OOP 实践相等或不同。


# 第十一章：实现设计模式-函数式方法

在[第十章]（383f5538-72cc-420a-ae77-896776c03f27.xhtml）中，我们看到了几种解决不同问题的函数式技术。然而，习惯于使用 OOP 的程序员可能会发现我们错过了一些众所周知的公式和解决方案，这些公式和解决方案在命令式编码中经常使用。由于设计模式是众所周知的，并且程序员可能已经了解它们在其他语言中的应用，因此重要的是看看如何进行函数实现。

在本章中，我们将考虑设计模式所暗示的解决方案，这些解决方案在面向对象编程中很常见，以便看到它们在 FP 中的等价物。特别是，我们将研究以下主题：

+   设计模式的概念及其适用范围

+   一些 OOP 标准模式以及在 FP 中我们有什么替代方案，如果需要的话。

+   与面向对象设计模式无关的 FP 设计模式讨论

# 什么是设计模式？

软件工程中最重要的书籍之一是《设计模式：可复用面向对象软件的元素》，1994 年，由 GoF（四人帮）：Erich Gamma，Richard Helm，Ralph Johnson 和 John Vlissides 编写。这本书介绍了大约两打不同的 OOP 模式，并被认为是计算机科学中非常重要的书籍。

*模式*实际上是建筑设计的概念，最初由建筑师克里斯托弗·亚历山大定义。

在软件术语中，*设计模式*是软件设计中通常出现的常见问题的一般适用的可重用解决方案。它不是特定的、完成的和编码的设计，而是一个可以解决许多情境中出现的给定问题的解决方案的描述（也使用了“模板”这个词）。鉴于它们的优势，设计模式本身是开发人员在不同类型的系统、编程语言和环境中使用的*最佳实践*。

这本书显然侧重于 OOP，并且其中的一些模式不能推荐或应用于 FP。其他模式是不必要的或无关的，因为 FP 语言已经为相应的 OOP 问题提供了标准解决方案。即使存在这种困难，由于大多数程序员已经接触过 OOP 设计模式，并且通常会尝试在其他上下文中（如 FP）应用它们，因此考虑原始问题，然后看看如何产生新的解决方案是有意义的。标准的基于对象的解决方案可能不适用，但问题仍然存在，因此看看如何解决它仍然是有效的。

通常用四个基本要素来描述模式：

1.  用于描述问题、解决方案及其后果的简单、简短的名称。这个名称对于与同事交流、解释设计决策或描述特定实现是有用的。

1.  模式适用的*上下文*：这意味着需要解决的特定情况，可能还需要满足一些额外条件。

1.  列出解决特定情况所需的元素（类、对象、函数、关系等）的解决方案

1.  如果应用模式，*后果*（结果和权衡）。您可能会从解决方案中获得一些收益，但它也可能意味着一些损失。

在本章中，我们将假设读者已经了解我们将描述和使用的设计模式，因此我们不会提供太多关于它们的细节。相反，我们将重点放在 FP 如何使问题变得无关（因为有一种明显的应用函数技术来解决它的方式）或以某种方式解决它。此外，我们不会涉及所有 GoF 模式；我们只会专注于那些应用 FP 更有趣的模式，从而带出与通常的 OOP 实现更多的差异。

# 设计模式类别

设计模式通常根据它们的焦点分为几个不同的类别。以下列表中的前三个是出现在原始 GoF 书中的模式，但还添加了更多的类别：

+   行为设计模式：这些与对象之间的交互和通信有关。与其关注对象如何创建或构建，关键是如何连接它们，以便它们在执行复杂任务时可以合作，最好以提供众所周知的优势的方式，例如减少耦合或增强内聚性。

+   创建设计模式：它们处理以适合当前问题的方式创建对象的方法，可能引导在几种替代对象之间进行选择，以便程序可以根据可能在编译时或运行时已知的参数以不同的方式工作。

+   结构设计模式：它们涉及对象的组成，从许多个体部分形成更大的结构，并实现对象之间的关系。一些模式意味着继承或接口的实现，而其他模式使用不同的机制，都旨在能够在运行时动态地改变对象组合的方式。

+   并发模式：它们与处理多线程编程有关。尽管函数式编程通常非常适合这样做（例如，由于缺少赋值和副作用），但由于我们使用 JavaScript，这些模式对我们来说并不是很相关。

+   架构模式：它们更加高层次，比我们列出的先前模式具有更广泛的范围，并提供了软件架构问题的一般解决方案。目前，我们不考虑这些问题，所以我们也不会处理这些问题。

耦合和内聚性是在面向对象编程流行之前就已经使用的术语；它们可以追溯到 60 年代末，当时 Larry Constantine 的《结构化设计》出版。前者衡量任何两个模块之间的相互依赖性，后者与模块的所有组件真正属于一起的程度有关。低耦合和高内聚性是软件设计的良好目标，因为它们意味着相关的事物是靠在一起的，而不相关的事物是分开的。

沿着这些线路，你也可以将设计模式分类为“对象模式”（涉及对象之间的动态关系）和“类模式”（处理类和子类之间的关系，这些关系在编译时静态定义）。我们不会过多地担心这种分类，因为我们的观点更多地与行为和函数有关，而不是类和对象。

正如我们之前提到的，我们现在可以清楚地观察到这些类别是严重面向面向对象编程的，并且前三个直接提到了对象。然而，不失一般性，我们将超越定义，记住我们试图解决的问题，然后探讨函数式编程的类似解决方案，即使不是与面向对象编程完全等价，也会以类似的方式解决相同的问题。

# 我们需要设计模式吗？

有一个有趣的观点认为，设计模式只是需要修补编程语言的缺陷。理由是，如果你可以用一种语言以简单、平凡的方式解决问题，那么你可能根本不需要设计模式。

无论如何，对于面向对象的开发人员来说，真正理解为什么函数式编程可以解决一些问题而无需进一步的工具是很有趣的。在下一节中，我们将考虑几种众所周知的设计模式，并看看为什么我们不需要它们，或者我们如何可以轻松地实现它们。事实上，我们在文本中已经应用了几种模式，所以我们也会指出这些例子。

然而，我们不会试图将所有设计模式都表达或转换成 FP 术语。例如，*Singleton*模式基本上需要一个单一的全局对象，这与函数式编程者习惯的一切都有点相悖。鉴于我们对 FP 的方法（还记得第一章初步部分的 SFP，*Sorta Functional Programming*吗？），我们也不会介意，如果需要 Singleton，我们可能会考虑使用它，即使 FP 没有合适的等价物。

最后，必须说一下，一个人的观点可能会影响什么被认为是模式，什么不是。对一些人来说可能是模式，对其他人来说可能被认为是微不足道的细节。我们会发现一些这样的情况，因为 FP 让我们以简单的方式解决一些特定问题，我们在之前的章节中已经看到了一些例子。

# 面向对象的设计模式

在本节中，我们将介绍一些 GoF 设计模式，检查它们是否与 FP 相关，并学习如何实现它们。当然，有一些设计模式没有 FP 解决方案。例如，没有 Singleton 的等价物，这意味着全局访问对象的外来概念。此外，虽然你可能不再需要面向对象的特定模式，但开发人员仍会以这些术语思考。最后，既然我们不是*完全函数式*，如果面向对象的模式适用，为什么不使用呢？

# Façade 和 Adapter

在这两种模式中，让我们从*Façade*开始。这是为了解决为类或库的方法提供不同接口的问题。其想法是为系统提供一个新的接口，使其更易于使用。你可以说，Façade 提供了一个更好的*控制面板*来访问某些功能，为用户消除了困难。

Façade 还是 facade？原词是建筑术语，意思是*建筑物的正面*，来自法语。根据这个来源和ç的通常发音，它的发音大约是*fuh-sahd*。另一种拼写可能与键盘上国际字符的缺失有关，并提出了以下问题：你不应该把它读成*faKade*吗？你可以把这个问题看作是*celtic*的反面，*celtic*的发音是*Keltic*，用*k*音代替了*s*音。

我们要解决的主要问题是能够以更简单的方式使用外部代码（当然，如果是你的代码，你可以直接处理这些问题；我们必须假设你不能——或者不应该——尝试修改其他代码。例如，当你使用任何可在网上获得的库时，就会出现这种情况）。关键是实现一个自己的模块，提供更适合你需求的接口。你的代码将使用你的模块，而不会直接与原始代码交互。

假设你想要进行 Ajax 调用，你唯一的可能性是使用一些具有非常复杂接口的库。有了 ES8 的模块，你可以编写以下内容，使用一个想象中的复杂 Ajax 库：

```js
// simpleAjax.js

import * as hard from "hardajaxlibrary";
// *import the other library that does Ajax calls*
// *but in a hard, difficult way, requiring complex code*

const convertParamsToHardStyle = params => {
 // *do some internal things to convert params*
 // *into the way that the hard library requires*
};

const makeStandardUrl = url => {
 // *make sure the url is in the standard*
 // *way for the hard library*
};

const getUrl = (url, params, callback) => {
 const xhr = hard.createAnXmlHttpRequestObject();
 hard.initializeAjaxCall(xhr);
 const standardUrl = makeStandardUrl(url);
 hard.setUrl(xhr, standardUrl);
 const convertedParams = convertParamsToHardStyle(params);
 hard.setAdditionalParameters(params);
 hard.setCallback(callback);
 if (hard.everythingOk(xhr)) {
 hard.doAjaxCall(xhr);
 } else {
 throw new Error("ajax failure");
 }
};

const postUrl = (url, params, callback) => {
 // *some similarly complex code*
 // *to do a POST using the hard library*
};

export {getUrl, postUrl}; // *the only methods that will be seen*
```

现在，如果你需要进行`GET`或`POST`，而不是必须经历提供的复杂 Ajax 库的所有复杂性，你可以使用提供更简单工作方式的新 façade。开发人员只需`import {getUrl, postUrl} from "simpleAjax"`，然后可以以更合理的方式工作。

然而，为什么我们要展示这段代码，虽然有趣，但并没有显示任何特定的 FP 方面？关键是，至少在浏览器中完全实现模块之前，隐式的内部方法是使用 IIFE（*立即调用函数表达式*），就像我们在第三章的*立即调用*部分中看到的那样，通过*模块模式*的方式：

```js
const simpleAjax = (function() {
 const hard = require("hardajaxlibrary");

 const convertParamsToHardStyle = params => {
 // ...
 };

 const makeStandardUrl = url => {
 // ...
 };

 const getUrl = (url, params, callback) => {
 // ...
 };

 const postUrl = (url, params, callback) => {
 // ...
 };

 return {
 getUrl,
 postUrl
 };
})();
```

*揭示模块*名称的原因现在应该是显而易见的。由于 JS 中的作用域规则，`simpleAjax`的唯一可见属性将是`simpleAjax.getUrl`和`simpleAjax.postUrl`；使用 IIFE 让我们以安全的方式实现模块（因此也实现了外观），使实现细节成为私有的。

现在，*适配器*模式类似，因为它也意味着定义一个新接口。然而，虽然*外观*为旧代码定义了一个新接口，但当您需要为新代码实现旧接口时，就会使用适配器，以便匹配您已经拥有的内容。如果您正在使用模块，很明显，对于*外观*有效的解决方案在这里也同样有效，因此我们不必深入研究它。

# 装饰器或包装器

*装饰器*模式（也称为*包装器*）在您希望以动态方式向对象添加额外的职责或功能时非常有用。让我们考虑一个简单的例子，我们将用一些 React 代码来说明。 （如果您不了解这个框架，不要担心；这个例子很容易理解）。假设我们想在屏幕上显示一些元素，并且出于调试目的，我们想在对象周围显示一个红色的细边框。您该如何做？

如果您使用面向对象编程，您可能需要创建一个具有扩展功能的新子类。对于这个特定的例子，您可能只需提供一些属性，其名称为一些 CSS 类，该类将提供所需的样式，但让我们将注意力集中在面向对象上；使用 CSS 并不总是解决这个软件设计问题，因此我们需要一个更通用的解决方案。新的子类将*知道*如何显示自己的边框，并且每当您想要对象的边框可见时，您将使用这个子类。

有了我们对高阶函数的经验，我们可以用*包装*的方式以不同的方式解决这个问题；将原始函数包装在另一个函数中，该函数将提供额外的功能。

请注意，在第六章的*生成函数 - 高阶函数*部分中，我们已经看到了一些包装的示例。例如，在该部分中，我们看到了如何包装函数以生成可以记录其输入和输出、提供时间信息，甚至记忆调用以避免未来延迟的新版本。在这种情况下，为了多样性，我们将这个概念应用于*装饰*一个可视组件，但原则仍然是相同的。

让我们定义一个简单的 React 组件，`ListOfNames`，它可以显示一个标题和一个人员列表，对于后者，它将使用`FullNameDisplay`组件。这些元素的代码如下片段所示：

```js
class FullNameDisplay extends React.Component {
 render() {
 return (
 <div>
 First Name: <b>{this.props.first}</b>
 <br />
 Last Name: <b>{this.props.last}</b>
 </div>
 );
 }
}

class ListOfNames extends React.Component {
 render() {
 return (
 <div>
 <h1>
 {this.props.heading}
 </h1>
 <ul>
 {this.props.people.map(v =>
 <FullNameDisplay first={v.first} last={v.last} />
 )}
 </ul>
 </div>
 );
 }
}
```

`ListOfNames`组件使用映射来创建`FullNameDisplay`组件，以显示每个人的数据。我们应用程序的完整逻辑可能如下：

```js
import React from "react";
import ReactDOM from "react-dom";

class FullNameDisplay extends React.Component {
 // *...as above...*
}

class ListOfNames extends React.Component {
 // *...as above...*
}

const GANG_OF_FOUR = [
 {first: "Erich", last: "Gamma"},
 {first: "Richard", last: "Helm"},
 {first: "Ralph", last: "Johnson"},
 {first: "John", last: "Vlissides"}
];

ReactDOM.render(
    <ListOfNames heading="GoF" people={GANG_OF_FOUR} />,
 document.body
);
```

在现实生活中，您不会将每个组件的所有代码都放在同一个源代码文件中——您可能会有几个 CSS 文件。但是，对于我们的例子，将所有内容放在一个地方，并使用内联样式就足够了，所以请忍耐一下，并记住以下格言：*说话容易做到难*。

我们可以在[`codesandbox.io/`](https://codesandbox.io/)在线 React 沙箱中快速测试结果；如果您想要其他选项，请搜索*react online sandbox*。结果并不值得讨论，但我们现在对设计模式感兴趣，而不是 UI 设计；参考图 11.1：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/a42709b0-331b-4b4c-91d5-6311602b8b7b.png)图 11.1：我们组件的原始版本显示了一个（不值得一提）的名称列表

在 React 中，内联组件是用 JSX（内联 HTML 样式）编写的，实际上被编译为对象，稍后将其转换为 HTML 代码以进行显示。每当调用`render()`方法时，它都会返回一组对象结构。因此，如果我们编写一个函数，该函数将以组件作为参数，并返回新的 JSX，这将是一个包装对象。在我们的情况下，我们希望在所需的边框内包装原始组件：

```js
const makeVisible = component => {
 return (
        <div style={{border: "1px solid red"}}>
 {component}
        </div>
 );
};
```

如果您愿意，您可以使此函数知道它是在开发模式下执行还是在生产模式下执行；在后一种情况下，它将简单地返回原始组件参数，而不做任何更改，但现在让我们不要担心这个。

现在我们必须更改`ListOfNames`以使用包装组件：

```js
class ListOfNames extends React.Component {
 render() {
 return (
 <div>
 <h1>
 {this.props.title}
 </h1>
 <ul>
 {this.props.people.map(v =>
 makeVisible(
 <FullNameDisplay
 first={v.first}
 last={v.last}
 />
 )
 )}
 </ul>
 </div>
 );
 }
}
```

代码的装饰版本按预期工作：现在`ListOfNames`组件中的每个组件都包装在另一个组件中，该组件为它们添加所需的边框；请参阅图 11.2：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/745c6765-ee43-43b5-bc74-31bd45f70c3a.png)图 11.2：装饰的 ListOfNames 组件仍然没有太多可看的，但现在它显示了一个添加的边框

在早期的章节中，我们看到如何装饰一个函数，将其包装在另一个函数中，以便执行额外的代码并添加一些功能。现在，在这里，我们看到了如何应用相同风格的解决方案，以提供一个*高阶组件*（在 React 术语中称为）包装在额外的`<div>`中，以提供一些视觉上的独特细节。

如果您使用过 Redux 和*react-redux*包，您可能会注意到后者的`connect()`方法也是以相同方式的装饰器；它接收一个组件类，并返回一个新的、连接到存储的组件类，供您在表单中使用；有关更多详细信息，请参阅[`github.com/reactjs/react-redux`](https://github.com/reactjs/react-redux)。

# 策略、模板和命令

*策略*模式适用于您希望能够通过更改*执行其操作方式*的方式来更改类、方法或函数的能力，可能是以动态方式。例如，GPS 应用程序可能希望在两个地点之间找到一条路线，但如果人是步行、骑自行车或开车，就应用不同的策略。在这种情况下，可能需要最快或最短的路线。问题是相同的，但根据给定条件，必须应用不同的算法。

顺便说一下，这听起来很熟悉吗？如果是这样，那是因为我们已经遇到过类似的问题。当我们想以不同的方式对一组字符串进行排序时，在第三章中，*从函数开始 - 核心概念*，我们需要一种方法来指定如何应用排序，或者等效地，如何比较两个给定的字符串并确定哪个应该先进行。根据语言的不同，我们必须应用不同的比较方法进行排序。

在尝试 FP 解决方案之前，让我们考虑更多实现我们的路由功能的方法。您可以通过编写足够大的代码来实现，该代码将接收声明要使用哪种算法以及起点和终点的参数。有了这些参数，函数可以执行 switch 或类似的操作来应用正确的路径查找逻辑。代码大致等同于以下片段：

```js
function findRoute(byMeans, fromPoint, toPoint) {
    switch (byMeans) {
        case "foot":
            /* *find the shortest road
                for a walking person* */

        case "bicycle":
            /** find a route apt 
                for a cyclist* */

        case "car-fastest":
            /* *find the fastest route
                for a car driver* */

        case "car-shortest":
            /** find the shortest route
                for a car driver* */

        default:
            /** plot a straight line,
                or throw an error, 
                or whatever suits you * */
    }
}
```

这种解决方案确实不理想，您的函数实际上是许多不同其他函数的总和，这并不提供高度的内聚性。如果您的语言不支持 lambda 函数（例如，直到 2014 年 Java 8 推出之前，Java 就是这种情况），则此问题的 OO 解决方案需要定义实现您可能想要的不同策略的类，创建一个适当的对象，并将其传递。

在 JS 中使用 FP，实现策略是微不足道的，而不是使用`byMeans`这样的变量进行切换，您可以只是传递一个函数，该函数将实现所需的路径逻辑：

```js
function findRoute(routeAlgorithm, fromPoint, toPoint) {
 return routeAlgorithm(fromPoint, toPoint);
}
```

您仍然必须实现所有所需的策略（没有其他方法），并决定要传递给`findRoute()`的函数，但现在该函数独立于路由逻辑，如果您想要添加新的路由算法，您不会触及`findRoute()`。

如果考虑*模板*模式，不同之处在于策略允许您使用完全不同的方式来实现结果，而模板提供了一个总体算法（或*模板*），其中一些实现细节留给方法来指定。同样，您可以提供函数来实现策略模式；您也可以为模板模式提供函数。

最后，*命令*模式也受益于能够将函数作为参数传递。这种模式旨在将请求封装为对象，因此对于不同的请求，您有不同参数化的对象。鉴于我们可以简单地将函数作为参数传递给其他函数，因此不需要*封闭*对象。

我们还在《第三章》的*A React+Redux reducer*部分看到了这种模式的类似用法，*从函数开始 - 核心概念*。在那里，我们定义了一个表，其中每个条目都是在需要时调用的回调。我们可以直接说，命令模式只是作为回调工作的普通函数的面向对象替代。

# 其他模式

让我们通过简要介绍一些其他模式来结束本节，其中等价性可能不那么完美：

+   **柯里化和部分应用**（我们在第七章中看到，*转换函数 - 柯里化和部分应用*）：这可以被视为函数的*工厂*的近似等价物。给定一个通用函数，您可以通过固定一个或多个参数来生成专门的情况，这本质上就是工厂所做的事情，当然，这是关于函数而不是对象。

+   **声明性函数**（例如`map()`或`reduce()`）：它们可以被视为*Iterator*模式的应用。容器元素的遍历与容器本身解耦。您还可以为不同的对象提供不同的`map()`方法，因此可以遍历各种数据结构。

+   **持久数据结构**：如第十章中所述，*确保纯度 - 不可变性*，它们允许实现*Memento*模式。其核心思想是，给定一个对象，能够返回到先前的状态。正如我们所看到的，数据结构的每个更新版本都不会影响先前的版本，因此您可以轻松添加一个机制来提供任何先前的状态并*回滚*到它。

+   **责任链**模式：在这种模式中，可能存在可变数量的*请求处理器*，并且要处理的请求流可以使用`find()`来确定哪个是处理请求的处理器（所需的是接受请求的列表中的第一个），然后简单地执行所需的处理。

请记住开始时的警告：对于这些模式，与 FP 技术的匹配可能不像我们之前看到的那样完美，但是我们的目的是要表明有一些常见的 FP 模式可以应用，并且将产生与面向对象解决方案相同的结果，尽管具有不同的实现。

# 功能设计模式

在看过了几种面向对象设计模式之后，可能会认为说 FP 没有经过批准、官方或甚至远程普遍接受的类似模式列表是一种欺骗。然而，对于某些问题，存在标准的 FP 解决方案，这些解决方案本身可以被视为设计模式，并且我们已经在书中涵盖了大部分。

可能的模式清单有哪些候选者？让我们尝试准备一个--但请记住，这只是一个个人观点；另外，我承认我并不打算模仿通常的模式定义风格--我只会提到一个一般问题并提到 JS 中 FP 的解决方法，我也不会为这些模式力求取一个好听、简短、易记的名字：

+   **使用 filter/map/reduce 处理集合**：每当你需要处理数据集合时，使用声明式的高阶函数，如`filter()`、`map()`和`reduce()`，就像我们在第五章中看到的那样，*声明式编程 - 更好的风格*，是一种从问题中消除复杂性的方法（通常的*MapReduce* web 框架是这个概念的扩展，它允许在多个服务器之间进行分布式处理，即使实现和细节并不完全相同）。你不应该将循环和处理作为一个步骤来执行，而应该将问题看作一系列顺序应用的步骤，应用转换直到获得最终期望的结果。

JS 还包括*迭代器*，也就是通过集合的另一种循环方式。使用*迭代器*并不特别功能，但你可能想看看它们，因为它们可能能简化一些情况。在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols)了解更多。

+   **使用 thunks 进行惰性求值**：*惰性求值*的概念是在实际需要之前不进行任何计算。在一些编程语言中，这是内置的。然而，在 JS（以及大多数命令式语言）中，应用的是*急切求值*，也就是表达式在绑定到某个变量时立即求值（另一种说法是 JavaScript 是一种*严格的编程语言*，具有*严格的范式*，只有在所有参数都完全求值后才允许调用函数）。当你需要精确指定求值顺序时，这种求值是必需的，主要是因为这样的求值可能会产生副作用。在 FP 中，你可以通过传递一个可以执行而不是进行计算的 thunk（我们在第九章的*Trampolines and Thunks*部分中使用了 thunk，*设计函数 - 递归*）来延迟这种求值，这样每当实际值需要时，它将在那时计算，而不是更早。

你可能还想看看 JS 的*生成器*，这是另一种延迟求值的方式，尽管它与 FP 并没有特别的关系。在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Generator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Generator)了解更多关于*生成器*的信息。*生成器*和 promises 的组合被称为异步函数，这可能会引起你的兴趣；参考[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function)。

+   **不可变性的持久数据结构**。拥有不可变的数据结构，就像我们在第十章中看到的那样，*确保纯净 - 不可变性*，在使用某些框架时是强制性的，而且一般来说是推荐的，因为它有助于推理程序或调试程序。（在本章的早些地方，我们还提到了*备忘录*面向对象模式可以以这种方式实现）。每当你需要表示结构化数据时，使用持久数据结构的 FP 解决方案在许多方面都有帮助。

+   **用于检查和操作的包装值**：如果直接使用变量或数据结构，您可能会随意修改它们（可能违反任何限制），或者在使用它们之前可能需要进行许多检查（例如在尝试访问相应对象之前验证值不为空）。这种模式的想法是将一个值包装在对象或函数中，这样就不可能进行直接操作，并且可以以更加功能化的方式进行管理检查。我们将在第十二章中更多地提到这一点，*构建更好的容器-功能数据类型*。

正如我们所说，FP 的力量在于，与其拥有几十种标准设计模式（这仅仅是在 GoF 书中；如果您阅读其他文本，列表会变得更长！），还没有一个标准或公认的功能模式列表。

# 问题

11.1\. **装饰方法，未来的方式**。在第六章中，*生成函数-高阶函数*，我们编写了一个装饰器来为任何函数启用日志记录。目前，方法装饰器正在考虑纳入 JavaScript 的即将推出的版本中：请参阅[`tc39.github.io/proposal-decorators/`](https://tc39.github.io/proposal-decorators/)（草案 2 意味着该功能很可能会被纳入标准，尽管可能会有一些添加或小的更改）。研究草案，看看是什么让下一个代码运行。

一些问题：您是否认为需要`savedMethod`变量？为什么在分配新的`descriptor.value`时使用`function()`，而不是箭头函数？您能理解为什么要使用`.bind()`吗？`descriptor`是什么？

```js
const logging = (target, name, descriptor) => {
 const savedMethod = descriptor.value;
 descriptor.value = function(...args) {
 console.log(`entering ${name}: ${args}`);
 try {
 const valueToReturn = savedMethod.bind(this)(...args);
 console.log(`exiting ${name}: ${valueToReturn}`);
 return valueToReturn;
 } catch (thrownError) {
 console.log(`exiting ${name}: threw ${thrownError}`);
 throw thrownError;
 }
 };
 return descriptor;
};
```

一个工作示例如下：

```js
class SumThree {
 constructor(z) {
 this.z = z;
 }
    @logging
 sum(x, y) {
 return x + y + this.z;
 }
}

new SumThree(100).sum(20, 8);
// *entering sum: 20,8*
// *exiting sum: 128*
```

11.2.**使用 mixin 的装饰器**：回到第一章的*问题*部分，*成为功能性-几个问题*，我们看到类是一等对象。利用这一点，完成以下`addBar()`函数，它将向`Foo`类添加一些 mixin，以便代码将如所示运行。创建的`fooBar`对象应该有两个属性（`.fooValue`和`.barValue`）和两个方法（`.doSomething()`和`.doSomethingElse()`），它们只是显示一些文本和一个属性。

```js
class Foo {
 constructor(fooValue) {
 this.fooValue = fooValue;
 }
 doSomething() {
 console.log("something: foo... ", this.fooValue);
 }
}

var addBar = BaseClass =>
 /*
      *your code goes here*
 */
 ;

var fooBar = new (addBar(Foo))(22, 9);
fooBar.doSomething();   // *something: foo... 22*
fooBar.somethingElse(); // *something else: bar... 9* console.log(Object.keys(fooBar)); // [*"fooValue", "barValue"*]
```

您能否包括第三个 mixin，`addBazAndQux()`，以便`addBazAndQux(addBar(Foo))`会向`Foo`添加更多属性和方法？

# 总结

在本章中，我们已经从面向对象的思维方式和编码时使用的常规模式，过渡到了函数式编程风格，通过展示如何解决相同的基本问题，但比使用类和对象更容易。

在第十二章中，*构建更好的容器-功能数据类型*，我们将使用一系列功能编程概念，这将给您更多关于可以使用的工具的想法。我承诺这本书不会变得深奥理论，而更加实用，我们会尽量保持这种方式，即使其中一些概念可能看起来晦涩或遥远。


# 第十二章：构建更好的容器-函数式数据类型

在第十二章 *以函数式方式实现设计模式* 中，我们已经讨论了使用函数实现不同结果的许多方法，在本章中，我们将更深入地从函数式角度考虑数据类型。我们将考虑实际实现自己的数据类型的方法，其中包括几个功能，以帮助组合操作或确保纯度，因此您的 FP 编码实际上会变得更简单和更短。我们将涉及几个主题：

+   **从函数式角度看数据类型**，因为即使 JavaScript 不是一种类型化的语言，也需要更好地理解类型和函数

+   **容器**，包括*函子*和神秘的*单子*，以更好地结构化数据流

+   **函数作为结构**，我们将看到另一种使用函数表示数据类型的方式，其中还加入了不可变性

# 数据类型

即使 JavaScript 是一种动态语言，没有静态或显式的类型声明和控制，也不意味着您可以简单地忽略类型。即使语言不允许您指定变量或函数的类型，您仍然会--即使只是在脑海中--使用类型。现在让我们来看看如何指定类型的主题，这样我们至少会有一些优势：

+   即使您没有运行时数据类型检查，也有一些工具，比如 Facebook 的*flow*静态类型检查器或 Microsoft 的*TypeScript*语言，可以让您处理它

+   如果您计划从 JavaScript 转移到更多的函数式语言，比如*Elm*，这将有所帮助

+   它作为文档，让未来的开发人员了解他们必须传递给函数的参数的类型，以及它将返回的类型。例如，Ramda 库中的所有函数都是以这种方式记录的

+   这也将有助于后面的函数数据结构，在这一部分中，我们将研究一种处理结构的方法，某些方面类似于您在 Haskell 等完全函数语言中所做的事情。

如果您想了解我引用的工具，请访问[`flow.org/`](https://flow.org/)了解 flow，[`www.typescriptlang.org/`](https://www.typescriptlang.org/)了解 TypeScript，以及[`elm-lang.org/`](http://elm-lang.org/)了解 Elm。如果您直接想了解类型检查，相应的网页是[`flow.org/en/docs/types/functions/`](https://flow.org/en/docs/types/functions/)，[`www.typescriptlang.org/docs/handbook/functions.html`](https://www.typescriptlang.org/docs/handbook/functions.html)，以及[`flow.org/en/docs/types/functions/`](https://flow.org/en/docs/types/functions/)

每当您阅读或使用函数时，您将不得不思考类型，考虑对这个或那个变量或属性的可能操作等。有类型声明将有所帮助，因此我们现在将开始考虑如何定义最重要的函数类型及其参数和结果。

# 函数的签名

函数的参数和结果的规范由*签名*给出。类型签名基于一个名为 Hindley-Milner 的*类型系统*，它影响了几种（最好是函数式）语言，包括 Haskell，尽管符号已经从原始论文中改变。这个系统甚至可以推断出不直接给出的类型；诸如 TypeScript 或 Flow 的工具也可以做到这种推断，因此开发人员不需要指定*所有*类型。与其去进行干燥、正式的解释关于编写正确签名的规则，我们不如通过例子来工作。我们只需要知道：

1.  我们将把类型声明写成注释。

1.  函数名首先写出，然后是`::`，可以读作*是类型*或*具有类型*。

1.  可选的约束条件可能会跟在之后，使用双（*粗*）箭头`⇒`（或者如果你无法输入箭头，则使用基本 ASCII 风格的`=>`）。

1.  函数的输入类型在箭头后面，使用`→`（或者根据你的键盘使用`->`）。

1.  函数的结果类型最后出现。

请注意，除了这种普通的 JS 风格之外，Flow 和 TypeScript 都有自己的语法来指定类型签名。

现在我们可以开始一些例子：

```js
// firstToUpper :: String → String
const firstToUpper = s => s[0].toUpperCase() + s.substr(1).toLowerCase();

// Math.random :: () → Number
```

这些都是简单的情况——注意签名；我们这里不关心实际的函数。第一个函数接收一个字符串作为参数，并返回一个新的字符串。第二个函数不接收参数（空括号表明如此），并返回一个浮点数。箭头表示函数。因此，我们可以将第一个签名解读为`firstToUpper` *是一个接收字符串并返回字符串的类型的函数*，我们也可以类似地谈论受到诟病（在纯度方面）的`Math.random()`函数，唯一的区别是它不接收参数。

我们看到了零个或一个参数的函数：那么多个参数的函数呢？对此有两个答案。如果我们在严格的函数式风格中工作，我们总是会进行柯里化（正如我们在第七章中看到的，*转换函数 - 柯里化和部分应用*），因此所有函数都是一元的。另一个解决方案是将参数类型的列表括在括号中。我们可以这样看待以下两种方式：

```js
// sum3C :: Number → Number → Number → Number
const sum3C = curry((a, b, c) => a + b + c);

// sum3 :: (Number, Number, Number) → Number
const sum3 = (a, b, c) => a + b + c;
```

第一个签名也可以解读为：

```js
// sum3C :: Number → (Number → (Number → (Number)))
```

当你记得柯里化的概念时，这是正确的。当你提供函数的第一个参数后，你会得到一个新的函数，它也期望一个参数，并返回一个第三个函数，当给定一个参数时，将产生最终结果。我们不会使用括号，因为我们总是假设从右到左进行分组。

现在，对于接收函数作为参数的高阶函数呢？`map()`函数提出了一个问题：它可以处理任何类型的数组。此外，映射函数可以产生任何类型的结果。对于这些情况，我们可以指定*通用类型*，用小写字母表示：这些通用类型可以代表任何可能的类型。对于数组本身，我们使用方括号。因此，我们会有以下内容：

```js
// map :: [a] → (a → b) →  [b]
const map = curry((arr, fn) => arr.map(fn));
```

*a*和*b*代表相同类型是完全有效的，就像应用于数字数组的映射会产生另一个数字数组一样。关键是，原则上*a*和*b*可以代表不同的类型，这就是之前描述的内容。还要注意，如果我们不进行柯里化，签名将是`([a], (a → b)) → [b]`，显示一个接收两个参数（类型为*a*的元素数组和从类型*a*到类型*b*的映射函数）并产生类型为*b*的元素数组作为结果的函数。鉴于此，我们可以以类似的方式写出以下内容：

```js
// filter :: [a] → (a → Boolean) → [a]
const filter = curry((arr, fn) => arr.filter(fn));
```

还有一个大问题：`reduce()`的签名是什么？一定要仔细阅读，看看你能否弄清楚为什么它是这样写的。你可能更喜欢将签名的第二部分看作`((b, a) → b)`：

```js
// reduce :: [a] → (b → a → b) → b → b
const reduce = curry((arr, fn, acc) => arr.reduce(fn, acc));
```

最后，如果你定义的是一个方法而不是一个函数，你会使用一个类似`~>`的波浪箭头：

```js
// String.repeat :: String ⇝ Number → String
```

# 其他类型选项

我们还缺少什么？让我们看看你可能会使用的其他选项。*联合类型*被定义为可能值的列表。例如，我们在第六章中的`getField()`函数，*生成函数 - 高阶函数*，要么返回属性的值，要么返回 undefined。然后我们可以写出以下签名：

```js
// getField :: String → attr → a | undefined
const getField = attr => obj => obj[attr];
```

我们还可以定义一个类型（联合类型或其他类型），然后在进一步的定义中使用它。例如，可以直接比较和排序的数据类型是数字、字符串和布尔值，因此我们可以写出以下定义：

```js
// Sortable :: Number | String | Boolean
```

之后，我们可以指定比较函数可以根据可排序类型来定义...但要小心：这里存在一个隐藏的问题！

```js
// compareFunction :: (Sortable, Sortable) → Number
```

实际上，这个定义并不太准确，因为实际上你可以比较任何类型，即使这并没有太多意义。然而，为了例子的完整性，请暂时忍耐！如果你想要回顾一下排序和比较函数，请参阅[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/sort`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)。

最后的定义将允许编写一个函数，比如说，接收一个数字和一个布尔值：它并没有说这两种类型应该是相同的。然而，还是有办法的。如果对于某些数据类型有约束条件，你可以在实际签名之前表达它们，使用一个*胖*箭头：

```js
// compareFunction :: Sortable a ⇒ (a, a) → Number
```

现在定义是正确的，因为所有相同类型的出现（在这种情况下，用相同的字母表示，*a*）必须完全相同。另一种选择，但需要更多的输入，是使用联合写出所有可能性：

```js
// compareFunction :: 
// ((Number, Number) | (String, String) | (Boolean, Boolean)) → Number
```

到目前为止，我们一直在使用标准类型定义。但是，当我们使用 JavaScript 时，我们必须考虑一些其他可能性，比如带有可选参数的函数，甚至带有不确定数量的参数。我们可以使用`...`代表任意数量的参数，并添加`?`来表示可选类型：

```js
// unary :: ((b, ...) → a) → (b → a) 
const unary = fn => (...args) => fn(args[0]);
```

我们在之前引用的同一章节中定义的`unary()`高阶函数，它以任何函数作为参数，并返回一个一元函数作为其结果：我们可以表明原始函数可以接收任意数量的参数，但结果只使用第一个：

```js
// parseInt :: (String, Number?) -> Number
```

`parseInt()`函数提供了可选参数的示例：虽然强烈建议不要省略第二个参数（基数），但实际上可以跳过它。

查看[`github.com/fantasyland/fantasy-land/`](https://github.com/fantasyland/fantasy-land/)和[`sanctuary.js.org/#types`](https://sanctuary.js.org/#types)以获取更正式的类型定义和描述，应用于 JavaScript。

从现在开始，在本章中，我们将经常为方法和函数添加签名。这不仅是为了让你习惯于它们，而且当我们开始深入研究更复杂的容器时，它将有助于理解我们正在处理的内容：有些情况可能很难理解！

# 容器

回到第五章，*声明式编程-更好的风格*，以及稍后的第八章，*连接函数-管道和组合*，我们看到能够将映射应用于数组的所有元素，甚至更好的是，能够链接一系列类似的操作，是生成更好、更易理解的代码的好方法。

然而，存在一个问题：`.map()`方法（或等效的*解方法*，如第六章，*生成函数-高阶函数*）仅适用于数组，我们可能希望能够将映射和链接应用于其他数据类型。那么，我们该怎么办呢？

让我们考虑不同的做法，这将为我们提供更好的功能编码工具。基本上，解决这个问题只有两种可能的方法：我们可以为现有类型添加新的方法（尽管这将受到限制，因为我们只能将其应用于基本的 JS 类型），或者我们可以将类型包装在某种类型的容器中，这将允许映射和链接。

让我们首先扩展当前类型，然后转而使用包装器，这将使我们进入深层的功能领域，涉及到诸如函子和单子等实体。

# 扩展当前数据类型

如果我们想要将基本的 JS 数据类型添加映射，让我们首先考虑我们的选择：

+   对于`null`、`undefined`和`Symbol`，应用映射听起来并不太有趣

+   对于`Boolean`、`Number`和`String`数据类型，我们有一些有趣的可能性，因此我们可以检查其中一些

+   将映射应用于对象将是微不足道的：你只需要添加一个`.map()`方法，它必须返回一个新对象

+   最后，尽管不是基本数据类型，我们也可以考虑特殊情况，比如日期或函数，我们也可以添加`.map()`方法

与本书的其余部分一样，我们坚持使用纯 JS，但是你应该查看诸如 LoDash、Underscore 或 Ramda 之类的库，它们已经提供了我们在这里开发的功能。

在所有这些映射操作中，一个关键点应该是返回的值与原始值的类型完全相同：当我们使用`Array.map()`时，结果也是一个数组，任何其他`.map()`实现都必须遵循类似的考虑（你可以观察到生成的数组可能具有不同的元素类型，但它仍然是一个数组）。

我们能对布尔值做什么？首先，让我们接受布尔值不是容器，因此它们的行为方式与数组不同：显然，布尔值只能有一个布尔值，而数组可以包含任何类型的元素。然而，接受这种差异，我们可以扩展`Boolean.prototype`（尽管，正如我已经提到的，这通常是不推荐的），通过向其添加一个新的`.map()`方法，并确保映射函数返回的任何内容都转换为新的布尔值。对于后者，解决方案将是类似的：

```js
// Boolean.map :: Boolean ⇝ (Boolean → a) → Boolean
Boolean.prototype.map = function(fn) {
 return !!fn(this);
};
```

`!!`运算符强制结果为布尔值：`Boolean(fn(this))`也可以使用。这种解决方案也可以应用于数字和字符串：

```js
// Number.map :: Number ⇝ (Number → a) → Number
Number.prototype.map = function(fn) {
 return Number(fn(this));
};

// String.map :: String ⇝ (String → a) → String
**String.prototype.map** = function(fn) {
 return **String(fn(this))**;
}; 
```

与布尔值一样，我们强制映射操作的结果为正确的数据类型。

最后，如果我们想将映射应用到一个函数，那意味着什么？映射一个函数应该产生一个函数。`f.map(g)`的逻辑解释应该是首先应用`f()`，然后将`g()`应用于结果。因此，`f.map(g)`应该与编写`x => g(f(x))`或等效地`pipe(f,g)`是相同的：

```js
// Function.map :: (a → b) ⇝ (b → c) → (a → c)
Function.prototype.map = function(fn) {
 return (...args) => fn(this(...args));
};
```

验证这是否有效很简单：

```js
const plus1 = x => x + 1;
const by10 = y => 10 * y;

console.log(plus1.map(by10)(3));
// 40: first add 1 to 3, then multiply by 10
```

有了这个，我们对基本的 JS 类型可以做的事情就完成了——但是如果我们想将这个应用到其他数据类型，我们需要一个更通用的解决方案。我们希望能够将映射应用到任何类型的值上，为此，我们需要创建一些容器；让我们来做这个。

# 容器和函子

我们在上一节中所做的确实有效，并且可以无问题地使用。然而，我们希望考虑一个更通用的解决方案，可以应用于任何数据类型。由于 JS 中并非所有东西都提供所需的`.map()`方法，我们将不得不扩展类型（就像我们在上一节中所做的那样），或者应用我们在第十一章中考虑过的设计模式，*实现设计模式-函数式方法*：用一个包装器包装我们的数据类型，该包装器将提供所需的`map()`操作。

# 包装一个值：一个基本的容器

让我们暂停一下，考虑一下我们需要这个包装器。有两个基本要求：

+   我们必须有一个`.map()`方法

+   我们需要一种简单的方法来包装一个值

让我们创建一个基本的容器来开始——但我们需要做一些改变：

```js
const VALUE = Symbol("Value");

class Container {
 constructor(x) {
 this[VALUE] = x;
 }

 map(fn) {
 return fn(this[VALUE]);
 }
}
```

一些基本的考虑：

+   我们希望能够将一些值存储在容器中，因此构造函数会处理这个问题

+   使用`Symbol`有助于*隐藏*字段：属性键不会显示在`Object.keys()`中，也不会显示在`for...in`或`for...of`循环中，使它们更加*不易干涉*

+   我们需要能够`.map()`，因此提供了一个方法

我们的基本容器已经准备好了，但是我们可以为方便起见添加一些其他方法：

+   为了获取容器的值，我们可以使用`.map(x => x)`，但这对于更复杂的容器不起作用，所以让我们添加一个`.valueOf()`方法来获取包含的值

+   能够列出一个容器肯定有助于调试：`.toString()`方法会派上用场

+   因为我们不需要一直写`new Container()`，我们可以添加一个静态的`.of()`方法来完成相同的工作。

当在函数式编程世界中使用类来表示容器（以及后来的函子和单子）可能看起来像异端邪说或罪恶...但请记住我们不想教条主义，`class`和`extends`简化了我们的编码。同样，可以说你绝不能从容器中取出一个值--但是使用`.valueOf()`有时太方便了，所以不会那么严格。我们的容器变成了这样：

```js
class Container {
 // 
 // *everything as above*
 //

    static of(x) {
 return new Container(x);
 }

    toString() {
 return `${this.constructor.name}(${this[VALUE]})`;
 }

    valueOf() {
 return this[VALUE];
 }
}
```

现在，我们可以使用这个容器来存储一个值，并且我们可以使用`.map()`来对该值应用任何函数...但这与我们可以用变量做的事情并没有太大的不同！让我们再加强一点。

# 增强我们的容器：函子

我们想要包装值，那么`map()`方法到底应该返回什么？如果我们想要能够链接操作，那么唯一合乎逻辑的答案是它应该返回一个新的包装对象。在真正的函数式风格中，当我们对包装值应用映射时，结果将是另一个包装值，我们可以继续使用它。

这个操作有时被称为`fmap()`，代表函子映射，而不是`.map()`。更改名称的原因是为了避免扩展`.map()`的含义。但是，由于我们正在使用支持重用名称的语言，我们可以保留它。

我们可以扩展我们的`Container`类来实现这个改变。`.of()`方法将需要一个小改变：

```js
class Functor extends Container {
 static of(x) {
 return new Functor(x);
 }

 map(fn) {
 return Functor.of(fn(this[VALUE]));
 }
}
```

有了这些属性，我们刚刚定义了范畴论中所谓的*函子*！（或者，如果你想变得更加技术化，是*指向函子*，因为有`.of()`方法--但让我们保持简单）。我们不会深入理论细节，但粗略地说，函子只是一种允许对其内容应用`.map()`的容器，产生相同类型的新容器...如果这听起来很熟悉，那是因为你已经知道一个函子：数组！当你对数组应用`.map()`时，结果是一个新数组，包含转换（映射）后的值。

函子还有更多要求。首先，包含的值可能是多态的（任何类型），就像数组一样。其次，必须存在一个函数，其映射产生相同的包含值--`x => x`就是这个工作。最后，连续应用两个映射必须产生与应用它们的组合相同的结果：`container.map(f).map(g)`必须与`container.map(compose(g,f))`相同。

让我们暂停一下来考虑我们函数和方法的签名：

```js
of :: Functor f ⇒ a → f a 
Functor.toString :: Functor f ⇒ f a ⇝ String
Functor.valueOf :: Functor f ⇒ f a ⇝ a
Functor.map :: Functor f ⇒ f a ⇝ (a → b) → f a → f b
```

第一个函数`of()`是最简单的：给定任何类型的值，它产生该类型的函子。接下来的两个也很容易理解：给定一个函子，`toString()`总是返回一个字符串（毫无意外！），如果函子包含的值是某种给定类型，`valueOf()`产生相同类型的结果。第三个`map()`更有趣。给定一个接受类型为*a*的参数并产生类型为*b*的结果的函数，将其应用于包含类型为*a*的值的函子，产生包含类型为*b*的值的函子--这正是我们上面描述的。

目前，函子不允许或期望产生副作用、抛出异常或任何其他行为，除了产生一个包含的结果。它们的主要用途是提供一种操作值、对其应用操作、组合结果等的方式，而不改变原始值--在这个意义上，我们再次回到了不可变性。

你也可以将函子与承诺进行比较，至少在一个方面是如此。在函子中，你不直接作用于其值，而是使用`.map()`应用函数——在承诺中，你也是这样做的，但是使用`.then()`！事实上，还有更多的类比，我们很快就会看到。

然而，你可能会说这还不够，因为在正常的编程中，必须处理异常、未定义或空值等情况是非常常见的。因此，让我们开始看更多的函子示例，过一段时间，我们将进入单子的领域，进行更复杂的处理。所以，现在让我们进行一些实验！

# 使用 Maybe 处理丢失的值

编程中的一个常见问题是处理丢失的值。造成这种情况的可能原因有很多：Web 服务 Ajax 调用可能返回空结果，数据集可能为空，或者对象中可能缺少可选属性，等等。在正常的命令式方式中处理这种情况需要在各处添加`if`语句或三元运算符，以捕获可能丢失的值，避免某种运行时错误。通过实现一个`Maybe`函子，我们可以做得更好，以表示可能存在（或可能*不存在*）的值！我们将使用两个类，`Just`（表示*刚好有些值*）和`Nothing`，每个函子一个：

```js
class Nothing extends Functor {
 isNothing() {
 return true;
 }

 toString() {
 return "Nothing()";
 }

    map(fn) {
        return this;
 }
}

class Just extends Functor {
 isNothing() {
 return false;
 }

    map(fn) {
        return Maybe.of(fn(this[VALUE]));
 }
}

class Maybe extends Functor {
    constructor(x) {
        return x === undefined || x === null
 ? new Nothing()
 : new Just(x);
 }

 static of(x) {
 return new Maybe(x);
 }
}
```

我们可以通过尝试将操作应用于有效值或丢失的值来快速验证这一点：

```js
const plus1 = x => x + 1;

Maybe.of(2209).map(plus1).map(plus1).toString(); // *"Just(2211)"*
Maybe.of(null).map(plus1).map(plus1).toString(); // *"Nothing()"*
```

我们刚刚对`Maybe.of(null)`值多次应用了`plus1()`，完全没有错误。`MayBe`函子可以处理映射丢失的值，只需跳过操作，并返回一个包装的`null`值。这意味着这个函子基本上包括了一个抽象的检查，不会让错误发生。让我们举一个更现实的例子来说明它的用法。

在本章后面，我们将看到 Maybe 实际上可以是一个单子，而不是一个函子，并且我们还将研究更多的单子示例。

假设我们正在 Node 中编写一个小的服务器端服务，并且我们想要获取某个城市的警报，并生成一个不太时尚的 HTML `<table>`，假设它是某个服务器端生成的网页的一部分（是的，我知道你应该尽量避免在你的页面中使用表格，但我在这里想要的是一个 HTML 生成的简短示例，实际结果并不重要）。如果我们使用*Dark Sky* API（请参阅[`darksky.net/`](https://darksky.net/)了解更多关于此 API 的信息，并注册使用），来获取警报，我们的代码将是这样的；都很正常...请注意错误的回调；你将在下面的代码中看到原因：

```js
const request = require("superagent");

const getAlerts = (lat, long, callback) => {
 const SERVER = "https://api.darksky.net/forecast";
 const UNITS = "units=si";
 const EXCLUSIONS = "exclude=minutely,hourly,daily,flags";
 const API_KEY = "*you.need.to.get.your.own.api.key*";

 request
 .get(`${SERVER}/${API_KEY}/${lat},${long}?${UNITS}&${EXCLUSIONS}`)
 .end(function(err, res) {
 if (err) {
                callback({});
 } else {
                callback(JSON.parse(res.text));
 }
 });
};
```

这样调用的输出（经过大幅编辑和缩小）可能是这样的：

```js
{
 latitude: 29.76,
 longitude: -95.37,
 timezone: "America/Chicago",
 offset: -5,
 currently: {
 time: 1503660334,
 summary: "Drizzle",
 icon: "rain",
 temperature: 24.97,
 ...
 uvIndex: 0
 },
 alerts: [
 {
 title: "Tropical Storm Warning",
 regions: ["Harris"],
 severity: "warning",
 time: 1503653400,
 expires: 1503682200,
 description:
 "TROPICAL STORM WARNING REMAINS IN EFFECT... WIND - LATEST LOCAL FORECAST: Below tropical storm force wind ... CURRENT THREAT TO LIFE AND PROPERTY: Moderate ... Locations could realize roofs peeled off buildings, chimneys toppled, mobile homes pushed off foundations or overturned ...",
 uri:
 "https://alerts.weather.gov/cap/wwacapget.php?x=TX125862DD4F88.TropicalStormWarning.125862DE8808TX.HGXTCVHGX.73ee697556fc6f3af7649812391a38b3"
 },
 ...
 {
 title: "Hurricane Local Statement",
 regions: ["Austin",...,"Wharton"],
 severity: "advisory",
 time: 1503748800,
 expires: 1503683100,
 description:
 "This product covers Southeast Texas **HURRICANE HARVEY DANGEROUSLY APPROACHING THE TEXAS COAST** ... The next local statement will be issued by the National Weather Service in Houston/Galveston TX around 1030 AM CDT, or sooner if conditions warrant.\n",
 uri:
 "https://alerts.weather.gov/cap/wwacapget.php?..."
 }
 ]
};
```

我在飓风哈维逼近德克萨斯州的那一天获取了这些信息。如果你在正常的一天调用 API，数据将完全排除`alerts:[...]`部分。因此，我们可以使用`Maybe`函子来处理接收到的数据，无论是否有警报，都不会出现任何问题：

```js
const getField = attr => obj => obj[attr];
const os = require("os");

const produceAlertsTable = weatherObj =>
    Maybe.of(weatherObj)
 .map(getField("alerts"))
 .map(a =>
 a.map(
 x =>
 `<tr><td>${x.title}</td>` +
 `<td>${x.description.substr(0, 500)}...</td></tr>`
 )
 )
 .map(a => a.join(os.EOL))
 .map(s => `<table>${s}</table>`)

getAlerts(29.76, -95.37, x =>
    console.log(produceAlertsTable(x).valueOf())
);
```

当然，你可能会做一些比仅仅记录`produceAlertsTable()`的结果更有趣的事情！最有可能的选择是再次使用`.map()`，使用一个输出表格的函数，将其发送给客户端，或者你需要做的任何其他事情。无论如何，最终的输出将与以下内容匹配：

```js
**<table><tr><td>**Tropical Storm Warning**</td><td>**...TROPICAL STORM WARNING REMAINS IN EFFECT... ...STORM SURGE WATCH REMAINS IN EFFECT... * WIND - LATEST LOCAL FORECAST: Below tropical storm force wind - Peak Wind Forecast: 25-35 mph with gusts to 45 mph - CURRENT THREAT TO LIFE AND PROPERTY: Moderate - The wind threat has remained nearly steady from the previous assessment. - Emergency plans should include a reasonable threat for strong tropical storm force wind of 58 to 73 mph. - To be safe, earnestly prepare for the potential of significant...**</td></tr>** 
**<tr><td>**Flash Flood Watch**</td><td>**...FLASH FLOOD WATCH REMAINS IN EFFECT THROUGH MONDAY MORNING... The Flash Flood Watch continues for * Portions of Southeast Texas...including the following counties...Austin...Brazoria...Brazos...Burleson... Chambers...Colorado...Fort Bend...Galveston...Grimes... Harris...Jackson...Liberty...Matagorda...Montgomery...Waller... Washington and Wharton. * Through Monday morning * Rainfall from Harvey will cause devastating and life threatening flooding as a prolonged heavy rain and flash flood thre...**</td></tr>** 
**<tr><td>**Hurricane Local Statement**</td><td>**This product covers Southeast Texas **PREPARATIONS FOR HARVEY SHOULD BE RUSHED TO COMPLETION THIS MORNING** NEW INFORMATION --------------- * CHANGES TO WATCHES AND WARNINGS: - None * CURRENT WATCHES AND WARNINGS: - A Tropical Storm Warning and Storm Surge Watch are in effect for Chambers and Harris - A Tropical Storm Warning is in effect for Austin, Colorado, Fort Bend, Liberty, Waller, and Wharton - A Storm Surge Warning and Hurricane Warning are in effect for Jackson and Matagorda - A Storm S...**</td></tr></table>** 
```

如果我们改为使用乌拉圭蒙得维的坐标调用`getAlerts(-34.9, -54.60, ...)`，因为该城市没有警报，`getField("alerts")`函数将返回`undefined`——尽管所有后续的`.map()`操作仍将被执行，但实际上没有任何操作，最终结果将是`null`值。见图 12.1：

图 12.1。输出表格看起来并不起眼，但产生它的逻辑并不需要一个 if 语句。

我们在编写错误逻辑时也利用了这种行为。如果在调用服务时发生错误，我们仍然会调用原始回调来生成一个表，但提供一个空对象。即使这个结果是意外的，我们也会很安全，因为相同的保护措施会避免导致运行时错误。

作为最后的增强，我们可以添加一个`.orElse()`方法，在没有值的情况下提供一个默认值：

```js
class Maybe extends Functor {
 //
 // *everything as before...*
 //
    orElse(v) {
 return this.isNothing() ? v : this.valueOf();
 }
}
```

使用这种新方法而不是`valueOf()`，如果尝试为某个地方获取警报，而那里没有警报，你将得到任何你想要的默认值。在我们之前引用的情况下，当尝试获取蒙得维的亚的警报时，我们现在将得到一个合适的结果，而不是一个`null`值：

```js
getAlerts(-34.9, -54.6, x =>
 console.log(
 produceAlertsTable(x).orElse("<span>No alerts today.</span>")
 )
);
```

以这种方式工作，我们可以简化我们的编码，并避免对空值和其他类似情况进行许多测试。然而，我们可能想要超越这一点；例如，我们可能想知道*为什么*没有警报：是服务错误吗？还是正常情况？最后只得到一个`null`是不够的，为了满足这些新的要求，我们需要向我们的函子添加一些东西，并进入*单子*的领域。

# 单子

*单子*在程序员中有着奇怪的名声。著名的开发者道格拉斯·克罗克福德曾经谈到过*它们*的“诅咒”，他认为*一旦你终于理解了单子，你立刻就失去了向其他人解释它们的能力！*另一方面，如果你决定回到基础，阅读一本像是*工作数学家的范畴*这样的书，作者是范畴论的创始人之一桑德斯·麦克莱恩，你可能会发现一个有些令人困惑的解释：*X 中的单子只是 X 的自函子范畴中的幺半群，乘积* × *被自函子的组合所取代，单位集由恒等自函子取代。*并不是太有启发性！

单子和函子之间的区别只是前者增加了一些额外的功能。让我们先看看新的要求，然后再考虑一些常见的有用的单子。与函子一样，我们将有一个基本的单子，你可以将其视为*抽象*版本，并且具体的*单子类型*，它们是*具体*的实现，旨在解决特定情况。

如果你想阅读关于函子、单子以及它们所有家族的精确和仔细的描述（但更倾向于理论方面，并且有大量的代数定义），你可以尝试一下 Fantasy Land 规范，网址是[`github.com/fantasyland/fantasy-land/`](https://github.com/fantasyland/fantasy-land/)。不要说我们没有警告过你：该页面的另一个名称是*代数 JavaScript 规范*！

# 添加操作

让我们考虑一个简单的问题。假设你有以下一对函数，它们使用`Maybe`函子工作：第一个函数尝试根据其键搜索*某些东西*（比如客户或产品，无论是什么），第二个函数尝试从中提取*某些*属性（我故意含糊其辞，因为问题与我们可能正在处理的任何对象或事物无关）。这两个函数产生`Maybe`结果，以避免可能的错误。我们使用了一个模拟的搜索函数，只是为了帮助我们看到问题：对于偶数键，它返回虚假数据，对于奇数键，它会抛出异常。

```js
const fakeSearchForSomething = key => {
 if (key % 2 === 0) {
 return {key, some: "whatever", other: "more data"};
 } else {
 throw new Error("Not found");
 }
};

const findSomething = key => {
 try {
 const something = fakeSearchForSomething(key);
 return Maybe.of(something);
 } catch (e) {
 return Maybe.of(null);
 }
};

const getSome = something => Maybe.of(something.map(getField("some")));

const getSomeFromSomething = key => getSome(findSomething(key));
```

问题在哪里？问题在于`getSome()`的输出是一个`Maybe`值，它本身包含一个`Maybe`值，所以我们想要的结果被双重包装了。

```js
let xxx = getSomeFromSomething(2222).valueOf().valueOf(); // *"whatever"*
let yyy = getSomeFromSomething(9999).valueOf().valueOf(); // *null*
```

这个玩具问题中可以很容易地解决这个问题（只需在`getSome()`中避免使用`Maybe.of()`），但这种结果可能以更复杂的方式发生。例如，您可能正在构建一个`Maybe`，其中一个属性恰好是一个`Maybe`，如果在访问该属性时出现相同的情况：您最终会得到一些双重包装的值。

单子应该提供以下操作：

+   一个构造函数。

+   一个将值插入单子的函数：我们的`.of()`方法。

+   允许链接操作的函数：我们的`.map()`方法。

+   可以去除额外包装的函数：我们将其称为`.unwrap()`，它将解决我们之前的多重包装问题。有时它被称为`.flatten()`。

我们还将有一个用于链接调用的函数，只是为了简化我们的编码，还有另一个用于应用函数的函数，但我们稍后再说。让我们看看实际的 JavaScript 代码中单子是什么样子的。数据类型规范非常类似于函子的规范，所以我们不会在这里重复它们：

```js
class Monad extends Functor {
 static of(x) {
 return new Monad(x);
 }

 map(fn) {
 return Monad.of(fn(this[VALUE]));
 }

    unwrap() {
 const myValue = this[VALUE];
 return myValue instanceof Container ? myValue.unwrap() : this;
 }
}
```

我们使用递归来逐步去除包装，直到包装的值不再是一个容器。使用这种方法，我们可以轻松地避免双重包装：

```js
const getSomeFromSomething = key => getSome(findSomething(key)).unwrap();
```

然而，这种问题可能会在不同的层面上重复出现。例如，如果我们正在进行一系列`.map()`操作，任何中间结果都可能最终被双重包装。您可以很容易地通过记住在每个`.map()`之后调用`.unwrap()`来解决这个问题--请注意，即使实际上并不需要，您也可以这样做，因为在这种情况下，`.unwrap()`的结果将是完全相同的对象（你能看出为什么吗？）。但我们可以做得更好！让我们定义一个`.chain()`操作，它将为我们执行这两个操作（有时`.chain()`被称为`.flatMap()`）：

```js
class Monad extends Functor {
 //
 // *everything as before...*
 //
    chain(fn) {
 return this.map(fn).unwrap();
 }
}
```

只剩下一个操作。假设您有一个柯里化的函数，有两个参数；没有什么奇怪的！如果您将该函数提供给`.map()`操作，会发生什么？

```js
const add = x => y => x+y; // *or* curry((x,y) => x+y)
const something = **Monad.of(2).map(add)**;
```

某物会是什么？鉴于我们只提供了一个参数来添加，该应用的结果将是一个函数...不仅仅是任何函数，而是一个*包装*的函数！（由于函数是一级对象，逻辑上没有障碍将函数包装在单子中，对吧？）我们想对这样的函数做什么？为了能够将这个包装的函数应用到一个值上，我们需要一个新的方法：`.ap()`。这个值可能是什么？在这种情况下，它可以是一个普通的数字，或者是由其他操作的结果作为单子包装的数字。由于我们总是可以将一个普通数字`Map.of()`成一个包装数字，让我们让`.ap()`使用一个单子作为它的参数：

```js
class Monad extends Functor {
 //
 // *everything as earlier...*
 //
    ap(m) {
 return m.map(this.valueOf());
 }
}
```

有了这个，你就可以这样做：

```js
const monad5 = something.ap(Monad.of(3)); // Monad(5)
```

现在，您可以使用单子来保存值或函数，并根据需要与其他单子和链接操作进行交互。因此，正如您所看到的，单子并没有什么大技巧，它们只是带有一些额外方法的函子。现在让我们看看如何将它们应用到我们的原始问题中，并以更好的方式处理错误。

# 处理替代方案 - Either 单子

知道一个值是否丢失在某些情况下可能足够了，但在其他情况下，您可能希望能够提供一个解释。如果我们使用一个不同的函子，它将接受两个可能的值，一个与问题、错误或失败相关联，另一个与正常执行或成功相关联，我们可以得到这样的解释：

+   一个*左*值，应该是 null，但如果存在，它代表某种特殊值（例如，错误消息或抛出的异常），它不能被映射

+   一个*正确*的值，它代表了函子的*正常*值，并且可以被映射

我们可以以与我们为`Maybe`所做的类似的方式构造这个 monad（实际上，添加的操作使得`Maybe`也可以扩展`Monad`）。构造函数将接收左值和右值：如果左值存在，它将成为`Either` monad 的值；否则将使用右值。由于我们为所有的 functors 提供了`.of()`方法，我们也需要为`Either`提供一个：

```js
class Left extends Monad {
    isLeft() {
 return true;
 }

    map(fn) {
        return this;
 }
}

class Right extends Monad {
    isLeft() {
 return false;
 }

    map(fn) {
        return Either.of(null, fn(this[VALUE]));
 }
}

class Either extends Monad {
    constructor(left, right) {
 return right === undefined || right === null
 ? new Left(left)
 : new Right(right);
 }

 static of(left, right) {
 return new Either(left, right);
 }
}
```

`.map()`方法是关键。如果这个 functor 有一个*left*值，它将不会被进一步处理；在其他情况下，映射将被应用于*right*值，并且结果将被包装。现在，我们如何用这个来增强我们的代码呢？关键的想法是每个涉及的方法都返回一个`Either` monad；`.chain()`将被用来依次执行操作。获取警报将是第一步--我们调用回调，要么得到`AJAX FAILURE`消息，要么得到 API 调用的结果：

```js
const getAlerts2 = (lat, long, callback) => {
 const SERVER = "https://api.darksky.net/forecast";
 const UNITS = "units=si";
 const EXCLUSIONS = "exclude=minutely,hourly,daily,flags";
 const API_KEY = "you.have.to.get.your.own.key";

 request
 .get(`${SERVER}/${API_KEY}/${lat},${long}?${UNITS}&${EXCLUSIONS}`)
 .end((err, res) =>
 callback(
 err
 ? Either.of("AJAX FAILURE", null)
 : Either.of(null, JSON.parse(res.text))
 )
 );
};
```

然后，一般的过程将变成如下。我们再次使用一个 Either：如果没有警报，而不是一个数组，我们返回一个`NO ALERTS`消息：

```js
const produceAlertsTable2 = weatherObj => {
 return weatherObj
        .chain(obj => {
 const alerts = getField("alerts")(obj);
            return alerts
 ? Either.of(null, alerts)
 : Either.of("NO ALERTS", null);
 })
        .chain(a =>
 a.map(
 x =>
 `<tr><td>${x.title}</td>` +
 `<td>${x.description.substr(0, 500)}...</td></tr>`
 )
 )
        .chain(a => a.join(os.EOL))
        .chain(s => `<table>${s}</table>`);
};
```

注意我们如何使用`.chain()`，所以多个包装器不会有问题。现在我们可以测试多种情况，并得到适当的结果--或者至少对于世界各地的当前天气情况是这样！

+   对于 TX 的 Houston，我们仍然得到一个 HTML 表格。

+   对于 UY 的 Montevideo，我们得到一条消息，说没有警报。

+   对于错误坐标的点，我们得知 AJAX 调用失败了：不错！

```js
// *Houston, TX, US:*
getAlerts2(29.76, -95.37, x => console.log(produceAlertsTable2(x).toString()));
Right("...*a table with alerts: lots of HTML code*...");

// *Montevideo, UY*
getAlerts2(-34.9, -54.6, x => console.log(produceAlertsTable2(x).toString()));
Left("NO ALERTS");

// *A point with wrong coordinates*
getAlerts2(444, 555, x => console.log(produceAlertsTable2(x).toString()));
Left("AJAX FAILURE");
```

我们还没有完成 Either monad。你的大部分代码可能涉及调用函数。让我们寻找一个更好的方法来实现这一点，通过这个 monad 的一个变体。

# 调用函数 - Try monad

如果我们调用可能抛出异常的函数，并且我们想以一种功能性的方式来做，我们可以使用*Try* monad，来封装函数的结果或异常。这个想法基本上与 Either monad 是一样的：唯一的区别在于构造函数，它接收一个函数，并调用它：

+   如果没有问题，返回的值将成为 monad 的右值

+   如果有异常，它将成为左值

```js
class Try extends Either {
 constructor(fn, msg) {
 try {
 return Either.of(null, fn());
 } catch (e) {
 return Either.of(msg || e, null);
 }
 }

 static of(fn, msg) {
 return new Try(fn, msg);
 }
}
```

现在，我们可以调用任何函数，以一种良好的方式捕获异常。例如，我们一直在使用的`getField()`函数，如果用空参数调用，就会崩溃：

```js
// getField :: String → attr → a | undefined
const getField = attr => obj => obj[attr];
```

我们可以使用 Try monad 来重写它，这样它就可以与其他组合函数*友好*地协作：

```js
const getField2 = attr => obj => Try.of(() => obj[attr], "NULL OBJECT");

const x = getField2("somefield")(null);
console.log(x.isLeft()); // true
console.log(x.toString()); // Left(NULL OBJECT)
```

还有许多其他的 monads，当然，你甚至可以定义自己的 monad，所以我们不可能涵盖所有的 monads。然而，让我们再访问一个，你可能一直在使用，却没有意识到它的*monad-ness*！

# 意外的 Monads - Promises

让我们通过提及另一个你可能使用过的 monad 来完成 monads 的这一部分，尽管它有一个不同的名字：*Promises*！我们在本章的前面已经评论过，functors（记住，monads 是 functors）至少与 promises 有一些共同之处：使用方法来访问值。然而，这种类比更大！

+   `Promise.resolve()`对应于`Monad.of()` -- 如果你传递一个值给`.resolve()`，你将得到一个解析为该值的 promise，如果你提供一个 promise，你将得到一个新的 promise，其值将是原始 promise 的值（有关更多信息，请参阅[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/resolve`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/resolve)）。这是一种*解包*行为！

+   `Promise.then()`代表`Monad.map()`，也代表`Monad.chain()`，鉴于前面提到的解包。

+   我们没有直接匹配`Monad.ap()`，但我们可以添加类似以下代码的东西：

```js
Promise.prototype.ap = function(promise2) {
 return this.then(x => promise2.map(x));
};
```

即使您选择现代的`async`和`await`功能，它们在内部也是基于承诺。此外，在某些情况下，您可能仍然需要`Promise.race()`和`Promise.all()`，因此您可能会继续使用承诺，即使选择完整的 ES8 编码。

这是本节的一个合适的结尾。之前，您已经发现常见的数组实际上是函子。现在，以同样的方式，就像莫里哀戏剧《市民绅士》中的角色若尔当先生发现他一生都在说散文一样，您现在知道自己已经在使用单子，即使不知道它！

# 函数作为数据结构

到目前为止，我们已经看到如何使用函数来处理其他函数，处理数据结构或创建数据类型。让我们通过展示函数实际上如何实现自己的数据类型来结束本章，成为一种容器。事实上，这是λ演算的一个基本理论点（如果您想了解更多，请查阅*Church 编码*和*Scott 编码*），因此我们很可能可以说我们已经回到了本书的起点，即函数式编程的起源！

# Haskell 中的二叉树

考虑一个二叉树。这样的树可以是空的，也可以由一个节点（树的*根*）和两个子树组成：左二叉树和右二叉树。

在第九章中，*设计函数 - 递归*，我们使用了更一般的树结构，比如文件系统或浏览器 DOM 本身，这些结构允许一个节点有任意数量的子节点。在本节中，我们正在处理的树的特殊情况是，每个节点始终有两个子节点，尽管它们中的每一个都可能为空。这种差异似乎很小，但允许空子树是让您定义所有节点都是二进制的关键。

让我们用 Haskell 语言做一个离题。在这种语言中，我们可能会写出以下内容；*a*将是我们在节点中持有的任何值的类型：

```js
data Tree a = Nil | Node a (Tree a) (Tree a)
```

在这种语言中，模式匹配经常用于编码。例如，我们可以定义一个`empty`函数，如下所示：

```js
empty :: Tree a -> Bool
empty Nil = True
empty (Node root left right) = False
```

逻辑很简单：如果树是`Nil`（类型定义中的第一种可能性），那么树肯定是空的；否则，树不是空的。最后一行可能会写成`empty _ = False`，因为您实际上不关心树的组件；它不是`Nil`就足够了。

在二叉搜索树中搜索值（其中根大于其左子树的所有值，并且小于其右子树的所有值）将类似地编写：

```js
contains :: (Ord a) => (Tree a) -> a -> Bool
contains Nil _ = False
contains (Node root left right) x 
        | x == root = True
        | x  < root = contains left x 
        | x  > root = contains right x
```

空树不包含搜索的值。对于其他树，如果根与搜索的值匹配，我们就完成了。如果根大于搜索的值，则在左子树中搜索；否则，在右子树中搜索。

有一个重要的要点需要记住：对于这种数据类型，两种可能类型的联合，我们必须提供两个条件，并且将使用模式匹配来决定应用哪一个。记住这一点！

# 函数作为二叉树

我们能否用函数做类似的事情？答案是肯定的：我们将用函数本身来表示树（或任何其他结构） - 请注意：不是用一组函数处理的数据结构，也不是用一些方法的对象，而只是一个函数。此外，我们将得到一个功能性数据结构，100%不可变，如果更新会产生一个新的副本。而且，我们将在不使用对象的情况下完成所有这些操作；相反，闭包将提供所需的结果。

这怎么可能？我们将应用与本章前面所见类似的概念，因此该函数将充当容器，并且其结果将是其包含值的映射。让我们倒着走，首先展示如何使用新的数据类型，然后再去实现细节。

创建树将使用两个函数：`EmptyTree()`和`Tree(value, leftTree, rightTree)`。例如，创建图 12.2 中所示的树，将使用以下代码：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/09f3f6b2-11cb-4c02-b8b1-07b63c60d964.jpg)图 12.2 二叉搜索树，由以下代码创建。

```js
const myTree = Tree(
 22,
 Tree(
 9,
 Tree(4, EmptyTree(), EmptyTree()),
 Tree(12, EmptyTree(), EmptyTree())
 ),
 Tree(
 60,
 Tree(56, EmptyTree(), EmptyTree()),
 EmptyTree()
 )
);
```

你如何使用这个结构？根据数据类型描述，每当你使用树时，你必须考虑两种情况：非空树或空树。在前面的代码中，`myTree()`实际上是一个接收两个函数作为参数的函数，分别对应两种数据类型情况。第一个函数将以节点值和左右树作为参数调用，第二个函数将不接收参数。因此，要获取根，我们可以写如下内容：

```js
const myRoot = myTree((value, left, right) => value, () => null);
```

如果我们处理的是非空树，我们期望调用第一个函数并将根的值作为结果。对于空树，应该调用第二个函数，然后返回一个`null`值。

同样，如果我们想要计算树中有多少个节点，我们会写如下代码：

```js
const treeCount = aTree => aTree(
    (value, left, right) => 1 + treeCount(left) + treeCount(right),
 () => 0
);
console.log(treeCount(myTree));
```

对于非空树，第一个函数将返回 1（对于根）加上根的子树的节点计数。对于空树，计数就是零。明白了吗？

现在我们可以展示`Tree()`和`EmptyTree()`函数：

```js
const Tree = (value, left, right) => (destructure, __) =>
 destructure(value, left, right);

const EmptyTree = () => (__, destructure) => destructure();
```

`destructure()`函数是你将作为参数传递的函数（名称来自 JS 中的解构语句，它允许你将对象属性分隔为不同的变量）。你将需要提供这个函数的两个版本。如果树是非空的，将执行第一个函数；对于空树，将运行第二个函数（这模仿了 Haskell 代码中的*case*选择，只是我们将非空树的情况放在第一位，空树的情况放在最后）。`__`变量只是作为占位符使用，表示一个被忽略的参数，但显示了假定有两个参数。

这可能很难理解，所以让我们看一些更多的例子。如果我们需要访问树的特定元素，我们有以下三个函数，其中一个（`treeRoot()`）我们已经看到了--让我们在这里重复一下以完整起见：

```js
const treeRoot = tree => tree((value, left, right) => value, () => null);
const treeLeft = tree => tree((value, left, right) => left, () => null);
const treeRight = tree => tree((value, left, right) => right, () => null);
```

访问结构的组件值的函数（或*构造*，用另一个术语）称为*投影函数*。我们不会使用这个术语，但你可能会在其他地方找到它。

我们如何判断一棵树是否为空？看看你是否能理解为什么这一行代码有效：

```js
const treeIsEmpty = tree => tree(() => false, () => true);
```

让我们再看一些例子。例如，我们可以从树中构建一个对象，这有助于调试。我添加了逻辑以避免包含左侧或右侧的空子树，因此生成的对象会更短：

```js
const treeToObject = tree =>
 tree((value, left, right) => {
 const leftBranch = treeToObject(left);
 const rightBranch = treeToObject(right);
 const result = { value };
 if (leftBranch) {
 result.left = leftBranch;
 }
 if (rightBranch) {
 result.right = rightBranch;
 }
 return result;
 }, () => null);
```

注意递归的使用，就像第九章中的*遍历树结构*部分中所述的那样，为了生成左右子树的对象等价物。这个函数的一个例子如下；我编辑了输出以使其更清晰：

```js
console.log(treeToObject(myTree));
{
 value: 22,
 left: {
 value: 9,
 left: {
 value: 4
 },
 right: {
 value: 12
 }
 },
 right: {
 value: 60,
 left: {
 value: 56
 }
 }
}
```

我们可以搜索节点吗？当然可以，逻辑紧随我们在上一节中看到的定义（我们可以缩短代码，但我确实想要与 Haskell 版本保持一致）：

```js
const treeSearch = (findValue, tree) =>
 tree(
 (value, left, right) =>
            findValue === value
 ? true
 : findValue < value
 ? treeSearch(findValue, left)
 : treeSearch(findValue, right),
 () => false
 );
```

最后，为了完成本节，让我们还包括如何向树中添加新节点。仔细研究代码，您会注意到当前树没有被修改，而是产生了一个新的树。当然，鉴于我们使用函数来表示我们的树数据类型，显然我们不能只修改旧结构：它默认是不可变的：

```js
const treeInsert = (newValue, tree) =>
 tree(
 (value, left, right) =>
 newValue <= value
 ? Tree(value, treeInsert(newValue, left), right)
 : Tree(value, left, treeInsert(newValue, right)),
 () => Tree(newValue, EmptyTree(), EmptyTree())
 );
```

当尝试插入一个新键时，如果它小于或等于树的根节点，我们会产生一个新树，该树的根节点为当前根节点，保留旧的右子树，但更改其左子树以包含新值（这将以递归方式完成）。如果键大于根节点，则更改不会对称，但类似。如果我们尝试插入一个新键，并且发现自己是一个空树，我们只需用一个新树替换该空结构，该树只有新值作为其根，以及空的左右子树。

我们可以轻松测试这个逻辑--但最简单的方法是验证之前显示的二叉树（图 12.2）是否由以下操作序列生成：

```js
let myTree = EmptyTree();
myTree = treeInsert(22, myTree);
myTree = treeInsert(9, myTree);
myTree = treeInsert(60, myTree);
myTree = treeInsert(12, myTree);
myTree = treeInsert(4, myTree);
myTree = treeInsert(56, myTree);

// *The resulting tree is:*
{
 value: 22,
 left: { value: 9, left: { value: 4 }, right: { value: 12 } },
 right: { value: 60, left: { value: 56 } }
};
```

我们可以通过提供比较器函数来使这个插入函数更加通用，该函数将用于比较值。这样，我们可以轻松地调整二叉树以表示通用映射。节点的值实际上将是一个对象，例如`{key:... , data:...}`，并且提供的函数将比较`newValue.key`和`value.key`以决定在哪里添加新节点。当然，如果两个键相等，我们将更改当前树的根节点：

```js
const compare = (obj1, obj2) =>
    obj1.key === obj2.key ? 0 : obj1.key < obj2.key ? -1 : 1;

const treeInsert2 = (comparator, newValue, tree) =>
 tree(
 (value, left, right) =>
            comparator(newValue, value) === 0
? Tree(newValue, left, right)
 : comparator(newValue, value) < 0
 ? Tree(
 value,
 treeInsert2(comparator, newValue, left),
 right
 )
 : Tree(
 value,
 left,
 treeInsert2(comparator, newValue, right)
 ),
 () => Tree(newValue, EmptyTree(), EmptyTree())
 );
```

我们还需要什么？当然，我们可以编写各种函数：删除节点，计算节点数，确定树的高度，比较两棵树等等。但是，为了获得更多的可用性，我们真的应该将结构转换为一个函子，通过实现`map()`函数。幸运的是，使用递归，这被证明是很容易的：

```js
const treeMap = (fn, tree) =>
 tree(
 (value, left, right) =>
            Tree(fn(value), treeMap(fn, left), treeMap(fn, right)),
 () => EmptyTree()
 );
```

我们可以继续举更多的例子，但这不会改变我们从这项工作中得出的重要结论：

+   我们正在处理一个数据结构（一个递归的数据结构），并用一个函数来表示它

+   我们没有为数据使用任何外部变量或对象：而是使用闭包

+   数据结构本身满足我们在第十章*确保纯度-不可变性*中分析的所有要求，因为它是不可变的，所有更改总是产生新的结构

+   最后，树是一个函子，提供了所有相应的优势

因此，我们甚至看到了函数式编程的另一个应用--我们看到一个函数实际上可以成为一个结构，这并不是人们通常习惯的！

# 问题

12.1\. **也许任务？** 在第八章的问题部分，*连接函数-管道和组合*，一个问题涉及获取某人的待办任务，但考虑到错误或边界情况，比如所选的人可能根本不存在。重新做这个练习，但使用 Maybe 或 Either 单子来简化编码。

12.2\. **扩展您的树**。为了获得我们的函数式二叉搜索树的更完整的实现，实现以下函数：

+   计算树的高度--或者等效地，从根到任何其他节点的最大距离

+   按升序列出树的所有键

+   从树中删除一个键

12.3\. **函数式列表**。在与二叉树相同的精神下，实现函数式列表。由于列表被定义为空或一个节点（头部）后跟另一个列表（尾部），您可能希望从以下内容开始：

```js
 const List = (head, tail) => (destructure, __) => 
 destructure(head, tail);
 const EmptyList = () => (__, destructure) => destructure();
```

以下是一些简单的一行操作，让您开始：

```js
 const listHead = list => list((head, __) => head, () => null);
 const listTail = list => list((__, tail) => tail, () => null);
 const listIsEmpty = list => (() => false, () => true);
 const listSize = list => list((head, tail) => 1 + listSize(tail), 
 () => 0);
```

您可以考虑进行以下操作：

+   将列表转换为数组，反之亦然

+   反转列表

+   将一个列表附加到另一个列表的末尾

+   连接两个列表

不要忘记`listMap()`函数！此外，`listReduce()`和`listFilter()`函数会派上用场。

12.4\. **代码缩短**。我们提到`treeSearch()`函数可以缩短 - 你能做到吗？是的，这更多是一个 JavaScript 问题，而不是一个功能性的问题，我并不是说更短的代码一定更好，但许多程序员似乎是这样认为的，所以了解这种风格是很好的，因为你可能会遇到它。

# 总结

在本章中，我们更接近理论，看到了如何从功能性的角度使用和实现数据类型。我们从定义函数签名的方式开始，以帮助理解后来遇到的多个操作所暗示的转换；然后，我们继续定义了几个容器，包括函子和单子，并看到它们如何用于增强函数组合，最后我们看到函数如何直接被自身使用，不需要额外的负担，来实现功能性数据结构。

到目前为止，在本书中我们已经看到了 JavaScript 的函数式编程的几个特性。我们从一些定义开始，到一个实际的例子，然后转向重要的考虑因素，如纯函数、避免副作用、不可变性、可测试性、通过函数连接和数据容器实现数据流的构建新函数，我们已经看到了很多概念，但我相信你能够将它们付诸实践，并开始编写更高质量的代码 - 试一试吧！
