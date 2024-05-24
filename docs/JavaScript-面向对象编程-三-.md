# JavaScript 面向对象编程（三）

> 原文：[`zh.annas-archive.org/md5/9BD01417886F7CF4434F47DFCFFE13F5`](https://zh.annas-archive.org/md5/9BD01417886F7CF4434F47DFCFFE13F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：ES6 迭代器和生成器

到目前为止，我们已经讨论了 JavaScript 的语言构造，而没有看任何特定的语言版本。然而，在本章中，我们将主要关注 ES6 中引入的一些语言特性。这些特性对你编写 JavaScript 代码有很大的影响。它们不仅显著改进了语言，还为 JavaScript 程序员提供了迄今为止无法使用的几个函数式编程构造。

在本章中，我们将看一下 ES6 中新引入的迭代器和生成器。有了这些知识，我们将继续详细了解增强的集合构造。

# For...of 循环

`for...of`循环是在 ES6 中引入的，与可迭代对象和迭代器构造一起。这个新的循环构造替代了 ES5 中的`for...in`和`for...each`循环构造。由于`for...of`循环支持迭代协议，它可以用于内置对象，比如数组、字符串、映射、集合等，以及可迭代的自定义对象。考虑下面的代码片段作为一个例子：

```js
    const iter = ['a', 'b']; 
    for (const i of iter) { 
      console.log(i); 
    } 
    "a" 
    "b" 

```

`for...of`循环适用于可迭代对象和内置对象，比如数组是可迭代的。如果你注意到，我们在定义循环变量时使用的是`const`而不是`var`。这是一个好的做法，因为当你使用`const`时，会创建一个新的变量绑定和存储空间。当你不打算在块内修改循环变量的值时，应该在`for...of`循环中使用`const`而不是`var`声明。

其他集合也支持`for...of`循环。例如，字符串是 Unicode 字符序列，`for...of`循环也可以正常工作：

```js
    for (let c of "String"){ 
      console.log(c); 
    } 
    //"s" "t" "r" "i" "n" "g" 

```

`for...in`和`for...of`循环的主要区别在于`for...in`循环遍历对象的所有可枚举属性。`for...of`循环有一个特定的目的，那就是根据对象定义的可迭代协议来遵循迭代行为。

# 迭代器和可迭代对象

ES6 引入了一种新的迭代数据的机制。遍历数据列表并对其进行操作是一种非常常见的操作。ES6 增强了迭代构造。这个变化涉及到两个主要概念——迭代器和可迭代对象。

## 迭代器

JavaScript 迭代器是一个公开`next()`方法的对象。这个方法以一个对象的形式返回集合中的下一个项，这个对象有两个属性——`done`和`value`。在下面的例子中，我们将通过公开`next()`方法从数组中返回一个迭代器：

```js
    //Take an array and return an iterator 
    function iter(array){ 
      var nextId= 0; 
      return { 
        next: function() { 
          if(nextId < array.length) { 
            return {value: array[nextId++], done: false}; 
          } else { 
            return {done: true}; 
          } 
        } 
      } 
    } 
    var it = iter(['Hello', 'Iterators']); 
    console.log(it.next().value); // 'Hello' 
    console.log(it.next().value); // 'Iterators' 
    console.log(it.next().done);  // true 

```

在上面的例子中，我们会不断通过`next()`方法返回数组中的元素，直到没有元素可返回为止，这时我们将返回`done`为`true`，表示迭代没有更多的值。通过`next()`方法重复访问迭代器中的元素。

## 可迭代对象

可迭代对象是定义了其迭代行为或内部迭代的对象。这样的对象可以在 ES6 中引入的`for...of`循环中使用。内置类型，比如数组和字符串，定义了默认的迭代行为。为了使对象可迭代，它必须实现`@@iterator`方法，也就是说对象必须有一个以`'Symbol.iterator'`为键的属性。

如果一个对象实现了一个键为`'Symbol.iterator'`的方法，那么它就变成了可迭代对象。这个方法必须通过`next()`方法返回一个迭代器。让我们看下面的例子来澄清这一点：

```js
    //An iterable object 
    //1\. Has a method with key has 'Symbol.iterator' 
    //2\. This method returns an iterator via method 'next' 
    let iter = { 
      0: 'Hello', 
      1: 'World of ', 
      2: 'Iterators', 
      length: 3, 
      [Symbol.iterator]() { 
        let index = 0; 
        return { 
          next: () => { 
            let value = this[index]; 
            let done = index >= this.length; 
            index++; 
            return { value, done }; 
          } 
        }; 
      } 
    }; 
    for (let i of iter) { 
      console.log(i);  
    } 
    "Hello" 
    "World of " 
    "Iterators" 

```

让我们把这个例子分解成更小的部分。我们正在创建一个可迭代对象。我们将使用对象字面语法创建一个`iter`对象，这是我们已经熟悉的。这个对象的一个特殊方面是`[Symbol.iterator]`方法。这个方法的定义使用了计算属性和 ES6 的简写方法定义语法，这是我们在上一章已经讨论过的。由于这个对象包含了`[Symbol.iterator]`方法，这个对象是可迭代的，或者说它遵循可迭代协议。这个方法还通过暴露`next()`方法返回迭代器对象，定义了迭代行为。现在这个对象可以与`for...of`循环一起使用。

# 生成器

与迭代器和可迭代对象密切相关，生成器是 ES6 中最受关注的功能之一。生成器函数返回一个生成器对象；这个术语起初听起来很令人困惑。当你编写一个函数时，你也本能地理解它的行为-函数开始执行，逐行执行，并在执行最后一行时结束执行。一旦函数以这种方式被线性执行，随后跟随函数的代码将被执行。

在支持多线程的语言中，这种执行流程可以被中断，部分完成的任务可以在不同的线程、进程和通道之间共享。JavaScript 是单线程的，你目前不需要处理多线程的挑战。

然而，生成器函数可以被暂停和稍后恢复。这里的重要思想是，生成器函数选择暂停自己，它不能被任何外部代码暂停。在执行期间，函数使用`yield`关键字来暂停。一旦生成器函数被暂停，它只能被函数外的代码恢复。

你可以暂停和恢复生成器函数多次。使用生成器函数，一个常见的模式是编写无限循环，并在需要时暂停和恢复它们。这样做有利有弊，但这种模式已经变得流行起来。

另一个重要的理解点是，生成器函数还允许双向消息传递，进出函数。每当你使用`yield`关键字暂停函数时，消息就会从生成器函数中发送出去，当函数恢复时，消息就会传回生成器函数。

让我们看下面的例子来澄清生成器函数的工作原理：

```js
    function* generatorFunc() { 
      console.log('1'); //-----------> A 
      yield;            //-----------> B 
      console.log('2'); //-----------> C 
    } 
    const generatorObj = generatorFunc(); 
    console.log(generatorObj.next());   
    //"1" 
    //Object { 
    // "done": false, 
    // "value": undefined 
    //} 

```

这是一个非常简单的生成器函数。然而，有几个有趣的方面需要仔细理解。

首先，注意关键字 function 后面紧跟着一个星号`*`，这是表示该函数是一个生成器函数的语法。在函数名之前紧跟着星号也是可以的。以下两种声明都是有效的：

```js
    function *f(){ }  
    function* f(){ } 

```

在函数内部，真正的魔力在于`yield`关键字。当遇到`yield`关键字时，函数会暂停自己。在我们继续之前，让我们看看函数是如何被调用的：

```js
    const generatorObj = generatorFunc(); 
    generatorObj.next();  //"1" 

```

当我们调用生成器函数时，它不像普通函数一样被执行，而是返回一个生成器对象。你可以使用这个生成器对象来控制生成器函数的执行。生成器对象上的`next()`方法会恢复函数的执行。

当我们第一次调用`next()`时，执行会一直进行到函数的第一行（标记为'A'），当遇到`yield`关键字时暂停。如果我们再次调用`next()`函数，它将从上次暂停执行的地方继续执行到下一行：

```js
    console.log(generatorObj.next());   
    //"2" 
    //Object { 
    // "done": true, 
    // "value": undefined 
    //} 

```

一旦整个函数体被执行，对生成器对象的任何`next()`调用都没有效果。我们谈到生成器函数允许双向消息传递。这是如何工作的？在前面的例子中，你可以看到每当我们恢复生成器函数时，我们会收到一个包含两个值`done`和`value`的对象；在我们的例子中，我们收到的值是`undefined`。这是因为我们没有用`yield`关键字返回任何值。当你用`yield`关键字返回一个值时，调用函数会接收到它。考虑以下例子：

```js
    function* logger() { 
      console.log('start') 
      console.log(yield) 
      console.log(yield) 
      console.log(yield) 
      return('end') 
    } 

    var genObj = logger(); 

    // the first call of next executes from the 
      start of the function until the first yield statement 
    console.log(genObj.next())         
    // "start", Object {"done": false,"value": undefined} 
    console.log(genObj.next('Save'))   
    // "Save", Object {"done": false,"value": undefined} 
    console.log(genObj.next('Our'))    
    // "Our", Object {"done": false,"value": undefined} 
    console.log(genObj.next('Souls'))  
    // "Souls",Object {"done": true,"value": "end"} 

```

让我们一步一步地追踪这个例子的执行流程。生成器函数有三个暂停或 yield。我们可以通过编写以下代码来创建生成器对象：

```js
    var genObj = logger(); 

```

我们将通过调用`next`方法开始执行生成器函数；这个方法开始执行，直到第一个`yield`。如果你注意到，在第一次调用中我们没有向`next()`方法传递任何值。这个`next()`方法的目的只是启动生成器函数。我们将再次调用`next()`方法，但这次传递一个`"Save"`值作为参数。当函数执行恢复时，`yield`接收到这个值，我们可以在控制台上看到打印出的值：

```js
    "Save", Object {"done": false,"value": undefined} 

```

我们将再次使用两个不同的值调用`next()`方法，输出与前面的代码类似。当我们最后一次调用`next()`方法时，执行结束，生成器函数将返回一个`end`值给调用代码。在执行结束时，你会看到`done`设置为`true`，`value`赋值为函数返回的值，即`end`：

```js
    "Souls",Object {"done": true,"value": "end"} 

```

重要的是要注意，第一个`next()`方法的目的是启动生成器函数的执行-它将我们带到第一个`yield`关键字，因此，传递给第一个`next()`方法的任何值都将被忽略。

到目前为止的讨论表明，生成器对象符合迭代器的约定：

```js
    function* logger() { 
      yield 'a' 
      yield 'b' 
    } 
    var genObj = logger(); 
    //the generator object is built using generator function 
    console.log(typeof genObj[Symbol.iterator] === 'function')    //true 
    // it is an iterable 
    console.log(typeof genObj.next === 'function') //true 
    // and an iterator (has a next() method) 
    console.log(genObj[Symbol.iterator]() === genObj) //true 

```

这个例子证实了生成器函数也符合可迭代的约定。

## 迭代生成器

生成器是迭代器，像所有支持可迭代的 ES6 构造一样，它们可以用于迭代生成器。

第一种方法是使用`for...of`循环，如下面的代码所示：

```js
    function* logger() { 
      yield 'a' 
      yield 'b' 
    } 
    for (const i of logger()) { 
      console.log(i) 
    } 
    //"a" "b" 

```

我们在这里没有创建生成器对象。`For...of`循环支持可迭代对象，生成器自然适用于这个循环。

扩展运算符可以用于将可迭代对象转换为数组。考虑以下示例：

```js
    function* logger() { 
      yield 'a' 
      yield 'b' 
    } 
    const arr = [...logger()] 
    console.log(arr) //["a","b"] 

```

最后，你可以使用解构语法与生成器，如下所示：

```js
    function* logger() { 
      yield 'a' 
      yield 'b' 
    } 
    const [x,y] = logger() 
    console.log(x,y) //"a" "b" 

```

生成器在异步编程中扮演着重要的角色。接下来，我们将看一下 ES6 中的异步编程和 Promise。JavaScript 和 Node.js 提供了一个很好的环境来编写异步程序。生成器可以帮助你编写协作式的多任务函数。

# 集合

ES6 引入了四种数据结构-`Map`、`WeakMap`、`Set`和`WeakSet`。与 Python 和 Ruby 等其他语言相比，JavaScript 的标准库非常薄弱，无法支持哈希或 Map 数据结构或字典。人们发明了一些方法来模拟`Map`的行为，通过将字符串键与对象进行映射。这些方法会产生一些副作用。语言对这些数据结构的支持是非常必要的。

ES6 支持标准的字典数据结构；我们将在下一节更详细地了解这些内容。

## Map

`Map`允许将任意值作为`key`。`keys`映射到值。Map 允许快速访问值。让我们看一些 Map 的例子：

```js
    const m = new Map(); //Creates an empty Map 
    m.set('first', 1);   //Set a value associated with a key 
    console.log(m.get('first'));  //Get a value using the key 

```

我们将使用构造函数创建一个空的`Map`。你可以使用`set()`方法向`Map`添加一个条目，将键与值关联起来，并覆盖具有相同键的任何现有条目。它的对应方法`get()`获取与键关联的值，如果在映射中没有这样的条目，则返回`undefined`。

Map 还有其他可用的辅助方法，如下所示：

```js
    console.log(m.has('first')); //Checks for existence of a key 
    //true 
    m.delete('first'); 
    console.log(m.has('first')); //false 

    m.set('foo', 1); 
    m.set('bar', 0); 

    console.log(m.size); //2 
    m.clear(); //clears the entire map 
    console.log(m.size); //0 

```

您也可以使用以下可迭代的*[key, value]*对来创建`Map`：

```js
    const m2 = new Map([ 
        [ 1, 'one' ], 
        [ 2, 'two' ], 
        [ 3, 'three' ], 
    ]); 

```

您可以使用链式`set()`方法来获得紧凑的语法，如下所示：

```js
    const m3 = new Map().set(1, 'one').set(2, 'two').set(3, 'three'); 

```

我们可以使用任何值作为键。对于对象，键只能是字符串，但是对于集合，这种限制被移除了。我们也可以使用对象作为键，尽管这种用法并不是很流行：

```js
    const obj = {} 
    const m2 = new Map([ 
      [ 1, 'one' ], 
      [ "two", 'two' ], 
      [ obj, 'three' ], 
    ]); 
    console.log(m2.has(obj)); //true 

```

### 遍历 Map

要记住的一件重要的事情是，对于 Map 来说，顺序很重要。Map 保留了添加元素的顺序。

有三种可迭代对象可用于遍历`Map`，即`keys`，`values`和`entries`。

`keys()`方法返回`Map`键的可迭代对象，如下所示：

```js
    const m = new Map([ 
      [ 1, 'one' ], 
      [ 2, 'two' ], 
      [ 3, 'three' ], 
    ]); 
    for (const k of m.keys()){ 
      console.log(k);  
    } 
    //1 2 3 

```

同样，`values()`方法返回`Map`值的可迭代对象，如下面的示例所示：

```js
    for (const v of m.values()){ 
      console.log(v);  
    } 
    //"one" 
    //"two" 
    //"three" 

```

`entries()`方法以*[key,value]*对的形式返回`Map`的条目，如下面的代码所示：

```js
    for (const entry of m.entries()) { 
      console.log(entry[0], entry[1]); 
    } 
    //1 "one" 
    //2 "two" 
    //3 "three" 

```

您可以使用解构来使其更简洁，如下所示：

```js
    for (const [key, value] of m.entries()) { 
      console.log(key, value); 
    } 
    //1 "one" 
    //2 "two" 
    //3 "three" 

```

更简洁的是：

```js
    for (const [key, value] of m) { 
      console.log(key, value); 
    } 
    //1 "one" 
    //2 "two" 
    //3 "three" 

```

### 将 Map 转换为数组

如果要将`Map`转换为数组，则扩展运算符(`...`)非常方便：

```js
    const m = new Map([ 
      [ 1, 'one' ], 
      [ 2, 'two' ], 
      [ 3, 'three' ], 
    ]); 
    const keys = [...m.keys()] 
    console.log(keys) 
    //Array [ 
    //1, 
    //2, 
    //3 
    //] 

```

由于 Map 是可迭代的，您可以使用扩展运算符将整个`Map`转换为数组：

```js
    const m = new Map([ 
      [ 1, 'one' ], 
      [ 2, 'two' ], 
      [ 3, 'three' ], 
    ]); 
    const arr = [...m] 
    console.log(arr) 
    //Array [ 
    //[1,"one"], 
    //[2,"two"], 
    //[3,"three"] 
    //] 

```

## Set

`Set`是一个值的集合。您可以向其中添加和删除值。尽管这听起来与数组类似，但集合不允许相同的值出现两次。`Set`中的值可以是任何类型。到目前为止，您一定在想这与数组有何不同？`Set`旨在快速执行一项操作-成员测试。相对而言，数组在这方面较慢。`Set`操作类似于`Map`操作：

```js
    const s = new Set(); 
    s.add('first'); 
    s.has('first'); // true 
    s.delete('first'); //true 
    s.has('first'); //false 

```

与 Map 类似，您可以通过迭代器创建一个`Set`：

```js
    const colors = new Set(['red', white, 'blue']); 

```

当您向`Set`添加一个值，并且该值已经存在时，不会发生任何事情。同样，如果您从`Set`中删除一个值，并且该值一开始不存在，也不会发生任何事情。没有办法捕获这种情况。

## WeakMap 和 WeakSet

`WeakMap`和`WeakSet`的 API 与`Map`和`Set`类似，但受到限制，并且它们大部分工作方式与它们的强大对应物相似。不过，也有一些区别，如下所示：

+   `WeakMap`仅支持`new`，`has()`，`get()`，`set()`和`delete()`方法

+   `WeakSet`仅支持`new`，`has()`，`add()`和`delete()`方法

+   `WeakMap`的键必须是对象

+   `WeakSet`的值必须是对象

+   您无法迭代`WeakMap`；您可以通过其键访问值的唯一方式

+   您无法迭代`WeakSet`

+   您无法清除`WeakMap`或`WeakSet`

首先让我们了解`WeakMap`。`Map`和`WeakMap`之间的区别在于`WeakMap`允许自身被垃圾回收。`WeakMap`中的键是弱引用的。当垃圾回收器进行引用计数时（一种查看所有存活引用的技术），`WeakMap`的键不会被计算，并且在可能的情况下会被垃圾回收。

当您无法控制在 Map 中保存的对象的生命周期时，`WeakMaps`非常有用。使用`WeakMaps`时不需要担心内存泄漏，因为即使对象的生命周期很长，它们也不会占用内存。

`WeakSet`也适用相同的实现细节。然而，由于无法迭代`WeakSet`，因此`WeakSet`的用例并不多。

# 总结

在本章中，我们详细研究了 ES6 生成器。生成器是 ES6 最受期待的功能之一。暂停和恢复函数执行的能力打开了许多关于协作编程的可能性。生成器的主要优势在于它们提供了单线程、同步代码风格，同时隐藏了异步的本质。这使我们更容易以非常自然的方式表达程序步骤/语句的流程，而无需同时导航异步语法和陷阱。我们通过生成器实现了关注点的分离。

生成器与迭代器和可迭代对象的约定密切相关。这些是 ES6 中受欢迎的添加，显著增强了语言提供的数据结构。迭代器提供了一种简单的方法来返回（可能是无界的）值序列。`@@iterator`符号用于为对象定义默认迭代器，使其成为可迭代对象。

迭代器最重要的用例是当我们想在消耗可迭代对象的结构中使用它时，比如`for...of`循环。在本章中，我们还研究了 ES6 中引入的新循环结构`for...of`。`for...of`与许多原生对象一起工作，因为它们定义了默认的`@@iterator`方法。我们还研究了 ES6 集合的新添加，如 Map、Set、WeakMap 和 Weak Set。这些集合有额外的迭代器方法-`.entries()`、`.values()`和`.keys()`。

下一章将详细研究 JavaScript 原型。


# 第六章：原型

在本章中，您将学习函数对象的`prototype`属性。理解`prototype`的工作原理是学习 JavaScript 语言的重要部分。毕竟，JavaScript 经常被归类为具有基于原型的对象模型。原型并不特别困难，但它是一个新概念，因此有时可能需要一点时间才能理解。就像闭包（见第三章，“函数”）一样，原型是 JavaScript 中的一些东西，一旦理解，就会显得如此明显并且合乎逻辑。与本书的其余部分一样，强烈建议您输入并尝试这些示例-这样学习和记忆概念会更容易。

在本章中，我们将涵盖以下主题：

+   每个函数都有一个`prototype`属性，它包含一个对象

+   向原型对象添加属性

+   使用添加到原型的属性

+   自有属性和原型属性之间的区别

+   `__proto__`属性，每个对象都保留着与其原型的秘密链接

+   诸如`isPrototypeOf()`、`hasOwnProperty()`和`propertyIsEnumerable()`之类的方法

+   增强内置对象，例如数组或字符串，以及为什么这可能是一个坏主意

# 原型属性

JavaScript 中的函数是对象，它们包含方法和属性。您已经熟悉的一些方法是`apply()`和`call()`，其他一些属性是`length`和`constructor`。函数对象的另一个属性是`prototype`。

如果您定义一个简单的函数`foo()`，您可以像处理其他对象一样访问它的属性。考虑以下代码：

```js
    > function foo(a, b) { 
        return a * b; 
      } 
    > foo.length; 
    2 
    > foo.constructor; 
    function Function() { [native code] } 

```

`prototype`属性是在定义函数时立即可用的属性。它的初始值是一个空对象：

```js
    > typeof foo.prototype; 
    "object" 

```

就好像您自己添加了这个属性一样，如下所示：

```js
    > foo.prototype = {}; 

```

您可以用属性和方法增强这个空对象。它们不会对`foo()`函数本身产生任何影响；它们只会在您将`foo()`作为构造函数调用时使用。

## 使用原型添加方法和属性

在上一章中，您学习了如何定义构造函数，以便用于创建（构造）新对象。主要思想是，在使用`new`调用的函数内部，您将可以访问`this`值，它指的是构造函数返回的对象。增强，即向`this`添加方法和属性，是您可以向正在构造的对象添加功能的方法。

让我们来看看构造函数`Gadget()`，它使用`this`向创建的对象添加了两个属性和一个方法，如下所示：

```js
    function Gadget(name, color) { 
      this.name = name; 
      this.color = color; 
      this.whatAreYou = function () { 
        return 'I am a ' + this.color + ' ' + this.name; 
      }; 
    } 

```

向构造函数的`prototype`属性添加方法和属性是另一种为该构造函数产生的对象添加功能的方法。让我们添加两个属性`price`和`rating`，以及一个`getInfo()`方法。由于`prototype`已经指向一个对象，您可以继续向其添加属性和方法，如下所示：

```js
    Gadget.prototype.price = 100; 
    Gadget.prototype.rating = 3; 
    Gadget.prototype.getInfo = function () { 
      return 'Rating: ' + this.rating + 
             ', price: ' + this.price; 
    }; 

```

或者，您可以完全覆盖`prototype`对象，用您选择的对象替换它，如下例所示：

```js
    Gadget.prototype = { 
      price: 100, 
      rating: ...  /* and so on... */ 
    }; 

```

# 使用原型的方法和属性

您添加到`prototype`的所有方法和属性在使用构造函数创建新对象时立即可用。如果您使用`Gadget()`构造函数创建一个`newtoy`对象，您可以访问已经定义的所有方法和属性，如下所示：

```js
    > var newtoy = new Gadget('webcam', 'black'); 
    > newtoy.name; 
    "webcam" 
    > newtoy.color; 
    "black" 
    > newtoy.whatAreYou(); 
    "I am a black webcam" 
    > newtoy.price; 
    100 
    > newtoy.rating; 
    3 
    > newtoy.getInfo(); 
    "Rating: 3, price: 100" 

```

重要的是要注意`prototype`是活动的。在 JavaScript 中，对象是按引用传递的，因此`prototype`不会随着每个新对象实例的创建而复制。这在实践中意味着什么？这意味着你可以随时修改`prototype`，所有的对象，甚至是在修改之前创建的对象，都会看到这些变化。

让我们通过向`prototype`添加一个新方法来继续示例：

```js
    Gadget.prototype.get = function (what) { 
      return this[what]; 
    }; 

```

即使`newtoy`对象在`get()`方法定义之前创建，`newtoy`对象仍然可以访问新方法，如下所示：

```js
    > newtoy.get('price'); 
    100 
    > newtoy.get('color'); 
    "black" 

```

## 自有属性与原型属性

在上面的例子中，`getInfo()`被内部使用来访问对象的属性。它也可以使用`Gadget.prototype`来实现相同的输出，如下所示：

```js
    Gadget.prototype.getInfo = function () { 
      return 'Rating: ' + Gadget.prototype.rating + 
             ', price: ' + Gadget.prototype.price; 
    }; 

```

有什么区别？为了回答这个问题，让我们详细研究一下`prototype`的工作原理。

让我们再次看看`newtoy`对象：

```js
    var newtoy = new Gadget('webcam', 'black'); 

```

当你尝试访问`newtoy`的属性，比如`newtoy.name`，JavaScript 引擎会查找对象的所有属性，寻找名为`name`的属性，如果找到，就返回它的值，如下所示：

```js
    > newtoy.name; 
    "webcam" 

```

如果你尝试访问`rating`属性会发生什么？JavaScript 引擎会检查`newtoy`对象的所有属性，没有找到名为`rating`的属性。然后，脚本引擎会识别用于创建此对象的构造函数的`prototype`（与`newtoy.constructor.prototype`相同）。如果在`prototype`对象中找到属性，则使用该属性：

```js
    > newtoy.rating; 
    3 

```

你可以做同样的事情并直接访问`prototype`。每个对象都有一个`constructor`属性，它是指向创建对象的函数的引用，所以在这种情况下看看下面的代码：

```js
    > newtoy.constructor === Gadget; 
    true 
    > newtoy.constructor.prototype.rating; 
    3 

```

现在，让我们进一步查找。每个对象都有一个构造函数。`prototype`是一个对象，所以它也必须有一个构造函数，而构造函数又有一个`prototype`。你可以沿着原型链向上查找，最终会得到内置的`Object()`对象，它是最高级的父对象。实际上，这意味着如果你尝试`newtoy.toString()`，而`newtoy`没有自己的`toString()`方法，它的`prototype`也没有，最终你会得到对象的`toString()`方法：

```js
    > newtoy.toString(); 
    "[object Object]" 

```

## 用自有属性覆盖原型的属性

正如前面的讨论所示，如果你的对象没有自己的某个属性，它可以使用原型链上的属性。如果对象有自己的属性，原型也有一个同名的属性会发生什么？那么自有属性优先于原型的属性。

考虑这样一个情景，一个属性名称既存在于自有属性中，又存在于`prototype`对象的属性中：

```js
    > function Gadget(name) { 
        this.name = name; 
      } 
    > Gadget.prototype.name = 'mirror'; 

```

创建一个新对象并访问它的`name`属性会给你对象自己的`name`属性，如下所示：

```js
    > var toy = new Gadget('camera'); 
    > toy.name; 
    "camera" 

```

可以使用`hasOwnProperty()`来确定属性的定义位置，如下所示：

```js
    > toy.hasOwnProperty('name'); 
    true 

```

如果删除`toy`对象自有的`name`属性，原型的具有相同名称的属性将显示出来：

```js
    > delete toy.name; 
    true 
    > toy.name; 
    "mirror" 
    > toy.hasOwnProperty('name'); 
    false 

```

当然，你总是可以重新创建对象的自有属性，如下所示：

```js
    > toy.name = 'camera'; 
    > toy.name; 
    "camera" 

```

你可以使用`hasOwnProperty()`方法来查找你感兴趣的特定属性的来源。前面提到了`toString()`方法。它是从哪里来的？

```js
    > toy.toString(); 
    "[object Object]" 
    > toy.hasOwnProperty('toString'); 
    false 
    > toy.constructor.hasOwnProperty('toString'); 
    false 
    > toy.constructor.prototype.hasOwnProperty('toString'); 
    false 
    > Object.hasOwnProperty('toString'); 
    false 
    > Object.prototype.hasOwnProperty('toString'); 
    true 

```

### 枚举属性

如果你想列出对象的所有属性，可以使用`for...in`循环。在第二章中，*基本数据类型、数组、循环和条件*，你看到你也可以使用`for...in`循环遍历数组的所有元素，但正如在那里提到的，`for`更适合数组，`for...in`更适合对象。让我们以构造一个查询字符串的 URL 为例：

```js
    var params = { 
      productid: 666, 
      section: 'products' 
    }; 

    var url = 'http://example.org/page.php?', 
        i, 
        query = []; 

    for (i in params) { 
        query.push(i + '=' + params[i]); 
    } 

    url += query.join('&'); 

```

这将产生以下`url`字符串：

`http://example.org/page.php?productid=666&section=products`。

以下是一些需要注意的细节：

+   并非所有属性都会出现在`for...in`循环中。例如，长度（对于数组）和构造函数属性不会显示出来。能够显示出来的属性被称为可枚举。你可以通过每个对象提供的`propertyIsEnumerable()`方法来检查哪些属性是可枚举的。在 ES5 中，你可以指定哪些属性是可枚举的，而在 ES3 中你没有这种控制。

+   通过原型链传递的原型也会显示出来，只要它们是可枚举的。你可以使用`hasOwnProperty()`方法来检查属性是对象自己的属性还是原型的属性。

+   `propertyIsEnumerable()`方法对于原型的所有属性都返回`false`，即使它们是可枚举的并出现在`for...in`循环中。

让我们看看这些方法的实际应用。看看这个简化版本的`Gadget()`：

```js
    function Gadget(name, color) { 
      this.name = name; 
      this.color = color; 
      this.getName = function () { 
        return this.name; 
      }; 
    } 
    Gadget.prototype.price = 100; 
    Gadget.prototype.rating = 3; 

```

创建一个新对象如下：

```js
    var newtoy = new Gadget('webcam', 'black'); 

```

现在，如果你使用`for...in`循环进行循环，你可以看到对象的所有属性，包括来自原型的属性：

```js
    for (var prop in newtoy) {  
      console.log(prop + ' = ' + newtoy[prop]);  
    } 

```

结果还包括对象的方法，因为方法只是恰好是函数的属性：

```js
    name = webcam 
    color = black 
    getName = function () { 
      return this.name; 
    } 
    price = 100 
    rating = 3 

```

如果你想区分对象自己的属性和原型的属性，使用`hasOwnProperty()`。首先尝试以下操作：

```js
    > newtoy.hasOwnProperty('name'); 
    true 
    > newtoy.hasOwnProperty('price'); 
    false 

```

让我们再次循环，但这次只显示对象自己的属性：

```js
    for (var prop in newtoy) {  
      if (newtoy.hasOwnProperty(prop)) { 
        console.log(prop + '=' + newtoy[prop]);  
      } 
    } 

```

结果如下：

```js
    name=webcam 
    color=black 
    getName = function () { 
      return this.name; 
    } 

```

现在，让我们尝试`propertyIsEnumerable()`。这个方法对于对象自己的非内置属性返回`true`，例如：

```js
    > newtoy.propertyIsEnumerable('name'); 
    true 

```

大多数内置属性和方法都不可枚举：

```js
    > newtoy.propertyIsEnumerable('constructor'); 
    false 

```

原型链中传递下来的任何属性都不可枚举：

```js
    > newtoy.propertyIsEnumerable('price'); 
    false 

```

然而，要注意的是，如果你到达`prototype`中包含的对象并调用它的`propertyIsEnumerable()`方法，这样的属性是可枚举的。考虑以下代码：

```js
    > newtoy.constructor.prototype.propertyIsEnumerable('price'); 
    true 

```

## 使用`isPrototypeOf()`方法

对象也有`isPrototypeOf()`方法。这个方法告诉你特定的对象是否被用作另一个对象的原型。

让我们来看一个名为`monkey`的简单对象：

```js
    var monkey = {    
      hair: true,    
      feeds: 'bananas',    
      breathes: 'air'  
    }; 

```

现在，让我们创建一个`Human()`构造函数，并将其`prototype`属性指向`monkey`：

```js
    function Human(name) { 
      this.name = name; 
    } 
    Human.prototype = monkey; 

```

现在，如果你创建一个名为`george`的新`Human`对象，并询问`monkey`是`george`的原型吗？你会得到`true`：

```js
    > var george = new Human('George');  
    > monkey.isPrototypeOf(george); 
    true 

```

请注意，你必须知道或怀疑原型是谁，然后问你的原型是否是`monkey`？以确认你的怀疑。但是，如果你什么都不怀疑，你一无所知呢？你能否询问对象告诉你它的原型？答案是，在大多数浏览器中你不能，但在大多数浏览器中你可以。大多数最新的浏览器已经实现了 ES5 的一个补充，叫做`Object.getPrototypeOf()`。

```js
    > Object.getPrototypeOf(george).feeds; 
    "bananas" 
    > Object.getPrototypeOf(george) === monkey; 
    true 

```

对于一些没有`getPrototypeOf()`的 ES5 之前的环境，你可以使用特殊属性`__proto__`。

## 秘密的`__proto__`链接

正如你已经知道的，当你尝试访问当前对象中不存在的属性时，会查找`prototype`属性。

考虑另一个名为`monkey`的对象，并在使用`Human()`构造函数创建对象时将其用作原型：

```js
    > var monkey = { 
        feeds: 'bananas', 
        breathes: 'air' 
      }; 
    > function Human() {}  
    > Human.prototype = monkey; 

```

现在，让我们创建一个`developer`对象，并给它以下属性：

```js
    > var developer = new Human(); 
    > developer.feeds = 'pizza'; 
    > developer.hacks = 'JavaScript'; 

```

现在，让我们访问这些属性（例如，`hacks`是`developer`对象的一个属性）：

```js
    > developer.hacks; 
    "JavaScript" 

```

`feeds`属性也可以在对象中找到，如下：

```js
    > developer.feeds; 
    "pizza" 

```

`breathes`属性并不存在于`developer`对象的属性中，所以会查找原型，就好像有一个秘密链接或通道通向`prototype`对象：

```js
    > developer.breathes; 
    "air" 

```

在大多数现代 JavaScript 环境中，秘密链接被暴露为`__proto__`属性，即`proto`一词前后各有两个下划线：

```js
    > developer.__proto__ === monkey; 
    true 

```

你可以使用这个秘密属性进行学习，但在你的真实脚本中使用它并不是一个好主意，因为它并不在所有浏览器中都存在（特别是 IE），所以你的脚本不具备可移植性。

请注意，`__proto__`和`prototype`不同，`__proto__`是实例（对象）的属性，而`prototype`是用于创建这些对象的构造函数的属性：

```js
    > typeof developer.__proto__; 
    "object" 
    > typeof developer.prototype; 
    "undefined" 
    > typeof developer.constructor.prototype; 
    "object" 

```

再次强调，你应该只在学习或调试目的时使用`__proto__`。或者，如果你足够幸运，你的代码只需要在符合 ES5 的环境中工作，你可以使用`Object.getPrototypeOf()`。

# 增强内置对象

由内置构造函数创建的对象，如`Array`、`String`，甚至`Object`和`Function`，都可以通过原型进行增强。这意味着你可以向`Array`原型添加新方法，以便让它们对所有数组可用。让我们看看如何做到这一点。

在 PHP 中，有一个名为`in_array()`的函数，它告诉你一个值是否存在于数组中。在 JavaScript 中，没有`inArray()`方法，尽管在 ES5 中有`indexOf()`，你可以用它来达到相同的目的。因此，让我们实现它并添加到`Array.prototype`中，如下所示：

```js
    Array.prototype.inArray = function (needle) { 
      for (var i = 0, len = this.length; i < len; i++) { 
        if (this[i] === needle) { 
          return true; 
        } 
      } 
      return false; 
    }; 

```

现在，所有数组都可以访问这个新方法。让我们测试以下代码：

```js
    > var colors = ['red', 'green', 'blue']; 
    > colors.inArray('red'); 
    true 
    > colors.inArray('yellow'); 
    false 

```

这很简单！让我们再做一次。想象一下，你的应用程序经常需要将单词倒过来拼写，你觉得字符串对象应该有一个内置的`reverse()`方法。毕竟，数组有`reverse()`。你可以通过借用`Array.prototype.reverse()`来轻松地向`String`原型添加一个`reverse()`方法（在第四章的结尾有一个类似的练习，*对象*）：

```js
    String.prototype.reverse = function () { 
      return Array.prototype.reverse. 
               apply(this.split('')).join(''); 
    }; 

```

这段代码使用`split()`方法从字符串创建一个数组，然后在这个数组上调用`reverse()`方法，产生一个反转的数组。然后使用`join()`方法将结果数组转换回字符串。让我们测试一下新方法：

```js
    > "bumblebee".reverse(); 
      "eebelbmub"

```

## 增强内置对象 - 讨论

通过原型增强内置对象是一种强大的技术，你可以用它来塑造 JavaScript 的任何方式。但是，由于它的强大，你在使用这种方法之前应该仔细考虑你的选择。

原因是一旦你了解了 JavaScript，你期望它以相同的方式工作，无论你使用的是哪个第三方库或小部件。修改核心对象可能会让用户和代码维护者感到困惑，并产生意外的错误。

JavaScript 不断发展，浏览器供应商不断支持更多功能。今天你认为缺少的方法并决定添加到核心原型中的方法，明天可能就成为内置方法。在这种情况下，你的方法就不再需要了。此外，如果你已经编写了大量使用该方法的代码，并且你的方法与新的内置实现略有不同，会怎么样呢？

增强内置原型的最常见和可接受的用例是为旧浏览器添加对新功能的支持（这些功能已经由 ECMAScript 委员会标准化并在新浏览器中实现）。一个例子是在旧版本的 IE 中添加 ES5 方法。这些扩展被称为**shims**或**polyfills**。

在增强原型时，你首先要检查方法是否存在，然后再自己实现。这样，如果浏览器中存在原生实现，你就可以使用它。例如，让我们为字符串添加`trim()`方法，这是 ES5 中存在的方法，但在旧浏览器中缺少：

```js
    if (typeof String.prototype.trim !== 'function') { 
      String.prototype.trim = function () { 
        return this.replace(/^\s+|\s+$/g,''); 
      }; 
    } 
    > " hello ".trim(); 
    "hello" 

```

### 提示

**最佳实践**

如果你决定增强内置对象或其原型以添加新属性，首先要检查新属性是否存在。

## 原型陷阱

处理原型时需要考虑的两个重要行为是：

+   原型链是活跃的，除非你完全替换了`prototype`对象

+   `prototype.constructor`方法不可靠

让我们创建一个简单的构造函数和两个对象：

```js
    > function Dog() { 
        this.tail = true; 
      } 
    > var benji = new Dog(); 
    > var rusty = new Dog(); 

```

即使您已经创建了`benji`和`rusty`对象，您仍然可以向`Dog()`的原型添加属性，现有对象将可以访问新属性。让我们加入`say()`方法：

```js
    > Dog.prototype.say = function () { 
        return 'Woof!'; 
      }; 

```

两个对象都可以访问新方法：

```js
    > benji.say(); 
    "Woof!" 
     rusty.say(); 
    "Woof!" 

```

到目前为止，如果您咨询您的对象，询问它们是使用哪个构造函数创建的，它们将正确报告：

```js
    > benji.constructor === Dog; 
    true 
    > rusty.constructor === Dog; 
    true 

```

现在，让我们完全用全新的对象覆盖`prototype`对象：

```js
    > Dog.prototype = { 
        paws: 4, 
        hair: true 
      }; 

```

事实证明，旧对象无法访问新原型的属性；它们仍然保留指向旧原型对象的秘密链接，如下所示：

```js
    > typeof benji.paws; 
    "undefined" 
    > benji.say(); 
    "Woof!" 
    > typeof benji.__proto__.say; 
    "function" 
    > typeof benji.__proto__.paws; 
    "undefined" 

```

从现在开始创建的任何新对象都将使用更新后的原型，如下所示：

```js
    > var lucy = new Dog(); 
    > lucy.say(); 
    TypeError: lucy.say is not a function 
    > lucy.paws; 
    4 

```

秘密的`__proto__`链接指向新的原型对象，如下面的代码行所示：

```js
    > typeof lucy.__proto__.say; 
    "undefined" 
    > typeof lucy.__proto__.paws; 
    "number" 

```

现在新对象的`constructor`属性不再正确报告。您期望它指向`Dog()`，但实际上它指向`Object()`，如下例所示：

```js
    > lucy.constructor; 
    function Object() { [native code] } 
    > benji.constructor; 
    function Dog() { 
      this.tail = true; 
    } 

```

在完全覆盖原型后，您可以通过重置`constructor`属性轻松防止混淆，如下所示：

```js
    > function Dog() {} 
    > Dog.prototype = {}; 
    > new Dog().constructor === Dog; 
    false 
    > Dog.prototype.constructor = Dog; 
    > new Dog().constructor === Dog; 
    true 

```

### 提示

**最佳实践**

当您覆盖原型时，请记得重置`constructor`属性。

# 练习

让我们练习以下练习：

1.  创建一个名为`shape`的对象，该对象具有类型`property`和一个`getType()`方法。

1.  定义一个`Triangle()`构造函数，其原型是`shape`。使用`Triangle()`创建的对象应该有三个自有属性-`a`，`b`和`c`，表示三角形的边长。

1.  在原型中添加一个名为`getPerimeter()`的新方法。

1.  使用以下代码测试您的实现：

```js
        > var t = new Triangle(1, 2, 3); 
        > t.constructor === Triangle; 
               true 
        > shape.isPrototypeOf(t); 
               true 
        > t.getPerimeter(); 
               6 
        > t.getType(); 
               "triangle" 

```

1.  循环遍历`t`，仅显示您自己的属性和方法，而不是原型的。

1.  使以下代码工作：

```js
        > [1, 2, 3, 4, 5, 6, 7, 8, 9].shuffle(); 
          [2, 4, 1, 8, 9, 6, 5, 3, 7] 

```

# 总结

让我们总结一下您在本章学到的最重要的主题：

+   所有函数都有一个名为`prototype`的属性。最初，它包含一个空对象-一个没有任何自有属性的对象。

+   您可以向`prototype`对象添加属性和方法。您甚至可以完全替换它为您选择的对象。

+   当您使用函数作为构造函数创建对象（使用`new`）时，对象会得到一个指向构造函数原型的秘密链接，并且可以访问原型的属性。

+   对象的自有属性优先于具有相同名称的原型属性。

+   使用`hasOwnProperty()`方法区分对象的自有属性和`prototype`属性。

+   存在原型链。当您执行`foo.bar`时，如果您的`foo`对象没有名为`bar`的属性，JavaScript 解释器将在原型中查找`bar`属性。如果找不到，则会继续在原型的原型中查找，然后在原型的原型的原型中查找，一直到`Object.prototype`。

+   您可以增强内置构造函数的原型，并且所有对象都将看到您的添加。将一个函数分配给`Array.prototype.flip`，所有数组将立即获得一个`flip()`方法，就像`[1,2,3].flip()`一样。但是，请检查您要添加的方法/属性是否已经存在，以便为您的脚本未来保值。


# 第七章：继承

如果您回到第一章 *面向对象的 JavaScript*，并回顾*面向对象编程*部分，您会发现您已经知道如何将大部分应用到 JavaScript 中。您知道对象、方法和属性是什么。您知道 ES5 中没有类，尽管您可以使用构造函数来实现它们。ES6 引入了类的概念；我们将在下一章详细了解 ES6 类的工作原理。封装？是的，对象封装了数据和处理数据的方法（方法）。聚合？当然，一个对象可以包含其他对象。事实上，这几乎总是这种情况，因为方法是函数，函数也是对象。

现在，让我们专注于继承部分。这是最有趣的特性之一，因为它允许您重用现有的代码，从而促进懒惰，这很可能是最初吸引人类物种进行计算机编程的原因。

JavaScript 是一种动态语言，通常有多种方法可以实现任何给定的任务。继承也不例外。在本章中，您将看到一些常见的实现继承的模式。对这些模式有很好的理解将帮助您选择合适的模式，或者根据您的任务、项目或风格选择合适的混合模式。

# 原型链

让我们从实现继承的默认方式开始 - 通过原型进行继承链。

正如您已经知道的，每个函数都有一个`prototype`属性，指向一个对象。当使用`new`运算符调用函数时，将创建并返回一个对象。这个新对象有一个指向`prototype`对象的秘密链接。秘密链接（在某些环境中称为`__proto__`）允许使用`prototype`对象的方法和属性，就好像它们属于新创建的对象一样。

`prototype`对象只是一个普通对象，因此它也有指向它的原型的秘密链接。因此，创建了一个称为原型链的链：

![原型链](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/proto.jpg)

在这个示例中，对象**A**包含许多属性。其中一个属性是隐藏的`__proto__`属性，它指向另一个对象**B**。**B**的`__proto__`属性指向**C**。这个链以`Object.prototype`对象结束，这是祖父，每个对象都从它继承。

这些都是很好知道的，但它如何帮助你呢？实际的一面是，当对象**A**缺少一个属性，但**B**有它时，**A**仍然可以访问这个属性作为它自己的。如果**B**也没有所需的属性，但**C**有，同样适用。这就是继承发生的方式 - 一个对象可以访问沿着继承链找到的任何属性。

在本章中，您将看到使用以下层次结构的不同示例 - 一个通用的`Shape`父类被一个`2D shape`继承，然后被任意数量的特定的二维形状继承，比如三角形、矩形等等。

## 原型链示例

原型链是实现继承的默认方式。为了实现层次结构，让我们定义三个构造函数：

```js
    function Shape(){ 
    this.name = 'Shape'; 
    this.toString = function () { 
        return this.name; 
      }; 
    } 

    function TwoDShape(){ 
      this.name = '2D shape'; 
    } 

    function Triangle(side, height){ 
      this.name = 'Triangle'; 
      this.side = side; 
      this.height = height; 
      this.getArea = function () { 
        return this.side * this.height / 2; 
      }; 
    } 

```

执行继承魔术的代码如下：

```js
    TwoDShape.prototype = new Shape(); 
    Triangle.prototype = new TwoDShape(); 

```

这里发生了什么？您获取了`TwoDShape`的`prototype`属性中包含的对象，并且不是增加个别属性，而是完全用另一个对象覆盖它，该对象是通过使用`new`调用`Shape()`构造函数创建的。对`Triangle`也可以遵循相同的过程-它的原型被`new TwoDShape()`创建的对象所取代。重要的是要记住 JavaScript 使用对象而不是类。您需要使用`new Shape()`构造函数创建一个实例，然后才能继承其属性；您不直接从`Shape()`继承。此外，在继承后，您可以修改`Shape()`构造函数，覆盖它，甚至删除它，这不会对`TwoDShape`产生影响，因为您只需要一个实例来继承。

正如您从上一章中所知道的，重写原型（而不仅仅是向其添加属性）会对`constructor`属性产生副作用。因此，在继承后重置`constructor`属性是一个好主意。考虑以下示例：

```js
    TwoDShape.prototype.constructor = TwoDShape; 
    Triangle.prototype.constructor = Triangle; 

```

现在，让我们测试一下到目前为止发生了什么。创建一个`Triangle`对象并调用其自己的`getArea()`方法可以正常工作：

```js
    >var my = new Triangle(5, 10); 
    >my.getArea(); 
    25 

```

尽管`my`对象没有自己的`toString()`方法，但它继承了一个，您可以调用它。请注意，继承的方法`toString()`将`this`对象绑定到`my`：

```js
    >my.toString(); 
    "Triangle" 

```

当您调用`my.toString()`时，考虑一下 JavaScript 引擎的操作：

+   它循环遍历`my`的所有属性，并没有找到名为`toString()`的方法。

+   它查看`my.__proto__`指向的对象，这个对象是在继承过程中创建的`new TwoDShape()`实例。

+   现在，JavaScript 引擎循环遍历`TwoDShape`的实例，并没有找到`toString()`方法。然后它检查该对象的`__proto__`。这一次，`__proto__`指向由`new Shape()`创建的实例。

+   检查`new Shape()`的实例，最终找到了`toString()`。

+   此方法在`my`的上下文中被调用，这意味着`this`指向`my`。

如果您问`my`，你的构造函数是谁？，它会正确报告，因为在继承后重置了`constructor`属性：

```js
    >my.constructor === Triangle; 
    true 

```

使用`instanceof`运算符，您可以验证`my`是所有三个构造函数的实例：

```js
    > my instanceof Shape; 
    true 
    > my instanceofTwoDShape; 
    true 
    > my instanceof Triangle; 
    true 
    > my instanceof Array; 
    false 

```

当您通过传递`my`调用`isPrototypeOf()`时，会发生相同的情况：

```js
    >Shape.prototype.isPrototypeOf(my); 
    true 
    >TwoDShape.prototype.isPrototypeOf(my); 
    true 
    >Triangle.prototype.isPrototypeOf(my); 
    true 
    >String.prototype.isPrototypeOf(my); 
    false 

```

您还可以使用其他两个构造函数创建对象。使用`new TwoDShape()`创建的对象也会继承自`Shape()`继承的`toString()`方法：

```js
    >var td = new TwoDShape(); 
    >td.constructor === TwoDShape; 
    true 
    >td.toString(); 
    "2D shape" 
    >var s = new Shape(); 
    >s.constructor === Shape; 
    true 

```

## 将共享属性移动到原型

当您使用构造函数创建对象时，使用`this`添加自己的属性。在属性跨实例不变的情况下，这可能效率低下。在前面的示例中，`Shape()`定义如下：

```js
    function Shape(){ 
    this.name = 'Shape'; 
    } 

```

这意味着每次使用`new Shape()`创建新对象时，都会创建一个新的`name`属性并将其存储在内存中的某个位置。另一种选择是将`name`属性添加到原型中，并在所有实例之间共享：

```js
    function Shape() {} 
    Shape.prototype.name = 'Shape'; 

```

现在，每次使用`new Shape()`创建对象时，该对象都不会获得自己的`name`属性，而是使用添加到原型中的属性。这更有效，但您应该只对不会从一个实例更改为另一个实例的属性使用它。方法非常适合这种共享。

通过将所有方法和适当的属性添加到`prototype`来改进前面的示例。在`Shape()`和`TwoDShape()`的情况下，一切都是共享的：

```js
    // constructor 
    function Shape() {} 

    // augment prototype 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.name; 
    }; 

    // another constructor 
    function TwoDShape() {} 

    // take care of inheritance 
    TwoDShape.prototype = new Shape(); 
    TwoDShape.prototype.constructor = TwoDShape; 

    // augment prototype 
    TwoDShape.prototype.name = '2D shape'; 

```

如您所见，您必须先处理继承，然后再增加原型。否则，当您继承时，添加到`TwoDShape.prototype`的任何内容都会被清除。

`Triangle`构造函数有点不同，因为它创建的每个对象都是一个新的三角形，可能具有不同的尺寸。因此，最好将`side`和`height`作为自有属性，并共享其余部分。例如，`getArea()`方法是相同的，无论每个三角形的实际尺寸如何。同样，首先进行继承，然后增加原型：

```js
    function Triangle(side, height) { 
    this.side = side; 
    this.height = height; 
    } 
    // take care of inheritance 
    Triangle.prototype = new TwoDShape(); 
    Triangle.prototype.constructor = Triangle; 

    // augment prototype 
    Triangle.prototype.name = 'Triangle'; 
    Triangle.prototype.getArea = function () { 
    return this.side * this.height / 2; 
    }; 

```

所有先前的测试代码都完全相同。这是一个例子：

```js
    >var my = new Triangle(5, 10); 
    >my.getArea(); 
    25 
    >my.toString(); 
    "Triangle" 

```

调用`my.toString()`时，只有一个微小的幕后差异。不同之处在于在找到`Shape.prototype`之前，需要进行一次额外的查找，而不是在`new Shape()`实例中，就像在先前的示例中一样。

您还可以使用`hasOwnProperty()`来查看自有属性与原型链中的属性之间的差异：

```js
    >my.hasOwnProperty('side'); 
    true 
    >my.hasOwnProperty('name'); 
    false 

```

先前示例中对`isPrototypeOf()`和`instanceof`运算符的调用方式完全相同：

```js
    >TwoDShape.prototype.isPrototypeOf(my); 
    true 
    > my instanceof Shape; 
    true 

```

# 只继承原型

如前所述，出于效率考虑，应将可重复使用的属性和方法添加到原型中。如果这样做，那么只继承原型是一个好主意，因为所有可重复使用的代码都在那里。这意味着继承`Shape.prototype`对象比继承使用`new Shape()`创建的对象更好。毕竟，`new Shape()`只会给出自有形状属性，这些属性不打算被重复使用（否则，它们将在原型中）。通过这样做，您可以获得更高的效率：

+   不仅仅为了继承而创建新对象

+   在运行时查找`toString()`时减少查找次数

例如，这是更新后的代码；更改部分已突出显示：

```js
    function Shape() {} 
    // augment prototype 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.name; 
    }; 

    function TwoDShape() {} 
    // take care of inheritance 
    TwoDShape.prototype = Shape.prototype; 
    TwoDShape.prototype.constructor = TwoDShape; 
    // augment prototype 
    TwoDShape.prototype.name = '2D shape'; 

    function Triangle(side, height) { 
      this.side = side; 
      this.height = height; 
    } 

    // take care of inheritance 
    Triangle.prototype = TwoDShape.prototype; 
    Triangle.prototype.constructor = Triangle; 
    // augment prototype 
    Triangle.prototype.name = 'Triangle'; 
    Triangle.prototype.getArea = function () { 
      return this.side * this.height / 2; 
    }; 

```

测试代码给出了相同的结果：

```js
    >var my = new Triangle(5, 10); 
    >my.getArea(); 
    25 
    >my.toString(); 
    "Triangle" 

```

调用`my.toString()`时查找的差异是什么？首先，像往常一样，JavaScript 引擎会查找`my`对象本身的`toString()`方法。引擎找不到这样的方法，所以它会检查原型。原型指向与`TwoDShape`的原型和`Shape.prototype`指向的相同对象。请记住，对象不是按值复制的，而是按引用复制的。因此，查找只是一个两步过程，而不是四步（在上一个示例中）或三步（在第一个示例中）。

简单地复制原型更有效，但会产生副作用，因为所有子代和父代的原型都指向相同的对象，当子代修改原型时，父代和兄弟也会得到更改。

看看下面这行：

```js
    Triangle.prototype.name = 'Triangle'; 

```

它更改了`name`属性，因此实际上也更改了`Shape.prototype.name`。如果使用`new Shape()`创建实例，其`name`属性会显示为`"Triangle"`：

```js
    >var s = new Shape(); 
    >s.name; 
    "Triangle" 

```

这种方法更有效，但可能不适用于所有用例。

## 临时构造函数 - new F()

解决先前概述的问题的一个解决方案是，所有原型都指向相同对象，父代获取子代的属性，是使用中介来打破链条。中介是一个临时构造函数的形式。创建一个空函数`F()`并将其`prototype`设置为父构造函数的原型，允许您调用`new F()`并创建没有自有属性但从父代`prototype`继承一切的对象。

让我们看一下修改后的代码：

```js
    function Shape() {} 
    // augment prototype 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
    return this.name; 
    }; 

    function TwoDShape() {} 
    // take care of inheritance 
    var F = function () {}; 
    F.prototype = Shape.prototype; 
    TwoDShape.prototype = new F(); 
    TwoDShape.prototype.constructor = TwoDShape; 
    // augment prototype 
    TwoDShape.prototype.name = '2D shape'; 

    function Triangle(side, height) { 
    this.side = side; 
    this.height = height; 
    } 

    // take care of inheritance 
    var F = function () {}; 
    F.prototype = TwoDShape.prototype; 
    Triangle.prototype = new F(); 
    Triangle.prototype.constructor = Triangle; 
    // augment prototype 
    Triangle.prototype.name = 'Triangle'; 
    Triangle.prototype.getArea = function () { 
    return this.side * this.height / 2; 
    }; 

```

创建`my`三角形并测试方法：

```js
    >var my = new Triangle(5, 10); 
    >my.getArea(); 
    25 
    >my.toString(); 
    "Triangle" 

```

使用这种方法，原型链保持不变：

```js
    >my.__proto__ === Triangle.prototype; 
    true 
    >my.__proto__.constructor === Triangle; 
    true 
    >my.__proto__.__proto__ === TwoDShape.prototype; 
    true 
    >my.__proto__.__proto__.__proto__.constructor === Shape; 
    true 

```

此外，父代的属性不会被子代覆盖：

```js
    >var s = new Shape(); 
    >s.name; 
    "Shape" 
    >"I am a " + new TwoDShape(); // calling toString() 
    "I am a 2D shape" 

```

同时，这种方法支持只继承原型应该继承的属性和方法的想法，而不应该继承自有属性。这背后的原理是，自有属性可能太具体，无法重复使用。

# Uber - 从子对象访问父对象

经典的面向对象语言通常有一个特殊的语法，让你可以访问父类，也称为超类。当子类想要一个方法，做父类方法的所有事情，再加上一些额外的东西时，这可能很方便。在这种情况下，子类用相同的名称调用父类的方法，并处理结果。

在 JavaScript 中，没有这样的特殊语法，但实现相同的功能非常简单。让我们重写上一个例子，同时处理继承，并创建一个指向父类`prototype`对象的`uber`属性：

```js
    function Shape() {} 
    // augment prototype 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
    var const = this.constructor; 
    returnconst.uber 
        ? this.const.uber.toString() + ', ' + this.name 
        : this.name; 
    }; 

    function TwoDShape() {} 
    // take care of inheritance 
    var F = function () {}; 
    F.prototype = Shape.prototype; 
    TwoDShape.prototype = new F(); 
    TwoDShape.prototype.constructor = TwoDShape; 
    TwoDShape.uber = Shape.prototype; 
    // augment prototype 
    TwoDShape.prototype.name = '2D shape'; 

    function Triangle(side, height) { 
    this.side = side; 
    this.height = height; 
    } 

    // take care of inheritance 
    var F = function () {}; 
    F.prototype = TwoDShape.prototype; 
    Triangle.prototype = new F(); 
    Triangle.prototype.constructor = Triangle; 
    Triangle.uber = TwoDShape.prototype; 
    // augment prototype 
    Triangle.prototype.name = 'Triangle'; 
    Triangle.prototype.getArea = function () { 
    return this.side * this.height / 2; 
    }; 

```

这里的新东西是：

+   一个新的`uber`属性指向父类的`prototype`

+   更新的`toString()`方法

以前，`toString()`只返回`this.name`。现在，除此之外，还有一个检查来看`this.constructor.uber`是否存在，如果存在，首先调用它的`toString()`。`this.constructor`是函数本身，`this.constructor.uber`指向父类的`prototype`。结果是，当你为`Triangle`实例调用`toString()`时，所有原型链上的`toString()`方法都会被调用：

```js
    >var my = new Triangle(5, 10); 
    >my.toString(); 
    "Shape, 2D shape, Triangle" 

```

`uber`属性的名称本来可以是 superclass，但这会暗示 JavaScript 有类。理想情况下，它本来可以是 super（就像 Java 中一样），但 super 在 JavaScript 中是一个保留字。Douglas Crockford 建议的德语单词 uber 的意思与 super 差不多，你不得不承认，听起来非常酷。

# 将继承部分隔离成一个函数

让我们将上一个例子中处理所有继承细节的代码移到一个可重用的`extend()`函数中：

```js
    function extend(Child, Parent) { 
    var F = function () {}; 
    F.prototype = Parent.prototype; 
    Child.prototype = new F(); 
    Child.prototype.constructor = Child; 
    Child.uber = Parent.prototype; 
    } 

```

使用这个函数（或你自己定制的版本）可以帮助你保持代码在重复的继承相关任务方面的整洁。这样，你可以通过简单地使用以下两行代码来继承：

```js
    extend(TwoDShape, Shape); 
    extend(Triangle, TwoDShape); 

```

让我们看一个完整的例子：

```js
    // inheritance helper 
    function extend(Child, Parent) { 
      var F = function () {}; 
      F.prototype = Parent.prototype; 
      Child.prototype = new F(); 
      Child.prototype.constructor = Child; 
      Child.uber = Parent.prototype; 
    } 

    // define -> augment 
    function Shape() {} 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.constructor.uber 
        ? this.constructor.uber.toString() + ', ' + this.name 
        : this.name; 
    }; 

    // define -> inherit -> augment 
    function TwoDShape() {} 
    extend(TwoDShape, Shape); 
    TwoDShape.prototype.name = '2D shape'; 

    // define 
    function Triangle(side, height) { 
      this.side = side; 
      this.height = height; 
    } 
    // inherit 
    extend(Triangle, TwoDShape); 
    // augment 
    Triangle.prototype.name = 'Triangle'; 
    Triangle.prototype.getArea = function () { 
      return this.side * this.height / 2; 
    }; 

```

让我们测试以下代码：

```js
    > new Triangle().toString(); 
    "Shape, 2D shape, Triangle" 

```

# 复制属性

现在，让我们尝试一个稍微不同的方法。由于继承都是关于重用代码，你能否简单地从一个对象复制你喜欢的属性到另一个对象？或者从父类到子类？保持与前面的`extend()`函数相同的接口，你可以创建一个`extend2()`函数，它接受两个构造函数，并将父类的`prototype`的所有属性复制到子类的`prototype`。当然，这也会复制方法，因为方法只是恰好是函数的属性：

```js
    function extend2(Child, Parent) { 
      var p = Parent.prototype; 
      var c = Child.prototype; 
      for (var i in p) { 
        c[i] = p[i]; 
      } 
      c.uber = p; 
    } 

```

正如你所看到的，通过属性的简单循环就可以完成。与前面的例子一样，如果你想要从子类方便地访问父类的方法，可以设置一个`uber`属性。不过与前面的例子不同的是，在这里，不需要重置`Child.prototype.constructor`，因为这里子类的`prototype`是增强的，而不是完全被覆盖。所以，`constructor`属性指向初始值。

与前一种方法相比，这种方法有点低效，因为子类的`prototype`的属性被复制，而不是在执行过程中通过原型链查找。请记住，这只对包含原始类型的属性有效。所有对象（包括函数和数组）都不会被复制，因为这些只是通过引用传递的。

让我们看一个使用两个构造函数`Shape()`和`TwoDShape()`的例子。`Shape()`函数的`prototype`对象包含一个原始属性`name`和一个非原始属性`toString()`：

```js
    var Shape = function () {}; 
    var TwoDShape = function () {}; 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.uber 
        ? this.uber.toString() + ', ' + this.name 
        : this.name; 
    }; 

```

如果你用`extend()`继承，用`TwoDShape()`创建的对象和它的原型都不会有自己的`name`属性，但它们可以访问继承的那个：

```js
    > extend(TwoDShape, Shape); 
    >var td = new TwoDShape(); 
    >td.name; 
    "Shape" 
    >TwoDShape.prototype.name; 
    "Shape" 
    >td.__proto__.name; 
    "Shape" 
    >td.hasOwnProperty('name'); 
    false 
    > td.__proto__.hasOwnProperty('name'); 
    false 

```

然而，如果你用`extend2()`继承，`TwoDShape()`的原型会得到自己的`name`属性的副本。它还会得到自己的`toString()`的副本，但这只是一个引用，所以函数不会被重新创建第二次：

```js
    >extend2(TwoDShape, Shape); 
    >var td = new TwoDShape(); 
    > td.__proto__.hasOwnProperty('name'); 
    true 
    > td.__proto__.hasOwnProperty('toString'); 
    true 
    > td.__proto__.toString === Shape.prototype.toString; 
    true 

```

如您所见，两个`toString()`方法是相同的函数对象。这是好的，因为这意味着不会创建不必要的方法副本。

因此，您可以说`extend2()`比`extend()`效率低，因为它重新创建了原型的属性。然而，这并不是很糟糕，因为只有原始数据类型被复制。此外，在原型链查找期间，这对于减少链条链接是有益的，因为在找到属性之前需要跟随的链条更少。

再次看一下`uber`属性。这次，出于变化的原因，它设置在`Parent`对象的原型`p`上，而不是`Parent`构造函数上。这就是为什么`toString()`使用它作为`this.uber`而不是`this.constructor.uber`。这只是一个说明，您可以以任何您认为合适的方式塑造您喜欢的继承模式。让我们来测试一下：

```js
    >td.toString(); 
    "Shape, Shape" 

```

`TwoDShape`没有重新定义`name`属性，因此会重复。它可以随时这样做，而且（原型链是活动的）所有实例都会看到更新：

```js
    >TwoDShape.prototype.name = "2D shape"; 
    >td.toString(); 
    "Shape, 2D shape" 

```

# 引用复制时要注意

对象（包括函数和数组）被引用复制的事实有时可能会导致您意想不到的结果。

让我们创建两个构造函数，并向第一个的原型添加属性：

```js
    > function Papa() {} 
    >function Wee() {} 
    >Papa.prototype.name = 'Bear';  
    >Papa.prototype.owns = ["porridge", "chair", "bed"]; 

```

现在，让我们让`Wee`从`Papa`继承（`extend()`或`extend2()`都可以）：

```js
    >extend2(Wee, Papa); 

```

使用`extend2()`，`Wee`函数的原型继承了`Papa.prototype`的属性作为自己的属性：

```js
    >Wee.prototype.hasOwnProperty('name'); 
    true 
    >Wee.prototype.hasOwnProperty('owns'); 
    true 

```

`name`属性是原始的，因此会创建一个新的副本。`owns`属性是一个数组对象，因此它是引用复制的：

```js
    >Wee.prototype.owns; 
    ["porridge", "chair", "bed"] 
    >Wee.prototype.owns=== Papa.prototype.owns; 
    true 

```

更改`Wee`函数的`name`副本不会影响`Papa`：

```js
    >Wee.prototype.name += ', Little Bear'; 
    "Bear, Little Bear" 
    >Papa.prototype.name; 
    "Bear" 

```

然而，更改`Wee`函数的`owns`属性会影响`Papa`，因为两个属性指向内存中的同一个数组：

```js
    >Wee.prototype.owns.pop(); 
    "bed" 
    >Papa.prototype.owns; 
    ["porridge", "chair"] 

```

当您完全用另一个对象（而不是修改现有对象）覆盖`Wee`函数的`owns`副本时，情况就不同了。在这种情况下，`Papa.owns`继续指向旧对象，而`Wee.owns`指向新对象：

```js
    >Wee.prototype.owns= ["empty bowl", "broken chair"]; 
    >Papa.prototype.owns.push('bed'); 
    >Papa.prototype.owns; 
    ["porridge", "chair", "bed"] 

```

将对象视为在内存中创建和存储的东西。变量和属性仅仅指向这个位置，因此当您将全新的对象分配给`Wee.prototype.owns`时，您实质上是在说-嘿，忘记这个旧对象，把你的指针移到这个新对象上。

以下图表说明了如果你想象内存是一堆对象（就像一堵砖墙），你指向（引用）其中一些对象会发生什么：

+   创建了一个新对象，并且**A**指向它。

+   创建了一个新变量**B**，并且使其等于**A**，这意味着它现在指向**A**指向的相同位置。

+   使用**B**句柄（指针）更改了属性颜色。砖头现在是白色的。`A.color === "white"`的检查将返回 true。

+   创建了一个新对象，并且**B**变量/指针被回收，指向了新对象。**A**和**B**现在指向内存堆的不同部分。它们没有共同之处，对其中一个的更改不会影响另一个：

![引用复制时要注意](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_07_002.jpg)

如果您想解决对象被引用复制的问题，请考虑深复制，本章后面会有描述。

# 对象从对象继承

到目前为止，本章中的所有示例都假设您使用构造函数创建对象，并且希望使用一个构造函数创建的对象继承来自另一个构造函数的属性。但是，您也可以创建对象而不使用构造函数的帮助，只使用对象文字，这实际上是更少的输入。那么，如何继承这些呢？

在 Java 或 PHP 中，你定义类并让它们继承自其他类。这就是为什么你会看到经典这个词，因为面向对象的功能来自于类的使用。在 JavaScript 中，没有类，所以来自经典背景的程序员会使用构造函数，因为构造函数是他们习惯的最接近的东西。此外，JavaScript 提供了`new`运算符，这可能会进一步暗示 JavaScript 类似于 Java。事实上，最终一切都归结为对象。本章的第一个例子就是用这种语法：

```js
    Child.prototype = new Parent(); 

```

在这里，`Child`构造函数（或类，如果你愿意的话）继承自`Parent`。然而，这是通过使用`new Parent()`创建一个对象并从中继承的。这也被称为**伪经典继承模式**，因为它类似于经典继承，尽管实际上并不是（没有涉及类）。

那么，为什么不摆脱中间人（构造函数/类），让对象直接继承对象呢？在`extend2()`中，父`prototype`对象的属性被复制为子`prototype`对象的属性。这两个原型本质上只是对象。忘记原型和构造函数，你可以简单地将一个对象的所有属性复制到另一个对象中。

你已经知道对象可以作为一个空白画布开始，没有任何自己的属性，使用`var o = {};`，然后稍后再添加属性。然而，你可以通过复制现有对象的所有属性来开始，而不是从头开始。这里有一个函数可以做到这一点：它接受一个对象并返回一个新的副本：

```js
    function extendCopy(p) { 
      var c = {}; 
      for (var i in p) { 
        c[i] = p[i]; 
      } 
      c.uber = p; 
      return c; 
    } 

```

简单地复制所有属性是一种简单的模式，它被广泛使用。让我们看看这个函数的作用。你首先有一个基础对象：

```js
    var shape = { 
    name: 'Shape', 
    toString: function () { 
    return this.name; 
    } 
    }; 

```

为了创建一个建立在旧对象基础上的新对象，你可以调用`extendCopy()`函数，它会返回一个新对象。然后，你可以用额外的功能来增强新对象：

```js
    var twoDee = extendCopy(shape); 
    twoDee.name = '2D shape'; 
    twoDee.toString = function () { 
    return this.uber.toString() + ', ' + this.name; 
    }; 

```

这里有一个继承`2D 形状`对象的三角形对象：

```js
    var triangle = extendCopy(twoDee); 
    triangle.name = 'Triangle'; 
    triangle.getArea = function () { 
    return this.side * this.height / 2; 
    }; 

```

例如，使用三角形：

```js
    >triangle.side = 5; 
    >triangle.height = 10; 
    >triangle.getArea(); 
    25 
    >triangle.toString(); 
    "Shape, 2D shape, Triangle" 

```

这种方法可能的一个缺点是初始化新的`triangle`对象的方式有点冗长，你需要手动设置`side`和`height`的值，而不是将它们作为值传递给构造函数。然而，这很容易通过一个名为`init()`（或者如果你来自 PHP，叫`__construct()`）的函数来解决，它充当构造函数并接受初始化参数。另外，让`extendCopy()`接受两个参数，一个是要继承的对象，另一个是要添加到副本中的属性的对象字面量。换句话说，就是合并两个对象。

# 深拷贝

之前讨论的`extendCopy()`函数创建了一个被称为浅拷贝的对象，就像之前的`extend2()`一样。浅拷贝的相反就是深拷贝。如前所述（在本章的*通过引用复制时要注意*部分），当你复制对象时，你只复制指向存储对象的内存位置的指针。这就是浅拷贝的情况。如果你在副本中修改一个对象，你也会修改原始对象。深拷贝避免了这个问题。

深拷贝的实现方式与浅拷贝相同-你遍历属性并逐个复制它们。然而，当你遇到指向对象的属性时，你会再次调用`deepcopy`函数：

```js
    function deepCopy(p, c) { 
      c = c || {}; 
      for (var i in p) { 
        if (p.hasOwnProperty(i)) { 
          if (typeof p[i] === 'object') { 
            c[i] = Array.isArray(p[i]) ? [] : {}; 
    deepCopy(p[i], c[i]); 
          } else { 
            c[i] = p[i]; 
          } 
        } 
      } 
      return c; 
    } 

```

让我们创建一个具有数组和子对象作为属性的对象：

```js
    var parent = { 
      numbers: [1, 2, 3], 
      letters: ['a', 'b', 'c'], 
      obj: { 
        prop: 1 
      }, 
      bool: true 
    }; 

```

让我们通过创建一个深拷贝和一个浅拷贝来测试一下。与浅拷贝不同，当你更新深拷贝的`numbers`属性时，原始对象不会受到影响：

```js
    >var mydeep = deepCopy(parent); 
    >var myshallow = extendCopy(parent); 
    >mydeep.numbers.push(4,5,6); 
    6 
    >mydeep.numbers; 
    [1, 2, 3, 4, 5, 6] 
    >parent.numbers; 
    [1, 2, 3] 
    >myshallow.numbers.push(10); 
    4 
    >myshallow.numbers; 
    [1, 2, 3, 10] 
    >parent.numbers; 
    [1, 2, 3, 10] 
    >mydeep.numbers; 
    [1, 2, 3, 4, 5, 6] 

```

关于`deepCopy()`函数的两个注意事项：

+   使用`hasOwnProperty()`过滤非自有属性总是一个好主意，以确保你不会带上别人对核心原型的添加。

+   `Array.isArray()`自 ES5 以来存在，因为否则很难区分真实数组和对象。最佳的跨浏览器解决方案（如果需要在 ES3 浏览器中定义`isArray()`）看起来有点奇怪，但它有效：

```js
    if (Array.isArray !== "function") { 
    Array.isArray = function (candidate) { 
        return  
    Object.prototype.toString.call(candidate) ===  
    '[object Array]'; 
    }; 
    } 

```

# 使用 object()方法

基于对象从对象继承的思想，Douglas Crockford 提倡使用一个接受对象并返回一个具有父对象作为原型的新对象的`object()`函数：

```js
    function object(o) { 
    function F() {} 
    F.prototype = o; 
    return new F(); 
    } 

```

如果您需要访问`uber`属性，可以修改`object()`函数如下：

```js
    function object(o) { 
    var n; 
    function F() {} 
    F.prototype = o; 
    n = new F(); 
    n.uber = o; 
    return n; 
    } 

```

使用`this`函数与使用`extendCopy()`相同，您可以从诸如`twoDee`之类的对象创建一个新对象，然后继续增强新对象：

```js
    var triangle = object(twoDee); 
    triangle.name = 'Triangle'; 
    triangle.getArea = function () { 
    return this.side * this.height / 2; 
    }; 

```

新的三角形仍然表现得一样：

```js
    >triangle.toString(); 
    "Shape, 2D shape, Triangle" 

```

这种模式也被称为**原型继承**，因为您使用父对象作为子对象的原型。它也被 ES5 采用并构建，称为`Object.create()`。这里是一个例子：

```js
    >var square = Object.create(triangle); 

```

# 使用原型继承和复制属性的混合

当您使用继承时，您很可能希望使用已经存在的功能，然后在此基础上构建。这意味着通过从现有对象继承创建一个新对象，然后添加其他方法和属性。您可以使用刚刚讨论的最后两种方法的组合来一次性完成这个功能。

您可以：

+   使用原型继承来使用现有对象作为新对象的原型

+   将另一个对象的所有属性复制到新创建的对象中：

```js
    function objectPlus(o, stuff) { 
      var n; 
      function F() {} 
      F.prototype = o; 
      n = new F(); 
      n.uber = o; 

     for (var i in stuff) { 
        n[i] = stuff[i]; 
        } 
      return n; 
    } 

```

此函数接受一个要继承的对象`o`和另一个具有要复制的附加方法和属性的对象`stuff`。让我们看看这个实际操作。

从基本`shape`对象开始：

```js
    var shape = { 
    name: 'Shape', 
    toString: function () { 
    return this.name; 
    } 
    }; 

```

通过继承形状并添加更多属性来创建一个 2D 对象。附加属性只是使用对象文字创建的：

```js
    var twoDee = objectPlus(shape, { 
      name: '2D shape', 
      toString: function () { 
        return this.uber.toString() + ', ' + this.name; 
      } 
    }); 

```

现在，让我们创建一个从 2D 继承并添加更多属性的`triangle`对象：

```js
    var triangle = objectPlus(twoDee, { 
      name: 'Triangle', 
      getArea: function () { return this.side * this.height / 2; 
     }, 
      side: 0, 
      height: 0 
    }); 

```

您可以通过创建具有定义的`side`和`height`的具体三角形`my`来测试所有这些工作：

```js
    var my = objectPlus(triangle, { 
      side: 4, height: 4 
    }); 
    >my.getArea(); 
    8 
    >my.toString(); 
    "Shape, 2D shape, Triangle, Triangle" 

```

在执行`toString()`时，这里的区别在于`Triangle`名称重复了两次。这是因为具体实例是通过继承`triangle`创建的，所以还有一层继承。您可以给新实例一个名称：

```js
    >objectPlus(triangle, { 
      side: 4,  
      height: 4, 
      name: 'My 4x4' 
    }).toString(); 
    "Shape, 2D shape, Triangle, My 4x4" 

```

这个`objectPlus()`甚至更接近 ES5 的`Object.create()`；只是 ES5 的`Object.create()`使用称为属性描述符的东西来获取附加属性（第二个参数）（在附录 C 中讨论，*内置对象*）。

# 多重继承

多重继承是指一个子对象从多个父对象继承。一些面向对象的语言原生支持多重继承，而一些不支持。您可以从两方面进行论证，即多重继承很方便，或者它是不必要的，使应用程序设计复杂化，并且最好使用继承链。在漫长而寒冷的冬夜中留下多重继承的利弊讨论，让我们看看您如何在 JavaScript 中实际操作。

实现可以简单地将继承的概念扩展为从无限数量的输入对象继承。

让我们创建一个接受任意数量输入对象的`multi()`函数。您可以在另一个循环中包装复制属性的循环，该循环通过作为函数`arguments`传递的所有对象：

```js
    function multi() { 
      var n = {}, stuff, j = 0, len = arguments.length; 
      for (j = 0; j <len; j++) { 
        stuff = arguments[j]; 
        for (var i in stuff) { 
          if (stuff.hasOwnProperty(i)) { 
            n[i] = stuff[i]; 
          } 
        } 
      } 
      return n; 
    } 

```

让我们通过创建三个对象-`shape`，`twoDee`和第三个未命名的对象来测试这一点。然后，创建一个`triangle`对象意味着调用`multi()`并传递所有三个对象：

```js
    var shape = { 
      name: 'Shape', 
      toString: function () { 
        return this.name; 
      } 
    }; 

    var twoDee = { 
      name: '2D shape', 
      dimensions: 2 
    }; 

    var triangle = multi(shape, twoDee, { 
      name: 'Triangle', 
      getArea: function () { 
        return this.side * this.height / 2; 
      }, 
      side: 5, 
      height: 10 
    }); 

```

这样行得通吗？让我们看看。`getArea()`方法应该是自己的属性，`dimensions`应该来自`twoDee`，`toString()`应该来自`shape`：

```js
    >triangle.getArea(); 
    25 
    >triangle.dimensions; 
    2 
    >triangle.toString(); 
    "Triangle" 

```

请记住，`multi()`按照输入对象出现的顺序循环，如果发生两个对象具有相同的属性，最后一个将获胜。

## 混合

你可能会遇到混入这个术语。把混入想象成一个提供一些有用功能的对象，但不是用来被子对象继承和扩展的。前面概述的多重继承方法可以被认为是混入思想的一种实现。当你创建一个新对象时，你可以选择任何其他对象混入到你的新对象中。通过将它们全部传递给`multi()`，你可以获得它们所有的功能，而不使它们成为继承树的一部分。

# 寄生式继承

如果你喜欢在 JavaScript 中有各种不同的实现继承的方式，并且渴望了解更多，这里有另一种方式。这种模式，由道格拉斯·克罗克福德提出，被称为寄生式继承。它是关于一个函数通过从另一个对象中获取所有功能来创建对象，增强新对象，并返回它，假装它已经完成了所有工作。

这是一个普通对象，用对象字面量定义，并不知道它很快就会成为寄生关系的受害者：

```js
    var twoD = { 
      name: '2D shape', 
      dimensions: 2 
    }; 

```

一个创建`triangle`对象的函数可以：

+   使用`twoD`对象作为一个名为`that`的对象的原型（为了方便类似于`this`）。这可以以你之前看到的任何方式来完成，例如使用`object()`函数或复制所有属性。

+   增加更多属性。

+   返回`that`：

```js
        function triangle(s, h) { 
          var that = object(twoD); 
          that.name ='Triangle'; 
          that.getArea = function () { 
            return this.side * this.height / 2; 
          }; 
          that.side = s; 
          that.height = h; 
          return that; 
        } 

```

因为`triangle()`是一个普通函数，而不是构造函数，所以它不需要`new`运算符。然而，因为它返回一个对象，所以错误地使用`new`调用它也是可以的：

```js
    >var t = triangle(5, 10); 
   >t.dimensions; 
    2 
    >var t2 = new triangle(5,5); 
    >t2.getArea(); 
    12.5 

```

请注意`that`只是一个名称，它没有特殊的含义，就像`this`一样。

# 借用构造函数

实现继承的另一种方式（本章最后一种，我保证）再次与构造函数有关，而不是直接与对象有关。在这种模式中，子级的构造函数使用`call()`或`apply()`方法调用父级的构造函数。这可以称为**偷取构造函数**或**通过借用构造函数继承**，如果你想更加微妙一些的话。

`call()`和`apply()`方法在第四章*对象*中已经讨论过，但这里是一个复习；它们允许你调用一个函数并传递一个对象，该函数应该将其`this`值绑定到该对象。因此，为了继承目的，子构造函数调用父构造函数，并将子级新创建的`this`对象绑定为父级的`this`。

让我们有这个父构造函数`Shape()`：

```js
    function Shape(id) { 
      this.id = id; 
    } 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.name; 
    }; 

```

现在，让我们定义`Triangle()`，它使用`apply()`来调用`Shape()`构造函数，传递`this`（使用`new Triangle()`创建的实例）和任何额外的参数：

```js
   function Triangle() { 
    Shape.apply(this, arguments); 
    } 
    Triangle.prototype.name = 'Triangle'; 

```

请注意，`Triangle()`和`Shape()`都向它们的原型添加了一些额外的属性。

现在，让我们通过创建一个新的`triangle`对象来测试一下：

```js
    >var t = new Triangle(101); 
    >t.name; 
    "Triangle" 

```

新的`triangle`对象从父级继承了`id`属性，但它没有继承任何添加到父级`prototype`的东西：

```js
    >t.id; 
    101 
    >t.toString(); 
    "[object Object]" 

```

三角形未能获取`Shape`函数的原型属性，因为从未创建过`new Shape()`实例，所以原型从未被使用。然而，你在本章的开头看到了如何做到这一点。你可以重新定义`Triangle`如下：

```js
    function Triangle() { 
      Shape.apply(this, arguments); 
    } 
    Triangle.prototype = new Shape(); 
    Triangle.prototype.name = 'Triangle'; 

```

在这种继承模式中，父级的自有属性被重新创建为子级的自有属性。如果子级继承了数组或其他对象，则它是一个全新的值（不是引用），对其进行修改不会影响父级。

缺点是父级的构造函数被调用两次——一次用`apply()`继承自有属性，一次用`new`继承原型。事实上，父级的自有属性被继承了两次。让我们看一个简化的情景：

```js
    function Shape(id) { 
      this.id = id; 
    } 
    function Triangle() { 
      Shape.apply(this, arguments); 
    } 
    Triangle.prototype = new Shape(101); 

```

在这里，我们将创建一个新实例：

```js
    >var t = new Triangle(202); 
    >t.id; 
    202 

```

有一个自有属性`id`，但也有一个通过原型链传递下来的，准备好发挥作用的属性：

```js
    >t.__proto__.id; 
    101 
    > delete t.id; 
    true 
    >t.id; 
    101 

```

## 借用构造函数并复制其原型

通过调用两次构造函数执行的双重工作问题可以很容易地得到纠正。您可以在父构造函数上调用`apply()`来获取所有自有属性，然后使用简单的迭代（或者如前所述的`extend2()`）复制原型的属性：

```js
    function Shape(id) { 
      this.id = id; 
    } 
    Shape.prototype.name = 'Shape'; 
    Shape.prototype.toString = function () { 
      return this.name; 
    }; 

    function Triangle() { 
      Shape.apply(this, arguments); 
    } 
    extend2(Triangle, Shape); 
    Triangle.prototype.name = 'Triangle'; 

```

让我们测试以下代码：

```js
   >var t = new Triangle(101); 
    >t.toString(); 
    "Triangle" 
    >t.id; 
    101 

```

没有双重继承：

```js
    >typeoft.__proto__.id; 
    "undefined" 

```

`extend2()`方法也可以访问`uber`（如果需要的话）：

```js
    >t.uber.name; 
    "Shape" 

```

# 案例研究-绘制形状

让我们以一个更实际的例子来完成本章，使用继承。任务是能够计算不同形状的面积和周长，并绘制它们，同时尽可能多地重用代码。

## 分析

让我们有一个包含所有共同部分的`Shape`构造函数。然后，让我们有`Triangle`，`Rectangle`和`Square`构造函数，它们都继承自`Shape`。正方形实际上是具有相同边长的矩形，因此在构建`Square`时让我们重用`Rectangle`。

为了定义一个形状，您需要带有`x`和`y`坐标的点。通用形状可以有任意数量的点。三角形由三个点定义，矩形（为了简单起见）由一个点和边长定义。任何形状的周长是其边长的总和。计算面积是形状特定的，将由每个形状实现。

`Shape`中的共同功能将是：

+   一个`draw()`方法，可以根据给定的点绘制任何形状

+   一个`getParameter()`方法

+   包含一个`points`数组的属性

+   其他所需的方法和属性

对于绘图部分，让我们使用`<canvas>`标签。它在早期 IE 中不受支持，但嘿，这只是一个练习。

让我们再添加两个辅助构造函数-`Point`和`Line`。在定义形状时，`Point`将会有所帮助。`Line`将使计算更容易，因为它可以给出连接任意两个给定点的线段长度。

您可以在[`www.phpied.com/files/canvas/`](http://www.phpied.com/files/canvas/)上玩一个可工作的示例。只需打开控制台，然后开始创建新形状，就像您马上会看到的那样。

## 实施

让我们从在空白 HTML 页面中添加一个`canvas`标签开始：

```js
    <canvas height="600" width="800" id="canvas" /> 

```

然后，将 JavaScript 代码放在`<script>`标签内：

```js
    <script> 
    // ... code goes here 
    </script> 

```

现在，让我们来看看 JavaScript 部分的内容。首先是辅助`Point`构造函数。它比以下内容更简单就不能再简单了：

```js
    function Point(x, y) { 
      this.x = x; 
      this.y = y; 
    } 

```

请记住，`canvas`上的点的坐标从`x=0`，`y=0`开始，这是左上角。右下角将是`x=800`，`y=600`：

![实施](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_07_003.jpg)

接下来是`Line`构造函数。它接受两个点，并使用毕达哥拉斯定理*a² + b² = c²*（想象一个直角三角形，斜边连接两个给定点）来计算它们之间的线段长度：

```js
    function Line(p1, p2) { 
      this.p1 = p1; 
      this.p2 = p2; 
      this.length = Math.sqrt( 
      Math.pow(p1.x - p2.x, 2) + 
      Math.pow(p1.y - p2.y, 2) 
      ); 
    } 

```

接下来是`Shape`构造函数。形状将有它们的点（以及连接它们的线）作为自有属性。构造函数还调用一个初始化方法`init()`，该方法将在原型中定义：

```js
    function Shape() { 
      this.points = []; 
      this.lines= []; 
      this.init(); 
    } 

```

现在，重要的部分-`Shape.prototype`的方法。让我们使用对象文字表示法定义所有这些方法。参考注释以了解每个方法的指导方针：

```js
    Shape.prototype = { 
      // reset pointer to constructor 
      constructor: Shape, 

      // initialization, sets this.context to point 
      // to the context if the canvas object 
      init: function () { 
        if (this.context === undefined) { 
          var canvas = document.getElementById('canvas'); 
          Shape.prototype.context = canvas.getContext('2d'); 
        } 
      }, 

      // method that draws a shape by looping through this.points 
      draw: function () { 
        var i, ctx = this.context; 
        ctx.strokeStyle = this.getColor(); 
        ctx.beginPath(); 
        ctx.moveTo(this.points[0].x, this.points[0].y); 
        for (i = 1; i<this.points.length; i++) { 
          ctx.lineTo(this.points[i].x, this.points[i].y); 
        } 
        ctx.closePath(); 
        ctx.stroke(); 
      }, 

      // method that generates a random color 
      getColor: function () { 
        var i, rgb = []; 
        for (i = 0; i< 3; i++) { 
          rgb[i] = Math.round(255 * Math.random()); 
        } 
        return 'rgb(' + rgb.join(',') + ')'; 
      }, 

      // method that loops through the points array, 
      // creates Line instances and adds them to this.lines 
     getLines: function () { 
        if (this.lines.length> 0) { 
          return this.lines; 
        } 
        var i, lines = []; 
        for (i = 0; i<this.points.length; i++) { 
          lines[i] = new Line(this.points[i],  
          this.points[i + 1] || this.points[0]); 
        } 
        this.lines = lines; 
        return lines; 
      }, 

     // shell method, to be implemented by children 
      getArea: function () {}, 

      // sums the lengths of all lines 
      getPerimeter: function () { 
        var i, perim = 0, lines = this.getLines(); 
        for (i = 0; i<lines.length; i++) { 
          perim += lines[i].length; 
        } 
        return perim; 
      } 
    }; 

```

现在，是子构造函数。首先是`Triangle`：

```js
    function Triangle(a, b, c) { 
      this.points = [a, b, c]; 

      this.getArea = function () { 
        var p = this.getPerimeter(), 
        s = p / 2; 
        return Math.sqrt( s * (s - this.lines[0].length) * 
          (s - this.lines[1].length) * (s - this.lines[2].length)); 
      }; 
    } 

```

`Triangle`构造函数接受三个点对象，并将它们分配给`this.points`（它自己的点集合）。然后，它实现`getArea()`方法，使用海伦公式：

```js
    Area = s(s-a)(s-b)(s-c) 

```

`s`是半周长（周长除以二）。

接下来是`Rectangle`构造函数。它接收一个点（左上角的点）和两边的长度。然后，它从那一个点开始填充它的`points`数组：

```js
    function Rectangle(p, side_a, side_b){ 
    this.points = [ 
    p, 
    new Point(p.x + side_a, p.y),// top right 
    new Point(p.x + side_a, p.y + side_b), // bottom right 
    new Point(p.x, p.y + side_b)// bottom left 
    ]; 
    this.getArea = function () { 
    return side_a * side_b; 
    }; 
    } 

```

最后一个子构造函数是`Square`。正方形是矩形的一种特殊情况，因此重用`Rectangle`是有意义的。这里最容易做的事情是借用构造函数：

```js
    function Square(p, side){ 
      Rectangle.call(this, p, side, side); 
    } 

```

现在所有的构造函数都完成了，让我们来处理继承。任何伪经典模式（与对象不同，使用构造函数的模式）都可以。让我们尝试使用修改和简化的原型链模式（本章描述的第一种方法）。这种模式要求创建父类的新实例，并将其设置为子类的原型。在这种情况下，不需要为每个子类创建一个新实例-它们都可以共享它：

```js
    (function () { 
    var s = new Shape(); 
    Triangle.prototype = s; 
    Rectangle.prototype = s; 
    Square.prototype = s; 
    })(); 

```

## 测试

让我们通过绘制形状来测试这一点。首先，为三角形定义三个点：

```js
    >var p1 = new Point(100, 100); 
    >var p2 = new Point(300, 100); 
    >var p3 = new Point(200, 0); 

```

现在你可以通过将三个点传递给`Triangle`构造函数来创建一个三角形：

```js
    >var t = new Triangle(p1, p2, p3); 

```

你可以调用绘制三角形的方法在`canvas`上，并获得它的面积和周长：

```js
    >t.draw(); 
    >t.getPerimeter(); 
    482.842712474619 
    >t.getArea(); 
    10000.000000000002 

```

现在让我们来玩一个矩形实例：

```js
    >var r = new Rectangle(new Point(200, 200), 50, 100); 
    >r.draw(); 
    >r.getArea(); 
    5000 
    >r.getPerimeter(); 
    300 

```

最后，让我们玩一个正方形：

```js
    >var s = new Square(new Point(130, 130), 50); 
    >s.draw(); 
    >s.getArea(); 
    2500 
    >s.getPerimeter(); 
    200 

```

画这些形状很有趣。你也可以像下面的例子一样懒惰，重用三角形的点来画另一个正方形：

```js
    > new Square(p1, 200).draw(); 

```

测试的结果将类似于以下内容：

![测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_07_004.jpg)

# 练习

让我们做以下练习：

1.  使用原型继承模式实现多重继承，而不是属性复制。以下是一个例子：

```js
        var my = objectMulti(obj, another_obj, a_third, { 
        additional: "properties" 
        }); 

```

`additional`属性应该是自有属性；其余的属性应该混合到原型中。

1.  使用`canvas`示例进行练习。尝试不同的东西。以下是一些例子：

+   画几个三角形、正方形和矩形。

+   为更多的形状添加构造函数，比如`Trapezoid`、`Rhombus`、`Kite`和`Pentagon`。如果你想了解更多关于`canvas`标签的知识，也可以创建一个`Circle`构造函数。它需要覆盖父类的`draw()`方法。

+   你能想到另一种方法来解决这个问题并使用另一种类型的继承吗？

+   选择一个使用`uber`作为子类访问其父类的方法。添加功能，使父类可以跟踪他们的子类，也许使用包含`children`数组的属性？

# 总结

在本章中，你学到了实现继承的许多方式（模式），以下表格对它们进行了总结。不同类型大致可以分为以下几类：

+   适用于构造函数的模式

+   适用于对象的模式

你也可以根据它们是否：

+   使用原型

+   复制属性

+   两者都做（复制原型的属性）：

| **#** | **名称** | **示例** | **分类** | **备注** |
| --- | --- | --- | --- | --- |
| 1 | 原型链（伪经典） |

```js
Child.prototype = new Parent();   

```

|

+   适用于构造函数

+   使用原型链

|

+   默认机制

+   提示-将所有希望被重用的属性/方法移动到原型中，并将不可重用的内容添加为自有属性

|

| 2 | 仅继承原型 |
| --- | --- |

```js
Child.prototype = Parent.prototype;   

```

|

+   适用于构造函数

+   复制原型（没有原型链，因为所有的对象共享同一个原型对象）

|

+   更高效；不会仅为了继承而创建新实例

+   运行时原型链查找；速度快，因为没有链

+   缺点：子类可以修改父类的功能

|

| 3 | 临时构造函数 |
| --- | --- |

```js
function extend(Child, Parent) {   
 var F = function(){};   
 F.prototype = Parent.prototype;   
Child.prototype = new F();   
Child.prototype.constructor = Child;   
Child.uber = Parent.prototype;   
}   

```

|

+   适用于构造函数

+   使用原型链

|

+   与#1 不同，它只继承原型的属性；自有属性（在构造函数内部使用 this 创建的属性）不会被继承。

+   提供方便的访问父类的方法（通过`uber`）

|

| 4 | 复制`prototype`属性 |
| --- | --- |

```js
function extend2(Child, Parent) {   
var p = Parent.prototype;   
var c = Child.prototype;   
 for (var i in p) {   
 c[i] = p[i];   
 }   
c.uber = p;   
}   

```

|

+   适用于构造函数

+   复制属性

+   使用原型链

|

+   父类原型的所有属性都成为子类原型的属性

+   不需要仅为了继承目的创建一个新对象

+   更短的原型链

|

| 5 | 复制所有属性（浅复制） |
| --- | --- |

```js
function extendCopy(p) {   
var c = {};    
 for (var i in p) {   
 c[i] = p[i];   
 }   
c.uber = p;   
 return c;   
}   

```

|

+   适用于对象

+   复制属性

|

+   简单

+   不使用原型

|

| 6 | 深复制 | 与前一个相同，但是递归到对象中 |
| --- | --- | --- |

+   适用于对象

+   复制属性

|

+   与#5 相同，但是克隆对象和数组

|

| 7 | 原型继承 |
| --- | --- |

```js
function object(o){   
 function F() {}   
F.prototype = o;   
 return new F();   
}   

```

|

+   适用于对象

+   使用原型链

|

+   没有伪类，对象从对象继承

+   利用原型的好处

|

| 8 | 扩展和增强 |
| --- | --- |

```js
function objectPlus(o, stuff) {   
var n;   
 function F() {}   
F.prototype = o;   
 n = new F();   
n.uber = o;   
 for (var i in stuff) {   
 n[i] = stuff[i];   
 }   
 return n;   
}   

```

|

+   适用于对象

+   使用原型链

+   复制属性

|

+   原型继承（＃7）和复制属性（＃5）的混合

+   一次函数调用同时继承和扩展

|

| 9 | 多重继承 |
| --- | --- |

```js
function multi() {   
var n = {}, stuff, j = 0,   
len = arguments.length;   
 for (j = 0; j <len; j++) {   
 stuff = arguments[j];   
 for (var i in stuff) {   
 n[i] = stuff[i];   
 }   
 }   
 return n;   
}    

```

|

+   适用于对象

+   复制属性

|

+   一种混合风格的实现

+   按出现顺序复制所有父对象的所有属性

|

| 10 | 寄生继承 |
| --- | --- |

```js
function parasite(victim) {   
var that = object(victim);   
that.more = 1;   
 return that;   
}   

```

|

+   适用于对象

+   使用原型链

|

+   类似构造函数的函数创建对象

+   复制一个对象，并增强并返回副本

|

| 11 | 借用构造函数 |
| --- | --- |

```js
function Child() {   
Parent.apply(this, arguments);   
}   

```

|

+   适用于构造函数

|

+   仅继承自有属性

+   可以与＃1 结合，也可以继承原型

+   处理子类继承对象属性（因此通过引用传递）时的便捷方式

|

| 12 | 借用构造函数并复制原型 |
| --- | --- |

```js
function Child() {   
Parent.apply(this, arguments);   
}   

extend2(Child, Parent);   

```

|

+   适用于构造函数

+   使用原型链

+   复制属性

|

+   ＃11 和＃4 的组合

+   允许您继承自有属性和原型属性，而不需要两次调用父构造函数。

|

有这么多选择，你一定想知道哪一个是正确的。这取决于你的风格和偏好，你的项目、任务和团队。你更习惯以类为思维方式吗？那么选择一个与构造函数一起工作的方法。你只需要一个或几个类的实例吗？那么选择一个基于对象的模式。

这些是实现继承的唯一方式吗？不是。你可以从上表中选择一个模式，你可以混合它们，或者你可以想出自己的。重要的是要理解并熟悉对象、原型和构造函数；其余只是纯粹的快乐。
