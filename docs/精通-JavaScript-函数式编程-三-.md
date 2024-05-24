# 精通 JavaScript 函数式编程（三）

> 原文：[`zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410`](https://zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：连接函数-管道和组合

在第七章中，*转换函数-柯里化和部分应用*，我们看到了通过应用高阶函数构建新函数的几种不同方式。在本章中，我们将深入 FP 的核心，看看如何创建函数调用序列，以便它们的组合将从几个更简单的组件中产生更复杂的结果。我们将包括以下内容：

+   **管道**，一种类似于 Unix/Linux 管道的函数连接方式

+   **链接**，这可能被认为是管道的一种变体，但限于对象

+   **组合**，这是一种经典操作，起源于基本的计算机理论

在这个过程中，我们将涉及相关概念，例如以下内容：

+   **无点风格**，通常与管道和组合一起使用

+   组合或管道函数的调试，我们将编写一些辅助工具

+   组合或管道函数的测试，这不会被证明是高复杂度的

# 管道

管道和组合是一种设置函数按顺序工作的技术，因此一个函数的输出成为下一个函数的输入。有两种看待这个问题的方式：从计算机的角度和从数学的角度。通常，大多数 FP 文本都从后者开始，但由于我假设大多数读者更接近计算机而不是数学，让我们从前者开始。

# Unix/Linux 中的管道

在 Unix/Linux 中，执行一个命令并将其输出作为第二个命令的输入，其输出将作为第三个命令的输入，依此类推，称为*管道*。这是相当常见的，也是 Unix 哲学的应用，正如贝尔实验室的一篇文章所解释的，这篇文章是由管道概念的创造者 Doug McIlroy 撰写的：

1.  让每个程序都做一件事情。要做新工作，最好重新构建，而不是通过添加新的*功能*来使旧程序复杂化。

1.  期望每个程序的输出成为另一个尚不知道的程序的输入。

鉴于 Unix 的历史重要性，我建议阅读一些描述（当时新的）操作系统的重要文章，位于*贝尔系统技术杂志*1978 年 7 月，网址为[`emulator.pdp-11.org.ru/misc/1978.07_-_Bell_System_Technical_Journal.pdf`](http://emulator.pdp-11.org.ru/misc/1978.07_-_Bell_System_Technical_Journal.pdf)。两条引用的规则在*风格*部分，*前言*文章中。

让我们考虑一个简单的例子来开始。假设我想知道一个目录中有多少个 LibreOffice 文本文档。有很多方法可以做到这一点，但这样做就可以了。我们将执行三个命令，将每个命令的输出作为输入传递给下一个命令（这就是`|`字符的含义）。假设我们`cd /home/fkereki/Documents`，然后执行以下操作：

```js
$ ls -1 | grep "odt$" | wc -l
***4***
```

这是什么意思？它是如何工作的？（忽略美元符号：这只是控制台提示。）我们必须逐步分析这个过程：

+   管道的第一部分`ls -1`列出目录中的所有文件（根据我们的`cd`命令为`/home/fkereki/Documents`），以单列形式，每行一个文件名

+   第一个命令的输出作为`grep "odt$"`的输入，它过滤（通过）只有以`"odt"`结尾的行，这是 LibreOffice Writer 的标准文件扩展名

+   过滤后的输出提供给计数命令`wc -l`，它计算其输入中有多少行

您可以在 Dennis Ritchie 和 Ken Thompson 的*UNIX 分时系统*文章的第 6.2 节*过滤器*中找到管道，这也是我上面提到的贝尔实验室期刊的一部分。

从 FP 的角度来看，这是一个关键概念。我们希望通过简单、单一用途、较短的函数来构建更复杂的操作。管道是 Unix shell 用来应用这个概念的方式，简化了执行命令、获取其输出，并将其作为输入传递给另一个命令的工作。我们将在 JS 中以我们自己的函数式风格应用类似的概念，正如我们将看到的；请查看图 8.1：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/bedb088b-2623-4076-b6ad-b5aab8b78d93.jpg)图 8.1\. JS 中的管道与 Unix/Linux 中的管道类似。每个函数的输出都成为下一个函数的输入。

顺便说一句（不，放心，这不会变成一个 shell 教程！）你也可以使管道接受参数。例如，如果我经常想要计算我有多少个带有这种或那种扩展名的文件，我可以创建一个名为`cfe`的函数，代表*计算扩展名的数量：*

```js
$ function cfe() {
 ls -1 | grep "$1\$"| wc -l
} 
```

然后我可以使用`cfe`作为一个命令，将所需的扩展名作为参数传递：

```js
$ cfe odt
***4***
$ cfe pdf
***6***
```

我们还希望编写类似的参数化管道：我们不仅受限于在我们的流程中只有固定的函数，而是完全自由地决定要包含什么。

# 重新审视一个例子

我们可以通过重新审视早期章节中的一个问题来开始将各个部分联系在一起。还记得之前需要计算一些地理数据的平均纬度和经度吗？我们在第五章的*从对象中提取数据*部分中看到了这个问题，*声明式编程 - 更好的风格*？基本上，我们从以下数据开始，问题是要计算给定点的平均纬度和经度：

```js
let markers = [
 {name: "UY", lat: -34.9, lon: -56.2},
 {name: "AR", lat: -34.6, lon: -58.4},
 {name: "BR", lat: -15.8, lon: -47.9},
 ...
 {name: "BO", lat: -16.5, lon: -68.1}
];
```

有了我们现在所知道的，我们可以用以下方式来编写一个解决方案：

+   能够从每个点中提取纬度（以及之后的经度）

+   使用该函数来创建一个纬度数组

+   将结果数组传递给我们在*计算平均值*部分编写的平均函数，上述章节

要完成第一个任务，我们可以使用第七章的*参数顺序*部分中的`myMap()`函数，以及第六章的*从对象中获取属性*部分中的`getField()`函数，再加上一些柯里化来固定一些值。用长篇大论来写，我们的解决方案可能是以下内容：

```js
const average = arr => arr.reduce(sum, 0) / arr.length;
const getField = attr => obj => obj[attr];
const myMap = curry(flipTwo(demethodize(map)));

const getLat = curry(getField)("lat");
const getAllLats = curry(myMap)(getLat);

let averageLat = pipeline(getAllLats, average);
// *and similar code to average longitudes*
```

当然，你总是可以屈服于去写一些*一行代码*的诱惑，但要注意：这样真的更清晰，更好吗？

```js
let averageLat2 = pipeline(curry(myMap)(curry(getField)("lat")), average);
let averageLon2 = pipeline(curry(myMap)(curry(getField)("lon")), average);
```

这是否对你有意义将取决于你对 FP 的经验。无论采取哪种解决方案，事实仍然是，添加管道（以及后来的组合）到你的工具集中可以帮助你编写更紧凑、声明式、更容易理解的代码，所以现在让我们转向看看如何以正确的方式进行函数管道化。

# 创建管道

我们希望能够生成一个包含多个函数的管道。我们可以以两种不同的方式来做到这一点：通过以问题特定的方式*手动*构建管道，或者试图使用更通用的构造，可以以一般性地应用。让我们看看这两种解决方案。

# 手动构建管道

让我们以一个 Node.js 的例子来进行，类似于我们在本章前面构建的命令行管道。我们需要一个函数来读取目录中的所有文件，我们可以这样做（这种方式不太推荐，因为它是同步调用，通常在服务器环境中不好）：

```js
function getDir(path) {
 const fs = require("fs");
 const files = fs.readdirSync(path);
 return files;
}
```

过滤`odt`文件非常简单。我们从以下函数开始：

```js
const filterByText = (text, arr) => arr.filter(v => v.endsWith(text));
```

因此，我们现在可以写出以下内容：

```js
const filterOdt = arr => filterByText(".odt", arr);
```

更好的是，我们可以应用柯里化，并采用无参风格，就像第三章中的*一个不必要的错误*部分所示的那样：

```js
const filterOdt2 = curry(filterByText)(".odt");
```

最后，要计算数组中的元素，我们可以简单地编写以下代码。由于`.length`不是一个函数，我们无法应用我们的去方法化技巧：

```js
const count = arr => arr.length;
```

有了这些函数，我们可以写出类似这样的代码：

```js
const countOdtFiles = (path) => {
 const files = getDir(path);
 const filteredFiles = filterOdt(files);
 const countOfFiles = count(filteredFiles);
 return countOfFiles;
}

countOdtFiles("/home/fkereki/Documents"); // 4, *as with the command line solution*
```

如果你想摆脱所有的中间变量，你也可以选择*一行式*的定义：

```js
const countOdtFiles2 = path => count(filterOdt(getDir(path)));

countOdtFiles2("/home/fkereki/Documents"); // 4, *as before*
```

这就是问题的关键：我们的文件计数函数的两种实现都有缺点。第一个定义使用了几个中间变量来保存结果，并且将 Linux shell 中的一行代码变成了多行函数。另一方面，第二个定义要短得多，但在某种程度上更难理解，因为我们似乎是以相反的顺序编写计算的步骤！我们的流水线必须首先读取文件，然后过滤它们，最后计数--但在我们的定义中，这些函数的顺序却是*相反的*！

我们当然可以手动实现流水线处理，正如我们所见，但如果我们可以采用更具声明性的风格会更好。让我们继续尝试以更清晰和可理解的方式构建更好的流水线，尝试应用我们已经见过的一些概念。

# 使用其他构造

如果我们从函数的角度思考，我们拥有的是一系列函数，我们想要按顺序应用它们，从第一个开始，然后将第二个应用于第一个函数产生的结果，然后将第三个应用于第二个函数的结果，依此类推。如果我们只是修复两个函数的流水线，这样就可以：

```js
const pipeTwo = (f, g) => (...args) => g(f(...args));
```

这并不是那么无用，因为我们可以组合更长的流水线--尽管，我承认，这需要写得太多了！我们可以用两种不同但等效的方式来编写我们的三个函数的流水线：

```js
const countOdtFiles3 = path =>
    pipeTwo(pipeTwo(getDir, filterOdt), count)(path);

const countOdtFiles4 = path =>
    pipeTwo(getDir, pipeTwo(filterOdt, count))(path);
```

我们正在利用管道是一个可结合的操作这一事实。在数学中，结合性质是指我们可以通过首先添加*1+2*然后将结果添加到 3，或者通过将 1 添加到添加*2+3*的结果来计算*1+2+3*：换句话说，*1+2+3*与*(1+2)+3*或*1+(2+3)*相同。

这是如何工作的？详细跟踪给定调用的执行将是有用的；很容易因为有这么多的调用而感到困惑！第一个实现可以一步一步地跟踪，直到最终结果，幸运的是与我们已经知道的相匹配：

```js
countOdtFiles3("/home/fkereki/Documents") ===
 pipeTwo(pipeTwo(getDir, filterOdt), count)("/home/fkereki/Documents") ===
 count(pipeTwo(getDir, filterOdt)("/home/fkereki/Documents")) ===
 count(filterOdt(getDir("/home/fkereki/Documents"))) // 4
```

第二个实现也得到了相同的最终结果：

```js
countOdtFiles4("/home/fkereki/Documents") ===
 pipeTwo(getDir, pipeTwo(filterOdt, count))("/home/fkereki/Documents") ===
 pipeTwo(filterOdt, count)(getDir("/home/fkereki/Documents")) ===
 count(filterOdt(getDir("/home/fkereki/Documents"))) // **4**
```

好吧，现在我们知道我们只需要一个基本的*两个管道*高阶函数...但我们真的希望能够以更短、更紧凑的方式工作。首先的实现可能是以下内容：

```js
const pipeline = (...fns) => (...args) => {
 let result = fns0;
 for (let i = 1; i < fns.length; i++) {
 result = fnsi;
 }
 return result;
};

pipeline(getDir, filterOdt, count)("/home/fkereki/Documents"); // *still* 4
```

这确实有效--现在我们的文件计数流水线的指定方式更清晰，因为现在函数按照正确的顺序给出。然而，`pipeline()`函数的实现本身并不是非常函数式的，而是回到了旧的、命令式的、手动循环的方法。我们可以使用`.reduce()`来做得更好，就像第五章中的*以更好的风格进行声明式编程*。

如果你查看一些 FP 库，我们这里称为`pipeline()`的函数也可能被称为`flow()`--因为数据从左到右流动--或`sequence()`--暗示操作是按升序顺序执行的--但语义是相同的。

这个想法是从第一个函数开始评估，将结果传递给第二个函数，然后将该结果传递给第三个函数，依此类推。然后我们可以用更短的代码实现我们的流水线：

```js
const pipeline2 = (...fns) =>
 fns.reduce((result, f) => **(...args) => f(result(...args))**);

pipeline2(getDir, filterOdt, count)("/home/fkereki/Documents"); // 4
```

这段代码更具声明性，你甚至可以通过使用我们的`pipeTwo()`函数来写得更好，它执行的是相同的操作：

```js
const pipeline3 = (...fns) => fns.**reduce(pipeTwo)**;

**pipeline3(getDir, filterOdt, count)**("/home/fkereki/Documents"); // *again* 4
```

您也可以通过意识到，基本上它使用了我们提到的结合性质，并首先将第一个函数传递给第二个；然后，将这个结果传递给第三个函数，依此类推来理解这段代码。

哪个版本更好？我会说引用`pipeTwo()`函数的版本更清晰：如果您知道`.reduce()`的工作原理，您可以很容易理解我们的管道是如何一次两个函数地通过的，从第一个开始--这与您对管道工作原理的了解相匹配。我们写的其他版本更多或少是陈述性的，但可能不那么容易理解。

# 调试管道

现在，让我们转向一个实际问题：如何调试您的代码？使用管道，您无法真正看到从函数到函数传递的内容，那么您该如何做呢？我们有两个答案：一个（也）来自 Unix/Linux 世界，另一个（最适合本书）使用包装器来提供一些日志。

# 使用 tee

我们将使用的第一个解决方案意味着向管道中添加一个函数，该函数将仅记录其输入。我们希望实现类似于`tee` Linux 命令的功能，它可以拦截管道中的标准数据流并将副本发送到备用文件或设备。记住`/dev/tty`是通常的控制台，我们可以执行以下操作并在屏幕上获得通过`tee`命令传递的所有内容的副本：

```js
$ ls -1 | grep "odt$" | **tee /dev/tty** | wc -l

*...the list of files with names ending in odt...*
*4*
```

我们可以轻松地编写一个类似的函数：

```js
const tee = arg => {
 console.log(arg);
 return arg;
};
```

如果您了解逗号运算符的用法，您可以更加简洁，只需编写`const tee = (arg) => (console.log(arg), arg)`--您明白为什么吗？查看[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comma_Operator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comma_Operator)获取答案！

我们的日志记录函数将接收一个参数，列出它，并将其传递给管道中的下一个函数。我们可以看到它的工作方式：

```js
console.log(
 pipeline2(getDir, tee, filterOdt, tee, count)(
 "/home/fkereki/Documents"
 )
);

[...*the list of all the files in the directory*...]
[...*the list of files with names ending in odt*...]
*4*
```

如果我们的`tee()`函数可以接收一个日志记录函数作为参数，那就更好了，就像我们在第六章的*以函数式方式记录日志*部分中所做的那样；这只是做出与我们之前所做的相同类型的更改的问题。同样的良好设计概念再次应用！

```js
const tee2 = (arg, logger = console.log) => {
    logger(arg);
 return args;
};
```

请注意，以这种方式传递`console.log`可能会存在绑定问题。最好写成`console.log.bind(console)`，作为一种预防措施。

然而，这只是一个特定的增强：现在让我们考虑一个更通用的接入函数，比仅仅做一些日志记录更有可能。

# 接入流

如果您愿意，您可以编写一个增强的`tee()`函数，可以产生更多的调试信息，可能将报告的数据发送到文件或远程服务等--您可以探索许多可能性。您还可以探索更一般的解决方案，`tee()`只是一个特例，并且还允许创建个性化的接入函数。参见图 8.2：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/b07f36e2-f002-4d72-ae32-abf179920530.jpg)图 8.2。接入允许您应用一些函数来检查数据在管道中流动的情况。

在使用管道时，您可能希望在其中间放置一个日志记录函数，或者您可能需要一些其他类型的*窥探*函数--可能在某处存储数据，或者调用服务，或者其他一些副作用。我们可以有一个通用的`tap()`函数，它可以以这种方式运行：

```js
const tap = curry((fn, x) => (fn(x), x));
```

这可能是本书中 *看起来最棘手的代码* 候选，所以让我们解释一下。我们想要生成一个函数，给定一个函数 `fn()` 和一个参数 `x`，将评估 `fn(x)`（以产生我们可能感兴趣的任何一种副作用），但返回 `x`（这样管道就可以继续进行而不受干扰）。逗号运算符正好具有这种行为：如果您编写像 `(a, b, c)` 这样的代码，JS 将按顺序评估这三个表达式，并使用最后一个值作为表达式的值。

逗号在 JS 中有几种用法，您可以在 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comma_Operator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comma_Operator) 上阅读更多关于其作为运算符的用法。

现在我们可以利用柯里化来生成几个不同的 tapping 函数。我们在上一节中编写的 `tee()` 函数也可以按照以下方式编写：

```js
const tee3 = tap(console.log);
```

顺便说一句，您也可以不使用柯里化来编写 `tap()`... 但您会承认它失去了一些神秘感！

```js
const tap2 = fn => x => (fn(x), x);
```

您会认出这种柯里化的方式，就像我们在 第七章 的 *Currying by hand* 部分中看到的那样，*Transforming Functions - Currying and Partial Application*。

# 使用日志包装器

我们提到的第二个想法基于我们在 第六章 的 *Logging* 部分中编写的 `addLogging()` 函数，*Producing Functions - Higher-Order Functions*。这个想法是用一些日志功能包装一个函数，这样在进入时，参数将被打印出来，退出时，函数的结果将被显示出来：

```js
pipeline2(
 **addLogging**(getDir), 
    **addLogging**(filterOdt), 
    **addLogging**(count))("/home/fkereki/Documents"));

entering getDir: /home/fkereki/Documents
exiting getDir: ...*the list of all the files in the directory*...
entering filterOdt: ...*the same list of files*...
exiting filterOdt: ...*the list of files with names ending in odt*...
entering count: ...*the list of files with names ending in odt*...
exiting count: 4 
```

我们可以轻松验证 `pipeline()` 函数是否正确执行 -- 函数产生的结果作为输入传递给下一个函数，我们也可以理解每次调用发生了什么。当然，您不需要在 *每个* 管道函数中添加日志记录：您可能只在怀疑出现错误的地方这样做。

# 链接和流畅接口

当您使用对象或数组时，还有另一种方法可以将多个调用的执行链接在一起，即应用 *chaining*。例如，当您使用数组时，如果应用了 `.map()` 或 `.filter()` 方法，结果将是一个新数组，您可以对其应用新的方法，依此类推。我们已经使用了这样的方法，就像我们在 第五章 的 *Working with ranges* 部分中定义 `range()` 函数时一样：

```js
const range = (start, stop) =>
 new Array(stop - start).fill(0).map((v, i) => start + i);
```

首先，我们创建了一个新数组；然后，我们对其应用了 `.fill()` 方法，这个方法会直接更新数组（副作用...）并返回更新后的数组，最后我们对其应用了 `.map()` 方法。后者确实生成了一个新数组，我们可以对其应用进一步的映射、过滤或任何其他可用的方法。

这种连续链式操作的风格也用于流畅的 API 或接口。举一个例子，图形库 `D3.js`（请参阅 [`d3js.org/`](https://d3js.org/) 了解更多信息）经常使用这种风格 -- 下面的例子取自 [`bl.ocks.org/mbostock/4063269`](https://bl.ocks.org/mbostock/4063269)：

```js
 var node = svg
 .selectAll(".node")
 .data(pack(root).leaves())
 .enter()
 .append("g")
 .attr("class", "node")
 .attr("transform", function(d) { 
 return "translate(" + d.x + "," + d.y + ")"; 
 });
```

每个方法都作用于前一个对象，并提供对将来应用方法调用的新对象的访问（例如 `.selectAll()` 或 `.append()` 方法），或者更新当前对象（就像 `.attr()` 属性设置调用一样）。这种风格并不是唯一的，还有其他一些知名的库（比如 jQuery，仅举一个例子）也应用了这种风格。

我们能自动化这个过程吗？在这种情况下，答案可能是*可能，但我宁愿不这样做*。在我看来，使用`pipeline()`或`compose()`同样可以实现相同的结果。使用对象链接，你只能返回新的对象或数组或可以应用方法的东西。 （请记住，如果你使用标准类型，比如字符串或数字，你不能给它们添加方法，除非你修改它们的原型，这是不推荐的！）然而，使用组合，你可以返回任何类型的值；唯一的限制是下一个函数必须期望你提供的数据类型。

另一方面，如果你正在编写自己的 API，那么你可以通过让每个方法`return this`来提供一个流畅的接口--当然，除非它需要返回其他东西！如果你正在使用其他人的 API，你也可以通过使用代理来进行一些技巧，但要注意可能有情况下你的代理代码可能会失败：也许正在使用另一个代理，或者有一些 getter 或 setter 会导致问题，等等。

你可能想在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Proxy`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Proxy)上阅读代理对象的相关内容--它们非常强大，可以提供有趣的元编程功能，但它们也可能陷入技术细节，并且会导致代理代码的轻微减速。

让我们来看一个基本的例子。我们可以有一个`City`类，带有名称、纬度（`lat`）和经度（`long`）属性：

```js
class City {
 constructor(name, lat, long) {
 this.name = name;
 this.lat = lat;
 this.long = long;
 }

 getName() {
 return this.name;
 }

 setName(newName) {
 this.name = newName;
 }

 setLat(newLat) {
 this.lat = newLat;
 }

 setLong(newLong) {
 this.long = newLong;
 }

 getCoords() {
 return [this.lat, this.long];
 }
}
```

我们可以像下面这样使用这个类，详细介绍我的家乡蒙得维的亚，乌拉圭：

```js
let myCity = new City("Montevideo, Uruguay", -34.9011, -56.1645);
console.log(myCity.getCoords(), myCity.getName());
// [ -34.9011, -56.1645 ] 'Montevideo, Uruguay'
```

如果我们想要允许流畅地处理 setter，我们可以设置一个代理来检测这样的调用，并提供缺失的`return this`。我们怎么做呢？如果原始方法没有返回任何东西，JS 将默认包含一个`return undefined`语句，因此我们可以检测方法是否返回这个值，并替换为`return this`。当然，这是一个问题：如果我们有一个方法，根据其语义，它可以合法地返回一个`undefined`值，我们可以有一种*异常列表*，告诉我们的代理在这些情况下不添加任何东西，但我们不要深入讨论这个问题。

我们的处理程序代码如下。每当调用对象的方法时，都会隐式调用一个 get，我们捕获它。如果我们得到一个函数，那么我们用自己的一些代码包装它，这些代码将调用原始方法，然后决定是返回它的值还是返回代理对象的引用。如果我们没有得到一个函数，那么我们直接返回所请求属性的值。我们的`chainify()`函数将负责将处理程序分配给一个对象，并创建所需的代理。

```js
const getHandler = {
    get(target, property, receiver) {
 if (typeof target[property] === "function") {
 // requesting a method? return a wrapped version
 return (...args) => {
 const result = targetproperty;
 return result === undefined ? receiver : result;
 };
 } else {
 // an attribute was requested - just return it
 return target[property];
 }
 }
};

const chainify = obj => new Proxy(obj, getHandler);
```

有了这个，我们可以*chainify*任何对象，这样我们就有机会检查任何调用的方法。当我写这篇文章时，我目前住在印度浦那，所以让我们反映这个变化。

```js
myCity = chainify(myCity);

console.log(myCity
 .setName("Pune, India")
 .setLat(18.5626)
 .setLong(73.8087)
 .g    oords(), 
 myCity.getName());
// [ 18.5626, 73.8087 ] 'Pune, India'
```

请注意以下内容：

+   我们将`myCity`更改为它自己的代理版本。

+   我们以流畅的方式调用了几个 setter，它们工作正常，因为我们的代理负责为下一个调用提供所需的 this 值。

+   对`.getCoords()`和`.getName()`的调用被拦截，但没有做任何特殊处理，因为它们已经返回一个值。

这值得吗？这取决于你--但请记住我的评论，可能有情况下这种方法会失败，所以要小心！

# Pointfree 风格

当你将函数连接在一起，无论是像这样以管道方式，还是像我们将在本章后面看到的组合方式，你都不需要任何中间变量来保存结果，这些结果将成为下一个函数的参数：它们是隐式的。同样，你可以编写函数而不提及它们的参数，这被称为 pointfree 风格。

点无码风格也被称为暗示式编程--以及无意义的编程，由反对者提出！术语*point*本身意味着函数参数，点无码指的是不命名这些参数。

# 定义点无码函数

你可以很容易地识别点无码函数定义，因为它既不需要`function`关键字，也不需要`=>`符号。我们可以重新审视本章中我们之前编写的一些函数的定义，来验证这一点。例如，我们原始的文件计数函数的定义：

```js
const countOdtFiles3 = path =>
 pipeTwo(pipeTwo(getDir, filterOdt), count)(path);

const countOdtFiles4 = path =>
 pipeTwo(getDir, pipeTwo(filterOdt, count))(path);
```

前面的代码可以重写如下：

```js
const countOdtFiles3b = pipeTwo(pipeTwo(getDir, filterOdt), count);

const countOdtFiles4b = pipeTwo(getDir, pipeTwo(filterOdt, count));
```

新的定义没有引用新定义的函数的参数。你可以通过检查管道中的第一个函数（在这种情况下是`getDir()`）并查看它接收的参数来推断它。 （在第十二章中，我们将看到，使用类型签名会对文档方面有所帮助。）同样，`getLat()`的定义是点无码的：

```js
const getLat = curry(getField)("lat");
```

等价的完整风格定义应该是什么？你需要检查`getField()`函数（我们刚在*重新访问一个例子*部分看到它），来确定它期望一个对象作为参数。然而，通过写成明确的形式来表达这种需求：

```js
const getLat = obj => curry(getField)("lat")(obj);
```

这没有太多意义：如果你愿意写所有这些，你可能只需坚持以下方式：

```js
const getLat = obj => obj.lat;
```

然后你可以根本不用关心柯里化或类似的东西！

# 转换为点无码风格

另一方面，最好稍作停顿，不要试图以点无码的方式写*所有*东西，不管它可能会付出什么代价。例如，考虑我们在第六章中编写的`isNegativeBalance()`函数，*生成函数 - 高阶函数*：

```js
const isNegativeBalance = v => v.balance < 0;
```

我们可以以点无码的方式写这个吗？可以，我们将看到如何做到这一点--但我不确定我们是否想以这种方式编写代码！我们可以考虑构建一个由两个函数组成的流水线：一个函数将从给定对象中提取余额，下一个函数将检查它是否为负数，因此我们将以以下方式编写我们的余额检查函数的替代版本：

```js
const isNegativeBalance2 = pipeline(getBalance, isNegative);
```

要从给定对象中提取余额属性，我们可以使用`getField()`和一点柯里化，然后写成以下形式：

```js
const getBalance = curry(getField)("balance");
```

对于第二个函数，我们可以写成以下形式：

```js
const isNegative = x => x < 0;
```

我们的点无码目标就在这里！相反，我们可以使用同一章节中的`binaryOp()`函数，再加上一些柯里化，来写成以下形式：

```js
const isNegative = curry(binaryOp(">"))(0);
```

我之所以以另一种方式编写测试（*0>x*而不是*x<0*）只是为了编码方便。另一种选择是使用我在同一章节的*一个更方便的实现*部分中提到的增强函数--稍微简单一些！

```js
const isNegative = binaryOpRight("<", 0);
```

因此，最终，我们可以写成以下形式：

```js
const isNegativeBalance2 = pipeline(
 curry(getField)("balance"),
 curry(binaryOp(">"))(0)
);
```

或者，我们可以写成以下形式：

```js
const isNegativeBalance3 = pipeline(
 curry(getField)("balance"),
 binaryOpRight("<", 0)
);
```

你真的认为这是一个进步吗？我们的`isNegativeBalance()`的新版本没有引用它们的参数，并且完全是点无码的，但使用点无码风格的想法应该是为了帮助提高代码的清晰度和可读性，而不是产生混淆和不透明性！我怀疑任何人看到我们函数的新版本并认为它们比原来的有任何优势。

如果你发现你的代码变得难以理解，而这只是因为你想使用点无码编程，那就停下来，撤销你的更改。记住我们书中的原则：我们想要进行 FP，但我们不想过分使用它--使用点无码风格并不是一个要求！

# 组合

*组合*与管道非常相似，但它源自数学理论。组合的概念很简单 - 一系列函数调用，其中一个函数的输出是下一个函数的输入 - 但顺序与管道相反。在后者中，要应用的第一个函数是最左边的，但在组合中，你从最右边开始。让我们更深入地研究一下这个问题。

当你定义三个函数的组合，比如(*f∘* *g∘* *h*)并将其应用于*x*时，这等同于你写成*f*(*g*(*h*(*x*)))。重要的是要注意，与管道相同，第一个要应用的函数的 arity 可以是任何值，但所有其他函数必须是一元的。此外，除了函数评估的顺序不同之外，组合是 FP 中的一个重要工具，因为它也抽象了实现细节（让你专注于你需要完成的任务，而不是为了实现这个任务而专注于具体的细节），因此让你以更声明式的方式工作。

如果有帮助的话，你可以将(*f∘* *g∘* *h*)看作是*f 在 g 之后在 h 之后*，这样就清楚了*h*是要应用的第一个函数，*f*是最后一个。

由于与管道的相似性，实现组合并不会太难，但仍然有一些重要和有趣的细节。

# 一些组合的例子

也许对你来说并不奇怪，但我们已经看到了几个组合的例子，或者至少是功能上等价于使用组合的情况。让我们回顾一些这些例子，并且也用一些新的例子来工作。

# 一元运算符

在第六章的*逻辑否定函数*部分，*生成函数 - 高阶函数*，我们写了一个`not()`函数，给定另一个函数，它会逻辑地反转其结果。我们使用该函数来否定对负余额的检查；示例代码可能如下：

```js
const not = fn => (...args) => !fn(...args);
const positiveBalance = not(isNegativeBalance);
```

在同一章的另一部分，*将操作转换为函数*，我给你留下了一个挑战，写一个`unaryOp()`函数，它将提供与常见 JS 运算符等价的一元函数。所以，如果你能写出以下内容：

```js
const logicalNot = unaryOp("!");
```

然后，假设存在一个`compose()`函数，你也可以写成以下形式：

```js
const positiveBalance = compose(logicalNot, isNegativeBalance);
```

你更喜欢哪一个？这实际上是一个品味的问题，但我认为第二个版本更清楚地表达了我们想要做的事情。使用`not()`函数，你必须检查它的作用才能理解整个代码。而使用组合，你仍然需要知道`logicalNot()`是什么，但整体结构是可以看到的。

在同一章的*反转结果*部分，你也可以看到另一个例子。记住，我们有一个函数可以根据西班牙语规则比较字符串，但我们想要反转比较的意义，以降序排序：

```js
const changeSign = unaryOp("-");
palabras.sort(**compose(changeSign, spanishComparison)**);
```

# 计算文件

我们也可以回到我们的管道。我们已经写了一个单行函数来计算给定路径中的`odt`文件：

```js
const countOdtFiles2 = path => count(filterOdt(getDir(path)));
```

暂且不考虑这段代码不如后来我们开发的管道版本清晰的观察，我们也可以用组合来编写这个函数：

```js
const countOdtFiles2b = path => compose(count, filterOdt, getDir)(path);
countOdtFiles2b("/home/fkereki/Documents"); // *4, no change here*
```

我们也可以以 pointfree 的方式编写这个函数，不指定`path`参数，使用`const countOdtFiles2 = compose(count, filterOdt, getDir)`，但我想更好地与之前的定义相对应。

也可以以*一行*的方式来看待这个问题：

```js
compose(count, filterOdt, getDir)("/home/fkereki/Documents");
```

即使它不像流水线版本那样清晰（这只是我的观点，可能受我对 Linux 的喜好影响！），这种声明式实现清楚地表明我们依赖于组合三个不同的函数来获得我们的结果--这很容易看出，并应用了将大型解决方案构建成更简单的代码片段的思想。

# 查找唯一单词

最后，让我们举一个例子，我同意，这也可以用于流水线处理。假设你有一段文本，你想从中提取所有唯一的单词：你会怎么做？如果你考虑它的步骤（而不是试图一次性创建一个完整的解决方案），你可能会想出类似这样的解决方案：

+   忽略所有非字母字符

+   将所有内容转换为大写

+   将文本拆分为单词

+   创建一个单词集合

为什么要使用集合？因为它会自动丢弃重复的值；请查看[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Set`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Set)了解更多信息。顺便说一句，我们将使用`Array.from()`方法将我们的集合转换为数组；请参阅[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from)。

现在，以 FP 方式解决每个问题：

```js
const removeNonAlpha = str => str.replace(/[^a-z]/gi, " ");
const toUpperCase = demethodize(String.prototype.toUpperCase);
const splitInWords = str => str.trim().split(/\s+/);
const arrayToSet = arr => new Set(arr);
const setToList = set => Array.from(set).sort();
```

有了这些函数，结果可以写成如下形式：

```js
const getUniqueWords = compose(
    setToList,
 arrayToSet,
 splitInWords,
 toUpperCase,
 removeNonAlpha
);
```

由于你看不到组合函数的参数，你真的不需要显示`getUniqueWords()`的参数，所以在这种情况下，点无风格是自然的。

我们可以测试我们的函数；让我们将这个函数应用于亚伯拉罕·林肯于 1863 年 11 月 19 日在葛底斯堡的演讲的前两句话，并打印出由 43 个不同单词组成的句子（相信我，我数过了！）：

```js
const GETTYSBURG_1_2 = `Four score and seven years ago
our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to
the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether
that nation, or any nation so conceived and dedicated,
can long endure.`; console.log(**getUniqueWords(GETTYSBURG_1_2)**); [ 'A', 'AGO', 'ALL', 'AND', 'ANY', 'ARE', 'BROUGHT', 'CAN', 'CIVIL',
... 'TESTING',| 'THAT', 'THE', 'THIS', 'TO', 'WAR', 'WE', 'WHETHER', 'YEARS' ]
```

当然，你可能已经以可能更短的方式编写了`getUniqueWords()`，但我要说的是，通过将解决方案组合成几个较短的步骤，你的代码更清晰，更容易理解。然而，如果你希望说流水线处理的解决方案似乎更好，那只是一种观点！

# 使用高阶函数进行组合

很明显，手动组合可以像我们上面看到的流水线处理一样轻松地完成。例如，我们在前面的几节中编写的唯一单词计数函数可以用简单的 JS 风格编写：

```js
const getUniqueWords1 = str => {
 const str1 = removeNonAlpha(str);
 const str2 = toUpperCase(str1);
 const arr1 = splitInWords(str2);
 const set1 = arrayToSet(arr1);
 const arr2 = setToList(set1);
 return arr2;
};
```

或者，它可以以更简洁（更晦涩！）的*一行*风格编写：

```js
const getUniqueWords2 = str =>
    setToList(arrayToSet(splitInWords(toUpperCase(removeNonAlpha(str)))));

console.log(getUniqueWords2(GETTYSBURG_1_2));
// [ 'A', 'AGO', 'ALL', 'AND', ... 'WAR', 'WE', 'WHETHER', 'YEARS' ]
```

然而，与流水线处理一样，让我们寻找一个更通用的解决方案，这样就不需要每次想要组合其他函数时都写一个特殊的函数。

组合两个函数非常容易，只需要对我们在本章前面看到的`pipeTwo()`函数进行一点小改动：

```js
const pipeTwo = (f, g) => (...args) => g(f(...args));
const composeTwo = (f, g) => (...args) => f(g(...args));
```

唯一的区别是，使用流水线处理时，你首先应用最左边的函数，而使用组合时，你从最右边的函数开始。这种变化表明我们可以使用来自第七章 *转换函数-柯里化和部分应用*部分的`flipTwo()`高阶函数。这样清楚吗？

```js
const composeTwoByFlipping = flipTwo(pipeTwo);
```

无论如何，如果我们想要组合超过两个函数，我们也可以利用结合律，编写类似以下的内容：

```js
const getUniqueWords3 = composeTwo(
 setToList,
 composeTwo(
 arrayToSet,
 composeTwo(splitInWords, composeTwo(toUpperCase, removeNonAlpha))
 )
);

console.log(getUniqueWords3(GETTYSBURG_1_2));
// [ 'A', 'AGO', 'ALL', 'AND', ... 'WAR', 'WE', 'WHETHER', 'YEARS' ] *OK again*
```

尽管这样可以运行，但让我们寻找更好的解决方案--我们可以提供至少两种。第一种方法与流水线和组合工作*相反*有关。当我们进行流水线处理时，我们从左到右应用函数，而在组合时，我们从右到左应用函数。因此，我们可以通过颠倒函数的顺序并进行流水线处理来实现与组合相同的结果；这是一个非常实用的解决方案，我非常喜欢！

```js
const compose = (...fns) => pipeline(...(fns.reverse**()))**; console.log(
 compose(
 setToList,
 arrayToSet,
 splitInWords,
 toUpperCase,
 removeNonAlpha
 )(GETTYSBURG_1_2)
);
// [ 'A', 'AGO', 'ALL', 'AND', ... 'WAR', 'WE', 'WHETHER', 'YEARS' ] *OK once more*  
```

唯一棘手的部分是在调用`pipeline()`之前使用展开运算符。在反转`fns`数组之后，我们必须再次展开其元素，以正确调用`pipeline()`。

另一个不太声明式的解决方案是使用`.reduceRight()`，所以我们不是反转函数列表，而是反转处理它们的顺序：

```js
const  compose2  = (...fns) => fns.reduceRight(pipeTwo);

console.log(
 compose2(
 setToList,
 arrayToSet,
 splitInWords,
 toUpperCase,
 removeNonAlpha
 )(GETTYSBURG_1_2)
);
// [ 'A', 'AGO', 'ALL', 'AND', ... 'WAR', 'WE', 'WHETHER', 'YEARS' ] *still OK* 
```

为什么/如何这个工作？让我们跟随这个调用的内部工作。我们可以用它的定义替换`pipeTwo()`，以使这更清晰：

```js
const  compose2b  = (...fns) => 
 fns.reduceRight((f,g) => (...args) =>  g(f(...args)));
```

好的，让我们看看！

+   由于没有提供初始值，第一次`f()`是`removeNonAlpha()`，`g()`是`toUpperCase()`，所以第一个中间结果是一个函数`(...args) => toUpperCase(removeNonAlpha(...args))`；让我们称之为`step1()`。

+   第二次，`f()`是前一步的`step1()`，`g()`是`splitInWords()`，所以新的结果是一个函数`(...args) => splitInWords(step1(...args)))`，我们可以称之为`step2()`

+   第三次，以同样的方式，我们得到`(...args) => arrayToSet(step2(...args))))`，我们称之为`step3()`

+   最后一次，结果是`(...args) => setToList(step3(...args))`，一个名为`step4()`的函数

最终的结果正确地成为一个接收`(...args)`的函数，并首先应用`removeNonAlpha()`，然后是`toUpperCase()`，以此类推，最后应用`setToList()`。

也许令人惊讶的是，我们也可以用`.reduce()`来实现这个功能--你能看出为什么吗？推理与我们所做的类似，所以我们将其留给读者作为*一个练习*！

```js
const  compose3  = (...fns) => fns.reduce(composeTwo**)**;
```

弄清楚`compose3()`的工作原理后，您可能想编写一个使用`.reduceRight()`的`pipeline()`版本，只是为了对称地完成一切！

我们可以通过提及，就测试和调试而言，我们可以应用与调试相同的思想；只是记住组合*走另一条路*！我们不会通过提供更多相同类型的示例来获得任何好处，所以现在让我们考虑一种在使用对象时链接操作的常见方式，并看看它是否有利，鉴于我们不断增长的 FP 知识和经验。

# 测试组合函数

让我们通过考虑对流水线化或组合函数进行测试来完成本章。鉴于这两种操作的机制相似，我们将为它们都提供示例，它们不会有区别，除了由于函数评估的从左到右或从右到左的逻辑差异。

在流水线方面，我们可以从看如何测试`pipeTwo()`函数开始，因为设置将类似于`pipeline()`。我们需要创建一些间谍，然后检查它们是否被正确调用了正确次数，以及每次是否收到了正确的参数。我们将设置间谍，以便它们提供对调用的已知答案，这样我们就可以看到函数的输出是否成为管道中下一个函数的输入：

```js
var fn1, fn2;

describe("pipeTwo", function() {
 beforeEach(() => {
 fn1 = () => {};
 fn2 = () => {};
 });

 it("works with single arguments", () => {
 spyOn(window, "fn1").and.returnValue(1);
 spyOn(window, "fn2").and.returnValue(2);

 const pipe = pipeTwo(fn1, fn2);
 const result = pipe(22);

 expect(fn1).toHaveBeenCalledTimes(1);
 expect(fn2).toHaveBeenCalledTimes(1);
 expect(fn1).toHaveBeenCalledWith(22);
 expect(fn2).toHaveBeenCalledWith(1);
 expect(result).toBe(2);
 });

 it("works with multiple arguments", () => {
 spyOn(window, "fn1").and.returnValue(11);
 spyOn(window, "fn2").and.returnValue(22);

 const pipe = pipeTwo(fn1, fn2);
 const result = pipe(12, 4, 56);

 expect(fn1).toHaveBeenCalledTimes(1);
 expect(fn2).toHaveBeenCalledTimes(1);
 expect(fn1).toHaveBeenCalledWith(12, 4, 56);
 expect(fn2).toHaveBeenCalledWith(11);
 expect(result).toBe(22);
 });
});
```

鉴于我们的函数始终接收两个函数作为参数，没有太多需要测试的。测试之间唯一的区别是一个显示了对单个参数应用的管道，另一个显示了对多个参数应用。

接下来是`pipeline()`，测试会相当类似。不过，我们可以为单函数管道添加一个测试（边界情况！），另一个测试包含四个函数：

```js
describe("pipeline", function() {
 beforeEach(() => {
 fn1 = () => {};
 fn2 = () => {};
 fn3 = () => {};
 fn4 = () => {};
 });

 it("works with a single function", () => {
 spyOn(window, "fn1").and.returnValue(11);

 const pipe = pipeline(fn1);
 const result = pipe(60);

 expect(fn1).toHaveBeenCalledTimes(1);
 expect(fn1).toHaveBeenCalledWith(60);
 expect(result).toBe(11);
 });

 // *we omit here tests for 2 functions,*
 // *which are similar to those for pipeTwo()*

 it("works with 4 functions, multiple arguments", () => {
 spyOn(window, "fn1").and.returnValue(111);
 spyOn(window, "fn2").and.returnValue(222);
 spyOn(window, "fn3").and.returnValue(333);
 spyOn(window, "fn4").and.returnValue(444);

 const pipe = pipeline(fn1, fn2, fn3, fn4);
 const result = pipe(24, 11, 63);

 expect(fn1).toHaveBeenCalledTimes(1);
 expect(fn2).toHaveBeenCalledTimes(1);
 expect(fn3).toHaveBeenCalledTimes(1);
 expect(fn4).toHaveBeenCalledTimes(1);
 expect(fn1).toHaveBeenCalledWith(24, 11, 63);
 expect(fn2).toHaveBeenCalledWith(111);
 expect(fn3).toHaveBeenCalledWith(222);
 expect(fn4).toHaveBeenCalledWith(333);
 expect(result).toBe(444);
 });
});
```

最后，对于组合，风格是一样的（除了函数评估的顺序相反），所以让我们只看一个测试--我只是改变了前一个测试中函数的顺序：

```js
var fn1, fn2, fn3, fn4;

describe("compose", function() {
 beforeEach(() => {
 fn1 = () => {};
 fn2 = () => {};
 fn3 = () => {};
 fn4 = () => {};
 });

 // *other tests omitted...*

 it("works with 4 functions, multiple arguments", () => {
 spyOn(window, "fn1").and.returnValue(111);
 spyOn(window, "fn2").and.returnValue(222);
 spyOn(window, "fn3").and.returnValue(333);
 spyOn(window, "fn4").and.returnValue(444);

 const pipe = compose(fn4, fn3, fn2, fn1);
 const result = pipe(24, 11, 63);

 expect(fn1).toHaveBeenCalledTimes(1);
 expect(fn2).toHaveBeenCalledTimes(1);
 expect(fn3).toHaveBeenCalledTimes(1);
 expect(fn4).toHaveBeenCalledTimes(1);

 expect(fn1).toHaveBeenCalledWith(24, 11, 63);
 expect(fn2).toHaveBeenCalledWith(111);
 expect(fn3).toHaveBeenCalledWith(222);
 expect(fn4).toHaveBeenCalledWith(333);
 expect(result).toBe(444);
 });
});
```

最后，为了测试`chainify()`函数，我选择使用上面创建的`City`对象--我不想搞乱模拟、存根、间谍之类的东西，而是想确保代码在正常情况下能够工作：

```js
class City {
 // *as above*
}

var myCity;

describe("chainify", function() {
 beforeEach(() => {
 myCity = new City("Montevideo, Uruguay", -34.9011, -56.1645);
 myCity = chainify(myCity);
 });

 it("doesn't affect get functions", () => {
 expect(myCity.getName()).toBe("Montevideo, Uruguay");
 expect(myCity.getCoords()[0]).toBe(-34.9011);
 expect(myCity.getCoords()[1]).toBe(-56.1645);
 });

 it("doesn't affect getting attributes", () => {
 expect(myCity.name).toBe("Montevideo, Uruguay");
 expect(myCity.lat).toBe(-34.9011);
 expect(myCity.long).toBe(-56.1645);
 });

 it("returns itself from setting functions", () => {
 expect(myCity.setName("Other name")).toBe(myCity);
 expect(myCity.setLat(11)).toBe(myCity);
 expect(myCity.setLong(22)).toBe(myCity);
 });

 it("allows chaining", () => {
 const newCoords = myCity
 .setName("Pune, India")
 .setLat(18.5626)
 .setLong(73.8087)
 .getCoords();

 expect(myCity.name).toBe("Pune, India");
 expect(newCoords[0]).toBe(18.5626);
 expect(newCoords[1]).toBe(73.8087);
 });
});
```

所有测试的最终结果显示在下图中：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/227d5add-a038-4d6d-815d-844f02424a28.png)图 8.3。组合函数测试的成功运行。

# 问题

8.1\. **标题大写**。让我们定义*标题风格大写*，要求一个句子全部用小写书写，除了每个单词的第一个字母。（这种风格的真正定义更复杂，所以让我们简化这个问题。）编写一个函数`headline(sentence)`，它将接收一个字符串作为参数，并返回一个适当大写的版本。空格分隔单词。通过组合较小的函数来构建这个函数：

```js
 console.log(headline("**Alice's ADVENTURES in WoNdErLaNd**")); 
 // Alice's Adventures In Wonderland
```

8.2\. **待办任务**。一个 web 服务返回一个结果，如下所示，逐个人显示他们所有分配的任务。任务可能已完成（`done===true`）或待办（`done===false`）。你的目标是为给定的人（通过名字识别）生成一个待办任务 ID 数组，该数组应该与`responsible`字段匹配。通过使用组合或管道解决这个问题：

```js
 const allTasks = {
 date: "2017-09-22",
 byPerson: [
 {
 responsible: "EG",
 tasks: [
 {id: 111, desc: "task 111", done: false},
 {id: 222, desc: "task 222", done: false}
 ]
 },
 {
 responsible: "FK",
 tasks: [
 {id: 555, desc: "task 555", done: false},
 {id: 777, desc: "task 777", done: true},
 {id: 999, desc: "task 999", done: false}
 ]
 },
 {
 responsible: "ST",
 tasks: [{id: 444, desc: "task 444", done: true}]
 }
 ]
 };
```

确保你的代码不会抛出异常，例如，如果你要查找的人在 web 服务结果中没有出现！

在书的最后一章，*更进一步*，我们将看到另一种解决这个问题的方法，通过使用`Maybe`单子，这将大大简化处理可能缺失的数据的问题。

8.3\. **以抽象方式思考**。假设你正在查看一些旧代码，你发现一个函数看起来像下面这样。（我保持名称模糊和抽象，这样你可以专注于结构而不是实际功能。）你能把这个转换成 Pointfree 风格吗？

```js
function getSomeResults(things) {
 return sort(group(filter(select(things))));
};
```

# 总结

在本章中，我们已经看到了通过不同方式将几个其他函数连接起来创建新函数的方法，通过管道化（还有一个我们不推荐的变体，链式）和组合。

在第九章中，*设计函数 - 递归*，我们将继续进行函数设计，并学习递归的使用，这在函数式编程中经典上是一种基本工具，并且允许非常干净的算法设计。


# 第九章：设计函数-递归

在第八章中，*连接函数-管道和组合*，我们考虑了更多的方法来通过组合现有的函数来创建新函数。在这里，我们将进入一个不同的主题：如何通过应用递归技术以典型的功能方式设计和编写函数。

我们将涵盖以下主题：

+   了解递归是什么以及如何思考以产生递归解决方案

+   将递归应用于一些众所周知的问题，例如找零钱或*汉诺塔*

+   使用递归而不是迭代来重新实现早期章节中的一些高阶函数

+   轻松编写搜索和回溯算法

+   遍历数据结构，例如树，以处理文件系统目录或浏览器 DOM

+   解决由浏览器 JS 引擎考虑引起的一些限制

# 使用递归

递归是 FP 中的关键技术，有些语言甚至不提供任何形式的迭代或循环，而完全使用递归（我们已经提到的 Haskell 就是一个典型例子）。计算机科学的一个基本事实是，无论您使用递归还是迭代（循环），您都可以使用递归完成的任何事情，反之亦然。关键概念是有许多算法的定义如果使用递归工作起来要容易得多。另一方面，递归并不总是被教授，或者许多程序员即使了解它，也宁愿不使用它。因此，在本节中，我们将看到几个递归思维的例子，以便您可以将其适应到您的功能编码中。

典型的、经常引用的、非常古老的计算机笑话！*字典定义：

**递归**：（n）见**递归***

但是，什么是递归？有许多定义递归的方法，但我见过的最简单的一种是*一个函数一遍又一遍地调用自己，直到不再需要*。递归是解决几种问题的自然技术，例如：

+   数学定义，例如斐波那契数或阶乘

+   与递归定义的结构相关的数据结构算法，例如*列表*（列表要么为空，要么由一个头节点和一个节点列表组成）或*树*（树可以被定义为一个特殊节点，称为根节点，链接到零个或多个树）

+   基于语法规则的编译器的语法分析，这些规则本身依赖于其他规则，这些规则又依赖于其他规则，依此类推

+   以及更多

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/702ab100-d540-4e19-a179-027a0c040b90.png)Google 本身就对此开玩笑：如果您询问递归，它会回答您是否想要：递归！

无论如何，递归函数除了一些简单的*基本*情况外，其中不需要进一步的计算，总是需要调用自身一次或多次以执行所需计算的一部分。这个概念现在可能不太清楚，所以让我们看看如何以递归的方式思考，然后通过应用该技术解决几个常见问题。

# 递归思考

递归解决问题的关键是假设您已经有一个可以满足您需求的函数，然后正常调用它。（这听起来奇怪吗？实际上，这是相当合适的：要使用递归解决问题，您必须首先解决问题...）另一方面，如果您试图在脑海中思考递归调用的工作方式并尝试在脑海中跟随流程，您可能会迷失方向。因此，您需要做的是：

1.  假设您已经有一个适当的函数来解决您的问题。

1.  然后，看看如何通过解决一个（或多个）较小的问题来解决大问题。

1.  使用步骤 1 中想象的函数解决这些问题。

1.  确定哪些是您的*基本情况*，足够简单，可以直接解决，不需要任何更多的调用。

有了这些元素，你可以通过递归来解决问题，因为你将拥有递归解决方案的基本结构。

通过应用递归，有三种通常的方法来解决问题：

+   **减少和征服**是最简单的情况，其中解决一个问题直接取决于解决其自身的一个更简单的情况

+   **分而治之**是一种更一般的方法。其思想是尝试将问题分解为两个或更多较小的版本，递归地解决它们，并使用这些解决方案来解决原始问题。*减少和征服*的唯一区别在于，这里你需要解决两个或更多其他问题，而不仅仅是一个问题

+   **动态规划**可以被看作是*分而治之*的一种变体：基本上，你通过将一个复杂的问题分解为一系列稍微简单的相同问题的版本，并依次解决每个问题来解决它。然而，这种策略中的一个关键思想是存储先前找到的解决方案，因此每当你发现自己需要再次解决一个更简单的情况时，你不会直接应用递归，而是使用存储的结果，避免不必要的重复计算

在这一部分，我们将看到一些问题，并通过递归的方式来解决它们。当然，在本章的其余部分，我们将看到递归的更多应用；在这里，我们将专注于创建这样一个算法所需的关键决策和问题。

# 减少和征服：搜索

递归的最常见情况涉及一个更简单的情况。我们已经看到了一些例子，比如普遍的阶乘计算：要计算*n*的阶乘，你之前需要计算*n-1*的阶乘。（见第一章，*成为函数式 - 几个问题*。）现在让我们转向一个非数学的例子。

要在数组中搜索一个元素，你也会使用这种*减少和征服*策略。如果数组为空，显然搜索的值不在其中。否则，结果在数组中，当且仅当它是数组中的第一个元素，或者它在数组的其余部分中：

```js
const search = (arr, key) => {
 if (arr.length === 0) {
 return false;
 } else if (arr[0] === key) {
 return true;
 } else {
 return search(arr.slice(1), key);
 }
};
```

这个实现直接反映了我们的解释，很容易验证其正确性。

顺便说一句，作为一种预防措施，让我们看看相同概念的另外两种实现。你可以稍微缩短搜索函数 -- 这样还清晰吗？

```js
const search2 = (arr, key) =>
 arr.length === 0
 ? false
 : arr[0] === key || search2(arr.slice(1), key);
```

稀疏性甚至可以更进一步！

```js
const search3 = (arr, key) =>
 arr.length && (arr[0] === key || search3(arr.slice(1), key));
```

我并不是真的建议你以这种方式编写函数 -- 相反，把它看作是对一些 FP 开发者倾向的一种警告，他们试图去寻求最紧凑、最简短的解决方案...而不在乎清晰度！

# 减少和征服：做幂

另一个经典的例子涉及以高效的方式计算数字的幂。如果你想计算，比如说，2 的 13 次方（2¹³），你可能需要进行 12 次乘法。然而，你可以通过将 2¹³写成以下形式来做得更好：

= 2 乘以 2¹²

= 2 乘以 4⁶

= 2 乘以 16³

= 2 乘以 16 乘以 16²

= 2 乘以 16 乘以 256¹

= 8192

总乘法次数的减少可能看起来并不是很令人印象深刻，但是从算法复杂度的角度来看，它可以将计算的顺序从*O(n)*降低到*O(lg n)*。在一些与加密相关的方法中，这将产生非常重要的差异。我们可以用几行代码来实现这个递归算法：

```js
const powerN = (base, power) => {
 if (power === 0) {
 return 1;
 } else if (power % 2) { // *odd power?*
 return base * powerN(base, power - 1);
 } else { // *even power?*
 return powerN(base * base, power / 2);
 }
};
```

在生产中实现时，会使用位操作，而不是模数和除法。检查一个数字是否是奇数可以写为`power & 1`，而除以 2 可以用`power > > 1`来实现。这些替代计算比被替换的操作要快得多。

当达到基本情况（将某物的零次方）或者基于先前计算较小指数的一些幂进行计算时，计算幂是简单的。（如果你愿意，你可以为将某物的一次方添加另一个基本情况。）这些观察表明，我们正在看到*减少和征服*递归策略的教科书案例。

最后，我们的一些高阶函数，比如`map()`、`reduce()`或`filter()`，也应用了这种技术；我们将在本章后面讨论这个问题。

# 分而治之：汉诺塔

使用这种策略，解决一个问题需要两个或更多的递归解决方案。首先，让我们考虑一个经典的难题，由 19 世纪法国数学家Édouard Lucas 发明。据说印度有一座寺庙，有三根柱子，上面有 64 个金质圆盘，直径递减。僧侣们必须将圆盘从第一根柱子移动到最后一根柱子，遵循两条规则：一次只能移动一个圆盘，较大的圆盘永远不能放在较小的圆盘上。根据传说，当 64 个圆盘移动时，世界将终结。这个难题通常以*汉诺塔*的名义（是的，他们换了国家！）在 10 个圆盘以下进行市场营销。见图 9.1：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/bf050084-6ffd-480f-91c0-e04a23136daa.jpg)图 9.1-经典的汉诺塔难题有一个简单的递归解法。n 个圆盘的解决方案需要*2^n-1*次移动。原始难题需要*2⁶⁴-1*次移动，以每秒一次的速度，需要超过 5840 亿年才能完成……这是一个非常长的时间，考虑到宇宙的年龄只有 138 亿年！

假设我们已经有一个能够解决从源柱移动任意数量的圆盘到目标柱，使用剩余柱作为额外辅助的问题的函数。那么，现在考虑解决一般问题，如果你已经有一个解决该问题的函数：`hanoi(disks, from, to, extra)`。如果你想要从一个柱移动多个圆盘到另一个柱，你可以通过使用这个（尚未编写的！）函数轻松解决：

+   将所有圆盘但一个移动到额外柱

+   将较大的圆盘移动到目标柱

+   再次使用你的函数，将所有圆盘从额外柱（你之前放置它们的地方）移动到目标柱

但是，我们的基本情况呢？我们可以决定，要移动一个单独的圆盘，你不需要使用函数；你可以直接移动它。编码后变成：

```js
const hanoi = (disks, from, to, extra) => {
 if (disks === 1) {
 console.log(`Move disk 1 from post ${from} to post ${to}`);
 } else {
        hanoi(disks - 1, from, extra, to);
 console.log(`Move disk ${disks} from post ${from} to post ${to}`);
        hanoi(disks - 1, extra, to, from);
 }
};
```

我们可以快速验证这段代码是否有效：

```js
hanoi (4, "A", "B", "C"); // we want to move all disks from A to B
Move disk 1 from post A to post C
Move disk 2 from post A to post B
Move disk 1 from post C to post B
Move disk 3 from post A to post C
Move disk 1 from post B to post A
Move disk 2 from post B to post C
Move disk 1 from post A to post C
Move disk 4 from post A to post B
Move disk 1 from post C to post B
Move disk 2 from post C to post A
Move disk 1 from post B to post A
Move disk 3 from post C to post B
Move disk 1 from post A to post C
Move disk 2 from post A to post B
Move disk 1 from post C to post B 
```

还有一个小细节需要考虑，可以进一步简化函数。在这段代码中，我们的基本情况（不需要进一步递归的情况）是`disks`等于 1。你也可以以不同的方式解决它，让圆盘减少到零，然后根本不做任何事情——毕竟，从一个柱移动零个圆盘到另一个柱是通过根本不做任何事情来实现的！

```js
const hanoi2 = (disks, from, to, extra) => {
 if (disks > 0) {
 hanoi(disks - 1, from, extra, to);
 console.log(`Move disk ${disks} from post ${from} to post ${to}`);
 hanoi(disks - 1, extra, to, from);
 }
};
```

我们可以跳过检查是否有圆盘需要移动，而不是在进行递归调用之前进行检查，并让函数在下一级测试是否有事情要做。

如果你正在手动解决这个难题，有一个简单的解决方案：在奇数轮次，总是将较小的圆盘移动到下一个柱子（如果圆盘的总数是奇数）或者移动到前一个柱子（如果圆盘的总数是偶数）。在偶数轮次，做唯一可能的不涉及较小圆盘的移动。

因此，递归算法设计的原则是有效的：假设你已经有了你想要的函数，并用它来构建它！

# 分而治之：排序

我们可以看到另一个例子，使用*分而治之*策略，进行排序。一种对数组进行排序的方法，称为*快速排序*，基于以下前提：

1.  如果你的数组有 0 或 1 个元素，什么也不做；它已经排序好了（这是基本情况）。

1.  否则，选择数组的某个元素（称为“枢轴”），并将数组的其余部分分成两个子数组：小于您选择的元素和大于或等于您选择的元素的元素。

1.  递归地对每个子数组进行排序。

1.  将两个排序后的结果连接起来，枢轴放在中间，以生成原始数组的排序版本。

让我们看一个简单版本的这个问题--有一些更好优化的实现，但我们现在对递归逻辑感兴趣。通常建议随机选择数组的一个元素，以避免一些性能不佳的边界情况，但是对于我们的例子，让我们只取第一个元素：

```js
const quicksort = arr => {
 if (arr.length < 2) {
 return arr;
 } else {
 const pivot = arr[0];
 const smaller = arr.slice(1).filter(x => x < pivot);
 const greaterEqual = arr.slice(1).filter(x => x >= pivot);
 return [...quicksort(smaller), pivot, ...quicksort(greaterEqual)];
 }
};

console.log(quicksort([22, 9, 60, 12, 4, 56]));
// *[4, 9, 12, 22, 56, 60]*
```

我们可以在图 9.2 中看到这是如何工作的：每个数组和子数组的枢轴都被划线标出。拆分用虚线箭头表示，并用实线连接：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/6a70f2e3-5083-417d-ba2b-a5eb0a3122e0.jpg)图 9.2\. 快速排序递归地对数组进行排序，应用分而治之的策略，将原始问题减小为较小的问题。

# 动态规划：找零

第三种一般策略，*动态规划*，假设您将不得不解决许多较小的问题，但是不是每次都使用递归，而是依赖于存储先前找到的解决方案...也就是记忆化！在第四章中，*行为得当 - 纯函数*，以及在第六章中以更好的方式，*生成函数 - 高阶函数*，我们已经看到了如何优化通常的斐波那契数列的计算，避免不必要的重复调用。现在，让我们考虑另一个问题。

给定一定金额的美元和现有票面值列表，计算我们可以用不同的票据组合支付该金额的美元的方式有多少种。假设您可以无限使用每张票据。我们该如何解决这个问题？让我们从考虑基本情况开始，不需要进一步计算的情况：

+   支付负值是不可能的，因此在这种情况下，我们应该返回 0

+   支付零美元只有一种可能的方式（不给任何票据），因此在这种情况下，我们应该返回 1

+   如果没有提供任何票据，则无法支付任何正数金额的美元，因此在这种情况下也返回 0

最后，我们可以回答这个问题：用给定的票据集合，我们可以用多少种方式支付`N`美元？我们可以考虑两种情况：我们根本不使用更大的票据，只使用较小面额的票据支付金额，或者我们可以拿一张更大金额的票据，并重新考虑这个问题。（现在让我们忘记避免重复计算。）

+   在第一种情况下，我们应该使用相同的`N`值调用我们假定存在的函数，但已经从可用票据列表中删除了最大面额的票据

+   在第二种情况下，我们应该使用`N`减去最大面额的票据调用我们的函数，保持票据列表不变：

```js
const makeChange = (n, bills) => {
 if (n < 0) {
 return 0; // no way of paying negative amounts

 } else if (n == 0) {
 return 1; // one single way of paying $0: with no bills

 } else if (bills.length == 0) {
 // here, n>0
 return 0; // no bills? no way of paying

 } else {
 return (
 makeChange(n, bills.slice(1)) + makeChange(n - bills[0], bills)
 );
 }
};

console.log(makeChange(64, [100, 50, 20, 10, 5, 2, 1]));
// *969 ways of paying $64*
```

现在，让我们进行一些优化。这种算法经常需要一遍又一遍地重新计算相同的值。（要验证这一点，在`makeChange()`的第一行添加`console.log(n, bills.length)`，但要准备大量的输出！）但是，我们已经有了解决方案：记忆化！由于我们正在将这种技术应用于二元函数，我们将需要一个处理多个参数的记忆化算法的版本：

```js
const memoize3 = fn => {
 let cache = {};
 return (...args) => {
 let strX = JSON.stringify(args);
 return strX in cache ? cache[strX] : (cache[strX] = fn(...args));
 };
};

const makeChange = memoize3((n, bills) => {
 // ...*same as above*
});
```

`makeChange()`的记忆化版本要高效得多，您可以通过记录来验证。虽然您可以自己处理重复（例如，通过保留已计算的值的数组），但是记忆化解决方案在我看来更好，因为它由两个函数组合产生了给定问题的更好解决方案。

# 高阶函数再探讨

经典的 FP 技术根本不使用迭代，而是完全依赖递归作为唯一的循环方式。让我们重新审视一些我们在第五章中已经看到的函数，如`map()`、`reduce()`、`find()`和`filter()`，看看我们如何只使用递归就能完成。

尽管如此，我们并不打算用我们自己的*递归 polyfills*替换基本的 JS 函数：很可能我们的性能会比*递归 polyfills*差，而且我们不会因为函数使用递归而获得任何优势。相反，我们想研究如何以递归方式执行迭代，因此我们的努力更多是教学性的，好吗？

# 映射和过滤

映射和过滤非常相似，因为两者都意味着遍历数组中的所有元素，并对每个元素应用回调以产生输出。让我们首先解决映射逻辑，这将有几个要解决的问题，然后过滤将变得几乎轻而易举，只需要做一些小改动。

对于映射，根据我们使用的递归函数开发方式，我们需要一个基本情况。幸运的是，这很容易：映射一个空数组只会产生一个新的空数组。映射一个非空数组可以通过首先将映射函数应用于数组的第一个元素，然后递归地映射数组的其余部分，最后产生一个累积两个结果的单一数组。

基于这个想法，我们可以制定一个简单的初始版本：让我们称之为`mapR()`，只是为了记住我们正在处理我们自己的递归版本的`map()`。但是，要小心：我们的 polyfill 有一些错误！我们将逐个解决它们：

```js
const mapR = (arr, cb) =>
    arr.length === 0 ? [] : [cb(arr[0])].concat(mapR(arr.slice(1), cb));
```

让我们来测试一下：

```js
let aaa = [ 1, 2, 4, 5, 7];
const timesTen = x => x * 10;

console.log(aaa.map(timesTen));   // *[**10, 20, 40, 50, 70**]*
console.log(mapR(aaa, timesTen)); // *[**10, 20, 40, 50, 70**]*
```

太好了！我们的`mapR()`函数似乎产生了与`.map()`相同的结果...但是，我们的回调函数不应该接收更多的参数吗，特别是数组中的索引和原始数组本身？我们的实现还不够完善。

查看`.map()`的回调函数的定义：[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/map)

```js
const timesTenPlusI = (v, i) => 10 * v + i;

console.log(aaa.map(timesTenPlusI));    // *[10, 21, 42, 53, 74]*
console.log(mapR2(aaa, timesTenPlusI)); // *[**NaN, NaN, NaN, NaN, NaN**]*
```

生成适当的索引位置将需要递归的额外参数，但基本上很简单：当我们开始时，我们有`index=0`，当我们递归调用我们的函数时，它从位置`index+1`开始。访问原始数组需要另一个参数，这个参数永远不会改变：

```js
const mapR2 = (arr, cb, i = 0, orig = arr) =>
 arr.length == 0
 ? []
 : [cb(arr[0], i, orig)].concat(
 mapR2(arr.slice(1), cb, i + 1, orig)
 );

let aaa = [1, 2, 4, 5, 7];
const senseless = (x, i, a) => x * 10 + i + a[i] / 10;
console.log(aaa.map(senseless));    // *[**10.1, 21.2, 42.4, 53.5, 74.7**]*
console.log(mapR2(aaa, senseless)); // *[**10.1, 21.2, 42.4, 53.5, 74.7**]*
```

太好了！当你使用递归而不是迭代时，你就无法访问索引，所以如果你需要它（就像我们的情况一样），你就必须自己生成它。这是一种经常使用的技术，所以制定我们的`.map()`替代方案是一个好主意。

但是，函数中有额外的参数并不是很好；开发人员可能会意外地提供它们，然后结果将是不可预测的。因此，使用另一种常用的技术，让我们定义一个内部函数`mapLoop()`来处理循环。实际上，这是唯一使用递归时实现循环的常规方式：

```js
const mapR3 = (orig, cb) => {
 const mapLoop = (arr, i) =>
 arr.length == 0
 ? []
 : [cb(arr[0], i, orig)].concat(
 mapR3(arr.slice(1), cb, i + 1, orig)
 );

 return mapLoop(orig, 0);
};
```

只有一个未解决的问题：如果原始数组中有一些缺失的元素，在循环过程中它们应该被跳过：

```js
[1, 2, , , 5].map(tenTimes)
// [10, 20, undefined × 2, 50]
```

幸运的是，修复这个问题很简单——并且很高兴在这里获得的所有经验将帮助我们编写本节中的其他函数！

```js
const mapR4 = (orig, cb) => {
 const mapLoop = (arr, i) => {
 if (arr.length == 0) {
 return [];
 } else {
 const mapRest = mapR4(arr.slice(1), cb, i + 1, orig);
 if (!(0 in arr)) {
 return [,].concat(mapRest);
 } else {
 return [cb(arr[0], i, orig)].concat(mapRest);
 }
 }
 };
 return mapLoop(orig, 0);
};

console.log(mapR4(aaa, timesTen)); // *[**10, 20, undefined × 2, 50**]*
```

哇！这比我们预期的要多得多，但我们看到了几种技巧：用递归替换迭代，如何在迭代中累积结果，如何生成和提供索引值——很好的建议！此外，编写过滤代码将会更容易，因为我们可以应用与映射几乎相同的逻辑。主要区别在于我们使用回调函数来决定元素是否进入输出数组，因此内部循环函数会稍微长一点：

```js
const filterR = (orig, cb) => {
 const filterLoop = (arr, i) => {
 if (arr.length == 0) {
 return [];
 } else {
 const filterRest = filterR(arr.slice(1), cb, i + 1, orig);
 if (!(0 in arr)) {
 return filterRest;
 } else if (cb(arr[0], i, orig)) {
 return [arr[0]].concat(filterRest);
 } else {
 return filterRest;
 }
 }
 };
 return filterLoop(orig, 0);
};

let aaa = [1, 12, , , 5, 22, 9, 60];
const isOdd = x => x % 2;
console.log(aaa.filter(isOdd));   // *[1, 5, 9]*
console.log(filterR(aaa, isOdd)); // *[1, 5, 9]*
```

好吧，我们成功实现了两个基本的高阶函数，使用了非常相似的递归函数。其他的呢？

# 其他高阶函数

从一开始，编写`.reduce()`就有点棘手，因为你可以决定省略累加器的初始值。既然我们之前提到提供该值通常更好，那么我们在这里假设它会被给出；处理其他可能性也不会太难。

基本情况很简单：如果数组为空，结果就是累加器。否则，我们必须将 reduce 函数应用于当前元素和累加器，更新后者，然后继续处理数组的其余部分。这可能有点令人困惑，因为有三元运算符，但毕竟，我们已经看到了，应该足够清楚：

```js
const reduceR = (orig, cb, accum) => {
 const reduceLoop = (arr, i) => {
 return arr.length == 0
 ? accum
 : reduceR(
 arr.slice(1),
 cb,
 !(0 in arr) ? accum : cb(accum, arr[0], i, orig),
 i + 1,
 orig
 );
 };
 return reduceLoop(orig, 0);
};

let bbb = [1, 2, , 5, 7, 8, 10, 21, 40];
console.log(bbb.reduce((x, y) => x + y, 0));   // 94
console.log(reduce2(bbb, (x, y) => x + y, 0)); // 94
```

另一方面，`.find()`特别适用于递归逻辑，因为你（尝试）找到某物的定义本身就是递归的：

+   你首先看你想到的地方——如果你找到了你要找的东西，你就完成了

+   或者，你可以看看其他地方，看看你所寻找的东西是否在那里

我们只缺少基本情况，但那很简单：如果你没有地方可以查找，那么你知道你在搜索中不会成功：

```js
const findR = (arr, cb) => {
 if (arr.length === 0) {
 return undefined;
 } else {
 return cb(arr[0]) ? arr[0] : findR(arr.slice(1), cb);
 }
};
```

同样地：

```js
const findR2 = (arr, cb) =>
 arr.length === 0
 ? undefined
 : cb(arr[0]) ? arr[0] : findR(arr.slice(1), cb);
```

我们可以快速验证它的有效性：

```js
let aaa = [1, 12, , , 5, 22, 9, 60];
const isTwentySomething = x => 20 <= x && x <= 29;
console.log(findR(aaa, isTwentySomething)); // 22
const isThirtySomething = x => 30 <= x && x <= 39;
console.log(findR(aaa, isThirtySomething)); // undefined
```

让我们完成我们的管道函数。管道的定义本身适合快速实现。

+   如果我们想要将单个函数串联起来，那么结果就是管道的结果

+   否则，如果我们想要将几个函数串联起来，那么我们必须先应用初始函数，然后将该结果作为输入传递给其他函数的管道

我们可以直接将这转化为代码：

```js
const pipelineR = (first, ...rest) =>
 rest.length == 0
 ? first
 : (...args) => pipelineR(...rest)(first(...args));
```

我们可以验证它的正确性：

```js
const plus1 = x => x + 1;
const by10 = x => x * 10;

pipelineR(
 by10,
 plus1,
 plus1,
 plus1,
 by10,
 plus1,
 by10,
 by10,
 plus1,
 plus1,
 plus1
)(2);
// 23103
```

对于组合来说，做同样的事情很容易，只是你不能使用展开运算符来简化函数定义，而必须使用数组索引——自己解决吧！

# 搜索和回溯

寻找问题的解决方案，特别是当没有直接的算法，你必须诉诸反复试验时，递归特别适用。这些算法中的许多都属于这样的方案：

+   在众多可选项中，选择一个

+   如果没有其他选择，你就失败了

+   如果你能挑选一个，应用相同的算法，但找到其余部分的解决方案

+   如果你成功了，你就完成了

+   否则，尝试另一个选择

稍微变种一下，你也可以应用类似的逻辑来找到一个好的——或者可能是最优的——解决方案。每当你找到一个可能的解决方案时，你都会将其与之前可能找到的解决方案进行匹配，并决定保留哪一个。这可能会一直持续下去，直到所有可能的解决方案都被评估，或者直到找到足够好的解决方案为止。

有许多问题适用于这种逻辑：

+   找到迷宫的出口——选择任何路径，标记为*已经跟随*，并尝试找到迷宫的出口，不要重复使用该路径：如果成功，你就完成了，如果没有，回去选择另一条路径

+   填充数独谜题——如果一个空单元格只能包含一个数字，那么分配它；否则，运行所有可能的分配，并对每一个进行递归尝试，看看是否可以填充谜题的其余部分

+   下棋——你不太可能能够跟随所有可能的走法序列，所以你更愿意选择最佳估计的位置

让我们将这些技术应用于两个问题：解决*八皇后*问题和遍历完整的文件目录。

# 八皇后问题

*八皇后*问题是在 19 世纪发明的，需要在标准国际象棋棋盘上放置八个国际象棋皇后。特殊条件是没有皇后可以攻击另一个——这意味着没有一对皇后可以共享一行、一列或对角线。这个谜题可能要求任何解决方案，或者，正如我们将要做的那样，要求不同解决方案的总数。

这个谜题也可以推广到*n 皇后*，通过在*nxn*方格棋盘上工作。已知对于 n 的所有值都有解决方案，除了 n=2（很容易看出为什么：放置一个皇后后，整个棋盘都受到威胁）和 n=3（如果在中心放置一个皇后，整个棋盘都受到威胁，如果在一侧放置一个皇后，只有两个方块没有受到威胁--但它们互相威胁，这使得不可能在它们上面放置皇后）。

让我们从顶层逻辑开始解决我们的问题。由于给定的规则，每列中将有一个皇后，因此我们使用`places()`数组来记录每个皇后在给定列中的行。`SIZE`常量可以修改以解决更一般的问题。我们将在`solutions`变量中计算每个找到的皇后分布。最后，`finder()`函数将对解决方案进行递归搜索。

```js
const SIZE = 8;
let places = Array(SIZE);
let solutions = 0;

finder();
console.log(`Solutions found: ${solutions}`);
```

当我们想在某一列的特定行放置一个皇后时，我们必须检查之前放置的任何一个皇后是否已经放在了同一行或对角线上。让我们编写一个`checkPlace(column, row)`函数来验证是否可以安全地在给定方块中放置皇后。最直接的方法是使用`.every()`，如下面的代码所示：

```js
const checkPlace = (column, row) =>
 places
 .slice(0, column)
 .every((v, i) => v !== row && Math.abs(v - row) !== column - i);
```

这种声明式的方式似乎是最好的：当我们在一个位置放置一个皇后时，我们希望确保每个先前放置的皇后都在不同的行和对角线上。递归解决方案也是可能的，所以让我们看看。我们怎么知道一个方块是安全的？

+   基本情况是：当没有更多的列可以检查时，方块是安全的

+   如果方块与任何其他皇后在同一行或对角线上，那么它是不安全的

+   如果我们已经检查了一列，并且没有问题，我们现在可以递归地检查下一列：

```js
 const checkPlace2 = (column, row) => {
 const checkColumn = i => {
 if (i == column) {
 return true;
 } else if (
 places[i] == row ||
 Math.abs(places[i] - row) == column - i
 ) {
 return false;
 } else {
 return checkColumn(i + 1);
 }
 };
 return checkColumn(0);
 };
```

代码可以运行，但我不会使用它，因为声明版本更清晰。无论如何，经过这个检查，我们可以关注主`finder()`逻辑，它将进行递归搜索。过程如我们在开始时描述的那样进行：尝试为皇后找到可能的位置，如果可以接受，使用相同的搜索过程尝试放置剩余的皇后。我们从第 0 列开始，我们的基本情况是当我们到达最后一列时，这意味着所有皇后都已成功放置：我们可以打印出解决方案，计数它，并返回搜索新的配置。

看看我们如何使用`.map()`和一个简单的箭头函数来打印皇后的行，逐列，作为 1 到 8 之间的数字，而不是 0 到 7。在国际象棋中，行编号从 1 到 8（列从*a*到*h*，但这里并不重要）。

```js
const finder = (column = 0) => {
 if (column === SIZE) {
 // *all columns tried out?*
 console.log(places.map(x => x + 1)); // *print out solution*
 solutions++; // *count it*

 } else {
 const testRowsInColumn = j => {
 if (j < SIZE) {
 if (checkPlace(column, j)) {
 places[column] = j;
                    finder(column + 1);
 }
 testRowsInColumn(j + 1);
 }
 };
 testRowsInColumn(0);
 }
};
```

内部的`testRowsInColumn()`函数也起到了迭代的作用，但是是递归的。想法是尝试在每一行放置一个皇后，从零开始：如果方块是安全的，就调用`finder()`从下一列开始搜索。无论是否找到解决方案，都会尝试列中的所有行，因为我们对解决方案的总数感兴趣；在其他搜索问题中，您可能只对找到任何解决方案感兴趣，并且会在那里停止搜索。

我们已经走到了这一步，让我们找到我们问题的答案！

```js
[1, 5, 8, 6, 3, 7, 2, 4]
[1, 6, 8, 3, 7, 4, 2, 5]
[1, 7, 4, 6, 8, 2, 5, 3]
[1, 7, 5, 8, 2, 4, 6, 3]
*...*
*... 84 lines snipped out ...*
*...*
[8, 2, 4, 1, 7, 5, 3, 6]
[8, 2, 5, 3, 1, 7, 4, 6]
[8, 3, 1, 6, 2, 5, 7, 4]
[8, 4, 1, 3, 6, 2, 7, 5]
Solutions found: 92
```

每个解决方案都是以皇后的行位置，逐列给出的--总共有 92 个解决方案。

# 遍历树结构

数据结构，其中包括递归在其定义中，自然适合递归技术。让我们在这里考虑一个例子，例如如何遍历完整的文件系统目录，列出其所有内容。递归在哪里？如果您考虑到每个目录都可以执行以下操作之一，答案就会出现：

+   为空--一个基本情况，在这种情况下，没有任何事情要做

+   包括一个或多个条目，每个条目都是文件或目录本身

让我们解决一个完整的递归目录列表--也就是说，当我们遇到一个目录时，我们继续列出它的内容，如果其中包括更多的目录，我们也列出它们，依此类推。我们将使用与`getDir()`中相同的 Node.js 函数（来自第八章中的*手动构建管道*部分，*连接函数-管道和组合*），再加上一些函数，以便测试目录条目是否是符号链接（我们不会跟随它，以避免可能的无限循环），目录（这将需要递归列表）或普通文件：

```js
const fs = require("fs");

const recursiveDir = path => {
 console.log(path);
 fs.readdirSync(path).forEach(entry => {
 if (entry.startsWith(".")) {
 // skip it!

 } else {
 const full = path + "/" + entry;
 const stats = fs.lstatSync(full);
 if (stats.isSymbolicLink()) {
 console.log("L ", full); // symlink, don't follow

 } else if (stats.isDirectory()) {
 console.log("D ", full);
                recursiveDir(full);

 } else {
 console.log(" ", full);
 }
 }
 });
};
```

列表很长，但是正确的。我选择在我自己的 OpenSUSE Linux 笔记本电脑上列出`/boot`目录：

```js
recursiveDir("/boot"); /boot
 /boot/System.map-4.11.8-1-default
   /boot/boot.readme
   /boot/config-4.11.8-1-default
D  /boot/efi
D  /boot/efi/EFI
D  /boot/efi/EFI/boot
   /boot/efi/EFI/boot/bootx64.efi
   /boot/efi/EFI/boot/fallback.efi
   ...
 ... *many omitted lines*
 ...
L  /boot/initrd
   /boot/initrd-4.11.8-1-default
   /boot/message
   /boot/symtypes-4.11.8-1-default.gz
   /boot/symvers-4.11.8-1-default.gz
   /boot/sysctl.conf-4.11.8-1-default
   /boot/vmlinux-4.11.8-1-default.gz
L  /boot/vmlinuz
   /boot/vmlinuz-4.11.8-1-default
```

顺便说一句，我们可以将相同的结构应用于类似的问题：遍历 DOM 结构。我们可以从给定元素开始列出所有标签，使用基本相同的方法：我们列出一个节点，然后（通过应用相同的算法）列出它的所有子节点。基本情况也与以前相同：当一个节点没有子节点时，不再进行递归调用：

```js
const traverseDom = (node, depth = 0) => {
 console.log(`${"| ".repeat(depth)}<${node.nodeName.toLowerCase()}>`);
 for (let i = 0; i < node.children.length; i++) {
        traverseDom(node.children[i], depth + 1);
 }
};
```

我们使用`depth`变量来知道我们距离原始元素有多少*级别。当然，我们也可以使用它来使遍历逻辑在某个级别停止；在我们的情况下，我们只是使用它来添加一些竖线和空格，以适当地缩进每个元素，根据其在 DOM 层次结构中的位置。这个函数的结果如下。很容易列出更多的信息，而不仅仅是元素标签，但我想专注于递归过程：

```js
traverseDom(document.body);
<body>
| <script>
| <div>
| | <div>
| | | <a>
| | | <div>
| | | | <ul>
| | | | | <li>
| | | | | | <a>
| | | | | | | <div>
| | | | | | | | <div>
| | | | | | | <div>
| | | | | | | | <br>
| | | | | | | <div>
| | | | | | <ul>
| | | | | | | <li>
| | | | | | | | <a>
| | | | | | | <li>
*...etc!*
```

然而，有一个丑陋的地方：为什么我们要循环遍历所有子节点？我们应该更了解！问题在于我们从 DOM 中得到的结构实际上并不是一个数组。但是，有一个办法：我们可以使用`Array.from()`将其创建为一个真正的数组，然后编写一个更具声明性的解决方案：

```js
const traverseDom2 = (node, depth = 0) => {
 console.log(`${"| ".repeat(depth)}<${node.nodeName.toLowerCase()}>`);
    Array.from(node.children).forEach(child =>
 traverseDom2(child, depth + 1)
 );
};
```

写`[...node.children].forEach()`也可以工作，但我认为使用`Array.from()`可以更清楚地告诉潜在的读者，我们试图从看起来像数组的东西中创建一个数组，但实际上并不是。

# 递归技术

虽然递归是一种非常好的技术，但由于实际实现中的细节，它可能会遇到一些问题。每个函数调用，无论是递归还是非递归，都需要在内部 JS 堆栈中有一个条目。当您使用递归时，每个递归调用本身都计为另一个调用，您可能会发现在某些情况下，由于多次调用而导致代码崩溃并抛出错误，因为内存耗尽。另一方面，对于大多数当前的 JS 引擎，您可能可以有数千个待处理的递归调用而没有问题（但对于早期浏览器和较小的机器，这个数字可能会下降到数百，甚至可能更低），因此可以说，目前您不太可能遇到任何特定的内存问题。

无论如何，让我们回顾一下问题，并讨论一些可能的解决方案，因为即使您可能无法真正应用它们，它们代表了有效的 FP 思想，您可能会在其他问题中找到它们的位置。

# 尾调用优化

递归调用何时不是递归调用？以这种方式提出问题可能没有多少意义，但有一个常见的优化--对于其他语言来说，不幸的是，但不适用于 JS！--可以解释答案。如果递归调用是函数将要执行的最后一件事，那么调用可以转换为简单地跳转到函数的开始，而无需创建新的堆栈条目。（为什么？不需要堆栈条目：在递归调用完成后，函数将没有其他事情要做，因此无需进一步保存进入函数时推入堆栈的任何元素。）原始堆栈条目将不再需要，可以简单地替换为新的堆栈条目，对应于最近的调用。

递归调用，作为典型的 FP 技术，被一个基本的命令式`GO TO`语句实现，这可能被认为是一个终极的讽刺！

这些调用被称为*尾调用*（理由很明显），并且意味着更高的效率，不仅因为节省了堆栈空间，而且因为跳转比任何其他替代方案都要快得多。如果浏览器实现了这个增强功能，它就是在进行*尾调用优化*，简称 TCO。然而，查看[`kangax.github.io/compat-table/es6/`](http://kangax.github.io/compat-table/es6/)上的兼容性表，现在（2017 年中）唯一提供 TCO 的浏览器是 Safari。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/d80bc118-3f87-4478-b8e2-9291a1c7361a.png)图 9.3。要理解这个笑话，你必须事先理解它！

（注意：这张 XKCD 漫画可以在 https://xkcd.com/1270/上在线获取。）

有一个简单（虽然非标准）的测试，可以让您验证您的浏览器是否提供 TCO。（我在网上的几个地方找到了这段代码片段，但很抱歉我不能证明原作者。不过，我相信这是来自匈牙利的 Csaba Hellinger。）调用`detectTCO()`可以让您知道您的浏览器是否使用 TCO：

```js
"use strict";

function detectTCO() {
 const outerStackLen = new Error().stack.length;
 return (function inner() {
 const innerStackLen = new Error().stack.length;
 return innerStackLen <= outerStackLen;
 })();
}
```

`Error().stack`的结果不是 JS 标准，但现代浏览器支持它，尽管方式有些不同。无论如何，这个想法是，当一个名字很长的函数调用另一个名字较短的函数时，堆栈跟踪：

+   如果浏览器实现了 TCO，堆栈应该会变短，因为较长命名函数的旧条目将被较短命名函数的条目替换

+   如果没有 TCO，堆栈应该变长，因为会创建一个完全新的堆栈条目，而不会消除原始的条目

我在我的 Linux 笔记本上使用 Chrome，并添加了一个`console.log()`语句来显示`Error().stack`。您可以看到`inner()`和`detectTCO()`的两个堆栈条目都是*活动的*，所以没有 TCO：

```js
Error
 at inner (<anonymous>:6:13)
 at detectTCO (<anonymous>:9:6)
 at <anonymous>:1:1
```

当然，还有另一种方法可以了解您的环境是否包括 TCO：尝试运行以下函数，它什么也不做，使用足够大的数字。如果您能够使用 100,000 或 1,000,000 这样的数字运行它，您可能相当确定您的 JS 引擎正在执行 TCO！

```js
function justLoop(n) {
 n && justLoop(n - 1); // *until n is zero*
}
```

让我们用一个非常简短的测验来结束这一节，以确保我们理解了什么是尾调用。我们在第一章中看到的阶乘函数中的递归调用是否是尾调用？

```js
function fact(n) {
 if (n === 0) {
 return 1;
 } else {
 return n * fact(n - 1);
 }
}
```

好好想想，因为答案很重要！您可能会倾向于肯定回答，但正确答案是*不是*。这有很好的理由，这是一个关键点：在递归调用完成之后，`fact(n-1)`的值已经被计算出来，函数*仍然*有工作要做。（因此，递归调用实际上不是函数将要做的最后一件事。）如果您用等价的方式编写函数，您会更清楚地看到它：

```js
function fact2(n) {
 if (n === 0) {
 return 1;
 } else {
 const aux = fact2(n - 1);
 return n * aux;
 }
}
```

所以...这一节的要点应该有两个：TCO 通常不被浏览器支持，即使支持，如果您的调用不是实际的尾调用，您也可能无法利用它。既然我们知道问题所在，让我们看看一些 FP 解决方法！

# 继续传递风格

如果我们的递归调用堆栈太高，我们已经知道我们的逻辑会失败。另一方面，我们知道尾调用应该缓解这个问题...但是，由于浏览器的实现，它并没有，但是有一种解决方法。让我们首先考虑如何将递归调用转换为尾调用，使用一个众所周知的 FP 概念，*continuations*，并且我们将在下一节解决 TCO 限制的问题。（我们在第三章的*回调，承诺和 continuations*部分提到了 continuations，但当时我们没有详细讨论。）

在 FP 术语中，*continuation*是表示进程状态并允许处理继续的东西。这可能太抽象了，所以让我们为我们的需求实际一些。关键思想是，当你调用一个函数时，你也会提供一个继续函数（实际上是一个简单的函数），它将在返回时被调用。

让我们看一个简单的例子。假设你有一个返回当天时间的函数，并且你想在控制台上显示出来。通常的做法可能如下：

```js
function getTime() {
 return new Date().toTimeString();
}

console.log(getTime()); // *"21:00:24 GMT+0530 (IST)"*
```

如果你正在使用 CPS（**Continuation Passing Style**），你会将一个继续函数传递给`getTime()`函数。函数不会返回计算出的值，而是会调用继续函数，将值作为参数传递给它：

```js
function getTime2(cont) {
 return cont(new Date().toTimeString());
}

getTime2(console.log); // *similar result as above*
```

有什么不同？关键在于我们可以应用这种机制将递归调用转换为尾调用，因为所有*之后的*代码都将在递归调用本身中提供。为了澄清这一点，让我们重新看一下阶乘函数，在明确表示我们没有进行尾调用的版本中：

```js
function fact2(n) {
 if (n === 0) {
 return 1;
 } else {
 const aux = fact2(n - 1);
 return n * aux;
 }
}
```

我们将为函数添加一个新的参数，用于继续函数。对于`fact(n-1)`调用的结果我们该怎么办？我们将它乘以`n`，所以让我们提供一个将这样做的继续函数。我将阶乘函数重命名为`factC()`，以明确表示我们正在使用继续函数：

```js
function factC(n, cont) {
 if (n === 0) {
 return cont(1);
 } else {
 return factC(n - 1, x => cont(n * x));
 }
}
```

我们如何得到最终结果？很简单：我们可以用一个继续函数调用`factC()`，这个继续函数将返回它所给出的任何东西：

```js
factC(7, x => x); // *5040, correctly*
```

在 FP 中，一个返回其参数作为结果的函数通常被称为`identity()`，原因是显而易见的。在组合逻辑中（我们不会使用），我们会谈到**I**组合子。

你能理解它是如何工作的吗？那么我们来看一个更复杂的例子，使用斐波那契函数，其中有*两个*递归调用：

```js
const fibC = (n, cont) => {
 if (n <= 1) {
 return cont(n);
 } else {
 return fibC(n - 2, p => fibC(n - 1, q => cont(p + q)));
 }
};
```

这更加棘手：我们用`n-2`调用`fibC()`，并且一个继续函数表示无论那个调用返回了什么，然后调用`fibC()`用`n-1`，当*那个*调用返回时，然后将这两个调用的结果相加并将结果传递给原始的继续函数。

让我们再看一个例子，涉及一个未定义数量的递归调用的循环，到那时，你应该对如何将 CPS 应用到你的代码有一些想法--尽管我愿意承认，它可能变得非常复杂！我们在本章的*遍历树结构*部分中已经看到了这个函数。这个想法是打印出 DOM 结构，就像这样：

```js
<body>
| <script>
| <div>
| | <div>
| | | <a>
| | | <div>
| | | | <ul>
| | | | | <li>
| | | | | | <a>
| | | | | | | <div>
| | | | | | | | <div>
| | | | | | | <div>
| | | | | | | | <br>
| | | | | | | <div>
| | | | | | <ul>
| | | | | | | <li>
| | | | | | | | <a>
| | | | | | | <li>
*...etc!*
```

我们最终设计的函数如下：

```js
const traverseDom2 = (node, depth = 0) => {
 console.log(`${"| ".repeat(depth)}<${node.nodeName.toLowerCase()}>`);
    Array.from(node.children).forEach(child =>
 traverseDom2(child, depth + 1)
 );
};
```

让我们从完全递归开始，摆脱`forEach()`循环。我们之前已经看过这种技术，所以我们可以直接转向结果：

```js
var traverseDom3 = (node, depth = 0) => {
 console.log(`${"| ".repeat(depth)}<${node.nodeName.toLowerCase()}>`);

 const traverseChildren = (children, i = 0) => {
 if (i < children.length) {
 traverseDom3(children[i], depth + 1);
 return traverseChildren(children, i + 1); // loop
 }
 return;
 };

 return traverseChildren(Array.from(node.children));
};
```

现在，我们需要给`traverseDom3()`添加一个继续函数。与之前的情况唯一的区别是这个函数不返回任何东西，所以我们不会给继续函数传递任何参数。另外，重要的是要记住`traverseChildren()`循环结束时的隐式`return`：我们必须调用继续函数：

```js
var traverseDom3C = (node, depth = 0, cont = () => {}) => {
 console.log(`${"| ".repeat(depth)}<${node.nodeName.toLowerCase()}>`);

 const traverseChildren = (children, i = 0) => {
 if (i < children.length) {
 return traverseDom3C(children[i], depth + 1, () =>
 traverseChildren(children, i + 1)
 );
 }
 return cont();
 };

 return traverseChildren(Array.from(node.children));
};
```

我们选择给`cont`一个默认值，所以我们可以像之前一样简单地调用`traverseDom3C(document.body)`。如果我们尝试这种逻辑，它可以工作--但潜在的大量待处理调用的问题还没有解决；现在让我们寻找一个解决方案。

# 跳板和 thunks

对于我们问题的最后一个关键点，我们必须考虑问题的原因。每个待处理的递归调用都会创建一个新的堆栈条目。每当堆栈变得太空，程序就会崩溃，你的算法也就结束了。因此，如果我们能找到一种避免堆栈增长的方法，我们就可以自由了。在这种情况下，解决方案相当响亮，需要 thunks 和一个跳板--让我们看看这些是什么！

首先，*thunk*真的很简单：它只是一个无参数的函数（所以，没有参数），它有助于延迟计算，提供了一种*惰性评估*的形式。如果你有一个 thunk，除非你调用它，否则你不会得到它的值。例如，如果你想要以 ISO 格式获取当前日期和时间，你可以用`new Date().toISOString()`得到它。然而，如果你提供一个计算它的 thunk，你在实际调用它之前不会得到值。

```js
const getIsoDateAndTime = () => new Date().toISOString(); // a thunk
const isoDateAndTime = getIsoDateAndTime(); // getting the thunk's value
```

这有什么用呢？递归的问题在于一个函数调用它自己，然后调用它自己，然后调用它自己，依此类推，直到堆栈溢出。我们不是直接调用它自己，而是让函数返回一个 thunk——当执行时，实际上会递归调用函数。所以，堆栈不会越来越多地增长，它实际上会相当平坦，因为函数永远不会真正调用它自己——当你调用函数时，堆栈会增加一个位置，然后在函数返回它的 thunk 时，堆栈会恢复到原来的大小。

但是...谁来做递归呢？这就是*蹦床*的概念介入的地方。蹦床只是一个调用函数的循环，获取它的返回值，如果它是一个 thunk，那么它就调用它，所以递归将继续进行——但是以一种平坦、线性的方式！当 thunk 评估返回一个实际值时，循环退出，而不是一个新的函数。

```js
const trampoline = (fn) => {
    while (typeof fn === 'function') { fn = fn();
    }
    return fn;
};
```

我们如何将这个应用到一个实际的函数？让我们从一个简单的函数开始，它只是递归地求和从 1 到 n 的所有数字，但以一种保证会导致堆栈崩溃的方式。

```js
const sumAll = n => (n == 0 ? 0 : n + sumAll(n - 1));

sumAll(10); // 55
sumAll(100); // 5050
sumAll(1000); // 500500
sumAll(10000); // ***Uncaught RangeError: Maximum call stack size exceeded***
```

堆栈问题将根据你的机器、内存大小等的不同，迟早会出现，但它肯定会出现。让我们以延续传递风格重写函数，这样它将变成尾递归。

```js
const sumAllC = (n, cont) =>
 n === 0 ? cont(0) : sumAllC(n - 1, v => cont(v + n));

sumAllC(10000, console.log); // *crash as earlier*
```

现在，让我们应用一个简单的规则：每当你要从一个调用中返回时，而不是返回一个 thunk，当执行时，它将执行你实际想要执行的调用。

```js
const sumAllT = (n, cont) =>
 n === 0 ? () => cont(0) : () => sumAllT(n - 1, v => () => cont(v + n));
```

每当应该调用一个函数时，我们现在返回一个 thunk。我们如何运行这个函数？这是缺失的细节。你需要一个初始调用，它将首次调用`sumAllT()`，并且（除非函数是用零参数调用的）会立即返回一个 thunk。蹦床函数将调用 thunk，这将导致一个新的调用，依此类推，直到最终得到一个简单返回值的 thunk，然后计算将结束。

```js
const sumAll2 = n => trampoline(sumAllT(n, x => x));
```

实际上，你可能不想要一个单独的`sumAllT()`函数，所以你可以选择这样的方式：

```js
const sumAll3 = n => {
 const sumAllT = (n, cont) =>
 n === 0
 ? () => cont(0)
 : () => sumAllT(n - 1, v => () => cont(v + n));

 return trampoline(sumAllT(n, x => x));
};
```

现在只剩下一个问题：如果我们递归函数的结果不是一个值，而是一个函数，我们该怎么办？问题在于`trampoline()`代码，只要 thunk 评估的结果是一个函数，它就会一次又一次地返回。最简单的解决方案是返回一个 thunk，但包装在一个对象中：

```js
function Thunk(fn) {
 this.fn = fn;
}

var trampoline2 = thk => {
 while (typeof thk === "object" && thk.constructor.name === "Thunk") {
 thk = thk.fn();
 }
 return thk;
};
```

现在的区别在于，你不再返回一个 thunk，而是写成`return (v) => new Thunk(() => cont(v+n)`，所以我们的新蹦床函数现在可以区分一个实际的 thunk（意味着要被调用和执行）和任何其他类型的结果（意味着要被返回）。

所以，如果你碰巧有一个非常复杂的算法，递归解决方案是最好的，但由于堆栈限制而无法运行，你可以通过一个合理的方式来修复它：

1.  通过使用延续，将所有递归调用改为尾递归。

1.  替换所有的返回语句，使它们返回 thunk。

1.  用蹦床调用替换对原始函数的调用，以开始计算。

当然，这并不是免费的。你会注意到，当使用这种机制时，会有额外的工作涉及返回 thunk，评估它们，等等，所以你可以期待总时间增加。尽管如此，这是一个便宜的代价，如果另一种选择是有一个不能工作的问题解决方案！

# 递归消除

还有另一种可能性你可能想探索，但这超出了 FP 的范围，而是算法设计的范畴。计算机科学事实是，任何使用递归实现的算法都有一个不使用递归而完全依赖于堆栈的等价版本。有方法可以将递归算法系统地转换为迭代算法，因此，如果你耗尽了所有选项（意思是：甚至连 continuations 或 thunks 也无法帮助你），那么你将有最后的机会，通过用迭代替换所有递归。我们不会深入讨论它--正如我所说的，这种消除与 FP 关系不大--但重要的是要知道这个工具存在，你可能能够使用它。

# 问题

9.1\. **逆转**。你能以递归的方式编写一个`reverse()`函数吗？显然，最好的方法是使用标准的 String`.reverse()`方法，如[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/reverse`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/reverse)中详细说明的，但这不适合作为递归问题的问题，是吗...？

9.2\. **爬楼梯**。假设你想要爬一个有*n*步的梯子。每次，你可以选择走 1 步或 2 步。你可以以多少种不同的方式爬上那个梯子？例如，你可以用五种不同的方式爬上一个有四步的梯子。

+   总是一次走一步

+   总是一次走两步

+   先走两步，然后一步，再一步

+   先走一步，然后两步，再走一步

+   先走一步，然后再一步，最后两步

9.3\. **最长公共子序列**。一个经典的动态规划问题如下：给定两个字符串，找到它们共同存在的最长子序列的长度。注意：我们将子序列定义为以相同相对顺序出现但不一定相邻的字符序列。例如，INTERNATIONAL 和 CONTRACTOR 的最长公共子序列是 N...T...R...A...T...O。尝试使用或不使用记忆化，看看有什么区别！

9.4\. **对称皇后**。在我们上面解决的八皇后问题中，只有一个解决方案显示了皇后的摆放对称性。你能修改你的算法找到它吗？

9.5\. **递归排序**。有许多可以用递归描述的排序算法；你能实现它们吗？

+   **选择排序**：找到数组的最大元素，移除它，递归地对剩下的部分进行排序，然后将最大元素推到排序好的剩余部分的末尾

+   **插入排序**：取数组的第一个元素；对剩下的部分进行排序；最后将移除的元素插入到排序好的剩余部分的正确位置

+   **归并排序**：将数组分成两部分；对每一部分进行排序；最后将两个排序好的部分合并成一个排序好的列表

9.6\. **完成回调**。在我们的`findR()`函数中，我们没有为`cb()`回调提供所有可能的参数。你能修复吗？你的解决方案应该沿用我们为`map()`和其他函数所做的方式。

9.7\. **递归逻辑**。我们没有使用递归编写`.every()`和`.some()`：你能做到吗？

# 总结

在本章中，我们已经看到了如何使用递归，这是 FP 中的一种基本工具，作为一种强大的技术来创建算法，对于其他问题，可能需要更复杂的解决方案。我们首先考虑了什么是递归以及如何递归思考来解决问题，然后继续看到了不同领域中几个问题的递归解决方案，最后分析了深度递归可能出现的问题以及如何解决这些问题。

在第十章中，“确保纯净性 - 不可变性”，我们将回顾本书中早前提到的一个概念，即函数纯净性，并了解一些技术，这些技术将帮助我们确保函数不会产生任何副作用，通过确保参数和数据结构的不可变性。
