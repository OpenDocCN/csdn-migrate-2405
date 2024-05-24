# 精通 JavaScript 函数式编程（二）

> 原文：[`zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410`](https://zh.annas-archive.org/md5/C4CB5F08EDA7F6C7DED597C949390410)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：声明式编程 - 更好的风格

到目前为止，我们还没有真正能够欣赏到 FP 的可能性，因为它涉及以更高级别、声明性的方式工作。在本章中，我们将纠正这一点，并通过使用一些高阶函数（HOF：接受函数作为参数的函数）来编写更短、更简洁、更易于理解的代码。

+   `.reduce()`和`.reduceRight()`来对整个数组应用操作，将其减少为单个结果

+   `.map()`，通过对其每个元素应用函数来将数组转换为另一个数组

+   `.forEach()`，通过抽象必要的循环代码来简化编写循环

我们还可以使用以下功能进行搜索和选择：

+   `.filter()`，从数组中选择一些元素

+   `.find()`和`.findIndex()`，用于搜索满足条件的元素

+   还有一对谓词`.every()`和`.some()`，用于检查数组是否通过了某些布尔测试

使用这些函数可以让您更加声明式地工作，您会发现您的注意力往往会转向需要做什么，而不是如何做；肮脏的细节隐藏在我们的函数内部。我们将不再编写一系列可能嵌套的`for`循环，而是更专注于使用函数作为构建块来指定我们想要的结果。

我们还可以以*流畅*的方式工作，其中函数的输出成为下一个函数的输入：这是我们稍后将涉及的一种风格。

# 转换

我们将要考虑的第一组操作是在数组上进行操作，并在函数的基础上处理它以产生一些结果。有几种可能的结果：使用`.reduce()`操作得到单个值；使用`.map()`得到一个新数组；或者使用`.forEach()`得到几乎任何类型的结果。

如果您在网上搜索，您会发现一些声明这些函数不高效的文章，因为手动完成的循环可能更快。尽管这可能是真的，但实际上并不重要。除非您的代码真的受到速度问题的困扰，并且能够测量出慢速是由于使用这些高阶函数导致的，否则试图避免它们，使用更长的代码和更多的错误可能性根本就没有多大意义。

让我们从考虑函数列表开始，按顺序开始，从最一般的函数开始，正如我们将看到的那样，甚至可以用来模拟本章中其余的转换！

# 将数组减少为一个值

回答这个问题：你有多少次不得不循环遍历数组，执行一些操作（比如，求和元素）以产生单个值（也许是所有数组值的总和）作为结果？可能很多次。这种操作通常可以通过应用`.reduce()`和`.reduceRight()`来实现函数化。让我们从前者开始！

是时候学一些术语了！在通常的 FP 术语中，我们谈论*折叠*操作：`.reduce()`是*foldl*（*fold left*）或简单的*fold*，而`.reduceRight()`相应地被称为*foldr*。在范畴论术语中，这两个操作都是*catamorphisms*：将*容器*中所有值减少到单个结果。

`reduce()`函数的内部工作如图 5.1 所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/619697be-da71-4712-b0c6-d85194919859.png)图 5.1：reduce 操作遍历数组，对每个元素和累积值应用函数为什么应该尽量使用`.reduce()`或`.reduceRight()`而不是手动编写循环？

+   所有循环控制方面都会自动处理，因此您甚至没有可能出现例如*偏移一个*的错误

+   结果值的初始化和处理也是隐式完成的

+   而且，除非你非常努力地进行不纯和修改原始数组，否则你的代码将是无副作用的

# 对数组求和

`.reduce()`的最常见应用示例通常在所有教科书和网页中都能看到，就是对数组中所有元素求和。因此，为了保持传统，让我们从这个例子开始！

基本上，要减少一个数组，你必须提供一个二元函数（也就是说，一个带有两个参数的函数；*二进制*可能是另一个名称）和一个初始值。在我们的情况下，函数将对它的两个参数求和。最初，函数将被应用于提供的初始值和数组的第一个元素，所以对我们来说，我们必须提供的第一个结果是零，第一个结果将是第一个元素本身。然后，函数将再次被应用，这次是对上一次操作的结果和数组的第二个元素--因此第二个结果将是数组的前两个元素的和。以这种方式沿着整个数组进行下去，最终的结果将是所有元素的和：

```js
const myArray = [22, 9, 60, 12, 4, 56];
const sum = (x, y) => x + y;
const mySum = myArray.reduce(sum, 0); // 163
```

你实际上不需要`sum`的定义；你可以直接写`myArray.reduce((x,y) => x+y, 0)`。然而，用这种方式代码的含义更清晰：你想通过对所有元素进行求和来将数组减少为一个单一的值。而不是必须编写循环，初始化一个变量来保存计算结果，然后遍历数组进行求和，你只需声明应该执行的操作。这就是我所说的，使用本章中将要看到的这些函数进行编程，可以让你更多地以声明性的方式工作，关注*做什么*而不是*如何做*。

你甚至可以不提供初始值：如果你跳过它，数组的第一个值将被使用，并且内部循环将从数组的第二个元素开始。更多信息请参见[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce)。然而，如果数组为空，并且你跳过提供初始值，你将得到一个运行时错误！

我们可以改变减少函数来看它是如何通过包含一点不纯度而进行计算的！

```js
const sumAndLog = (x, y) => {
 console.log(`${x}+${y}=${x + y}`);
 return x + y;
};
myArray.reduce(sumAndLog, 0);
```

输出将是：

```js
0+22=22
22+9=31
31+60=91
91+12=103
103+4=107
107+56=163
```

你可以看到第一个求和是通过将初始值（零）和数组的第一个元素相加来完成的，然后将该结果用于第二次相加，依此类推。

之前看到的*foldl*名称的一部分（至少是`l`部分）现在应该是清楚的：减少操作从左到右进行，从第一个元素到最后一个元素。然而，你可能会想知道，如果它是由一个从右到左的语言（比如阿拉伯语、希伯来语、波斯语或乌尔都语）的说话者定义的，它会被命名为什么！

# 计算平均值

让我们再多做一点工作；如何计算一组数字的平均值？如果你要向某人解释这个问题，你的答案肯定会有点像“对列表中的所有元素求和，然后除以元素的数量”。从编程的角度来看，这不是一个*过程性*的描述（你不解释如何对元素求和，或者如何遍历数组），而是一个*声明性*的描述，因为你说了要做什么，而不是如何做。

我们可以将这个计算的描述转化为一个几乎是自解释的函数：

```js
const average = arr => arr.reduce(sum, 0) / arr.length;

console.log(average(myArray)); // *27.166667*
```

`average()`的定义遵循了一个口头解释：对数组中的元素求和，从零开始，然后除以数组的长度--简单，不可能出错！

正如我们在前一节中提到的，你也可以写成`arr.reduce(sum)`，而不指定减少的初始值（零）；这样更简洁，更接近所需计算的口头描述。然而，这样做不太安全，因为如果数组为空，它会失败（产生运行时错误）。因此，最好总是提供起始值。

然而，这并不是计算平均值的唯一方法。减少函数还会传递数组的当前位置的索引和数组本身，因此您可以在最后一次做一些不同的事情：

```js
const myArray = [22, 9, 60, 12, 4, 56];

const average2 = (sum, val, ind, arr) => {
 sum += val;
 return ind == arr.length - 1 ? sum / arr.length : sum;
};

console.log(myArray.reduce(average2, 0)); // 27.166667
```

获取数组和索引意味着您也可以将函数转换为不纯的函数；避免这样做！每个看到`.reduce()`调用的人都会自动假设它是一个纯函数，并且在使用它时肯定会引入错误。

然而，从可读性的角度来看，我相信我们会同意，我们看到的第一个版本比这个第二个版本更具声明性，更接近数学定义。

也可以修改`Array.prototype`以添加新函数。通常修改原型是不受欢迎的，因为至少可能会与不同的库发生冲突。但是，如果您接受这个想法，那么您可以编写以下代码。请注意需要外部`function()`（而不是箭头函数）的需要，因为它隐式处理`this`，否则将无法绑定：

```js
Array.prototype.average = function() {
 return this.reduce((x, y) => x + y, 0) / this.length;
};

let myAvg = [22, 9, 60, 12, 4, 56].average(); // *27.166667*
```

# 同时计算多个值

如果您需要计算两个或更多结果，您会怎么做？这似乎是一个适合使用普通循环的情况，但是您可以使用一个技巧。让我们再次回顾一下平均值的计算。我们可能想要以*老式的方式*循环，同时对所有数字进行求和和计数。嗯，`.reduce()`只允许您生成一个单一的结果，但是没有反对返回一个对象，其中包含尽可能多的字段：

```js
const average3 = arr => {
 const sc = arr.reduce(
 (ac, val) => ({ sum: val + ac.sum, count: ac.count + 1 }),
    { sum: 0, count: 0 }
 );
 return sc.sum / sc.count;
};

console.log(average3(myArray)); // *27.166667*
```

仔细检查代码。我们需要两个变量，用于所有数字的总和和计数。我们提供一个对象作为累加器的初始值，其中两个属性设置为零，我们的减少函数更新这两个属性。

顺便说一句，使用对象并不是唯一的选择。您还可以生成任何其他数据结构；让我们看一个数组的例子：

```js
const average4 = arr => {
 const sc = arr.reduce((ac, val) => [ac[0] + val, ac[1] + 1], [0, 0]);
 return sc[0] / sc[1];
};
console.log(average4(myArray)); // *27.166667*
```

坦率地说，我认为这比使用对象的解决方案更加晦涩。只需将其视为一种（不太可取的）同时计算多个值的替代方法！

# 左右折叠

补充的`.reduceRight()`方法与 reduce 方法一样，只是从末尾开始循环，直到数组的开头。对于许多操作（例如我们之前看到的平均值的计算），这没有区别，但也有一些情况会有区别。

我们将在第八章中看到一个明显的例子，*连接函数 - 管道和组合*，当我们比较管道和组合时：让我们在这里使用一个更简单的例子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/224b131b-0306-4be3-a482-ec57be888b0e.png)图 5.2：`.reduceRight()`操作与`.reduce()`相同，只是顺序相反。在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/ReduceRight`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/ReduceRight)上阅读更多关于`.reduceRight()`的信息。

假设我们想要实现一个反转字符串的函数。一种解决方案是使用`.split()`将字符串转换为数组，然后反转该数组，最后使用`.join()`将其重新组合：

```js
const reverseString = str => {
 let arr = str.split("");
 arr.reverse();
 return arr.join("");
};

console.log(reverseString("MONTEVIDEO")); // *OEDIVETNOM*
```

这个解决方案（是的，它可以被简化，但这不是重点）有效，但让我们以另一种方式来做，只是为了尝试`.reduceRight()`：

```js
const reverseString2 = str =>
 str.split("").reduceRight((x, y) => x + y, "");

console.log(reverseString2("OEDIVETNOM")); // *MONTEVIDEO*
```

鉴于加法运算符也适用于字符串，我们也可以编写`reduceRight(sum,"")`。如果我们使用的不是函数，而是`(x,y) => y+x`，结果将是我们的原始字符串；您能看出为什么吗？

从前面的例子中，你也可以得到一个想法：如果你首先对一个数组应用`reverse()`，然后使用`reduce()`，效果将与你只是对原始数组应用`.reduceRight()`相同。只需要考虑一点：`reverse()`改变了给定的数组，所以你会导致一个意外的副作用，即颠倒了原始数组！唯一的出路是首先生成数组的副本，然后再做其他操作... 太麻烦了；还是继续使用`.reduceRight()`吧！

然而，我们可以得出另一个结论，展示了我们之前预言的结果：即使更加繁琐，也可以使用`.reduce()`来模拟与`.reduceRight()`相同的结果--在后面的章节中，我们还将使用它来模拟本章中的其他函数。

# 应用操作 - map

处理元素列表，并对每个元素应用某种操作，在计算机编程中是一个非常常见的模式。编写循环，系统地遍历数组或集合的所有元素，从第一个开始循环，直到最后一个结束，并对每个元素进行某种处理，是一个基本的编码练习，通常在所有编程课程的第一天就学到。我们已经在上一节中看到了这样一种操作，使用了`.reduce()`和`.reduceRight()`；现在让我们转向一个新的操作，叫做`.map()`。

在数学中，*map*是将元素从*域*转换为*余域*的变换。例如，你可以将数字转换为字符串，或者字符串转换为数字，但也可以将数字转换为数字，或者字符串转换为字符串：重要的是你有一种方法将第一种*类型*或*域*的元素（如果有帮助的话，可以考虑*类型*）转换为第二种*类型*或*余域*的元素。在我们的情况下，这意味着取出数组的元素，并对每个元素应用一个函数，以产生一个新的数组。更像计算机的术语，map 函数将输入数组转换为输出数组。

还有一些术语。我们会说一个数组是一个函子，因为它提供了一个具有一些预先指定属性的映射操作，我们稍后会看到。在范畴论中，我们将在第十二章中稍微谈一下，*构建更好的容器-函数数据类型*，映射操作本身将被称为态射。

`.map()`操作的内部工作可以在图 5.3 中看到：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/0fafb8ed-5d29-4410-b453-f30e702db535.png)图 5.3：map()操作通过应用映射函数转换输入数组的每个元素 jQuery 库提供了一个函数`$.map(array, callback)`，它类似于`.map()`方法。不过要小心，因为有重要的区别。jQuery 函数处理数组的未定义值，而`.map()`跳过它们。此外，如果应用的函数产生一个数组作为其结果，jQuery 会*展平*它，并单独添加其每个个体元素，而`.map()`只是将这些数组包含在结果中。

使用`.map()`的优势，而不是使用直接的循环是什么？

+   首先，你不必编写任何循环，这样就少了一个可能的错误来源。

+   其次，你甚至不需要访问原始数组或索引位置，尽管它们可以供你使用，如果你真的需要的话

+   最后，产生了一个新的数组，所以你的代码是纯的（当然，如果你真的想产生副作用，当然可以！）

在 JS 中，`.map()`基本上只适用于数组。（在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map)上阅读更多。）然而，在第十二章的*扩展当前数据类型*中，*构建更好的容器-功能数据类型*，我们将考虑如何使它适用于其他基本类型，如数字、布尔值、字符串，甚至函数。此外，诸如 LoDash 或 Underscore 或 Ramda 之类的库提供类似的功能。

在使用此功能时只有两个注意事项：

+   总是从您的映射函数返回一些东西。如果您忘记了这一点，因为 JS 总是为所有函数提供默认的`return undefined`，那么您将只会生成一个填满`undefined`的数组。

+   如果输入数组元素是对象或数组，并且您将它们包含在输出数组中，那么 JS 仍然允许访问原始元素。

# 从对象中提取数据

让我们从一个简单的例子开始。假设我们有一些地理数据，如下面的片段所示，与国家和它们首都的坐标（纬度、经度）有关。假设我们碰巧想要计算这些城市的平均位置。（不，我不知道为什么我们要这样做……）我们该如何去做？

```js
const markers = [
 {name: "UY", lat: -34.9, lon: -56.2},
 {name: "AR", lat: -34.6, lon: -58.4},
 {name: "BR", lat: -15.8, lon: -47.9},
 ...
 {name: "BO", lat: -16.5, lon: -68.1}
];
```

如果您想知道为什么所有数据都是负数，那只是因为所显示的国家都位于赤道以南，而且位于格林威治以西。然而，有一些南美国家的纬度是正数，比如哥伦比亚或委内瑞拉，所以并非所有数据都是负数。当我们学习`some()`和`every()`方法时，我们将在下面回到这个问题。

我们想要使用我们在本章前面开发的`average()`函数，但是有一个问题：该函数只能应用于*数字*数组，而我们这里有的是*对象*数组。然而，我们可以做一个小技巧。专注于计算平均纬度；我们可以以类似的方式稍后处理经度。我们可以将数组的每个元素映射到其纬度，然后我们就可以得到`average()`的适当输入。解决方案可能是以下内容：

```js
let averageLat = average(markers.map(x => x.lat));
let averageLon = average(markers.map(x => x.lon));
```

如果您扩展了`Array.prototype`，那么您可以以不同的风格编写一个等效版本：

```js
let averageLat2 = markers.map(x => x.lat).average();
let averageLon2 = markers.map(x => x.lon).average();
```

我们将在第八章中看到更多关于这些风格的内容，*连接函数-管道和组合*。

# 暗示式解析数字

使用 map 通常比手动循环更安全和更简单，但有些边缘情况可能会让您感到困惑。假设您收到了一个表示数值的字符串数组，并且您想将它们解析为实际的数字。您能解释以下结果吗？

```js
["123.45", "67.8", "90"].map(parseFloat);
// [123.45, 67.8, 90]

["123.45", "-67.8", "90"].map(parseInt);
// [123, NaN, NaN]
```

当您使用`parseFloat()`获得浮点结果时，一切都很好。然而，如果您想要将结果截断为整数值，那么输出就会出现问题……发生了什么？

答案在于暗示式编程的问题。（我们已经在第三章的*不必要的错误*部分看到了一些暗示式编程的用法，我们将在第八章中看到更多，*连接函数-管道和组合*。）当您不明确显示函数的参数时，很容易出现一些疏忽。请看下面的代码，这将引导我们找到解决方案：

```js
["123.45", "-67.8", "90"].map(x => parseFloat(x));
// [123.45, -67.8, 90]

["123.45", "-67.8", "90"].map(x => parseInt(x));
// [123, -67, 90]
```

`parseInt()`出现意外行为的原因是，这个函数也可以接收第二个参数，即在将字符串转换为数字时要使用的基数。例如，像`parseInt("100010100001", 2)`这样的调用将把二进制数 100010100001 转换为十进制数。

在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/parseInt`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/parseInt)上查看更多关于`parseInt()`的信息，其中详细解释了基数参数。您应该始终提供它，因为某些浏览器可能会将具有前导零的字符串解释为八进制，这将再次产生不需要的结果。

那么，当我们将`parseInt()`提供给`map()`时会发生什么？记住，`.map()`调用映射函数时会传递三个参数：数组元素值，其索引和数组本身。当`parseInt`接收这些值时，它会忽略数组，但假设提供的索引实际上是一个基数...并且会产生`NaN`值，因为原始字符串在给定基数下不是有效数字。

# 使用范围

现在让我们转向一个辅助函数，这将对许多用途很有用。我们想要一个`range(start,stop)`函数，它生成一个数字数组，值范围从`start`（包括）到`stop`（不包括）：

```js
const range = (start, stop) =>
 new Array(stop - start).fill(0).map((v, i) => start + i);

let from2To6 = range(2, 7); // [2, 3, 4, 5, 6];
```

为什么要使用`.fill(0)`？所有未定义的数组元素都会被`map()`跳过，所以我们需要用一些东西来填充它们，否则我们的代码将没有效果。

像 Underscore 或 LoDash 这样的库提供了我们的范围函数的更强大版本，让您可以按升序或降序进行操作，并且还可以指定要使用的步长，就像`_.range(0, -8, -2)`会产生[`0`, `-2`, `-4`, `-6`]，但对于我们的需求，我们编写的版本就足够了。请参阅本章末尾的*问题*部分。

我们如何使用它？在接下来的部分中，我们将看到一些使用`forEach()`进行控制循环的用法，但我们可以通过应用`range()`然后`reduce()`来重新实现我们的阶乘函数。这个想法很简单，就是生成从 1 到 n 的所有数字，然后将它们相乘：

```js
const factorialByRange = n => range(1, n + 1).reduce((x, y) => x * y, 1);

factorialByRange(5); // 120
factorialByRange(3); // 6
```

检查边界情况很重要，但该函数也适用于零；你能看出原因吗？原因是生成的范围是空的（调用是`range(1,1)`返回一个空数组），然后`reduce()`不进行任何计算，只是返回初始值（1），这是正确的。

在第八章中，*连接函数-管道和组合*，我们将有机会使用`range()`来生成源代码；请查看*使用* *eval()* *进行柯里化*和*使用* *eval()* *进行部分应用*部分。

您可以使用这些数字范围来生成其他类型的范围。例如，如果您需要一个包含字母表的数组，您肯定可以（而且很繁琐地）写`["A", "B", "C"...`一直到`..."X", "Y", "Z"]`。一个更简单的解决方案是生成一个包含字母表的 ASCII 代码范围，并将其映射为字母：

```js
const ALPHABET = range("A".charCodeAt(), "Z".charCodeAt() + 1).map(x =>
 String.fromCharCode(x)
);
// ["A", "B", "C", ... "X", "Y", "Z"]
```

请注意使用`charCodeAt()`获取字母的 ASCII 代码，以及`String.fromCharCode(x)`将 ASCII 代码转换回字符。

# 使用 reduce()模拟 map()

在本章的早些时候，我们看到`reduce()`可以用来实现`reduceRight()`。现在，让我们看看`reduce()`也可以用来为`map()`提供一个 polyfill--尽管您可能不需要它，因为浏览器通常提供这两种方法，但只是为了更多地了解您可以用这些工具实现什么样的想法。

我们自己的`myMap()`是一行代码，但可能很难理解。思路是我们将函数应用于数组的每个元素，并将结果`concat()`到（最初为空的）结果数组中。当循环完成处理输入数组时，结果数组将具有所需的输出值：

```js
const myMap = (arr, fn) => arr.reduce((x, y) => x.concat(fn(y)), []);
```

让我们用一个简单的数组和函数来测试一下：

```js
const myArray = [22, 9, 60, 12, 4, 56];
const dup = x => 2 * x;

console.log(myArray.map(dup));    // *[44, 18, 120, 24, 8, 112]*
console.log(myMap(myArray, dup)); // *[44, 18, 120, 24, 8, 112]*
console.log(myArray);             // *[22, 9, 60, 12, 4, 56]*
```

第一个日志显示了由`map()`产生的预期结果。第二个输出给出了相同的结果，所以似乎`.myMap()`有效！最后一个输出只是为了检查原始输入数组没有以任何方式被修改；映射操作应该总是产生一个新数组。

# 更一般的循环

我们上面看到的例子，只是简单地循环遍历数组。然而，有时您需要做一些循环，但所需的过程实际上并不适合`.map()`或`.reduce()`...那么该怎么办呢？有一个`.forEach()`方法可以帮助。

在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/forEach`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/forEach)上阅读更多关于`.forEach()`方法的规范。

您必须提供一个回调函数，该函数将接收值、索引和您正在操作的数组。（最后两个参数是可选的。）JS 将负责循环控制，您可以在每一步做任何您想做的事情。例如，我们可以通过使用一些`Object`方法逐个复制源对象属性，并生成一个新对象来编写对象复制方法：

```js
const objCopy = obj => {
 let copy = Object.create(Object.getPrototypeOf(obj));
 Object.getOwnPropertyNames(obj).forEach(prop =>
 Object.defineProperty(
 copy,
 prop,
 Object.getOwnPropertyDescriptor(obj, prop)
 )
 );
 return copy;
};

const myObj = {fk: 22, st: 12, desc: "couple"};
const myCopy = objCopy(myObj);
console.log(myObj, myCopy); // {fk: 22, st: 12, desc: "couple"}, twice
```

是的，当然，您也可以编写`myCopy={...myObj}`，但这样做有什么乐趣呢？好吧，那样更好，但我需要一个好的例子来使用`.forEach()`...对此很抱歉！此外，在那段代码中还有一些隐藏的不便之处，我们将在第十章中解释，*确保纯度-不可变性*，当我们试图获得真正冻结的、不可修改的对象时。只是一个提示：新对象可能与旧对象共享值，因为我们进行的是*浅*复制，而不是*深*复制。我们将在本书的后面更多地了解这一点。

如果您使用我们之前定义的`range()`函数，您也可以执行常见的循环，例如`for(i=0; i<10; i++)`。我们可以使用这种方式编写阶乘（!）的另一个版本：

```js
const factorial4 = n => {
 let result = 1;
    range(1, n + 1).forEach(v => (result *= v));
 return result;
};

console.log(factorial4(5)); // 120
```

这个阶乘的定义确实与通常的描述相匹配：它生成从 1 到 n 的所有数字，并将它们相乘；简单！

为了更通用，您可能希望扩展`range()`，使其能够生成升序和降序的值范围，可能还可以通过不同于 1 的数字进行步进。这实际上可以让您用`.forEach()`循环替换代码中的所有循环。

# 逻辑高阶函数

到目前为止，我们一直在使用高阶函数来生成新的结果，但也有一些其他函数，通过将谓词应用于数组的所有元素来生成逻辑结果。

一些术语：*谓词*一词可以用多种意义（如*谓词逻辑*）,但对于我们来说，在计算机科学中，我们采用*返回 true 或 false 的函数*的含义。好吧，这不是一个非常正式的定义，但对我们的需求来说足够了。例如，我们将根据谓词筛选数组，这意味着我们可以决定根据谓词的结果包含或排除哪些元素。

使用这些函数意味着您的代码将变得更短：您可以用一行代码获得与整套值对应的结果。

# 筛选数组

一个常见的需求是根据某些条件筛选数组的元素。`.filter()`方法允许您检查数组的每个元素，方式与`.map()`相同。不同之处在于，函数的结果决定了输入值是否会保留在输出中（如果函数返回`true`）或者是否会被跳过（如果函数返回`false`）。与`.map()`类似，`.filter()`不会改变原始数组，而是返回一个包含选定项的新数组。

查看图 5.4，显示输入和输出的图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/834e362e-be10-4a3b-875c-ffdcc0685d27.png)图 5.4：`filter()`方法选择满足给定谓词的数组元素在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/filter`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Array/filter)上阅读更多关于`.filter()`函数的内容。

筛选数组时要记住的事情有：

+   **始终从谓词中返回一些东西**。如果你忘记包含一个`return`，函数将隐式返回`undefined`，而由于那是一个*假值*，输出将是一个空数组。

+   **复制的是浅层的**。如果输入数组元素是对象或数组，原始元素仍然是可访问的。

# 一个 reduce()示例

让我们看一个实际的例子。假设一个服务返回了一个 JSON 对象，其中包含一个包含账户`id`和账户`balance`的对象数组。我们如何获取*处于赤字状态*，即余额为负的 ID 列表？输入数据可能如下：

```js
{
 accountsData: [
 {
 id: "F220960K",
 balance: 1024
 },
 {
 id: "S120456T",
 balance: 2260
 },
 {
 id: "J140793A",
 balance: -38
 },
 {
 id: "M120396V",
 balance: -114
 },
 {
 id: "A120289L",
 balance: 55000
 }
 ]
}
```

假设我们将这些数据存储在一个`serviceResult`变量中，我们可以通过以下方式获取拖欠账户：

```js
const delinquent = serviceResult.accountsData.filter(v => v.balance < 0);

console.log(delinquent); // two objects, with id's J140793A and M120396V
```

顺便说一下，考虑到过滤操作产生了另一个数组，如果你只想要账户 ID，你可以通过映射输出来实现。

```js
const delinquentIds = delinquent.map(v => v.id);
```

如果你不在乎中间结果，一行代码也可以。

```js
const delinquentIds2 = serviceResult.accountsData
 .filter(v => v.balance < 0)
 .map(v => v.id);
```

# 使用 reduce()模拟 filter()

就像我们之前用`.map()`做的一样，我们也可以通过使用`.reduce()`创建我们自己的`.filter()`版本。这个想法是类似的：循环遍历输入数组的所有元素，对其应用谓词，如果结果为`true`，则将原始元素添加到输出数组中。当循环结束时，输出数组将只包含谓词为`true`的那些元素。

```js
const myFilter = (arr, fn) =>
 arr.reduce((x, y) => (fn(y) ? x.concat(y) : x), []);
```

我们可以很快地看到我们的函数按预期工作。

```js
console.log(myFilter(serviceResult.accountsData, v => v.balance < 0));
// two objects, with id's J140793A and M120396V
```

输出与本节前面的账户对相同。 

# 搜索数组

有时，你不想过滤数组的所有元素，而是想找到满足给定条件的元素。根据你的具体需求，可以使用一些函数来实现这一点：

+   `.find()`搜索数组并返回满足给定条件的第一个元素的值，如果找不到这样的元素，则返回`undefined`

+   `.findIndex()`执行类似的任务，但是它返回的不是元素，而是数组中满足条件的第一个元素的索引，如果找不到则返回-1

这个类比很明显，`.includes()`和`.indexOf()`搜索特定的值，而不是满足更一般条件的元素。我们可以很容易地编写等效的一行代码：

```js
arr.includes(value); // arr.find(**v => v === value**)
arr.indexOf(value);  // arr.findIndex(**v => v === value**)
```

回到我们之前使用的地理数据，我们可以很容易地找到一个给定的国家。

```js
markers = [
 {name: "UY", lat: -34.9, lon: -56.2},
 {name: "AR", lat: -34.6, lon: -58.4},
 {name: "BR", lat: -15.8, lon: -47.9},
 //…
 {name: "BO", lat: -16.5, lon: -68.1}
];

let brazilData = markers.find(v => v.name === "BR");
// {name:"BR", lat:-15.8, lon:-47.9}
```

我们无法使用更简单的`.includes()`方法，因为我们必须深入对象以获取我们想要的字段。如果我们想要数组中国家的位置，我们将使用`.findIndex()`：

```js
let brazilIndex = markers.findIndex(v => v.name === "BR"); // 2
let mexicoIndex = markers.findIndex(v => v.name === "MX"); // -1
```

# 特殊的搜索情况

现在，为了多样化，来做一个小测验。假设你有一个数字数组，并想要进行一次健全性检查，研究其中是否有任何`NaN`。你会怎么做？提示：不要尝试检查数组元素的类型：尽管`NaN`代表*Not a Number*，`typeof NaN === "number"`...如果你试图以*显而易见的方式*进行搜索，你会得到一个令人惊讶的结果...

```js
[1, 2, NaN, 4].findIndex(x => x === NaN); // -1
```

这里发生了什么？这是有趣的 JS 小知识：`NaN`是唯一不等于自身的值。如果你需要查找`NaN`，你将不得不使用新的`isNaN()`函数，如下所示：

```js
[1, 2, NaN, 4].findIndex(x => isNaN(x)); // 2
```

# 使用 reduce()模拟 find()和 findIndex()

和其他方法一样，让我们通过使用万能的`.reduce()`来学习如何实现我们展示的方法。这是一个很好的练习，可以让你习惯使用高阶函数，即使你永远不会真正使用这些 polyfills！

`.find()`函数需要一些工作。我们从一个未定义的值开始搜索，如果我们找到一个数组元素使得谓词为`true`，我们就将累积值更改为数组的值：

```js
arr.find(fn);
// arr.reduce((x, y) => (x === undefined && fn(y) ? y : x), undefined);
```

对于`findIndex()`，我们必须记住回调函数接收累积值、数组当前元素和当前元素的索引，但除此之外，等价表达式与`find()`的表达式非常相似；比较它们是值得的。

```js
arr.findIndex(fn);
// arr.reduce((x, y, i) => (x == -1 && fn(y) ? i : x), -1);
```

初始累积值在这里是`-1`，如果没有元素满足谓词，则将返回该值。每当累积值仍为`-1`，但我们找到满足谓词的元素时，我们将累积值更改为数组索引。

# 更高级的谓词-一些，每个

我们要考虑的最后一个函数大大简化了通过数组来测试条件。这些函数是：

+   `.every()`，如果数组中的每个元素都满足给定的谓词，则为`true`

+   `.some()`，如果数组中至少*一个*元素满足谓词，则为`true`

例如，我们可以轻松检查我们关于所有国家都有负坐标的假设：

```js
markers.every(v => v.lat < 0 && x.lon < 0); // *false*

markers.some(v => v.lat < 0 && x.lon < 0);  // *true*
```

如果我们想要找到这两个函数的`reduce()`等价物，那么两个替代方案显示出很好的对称性：

```js
arr.every(fn);
// arr.reduce((x, y) => x && fn(y), true);

arr.some(fn);
// arr.reduce((x, y) => x || fn(y), false);
```

第一个折叠操作评估`fn(y)`，并将结果与先前的测试进行逻辑与运算；最终结果为`true`的唯一方式是如果每个测试都为`true`。第二个折叠操作类似，但将结果与先前的结果进行逻辑或运算，除非每个测试都为`false`，否则将产生`true`。

从布尔代数的角度来看，我们会说`every()`和`some()`的替代形式表现出对偶性。这种对偶性与表达式`x === x && true`和`x === x || false`中出现的对偶性相同；如果`x`是一个布尔值，并且我们交换`&&`和`||`，以及`true`和`false`，我们将一个表达式转换为另一个表达式，两者都是有效的。

# 检查负数-无

如果您愿意，您还可以定义`.none()`，作为`.every()`的补集--这个新函数只有在数组的元素都不满足给定的谓词时才为真。编写这个函数的最简单方法是注意到如果没有元素满足条件，那么所有元素都满足条件的否定。

```js
const none = (arr, fn) => arr.every(v => !fn(v));
```

如果您愿意，您可以将其转换为一个方法，通过修改数组原型，就像我们之前看到的那样--这仍然是一个不好的做法，但这是我们在开始寻找更好的方法来组合和链接函数之前所拥有的。

```js
Array.prototype.none = function(fn) {
 return this.every(v => !fn(v));
};
```

我们必须使用`function()`，而不是箭头函数，原因与我们之前看到的相同；在这种情况下，我们确实需要正确分配`this`。 

在第六章中，*生成函数-高阶函数*，我们将看到通过编写适当的自定义高阶函数来否定函数的其他方法。

# 问题

5.1\. **过滤...但是什么**：假设您有一个名为`someArray`的数组，并且您对其应用以下`.filter()`，乍一看甚至看起来不像有效的 JS 代码。新数组中会有什么，为什么？

```js
 let newArray = someArray.filter(Boolean);
```

5.2\. **生成 HTML 代码，带限制**：使用`filter()`...`map()`...`reduce()`序列是相当常见的（即使有时您可能不会使用所有三个），我们将在第十一章的*功能设计模式*部分回到这一点，*实现设计模式-功能方式*。这里的问题是使用这些函数（而不是其他任何函数！）来生成一个无序元素列表（`<ul>`...`</ul>`），以便稍后在屏幕上使用。您的输入是一个类似以下对象的数组（字符列表是否让我显得老？），您必须列出与国际象棋或跳棋玩家对应的每个名称：

```js
 var characters = [
 {name: "Fred", plays: "bowling"},
 {name: "Barney", plays: "chess"},
 {name: "Wilma", plays: "bridge"},
 {name: "Betty", plays: "checkers"},
 .
 .
 .
 {name: "Pebbles", plays: "chess"}
 ];
```

输出将类似于以下内容--尽管如果您不生成空格和缩进也没关系。如果您能使用`.join()`，那将更容易，但在这种情况下，不允许使用；只能使用这三个提到的函数。

```js
 <div>
 <ul>
 <li>Barney</li>
 <li>Betty</li>
 .
 .
 .
 <li>Pebbles</li>
 </ul>
 </div>;
```

5.3 **更正式的测试：** 在前面的一些示例中，比如在*用`reduce()`模拟`map()`*部分，我们没有编写实际的单元测试，而是满足于做一些控制台日志记录。你能否写出适当的单元测试呢？

5.4\. **广泛涉猎：** 我们在这里看到的`range()`函数可以有很多用途，但在通用性上有点欠缺。你能否扩展它，使其允许降序范围，比如`range(10,1)`？（范围中的最后一个数字应该是什么？）另外，你还能否允许包含步长，以指定范围中连续数字之间的差异？有了这个，`range(1,10,2)`将产生`[1, 3, 5, 7, 9]`。

5.5 **做字母表：** 如果在*使用范围*部分，而不是编写`map(x => String.fromCharCode(x))`，你只是简单地写了`map(String.fromCharCode)`会发生什么？你能解释不同的行为吗？提示：我们在本章的其他地方已经看到了类似的问题。

5.6\. **生成 CSV：** 在某个应用程序中，您希望用户能够通过使用数据 URI（逗号分隔值）文件下载一组数据。 （在[`developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs/`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs/)中了解更多。）当然，第一个问题是生成 CSV 本身！假设您有一个数字值数组的数组，如下面的代码段所示，并编写一个函数，将该结构转换为 CSV 字符串，然后您将能够将其插入 URI 中。像往常一样，`\n`代表换行符：

```js
 let myData = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
 let myCSV = dataToCsv(myData); // "1,2,3,4\n5,6,7,8\n9,10,11,12\n"
```

# 摘要

在本章中，我们已经开始使用高阶函数，以展示更具声明性的工作方式，以更简洁、更具表现力的代码。我们已经讨论了几种操作：我们已经看到了`.reduce()`和`.reduceRight()`，从数组中获取单个结果；`.map()`，对数组的每个元素应用函数；`.forEach()`，简化循环；`.filter()`，从数组中选择元素；`.find()`和`.findIndex()`，在数组中搜索；以及`.every()`和`.some()`，验证一般逻辑条件。

在第六章中，*生成函数 - 高阶函数*，我们将继续使用高阶函数，但随后我们将转而编写自己的函数，以获得更多表达力，为我们的编码。


# 第六章：生成函数 - 高阶函数

在第五章中，*声明式编程 - 更好的风格*，我们使用了一些预定义的高阶函数，并且能够看到它们的使用方式让我们编写了声明式的代码，不仅在可理解性上有所提升，而且在紧凑性上也有所提升。在这一新章节中，我们将进一步探讨高阶函数的方向，并且我们将开发我们自己的高阶函数。我们可以将我们要进入的函数类型大致分类为三组：

+   **包装函数**，保持其原始功能，添加某种新功能。在这一组中，我们可以考虑*日志记录*（为任何函数添加日志记录功能）、*计时*（为给定函数生成时间和性能数据）和*记忆化*（缓存结果以避免未来的重新计算）。

+   **修改函数**，在某些关键点上与它们的原始版本不同。在这里，我们可以包括`once()`函数（我们在第二章中编写过，*函数式思维 - 第一个示例*），它改变了原始函数只运行一次，像`not()`或`invert()`这样改变函数返回值的函数，以及产生具有固定参数数量的新函数的 arity 相关转换。

+   **其他产物**，提供新的操作，将函数转换为 promises，提供增强的搜索功能，或允许将方法与对象解耦，以便我们可以在其他上下文中使用它们，就像它们是普通函数一样。

# 包装函数

在这一部分，让我们考虑一些提供对其他函数进行*包装*以某种方式增强其功能，但不改变其原始目的的高阶函数。在*设计模式*方面（我们将在第十一章中重新讨论），我们也可以谈论*装饰器*。这种模式基于向对象（在我们的情况下是函数）添加一些行为而不影响其他对象的概念。装饰器这个术语也很受欢迎，因为它在 Angular 等框架中的使用，或者（在实验模式下）用于 JS 的一般编程。

装饰器正在考虑在 JS 中进行一般采用，但目前（2017 年 8 月）处于 2 阶段，*草案*级别，可能要等一段时间才能进入 3 阶段（*候选*）和最终进入 4 阶段（*完成*，意味着正式采用）。你可以在[`tc39.github.io/proposal-decorators/`](https://tc39.github.io/proposal-decorators/)了解更多关于 JS 装饰器的信息，以及 JS 采用过程本身，称为 TC39，在[`tc39.github.io/process-document/`](https://tc39.github.io/process-document/)。在第十一章，*实现设计模式 - 函数式方法*的*问题*部分中查看更多信息。

至于*包装器*这个术语，它比你想象的更重要和普遍；事实上，JavaScript 广泛使用它。在哪里？你已经知道对象属性和方法是通过点表示法访问的。然而，你也知道你可以编写诸如`myString.length`或`22.9.toPrecision(5)`的代码--这些属性和方法是从哪里来的，因为字符串和数字都不是对象？JavaScript 实际上在你的原始值周围创建了一个*包装对象*。这个对象继承了适用于包装值的所有方法。一旦需要进行评估，JavaScript 就会丢弃刚刚创建的包装器。我们无法对这些瞬时包装器做任何事情，但有一个概念我们将会回来：包装器允许在不适当类型的东西上调用方法--这是一个有趣的想法；参见第十二章，*构建更好的容器 - 函数式数据类型*，了解更多应用。

# 日志

让我们从一个常见的问题开始。在调试代码时，通常需要添加某种日志信息，以查看函数是否被调用，使用了什么参数，返回了什么，等等。（是的，当然，您可以简单地使用调试器并设置断点，但请在这个例子中忍耐一下！）正常工作意味着您将不得不修改函数本身的代码，无论是在进入还是退出时。您将不得不编写如下的代码：

```js
function someFunction(param1, param2, param3) {
 // *do something*
 // *do something else*
 // *and a bit more,*
 // *and finally*
 return *some expression*;
}
```

到这样的程度：

```js
function someFunction(param1, param2, param3) {
 console.log("entering someFunction: ", param1, param2, param3);
 // *do something*
 // *do something else*
 // *and a bit more,*
 // *and finally*
 let auxValue = *some expression*;
 console.log("exiting someFunction: ", auxValue);
 return auxValue;
}
```

如果函数可以在多个地方返回，您将不得不修改所有的`return`语句，以记录要返回的值。当然，如果您只是在动态计算返回表达式，您将需要一个辅助变量来捕获该值。

# 以一种功能性的方式记录

这样做并不困难，但修改代码总是危险的，容易发生“意外”。因此，让我们戴上我们的 FP 帽子，想出一种新的方法来做这件事。我们有一个执行某种工作的函数，我们想知道它接收到的参数和它返回的值。

我们可以编写一个高阶函数，它将有一个参数，即原始函数，并返回一个新的函数，该函数将执行以下操作：

1.  记录接收到的参数。

1.  调用原始函数，捕获其返回的值。

1.  记录该值；最后。

1.  返回给调用者。

一个可能的解决方案如下：

```js
const addLogging = fn => (...args) => {
    console.log(`entering ${fn.name}: ${args})`);
 const valueToReturn = fn(...args);
    console.log(`exiting ${fn.name}: ${valueToReturn}`);
 return valueToReturn;
};
```

由`addLogging()`返回的函数的行为如下：

+   第一个`console.log()`行显示了原始函数的名称及其参数列表

+   然后调用原始函数`fn()`，并存储返回的值

+   第二个`console.log()`行显示函数名称（再次）及其返回值

+   最后，`fn()`计算的值被返回

如果您为 Node.js 应用程序执行此操作，您可能会选择更好的日志记录方式，比如使用 Winston、Morgan 或 Bunyan 等库--但我们的重点是展示如何包装原始函数，使用这些库所需的更改将很小。

例如，我们可以将其与即将到来的函数一起使用--我同意，以一种过于复杂的方式编写，只是为了有一个合适的例子！

```js
function subtract(a, b) {
 b = changeSign(b);
 return a + b;
}

function changeSign(a) {
 return -a;
}

subtract = addLogging(subtract);
changeSign = addLogging(changeSign);
let x = subtract(7, 5);
```

执行最后一行的结果将产生以下日志行：

```js
entering subtract: 7 5
entering changeSign: 5
exiting changeSign: -5
exiting subtract: 2
```

我们在代码中所做的所有更改都是重新分配`subtract()`和`changeSign()`，这实质上替换了它们的新的生成日志的包装版本。对这两个函数的任何调用都将产生此输出。

我们将会看到一个可能的错误，因为在下一节的*Memoizing*中没有重新分配包装的日志函数。

# 考虑异常情况

让我们稍微增强我们的日志函数，考虑到需要的调整。如果函数抛出错误，您的日志会发生什么？幸运的是，这很容易解决。我们只需要添加一些代码：

```js
const addLogging2 = fn => (...args) => {
 console.log(`entering ${fn.name}: ${args}`);
 try {
 const valueToReturn = fn(...args);
 console.log(`exiting ${fn.name}: ${valueToReturn}`);
 return valueToReturn;
 } catch (thrownError) {
        console.log(`exiting ${fn.name}: threw ${thrownError}`);
 throw thrownError;
 }
};
```

其他更改将由您决定--添加日期和时间数据，增强参数列表的方式等。然而，我们的实现仍然存在一个重要的缺陷；让我们改进一下。

# 以更纯粹的方式工作

当我们编写了`addLogging()`前面的函数时，我们放弃了第四章中看到的一些原则，*行为得体 - 纯函数*，因为我们在代码中包含了一个不纯的元素（`console.log()`）。这样做，我们不仅失去了灵活性（您能够选择替代的日志方式吗？），而且还使我们的测试变得更加复杂。当然，我们可以通过监听`console.log()`方法来测试它，但这并不是很干净：我们依赖于了解我们想要测试的函数的内部，而不是进行纯粹的黑盒测试：

```js
describe("a logging function", function() {
 it("should log twice with well behaved functions", () => {
 let something = (a, b) => `result=${a}:${b}`;
 something = addLogging(something);

 spyOn(window.console, "log");
 something(22, 9);
 expect(window.console.log).toHaveBeenCalledTimes(2);
 expect(window.console.log).toHaveBeenCalledWith(
 "entering something: 22,9"
 );
 expect(window.console.log).toHaveBeenCalledWith(
 "exiting something: result=22:9"
 );
 });

 it("should report a thrown exception", () => {
 let thrower = (a, b, c) => {
 throw "CRASH!";
 };
 spyOn(window.console, "log");
 expect(thrower).toThrow();

 thrower = addLogging(thrower);
 try {
 thrower(1, 2, 3);
 } catch (e) {
 expect(window.console.log).toHaveBeenCalledTimes(2);
 expect(window.console.log).toHaveBeenCalledWith(
 "entering thrower: 1,2,3"
 );
 expect(window.console.log).toHaveBeenCalledWith(
 "exiting thrower: threw CRASH!"
 );
 }
 });
});
```

运行这个测试表明`addLogging()`的行为符合预期，所以这是一个解决方案。

即使这样，以这种方式测试我们的函数并不能解决我们提到的灵活性不足。我们应该注意我们在*注入不纯函数*部分写的内容：日志函数应该作为参数传递给包装函数，这样我们就可以在需要时更改它：

```js
const addLogging3 = (fn, logger = console.log) => (...args) => {
    logger(`entering ${fn.name}: ${args}`);
 try {
 const valueToReturn = fn(...args);
        logger(`exiting ${fn.name}: ${valueToReturn}`);
 return valueToReturn;
 } catch (thrownError) {
        logger(`exiting ${fn.name}: threw ${thrownError}`);
 throw thrownError;
 }
};
```

如果我们什么都不做，日志包装器显然会产生与前一节相同的结果。然而，我们可以提供一个不同的记录器——例如，在 Node.js 中，我们可以使用*winston*，结果会相应地有所不同：

有关*winston*日志工具的更多信息，请参见[`github.com/winstonjs/winston`](https://github.com/winstonjs/winston)。

```js
const winston = require("winston");
const myLogger = **t => winston.log("debug", "Logging by winston: %s", t)**;
winston.level = "debug";

subtract = addLogging3(subtract, myLogger);
changeSign = addLogging3(changeSign, myLogger);
let x = subtract(7, 5);

// *debug: Logging by winston: entering subtract: 7,5*
// *debug: Logging by winston: entering changeSign: 5*
// *debug: Logging by winston: exiting changeSign: -5*
// *debug: Logging by winston: exiting subtract: 2*
```

现在我们已经遵循了我们之前的建议，我们可以利用存根。测试代码几乎与以前相同，但我们使用了一个没有提供功能或副作用的存根`dummy.logger()`，所以在各方面都更安全。确实：在这种情况下，最初被调用的真实函数`console.log()`不会造成任何伤害，但并非总是如此，因此建议使用存根：

```js
describe("after addLogging2()", function() {
 let dummy;

 beforeEach(() => {
 dummy = {logger() {}};
 spyOn(dummy, "logger");
 });

 it("should call the provided logger", () => {
 let something = (a, b) => `result=${a}:${b}`;
 something = addLogging2(something, dummy.logger);

 something(22, 9);
 expect(dummy.logger).toHaveBeenCalledTimes(2);
 expect(dummy.logger).toHaveBeenCalledWith(
 "entering something: 22,9"
 );
 expect(dummy.logger).toHaveBeenCalledWith(
 "exiting something: result=22:9"
 );
 });

 it("a throwing function should be reported", () => {
 let thrower = (a, b, c) => {
 throw "CRASH!";
 };
 thrower = addLogging2(thrower, dummy.logger);

 try {
 thrower(1, 2, 3);
 } catch (e) {
 expect(dummy.logger).toHaveBeenCalledTimes(2);
 expect(dummy.logger).toHaveBeenCalledWith(
 "entering thrower: 1,2,3"
 );
 expect(dummy.logger).toHaveBeenCalledWith(
 "exiting thrower: threw CRASH!"
 );
 }
 });
});
```

在应用 FP 技术时，一定要记住，如果你在某种程度上使自己的工作复杂化——例如，使测试任何一个函数变得困难——那么你一定是在做错事。在我们的案例中，`addLogging()`的输出是一个不纯的函数，这一事实本应引起警惕。当然，鉴于代码的简单性，在这种特殊情况下，你可能会决定不值得修复，你可以不测试，你也不需要能够更改日志生成的方式。然而，长期的软件开发经验表明，迟早你会后悔这样的决定，所以尽量选择更清洁的解决方案。

# 时间

包装函数的另一个可能的应用是以完全透明的方式记录和记录每个函数调用的时间。

如果你计划优化你的代码，请记住以下规则：*不要这样做*，然后*还不要这样做*，最后*不要在没有测量的情况下这样做*。经常提到，很多糟糕的代码都是由早期的优化尝试产生的，所以不要试图写出最佳的代码，不要试图优化，直到你意识到需要优化，不要随意地进行优化，而是通过测量应用程序的所有部分来确定减速的原因。

在前面的例子的基础上，我们可以编写一个`addTiming()`函数，给定任何函数，它将生成一个包装版本，该版本将在控制台上写出时间数据，但在其他方面的工作方式完全相同：

```js
const myPut = (text, name, tStart, tEnd) =>
 console.log(`${name} - ${text} ${tEnd - tStart} ms`);

const myGet = () => performance.now();

const addTiming = (fn, getTime = myGet, output = myPut) => (...args) => {
 let tStart = getTime();
 try {
 const valueToReturn = fn(...args);
        output("normal exit", fn.name, tStart, getTime());
 return valueToReturn;
 } catch (thrownError) {
        output("exception thrown", fn.name, tStart, getTime());
 throw thrownError;
 }
};
```

请注意，与我们在前一节对日志函数应用的增强相一致，我们提供了单独的记录器和时间访问函数。编写我们的`addTiming()`函数的测试应该很容易，因为我们可以注入两个不纯函数。

使用`performance.now()`提供了最高的精度。如果你不需要这个函数提供的精度（它可能是过度的），你可以简单地用`Date.now()`替代。有关这些替代方案的更多信息，请参见[`developer.mozilla.org/en-US/docs/Web/API/Performance/now`](https://developer.mozilla.org/en-US/docs/Web/API/Performance/now)和[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Date/now`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Date/now)。你也可以考虑使用`console.time()`和`console.timeEnd()`；请参见[`developer.mozilla.org/en-US/docs/Web/API/Console/time`](https://developer.mozilla.org/en-US/docs/Web/API/Console/time)。

为了能够充分尝试日志功能，我修改了`subtract()`函数，这样如果你尝试减去零，它会抛出一个错误。如果需要，你也可以列出输入参数，以获取更多信息：

```js
subtract = **addTiming(subtract)**;

let x = subtract(7, 5);
// subtract - normal exit 0.10500000000001819 ms

let y = subtract(4, 0);
// subtract - exception thrown 0.0949999999999136 ms
```

这段代码与之前的`addLogging()`函数非常相似，这是合理的--在这两种情况下，我们都在实际函数调用之前添加了一些代码，然后在函数返回后添加了一些新代码。您甚至可以考虑编写一个*更高级*的高阶函数，它将接收三个函数，并且会产生一个高阶函数作为输出（例如`addLogging()`或`addTiming()`），该函数将在开始时调用第一个函数，然后在包装函数返回值时调用第二个函数，或者在抛出错误时调用第三个函数！怎么样？

# 记忆化

在第四章中，*行为良好-纯函数*，我们考虑了斐波那契函数的情况，并看到了如何通过手工将其转换为更高效的版本，通过*记忆化*：缓存计算的值，以避免重新计算。为简单起见，现在让我们只考虑具有单个非结构化参数的函数，并留待以后处理具有更复杂参数（对象、数组）或多个参数的函数。

我们可以轻松处理的值的类型是 JS 的原始值：不是对象且没有方法的数据。JS 有六种原始值：`boolean`、`null`、`number`、`string`、`symbol`和`undefined`。很可能我们只会看到前四个作为实际参数。在[`developer.mozilla.org/en-US/docs/Glossary/Primitive`](https://developer.mozilla.org/en-US/docs/Glossary/Primitive)中了解更多。

# 简单的记忆化

我们将使用我们提到的斐波那契函数，这是一个简单的情况：它接收一个数字参数。我们看到的函数如下：

```js
function fib(n) {
 if (n == 0) {
 return 0;
 } else if (n == 1) {
 return 1;
 } else {
 return fib(n - 2) + fib(n - 1);
 }
}
```

我们在那里做的解决方案在概念上是通用的，但在实现上特别是：我们必须直接修改函数的代码，以便利用所述的记忆化。现在我们应该研究一种自动执行相同方式的方法，就像对其他包装函数一样。解决方案将是一个`memoize()`函数，它包装任何其他函数，以应用记忆化：

```js
const memoize = fn => {
 let cache = {};
 return x => (x in cache ? cache[x] : (cache[x] = fn(x)));
};
```

这是如何工作的？对于任何给定的参数，返回的函数首先检查参数是否已经接收到；也就是说，它是否可以在缓存对象中找到。如果是这样，就不需要计算，直接返回缓存的值。否则，我们计算缺失的值并将其存储在缓存中。（我们使用闭包来隐藏缓存，防止外部访问。）我们在这里假设记忆化函数只接收一个参数（`x`），并且它是一个原始值，然后可以直接用作缓存对象的键值；我们以后会考虑其他情况。

这个方法有效吗？我们需要计时--我们碰巧有一个有用的`addTiming()`函数来做这个！首先，我们对原始的`fib()`函数进行一些计时。我们想要计时完整的计算过程，而不是每个递归调用，所以我们编写了一个辅助的`testFib()`函数，这是我们将计时的函数。我们应该重复计时操作并取平均值，但是，由于我们只是想确认记忆化是否有效，我们将容忍差异：

```js
const testFib = n => fib(n);
addTiming(testFib)(45); // 15,382.255 ms
addTiming(testFib)(40); //  1,600.600 ms
addTiming(testFib)(35); //    146.900 ms
```

当然，您的时间可能会有所不同，但结果似乎是合乎逻辑的：我们在第四章中提到的指数增长似乎是存在的，时间增长迅速。现在，让我们对`fib()`进行记忆化，我们应该得到更短的时间--或者不应该吗？

```js
const testMemoFib = memoize(n => fib(n));
addTiming(testMemoFib)(45); // 15,537.575 ms
addTiming(testMemoFib)(45); //      0.005 ms... *good!*
addTiming(testMemoFib)(40); //  1,368.880 ms... *recalculating?*
addTiming(testMemoFib)(35); //    123.970 ms... *here too?*
```

出了些问题！时间应该下降了——但它们几乎一样。这是因为一个常见的错误，我甚至在一些文章和网页中看到过。我们正在计时`memofib()`——但除了计时之外，没有人调用那个函数，而且那只会发生一次！在内部，所有的递归调用都是`fib()`，它没有被记忆化。如果我们再次调用`testMemoFib(45)`，*那个*调用会被缓存，它会几乎立即返回，但这种优化不适用于内部的`fib()`调用。这也是为什么`testMemoFib(40)`和`testMemoFib(35)`的调用没有被优化的原因——当我们计算`testMemoFib(45)`时，那是唯一被缓存的值。

正确的解决方案如下：

```js
fib = memoize(fib);
addTiming(testFib)(45); // 0.080 ms
addTiming(testFib)(40); // 0.025 ms
addTiming(testFib)(35); // 0.009 ms
```

现在，当计算`fib(45)`时，实际上所有中间的斐波那契值（从`fib(0)`到`fib(45)`本身）都被存储了，所以即将到来的调用几乎没有什么工作要做。

# 更复杂的记忆化

如果我们必须处理接收两个或更多参数的函数，或者可以接收数组或对象作为参数的函数，我们该怎么办？当然，就像我们在第二章中看到的问题一样，*函数式思维 - 第一个例子*，关于让函数只执行一次，我们可以简单地忽略这个问题：如果要进行记忆化的函数是一元的，我们就进行记忆化；否则，如果函数的 arity 不同，我们就什么都不做！

函数的参数个数称为函数的*arity*，或者它的*valence*。你可以用三种不同的方式来说：你可以说一个函数的 arity 是 1、2、3 等，或者你可以说一个函数是一元的、二元的、三元的等，或者你也可以说它是单元的、二元的、三元的等：随你挑！

```js
const memoize2 = fn => {
 if (fn.length === 1) {
 let cache = {};
 return x => (x in cache ? cache[x] : (cache[x] = fn(x)));
 } else {
        return fn;
 }
};
```

更认真地工作，如果我们想要能够记忆化任何函数，我们必须找到一种生成缓存键的方法。为此，我们必须找到一种将任何类型的参数转换为字符串的方法。我们不能直接使用非原始值作为缓存键。我们可以尝试将值转换为字符串，比如`strX = String(x)`，但会遇到问题。对于数组，似乎可以工作，但看看这三种情况：

```js
var a = [1, 5, 3, 8, 7, 4, 6];
String(a); // "1,5,3,8,7,4,6"

var b = [[1, 5], [3, 8, 7, 4, 6]];
String(b); // "1,5,3,8,7,4,6"

var c = [[1, 5, 3], [8, 7, 4, 6]];
String(c); // "1,5,3,8,7,4,6"
```

这三种情况产生相同的结果。如果我们只考虑单个数组参数，我们可能能够应付，但当不同的数组产生相同的键时，那就是个问题。

如果我们必须接收对象作为参数，情况会变得更糟，因为任何对象的`String()`表示都是`"[object Object]"`：

```js
var d = {a: "fk"};
String(d); // "[object Object]"

var e = [{p: 1, q: 3}, {p: 2, q: 6}];
String(e); // "[object Object],[object Object]"
```

最简单的解决方案是使用`JSON.stringify()`将我们收到的任何参数转换为有用的、不同的字符串：

```js
var a = [1, 5, 3, 8, 7, 4, 6];
JSON.stringify(a); // "[1,5,3,8,7,4,6]"

var b = [[1, 5], [3, 8, 7, 4, 6]];
JSON.stringify(b); // "[[1,5],[3,8,7,4,6]]"

var c = [[1, 5, 3], [8, 7, 4, 6]];
JSON.stringify(c); // "[[1,5,3],[8,7,4,6]]"

var d = {a: "fk"};
JSON.stringify(d); // "{"a":"fk"}"

var e = [{p: 1, q: 3}, {p: 2, q: 6}];
JSON.stringify(e); // "[{"p":1,"q":3},{"p":2,"q":6}]"
```

为了性能，我们的逻辑应该是这样的：如果我们要进行记忆化的函数接收一个单一的原始值作为参数，直接使用该参数作为缓存键；在其他情况下，使用`JSON.stringify()`应用于参数数组的结果作为缓存键。我们增强的记忆化高阶函数可以如下：

```js
const memoize3 = fn => {
 let cache = {};
 const PRIMITIVES = ["number", "string", "boolean"];
 return (...args) => {
 let strX =
 args.length === 1 && PRIMITIVES.includes(typeof args[0])
 ? args[0]
 : JSON.stringify(args);
 return strX in cache ? cache[strX] : (cache[strX] = fn(...args));
 };
};
```

就普遍性而言，这是最安全的版本。如果你确定要处理的函数的参数类型，可以说我们的第一个版本更快。另一方面，如果你想要更容易理解的代码，即使牺牲一些 CPU 周期，你可以选择一个更简单的版本：

```js
const memoize4 = fn => {
 let cache = {};
 return (...args) => {
 let strX = JSON.stringify(args);
 return strX in cache ? cache[strX] : (cache[strX] = fn(...args));
 };
};
```

如果你想了解一个性能最佳的记忆化函数的开发情况，可以阅读 Caio Gondim 的文章*How I wrote the world's fastest JavaScript memoization library*，在线可供阅读[`community.risingstack.com/the-worlds-fastest-javascript-memoization-library/`](https://community.risingstack.com/the-worlds-fastest-javascript-memoization-library/)。

# 记忆化测试

测试记忆化高阶函数提出了一个有趣的问题--你会怎么做？第一个想法是查看缓存--但那是私有的，不可见的。当然，我们可以改变`memoize()`来使用全局缓存，或者以某种方式允许外部访问缓存，但这种内部检查是不受欢迎的：你应该尝试仅基于外部属性进行测试。

接受我们应该省略尝试检查缓存，我们可以进行时间控制：调用一个函数，比如`fib()`，对于一个很大的 n 值，如果函数没有进行记忆化，应该需要更长的时间。这当然是可能的，但也容易出现可能的失败：你的测试之外的某些东西可能会在恰好的时候运行，可能你的记忆化运行时间会比原始运行时间更长。好吧，这是可能的，但不太可能--但你的测试并不完全可靠。

然后，让我们更直接地分析记忆化函数的实际调用次数。使用非记忆化的原始`fib()`，我们可以首先测试函数是否正常工作，并检查它调用了多少次：

```js
var fib = null;

beforeEach(() => {
 fib = n => {
 if (n == 0) {
 return 0;
 } else if (n == 1) {
 return 1;
 } else {
 return fib(n - 2) + fib(n - 1);
 }
 };
});

describe("the original fib", function() {
 it("should produce correct results", () => {
 expect(fib(0)).toBe(0);
 expect(fib(1)).toBe(1);
 expect(fib(5)).toBe(5);
 expect(fib(8)).toBe(21);
 expect(fib(10)).toBe(55);
 });

 it("should repeat calculations", () => {
 spyOn(window, "fib").and.callThrough();
 expect(fib(6)).toBe(8);
 expect(fib).toHaveBeenCalledTimes(25);
 });
});
```

`fib(6)`等于 8 这一事实很容易验证，但你怎么知道函数被调用了 25 次？为了回答这个问题，让我们重新看一下之前在第四章中看到的图表，*行为得体-纯函数*：

图 6.1。计算 fib(6)所需的所有递归调用。

每个节点都是一个调用；仅仅计数，我们得到为了计算`fib(6)`，实际上有 25 次对`fib()`的调用。现在，让我们转向函数的记忆版本。测试它是否仍然产生相同的结果很容易：

```js
describe("the memoized fib", function() {
 beforeEach(() => {
 fib = memoize(fib);
 });

 it("should produce same results", () => {
 expect(fib(0)).toBe(0);
 expect(fib(1)).toBe(1);
 expect(fib(5)).toBe(5);
 expect(fib(8)).toBe(21);
 expect(fib(10)).toBe(55);
 });

 it("shouldn't repeat calculations", () => {
 spyOn(window, "fib").and.callThrough();

 expect(fib(6)).toBe(8); // 11 calls
 expect(fib).toHaveBeenCalledTimes(11);

 expect(fib(5)).toBe(5); // 1 call
 expect(fib(4)).toBe(3); // 1 call
 expect(fib(3)).toBe(2); // 1 call
 expect(fib).toHaveBeenCalledTimes(14);
 });
});
```

但为什么在计算`fib(6)`时被调用了 11 次，然后在计算`fib(5)`，`fib(4)`和`fib(3)`之后又被调用了三次？为了回答问题的第一部分，让我们分析一下之前看到的图：

+   首先，我们调用`fib(6)`，它调用了`fib(4)`和`fib(5)`：三次调用

+   在计算`fib(4)`时，调用了`fib(2)`和`fib(3)`；计数增加到了五

+   在计算`fib(5)`时，调用了`fib(3)`和`fib(4)`；计数上升到 11

+   最后，计算并缓存了`fib(6)`

+   `fib(3)`和`fib(4)`都被缓存了，所以不再进行调用

+   `fib(5)`被计算并缓存

+   在计算`fib(2)`时，调用了`fib(0)`和`fib(1)`；现在我们有了七次调用

+   在计算`fib(3)`时，调用了`fib(1)`和`fib(2)`；计数增加到了九

+   `fib(4)`被计算并缓存

+   `fib(1)`和`fib(2)`都已经被缓存了，所以不会再进行进一步的调用

+   `fib(3)`被计算并缓存

+   在计算`fib(0)`和`fib(1)`时，不会进行额外的调用，两者都被缓存了

+   `fib(2)`被计算并缓存

哇！所以`fib(6)`的调用次数是 11--现在，鉴于所有`fib(n)`的值都已经被缓存，对于 n 从 0 到 6，很容易看出计算`fib(5)`，`fib(4)`和`fib(3)`只会增加三次调用：所有其他所需的值都已经被缓存。

# 改变函数

在前一节中，我们考虑了一些包装函数的方法，使它们保持其原始功能，尽管在某些方面得到了增强。现在我们将转而实际修改函数的功能，使新的结果实际上与原始函数的结果不同。

# 重新做一次事情

回到第二章，*思考功能性-第一个例子*，我们通过一个简单的问题的 FP 风格解决方案的例子：修复一个给定函数只能工作一次的问题：

```js
const once = func => {
 let done = false;
 return (...args) => {
 if (!done) {
 done = true;
 func(...args);
 }
 };
};
```

这是一个完全合理的解决方案，我们没有任何异议。然而，我们可以考虑一种变体。我们可以观察到给定的函数被调用一次，但其返回值被丢失了。然而，这很容易解决；我们只需要添加一个`return`语句。然而，这还不够；如果调用更多次，函数会返回什么呢？我们可以借鉴记忆化解决方案，并为将来的调用存储函数的返回值：

```js
const once2 = func => {
 let done = false;
    let result;
 return (...args) => {
 if (!done) {
 done = true;
            result = func(...args);
 }
        return result;
 };
};
```

你也可以考虑使函数仅对每组参数起作用一次...但是你不必为此做任何工作：`memoize()`就足够了！

回到提到的第二章，*函数式思维 - 第一个例子*，我们考虑了`once()`的一个可能替代品：另一个高阶函数，它以两个函数作为参数，并且只允许调用第一个函数一次，从那时起调用第二个函数。添加一个`return`语句，它将如下所示：

```js
const onceAndAfter = (f, g) => {
 let done = false;
 return (...args) => {
 if (!done) {
 done = true;
 return f(...args);
 } else {
 return g(...args);
 }
 };
};
```

如果我们记得函数是一级对象，我们可以重写这个过程。我们可以使用一个变量（`toCall`）直接存储需要调用的函数，而不是使用标志来记住要调用哪个函数。从逻辑上讲，该变量将被初始化为第一个函数，但随后将更改为第二个函数：

```js
const onceAndAfter2 = (f, g) => {
    let toCall = f;
 return (...args) => {
 let result = toCall(...args);
        toCall = g;
 return result;
 };
};
```

我们之前看到的完全相同的例子仍然可以工作：

```js
const squeak = (x) => console.log(x, "squeak!!");
const creak = (x) => console.log(x, "creak!!");
const makeSound = onceAndAfter2(squeak, creak);

makeSound("door"); // *"door squeak!!"*
makeSound("door"); // *"door creak!!"*
makeSound("door"); // *"door creak!!"*
makeSound("door"); // *"door creak!!"*
```

在性能方面，差异可能微乎其微。展示这种进一步变化的原因只是为了记住，通过存储函数，你通常可以以更简单的方式产生结果。在过程式编程中，使用标志存储状态是一种常见的技术，随处可见。然而，在这里，我们设法跳过了这种用法，但却产生了相同的结果。

# 逻辑否定一个函数

让我们考虑一下来自第五章的`.filter()`方法，*声明式编程 - 更好的风格*。给定一个谓词，我们可以过滤数组，只包括谓词为真的元素。但是如何进行反向过滤并*排除*谓词为真的元素呢？

第一个解决方案应该是相当明显的：重新设计谓词，使其返回与原始返回值相反的值。在前面提到的章节中，我们看到了这个例子：

```js
const delinquent = serviceResult.accountsData.filter(v => v.balance < 0);
```

因此，我们可以以另一种方式写出它，以这两种等效方式之一：

```js
const notDelinquent = serviceResult.accountsData.filter(
    v => v.balance >= 0
);

const notDelinquent2 = serviceResult.accountsData.filter(
    v => !(v.balance < 0)
);
```

这是完全可以的，但我们也可以有类似以下的东西：

```js
const isNegativeBalance = v => v.balance < 0;

// ...*many lines later..*.

const delinquent2 = serviceResult.accountsData.filter(isNegativeBalance);
```

在这种情况下，重写原始函数是不可能的。然而，在函数式编程中，我们可以编写一个高阶函数，它将接受任何谓词，评估它，然后否定其结果。由于 ES8 的语法，可能的实现会非常简单：

```js
const not = fn => (...args) => !fn(...args);
```

以这种方式工作，我们可以将前面的过滤重写为以下形式：

```js
const isNegativeBalance = v => v.balance < 0;

// ...*many lines later...* 
const notDelinquent3 = serviceResult.accountsData.filter(
    not(isNegativeBalance)
);
```

我们可能想要尝试的另一个解决方案是--而不是颠倒条件（如我们所做的），我们可以编写一个新的过滤方法（可能是`filterNot()`？），它将以与`filter()`相反的方式工作：

```js
const filterNot = arr => fn => arr.filter(not(fn));
```

这个解决方案与`.filter()`并不完全匹配，因为你不能将其用作方法，但我们可以将其添加到`Array.prototype`中，或者应用一些我们将在第八章中看到的方法，*连接函数 - 管道和组合*。然而，更有趣的是，我们使用了否定的函数，因此`not()`对于反向过滤问题的两种解决方案都是必要的。在即将到来的去方法化部分中，我们将看到另一个解决方案，因为我们将能够将诸如`.filter()`之类的方法与它们适用的对象分离开来，将它们变成普通函数。

至于否定函数*与*使用新的`filterNot()`，尽管两种可能性同样有效，但我认为使用`not()`更清晰；如果你已经理解了过滤的工作原理，那么你几乎可以大声朗读它，它就会被理解：我们想要那些没有负余额的，对吧？

# 反转结果

与前面的过滤问题类似，现在让我们重新讨论第三章中的*注入-排序*部分中的排序问题，*从函数开始-核心概念*。我们想要使用特定的方法对数组进行排序，并且我们使用了`.sort()`，提供了一个比较函数，基本上指出了哪个字符串应该先进行排序。为了提醒你，给定两个字符串，函数应该执行以下操作：

+   如果第一个字符串应该在第二个字符串之前，则返回一个负数

+   如果两个字符串相同，则返回零

+   返回一个正数，如果第一个字符串应该跟在第二个字符串后面

让我们回到我们之前在西班牙语排序中看到的代码。我们必须编写一个特殊的比较函数，以便排序能够考虑西班牙语的特殊字符顺序规则，比如在*n*和*o*之间包括字母*ñ*，等等。

```js
const spanishComparison = (a, b) => a.localeCompare(b, "es");

palabras.sort(spanishComparison); // *sorts the* palabras *array according to Spanish rules*
```

我们面临着类似的问题：我们如何能够以*降序*的方式进行排序？根据我们在前一节中看到的内容，应该立即想到两种替代方案：

+   编写一个函数，它将反转比较函数的结果。这将反转所有关于哪个字符串应该在前面的决定，最终结果将是一个完全相反排序的数组。

+   编写一个`sortDescending()`函数或方法，以与`sort()`相反的方式进行工作。

让我们编写一个`invert()`函数，它将改变比较的结果。代码本身与前面的`not()`非常相似：

```js
const invert = fn => (...args) => -fn(...args);
```

有了这个高阶函数，我们现在可以通过提供一个适当反转的比较函数来进行降序排序：

```js
const spanishComparison = (a, b) => a.localeCompare(b, "es");

var palabras = ["ñandú", "oasis", "mano", "natural", "mítico", "musical"];

palabras.sort(spanishComparison);
// ["mano", "mítico", "musical", "natural", "ñandú", "oasis"]

palabras.sort(**invert(spanishComparison)**);
// ["oasis", "ñandú", "natural", "musical", "mítico", "mano"]
```

输出与预期相符：当我们`invert()`比较函数时，结果是相反的顺序。顺便说一句，编写单元测试将非常容易，因为我们已经有了一些测试用例和它们的预期结果，不是吗？

# 改变参数数量

回到第五章中*隐式地*解析数字的部分，我们看到使用`parseInt()`与`.reduce()`会产生问题，因为该函数的参数数量是意外的，它需要多于一个参数：

```js
["123.45", "-67.8", "90"].map(parseInt); // *problem: parseInt isn't monadic!*
// [123, NaN, NaN]
```

我们有多种解决方法。在提到的章节中，我们选择了箭头函数，这是一个简单的解决方案，而且具有清晰易懂的优势。在第七章中，*转换函数-柯里化和部分应用*，我们将看到另一种方法，基于部分应用。但是，在这里，让我们使用一个高阶函数。我们需要的是一个函数，它将另一个函数作为参数，并将其转换为一元函数。使用 JS 的展开运算符和箭头函数，这很容易管理：

```js
const unary = fn => (...args) => fn(args[0]);
```

使用这个函数，我们的数字解析问题就解决了：

```js
["123.45", "-67.8", "90"].map(unary(parseInt));
// *[123, -67, 90]*
```

不用说，同样简单地定义进一步的`binary()`、`ternary()`等函数，可以将任何函数转换为等效的、限定数量参数的版本。

你可能会认为没有多少情况需要应用这种解决方案，但事实上，情况比你想象的要多得多。通过查看所有 JavaScript 的函数和方法，你可以轻松地列出一个以`.apply()`、`.assign()`、`.bind()`、`.concat()`、`.copyWithin()`...等等开头的列表！如果你想以一种心照不宣的方式使用其中任何一个，你可能需要修复它的参数数量，这样它就可以使用固定的、非可变的参数数量。

如果你想要一个漂亮的 JavaScript 函数和方法列表，请查看[`developer.mozilla.org/en/docs/Web/JavaScript/Guide/Functions`](https://developer.mozilla.org/en/docs/Web/JavaScript/Guide/Functions)和[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Methods_Index`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Methods_Index)上的页面。至于暗示（或点自由风格）编程，我们将在第八章中回到它，*连接函数 - 管道和组合*。

# 其他高阶函数

让我们在本章结束时考虑其他杂项函数，提供诸如新查找器、将方法与对象解耦等结果。

# 将操作转换为函数

我们已经看到了几种情况，我们需要编写一个函数来添加或乘以一对数字。例如，在第五章的*求和数组*部分，*声明式编程 - 更好的风格*，我们不得不编写等效于以下代码的代码：

```js
const mySum = myArray.reduce((x, y) => x + y, 0);
```

在同一章节中，在*使用范围*部分，为了计算阶乘，我们需要这样：

```js
const factorialByRange = n => range(1, n + 1).reduce((x, y) => x * y, 1);
```

如果我们能够将二元运算符转换为计算相同结果的函数，那将会更容易。前面的两个例子可以更简洁地写成如下所示：

```js
const mySum = myArray.reduce(binaryOp("+"), 0);
const factorialByRange = n => range(1, n + 1).reduce(binaryOp("*"), 1);
```

# 实施操作

我们如何编写这个`binaryOp()`函数？至少有两种方法：一种安全但冗长，一种更冒险但更短的替代方法。第一种方法需要列出每个可能的运算符：

```js
const binaryOp1 = op => {
 switch (op) {
 case "+":
 return (x, y) => x + y;
 case "-":
 return (x, y) => x - y;
 case "*":
 return (x, y) => x * y;
 //
 // etc.
 //
 }
};
```

这个解决方案完全没问题，但需要太多的工作。第二个更危险，但更短。请将其仅视为一个示例，用于学习目的；出于安全原因，不建议使用`eval()`！

```js
const binaryOp2 = op => new Function("x", "y", `return x ${op} y;`);
```

如果你遵循这种思路，你也可以定义一个`unaryOp()`函数，尽管它的应用更少。 （我把这个实现留给你；它与我们已经写的内容非常相似。）在即将到来的第七章中，*转换函数 - 柯里化和部分应用*，我们将看到创建这个一元函数的另一种方法，即使用部分应用。

# 更方便的实现

让我们超前一步。进行 FP 并不意味着总是要回到非常基本、最简单的函数。例如，在第八章的*转换为自由点风格*部分，*连接函数 - 管道和组合*，我们将需要一个函数来检查一个数字是否为负数，并考虑使用`binaryOp2()`来编写它：

```js
const isNegative = curry(binaryOp2(">"))(0);
```

现在不要担心`curry()`函数（我们很快会在第七章中讨论它，*转换函数 - 柯里化和部分应用*），但其思想是将第一个参数固定为零，因此我们的函数将检查给定数字*n*是否*0>n*。这里的重点是，我们刚刚编写的函数并不是很清晰。如果我们定义一个二元操作函数，还可以让我们指定其参数之一，左边的参数或右边的参数，以及要使用的运算符，我们可以做得更好：

```js
const binaryLeftOp = (x, op) => 
 (y) => binaryOp2(op)(x,y);

const binaryOpRight = (op, y) => 
 (x) => binaryOp2(op)(x,y);
```

或者，你可以回到`new Function()`风格的代码：

```js
const binaryLeftOp2 = (x, op) => y => binaryOp2(op)(x, y);

const binaryOpRight2 = (op, y) => x => binaryOp2(op)(x, y);
```

有了这些新函数，我们可以简单地写出以下任一代码--尽管我认为第二个更清晰：我宁愿测试一个数字是否小于零，而不是零是否大于该数字：

```js
const isNegative1 = binaryLeftOp(0, ">");

const isNegative2 = binaryOpRight("<", 0);
```

这有什么意义？不要追求某种*基本简单*或*回归基础*的代码。我们可以将运算符转换为函数，没错--但如果你能做得更好，并通过允许指定操作的两个参数之一来简化编码，那就去做吧！FP 的理念是帮助编写更好的代码，而创造人为限制对任何人都没有好处。

当然，对于一个简单的函数，比如检查一个数字是否为负数，我绝对不想用柯里化、二元运算符或点自由风格或其他任何东西来复杂化事情，我只会毫不犹豫地写出以下内容：

```js
const isNegative3 = x => x < 0;
```

# 将函数转换为 promises

在 Node 中，大多数异步函数需要一个回调，比如`(err,data)=>{...}`：如果`err`是`null`，函数成功，`data`是其结果，如果`err`有一些值，函数失败，`err`给出了原因。（有关更多信息，请参见[`nodejs.org/api/errors.html#errors_node_js_style_callbacks`](https://nodejs.org/api/errors.html#errors_node_js_style_callbacks)。）

但是，您可能更喜欢使用 promises。因此，我们可以考虑编写一个高阶函数，将需要回调的函数转换为一个 promise，让您使用`.then()`和`.catch()`方法。（在第十二章中，*构建更好的容器-功能数据类型*，我们将看到 promises 实际上是 monads，因此这种转换在另一个方面也很有趣。）

我们如何管理这个？转换相当简单。给定一个函数，我们生成一个新的函数：这将返回一个 promise，当使用一些参数调用原始函数时，将适当地`reject()`或`resolve()`promise：

```js
const promisify = fn => (...args) =>
 new Promise((resolve, reject) =>
 fn(...args, (err, data) => (err ? reject(err) : resolve(data)))
 );
```

有了这个函数，我们可以这样写代码：

```js
const fs = require("fs");

const cb = (err, data) =>
 err ? console.log("ERROR", err) : console.log("SUCCESS", data);

fs.readFile("./exists.txt", cb); // *success, list the data*
fs.readFile("./doesnt_exist.txt", cb); // *failure, show exception*
```

相反，您可以使用 promises：

```js
const fspromise = promisify(fs.readFile.bind(fs));

const goodRead = data => console.log("SUCCESSFUL PROMISE", data);
const badRead = err => console.log("UNSUCCESSFUL PROMISE", err);

fspromise("./readme.txt") *// success*
 .then(goodRead)
 .catch(badRead);

fspromise("./readmenot.txt") // *failure*
 .then(goodRead)
 .catch(badRead);
```

现在您可以使用`fspromise()`而不是原始方法。我们必须绑定`fs.readFile`，正如我们在第三章的*一个不必要的错误*部分中提到的那样，*从函数开始-核心概念*。

# 从对象中获取属性

有一个简单但经常使用的函数，我们也可以生成。从对象中提取属性是一个常见的操作。例如，在第五章中，*以声明方式编程-更好的风格*，我们需要获取纬度和经度以便计算平均值：

```js
markers = [
 {name: "UY", lat: -34.9, lon: -56.2},
 {name: "AR", lat: -34.6, lon: -58.4},
 {name: "BR", lat: -15.8, lon: -47.9},
 ...
 {name: "BO", lat: -16.5, lon: -68.1}
];

let averageLat = average(markers.map(x => x.lat));
let averageLon = average(markers.map(x => x.lon));
```

当我们看到如何过滤数组时，我们有另一个例子；在我们的例子中，我们想要获取所有余额为负的帐户的 ID，并在过滤掉所有其他帐户后，我们仍然需要提取 ID 字段：

```js
const delinquent = serviceResult.accountsData.filter(v => v.balance < 0);
const delinquentIds = delinquent.map(v => v.id);
```

我们本可以将这两行合并，并用一行代码产生所需的结果，但这里并不重要。事实上，除非`delinquent`中间结果出于某种原因是必需的，大多数 FP 程序员都会选择一行解决方案。

我们需要什么？我们需要一个高阶函数，它将接收一个属性的名称，并产生一个新的函数作为其结果，这个函数将能够从对象中提取所述属性。使用 ES8 语法，这个函数很容易编写：

```js
const getField = attr => obj => obj[attr];
```

在第十章的*获取器和设置器*部分，*确保纯度-不可变性*，我们将编写这个函数的更通用版本，能够“深入”到对象中，获取对象的任何属性，无论其在对象中的位置如何。

有了这个函数，坐标提取可以这样写：

```js
let averageLat = average(markers.map(getField("lat")));
let averageLon = average(markers.map(getField("lon")));
```

为了多样化，我们可以使用辅助变量来获取拖欠的 ID。

```js
const getId = getField("id");
const delinquent = serviceResult.accountsData.filter(v => v.balance < 0);
const delinquentIds = delinquent.map(getId);
```

一定要完全理解这里发生了什么。`getField()`调用的结果是一个函数，将在进一步的表达式中使用。`map()`方法需要一个映射函数，这就是`getField()`产生的东西。

# 去方法化-将方法转换为函数

`.filter()`或`.map()`等方法仅适用于数组--但实际上，你可能希望将它们应用于`NodeList`或`String`，但你可能会碰壁。此外，我们正在关注字符串，因此必须将这些函数用作方法并不是我们想要的。最后，每当我们创建一个新函数（比如`none()`，我们在第五章 *以更好的方式编程 - 声明式编程* 的*检查否定*部分中看到的），它不能像它的同行（在这种情况下是`.some()`和`.every()`）那样应用，除非你做一些原型的把戏--这是被严厉谴责的，也完全不推荐...但是请看第十二章 *构建更好的容器 - 函数数据类型* 的*扩展当前数据类型*部分，我们将使`.map()`适用于大多数基本类型！

那么...我们能做什么呢？我们可以应用古话*如果山不来，穆罕默德就去山*，而不是担心无法创建新的方法，我们将现有的方法转换为函数。如果我们将每个方法转换为一个函数，该函数将作为其第一个参数接收它将要操作的对象。

解耦方法和对象可以帮助你，因为一旦你实现了这种分离，一切都变成了一个函数，你的代码会更简单。（还记得我们在*逻辑否定一个函数*中写的内容吗，关于可能的`filterNot()`函数与`.filter()`方法的比较？）解耦的方法在某种程度上类似于其他语言中所谓的*通用*函数，因为它们可以应用于不同的数据类型。

在 ES8 中，有三种不同但相似的实现方式。列表中的第一个参数将对应于对象；其他参数将对应于被调用方法的实际参数。

请参阅[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function)以了解`apply()`、`call()`和`bind()`的解释。顺便说一句，在第一章 *成为函数 - 几个问题* 中，我们看到了在使用展开运算符时`.apply()`和`.call()`之间的等价性。

```js
const demethodize1 = fn => (arg0, ...args) => fn.apply(arg0, args);

const demethodize2 = fn => (arg0, ...args) => fn.call(arg0, ...args);

const demethodize3 = fn => (...args) => fn.bind(...args)();
```

还有另一种方法：`demethodize = Function.prototype.bind.bind(Function.prototype.call)`。如果你想了解这是如何工作的，请阅读 Leland Richardson 的*Clever way to* demethodize *Native JS Methods*，网址为[`www.intelligiblebabble.com/clever-way-to-demethodize-native-js-methods`](http://www.intelligiblebabble.com/clever-way-to-demethodize-native-js-methods)。

让我们看一些应用！从一个简单的例子开始，我们可以使用`.map()`来循环遍历一个字符串，而不必先将其转换为字符数组。假设你想将一个字符串分隔成单个字母并将它们转换为大写：

```js
const name = "FUNCTIONAL";
const result = name.split("").map(x => x.toUpperCase());
// *["F", "U", "N", "C", "T", "I", "O", "N", "A", "L"]*
```

然而，如果我们解除了`.map()`和`.toUpperCase()`，我们可以简单地写成以下形式：

```js
const map = demethodize3(Array.prototype.map);
const toUpperCase = demethodize3(String.prototype.toUpperCase);

const result2 = map(name, toUpperCase);
// *["F", "U", "N", "C", "T", "I", "O", "N", "A", "L"]*
```

是的，对于这种特殊情况，我们可以先将字符串转换为大写，然后将其拆分为单独的字母，如`name.toUpperCase().split("")` -- 但这不会是一个很好的例子，毕竟有两个解除方法的用法，对吧？

类似地，我们可以将一个十进制金额数组转换为格式正确的字符串，带有千位分隔符和小数点：

```js
const toLocaleString = demethodize3(Number.prototype.toLocaleString);

const numbers = [2209.6, 124.56, 1048576];
const strings = numbers.map(toLocaleString);
// *["2,209.6", "124.56", "1,048,576"]*
```

或者，给定前面的 map 函数，这也可以工作：

```js
const strings2 = map(numbers, toLocaleString);
```

将方法解除为函数的想法在不同的情况下将会非常有用。我们已经看到了一些例子，我们可以应用它，并且在本书的其余部分还会有更多这样的情况。

# 找到最佳解决方案

让我们通过创建`.find()`方法的扩展来结束本节。假设我们想要找到数组中的最优值--假设它是最大值--：

```js
const findOptimum = arr => Math.max(...arr);

const myArray = [22, 9, 60, 12, 4, 56];
findOptimum(myArray); // 60
```

现在，这是否足够通用？这种方法至少存在一对问题。首先，你确定集合的最优值总是最大值吗？如果你考虑了几种抵押贷款，那么利率最低的那个可能是最好的，不是吗？假设我们总是想要集合的*最大值*太过于局限了。

你可以绕个弯：如果你改变数组中所有数字的符号，找到它的最大值，然后改变它的符号，那么你实际上得到了数组的最小值。在我们的例子中，`-findOptimum(myArray.map((x) => -x))`将产生 4--但这不是容易理解的代码。

其次，找到最大值的这种方式取决于每个选项都有一个数值。但如果这样的值不存在，你该如何找到最优值？通常的方法依赖于将元素相互比较，并选择在比较中排在前面的元素：将第一个元素与第二个元素进行比较，并保留其中较好的那个；然后将该值与第三个元素进行比较，并保留最好的；依此类推，直到你完成了所有元素的遍历。

以更一般的方式解决这个问题的方法是假设存在一个`comparator()`函数，它以两个元素作为参数，并返回最好的那个。如果你能为每个元素关联一个数值，那么比较函数可以简单地比较这些值。在其他情况下，它可以根据需要执行任何逻辑，以便决定哪个元素排在前面。

让我们尝试创建一个合适的高阶函数：

```js
const findOptimum2 = fn => arr => arr.reduce(fn);
```

有了这个，我们可以轻松地复制最大值和最小值查找函数。

```js
const findMaximum = findOptimum2((x, y) => (x > y ? x : y));
const findMinimum = findOptimum2((x, y) => (x < y ? x : y));

findMaximum(myArray); // 60
findMinimum(myArray); // 4
```

让我们更上一层楼，比较非数值值。假设有一款超级英雄卡牌游戏：每张卡代表一个英雄，具有几个数值属性，如力量、能力和科技。当两个英雄互相对抗时，具有更多类别的英雄，其数值高于另一个英雄，将成为赢家。让我们为此实现一个比较器：

```js
const compareHeroes = (card1, card2) => {
 const oneIfBigger = (x, y) => (x > y ? 1 : 0);

 const wins1 =
 oneIfBigger(card1.strength, card2.strength) +
 oneIfBigger(card1.powers, card2.powers) +
 oneIfBigger(card1.tech, card2.tech);

 const wins2 =
 oneIfBigger(card2.strength, card1.strength) +
 oneIfBigger(card2.powers, card1.powers) +
 oneIfBigger(card2.tech, card1.tech);

 return wins1 > wins2 ? card1 : card2;
};
```

然后，我们可以将这应用到我们的英雄“比赛”中：

```js
function Hero(n, s, p, t) {
 this.name = n;
 this.strength = s;
 this.powers = p;
 this.tech = t;
}

const codingLeagueOfAmerica = [
 new Hero("Forceful", 20, 15, 2),
 new Hero("Electrico", 12, 21, 8),
 new Hero("Speediest", 8, 11, 4),
 new Hero("TechWiz", 6, 16, 30)
];

const findBestHero = findOptimum2(compareHeroes);
findBestHero(codingLeagueOfAmerica); // Electrico is the top hero!
```

当你根据一对一比较对元素进行排名时，可能会产生意想不到的结果。例如，根据我们的超级英雄比较规则，你可能会找到三个英雄，第一个击败第二个，第二个击败第三个，但第三个击败第一个！在数学术语中，这意味着比较函数不是传递的，你没有集合的*完全排序*。

# 问题

6.1\. **一个边界情况**。如果我们将`getField()`函数应用于一个空对象，会发生什么？它应该是什么行为？如果需要，修改该函数。

6.2\. **多少次？** 要计算`fib(50)`需要多少次调用而不使用记忆化？例如，计算`fib(0)`或`fib(1)`，只需要一次调用，不需要进一步递归，而对于`fib(6)`，我们看到需要 25 次调用。你能找到一个公式来做这个计算吗？

6.3\. **一个随机平衡器**。编写一个高阶函数`randomizer(fn1, fn2, ...)`，它将接收可变数量的函数作为参数，并返回一个新的函数，该函数在每次调用时将随机调用`fn1`、`fn2`等。如果每个函数都能执行 Ajax 调用，你可能会用到这个函数来平衡对服务器上不同服务的调用。为了加分，确保连续两次不会调用同一个函数。

6.4\. **只说不！** 在本章中，我们编写了一个与布尔函数一起工作的`not()`函数和一个与数值函数一起工作的`negate()`函数。你能更上一层楼，只编写一个`opposite()`函数，根据需要表现为`not()`或`negate()`吗？

# 总结

在本章中，我们已经看到如何编写我们自己的高阶函数，它可以包装另一个函数以提供一些新功能，改变函数的目标以便做其他事情，甚至是全新的功能，比如将方法与对象解耦或创建更好的查找器。

在第七章中，*函数转换-柯里化和部分应用*，我们将继续使用高阶函数，并且我们将看到如何通过柯里化和部分应用来生成现有函数的专门版本，带有预定义的参数。


# 第七章：函数转换-柯里化和部分应用

在第六章中，*生成函数-高阶函数*，我们看到了几种操纵函数的方法，以获得具有某些功能变化的新版本。在本章中，我们将深入研究一种特定类型的转换，一种*工厂*方法，它让您可以使用一些固定参数来生成任何给定函数的新版本。

我们将考虑以下内容：

+   *柯里化*，一个经典的 FP 理论函数，将具有许多参数的函数转换为一系列一元函数

+   *部分应用*，另一个历史悠久的 FP 转换，通过固定一些参数来产生函数的新版本

+   我将称之为*部分柯里化*的东西，可以看作是两种先前转换的混合体

公平地说，我们还将看到，一些这些技术可以通过简单的箭头函数来模拟，可能会更清晰。然而，由于您很可能会在各种 FP 文本和网页上找到柯里化和部分应用，因此了解它们的含义和用法非常重要，即使您选择更简单的方法。

# 一点理论

本章中我们将使用的概念在某些方面非常相似，在其他方面则有很大不同。人们常常会对它们的真正含义感到困惑，并且有很多网页滥用术语。您甚至可以说，本章中的所有转换大致等效，因为它们让您将一个函数转换为另一个函数，固定一些参数，留下其他参数自由，并最终导致相同的结果。好吧，我同意，这并不是很清楚！因此，让我们从澄清一些概念开始，并提供一些简短的定义，稍后我们将进行扩展。（如果您觉得自己的眼睛开始发直，请跳过这一部分，稍后再来看！）是的，您可能会觉得以下描述有点令人困惑，但请耐心等待：我们马上就会详细介绍！

+   *柯里化*是将*m*元函数（即，具有*m*个参数的函数）转换为一系列*m*个一元函数的过程，每个函数接收原始函数的一个参数，从左到右。（第一个函数接收原始函数的第一个参数，第二个函数接收第二个参数，依此类推。）每次调用带有参数的函数时，都会产生序列中的下一个函数，最后一个函数执行实际的计算。

+   *部分应用*是提供*n*个参数给*m*元函数的想法，其中*n*小于或等于*m*，以将其转换为具有(*m-n*)个参数的函数。每次提供一些参数时，都会产生一个具有更小元数的新函数。当提供最后的参数时，将执行实际的计算。

+   *部分柯里化*是两种先前想法的混合体：您向*m*元函数提供*n*个参数（从左到右），并产生一个新的元函数（*m-n*）。当这个新函数接收到其他参数，同样是从左到右，它将产生另一个函数。当提供最后的参数时，函数将产生正确的计算结果。

在本章中，我们将看到这三种转换，它们需要什么，以及实现它们的方法。关于这一点，我们将探讨每个高阶函数的编码方式，这将为我们提供有关 JS 编码的一些有趣见解，您可能会发现对其他应用程序很有趣。

# 柯里化

我们已经在第一章的*箭头函数*部分和第三章的*一个参数还是多个参数？*部分中提到了柯里化，但让我们在这里更加彻底。柯里化是一种设备，它使您只能使用单变量函数，即使您需要多变量函数。

将多变量函数转换为一系列单变量函数的想法（或者更严格地说，将具有多个操作数的运算符减少为单操作数运算符的一系列应用）是由 Moses Schönfinkel 研究过的，有一些作者建议，不一定是开玩笑，柯里化更正确地被称为*Schönfinkeling*！

# 处理许多参数

柯里化的想法本身很简单。如果您需要一个带有三个参数的函数，而不是（使用箭头函数）像下面这样写：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);
```

您可以有一系列具有单个参数的函数：

```js
const make3curried = a => b => c => String(100 * a + 10 * b + c);
```

或者，您可能希望将它们视为嵌套函数：

```js
const make3curried2 = function(a) {
 return function(b) {
 return function(c) {
 return String(100 * a + 10 * b + c);
 };
 };
};
```

在使用上，每个函数的使用方式有一个重要的区别。虽然您可以像这样调用第一个函数，比如`make3(1,2,4)`，但是对于第二个定义，这样是行不通的。让我们来看看为什么：`make3curried()`是一个*一元*（单参数）函数，所以我们应该写`make3curried(1)`...但是这会返回什么？根据上面的定义，这也会返回一个一元函数--*那*个函数也会返回一个一元函数！因此，要获得与三元函数相同的结果，正确的调用应该是`make3curried(1)(2)(4)`！参见图 7.1：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-js-fp/img/47ca4163-c4a1-44eb-90ff-76d77804c6d7.jpg)图 7.1。普通函数和柯里化等价函数之间的区别。

仔细研究这一点--我们有第一个函数，当我们对其应用一个参数时，我们得到第二个函数。对它应用一个参数会产生第三个函数和最终的应用会产生期望的结果。这可以被视为在理论计算中不必要的练习，但实际上它带来了一些优势，因为您可以始终使用一元函数，即使您需要具有更多参数的函数。

由于存在柯里化转换，也存在反柯里化转换！在我们的例子中，我们会写`make3uncurried = (a,b,c) => make3curried(a)(b)(c)`来恢复柯里化过程，并再次使用，一次性提供所有参数。

在某些语言中，比如 Haskell，函数只允许接受一个参数--但是语言的语法允许您调用函数，就好像允许多个参数一样。对于我们的例子，在 Haskell 中，写`make3curried 1 2 4`会产生结果 124，甚至不需要有人意识到它涉及*三*个函数调用，每个函数都有一个参数。由于您不在参数周围写括号，并且不用逗号分隔它们，您无法知道您没有提供三个单一值而是三个值的三元组。

柯里化在 Scala 或 Haskell 中是基本的，这些都是完全功能的语言，但 JavaScript 有足够的功能来允许我们在工作中定义和使用柯里化。这不会那么容易--毕竟，它不是内置的--但我们将能够应对。

因此，回顾基本概念，我们原始的`make3()`和`make3curried()`之间的关键区别如下：

+   `make3()`是一个三元函数，但`make3curried()`是一元的

+   `make3()`返回一个字符串；`make3curried()`返回另一个函数--它本身返回*第二*个函数，然后返回*第三*个函数，最终返回一个字符串！

+   您可以通过编写类似`make3(1,2,4)`的东西来生成一个字符串，它返回 124，但是您将不得不编写`make3curried(1)(2)(4)`来获得相同的结果

为什么要费这么大的劲呢？让我们看一个简单的例子，然后我们将看到更多的例子。假设您有一个计算增值税（VAT）的函数：

```js
const addVAT = (rate, amount) => amount * (1 + rate / 100);
addVAT(20, 500); // 600 -- *that is,* 500 + 20%
addVAT(15, 200); // 230 -- 200 +15%
```

如果您必须应用单一的恒定费率，那么您可以对`addVAT()`函数进行柯里化，以生成一个更专业的版本，它总是应用您给定的费率。例如，如果您的国家税率是 6%，那么您可以有以下内容：

```js
const addVATcurried = rate => amount => amount * (1 + rate / 100);
const addNationalVAT = addVATcurried(6);
addNationalVAT(1500); // 1590 -- 1500 + 6%
```

第一行定义了我们的增值税计算函数的柯里化版本。给定一个税率，`addVATcurried()`返回一个新函数，当给定一定金额的钱时，最终将原始税率加到其中。因此，如果国家税率为 6%，那么`addNationalVAT()`将是一个函数，它会给任何给定的金额增加 6%。例如，如果我们要计算`addNationalVAT(1500)`，就像前面的代码一样，结果将是 1590：1500 美元，再加上 6%的税。

当然，你可能会认为这种柯里化对于只增加 6%的税来说有点过分，但简化才是最重要的。让我们看一个例子。在您的应用程序中，您可能希望包含一些日志记录，例如以下函数：

```js
let myLog = (severity, logText) => {
 // *display logText in an appropriate way,*
 // *according to its severity ("NORMAL", "WARNING", or "ERROR")*
};
```

然而，采用这种方法，每次您想要显示一个正常的日志消息时，您将写`myLog`(`"NORMAL"`, "一些正常文本")，而对于警告，您将写`myLog`(`"WARNING"`, "一些警告")--但您可以通过柯里化简化一下，通过固定`myLog()`的第一个参数，如下所示，使用我们稍后将看到的`curry()`函数：

```js
myLog = curry(myLog);
// *replace myLog by a curried version of itself*

const myNormalLog = myLog("NORMAL");
const myWarningLog = myLog("WARNING");
const myErrorLog = myLog("ERROR");
```

你得到了什么？现在你可以只写`myNormalLog("一些正常文本")`或`myWarningLog("一些警告")`，因为你已经对`myLog()`进行了柯里化，然后固定了它的参数--这使得代码更简单，更易读！

顺便说一句，如果您愿意，您也可以通过逐个案例地对原始的非柯里化`myLog()`函数进行柯里化来以单个步骤实现相同的结果：

```js
const myNormalLog2 = curry(myLog)("NORMAL");
const myWarningLog2 = curry(myLog)("WARNING");
const myErrorLog2 = curry(myLog)("ERROR");
```

# 手动柯里化

如果我们只想为特殊情况实现柯里化，就没有必要做任何复杂的事情，因为我们可以使用简单的箭头函数来处理：我们看到了`make3curried()`和`addVATcurried()`都是如此，所以没有必要重新审视这个想法。

相反，让我们看一些自动执行这些操作的方法，这样我们将能够生成任何函数的等效柯里化版本，即使事先不知道它的 arity。更进一步，我们可能希望编写一个函数的更智能版本，它可以根据接收到的参数数量而有所不同。例如，我们可以有一个`sum(x,y)`函数，它的行为如下例所示：

```js
sum(3, 5); // 8; *did you expect otherwise?*

const add2 = sum(2);
add2(3); // 5

sum(2)(7); // 9 -- *as if it were curried*
```

我们可以手动实现这种行为。我们的函数将是以下内容：

```js
const sum = (x, y) => {
 if (x !== undefined && y !== undefined) {
 return x + y;
 } else if (x !== undefined && y == undefined) {
 return z => sum(x, z);
 } else {
 return sum;
 }
};
```

让我们回顾一下我们在这里做了什么。我们手动柯里化的函数有以下行为：

+   如果我们用两个参数调用它，它会将它们相加，并返回总和；这提供了我们的第一个用例，就像`sum(3,5)==8`一样。

+   如果只提供一个参数，它将返回一个新函数。这个新函数期望一个参数，并将返回该参数和原始参数的总和：这种行为是我们在其他两种用例中所期望的，比如`add2(3)==5`或`sum(2)(7)==9`。

+   最后，如果没有提供参数，它将返回自身。这意味着我们可以写`sum()(1)(2)`如果我们愿意。（不，我想不出想要写那个的原因...）

因此，如果我们愿意，我们可以在函数的定义中直接包含柯里化。然而，您必须同意，必须在每个函数中处理所有特殊情况，这很容易变得麻烦，也容易出错。因此，让我们尝试找出一些更通用的方法来实现相同的结果，而不需要任何特定的编码。

# 使用 bind()进行柯里化

我们可以通过使用`.bind()`方法找到柯里化的解决方案。这使我们能够固定一个参数（或更多，如果需要；我们现在不需要，但以后会用到），并提供具有固定参数的函数。当然，许多库（如 Lodash、Underscore、Ramda 等）提供了这种功能，但我们想看看如何自己实现。

在[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_objects/Function/bind`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_objects/Function/bind)上阅读更多关于`.bind()`的内容--这将很有用，因为我们将在本章中多次利用这个方法。

我们的实现非常简短，但需要一些解释：

```js
const curryByBind = fn =>
 fn.length === 0 ? fn() : p => curryByBind(fn.bind(null, p));
```

首先注意到`curry()`总是返回一个新函数，该函数取决于作为其参数给定的函数`fn`。如果函数没有（更多）剩余参数（当`fn.length===0`时），因为所有参数已经被固定，我们可以通过执行`fn()`来简单评估它。否则，柯里化函数的结果将是一个新函数，它接收一个参数，并产生一个新的柯里化函数，其中另一个参数被固定。让我们通过一个详细的例子来看看这个过程，再次使用我们在本章开头看到的`make3()`函数：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);

const f1 = curryByBind(make3); // *f1 is a function, that will fix make3's 1st parameter*
const f2 = f1(6); // *f2 is a function, that will fix make3's 2nd parameter*
const f3 = f2(5); // *f3 is a function, that will fix make3's last parameter*
const f4 = f3(8); // *"658" is calculated, since there are no more parameters to fix*
```

这段代码的解释如下：

+   第一个函数`f1()`还没有接收任何参数。它的结果是一个单参数函数，它本身将产生`make3()`的柯里化版本，其第一个参数固定为给定的值。

+   调用`f1(6)`会产生一个新的一元函数`f2()`，它本身将产生`make3()`的柯里化版本--但其第一个参数设置为`6`，因此实际上新函数将结束固定`make3()`的第二个参数。

+   类似地，调用`f2(5)`会产生第三个一元函数`f3()`，它将产生`make3()`的一个版本，但固定其第三个参数，因为前两个参数已经被固定。

+   最后，当我们计算`f3(8)`时，这将把`make3()`的最后一个参数固定为`8`，并且由于没有更多的参数了，三次绑定的`make3()`函数被调用，产生结果`"658"`。

如果您想手动进行函数柯里化，可以使用 JavaScript 的`.bind()`方法。顺序如下：

```js
const step1 = make3.bind(null, 6);
const step2 = step1.bind(null, 5);
const step3 = step2.bind(null, 8);
step3(); // *"658"*
```

在每一步中，我们提供一个进一步的参数。（需要`null`值来提供上下文。如果它是附加到对象的方法，我们将该对象作为`.bind()`的第一个参数提供。由于这不是这种情况，所以期望是`null`。）这相当于我们的代码所做的事情，唯一的例外是最后一次，`curryByBind()`执行实际计算，而不是让您自己来做，就像`step3()`中一样。

测试这个转换相当简单--因为柯里化的可能方式并不多！

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);

describe("with curryByBind", function() {
 it("you fix arguments one by one", () => {
 const make3a = curryByBind(make3);
 const make3b = make3a(1)(2);
 const make3c = make3b(3);
 expect(make3c).toBe(make3(1, 2, 3));
 });
});
```

还有什么可以测试的吗？也许可以添加只有一个参数的函数，但没有更多可以尝试的了。

如果我们想对具有可变参数数量的函数进行柯里化，那么使用`fn.length`是行不通的；它只对具有固定参数数量的函数有值。我们可以通过提供所需的参数数量来简单解决这个问题：

```js
const curryByBind2 = (fn, len = fn.length) =>
 len === 0 ? fn() : p => curryByBind2(fn.bind(null, p), len - 1);

const sum2 = (...args) => args.reduce((x, y) => x + y, 0);
sum2.length; // *0;* *curryByBind() wouldn't work*

sum2(1, 5, 3); // 9
sum2(1, 5, 3, 7); // 16
sum2(1, 5, 3, 7, 4); // 20

curriedSum5 = curryByBind2(sum2, 5); // *curriedSum5 will expect 5 parameters*
curriedSum5(1)(5)(3)(7)(4); // *20*
```

新的`curryByBind2()`函数与以前的工作方式相同，但是不再依赖于`fn.length`，而是使用`len`参数，该参数默认为`fn.length`，用于具有恒定参数数量的标准函数。请注意，当`len`不为 0 时，返回的函数调用`curry2()`，并将`len-1`作为其最后一个参数--这是有道理的，因为如果一个参数刚刚被固定，那么剩下要固定的参数就会少一个。

在我们的例子中，`sum()`函数可以处理任意数量的参数，JavaScript 告诉我们`sum.length`为零。然而，当对函数进行柯里化时，如果我们将`len`设置为`5`，柯里化将被视为`sum()`是一个五参数函数--代码中列出的最后一行显示这确实是这种情况。

与之前一样，测试是相当简单的，因为我们没有要尝试的变体：

```js
const sum2 = (...args) => args.reduce((x, y) => x + y, 0);

describe("with curryByBind2", function() {
 it("you fix arguments one by one", () => {
 const suma = curryByBind2(sum2, 5);
 const sumb = suma(1)(2)(3)(4)(5);
 expect(sumb).toBe(sum(1, 2, 3, 4, 5));
 });

 it("you can also work with arity 1", () => {
 const suma = curryByBind2(sum2, 1);
 const sumb = suma(111);
 expect(sumb).toBe(sum(111));
 });
});
```

我们测试了将柯里化函数的 arity 设置为 1，作为边界情况，但没有更多的可能性。

# 使用 eval()进行柯里化

还有一种有趣的柯里化函数的方法，通过使用`eval()`创建一个新的函数... 是的，那个不安全的、危险的`eval()`！（记住我们之前说过的：这是为了学习目的，但最好避免`eval()`可能带来的潜在安全问题！）我们还将使用我们在第五章的*使用范围*部分编写的`range()`函数，*声明式编程-更好的风格*。

像 LISP 这样的语言一直都有生成和执行 LISP 代码的可能性。JavaScript 也共享了这一功能，但并不经常使用--主要是因为可能带来的危险！然而，在我们的情况下，由于我们想要生成新的函数，利用这种被忽视的能力似乎是合乎逻辑的。

这个想法很简单：在本章的*一点理论*部分中，我们看到我们可以通过使用箭头函数轻松地柯里化一个函数：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);

const make3curried = a => b => c => String(100 * a + 10 * b + c);
```

让我们对第二个版本进行一些更改，以便以后能更好地帮助我们：

```js
const make3curried = x1 => x2 => x3 => make3(x1, x2, x3);
```

生成等效版本所需的代码如下。我们将使用我们在第五章的*使用范围*部分编写的`range()`函数，以避免需要编写显式循环：

```js
const range = (start, stop) =>
 new Array(stop - start).fill(0).map((v, i) => start + i);

const curryByEval = (fn, len = fn.length) =>
 eval(`**${range(0, len).map(i => `x${i}`).join("=>")}** **=> 
 ${fn.name}(${range(0, len).map(i => `x${i}`).join(",")})**`);
```

这是相当多的代码需要消化，实际上，它应该被编码成几行分开来更容易理解。让我们以`make3()`函数作为输入来跟随它：

+   `range()`函数生成一个值为`[0,1,2]`的数组。如果我们不提供`len`参数，将使用`make3.length`（即 3）。

+   我们使用`.map()`生成一个包含值`["x0","x1","x2"]`的新数组。

+   我们使用`join()`将该数组中的值连接起来，生成`x0=>x1=>x2`，这将是我们将要`eval()`的代码的开头。

+   然后我们添加一个箭头，函数的名称和一个开括号，以使我们新生成的代码的中间部分：`=> make3(`。

+   我们再次使用`range()`、`map()`和`join()`，但这次是为了生成参数列表：`x0,x1,x2`。

+   最后我们添加一个闭括号，并在应用`eval()`之后，我们得到了`make3()`的柯里化版本：

```js
curryByEval(make3); // x0=>x1=>x2=> make3(x0,x1,x2)
```

只有一个问题：如果原始函数没有名称，转换就无法进行。（有关更多信息，请查看第三章的*关于 Lambda 和函数*部分，*从函数开始-核心概念*。）我们可以通过包含要柯里化的函数的实际代码来解决函数名称问题：

```js
const curryByEval2 = (fn, len = fn.length) =>
 eval(`${range(0, len).map(i => `x${i}`).join("=>")} => 
 **(${fn.toString()})**(${range(0, len).map(i => `x${i}`).join(",")})`);
```

唯一的变化是，我们用实际的代码替换原始函数名：

```js
curryByEval2(make3); // x0=>x1=>x2=> ((a,b,c) => 100*a+10*b+c)(x0,x1,x2)
```

生成的函数令人惊讶，有一个完整的函数后跟其参数--但这实际上是有效的 JavaScript！所有以下都会产生相同的结果：

```js
const add = (x, y) => x + y;
add(2, 5); // 7
((x, y) => x + y)(2, 5); // *7*
```

当你想调用一个函数时，你写下它，并在括号内跟上它的参数--这就是我们正在做的，即使看起来有点奇怪！

# 部分应用

我们将要考虑的第二个转换允许你固定函数的一些参数，创建一个接收其余参数的新函数。让我们通过一个无意义的例子来澄清这一点。想象一下，你有一个有五个参数的函数。你可能想要固定第二个和第五个参数，部分应用将产生一个新版本的函数，固定这两个参数，但为新的调用留下其他三个。如果你用这三个必需的参数调用结果函数，它将使用原始的两个固定参数加上新提供的三个参数产生正确的答案。

在函数应用中只指定一些参数，生成剩余参数的函数的想法被称为*投影*：你被认为是*投影*函数到剩余的参数上。我们不会使用这个术语，但我们想引用一下，以防你在其他地方找到它。

让我们考虑一个例子，使用被广泛认为是现代 Ajax 调用的`fetch()` API。你可能想要获取多个资源，总是指定调用的相同参数（例如请求头），只改变搜索的 URL。因此，通过部分应用，你可以创建一个新的`myFetch()`函数，它总是提供固定的参数。假设我们有一个实现这种应用的`partial()`函数，看看我们如何使用它。

你可以在[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)上了解更多关于`fetch()`的信息。根据[`caniuse.com/#search=fetch`](http://caniuse.com/#search=fetch)的信息，你可以在大多数浏览器中使用它，除了（哦，惊讶！）Internet Explorer...但你可以通过 polyfill 绕过这个限制，比如在[`github.com/github/fetch`](https://github.com/github/fetch)找到的 polyfill：

```js
const myParameters = {
 method: "GET",
 headers: new Headers(),
 cache: "default"
};

const myFetch = partial(fetch, undefined, myParameters);
// *undefined means the first argument for fetch is not yet defined*
// *the second argument for fetch() is set to myParameters*

myFetch("a/first/url").then(/* do something */).catch(/* on error */);
myFetch("a/second/url")
 .then(/* do something else */)
 .catch(/* on error */);
```

如果请求参数是`fetch()`的第一个参数，柯里化就会起作用。（我们稍后会详细讨论参数的顺序。）通过部分应用，你可以替换任何参数，所以在这种情况下，`myFetch()`最终成为一个一元函数。这个新函数将从任何你希望的 URL 获取数据，始终传递相同的参数集合进行`GET`操作。

# 箭头函数的部分应用

手动进行部分应用，就像我们用柯里化一样，太复杂了，因为对于一个有五个参数的函数，你需要编写代码，允许用户提供 32 种可能的固定和未固定参数的组合（32 等于 5 的 2 次方），即使你可以简化问题，编写和维护仍然很困难。见图 7.2：

图 7.2。部分应用可能让你首先提供一些参数，然后提供其余的参数，最终得到结果。

然而，使用箭头函数进行部分应用要简单得多。对于上面提到的例子，我们会有以下代码。在这种情况下，我们假设我们想要将第二个参数固定为 22，第五个参数固定为 1960：

```js
const nonsense = (a, b, c, d, e) => `${a}/${b}/${c}/${d}/${e}`;

const fix2and5 = (a, c, d) => nonsense(a, 22, c, d, 1960);
```

以这种方式进行部分应用是相当简单的，尽管我们可能想找到一个更一般的解决方案。你可以固定任意数量的参数，你所做的就是从之前的函数中创建一个新函数，但固定了更多的参数。例如，你现在可能还想将新的`fix2and5()`函数的最后一个参数固定为 9；没有比这更容易的了！

```js
const fixLast = (a, c) => fix2and5(a, c, 9);
```

如果你愿意，你也可以写成`nonsense(a, 22, c, 9, 1960)`，但事实仍然是，使用箭头函数固定参数是简单的。现在让我们考虑一个更一般的解决方案。

# 使用 eval()进行部分应用

如果我们想要能够部分应用固定任意组合的参数，我们必须有一种方法来指定哪些参数将被保留，哪些将从那一点开始被固定。一些库，比如 Underscore 或 LoDash，使用一个特殊对象 `_` 来表示省略的参数。以这种方式，仍然使用相同的 `nonsense()` 函数，我们将编写以下内容：

```js
const fix2and5 = _.partial(nonsense, _, 22, _, _, 1960);
```

我们可以通过使用一个全局变量来表示一个待处理的、尚未固定的参数来做同样的事情，但让我们简化一下，只需写 `undefined` 来表示缺少的参数。

在检查未定义时，记得始终使用 `===` 运算符；使用 `==` 会导致 `null==undefined`，你不希望出现这种情况。请参阅 [`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/undefined`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/undefined) 了解更多信息。

我们想要编写一个函数，部分应用一些参数，并将其余部分留给未来。我们想要编写类似以下的代码，并以与我们之前使用箭头函数相同的方式生成一个新函数：

```js
const nonsense = (a, b, c, d, e) => `${a}/${b}/${c}/${d}/${e}`;

const fix2and5 = partialByEval(
 nonsense,
 undefined,
 22,
 undefined,
 undefined,
 1960
);
// *fix2and5 would become* (X0, X2, X3) => nonsense(X0, 22, X2, X3, 1960);
```

我们可以回到使用 `eval()`，并想出类似以下的东西：

```js
const range = (start, stop) =>
 new Array(stop - start).fill(0).map((v, i) => start + i);

const partialByEval = (fn, ...args) => {
 const rangeArgs = range(0, fn.length);
 const leftList = rangeArgs
 .map(v => (args[v] === undefined ? `x${v}` : null))
 .filter(v => !!v)
 .join(",");
 const rightList = rangeArgs
 .map(v => (args[v] === undefined ? `x${v}` : args[v]))
 .join(",");
 return eval(`(${leftList}) => ${fn.name}(${rightList})`);
};
```

让我们一步一步地分解这个函数。我们再次使用我们的 `range()` 函数：

+   `rangeArgs` 是一个包含从零到输入函数的参数数量（不包括）的数字的数组。

+   `leftList` 是一个字符串，表示未应用变量的列表。在我们的例子中，它将是 `"X0,X2,X3"`，因为我们为第二个和第五个参数提供了值。这个字符串将用于生成箭头函数的左部分。

+   `rightList` 是一个字符串，表示调用提供的函数的参数列表。在我们的例子中，它将是 `"X0,'Z',X2,X3,1960"`。我们将使用这个字符串来生成箭头函数的右部分。

在生成了两个列表之后，代码的剩余部分只是生成适当的字符串，并将其传递给 `eval()` 以获得一个函数。

如果我们对具有可变数量参数的函数进行部分应用，我们可以用 `args.length` 替换 `fn.length`，或者提供一个额外的（可选的）参数来指定要使用的数量，就像我们在本章的柯里化部分所做的那样。

顺便说一句，我故意用这种冗长的方式来表达这个函数，以使其更清晰。（我们之前已经看到了类似的，虽然更短的代码，当我们使用 `eval()` 进行柯里化时。）然而，请注意，你可能会找到一个更短、更紧凑和更难理解的版本……这就是给函数式编程带来不好名声的代码！

```js
const partialByEval2 = (fn, ...args) =>
 eval(
 `(${range(0, fn.length)
 .map(v => (args[v] === undefined ? `x${v}` : null))
 .filter(v => !!v)
 .join(",")}) => ${fn.name}(${range(0, fn.length)
 .map(v => (args[v] == undefined ? `x${v}` : args[v]))
 .join(",")})`
 );
```

让我们通过编写一些测试来结束这一部分。我们应该考虑一些什么事情？

+   当我们进行部分应用时，生成的函数的参数个数应该减少。

+   当参数按正确顺序传入时，应该调用原始函数。

我们可以编写类似以下的代码，允许在不同位置固定参数。我们可以直接使用 `nonsense()` 函数，而不是使用间谍或模拟，因为它非常高效：

```js
const nonsense = (a, b, c, d, e) => `${a}/${b}/${c}/${d}/${e}`;

describe("with partialByEval()", function() {
 it("you could fix no arguments", () => {
 const nonsensePC0 = partialByEval(nonsense);
 expect(nonsensePC0.length).toBe(5);
 expect(nonsensePC0(0, 1, 2, 3, 4)).toBe(nonsense(0, 1, 2, 3, 4));
 });

 it("you could fix only some initial arguments", () => {
 const nonsensePC1 = partialByEval(nonsense, 1, 2, 3);
 expect(nonsensePC1.length).toBe(2);
 expect(nonsensePC1(4, 5)).toBe(nonsense(1, 2, 3, 4, 5));
 });

 it("you could skip some arguments", () => {
 const nonsensePC2 = partialByEval(
 nonsense,
 undefined,
 22,
 undefined,
 44
 );
 expect(nonsensePC2.length).toBe(3);
 expect(nonsensePC2(11, 33, 55)).toBe(nonsense(11, 22, 33, 44, 55));
 });

 it("you could fix only some last arguments", () => {
 const nonsensePC3 = partialByEval(
 nonsense,
 undefined,
 undefined,
 undefined,
 444,
 555
 );
 expect(nonsensePC3.length).toBe(3);
 expect(nonsensePC3(111, 222, 333)).toBe(
 nonsense(111, 222, 333, 444, 555)
 );
 });

 it("you could fix ALL the arguments", () => {
 const nonsensePC4 = partialByEval(nonsense, 6, 7, 8, 9, 0);
 expect(nonsensePC4.length).toBe(0);
 expect(nonsensePC4()).toBe(nonsense(6, 7, 8, 9, 0));
 });
});
```

我们编写了一个部分应用的高阶函数，但它并不像我们希望的那样灵活。例如，我们可以在第一次调用中固定一些参数，但然后我们必须在下一次调用中提供所有其余的参数。如果在调用 `partialByEval()` 后，我们得到一个新函数，并且如果我们没有提供所有需要的参数，我们将得到另一个函数，以此类推，直到所有参数都被提供——这与柯里化的情况有些类似。因此，让我们改变部分应用的方式，并考虑另一个解决方案。

# 使用闭包进行部分应用

让我们再看一种进行部分应用的方式，它的行为方式有点像我们在本章前面写的`curry()`函数，并解决了我们在上一节末尾提到的不足：

```js
const partialByClosure = (fn, ...args) => {
 const partialize = (...args1) => (...args2) => {
 for (let i = 0; i < args1.length && args2.length; i++) {
 if (args1[i] === undefined) {
 args1[i] = args2.shift();
 }
 }
 const allParams = [...args1, ...args2];
 return (allParams.includes(undefined) ||
 allParams.length < fn.length
 ? partialize
 : fn)(...allParams);
 };

 return partialize(...args);
};
```

哇，一大段代码！关键在于内部函数`partialize()`。给定一个参数列表（`args1`），它生成一个接收第二个参数列表（`args2`）的函数：

+   首先，它用`args2`中的值替换`args1`中所有可能的未定义值。

+   然后，如果`args2`中还有任何参数，它也会将它们附加到`args1`的参数中，生成`allParams`。

+   最后，如果参数列表中不再包含任何未定义值，并且足够长，它就会调用原始函数。

+   否则，它会部分化自身，等待更多的参数。

举个例子会更清楚。让我们回到我们可靠的`make3()`函数，并构建它的一个部分版本：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);
const f1 = partialByClosure(make3, undefined, 4);
```

现在我们写一个第二个函数：

```js
const f2 = f1(7);
```

发生了什么？原始参数列表（`[undefined, 4]`）与新列表（在这种情况下是一个单一元素，`[7]`）合并，生成一个现在接收`7`和`4`作为它的前两个参数的函数。然而，这还不够，因为原始函数需要三个参数。如果我们现在写：

```js
const f3 = f2(9);
```

然后，当前的参数列表将与新参数合并，生成`[7,4,9]`。由于列表现在是完整的，原始函数将被评估，产生`749`作为最终结果。

这段代码的结构与我们之前在*使用`bind()`进行柯里化*部分写的另一个高阶函数有重要的相似之处。

+   如果所有参数都已经提供，原始函数就会被调用。

+   如果还需要一些参数（在柯里化时，只是简单地计算参数的数量；在进行部分应用时，你还必须考虑可能存在一些未定义的参数），那么高阶函数会调用自身来生成函数的新版本，这个新版本将*等待*缺失的参数。

让我们最后写一些测试，展示我们新的部分应用方式的增强。基本上，我们之前做的所有测试都会生效，但我们还必须尝试按顺序应用参数，这样我们应该在两个或更多步骤的应用之后得到最终结果。然而，由于我们现在可以用任意数量的参数调用我们的中间函数，我们无法测试参数个数：对于所有函数，`function.length===0`：

```js
describe("with partialByClosure()", function() {
 it("you could fix no arguments", () => {
 const nonsensePC0 = partialByClosure(nonsense);
 expect(nonsensePC0(0, 1, 2, 3, 4)).toBe(nonsense(0, 1, 2, 3, 4));
 });

 it("you could fix only some initial arguments, and then some more", () => {
 const nonsensePC1 = partialByClosure(nonsense, 1, 2, 3);
 const nonsensePC1b = nonsensePC1(undefined, 5);
 expect(nonsensePC1b(4)).toBe(nonsense(1, 2, 3, 4, 5));
 });

 it("you could skip some arguments", () => {
 const nonsensePC2 = partialByClosure(
 nonsense,
 undefined,
 22,
 undefined,
 44
 );
 expect(nonsensePC2(11, 33, 55)).toBe(nonsense(11, 22, 33, 44, 55));
 });

 it("you could fix only some last arguments", () => {
 const nonsensePC3 = partialByClosure(
 nonsense,
 undefined,
 undefined,
 undefined,
 444,
 555
 );
 expect(nonsensePC3(111)(222, 333)).toBe(
 nonsense(111, 222, 333, 444, 555)
 );
 });

 it("you could simulate currying", () => {
 const nonsensePC4 = partialByClosure(nonsense);
 expect(nonsensePC4(6)(7)(8)(9)(0)).toBe(nonsense(6, 7, 8, 9, 0));
 });

 it("you could fix ALL the arguments", () => {
 const nonsensePC5 = partialByClosure(nonsense, 16, 17, 18, 19, 20);
 expect(nonsensePC5()).toBe(nonsense(16, 17, 18, 19, 20));
 });
});
```

代码比以前长了，但测试本身很容易理解。倒数第二个测试应该会让你想起柯里化！

# 部分柯里化

最后一个我们将看到的转换是柯里化和部分应用的混合。如果你在网上搜索一下，在一些地方你会发现它被称为*柯里化*，在其他地方被称为*部分应用*，但事实上，它都不太符合……所以我还在犹豫不决，称它为*部分柯里化*！

这个想法是，给定一个函数，固定它的前几个参数，并生成一个新的函数来接收其余的参数。然而，如果给这个新函数传递的参数较少，它将固定它所接收到的参数，并生成一个新的函数来接收其余的参数，直到所有参数都被给出并且最终结果可以被计算出来。参见图 7.3：

图 7.3。"部分柯里化"是柯里化和部分应用的混合。你可以提供任意数量的参数，直到所有参数都被提供，然后计算结果。

为了举例说明，让我们回到我们在之前部分中一直在使用的`nonsense()`函数。假设我们已经有了一个`partialCurry()`函数：

```js
const nonsense = (a, b, c, d, e) => `${a}/${b}/${c}/${d}/${e}`;

const pcNonsense = partialCurry(nonsense);
const fix1And2 = pcNonsense(9, 22); // fix1And2 is now a ternary function
const fix3 = fix1And2(60); // fix3 is a binary function
const fix4and5 = fix3(12, 4); // fix4and5 === nonsense(9,22,60,12,4), "9/22/60/12/4"
```

原始函数的参数个数为 5。当我们*部分柯里化*该函数，并给它参数 9 和 22 时，它变成了一个三元函数，因为在原始的五个参数中，有两个已经固定。如果我们拿到这个三元函数并给它一个参数（60），结果就是另一个函数：在这种情况下，是一个二元函数，因为现在我们已经固定了原始五个参数中的前三个。最后一次调用，提供最后两个参数，然后执行实际计算所需的结果。

柯里化和部分应用有一些共同点，但也有一些不同之处：

+   原始函数被转换为一系列函数，每个函数产生下一个函数，直到系列中的最后一个实际执行其计算。

+   您始终从第一个参数（最左边的参数）开始提供参数，就像柯里化一样，但您可以像部分应用一样提供多个参数。

+   在柯里化函数时，所有中间函数都是一元的，但部分柯里化则不需要如此。然而，如果在每个实例中我们提供一个参数，那么结果将需要与普通柯里化一样多的步骤。

所以，我们有了我们的定义--现在让我们看看如何实现我们的新高阶函数；我们可能会在本章的这一部分中重复使用前几节中的一些概念。

# 使用 bind()进行部分柯里化

与我们对柯里化所做的类似，有一种简单的方法可以进行部分柯里化。我们将利用`.bind()`实际上可以一次固定多个参数的事实：

```js
const partialCurryingByBind = fn =>
 fn.length === 0
 ? fn()
 : (...pp) => partialCurryingByBind(**fn.bind(null, ...pp)**);
```

将代码与之前的`curryByBind()`函数进行比较，您会看到非常小的差异：

```js
const curryByBind = fn =>
 fn.length === 0 
 ? fn() 
 : p => curryByBind(fn.bind(null, p));
```

机制完全相同。唯一的区别是在我们的新函数中，我们可以同时绑定多个参数，而在`curryByBind()`中我们总是只绑定一个。我们可以重新访问我们之前的例子--唯一的区别是我们可以在更少的步骤中得到最终结果：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);

const f1 = partialCurryingByBind(make3);
const f2 = f1(6, 5); // *f2 is a function, that fixes make3's first two arguments*
const f3 = f2(8); // *"658" is calculated, since there are no more parameters to fix*
```

顺便说一句，只要意识到现有的可能性，您可以在柯里化时固定一些参数：

```js
const g1 = partialCurryingByBind(make3)(8, 7);
const g2 = g1(6); // "876"
```

测试这个函数很容易，我们提供的例子是一个很好的起点。但是，请注意，由于我们允许固定任意数量的参数，我们无法测试中间函数的参数个数：

```js
const make3 = (a, b, c) => String(100 * a + 10 * b + c);

describe("with partialCurryingByBind", function() {
 it("you could fix arguments in several steps", () => {
 const make3a = partialCurryingByBind(make3);
 const make3b = make3a(1, 2);
 const make3c = make3b(3);
 expect(make3c).toBe(make3(1, 2, 3));
 });

 it("you could fix arguments in a single step", () => {
 const make3a = partialCurryingByBind(make3);
 const make3b = make3a(10, 11, 12);
 expect(make3b).toBe(make3(10, 11, 12));
 });

 it("you could fix ALL the arguments", () => {
 const make3all = partialCurryingByBind(make3);
 expect(make3all(20, 21, 22)).toBe(make3(20, 21, 22));
 });

 it("you could fix one argument at a time", () => {
 const make3one = partialCurryingByBind(make3)(30)(31)(32);
 expect(make3one).toBe(make3(30, 31, 32));
 });
});
```

现在，让我们考虑具有可变参数数量的函数。与以前一样，我们将不得不提供额外的值：

```js
const partialCurryingByBind2 = (fn, len = fn.length) =>
    len === 0
 ? fn()
 : (...pp) =>
 partialCurryingByBind2(
 fn.bind(null, ...pp),
                  len - pp.length
 );
```

我们可以以一种简单的方式尝试这一点，重新访问一些页面前的柯里化示例：

```js
const sum = (...args) => args.reduce((x, y) => x + y, 0);

pcSum5 = partialCurryingByBind2(sum2, 5); // curriedSum5 will expect 5 parameters
pcSum5(1, 5)(3)(7, 4); // 20
```

新的`pcSum5()`函数首先收集了两个参数（1,5），并产生了一个期望另外三个参数的新函数。给定了一个单一参数（3），并创建了第三个函数，等待最后两个参数。当提供了这两个参数（7,4）时，原始函数被调用，计算结果为（20）。

我们还可以为这种替代的部分柯里化添加一些测试：

```js
const sum2 = (...args) => args.reduce((x, y) => x + y, 0);

describe("with partialCurryingByBind2", function() {
 it("you could fix arguments in several steps", () => {
 const suma = partialCurryingByBind2(sum2, 3);
 const sumb = suma(1, 2);
 const sumc = sumb(3);
 expect(sumc).toBe(sum2(1, 2, 3));
 });

 it("you could fix arguments in a single step", () => {
 const suma = partialCurryingByBind2(sum2, 4);
 const sumb = suma(10, 11, 12, 13);
 expect(sumb).toBe(sum(10, 11, 12, 13));
 });

 it("you could fix ALL the arguments", () => {
 const sumall = partialCurryingByBind2(sum2, 5);
 expect(sumall(20, 21, 22, 23, 24)).toBe(sum2(20, 21, 22, 23, 24));
 });

 it("you could fix one argument at a time", () => {
 const sumone = partialCurryingByBind2(sum2, 6)(30)(31)(32)(33)(34)(
 35
 );
 expect(sumone).toBe(sum2(30, 31, 32, 33, 34, 35));
 });
});
```

尝试不同的参数个数比坚持只使用一个更好，所以我们为了多样性而这样做了。

# 使用闭包进行部分柯里化

与部分应用一样，有一种使用闭包的解决方案：

```js
const partialCurryByClosure = fn => {
 const curryize = (...args1) => (...args2) => {
 const allParams = [...args1, ...args2];
 return (allParams.length < func.length ? curryize : fn)(
 ...allParams
 );
 };
 return curryize();
};
```

如果您比较`partialCurryByClosure()`和`partialByClosure()`，主要区别在于部分柯里化，因为我们总是从左边提供参数，没有办法跳过一些参数，您将之前的任何参数与新参数连接起来，并检查是否已经足够。如果新的参数列表达到了原始函数的预期参数个数，您可以调用它，并得到最终结果。在其他情况下，您只需使用`curryize()`来获得一个新的中间函数，等待更多的参数。

与以前一样，如果您必须处理具有不同数量参数的函数，您可以为部分柯里化函数提供额外的参数：

```js
const partialCurryByClosure2 = (fn, len = fn.length) => {
 const curryize = (...args1) => (...args2) => {
 const allParams = [...args1, ...args2];
 return (allParams.length < len ? curryize : fn)(...allParams);
 };
 return curried();
};
```

结果与上一节的*通过 bind 进行部分柯里化*完全相同，因此不值得重复。您还可以轻松地更改我们编写的测试，使用`partialCurryByClosure()`而不是`partialCurryByBind()`，它们也可以正常工作。

# 最后的想法

让我们以两个更多的关于柯里化和部分应用的哲学考虑来结束这一章，这可能会引起一些讨论：

+   首先，许多库在参数顺序上都是错误的，使它们更难使用

+   其次，我通常甚至不使用本章中的高阶函数，而是使用更简单的 JS 代码！

这可能不是您此时所期望的，所以让我们更详细地讨论这两点，这样您就会看到这不是*我说什么，我做什么*或*库所做的*的问题！

# 参数顺序

不仅如此，这个问题不仅存在于 Underscore 或 LoDash 的`_.map(list, mappingFunction)`或`_.reduce(list, reducingFunction, initialValue)`等函数中，还存在于我们在本书中生成的一些函数中，比如`demethodize()`的结果。 （请参阅第六章的*Demethodizing: turning methods into functions*部分，以回顾高阶函数。）问题在于它们的参数*顺序*并不能真正帮助柯里化。

在柯里化函数时，您可能希望存储中间结果。当我们像下面的代码一样做某事时，我们假设您将重用带有固定参数的柯里化函数，这意味着原始函数的第一个参数最不可能改变。现在让我们考虑一个具体的情况。回答这个问题：更可能的是——您将使用`map()`将相同的函数应用于几个不同的数组，还是将几个不同的函数应用于相同的数组？对于验证或转换，前者更有可能……但这并不是我们得到的结果！

我们可以编写一个简单的函数来翻转二元函数的参数：

```js
const flipTwo = fn => (p1, p2) => fn(p2, p1);
```

请注意，即使原始的`fn()`函数可以接收更多或更少的参数，但在将`flipTwo()`应用于它之后，结果函数的 arity 将固定为 2。我们将在接下来的部分中利用这一事实。

有了这个，您可以按照以下方式编写代码：

```js
const myMap = curry(flipTwo(demethodize(map)));
const makeString = v => String(v);

const stringify = myMap(makeString);
let x = stringify(anArray);
let y = stringify(anotherArray);
let z = stringify(yetAnotherArray);
```

最常见的使用情况是您希望将函数应用于几个不同的列表，无论是库函数还是我们自己的*demethodized*函数都无法提供这种功能。然而，通过使用`flipTwo()`，我们可以按照我们希望的方式工作。

在这种特殊情况下，我们可能已经通过使用部分应用来解决了我们的问题，而不是柯里化，因为这样我们就可以固定`map()`的第二个参数而不需要进一步的麻烦。然而，翻转参数以产生具有不同参数顺序的新函数也是一种经常使用的技术，我认为你应该意识到这一点很重要。

对于像`.reduce()`这样通常接收三个参数（列表、函数和初始值）的情况，我们可以选择这样做：

```js
const flip3 = fn => (p1, p2, p3) => fn(p2, p3, p1);

const myReduce = partialCurry(flip3(demethodize(reduce)));
const sum = (x, y) => x + y;

const sumAll = myReduce(sum, 0);
sumAll(anArray);
sumAll(anotherArray);
```

我使用了部分柯里化，简化了`sumAll()`的表达式。另一种选择是使用常规柯里化，然后我会定义`sumAll = myReduce(sum)(0)`。

如果您愿意，您也可以选择更神秘的参数重新排列函数，但通常您不需要更多的这两种。对于真正复杂的情况，您可能更愿意使用箭头函数（就像我们在定义`flipTwo()`和`flip3()`时所做的那样），并明确说明您需要哪种重新排序。

# 功能性

现在我们接近本章的结束，有一个坦白的话要说：我并不总是像上面所示的那样使用柯里化和部分应用！不要误会我，我确实应用这些技术 -- 但有时它会导致更长、不太清晰、不一定更好的代码。让我向您展示我在说什么。

如果我正在编写自己的函数，然后想要对其进行柯里化以固定第一个参数，与箭头函数相比，柯里化（或部分应用，或部分柯里化）并不真的有什么区别。我将不得不编写以下内容：

```js
const myFunction = (a, b, c) => { ... };
const myCurriedFunction = curry(myFunction)(fixed_first_argument);

// *and later in the code...*
myCurriedFunction(second_argument)(third_argument);
```

柯里化函数，并在同一行给它一个第一个参数，可能被认为不太清晰；另一种调用需要一个额外的变量和一行代码。稍后，未来的调用也不太好；然而，部分柯里化使它更简单：`myPartiallyCurriedFunction(second_argument, third_argument)`。无论如何，当我将最终代码与箭头函数的使用进行比较时，我认为其他解决方案并不真的更好：

```js
const myFunction = (a, b, c) => { ... };
const myFixedFirst = (b, c) => myFunction(fixed_first_argument, b, c);

// *and later...*
myFixedFirst(second_argument, third_argument);
```

我认为柯里化和部分应用非常好的地方在于我的小型库中的去方法化、预柯里化的基本高阶函数。我有自己的一组函数，如下所示：

```js
const _plainMap = demethodize(map);
const myMap = curry(_plainMap, 2);
const myMapX = curry(flipTwo(_plainMap));

const _plainReduce = demethodize(reduce);
const myReduce = curry(_plainReduce, 3);
const myReduceX = curry(flip3(_plainReduce));

const _plainFilter = demethodize(filter);
const myFilter = curry(_plainFilter, 2);
const myFilterX = curry(flipTwo(_plainFilter));

// *...and more functions in the same vein*
```

以下是有关代码的一些要点：

+   我将这些函数放在一个单独的模块中，并且只导出`myXXX()`命名的函数。

+   其他函数是私有的，我使用前导下划线来提醒我这一点。

+   我使用`my...`前缀来记住这些是*我的*函数，而不是正常的 JavaScript 函数。有些人可能更愿意保留标准名称，如`map()`或`filter()`，但我更喜欢不同的名称。

+   由于大多数 JavaScript 方法具有可变的 arity，我在进行柯里化时必须指定它。

+   我总是为`.reduce()`提供第三个参数（用于减少的初始值），因此我为该函数选择的 arity 是三。

+   当对翻转函数进行柯里化时，您不需要指定参数的数量，因为翻转已经为您做到了。

最终，这完全取决于个人决定；尝试本章中所见的技术，并看看您更喜欢哪些！

# 问题

7.1\. **随心所欲地求和**。以下练习将帮助您理解我们上面讨论的一些概念，即使您在不使用我们在本章中看到的任何函数的情况下解决它。编写一个`sumMany()`函数，让您以以下方式对不定数量的数字求和。请注意，当不带参数调用该函数时，将返回总和：

```js
 let result = sumMany((9)(2)(3)(1)(4)(3)());
 // *22*
```

7.2\. **时尚工作**。编写一个`applyStyle()`函数，让您以以下方式对字符串应用基本样式。使用柯里化或部分应用：

```js
 const makeBold = applyStyle("b");
 document.getElementById("myCity").innerHTML = 
 makeBold("Montevideo");
 // <b>Montevideo</b>, *to produce* Montevideo

 const makeUnderline = applyStyle("u");
 document.getElementById("myCountry").innerHTML = 
 makeUnderline("Uruguay");
 // <u>Uruguay</u>, *to produce* Uruguay
```

7.3\. **原型柯里化**。修改`Function.prototype`以提供一个`.curry()`方法，该方法将像我们在文本中看到的`curry()`函数一样工作。完成下面的代码应该产生以下结果：

```js
 Function.prototype.curry = function() {
 // ...*your code goes here...*
 };

 const sum3 = (a, b, c) => 100 * a + 10 * b + c;
 sum3.curry()(1)(2)(4); // *124*

 const sum3C = sum3.curry()(2)(2);
 sum3C(9); // *229*
```

7.4\. **取消柯里化**。编写一个函数`unCurry(fn,arity)`，它接收一个（柯里化的）函数和其预期的 arity 作为参数，并返回`fn()`的一个非柯里化版本；也就是说，一个将接收*n*个参数并产生结果的函数。（提供预期的 arity 是必要的，因为您无法自行确定它。）

```js
 const make3 = (a, b, c) => String(100 * a + 10 * b + c);

 const make3c = curry(make3);
 console.log(make3c(1)(2)(3)); // 123

 const remake3 = uncurry(make3c, 3);
 console.log(remake3(1, 2, 3)); // 123
```

# 总结

在本章中，我们考虑了一种新的生成函数的方式，即通过多种不同的方式固定现有函数的参数：柯里化，一种理论方式；部分应用，更灵活；以及部分柯里化，结合了前两种方法的优点。使用这些转换，您可以简化编码，因为您可以生成更专门的通用函数版本，而无需任何麻烦。

在第八章中，*连接函数 - 管道和组合*，我们将回顾一些我们在纯函数章节中看到的概念，并考虑确保函数不会因为意外变得*不纯*的方法，通过寻找使它们的参数不可变的方式，使它们不可能被改变。
