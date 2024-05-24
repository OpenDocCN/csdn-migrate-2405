# 精通 JavaScript（二）

> 原文：[`zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3`](https://zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章．数据结构与操作

在编程中你花费大部分时间做的事情是操作数据。你处理数据的属性，根据数据得出结论，改变数据的本性。在本章中，我们将详细介绍 JavaScript 中的各种数据结构和数据操作技术。正确使用这些表达式结构，你的程序将会是正确的、简洁的、易于阅读的，并且很有可能是更快的。这将在以下主题帮助下解释：

+   正则表达式

+   精确匹配

+   从字符类中匹配

+   重复出现

+   开始和结束

+   反向引用

+   贪婪与懒惰量词

+   数组

+   映射

+   集合

+   风格问题

# 正则表达式

如果你不熟悉正则表达式，我建议你花时间去学习它们。有效地学习和使用正则表达式是你会获得的最有价值的技能之一。在大多数代码审查会议中，我首先评论的是如何将一段代码转换成单个正则表达式（或 RegEx）的行。如果你研究流行的 JavaScript 库，你会惊讶地看到正则表达式的普遍性。大多数经验丰富的工程师主要依赖正则表达式，因为一旦你知道如何使用它们，它们就是简洁且易于测试的。然而，学习正则表达式将需要大量的精力和时间。正则表达式是表达匹配文本字符串的模式的方法。表达式本身由术语和操作符组成，使我们能够定义这些模式。我们很快就会看到这些术语和操作符由什么组成。

在 JavaScript 中，创建正则表达式有两种方法：通过正则表达式字面量和使用`RegExp`对象实例化。

例如，如果我们想要创建一个正好匹配字符串 test 的正则表达式，我们可以使用以下正则表达式字面量：

```js
var pattern = /test/;
```

正则表达式字面量使用斜杠分隔。或者，我们可以构造一个`RegExp`实例，将正则表达式作为字符串传递：

```js
var pattern = new RegExp("test");
```

这两种格式都会在变量 pattern 中创建相同的正则表达式。除了表达式本身，还有三个标志可以与正则表达式关联：

+   `i`：这使正则表达式不区分大小写，所以`/test/i`不仅匹配`test`，还匹配`Test`、`TEST`、`tEsT`等。

+   `g`：这与默认的局部匹配相反，后者只匹配第一个出现。稍后会有更多介绍。

+   `m`：这允许跨多行匹配，这可能来自`textarea`元素的值。

这些标志在字面量末尾附加（例如，`/test/ig`）或作为字符串传递给`RegExp`构造器的第二个参数（`new RegExp("test", "ig")`）。

以下示例说明了各种标志以及它们如何影响模式匹配：

```js
var pattern = /orange/;
console.log(pattern.test("orange")); // true

var patternIgnoreCase = /orange/i;
console.log(patternIgnoreCase.test("Orange")); // true

var patternGlobal = /orange/ig;
console.log(patternGlobal.test("Orange Juice")); // true
```

如果我们只能测试模式是否与一个字符串匹配，那就没什么意思了。让我们看看如何表达更复杂的模式。

# 精确匹配

任何不是特殊正则字符或运算符的连续字符都代表一个字符字面量：

```js
var pattern = /orange/;
```

我们的意思是`o`后面跟着`r`，后面跟着`a`，后面跟着`n`，后面跟着……—你应该明白了。当我们使用正则表达式时，我们很少使用精确匹配，因为那就像是比较两个字符串。精确匹配模式有时被称为简单模式。

# 从一类字符中匹配

如果你想匹配一组字符，你可以在`[]`里放置这一组字符。例如，`[abc]`就意味着任何字符`a`、`b`或`c`：

```js
var pattern = /[abc]/;
console.log(pattern.test('a')); //true
console.log(pattern.test('d')); //false
```

你可以指定想匹配除模式以外的任何内容，通过在模式的开头添加一个`^`（感叹号）来实现：

```js
var pattern = /[^abc]/;
console.log(pattern.test('a')); //false
console.log(pattern.test('d')); //true
```

这个模式的一个关键变体是值的范围。如果我们想匹配一系列连续的字符或数字，我们可以使用以下的模式：

```js
var pattern = /[0-5]/;
console.log(pattern.test(3)); //true
console.log(pattern.test(12345)); //true
console.log(pattern.test(9)); //false
console.log(pattern.test(6789)); //false
console.log(/[0123456789]/.test("This is year 2015")); //true
```

特殊字符，比如`$`和`.`，要么代表与自身以外的匹配，要么是修饰前面项的运算符。实际上，我们已经看到了`[`, `]`, `-`, 和`^`字符如何用来表示它们字面值以外的含义。

那么我们如何指定想匹配一个字面`[`或`$`或`^`或其他特殊字符呢？在正则表达式中，反斜杠字符转义它后面的任何字符，使其成为一个字面匹配项。所以`\[`指定了一个对`[`字符的精确匹配，而不是字符类表达式的开始。双反斜杠（`\\`）匹配一个单反斜杠。

在前面的例子中，我们看到了`test()`方法，它基于匹配到的模式返回`true`或`false`。有时你想访问特定模式的各个出现。在这种情况下，`exec()`方法就派上用场了。

`exec()`方法接收一个字符串作为参数，返回一个包含所有匹配项的数组。考虑以下例子：

```js
var strToMatch = 'A Toyota! Race fast, safe car! A Toyota!'; 
var regExAt = /Toy/;
var arrMatches = regExAt.exec(strToMatch); 
console.log(arrMatches);
```

```js
['Toy']; if you want all the instances of the pattern Toy, you can use the g (global) flag as follows:
```

```js
var strToMatch = 'A Toyota! Race fast, safe car! A Toyota!'; 
var regExAt = /Toy/g;
var arrMatches = regExAt.exec(strToMatch); 
console.log(arrMatches);
```

这将返回原文中所有单词`oyo`的出现。String 对象包含`match()`方法，其功能与`exec()`方法类似。在 String 对象上调用`match()`方法，把正则表达式作为参数传给它。考虑以下例子：

```js
var strToMatch = 'A Toyota! Race fast, safe car! A Toyota!'; 
var regExAt = /Toy/;
var arrMatches = strToMatch.match(regExAt);
console.log(arrMatches);
```

在这个例子中，我们在 String 对象上调用`match()`方法。我们把正则表达式作为参数传给`match()`方法。这两种情况的结果是一样的。

另一个 String 对象的方法是`replace()`。它用一个不同的字符串替换所有子字符串的出现：

```js
var strToMatch = 'Blue is your favorite color ?'; 
var regExAt = /Blue/;
console.log(strToMatch.replace(regExAt, "Red"));
//Output- "Red is your favorite color ?"
```

你可以把一个函数作为`replace()`方法的第二个参数。`replace()`函数把匹配到的文本作为参数，并返回用作替换的文本：

```js
var strToMatch = 'Blue is your favorite color ?'; 
var regExAt = /Blue/;
console.log(strToMatch.replace(regExAt, function(matchingText){
  return 'Red';
}));
//Output- "Red is your favorite color ?"
```

字符串对象的`split()`方法也接受一个正则表达式参数，并返回一个包含在原字符串分割后生成的所有子字符串的数组：

```js
var sColor = 'sun,moon,stars';
var reComma = /\,/;
console.log(sColor.split(reComma));
//Output - ["sun", "moon", "stars"]
```

我们需要在逗号之前加上反斜杠，因为正则表达式中逗号有特殊含义，如果我们想直接使用它，就需要转义它。

使用简单的字符类，你可以匹配多个模式。例如，如果你想匹配`cat`、`bat`和`fat`，以下片段展示了如何使用简单的字符类：

```js
var strToMatch = 'wooden bat, smelly Cat,a fat cat';
var re = /[bcf]at/gi;
var arrMatches = strToMatch.match(re);
console.log(arrMatches);
//["bat", "Cat", "fat", "cat"]
```

正如你所看到的，这种变化打开了编写简洁正则表达式模式的可能性。看下面的例子：

```js
var strToMatch = 'i1,i2,i3,i4,i5,i6,i7,i8,i9';
var re = /i[0-5]/gi;
var arrMatches = strToMatch.match(re);
console.log(arrMatches);
//["i1", "i2", "i3", "i4", "i5"]
```

在这个例子中，我们匹配匹配字符的数字部分，范围为`[0-5]`，因此我们从`i0`得到匹配到`i5`。您还可以使用否定类`^`过滤其余的匹配：

```js
var strToMatch = 'i1,i2,i3,i4,i5,i6,i7,i8,i9';
var re = /i[⁰-5]/gi;
var arrMatches = strToMatch.match(re);
console.log(arrMatches);
//["i6", "i7", "i8", "i9"]
```

注意我们是如何只否定范围子句而不是整个表达式的。

几个字符组有快捷方式。例如，快捷方式`\d`与`[0-9]`相同：

| 表示法 | 意义 |
| --- | --- |
| `\d` | 任何数字字符 |
| `\w` | 字母数字字符（单词字符） |
| `\s` | 任何空白字符（空格、制表符、换行符等） |
| `\D` | 非数字字符 |
| `\W` | 非字母数字字符 |
| `\S` | 非空白字符 |
| `.` | 除换行符外的任何字符 |

这些快捷方式在编写简洁的正则表达式中很有价值。考虑这个例子：

```js
var strToMatch = '123-456-7890';
var re = /[0-9][0-9][0-9]-[0-9][0-9][0-9]/;
var arrMatches = strToMatch.match(re);
console.log(arrMatches);
//["123-456"]
```

这个表达式看起来确实有点奇怪。我们可以用`\d`替换`[0-9]`，使这变得更易读：

```js
var strToMatch = '123-456-7890';
var re = /\d\d\d-\d\d\d/;
var arrMatches = strToMatch.match(re);
console.log(arrMatches);
//["123-456"]
```

然而，你很快就会看到还有更好的方法来这样做。

# 重复出现

到目前为止，我们看到了如何匹配固定字符或数字模式。大多数时候，你希望处理模式的某些重复特性。例如，如果我想要匹配 4 个`a`，我可以写`/aaaa/`，但如果我想指定一个可以匹配任意数量`a`的模式呢？

正则表达式为您提供了各种重复量词。重复量词让我们指定特定模式可以出现的次数。我们可以指定固定值（字符应出现 *n* 次）和变量值（字符可以出现至少 *n* 次，直到它们出现 *m* 次）。以下表格列出了各种重复量词：

+   `?`: 要么出现 0 次要么出现 1 次（将出现标记为可选）

+   `*`: 0 或多个出现

+   `+`: 1 或多个出现

+   `{n}`: 正好 `n` 次出现

+   `{n,m}`: 在 `n` 和 `m` 之间的出现

+   `{n,}`: 至少出现 `n` 次

+   `{,n}`: 0 到 `n` 次出现

在以下示例中，我们创建一个字符`u`可选（出现 0 或 1 次）的模式：

```js
var str = /behaviou?r/;
console.log(str.test("behaviour"));
// true
console.log(str.test("behavior"));
// true
```

把`/behaviou?r/`表达式看作是 0 或 1 次字符`u`的出现有助于阅读。重复量词 succeeds 了我们想要重复的字符。让我们尝试一些更多例子：

```js
console.log(/'\d+'/.test("'123'")); // true
```

你应该读取并解释`\d+`表达式，就像`'`是字面字符匹配，`\d`匹配字符`[0-9]`，`+`量词将允许一个或多个出现，而`'`是字面字符匹配。

您还可以使用`()`对字符表达式进行分组。观察以下示例：

```js
var heartyLaugh = /Ha+(Ha+)+/i;
console.log(heartyLaugh.test("HaHaHaHaHaHaHaaaaaaaaaaa"));
//true
```

让我们把前面的表达式分解成更小的块，以了解这里发生了什么：

+   `H`：字面字符匹配

+   `a+`：字符`a`的一个或多个出现

+   `(`：表达式组的开始

+   `H`：字面字符匹配

+   `a+`：字符`a`的一个或多个出现

+   `)`：表达式组的结束

+   `+`：表达式组（`Ha+`）的一个或多个出现

现在更容易看出分组是如何进行的。如果我们必须解释表达式，有时读出表达式是有帮助的，如前例所示。

通常，你想匹配一组字母或数字本身，而不仅仅是作为子字符串。当你匹配的词不是其他任何词的一部分时，这是一个相当常见的用例。我们可以通过使用`\b`模式来指定单词边界。`\b`的单词边界匹配一侧是单词字符（字母、数字或下划线）而另一侧不是的位置。考虑以下示例。

以下是一个简单的字面匹配。如果`cat`是子字符串的一部分，这个匹配也会成功：

```js
console.log(/cat/.test('a black cat')); //true
```

然而，在下面的示例中，我们通过在单词`cat`前标示`\b`来定义一个单词边界——这意味着我们只想匹配`cat`作为一个单词而不是一个子字符串。边界是在`cat`之前建立的，因此在文本`a black cat`中找到了匹配项：

```js
console.log(/\bcat/.test('a black cat')); //true
```

当我们对单词`tomcat`使用相同的边界时，我们得到一个失败的匹配，因为在单词`tomcat`中`cat`之前没有单词边界：

```js
console.log(/\bcat/.test('tomcat')); //false
```

在单词`tomcat`中，`cat`之后有一个单词边界，因此以下是一个成功的匹配：

```js
console.log(/cat\b/.test('tomcat')); //true
```

在以下示例中，我们在单词`cat`的前后都定义了单词边界，以表示我们想要`cat`作为一个有前后边界的独立单词：

```js
console.log(/\bcat\b/.test('a black cat')); //true
```

基于相同逻辑，以下匹配失败，因为在单词`concatenate`中`cat`前后的边界不存在：

```js
console.log(/\bcat\b/.test("concatenate")); //false
```

`exec()`方法在获取关于找到匹配的信息方面很有用，因为它返回一个包含关于匹配的信息的对象。`exec()`返回的对象有一个`index`属性，告诉我们成功匹配在字符串中的开始位置。这在许多方面都是有用的：

```js
var match = /\d+/.exec("There are 100 ways to do this");
console.log(match);
// ["100"]
console.log(match.index);
// 10
```

## 替代方案——或

使用`|`（管道）字符可以表示替代方案。例如，`/a|b/`匹配`a`或`b`字符，而`/(ab)+|(cd)+/`匹配`ab`或`cd`的一个或多个出现。

# 开始和结束

经常，我们可能希望确保模式在字符串的开始处或 perhaps 在字符串的结束处匹配。当正则表达式的第一个字符是井号时（`^`），它将匹配固定在字符串的开始处，例如`/^test/`仅当`test`子字符串出现在要匹配的字符串的开头时才匹配。同样，美元符号（`$`）表示模式必须出现在字符串的末尾：`/test$/`。

使用`^`和`$`指示指定的模式必须包含整个候选字符串：`/^test$/`。

# 反向引用

在表达式计算之后，每个组都存储起来以供以后使用。这些值称为反向引用。反向引用通过从左到右遇到左括号字符的顺序创建并编号。你可以将反向引用视为与正则表达式中的项成功匹配的字符串的部分。

引用后缀的表示方法是一个反斜杠，后面跟着要引用的捕获组的编号，从 1 开始，例如`\1`、`\2`等等。

一个例子可能是`/^([XYZ])a\1/`，它匹配一个以`X`、`Y`或`Z`中的任何一个字符开头，后面跟着一个`a`，再后面跟着与第一个捕获组匹配的任何字符的字符串。这与`/[XYZ] a[XYZ]/`非常不同。`a`后面的字符不能是`X`、`Y`或`Z`中的任何一个，而必须是触发第一个字符匹配的那个。反向引用用于字符串的`replace()`方法，使用特殊字符序列`$1`、`$2`等等。假设你想把`1234 5678`字符串改为`5678 1234`。以下代码实现此功能：

```js
var orig = "1234 5678";
var re = /(\d{4}) (\d{4})/;
var modifiedStr = orig.replace(re, "$2 $1"); 
console.log(modifiedStr); //outputs "5678 1234" 
```

在这个例子中，正则表达式有两个组，每个组都有四个数字。在`replace()`方法的第二个参数中，`$2`等于`5678`，`$1`等于`1234`，对应于它们在表达式中出现的顺序。

# 贪婪与懒惰量词

我们迄今为止讨论的所有量词都是贪婪的。一个贪婪的量词从整个字符串开始寻找匹配。如果没有找到匹配，它会删除字符串中的最后一个字符并重新尝试匹配。如果没有再次找到匹配，它将再次删除最后一个字符，并重复这个过程，直到找到匹配或者字符串剩下没有字符。

例如，`\d+`模式将匹配一个或多个数字。例如，如果你的字符串是`123`，贪婪匹配将匹配`1`、`12`和`123`。贪婪模式`h`.`+l`将在字符串`hello`中匹配`hell`—这是可能的最长字符串匹配。由于`\d+`是贪婪的，它会尽可能多地匹配数字，因此匹配将是`123`。

与贪婪量词相比，懒惰量词尽可能少地匹配量词化的令牌。你可以在正则表达式中添加一个问号（`?`）使其变得懒惰。一个懒惰的模式`h.?l`将在字符串`hello`中匹配`hel`—这是可能的最短字符串。

`\w*?X`模式将匹配零个或多个单词，然后匹配一个`X`。然而，在`*`后面的问号表示应该尽可能少地匹配字符。对于字符串`abcXXX`，匹配可以是`abcX`、`abcXX`或`abcXXX`。哪一个应该被匹配？由于`*?`是懒惰的，尽可能少地匹配字符，因此匹配是`abcX`。

有了这些必要的信息，让我们尝试使用正则表达式解决一些常见问题。

从字符串的开始和结束去除多余的空格是一个非常常见的用例。由于字符串对象直到最近才有一个`trim()`方法，因此一些 JavaScript 库为没有`String.trim()`方法的旧浏览器提供并使用了字符串截取的实现。最常用的方法看起来像下面的代码：

```js
function trim(str) {
  return (str || "").replace(/^\s+|\s+$/g, "");
}
console.log("--"+trim("   test    ")+"--");
//"--test--"
```

如果我们想用一个空格替换重复的空格怎么办？

```js
re=/\s+/g;
console.log('There are    a lot      of spaces'.replace(re,' '));
//"There are a lot of spaces"
```

```js
As you can see, regular expressions can prove to be a Swiss army knife in your JavaScript arsenal. Careful study and practice will be extremely rewarding for you in the long run.
```

# 数组

数组是一个有序的值集合。你可以用一个名字和索引来引用数组元素。以下是 JavaScript 中创建数组的三个方法：

```js
var arr = new Array(1,2,3);
var arr = Array(1,2,3);
var arr = [1,2,3];
```

当这些值被指定时，数组初始化为这些值作为数组的元素。数组的`length`属性等于参数的数量。方括号语法称为数组字面量。这是一种更简短且更推荐的方式来初始化数组。

如果你想初始化一个只有一个元素且该元素碰巧是数字的数组，你必须使用数组字面量语法。如果你将一个单一的数字值传递给`Array()`构造函数或函数，JavaScript 将这个参数视为数组的长度，而不是单个元素：

```js
var arr = [10];
var arr = Array(10); // Creates an array with no element, but with arr.length set to 10
// The above code is equivalent to
var arr = [];
arr.length = 10;
```

JavaScript 没有显式的数组数据类型。然而，你可以使用预定义的`Array`对象及其方法来处理应用程序中的数组。`Array`对象有各种方式操作数组的方法，如连接、反转和排序它们。它有一个属性来确定数组长度和其他用于正则表达式的属性。

你可以通过给它的元素赋值来填充一个数组：

```js
var days = [];
days[0] = "Sunday";
days[1] = "Monday";
```

你也可以在创建数组时填充它：

```js
var arr_generic = new Array("A String", myCustomValue, 3.14);
var fruits = ["Mango", "Apple", "Orange"]
```

在大多数语言中，数组的元素都必须是同一类型。JavaScript 允许数组包含任何类型的值：

```js
var arr = [
  'string', 42.0, true, false, null, undefined,
  ['sub', 'array'], {object: true}, NaN
]; 
```

你可以使用元素的索引号码来引用`Array`的一个元素。例如，假设你定义了以下数组：

```js
var days = ["Sunday", "Monday", "Tuesday"]
```

然后你将数组的第一个元素称为`colors[0]`，第二个元素称为`colors[1]`。元素的索引从`0`开始。

JavaScript 内部将数组元素作为标准对象属性存储，使用数组索引作为属性名。`length`属性是不同的。`length`属性总是返回最后一个元素索引加一。正如我们讨论的，JavaScript 数组索引是基于 0 的：它们从`0`开始，而不是`1`。这意味着`length`属性将是数组中存储的最高索引加一：

```js
var colors = [];
colors[30] = ['Green'];
console.log(colors.length); // 31
```

你还可以赋值给`length`属性。如果写入的值比存储的项目数少，数组就会被截断；写入`0`则会清空它：

```js
var colors = ['Red', 'Blue', 'Yellow'];
console.log(colors.length); // 3
colors.length = 2;
console.log(colors); // ["Red","Blue"] - Yellow has been removed
colors.length = 0;
console.log(colors); // [] the colors array is empty
colors.length = 3;
console.log(colors); // [undefined, undefined, undefined]
```

如果你查询一个不存在的数组索引，你会得到`undefined`。

一个常见的操作是遍历数组的值，以某种方式处理每一个值。这样做最简单的方式如下：

```js
var colors = ['red', 'green', 'blue']; 
for (var i = 0; i < colors.length; i++) { 
  console.log(colors[i]); 
}
```

`forEach()` 方法提供了另一种遍历数组的方式：

```js
var colors = ['red', 'green', 'blue'];
colors.forEach(function(color) {
  console.log(color);
});
```

传递给 `forEach()` 的函数对数组中的每个项目执行一次，将数组项目作为函数的参数传递。在 `forEach()` 循环中不会遍历未赋值的值。

`Array` 对象有一组实用的方法。这些方法允许操作数组中存储的数据。

`concat()` 方法将两个数组合并成一个新数组：

```js
var myArray = new Array("33", "44", "55");
myArray = myArray.concat("3", "2", "1"); 
console.log(myArray);
// ["33", "44", "55", "3", "2", "1"]
```

`join()` 方法将数组的所有元素合并成一个字符串。这在处理列表时可能很有用。默认的分隔符是逗号 (`,`)：

```js
var myArray = new Array('Red','Blue','Yellow');
var list = myArray.join(" ~ "); 
console.log(list);
//"Red ~ Blue ~ Yellow"
```

`pop()` 方法从数组中移除最后一个元素，并返回该元素。这与栈的 `pop()` 方法类似：

```js
var myArray = new Array("1", "2", "3");
var last = myArray.pop(); 
// myArray = ["1", "2"], last = "3"
```

`push()` 方法向数组的末尾添加一个或多个元素，并返回数组的结果长度：

```js
var myArray = new Array("1", "2");
myArray.push("3"); 
// myArray = ["1", "2", "3"]
```

`shift()` 方法从数组中移除第一个元素，并返回该元素：

```js
var myArray = new Array ("1", "2", "3");
var first = myArray.shift(); 
// myArray = ["2", "3"], first = "1"
```

`unshift()` 方法向数组的开头添加一个或多个元素，并返回数组的新长度：

```js
var myArray = new Array ("1", "2", "3");
myArray.unshift("4", "5"); 
// myArray = ["4", "5", "1", "2", "3"]
```

`reverse()` 方法反转或转置数组的元素——第一个数组元素变为最后一个，最后一个变为第一个：

```js
var myArray = new Array ("1", "2", "3");
myArray.reverse(); 
// transposes the array so that myArray = [ "3", "2", "1" ]
```

`sort()` 方法对数组的元素进行排序：

```js
var myArray = new Array("A", "C", "B");
myArray.sort(); 
// sorts the array so that myArray = [ "A","B","c" ]
```

`sort()` 方法可以接受一个回调函数作为可选参数，以定义元素如何进行比较。该函数比较两个值并返回三个值之一。让我们研究以下函数：

+   `indexOf(searchElement[, fromIndex])`：此方法在数组中搜索 `searchElement` 并返回第一个匹配项的索引：

    ```js
    var a = ['a', 'b', 'a', 'b', 'a','c','a'];
    console.log(a.indexOf('b')); // 1
    // Now try again, starting from after the last match
    console.log(a.indexOf('b', 2)); // 3
    console.log(a.indexOf('1')); // -1, 'q' is not found
    ```

+   `lastIndexOf(searchElement[, fromIndex])`：此方法类似于 `indexOf()`，但只从后向前搜索：

    ```js
    var a = ['a', 'b', 'c', 'd', 'a', 'b'];
    console.log(a.lastIndexOf('b')); //  5
    // Now try again, starting from before the last match
    console.log(a.lastIndexOf('b', 4)); //  1
    console.log(a.lastIndexOf('z')); //  -1
    ```

既然我们已经深入讲解了 JavaScript 数组，那么让我向您介绍一个名为 **Underscore.js** 的绝佳库（[`underscorejs.org/`](http://underscorejs.org/)）。Underscore.js 提供了一系列极其有用的函数编程助手，使您的代码更加清晰和功能化。

我们假设您熟悉**Node.js**；在这种情况下，通过 npm 安装 Underscore.js：

```js
npm install underscore
```

由于我们正在将 Underscore 作为 Node 模块进行安装，因此我们将通过在 Node.js 上运行 `.js` 文件来输入所有示例。您也可以使用 **Bower** 安装 Underscore。

类似于 jQuery 的 `$` 模块，Underscore 带有一个 `_` 模块的定义。您将使用这个模块引用调用所有函数。

将以下代码输入文本文件并命名为 `test_.js`：

```js
var _ = require('underscore');
function print(n){
  console.log(n);
}
_.each([1, 2, 3], print);
//prints 1 2 3
```

以下是不使用 underscore 库中的 `each()` 函数的写法：

```js
var myArray = [1,2,3];
var arrayLength = myArray.length;
for (var i = 0; i < arrayLength; i++) {
  console.log(myArray[i]);
}
```

这里所展示的是一个强大的功能性结构，使代码更加优雅和简洁。你可以明显看出传统方法是冗长的。像 Java 这样的许多语言都受到这种冗长的影响。它们正在逐渐接受函数式编程范式。作为 JavaScript 程序员，我们尽可能地将这些思想融入到我们的代码中是非常重要的。

前面例子中看到的`each()`函数遍历元素列表，依次将每个元素传递给迭代函数。每次迭代函数调用时，都会传入三个参数（元素、索引和列表）。在前面的例子中，`each()`函数遍历数组`[1,2,3]`，对于数组中的每个元素，`print`函数都会被调用，并传入数组元素作为参数。这是访问数组中所有元素的方便方法，代替传统的循环机制。

`range()`函数创建整数列表。如果省略起始值，默认为`0`，步长默认为`1`。如果你想要一个负范围，使用负步长：

```js
var _ = require('underscore');
console.log(_.range(10));
// [0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ]
console.log(_.range(1, 11));
//[ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ]
console.log(_.range(0, 30, 5));
//[ 0, 5, 10, 15, 20, 25 ]
console.log(_.range(0, -10, -1));
//[ 0, -1, -2, -3, -4, -5, -6, -7, -8, -9 ]
console.log(_.range(0));
//[]
```

默认情况下，`range()`用整数填充数组，但用一点小技巧，你也可以用其他数据类型填充：

```js
console.log(_.range(3).map(function () { return 'a' }) );
[ 'a', 'a', 'a' ]
```

这是一种快速方便的方法来创建和初始化一个带有值的数组。我们经常通过传统循环来做这件事。

`map()`函数通过映射每个列表中的值到一个转换函数，生成一个新的值数组。考虑以下示例：

```js
var _ = require('underscore');
console.log(_.map([1, 2, 3], function(num){ return num * 3; }));
//[3,6,9]
```

`reduce()`函数将一个值列表减少到一个单一的值。初始状态由迭代函数传递，每个连续步骤由迭代函数返回。以下示例展示了使用方法：

```js
var _ = require('underscore');
var sum = _.reduce([1, 2, 3], function(memo, num){console.log(memo,num);return memo + num; }, 0);
console.log(sum);
```

在这个例子中，`console.log(memo,num);`这行代码只是为了更清楚地说明想法。输出结果如下：

```js
0 1
1 2
3 3
6
```

最终输出是`*1+2+3=6*`的和。正如你所见，两个值被传递到迭代函数中。在第一次迭代中，我们调用迭代函数并传入两个值`(0,1)`——`memo`在调用`reduce()`函数时的默认值是`0`，`1`是列表的第一个元素。在函数中，我们计算`memo`和`num`的和并返回中间的`sum`，这个`sum`将被`iterate()`函数作为`memo`参数使用——最终，`memo`将累积`sum`。理解这个概念对于了解如何使用中间状态来计算最终结果很重要。

`filter()`函数遍历整个列表，返回满足条件的所有元素的数组。看看下面的例子：

```js
var _ = require('underscore');
var evens = _.filter([1, 2, 3, 4, 5, 6], function(num){ return num % 2 == 0; });
console.log(evens);
```

`filter()`函数的迭代函数应该返回一个真值。结果的`evens`数组包含所有满足真值测试的元素。

`filter()`函数的反义词是`reject()`。正如名字 suggest，它遍历列表并忽略满足真值测试的元素：

```js
var _ = require('underscore');
var odds = _.reject([1, 2, 3, 4, 5, 6], function(num){ return num % 2 == 0; });
console.log(odds);
//[ 1, 3, 5 ]
```

我们使用了与上一个例子相同的代码，但这次用`reject()`方法而不是`filter()`——结果正好相反。

`contains()`函数是一个有用的小函数，如果值在列表中，就返回`true`；否则，返回`false`：

```js
var _ = require('underscore');
console.log(_.contains([1, 2, 3], 3));
//true
```

一个非常实用的函数，我已经喜欢上了，就是 `invoke()`。它在列表中的每个元素上调用一个特定的函数。我无法告诉你自从偶然发现它以来我使用了多少次。让我们研究以下示例：

```js
var _ = require('underscore');
console.log(_.invoke([[5, 1, 7], [3, 2, 1]], 'sort'));
//[ [ 1, 5, 7 ], [ 1, 2, 3 ] ]
```

在这个例子中，`Array` 对象的 `sort()` 方法被应用于数组中的每个元素。注意这将失败：

```js
var _ = require('underscore');
console.log(_.invoke(["new","old","cat"], 'sort'));
//[ undefined, undefined, undefined ]
```

这是因为 `sort` 方法不是字符串对象的一部分。然而，这完全有效：

```js
var _ = require('underscore');
console.log(_.invoke(["new","old","cat"], 'toUpperCase'));
//[ 'NEW', 'OLD', 'CAT' ]
```

这是因为 `toUpperCase()` 是字符串对象的方法，列表中的所有元素都是字符串类型。

`uniq()` 函数返回去除原始数组所有重复项后的数组：

```js
var _ = require('underscore');
var uniqArray = _.uniq([1,1,2,2,3]);
console.log(uniqArray);
//[1,2,3]
```

`partition()` 函数将数组分成两部分；一部分是满足谓词的元素，另一部分是不满足谓词的元素：

```js
var _ = require('underscore');
function isOdd(n){
  return n%2==0;
}
console.log(_.partition([0, 1, 2, 3, 4, 5], isOdd));
//[ [ 0, 2, 4 ], [ 1, 3, 5 ] ]
```

```js
[1,2,3]—this is a helpful method to eliminate any value from a list that can cause runtime exceptions.
```

`without()` 函数返回一个删除特定值所有实例的数组副本：

```js
var _ = require('underscore');
console.log(_.without([1,2,3,4,5,6,7,8,9,0,1,2,0,0,1,1],0,1,2));
//[ 3, 4, 5, 6, 7, 8, 9 ]
```

# 映射（Maps）

```js
Map type and their usage:
```

```js
var founders = new Map();
founders.set("facebook", "mark");
founders.set("google", "larry");
founders.size; // 2
founders.get("twitter"); // undefined
founders.has("yahoo"); // false

for (var [key, value] of founders) {
  console.log(key + " founded by " + value);
}
// "facebook founded by mark"
// "google founded by larry"
```

# 集合

ECMAScript 6 引入了集合。集合是值的集合，并且可以按照它们的元素插入顺序进行迭代。关于集合的一个重要特征是，集合中的值只能出现一次。

以下代码片段展示了集合的一些基本操作：

```js
var mySet = new Set();
mySet.add(1);
mySet.add("Howdy");
mySet.add("foo");

mySet.has(1); // true
mySet.delete("foo");
mySet.size; // 2

for (let item of mySet) console.log(item);
// 1
// "Howdy"
```

我们简要讨论过，JavaScript 数组并不是真正意义上的数组。在 JavaScript 中，数组是具有以下特征的对象：

+   `length` 属性

+   继承自 `Array.prototype` 的函数（我们将在下一章讨论这个）

+   对数字键的特殊处理

当我们写数组索引作为数字时，它们会被转换为字符串——`arr[0]` 内部变成了 `arr["0"]`。由于这一点，当我们使用 JavaScript 数组时，我们需要注意一些事情：

+   通过索引访问数组元素并不是一个常数时间操作，比如在 C 语言中。因为数组实际上是键值映射，访问将取决于映射的布局和其他因素（冲突等）。

+   JavaScript 数组是稀疏的（大多数元素都有默认值），这意味着数组中可能会有间隙。为了理解这一点，看看以下代码片段：

    ```js
    var testArr=new Array(3);
    console.log(testArr); 
    ```

    你会看到输出是 `[undefined, undefined, undefined]`——`undefined` 是数组元素存储的默认值。

考虑以下示例：

```js
var testArr=[];
testArr[3] = 10;
testArr[10] = 3;
console.log(testArr);
// [undefined, undefined, undefined, 10, undefined, undefined, undefined, undefined, undefined, undefined, 3]
```

你可以看到这个数组中有间隙。只有两个元素有值，其余的都是使用默认值填充的间隙。了解这一点可以帮助你避免一些问题。使用 `for...in` 循环迭代数组可能会导致意外的结果。考虑以下示例：

```js
var a = [];
a[5] = 5;
for (var i=0; i<a.length; i++) {
  console.log(a[i]);
}
// Iterates over numeric indexes from 0 to 5
// [undefined,undefined,undefined,undefined,undefined,5]

for (var x in a) {
  console.log(x);
}
// Shows only the explicitly set index of "5", and ignores 0-4
```

# 风格问题

和前面章节一样，我们将花些时间讨论创建数组时的风格考虑。

+   使用字面量语法创建数组：

    ```js
    // bad
    const items = new Array();
    // good
    const items = [];
    ```

+   使用 `Array#push` 而不是直接赋值来向数组中添加项目：

    ```js
    const stack = [];
    // bad
    stack[stack.length] = 'pushme';
    // good
    stack.push('pushme');
    ```

# 总结

随着 JavaScript 作为一种语言的成熟，其工具链也变得更加健壮和有效。经验丰富的程序员很少会避开像 Underscore.js 这样的库。随着我们看到更多高级主题，我们将继续探索更多这样的多功能库，这些库可以使你的代码更加紧凑、易读且性能更优。我们研究了正则表达式——它们在 JavaScript 中是第一类对象。一旦你开始理解`RegExp`，你很快就会发现自己更多地使用它们来使你的代码更加简洁。在下一章，我们将探讨 JavaScript 对象表示法以及 JavaScript 原型继承是如何为面向对象编程提供一种新的视角。


# 第四章：面向对象的 JavaScript

JavaScript 最基本的数据类型是对象数据类型。JavaScript 对象可以被视为可变的基于键值对的集合。在 JavaScript 中，数组、函数和 RegExp 都是对象，而数字、字符串和布尔值是类似对象的构造，是不可变的，但具有方法。在本章中，你将学习以下主题：

+   理解对象

+   实例属性与原型属性

+   继承

+   获取器和设置器

# 理解对象

在我们开始研究 JavaScript 如何处理对象之前，我们应该先花些时间来了解一下面向对象范式。像大多数编程范式一样，**面向对象编程**（**OOP**）也是为了解决复杂性而产生的。主要思想是将整个系统划分为更小的、相互隔离的部分。如果这些小部分能隐藏尽可能多的实现细节，它们就变得容易使用了。一个经典的汽车类比将帮助你理解 OOP 的非常重要的一点。

当你驾驶汽车时，你在操作界面——转向、离合器、刹车和油门。你使用汽车的视角被这个界面所限制，这使得我们能够驾驶汽车。这个界面本质上隐藏了所有真正驱动汽车复杂的系统，比如它的发动机内部运作、电子系统等等。作为一名驾驶员，你不需要关心这些复杂性。这是面向对象编程（OOP）的主要驱动力。一个对象隐藏了实现特定功能的所有复杂性，并向外界暴露了一个有限的接口。所有其他系统都可以使用这个接口，而无需真正关心被隐藏的内部复杂性。此外，一个对象通常会隐藏其内部状态，不让其他对象直接修改。这是 OOP 的一个重要方面。

在一个大型系统中，如果许多对象调用其他对象的接口，而允许它们修改这些对象的内部状态，事情可能会变得非常糟糕。OOP 的基本理念是，对象的内部状态 inherently hidden from the outside world，并且只能通过受控的接口操作来更改。

面向对象编程（OOP）是一个重要的想法，也是从传统的结构化编程向前迈出的明确一步。然而，许多人认为 OOP 做得过头了。大多数 OOP 系统定义了复杂且不必要的类和类型层次结构。另一个大的缺点是，在追求隐藏状态的过程中，OOP 几乎将对象状态视为不重要。尽管 OOP 非常流行，但在许多方面显然是有缺陷的。然而，OOP 确实有一些非常好的想法，尤其是隐藏复杂性并只向外部世界暴露接口。JavaScript 采纳了一些好想法，并围绕它们构建了其对象模型。幸运的是，这使得 JavaScript 对象非常多功能。在他们开创性的作品中，《设计模式：可重用面向对象软件的元素》，*四人帮*给出了更好的面向对象设计两个基本原则：

+   面向接口编程，而不是面向实现

+   对象组合优于类继承

这两个想法实际上是与经典 OOP 的运作方式相反的。经典继承的运作方式是基于继承，将父类暴露给所有子类。经典继承紧密耦合了子类和其父类。经典继承中有机制可以在一定程度上解决这个问题。如果你在像 Java 这样的语言中使用经典继承，通常建议*面向接口编程，而不是面向实现*。在 Java 中，你可以使用接口编写松耦合的代码：

```js
//programming to an interface 'List' and not implementation 'ArrayList'
List theList = new ArrayList();
```

而不是编程到实现，你可以执行以下操作：

```js
ArrayList theList = new ArrayList();
```

编程到一个接口有什么帮助？当你编程到`List`接口时，你只能调用`List`接口独有的方法，不能调用`ArrayList`特定的方法。编程到一个接口给你自由改变你的代码并使用`List`接口的任何其他特定子类。例如，我可以改变我的实现并使用`LinkedList`而不是`ArrayList`。你可以将你的变量更改为使用`LinkedList`：

```js
List theList = new LinkedList();
```

这种方法的优点是，如果你在你的程序中 100 次使用`List`，你根本不需要担心在所有这些地方改变实现。因为你是面向接口编程，而不是面向实现，所以你能够编写松耦合的代码。当你使用经典继承时，这是一个重要的原则。

经典继承也有一个限制，即你只能在父类范围内增强子类。你不能根本区别于从祖先那里得到的东西。这阻碍了重用。经典继承还有其他几个问题，如下：

+   继承引入了紧密耦合。子类对其祖先有所了解。这种紧密耦合了一个子类与其父类之间的关系。

+   当你从父类继承时，你无法选择继承什么和不继承什么。*Joe Armstrong*（**Erlang**的发明者）很好地解释了这种情况——他那如今著名的名言：

    > *"面向对象语言的问题在于，它们携带的所有这些隐式环境。你想要一根香蕉，但你所得到的是一个拿着香蕉和整个丛林的大猩猩。"*

## JavaScript 对象的行为

有了这些背景知识，让我们来探讨一下 JavaScript 对象的行为。从广义上讲，一个对象包含属性，这些属性定义为键值对。属性键（名称）可以是字符串，值可以是任何有效的 JavaScript 值。你可以使用对象字面量来创建对象。以下片段展示了对象字面量是如何创建的：

```js
var nothing = {};
var author = {
  "firstname": "Douglas",
  "lastname": "Crockford"
}
```

属性的名称可以是任何字符串或空字符串。如果属性名是合法的 JavaScript 名称，你可以省略属性名周围的引号。所以`first-name`周围需要引号，但`firstname`周围可以省略引号。逗号用于分隔这些对。你可以像下面这样嵌套对象：

```js
var author = {
  firstname : "Douglas",
  lastname : "Crockford",
  book : {
    title:"JavaScript- The Good Parts",
    pages:"172"
  }
};
```

可以通过使用两种表示法来访问对象的属性：数组表示法和点表示法。根据数组表示法，你可以通过将字符串表达式包裹在`[]`中来从对象中检索值。如果表达式是一个有效的 JavaScript 名称，你可以使用点表示法使用`.`代替。使用`.`是从对象中检索值的首选方法：

```js
console.log(author['firstname']); //Douglas
console.log(author.lastname);     //Crockford
console.log(author.book.title);   // JavaScript- The Good Parts
```

如果你尝试获取一个不存在的值，你会得到一个`undefined`错误。以下将返回`undefined`：

```js
console.log(author.age);
```

一个有用的技巧是使用`||`运算符在这种情况下填充默认值：

```js
console.log(author.age || "No Age Found");
```

你可以通过将新值赋给属性来更新对象的值：

```js
author.book.pages = 190;
console.log(author.book.pages); //190
```

如果你仔细观察，你会意识到你看到的对象字面量语法与 JSON 格式非常相似。

对象的方法是对象的属性，可以持有函数值，如下所示：

```js
var meetingRoom = {};
meetingRoom.book = function(roomId){
  console.log("booked meeting room -"+roomId);
}
meetingRoom.book("VL");
```

## 原型

除了我们添加到对象上的属性外，几乎所有对象都有一个默认属性，称为**原型**。当一个对象没有请求的属性时，JavaScript 会去它的原型中查找。`Object.getPrototypeOf()`函数返回一个对象的 prototype。

许多程序员认为原型与对象的继承密切相关——它们确实是一种定义对象类型的方式——但从根本上说，它们与函数紧密相关。

原型是用来定义将应用于对象实例的属性和函数的一种方式。原型的属性最终成为实例化对象的属性。原型可以被视为创建对象的蓝图。它们可以被视为面向对象语言中类的类似物。JavaScript 中的原型用于编写经典风格的面向对象代码并模仿经典继承。让我们重新回顾一下我们之前的例子：

```js
var author = {};
author.firstname = 'Douglas';
author.lastname = 'Crockford';
```

```js
new operator to instantiate an object via constructors. However, there is no concept of a class in JavaScript, and it is important to note that the new operator is applied to the constructor function. To clearly understand this, let's look at the following example:
```

```js
//A function that returns nothing and creates nothing
function Player() {}

//Add a function to the prototype property of the function
Player.prototype.usesBat = function() {
  return true;
}

//We call player() as a function and prove that nothing happens
var crazyBob = Player();
if(crazyBob === undefined){
  console.log("CrazyBob is not defined");
}

//Now we call player() as a constructor along with 'new' 
//1\. The instance is created
//2\. method usesBat() is derived from the prototype of the function
var swingJay = new Player();
if(swingJay && swingJay.usesBat && swingJay.usesBat()){
  console.log("SwingJay exists and can use bat");
}
```

在前一个例子中，我们有一个`player()`函数，它什么也不做。我们以两种不同的方式调用它。第一个调用是作为普通函数，第二个调用作为构造函数——注意这个调用中使用了`new()`操作符。一旦函数被定义，我们向它添加了一个`usesBat()`方法。当这个函数作为普通函数调用时，对象没有被实例化，我们看到`undefined`被赋值给`crazyBob`。然而，当我们使用`new`操作符调用这个函数时，我们得到了一个完全实例化的对象，`swingJay`。

# 实例属性与原型属性对比

实例属性是对象实例本身的一部分属性，如下例所示：

```js
function Player() {
  this.isAvailable = function() {
    return "Instance method says - he is hired";
  };
}
Player.prototype.isAvailable = function() {
  return "Prototype method says - he is Not hired";
};
var crazyBob = new Player();
console.log(crazyBob.isAvailable());
```

当你运行这个例子时，你会看到**实例方法说 - 他被雇佣了**被打印出来。在`Player()`函数中定义的`isAvailable()`函数被称为`Player`的实例。这意味着除了通过原型附加属性外，你还可以使用`this`关键字在构造函数中初始化属性。当我们实例属性和原型中都有相同的函数定义时，实例属性优先。决定初始化优先级的规则如下：

+   属性从原型绑定到对象实例。

+   属性在构造函数中绑定到对象实例。

这个例子让我们了解了`this`关键字的用法。`this`关键字很容易让人混淆，因为它在 JavaScript 中的行为不同。在其他面向对象的编程语言（如 Java）中，`this`关键字指的是类当前的实例。在 JavaScript 中，`this`的值由函数的调用上下文和调用位置决定。让我们看看这种行为需要如何仔细理解：

+   在全局上下文中使用`this`：当在全局上下文中调用`this`时，它绑定到全局上下文。例如，在浏览器中，全局上下文通常是`window`。这也适用于函数。如果你在全局上下文中定义的函数中使用`this`，它仍然绑定到全局上下文，因为函数是全局上下文的一部分：

    ```js
    function globalAlias(){
      return this;
    }
    console.log(globalAlias()); //[object Window]
    ```

+   在对象方法中使用`this`：在这种情况下，`this`被赋值或绑定到包含它的对象。注意，如果你们嵌套对象，包含对象是立即的父级：

    ```js
    var f = {
      name: "f",
      func: function () {
        return this; 
      }
    };
    console.log(f.func());  
    //prints - 
    //[object Object] {
    //  func: function () {
    //    return this; 
    //  },
    //  name: "f"
    //}
    ```

+   在没有上下文的情况下：如果一个函数没有被任何对象调用，它不会获得任何上下文。默认情况下，它绑定到全局上下文。当你在这样一个函数中使用`this`时，它也绑定到全局上下文。

+   当在构造函数中使用`this`时：正如我们之前所看到的，当一个函数通过`new`关键字调用时，它充当构造函数。在构造函数的情况下，`this`指向正在构造的对象。在下面的例子中，`f()`被用作构造函数（因为它通过`new`关键字调用），因此，`this`指向正在创建的新对象。所以当我们说`this.member = "f"`时，新成员被添加到正在创建的对象中，在这个例子中，这个对象碰巧是`o`：

    ```js
    var member = "global";
    function f()
    {
      this.member = "f";
    }
    var o= new f(); 
    console.log(o.member); // f
    ```

我们发现，当实例属性和原型属性同时定义同一个属性时，实例属性具有优先权。很容易想象，当创建新对象时，构造函数的原型属性会被复制过来。然而，这并不是一个正确的假设。实际发生的情况是，原型被附加到对象上，并在引用该对象的任何属性时引用它。本质上，当引用对象的属性时，以下情况之一会发生：

+   检查对象是否具有该属性。如果找到，则返回该属性。

+   检查相关原型。如果找到属性，则返回该属性；否则，返回一个`undefined`错误。

这是一个重要的理解，因为在 JavaScript 中，以下代码实际上完全有效：

```js
function Player() {
  isAvailable=false;
}
var crazyBob = new Player();
Player.prototype.isAvailable = function() {
  return isAvailable;
};
console.log(crazyBob.isAvailable()); //false
```

这段代码是之前示例的稍微变体。我们首先创建一个对象，然后将其函数附加到原型上。当你最终在对象上调用`isAvailable()`方法时，如果在该对象中找不到它（在这个例子中是`crazyBob`），JavaScript 会到其原型中寻找。你可以将其视为*热代码加载*——如果使用得当，这种能力可以在对象创建后为你提供巨大的扩展基本对象框架的权力。

如果你已经熟悉面向对象编程（OOP），你可能想知道我们是否能控制对象成员的可见性和访问权限。正如我们之前讨论的，JavaScript 没有类。在像 Java 这样的编程语言中，你有访问修饰符，如`private`和`public`，可以让你控制类成员的可见性。在 JavaScript 中，我们可以使用函数作用域实现类似的功能：

+   你可以在函数中使用`var`关键字声明私有变量。它们可以通过私有函数或特权方法访问。

+   私有函数可以在对象的构造函数中声明，并且可以通过特权方法调用。

+   特权方法可以通过`this.method=function() {}`声明。

+   公共方法通过`Class.prototype.method=function(){}`声明。

+   公共属性可以用`this.property`声明，并从对象外部访问。

以下示例展示了几种实现方式：

```js
function Player(name,sport,age,country){ 

  this.constructor.noOfPlayers++;

  // Private Properties and Functions
  // Can only be viewed, edited or invoked by privileged members
  var retirementAge = 40;
  var available=true;
  var playerAge = age?age:18;
  function isAvailable(){ return available && (playerAge<retirementAge); } 
  var playerName=name ? name :"Unknown";
  var playerSport = sport ? sport : "Unknown";

  // Privileged Methods
  // Can be invoked from outside and can access private members
  // Can be replaced with public counterparts
  this.book=function(){ 
    if (!isAvailable()){ 
      this.available=false;
    } else {
      console.log("Player is unavailable");
    } 
  };
  this.getSport=function(){ return playerSport; }; 
  // Public properties, modifiable from anywhere
  this.batPreference="Lefty";
  this.hasCelebGirlfriend=false;
  this.endorses="Super Brand";
} 

// Public methods - can be read or written by anyone
// Can only access public and prototype properties
Player.prototype.switchHands = function(){ this.batPreference="righty"; }; 
Player.prototype.dateCeleb = function(){ this.hasCelebGirlfriend=true; } ;
Player.prototype.fixEyes = function(){ this.wearGlasses=false; };

// Prototype Properties - can be read or written by anyone (or overridden)
Player.prototype.wearsGlasses=true;

// Static Properties - anyone can read or write
Player.noOfPlayers = 0;

(function PlayerTest(){ 
  //New instance of the Player object created.
  var cricketer=new Player("Vivian","Cricket",23,"England"); 
  var golfer =new Player("Pete","Golf",32,"USA"); 
  console.log("So far there are " + Player.noOfPlayers + " in the guild");

  //Both these functions share the common 'Player.prototype.wearsGlasses' variable
  cricketer.fixEyes(); 
  golfer.fixEyes(); 

  cricketer.endorses="Other Brand";//public variable can be updated 

  //Both Player's public method is now changed via their prototype 
  Player.prototype.fixEyes=function(){ 
    this.wearGlasses=true;
  };
  //Only Cricketer's function is changed
  cricketer.switchHands=function(){
    this.batPreference="undecided";
  };

})();
```

让我们从这个例子中理解一些重要的概念：

+   `retirementAge`变量是一个私有变量，没有特权方法来获取或设置其值。

+   `country`变量是一个通过构造函数参数创建的私有变量。构造函数参数作为私有变量对对象可用。

+   当我们调用`cricketer.switchHands()`时，这个函数只应用于`cricketer`本身，而没有同时应用于两名球员，尽管它本身是`Player`对象的一个原型函数。

+   私有函数和特权方法随着每个新对象的创建而实例化。在我们的例子中，每次我们创建一个新的球员实例时，都会创建`isAvailable()`和`book()`的新副本。另一方面，只有公共方法的一个副本被创建，并在所有实例之间共享。这可能会带来一些性能提升。如果你*真的*不需要将某事设为私有，考虑将其设为公共。

# 继承

继承是面向对象编程（OOP）的一个重要概念。通常会有许多实现相同方法的对象，也很常见几乎相似的对象定义，差异仅在于几个方法。继承在促进代码重用方面非常有用。我们可以看看以下继承关系的经典示例：

![继承](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00007.jpeg)

在这里，你可以看到从通用的**Animal**类中，我们派生出更具体的一些类，如**Mammal**和**Bird**，这些都是基于特定的特性。哺乳动物和鸟类班级都有动物类的同一个模板；然而，它们还定义了特定于它们自己的行为和属性。最后，我们派生出一个非常具体的哺乳动物，**Dog**。狗从动物类和哺乳动物类中继承了共同的属性和行为，同时它还增加了狗特有的属性和行为。这可以继续添加复杂的继承关系。

传统上，继承被用来建立或描述**IS-A**关系。例如，狗是哺乳动物。这就是我们所说的**经典继承**。你可能会在面向对象的语言如 C++和 Java 中看到这样的关系。JavaScript 有一个完全不同的机制来处理继承。JavaScript 是一种无类语言，使用原型进行继承。原型继承在本质上非常不同，需要深入理解。经典继承和原型继承在本质上非常不同，需要仔细研究。

在经典继承中，实例从类蓝图中继承，并创建子类关系。你不能在类定义本身上调用实例方法。你需要创建一个实例，然后在这个实例上调用方法。另一方面，在原型继承中，实例从其他实例中继承。

至于继承，JavaScript 只使用对象。如我们之前讨论的，每个对象都有一个链接到另一个对象的原型。这个原型对象，反过来，也有自己的原型，依此类推，直到找到一个其原型为`null`的对象；`null`，按定义，没有原型，作为原型链中的最后一个链接。

为了更好地理解原型链，让我们考虑以下示例：

```js
function Person() {}
Person.prototype.cry = function() { 
  console.log("Crying");
}
function Child() {}
Child.prototype = {cry: Person.prototype.cry};
var aChild = new Child();
console.log(aChild instanceof Child);  //true
console.log(aChild instanceof Person); //false
console.log(aChild instanceof Object); //true
```

在这里，我们定义了一个`Person`，然后是`Child`——一个孩子 IS-A 人。我们还把`Person`的`cry`属性复制给了`Child`的`cry`属性。当我们尝试使用`instanceof`来看这种关系时，我们很快意识到，仅仅通过复制行为，我们并不能真正使`Child`成为`Person`的实例；`aChild instanceof Person`失败。这只是复制或伪装，并不是继承。即使我们把`Person`的所有属性复制给`Child`，我们也不会从`Person`继承。这通常是一个糟糕的主意，这里只是为了说明目的。我们希望导出一个原型链——一个 IS-A 关系，一个真正的继承，我们可以说是 child IS-A person。我们希望创建一个链：child IS-A person IS-A mammal IS-A animal IS-A object。在 JavaScript 中，这是通过使用一个对象的实例作为原型来完成的：

```js
SubClass.prototype = new SuperClass();
Child.prototype = new Person();
```

让我们修改之前的示例：

```js
function Person() {}
Person.prototype.cry = function() { 
  console.log("Crying");
}
function Child() {}
Child.prototype = new Person();
var aChild = new Child();
console.log(aChild instanceof Child);  //true
console.log(aChild instanceof Person); //true
console.log(aChild instanceof Object); //true
```

修改后的行使用了`Person`实例作为`Child`的原型。这与之前的方法有重要的区别。这里我们声明 child IS-A person。

我们讨论了 JavaScript 如何在一个属性直到它达到`Object.prototype`的原型链中寻找属性。让我们详细讨论原型链的概念，并尝试设计以下员工层次结构：

![继承](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00008.jpeg)

这是继承的典型模式。经理 IS-A(n) 员工。**经理**从**员工**继承了共同的属性。它可以拥有一个报告人员的数组。一个**个人贡献者**也是基于一个员工，但他没有任何报告人员。一个**团队领导**从经理派生出来，有几个与经理不同的功能。我们本质上是在做每个孩子从它的父母那里导出属性（经理是父母，团队领导是孩子）。

让我们看看我们如何在 JavaScript 中创建这个层次结构。让我们定义我们的`Employee`类型：

```js
function Employee() {
  this.name = '';
  this.dept = 'None';
  this.salary = 0.00;
}
```

这些定义没有什么特别之处。`Employee`对象包含三个属性—姓名、薪水、部门。接下来，我们定义`Manager`。这个定义展示了如何指定继承链中的下一个对象：

```js
function Manager() {
 Employee.call(this);
  this.reports = [];
}
Manager.prototype = Object.create(Employee.prototype);

```

在 JavaScript 中，你可以在定义构造函数后任何时候将原型实例添加到构造函数的 prototype 属性中。在这个例子中，我们还没有探索到两个想法。首先，我们调用`Employee.call(this)`。如果你来自 Java 背景，这与构造函数中的`super()`方法调用类似。`call()`方法用一个特定的对象作为其上下文（在这个例子中，是给定的`this`值）调用一个函数，换句话说，`call()`允许指定在函数执行时哪个对象将被`this`关键字引用。与 Java 中的`super()`类似，调用`parentObject.call(this)`是初始化正在创建的对象所必需的。

我们看到的另一点是使用`Object.create()`而不是调用`new`。`Object.create()`创建了一个具有指定原型的对象。当我们调用`new Parent()`时，会调用父类的构造逻辑。在大多数情况下，我们想要的是`Child.prototype`是一个通过原型链接到`Parent.prototype`的对象。如果父类构造函数包含特定于父类的额外逻辑，我们在创建子对象时不想运行这个逻辑。这可能会导致非常难以发现的错误。`Object.create()`创建了与`new`运算符相同的父子原型链接，而不会调用父类构造函数。

为了有一个无副作用且准确的继承机制，我们必须确保我们执行以下操作：

+   将原型设置为父类的实例来初始化原型链（继承）；这只需要做一次（因为原型对象是共享的）

+   调用父类的构造函数初始化对象本身；这在每次实例化时都会进行（你可以在构造它时传递不同的参数）

在理解了这一点的基础上，我们来定义其余的对象：

```js
function IndividualContributor() {
  Employee.call(this);
  this.active_projects = [];
}
IndividualContributor.prototype = Object.create(Employee.prototype);

function TeamLead() {
  Manager.call(this);
  this.dept = "Software";
  this.salary = 100000;
}
TeamLead.prototype = Object.create(Manager.prototype);

function Engineer() {
  TeamLead.call(this);
  this.dept = "JavaScript";
  this.desktop_id = "8822" ;
  this.salary = 80000;
}
Engineer.prototype = Object.create(TeamLead.prototype);
```

基于这个层次结构，我们可以实例化这些对象：

```js
var genericEmployee = new Employee();
console.log(genericEmployee);
```

你可以看到以下代码片段的输出：

```js
[object Object] {
  dept: "None",
  name: "",
  salary: 0
}
```

一个通用的`Employee`对象分配给`None`的部门（如默认值中所指定），其余属性也分配为默认值。

接下来，我们实例化一个经理；我们可以像下面这样提供具体的值：

```js
var karen = new Manager();
karen.name = "Karen";
karen.reports = [1,2,3];
console.log(karen);
```

你会看到以下输出：

```js
[object Object] {
  dept: "None",
  name: "Karen",
  reports: [1, 2, 3],
  salary: 0
}
```

对于`TeamLead`，其`reports`属性是从基类（在这个例子中是 Manager）派生出来的：

```js
var jason = new TeamLead();
jason.name = "Json";
console.log(jason);
```

你会看到以下的输出：

```js
[object Object] {
  dept: "Software",
  name: "Json",
  reports: [],
  salary: 100000
}
```

当 JavaScript 处理新的操作符时，它创建一个新对象，并将这个对象作为`this`的值传递给父对象——即`TeamLead`构造函数。构造函数设置`projects`属性的值，并隐式地将内部`__proto__`属性的值设置为`TeamLead.prototype`的值。`__proto__`属性决定了用于返回属性值的原型链。这个过程不会在`jason`对象中设置从原型链继承的属性值。当读取属性的值时，JavaScript 首先检查该对象中是否存在这个值。如果值存在，这个值就被返回。如果值不存在，JavaScript 使用`__proto__`属性检查原型链。说到这里，当你做以下操作时会发生什么：

```js
Employee.prototype.name = "Undefined";
```

它不会传播到`Employee`的所有实例中。这是因为当你创建一个`Employee`对象的实例时，这个实例获得了名字的局部值。当你通过创建一个新的`Employee`对象来设置`TeamLead`原型时，`TeamLead.prototype`拥有`name`属性的局部值。因此，当 JavaScript 查找`jason`对象（`TeamLead`的一个实例）的`name`属性时，它找到了`TeamLead.prototype`中的这个属性的局部值。它不会尝试进一步查找链中的`Employee.prototype`。

如果你想在运行时改变属性的值，并且希望新值被对象的的所有后代继承，你不能在对象的构造函数中定义属性。要实现这一点，你需要将其添加到构造函数的原型中。例如，让我们稍稍修改一下先前的例子：

```js
function Employee() {
  this.dept = 'None';
  this.salary = 0.00;
}
Employee.prototype.name = '';
function Manager() {
  this.reports = [];
}
Manager.prototype = new Employee();
var sandy = new Manager();
var karen = new Manager();

Employee.prototype.name = "Junk";

console.log(sandy.name);
console.log(karen.name);
```

```js
String object to add a reverse() method to reverse a string. This method does not exist in the native String object but by manipulating String's prototype, we add this method to String:
```

```js
String.prototype.reverse = function() {
  return Array.prototype.reverse.apply(this.split('')).join('');
};
var str = 'JavaScript';
console.log(str.reverse()); //"tpircSavaJ"
```

虽然这是一个非常强大的技术，但使用时应该小心，不要过度使用。参阅[`perfectionkills.com/extending-native-builtins/`](http://perfectionkills.com/extending-native-builtins/)以了解扩展原生内置对象的陷阱以及如果你打算这样做应该注意什么。

# 访问器和方法

**访问器方法**是获取特定属性值方便的方法；正如其名，**设置器方法**是设置属性值的方法。通常，你可能希望基于其他值派生一个值。传统上，访问器和方法通常是像下面的函数：

```js
var person = {
  firstname: "Albert",
  lastname: "Einstein",
  setLastName: function(_lastname){
    this.lastname= _lastname;
  },
  setFirstName: function (_firstname){
    this.firstname= _firstname;
  },
  getFullName: function (){
    return this.firstname + ' '+ this.lastname;
  }  
};
person.setLastName('Newton');
person.setFirstName('Issac');
console.log(person.getFullName());
```

如你所见，`setLastName()`、`setFirstName()`和`getFullName()`是用于属性*获取*和*设置*的函数。`Fullname`是通过连接`firstname`和`lastname`属性派生出的属性。这是一个非常常见的用例，ECMAScript 5 现在为您提供了访问器和方法的默认语法。

以下示例展示了如何在 ECMAScript 5 中使用对象字面量语法创建访问器和方法：

```js
var person = {
  firstname: "Albert",
  lastname: "Einstein",
  get fullname() {
    return this.firstname +" "+this.lastname;
  },
  set fullname(_name){
    var words = _name.toString().split(' ');
    this.firstname = words[0];
    this.lastname = words[1];
  }
};
person.fullname = "Issac Newton";
console.log(person.firstname); //"Issac"
console.log(person.lastname);  //"Newton"
console.log(person.fullname);  //"Issac Newton"
```

声明访问器和方法的另一种方式是使用`Object.defineProperty()`方法：

```js
var person = {
  firstname: "Albert",
  lastname: "Einstein",
};
Object.defineProperty(person, 'fullname', {
  get: function() {
    return this.firstname + ' ' + this.lastname;
  },
  set: function(name) {
    var words = name.split(' ');
    this.firstname = words[0];
    this.lastname = words[1];
  }
});
person.fullname = "Issac Newton";
console.log(person.firstname); //"Issac"
console.log(person.lastname);  //"Newton"
console.log(person.fullname);  //"Issac Newton"
```

在这个方法中，即使对象已经被创建，你也可以调用`Object.defineProperty()`。

既然你已经尝到了 JavaScript 对象导向的味道，接下来我们将介绍由**Underscore.js**提供的一组非常有用的工具方法。我们在上一章讨论了 Underscore.js 的安装和基本使用。这些方法将使对对象的基本操作变得非常容易：

+   `keys()`：这个方法检索对象自身可枚举属性的名称。请注意，这个函数不会遍历原型链：

    ```js
    var _ = require('underscore');
    var testobj = {
      name: 'Albert',
      age : 90,
      profession: 'Physicist'
    };
    console.log(_.keys(testobj));
    //[ 'name', 'age', 'profession' ]
    ```

+   `allKeys()`: 这个方法会检索对象自身和继承的属性的名称：

    ```js
    var _ = require('underscore');
    function Scientist() {
      this.name = 'Albert';
    }
    Scientist.prototype.married = true;
    aScientist = new Scientist();
    console.log(_.keys(aScientist)); //[ 'name' ]
    console.log(_.allKeys(aScientist));//[ 'name', 'married' ]

    ```

+   `values()`：这个方法检索对象自身属性的值：

    ```js
    var _ = require('underscore');
    function Scientist() {
      this.name = 'Albert';
    }
    Scientist.prototype.married = true;
    aScientist = new Scientist();
    console.log(_.values(aScientist)); //[ 'Albert' ]
    ```

+   `mapObject()`: 这个方法会将对象中每个属性的值进行转换：

    ```js
    var _ = require('underscore');
    function Scientist() {
      this.name = 'Albert';
      this.age = 90;
    }
    aScientist = new Scientist();
    var lst = _.mapObject(aScientist, function(val,key){
      if(key==="age"){
        return val + 10;
      } else {
        return val;
      }
    });
    console.log(lst); //{ name: 'Albert', age: 100 }
    ```

+   `functions()`：这会返回一个排序好的列表，包含对象中每个方法的名称——对象每个函数属性的名称。

+   `pick()`：这个函数返回一个对象的副本，过滤出提供的键的值：

    ```js
    var _ = require('underscore');
    var testobj = {
      name: 'Albert',
      age : 90,
      profession: 'Physicist'
    };
    console.log(_.pick(testobj, 'name','age')); //{ name: 'Albert', age: 90 }
    console.log(_.pick(testobj, function(val,key,object){
      return _.isNumber(val);
    })); //{ age: 90 }
    ```

+   `omit()`: 这个函数是`pick()`的逆操作——它返回一个对象的副本，过滤掉指定键的值。

# 总结

允许 JavaScript 应用程序通过使用对象导向带来的更大控制和结构，从而提高代码的清晰度和质量。JavaScript 的对象导向基于函数原型和原型继承。这两个概念可以为开发者提供大量的财富。

在本章中，我们看到了基本的对象创建和操作。我们探讨了构造函数如何用于创建对象。我们深入研究了原型链以及如何在原型链上操作继承。这些基础将用于构建我们在下一章中探索的 JavaScript 模式的知识。


# 第五章：JavaScript 模式

到目前为止，我们已经查看了几个编写 JavaScript 代码所必需的基本构建块。一旦你开始使用这些基本构建块来构建更大的系统，你很快就会意识到有些事情可能有一种标准的方法。在开发大型系统时，你会遇到重复的问题；模式旨在为这些已知和识别的问题提供标准化的解决方案。模式可以被视为最佳实践、有用的抽象或模板来解决常见问题。编写可维护的代码是困难的。编写模块化、正确和可维护的代码的关键是理解重复的主题并使用通用模板来编写这些优化的解决方案。关于设计模式的最重要文本是一本于 1995 年出版的书籍，名为《设计模式：可重用面向对象软件的元素》，作者是埃里希·伽玛（Erich Gamma）、理查德·赫尔姆（Richard Helm）、拉尔夫·约翰逊（Ralph Johnson）和约翰·维利斯 ides（John Vlissides）——一个被称为**四人帮**（简称 GOF）的团队。这本开创性的作品给出了各种模式的正式定义，并解释了今天我们使用的大多数流行模式的实现细节。理解模式的重要性是非常重要的：

+   模式提供了解决常见问题的经过验证的解决方案：模式提供了优化解决特定问题的模板。这些模式得到了坚实的工程经验支持，并经过验证。

+   模式旨在被重用：它们足够通用，可以适应问题的变体。

+   模式定义了词汇：模式是定义良好的结构，因此为解决方案提供了一个通用的词汇。这在跨大型团队沟通时非常有表现力。

# 设计模式

在本章中，我们将探讨一些适用于 JavaScript 的设计模式。然而，编码模式对于 JavaScript 来说非常具体，对我们来说也非常重要。虽然我们花费了大量时间和精力来理解和掌握设计模式，但理解反模式以及如何避免陷阱也同样重要。在通常的软件开发周期中，有几种地方可能会引入糟糕的代码，主要是在代码接近发布的时候，或者当代码交给另一个团队进行维护时。如果将这些糟糕的设计结构记录为反模式，它们可以指导开发者知道该避免哪些陷阱，以及如何不采用糟糕的设计模式。大多数语言都有它们自己的反模式。根据它们解决的问题类型，设计模式被 GOF 归类为几个大类：

+   **创建型设计模式**：这些模式处理各种对象创建机制。尽管大多数语言提供了基本对象创建方法，但这些模式关注对象创建的优化或更受控的机制。

+   **结构设计模式**：这些模式都是关于对象及其之间关系的组合。想法是在系统中的某处发生变化时，对整体对象关系的影响最小。

+   **行为设计模式**：这些模式专注于对象之间的相互依赖和通信。

下面的表格是一个有用的工具，用于识别模式的类别：

+   创建型模式：

    +   工厂方法

    +   抽象工厂

    +   建造者

    +   原型

    +   单例

+   结构模式：

    +   适配器

    +   桥接

    +   组合

    +   装饰器

    +   外观

    +   享元

    +   代理

+   行为模式

    +   解释器

    +   模板方法

    +   责任链

    +   命令

    +   迭代器

    +   中介者

    +   备忘录

    +   观察者

    +   状态

    +   策略

    +   访问者

本章中我们将讨论的一些模式可能不包括在此列表中，因为它们更特定于 JavaScript 或这些经典模式的一种变体。同样，我们也不会讨论不适合 JavaScript 或不常用的模式。

# 命名空间模式

在 JavaScript 中过度使用全局作用域几乎是一种禁忌。当你构建更大的程序时，有时很难控制全局作用域被污染的程度。命名空间可以减少程序创建的全局变量数量，并帮助避免命名冲突或过度的前缀命名。使用命名空间的想法是创建一个全局对象，为您的应用程序或库添加所有这些对象和函数，而不是用对象污染全局作用域。JavaScript 没有显式的语法来定义命名空间，但命名空间可以很容易地创建。考虑以下示例：

```js
function Car() {}
function BMW() {}
var engines = 1;
var features = {
  seats: 6,
  airbags:6
};
```

我们正在全局作用域中创建所有这些内容。这是一个反模式，这从来不是一个好主意。然而，我们可以重构这个代码，创建一个全局对象，并让所有的函数和对象成为这个全局对象的一部分，如下所示：

```js
// Single global object
var CARFACTORY = CARFACTORY || {};
CARFACTORY.Car = function () {};
CARFACTORY.BMW = function () {};
CARFACTORY.engines = 1;
CARFACTORY.features = {
  seats: 6,
  airbags:6
};
```

按惯例，全局命名空间对象名称通常全部用大写书写。这种模式为应用程序添加了命名空间，防止了您的代码以及您的代码与使用的第三方库之间的命名冲突。许多项目在其公司或项目名后使用独特名称来为他们的命名空间创建唯一名称。

尽管这似乎是一种理想的方式来限制你的全局变量并为你的代码添加一个命名空间，但它有点冗长；你需要为每个变量和函数加上命名空间前缀。你需要输入更多内容，代码变得不必要地冗长。此外，单一的全局实例意味着代码的任何部分都可以修改全局实例，其余的功能得到更新状态—这可能会导致非常糟糕的副作用。在之前的例子中，一个有趣的现象是这一行—`var CARFACTORY = CARFACTORY || {};`. 当你在一个大型代码库上工作时，你不能假设你正在为这个命名空间（或者给它分配一个属性）创建第一次。有可能命名空间已经存在。为了确保只有当命名空间尚未创建时才创建命名空间，始终依赖通过短路`||`操作符的快速默认是安全的。

# 模块模式

随着你构建大型应用程序，你很快会意识到保持代码库的组织和模块化变得越来越困难。模块模式有助于保持代码清晰地分离和组织。

模块将更大的程序分成更小的部分，并赋予它们一个命名空间。这非常重要，因为一旦你将代码分成模块，这些模块可以在多个地方重复使用。仔细设计模块的接口将使您的代码非常易于重用和扩展。

JavaScript 提供了灵活的函数和对象，这使得创建健壮的模块系统变得容易。函数作用域有助于创建模块内部的命名空间，而对象可用于存储一系列导出的值。

在我们开始探索模式本身之前，让我们快速回顾一下我们之前讨论的一些概念。

我们详细讨论了对象字面量。对象字面量允许你按照如下方式创建名称-值对：

```js
var basicServerConfig = {
  environment: "production",
  startupParams: {
    cacheTimeout: 30,
    locale: "en_US"
  },
  init: function () {
    console.log( "Initializing the server" );
  },
  updateStartup: function( params ) {
      this.startupParams = params;
      console.log( this.startupParams.cacheTimeout );
      console.log( this.startupParams.locale );
  }
};
basicServerConfig.init(); //"Initializing the server"
basicServerConfig.updateStartup({cacheTimeout:60, locale:"en_UK"}); //60, en_UK
```

在这个例子中，我们创建了一个对象字面量，并定义了键值对来创建属性和函数。

在 JavaScript 中，模块模式被广泛使用。模块有助于模仿类的概念。模块允许我们包含一个对象的公共/私有方法和变量，但最重要的是，模块将这些部分限制在全局作用域之外。由于变量和函数被包含在模块作用域内，我们自动防止了与其他使用相同名称的脚本发生命名冲突。

模块模式的另一个美丽方面是，我们只暴露公共 API。与内部实现相关的所有其他内容都在模块的闭包内保持私有。

与其他面向对象的编程语言不同，JavaScript 没有显式的访问修饰符，因此，没有*隐私*的概念。你不能有公共变量或私有变量。如我们之前讨论的，在 JavaScript 中，函数作用域可以用来强制这个概念。模块模式使用闭包来限制变量和函数的访问仅限于模块内部；然而，变量和函数是在被返回的对象中定义的，这对外部是可用的。

让我们考虑之前的例子，将其转换为模块。我们实际上是在使用一个立即执行的函数表达式（IIFE），并返回模块的接口，即`init`和`updateStartup`函数：

```js
var basicServerConfig = (function () {
  var environment= "production";
  startupParams= {
    cacheTimeout: 30,
    locale: "en_US"
  };
  return {
    init: function () {
      console.log( "Initializing the server" );
    },
    updateStartup: function( params ) {
      this.startupParams = params;
      console.log( this.startupParams.cacheTimeout );
      console.log( this.startupParams.locale );
    }
  };
})();
basicServerConfig.init(); //"Initializing the server"
basicServerConfig.updateStartup({cacheTimeout:60, locale:"en_UK"}); //60, en_UK
```

在这个例子中，`basicServerConfig`作为全局上下文中的一个模块创建。为了确保我们不会污染全局上下文，创建模块时命名空间很重要。此外，由于模块本质上是可以重用的，确保我们使用命名空间避免命名冲突也很重要。对于`basicServerConfig`模块，以下代码片段展示了创建命名空间的方法：

```js
// Single global object
var SERVER = SERVER||{};
SERVER.basicServerConfig = (function () {
  Var environment= "production";
  startupParams= {
    cacheTimeout: 30,
    locale: "en_US"
  };
  return {
    init: function () {
      console.log( "Initializing the server" );
    },
    updateStartup: function( params ) {
      this.startupParams = params;
      console.log( this.startupParams.cacheTimeout );
      console.log( this.startupParams.locale );
    }
  };
})();
SERVER.basicServerConfig.init(); //"Initializing the server"
SERVER.basicServerConfig.updateStartup({cacheTimeout:60, locale:"en_UK"}); //60, en_UK
```

使用命名空间与模块通常是好主意；然而，并不是说模块必须与命名空间相关联。

模块模式的一种变体试图克服原始模块模式的一些问题。这种改进的模块模式也被称为**揭示**模块模式（**RMP**）。RMP 最初由*Christian Heilmann*普及。他不喜欢在从另一个函数调用公共函数或访问公共变量时必须使用模块名。另一个小问题是，你必须在返回公共接口时使用对象字面量表示法。考虑以下示例：

```js
var modulePattern = function(){
  var privateOne = 1;
  function privateFn(){
    console.log('privateFn called');
  }
  return {
    publicTwo: 2,
    publicFn:function(){
      modulePattern.publicFnTwo();   
    },
    publicFnTwo:function(){
      privateFn();
    }
  }
}();
modulePattern.publicFn(); "privateFn called"
```

你可以看到，在`publicFn()`中我们需要通过`modulePattern`调用`publicFnTwo()`。此外，公共接口是以对象字面量返回的。改进经典的模块模式的就是所谓的 RMP。这个模式背后的主要思想是在私有作用域中定义所有成员，并返回一个匿名对象，该对象指向需要作为公共接口公开的私有功能。

让我们看看如何将我们之前的示例转换为 RMP。这个示例深受 Christian 博客的启发：

```js
var revealingExample = function(){
  var privateOne = 1;
  function privateFn(){
    console.log('privateFn called');
  }
  var publicTwo = 2;
  function publicFn(){
    publicFnTwo();    
  }
  function publicFnTwo(){
    privateFn();
  }
  function getCurrentState(){
    return 2;
  }
  // reveal private variables by assigning public pointers
  return {
    setup:publicFn,
    count:publicTwo,
    increaseCount:publicFnTwo,
    current:getCurrentState()
  };
}();
console.log(revealingExample.current); // 2
revealingExample.setup(); //privateFn called
```

在这里的一个重要区别是，你在私有作用域中定义函数和变量，并返回一个匿名对象，该对象指向你想作为公共接口公开的私有变量和函数。这是一个更干净的变体，应优先于经典模块模式。

然而，在生产代码中，你希望使用一种更标准的模块创建方法。目前，创建模块主要有两种方法。第一种被称为**CommonJS 模块**。CommonJS 模块通常更适合服务器端 JavaScript 环境，如**Node.js**。一个 CommonJS 模块包含一个`require()`函数，该函数接收模块的名称并返回模块的接口。该格式是由 CommonJS 的志愿者小组提出的；他们的目标是设计、原型化和标准化 JavaScript API。CommonJS 模块由两部分组成。首先，模块需要暴露的变量和函数列表；当你将一个变量或函数赋值给`module.exports`变量时，它就从模块中暴露出来。其次，一个`require`函数，模块可以使用它来导入其他模块的导出：

```js
//Add a dependency module 
var crypto = require('crypto');
function randomString(length, chars) {
  var randomBytes = crypto.randomBytes(length);
  ...
  ...
}
//Export this module to be available for other modules
module.exports=randomString;
```

CommonJS 模块在服务器端的 Node.js 和浏览器端的**curl.js**中得到支持。

JavaScript 模块的另一种形式被称为**异步模块定义**（**AMD**）。它们是以浏览器为首要目标的模块，并选择异步行为。AMD 使用一个`define`函数来定义模块。这个函数接受一个模块名称数组和一个函数。一旦模块被加载，`define`函数就带着它们的接口作为参数执行这个函数。AMD 提案旨在异步加载模块及其依赖项。`define`函数用于根据以下签名定义命名或未命名模块：

```js
define(
  module_id /*optional*/,
  [dependencies] /*optional*/,
  definition function /*function for instantiating the module or object*/
);
```

你可以如下添加一个无依赖的模块：

```js
define(
{ 
  add: function(x, y){ 
    return x + y; 
  } 
});
```

`require`模块的使用如下：

```js
require(["math","draw"], function ( math,draw ) {
  draw.2DRender(math.pi);
});
```

**RequireJS**([`requirejs.org/docs/whyamd.html`](http://requirejs.org/docs/whyamd.html))是实现 AMD 的模块加载器之一。

## ES6 模块

两种不同的模块系统和不同的模块加载器可能会让人感到有些害怕。ES6 试图解决这个问题。ES6 有一个拟定的模块规范，试图保留 CommonJS 和 AMD 模块模式的优点。ES6 模块的语法类似于 CommonJS，并且 ES6 模块支持异步加载和可配置的模块加载：

```js
//json_processor.js
function processJSON(url) {
  ...
}
export function getSiteContent(url) {
  return processJSON(url);
}
//main.js
import { getSiteContent } from "json_processor.js";
content=getSiteContent("http://google.com/");
```

ES6 导出允许你以类似于 CommonJS 的方式导出一个函数或变量。在需要使用这个导入的函数的代码中，你使用`import`关键字来指定你想从哪里导入这个依赖。一旦依赖被导入，它就可以作为程序的一个成员使用。我们将在后面的章节中讨论如何在不支持 ES6 的环境中使用 ES6。

# 工厂模式

工厂模式是另一种流行的对象创建模式。它不需要使用构造函数。这个模式提供了一个接口来创建对象。基于传递给工厂的类型，该特定类型的对象由工厂创建。这个模式的一个常见实现通常是使用类的构造函数或静态方法。这样的类或方法的目的如下：

+   它抽象了创建类似对象时的重复操作

+   它允许消费者不了解对象创建的内部细节就能创建对象

让我们举一个常见的例子来了解工厂的使用。假设我们有以下内容：

+   构造函数，`CarFactory()`

+   在`CarFactory`中有一个名为`make()`的静态方法，它知道如何创建`car`类型的对象

+   具体的`car`类型，如`CarFactory.SUV`、`CarFactory.Sedan`等

我们希望如下使用`CarFactory`：

```js
var golf = CarFactory.make('Compact');
var vento = CarFactory.make('Sedan');
var touareg = CarFactory.make('SUV');
```

以下是实现这样一个工厂的方法。以下实现相当标准。我们通过编程调用构造函数来创建指定类型的对象——`CarFactory[const].prototype = new CarFactory();`。

我们在映射对象类型到构造函数。实现这个模式可能有以下几种变化：

```js
// Factory Constructor
function CarFactory() {}
CarFactory.prototype.info = function() {
  console.log("This car has "+this.doors+" doors and a "+this.engine_capacity+" liter engine");
};
// the static factory method
CarFactory.make = function (type) {
  var constr 0= type;
  var car;
  CarFactory[constr].prototype = new CarFactory();
  // create a new instance
  car = new CarFactory[constr]();
  return car;
};

CarFactory.Compact = function () {
  this.doors = 4;
  this.engine_capacity = 2; 
};
CarFactory.Sedan = function () {
  this.doors = 2;
  this.engine_capacity = 2;
};
CarFactory.SUV = function () {
  this.doors = 4;
  this.engine_capacity = 6;
}; 
  var golf = CarFactory.make('Compact');
  var vento = CarFactory.make('Sedan');
  var touareg = CarFactory.make('SUV');
  golf.info(); //"This car has 4 doors and a 2 liter engine"
```

我们建议您在 JS Bin 中尝试这个例子，并通过实际编写代码来理解这个概念。

# 混入模式

混入有助于显著减少我们代码中的功能重复，并有助于功能重用。我们可以将共享功能移动到混入中，减少共享行为的重复。这样，您就可以专注于构建实际功能，而不必重复共享行为。让我们考虑以下示例。我们想要创建一个可以被任何对象实例使用的自定义日志记录器。日志记录器将成为需要在使用/扩展混入的对象之间共享的功能：

```js
var _ = require('underscore');
//Shared functionality encapsulated into a CustomLogger
var logger = (function () {
  var CustomLogger = {
    log: function (message) {
      console.log(message);
    }
  };
  return CustomLogger;
}());

//An object that will need the custom logger to log system specific logs
var Server = (function (Logger) {
  var CustomServer = function () {
    this.init = function () {
      this.log("Initializing Server...");
    };
  };

  // This copies/extends the members of the 'CustomLogger' into 'CustomServer'
  _.extend(CustomServer.prototype, Logger);
  return CustomServer;
}(logger));

(new Server()).init(); //Initializing Server...
```

在这个例子中，我们使用了来自**Underscore.js**的`_.extend`——我们在上一章讨论了这个函数。这个函数用于将源（`Logger`）的所有属性复制到目标（`CustomServer.prototype`）。正如您在这个例子中观察到的，我们创建了一个共享的`CustomLogger`对象，旨在被任何需要其功能的对象实例使用。这样一个对象是`CustomServer`——在其`init()`方法中，我们调用这个自定义日志记录器的`log()`方法。这个方法对`CustomServer`是可用的，因为我们通过 Underscore 的`extend()`将`CustomLogger`扩展到`CustomServer`。我们动态地将混入的功能添加到消费者对象中。理解混入和继承之间的区别很重要。当您在多个对象和类层次结构中有共享功能时，您可以使用混入。如果您在单一的类层次结构中有共享功能，您可以使用继承。在原型继承中，当你从原型继承时，对原型的任何更改都会影响继承原型的一切。如果您不想这样，可以使用混入。

# 装饰器模式

装饰器模式背后的主要思想是，你应以一个具有某些基本功能的普通对象开始你的设计。随着设计的演变，你可以使用现有的装饰器来增强你的普通对象。这是一种在面向对象世界中非常流行的模式，尤其是在 Java 中。让我们以`BasicServer`为例，这是一个具有非常基本功能的服务器。这些基本功能可以通过装饰来服务于特定目的。我们可以有两个不同的情况，这个服务器可以同时服务于 PHP 和 Node.js，并在不同的端口上提供服务。这些不同的功能是通过装饰基本服务器实现的：

```js
var phpServer = new BasicServer();
phpServer = phpServer.decorate('reverseProxy');
phpServer = phpServer.decorate('servePHP');
phpServer = phpServer.decorate('80');
phpServer = phpServer.decorate('serveStaticAssets');
phpServer.init();
```

节点服务器将具有以下内容：

```js
var nodeServer = new BasicServer();
nodeServer = nodeServer.decorate('serveNode');
nodeServer = nodeServer.decorate('3000');
nodeServer.init();
```

在 JavaScript 中实现装饰器模式有几种方法。我们将讨论一种方法，其中模式通过列表实现，不依赖于继承或方法调用链：

```js
//Implement BasicServer that does the bare minimum
function BasicServer() {
  this.pid = 1;
  console.log("Initializing basic Server");
  this.decorators_list = []; //Empty list of decorators
}
//List of all decorators
BasicServer.decorators = {};

//Add each decorator to the list of BasicServer's decorators
//Each decorator in this list will be applied on the BasicServer instance
BasicServer.decorators.reverseProxy = {
  init: function(pid) {
    console.log("Started Reverse Proxy");
    return pid + 1;
  }
};
BasicServer.decorators.servePHP = {
  init: function(pid) {
    console.log("Started serving PHP");
    return pid + 1;
  }
};
BasicServer.decorators.serveNode = {
  init: function(pid) {
    console.log("Started serving Node");
    return pid + 1;
  }
};

//Push the decorator to this list everytime decorate() is called
BasicServer.prototype.decorate = function(decorator) {
  this.decorators_list.push(decorator);
};
//init() method looks through all the applied decorators on BasicServer
//and executes init() method on all of them
BasicServer.prototype.init = function () {
  var running_processes = 0;
  var pid = this.pid;
  for (i = 0; i < this.decorators_list.length; i += 1) {
    decorator_name = this.decorators_list[i];
    running_processes = BasicServer.decorators[decorator_name].init(pid);
  }
  return running_processes;
};

//Create server to serve PHP
var phpServer = new BasicServer();
phpServer.decorate('reverseProxy');
phpServer.decorate('servePHP');
total_processes = phpServer.init();
console.log(total_processes);

//Create server to serve Node
var nodeServer = new BasicServer();
nodeServer.decorate('serveNode');
nodeServer.init();
total_processes = phpServer.init();
console.log(total_processes);
```

`BasicServer.decorate()`和`BasicServer.init()`是两个真正发生事情的方法。我们将所有要应用到`BasicServer`上的装饰器推送到`BasicServer`的装饰器列表中。在`init()`方法中，我们从这些装饰器列表中执行或应用每个装饰器的`init()`方法。这是一种不使用继承的更清洁的装饰器模式方法。这种方法在 Stoyan Stefanov 的书中《JavaScript 模式，O'Reilly 媒体》中有描述，因其简单性而在 JavaScript 开发者中得到了重视。

# 观察者模式

首先，让我们看看观察者模式的语言无关定义。在 GOF 的书中，《设计模式：可重用面向对象软件的元素》，定义观察者模式如下：

一个或多个观察者对主题的状态感兴趣，并通过附着自身向主题注册他们的兴趣。当主题中发生观察者可能感兴趣的变化时，会发送一个通知消息，调用每个观察者的更新方法。当观察者不再对主题的状态感兴趣时，他们可以简单地将自己分离。

在观察者设计模式中，主题保持一个依赖于它的对象列表（称为观察者），并在状态变化时通知它们。主题使用广播向观察者通知变化。观察者可以在不再希望收到通知时从列表中删除自己。基于这种理解，我们可以定义此模式中的参与者：

+   **主题**：它保持观察者的列表，并具有添加、删除和更新观察者的方法

+   **观察者**：为需要在主题状态变化时通知的对象提供接口

让我们创建一个可以添加、删除和通知观察者的主题：

```js
var Subject = ( function(  ) {
  function Subject() {
    this.observer_list = [];
  }
  // this method will handle adding observers to the internal list
  Subject.prototype.add_observer = function ( obj ) {
    console.log( 'Added observer' );
    this.observer_list.push( obj );
  };
  Subject.prototype.remove_observer = function ( obj ) {
    for( var i = 0; i < this.observer_list.length; i++ ) {
      if( this.observer_list[ i ] === obj ) {
        this.observer_list.splice( i, 1 );
        console.log( 'Removed Observer' );
      }
    }
  };
  Subject.prototype.notify = function () {
    var args = Array.prototype.slice.call( arguments, 0 );
    for( var i = 0; i<this.observer_list.length; i++ ) {
 this.observer_list[i].update(args);
    }
  };
  return Subject;
})();
```

这是一个相当直接实现的`Subject`。关于`notify()`方法的重要事实是，所有观察者对象`update()`方法的调用方式，以广播方式更新。

现在让我们定义一个创建随机推文的简单对象。这个对象提供了一个接口，通过 `addObserver()` 和 `removeObserver()` 方法向 `Subject` 添加和删除观察者。它还调用 `Subject` 的 `notify()` 方法，并传递新获取的推文。当这种情况发生时，所有观察者都会传播新推文已更新，新推文作为参数传递：

```js
function Tweeter() {
  var subject = new Subject();
  this.addObserver = function ( observer ) {
    subject.add_observer( observer );
  };
  this.removeObserver = function (observer) {
    subject.remove_observer(observer);
  };
  this.fetchTweets = function fetchTweets() {
    // tweet
    var tweet = {
      tweet: "This is one nice observer"
    };
    // notify our observers of the stock change
    subject.notify( tweet );
  };
}
```

现在让我们添加两个观察者：

```js
var TweetUpdater = {
  update : function() {
    console.log( 'Updated Tweet -  ', arguments );
  }
};
var TweetFollower = {
  update : function() {
    console.log( '"Following this tweet -  ', arguments );
  }
};
```

这两个观察者都只有一个 `update()` 方法，该方法将由 `Subject.notify()` 方法调用。现在我们实际上可以通过推特的界面将这些观察者添加到 `Subject` 中：

```js
var tweetApp = new Tweeter();
tweetApp.addObserver( TweetUpdater );
tweetApp.addObserver( TweetFollower );
tweetApp.fetchTweets();
tweetApp.removeObserver(TweetUpdater);
tweetApp.removeObserver(TweetFollower);
```

这将导致以下输出：

```js
Added observer
Added observer
Updated Tweet -   { '0': [ { tweet: 'This is one nice observer' } ] }
"Following this tweet -   { '0': [ { tweet: 'This is one nice observer' } ] }
Removed Observer
Removed Observer
```

这是一个基本的实现，用于说明观察者模式的思想。

# JavaScript 模型-视图*模式

**模型-视图-控制器**（**MVC**）、**模型-视图-呈现器**（**MVP**）和 **模型-视图-视图模型**（**MVVM**）在服务器应用程序中一直很受欢迎，但在最近几年，JavaScript 应用程序也开始使用这些模式来结构和管理工作量大的项目。许多 JavaScript 框架已经出现，支持 **MV*** 模式。我们将讨论使用 **Backbone.js** 的几个示例。

## 模型-视图-控制器

模型-视图-控制器（MVC）是一种流行的结构模式，其核心思想是将应用程序分为三个部分，以将信息的内部表示与表示层分离。MVC 包含组件。模型是应用程序对象，视图是底层模型对象的表示，控制器处理用户界面根据用户交互的行为。

## 模型

模型是代表应用程序中数据的构造。它们与用户界面或路由逻辑无关。模型更改通常通过遵循观察者设计模式来通知视图层。模型也可能包含用于验证、创建或删除数据的代码。当数据更改时自动通知视图层做出反应的能力使得像 Backbone.js、**Amber.js** 等框架在构建 MV* 应用程序时非常有用。以下示例向您展示了一个典型的 Backbone 模型：

```js
var EmployeeModel = Backbone.Model.extend({
  url: '/employee/1',
  defaults: {
    id: 1,
    name: 'John Doe',
    occupation: null
  }
  initialize: function() {
 }
}); var JohnDoe = new EmployeeModel();
```

这个模型结构可能在不同框架之间有所不同，但它们通常有一些共同点。在大多数现实世界中应用程序中，您希望您的模型被持久化到内存存储或数据库中。

## 视图

视图是您模型的视觉表示。通常，模型的状态在呈现给视图层之前进行处理、筛选或按摩。在 JavaScript 中，视图负责渲染和操作 DOM 元素。视图观察模型，并在模型发生变化时收到通知。当用户与视图交互时，通过视图层（通常通过控制器）更改模型的某些属性。在诸如 Backbone 的 JavaScript 框架中，视图是使用模板引擎（如**Handlebar.js**([`handlebarsjs.com/`](http://handlebarsjs.com/))或**mustache.js**([`mustache.github.io/`](https://mustache.github.io/)))创建的。这些模板本身并不是视图。它们观察模型，并根据这些变化保持视图状态更新。让我们来看一个用 Handlebar 定义的视图示例：

```js
<li class="employee_photo">
  <h2>{{title}}</h2>
  <img class="emp_headshot_small" src="img/{{src}}"/>
  <div class="employee_details">
    {{employee_details}}
  </div>
</li>
```

像前一个示例这样的视图包含包含模板变量的标记。这些变量通过自定义语法进行分隔。例如，在 Handlebar.js 中，模板变量使用`{{ }}`进行分隔。框架通常以 JSON 格式传输数据。视图如何从模型中填充由框架透明处理。

## 控制器

控制器作为模型和视图之间的层，负责当用户改变视图属性时更新模型。大多数 JavaScript 框架与经典定义的控制器有所偏离。例如，Backbone 没有一个叫做控制器的概念；他们有一个叫做**路由器**的东西，负责处理路由逻辑。你可以把视图和路由器的组合看作是一个控制器，因为很多同步模型和视图的逻辑都在视图本身内完成。一个典型的 Backbone 路由器如下所示：

```js
var EmployeeRouter = Backbone.Router.extend({
  routes: { "employee/:id": "route" },
  route: function( id ) {
    ...view render logic...
  }
});
```

# 模型-视图-呈现器模式

模型-视图-呈现器是我们之前讨论的原始 MVC 模式的一种变体。MVC 和 MVP 都旨在分离关注点，但在很多基本方面它们是不同的。MVP 中的呈现器具有视图所需的必要逻辑。视图的任何调用都会委派给呈现器。呈现器还观察模型，并在模型更新时更新视图。许多作者认为，因为呈现器将模型与视图绑定在一起，所以它也执行了传统控制器的角色。有各种 MVP 的实现方式，而且没有框架提供开箱即用的经典 MVP。在 MVP 的实现中，以下是一些将 MVP 与 MVC 分开的主要区别：

+   视图没有参考模型

+   呈现器有一个模型参考，并在模型变化时负责更新视图

MVP 通常有两种实现方式：

+   被动视图：视图尽可能天真，所有的业务逻辑都在呈现器中。例如，一个简单的 Handlebars 模板可以被视为一个被动视图。

+   监控控制器：视图中大多包含声明性逻辑。当视图中的简单声明性逻辑不足时，由呈现器接管。

下面的图表描述了 MVP 架构：

![模型-视图-呈现器模式](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00009.jpeg)

# 模型-视图-视图模型

MVVM 最初是由微软为与**Windows Presentation Foundation** (**WPF**) 和 **Silverlight** 使用而提出的。MVVM 是 MVC 和 MVP 的一个变种，并进一步试图将用户界面（视图）与业务模型和应用程序行为分离。MVVM 在 MVC 和 MVP 中讨论的领域模型之上创建了一个新的模型层。这个模型层将属性作为视图的接口。假设我们 UI 上有复选框。复选框的状态被捕捉到一个`IsChecked`属性中。在 MVP 中，视图会有这个属性，呈现器会设置它。然而，在 MVVM 中，呈现器会有`IsChecked`属性，视图负责与它同步。既然呈现器实际上并没有做传统呈现器的工作，它被重新命名为视图模型：

![模型-视图-视图模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00010.jpeg)

这些方法的实现细节取决于我们试图解决的问题和所使用的框架。

# 摘要

在构建大型应用程序时，我们会看到某些问题模式一次又一次地重复。这些问题模式有定义良好的解决方案，可以复用以构建健壮的解决方案。在本章中，我们讨论了一些关于这些模式的重要模式和思想。大多数现代 JavaScript 应用程序使用这些模式。在一个大型系统中不实现模块、装饰器、工厂或 MV*模式的情况很少见。这些是我们本章讨论的基础思想。下一章我们将讨论各种测试和调试技术。
