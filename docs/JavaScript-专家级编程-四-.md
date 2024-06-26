# JavaScript 专家级编程（四）

> 原文：[`zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD`](https://zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：高级 JavaScript

## 学习目标

在本章结束时，您将能够：

+   使用 Node.js REPL 测试简单脚本

+   构造对象和数组并修改它们的内容

+   使用对象方法和运算符获取有关对象的信息

+   创建简单的 JavaScript 类和继承自其他类的类

+   使用 Math、RegEx、Date 和 String 的高级内置方法

+   使用数组、Map 和 Set 方法在 JavaScript 中操作数据

+   实现符号、迭代器、生成器和代理

在本章中，我们将使用 JavaScript 中的数组、类和对象，然后我们将使用继承和常见 JavaScript 类中的内置方法来简化我们的代码并使其高度可重用。

## 介绍

在为中大型项目（10+个文件）编写 JavaScript 代码时，了解语言提供的所有可能特性是有帮助的。使用已有的东西总比重新发明轮子更容易更快。这些内置方法不仅可以帮助您执行基本功能，还可以帮助提高代码的可读性和可维护性。这些内置方法涵盖了从基本计算到开发人员每天面临的复杂数组和字符串操作。通过使用这些内置方法，我们可以减少代码大小，并帮助提高应用程序的性能。

JavaScript 通常用作函数式语言，但您也可以将其用于**面向对象编程**（**OOP**）。近年来，为了满足 JavaScript 完成更复杂和数据驱动的任务的不断增长的需求，语言中添加了许多新功能，例如类。虽然仍然可以使用函数原型创建 JavaScript，但许多开发人员已经放弃了这样做，因为它提供了更接近流行的 OOP 语言（如 C++、Java 和 C#）的语法。

在本章中，我们将探索 JavaScript 提供的大量内置方法。我们将使用 Node.js **REPL**（**读取-求值-打印循环**）来测试我们的代码，因为这不需要我们在磁盘上创建任何文件或调用任何特殊命令。

## ES5、ES6、ES7、ES8 和 ES9 支持的语言特性

在我们深入了解这些令人惊奇的语言特性之前，让我们先看一下不同版本的 JavaScript。目前，大多数您经常遇到的支持旧版浏览器的网站使用 ES5。截至 2019 年，许多主流浏览器已经添加了对 ES6 的支持。后续版本将只有最小的浏览器支持。由于我们将在 Node.js 运行时中运行和测试我们的代码，只要我们使用最新的 LTS（长期支持）版本的 Node.js，就不必担心版本兼容性。关于本章将使用的材料，以下是您的运行时需要支持的最低 ES 版本的详细说明：

![图 7.1：最低要求的 ES 版本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_01.jpg)

###### 图 7.1：最低要求的 ES 版本

在本章中，我们不会切换运行时，但在将来，在开始之前最好先检查您要开发的运行时的语言支持。

### 在 Node.js REPL 中工作

在本章中，我们不会做任何太复杂的事情，所以我们将在`Node.js` REPL 中编写我们的代码。这样可以让我们在开始编码之前测试一些想法，而无需创建任何文件。在开始之前，请确保您的计算机上已安装了 Node.js，并且已打开终端应用程序。

### 执行 Node.js REPL

每个 Node.js 安装都包括一个 node 可执行文件，允许您运行本地 JavaScript 文件或启动 REPL。要将 Node.js 可执行文件作为 REPL 运行，您只需在您喜欢的终端中输入`node`命令，不带任何参数。要测试我们的 Node.js 安装，您可以运行`node -v`命令：

![图 7.2：测试 Node.js 安装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_02.jpg)

###### 图 7.2：测试 Node.js 安装

如果你看到这样的输出，这意味着你已经正确安装了`Node.js`。

#### 注意

这个命令输出当前运行的`Node.js`运行时版本，因此这也是一个非常好的检查当前版本的方法。对于本书，我们将使用当前的 LTS，即 v10.16.0。

在验证了我们的 Node.js 安装之后，要以 REPL 模式运行 node 命令，你只需要在命令提示符中输入`node`：

![图 7.3：在 REPL 模式下运行 node 命令](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_03.jpg)

###### 图 7.3：在 REPL 模式下运行 node 命令

如果你看到一个等待你输入的光标，恭喜你——你已经成功进入了 Node.js 的 REPL 模式！从现在开始，你可以开始在提示符中输入代码，然后按 Enter 键进行评估。

### JavaScript 中的数组操作

在 JavaScript 中创建数组并修改其内容非常容易。与其他语言不同，在 JavaScript 中创建数组不需要指定数据类型或大小，因为这些可以在以后根据需要更改。

要创建一个 JavaScript 数组，请使用以下命令：

```js
const jsArray = [];
```

请注意，在 JavaScript 中，不需要定义数组中的大小或类型。

要创建一个具有预定义元素的数组，请使用以下命令：

```js
const foodList = ['sushi', 'fried chicken', 21];
```

要访问和修改数组中的项目，请使用以下命令：

```js
const sushi = foodList[0];
foodList[2] = 'steak';
```

这与访问数组时其他编程语言非常相似。

### 练习 37：创建和修改数组中的项目

在这个练习中，我们将创建一个简单的数组，并使用 REPL 来探索它的值。创建数组的语法与许多其他脚本语言非常相似。我们将以两种方式创建`singers`数组：一种是使用`Array`构造函数，另一种是使用数组文字方式。一旦我们创建了数组，我们将操纵数组的内容。让我们开始吧：

1.  使用数组文字方法创建一个空数组并测试它是否成功创建后：

```js
> let exampleArray1 = [];
=> undefined
> Array.isArray(exampleArray1);
=> true
```

1.  现在，我们将使用`Array`构造函数来做同样的事情。虽然它们产生相同的结果，但构造函数允许更多的灵活性：

```js
> let exampleArray2 = new Array();
=> undefined
> Array.isArray(exampleArray2);
=> true
```

请注意，我们没有使用`typeof`来检查数组的类型，因为在 JavaScript 中，数组是对象的一种类型。如果我们在刚刚创建的数组上使用`typeof`，我们会得到一个意外的结果：

```js
> let exampleArray3 = [];
=> undefined
> typeof exampleArray3
=> 'object'
```

1.  创建具有预定义大小和项目的数组。请注意，随着向数组添加项目，JavaScript 数组将自动调整大小：

```js
> let exampleArray4 = new Array(6)
=> undefined
> exampleArray4
=> [ <6 empty items> ]
or
> let singers = new Array(6).fill('miku')
=> undefined
> singers
=> [ 'miku', 'miku', 'miku', 'miku', 'miku', 'miku' ]
```

正如你所看到的，我们初始化了一个具有初始大小为`6`的数组。我们还使用了`fill`方法来预定义数组中的所有项目。当我们想要使用数组来跟踪应用程序中的标志时，这是非常有用的。

1.  为索引`0`分配一个值：

```js
> singers[0] = 'miku'
=> 'miku'
> singers
=> [ 'miku' ]
```

1.  为 JavaScript 数组分配任意索引。未分配的索引将简单地是`undefined`：

```js
> singers[3] = 'luka'
=> 'luka'
> singers[1]
=> undefined
```

1.  使用数组的长度修改数组末尾的项目：

```js
> singers[singers.length - 1] = 'rin'
=> 'rin'
> singers
=> [ 'miku', 'miku', 'miku', 'miku', 'miku', 'rin' ]
```

因此，我们已经学会了如何在 JavaScript 中定义数组。这些数组的行为类似于其他语言，它们也会自动扩展，因此你不必担心手动调整数组的大小。在下一个练习中，我们将讨论如何向数组中添加项目。

### 练习 38：添加和删除项目

在 JavaScript 中，很容易添加和删除数组中的项目，在许多应用程序中我们必须累积许多项目。在这个练习中，我们将修改之前创建的`singers`数组。让我们开始吧：

1.  从一个空数组开始：

```js
> let singers = [];
=> undefined
```

1.  使用`push`在数组末尾添加一个新项目：

```js
> singers.push('miku')
=> 1
> singers
=> [ 'miku' ]
```

`push`方法将始终将项目添加到数组的末尾，即使数组中有`undefined`的项目：

```js
> let food = new Array(3)
=> undefined
> food.push('burger')
=> 4
> food
=> [ <3 empty items>, 'burger' ]
```

如你在上面的代码中所看到的，如果你有一个预定义大小的数组，使用`push`将会扩展数组并将其添加到数组的末尾，而不是只将其添加到开头

1.  从数组末尾删除一个项目：

```js
> singers.push('me')
=> 2
> singers
=> [ 'miku', 'me' ]
> singers.pop()
=> 'me'
> singers
=> [ 'miku' ]
```

1.  在数组开头添加一个项目：

```js
> singers.unshift('rin')
=> 2
> singers
=> [ 'rin', 'miku' ]
```

1.  从数组的开头移除项目：

```js
> singers.shift()
=> 'rin'
> singers
=> [ 'miku' ]
```

在更大规模的应用程序中，这些非常有用，比如如果您正在构建一个处理图像的简单 Web 应用程序。当请求到来时，您可以将图像数据、作业 ID 甚至客户端连接推送到数组中，这意味着 JavaScript 数组可以是任何类型。您可以有另一个工作人员在数组上调用`pop`来检索作业，然后处理它们。

### 练习 39：获取数组中项目的信息

在这个练习中，我们将介绍获取有关数组中项目的各种基本方法。当我们在处理需要操作数据的应用程序时，这些函数非常有帮助。让我们开始吧：

1.  创建一个空数组并向其中推送项目：

```js
> let foods = []
=> undefined
> foods.push('burger')
=> 1
> foods.push('fries')
=> 2
> foods.push('wings')
=> 3
```

1.  查找项目的索引：

```js
> foods.indexOf('burger')
=> 0
```

1.  查找数组中项目的数量：

```js
> foods.length
=> 3
```

1.  从数组中的特定索引中移除一个项目。我们将通过将要移除的项目的位置存储到一个变量中来实现这一点。知道我们要移除项目的位置后，我们可以调用`array.splice`来移除它：

```js
> let position = foods.indexOf('burger')
=> undefined
> foods.splice(position, 1) // splice(startIndex, deleteCount)
=> [ 'burger' ]
> foods
=> [ 'fries', 'wings' ]
```

#### 注意

`array.splice`也可以用于在特定索引处插入/替换项目到数组中。我们将在后面详细介绍该函数的具体情况。当我们使用它时，我们提供它两个参数。第一个告诉 splice 从哪里开始，下一个告诉它从起始位置删除多少个项目。因为我们只想删除该索引处的项目，所以我们提供 1。

在这个练习中，我们探讨了获取有关数组更多信息的方法。尝试定位特定项目的索引在构建应用程序中非常有用。使用这些内置方法非常有用，因为您不需要通过数组来查找项目。在下一个活动中，我们将使用用户的 ID 构建一个简单的用户跟踪器。

### 活动 8：创建用户跟踪器

假设您正在构建一个网站，并且想要跟踪当前有多少人正在查看它。为了做到这一点，您决定在后端保留一个用户列表。当用户打开您的网站时，您将更新列表以包括该用户，当该用户关闭您的网站时，您将从列表中删除该用户。

对于此活动，我们将有一个名为`users`的列表，其中存储了一系列字符串，以及一些辅助函数来帮助存储和删除列表中的用户。

为了做到这一点，我们需要定义一个函数，该函数接受我们的用户列表并对其进行修改以符合我们的要求。

完成此活动的步骤如下：

1.  创建`Activity08.js`文件。

1.  定义一个`logUser`函数，它将添加用户到提供的`userList`参数中，并确保不添加重复项。

1.  定义一个`userLeft`函数。它将从提供的`userList`参数中移除用户。

1.  定义一个`numUsers`函数，它返回当前列表中的用户数量。

1.  定义一个名为`runSite`的函数。这将用于测试我们的实现。

#### 注意

此活动的解决方案可在第 607 页找到。

在这个活动中，我们探讨了在 JavaScript 中使用数组完成某些任务的一种方式。我们可以使用它来跟踪项目列表，并使用内置方法来添加和删除项目。我们看到**user3**、**user5**和**user6**是因为这些用户从未被移除。

### JavaScript 中的对象操作

在 JavaScript 中创建基本对象非常容易，并且对象在每个 JavaScript 应用程序中都被使用。JavaScript 对象还包括一系列内置方法供您使用。当我们编写代码时，这些方法非常有帮助，因为它使得在 JavaScript 中开发非常容易和有趣。在本节中，我们将研究如何在我们的代码中创建对象以及如何最大限度地利用它们的潜力。

要在 JavaScript 中创建一个对象，请使用以下命令：

```js
const myObj = {};
```

通过使用`{}`符号，我们正在定义一个空对象并将其分配给我们的变量名。

我们可以使用对象在我们的应用程序中存储许多键值对的数字：

```js
myObj.item1 = 'item1';
myObj.item2 = 12;
```

如果我们想要访问值，这也很容易：

```js
const item = myObj.item1;
```

在 JavaScript 中，创建对象并不意味着必须遵循特定的模式。您可以在对象中放入任意数量的属性。只需确保对象键没有重复：

```js
> dancers = []
=> undefined
> dancers.push({ name: 'joey', age: 30 })
=> undefined
```

请注意，新对象的语法与 JSON 表示法非常相似。有时我们需要确切知道对象中有什么样的信息。

您可以创建一个具有一些属性的用户对象：

```js
> let myConsole = { name: 'PS4', color: 'black', price: 499, library: []}
=> undefined
```

要获取所有属性名称，您需要使用`keys`方法，如下所示：

```js
> Object.keys(myConsole)
=> [ 'name', 'color', 'price', 'library' ]
```

我们还可以测试属性是否存在。让我们检查尚未定义的属性：

```js
> if (myConsole.ramSize) {
... console.log('ram size is defined.');
... }
> undefined
```

现在，让我们检查我们之前定义的属性：

```js
> if (myConsole.price) {
... console.log('price is defined.');
... }
> price is defined.
```

这是测试属性是否存在于对象中的一种非常简单的方法。在许多应用程序中，这经常用于检查字段的存在性，如果不存在，则将设置默认值。只需记住，在 JavaScript 中，空字符串、空数组、数字零和其他虚假值将被`if`语句评估为`false`。在下一个练习中，我们将尝试创建一个包含大量信息并从中输出非常有用信息的对象。

### 练习 40：在 JavaScript 中创建和修改对象

在这个练习中，我们将在数组中存储对象，并通过对对象进行更改来修改数组。然后，我们将检查如何使用其属性访问对象。我们将继续使用之前定义的`singers`数组，但这次不仅存储字符串列表，而是使用对象。让我们开始吧：

1.  将`singers`数组设置为空数组：

```js
> singers = []
=> undefined
```

1.  将对象推送到数组中：

```js
> singers.push({ name: 'miku', age: 16 })
=> undefined
```

1.  修改数组中第一个对象的`name`属性：

```js
> singers[0].name = 'Hatsune Miku'
=> 'Hatsune Miku'
> singers
=> [ { name: 'Hatsune Miku', age: 16 } ]
```

修改对象中的值非常简单；例如，您可以将任何值分配给属性，但不仅如此。您还可以添加原本不是对象一部分的属性，以扩展其信息。

1.  向对象添加一个名为`birthday`的属性：

```js
> singers[0].birthday = 'August 31'
=> 'August 31'
> singers
=> [ { name: 'Hatsune Miku', age: 16, birthday: 'August 31' } ]
```

要向现有对象添加属性，只需将值分配给属性名称。如果该属性不存在，将创建该属性。您可以将任何值分配给属性，函数、数组或其他对象。

1.  通过执行以下代码读取对象中的属性：

```js
> singers[0].name
=> 'Hatsune Miku'
or
> const propertyName = 'name'
=> undefined
> singers[0][propertyName]
=> 'Hatsune Miku'
```

正如您所看到的，访问 JavaScript 对象的属性值非常简单。如果您已经知道值的名称，只需使用点表示法。在某些情况下，属性名称是动态的或来自变量，您可以使用括号表示法来访问该属性名称的属性值。

在这个练习中，我们讨论了在 JavaScript 中创建对象的方法以及如何修改和添加属性。JavaScript 对象和数组一样，非常容易修改，而且不需要您指定模式。在下一个活动中，我们将构建一个非常有趣的实用程序，可以帮助您了解对象在网络中的工作方式以及如何有效地使用它们。

### JSON.stringify

`JSON.stringify`是一个非常有用的实用程序，它将 JavaScript 对象转换为格式化的字符串。稍后，可以通过网络传输字符串。

例如，假设我们有一个`user`对象，我们想将其转换为字符串：

```js
const user = {
   name: 'r1cebank',
   favoriteFood: [
      'ramen',
      'sushi',
      'fried chicken'
   ]
};
```

如果我们想要将对象转换为字符串，我们需要使用`JSON.stringify`调用此对象，如下面的代码所示：

```js
JSON.stringify(user);
```

我们将得到这样的结果：

![图 7.4：使用 JSON.stringify 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_04.jpg)

###### 图 7.4：使用 JSON.stringify 的结果

正如您所看到的，调用`JSON.stringify`已将我们的对象转换为对象的字符串表示。

但由于它的实现方式，`JSON.stringify`非常低效。尽管在大多数应用程序中性能差异并不明显，在高性能应用程序中，性能确实很重要。使`JSON.stringify`更快的一种方法是知道你需要最终输出中的哪些属性。

### 练习 41：创建一个高效的 JSON.Stringify

我们的目标是编写一个简单的函数，该函数接受一个对象和要包含在最终输出中的属性列表。然后，该函数将调用`JSON.stringify`来创建对象的字符串版本。让我们在`Exercise41.js`文件中定义一个名为`betterStringify`的函数：

1.  创建`betterStringify`函数：

```js
function betterStringify(item, propertyMap) {
}
```

1.  现在，我们将创建一个临时输出。我们将存储我们想要包含在`propertyMap`中的属性：

```js
let output = {};
```

1.  遍历我们的`propertyMap`参数以挑选我们想要包含的属性：

```js
propertyMap.forEach((key) => {
});
```

因为我们的`propertyMap`参数是一个数组，我们希望使用`forEach`来对其进行迭代。

1.  将值从我们的项目分配给临时输出：

```js
propertyMap.forEach((key) => {
if (item[key]) {
   output[key] = item[key];
}
});
```

在这里，我们正在检查我们的`propertyMap`参数中的键是否已设置。如果已设置，我们将把值存储在我们的`output`属性中。

1.  在测试对象上使用一个函数：

```js
const singer = {
 name: 'Hatsune Miku',
 age: 16,
 birthday: 'August 31',
 birthplace: 'Sapporo, Japan',
 songList: [
  'World is mine',
  'Tell your world',
  'Melt'
 ]
}
console.log(betterStringify(singer, ['name', 'birthday']))
```

完成函数后，运行文件将产生以下输出：

![图 7.5：运行 better_stringify.js 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_05.jpg)

###### 图 7.5：运行 Exercise41.js 的输出

现在，是时候回答一个棘手的问题了：如果你像这样做了一些事情，你的代码会有多快？

如果你对此进行基准测试，你会看到比`JSON.stringify`快 30%的性能提升：

![图 7.6 JSON.stringify 和我们的方法之间的性能差异](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_06.jpg)

###### 图 7.6：JSON.stringify 和我们的方法之间的性能差异

这是你可以用来挑选属性而不是使用`JSON.stringify`来转储所有内容的一个非常基本的例子。

### 数组和对象的解构赋值

在之前的练习和活动中，我们讨论了修改对象和数组中的值的基本方法，以及从中获取更多信息的方法。还有一种方法可以使用**解构赋值**从数组或对象中检索值。

假设你已经得到了一个需要分配给变量的参数列表：

```js
const param = ['My Name', 12, 'Developer'];
```

一种分配它们的方法是访问数组中的每个项目：

```js
const name = param[0];
const age = param[1];
const job = param[2];
```

我们还可以使用解构赋值将其简化为一行：

```js
[name, age, job] = param;
```

### 练习 42：使用数组的解构赋值

在这个练习中，我们将声明一个名为`userInfo`的数组。它将包括基本的用户信息。我们还将声明一些变量，以便我们可以使用解构赋值将数组中的项目存储起来。让我们开始吧：

1.  创建`userInfo`数组：

```js
> const userInfo = ['John', 'chef', 34]
=> undefined
```

1.  创建用于存储`name`、`age`和`job`的变量：

```js
> let name, age, job
=> undefined
```

1.  使用解构赋值语法将值分配给我们的变量：

```js
> [name, job, age] = userInfo
=> [ 'John', 'chef', 34 ]
```

检查我们的值：

```js
> name
=> 'John'
> job
=> 'chef'
> age
=> 34
```

1.  你还可以使用以下代码忽略数组中的值：

```js
> [name, ,age] = userInfo
=> [ 'John', 'chef', 34 ] // we ignored the second element 'chef'
```

解构赋值在处理数据时非常有用，因为数据的格式通常不是你所期望的。它还可以用来挑选数组中你想要的项目。

### 练习 43：使用对象的解构赋值

在之前的练习中，我们声明了一个包含用户信息的数组，并使用解构赋值从中检索了一些值。同样的事情也可以用于对象。在这个练习中，我们将尝试对对象使用解构赋值。让我们开始吧：

1.  创建一个名为`userInfo`的对象：

```js
> const userInfo = { name: 'John', job: 'chef', age: 34 }
=> undefined
```

1.  创建我们将用来存储信息的变量：

```js
> let name, job
=> undefined
```

1.  使用解构赋值语法来分配值：

```js
> ({ name, job } = userInfo)
=> { name: 'John', job: 'chef', age: 34 }
```

1.  检查这些值：

```js
> name
=> 'John'
> job
=> 'chef'
```

请注意，在对象上使用解构赋值时，它的作用类似于一个过滤器，其中变量名必须匹配，并且您可以有选择地选择要选择的数组中的属性。还有一种不需要预先声明变量的对象使用方式。

1.  使用数组进行解构赋值：

```js
> userInfo = ['John', 'chef', 34]
=> undefined
> [ name, , age] = userInfo
=> undefined
> name
=> 'John'
> age
=> 34
```

1.  使用解构运算符从对象值创建变量：

```js
> const userInfoObj = { name: 'John', job: 'chef', age: 34 }
=> undefined
> let { job } = userInfoObj
=> undefined
> job
=> 'chef'
```

以下是前面代码的输出：

![图 7.7：作业变量的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_07.jpg)

###### 图 7.7：作业变量的输出

在这个练习中，我们讨论了如何使用解构运算符从对象和数组中提取特定信息。当我们处理大量信息并且只想传输该信息的子集时，这非常有用。

### 展开运算符

在上一个练习中，我们讨论了从对象或数组中获取特定信息的一些方法。还有另一个运算符可以帮助我们展开数组或对象。展开运算符被添加到 ES6 规范中，但在 ES9 中，它还添加了对对象展开的支持。展开运算符的功能是将每个项目展开为单独的项目。对于数组，当我们使用展开运算符时，我们可以将其视为单独值的列表。对于对象，它们将展开为键值对。在下一个练习中，我们将探索在应用程序中使用展开运算符的不同方式。

要使用展开运算符，我们在任何可迭代对象之前使用三个点（`…`），就像这样：

```js
printUser(...userInfo)
```

### 练习 44：使用展开运算符

在这个练习中，我们将看到展开运算符如何帮助我们。我们将使用上一个练习中的原始`userInfo`数组。

执行以下步骤完成练习：

1.  创建`userInfo`数组：

```js
> const userInfo = ['John', 'chef', 34]
=> undefined
```

1.  创建一个打印用户信息的函数：

```js
> function printUser(name, job, age) {
... console.log(name + ' is working as ' + job + ' and is ' + age + ' years old');
... }
=> undefined
```

1.  将数组展开为参数列表：

```js
> printUser(...userInfo)
John is working as chef and is 34 years old
```

正如你所看到的，调用这个函数的原始方式，没有使用展开运算符，是使用数组访问运算符，并为每个参数重复这样做。由于数组的排序与相应的参数匹配，我们可以只使用展开运算符。

1.  当你想要合并数组时使用展开运算符：

```js
> const detailedInfo = ['male', ...userInfo, 'July 5']
=> [ 'male', 'John', 'chef', 34, 'July 5' ]
```

1.  使用展开运算符作为复制数组的一种方式：

```js
> let detailedInfoCopy = [ ...detailedInfo ];
=> undefined
> detailedInfoCopy
=> [ 'male', 'John', 'chef', 34, 'July 5' ]
```

在对象上使用展开运算符要强大得多且实用。

1.  创建一个名为`userRequest`的新对象：

```js
> const userRequest = { name: 'username', type: 'update', data: 'newname'}
=> undefined
```

1.  使用`object`展开克隆对象：

```js
> const newObj = { ...userRequest }
=> undefined
> newObj
=> { name: 'username', type: 'update', data: 'newname' }
```

1.  创建一个包含此对象的每个属性的对象：

```js
> const detailedRequestObj = { data: new Date(), new: true, ...userRequest}
=> undefined
> detailedRequestObj
=> { data: 'newname', new: true, name: 'username', type: 'update' }
```

您可以看到，当您想要复制所有属性到一个新对象时，展开运算符非常有用。您可以在许多应用程序中看到它的使用，其中您希望用一些通用属性包装用户请求以进行进一步处理。

### 剩余运算符

在上一节中，我们看了展开运算符。同样的运算符也可以以不同的方式使用。在函数声明中，它们被称为**剩余运算符**。

剩余运算符主要用于表示无限数量的参数。然后，参数将被放入一个数组中：

```js
function sum(...numbers) {
   console.log(numbers);
}
sum(1, 2, 3, 4, 5, 6, 7, 8, 9);
```

正如你所看到的，我们在名称前使用了相同的三个点。这告诉我们的代码，我们期望这个函数有无限数量的参数。当我们使用参数列表调用函数时，它们将被放入一个 JavaScript 数组中：

![图 7.8：当使用数字列表调用 sum 时的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_08.jpg)

###### 图 7.8：当使用数字列表调用 sum 时的输出

这并不意味着你对参数的数量没有任何控制。您可以像这样编写函数声明，让 JavaScript 将多个参数映射到您喜欢的方式，并将其余参数放入数组中：

```js
function sum(initial, ...numbers) {
   console.log(initial, numbers);
}
```

这将第一个参数映射到名为 initial 的变量，其余参数映射到名为`numbers`的数组：

```js
sum(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
```

以下是前面代码的输出：

![图 7.9：当使用 0 和 1-9 调用 sum 时的输出。](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_09.jpg)

###### 图 7.9：调用 0 和 1-9 时 sum 的输出。

## JavaScript 中的面向对象编程

由于 JavaScript 在 Web 开发中的流行，它主要以一种功能性的方式使用。这导致许多开发人员认为在 JavaScript 中没有办法进行面向对象编程。甚至在 ES6 标准发布之前，已经有一种定义类的方式：使用函数。您可能在旧版前端代码中看到过这种定义类的方式。例如，如果您想创建一个名为`Food`的类，您将不得不写类似于这样的代码：

```js
function Food(name) {
   this.name = name;
}
var leek = new Food("leek");
console.log(leek.name); // Outputs "leek"
```

在 ES6 发布后，越来越多的开发人员采用了使用`class`关键字编写现代 JavaScript 类的方式。在本章中，我们将介绍使用 ES6 标准声明类的方法。

### 在 JavaScript 中定义类

在我们深入讨论 JavaScript 中定义类的最新语法之前，让我们先了解 ES6 之前的做法。

在 ES6 之前用于定义类的语法如下：

```js
function ClassName(param1, param2) {
   // Constructor Logic
}
```

本质上，我们正在定义`constructor`类。函数的名称将是类的名称。

使用 ES6 定义类的语法如下：

```js
class ClassName {
   constructor(param1, param2) {
      // Constructor logic
   }
   method1(param) {
      // Method logic
   }
}
```

这通常是我们在其他语言中对类定义所做的事情。在这里，我们可以定义一个构造函数和一个方法。

### 练习 45：使用函数声明对象构造函数

在这个练习中，我们将创建一个非常简单的名为`Food`的类。稍后，我们还将为类添加一些方法。我们将在这里使用函数构造方法。让我们开始吧：

1.  定义`Food`构造函数：

```js
function Food(name, calories, cost) {
   this.name = name;
   this.calories = calories;
   this.cost = cost;
}
```

1.  将方法添加到构造函数中：

```js
Food.prototype.description = function () {
   return this.name + ' calories: ' + this.calories;
}
```

1.  使用`Food`构造函数创建一个新对象：

```js
let burger = new Food('burger', 1000, 9);
```

1.  调用我们声明的方法：

```js
console.log(burger.description());
```

以下是前面代码的输出：

![图 7.10：burger.description()方法的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_10.jpg)

###### 图 7.10：burger.description()方法的输出

你们中的许多人可能熟悉这种类声明的方式。但这也会带来问题。首先，使用函数作为构造函数会让开发人员不清楚何时将函数视为函数，何时将其视为构造函数。后来，当 JavaScript 发布了 ES6 时，它引入了一种新的声明类的方式。在下一个练习中，我们将使用新的方法来声明`Food`类。

### 练习 46：在 JavaScript 中创建一个类

在这个练习中，我们将在 JavaScript 中创建一个类定义来存储食物数据。它将包括一个名称、成本和卡路里计数。稍后，我们还将创建一些返回食物描述的方法，以及另一个静态方法来输出特定食物的卡路里。让我们开始吧：

1.  声明一个`Food`类：

```js
class Food {
}
```

1.  对类名运行`typeof`以查看它的类型：

```js
console.log(typeof Food) // should print out 'function'
```

以下是前面代码的输出：

![图 7.11：在类上运行 typeof 命令](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_11.jpg)

###### 图 7.11：在类上运行 typeof 命令

正如您所看到的，我们刚刚声明的新类的类型是`function` - 这不是很有趣吗？这是因为在 JavaScript 内部，我们声明的类只是另一种编写`constructor`函数的方式。

1.  让我们添加我们的`constructor`：

```js
class Food {
   constructor(name, calories, cost) {
      this.name = name;
      this.calories = calories;
      this.cost = cost;
   }
}
```

就像任何其他语言一样，类定义将包括一个构造函数，使用`new`关键字调用它来创建这个类的实例。

1.  在类定义中编写`description`方法：

```js
class Food {
   constructor(name, calories, cost) {
      this.name = name;
      this.calories = calories;
      this.cost = cost;
   }
   description() {
      return this.name + ' calories: ' + this.calories;
   }
}
```

1.  如果您尝试像调用函数一样调用`Food`类构造函数，它将抛出以下错误：

```js
Food('burger', 1000, 9);
// TypeError: Class constructor Food2 cannot be invoked without 'new'
```

以下是前面代码的输出：

![图 7.12：以函数方式调用构造函数的 TypeError](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_12.jpg)

###### 图 7.12：以函数方式调用构造函数的 TypeError

请注意，当您尝试将构造函数作为函数调用时，运行时会抛出错误。这非常有帮助，因为它可以防止开发人员错误地将构造函数作为函数调用。

1.  使用类构造函数创建一个新的食物对象：

```js
let friedChicken = new Food('fried chicken', 520, 5);
```

1.  调用我们声明的方法：

```js
console.log(friedChicken.description());
```

1.  声明`static`方法，它返回卡路里数：

```js
class Food {
   constructor(name, calories, cost) {
      this.name = name;
      this.calories = calories;
      this.cost = cost;
   }
   static getCalories(food) {
      return food.calories
   }
   description() {
      return this.name + ' calories: ' + this.calories;
   }
}
```

1.  使用我们刚刚创建的对象调用`static`方法：

```js
console.log(Food.getCalories(friedChicken)); /// 520
```

以下是前面代码的输出：

![图 7.13：调用 Food 类的静态方法后生成的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_13.jpg)

###### 图 7.13：调用 Food 类的静态方法后生成的输出

与任何其他编程语言一样，您可以在不实例化对象的情况下调用`static`方法。

现在我们已经看过了在 JavaScript 中声明类的新方法，让我们谈谈一些类声明的不同之处：

+   构造函数方法是必需的。 如果您没有声明一个，JavaScript 将添加一个空构造函数。

+   类声明不会被提升，这意味着您不能在声明之前使用它。 因此，最好将类定义或导入放在代码的顶部。

### 使用对象创建简单的用户信息缓存

在本节中，我们将设计一个简单的用户信息缓存。 缓存是一个临时位置，您可以在从原始位置获取它们时将最常访问的项目存储在其中。 假设您正在为处理用户配置文件的后端应用程序进行设计。 每当请求到来时，服务器都需要调用数据库来检索用户配置文件并将其发送回处理程序。 正如您可能知道的那样，调用数据库是一个非常昂贵的操作。 作为后端开发人员，您可能会被要求提高服务的读取性能。

在下一个练习中，您将创建一个简单的缓存，用于存储用户配置文件，以便大部分时间可以跳过对数据库的请求。

### 练习 47：创建一个缓存类以添加/更新/删除数据存储中的记录

在这个练习中，我们将创建一个包含本地内存数据存储的缓存类。 它还包括一个从数据存储中添加/更新/删除记录的方法。

执行以下步骤以完成此练习：

1.  创建`MySimpleCache`类：

```js
class MySimpleCache {
constructor() {
   // Declare your cache internal properties here
   this.cacheItems = {};
}
}
```

在构造函数中，我们还将初始化缓存的内部状态。 这将是一个简单的对象。

1.  定义`addItem`，它将为键设置缓存项：

```js
addItem(key, value) {
// Add an item with the key
this.cacheItems[key] = value;
  }
```

1.  定义`updateItem`，它将使用我们已经定义的`addItem`：

```js
updateItem(key, value) {
// Update a value use the key
this.addItem(key, value);
}
```

1.  定义`removeItem`。 这将删除我们存储在缓存中的对象，并调用我们之前创建的`updateItem`方法：

```js
removeItem(key) {
this.updateItem(key, undefined);
}
```

1.  使用`assert()`测试我们的缓存，通过更新和删除一些用户来测试`testMycache`：

```js
function testMyCache() {
   const cache = new MySimpleCache ();
   cache.addItem('user1', { name: 'user1', dob: 'Jan 1' });
   cache.addItem('user2', { name: 'user2', dob: 'Jul 21' });
   cache.updateItem('user1', { name: 'user1', dob: 'Jan 2' });
   cache.addItem('user3', { name: 'user3', dob: 'Feb 1' });
   cache.removeItem('user3');
   assert(cache.getItem('user1').dob === 'Jan 2');
   assert(cache.getItem('user2').dob === 'Jul 21');
   assert(cache.getItem('user3') === undefined);
   console.log ('=====TEST PASSED=====')
}
testMyCache();
```

#### 注意

`assert()`是一个内置的 Node.js 函数，它接受一个表达式。 如果表达式求值为`true`，它将通过，如果求值为`false`，它将抛出异常。

运行文件后，您应该看不到错误，并且会看到以下输出：

![图 7.14：simple_cache.js 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_14.jpg)

###### 图 7.14：simple_cache.js 的输出

### 类继承

到目前为止，我们只在 JavaScript 中创建了简单的类定义。 在 OOP 中，我们还可以让一个类继承自另一个类。 类继承只是使一个类的实现派生自另一个类。 创建的子类将具有父类的所有属性和方法。 这在以下图表中显示：

![图 7.15：类继承](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_15.jpg)

###### 图 7.15：类继承

类继承提供了一些好处：

+   它创建了干净，可测试和可重用的代码。

+   它减少了相似代码的数量。

+   在编写适用于所有子类的新功能时，减少了维护时间。

在 JavaScript 中，很容易创建一个从另一个类继承的子类。 为此，使用`extends`关键字：

```js
class MySubClass extends ParentClass {
}
```

### 练习 48：实现子类

在这个练习中，我们将定义一个名为`Vehicle`的超类，并从中创建我们的子类。 超类将具有名为`start`，`buy`和`name`，`speed`和`cost`的方法作为其属性。

超类的构造函数将获取名称，颜色和速度属性，然后将它们存储在对象内部。

`start`方法将简单地打印一个字符串，告诉您正在使用哪种车辆以及您是如何旅行的。`buy`函数将打印出您即将购买的车辆。

执行以下步骤以完成此练习：

1.  定义`Vehicle`类：

```js
class Vehicle {
   constructor(name, speed, cost) {
      this.name = name;
      this.speed = speed;
      this.cost = cost;
   }
   start() {
      console.log('Starting vehicle, ' + this.name + ' at ' + this.speed + 'km/h');
   }
   buy() {
      console.log('Buying for ' + this.cost);
   }
}
```

1.  创建一个`vehicle`实例并测试其方法：

```js
const vehicle = new Vehicle('bicycle', 15, 100);
vehicle.start();
vehicle.buy();
```

您应该看到以下输出：

![图 7.16：车辆类的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_16.jpg)

###### 图 7.16：车辆类的输出

1.  创建`Car`，`Plane`和`Rocket`子类：

```js
class Car extends Vehicle {}
class Plane extends Vehicle {}
class Rocket extends Vehicle {}
```

1.  在`Car`，`Plane`和`Rocket`中，重写`start`方法：

```js
class Car extends Vehicle {
   start() {
      console.log('Driving car, at ' + this.speed + 'km/h');
   }
}
class Plane extends Vehicle {
   start() {
      console.log('Flying plane, at ' + this.speed + 'km/h');
   }
}
class Rocket extends Vehicle {
   start() {
      console.log('Flying rocket to the moon, at ' + this.speed + 'km/h');
   }
}
```

1.  为`Plane`，`Rocket`和`Car`创建一个实例：

```js
const car = new Car('Toyota Corolla', 120, 5000);
const plane = new Plane('Boeing 737', 1000, 26000000);
const rocket = new Rocket('Saturn V', 9920, 6000000000);
```

1.  在所有三个对象上调用`start`方法：

```js
car.start();
plane.start();
rocket.start();
```

以下是前述代码的输出：

![图 7.17：对象的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_17.jpg)

###### 图 7.17：对象的输出

现在当您调用这些 start 方法时，您可以清楚地看到输出是不同的。在声明子类时，大多数时候，我们需要重写父类的一些方法。当我们减少重复的代码同时保留定制时，这非常有用。

定制不止于此 - 您还可以创建具有不同构造函数的新子类。您还可以从子类调用父方法。

1.  对我们之前创建的子类，我们将修改`Car`子类，以便在构造函数中包含额外的参数：

```js
class Car extends Vehicle {
   constructor(name, speed, cost, tankSize) {
      super(name, speed, cost);
      this.tankSize = tankSize;
   }
   start() {
      console.log('Driving car, at ' + this.speed + 'km/h');
   }
}
```

1.  检查额外的属性是否已设置：

```js
const car2 = new Car('Toyota Corolla 2', 120, 5000, 2000);
console.log(car2.tankSize); // 2000
```

以下是前述代码的输出：

![图 7.18：检查 Car 类的额外属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_18.jpg)

###### 图 7.18：检查 Car 类的额外属性

如您所见，声明子类非常容易 - 在以这种方式编码时，您可以共享大量代码。此外，您不会失去进行定制的能力。在 ES6 标准之后，您可以轻松地定义类，就像其他面向对象的编程语言一样。它可以使您的代码更清晰，更易于测试和更易于维护。

### 私有和公共方法

在面向对象编程中，有时将可公开访问的属性和函数与私有可访问的属性和函数分开是有用的。这是一种保护层，可以防止使用类的开发人员调用或访问类的一些内部状态。在 JavaScript 中，这种行为是不可能的，因为 ES6 不允许声明私有属性；您在类中声明的所有属性都将是公开可访问的。为了实现这种类型的行为，一些开发人员选择使用下划线前缀，例如`privateMethod()`，以通知其他开发人员不要使用它。但是，有关声明私有方法的黑客。在下一个练习中，我们将探讨私有方法。

### 练习 49：车辆类中的私有方法

在这个练习中，我们将尝试为我们之前创建的`Car`类声明一个私有函数，以便在以后将类导出为模块时确保我们的私有方法不会暴露出来。让我们开始吧：

1.  创建一个名为`printStat`的函数：

```js
function printStat() {
   console.log('The car has a tanksize of ', this.tankSize);
}
```

1.  修改`public`方法以使用我们刚刚声明的函数：

```js
class Car extends Vehicle {
   constructor(name, speed, cost, tankSize) {
      super(name, speed, cost);
      this.tankSize = tankSize;
   }
   start() {
      console.log('Driving car, at ' + this.speed + 'km/h');
      printStat();
   }
}
```

我们直接从`start`方法调用了`printStat`，但是没有真正的方法可以直接访问，而是使用我们类中的一个方法。通过在外部声明方法，我们使方法成为`private`。

1.  创建另一个`car`实例并调用`start`方法：

```js
const car = new Car('Toyota Corolla', 120, 5000, 2000);
car.start();
```

当您运行此代码时，您将意识到这会导致异常：

![图 7.19：printStat 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_19.jpg)

###### 图 7.19：printStat 的输出

1.  修改`start`方法，以便函数了解我们从中调用它的对象实例：

```js
start() {
      console.log('Driving car, at ' + this.speed + 'km/h');
      printStat.bind(this)();
   }
```

请注意我们使用了`.bind()`。通过使用绑定，我们将当前实例绑定到此函数内部的`this`变量。这使我们的代码能够按预期工作：

![图 7.20：使用.bind()后的 printStat 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_20.jpg)

###### 图 7.20：使用.bind()后 printStat 的输出

正如您所看到的，目前在 JavaScript 中没有一种简单地声明`private`方法或属性的方法。这个例子只是对这个问题的一个变通方法；它仍然不能像其他面向对象的语言（如 Java 或 Python）那样提供相等的分离。也有在线选项，可以使用符号声明私有方法，但如果知道在哪里查找，它们也可以被访问。

### 数组和对象内置方法

之前，我们讨论了基本数组和对象。它们处理我们如何存储数据。现在，我们将深入探讨如何对刚刚存储在其中的数据进行高级计算和操作。

**array.map(function)**

数组映射将遍历数组中的每个项目，并返回一个新数组作为结果。传递给方法的函数将以当前项目作为参数，并且函数的返回值将包含在最终数组的结果中；例如：

```js
const singers = [{ name: 'Miku', age: 16}, { name: 'Kaito', age: 20 }];
```

如果我们想要创建一个新数组，并且只包括列表中对象的名称属性，我们可以使用`array.map`来实现：

```js
const names = singers.map((singer) => singer.name);
```

以下是上述代码的输出：

![图 7.21：使用数组映射方法的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_21.jpg)

###### 图 7.21：使用数组映射方法的输出

**array.forEach(function)**

`.forEach`是一种迭代数组项的方法。与`.map`不同，它不会返回新值。我们传递的函数只是重复调用数组中的值；例如：

```js
const singers = [{ name: 'Miku', age: 16}, { name: 'Kaito', age: 20 }];
singers.forEach((singer) => {
   console.log(singer.name);
})
```

这将打印出数组中每个歌手的名字。

**array.find(function)**

`.find`方法的工作原理与`.map`和`.forEach`方法相同；它接受一个函数作为参数。此函数将用于确定当前对象是否符合搜索的要求。如果找到匹配项，它将用作方法的返回结果。如果数组中找到多个匹配项，则此方法将不返回任何结果。例如，如果我们想要找到名称等于某个字符串的对象，我们可以这样做：

```js
const singers = [{ name: 'Miku', age: 16}, { name: 'Kaito', age: 20 }];
const miku = singers.find((singer) => singer.name === 'Miku');
```

**array.filter(function)**

`.filter`的工作原理与`.find`相同，但它允许返回多个项目。如果我们想要在列表中匹配多个项目，我们需要使用`.filter`。如果要查找年龄小于 30 岁的歌手列表，请使用以下代码：

```js
const singers = [{ name: 'Miku', age: 16}, { name: 'Kaito', age: 20 }];
const youngSingers = singers.filter((singer) => singer.age < 30);
```

数组的`map`方法在迭代数组中的每个项目时创建一个新数组。`map`方法接受一个函数，就像`forEach`方法一样。当执行时，它将使用当前项目调用函数的第一个参数和当前索引的第二个参数。`map`方法还期望返回提供给它的函数。返回的值将放入新数组中，并由该方法返回，如下所示：

```js
const programmingLanguages = ['C', 'Java', 'Python'];
const myMappedArray = programmingLanguages.map((language) => {
   return 'I know ' + language;
});
```

`.map`方法将遍历数组，我们的`map`函数将返回`"I know,"`加上当前语言。因此，`myMappedArray`的结果将如下所示：

![图 7.22：使用数组映射方法的示例输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_22.jpg)

###### 图 7.22：使用数组映射方法的示例输出

我们将在*第十章* *JavaScript 中的函数式编程*中更详细地介绍`array.map`。

我们将在接下来的练习中使用的另一种方法是`forEach`方法。`forEach`方法更加简洁，因为不需要管理当前索引并编写实际调用函数的代码。`forEach`方法是一个内置的数组方法，它接受一个函数作为参数。以下是`forEach`方法的示例：

```js
foods.forEach(eat_food);
```

在接下来的练习中，我们将在数组上使用迭代方法。

### 练习 50：在数组上使用迭代方法

有许多遍历数组的方法。一种是使用带有索引的`for`循环，另一种是使用其中一种内置方法。在这个练习中，我们将初始化一个字符串数组，然后探索 JavaScript 中可用的一些迭代方法。让我们开始吧：

1.  创建一个食物列表作为数组：

```js
const foods = ['sushi', 'tofu', 'fried chicken'];
```

1.  使用`join`连接数组中的每个项目：

```js
foods.join(', ');
```

以下是上述代码的输出：

![图 7.23：数组中的连接项目](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_23.jpg)

###### 图 7.23：数组中的连接项目

数组连接是另一种遍历数组中每个项目的方法，使用提供的分隔符将它们组合成一个单一的字符串。

1.  创建一个名为`eat_food`的函数：

```js
function eat_food(food) {
   console.log('I am eating ' + food);
}
```

1.  使用`for`循环来遍历数组并调用函数：

```js
const foods = ['sushi', 'tofu', 'fried chicken'];
function eat_food(food) {
   console.log('I am eating ' + food);
}
for(let i = 0; i < foods.length; i++) {
   eat_food(foods[i]);
}
```

以下是上述代码的输出：

![图 7.24：在循环中调用 eat_food 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_24.jpg)

###### 图 7.24：在循环中调用 eat_food 的输出

1.  使用`forEach`方法来实现相同的效果：

```js
foods.forEach(eat_food);
```

以下是上述代码的输出：

![图 7.25：使用 forEach 方法生成相同的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_24.jpg)

###### 图 7.25：使用 forEach 方法生成相同的输出

因为`eat_food`是一个函数，它的第一个参数引用了当前项目，所以我们可以直接传递函数名。

1.  创建一个新的卡路里数字数组：

```js
const nutrition = [100, 50, 400]
```

这个数组包括我们`food`数组中每个项目的卡路里。接下来，我们将使用不同的迭代函数来创建一个包含这些信息的新对象列表。

1.  创建新的对象数组：

```js
const foodInfo = foods.map((food, index) => {
   return {
      name: food,
      calories: nutrition[index]
   };
});
```

1.  将`foodInfo`打印到控制台上：

```js
console.log(foodInfo);
```

以下是上述代码的输出：

![图 7.26：包含食物和卡路里信息的数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_26.jpg)

###### 图 7.26：包含食物和卡路里信息的数组

运行`array.map`后，将创建一个新数组，其中包含有关我们食物名称和其卡路里计数的信息。

在这个练习中，我们讨论了两种迭代方法，即`forEach`和`map`。每种方法都有其自己的功能和用法。在大多数应用程序中，通常使用映射来通过在每个数组项上运行相同的代码来计算数组结果。如果你想要在不直接修改数组的情况下操作数组中的每个项目，这是非常有用的。

### 练习 51：查找和过滤数组

以前，我们讨论了遍历数组的方法。这些方法也可以用于查找。众所周知，当你从头到尾迭代数组时，查找是非常昂贵的。幸运的是，JavaScript 数组有一些内置方法，因此我们不必自己编写搜索函数。在这个练习中，我们将使用`includes`和`filter`来搜索数组中的项目。让我们开始吧：

1.  创建一个名为`profiles`的名称列表：

```js
let profiles = [
   'Michael Scott',
   'Jim Halpert',
   'Dwight Shrute',
   'Random User',
   'Hatsune Miku',
   'Rin Kagamine'
];
```

1.  尝试找出`profiles`列表中是否包含名为`Jim Halpert`的人：

```js
let hasJim = profiles.includes('Jim Halpert');
console.log(hasJim);
```

以下是上述代码的输出：

![图 7.27：hasJim 方法的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_27.jpg)

###### 图 7.27：hasJim 方法的输出

1.  修改`profiles`数组以包含额外的信息：

```js
const profiles = [
   { name: 'Michael Scott', age: 42 },
   { name: 'Jim Halpert', age: 27},
   { name: 'Dwight Shrute', age: 37 },
   { name: 'Random User', age: 10 },
   { name: 'Hatsune Miku', age: 16 },
   { name: 'Rin Kagamine', age: 14 }
]
```

现在，数组不再是简单的字符串列表-它是一个对象列表，当我们处理对象时，事情会有点不同。

1.  尝试再次使用`includes`查找`Jim Halpert`个人资料：

```js
hasJim = profiles.includes({ name: 'Jim Halpert', age: 27});
console.log(hasJim);
```

以下是上述代码的输出：

![图 7.28：hasJim 方法的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_28.jpg)

###### 图 7.28：hasJim 方法的输出

1.  找到名为`Jim Halpert`的个人资料：

```js
hasJim = !!profiles.find((profile) => {
   return profile.name === 'Jim Halpert';
}).length;
console.log(hasJim);
```

1.  找到所有年龄大于`18`的用户：

```js
const adults = profiles.filter((profile) => {
   return profile.age > 18;
});
console.log(adults);
```

当你运行上述代码时，它应该输出所有年龄超过 18 岁的用户。`filter`和`find`之间的区别在于`filter`返回一个数组：

![图 7.29：使用 filter 方法后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_29.jpg)

###### 图 7.29：使用 filter 方法后的输出

在这个练习中，我们看了两种定位数组中特定项的方法。通过使用这些方法，我们可以避免重写搜索算法。`find`和`filter`之间的区别在于`filter`返回符合要求的所有对象的数组。在实际的生产环境中，当我们想要测试数组是否有与我们要求匹配的对象时，通常使用`find`方法，因为它在找到一个匹配时就停止扫描，而`filter`会与数组中的所有对象进行比较，并返回所有匹配的结果。如果您只是测试某物的存在，这将更加昂贵。我们还使用了双重否定运算符将结果转换为布尔值。如果您稍后在条件语句中使用这个值，这种表示法非常有用。

## 排序

排序是开发人员面临的最大挑战之一。当我们想要对数组中的一些项目进行排序时，通常需要定义特定的排序算法。这些算法通常需要我们编写大量的排序逻辑，并且不容易重用。在 JavaScript 中，我们可以使用内置的数组方法对我们的自定义项目列表进行排序，并编写最少的自定义代码。

在 JavaScript 数组中进行排序需要在数组上调用`.sort()`函数。`sort()`函数接受一个参数，称为排序比较器。根据比较器，`sort()`函数将决定如何排列每个元素。

以下是我们将在即将进行的练习中使用的一些其他函数的简要描述。

`compareNumber`函数只计算`a`和`b`之间的差异。在`sort`方法中，我们可以声明自己的自定义比较函数进行比较：

```js
function compareNumber(a, b) {
   return a - b;
}
```

`compareAge`函数与`compareNumber`函数非常相似。唯一的区别在于我们比较的是 JavaScript 对象而不是数字：

```js
function compareAge(a, b) {
   return a.age - b.age;
}
```

### 练习 52：JavaScript 中的数组排序

在这个练习中，我们将讨论对数组进行排序的方法。在计算机科学中，排序总是复杂的。在 JavaScript 中，数组对象内置了一个排序方法，可以对数组进行基本排序。

我们将使用上一个练习中的`profiles`对象数组。让我们开始吧：

1.  创建一个`numbers`数组：

```js
const numbers = [ 20, 1, 3, 55, 100, 2];
```

1.  调用`array.sort()`对这个数组进行排序：

```js
numbers.sort();
console.log(numbers);
```

当您运行上述代码时，您将获得以下输出：

![图 7.30：数组.sort()的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_30.jpg)

###### 图 7.30：数组.sort()的输出

这并不是我们想要的；似乎`sort`函数只是随机排列值。其背后的原因是，在 JavaScript 中，`array.sort()`实际上并不支持按值排序。默认情况下，它将所有内容视为字符串。当我们使用数字数组调用它时，它将所有内容转换为字符串，然后开始排序。这就是为什么您会看到数字 1 出现在 2 和 3 之前的原因。为了实现对数字的排序，我们需要做一些额外的工作。

1.  定义`compareNumber`函数：

```js
function compareNumber(a, b) {
   return a - b;
}
```

该函数期望接受两个要进行比较的值，并返回一个必须匹配以下内容的值：如果`a`小于`b`，则返回小于 0 的数字；如果`a`等于`b`，则返回 0；如果`a`大于`b`，则返回大于 0 的数字。

1.  运行`sort`函数，并将`compareNumber`函数作为参数传递：

```js
numbers.sort(compareNumber);
console.log(numbers);
```

当您运行上述代码时，您将看到该函数已将我们的数组按照我们想要的顺序排序：

![图 7.31：数组.sort(compareNumber)的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_31.jpg)

###### 图 7.31：数组.sort(compareNumber)的输出

现在，数组已经正确地从最小到最大排序。然而，大多数情况下，当我们需要进行排序时，我们需要将复杂的对象排序。在下一步中，我们将使用在上一个练习中创建的`profiles`数组。

1.  如果您的工作空间中未定义`profiles`数组，请创建它：

```js
const profiles = [
   { name: 'Michael Scott', age: 42 },
   { name: 'Jim Halpert', age: 27},
   { name: 'Dwight Shrute', age: 37 },
   { name: 'Random User', age: 10 },
   { name: 'Hatsune Miku', age: 16 },
   { name: 'Rin Kagamine', age: 14 }
]
```

1.  调用`profiles.sort()`：

```js
profiles.sort();
console.log(profiles);
```

以下是前面代码的输出：

![图 7.32：profiles.sort()函数的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_32.jpg)

###### 图 7.32：profiles.sort()函数的输出

因为我们的`sort`函数不知道如何比较这些对象，所以数组保持原样。为了正确排序对象，我们需要一个与上次一样的比较函数。

1.  定义`compareAge`：

```js
function compareAge(a, b) {
   return a.age - b.age;
}
```

提供给`compareAge`的两个参数`a`和`b`是数组中的对象。因此，为了正确排序它们，我们需要访问这些对象的`age`属性并进行比较。

1.  使用我们刚刚定义的`compare`函数调用`sort`函数：

```js
profiles.sort(compareAge);
console.log(profiles);
```

以下是前面代码的输出：

![图 7.33：profile.sort(compareAge)的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_33.jpg)

###### 图 7.33：profile.sort(compareAge)的结果

在这个练习中，我们讨论了对数组进行排序的方法。需要记住的一件事是，在 JavaScript 中，如果不对字符串值进行排序，则需要使用比较函数来告诉它如何排序。该方法的空间和时间复杂度因平台而异，但如果使用 Node.js，JavaScript 的 V8 引擎对这些类型的操作进行了高度优化，因此您不必担心性能问题。在下一个练习中，我们将讨论 JavaScript 中非常有趣但又有用的数组操作，即数组减少器。通过使用数组减少器，我们可以轻松地将数组中的项目组合在一起，并将它们减少为一个单一的值。

### 数组减少

在构建后端应用程序时，经常会出现给定格式化结果列表并且必须从中计算单个值的情况。虽然可以使用传统的循环方法来完成，但使用 JavaScript 减少函数时更加简洁和易于维护。减少意味着对数组中的每个元素进行处理，并返回一个单一的值。

如果我们想要减少一个数组，我们可以调用内置的`array.reduce()`方法：

```js
Array.reduce((previousValue, currentValue) => {
   // reducer
}, initialValue);
```

当我们调用`array.reduce()`时，我们需要传入一个函数和初始值。该函数将以前一个值和当前一个值作为参数，并将返回值用作最终值。

### 练习 53：使用 JavaScript 减少方法为购物车进行计算

在这个练习中，我们将尝试使用 JavaScript 的`reduce`方法为购物车进行计算。让我们开始吧：

1.  创建购物车变量：

```js
const cart = [];
```

1.  将项目推入数组：

```js
cart.push({ name: 'CD', price: 12.00, amount: 2 });
cart.push({ name: 'Book', price: 45.90, amount: 1 });
cart.push({ name: 'Headphones', price: 5.99, amount: 3 });
cart.push({ name: 'Coffee', price: 12.00, amount: 2 });
cart.push({ name: 'Mug', price: 15.45, amount: 1 });
cart.push({ name: 'Sugar', price: 5.00, amount: 1 });
```

1.  使用循环方法计算购物车的总成本：

```js
let total = 0;
cart.forEach((item) => {
   total += item.price * item.amount;
});
console.log('Total amount: ' + total);
```

以下是前面代码的输出：

![图 7.34：计算总数的循环方法的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_34.jpg)

###### 图 7.34：计算总数的循环方法的结果

1.  我们编写了名为`priceReducer`的 reducer：

```js
function priceReducer (accumulator, currentValue) {
   return accumulator += currentValue.price * currentValue.amount;
}
```

1.  使用我们的 reducer 调用`cart.reduce`：

```js
total = cart.reduce(priceReducer, 0);
console.log('Total amount: ' + total);
```

以下是前面代码的输出：

![图 7.35：cart.reduce 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_34.jpg)

###### 图 7.35：cart.reduce 的结果

在这个练习中，我们讨论了在 JavaScript 中将数组减少为单个值的方法。虽然使用循环迭代数组并返回累加器是完全正确的，但是使用减少函数时，代码会更加简洁。我们不仅减少了作用域中可变变量的数量，还使代码更加简洁和可维护。下一个维护代码的人将知道该函数的返回值将是一个单一的值，而`forEach`方法可能会使得返回结果不清晰。

### 活动 9：使用 JavaScript 数组和类创建学生管理器

假设你正在为当地的学区工作，到目前为止，他们一直在使用纸质登记簿来记录学生信息。现在，他们获得了一些资金，并希望您开发一款计算机软件来跟踪学生信息。他们对软件有以下要求：

+   它需要能够记录关于学生的信息，包括他们的姓名、年龄、年级和书籍信息。

+   每个学生将被分配一个唯一的 ID，用于检索和修改学生记录。

+   书籍信息将包括该学生的书籍名称和当前成绩（数字成绩）。

+   需要一种方法来计算学生的平均成绩。

+   需要一种方法来搜索具有相同年龄或年级的所有学生。

+   需要一种方法来使用他们的名字搜索学生。当找到多个时，返回所有学生。

#### 注意

此活动的完整代码也可以在我们的 GitHub 存储库中找到，链接在这里：[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson07/Activity09/Activity09.js`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson07/Activity09/Activity09.js)。

执行以下步骤以完成此活动：

1.  创建一个`School`类并在构造函数中初始化学生列表。

1.  创建一个`Student`类，并在其中存储课程列表、学生的`age`、`name`和`grade level`。

1.  创建一个`Course`类，其中包括有关`course`、`name`和`grades`的信息。

1.  在`School`类中创建`addStudent`函数，将学生推入`school`对象中的列表中。

1.  在`School`类中创建`findByGrade`函数，该函数返回具有给定`grade level`的所有学生。

1.  在`School`类中创建`findByAge`函数，该函数返回具有相同`age`的学生列表。

1.  在`School`类中创建`findByName`函数，通过姓名搜索学校中的所有学生。

1.  在`Student`类中，为计算学生的平均成绩创建一个`calculateAverageGrade`方法。

1.  在`Student`类中，创建一个`assignGrade`方法，该方法将为学生所学课程分配一个数字成绩。

#### 注意

此活动的解决方案可以在第 608 页找到。

在上一节中，我们讨论了允许我们迭代、查找和减少数组的方法。在处理数组时，这些方法非常有用。虽然大多数方法只能完成基本任务，并且可以很容易地使用循环实现，但使用它们有助于使我们的代码更易用和可测试。一些内置方法也经过了运行时引擎的优化。

在下一节中，我们将讨论 Map 和 Set 的一些内置函数。如果我们需要在应用程序中跟踪值，它们非常有用。

## Map 和 Set

Map 和 Set 在 JavaScript 中是非常被低估的类型，但在某些应用中它们可以非常强大。Map 在 JavaScript 中的工作原理就像一个基本的哈希映射，当您需要跟踪一组键值对时非常有用。Set 用于在需要保留一组唯一值时使用。大多数开发人员经常在所有情况下都使用对象，而忽略了在某些情况下使用 Map 和 Set 更有效的事实。在接下来的部分中，我们将讨论 Map 和 Set 以及如何使用它们。

有许多情况下，我们必须跟踪应用程序中的一组唯一键值对。在使用其他语言编程时，我们经常需要实现一个名为**哈希映射**的类。在 JavaScript 中，有两种类型可以实现这一点：一种是 Map，另一种是 Object。因为它们似乎做同样的事情，许多 JavaScript 开发人员倾向于在所有情况下都使用 Object，而忽略了在某些情况下使用 Map 对他们的用例更有效的事实。

### 练习 54：使用 Map 与对象

在这个练习中，我们将讨论我们可以如何使用 Map 以及它们与对象相比有何不同：

1.  创建一个名为`map`的新 Map：

```js
const map = new Map()
```

1.  创建我们想要用作键的对象列表：

```js
const key1 = 'key1';
const key2 = { name: 'John', age: 18 };
const key3 = Map;
```

1.  使用`map.set`为我们之前定义的所有键设置一个值：

```js
map.set(key1, 'value for key1');
map.set(key2, 'value for key2');
map.set(key3, 'value for key3');
```

以下是前面代码的输出：

![图 7.36：对 map.set 分配值后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_36.jpg)

###### 图 7.36：对 map.set 分配值后的输出

1.  获取键的值：

```js
console.log(map.get(key1));
console.log(map.get(key2));
console.log(map.get(key3));
```

以下是前面代码的输出：

![图 7.37：值检索的 console.log 输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_37.jpg)

###### 图 7.37：值检索的 console.log 输出

1.  在不使用引用的情况下检索`key2`的值：

```js
console.log(map.get({ name: 'John', age: 18 }));
```

以下是前面代码的输出：

![图 7.38：在没有引用的情况下使用 get 时的 console.log 输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_38.jpg)

###### 图 7.38：在没有引用的情况下使用 get 时的 console.log 输出

虽然我们输入了所有正确的内容，但是我们的地图似乎无法找到该键的值。这是因为在进行这些检索时，它使用的是对象的引用而不是值。

1.  使用`forEach`迭代地图：

```js
map.forEach((value, key) => {
   console.log('the value for key: ' + key + ' is ' + value);
});
```

地图可以像数组一样进行迭代。使用`forEach`方法时，传入的函数将被调用两个参数：第一个参数是值，第二个参数是键。

1.  获取键和值的数组列表：

```js
console.log(map.keys());
console.log(map.values());
```

以下是前面代码的输出：

![图 7.39：键和值的数组列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_39.jpg)

###### 图 7.39：键和值的数组列表

当您只需要存储信息的一部分时，这些方法非常有用。如果您有一个地图来跟踪用户，使用他们的 ID 作为键，调用`values`方法将简单地返回一个用户列表。

1.  检查地图是否包含一个键：

```js
console.log(map.has('non exist')); // false
```

以下是前面代码的输出：

![图 7.40：指示地图不包括键的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_40.jpg)

###### 图 7.40：指示地图不包括键的输出

#### 注意

在这里，我们可以看到地图和对象之间的第一个主要区别，尽管两者都能够跟踪唯一键值对的列表。在地图中，您可以拥有对象或函数的引用作为键。这在 JavaScript 中的对象中是不可能的。我们还可以看到的另一件事是，它还保留了根据它们被添加到地图中的顺序的键的顺序。虽然您可能会在对象中获得有序的键，但 JavaScript 不能保证键的顺序与它们被添加到对象中的顺序一致。

通过这个练习，我们了解了地图的用法及其与对象的区别。当你处理键值数据并且需要进行排序时，地图应该始终优先于对象，因为它不仅保留了键的顺序，还允许将对象引用用作键。这是两种类型之间的主要区别。在下一个练习中，我们将介绍另一种经常被开发人员忽视的类型：集合。

在数学中，集合被定义为不同对象的集合。在 JavaScript 中，它很少被使用，但是我们将无论如何介绍一种使用集合的方法。

### 练习 55：使用集合跟踪唯一值

在这个练习中，我们将介绍 JavaScript 集合。我们将构建一个算法来删除数组中的所有重复值。

执行以下步骤完成此练习：

1.  声明一个名为`planets`的字符串数组：

```js
const planets = [
   'Mercury',
   'Uranus',
   'Mars',
   'Venus',
   'Neptune',
   'Saturn',
   'Mars',
   'Jupiter',
   'Earth',
   'Saturn'
]
```

1.  使用数组创建一个新的集合：

```js
const planetSet = new Set(planets);
```

1.  检索`planets`数组中的唯一值：

```js
console.log(planetSet.values());
```

以下是前面代码的输出：

![图 7.41：唯一的数组值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_41.jpg)

###### 图 7.41：唯一的数组值

1.  使用`add`方法向集合添加更多值：

```js
planetSet.add('Venus');
planetSet.add('Kepler-440b');
```

我们可以使用`add`方法向我们的集合添加一个新值，但是因为集合始终保持其成员的唯一性，如果您添加任何已经存在的内容，它将被忽略：

![图 7.42：无法添加重复值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_42.jpg)

###### 图 7.42：无法添加重复值

1.  使用`.size`属性获取 Set 的大小：

```js
console.log(planetSet.size);
```

1.  清除集合中的所有值：

```js
planetSet.clear();
console.log(planetSet);
```

以下是前面代码的输出：

！[图 7.43：从集合中清除所有值

]（Images/C14587_07_43.jpg）

###### 图 7.43：从集合中清除所有值

在这个练习中，我们介绍了一些使用 Set 作为工具来帮助我们在数组中删除重复值的方法。当您想要保留一系列唯一值并且不需要通过索引访问它们时，集合非常有用。否则，如果您处理可能包含重复项的大量项目，则数组仍然是最佳选择。在下一节中，我们将讨论 Math，Date 和 String 方法。

## 数学，日期和字符串

在使用 JavaScript 构建复杂应用程序时，有时您需要处理字符串操作，数学计算和日期。幸运的是，JavaScript 有几种内置方法可以处理这种类型的数据。在接下来的练习中，我们将介绍如何在应用程序中利用这些方法。

要创建`new Date`对象，请使用以下命令：

```js
const currentDate = new Date();
```

这将指向当前日期。

要创建一个新字符串，请使用以下命令：

```js
const myString = 'this is a string';
```

要使用`Math`模块，我们可以使用`Math`类：

```js
const random = Math.random();
```

### 练习 56：使用字符串方法

在这个练习中，我们将介绍一些更容易在应用程序中处理字符串的方法。在其他语言中，字符串操作和构建一直是复杂的任务。在 JavaScript 中，通过使用 String 方法，我们可以轻松地创建，匹配和操作字符串。在这个练习中，我们将创建各种字符串并使用 String 方法来操作它们。

执行以下步骤以完成此练习：

1.  创建一个名为`planet`的变量：

```js
let planet = 'Earth';
```

1.  使用模板字符串创建`句子`：

```js
let sentence = `We are on the planet ${planet}`;
```

模板字符串是 ES6 中引入的非常有用的功能。我们可以通过组合模板和变量来创建字符串，而无需创建字符串构建或使用字符串连接。字符串模板使用`` ` ``包装，而要插入到字符串中的变量用`${}`包装。

1.  将我们的句子分割成单词：

```js
console.log(sentence.split(' '));
```

我们可以使用 `split` 方法和分隔符将字符串拆分为数组。在上面的示例中，JavaScript 将我们的句子分割成一个单词数组，就像这样：

![图 7.44：将字符串分割为单词数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_44.jpg)

###### 图 7.44：将字符串分割为单词数组

1.  我们还可以使用 `replace` 方法将任何匹配的子字符串替换为另一子字符串，如下所示：

```js
sentence = sentence.replace('Earth', 'Venus');
console.log(sentence);
```

以下是先前代码的输出结果：

![图 7.45：替换字符串中的单词](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_45.jpg)

###### 图 7.45：替换字符串中的单词

在 `replace` 方法中，我们将第一个参数作为要在字符串中匹配的子字符串提供。第二个参数是您要用来替换的字符串。

1.  检查我们的句子是否包含单词 `火星`：

```js
console.log(sentence.includes('Mars'));
```

以下是先前代码的输出结果：

![图 7.46：检查字符串中是否存在某个字符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_46.jpg)

###### 图 7.46：检查字符串中是否存在某个字符

1.  您还可以将整个字符串转换为大写或小写：

```js
sentence.toUpperCase();
sentence.toLowerCase();
```

1.  使用 `charAt` 方法在字符串中获取索引处的字符：

```js
sentence.charAt(0); // returns W
```

由于句子并不一定是数组，所以无法像数组那样访问特定位置的字符。要实现这一点，您需要调用 `charAt` 方法。

1.  使用字符串的 `length` 属性获取字符串的长度：

```js
sentence.length;
```

以下是先前代码的输出结果：

![图 7.47：修改后句子的长度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_47.jpg)

###### 图 7.47：我们修改后句子的长度

在这个练习中，我们将介绍如何使用模板字符串和字符串方法构建字符串，这些方法有助于我们操作字符串。这在处理大量用户输入的应用程序中非常有用。在下一个练习中，我们将学习 Math 和 Date 方法。

### Math 和 Date

在本节中，我们将学习 Math 和 Date 类型。我们很少在应用程序中涉及 Math，但是当我们涉及它时，充分利用 Math 库非常有用。稍后，我们将讨论 Date 对象及其方法。Math 和 Date 类包括各种有用的方法，帮助我们进行数学计算和日期操作。

### 练习 57：使用 Math 和 Date

在本练习中，我们将学习如何在 JavaScript 中实现 Math 和 Date 类型。我们将使用它们来生成随机数，并使用其内置常量进行数学计算。我们还将使用 Date 对象来测试 JavaScript 中不同处理日期的方式。让我们开始吧：

1.  创建一个名为 `generateRandomString` 的函数：

```js
function generateRandomString(length) {

}
```

1.  创建一个在一定范围内生成随机数的函数：

```js
function generateRandomNumber(min, max) {
   return Math.floor(Math.random() * (max - min + 1)) + min;
}
```

在上述函数中，`Math.random` 生成 0（inclusive）到 1（exclusive）之间的随机数。当我们想要两个范围内的数字时，我们也可以使用 `Math.floor` 将数字四舍五入以确保它不包括 `max` 在我们的输出中。

1.  在`generateRandomString`中使用随机数生成函数：

```js
function generateRandomString(length) {
   const characters = [];
   const characterSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
   for (let i = 0; i < length; i++) {
      characters.push(characterSet.charAt(generateRandomNumber(0, characterSet.length)));
   }
   return characters.join(');
}
```

我们用于随机数生成的方法非常简单 - 我们有一个包含在随机字符串中的字符集。之后，我们将运行一个循环，使用我们创建的函数来获取一个随机字符，使用`charAt`传递一个随机索引。

1.  测试我们的函数：

```js
console.log(generateRandomString(16));
```

以下是先前代码的输出：

![图 7.48：我们随机字符串函数的输出    ](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_48.jpg)

###### 图 7.48：我们随机字符串函数的输出

每次运行这个函数，它都会给我们一个完全随机的字符串，该字符串的长度与我们传递的参数相同。这是生成随机用户名的非常简单的方法，但不太适合生成 ID，因为它无法保证唯一性。

1.  使用`Math`常数创建一个计算圆形面积的函数，如下所示：

```js
function circleArea(radius) {
   return Math.pow(radius, 2) * Math.PI;
}
```

在这个函数中，我们使用了`Math`对象中的`Math.PI`。它赋予了 radius 参数的平方值。接下来，我们将探讨 JavaScript 中的`Date`类型。

1.  创建一个新的`Date`对象：

```js
const now = new Date();
console.log(now);
```

以下是先前代码的输出：

![图 7.49：新日期对象的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_49.jpg)

###### 图 7.49：新日期对象的输出

当我们创建一个不带参数的新`Date`对象时，它将生成一个存储当前时间的对象。

1.  在特定的日期和时间创建一个新的`Date`对象：

```js
const past = new Date('August 31, 2007 00:00:00');
```

`Date`构造函数将接受一个可解析为日期的字符串参数。当我们使用这个字符串调用构造函数时，它将创建一个`Date`对象在那个日期和时间。

1.  从我们的`past`日期对象中获取年、月和日：

```js
console.log(past.getFullYear());
console.log(past.getMonth());
console.log(past.getDate());
```

以下是先前代码的输出：

![图 7.50：过去日期对象的年、月和日     ](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_50.jpg)

###### 图 7.50：过去日期对象的年、月和日

返回的月份不是从 1 开始的，一月是 1。相反，它从 0 开始，因此八月是 7。

1.  你也可以通过调用`toString`生成对象的字符串表示版本：

```js
console.log(past.toString());
```

以下是先前代码的输出：

![图 7.51：以字符串形式呈现的日期](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_51.jpg)

###### 图 7.51：以字符串形式呈现的日期

通过使用`toString`方法，我们可以简单地在应用程序中记录时间戳。

1.  如果你想得到 Unix 时间，你可以使用`Date.now`：

```js
console.log(Math.floor(Date.now() / 1000));
```

我们再次使用`Math.floor`的原因是，我们需要将`Date.now`的输出除以 1,000，因为它以毫秒返回。

在这个练习中，我们介绍了 Math 和 Date 类型在应用程序中的几种用法。当我们需要生成伪随机 ID 或随机字符串时，它们非常有用。`Date`对象还在我们需要在应用程序中跟踪时间戳时使用。在下一节中，我们将简要介绍 Symbols、Iterators、Generators 和 Proxies。

## 符号、迭代器、生成器和代理

在 JavaScript 开发中，这些类型很少被使用，但对于某些用例，它们可以非常有用。在本节中，我们将介绍这些是什么，以及如何在我们的应用程序中使用它们。

### 符号

符号是唯一的值；它们可以作为标识符使用，因为每次调用`Symbol()`时，它都会返回一个唯一的符号。即使函数返回一个 Symbol 类型，它也不能使用`new`关键字调用，因为它不是一个构造函数。当存储在对象中时，它们在遍历属性列表时不会被包括，因此如果你想将任何东西存储为对象内的属性，又不希望它们在运行`JSON.stringify`时被公开，你可以使用符号来实现这一点。

### 迭代器与生成器

迭代器和生成器经常一起使用。生成器函数是调用时不立即执行其代码的函数。当需要从生成器返回一个值时，需要使用`yield`进行调用。之后它将暂停执行，直到再次调用下一个函数。这使得生成器非常适合用作迭代器。在迭代器中，我们需要定义一个具有`next`方法的函数，每次调用时都会返回一个值。通过这两者的结合，我们可以构建非常强大的迭代器，其中包含大量可重用的代码。

符号是 JavaScript 中一个难以理解的概念，并且并不经常使用。在这个练习中，我们将介绍一些使用符号并探索它们属性的方法。

### 练习 58：使用符号并探索它们的属性

在这个练习中，我们将使用符号及其属性来识别对象的属性。让我们开始吧：

1.  创建两个符号：

```js
let symbol1 = Symbol();
let symbol2 = Symbol('symbol');
```

1.  测试它们的等价性：

```js
console.log(symbol1 === symbol2);
console.log(symbol1 === Symbol('symbol'));
```

两个语句都将被评估为 false。这是因为在 JavaScript 中，符号是唯一的，即使它们具有相同的名称，它们仍然不相等。

1.  创建一个带有一些属性的测试对象：

```js
const testObj = {};
testObj.name = 'test object';
testObj.included = 'this will be included';
```

1.  使用符号作为键在对象中创建一个属性：

```js
const symbolKey = Symbol();
testObj[symbolKey] = 'this will be hidden';
```

1.  打印出对象中的键：

```js
console.log(Object.keys(testObj));
```

以下是前面代码的输出结果：

![图 7.52：使用 Object.keys 打印出的键列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_52.jpg)

###### 图 7.52：使用 Object.keys 打印出的键列表

看起来调用`Object.keys`并没有返回我们的`Symbol`属性。这背后的原因是因为符号不可枚举，因此它们既不会被`Object.keys`返回，也不会被`Object.getOwnPropertyNames`返回。

1.  让我们尝试获取我们的`Symbol`属性的值：

```js
console.log(testObj[Symbol()]); // Will return undefined
console.log(testObj[symbolKey]); // Will return our hidden property
```

1.  使用`Symbol`注册表：

```js
const anotherSymbolKey = Symbol.for('key');
const copyOfAnotherSymbol = Symbol.for('key');
```

在这个例子中，我们可以对`Symbol`键进行搜索，并将该引用存储在我们的新常量中。`Symbol`注册表是我们应用程序中所有符号的注册表。在这里，你可以将你创建的符号存储在一个全局注册表中，这样它们以后就可以被检索到。

1.  使用其引用检索`Symbol`属性的内容：

```js
testObj[anotherSymbolKey] = 'another key';
console.log(testObj[copyOfAnotherSymbol]);
```

以下是前面代码的输出结果：

![图 7.53：通过符号引用检索值的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_53.jpg)

###### 图 7.53：通过符号引用检索值的结果

当我们运行这段代码时，它将打印出我们想要的结果。当我们使用`Symbol.for`创建一个符号时，我们将在键和引用之间创建一个一对一的关系，这样当我们使用`Symbol.for`获取另一个引用时，这两个符号将是相等的。

在这个练习中，我们讨论了符号的一些属性。如果您需要将它们用作`object`属性的标识符，它们非常有用。使用`Symbol`注册表也可以帮助我们重新定位我们之前创建的`Symbol`。在下一个练习中，我们将讨论迭代器和生成器的一般用法。

在前一个练习中，我们讨论了符号。在 JavaScript 中还有另一种叫做`Symbol`的类型，叫做`Symbol.iterator`，它是一个特定的符号，用于创建迭代器。在这个练习中，我们将使用生成器来创建一个可迭代对象。

### 练习 59：迭代器和生成器

Python 中有一个非常有用的函数叫做`range()`，可以生成给定范围内的数字；现在，让我们尝试用迭代器重新创建它：

1.  创建一个名为`range`的函数，它返回具有`iterator`属性的对象：

```js
function range(max) {
   return {
      *[Symbol.iterator]() {
        yield 1;
      }
   };
}
```

1.  在我们的`range`函数上使用`for..in`循环：

```js
for (let value of range(10)) {
   console.log(value);
}
```

以下是上述代码的输出：

![图 7.54：使用 for..in 循环输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_54.jpg)

###### 图 7.54：使用 for..in 循环输出

当我们运行这段代码时，它只会产生一个值。为了修改它以产生多个结果，我们将用循环包装它。

1.  让我们用循环包装`yield`语句：

```js
function range(max) {
   return {
      *[Symbol.iterator]() {
        for (let i = 0; i < max; i++) {
           yield i;
        }
      }
   };
}
```

通常情况下，这不会与`returns`一起使用，因为它只能被返回一次。这是因为期望生成器函数使用`.next()`多次被消耗。我们可以延迟其执行，直到再次被调用：

![图 7.55：在循环中包装 yield 语句后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_55.jpg)

###### 图 7.55：在循环中包装 yield 语句后的输出

为了更好地理解生成器函数，我们还可以定义一个简单的生成器函数，而不必将其实现为迭代器。

1.  创建一个名为`gen`的生成器函数：

```js
function* gen() {
   yield 1;
}
```

这是对生成器函数的非常简单的定义。当它被调用时，它将返回一个只能遍历一次的生成器。然而，你可以使用前述函数生成任意多的生成器。

1.  生成一个名为`generator`的函数：

```js
const generator = gen();
```

1.  调用生成器的`next`方法来获取它的值：

```js
console.log(generator.next());
console.log(generator.next());
console.log(generator.next());
```

    当我们在生成器上调用`.next()`时，它将执行我们的代码，直到达到`yield`关键字。然后，它将返回该语句产生的值。它还包括一个`done`属性，用于指示这个生成器是否已经遍历了所有可能的值。一旦生成器达到了`done`状态，除非你修改内部状态，否则没有重新开始迭代的方法：

![图 7.56：生成语句后的值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_56.jpg)

###### 图 7.56：生成语句后的值

如您所见，第一次调用`next`方法时，我们将得到值 1。之后，`done`属性将设置为`true`。无论我们调用多少次，它都将始终返回`undefined`，这意味着生成器已经完成了迭代。

在这个练习中，我们介绍了迭代器和生成器。它们在 JavaScript 中非常强大，早期的 async/await 功能很大程度上是使用生成器函数创建的，即使在官方支持之前。下次您创建可以通过迭代的自定义类或对象时，可以创建生成器。这使得代码更清晰，因为不需要管理大量内部状态。

### 代理

当您需要对对象进行更精细的控制，需要管理每个基本操作时，可以使用代理。您可以将 JavaScript 代理视为操作和对象之间的中介。通过它可以有代理，这意味着您可以实现非常复杂的对象。在下一个练习中，我们将介绍可以使用代理来启用对象的创造性方式。

代理就像是对象和程序其余部分之间的中间人。对该对象进行的任何更改都将由代理中继，并且代理将决定如何处理该更改。

创建代理非常容易 - 您只需使用包括我们的处理程序和我们正在代理的对象的对象调用`Proxy`构造函数。创建代理后，您可以将代理视为原始值，并且可以开始修改代理上的属性。

以下是代理的一个示例用法：

```js
const handlers = {
   set: (object, prop, value) => {
      console.log('setting ' + prop);
   }
}
const proxiesValue = new Proxy({}, handlers);
proxiesValue.prop1 = 'hi';
```

我们创建了一个`proxiesValue`并为其设置了一个处理程序。当我们尝试设置`prop1`属性时，我们将得到以下输出：

![图 7.57：创建的代理值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_57.jpg)

###### 图 7.57：创建的代理值

### 练习 60：使用代理构建复杂对象

在这个练习中，我们将使用代理来演示如何构建一个能够隐藏其值并对属性执行数据类型强制的对象。我们还将扩展和定制一些基本操作。让我们开始吧：

1.  创建一个基本的 JavaScript 对象：

```js
const simpleObject = {};
```

1.  创建一个`handlers`对象：

```js
const handlers = {
}
```

1.  为我们的基本对象创建代理封装：

```js
const proxiesValue = new Proxy(simpleObject, handlers);
```

1.  现在，将`handlers`添加到我们的代理中：

```js
const handlers = {
   get: (object, prop) => {
      return 'values are private';
   }
}
```

在这里，我们为我们的对象添加了一个`get`处理程序，我们忽略了它请求的键，只返回了一个固定的字符串。当我们这样做时，无论我们做什么，对象都只会返回我们定义的值。

1.  让我们在代理中测试我们的处理程序：

```js
proxiedValue.key1 = 'value1';
console.log(proxiedValue.key1);
console.log(proxiedValue.keyDoesntExist);
```

以下是上述代码的输出：

![图 7.58：在代理中测试处理程序    ](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_58.jpg)

###### 图 7.58：在代理中测试处理程序

当我们运行这段代码时，我们在对象中给`key1`赋了一个值，但由于我们定义处理程序的方式，在尝试读取值时，它总是返回我们之前定义的字符串。当我们尝试对一个不存在的值进行这样的操作时，它也返回相同的结果。

1.  让我们为验证添加一个 `set` 处理程序：

```js
set: (object, prop, value) => {
      if (prop === 'id') {
        if (!Number.isInteger(value)) {
           throw new TypeError('The id needs to be an integer');
        }
      }
   }
```

我们添加了一个 `set` 处理程序；每当我们尝试对我们的代理整数执行设置操作时，这个处理程序将被调用。

1.  尝试将 `id` 设置为字符串：

```js
proxiedValue.id = 'not an id'
```

![图 7.59：尝试将 id 设置为字符串时显示的 TypeError 截图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_59.jpg)

###### 图 7.59：尝试将 id 设置为字符串时显示的 TypeError 截图

正如你可能已经猜到的那样，当我们尝试进行此操作时，它将给我们一个 `TypeError` 异常。如果您正在构建一个库，且不希望内部属性被覆盖，这是非常有用的。您可以使用符号来做到这一点，但使用代理也是一个选择。另一个用途是实现验证。

在这个练习中，我们讨论了一些可以用来创建对象的创造性方法。通过使用代理，我们可以创建具有内置验证的非常复杂的对象。

### JavaScript 中的重构

在大型应用程序中使用 JavaScript 时，我们需要不时进行重构。重构意味着在保持兼容性的同时重写部分代码。因为 JavaScript 经历了许多阶段和升级，重构也利用了提供的新功能，并使我们的应用程序运行更快，更可靠。重构的一个例子如下：

```js
function appendPrefix(prefix, input) {
   const result = [];
   for (var i = 0; i < input.length; i++) {
      result.push(prefix + input[i]);
   }
   return result;
}
```

这段代码简单地在输入数组的所有元素前附加一个前缀。让我们这样调用它：

```js
appendPrefix('Hi! ', ['Miku', 'Rin', 'Len']);
```

我们将得到以下输出：

![图 7.60：运行数组代码后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_60.jpg)

###### 图 7.60：运行数组代码后的输出

在重构过程中，我们可以用更少的代码编写前面的函数，并仍然保留所有的功能：

```js
function appendPrefix(prefix, input) {
   return input.map((inputItem) => {
      return prefix + inputItem;
   });
}
```

当我们再次调用它时会发生什么？让我们来看一下：

```js
appendPrefix('Hi! ', ['Miku', 'Rin', 'Len']);
```

我们仍然会得到相同的输出：

![图 7.61：重构代码后获得相同的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_07_60.jpg)

###### 图 7.61：重构代码后获得相同的输出

### 活动 10：重构函数以使用现代 JavaScript 特性

你最近加入了一家公司。分配给你的第一个任务是重构一些遗留模块。你打开了文件，发现现有的代码已经使用了遗留的 JavaScript 方法编写。你需要重构该文件中的所有函数，并确保它仍然可以通过所需的测试。

执行以下步骤以完成此活动：

1.  使用 node.js 运行`Activity10.js`来检查测试是否通过。

1.  使用`includes`数组重构`itemExist`函数。

1.  在`pushunique`函数中使用`array push`来向底部添加一个新项。

1.  在`createFilledArray`中使用`array.fill`来用初始值填充我们的数组。

1.  在`removeFirst`函数中使用`array.shift`来移除第一项。

1.  在`removeLast`函数中使用`array.pop`来移除最后一项。

1.  在`cloneArray`中使用展开运算符来克隆我们的数组。

1.  使用`ES6`类重构`Food`类。

1.  重构后，运行代码以观察与旧代码生成相同的输出。

#### 注意

这个活动的解决方案可以在第 611 页找到。

在这个活动中，我们学会了如何通过重构函数来使用现代 JavaScript 函数。我们已经成功学会了如何重写代码同时保持其兼容性。

## 总结

在本章中，我们首先看了一下在 JavaScript 中构建和操作数组和对象的方法。然后，我们看了一下使用展开运算符来连接数组和对象的方法。使用展开运算符可以避免我们编写不带循环的函数。后来，我们看了一下在 JavaScript 中进行面向对象编程的方法。通过使用这些类和类继承，我们可以构建复杂的应用程序，而不必编写大量重复的代码。我们还看了 Array、Map、Set、Regex、Date 和 Math 的内置方法。当我们需要处理大量不同类型的数据时，这些方法非常有用。最后，符号、迭代器、生成器和代理在使我们的程序动态和清晰方面开辟了广阔的可能性。这结束了我们关于高级 JavaScript 的章节。在下一章中，我们将讨论 JavaScript 中的异步编程。
