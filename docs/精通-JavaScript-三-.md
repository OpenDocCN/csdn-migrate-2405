# 精通 JavaScript（三）

> 原文：[`zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3`](https://zh.annas-archive.org/md5/866633107896D180D34D9AC33F923CF3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：测试与调试

随着你编写 JavaScript 应用程序，你很快就会意识到拥有一个健全的测试策略是不可或缺的。事实上，编写足够的测试用例几乎总是一个坏主意。确保以下几点非常重要：

+   现有的代码按照规范运行。

+   任何新代码都不会破坏规格定义的行为。

这两个点都非常重要。许多工程师认为只有第一个点是覆盖代码足够测试的唯一原因。测试覆盖的最明显优势是确保推送到生产系统的代码基本上是错误免费的。编写测试用例以智能地覆盖代码的最大功能区域通常会给你关于代码整体质量的一个很好的指示。在这个问题上不应该有任何争论或妥协。不幸的是，许多生产系统仍然缺乏足够的代码覆盖。建立一个工程师文化，让开发者在编写代码时思考编写测试用例，这一点非常重要。

第二个点甚至更重要。遗留系统通常非常难以管理。当你在别人写的代码或大型分布式团队写的代码上工作时，很容易引入错误和破坏事物。即使是最优秀的工程师也会犯错误。当你在一个你不太熟悉的大的代码库上工作时，如果没有健全的测试覆盖来帮助你，你会引入错误。由于没有测试用例来确认你的更改，你对所做的更改没有信心，你的代码发布将会是颤抖的、缓慢的，显然充满了隐藏的错误。

你将避免重构或优化你的代码，因为你其实不确定代码库的哪些更改可能会潜在地破坏某些功能（再次，因为没有测试用例来确认你的更改）——所有这些都是一个恶性的循环。这就像一个土木工程师说，“虽然我已经建造了这座桥，但我对自己建造的质量没有信心。它可能会立即倒塌或永远不会倒塌。”尽管这听起来像是一种夸张，但我见过很多高影响的生产代码在没有测试覆盖的情况下被推送到生产环境中。这是危险的，应该避免。当你编写足够的测试用例来覆盖大部分功能性代码，并对这些代码进行更改时，你会立即意识到是否有新更改的问题。如果你的更改导致测试用例失败，你就会意识到问题。如果你的重构破坏了测试场景，你就会意识到问题——所有这些都发生在代码推送到生产环境之前。

近年来，像测试驱动开发和自测试代码这样的想法越来越流行，尤其是在**敏捷方法论**中。这些从根本上来说是正确的想法，将帮助你编写健壮的代码——你自信的代码。我们将在本章讨论所有这些想法。你将了解如何在现代 JavaScript 中编写好的测试用例。我们还将查看几种调试代码的工具和方法。JavaScript 传统上在测试和调试方面一直有点困难，主要是因为缺乏工具，但现代工具使这两者变得容易和自然。

# 单元测试

当我们谈论测试用例时，我们大部分时候是指**单元测试**。假设我们要测试的单元始终是一个函数是不正确的。单元（或工作单元）是一个构成单一行为的逻辑单位。这个单元应该能够通过公共接口调用，并且应该能够独立测试。

因此，单元测试执行以下功能：

+   它测试一个单一的逻辑函数

+   它可以不按照特定的执行顺序运行

+   它处理自己的依赖项和模拟数据

+   它总是对相同的输入返回相同的结果

+   它应该是自解释的，可维护的，可读的

### 注意

马丁·福勒提倡使用**测试金字塔**([`martinfowler.com/bliki/TestPyramid.html`](http://martinfowler.com/bliki/TestPyramid.html))策略，以确保我们有大量的单元测试，从而确保最大的代码覆盖率。测试金字塔指出，你应该编写比高级集成和 UI 测试更多的底层单元测试。

有两种重要的测试策略我们将在此章节讨论。

## 测试驱动开发

**测试驱动** **开发**（**TDD**）在过去几年中得到了很多重视。这个概念最初是在**极限编程**方法论中提出的。这个想法是有一个短暂重复的开发周期，重点是先编写测试用例。这个周期如下所示：

1.  根据特定代码单元的规格添加测试用例。

1.  运行现有的测试用例套，看看你写的新的测试用例是否会失败——它应该会（因为没有为此单元编写代码）。这一步确保当前的测试框架运行良好。

1.  编写主要用来确认测试用例的代码。这段代码没有优化或重构，甚至可能不完全正确。然而，此刻这是可以接受的。

1.  重新运行测试，看看所有测试用例是否通过。在这个步骤之后，你会自信新代码没有破坏任何东西。

1.  重构代码，确保你在优化单元并处理所有边缘情况。

这些步骤会为新添加的所有代码重复执行。这是一种非常优雅的策略，非常适合敏捷方法论。TDD 只有在可测试的代码单元小且只符合测试用例时才会成功。编写小型的、模块化的、精确的代码单元非常重要，这些单元的输入和输出符合测试用例。

## 行为驱动开发

在尝试遵循 TDD 时一个非常常见的问题就是词汇和正确性的定义。BDD 试图在遵循 TDD 时引入一个*普遍的语言*。这种语言确保业务和工程团队都在谈论同一件事。

我们将使用**Jasmine**作为主要的 BDD 框架，并探索各种测试策略。

### 注意

您可以从[`github.com/jasmine/jasmine/releases/download/v2.3.4/jasmine-standalone-2.3.4.zip`](https://github.com/jasmine/jasmine/releases/download/v2.3.4/jasmine-standalone-2.3.4.zip)下载独立包来安装 Jasmine。

解压此包后，您将拥有以下目录结构：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00011.jpeg)

`lib`目录包含了你在项目中开始编写 Jasmine 测试用例所需的 JavaScript 文件。如果你打开`SpecRunner.html`，你会发现以下 JavaScript 文件包含在其中：

```js
<script src="img/jasmine.js"></script>
<script src="img/jasmine-html.js"></script>
<script src="img/boot.js"></script>    

<!-- include source files here... -->   
<script src="img/Player.js"></script>   
<script src="img/Song.js"></script>    
<!-- include spec files here... -->   
<script src="img/SpecHelper.js"></script>   
<script src="img/PlayerSpec.js"></script>
```

前三项是 Jasmine 自己的框架文件。下一部分包括我们要测试的源文件和实际的测试规格。

让我们用一个非常普通的例子来实验 Jasmine。创建一个`bigfatjavascriptcode.js`文件，并将其放在`src/`目录中。我们将测试以下函数：

```js
function capitalizeName(name){
  return name.toUpperCase();
}
```

这是一个只做一件事情的简单函数。它接收一个字符串并返回一个首字母大写的字符串。我们将围绕这个函数测试各种场景。这是我们之前讨论过的代码单元。

接下来，创建测试规格。创建一个 JavaScript 文件，`test.spec.js`，并将其放在`spec/`目录中。该文件应包含以下内容。您需要向`SpecRunner.html`中添加以下两行：

```js
<script src="img/bigfatjavascriptcode.js"></script> 
<script src="img/test.spec.js"></script> 
```

这个包含的顺序不影响。当我们运行`SpecRunner.html`时，你会看到如下内容：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00012.jpeg)

这是显示执行测试次数和失败和成功计数的 Jasmine 报告。现在，让我们让测试用例失败。我们想测试一个将未定义变量传递给函数的用例。再添加一个测试用例如下：

```js
it("can handle undefined", function() {
  var str= undefined;
  expect(capitalizeName(str)).toEqual(undefined);
});
```

现在，当你运行`SpecRunner.html`时，你会看到以下结果：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00013.jpeg)

正如你所见，这个测试用例的失败以详细的错误堆栈显示出来。现在，我们来解决这个问题。在你原始的 JavaScript 代码中，我们可以这样处理一个未定义的条件：

```js
function capitalizeName(name){
  if(name){
    return name.toUpperCase();
  }
}
```

有了这个改变，你的测试用例将通过，你将在 Jasmine 报告中看到以下内容：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00014.jpeg)

这和测试驱动开发非常相似。你编写测试用例，然后填充必要的代码以符合规格，然后重新运行测试套件。让我们了解 Jasmine 测试的结构。

我们的测试规格如下：

```js
describe("TestStringUtilities", function() {
  it("converts to capital", function() {
    var str = "albert";
    expect(capitalizeName(str)).toEqual("ALBERT");
  });
  it("can handle undefined", function() {
    var str= undefined;
    expect(capitalizeName(str)).toEqual(undefined);
  });
});
```

`describe("TestStringUtilities"`是一个测试套件。测试套件的名称应该描述我们正在测试的代码单元——这可以是一个函数或一组相关功能。在规格说明中，你调用全局 Jasmine `it`函数，并向其传递规格的标题和测试函数，该函数用于测试用例。这个函数是实际的测试用例。你可以使用`expect`函数捕获一个或多个断言或一般期望。当所有期望都是`true`时，你的规格说明通过。你可以在`describe`和`it`函数中编写任何有效的 JavaScript 代码。作为期望值的一部分，我们使用匹配器进行匹配。在我们示例中，`toEqual()`是匹配两个值相等的匹配器。Jasmine 包含一组丰富的匹配器，以适应大多数常见用例。Jasmine 支持的一些常见匹配器如下：

+   `toBe()`：这个匹配器检查两个比较对象是否相等。这和`===`比较一样，如下面的代码所示：

    ```js
    var a = { value: 1};
    var b = { value: 1 };

    expect(a).toEqual(b);  // success, same as == comparison
    expect(b).toBe(b);     // failure, same as === comparison
    expect(a).toBe(a);     // success, same as === comparison
    ```

+   `not`：你可以用`not`前缀来否定一个匹配器。例如，`expect(1).not.toEqual(2);`将否定`toEqual()`所建立的匹配。

+   `toContain()`：这检查一个元素是否是数组的一部分。这不同于`toBe()`的精确对象匹配。例如，看看以下代码：

    ```js
    expect([1, 2, 3]).toContain(3);
    expect("astronomy is a science").toContain("science");
    ```

+   `toBeDefined()`和`toBeUndefined()`：这两个匹配器很方便，用于检查变量是否未定义（或不是）。

+   `toBeNull()`：这检查变量的值是否为`null`。

+   `toBeGreaterThan()`和`toBeLessThan()`：这些匹配器执行数值比较（它们也可以用于字符串）：

    ```js
    expect(2).toBeGreaterThan(1);
    expect(1).toBeLessThan(2);
    expect("a").toBeLessThan("b");
    ```

Jasmine 的一个有趣特性是**间谍**功能。当你编写一个大型系统时，不可能确保所有系统始终可用且正确。同时，你不想因为一个可能已损坏或不可用的依赖而使单元测试失败。为了模拟一个所有依赖项对我们要测试的代码单元都可用的情况，我们模拟这些依赖项以总是给出我们期望的响应。模拟是测试的一个重要方面，大多数测试框架都提供对模拟的支持。Jasmine 通过一个称为间谍的特征允许模拟。Jasmine 间谍本质上是我们可能没有准备好的函数的桩；在编写测试用例时，我们需要跟踪我们正在执行这些依赖项，而不是忽略它们。请考虑以下示例：

```js
describe("mocking configurator", function() {
  var configurator = null;
  var responseJSON = {};

  beforeEach(function() {
    configurator = {
      submitPOSTRequest: function(payload) {
        //This is a mock service that will eventually be replaced 
        //by a real service
        console.log(payload);
        return {"status": "200"};
      }
    };
 spyOn(configurator, 'submitPOSTRequest').and.returnValue({"status": "200"});
    configurator.submitPOSTRequest({
      "port":"8000",
      "client-encoding":"UTF-8"
    });
  });

  it("the spy was called", function() {
    expect(configurator.submitPOSTRequest).toHaveBeenCalled();
  });

  it("the arguments of the spy's call are tracked", function() {
    expect(configurator.submitPOSTRequest).toHaveBeenCalledWith({"port":"8000","client-encoding":"UTF-8"});
  });
});
```

在这个例子中，当我们编写这个测试用例时，要么我们没有`configurator.submitPOSTRequest()`依赖的实际实现，要么有人正在修复这个特定的依赖。无论如何，我们目前没有可用。为了让我们的测试工作，我们需要模拟它。Jasmine 间谍允许我们用模拟函数替换一个函数并追踪其执行。

在这种情况下，我们需要确保我们调用了依赖。当实际的依赖准备就绪时，我们将重新审视这个测试用例，以确保它符合规格，但此时，我们只需要确保依赖被调用即可。Jasmine 的`toHaveBeenCalled()`函数让我们能够追踪函数的执行，该函数可能是一个模拟函数。我们可以使用`toHaveBeenCalledWith()`来确定 stub 函数是否用正确的参数被调用。使用 Jasmine 间谍，你可以创建几个其他有趣的场景。本章节的范围不允许我们涵盖它们所有，但我鼓励你自己去发现这些领域。

### 注意

你可以参考 Jasmine 用户手册，了解关于 Jasmine 间谍的更多信息，链接为：[`jasmine.github.io/2.0/introduction.html`](http://jasmine.github.io/2.0/introduction.html)。

### 提示

**Mocha，Chai 和 Sinon**

尽管 Jasmine 是最著名的 JavaScript 测试框架，但在 Node.js 环境中，**Mocha**和**Chai**越来越受到重视。Mocha 是用于描述和运行测试用例的测试框架。Chai 是支持 Mocha 的断言库。**Sinon.JS**在创建测试的模拟和 stub 时非常有用。本书不会讨论这些框架，但如果你想尝试这些框架，对 Jasmine 的了解将会有帮助。

# JavaScript 调试

如果你不是一个完全的新程序员，我相信你一定花了一些时间来调试自己的代码或别人的代码。调试几乎像一种艺术形式。每种语言都有不同的调试方法和挑战。JavaScript 传统上是一个难以调试的语言。我曾经为了使用`alert()`函数调试糟糕的 JavaScript 代码而痛苦不堪。幸运的是，现代浏览器如 Mozilla Firefox 和 Google Chrome 都有出色的开发者工具来帮助调试浏览器中的 JavaScript。还有像**IntelliJ WebStorm**这样的 IDE，为 JavaScript 和 Node.js 提供了出色的调试支持。在本章中，我们将重点介绍 Google Chrome 内置的开发者工具。Firefox 也支持 Firebug 扩展，并具有出色的内置开发者工具，但它们的行为与 Google Chrome 的**开发者工具**（**DevTools**）大致相同，因此我们将讨论这两种工具都适用的常见调试方法。

在我们讨论具体的调试技术之前，让我们先了解在尝试调试我们的代码时我们可能感兴趣的错误类型。

## 语法错误

当你的代码有不符合 JavaScript 语言语法的内容时，解释器会拒绝这部分代码。如果你的 IDE 支持语法检查，这些错误很容易被捕捉到。大多数现代 IDE 都能帮助检测这些错误。之前，我们讨论了像**JSLint**和**JSHint**这样的工具有助于捕捉代码中的语法问题。它们分析代码并在语法上标出错误。JSHint 的输出可能非常有启发性。例如，以下输出显示了代码中我们可以更改许多内容。以下片段来自我现有项目中的一个：

```js
temp git:(dev_branch) ✗ jshint test.js
test.js: line 1, col 1, Use the function form of "use strict".
test.js: line 4, col 1, 'destructuring expression' is available in ES6 (use esnext option) or Mozilla JS extensions (use moz).
test.js: line 44, col 70, 'arrow function syntax (=>)' is only available in ES6 (use esnext option).
test.js: line 61, col 33, 'arrow function syntax (=>)' is only available in ES6 (use esnext option).
test.js: line 200, col 29, Expected ')' to match '(' from line 200 and instead saw ':'.
test.js: line 200, col 29, 'function closure expressions' is only available in Mozilla JavaScript extensions (use moz option).
test.js: line 200, col 37, Expected '}' to match '{' from line 36 and instead saw ')'.
test.js: line 200, col 39, Expected ')' and instead saw '{'.
test.js: line 200, col 40, Missing semicolon.
```

## 使用严格模式

在早前的章节中，我们简要讨论了**严格模式**。JavaScript 中的严格模式可以标出或消除一些 JavaScript 的隐式错误。严格模式不会默默失败，而是让这些错误抛出异常。严格模式还能帮助将错误转化为实际的错误。强制严格模式有两种方法。如果你想让整个脚本都使用严格模式，你只需在 JavaScript 程序的第一行添加`use strict`声明。如果你想让某个特定函数遵循严格模式，你可以在函数的第一行添加指令：

```js
function strictFn(){ 
// This line makes EVERYTHING under this strict mode
'use strict'; 
…
function nestedStrictFn() { 
//Everything in this function is also nested
…
} 
}
```

## 运行时异常

这些错误出现在执行代码时，尝试引用一个未定义的变量或处理一个 null。当运行时异常发生时，导致异常的那一行之后的任何代码都不会被执行。在代码中正确处理这种异常情况至关重要。虽然异常处理可以帮助防止程序崩溃，但它也助于调试。你可以将可能遇到运行时异常的代码包裹在一个`try{ }`块中。当这个块中的任何代码引发运行时异常时，相应的处理程序会捕获它。这个处理程序由一个`catch(exception){}`块定义。让我们通过一个例子来澄清这一点：

```js
try {
  var a = doesnotexist; // throws a runtime exception
} catch(e) { 
  console.log(e.message);  //handle the exception
  //prints - "doesnotexist is not defined"
}
```

在这个例子中，`var a = doesnotexist;`行试图将一个未定义的变量`doesnotexist`赋值给另一个变量`a`。这会导致运行时异常。当我们把这段有问题的代码包裹在`try{} catch(){}`块中，当异常发生（或被抛出）时，执行会在`try{}`块中停止，并直接跳到`catch() {}`处理程序。`catch`处理程序负责处理异常情况。在这个例子中，我们在控制台上显示错误消息以供调试。你可以显式地抛出一个异常来触发代码中的一个未处理场景。考虑以下例子：

```js
function engageGear(gear){
  if(gear==="R"){ console.log ("Reversing");}
  if(gear==="D"){ console.log ("Driving");}
  if(gear==="N"){ console.log ("Neutral/Parking");}
 throw new Error("Invalid Gear State");
}
try
{
  engageGear("R");  //Reversing
  engageGear("P");  //Invalid Gear State
}
catch(e){
  console.log(e.message);
}
```

在这个例子中，我们处理了齿轮换挡的有效状态（`R`、`N`和`D`），但当我们收到一个无效状态时，我们明确地抛出一个异常，清楚地说明原因。当我们调用我们认为是可能抛出异常的函数时，我们将代码包裹在`try{}`块中，并附上一个`catch(){}`处理程序。当异常被`catch()`块捕获时，我们适当地处理异常条件。

### 控制台打印和断言

在控制台上显示执行状态在调试时非常有用。然而，现代开发者工具允许你在运行时设置断点并暂停执行以检查特定值。你可以在控制台上记录一些变量的状态，快速检测小问题。

有了这些概念，让我们看看如何使用 Chrome 开发者工具来调试 JavaScript 代码。

### Chrome DevTools

你可以通过导航到菜单 | **更多工具** | **开发者工具**来启动 Chrome DevTools：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00015.jpeg)

Chrome DevTools 在浏览器的下部面板中打开，并有一组非常有用的部分：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00016.jpeg)

**元素**面板帮助你检查和监视每个组件的 DOM 树和相关样式表。

**网络**面板有助于了解网络活动。例如，你可以实时监视网络上下载的资源。

对我们来说最重要的面板是**源代码**面板。这个面板是显示 JavaScript 源代码和调试器的部分。让我们创建一个带有以下内容的示例 HTML：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>This test</title>
  <script type="text/javascript">
  function engageGear(gear){
    if(gear==="R"){ console.log ("Reversing");}
    if(gear==="D"){ console.log ("Driving");}
    if(gear==="N"){ console.log ("Neutral/Parking");}
    throw new Error("Invalid Gear State");
  }
  try
  {
    engageGear("R");  //Reversing
    engageGear("P");  //Invalid Gear State
  }
  catch(e){
    console.log(e.message);
  }
  </script>
</head>
<body>
</body>
</html>
```

保存这个 HTML 文件并在 Google Chrome 中打开它。在浏览器中打开 DevTools，你会看到以下屏幕：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00017.jpeg)

这是**源代码**面板的视图。你可以在这个面板中看到 HTML 和嵌入的 JavaScript 源代码。你也可以看到控制台窗口。你可以看到文件被执行并在**控制台**中显示输出。

在右侧，你会看到调试器窗口：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00018.jpeg)

在**源代码**面板中，点击行号**8**和**15**来添加断点。断点允许你在指定的点停止脚本的执行：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00019.jpeg)

在调试面板中，你可以看到所有现有的断点：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00020.jpeg)

现在，当你再次运行同一页面时，你会看到执行停留在调试点。在调试阶段注入代码是一个非常实用的技术。当调试器正在运行时，你可以添加代码以帮助你更好地理解代码的状态：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00021.jpeg)

这个窗口现在有所有的动作。你可以看到执行停在**15**行。在调试窗口中，你可以看到哪个断点被触发。你也可以看到**调用栈**。你有几种方法可以继续执行。调试命令窗口有一组动作：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00022.jpeg)

你可以通过点击![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00023.jpeg)按钮来继续执行（这将执行到下一个断点），当你这样做时，执行会继续直到遇到下一个断点。在我们的案例中，我们在第**8**行暂停：

![Chrome DevTools](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00024.jpeg)

你可以观察到**调用栈**窗口显示了我们如何到达第**8**行。**作用域**面板显示了**局部**作用域，你可以看到在到达断点时的作用域中的变量。你还可以步入或跳过下一个函数。

使用 Chrome DevTools 还有其他非常实用的机制来调试和分析你的代码。我建议你去尝试这个工具，并使其成为你常规开发流程的一部分。

# 摘要

测试和调试阶段对于开发健壮的 JavaScript 代码都至关重要。TDD 和 BDD 是与敏捷方法论紧密相关的方法，并被 JavaScript 开发者社区广泛采用。在本章中，我们回顾了围绕 TDD 的最佳实践以及使用 Jasmine 作为测试框架的方法。我们看到了使用 Chrome DevTools 进行各种 JavaScript 调试的方法。在下一章中，我们将探索 ES6、DOM 操作和跨浏览器策略这个新奇的世界。


# 第七章：ECMAScript 6

到目前为止，我们已经对 JavaScript 编程语言进行了详细的了解。我相信您一定对语言的核心有了深刻的了解。到目前为止，我们所了解的都是按照**ECMAScript** **5**（**ES5**）标准进行的。**ECMAScript 6**（**ES6**）或**ECMAScript 2015**（**ES2015**）是 ECMAScript 标准的最新版本。这个标准在不断发展，最后一次修改是在 2015 年 6 月。ES2015 在其范围和推荐方面都具有重要意义，并且 ES2015 的推荐正在大多数 JavaScript 引擎中得到实施。这对我们来说是个好消息。ES6 引入了大量的新特性和帮助器，这些新特性和帮助器极大地丰富了语言。ECMAScript 标准的快速发展使得浏览器和 JavaScript 引擎支持新特性变得有些困难。同时，大多数程序员实际上需要编写可以在旧浏览器上运行的代码。臭名昭著的 Internet Explorer 6 曾经是世界上使用最广泛的浏览器。确保您的代码与尽可能多的浏览器兼容是一项艰巨的任务。因此，虽然您想使用 ES6 下一组酷炫的特性，但您必须考虑这样一个事实：许多 ES6 特性可能不被最流行的浏览器或 JavaScript 框架支持。

这看起来可能是一个糟糕的情况，但事情并没有那么糟糕。**Node.js**使用支持大多数 ES6 特性的最新版 V8 引擎。Facebook 的**React**也支持它们。Mozilla Firefox 和 Google Chrome 是目前使用最广泛的两种浏览器，它们支持大多数 ES6 特性。

为了避免这些陷阱和不可预测性，提出了一些解决方案。这些解决方案中最有用的是 polyfills/shims 和转译器。

# Shims 或 polyfills

Polyfills（也称为 shims）是一种定义新版本环境中兼容旧版本环境的行为的模式。有一个很棒的 ES6 shims 集合叫做**ES6 shim**（[`github.com/paulmillr/es6-shim/`](https://github.com/paulmillr/es6-shim/)）；我强烈建议您研究这些 shims。从 ES6 shim 集合中，考虑以下 shim 的示例。

根据 ECMAScript 2015（ES6）标准，`Number.isFinite()`方法用于确定传递的值是否是一个有限数字。它的等效 shim 可能如下所示：

```js
var numberIsFinite = Number.isFinite || function isFinite(value) {
  return typeof value === 'number' && globalIsFinite(value);
};
```

这个 shim 首先检查`Number.isFinite()`方法是否可用；如果不可用，则用实现来*填充*它。这是一种非常巧妙的技巧，用于填补规范中的空白。shims 不断升级，加入新特性，因此，在项目中保留最新版本的 shims 是一个明智的策略。

### 注意

`endsWith()` polyfill 的详细说明可以在 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith) 找到。`String.endsWith()` 是 ES6 的一部分，但可以很容易地为 pre-ES6 环境进行 polyfill。

然而，shims 不能 polyfill 语法变化。为此，我们可以考虑转译器作为一个选项。

# 转译器

转译是一种结合了编译和转换的技术。想法是写 ES6 兼容的代码，并使用一个将这种代码转译成有效且等效的 ES5 代码的工具。我们将探讨最完整且流行的 ES6 转译器，名为 **Babel** ([`babeljs.io/`](https://babeljs.io/)）。

Babel 可以用多种方式使用。你可以把它安装为 node 模块，从命令行调用它，或者在你的网页中导入它作为一个脚本。Babel 的设置非常全面且文档齐全，详情请查看 [`babeljs.io/docs/setup/`](https://babeljs.io/docs/setup/)。Babel 还有一个很棒的 **Read-Eval-Print-Loop** (**REPL**)。在本章中，我们将使用 Babel REPL 来进行大多数示例。深入理解 Babel 可以用的各种方式超出了本书的范围。然而，我建议你开始将 Babel 作为你开发工作流程的一部分来使用。

我们将在本章覆盖 ES6 规范的最重要部分。如果可能的话，你应该探索 ES6 的所有特性，并让它们成为你开发工作流程的一部分。

# ES6 语法变化

ES6 为 JavaScript 带来了重大的语法变化。这些变化需要仔细学习和适应。在本节中，我们将学习一些最重要的语法变化，并了解如何使用 Babel 立即在你的代码中使用这些新的构造。

## 块级作用域

我们之前讨论过，JavaScript 中的变量是函数作用域的。在嵌套作用域中创建的变量对整个函数都是可用的。几种编程语言为你提供了一个默认的块作用域，其中在任何代码块（通常由 `{}` 限定）中声明的变量（可用）仅限于这个块。为了在 JavaScript 中实现类似的块作用域，一个普遍的方法是使用立即调用函数表达式（**IIFE**）。考虑以下示例：

```js
var a = 1;
(function blockscope(){
    var a = 2;
    console.log(a);   // 2
})();
console.log(a);       // 1
```

使用 IIFE，我们为 `a` 变量创建了一个块作用域。当在 IIFE 中声明一个变量时，它的作用域被限制在函数内部。这是模拟块作用域的传统方式。ES6 支持不使用 IIFE 的块作用域。在 ES6 中，你可以用 `{}` 定义的块来包含任何语句（或语句）。用 `var` 声明变量，你可以使用 `let` 来定义块作用域。前一个示例可以用 ES6 块作用域重写如下：

```js
"use strict";
var a = 1;
{
  let a = 2;
  console.log( a ); // 2
}
console.log( a ); // 1
```

在 JavaScript 中使用独立的方括号`{}`可能看起来很奇怪，但这种约定在许多语言中用来创建块级作用域是非常普遍的。块级作用域同样适用于其他构造，比如`if { }`或`for (){ }`。

当你以这种方式使用块级作用域时，通常最好将变量声明放在块的最顶部。`var`和`let`声明的变量之间的一个区别是，用`var`声明的变量附着在整个函数作用域上，而用`let`声明的变量附着在块级作用域上，并且在块中出现之前它们不会被初始化。因此，你不能在声明之前访问用`let`声明的变量，而对于用`var`声明的变量，顺序并不重要：

```js
function fooey() {
  console.log(foo); // ReferenceError
  let foo = 5000;
}
```

`let`的一个特定用途是在 for 循环中。当我们使用`var`声明一个变量在 for 循环中时，它是在全局或父作用域中创建的。我们可以在 for 循环作用域中通过使用`let`声明一个变量来创建一个块级作用域的变量。考虑以下示例：

```js
for (let i = 0; i<5; i++) {
  console.log(i);
}
console.log(i); // i is not defined
```

由于`i`是通过`let`创建的，它在`for`循环中是有作用域的。你可以看到，这个变量在作用域之外是不可用的。

在 ES6 中，块级作用域的另一个用途是创建常量。使用`const`关键字，你可以在块级作用域中创建常量。一旦值被设置，你就无法改变这样一个常量的值：

```js
if(true){
  const a=1;
  console.log(a);
  a=100;  ///"a" is read-only, you will get a TypeError
}
```

常量必须在声明时初始化。同样的块级作用域规则也适用于函数。当一个函数在块内部声明时，它只能在那个作用域内使用。

## 默认参数

默认值是非常常见的。你总是为传递给函数的参数或你初始化的变量设置一些默认值。你可能见过类似下面的代码：

```js
function sum(a,b){
  a = a || 0;
  b = b || 0;
  return (a+b);
}
console.log(sum(9,9)); //18
console.log(sum(9));   //9
```

在这里，我们使用`||`（或运算符）来默认变量`a`和`b`如果没有在调用函数时提供值，则默认为`0`。在 ES6 中，你有了一种标准的默认函数参数的方法。之前的示例可以重写如下：

```js
function sum(a=0, b=0){
  return (a+b);
}
console.log(sum(9,9)); //18
console.log(sum(9));   //9
```

你可以将任何有效的表达式或函数调用作为默认参数列表的一部分传递。

## 展开和剩余

ES6 有一个新的操作符，`…`。根据它的使用方式，它被称为`展开`或`剩余`。让我们看一个简单的例子：

```js
function print(a, b){
  console.log(a,b);
}
print(...[1,2]);  //1,2
```

这里发生的事情是，当你在数组（或可迭代对象）前加上`…`时，它*展开*了数组中的元素，将其分别赋值给函数参数中的独立变量。当数组被展开时，`a`和`b`这两个函数参数被赋予了数组中的两个值。在展开数组时，会忽略多余的参数：

```js
print(...[1,2,3 ]);  //1,2
```

这仍然会打印`1`和`2`，因为这里只有两个功能参数可用。展开也可以用在其他地方，比如数组赋值：

```js
var a = [1,2];
var b = [ 0, ...a, 3 ];
console.log( b ); //[0,1,2,3]
```

`…`操作符还有一个与我们刚才看到完全相反的用途。不是展开值，而是用同一个操作符将它们聚集到一起：

```js
function print (a,...b){
  console.log(a,b);
}
console.log(print(1,2,3,4,5,6,7));  //1 [2,3,4,5,6,7]
```

在这种情况下，变量`b`取剩余的值。变量`a`取第一个值作为`1`，变量`b`取剩余的值作为一个数组。

## 解构

如果你在函数式语言如**Erlang**上工作过，你会理解模式匹配的概念。JavaScript 中的解构与之一致。解构允许你使用模式匹配将值绑定到变量。考虑以下示例：

```js
var [start, end] = [0,5];
for (let i=start; i<end; i++){
  console.log(i);
}
//prints - 0,1,2,3,4
```

我们使用数组解构来分配两个变量：

```js
var [start, end] = [0,5];
```

如前所示的例子，我们希望模式在第一个值分配给第一个变量（`start`）和第二个值分配给第二个变量（`end`）时匹配。考虑以下片段，看看数组元素解构是如何工作的：

```js
function fn() {
  return [1,2,3];
}
var [a,b,c]=fn();
console.log(a,b,c); //1 2 3
//We can skip one of them
var [d,,f]=fn();
console.log(d,f);   //1 3
//Rest of the values are not used
var [e,] = fn();
console.log(e);     //1
```

让我们讨论一下对象解构是如何工作的。假设你有一个返回对象的函数`f`，它按照如下方式返回：

```js
function f() {
  return {
    a: 'a',
    b: 'b',
    c: 'c'
  };
}
```

当我们解构这个函数返回的对象时，我们可以使用我们之前看到的类似语法；不同的是，我们使用`{}`而不是`[]`：

```js
var { a: a, b: b, c: c } = f();
console.log(a,b,c); //a b c
```

与数组类似，我们使用模式匹配将变量分配给函数返回的相应值。如果你使用与匹配的变量相同的变量，这种写法会更短。下面的例子恰到好处：

```js
var { a,b,c } = f();
```

然而，你通常会使用与函数返回的变量不同的变量名。重要的是要记住，语法是*源：目标*，而不是通常的*目标：源*。仔细观察下面的例子：

```js
//this is target: source - which is incorrect
var { x: a, x: b, x: c } = f();
console.log(x,y,z); //x is undefined, y is undefined z is undefined
//this is source: target - correct
var { a: x, b: y, c: z } = f();
console.log(x,y,z); // a b c
```

这是*目标 = 源*赋值方式的相反，因此需要一些时间来适应。

## 对象字面量

对象字面量在 JavaScript 中无处不在。你会认为没有改进的余地。然而，ES6 也想改进这一点。ES6 引入了几种快捷方式，以围绕对象字面量创建紧凑的语法：

```js
var firstname = "Albert", lastname = "Einstein",
  person = {
    firstname: firstname,
    lastname: lastname
  };
```

如果你打算使用与分配变量相同的属性名，你可以使用 ES6 的紧凑属性表示法：

```js
var firstname = "Albert", lastname = "Einstein",
  person = {
    firstname,
    lastname
  };
```

同样地，你是这样给属性分配函数的：

```js
var person = {
  getName: function(){
    // ..
  },
  getAge: function(){
    //..
  }
}
```

与其前的行相比，你可以这样说：

```js
var person = {
  getName(){
    // ..
  },
  getAge(){
    //..
  }
}
```

## 模板字面量

我相信你肯定做过如下的事情：

```js
function SuperLogger(level, clazz, msg){
  console.log(level+": Exception happened in class:"+clazz+" - Exception :"+ msg);
}
```

这是一种非常常见的替换变量值以形成字符串字面量的方法。ES6 为您提供了一种新的字符串字面量类型，使用反引号（`）：

函数 SuperLogger(level, clazz, msg){

console.log(`${level} : 在类: ${clazz} 中发生异常 - 异常 : {$msg}`);

}

` around 一个字符串字面量。在这个字面量内部，任何`${..}`形式的表达式都会立即解析。这种解析称为插值。在解析时，变量的值替换了`${}`内的占位符。结果字符串只是普通字符串，占位符被实际变量值替换。

使用字符串插值，你也可以将字符串拆分为多行，如下面的代码所示（与 Python 非常相似）：

```js
var quote =
`Good night, good night! 
Parting is such sweet sorrow, 
that I shall say good night 
till it be morrow.`;
console.log( quote );
```

你可以使用函数调用或有效的 JavaScript 表达式作为字符串插值的一部分：

```js
function sum(a,b){
  console.log(`The sum seems to be ${a + b}`);
}
sum(1,2); //The sum seems to be 3
```

模板字符串的最后一种变体称为**带标签的模板字符串**。想法是用一个函数来修改模板字符串。考虑以下示例：

```js
function emmy(key, ...values){
  console.log(key);
  console.log(values);
}
let category="Best Movie";
let movie="Adventures in ES6";
emmy`And the award for ${category} goes to ${movie}`;

//["And the award for "," goes to ",""]
//["Best Movie","Adventures in ES6"]
```

当我们用模板字面量调用`emmy`函数时，最奇怪的是这并不是传统函数调用的语法。我们不是写`emmy()`；我们只是在标记字面量。当这个函数被调用时，第一个参数是所有普通字符串（插值表达式之间的字符串）的数组。第二个参数是所有插值表达式被求值和存储的数组。

这意味着标签函数实际上可以改变结果模板标签：

```js
function priceFilter(s, ...v){
  //Bump up discount
  return s[0]+ (v[0] + 5);
}
let default_discount = 20;
let greeting = priceFilter `Your purchase has a discount of ${default_discount} percent`;
console.log(greeting);  //Your purchase has a discount of 25
```

正如你所看到的，我们在标签函数中修改了折扣的值并返回了修改后的值。

## 映射和集合

ES6 引入了四种新的数据结构：**Map**、**WeakMap**、**Set**和**WeakSet**。我们之前讨论过，对象是 JavaScript 中创建键值对的常用方式。对象的缺点是你不能使用非字符串值作为键。以下片段演示了如何在 ES6 中创建映射：

```js
let m = new Map();
let s = { 'seq' : 101 };

m.set('1','Albert');
m.set('MAX', 99);
m.set(s,'Einstein');

console.log(m.has('1')); //true
console.log(m.get(s));   //Einstein
console.log(m.size);     //3
m.delete(s);
m.clear();
```

你可以在声明它时初始化映射：

```js
let m = new Map([
  [ 1, 'Albert' ],
  [ 2, 'Douglas' ],
  [ 3, 'Clive' ],
]);
```

如果你想遍历映射中的条目，你可以使用`entries()`函数，它将返回一个迭代器。你可以使用`keys()`函数遍历所有键，使用`values()`函数遍历映射的值：

```js
let m2 = new Map([
    [ 1, 'Albert' ],
    [ 2, 'Douglas' ],
    [ 3, 'Clive' ],
]);
for (let a of m2.entries()){
  console.log(a);
}
//[1,"Albert"] [2,"Douglas"][3,"Clive"] 
for (let a of m2.keys()){
  console.log(a);
} //1 2 3
for (let a of m2.values()){
  console.log(a);
}
//Albert Douglas Clive
```

JavaScript 映射的一种变体是 WeakMap——WeakMap 不阻止其键被垃圾回收。WeakMap 的键必须是对象，而值可以是任意值。虽然 WeakMap 的行为与普通映射相同，但你不能遍历它，也不能清空它。这些限制背后有原因。由于映射的状态不能保证保持静态（键可能被垃圾回收），你不能确保正确的遍历。

使用 WeakMap 的情况并不多。大多数映射的使用可以用普通映射来实现。

虽然映射允许你存储任意值，但集合是唯一值的集合。映射和集合有类似的方法；然而，`set()`被替换为`add()`，而`get()`方法不存在。`get()`方法不存在的原因是因为集合有唯一值，所以你只关心集合是否包含一个值。考虑以下示例：

```js
let x = {'first': 'Albert'};
let s = new Set([1,2,'Sunday',x]);
//console.log(s.has(x));  //true
s.add(300);
//console.log(s);  //[1,2,"Sunday",{"first":"Albert"},300]

for (let a of s.entries()){
  console.log(a);
}
//[1,1]
//[2,2]
//["Sunday","Sunday"]
//[{"first":"Albert"},{"first":"Albert"}]
//[300,300]
for (let a of s.keys()){
  console.log(a);
}
//1
//2
//Sunday
//{"first":"Albert"}
//300
for (let a of s.values()){
  console.log(a);
}
//1
//2
//Sunday
//{"first":"Albert"}
//300
```

`keys()`和`values()`迭代器都返回集合中唯一值的列表。`entries()`迭代器生成一个条目数组列表，数组中的两个项目都是集合中的唯一值。集合的默认迭代器是其`values()`迭代器。

## 符号

ES6 引入了一种新数据类型叫做 Symbol。Symbol 是保证唯一且不可变的。Symbol 通常用作对象属性的标识符。它们可以被认为是唯一生成的 ID。你可以使用`Symbol()`工厂方法创建 Symbols——记住这不是一个构造函数，因此你不应该使用`new`操作符：

```js
let s = Symbol();
console.log(typeof s); //symbol
```

与字符串不同，Symbols 保证是唯一的，因此有助于防止名称冲突。有了 Symbols，我们有一个对每个人都有效的扩展机制。ES6 带有一些预定义的内置 Symbols，它们揭示了 JavaScript 对象值的各种元行为。

## 迭代器

迭代器在其他编程语言中已经存在很长时间了。它们提供了方便的方法来处理数据集合。ES6 引入了迭代器来处理同样的用例。ES6 的迭代器是一个具有特定接口的对象。迭代器有一个`next()`方法，它返回一个对象。返回的对象有两个属性——`value`（下一个值）和`done`（表示是否已经达到最后一个结果）。ES6 还定义了一个`Iterable`接口，描述了必须能够产生迭代器的对象。让我们看看一个数组，它是一个可迭代的，以及它能够产生的迭代器来消费其值：

```js
var a = [1,2];
var i = a[Symbol.iterator]();
console.log(i.next());      // { value: 1, done: false }
console.log(i.next());      // { value: 2, done: false }
console.log(i.next());      // { value: undefined, done: true }
```

正如你所见，我们是通过`Symbol.iterator()`访问数组的迭代器，并在其上调用`next()`方法来获取每个连续元素。`next()`方法调用返回`value`和`done`两者。当你在数组的最后一个元素之后调用`next()`时，你会得到一个未定义的值和`done: true`，这表明你已经遍历了整个数组。

## 对于..of 循环

ES6 添加了一种新的迭代机制，形式为`for..of`循环，它遍历由迭代器产生的值集合。

我们遍历的`for..of`值是一个可迭代的。

让我们比较一下`for..of`和`for..in`：

```js
var list = ['Sunday','Monday','Tuesday'];
for (let i in list){
  console.log(i);  //0 1 2
}
for (let i of list){
  console.log(i);  //Sunday Monday Tuesday
}
```

正如你所见，使用`for..in`循环，你可以遍历`list`数组的索引，而`for..of`循环让你遍历存储在`list`数组中的值。

## 箭头函数

ECMAScript 6 最有趣的新特性之一是箭头函数。箭头函数，正如其名称所暗示的，是使用一种新语法定义的函数，该语法使用*箭头*（`=>`）作为语法的一部分。让我们首先看看箭头函数看起来如何：

```js
//Traditional Function
function multiply(a,b) {
  return a*b;
}
//Arrow
var multiply = (a,b) => a*b;
console.log(multiply(1,2)); //2
```

箭头函数定义包括参数列表（零个或多个参数，如果恰好有一个参数则周围是`( .. )`），后面跟着`=>`标记，后面跟着函数体。

如果函数体中有多个表达式，可以用`{ .. }`括起来。如果只有一个表达式，并且省略了周围的`{ .. }`，则在表达式前面有一个隐式的返回。你可以以几种不同的方式编写箭头函数。以下是最常用的几种：

```js
// single argument, single statement
//arg => expression;
var f1 = x => console.log("Just X");
f1(); //Just X

// multiple arguments, single statement
//(arg1 [, arg2]) => expression;
var f2 = (x,y) => x*y;
console.log(f2(2,2)); //4

// single argument, multiple statements
// arg => {
//     statements;
// }
var f3 = x => {
  if(x>5){
    console.log(x);
  }
  else {
    console.log(x+5);
  }
}
f3(6); //6

// multiple arguments, multiple statements
// ([arg] [, arg]) => {
//   statements
// }
var f4 = (x,y) => {
  if(x!=0 && y!=0){
    return x*y;
  }
}
console.log(f4(2,2));//4

// with no arguments, single statement
//() => expression;
var f5 = () => 2*2;
console.log(f5()); //4

//IIFE
console.log(( x => x * 3 )( 3 )); // 9
```

重要的是要记住，所有正常函数参数的特征都适用于箭头函数，包括默认值、解构和剩余参数。

箭头函数提供了一种方便且简洁的语法，给你的代码带来了非常*函数式编程*的风格。箭头函数之所以受欢迎，是因为它们通过从代码中删除 function、return 和{ .. }，提供了编写简洁函数的吸引力。然而，箭头函数是为了根本解决与 this 相关的编程中的一个特定且常见痛点而设计的。在正常的 ES5 函数中，每个新定义的函数都定义了自己的`this`值（在构造函数中是一个新对象，在严格模式函数调用中是`undefined`，如果函数作为*对象方法*调用，则是上下文对象等）。JavaScript 函数总是有自己的`this`，这阻止了你从回调内部访问例如周围方法中的`this`。为了理解这个问题，请考虑以下示例：

```js
function CustomStr(str){
  this.str = str;
}
CustomStr.prototype.add = function(s){   // --> 1
  'use strict';
  return s.map(function (a){             // --> 2
    return this.str + a;                 // --> 3
  });
};

var customStr = new CustomStr("Hello");
console.log(customStr.add(["World"])); 
//Cannot read property 'str' of undefined
```

在标记为`3`的行上，我们试图获取`this.str`，但匿名函数也有自己的`this`，它遮蔽了从行`1`来的方法中的`this`。为了在 ES5 中修复这个问题，我们可以将`this`赋值给一个变量，然后使用这个变量：

```js
function CustomStr(str){
  this.str = str;
}
CustomStr.prototype.add = function(s){   
  'use strict';
 var that = this;                       // --> 1
  return s.map(function (a){             // --> 2
    return that.str + a;                 // --> 3
  });
};

var customStr = new CustomStr("Hello");
console.log(customStr.add(["World"])); 
//["HelloWorld]
```

在标记为`1`的行上，我们将`this`赋值给一个变量`that`，在匿名函数中我们使用`that`变量，它将引用正确上下文中的`this`。

ES6 箭头函数具有词法`this`，这意味着箭头函数捕获了外层上下文的`this`值。我们可以如下将前面的函数转换为等效的箭头函数：

```js
function CustomStr(str){
  this.str = str;
}
CustomStr.prototype.add = function(s){ 
 return s.map((a)=> {
 return this.str + a;
 });
};
var customStr = new CustomStr("Hello");
console.log(customStr.add(["World"])); 
//["HelloWorld]
```

# 摘要

在本章中，我们讨论了几种重要特性，这些特性被添加到 ES6 语言中。这是一组令人兴奋的新语言特性和范式，并且，通过使用 polyfills 和 transpilers，你可以立即开始使用它们。JavaScript 是一种不断发展的语言，了解未来趋势非常重要。ES6 特性使 JavaScript 成为一个更加有趣和成熟的语言。在下一章中，我们将深入研究使用 jQuery 和 JavaScript 操纵浏览器的**文档对象模型**（**DOM**）和事件。


# 第八章：DOM 操作与事件

javascript 存在最重要的原因就是网络。JavaScript 是网络的语言，浏览器就是 JavaScript 存在的理由。JavaScript 为原本静态的网页赋予了动态性。在本章中，我们将深入探讨浏览器与语言之间的关系。我们将了解 JavaScript 与网页组件进行交互的方式。我们将查看**文档对象模型**（**DOM**）和 JavaScript 事件模型。

# DOM

在本章中，我们将探讨 JavaScript 与浏览器和 HTML 的各种方面。HTML，我相信您已经知道，是用于定义网页的标记语言。存在各种形式的标记用于不同的用途。流行的标记有**可扩展标记语言**（**XML**）和**标准通用标记语言**（**SGML**）。除了这些通用的标记语言之外，还有针对特定目的非常具体的标记语言，例如文本处理和图像元信息。**超文本标记语言**（**HTML**）是定义网页表示语义的标准标记语言。网页本质上是一个文档。DOM 为您提供了这个文档的表示。DOM 还为您提供了存储和操纵这个文档的手段。DOM 是 HTML 的编程接口，并允许使用脚本语言（如 JavaScript）进行结构操作。DOM 为文档提供了结构表示。该结构由节点和对象组成。节点有属性和方法，您可以对这些属性和方法进行操作以操纵节点本身。DOM 只是一个表示，并不是一个编程结构。DOM 作为 DOM 处理语言（如 JavaScript）的模型。

## 访问 DOM 元素

大多数时候，你将会想要访问 DOM 元素以检查它们的值，或者处理这些值以进行某些业务逻辑。我们将详细查看这个特定的用例。让我们创建一个带有以下内容的示例 HTML 文件：

```js
<html>
<head>
  <title>DOM</title> 
</head>
<body>
  <p>Hello World!</p>
</body>
</html>
```

您可以将此文件保存为`sample_dom.html`；当您在 Google Chrome 浏览器中打开此文件时，您将看到显示**Hello World**文本的网页。现在，打开 Google Chrome 开发者工具，通过转到选项 | **更多工具** | **开发者工具**（此路径可能因您的操作系统和浏览器版本而异）。在**开发者工具**窗口中，您将看到 DOM 结构：

![访问 DOM 元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00025.jpeg)

接下来，我们将向这个 HTML 页面中插入一些 JavaScript。当网页加载时，我们将调用 JavaScript 函数。为此，我们将调用`window.onload`上的一个函数。您可以将您的脚本放在`<script>`标签下，该标签位于`<head>`标签下。您的页面应如下所示：

```js
<html>
  <head>
    <title>DOM</title>
    <script>
      // run this function when the document is loaded
      window.onload = function() {
        var doc = document.documentElement;
        var body = doc.body;
        var _head = doc.firstChild;
        var _body = doc.lastChild;
        var _head_ = doc.childNodes[0];
        var title = _head.firstChild;
        alert(_head.parentNode === doc); //true
      }
    </script>
  </head>
  <body>
    <p>Hello World!</p>
  </body>
</html>
```

匿名函数在浏览器加载页面时执行。在函数中，我们获取 DOM 节点的程序化方式。整个 HTML 文档可以通过`document.documentElement`函数访问。我们将文档存储在一个变量中。一旦访问了文档，我们就可以使用文档的几个辅助属性来遍历节点。我们使用`doc.body`访问`<body>`元素。可以通过`childNodes`数组遍历元素的子节点。节点的第一个和最后一个子节点可以通过额外的属性——`firstChild`和`lastChild`来访问。

### 注意

不建议在`<head>`标签中使用阻塞渲染的 JavaScript。这会显著减慢页面渲染速度。现代浏览器支持`async`和`defer`属性，以指示浏览器在下载脚本的同时可以继续渲染。你可以在`<head>`标签中使用这些标签，而不用担心性能下降。你可以在[`stackoverflow.com/questions/436411/where-is-the-best-place-to-put-script-tags-in-html-markup`](http://stackoverflow.com/questions/436411/where-is-the-best-place-to-put-script-tags-in-html-markup)获取更多信息。

## 访问特定节点

核心 DOM 定义了`getElementsByTagName()`方法，返回所有`tagName`属性等于特定值的元素对象`NodeList`。以下代码行返回一个文档中所有`<p>`元素的列表：

```js
var paragraphs = document.getElementsByTagName('p');
```

HTML DOM 定义了`getElementsByName()`方法来获取所有名称属性设置为特定值的元素。考虑以下片段：

```js
<html>
  <head>
    <title>DOM</title>
    <script>
 showFeelings = function() {
 var feelings = document.getElementsByName("feeling");
 alert(feelings[0].getAttribute("value"));
 alert(feelings[1].getAttribute("value"));
 }
    </script>
  </head>
  <body>
    <p>Hello World!</p>
    <form method="post" action="/post">
      <fieldset>
        <p>How are you feeling today?</p>
        <input type="radio" name="feeling" value="Happy" /> Happy<br />
        <input type="radio" name="feeling" value="Sad" />Sad<br />
      </fieldset>
      <input type="button" value="Submit" onClick="showFeelings()"/>
    </form>
  </body>
</html>
```

在这个例子中，我们创建了一组单选按钮，其`name`属性定义为`feeling`。在`showFeelings`函数中，我们获取所有`name`属性设置为`feeling`的元素，并对这些元素进行遍历。

HTML DOM 还定义了`getElementById()`方法。这是一个非常实用的方法，用于访问特定元素。该方法基于与元素相关联的`id`属性进行查找。`id`属性对每个元素都是唯一的，因此这种查找非常快速，应优先于`getElementsByName()`方法。然而，你应该注意到浏览器不保证`id`属性的唯一性。在以下示例中，我们使用 ID 访问一个特定元素。元素 ID 相对于标签或名称属性来说是唯一的：

```js
<html>
  <head>
    <title>DOM</title>
    <script>
      window.onload= function() {
 var greeting = document.getElementById("greeting");
 alert(greeting.innerHTML); //shows "Hello World" alert
      }
    </script>
  </head>
  <body>
    <p id="greeting">Hello World!</p>
    <p id="identify">Earthlings</p>
  </body>
</html>
```

迄今为止，我们讨论的是 DOM 遍历的基本知识。当 DOM 变得复杂且需要在 DOM 上进行复杂操作时，这些遍历和访问函数似乎有限。有了这些基本知识，是时候介绍一个用于 DOM 遍历（以及其他功能）的出色库——jQuery。

jQuery 是一个轻量级库，旨在使常见的浏览器操作更加容易。纯 JavaScript 中进行诸如 DOM 遍历和操作、事件处理、动画和 Ajax 等常见操作可能会很繁琐。jQuery 提供了易于使用且更短的助手机制，帮助你轻松快速地开发这些常见操作。jQuery 是一个功能丰富的库，但就本章而言，我们将主要关注 DOM 操作和事件。

你可以通过从**内容分发网络**（**CDN**）直接添加脚本来将 jQuery 添加到你的 HTML 中，或者手动下载文件并将其添加到脚本标签中。以下示例将指导你如何从谷歌的 CDN 下载 jQuery：

```js
<html>
  <head>
    <script src="img/jquery.min.js"></script>
  </head>
  <body>
  </body>
</html>
```

使用 CDN 下载的优势在于，谷歌的 CDN 会自动为你找到最近的下载服务器，并保持对 jQuery 库的更新稳定副本。如果你希望下载并手动托管 jQuery 以及你的网站，你可以按照以下方式添加脚本：

```js
<script src="img/jquery.js"></script>
```

在这个例子中，jQuery 库是在`lib`目录中手动下载的。在 HTML 页面中设置 jQuery 后，让我们探索操纵 DOM 元素的方法。考虑以下示例：

```js
<html>
  <head>
    <script src="img/jquery.min.js"></script>
    <script>
 $(document).ready(function() {
 $('#greeting').html('Hello World Martian');
 });
  </script>
  </head>
  <body>
    <p id="greeting">Hello World Earthling ! </p>
  </body>
</html>
```

在将 jQuery 添加到 HTML 页面后，我们编写自定义 JavaScript，选择具有`greeting` ID 的元素并更改其值。`$()`内的奇怪代码是 jQuery 在起作用。如果你阅读 jQuery 源代码（并且你应该阅读，它非常出色）你会看到最后一行：

```js
// Expose jQuery to the global object
window.jQuery = window.$ = jQuery;
```

`$`只是一个函数。它是调用名为 jQuery 的函数的别名。`$`是一种语法糖，使代码更加简洁。实际上，你可以交替使用`$`和`jQuery`。例如，`$('#greeting').html('Hello World Martian');`和`jQuery('#greeting').html('Hello World Martian');`是相同的。

在页面完全加载之前不能使用 jQuery。因为 jQuery 需要知道 DOM 结构的的所有节点，整个 DOM 必须保存在内存中。为了确保页面完全加载并处于可以被操纵的状态，我们可以使用`$(document).ready()`函数。在这里，IIFE 仅在整个文档*准备就绪*后执行：

```js
$(document).ready(function() {
  $('#greeting').html('Hello World Martian');
});
```

```js
.ready() function. This function will be executed once the document is ready. We are using $(document) to create a jQuery object from our page's document. We are calling the .ready() function on the jQuery object and passing it the function that we want to execute.
```

在使用 jQuery 时，这是一个非常常见的行为——以至于它有自己的快捷方式。你可以用一个短的`$()`调用替换整个`ready()`调用：

```js
$(function() {
  $('#greeting').html('Hello World Martian');
});
```

jQuery 中最重要的函数是`$()`。这个函数通常接受一个 CSS 选择器作为其唯一参数，并返回一个指向页面相应元素的新 jQuery 对象。三种主要的选择器是标签名、ID 和类。它们可以单独使用，也可以与其他元素组合使用。以下简单示例展示了这三种选择器在代码中的表现形式：

| **选择器** | CSS 选择器 | jQuery 选择器 | 选择器的输出 |
| --- | --- | --- | --- |
| **标签** | `p{}` | `$('p')` | 这选择了文档中的所有`p`标签。 |
| **ID** | `#div_1` | `$('#div_1')` | 这选择具有`div_1` ID 的单个元素。用来标识 ID 的符号是`#`。 |
| **类** | `.bold_fonts` | `$('.bold_fonts')` | 这选择文档中具有`bold_fonts` CSS 类的所有元素。用来标识类匹配的符号是"`.`"。 |

jQuery 工作在 CSS 选择器上。

### 注意

由于 CSS 选择器超出了本书的范围，我建议你前往[`www.w3.org/TR/CSS2/selector.html`](http://www.w3.org/TR/CSS2/selector.html)以了解这个概念。

我们假设你对 HTML 标签和语法也很熟悉。以下示例涵盖了 jQuery 选择器的基本工作原理：

```js
<html>
  <head>
    <script src="img/jquery.min.js"></script>
    <script>
 $(function() {
 $('h1').html(function(index, oldHTML){
 return oldHTML + "Finally?";
 });
 $('h1').addClass('highlight-blue');
 $('#header > h1 ').css('background-color', 'cyan');
 $('ul li:not(.highlight-blue)').addClass('highlight-green');
 $('tr:nth-child(odd)').addClass('zebra');
 });
    </script>
    <style>
      .highlight-blue {
        color: blue;
      }
      .highlight-green{
        color: green;
      }
      .zebra{
        background-color: #666666;
        color: white;
      }
    </style>
  </head>
  <body>
    <div id=header>
      <h1>Are we there yet ? </h1>
      <span class="highlight">
        <p>Journey to Mars</p>
        <ul>
          <li>First</li>
          <li>Second</li>
          <li class="highlight-blue">Third</li>
        </ul>
      </span>
      <table>
        <tr><th>Id</th><th>First name</th><th>Last Name</th></tr>
        <tr><td>1</td><td>Albert</td><td>Einstein</td></tr>
        <tr><td>2</td><td>Issac</td><td>Newton</td></tr>
        <tr><td>3</td><td>Enrico</td><td>Fermi</td></tr>
        <tr><td>4</td><td>Richard</td><td>Feynman</td></tr>
      </table>
    </div>
  </body>
</html>
```

在这个例子中，我们使用选择器在 HTML 页面上选择几个 DOM 元素。我们有一个文本为`Are we there yet ?`的 H1 头部；当页面加载时，我们的 jQuery 脚本访问所有的 H1 头部并将文本`Finally?`附加到它们：

```js
$('h1').html(function(index, oldHTML){
  return oldHTML + "Finally ?";
});
```

`$.html()`函数设置目标元素的 HTML——在这个例子中是一个 H1 头部。此外，我们选择所有的 H1 头部并为它们应用一个特定的 CSS 样式类，`highlight-blue`。`$('h1').addClass('highlight-blue')`语句选择所有的 H1 头部，并使用`$.addClass(<CSS 类>)`方法为使用选择器选择的所有的元素应用一个 CSS 类。

我们使用子组合符（`>`）和`$.css()`函数自定义 CSS 样式。实际上，`$()`函数中的选择器是在说：“找到每个`h1`头部元素（`#header`的子元素）。” 对每个这样的元素，我们应用一个自定义的 CSS。下一个用法是有趣的。考虑以下行：

```js
$('ul li:not(.highlight-blue)').addClass('highlight-green');

```

我们选择“对所有未应用`highlight-blue`类的`li`列表元素，应用`highlight-green` CSS 类。最后一行—`$('tr:nth-child(odd)').addClass('zebra')`—可以解释为：从所有表格行（`tr`）中，对每一行，应用`zebra` CSS 样式。第*n*个孩子选择器是 jQuery 提供的自定义选择器。最终输出类似于以下内容（虽然它展示了几个 jQuery 选择器类型，但非常清晰地表明了，了解 jQuery 并不是设计糟糕的替代品。）：

![访问特定节点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00026.jpeg)

一旦你做出了一个选择，你可以在选定的元素上调用两种广泛的方法。这些方法是**获取器**和**设置器**。获取器从选择集中检索信息，设置器以某种方式更改选择集。

获取器通常只对选择集中的第一个元素进行操作，而设置器则对选择集中的所有元素进行操作。设置器通过隐式迭代来自动遍历选择集中的所有元素。

例如，我们想要给页面上的所有列表项应用一个 CSS 类。当我们对选择器调用 `addClass` 方法时，它自动应用于这个特定选择的所有元素。这就是隐式迭代在行动：

```js
$( 'li' ).addClass( highlighted' );
```

然而，有时你只是不想通过隐式迭代来遍历所有元素。你可能只想选择性地修改几个元素。你可以使用 `.each()` 方法显式地遍历元素。在以下代码中，我们选择性地处理元素并使用元素的 `index` 属性：

```js
$( 'li' ).each(function( index, element ) {
  if(index % 2 == 0)
    $(elem).prepend( '<b>' + STATUS + '</b>' );
});
```

# 链式操作

链式 jQuery 方法允许你在选择上调用一系列方法，而无需临时存储中间值。这是可能的，因为我们所调用的每个设置器方法都会返回它被调用的选择。这是一个非常强大的特性，你将会看到许多专业库在使用它。考虑以下示例：

```js
$( '#button_submit' )
  .click(function() {
    $( this ).addClass( 'submit_clicked' );
  })
  .find( '#notification' )
    .attr( 'title', 'Message Sent' );x
```

```js
click(), find(), and attr() methods on a selector. Here, the click() method is executed, and once the execution finishes, the find() method locates the element with the notification ID and changes its title attribute to a string.
```

# 遍历和操作

我们讨论了使用 jQuery 进行元素选择的各种方法。我们在本节中将讨论使用 jQuery 进行 DOM 遍历和操作的几个方法。这些任务如果使用原生的 DOM 操作来实现将会相当繁琐。jQuery 使它们变得直观和优雅。

在我们深入这些方法之前，让我们先熟悉一些我们接下来会使用的 HTML 术语。考虑以下 HTML：

```js
<ul> <-This is the parent of both 'li' and ancestor of everything in 
  <li> <-The first (li) is a child of the (ul)
    <span>  <-this is the descendent of the 'ul'
      <i>Hello</i>
    </span>
  </li>
  <li>World</li> <-both 'li' are siblings
</ul>
```

使用 jQuery 遍历方法，我们选择第一个元素并相对于这个元素遍历 DOM。在遍历 DOM 的过程中，我们改变了原始选择，我们或者是用新的选择替换原始选择，或者是修改原始选择。

例如，你可以过滤现有的选择，只包括符合某些标准的元素。考虑这个例子：

```js
var list = $( 'li' ); //select all list elements
// filter items that has a class 'highlight' associated
var highlighted = list.filter( '.highlight );
// filter items that doesn't have class 'highlight' associated 
var not_highlighted = list.not( '.highlight );
```

jQuery 允许你给元素添加和移除类。如果你想要切换元素的类值，你可以使用 `toggleClass()` 方法：

```js
$( '#usename' ).addClass( 'hidden' );
$( '#usename' ).removeClass( 'hidden' );
$( '#usename' ).toggleClass( 'hidden' );
```

大多数时候，你可能想更改元素的值。你可以使用 `val()` 方法来更改元素值的形式。例如，以下行更改了表单中所有 `text` 类型输入的值：

```js
$( 'input[type="text"]' ).val( 'Enter usename:' );
```

要修改元素属性，你可以如下使用 `attr()` 方法：

```js
$('a').attr( 'title', 'Click' );
```

jQuery 在 DOM 操作方面具有 incredible 的功能深度——本书的范围限制了对所有可能性的详细讨论。

# 处理浏览器事件

当你为浏览器开发时，你将不得不处理与它们相关的用户交互和事件，例如文本框中输入的文本、页面的滚动、鼠标按键按下等。当用户在页面上做些什么时，一个事件就会发生。有些事件不是由用户交互触发的，例如，`load` 事件不需要用户输入。

当你在浏览器中处理鼠标或键盘事件时，你无法预测这些事件何时以及以何种顺序发生。你必须不断寻找按键或鼠标移动事件的发生。这就像运行一个无尽的后台循环，监听某个键或鼠标事件的发生。在传统编程中，这被称为轮询。有许多变体，其中等待线程通过队列进行优化；然而，轮询通常仍然不是一个好主意。

浏览器提供了一种比轮询更好的替代方案。浏览器为您提供了在事件发生时做出反应的程序化手段。这些钩子通常称为监听器。您可以注册一个监听器，用于在特定事件发生时执行关联的回调函数。请参考这个例子：

```js
<script> 
  addEventListener("click", function() { 
    ... 
  }); 
</script>
```

`addEventListener` 函数将其第二个参数注册为回调函数。当第一个参数指定的事件触发时，执行此回调。

刚才我们看到的是一个通用的 `click` 事件监听器。同样，每个 DOM 元素都有自己的 `addEventListener` 方法，允许你在这个元素上特别监听：

```js
<button>Submit</button> 
<p>No handler here.</p> 
<script> 
  var button = document.getElementById("#Bigbutton");
  button.addEventListener("click", function() {
    console.log("Button clicked."); 
  }); 
</script>
```

在这个示例中，我们通过调用 `getElementById()` 使用特定元素的引用——一个具有 `Bigbutton` ID 的按钮。在按钮元素的引用上，我们调用 `addEventListener()` 为点击事件分配一个处理函数。在 Mozilla Firefox 或 Google Chrome 等现代浏览器中，这段代码完全合法且运行良好。然而，在 IE9 之前的 Internet Explorer 中，这段代码是无效的。这是因为微软在 Internet Explorer 9 之前实现了自己的自定义 `attachEvent()` 方法，而不是 W3C 标准的 `addEventListener()`。这非常不幸，因为你将不得不编写非常糟糕的快捷方式来处理浏览器特定的怪癖。

# 传播

在这个时候，我们应该问一个重要的问题——如果一个元素和它的一个祖先元素都有同一个事件处理程序，哪个处理程序将首先被触发？请参考以下图形：

![传播](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00027.jpeg)

例如，我们有一个 **Element2** 作为 **Element1** 的子元素，两者都具有 `onClick` 处理程序。当用户点击 Element2 时，Element2 和 Element1 的 `onClick` 都会被触发，但问题是哪个先被触发。事件顺序应该是怎样的？嗯，不幸的是，答案完全取决于浏览器。当浏览器首次出现时，自然会从 Netscape 和 Microsoft 出现两种观点。

Netscape 决定首先触发的是 Element1 的 `onClick` 事件。这种事件排序被称为事件捕获。

Microsoft 决定首先触发的是 Element2 的 `onClick` 事件。这种事件排序被称为事件冒泡。

这两种方法完全代表了浏览器处理事件的两种相反观点和实现。为了结束这种疯狂，**万维网联盟**（**W3C**）决定采取明智的中庸之道。在这个模型中，事件首先被捕获，直到它到达目标元素，然后再次冒泡。在这个标准行为中，你可以选择在哪个阶段注册你的事件处理程序——捕获阶段或冒泡阶段。如果在`addEventListener()`中的最后一个参数为 true，则事件处理程序设置为捕获阶段，如果为 false，则事件处理程序设置为冒泡阶段。

有时，如果你已经通过子元素触发了事件，你不想让父元素也触发事件。你可以在事件对象上调用`stopPropagation()`方法，以防止更高层次的处理程序接收事件。一些事件与它们关联的默认动作。例如，如果你点击一个 URL 链接，你会被带到链接的目标。在默认行为执行之前调用 JavaScript 事件处理程序。你可以在事件对象上调用`preventDefault()`方法，以阻止默认行为的触发。

当你在浏览器上使用纯 JavaScript 时，这些都是事件基础。这里有一个问题。浏览器在定义事件处理行为方面臭名昭著。我们将看看 jQuery 的事件处理。为了使管理更加容易，jQuery 总是为模型的冒泡阶段注册事件处理程序。这意味着最具体的元素将首先有机会对任何事件做出响应。

# jQuery 事件处理和传播

jQuery 事件处理可以解决浏览器许多怪癖。你可以专注于编写在大多数受支持的浏览器上运行的代码。jQuery 对浏览器事件的支持简单直观。例如，这段代码监听用户点击页面上的任何按钮元素：

```js
$('button').click(function(event) {
  console.log('Mouse button clicked');
});
```

就像`click()`方法一样，还有几个其他助手方法来涵盖几乎所有类型的浏览器事件。以下助手方法存在：

+   `blur`

+   `change`

+   `click`

+   `dblclick`

+   `error`

+   `focus`

+   `keydown`

+   `keypress`

+   `keyup`

+   `load`

+   `mousedown`

+   `mousemove`

+   `mouseout`

+   `mouseover`

+   `mouseup`

+   `resize`

+   `scroll`

+   `select`

+   `submit`

+   `unload`

另外，你可以使用`.on()`方法。使用`.on()`方法有几个优点，因为它为你提供了更多的灵活性。`.on()`方法允许你将处理程序绑定到多个事件。使用`.on()`方法，你也可以处理自定义事件。

事件名称作为`on()`方法的第一个参数传递，就像我们看到的其它方法一样：

```js
$('button').on( 'click', function( event ) {
  console.log(' Mouse button clicked');
});
```

一旦你向元素注册了一个事件处理程序，你可以按照以下方式触发这个事件：

```js
$('button').trigger( 'click' );
```

这个事件也可以按照以下方式触发：

```js
$('button').click();
```

你可以使用 jQuery 的`.off()`方法解除事件绑定。这将移除绑定到指定事件的任何事件处理程序：

```js
$('button').off( 'click' );
```

你可以向元素添加多个处理程序：

```js
$("#element")   
.on("click", firstHandler) 
.on("click", secondHandler);
```

当事件被触发时，两个处理器都会被调用。如果你只想删除第一个处理器，你可以使用带有第二个参数的`off()`方法，该参数指明你想删除的处理器：

```js
$("#element).off("click",firstHandler);
```

如果你有处理器的引用，这是可能的。如果你使用匿名函数作为处理器，你不能获取对它们的引用。在这种情况下，你可以使用命名空间事件。考虑以下示例：

```js
$("#element").on("click.firstclick",function() { 
  console.log("first click");
});
```

现在你已经为元素注册了一个命名空间事件处理器，你可以按照以下方式删除它：

```js
$("#element).off("click.firstclick");
```

使用`.on()`的一个主要优点是，你可以一次绑定多个事件。`.on()`方法允许你通过空格分隔的字符串传递多个事件。考虑以下示例：

```js
$('#inputBoxUserName').on('focus blur', function() {
  console.log( Handling Focus or blur event' );
});
```

你可以为多个事件添加多个事件处理器如下：

```js
$( "#heading" ).on({
  mouseenter: function() {
    console.log( "mouse entered on heading" );
  },
  mouseleave: function() {
    console.log( "mouse left heading" );
  },
  click: function() {
    console.log( "clicked on heading" );
  }
});
```

截至 jQuery 1.7，所有事件都是通过`on()`方法绑定的，即使你调用如`click()`的帮助方法。内部地，jQuery 将这些调用映射到`on()`方法。因此，通常建议使用`on()`方法以保持一致性和更快的执行。

# 事件委托

事件委托允许我们将一个事件监听器附加到父元素上。这个事件将会为所有匹配选择器的后代元素触发，即使这些后代元素是在监听器绑定后创建的（将来创建）。

我们之前讨论了*事件冒泡*。jQuery 中的事件委托主要归功于事件冒泡。每当页面上的事件发生时，事件会从它起源的元素开始冒泡，一直冒泡到它的父元素，然后冒泡到父元素的父元素，依此类推，直到它达到根元素（`window`）。考虑以下示例：

```js
<html>
  <body>
    <div id="container">
      <ul id="list">
        <li><a href="http://google.com">Google</a></li>
        <li><a href="http://myntra.com">Myntra</a></li>
        <li><a href="http://bing.com">Bing</a></li>
      </ul>
    </div>
  </body>
</html>
```

现在假设我们想要对任何 URL 的点击执行一些常见操作。我们可以如下向列表中的所有`a`元素添加事件处理器：

```js
$( "#list a" ).on( "click", function( event ) {
  console.log( $( this ).text() );
});
```

这完全没问题，但这段代码有一个小错误。如果由于某些动态操作在列表中添加了一个额外的 URL 会发生什么？比如说，我们有一个**添加**按钮，它将新的 URL 添加到这个列表中。所以，如果新列表项是通过一个新的 URL 添加的，那么早先的事件处理器将不会附加到它。例如，如果以下链接动态地添加到列表中，点击它将不会触发我们刚刚添加的处理器：

```js
<li><a href="http://yahoo.com">Yahoo</a></li>
```

这是因为这样的事件只有在调用`on()`方法时才注册。在这种情况下，由于这个新元素在调用`.on()`时不存在，所以它不会获得事件处理器。根据我们对事件冒泡的理解，我们可以想象事件将如何在 DOM 树中向上传播。当点击任何一个 URL 时，传播将如下进行：

```js
a(click)->li->ul#list->div#container->body->html->root
```

我们可以如下创建一个委托事件：

```js
$( "#list" ).on( "click", "a", function( event ) {
  console.log( $( this ).text() );
});
```

我们把`a`从原来的选择器移动到了`on()`方法的第二个参数。`on()`方法的第二个参数使得处理程序监听这个特定的事件，并检查触发元素是否为第二个参数（在我们这个案例中的`a`）。由于第二个参数匹配，处理函数将被执行。通过这种委派事件，我们为整个`ul#list`添加了一个处理程序。这个处理程序将监听`ul`元素的任何后代元素触发的点击事件。

# 事件对象

到目前为止，我们为匿名函数添加了事件处理程序。为了使我们的事件处理程序更具通用性和可用性，我们可以创建命名函数并将它们分配给事件。考虑以下几行：

```js
function handlesClicks(event){
  //Handle click event
}
$("#bigButton").on('click', handlesClicks);
```

这里，我们传递了一个命名函数而不是一个匿名函数给`on()`方法。现在让我们将注意力转移到我们传递给函数的`event`参数。jQuery 为所有事件回调传递了一个事件对象。事件对象包含了有关触发的事件的非常有用的信息。在不想让元素的默认行为发生的情况下，我们可以使用事件对象上的`preventDefault()`方法。例如，我们希望在提交完整表单之前发起一个 AJAX 请求，或者在点击 URL 锚点时阻止默认位置的打开。在这些情况下，您可能还希望阻止事件在 DOM 上冒泡。您可以通过调用事件对象的`stopPropagation()`方法来停止事件传播。考虑以下示例：

```js
$( "#loginform" ).on( "submit", function( event ) { 
  // Prevent the form's default submission.
  event.preventDefault();
  // Prevent event from bubbling up DOM tree, also stops any delegation
  event.stopPropagation();
});
```

除了事件对象，您还可以获得一个对触发事件的 DOM 对象的引用。这个元素可以通过`$(this)`来引用。考虑以下示例：

```js
$( "a" ).click(function( event ) {
  var anchor = $( this );
  if ( anchor.attr( "href" ).match( "google" ) ) {
    event.preventDefault();
  }
});
```

# 摘要

本章主要讲解的是 JavaScript 在其最重要的角色——浏览器语言中的使用。JavaScript 通过在浏览器上实现 DOM 操作和事件管理，引入了网页的动态性。我们讨论了有无 jQuery 的情况下这两种概念。随着现代网页需求的增加，使用如 jQuery 的库变得至关重要。这些库能显著提高代码质量和效率，同时让你有更多的自由去关注重要的事情。

我们将关注 JavaScript 的另一种化身——主要是服务器端。Node.js 已经成为一个流行的 JavaScript 框架，用于编写可扩展的服务器端应用程序。我们将详细探讨如何最佳地利用 Node.js 进行服务器应用程序的开发。


# 第九章．服务器端 JavaScript

到目前为止，我们一直在关注 JavaScript 作为浏览器语言的多样性。考虑到 JavaScript 已经作为一种可编程可扩展服务器系统的语言获得了显著的流行，这充分说明了这种语言的辉煌。在本章中，我们将介绍 Node.js。Node.js 是最受欢迎的 JavaScript 框架之一，用于服务器端编程。Node.js 也是 GitHub 上最受关注的项目之一，并且拥有非常出色的社区支持。

Node.js 使用 V8，这是为 Google Chrome 提供动力的虚拟机，来进行服务器端编程。V8 给 Node.js 带来了巨大的性能提升，因为它直接将 JavaScript 编译成本地机器代码，而不是执行字节码或使用解释器作为中间件。

V8 和 JavaScript 的多样性是一种美好的组合——性能、覆盖面以及 JavaScript 的整体流行度使得 Node.js 一夜之间取得了成功。在本章中，我们将涵盖以下主题：

+   浏览器和服务器端 Node.js 中的异步事件模型

+   回调

+   定时器

+   事件发射器

+   模块和 npm

# 浏览器中的异步事件模型

在我们尝试理解 Node.js 之前，让我们先来理解一下浏览器中的 JavaScript。

Node.js 依赖于事件驱动和异步的平台来进行服务器端 JavaScript 的编程。这与浏览器处理 JavaScript 的方式非常相似。当浏览器和 Node.js 在进行 I/O 操作时，都是事件驱动和非阻塞的。

为了更深入地了解 Node.js 的事件驱动和异步特性，让我们首先比较一下各种操作及其相关的成本：

| 从 L1 缓存读取 | 0.5 纳秒 |
| --- | --- |
| 从 L2 缓存读取 | 7 纳秒 |
| 读取 RAM | 100 纳秒 |
| 从 SSD 随机读取 4 KB | 150,000 纳秒 |
| 从 SSD 顺序读取 1 MB | 1,000,000 纳秒 |
| 从磁盘顺序读取 1 MB | 20,000,000 纳秒 |

这些数字来自[`gist.github.com/jboner/2841832`](https://gist.github.com/jboner/2841832)，展示了**输入/输出**（**I/O**）可能有多么昂贵。计算机程序中最耗时的操作就是 I/O 操作，如果程序一直在等待这些 I/O 操作完成，这些操作就会降低整个程序的执行效率。让我们来看一个这样的操作示例：

```js
console.log("1");
var log = fileSystemReader.read("./verybigfile.txt");
console.log("2");
```

当你调用`fileSystemReader.read()`时，你正在从文件系统中读取文件。正如我们刚才看到的，I/O 是这里的瓶颈，而且可能需要相当长的时间才能完成读取操作。根据硬件、文件系统、操作系统等不同，这个操作会很大程度上阻塞整个程序的执行。前面的代码执行了一些 I/O 操作，这是一个阻塞操作——进程将会一直阻塞，直到 I/O 操作完成并返回数据。这是传统的 I/O 模型，我们大多数人都很熟悉。然而，这种方法代价高昂，可能会导致可怕的延迟。每个进程都关联着内存和状态——在这两个方面，都会一直阻塞，直到 I/O 操作完成。

如果一个程序阻塞了 I/O，Node 服务器将拒绝新的请求。解决这个问题有几种方法。最传统的流行方法是使用多个线程来处理请求——这种技术被称为多线程。如果你熟悉像 Java 这样的语言，那么你很可能写过多线程代码。多种语言支持线程的不同形式——线程本质上保持自己的内存和状态。在大规模上编写多线程应用程序是困难的。当多个线程访问公共共享内存或值时，在这些线程之间维护正确的状态是非常困难的工作。线程在内存和 CPU 利用率方面也是昂贵的。用于同步资源的线程可能会最终被阻塞。

浏览器处理方式不同。浏览器中的 I/O 发生在主线程之外，当 I/O 完成时会发出一个事件。这个事件由与该事件关联的回调函数处理。这种 I/O 是非阻塞和异步的。因为 I/O 不阻塞主线程，所以浏览器可以继续处理其他事件，而无需等待任何 I/O。这是一个强大的想法。异步 I/O 允许浏览器响应多个事件，并实现高度的交互性。

Node 为异步处理使用了类似的想法。Node 的事件循环作为一个单线程运行。这意味着你编写的应用程序本质上是单线程的。这并不意味着 Node 本身是单线程的。Node 使用了**libuv**并且是多线程的——幸运的是，这些细节被隐藏在 Node 内部，你在开发应用程序时不需要了解它们。

每个涉及 I/O 调用的调用都需要你注册一个回调函数。注册回调函数也是异步的，并且会立即返回。一旦 I/O 操作完成，其回调函数就会被推送到事件循环中。当所有在其他事件循环中被推送到的事件回调执行完毕后，它才会被执行。所有的操作本质上都是线程安全的，这主要是因为事件循环中没有需要同步的并行执行路径。

本质上，只有一个线程在运行你的代码，并且没有并行执行；然而，除了你的代码之外的所有其他操作都是并行运行的。

Node.js 依赖于**libev**([`software.schmorp.de/pkg/libev.html`](http://software.schmorp.de/pkg/libev.html))来提供事件循环，并通过**libeio**([`software.schmorp.de/pkg/libeio.html`](http://software.schmorp.de/pkg/libeio.html))使用池化线程提供异步 I/O。要了解更多，请查看 libev 文档：[`pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod`](http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod)。

考虑以下 Node.js 中异步代码执行的示例：

```js
var fs = require('fs');
console.log('1');
fs.readFile('./response.json', function (error, data) {
  if(!error){
    console.log(data);
  });
console.log('2');
```

在这个程序中，我们从磁盘上读取`response.json`文件。当磁盘 I/O 完成后，回调函数会以包含任何错误发生的参数和文件数据的参数执行。你将在控制台看到的是`console.log('1')`和`console.log('2')`的输出连续出现：

![浏览器中的异步事件模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00028.jpeg)

Node.js 不需要任何额外的服务器组件，因为它创建了自己的服务器进程。Node 应用程序本质上是在指定端口上运行的服务器。在 Node 中，服务器和应用程序是相同的。

以下是一个 Node.js 服务器示例，当通过浏览器运行`http://localhost:3000/` URL 时，会返回**Hello Node**字符串：

```js
var http = require('http');
var server = http.createServer();
server.on('request', function (req, res) {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello Node\n');
});
server.listen(3000); 
```

在这个例子中，我们使用了一个`http`模块。如果你回想我们之前关于 JavaScript 模块的讨论，你就会意识到这是 CommonJS 模块的实现。Node 将几个模块编译到二进制文件中。核心模块在 Node 的源代码中定义。它们可以在`lib/`文件夹中找到。

如果传递了它们的标识符给`require()`，它们会首先被加载。例如，`require('http')`总是会返回内置的 HTTP 模块，即使存在同名的文件也是如此。

加载处理 HTTP 请求的模块后，我们创建一个`server`对象，并使用`server.on()`函数为`request`事件添加一个监听器。无论何时有请求到达端口`3000`上的此服务器，回调都会被调用。回调接收`request`和`response`参数。我们还在发送响应之前设置`Content-Type`头和 HTTP 响应代码。你可以复制上面的代码，将其保存为一个纯文本文件，并命名为`app.js`。你可以使用以下命令行节点 js 运行服务器：

```js
$ » node app.js
```

一旦服务器启动，你可以打开`http://localhost:3000` URL 在浏览器中，你会看到令人兴奋的文本：

![浏览器中的异步事件模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00029.jpeg)

如果你想要检查内部正在发生的事情，你可以发出如下`curl`命令：

```js
~ » curl -v http://localhost:3000 
* Rebuilt URL to: http://localhost:3000/
*   Trying ::1...
* Connected to localhost (::1) port 3000 (#0)
> GET / HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.43.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Content-Type: text/plain
< Date: Thu, 12 Nov 2015 05:31:44 GMT
< Connection: keep-alive
< Transfer-Encoding: chunked
<
Hello Node
* Connection #0 to host localhost left intact
```

Curl 显示了一个漂亮的请求（`>`）和响应（`<`）对话，包括请求和响应头。

# 回调

在 JavaScript 中的回调通常需要一段时间来适应。如果你来自其他一些非异步编程背景，你需要仔细理解回调是如何工作的；你可能会觉得你正在第一次学习编程。因为 Node 中一切都是异步的，所以你将不尝试仔细地结构它们而使用回调。Node.js 项目最重要的部分有时是代码组织和模块管理。

回调函数是在稍后异步执行的函数。而不是代码从上到下按程序顺序阅读，异步程序可能会根据早期函数（如 HTTP 请求或文件系统读取）的顺序和速度在不同时间执行不同的函数。

函数执行是顺序还是异步取决于它执行的上下文：

```js
var i=0;
function add(num){
  console.log(i);
  i=i+num;
}
add(100);
console.log(i);
```

如果你使用 Node 运行这个程序，你会看到以下输出（假设你的文件名为`app.js`）：

```js
~/Chapter9 » node app.js
0
100
```

我们都习惯了这种情况。这是传统的同步代码执行，每一行按顺序执行。这里的代码定义了一个函数，然后在下一行调用这个函数，而不等待任何东西。这是顺序控制流。

如果我们在这个序列中引入 I/O，情况将会不同。如果我们试图从文件中读取一些内容或调用远程端点，Node 将以异步方式执行这些操作。在下一个例子中，我们将使用一个名为`request`的 Node.js 模块。我们将使用这个模块来执行 HTTP 调用。你可以按照以下方式安装这个模块：

```js
npm install request
```

我们将在本章后面讨论 npm 的使用。考虑以下例子：

```js
var request = require('request');
var status = undefined;
request('http://google.com', function (error, response, body) {
  if (!error && response.statusCode == 200) {
    status_code = response.statusCode;
  }
});
console.log(status); 
```

当你执行这段代码时，你会看到`status`变量的值仍然是`undefined`。在这个例子中，我们正在执行一个 HTTP 调用——这是一个 I/O 操作。当我们进行 I/O 操作时，执行变得异步。在之前的例子中，我们在内存中完成所有事情，并且没有涉及 I/O，因此，执行是同步的。当我们运行这个程序时，所有函数都被立即定义，但它们并不都立即执行。`request()`函数被调用，执行继续到下一行。如果没有东西要执行，Node 将等待 I/O 完成，或者退出。当`request()`函数完成其工作时，它将执行回调函数（作为`request()`函数第二个参数的匿名函数）。我们在前面例子中得到`undefined`的原因是，在我们的代码中没有任何逻辑告诉`console.log()`语句等待`request()`函数从 HTTP 调用中获取响应。

回调函数是在稍后的时间执行的函数。这改变了你组织代码的方式。重新组织代码的想法如下：

+   将异步代码包裹在函数中

+   将回调函数传递给包装函数

我们将在考虑这两个想法的基础上组织我们之前的例子。考虑这个修改后的例子：

```js
var request = require('request');
var status = undefined;
function getSiteStatus(callback){
  request('http://google.com', function (error, response, body) {
    if (!error && response.statusCode == 200) {
      status_code = response.statusCode;
    }
    callback(status_code);
  });
}
function showStatusCode(status){
  console.log(status);
}
getSiteStatus(showStatusCode);
```

当你运行这个程序时，你会得到以下（正确）输出：

```js
$node app.js
200
```

我们所改变的是将异步代码包裹在`getSiteStatus()`函数中，将一个名为`callback()`的函数作为参数传递给这个函数，在`getSiteStatus()`的最后一行执行这个函数。`showStatusCode()`回调函数仅仅是围绕我们之前调用的`console.log()`。然而，异步执行的工作方式有所不同。在学习如何使用回调编程时，理解函数是一等对象，可以存储在变量中并以不同的名称传递是非常重要的。给你的变量取简单且描述性的名称，这对于让你的代码更容易被他人阅读很重要。现在，一旦 HTTP 调用完成，回调函数就会被调用，`status_code`变量的值将会有一个正确的值。在某些真实情况下，你可能希望一个异步任务在另一个异步任务完成后执行。考虑这个场景：

```js
http.createServer(function (req, res) {
  getURL(url, function (err, res) {
    getURLContent(res.data, function(err,res) {
      ...
    });
  });
});
```

正如你所看到的，我们在一个异步函数中嵌套另一个异步函数。这种嵌套可能导致代码难以阅读和管理。这种回调风格有时被称为**回调地狱**。为了避免这种情况，如果你有代码必须等待其他异步代码完成，那么你通过将你的代码放在作为回调传递的函数中来表达这种依赖关系。另一个重要的想法是给你的函数命名，而不是依赖匿名函数作为回调。我们可以将前面的示例重构为更易读的一个，如下所示：

```js
var urlContentProcessor = function(data){
  ...
}
var urlResponseProcessor = function(data){
  getURLContent(data,urlContentProcessor);
}
var createServer = function(req,res){
  getURL(url,urlResponseProcessor);
};
http.createServer(createServer);
```

这个片段使用了两个重要的概念。首先，我们使用了命名函数并将它们作为回调使用。其次，我们并没有嵌套这些异步函数。如果你在内部函数中访问闭包变量，之前的实现会有所不同。在这种情况下，使用内联匿名函数更是可取的。

回调在 Node 中最为常用。它们通常用于定义一次性响应的逻辑。当你需要对重复事件做出响应时，Node 提供了另一种机制。在进一步讲解之前，我们需要了解 Node 中的定时器和事件函数。

# 定时器

定时器用于在特定延迟后安排特定回调的执行。设置这种延迟执行有两种主要方法：`setTimeout`和`setInterval`。`setTimeout()`函数用于在延迟后安排特定回调的执行，而`setInterval`用于安排回调的重复执行。`setTimeout`函数适用于需要计划执行的任务，例如家务。考虑以下示例：

```js
setTimeout(function() {
  console.log("This is just one time delay");
},1000);
var count=0;
var t = setInterval(function() {
  count++;
  console.log(count);
  if (count> 5){
    clearInteval(t);
  }
}, 2000 );
```

首先，我们使用`setTimeout()`在 1,000 毫秒后执行回调（匿名函数）。这只是对这个回调的一次性计划。我们使用`setInterval()`来安排回调的重复执行。注意我们将`setInterval()`返回的值赋给变量`t`——我们可以在`clearInterval()`中使用这个引用来清除这个计划。

# 事件发射器

我们之前讨论过，回调对于执行一次性逻辑非常出色。**EventEmitter**在响应重复事件方面很有用。EventEmitter 触发事件，并在事件触发时处理这些事件。一些重要的 Node API 是基于 EventEmitter 构建的。

由 EventEmitter 引发的事件通过监听器处理。监听器是与事件关联的回调函数——当事件触发时，其关联的监听器也会被触发。`event.EventEmitter`是一个类，用于提供一致的接口来触发（触发）和绑定回调到事件。

作为一个常见的样式约定，事件名用驼峰命名法表示；然而，任何有效的字符串都可以作为事件名。

使用`require('events')`来访问`EventEmitter`类：

```js
var EventEmitter = require('events');
```

当 EventEmitter 实例遇到错误时，它会触发一个`error`事件。在 Node.js 中，错误事件被视为一个特殊案例。如果你不处理这些错误，程序将以异常堆栈退出。

所有 EventEmitter 在添加新监听器时都会触发`newListener`事件，并在移除监听器时触发`removeListener`。

为了理解 EventEmitter 的使用方法，我们将构建一个简化的 telnet 服务器，不同的客户端可以登录并输入某些命令。根据这些命令，我们的服务器将做出相应的响应：

```js
var _net = require('net');
var _events = require ('events');
var _emitter = new events.EventEmitter();
_emitter.on('join', function(id,caller){
  console.log(id+" - joined");
});
_emitter.on('quit', function(id,caller){
  console.log(id+" - left");
});

var _server = _net.createServer(function(caller) {
  var process_id = caller.remoteAddress + ':' + caller.remotePort;
  _emitter.emit('join',id,caller);
  caller.on('end', function() {
    console.log("disconnected");
    _emitter.emit('quit',id,caller);
  });
});
_server.listen(8124);
```

```js
net module from Node. The idea here is to create a server and let the client connect to it via a standard telnet command. When a client connects, the server displays the client address and port, and when the client quits, the server logs this too.
```

当一个客户端连接时，我们触发一个`join`事件，当客户端断开连接时，我们触发一个`quit`事件。我们对这两个事件都有监听器，它们在服务器上记录适当的消息。

你启动这个程序，并通过 telnet 连接到我们的服务器，如下所示：

```js
telnet 127.0.0.1 8124
```

在服务器控制台上，你会看到服务器记录哪个客户端加入了服务器：

```js
» node app.js
::ffff:127.0.0.1:51000 - joined
::ffff:127.0.0.1:51001 – joined
```

如果任何客户端退出会话，会出现一个适当的消息。

# 模块

当你写很多代码时，你很快就会达到一个需要开始思考如何组织代码的点。Node 模块是我们在讨论模块模式时提到的 CommonJS 模块。Node 模块可以发布到**Node 包管理器**（**npm**）仓库。npm 仓库是 Node 模块的在线集合。

## 创建模块

Node 模块可以是单个文件或包含一个或多个文件的目录。通常创建一个单独的模块目录是个好主意。模块目录中的文件通常命名为`index.js`。模块目录可能如下所示：

```js
node_project/src/nav
                --- >index.js
```

在你的项目目录中，`nav`模块目录包含了模块代码。通常，你的模块代码需要放在`index.js`文件中——如果你想要，你可以将其改放到另一个文件中。考虑这个叫做`geo.js`的简单模块：

```js
exports.area = function (r) {
  return 3.14 * r * r;
};
exports.circumference = function (r) {
  return 3.14 * 3.14 * r;
};
```

你通过`exports`导出了两个函数。你可以使用`require`函数来使用这个模块。这个函数接收模块的名称或者模块代码的系统路径。你可以像下面这样使用我们创建的模块：

```js
var geo = require('./geo.js');
console.log(geo.area(2));
```

因为我们只向外部导出两个函数，所以其他所有内容都保持私有。如果你还记得，我们详细讨论了模块模式——Node 使用 CommonJS 模块。创建模块还有一种替代语法。你可以使用`modules.exports`来导出你的模块。实际上，`exports`是为`modules.exports`创建的一个助手。当你使用`exports`时，它将一个模块导出的属性附加到`modules.exports`上。然而，如果`modules.exports`已经有一些属性附加到它上面，`exports`附加的属性将被忽略。

本节开头创建的`geo`模块可以改写，以返回一个`Geo`构造函数，而不是包含函数的对象。我们可以重写`geo`模块及其使用方式，如下：

```js
var Geo = function(PI) {
  this.PI = PI;
}
Geo.prototype.area = function (r) {
  return this.PI * r * r;
};
Geo.prototype.circumference = function (r) {
  return this.PI * this.PI * r;
};
module.exports = Geo;
```

考虑一个`config.js`模块：

```js
var db_config = {
  server: "0.0.0.0",
  port: "3306",
  user: "mysql",
  password: "mysql"
};
module.exports = db_config;
```

如果你想要从模块外部访问`db_config`，你可以使用`require()`来包含这个模块，并像下面这样引用这个对象：

```js
var config = require('./config.js');
console.log(config.user);
```

组织模块有三种方式：

+   使用相对路径，例如，`config = require('./lib/config.js')`

+   使用绝对路径，例如，`config = require('/nodeproject/lib/config.js')`

+   使用模块搜索，例如，`config = require('config')`

前两个选项是很容易理解的——它们允许 Node 在文件系统中特定位置查找模块。

当你使用第三种选项时，你是在要求 Node 使用标准的查找方法来定位模块。为了定位模块，Node 从当前目录开始，并附上`./node_modules/`。Node 然后尝试从这个位置加载模块。如果找不到模块，那么搜索从父目录开始，直到达到文件系统的根目录。

例如，如果`require('config')`在`/projects/node/`中被调用，Node 将会搜索以下位置，直到找到匹配项：

+   `/projects/node /node_modules/config.js`

+   `/projects/node_modules/config.js`

+   `/node_modules/config.js`

对于从 npm 下载的模块，使用这种方法相对简单。正如我们之前讨论的，只要为 Node 提供一个入口点，你就可以将你的模块组织在目录中。

实现这一点最简单的方法是创建一个`./node_modules/supermodule/`目录，并在该目录中插入一个`index.js`文件。这个`index.js`文件将会被默认加载。另外，你也可以在`mymodulename`文件夹中放一个`package.json`文件，指明模块的名称和主文件：

```js
{
  "name": "supermodule",
  "main": "./lib/config.js"
}
```

你必须明白 Node 将模块缓存为对象。如果你有两个（或更多）文件需要某个特定模块，第一个`require`将在内存中缓存该模块，这样第二个`require`就无需重新加载模块源代码。然而，第二个`require`可以更改模块的功能，如果它愿意的话。这通常被称为**猴子补丁**，用于修改模块的行为，而不真正修改或版本化原始模块。

# npm

npm 是 Node 用来分发模块的包管理器。npm 可以用来安装、更新和管理模块。包管理器在其他语言中也很流行，如 Python。npm 会自动为包解决和更新依赖，因此使你的生活变得轻松。

## 安装包

安装 npm 包有两种方法：本地安装或全局安装。如果你只想为特定的 Node 项目使用模块的功能，可以在项目相对路径下本地安装，这是`npm install`的默认行为。另外，有许多模块可以用作命令行工具；在这种情况下，你可以全局安装它们：

```js
npm install request
```

使用`npm`的`install`指令将安装一个特定的模块——`request`在这个例子中。为了确认`npm install`是否正确工作，检查是否存在一个`node_modules`目录，并验证它包含你安装的包的目录。

随着你向项目中添加模块，管理每个模块的版本/依赖变得困难。管理本地安装包的最佳方式是在你的项目中创建一个`package.json`文件。

`package.json`文件可以通过以下方式帮助你：

+   定义你想安装的每个模块的版本。有时你的项目依赖于模块的特定版本。在这种情况下，你的`package.json`帮助你下载和维护正确的版本依赖。

+   作为项目所需所有模块的文档。

+   部署和打包你的应用程序，而不用担心每次部署代码时都要管理依赖。

你可以通过以下命令创建`package.json`：

```js
npm init
```

在回答了关于你的项目的基本问题后，会创建一个空白的`package.json`，其内容与以下类似：

```js
{
  "name": "chapter9",
  "version": "1.0.0",
  "description": "chapter9 sample project",
  "main": "app.js",
  "dependencies": {
    "request": "².65.0"
  },
  "devDependencies": {},
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [
    "Chapter9",
    "sample",
    "project"
  ],
  "author": "Ved Antani",
  "license": "MIT"
}
```

您可以在文本编辑器中手动编辑此文件。这个文件的一个重要部分是`dependencies`标签。为了指定你的项目依赖的包，你需要在你的`package.json`文件中列出你想要使用的包。你可以列出两种类型的包：

+   `dependencies`：这些包是应用程序在生产中所需的

+   `devDependencies`：这些包仅用于开发和测试（例如，使用**Jasmine node 包**）

在前面的示例中，你可以看到以下依赖关系：

```js
"dependencies": {
  "request": "².65.0"
},
```

这意味着项目依赖于`request`模块。

### 注意

模块的版本依赖于语义版本规则——[`docs.npmjs.com/getting-started/semantic-versioning`](https://docs.npmjs.com/getting-started/semantic-versioning)。

一旦你的 `package.json` 文件准备好了，你只需使用 `npm install` 命令就可以自动为你的项目安装所有模块。

有一个我很喜欢的酷炫技巧。在从命令行安装模块时，我们可以添加 `--save` 标志以自动将该模块的依赖项添加到 `package.json` 文件中：

```js
npm install async --save
npm WARN package.json chapter9@1.0.0 No repository field.
npm WARN package.json chapter9@1.0.0 No README data
async@1.5.0 node_modules/async
```

在前面的命令中，我们使用带有 `--save` 标志的正常 `npm` 命令安装了 `async` 模块。在 `package.json` 中自动创建了相应的条目：

```js
"dependencies": {
  "async": "¹.5.0",
  "request": "².65.0"
},
```

# JavaScript 性能

像任何其他语言一样，编写大规模正确的 JavaScript 代码是一项涉及的任务。随着语言的成熟，许多内在问题正在得到解决。有许多优秀的库可以帮助编写高质量的代码。对于大多数严肃的系统来说，*好的代码 = 正确的代码 + 高性能的代码*。新一代软件系统对性能的要求很高。在本节中，我们将讨论一些你可以使用来分析你的 JavaScript 代码并了解其性能指标的工具。

在本节中，我们将讨论以下两个想法：

+   剖析：在脚本剖析过程中计时各种函数和操作有助于识别你可以优化代码的区域。

+   网络性能：检查网络资源的加载，如图片、样式表和脚本。

## JavaScript 剖析

JavaScript 剖析对于理解代码各个部分的性能方面至关重要。你可以观察函数和操作的时间来了解哪个操作花费的时间更多。有了这些信息，你可以优化耗时函数的性能并调整代码的整体性能。我们将重点关注 Chrome 开发者工具提供的剖析选项。还有全面的分析工具，你可以使用它们来了解代码的性能指标。

### CPU 剖析

CPU 剖析显示了你的代码各个部分执行花费的时间。我们必须通知 DevTools 记录 CPU 剖析数据。让我们来试试剖析器。

你可以按照以下方式在 DevTools 中启用 CPU 剖析器：

1.  打开 Chrome DevTools 的**性能**面板。

1.  确认**收集 JavaScript CPU 剖析**已选中：![CPU 剖析](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00030.jpeg)

为此章节，我们将使用谷歌自己的基准页面，[`octane-benchmark.googlecode.com/svn/latest/index.html`](http://octane-benchmark.googlecode.com/svn/latest/index.html)。我们将使用这个页面，因为它包含示例函数，我们可以看到各种性能瓶颈和基准测试。要开始记录 CPU 配置文件，请在 Chrome 中打开开发者工具，在**配置文件**标签中，点击**开始**按钮或按*Cmd*/*Ctrl* + *E*。刷新**V8 基准套件**页面。当页面完成重新加载后，将显示基准测试的得分。返回**配置文件**面板，通过点击**停止**按钮或再次按*Cmd*/*Ctrl* + *E*来停止记录。

记录的 CPU 配置文件为您提供了函数及其执行时间的详细视图，以下图所示：

![CPU 配置文件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00031.jpeg)

### 时间线视图

谷歌开发者工具**时间线**工具是您可以开始查看代码整体性能的第一站。它允许您记录并分析应用程序运行过程中的所有活动。

**时间线**为您提供了加载和使用您网站时时间花费的完整概述。时间线记录包括每个发生事件的记录，并以**瀑布**图的形式显示：

![时间线视图](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00032.jpeg)

前一个屏幕展示了我们在浏览器中尝试渲染[`twitter.com/`](https://twitter.com/)时的时间线视图。时间线视图为您提供了执行中各个操作花费了多少时间的总体视图：

![时间线视图](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00033.jpeg)

在前一个屏幕截图中，我们可以看到各种 JavaScript 函数、网络调用、资源下载和其他渲染 Twitter 主页的操作逐步执行。这个视图让我们对哪些操作可能需要更长时间有了很好的了解。一旦我们识别出这样的操作，我们就可以对其进行性能优化。**内存**视图是一个很好的工具，可以帮助您了解在浏览器中您的应用程序生命周期内内存的使用情况。**内存**视图向您展示了您的应用程序随时间使用的内存的图表，并维护了一个计数器，用于统计保存在内存中的文档数量、DOM 节点和事件监听器。**内存**视图可以帮助检测内存泄漏，并给出足够好的提示，让您了解需要进行哪些优化：

![时间线视图](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/ms-js/img/00034.jpeg)

JavaScript 性能是一个迷人的主题，完全值得一本专著。我强烈建议您探索 Chrome 的开发者工具，了解如何最佳地使用这些工具来检测和诊断您代码中的性能问题。

# 概要

在本章中，我们查看了 JavaScript 的另一个化身——以 Node.js 形式的 server-side 框架。

Node 提供了一个异步事件模型，用 JavaScript 编写可扩展和高性能的服务器应用程序。我们深入探讨了 Node 的一些核心概念，例如事件循环、回调、模块和定时器。理解它们对于编写好的 Node 代码至关重要。我们还讨论了几种更好地组织 Node 代码和回调的技术。

至此，我们已经探索了一种出色的编程语言。JavaScript 之所以在万维网的演变中发挥了重要作用，是因为它的多样性。该语言继续扩大其视野，并在每次新迭代中得到改进。

我们的旅程始于理解语言的语法和语法的构建块。我们掌握了闭包和 JavaScript 的功能行为的基本思想。这些概念是如此基本，以至于大多数 JavaScript 模式都是基于它们的。我们探讨了如何利用这些模式用 JavaScript 写出更好的代码。我们研究了 JavaScript 如何操作 DOM 以及如何有效地使用 jQuery 操纵 DOM。最后，我们查看了 JavaScript 的服务器端化身 Node.js。

这本书应该已经让你在开始用 JavaScript 编程时思维方式有所不同。你不仅会在编码时考虑常见的模式，而且会欣赏并使用 ES6 带来的新语言特性。
