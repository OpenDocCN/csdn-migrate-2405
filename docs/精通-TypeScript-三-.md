# 精通 TypeScript（三）

> 原文：[`zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E`](https://zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：模块化

模块化是现代编程语言中常用的一种技术，它允许程序由一系列较小的程序或模块构建而成。编写使用模块的程序鼓励程序员编写符合称为“关注点分离”的设计原则的代码。换句话说，每个模块专注于做一件事，并且有一个明确定义的接口。如果我们通过关注接口来使用这个模块，我们可以很容易地用其他东西替换这个接口，而不会破坏我们的代码。我们将在下一章更多地关注“关注点分离”和其他面向对象的设计模式。

JavaScript 本身并没有模块的概念，但它被提议用于即将到来的 ECMAScript 6 标准。流行的框架和库，如 Node 和 Require，已经在它们的框架中构建了模块加载功能。然而，这些框架使用略有不同的语法。Node 使用 CommonJS 语法进行模块加载，而 Require 使用**异步模块加载**（**AMD**）语法。TypeScript 编译器有一个选项可以打开模块编译，然后在这两种语法风格之间切换。

在本章中，我们将看一下两种模块风格的语法，以及 TypeScript 编译器如何实现它们。我们将看一下在编写 Node 和 Require 的代码时如何使用模块。我们还将简要介绍 Backbone，以及如何使用 Model、View 和 Controller 编写应用程序。这些 Backbone 组件将被构建为可加载的模块。

# CommonJs

使用 CommonJs 语法编写模块的最普遍用法是编写服务器端代码。有人认为基于浏览器的 CommonJs 语法简直无法做到，但也有一些库，比如 Curl（[`github.com/cujojs/curl`](https://github.com/cujojs/curl)）可以实现这种语法。然而，在本节中，我们将专注于 Node 应用程序开发。

## 在 Visual Studio 中设置 Node

在 Visual Studio 中使用 Node 已经变得非常简单，这得益于 Node 工具的 Visual Studio 插件（[`nodejstools.codeplex.com`](https://nodejstools.codeplex.com)）。这个工具集也已经更新，使用 TypeScript 作为默认编辑器，为 Node 带来了完整的 TypeScript 开发体验。安装了扩展后，我们可以创建一个新的空白 Node 应用程序，如下面的截图所示：

![在 Visual Studio 中设置 Node](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_01.jpg)

使用 Node 工具集创建空白 Node 应用程序

这个项目模板将自动为我们创建一个`server.ts` TypeScript 文件，并自动包含`node.d.ts`声明文件。如果我们编译并运行这个默认实现，只需按下*F5*，项目模板将自动启动一个新的控制台来运行我们的 Node 服务器，启动服务器实例，并打开一个浏览器连接到这个实例。如果一切顺利，你的浏览器将简单地显示**Hello World**。

让我们来看看创建我们的 Node 服务器实例的`server.ts` TypeScript 文件：

```ts
import _http = require('http');
var port = process.env.port || 1337
http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
}).listen(port);
```

这段代码片段的第一行使用 CommonJs 模块语法告诉我们的 Node 服务器必须`import`名为`'http'`的库。

这一行有两个关键部分。为了解释这些关键部分，让我们从`=`号的右侧开始，然后向左工作。`require`函数接受一个参数，并用于告诉应用程序有一个名为`'http'`的库。`require`函数还告诉应用程序需要这个库才能继续正常运行。由于`require`是 TypeScript 模块语法的关键部分，它被赋予了关键字状态，并且将会像`var`、`string`和`function`等其他关键字一样以蓝色高亮显示。如果应用程序找不到`'http'`库，那么 Node 将立即抛出异常。

`=`号的左侧使用了`import`关键字，这也是模块语法中的一个基本概念。`import`语句告诉应用程序将通过`require`函数加载的库`require('http')`附加到名为`_http`的命名空间中。`'http'`库公开的任何函数或对象都将通过`_http`命名空间对程序可用。

如果我们快速跳到第三行，我们会看到我们调用了`'http'`模块中定义的`createServer`函数，并通过`_http`命名空间调用它，因此是`_http.createServer()`。

### 注意

由空白 Node 项目模板生成的默认`server.ts`文件与我们前面的代码示例略有不同。它将导入命名为`http`，与库名`'http'`匹配，如下所示：

`import http = require('http');`

这是 Node 的一个常见命名标准。当然，您可以将导入的命名空间命名为任何您喜欢的名称，但是将命名空间与导入的库的名称匹配会有助于提高代码的可读性。

我们的代码片段的第二行只是将名为`port`的变量设置为全局变量`process.env.port`的值，或者默认值`1337`。这个端口号在最后一行使用，使用流畅的语法在`http.createServer`函数的返回值上调用`listen`函数。

我们的`createServer`函数有两个名为`req`和`res`的变量。如果我们将鼠标悬停在`req`变量上，我们会看到它的类型是`_http.ServerRequest`。同样，`res`变量的类型是`_http.ServerResponse`。这两个变量是我们的 HTTP 请求和响应流。在代码体中，我们在 HTTP 响应上调用`writeHead`函数来设置内容类型，然后在 HTTP 响应上调用`end`函数来向浏览器写入文本`'Hello World\n'`。

通过这几行代码，我们创建了一个运行中的 Node HTTP 服务器，提供一个简单的网页，其中包含文本**"Hello World"**。

请注意，如果您对 TypeScript 语法有敏锐的眼光，您会注意到这个文件使用 JavaScript 语法而不是 TypeScript 语法来调用我们的`createServer`函数。这很可能是由于最近将 Node 工具集从 JavaScript 升级到 TypeScript。调用`createServer`也可以使用 TypeScript 的箭头函数语法来编写，如下所示：

```ts
_http.createServer((req, res) => { .. }
```

## 创建一个 Node 模块

要创建一个 Node 模块，我们只需要创建另一个 TypeScript 文件来存放我们的模块代码。让我们创建一个名为`ServerMain.ts`的文件，并将写入 HTTP 响应的代码移入此模块，如下所示：

```ts
import http = require('http');
export function processRequest(
    req: http.ServerRequest,
    res: http.ServerResponse): void
{
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
}
```

我们的`ServerMain`模块以将`'http'`模块导入到`http`命名空间开始。这是必要的，以便我们可以使用此库的`ServerRequest`和`ServerResponse`类型。

现在使用关键字`export`来指示哪些函数将对该模块的用户可用。正如我们所看到的，我们导出了一个名为`processRequest`的函数，它接受两个参数，`req`和`res`。这个函数将用作替代我们之前在`server.ts`文件中使用的匿名函数`(req, res) => { ... }`。

请注意，作为优秀的 TypeScript 编码者，我们还强类型化了`req`和`res`变量，分别为`http.ServerRequest`类型和`http.ServerResponse`类型。这将使我们的 IDE 内置智能提示，并且也符合强类型的两个原则（S.F.I.A.T 和自描述函数）。

在修改`server.ts`文件以使用我们的新模块之前，让我们打开生成的 JavaScript 文件，更仔细地查看一下 CommonJs 语法：

```ts
function processRequest(req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
}
exports.processRequest = processRequest;
```

这个 JavaScript 的前半部分足够简单——我们有一个名为`processRequest`的函数。然而，最后一行将这个函数附加到`exports`全局变量的一个属性上。这个`exports`全局变量是 CommonJs 将模块发布到外部世界的方式。任何需要暴露给外部世界的函数、类或属性都必须附加到`exports`全局变量上。每当我们在 TypeScript 文件中使用`exports`关键字时，TypeScript 编译器将为我们生成这行代码。

## 使用 Node 模块

现在我们已经有了我们的模块，我们可以修改我们的`server.ts`文件来使用这个模块，如下所示：

```ts
import http = require('http');
import ServerMain = require('./ServerMain');
var port = process.env.port || 1337;
http.createServer(ServerMain.processRequest).listen(port);
```

第一行保持不变，但第二行使用相同的`import`和`require`语法来将我们的`'./ServerMain'`模块导入到`ServerMain`命名空间中。

### 注意

我们用来命名这个模块的语法指向一个本地文件模块，因此使用相对文件路径到模块文件。这个相对路径将解析为 TypeScript 生成的`ServerMain.js`文件。创建一个名为`'ServerMain'`的全局 Node 模块，它将全局可用——类似于`'http'`模块——超出了本讨论的范围。

我们对`http.createServer`函数的调用现在将我们的`processRequest`函数作为参数传入。我们已经从使用箭头函数的匿名函数改为了来自`ServerMain`模块的命名函数。我们还开始遵循我们的“关注点分离”设计模式。`server.ts`文件在特定端口上启动服务器，而`ServerMain.ts`文件现在包含用于处理单个请求的代码。

## 链接异步函数

在编写 Node 代码时，有必要仔细注意所有 Node 编程的异步性质，以及 JavaScript 的词法作用域规则。幸运的是，TypeScript 编译器会在我们违反这些规则时生成错误。举个例子，让我们更新我们的`ServerMain`模块，从磁盘中读取文件，并提供该文件的内容，而不是我们的`Hello world`文本，如下所示：

```ts
import fs = require("fs");
export function processRequestReadFromFileAnonymous(
      req: http.ServerRequest, res: http.ServerResponse) 
{
    fs.readFile('server.js', 'utf8', (err, data) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        if (err)
            res.write("could not open file for reading");
        else {
            res.write(data);
            res.end();
        }
    });
}
```

要从磁盘中读取文件，我们需要使用名为`"fs"`的 Node 全局模块，或者文件系统，它在代码的第一行被导入。然后我们暴露一个名为`processRequestReadFromFileAnonymous`的新函数，再次使用`req`和`res`参数。在这个函数内部，我们使用`fs.readFile`函数来使用三个参数从磁盘中读取文件。第一个参数是要读取的文件名，第二个参数是文件类型，第三个参数是一个回调函数，Node 在从磁盘中读取文件后将调用它。

这个匿名函数的主体与我们之前看到的类似，但它还检查`err`参数，以查看在加载文件时是否出现错误。如果没有错误，函数就简单地将文件写入响应流中。

在现实世界的应用程序中，主`processRequestReadFromFileAnonymous`函数内部的逻辑可能会变得非常复杂（除了名称之外），并且可能涉及从磁盘读取硬编码文件名的多个步骤。让我们将这个匿名函数移到一个私有函数中，看看会发生什么。我们对重构这段代码的第一次尝试可能类似于以下内容：

```ts
export function processRequestReadFromFileError(
    req: http.ServerRequest, res: http.ServerResponse) 
{
    fs.readFile('server.js', 'utf8', writeFileToStreamError);
}
function writeFileToStreamError(err, data) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    if (err)
        res.write("could not open file for reading");
    else {
        res.write(data);
        res.end();
    }
}
```

在这里，我们修改了`fs.readFile`函数调用，并用命名函数`writeFileToStreamError`替换了匿名回调函数。然而，这个改变会立即生成一个编译错误：

```ts
Cannot find name 'res'.

```

这个编译错误是由 JavaScript 的词法作用域规则引起的。函数`writeFileToStreamError`试图使用父函数的`res`参数。然而，一旦我们将这个函数移出父函数的词法作用域，变量`res`就不再在作用域内 - 因此将是`undefined`。为了解决这个错误，我们需要确保`res`参数的词法作用域在我们的代码结构中得到维持，并且我们需要将`res`参数的值传递给我们的`writeFileToStream`函数，如下所示：

```ts
export function processRequestReadFromFileChained(
    req: http.ServerRequest, res: http.ServerResponse) 
{
    fs.readFile('server.js', 'utf8', (err, data) => {
        writeFileToStream(err, data, res);
    });
}
function writeFileToStream(
    err: ErrnoException, data: any, 
    res: http.ServerResponse): void 
{
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    if (err)
        res.write("could not open file for reading");
    else {
        res.write(data);
        res.end();
    }
}
```

请注意，在前面代码的第三行调用`fs.readFile`时，我们已经恢复到了匿名语法，并将父级`res`参数的值传递给我们的新函数`writeFileToStream`。我们对代码的这种修改现在正确地遵守了 JavaScript 的词法作用域规则。另一个副作用是，我们已经清楚地定义了`writeFileToStream`函数需要哪些变量才能工作。它需要`fs.readFile`回调中的`err`和`data`变量，但它还需要原始 HTTP 请求中的`res`变量。

### 注意

我们没有导出`writeFileToStream`函数；它纯粹是我们模块内部使用的函数。

现在我们可以修改我们的`server.ts`文件来使用我们的新的链式函数：

```ts
http.createServer(ServerMain.processRequestReadFromFileChained) .listen(port);
```

现在运行应用程序将展示`server.js`文件的内容：

![链接异步函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_02.jpg)

Node 应用程序提供磁盘上文件的内容

请注意，由于我们使用了模块，我们已经能够编写`processRequest`函数的三个不同版本，每个版本都有一点不同。然而，我们对启动服务器的`server.ts`文件的修改非常简单。我们只是替换了服务器调用的函数，以有效地运行我们应用程序的三个不同版本。再次，这符合“关注点分离”设计原则。`server.ts`代码只是用于在特定端口上启动 Node 服务器，并不应该关心每个请求是如何处理的。我们`ServerMain.ts`中的代码只负责处理请求。

这结束了我们在 TypeScript 中编写 Node 应用程序的部分。正如我们所见，TypeScript 开发者体验带来了一个编译步骤，它将快速捕捉到我们代码中的词法作用域规则和许多其他问题。最终得分，TypeScript：1，有错误的代码：0！

# 使用 AMD

AMD 代表异步模块定义，正如其名称所示，它异步加载模块。这意味着当加载 HTML 页面时，获取 JavaScript 模块文件的请求同时发生。这使得我们的页面加载更快，因为我们同时请求了更小量的 JavaScript。

AMD 模块加载通常用于浏览器应用程序，并与提供脚本加载功能的第三方库一起工作。目前最流行的脚本和模块加载器之一是 Require。在本节中，我们将看看如何使用 AMD 模块加载语法，以及如何在基于浏览器的应用程序中实现 Require。

首先，让我们使用“**带有 TypeScript 的 HTML 应用程序”**Visual Studio 模板创建一个简单的基于 TypeScript 的解决方案。如果您不使用 Visual Studio，那么只需创建一个新项目或基本源目录，并设置 TypeScript 编译环境。为了使用 AMD 编译，我们需要设置 TypeScript 项目属性，以便编译为 AMD 模块语法。

使用 NuGet，我们将安装以下包：

+   RequireJS

+   `Requirejs.TypeScript.DefinitelyTyped`

+   jQuery

+   jquery.TypeScript.DefinitelyTyped

+   JasmineTest

+   Jasmine.TypeScript.DefinitelyTyped

因此，我们还将基于 Backbone 构建我们的应用程序，因此我们需要以下 NuGet 包：

+   Backbone.js

+   `Backbone.TypeScript.DefinitelyTyped`

### 注意

Backbone 安装还将安装 Underscore，而`Backbone.TypeScript.DefinitelyTyped`包还将安装`underscore.TypeScript.DefinitelyTyped`。

## Backbone

Backbone 提供了一个非常简约的框架，用于编写丰富的客户端 JavaScript 应用程序。它使用 MVC 模式将我们的逻辑抽象出来，远离直接的 DOM 操作。Backbone 提供了一组核心功能，分为模型、集合和视图，以及一些辅助类来帮助处理事件和路由。库本身非常小，最小化的`.js`文件大小不到 20 KB。它的唯一依赖是 Underscore，这是一个实用库，大小不到 16 KB。Backbone 是一个非常受欢迎的库，有大量的扩展，并且相对容易学习和实现。

## 模型、集合和视图

在 Backbone 的核心是模型。模型是一个具有一组属性的类，代表将被视为一个单元的信息项。您可以将模型视为数据库表中的单行数据，或者作为保存特定类型信息的对象。模型对象通常非常简单，每个属性都有一些 getter 和 setter，可能还有一个用于 RESTful 服务的`url:`属性。模型的数组存储在集合中。集合可以被视为数据库表中的所有数据行，或者是相同类型的逻辑模型组。模型可以包含其他模型，也可以包含集合，因此我们可以自由地混合和匹配和组合集合和模型。

因此，模型用于定义我们的应用程序使用的数据结构。Backbone 为模型和集合都提供了一个简单的`url:`属性，用于将 Backbone 模型与 RESTful 服务同步。Backbone 将通过这个`url:`属性来生成对我们服务的创建、读取、更新和删除的 AJAX 调用。

一旦模型或集合被创建，它就会被传递给视图。Backbone 视图负责将模型的属性与 HTML 模板结合在一起。模板由普通 HTML 组成，但具有特殊的语法，允许将模型的属性注入到此 HTML 中。一旦将此 HTML 模板与模型结合，视图就可以将生成的 HTML 呈现到页面上。

Backbone 实际上并没有控制器的概念，就像经典的 MVC 定义中那样，但我们可以使用普通的 TypeScript 类来实现相同的功能。

## 创建模型

让我们立即深入 Backbone，并从定义模型开始。在此示例中，我们将使用联系人的概念——只有`Name`和`EmailAddress`属性——如下所示。

请注意，`ContactModel.ts`文件位于`/tscode/app/models`目录下：

```ts
interface IContactModel {
    Name: string;
    EmailAddress: string;
}
export class ContactModel extends Backbone.Model
    implements IContactModel 
{
    get Name() {
        return this.get('Name');
    }
    set Name(val: string) {
        this.set('Name', val);
    }
    get EmailAddress() {
        return this.get('EmailAddress');
    }
    set EmailAddress(val: string) {
        this.set('EmailAddress', val);
    }
}
```

我们从定义一个名为`IContactModel`的接口开始，其中包含我们的`Name`和`EmailAddress`属性，都是字符串。

接下来，我们创建了一个名为`ContactModel`的类，它派生自基类`Backbone.Model`。请注意，我们在类定义之前使用了`export`关键字，以指示给 TypeScript 编译器我们正在创建一个可以在其他地方导入的模块。`export`关键字和用法与我们之前使用 CommonJS 语法时完全相同。我们的`ContactModel`类实现了`IContactModel`接口，并且还使用了 ES5 的`get`和`set`语法来定义`Name`和`EmailAddress`属性。

### 注意

每个属性的实现都调用了 Backbone 的`this.get('<propertyname>')`或`this.set('<propertyname>', value)`函数。Backbone 将模型属性存储为对象属性，并在内部使用这些`get`和`set`函数与模型属性交互，因此之前使用的语法。

让我们遵循 TDD 实践，并编写一组单元测试，以确保我们可以正确地创建`ContactModel`的实例。对于这个测试，我们将在`/tscode/tests/models`目录下创建一个`ContactModelTests.ts`文件，如下所示：

```ts
import cm = require("../../app/models/ContactModel");
describe('/tests/models/ContactModelTests', () => {
    var contactModel: cm.ContactModel;
    beforeEach(() => {
        contactModel = new cm.ContactModel(	
            { Name: 'testName', EmailAddress: 'testEmailAddress'
            });
    });
    it('should set the Name property', () => {
        expect(contactModel.Name).toBe('testName');
    });
    it('should set the Name attribute', () => {
        expect(contactModel.get('Name')).toBe('testName');
    });
});
```

这个测试的第一行使用了我们之前见过的`import <namespace> = require('<filename>')`语法，导入了我们之前导出的`ContactModel`模块。您会注意到文件名使用了相对路径，它在指定`"app/models/ContactModel"`路径之前向下跨越了两个目录(`"../../"`)。这是因为 AMD 模块编译使用相对于当前文件的路径。由于我们的测试代码在`/tscode/tests/models`目录中，这个相对路径必须指向包含`ContactModel.ts` TypeScript 文件的正确目录。

我们的测试定义了一个名为`contactModel`的变量，它被强类型为`cm.ContactModel`类型。同样，我们使用了`import`语句中的前缀作为命名空间，以便引用导出的`ContactModel`类。我们的`beforeEach`函数然后创建了`ContactModel`类的一个实例，将一个具有`Name`和`EmailAddress`属性的 JavaScript 对象传递给构造函数。

### 注意

我们在`ContactModel`类的构造函数中使用了 JSON 语法。这个语法与 RESTful 服务返回的数据非常接近，因此是一种方便的方式来构造类并在单个构造函数调用中分配属性。

我们的第一个测试检查`contactModel.Name` ES5 语法是否正确工作，并且将返回文本`'testName'`。第二个测试几乎相同，但是使用了`.get('Name')`内部 Backbone 属性语法，以确保我们的 TypeScript 类和 Backbone 类按预期工作。

## require.config 文件

现在我们已经定义了一个`Backbone.Model`，并且为它编写了一个 Jasmine 测试，我们需要在浏览器中运行这个测试来验证我们的结果。通常，我们会创建一个 HTML 页面，然后在头部部分包含每个 JavaScript 文件的`<script>`标签。这就是 AMD 发挥作用的地方。我们不再需要在 HTML 中指定每个 JavaScript 文件。我们只需要包含一个 Require 的`<script>`标签（这是我们的模块加载器），它将自动协调加载我们需要的所有文件。

为此，让我们在`/tests`目录中创建一个`SpecRunner.html`文件，如下所示：

```ts
<!DOCTYPE html>
<html >
<head>
    <title>AMD SpecRunner</title>
    <link rel="stylesheet" 
          type="text/css" 
          href="/Scripts/jasmine/jasmine.css">
    <script
        data-main="/tscode/tests/TestConfig"
        type="text/javascript"
        src="img/require.js">
    </script>
</head>
<body>
</body>
</html>
```

这是一个非常简单的 HTML 文件。这里需要注意的是`<script>`标签加载了`/Scripts/require.js`。这个脚本标签有一个`data-main`属性，它设置为`"/tscode/tests/TestConfig"`。`data-main`属性被传递给 Require，它告诉 Require 从哪里开始寻找我们的 JavaScript 文件。在前面的代码中，Require 将寻找一个名为`/tscode/tests/TestConfig.js`的文件。

我们将按照以下方式构建`/tscode/tests/TestConfig.ts`文件：

```ts
require.config(
    {
        baseUrl: "../../",
        paths: {
            'jasmine': '/Scripts/jasmine/jasmine',
            'jasmine-html': '/Scripts/jasmine/jasmine-html',
            'jasmine-boot': '/Scripts/jasmine/boot',
            'underscore' : '/Scripts/underscore',
            'backbone': '/Scripts/backbone',
            'jquery': '/Scripts/jquery-2.1.1',
        },
        shim: {
            underscore: {
                exports: '_'
            },
            backbone : {
                deps: ['underscore'],
                exports: 'Backbone'
            },
            'jasmine' : {
                exports: 'window.jasmineRequire'
            },
            'jasmine-html': {
                deps : ['jasmine'],
                exports: 'window.jasmineRequire'
            },
            'jasmine-boot': {
                deps : ['jasmine-html', 'backbone'],
                exports: 'window.jasmineRequire'
            }
        }
    }
);

var specs = [
    'tscode/tests/models/ContactModelTests'
];

require(['jasmine-boot'], (jb) => {
    require(specs, () => {
        (<any>window).onload();
    });
});
```

我们从调用`require.config`函数开始，并传递一个具有三个属性的 JavaScript 对象：`baseUrl`，`paths`和`shim`。`baseUrl`属性告诉 Require 在查找 JavaScript 文件时要使用的基本目录。在示例应用程序中，我们的`TestConfig.ts`文件位于`/tscode/tests`目录中，因此我们的基本目录将是`/`。

`paths`属性指定了我们 JavaScript 文件的完整路径，每个条目都有一个名称。在前面的示例中，脚本`/Scripts/jasmine/jasmine.js`被命名为`'jasmine'`，并且可以在脚本的其余部分中被称为`'jasmine'`。

### 注意

Require 会自动将`.js`附加到这些条目中，因此`paths`属性中的任何条目都不应包含文件条目中的`.js`。

`shim`属性告诉 Require 关于`paths`属性中每个条目的更多细节。看一下`backbone`的`shim`条目。它有一个`deps`属性，指定了 Backbone 的依赖关系。Backbone 依赖于 Underscore，因此必须在 Backbone 之前加载 Underscore。

`exports`属性告诉 Require 将库附加到指定为 exports 值的命名空间。因此，在我们之前的示例中，对 Underscore 的任何调用都必须在 Underscore 库中的任何函数调用之前加上`_`。例如，`_.bindAll`调用 Underscore 的`bindAll`函数。

在`require.config`的`shim`部分指定的依赖关系是递归的。如果我们看一下`jasmine-boot`的 shim，我们可以看到它依赖于`jasmine-html`，而`jasmine-html`又依赖于`jasmine`。Require 将确保在运行需要`jasmine-boot`的代码之前，按正确的顺序加载所有这些脚本。

接下来让我们看一下文件底部的`require`函数调用。这个调用有两个参数：需要加载的文件数组和一旦加载步骤完成后要调用的回调函数。这个回调函数对应于数组中每个文件条目的参数。因此，在前面的示例中，`'jasmine-boot'`将通过相应的参数`jb`提供给我们的函数。稍后我们将看到更多这方面的例子。

对`require`函数的调用，每个调用都有其需要加载的文件数组和相应的回调参数，可以嵌套。在我们的示例中，我们在初始调用内嵌套了对 require 函数的第二次调用，但这次我们传入了`specs`数组并省略了回调参数。这个`specs`数组目前只包含我们的`ContactModelTests`文件。我们嵌套的匿名函数只是调用`window.onload`函数，这将触发 Jasmine 运行我们所有的测试。

### 注意

对`window.onload()`的调用具有稍微奇怪的语法。在调用`onload()`函数之前，我们使用显式转换将`window`变量转换为`<any>`类型。这是因为 TypeScript 编译器期望将`Event`参数传递给`onload()`函数。我们没有事件参数，需要确保生成的 JavaScript 语法正确 - 因此转换为`<any>`。

如果一切顺利，我们现在可以启动浏览器，并在`/tscode/tests/SpecRunner.html`页面上调用`SpecRunner.html`。

## 修复 Require 配置错误

在使用 Require 开发 AMD 应用程序时，经常会出现意外行为、奇怪的错误消息或者空白页面。这些奇怪的结果通常是由 Require 的配置引起的，要么是在`paths`，`shim`或`deps`属性中。修复这些 AMD 错误一开始可能会令人沮丧，但通常是由两种情况引起的 - 不正确的依赖关系或`file-not-found`错误。

要修复这些错误，我们需要打开浏览器中的调试工具，大多数浏览器可以通过简单地按下*F12*来实现。

### 不正确的依赖关系

一些 AMD 错误是由`require.config`中的不正确依赖关系引起的。可以通过检查浏览器中的控制台输出来找到这些错误。依赖错误会生成类似以下的浏览器错误：

```ts
ReferenceError: jasmineRequire is not defined
ReferenceError: Backbone is not defined

```

这种类型的错误可能意味着 AMD 加载器在加载 Underscore 之前加载了 Backbone，例如。因此，每当 Backbone 尝试使用下划线函数时，我们会得到一个`未定义`错误，如前面的输出所示。修复这种类型的错误的方法是更新导致错误的库的`deps`属性。确保所有先决条件库都已在`deps`属性中命名，错误应该会消失。如果没有，那么错误可能是由下一种类型的 AMD 错误引起的，即`文件未找到`错误。

### 404 错误

文件未找到，或 404 错误通常由类似以下的控制台输出指示：

```ts
Error: Script error for: jquery
http://requirejs.org/docs/errors.html#scripterror
Error: Load timeout for modules: jasmine-boot
http://requires.org/docs/errors.html#timeout

```

要找出哪个文件导致了前面的错误，请切换到调试工具中的网络选项卡并刷新页面。查找 404（`文件未找到`）错误，如下面的截图所示：

![404 错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_03.jpg)

Firefox 网络选项卡显示 404 错误

在这个截图中，我们可以看到对`jquery.js`的调用生成了一个 404 错误，因为我们的文件实际上被命名为`/Scripts/jquery-2.1.1.js`。这种错误可以通过在`require.config`的`paths`参数中添加一个条目来修复，这样任何对`jquery.js`的调用都会被替换为对`jquery-2.1.1.js`的调用。

### 注意

Require 有一套很好的常见 AMD 错误文档（[`requirejs.org/docs/errors.html`](http://requirejs.org/docs/errors.html)），以及包括循环引用在内的高级 API 用法，因此请务必查看该网站，了解可能的 AMD 错误的更多信息。

## 使用 Backbone.Collections

现在我们已经有了一个工作并经过测试的`ContactModel`，我们可以构建一个`Backbone.Collection`来容纳一组`ContactModel`实例。由于我们使用了 AMD，我们可以创建一个新的`ContactCollection.ts`文件，并添加以下代码：

```ts
import cm = require("./ContactModel")
export class ContactCollection
    extends Backbone.Collection<cm.ContactModel> {
    model = cm.ContactModel;
    url = "/tscode/tests/contacts.json";
}
```

创建一个`Backbone.Collection`相对简单。首先，我们像之前看到的那样`import`了`ContactModel`，并将其赋值给`cm`命名空间。然后我们创建了一个名为`ContactCollection`的类，它`extends`自`Backbone.Collection`，并使用了泛型类型`cm.ContactModel`。这个`ContactCollection`有两个属性：`model`和`url`。`model`属性告诉 Backbone 内部使用哪个模型类，`url`属性指向服务器端的 RESTful URL。当我们将数据与服务器同步时，Backbone 将为服务器端的 RESTful 调用生成正确的 POST、GET、DELETE 和 UPDATE HTTP 协议。在前面的示例中，我们只是返回一个硬编码的 JSON 文件，因为我们只会使用 HTTP GET。

如果我们打开 TypeScript 生成的结果 JavaScript 文件，我们会看到编译器已经对我们的文件进行了相当多的修改：

```ts
var __extends = this.__extends || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
define(["require", "exports", "./ContactModel"], function (require, exports, cm) {
    var ContactCollection = (function (_super) {
        __extends(ContactCollection, _super);
        function ContactCollection() {
            _super.apply(this, arguments);
            this.model = cm.ContactModel;
            this.url = "/tscode/tests/contacts.json";
        }
        return ContactCollection;
    })(Backbone.Collection);
    exports.ContactCollection = ContactCollection;
});
//# sourceMappingURL=ContactCollection.js.map
```

文件的前六行以`var __extends`开头，只是 TypeScript 在 JavaScript 中实现继承的方式，我们不需要过多关注它。

需要注意的行以`define`函数开头。TypeScript 已经将我们的类定义包裹在一个外部的`define`调用中。这个`define`函数现在有三个参数：`require`，`exports`和`./ContactModel`。这个函数的语法和用法与我们在`TestConfig.ts`文件中自己编写的`require`函数调用完全相同。

第一个参数是要导入的文件数组，第二个参数是在这些文件加载完成后要调用的回调函数。同样，我们第一个数组中的每个元素在回调参数中都有对应的参数。TypeScript 会自动为我们添加`"require"`和`"exports"`参数，然后包含我们使用`import`关键字指定的任何文件。当 TypeScript 使用 AMD 语法编译我们的文件时，它会自动生成与 AMD 加载器（如 Require）兼容的 JavaScript 样式。

现在让我们为我们的`ContactCollection`编写一些单元测试：

```ts
import cc = require("../../app/models/ContactCollection");
import cm = require("../../app/models/ContactModel");
describe("/tests/models/ContactCollectionTests", () => {
    it("should create a collection", () => {
        var contactCollection = new cc.ContactCollection(
        [
            new cm.ContactModel(
              { Name: 'testName1', EmailAddress: 'testEmail1' }),
            new cm.ContactModel(
              { Name: 'testName2', EmailAddress: 'testEmail2' })
        ]);
        expect(contactCollection.length).toBe(2);
    });
});
```

这个测试以`import`语句开始，导入了`ContactCollection`和`ContactModel`，因为我们将在这个测试中使用这两者。然后简单地创建一个新的`ContactCollection`，并传入一个包含两个新的`ContactModels`的数组。这个测试突出了如何通过编程方式创建一个新的`ContactCollection`并填充它。

现在让我们编写一个测试，通过`url`属性加载集合：

```ts
describe("contact json tests", () => {
    var collection: cc.ContactCollection;
    it("should load collection from url", () => {
        collection = new cc.ContactCollection();
        collection.fetch({ async: false });
        expect(collection.length).toBe(4);
    });
});
```

这个测试创建了一个新的`ContactCollection`，然后调用了`fetch`函数。

### 注意

我们传递了一个设置为`false`的`async`标志，以强制 Backbone 使用同步调用服务器。换句话说，JavaScript 将在获取完成之前暂停，然后再继续执行下一行。我们本可以使用 Jasmine 的异步`done`语法来编写这个测试，但对于较小的测试，传递这个`async`标志使代码更容易阅读。

如前所述，`fetch`函数将使用`url`参数向提供的 URL 发出 GET HTTP 请求，在这种情况下，它只是加载`contacts.json`文件。该文件的内容如下：

```ts
[
    { "Name": "Mr Test Contact", 
       "EmailAddress": "mr_test_contact@test.com" },
    { "Name": "Mrs Test Contact", 
       "EmailAddress": "mrs_test_contact@test.com" },
    { "Name": "Ms Test Contact",
       "EmailAddress": "ms_test_contact@test.com" },
    { "Name": "Dr Test Contact", 
       "EmailAddress": "dr_test_contact@test.com" }
]
```

这个文件使用简单的 JSON 语法定义了四个联系人，每个联系人都有一个`Name`和`EmailAddress`属性。让我们编写一些集成测试，以确保使用这个 JSON 的`fetch`函数实际上正确地创建了一个`ContactCollection`：

```ts
describe("contact json model tests", () => {
    var collection: cc.ContactCollection;
    beforeEach(() => {
        collection = new cc.ContactCollection();
        collection.fetch({ async: false });
    });
    it("ContactModel at 0 should have attribute called Name", () => {
        var contactModel = collection.at(0);
        expect(contactModel.get('Name')).toBe('Mr Test Contact');
    });
    it("ContactModel at 0 should have property called Name", () => {
        var contactModel : cm.ContactModel = collection.at(0);
        expect(contactModel.Name).toBe('Mr Test Contact');
    });
});
```

在这个测试代码中，我们使用`beforeEach`函数用`ContactCollection`类的一个实例填充我们的集合变量，然后再次调用`fetch`函数，使用`{async: false}`标志。我们的第一个测试然后使用 Backbone 的`at`函数从索引`0`处的集合中检索第一个模型。然后我们使用 Backbone 的内部`get`函数检查返回的模型的`'Name'`属性。第二个测试使用我们`ContactModel`类的 ES5 语法，只是为了测试 Backbone 是否确实在其集合中存储了我们的`ContactModel`类的实例。

要将这些测试包含在我们的测试套件中，现在我们只需要修改`TestConfig.ts`文件，并在我们的 specs 数组中添加一个条目，如下所示：

```ts
var specs = [
    'tscode/tests/models/ContactModelTests',
    'tscode/tests/models/ContactCollectionTests'
];
```

## Backbone 视图

现在我们有了一个用于存放我们的`ContactModels`的`ContactCollection`，让我们创建一个`Backbone.View`，将这个集合渲染到 DOM 中。为了做到这一点，我们实际上会创建两个视图：一个视图用于集合中的每个项目，另一个视图用于集合本身。请记住，Backbone 视图将`Backbone.Model`与模板结合起来，以便将模型的属性呈现到 DOM 中。

我们将从视图开始，以渲染单个集合项（在本例中是单个`ContactModel`），称为`ContactItemView`：

```ts
import cm = require("../models/ContactModel");
export class ContactItemView extends Backbone.View<cm.ContactModel> {
    template: (properties?: any) => string;
    constructor(options?: any) {
        this.className = "contact-item-view";
        this.template = _.template(
            '<p><%= Name %> (<%= EmailAddress %>)</p>');
        super(options);
    }
    render(): ContactItemView {
        this.$el.html(this.template(this.model.attributes));
        return this;
    }
}
```

这段代码片段以我们附加到`cm`命名空间的`ContactModel`类的`import`开始。然后我们创建了一个名为`ContactItemView`的类，它`extends`自`Backbone.View`。与我们用于集合的通用语法类似，这个视图类也使用`ContactModel`作为其通用实例的类型。最后，我们导出这个类，使其作为 AMD 模块对我们的代码可用。

`ContactItemView`类有一个名为`template`的公共属性，它是一个返回字符串的函数。这个函数将模型的属性作为输入参数。`template`函数在构造函数的第二行被赋值为调用 Underscore 的`_.template( … )`函数的结果。如果我们仔细看一下这个模板函数中使用的字符串，我们会发现它是一个 HTML 字符串，它使用`<%= propertyName %>`语法将 Backbone 模型的属性注入到 HTML 中。我们还指定了 DOM 的`className`应该设置为`"contact-item-view"`。最后，我们使用传递给构造函数的`options`参数调用基类构造函数。

那么，我们在这里做了什么？我们创建了一个`Backbone.View`类，指定了它的`className`，并设置了视图应该用来将其模型呈现到 DOM 的`template`。我们需要的最后一段代码是`render`函数本身。这个`render`函数在一行中做了几件事情。首先，每个 Backbone 视图都有一个`$el`属性，它保存着 DOM 元素。然后我们在这个元素上调用`html`函数来设置它的 HTML，并传入`template`函数的调用结果。按照惯例，`render`函数总是返回`this`，以便调用类在调用`render`函数后使用流畅的语法。

### 注意

Backbone 可以与许多模板引擎一起使用，例如 Handlebars（[`handlebarsjs.com/`](http://handlebarsjs.com/)）和 Moustache（[`github.com/janl/mustache.js/`](https://github.com/janl/mustache.js/)）。在这个示例中，我们将坚持使用 Underscore 模板引擎。

现在我们已经定义了`Backbone.View`，我们可以为其编写一个简单的测试：

```ts
import cm = require("../../app/models/ContactModel");
import ccv = require("../../app/views/ContactItemView");
describe("/tscode/tests/views/ContactItemViewTests", () => {
    it("should generate html from template and model", () => {
        var contactModel = new cm.ContactModel(
            { Name: 'testName', EmailAddress: 'testEmailAddress' });

        var contactItemView = new ccv.ContactItemView(
            { model: contactModel });
        var html = contactItemView.render().$el.html();

        expect(html).toBe('<p>testName (testEmailAddress)</p>');
    });
});
```

这段代码片段以`ContactModel`和`ContactItemView`的导入开始。这个套件中只有一个测试，而且非常简单。首先，我们创建一个`ContactModel`的实例，在构造函数中设置`Name`和`EmailAddress`属性。然后我们创建`ContactItemView`类的一个实例，并将我们刚刚创建的模型作为构造函数的参数传递。请注意我们在构造函数中使用的语法：`{ model: contactModel }`。Backbone 视图可以以几种不同的方式构造，我们在构造时设置的属性-在这种情况下是`model`属性-通过我们的构造函数中的`super()`函数调用传递给基本的 Backbone 类。

我们的测试然后在`contactItemView`实例上调用`render`函数。请注意，我们直接引用了视图的`$el`属性，并调用了`html`函数-就好像它是一个 jQuery DOM 元素一样。这就是为什么所有`render`函数都应该返回`this`的原因。

我们的测试然后检查`render`函数的结果是否生成了我们根据模板和我们的模型属性所期望的 HTML。

## 使用 Text 插件

然而，在我们的视图中硬编码 HTML 将使我们的代码难以维护。为了解决这个难题，我们将使用一个名为 Text 的 Require 插件。Text 使用正常的 require 语法，只是使用`'text!"`前缀从站点加载文件以在我们的代码中使用。要通过 NuGet 安装此插件，只需键入：

```ts
Install-package RequireJS.Text

```

要使用 Text，我们首先需要在`require.config paths`属性中列出`text`，如下所示：

```ts
paths: {
    // existing code
    'text': '/Scripts/text'
},
```

然后我们可以修改我们在`TestConfig.ts`中对`require`的调用如下：

```ts
var CONTACT_ITEM_SNIPPET = "";
require(
    ['jasmine-boot',
     'text!/tscode/app/views/ContactItemView.html'],
    (jb, contactItemSnippet) => {
        CONTACT_ITEM_SNIPPET = contactItemSnippet;
        require(specs, () => {
            (<any>window).onload();
        });
    });
```

在这段代码片段中，我们创建了一个名为`CONTACT_ITEM_SNIPPET`的全局变量来保存我们的片段，然后我们在调用`require`时使用`'text!<path to html>'`语法来包含我们需要加载的 HTML 文件。同样，我们在`require`函数调用的数组中的每个项目都在我们的匿名函数中有一个对应的变量。

这样，Require 将加载在`/tscode/app/views/ContactItemView.html`找到的文本，并通过字符串作为`contactItemSnippet`参数传递给我们的函数。然后我们可以将全局变量`CONTACT_ITEM_SNIPPET`设置为这个值。然而，在运行这段代码之前，我们需要修改我们的`ContactItemView`来使用这个变量。

```ts
constructor(options?: any) {
    this.className = "contact-item-view";
    this.events = <any>{ 'click': this.onClicked };
    this.template = _.template(CONTACT_ITEM_SNIPPET);

    super(options);
}
```

在前面的代码中改变的行是使用全局变量`CONTACT_ITEM_SNIPPET`的值调用`_.template`函数，而不是使用硬编码的 HTML 字符串。

我们需要做的最后一件事是创建`ContactItemView.html`文件本身，如下所示：

```ts
<div class="contact-outer-div">
    <div class="contact-name-div">
        <%= Name %>
    </div>
    <div class="email-address-div">
        (<%= EmailAddress %>)
    </div>
</div>
```

这个 HTML 文件使用了与之前相同的`<%= propertyName %>`语法，但是现在我们可以很容易地扩展我们的 HTML，包括外部的`divs`，并为每个属性分配自己的 CSS 类，以便稍后进行一些样式设置。

然而，现在运行我们的测试将会破坏我们的`ContactItemViewTests`，因为我们使用的 HTML 已经被更改了。让我们现在修复这个破损的测试：

```ts
//expect(html).toBe('<p>testName (testEmailAddress)</p>');
expect(html).toContain('testName');
expect(html).toContain('testEmailAddress');
```

我们已经注释了有问题的行，并使用`.toContain`匹配器来确保我们的 HTML 已经正确地注入了模型属性，而不是寻找`html`字符串值的精确匹配。

## 渲染一个集合

现在我们有了一个用于渲染单个联系人项目的视图，我们需要另一个视图来渲染整个`ContactCollection`。为此，我们简单地为我们的集合创建一个新的`Backbone.View`，然后为集合中的每个项目创建一个新的`ContactItemView`实例，如下所示：

```ts
import cm = require("../models/ContactModel");
import civ = require("./ContactItemView");
export class ContactCollectionView extends Backbone.View<Backbone.Model> {
    constructor(options?: any) {
        super(options);
        _.bindAll(this, 'renderChildItem');
    }

    render(): ContactCollectionView {
        this.collection.each(this.renderChildItem);
        return this;
    }
    renderChildItem(element: Backbone.Model, index: number) {
        var itemView = new civ.ContactItemView( { model: element });
        this.$el.append(itemView.render().$el);
    }
}
```

我们从`ContactModel`和`ContactItemView`模块导入开始这个代码片段。然后我们创建了一个扩展了`Backbone.View`的`ContactCollectionView`，这次使用了一个基本的`Backbone.Model`来进行通用的语法。我们的`constructor`简单地通过`super`函数调用将它接收到的任何`options`传递给基本视图类。然后我们调用了一个 Underscore 函数命名为`bindAll`。Underscore 的`bindAll`函数是一个实用函数，用于在类函数中绑定`this`的作用域到正确的上下文。让我们稍微探索一下代码，以使这一点更清楚。

`render`函数将被`ContactCollectionView`的用户调用，并简单地为它的集合中的每个模型调用`renderChildItem`函数。`this.collection.each`接受一个参数，这个参数是一个回调函数，用于对集合中的每个模型进行调用。我们可以将这段代码写成如下形式：

```ts
render(): ContactCollectionView {
    this.collection.each(
        (element: Backbone.Model, index: number) => {
// include rendering code within this anonymous function
        }
    );
    return this;
}
```

这个版本的相同代码在`each`函数内部使用了一个匿名函数。然而，在我们之前的代码片段中，我们已经将`renderChildItem`写成了一个类函数，而不是使用匿名函数。由于 JavaScript 的词法作用域规则，这种细微的变化意味着`this`属性现在将指向函数本身，而不是类实例。通过使用`_.bindAll(this,'renderChildItem')`，我们已经将变量`this`绑定为所有对`renderChildItem`的调用的类实例。然后我们可以在`renderChildItem`函数内部使用`this`变量，`this.$el`将正确地作用于`ContactCollectionView`类的实例。

现在对这个`ContactCollectionView`类进行一些测试：

```ts
import cc = require("../../app/models/ContactCollection");
import cm = require("../../app/models/ContactModel");
import ccv = require("../../app/views/ContactCollectionView");
describe("/ts/views/ContactCollectionViewTests", () => {
    var contactCollection: cc.ContactCollection;
    beforeAll(() => {
        contactCollection = new cc.ContactCollection([
            new cm.ContactModel(
                { Name: 'testName1', EmailAddress: 'testEmail1' }),
            new cm.ContactModel(
                { Name: 'testName2', EmailAddress: 'testEmail2' })
        ]);
    });

    it("should create a collection property on the view", () => {
        var contactCollectionView = new ccv.ContactCollectionView({
            collection: contactCollection
        });
        expect(contactCollectionView.collection.length).toBe(2);
    });
});
```

在这个代码片段中，`import`和`beforeAll`函数应该很容易理解，所以让我们专注于实际测试的主体。首先，我们创建了一个`ContactCollectionView`实例，并通过构造函数中的`{ collection: contactCollection}`属性将这个`contactCollection`实例传递给它。使用单个项目的 Backbone 视图使用`{ model: <modelName> }`属性，而使用集合的视图使用`{ collection: <collectionInstance> }`属性。我们的第一个测试简单地检查内部的`collection`属性是否确实包含一个`length`为`2`的集合。

现在我们可以写一个测试，检查当我们在`ContactCollectionView`上调用`render`函数时，`renderChildItem`函数是否被调用：

```ts
it("should call render on child items", () => {
    var contactCollectionView = new ccv.ContactCollectionView({
        collection: contactCollection
    });
    spyOn(contactCollectionView, 'renderChildItem');
    contactCollectionView.render();

 expect(contactCollectionView.renderChildItem).toHaveBeenCalled();
});
```

这个测试创建了一个视图，就像我们之前看到的那样，然后在`renderChildItem`函数上创建了一个间谍。为了触发调用这个函数，我们在视图实例上调用`render`函数。最后，我们只是检查我们的间谍是否被调用了。

接下来，我们可以写一个快速测试，看看`render`函数生成的 HTML 是否包含我们集合模型的属性：

```ts
it("should generate html from child items", () => {
    var contactCollectionView = new ccv.ContactCollectionView({
        collection: contactCollection
    });
    var renderedHtml = contactCollectionView.render().$el.html();
    expect(renderedHtml).toContain("testName1");
    expect(renderedHtml).toContain("testName2");

});
```

这个测试与我们的`ContactItemView`渲染测试非常相似，但是使用了`ContactCollectionView`的`render`函数。

## 创建一个应用程序

有了这两个 Backbone 视图，我们现在可以构建一个简单的类来协调我们集合的加载和完整集合的渲染到 DOM 中：

```ts
import cc = require("tscode/app/models/ContactCollection");
import cm = require("tscode/app/models/ContactModel");
import civ = require("tscode/app/views/ContactItemView");
import ccv = require("tscode/app/views/ContactCollectionView");
export class ContactViewApp {
    run() {
        var contactCollection = new cc.ContactCollection();
        contactCollection.fetch(
            {
                success: this.contactCollectionLoaded,
                error: this.contactCollectionError
            });
    }

    contactCollectionLoaded(model, response, options) {
        var contactCollectionView = new ccv.ContactCollectionView(
            {
                collection: model
            });
        $("#mainContent").append(
            contactCollectionView.render().$el);
    }
    contactCollectionError(model, response, options) {
        alert(model);
    }
}
```

我们的代码从各种模块的导入开始。然后我们创建了一个名为`ContactViewApp`的类定义，在这个类中，有一个名为`run`的方法。这个`run`方法简单地创建了一个新的`ContactCollection`，并调用`fetch`来触发 Backbone 加载集合。这次调用`fetch`然后定义了一个`success`和一个`error`回调，每个都设置为类内部的相关函数。

当`ContactCollection`成功返回时，Backbone 将调用`contactCollectionLoaded`函数。在这个函数中，我们简单地创建一个`ContactCollectionView`，然后使用 jQuery 将通过`render`函数返回的 HTML 附加到 DOM 元素`"#mainContent"`上。

现在我们可以创建一个网页来把所有东西放在一起。我们的 HTML 页面的内容现在应该如下所示：

```ts
<!DOCTYPE html>
<html >
<head>
    <title>Contacts View</title>
    <link rel="stylesheet" type="text/css"
          href="/css/app.css">
    <script data-main="/tscode/app/AppConfig"
            type="text/javascript"
            src="img/require.js"></script>

</head>
<body>
    <div id="mainContent"></div>
</body>
</html>
```

这个页面与我们之前用于运行测试的页面非常相似。我们包含了一个`app.css`链接以允许一些样式，然后调用 Require 并使用一个新的配置文件，名为`/tscode/app/AppConfig`。我们还在 body 标签内有一个 id 为`mainContent`的`div`，用来容纳我们的`ContactViewApp`返回的渲染 HTML。现在我们需要创建我们的`AppConfig.ts`文件供 Require 使用，如下所示：

```ts
require.config(
    {
        baseUrl: "../../",
        paths: {
            'underscore': '/Scripts/underscore',
            'backbone': '/Scripts/backbone',
            'jquery': '/Scripts/jquery-2.1.1',
            'ContactViewApp': '/tscode/app/ContactViewApp',
            'text': '/Scripts/text'
        },
        shim: {
            underscore: {
                exports: '_'
            },
            backbone: {
                deps: ['underscore'],
                exports: 'Backbone'
            }
            ,ContactViewApp: {
                deps: ['backbone']
            }
        }
    }
);

var CONTACT_ITEM_SNIPPET = "";

require([
    'ContactViewApp',
    'text!/tscode/app/views/ContactItemView.html'
    ], (app, contactItemSnippet) => {

    CONTACT_ITEM_SNIPPET = contactItemSnippet;
    var appInstance = new app.ContactViewApp();
    appInstance.run();
});
```

在这段代码片段中要注意的第一件事是，我们现在已经在我们的`ContactViewApp`中包含了一个`paths`引用。`ContactViewApp`的相应`shim`条目指定它依赖于`backbone`。同样，我们有一个名为`CONTACT_ITEM_SNIPPET`的全局变量，然后我们调用`require`函数来加载我们的`ContactViewApp`类，以及 HTML 片段。还要注意，我们能够通过匿名函数中的`app`参数引用我们的`ContactViewApp`，并且通过`contactItemSnippet`参数引用 HTML。要运行应用程序，我们只需创建`ContactViewApp`类的一个实例，并调用`run`方法。

现在我们应该能够看到我们所有辛苦工作的结果了：

![创建一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_04.jpg)

使用 Require.js 运行的 Backbone 应用程序

## 使用 jQuery 插件

完成我们的应用程序，让我们使用一个名为**flip**的 jQuery 插件（[`lab.smashup.it/flip/`](http://lab.smashup.it/flip/)），触发一个动画来旋转或翻转项目的外部`div`。Flip 是一系列可以应用于我们应用程序元素的 jQuery 插件的典型代表。然而，在触发 Flip 动画之前，我们需要在`ContactItemView`中响应用户的点击事件，如下所示：

```ts
import cm = require("../models/ContactModel");

export class ContactItemView extends Backbone.View<cm.ContactModel> {
    template: (properties?: any) => string;
    constructor(options?: any) {
        this.className = "contact-item-view";
        this.events = <any>{ 'click': this.onClicked };
        this.template = _.template(CONTACT_ITEM_SNIPPET);
        super(options);
    }

    render(): ContactItemView {
        this.$el.html(this.template(this.model.attributes));
        return this;
    }

    onClicked() {
        alert('clicked : ' + this.model.Name);
    }
}
```

在这段代码片段中，我们现在在我们的`ContactItemView`类中添加了一个`onClicked`函数，简单地弹出一个`alert`。请注意，我们能够引用视图类的`model`属性，以便从该类实例创建时使用的底层`Backbone.Model`中读取属性。在`constructor`中，我们还将`this.events`设置为一个具有一个属性`'click'`的 JavaScript 对象。

`'click'`属性设置为我们的`onClicked`函数，并在`ContactItemView` DOM 元素接收到用户点击事件时调用。有了这个设置，每当我们在页面上点击渲染的元素时，我们将收到一个警报弹窗：

![使用 jQuery 插件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_05.jpg)

点击事件显示模型属性的警报弹窗

现在我们可以转向使用 Flip jQuery 插件。Flip 依赖于 jQuery 和 jQueryUI，因此我们需要从 NuGet 安装 jQueryUI，如下所示：

```ts
Install-package jQuery.UI.Combined

```

Flip 本身没有 NuGet 包，因此需要下载并以传统的方式将其包含在我们的项目中。Flip 也没有 DefinitelyTyped 定义，因此我们需要在项目中包含一个如下所示的定义：

```ts
interface IFlipOptions {
    direction: string;
    onBefore?: () => void;
    onAnimation?: () => void;
    onEnd?: () => void;
    speed?: number;
    color?: string;
    content?: string;
}
interface JQuery {
    flip(input: IFlipOptions): JQuery;
    revertFlip();
}
```

Flip 插件的声明文件非常简单，是从网站上的文档生成的。由于 Flip 是一个 jQuery 插件，它可以在通过`$( )`符号引用的任何 jQuery 对象上使用。因此，我们必须使用我们自己的`extend` JQuery 类型定义 - 因此我们创建了带有我们两个新函数`flip`和`revertFlip`的 jQuery 接口。Flip 的输入已被定义为`IFlipOptions`接口，根据网站文档构建。

要在 Require 中加载此库，我们修改对`require.config`的调用如下：

```ts
require.config(
    {
        baseUrl: "../../",
        paths: {
            'underscore': '/Scripts/underscore',
            'backbone': '/Scripts/backbone',
            'jquery': '/Scripts/jquery-2.1.1',
            'ContactViewApp': '/tscode/app/ContactViewApp',
            'text': '/Scripts/text',
            'jqueryui': '/Scripts/jquery-ui-1.11.2',
            'jqueryflip' : '/Scripts/jquery.flip'
        },
        shim: {
            underscore: {
                exports: '_'
            },
            backbone: {
                deps: ['underscore'],
                exports: 'Backbone'
            }
            ,jqueryui: {
                deps: ['jquery']
            }
            ,jqueryflip: {
                deps: ['jqueryui'],
                exports: '$'
            }
            ,ContactViewApp: {
                deps: ['backbone'
                    , 'jqueryflip'
                ]
            }
        }
    }
);
```

在这里，我们已经向我们的路径对象添加了两个条目：`jqueryui`和`jqueryflip`。然后，我们添加了相应的`shim`条目并指定了相关的依赖关系。这里需要注意的一行是`jqueryflip`上的`exports`属性。我们指定它必须导出到`$`符号。这是默认的 jQuery 选择器符号，所有 jQuery 插件必须导出到`$`符号，以便在使用 Require 时正确定义。我们对代码的最终更改是在`ContactItemView`的点击事件上使用`flip`函数，如下所示：

```ts
onClicked() {
    this.$el.flip({
        direction: 'tb',
        speed : 200
    });
}
```

在这里，我们引用了`Backbone.View`中的`$el`元素，这是 jQuery 选择器的简写语法。然后我们调用`flip`函数，并指定从上到下翻转，持续 200 毫秒。现在运行我们的页面，点击联系人元素将触发翻转动画：

![使用 jQuery 插件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_07_06.jpg)

Flip.js 在操作中翻转 div 元素

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。

# 摘要

在本章中，我们已经研究了使用模块 - 包括 CommonJs 和 AMD。我们探讨了在 Node 应用程序中使用的 CommonJS 模块，并讨论了在 TypeScript 中创建和使用这些模块。然后，我们转向基于浏览器的模块，并探讨了与 Require 相关的 AMD 编译的使用。我们构建了一个非常简单的基于 Backbone 的应用程序，包括 Jasmine 单元测试，然后研究了在 Require 中使用 Text 插件。我们还整合了一个名为 Flip 的第三方 jQuery 插件，以在用户界面上提供一些动画。在下一章中，我们将探讨一些面向对象的编程原则，并研究依赖注入和领域事件。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第八章：使用 TypeScript 进行面向对象编程

1995 年，**四人帮**（**GoF**）出版了一本名为*设计模式：可复用面向对象软件的元素*的书。在这本书中，作者 Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 描述了许多经典的软件设计模式。这些模式提供了常见软件问题的简单而优雅的解决方案。如果你从未听说过工厂模式、组合模式、观察者模式或单例模式等设计模式，那么强烈建议阅读这本 GoF 书籍。

GoF 提出的设计模式已经在许多不同的编程语言中复制，包括 Java 和 C#。Mark Torok 甚至将这些模式移植到了 TypeScript 中，他的 GitHub 存储库可以在[`github.com/torokmark/design_patterns_in_typescript`](https://github.com/torokmark/design_patterns_in_typescript)找到。我们已经在第三章*接口、类和泛型*中探讨了其中的一个模式，即工厂设计模式，Mark 的工作为 TypeScript 中的所有 GoF 模式提供了快速简单的参考实现。

Simon Timms 还出版了一本名为*精通 JavaScript 设计模式*的书，*Packt Publishing*（[`www.packtpub.com/application-development/mastering-javascript-design-patterns`](https://www.packtpub.com/application-development/mastering-javascript-design-patterns)），该书为读者逐一介绍了这些模式，何时使用它们以及如何使用它们。

在本章中，我们不会涵盖标准的 GoF 设计模式，而是看一看另外两种流行的设计模式以及它们如何在 TypeScript 中实现。我们将讨论使用服务定位器模式进行依赖注入，然后看看这些技术如何用于构建领域事件模式的实现。

# 按接口编程

四人帮坚持的主要观念之一是，程序员应该“按接口编程，而不是按实现编程”。这意味着程序是使用接口作为对象之间定义的交互来构建的。通过按接口编程，客户对象不知道其依赖对象的内部逻辑，并且更具有抵抗变化的能力。

TypeScript 语言带来了`interface`关键字，使我们能够以比标准 JavaScript 更简单的方式针对接口编写面向对象的代码。不过，请记住，接口只是 TypeScript 的概念，会在生成的 JavaScript 中被编译掉。

请注意，许多其他语言都有能够询问对象以查看它们实现了哪些接口的概念，这个过程称为**反射**。

# SOLID 原则

“按接口编程”原则的延伸是所谓的 SOLID 设计原则，基于 Robert Martin 的思想。这是五个不同编程原则的首字母缩写，无论何时讨论面向对象编程，都值得一提。单词 SOLID 中的每个字母都与一个面向对象原则相关，如下所示：

+   S：单一职责

+   O：开闭原则

+   L：里氏替换

+   I：接口隔离

+   D：依赖反转

## 单一职责

单一职责原则的理念是，一个对象应该只有一个职责，或者说只有一个存在的理由。换句话说，做一件事，并且做好。我们在上一章中已经看到了这个原则的例子，在我们使用 Backbone 时。Backbone 模型类用于表示单个模型。Backbone 集合类用于表示这些模型的集合，Backbone 视图类用于渲染模型或集合。

## 开闭原则

开闭原则的理念是，一个对象应该对扩展开放，但对修改关闭。换句话说，一旦为一个类设计了接口，随着时间的推移对这个接口的更改应该通过继承来实现，而不是直接修改接口。

请注意，如果您正在编写通过 API 由第三方使用的库，则此原则至关重要。对 API 的更改应仅通过新的、有版本的发布进行，并且不应破坏现有的 API 或接口。

## 里斯科夫替换

里斯科夫替换原则规定，如果一个对象是从另一个对象派生的，那么这些对象可以相互替换而不会破坏功能。虽然这个原则似乎很容易实现，但在处理与更复杂类型相关的子类型规则时，比如对象列表或对象上的操作时，情况可能会变得非常复杂——这些通常出现在使用泛型的代码中。在这些情况下，引入了变异的概念，对象可以是协变的、逆变的或不变的。我们不会在这里讨论变异的细节，但在编写库或使用泛型的代码时，请记住这个原则。

## 接口分离

接口分离原则的理念是，许多接口比一个通用接口更好。如果我们将这个原则与单一责任原则联系起来，我们将开始将我们的接口视为谜题的小部分，这些小部分将被组合在一起，以创建更广泛的应用程序功能。

## 依赖反转

依赖反转原则规定，我们应该依赖于抽象（或接口），而不是具体对象的实例。同样，这与“根据接口而不是实现编程”的原则相同。

# 构建服务定位器

服务定位器模式的理念是，应用程序的某些区域可以被分解为服务。每个服务都应遵循我们的 SOLID 设计原则，并提供一个作为服务 API 的小外部接口。应用程序使用的每个服务都会在服务定位器中注册。当应用程序需要特定的信息或功能时，它可以查询这个服务定位器，以找到基于服务接口的正确服务。

## 问题空间

在上一章中，我们探讨了 Backbone，我们的应用程序被分解为模型、集合和视图。除了这些元素之外，我们还有一个应用程序类来协调通过集合加载数据，并使用视图呈现此集合。一旦我们构建了应用程序类，谜题的最后一块就是组合`require.config`对象，以协调加载我们的 AMD 模块、应用程序中需要的任何 HTML 和我们的 jQuery 插件。

如果我们看一下应用程序加载哪些文件的视觉表示，我们会得到以下内容：

![问题空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_01.jpg)

应用对象依赖树

我们从一个名为`ContactViewApp.html`的 HTML 页面开始，这是我们应用程序的主入口页面，将提供给 Web 浏览器。然后这个 HTML 页面加载 Require 库，Require 库又加载包含`require.config`部分的`AppConfig.ts`文件。然后`require.config`部分指示 Require 从`/Scripts/`目录加载各种脚本，以及通过 Text 插件加载一小段 HTML。一旦 Require 加载了所有文件，`AppConfig.ts`文件的最后一部分加载`ContactViewApp.ts`，然后加载我们的`ContactCollection.ts`和`ContactCollectionView.ts`文件。然后这两个文件指示 Require 分别加载名为`ContactModel.ts`和`ContactItemView.ts`的模块文件。

如果我们更仔细地看一下这个层次结构，很容易想象在一个大型应用程序中，我们会有大量的集合、模型、视图和项目视图。可能我们正在加载集合的集合，以及包含子视图的视图，其中包含进一步的子视图。每个这些视图都需要通过文本插件加载一些 HTML，以使用我们的模板机制。

让我们更仔细地看一下在我们之前的例子中如何加载和使用 HTML 片段：

![问题空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_02.jpg)

使用全局变量的依赖树

在这个图中，我们可以看到我们通过文本插件在`AppConfig.ts`文件中加载了一个 HTML 片段，然后将其存储到名为`CONTACT_ITEM_SNIPPET`的全局变量中。唯一使用这个全局变量的代码是`ContactItemView`类本身。

使用全局变量违反了我们的依赖反转原则，因为我们在编程时针对一个全局变量的具体实例，而不是一个接口。这个全局变量也可能被任何正在运行的代码无意中改变，这可能导致我们的视图停止工作。当运行我们的测试套件时，我们遇到的另一个问题是，更改原始的 HTML 模板会破坏一些单元测试。虽然我们能够稍微修改测试以通过，但这个破损的测试突显出我们在某个地方违反了开闭原则。

## 创建一个服务

我们将分两部分解决使用全局变量存储 HTML 片段的问题。

首先，让我们定义一个服务来替换我们的全局变量 - `SnippetService`。这个服务将有一个非常简单的接口，只负责两件事：存储 HTML 片段和检索 HTML 片段。

其次，我们需要一种机制来获取这个`SnippetService`，在我们存储片段的代码点（在`AppConfig.ts`中）和使用片段的代码点（在`ContactItemView.ts`中）。我们稍后将在这两个接触点使用服务定位器，但现在，让我们为我们的片段服务设计一个设计。

引入`SnippetService`会改变我们的依赖图如下：

![创建一个服务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_03.jpg)

使用服务存储 HTML 片段的依赖树

我们可以看到，我们现在已经抽象出了对全局变量的使用。我们仍然有一个全局区域来存储这些 HTML 片段，即片段存储区，但我们现在是针对一个接口编程 - `SnippetService`提供的接口，而不是针对一个具体的实现。我们的应用程序现在受到了对这些 HTML 片段的内部存储的任何更改的保护。例如，我们可能决定从使用 HTML 文件改为在数据库中存储 HTML 片段。在这种情况下，只需要修改`SnippetService`的内部，我们的代码就可以继续运行而无需更改。

显然，我们需要一种键来允许我们存储多个片段，但`SnippetService`是否应该负责定义这个键呢？考虑单一职责原则。`SnippetService`是否真的负责管理与片段相关的键？换句话说，它需要添加或删除这些键吗？并不是真的。一个更小的枚举类在这里会非常有用，并且更倾向于许多较小的接口而不是一个通用接口 - 考虑接口隔离。

考虑到这些事情，我们可以定义`SnippetService`的接口如下：

```ts
enum SnippetKey {
    CONTACT_ITEM_SNIPPET,
    OTHER_SNIPPET,
}

interface ISnippetService {
    storeSnippet(key: SnippetKey, value: string): void;
    retrieveSnippet(key: SnippetKey): string;
}
```

首先，我们定义了一个名为`SnippetKey`的`enum`，用于存储`SnippetService`要使用的所有键。其次，我们定义了实际`SnippetService`的接口，名为`ISnippetService`，它有两个函数。第一个函数将是一个存储片段的方法，名为`storeSnippet`。这个函数有两个参数，第一个是`SnippetKey`枚举值，第二个参数当然是 HTML 片段本身。类似地，第二个函数，名为`retrieveSnippet`，使用一个`SnippetKey`参数来检索 HTML 片段。

现在我们已经定义了一个接口，我们可以创建`SnippetService`类的结构：

```ts
class SnippetService implements ISnippetService {
    public storeSnippet(key: SnippetKey, value: string) {
    }
    public retrieveSnippet(key: SnippetKey) {
        return "";
    }
}
```

在这里，我们有一个名为`SnippetService`的类，它实现了我们的`ISnippetService`接口。我们已经创建了接口中定义的两个方法，但尚未提供实现。我们将利用这个机会遵循 TDD 原则，在编写使测试通过的代码之前编写一个失败的单元测试。我们的单元测试如下：

```ts
describe("/tscode/tests/services/SnippetServiceTests.ts", () => {
    it("should store a snippet", () => {
        var snippetService = new SnippetService();
        snippetService.storeSnippet(
            SnippetKey.CONTACT_ITEM_SNIPPET, "contact_snippet");
        expect(
            snippetService.retrieveSnippet(
                SnippetKey.CONTACT_ITEM_SNIPPET)
        ).toBe("contact_snippet");
    });
});
```

在这个测试中，我们只是创建了一个`SnippetService`的实例，使用`SnippetKey.CONTACT_ITEM_SNIPPET`作为键存储了一个片段，然后使用相同的键调用`retrieveSnippet`，验证返回的字符串值。请记住，这是一个模拟测试，在真实应用中，`storeSnippet`调用将在应用初始化期间发生，而`retrieveSnippet`调用将在稍后的阶段发生。

现在让我们完善`SnippetService`，使测试通过：

```ts
class SnippetService implements ISnippetService {
    private snippetArray: string[] = new Array();
    public storeSnippet(key: SnippetKey, value: string) {
        this.snippetArray[key] = value;
    }
    public retrieveSnippet(key: SnippetKey) {
        if (!this.snippetArray[key]) {
            throw new Error(
                "SnippetService no snippet with key :" + key);
        }
        return this.snippetArray[key];
    }
}
```

我们的`SnippetService`类现在有一个名为`snippetArray`的内部字符串数组，标记为`private`，它将保存我们的 HTML 片段值。我们的`storeSnippet`和`retrieveSnippet`函数现在只是简单地从这个数组中存储或检索值。有了这段代码，我们的测试现在将通过，我们简单的`SnippetService`完成了。

# 依赖解析

到目前为止，我们已经重构了我们的代码，使其依赖于接口而不是具体对象。这一切都很好，但引出了一个问题：“我们如何获得一个接口？”- 或者更正确地说 - “我们如何获得当前实现这个接口的具体类？”这是依赖注入器试图回答的基本问题。

类可以获得实现接口的另一个类的方式有很多种。

## 服务定位

如果类本身根据接口请求一个具体对象，那么这个过程称为“**服务定位**”。换句话说，类使用注册表或助手来定位它需要的服务。您还可以将这种技术描述为“依赖请求”。一个中央注册表保存了所有已注册类与它们各自接口的查找表。当接口被请求时，服务定位器简单地查找其表中存储的接口对应的类实例，并从其注册表返回对象。

## 依赖注入

如果创建类的实例的行为可以交给某种框架处理，那么这个框架可以找出类需要什么接口，并在类实例化期间“注入”这些依赖关系。这种依赖注入也称为**装配**。在这种情况下，装配器类或框架需要能够查询对象以找出它依赖的接口。不幸的是，在 JavaScript 或 TypeScript 中我们没有这种能力，因为所有接口都被编译掉了。因此，我们不能单独使用 TypeScript 接口来实现依赖注入。如果我们要在 TypeScript 或 JavaScript 中实现依赖注入，我们需要一种命名约定来告诉装配器框架我们需要一个具体对象来替换接口。

依赖注入也被称为控制反转，因为我们把类的创建和依赖项的解析控制权交给了第三方。当我们收到类的实例时，所有的服务或依赖项都已经被“神奇”地填充进去了。

## 服务定位与依赖注入

服务定位模式的想法最早是由马丁·福勒在 2004 年左右提出的，在一篇名为《控制反转容器和依赖注入模式》的博客中（[`martinfowler.com/articles/injection.html`](http://martinfowler.com/articles/injection.html)）。然而，在他的书《.NET 中的依赖注入》中，马克·西曼认为服务定位模式实际上是一种反模式。

马克对马丁最初的想法是，使用服务定位很容易引入运行时错误，或者误解特定类的使用。这是因为找出一个类使用了哪些服务意味着要阅读整个类。他认为更好的使用依赖注入的方法是，在类的构造函数中列出所有的依赖项，并让服务定位器在类构造过程中解析每个依赖项。马克的大部分例子似乎都围绕着构建和使用 API，其中特定类的内部不能简单地从代码中读取，并且在不知道一个类依赖于哪些服务的情况下使用一个类很容易引起运行时错误。

尽管他的想法确实是正确的，但是解决这个问题的方法都与.NET 语言相关，而这在 JavaScript 中是不可用的，这就是反射。反射是程序在运行时询问对象自身信息的能力，比如它有哪些属性，它实现或期望实现哪些接口。尽管 TypeScript 提供了接口关键字，并对这些接口进行了编译时检查，但所有接口都在生成的 JavaScript 中被编译掉了。

这给我们带来了一个严重的问题。如果一个类依赖于一个接口，我们不能在运行时使用这个接口来查找接口的具体实现，因为在运行时，这个接口根本不存在。

Angular 使用命名约定（以`$`前缀）来提供依赖注入功能。这已经相当成功，尽管在使用缩小程序时会有一些注意事项和一些解决方法。Angular 2.0 也通过提供自定义语法来解决这个问题，以表示需要注入依赖项的位置。其他 JavaScript 框架，如 ExtJs，提供了使用全局创建例程来创建对象的机制，然后允许框架注入依赖项。不幸的是，这种 ExtJs 技术与 TypeScript 语法不太兼容（参见第五章，“第三方库”中我们讨论了 ExtJs）。

此外，如果我们不使用 Angular、Angular 2.0、ExtJs 或任何其他框架，那么在标准 JavaScript 中依赖注入就略微超出了我们的能力。另一方面，服务定位是可以实现的，并且结合 TypeScript 接口，可以为我们带来依赖项解析的所有好处，因此也可以实现模块化编程。

我们也可以做出妥协，以纳入马克建议的想法，并将我们的服务定位限制在对象构造函数中。在编写使用服务定位的库时，我们需要清楚地记录特定类有哪些依赖项，以及它们需要如何注册。即使像 StructureMap 这样的流行.NET 依赖注入框架仍然允许使用服务定位技术，尽管它们正在被弃用。

因此，为了本书的目的，让我们探讨如何编写一个简单的服务定位器，并在我们的代码中使用它来构建一个更模块化的应用程序，并将模式与反模式的论点留给那些具有自然实现依赖注入功能的语言。

# 一个服务定位器

让我们回到我们问题的核心：给定一个接口，我们如何获得当前实现它的类的具体实现？

在第三章, *接口，类和泛型*，我们编写了一个名为`InterfaceChecker`的通用类，它对类进行了运行时评估，以检查它是否实现了一组特定的方法和属性。这个`InterfaceChecker`背后的基本思想是，如果我们提供了一个列出了接口的预期属性和方法的元数据类，我们就可以在运行时根据这些元数据来查询一个类。如果类具有所有必需的属性和方法，那么就说它实现了这个接口。

因此，我们现在有了一个机制——在运行时——来确保一个类实现了一个接口：注意，不是 TypeScript 接口，而是元数据定义的接口。如果我们扩展这个想法，并为我们的每个元数据接口提供一个唯一的名称，我们就有了“命名接口”的概念。只要这些接口名称在我们的应用程序中是唯一的，我们现在就有了一个在运行时查询一个类是否实现了命名接口的机制。

如果一个类实现了一个命名接口，我们可以使用注册表来存储该类的实例与其命名接口。任何需要实现这个命名接口的类实例的其他代码，只需查询注册表，提供接口名称，注册表就能返回类实例。

只要我们确保我们的 TypeScript 接口与命名接口定义匹配，我们就可以开始了。

## 命名接口

回到第三章, *接口，类和泛型*，我们编写了一个名为`IInterfaceChecker`的接口，我们可以将其用作元数据的标准模板。让我们更新这个接口，并给它一个必需的`className`属性，这样我们就可以将其用作命名接口：

```ts
interface IInterfaceChecker {
    methodNames?: string[];
    propertyNames?: string[];
    className: string;
}
```

我们仍然有可选的`methodNames`和`propertyNames`数组，但现在每个实现这个接口的类也将需要一个`className`属性。

因此，考虑到以下 TypeScript 接口：

```ts
interface IHasIdProperty {
    id: number;
}
```

我们的命名接口元数据类匹配这个 TypeScript 接口将如下所示：

```ts
class IIHasIdProperty implements IInterfaceChecker {
    propertyNames: string[] = ["id"];
    className: string = "IIHasIdProperty";
}
```

这个`IHasIdProperty`接口有一个名为`id`的属性，类型为`number`。然后我们创建一个名为`IIHasIdProperty`的类，作为一个命名接口定义。这个类实现了我们更新的`IInterfaceChecker`接口，因此必须提供一个`className`属性。`propertyNames`属性有一个名为`id`的单个数组条目，并将被我们的`InterfaceChecker`类用来与我们的 TypeScript 接口的`id`属性进行匹配。

注意这个类的命名约定——它与接口的名称相同，但添加了额外的`I`。这个双`I`约定将帮助我们将 TypeScript 接口命名为`IHasIdProperty`与其`IIHasIdProperty`元数据命名接口类联系起来。

现在，我们可以创建一个正常的 TypeScript 类，实现`IHasIdProperty`TypeScript 接口，如下所示：

```ts
class PropertyOne implements IHasIdProperty  {
    id = 1;
}
```

我们现在已经有了所有的要素来开始构建一个服务定位器：

+   一个名为`IHasIdProperty`的 TypeScript 接口。这将提供对实现这个接口的类的编译时类型检查。

+   一个名为`IIHasIdProperty`的命名接口或元数据类。这将提供对类的运行时类型检查，并且还有一个唯一的名称。

+   一个实现了 TypeScript 接口`IHasIdProperty`的类。这个类将通过运行时类型检查，并且这个类的实例可以被注册到我们的服务定位器中。

## 注册类与命名接口对应

有了这些元数据类，我们现在可以创建一个中央存储库，作为服务定位器。这个类有用于注册类以及解析接口的静态函数：

```ts
class TypeScriptTinyIoC {
    static registeredClasses: any[] = new Array();
    public static register(
        targetObject: any,
        targetInterface: { new (): IInterfaceChecker; }): void {
    }

    public static resolve(
        targetInterface: { new (): IInterfaceChecker; }): any {
    }
    public static clearAll() {}
}
```

这个名为`TypeScriptTinyIoC`的类有一个名为`registeredClasses`的静态属性，它是一个`any`类型的数组。这个数组本质上是我们的注册表。由于我们不知道要在这个数组中存储什么类型的类，所以在这种情况下使用`any`类型是正确的。

这个类提供了两个主要的静态函数，名为`register`和`resolve`。`register`函数以`targetObject`作为第一个参数，然后是一个命名接口的类定义，即从`IInterfaceChecker`派生的类。注意`targetInterface`参数的语法，它与我们在第三章中使用的泛型语法相同，用于表示类定义。

如果我们看一下它们的使用示例，就更容易理解这些函数签名，所以让我们写一个快速测试：

```ts
it("should resolve instance of IIProperty to PropertyOne", () => {
    var propertyInstance = new PropertyOne();
    TypeScriptTinyIoC.register(propertyInstance, IIHasIdProperty);

    var iProperty: IHasIdProperty = 
        TypeScriptTinyIoC.resolve(IIHasIdProperty);
    expect(iProperty.id).toBe(1);
});
```

这个测试首先创建了一个`PropertyOne`类的实例，该类实现了`IHasIdProperty`接口。这个类是我们想要注册的类。然后测试调用`TypeScriptTinyIoC`的`register`函数，有两个参数。第一个参数是类实例本身，第二个参数是与命名接口`IIHasIdProperty`相关的类定义。我们之前已经见过这种语法，当我们讨论使用泛型创建类的实例时，但它的签名也适用于非泛型函数。

如果不使用`targetInterface: { new (): IInterfaceChecker; }`的签名，我们将不得不如下调用这个函数：

```ts
TypeScriptTinyIoC.register(propertyOneInstance,
    new IIHasIdProperty());
```

但是有了这个签名，我们可以将`IIHasIdProperty`命名接口类的创建推迟到`register`函数中，并且可以删除如下的新语法：

```ts
TypeScriptTinyIoC.register(propertyOneInstance, IIHasIdProperty);
```

然后我们的测试调用`TypeScriptTinyIoC`的`resolve`函数，并再次传入我们命名接口的类定义作为查找键。最后，我们检查返回的类是否实际上是我们最初注册的`PropertyOne`类的实例。

在这个阶段，我们的测试将会失败，所以让我们完善`TypeScriptTinyIoC`类，从`register`函数开始：

```ts
public static register(
    targetObject: any,
    targetInterface: { new (): IInterfaceChecker; })
{
    var interfaceChecker = new InterfaceChecker();
    var targetClassName = new targetInterface();
    if (interfaceChecker.implementsInterface(
        targetObject, targetInterface)) {
        this.registeredClasses[targetObject.className]
            = targetObject;
    } else {
        throw new Error(
            "TypeScriptTinyIoC cannot register instance of "
            + targetClassName.className);
    }
}
```

这个`register`函数首先创建了一个`InterfaceChecker`类的实例，然后通过`targetInterface`参数创建了传入的类定义的实例。这个`targetInterface`是命名接口或元数据类。然后我们调用`interfaceChecker`的`implementsInterface`函数来确保`targetObject`实现了`targetInterface`描述的接口。如果通过了这个检查，我们就使用`className`属性作为键将其添加到我们的内部数组`registeredClasses`中。

再次使用我们的`InterfaceChecker`给我们提供了运行时类型检查，这样我们就可以确保我们注册的任何类实际上都实现了正确的命名接口。

现在我们可以如下完善`resolve`函数：

```ts
public static resolve(
    targetInterface: { new (): IInterfaceChecker; })
{
    var targetClassName = new targetInterface();
    if (this.registeredClasses[targetClassName.className]) {
        return this.registeredClasses[targetClassName.className];
    } else {
        throw new Error(
            "TypeScriptTinyIoC cannot find instance of "
            + targetClassName.className);
    }
}
```

这个`resolve`函数只有一个参数，即我们命名接口的定义。同样，我们使用了之前见过的可实例化的语法。这个函数简单地创建了`targetInterface`类的一个实例，然后使用`className`属性作为`registeredClasses`数组的键。如果找到了条目，我们就简单地返回它；否则，我们抛出一个错误。

我们`TypeScriptTinyIoC`类上的最后一个函数是`clearAll`函数，它主要用于测试，用于清除我们的注册类数组：

```ts
public static clearAll() {
    this.registeredClasses = new Array();
}
```

我们的服务定位器现在已经完成。

## 使用服务定位器

现在让我们更新我们的依赖树，看看`TypeScriptTinyIoC`服务定位器将如何被使用：

![使用服务定位器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_04.jpg)

带有服务定位器模式的依赖图

我们的`AppConfig.ts`代码现在将创建一个`SnippetService`的实例，并使用命名接口`IISnippetService`将其注册到`TypeScriptTinyIoC`中。然后我们将更新`ContactItemView`的构造函数，以从注册表中解析`IISnippetService`的实例。这样，我们现在是编程到一个接口——`IISnippetService`接口。我们在注册服务到服务定位器时使用这个命名接口，以及在以后解析服务时再次使用。然后，我们的`ContactItemView`要求服务定位器给我们实现`IISnippetService`接口的当前对象。

为了实现这个改变，我们首先需要一个命名接口来匹配`ISnippetService` TypeScript 接口。作为一个复习，我们的`ISnippetService`定义如下：

```ts
interface ISnippetService {
    storeSnippet(key: SnippetKey, value: string): void;
    retrieveSnippet(key: SnippetKey): string;
}
```

根据我们的命名规则，我们的命名接口定义将被称为`IISnippetService`，如下所示：

```ts
class IISnippetService implements IInterfaceChecker {
    methodNames: string[] = ["storeSnippet", "retrieveSnippet"];
    className: string = "IISnippetService";
}
```

请注意，`methodNames`数组包含两个与我们的 TypeScript 接口匹配的条目。按照惯例，我们还指定了一个`className`属性，这样我们就可以将这个类用作命名接口。使用类的名称（`IISnippetService`）作为`className`属性也将确保一个唯一的名称，因为 TypeScript 不允许使用相同名称定义多个类。

现在让我们专注于我们的测试套件。记住我们的`TestConfig.ts`文件几乎与我们的`AppConfig.ts`文件相同，但是它启动了 Jasmine 测试套件而不是运行我们的应用程序。我们将修改这个`TestConfig.ts`文件，包括我们的`SnippetService`和`TypeScriptTinyIoC`，如下所示。

```ts
require.config(
    {
        // existing code 
        paths: {
            // existing code
            'tinyioc': '/tscode/app/TypeScriptTinyIoC',
            'snippetservice': '/tscode/app/services/SnippetService'
        },
        shim: {
          // existing code
        }
    }
);

require(
    ['jasmine-boot', 'tinyioc', 'snippetservice',
    'text!/tscode/app/views/ContactItemView.html'],
     (jb, tinyioc, snippetservice, contactItemSnippet) => {
        var snippetService = new SnippetService();
        snippetService.storeSnippet( SnippetKey.CONTACT_ITEM_SNIPPET, contactItemSnippet);
        TypeScriptTinyIoC.register(snippetService, IISnippetService);
        require(specs, () => {
             (<any>window).onload();
        });
    }
);
```

首先，我们在路径属性中包含了对`tinyioc`和`snippetservice`的条目，以确保 Require 会从指定目录加载我们的文件。然后我们更新对 require 函数的调用，将`tinyioc`和`snippetservice`都包含在两个参数中。我们的匿名函数然后创建了`SnippetService`的一个新实例，并使用`CONTACT_ITEM_SNIPPET`键存储由 Text 加载的片段。然后我们使用命名接口`IISnippetService`将这个`SnippetService`的实例注册到`TypeScriptTinyIoC`中。如果我们现在运行测试套件，应该会有一些失败的测试：

![使用服务定位器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_05.jpg)

单元测试失败

这个失败是因为`ContactItemView`仍然引用`CONTACT_ITEM_SNIPPET`全局变量。现在让我们修改这个视图的构造函数如下：

```ts
constructor(options?: any) {
    var snippetService: ISnippetService =
        TypeScriptTinyIoC.resolve(IISnippetService);
    var contactItemSnippet = snippetService.retrieveSnippet(
        SnippetKey.CONTACT_ITEM_SNIPPET);

    this.className = "contact-item-view";
    this.events = <any>{ 'click': this.onClicked };
    this.template = _.template(contactItemSnippet);

    super(options);
}
```

构造函数的第一行调用`TypeScriptTinyIoC.resolve`函数，使用命名接口`IISnippetService`的定义。这个调用的结果存储在`snippetService`变量中，它的类型与`ISnippetService`接口强类型绑定。这就是服务定位器模式的本质：我们编程到一个接口（`ISnippetService`），并且通过我们的服务定位器定位这个接口。一旦我们有了提供接口的类的实例，我们就可以简单地使用所需的键调用`retrieveSnippet`来加载我们的模板。

现在我们已经更新并修复了我们的测试，我们只需要以与我们修改`TestConfig.ts`文件相同的方式修改我们的`AppConfig.ts`文件。

## 可测试性

现在我们正在根据一个定义好的接口进行编程，我们可以开始以不同的方式测试我们的代码。在一个测试中，我们现在可以用另一个在调用`retrieveSnippet`时抛出错误的服务替换实际的`SnippetService`。对于这个测试，让我们创建一个名为`SnippetServiceRetrieveThrows`的类，如下所示：

```ts
class SnippetServiceRetrieveThrows implements ISnippetService {
    storeSnippet(key: SnippetKey, value: string) {}

    retrieveSnippet(key: SnippetKey) {
        throw new Error("Error in retrieveSnippet");
    }
}
```

这个类可以注册到`IISnippetService`命名接口，因为它正确实现了 TypeScript 接口`ISnippetService`。然而，`retrieveSnippet`函数只是抛出一个错误。

然后，我们的测试可以轻松注册此服务的版本，然后创建一个`ContactItemView`类的实例，以查看如果调用`retrieveSnippet`函数失败会发生什么。请注意，我们并没有以任何方式修改我们的`ContactItemView`类 - 我们只是针对`IISnippetService`命名接口注册了一个不同的类。在这种情况下，我们的测试将如下：

```ts
beforeAll(() => {
    var errorService = new SnippetServiceRetrieveThrows();
    TypeScriptTinyIoC.register(errorService, IISnippetService);
});

it("should handle an error on constructor", () => {
    var contactModel = new cm.ContactModel(
      { Name: 'testName', EmailAddress: 'testEmailAddress' });

    var contactItemView = new ccv.ContactItemView(
      { model: contactModel });
    var html = contactItemView.render().$el.html();
    expect(html).toContain('error');

});
```

在这个测试中，我们在`beforeAll`函数中注册了我们抛出版本的`SnippetService`，然后测试了`ContactItemView`的渲染能力。运行此测试将在`ContactItemView`调用`retrieveSnippet`时引发错误。为了使此测试通过，我们需要更新`ContactItemView`以优雅地处理错误：

```ts
var contactItemSnippet = "";
var snippetService: ISnippetService =
    TypeScriptTinyIoC.resolve(IISnippetService);
try {
    contactItemSnippet = snippetService.retrieveSnippet(
        SnippetKey.CONTACT_ITEM_SNIPPET);
} catch (err) {
    contactItemSnippet = 
     "There was an error loading CONTACT_ITEM_SNIPPET";
}
```

在这里，我们只是用`try` `catch`块包围了对`retrieveSnippet`的调用。如果发生错误，我们将修改片段为标准错误消息。通过放置这样的测试，我们进一步巩固了我们的代码，以便处理各种错误。

到目前为止，我们取得了什么成就呢？我们已经建立了一个服务来提供 HTML 片段，并且我们已经建立了一个服务定位器，可以注册此服务的实例，以便在整个代码中使用。通过在测试期间注册不同版本的此服务，我们还可以通过模拟常见错误来进一步防止错误，并在这些情况下测试我们的组件。

# 域事件模式

大多数 JavaScript 框架都有事件总线的概念。事件总线只是一种将事件发布到全局总线的方法，以便订阅这些事件的应用程序的其他部分将接收到消息，并能够对其做出反应。使用基于事件的架构有助于解耦我们的应用程序，使其更具有适应变化的能力，并更易于测试。

域事件是特定于我们应用程序域的事件。例如“当发生错误时，将其记录到控制台”，或者“当单击菜单按钮时，更改子菜单面板以反映此选项”。域事件可以在代码的任何位置引发。任何类都可以针对此事件注册事件处理程序，然后在引发此事件时将收到通知。对于单个域事件可以有多个事件处理程序。

Martin Fowler 在 2005 年的一篇博客中首次提出了域事件的概念，该博客位于[`martinfowler.com/eaaDev/DomainEvent.html`](http://martinfowler.com/eaaDev/DomainEvent.html)。然后，Udi Dahan 在另一篇博客中展示了如何在 C#中实现简单的域事件模式，该博客位于[`www.udidahan.com/2009/06/14/domain-events-salvation/`](http://www.udidahan.com/2009/06/14/domain-events-salvation/)。Mike Hadlow 还在博客中讨论了域事件的关注点分离，该博客位于[`mikehadlow.blogspot.com.au/2010/09/separation-of-concerns-with-domain.html`](http://mikehadlow.blogspot.com.au/2010/09/separation-of-concerns-with-domain.html)。

Mike 认为，引发事件的代码片段不应该关心之后会发生什么 - 我们应该有单独的处理程序来处理这些事件 - 这些处理程序与实际引发事件的任何内容都没有耦合。

虽然有许多处理事件的 JavaScript 库 - 例如 Postal - 但这些库中的大多数都将字符串或简单的 JavaScript 对象作为消息包发送。无法确保发送消息的对象填写了消息处理程序所期望的所有属性。换句话说，这些消息不是强类型的 - 可能会很容易地导致运行时错误 - 试图将“方形销子”消息适配到“圆形孔”事件处理程序中。

在本节中，我们将构建一个强类型的领域事件消息总线，并展示事件引发方和事件处理方如何确保引发的事件具有事件处理方期望的所有属性。我们还将展示如何确保事件处理程序被正确编写和正确注册，以便以强类型的方式传递事件。

## 问题空间

假设我们有以下业务需求：“如果发生错误，请向用户显示一个通知弹出窗口中的错误消息。这个弹出窗口应该显示两秒钟，然后消失，让用户继续工作。”

在我们当前的应用程序中，有许多可能发生错误的地方——例如通过`ContactCollection`加载 JSON 时，或者渲染`ContactItemView`时。这些错误可能会发生在我们的类层次结构中的深层。为了实现我们的需求，我们需要在`ContactViewApp`级别处理这些错误。请考虑以下图表：

![问题空间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_06.jpg)

带有领域事件处理程序和事件引发方的依赖树。

我们的`ContactViewApp`将使用`TypeScriptTinyIoC`注册一个事件处理程序，指定它感兴趣的事件类型。当我们的模块中的任何一个引发了这种类型的事件时，我们的消息总线将把消息传递给正确的处理程序或一组处理程序。在前面的图表中，`ContactCollection`和`ContactItemView`类被显示为通过`TypeScriptTinyIoC`引发`ErrorEvent`。

## 消息和处理程序接口

我们需要两组关键信息来注册和引发强类型消息。第一组是描述消息本身的接口，与其命名接口配对。第二组是描述消息处理程序函数的接口，同样与其命名接口配对。我们的 TypeScript 接口为我们提供了消息和处理程序的编译时检查，而我们的命名接口（实现`IInterfaceChecker`）为我们提供了消息和处理程序的运行时类型检查。

首先，我们的消息接口如下：

```ts
interface IErrorEvent {
    Message: string;
    Description: string;
}

export class IIErrorEvent implements IInterfaceChecker {
    propertyNames: string [] = ["Message", "Description"];
    className: string = "IIErrorEvent";
}
```

我们从 TypeScript 接口`IErrorEvent`开始。这个接口有两个属性，`Message`和`Description`，都是字符串。然后我们创建我们的`IIErrorEvent`类，它是我们命名接口的一个实例——再次使用`propertyNames`数组匹配我们的 TypeScript 接口属性名。`className`属性也设置为类的名称`IIErrorEvent`，以确保唯一性。

然后我们的事件处理程序接口如下：

```ts
interface IErrorEvent_Handler {
    handle_ErrorEvent(event: IErrorEvent);
}

export class IIErrorEvent_Handler implements IInterfaceChecker {
    methodNames: string[] = ["handle_ErrorEvent"];
    className: string = "IIErrorEvent_Handler";
}
```

TypeScript 接口`IErrorEvent_Handler`包含一个名为`handle_ErrorEvent`的方法。这个处理程序方法有一个名为`event`的参数，再次强类型化为我们的事件接口`IErrorEvent`。然后我们构建一个名为`IIErrorEvent_Handler`的命名接口，并通过`methodNames`数组匹配 TypeScript 接口。同样，我们为这个命名接口提供一个独特的`className`属性。

有了这两个接口和命名接口，我们现在可以创建实际的`ErrorEvent`类如下：

```ts
export class ErrorEvent implements IErrorEvent {
    Message: string;
    Description: string;
    constructor(message: string, description: string) {
        this.Message = message;
        this.Description = description;
    }
}
```

`ErrorEvent`的类定义实现了`IErrorEvent`接口，从而使其与我们的事件处理程序兼容。请注意这个类的`constructor`。我们强制这个类的用户在构造函数中提供`message`和`description`参数——从而使用 TypeScript 编译时检查来确保我们无论在何处都正确构造这个类。

然后我们可以创建一个实现`IErrorEvent_Handler`接口的类，该类将接收事件本身。举个快速的例子，考虑以下类：

```ts
class EventHandlerTests_ErrorHandler
    implements IErrorEvent_Handler {
    handle_ErrorEvent(event: IErrorEvent) {
    }
}
```

这个类实现了`IErrorEvent_Handler` TypeScript 接口，因此编译器将强制这个类定义一个具有正确签名的`handle_ErrorEvent`函数，以接收消息。

## 多事件处理程序

为了能够注册多个事件，并且每个事件可以有多个事件处理程序，我们将需要一个事件数组，每个事件将依次保存一个处理程序数组，如下所示：

![多事件处理程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_07.jpg)

用于注册每个事件的多个事件处理程序的类结构。

我们的`TypeScriptTinyIoC`类将有一个名为`events`的数组，它使用事件的名称作为键。这个名称将来自我们的事件的命名接口 - 再次因为 TypeScript 接口被编译掉了。为了帮助管理每个事件的多个事件处理程序，我们将创建一个名为`EventHandlerList`的新类，它将便于注册多个事件处理程序。这个`EventHandlerList`类的实例将被存储在我们已注册的每个命名事件的`events`数组中。

让我们从事件处理程序列表开始，并实现我们的`EventHandlerList`类。在这个阶段，我们只需要一个内部数组来存储处理程序，名为`eventHandlers`，以及一个`registerHandler`函数，如下所示：

```ts
class EventHandlerList {
    eventHandlers: any[] = new Array();
    registerHandler(handler: any,
        interfaceType: { new (): IInterfaceChecker }) {
    }
}
```

`registerHandler`函数再次使用`{ new(): IInterfaceChecker }`语法来为`interfaceType`参数，从而允许我们为这个函数调用使用类型名称。一个快速的单元测试如下：

```ts
import iee = require("../app/events/ErrorEvent");

class EventHandlerTests_ErrorHandler
    implements iee.IErrorEvent_Handler {
    handle_ErrorEvent(event: iee.IErrorEvent) {
    }
}

describe("/tests//EventHandlerTests.ts", () => {

    var testHandler: EventHandlerTests_ErrorHandler;
    beforeEach(() => {
        testHandler = new EventHandlerTests_ErrorHandler();
    });

    it("should register an event Handler", () => {
        var eventHandlerList = new EventHandlerList();
        eventHandlerList.registerHandler(testHandler,
            iee.IIErrorEvent_Handler);

        expect(eventHandlerList.eventHandlers.length).toBe(1);
    });
});
```

我们从导入我们的事件类的`import`语句开始，然后是一个名为`EventHandlerTests_ErrorHandler`的类。这个类将被用作一个仅用于这个测试套件的注册事件处理程序。该类实现了`iee.IErrorEvent_Handler`，因此，如果我们没有一个接受`IErrorEvent`作为唯一参数的`handle_ErrorEvent`函数，它将生成一个编译错误。仅仅通过使用 TypeScript 接口，我们已经确保这个类具有正确的函数名称和函数签名来接受`ErrorEvent`消息。

我们的测试首先声明一个名为`testHandler`的变量来存储我们的`EventHandlerTests_ErrorHandler`类的一个实例。`beforeEach`函数将创建这个实例，并将其赋给我们的`testHandler`变量。测试本身然后创建一个`EventHandlerList`类的实例，调用`registerHandler`，然后期望内部`eventHandlers`属性的`length`值为 1。

再次注意`registerHandler`的调用语法。我们将我们的`testHandler`实例作为第一个参数传入，然后指定命名接口`IIErrorEvent_Handler`类类型。正如我们在服务定位器模式中看到的，我们再次使用相同的类名语法来表示我们的命名接口，而不是调用`new()`。

现在让我们填写代码使测试通过：

```ts
class EventHandlerList {
    eventHandlers: any[] = new Array();
    registerHandler(handler: any,
        interfaceType: { new (): IInterfaceChecker }) {

        var interfaceChecker = new InterfaceChecker();
        if (interfaceChecker.implementsInterface(
            handler, interfaceType)) {
            this.eventHandlers.push(handler);
        } else {
            var interfaceExpected = new interfaceType();
            throw new Error(
                "EventHandlerList cannot register handler of "
                + interfaceExpected.className);
        }
    }
}
```

我们的`registerHandler`函数首先创建一个`InterfaceChecker`类的实例，然后调用`implementsInterface`来确保在运行时，传入的处理程序对象确实具有我们命名接口定义的所有方法名称。如果`implementsInterface`函数返回`true`，我们可以简单地将这个处理程序推入我们的内部数组。

如果处理程序没有实现命名接口，我们会抛出一个错误。为了完整起见，这个错误包含了命名接口的`className`属性，因此我们首先要实例化这个命名接口类的一个实例，然后才能提取`className`属性。

现在让我们创建一个测试，故意使我们的`implementsInterface`检查失败，并确保实际上抛出了一个错误：

```ts
class No_ErrorHandler {
}

it("should throw an error with the correct className", () => {
    var eventHandlerList = new EventHandlerList();
    expect(() => {
        eventHandlerList.registerHandler(new No_ErrorHandler(),
            iee.IIErrorEvent_Handler);
    }).toThrow(new Error(
        "EventHandlerList cannot register handler of IIErrorEvent_Handler"
        ));
});
```

我们从`No_ErrorHandler`类的类定义开始，显然它没有实现我们的命名接口。然后我们设置`EventHandlerList`类，并调用`registerHandler`函数，使用`No_ErrorHandler`类的新实例和我们的`IIErrorEvent_Handler`命名接口。然后我们期望一个特定的错误消息 - 这个消息应该包括我们命名接口`IIErrorEvent_Handler`的名称。

## 触发事件

现在我们可以把注意力转向触发事件。为了做到这一点，我们需要知道事件处理程序的实际函数名称。我们将对`EventHandlerList`进行轻微更改，并将事件名称传递给构造函数，如下所示：

```ts
class EventHandlerList {
    handleEventMethod: string;
    constructor(handleEventMethodName: string) {
        this.handleEventMethod = handleEventMethodName;
    }

    raiseEvent(event: any) {
    }
}
```

我们的构造函数现在期望一个`handleEventMethodName`作为必需的参数，并且我们将其存储在名为`handleEventMethod`的属性中。请记住，注册到此类实例的所有处理程序都在响应相同的事件 - 因此都将具有相同的方法名称 - 这是由 TypeScript 编译器强制执行的。我们还定义了一个`raiseEvent`函数，由于我们不知道这个类将处理什么事件，所以事件的类型是`any`。

现在，我们可以创建一个单元测试，该测试将失败，因为`raiseEvent`函数实际上还没有做任何事情。在这之前，让我们更新我们的测试处理程序类`EventHandlerTests_ErrorHandler`，以便将最后触发的事件存储在一个我们以后可以访问的属性中：

```ts
class EventHandlerTests_ErrorHandler
    implements iee.IErrorEvent_Handler {
    LastEventFired: iee.IErrorEvent;
    handle_ErrorEvent(event: iee.IErrorEvent) {
        this.LastEventFired = event;
    }
}
```

我们已经更新了这个类定义，增加了一个名为`LastEventFired`的属性，并在`handle_ErrorEvent`函数中设置了这个属性。有了这个改变，当一个事件被触发时，我们可以询问`LastEventFired`属性来查看最后触发的事件是什么。现在让我们编写一个调用`raiseEvent`方法的测试。

```ts
it("should fire an event", () => {
    var eventHandlerList = new
        EventHandlerList('handle_ErrorEvent');
    eventHandlerList.registerHandler(testHandler,
        iee.IIErrorEvent_Handler);
    eventHandlerList.raiseEvent(
        new iee.ErrorEvent("test", "test"));
    expect(testHandler.LastEventFired.Message).toBe("test");
});
```

我们从一个名为`eventHandlerList`的变量开始，它保存了我们`EventHandlerList`类的一个实例，并通过构造函数传递了要调用的函数的名称。然后我们使用这个`testHandler`实例调用`registerHandler`。现在，我们可以调用`raiseEvent`函数，传入一个`new ErrorEvent`。由于我们`ErrorEvent`类的构造函数需要两个参数，我们刚刚为这些参数传入了`"test"`。最后，我们期望我们的事件处理程序的`LastEventFired`属性被正确设置。在这个阶段运行我们的测试将失败，所以让我们实现`EventHandlerList`类上的`raiseEvent`方法如下：

```ts
raiseEvent(event: any) {
    var i, len = 0;
    for (i = 0, len = this.eventHandlers.length; i < len; i++) {
        var handler = this.eventHandlers[i];
        handlerthis.handleEventMethod;
    }
}
```

这个`raiseEvent`函数的实现相对简单。我们只需遍历我们的`eventHandlers`数组，然后使用索引引用每个事件处理程序。这里需要注意的一行是我们如何执行处理程序函数：`handlerthis.handleEventMethod`。这利用了 JavaScript 能够使用与函数名称匹配的字符串值来调用函数的能力。在我们的测试中，这相当于`handler'handle_ErrorEvent'`，在 JavaScript 中相当于`handler.handle_ErrorEvent(event)` - 对处理程序函数的实际调用。有了这个 JavaScript 魔法，我们的事件被触发，我们的单元测试正确运行。

## 为事件注册事件处理程序

现在我们有一个可工作、经过测试的类来管理多个事件处理程序响应特定事件，我们可以把注意力转回到`TypeScriptTinyIoC`类上。

就像我们为服务定位器模式所做的那样，我们需要注册一个对象的实例来处理特定的事件。我们的事件处理程序注册的方法签名将如下所示：

```ts
public static registerHandler(
    handler: any,
    handlerInterface: { new (): IInterfaceChecker },
    eventInterface: { new (): IInterfaceChecker }) {
}
```

这个`registerHandler`函数有三个参数。第一个是实现处理程序的对象的实例。第二个参数是处理程序的命名接口类，这样我们可以在运行时检查这个类，以确保它实现了处理程序接口。第三个参数是事件本身的命名接口。这个`register`函数也是将事件绑定到处理程序的方法。

在我们组合单元测试之前，我们需要另一个静态函数来触发事件：

```ts
static raiseEvent(event: any,
    eventInterface: { new (): IInterfaceChecker }) {
}
```

这个`TypeScriptTinyIoC`类上的`raiseEvent`函数将调用这个事件的`EventHandlerList`类实例上的`raiseEvent`函数。我们还将在这里进行一个`interfaceChecker`测试，以确保正在触发的事件与我们为事件提供的命名接口类匹配——在我们实际触发事件之前。

现在到我们的单元测试：

```ts
it("should register an event handler with
TypeScriptTinyIoC and fire an event", () => {
    TypeScriptTinyIoC.registerHandler(testHandler,
        iee.IIErrorEvent_Handler, iee.IIErrorEvent);
    TypeScriptTinyIoC.raiseEvent(
        new iee.ErrorEvent("test", "test"),
        iee.IIErrorEvent);
    expect(testHandler.LastEventFired.Message).toBe("test");
});
```

这个测试与我们为`EventHandlerList`类编写的测试非常相似，只是我们在`TypeScriptTinyIoC`类上调用`registerHandler`和`raiseEvent`方法，而不是特定的`EventHandlerList`。有了这个失败的测试，我们现在可以填写`registerHandler`和`raiseEvent`函数如下：

```ts
static events: EventHandlerList[] = new Array<EventHandlerList>();
public static registerHandler(
    handler: any,
    handlerInterface: { new (): IInterfaceChecker },
    eventInterface: { new (): IInterfaceChecker }) {

    var eventInterfaceInstance = new eventInterface();
    var handlerInterfaceInstance = new handlerInterface();

    var handlerList = 
        this.events[eventInterfaceInstance.className];
    if (handlerList) {
        handlerList.registerHandler(handler, handlerInterface);
    } else {
        handlerList = new EventHandlerList(
            handlerInterfaceInstance.methodNames[0]);
        handlerList.registerHandler(handler, handlerInterface);
        this.events[eventInterfaceInstance.className] =
            handlerList;
    }
}
```

首先，我们添加了一个名为`events`的静态属性，它是`EventHandlerList`实例的数组。我们将使用命名事件接口的`className`作为键来添加到这个数组中。我们的`registerHandler`函数首先创建通过`handlerInterface`和`eventInterface`参数传入的命名接口类的实例。然后我们检查我们的内部数组是否已经有了一个针对这个事件的`EventHandlerList`实例，通过命名事件接口的`className`属性作为键。如果已经有了条目，我们可以简单地在现有的`EventHandlerList`实例上调用`registerHandler`函数。如果这个事件尚未注册，我们只需创建一个`EventHandlerList`类的新实例，调用`registerHandler`，然后将这个条目添加到我们的内部数组中。

注意我们是如何找出事件处理程序函数调用的实际名称的。我们只是使用在我们的方法名称数组中找到的第一个方法名称：`handlerInterfaceInstance.methodNames[0]`，这将返回一个字符串。在我们的示例中，这将返回`'handle_ErrorEvent'`字符串，这是我们在调用事件的处理程序函数时需要调用的方法名称。

接下来，我们可以专注于`raiseEvent`函数：

```ts
static raiseEvent(event: any,
    eventInterface: { new (): IInterfaceChecker }) {

    var eventChecker = new InterfaceChecker();
    if (eventChecker.implementsInterface(event, eventInterface)) {
        var eventInterfaceInstance = new eventInterface();
        var handlerList = 
            this.events[eventInterfaceInstance.className];
        if (handlerList) {
            handlerList.raiseEvent(event);
        }
    }

}
```

这个函数首先创建一个`InterfaceChecker`类的实例，然后确保正在触发的事件符合我们作为第二个参数提供的命名接口。同样，这是一个运行时类型检查，以确保我们试图触发的事件实际上是正确类型的。如果事件是有效的，我们获取为这个事件注册的`EventHandlerList`类的实例，然后调用它的`raiseEvent`函数。

我们的强类型域事件机制现在已经完成。我们在两个方面使用了编译时 TypeScript 接口检查和运行时类型检查。首先，在注册处理程序时，我们进行了接口检查，然后在触发事件时，我们进行了另一个接口检查。这意味着事件的两个方面——注册和触发——在编译时和运行时都是强类型的。

## 显示错误通知

现在我们已经在`TypeScriptTinyIoC`中有了事件机制，我们可以专注于解决当错误发生时显示错误通知的业务问题。Notify 是一个完全符合我们需求的 jQuery 插件（[`notifyjs.com/`](http://notifyjs.com/)）。我们可以从 NuGet 安装 JavaScript 库（安装`jQuery.notify`包），但是这个包的默认版本依赖于另一个名为 Bootstrap 的包来进行样式设置。然而，Notify 还在他们的网站上提供了一个选项，可以下载一个包含所有这些样式的自定义 notify.js 脚本。我们将使用这个自定义版本，因为我们的项目没有使用 Bootstrap 包。

Notify 的定义文件可以从 DefinitelyTyped（[`github.com/borisyankov/DefinitelyTyped/tree/master/notify`](https://github.com/borisyankov/DefinitelyTyped/tree/master/notify)）下载。然而，在撰写本文时，似乎有两个版本的 Notify 库，一个名为 Notify，另一个名为 Notify.js。使用 Notify 版本，因为它似乎更加更新。

为了模拟一个错误，让我们附加到`ContactItemView onClicked`函数，我们当前正在执行 flip，并在某人点击我们的联系链接时引发一个虚拟错误：

```ts
onClicked() {
    this.$el.flip({
        direction: 'tb',
        speed : 200
    });
    var errorEvent = new iee.ErrorEvent(
        "Dummy error message", this.model.Name);
    TypeScriptTinyIoC.raiseEvent(errorEvent, iee.IIErrorEvent);
}
```

在我们调用 flip 之后，我们只是创建了一个`ErrorEvent`类的实例，带有它的两个必需参数。然后我们调用`TypeScriptTinyIoC`上的`raiseEvent`函数，使用这个`errorEvent`实例和我们正在引发的事件类型的命名接口。就是这么简单。

现在，我们可以修改我们的`ContactViewApp`来注册此事件的处理程序如下：

```ts
import iee = require("tscode/app/events/ErrorEvent");

export class ContactViewApp implements iee.IErrorEvent_Handler {
    constructor() {
        TypeScriptTinyIoC.registerHandler(this,
            iee.IIErrorEvent_Handler, iee.IIErrorEvent);
    }
    run() {

    }

    contactCollectionLoaded(model, response, options) {

    }
    contactCollectionError(model, response, options) {

    }
    handle_ErrorEvent(event: iee.IErrorEvent) {
        $.notify("Error : " + event.Message
            + "\n" + event.Description);
    }
}
```

在这里，我们对`ContactViewApp`类进行了一些更改。首先，我们实现了`IErrorEvent_Handler` TypeScript 接口，这将强制我们在类中包含`handle_ErrorEvent`函数。我们还定义了一个`constructor`，在其中，我们使用我们的两个命名接口`IIErrorEvent_Handler`和`IIErrorEvent`注册了类实例作为处理程序。

在`handle_ErrorEvent`函数中，我们调用`$.notify`——Notify jQuery 插件。请注意，传递给`handle_ErrorEvent`函数的`event`参数的类型是`IErrorEvent`。这意味着我们可以在事件处理程序函数中安全地使用`IErrorEvent`接口的任何属性或方法，因为在事件引发期间，我们已经确保此事件正确实现了接口。

我们调用 Notify 只是使用了从我们的`ErrorEvent`构建的消息。以下屏幕截图显示了此 Notify 调用的结果：

![显示错误通知](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_08_08.jpg)

应用程序显示错误通知的屏幕截图

### 注意

在本章中，我们已经通过 GitHub 项目*typescript-tiny-ioc*（[`github.com/blorkfish/typescript-tiny-ioc`](https://github.com/blorkfish/typescript-tiny-ioc)）实现了此服务定位器模式和强类型域事件模式。该项目还有更多的代码示例以及用于 AMD 和普通 JavaScript 使用的完整单元测试套件。

# 总结

在本章中，我们研究了面向对象编程，从 SOLID 设计原则开始。然后，我们针对这些原则回顾了我们在第七章 *模块化* 中构建的应用程序。我们讨论了各种依赖注入的方法，然后构建了一个基于我们在第三章 *接口、类和泛型* 中的`InterfaceChecker`的机制，以获得命名接口的实例。我们使用了这个原则来构建一个服务定位器，然后将这个原则扩展到为域事件模式构建一个强类型的事件总线。最后，我们将 Notify 整合到我们的应用程序中，用于对这些错误事件进行简单通知。在我们接下来的最后一章中，我们将把我们迄今学到的所有原则付诸实践，并从头开始构建一个应用程序。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需获得版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第九章：让我们动手吧

在本章中，我们将从头开始构建一个 TypeScript 单页 Web 应用程序。我们将从讨论网站应该是什么样子开始，我们希望我们的页面转换如何流动，然后转向探索 Bootstrap 框架的功能，并讨论我们网站的纯 HTML 版本。我们的重点将转向我们应用程序所需的数据结构，以及我们需要用来表示这些数据的 Backbone 模型和集合。在此过程中，我们将为这些模型和集合编写一组单元和集成测试。

一旦我们有了要处理的数据，我们将使用**Marionette**框架来构建视图，以将我们的应用程序呈现到 DOM 中。然后，我们将展示如何将我们网站的纯 HTML 版本分解为 HTML 片段的较小部分，然后将这些片段与我们的 Marionette 视图集成。最后，我们将使用事件将应用程序联系在一起，并探讨**State**和**Mediator**设计模式，以帮助我们管理复杂的页面转换和 DOM 元素。

# Marionette

Marionette 是 Backbone 库的扩展，引入了一些增强功能，以减少样板 Backbone 代码，并使处理 DOM 元素和 HTML 片段更容易。Marionette 还引入了布局和区域的概念，以帮助管理大型网页中的逻辑部分。Marionette 布局是一种管理多个区域的控制器，而 Marionette 区域是管理我们页面上特定 HTML 部分的对象。例如，我们可以为标题面板设置一个区域，为侧边栏面板设置一个区域，为页脚区域设置另一个区域。这使我们能够将应用程序分解为逻辑区域，然后通过消息将它们联系在一起。

# Bootstrap

我们还将使用 Bootstrap 来帮助我们进行页面布局。Bootstrap 是一个流行的移动优先框架，用于在许多不同平台上呈现 HTML 元素。Bootstrap 的样式和定制是一个足够大的主题，需要一本专门的书来探讨，所以我们不会探讨各种 Bootstrap 选项的细节。如果你有兴趣了解更多，请务必阅读 David Cochran 和 Ian Whitley 的优秀著作*Boostrap Site Blueprints*，*Packt Publishing* ([`www.packtpub.com/web-development/bootstrap-site-blueprints`](https://www.packtpub.com/web-development/bootstrap-site-blueprints))。

# Board Sales

我们的应用将是一个相当简单的应用，名为 Board Sales，将在主页上列出一系列风浪板，使用摘要视图或板列表视图。单击其中任何一个板将使页面转换为显示所选板的详细信息。在屏幕的左侧，将有一个简单的面板，允许用户通过制造商或板类型来过滤主板列表。

现代的风浪板有各种尺寸，并且是按体积来衡量的。较小体积的板通常用于波浪帆船，而较大体积的板用于比赛或障碍赛。介于两者之间的板可以归类为自由式板，用于在平静水域上进行杂技表演。任何板的另一个重要元素是板设计的帆范围。在非常强风下，使用较小的帆来允许风帆手控制风力产生的动力，在较轻的风中，使用较大的帆来产生更多的动力。我们的摘要视图将包括对每个板的体积测量的快速参考，我们的详细视图将显示所有各种板的测量和兼容的帆范围列表。

# 页面布局

通过这个应用程序，我们将利用 JavaScript 的强大功能来提供从左到右的面板式页面布局。我们将使用一些 Bootstrap 过渡效果，从左侧或右侧滑入面板，以提供用户稍微不同的浏览体验。让我们来看看这在概念上是什么样子：

![页面布局](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_01.jpg)

Board Sales 的页面转换的概念视图

**查看面板**将是我们的主页面，有一个**头部面板**，一个**板块列表面板**和一个**页脚面板**。左侧隐藏的是**过滤面板**，主面板的左上方有一个按钮，用于显示或隐藏此过滤面板。需要时，过滤面板将从左侧滑入，隐藏时将滑回左侧。同样，**板块详细** **面板**将在点击板块时从右侧滑入，点击返回按钮时将滑回右侧，显示板块列表面板。

当在桌面设备上查看网站时，左侧的过滤面板将默认显示，但当在平板设备上查看网站时，由于屏幕较小，过滤面板将默认隐藏，以节省屏幕空间。

## 安装 Bootstrap

Bootstrap 是一组 CSS 样式和 JavaScript 函数，可帮助简单轻松地构建响应式网站。Bootstrap 的响应性意味着页面将自动调整元素大小，以便在手机的较小屏幕尺寸上呈现，以及在平板电脑和台式机上使用的较大屏幕上呈现。通过使用 Bootstrap，我们获得了额外的好处，可以以非常少的改动来针对移动用户和桌面用户。

Bootstrap 可以通过 NuGet 包安装，以及相应的 TypeScript 定义如下：

```ts
Install-package bootstrap
Install-package bootstrap.TypeScript.DefinitelyTyped

```

安装了 Bootstrap 后，我们可以开始构建一个纯粹使用 Bootstrap 编写的示例网页。以这种方式构建演示页面有助于我们确定要使用的 Bootstrap 元素，并允许我们在开始构建应用程序之前修改我们的 CSS 样式和正确构造我们的 HTML。这就是 Brackets 编辑器真正发挥作用的地方。通过使用编辑器的实时预览功能，我们可以在一个 IDE 中编辑我们的 HTML 和 CSS，并在预览窗格中获得即时的视觉反馈。以这种方式在示例 HTML 上工作既有益又有趣，更不用说节省了大量时间。

## 使用 Bootstrap

我们的页面将使用一些 Bootstrap 元素来定义主页面区域，如下：

1.  一个**导航栏**组件来渲染头部面板。

1.  一个**页脚**组件来渲染页脚面板。

1.  一个**轮播**组件，用于从板块列表视图滑动到板块详细视图。

1.  一个**手风琴**组件来渲染左侧面板中的过滤选项。

1.  **行**和**列**组件来控制我们板块列表视图中的板块的 HTML 布局，以及板块详细视图中的布局。

1.  表格 CSS 元素来渲染表格。

在本章中，我们不会详细介绍如何使用 Bootstrap 构建 HTML 页面。相反，我们将从一个可在目录/`tscode/tests/brackets/TestBootstrap.html`下的示例代码中找到的工作版本开始。

我们的 Bootstrap 元素如下：

![使用 Bootstrap](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_02.jpg)

在我们页面的顶部是导航栏元素，它被赋予了`navbar-inverse`样式，以黑色背景呈现。**轮播面板 1**元素是第一个轮播面板，包含左侧的过滤面板，以及板块列表和**显示/隐藏面板**按钮。左侧面板上的**过滤**选项使用了 Bootstrap 手风琴组件。最后，我们的页脚被设计成“粘性页脚”，意味着它将始终显示在页面上。

当我们点击板列表中的任何一个板时，我们的轮播组件将把轮播面板向左滑动，并从右侧滑入板详细视图。

我们的面板详细信息如下：

![使用 Bootstrap](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_03.jpg)

再次，我们有标准的页眉和页脚区域，但这次我们正在查看**轮播面板 2**。该面板在左上角有一个返回按钮，并显示所选板的详细信息。

当您运行此测试页面时，您会注意到页脚区域有四个链接，分别命名为**next**、**prev**、**show**和**hide**。这些按钮用于测试轮播面板的循环和左侧面板的显示/隐藏功能。

Bootstrap 非常适合快速构建站点的工作版本的模拟。这个版本可以轻松地展示给客户，或者用于项目会议的演示目的。向客户展示站点的演示模型将为您提供有关整个站点流程和设计的宝贵反馈。理想情况下，这样的工作应该由一位资深的网页设计师或者具有相同技能的人来完成，他们专门负责 CSS 样式。

当我们开始构建 Marionette 视图时，我们将稍后重用和重新设计这个 HTML。然而，将这些演示 HTML 页面保留在项目中是一个好主意，这样您就可以在不同的浏览器和设备上测试它们的外观和感觉，同时调整您的 HTML 布局和 CSS 样式。

# 数据结构

在现实世界的应用程序中，网站的数据将存储在某种数据库中，并从中检索。为了在 JavaScript 网页中使用数据，这些数据结构将被序列化为 JSON 格式。Marionette 使用标准的 Backbone 模型和集合来加载和序列化数据结构。对于这个示例应用程序，我们的数据结构将如下所示：

![数据结构](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_04.jpg)

`ManufacturerCollection`和相关的 Backbone 模型的类图

我们的数据源是`ManufacturerCollection`，它将有一个`url`属性来从我们的网站加载数据。这个`ManufacturerCollection`持有一个`ManufacturerModels`集合，可以通过`models`属性获得。`ManufacturerCollection`还实现了两个接口：`IManufacturerCollection`和`IFilterProvider`。我们稍后会讨论这两个接口。

`ManufacturerModel`的属性将用于将单个制造商的名称和徽标呈现到 DOM 中。每个`ManufacturerModel`还有一个名为`boards`的数组，其中包含一个`BoardModels`数组。

每个`BoardModel`都有必要用于呈现的属性，以及一个名为`board_types`的数组，其中包含一组`BoardType`类。`BoardType`是一个简单的字符串，将包含"Wave"、"Freestyle"或"Slalom"中的一个值。

每个`BoardModel`还将有一个`sizes`数组，其中包含一个`BoardSize`类，其中包含有关可用尺寸的详细信息。

例如，用于序列化前述对象结构的 JSON 数据结构将如下所示：

```ts
{
"manufacturer": "JP Australia",
"manufacturer_logo": "jp_australia_logo.png",
"logo_class" : "",
"boards": [
    {
        "name": "Radical Quad",
        "board_types": [ { "board_type": "Wave" } ],

        "description": "Radical Wave Board",
        "image": "jp_windsurf_radicalquad_ov.png",
        "long_description": "long desc goes here",
        "sizes": [
            { "volume": 68, "length": 227, 
              "width": 53, "sail_min": "< 5.0", "sail_max": "< 5.2" }
        ]
    }]
}
```

在我们的示例应用程序中，完整的 JSON 数据集可以在`/tscode/tests/boards.json`找到。

## 数据接口

为了在 TypeScript 中使用这个 JSON 数据结构，我们需要定义一组接口来描述上述数据结构，如下所示：

```ts
export interface IBoardType {
    board_type: string;
}
export interface IBoardSize {
    volume: number;
    length: number;
    width: number;
    sail_min: string;
    sail_max: string;
}
export interface IBoardModel {
    name: string;
    board_types: IBoardType[];
    description: string;
    image: string;
    long_description: string;
    sizes: IBoardSize[];
}
export interface IManufacturerModel {
    manufacturer: string;
    manufacturer_logo: string;
    logo_class: string;
    boards: IBoardModel[];
}
```

这些接口简单地匹配了前面图表中的模型属性，然后我们可以构建相应的实现这些接口的`Backbone.Model`类。请注意，为了简洁起见，我们没有在这里列出每个模型的每个属性，因此请务必参考附带的源代码以获取完整列表。我们的 Backbone 模型如下：

```ts
export class BoardType extends Backbone.Model
    implements IBoardType {
    get board_type() { return this.get('board_type'); }
    set board_type(val: string) { this.set('board_type', val); }
}
export class BoardSize extends Backbone.Model 
    implements IBoardSize {
    get volume() { return this.get('volume');}
    set volume(val: number) { this.set('volume', val); }
    // more properties
}
export class BoardModel extends Backbone.Model implements IBoardModel {
    get name() { return this.get('name'); }
    set name(val: string) { this.set('name', val); }
    // more properties
    get sizes() { return this.get('sizes'); }
    set sizes(val: IBoardSize[]) { this.set('sizes', val); }
}
export class ManufacturerModel extends Backbone.Model implements IManufacturerModel {
    get manufacturer() { return this.get('manufacturer'); }
    set manufacturer(val: string) { this.set('manufacturer', val); }
    // more properties
    get boards() { return this.get('boards'); }
    set boards(val: IBoardModel[]) { this.set('boards', val); }
}
```

每个类都扩展了`Backbone.Model`，并实现了我们之前定义的接口之一。这些类没有太多内容，除了为每个属性定义`get`和`set`方法，并使用正确的属性类型。

此时，我们的模型已经就位，我们可以编写一些单元测试，以确保我们可以正确地创建我们的模型：

```ts
it("should build a BoardType", () => {
    var boardType = new bm.BoardType(
        { board_type: "testBoardType" });
    expect(boardType.board_type).toBe("testBoardType");
});
```

我们从一个简单的测试开始，创建一个`BoardType`模型，然后测试`board_type`属性是否已正确设置。同样，我们可以为`BoardSize`模型创建一个测试：

```ts
describe("BoardSize tests", () => {
    var boardSize: bm.IBoardSize;
    beforeAll(() => {
        boardSize = new bm.BoardSize(
          { "volume": 74, "length": 227,
            "width": 55, "sail_min": "4.0", "sail_max": "5.2" });
    });
    it("should build a board size object",() => {
        expect(boardSize.volume).toBe(74);
    });
});
```

这个测试也只是创建了一个`BoardSize`模型的实例，但它使用了`beforeAll` Jasmine 方法。为简洁起见，我们只展示了一个测试，检查`volume`属性，但在实际应用中，我们会测试每个`BoardSize`属性。最后，我们可以编写一个`BoardModel`的测试如下：

```ts
describe("BoardModel tests",() => {
    var board: bm.IBoardModel;
    beforeAll(() => {
        board = new bm.BoardModel({
            "name": "Thruster Quad",
            "board_types": [{ "board_type": "Wave" }],
            "description": "Allround Wave Board",
            "image": "windsurf_thrusterquad_ov.png",
            "long_description": 
                "Shaper Werner Gnigler and pro riders Robby Swift",
            "sizes": [
                { "volume": 73, "length": 228, "width": 55.5,
                     "sail_min": "4.0", "sail_max": "5.2" }
            ]
        });
    });

    it("should find name property",() => {
        expect(board.name).toBe("Thruster Quad");
    });
    it("should find sizes[0].volume property",() => {
        expect(board.sizes[0].volume).toBe(73);
    });
    it("should find sizes[0].sail_max property",() => {
        expect(board.sizes[0].sail_max).toBe("5.2");
    });
    it("should find board_types[0].sail_max property",() => {
        expect(board.board_types[0].board_type).toBe("Wave");
    });
});
```

再次强调，在我们的`beforeAll`函数中创建了一个`BoardModel`实例，然后测试属性是否设置正确。注意代码片段底部附近的测试：我们正在检查`sizes`属性和`board_types`属性是否已正确构建，并且它们实际上是可以用`[]`数组表示法引用的数组。

在附带的源代码中，您将找到这些模型的进一步测试，以及对`ManufacturerModel`的测试。

### 注意

注意每个模型是如何通过简单地剪切和粘贴原始 JSON 样本的部分来构建的。当 Backbone 模型通过 RESTful 服务进行填充时，这些服务只是简单地返回 JSON，因此我们的测试与 Backbone 本身的操作是匹配的。

## 集成测试

此时，您可能会想为什么我们要编写这些测试，因为它们可能看起来微不足道，只是检查某些属性是否已正确构建。在实际应用中，模型经常会发生变化，特别是在项目的初期阶段。通常会有一个开发人员或团队的一部分负责后端数据库和向前端提供 JSON 的服务器端代码。另一个团队可能负责前端 JavaScript 代码的开发。通过编写这样的测试，您清楚地定义了数据结构应该是什么样子，以及您的模型中期望的属性是什么。如果服务器端进行了修改数据结构的更改，您的团队将能够快速确定问题的原因所在。

编写基于属性的测试的另一个原因是，Backbone、Marionette 和几乎任何其他 JavaScript 库都将使用这些属性名称来将 HTML 呈现到前端。如果您的模板期望一个名为`manufacturer_logo`的属性，而您将此属性名称更改为`logo_image`，那么您的渲染代码将会出错。这些错误通常很难在运行时跟踪。遵循“尽早失败，失败得响亮”的测试驱动开发原则，我们的模型属性测试将快速突出显示这些潜在错误，如果发生的话。

一旦一系列基于属性的测试就位，我们现在可以专注于一个集成测试，实际上会调用服务器端代码。这将确保我们的 RESTful 服务正常工作，并且我们网站生成的 JSON 数据结构与我们的 Backbone 模型期望的 JSON 数据结构匹配。同样，如果两个独立的团队负责客户端和服务器端代码，这种集成测试将确保数据交换是一致的。

我们将通过`Backbone.Collection`类加载此应用程序的数据，并且此集合将需要加载多个制造商。为此，我们现在可以构建一个`ManufacturerCollection`类，如下所示：

```ts
export class ManufacturerCollection 
    extends Backbone.Collection<ManufacturerModel>
{
    model = ManufacturerModel;
    url = "/tscode/boards.json";
}
```

这是一个非常简单的`Backbone.Collection`类，它只是将`model`属性设置为我们的`ManufacturerModel`，将`url`属性设置为`/tscode/boards.json`。由于我们的示例应用程序没有后端数据库或 REST 服务，因此我们将在此阶段仅从磁盘加载我们的 JSON。请注意，即使在此测试中我们使用静态 JSON 文件，Backbone 仍将向服务器发出 HTTP 请求以加载此文件，这意味着对`ManufacturerCollection`的任何测试实际上都是集成测试。现在我们可以编写一些集成测试，以确保该模型可以从`url`属性正确加载，如下所示：

```ts
describe("ManufacturerCollection tests", () => {
    var manufacturers: bm.ManufacturerCollection;

    beforeAll(() => {
        manufacturers = new bm.ManufacturerCollection();
        manufacturers.fetch({ async: false });
    });

    it("should load 3 manufacturers", () => {
        expect(manufacturers.length).toBe(3);
    });

    it("should find manufacturers.at(2)",() => {
        expect(manufacturers.at(2).manufacturer)
           .toBe("Starboard");
    });
}
```

我们再次使用 Jasmine 的`beforeAll`语法来设置我们的`ManufacturerCollection`实例，然后调用`fetch({ async: false })`来等待集合加载。然后我们有两个测试，一个是检查我们是否将三个制造商加载到我们的集合中，另一个是检查索引为`2`的`Manufacturer`模型。

## 遍历集合

现在我们已经加载了完整的`ManufacturerCollection`，我们可以将注意力转向处理它包含的数据。我们需要搜索此集合以找到两件事：制造商列表和板类型列表。这两个列表将被用于左侧面板上的过滤面板。在现实世界的应用程序中，这两个列表可能由服务器端代码提供，返回简单的 JSON 数据结构来表示这两个列表。然而，在我们的示例应用程序中，我们将展示如何遍历我们已经加载的主制造商 Backbone 集合。过滤数据结构如下：

![遍历集合](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_05.jpg)

具有相关 Backbone 模型的 FilterCollection 类图

与前面图表中显示的 Backbone 模型的完整实现不同，我们将查看 TypeScript 接口。我们的这些过滤模型的接口如下：

```ts
export enum FilterType {
    Manufacturer,
    BoardType,
    None
}
export interface IFilterValue {
    filterValue: string;
}
export interface IFilterModel {
    filterType: FilterType;
    filterName: string;
    filterValues: IFilterValue[];
}
```

我们从`FilterType`枚举开始，我们将使用它来定义我们可用的每种类型的过滤器。我们可以通过制造商名称、板类型或使用`None`过滤器类型清除所有过滤器来过滤我们的板列表。

`IFilterValue`接口简单地保存一个用于过滤的字符串值。当我们按板类型进行过滤时，此字符串值将是“Wave”、“Freestyle”或“Slalom”之一，当我们按制造商进行过滤时，此字符串值将是制造商的名称。

`IFilterModel`接口将保存`FilterType`，过滤器的名称和`filterValues`数组。

我们将为这些接口创建一个 Backbone 模型，这意味着我们最终将拥有两个 Backbone 模型，名为`FilterValue`（实现`IFilterValue`接口）和`FilterModel`（实现`IFilterModel`接口）。为了容纳`FilterModel`实例的集合，我们还将创建一个名为`FilterCollection`的 Backbone 集合。此集合有一个名为`buildFilterCollection`的方法，它将使用`IFilterProvider`接口来构建其内部的`FilterModels`数组。此`IFilterProvider`接口如下：

```ts
export interface IFilterProvider {
    findManufacturerNames(): bm.IManufacturerName[];
    findBoardTypes(): string[]
}
```

我们的`IFilterProvider`接口有两个函数。`findManufacturerNames`函数将返回制造商名称列表（及其关联的标志），`findBoardTypes`函数将返回所有板类型的字符串列表。这些信息是构建我们的`FilterCollection`内部数据结构所需的全部信息。

用于填充此`FilterCollection`所需的所有值将来自已包含在我们的`ManufacturerCollection`中的数据。因此，`ManufacturerCollection`将需要实现此`IFilterProvider`接口。

### 查找制造商名称

让我们继续在我们的测试套件中工作，以充实`ManufacturerCollection`需要实现的`IFilterProvider`接口的`findManufacturerNames`函数的功能。这个函数返回一个`IManufacturerName`类型的数组，定义如下：

```ts
export interface IManufacturerName {
    manufacturer: string;
    manufacturer_logo: string;
}
```

现在我们可以使用这个接口构建一个测试：

```ts
it("should return manufacturer names ",() => {
    var results: bm.IManufacturerName[] = 
        manufacturers.findManufacturerNames();
    expect(results.length).toBe(3);
    expect(results[0].manufacturer).toBe("JP Australia");
});
```

这个测试重用了我们在之前的测试套件中设置的`manufacturers`变量。然后调用`findManufacturerNames`函数，并期望结果是一个包含三个制造商名称的数组，即"JP Australia"，"RRD"和"Starboard"。

现在，我们可以更新实际的`ManufacturerCollection`类，以提供`findManufacturerNames`函数的实现：

```ts
public findManufacturerNames(): IManufacturerName[] {
    var items = _(this.models).map((iterator) => {
        return {
            'manufacturer': iterator.manufacturer,
            'manufacturer_logo': iterator.manufacturer_logo
        };
    });
    return items;
}
```

在这个函数中，我们使用 Underscore 实用函数`map`来循环遍历我们的集合。每个 Backbone 集合类都有一个名为`models`的内部数组。`map`函数将循环遍历这个`models`属性，并为集合中的每个项目调用匿名函数，通过`iterator`参数将当前模型传递给我们的匿名函数。然后我们的代码构建了一个具有`IManufacturer`接口所需属性的 JSON 对象。

### 注意

如果返回的对象不符合`IManufacturer`名称接口，TypeScript 编译器将生成错误。

### 查找板类型

现在我们可以专注于`IFilterProvider`接口的第二个函数，名为`findBoardTypes`，`ManufacturerCollection`需要实现。这是一个单元测试：

```ts
it("should find board types ",() => {
    var results: string[] = manufacturers.findBoardTypes();
    expect(results.length).toBe(3);
    expect(results).toContain("Wave");
    expect(results).toContain("Freestyle");
    expect(results).toContain("Slalom");
});
```

这个测试调用`findBoardTypes`函数，它将返回一个字符串数组。我们期望返回的数组包含三个字符串："Wave"，"Freestyle"和"Slalom"。

我们`ManufacturerCollection`类中对应的函数实现如下：

```ts
public findBoardTypes(): string[] {
    var boardTypes = new Array<string>();
    _(this.models).each((manufacturer) => {
        _(manufacturer.boards).each((board) => {
            _(board.board_types).each((boardType) => {
                if (! _.contains(
                    boardTypes, boardType.board_type)) {
                        boardTypes.push(boardType.board_type);
                }
            });
        });
    });
    return boardTypes;
}
```

`findBoardTypes`函数的实现从创建一个名为`boardTypes`的新字符串数组开始，它将保存我们的结果。然后我们使用 Underscore 的`each`函数来循环遍历每个制造商。Underscore 的`each`函数类似于`map`函数，将迭代我们集合中的每个项目。然后我们循环遍历制造商的所有板，以及每个板上列出的每种板类型。最后，我们测试看看板类型集合是否已经包含一个项目，使用 underscore 的`_.contains`函数。如果数组中还没有板类型，我们将`board_type`字符串推入我们的`boardTypes`数组中。

### 注意

Underscore 库有许多实用函数可用于搜索、操作和修改数组和集合，因此请务必查阅文档，找到适合在您的代码中使用的合适函数。这些函数不仅限于 Backbone 集合，可以用于任何类型的数组。

这完成了我们对`IFilterProvider`接口的工作，以及它在`ManufacturerCollection`类中的实现。

## 集合过滤

当用户在左侧面板上点击过滤选项时，我们需要将所选的过滤器应用到制造商集合中包含的数据。为了做到这一点，我们需要在`ManufacturerCollection`类中实现两个函数，名为`filterByManufacturer`和`filterByBoardType`。让我们从一个测试开始，通过制造商名称来过滤我们的集合：

```ts
it("should filter by manufacturer name ",() => {
    var results = manufacturers.filterByManufacturer("RRD");
    expect(results.length).toBe(1);
});
```

这个测试调用`filterByManufacturer`函数，期望只返回一个制造商。有了这个测试，我们可以在`ManufacturerCollection`上创建真正的`filterByManufacturer`函数，如下所示：

```ts
public filterByManufacturer(manufacturer_name: string) {
    return _(this.models).filter((item) => {
        return item.manufacturer === manufacturer_name;
    });
}
```

在这里，我们使用 Underscore 函数`filter`来对我们的集合应用过滤器。

第二个筛选函数是按板子类型筛选，稍微复杂一些。我们需要循环遍历我们的集合中的每个制造商，然后循环遍历每个板子，然后循环遍历每个板子类型。如果我们找到了板子类型的匹配，我们将标记这个板子包含在结果集中。在我们着手编写`filterByBoardType`函数之前，让我们写一个测试：

```ts
it("should only return Slalom boards ",() => {
    var results = manufacturers.filterByBoardType("Slalom");
    expect(results.length).toBe(2);
    _(results).each((manufacturer) => {
        _(manufacturer.boards).each((board) => {
            expect(_(board.board_types).some((boardType) => {
                return boardType.board_type == 'Slalom';
            })).toBeTruthy(); 

        });
    });
});
```

我们的测试调用`filterByBoardType`函数，使用字符串`"Slalom"`作为筛选条件。请记住，这个函数将返回一个`ManufacturerModel`对象的集合，顶层的每个对象中的`boards`数组都经过板子类型的筛选。我们的测试然后循环遍历每个制造商，以及结果集中的每个板子，然后使用 Underscore 函数`some`来测试`board_types`数组是否有正确的板子类型。

我们在`ManufacturerCollection`上实现这个函数的代码也有点棘手，如下所示：

```ts
public filterByBoardType(board_type: string) {
    var manufWithBoard = new Array();
    _(this.models).each((manuf) => { 
        var hasBoardtype = false;
        var boardMatches = new Array();
        _(manuf.boards).each((board) => {
            var match = _(board.board_types).some((item) => {
                return item.board_type == board_type;
            });
            if (match) {
                boardMatches.push(new BoardModel(board));
                hasBoardtype = true;
            }
        });

        if (hasBoardtype) {
            var manufFiltered = new ManufacturerModel(manuf);
            manufFiltered.set('boards', boardMatches);
            manufWithBoard.push(manufFiltered);
        }
    });
    return manufWithBoard;
}
```

我们的`ManufacturerCollection`类实例保存了通过网站上的 JSON 文件加载的整个集合。为了保留这些数据以进行重复筛选，我们需要构造一个新的`ManufacturerModel`数组来从这个函数中返回——这样我们就不需要修改基础的“全局”数据。一旦我们构造了这个新数组，我们就可以循环遍历每个制造商。如果我们找到与所需筛选匹配的板子，我们将设置一个名为`hasBoardType`的标志为 true，以指示这个制造商必须添加到我们的筛选数组中。

在这个经过筛选的数组中，每个制造商还需要列出与我们的筛选条件匹配的板子类型，因此我们需要另一个数组——称为`boardMatches`——来保存这些匹配的板子。然后我们的代码将循环遍历每个板子，并检查它是否具有所需的`board_type`。如果是，我们将把它添加到`boardMatches`数组中，并将`hasBoardType`标志设置为`true`。

一旦我们循环遍历了每个制造商的板子，我们就可以检查`hasBoardType`标志。如果我们的制造商有这种板子类型，我们将构造一个新的`ManufacturerModel`，然后将这个模型的`boards`属性设置为我们内存中匹配的板子的数组。

我们对底层的 Backbone 集合和模型的工作现在已经完成。我们还编写了一组单元测试和集成测试，以确保我们可以从网站加载我们的集合，从这个集合构建我们的筛选列表，然后对这些数据应用特定的筛选。

# Marionette 应用程序、区域和布局

现在我们可以把注意力集中在构建应用程序本身上。在 Marionette 中，这是通过创建一个从`Marionette.Application`派生的类来实现的，如下所示：

```ts
export class BoardSalesApp extends Marionette.Application {
    viewLayout: pvl.PageViewLayout;
    constructor(options?: any) {
        if (!options)
            options = {};
        super();
        this.viewLayout = new pvl.PageViewLayout();
    }
    onStart() {
        this.viewLayout.render();
    }
}
```

在这里，我们定义了一个名为`BoardSalesApp`的类，它派生自`Marionette.Application`类，并将作为我们应用程序的起点。我们的构造函数非常简单，它创建了`PageViewLayout`类的一个新实例，我们将很快讨论。我们应用程序中的唯一其他函数是`onStart`函数，它将我们的`PageViewLayout`呈现到屏幕上。当应用程序启动时，Marionette 将触发这个`onStart`函数。

我们的`PageLayoutView`类如下：

```ts
export class PageViewLayout extends Marionette.LayoutView<Backbone.Model> {
    constructor(options?: any) {
        if (!options)
            options = {};
        options.el = '#page_wrapper';
        var snippetService: ISnippetService = 
            TypeScriptTinyIoC.resolve(IISnippetService);
        options.template = snippetService.retrieveSnippet(
            SnippetKey.PAGE_VIEW_LAYOUT_SNIPPET);
        super(options);
    }
}
```

这个类扩展自`Marionette.LayoutView`，并做了两件重要的事情。首先，在`options`对象上设置了一些属性，然后通过`super`函数调用了基类的构造函数，传入了这个`options`对象。这个`options`对象的一个属性名为`el`，包含了这个视图将呈现到的 DOM 元素的名称。在这段代码中，这个`el`属性被设置为 DOM 元素`'#page_wrapper'`。如果不设置这个`el`属性，当我们尝试将视图呈现到 DOM 时，我们将得到一个空白屏幕。

我们构造函数中的第二个重要步骤是从`SnippetService`加载一个片段。然后使用这个片段来设置`options`对象上的`template`属性。与 Backbone 类似，Marionette 加载模板，然后将底层模型属性与视图模板结合起来，以生成将呈现到 DOM 中的 HTML。

在这个阶段，为了运行我们的`BoardSalesApp`，并让它将`PageViewLayout`呈现到 DOM 中，我们需要两样东西。第一是在我们的`index.html`页面中有一个`id="page_wrapper"`的 DOM 元素，以匹配我们的`options.el`属性，第二是我们的`PAGE_VIEW_LAYOUT_SNIPPET`。

我们的`index.html`页面如下：

```ts
<!DOCTYPE html>
<html >
<head>
    <title>BoardSales</title>
    <link rel="stylesheet" href="/Content/bootstrap.css" />
    <link rel="stylesheet" type="text/css"
          href="/Content/app.css">
    <script type="text/javascript"
            src="img/head-1.0.3.js"></script>
    <script data-main="/tscode/app/AppConfig"
            type="text/javascript"
            src="img/require.js"></script>
</head>
<body>
    <div id="page_wrapper">

    </div>
    <footer class="footer footer_style">
        <div class="container">
            <p class="text-muted"><small>Footer</small></p>
        </div>

    </footer>
</body>
</html>
```

这个页面包括`bootstrap.css`和`app.css`样式表，以及一个带有`data-main`属性设置为名为`/tscode/app/AppConfig`的 Require 配置文件的 Require 调用。`index.html`页面的主体只包括带有`id="page_wrapper"`的 DOM 元素和页脚。这是我们之前构建的演示 HTML 页面的一个非常简化的版本。

### 注意

我们还包括了一个名为`head-1.0.3.js`的脚本，可以通过 NuGet 包`HeadJS`安装。这个脚本会查询我们的浏览器，以找出它是在移动设备还是桌面设备上运行，我们正在使用什么浏览器，甚至当前屏幕尺寸是多少。我们将在应用程序中稍后使用`head.js`的输出。

我们现在需要为`PageViewLayout`创建一个 HTML 片段。这个文件叫做`PageViewLayout.html`，位于`/tscode/app/views`目录中，因此在处理`PageViewLayout.ts`文件时可以很容易找到。查看完整的 HTML 文件清单的示例代码，其中包括以下相关部分：

```ts
<div id="page_wrapper">
    <div id="main_panel_div">
            <div class="carousel-inner" >
                <div id="carousel_panel_1" >
                    <div id="content_panel_left" >
                            <!--filter panel goes here-->
                    </div>
                    <div id="content_panel_main">
                      <div id="manufacturer_collection">
                            <!--board list goes here-->
                        </div>
                    </div>
                </div>
                <div id="carousel_panel_2">
                        <!--board detail panel goes here-->
                </div>
            </div>
    </div>
</div>
```

我们的`PageViewSnippet.html`文件包含了我们页面的主要元素。我们有一个`main_panel_div`作为应用程序的中间面板，其中包含了我们的两个轮播面板 div，名为`carousel_panel_1`和`carousel_panel_2`。在这些轮播面板中，我们将呈现过滤面板、板块列表面板和板块详细信息面板。

现在我们需要组合我们的`AppConfig.ts`文件，Require 将加载，并设置`SnippetService`来加载`PageViewLayout.html`片段。为了简洁起见，我们没有在这里列出完整的`require.config`，并且已经排除了`paths`和`shims`部分。我们将专注于对 Require 的调用如下：

```ts
require([
    'BoardSalesApp', 'tinyioc', 'snippetservice'
    ,'text!/tscode/app/views/PageViewLayout.html' ],
    (app, tinyioc, snippetservice, pageViewLayoutSnippet) => {

     var snippetService = new SnippetService();
     snippetService.storeSnippet(
          SnippetKey.PAGE_VIEW_LAYOUT_SNIPPET,
          pageViewLayoutSnippet);
     TypeScriptTinyIoC.register(snippetService, IISnippetService);

     var boardSalesApp = new app.BoardSalesApp();
     boardSalesApp.start();

    });
```

在这里，我们包括了`BoardSalesApp`、`tinyioc`和`snippetservice`，以及我们的`PageViewLayout.html`片段在 require 的调用中。然后我们设置了`SnippetService`，将`pageViewLayoutSnippet`存储在正确的键下，并将`SnippetService`注册到我们的服务定位器中。为了启动我们的 Marionette 应用程序，我们创建了`BoardSalesApp`的一个新实例，并调用`start`。一旦调用了`start`方法，Marionette 将触发我们的`BoardSalesApp.onStart`方法，然后渲染`PageViewLayout`类。

## 加载主要集合

在这个应用程序中，我们将只加载我们的`ManufacturerCollection`一次，然后重复使用这个“全局”集合进行过滤。现在让我们更新我们的`BoardSalesApp`，以包括这个“全局”集合，并在应用程序启动时加载它。再次参考完整清单的示例代码：

```ts
export class BoardSalesApp extends Marionette.Application {
    viewLayout: pvl.PageViewLayout;
    _manufCollection: bm.ManufacturerCollection;

    constructor(options?: any) {
        if (!options)
            options = {};
        super();
        _.bindAll(this, 'CollectionLoaded');
        _.bindAll(this, 'CollectionLoadError');
        this.viewLayout = new pvl.PageViewLayout();
    }

    onStart() {
        this.viewLayout.render();
        this._manufCollection = new bm.ManufacturerCollection();
        TypeScriptTinyIoC.register(this._manufCollection, 
            bm.IIManufacturerCollection);
        this._manufCollection.fetch({ 
            success: this.CollectionLoaded, 
            error: this.CollectionLoadError });
    }

    CollectionLoaded() {
        TypeScriptTinyIoC.raiseEvent(
            new ev.NotifyEvent(
                ev.EventType.ManufacturerDataLoaded), ev.IINotifyEvent);
    }

    CollectionLoadError(err) {
        TypeScriptTinyIoC.raiseEvent(
           new ev.ErrorEvent(err), ev.IIErrorEvent);
    }
}
```

我们已经更新了我们的`BoardSalesApp`，在私有变量`_manufCollection`中存储了`ManufacturerCollection`类的一个实例。我们的`onStart`函数已经更新，以在调用`viewLayout.render`之后实例化这个集合。注意下一个对`TypeScriptTinyIoC`的调用。我们正在注册`this._manufCollection`作为一个将实现`IIManufacturerCollection`命名接口的服务。然后我们在集合上调用 Backbone 的`fetch`函数，带有`success`和`error`回调。`success`回调和`error`回调都只是触发一个事件。

通过将我们的`ManufacturerCollection`类的实例注册到命名接口`IIManufacturerCollection`，我们的任何需要访问主要集合的类都可以简单地从我们的服务定位器中请求此类的实例。这些命名接口如下：

```ts
export interface IManufacturerCollection {
    models: ManufacturerModel[];
}
export class IIManufacturerCollection implements IInterfaceChecker {
    propertyNames = ['models'];
    className = 'IIManufacturerCollection';
}
```

我们还需要修改我们的`ManufacturerCollection`类以实现`IManufacturerCollection`接口，如下所示：

```ts
export class ManufacturerCollection extends Backbone.Collection<ManufacturerModel>
    implements IManufacturerCollection
{
    // existing code
}
```

现在让我们来看一下将从我们的`success`和`error`回调中触发的事件。在`success`函数回调中，我们正在引发`INotifyEvent`类型的事件。请注意，我们在这里只列出接口定义—有关相应的`IInterfaceChecker`类和事件类，请参考附带的源代码：

```ts
export enum EventType {
    ManufacturerDataLoaded,
    ErrorEvent
}
export interface INotifyEvent {
    eventType: EventType;
}
export interface INotifyEvent_Handler {
    handle_NotifyEvent(event: INotifyEvent): void;
}
```

在这里，我们定义了一个`EventType`枚举来保存事件类型，然后定义了一个`INotifyEvent`接口，它只包含一个名为`eventType`的属性。我们还定义了相应的`INotifyEvent_Handler`接口，任何处理程序都需要实现。

我们的错误事件将使用继承从这些接口派生如下：

```ts
export interface IErrorEvent extends INotifyEvent {
    errorMessage: string;
}
export interface IErrorEvent_Handler {
    handle_ErrorEvent(event: IErrorEvent);
}
```

在这里，我们从`INotifyEvent`派生`IErrorEvent`接口，从而重用基接口的`EventType`枚举和属性。

现在我们可以在我们的`PageViewLayout`类中响应这些事件：

```ts
export class PageViewLayout extends Marionette.LayoutView<Backbone.Model>
    implements ev.INotifyEvent_Handler
{

    private _manufacturerView: mv.ManufacturerCollectionView;

    constructor(options?: any) {
        // exising code
        _.bindAll(this, 'handle_NotifyEvent');
        TypeScriptTinyIoC.registerHandler(
            this, ev.IINotifyEvent_Handler, ev.IINotifyEvent);
    }
    handle_NotifyEvent(event: ev.INotifyEvent) {
        if (event.eventType == ev.EventType.ManufacturerDataLoaded) 
        {
            this._manufacturerView =
                new mv.ManufacturerCollectionView();
            this._manufacturerView.render();
        }
    }
}
```

我们已经实现了`INotifyEvent_Handler`接口，并在`TypeScriptTinyIoC`中为`IINotifyEvent`注册了。我们的`handle_NotifyEvent`类将检查事件类型是否为`ManufacturerDataLoaded`事件，然后创建`ManufacturerCollectionView`类的实例并将其渲染到 DOM 中。

## Marionette 视图

Marionette 提供了许多不同的视图类供我们使用，根据我们需要渲染到 DOM 的对象类型。任何需要渲染`Backbone.Collection`的类都可以使用`CollectionView`，任何需要渲染此集合中的单个项目的类都可以使用`ItemView`。Marionette 还提供了这两种视图的混合称为`CompositeView`。如果我们看一下我们的演示应用程序，我们将能够将我们的屏幕分解为许多逻辑视图，如下所示：

![Marionette views](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_06.jpg)

带有 Marionette 视图覆盖的板列表视图

我们需要构建的视图的确定与我们为 Backbone 集合和模型设置的数据结构密切相关。当我们将前面的视图叠加在我们的`ManufacturerCollection`类的类图上时，这种关系显而易见：

![Marionette views](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_07.jpg)

具有相应 Marionette 视图的模型类图

### ManufacturerCollectionView 类

我们从`ManufacturerCollectionView`开始，这是一个渲染整个`ManufacturerCollection`的视图。我们还需要一个`ManufacturerView`来渲染特定的`ManufacturerModel`，然后是一个`BoardView`来渲染制造商武器库中的每个板。每个板都有一个内部的`BoardSize`对象数组，因此我们将创建一个`BoardSizeView`来渲染这些项目。

让我们开始构建这些视图，从`ManufacturerCollectionView`开始：

```ts
export class ManufacturerCollectionView
    extends Marionette.CollectionView<bm.ManufacturerModel> {
    constructor(options?: any) {
        if (!options)
            options = {};
        options.el = '#manufacturer_collection';
        options.className = "row board_row";

        super(options);
        this.childView = ManufacturerView;

        var manufColl: bm.IManufacturerCollection = 
           TypeScriptTinyIoC.resolve(bm.IIManufacturerCollection);
        if (!options.collection) {
            this.collection = <Backbone.Collection<bm.ManufacturerModel>> manufColl;
        } else {
            this.collection = options.collection;
        }
    }
}
```

这个类扩展自`Marionette.CollectionView`，并将我们的`ManufacturerModel`指定为类的泛型类型。我们的`constructor`将`el`属性设置为`"＃manufacturer_collection"`的`options`对象。正如我们在`PageLayoutView`中看到的，Marionette 将使用此属性将整个集合渲染到 DOM 中。我们还在我们的`options`中设置了一个`className`属性。Marionette 将使用`className`属性将`class="…"`属性附加到外部 DOM 元素。这将在渲染的 HTML 中将`CSS`样式应用于`manufacturer_collection`元素的`row`和`board_row`。一旦我们正确构造了我们的`options`，我们调用`super(options)`将这些选项传递给基类构造函数。

`CollectionView`的`childView`属性指示 Marionette 为集合中找到的每个元素创建我们指定的类的实例。我们将这个`childView`属性设置为`ManfuacturerView`，因此 Marionette 将为集合中的每个元素构造一个新的`ManufacturerView`。

最后，在我们的构造函数中，我们使用我们的服务定位器模式查找`ManufacturerCollection`服务的一个实例，然后将内部的`this.collection`属性设置为返回的对象。一旦我们定义了`childView`类名，并设置了`this.collection`属性，Marionette 将自动创建我们的子视图的实例，并将它们呈现到 DOM 中。

请注意，对于`CollectionView`，我们不需要 HTML 模板或片段。这是因为我们将单个项目的渲染推迟到`childView`类。

### ManufacturerView 类

我们的`childView`类`ManufacturerView`如下：

```ts
export class ManufacturerView
    extends Marionette.CompositeView<Backbone.Model> {
    constructor(options?: any) {
        if (!options)
            options = {};
        options.template = _.template('<div></div>');
        super(options);
        this.collection = new Backbone.Collection(
            this.model.get('boards')
        );
        this.childView = BoardView;
        this.childViewOptions = { 
            parentIcon: this.model.get('manufacturer_logo')
        };
    }
}
```

在这种情况下，我们从`Marionette.CompositeView`派生我们的视图，并使用标准的`Backbone.Model`作为通用类型。因为我们的板列表视图中有多个制造商，我们实际上不需要为每个制造商渲染任何特定的内容。因此，我们的模板是一个简单的`<div></div>`。

这个视图的重要部分是为我们的`boards`数组设置一个新的`Backbone.Collection`，然后设置一个`childView`类来渲染集合中的每个`board`。我们的`childView`属性设置为`BoardView`，我们还设置了一个`childViewOptions`属性，将通过它传递给每个`BoardView`实例。请记住，每个`BoardView`显示制造商的标志，但这个标志图像是在制造商级别保存的。因此，我们需要将这些信息传递给每个创建的`BoardView`。Marionette 允许我们使用`childViewOptions`属性将任何额外的属性传递给子视图。在这里，我们在`childViewOptions`对象中定义了一个`parentIcon`属性，以便将制造商的标志传递给每个子`BoardView`类的实例。然后，这个`parentIcon`属性将通过`options`参数对子视图可用。

### BoardView 类

我们的`BoardView`类也是一个`CompositeView`，如下所示：

```ts
export class BoardView
    extends Marionette.CompositeView<bm.BoardModel> {
    constructor(options?: any) {
        if (!options)
            options = {};
            var snippetService: ISnippetService =
               TypeScriptTinyIoC.resolve(IISnippetService);
            options.template = _.template(
               snippetService.retrieveSnippet(
                  SnippetKey.BOARD_VIEW_SNIPPET)
            );
        super(options);

        this.model.set('parentIcon', options.parentIcon);

         this.collection =
            <any>(new Backbone.Collection(
                this.model.get('sizes')));
        this.childView = BoardSizeView;
        this.childViewContainer = 'tbody';

        var snippetService: ISnippetService = 
             TypeScriptTinyIoC.resolve(IISnippetService);
        this.childViewOptions = { 
             template: _.template(
                  snippetService.retrieveSnippet(
                      SnippetKey.BOARD_SIZE_MINI_VIEW_SNIPPET)
                )
        };

    }

}
```

这个`BoardView`构造函数做了几件事。首先，它检索名为`BOARD_VIEW_SNIPPET`的片段，用作自己的`template`。然后，它设置一个内部模型属性`parentIcon`，用于存储通过父视图的`options`参数传递的`parentIcon`属性。然后，我们为`sizes`数组创建一个新的`Backbone.Collection`，并将`childView`属性设置为`BoardSizeView`。`childViewContainer`属性告诉 Marionette 在我们的片段中有一个`<tbody></tbody>`的 HTML div，它应该用来渲染任何`childView`。最后，我们检索另一个名为`BOARD_SIZE_MINI_VIEW_SNIPPET`的片段，并将这个片段作为`template`属性传递给`childView`。

`BoardSizeView`类不是解析自己的 HTML 片段，而是将控制权移动到类层次结构的父类`BoardSizeView`的父类。这使我们能够在摘要视图中重用`BoardSizeView`类，以及在稍后将讨论的`BoardDetailView`中重用。由于摘要大小视图和详细大小视图的内部数据模型是相同的，唯一需要改变的是我们的 HTML 模板。因此，我们使用`childViewOption`属性将此模板传递到`BoardSizeView`中，就像我们之前看到的那样。

### BoardSizeView 类

我们的`BoardSizeView`类非常简单，如下所示：

```ts
export class BoardSizeView
    extends Marionette.ItemView<bm.BoardSize> {
    constructor(options?: any) {
        if (!options)
            options = {};
        super(options);
    }
}
```

这个类只是一个`ItemView`，它使用`BoardSize`模型作为通用类型。在这个类中我们没有任何自定义代码，而是简单地将它作为前面的`BoardView`类中的一个命名的`childView`。

现在让我们来看看我们将需要为每个视图准备的 HTML 片段。首先是我们的`BoardViewSnippet.html`。同样，您可以在附带的源代码中找到完整的片段。`BoardViewSnippet.html`的一般结构如下：

```ts
<div class="col-sm-4 board_panel">
    <div class="board_inner_panel">
         <div class="row board_title_row">
         <!- -some divs just for styling here -->
            <%= name %>
         <!- -some divs just for styling here -->
            <%= description %>
            <img src="img/<%= parentIcon %>" />
         </div>
         <div class="row board_details_row">
            <a >
                <img src="img/<%= image %>" />
            </a>
         <!- -some divs just for styling here -->
             Sizes:
             <table>
                <tbody></tbody>
             </table>
         </div>
    </div>
</div>
```

在这个片段中，我们包含了`<%= name %>`、`<%= description %>`、`<%= parentIcon %>`和`<%= image %>`语法作为我们模型属性的占位符。在片段的底部附近，我们创建了一个带有空的`<tbody></tbody>`标记的表。这个标记对应于我们在`BoardView`类中使用的`childViewContainer`属性，Marionette 将每个`BoardSizeView`项目呈现到这个`<tbody>`标记中。

我们的`BoardSizeMiniViewSnippet.html`如下：

```ts
<tr>
    <td>&nbsp;</td>
    <td><%= volume %> L</td>
</tr>
```

在这里，我们只对`BoardSize`模型的`<%= volume %>`属性感兴趣。有了这些视图类和两个片段，我们的板列表视图就完成了。我们需要做的就是在我们的`require.config`块中加载这些片段，并将适当的片段存储在我们的`SnippetService`实例上：

```ts
require([
    'BoardSalesApp', 'tinyioc', 'snippetservice'
    , 'text!/tscode/app/views/PageViewLayout.html'
    , 'text!/tscode/app/views/BoardViewSnippet.html'
    , 'text!/tscode/app/views/BoardSizeMiniViewSnippet.html'
    ],(app, tinyioc, snippetservice, pageViewLayoutSnippet
      , boardViewSnippet, bsMiniViewSnippet) => {

        var snippetService = new SnippetService();
        snippetService.storeSnippet(
            SnippetKey.PAGE_VIEW_LAYOUT_SNIPPET,
                pageViewLayoutSnippet);
        snippetService.storeSnippet(
            SnippetKey.BOARD_VIEW_SNIPPET, boardViewSnippet);
        snippetService.storeSnippet(
            SnippetKey.BOARD_SIZE_MINI_VIEW_SNIPPET,
                bsMiniViewSnippet);

        var boardSalesApp = new app.BoardSalesApp();
        boardSalesApp.start();

    });
```

### 使用 IFilterProvider 接口进行过滤

当我们组合`ManufacturerCollection`类时，我们编写了两个函数来查询数据结构，并返回制造商和板类型的列表。这两个函数分别称为`findManufacturerNames`和`findBoardTypes`。我们的新`FilterCollection`类将需要调用这些方法来从我们的“全局”数据集中检索过滤器值。

我们可以以两种方式实现这个功能。一种方式是通过`IIManufacturerCollection`命名接口获取对全局`ManufacturerCollection`实例的引用。然而，这个选项意味着`FilterCollection`的代码需要理解`ManufacturerCollection`的代码。实现这个功能的更好方式是获取对`IFilterProvider`接口的引用。然后，这个接口将只公开我们构建过滤器列表所需的两个方法。让我们采用这种第二种方法，并定义一个命名接口，如下所示：

```ts
export interface IFilterProvider {
    findManufacturerNames(): bm.IManufacturerName[];
    findBoardTypes(): string[]
}
export class IIFilterProvider implements IInterfaceChecker {
    methodNames = ['findManufacturerNames', 'findBoardTypes'];
    className = 'IIFilterProvider';
}
```

然后我们可以简单地修改现有的`ManufacturerCollection`以实现这个接口（它已经这样做了）：

```ts
export class ManufacturerCollection extends Backbone.Collection<ManufacturerModel>
    implements IManufacturerCollection, fm.IFilterProvider
{
    // existing code
}
```

我们现在可以在我们的`BoardSalesApp.onStart`方法中使用`TypeScriptTinyIoC`注册`ManufacturerCollection`到`IIFilterProvider`命名接口，如下所示：

```ts
onStart() {
        this.viewLayout.render();
        this._manufCollection = new bm.ManufacturerCollection();
        TypeScriptTinyIoC.register(this._manufCollection, bm.IIManufacturerCollection);
        TypeScriptTinyIoC.register(this._manufCollection,
            fm.IIFilterProvider);
        this._manufCollection.fetch({ 
            success: this.CollectionLoaded, error: this.CollectionLoadError });
}
```

我们现在已经注册了我们的`ManufacturerCollection`来提供名为`IIManfacturerCollection`的接口，以及名为`IIFilterProvider`的接口。

### FilterCollection 类

然后，我们的`FilterCollection`可以在其构造函数中解析`IIFilterProvider`接口，如下所示：

```ts
export class FilterCollection extends Backbone.Collection<FilterModel> {
    model = FilterModel;

    private _filterProvider: IFilterProvider;
    constructor(options?: any) {
        super(options);
        try {
            this._filterProvider = 
            TypeScriptTinyIoC.resolve(IIFilterProvider);
        } catch (err) {
            console.log(err);
        }
    }
}
```

在这里，我们将调用`TypeScriptTinyIoC`返回的类存储在名为`_filterProvider`的私有变量中。通过为`FilterProvider`定义这些接口，我们现在可以使用模拟`FilterProvider`对我们的`FilterCollection`进行单元测试，如下所示：

```ts
class MockFilterProvider implements fm.IFilterProvider {
    findManufacturerNames(): bm.IManufacturerName[] {
        return [ 
        { manufacturer: 'testManuf1',
          manufacturer_logo: 'testLogo1'}, { manufacturer: 'testManuf2',
          manufacturer_logo: 'testLogo2' }
        ];
    }
    findBoardTypes(): string[] {
        return ['boardType1', 'boardType2', 'boardType3'];
    }
}
describe('/tscode/tests/models/FilterModelTests',() => {
    beforeAll(() => {
        var mockFilterProvider = new MockFilterProvider();
        TypeScriptTinyIoC.register(
            mockFilterProvider, fm.IIFilterProvider);
    });
});
```

在我们的测试设置中，我们创建了一个实现我们的`IFilterProvider`接口的`MockFilterProvider`，并为我们的测试目的注册了它。通过使用模拟提供程序，我们还知道在我们的测试中可以期望什么数据。我们的实际测试将如下所示：

```ts
describe("FilterCollection tests",() => {
    var filterCollection: fm.FilterCollection;
    beforeAll(() => {
        filterCollection = new fm.FilterCollection();
        filterCollection.buildFilterCollection();
    });

    it("should have two manufacturers", () => {
        var manufFilter = filterCollection.at(0);
        expect(manufFilter.filterType)
           .toBe(fm.FilterType.Manufacturer);
        expect(manufFilter.filterValues[0].filterValue)
           .toContain('testManuf1');
    });

    it("should have two board types",() => {
        var manufFilter = filterCollection.at(1);
        expect(manufFilter.filterType)
           .toBe(fm.FilterType.BoardType);
        expect(manufFilter.filterValues[0].filterValue)
           .toContain('boardType1');
    });
});
```

这些测试从创建`FilterCollectionClass`的实例开始，然后调用`buildFilterCollection`函数。然后我们测试集合在索引`0`处是否有`FilterType.Manufacturer`，以及预期值。有了这些失败的测试，我们可以完善`buildFilterCollection`函数：

```ts
buildFilterCollection() {
    // build Manufacturer filter.
    var manufFilter = new FilterModel({
        filterType: FilterType.Manufacturer,
        filterName: "Manufacturer"
    });
    var manufArray = new Array<FilterValue>();
    if (this._filterProvider) {
        _(this._filterProvider.findManufacturerNames())
            .each((manuf) => {
                manufArray.push(new FilterValue(
                    { filterValue: manuf.manufacturer }));
        });
        manufFilter.filterValues = manufArray;
    }
    this.push(manufFilter);
    // build Board filter.
    var boardFilter = new FilterModel({
        filterType: FilterType.BoardType,
        filterName: "Board Type"
    });
	var boardTypeArray = new Array<FilterValue>();
    if (this._filterProvider) {
        _(this._filterProvider.findBoardTypes()).each((boardType) =>
        {
            boardTypeArray.push(new FilterValue(
                { filterValue: boardType }));
        });
        boardFilter.filterValues = boardTypeArray;
    }
    this.push(boardFilter);
    // build All filter to clear filters.
    var noFilter = new FilterModel({
        filterType: FilterType.None,
        filterName: "All"
    });
    var noTypeArray = new Array<FilterValue>();
    noTypeArray.push(new FilterValue({ filterValue: "Show All" }));
    noFilter.filterValues = noTypeArray;
    this.push(noFilter);
}
```

我们的`buildFilterCollection`函数正在创建三个`FilterModel`的实例。第一个实例名为`manufFilter`，其`filterType`设置为`FilterType.Manufacturer`，并使用`_filterProvider.findManufacterNames`函数来构建此`FilterModel`的值。然后通过调用`this.push(manufFilter)`将`manufFilter`实例添加到内部`collection`中。第二个和第三个`FilterModel`实例的`filterType`分别设置为`FilterType.BoardType`和`FilterType.None`。

## 过滤视图

当我们将视图叠加在我们的 Backbone 模型上时，我们需要实现的 Marionette 视图之间的关系很容易可视化如下：

![过滤视图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_09.jpg)

显示相关 Marionette 视图的过滤类图

第一个视图名为`FilterCollectionView`，将从`CollectionView`派生，并将与我们的顶级`FilterCollection`绑定。第二个视图名为`FilterModelView`，将是一个`CompositeView`，并将每个`FilterType`呈现到其自己的手风琴标题中。第三个和最后一个视图将是每个过滤选项的`ItemView`，名为 FilterItemView。

构建这些 Marionette 视图的过程与我们之前对制造商和板视图所做的工作非常相似。因此，我们不会在这里详细介绍每个视图的实现。请务必参考本章附带的示例代码，以获取这些视图及其相关 HTML 片段的完整列表。

现在我们在左侧面板上呈现了我们的过滤器，我们需要能够响应`FilterItemView`上的点击事件，并触发实际的过滤代码。

## Marionette 中的 DOM 事件

Marionette 提供了一个简单的语法来捕获 DOM 事件。任何视图都有一个名为`events`的内部属性，它将把 DOM 事件绑定到我们的 Marionette 视图上。然后，我们的`FilterItemView`可以更新以响应 DOM 事件，如下所示：

```ts
export class FilterItemView
    extends Marionette.ItemView<fm.FilterValue> {
    private _filterType: number;
    constructor(options?: any) {
        if (!options)
            options = {};
        options.tagName = "li";
        options.template = 
            _.template('<a><%= filterValue %></a>');

        options.events = { click: 'filterClicked' };
        this._filterType = options.filterType;
        super(options);
        _.bindAll(this, 'filterClicked');

    }
    filterClicked() {
        TypeScriptTinyIoC.raiseEvent(
            new bae.FilterEvent(
                this.model.get('filterValue'),
                    this._filterType),
            bae.IIFilterEvent);
    }
}
```

我们已经向我们的`options`对象添加了一个`events`属性，并为`click` DOM 事件注册了一个处理程序函数。每当有人点击`FilterItemView`时，Marionette 将调用`filterClicked`函数。我们还为此事件添加了一个`_.bindAll`调用，以确保在调用`filterClicked`函数时，`this`变量被限定为类实例。

请记住，每个`FilterItemView`的实例都可以通过内部的`model`属性获得相应的`FilterValue`模型。因此，在我们的`filterClicked`函数中，我们只是使用内部`model`变量的属性来引发一个新的`FilterEvent`。

我们的事件定义接口如下 - 再次，请参考匹配的`IInterfaceChecker`定义的示例代码：

```ts
export interface IFilterEvent {
    filterType: fm.FilterType;
    filterName: string;
}
export interface IFilterEvent_Handler {
    handle_FilterEvent(event: IFilterEvent);
}
```

现在我们可以在代码的其他地方注册这些过滤器事件的处理程序。将此事件处理程序放在`PageViewLayout`本身上是一个合乎逻辑的地方，因为这个类负责呈现板列表。我们将在`PageViewLayout`上定义我们的`handle_FilterEvent`函数如下：

```ts
handle_FilterEvent(event: ev.IFilterEvent) {

    var mainCollection: bm.ManufacturerCollection =
        TypeScriptTinyIoC.resolve(bm.IIManufacturerCollection);
    var filteredCollection;
    if (event.filterType == fm.FilterType.BoardType)
        filteredCollection = new bm.ManufacturerCollection(
            mainCollection.filterByBoardType(event.filterName));
    else if (event.filterType == fm.FilterType.Manufacturer)
        filteredCollection = new bm.ManufacturerCollection(
            mainCollection.filterByManufacturer(event.filterName));
    else if (event.filterType == fm.FilterType.None)
        filteredCollection = mainCollection;

    this._manufacturerView.collection = filteredCollection;
    this._manufacturerView.render();
}
```

该功能首先通过获取对我们“全局”注册的`ManufacturerCollection`的引用来开始。然后，我们定义一个名为`filteredCollection`的变量来保存我们对主`ManufacturerCollection`进行过滤的版本。根据事件本身的`FilterType`，我们调用`filterByBoardType`或`filterByManufacturer`。如果事件类型是`FilterType.None`，我们只需将`filteredCollection`设置为`mainCollection`，有效地清除所有过滤器。

该函数的最后部分将我们主视图（`this._manufacturerView`）的内部`collection`属性设置为结果`filteredCollection`，然后调用`render`。

我们的应用程序现在正在响应`FilterItemView`上的点击事件，触发一个事件，并重新渲染`ManufacturerView`，以便将所选的过滤器应用于我们的数据进行渲染。

### 触发详细视图事件

然而，我们还需要响应另一个点击事件。当用户点击特定的面板时，我们需要触发一个事件，将面板滑动过去，并显示详细的面板视图。

在我们继续讨论详细视图以及如何渲染它之前，让我们首先在`BoardView`类上挂接一个点击事件。为此，我们只需要在`BoardView`类的`options.events`参数上指定一个点击事件处理程序，类似于我们之前的点击事件处理程序。我们还需要创建一个`onClicked`函数，如下所示：

```ts
export class BoardView
    extends Marionette.CompositeView<bm.BoardModel> {
    constructor(options?: any) {
        // existing code
        options.events = {
            "click": this.onClicked,
        };

        super(options);

        // existing code
        _.bindAll(this, 'onClicked');
    }

    onClicked() {
        this.$el.find('.board_inner_panel').flip({
            direction: 'lr',
            speed: 100,
            onEnd: () => {
            TypeScriptTinyIoC.raiseEvent(
                new bae.BoardSelectedEvent(this.model),
                    bae.IIBoardSelectedEvent);
            }
        });
    }
}
```

对这个类的更改非常小，我们只需正确设置`options`上的`events`属性，发出对`_.bindAll`的调用，就像我们在`FilterItem`代码中所做的那样，然后编写一个`onClicked`函数。这个`onClicked`函数发出一个调用`flip`，就像我们在第七章中看到的那样，*模块化*，然后触发一个新的`BoardSelectedEvent`。我们的`BoardSelectedEvent`接口和处理程序接口如下-再次，请参考示例代码以获取匹配的`IInterfaceChecker`定义：

```ts
export interface IBoardSelectEvent {
    selectedBoard: bm.BoardModel;
}
export interface IBoardSelectedEvent_Handler {
    handle_BoardSelectedEvent(event: IBoardSelectEvent);
}
```

`BoardSelectedEvent`只是包含整个`BoardModel`本身，在`selectedBoard`属性中。有了这些事件接口和类，我们现在可以在代码的任何地方注册`BoardSelectedEvent`。

### 渲染 BoardDetailView

在这个应用程序中，处理`BoardSelectedEvent`的逻辑位置应该是在`PageViewLayout`中，因为它负责循环轮播面板，并渲染`BoardDetailView`。让我们按照以下方式更新这个类：

```ts
export class PageViewLayout extends Marionette.LayoutView<Backbone.Model>
    implements ev.INotifyEvent_Handler,
    ev.IBoardSelectedEvent_Handler,
    ev.IFilterEvent_Handler
{
    // existing code
    constructor(options?: any) {
        // existing code
        _.bindAll(this, 'handle_NotifyEvent');
        _.bindAll(this, 'handle_BoardSelectedEvent');
        TypeScriptTinyIoC.registerHandler(this, ev.IINotifyEvent_Handler, ev.IINotifyEvent);
        TypeScriptTinyIoC.registerHandler(this,
            ev.IIBoardSelectedEvent_Handler,
            ev.IIBoardSelectedEvent);
    }
    handle_BoardSelectedEvent(event: ev.IBoardSelectEvent) {
        var boardDetailView = new bdv.BoardDetailView(
            { model: event.selectedBoard });
        boardDetailView.render();
    }
}
```

在这里，我们已经更新了我们的`PageViewLayout`类以实现`IBoardSelectedEvent_Hander`接口，并将其注册到`TypeScriptTinyIoC`。我们通过创建一个新的`BoardDetailView`类来响应`BoardSelectedEvent`，使用事件中包含的完整`BoardModel`，然后调用`render`。我们的`BoardDetailView`类如下：

```ts
export class BoardDetailView
    extends Marionette.CompositeView<bm.BoardSize> {
    constructor(options?: any) {
        if (!options)
            options = {};

        options.el = "#board_detail_view";
        var snippetService: ISnippetService = 
            TypeScriptTinyIoC.resolve(IISnippetService);
        options.template = _.template(
            snippetService.retrieveSnippet(
                SnippetKey.BOARD_DETAIL_VIEW_SNIPPET));

        super(options);

        this.collection = <any>(
            new Backbone.Collection(this.model.get('sizes')));
        this.childView = mv.BoardSizeView;
        this.childViewContainer = 'tbody';

        var snippetService: ISnippetService = 
            TypeScriptTinyIoC.resolve(IISnippetService);
        this.childViewOptions = { 
               template: _.template(
                  snippetService.retrieveSnippet(
                    SnippetKey.BOARD_SIZE_VIEW_SNIPPET)), tagName: 'tr'
        };
    }

}
```

`BoardDetailView`类与我们的`BoardView`非常相似，但它使用`"＃board_detail_view"`元素作为`options.el`属性，这是我们对应的 DOM 元素。我们的片段具有`BOARD_DETAIL_VIEW_SNIPPET`键。然后我们从`sizes`属性创建一个`Backbone.Collection`，并将`childView`设置为`BoardSize`视图类模板，就像我们之前为`BoardView`所做的那样。

然而，我们的`childViewContainer`现在将目标定位到`<tbody></tbody>`标签以渲染子元素。我们还将模板从`BOARD_SIZE_VIEW_SNIPPET`传递给子`BoardSize`视图，并将`tagName`设置为`'tr'`。还记得我们如何将子`BoardSize`视图的配置移到`BoardView`中吗？嗯，我们在这里做同样的事情。

有关`BoardDetailViewSnippet.html`和`BoardSizeViewSnippet.html`的完整清单，请参考示例代码。

# 状态设计模式

我们这个应用程序的最后一个任务是在用户与我们的应用程序交互时控制各种屏幕元素。当用户导航应用程序时，我们需要从轮播面板 1 移动到轮播面板 2，并更新屏幕元素，例如显示和隐藏左侧的过滤面板。在大型 Web 应用程序中，可能会有许多屏幕元素，许多不同的过渡效果，以及诸如弹出窗口或遮罩等内容，显示**“加载中…”**，而我们的应用程序从后端服务获取数据。跟踪所有这些元素变得困难且耗时，通常会在代码的许多不同区域留下大量的 if-else 或 switch 语句，导致大量直接的 DOM 操作混乱。

状态设计模式是一种可以简化我们应用程序代码的设计模式，这样可以将操作这些不同 DOM 元素的代码放在一个地方。状态设计模式定义了应用程序可能处于的一组状态，并提供了一种简单的机制来在这些状态之间进行转换，控制视觉屏幕元素，并处理动画。

## 问题空间

作为我们试图实现的一个例子，考虑以下业务规则：

+   当用户首次登录到桌面上的 BoardSales 应用程序时，左侧的筛选面板应该可见。

+   如果用户使用移动设备，当用户首次登录时，左侧的筛选面板不应该可见。这样做是为了节省屏幕空间。

+   如果筛选面板可见，则展开图标应该切换为左箭头（<），以允许用户隐藏它。

+   如果筛选面板不可见，则展开图标应该是右箭头（>），以允许用户显示它。

+   如果用户展开了筛选面板，然后切换到看板详细视图，然后再切回来，那么筛选面板应该保持展开状态。

+   如果用户隐藏了筛选面板，然后切换到看板详细视图，然后再切回来，那么筛选面板应该保持隐藏状态。

除了这些业务规则之外，我们还有一个已经报告给使用 Firefox 浏览器的用户的未解决 bug（您可以使用演示 HTML 页面测试此行为）：

在看板列表视图中点击一个看板时，如果筛选面板是打开的，轮播面板就不会正确地行为。轮播首先跨越到看板详细视图，然后关闭筛选面板。这种转换与其他浏览器不一致，在其他浏览器中，筛选面板与看板列表同时循环。

因此，这个 bug 给我们的清单增加了另一个业务需求：

+   对于使用 Firefox 浏览器的用户，请在循环轮播到看板详细视图之前先隐藏筛选面板。

状态设计模式使用一组非常相似的类，每个类代表特定的应用程序状态。这些状态类都是从同一个基类派生的。当我们希望应用程序切换到不同的状态时，我们只需切换到表示我们感兴趣的状态的对象。

例如，我们的应用实际上只有三种状态。我们有一个状态，其中看板列表和筛选面板都是可见的。我们有另一个状态，只有看板列表是可见的，我们的第三个状态是看板详细面板可见。根据我们所处的状态，我们应该在`carousel_panel_1`上，或者在`carousel_panel_2`上。此外，与筛选面板一起使用的图标需要根据应用程序状态从左手的尖角`<`切换到右手的尖角`>`。

状态设计模式还有一个中介者类的概念，它将跟踪当前状态，并包含如何在这些状态之间切换的逻辑。

## 状态类图

考虑以下状态和中介者设计模式的类图：

![状态类图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_09_10.jpg)

状态和中介者模式类图

我们从一个名为`StateType`的枚举开始，列出了我们的三种应用程序状态，第二个名为`PanelType`的枚举用于指示每个状态所在的轮播面板。然后，我们定义了一个名为`IState`的接口，每个状态都必须实现该接口。为了保存每个状态的公共属性，我们还定义了一个名为`State`的基类，所有状态都将从中派生。我们的实现如下所示：这些枚举，`IState`接口和基类`State`。

```ts
export enum StateType {
    BoardListOnly,
    BoardListWithFilter,
    BoardDetail,
}
export enum PanelType { Initial, Secondary }
export interface IState {
    getPanelType(): PanelType;
    getStateType(): StateType;
    getShowFilterClass(): string;
    isFilterPanelVisible(): boolean;
}
export class State {
    private _mediator: sm.Mediator;
    constructor(mediator: sm.Mediator) {
        this._mediator = mediator;
    }
}
```

我们的`StateType`枚举已经定义了我们将使用的每个状态。因此，我们的应用程序可能处于`BoardListOnly`状态、`BoardListWithFilter`状态或`BoardDetail`状态。我们的第二个枚举，名为`PanelType`，用于指示我们当前位于哪个旋转木马面板，即`Initial`面板（carousel_panel_1）或`Secondary`面板（carousel_panel_2）。

然后我们定义了一个`IState`接口，所有状态对象都必须实现。此接口允许我们查询每个状态，并确定四个重要信息。 `getPanelType`函数告诉我们我们当前应该查看哪个面板，`getStateType`函数返回`StateType`枚举值。 `getShowFilterClass`函数将返回一个字符串，用于将 CSS 类应用于显示/隐藏过滤按钮，`isFilterPanelVisible`函数返回一个布尔值，指示过滤面板是否可见。

每个状态都需要引用“中介者”类，因此我们创建了一个带有`constructor`函数的基本`State`类，从中可以派生出我们的每个 State 对象。

### 具体状态类

现在让我们为每个状态创建具体类。我们的应用程序可能处于的第一个状态是，当我们查看看板列表时，过滤面板是隐藏的：

```ts
export class BoardListOnlyState
    extends ss.State
    implements ss.IState {
    constructor(mediator: sm.Mediator) {
        super(mediator);
    }
    getPanelType(): ss.PanelType {
        return ss.PanelType.Initial;
    }
    getShowFilterClass() {
        return "glyphicon-chevron-right";
    }
    isFilterPanelVisible(): boolean {
        return false;
    }
    getStateType(): ss.StateType {
        return ss.StateType.BoardListOnly;
    }
}
```

我们的`BoardListOnlyState`类扩展了我们之前定义的`State`类，并实现了`IState`接口。在这种`BoardListOnly`状态下，我们应该在`Initial`旋转木马面板上，用于显示/隐藏过滤面板按钮的类应该是`glyphicon-chevron-right` [ `>` ]，左侧的过滤面板不应该可见。

我们的应用程序可能处于的下一个状态是，当看板列表显示时，我们还可以看到过滤面板：

```ts
export class BoardListWithFilterPanelState
    extends ss.State 
    implements ss.IState {
    constructor(mediator: sm.Mediator) {
        super(mediator);
    }
    getPanelType(): ss.PanelType {
        return ss.PanelType.Initial;
    }
    getShowFilterClass() {
        return "glyphicon-chevron-left";
    }
    isFilterPanelVisible(): boolean {
        return true;
    }
    getStateType(): ss.StateType {
        return ss.StateType.BoardListWithFilter;
    }
}
```

在`BoardListWithFilterPanel`状态下，我们的旋转木马面板再次是`Initial`面板，但我们用于显示/隐藏过滤面板按钮的类现在是`glyphicon-chevron-left`（<）。我们的过滤面板也是可见的。

我们需要为我们的应用程序定义的最后一个状态是，当我们循环到`carousel_panel_2`并查看看板详细信息屏幕时：

```ts
export class DetailPanelState
    extends ss.State
    implements ss.IState {
    constructor(mediator: sm.Mediator) {
        super(mediator);
    }
    getPanelType(): ss.PanelType {
        return ss.PanelType.Secondary;
    }
    getShowFilterClass() {
        return "";
    }
    isFilterPanelVisible(): boolean {
        return false;
    }
    getStateType(): ss.StateType {
        return ss.StateType.BoardDetail;
    }
}
```

在`DetailPanel`状态下，我们位于`Secondary`旋转木马面板上，我们不需要一个用于显示/隐藏过滤面板按钮的类（因为面板已经移出屏幕），过滤面板本身也不可见。

请注意，在示例应用程序源代码中，您将找到一系列单元测试，测试每个属性。出于简洁起见，我们在这里不列出它们。

## 中介者类

在面向对象的模式中，中介者用于封装一组对象交互的逻辑。在我们的情况下，我们有一组状态，定义了应该显示哪些视觉元素。还需要定义这些不同元素如何根据这些状态之间的移动进行过渡。

因此，我们将定义一个“中介者”类来封装所有这些过渡逻辑，并根据状态之间的移动协调对我们的视觉元素的更改。为了使我们的“中介者”类与 UI 交互，我们将定义一组四个函数，任何使用此“中介者”的类都必须实现：

```ts
export interface IMediatorFunctions {
    showLeftPanel();
    hideLeftPanel();
    cyclePanels(forwardOrNext: string);
    showFilterButtonChangeClass(
        fromClass: string, toClass: string
    );
}
```

我们的`IMediatorFunctions`接口有四个函数。`showLeftPanel`函数将显示我们的过滤面板。`hideLeftPanel`函数将隐藏过滤面板。`cyclePanels`函数将以`'prev'`字符串或`'next'`字符串调用，以将轮播面板从`carousel_panel_1`循环到`carousel_panel_2`。`showFilterButtonChangeClass`将以两个参数调用——一个是 CSS 类的`fromClass`字符串，另一个是另一个 CSS 类的`toClass`字符串。这个函数将从 DOM 元素中删除`fromClass` CSS 类，然后将`toClass` CSS 类添加到 DOM 元素中。通过这种方式，我们可以将用于显示/隐藏过滤按钮的图标从 chevron-right（`>`）更改为 chevron-left（`<`）。

现在我们可以看一下`Mediator`类本身的内部逻辑，从一组私有变量和构造函数开始：

```ts
export class Mediator {
    private _currentState: ss.IState;
    private _currentMainPanelState: ss.IState;
    private _pageViewLayout: IMediatorFunctions;
    private _isMobile: boolean;

    private _mainPanelState: as.BoardListOnlyState;
    private _detailPanelState: as.DetailPanelState;
    private _filterPanelState: as.BoardListWithFilterPanelState;

    constructor(pageViewLayout: IMediatorFunctions,
        isMobile: boolean) {
        this._pageViewLayout = pageViewLayout;
        this._isMobile = isMobile;

        this._mainPanelState = new as.BoardListOnlyState(this);
        this._detailPanelState = new as.DetailPanelState(this);
        this._filterPanelState = new as.BoardListWithFilterPanelState(this);

        if (this._isMobile)
            this._currentState = this._mainPanelState;
        else
            this._currentState = this._filterPanelState;
        this._currentMainPanelState = this._currentState;
    }
}
```

我们的`Mediator`类有许多私有变量。`_currentState`变量用于保存我们`State`类之一的实例，并表示 UI 的当前状态。这个`_currentState`变量可以保存我们三个状态中的任何一个。`_currentMainPanelState`变量再次保存我们的`State`类之一，但表示主面板的当前状态。这个`_currentMainPanelState`只会保存`BoardListOnlyState`或`BoardListWithFilterPanelState`中的一个。

`_pageViewLayout`变量将保存实现我们的`IMediatorFunctions`接口的类的实例，我们将通过这个变量对 UI 应用状态变化。对于熟悉 MVP 模式的人来说，`Mediator`类充当 Presenter，`_pageViewLayout`变量充当 View。

`_isMobile`变量只是保存一个布尔值，指示我们是否在移动设备上。我们稍后会设置这个变量。

然后我们有三个私有变量，它们将保存我们三个状态的实例——`BoardListOnlyState`、`DetailPanelState`和`BoardListWithFilterPanelState`。

我们的构造函数简单地设置了这些私有变量，然后实例化了我们每个状态类的一个实例，并将它们分配给正确的内部变量。

请注意构造函数底部附近的代码。这是我们一个业务规则的实现。如果应用程序在移动设备上查看，则过滤面板默认情况下不应可见。因此，我们将`_currentState`变量的值设置为初始状态之一，基于我们的`isMobile`标志。为了完成构造函数功能，我们还将`_currentMainPanelState`变量的初始值设置为`_currentState`。

我们的下一个`Mediator`函数`getNextState`只是使用`StateType`枚举作为输入返回我们的私有`State`变量之一：

```ts
private getNextState(stateType: ss.StateType): ss.IState {
    var nextState: ss.IState;
    switch (stateType) {
       case ss.StateType.BoardDetail:
            nextState = this._detailPanelState;
            break;
        case ss.StateType.BoardListOnly:
            nextState = this._mainPanelState;
            break;
        case ss.StateType.BoardListWithFilter:
            nextState = this._filterPanelState;
    }
    return nextState;
}
```

这本质上是一个迷你工厂方法，将根据`StateType`参数的值返回正确的内部`State`对象。

### 转移到新状态

控制 UI 如何根据状态之间的移动更新的主要逻辑体现在`moveToState`函数中，如下所示：

```ts
public moveToState(stateType: ss.StateType) {
    var previousState = this._currentState;
    var nextState = this.getNextState(stateType);

    if (previousState.getPanelType() == ss.PanelType.Initial &&
        nextState.getPanelType() == ss.PanelType.Secondary) {
        this._pageViewLayout.hideLeftPanel();
        this._pageViewLayout.cyclePanels('next');
    }

    if (previousState.getPanelType() == ss.PanelType.Secondary &&
        nextState.getPanelType() == ss.PanelType.Initial) {
        this._pageViewLayout.cyclePanels('prev');
    }

    this._pageViewLayout.showFilterButtonChangeClass(
        previousState.getShowFilterClass(),
        nextState.getShowFilterClass()
    );

    if (nextState.isFilterPanelVisible())
        this._pageViewLayout.showLeftPanel();
    else
        this._pageViewLayout.hideLeftPanel();

    this._currentState = nextState;
    if (this._currentState.getStateType() == ss.StateType.BoardListOnly 
       || this._currentState.getStateType() == ss.StateType.BoardListWithFilter)
        this._currentMainPanelState = this._currentState;
}
```

这个函数将在我们想要从一个状态转换到另一个状态时调用。这个函数做的第一件事是设置两个变量：`previousState`和`nextState`。`previousState`变量实际上是我们当前的状态对象，而`nextState`变量是我们要转移到的状态的`State`对象。

现在我们可以比较`previousState`变量和`nextState`变量并做出一些决定。

我们第一个 if 语句的逻辑大致如下：如果我们从`Initial`面板类型移动到`Secondary`面板，则调用 UI 上的相关函数隐藏左侧面板，并启动轮播循环到`'next'`。这个逻辑将修复我们之前收到的 Firefox 错误。

我们第二个 if 语句的逻辑与第一个相反：如果我们从`Secondary`面板移动到`Initial`面板，那么就用`'prev'`来启动轮播循环。

我们逻辑的下一步是通过在 UI 上调用`showFilterButtonChangeClass`函数，将显示/隐藏过滤按钮的类应用到 UI 上，传入来自`previousState`的 CSS 类名和来自`nextState`的 CSS 类名作为参数。请记住，这将从`previousState`中移除 CSS 类，然后将`nextState`中的 CSS 类添加到显示/隐藏过滤按钮的 CSS 中。

我们的下一个逻辑步骤是检查过滤面板是否应该显示或隐藏，并在我们的`_pageViewLayout`上调用相应的函数。

由于我们现在已经完成了状态更改逻辑，并且可以将`_currentState`变量的值设置为持有我们的`nextState`。

最后一部分逻辑只是检查我们当前是否处于`BoardListOnly`或`BoardListWithFilter`状态，如果是的话，将当前状态存储在`_currentMainPanelState`变量中。这个逻辑将成为我们已经给出的业务规则的一部分，以确保当我们从主面板切换到详细面板，然后再切换回来时，过滤面板的状态被正确地维护。

我们的`Mediator`类中还有两个要讨论的函数，如下所示：

```ts
public showHideFilterButtonClicked() {
    switch (this._currentState.getStateType()) {
        case ss.StateType.BoardListWithFilter:
            this.moveToState(ss.StateType.BoardListOnly);
            break;
        case ss.StateType.BoardListOnly:
            this.moveToState(ss.StateType.BoardListWithFilter);
            break;
    }
}

public getCurrentMainPanelState(): ss.IState {
    return this._currentMainPanelState;
}
```

第一个函数叫做`showHideFilterButtonClicked`，实际上是当我们在应用程序中点击显示/隐藏过滤按钮时需要调用的函数。根据过滤面板是打开还是关闭，此按钮的行为会略有不同。唯一知道根据应用程序的状态该做什么的对象是`Mediator`类本身。因此，我们将决定当按钮被点击时该做什么的决策推迟到`Mediator`类。

`showHideFilterButtonClicked`函数的实现只是检查我们当前的状态是什么，然后调用一个带有正确`nextState`作为参数的`moveToState`。

### 注意

当构建大型应用程序时，可能会有许多不同的按钮或屏幕元素，这些元素会根据应用程序的状态稍有不同。将决策逻辑推迟到中介者类提供了一种简单而优雅的方式来管理所有屏幕元素。这个业务逻辑被捕获在一个地方，并且也可以得到充分的测试。一定要检查中介者类周围的完整测试套件的示例代码。

我们的最后一个函数`getCurrentMainPanelState`只是返回我们主面板的最后已知状态，并将用于实现业务逻辑，以记住过滤面板是打开还是关闭。

## 实现 IMediatorFunctions 接口

当`Mediator`类需要触发对 UI 的更改时，它会调用`IMediatorFunctions`接口上的函数，就像我们之前看到的那样。因此，我们的应用程序必须在某个地方实现这个`IMediatorFunctions`接口。由于`PageViewLayout`类持有我们需要更改的每个 UI 元素的引用，因此实现这个接口的逻辑地方是在`PageViewLayout`类本身，如下所示：

```ts
export class PageViewLayout extends
    Marionette.LayoutView<Backbone.Model>
    implements ev.INotifyEvent_Handler,
    ev.IBoardSelectedEvent_Handler,
    ev.IFilterEvent_Handler,
    sm.IMediatorFunctions
{
    private _mediator: sm.Mediator;
    constructor(options?: any) {
        // existing code
        options.events = {
             "click #show_filter_button": 
             this.showHideFilterButtonClicked
           };
        // existing code
        var isMobile = $('html').hasClass('mobile');
        this._mediator = new sm.Mediator(this, isMobile);
        // existing code
    }
    // existing functions
    showLeftPanel() {
        $('#content_panel_left')
            .removeClass('sidebar_panel_push_to_left');
        $('#content_panel_main')
            .removeClass('main_panel_push_to_left');
    }
    hideLeftPanel() {
        $('#content_panel_left')
            .addClass('sidebar_panel_push_to_left');
        $('#content_panel_main')
            .addClass('main_panel_push_to_left');
    }
    cyclePanels(forwardOrNext: string) {
      $('#carousel-main-container').carousel(forwardOrNext);
    }
    showFilterButtonChangeClass(
       fromClass: string, toClass: string) {
           $('#show_filter_button')
            .removeClass(fromClass).addClass(toClass);
    }
    showHideFilterButtonClicked() {
      this._mediator.showHideFilterButtonClicked();
    }
    // existing functions
}
```

我们已经更新了我们的`PageViewLayout`类，以实现`IMediatorFunctions`接口中的所有函数。我们还包括了一个名为`_mediator`的私有变量，用于保存`Mediator`类的一个实例，并在我们的构造函数中设置这个实例。

与我们的其他需要响应点击事件的视图一样，我们设置了一个`options.events`对象，将 DOM 上的`click`事件与`#show_filter_button` DOM 元素（我们的显示/隐藏按钮）绑定到`showHideFilterButtonClicked`函数上。

### 注意

我们正在使用 jQuery 来检查我们页面中的主 HTML 元素是否有一个名为`mobile`的类。这个类将由我们在本章开头包含在`index.html`页面中的`head.js`实用程序脚本设置。通过这种方式，我们能够确定我们的应用程序是在移动设备上还是在桌面设备上使用。

`showLeftPanel`和`hideLeftPanel`函数只是包含了 jQuery 片段，以应用或移除相关的类，以便滑动筛选面板进入或退出。

`cyclePanels`函数调用我们的 Bootstrap 轮播函数，带有`'next'`或`'prev'`参数，就像我们在演示 HTML 页面中所做的那样。

`showFilterButtonChangeClass`只是从我们的`show_filter_button` DOM 元素中移除`fromClass` CSS 样式，然后添加新的`toClass` CSS 样式。移除和添加这些 CSS 类将切换按钮的显示，从左切换到右（`<`到`>`），或者反之。

当用户点击`#show_filter_button` DOM 元素时，我们的`showHideFilterButtonClicked`方法将被调用。正如之前讨论的，我们正在将这个调用转发到`Mediator`实例，以便`Mediator`逻辑可以决定当按钮被点击时该做什么。

## 触发状态变化

为了完成我们的状态和中介者设计模式，我们现在只需要在正确的位置调用`Mediator`函数，以触发逻辑移动到不同的状态。

我们第一次调用`moveToState`函数的地方是在我们的`handle_NotifyEvent`中，当我们的`ManufacturerDataLoaded`事件被触发时。这个事件在我们的应用程序中只会发生一次，那就是在`ManufacturerCollection`成功加载之后。我们已经在我们的`PageViewLayout`类中有一个事件处理程序，所以让我们更新这个函数如下：

```ts
handle_NotifyEvent(event: ev.INotifyEvent) {
    if (event.eventType == ev.EventType.ManufacturerDataLoaded) {
        // existing code
        this._manufacturerView =
            new mv.ManufacturerCollectionView();
        this._manufacturerView.render();

        this._mediator.moveToState(
            this._mediator
                .getCurrentMainPanelState().getStateType()
              );
    }
    if (event.eventType == ev.EventType.BoardDetailBackClicked) {
        this._mediator.moveToState(
            this._mediator.getCurrentMainPanelState()
               .getStateType()
            );
    }
}
```

我们的第一个`if`语句检查`ManufacturerDataLoaded`事件类型，然后创建一个新的`ManufacturerCollectionView`并调用它的`render`函数，就像我们之前看到的那样。然后我们调用`moveToState`函数，传入中介者的`currentMainPanelState`作为参数。还记得我们如何在中介者的构造函数中根据浏览器是否在移动设备上设置了初始主面板状态吗？这次对`moveToState`的调用将使用该初始状态作为参数，从而在正确的状态下启动应用程序。

我们的第二个`if`语句将在用户在`BoardDetail`屏幕上，并在标题面板上点击返回按钮时触发`moveToState`。这个逻辑再次使用`currentMainPanelState`根据我们的业务规则将我们的板块列表恢复到正确的状态。

`PageLayoutView`中的另一个函数将触发对`moveToState`的调用，是我们对`BoardSelectedEvent`的处理程序：

```ts
handle_BoardSelectedEvent(event: ev.IBoardSelectEvent) {
    var boardDetailView = new bdv.BoardDetailView(
       { model: event.selectedBoard });
    boardDetailView.render();

    this._mediator.moveToState(ss.StateType.BoardDetail);
}
```

每当用户在板块列表中点击一个板块时，都会触发一个`BoardSelectedEvent`，然后我们渲染`BoardDetailView`。然而，这个`BoardDetailView`位于第二个轮播面板上，所以我们需要在这个事件处理程序中移动到`BoardDetail`状态。

最后，当用户在`BoardDetailView`中，并点击返回按钮时，我们需要触发`moveToState`函数。为了实现这一点，我们需要从我们的`BoardDetailView`中触发一个`NotifyEvent`，并将`eventType`设置为`BoardDetailBackClicked`，如下所示：

```ts
export class BoardDetailView
    extends Marionette.CompositeView<bm.BoardSize> {
    constructor(options?: any) {
        // existing code
        options.events = {
            "click #prev_button": this.onPrev
           };
        super(options);
        // existing code
    }

    onPrev() {
        TypeScriptTinyIoC.raiseEvent(
            new bae.NotifyEvent(bae.EventType.BoardDetailBackClicked),
            bae.IINotifyEvent);
    }
}
```

在这里，我们将`onPrev`函数绑定到`#prev_button`元素上的 DOM`click`事件。一旦触发了点击，我们只需要触发一个新的`NotifyEvent`，并将`eventType`设置为`BoardDetailBackClicked`，以触发`moveToState`函数调用。

有了我们的状态和中介者设计模式类，我们的示例应用现在已经完成。

# 总结

在本章中，我们从头开始构建了一个完整的 TypeScript 单页应用程序。我们从应用程序设计的初始想法开始，以及我们希望页面如何过渡。然后，我们使用现成的 Bootstrap 元素构建了一个纯 HTML 演示页面，并添加了一些 JavaScript 魔法来创建一个完整的演示页面。我们对 HTML 应用了各种样式，在 Brackets 中预览，并调整外观，直到满意为止。

我们接下来的主要步骤是理解并处理我们应用程序中需要的数据结构。我们编写了 Jasmine 单元测试和集成测试来巩固我们的 Backbone 模型和集合，并编写了我们需要的过滤函数。

然后，我们建立了一组 Marionette 视图，并将我们的演示 HTML 拆分成每个视图使用的片段。我们将视图与我们的集合和模型联系起来，并使用接口与数据提供程序一起工作。我们的应用程序随后开始通过使用真实的服务器端数据来完善。

最后，我们讨论了页面过渡策略，并实现了状态和中介者设计模式来实现我们所需的业务逻辑。

希望您喜欢从头开始构建应用程序的旅程——从概念到可视化，然后通过实施和测试。我们最终到达了一个工业强度、企业就绪的 TypeScript 单页 Marionette 应用程序。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。
