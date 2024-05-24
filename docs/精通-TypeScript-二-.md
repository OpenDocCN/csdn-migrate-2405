# 精通 TypeScript（二）

> 原文：[`zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E`](https://zh.annas-archive.org/md5/EF6D1933EE7A1583ABD80988FCB79F1E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：编写和使用声明文件

JavaScript 开发最吸引人的一个方面是已经发布的大量外部 JavaScript 库，比如 jQuery、Knockout 和 Underscore。TypeScript 的设计者知道，向 TypeScript 语言引入“语法糖”将为开发人员带来一系列好处。这些好处包括 IDE 功能，如智能感知，以及详细的编译时错误消息。我们已经看到了如何将这种语法应用于大多数 TypeScript 语言特性，比如类、接口和泛型，但是我们如何将这种“糖”应用于现有的 JavaScript 库呢？答案相对简单——声明文件。

声明文件是 TypeScript 编译器使用的一种特殊类型的文件。它以`.d.ts`扩展名标记，然后在编译步骤中由 TypeScript 编译器使用。声明文件类似于其他语言中使用的头文件；它们只是描述可用函数和属性的语法和结构，但不提供实现。因此，声明文件实际上不会生成任何 JavaScript 代码。它们只是用来提供 TypeScript 与外部库的兼容性，或者填补 TypeScript 不了解的 JavaScript 代码的空白。为了在 TypeScript 中使用任何外部 JavaScript 库，您将需要一个声明文件。

在本章中，我们将探讨声明文件，展示它们背后的原因，并基于一些现有的 JavaScript 代码构建一个声明文件。如果您熟悉声明文件以及如何使用它们，那么您可能会对*声明语法参考*部分感兴趣。本节旨在作为模块定义语法的快速参考指南。由于编写声明文件只是 TypeScript 开发的一小部分，我们并不经常编写它们。*声明语法参考*部分展示了等效 JavaScript 语法的示例声明文件语法。

# 全局变量

大多数现代网站都使用某种服务器引擎来生成它们的网页 HTML。如果您熟悉微软技术栈，那么您会知道 ASP.NET MVC 是一个非常流行的服务器端引擎，用于基于主页面、部分页面和 MVC 视图生成 HTML 页面。如果您是 Node 开发人员，那么您可能正在使用其中一个流行的 Node 包来帮助您通过模板构建网页，比如 Jade 或嵌入式 JavaScript（EJS）。

在这些模板引擎中，您有时可能需要根据后端逻辑在 HTML 页面上设置 JavaScript 属性。举个例子，假设您在后端数据库中保存了一组联系人电子邮件地址，然后通过名为`CONTACT_EMAIL_ARRAY`的 JavaScript 全局变量将其呈现到前端 HTML 页面上。您的渲染的 HTML 页面将包含一个包含这个全局变量和联系人电子邮件地址的`<script>`标签。您可能有一些 JavaScript 代码来读取这个数组，然后在页脚中呈现这些值。以下 HTML 示例显示了 HTML 页面中生成的脚本可能看起来像什么：

```ts
<body>
    <script type="text/javascript">
        var CONTACT_EMAIL_ARRAY = [
            "help@site.com",
            "contactus@site.com",
            "webmaster@site.com"
        ];
    </script>
</body>
```

这个 HTML 文件有一个脚本块，在这个脚本块中有一些 JavaScript。JavaScript 只是一个名为`CONTACT_EMAIL_ARRAY`的变量，其中包含一些字符串。假设我们想编写一些 TypeScript 代码来读取这个全局变量。考虑以下 TypeScript 代码：

```ts
class GlobalLogger {
    static logGlobalsToConsole() {
        for (var i = 0; i < CONTACT_EMAIL_ARRAY.length; i++) {
            console.log("found contact : " + CONTACT_EMAIL_ARRAY[i]);
        }
    }
}

window.onload = () => {
    GlobalLogger.logGlobalsToConsole();
}
```

这段代码创建了一个名为`GlobalLogger`的类，其中包含一个名为`logGlobalsToConsole`的静态函数。该函数只是遍历`CONTACT_EMAIL_ARRAY`全局变量，并将数组中的项记录到控制台中。

如果我们编译这段 TypeScript 代码，将会生成以下错误：

```ts
error TS2095: Build: Could not find symbol 'CONTACT_EMAIL_ARRAY'.

```

这个错误表明 TypeScript 编译器对名为`CONTACT_EMAIL_ARRAY`的变量一无所知。它甚至不知道它是一个数组。由于这段 JavaScript 代码位于任何 TypeScript 代码之外，我们需要以与“外部”JavaScript 相同的方式处理它。

为了解决我们的编译问题，并使`CONTACT_EMAIL_ARRAY`变量对 TypeScript 可见，我们需要使用一个声明文件。让我们创建一个名为`globals.d.ts`的文件，并在其中包含以下 TypeScript 声明：

```ts
declare var CONTACT_EMAIL_ARRAY: string [];
```

首先要注意的是，我们使用了一个新的 TypeScript 关键字：`declare`。`declare`关键字告诉 TypeScript 编译器，我们想要定义某个东西的类型，但这个对象（或变量或函数）的实现将在运行时解析。我们声明了一个名为`CONTACT_EMAIL_ARRAY`的变量，其类型为字符串数组。这个`declare`关键字为我们做了两件事：它允许在 TypeScript 代码中使用变量`CONTACT_EMAIL_ARRAY`，并且还将这个变量强类型为字符串数组。

### 注意

TypeScript 编译器的 1.0 版本及更高版本将扫描我们的源代码目录以寻找`.d.ts`文件，并自动包含它们在编译步骤中。在以前的版本中，需要包含一个注释作为对这些文件的引用，但现在不再需要这个引用注释行。

有了`globals.d.ts`文件，我们的代码可以正确编译。如果我们现在在浏览器中运行它，输出将如下所示：

```ts
found contact : help@site.com
found contact : contactus@site.com
found contact : webmaster@site.com

```

因此，通过使用名为`globals.d.ts`的声明文件，我们已经能够描述“外部”JavaScript 变量的结构给 TypeScript 编译器。这个 JavaScript 变量是在我们的任何 TypeScript 代码之外定义的，但我们仍然能够在 TypeScript 中使用这个变量的定义。

这就是声明文件的用途。基本上，我们告诉 TypeScript 编译器在编译步骤中使用声明文件中找到的定义，并且实际的变量本身只在运行时可用。

### 注意

定义文件还为我们的 IDE 带来了外部 JavaScript 库和代码的智能提示或代码补全功能。

# 在 HTML 中使用 JavaScript 代码块

我们刚刚看到的示例是在您的网页上生成的 HTML 内容（其中包含脚本块中的 JavaScript 代码）与实际运行的 JavaScript 之间紧密耦合的一个例子。然而，您可能会认为这是一个设计缺陷。如果网页需要一个联系人电子邮件数组，那么 JavaScript 应用程序应该简单地向服务器发送一个 AJAX 请求以获取相同的 JSON 格式信息。虽然这是一个非常合理的论点，但在某些情况下，将内容包含在呈现的 HTML 中实际上更快。

曾经有一个时代，互联网似乎能够在眨眼之间发送和接收大量信息。互联网的带宽和速度呈指数增长，台式机的内存和处理器速度也在不断提高。在互联网高速发展阶段，作为开发人员，我们不再考虑典型用户在其设备上拥有多少内存。我们也不再考虑我们通过网络发送了多少数据。这是因为互联网速度如此之快，浏览器处理速度似乎是无限的。

是的，然后移动电话出现了，感觉就像我们回到了 20 世纪 90 年代，互联网连接非常缓慢，屏幕分辨率很小，处理能力有限，内存很少（还有像*Elevator Action*这样的流行街机游戏，可以在[`archive.org/details/Elevator_Action_1985_Sega_Taito_JP_en`](https://archive.org/details/Elevator_Action_1985_Sega_Taito_JP_en)找到）。这个故事的要点是，作为现代网页开发人员，我们仍然需要注意运行在移动电话上的浏览器。这些浏览器有时在非常有限的互联网连接上运行，这意味着我们必须仔细测量我们的 JavasScript 库、JSON 数据和 HTML 页面的大小，以确保我们的应用程序即使在移动浏览器上也是快速和可用的。

在渲染的 HTML 页面中包含 JavaScript 变量或较小的静态 JSON 数据的技术通常为我们提供了在旧浏览器或现代手机上快速渲染屏幕的最快方式。许多流行的网站使用这种技术在通过异步 JSON 请求传递主要内容之前，快速渲染页面的一般结构（标题、侧边栏、页脚等）。这种技术之所以有效，是因为它能更快地渲染页面，并为用户提供更快的反馈。

## 结构化数据

让我们用一些更相关的数据增强这个简单的联系人电子邮件数组。对于这些电子邮件地址中的每一个，我们现在想要包含一些文本，我们将在页面的页脚中渲染，以及电子邮件地址。考虑以下使用 JSON 结构的全局变量的 HTML 代码：

```ts
<script type="text/javascript">
    var CONTACT_DATA = [
        { DisplayText: "Help", Email: "help@site.com" },
        { DisplayText: "Contact Us", Email: "contactus@site.com" },
        { DisplayText: "Web Master", Email: "webmaster@site.com" }
    ];
</script>
```

在这里，我们定义了一个名为`CONTACT_DATA`的全局变量，它是一个 JSON 对象数组。每个 JSON 对象都有一个名为`DisplayText`和一个名为`Email`的属性。与以前一样，我们现在需要在`globals.d.ts`声明文件中包含这个变量的定义：

```ts
interface IContactData {
    DisplayText: string;
    Email: string;
}

declare var CONTACT_DATA: IContactData[];
```

我们从一个名为`IContactData`的接口定义开始，表示`CONTACT_DATA`数组中单个项目的属性。每个项目都有一个`DisplayText`属性，类型为`string`，以及一个`Email`属性，类型也为`string`。因此，我们的`IContactData`接口与 JSON 数组中单个项目的原始对象属性相匹配。然后，我们声明一个名为`CONTACT_DATA`的变量，并将其类型设置为`IContactData`接口的数组。

这允许我们在 TypeScript 中使用`CONTACT_DATA`变量。现在让我们创建一个处理这些数据的类，如下所示：

```ts
class ContactLogger {
    static logContactData() {
        for (var i = 0; i < CONTACT_DATA.length; i++) {
            var contactDataItem: IContactData = CONTACT_DATA[i];
            console.log("Contact Text : " + contactDataItem.DisplayText
                 + " Email : " + contactDataItem.Email
                );
        }
    }
}

window.onload = () => {
    ContactLogger.logContactData();
}
```

`ContactLogger`类有一个名为`logContactData`的静态方法。在这个方法中，我们循环遍历`CONTACT_DATA`数组中的所有项目，使用所有 JavaScript 数组中固有的`length`属性。然后，我们创建一个名为`contactDataItem`的变量，它的类型被强制为`IContactData`，并将当前数组项的值赋给它。作为`IContactData`类型，`contactDataItem`现在有两个属性，`DisplayText`和`Email`。我们只需将这些值记录到控制台。这段代码的输出将是：

```ts
Contact Text : Help Email : help@site.com
Contact Text : Contact Us Email : contactus@site.com
Contact Text : Web Master Email : webmaster@site.com

```

# 编写自己的声明文件

在任何开发团队中，都会有一个时刻，你需要修复 bug 或增强已经编写的 JavaScript 代码。如果你处于这种情况，那么你会想尝试用 TypeScript 编写新的代码，并将其与现有的 JavaScript 代码集成。然而，为了这样做，你需要为任何需要重用的现有 JavaScript 编写自己的声明文件。这可能看起来是一项令人望而却步且耗时的任务，但当你面对这种情况时，只需记住采取小步骤，一次定义一小部分代码。你会惊讶地发现它实际上是多么简单。

在这一部分，让我们假设您需要集成一个现有的辅助类——一个在许多项目中重复使用、经过充分测试并且是开发团队标准的类。这个类已经被实现为一个 JavaScript 闭包，如下所示：

```ts
ErrorHelper = (function() {
    return {
        containsErrors: function (response) {
            if (!response || !response.responseText)
                return false;

            var errorValue = response.responseText;

            if (String(errorValue.failure) == "true"
                || Boolean(errorValue.failure)) {
                return true;
            }
            return false;
        },
        trace: function (msg) {
            var traceMessage = msg;
            if (msg.responseText) {
                traceMessage = msg.responseText.errorMessage;
            }
            console.log("[" + new Date().toLocaleDateString()
                + "] " + traceMessage);
        }
    }
})();
```

这段 JavaScript 代码片段定义了一个名为`ErrorHelper`的 JavaScript 对象，它有两个方法。`containsErrors`方法以一个名为`response`的对象作为参数，并测试它是否有一个名为`responseText`的属性。如果有，它然后检查`responseText`属性本身是否有一个名为`failure`的属性。如果这个`failure`属性是一个包含文本`"true"`的字符串，或者`failure`属性是一个值为`true`的布尔值，那么这个函数返回`true`；换句话说，我们正在评估`response.responseText.failure`属性。`ErrorHelper`闭包还有一个名为`trace`的函数，可以用一个字符串或类似`containsErrors`函数期望的响应对象来调用。

不幸的是，这个`ErrorHelper`函数缺少关键的文档部分。被传递到这两个方法中的对象的结构是什么，它有哪些属性？没有任何形式的文档，我们被迫反向工程代码来确定`response`对象的结构是什么样的。如果我们能找到`ErrorHelper`类的一些样本用法，这可能会帮助我们猜测这个结构。作为这个`ErrorHelper`的用法示例，考虑以下 JavaScript 代码：

```ts
   var failureMessage = {
        responseText: { 
            "failure": true,
            "errorMessage": "Unhandled Exception"
        }
    };
   var failureMessageString = {
        responseText: {
            "failure": "true",
            "errorMessage": "Unhandled Exception"
        }
   };
   var successMessage = { responseText: { "failure": false } };

   if (ErrorHelper.containsErrors(failureMessage))
        ErrorHelper.trace(failureMessage);
   if (ErrorHelper.containsErrors(failureMessageString))
        ErrorHelper.trace(failureMessageString);
   if (!ErrorHelper.containsErrors(successMessage))
        ErrorHelper.trace("success");
```

在这里，我们首先有一个名为`failureMessage`的变量，它有一个名为`responseText`的属性。`responseText`属性又有两个子属性：`failure`和`errorMessage`。我们的下一个变量`failureMessageString`具有相同的结构，但将`responseText.failure`属性定义为字符串，而不是布尔值。最后，我们的`successMessage`对象只定义了`responseText.failure`属性为`false`，但它没有`errorMessage`属性。

### 注意

在 JavaScript 的 JSON 格式中，属性名需要用引号括起来，而在 JavaScript 中这是可选的。因此，结构`{"failure" : true}`在语法上等同于结构`{failure : true}`。

前面代码片段的最后几行显示了`ErrorHelper`闭包的使用方式。我们只需要用我们的变量调用`ErrorHelper.containsErrors`方法，如果结果是`true`，则通过`ErrorHelper.trace`函数将消息记录到控制台。我们的输出将如下所示：

![编写自己的声明文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_04_01.jpg)

ErrorHelper 控制台输出

## 模块关键字

为了使用 TypeScript 测试这个 JavaScript 的`ErrorHelper`闭包，我们需要一个包含`ErrorHelper.js`文件和 TypeScript 生成的 JavaScript 文件的 HTML 页面。假设我们的 TypeScript 文件叫做`ErrorHelperTypeScript.ts`，那么我们的 HTML 页面将如下所示：

```ts
<!DOCTYPE html>
<html >
<head>specify.
    <title></title>
    <script src="img/ErrorHelper.js"></script>
    <script src="img/ErrorHelperTypeScript.js"></script>
</head>
<body>

</body>
</html>
```

这个 HTML 非常简单，包括了现有的`ErrorHelper.js` JavaScript 文件，以及 TypeScript 生成的`ErrorHelperTypeScript.js`文件。

在`ErrorHelperTypeScript.ts`文件中，让我们如下使用`ErrorHelper`：

```ts
window.onload = () => {
    var failureMessage = {
        responseText: { "failure": true,
            "errorMessage": "Unhandled Exception" }
    };

    if (ErrorHelper.containsErrors(failureMessage))
        ErrorHelper.trace(failureMessage);

 }
```

这段代码片段展示了我们原始 JavaScript 样本的简化版本。实际上，我们可以直接将原始 JavaScript 代码复制粘贴到我们的 TypeScript 文件中。我们首先创建一个具有正确属性的`failureMessage`对象，然后简单地调用`ErrorHelper.containsErrors`方法和`ErrorHelper.trace`方法。如果我们在这个阶段编译我们的 TypeScript 文件，我们将收到以下错误：

```ts
error TS2095: Build: Could not find symbol 'ErrorHelper'.

```

这个错误表明，虽然我们在 JavaScript 文件中有`ErrorHelper`的完整源代码，但没有有效的 TypeScript 类型名为`ErrorHelper`。默认情况下，TypeScript 会查找项目中所有的 TypeScript 文件来找到类定义，但不会解析 JavaScript 文件。为了正确编译这段代码，我们需要一个新的 TypeScript 定义文件。

### 注意

这个定义文件根本没有包含在 HTML 文件中；它只被 TypeScript 编译器使用，不会生成任何 JavaScript。

在我们的`ErrorHelper`类上没有一套有用的文档，我们需要通过阅读源代码来纯粹地逆向工程一个 TypeScript 定义。这显然不是一个理想的情况，也不推荐，但在这个阶段，这是我们能做的一切。在这些情况下，最好的起点就是简单地查看用法示例，然后从那里开始。

通过查看 JavaScript 中`ErrorHelper`闭包的用法，我们应该在我们的声明文件中包含两个关键部分。第一个是`containsErrors`和`trace`函数的一组函数定义。第二个是一组接口，用于描述`ErrorHelper`闭包依赖的`response`对象的结构。让我们从函数定义开始，创建一个名为`ErrorHelper.d.ts`的新的 TypeScript 文件，其中包含以下代码：

```ts
declare module ErrorHelper {
    function containsErrors(response);
    function trace(message);
}
```

这个声明文件以我们之前见过的`declare`关键字开头，然后使用了一个新的 TypeScript 关键字：`module`。`module`关键字后面必须跟着一个模块名，这里是`ErrorHelper`。这个模块名必须与我们描述的原始 JavaScript 中的闭包名匹配。在我们所有对`ErrorHelper`的使用中，我们总是用闭包名`ErrorHelper`本身作为`containsErrors`和`trace`函数的前缀。这个模块名也被称为命名空间。如果我们有另一个名为`AjaxHelper`的类，它也包括一个`containsErrors`函数，我们可以通过使用这些命名空间或模块名来区分`AjaxHelper.containsErrors`和`ErrorHelper.containsErrors`函数。

前面代码片段的第二行指示我们正在定义一个名为`containsErrors`的函数，它接受一个参数。模块声明的第三行指示我们正在定义另一个名为`trace`的函数，它接受一个参数。有了这个定义，我们的 TypeScript 代码样本将能够正确编译。

## 接口

虽然我们已经正确定义了`ErrorHelper`闭包可用的两个函数，但我们缺少关于`ErrorHelper`闭包可用的函数的第二部分信息——`response`参数的结构。我们没有为`containsErrors`或`trace`函数中的任何一个强类型参数。在这个阶段，我们的 TypeScript 代码可以将任何东西传递给这两个函数，因为它没有`response`或`message`参数的定义。然而，我们知道这两个函数都查询这些参数的特定结构。如果我们传入一个不符合这个结构的对象，那么我们的 JavaScript 代码将会引起运行时错误。

为了解决这个问题并使我们的代码更稳定，让我们为这些参数定义一个接口：

```ts
interface IResponse {
    responseText: IFailureMessage;
}

interface IFailureMessage {
    failure: boolean;
    errorMessage: string;
}
```

我们从一个名为`IResponse`的接口开始，它具有一个名为`responseText`的属性，与原始的 JSON 对象相同。这个`responseText`属性被强类型为`IFailureMessage`类型。`IFailureMessage`接口被强类型为具有两个属性：`failure`是`boolean`类型，`errorMessage`是`string`类型。这些接口正确描述了`containsErrors`函数的`response`参数的正确结构。现在我们可以修改`containsErrors`函数的原始声明，以在`response`参数上使用这个接口。

```ts
declare module ErrorHelper {
    function containsErrors(response: IResponse);
    function trace(message);
}
```

`containsErrors`的函数定义现在将响应参数强类型为我们之前定义的`IResponse`类型。对声明文件的这种修改现在将强制`containsErrors`函数的任何进一步使用发送一个符合`IResponse`结构的有效参数。让我们写一些故意不正确的 TypeScript 代码，看看会发生什么：

```ts
var anotherFailure : IResponse = { responseText: { success: true } };

if (ErrorHelper.containsErrors(anotherFailure))
    ErrorHelper.trace(anotherFailure);
```

我们首先创建一个名为`anotherFailure`的变量，并将其类型指定为`IResponse`类型。即使我们使用定义文件来定义这个接口，TypeScript 编译器应用的规则与我们以前看到的没有什么不同。这段代码中的第一行将生成以下错误：

![接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_04_02.jpg)

编译错误的响应文本对象

从这个相当冗长但信息丰富的错误消息中可以看出，`anotherFailure`变量的结构导致了所有的错误。即使我们正确引用了`IResponse`的`responseText`属性，`responseText`属性也被强类型为`IFailureMessage`类型，它要求`failure`属性和`errorMessage`属性都存在，因此会出现错误。

我们可以通过在变量`anotherFailure`中包含`failure`和`errorMessage`的必需属性来修复这些错误：

```ts
var anotherFailure: IResponse = {
    responseText: {
        failure: false, errorMessage: "", success: true
        }
    };
```

我们的 TypeScript 现在可以正确编译。变量`anotherFailure`现在具有所有必需的属性，以便正确使用`ErrorHelper`函数。通过为现有的`ErrorHelper`类创建一个强类型声明文件，我们可以确保对现有的`ErrorHelper` JavaScript 闭包的任何进一步的 TypeScript 使用都不会生成运行时错误。

## 函数重载

我们对`ErrorHelper`的声明文件还没有完全完成。如果我们看一下`ErrorHelper`的原始 JavaScript 用法，我们会注意到`containsErrors`函数还允许`responseText`的`failure`属性是一个字符串：

```ts
var failureMessageString = {
    responseText: { "failure": "true",
        "errorMessage": "Error Message" }
};

if (ErrorHelper.containsErrors(failureMessageString))
    ErrorHelper.trace(failureMessage);
```

如果我们现在编译这段代码，将会得到以下编译错误：

![函数重载](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_04_03.jpg)

响应文本的多个定义的编译错误

在变量`failureMessageString`的先前定义中，`failure`属性的类型为`true`，这是一个`string`类型，而不是`boolean`类型的`true`。为了允许在原始`IFailureMessage`接口上进行这种变体，我们需要修改我们的声明文件。首先，我们需要两个新接口，指定`failure`属性的类型为`string`：

```ts
interface IResponseString {
    responseText: IFailureMessageString;
}

interface IFailureMessageString {
    failure: string;
    errorMessage: string;
}
```

`IResponseString`接口与`IResponse`接口几乎相同，只是它使用`IFailureMessageString`类型作为`responseText`属性的类型。`IFailureMessageString`接口与原始的`IFailureMessage`接口几乎相同，只是`failure`属性的类型为`string`。现在我们需要修改我们的声明文件，以允许`containsErrors`函数上的两个调用签名：

```ts
declare module ErrorHelper {
    function containsErrors(response: IResponse);
    function containsErrors(response: IResponseString);
    function trace(message);
}
```

与接口和类定义一样，模块也允许函数覆盖。模块`ErrorHelper`现在有一个`containsErrors`函数定义，使用原始的`IResponse`接口，以及一个使用新的`IReponseString`接口的第二个函数定义。这个模块定义的新版本将允许`failure`消息结构的两种变体都正确编译。

在这个例子中，我们还可以利用联合类型，并简化我们先前对`containsErrors`函数的声明为单个定义：

```ts
declare module ErrorHelper {
    function containsErrors(response: IResponse | IResponseString);
    function trace(message: string);
}
```

## 完善我们的定义文件

现在我们可以将注意力集中在`trace`函数上。`trace`函数可以接受`IResponse`接口的两个版本，或者它可以简单地接受一个字符串。让我们更新`trace`函数签名的定义文件：

```ts
declare module ErrorHelper {
    function containsErrors(response: IResponse | IResponseString);
    function trace(message: string | IResponse | IResponseString);
}
```

在这里，我们已经更新了`trace`函数，以允许三种不同类型的消息类型——普通的`string`，一个`IResponse`类型，或一个`IResponseString`类型。

这完成了我们对`ErrorHelper`JavaScript 类的定义文件。

# 模块合并

正如我们现在所知，TypeScript 编译器将自动搜索项目中所有`.d.ts`文件，以获取声明文件。如果这些声明文件包含相同的模块名称，TypeScript 编译器将合并这两个声明文件，并使用模块声明的组合版本。

如果我们有一个名为`MergedModule1.d.ts`的文件，其中包含以下定义：

```ts
declare module MergedModule {
    function functionA();
}
```

和一个名为`MergedModule2.d.ts`的第二个文件，其中包含以下定义：

```ts
declare module MergedModule {
    function functionB();
}
```

TypeScript 编译器将合并这两个模块，就好像它们是单个定义一样：

```ts
declare module MergedModule {
    function functionA();
    function functionB();
}
```

这将允许`functionA`和`functionB`都是相同`MergedModule`命名空间的有效函数，并允许以下用法：

```ts
MergedModule.functionA();
MergedModule.functionB();
```

### 注意

模块还可以与接口、类和枚举合并。但是，类不能与其他类、变量或接口合并。

# 声明语法参考

在创建声明文件并使用`module`关键字时，可以使用一些规则来混合和匹配定义。我们已经涵盖了其中之一——函数覆盖。作为 TypeScript 程序员，你通常只会偶尔编写模块定义，并且偶尔需要向现有声明文件添加新的定义。

因此，本节旨在成为此声明文件语法的快速参考指南，或者一张备忘单。每个部分包含模块定义规则的描述，JavaScript 语法片段，然后是等效的 TypeScript 声明文件语法。

要使用此参考部分，只需匹配 JavaScript 语法部分中要模拟的 JavaScript，然后使用等效的定义语法编写您的声明文件。我们将以函数覆盖语法作为示例开始：

## 函数覆盖

声明文件可以包含同一函数的多个定义。如果相同的 JavaScript 函数可以使用不同类型进行调用，则需要为函数的每个变体声明一个函数覆盖。

### JavaScript 语法

```ts
trace("trace a string");
trace(true);
trace(1);
trace({ id: 1, name: "test" });
```

### 声明文件语法

```ts
declare function trace(arg: string | number | boolean );
declare function trace(arg: { id: number; name: string });
```

### 注意

每个函数定义必须具有唯一的函数签名。

## 嵌套命名空间

模块定义可以包含嵌套的模块定义，然后转换为嵌套的命名空间。如果您的 JavaScript 使用命名空间，则需要定义嵌套模块声明以匹配 JavaScript 命名空间。

### JavaScript 语法

```ts
FirstNamespace.SecondNamespace.ThirdNamespace.log("test");
```

### 声明文件语法

```ts
declare module FirstNamespace {
    module SecondNamespace {
        module ThirdNamespace {
            function log(msg: string);
        }
    }
}
```

## 类

类定义允许在模块定义内。如果您的 JavaScript 使用类或 new 操作符，则可实例化的类将需要在声明文件中定义。

### JavaScript 语法

```ts
var myClass = new MyClass();
```

### 声明文件语法

```ts
declare class MyClass {
}
```

## 类命名空间

类定义允许在嵌套模块定义中。如果您的 JavaScript 类具有前置命名空间，则需要先声明匹配命名空间的嵌套模块，然后可以在正确的命名空间内声明类。

### JavaScript 语法

```ts
var myNestedClass = new OuterName.InnerName.NestedClass();
```

### 声明文件语法

```ts
declare module OuterName {
    module InnerName {
        class NestedClass {}
    }
}
```

## 类构造函数重载

类定义可以包含构造函数重载。如果您的 JavaScript 类可以使用不同类型或多个参数进行构造，则需要在声明文件中列出每个变体作为构造函数重载。

### JavaScript 语法

```ts
var myClass = new MyClass();
var myClass2 = new MyClass(1, "test");
```

### 声明文件语法

```ts
declare class MyClass {
    constructor(id: number, name: string);
    constructor();
}
```

## 类属性

类可以包含属性。您需要在类声明中列出类的每个属性。

### JavaScript 语法

```ts
var classWithProperty = new ClassWithProperty();
classWithProperty.id = 1;
```

### 声明文件语法

```ts
declare class ClassWithProperty {
    id: number;
}
```

## 类函数

类可以包含函数。您需要在类声明中列出 JavaScript 类的每个函数，以便 TypeScript 编译器接受对这些函数的调用。

### JavaScript 语法

```ts
var classWithFunction = new ClassWithFunction();
classWithFunction.functionToRun();
```

### 声明文件语法

```ts
declare class ClassWithFunction {
    functionToRun(): void;
}
```

### 注意

被视为私有的函数或属性不需要通过声明文件公开，可以简单地省略。

## 静态属性和函数

类方法和属性可以是静态的。如果您的 JavaScript 函数或属性可以在不需要对象实例的情况下调用，则这些属性或函数需要标记为静态。

### JavaScript 语法

```ts
StaticClass.staticId = 1;
StaticClass.staticFunction();
```

### 声明文件语法

```ts
declare class StaticClass {
    static staticId: number;
    static staticFunction();
}
```

## 全局函数

不带命名空间前缀的函数可以在全局命名空间中声明。如果您的 JavaScript 定义了全局函数，则需要在没有命名空间的情况下声明这些函数。

### JavaScript 语法

```ts
globalLogError("test");
```

### 声明文件语法

```ts
declare function globalLogError(msg: string);
```

## 函数签名

函数可以使用函数签名作为参数。使用回调函数或匿名函数的 JavaScript 函数，需要用正确的函数签名声明。

### JavaScript 语法

```ts
describe("test", function () {
    console.log("inside the test function");
});
```

### 声明文件语法

```ts
declare function describe(name: string, functionDef: () => void);
```

## 可选属性

类或函数可以包含可选属性。在 JavaScript 对象参数不是必需时，这些参数需要在声明中标记为可选属性。

### JavaScript 语法

```ts
var classWithOpt  = new ClassWithOptionals();
var classWithOpt1 = new ClassWithOptionals({ id: 1 });
var classWithOpt2 = new ClassWithOptionals({ name: "first" });
var classWithOpt3 = new ClassWithOptionals({ id: 2, name: "second" });
```

### 声明文件语法

```ts
interface IOptionalProperties {
    id?: number;
    name?: string;
}

declare class ClassWithOptionals {
    constructor(options?: IOptionalProperties);
}
```

## 合并函数和模块

具有特定名称的函数定义可以与相同名称的模块定义合并。这意味着如果您的 JavaScript 函数可以使用参数调用并且还具有属性，则需要将函数与模块合并。

### JavaScript 语法

```ts
fnWithProperty(1);
fnWithProperty.name = "name";
```

### 声明文件语法

```ts
declare function fnWithProperty(id: number);
declare module fnWithProperty {
    var name: string;
}
```

# 总结

在本章中，我们概述了您需要了解的内容，以便编写和使用自己的声明文件。我们讨论了在呈现的 HTML 中的 JavaScript 全局变量以及如何在 TypeScript 中访问它们。然后，我们转向了一个小的 JavaScript 辅助函数，并为这个 JavaScript 编写了我们自己的声明文件。我们通过列出一些模块定义规则来结束本章，强调了所需的 JavaScript 语法，并展示了等效的 TypeScript 声明语法。在下一章中，我们将讨论如何使用现有的第三方 JavaScript 库，以及如何将这些库的现有声明文件导入到您的 TypeScript 项目中。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第五章：第三方库

如果我们无法重用现有的 JavaScript 库、框架和其他好东西，那么我们的 TypeScript 开发环境就不会有多大作用。然而，正如我们所看到的，为了在 TypeScript 中使用特定的第三方库，我们首先需要一个匹配的定义文件。

TypeScript 发布后不久，Boris Yankov 建立了一个 github 存储库，用于存放第三方 JavaScript 库的 TypeScript 定义文件。这个名为 DefinitelyTyped 的存储库（[`github.com/borisyankov/DefinitelyTyped`](https://github.com/borisyankov/DefinitelyTyped)）迅速变得非常受欢迎，目前是获取高质量定义文件的地方。DefinitelyTyped 目前拥有超过 700 个定义文件，这些文件是来自世界各地数百名贡献者多年来建立起来的。如果我们要衡量 TypeScript 在 JavaScript 社区中的成功，那么 DefinitelyTyped 存储库将是 TypeScript 被采用程度的一个很好指标。在尝试编写自己的定义文件之前，先检查 DefinitelyTyped 存储库，看看是否已经有可用的文件。

在这一章中，我们将更仔细地研究如何使用这些定义文件，并涵盖以下主题：

+   下载定义文件

+   在 Visual Studio 中使用 NuGet

+   使用 TypeScript Definition manager (TSD)

+   选择一个 JavaScript 框架

+   使用 Backbone 的 TypeScript

+   使用 Angular 的 TypeScript

+   使用 ExtJs 的 TypeScript

# 下载定义文件

在 TypeScript 项目中包含定义文件的最简单方法是从 DefinitelyTyped 下载匹配的`.d.ts`文件。这只是简单地找到相关文件，并下载原始内容。假设我们想要在项目中开始使用 jQuery。我们已经找到并下载了 jQuery JavaScript 库（v2.1.1），并在项目中的一个名为`lib`的目录下包含了相关文件。要下载声明文件，只需浏览到 DefinitelyTyped 上的`jquery`目录（[`github.com/borisyankov/DefinitelyTyped/tree/master/jquery`](https://github.com/borisyankov/DefinitelyTyped/tree/master/jquery)），然后点击`jquery.d.ts`文件。这将打开一个 GitHub 页面，显示文件的编辑器视图。在这个编辑器视图的菜单栏上，点击**Raw**按钮。这将下载`jquery.d.ts`文件，并允许您将其保存在项目目录结构中。在**lib**文件夹下创建一个名为**typings**的新目录，并将**jquery.d.ts**文件保存在其中。

您的项目文件应该看起来像这样：

![下载定义文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_05_01.jpg)

带有下载的 jquery.d.ts 文件的 Visual Studio 项目结构

现在我们可以修改我们的`index.html`文件，包含`jquery` JavaScript 文件，并开始编写针对 jQuery 库的 TypeScript 代码。我们的`index.html`文件需要修改如下：

```ts
<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="utf-8" />
    <title>TypeScript HTML App</title>
    <link rel="stylesheet" href="app.css" type="text/css" />
    <script src="img/jquery-2.1.1.min.js"></script>
    <script src="img/app.js"></script>
</head>
<body>
    <h1>TypeScript HTML App</h1>

    <div id="content"></div>
</body>
</html>
```

这个`index.html`文件的第一个`<script>`标签现在包含了一个指向`jquery-2.1.1.min.js`的链接，第二个`<script>`标签包含了一个指向 TypeScript 生成的`app.js`的链接。打开`app.ts` TypeScript 文件，删除现有的源代码，并用以下 jQuery 代码替换它：

```ts
$(document).ready(() => {
    $("#content").html("<h1>Hello World !</h1>");
});
```

这段代码首先定义了一个匿名函数，在 jQuery 的`document.ready`事件上执行。`document.ready`函数类似于我们之前使用的`window.onload`函数，它会在 jQuery 初始化后执行。这段代码的第二行简单地使用 jQuery 选择器语法获取名为`content`的 DOM 元素的句柄，然后调用`html`函数设置其 HTML 值。

我们下载的`jquery.d.ts`文件为我们提供了在 TypeScript 中编译 jQuery 所需的相关模块声明。

# 使用 NuGet

NuGet 是一个流行的包管理平台，可以下载所需的外部库，并自动包含在您的 Visual Studio 或 WebMatrix 项目中。它可用于打包为 DLL 的外部库，例如 StructureMap，也可用于 JavaScript 库和声明文件。NuGet 也可用作命令行实用程序。

## 使用扩展管理器

要在 Visual Studio 中使用 NuGet 包管理器对话框，请在主工具栏上选择**工具**选项，然后选择**NuGet 包管理器**，最后选择**管理解决方案的 NuGet 包**。这将打开 NuGet 包管理器对话框。在对话框的左侧，单击**在线**。NuGet 对话框将查询 NuGet 网站并显示可用包的列表。屏幕右上方有一个**搜索**框。单击**搜索**框，并输入`jquery`，以显示 NuGet 中为 jQuery 提供的所有包，如下图所示：

![使用扩展管理器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_05_02.jpg)

NuGet 包管理器对 jQuery 查询的对话框

在**搜索结果**面板中选择包时，每个包都将有一个突出显示的**安装**按钮。选择包后，右侧窗格将显示有关所讨论的 NuGet 包的更多详细信息。请注意，项目详细信息面板还显示了您即将安装的包的版本。单击**安装**按钮将自动下载相关文件以及任何依赖项，并将它们自动包含在您的项目中。

### 注意

NuGet 用于 JavaScript 文件的安装目录实际上称为`Scripts`，而不是我们之前创建的`lib`目录。NuGet 使用`Scripts`目录作为标准，因此任何包含 JavaScript 的包都将安装相关的 JavaScript 文件到`Scripts`目录中。

## 安装声明文件

您会发现在 DefinitelyTyped GitHub 存储库上找到的大多数声明文件都有相应的 NuGet 包。这些包的命名约定是`<library>`.`TypeScript.DefinitelyTyped`。如果我们在搜索框中输入`jquery typescript`，我们将看到返回的这些 DefinitelyTyped 包的列表。我们要找的 NuGet 包的名称是**jquery.TypeScript.DefinitelyTyped**，由**Jason Jarret**创建，在撰写本文时，版本为 1.4.0。

### 注意

DefinitelyTyped 包有它们自己的内部版本号，这些版本号不一定与您使用的 JavaScript 库的版本匹配。例如，jQuery 包的版本为 2.1.1，但相应的 TypeScript 定义包显示的版本号为 1.4.0。

安装`jQuery.TypeScript.DefinitelyTyped`包将在`Scripts`目录下创建一个`typings`目录，然后包含`jquery.d.ts`定义文件。这种目录命名标准已被各种 NuGet 包作者采用。

## 使用包管理器控制台

Visual Studio 还有一个命令行版本的 NuGet 包管理器，可以作为控制台应用程序使用，也集成到了 Visual Studio 中。单击**工具**，然后**NuGet 包管理器**，最后**包管理器控制台**，将打开一个新的 Visual Studio 窗口，并初始化 NuGet 命令行界面。NuGet 的命令行版本具有一些在 GUI 版本中不包括的功能。输入`get-help NuGet`以查看可用的顶级命令行参数列表。

### 安装包

要从控制台命令行安装 NuGet 包，只需输入`install-package <packageName>`。例如，要安装`jquery.TypeScript.DefinitelyTyped`包，只需输入：

```ts
Install-Package jquery.TypeScript.DefinitelyTyped

```

此命令将连接到 NuGet 服务器，并下载并安装包到您的项目中。

### 注意

在**包管理器控制台**窗口的工具栏上有两个下拉列表，**包源**和**默认项目**。如果您的 Visual Studio 解决方案有多个项目，您需要从**默认项目**下拉列表中选择正确的项目，以便 NuGet 将包安装到其中。

### 搜索包名称

从命令行搜索包名称是通过`Get-Package –ListAvailable`命令完成的。此命令使用`–Filter`参数作为搜索条件。例如，要查找包含`definitelytyped`搜索字符串的可用包，请运行以下命令：

```ts
Get-Package –ListAvailable –Filter definitelytyped

```

### 安装特定版本

有一些 JavaScript 库与 jQuery 2.x 版本不兼容，需要使用 1.x 范围内的 jQuery 版本。要安装特定版本的 NuGet 包，我们需要从命令行指定`-Version`参数。例如，要安装`jquery v1.11.1`包，请从命令行运行以下命令：

```ts
Install-Package jQuery –Version 1.11.1

```

### 注意

如果 NuGet 发现您的项目中已经安装了另一个版本的包，它将升级或降级要安装的包的版本。在上面的示例中，我们已经在项目中安装了最新版本的 jQuery（2.1.1），因此 NuGet 将首先删除`jQuery 2.1.1`，然后安装`jQuery 1.11.1`。

# 使用 TypeScript Definition Manager

如果您正在使用 Node 作为 TypeScript 开发环境，那么您可能考虑使用**TypeScript Definition Manager**来获取 DefinitelyTyped 的 TypeScript 定义（**TSD**位于[`definitelytyped.org/tsd/`](http://definitelytyped.org/tsd/)）。TSD 提供类似于 NuGet 包管理器的功能，但专门针对 DefinitelyTyped GitHub 存储库中的 TypeScript 定义。

要安装 TSD，请使用以下`npm`命令：

```ts
npm install tsd@next –g

```

这将安装`tsd prerelease v0.6.x`。

### 注意

在撰写本文时，您需要 v0.6.x 及更高版本才能从命令行使用`install`关键字。如果您只是输入`npm install tsd –g`，那么 npm 将安装 v0.5.x，其中不包括`install`关键字。

## 查询包

TSD 允许使用`query`关键字查询包存储库。要搜索`jquery`定义文件，输入以下内容：

```ts
tsd query jquery

```

上述命令将在`DefinitelyTyped`存储库中搜索任何名为`jquery.d.ts`的定义文件。由于只有一个，搜索返回的结果将是：

```ts
Jquery / jquery

```

## 使用通配符

TSD 还允许使用星号`*`作为通配符。要搜索以`jquery`开头的`DefinitelyTyped`声明文件，输入以下内容：

```ts
tsd query jquery.*

```

这个`tsd`命令将搜索存储库，并返回以 jQuery 开头的声明文件的结果。

## 安装定义文件

要安装定义文件，请使用以下`install`关键字：

```ts
tsd install jquery

```

此命令将下载`jquery.d.ts`文件到以下目录：

```ts
\typings\jquery\jquery.d.ts

```

### 注意

TSD 将基于运行 tsd 的当前目录创建`\typings`目录，因此请确保每当您从命令行使用 TSD 时，都要导航到项目中的相同基本目录。

# 使用第三方库

在本章的这一部分，我们将开始探索一些更受欢迎的第三方 JavaScript 库，它们的声明文件以及如何为每个框架编写兼容的 TypeScript。我们将比较 Backbone、Angular 和 ExtJs，它们都是用于构建丰富的客户端 JavaScript 应用程序的框架。在我们的讨论中，我们将看到一些框架与 TypeScript 语言及其特性高度兼容，一些部分兼容，一些则兼容性很低。

## 选择 JavaScript 框架

选择一个 JavaScript 框架或库来开发单页应用程序是一个困难且有时令人望而生畏的任务。似乎每个月都会出现一个新的框架，承诺用更少的代码提供更多的功能。

为了帮助开发人员比较这些框架，并做出明智的选择，Addy Osmani 写了一篇名为*Journey Through the JavaScript MVC Jungle*的优秀文章。([`www.smashingmagazine.com/2012/07/27/journey-through-the-javascript-mvc-jungle/`](http://www.smashingmagazine.com/2012/07/27/journey-through-the-javascript-mvc-jungle/))。

实质上，他的建议很简单 - 这是一个个人选择 - 所以尝试一些框架，看看哪个最适合你的需求、编程思维方式和现有技能。Addy 开始的**TodoMVC**项目([`todomvc.com`](http://todomvc.com))，在几种 MV* JavaScript 框架中实现了相同的应用程序，做得非常出色。这真的是一个参考站点，可以深入了解一个完全工作的应用程序，并比较不同框架的编码技术和风格。

同样，取决于你在 TypeScript 中使用的 JavaScript 库，你可能需要以特定的方式编写你的 TypeScript 代码。在选择框架时要记住这一点 - 如果在 TypeScript 中使用起来很困难，那么你可能最好看看另一个集成更好的框架。如果在 TypeScript 中使用这个框架很容易和自然，那么你的生产力和整体开发体验将会更好。

在本节中，我们将看一些流行的 JavaScript 库，以及它们的声明文件，并了解如何编写兼容的 TypeScript。要记住的关键是 TypeScript 生成 JavaScript - 所以如果你在使用第三方库时遇到困难，那么打开生成的 JavaScript，看看 TypeScript 生成的 JavaScript 代码是什么样子的。如果生成的 JavaScript 与库的文档中的 JavaScript 代码示例匹配，那么你就在正确的轨道上。如果不匹配，那么你可能需要修改你的 TypeScript，直到编译后的 JavaScript 与示例相匹配。

当尝试为第三方 JavaScript 框架编写 TypeScript 代码时 - 特别是如果你是根据 JavaScript 文档进行工作 - 你的初始尝试可能只是试错。在这个过程中，你可能会发现你需要以特定的方式编写你的 TypeScript，以匹配特定的第三方库。本章的其余部分展示了三种不同的库需要不同的 TypeScript 编写方式。

# Backbone

Backbone 是一个流行的 JavaScript 库，通过提供模型、集合和视图等内容，为 Web 应用程序提供结构。Backbone 自 2010 年以来一直存在，并且拥有大量的追随者，许多商业网站都在使用这个框架。根据[Infoworld.com](http://Infoworld.com)的报道，Backbone 在 GitHub 上有超过 1600 个与 Backbone 相关的项目，评分超过 3 星，这意味着它拥有庞大的扩展生态系统和相关库。

让我们快速看一下用 TypeScript 编写的 Backbone。

### 注意

要在自己的项目中跟着代码进行，你需要安装以下 NuGet 包：`backbone.js`（当前版本为 v1.1.2），和`backbone.TypeScript.DefinitelyTyped`（当前版本为 1.2.3）。

## 在 Backbone 中使用继承

从 Backbone 的文档中，我们找到了在 JavaScript 中创建`Backbone.Model`的示例如下：

```ts
var Note = Backbone.Model.extend(
    {
        initialize: function() {
            alert("Note Model JavaScript initialize");
        },
        author: function () { },
        coordinates: function () { },
        allowedToEdit: function(account) {
            return true;
        }
    }
);
```

这段代码展示了 JavaScript 中 Backbone 的典型用法。我们首先创建一个名为`Note`的变量，它扩展（或派生自）`Backbone.Model`。这可以通过`Backbone.Model.extend`语法看出。Backbone 的`extend`函数使用 JavaScript 对象表示法在外部花括号`{ ... }`中定义一个对象。在前面的代码中，这个对象有四个函数：`initialize`，`author`，`coordinates`和`allowedToEdit`。

根据 Backbone 文档，`initialize`函数将在创建此类的新实例时被调用一次。在我们之前的示例中，`initialize`函数只是创建一个**警报**来指示该函数被调用。`author`和`coordinates`函数在这个阶段是空的，只有`allowedToEdit`函数实际上做了一些事情：`return true`。

如果我们只是简单地将上面的 JavaScript 复制粘贴到一个 TypeScript 文件中，我们将生成以下编译错误：

```ts
Build: 'Backbone.Model.extend' is inaccessible.

```

在使用第三方库和来自 DefinitelyTyped 的定义文件时，我们首先应该看看定义文件是否有错误。毕竟，JavaScript 文档说我们应该能够像示例中那样使用`extend`方法，那么为什么这个定义文件会导致错误呢？如果我们打开`backbone.d.ts`文件，然后搜索找到`Model`类的定义，我们会找到编译错误的原因：

```ts
class Model extends ModelBase {

    /**
    * Do not use, prefer TypeScript's extend functionality.
    **/
    private static extend(
        properties: any, classProperties?: any): any;
```

这个声明文件片段显示了 Backbone `Model`类的一些定义。在这里，我们可以看到`extend`函数被定义为`private static`，因此它在 Model 类本身之外不可用。然而，这似乎与我们在文档中看到的 JavaScript 示例相矛盾。在`extend`函数定义的前面评论中，我们找到了在 TypeScript 中使用 Backbone 的关键：更喜欢 TypeScript 的 extend 功能。

这个评论表明 Backbone 的声明文件是围绕 TypeScript 的`extends`关键字构建的，因此我们可以使用自然的 TypeScript 继承语法来创建 Backbone 对象。因此，这段代码的 TypeScript 等价物必须使用`extends` TypeScript 关键字从基类`Backbone.Model`派生一个类，如下所示：

```ts
class Note extends Backbone.Model {
    initialize() {
        alert("Note model Typescript initialize");
    }
    author() { }
    coordinates() { }
    allowedToEdit(account) {
        return true;
    }
}
```

现在我们正在创建一个名为`Note`的类定义，它`extends`了`Backbone.Model`基类。这个类然后有`initialize`，`author`，`coordinates`和`allowedToEdit`函数，与之前的 JavaScript 版本类似。我们的 Backbone 示例现在将正确编译和运行。

使用这两个版本中的任何一个，我们都可以通过在 HTML 页面中包含以下脚本来创建`Note`对象的实例：

```ts
<script type="text/javascript">
    $(document).ready( function () {
        var note = new Note();
    });
</script>
```

这个 JavaScript 示例只是等待 jQuery 的`document.ready`事件被触发，然后创建一个`Note`类的实例。如前所述，当类的实例被构造时，`initialize`函数将被调用，因此当我们在浏览器中运行时，我们会看到一个警报框出现。

Backbone 的所有核心对象都是以继承为设计基础的。这意味着创建新的 Backbone 集合、视图和路由器将在 TypeScript 中使用相同的`extends`语法。因此，Backbone 非常适合 TypeScript，因为我们可以使用自然的 TypeScript 语法来继承创建新的 Backbone 对象。

## 使用接口

由于 Backbone 允许我们使用 TypeScript 继承来创建对象，因此我们也可以轻松地在任何 Backbone 对象中使用 TypeScript 接口。提取上面`Note`类的接口将如下所示：

```ts
interface INoteInterface {
    initialize();
    author();
    coordinates();
    allowedToEdit(account: string);
}
```

现在我们可以更新我们的`Note`类定义来实现这个接口，如下所示：

```ts
class Note extends Backbone.Model implements INoteInterface {
    // existing code
}
```

我们的类定义现在实现了`INoteInterface` TypeScript 接口。这个简单的改变保护了我们的代码不会被无意中修改，并且还打开了使用标准面向对象设计模式与核心 Backbone 对象一起工作的能力。如果需要的话，我们可以应用第三章中描述的工厂模式，*接口、类和泛型*，来返回特定类型的 Backbone 模型 - 或者其他任何 Backbone 对象。

## 使用泛型语法

Backbone 的声明文件还为一些类定义添加了泛型语法。这在为 Backbone 编写 TypeScript 代码时带来了更强的类型化好处。Backbone 集合（惊喜，惊喜）包含一组 Backbone 模型，允许我们在 TypeScript 中定义集合如下：

```ts
class NoteCollection extends Backbone.Collection<Note> {
    model = Note;
    //model: Note; // generates compile error
    //model: { new (): Note }; // ok
}
```

在这里，我们有一个`NoteCollection`，它派生自`Backbone.Collection`，但也使用泛型语法来限制集合只处理`Note`类型的对象。这意味着任何标准的集合函数，比如`at()`或`pluck()`，都将被强类型化为返回`Note`模型，进一步增强了我们的类型安全和智能感知。

请注意第二行用于将类型分配给集合类的内部`model`属性的语法。我们不能使用标准的 TypeScript 语法`model: Note`，因为这会导致编译时错误。我们需要将`model`属性分配给类定义，就像`model=Note`语法所示，或者我们可以使用`{ new(): Note }`语法，就像最后一行所示。

## 使用 ECMAScript 5

Backbone 还允许我们使用 ECMAScript 5 的能力来为`Backbone.Model`类定义 getter 和 setter，如下所示：

```ts
interface ISimpleModel {
    Name: string;
    Id: number;
}
class SimpleModel extends Backbone.Model implements ISimpleModel {
    get Name() {
        return this.get('Name');
    }
    set Name(value: string) {
        this.set('Name', value);
    }
    get Id() {
        return this.get('Id');
    }
    set Id(value: number) {
        this.set('Id', value);
    }
}
```

在这个片段中，我们定义了一个具有两个属性的接口，名为`ISimpleModel`。然后我们定义了一个`SimpleModel`类，它派生自`Backbone.Model`，并且还实现了`ISimpleModel`接口。然后我们为我们的`Name`和`Id`属性定义了 ES 5 的 getter 和 setter。Backbone 使用类属性来存储模型值，所以我们的 getter 和 setter 只是调用了`Backbone.Model`的底层`get`和`set`方法。

## Backbone TypeScript 兼容性

正如我们所看到的，Backbone 允许我们在我们的代码中使用 TypeScript 的所有语言特性。我们可以使用类、接口、继承、泛型，甚至是 ECMAScript 5 属性。我们所有的类也都派生自基本的 Backbone 对象。这使得 Backbone 成为了一个非常兼容 TypeScript 的构建 Web 应用程序的库。我们将在后面的章节中更多地探索 Backbone 框架。

# Angular

AngularJs（或者只是 Angular）也是一个非常流行的 JavaScript 框架，由 Google 维护。Angular 采用了完全不同的方法来构建 JavaScript SPA，引入了一个 HTML 语法，运行中的 Angular 应用程序可以理解。这为应用程序提供了双向数据绑定的能力，自动同步模型、视图和 HTML 页面。Angular 还提供了**依赖注入**（**DI**）的机制，并使用服务来为视图和模型提供数据。

让我们来看一下 Angular 教程中的一个示例，该示例位于第 2 步，我们开始构建一个名为`PhoneListCtrl`的控制器。教程中提供的示例显示了以下 JavaScript：

```ts
var phonecatApp = angular.module('phonecatApp', []);
phonecatApp.controller('PhoneListCtrl', function ($scope) 
{
  $scope.phones = [
    {'name': 'Nexus S',
     'snippet': 'Fast just got faster with Nexus S.'},
    {'name': 'Motorola XOOM™ with Wi-Fi',
     'snippet': 'The Next, Next Generation tablet.'},
    {'name': 'MOTOROLA XOOM™',
     'snippet': 'The Next, Next Generation tablet.'}
  ];
});
```

这段代码片段是典型的 Angular JavaScript 语法。我们首先创建一个名为`phonecatApp`的变量，并通过在`angular`全局实例上调用`module`函数将其注册为一个 Angular 模块。`module`函数的第一个参数是 Angular 模块的全局名称，空数组是其他模块的占位符，这些模块将通过 Angular 的依赖注入机制注入。

然后我们调用新创建的`phonecatApp`变量上的`controller`函数，带有两个参数。第一个参数是控制器的全局名称，第二个参数是一个接受名为`$scope`的特殊命名的 Angular 变量的函数。在这个函数中，代码将`$scope`变量的`phones`对象设置为一个 JSON 对象数组，每个对象都有`name`和`snippet`属性。

如果我们继续阅读教程，我们会发现一个单元测试，展示了`PhoneListCtrl`控制器的使用方式：

```ts
describe('PhoneListCtrl', function(){
    it('should create "phones" model with 3 phones', function() {
      var scope = {},
          ctrl = new PhoneListCtrl(scope);

      expect(scope.phones.length).toBe(3);
  });

});
```

这段代码片段的前两行使用了一个名为`describe`的全局函数，以及在这个函数内部另一个名为`it`的函数。这两个函数是单元测试框架 Jasmine 的一部分。我们将在下一章讨论单元测试，但目前让我们专注于代码的其余部分。

我们声明了一个名为`scope`的变量，它是一个空的 JavaScript 对象，然后声明了一个名为`ctrl`的变量，它使用`new`关键字来创建我们`PhoneListCtrl`类的一个实例。`new PhoneListCtrl(scope)`语法表明 Angular 正在使用控制器的定义，就像我们在 TypeScript 中使用普通类一样。

在 TypeScript 中构建相同的对象将允许我们使用 TypeScript 类，如下所示：

```ts
var phonecatApp = angular.module('phonecatApp', []);

class PhoneListCtrl  {
    constructor($scope) {
        $scope.phones = [
            { 'name': 'Nexus S',
              'snippet': 'Fast just got faster' },
            { 'name': 'Motorola',
              'snippet': 'Next generation tablet' },
            { 'name': 'Motorola Xoom',
              'snippet': 'Next, next generation tablet' }
        ];
    }
};
```

我们的第一行与之前的 JavaScript 示例相同。然而，我们使用了 TypeScript 类语法来创建一个名为`PhoneListCtrl`的类。通过创建一个 TypeScript 类，我们现在可以像在 Jasmine 测试代码中所示的那样使用这个类：`ctrl = new PhoneListCtrl(scope)`。我们`PhoneListCtrl`类的`constructor`函数现在充当了原始 JavaScript 示例中看到的匿名函数：

```ts
phonecatApp.controller('PhoneListCtrl', function ($scope) {
    // this function is replaced by the constructor
}
```

## Angular 类和$scope

让我们进一步扩展我们的`PhoneListCtrl`类，并看看完成后会是什么样子：

```ts
class PhoneListCtrl  {
    myScope: IScope;
    constructor($scope, $http: ng.IHttpService, Phone) {
        this.myScope = $scope;
        this.myScope.phones = Phone.query();
        $scope.orderProp = 'age';
         _.bindAll(this, 'GetPhonesSuccess');
    }
    GetPhonesSuccess(data: any) {
        this.myScope.phones = data;
    }
};
```

这个类中需要注意的第一件事是，我们正在定义一个名为`myScope`的变量，并将通过构造函数传入的`$scope`参数存储在这个内部变量中。这是因为 JavaScript 的词法作用域规则。请注意构造函数末尾的`_.bindAll`调用。这个 Underscore 实用函数将确保每当调用`GetPhonesSuccess`函数时，它将在类实例的上下文中使用变量`this`，而不是在调用代码的上下文中。我们将在后面的章节中详细讨论`_.bindAll`的用法。

`GetPhonesSuccess`函数在其实现中使用了`this.myScope`变量。这就是为什么我们需要将初始的`$scope`参数存储在内部变量中的原因。

从这段代码中我们注意到的另一件事是，`myScope`变量被类型化为一个名为`IScope`的接口，需要定义如下：

```ts
interface IScope {
    phones: IPhone[];
}
interface IPhone {
    age: number;
    id: string;
    imageUrl: string;
    name: string;
    snippet: string;
};
```

这个`IScope`接口只包含了一个`IPhone`类型的对象数组（请原谅这个接口的不幸命名 - 它也可以包含安卓手机）。

这意味着我们在处理`$scope`对象时没有标准的接口或 TypeScript 类型可用。由于其性质，`$scope`参数的类型会根据 Angular 运行时调用它的时间和位置而改变，因此我们需要定义一个`IScope`接口，并将`myScope`变量强类型化为这个接口。

`PhoneListCtrl`类的构造函数中另一个有趣的事情是`$http`参数的类型。它被设置为`ng.IHttpService`类型。这个`IHttpService`接口在 Angular 的声明文件中找到。为了在 TypeScript 中使用 Angular 变量（如`$scope`或`$http`），我们需要在声明文件中找到匹配的接口，然后才能使用这些变量上可用的任何 Angular 函数。

在这个构造函数代码中要注意的最后一个参数是名为`Phone`的参数。它没有分配给它的 TypeScript 类型，因此自动变成了`any`类型。让我们快速看一下这个`Phone`服务的实现，如下所示：

```ts
var phonecatServices = angular.module('phonecatServices', ['ngResource']);

phonecatServices.factory('Phone',
    [
        '$resource', ($resource) => {
            return $resource('phones/:phoneId.json', {}, {
                query: {
                    method: 'GET',
                    params: {
                        phoneId: 'phones'
                    },
                    isArray: true
                }
            });
        }
    ]
);
```

这段代码片段的第一行再次使用`angular.module`全局函数创建了一个名为`phonecatServices`的全局变量。然后我们调用`phonecatServices`变量上可用的`factory`函数，以定义我们的`Phone`资源。这个`factory`函数使用一个名为`'Phone'`的字符串来定义`Phone`资源，然后使用 Angular 的依赖注入语法来注入一个`$resource`对象。通过查看这段代码，我们可以看到我们不能轻松地为 Angular 在这里使用标准的 TypeScript 类。也不能在这个 Angular 服务上使用标准的 TypeScript 接口或继承。

## Angular TypeScript 兼容性

在使用 TypeScript 编写 Angular 代码时，我们可以在某些情况下使用类，但在其他情况下必须依赖于底层的 Angular 函数（如`module`和`factory`）来定义我们的对象。此外，当使用标准的 Angular 服务（如`$http`或`$resource`）时，我们需要指定匹配的声明文件接口才能使用这些服务。因此，我们可以描述 Angular 库与 TypeScript 的兼容性为中等。

# 继承 - Angular 与 Backbone

继承是面向对象编程的一个非常强大的特性，也是在使用 JavaScript 框架时的一个基本概念。在每个框架中使用 Backbone 控制器或 Angular 控制器都依赖于某些特性或可用的功能。然而，我们已经看到，每个框架以不同的方式实现继承。

由于 JavaScript 没有继承的概念，每个框架都需要找到一种实现方式，以便框架可以允许我们扩展基类及其功能。在 Backbone 中，这种继承实现是通过每个 Backbone 对象的`extend`函数来实现的。正如我们所见，TypeScript 的`extends`关键字与 Backbone 的实现方式类似，允许框架和语言相互配合。

另一方面，Angular 使用自己的继承实现，并在 angular 全局命名空间上定义函数来创建类（即`angular.module`）。我们有时也可以使用应用程序的实例（即`<appName>.controller`）来创建模块或控制器。不过，我们发现 Angular 与 TypeScript 类似地使用控制器，因此我们可以简单地创建标准的 TypeScript 类，这些类将在 Angular 应用程序中起作用。

到目前为止，我们只是浅尝辄止了 Angular TypeScript 语法和 Backbone TypeScript 语法。这个练习的目的是尝试理解如何在这两个第三方框架中使用 TypeScript。

一定要访问[`todomvc.com`](http://todomvc.com)，并查看用 TypeScript 编写的 Angular 和 Backbone 的 Todo 应用程序的完整源代码。它们可以在示例部分的**Compile-to-JS**选项卡中找到。这些运行的代码示例，结合这些网站上的文档，将在尝试在外部第三方库（如 Angular 或 Backbone）中编写 TypeScript 语法时，证明是一个宝贵的资源。

## Angular 2.0

微软 TypeScript 团队和谷歌 Angular 团队刚刚完成了数月的合作，并宣布即将发布的名为 Angular 2.0 的 Angular 版本将使用 TypeScript 构建。最初，Angular 2.0 将使用一种名为 AtScript 的新语言进行 Angular 开发。然而，在微软和谷歌团队的合作工作期间，AtScript 的功能已经在 TypeScript 中实现，这是 Angular 2.0 开发所需的。这意味着一旦 Angular 2.0 库和 TypeScript 编译器的 1.5 版可用，Angular 2.0 库将被归类为与 TypeScript 高度兼容。

# ExtJs

ExtJs 是一个流行的 JavaScript 库，拥有各种各样的小部件、网格、图形组件、布局组件等。在 4.0 版中，ExtJs 将模型、视图、控制器式的应用程序架构整合到他们的库中。虽然它对于开源开发是免费的，但对于商业用途需要许可证。它受到开发团队的欢迎，这些团队正在构建基于 Web 的桌面替代品，因为它的外观和感觉与普通的桌面应用程序相当。ExtJs 默认确保每个应用程序或组件在任何浏览器中运行时看起来和感觉都完全相同，并且几乎不需要 CSS 或 HTML。

然而，尽管社区施加了很大压力，ExtJs 团队尚未发布官方的 TypeScript 声明文件。幸运的是，更广泛的 JavaScript 社区已经出手相助，首先是 Mike Aubury。他编写了一个小型实用程序，从 ExtJs 文档中生成声明文件（[`github.com/zz9pa/extjsTypescript`](https://github.com/zz9pa/extjsTypescript)）。

这项工作是否影响了 DefinitelyTyped 上当前版本的 ExtJs 定义，还有待观察，但 Mike Aubury 的原始定义和 DefinitelyTyped 上 brian428 的当前版本非常相似。

## 在 ExtJs 中创建类

ExtJs 是一个以自己的方式做事的 JavaScript 库。如果我们要对 Backbone、Angular 和 ExtJs 进行分类，我们可能会说 Backbone 是一个高度兼容的 TypeScript 库。换句话说，TypeScript 中的类和继承语言特性与 Backbone 高度兼容。

在这种情况下，Angular 将是一个部分兼容的库，其中一些 Angular 对象的元素符合 TypeScript 语言特性。另一方面，ExtJs 将是一个最低限度兼容的库，几乎没有适用于该库的 TypeScript 语言特性。

让我们来看一个用 TypeScript 编写的示例 ExtJs 4.0 应用程序。考虑以下代码：

```ts
Ext.application(
    {
        name: 'SampleApp',
        appFolder: '/code/sample',
        controllers: ['SampleController'],
        launch: () => {

            Ext.create('Ext.container.Viewport', {
                layout: 'fit',
                items: [{
                    xtype: 'panel',
                    title: 'Sample App',
                    html: 'This is a Sample Viewport'
                }]
            });

        }

    }
);
```

我们首先通过在`Ext`全局实例上调用`application`函数来创建一个 ExtJs 应用程序。然后，`application`函数使用一个 JavaScript 对象，在第一个和最后一个大括号`{ }`中定义属性和函数。这个 ExtJs 应用程序将`name`属性设置为`SampleApp`，`appFolder`属性设置为`/code/sample`，`controllers`属性设置为一个包含一个条目的数组：`'SampleController'`。

然后我们定义了一个`launch`属性，这是一个匿名函数。这个`launch`函数然后使用全局`Ext`实例上的`create`函数来创建一个类。`create`函数使用`"Ext.container.Viewport"`名称来创建`Ext.container.Viewport`类的一个实例，该类具有`layout`和`items`属性。`layout`属性只能包含特定一组值之一，例如`'fit'`、`'auto'`或`'table'`。`items`数组包含进一步的 ExtJs 特定对象，这些对象根据它们的`xtype`属性创建。

ExtJs 是那种不直观的库之一。作为程序员，你需要随时打开一个浏览器窗口，查看库文档，并用它来弄清楚每个属性对于每种可用类的含义。它还有很多魔术字符串 - 在前面的示例中，如果我们错写了`'Ext.container.Viewport'`字符串，或者在正确的位置忘记了大写，`Ext.create`函数将会失败。对于 ExtJs 来说，`'viewport'`和`'ViewPort'`是不同的。记住，我们在 TypeScript 中解决魔术字符串的一个方法是使用枚举。不幸的是，当前版本的 ExtJs 声明文件没有一组枚举来表示这些类类型。

## 使用类型转换

然而，我们可以使用 TypeScript 的类型转换语言特性来帮助编写 ExtJs 代码。如果我们知道我们要创建的 ExtJs 对象的类型，我们可以将 JavaScript 对象转换为这种类型，然后使用 TypeScript 来检查我们使用的属性是否适用于该类型的 ExtJs 对象。为了帮助理解这个概念，让我们只考虑`Ext.application`的外部定义。去掉内部代码后，对`Ext`全局对象上的`application`函数的调用将被简化为这样：

```ts
Ext.application(
    {
        // properties of an Ext.application
        // are set within this JavaScript
        // object block
    }
);
```

使用 TypeScript 声明文件、类型转换和大量的 ExtJs 文档，我们知道内部 JavaScript 对象应该是`Ext.app.IApplication`类型，因此我们可以将这个对象转换为如下形式：

```ts
Ext.application(
   <Ext.app.IApplication> {
       // this JavaScript block is strongly
       // type to be of Ext.app.IApplication
    }
);
```

这段代码片段的第二行现在使用了 TypeScript 类型转换语法，将大括号`{ }`之间的 JavaScript 对象转换为`Ext.app.IApplication`类型。这给我们提供了强类型检查和智能感知，如下图所示：

![使用类型转换](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/9665OS_05_03.jpg)

Visual Studio 对 ExtJs 配置块的智能感知

类似地，这些显式类型转换也可以用于创建 ExtJs 类的任何 JavaScript 对象。目前在 DefinitelyTyped 上的 ExtJs 声明文件使用与 ExtJs 文档相同的对象定义名称，因此找到正确的类型应该相当简单。

上述显式类型转换的技术几乎是我们可以在 ExtJs 库中使用的唯一的 TypeScript 语言特性 - 但这仍然突显了对象的强类型化如何在开发过程中帮助我们，使我们的代码更加健壮，更加抗错误。

## ExtJs 特定的 TypeScript 编译器

如果你经常使用 ExtJs，那么你可能会想看看 Gareth Smith、Fabio Parra dos Santos 及其团队在[`github.com/fabioparra/TypeScript`](https://github.com/fabioparra/TypeScript)上的工作。这个项目是 TypeScript 编译器的一个分支，它将从标准的 TypeScript 类中生成 ExtJs 类。使用这个版本的编译器可以改变正常的 ExtJs 开发方式，允许使用自然的 TypeScript 类语法，通过`extends`关键字使用继承，以及自然的模块命名，而不需要魔术字符串。这个团队的工作表明，由于 TypeScript 编译器是开源的，它可以被扩展和修改以特定的方式生成 JavaScript，或者针对特定的库。向 Gareth、Fabio 和他们的团队致敬，因为他们在这个领域做出了开创性的工作。

# 总结

在本章中，我们已经看过第三方 JavaScript 库以及它们如何在 TypeScript 应用程序中使用。我们首先看了包括社区发布的 TypeScript 声明文件在内的各种包含方式，从下载原始文件到使用 NuGet 和 TSD 等包管理器。然后，我们看了三种类型的第三方库，并讨论了如何将这些库与 TypeScript 集成。我们探讨了 Backbone，它可以被归类为高度兼容的第三方库，Angular 是一个部分兼容的库，而 ExtJs 是一个最低限度兼容的库。我们看到了 TypeScript 语言的各种特性如何与这些库共存，并展示了在这些情况下 TypeScript 等效代码会是什么样子。在下一章中，我们将看看测试驱动开发，并探讨一些可用于单元测试、集成测试和自动验收测试的库。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需著作权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第六章：测试驱动开发

在过去的几年中，**模型视图控制器**（**MVC**）、**模型视图呈现器**（**MVP**）和**模型视图视图模型**（**MVVM**）模式的流行使得出现了一系列第三方 JavaScript 库，每个库都实现了自己的这些模式的版本。例如，Backbone 可以被描述为 MVP 实现，其中视图充当呈现器。ExtJS 4 引入了 MVC 模式到他们的框架中，而 Angular 可以被描述为更多的 MVVM 框架。当一起讨论这组模式时，有些人将它们描述为**模型视图任何**（**MVW**）或**模型视图某物**（**MV***）。

编写应用程序的 MV*风格的一些好处包括模块化和关注点分离。构建应用程序的 MV*风格还带来了一个巨大的优势——能够编写可测试的 JavaScript。使用 MV*允许我们对我们精心编写的 JavaScript 进行单元测试、集成测试和功能测试。这意味着我们可以测试我们的渲染函数，以确保 DOM 元素在页面上正确显示。我们还可以模拟按钮点击、下拉选择和动画。我们还可以将这些测试扩展到页面转换，包括登录页面和主页。通过为我们的应用程序构建大量的测试，我们将获得对我们的代码按预期工作的信心，并且它将允许我们随时重构我们的代码。

在本章中，我们将讨论与 TypeScript 相关的测试驱动开发。我们将讨论一些更受欢迎的测试框架，编写一些单元测试，然后讨论测试运行器和持续集成技术。

# 测试驱动开发

**测试驱动开发**（**TDD**）是一个开发过程，或者说是一个开发范式，它从测试开始，并通过这些测试推动生产代码的动力。测试驱动开发意味着提出问题“我如何知道我已经解决了问题？”而不仅仅是“我如何解决这个问题？”

测试驱动方法的基本步骤如下：

+   编写一个失败的测试

+   运行测试以确保它失败

+   编写代码使测试通过

+   运行测试以查看它是否通过

+   运行所有测试以确保新代码不会破坏其他任何测试

+   重复这个过程

使用测试驱动开发实践实际上是一种心态。一些开发人员遵循这种方法，首先编写测试，而其他人先编写他们的代码，然后再编写测试。然后还有一些人根本不写测试。如果你属于最后一类人，那么希望你在本章学到的技术将帮助你朝正确的方向迈出第一步。

有很多借口可以用来不写单元测试。一些典型的借口包括诸如“测试框架不在我们最初的报价中”，或者“它将增加 20%的开发时间”，或者“测试已经过时，所以我们不再运行它们”。然而，事实是，在当今这个时代，我们不能不写测试。应用程序的规模和复杂性不断增长，需求随时间变化。一个拥有良好测试套件的应用程序可以比没有测试的应用程序更快地进行修改，并且对未来的需求变化更具有弹性。这时，单元测试的真正成本节约才显现出来。通过为应用程序编写单元测试，您正在未来保护它，并确保对代码库的任何更改不会破坏现有功能。

在 JavaScript 领域的 TDD 为我们的代码覆盖率增加了另一层。开发团队经常只编写针对应用程序的服务器端逻辑的测试。例如，在 Visual Studio 空间中，这些测试通常只针对控制器、视图和基础业务逻辑的 MVC 框架。测试应用程序的客户端逻辑一直是相当困难的——换句话说，就是实际呈现的 HTML 和基于用户的交互。

JavaScript 测试框架为我们提供了填补这一空白的工具。现在我们可以开始对呈现的 HTML 进行单元测试，以及模拟用户交互，比如填写表单和点击按钮。这种额外的测试层，结合服务器端测试，意味着我们有一种方法来对应用程序的每一层进行单元测试——从服务器端业务逻辑，通过服务器端页面呈现，直到呈现和用户交互。对前端用户交互进行单元测试是任何 JavaScript MV*框架的最大优势之一。事实上，它甚至可能影响您在选择技术栈时所做的架构决策。

# 单元测试、集成测试和验收测试

自动化测试可以分为三个一般领域，或测试类型——单元测试、集成测试和验收测试。我们也可以将这些测试描述为黑盒测试或白盒测试。白盒测试是测试者知道被测试代码的内部逻辑或结构的测试。另一方面，黑盒测试是测试者不知道被测试代码的内部设计或逻辑的测试。

## 单元测试

单元测试通常是一种白盒测试，其中代码块的所有外部接口都被模拟或存根化。例如，如果我们正在测试一些进行异步调用以加载一块 JSON 的代码，单元测试这段代码将需要模拟返回的 JSON。这种技术确保被测试对象始终获得已知的数据集。当出现新的需求时，这个已知的数据集当然可以增长和扩展。被测试对象应该被设计为与接口交互，以便这些接口可以在单元测试场景中轻松地被模拟或存根化。

## 集成测试

集成测试是另一种白盒测试的形式，允许被测试的对象在接近真实代码的环境中运行。在我们之前的例子中，一些代码进行异步调用以加载一块 JSON，集成测试需要实际调用生成 JSON 的**表述性状态转移**（**REST**）服务。如果这个 REST 服务依赖于来自数据库的数据，那么集成测试就需要数据库中与集成测试场景匹配的数据。如果我们将单元测试描述为在被测试对象周围有一个边界，那么集成测试就是简单地扩展这个边界，以包括依赖对象或服务。

为应用程序构建自动化集成测试将极大地提高应用程序的质量。考虑我们一直在使用的场景——一段代码调用 REST 服务获取一些 JSON 数据。有人很容易改变 REST 服务返回的 JSON 数据的结构。我们的单元测试仍然会通过，因为它们实际上并没有调用 REST 服务器端代码，但我们的应用程序会出现问题，因为返回的 JSON 不是我们期望的。

没有集成测试，这些类型的错误只能在手动测试的后期阶段被发现。考虑集成测试，实现特定的数据集用于集成测试，并将其构建到测试套件中，将能够及早消除这些类型的错误。

## 验收测试

验收测试是黑盒测试，通常基于场景。它们可能包含多个用户屏幕或用户交互以通过。这些测试通常也由测试团队执行，因为可能需要登录到应用程序，搜索特定的数据，更新数据等。通过一些规划，我们还可以将这些验收测试的部分自动化为集成套件，因为我们在 JavaScript 中有能力查找并单击按钮，将数据插入所需字段，或选择下拉项。项目拥有的验收测试越多，它就会越健壮。

### 注意

在测试驱动开发方法论中，手动测试团队发现的每个错误都必须导致新的单元测试、集成测试或验收测试的创建。这种方法将有助于确保一旦发现并修复错误，它就不会再次出现。

# 使用持续集成

当为任何应用程序编写单元测试时，很快就会变得重要，设置一个构建服务器，并将您的测试作为每个源代码控制检入的一部分运行。当您的开发团队超出单个开发人员时，使用**持续集成**（**CI**）构建服务器变得至关重要。这个构建服务器将确保提交到源代码控制服务器的任何代码都通过所有已知的单元测试、集成测试和自动验收测试。构建服务器还负责标记构建并生成在部署过程中需要使用的任何部署工件。

构建服务器的基本步骤如下：

+   检出最新版本的源代码，并增加构建编号

+   在构建服务器上编译应用程序

+   运行任何服务器端单元测试

+   为部署打包应用程序

+   将软件包部署到构建环境

+   运行任何服务器端集成测试

+   运行任何 JavaScript 单元测试、集成测试和验收测试

+   标记更改集和构建编号为通过或失败

+   如果构建失败，请通知责任人

### 注意

如果前面的任何步骤失败，构建服务器应该失败。

## 持续集成的好处

使用构建服务器运行前面的步骤对任何开发团队都带来巨大的好处。首先，应用程序在构建服务器上编译，这意味着任何使用的工具或外部库都需要安装在构建服务器上。这为您的开发团队提供了在新机器上安装软件的机会，以便编译或运行应用程序。

其次，在尝试打包之前，可以运行一组标准的服务器端单元测试。在 Visual Studio 项目中，这些测试将是使用任何流行的.NET 测试框架构建的 C#单元测试，例如 MSTest、NUnit 或 xUnit。

接下来，运行整个应用程序的打包步骤。假设一名开发人员在项目中包含了一个新的 JavaScript 库，但忘记将其添加到 Visual Studio 解决方案中。在这种情况下，所有测试将在他们的本地计算机上运行，但由于缺少库文件，构建将失败。如果我们在这个阶段部署站点，运行应用程序将导致 404 错误-文件未找到。通过运行打包步骤，这类错误可以很快被发现。

一旦成功完成了打包步骤，构建服务器应该将站点部署到一个特别标记的构建环境中。这个构建环境仅用于 CI 构建，因此必须具有自己的数据库实例、Web 服务引用等，专门为 CI 构建设置。再次，实际上部署到目标环境测试了部署工件以及部署过程。通过为自动打包部署设置构建环境，您的团队再次能够记录部署的要求和过程。

在这个阶段，我们在一个独立的构建环境上完整地运行了我们的网站实例。然后，我们可以轻松地针对特定的网页运行我们的 JavaScript 测试，并直接在完整版本的网站上运行集成或自动接受测试。这样，我们可以编写针对真实网站 REST 服务的测试，而无需模拟这些集成点。因此，实际上，我们是从头开始测试应用程序。显然，我们可能需要确保我们的构建环境具有一组特定的数据，可以用于集成测试，或者一种生成所需数据集的方法，我们的集成测试将需要。

## 选择构建服务器

有许多持续集成构建服务器，包括 TeamCity、Jenkins 和 Team Foundation Server（TFS）。

### Team Foundation Server

TFS 需要在其构建代理上进行特定配置，以便能够运行 Web 浏览器的实例。对于较大的项目，实际在特定浏览器中运行 JavaScript 测试是有意义的，并很快就成为必需的步骤。您可能需要支持多个浏览器，并希望在 Firefox、Chrome、IE、Safari 或其他浏览器中运行您的测试。TFS 还使用 Windows Workflow Foundation（WF）来配置构建步骤，这需要相当多的经验和知识来修改。

### Jenkins

Jenkins 是一个开源的免费使用的 CI 构建服务器。它有广泛的社区使用和许多插件。Jenkins 的安装和配置相当简单，Jenkins 将允许进程运行浏览器实例，使其与基于浏览器的 JavaScript 单元测试兼容。Jenkins 的构建步骤是基于命令行的，有时需要一些技巧来正确配置构建步骤。

### TeamCity

一个非常受欢迎且功能强大的免费设置的构建服务器是 TeamCity。如果您有少量开发人员（<20）和少量项目（<20），TeamCity 允许免费安装。完整的商业许可证只需约 1500 美元，这使得大多数组织都能负担得起。在 TeamCity 中配置构建步骤比在 Jenkins 或 TFS 中要容易得多，因为它使用向导样式的配置，具体取决于您正在创建的构建步骤的类型。TeamCity 还具有丰富的围绕单元测试的功能，能够显示每个单元测试的图表，因此被认为是构建服务器的最佳选择。

# 单元测试框架

有许多可用的 JavaScript 单元测试框架，也有一些用 TypeScript 编写的框架。最受欢迎的两个 JavaScript 框架是 Jasmine（[`jasmine.github.io/`](http://jasmine.github.io/)）和 QUnit（[`qunitjs.com/`](http://qunitjs.com/)）。如果您正在编写 Node TypeScript 代码，那么您可能想看看 mocha（[`github.com/mochajs/mocha/wiki`](https://github.com/mochajs/mocha/wiki)）。

两个基于 TypeScript 的测试框架是 MaxUnit（[`github.com/KnowledgeLakegithub/MaxUnit`](https://github.com/KnowledgeLakegithub/MaxUnit)）和 tsUnit（[`github.com/Steve-Fenton/tsUnit`](https://github.com/Steve-Fenton/tsUnit)）。不幸的是，MaxUnit 和 tsUnit 都是这个领域的新手，因此可能没有老一辈更流行的框架所固有的功能。例如，MaxUnit 在撰写时没有任何文档，而 tsUnit 没有与 CI 构建服务器兼容的测试报告框架。随着时间的推移，这些 TypeScript 框架可能会成长，但是看到使用第三方库和使用 DefinitelyTyped 声明文件编写 QUnit 或 Jasmine 的单元测试是非常简单的。

在本章的其余部分，我们将使用 Jasmine 2.0 作为我们的测试框架。

# Jasmine

在本章的这一部分，我们将创建一个基于 MVC 框架项目类型的新的 Visual Studio 项目。现在，我们可以使用空的 MVC 模板。

Jasmine 可以通过以下两个 NuGet 包安装到我们的新 TypeScript 项目中：

```ts
Install-Package JasmineTest
Install-Package jasmine.TypeScript.DefinitelyTyped

```

有了这两个包，我们就有了所需的 JavaScript 库和 TypeScript 定义文件，可以开始编写 Jasmine 测试。

### 注意

通过 NuGet 默认安装`JasmineTest`使用了 ASP.NET MVC 框架，并在`Controllers`目录中创建了一个`JasmineController`。如果您没有使用 MVC 框架，或者在 Node 环境中安装了这个包，那么这个`JasmineController`应该被删除，因为它会导致编译错误。在本章的后面，我们将展示如何对这个`JasmineController`运行集成测试，所以最好暂时保留它。

## 一个简单的 Jasmine 测试

Jasmine 使用一种简单的格式来编写测试。考虑以下 TypeScript 代码：

```ts
describe("tests/01_SimpleJasmineTests.ts ", () => {
    it("should fail", () => {
        var undefinedValue;
        expect(undefinedValue).toBeDefined();
    });
});
```

这个片段以一个名为`describe`的 Jasmine 函数开始，它接受两个参数。第一个参数是测试套件的名称，第二个是包含我们的测试套件的匿名函数。接下来的一行使用了名为`it`的 Jasmine 函数，它也接受两个参数。第一个参数是测试名称，第二个参数是包含我们的测试的匿名函数；换句话说，`it`匿名函数中的内容就是我们的实际测试。这个测试首先定义了一个名为`undefinedValue`的变量，但实际上并没有设置它的值。接下来，我们使用了 Jasmine 函数`expect`。仅仅通过阅读这个`expect`语句的代码，我们就可以快速理解这个单元测试在做什么。它期望`undefinedValue`变量的值应该被定义，也就是不是`undefined`。

`expect`函数接受一个参数，并返回一个 Jasmine 匹配器。然后我们可以调用任何 Jasmine 匹配器函数来评估传入`expect`的值与匹配器函数的关系。`expect`关键字类似于其他测试库中的`Assert`关键字。`expect`语句的格式是人类可读的，使得 Jasmine 的期望相对简单易懂。

## Jasmine SpecRunner.html 文件

为了运行这个测试，我们需要一个包含所有相关 Jasmine 第三方库以及我们的测试 JavaScript 文件的 HTML 页面。我们可以创建一个`SpecRunner.html`文件，其中包含以下 HTML：

```ts
<!DOCTYPE html>
<html >
    <head>
        <title>Jasmine Spec Runner</title>
        <link rel="shortcut icon" type="image/png" href="/Content/jasmine/jasmine_favicon.png">
        <link rel="stylesheet" type="text/css" href="/Content/jasmine/jasmine.css">
        <script type="text/javascript" src="img/jasmine.js"></script>
        <script type="text/javascript" src="img/jasmine-html.js"></script>
        <script type="text/javascript" src="img/boot.js"></script>
        <script type="text/javascript" src="img/01_SimpleJasmineTests.js"></script>

    </head>
<body>

</body>
</html>
```

这个 HTML 页面只是包含了所需的 Jasmine 文件，`jasmine.css`、`jasmine.js`、`jasmine-html.js`和`boot.js`。最后一行包含了从我们的 TypeScript 测试文件编译出的 JavaScript 文件。

如果我们将这个页面设置为在 Visual Studio 中的启动页面并运行它，我们应该会看到一个失败的单元测试：

![Jasmine SpecRunner.html 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_01.jpg)

显示 Jasmine 输出的 SpecRunner.html 页面

太棒了！我们正在遵循测试驱动开发的过程，首先创建一个失败的单元测试。结果正是我们所期望的。我们的名为`undefinedVariable`的变量还没有被赋值，因此将是`undefined`。如果我们遵循 TDD 过程的下一步，我们应该编写使测试通过的代码。更新我们的测试如下将确保测试通过：

```ts
describe("tests/01_SimpleJasmineTests.ts ", () => {
    it("value that has been assigned should be defined", () => {
        var undefinedValue = "test";
        expect(undefinedValue).toBeDefined();
    });
});
```

请注意，我们已经更新了我们的测试名称以描述测试的目标。为了使测试通过，我们只需将值`"test"`赋给我们的`undefinedValue`变量。现在运行`SpecRunner.html`页面将显示一个通过的测试。

## 匹配器

Jasmine 有各种各样的匹配器可以在测试中使用，并且还允许我们编写和包含自定义匹配器。从以下 TypeScript 代码中可以看出，Jasmine 匹配器的语法非常直观：

```ts
    var undefValue;
    expect(undefValue).not.toBeDefined();
```

在这里，我们使用`.not.`匹配器语法来检查变量`undefValue`是否确实是`undefined`。

```ts
    var definedValue = 2;
    expect(definedValue).not.toBe(null);
```

这个`expect`语句使用`not.toBe`匹配器来确保`definedValue`变量不是`null`。

```ts
    expect(definedValue).toBe(2);
```

在这里，我们使用`.toBe`匹配器来检查`definedValue`实际上是一个值为 2 的数字。

```ts
    expect(definedValue.toString()).toEqual("2");
```

这个`expect`语句使用`toEqual`匹配器来确保`toString`函数将返回字符串值`"2"`。

```ts
    var trueValue = true;
    expect(trueValue).toBeTruthy();
    expect(trueValue).not.toBeFalsy();
```

在这里，我们使用`toBeTruthy`和`toBeFalsy`匹配器来测试`boolean`值。

```ts
    var stringValue = "this is a string";
    expect(stringValue).toContain("is");
    expect(stringValue).not.toContain("test");
```

最后，我们还可以使用`toContain`匹配器来解析一个字符串，并测试它是否包含另一个字符串，或者使用`.not.`匹配器与`toContain`进行相反的测试。

一定要前往 Jasmine 网站查看匹配器的完整列表，以及编写自定义匹配器的详细信息。

## 测试启动和拆卸

与其他测试框架一样，Jasmine 提供了一种定义函数的机制，这些函数将在每个测试之前和之后运行，或作为测试启动和拆卸机制。在 Jasmine 中，`beforeEach`和`afterEach`函数充当测试启动和拆卸函数，如下面的 TypeScript 代码所示：

```ts
describe("beforeEach and afterEach tests", () => {
    var myString;

    beforeEach(() => {
        myString = "this is a test string";
    });
    afterEach(() => {
        expect(myString).toBeUndefined();
    });

    it("should find then clear the myString variable", () => {
        expect(myString).toEqual("this is a test string");
        myString = undefined;
    });

});
```

在这个测试中，我们在匿名函数的开头定义了一个名为`myString`的变量。根据 JavaScript 的词法作用域规则，这个`myString`变量将在接下来的`beforeEach`、`afterEach`和`it`函数中可用。在`beforeEach`函数中，这个变量被设置为一个字符串值。在`afterEach`函数中，测试这个变量是否已被重置为`undefined`。我们在测试中的期望是，这个变量已经通过`beforeEach`函数设置。在测试结束时，我们将变量重置为`undefined`。请注意，`afterEach`函数也调用了一个`expect`，在这种情况下是为了确保测试已将变量重置为`undefined`。

### 注意

Jasmine 2.1 版本引入了第二个版本的设置和拆卸，称为`beforeAll`和`afterAll`。在撰写本书时，`jasmine.js`和`jasmine.d.ts`文件的版本都还没有更新到 v2.1。

## 数据驱动测试

为了展示 Jasmine 测试库的可扩展性，JP Castro 编写了一个非常简短但功能强大的实用程序，以在 Jasmine 中提供数据驱动测试。他关于这个主题的博客可以在这里找到（[`blog.jphpsf.com/2012/08/30/drying-up-your-javascript-jasmine-tests/`](http://blog.jphpsf.com/2012/08/30/drying-up-your-javascript-jasmine-tests/)），GitHub 存储库可以在这里找到（[`github.com/jphpsf/jasmine-data-provider`](https://github.com/jphpsf/jasmine-data-provider)）。这个简单的扩展允许我们编写直观的 Jasmine 测试，每个测试都带有一个参数，如下所示：

```ts
describe("data driven tests", () => {
    using<string>("valid values", [
        "first string",
        "second string",
        "third string"
    ], (value) => {
        it("should contain string (" + value + ")", () => {
            expect(value).toContain("string");
        });
    });
});
```

在这里，我们将我们的`it`测试函数包裹在另一个名为`using`的函数中。这个`using`函数接受三个参数：值集的字符串描述，值的数组，以及一个函数定义。这个最后的函数定义使用变量`value`，并将使用这个值来调用我们的测试。还要注意，在调用我们的测试时，我们正在动态更改测试名称，以包含传入的`value`参数。这是为了确保每个测试都有一个唯一的测试名称。

前面的解决方案只需要 JP Castro 的 Jasmine 扩展，如下面的 JavaScript 代码所示：

```ts
function using(name, values, func) {
    for (var i = 0, count = values.length; i < count; i++) {
        if (Object.prototype.toString.call(values[i]) !== '[object Array]') 
        {
            values[i] = [values[i]];
        }
        func.apply(this, values[i]);
    }
}
```

这是一个非常简单的名为`using`的函数，它接受我们之前提到的三个参数。该函数通过数组值进行简单的循环，并将每个数组值传递给我们的测试。

我们需要的最后一样东西是一个用于前面`using`函数的 TypeScript 定义文件。这是一个非常简单的函数声明，如下所示：

```ts
declare function using<T>(
    name: string,
    values : T [],
    func : (T) => void
);
```

这个 TypeScript 声明使用了泛型语法`<T>`，以确保第二个和第三个参数使用相同的类型。有了这个声明，以及 JavaScript 的`using`函数，我们的代码将正确编译，并且测试将针对数据数组中的每个值运行一次：

```ts
data driven tests
should contain string (first string)
should contain string (second string)
should contain string (third string)

```

## 使用间谍

Jasmine 还有一个非常强大的功能，可以让你的测试看到特定的函数是否被调用，以及它被调用时使用的参数。它还可以用来创建模拟和存根。所有这些功能都包含在 Jasmine 所称的间谍中。

考虑以下测试：

```ts
class MySpiedClass {
    testFunction(arg1: string) {
        console.log(arg1);
    }
}
describe("simple spy", () => {
    it("should register a function call", () => {
        var classInstance = new MySpiedClass();
        spyOn(classInstance, 'testFunction');

        classInstance.testFunction("test");

        expect(classInstance.testFunction).toHaveBeenCalled();
    });
});
```

我们从一个名为`MySpiedClass`的简单类开始，它有一个名为`testFunction`的函数。这个函数接受一个参数，并将参数记录到控制台上。

我们的测试从创建一个`MySpiedClass`的新实例开始，并将其赋值给一个名为`classInstance`的变量。然后我们在`classInstance`变量的`testFunction`函数上创建了一个 Jasmine 间谍。一旦我们创建了一个间谍，就可以调用这个函数。我们的期望是检查这个函数是否被调用。这就是间谍的本质。Jasmine 将“监视”`MySpiedClass`实例的`testFunction`函数，以查看它是否被调用。

### 注意

默认情况下，Jasmine 间谍会阻止对底层函数的调用。换句话说，它们会用 Jasmine 代理替换你试图调用的函数。如果你需要对一个函数进行间谍，但仍然需要执行函数体，你必须使用`.and.callThrough()`流畅语法来指定这种行为。

虽然这只是一个非常简单的例子，但在许多不同的测试场景中，间谍变得非常强大。例如，需要回调参数的类或函数需要一个间谍来确保回调函数实际上被调用。

让我们看看如何测试回调函数是否被正确调用。考虑以下 TypeScript 代码：

```ts
class CallbackClass {
    doCallBack(id: number, callback: (result: string) => void ) {
        var callbackValue = "id:" + id.toString();
        callback(callbackValue);
    }
}

class DoCallBack {
    logValue(value: string) {
        console.log(value);
    }
}
```

在这段代码片段中，我们定义了一个名为`CallbackClass`的类，它有一个名为`doCallback`的函数。这个`doCallback`函数接受一个`number`类型的`id`参数，还有一个`callback`函数。`callback`函数接受一个`string`作为参数，并返回`void`。

我们定义的第二个类有一个名为`logValue`的函数。这个函数的签名与`doCallback`函数上所需的回调函数签名相匹配。使用 Jasmine 间谍，我们可以测试`doCallBack`函数的逻辑。这个逻辑根据传入的`id`参数创建一个字符串，然后用这个字符串调用`callback`函数。我们的测试需要确保这个字符串格式正确。因此，我们的 Jasmine 测试可以写成如下形式：

```ts
describe("using callback spies", () => {
    it("should execute callback with the correct string value", () => {
        var doCallback = new DoCallBack();
        var classUnderTest = new CallbackClass();

        spyOn(doCallback, 'logValue');
        classUnderTest.doCallBack(1, doCallback.logValue);

        expect(callbackSpy.logValue).toHaveBeenCalled();
        expect(callbackSpy.logValue).toHaveBeenCalledWith("id:1");

    });
});
```

这个测试代码首先创建了一个`CallbackClass`类的实例，也创建了一个`DoCallBack`类的实例。然后我们在`DoCallBack`类的`logValue`函数上创建了一个间谍。接着我们调用`doCallback`函数，将`1`作为第一个参数传入，并将`logValue`函数作为第二个参数传入。我们在最后两行的`expect`语句中检查回调函数`logValue`是否被实际调用，以及它被调用时使用的参数。

## 使用间谍作为伪装

Jasmine 间谍的另一个好处是它们可以充当伪装。换句话说，它们代替了对真实函数的调用，而是委托给了 Jasmine 间谍。Jasmine 还允许间谍返回值——这在生成小型模拟框架时非常有用。考虑以下测试：

```ts
Class ClassToFake {
    getValue(): number {
        return 2;
    }
}
describe("using fakes", () => {
    it("calls fake instead of real function", () => {
        var classToFake = new ClassToFake();
        spyOn(classToFake, 'getValue')
            .and.callFake( () => { return 5; }
            );
        expect(classToFake.getValue()).toBe(5);
    });
});
```

我们从一个名为`ClassToFake`的类开始，它有一个名为`getValue`的单一函数，返回`2`。我们的测试然后创建了这个类的一个实例。然后我们调用 Jasmine 的`spyOn`函数来创建一个对`getValue`函数的间谍，然后使用`.and.callFake`语法将一个匿名函数附加为一个伪造函数。这个伪造函数将返回`5`而不是原来会返回`2`的`getValue`函数。测试然后检查当我们在`ClassToFake`实例上调用`getValue`函数时，Jasmine 会用我们的新伪造函数替换原来的`getValue`函数，并返回`5`而不是`2`。

Jasmine 的伪造语法有许多变体，包括抛出错误或返回值的方法，请参考 Jasmine 文档以获取其伪造能力的完整列表。

## 异步测试

JavaScript 的异步特性——由 AJAX 和 jQuery 广泛使用，一直是这门语言的吸引点之一，也是 Node.js 应用程序的主要架构原理。让我们快速看一下一个异步类，然后描述我们应该如何测试它。考虑以下 TypeScript 代码：

```ts
class MockAsyncClass {
    executeSlowFunction(success: (value: string) => void) {
        setTimeout(() => {
            success("success");
        }, 1000);
    }
}
```

`MockAsyncClass`有一个名为`executeSlowFunction`的单一函数，它接受一个名为`success`的函数回调。在`executeSlowFunction`的代码中，我们通过使用`setTimeout`函数模拟了一个异步调用，并且只在`1000`毫秒（1 秒）后调用成功回调。这种行为模拟了标准的 AJAX 调用（它会使用`success`和`error`回调），这可能需要几秒钟才能返回，取决于后端服务器的速度或数据包的大小。

我们对`executeSlowFunction`的测试可能如下所示：

```ts
describe("asynchronous tests", () => {
    it("failing test", () => {

        var mockAsync = new MockAsyncClass();
        var returnedValue;
        mockAsync.executeSlowFunction((value: string) => {
            returnedValue = value;
        });
        expect(returnedValue).toEqual("success");
    });

});
```

首先，我们实例化了`MockAsyncClass`的一个实例，并定义了一个名为`returnedValue`的变量。然后我们用一个匿名函数调用`executeSlowFunction`作为`success`回调函数。这个匿名函数将`returnedValue`的值设置为从`MockAsyncClass`传入的任何值。我们的期望是`returnedValue`应该等于`"success"`。然而，如果我们现在运行这个测试，我们的测试将失败，并显示以下错误消息：

```ts
Expected undefined to equal 'success'.

```

这里发生的情况是，因为`executeSlowFunction`是异步的，JavaScript 不会等到回调函数被调用之后再执行下一行代码。这意味着期望被调用之前`executeSlowFunction`还没有机会调用我们的匿名回调函数（设置`returnedValue`的值）。如果你在`expect(returnValue).toEqual("success")`行上设置一个断点，并在`returnedValue = value`行上设置另一个断点，你会看到期望行先被调用，而`returnedValue`行只在一秒后才被调用。这个时间问题导致了这个测试的失败。我们需要以某种方式让我们的测试等到`executeSlowFunction`调用回调之后再执行我们的期望。

## 使用`done()`函数

Jasmine 2.0 版本引入了一种新的语法来帮助我们处理这种异步测试。在任何`beforeEach`、`afterEach`或`it`函数中，我们传递一个名为`done`的参数，它是一个函数，然后在我们的异步代码的末尾调用它。考虑以下测试：

```ts
describe("asynch tests with done", () => {
    var returnedValue;

    beforeEach((done) => {
        returnedValue = "no_return_value";
        var mockAsync = new MockAsyncClass();
        mockAsync.executeSlowFunction((value: string) => {
            returnedValue = value;
            done();
        });
    });

    it("should return success after 1 second", (done) => {
        expect(returnedValue).toEqual("success");
        done();
    });
});
```

首先，我们已经将`returnedValue`变量移出了我们的测试，并包含了一个`beforeEach`函数，在我们实际的测试之前运行。这个`beforeEach`函数首先重置了`returnValue`的值，然后设置了`MockAsyncClass`的实例。最后调用了这个实例上的`executeSlowFunction`。

请注意`beforeEach`函数接受一个名为`done`的参数，然后在调用`returnedValue = value`行之后调用此`done`函数。还要注意，`it`函数的第二个参数现在也接受一个`done`参数，并在测试完成时调用此`done`函数。

### 注意

来自 Jasmine 文档：在调用`beforeEach`时，`done`函数被调用之前，规范不会开始，并且在调用`done`函数之前，规范不会完成。默认情况下，Jasmine 将等待 5 秒钟，然后导致超时失败。可以使用`jasmine.DEFAULT_TIMEOUT_INTERVAL`变量进行覆盖。

## Jasmine fixtures

很多时候，我们的代码要么负责从 JavaScript 中读取 DOM 元素，要么在大多数情况下操纵 DOM 元素。这意味着任何依赖于 DOM 元素的运行代码，如果底层 HTML 不包含正确的元素或一组元素，可能会失败。另一个名为`jasmine-jquery`的 Jasmine 扩展库允许我们在测试执行之前将 HTML 元素注入到 DOM 中，并在测试运行后从 DOM 中删除它们。

在撰写本书时，此库尚未在 NuGet 上可用，因此我们需要以传统方式下载`jasmine-jquery.js`文件，并将其包含在我们的项目中。但是，TypeScript 定义文件在 NuGet 上是可用的：

```ts
Install-package Jasmine-jquery.TypeScript.DefinitelyTyped

```

### 注意

我们还需要更新`.html`文件，在头部脚本部分包含`jquery.js`和`jasmine-jquery.js`文件。

让我们看一个使用`jasmine-jquery`库注入 DOM 元素的测试。首先，一个操纵特定 DOM 元素的类：

```ts
Class ModifyDomElement {
    setHtml() {
        var elem = $("#my_div");
        elem.html("<p>Hello world</p>");
    }
}
```

这个`ModifyDomElement`类有一个名为`setHtml`的单个函数，它使用 jQuery 查找 id 为`my_div`的 DOM 元素。然后，这个 div 的 HTML 被设置为一个简单的`"Hello world"`段落。现在是我们的 Jasmine 测试：

```ts
describe("fixture tests", () => {
    it("modifies dom element", () => {
        setFixtures("<div id='my_div'></div>");
        var modifyDom = new ModifyDomElement();
        modifyDom.setHtml();
        var modifiedElement = $("#my_div");
        expect(modifiedElement.length).toBeGreaterThan(0);
        expect(modifiedElement.html()).toContain("Hello");
    });
});
```

测试从调用`jasmine-jquery`函数`setFixtures`开始。此函数将提供的 HTML 作为第一个字符串参数直接注入到 DOM 中。然后，我们创建`ModifyDomElement`类的一个实例，并调用`setHtml`函数来修改`my_div`元素。然后，我们将变量`modifiedElement`设置为 DOM 中 jQuery 搜索的结果。如果 jQuery 找到了元素，则其`length`属性将为`> 0`，然后我们可以检查 HTML 是否确实被修改。

### 注意

`jasmine-jquery`提供的 fixture 方法还允许从磁盘加载原始 HTML 文件，而不必编写 HTML 的冗长字符串表示。如果您的 MV*框架使用 HTML 文件片段，这也特别有用。`jasmine-jquery`库还具有从磁盘加载 JSON 的实用程序，并且可以与 jQuery 一起使用的特定构建匹配器。请务必查看文档（[`github.com/velesin/jasmine-jquery`](https://github.com/velesin/jasmine-jquery)）。

## DOM 事件

`jasmine-jquery`库还添加了一些 Jasmine 间谍，以帮助处理 DOM 事件。如果我们正在创建一个按钮，无论是在 TypeScript 代码中还是在 HTML 中，我们都可以确保我们的代码正确响应 DOM 事件，比如`click`。考虑以下代码和测试：

```ts
Function handle_my_click_div_clicked() {
    // do nothing at this time
}
describe("click event tests", () => {
    it("spies on click event element", () => {
        setFixtures("<div id='my_click_div' "+"onclick='handle_my_click_div_clicked'>Click Here</div>");

        var clickEventSpy = spyOnEvent("#my_click_div", "click");

        $('#my_click_div').click();
        expect(clickEventSpy).toHaveBeenTriggered();
    });
});
```

首先，我们定义了一个名为`handle_my_click_div_clicked`的虚拟函数，该函数在 fixture HTML 中使用。仔细查看`setFixtures`函数调用中使用的 HTML，我们创建了一个带有 id 为`my_click_div`的按钮，并且具有一个`onclick` DOM 事件，将调用我们的虚拟函数。然后，我们在`my_click_div` div 上创建一个点击事件的间谍，然后在下一行实际调用点击事件。我们的期望是使用`jasmine-jquery`匹配器`toHaveBeenTriggered`来测试`onclick`处理程序是否被调用。

### 注意

jQuery 和 DOM 操作为我们提供了一种填写表单、单击**提交**、**取消**、**确定**按钮，并一般模拟用户与我们的应用程序的交互的方法。我们可以使用这些技术在 Jasmine 中轻松编写完整的验收或用户验收测试，进一步巩固我们的应用程序，防止错误和变更。

# 茉莉花运行器

有许多方法可以在实际网页之外运行 Jasmine 测试，就像我们一直在做的那样。但请记住，Visual Studio 不支持在直接运行 Internet Explorer 的网页之外调试 TypeScript。在这些情况下，您需要回到目标浏览器中现有的开发人员工具。

大多数测试运行器依赖于一个简单的静态 HTML 页面来包含所有测试，并将启动一个小型的 Web 服务器实例，以便将此 HTML 页面提供给测试运行器。一些测试运行器使用配置文件来实现这一目的，并构建一个无需 HTML 的测试环境。这对于单元测试可能很好，其中代码的集成点被模拟或存根，但这种方法对于集成或验收测试效果不佳。

例如，许多现实世界的 Web 应用程序通过一些服务器端业务逻辑来生成每个 Web 请求的 HTML。例如，身份验证逻辑可能会将用户重定向到登录页面，然后在后续页面请求或 RESTful 数据请求中使用基于表单的身份验证 cookie。在这些情况下，在实际 Web 应用程序之外运行简单的 HTML 页面将不起作用。您需要在实际与 Web 应用程序的其余部分一起托管的页面中运行您的测试。此外，如果您尝试将 JavaScript 测试套件添加到现有的 Web 项目中，这种逻辑可能不容易放在一边。

出于这些原因，我们专注于在我们的 Web 应用程序中使用标准 HTML 页面来运行我们的测试。例如，在 MVC 应用程序中，我们将设置一个 Jasmine 控制器，其中包含一个返回`SpecRunner.cshtml`视图页面的`Run`函数。实际上，NuGet 包`JasmineTest`的默认安装将在安装时为我们设置这些控制器和视图作为标准模板。

## Testem

Testem 是一个基于 Node 的命令行实用程序，当它检测到 JavaScript 文件已被修改时，将连续运行测试套件以针对连接的浏览器。Testem 非常适用于在多个浏览器上快速获得反馈，还具有可以在构建服务器上使用的持续集成标志。Testem 适用于单元测试。更多信息可以在 GitHub 存储库中找到（[`github.com/airportyh/testem`](https://github.com/airportyh/testem)）。

可以通过以下命令在 Node 上安装 Testem：

```ts
Npm install –g testem

```

要运行`testem`，只需在命令行窗口中导航到测试套件的根文件夹，并输入`testem`。Testem 将启动，启动一个 Web 服务器，并邀请您通过浏览器连接到它。按照屏幕截图，Testem 在`http://localhost:7357`上运行。您可以将多个不同的浏览器连接到此 URL，并且 Testem 将针对每个浏览器运行它找到的规范。默认情况下，Testem 将在当前目录中搜索包含测试的 JavaScript 文件，构建包含这些测试的 HTML 页面并执行它们。如果您已经有一个包含您的测试的 HTML 页面，那么可以通过`testem.yml`配置文件将此页面指定给 Testem，如下所示：

```ts
{
    "test_page":"tests/01_SpecRunner.html"
}
```

此 HTML 页面还需要包含 testem.js 文件，以便与 Testem 服务器进行通信。

![Testem](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_02.jpg)

Testem 输出显示三个连接的浏览器

Testem 有许多强大的配置选项，可以在配置文件中指定。请务必前往 GitHub 存储库获取更多信息。

请注意，Testem 将无法与 ASP.NET MVC 控制器路由一起工作，因此不适用于 ASP.NET MVC 站点的集成测试。如果您正在使用 MVC 控制器和视图来生成您的测试套件，例如，您正在运行测试页面的 URL 是`/Jasmine/Run`，Testem 将无法工作。

## Karma

Karma 是由 Angular 团队构建的测试运行器，并在 Angular 教程中大量使用。它只是一个单元测试框架，Angular 团队建议使用 Protractor 构建和运行端到端或集成测试。Karma，像 Testem 一样，运行自己的 Web 服务器实例，以便为测试套件提供所需的页面和工件，并具有大量的配置选项。它也可以用于不针对 Angular 的单元测试。要安装 Karma 以与 Jasmine 2.0 一起使用，我们需要使用`npm`安装一些软件包：

```ts
Npm install karma-jasmine@2_0 –save-dev
Npm install jasmine-core –save-dev
Npm install karma-chrome-launcher
Npm install karma-jasmine-jquery

```

要运行 Karma，我们首先需要一个配置文件。按照惯例，这通常称为`karma.conf.js`。示例`karma`配置文件如下：

```ts
module.exports = function (config) {
    config.set({
        basePath: '../../',
        files: [
          'Scripts/underscore.js',
          'Scripts/jquery-1.8.0.js',
          'Scripts/jasmine-jquery/jasmine-jquery.js',
          'Scripts/jasmine-data-provider/SpecHelper.js',
          'tests/*.js'
        ],
        autoWatch: true,
        frameworks: ['jasmine'],
        browsers: ['Chrome'],
        plugins: [
                'karma-chrome-launcher',
                'karma-jasmine'
        ],

        junitReporter: {
            outputFile: 'test_out/unit.xml',
            suite: 'unit'
        }
    });
};
```

所有 Karma 的配置都必须通过`module.exports`和`config.set`约定传递，如前两行所示。`basePath`参数指定 Web 项目的根路径，并与`karma.config.js`文件所在的目录相关。`files`数组包含要包含在生成的 HTML 文件中的文件列表，并且可以使用`\**\*.js`匹配算法来加载整个目录和子目录的 JavaScript 文件。`autoWatch`参数使 Karma 在后台运行，监视文件的更改，类似于 Testem。Karma 还允许指定各种浏览器，每个浏览器都有自己的启动器插件。最后，本示例中使用`junitReporter`将测试报告回报给 Jenkins CI 服务器。一旦配置文件就位，只需运行以下命令启动 karma：

```ts
karma start <path to karma.config.js>.

```

![Karma](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_03.jpg)

Karma 从一个简单的测试中输出

## Protractor

Protractor 是一个基于 Node 的测试运行器，用于端到端测试。它最初是为 Angular 应用程序设计的，但可以与任何网站一起使用。与 Testem 和 Karma 不同，Protractor 能够浏览到特定页面，然后从 JavaScript 与页面交互，适用于集成测试。它可以检查页面标题等元数据属性，或填写表单和点击按钮，并允许后端服务器重定向到不同的页面。Protractor 文档可以在这里找到（[`github.com/angular/protractor`](https://github.com/angular/protractor)），并可以使用`npm`安装：

```ts
Npm install –g protractor

```

稍后我们将运行 Protractor，但首先让我们讨论 Protractor 用于自动化网页的引擎。

### 使用 Selenium

Selenium 是一个用于 Web 浏览器的驱动程序。它允许对 Web 浏览器进行编程远程控制，并可用于在 Java、C#、Python、Ruby、PHP、Perl 甚至 JavaScript 中创建自动化测试。Protractor 在底层使用 Selenium 来控制 Web 浏览器实例。要安装用于 Protractor 的 Selenium 服务器，请运行以下命令：

```ts
Webdriver-manager update

```

要启动 Selenium 服务器，请运行以下命令：

```ts
Webdriver-manager start

```

如果一切顺利，Selenium 将报告服务器已启动，并详细说明 Selenium 服务器的地址。检查您的输出是否有类似以下行：

```ts
RemoteWebDriver instances should connect to: http://127.0.0.1:4444/wd/hub

```

### 注意

您需要在您的计算机上安装 Java 才能运行 Selenium 服务器，因为 webdriver-manager 脚本使用 Java 启动 Selenium 服务器。

一旦服务器运行，我们将需要一个 Protractor 的配置文件（名为`protractor.conf.js`），其中包含一些设置。在这个阶段，我们只需要以下内容：

```ts
exports.config = {
    seleniumAddress: 'http://localhost:4444/wd/hub',
    specs: ['*.js']
}
```

这些 protractor 设置只是将`seleniumAddress`设置为之前报告的 Selenium 服务器的地址。我们还有一个`specs`属性，它被设置为在与`protractor.conf.js`相同目录中查找任何`.js`文件，并将它们视为测试规范。

现在是最简单的测试：

```ts
describe("simple protractor test", () => {
    it("should navigate to a page and find a title", () => {
        browser.driver.get('http://localhost:64227/Jasmine/Run');
        expect(browser.driver.getTitle()).toContain("Jasmine");
    });
});
```

我们的测试从在`/Jasmine/Run`打开页面开始。请注意，这是一个使用默认 Jasmine 控制器的 ASP.NET MVC 路径，并返回`Views/Jasmine/SpecRunner.cshtml`。这个控制器和视图是之前安装的 Jasmine NuGet 包中包含的。在尝试执行 Protractor 测试之前，请确保您可以在浏览器中导航到此页面。

使用配置文件运行 Protractor 现在将执行我们之前的测试：

```ts
protractor .\tests\protractor\protractor.conf.js

```

并且将产生期望的结果：

```ts
Using the selenium server at http://localhost:4444/wd/hub.
Finished in 1.606 seconds
1 test, 1 assertion, 0 failures

```

### 注意

这里必须有两件事情在运行，以便这个测试能够工作：

Selenium 服务器必须在命令提示符中运行，以便`localhost:4444/wd/hub`是有效地址，并且不返回 404 错误

开发人员 ASP.NET 网站必须正常运行，以便`localhost:64277/Jasmine/Run`访问我们的 Visual Studio Jasmine 控制器，并呈现 HTML 页面

# 集成测试

假设我们正在进行集成测试，测试页面是使用 ASP.NET MVC 路由渲染的。我们希望使用标准的 MVC 控制器、操作、视图方法来生成 HTML 页面，因为我们可能需要执行一些服务器端逻辑来设置集成测试开始之前的前提条件。

请注意，在现实世界的应用程序中，通常需要运行服务器端逻辑或使用服务器端 HTML 渲染进行集成测试。例如，大多数应用程序在允许通过 JavaScript 调用 REST 服务之前，都需要某种形式的身份验证。向 RESTful API 控制器实现[Authorize]属性是合乎逻辑的解决方案。不幸的是，从普通 HTML 页面调用这些 REST 控制器将返回 401（未经授权）错误。解决这个问题的一种方法是使用 MVC 控制器来提供测试 HTML 页面，然后在服务器端代码中设置虚拟表单身份验证票证。一旦这个设置完成，从此页面对 RESTful 服务的任何调用都将使用虚拟用户配置文件进行身份验证。这种技术也可以用于运行具有不同角色和不同权限的用户的集成测试，这些角色和权限基于他们的身份验证凭据。

## 模拟集成测试

为了模拟这种集成测试页面，让我们重用之前安装的 Jasmine NuGet 包中的`JasmineController`。如前所述，集成测试将需要访问后端服务器端逻辑（在这种情况下是 Jasmine MVC 控制器），然后将服务器端生成的 HTML 页面呈现到浏览器（在这种情况下是`SpecRunner.cshtml`视图）。这种模拟意味着我们依赖服务器端 MVC 框架来解析`/Jasmine/Run` URL，动态生成 HTML 页面，并将生成的 HTML 页面返回给浏览器。

这个`SpecRunner.cshtml`文件（用于生成 HTML 的 MVC 模板）非常简单：

```ts
{
  Layout = null;
}
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
  <title>Jasmine Spec Runner</title>

  <link rel="shortcut icon" type="image/png" href="/Content/jasmine/jasmine_favicon.png">
  <link rel="stylesheet" type="text/css" href="/Content/jasmine/jasmine.css">
  <script type="text/javascript" src="img/jasmine.js"></script>
  <script type="text/javascript" src="img/jasmine-html.js"></script>
  <script type="text/javascript" src="img/boot.js"></script>

  <!—include source files here... -->
  <script type="text/javascript" src="img/SpecHelper.js"></script>
  <script type="text/javascript"
          src="img/PlayerSpec.js"></script>

  <!—include spec files here... -->
  <script type="text/javascript" src="img/Player.js"></script>
  <script type="text/javascript" src="img/Song.js"></script>
</head>

<body>
</body>
</html>
```

这个 ASP.NET MVC 视图页面使用 Razor 语法，不是基于主页面，因为文件顶部的`Layout`参数设置为`null`。页面在`head`元素中包含了一些链接，包括`jasmine.css`、`jasmine.js`、`jasmine-html.js`和`boot.js`。这些是我们之前看到的必需的 Jasmine 文件。之后，我们只包括了`jasmine-samples`目录中的`SpecHelper.js`、`PlayerSpec.js`、`Player.js`和`Song.js`文件。通过导航到`/Jasmine/Run` URL 运行此页面将运行 Jasmine 附带的示例测试。

![模拟集成测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_04.jpg)

默认/Jasmine/Run 网页的输出

在这个示例中，我们模拟的集成测试页面只运行了一些标准的 Jasmine 测试。现在使用服务器端生成的 HTML 页面可以允许我们使用虚拟身份验证，如果需要的话。有了虚拟身份验证，我们可以开始编写 Jasmine 测试来针对安全的 RESTful 数据服务。

在下一章中，我们将看一下构建和测试一些 Backbone 模型和集合，并将通过更多的集成测试示例来实际请求服务器上的数据。不过，目前我们有一个由服务器端生成的示例页面，可以作为进一步集成测试的基础。

### 注意

这样的测试页面不应该被打包在用户验收测试（UAT）或发布配置中。在 ASP.NET 中，我们可以简单地在我们的控制器类周围使用编译指令，比如`#if DEBUG … #endif`，来排除它们从任何其他构建配置中。

## 详细的测试结果

所以现在我们有了一个集成测试页面的开端，它显示了我们的 Jasmine 测试运行的结果。这个 HTML 页面对于快速概览很好，但我们现在希望一些更详细的关于每个测试的信息，以便我们可以报告给我们的构建服务器；每个测试花费的时间，以及它的`success` / `fail`状态。

为了报告这些目的，Jasmine 包括使用自定义测试报告者的能力，超出了 Jasmine 默认的`HtmlReporter`。GitHub 项目 jasmine-reporters（[`github.com/larrymyers/jasmine-reporters`](https://github.com/larrymyers/jasmine-reporters)）有许多预构建的测试报告者，适用于最流行的构建服务器。不幸的是，这个项目没有相应的 NuGet 包，所以我们需要手动在我们的项目中安装`.js`文件。

### 注意

管理 JavaScript 库的另一种方法是使用**Bower**包管理器。Bower 是一个基于 Node 的命令行实用程序，类似于 NuGet，但只处理 JavaScript 库和框架。

现在让我们修改我们的 HTML 页面来包含 TeamCity 报告者。首先，修改`SpecRunner.cshtml`文件，包含`teamcity_reporter.js`文件的`script`标签如下：

```ts
<script type="text/javascript" src="img/teamcity_reporter.js">
</script>
```

接下来，我们需要在`body`标签内创建一个简单的脚本来注册这个报告者到 Jasmine：

```ts
<script type="application/javascript">
    window.tcapi = new jasmineReporters.TeamCityReporter({});
    jasmine.getEnv().addReporter(window.tcapi);
</script>
```

这个脚本只是创建了一个`TeamCityReporter`类的实例，并将其分配给`window`对象上的一个名为`tcapi`的变量。这个脚本的第二行将这个报告者添加到 Jasmine 环境中。现在运行我们的页面将会产生记录在控制台的 TeamCity 结果：

![详细的测试结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_05.jpg)

Jasmine 输出与记录在控制台的 TeamCity 消息

## 记录测试结果

现在我们需要访问这个输出，并找到一种方法将其报告给 Protractor 实例。不幸的是，通过 Selenium 访问控制台的日志只会报告关键错误，因此前面的 TeamCity 报告输出将不可用。快速查看`teamcity_reporter.js`代码，发现所有的`console.log`输出消息都使用`tclog`函数来构建一个字符串，然后调用`console.log`输出这个字符串。由于我们有一个可用的`TeamCityReporter`实例，我们可以很容易地将这些记录的消息存储到一个数组中，然后在测试套件运行结束后读取它们。对 JavaScript 文件`teamcity_reporter.js`进行一些快速修改如下。

在`TeamCityReporter`类的构造函数下方，创建一个数组：

```ts
exportObject.TeamCityReporter = function (args) {

    self.logItems = new Array();
}
```

现在我们可以修改`tclog`函数来返回它构建的字符串：

```ts
Function tclog(message, attrs) {

    log(str); // call to console.log
    return str; // return the string to the calling function
}
```

然后，每次调用`tclog`都可以将返回的字符串推送到这个数组中：

```ts
self.jasmineStarted = function (summary) {

    self.logItems.push(
       tclog("progressStart 'Running Jasmine Tests'"));
};
```

现在`TeamCityReporter`有一个`logItems`数组，我们需要一些方法来找出测试套件何时完成，然后我们可以循环遍历`logItems`数组，并将它们附加到 DOM 上。一旦它在 DOM 中，我们的 Protractor 实例就可以使用 Selenium 来读取这些值并报告给命令行。

让我们构建一个名为`JasmineApiListener`的小类，它接受`TeamCityReporter`类的一个实例来为我们做所有这些工作：

```ts
class JasmineApiListener {
    private _outputComplete: boolean;
    private _tcReporter: jasmine.ITeamCityReporter;

    constructor(tcreporter: jasmine.ITeamCityReporter) {
        this._outputComplete = false;

        this._tcReporter = tcreporter;
        var self = this;

        window.setInterval(() => {

            if (self._tcReporter.finished && !self._outputComplete) {
                var logItems = self._tcReporter.logItems;
                var resultNode = document.getElementById( 'teamCityReporterLog');
                resultNode.setAttribute('class', 'teamCityReporterLog');
                for (var I = 0; I < logItems.length; i++) {
                    var resultItemNode = document.createElement('div');
                    resultItemNode.setAttribute('class', 'logentry');
                    var textNode = document.createTextNode(logItems[i]);
                    resultItemNode.appendChild(textNode);
                    resultNode.appendChild(resultItemNode);

                }
                self._outputComplete = true;

                var doneFlag = document.getElementById( 'teamCityResultsDone');
                var doneText = document.createTextNode("done");
                doneFlag.appendChild(doneText);
            }

        }, 3000);
    }

}
```

我们的`JasmineApiListener`类有两个私有变量。`_outputComplete`变量是一个布尔标志，指示测试套件已完成，并且结果已经写入 DOM。`_tcReporter`变量保存了`TeamCityReporter`类的一个实例，它通过`constructor`传递。`constructor`简单地将标志`_outputComplete`设置为`false`，创建一个名为`self`的变量，并在三秒间隔上设置一个简单的定时器。

### 注意

`self`变量是必要的作用域步骤，以便在传递给`setInterval`的匿名函数内访问`this`的正确实例。

我们匿名函数的主体是所有好东西发生的地方。首先，我们检查`TeamCityReporter`实例上的`_tcReporter.finished`属性，以判断套件是否已完成。如果是，并且我们还没有将结果附加到 DOM `(!self._outputComplete)`，那么我们可以访问`logItems`数组，并为每个条目创建 DOM 元素。这些元素作为`<div class="logentry">…</div>`元素附加到父级`<div id="teamCityReporterLog">`元素。

请注意，前面的代码使用了原生的`document.getElementById`和`appendChild`语法进行 DOM 操作，而不是 jQuery 风格的语法，以避免对 jQuery 的依赖。

现在我们可以在`SpecRunner.cshtml`视图中修改脚本如下：

```ts
<script type="application/javascript">
    window.tcapi = new jasmineReporters.TeamCityReporter({});
    jasmine.getEnv().addReporter(window.tcapi);
    var jasmineApiListener = new JasmineApiListener(window.tcapi);
</script>

<div id="teamCityResultsDone"></div>
<div id="teamCityReporterLog"></div>
```

第一个脚本是我们之前使用的更新版本，现在它创建了我们的`JasmineApiListener`类的一个实例，并在构造函数中传递了`TeamCityReporter`类的实例。我们还添加了两个`<div>`标签。第一个`teamCityResultsDone`是一个标志，表示我们已经完成了将 TeamCity 结果写入 DOM，第二个`teamCityReporterLog`是父`div`，用于容纳所有子`logentry`元素。

如果我们现在打开这个页面，我们应该能看到我们的测试运行，然后三秒后，DOM 将被更新，显示我们从`TeamCityReporter`数组中读取的结果，如下面的截图所示：

![记录测试结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_07.jpg)

Jasmine 输出被记录到 DOM

现在我们有了一种将测试结果记录到 DOM 的方法，我们可以更新基于 Protractor 的 Selenium 测试，将这些结果与构建服务器相关联。

## 查找页面元素

如前所述，Protractor 可以用于运行集成测试，以及自动接受测试。Protractor 测试可以浏览到登录页面，找到登录用户名文本框，向该文本框发送值，例如"`testuser1"`，然后重复该过程以输入密码。然后可以使用相同的测试代码单击**登录**按钮，这将提交表单到我们的服务器登录控制器。然后我们的测试可以确保服务器以正确的重定向响应到我们的主页。这个主页可能包含多个按钮、网格、图片、侧边栏和导航元素。理想情况下，我们希望为每个这些页面元素编写接受测试。

Protractor 使用定位器在 DOM 中查找这些元素。这些元素可以通过它们的 CSS 选择器、`id`来找到，或者如果使用 Angular，则可以通过模型或绑定来找到。构建这些选择器的正确字符串有时可能很困难。

Selenium 为我们提供了一个有用的 Firefox 扩展，用于编写基于 Selenium 的测试 - Selenium IDE ([`docs.seleniumhq.org/projects/ide/`](http://docs.seleniumhq.org/projects/ide/))。安装了这个扩展后，我们可以使用 IDE 来帮助找到页面上的元素。

作为如何使用这个扩展的示例，让我们继续我们正在编写的 Jasmine 报告器的工作，并找到我们一直在使用来标记完成测试套件的`teamCityResultsDone`DOM 元素。我们用来找到这个 DOM 元素的代码和过程与我们在登录页面上找到其他页面元素的代码和过程相同，例如，或者我们通过 Selenium 驱动的任何其他页面。

如果我们在 Firefox 中启动我们的`/Jasmine/Run`页面，现在我们可以点击浏览器右上角的 Selenium IDE 按钮来启动 Selenium IDE。这个 IDE 使用命令来记录对网页的交互，并在主窗口中显示这些命令列表。右键单击命令窗口，然后选择**插入新命令**。在命令名称文本框中给新命令一个名称，比如`find done element`。一旦命令有了名称，目标输入框旁边的两个按钮就变成了启用状态，我们可以点击**选择**。然后我们可以在网页上拖动鼠标，并点击页面顶部的**done**文本。注意命令已经自动填写了 Selenium IDE 中的**目标**元素。**目标**输入框现在变成了一个下拉列表，我们可以使用这个列表来显示我们`teamCityResultsDone`的`div`的 Selenium 选择器语法，如下面的截图所示：

![查找页面元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_08.jpg)

FireFox Selenium IDE

## 在 Jasmine 中使用页面元素

现在我们知道如何使用 Selenium IDE 来找到 HTML 页面元素，我们可以开始编写 Selenium 命令来查询我们 Jasmine 测试的页面元素。记住我们需要找到两个元素。

首先，我们需要找到`teamCityResultsDone`的`div`，并等待该元素的文本被更新。这个`div`只有在我们的 Jasmine 测试套件完成时才会被更新，并且我们的测试结果已经包含在 DOM 中。一旦我们的测试套件被标记为完成，我们就需要循环遍历`teamCityReporterLog`的子元素`logentry`的每一个`div`。这些`logentry`的`div`将包含我们每个测试的详细结果。

我们在 protractor 测试中需要的更改如下：

```ts
describe("team city reporter suite", () => {
    it("should find test results", () => {
        browser.driver.get('http://localhost:64227/Jasmine/Run');

        expect(browser.driver.getTitle()).toContain("Jasmine");

        var element = browser.driver.findElement(
            { id: "teamCityResultsDone" });

        browser.driver.wait(() => {
            return element.getText().then((value) => {
                return value.length > 0;
            });
        }, 60000, "failed to complete in 60 s");
    });

    afterEach(() => {
        browser.driver.findElements(
                by.css("#teamCityReporterLog > div.logentry")
            ).then((elements) => {
            for (var i = 0; i < elements.length; i++) {
                elements[i].getText().then((textValue) => {
                    console.log(textValue);
                });
            }
        });
    });
});
```

我们的测试从浏览到`/Jasmine/Run`页面开始，并期望该页面的标题包含`"Jasmine"`，就像我们之前看到的那样。然后，我们使用来自 Selenium 的`findElement`函数在页面上找到一个元素。这个函数传递了一个 JavaScript 对象，其中`id`设置为`teamCityResultsDone`，并且使用了我们之前在 Selenium IDE 中看到的选择语法。

然后，我们调用`wait`函数等待`teamCityResultsDone`元素的文本被更新（即其`length`为`> 0`），并为这个`wait`函数设置了 60 秒的超时。记住我们的`JasmineApiListener`代码将在我们完成更新 DOM 时将这个`div`的文本值设置为`"done"`，这将有效地触发`wait`函数。

然后，我们使用`afterEach`函数循环遍历`logentry`的`divs`。我们现在不是找到父元素，而是使用`findElements` Selenium 函数在页面上找到多个元素。

注意我们用于这些`div`的 Selenium 选择器语法：`by.css("#teamCityReporterLog > div.logentry")`。这个`by.css`函数使用 CSS 选择器语法来找到我们的元素，输入字符串对应于 Selenium IDE 显示的 CSS 选择器。因此，我们可以使用 Selenium IDE 来帮助我们找到正确的 CSS 选择器语法。

Selenium 对其大多数 API 函数使用流畅的语法。因此，对 `findElements` 的调用后面跟着一个 `.then` 函数，它将在数组中找到的元素传递给匿名函数。我们使用这个匿名函数与 `.then( (elements) => { .. })` 语法。在这个函数中，我们循环遍历元素数组的每个元素，并调用 `.getText` Selenium 函数。同样，这个 `getText` 函数提供了流畅的语法，允许我们编写另一个匿名函数来使用返回的文本值，就像在 `elements[i].getText().then( (textValue ) => { … });` 中看到的那样。这个函数只是将 `textValue` 记录到 protractor 控制台中。

现在运行我们的 Protractor 测试将会将测试结果报告到命令行，如下所示：

![在 Jasmine 中使用页面元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/ms-ts/img/image_9665OS_06_09.jpg)

Protractor 将测试结果记录到控制台

任务完成。我们现在正在使用 Protractor 浏览到一个由服务器生成的 HTML 页面，运行一组 Jasmine 测试。然后我们使用 Selenium 在页面上查找元素，等待 DOM 更新，然后循环遍历元素数组，以便将我们的 Jasmine 测试结果记录到 protractor 控制台中。

这些 Selenium 函数，如 `browser.driver.get`、`findElements` 和 `wait`，都是 Selenium 提供的丰富功能集的一部分，用于处理 DOM 元素。请务必查阅 Selenium 文档以获取更多信息。

我们现在有了一种机制，可以启动集成测试页面，运行 Jasmine 测试套件，将这些测试结果报告给 DOM，然后读取这些结果并将其记录到 Protractor 控制台中。然后在 TeamCity 构建服务器中设置一个构建步骤来执行 protractor，并在构建过程中记录这些测试结果。

# 总结

在本章中，我们从头开始探讨了测试驱动开发。我们讨论了 TDD 的理论，探讨了单元测试、集成测试和验收测试之间的区别，并看了一下 CI 构建服务器流程会是什么样子。然后我们探讨了 Jasmine 作为一个测试框架，学习了如何编写测试，使用期望和匹配器，还探讨了 Jasmine 扩展，以帮助进行数据驱动测试和通过固定装置进行 DOM 操作。最后，我们看了测试运行器，并构建了一个基于 Protractor 的测试框架，通过 Selenium 驱动网页，并将结果报告给构建服务器。在下一章中，我们将探讨 TypeScript 模块语法，以便同时使用 CommonJS 和 AMD JavaScript 模块。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online, LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用都需要版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。
