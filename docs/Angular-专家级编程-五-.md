# Angular 专家级编程（五）

> 原文：[`zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9`](https://zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：实现 Angular 管道

在本章中，您将学习关于 Angular 管道。将 Angular 管道视为过滤器的现代化版本，包括帮助我们在模板中格式化值的函数。Angular 中的管道基本上是 Angular v1 中过滤器的扩展。我们可以在模板中轻松使用许多有用的内置管道。您将学习内置管道，我们还将创建自定义用户定义的管道。

在本章结束时，您将学习并实现以下内容：

+   介绍 Angular 管道

+   定义和实现管道

+   了解各种内置管道

+   DatePipe

+   DecimalPipe

+   CurrencyPipe

+   LowerCasePipe 和 UpperCasePipe

+   JSON 管道

+   SlicePipe

+   async 管道

+   学习实现自定义用户定义的管道

+   为管道参数化

+   链接管道

+   了解纯管道和不纯管道

# Angular 管道-概述

管道允许我们在模板视图中显示值之前格式化值。例如，在大多数现代应用程序中，我们希望显示诸如今天、明天等术语，而不是系统日期格式，例如 2017 年 4 月 13 日 08:00。让我们看看更多现实世界的场景。

您希望应用程序中的提示文本始终为小写吗？没问题；定义并使用`LowercasePipe`。在天气应用程序中，如果您希望显示月份名称为 MAR 或 APR 而不是其全名，请使用`DatePipe`。

很酷，对吧？你明白了。管道帮助您添加业务规则，因此您可以在模板中实际显示数据之前转换数据。

与 Angular 1.x 过滤器建立联系的一个好方法是通过 Angular 管道，但管道不仅仅是过滤。

我们已经使用了 Angular 路由器来定义路由路径，因此我们在一个页面中拥有所有管道的功能；您可以在相同或不同的应用程序中创建它。随意发挥您的创造力。

在 Angular 1.x 中，我们有过滤器--管道是过滤器的替代品。

在下一节中，您将学习如何定义和使用 Angular 管道。

# 定义管道

管道运算符用管道符号（`|`）定义，后跟管道的名称：

```ts
{{ appvalue  | pipename }}

```

以下是一个简单的`lowercase`管道的示例：

```ts
{{"Sridhar Rao"  |  lowercase}} 

```

在上述代码中，我们使用`lowercase`管道将文本转换为小写。

现在，让我们编写一个使用`lowercase`管道示例的示例`Component`：

```ts
@Component({
 selector: 'demo-pipe',
 template: `
 Author name is {{authorName | lowercase}}
 `
})
export class DemoPipeComponent {
 authorName = 'Sridhar Rao';
}

```

让我们详细分析上述代码：

+   我们定义了一个`DemoPipeComponent`组件类

+   我们创建了一个字符串变量`authorName`，并赋予了值`'Sridhar Rao'`

+   在模板视图中，我们显示了`authorName`；然而，在将其打印到 UI 之前，我们使用了`lowercase`管道进行转换

运行上述代码，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/0827f6c1-8664-4c85-bdb5-3571e7885975.png)

干得好！在前面的例子中，我们使用了内置管道。在接下来的部分，您将学习更多关于内置管道，并创建一些自定义管道。

请注意，管道运算符仅在模板中起作用，而不在控制器内部。

# 内置管道

Angular 管道是 Angular 1.x 过滤器的现代化版本。Angular 带有许多预定义的内置管道。我们可以直接在视图中使用它们，并在运行时转换数据。

以下是 Angular 内置支持的所有管道的列表：

+   DatePipe

+   DecimalPipe

+   CurrencyPipe

+   LowercasePipe 和 UppercasePipe

+   JSON 管道

+   SlicePipe

+   异步管道

在接下来的部分，让我们实现并学习更多关于各种管道，并看到它们的实际应用。

# DatePipe

DatePipe，顾名思义，允许我们格式化或转换与日期相关的值。DatePipe 也可以根据运行时传递的参数以不同格式转换值。

一般语法如下代码片段所示：

```ts
{{today | date}} // prints today's date and time
{{ today | date:'MM-dd-yyyy' }} //prints only Month days and year
{{ today | date:'medium' }} 
{{ today | date:'shortTime' }} // prints short format

```

让我们详细分析前面的代码片段：

+   如前一节所述，一般语法是变量后跟着一个（`|`）管道运算符，然后是管道运算符的名称

+   我们使用 DatePipe 来转换`today`变量

+   此外，在前面的例子中，您会注意到我们向管道运算符传递了一些参数；我们将在下一节中介绍向管道传递参数

现在，让我们创建一个完整的`DatePipe`组件示例；以下是实现`DatePipe`组件的代码片段：

```ts
import { Component } from '@angular/core';

@Component({
 template: `
 <h5>Built-In Pipes</h5>
 <ol>
 <li>
 <strong class="packtHeading">DatePipe example 1</strong>
 <p>Today is {{today | date}}
 </li>
 <li>
 <strong class="packtHeading">DatePipe example 2</strong>
 <p>{{ today | date:'MM-dd-yyyy' }} 
 <p>{{ today | date:'medium' }}
 <p>{{ today | date:'shortTime' }} 
 </li>
 </ol>
 `,
})
export class PipeComponent {
 today = new Date();
}

```

让我们详细分析前面的代码片段：

1.  我们创建了一个`PipeComponent`组件类。

1.  我们定义了一个`today`变量。

1.  在视图中，我们根据不同的参数将变量的值转换为各种表达式。

现在运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/82ba1432-01a5-4451-8fb6-b0e633d74748.png)

您在本节中学习了`DatePipe`。在接下来的部分，您将继续学习和实现其他内置管道，并创建一些自定义用户定义的管道。

# DecimalPipe

在本节中，您将了解另一个内置管道--DecimalPipe。

DecimalPipe 允许我们根据区域规则格式化数字。 DecimalPipe 也可以用于以不同格式转换数字。

一般的语法如下：

```ts
appExpression | number [:digitInfo]

```

在上述代码片段中，我们使用了数字管道，可以选择性地传递参数。

让我们看看如何创建一个实现小数点的`DatePipe`，以下是相同的示例代码：

```ts
import { Component } from '@angular/core';
@Component({
 template: `
  <h5>Built-In Pipes</h5>
 <ol>
<li>
<strong class="packtHeading">DecimalPipe example</strong>
 <p>state_tax (.5-5): {{state_tax | number:'.5-5'}}</p>
 <p>state_tax (2.10-10): {{state_tax | number:'2.3-3'}}</p>
 </li>
 </ol>
 `,
})
export class PipeComponent {
 state_tax: number = 5.1445;
}

```

让我们详细分析上述代码片段：

1.  我们定义了一个组件类，即`PipeComponent`。

1.  我们定义了一个`state_tax`变量。

1.  然后我们在视图中转换了`state_tax`。

1.  第一个管道操作符告诉表达式将小数打印到小数点后五位。

1.  第二个管道操作符告诉表达式将值打印到小数点后三位。

上述管道组件示例的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/d6c7f634-b494-427e-aca6-4a2ca689005d.png)

毫无疑问，数字管道是各种应用程序中最有用和常用的管道之一。我们可以转换数字值，特别是处理小数和浮点数。

# CurrencyPipe

对于希望迎合多国地理位置的应用程序，我们需要显示特定国家的代码及其相应的货币值--这就是`CurrencyPipe`派上用场的地方。

`CurrencyPipe`操作符用于在数字值前附加`国家`代码或`货币`符号。

看一下实现`CurrencyPipe`操作符的代码片段：

```ts
{{ value | currency:'USD' }}

Expenses in INR: {{ expenses | currency:'INR' }}

```

让我们详细分析上述代码片段：

1.  第一行代码显示了编写`CurrencyPipe`的一般语法。

1.  第二行显示了货币的语法，我们用它来转换`expenses`的值，并在其后附加了印度货币符号。

现在我们知道如何使用`CurrencyPipe`操作符，让我们组合一个示例来显示多种`货币`和`国家`格式；以下是实现`CurrencyPipe`操作符的完整组件类：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'currency-pipe',
 template: `
 <h5>CurrencyPipe Example</h5>
 <ol>
 <li>
 <p>Salary in USD: {{ salary | currency:'USD':true }}</p>
 <p>Expenses in INR: {{ expenses | currency:'INR':false }}</p>
 </li>
 </ol>
 `
})
export class CurrencyPipeComponent {
 salary: number = 2500;
 expenses: number = 1500;
}

```

让我们详细分析上述代码：

1.  我们创建了一个组件类`CurrencyPipeComponent`，并声明了几个变量，即`salary`和`expenses`。

1.  在组件模板中，我们通过添加`国家`和`货币`详情来转换变量的显示。

1.  在第一个管道操作符中，我们使用了`'currency: USD'`，这将在变量之前附加（$）美元符号。

1.  在第二个管道操作符中，我们使用了`'currency : 'INR':false'`，这将添加货币代码，`false`将告诉它不要打印符号。

现在，启动应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/34796edd-7a0f-4529-85c5-30bf4d0da612.png)

在本节中，我们讨论并实现了`CurrencyPipe`。在接下来的几节中，我们将继续探索和学习其他内置管道以及更多内容。

# LowerCasePipe 和 UpperCasePipe

LowerCasePipe 和 UpperCasePipe，顾名思义，分别用于将文本转换为小写和大写。

看一下以下代码片段：

```ts
Author is Lowercase {{authorName | lowercase }}
Author in Uppercase is {{authorName | uppercase }}

```

让我们详细分析前面的代码：

1.  第一行代码使用`lowercase`管道将`authorName`的值转换为小写。

1.  第二行代码使用`uppercase`管道将`authorName`的值转换为大写。

现在我们已经看到如何定义小写和大写管道，是时候创建一个完整的组件示例了，该示例实现了管道以显示作者姓名的小写和大写形式。

看一下以下代码片段：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'textcase-pipe',
 template: `
 <h5>Built-In LowercasPipe and UppercasePipe</h5>
 <ol>
 <li>
 <strong>LowercasePipe example</strong>
 <p>Author in lowercase is {{authorName | lowercase}}
 </li>
 <li>
 <strong>UpperCasePipe example</strong>
 <p>Author in uppercase is {{authorName | uppercase}}
 </li>
 </ol>
 `
})
export class TextCasePipeComponent {
 authorName = "Sridhar Rao";
}

```

让我们详细分析前面的代码：

1.  我们创建了一个组件类，`TextCasePipeComponent`，并定义了一个`authorName`变量。

1.  在组件视图中，我们使用了`lowercase`和`uppercase`管道。

1.  第一个管道将变量的值转换为小写文本。

1.  第二个管道将变量的值转换为大写文本。

运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/926ebe20-e308-4138-b99c-ab3c6b64b444.png)

在本节中，您学会了如何使用`lowercase`和`uppercase`管道来转换值。

# JSON Pipe

类似于 Angular 1.x 中的 JSON 过滤器，我们有 JSON 管道，它可以帮助我们将字符串转换为 JSON 格式的字符串。

在小写或大写管道中，我们转换了字符串；使用 JSON 管道，我们可以将字符串转换并显示为 JSON 格式的字符串。

通用的语法如下代码片段所示：

```ts
<pre>{{ myObj | json }}</pre>

```

现在，让我们使用前面的语法并创建一个完整的`Component`示例，其中使用了 JSON Pipe：

```ts
import { Component } from '@angular/core';

@Component({ 
 template: `
 <h5>Author Page</h5>
 <pre>{{ authorObj | json }}</pre>
 `
})
export class JSONPipeComponent {
 authorObj: any; 
 constructor() {
 this.authorObj = {
 name: 'Sridhar Rao',
 website: 'http://packtpub.com',
 Books: 'Mastering Angular2'
 };
 }
}

```

让我们详细分析前面的代码：

1.  我们创建了一个组件类，`JSONPipeComponent`和`authorObj`，并将 JSON 字符串赋给了这个变量。

1.  在组件模板视图中，我们转换并显示了 JSON 字符串。

运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/31c7bcc9-8279-4539-b9c3-1c24a6ead706.png)

JSON 很快就成为了 Web 应用程序之间集成服务和客户端技术的事实标准。因此，每当我们需要将值转换为视图中的 JSON 结构时，JSON 管道都非常方便。

# SlicePipe

SlicePipe 与数组切片 JavaScript 函数非常相似。Slice 管道从字符串中提取两个指定索引之间的字符，并返回新的子字符串。

定义 SlicePipe 的一般语法如下：

```ts
{{email_id | slice:0:4 }}

```

在前面的代码片段中，我们正在对电子邮件地址进行切片，以仅显示变量值`email_id`的前四个字符。

既然我们知道如何使用 SlicePipe，让我们在组件中将其放在一起。

以下是实现 SlicePipe 的完整代码片段：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'slice-pipe',
 template: `
 <h5>Built-In Slice Pipe</h5>
 <ol>
 <li>
 <strong>Original string</strong>
 <p> Email Id is {{ emailAddress }}
 </li>
 <li>
 <strong>SlicePipe example</strong>
 <p>Sliced Email Id is {{emailAddress | slice : 0: 4}}
 </li>
 </ol>
 `
})
export class SlicePipeComponent {
 emailAddress = "test@packtpub.com";
}

```

让我们详细分析前面的代码片段：

1.  我们创建了一个`SlicePipeComponent`类。

1.  我们定义了一个字符串变量`emailAddress`并为其赋值`test@packtpub.com`。

1.  然后，我们将 SlicePipe 应用于`{{emailAddress | slice : 0: 4}}`变量。

1.  我们从`0`位置开始获取子字符串，并从变量值`emailAddress`中获取`4`个字符。

运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/aec0e6f4-0964-4f92-bbf7-7202cf800a94.png)

SlicePipe 肯定是一个非常有用的内置管道，特别是处理字符串或子字符串。

# 异步管道

异步管道允许我们直接将 promise 或 observable 映射到我们的模板视图中。为了更好地理解异步管道，让我先介绍一下 observable。

Observables 是 Angular 可注入的服务，可用于将数据流式传输到应用程序中的多个部分。在下面的代码片段中，我们使用`async`管道作为一个 promise 来解析返回的作者列表：

```ts
<ul id="author-list">
 <li *ngFor="let author of authors | async" >
 <!-- loop the object here -->
 </li>
</ul>

```

`async`管道现在订阅`Observable`（作者）并检索最后一个值。

让我们看一下如何使用`async`管道作为`Promise`和`Observable`的示例。

在我们的`app.component.ts`文件中添加以下代码行：

```ts
 getAuthorDetails(): Observable<Author[]> {
  return this.http.get(this.url).map((res: Response) => res.json());
 }

 getAuthorList(): Promise<Author[]> {
  return this.http.get(this.url).toPromise().then((res: Response) => 
   res.json());
 }

```

让我们详细分析前面的代码片段：

1.  我们创建了一个`getAuthorDetails`方法，并附加了一个相同的 observable。该方法将返回来自`url`的响应，这是一个 JSON 输出。

1.  在`getAuthorList`方法中，我们绑定了一个需要在通过`http`请求调用的`url`返回的输出中解析或拒绝的 promise。

在本节中，我们已经看到了`async`管道的工作原理。您会发现它与处理服务非常相似。我们可以映射一个 promise 或一个 observable，并将结果映射到模板上。

# 参数化管道

管道也可以带参数。我们可以在管道后面传递参数。参数在管道后用冒号符号（`:`）分隔：

```ts
{{appValue  |  Pipe1: parameter1: parameter2 }}

```

让我们快速构建一个简单的管道示例，看看它的运行情况。以下是带有`MM-dd-yyyy`参数的`DatePipe`的示例：

```ts
{{today | date:'MM-dd-yyyy' }} 

```

另一个带参数的管道示例如下：

```ts
{{salary | currency:'USD':true}}

```

让我们详细分析前面的代码片段：

1.  我们向`CurrencyPipe`传递了 USD 作为参数，这将告诉管道显示货币代码，例如美元的*USD*和欧元的*EUR*。

1.  `true`参数表示显示货币符号（$）。默认情况下，它设置为 false。

让我们通过组件的完整代码来看它们的运行情况：

```ts
import { Component } from '@angular/core';

@Component({
 template: `
 <h5>Parametrizing pipes</h5>

 <p>Date with parameters {{ today | date:'MM-dd-yyyy' }} 
 <p>Salary in USD: {{salary | currency:'USD':true}}</p>
 `,
})
export class ParamPipeComponent {
 today = new Date();
 salary: number = 1200;
}

```

在前面的代码片段中，我们创建了一个`ParamPipeComponent`类，并定义了`today`和`salary`变量。

在`Component`模板视图中，我们为`DatePipe`传递了`date:'MM-dd-yyyy'`参数，为`CurrencyPipe`传递了`currency:'USD' :true`参数。

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/dfce4e6f-48cb-4eda-8f26-d52111ebb02d.png)

在前面的示例中，我们传递了自定义参数，如`currency`和`date`格式，给管道，并相应地查看了输出。

在大多数应用用例中，我们需要向管道传递参数，以根据业务逻辑转换值。在本节中，我们重点介绍了通过传递值来对管道进行参数化。

到目前为止，我们一直在使用内置管道并向管道传递参数。

在接下来的章节中，您将学习如何链接管道、创建自定义管道，以及向自定义用户定义的管道传递参数。

# 链式管道

我们可以将多个管道链接在一起。这在我们需要关联多个需要应用的管道，并且最终输出将被所有应用的管道转换的情况下特别有帮助。

工作流或链将被触发，并依次应用管道。链管道语法的示例如下：

```ts
{{today | date | uppercase | slice:0:4}}

```

我们在前面的代码中应用了两个链式管道。首先，`DatePipe`应用于`today`变量，然后立即应用`uppercase`管道。以下是`ChainPipeComponent`的整个代码片段：

```ts
import {Component } from '@angular/core';

@Component({
 template: `
 <h5>Chain Pipes</h5>
 <p>Month is {{today | date | uppercase | slice:0:4}}
 `,
})
export class ChainPipeComponent {
 today = new Date();
}

```

我们使用了 slice 来仅显示月份的前四个字符。以下截图显示了前面组件的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/1f371c11-34df-4a31-a921-a8061cdc258b.png)

应用链式管道时需要记住的一些关键事项如下：

+   执行顺序是从左到右

+   管道是依次应用的。

在本节中，您了解了如何在我们的应用程序中将多个管道链接在一起。在下一节中，您将详细了解如何创建自己的自定义管道。

# 创建自定义管道

到目前为止，一切都很好。管道确实给我们留下了深刻的印象，但等等，我们还可以用管道做更棒的事情。内置管道，正如您所见，非常有限且少。我们当然需要创建自己的自定义管道，以满足我们应用程序的功能。

在本节中，您将学习如何为我们的应用程序创建自定义管道。

在这个例子中，我们将构建一个管道，它将是一个税收计算器。我们传递产品的价格，并使用管道功能自动计算并显示销售税。神奇，对吧？

要创建自定义管道，我们需要执行以下步骤：

1.  创建一个模板来应用到管道上（在我们的例子中，它是`updateTaxPipe`）。

1.  创建一个管道文件，即`update-tax.pipe.ts`。

1.  每个管道文件都必须从 Angular 核心中导入管道。

1.  定义管道元数据。

1.  创建`Component`类。它应该有`transform`函数，其中包含管道应该执行的业务逻辑。

在下面的代码片段中，我们正在定义一个名为`UpdateTaxPipe`的自定义管道，它将接受一个`percentage`参数，并进行销售税计算并在我们的模板中显示：

```ts
{{ productPrice | UpdateTaxPipe: percentage }}

```

让我们创建我们的`update-tax.pipe.ts`文件：

```ts
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
 name : "UpdateTaxPipe"
})

export class UpdateTaxPipe implements PipeTransform{
 transform(value:number, taxVal: number):number{
 return (value*taxVal)/100;
 }
}

```

让我们详细分析前面的代码片段：

1.  为了告诉 Angular 这是一个管道，我们应用了`@Pipe`装饰器，它是从核心 Angular 库中导入的。

1.  我们创建了一个自定义管道，名为`UpdateTaxPipe`，使用了`name`管道元数据。

1.  我们创建了一个`transform`方法，这对于管道是必需的，并在方法内定义了我们的业务逻辑和规则。

1.  我们向`transform`方法传递了两个参数，它返回了更新后的值。

无论我们是否包括接口 PipeTransform，Angular 都会寻找并执行`transform`方法。

运行应用程序，我们应该看到如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/9d770113-f482-4303-aa39-e2f6175b42c6.png)

在本节中，您学习了如何创建自定义管道。创建用户定义的管道非常简单和容易。自定义管道确实帮助我们轻松地集成应用程序的业务逻辑。

尝试创建自定义管道，可以适应一次编写，多次使用逻辑，也可以在许多组件视图中使用；例如，验证电话号码、地址等。

# 纯管道和非纯管道

管道还接受一个名为 Pure 的元数据。管道有两种状态：

+   纯管道

+   非纯管道

# 纯管道

纯管道只有在输入参数的值发生变化时才会执行。它不会记住或追踪任何先前的值或状态。Angular 内置管道都是`pure`管道。

到目前为止我们看到的所有管道示例都是纯管道。

# 非纯管道

无论值或参数是否改变，非纯管道都会在每次变更检测周期中调用。为了使用非纯管道，我们应该将管道修饰符`pure`设置为`false`。

默认情况下，所有管道修饰符的`pure`都设置为`true`。

将管道修饰符的值设置为`pure`将检查管道的输出，无论其值是否改变，都会保持更新管道提供的值。

定义非纯管道与创建任何自定义用户定义管道相同，唯一的区别在于在`@Pipe`修饰符中，我们将通过将值设置为`false`来明确指定管道为非纯的。

以下是通过将管道的值设置为 false 来定义非纯管道的语法：

```ts
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'authorName'
  pure: false
})

```

在本节中，您了解了不同类型的 Angular 管道，即纯管道和非纯管道。只有在输入组件的值发生变化时才会调用纯管道。无论值是否改变，非纯管道都会在每次变更检测时调用。

# 摘要

在本章中，您了解了关于 Angular 管道的一切。Angular 管道在转换视图模板中的数据方面非常有用。Angular 管道是 Angular 1.x 中可用的过滤器的现代化版本。

我们可以在模板中轻松使用许多有用的内置管道操作符。在本章中，您了解了内置管道以及创建自定义用户定义管道。

在处理数字时，我们可以使用`DatePipe`、`DecimalPipe`和`CurrencyPipe`。在专门处理字符串时，我们可以始终使用`SlicePipe`、`LowercasePipe`和`UppercasePipe`。

当我们主要处理服务器端响应或进行异步调用并处理响应时，我们可以使用`JSONPipe`和`asyncPipe`。我们还涵盖了向管道传递参数，并根据应用程序的需要进行定制。

我们探讨了如何创建和实现自定义用户定义的管道，这些管道还可以接受参数，以根据我们应用程序的需求更好地定制它们。

所以继续，用管道转换你的视图。

在下一章中，您将学习如何实现 Angular 服务。您将学习有关服务和工厂的知识，创建 Angular 服务，使用服务从组件中访问数据以及创建异步服务。


# 第十一章：实现 Angular 服务

服务在任何 Angular 应用程序中都扮演着重要的角色。我们可以通过充分利用 Angular 中的许多内置服务来设计我们自己的 Angular 服务。在本章中，我们将讨论如何做到这一点，以便您了解如何创建和管理 Angular 服务。

在本章中，我们将涵盖以下主题：

+   为什么要使用服务或工厂？

+   创建服务

+   使用服务从组件中访问数据

+   创建异步服务

# 为什么要使用服务或工厂？

我们已经讨论了单向数据绑定、双向数据绑定以及组件之间的数据共享。我们可能已经定义了非常清晰的视图并实现了整洁的组件，但是业务逻辑和数据获取/存储逻辑必须存在于某个地方。构建出色的 Angular 应用程序来自于充分利用内置服务。Angular 框架包括帮助您进行网络、缓存、日志记录、承诺等方面的服务。

编写我们自己的服务或工厂有助于实现代码的可重用性，并使我们能够在应用程序块（如组件、指令等）之间共享特定于应用程序的逻辑。将特定于应用程序的逻辑组织到服务或工厂中会导致更清晰、更明确定义的组件，并帮助您以更易维护的代码组织项目。

在 AngularJS 中，我们为此目的实现服务或工厂。服务是在运行时使用 new 关键字调用的，比如构造函数。以下代码片段显示了服务实现的 AngularJS 代码：

```ts
function MovieService($http) {   
  this.getMovieList = function   getMovieList() {   
    return $http.get('/api/movies');   
  };   
}   
angular.module('moviedb').service('MovieService',   MovieService);   

```

`MovieService`函数可以注入到任何需要从 API 获取电影列表的控制器中。

在 Angular 中，可以使用工厂来实现相同的功能，并具有额外的功能。工厂是处理创建对象的一种设计模式。我们可以从工厂返回新的类、函数或闭包。与服务类似，工厂也可以注入到控制器中。以下代码片段显示了工厂实现的 AngularJS 代码：

```ts
function MovieService($http) {   
  return {   
    getMovieList: function() {   
         return $http.get('/api/movies');   
    }   
  };   
}   
angular.module('moviedb').factory('MovieService',   MovieService);   

```

服务和工厂都可以注入到控制器中，并且可以调用`getMovieList`函数，如下所示：

```ts
function MovieController(MovieService   service) {   
  service.getMovieList().then(function   (response) {   
      // manage response   
    });   
}   
angular.module('moviedb').controller('MovieController',   
        MovieController);   

```

虽然工厂是灵活的，但服务是使迁移到 ES6 更容易的最佳选择。使用服务时，ES5 中的构造函数可以在迁移到 ES6 的过程中顺利替换为 ES6 类。我们可以将`MovieService`服务重写为 ES6 如下：

```ts
class MovieService {
 getMovieList() {
  return $http.get('/api/movies');
 }
}
app.service('MovieService', MovieService);

```

服务是用户定义的类，用于解决特定目的，并可以注入到组件中。Angular 建议在组件中只包含与视图相关的代码，以丰富 Angular 应用程序中的 UI/UX。组件是服务的消费者，它们作为应用程序数据的来源和业务逻辑的库。保持组件清晰并注入服务使我们能够针对模拟服务测试组件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/d92acc85-6515-4c4a-a88e-afef782f2756.png)

# 创建一个服务

应用程序特定或业务逻辑函数，如持久化应用程序数据、记录错误、文件存储等，应该委托给服务，组件应该消费相应的服务来处理适当的业务或应用程序特定逻辑：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/25fc7ba0-69e9-40cd-bb64-6a8f875e116e.png)

让我们创建一个简单的名为`BookService`的服务，处理获取源中可用的书籍集合。源可以是从 Web API 服务返回的数据或 JSON 文件。

首先，让我们创建一个`Book`模型来持久化领域对象值。下面显示了`Book`类的代码片段：

```ts
export class Book { 
  id: number; 
  title: string; 
  author: string; 
  publisher: string; 
} 

```

前面的代码片段显示了一个`Book`的 TypeScript 类，其中包括`id`、`title`、`author`和`publisher`等属性。现在让我们创建一个名为`BookService`的服务，处理与`Book`相关的操作：

```ts
import { Injectable } from '@angular/core';
import {Book} from './book';
@Injectable()
export class BookService {
  getBooks() {
  var books: Book[] = [
    { "id": 1, "title": "ASP.NET Web API Security Essentials", author:   
         "Rajesh Gunasundaram", publisher: "Packt Publishing" },
    { "id": 2, "title": "Learning Angular for .Net Developers", author: 
         "Rajesh Gunasundaram", publisher: "Packt Publishing" },
    { "id": 3, "title": "Mastering Angular", author: "Rajesh 
         Gunasundaram", publisher: "Packt Publishing" },
   ];
  return books;
  }
}

```

在这里，我们首先导入了`Book`模型类。然后，我们定义了`BookService`类，其中包含一个`getBooks`方法，返回书籍的集合。

现在我们需要一个组件来注入`BookService`并消费。让我们创建一个`BookListComponent`，通过调用`BookService`的`getBooks`方法来检索书籍列表。以下代码片段显示了`BookListComponent`类：

```ts
import { Component, OnInit } from '@angular/core';
import { Book } from './book';
import { BookService } from './book.service';
@Component({
   selector: 'book-list',
   template: `
   <div *ngFor="let book of books">
   {{book.id}} - {{book.title}}<br/>
   Author: {{book.author}}<br/>
   Publication: {{book.publisher}} 
   </div>
    `,
   providers: [BookService]
  })
 export class BookListComponent implements OnInit {
   books: Array<Book>;
   constructor(private bookService: BookService) { }
   ngOnInit() {   
       this.books = this.bookService.getBooks();
      }
   }

```

在这里，我们首先从`@angular/core`中导入`Component`和`OnInit`，然后导入`Book`模型类和`BookService`类。然后我们用`@Component`属性对`BookListComponent`类进行了注释，以及选择器和模板等元数据信息。`BookListComponent`类定义了一个`Book`数组的`books`变量和一个构造函数，它被注入了`BookService`。请注意，`BookListComponent`实现了`OnInit`生命周期钩子，并且它通过使用注入到构造函数中的`BookService`实例来调用`BookService`类的`getBooks`方法。`getBooks`返回的书籍列表被赋给了`BookListComponent`类的`books`变量。

现在让我们创建一个根组件`AppComponent`。将`BookListComponent`作为指令传递，并将`BookService`作为提供者。以下是`AppComponent`的代码片段：

```ts
import { Component } from '@angular/core';   
import { BookService } from './book.service';   

@Component({   
  selector: 'my-books',   
  template: '   
    <h2>Book Library</h2>   
  <book-list></book-list>   
  '   
})   
export class AppComponent { }   

```

在这里，我们首先从`@angular/core`中导入`Component`，`BookListComponent`和`BookService`。然后我们用`@Component`属性对`AppComponent`进行了注释，以及选择器和模板等元数据。请注意，模板中有一个特殊的 HTML 标签`<book-list/>`。在某个地方，我们需要指示 Angular 初始化`BooklistComponent`并相应地渲染视图。我们还需要告诉 Angular，`AppComponent`是根组件，通过引导它来实现这一点。我们可以通过为我们的 Angular 应用程序创建一个`入口点`来实现这一点。

创建一个名为`AppModule`的类，并用`NgModule`进行注释（`app.module.ts`）。这指示 Angular 模块，这个类是应用程序的`入口点`。这里给出了`AppModule`的代码片段：

```ts
import { NgModule }          from '@angular/core';   
import { BrowserModule }  from '@angular/platform-browser';   
import { AppComponent }   from './app.component';   
import { BookListComponent }  from './book-list.component';   

@NgModule({   
  imports:        [ BrowserModule ],   
  declarations: [ AppComponent,   BooklistComponent ],   
  bootstrap:     [ AppComponent ]   
})   
export class AppModule { }   

```

在这里，我们首先从 Angular 核心中导入`NgModule`。然后我们从 Angular 平台浏览器中导入`BrowserModule`，因为我们的应用程序在 Web 浏览器上运行。然后我们导入应用程序组件，比如`AppComponent`，它是一个引导根组件，以及`BooklistComponent`，导入并添加到声明中。请注意，`AppModule`被装饰为`NgModule`，同时具有元数据，如导入、声明和引导。

现在让我们创建一个`index.html`页面，其中包含以下代码片段：

```ts
<!DOCTYPE html>   
<html>   
  <head>   
    <base href="/">   
    <title>Book   Library</title>   
    <meta charset="UTF-8">   
    <meta name="viewport"   content="width=device-width, initial-
          scale=1">   
  </head>   
  <body>   
    <h1>TodoList Angular app for   Packt Publishing...</h1>

```

```ts
    <my-books>Loading...</my-books>   
  </body>   
</html>   

```

在这里，我们没有引用任何必要的库来自`node_modules`，因为它们将由 Webpack 加载。Webpack 是一个用于捆绑资源并从服务器提供给浏览器的工具。Webpack 是 systemJS 的推荐替代方案。

# 使用服务从组件中访问数据

随着 Angular 应用程序的发展，我们不断引入更多的组件，这些组件将处理应用程序的核心数据。因此，我们可能会写重复的代码来访问数据。然而，我们可以通过引入可重用的数据服务来避免编写冗余的代码。需要数据的组件可以注入数据服务，并且可以用来访问数据。通过这种方式，我们可以重用逻辑，编写更少的代码，并在设计组件时有更多的分离。

我们将使用 Angular 的`HttpModule`，它作为一个`npm`包进行发布。为了在我们的应用程序中使用`HttpModule`，我们需要从`@Angular/http`导入`HttpModule`，并且 HTTP 服务应该被注入到控制器或应用程序服务的构造函数中。

# 实施服务

应用程序可以在组件之间共享数据。考虑一个电影数据库应用程序，其中`Movies`列表或单个`Movie`对象将在组件之间共享。我们需要一个服务来在任何组件请求时提供`Movies`列表或单个`Movie`对象。

首先，让我们使用 Angular CLI 创建一个电影服务。在命令提示符中执行以下命令以生成`movie.service`的样板代码：

```ts
e:\Explore\packt\MovieDB>ng generate   service Movie   
installing service   
  create src\app\movie.service.spec.ts   
  create src\app\movie.service.ts   

e:\Explore\packt\MovieDB>   

```

在这里，Angular CLI 创建了两个文件，即`movie.service.ts`和`movie.service.spec.ts`。生成的`movie.service.ts`的样板代码如下所示：

```ts
import { Injectable } from '@angular/core';   

@Injectable()   
export class MovieService {   

  constructor() { }   

}   

```

请注意，`MovieService`类被装饰为`@Injectable`属性，以便依赖注入来实例化并将此服务注入到任何需要它的组件中。我们通过从 Angular 核心导入它，使这个`Injectable`函数可用。

接下来，我们需要向生成的`MovieService`添加`getMovies`函数。将`getMovies()`函数引入到`MovieService`类中如下：

```ts
import { Injectable } from '@angular/core';   

@Injectable()   
export class MovieService {   

  constructor() { }   
  getMovies(): void {}   
}   

```

请注意，我们现在将返回类型设置为 void，但是当我们进行进一步实现时，我们需要进行更改。

我们需要引入一个领域模型，`Movie`，来表示整个应用程序中的电影。让我们使用 Angular CLI 生成`Movie`类的样板代码如下：

```ts
e:\Explore\packt\MovieDB>ng generate   class Movie   
installing class   
  create src\app\movie.spec.ts   
  create src\app\movie.ts   

e:\Explore\packt\MovieDB>   

```

在这里，这个命令创建了两个文件，分别是`movie.ts`和`movie.spec.ts`。实际上，在领域模式下，我们可能不会编写任何测试方法来断言它，所以你可以安全地删除`movie.spec.ts`。生成的`movie.ts`的代码片段如下所示：

```ts
export class Movie {   
}   

```

让我们添加一些属性来使其代表电影的特征。代码如下所示：

```ts
export class Movie {   

   public constructor(   
         private _movie_id:number,   
         private _title: string,   
         private _phase: string,   
         private _category_name: string,   
         private _release_year: number,   
         private _running_time: number,   
         private _rating_name: string,   
         private _disc_format_name:   string,   
         private _number_discs: number,   
         private _viewing_format_name:   string,   
         private _aspect_ratio_name:   string,   
         private _status: string,   
         private _release_date: string,   
         private _budget: number,   
         private _gross: number,   
         private _time_stamp:Date){   
   }   

   public toString = () : string => {   

         return `Movie (movie_id:   ${this._movie_id},   
         title: ${this._title},   
         phase: ${this._phase},   
         category_name:   ${this._category_name},   
         release_year:   ${this._release_year},   
         running_time: ${this._running_time},   
         rating_name:   ${this._rating_name},   
         disc_format_name:   ${this._disc_format_name},   
          number_discs:   ${this._number_discs},   
         viewing_format_name:   ${this._viewing_format_name},   
         aspect_ratio_name: ${this._aspect_ratio_name},   
         status: ${this._status},   
         release_date:   ${this._release_date},   
         budget: ${this._budget},   
         gross: ${this._gross},   
         time_stamp:   ${this._time_stamp})`;   

   }   
}   

```

我们已经准备好领域模型。现在让我们更新`MovieService`中`getMovies()`函数的返回类型如下：

```ts
getMovies(): Movie[] {   
    let movies: Movie[] = [   
          {   
               "movie_id" : 1,   
               "title" : "Iron   Man",   
               "phase" : "Phase   One: Avengers Assembled",   
               "category_name"   : "Action",   
               "release_year" :   2015,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         },   
          {   
               "movie_id" : 2,   
               "title" : "Spiderman",   
               "phase" : "Phase   One",   
               "category_name"   : "Action",   
               "release_year" :   2014,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         }   
        ];   
        return movies;   
  }   

```

`MovieService`的完整代码片段如下所示：

```ts
import { Injectable } from '@angular/core';   
import { Movie} from './movie';   

@Injectable()   
export class MovieService {   
  getMovies(): Movie[] {   
    let movies: Movie[] = [   
          {   
               "movie_id" : 1,   
               "title" : "Iron   Man",   
               "phase" : "Phase   One: Avengers Assembled",   
               "category_name"   : "Action",   
               "release_year" :   2015,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         },   
          {   
               "movie_id" : 2,   
               "title" : "Spiderman",   
               "phase" : "Phase   One",   
               "category_name"   : "Action",   
               "release_year" :   2014,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         }   
        ];   
        return movies;   
  }   
}   

```

在这里，`getMovies()`函数返回类型为`Movie[]`的电影集合。

# 消费服务

我们已经准备好消费`MovieService`。让我们在一个组件中消费它。使用 Angular CLI，我们将通过执行以下命令来创建一个组件：

```ts
e:\Explore\packt\MovieDB>ng generate   component movie   
installing component   
  create src\app\movie\movie.component.css   
  create   src\app\movie\movie.component.html   
  create   src\app\movie\movie.component.spec.ts   
  create src\app\movie\movie.component.ts   

e:\Explore\packt\MovieDB>   

```

这将创建四个文件，分别是`movie.component.ts`、`movie.component.html`、`movie.component.css`和`movie.component.spec.ts`。`movie.component.ts`文件的代码片段如下所示：

```ts
import { Component, OnInit } from '@angular/core';   

@Component({   
  selector: 'app-movie',   
  templateUrl: './movie.component.html',   
  styleUrls: ['./movie.component.css']   
})   
export class MovieComponent implements   OnInit {   

  constructor() { }   

  ngOnInit() {   
  }   

}   

```

`MovieComponent`被`@Component`装饰器修饰，以及元数据，比如选择器、`templateUrl`和`styleUrls`。`MovieService`将被挂钩在`ngOnInit`方法下。让我们继续修改`MovieComponent`来消费`MovieService`。

首先，我们需要将`MovieService`导入到我们的组件`MovieComponent`中。这个导入语句为`MovieComponent`提供了对`MovieService`的引用。但是要消费`MovieService`，我们需要创建`MovieService`的实例。我们该如何做呢？在标准方式中，我们可以实例化`MovieService`如下：

```ts
let movieService = new MovieService();   

```

在`OnInit`生命周期钩子方法中导入`MovieService`并实例化`MovieService`后的`MovieComponent`的代码片段如下所示：

```ts
import { Component, OnInit } from '@angular/core';   
import { MovieService } from './movie.service';   
import { Movie } from './movie';   

@Component({   
  selector: 'app-movie',   
  templateUrl: './movie.component.html',   
  styleUrls: ['./movie.component.css']   
})   
export class MovieComponent implements   OnInit {   
  movies : Movie[];   

  constructor() { }   

  ngOnInit() {   
    let movieService = new   MovieService();   
    this.movies =   movieService.getMovies();   
  }   

}   

```

在这里，当`OnInit`事件被触发时，`MovieService`被实例化，并且通过调用`getMovies()`函数来检索电影集合。电影列表将被分配给`MovieComponent`的`movies`属性，以便在模板中进一步使用。

# 创建一个异步服务

我们刚刚创建了一个名为`MovieService`的服务，它同步调用`getMovies()`方法来检索电影集合。由于我们正在消费外部来源，比如 Web API，来检索电影集合，我们的应用程序必须等待服务器响应电影列表，因为`getMovies`函数是同步的。

因此，我们需要实现一种异步机制来检索电影集合。通过这种方式，我们可以避免使我们的应用程序等待 Web API 响应电影集合。我们可以通过使用 Promise 来实现这一点。

# 什么是 Promise？

**Promise**是一个真诚的保证，表示将执行某个操作。当服务器响应结果时，它会回调一个函数。我们请求一个异步服务，并使用回调函数执行某些操作，服务会用结果或错误调用我们的回调函数。您可以在第七章中了解更多关于 Promise 的内容，*使用可观察对象进行异步编程*。

# 在服务中使用 Promise

让我们更新`MovieService`中的`getMovies`函数，以返回一个已解决的`Promise`，如下所示：

```ts
getMovies(): Promise<Movie[]> {   
    let movies: Movie[] = [   
          {   
               "movie_id" : 1,   
               "title" : "Iron   Man",   
               "phase" : "Phase   One: Avengers Assembled",   
               "category_name"   : "Action",   
               "release_year" :   2015,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         },   
          {   
               "movie_id" : 2,   
               "title" : "Spiderman",   
               "phase" : "Phase   One",   
               "category_name"   : "Action",   
               "release_year" :   2014,   
               "running_time" :   126,   
               "rating_name" : "PG-13",   
               "disc_format_name"   : "Blu-ray",   
               "number_discs" :   1,   
               "viewing_format_name"   : "Widescreen",   
               "aspect_ratio_name"   : " 2.35:1",   
               "status" : 1,   
               "release_date" :   "May 2, 2008",   
               "budget" : "140,000,000",   
               "gross" : "318,298,180",   
               "time_stamp" : "2015-05-03"   
         }   
        ];   
  return Promise.resolve(movies);   
}   

```

请注意，我们从`getMovies`函数中返回电影集合作为已解决的`Promise`。现在我们需要修改将电影集合分配给`MovieComponent`中的 movies 属性的代码。

`MovieComponent`中的现有代码将`Promise`分配给`movies`属性，而不是电影集合，因为`MovieService`中的`getMovies`现在返回已解决的`Promise`。因此，让我们修改`ngOnInit`事件的代码如下：

```ts
ngOnInit() {   
    let movieService = new   MovieService();   
    movieService.getMovies().then(movies   => this.movies = movies);   
}   

```

我们将我们的回调函数提供给`Promise`的`then`方法，所以`getMovies`中的链式函数`then`有命令将从 Web API 返回的电影集合分配给`MovieComponent`的属性`this.movies`。

在这里，应用程序不会等待`MovieService`返回电影集合。`movies`属性从回调函数中获取分配的电影列表。

# 摘要

很酷！这就是本章的结束。我们了解了在应用程序中实现服务的重要性和优势。我们还学习了如何在组件中使用服务。

然而，直接实例化`MovieService`是一个不好的方法。组件不需要知道如何实例化服务；它们的唯一目的是知道如何使用服务。服务还使组件能够与`MovieServices`的类型和它们的实例化方式紧密耦合。这是不可接受的；组件应尽可能松散耦合。

在下一章中，我们将讨论使用依赖注入将服务注入到组件中，这样我们就可以拥有松散耦合的组件。


# 第十二章：应用依赖注入

在本章中，您将学习关于 Angular 依赖注入。依赖注入是 Angular 中最引人注目的特性之一；它允许我们创建可注入对象，可以在各种组件之间作为共享资源使用。

在本章中，我们将讨论以下内容：

+   探索依赖注入

+   详细了解提供者类

+   了解分层依赖注入

+   创建可注入对象

+   学习将提供者注入到服务中

+   学习将提供者注入到组件中

+   学习为提供者类解析依赖项

+   使用`@Inject`、`provide`和`useValue`装饰器创建示例

# 没有依赖注入的应用程序

如果没有依赖注入框架，开发人员的生活将非常艰难。看看不使用依赖注入的以下缺点：

+   每次需要传递构造函数参数时，我们都需要编辑类的构造函数定义

+   我们需要创建构造函数，并单独注入每个所需的依赖类

让我们看一个没有依赖注入的应用程序，以了解其中的挑战和不足之处：

```ts
class products {
 available;
 category;

 constructor() {
  this.available = new warehouse();
  this.category = new category();
 }
}

```

让我们分析前面的代码片段以更好地理解：

1.  我们创建了一个名为`products`的`class`。

1.  在`constructor`方法中，我们实例化了依赖类`warehouse`和`category`。

1.  请注意，如果`warehouse`或`category`类的构造函数定义发生更改，我们将需要手动更新所有类的实例。

由于作为开发人员，我们的任务是手动定义所有依赖项，因此前面的代码并不完全可测试和可维护。这就是 Angular 依赖注入的用武之地。

# 依赖注入 - 介绍

**依赖注入**（**DI**）是一种编码模式，其中一个类接收依赖项而不是自己创建它们。一些开发人员和技术狂人也将其称为设计模式。

它被广泛使用，通常被称为 DI。我们将在所有章节中将依赖注入系统称为 DI。

以下是我们绝对需要 DI 的原因：

+   DI 是一种软件设计模式，其中一个类接收其依赖项而不是创建对象本身

+   DI 创建并提供动态所需的对象

+   我们可以将可注入对象视为应用程序的可重用存储库

+   DI 允许远程开发团队独立开发依赖模块。

没有使用 DI，无法完全编写任何 Angular 应用程序。现在，让我们重新审视一下之前没有使用 DI 编写的代码，并使用 Angular DI 编写它：

```ts
class products {

constructor(private _warehouse: warehouse, private _category: category) {

  // use _warehouse and _category now as reference
 }
} 

```

在前面的代码中发生了什么：

1.  我们创建了一个`products`类。

1.  在`constructor`中，我们将依赖类--`warehouse`和`category`--作为参数传递。

1.  我们现在可以在整个类中使用实例`_warehouse`和`_category`。

1.  请注意，我们没有创建依赖类的对象；相反，我们只是通过 DI 系统接收它们。

1.  我们不必担心`warehouse`或`category`所需的依赖关系；这将由 Angular DI 在内部解决。

现在我们知道了什么是 Angular DI，让我们专注于它是如何在我们的 Angular 应用程序中实现和使用的。在学习提供者类和更多内容之前，我们应该了解一些关于 Angular DI 框架的基本知识。

当然，我们将在接下来的几节中详细介绍这些。了解基本概念是很好的：

1.  `@Injectable`：这个装饰器标记一个类可供注入器实例化。

1.  `@Inject`：使用`@Inject`装饰器，我们可以将配置对象注入到任何需要它的构造函数中。

1.  `Provider`：提供者是我们注册需要注入的依赖项的方式。

现在让我们开始学习提供者类。

# 理解提供者类

要在我们的应用程序中开始使用 DI，我们需要了解提供者的概念。组件装饰器中的提供者配置告诉 Angular 需要提供哪些类给组件。

在提供者配置中，DI 接受一个类的数组，即我们要提供给组件的注入标记。我们还可以使用`useClass`指定要为注册的标记实例化的`class`。

快速查看使用提供者配置的语法：

```ts
@Component({
 templateUrl: './calculate-tax.component.html',
 styleUrls: ['./calculate-tax.component.css'],
 providers: [MyTax]
})

```

在前面的代码中，我们告诉 Angular 前面的组件需要由`MyTax`类提供。

以下是使用提供者类的优点：

+   提供者是每个注入器维护的

+   每个`provider`提供一个 Injectable 的单个实例

+   提供者类提供了调用方法的返回值

我们还可以明确提到应该从服务中使用的类。

这是一般的语法：

```ts
@Component({
 templateUrl: './calculate-tax.component.html',
 styleUrls: ['./calculate-tax.component.css'],
 providers: [
    { provide: MyTax, useClass: MyTax }
  ]
})

```

在前面的代码片段中，我们明确告诉 Angular 注入`MyTax`提供者并使用`useClass`配置使用`MyTax`类。

让我们更多地了解提供者类如何注册和使用；让我们看一下以下的图表：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/83f23e5f-5248-4111-8acf-78d7a2cf2e18.png)

让我们详细分析前面的图表，以了解关键要点：

+   组件共享资源是通过提供者类提供的

+   提供者类可以注册到多个组件中（一个或多个）

+   我们还可以将提供者类注册到其他提供者类中

+   在前面的图表中，`组件＃1`依赖于`提供者类＃1`

+   在前面的图表中，`组件＃2`依赖于`提供者类＃1`和`提供者类＃2`

+   在前面的图表中，`组件＃3`依赖于`提供者类＃2`和`提供者类＃3`

到目前为止，我们了解了 DI 对我们的应用程序有多么关键。DI 确实有助于组织数据，并且是实现独立模块或组件的最合适的设计模式。

这个想法是保持组件独立开发，并在提供者或可注入的地方编写更通用的共享或常用功能。

让我们快速创建一个提供者类的示例，它可以被注入到一个组件中。我们创建一个提供者类--`MyTax.ts`文件--并添加以下代码片段：

```ts
export class MyTax {
 public taxValue: string;
 constructor () {
     }

 getTaxes() {
  this.taxValue=Math.round(Math.random()*100);
  return this.taxValue; 
 }

}

```

让我们详细分析前面的代码片段：

1.  我们创建了一个名为`MyTax`的提供者类。

1.  我们将一个`taxValue`变量定义为数字。

1.  我们创建了一个`getTaxes`方法，它将返回一个随机数。

1.  我们给`taxValue`变量赋值，并通过`getTaxes`方法返回值。

现在，我们需要在我们组件的提供者数组配置中注册这个提供者类，并显示`taxValue`的值。

我们需要创建一个`component`类--`calculate-tax.component.ts`，并添加以下代码行：

```ts
import { Component } from '@angular/core';
import { MyTax } from './my-tax';

@Component({
 template: `<p>tax option: {{ taxName }}</p>`,
 styleUrls: ['./calculate-tax.component.css'],
 providers: [MyTax]
})
export class CalculateTaxComponent{

 public taxName: string;

 constructor( _myTax : MyTax) {
   this.taxName = _myTax.getTaxes();
 }

}

```

让我们详细分析前面的代码：

1.  我们导入了最近创建的提供者类--`MyTax`。

1.  我们创建并定义了`CalculateTax`组件。

1.  我们定义了一个`taxName`变量，并使用数据绑定在模板中映射了这个变量。

1.  在构造函数中，我们在应用程序模块的提供者数组中注册了`MyTax`，Angular DI 将创建提供者类的实例并将其分配给`_myTax`。

1.  使用提供类的实例，我们调用了`getTaxes`方法。

运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/f9a54e14-86e4-487f-ad91-483d138c8b83.png)

在本节中，您学习了如何创建提供程序类并在组件中注册它们以供使用。您可以将相同的提供程序类注册到多个组件中；在我们想要共享多个可重用方法的情况下，这无疑是理想的。

在下一节中，您将学习有关分层 DI 的知识--当我们有多个嵌套组件时。

# 理解分层 DI

在前面的部分中，我们介绍了通过提供程序类进行 DI，还介绍了在各个独立组件之间共享提供程序类。在本节中，您将学习如何在分层组件之间使用带有 DI 的提供程序类。

Angular 在内部创建了一个索引树，跟踪所有组件和正在创建的树结构，并维护其依赖矩阵，该矩阵在实时加载以提供所有必要的模块、服务和组件。

分层组件和各种组件之间的 DI 最好的部分是，我们不必担心这些依赖项是如何创建的，或者它们自身内部需要什么依赖项。

# 概述-分层组件和 DI

Angular 内部维护组件的树结构是一个公开的秘密。它还维护依赖项的树索引。

在任何真实的 Angular 应用程序中，我们将使用许多组件和服务。这些组件将具有从根组件到子组件和内部子组件等的树结构。

这在内部形成了一个组件树结构。由于我们的组件也将具有依赖项和可注入项，Angular 将在内部形成一个依赖项树矩阵，以跟踪和解析服务或组件所需的所有依赖项。

以下是您需要了解有关分层 DI 的关键事项：

+   Angular 框架在内部为组件创建了一个分层树结构的 DI

+   提供程序类需要注册到组件中

+   我们可以将提供程序类注册到其他提供程序类中

在下一节中，您将创建可注入的服务，并在组件中使用它们。

# 创建可注入项

我们不必创建 Angular 注入器，它是默认注入的。Angular 在引导过程中创建了一个应用程序范围的注入器。

我们使用`@Injectable`装饰器定义可注入的类，并在类中定义方法。`@Injectable`使得一个类可以被注入器实例化。

以下是创建`@Injectable`服务的示例代码：

```ts
import { Injectable } from '@angular/core';

@Injectable()
 export class ListService {
  getList() { 
   console.log("Demo Injectable Service");
  }
}

```

让我们详细分析代码片段：

1.  我们从 Angular 核心模块中导入了`Injectable`。

1.  我们使用`@Injectable`装饰器告诉 Angular 以下类可以被注入，并且可以被注入器实例化。

1.  我们创建了一个名为`ListService`的类。

1.  我们实现了一个名为`getList`的方法，目前只是在`console.log`中打印一条消息。

# 注册提供者

注入器使用提供者创建依赖项。提供者需要在消费服务或组件中注册。通过注册它们，提供者类允许我们创建独立的可重用功能，可以由各个团队成员使用。

配置和注册提供者类还可以将功能分解为更小的模块，这样更容易维护和修改。我们可以以不同的方式将提供者类注册到服务和组件中。关于注入器，始终要牢记的重要点如下：

+   我们必须在我们的`NgModule`、组件构造函数或指令中创建一个提供者

+   在组件的构造函数中注册服务

我们在前面的部分创建了一个`ListService`服务，它有一个方法，现在可以被注册并在多个组件中使用：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/c704df8b-daba-4919-a49d-651c9aac5750.png)

让我们详细分析前面的图表，以了解我们正在构建的用例：

1.  我们将创建一个`@Injectable`服务类`ListService`。

1.  我们将创建一个名为`TestDiComponent`的组件。

1.  我们需要将`ListService`注册到`TestDiComponent`中。

那么，现在让我们立即开始学习如何在`ngModule`中注册提供者。看一下`ngModule`文件：

```ts
import { ListService } from "./shared/list.service";

@NgModule({
 providers: [
 {
  provide: ListService,
  useClass: ListService
 }
 ]
})

```

简而言之，上面的代码通常写成如下形式：

```ts
import { ListService } from "./shared/list.service";

@NgModule({
 providers: [
   ListService
 ]
})

```

让我们详细分析前面的代码片段：

1.  我们已经将`ListService`服务类导入到`ngModule`中。

1.  请注意，我们在提供者中注册了`ListService`。Angular 将在运行时内部解析并创建一个注入器。

1.  在简写表示法中，我们只提到提供者的名称，Angular 将`provide`属性映射到`useClass`的值以进行注册和使用。

在前面的部分中，您学会了如何在`ngModule`的提供者配置数组中注册服务。

在 AppModule 中注册提供者与在组件中注册提供者的主要区别在于服务的可见性。在 AppModule 中注册的服务在整个应用程序中都可用，而在特定组件内注册的服务只在该组件内可用。

# 在组件内注册提供者

现在，您将学习如何在组件中注册提供者并在组件内使用可注入的服务类。

首先，让我们使用 Angular CLI 的`ng`命令快速生成一个组件和服务：

```ts
ng g component ./test-di

```

这将生成组件和所需的文件。命令的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/595fdc54-26b2-479d-b3ac-fe37cd602dbc.png)

现在，我们必须在同一文件夹中生成一个 Angular 服务。

```ts
ng g service ./test-di

```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/780cb6e8-5539-4bf4-b567-1c59b36c5e47.png)

我们看到 Angular CLI 生成了一个警告消息，指出服务已生成但未提供。

到目前为止，我们已经分别创建了组件和服务，但现在我们需要在组件中注册提供者，以便我们可以使用该服务。

在继续在组件中注册提供者之前，让我们快速查看一下 CLI 工具生成的服务代码。

这是我们的`test-di.service.ts`文件代码：

```ts
import { Injectable } from '@angular/core';

@Injectable()
 export class TestDiService {
  constructor() { }
}

```

这是由脚手架 Angular CLI 工具生成的默认代码。让我们添加一个我们想在组件内访问的方法：

```ts
import { Injectable } from '@angular/core';

@Injectable()

 export class TestDiService {
  getAuthors() {
  let Authors =[
   {name :"Sridhar"},
   {name: "Robin"},
   {name: "John"},
   {name: "Aditi"}
  ];
  return Authors;
 }
}

```

现在让我们在组件`test-di.component.ts`文件的 providers 数组中注册服务：

```ts
import { Component } from '@angular/core';
import { TestDiService } from './test-di.service';

@Component({
 selector: 'app-test-di',
 templateUrl: './test-di.component.html',
 styleUrls: ['./test-di.component.css'],
 providers: [TestDiService]
})

export class TestDiComponent{
 constructor(private _testDiService: TestDiService) {}
 authors = this._testDiService.getAuthors();
}

```

让我们详细分析上述代码：

1.  我们创建了一个名为`TestDiComponent`的组件。

1.  我们将新创建的服务`TestDiService`导入到组件中。

1.  我们在 providers 中注册了`TestDiService`，告诉 Angular 动态创建服务的实例。

1.  Angular DI 将创建一个我们在`constructor`中传递的`_testDiService`服务类的新`private`实例。

1.  我们使用了`_testDiService`服务的实例，并调用了`getAuthors`方法来获取作者列表。

运行应用程序，我们应该看到如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/63ce8a23-d436-4a54-83ff-dfa814dd9a42.png)

到目前为止，您已经学会了创建一个`Injectable`服务，将服务注册到组件装饰器内的提供者数组中，并使用服务的实例来调用方法，这很棒。

在本节中，您学会了如何使用相同的一组共享提供者类创建多个组件。

# 带有依赖关系的提供者类

在前面的部分中，我们讨论了将服务注册到组件中，但是如果我们的服务本身需要一些依赖怎么办？在本节中，您将学习并实现解决服务所需依赖的方法。

为了更好地理解带有依赖关系的提供者类，让我们了解以下用例。我们有两个服务——`CityService`和`TestDiService`，以及一个组件——`TestDiComponent`。

让我们可视化这些服务和组件的依赖树：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/abd05c78-6923-48b8-814d-4686bbcc398d.png)

让我们详细分析前面的图表，以了解我们正在构建的用例：

1.  我们将创建一个`Injectable`服务——`CityService`。

1.  我们将创建一个`Injectable`服务——`TestDiService`。

1.  我们需要将`CityService`注册到`TestDiService`类中。

1.  我们将创建一个`TestDiComponent`。

1.  我们需要将`TestDiService`注册到`TestDiComponent`中。

在本节中，我们将继续使用之前创建的服务`TestDiService`和组件`TestDiComponent`。

现在，我们将创建一个名为`CityService`的额外服务，并将文件保存为`city.service.ts`。

将以下代码片段添加到服务文件中：

```ts
import { Injectable } from '@angular/core';

@Injectable()
export class CityService {

 getCities() {
  let cities =[
  { name :"New York" },
  { name: "Dallas" },
  { name: "New Jersey" },
  { name: "Austin" }
  ];

 return cities;
 }
}

```

让我们分析前面的代码片段：

1.  我们创建并导出了一个名为`CityService`的新服务。

1.  我们实现了一个`getCities`方法，该方法返回一个城市列表。

创建服务后，我们导入文件并在`app.module.ts`文件中将服务注册为提供者：

```ts
import { CityService } from "./test-di/city.service";

@NgModule({
 providers: [
   CityService
 ]
})

```

由于我们在`app.module.ts`文件的 providers 数组中注册了该服务，它现在可以在整个应用程序中使用。

要在`TestDiService`中使用该服务，我们必须导入该服务并在构造函数中创建`CityService`的实例：

```ts
import { Injectable } from '@angular/core';
import { CityService } from './city.service';

@Injectable()
export class TestDiService {

  constructor(private _city: CityService) { }
    getAuthors() { 
      let Authors =[
         {name :"Sridhar"},
         {name: "Robin"},
         {name: "John"},
         {name: "Aditi"}
      ];
     return Authors;
  }
  getCityList() {
    let cities = this._city.getCities();
    return cities;
 }
}

```

在前面的部分提到的示例中，我们使用服务来显示作者列表。

现在，让我们分析前面的代码：

1.  我们创建了一个名为`CityService`的服务，并在`TestDiService`中导入了该类。

1.  我们在构造方法中创建了`CityService`类的一个实例——`_City`。

1.  我们定义了一个方法，即`getAuthors`。

1.  使用 `this` 运算符，我们在 `getCityList` 方法中调用了 `CityService` 类的 `getCities` 方法。

1.  `getCities` 方法返回城市列表。

运行应用程序，您将看到前面代码的输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/1db00e73-e31d-4f29-9d67-28beda5274d3.png)

在本节中，您学习并实现了如何通过使用 `@Injectable` 装饰器注册其他提供者类来解决提供者类的依赖关系。

# 使用 @Inject、provide 和 useValue

让我们快速回顾一下学习 DI 的进展。我们讨论了如何编写提供者类和层次组件的依赖注入，以及如何使用 `@injectable` 装饰器编写可重用的提供者。

在本节中，您将学习如何使用 `@Inject`、`provide` 和 `useValue` 来在不同组件之间共享数据。

要声明一个服务可以在类中被注入，我们需要一个 `@Injectable` 装饰器。该装饰器告诉 Angular 将使用 `@Injectable` 定义的类可用于注入器，以便实例化到其他类、服务或组件中，并且该类应通过 DI 动态解析。我们主要用它们来编写通用服务并创建我们自己的存储库。

正如我们之前提到的，即使服务需要在其中注入依赖项，我们也使用 `@Injectable` 装饰器。我们还可以将服务注册到另一个服务或任何组件中。

每当我们需要注入构造函数参数的类型时，我们将使用 `@inject` 装饰器。

看一下 `app.module.ts` 文件中 `ngModule` 的以下示例代码：

```ts
import { ListService } from "./shared/list.service";

@NgModule({
 providers: [
  {
   provide: ListService,
   useClass: ListService
  }
 ]
})

```

关于前面的代码，有一些要注意的要点：

1.  我们导入了之前创建的服务，即 `ListService`。

1.  现在我们已经导入了服务，我们需要将其添加到 `providers` 列表中。

1.  我们明确说明需要注册服务名 `ListService`。

1.  使用 `useClass`，我们将指示 Angular 实例化并使用 `ListService` 类。

如果我们仔细注意，我们主要处理的是服务/提供者类。但是，如果我们需要注入某些变量，以便我们可以在不同的组件和服务之间共享值呢？

太棒了！这就是我们可以轻松使用 `@Inject` 装饰器并创建一个变量或类名，我们可以在其他组件和服务中重用。

现在看一下`ngModule`文件；我们已经修改它以适应我们想要在各种服务和组件之间共享的变量：

```ts
import { ListService } from "./shared/list.service";

@NgModule({
 providers: [
 {
   provide : 'username',
   useValue: 'Sridhar@gmail.com'
 }
 ]
})

```

让我们分析前面的代码：

1.  在提供者中，我们创建了一个新的条目，对于`provide`，我们应用了一个名称`username`。请记住，无论您在这里提到的名称是什么，我们都需要在其他服务或组件中始终使用它。

1.  我们为`username`变量提供了一个值。

1.  请注意，这个值不会被更改或更新；把它想象成应用程序中的一个常量值。

现在我们已经创建了一个值常量提供者，让我们看看如何在我们的组件中使用它。

在`app.component.ts`中，添加以下代码片段：

```ts
import { Component, Inject } from  '@angular/core';
 @Component({
 selector:  'app-root',
  templateUrl:  './app.component.html',
  styleUrls: ['./app.component.css']
 })  export  class  AppComponent {  title = 'Learning Angular - Packt Way';
  constructor ( @Inject('username') private  username ) {} } 

```

让我们详细分析前面的代码片段：

1.  我们从`@angular/core`中导入了`component`和`Inject`模块。

1.  我们创建了我们的组件，并为组件的 HTML 和样式表定义了相应的 HTML 和 CSS 文件。

1.  在`AppComponent`类中，我们定义了一个`title`变量并为其赋值。

1.  我们创建了一个类的构造函数，并传递了一个`@inject`装饰器来传递我们在`app.module.ts`文件中定义的`username`名称。

1.  现在我们已经在提供者数组配置中注册了`username`变量，我们可以在组件模板中的任何地方使用该变量的值。

太棒了，现在让我们运行这个应用程序；我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/f3dc9711-d107-4d3f-afe9-5d0faf8c0d35.png)

在以下截图中需要注意的一点是，以绿色标记的变量值`'Sridhar@gmail.com'`在模板中被打印出来。

在本节中，您学会了使用`@Inject`装饰器定义和使用常量提供者。

您学会了如何为我们的服务类使用`@Injectable`；我们可以将其注册为提供者，并在其他服务或组件中使用它。

我们可以定义一些常量变量，也可以注入和在不同组件中使用该值。

现在您应该能够创建多个可重用的服务、提供者类，以及常量变量，这些可以用来创建我们的应用程序存储库。

# 总结

在本章中，我们讨论了现在我们所知道的 Angular DI。DI 允许我们将提供者类和可注入对象注入到组件中使用提供者。我们学习并实现了提供者类和分层依赖注入。我们还学会了在`NgModule`中注册提供者，或者直接在组件内部注册提供者。

我们重点关注如何创建和配置注入器，以及如何在组件装饰器中注册服务提供者。

本章解释了提供者类也可以有依赖项，这些依赖项可以在内部再次注入到服务或组件中。在下一章中，您将学习关于 Angular 动画。Angular 动画是一个核心库，通过将动作和过渡应用到应用程序中，提供更好的用户体验。

我们将学习各种过渡和动作，以及如何设计动画；最重要的是，我们将在学习过程中创建一些很酷的东西。
