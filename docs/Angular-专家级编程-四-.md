# Angular 专家级编程（四）

> 原文：[`zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9`](https://zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：模板和数据绑定语法

在本章中，您将学习 Angular 框架提供的模板语法和数据绑定。模板语法和数据绑定主要关注应用程序的 UI 或视图方面；因此，这是一个非常重要和关键的功能。

在本章中，您将学习有关模板语法和在我们的组件中包含模板的不同方式。您还将学习创建组件，包括子组件，并在视图模板中使用表达式和运算符。您还将专注于如何在模板中附加事件、属性和实现指令。

数据绑定是 Angular 的关键特性之一，它允许我们将数据从源映射到视图目标，反之亦然。您将学习不同的数据绑定方式。

在本章中，您将学习如何在学习过程中创建示例的帮助下，包含视图模板并在模板中定义数据绑定。

您将在本章中学习并实现以下内容：

+   模板语法

+   包含模板语法的各种方式

+   Angular 中的模板表达式

+   数据绑定语法

+   Angular 双向数据绑定

+   模板中的属性绑定

+   在模板中将事件附加到视图

+   模板中的表达式和语句

+   模板中的指令

# 学习模板语法

组件的视图是使用模板定义的，告诉 Angular 如何呈现外观。在模板中，我们定义数据应该如何显示，并使用数据绑定附加事件。

大多数 HTML 标签都可以在 Angular 模板中使用。我们可以使用和定义用户自定义指令。

为组件定义模板的一般语法如下：

```ts
import {Component, View} from "@angular/core";

@Component({
 selector: 'my-app',
 template: `<h2>{{ title }}</h2>`
})

export class MyTemplateComponent {
 title = 'Learning Angular!!!'
}

```

让我们详细分析上述代码片段：

1.  我们定义了一个组件，`MyTemplateComponent`。

1.  我们使用`template`定义了组件视图。

1.  在模板中，我们定义了一个`<h2>`标签。

1.  我们定义了一个`title`变量并赋予了一个值。

1.  使用`{{ }}`插值，我们将变量绑定到模板上。

运行应用程序，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/29e6ad6c-1d38-4d20-8513-c7682319f453.png)

在下一节中，您将详细了解包含模板的各种方式，以及插值的相关内容。

# 包含模板语法的各种方式

在本节中，您将学习有关在组件视图中包含模板的不同方法。在组件语法中包含模板语法有两种方式：

+   我们可以在`component`装饰器内定义视图模板。使用`template`，我们可以在组件装饰器内联包含模板。

+   我们也可以使用`templateURL`包含模板。使用`templateUrl`，我们将模板元素写在一个单独的文件中，并将模板的路径提供给组件。

`templateURL`是一个更受欢迎的方式，因为它允许我们以逻辑方式分离代码，更有效地组织代码。

# 使用内联模板语法

我们讨论了在组件中以不同方式包含模板。让我们学习如何在组件内定义我们的模板。

在组件装饰器内使用模板的语法如下：

```ts
import {Component, View} from "@angular/core";

@Component({
 selector: 'my-app',
 template: `<h2> {{ title }} </h2>`
})

export class MyTemplate {
 title = 'Learning Angular!!!'
}

```

在前面的代码片段中需要注意的最重要的事情如下：

1.  我们在`@component`装饰器内定义模板。

1.  组件`class`定义和模板在同一个文件中定义。

# 使用 templateURL 来包含一个模板

在前面的代码片段中，我们在同一个文件中创建了模板和组件类。然而，当组件类的复杂性在模板元素和类定义中增加时，将很难维护它。

我们需要分离逻辑类和视图，这样更容易维护和理解。现在，让我们看另一种使用`templateURL`为组件定义视图模板的方式。

使用`templateURL`进行查看的语法如下；让我们创建一个名为`app-template.component.ts`的文件：

```ts
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
 selector: 'app-data-binding',
 templateUrl: './data-binding.component.html',
 styleUrls: ['./data-binding.component.css']
})
export class DataBindingComponent {
}

```

如果我们使用上述任何一种方式来使用模板，将不会有视觉上的区别。为 HTML、CSS 和组件类创建单独的文件是有意义的，因为这样可以更好地组织代码，并在代码增加时最终有助于维护代码库。

在下一节中，您将学习 Angular 框架为数据和模板绑定提供的功能。

# 模板中的插值

双大括号`{{ }}`是 Angular 中的插值。它们是一种将大括号之间的文本映射到组件属性的方式。我们已经在整个章节中的各种示例中使用和实现了插值。

在我们将要编写的模板中，值写在双大括号内，如下所示：

```ts
{{ test_value }}

```

让我们快速创建一个简单的例子来理解插值。在`app.component.ts`文件中，让我们定义一个名为`title`的变量：

```ts
import { Component } from '@angular/core';

@Component({
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})

export class AppComponent {
  constructor() { }
  title = "Data Binding";
}

```

现在，我们需要在模板中显示`title`的值。更新`app.component.html`文件，并添加以下代码行：

```ts
<p> {{ title }} </p>

```

现在，尝试更改类中`title`的值；我们将看到模板中自动反映出更新后的值。这就是插值，这是我们在 Angular 中喜爱的一个关键特性。

现在我们知道如何使用插值，接下来我们将处理如何在模板中添加表达式。

# Angular 中的模板表达式

我们可以在模板中使用表达式；表达式执行并产生一个值。

就像在 JavaScript 中一样，我们可以使用表达式语句，但不能使用赋值、new 和链式操作符。

让我们看一些模板表达式的例子：

```ts
<p> {{ tax+10 }} </p> // Using plus operator

<p> {{( tax*50)-10 }} </p>

```

在前面的代码片段中，我们正在使用变量`tax`进行算术运算。

如果您使用过任何编程语言，很可能会发现本节非常简单。就像在任何其他语言中一样，我们可以使用算术运算符。

让我们快速创建一个示例。更新**`app.component.html`**文件，并添加以下代码：

```ts
<h4>Template Expressions</h4>

<p> Expression with (+) Operator: <strong>{{ tax+ 10 }}</strong></p>

<p> Expression with (+ and *) Operator: <strong>{{ (tax*50) +10 }} 
   </strong></p>

```

在前面的代码片段中，我们在模板中使用了表达式。我们对`tax`变量进行了加法和算术运算。

在更新的`app.component.ts`文件中，添加以下代码片段：

```ts
import { Component } from '@angular/core';

@Component({
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})

export class AppComponent {
 constructor() { }

 title = "Data Binding";
 tax = 10;
}

```

我们正在创建一个`AppComponent`类并声明两个变量，`title`和`tax`。我们为`title`和`tax`分配了初始值。

运行应用程序，我们应该看到前面代码片段的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/de8e8af2-e5a2-42cd-870e-c4f4a37cd48c.png)

到目前为止，您已经学习了如何在视图中使用模板、插值以及在模板中使用表达式。现在，让我们学习如何在模板中附加事件并实现指令。

# 在模板中将事件附加到视图

在前面的部分中，我们介绍了如何在组件中定义和包含模板以及在模板中使用插值和表达式。

在本节中，您将学习如何将事件附加到模板中的元素。

事件是基于用户操作触发的常规 JavaScript 方法，例如`onclick`和`onmouseover`。方法是一组定义为执行特定任务的语句。

附加事件的一般语法如下：

```ts
<button (click)= function_name()> Update Tax</button>

```

让我们详细分析前面的代码：

1.  我们在模板中创建了一个`button`。

1.  我们正在将`click`事件附加到按钮上。

1.  通过`click`事件，我们绑定了`function_name()`方法。

现在，让我们用上述代码更新我们的`component`文件，并看看它的运行情况。

我们将首先更新我们的`app.component.html`文件，并添加以下代码片段：

```ts
<p> {{ title }} </p>
<p> {{ tax+ 10 }}</p>
<p> {{ (tax*50) +10 }} </p>
<button (click)= updateTax()> Update Tax </button>

```

关于上述代码片段的一些快速注释：

1.  我们在模板中添加了`button`。

1.  我们在`click`事件的按钮上附加了一个名为`updateTax`的事件。

现在，是时候用以下代码更新我们的`app.component.ts`文件了：

```ts
import { Component } from '@angular/core';

@Component({
 templateUrl: './data-binding.component.html',
 styleUrls: ['./data-binding.component.css']
})

export class DataBindingComponent {
 constructor() { }

 title = "Data Binding and Template Syntax";
 tax = 10;

 updateTax() {
  this.tax = 20;
 }
}

```

让我们分析上述代码片段：

1.  我们正在定义和创建一个组件--`AppComponent`。

1.  我们已经定义了两个变量，`title`和`tax`，并为它们分配了一些值。

1.  我们正在定义和创建一个`updateTax`方法，当调用时将更新`tax`变量。

1.  更新后的`tax`值将显示在模板中。

现在，运行应用程序，我们应该看到如下截图所示的输出；点击“更新税收”按钮，您应该看到模板中的数据得到更新：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/08491992-6727-4b69-ad4e-ab4913c1892f.png)

太棒了！所以，在本节中，您学会了在模板中附加事件，还学会了在组件类中定义方法来更新组件的属性。在下一节中，您将学会在模板中实现指令。

# 在模板中实现指令

我们在学习模板语法方面取得了良好的进展。我们讨论了如何包含模板语法，如何在模板中使用插值，并附加事件。

就像事件一样，我们也可以在模板中实现指令和属性。在本节中，我们将解释如何在模板中实现指令。

看一下以下代码片段：

```ts
<list-products></list-products>

```

上述代码看起来是否类似于在早期版本的 Angular 中定义自定义指令的方式？没错。在 Angular 框架中，自定义指令现在被称为组件。

我们可以根据应用程序的要求创建和定义自定义指令或标签。

目录结构和子组件之间没有关系，但作为一个良好的实践，始终将逻辑上的父子关系组件放在一个目录下；这有助于更好地组织代码。

我们将使用我们在上一节中创建的组件。我们创建了一个组件--`data-binding.component.ts`。现在我们将创建一个新的组件，`list-products`，我们将能够将其绑定到`data-binding`组件。

将以下代码片段添加到`list-products.component.ts`文件中：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'list-products',
 templateUrl: './list-products.component.html',
 styleUrls: ['./list-products.component.css']
})

export class ListProductsComponent {
 constructor() { }
}

```

让我们分析前面的代码：

1.  我们创建了一个新的组件，即`list-products`组件。

1.  在组件定义中，我们将`selector`命名为`list-products`。

1.  `@Component`装饰器为组件提供了 Angular 元数据。使用 CSS `selector`，我们可以在`list-products`标签内显示模板或视图的输出。

1.  我们可以为`selector`指定任何名称，但确保在父组件中也使用相同的名称进行调用。

现在我们已经告诉 Angular 我们需要将`list-products`组件的输出放在自定义标签`list-products`中，我们需要在父组件模板中放置子组件标签。

我们需要使用选择器标签来在模板`data-binding.component.html`文件中识别`list-products`组件：

```ts
<list-products></list-products>

```

我们已经准备好了。现在运行应用程序，我们应该看到前面的代码和子组件的输出以及`data-binding.component.html`模板视图一起显示出来：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/75cb882e-f4ab-4b8d-a0af-24fd6299a8f5.png)

太棒了！所以，你现在学会了如何在模板中包含子组件。任何一个 Angular 应用程序如果没有使用其中任何一个都很少完整。我们将在下一节继续学习和构建更多示例，在那里你将学习如何在模板中使用属性绑定。

# 模板中的绑定

在这一部分，我们将扩展在前一部分创建的示例。我们将介绍如何在模板中使用属性绑定。属性是模板中元素的属性，例如 class、ID 等。

HTML 属性的一般语法如下：

```ts
<button class="myBtn" [disabled]="state=='texas'"  .
  (click)="updateTax()"></button>

```

前面代码片段中需要注意的重点如下：

1.  我们使用`button`标签定义了一个`html`元素。

1.  我们向`button`标签添加了`class`属性。

1.  我们附加了一个`click`事件，调用了一个名为`updateTax`的方法到按钮上。

1.  我们有一个`disabled`属性；如果`state`的值是`texas`，按钮元素将显示在页面上并且将被`disabled`。如果不是，它将显示一个启用的按钮。

使用属性绑定，我们可以动态更改`disabled`的属性值；当组件类中的值更新或更改时，视图也会更新。

让我们更新`app.component.html`文件，并将属性添加到模板中的元素：

```ts
<button (click)= updateTax() [disabled]="state=='texas'"> Update Tax 
  </button>

```

仔细观察，你会发现我们已经添加了`disabled`属性；根据`state`的值，按钮将被启用或禁用。

现在，在`app.component.ts`文件中，让我们定义一个名为`state`的属性变量并为其赋值：

```ts
import { Component } from '@angular/core';

@Component({
 templateUrl: './data-binding.component.html',
 styleUrls: ['./data-binding.component.css']
})
export class DataBindingComponent {

 constructor() { }

 title = "Data Binding and Template Syntax";

 tax = 10;
 state = 'texas';

 updateTax() {
  this.tax = 20;
 }
}

```

在前面的代码中，我们只是定义了一个名为`state`的新变量，并为其赋值。根据`state`的值——分配或更新——按钮将被启用或禁用。

运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/212f0643-0885-4a3a-860d-ddbbdc314755.png)

太棒了！你学会了如何在 Angular 组件中使用模板。

我们讨论了如何编写模板语法，不同的包含模板语法的方式，如何将事件附加到元素，将属性附加到元素，以及如何在模板中实现指令。

在下一节中，您将了解数据绑定——这是 Angular 最重要和最突出的特性之一，也是最常与模板语法一起使用的特性之一。

# Angular 数据绑定

Angular 提供了一种在同一视图和模型之间轻松共享数据的机制。我们可以将一个值关联和赋值给一个类组件，并在视图中使用它。它提供了许多种数据绑定。我们将首先了解各种可用的数据绑定，然后继续创建一些示例。

数据绑定可以分为三个主要类别：

1.  单向数据绑定，即从数据源到视图。

1.  单向数据绑定，即从视图到数据源。

1.  双向数据绑定，即从视图目标到数据源和从数据源到视图。

# 单向数据绑定 - 数据源到视图

在本节中，您将学习从数据源到视图目标的单向数据绑定。在下一节中，您将学习从模板到数据源的单向数据绑定。

在 Angular 中，单向数据绑定指的是从数据源到视图的数据流。换句话说，我们可以说每当值和数据更新时，它们会反映在视图目标中。

单向数据绑定从数据源到视图目标应用于以下 HTML 元素属性：

+   `插值`

+   `属性`

+   `属性`

+   `类`

+   `样式`

现在我们知道了单向数据绑定从数据源到目标应用于哪些属性和元素，让我们学习如何在我们的代码中使用它们。

让我们来看一下从数据源到视图模板的单向数据绑定的一般语法。

```ts
{{ value_to_display }} // Using Interpolation  [attribute] = "expression" // Attribute binding

```

让我们详细分析先前定义的语法：

+   `插值`是在双大括号中写入的值，就像上面的代码中所示的那样。

+   大括号`{{ }}`之间的文本通常是组件属性的名称。Angular 会用相应组件属性的字符串值替换该名称。

+   我们可以通过在方括号`[]`中写入来定义`属性`和`属性`的单向数据绑定。

+   `value_to_display`和`expression`属性是在组件类中定义的。

一些开发人员还喜欢使用规范形式，通过在属性后添加前缀。

```ts
<a bind-href = "value"> Link 1</a>

```

使用`bind`前缀与元素的定义一起，绑定属性或属性。

现在我们知道了写单向数据绑定的语法，是时候为此编写示例了：

```ts
<h4>{{ title }}</h4>

<div [style.color]="colorVal">Updating element Style CSS 
    Attributes</div>
<p>
  <div [className]="'special'" >I am Div with className directive</div>
<p>
  <div [ngClass]="{'specialClass': true, 'specialClass2': true}" >I am 
        Div with ngClass directive</div>
<p>
<img [src]="imageUrl" width="100" height="100">

```

让我们快速分析一下上述代码片段中的一些关键点：

1.  我们正在使用插值--双大括号`{{ }}`中的值--来显示来自数据源到模板的值。属性`title`将在组件模型中设置。

1.  我们通过将值动态绑定到组件类中定义的变量`colorVal`，来定义`style`属性`color`。

1.  我们正在定义`ngClass`属性，并且根据条件，无论是`specialClass`还是`specialClass2`属性中的哪一个被设置为 true，相应的类都将被分配。

1.  我们通过将组件类中的属性`imageUrl`绑定到`src`属性值，动态地提供了图片的`src`属性值。

让我们快速在组件类`one-way.component.ts`文件中定义我们的变量：

```ts
import { Component } from '@angular/core';

@Component({
  selector: 'app-one-way',
  templateUrl: './one-way.component.html',
  styleUrls: ['./one-way.component.css']
})
export class OneWayComponent {
 constructor() { }

 title = 'One way data bindings';

  state = 'california';
  colorVal = 'red';
  specialClass : true;
  imageUrl = '././././assets/images/angular.jpeg';
  tax = 20;
}

```

在上述代码片段中，我们已经定义了我们的`colorVal`、`isStyleVisible`和`imageUrl`变量。

现在，让我们运行上述代码，你应该会看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/4fe82ab8-7a74-4de7-8d01-8c0127cb0912.png)

如果你仔细注意，在所有上述的代码片段中，我们只是单向绑定数据，也就是说，只从数据源到视图目标。

因此，从本质上讲，这是给你的最终用户的只读数据。在下一节中，我们将学习有关从视图模板到数据源的单向数据绑定。

考虑以下的实践练习：尝试创建更多的变量并将它们映射到视图中。

# 单向数据绑定 - 视图模板到数据源

在前面的部分中，我们学习了从数据源到视图模板的单向数据绑定。

在本节中，我们将学习从视图模板到数据源的单向数据绑定。

从视图模板到数据源的单向数据绑定主要用于事件。

创建绑定的一般语法如下：

```ts
(target)="statement"

```

从视图到数据源的绑定主要用于调用方法或捕获事件交互。

下面给出了从视图模板到数据源的单向绑定示例

```ts
<button (click)="updateTax()"></button>

```

我们附加了`click`事件，当按钮被点击时，将调用`updateTax`方法。

我们学习了从数据源到模板以及从视图模板到数据源的单向数据绑定。

在下一节中，您将学习双向数据绑定，显示数据属性以及在对元素的属性进行更改时更新这些属性。

# Angular 双向数据绑定

双向数据绑定必须是 Angular 中最重要的功能之一。双向数据绑定帮助使用`ngModel`指令将输入和输出绑定表达为单个符号。

双向数据绑定是一种机制，可以直接将数据从模型映射到视图，反之亦然。这种机制允许我们在视图和模型之间保持数据同步，即从数据源到视图使用`[]`，从视图到数据源使用`()`。

在 Angular 中，我们使用`ngModel`实现双向数据绑定。

双向数据绑定的一般语法如下：

```ts
<input [(ngModel)]="sample_value" />

```

在上述语法中，请注意以下内容：

+   我们使用`ngModel`写在`[()]`内绑定元素

+   我们为`input`元素关联了双向数据绑定

不要忘记从`@angular/forms`导入`FormsModule`，否则会出错。`ngModel`从领域模型创建一个`FormControl`实例，并将其绑定到表单控件元素。

现在，让我们使用`ngModel`创建一个示例：

```ts
<div> {{sample_value}}</div>

<input [(ngModel)]="sample_value" />

```

我们添加了一个`div`元素，并使用数据绑定，将输入元素的值映射到`ngModel`。使用`ngModel`有助于跟踪控件的值、用户交互和验证状态，并保持视图与模型同步。

现在，当我们开始在类型为文本的`input`元素中输入时，我们看到我们输入的内容被复制到我们的`div`元素中作为`value`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/2f1461c0-df0c-41d9-8a42-bcc8262209d1.png)

太棒了！就数据绑定和模板而言，我们在这一章中取得了相当大的进展。凭借我们在整个章节中获得的所有知识，我们可以创建出优雅而强大的应用程序界面。

# 总结

模板语法和数据绑定是 Angular 应用程序的骨架和灵魂。我们介绍了模板：如何以不同的方式包含它们并在视图模板中使用表达式。然后，我们通过将事件和属性附加到模板来遍历模板。

我们探讨了 Angular 应用程序中数据绑定的方面，并专注于如何为模板内的值实现数据绑定。

在数据绑定中，我们深入探讨了它的广泛类别。我们探索了数据绑定的可用方式：单向数据绑定和双向数据绑定。

利用数据绑定和模板结合在一起，我们几乎可以为我们的 Angular 应用程序创建模拟的功能屏幕：这就是数据绑定和模板语法的力量。

所以，继续发挥你的创造力吧！祝你好运。

在下一章中，您将学习有关 Angular 中的高级表单，学习如何使用和掌握响应式表单。我们通过强调您的 html 模型和您的`NgModel`之间的关系来解决响应式表单的响应部分，因此给定表单上的每个更改都会传播到模型


# 第八章：Angular 中的高级表单

在第七章 *异步编程* *使用 Observables*中，我们使用 Observables 构建了一个简单但易于扩展的 JSON API 来查询漫威电影宇宙。在本章中，我们将构建表单，以更加用户友好的方式查询我们的 API。这些表单将帮助我们不仅从漫威电影宇宙中检索电影，还可以添加电影。除了表单本身，我们显然需要在我们的 API 上进行构建，以支持添加和修改电影。

在本章中，我们将详细介绍以下主题：

+   响应式表单

+   控件和控件组

+   表单指令

+   使用 FormBuilder

+   添加验证

+   自定义验证

# 开始

正如本章介绍中所述，我们将在第七章 *异步编程* *使用 Observables*中构建我们的漫威电影宇宙的 JSON API。更准确地说，我们将改进基于 Promise 的版本。为什么使用 Promise 而不是纯观察者？嗯，Promise 是一个非常强大的工具，在我迄今为止看到的大多数 Angular/Typescript 项目中都在使用。因此，多练习一下 Promise 不会有太大的坏处。

您可以在这里找到 Promises 部分的代码[`bit.ly/mastering-angular2-chap7-part3`](http://bit.ly/mastering-angular2-chap7-part3)。

要将此代码克隆到名为`advanced-forms`的新存储库中，请使用以下命令：

```ts
$ git clone --depth one https://github.com/MathieuNls/mastering-
   angular2 advanced-forms
$ cd advanced-forms
$ git filter-branch --prune-empty --subdirectory-filter chap7/angular-
   promise HEAD
$ npm install

```

这些命令将最新版本的 GitHub 存储库中包含本书代码的文件夹命名为`advanced-forms`。然后，我们进入`advanced-forms`文件夹，并清除不在`chap7/angular-promise`子目录中的所有内容。神奇的是，Git 会重写存储库的历史，只保留在`chap7/angular-promise`子目录中的文件。最后，`npm install`将准备好所有我们的依赖项。

因此，您将在名为 advanced-forms 的新项目中实现我们在《第七章》*使用可观察对象进行异步编程*中实现的行为（例如从漫威电影宇宙查询电影）。现在，如果我们使用表单来创建、读取、更新和删除漫威电影宇宙中的电影，并且这些更改不反映在查询部分，那将不会有太多乐趣。提醒一下，我们在《第七章》*使用可观察对象进行异步编程*中构建的查询 API 是一个静态的 JSON 文件作为后端模拟。为了保存来自我们表单的更改，我们将不得不修改 JSON 文件。虽然这是可能的，但这意味着我们将为我们的模拟构建一个全新的功能（即编辑文件）只是为了这个目的。这个新功能在我们继续使用真正的后端时将毫无帮助。因此，我们将使用漫威电影宇宙中的电影的内存引用。

`app.component.ts`文件如下所示：

```ts
import { Component } from '@angular/core';
import { IMDBAPIService } from './services/imdbapi.service';
import { Movie, MovieFields } from './models/movie'; 

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
}) 
export class AppComponent { 
  title = 'app works!';

  private movies:Movie[] = [];
  private error:boolean = false;
  private finished:boolean = false;

  constructor(private IMDBAPI:IMDBAPIService){

      this.IMDBAPI.fecthOneById(1).then(
        value => {
            this.movies.push(value); 
            console.log("Component", value)
        },
        error => this.error = true
      );

      this.IMDBAPI.fetchByField(MovieFields.release_year, 2015).then(
        value => {
            this.movies = value; 
            console.log("Component", value)
        },
        error => this.error = true
      )

      this.IMDBAPI.byField(MovieFields.release_year, 2015)
        .or(MovieFields.release_year, 2014)
        .or(MovieFields.phase, "Phase Two")
        .fetch()
        .then(
          value => {
              this.movies = value; 
              console.log("Component", value)
          },
          error => this.error = true
        );
     }
} 

```

相关的 HTML 模板如下：

```ts
<h1>
  {{title}}
</h1>

<ul>
    <li *ngFor="let movie of movies">{{movie}}</li> 
</ul> 

```

`IMDBAPIService`与《第七章》*使用可观察对象进行异步编程*中的内容相同，执行`ng start`将得到以下结果：

在《第七章》*使用可观察对象进行异步编程*结束时的状态。

# 响应式表单

在《第八章》*模板和数据绑定语法*中，我们学习了如何在 Angular 中利用数据绑定和模板化。在这里，我们将把这些新概念与表单结合起来。任何有两个小时 HTML 经验的人都知道`<form>`的含义以及如何使用它们。在您掌握了几个小时的 HTML 之后，您就知道如何识别表单中的不同信息，并选择一种方法（即`GET`、`POST`、`PUT`和`DELETE`）将所有内容发送到您选择的后端。

然而，在这个示例中，我们将使用命令式的 TypeScript 代码构建表单，而不是传统的 HTML。你可能会问，为什么？嗯，这样可以让我们在不依赖生成 DOM 的端到端测试的情况下测试我们的表单。使用响应式表单，我们可以像在﻿第十六章中描述的那样，使用经典的单元测试来测试我们的表单。

让我们从为表单构建基础的 HTML 结构开始，旨在向漫威电影宇宙添加一部新电影，如下所示：

```ts
<form [formGroup]="movieForm">
        <label>movie_id</label>
        <input type="text" formControlName="movie_id"><br/>
        <label>title</label>
        <input type="text" formControlName="title"><br/>
        <label>phase</label>
        <input type="text" formControlName="phase"><br/>
        <label>category_name</label>
        <input type="text" formControlName="category_name"><br/>
        <label>release_year</label>
        <input type="text" formControlName="release_year"><br/>
        <label>running_time</label>
        <input type="text" formControlName="running_time"><br/>
        <label>rating_name</label>
        <input type="text" formControlName="rating_name"><br/>
        <label>disc_format_name</label>
        <input type="text" formControlName="disc_format_name"><br/>
        <label>number_discs</label>
        <input type="text" formControlName="number_discs"><br/>
        <label>viewing_format_name</label>
        <input type="text" formControlName="viewing_format_name"><br/>
        <label>aspect_ratio_name</label>
        <input type="text" formControlName="aspect_ratio_name"><br/>
        <label>status</label>
        <input type="text" formControlName="status"><br/>
        <label>release_date</label>
        <input type="text" formControlName="release_date"><br/>
        <label>budget</label>
        <input type="text" formControlName="budget"><br/>
        <label>gross</label>
        <input type="text" formControlName="gross"><br/>
        <label>time_stamp</label>
        <input type="text" formControlName="time_stamp"><br/>
</form> 

```

在上述表单中，我们为`Movie`模型的每个属性都有一个标签-输入对。现在，这个表单中有一些明显不是纯 HTML 的指令。即`[formGroup]="movieForm"`和`formControlName=""`。第一个指令(`[formGroup]="movieForm"`)用于将这个特定表单与`FormGroup`的实例绑定。然后，`formControlName`指的是`FormControl`类的实例，它包括`FormGroup`。换句话说，`movieForm`是由`FormControl`、`FormGroup`和`FormControl`组成的，`@angular/forms`包中都有。因此，我们需要在`app.component.ts`文件中导入这个包：`import { FormGroup, FormControl }` from `@angular/forms`；在更新了`app.component.html`文件后。此外，我们需要导入`ReactiveFormsModule`并将其添加到我们的应用程序模块中。

如果你现在就启动你的应用程序，它会毫无问题地转译。然而，在运行时，它会抱怨，因为`movieForm`表单组在你的组件中还不存在。让我们创建它：

```ts
 private movieForm:FormGroup =  new FormGroup({
    movie_id: new FormControl(),
    title: new FormControl(),
    phase: new FormControl(),
    category_name: new FormControl(),
    release_year: new FormControl(),
    running_time: new FormControl(),
    rating_name: new FormControl(),
    disc_format_name: new FormControl(),
    number_discs: new FormControl(),
    viewing_format_name: new FormControl(),
    aspect_ratio_name: new FormControl(),
    status: new FormControl(),
    release_date: new FormControl(),
    budget: new FormControl(),
    gross: new FormControl(),
    time_stamp: new FormControl()
}); 

```

正如你所看到的，`AppComponent`组件有一个`FormGroup`的私有成员实例。这个`FormGroup`实例由许多`FormControl`实例组成，每个字段都是精确的一个。

此外，每个字段的值可以通过`this.movieForm.value.my_field`来访问。因此，如果我们在表单中添加一个提交按钮：

```ts
<button (click)="submit()" type="submit">SUBMIT</button> 

```

然后，在`AppComponent`组件中对应的`submit()`函数，然后我们可以显示每个字段的值。

```ts
  private submit(){
    console.log(
      "Form Values",
      this.movieForm.value.movie_id,
      this.movieForm.value.title,
      this.movieForm.value.phase,
      this.movieForm.value.category_name,
      this.movieForm.value.release_year,
      this.movieForm.value.running_time,
      this.movieForm.value.rating_name,
      this.movieForm.value.disc_format_name,
      this.movieForm.value.number_discs,
      this.movieForm.value.viewing_format_name,
      this.movieForm.value.aspect_ratio_name,
      this.movieForm.value.status,
      this.movieForm.value.release_date,
      this.movieForm.value.budget,
      this.movieForm.value.gross,
      this.movieForm.value.time_stamp
    );
  } 

```

就是这么简单；我们在 HTML 模板和组件之间建立了通信：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/2a659178-4ae0-4628-95de-27588d0c3131.png)显示相当粗糙的 HTML 表单和提交函数的控制台输出。

然后，我们可以创建`Movie`模型的实例并将其发送到`IMDBAPI`进行持久化。唯一缺少的是一个可用的后端。

```ts
private submit(){
    console.log(
      "Form Values",
      this.movieForm.value.movie_id,
      this.movieForm.value.title,
      this.movieForm.value.phase,
      this.movieForm.value.category_name,
      this.movieForm.value.release_year,
      this.movieForm.value.running_time,
      this.movieForm.value.rating_name,
      this.movieForm.value.disc_format_name,
      this.movieForm.value.number_discs,
      this.movieForm.value.viewing_format_name,
      this.movieForm.value.aspect_ratio_name,
      this.movieForm.value.status,
      this.movieForm.value.release_date,
      this.movieForm.value.budget,
      this.movieForm.value.gross,
      this.movieForm.value.time_stamp
    );

    let movie:Movie = new Movie(
      this.movieForm.value.movie_id,
      this.movieForm.value.title,
      this.movieForm.value.phase,
      this.movieForm.value.category_name,
      this.movieForm.value.release_year,
      this.movieForm.value.running_time,
      this.movieForm.value.rating_name,
      this.movieForm.value.disc_format_name,
      this.movieForm.value.number_discs,
      this.movieForm.value.viewing_format_name,
      this.movieForm.value.aspect_ratio_name,
      this.movieForm.value.status,
      this.movieForm.value.release_date,
      this.movieForm.value.budget,
      this.movieForm.value.gross,
      this.movieForm.value.time_stamp
     );

    console.log(movie);

    //Persist movie

  } 

```

在下面的截图中，我们可以看到显示的 HTML 表单和改进的`submit`函数的控制台输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/6f8ce37d-dc19-4504-86f1-9e8e20c20e40.png)

现在很好；我们已经从 HTML 表单中检索到了值，并在应用程序的组件端创建了一个可以移动和持久化的`Movie`对象。这个表单中至少有两个不同的改进之处：

+   表单创建的冗长（`new FormControl()`太多了？）

+   对不同输入的验证

# 使用 FormBuilder

`FormBuilder`是 Angular 的`@angular/forms`包中的可注入辅助类。这个类有助于减少表单创建的冗长，如下面的代码所示：

```ts
this.movieForm = this.formBuilder.group({
   movie_id: '',
   title: '',
   phase: '',
   category_name: '',
   release_year: '',
   running_time: '',
   rating_name: '',
   disc_format_name: '',
   number_discs: '',
   viewing_format_name: '',
   aspect_ratio_name: '',
   status: '',
   release_date: '',
   budget: '',
   gross: '',
   time_stamp: ''
}); 

```

正如你所看到的，使用`FormBuilder`类的`group`方法，`FormGroup`和`FormControl`的声明现在是隐式的。我们只需要有字段名称，后面跟着它的默认值。在这里，所有的默认值都是空白的。

要使用`FormBuilder`类，我们首先必须导入它：

```ts
Import { FormGroup, FormControl, FormBuilder } from '@angular/forms'; 

```

然后我们在`AppComponent`组件的构造函数中注入它：

```ts
 constructor(private IMDBAPI:IMDBAPIService, private formBuilder: FormBuilder) 

```

请注意，我们仍然从第七章注入了`IMDBAPIService`，*使用可观察对象进行异步编程*。

因此，`AppComponent`现在看起来像下面这样：

```ts

import { Component } from '@angular/core';
import { IMDBAPIService } from './services/imdbapi.service';
import { Movie, MovieFields } from './models/movie';

import { FormGroup, FormControl, FormBuilder } from '@angular/forms';

@Component({ 
  selector: 'app-root', 
  templateUrl: './app.component.html', 
  styleUrls: ['./app.component.css'] 
})
export class AppComponent {
  title = 'app works!';

  private movies:Movie[] = [];
  private error:boolean = false;
  private finished:boolean = false;
  private movieForm:FormGroup;

  constructor(private IMDBAPI:IMDBAPIService, private formBuilder: 
     FormBuilder){

      this.movieForm =  this.formBuilder.group({
        movie_id: '',
        title: '',
        phase: '',
        category_name: '',
        release_year: '',
        running_time: '',
        rating_name: '',
        disc_format_name: '',
        number_discs: '',
        viewing_format_name: '',
        aspect_ratio_name: '',
        status: '',
        release_date: '',
        budget: '',
        gross: '',
        time_stamp: ''
      });

      // IMDB queries have been removed for simplicity
    }

    private submit(){
        // submit body has been removed for simplicity
    }    

```

我们解决了我们两个问题中的第一个：表单创建的冗长。在下一节中，我们将解决本章的验证部分，学习如何验证传入的输入。

# 添加验证

处理表单对开发人员来说通常是一种痛苦，因为显然你不能信任用户提供的输入。这要么是因为他们只是没有注意到你在表单中期望的内容，要么是因为他们想要破坏事情。验证来自表单的输入在每种语言中都是痛苦的，无论是服务器端还是客户端。

现在，Angular 团队提出了一种相当简单的方法，通过在表单创建时定义对每个字段的期望来验证输入，使用`Validators`。Angular 包含以下内置的`Validators`，我们可以使用：

+   `required`: 要求非空值

+   `minLength(minLength: number)`: 要求控件值的最小长度为`minLength`

+   `maxLength(maxLength: number)`: 要求控件值的最大长度为`maxLength`

+   `pattern(pattern: string)`: 要求控件值与提供的模式匹配

向我们的表单添加这些内置的`validators`很简单：

```ts

//In AppComponent

import { FormGroup, FormControl, FormBuilder, Validators } from '@angular/forms';

//[...]

constructor(private IMDBAPI:IMDBAPIService, private formBuilder: FormBuilder){

      this.movieForm =  this.formBuilder.group({
        movie_id: ['', Validators.required],
        title: ['', Validators.required],
        phase: ['', Validators.required],
        category_name: ['', Validators.required],
        release_year: ['', Validators.required],
        running_time: ['', Validators.required],
        rating_name: ['', Validators.required],
        disc_format_name: ['', Validators.required],
        number_discs: ['', Validators.required],
        viewing_format_name: ['', Validators.required],
        aspect_ratio_name: ['', Validators.required],
        status: ['', Validators.required],
        release_date: ['', Validators.required],
        budget: ['', Validators.required],
        gross: ['', Validators.required],
        time_stamp: ['', Validators.required]
      });
}

//[...] 

```

除了每个字段的空白默认值之外，我们还添加了必需的`validator`，这是`@angular/forms`包中包含的`Validators`类的静态属性。我们可以使用`FormGroup`的 valid 属性来读取表单的有效性（即，如果所有验证器都通过了）：

```ts
 private submit(){
    console.log(
      "Form Values",
      this.movieForm.value.movie_id,
      this.movieForm.value.title,
      this.movieForm.value.phase,
      this.movieForm.value.category_name,
      this.movieForm.value.release_year,
      this.movieForm.value.running_time,
      this.movieForm.value.rating_name,
      this.movieForm.value.disc_format_name,
      this.movieForm.value.number_discs,
      this.movieForm.value.viewing_format_name,
      this.movieForm.value.aspect_ratio_name,
      this.movieForm.value.status,
      this.movieForm.value.release_date,
      this.movieForm.value.budget,
      this.movieForm.value.gross,
      this.movieForm.value.time_stamp
    );

    if(this.movieForm.valid){
      let movie:Movie = new Movie(
        this.movieForm.value.movie_id,
        this.movieForm.value.title,
        this.movieForm.value.phase,
        this.movieForm.value.category_name,
        this.movieForm.value.release_year,
        this.movieForm.value.running_time,
        this.movieForm.value.rating_name,
        this.movieForm.value.disc_format_name,
        this.movieForm.value.number_discs,
        this.movieForm.value.viewing_format_name,
        this.movieForm.value.aspect_ratio_name,
        this.movieForm.value.status,
        this.movieForm.value.release_date,
        this.movieForm.value.budget,
        this.movieForm.value.gross,
        this.movieForm.value.time_stamp
       );

      console.log(movie);
      //Persist movie
    }else{
      console.error("Form not valid");
    }
} 

```

在`submit`方法的上一个修改中，如果用户没有填写其中一个字段，则`Movie`对象将不会被创建。此外，我们将显示`console.error("表单无效")`；如果我们添加一个条件`<p></p>`块，并附带一些基本的 CSS，我们可以为用户提供一些反馈。

```ts
<p class='error' *ngIf=!movieForm.valid>Error</p> 
/*app.component.css*/
.error{
    color:red;
} 

```

在以下屏幕截图中，我们可以看到显示的 HTML 表单，并对表单的有效性进行了反馈。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/4a308388-9826-4170-b858-2a40d3f7193b.png)

我们可以再进一步，为每个字段提供可视化反馈。通过每个子`FormControl`的`valid`属性可以访问每个字段的状态。

```ts
<form [formGroup]="movieForm">

        <p class='error' *ngIf=!movieForm.valid>Error</p>
        <label>movie_id</label>
        <p class='error' *ngIf=!movieForm.controls.movie_id.valid>This 
               field is required</p>
        <input type="text" formControlName="movie_id"><br/>
        <label>title</label>
        <p class='error' *ngIf=!movieForm.controls.title.valid>This 
               field is required</p>
        <input type="text" formControlName="title"><br/>
        <label>phase</label>
        <p class='error' *ngIf=!movieForm.controls.phase.valid>This 
               field is required</p>
        <input type="text" formControlName="phase"><br/>
        <label>category_name</label>
        <p class='error' 
              *ngIf=!movieForm.controls.category_name.valid>This field 
               is required</p>
        <input type="text" formControlName="category_name"><br/>
        <label>release_year</label>
        <p class='error' 
              *ngIf=!movieForm.controls.release_year.valid>This field 
               is required</p>
        <input type="text" formControlName="release_year"><br/>
        <label>running_time</label>
        <p class='error' 
              *ngIf=!movieForm.controls.running_time.valid>This field  
               is required</p>
        <input type="text" formControlName="running_time"><br/>
        <label>rating_name</label>
        <p class='error' 
               *ngIf=!movieForm.controls.rating_name.valid>This field 
                is required</p>
        <input type="text" formControlName="rating_name"><br/>
        <label>disc_format_name</label>
        <p class='error' 
              *ngIf=!movieForm.controls.disc_format_name.valid>This 
               field is required</p>
        <input type="text" formControlName="disc_format_name"><br/>
        <label>number_discs</label>
        <p class='error' 
              *ngIf=!movieForm.controls.number_discs.valid>This field 
              is required</p>
        <input type="text" formControlName="number_discs"><br/>
        <label>viewing_format_name</label>
        <p class='error' 
            *ngIf=!movieForm.controls.viewing_format_name.valid>This 
             field is required</p>
        <input type="text" formControlName="viewing_format_name"><br/>
        <label>aspect_ratio_name</label>
        <p class='error' 
            *ngIf=!movieForm.controls.aspect_ratio_name.valid>This         
             field is required</p>
        <input type="text" formControlName="aspect_ratio_name"><br/>
        <label>status</label>
        <p class='error' *ngIf=!movieForm.controls.status.valid>This 
              field is required</p>
        <input type="text" formControlName="status"><br/>
        <label>release_date</label>
        <p class='error' 
             *ngIf=!movieForm.controls.release_date.valid>This field is 
              required</p>
        <input type="text" formControlName="release_date"><br/>
        <label>budget</label>
        <p class='error' *ngIf=!movieForm.controls.budget.valid>This 
            field is required</p>
        <input type="text" formControlName="budget"><br/>
        <label>gross</label>
        <p class='error' *ngIf=!movieForm.controls.gross.valid>This 
             field is required</p>
        <input type="text" formControlName="gross"><br/>
        <label>time_stamp</label>
        <p class='error' 
           *ngIf=!movieForm.controls.time_stamp.valid>This field is 
            required</p>
        <input type="text" formControlName="time_stamp"><br/>

        <button (click)="submit()" type="submit">SUBMIT</button>
</form> 

```

这产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/760e8212-8c78-4687-984c-d85a00b521f7.png)显示带有每个字段有效性反馈的 HTML 表单。

正如您所看到的，除了`movid_id`之外的每个表单都显示了“此字段为必填项”错误，因为它们为空。`*ngIf`结构指令监听与关联变量的任何更改，并在字段变得无效/有效时显示/隐藏段落。表单的另一个有用属性是 pristine。它定义了给定字段是否已被用户修改。在我们的情况下，即使没有进行编辑，它也可以用来避免显示错误。

关于`validators`的另一个方便的事情是，它们可以使用`Validators`类的 compose 方法进行组合。在以下示例中，我们将从四个不同的验证器：`Validators.required`、`Validators.minLength`、`Validators.maxLength`和`Validators.pattern`，组合一个`movie_id`字段的验证器。

```ts
this.movieForm =  this.formBuilder.group({
    movie_id: ['',  
       Validators.compose(
       [
          Validators.required,
          Validators.minLength(1), 
          Validators.maxLength(4), 
          Validators.pattern('[0-9]+')
       ]
      )
    ],
    title: ['', Validators.required],
    phase: ['', Validators.required],
    category_name: ['', Validators.required],
    release_year: ['', Validators.required],
    running_time: ['', Validators.required],
    rating_name: ['', Validators.required],
    disc_format_name: ['', Validators.required],
    number_discs: ['', Validators.required],
    viewing_format_name: ['', Validators.required],
    aspect_ratio_name: ['', Validators.required],
    status: ['', Validators.required],
    release_date: ['', Validators.required],
    budget: ['', Validators.required],
    gross: ['', Validators.required],
    time_stamp: ['', Validators.required]
}); 

```

因此，生成的复合验证器将确保`movie_id`是一个介于`1`和`4`位数字之间的数字。以下屏幕截图显示了带有 movide_id 字段反馈的 HTML 表单。该字段有效，因为它由四个数字组成：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/9ee66d91-894e-4aea-a083-32cecaded17d.png)

# 自定义验证

在前一节中，我们看到了如何使用验证器并将验证器组合在一起以创建更复杂的验证。`Validators.required`、`Validators.minLength`、`Validators.maxLength`和`Validators.pattern`的组合可以涵盖在开发 Angular 应用程序过程中可能出现的许多验证情况。如果有时候您无法使用内置验证器处理验证需求，那么您可以构建自己的验证器。

在本节中，我们将看到如何验证`movie_id`字段包含有效的条目（即一个介于一到四位数之间的数字），并且另一个电影尚未使用该 ID。为此，我们可以创建以下类：

```ts

import { FormControl } from '@angular/forms';

interface ValidationResult {
 [key:string]:boolean;
}

export class MovieIDValidator{
    static idNotTaken(control: FormControl): ValidationResult { 

        let movies = require('./marvel-cinematic-
                universe.json').movies;
        let found:boolean = false;

        for (var i = 0; i < movies.length; ++i) {

            if(control.value == movies[i].movie_id){
                 return { "idNotTaken": true };
            }
        }

       return null;
    }
} 

```

在这里，我们可以看到验证结果实际上是一个简单的`[key:string]:boolean`结构。如果布尔值为 true，则意味着验证器失败（即字段无效）。接下来是`MovieIDValidator`类本身，我们有一个静态方法返回`ValidationResult`，并接受`FormControl`作为参数。在这个方法中，我们从包含漫威电影宇宙的 JSON 文件中提取所有电影。然后，我们遍历所有电影，并检查`movie_id`字段的当前值是否与现有 ID 匹配。如果是，我们返回`{ "idNotTaken": true }`，这意味着`idNotTaken`验证器存在问题。将这个新的自定义验证器与其他四个（即`Validators.required`、`Validators.minLength`、`Validators.maxLength`和`Validators.pattern`）结合起来非常容易：

```ts
import { MovieIDValidator } from './movie-id.validator'

// [...]

this.movieForm =  this.formBuilder.group({
        movie_id: ['',  
          Validators.compose(
            [
             Validators.required,
             Validators.minLength(1), 
             Validators.maxLength(4), 
             Validators.pattern('[0-9]+'),
             MovieIDValidator.idNotTaken
            ]
          )
        ],
        title: ['', Validators.required],
        phase: ['', Validators.required],
        category_name: ['', Validators.required],
        release_year: ['', Validators.required],
        running_time: ['', Validators.required],
        rating_name: ['', Validators.required],
        disc_format_name: ['', Validators.required],
        number_discs: ['', Validators.required],
        viewing_format_name: ['', Validators.required],
        aspect_ratio_name: ['', Validators.required],
        status: ['', Validators.required],
        release_date: ['', Validators.required],
        budget: ['', Validators.required],
        gross: ['', Validators.required],
        time_stamp: ['', Validators.required]
      }); 

```

我们还可以添加一个异步表单验证器，它返回一个 Promise（例如`Promise<ValidationResult>`而不是`ValidationResult`）。当您必须使用远程 API 进行验证时，这非常方便。

```ts
import { FormControl } from '@angular/forms';

interface ValidationResult {
 [key:string]:boolean;
}

export class MovieIDValidator{
    static idNotTaken(control: FormControl): ValidationResult { 

        let movies = require('./marvel-cinematic-
           universe.json').movies;
        let found:boolean = false;

        for (var i = 0; i < movies.length; ++i) {

            if(control.value == movies[i].movie_id){
                 return { "idNotTaken": true };
            }
        }

       return null;
    }

    static idTakenAsync(control: FormControl): 
     Promise<ValidationResult> { 

        let p = new Promise((resolve, reject) => {
         setTimeout(() => {

            let movies = require('./marvel-cinematic-
                universe.json').movies;
            let found:boolean = false;

            for (var i = 0; i < movies.length; ++i) {

                if(control.value == movies[i].movie_id){
                     resolve({ "idNotTaken": true });
                }
            }

            resolve(null);

         }, 1000)
       });

       return p;

    }
} 

```

在这里，我们构建了一个模拟远程 API 调用的 Promise，超时为 1 秒。Promise 的作用与`idNotTaken`相同，我们检查电影的 ID 是否已经被使用。创建 Promise 后，我们将其返回，以便在相关组件中使用。

# 使用 ngModel 进行双向数据绑定

在通过表单创建或更新 Angular 应用程序的模型时，使用`ngModel`进行双向数据绑定非常方便。在前一个应用程序中，我们有以下`submit()`方法：

```ts
private submit(){
  console.log(
    "Form Values",
    this.movieForm.value.movie_id,
    this.movieForm.value.title,
    this.movieForm.value.phase,
    this.movieForm.value.category_name,
    this.movieForm.value.release_year,
    this.movieForm.value.running_time,
    this.movieForm.value.rating_name,
    this.movieForm.value.disc_format_name,
    this.movieForm.value.number_discs,
    this.movieForm.value.viewing_format_name,
    this.movieForm.value.aspect_ratio_name,
    this.movieForm.value.status,
    this.movieForm.value.release_date,
    this.movieForm.value.budget,
    this.movieForm.value.gross,
    this.movieForm.value.time_stamp
  );

  if(this.movieForm.valid){
    let movie:Movie = new Movie(
      this.movieForm.value.movie_id,
      this.movieForm.value.title,
      this.movieForm.value.phase,
      this.movieForm.value.category_name,
      this.movieForm.value.release_year,
      this.movieForm.value.running_time,
      this.movieForm.value.rating_name,
      this.movieForm.value.disc_format_name,
      this.movieForm.value.number_discs,
      this.movieForm.value.viewing_format_name,
      this.movieForm.value.aspect_ratio_name,
      this.movieForm.value.status,
      this.movieForm.value.release_date,
      this.movieForm.value.budget,
      this.movieForm.value.gross,
      this.movieForm.value.time_stamp
    );

    console.log(movie);
   }
  else{
      console.error("Form not valid");
    }
  } 

```

对于经验丰富的人来说，这看起来很笨拙。事实上，我们知道我们会要求用户输入一个新电影。因此，所有字段都将被显示，并且它们的值将用于创建上述电影。使用双向数据绑定，您可以指定每个 HTML 输入与模型属性之间的绑定。在我们的情况下，这是`Movie`对象的一个属性。

```ts
<form [formGroup]="movieForm">

        <p class='error' *ngIf=!movieForm.valid>Error</p>
        <label>movie_id</label>
        <p class='error' *ngIf=!movieForm.controls.movie_id.valid>This 
              field is required</p>
        <input type="text" formControlName="movie_id" 
             [(ngModel)]="movie.movie_id" name="movie_id" ><br/>
        <label>title</label>
        <p class='error' *ngIf=!movieForm.controls.title.valid>This 
             field is required</p>
        <input type="text" formControlName="title" 
            [(ngModel)]="movie.title" name="movie_title"><br/>
        <label>phase</label>
        <p class='error' *ngIf=!movieForm.controls.phase.valid>This 
            field is required</p>
        <input type="text" formControlName="phase" 
            [(ngModel)]="movie.phase" name="movie_phase"><br/>
        <label>category_name</label>
        <p class='error' *ngIf=!movieForm.controls.
            category_name.valid>This field is required</p>
        <input type="text" formControlName="category_name" 
             [(ngModel)]="movie.category_name"  name="movie_cat"><br/>
        <label>release_year</label>
        <p class='error' *ngIf=!movieForm.controls.release_year
              .valid>This field is required</p>
        <input type="text" formControlName="release_year"  
            [(ngModel)]="movie.release_year" name="movie_year"><br/>
        <label>running_time</label>
        <p class='error'*ngIf=!movieForm.controls.
             running_time.valid>This field is required</p>
        <input type="text" formControlName="running_time" 
              [(ngModel)]="movie.running_time" name="movie_time"><br/>
        <label>rating_name</label>
        <p class='error' *ngIf=!movieForm.controls.rating_name.
        valid>This field is required</p>
        <input type="text" formControlName="rating_name" 
             [(ngModel)]="movie.rating_name" name="movie_rating"><br/>
        <label>disc_format_name</label>
        <p class='error' *ngIf=!movieForm.controls.
            disc_format_name.valid>This field is required</p>
        <input type="text" formControlName="disc_format_name" 
           [(ngModel)]="movie.disc_format_name" name="movie_disc"><br/>
        <label>number_discs</label>
        <p class='error' *ngIf=!movieForm.controls.number_discs.valid>
              This field is required</p>
        <input type="text" formControlName="number_discs" 
           [(ngModel)]="movie.number_discs" name="movie_discs_nb"><br/>
        <label>viewing_format_name</label>
        <p class='error' *ngIf=!movieForm.controls.viewing_format_name.
             valid>This field is required</p>
        <input type="text" formControlName="viewing_format_name" 
             [(ngModel)]="movie.viewing_format_name"
             name="movie_format"><br/>
        <label>aspect_ratio_name</label>
        <p class='error' *ngIf=!movieForm.controls.aspect_ratio_name.
                valid>This field is required</p>
        <input type="text" formControlName="aspect_ratio_name"  
           [(ngModel)]="movie.aspect_ratio_name" 
             name="movie_ratio"><br/>
        <label>status</label>
        <p class='error' *ngIf=!movieForm.
           controls.status.valid>This field is required</p>
        <input type="text" formControlName="status" 
            [(ngModel)]="movie.status" name="movie_status"><br/>
        <label>release_date</label>
        <p class='error' *ngIf=!movieForm.controls.release_date.
              valid>This field is required</p>
        <input type="text" formControlName="release_date" 
            [(ngModel)]="movie.release_date" name="movie_release"><br/>
        <label>budget</label>
        <p class='error' *ngIf=!movieForm.controls.budget.valid>This 
               field is required</p>
        <input type="text" formControlName="budget" 
            [(ngModel)]="movie.budget" name="movie_budget"><br/>
        <label>gross</label>
        <p class='error' *ngIf=!movieForm.controls.gross.valid>This 
              field is required</p>
        <input type="text" formControlName="gross" 
              [(ngModel)]="movie.gross" name="movie_gross"><br/>
        <label>time_stamp</label>
        <p class='error' *ngIf=!movieForm.controls.time_stamp.
               valid>This field is required</p>
        <input type="text" formControlName="time_stamp" 
          [(ngModel)]="movie.time_stamp" name="movie_timestamp"><br/>

        <button (click)="submit()" type="submit">SUBMIT</button>
</form> 

```

看一下`[(ngModel)]`指令。在这里，我们使用`[]`单向绑定，使用`()`另一种方式。一种方式是表单的模型，另一种方式是从表单到模型。这意味着对表单所做的任何修改都会影响模型，对模型所做的任何修改都会反映在表单上。

现在，我们的提交方法可以简化为以下内容：

```ts
private submit(){ if(this.movieForm.valid){ 
  console.log(this.movie);

  //persist
}else{
  console.error("Form not valid");
} 
} 

```

要牢记的一点是，即使验证器无效，表单的值也会传递到模型。例如，如果您在`movie_id`字段中输入`ABC`，则`validators`将无效，但`console.log(this.movie.movie_id)`将显示`ABC`。

# 保持整洁（额外学分）

我一直发现表单是干净、整洁、有组织的 HTML 模板的大敌。即使是小型表单，也经过良好的缩进和注释分隔，但在我看来，它们看起来也很凌乱。为了以 Angular 的方式解决这个问题，我们可以创建指令来保持表单输入的有序。以下是我在为`Toolwatch.io`创建表单时使用的示例：

```ts
<toolwatch-input 
      [id]             = "'email'"
      [control]        = "loginForm.controls.email" 
      [errorLabel]     = "'email-required'"
      [submitAttempt]  = "submitAttempt"
      [autoCapitalize] = false
      [autoCorrect]    = false
      [spellCheck]     = false
> 

```

正如您所看到的，该指令接受一个不同的`@Input`参数，控制输入的外观和行为。

以下是相关的组件：

```ts
import { Component, Input, EventEmitter, Output  } from '@angular/core';
import {   
  FormControl
} from '@angular/forms';

@Component({
    templateUrl: './toowatch-input.html',
    pipes: [TranslatePipe],
    selector: 'toolwatch-input',
})
export class ToolwatchInput {

    @Input()
     id             : string;
    @Input()
     control        : FormControl;
    @Input()
     model          : any = null;
    @Input()
     type           : string = "text";
    @Input()
     label          : string;
    @Input()
     errorLabel     : string;
    @Input()
     formControlName: string;
    @Input()
     submitAttempt  : boolean = true;
    @Input()
     autoCapitalize : boolean = true;
    @Input()
     autoCorrect    : boolean = true;
    @Input()
     autoComplete   : boolean = true;
    @Input()
     spellCheck     : boolean = true;

    @Output()
     update         = new EventEmitter();

    constructor() {

    }

    ngAfterViewInit() {

        if(this.control == null || this.id == null){
            throw "[Control] and [id] must be set";
        }

        //initialize other variables to the value of id 
        //if they are null
        let variablesToInitialize = [
            "label", 
            "errorLabel", 
            "formControlName"
        ];

        for (var i = variablesToInitialize.length - 1; i >= 0; i--) {
            if(this[variablesToInitialize[i]] == null){
                this[variablesToInitialize[i]] = this.id;
            }
        }
    }

} 

```

该组件接受以下属性作为输入：

+   `id`：输入的`id`

+   `control`：控制此输入的`FormControl`

+   `model`：绑定的模型字段

+   `type`：输入类型

+   `label`：要显示的标签

+   `errorLabel`：要显示的错误标签

+   `formControlName`：表单控件的名称

+   `submitAttempt`：如果表单已经提交过一次

+   `autoCapitalize`：`autoCapitalize`的 HTML 属性开/关

+   `autoCorrect`：`autoCorrect`的 HTML 属性开/关

+   `autoComplete`：`autoComplete`的 HTML 属性开/关

+   `spellCheck`：`spellCheck`的 HTML 属性开/关

它还使用`id`的值初始化了`label`、`errorLabel`和`formControlName`的值，如果它们没有提供。最后，该组件还有一个名为`update`的`@Output`属性，在`value`更改时会触发事件，因此您可以注册它。

在 HTML 端，我们有类似以下的内容：

```ts
<div  class="group"
  [ngClass]="{ 'has-error' : !control.valid && submitAttempt }"

    >
    <em *ngIf="!control.valid && submitAttempt">
      {{ errorLabel | translate:{value: param} }}
    </em>

    <input #input_field
      [attr.autocapitalize] = "autoCapitalize ? 'on' : 'off'"
      [attr.autocorrect]    = "autoCorrect ? 'on' : 'off'"
      [attr.autocomplete]   = "autoComplete ? 'on' : 'off'"
      [attr.spellcheck]     = "spellCheck ? 'on' : 'off'"
      class                 = "form-control" 
      id                    = "{{id}}" 
      type                  = "{{type}}" 
      [formControl]         = "control" 
      (keyup) = "update.emit(input_field.value)"
    >
    <span class="highlight"></span>
    <span class="bar"></span>
    <label htmlFor="{{id}}">
      {{ label | translate:{value: param} }}
    </label>
</div> 

```

主要优势在于 HTML 和 CSS 类管理被封装起来，我不必每次想要输入时都复制粘贴它们。

# 总结

在本章中，我们学习了如何利用响应式表单的优势。响应式表单可以手动创建，也可以使用`FormBuilder`进行程序化创建。此外，我们强调了响应式表单的响应式部分，强调了 HTML 模型和`ngModel`之间的关系，因此给定表单上的每个更改都会传播到模型上。我们还看到了如何自定义验证并将我们新获得的关于表单的知识嵌入到清晰、可重用的指令中。

在下一章中，我们将学习如何将 Material Design 与 Angular 集成，以创建出色且响应灵敏的应用程序。


# 第九章：Angular 中的 Material Design

Material Design 是新的、备受炒作的设计风格。它取代了扁平设计成为新的必须使用的设计。Material Design 是由 Google 在 2014 年推出的，它扩展了 Google Now 的卡片图案。以下是 Google Now 卡片的图片：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/8366c1fe-b2ad-4802-b96b-fe7d122ecedd.png)

Google Now 卡片。

Material Design 背后的整个理念是建立在基于网格的系统、动画和过渡的响应性基础上，同时增加设计的深度。Material Design 的首席设计师 Matias Duarte 这样说：

“与真实的纸张不同，我们的数字材料可以智能地扩展和重塑。材料具有物理表面和边缘。接缝和阴影提供了关于您可以触摸的内容的含义。”

Material Design 是一套非常精确和完整的规范，可以在这里找到：[`material.google.com/`](https://material.google.com/)。

任何对 CSS3 和 HTML5 有扎实知识的人都可以阅读文档并实现每个组件。然而，这将需要大量的时间和精力。幸运的是，我们不必等那么久。事实上，一组才华横溢的开发人员组成并为 Angular 创建了一个 Material Design 组件。在撰写本文时，这仍处于测试阶段，这意味着一些组件尚未实现或未完全实现。然而，我很少发现自己因为某个组件不存在或不起作用而被困住，以至于不得不改变整个设计。

在本章中，我们将学习如何安装 Material Design 的 Angular 组件，然后使用一些最受欢迎的组件。我们还将看一下材料图标。更详细地说，我们将看到：

+   如何为 Angular 安装 Material Design

+   响应式布局的处理方式

+   材料图标

+   按钮

+   菜单

+   工具栏

+   对话框

+   创建自己的主题

# 安装包

首先，我们需要安装 Angular Material Design 包。使用 Angular CLI 相对简单：

```ts
ng new chap10
cd chap10
npm install --save @angular/material 
npm install --save @angular/animations
npm install --save hammerjs 

```

我们在这里安装了两个包，`@angular/material`和`hammerjs`包。第一个包包括了我们的应用程序中将在下一节中使用的 Material Design 模块。然而，第二个包是触摸移动的 JavaScript 实现。一些 Material Design 组件，如`slider`，依赖于`hammerjs`。

然后，根据`NgModule`规范，我们可以导入`MaterialModule`如下：

```ts
//src/app/app.module.ts

import { MaterialModule } from '@angular/material';
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';

import { AppComponent } from './app.component';

@NgModule({
 declarations: [
   AppComponent
 ],
 imports: [
   BrowserModule,
   FormsModule,
   HttpModule,
   ReactiveFormsModule,
   NgbModule.forRoot(),
   MaterialModule.forRoot()
 ],
 providers: [],
 bootstrap: [AppComponent]
})
export class AppModule { } 

```

接下来，我们需要选择一个主题。主题是将应用于 Angular Material 组件的一组颜色。在一个主题中，您有以下颜色：

+   主要调色板包括在所有屏幕和组件上最广泛使用的颜色

+   强调调色板包括用于浮动操作按钮和交互元素的颜色。

+   警告调色板包括用于传达错误状态的颜色

+   前景调色板包括文本和图标的颜色

+   背景调色板包括用于元素背景的颜色

幸运的是，有默认主题（谷歌在大多数服务中使用的主题），我们可以直接使用。为此，请将以下行添加到您的`/src/styles.css`文件中：

```ts
@import '~@angular/material/core/theming/prebuilt/deeppurple-
     amber.css'; 

```

在这里，我们使用深紫色主题，这是可用的默认主题之一。您可以在这里看到所有默认主题：`node_modules/@angular/material/core/theming/prebuilt`。

此外，就是这样！您可以运行`ng serve`来重新编译您的项目，并确认一切都按计划进行。不出所料，目前没有太多要展示的。这是在运行`ng serve`后拍摄的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e0032b20-55d5-457c-bd3f-4a0612abfedd.png)应用程序运行正常！

# 响应式布局

Material Designs 的一个重要部分是响应式布局，可以适应任何可能的屏幕尺寸。为了实现这一点，我们使用断点宽度：480、600、840、960、1280、1440 和 1600 dp，如以下表格所定义：[`material.io/guidelines/layout/responsive-ui.html#responsive-ui-breakpoints`](https://material.io/guidelines/layout/responsive-ui.html#responsive-ui-breakpoints)：

| **断点（dp）** | **手机/平板竖屏** | **手机/平板横屏** | **窗口** | **列** | **间距** |
| --- | --- | --- | --- | --- | --- |
| 0 | 小手机 |  | 超小 | 4 | 16 |
| 360 | 中等手机 |  | 超小 | 4 | 16 |
| 400 | 大手机 |  | 超小 | 4 | 16 |
| 480 | 大手机 | 小手机 | 超小 | 4 | 16 |
| 600 | 小平板 | 中等手机 | 小 | 8 | 16/24 |
| 720 | 大平板 | 大手机 | 小 | 8 | 16/24 |
| 840 | 大平板 | 大手机 | 小 | 12 | 16/24 |
| 960 |  | 小平板 | 小 | 12 | 24 |
| 1024 |  | 大平板 | 中等 | 12 | 24 |
| 1280 |  | 大平板 | 中等 | 12 | 24 |
| 1440 |  |  | 大 | 12 | 24 |
| 1600 |  |  | 大 | 12 | 24 |
| 1920 |  |  | 超大 | 12 | 24 |

请注意，本章中我们将使用的所有 Material Design 指令已经实现了这些断点。然而，如果您开始主题化（请参阅本章的最后一节）或实现自定义指令，您必须牢记它们。CSS 断点相当容易定义，但可能是繁琐的工作：

```ts
@media (min-width: 600dp) {
 .class {
   content: 'Whoa.';
 }
} 

```

现在，前表的前四列相当不言自明，我们有 dp 中的断点，手持设备/平板电脑纵向，手持设备/平板电脑横向和窗口。然而，最后两个需要一些解释。列栏指示每个 dp 大小均等分屏幕的列数。

间距是每个列之间的空间。这是一个 12 列网格布局：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/8a292a51-269f-4761-84c1-48f4dc3cfd65.png)列（粉色）和间距（蓝色）。

要使用网格系统，您可以将`md-columns`附加到任何给定标签的类中。例如，`<button class="md-2">`创建一个宽度为两列的按钮。

要查看您的网站在不同尺寸下的效果，您可以使用 Google Chrome 开发者工具（*F12*然后*CTRL* + *Shift* + *M*）或[`material.io/resizer/`](http://material.io/resizer/)。请注意，如果您尝试分析的网站将*X-Frame-Options*设置为*DENY*，[`material.io`](http://material.io)将会静默失败。

# 材料图标

让我们从材料图标开始我们的 Material Design 之旅。材料图标是图标字体，已经创建为在任何分辨率和设备（Web、Android 和 iOS 都得到了官方支持）上工作。

图标传达特殊含义，开发人员倾向于使用相同的图标来传达相同的事物。因此，用户更容易在您的应用程序中找到他们的方式。

有数百个图标可供您使用，每天都会添加新的图标。

以下是一些示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e702fae1-b848-4c73-ba0f-0d20d291d80c.png)折叠图标。

您可以在[`material.io/icons/`](https://material.io/icons/)上看到所有图标。

由于材料图标是 Material Design 的可选部分（也就是说，您可以使用 Material Design 设计应用程序，例如，使用字体 awesome 图标甚至自定义图标），因此还有另一行代码需要添加到您的代码中。在您的`src/index.html`文件中，在`head`部分中添加以下内容：

```ts
<link href="https://fonts.googleapis.com/icon?family=Material+Icons" 
    rel="stylesheet"> 

```

最终的`src/index.html`将如下所示：

```ts
<!doctype html>
<html>
<head>
 <meta charset="utf-8">
 <title>Chap10</title>
 <base href="/">

 <meta name="viewport" content="width=device-width, initial-scale=1">
 <link rel="icon" type="image/x-icon" href="favicon.ico">
 <link href="https://fonts.googleapis.com/icon?family=Material+Icons" 
    rel="stylesheet">
</head>
<body>
 <app-root>Loading...</app-root>
</body>
</html> 

```

现在，为了查看导入是否成功，我们将在自动生成的应用组件中添加一个图标。在 `src/app/app.component.html` 中，添加以下内容 `<i class="material-icons">cast_connected</i>`，使其看起来像这样：

```ts
<h1>
 {{title}}

 <i class="material-icons">cast_connected</i>
</h1> 

```

您的浏览器应该刷新 `http://localhost:4200/` 页面并显示 `cast_connected` 图标：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/a3436333-5125-423b-9d99-78301d21a2d2.png)Cast connected 图标。

正如您所看到的，使用 Material 图标非常简单。第一步是在[`material.io/icons/`](https://material.io/icons/)上识别您想要使用的一个图标的名称，然后创建一个带有 `class="material-icons"` 属性的 `<i></i>` 标签，最后包含您想要的图标名称。以下是一些例子：

+   `<i class="material-icons">cast_connected</i>`

+   `<i class="material-icons">gamepad</i>`

+   `<i class="material-icons">dock</i>`

+   `<i class="material-icons">mouse</i>`

# 按钮

除了图标之外，与 Material Design 一起使用的最简单的指令之一是按钮指令。我们可以有一个扁平的、凸起的、圆形的按钮，并且有三种不同的预设颜色：primary、accent 和 warn。以下是一个包含模板的组件，尝试一些可能的组合：

```ts

 @Component({
  selector: 'buttons',
  template: `
    <button md-button>FLAT</button>
    <button md-raised-button>RAISED</button> 
    <button md-fab>
        <md-icon>add</md-icon>
    </button>
    <button md-mini-fab>
        <md-icon>add</md-icon>
    </button>
    <button md-raised-button color="primary">PRIMARY</button>
    <button md-raised-button color="accent">ACCENT</button>
    <button md-raised-button color="warn">WARN</button>
  `
 })
 export class ButtonsComponent {
  constructor() { }
 }

```

结果如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/879e3180-fa7f-40d2-8c56-bf3e8a878efb.png)

接下来是：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/3b5a7151-8e37-40b8-a7b1-4fc1186fbc9a.png)

Primary、Accent 和 Warn 颜色要么在您的 `style.scss` 中定义为 SCCS 变量，要么在默认的 Material Design 主题中定义，如果您没有覆盖它们。

# 菜单

在这一部分，我们将对“菜单”指令感兴趣。以下组件创建了一个包含四个元素的菜单。第四个元素被禁用（也就是说，我们无法点击它）：

```ts
@Component({
 selector: 'menu',
 template: `
 <md-menu>
     <button md-menu-item> Refresh </button>
     <button md-menu-item> Settings </button>
     <button md-menu-item> Help </button>
     <button md-menu-item disabled> Sign Out </button>
 </md-menu>
 `
})
export class MenuComponent {
 constructor() { }
} 

```

当菜单关闭时，它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/dbbf37f1-1ffd-4cfc-9006-bb3c6808986a.png)菜单关闭。

并且在用户点击后打开的版本显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/402bfbcd-14d5-4354-be69-aacb064fdac1.png)菜单已打开。

# 工具栏

Angular Material Design 的工具栏组件应该按以下方式使用：

```ts
<md-toolbar>
 One good looking toolbar
</md-toolbar> 

```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/17f258d6-21e1-4f12-a38d-a64cde873bea.png)基本工具栏。

此外，您可以使用 Angular 的 `[color]="primary" | "accent" | "warn"` 属性。此外，工具栏可以通过使用 `<md-toolbar-row>` 标记包含行。

```ts
<md-toolbar [color]="accent">
  One good looking toolbar
</md-toolbar>
<md-toolbar [color]="warn">
  <span>First Row</span>

  <md-toolbar-row>
    <span>Second Row</span>
  </md-toolbar-row>

  <md-toolbar-row>
    <span>Third Row</span>
  </md-toolbar-row>
</md-toolbar>
<md-toolbar [color]="primary">
  Another good looking toolbar
</md-toolbar> 

```

以下将产生三个不同的工具栏，相互叠放。第二个工具栏将由三行组成。

# 对话框

根据谷歌的定义：<q>对话框通知用户特定任务的信息，可能包含关键信息，需要决策，或涉及多个任务</q>。在 Angular 中使用对话框时，有以下方法：

+   `open(component: ComponentType<T>, config: MdDialogConfig): MdDialogRef<T>`，创建并打开一个新的对话框，供用户进行交互

+   `closeAll()`: 用于关闭对话框的 void

然后，对话框本身可以使用四个不同的指令：

+   `md-dialog-title`将包含对话框的标题，如下所示：`<md-dialog-title>我的对话框标题</md-dialog-title>`。

+   `md-dialog-content`包含对话框的内容。

例如：`<md-dialog-content>我的对话框内容</md-dialog-title>`。

+   `md-dialog-close`要添加到按钮中（`<button md-dialog-close>关闭</button>`）。它使按钮关闭对话框本身。

+   `md-dialog-actions`用于设置对话框的不同操作，即关闭、放弃、同意等。

在下面的示例中，我们首先有一个草稿组件。草稿组件有一个简单的模板，只包含一个按钮。按钮的`click`事件调用`openDialog`方法。对于组件本身的定义，我们有一个接收名为`dialog`的`MdDialog`的构造函数。`openDialog`方法有两个回调--一个用于实际打开对话框，另一个用于在对话框关闭时打印包含在`result:`字符串中的`result`变量：

```ts
@Component({
 selector: 'draft-component',
 template: `
 <button type="button" (click)="openDialog()">Open dialog</button>
 `
})
export class DraftComponent {

 dialogRef: MdDialogRef<DraftDialog>;

 constructor(public dialog: MdDialog) { }

 openDialog() {
   this.dialogRef = this.dialog.open(DraftDialog, {
     disableClose: false
   });

   this.dialogRef.afterClosed().subscribe(result => {
     console.log('result: ' + result);
     this.dialogRef = null;
   });
 }
} 

```

正如您所看到的，`DraftComponent`组件的`dialogRef`属性是通用的。更具体地说，它是`DraftDialog`类的通用实例。让我们来定义它：

```ts
@Component({
 selector: 'draft-dialog',
 template: `
 <md-dialog-content>
   Discard Draft?
 </md-dialog-content>
 <md-dialog-actions>
   <button (click)="dialogRef.close('can
cel')">Cancel</button>
   <button md-dialog-close>Discard</button>
 </md-dialog-actions>
 `
})
export class DraftDialog {
 constructor(public dialogRef: MdDialogRef<DraftDialog>) { }
} 

```

再次强调，这是一个简单的类。在这里，我们可以看到模板包含了四个可能的指令中的三个。的确，我使用了`<md-dialog-content>`来定义要显示的对话框内容，`<md-dialog-actions>`来为对话框的操作按钮提供专用空间，最后，使用`md-dialog-close`来使“放弃”按钮关闭我的对话框。组件本身只有一个构造函数，定义了`public`属性：`MdDialogRef<DraftDialog>`。

使用此对话框的最后一步是在我们的`NgModule`中引用它，就像这样：

```ts
@NgModule({
 declarations: [
   ...,
   DraftDialog
 ],
 entryComponents: [
   ...,
   DraftDialog
 ],
 ...
})
export class AppModule { } 

```

当我们按下按钮时，这是对话框的图像：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/6584b231-4072-422b-872e-ae19bedf2b03.png)草稿对话框。

# 侧边导航抽屉

侧边导航抽屉在移动设备上非常受欢迎。然而，它们开始出现在完整版本的网站中；因此它们在本章中有所涉及。

侧边导航抽屉可以是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e2457bb6-3410-402a-bcc8-a10e879eddb3.png)侧边导航抽屉。

在左侧的浅灰色中，我们有导航抽屉，在调用时会弹出我们的内容。在较深的灰色中，我们有页面的内容。

使用以下组件，我们可以重现本节开头显示的侧边导航：

```ts
@Component({
 selector: 'sidenav',
 template: `
   <md-sidenav-container>
   <md-sidenav #side (open)="closeButton.focus()">
      Side Navigation.
     <br>
     <button md-button #closeButton      
         (click)="side.close()">Close</button>
   </md-sidenav>

   My regular content. This will be moved into the proper DOM at 
       runtime.
   <button md-button (click)="side.open()">Open side sidenav</button>

 </md-sidenav-container>
 `
})
export class SideNavComponent {
 constructor() { }
} 

```

这里唯一有趣的是模板。让我们来分解一下。首先，我们有封闭的`<md-sidenav-container>`标签，它允许我们为内容定义两个单独的区域。这两个区域分别是`md-sidenav`和我们页面的实际内容。虽然`md-sidenav`标签清楚地定义了内容的`sidenav`部分，但我们页面的其余内容（即实际页面）没有被包含在任何特殊的标签中。页面内容只需在`md-sidenav`定义之外。我们使用`#side`属性引用`md-sidenav`块。作为提醒，向任何 Angular 指令添加`#myName`会给你一个引用，以便在模板的其余部分中访问它。`md-sidenav`有一个打开方法，将焦点放在其内部定义的`#closeButton`上。这个按钮有一个`click`方法，调用`#side`的`close`方法。最后，在页面内容中，我们有一个按钮，当点击时调用`#side.open`。除了这两个方法（`open`和`close`），`md-sidenav`指令还有一个`toggle`方法，用于切换`sidenav`（即`opened = !opened`）。

# 主题化

现在，我们可以描述 Angular Material Design 中每个可用组件。然而，它们有很多，它们的用途都不复杂。在我撰写本章时，以下是支持的指令列表：

+   按钮

+   卡片

+   复选框

+   单选按钮

+   输入

+   侧边栏

+   工具栏

+   列表

+   网格

+   图标

+   进度

+   选项卡

+   滑动

+   滑块

+   菜单

+   工具提示

+   涟漪

+   对话框

+   消息框

在接下来的几个月里，将会添加更多的指令。你可以在这里找到它们：[`github.com/angular/material2`](https://github.com/angular/material2)。

不用说，我们在指令方面已经覆盖了。尽管有如此广泛的可能性，我们可以通过创建自定义主题进一步定制 Angular 的 Material Design。在 Angular Material 中，主题是通过组合多个调色板创建的。特别是，主题包括：

+   主要调色板由在所有屏幕和组件上广泛使用的颜色组成

+   强调调色板由用于浮动操作按钮和交互元素的颜色组成

+   警告调色板由用于传达错误状态的颜色组成

+   前景调色板由用于文本和图标的颜色组成

+   背景调色板由用于元素背景的颜色组成

以下是一个自定义主题的示例：

```ts
//src/styles.scss

@import '~https://fonts.googleapis.com/icon?family=Material+Icons';
@import '~@angular/material/core/theming/all-theme';
// Plus imports for other components in your app.

// Include the base styles for Angular Material core. We include this here so that you only
// have to load a single css file for Angular Material in your app.
@include md-core();

// Define the palettes for your theme using the Material Design 
   palettes available in palette.scss
// (imported above). For each palette, you can optionally specify a 
  default, lighter, and darker
// hue.
  $candy-app-primary: md-palette($md-indigo);
  $candy-app-accent:  md-palette($md-pink, A200, A100, A400);

// The warn palette is optional (defaults to red).
   $candy-app-warn:    md-palette($md-red);

// Create the theme object (a Sass map containing all of the palettes).
  $candy-app-theme: md-light-theme($candy-app-primary, $candy-app-  
   accent, $candy-app-warn);

// Include theme styles for core and each component used in your app.
// Alternatively, you can import and @include the theme mixins for each 
   component
// that you are using.
@include angular-material-theme($candy-app-theme); 

```

因此，我们已经学会了为 Material Design 创建自定义主题。

# 总结

在本章中，我们通过使用 Angular/Material2 模块了解了 Material Design 和响应式设计。我们看到了一些最常用的指令，如`buttons`、`icons`、`dialogs`或`sidenav`。此外，我们还利用了 Angular/Material2 的主题能力来定制 Material Design。

在第十五章中，*将 Bootstrap 与 Angular 应用程序集成*，我们将看到如何通过使用 Bootstrap（由 Twitter 提供）而不是 Material Design（由 Google 提供）来驱动我们的 Angular2 应用程序的设计。
