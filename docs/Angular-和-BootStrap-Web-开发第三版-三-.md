# Angular 和 BootStrap Web 开发第三版（三）

> 原文：[`zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD`](https://zh.annas-archive.org/md5/C3E0BC11B26050B30F3DD95AAA2C59BD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 NG Bootstrap

Bootstrap 是最受欢迎的 CSS 框架之一，而 Angular 是最受欢迎的 Web 应用程序框架之一。NG Bootstrap 是一个由 Bootstrap 4 CSS 构建的小部件（即组件）集合。它们专门用于作为 Angular 组件使用，并旨在完全替代由 JavaScript 驱动的 Bootstrap 组件。一些由 JavaScript 驱动的 Bootstrap 组件的示例包括以下内容：

+   轮播

+   折叠

+   模态

+   弹出框

+   工具提示

在本章中，我们将继续探讨组件，但将重点放在 ng-bootstrap 上，这是一个第三方 Angular 组件库，而不是 Angular 代码库的一部分。这一章和第九章，*使用 Angular Material*，都是相对较短的章节，但我想把它们包括在这本书中，原因与我包括第五章，*Flex-Layout – Angular's Responsive Layout Engine*相同-那就是给你选择的机会。在这一章的背景下，这意味着你可以选择为你的 Angular 应用程序利用的现成组件。

ng-bootstrap 没有官方的缩写，但为了方便起见，在本章中，我将给它一个。我们将把 NG Bootstrap 称为 NGB-事实证明，这也是键盘上有趣的输入（因为字母之间的距离如此接近）。试试看。

就像本书中的其他章节一样，我不会消耗大量页面来简单地重复 NGB 的官方文档，这些文档可以在网上免费获取，只是为了让这本书看起来令人敬畏。我宁愿给你一本 300 到 400 页的书，充满了精心挑选的好东西，让你一直阅读，而不是一本 500-600 页的书，可以用作你辛苦赚来的钱的催眠剂。话虽如此，NGB 的官方在线文档可以在这里找到：

[`ng-bootstrap.github.io`](https://ng-bootstrap.github.io)。

我想最后快速提一下的是，本章和接下来的一章（第八章，*使用 NG Bootstrap*）将比本书中的其他章节更加视觉化。这是因为我们现在开始进入我们示例应用程序的实质内容，并且我们将开始在视觉上构建事物。

现在处理完了杂事，接下来我们将一起讨论本章中要涵盖的内容：

+   集成 NGB

+   NGB 小部件（特别是折叠、模态和轮播）

+   设计规则是我们应该考虑的要点，以帮助避免过度使用小部件

# 集成 NGB

NGB 的存在意义是成为 Bootstrap 需要 JavaScript 的组件的完整替代品（例如本章开头列出的组件）。事实上，在官方网站的*入门*部分的第一页上，他们进一步表示，您不应该使用任何基于 JavaScript 的组件，甚至不应该使用它们的依赖项，如 jQuery 或 Popper.js。这可以在以下网址找到：[`ng-bootstrap.github.io/#/getting-started`](https://ng-bootstrap.github.io/#/getting-started)。

# 安装 NBG

首先要做的事情是：在我们查看使用 NGB 时需要注意的一个警告之前，让我们将其添加到我们的项目中——我还将向您展示如何解决可能遇到的冲突库（通过展示我的`package.json`文件）。

使用`npm`安装 NGB 很简单。但是，与其他模块一样，我们还需要将其导入并在根模块中列出（即`app.module.ts`）。以下是步骤：

1.  运行`npm install`：`npm install --save @ng-bootstrap/ng-bootstrap`

1.  将 NGB 导入到我们的根模块中：`import {NgbModule} from '@ng-bootstrap/ng-bootstrap';`

1.  在导入数组中列出`NgbModule`（作为根模块的`@NgModule`装饰器的参数）如下：`NgbModule.forRoot()`

如果您创建了一个使用 NGB 的 Angular 模块，那么您也需要将 NGB 导入其中。将 NGB 导入其他模块的语法与刚刚概述的导入到根模块中的语法完全相同，但是将 NGB 模块列为模块的`@NgModule`装饰器的参数的语法略有不同。它只是在导入数组中列出为`NgbModule`，而不是`NgbModule.forRoot()`，因为我们必须在根模块中列出它。

那么，我们要如何查看一些组件，而不会无意中搞乱我们示例应用程序的 NGB 部分呢？只有一种方法——我们要确保我们不直接或间接地将 jQuery 或 Popper.js 加载到我们的示例应用程序中，不使用 Bootstrap 组件（确保您理解 Bootstrap 和 NGB 是两个不同的库）。

让我快速澄清一些事情。我们的示例应用程序中安装了 jQuery 和 Popper.js，您可以通过查看我们的`package.json`文件来验证这一点。在其中，您将在依赖项部分看到 jQuery 和 Popper.js 的条目。我们不打算卸载这些库。只要我们不通过同时使用 Bootstrap 来加载它们，它们对我们使用 NGB 是无害的。换句话说，NGB 组件和 Bootstrap 组件不应共存于我们的 Angular 应用程序中。我们可以使用其中一个而不会出现问题，但绝不能同时使用两者。这样清楚吗？好的。

如果您尝试从项目中删除 jQuery 和/或 Popper.js，每当运行项目时，您可能会收到几个编译警告。虽然警告可能不会阻止项目运行，但始终努力实现干净的构建。

确保获得干净的构建有时可能会很麻烦，因为您需要注意库的版本。接下来的代码清单是我的`package.json`文件。当我运行`npm install`然后`npm start`时，我一直能够获得干净的安装编译。如果您没有获得干净的编译，您可能想要将您的`package.json`与我的进行比较，如下所示：

```ts
{
  "name": "listcaro",
  "version": "0.0.0",
  "license": "MIT",
  "scripts": {
    "ng": "ng",
    "start": "ng serve -o",
    "build": "ng build --prod",
    "test": "ng test",
    "lint": "ng lint",
    "e2e": "ng e2e"
  },
  "private": true,
  "dependencies": {
    "@angular/animations": "⁶.0.4",
    "@angular/cdk": "⁶.2.1",
    "@angular/common": "⁶.0.4",
    "@angular/compiler": "⁶.0.4",
    "@angular/core": "⁶.0.4",
    "@angular/flex-layout": "⁶.0.0-beta.16",
    "@angular/forms": "⁶.0.4",
    "@angular/http": "⁶.0.4",
    "@angular/platform-browser": "⁶.0.4",
    "@angular/platform-browser-dynamic": "⁶.0.4",
    "@angular/router": "⁶.0.4",
    "@angular/material": "⁶.2.1",
    "@ng-bootstrap/ng-bootstrap": "².1.0",
    "bootstrap": "⁴.0.0",
    "core-js": "².4.1",
    "jquery": "³.3.1",
    "npm": "⁶.1.0",
    "popper": "¹.0.1",
    "popper.js": "¹.14.3",
    "rxjs": "⁶.0.0",
    "save": "².3.2",
    "zone.js": "⁰.8.26"
  },
  "devDependencies": {
    "typescript": "2.7.2",
    "@angular/cli": "~1.7.4",
    "@angular/compiler-cli": "⁶.0.4",
    "@angular/language-service": "⁵.2.0",
    "@types/jasmine": "~2.8.3",
    "@types/jasminewd2": "~2.0.2",
    "@types/node": "~6.0.60",
    "codelyzer": "⁴.0.1",
    "jasmine-core": "~2.8.0",
    "jasmine-spec-reporter": "~4.2.1",
    "karma": "~2.0.0",
    "karma-chrome-launcher": "~2.2.0",
    "karma-coverage-istanbul-reporter": "¹.2.1",
    "karma-jasmine": "~1.1.0",
    "karma-jasmine-html-reporter": "⁰.2.2",
    "protractor": "~5.1.2",
    "ts-node": "~4.1.0",
    "tslint": "~5.9.1"
  }
}
```

您可以查看可用的 Angular 模块列表及其最新版本号，您可以使用`npm`安装，网址是：[`www.npmjs.com/~angular`](https://www.npmjs.com/~angular)。

# 为什么使用 NGB？

由于无法使用基于 JavaScript 的组件，也无法直接使用 JavaScript 库（如 jQuery 或 Popper.js），您可能会问，*为什么要使用 NGB*？

这是一个很好的问题。以下是简短的答案，以要点形式：

+   Angular 不依赖于 jQuery。它使用自己的 jQuery 实现，称为 jQLite，这是 jQuery 的子集。

+   我们不会失去使用任何由 JavaScript 驱动的 Bootstrap 组件的能力（例如模态框或轮播），因为它们在 NGB 中已经重新设计为 Angular。再次强调，NGB 的唯一目的是完全替代任何由 JavaScript 驱动的 Bootstrap 组件。

+   在构建 Angular 应用程序时的一个经验法则是尽量只使用特定于 Angular 的组件；也就是说，专门为 Angular 制作的组件，比如 NGB 小部件和来自 Angular Material 的组件。当然，这包括创建自定义的 Angular 组件。虽然你可以通过折衷使用非特定于 Angular 的组件来解决问题，但这并不推荐。Angular 功能齐全，正如我们所学到的，它也非常可扩展。很难想象有哪种情况下坚持使用特定于 Angular 的组件、模块、指令、管道、服务等会阻止你做你需要做的事情。

+   NGB 是一个坚实的 Angular 中心组件库，在你不尝试创建被不鼓励的变通方法时运行良好。

# 为 NGB（和 Angular Material 等）创建我们的游乐场

NGB 只有两个依赖项（Angular 和 Bootstrap CSS），幸运的是，我们的示例应用程序已经有了这两个东西——一个是默认的（因为我们的示例应用程序是一个 Angular 应用程序），另一个是在第三章中安装 Bootstrap 时安装的。然而，我们将向我们的示例应用程序添加一些内容，以便我们可以尝试使用 NGB 组件——一个游乐场视图。

在构建任何技术堆栈的 Web 应用程序时，我长期以来的传统做法，不仅适用于 Angular 应用程序，是添加一个页面作为我可以在当前构建的应用程序的上下文中尝试各种东西的地方。我把它称为游乐场。在我们的情况下，我们的游乐场将是一个组件，其模板将作为我们探索一些 NGB 组件时的实验画布。我们还将把它连接到我们的菜单，以便我们可以轻松访问它。

在本书的其余部分，我们将保留我们的游乐场视图，只会在第十五章中删除它，*部署 Angular 应用程序*，在那里我们将学习如何部署我们的应用程序，并不希望我们的游乐场随之而去。

所以，现在让我们这样做。自从我们在第四章中创建的示例应用程序中添加组件以来已经过了一段时间，因此我想借此机会列举出使用 playground 作为示例的步骤（在接下来的各自部分中）。请注意，这是手动向我们的项目添加组件的方式，与几章前使用 CLI 为我们添加的方式不同。

# 创建 playground 目录

我们需要做的第一件事是创建一个目录，用于保存我们 playground 组件所需的文件。我们的每个组件都有自己的目录，并且都是`app`目录的子目录，而`app`目录本身是项目根目录中`src`目录的子目录。

由于我们正在添加一个新组件，我们将遵循我们的惯例并为其创建一个目录。在您的 IDE 中，右键单击`app`目录，选择“新建文件夹”，输入`playground`作为名称，这遵循了我们迄今为止使用的惯例。完成后，我们将有一个地方来插入将共同组成我们组件的文件。

# 创建 playground 组件类

现在我们需要创建我们的 playground 组件类。在您的 IDE 中，右键单击新创建的`playground`目录，然后选择“新建文件”，输入`playground.component.ts`作为名称。`playground.component.ts`文件是我们的`component`类。在此文件中输入以下代码：

```ts
import { Component, OnInit } from '@angular/core';

@Component({
    selector: 'playground',
    templateUrl: './playground.component.html',
    styleUrls: ['./playground.component.css']
})
export class PlaygroundComponent implements OnInit {

    constructor() { }

    ngOnInit() { }

    pageTitle: string = "Playground";

}
```

通过查看我们的 playground`Component`类文件，您会注意到一些事情：

+   除了从`@angular/core`模块中导入组件之外，我们还导入了`OnInit`。这是因为我们给自己一个设置一些变量的地方，如果需要的话，比如用于传递任何子组件。

+   我们已经为我们的类包含了一个构造函数。无论我们是否使用它，它都为我们提供了一种机制，可以在组件的生命周期中触发一些代码。我们现在不会使用它，但我想向您展示，我们的“组件”函数就像传统的面向对象类一样，因此具有我们可以利用的构造函数。

+   我们已经设置了组件以使用外部文件作为其模板和样式，而不是内联。因此，下一步是创建这两个文件（请参见以下两个部分）。

+   我们在类中声明了一个属性（即`pageTitle`），类型为字符串，并将我们视图的名称分配给它。在下一节中，我们的模板将使用单向绑定语法显示此属性。

# 创建游乐场模板文件

我们现在需要为我们的游乐场组件创建模板文件，这将是我们组件的视觉界面。在您的 IDE 中，右键单击`playground`目录，选择`新建文件`，输入`playground.component.html`。`playground.component.html`文件是必需的，因为我们已将其作为参数传递给了我们的组件装饰器。在此文件中输入以下代码：

```ts
<h3> 
{{ pageTitle }} </h3> <hr>  
```

目前这个文件中还没有太多内容，但这将是我们添加 NGB 组件以便进行实验的地方。当然，实验是学习任何对您来说可能是新的技术的最佳方式。目前我们的模板只是通过绑定到我们类的`pageTitle`属性来显示我们的页面名称。

# 创建游乐场 CSS 文件

我们需要为游乐场组件创建的最后一个文件是用来存放其样式的文件。在您的 IDE 中，右键单击`playground`目录，选择`新建文件`，输入`playground.component.css`作为名称。`playground.component.css`文件也是必需的，因为我们已将其作为参数传递给了我们的组件装饰器。在此文件中输入以下代码：

```ts
/* Nothing here yet. This is a placeholder file that we may use later. */
```

前面的代码是不言自明的。目前这个文件中还没有任何样式，但为您创建的每个组件至少创建一个 CSS 文件是个好主意。

# 创建游乐场菜单项

好的。因此，按照前面部分的说明，您现在应该有一个游乐场组件，可以用作几乎任何实验的沙盒。在我们的特定情况下，我们将使用它来实验 NGB 小部件（即组件），但我们还将在第九章 *使用 Angular Material*期间使用这个沙盒。

在我们继续插入第一个 NGB 小部件之前，我们将会看一下。为我们的游乐场视图创建一个临时菜单链接是个好主意，这样我们就可以很容易地从应用程序内部访问它。现在让我们来做这个。

在您的 IDE 中，打开`app.component.html`文件。这是在启动过程中为您的 Angular 应用程序加载的主要或起始模板。这也是我们在《第四章》《路由》中创建菜单的地方。在这个文件中，在清单菜单项之后插入以下代码：

```ts
<li routerLinkActive="active" class="nav-item"> 
  <a routerLink="playground" class="nav-link">Playground</a> 
</li>
```

这个小的 HTML 代码片段所做的只是在我们的菜单中添加一个`playground`导航链接，并指示 Angular 的路由系统在点击时加载游乐场组件（因此加载游乐场模板，然后递归加载任何子组件）。

好的，很好，我们现在已经设置好，准备好看我们的第一个 NGB 小部件了。

# NGB 小部件

如前所述，NGB 小部件是第三方 Angular 组件，旨在取代基于 JavaScript 的 Bootstrap CSS 组件。NGB 有许多小部件可用，但在接下来的章节中，我们只会看到其中的三个。

您可以在以下网址找到完整的 NGB 小部件列表以及它们的文档：[`ng-bootstrap.github.io/#/components/`](https://ng-bootstrap.github.io/#/components/)。

# 折叠

折叠组件是一个有用的东西，可以节省屏幕空间。我们使用这个组件的用例是切换说明的显示或隐藏。当其父组件的模板被渲染时，组件的状态最初将被折叠，但用户可以根据需要切换说明的显示和重新折叠它们。

让我们在代码中看一个快速示例，我们可以在我们的游乐场中尝试，在这个示例中，我们可以切换页面上的一部分内容的显示和隐藏，这部分内容将是假设的说明（目前）。

我们需要修改三个文件才能使其工作。其他 NGB 组件的使用（甚至是我们将在下一章中看到的 Angular Material 组件）工作方式类似，因此我将花时间在每个代码清单后解释事情，因为这是我们一起看的第一个第三方组件。在以后看类似的组件时，如果它们与这些组件有实质性的不同，我会给出解释。

# 我们的父组件

在本章以及《第八章》《使用 NG Bootstrap》中，我们的父组件将始终是我们的游乐场组件。

修改你的 playground 组件模板（即`playground.component.html`文件），使其看起来如下：

```ts
<h3> 
  {{ pageTitle }} 
</h3> 
<hr> 

<ngb-collapse></ngb-collapse>

<br />

This is our page's main content
```

我们在 playground 模板中唯一添加的新内容是`<ngb-collapse></ngb-collapse>`，这是我们的自定义指令，将指示 Angular 在那里插入我们子组件的模板。`ngb-collapse`是我们组件类元数据中的选择器（即我们传递给组件装饰器的对象）。接下来让我们来看看那个文件。

# 我们的 NGB 折叠组件类

我们已经命名了我们的组件类（利用了 NGB 的`collapse`组件）*`NgbCollapseComponent`*—但这段代码在哪里呢？好吧，我们需要创建一个新目录，并在该目录中创建两个新文件，就像我们创建 playground 组件时所做的那样。是的—我们为我们的 playground 组件创建了三个文件，但是对于`NgbCollapseComponent`，我们将跳过 CSS 文件。

首先，创建一个名为`ngb-collapse`的目录。在这个新目录中，创建一个名为`ngb-collapse.component.ts`的文件，并在其中添加以下代码：

```ts
import { Component } from '@angular/core';

@Component({
  selector: 'ngb-collapse',
  templateUrl: './ngb-collapse.component.html'
})
export class NgbCollapseComponent {
  public isCollapsed = true;
}
```

正如你所看到的，我们没有定义`styleUrls`数组，这就是为什么我们不需要为它创建一个文件（如果我们想要给这个组件添加样式，我们会命名为`ngb-collapse.component.css`）。为了实验 NBG 折叠组件，我们只关心创建一个组件类文件和它的模板文件。

我们在组件类文件中感兴趣的另一件事是`isCollapsed`属性。当然，我们可以随意命名它，但重要的是它被声明并且最初设置为`true`。我们将通过将其值绑定到模板文件中的`ngbCollapse`属性来使用这个属性。这样做将导致我们组件模板的一部分被折叠（隐藏）或展开（显示）。请注意，我强调了我们组件中的目标内容将被隐藏或显示，而不是被添加或从 DOM 中移除。如果我们的内容被隐藏（即不可见），它仍然存在于 DOM 中。这是因为 NGB 折叠小部件不作为结构指令。它通过属性绑定实现其隐藏/显示功能。

现在让我们来看第三个文件，我们的组件模板

`NgbCollapseComponent`类。

# 我们的 NGB 折叠组件模板

在`ngb-collapse`目录中创建另一个文件，命名为`ngb-collapse.component.ts`，并在其中添加以下代码：

```ts
<p> 
    <button type="button" class="btn btn-outline-primary" (click)="isCollapsed = !isCollapsed"> 
        {{ isCollapsed ? 'Show' : 'Hide' }} Instructions 
    </button> 
</p> 
<div id="collapseExample" [ngbCollapse]="isCollapsed"> 
    <div class="card">
        <div class="card-body">
            These are the hypothetical instructions for something.
        </div>
    </div>
</div>
```

让我们一起看一下这段代码。我们感兴趣的第一件事是将`click`事件绑定到表达式上，这个表达式基本上在我们的组件类中定义的`isCollapsed`变量之间切换`true`和`false`：

```ts
(click)="isCollapsed = !isCollapsed"  
```

我们的切换按钮的文本始终设置为两个值中的一个。当显示说明时，按钮文本为“隐藏说明”。当说明被隐藏时，按钮文本为“显示说明”。这当然是我们想要的行为，但乍一看，你可能会认为需要一个`if .. else`结构才能使其全部工作。令人惊讶的是，多亏了 Angular 的插值模板语法，只需要很少的代码就可以根据我们的`isCollapsed`变量的值来改变按钮的文本。让我们花点时间来看一下负责确定按钮文本应该是什么的小代码片段，以及它是如何为我们呈现的：

```ts
{{ isCollapsed ? 'Show' : 'Hide' }} Instructions
```

在第七章中，*模板、指令和管道*，我们看了一下我们可以在模板语法中使用的所有符号，比如插值、双向绑定等等。在这种情况下，为我们工作的符号是插值符号（即一对双大括号）。我之所以称它为神奇，是因为它不仅可以用作字符串插值，而且还足够聪明，可以处理表达式甚至函数调用。因此，我们不仅仅局限于将变量名视为简单的字符串插值。

为了确定我们的按钮文本应该是什么，我们使用 JavaScript 的三元运算符语法根据我们的`isCollapsed`变量的值渲染（或插值）文本为两个值中的一个，显示或隐藏。当然，无论布尔值是什么，*说明*文本都将始终被呈现，从而使按钮文本成为“显示说明”或“隐藏说明”。这一切都是简洁而内联完成的。相当酷，不是吗？

# 导入和声明

如果你尝试运行项目，你会得到一些错误。这是因为我们还没有在`app.module.ts`文件中为这个组件设置导入和声明。让我们现在来做这个。

在我们为我们的游乐场组件添加的导入行之后添加这个导入行：

```ts
import { NgbCollapseComponent } from './ngb-collapse/ngb-collapse.component';
```

并将`NgbCollapseComponent`添加到声明数组中。

通过在`app.module.ts`文件的声明数组中导入前述导入并将我们的组件类添加到其中，我们的项目应该可以构建和运行得很好。

干得好。现在让我们继续进行我们的模态组件。

# 模态

模态对话框窗口自从桌面 Windows 操作系统的早期时代（互联网之前）就存在了，并且在网站上也变得很受欢迎——特别是自从 jQuery 出现以来。模态窗口用于与用户进行交互，通常是为了从他们那里获取信息。此外，它们通过调暗背景以及禁用模态区域外的任何交互来帮助设计师将用户的注意力集中在应该的地方。我们使用模态窗口的一个用例是显示登录表单。

让我们看一个在我们的播放中可以尝试的快速示例代码，以显示一个模态窗口。由于 NGB 小部件的集成都遵循相同的模式，我不会像折叠 NGB 小部件那样详细介绍它，但我会指出重要的地方。

我们所有的组件都以相同的方式开始。我们需要为我们的组件创建一个文件夹（让我们将其命名为`ngb-modal`），并且我们需要创建我们的两个文件——一个用于我们的组件类，另一个用于我们的组件模板。让我们分别将它们命名为`ngb-modal.component.ts`和`ngb-modal.component.html`。

接下来的部分是我们的 NGB 模态组件的两个代码清单，然后是必要的导入和声明，就像我们为折叠组件所做的那样。

# 我们的 NGB 模态组件类

在我们的组件类中，我们首先从适当的模块中导入必要的类，然后我们使用`@Component`装饰器装饰我们的类，这样我们就可以将其链接到模板并设置我们的选择器（即，我们将添加到我们的播放模板中的自定义 HTML 标记）。

接下来，我们添加一个构造函数，这样我们就可以注入`NgbModal`服务（注意：我们将在第十二章中介绍依赖注入，*集成后端数据服务*）。

我们的类有一个名为`closeResult`的变量，它由私有方法`getDismissReason`填充，描述了用户如何关闭模态对话框。

我们还有一个`open`方法，负责使模态对话框渲染。正如我们将在下一节的代码清单中看到的（在我们的组件模板中），`open`方法是由我们的游乐场内的按钮点击触发的。

您会注意到 open 方法接受一个参数（在本例中命名为`content`）。我们组件的模板将要在模态对话框中显示的内容包裹在它的`ng-template`标签中，正如您将看到的，这些标签与`#content`模板变量相关联。如果您还记得第七章中的内容，*模板、指令和管道*，模板语法中的井号（即`#`）用于表示一个变量：

```ts
import {Component} from '@angular/core';
import {NgbModal, ModalDismissReasons} from '@ng-bootstrap/ng-bootstrap';

@Component({
  selector: 'ngb-test-modal',
  templateUrl: './ngb-modal.component.html'
})
export class NgbModalComponent {
  closeResult: string;

  constructor(private modalService: NgbModal) {}

  open(content) {
    this.modalService.open(content).result.then((result) => {
    this.closeResult = `Closed with: ${result}`;
  }, (reason) => {
    this.closeResult = `Dismissed ${this.getDismissReason(reason)}`;
  });
}

  private getDismissReason(reason: any): string {
    if (reason === ModalDismissReasons.ESC) {
      return 'by pressing ESC';
    } else if (reason === ModalDismissReasons.BACKDROP_CLICK) {
      return 'by clicking on a backdrop';
    } else {
      return `with: ${reason}`;
    }
  } 
} 
```

现在让我们来看看我们的组件模板，`ngb-modal.component.html`。

# 我们的 NGB 模态组件模板

我们的组件模板不仅负责为模态对话框中显示的内容提供视图，还将为我们提供用户将使用的视觉元素（在本例中为按钮）来触发模态对话框。

以下 HTML 代码是我们的组件模板，稍后我们将用于我们的登录表单（注意：我们将在第十章中涵盖表单，*使用表单*）：

```ts
<ng-template #content let-c="close" let-d="dismiss">
  <div class="modal-header">
    <h4 class="modal-title">Log In</h4>
    <button type="button" class="close" aria-label="Close" (click)="d('Cross click')">
    <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="modal-body">
    <form>
      <div class="form-group">
        <input id="username" class="form-control" placeholder="username" >
        <br>
        <input id="password" type="password" class="form-control" placeholder="password" >
      </div>
    </form>
  </div>
  <div class="modal-footer">
    <button type="button" class="btn btn-outline-dark" (click)="c('Save click')">submit</button>
  </div>
</ng-template>

<button class="btn btn-lg btn-outline-primary" (click)="open(content)">Launch test modal</button>
```

既然我们已经有了我们的组件类和组件模板，我们必须告诉我们应用程序的根模块关于它们——我们将在下一节中做到这一点。

# 导入和声明

就像我们的折叠组件一样，如果您在这一点上尝试运行项目，您会得到一些错误——出于同样的原因——因为我们还没有在`app.module.ts`文件中为这个组件设置导入和声明。你知道该怎么做。

在我们为游乐场和折叠组件添加的导入行之后，添加这个导入行：

```ts
import { NgbModalComponent } from './ngb-modal/ngb-modal.component';
```

并将`NgbModalComponent`添加到声明数组中。

我知道你已经掌握了这个。让我们通过将另一个 NGB 小部件集成到我们的游乐场视图中来进行更多练习——作为奖励，我们将预览一下 Angular 的`HttpClient`模块。我们将使用`HttpClient`模块来获取我们轮播图的图片，并且我们还将在第十一章中使用`HttpClient`模块来调用我们的 API，*依赖注入和服务*。

所以让我们伸展双腿和双臂，用咖啡杯装满咖啡，然后继续前进到更有趣的组件之一（也将是我们示例应用程序的焦点），NGB 轮播。

# 轮播

轮播组件最显著的特点是作为一种工具（即小部件或组件）来按照预定顺序显示一系列图像，就像翻阅相册一样。我们的用例将会是这样：让用户有能力翻阅物业的照片。

让我们看一个快速的示例代码，我们可以在我们的游乐场中尝试显示三张图片。我们将从组件类开始，然后转到组件模板。这些代码清单直接来自 NGB 网站上的轮播示例，网址为：[`ng-bootstrap.github.io/#/components/carousel/examples`](https://ng-bootstrap.github.io/#/components/carousel/examples)。

我将把类的连接，使用`import`语句等等留给你作为练习。提示：这与我们之前在游乐场中添加折叠和模态组件时涵盖的过程完全相同（在它们各自的*导入和声明*部分）。然而，我会在每个代码清单后提到一些事情。

# 我们的 NGB 轮播组件类

在这一部分，我们将实现`ngb-carousel`组件类。以下是更新后的组件类。我们将稍后分析代码：

```ts
import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map } from 'rxjs/operators';

@Component({
  selector: 'ngb-test-carousel', 
  templateUrl: './ngb-carousel.component.html',
  styles: [`
    .carousel {
      width: 500px;
    }
 `]
})
export class NgbCarouselComponent implements OnInit {
  images: Array<string>;

  constructor(private _http: HttpClient) {}

  ngOnInit() {
    this._http.get('https://picsum.photos/list')
    .pipe(map((images: Array<{id: number}>) => this._randomImageUrls(images)))
    .subscribe(images => this.images = images);
  }

  private _randomImageUrls(images: Array<{id: number}>): Array<string> {
    return [1, 2, 3].map(() => {
      const randomId = images[Math.floor(Math.random() * images.length)].id;
      return `https://picsum.photos/900/500?image=${randomId}`;
    });
  }
}
```

在我们的组件类`ngb-carousel.component.ts`中有一些事情正在进行。我们从 Angular 的`http`模块中导入`HttpClient`类，还从`rxjs/operators`模块中导入`map`类。`HttpClient`类将在第十一章中更仔细地讨论，*依赖注入和服务*，用于从[`picsum.photos`](https://picsum.photos)获取图像对象的 JSON 列表，这是一个免费服务，提供占位图像，就像他们的网站所说的那样，照片的 Lorem Ipsum。`map`类用于将从`HttpClient`的`GET`请求返回的许多图像对象中随机映射三个到我们的字符串数组变量`images`。

从 API 中获取图像对象发生在我们的组件初始化时，因为`GET`请求发生在`ngOnInit()`组件的生命周期钩子内。

# 我们的 NGB 轮播组件模板

在本节中，我们将实现我们的`ngb-carousel`组件模板文件：

```ts
<ngb-carousel *ngIf="images" class="carousel">
  <ng-template ngbSlide>
    <img [src]="images[0]" alt="Random first slide">
    <div class="carousel-caption">
      <h3>First slide label</h3>
      <p>Nulla vitae elit libero, a pharetra augue mollis interdum.</p>
    </div>
  </ng-template>
  <ng-template ngbSlide>
    <img [src]="images[1]" alt="Random second slide">
    <div class="carousel-caption">
      <h3>Second slide label</h3>
      <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
    </div>
  </ng-template>
  <ng-template ngbSlide>
    <img [src]="images[2]" alt="Random third slide">
    <div class="carousel-caption">
      <h3>Third slide label</h3>
      <p>Praesent commodo cursus magna, vel scelerisque nisl consectetur.</p>
    </div>
  </ng-template>
</ngb-carousel>
```

这个模板很简单。除了`img` HTML 元素的`src`属性之外，其他都是硬编码的。在 HTML `img src`属性周围使用方括号是属性绑定的一个例子（正如我们在第七章中学到的，*模板、指令和管道*）。在这种情况下，轮播中的图片数量已知为三张。在实践中，就像我们在示例应用程序中所做的那样，模板通常会使用`*ngFor`结构指令来迭代长度可变的项目数组。

通过几个示例了解了如何将 NGB 小部件集成到我们的 playground 中后，现在我们可以在我们的应用程序中实现它们。

# 将 NGB 集成到我们的示例应用程序中

在前面的*NGBwidgets*部分，我们介绍了一些 NGB 中可用的组件。当然，你现在知道为什么我不会介绍所有可用的组件了，对吧？如果你说，“是的 Aki，我知道为什么。如果你介绍了所有的组件，基本上就是在重复已经可以在其他地方找到的文档”，那么你是正确的！介绍 16 个组件中的 3 个就足够了，几乎占了 19%（这几乎等同于每五页文档中重复一次！）。

但还有另一个原因。我们只打算实现我们介绍过的三个 NGB 组件中的两个，即模态组件和轮播组件，所以没有必要介绍太多其他的内容。好的，让我们继续把我们新学到的知识付诸实践。

我们在前面的部分学习了如何实现模态、轮播和折叠组件。我们为每个组件创建了选择器。对于模态组件，我们创建了一个名为`ngb-test-modal`的选择器；对于轮播组件，我们创建了一个名为`ngb-test-carousel`的选择器；最后，对于折叠组件，我们创建了一个名为`ngb-collapse`的选择器。现在我们需要在`playground.component.html`文件中使用这些选择器，以便小部件在页面上可见。

以下是 playground 组件模板文件的更新代码：

```ts
<p>
 {{pageTitle}} </p> <app-ngb-collapse></app-ngb-collapse> <app-ngb-modal></app-ngb-modal> <app-ngb-carousel></app-ngb-carousel>
```

我们使用了每个组件的选择器添加了指令。在命令行中使用`ng serve`命令运行应用程序，我们应该能看到输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/34434c9b-57ad-4f17-bec9-3f8fe7d366db.png)

我们的应用程序已经集成了小部件，但我们肯定可以在设计上做得更好。在接下来的几节中，我们将学习一些设计原则和最佳实践，这些将在接下来的章节中实施。

# UX 设计原则

几乎所有事情都有经验法则，网页设计也不例外。在网页设计中有应该做和不应该做的事情，既然我们现在真的开始深入研究我们的模板，现在是回顾一些这些设计原则的好时机。

可能有几十个设计原则，但我不是一个专家，所以最好是去找一本专注于 UX 和 GUI/界面设计的好书（我知道 Packt 有一些相关的书）。然而，由于我们正在构建一个应用程序，我们的应用程序由几个组件组成，如果我不介绍这三个基本的设计原则，那就不够周全。

我们不仅将在接下来的三个小节中涵盖它们，而且在构建示例应用程序的模板时，我们将遵守它们。我们之所以有 UX 设计原则之类的东西，归根结底就是一件事——我们希望用户能够快乐！

# 保持简洁

UX 准则 #1：保持简洁。

没有什么比过于繁忙（即混乱）的用户界面更容易让用户头疼。你可能听说过“少即是多”的表达方式，这个表达方式当然也适用于 UX 设计。

人们觉得自己没有时间做任何事情——如果做某事让他们觉得他们在浪费他们宝贵的资源（即时间），他们会比你数到 10 更快地变得不快乐。这如何与第一个 UX 设计原则相关？如果你的页面上有很多东西要看，他们不知道从哪里开始看——如果他们不能很快理解他们所看到的东西，那么你猜对了：他们会变得不快乐。

混乱几乎从来都不是一件好事。想想你的卧室或厨房。当它整洁，每样东西都有一个地方和目的，你可以轻松快速地找到你要找的东西时，你会更快乐吗？还是当你浪费 5 分钟找那个铲子来做早餐，而你几乎没有时间吃时，你会更快乐？答案，我希望是显而易见的。访问网站的用户也是这样想的。

# 保持功能性

UX 准则 #2：保持功能性。

这个 UX 原则与第一个原则相关，因为它与说我们视图上的几乎所有东西都应该有一个功能是一样的。在屏幕上有成千上万个毫无意义的东西的日子已经过去了。你还记得上世纪 90 年代网站的样子吗？Flash 风靡一时。网页看起来像雪球，或者有着大大的跳动的动画按钮，上面写着“立即点击这里”。这些都不再被容忍。如果你的网页上有这样的东西，很有可能你的访客会尽可能快地离开你的网站。如果屏幕上有东西，它最好有一个目的。

如果你想看一个极端的例子，一个网站关注第一和第二（以及即将到来的第三）UX 设计原则，只需看一下谷歌的主页：[`www.google.com/`](https://www.google.com/)。

# 保持明显

UX 原则 #3：保持明显。

没有什么比强迫用户使用大量的脑力、时间和侦探技能来找出他们需要做什么，或者如何在网页应用程序中执行他们想要执行的特定任务更让用户沮丧的了。

您的网页应用程序的用户之所以成为用户，是因为他们需要一个工具来完成某些事情。无论他们想要完成的任务是为了快乐还是工作，都无关紧要。无论他们想要完成什么，他们都不想花费比合理时间更多的时间。如果他们需要花费太多时间来弄清楚事情，猜猜看？是的！他们会变得不快乐！

这第三个 UX 设计原则可能是最难坚持的，但作为应用程序构建者，我们有责任给予它应有的关注。

# 总结

在本章中，我们探讨了 NG Bootstrap——两个免费提供给我们在 Angular 应用程序中使用的第三方组件库中的第一个。我们将在下一章中探讨第二个，Angular Material。

我们学习了如何安装 NGB，然后在应用程序中创建了一个游乐场，这样我们就有了一个可以玩耍（即实验）这些第三方组件的地方，包括临时通过路由将游乐场与菜单连接起来，以便轻松访问我们的游乐场。虽然我们本可以在集成这些组件到应用程序的预期用途之前创建一个完全独立的项目来玩耍，但通常更方便的是在现有基础设施中创建一个游乐场。当然，当我们部署应用程序时，我们可以轻松地删除游乐场和菜单选项及其相应的路由。

设置好我们的游乐场后，我们开始学习如何集成 NGB 的三个小部件：折叠、模态和轮播。

最后，为了结束本章，因为我们现在处于书中的组件和布局部分（而不是后端数据集成和服务部分），现在是一个很好的时机来介绍一些设计原则。因此，我们简要介绍了三个良好设计的主要原则：保持清晰、功能性和明显性。在本书的其余部分，我们将尽力遵守这些设计原则。

现在，戴上你的组件帽子，翻开书页，让我们来看看 Angular 团队为我们设计的华丽组件。合理地利用 Angular Material 组件，可以提高我们示例应用的可用性和美观度。幸运的是，Angular Material 与 Bootstrap 兼容良好，因此在同一个 Angular 项目中同时使用这两个库并不成问题。


# 第九章：使用 Angular Material

欢迎来到关于 Angular Material 的章节。我必须说，我印象深刻。统计数据显示，购买技术书籍的大多数人并没有读很远。您已经完成了大部分书籍——干得好，Angular 绝地！

这将是一个简短的章节，原因有几个。首先，这本书主要用于构建应用程序，主要使用 Angular 和 Bootstrap。因此，可以将这一章视为我们的额外奖励。另一个原因是，这一章仅旨在介绍在使用 Angular 时与 Bootstrap 一起使用的另一种用户界面（UI）组件库。应该有一本单独的关于 Angular Material 的书，但这一章将在展示库提供的功能和组件方面涵盖很多内容。

我们将了解导航和菜单组件、布局组件、表单字段元素、按钮、对话框和弹出组件，以及许多有趣的元素，您肯定会喜欢，并可能考虑在下一个项目的框架中使用。

总结一下，本章将涵盖的主题有：

+   什么是 Angular Material？

+   安装 Angular Material

+   组件的类别

好的，让我们直接开始，从描述 Angular Material 开始。

# 什么是 Angular Material？

Angular Material 是一个丰富的组件集合，可以轻松地插入到 Angular 应用程序中，并且也适用于 Web、移动和桌面应用程序。Material Design 来自谷歌，是 Angular 的制造商，这意味着对组件以及将来推出的新组件进行了大量的本地支持、优化和性能调整。以下列表显示了在我们的应用程序中使用 Material Design 时我们可以获得的一些好处：

+   UI 组件可以立即使用，无需额外的开发工作

+   我们可以选择性地选择单独使用组件，而不是被迫一次性导入所有模块

+   组件的渲染非常快

+   通过双向或单向数据绑定功能，可以轻松地将数据插入组件中，这是 Angular 的一个非常强大的功能

+   组件在 Web、移动和桌面应用程序中具有相同的外观、感觉和行为，这解决了许多跨浏览器和跨设备的问题

+   性能经过调整和优化，以便与 Angular 应用程序集成

您可以在官方网站[`material.angular.com`](https://material.angular.io/)上找到有关 Angular Material 的所有必要文档。

在本章中继续之前，让我们快速生成一个应用程序，在这个应用程序中我们将实现所有的 Angular Material 组件。运行以下`ng`命令以生成一个名为`AngularMaterial`的新应用程序：

```ts
ng new AngularMaterial
```

一旦命令成功执行，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/c0174b28-d32b-40aa-a72a-d5587896fc8b.png)

现在我们的应用程序已经生成，让我们学习如何在项目中安装 Angular Material 库。

# 安装 Angular Material

到目前为止，您一定有一种强烈的直觉，即当我们想在 Angular 应用程序中安装任何东西时，我们有一个强大的**命令行界面**（**CLI**）工具。我们将继续使用相同的 CLI，并借助`npm`来安装 Angular Material。

您也可以选择通过 YARN 命令安装 Angular Material—不同的打包系统，同样的结果。

Angular Material 有一个核心依赖和先决条件，需要安装两个包—CDK 和 Animations。所以，让我们先安装这些，然后再安装 Angular Material：

```ts
npm i @angular/cdk --save

npm i @angular/animations --save

npm i @angular/material --save
```

成功运行上述命令后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2432176e-e0d9-4615-a0c9-7b7481accdee.png)

打开`package.json`文件；我们应该看到已安装的包，以及它们旁边列出的相应版本号。如果你看到我们最近安装的三个包，那就意味着我们准备好开始使用 Angular Material 创建一些很棒的 UI 界面了。

一旦我们安装了 Angular Material，我们将需要将所有必需的模块导入到我们的`app.module.ts`文件中。Material 提供了许多模块，每个模块都有特定的目的。例如，如果我们打算使用 Material 卡片，我们将需要导入`MatCardModule`。同样，如果我们想在应用程序中使用 Material 芯片，我们需要导入`MatChipsModule`。虽然我们可以在`AppModule`中确实只导入所需的模块，但在大多数使用 Material UI 的应用程序中，我们将需要所有模块。现在，让我们快速学习如何一次性导入所有模块。我们可以将所有模块导入到一个通用模块中，然后在`app.module.ts`文件中使用新创建的通用模块。首先，在我们的项目结构中创建一个文件，并将其命名为`material-module.ts`，然后我们可以添加以下代码以一次性导入所有模块到这个文件中：

```ts
import  {A11yModule}  from  '@angular/cdk/a11y'; import  {DragDropModule}  from  '@angular/cdk/drag-drop'; import  {ScrollingModule}  from  '@angular/cdk/scrolling'; import  {CdkStepperModule}  from  '@angular/cdk/stepper'; import  {CdkTableModule}  from  '@angular/cdk/table'; import  {CdkTreeModule}  from  '@angular/cdk/tree'; import  {NgModule}  from  '@angular/core'; import  {
  MatAutocompleteModule,
  MatBadgeModule,
  MatBottomSheetModule,
  MatButtonModule,
  MatButtonToggleModule,
  MatCardModule,
  MatCheckboxModule,
  MatChipsModule,
  MatDatepickerModule,
  MatDialogModule,
  MatDividerModule,
  MatExpansionModule,
  MatGridListModule,
  MatIconModule,
  MatInputModule,
  MatListModule,
  MatMenuModule,
  MatNativeDateModule,
  MatPaginatorModule,
  MatProgressBarModule,
  MatProgressSpinnerModule,
  MatRadioModule,
  MatRippleModule,
  MatSelectModule,
  MatSidenavModule,
  MatSliderModule,
  MatSlideToggleModule,
  MatSnackBarModule,
  MatSortModule,
  MatStepperModule,
  MatTableModule,
  MatTabsModule,
  MatToolbarModule,
  MatTooltipModule,
  MatTreeModule, }  from  '@angular/material'; @NgModule({
 exports:  [
  A11yModule,
  CdkStepperModule,
  CdkTableModule,
  CdkTreeModule,
  DragDropModule,
  MatAutocompleteModule,
  MatBadgeModule,
  MatBottomSheetModule,
  MatButtonModule,
  MatButtonToggleModule,
  MatCardModule,
  MatCheckboxModule,
  MatChipsModule,
  MatStepperModule,
  MatDatepickerModule,
  MatDialogModule,
  MatDividerModule,
  MatExpansionModule,
  MatGridListModule,  MatIconModule,
  MatInputModule,
 MatListModule,
 MatMenuModule,
 MatNativeDateModule,
 MatPaginatorModule,
 MatProgressBarModule,
 MatProgressSpinnerModule,
 MatRadioModule,
 MatRippleModule,
 MatSelectModule,
 MatSidenavModule,
 MatSliderModule,
 MatSlideToggleModule,
 MatSnackBarModule,
 MatSortModule,
 MatTableModule,
 MatTabsModule,
 MatToolbarModule,
 MatTooltipModule,
 MatTreeModule,
 ScrollingModule, ] }) export  class  MaterialModule  {}
```

在上述代码中，我们将所有必需的模块导入到文件中。暂时不要担心对先前列出的模块进行分类。当我们学习 Material 提供的组件时，我们会了解这些模块。下一步非常明显——我们需要将这个新创建的模块导入到我们的`app.module.ts`文件中：

```ts
import  {MaterialModule}  from  './material-module';
```

一旦我们导入了模块，不要忘记将其添加到`AppModule`的导入中。就这样。我们已经准备好开始学习和实现由 Angular Material 提供的组件了。

你知道吗？谷歌还发布了一个轻量级的基于 CSS 和 JavaScript 的 Lite 库，Material Design Lite，它开始使用组件的方式与任何其他 UI 库一样。然而，可能有一些组件不具有完全支持。在[`getmdl.io/`](https://getmdl.io/)了解更多信息。

让我们立即开始学习 Angular Material 的组件。 

# 组件类别

作为前端开发人员，你可能已经使用了许多 UI 组件，甚至更好的是，你可能在过去的项目中创建了自己的自定义组件。正如前面提到的，Angular Material 提供了许多组件，可以在我们的应用程序中方便地使用。Angular Material 提供的 UI 组件可以归类为以下类别：

+   布局

+   材料卡片

+   表单控件

+   导航

+   按钮和指示器

+   模态框和弹出窗口

+   表格

为每个类别生成组件是一个好主意，这样当我们开始实现应用程序时，占位符将可用。这些组件将以清晰的分类方式托管所有组件，并且它们将成为您可以用来参考 Material 库中任何组件实现的一站式组件。

首先，让我们为我们的类别生成组件。依次运行以下`ng`命令：

```ts
ng g component MaterialLayouts
ng g component MaterialCards
ng g component MaterialForm
ng g component MaterialNavigation
ng g component MaterialButtons
ng g component MaterialModals
ng g component MaterialTable
```

在成功运行命令后，我们应该看到生成的组件已添加到我们的项目结构中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/5e3af425-e7e2-41d1-a6b6-d0721ace3089.png)

很好。我们已经生成了我们的应用程序；我们已经安装了 Angular Material。我们还将所有所需的模块导入到了我们的`AppModule`文件中，最后，我们为 Material 的 UI 组件中的每个类别生成了组件。在我们开始实现 Material 组件之前，我们需要做的最后一件事是为之前列出的每个类别添加路由。打开`app-routing.module.ts`文件，导入所有新创建的组件，并将路由添加到文件中：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { MaterialFormComponent } from './material-form/material-form.component';
import { MaterialNavigationComponent } from './material-navigation/material-navigation.component';
import { MaterialCardsComponent } from './material-cards/material-cards.component';
import { MaterialLayoutComponent } from './material-layout/material-layout.component';
import { MaterialTableComponent } from './material-table/material-table.component';
import { MaterialModalsComponent } from './material-modals/material-modals.component';
import { MaterialButtonsComponent } from './material-buttons/material-buttons.component';

const routes: Routes = [
 { path: 'material-forms', component: MaterialFormComponent },
 { path: 'material-tables', component: MaterialTableComponent },
 { path: 'material-cards', component: MaterialCardsComponent},
 { path: 'material-layouts', component: MaterialLayoutComponent},
 { path: 'material-modals', component: MaterialModalsComponent },
 { path: 'material-buttons', component: MaterialButtonsComponent },
 { path: 'material-navigation', component: MaterialNavigationComponent }
];

@NgModule({
 imports: [RouterModule.forRoot(routes)],
 exports: [RouterModule]
})
export class AppRoutingModule { }
```

在上述代码中，我们导入了所有新创建的组件，并为每个组件创建了路由路径。到目前为止，一切都很顺利。现在，大舞台已经准备就绪，可以开始了。让我们先从我们的布局开始。

# 导航

任何 Web 应用程序最常见和基本的需求之一是导航菜单或工具栏。Angular Material 为我们提供了多种选项，我们可以选择最适合我们应用程序的菜单类型。

# 使用原理图生成导航组件

我们将从最简单和最快的方式开始，通过使用原理图来将导航添加到我们的应用程序中。没错，离我们的菜单上线只有一步之遥。Angular CLI 提供了原理图，以便获得各种组件。要在我们的应用程序中安装导航菜单，请在 Angular CLI 命令提示符中运行以下命令：

```ts
ng generate @angular/material:nav myMenu
```

在上述命令中，我们使用原理图生成了一个名为`myMenu`的新菜单组件。在成功运行命令后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/319b20ae-4874-400b-bb44-b6b52d48bb54.png)

使用`ng serve`命令运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/05466c30-f141-438f-9d69-6fa346e37940.png)

这不是一个非常酷的导航菜单吗？它带有一个顶部标题工具栏和一个可折叠的侧边栏菜单。这个组件是由原理图自动生成的。如果你不是自动生成组件的忠实粉丝，没关系，我们开发人员对这些事情可能会挑剔。让我们看看如何创建我们自己的菜单。

# 自定义 Material 菜单和导航

Angular Material 提供了`MatMenuModule`模块，其中提供了`<mat-menu>`和`MatToolBarModule`指令。还提供了`<mat-toolbar>`，它将用于在我们的应用程序中实现菜单和标题。打开`material-navigation.component.html`文件并添加以下代码：

```ts
<mat-toolbar id="appToolbar" color="primary">
<h1 class="component-title">
 <a class="title-link">Angular Material</a>
 </h1>
 <span class="toolbar-filler"></span>
 <a href="#">Login</a>
 <a href="#">Logout</a>
</mat-toolbar>
```

在上述代码中，我们使用`<mat-toolbar>`作为包装器实现了工具栏指令，并使用`<h1>`添加了一个标题。我们还在标题部分添加了一些链接。使用`ng serve`运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/88e74315-d203-4418-a9bb-9ecfd0e0e0d9.png)

太棒了。让我们再增强一下。我们想要在标题工具栏中添加一个下拉菜单。记得我告诉过你，我们有`MatMenuModule`模块提供的`<mat-menu>`指令吗？让我们在上述代码中的标题工具栏中添加菜单指令如下：

```ts
<mat-toolbar id="appToolbar" color="primary">
<button md-icon-button (click)="sidenav.toggle()" class="md-icon-button sidenav-toggle-button" [hidden]="sidenav.opened">
<mat-icon aria-label="Menu" class="material-icons">menu</mat-icon>
</button>

<h1 class="component-title">
<a class="title-link">Angular Material</a>
</h1>
<span class="toolbar-filler"></span>

<button mat-button [matMenuTriggerFor]="menu" color="secondary">Menu</button>
<mat-menu #menu="matMenu" >
<button mat-menu-item>Item 1</button>
<button mat-menu-item>Item 2</button>
</mat-menu>

<a href="#">Login</a>
<a href="#">Logout</a>
</mat-toolbar>
```

请注意，我们使用`mat-button`属性添加了一个按钮，并绑定了`matMenuTriggerFor`属性。这将显示使用`<mat-menu>`指令定义的下拉菜单。现在让我们使用`ng serve`命令运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2ee0cf78-0bdf-45fd-bcb4-196931da3229.png)

# 自定义侧边栏菜单

太棒了。现在我们有了自制菜单可以使用。我知道你想要更多，对吧？你也想要添加一个侧边栏吗？让我们来做吧。为了将侧边栏添加到我们的应用程序中，Angular Material 为我们提供了一个`MatSidenavModule`模块，其中提供了我们可以在应用程序中使用的`<mat-sidenav>`指令。因此，让我们继续修改上述代码如下：

```ts
<mat-sidenav-container fullscreen>
 <mat-sidenav #sidenav mode="push" class="app-sidenav">
 <mat-toolbar color="primary">
 <span class="toolbar-filler"></span>
 <button md-icon-button (click)="sidenav.toggle()" class="md-icon-button 
   sidenav-toggle-button" [hidden]="!sidenav.opened">
 </button>
 </mat-toolbar>
</mat-sidenav>
<mat-toolbar id="appToolbar" color="primary">
 <button md-icon-button (click)="sidenav.toggle()" class="md-icon-button 
   sidenav-toggle-button" [hidden]="sidenav.opened">
 <mat-icon aria-label="Menu" class="material-icons">menu</mat-icon>
 </button>
 <h1 class="component-title">
 <a class="title-link">Angular Material</a>
 </h1>
 <span class="toolbar-filler"></span>
 <button mat-button [matMenuTriggerFor]="menu" 
   color="secondary">Menu</button>
 <mat-menu #menu="matMenu" >
 <button mat-menu-item>Item 1</button>
 <button mat-menu-item>Item 2</button>
 </mat-menu>
 <a href="#">Login</a>
 <a href="#">Logout</a>
 </mat-toolbar>
</mat-sidenav-container>
```

不要被代码行数吓到。我们只是做了一些改动，比如添加了`<mat-sidenav>`指令，它将包含侧边栏的内容。最后，我们将整个内容包装在`<mat-sidenav-container>`指令内；这很重要，因为侧边栏将覆盖在内容上方。使用`ng serve`命令运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/3468908b-0cf1-42c8-b0b3-5dd7b59ae589.png)

如果你看到了上面截图中显示的输出，给自己一个鼓励。太棒了！你做得非常好。所以，我们已经学会了两种在我们的应用程序中实现导航和菜单的方法。我们可以使用原理图生成导航组件，也可以编写自定义菜单导航组件。无论哪种方式，**用户体验**（**UX**）都是赢家！

现在我们有了导航菜单组件，让我们学习一下 Angular Material 库的其他组件。

# 卡片和布局

在这一部分，我们将学习关于 Angular Material 卡片和布局的知识。Angular Material 的基本布局组件是卡片。卡片包装布局组件还可以包括列表、手风琴或展开面板、选项卡、步进器等等。

# 材料卡片

卡片是用于组合单个主题的数据的文本、图像、链接和操作的内容容器。卡片可以有标题、正文、图像或链接，根据它们的可用性和功能，可以显示给用户。Angular Material 提供了一个名为`MatCardModule`的模块，其中提供了`<mat-card>`指令。我们将使用这个来组合我们应用程序的内容。

创建卡片的基本示例如下：

```ts
<mat-card class="z-depth" >
 <mat-card-title><a href="" primary >Packt Books</a></mat-card-title>
 <mat-card-subtitle>Family of wonderful Authors and Readers
   </mat-card-subtitle>
 <mat-card-content>
 We are learning to create wonderful cards. Each card has some specific 
  data to be displayed to users.
 </mat-card-content>
<mat-card-actions> <button mat-raised-button>Tweet This</button>
  <button mat-raised-button>Share</button></mat-card-actions>
</mat-card>
```

在上面的代码中，我们使用了`MatCardModule`提供的指令。我们将使用`<mat-card>`作为包装指令，以便将内容分组。通过使用`<mat-card-title>`指令，我们设置了卡片的标题。我们使用`<mat-card-subtitle>`指令在`<mat-card>`指令内设置副标题。在`<mat-card-content>`内，我们放置所有需要显示给用户的内容。每个卡片可能有我们希望用户执行的操作，例如分享、编辑、批准等。我们可以使用`<mat-card-actions>`指令显示卡片操作。

使用`ng serve`命令运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/323a6edf-28da-483d-a148-e126f0335576.png)

请注意，我们在 Angular Material 卡片内添加了一些内容。您是否想知道卡片内可以显示什么样的内容？只要您想，我们都可以使用。我们可以添加链接、图片、列表、手风琴、步进器等。在下一节中，我们将学习如何将列表添加到我们的卡片中。

# 列表

列表是一组项目的集合。在我们的应用程序中，可以是有序列表，也可以是无序列表。在本节中，我们将学习如何在卡片内添加不同类型的列表。看看下面的示例代码：

```ts
<mat-card class="z-depth" >
 <mat-card-title>Material Lists</mat-card-title>
 <mat-card-content>
 <mat-list>
 <mat-list-item> New York City</mat-list-item>
 <mat-list-item> London</mat-list-item>
 <mat-list-item> Dallas</mat-list-item>
</mat-list>
 </mat-card-content>
</mat-card>
```

在上面的代码中，我们添加了几个城市的列表。我们使用了`MatListModule`中提供的`<mat-list>`和`<mat-list-item>`指令，以便在卡片内创建和显示城市列表。上面的代码输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/fcc17b3f-51e2-4b64-84c7-7463058f3630.png)

# 带分隔线的列表

我们还可以很容易地为列表项添加`divider`类，以便在视觉上将它们分隔成行。我们需要添加`<mat-divider>`指令以实现该功能。看看下面更新的代码：

```ts
<mat-card class="z-depth" >
 <mat-card-title>Material Lists with Divider</mat-card-title>
 <mat-card-content>
<mat-list>
 <mat-list-item> Home </mat-list-item>
 <mat-divider></mat-divider>
 <mat-list-item> About </mat-list-item>
 <mat-divider></mat-divider>
 <mat-list-item> Contact </mat-list-item>
 <mat-divider></mat-divider>
</mat-list>
</mat-card-content>
</mat-card>
```

# 导航列表

我们可以扩展列表使其可点击，从而将其转换为导航链接。要使列表项可点击，我们需要使用`<mat-nav-list>`指令。看看下面的示例代码：

```ts
<mat-card class="z-depth" >
 <mat-card-title>Material Navigational Lists</mat-card-title>
 <mat-card-content>
<mat-nav-list>
 <a mat-list-item href="#" *ngFor="let nav of menuLinks"> {{ nav }} </a>
</mat-nav-list>
 </mat-card-content>
</mat-card>
```

在上面的代码中，我们使用了`MatListModule`模块中提供的`<mat-nav-list>`和`<mat-list-item>`指令，创建了导航类型的列表和卡片内的列表项。上面的代码输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/823821fa-d49d-4c3f-ad0f-c6244e57222f.png)

# 手风琴和展开面板

另一个非常酷的 UI 组件是手风琴或展开面板。当我们需要将数据分组在一起时，使用它非常方便。我们需要使用`MatExpansionModule`模块中提供的`<mat-accordion>`和`<mat-expansion-panel>`来实现我们应用程序中的手风琴功能。看看下面的示例代码：

```ts
<mat-card class="z-depth" >
 <mat-card-title>Material Expansion Panels</mat-card-title>
 <mat-card-content>
<mat-accordion>
 <mat-expansion-panel>
 <mat-expansion-panel-header>
 <mat-panel-title>
 Personal Details
 </mat-panel-title>
 </mat-expansion-panel-header>
</mat-expansion-panel>
 <mat-expansion-panel >
 <mat-expansion-panel-header>
 <mat-panel-title>
 Professional Details
 </mat-panel-title>
 <mat-panel-description>
 </mat-panel-description>
 </mat-expansion-panel-header>
 <p>I'm visible because I am open</p>
 </mat-expansion-panel>
</mat-accordion>
 </mat-card-content>
</mat-card>
```

每个`<mat-expansion-panel>`都将有一个`<mat-expansion-panel-header>`，我们可以在其中为展开面板提供标题和描述，并将内容放在`<mat-expansion-panel>`指令本身内。上面的代码输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2048cc2a-8f6c-4e4f-9c97-fe337655a8e6.png)

有时我们需要引导用户完成一系列步骤的用例。这就是我们下一个组件发挥作用的地方。它被称为步进器。顾名思义，这将用于设计水平或垂直的步骤，并将一系列步骤分组，用户可以导航到这些步骤。

# 步进器

与我们在*手风琴和展开面板*部分学到的类似，我们需要添加一个`包装器`和一个`<mat-horizontal-stepper>`指令，在其中，我们将创建`<mat-step>`指令。对于我们想要添加的每个步骤，我们需要为我们的应用程序创建一个新的`<mat-step>`指令。我们也可以创建一个垂直步进器。为此，我们将使用`<mat-vertical-stepper>`指令作为`包装器`类。请看下面的代码；我们正在创建一个水平步进器：

```ts
<mat-card class="z-depth" >
<mat-card-title>Material Stepper</mat-card-title>
<mat-card-content>
<mat-horizontal-stepper [linear]="isLinear" #stepper>
<mat-step label="Personal Details">
Step #1
</mat-step>
<mat-step label="Professional Details">
Step #2
</mat-step>
<mat-step>
<ng-template matStepLabel>Done</ng-template>
You are now done.
<div>
<button mat-button matStepperPrevious>Back</button>
<button mat-button (click)="stepper.reset()">Reset</button>
</div>
</mat-step>
</mat-horizontal-stepper>
</mat-card-content>
</mat-card>
```

在上面的代码中，我们创建了一个包含三个步骤的水平步进器。为了定义步进器，我们使用了`<mat-horizontal-stepper>`，用于定义实际步骤，我们使用了`<mat-step>`指令。上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/69a83ba5-3466-4b3f-94e7-47e98d94707b.png)

# 标签页

我们要学习的最后一个布局组件是标签页。Angular Material 提供了一个名为`MatTabsModule`的模块，该模块提供了`<mat-tab-group>`和`<mat-tab>`指令，以便我们可以轻松地在我们的应用程序中创建一个标签页组件。请看下面的示例代码：

```ts
<mat-card class="z-depth" >
 <mat-card-title>Material Tabs</mat-card-title>
 <mat-card-content>
 <mat-tab-group>
 <mat-tab label="Personal"> This is a Personal Tab </mat-tab>
 <mat-tab label="Professional"> This is a Professional tab </mat-tab>
 <mat-tab label="Contact"> This is Contacts Tab </mat-tab>
</mat-tab-group>
</mat-card-content>
</mat-card>
```

在上面的代码中，我们使用了`<mat-tab-group>`包装指令，在其中，我们使用了`<mat-tab>`指令来指定每个特定的标签页。每个标签页都有一个标签，将显示在标签页的顶部。在`<mat-tab>`内部，我们将显示每个标签页的内容。请看下面截图中上面代码的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/27a9c3bf-23ed-49f3-963f-f591dea8cb06.png)

在下一节中，我们将学习关于 Angular Material 表单的知识。继续阅读。

# 表单控件

表单是任何交互式和动态应用程序的主要组成部分。Angular Material 原生支持表单和表单控件，可以轻松地集成到我们的应用程序中。在本节中，我们将学习如何使用 Angular Material 组合表单。

总的来说，表单在 UX/UI 方面已经有了很大的发展。Angular Material 支持涉及文本字段、文本区域、下拉选择选项、单选按钮和复选框等基本表单字段元素。Angular Material 还提供了高级表单元素，例如自动完成、日期选择器、滑动开关等。在我们进行实际示例的过程中，我们将学习如何将所有这些添加到我们的表单中。

Angular Material 提供了许多与表单和表单字段元素相关的模块，包括以下列出的模块：

+   `MatFormFieldModule`

+   `MatInputField`

+   `MatRadioModule`

+   `MatChipModule`

+   `MatProgressBarModule`

+   `MatSelectModule`

+   `MatSlideModule`

+   `MatSlideToggleModule`

+   ``MatListModule``

+   `MatDatePickerModule`

+   `MatAutocompleteModule`

+   `MatCheckboxModule`

如前所述，我们可以单独导入这些，或者像在前一节中的`MaterialModule`文件中那样一次性导入所有模块。我们已经在`AppModule`中导入了我们的模块；我们可以开始将表单字段实现到我们的表单中。我们将把每个`input`和`textarea`表单元素包装在一个`<mat-form-field>`包装指令中。为了实现输入文本框，我们将使用`matInput`属性，以及我们的`HTML`输入标签：

```ts
<mat-form-field>
<input matInput placeholder="Enter Email Address" value="">
</mat-form-field>
```

这非常简单明了，对吧？当然。现在，同样地，我们可以轻松地向我们的表单中添加一个`textarea`字段：

```ts
<mat-form-field class="example-full-width">
<textarea matInput placeholder="Enter your comments here"></textarea>
</mat-form-field>
```

好吧，添加`Input`和`Textarea`表单元素并不是什么难事。接下来，我们将实现单选按钮和复选框字段元素：

```ts
 <mat-radio-group>
 <p>Select your Gender</p>
 <mat-radio-button>Male</mat-radio-button>
 <mat-radio-button>Female</mat-radio-button>
 </mat-radio-group>
```

为了在我们的表单中实现单选按钮，我们将使用`<mat-radio-button>`指令。在大多数情况下，我们还将使用多个单选按钮来提供不同的选项。这就是我们将使用`<mat-radio-group>`包装指令的地方。与单选按钮类似，Material 提供了一个指令，我们可以轻松地将复选框集成到我们的应用程序中。我们将使用`<mat-checkbox>`指令如下：

```ts
<mat-checkbox>
    Agree to Terms and Conditions
</mat-checkbox>
```

该指令由`MatCheckboxModule`模块提供，并提供了许多属性，我们可以用来扩展或处理数据。

为了在我们的表单中实现下拉选项，我们需要使用 HTML 的`<select>`和`<option>`标签。Material 库提供了我们可以轻松使用的指令，以扩展我们表单的功能：

```ts
<mat-form-field>
Select City
<mat-select matNativeControl required>
 <mat-option value="newyork">New York City</mat-option>
 <mat-option value="london">London</mat-option>
 <mat-option value="bangalore">Bangalore</mat-option>
 <mat-option value="dallas">Dallas</mat-option>
</mat-select>
</mat-form-field>
```

在前面的代码中，为了使用`<select>`和`<option>`标签，我们将使用`<mat-select>`和`<mat-option>`指令。我们在这里取得了很好的进展。让我们保持这种势头。我们要实现的下一个表单字段元素是滑块组件。

当用户想要指定起始值和结束值时，滑块可以非常有帮助。当用户可以开始浏览范围并且数据根据所选范围进行过滤时，它可以改善用户体验。要向我们的表单添加滑块，我们需要添加`<mat-slider>`指令：

```ts
<mat-form-field>
Select Range
<mat-slider></mat-slider>
</mat-form-field>
```

那很简单。`MatSliderModule` API 提供了许多选项，以便以许多有用的方式扩展和使用指令。我们可以指定最大和最小范围。我们可以设置间隔值，等等。谈到 UI 中的滑块功能，有一个组件可以使用，称为滑动切换。我们可以使用`<mat-slide-toggle>`指令来实现滑动切换：

```ts
 <mat-slide-toggle>Save Preferences</mat-slide-toggle>
```

我们使用了`MatSlideToggleModule`模块提供的`<mat-slide-toggle>`指令。该 API 提供了许多属性，例如`dragChange`、`toggleChange`、根据需要设置颜色或验证等。

现在我们已经在模板文件中放置了所有前面的表单字段元素，让我们运行应用程序以查看输出。使用`ng serve`命令运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/50f8506a-1761-4ec3-965a-cde69e7e0120.png)

在下一节中，我们将学习由 Angular Material 提供的按钮和指示器组件。

# 按钮和指示器

这里有一个小小的趣闻——你见过没有任何按钮的网站或应用程序吗？如果有的话，请写信给我。

就我的经验而言，按钮是 Web 应用程序的一个组成部分。在本节中，我们将学习有关按钮、按钮组和指示器的所有内容。

Angular Material 提供了许多有用且易于附加到按钮标签的属性，然后，神奇发生了。开始使用 Angular Material 按钮的最简单方法是将`mat-button`属性添加到`<button>`标签中：

```ts
<div>
<button mat-button>Simple Button</button>
<button mat-button color="primary">Primary Button</button>
<button mat-button color="accent">Accent Button</button>
<button mat-button color="warn">Warn Button</button>
<button mat-button disabled>Disabled</button>
<a mat-button routerLink=".">Link</a>
</div>
```

在上述代码中，我们为添加到`material-button.component.html`模板文件中的所有按钮添加了`mat-button`属性。我们还使用了`color`和`disabled`等属性来自定义按钮的外观和行为。上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/cf352d5c-b16c-4dea-b9b9-7110f6ca895b.png)

上述截图中的按钮看起来更像链接而不是按钮，对吧？让我们自定义它们，使它们看起来更像按钮。我们可以通过添加`mat-raised-button`属性来轻松实现这一点。请注意，在上一个示例中，我们使用了`mat-button`属性，在这个示例中，我们添加了`mat-raised-button`。更新后的代码如下：

```ts
<div>
  <button mat-raised-button>Basic Button</button>
  <button mat-raised-button color="primary">Primary Button</button>
  <button mat-raised-button color="accent">Accent Button</button>
  <button mat-raised-button color="warn">Warn Button</button>
  <button mat-raised-button disabled>Disabled Button</button>
  <a mat-raised-button routerLink=".">Link</a>
</div>
```

上述代码的输出如下。请注意，现在添加了新属性后，按钮的外观和感觉有所不同：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/b38f8db1-2cea-4752-b7b4-38a0159cff3d.png)

这些是漂亮的按钮！使用预定义的属性可以让我们在整个应用程序中保持按钮的统一性。

接下来，我们将探索 Angular Material 提供的指示器。作为指示器组件的一部分，我们将学习徽章和进度条组件。

徽章是突出显示一些数据以及其他 UI 元素的一种方式。我们可能会遇到一些使用案例，希望在按钮上使用徽章。你可能已经在想，我们是否也可以为按钮添加一些 UX 来设计一些功能呢？是的，我们可以！

Angular Material 提供了一个名为`MatBadgeModule`的模块，其中包含了`matBadge`、`matBadgePosition`和`matBadgeColor`属性的实现，可以轻松地用于设置按钮的徽章。看一下以下示例代码：

```ts
<button mat-raised-button color="primary"
 matBadge="10" matBadgePosition="before" matBadgeColor="accent">
 Left Badge
</button>
```

在上述代码中，我们添加了一个按钮元素，并指定了属性，如`matBadge`、`matBadgePosition`和`matBadgeColor`。上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/c852e365-4b85-4b14-89d8-9bdb9817a597.png)

这是一个带徽章的按钮。还有另一个名为 chips 的 UI 组件。我们也可以轻松使用这些来增强 UX。将 Material chips 想象成之前使用过的任何其他应用程序中的*标签*。Angular Material 提供了一个名为`MatChipModule`的模块，其中提供了`<mat-chip-list>`和`<mat-chip>`指令，我们可以轻松地集成到我们的应用程序中。看一下以下示例代码：

```ts
<mat-chip-list>
<mat-chip color="primary" selected>New York</mat-chip>
<mat-chip>London</mat-chip>
<mat-chip>Dallas</mat-chip>
<mat-chip>Accent fish</mat-chip>
</mat-chip-list>
```

在前面的代码中，我们使用了从`MatChipModule`中得到的指令，并将标签组合在一起。前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/469aa4f0-551d-46f9-b52a-dbeabb2312a6.png)

很好。我们将学习实现的下一个指示器是非常重要的；进度条。我们需要向用户显示并告知正在后台执行的操作，或显示处理某些用户数据的进度。在这种情况下，我们需要清楚地使用进度条来显示这一点。

Angular Material 提供了名为`MatProgressBarModule`和`MatProgressSpinnerModule`的模块，使用这些模块，我们可以轻松地向我们的 Web 应用程序添加加载图标或旋转器。使用 API 属性和事件，我们还可以轻松地捕获和处理数据。看一下以下示例代码：

```ts
<mat-spinner></mat-spinner>
```

就这样？真的吗？我们在开玩笑吗？不，我们不是。只需使用这个模块，我们应该在我们的应用程序中看到旋转的轮子。看一下前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/68f67a97-e278-4a6a-9539-937327e36fa2.png)

在下一节中，我们将学习 Angular Material 提供的所有有关模态窗口和对话框窗口的信息。

# 弹出窗口和模态窗口

现代 Web 应用程序引入了许多创新的 UX 功能和功能。一个真正突出的功能必须是模态窗口。打开任何主要的 Web 应用程序；它都会有一些模态窗口的实现。Angular Material 库也为我们提供了一种轻松实现模态或对话框弹出窗口的方法。

Angular Material 有一个名为`MatDialogModule`的模块，它提供了我们可以在组件类中使用的各种类。与其他 UI 组件不同，没有指令可以直接在模板文件中使用；相反，我们需要以编程方式实现此功能。在我们开始创建对话框窗口实现之前，我们将需要一个组件来存储模态窗口内容。运行以下命令并生成一个组件。让我们称之为`addDialog`组件：

```ts
ng g c addDialog
```

当命令成功执行时，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/70d10286-0b19-48e2-b30c-233f38def789.png)

现在，打开新创建的`add-dialog.component.html`文件，并添加一些内容。即使现在只是*Hello World*也可以。

接下来，让我们开始修改我们的`MaterialModalComponent`类，并将以下代码添加到其中：

```ts
import { Component, OnInit, Inject} from '@angular/core';
import { VERSION, MatDialogRef, MatDialog} from '@angular/material';
import {AddDialogComponent} from '../add-dialog/add-dialog.component';

@Component({
 selector: 'app-material-modals',
 templateUrl: './material-modals.component.html',
 styleUrls: ['./material-modals.component.scss']
})
export class MaterialModalsComponent implements OnInit {

constructor(private dialog: MatDialog) { }

ngOnInit() { }

openDialog() {
 const dialogRef = this.dialog.open(AddDialogComponent);
 }
}
```

让我们分析前面的代码。我们将所有所需的模块导入到文件中。然后我们将`VERSION`，`MatDialogRef`和`MatDialog`导入到我们的组件类中。我们还导入了`AddNewComponent`，我们希望在模态窗口中显示它。由于我们在类中导入了`MatDialog`，我们需要将其注入到我们的构造方法中，然后创建一个实例。然后我们将创建另一个名为`openDialog`的方法。在这个方法中，通过使用`MatDialog`实例，我们调用 open 方法并将`AddNewComponent`作为参数传递。我们已经实现了模态窗口的功能，但在实际调用`openDialog`方法之前，这不会起作用。

因此，让我们打开我们的`material-modal.component.html`模板文件，并在其中添加以下行：

```ts
<button mat-raised-button (click)="openDialog()">Pick one</button>
```

这里没有太多要描述的。我们只是添加了一个按钮，并附加了一个`onclick`事件，以便调用`openDialog`方法：简单而甜蜜。让我们使用`ng serve`命令运行应用程序，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/82648a01-8f32-4ba5-9ff1-f0da8ca80696.png)

在我的`AddDialogComponent`中，我添加了一些文本和一个按钮。您也可以添加或设计自己的模板。API 提供了许多属性和事件，我们可以与对话框窗口关联起来。

在下一节中，我们将学习 Angular Material 提供的数据表功能。

# 数据表

表格是设计复杂的登录后屏幕功能的关键方面之一。我说在登录屏幕后面，因为这样，搜索引擎优化的争论就不会出现。传统表格的问题在于我们需要自己映射数据、行和列，并实现分页和响应性。多亏了 Angular Material，我们现在可以用一行命令就能生成所有这些。没错，你没看错——只用一个命令，当我们使用原理图时。运行以下命令，我们应该很快就能准备好我们的数据表：

```ts
ng generate @angular/material:table issueList
```

我们使用`ng`命令来指定我们要从 Angular Material 生成表格的原理图，并且应该在名为`issueList`的新组件中创建它。成功运行命令后，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/e0be43c4-5d3e-4aeb-b5c4-7598cc5a125c.png)

使用`ng serve`命令运行应用程序，并导航到表的路由。我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/4b274d70-640f-435b-a8f4-8b8a7cfe7007.png)

看！我们现在已经准备好使用我们的动态表格了。我们可以自定义数据源的值和需要显示和更新的列，只需使用我们`component`类中的配置。继续尝试一下吧。

# 总结

我们通过为 UI 组件的每个主要类别创建占位符组件来开始本章。这些组件分为各种类别布局、材料卡片、表单控件、导航、按钮和指示器、模态和弹出窗口以及表格。

我们首先创建了导航菜单组件。我们学习了如何使用原理图自动生成导航菜单组件。然后，我们还学习了如何为我们的应用程序实现自定义菜单。接下来，我们开始学习并实现由 Angular Material 提供的布局组件。在布局组件中，我们了解了 Material 卡片。我们学习了如何在 Material 卡片中包含各种内容。我们了解了 Material 支持的各种列表。我们了解了带有分隔线的列表和导航列表。我们还学习了如何实现手风琴和扩展面板，以更好地对数据进行分组和排列。我们还探索了如何使用步进器组件，在设计需要各种步骤的数据的 UX 时非常有用。同样，我们学习了如何使用选项卡来对事物进行分组。

接下来，我们探索了 Material 表单，并学习了如何实现表单字段元素，包括输入、文本区域、单选和复选按钮、滑块和滑动切换。我们还学习了 Material 提供的不同类型的按钮和指示器，包括徽章和标签。然后，我们了解并实现了由 Angular Material 提供的模态框和弹出窗口。

最后，我们了解了数据表，以及原理图如何帮助我们快速在应用程序中设置数据表。

如果我们想要涵盖 Angular Material 组件的每一个细节，就需要一本单独的书。我们试图为您概述不同的可用组件，以及在下一个项目中为什么您可能考虑使用 Material，并在合适的时候适合您/您的客户。这绝对值得一试！


# 第十章：处理表单

让我们从一个简单的猜谜游戏开始这一章。你能想到任何没有任何形式的网页应用程序，比如注册、登录、创建、联系我们、编辑表单等等；列表是无穷无尽的。（错误答案-甚至 Google 主页上也有一个搜索表单。）

从技术上讲，这是可能的。我 100%确定有一些网站根本不使用表单，但我同样确信它们将是静态的，不会与用户动态交互或互动，这就是本章的主要内容和重点：在我们的 Angular 应用程序中实现和使用表单。

好的，现在让我们来看看本章我们将涵盖的内容：

+   引导表单简介

+   引导表单类

+   引导表单类-扩展

+   角度形式

+   模板驱动表单

+   响应式表单

+   表单验证

+   提交和处理表单数据

# 引导表单

我们将学会使用强大的 Bootstrap 库，它为我们设计和开发应用程序中的表单提供了丰富的类和实用程序，使开发人员和设计人员的生活变得轻松！

# 什么是表单？

表单是一组输入字段的集合，通过键盘、鼠标或触摸输入，使我们能够从用户那里收集数据。

我们将学会将输入元素组合在一起，并构建一些示例表单，比如登录、注册，或者当用户忘记密码时。

在我们开始创建表单之前，这里有一个我们可以在应用程序中使用的可用 HTML 输入元素的快速列表：

+   输入（包括文本、单选框、复选框或文件）

+   文本区

+   选择

+   按钮

+   形式

+   字段集

如果你想快速复习 HTML 标签和元素，你可以访问[W3schools.com](https://www.w3schools.com/)。

掌握了关于表单和可用的 HTML 元素的知识，现在是动手的时候了。

# 引导表单类

在本节中，我们将学习 Bootstrap 框架中可用的类，我们可以在构建表单时使用这些类。每个表单可以包含各种输入元素，如文本表单控件、文件输入控件、输入复选框和单选按钮。`.form-group`类是一种为我们的表单添加结构的简单方法。使用`.form-group`类，我们可以轻松地将输入元素、标签和帮助文本分组，以确保表单中元素的正确分组。在`.form-group`元素内，我们将添加输入元素，并为每个元素分配`.form-control`类。

使用`.form-group`类对元素进行分组的示例如下：

```ts
 <div class="form-group">
 <label for="userName">Enter username</label>
 <input type="text" class="form-control" id="userName" placeholder="Enter username">
 </div>
```

在上述代码中，我们创建了一个包含标签和文本输入元素的表单组。

在同样的线上，我们可以轻松地添加文本输入元素，比如`email`，`password`和`textarea`。以下是添加类型为`email`的输入元素的代码：

```ts
<div class="form-group">
<label for="userEmailAddress">Enter email address</label>
<input type="email" class="form-control" id="emailAddress" placeholder="name@example.com">
</div>
```

同样，我们也可以轻松地添加类型为`password`的输入元素。再次注意，我们正在使用`form-group`作为包装，并将`form-control`添加到元素中：

```ts
<div class="form-group">
<label for="userPassword">Enter password</label>
<input type="password" class="form-control" id="userPassword">
</div>
```

不错。我们学会了在输入元素上使用`form-group`和`form-control`类。现在，让我们将相同的类添加到`textarea`元素上。以下是为`textarea`元素添加类的示例代码：

```ts
<div class="form-group">
<label for="userComments">Example comments</label>
<textarea class="form-control" id="userComments" rows="3"></textarea>
</div>
```

您会注意到所有上述元素都具有相同的结构和分组。对于`select`和`multiple` `select`输入元素，也完全相同。

在以下示例代码中，我们创建了一个`select`下拉元素，并使用了`form-control`类：

```ts
<div class="form-group">
<label for="userRegion">Example select</label>
<select class="form-control" id="userRegion">
<option>USA</option>
<option>UK</option>
<option>APAC</option>
<option>Europe</option>
</select>
</div>
```

我们已经添加了一个`select`下拉元素，并且将允许用户从列表中选择一个选项。只需添加一个额外的属性`multiple`，我们就可以轻松地允许用户选择多个选项：

```ts

<div class="form-group">
<label for="userInterests">Example multiple select</label>
<select multiple class="form-control" id="userInterests">
<option>Biking</option>
<option>Skiing</option>
<option>Movies</option>
<option>Music</option>
<option>Sports</option>
</select>
</div>
```

这很简单明了。让我们继续前进。

现在，让我们继续其他重要的输入元素：复选框和单选按钮。但是，`checkbox`和`radio`元素的类是不同的。

有三个新的类，我们将学习如何为`checkbox`和`radio`元素实现：

+   为了包装元素，我们将使用`form-check`类

+   对于输入类型为`checkbox`和`radio`的元素，我们将使用`form-check-input`

+   对于`checkbox`和`radio`元素，我们需要显示标签，为此我们将使用`form-check-label`类：

```ts
<div class="form-check">
 <input class="form-check-input" type="checkbox" value="" id="Worldwide">
 <label class="form-check-label" for="Worldwide">
 Worldwide
 </label>
</div>
```

在上述代码中，我们使用`.form-check`类，`.form-check-input`和`.form-check-label`来包装我们的`div`和`label`元素。

同样，在类似的线上，我们将使用上述类来添加到输入`radio`元素中：

```ts

<div class="form-check">
 <input class="form-check-input" type="radio" name="gender" id="maleGender" 
    value="option1" checked>
 <label class="form-check-label" for="maleGender">
 Male
 </label>
</div>
<div class="form-check">
 <input class="form-check-input" type="radio" name="gender" id="femaleGender" 
    value="option2">
 <label class="form-check-label" for="femaleGender">
 Female
 </label>
</div>
```

在上述代码中，我们为用户创建了两个单选按钮，以选择他们的性别，并且用户只能在两个选项中选择一个。

在大多数现代 Web 应用程序中，我们需要用户能够上传文件或资源到我们的应用程序。Bootstrap 为我们提供了一个名为"form-control-file"的类，我们可以将其关联到文件上传元素。

我们将使用`form-control-file`类将其应用于我们的输入类型`file`元素。此示例代码如下：

```ts
<div class="form-group">
 <label for="userProfilePic">Upload Profile Pic</label>
 <input type="file" class="form-control-file" id="userProfilePic">
 </div>
```

很好。我们已经学会了如何组合所有元素，从而创建我们美丽而强大的表单。

# Bootstrap 表单类 - 扩展

我们已经学会了创建带有输入元素的表单，并在 Bootstrap 中添加了一些可用的表单类来对元素进行分组，以及改善我们的应用程序。

在本节中，我们将查看 Bootstrap 框架提供的其他附加类和属性，这些类和属性可用于改善用户体验（UX），以及扩展元素的行为：

+   大小

+   只读

+   内联表单

+   使用 Bootstrap 网格类的表单

+   禁用

+   帮助文本

+   `form-group`内的纯文本

我们将逐个讨论上述选项，并学会实现它们并看到它们的效果。

# 大小

我们可以设置表单中输入元素的大小。我们可以使用各种类来控制元素的高度，适用于小、中和大分辨率。

我们已经在上一节中学会了使用`.form-control`类，默认情况下，使用`.form-control-md`类应用了中等大小的高度。还有其他类可用于设置高度为大或小。我们可以分别使用`.form-control-lg`和`.form-control-sm`。

以下是示例代码，我们将使用`.form-control-lg`类将电子邮件地址元素的高度设置为大，并使用`.form-control-sm`类将密码字段设置为小：

```ts
<form>
 <div class="form-group mb-2 mr-sm-2">
   <label for="userEmailAddress">Enter email address</label>
   <input type="email" class="form-control form-control-lg" 
     id="userEmailAddress">
 </div>

 <div class="form-group mb-2 mr-sm-2">
   <label for="userPassword">Enter password</label>
   <input type="password" class="form-control form-control-sm" 
     id="userPassword">
 </div>

<button type="submit" class="btn btn-primary">Submit</button>
</form>
```

我们已将`form-control-lg`和`form-control-sm`类添加到表单控件的电子邮件地址和密码表单元素中，分别。

当我们运行应用程序时，上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/3d8bbef5-a504-4b21-b76e-f3b1feb319b2.png)

在上面的屏幕截图中，请注意输入元素高度的差异。电子邮件地址文本字段的高度增加了，密码字段很小。

# 只读

我们可能会遇到一个使用情况，需要禁用字段并使其只读。我们可以利用属性`readonly`。通过向任何表单控件元素添加布尔`readonly`属性，我们可以禁用该元素。

显示在用户名字段上使用`readonly`属性的示例代码如下：

```ts
<div class="form-group">
 <label for="userName">Enter username</label>
 <input type="text" class="form-control" id="userName" placeholder="E.g 
    packtpub" **readonly**>
 </div>
```

上述代码的输出如下所示。请注意，电子邮件地址字段已禁用，因此用户将无法添加/编辑该元素：

！[](assets/62eecb1f-cbae-4243-aaa2-f676a93b5724.png)

# 内联表单

设计也是我们如何显示表单的同样重要的方面。我们可能会遇到这样的用例，我们需要将我们的表单水平放置，而不是常规的垂直方式。

Bootstrap 有`.form-inline`类来支持内联或水平表单。当使用`.form-inline`类时，表单元素会自动水平浮动。

以下是一些示例代码，我们在其中使用电子邮件地址和密码创建登录表单。我们使用`form-inline`类使其成为内联表单：

```ts
<form class="form-inline">
 <div class="form-group">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control" id="emailAddress" 
    placeholder="name@example.com">
 </div>

 <div class="form-group">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
</form>
```

在上述代码中，需要注意的重要事项是使用`.form-inline`类。

上述代码的输出如下：

！[](assets/2938203b-a18e-44d5-bd43-2958357e0bec.png)

默认情况下，使用 Bootstrap 设计的所有表单都是垂直的。

# 使用 Bootstrap 网格类的表单

还记得我们在第三章中学到的 Bootstrap 网格类吗，*Bootstrap-网格布局和组件*？是的，行、列和设计屏幕布局。

在本节中，我们将学习在表单内部使用相同的行和列网格类，这是一个好消息，因为使用这些类，我们可以设计自定义布局并更新表单的外观。

此示例代码如下：

```ts
<form>
 <div class="row">
 <div class="col">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control" id="emailAddress" readonly>
 </div>
 <div class="col">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
 </div>
</form>
```

在上述代码中，我们不是使用`.form-group`类，而是使用`row`和`col`类，这些类主要用于设计布局。

我们创建一个具有两列的单行，并在每列中添加输入元素。

上述代码的输出如下：

！[](assets/7c02ddc6-166a-4b89-ab2b-8db49242f727.png)

现在是你的作业。尝试使用表单和网格类进行这些有趣的用例：

+   通过向同一行添加更多列 div 元素，可以在同一行中添加更多输入元素

+   向表单添加多行

+   为某些列（第 4 列或第 3 列）分配固定宽度

# 禁用

在开发具有关键和复杂合规要求的 Web 应用程序时，很常见的是我们将不得不根据用户选择禁用某些输入元素。

一个很好的用例是，某些字段不适用于用户选择的特定国家，因此我们需要禁用其他依赖字段。

使用`disabled`属性，该属性接受布尔值，我们可以禁用表单或特定元素。

让我们看看`disabled`属性的作用：

```ts
<form>
 <div class="row">
 <div class="col">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control" id="emailAddress" disabled>
 </div>
 <div class="col">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
 </div>
</form>
```

在上述代码中，我们使用了`disabled`属性。我们可以在以下截图中看到，电子邮件地址字段完全被禁用：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/2c9b895e-8d4e-40eb-a13f-996cf8394c89.png)

我们可以通过向元素添加`disabled`属性来使任何元素被禁用。这很好，但是如果我们想一次性禁用整个表单怎么办？我们也可以做到。

看一下以下代码：

```ts
<form>
 <fieldset disabled>
 <div class="row">
 <div class="col">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control" id="emailAddress">
 </div>
 <div class="col">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
 </div>
 </fieldset>
</form>
```

我们在表单内部添加`fieldset`标签，将表单的所有元素包装在一起，并将`disabled`属性应用于`fieldset`元素，这将一次性禁用整个表单。

上述代码的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/cb30d38d-f476-4547-a2fc-023cba555368.png)

# 表单内的帮助文本

任何优秀的 Web 应用程序都将拥有美观而强大的表单，这些表单可以与用户交流，并创造良好的用户体验。

帮助文本是我们通知用户有关表单中任何错误、警告或必填字段的选项之一，以便用户可以采取必要的行动。

看一下以下代码：

```ts
<form>
 <div class="form-group">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control" id="userEmailAddress">
 <small id="userEmailAddressHelp" class="form-text text-danger">
 Email address cannot be blank.
 Email address should be atleast 3 characters
 </small>
 </div>
 <div class="form-group">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
</form>
```

在上述代码中，我们在`<small>`标签内添加文本，并分配`.form-text`类和`.text-danger`。

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/245b42fa-42d2-4938-bdad-f1b4eae474d4.png)

# 将输入元素显示为纯文本

我们可能会遇到这样的要求，我们需要将输入元素显示为纯文本，而不是输入元素。

我们可以通过自定义样式表来简单地实现这一点，或者只需在具有`.form-group`类的元素内使用`.form-control-plaintext`类。

看一下以下代码：

```ts
<form>
 <div class="form-group">
 <label for="userEmailAddress">Enter email address</label>
 <input type="email" class="form-control-plaintext" id="userEmailAddress" 
   placeholder="Enter email address">
 <small id="userEmailAddressHelp" class="form-text text-danger">
 Email address cannot be blank.
 Email address should be atleast 3 characters
 </small>
 </div>
 <div class="form-group">
 <label for="userPassword">Enter password</label>
 <input type="password" class="form-control" id="userPassword">
 </div>
</form>
```

在上述代码中，我们已经将`.form-control-plaintext`类添加到输入元素中。

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/1920ea3b-d4f6-4786-a2cc-93d0ee5417e5.png)

在本节中，我们已经了解了各种类和属性，我们可以使用它们来增强和使我们的表单更具交互性和强大性，最重要的是，为更好的用户设计和体验增添内容。

# Angular 表单

在本节中，Angular 应用程序中的表单真正发挥作用。表单是任何应用程序的核心，也是收集、查看、捕获和处理用户提供的数据的主要构建块。在本节中，我们将继续使用 Bootstrap 库来增强我们表单的设计。

Angular 提供了两种不同的方法来构建应用程序内的表单。

Angular 提供的构建表单的两种方法如下：

+   模板驱动表单：HTML 和数据绑定在模板文件中定义

+   使用模型和验证在`Component`类文件中的响应式或模型驱动表单

尽管表单模型是模板驱动表单和响应式表单之间的共同点，但它们的创建方式不同。

当涉及到模板时，响应式表单和模板驱动表单的主要区别在于数据绑定。在模板驱动表单中，我们使用双向数据绑定将我们的数据模型直接绑定到表单元素。另一方面，使用响应式表单时，我们将我们的数据模型绑定到表单本身（而不是其各个表单元素）。

我们将详细探讨这些方法，了解这些方法的利弊，最后，我们将使用这两种方法构建一些表单。让我们开始吧。

# 模板驱动表单

模板驱动表单，顾名思义，涉及表单的所有繁重工作都在组件模板中进行。这种方法很好，建议在处理简单、直接的表单时使用，而不涉及太多复杂的验证或规则。

所有逻辑都在模板文件中，这基本上意味着我们将利用 HTML 元素和属性。在模板驱动的表单中，我们使用 HTML 来创建表单和输入元素，并将验证规则创建为 HTML 属性。双向数据绑定是关键部分，因此我们可以将表单元素与`Component`类中的属性绑定起来。

Angular 会自动生成表单模型，自动跟踪表单和输入元素的状态供我们使用。我们可以直接将表单作为对象并轻松处理数据。

在使用模板驱动方法时，我们首先导入`FormsModule`，这样我们就可以访问以下指令：

+   `ngForm`

+   `ngModel`

+   `ngModelGroup`

我们需要将`FormsModule`导入到我们的`app.module.ts`文件中。

让我们来看看在我们的应用程序中使用模板驱动表单方法的利弊。

# 模板驱动表单-优点

如果我们应用程序中的表单简单直接，没有太多元数据和验证，模板驱动表单可以非常有用和有帮助。在本节中，我们将强调在我们的应用程序中使用模板驱动表单的优点：

+   模板驱动表单非常容易使用

+   适用于简单和直接的用例

+   易于使用的双向数据绑定，因此代码和复杂性很少

+   Angular 自动跟踪表单和输入元素的状态（如果表单状态不完整，则可以禁用提交按钮）

+   如果表单具有复杂的表单验证或需要自定义表单验证，则不建议使用

# 基于模板的表单 - 缺点

在前一节中，我们已经了解了在应用程序中使用基于模板的表单的优势，并且我们已经就使用基于模板的表单方法的优点进行了充分论证。在本节中，我们将了解在我们的应用程序中使用基于模板的表单的一些缺点：

+   不建议或适用于表单要求复杂且包括自定义表单验证的情况

+   无法完全覆盖单元测试以测试所有用例

# 基于模板的表单 - 重要模块

掌握了使用基于模板的方法的优缺点的知识，我们将立即深入学习如何在我们的应用程序中实现基于模板的表单。我们将首先学习所需的模块，然后逐渐创建我们应用程序中的表单。如前所述，基于模板的表单大多在模板文件中定义。在我们开始创建基于模板的表单示例之前，我们应该了解与表单相关的一些最重要的概念，即`ngForm`和`ngModel`：

+   `ngForm`：这是一个指令，用于在表单指令内部创建控件组

+   `ngModel`：当在`ngForm`内的元素上使用`ngModel`时，所有元素和数据都会在`ngForm`内注册。 

如果 Angular 表单使用`ngForm`和`ngModel`，这意味着该表单是基于模板的。

# 构建我们的登录表单

到目前为止，我们对基于模板的表单有了一个很好的高层次理解。在本节中，我们将把我们的知识付诸实践，通过构建一个表单来实现。让我们使用我们在前一节中学到的类来组合一个表单。

我们将处理的用例是我们应用程序的用户登录表单。首先，我们需要生成我们的登录组件。运行以下`ng`命令以生成登录组件：

```ts
ng g c login
```

前面命令的输出如下所示：

我们需要在`app-routing.module.ts`文件中添加我们的路由路径，以便访问`login`和`register`的路由。

我们正在使用模板驱动方法构建我们的表单，因此我们需要在我们的模板文件中做大部分工作。在开始修改我们的模板文件之前，我们需要将一个必需的模块导入到我们的`app.module.ts`文件中。

打开`app.module.ts`文件并添加以下代码行：

```ts
import {FormsModule} from '@angular/forms';
```

一旦我们将`FormsModule`导入到我们的`app.module.ts`文件中，不要忘记将其添加到`ngModule`内的导入列表中。

更新后的`app.module.ts`文件显示如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/98682a79-39dc-4a24-a378-83d38e562d8c.png)

现在，让我们打开我们的登录组件模板文件，并在`login.component.html`文件中创建我们的登录表单。以下是我们将添加到模板文件中的代码：

```ts
<form #loginForm="ngForm" (ngSubmit)="login(loginForm.value)">
 <h3 class="text-center text-primary">Login</h3>
 <div class="form-group">
 <label for="username">Username:</label><br>
 <input type="text" [ngModel]="username" name="username" 
    class="form-control">
 </div>
 <div class="form-group">
 <label for="password">Password:</label><br>
 <input type="password" [ngModel]="password" name="password" 
   class="form-control">
 </div>

<button type="submit" class="btn btn-primary">Sign in</button>

 </form>
```

让我们深入分析上述代码。我们正在使用 HTML 输入元素创建一个表单，并向表单添加用户名、密码和提交按钮。需要注意的重要事项是，对于表单本身，我们告诉模板表单是`ngForm`，`ngForm`将把表单的所有输入元素组合到`#loginForm`模板变量中。对于输入元素，我们添加了`ngModel`属性，并为元素指定了`name`属性。

使用`ngForm`，我们现在可以轻松地检索表单内元素的值。由于我们已经定义了本地`#loginForm`模板变量，我们现在可以轻松地使用它的属性。`loginForm`具有以下属性：

+   `loginForm.value`：返回包含表单内所有输入元素值的对象

+   `loginForm.valid`：根据模板中应用的 HTML 属性验证器返回表单是否有效

+   `loginForm.touched`：根据用户是否触摸/编辑表单返回`true`或`false`

在上述代码中，我们将`loginForm.value`传递给组件。我们可以将任何这些值传递给组件进行处理或验证。请注意，我们还调用了一个`login`方法，我们需要在我们的`Component`类文件中实现它。

现在，让我们在我们的`Component`类中创建一个方法来捕获来自我们的`loginForm`的数据。我们正在收集表单的值并在控制台中显示它：

```ts
import { Component, OnInit } from '@angular/core';
@Component({
 selector: 'app-login',
 templateUrl: './login.component.html',
 styleUrls: ['./login.component.scss']
})
export class LoginComponent {

constructor() { }

login(loginForm) {
 console.log(loginForm);
 console.log(loginForm.controls.username);
}
}
```

使用`ng serve`命令运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/e298edd1-6fd2-426f-ba2e-e99c4e4c88d7.png)

记住，在典型的服务器端脚本中，我们过去常常为表单编写`action`和`method`属性。现在我们不需要再定义这些，因为它们在`Component`类中已经声明和使用了。

这是很好的东西和很好的进展。我们将继续使用前面的登录表单，并很快添加验证。让我们继续深入了解更多信息。

# 基于模型驱动的表单，或者叫做响应式表单

响应式表单也被称为基于模型驱动的表单。在基于模型驱动的表单中，模型是在`Component`类文件中创建的，并负责进行表单验证、处理数据等等。

Angular 在内部构建了 Angular 表单控件的树结构，这样更容易在数据模型和 UI 元素之间推送和管理数据。

我们需要在`Component`类中构建表单模型，通过创建构建块的实例（即`FormControl`和`FormGroup`）来实现。此外，我们还在类中编写验证规则和验证错误消息。我们甚至在类中管理属性（即数据模型），而不是在 HTML 中使用数据绑定。

模板驱动的表单将表单的责任放在模板上，而响应式表单将验证的责任转移到`Component`类上。

在本章中，我们将同时使用这两个术语：基于模型驱动的表单和响应式表单，因为它们都指代同一件事情。

# 基于模型驱动的表单 - 优点

响应式表单在我们的应用程序中创建、验证和应用自定义表单验证非常有用。我们可以轻松地信任基于模型驱动的方法来完成通常与任何复杂表单相关的繁重工作。在本节中，我们将列出并了解在我们的应用程序中使用基于模型驱动的表单的优点：

+   更灵活，适用于更复杂的验证场景和自定义复杂表单验证

+   数据模型是不可变的

+   由于数据模型是不可变的，所以不进行数据绑定

+   使用表单数组动态添加输入元素更容易（例如，在任务表单上添加子任务）

+   使用`HostListener`和`HostBindings`很容易将各种事件绑定到输入元素

+   所有表单控件和验证的代码都在组件内部，这样模板会更简单、更易于维护

+   更容易进行单元测试

# 基于模型驱动的表单 - 缺点

生活中所有美好的事物都有一些缺点。响应式表单也不例外。虽然使用响应式表单的优点和优势肯定可以超过缺点，但学习和理解在应用程序中使用响应式表单的缺点仍然很重要。在本节中，我们将列出在应用程序中使用模型驱动表单的缺点：

+   初学者可能会觉得初始学习曲线太高

+   开发人员应该了解与模型驱动表单一起使用所需的各种模块，比如`ngvalidators`等等

# 模型驱动表单 - 重要模块

我们使用 Angular 提供的两个强大类`formGroup`和`formControl`来创建模型：

+   `FormControl`：跟踪单个表单输入元素的值和状态

+   `FormGroup`：跟踪一组表单控件的值和状态

+   `FormBuilder`：帮助我们使用它们的初始值和验证开发表单

就像我们在模板驱动表单中导入了`FormsModule`一样，我们需要在`app.module.ts`文件中导入`ReactiveFormsModule`。

更新后的`app.module.ts`文件应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/34059900-9e37-43f3-8b5d-638d8585057b.png)

掌握了关于模型驱动表单方法的所有知识，现在是进行实际示例的时候了。

# 响应式表单 - 注册表单示例

在上一节中，我们在讲解模板驱动表单时，为我们的应用程序创建了登录表单。现在是使用响应式表单进行实际练习的时候了。使用不同方法实现登录和注册表单的基本想法是向您展示每种方法的实现差异。没有正确或错误的方法，决定是由应用程序中表单的复杂性和要求驱动的。

在本节中，我们将学习使用模型驱动方法实现我们的新用户注册表单。

首先，我们需要生成我们的`register`组件。运行以下`ng`命令来生成`register`组件：

```ts
ng g c register
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/c044b603-8c86-4bd8-80e7-3012fdba4c7b.png)

因为我们正在谈论模型驱动表单，所有的辛苦工作都必须在`Component`类中完成。我们仍然需要为我们的响应式表单准备一个模板，但我们不会在模板中添加任何验证或数据绑定。

我们希望我们的注册表单有四个表单元素，即全名、电子邮件地址、密码和条款与条件的字段。

让我们更新`register.component.ts`文件中的`Component`类，并创建一个`formGroup`实例：

```ts
import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent implements OnInit {

registerForm = new FormGroup({
  fullName: new FormControl(),
  emailAddress: new FormControl(''),
  password: new FormControl(''),
  termsConditions: new FormControl('')
 });
 constructor() { }

 ngOnInit() {
 }

 register()
 {
     console.log(this.registerForm.value);
 }

}
```

您会注意到在上面的代码中有很多新东西。让我们慢慢来，一步一步地。我们正在从`angular/core`中导入所需的模块`FormGroup`和`FormControl`。在`Component`类内部，我们正在创建`FormGroup`类的一个实例`registerForm`。您会注意到我们现在正在创建多个`FormControl`实例，每个实例都是我们想要添加到我们的表单中的一个表单元素。

这就是我们需要做的全部吗？目前是的。请记住，如前所述，响应式表单也需要一个基本模板，但所有的逻辑和验证将在组件内部，而不是模板文件中。

现在，让我们更新我们的模板文件。在`register.component.html`文件中，添加以下代码：

```ts
<div>
   <form [formGroup]="registerForm" (ngSubmit)="register()">
 <h3 class="text-center text-primary">New User Registration</h3>
   <div class="form-group">
 <label for="fullName">Your Name</label><br>
   <input type="text" formControlName="fullName" class="form-control">
 </div>
 <div class="form-group">
 <label for="emailAddress">Enter Email Address:</label><br>
   <input type="text" formControlName="emailAddress" class="form-control">
 </div>
 <div class="form-group">
 <label for="password">Password:</label><br>
 <input type="password" formControlName="password" class="form-control">
 </div>
 <div class="form-group">
 <div class="form-check">
 <input class="form-check-input" type="checkbox" 
    formControlName="termsConditions" id="defaultCheck1">
 <label class="form-check-label" for="defaultCheck1">
 I agree to Terms and Conditions
 </label>
 </div>
 </div>
 <button type="submit" class="btn btn-primary">Sign in</button>

 </form>
</div>
```

在上面的代码中，我们正在创建一个动态的响应式表单。在上面的代码中，有许多重要的概念我们需要理解。我们在基于模型的表单中使用`FormGroup`属性。在基于模板的表单中，我们使用`ngForm`。请注意，对于每个表单元素，我们都提到了`FormControlName`属性，而此属性的值必须与在`FormControl`实例声明期间在`Component`类中提到的值完全相同。暂停一下，再读一遍最后几句话。

我们不再需要为元素提及`ngModel`，因为数据绑定已经紧密耦合在`Component`类本身内。我们还附加了一个`ngSubmit`事件，它将调用组件内实现的`register`方法，以在控制台上打印表单值。

太棒了。就是这样。现在使用`ng serve`命令启动您的应用程序，我们应该看到如下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/36bf4dd1-b7ec-4f94-baef-76a3565cc72e.png)

恭喜您使用 Angular 提供的方法成功启动并运行您的表单。我们已经学会了使用基于模板和基于模型的方法构建表单。在接下来的部分，我们将学习通过添加验证和自定义规则来扩展它们。

# Angular 表单验证

到目前为止，我们已经了解到表单对于我们所有的应用程序是多么重要和关键。由于我们将处理来自用户的数据，确保我们接收到的数据是正确和有效的非常重要。

例如，当我们期望用户输入电子邮件地址时，我们不应该允许在电子邮件地址中输入空格或一些特殊字符。再举一个例子，如果我们要求用户输入电话号码，电话号码不应该超过 10 位数（当然不包括国家代码）。

我们可能希望在我们的表单中有许多这样的自定义有效检查点。

在本节中，我们将继续使用登录表单和注册表单，学习如何在模板驱动表单和模型驱动表单中添加验证。

# 模板驱动表单验证

打开我们使用模板驱动方法开发的登录表单。请记住，在模板驱动表单中，验证是在模板本身使用 HTML 属性进行的。

我们可以使用任何 HTML 属性，例如 required、`maxlength`、`minlength`、`size`、`email`、`number`、`length`等，在表单中进行验证。我们还可以利用 HTML 模式属性在我们的表单元素中进行正则表达式检查。

我们可以利用各种类来实现表单验证：

+   `ng-touched`：输入控件已被访问

+   `ng-untouched`：输入控件尚未被访问

+   `ng-dirty`：输入控件数据已更改

+   `ng-pristine`：输入控件数据尚未更改/更新

+   `ng-valid`：输入控件数据是有效的，并使表单有效

+   `ng-invalid`：输入控件数据无效，因此表单无效

在模板驱动的表单中，Angular 会自动跟踪每个输入元素的状态以及表单的状态。因此，我们也可以在我们的 CSS/SCSS 中使用上述类来设计我们的错误通知，例如：

```ts
input.ng-invalid {
 border:2px solid red;
}
```

好了，现在我们已经了解了模板驱动表单中的验证，是时候更新我们的登录表单组件并使其更加时尚。我们将通过向表单元素添加验证来更新`login.component.html`文件。

```ts
<div>
 <form #loginForm="ngForm" (ngSubmit)="login(loginForm.value)">
 <h3 class="text-center text-primary">Login</h3>
  <div class="form-group">
 <label for="username">Username:</label><br>
  <input type="text" ngModel #username="ngModel" name="username" 
      placeholder="Enter username" required class="form-control">
  <span class="text-danger" *ngIf="username.touched && !username.valid"> 
     enter username </span>
 </div>
 <div class="form-group">
 <label for="password">Password:</label><br>
 <input type="password" [ngModel]="password" name="password" 
     required minlength="3" class="form-control">
 </div>
 <button type="submit" class="btn btn-primary" [disabled]="!loginForm.valid">
    Sign in</button>

 </form> 
</div>
```

让我们仔细看一下上面的代码。我们扩展了之前创建的登录表单。请注意，对于用户名表单控件，我们有 HTML 属性`required`，它将设置在表单控件上。如果用户没有为该字段输入任何值并且离开了该字段的焦点，使用`ngIf`条件，我们正在检查用户是否触摸了该字段，并且如果值无效，我们将显示错误消息。对于`password`字段，我们设置了其他 HTML 属性，如`required`和`minlength`验证检查。如果表单控件数据无效，我们不应该启用表单，对吧？这就是我们通过向提交按钮添加`disabled`属性来做的。

现在让我们使用`ng serve`命令运行应用程序，我们应该看到输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/fcbb84dd-9730-4111-9b1e-51c29bdaef9b.png)

对于您的作业，请尝试在模板驱动表单中尝试这些用例：

+   为用户名表单元素添加最小和最大长度

+   添加一个新的表单元素，并添加验证，它应该是电子邮件格式

# 响应式表单或模型驱动表单验证

到目前为止，我们实现的所有验证都只是在模板文件中使用基本的 HTML 属性。在本节中，我们将学习如何在组件中使用模型驱动表单实现验证。

在之前的章节中，我们已经学会了在我们的`Component`类中使用`formControl`和`formGroup`类创建表单。我们将继续使用相同的注册表单来扩展和实现验证。

我们通过在`register.component.ts`文件中添加验证来为我们的组件添加验证代码。看一下我们将在文件中添加的代码：

```ts
import { Component, OnInit } from '@angular/core';
import { FormGroup, Validators, FormControl } from '@angular/forms';

 @Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent implements OnInit {
 registerForm = new FormGroup({ 
   fullName: new FormControl('',[Validators.required, 
   Validators.maxLength(15)]), emailAddress: 
   new FormControl('',[Validators.pattern('[a-zA-Z]*')]),
   password: new FormControl('',[Validators.required]),
   termsConditions: new FormControl('',[Validators.required])
 });

 constructor() { }

 ngOnInit() {
 }

 register()
 {
   console.log(this.registerForm.value);
 }
}
```

在上述代码中，您会注意到我们已经将所需的模块`FormGroup`、`FormControl`和`Validators`导入到我们的`Component`类中。我们已经导入并使用了`FormGroup`和`FormControl`。`Validators`模块是我们现在导入的唯一额外模块。我们将验证器作为选项传递给`FormControl`。对于`fullname`，我们将验证器添加为`required`和`maxLength`。请注意，我们可以为每个`FormControl`传递多个验证器。同样，对于电子邮件地址表单控件，我们正在传递一个验证器模式，其中包含正则表达式检查。我们已经在我们的组件中进行了所有必要的更改和验证。

现在是时候更新我们的模板`register.component.html`文件了：

```ts
<div>
   <form [formGroup]="registerForm" (ngSubmit)="register()">
<h3 class="text-center text-primary">New User Registration</h3>
   <div class="form-group">
<label for="fullName">Your Name</label><br>
<input type="text" formControlName="fullName" class="form-control">
</div>
<div class="form-group">
<label for="emailAddress">Enter Email Address:</label><br>
   <input type="text" formControlName="emailAddress" class="form-control">
</div>
<div class="form-group">
<label for="password">Password:</label><br>
<input type="password" formControlName="password" class="form-control">
</div>
<div class="form-group">
<div class="form-check">
<input class="form-check-input" type="checkbox" formControlName="termsConditions" id="defaultCheck1">
<label class="form-check-label" for="defaultCheck1">
I agree to Terms and Conditions
</label>
</div>
</div>
<button type="submit" class="btn btn-primary" [disabled]="!registerForm.valid">Sign in</button>

</form>
</div>
```

HTML 模板与我们之前为我们的基于模型的表单创建的模板相同。我们为表单添加了一些功能。请注意，我们在提交按钮上添加了`disabled`属性，如果任何表单元素为空或无效，它将禁用表单。

看，我告诉过你，我们的模板文件只是一个占位符，几乎所有的操作都发生在我们的`Component`类中。

现在，让我们使用`ng serve`命令来启动应用程序，我们应该看到输出，就像下面的截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-ng-bts-3e/img/419a17df-99f3-4481-b97f-2cd8ebb1483a.png)

如果你看到了前面的截图，就跳到你的桌子上。因为我们现在已经学会并实现了使用模板驱动和基于模型的方法来创建表单。

如果你在整个章节中注意到了我们涵盖的示例，你也会注意到我们创建了处理表单数据的方法。

在下一节中，我们将专门关注这一点，并学习一些处理表单数据的最佳实践。

# 提交表单数据

到目前为止，我们已经学会了在我们的应用程序中设计和开发我们的表单。在本节中，我们将把事情带到下游系统，即捕获数据并处理数据。

Angular 在这两种方法中都生成了一个表单模型，无论是模板驱动表单还是响应式表单。表单模型保存了表单元素的数据和状态。

在之前的章节中，我们已经创建了一个方法来调用`ngSubmit`。

对于我们的模板驱动登录表单，我们在`login.component.ts`文件中添加了以下代码：

```ts
login(loginForm)
{
  console.log(loginForm);
  console.log(loginForm.username);
}
```

我们将整个表单对象传递给登录方法。现在`loginForm`对象将包含表单控件的所有细节，以及状态。

在我们的注册表单中，我们使用了基于模型驱动的方法生成的实例`formGroup`，这个实例是在我们的`Component`类`register.component.ts`文件中创建的。

以下是我们添加的用于捕获和处理数据的代码：

```ts
register()
 {
   console.log(this.registerForm.value);
 }
```

如果你注意到，对于响应式表单，我们不需要传递任何表单数据，因为我们已经创建了`FormGroup`的`registerForm`实例，所以它可以在我们的类中使用`this`运算符来访问。

一旦我们捕获了用户提供的数据，根据应用程序的要求，我们现在可以在组件内部实现我们的自定义逻辑。

一旦我们捕获数据，我们进行的一些常见活动如下：

+   保护数据，以确保我们不允许垃圾数据进入我们的系统。

+   处理/增强数据，例如将密码转换为加密值。

+   检查是否有任何自动化机器人处理我们的应用程序。

+   使用 Angular 服务向后端服务发出 HTTP 调用。我们有一个专门讨论这个特定主题的章节：第十二章，*集成后端数据服务*。

这就结束了关于 Angular 表单的章节。我们涵盖了很多内容，我相信此时您一定会很兴奋地创建自己的表单，编写自定义验证并处理捕获的数据。

# 总结

表单是任何良好应用程序的核心和灵魂。我们首先学习了 Bootstrap 库提供的出色类和实用工具。我们详细探讨了`form-group`和`form-control`类。我们学习并实现了各种辅助和附加属性，以使我们的表单看起来和行为更好。

我们通过学习 Angular 提供的两种方法，即基于模板的表单和基于模型的表单，深入研究了 Angular 表单。

我们详细了解了每种方法的优缺点，并使用每种方法创建了我们的登录和注册表单。我们还探讨了我们在基于模板的表单和响应式表单中使用的各种类型的验证。

最后，但同样重要的是，我们学习了如何处理我们从表单接收到的表单数据。现在是时候展翅飞翔，创建您自己的精彩表单了。

在开发具有多个开发人员的复杂应用程序时，情况可能会失控。幸运的是，Angular 支持依赖注入和服务，这使我们能够创建可重用的服务并定义接口类。我们可以定义新的数据类型，并确保所有团队成员在不破坏彼此功能的情况下推送代码。我们将如何实现这一点？这将在下一章中介绍。继续阅读！
