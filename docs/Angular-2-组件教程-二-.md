# Angular 2 组件教程（二）

> 原文：[`zh.annas-archive.org/md5/D90F9C2E423CFD3C0CE82E57CF69A28E`](https://zh.annas-archive.org/md5/D90F9C2E423CFD3C0CE82E57CF69A28E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：集成第三方组件

有许多使用其他库构建的 UI 组件，我们可能想在我们的 Angular 2 应用程序中使用。在本章中，我们将集成来自流行的 bootstrap 库的 tooltip 小部件。

导入 bootstrap 和 jQuery 库是我们在本章中涵盖的主题。

# 准备我们的开发环境

在继续之前，让我们创建一个新项目。打开`app.component.ts`并删除 HTML 模板和 CSS 文件的外部链接：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `<h1>Angular2 components</h1>`
})
export class AppComponent {}
```

# 导入依赖项

由于我们将包装来自 bootstrap 库的组件，我们首先需要下载并导入 bootstrap 库及其依赖项，并将其导入到我们的代码中。第一步是使用`npm`安装`bootstrap`。打开终端，确保你在项目根目录中，然后键入`npm install bootstrap -S`。此命令将下载 bootstrap 文件到`node_modules`并将其写入`package.json`。

由于 bootstrap 依赖于 jQuery 库，我们也需要安装它。我们也将使用`npm`。在终端中，键入`npm install jquery –S`。

我们还需要安装这两个库的相应类型，以便能够编译应用程序。相应类型模块的名称与目标库相同，但带有`@types`前缀。要安装它们，只需使用以下命令：

```ts
**npm install @types/jquery @types/bootstrap --save-dev**

```

`Bootstrap`库的 CSS 文件需要在`angular-cli.json`文件的样式部分中全局配置为应用程序：

```ts
[angular-cli.json]
{
  "project": {
    "version": "1.0.0-beta.16",
    "name": "ng-components"
  },
  "apps": [
    {
      "root": "src",
      "outDir": "dist",
      "assets": "assets",
      "index": "index.html",
      "main": "main.ts",
      "test": "test.ts",
      "tsconfig": "tsconfig.json",
      "prefix": "app",
      "mobile": false,
      "styles": [
        "styles.css",
        "../node_modules/bootstrap/dist/css/bootstrap.css"
      ],
      "scripts": [
      ],
      "environments": {
        "source": "environments/environment.ts",
        "dev": "environments/environment.ts",
        "prod": "environments/environment.prod.ts"
      }
    }
  ],
  (…)
}
```

由于最新版本的 Angular CLI 依赖于`Webpack`，我们使用其暴露加载器将 jQuery 全局可用于`Bootstrap`库。后者需要这样做以通过添加一组方法（如`tooltip`和`collapse`）来扩展 jQuery。要安装`expose loader`，只需使用以下命令：

```ts
**npm install expose-loader --save-dev**

```

现在我们可以在需要的地方使用`import`子句导入 jQuery 和 Bootstrap。

在继续之前，打开`app.component.ts`并添加以下导入语句以导入 jQuery 和 Bootstrap 库：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import 'expose?jQuery!jquery';
import 'bootstrap';
import * as $ from 'jquery';

@Component({
  selector: 'app-root',
  template: `<h1>Angular2 components</h1>`
})
export class AppComponent {}
```

# Bootstrap tooltip 组件

Angular 2 能够绑定到元素属性和事件，而无需自定义指令，使我们能够轻松集成第三方代码。Bootstrap 使用一些自定义属性来使提示工作。我们可以直接使用它。打开`app.component.ts`并将 bootstrap 属性添加到标题中，以从底部显示提示。我们还需要利用`AfterViewInit`钩子在模板渲染时初始化提示：

```ts
[app.component.ts]
import { Component, AfterViewInit } from '@angular/core';
import 'expose?jQuery!jquery';
import 'bootstrap';
import * as $ from 'jquery';

@Component({
  selector: 'app-root',
  template: `
    <h1 data-toggle="tooltip"
        data-placement="bottom"
        title="A Tooltip on the right">Angular2 components</h1>
  `
})
export class AppComponent implements AfterViewInit {
  ngAfterViewInit() {
    $('h1').tooltip();
  }
}
```

现在，让我们打开浏览器测试一下。将鼠标悬停在标题上，等待提示出现在底部：

![Bootstrap 提示组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00115.jpeg)

现在，让我们将其与 Angular 集成并使其动态化。这个过程很简单。我们可以绑定到我们想要控制的每个属性。让我们从`title`开始。

打开`app.component.ts`并添加以下代码：

```ts
[app.component.ts]
import { Component, AfterViewInit } from '@angular/core';
import 'expose?jQuery!jquery';
import 'bootstrap';
import * as $ from 'jquery';

@Component({
  selector: 'app-root',
  template: `
    <input type="text" [(ngModel)]="title" placeholder="enter custom title..">
    <h1 data-toggle="tooltip"
        data-placement="bottom"
        [title]="title">Angular2 components</h1>
  `
})
export class AppComponent implements AfterViewInit {
  ngAfterViewInit() {
    $('h1').tooltip();
  }
}
```

我们不必在组件类中编写任何代码就能使其工作。打开浏览器，输入一个标题，将鼠标悬停在标题上，看看结果：

![Bootstrap 提示组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00116.jpeg)

# Bootstrap 折叠组件

让我们尝试另一个例子，但这次我们将绑定到事件。对于这个例子，我们将使用 bootstrap 库中的另一个小部件，称为`collapse`。在`components`文件夹中，创建一个名为`collapse`的新文件夹。在其中，为我们的组件创建一个名为`collapse.ts`的文件和一个名为`collapse.html`的`component`模板文件。

打开`collapse.ts`并粘贴以下代码。这是一个折叠小部件的示例，直接从 bootstrap 网站([`getbootstrap.com/javascript/#collapse`](http://getbootstrap.com/javascript/#collapse))中获取：

```ts
[collapse.ts]
import { Component, AfterViewInit } from '@angular/core';
import * as $ from 'jquery';

@Component({
  selector: 'collapse',
  templateUrl: './collapse.html'
})

export class Collapse implements AfterViewInit {
  ngAfterViewInit() {
    $('.collapse').collapse();
  }
}
```

打开`collapse.html`并粘贴以下内容：

```ts
[collapse.html]
<button class="btn btn-primary"
        data-toggle="collapse"
        data-target="#collapseExample"
        aria-expanded="false"
        aria-controls="collapseExample">
  Collapse!
</button>

<div class="collapse"
     id="collapseExample">
  <div class="well">
    Integrating third party is easy with angular2!
  </div>
</div>
```

让我们渲染这个组件。打开`app.component.ts`，导入`collapse`组件，并在模板中使用它，如下所示：

```ts
[app.component.ts]
import { Component } from '@angular/core';
import 'expose?jQuery!jquery';
import 'bootstrap';

@Component({
  selector: 'app-root',
  template: '<collapse></collapse>'
})
export class AppComponent {}
```

不要忘记将`Collapse`类添加到应用程序的根模块的`declarations`属性中，以使`collapse`组件可用，如下所示：

```ts
[app.module.ts]
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';
import { Collapse } from './components/collapse/collapse';

@NgModule({
  declarations: [
    AppComponent,
    Collapse
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

现在，打开浏览器测试折叠事件：

![Bootstrap 折叠组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00117.jpeg)

我们已经知道如何从提示示例中绑定属性。在这个例子中，我们将绑定到折叠事件。

根据 bootstrap 文档，折叠在其生命周期中触发四个事件。我们将专注于其中两个：

+   `show.bs.collapse`：当调用`show`方法时触发此方法。

+   `hide.bs.collapse`：当调用`hide`方法时，此方法将触发。

如果我们想要监听这些事件，我们需要保存对 DOM 元素的引用。为此，我们将注入`ElementRef`。打开`collapse.ts`并添加以下代码：

```ts
[collapse.ts]
import { Component, Inject, ElementRef } from '@angular/core';
import * as $ from 'jquery';

@Component({
  selector: 'collapse',
  templateUrl: './collapse.html'
})
export class Collapse {
  constructor(element: ElementRef) {
    $(element.nativeElement)
      .on('show.bs.collapse', 
      ()=> console.log('handle show event'));
    $(element.nativeElement)
      .on('hide.bs.collapse', 
      ()=> console.log('handle hideevent'));
  } 
}
```

有很多方法可以监听元素上的事件。我们选择使用 jQuery 来包装原生元素，并为折叠注册事件监听器。

您可以打开浏览器并观看控制台中与折叠事件对应的日志：

![Bootstrap 折叠组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00118.jpeg)

# 总结

Angular 2 通过自然地绑定到原生属性，与第三方代码很好地配合。另一方面，如果我们需要保存对 DOM 元素的引用，我们可以在组件中注入`ElementRef`。


# 第九章：Angular 2 指令

在整本书中，我们学习了如何制作 Angular 2 组件。在结束我们的旅程之前，了解 Angular 2 并没有淘汰指令的概念是很重要的。事实上，组件*就是*指令。在本章中，我们将介绍 Angular 2 指令以及如何使用它们。

以下是我们将要涵盖的主题：

+   Angular 2 中组件和指令的区别

+   Angular 2 指令类型

+   如何构建一个简单的属性指令

+   如何构建一个简单的结构指令

# Angular 2 中的组件和指令

到目前为止，我们已经构建了组件。但是组件并没有取代我们从 Angular 1 中熟悉的指令。如果您不熟悉 Angular 1 指令，不用担心，我们将在一分钟内解释区别。

让我们首先定义在 Angular 术语中指令是什么：指令是一个自定义属性或元素，通过添加自定义行为来扩展 HTML 标签。

在 Angular 2 中，我们有三种类型的指令：组件指令，属性指令和结构指令。我们已经熟悉了组件，所以让我们定义其他类型：

+   **属性指令**：这改变了元素的外观或行为。其中一个例子是 Angular 核心中的 NgStyle 指令。

+   **结构指令**：这操纵 DOM，就像 Angular 核心中的 NgFor 和 NgSwitch 一样。

与组件相反，指令不需要模板，并通常将选择器定义为属性。

# 准备我们的开发环境

就像前几章一样，让我们创建一个新项目，如第二章中所述，*使用 angular-cli 设置 Angular 2 开发环境*。您还可以删除所有现有文件夹，并从`app.component.ts`中删除所有不必要的代码：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `<h1>Angular2 components</h1>`
})
export class AppComponent {}
```

# 基本属性指令

让我们开始创建一个名为`text-marker.ts`的新指令文件。在其中，粘贴以下代码：

```ts
[text-marker.ts]
import { Directive, ElementRef, Renderer } from '@angular/core';

@Directive({
  selector: '[text-marker]'
})
export class TextMarker {
  constructor(element: ElementRef, renderer: Renderer) {
    renderer.setElementStyle(element.nativeElement,
      'text-decoration', 'underline');
  }
}
```

要创建一个指令，我们需要从 Angular 核心导入`Directive`装饰器函数。我们还需要另外两个名为`ElementRef`和`Renderer`的类来操纵元素。它们从构造函数中注入到我们的指令类中。

该指令将为元素添加样式，并用下划线装饰文本。

让我们通过将其应用于我们的`app 组件`模板来测试这个指令。打开`index.ts`并添加以下代码：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `<h1 text-marker>Angular2 components</h1>`
}) 
export class AppComponent {}
```

不要忘记将`TextMarker`类添加到根模块的`declarations`属性中。这个操作对本章中实现的所有自定义组件和指令都是必需的。打开`app.module.ts`文件并按照这里描述的更新它：

```ts
[app.module.ts]
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';
import { TextMarker } from './text-marker';

@NgModule({
  declarations: [
    AppComponent,
     TextMarker
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

打开浏览器并检查结果：

![基本属性指令](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00119.jpeg)

## ElementRef 和 Renderer

属性指令旨在为元素添加行为。为此，我们需要访问元素本身。在 Angular 2 中，直接访问 DOM 元素被认为是不良实践。Angular 通过引入一个抽象层将代码与视图层分离。

为了引用元素，我们使用`ElementRef`，它是代表我们正在运行的平台的元素类型的类。在我们的情况下，它是浏览器 DOM。`ElementRef`类具有揭示它包装的原生元素的能力，但我们不需要它。相反，我们将使用另一个名为`Renderer`的类，并将`ElementRef`实例传递给它。`Renderer`是一个公开用于操作元素的方法的类，而不指定它是哪种类型的元素。这种机制使我们的代码与元素的实现保持解耦。

## 对来自宿主元素的事件做出反应

属性指令适用于一个元素。如果我们想要对这个元素触发的事件做出反应，我们可以在`Directive`类的一些方法上使用`HostListener`装饰器。在下面的例子中，我们的指令将监听来自元素的鼠标事件并做出响应地改变样式：

```ts
[text-marker.ts]
import { 
Directive, ElementRef, Renderer, HostListener 
} from '@angular/core';

@Directive({
 selector: '[text-marker]'
})
export class TextMarker {
  constructor(private element: ElementRef, 
  private renderer: Renderer) { }

  @HostListener('mouseenter')
  markText() {
    this.renderer.setElementStyle(
      this.element.nativeElement,
      'text-decoration',
      'underline'
    );
  }

  @HostListener('mouseleave')
  unmarkText() {
    this.renderer.setElementStyle(
      this.element.nativeElement,
      'text-decoration',
      ''
    );
  }
}
```

现在，每次鼠标进入和离开*承载*属性指令的元素时，样式都会被应用和移除。

## 将属性传递给指令

我们还可以通过使用属性将配置传递给指令。就像组件一样，指令可以声明输入。让我们重构我们的`Directive`类以从属性中获取并应用文本颜色

```ts
[text-marker.ts]
import {
  Directive,
  ElementRef,
  Renderer, Input,
  HostListener
} from '@angular/core';

@Directive({
  selector: '[text-marker]'
})
export class TextMarker {
  @Input('text-marker') 
  private color: string;

  constructor(
    private element: ElementRef, 
    private renderer: Renderer
  ){ }

  @HostListener('mouseenter')
  onEnter() {
    this.applyStyle(this.color, true);
  }
  @HostListener('mouseleave')
  onExit() {
    this.applyStyle('', false);
  }

  private applyStyle(
    color:string, mark:boolean) {

      // apply underline
      this.renderer.setElementStyle(
        this.element.nativeElement,
        'text-decoration',
        mark ? 'underline' : ''
      );

      // apply color
      this.renderer.setElementStyle(
        this.element.nativeElement
        'color', color
      );
  }
}
```

通过使用`Input`装饰器，我们可以接受属性的值（在我们的例子中是`text-marker`）并在指令类内部使用它。现在我们可以传递我们想要使用的颜色。打开`app.component.ts`并尝试以下代码：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `<h1 text-marker="red">Angular2 components</h1>`
})
export class AppComponent {}
```

现在，每次鼠标进入`h1`元素时，文本应该被着色为红色并带有下划线：

![将属性传递给指令](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng2-cpn/img/image00120.jpeg)

# 基本结构指令

正如我们在本章开头提到的，第三种指令类型称为结构指令，顾名思义，这些指令旨在操作它们所应用的元素。Angular 核心包括几个操作 DOM 的指令，如`ngIf`、`ngFor`和`ngSwitch`。

对于我们的示例，我们将实现自己的`ngIf`指令，其行为与原始指令完全相同。

首先，创建一个名为`only-if.ts`的新文件，让我们为指令定义基本结构：

```ts
[only-if.ts]
import { Directive } from '@angular/core';

@Directive({
  selector: '[onlyIf]'
})
export class OnlyIf {
}
```

结构指令的生命周期开始时就像属性指令一样。我们从 Angular 核心导入`@Directive`装饰器，并将选择器声明为属性。

接下来，我们需要访问模板，并且我们需要一些容器类型，以便我们可以附加或移除视图。为此，我们需要注入`TemplateRef`和`ViewContainerRef`：

```ts
[only-if.ts]
import {
  Directive,
  TemplateRef,
  ViewContainerRef
} from '@angular/core';

@Directive({
  selector: '[onlyIf]'
})
export class OnlyIf {
  constructor(private _templateRef: TemplateRef,
              private _viewContainerRef: ViewContainerRef)
  {  }
}
```

我们的指令，就像 Angular 的`ngIf`一样，需要从其调用者那里接收一个布尔值，表示内容将显示或移除的条件。为此，我们将为此条件声明一个输入，并利用`ViewContainerRef`和`TemplateRef`：

```ts
[only-if.ts]
import {
  Directive,
  Input,
  TemplateRef,
  ViewContainerRef
} from 'angular/core';

@Directive({
  selector: '[onlyIf]'
})
export class OnlyIf {
  constructor(private _templateRef: TemplateRef<any>,
              private _viewContainerRef: ViewContainerRef) {  }

  @Input()
  set onlyIf(condition:boolean) {
    if (condition) {
      this._viewContainerRef.createEmbeddedView(this._templateRef);
    } else {
      this._viewContainerRef.clear();
    }
  }
}
```

让我们使用这个指令。打开`app.component.ts`并粘贴以下代码：

```ts
[app.component.ts]
import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <input type="checkbox" [(ngModel)]="condition">
    <p *onlyIf="condition">
      This content will shown only if the condition is true
    </p>
  `
}) 
export class AppComponent {}
```

不要忘记将`OnlyIf`类添加到根模块的`declarations`属性中。

让我们来探究一下：当我们使用星号（`*`）来调用我们的指令时，Angular 在幕后创建了一个`<template>`标签。在我们的指令内部，我们可以通过`TemplateRef`类获取对此模板的引用。然后，我们可以使用`ViewContainerRef`类，它代表一个`容器`，以便我们可以将视图嵌入其中，或者从模板的内容中创建或清除视图。

# 摘要

在 Angular 2 中，有三种类型的指令：组件指令、属性指令和结构指令。在本章中，我们对它们进行了简要介绍，并学习了如何构建简单的指令。指令可以做更多的事情，但这超出了本书的范围。
