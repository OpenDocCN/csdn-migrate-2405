# Angular2 Bootstrap4 Web 开发（五）

> 原文：[`zh.annas-archive.org/md5/1998a305c23fbffe24116fac6b321687`](https://zh.annas-archive.org/md5/1998a305c23fbffe24116fac6b321687)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：高级组件

本章描述了组件的生命周期以及可以在生命周期的不同阶段使用的方法。在本章中，我们将分析此周期的每个阶段，并学习如何充分利用在组件从一个阶段转移到另一个阶段时触发的钩子方法。本章还讨论了如何创建多组件应用程序。读者将能够使用 Bootstrap 为应用程序添加更多功能。

在本章结束时，您将对以下内容有扎实的理解：

+   组件生命周期钩子接口

+   生命周期钩子方法

+   实现钩子接口

+   变更检测

+   组件之间的通信

# 指令

指令是 Angular 2 的基本构建块，允许您将行为连接到 DOM 中的元素。有三种类型的指令：

+   属性指令

+   结构指令

+   组件

指令是一个带有分配的类`@Directive`装饰器。

## 属性指令

属性指令通常改变元素的外观或行为。我们可以通过绑定属性来改变多个样式或使用它来渲染文本为粗体或斜体。

## 结构指令

结构指令通过添加和删除其他元素来改变 DOM 布局。

## 组件

组件是带有模板的指令。每个组件由两部分组成：

+   我们定义应用程序逻辑的类

+   由组件控制的视图，通过属性和方法的 API 与其交互

组件是一个带有分配的类`@Component`装饰器。

# 指令生命周期

要为任何项目开发自定义指令，您应该了解 Angular 2 指令生命周期的基础知识。指令在创建和销毁之间经历了许多不同阶段：

1.  实例化

1.  初始化

1.  变更检测和渲染

1.  内容投影（仅适用于组件）

1.  视图之后（仅适用于组件）

1.  销毁

# Angular 生命周期钩子

Angular 提供了指令生命周期钩子，使我们能够在发生这些关键时刻时采取行动。我们可以在 Angular `core`库中实现一个或多个生命周期钩子接口。每个接口都有一个单一的方法，其名称是以`ng`为前缀的接口名称。接口对于 TypeScript 是可选的，如果定义了接口，Angular 将调用钩子方法。

### 注意

我建议实现生命周期钩子接口到指令类中，以便从强类型和编辑器工具中受益。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 实例化

注入器使用`new`关键字创建指令实例。每个指令最多可以包含一个构造函数声明。如果一个类不包含构造函数声明，将提供自动构造函数。构造函数的主要目的是创建对象的新实例并为其设置初始属性。Angular 2 使用构造函数进行依赖注入，因此我们可以保存对依赖实例的引用以供以后使用：

```ts
export class CategoryListComponent { 

    categories: Category[]; 

    constructor(private router: Router,  
                private categoryService: CategoryService) { 
        this.categories = this.categoryService.getCategories(); 
    } 

    filterProducts(category: Category) { 
        this.router.navigate(['/products'], {  
          queryParams: { category: category.id}  
        }); 
    } 
} 

```

在上面的例子中，`CategoryListComponent`类有一个构造函数，其中有两个参数引用`Router`和`CategoryService`。

# 初始化

在每个指令中都有数据绑定的输入属性，并且 Angular 在初始化阶段保存了绑定属性的值：

```ts
export class CategorySlideComponent { 
    @Input() category: Category; 
    @Output() select: EventEmitter<Category> =  
       new EventEmitter<Category>(); 
} 

```

`CategorySlideComponent`类有一个与模板中同名属性绑定的类别。

我们可以实现`OnInit`和`OnChanges`接口来做出相应的响应：

+   当数据绑定的输入属性值发生变化时，Angular 调用`ngOnChanges`方法

+   Angular 在第一次`ngOnChanges`之后调用`ngOnInit`方法，并向我们发出信号，表明组件已经初始化

在下面的代码中，我们实现了`OnInit`接口来创建表单控件并开始监听其值的变化：

```ts
@Component({ 
    selector: 'db-product-search', 
    templateUrl: 'app/product/product-search.component.html', 
    changeDetection: ChangeDetectionStrategy.OnPush 
}) 
export class ProductSearchComponent implements OnInit { 

    disabled: boolean = true; 
    seachControl: FormControl; 

    constructor(private router: Router,  
                private changeDetection: ChangeDetectorRef) {} 

 **ngOnInit() {** 

 **this.seachControl = new FormControl();** 

 **this.seachControl.valueChanges.subscribe((value: string)** 

 **=> {** 

 **this.searchChanged(value);** 

 **this.changeDetection.markForCheck();** 

 **});** 

 **}** 

... 
} 

```

大多数情况下，我们依赖`ngOnInit`方法有以下原因：

+   我们需要在构造函数之后执行初始化

+   在 Angular 设置输入属性后，完成组件设置

这个方法是一个完美的位置，用于从服务器获取数据或根据输入属性更新内部状态的繁重初始化逻辑。

# 变更检测和渲染

这个阶段故意结合了 Angular 2 用来为应用程序注入生命的两种重要技术。一方面，框架的变更检测模块负责监视程序的内部状态的变化。它可以检测任何数据结构的变化，从基本类型到对象数组。另一方面，Angular 的渲染部分使这些变化在 DOM 中可见。Angular 将这两种技术结合在一个阶段中，以最小化工作量，因为重建 DOM 树是昂贵的。

## NgZone 服务

大多数情况下，应用程序状态的变化是因为应用程序中发生了以下异步任务：

+   用户或应用程序触发的事件

+   指令和管道属性变化

+   从 AJAX 响应中调用回调函数

+   来自定时器的回调函数调用

Angular 使用 Zone 库中的执行上下文`NgZone`来钩入这些异步任务以检测变化、处理错误和进行分析。当代码进入或退出区域时，区域可以执行几个重要的操作，例如：

+   启动或停止计时器

+   保存堆栈跟踪

+   覆盖执行代码的方法

+   将数据与各个区域关联等

每个 Angular 应用程序都有一个包装可执行代码的全局区域对象，但我们也可以使用`NgZone`服务在 Angular 区域内外执行工作。 `NgZone`是一个扩展了标准区域 API 并向执行上下文添加了一些附加功能的分支区域。 Angular 使用`NgZone`来 monkey-patch 全局异步操作，例如`setTimeout`和`addEventListener`以更新 DOM。

## 变更检测

Angular 框架中的每个指令都有一个变更检测器，因此我们可以定义如何执行变更检测。指令的分层结构将变更带入了舞台上的检测器树，因此 Angular 始终使用单向数据流作为一种工具，将数据从父级传递给子级。

大多数情况下，Angular 的变更检测发生在属性上，并相应地更新视图，与数据结构无关：

```ts
@Component({ 
    selector: 'db-product-card', 
    templateUrl: 'app/product/product-card.component.html' 
}) 
export class ProductCardComponent { 
 **@Input() products: Product[];** 

 **@Output() addToCart: EventEmitter<Product> =** 

 **new EventEmitter<Product>();** 

    setClasses(product: Product) { 
        return { 
            'card-danger': product.isSpecial, 
            'card-inverse': product.isSpecial 
        }; 
    } 

    buy(product: Product) { 
      this.addToCart.emit(product); 
    } 
} 

```

属性绑定用于向`product`提供数据，事件绑定用于通知其他组件进行任何更新，并将其委托给存储。 `product`是一个指向具有许多字段的真实对象的引用：

```ts
export interface Product { 
    // Unique Id 
    id: string; 
    // Ref on category belongs to 
    categoryId: string; 
    // The title 
    title: string; 
    // Price 
    price: number; 
    // Mark product with special price 
    isSpecial: boolean; 
    // Description 
    desc: string; 
    // Path to small image 
    imageS: string; 
    // Path to large image 
    imageL: string; 
} 

```

即使任何字段都可以更改，`product`引用本身仍然保持不变。由于框架变更检测系统可以在几毫秒内执行数百甚至数千次检查指令属性的更改而不会降低性能，因此 Angular 将在每次执行大量的检查变更时执行大量的检查变更。有时这种大规模的变更检测可能非常昂贵，因此我们可以根据每个指令选择变更检测策略。

指令的内部状态仅取决于其输入属性，因此如果这些属性从一次检查到下一次没有发生变化，那么指令就不需要重新渲染。请记住，所有的 JavaScript 对象都是可变的，因此变更检测应该检查所有输入属性字段，以在必要时重新渲染指令。如果我们使用不可变结构，那么变更检测可以更快。让我们看看可能发生的情况。

## 不可变对象

不可变对象是不会改变的。它始终只有一个内部状态，如果我们想对这样的对象进行更改，我们将始终得到对该更改的新引用。

## 变更检测策略

Angular 支持以下变更检测策略：

+   `Default`策略意味着变更检测器将深度检查每个脏检查的属性

+   `OnPush`策略意味着变更检测器将检查每个脏检查的属性引用的变化

我们可以通过装饰器的`changeDetection`属性指示 Angular 可以为特定指令使用哪种变更检测策略：

```ts
@Component({ 
    selector: 'db-product-card', 
    templateUrl: 'app/product/product-card.component.html', 
 **changeDetection: ChangeDetectionStrategy.OnPush** 

}) 
export class ProductCardComponent { 
... 
} 

```

只有当通过输入属性提供给指令的所有值都是不可变的时，`OnPush`策略才能正常工作。

### 注意

不要在`OnPush`检测策略中使用可变值，因为这可能会使 Angular 应用程序处于不一致或不可预测的状态。

Angular 会自动触发变更检测，以检查指令在`OnPush`模式下是否发生以下情况：

+   当任何指令输入属性发生变化时

+   每当指令触发事件时

+   当属于该指令的任何可观察对象触发事件时

## 以编程方式触发变更检测

如前所述，每个指令都有一个自动工作的变更检测器。在需要以编程方式触发变更检测的情况下，我们可以使用`ChangeDetectionRef`类。我们可以在发生变化的地方调用该类的`markForCheck`方法，这样它就会标记从该指令到根的路径，以便在下一次变更检测运行时进行检查：

```ts
import {Component, ChangeDetectionStrategy, ChangeDetectorRef}   
    from '@angular/core'; 
import {Router} from '@angular/router'; 
import {FormControl} from '@angular/forms'; 

@Component({ 
    selector: 'db-product-search', 
    templateUrl: 'app/product/product-search.component.html', 
    changeDetection: ChangeDetectionStrategy.OnPush 
}) 
export class ProductSearchComponent { 

    disabled: boolean = true; 
    seachControl: FormControl; 

    constructor(private router: Router,  
                private changeDetection: ChangeDetectorRef) {} 

    ngOnInit() { 
        this.seachControl = new FormControl(); 
        this.seachControl.valueChanges.subscribe((value: string)  
        => { 
            this.searchChanged(value); 
 **this.changeDetection.markForCheck();** 

        }); 
    } 

    searchProduct(value: string) { 
        this.router.navigate(['/products'], {  
          queryParams: { search: value}  
        }); 
    } 

    searchChanged(value: string) { 
        // Update the disabled property depends on value  
        if (value) { 
            this.disabled = false; 
        } else { 
            this.disabled = true; 
        } 
    } 
} 

```

在前面的代码中，我们触发了变更检测，因为字符串值来自`searchControl`，而该值始终是不可变的。

正如我们所提到的，我们可以实现`OnChanges`接口来检测指令的输入属性的变化，并相应地做出响应：

+   当数据绑定的输入属性值发生变化时，Angular 调用`ngOnChanges`方法。大多数情况下，我们不使用这个方法，但如果需要根据输入属性改变内部状态的依赖关系，这就是合适的地方。

在下面的代码中，我们使用`OnChanges`接口来监视`category`输入属性的变化：

```ts
import {Component, Input, OnChanges, SimpleChanges}  
   from '@angular/core'; 
import {Router} from '@angular/router'; 

import {Category} from './category.service'; 

@Component({ 
    selector: 'db-category-card', 
    templateUrl: 'app/category/category-card.component.html' 
}) 
export class CategoryCardComponent implements OnChanges { 
 **@Input() category: Category;** 

    constructor(private router: Router) {} 

 **ngOnChanges(changes: SimpleChanges): void {** 

 **for (let propName in changes) {** 

 **let change = changes[propName];** 

 **let current  = JSON.stringify(change.currentValue);** 

 **let previous = JSON.stringify(change.previousValue);** 

 **console.log(`${propName}: currentValue = ${current},** 

 **previousValue = ${previous}`);** 

 **}** 

 **}** 

    filterProducts(category: Category) { 
        this.router.navigate(['/products'], {  
          queryParams: { category: category.id}  
        }); 
    } 
} 

```

当将值分配给`category`时，`ngOnChanges`方法打印以下信息：

```ts
category: currentValue = {"id":"1", "title":"Bread & Bakery", "imageL":"http://placehold.it/1110x480", "imageS":"http://placehold.it/270x171",  "desc":"The best cupcakes, cookies, cakes, pies, cheesecakes, fresh bread, biscotti, muffins, bagels, fresh coffee and more."}, previousValue = {} 

```

`SimpleChanges`类保留了每个更改的属性名称的当前值和先前值，因此我们可以遍历并记录它们。

我们可以在指令中实现`DoCheck`接口来检测并对 Angular 无法捕捉到的变化做出反应。Angular 在每次变化检测周期中调用`ngDoCheck`方法。请谨慎使用此方法，因为 Angular 会以极高的频率调用它，因此实现必须非常轻量级。

# 内容投影（仅适用于组件）

一般来说，组件是一个 HTML 元素，可能包含文本或标记等内容。Angular 2 使用带有`ng-content`标记的特定入口点将内容注入到组件模板中。这种技术被称为**内容投影**，Angular 使用 Shadow DOM 来实现。

Angular 2 利用 Web 组件标准并使用一组以下技术：

+   用于结构性 DOM 更改的模板

+   Shadow DOM 用于样式和 DOM 封装

我们在项目中使用了模板，现在是时候谈谈 Angular 如何在不同的封装类型中使用 Shadow DOM 了。

Shadow DOM 允许我们将 DOM 逻辑隐藏在其他元素后面，并在其范围内应用样式。Shadow DOM 内部的所有内容对其他组件不可用，因此我们称之为封装。事实上，Shadow DOM 是一种新技术，并非所有的 Web 浏览器都支持它，因此 Angular 使用模拟来模仿 Shadow DOM 的行为方式。

Angular 中有三种封装类型：

+   `ViewEncapsulation.None`：Angular 不使用 Shadow DOM 和样式封装

+   `ViewEncapsulation.Emulated`：Angular 不使用 Shadow DOM，但模拟样式封装

+   `ViewEncapsulation.Native`：Angular 使用原生 Shadow DOM 并获得所有的好处

我们将使用`@Component`装饰器的`encapsulation`属性来指示 Angular 使用哪种封装类型。

## 组件样式

在 Angular 2 中，我们可以为整个文档和特定组件应用样式。这种变化带来了另一种粒度级别，并有助于比常规样式表更模块化的设计。组件样式与任何全局样式都不同。组件样式中的任何选择器都在该组件及其子元素的范围内应用。组件样式带来以下好处：

+   我们可以在组件的上下文中使用任何 CSS 类或选择器，而不必担心与应用程序其他部分中使用的类和选择器发生名称冲突。

+   组件中封装的样式对应用程序的其余部分是不可见的，也不能在其他地方更改。我们可以更改或删除组件样式而不影响整个应用程序的样式。

+   组件样式可以放在单独的文件中，并且可以与 TypeScript 和 HTML 代码共存，这使得项目代码更加结构化和有组织。

### 特殊选择器

组件样式可能包括几个特殊选择器。所有这些都来自 Shadow DOM 世界。

#### :host 伪类

托管组件的任何元素都称为宿主。从托管组件中的宿主元素中定位宿主元素的样式的唯一方法是使用`:host`伪类选择器：

```ts
:host { 
  display: block; 
  border: 1px solid black; 
} 

```

在前面的代码片段中，我们更改了父组件模板中的显示和边框样式。在需要有条件地应用宿主样式时，可以使用另一个选择器作为样式函数形式的参数：

```ts
:host(.active) { 
  border-width: 3px; 
} 

```

前面的样式只有在宿主具有`active`类时才适用。

#### :host-context 伪类

想象一下，当您为 Web 应用程序创建主题并希望根据其他选择器的存在或不存在应用特定样式到您的组件时。您可以轻松地使用`:host-context`函数来实现：

```ts
:host-context(.theme-dark) p { 
  background-color: gray; 
} 

```

前面代码的逻辑是在组件宿主元素到文档根部之间查找`theme-dark` CSS 类，并将`gray`应用于组件内所有段落元素的`background-color`样式。

#### /deep/选择器

组件的样式仅适用于其模板。如果我们需要将它们应用于所有子元素，那么我们需要使用`/deep/`选择器：

```ts
:host /deep/ h4 { 
  font-weight: bold; 
} 

```

前面代码片段中的`/deep/`选择器将把`bold`应用于组件中所有`h4`标题元素的`font-weight`样式，通过子组件树一直到所有子组件视图。

`/deep/`选择器有一个别名`>>>`，我们可以在模拟视图封装中互换使用。

## 非视图封装

Angular 不使用此类型的 Shadow DOM 和样式封装。让我们想象一下，在我们的项目中有一个`ParentComponent`：

```ts
import {Component, Input, ViewEncapsulation} from '@angular/core'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
        <ng-content></ng-content> 
    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `], 
 **encapsulation: ViewEncapsulation.None** 

}) 
export class ParentComponent { 
  @Input() title: string; 
} 

```

在`AppComponent`的代码中，我们有以下内容：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'my-app', 
  template: ` 
 **<my-parent >** 

 **<my-child></my-child>** 

 **</my-parent>`** 

}) 
export class AppComponent { } 

```

`ParentComponent`有自己的样式，它可以用另一个组件覆盖它，因为它将稍后应用于文档头部：

```ts
<head> 
  ... 
  <style> 
    .parent { 
      background: green; 
      color: white; 
    } 
  </style> 
  <style>.child[_ngcontent-ced-3] { 
    background: red; 
    color: yellow; 
  }</style> 
</head> 

```

Angular 生成以下在浏览器中运行的 HTML 代码：

```ts
<my-app> 
  <my-parent  ng-reflect-> 
    <div class="parent"> 
      <div class="parent__title"> 
       Parent 
      </div> 
      <div class="parent__content"> 
        <my-child _nghost-fhc-3=""> 
          <div _ngcontent-fhc-3="" class="child"> 
            Child 
          </div> 
        </my-child> 
      </div> 
    </div> 
  </my-parent> 
</my-app> 

```

没有 Shadow DOM 的参与，应用程序将样式应用于整个文档。Angular 用子组件的内容替换了`ng-content`。

![非视图封装](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00132.jpg)

## 模拟视图封装

模拟视图是 Angular 用来创建组件的默认视图封装。Angular 不使用 Shadow DOM，但模拟样式封装。让我们改变`encapsulation`属性的值来看看区别。这是 Angular 为模拟视图封装生成的样式：

```ts
<head> 
  ... 
  <style>.parent[_ngcontent-xdn-2] { 
    background: green; 
    color: white; 
  }</style><style>.child[_ngcontent-xdn-3] { 
    background: red; 
    color: yellow; 
  }</style> 
</head> 

```

父组件的样式看起来不同，并属于特定元素。这就是 Angular 模拟样式封装的方式：

```ts
<my-app> 
    <my-parent  _nghost-xdn-2=""  
               ng-reflect-> 
        <div _ngcontent-xdn-2="" class="parent"> 
            <div _ngcontent-xdn-2="" class="parent__title"> 
                Parent 
            </div> 
            <div _ngcontent-xdn-2="" class="parent__content"> 
                <my-child _nghost-xdn-3=""> 
                    <div _ngcontent-xdn-3="" class="child"> 
                        Child 
                    </div> 
                </my-child> 
            </div> 
        </div> 
    </my-parent> 
</my-app> 

```

页面的标记部分看起来与非视图封装非常相似。

## 原生视图封装

原生视图是最简单的封装之一。它使用原生 Shadow DOM 来封装内容和样式。Angular 不需要为父组件生成任何样式：

```ts
<head> 
  ... 
  <style>.child[_ngcontent-sgt-3] { 
      background: red; 
      color: yellow; 
    }</style> 
</head> 

```

现在，父组件的样式对其他应用程序以及标记代码都不可用：

```ts
<my-app> 
  <my-parent  ng-reflect-> 
 **#shadow-root** 

      <style>.child[_ngcontent-sgt-3] { 
        background: red; 
        color: yellow; 
      }</style> 
      <style>.parent { 
        background: green; 
        color: white; 
      }</style> 
      <div class="parent"> 
        <div class="parent__title"> 
          Parent 
        </div> 
        <div class="parent__content"> 
            <my-child _nghost-sgt-3=""> 
                <div _ngcontent-sgt-3="" class="child"> 
                    Child 
                </div> 
            </my-child> 
        </div> 
    </div> 
  </my-parent> 
</my-app> 

```

如果我们需要投影多个子内容，我们可以使用带有专用`select`属性的`ng-content`：

```ts
import {Component, Input, ViewEncapsulation} from '@angular/core'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
 **<ng-content></ng-content>** 

    </div> 
    <div class="parent__content"> 
 **<ng-content select=".another"></ng-content>** 

    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `], 
  encapsulation: ViewEncapsulation.Native 
}) 
export class ParentComponent { 
  @Input() title: string; 
} 

```

请记住，`select`属性期望 Angular 可以在`document.querySelector`中使用的字符串值。在应用程序组件中，我们有类似的东西：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'my-app', 
  template: ` 
  <my-parent > 
 **<my-child></my-child>** 

 **<my-child class="another"></my-child>** 

  </my-parent>` 
}) 
export class AppComponent { } 

```

这是 Angular 生成的结果标记：

```ts
<div class="parent"> 
    <div class="parent__title"> 
        Parent 
    </div> 
    <div class="parent__content"> 
 **<my-child _nghost-cni-3="">** 

 **<div _ngcontent-cni-3="" class="child">** 

 **Child** 

 **</div>** 

 **</my-child>** 

    </div> 
    <div class="parent__content"> 
 **<my-child class="another" _nghost-cni-3="">** 

 **<div _ngcontent-cni-3="" class="child">** 

 **Child** 

 **</div>** 

 **</my-child>** 

    </div> 
</div> 

```

![原生视图封装](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00133.jpg)

### 提示

您可以在`chapter_8/1.view-encapsulation`找到源代码。

现在，我们知道内容投影是 Angular 从组件外部导入 HTML 内容并将其插入到模板的设计部分的方式。当 Angular 把外部内容投影到组件中时，它会调用 `AfterContentInit` 和 `AfterContentChecked` 接口的钩子方法：

+   在 Angular 把外部内容投影到其视图中并且内容已初始化后，它会调用 `ngAfterContentInit` 方法

+   在 Angular 检查它投影到其视图中的外部内容的绑定后，它会调用 `ngAfterContentChecked` 钩子方法

我们可以使用其中任何一个来操作内容元素的属性。为了组织对一个或多个内容元素的访问，我们必须获取父组件的属性并用 `@ContentChild` 或 `@ContentChildren` 进行装饰。Angular 使用传递给装饰器的参数来选择内容元素：

+   如果参数是一个类型，Angular 将找到与相同类型的指令或组件绑定的元素

+   如果参数是一个字符串，Angular 将解释它为一个选择器，以查找相应的元素

Angular 在调用 `ngAfterContentInit` 方法之前设置装饰属性的值，以便我们可以在方法内部访问它。稍后，当 Angular 检查和更新内容元素时，它会调用 `ngAfterContentChecked` 来通知我们包含元素已更新。让我们看看如何使用它。这是我们将用作父组件内容的子组件：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
    Child is {{status}} 
  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent {  
  @Input() status: string = 'Not Ready'; 
} 

```

我们将查看子组件的 `status` 属性，并从父组件在控制台上打印出值：

```ts
import {Component, Input, AfterContentInit, AfterContentChecked,  
        ContentChild} from '@angular/core'; 

import {ChildComponent} from './child.component'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
        <ng-content></ng-content> 
    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `] 
}) 
export class ParentComponent implements  
             AfterContentInit, AfterContentChecked { 
  @Input() title: string; 

  // Query for a CONTENT child of type ChildComponent` 
 **@ContentChild(ChildComponent) contentChild: ChildComponent;** 

 **ngAfterContentInit() {** 

    // contentChild is set after the content has been initialized 
    console.log('AfterContentInit. Child is',  
                 this.contentChild.status); 
    this.title = 'Parent'; 
  } 

 **ngAfterContentChecked() {** 

    console.log('AfterContentChecked. Child is',  
                 this.contentChild.status); 
    // contentChild is updated after the content has been checked 
    if (this.contentChild.status == 'Ready') { 
      console.log('AfterContentChecked (no change)'); 
    } else { 
      this.contentChild.status = 'Ready'; 
    } 
  } 
} 

```

让我们将它们组合在应用程序组件模板中：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'my-app', 
  template: ` 
 **<my-parent >** 

 **<my-child></my-child>** 

 **</my-parent>`** 

}) 
export class AppComponent { } 

```

现在，运行应用程序，我们将在控制台上得到以下登录信息：

```ts
 **AfterContentInit. Child is Not Ready** 

 **AfterContentChecked. Child is Not Ready** 

 **AfterContentChecked. Child is Ready** 

 **AfterContentChecked (no change)** 

```

### 提示

您可以在 `chapter_8/2.after-content` 找到此源代码。

# 视图之后（仅适用于组件）

当 Angular 完成组件视图及其子视图的初始化时，它会调用两个钩子接口 `AfterViewInit` 和 `AfterViewChecked` 的方法。我们可以利用初始化的时刻来更新或操作视图元素：

+   当 Angular 完成组件视图及其子视图的初始化时，它会调用 `ngAfterViewInit` 方法

+   Angular 在检查组件视图的绑定和其子视图的视图之后调用 `ngAfterViewChecked` 方法

我们可以使用其中任何一个来操作视图元素。为了组织对一个或多个视图元素的访问，我们必须在父组件中拥有该属性，并用`@ViewChild`或`@ViewChildren`装饰它。Angular 使用传递到装饰器的参数来选择视图元素：

+   如果参数是一个类型，Angular 将找到一个与相同类型的指令或组件绑定的元素

+   如果参数是一个字符串，Angular 会将其解释为一个选择器，以找到相应的元素

在调用`ngAfterViewInit`方法之前，Angular 会设置装饰属性的值。稍后，在检查和更新视图元素后，它会调用`ngAfterViewChecked`来通知我们视图元素已更新。让我们看看我们如何使用它。这是我们将在父组件模板中使用的子组件：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
    Child is {{status}} 
  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent {  
  @Input() status: string = 'Not Ready'; 
} 

```

我们正在观察子组件的`status`属性，并将从父组件打印出值：

```ts
import {Component, Input, AfterViewInit, AfterViewChecked,  
        ViewChild, ChangeDetectionStrategy} from '@angular/core'; 

import {ChildComponent} from './child.component'; 

@Component({ 
  selector: 'my-parent', 
 **changeDetection: ChangeDetectionStrategy.OnPush,** 

  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
 **<my-child></my-child>** 

    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `] 
}) 
export class ParentComponent implements  
 **AfterViewInit, AfterViewChecked {** 

  @Input() title: string; 

  // Query for a VIEW child of type `ChildComponent` 
 **@ViewChild(ChildComponent) viewChild: ChildComponent;** 

  ngAfterViewInit() { 
    // viewChild is set after the view has been initialized 
    console.log('AfterViewInit. Child is', this.viewChild.status); 
    this.title = 'Parent'; 
  } 

  ngAfterViewChecked() { 
    console.log('AfterViewChecked. Child is',  
                 this.viewChild.status); 
    // viewChild is updated after the view has been checked 
    if (this.viewChild.status == 'Ready') { 
      console.log('AfterViewChecked (no change)'); 
    } else { 
      this.viewChild.status = 'Ready'; 
    } 
  } 
} 

```

请记住，我们在这段代码中使用`OnPush`变更检测，以防止循环调用`ngAfterViewChecked`方法。这是应用程序组件模板：

```ts
import { Component } from '@angular/core'; 

@Component({ 
  selector: 'my-app', 
  template: ` 
 **<my-parent >** 

 **</my-parent>`** 

}) 
export class AppComponent { } 

```

现在，运行应用程序，我们将得到以下登录控制台：

```ts
 **AfterViewInit. Child is Not Ready** 

 **AfterViewChecked. Child is Not Ready** 

 **AfterViewChecked. Child is Ready** 

 **AfterViewChecked (no change)** 

```

### 提示

你可以在`chapter_8/3.after-view`找到这个的源代码。

# 从父到子的通信

组织父子组件之间的通信并不是微不足道的，所以让我们谈谈我们可以使用的不同技术来实现这一点。

## 通过输入绑定进行父到子的通信

每个指令可能有一个或多个输入属性。我们可以将子组件的任何属性与静态字符串或父组件变量绑定，以组织它们之间的通信。这是子组件：

```ts
import {Component, Input, Output, EventEmitter, OnInit }  
       from '@angular/core'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
 **{{desc}} belongs to {{parent}} with {{emoji}}** 

  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent {  
 **@Input() desc: string;** 

 **@Input('owner') parent: string;** 

 **private _emoji: string;** 

 **@Input() set emoji(value: string) {** 

 **this._emoji = value || 'happy';** 

 **}** 

 **get emoji(): string {** 

 **return this._emoji;** 

 **}** 

@Output() status: EventEmitter<string> =  
              new EventEmitter<string>(); 

  ngOnInit(): void { 
    this.status.emit('Ready'); 
  } 
} 

```

它有三个用`@Input`装饰器标记的输入属性：

+   属性`desc`由其自然名称装饰

+   属性`parent`用别名装饰，以便父组件将其视为`owner`的名称

+   属性`emoji`是一组 getter/setter 方法的组合，这样我们可以添加一些逻辑来为私有变量分配值

它有一个输出属性`status`，用于从子级到父级进行通信。我特意添加了一个`OnInit`钩子接口，这样我们可以在创建子级后向父级发送消息。这是父组件：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}}. Child is {{status}} 
    </div> 
    <div class="parent__content"> 
 **<my-child [desc]="'Child'"** 

 **[owner]="title"** 

 **[emoji]="'pleasure'"** 

 **(status)="onStatus($event)" ></my-child>** 

    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `] 
}) 
export class ParentComponent { 
  @Input() title: string; 
  status: string; 

  onStatus(value: string) { 
    this.status = value; 
  } 
} 

```

父组件设置子组件的所有输入属性，并在`onStatus`方法中监听`status`事件。创建后，子组件会发出状态事件，父组件会在标题附近打印该信息。

![通过输入绑定进行父子通信](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00134.jpg)

### 提示

您可以在`chapter_8/4.parent-child-input-binding`找到此源代码。

## 通过本地变量进行父子通信

父元素无法访问子组件的属性或方法。我们可以在父模板中创建一个模板引用变量，以便访问子组件的类成员：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent" [ngInit]="child.setDesc('You are mine')"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
        <my-child #child></my-child> 
    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `] 
}) 
export class ParentComponent { 
  @Input() title: string; 
} 

```

在前面的父组件中，我们创建了`child`本地模板变量，并在`NgInit`指令中使用它来调用子组件的`setDesc`方法：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
    {{desc}} 
  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent {  
  @Input() desc: string; 

  setDesc(value: string) { 
    this.desc = value; 
  } 
} 

```

我们使用了`NgInit`指令来初始化子组件的`desc`属性：

```ts
import {Directive, Input} from '@angular/core'; 

@Directive({ 
  selector: '[ngInit]' 
}) 
export class NgInit { 
  @Input() ngInit; 

  ngOnInit() { 
    if(this.ngInit) {  
        this.ngInit();  
    } 
  } 
} 

```

### 提示

您可以在`chapter_8/5.parent-child-local-variable`找到此源代码。

## 通过调用 ViewChild 进行父子通信

当我们需要从父组件访问子组件时，我们可以使用`AfterViewInit`和`AfterViewChecked`钩子。Angular 在创建组件的子视图后调用它们。以下是子组件：

```ts
import {Component, Input} from '@angular/core'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
    {{desc}} 
  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent {  
  @Input() desc: string; 
} 

```

父组件导入必要的类并实现`AfterViewInit`接口：

```ts
import {Component, Input, AfterViewInit, ViewChild}  
   from '@angular/core'; 

import {ChildComponent} from './child.component'; 

@Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
 **<my-child></my-child>** 

    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `] 
}) 
export class ParentComponent implements AfterViewInit { 
  @Input() title: string; 

 **@ViewChild(ChildComponent)** 

 **private child: ChildComponent;** 

 **ngAfterViewInit()
 {** 

 **this.child.desc = "You are mine";** 

 **}** 

} 

```

我们通过之前介绍的`@ViewChild`装饰器将子组件注入到父组件中。在这种情况下，`AfterViewInit`接口非常重要，因为在 Angular 显示父视图并调用`ngAfterViewInit`方法之前，`child`组件是不可用的。

### 提示

您可以在`chapter_8/6.parent-child-viewchild`找到此源代码。

## 通过服务进行父子通信

组织父子通信的另一种可能方式是通过一个公共服务。我们将服务分配给父组件，并在该父组件和其子组件之间锁定服务实例的范围。此子树之外的任何单个组件都无法访问该服务或它们的通信。在这里，子组件可以通过构造函数注入来访问服务：

```ts
import {Component, Input, OnDestroy} from '@angular/core'; 
import {Subscription} from 'rxjs/Subscription'; 
import {CommonService} from './common.service'; 

@Component({ 
  selector: 'my-child', 
  template: ` 
  <div class="child"> 
    {{desc}} 
  </div>`, 
  styles: [` 
    .child { 
      background: red; 
      color: yellow; 
    } 
  `] 
}) 
export class ChildComponent implements OnDestroy {  
  @Input() desc: string; 

  subscription: Subscription; 

  constructor(private common: CommonService) { 
    this.subscription = this.common.childQueue.subscribe( 
      message => { 
        this.desc = message; 
      } 
    ); 
  } 

  ngOnDestroy() { 
    // Clean after yourself 
    this.subscription.unsubscribe(); 
  } 
} 

```

我们在构造函数中对来自父组件的消息进行订阅。请在实现时注意`OnDestroy`接口。`ngOnDestroy`方法中的代码是一个内存泄漏保护步骤。父组件已经注册了一个`CommonService`作为提供者，并通过构造函数注入：

```ts
import {Component, Input, OnInit} from '@angular/core'; 
import {CommonService} from './common.service'; 

 @Component({ 
  selector: 'my-parent', 
  template: ` 
  <div class="parent"> 
    <div class="parent__title"> 
     {{title}} 
    </div> 
    <div class="parent__content"> 
        <my-child></my-child> 
    </div> 
  </div>`, 
  styles: [` 
    .parent { 
      background: green; 
      color: white; 
    } 
  `], 
 **providers: [CommonService]** 

}) 
export class ParentComponent implements OnInit { 
  @Input() title: string; 

  constructor(private common: CommonService) { 
 **this.common.parentQueue.subscribe(** 

 **message => {** 

 **this.title = message;** 

 **}** 

 **);** 

  } 

  ngOnInit() { 
 **this.common.toChild("You are mine");** 

  } 
} 

```

在这里我们不需要内存泄漏保护步骤，因为父组件控制着注册提供者的生命周期。

### 提示

您可以在`chapter_8/7.parent-child-service`找到此源代码。

# 销毁

这个阶段是最后一个存在指令的阶段。我们可以实现`OnDestroy`接口来捕获这一时刻：

+   在销毁指令之前，Angular 会调用`ngOnDestroy`方法

+   Angular 在这个方法中添加了清理逻辑，以取消订阅可观察对象并分离事件处理程序，以避免内存泄漏

我们可以通知另一个组件（父组件或同级组件），指令即将消失。我们必须释放分配的资源，取消订阅可观察对象和 DOM 事件监听器，并取消来自服务的所有回调。

# 总结

在本章中，我们了解了组件的生命周期以及可以在不同阶段使用的方法。我们了解到 Angular 具有具有钩子方法的接口，以及如何充分利用这些钩子方法，这些钩子方法在组件从一个阶段转移到另一个阶段时触发。

我们揭示了 Angular 变化检测的工作原理以及我们如何管理它。我们讨论了如何组织组件之间的通信。

在第九章中，*通信和数据持久性*，我们将学习如何进行 HTTP 请求并在 Firebase 平台上存储数据。我们将学习如何使用内置的 HTTP 库来处理端点。此外，我们还将学习如何使用可观察对象来处理数据。在本章末尾，我们将学习如何将 Firebase 作为应用程序的持久性层。与往常一样，我们将继续构建我们在之前章节中开始开发的项目。


# 第九章：通信和数据持久性

本章讲解如何处理 HTTP 请求并将数据存储在服务器上。我们将学习如何使用内置的 HTTP 库来处理端点。此外，我们还将学习如何使用**可观察对象**来处理数据。在本章结束时，我们将学习如何将 Firebase 作为应用程序的持久层。和往常一样，我们将继续构建之前章节中开始开发的项目。

在本章结束时，您将对以下内容有扎实的了解：

+   HttpModule

+   创建连接

+   可观察对象

+   安装 Firebase 工具

+   连接到 Firebase

让我们开始吧：

1.  打开终端，创建文件夹`ecommerce`，并进入该文件夹。

1.  将项目文件夹`chapter_9/1.ecommerce-seed`中的内容复制到新项目中。

1.  运行以下脚本以安装 npm 模块：

```ts
 **npm install** 

```

1.  使用以下命令启动 TypeScript 监视器和轻量级服务器：

```ts
 **npm start** 

```

此脚本打开 Web 浏览器并导航到项目的欢迎页面。

# 客户端到服务器的通信

Web 浏览器和服务器作为**客户端-服务器系统**运行。一般来说，Web 服务器保存数据，并在请求时与任意数量的 Web 浏览器共享数据。Web 浏览器和服务器必须有共同的语言，并且必须遵循规则，以便双方知道可以期待什么。通信的语言和规则在通信协议中定义。**传输控制协议**（**TCP**）是一种标准，定义了如何建立和维护网络会话，通过该会话应用程序可以交换数据。TCP 与**互联网协议**（**IP**）一起工作，后者定义了计算机如何相互发送数据包。TCP 和 IP 共同定义了互联网的基本规则。Web 浏览器和服务器通过**TCP/IP**堆栈进行通信。要在 TCP/IP 网络上发送数据，需要四个步骤或层：

+   **应用层**对发送的数据进行编码。它不关心数据如何在两点之间传输，对网络状态知之甚少。应用程序将数据传递给 TCP/IP 堆栈中的下一层，然后继续执行其他功能，直到收到回复。

+   **传输层**将数据分割成可管理的块，并添加端口号信息。传输层使用端口号进行寻址，端口号范围从 1 到 65,535。从 0 到 1,023 的端口号被称为**众所周知的端口**。256 以下的数字保留用于在应用层上运行的公共服务。

+   **互联网层**添加 IP 地址，说明数据的来源和去向。它是将网络连接在一起的“胶水”。它允许数据的发送、接收和路由。

+   **链接层**添加**媒体访问控制**（**MAC**）地址信息，以指定消息来自哪个硬件设备，消息将要传送到哪个硬件设备。MAC 地址在接口制造时固定，并且无法更改。

所有客户端-服务器协议都在应用层操作。应用层协议规定了基本的通信模式。为了使数据交换格式得到正式化，服务器实现了一个**应用程序接口**（**API**），比如一个网络服务。API 是资源（比如数据库和自定义软件）的抽象层。**超文本传输协议**（**HTTP**）是实现**万维网**（**WWW**）的应用层协议。虽然网络本身有许多不同的方面，但 HTTP 的主要目的是将超文本文档和其他文件从网络服务器传输到网络客户端。

# Web API

Web 客户端和服务器资产之间的交互是通过定义的接口**Web API**进行的。它是一种服务器架构方法，为不同类型的消费者提供可编程接口。Web API 通常被定义为一组 HTTP 请求和响应消息。一般来说，回复消息的结构以**可扩展标记语言**（**XML**）或**JavaScript 对象表示**（**JSON**）格式表示。

在 Web 1.0 时代，Web API 是**简单对象访问协议**（**SOAP**）为基础的网络服务和**面向服务的架构**（**SOA**）的同义词。在 Web 2.0 中，这个术语正在向**表述状态转移**（**REST**）风格的网络资源和**面向资源的架构**（**ROA**）转变。

# REST

REST 是万维网的一种架构风格，用于设计网络应用程序。REST 没有标准或 W3C 推荐。REST 这个术语是由 Roy Fielding 在他的博士论文中于 2000 年引入和定义的。后来，他使用 REST 设计了 HTTP 1.1 和统一资源标识符（URIs）。

作为一种编程方法，REST 是：

+   与平台无关，因此服务器可以安装在 Linux、Windows 等上。

+   与语言无关，因此我们可以使用 C＃、Java、JavaScript 等。

+   基于标准，并且可以在 HTTP 标准之上运行。

REST 使用简单的 HTTP 协议在客户端和服务器之间进行调用，而不是使用复杂的机制，如远程过程调用（RPC）、公共对象请求代理体系结构（CORBA）或 SOAP。任何调用 RESTful 的应用程序都符合 REST 的约束：

+   客户端-服务器约束意味着客户端和服务器是分离的，因此它们可以独立替换和开发。

+   客户端和服务器的通信基于无状态约束，因此在请求之间服务器上没有存储客户端上下文，每个请求都包含了服务请求所需的所有信息。

+   可缓存约束定义了服务器响应是否必须隐式或显式地标记自己为可缓存或不可缓存。

+   遵守层系统约束，客户端和服务器使用分层架构来提高整个系统的能力和可扩展性

+   服务器可以遵循代码应请求可选约束，通过传输可执行代码（如 JavaScript）来自定义客户端的功能。

RESTful 应用程序使用 HTTP 请求进行所有四个 CRUD（创建、读取、更新和删除）操作。REST 不包括安全性、加密、会话管理等，但我们可以在 HTTP 的基础上构建它们。

让我们看一个典型的端点，我们用来读取产品：`http://localhost:9000/product/123`。

只需使用简单的 HTTP GET 请求将 URL 发送到服务器。这里的“产品”是 URL 中的资源。在 REST 设计中有一个标准约定，即使用名词来标识资源。REST 可以处理更复杂的请求，比如：`http://localhost:3000/products?category=1`。

如果需要，我们可以利用 HTTP 的 POST 方法在 POST 主体内发送长参数或二进制数据。

## REST 响应格式

大多数情况下，服务器以 XML、**逗号分隔值**（**CSV**）或 JSON 格式响应 REST。选择取决于格式的优势：

+   XML 易于扩展和类型安全

+   CSV 非常紧凑

+   JSON 易于解析

## REST 和 AJAX

我们使用**异步 JavaScript 和 XML**（**AJAX**）客户端技术来创建异步 Web 应用程序。AJAX 使用`XMLHttpRequest`对象向服务器发送请求以动态更改网页。AJAX 和 REST 请求类似。

## REST API 设计指南

我们需要采取下一步来创建适当的 REST API 吗？这个问题没有简单的答案，因为没有一个被广泛采用的标准适用于所有情况，我建议我们从微软 REST API 指南等知名来源获取答案，可在以下网址找到：[`github.com/Microsoft/api-guidelines`](https://github.com/Microsoft/api-guidelines)。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# HttpModule

到目前为止，我们只开发了应用程序的前端，因此它几乎没有用。我们需要一个地方来存储我们的产品和类别，以便以后可以获取它们。为此，我们将连接到一个服务器，该服务器将承载提供 JSON 的 RESTful API。

Angular 2 默认包含`HttpModule`来组织一些低级方法来获取和发布我们的数据。

要在我们的项目中使用新的`HttpModule`，我们必须将其导入为一个名为`@angular/http`的单独的附加模块，作为 Angular npm 包的一部分，以单独的脚本文件的形式提供。我们在`systemjs.config.js`文件中导入`@angular/http`，配置`SystemJS`在需要时加载该库：

```ts
var ngPackageNames = [ 
    'common', 
    'compiler', 
    'core', 
    'forms', 
 **'http',** 

    'platform-browser', 
    'platform-browser-dynamic', 
    'router', 
    'router-deprecated', 
    'upgrade', 
  ]; 

```

我们的应用程序将从应用程序的任何地方访问`HttpModule`服务，因此我们应该通过将`HttModule`添加到`AppModule`的`imports`列表中来注册它们。引导之后，所有`HttpModule`服务都将对`AppComponent`的根级别可用：

```ts
import {NgModule} from '@angular/core'; 
import {BrowserModule} from '@angular/platform-browser'; 
import {FormsModule, ReactiveFormsModule} from '@angular/forms'; 
 **import {HttpModule} from '@angular/http';** 

/** 
 * Modules 
 */ 
import {CartModule} from './cart/cart.module'; 
import {CategoryModule} from './category/category.module'; 
import {ProductModule} from './product/product.module'; 

/* 
 * Components 
 */ 
import {AppComponent}  from './app.component'; 
import {NavbarComponent} from './navbar/navbar.component'; 
import {FooterComponent} from './footer/footer.component'; 
import {WelcomeComponent} from './welcome/welcome.component'; 
import {CheckoutViewComponent} from 
'./checkout/checkout-view.component'; 

/* 
 * Routing 
 */ 
import {routing}  from './app.routes'; 

@NgModule({ 
  imports: [ **HttpModule** 

, BrowserModule, FormsModule, 
            ReactiveFormsModule, routing, CartModule, 
            CategoryModule, ProductModule], 
  declarations: [AppComponent, NavbarComponent, FooterComponent, 
                WelcomeComponent, CheckoutViewComponent], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { } 

```

# 内存中的 Web API

因为我们没有一个真正能处理我们请求的网络服务器，我们将使用模拟服务来模仿真实服务器的行为。这种方法具有以下优点：

+   它快速地创建 API 设计和新的端点。**服务模拟**使您能够使用**测试驱动开发**（**TDD**）。

+   它在团队成员之间共享 API。我们不会因为前端团队等待其他团队完成而停机。这种方法使得模拟的财务论点异常高。

+   它控制模拟响应和性能条件。我们可以使用模拟来创建概念验证，作为线框图或演示，因此它们非常具有成本效益。

它有一些我们应该知道的缺点：

+   我们必须做双倍的工作，有时这意味着相当多的工作

+   如果需要在某个地方部署它，它有部署约束

+   模拟代码容易出现错误

+   模拟只是对所模拟的东西的一种表示，它可能会误导真实的服务

内存 Web API 是`angular-in-memory-web-api`库中的一个可选服务。它不是 Angular 2 的一部分，因此我们需要将其安装为单独的 npm 包，并在`systemjs.config.js`文件中通过`SystemJS`进行模块加载注册：

```ts
// map tells the System loader where to look for things 
var map = { 
    'app':      'app', 
    'rxjs':     'node_modules/rxjs', 
    **'angular-in-memory-web-api': 
                 'node_modules/angular-in-memory-web-api',** 

    '@angular': 'node_modules/@angular' 
  }; 

  // packages tells the System loader how to load when no filename 
  // and/or no extension 
  var packages = { 
    'app':  { main: 'main.js',  defaultExtension: 'js' }, 
    'rxjs': { defaultExtension: 'js' }, 
    **'angular-in-memory-web-api': 
             { main: 'index.js', defaultExtension: 'js' },** 

  }; 

```

接下来，我们需要创建一个实现`InMemoryDbService`的`InMemoryDataService`类，以创建一个内存数据库：

```ts
import {InMemoryDbService} from 'angular-in-memory-web-api'; 

import {Category} from './category/category.service'; 
import {Product} from './product/product.service'; 

export class InMemoryDataService implements InMemoryDbService { 
  createDb() { 
    let categories: Category[] = [ 
        { id: '1', title: 'Bread & Bakery', 
          imageL: 'http://placehold.it/1110x480', 
          imageS: 'http://placehold.it/270x171', 
          desc: 'The best cupcakes, cookies, cakes, pies, 
                 cheesecakes, fresh bread, biscotti, muffins, 
                 bagels, fresh coffee and more.' }, 
        { id: '2', title: 'Takeaway', 
          imageL: 'http://placehold.it/1110x480', 
          imageS: 'http://placehold.it/270x171', 
          desc: 'It's consistently excellent, dishes are superb 
                 and healthily cooked with high quality 
                 ingredients.' }, 
                       // ... 
]; 

    let products: Product[] = [ 
        // Bakery 
        { id: '1', categoryId: '1', title: 'Baguette', 
          price: 1.5, isSpecial: false, 
          imageL: 'http://placehold.it/1110x480', 
          imageS: 'http://placehold.it/270x171', 
          desc: 'Great eaten fresh from oven. Used to make sub 
          sandwiches, etc.' }, 
        { id: '2', categoryId: '1', title: 'Croissants', 
          price: 0.5, isSpecial: true, 
          imageL: 'http://placehold.it/1110x480', 
          imageS: 'http://placehold.it/270x171', 
          desc: 'A croissant is a buttery, flaky, 
                 viennoiserie-pastry named for its well-known 
                 crescent shape.' }, 
        // 
    ];   
    return { 
      categories, 
      products 
    }; 
  } 
} 

```

`createDb`方法应该创建一个*数据库*对象哈希，其键是集合名称，其值是组对象的数组。可以安全地再次调用它，因为它返回具有新对象的新数组。这允许`InMemoryBackendService`在不触及源数据的情况下改变数组和对象。我将这个文件中的数据集从`ProductService`和`CategoryService`中移动过来。

与`HttModule`类似，我们正在将`InMemoryWebApiModule`和`InMemoryDataService`导入到`AppModule`的`imports`列表中。它们替换了内存 Web API 替代服务中的默认`Http`客户端后端：

```ts
import {HttpModule} from '@angular/http'; 
// Imports for loading & configuring the in-memory web api 
import { **InMemoryWebApiModule** 

} from 'angular-in-memory-web-api'; 
import { **InMemoryDataService** 

}  from './in-memory-data.service'; 
And finally, we need to link the InMemoryWebApiModule to use the InMemoryDataService: 
@NgModule({ 
  imports: [HttpModule, 
           **InMemoryWebApiModule.forRoot(InMemoryDataService),** 

            BrowserModule, FormsModule, ReactiveFormsModule, 

```

`forRoot`方法在根应用程序模块中准备内存 Web API，以在引导时创建内存数据库。它有一个`InMemoryBackendConfigArgs`类型的第二个参数，并保留`InMemoryBackend`配置选项，例如延迟（以毫秒为单位）以模拟延迟，为此服务的主机等。

现在一切准备就绪，可以更改`ProductService`和`CategoryService`，以开始使用`HTTP`服务。

# HTTP 客户端

Angular **HTTP 客户端**通过 HTTP 协议的 AJAX 请求与服务器通信。我们项目的组件将永远不会直接与 HTTP 客户端服务通信。我们将数据访问委托给服务类。让我们按照以下所示更新`ProductService`中的导入：

```ts
import {Injectable} from '@angular/core'; 
 **import {Headers, Http, Response} from '@angular/http';** 

import 'rxjs/add/operator/toPromise'; 

```

接下来，使用`Http`服务获取产品：

```ts
getProducts(category?:string, search?:string):Promise<Product[]> { 
  let url = this.productsUrl; 
  if (category) { 
    url += `/?categoryId=${category}`; 
  } else if (search) { 
    url += `/?title=${search}`; 
  } 
  return this.http 
   .get(url) 
   .toPromise() 
   .then((response:Response) => response.json().data as Product[]) 
   .catch(this.handleError); 
 } 

```

如您所见，我们使用标准的 HTTP GET 请求来获取产品集。`InMemoryWebApiModule`非常聪明地理解了请求 URL 中的查询参数。在这里，`ProductGridComponent`利用`ProductService`在网页上显示我们的产品网格：

```ts
@Component({ 
    selector: 'db-product-grid', 
    templateUrl: 'app/product/product-grid.component.html' 
}) 
export class ProductGridComponent implements OnInit { 
  **products: any = [];** 

    constructor(private route: ActivatedRoute, 
                private productService: ProductService, 
                private cartService: CartService) {} 

    ngOnInit(): void { 
        this.route 
            .queryParams 
            .subscribe(params => { 
                let category: string = params['category']; 
                let search: string = params['search']; 
                // Clear view before request 
                this.products = []; 
                // Return filtered data from getProducts function 
                this.productService.getProducts(category, search) 
               **.then((products: Product[]) => {** 

                    // Transform products to appropriate data 
                    // to display 
                    this.products = this.transform(products); 
                }); 
            }); 
    } 
    // 
} 

```

这里的`products`属性只是一个产品数组。我们使用简单的`NgFor`指令来遍历它们：

```ts
<db-product-card ***ngFor="let row of products"** 

    [products]="row" (addToCart)="addToCart($event)"> 
</db-product-card> 

```

由于类别数据的性质不同，`CategoryService`中的源代码更改有些不同。类别集是静态的，所以我们不需要每次都获取它们，可以将它们保存在`CategoryService`内的缓存中：

```ts
@Injectable() 
export class CategoryService { 
    // URL to Categories web api 
    private categoriesUrl = 'app/categories'; 
    // We keep categories in cache variable 
   **private categories: Category[] = [];** 

    constructor(private http: Http) {} 

    getCategories(): Promise<Category[]> { 
      return this.http 
          .get(this.categoriesUrl) 
          .toPromise() 
          .then((response: Response) => { 
             this.categories = response.json().data as Category[]; 
             return this.categories; 
          }) 
          .catch(this.handleError); 
    } 

    getCategory(id: string): Category { 
        for (let i = 0; i < this.categories.length; i++) { 
            if (this.categories[i].id === id) { 
                return this.categories[i]; 
            } 
        } 
        return null; 
    } 

    private handleError(error: any): Promise<any> { 
        window.alert(`An error occurred: ${error}`); 
        return Promise.reject(error.message || error); 
    } 
} 

```

在`getCategory`方法中，我们可以很容易地通过 ID 找到类别，因为我们只是从缓存中获取它。

# HTTP 承诺

仔细看看我们如何从 HTTP GET 请求中返回数据。我们在`Http`类的`get`方法之后立即使用`toPromise`方法：

```ts
getCategories(): Promise<Category[]> { 
      return this.http 
          .get(this.categoriesUrl) 
          **.toPromise()** 

          .then((response: Response) => { 
             this.categories = response.json().data as Category[]; 
             return this.categories; 
          }) 
          .catch(this.handleError); 
} 

```

那么，为什么我们需要这个方法，它到底是做什么的呢？

几乎所有的`Http`服务方法都返回 RxJS`Observable`。可观察对象是管理异步数据流的强大方式。要将 RxJS`Observable`转换为`Promise`，我们使用`toPromise`操作符。它只是立即获取单个数据块并立即返回。在使用`toPromise`操作符之前，我们需要隐式从 RxJS 导入它，因为该库非常庞大，我们应该只包含我们需要的功能：

```ts
import 'rxjs/add/operator/toPromise'; 

```

让我们谈谈`Observable`以及为什么`Http`在各处使用它们。

### 提示

您可以在`chapter_9/2.ecommerce-promise`找到此源代码。

# RxJS 库

**RxJS**是微软与许多开源开发人员合作积极开发的项目。它是一组组织为异步和基于事件的编程 API 的库。我们使用可观察对象来表示异步数据流。有许多操作符来查询和调度器来参数化它们的并发性。简而言之 - RxJS 是观察者和迭代器模式以及函数式编程的结合。

在使用之前，我们可以导入所有核心模块：

```ts
import * as Rx from 'rxjs/Rx';
```

如果你关心应用程序的大小，最好只导入必要的功能：

```ts
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/map';

Observable.of(1,2,3).map(x => x * x); // Result: [1, 4, 9]
```

RxJs 非常庞大，我建议参考官方网站了解更多：[`reactivex.io`](http://reactivex.io)

# 可观察对象与承诺

在我们的日子里，**可观察对象**是 JavaScript 版本 ES2016（ES7）的一个提议功能，因此我们使用 RxJS 作为填充库将它们引入项目，直到下一个新版本的 JavaScript 发布。Angular 2 对可观察对象有基本支持，我们使用 RxJS 来扩展这个功能。Promise 和可观察对象提供了帮助我们处理应用程序异步特性的抽象，有一些关键的区别：

+   可观察对象随时间发出多个值，与只能返回一个值或错误的 Promise 相反

+   可观察对象被视为数组，并允许我们使用操作符、类似集合的方法来操作值

+   可观察对象可以被取消

+   可观察对象可以使用重试操作符之一进行重试

因此，我们特别使用`toPromise`将请求的数据流转换为单个值。我们真的需要吗？我对项目进行了一些更改，以向您展示在 Angular 2 应用程序中如何轻松使用可观察对象。只需查看`ProductService`的修改版本：

```ts
getProducts(category?:string,search?:string):Observable<Product[]>{ 
  let url = this.productsUrl; 
  if (category) { 
    url += `/?categoryId=${category}`; 
  } else if (search) { 
    url += `/?title=${search}`; 
  } 
  return this.http 
    .get(url) 
    .map((response:Response) => response.json().data as Product[]) 
    .catch(this.handleError); 
} 

getProduct(id: string): Observable<Product> { 
  return this.http 
    .get(this.productsUrl + `/${id}`) 
    .map((response: Response) => response.json().data as Product) 
    .catch(this.handleError); 
} 

```

我们在上面的代码中使用了 RxJS 包中的几个转换操作符，所以不要忘记从包中导入它们。RxJS 中有许多操作符，可以帮助我们组织不同类型的转换：

+   `map`操作符通过对每个项目应用函数来转换项目。

+   `flatMap`，`concatMap`和`flatMapIterable`操作符将项目转换为可观察对象或可迭代对象，并将它们展平为一个。

+   `switchMap`操作符将项目转换为可观察对象。最近转换的可观察对象发出的项目将被镜像。

+   `scan`操作符依次对每个发出的项目应用函数，以仅发出连续的值。

+   `groupBy`操作符帮助按键划分和组织可观察对象，以从原始对象中发出项目组。

+   `buffer`操作符将发出的项目组合成包。它发出包而不是一次发出一个项目。

+   **cast**将源可观察对象中的所有项目转换为特定类型，然后重新发出它们。

RxJS 非常庞大，我建议从官方网站开始学习更多关于它的知识：[`github.com/Reactive-Extensions/RxJS`](https://github.com/Reactive-Extensions/RxJS)。

成功的请求返回`Response`类的实例。响应数据以 JSON 字符串格式返回，因此我们必须通过调用`Response`类的`json`方法将该字符串解析为 JavaScript 对象。通常情况下，我们应该处理错误，因为我们必须为可能出错的情况做好准备。我们通过调用我们的类的`handleError`方法来捕获错误。请记住，我们必须将错误转换为用户友好的消息，并通过`Observable.throw`返回一个新的失败的 observable：

```ts
private handleError(error: any): Promise<any> { 
    window.alert(`An error occurred: ${error}`); 
    return Promise.reject(error.message || error); 
} 

```

在网页上显示 Observable 数据有两种不同的技术。第一种方法是组织 Observable 数据的订阅，如下所示：

```ts
ProductViewComponent: 
@Component({ 
    selector: 'db-product-view', 
    templateUrl: 'app/product/product-view.component.html' 
}) 
export class ProductViewComponent implements OnInit { 

   **product: Product;** 

    constructor(private route: ActivatedRoute, 
                private productService: ProductService, 
                private cartService: CartService) { } 

    ngOnInit(): void { 
        this.route 
            .params 
            .subscribe(params => { 
                // Get the product id 
                let id: string = params['id']; 
                // Return the product from ProductService 
               **this.productService.getProduct(id) 
                   .subscribe((product:Product) => 
                     this.product = product);** 

                // Return the cart item 
                this.cartItem = this.cartService.findItem(id); 
            }); 
    } 
  } 
} 

```

我们订阅了在`ProductService`中发生的所有变化，并立即将它们分配给`product`属性，因此 Angular 将它们传递到模板中。

另一种方法是将 Observable 结果转发到模板中，如下所示：

```ts
ProductGridComponent: 
@Component({ 
    selector: 'db-product-grid', 
    templateUrl: 'app/product/product-grid.component.html' 
}) 
export class ProductGridComponent implements OnInit { 
    **products: Observable<Product[]>;** 

    constructor(private route: ActivatedRoute, 
                private productService: ProductService, 
                private cartService: CartService) {} 

    ngOnInit(): void { 
        this.route 
            .queryParams 
            .debounceTime(300) // wait for 300ms pause in events 
            .subscribe(params => { 
                let category: string = params['category']; 
                let search: string = params['search']; 
               **this.products = this.productService 
                                .getProducts(category, search) 
                                .map(this.transform);** 

            }); 
    } 
    // 
} 

```

然后，我们通过`product`属性将 Observable 结果转发到模板，其中`NgFor`中的`async`管道处理订阅：

```ts
<db-product-card ***ngFor="let row of products | async"** 

      [products]="row" (addToCart)="addToCart($event)"> 
</db-product-card> 

```

有时，我们可能需要开始一个请求，然后取消它，并在服务器对第一个请求做出响应之前进行不同的请求。使用 Promises 来实现这样的顺序是复杂的，所以让我们看看 Observables 如何帮助我们。

# 搜索标题中的 Observables

我们有一个按标题搜索产品的功能。用户输入标题，然后按下**Go**按钮从服务器请求数据。我们可以在这里改善用户体验，当用户在搜索框中输入标题时，我们将重复进行产品的 HTTP 请求，以标题进行过滤。看一下`ProductSearchComponent`的更新标记：

```ts
<div class="card"> 
    <div class="card-header">Quick Shop</div> 
    <input #search type="text" class="form-control" 
           placeholder="Search for..." 
           (keyup)="searchProduct(search.value)"> 
</div> 

```

我们移除了**Go**按钮。输入元素从用户那里收集搜索标题，并在每次`keyup`事件后调用`searchProduct`方法。`searchProduct`方法更新 URL 的查询参数：

```ts
@Component({ 
    selector: 'db-product-search', 
    templateUrl: 'app/product/product-search.component.html' 
}) 
export class ProductSearchComponent { 

    constructor(private router: Router) {} 

   **searchProduct(value: string) { 
      this.router.navigate(['/products'], { 
        queryParams: { search: value} });** 

 **}** 

} 

```

`ProductGridComponent`监听`route`中查询参数变化的流，并在到达`productService`之前操作流：

```ts
ngOnInit(): void { 
 **this.route 
        .queryParams 
        .debounceTime(300) // wait for 300ms pause in events 
        .distinctUntilChanged() // only changed values pass 
        .subscribe(params => {** 

            let category: string = params['category']; 
            let search: string = params['search']; 
            this.products = this.productService 
                            .getProducts(category, search) 
                            .map(this.transform); 
        }); 
} 

```

在前面的代码中，我们使用`debounceTime`操作符等待用户停止输入至少 300 毫秒。只有改变的搜索数值通过`distinctUntilChanged`操作符传递到服务端。之后，我们获取类别和搜索查询参数，并从`productService`请求产品。

我们可以快速启动服务器并在浏览器中打开我们的 Web 应用程序，以检查所有内容是否按预期工作。从那时起，我们可以向同事或利益相关者展示我们的项目，作为我们将来开发中使用的概念验证。

接下来，我们需要一个真正的数据库和托管服务器来完成开发，并在真实环境中测试所有内容。让我们使用 Firebase 实时存储和同步我们的数据，并更快地提供 Web 内容。

### 提示

您可以在`chapter_9/3.ecommerce-promise`找到此源代码。

# Firebase 简介

Firebase 是一个实时的 NoSQL JSON 数据库。任何数据都可以通过 URL 访问。Firebase 包含不同平台的 SDK，比如 Web 的 JavaScript，IOS，Android 等。它包括身份验证内置在核心库中，因此我们可以通过 GitHub、Google、Twitter 和 Facebook 提供的 OAuth 直接从客户端快速验证用户。它还支持匿名和密码验证。Firebase 通过 Firebase 控制台或 CLI 提供静态资产的托管服务。Firebase 使用 Web 套接字实时更新所有连接的客户端上的数据。

如果您以前从未使用过 Firebase，您需要先注册一个帐户。打开您的 Web 浏览器，转到[`firebase.google.com/`](https://firebase.google.com/)。点击“登录”并使用您的 Google 帐户设置您的 Firebase 帐户。

## 创建 Firebase 项目

我们计划使用 Firebase SDK 库来访问和存储数据。但在此之前，我们需要将 Firebase 添加到我们的 Web 应用程序中。我们需要一个 Firebase 项目、Firebase SDK 和一个关于我们项目的一些细节的初始化代码片段。点击“转到控制台”或从以下地址打开“Firebase 控制台”：[`firebase.google.com/console`](https://firebase.google.com/console)。

点击“创建新项目”按钮，添加项目名称和您的原籍国：

![创建 Firebase 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00135.jpg)

不到一分钟，我们将可以访问 Firebase 相关的数据库、身份验证、存储等。

## 安装 Firebase CLI 工具

我们将使用 Firebase CLI 工具从终端管理、查看和部署我们的项目到 Firebase。让我们打开终端，转到我们的项目，并运行以下命令：

```ts
 **npm install -g firebase-tools** 

```

安装后，我们将拥有一个全局可用的 Firebase 命令。现在，我们可以从终端登录到 Firebase。请记住，您必须已经设置了 Google 账户才能继续：

```ts
 **firebase login** 

```

这个命令建立了与远程 Firebase 账户的连接，并授予了我们对项目的访问权限：

![安装 Firebase CLI 工具](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00136.jpg)

如果您想知道 Firebase CLI 支持哪些命令，请访问官方网站：[`firebase.google.com/docs/cli/`](https://firebase.google.com/docs/cli/)。

## 初始化项目目录

我们将使用 Firebase CLI 执行许多琐碎的任务，比如运行本地服务器或部署。在使用之前，我们需要为包含`firebase.json`文件的文件夹初始化项目目录。通常我们使用 Angular 项目的根文件夹作为 Firebase 项目目录。打开终端，导航到我们项目的根文件夹，并执行以下命令：

```ts
 **firebase init** 

```

这个命令将引导您设置项目目录。如果需要，您可以安全地再次运行此命令。

![初始化项目目录](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00137.jpg)

请回答“是”以回答问题：“配置为单页应用程序（将所有 URL 重写为/index.html）？” Firebase CLI 会在`firebase.json`文件中创建`rewrites`设置。我们使用重写是因为我们希望为多个 URL 显示相同的内容。这适用于我们的应用程序，因为我们使用默认的 HTML 5 `pushState`策略配置了 Angular 组件路由。它生成了用户更容易理解的 URL，并保留了以后进行服务器端渲染的选项。

## 将数据导入 Firebase

在使用之前，我们需要将我们的数据导入 Firebase 数据库。打开 Firebase 控制台，找到您的项目，然后点击移动它：

![将数据导入 Firebase](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00138.jpg)

在侧边栏上找到**数据库**菜单项并点击。这将把 Firebase 实时数据库实例带到舞台上。点击右侧的上下文菜单按钮，从下拉菜单中选择**导入 JSON**。我已经准备好了`firebase.import.json`文件供导入，所以只需从项目的根文件夹中选择它，然后点击**导入**：

![将数据导入 Firebase](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00139.jpg)

Firebase 实时数据库将数据存储为 JSON 对象。它看起来像是一个托管在云端的 JSON 树。与 SQL 数据库相反，这里没有表或记录。每个添加到 JSON 树中的数据都成为现有 JSON 结构中的一个节点，并带有关联的键。我们可以提供自己的键，例如`category`或`product` ID，或者 Firebase 可以在我们使用 POST 请求保存数据时为我们提供它们。

### 注意

键必须采用 UTF-8 编码，长度不能超过 768 字节。它们不能包含.，$，#，[，]，/或 ASCII 控制字符，如 0-31 或 127。

Dream Bean 网站的数据结构非常简单，只包含两个实体，具有产品到类别的关系。Firebase 实时数据库支持嵌套数据，最多可以深达 32 级，最初的诱惑是将`category`添加到`product`中，但要小心，因为当您稍后检索数据时，Firebase 将返回产品及其所有子节点。此外，当我们尝试授予某人对节点的读取或写入访问权限时，会遇到麻烦。这里的最佳解决方案是对数据进行去规范化，以尽可能保持结构的扁平化。我们可以遵循以下建议：

+   将数据拆分为单独的路径

+   向数据添加索引或键

+   使用索引或键来获取关联数据

在开始阶段，我们故意将`categoryId`添加到产品实体中，以便通过索引快速高效地获取数据：

![将数据导入 Firebase](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00140.jpg)

## Firebase 数据库规则

Firebase 始终为每个新数据库创建默认规则：

![Firebase 数据库规则](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00141.jpg)

Firebase 实时数据库的规则非常灵活且基于表达式。我们可以使用类似 JavaScript 的语言来定义：

+   数据结构

+   数据索引

+   使用 Firebase 身份验证服务保护数据

默认情况下，数据库规则要求 Firebase 身份验证并仅授予完全读写权限给经过身份验证的用户，因此它对每个人都不可访问。我们将更改规则以使每个人都可以读取，但保持写入权限给经过身份验证的用户。规则可以以两种不同的方式进行配置。创建立即生效的最简单方法是使用 Firebase 控制台，因此让我们打开它，从侧边栏中选择**数据库**菜单，然后选择**规则**选项卡。您应该看到带有当前规则的文本区域。您可以手动更改它们，或者复制以下规则并粘贴到文本区域中：

```ts
{ 
  "rules": { 
 **".read": true,** 

    ".write": "auth != null" 
  } 
} 

```

单击**发布**以将新规则应用于数据库。管理数据库规则的另一种方法是创建一个特殊的 JSON 文件，这样当我们将项目部署到 Firebase 时，Firebase CLI 将使用这个文件。打开终端，进入我们的项目并运行以下命令：

```ts
 **firebase init** 

```

现在，选择**数据库：部署 Firebase 实时数据库规则**选项。对所有问题保持默认答案：

![Firebase 数据库规则](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00142.jpg)

打开`database.rules.json`并更新它：

```ts
{ 
  "rules": { 
    **".read": true,** 

    ".write": "auth != null" 
  } 
} 

```

现在，一旦数据被导入到数据库，就该将我们的项目连接到它了。

# 连接到 Firebase

为了组织通信，我们需要**AngularFire2**库来将 Firebase 实时观察者和身份验证与 Angular2 集成。

## 安装 AngularFire2 和 Firebase

首先，将 AngularFire2 和 Firebase SDK 库安装为 npm 模块：

```ts
 **npm install -save angularfire2 firebase** 

```

下一步是在本地安装 Typescript 2，因为 AngularFire2 依赖于它：

```ts
 **npm install -save-dev typescript@2.0.0** 

```

现在，使用这两个库更新`systemjs.config.js`文件，因为它们需要与`SystemJS`进行映射以进行模块加载：

```ts
// map tells the System loader where to look for things 
var map = { 
    'app':          'app', 
    'rxjs':         'node_modules/rxjs', 
    '@angular':     'node_modules/@angular', 
    **'firebase':     'node_modules/firebase', 
    'angularfire2': 'node_modules/angularfire2'** 

  }; 

// packages tells the System loader how to load 
// when no filename and/or no extension 
var packages = { 
 'app':          {main: 'main.js',  defaultExtension: 'js'}, 
 'rxjs':         {defaultExtension: 'js'}, 
 **'firebase':      {main: 'firebase.js', defaultExtension: 'js'}, 
 'angularfire2':  {main: 'angularfire2.js', defaultExtension: 'js'}** 

}; 

```

## AngularFire2 和 Firebase 设置

在使用之前，我们需要设置 AngularFire2 模块和 Firebase 配置。打开`app.module.ts`文件并导入`AngularFireModule`。现在打开 Web 浏览器，导航到 Firebase 控制台，并选择您的项目（如果尚未打开）。接下来，单击**将 Firebase 添加到您的应用程序**链接：

![AngularFire2 和 Firebase 设置](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00143.jpg)

Firebase 创建了初始化代码片段，我们将在我们的应用程序中使用：

![AngularFire2 和 Firebase 设置](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00144.jpg)

选择初始化配置并复制到剪贴板。切换回我们的项目并粘贴，这样我们的代码将如下所示：

```ts
/* 
 * Angular Firebase 
 */ 
import {AngularFireModule} from 'angularfire2'; 
 **// Initialize Firebase 
export var firebaseConfig = { 
  apiKey: "AIzaSyDDrc42huFLZqnG-pAg1Ly9VnFtVx3m-Cg", 
  authDomain: "ecommerce-a99fc.firebaseapp.com", 
  databaseURL: "https://ecommerce-a99fc.firebaseio.com", 
  storageBucket: "ecommerce-a99fc.appspot.com", 
};** 

@NgModule({ 
  imports: [HttpModule, 
           **AngularFireModule.initializeApp(firebaseConfig),** 

            BrowserModule, FormsModule, ReactiveFormsModule, 
            routing, CartModule, CategoryModule, ProductModule], 
  declarations: [AppComponent, NavbarComponent, FooterComponent, 
                WelcomeComponent, CheckoutViewComponent], 
  bootstrap: [AppComponent] 
}) 
export class AppModule { } 

```

我们准备在我们的项目中使用 Firebase。

## 从 Firebase 获取类别

AngularFire2 通过`FirebaseListObservable`将数据同步为列表，因此打开`category.service.ts`文件并导入它： 

```ts
import {Injectable} from '@angular/core'; 
 **import {AngularFire, FirebaseListObservable} from 'angularfire2';** 

import {Observable} from 'rxjs/Observable'; 
import 'rxjs/add/operator/catch'; 
// 
@Injectable() 
export class CategoryService { 

    // URL to Categories Firebase api 
    private categoriesUrl = 'categories'; 
    // We keep categories in cache variable 
    private categories: Category[] = []; 

 constructor( **private af: AngularFire** 

) {} 

    getCategories(): Observable<Category[]> { 
      **return this.af.database 
            .list(this.categoriesUrl) 
            .catch(this.handleError);** 

    } 

    getCategory(id: string): Category { 
        for (let i = 0; i < this.categories.length; i++) { 
            if (this.categories[i].id === id) { 
                return this.categories[i]; 
            } 
        } 
        return null; 
    } 

    // 
} 

```

我们将`AngularFire`服务注入到构造函数中。通过`AngularFire.database`服务创建`FirebaseListObservable`，我们在`getCategories`方法中使用相对 URL 进行调用。

## 从 Firebase 获取产品

对于获取产品数据来说情况就不同了。仅有一个 URL 是不够的，我们需要使用查询参数。`AngularFire.database`服务的列表方法有一个第二个参数对象，我们可以用它来指定查询参数：

```ts
import {Injectable} from '@angular/core'; 
import {AngularFire, FirebaseListObservable} from 'angularfire2'; 
 **import {Observable} from 'rxjs/Observable';** 

import 'rxjs/add/operator/catch'; 
import 'rxjs/add/observable/empty'; 
//... 
export class ProductService { 

    // URL to Products web api 
    private productsUrl = 'products'; 

    constructor( **private af: AngularFire** 

) {} 

    getProducts(category?: string, search?: string): 
           Observable<Product[]> { 
        if (category || search) { 
            let query = <any>{}; 
            if (category) { 
                query.orderByChild = 'categoryId'; 
                query.equalTo = category; 
            } else { 
                query.orderByChild = 'title'; 
                query.startAt = search.toUpperCase(); 
                query.endAt = query.startAt + '\uf8ff'; 
            } 
            return **this.af.database 
                .list(this.productsUrl, { 
                    query: query 
                })** 

                .catch(this.handleError); 
        } else { 
            return Observable.empty(); 
        } 
    } 

    getProduct(id: string): Observable<Product> { 
        return this.af.database 
            .object(this.productsUrl + `/${id}`) 
            .catch(this.handleError); 
    } 
   //... 
} 

```

我们使用 Firebase 实时数据库查询有选择地检索基于各种因素的数据。要为`products`构建查询，我们首先指定如何使用其中一个排序函数对数据进行排序：

+   `orderByChild`按子键检索排序的节点

+   `orderByKey`按其键检索排序的节点

+   `orderByValue`按其子节点的值检索排序的节点

+   `orderByPriority`按优先级值检索排序的节点

指定子键的`orderByChild`函数的结果将按以下顺序排序：

+   具有空值的子节点

+   具有 false 布尔值的子节点

+   具有 true 布尔值的子节点

+   具有按升序排序的数值的子节点

+   带有按字典顺序升序排序的字符串的子节点

+   具有按键名按升序排序的对象的子节点

### 注意

Firebase 数据库键只能是字符串。

`orderByKey`函数的结果将按键名升序返回：

+   可以解析为 32 位整数的键的子节点首先出现，并按升序排序

+   具有字符串值键的子节点紧随其后，并按字典顺序升序排序

`orderByValue`函数的结果将按其值排序。

### 注意

Firebase 数据库优先级值只能是数字和字符串。

`orderByPriority`函数的结果将是子节点的排序，由其优先级和键决定如下：

+   没有优先级的子节点按键排序

+   具有数字的子节点按数字顺序排序

+   带有字符串的子节点按字典顺序排序

+   具有相同优先级的子节点按键排序

在决定检索到的数据应该如何排序之后，我们可以使用限制或范围方法进行复杂的查询：

+   `limitToFirst` 创建一个查询，限制为第一组子元素

+   `limitToLast` 创建一个查询，限制为最后一组子元素

+   `startAt` 创建一个具有特定起始点的查询

+   `endAt` 创建一个具有特定结束点的查询

+   `equalTo` 创建一个具有特定匹配值的查询

我们使用 `limitToFirst` 和 `limitToLast` 查询来设置 Firebase 将返回的最大子元素数量。使用 `startAt` 和 `endAt` 查询帮助我们在 JSON 树中选择任意的起始点和结束点。`equalTo` 查询根据**精确匹配**过滤数据。

当我们选择类别时，我们基于组合创建一个查询，`orderByChild` 和 `equalTo`，因为我们知道 `categoryId` 的确切值来进行过滤：

```ts
let query = <any>{}; 
query.orderByChild = 'categoryId'; 
query.equalTo = category; 
return this.af.database 
    .list(this.productsUrl, { 
        query: query 
    }) 
    .catch(this.handleError); 

```

当用户通过输入标题进行搜索时，我们使用 `orderByChild`、`startAt` 和 `endAt` 的组合：

```ts
let query = <any>{}; 
query.orderByChild = 'title'; 
query.startAt = search.toUpperCase(); 
query.endAt = query.startAt + '\uf8ff'; 
return this.af.database 
    .list(this.productsUrl, { 
        query: query 
    }) 
    .catch(this.handleError); 

```

在前面的查询中使用的 `\uf8ff` 字符帮助我们创建一个技巧。它是 Unicode 范围内的一个非常高的值，因为它在大多数常规字符之后，所以查询匹配以用户输入值开头的所有值。

# 将应用程序部署到 Firebase

我们的应用只有静态内容，这意味着我们可以将其部署到 Firebase Hosting。我们可以用一条命令来做到这一点：

```ts
 **firebase deploy** 

```

Firebase CLI 将我们的 Web 应用部署到域名：`https://<your-firebase-app>.firebaseapp.com`。

我们可以从 Firebase 控制台管理和回滚部署：

![将应用程序部署到 Firebase](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/web-dev-bts4-ng2-2e/img/Image00145.jpg)

### 提示

您可以在 `chapter_9/4.ecommerce-firebase` 找到本章的源代码。

# 总结

在本章中，我们发现了数据持久性是什么，以及在客户端到服务器通信中它有多重要。我们从对 Web API 的简要介绍开始，然后深入研究 REST，以提醒主要原则。

我们看了 Angular 2 从 `HttpModule` 的离开，并讨论了如何使用它来组织客户端到服务器的通信。作为奖励，我们了解到我们可以使用内存 Web API 来创建概念验证、线框或演示。

可观察对象是 JavaScript 版本 ES2016（ES7）的一个提议特性，我们讨论了在 Angular 2 中使用 RxJS polyfill 库与可观察对象来帮助我们处理应用程序的异步特性。

Firebase 是一个实时的无 SQL JSON 数据库，可以通过 URL 访问任何数据。Firebase 包含不同平台的 SDK，比如 Web 的 JavaScript，IOS 和 Android。我们演示了如何将其用作应用程序的持久层。

在第十章中，*高级 Angular 技术*，我们将借助 Firebase 平台保护我们的数据。我们将学习如何安装`ng2-bootstrap`，以及这将如何使我们更容易地创建指令。最后，我们将结束在之前章节中开始开发的项目。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享
