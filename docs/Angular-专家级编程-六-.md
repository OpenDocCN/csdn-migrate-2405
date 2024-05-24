# Angular 专家级编程（六）

> 原文：[`zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9`](https://zh.annas-archive.org/md5/EE5928A26B54D366BD1C7A331E3448D9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：处理 Angular 动画

在本章中，我们将学习关于 Angular 动画。动画；这个词听起来很有趣和创造性，所以系好安全带；我们将乐在学习 Angular 动画。Web 应用程序中的动作是关键和重要的设计因素之一，也是良好用户体验的主要驱动因素。特别是过渡，它们非常有趣，因为它们使应用程序的元素从一个状态移动到另一个状态。

本章详细介绍以下主题：

+   介绍 Angular 动画

+   Angular 2 中内置的类来支持动画

+   理解和学习如何使用动画模块，`transition`，`states`，`keyframes`等

+   页面过渡动画

+   动画切换/折叠手风琴幻灯片

# 介绍 Angular 动画

Angular 自带了对动画的坚实本地支持，因为运动和过渡是任何应用程序的重要部分。

Angular 具有内置的动画引擎，还支持和扩展了运行在大多数现代浏览器上的 Web 动画 API。

我们必须在项目文件夹中单独安装 Angular 动画。我们将在接下来的部分中创建一些动画示例。

# 安装 Angular 动画库

正如我们之前讨论的，Angular 动画已经被分离出来作为一个单独的库，需要单独安装。

在这一部分，我们将讨论如何获取最新的 Angular 动画版本并安装它；按照以下步骤进行：

1.  获取最新的 Angular 动画库。

您可以使用以下`npm`命令进行安装：

```ts
npm install @angular/animations@latest --save

```

运行上述命令将保存最新版本的 Angular 动画库，并将其添加为`package.json`文件中的依赖项。

1.  验证最新安装的 Angular 动画库。

确保我们已经安装了 Angular 动画库，打开`package.json`文件，应该在依赖列表中有`@animations/animations`的条目。

一旦 Angular 动画库已经被正确导入和安装，`package.json`文件应该看起来像以下的截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/88d1a258-fd8a-4583-bc5f-bcf22acf8119.png)

1.  在`app.module.ts`文件中导入 Angular 动画库。

我们需要在`app.module.ts`文件中导入 Angular 动画库。为了包含该库，我们将使用以下代码片段：

```ts
import { BrowserAnimationsModule } from '@angular/platform-
   browser/animations';

```

1.  在`ngModule`装饰器的导入中包含 Angular 动画库：

```ts
@ngModule({
 imports: [
BrowserModule,
BrowserAnimationsModule
 ],
//other imports
})

```

在前面的代码片段中，我们只是将`BrowserAnimationsModule`导入到我们的`ngModule`中，以便在整个应用程序中使用。

太棒了！现在我们的应用程序中有了 Angular 动画库，我们可以继续像往常一样构建我们的组件，添加动画和效果。

在我们开始编写使用动画的组件示例之前，重要的是花一些时间探索 Angular 动画中所有可用的类，以便我们可以利用它们。

# Angular 动画 - 特定函数

如前所述，Angular 自带了一个独立的动画库，其中有许多内置类和方法来支持各种动画。

让我们了解本节中提供的各种内置类：

+   `trigger`

+   `transition`

+   `state`

+   `style`

+   `animate`

我们将详细学习上述每种方法，但在这之前，让我们快速看一下使用这些方法的一般语法。

编写动画的一般语法示例如下：

```ts

animations : [
 trigger('slideInOut', [
  state('in', style({
      transform: 'translate3d(0, 0, 0)'
    })),
  state('out', style({
      transform: 'translate3d(100%, 0, 0)'
    })),
  transition('in => out', animate('400ms ease-in-out')),
  transition('out => in', animate('400ms ease-in-out'))
 ])
]

```

让我们详细分析前面的代码：

1.  我们正在定义一个名为`slideInOut`的触发器。

1.  我们正在定义两个`states`：`in`和`out`。

1.  对于每个状态，我们都分配了一个样式，即每个相应状态的 CSS `transform`属性。

1.  我们还添加了`transition`来提及`state`和`animation`的细节。

看起来很简单，对吧？是的，当然！

现在我们知道了如何编写动画的语法，让我们深入了解 Angular 动画库中提供的每种方法。

# 触发器

触发器定义了一个将触发动画的名称。触发器名称帮助我们确定基于事件应该触发哪个触发器。

定义触发器的一般语法如下：

```ts
trigger('triggerName', [
  we define states and transitions here
])

```

在前面的代码语法中，我们正在定义以下内容：

1.  通过传递一个必需的参数来定义触发器，即名称和可选参数，其中可以包括`state`和`transition`。

1.  触发器名称；我们定义一个名称来识别触发器。

1.  我们还可以在触发器定义中将我们的状态和转换定义为参数。

# 状态

状态是元素在特定时间点的定义动画属性。

状态是我们应用程序的逻辑状态，例如活动和非活动。我们为状态定义状态名称和相应的样式属性。

定义状态的语法的一般语法如下：

```ts
state('in', style({
 backgroundColor: '#ffffcc'
}))

```

在前面的代码语法中，我们正在定义以下内容：

1.  我们正在定义一个名为`'in'`的`state`，这是我们应用程序中的一个逻辑状态。

1.  在样式中，我们定义了需要应用于元素的状态的`CSS`属性。常规的`CSS`样式属性在这里被定义。

# 过渡

过渡允许元素在不同状态之间平滑移动。在过渡中，我们定义了各种状态（一个或多个）的动画。

状态是过渡的一部分。

编写`transition`的一般语法如下：

```ts
//Duration Example - seconds or milliseconds
transition('in => out', animate('100')) 

// Easing Example: refer http://easings.net
transition('in => out', animate('300ms ease-in'))

// Using Delay in Animation
transition('in => out', animate('10s 50ms'))

```

在前面的代码语法中，我们正在定义以下内容

1.  我们正在定义我们的过渡状态，即从起始状态到结束状态。在我们的语法中，它是从 in 状态到 out 状态。

1.  动画选项如下：

1.  缓动：动画进行的平滑程度

1.  持续时间：动画从开始到结束运行的时间

1.  延迟：延迟控制动画触发和过渡开始之间的时间长度。

通过对如何编写 Angular 动画的概念和语法有着深刻的理解，让我们继续使用前面的所有函数来创建示例。

# 页面过渡动画

在前面的部分中，我们为动画创建了一些状态。在本节中，我们将学习如何使用状态创建过渡。

`transition`是 Angular 动画库中最重要的方法，因为它负责所有效果和状态变化。

让我们创建一个完整页面过渡的示例。我们将创建组件类`learn-animation.component.ts`：

```ts
import { Component } from '@angular/core';
import { state, style, animate, trigger, transition, keyframes} from '@angular/core';

@Component({
 templateUrl: './learn-animation.component.html',
 styleUrls: ['./learn-animation.component.css'],
 animations : [
 trigger('customHover', [
  state('inactive', style({
   transform: 'scale(1)',
    backgroundColor: '#ffffcc'
  })),
  state('active', style({
   transform: 'scale(1.1)',
   backgroundColor: '#c5cae8'
  })),

 transition('inactive => active', animate('100ms ease-in')),
 transition('active => inactive', animate('100ms ease-out'))
 ]),
 ]
})
export class AppComponent {
 title = 'Animation works!';
 constructor() {}

 state: string = 'inactive';
 toggleBackground() {
  this.state = (this.state === 'inactive' ? 'active' : 'inactive');
 }
}

```

让我们详细分析前面的代码，以了解 Angular 动画：

1.  我们正在定义一个名为`customHover`的触发器。

1.  我们正在定义两个`states`：`inactive`和`active`。

1.  对于每个状态，我们都分配了一个样式，即 CSS；对于各自的状态，我们分配了`transform`和`backgroundColor`属性。

1.  我们还添加了过渡来提及状态和动画细节：

1.  `transition`影响状态从`inactive`到`active`的移动。

1.  `transition`影响状态从`active`到`inactive`的移动。

1.  我们正在定义一个`toggleBackground`方法，当调用时，将从`inactive`状态切换到`active`状态，反之亦然。

现在我们已经创建了组件类，在我们的`learn-animation.component.html`模板中调用了`toggleBackground`方法：

```ts
<div>
 <div id="content" [@customHover]='state' 
       (mouseover)="toggleBackground()"  
       (mouseout)="toggleBackground()">Watch this fade</div>
</div>

```

让我们详细分析前面的代码：

1.  在`learn-animation.component.html`中，我们正在定义一个`div`元素。

1.  我们正在将`mouseover`和`mouseout`事件与`toggleBackground`方法进行绑定。

1.  由于我们将触发器定义为`@customHover`，我们将使用它进行属性绑定。在我们放置`[@customHover]`的任何元素上，将应用所定义的动画。

1.  由于我们应用了属性绑定，属性`@customHover`的值将在`active`和`inactive`之间切换。

1.  当我们将鼠标悬停在元素上时，将调用`toggleBackground`方法，并且我们将看到背景颜色随着`transform`属性的变化而改变。

1.  在鼠标移出事件上，再次调用`toggleBackground`方法，并且样式将重置回原始状态。

运行应用程序，我们应该在以下截图中看到输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/bcd37f1e-17b7-4f3c-99ba-9c5e7ac1258e.png)

在本节中，我们讨论了如何使用基本的 Angular 动画。在下一节中，我们将探索更多动画示例。

# 另一个示例 - Angular 动画

在前一节中，我们学习了动画的基础知识；在本节中，我们将使用 Angular 动画创建另一个示例。

在这个例子中，我们将创建一个按钮和一个`div`元素。当点击按钮时，`div`元素将滑入页面。很酷，对吧？

让我们开始吧。将以下代码添加到我们在前一节中创建的组件文件`learn-animation.component.ts`中：

```ts
 trigger('animationToggle', [
  transition('show => hide', [
   style({transform: 'translateX(-100%)'}),
   animate(350) ]),
   transition('hide => show', animate('3000ms'))
 ])

```

在前面的代码中，需要注意以下重要事项：

1.  我们正在创建一个带有`animationToggle`的触发器。

1.  我们正在定义两个过渡，即从`show => hide`和`hide => show`。

1.  我们正在向`show => hide`过渡添加样式属性。

1.  我们没有向`hide => show`过渡添加样式属性。

定义过渡样式并不是强制性的，但往往我们需要为具有动画效果的元素定义自定义样式。

运行应用程序，您应该在截图后看到以下应用程序和动画：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e485edc7-9fe0-49bb-a627-9e2e07e1c2d6.png)

在我们的应用程序中，当您点击显示按钮时，`DIV`元素将从右侧滑入页面到左侧。再次点击按钮，它将切换隐藏。

很酷，对吧？是的。Angular 动画使我们能够为元素创建美丽的动画和过渡效果，这将增加用户体验。

我们将构建许多很酷的示例来实现动画。

# 使用关键帧 - 样式序列

到目前为止，我们已经使用各种方法实现了 Angular 动画的示例。

当我们设计/决定元素的运动和转换时，我们需要遍历各种样式以实现平滑的过渡。

使用`keyframes`，我们可以在过渡时定义不同样式的迭代。`keyframes`本质上是为元素定义的一系列样式。

为了更好地理解这一点，让我们看一下以下代码片段：

```ts
transition('frameTest1 => frameTest2', [
 animate(300, keyframes([
 style({opacity: 1, transform: 'rotate(180deg)', offset: 0.3}),
 style({opacity: 1, transform: 'rotate(-90deg)', offset: 0.7}),
 style({opacity: 0, transform: 'rotate(-180deg)', offset: 1.0})
 ]))

```

让我们详细分析前面的代码片段：

1.  我们正在定义从`frameTest1 => frameTest2`的`transition`

1.  我们用`300`毫秒定义了`animate`属性。

1.  我们正在定义`keyframes`，在其中我们定义了三种不同的样式；元素将逐步经历每个`transition`帧。

现在，让我们用下面的代码扩展前面部分创建的示例。

更新后的`learn-animation.component.ts`文件将具有以下代码：

```ts
import { Component } from '@angular/core';
import { state, style, animate, trigger, transition, keyframes} from '@angular/animations';

@Component({
 selector: 'app-learn-animation',
 templateUrl: './learn-animation.component.html',
 styleUrls: ['./learn-animation.component.css'],
 animations: [
 trigger('animationState', [
   state('frameTest1', style({ transform: 'translate3d(0, 0, 0)'  })),
   state('frameTest2', style({ transform:
                 'translate3d(300px, 0, 0)'  })),
   transition('frameTest1 => frameTest2', 
                  animate('300ms ease-in-out')),

   transition('frameTest2 => frameTest1', [
     animate(1000, keyframes([
       style({opacity: 1, transform: 'rotate(180deg)', offset: 0.3}),
       style({opacity: 1, transform: 'rotate(-90deg)', offset: 0.7}),
       style({opacity: 0, transform: 'rotate(-180deg)', offset: 1.0})
     ]))
   ])
  ])
 ]
})
export class LearnAnimationComponent{
 constructor() {}

 public left : string = 'frameTest1';
 public onClick () : void
 {
  this.left = this.left === 'frameTest1' ? 'frameTest2' : 'frameTest1';
 }
}

```

让我们详细分析前面的代码：

1.  我们从 Angular 动画库中导入所需的模块：`state`、`style`、`animate`、`keyframes`和`transition`。这些模块帮助我们在应用程序中创建动画。

1.  我们创建了一个`LearnAnimationComponent`组件。

1.  我们为组件指定了`animations`。

1.  我们定义了一个名为`animationState`的触发器。

1.  对于创建的触发器，我们定义了两个状态--`frameTest1`和`frameTest2`。

1.  我们定义了两个转换：`'frameTest2 => frameTest1'`和`'frameTest2 => frameTest1'`。

1.  对于定义的每个转换，我们已经实现了`keyframes`，也就是与`animate`方法一起使用的一系列样式，以实现平滑的过渡和时间延迟。

1.  在组件类中，我们定义了一个`left`变量。

1.  我们正在定义一个`onClick`方法，切换从`frameTest1`到`frameTest2`的值。

到目前为止，一切顺利。我们已经实现了组件。

现在是时候更新我们的`learn-animation.component.html`并将以下代码片段添加到文件中：

```ts
<h4>Keyframe Effects</h4>

<div class="animateElement" [@animationState]="left"    
  (click)="onClick()">
     Click to slide right/ Toggle to move div
</div>

```

好了，一切准备就绪。现在运行应用程序，您应该看到如屏幕截图所示的输出和下面提到的动画：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/e58fdda2-5a05-4481-8e76-2d29da52b2c6.png)

当您运行应用程序时，您应该看到以下动画

1.  当您点击`DIV`元素时--它应该向右滑动

1.  再次点击`DIV`元素，元素应该向右移动，`DIV`元素变换--给人一种 DIV 在旋转的感觉。

在本节中，您将学习如何使用`keyframes`并为元素创建一系列样式，以实现更平滑的过渡。

# 动画折叠菜单

在本节中，我们将为我们的应用程序创建一个非常重要的部分，即应用程序的侧边栏菜单。

根据我们迄今为止学到的关于 Angular 动画的知识，在本节中我们将创建一个折叠侧边栏的示例。

让我们更新组件模板`learn-animation.component.html`，并使用以下代码片段更新文件：

```ts
<h4>Collapse Menu</h4>

<button (click)="toggleMenu()" class="menuIcon">Toggle Menu</button>
 <div class="menu" [@toggleMenu]="menuState">
 <ul>
   <li>Home</li>
   <li>Angular</li>
   <li>Material Design</li>
   <li>Sridhar Rao</li>
   <li>Packt Publications</li>
 </ul>
</div>

```

对前面的代码进行分析如下：

1.  我们正在添加一个`<h4>`标题，一个`Collapse`菜单。

1.  我们正在定义一个按钮，并将`click`事件与`toggleMenu`方法关联起来。

1.  我们正在创建一个带有示例列表项`<li>`的无序列表`<ul>`。

现在，我们将向`learn-animation.component.css`文件添加一些基本的 CSS 样式：

```ts
.animateElement{
   background:red;
   height:100px;
   width:100px;
}
.menu {
   background: #FFB300;
   color: #fff;
   position: fixed;
   left: auto;
   top: 0;
   right: 0;
   bottom: 0;
   width: 20%;
   min-width: 250px;
   z-index: 9999;
   font-family: Arial, "Helvetica Neue", Helvetica, sans-serif;
 }

 ul {
   font-size: 18px;
   line-height: 3;
   font-weight: 400;
   padding-top: 50px;
   list-style: none;
 }
 .menuIcon:hover {
   cursor: pointer;
 }

```

到目前为止，我们已经创建了我们的应用程序组件模板`learn-animation.component.html`并为菜单组件`learn-animation.component.css`设置了样式。

现在，我们将创建菜单组件类。

将以下代码添加到`learn-animation.component.ts`文件中：

```ts
import { Component } from '@angular/core';
import { state, style, animate, trigger, transition, keyframes} from '@angular/core';

@Component({
 selector: 'app-learn-animation',
 templateUrl: './learn-animation.component.html',
 styleUrls: ['./learn-animation.component.css'],
 animations: [

  trigger('toggleMenu', [
   state('opened', style({
    transform: 'translate3d(0, 0, 0)'
   })),
   state('closed', style({
    transform: 'translate3d(100%, 0, 0)'
   })),
   transition('opened => closed', animate('400ms ease-in-out')),
   transition('closed => opened', animate('400ms ease-in-out'))
  ])
 ])
 ]
})
export class LearnAnimationComponent{

constructor() {}
 menuState : string = 'opened';
 toggleMenu()
 {
  this.menuState = this.menuState === 'closed' ? 'opened' : 'closed';
 }
}

```

让我们详细分析前面的代码：

1.  我们正在导入所需的 Angular 动画库模块，例如`state`，`style`，`animate`，`trigger`，`transition`和`keyframes`。

1.  在动画中，我们定义了一个触发器：`toggleMenu`。

1.  我们正在创建两种状态：`opened`和`closed`。

1.  对于每个状态，我们正在定义一些带有`transform`的样式属性。

1.  我们现在定义了转换`opened => closed`和`closed => open`，并带有一些动画细节延迟。

1.  我们已经定义了一个`menuState`变量。

1.  在组件类中，我们定义了`toggleMenu`。

1.  在`toggleMenu`方法中，我们正在切换`menuState`变量值为`opened`或`closed`，反之亦然。

现在是演示时间。运行应用程序，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/efde53e9-fd39-4938-88e5-437701ba9fb0.png)

再次点击 Toggle 菜单按钮，我们应该看到菜单向右滑动，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/b42eb804-7fa2-46ec-9b2c-dc60ac48e066.png)

在本节中，我们使用 Angular 动画创建了应用程序的侧边栏菜单。

# 总结

在本章中，我们介绍了 Angular 动画。动画对于设计和构建具有平滑过渡和元素效果的美观用户体验至关重要。

我们介绍了如何安装和导入 Angular 动画库，并在库中使用各种模块。

我们讨论了重要的模块，比如`state`、`style`、`animate`、`trigger`、`transition`和`keyframes`。

我们创建并实现了一些使用 Angular 动画的示例。

最后，我们创建了一个带有一些动画效果的网页应用侧边栏菜单。现在，轮到你了！

在下一章中，您将学习如何将 Bootstrap 与 Angular 应用程序集成。Bootstrap 可以说是目前最流行的前端框架，在本章中，您将了解拥有一个 Angular x Bootstrap 应用程序意味着什么。


# 第十四章：将 Bootstrap 与 Angular 应用程序集成

Bootstrap 可以说是目前最受欢迎的前端框架。你可能会问，Angular 本身不就是一个前端框架吗？是的。那么为什么我需要在同一个应用程序中使用两个前端框架呢？答案是，你不需要。Bootstrap 是由 Twitter 创建和使用的，非常受欢迎。它允许您管理许多事情，比如使用一个名为网格的系统在页面上布置 HTML 组件。我将在接下来的页面中详细解释这个系统，它允许您在不明确使用 CSS 的情况下将网页空间划分为区域。此外，一切都将立即响应。此外，Bootstrap 提供了动态元素，如轮播、进度条、对用户输入的表单反应等。简而言之，Angular 允许您创建应用程序结构并管理数据呈现，而 Bootstrap 处理图形的呈现。

Bootstrap 围绕三个元素展开：

+   `bootstrap.css`

+   `bootstrap.js`

+   `glyphicons`

在这里，`bootstrap.css`包含了允许响应式空间划分的框架，而`bootstrap.js`是一个使您的页面动态化的 JavaScript 框架。

需要注意的是，`bootstrap.js`依赖于 jQuery 库。

最后，`glyphicons`是一个包含使用 Bootstrap 时可能需要的所有图标的字体。

在第十章*,* *Angular 中的 Material Design*中，您将学习如何使用由 Google 官方提供的`Material Design`包来创建管理动态元素、轮播和其他进度条的应用程序（ng2-material）。Bootstrap（由 Twitter 提供）和 Material Design（由 Google 为 Angular 提供）最终都旨在实现同样的目标：在严格呈现页面给用户时简化您的生活。例如，它们都确保跨浏览器兼容性，防止在项目之间重复编写代码，并在代码库中添加一致性。

在我看来，您应该使用哪一个是个人选择，我可以预见未来几个月将会有关于 C#与 Java 或 PC 与 Mac 之类的激烈争论。一方面，如果您已经精通 Bootstrap 并且在各处都在使用它，那么您也可以在这里使用它。另一方面，如果 Bootstrap 不是您的技能范围，您可以利用这个机会学习并选择您喜欢的。

第三个选项将是完全跳过本章，如果您已经选择了 Material Design（由 Google 为 Angular 提供）的方法。我不介意，我保证。本章涵盖的主题有：

+   安装 Bootstrap

+   了解 Bootstrap 的网格系统

+   使用 Bootstrap 指令

# 安装 Bootstrap

话不多说，让我们开始并为 Angular 安装 Bootstrap。

在没有像 Angular 这样的前端框架的标准 Web 应用中使用 Bootstrap 时，您需要使用内容传递网络（CDN）来获取组成 Bootstrap 框架的三个部分（`bootstrap.css`，`bootstrap.js`和`glyphicons`）。即使下载了缩小的文件，这些调用仍然需要时间（例如，三个 HTTP 请求，下载，校验和等）才能完成。对于您的客户来说，使用 Angular，我们可以采用相同的方法，并简单地在`src/index.html`中添加对某些 CDN 的引用，但这将是一个相当大的错误。

首先，如果用户没有缓存资源的副本，那么我们将遭受与标准 Web 应用相同的副作用，因为我们的客户将不得不等待 CDN 提供 Bootstrap 框架，特别是考虑到我们的应用经过 Angular CLI 部署流程进行了缩小并以单个文件提供。其次，我们将无法轻松地在我们的 Angular 组件中控制 Bootstrap 组件。

将 Bootstrap 与我们的 Angular 应用程序集成的更好方法是使用`ng-bootstrap`包。该包允许我们在我们的组件中使用 Angular 指令来管理 Bootstrap。在撰写本文时，这是最全面、维护良好且与 Angular 集成良好的包，允许我们在 Angular 中使用 Bootstrap。

为了探索 Bootstrap，我们将在第七章，*使用可观察对象进行异步编程*和第九章，*Angular 中的高级表单*中使用的 Marvel Cinematic Universe 的 JSON API 基础上构建。

您可以在[`github.com/MathieuNls/mastering-angular2/tree/master/chap9`](https://github.com/MathieuNls/mastering-angular2/tree/master/chap9)找到《第九章》，*Angular 中的高级表单*的代码。

要将此代码克隆到名为`angular-bootstrap`的新存储库中，请使用以下命令：

```ts
$ **git** clone --depth one https://github.com/MathieuNls/mastering-angular    
    angular-bootstrap
$ **cd** angular-bootstrap
$ **git** filter-branch --prune-empty --subdirectory-filter chap9 HEAD

```

这些命令将 GitHub 存储库的最新版本拉到名为`angular-bootstrap`的文件夹中。然后，我们进入`angular-bootstrap`文件夹，并清除不在第九章 *Angular 中的高级表单*目录中的所有内容。

现在让我们安装`ng-bootstrap`包：

```ts
npm install --save @ng-bootstrap/ng-bootstrap

```

现在，在`src/app/app.module.ts`中，导入`import {NgbModule}` from `@ng-bootstrap/ng-bootstrap`包，并将`NgbModule.forRoot()`添加到`AppModule`类的导入列表中。如果您重用了第九章 *Angular 中的高级表单*中的代码，它应该是这样的：

```ts
 import { BrowserModule } from '@angular/platform-browser';
 import { NgModule } from '@angular/core';
 import { FormsModule, ReactiveFormsModule  } from '@angular/forms';
 import { HttpModule } from '@angular/http';
 import { NgbModule } from '@ng-bootstrap/ng-bootstrap

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
     NgbModule.forRoot()
   ],
   providers: [],
   bootstrap: [AppComponent]
 })
 export class AppModule { }

```

这个包允许我们摆脱 jQuery 和`bootstrap.js`的依赖，但不幸的是，它不包括`bootstrap.css`。它包含了我们即将使用的网格系统和组件所需的样式。

前往[`getbootstrap.com/`](http://getbootstrap.com/)，并在`src/index.html`中导入以下显示的链接：

```ts
<!doctype html>
 <html>
 <head>
   <meta charset="utf-8">
   <title>Chap15</title>
   <base href="/">
   <link rel="stylesheet" 
        href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-
        alpha.4/css/bootstrap.min.css" integrity="sha384-
        2hfp1SzUoho7/TsGGGDaFdsuuDL0LX2hnUp6VkX3CUQ2K4K+xjboZdsXyp4oUHZj" 
        crossorigin="anonymous">
   <meta name="viewport" content="width=device-width, initial-scale=1">
   <link rel="icon" type="image/x-icon" href="favicon.ico">
 </head>
 <body>
   <app-root>Loading...</app-root>
 </body>
 </html>

```

通过这些小改变，我们已经可以看到 Bootstrap 正在接管我们的样式。在下面的图片中，左边是我们在第九章 *Angular 中的高级表单*结束时表单的样子。

然而，右边是我们现在表单的样子。正如您所看到的，这里和那里有一些小的不同。例如，`h1`标记，错误字段和输入的样式不同：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/561f8ba8-175a-4af1-8272-060cfc726aee.png)Bootstrap 之前和之后。

如果我们使用 Google Chrome 的检查功能，我们可以清楚地看到我们的`h1`标记的应用样式来自 http://maxcdn.bootstrapcdn.com，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/c2bdb3bf-3fb2-4cf5-9ec4-d3f546aa165b.png)Chrome 检查样式。

就是这样：我们完成了 Bootstrap 的初始化。让我们学习如何使用 Angular 指令来使用 Bootstrap。

# 理解网格系统

在本章中，我们更关心学习如何使用不同的 Angular Bootstrap 指令，而不是学习 Sass 混合和其他演示技巧。换句话说，网格系统的高级功能超出了本章的范围。然而，在本节中，我将快速介绍网格系统是什么，以及如何使用它的概述。

如果你以前使用过 Bootstrap，尤其是使用过网格系统，你可以跳过这一部分，直接进入下一部分，在那里我们学习如何使用手风琴指令。

因此，网格系统将我们的演示分成了十二列。列的大小可以是额外小、小、中、大和额外大。列的大小可以通过 CSS 类前缀（分别是`col-xs`、`col-sm`、`col-md`、`col-lg`和`col-xl`）手动设置，并对应不同的屏幕宽度（小于 540 像素、540 像素、720 像素、960 像素和 1140 像素）。

为了了解如何利用网格系统来分隔我们的演示，让我们在`src/app/app.component.html`中的`<h1>{{title}}</h1>`标记后面添加以下内容：

```ts
<div class="container">
   <div class="row">
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
     <div class="col-md-1">col-md-1</div>
   </div>
   <div class="row">
     <div class="col-md-8">col-md-8</div>
     <div class="col-md-4">col-md-4</div>
   </div>
   <div class="row">
     <div class="col-md-4">col-md-4</div>
     <div class="col-md-4">col-md-4</div>
     <div class="col-md-4">col-md-4</div>
   </div>
   <div class="row">
     <div class="col-md-6">col-md-6</div>
     <div class="col-md-6">col-md-6</div>
   </div>
 </div>

```

正如你所看到的，这里有几个 CSS 类在起作用。首先，让我们看看容器。这是必需的，它定义了 Bootstrap 网格系统将应用的空间。然后，我们有包含`col-`的行。每行占据屏幕的整个宽度，并被分成列。列的实际宽度取决于你在列类声明的末尾使用的数字（4、8、6 等）。知道行被分成 12 列，我们使用了`col-md`类前缀，我们可以推断出一行的最大尺寸是 720 像素。因此，每列宽 60 像素。在第一行中，我们在我们的声明中使用了`-1`后缀；因此，我们有 60 像素宽的列（即屏幕宽度除以 12）。然而，在第二行，我们使用了`-8`和`-4`后缀。

这意味着我们将有一列的宽度是`a-1`列的 8 倍（480 像素），另一列的宽度是`a-1`列的 4 倍（240 像素）。在第三行，我们使用了三个四列，最后，在第四行，我们有两个六列。

要查看发生了什么，请在`app/app.component.css`中添加以下内容：

```ts
.row > [class^="col-"]{
   padding-top: .75rem;
     padding-bottom: .75rem;
     background-color: rgba(86, 61, 124, 0.15);
     border: 1px solid rgba(86, 61, 124, 0.2);
 }

```

这段 CSS 将为任何`col`类添加背景和边框，无论它们可能具有的前缀或后缀是什么：

网格系统的运行。

正如你在上图中所看到的，空间被很好地按计划划分。现在，这并不是网格系统的真正优势。主要优势在于，如果屏幕宽度变小于 720 像素，列会自动堆叠在彼此上面。

例如，在 iPhone 6 上，其屏幕宽度为 375px，所有列将堆叠在一起，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/aab631a1-971c-48c6-8b31-1a25818857cc.png)iPhone 6 上的网格系统。

这是官方文档中的另一个例子，可以在[`v4-alpha.getbootstrap.com/layout/grid/`](https://v4-alpha.getbootstrap.com/layout/grid/)找到：

```ts
<!-- Stack the columns on mobile by making one full-width and the other half-width -->
 <div class="row">
   <div class="col-xs-12 col-md-8">.col-xs-12 .col-md-8</div>
   <div class="col-xs-6 col-md-4">.col-xs-6 .col-md-4</div>
 </div>

 <!-- Columns start at 50% wide on mobile and bump up to 33.3% wide on desktop -->
 <div class="row">
   <div class="col-xs-6 col-md-4">.col-xs-6 .col-md-4</div>
   <div class="col-xs-6 col-md-4">.col-xs-6 .col-md-4</div>
   <div class="col-xs-6 col-md-4">.col-xs-6 .col-md-4</div>
 </div>

 <!-- Columns are always 50% wide, on mobile and desktop -->
 <div class="row">
   <div class="col-xs-6">.col-xs-6</div>
   <div class="col-xs-6">.col-xs-6</div>
 </div>

```

我不会详细介绍网格系统，但知道你可以在 Packt Library 找到很多关于这个主题的精彩书籍。只需查找以下内容：

+   *精通 Bootstrap 4*

+   *Bootstrap 4 蓝图*

# 使用 Bootstrap 指令

在本节中，我们将学习如何使用一些最常用的 Bootstrap 指令来构建您的应用程序。

# 手风琴

我们将首先概述手风琴指令。手风琴允许您创建一个可以通过单击其各自的标题独立显示的不同内容面板。

我们将使用我们在第九章中制作的表单，*Angular 中的高级表单*，允许用户在漫威电影宇宙中添加电影，以实验手风琴。这里的目标是为表单设置一个面板，为电影的枚举设置另一个面板。

让我们从研究创建 Bootstrap 手风琴所需的最小 HTML 开始，如下所示：

```ts
<ngb-accordion>
   <ngb-panel>
     <template ngbPanelTitle>
       <span>Mastering angular X Bootstrap</span>
     </template>
     <template ngbPanelContent>
       Some deep insights
     </template>
   </ngb-panel>
   <ngb-panel>
     <template ngbPanelTitle>
       <span>Some Title</span>
     </template>
     <template ngbPanelContent>
       Some text
     </template>
   </ngb-panel>
 </ngb-accordion>

```

前面的 HTML 模板将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/3aa4acce-4fca-4bda-93d7-3a430b529a5d.png)一个简单的手风琴。

分析前面的代码片段，我们可以看到以下特点：

+   `ngb-accordion`：这是主要的手风琴指令。它定义了一个包含`ngb-panel`的手风琴。

+   `ngb-panel：` 这代表手风琴的一个面板。可以通过单击面板标题来切换其可见性。`ngb-panel`包含一个可以用于标题或内容的模板。

+   `<template ngbPanelContent>`：这包含给定面板的标题或内容。

+   `<template ngbPanelTitle>：` 这包含标题。

到目前为止，一切都相当简单。现在，它变得强大的地方是当您从您的 TypeScript 组件中管理它时。首先，`ngb-accordion`指令有三个不同的`@Input`属性，我们利用了它们。第一个是`activeIds`，它是`string[]`类型，包含您希望打开的面板的 ID。面板 ID 是从`ngb-panel-0`自动生成的。面板 ID 的格式为`ngb-panel-x`。第二个`@Input`是一个布尔值：`closeOthers`。这允许您指定是否一次只能打开一个面板。最后，使用`string`类型来指定手风琴的类型。在 Bootstrap 中，有四种类型被识别：`success`、`info`、`warning`和`danger`。

除了这三个`@Inputs`之外，`ngb-accordion`指令还提供了一个名为`panelChange`的`@Output`。这个`@Output`会在每次面板的可见性即将被切换时触发。

让我们通过将`app/app.component.html`转换为以下内容来尝试这些`@Input`和`@Output`属性：

```ts
<div class="container">

     <!-- First Row -->
     <div class="row">
         <h1 class="col-md-12">
           {{title}}
         </h1>
     </div>

     <!-- Second Row -->
     <div class="row">

         <!-- Start of the accordion -->
         <ngb-accordion class="col-md-12" 
         <!-- Bind to a variable called activeIds -->
         [activeIds]="activeIds" 
         <!-- Simply use the string 'success' -->
         type="success" 
         <!-- Simply use true -->
         closeOthers="true"
         <!-- Bind to the output -->
         (panelChange)=pannelChanged($event)
         >
           <!-- Firt pannel -->
           <ngb-panel>
             <template ngbPanelTitle>
               <span>Add a Movie</span>
             </template>
             <!-- Form content is here -->
             <template ngbPanelContent>
               <form [formGroup]="movieForm">
                 <!-- Form content omitted for clarity -->
               </form>
             </template>
           </ngb-panel>
           <!-- Second pannel -->
           <ngb-panel>
             <template ngbPanelTitle>
               <span>Movies</span>
             </template>
             <!-- Movie enumeration is here -->
             <template ngbPanelContent>

                 <ul>
                     <li *ngFor="let movie of movies">{{movie}}</li> 
                 </ul>

             </template>
           </ngb-panel>
         </ngb-accordion>

     </div>
 </div>

```

在这里，我们使用了`[activeIds]="activeIds"`、`type="success"`、`closeOthers="true"`和`(panelChange)=pannelChanged($event)`来绑定到我们组件中的一个名为`activeIds`的变量，将表单类型设置为`success`，并将`closeOthers`设置为 true。然后，我们将一个名为`pannelChanged`的方法绑定到`panelChange`输出。在`app.component.ts`中，我们需要添加`activeIds`变量和`pannelChanged`方法如下：

```ts
  private activeIds = ["ngb-panel-1"];

   private pannelChanged(event:{panelId:string, nextState:boolean}){
     console.log(event.nextState, event.panelId);
   }

```

在这里，`private activeIds = ["ngb-panel-1"];`允许我们定义`panel-1`（第二个）应该默认打开，并且`pannelChanged`方法应该接收一个由`panelId:string`和`nextState:boolean`组成的事件负载。我们记录了这两个负载属性。

应用程序现在看起来像下面截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/9aea1b72-1074-4da4-9724-8c8a73dec9aa.png)一个由 TypeScript 管理的手风琴。

当您切换面板时，控制台会记录以下内容：

```ts
**true** "ngb-panel-0"
**false** "ngb-panel-0"  

```

# 警报

本章中我们将探讨的下一个指令是`ng-alert`。在 Bootstrap 词汇中，警报是以有色`div`形式显示给用户的重要信息。有四种类型的警报：`success`、`info`、`warning`和`danger`。

要创建一个 Bootstrap 警报，最小可行的 HTML 模板如下：

```ts
  <ngb-alert> 
    Something important 
  </ngb-alert> 

```

这段代码的结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/93c0e03c-2c1a-4d86-a030-0dab9b1456bf.png)一个基本的警报。

与手风琴类似，警报指令提供了一些`@Input`和`@Output`。我们可以使用`@Input`作为`dismissible:boolean`，它管理警报的可解除性，以及`type:string`，它接受`success`、`info`、`warning`和`danger`。

为了使我们的表单更具 Bootstrap 风格，我们可以用警报替换我们的错误消息。目前，在表单中，错误消息看起来像这样：

```ts
<p class='error' *ngIf=!movieForm.controls.movie_id.valid>This field is required</p>

```

现在的目标是有以下内容：

```ts
  <ngb-alert 
   [dismissible]="false" 
   *ngIf=!movieForm.controls.movie_id.valid
   type="danger"
   >
     This field is required
   </ngb-alert>

```

在上述片段中的每个字段，上述代码将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/1e17b924-e47c-4332-b840-9f7d9bd9d425.png)危险警报作为表单错误。

# 日期选择器

本章中的下一个指令是日期选择器。无论您使用什么技术，日期总是有些棘手，因为每个供应商都提出了许多格式。此外，日期国际化使事情变得更加困难。

幸运的是，Bootstrap 带有一个足够简单的日期选择器，允许用户在弹出的日历中选择日期。其代码如下所示：

```ts
<div class="input-group">
   <input class="form-control" placeholder="yyyy-mm-dd" 
      ngbDatepicker #dp="ngbDatepicker">
   <div class="input-group-addon" (click)="dp.toggle()" >
     <img src="https://ng-bootstrap.github.io/img/calendar-icon.svg"
         style="width: 1.2rem; height: 
             1rem; cursor: pointer;"/>
    </div>
</div>

```

这里发生了很多事情。首先，我们有一个`formControl`输入，其占位符设置为`yyyy-mm-dd`。您定义的占位符很重要，因为它将作为用户选择的数据的强制格式化程序。对于格式化程序的语法，您可以使用日期的每个经典符号（例如，d、D、j、l、N、S、w、z 等）。换句话说，我们输入的日期将自动匹配此模式。然后，我们有`ngbDatepicker #d="ngbDatepicker"`。`ngbDatepicker`定义了我们的输入是一个`ngbDatepicker`，`#dp="ngbDatepicker"`允许我们创建对我们的输入的本地引用。这个名为`dp`的本地引用在以下`div`的`(click)`事件上使用：`(click)="dp.toggle()"`。这个`div`包含了日历的图像。点击它，一个动态的日历将弹出，我们将能够选择一个日期。

这个 HTML 将给我们以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/59629aed-ee64-4b4e-9b08-d5869cd5962a.png)日期选择器。

然后，一旦触发了`click`事件，将显示如下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/1c9dd50c-abfa-45a2-a4f8-ebe97a16cddc.png)日期选择器被点击。

为了改善我们对漫威电影宇宙的管理，我们可以将`release_date`字段更改为日期选择器。目前，`release_date`字段看起来像这样：

```ts
<label>release_date</label>
 <ngb-alert [dismissible]="false" type="danger" 
       *ngIf=!movieForm.controls.release_date.valid>This field is required</ngb-alert>
 <input type="text" formControlName="release_date" [(ngModel)]="movie.release_date"><br/>

```

如果字段无效，我们会有输入和 Bootstrap 警报。Bootstrap 警报默认是活动的（即当字段为空时）。让我们将我们的输入转换为以下内容：

```ts
  <label>release_date</label>
   <ngb-alert [dismissible]="false" type="danger" 
      *ngIf=!movieForm.controls.release_date.valid>This 
      field is required</ngb-alert>
   <div class="input-group">
     <input 
     formControlName="release_date" 
     placeholder="yyyy-mm-dd"  
     ngbDatepicker #dp="ngbDatepicker"
     [(ngModel)]="movie.release_date">
     <div class="input-group-addon" (click)="dp.toggle()" >
       <img src="https://ng-bootstrap.github.io/img/calendar-icon.svg" 
           style="width: 1.2rem; 
           height: 1rem; cursor: pointer;"/>
     </div>
   </div>

```

这里的不同之处在于我们将输入链接到了我们的`formControl`。实际上，在第九章 *Angular 中的高级表单*中，我们定义了表单如下：

```ts
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
         budget: ['', Valida tors.required],
         gross: ['', Validators.required],
         time_stamp: ['', Validators.required]
});

```

所以，我们有一个必填的`release_date`字段。HTML 输入定义了与`release_date`字段的双向数据绑定，带有`[(ngModel)]="movie.release_date"`，此外，我们还需要在输入框内添加`formControlName="release_date"`属性。实施后，屏幕上将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/08e4e8c9-4218-4256-8dcc-68593dbfb171.png)MCU 的日期选择器。

# 工具提示

接下来，我们有 tooltip 指令，它允许我们在给定一组元素的左侧、右侧、顶部或底部显示信息性文本。

tooltip 指令是最简单的之一。实际上，你只需要为你希望增强的元素添加两个属性：placement 和`ngbTooltip`。placement 的值可以是 top、bottom、left 或 right，而`ngbTooltip`的值是你希望显示的文本。

让我们修改`movie_id`字段的标签：

```ts
<ngb-alert [dismissible]="false" type="danger" 
   *ngIf=!movieForm.valid>danger</ngb-alert>
<label >movie_id</label>
<ngb-alert [dismissible]="false" type="danger" 
  *ngIf=!movieForm.controls.movie_id.valid>This field 
    is required</ngb-alert>
  <input type="text" formControlName="movie_id" 
     [(ngModel)]="movie.movie_id" name="movie_id" >
   <br/> to 
    <ngb-alert [dismissible]="false" type="danger" 
       *ngIf=!movieForm.valid>danger</ngb-alert>
    <label placement="top" ngbTooltip="Title of
      your movie"> movie_id</label>
    <ngb-alert [dismissible]="false" type="danger" 
       *ngIf=!movieForm.controls.movie_id.valid>This 
    field is required</ngb-alert>
 <input type="text" formControlName="movie_id" 
    [(ngModel)]="movie.movie_id" name="movie_id" ><br/>

```

在这里，我们保持了警报和输入不变。但是，我们在标签中添加了 placement 和`ngbTooltip`属性。结果，当我们悬停在`movie_id`标签上时，电影标题将显示在顶部。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/f0fc6a9c-340f-43a5-8abf-2534c96c0043.png)movie_id 上的工具提示。

# 进度条

还有一些其他的 Bootstrap 组件可以用来增强我们的表单；然而，太多的组件很快就会成为可用性过度的情况。例如，将进度条集成到我们的表单中将会很棘手。然而，我们可以为我们想要测试的每个新的 Bootstrap 指令添加一个手风琴面板。

让我们为进度条添加一个面板：

```ts
<ngb-panel>
     <template ngbPanelTitle>
         <span>Progress Bar</span>
     </template>

     <template ngbPanelContent>

       <ngb-progressbar type="success" [value]="25"></ngb-progressbar>

    </template>
</ngb-panel>

```

`progressbar`指令是另一个简单的指令。它有两个`@Input`属性：type 和 value。和往常一样，type 可以是`success`、`danger`、`warning`或`info`。value 属性可以绑定到一个 TypeScript 变量，而不是像我做的那样硬编码为 25。

这是结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/cd71611f-8ba6-450d-a78f-66f416bd14f9.png)movie_id 上的进度条。

# 评分

评分指令也是非常出名的。它允许用户对某物进行评分，或者显示给定的评分。

正如预期的那样，这个指令很容易理解。它有一个评分输入，您可以硬编码（例如，`"rate"=25`），绑定（`[rate]="someVariable"`），或者应用双向数据绑定（`[(rate)]="someVariable"`）。除了评分输入，您还可以使用`[readonly]="read-only"`来使您的评分条不可修改。

默认情况下，评分条由 10 颗星组成。评分值可以从 0 到 10，包括小数。

以下是一个新面板内默认评分条的示例：

```ts
<ngb-panel>
        <template ngbPanelTitle>
           <span>Rating bar</span>
         </template>
         <template ngbPanelContent>

            <ngb-rating rate="5"></ngb-rating>

          </template>
  </ngb-panel>

```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/67f6dba3-16d6-4c86-929a-4351bed46fed.png)评分条。

# 摘要

在本章中，我们看到了一些最受欢迎的 Bootstrap 组件。我们学会了如何使用 ng2-Bootstrap 包提供的原生 Angular 指令来使用它们。然而，我们并没有探索每一个 Bootstrap 组件。您可以查看托管在[`ng-bootstrap.github.io/`](https://ng-bootstrap.github.io/)的官方文档。

在下一章中，您将学习如何使用单元测试来测试您的 Angular 应用程序。


# 第十五章：使用 Jasmine 和 Protractor 框架测试 Angular 应用程序

测试是现代应用程序开发过程中最重要的方面之一。我们甚至有专门的软件开发方法论，主要是基于测试优先的方法。

除了 Angular 提供的测试工具之外，还有一些推荐的框架，如 Jasmine、Karma 和 Protractor，使用这些框架可以轻松创建、维护和编写测试脚本。使用 Jasmine 和 Protractor 编写的测试脚本可以节省时间和精力，并且最重要的是在开发过程中更早地发现缺陷。

在本章中，您将学习如何使用 Jasmine 和 Protractor 测试 Angular 应用程序。在本章中，我们将讨论以下内容：

+   了解测试中的重要概念

+   了解 Angular CLI 用于单元测试特定环境

+   介绍 Jasmine 框架

+   使用 Jasmine 编写测试脚本

+   编写测试脚本来测试 Angular 组件

+   测试 Angular 组件：一个高级示例

+   使用 Jasmine 测试脚本测试 Angular 服务

+   学习 Protractor

+   使用 Protractor 编写 E2E 测试脚本

# 测试中的概念

在我们开始测试我们的 Angular 应用程序之前，重要的是我们快速复习并了解一些在测试中常用的术语：

+   **单元测试**：一个单元测试可以被视为应用程序中最小的可测试部分。

+   **测试用例**：这是一组测试输入、执行条件和期望结果，以实现一个目标。在 Jasmine 框架中，这些被称为规范。

+   **TestBed**：TestBed 是一种通过传递所有必需的数据和对象来以隔离的方式测试特定模块的方法。

+   **测试套件**：这是一组旨在用于端到端测试模块的测试用例集合。

+   **系统测试**：对完整和集成的系统进行的测试，以评估系统功能。

+   **端到端测试**：这是一种测试方法，用于确定应用程序的行为是否符合要求。我们传递数据、必需对象和依赖项，并在模拟实时用例和场景的情况下从头到尾执行。

既然我们知道了前面的术语，让我们学习如何测试 Angular 应用程序。

# 了解并设置 Angular CLI 进行测试

到目前为止，我们已经使用 Angular CLI 来设置我们的项目，创建新组件、服务等。我们现在将讨论如何使用命令行工具来设置和执行测试套件，以测试我们的 Angular 应用程序。

首先，快速回顾如何使用 Angular CLI 快速创建项目：

```ts
npm install -g angular-cli

```

使用上述代码片段，我们安装了 Angular 命令行工具。现在，让我们创建一个名为`test-app`的新目录并进入项目目录：

```ts
ng new test-app
cd test-app

```

现在是时候快速创建一个名为`test-app`的新组件了：

```ts
ng g component ./test-app

```

现在，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/46868d9b-453f-4048-9c52-73bb40e9c73c.png)

我们应该看到新目录和相应的文件在目录中创建。命令行工具已经创建了与组件相关的四个文件，包括`test-app.component.spec.ts`测试脚本占位符文件。

现在，让我们启动我们的应用程序：

```ts
ng serve

```

此时，我们的应用程序已经启动。现在是时候开始测试我们的 Angular 应用程序了。

# Jasmine 框架介绍

Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。这是官方网站如何解释 Jasmine 的方式：

Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。它不依赖于任何其他 JavaScript 框架。它不需要 DOM。它有一个清晰明了的语法，让您可以轻松编写测试。

Jasmine 测试套件的一般语法如下所示：

```ts
describe("Sample Test Suite", function() {
 it("This is a spec that defines test", function() {
   expect statement // asserts the logic etc
 });
});

```

让我们分析上述代码片段，以了解测试套件语法。已经按照以下步骤进行了操作：

1.  每个 Jasmine 测试套件都将有一个`describe`语句，我们可以给出一个名称。

1.  在测试套件内，我们使用`it`语句创建较小的测试用例；每个测试用例将有两个参数，一个名称和一个函数，其中包含需要测试的应用程序逻辑。

1.  我们使用`expect`语句来验证数据，以确保我们的应用程序和数据按预期工作。

在下一节中，您将详细了解 Jasmine 框架和可用的方法和函数，我们可以在测试脚本中使用。

# Jasmine 框架 - 我们可以使用的全局方法

Jasmine 框架支持并为我们提供了许多预定义的方法来使用和编写我们的测试套件。 Jasmine 对测试环境、对元素进行间谍操作等提供了广泛的支持。请参阅官方网站以获取有关可用方法的完整帮助和文档。

为了编写测试脚本，我们需要对 Jasmine 框架中最常用和频繁使用的一些方法有基本的理解和知识。

# Jasmine 中常用的方法

以下是编写测试套件可用的最常用的 Jasmine 全局方法列表：

| **全局方法** | **描述** |
| --- | --- |
| describe | describe 函数是实现测试套件的代码块 |
| it | 通过调用全局 Jasmine 函数`it`来定义规范，如所述，它接受一个字符串和一个函数 |
| beforeEach | 此方法在调用它的描述中的每个规范之前调用一次 |
| afterEach | 此方法在每个规范后调用一次 |
| beforeAll | 此方法在描述中的所有规范之前调用一次 |
| afterAll | 此方法仅在所有规范调用后调用一次 |
| xdescribe | 这会暂时禁用您不想执行的测试 |
| pending | 未运行的待定规范将被添加到待定结果列表中 |
| xit | 任何使用 xit 声明的规范都会被标记为待定 |
| spyOn | 间谍可以替换任何函数并跟踪对它的调用和所有参数；这在描述或 it 语句内部使用 |
| spyOnProperty | 对间谍的每次调用都会被跟踪并暴露在 calls 属性上 |

有关更多详细信息和完整文档，请参阅 GitHub 上的 Jasmine 框架文档。

# Angular CLI 和 Jasmine 框架-第一个测试

安装 Angular CLI 时，Jasmine 框架会自动与工具一起提供。

在前面的部分中，我们看到了在 Jasmine 中编写测试的一般语法。现在，让我们使用 Jasmine 框架编写一个快速的测试脚本：

```ts
describe('JavaScript addition operator', function () {  it('adds two numbers together', function () {  expect(1 + 2).toEqual(3); }); });

```

以下是关于前面的测试脚本的重要事项：

1.  我们编写一个`describe`语句来描述测试脚本。

1.  然后我们使用`it`语句和相应的方法定义一个测试脚本。

1.  在`expect`语句中，我们断言两个数字，并使用`toEqual`测试两个数字的相加是否等于`3`。

# 使用 Jasmine 测试 Angular 组件

现在是时候使用 Jasmine 框架创建我们的测试套件了。在第一部分“理解和设置用于测试的 Angular CLI”中，我们使用`ng`命令创建了`TestAppComponent`组件和`test-app.component.ts`文件。我们将在本节中继续使用相同的内容。

要开始，请添加以下代码文件的所有内容：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TestAppComponent } from './test-app.component';

describe('Testing App Component', () => {
   it('Test learning component', () => {
    let component = new TestAppComponent();
    expect(component).toBeTruthy();
   });
});

```

让我们逐步分析前面的测试套件步骤。在代码块中遵循的步骤如下：

1.  在第一步中，我们从`@angular/core/testing`导入了所有所需的测试模块。

1.  我们导入了新创建的组件`TestAppComponent`。

1.  我们通过编写一个带有名称的`describe`语句`Testing App Component`来创建了一个测试套件。

1.  我们使用`it`和相应的方法`() =>`编写了一个测试脚本。

1.  我们创建了一个`TestAppComponent`类的`component`对象。

1.  然后我们断言返回的值是否为 true。如果将该值强制转换为`boolean`后得到 true，则该值为`toBeTruthy`。

所有编写的测试套件都将以`.spec.ts`扩展名结尾，例如`test-app.component.spec.ts`。

我们目前做得很好！太棒了，现在我们将运行我们的测试套件并查看其输出。

我们仍在使用 Angular CLI 工具；让我们在项目目录中使用`ng`命令运行测试，并在终端中运行以下命令：

```ts
ng test

```

命令行工具将构建整个应用程序，打开一个新的 Chrome 窗口，使用 Karma 测试运行器运行测试，并运行 Jasmine 测试套件。

Karma 测试运行器会生成一个在浏览器中执行所有测试并监视`karma.conf.js`中指定的所有配置的 Web 服务器。我们可以使用测试运行器来运行各种框架，包括 Jasmine 和 Mocha。Web 服务器会收集所有捕获浏览器的结果并显示给开发人员。

我们应该看到如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/b19a3651-feaf-4aae-a83c-120f0530538e.png)

如果你看到了前面的截图，恭喜你。你已成功执行了测试套件，并注意测试脚本已通过。

恭喜！现在让我们深入研究并为测试组件和服务创建更复杂的测试脚本。

# 使用 Jasmine 测试 Angular 组件

在我们之前的示例中，我们已经看到了编写测试脚本和测试 Angular 组件的基本示例。

在本节中，我们将探讨编写测试 Angular 组件的最佳实践。我们将使用在前一节中创建的相同组件--`TestAppComponent`--并通过添加变量和方法来扩展测试套件。

在`test-app.component.ts`文件中，让我们创建一些变量并将它们映射到视图中：

```ts
import { Component, OnInit } from '@angular/core';

@Component({
 selector: 'app-test-app',
 templateUrl: './test-app.component.html',
 styleUrls: ['./test-app.component.css']
})
export class TestAppComponent implements OnInit {
  public authorName = 'Sridhar';
}

```

让我们分析在我们的`test-app.component.ts`文件中编写的前面的代码：

1.  我们创建了一个组件--`TestAppComponent`。

1.  我们在`templateUrl`和`styleUrls`中映射了相应的 HTML 和 CSS 文件。

1.  我们声明了一个名为`authorName`的公共`变量`，并赋予了值`'Sridhar'`。

现在，让我们转到`test-app.component.spec.ts`。我们将编写我们的测试套件，并定义一个测试用例来验证`authorName`是否与传递的字符串匹配：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { TestAppComponent } from './test-app.component';

 describe('TestAppComponent', () => {
  it('Testing App component', () => {
   let component = new TestAppComponent();
   expect(component.authorName).toMatch('Sridhar');
  });
});

```

让我们分析在`test-app.component.spec.ts`文件中前面的代码片段。已遵循以下步骤来编写代码块：

1.  我们导入了所有必需的模块`async`、`componentFixture`和`TestBed`来运行测试。

1.  我们通过编写`describe`语句并分配`Testing App Component`名称来创建了一个测试套件。

1.  我们创建了一个测试用例，并创建了`TestAppComponent`类的新实例。

1.  在`expect`语句中，我们断言`authorName`变量是否与字符串匹配。结果将返回 true 或 false。

很好！到目前为止，一切顺利。现在，继续阅读。

是时候将其提升到下一个级别了。我们将向`component`类添加新方法，并在`specs`文件中对它们进行测试。

在`test-app.component.ts`文件中，让我们添加一个变量和一个方法：

```ts
import { Component, OnInit } from '@angular/core';

@Component({
 selector: 'app-test-app',
 templateUrl: './test-app.component.html',
 styleUrls: ['./test-app.component.css']
})
export class TestAppComponent {
 public authorName = 'Sridhar';
 public publisherName = 'Packt'

 public hiPackt() {
 return 'Hello '+ this.publisherName;
 }
}

```

让我们创建`test-app.component.spec.ts`文件，并测试在`component`类中定义的变量和方法。

在`test-app.component.spec.ts`文件中，添加以下代码行：

```ts
it('Testing Component Method', () => {
 let component = new TestAppComponent();
 expect(component.hiPackt()).toBe("Hello Packt");
});

```

让我们详细分析前面的代码片段。已遵守以下步骤：

1.  我们创建了一个测试用例，并创建了`TestAppComponent`类的`component`实例。

1.  在`expect`语句中，我们断言并验证传递的字符串是否与`hiPackt`方法的返回值匹配。

在运行前面的测试脚本之前，让我们也快速看一下另一个测试用例：

```ts
describe('TestAppComponent', () => {  beforeEach(function() {
  this.app = new TestAppComponent();
 });  it('Component should have matching publisher name', function() {
  expect(this.app.publisherName).toBe('Packt');
 }); });

```

让我们分析前面的代码片段：

1.  我们实现了`beforeEach` Jasmine 方法。我们在每个测试脚本之前创建一个`AppComponent`的实例。

1.  我们编写了一个测试脚本，并使用了组件的实例，也就是`this.app`，我们获取了`publisherName`变量的值，并断言`publisherName`变量的值是否与`toBe('Packt')`匹配。

现在，测试应该自动构建，否则调用`ng test`来运行测试。

我们应该看到以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/baf610e7-e3f7-4565-94bc-ab402e678f1f.png)

太棒了！您学会了编写测试脚本来测试我们的 Angular 组件，包括变量和方法。

您学会了使用 Jasmine 框架的一些内置方法，比如`beforeEach`、`expect`、`toBeTruthy`和`toBe`。

在下一节中，我们将继续学习高级技术，并编写更多的测试脚本，以更详细地测试 Angular 组件。

# 测试 Angular 组件-高级

在本节中，我们将更深入地探讨并学习测试 Angular 组件的一些更重要和高级的方面。

如果你注意到，在前面部分的示例中可以注意到以下内容：

1.  我们在每个测试用例中单独创建了对象的实例。

1.  我们必须为每个测试用例单独注入所有的提供者。

相反，如果我们可以在每个测试脚本之前定义组件的实例，那将是很好的。我们可以通过使用`TestBed`来实现这一点--这是 Angular 提供的用于测试的最重要的实用程序之一。

# TestBed

`TestBed`是 Angular 提供的最重要的测试实用程序。它创建了一个 Angular 测试模块--一个`@NgModule`类，我们可以用于测试目的。

由于它创建了一个`@NgModule`，我们可以定义提供者、导入和导出--类似于我们常规的`@NgModule`配置。

我们可以在`async`或`sync`模式下配置`TestBed`。

+   为了异步配置`TestBed`，我们将使用`configureTestingModule`来定义对象的元数据。

+   为了同步配置`TestBed`，我们将根据前面部分的讨论定义组件的对象实例。

现在，让我们看一下以下代码片段：

```ts
beforeEach(() => {  fixture = TestBed.createComponent(AppComponent);
  comp = fixture.componentInstance;
  de = fixture.debugElement.query(By.css('h1'));
 });

```

在前面的代码片段中需要注意的重要事项：

1.  我们定义了`beforeEach`，这意味着这段代码将在每个测试用例运行之前运行。

1.  我们使用`TestBed`创建了一个组件实例。

1.  使用`TestBed`同步方式，我们定义了一个`fixture`变量，它创建了组件`AppComponent`。

1.  使用`componentInstance`，我们创建了一个`comp`变量，它是`AppComponent`的一个测试实例。

1.  使用`debugElement`函数，我们可以在视图中定义和定位特定的元素。

1.  使用`debugElement`，我们可以通过 CSS 元素选择器来定位单个元素。

现在，使用前面的`beforeEach`方法，该方法具有组件实例，我们将创建用于测试 Angular 组件的测试脚本。

# 示例 - 使用变化检测编写测试脚本

在本节中，我们将继续编写一些带有变化的测试脚本单元测试。我们还将实现变化检测和元素跟踪。

让我们开始创建一个简单的`app.component.ts`组件：

```ts
import { Component } from '@angular/core';

@Component({
 selector: 'test-root',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})

export class AppComponent {
 title = 'Packt Testing works';
}

```

让我们分析上述代码片段：

1.  我们创建了一个`AppComponent`组件类。

1.  我们声明了一个具有值的`title`变量。

1.  我们将组件的模板和样式文件映射到它们各自的`templateUrl`和`styleUrls`。

在`app.component.html`中，添加以下代码：

```ts
<h1> {{ title }} </h1>

```

在上述代码中，我们正在添加一个`<h1>`标签并映射`title`变量。

现在，是时候创建我们的测试脚本，其中包含多个断言。但在编写测试脚本之前，让我们了解用例：

1.  我们将编写脚本来检查是否创建了`ChangeDetectTestComponent`。

1.  我们将编写断言来检查`title`是否等于`Packt Testing works`。

1.  最后，我们将检查变化检测并验证`h1`标记是否应呈现并包含值`Packt Testing works`。

1.  我们还将利用`querySelector`来定位特定的元素并匹配值。

现在，让我们来看看前面用例的测试脚本：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ChangeDetectTestComponent } from './change-detect-test.component';
import { By } from '@angular/platform-browser';
import { DebugElement } from '@angular/core';

describe('ChangeDetectTestComponent', () => {

 let comp:ChangeDetectTestComponent;
   let fixture: ComponentFixture<ChangeDetectTestComponent>;
   let de:DebugElement;
   let el:HTMLElement;

 beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ ChangeDetectTestComponent ]
    });
    fixture = TestBed.createComponent(ChangeDetectTestComponent);
    comp = fixture.componentInstance;
    de = fixture.debugElement.query(By.css('h1'));
    el = de.nativeElement;
  });

it('should have as title 'Packt Testing works!'', async(() => {
   const fixture = TestBed.createComponent(ChangeDetectTestComponent);
   const app = fixture.debugElement.componentInstance;
   expect(app.title).toEqual('Packt Testing works');
 }));

it('should render title in a h1 tag', async(() => {
  const fixture = TestBed.createComponent(ChangeDetectTestComponent);
  fixture.detectChanges();
  const compiled = fixture.debugElement.nativeElement;
  expect(compiled.querySelector('h1').textContent).toContain('Packt   
    Testing works');
 }));
});

```

让我们详细分析上述代码片段：

1.  我们从`angular/core/testing`中导入所需的模块，即`TestBed`，`ComponentFixture`和`async`。

1.  我们定义`beforeEach`并初始化变量`fixture`，`comp`和`de`。

1.  在第一个测试脚本中，我们为组件编写了一个简单的期望语句，即`tobeTruthy`。

1.  在第二个测试脚本中，我们通过`TestBed.createComponent`创建了组件的实例。

1.  使用`debugElement`，我们创建了已创建组件的实例，即`app`。

1.  使用`app`组件的实例，我们能够获取组件的`title`并断言`toEqual`。

1.  在最后一个测试脚本中，我们使用`async`方法。我们利用`debugElement`的`nativeElement`方法并定位一个元素--在我们的情况下是`<h1>`，并检查标题是否包含`Packt Testing Works`。

1.  第二个和第三个测试脚本之间的区别在于我们使用了`async`方法，并等待变化被检测--`detectChanges`--在第三个测试脚本中。

运行测试，我们应该看到如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/f5076db7-4e34-4f32-8a80-0c1723b18248.png)

在本节中，您学会了如何使用`beforeEach`为所有测试脚本创建一个组件实例，以及如何使用`nativeElement`来定位任何元素。

我们使用`detectChanges`方法来识别元素中发生的变化。

在接下来的部分，我们将继续学习有关 Jasmine 框架测试 Angular 服务的更多知识。

# 测试 Angular 服务

在本节中，我们将学习有关测试 Angular 服务的知识。

在大多数 Angular 应用程序中，编写服务是一个重要且核心的方面，因为它执行与后端服务的交互；创建和共享组件之间的数据，并且在长期内易于维护。因此，确保我们彻底测试我们的 Angular 服务同样重要。

让我们学习如何编写测试脚本来测试我们的服务。为了测试一个服务，让我们首先使用`ng`命令创建一个服务。

在您的终端中运行以下命令：

```ts
ng g service ./test-app/test-app

```

上述命令将在`test-app`文件夹中生成`test-app.service.ts`和`test-app.service.spec.ts`文件。

服务是可注入的，这意味着我们必须将它们导入到它们各自的组件中，将它们添加到提供者列表中，并在组件构造函数中创建服务的实例。

我们修改`test-app.service.ts`并向其中添加以下代码：

```ts
import { Injectable } from '@angular/core';

@Injectable()
export class TestAppService {

  getAuthorCount() {
    let Authors =[
      {name :"Sridhar"},
      {name: "Robin"},
      {name: "John"},
      {name: "Aditi"}
   ];
  return Object.keys(Authors).length;
 };
}

```

从上述代码片段中注意以下重要事项：

1.  我们从 Angular 核心中导入了`injectable`。

1.  我们定义了`@injectable`元数据，并为我们的服务创建了一个类--`TestAppService`。

1.  我们定义了`getAuthorCount`方法来返回作者的数量。

我们需要将服务类导入并注入到组件中。为了测试上述服务，我们将在`test-app.service.specs.ts`文件中编写我们的测试脚本。

我们编写测试服务的方式与编写测试组件的方式类似。

现在，让我们通过在`test-app.service.spec.ts`文件中添加以下代码来创建测试套件以测试一个服务：

```ts
import { TestBed, inject } from '@angular/core/testing';
import { TestAppService } from './test-app.service';

describe('TestAppService', () => {
 beforeEach(() => {
 TestBed.configureTestingModule({
 providers: [TestAppService]
 });
 });

 it('Service should return 4 values', inject([TestAppService], 
  (service: TestAppService) => {
     let countAuthor = service.getAuthorCount;
     expect(countAuthor).toBe(4);
 }));

});

```

上述代码的分析如下：

1.  我们将所需的模块`TestBed`和`inject`导入到`spec`文件中。

1.  我们将`TestAppService`服务导入`spec`文件。

1.  使用**依赖注入**（**DI**），我们创建了`TestAppService`的`service`实例。

1.  我们创建一个测试用例；我们需要注入服务，调用`getAuthorCount`方法，并断言该值是否等于`4`。

当我们运行测试时，以下截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/8a77bcb2-5ef1-4267-a8d1-1c891a22616f.png)

在本节中，您学习了使用 Jasmine 测试脚本对 Angular 组件和服务进行单元测试。

我们必须在每个测试用例中使用 DI 来注入服务。

# 测试 Angular 服务-模拟后端服务

在前面的部分，您学习了如何编写测试脚本来测试我们的 Angular 服务。在本节中，我们将编写一个测试脚本，并学习如何在实时项目中模拟后端服务。

以下是我们将为其编写测试脚本的用例：

1.  编写一个测试脚本来测试服务中的方法。

1.  编写一个测试脚本来检查方法的返回值是否包含特定值。

1.  编写一个测试脚本来模拟后端连接使用`mockBackend`，并检查目标 URL 是否正确。

1.  编写一个测试脚本来为请求 URL 设置`mockResponse`。

1.  最后，调用`service`中编写的方法并映射响应，这应该等于`mockResponse`。

让我们创建我们的服务`test.service.ts`文件，并将以下代码添加到其中：

```ts
import { Injectable } from  '@angular/core'; import { Http } from  '@angular/http'; import { Observable } from  'rxjs'; import  'rxjs/add/operator/map'; @Injectable() export  class  TestService {
 constructor (private  http: Http) {}

 getpublications() {
    return ['Packt', 'Packt PDF', 'Packt Video'];
  }

  getproducts() {
    return  this.http.get('someurl1').map((response) =>  response);
  }

 search(term: string): Observable<any> {
   return  this.http.get(
      'someurl'
    ).map((response) =>  response.json());
  }
}

```

在前面的代码片段中需要注意的重要事项如下：

1.  我们将所需的模块导入`spec`文件，即从`Angular/core`导入`injectable`。

1.  我们将所需的模块导入`spec`文件，即从`Angular/http`导入`Http`。

1.  我们将所需的模块导入`spec`文件，即从`Angular/rxjs`导入`Observable`。

1.  我们正在为`TestService`创建组件类。

1.  我们正在使用`@injectable`装饰器，这将允许服务被注入到任何组件或服务中。

1.  在构造函数中，我们注入`HTTP`服务并创建一个 HTTP 实例。

1.  我们正在创建三个方法：`getPublications`，`getProducts`和`search`。

1.  在`getProducts`中，我们正在进行 HTTP 调用，当然，我们使用它来模拟服务器 URL。

1.  我们正在将 HTTP 请求的响应映射到`response`变量。

现在我们的服务准备就绪，我们可以开始编写我们的测试规范文件来测试变量和方法。

在`spec`文件中编写测试脚本之前，让我们创建一个`beforeEach`方法，其中将包含所有的初始化，并在每个测试脚本之前注册提供者：

```ts
  beforeEach(() => {  TestBed.configureTestingModule({
  imports: [ HttpModule ],  providers: [ {  provide:  XHRBackend,
  useClass:  XHRBackend
 }, TestService ]
 }); });

```

就像我们为测试 Angular 组件定义了`beforeEach`方法一样，我们也为服务定义了`beforeEach`方法。在提供者数组配置中，我们正在注册`XHRBackend`类。

由于服务依赖于其他模块并需要提供者，我们需要使用`configureTestingModule`来定义和注册所需的服务。

让我们详细分析前面的代码片段：

1.  我们正在定义一个`beforeEach`方法，它将在每个测试脚本之前执行。

1.  使用`TestBed`，我们正在使用`configuringTestingModule`配置测试模块。

1.  由于`configureTestingModule`中传递的参数类似于传递给`@NgModule`装饰器的元数据，我们可以指定提供者和导入项。

1.  在`imports`中，我们导入`HttpModule`。

1.  我们在提供者列表中配置所需的依赖项--`XHRBackend`和`TestService`。

1.  我们正在注册一个提供者，使用一个注入令牌`XHRBackend`并将提供者设置为`XHRBackend`，这样当我们请求提供者时，DI 系统会返回一个`XHRBackend`实例。

现在我们可以创建`spec`文件`test.service.spec.ts`，并将以下代码添加到文件中：

```ts
import {TestService} from  './test.service'; import { TestBed, inject } from  '@angular/core/testing'; import { MockBackend, MockConnection} from  '@angular/http/testing'; import { HttpModule,XHRBackend, ResponseOptions,Response, RequestMethod } from  '@angular/http'; const  mockResponse = { 'isbn':  "123456",
  'book': {  "id":  10,
  "title":  "Packt Angular"
 } }; const  mockResponseText = 'Hello Packt'; describe('service: TestService', () => {  beforeEach(() => {  TestBed.configureTestingModule({
  imports: [ HttpModule ],  providers: [ {  provide:  XHRBackend,
  useClass: XHRBackend  }, TestService]
 }); });  it('Service should return 4 publication values',    
    inject([TestService, XHRBackend], (service: TestService, 
      XHRBackend: XHRBackend) => {  let  names = service.getpublications();
  expect(names).toContain('Packt');
  expect(names).toContain('Packt PDF');
  expect(names).toContain('Packt Video');
  expect(names.length).toEqual(3);
 }));  it('Mocking Services with Json', inject([TestService, XHRBackend], 
     (service: TestService, XHRBackend: XHRBackend) => {  const  expectedUrl = 'someurl';
 XHRBackend.connections.subscribe(
 (connection: MockConnection) => {  expect(connection.request.method).toBe(RequestMethod.Get);
  expect(connection.request.url).toBe(expectedUrl);
  connection.mockRespond(new  Response(
  new  ResponseOptions({ body:  mockResponse }) )); });  service.getbooks().subscribe(res  => {  expect(res).toEqual(mockResponse);
 }); })); });

```

这是一个很长的代码片段，让我们分解进行分析：

1.  我们将`TestService`服务文件导入到`spec`文件中。

1.  我们从`@angular/core/testing`中导入所需的模块`TestBed`和`inject`。

1.  我们从`@angular/http/testing`中导入模块`MockBackend`和`MockConnection`。

1.  我们从`@angular/http`中导入模块`HttpModule`、`XHRBackend`、`ResponseOptions`、`Response`和`RequestMethod`。

1.  我们定义了一个`mockResponse`变量，其中包含一个临时的`json`对象。

1.  我们还定义了一个`mockResponseText`变量并为其赋值。

1.  我们将使用之前定义的`beforeEach`方法，通过它我们将注册所有的提供者和依赖项。

1.  在第一个测试脚本中，我们将`TestService`实例注册为`service`，将`XHRBackend`实例注册为`XHRBackend`。

1.  我们调用`service.getpublications()`方法，它将返回数组。

1.  在结果名称中，我们断言值应包含作为测试数据传递的字符串。

1.  在第二个测试脚本中，我们使用`mockBackend`创建连接，并使用`subscribe`传递请求的`method`和`url`。

1.  使用`mockRespond`连接，我们将响应值设置为`mockResponse`。

1.  我们还调用`getbooks`方法，映射响应，并断言`toEqual`值为`mockResponse`。

运行测试，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/2b790ded-b7b3-4404-8546-71ff4121305a.png)

如果你看到了前面的截图，那太棒了。

到目前为止，在本节中，你已经学习并探索了 Jasmine 框架及其用于测试 Angular 组件和服务的内置方法。

我们讨论了测试 Angular 组件：测试变量和方法。我们还讨论了如何编写`beforeEach`方法，在每个测试脚本之前执行，并如何创建组件的实例并访问其属性。我们还介绍了如何使用 Jasmine 框架测试 Angular 服务以及测试 Angular 服务及其属性：变量和方法。

对于测试 Angular 服务，你学会了如何创建一个`beforeEach`方法，在每个测试脚本之前执行，并且在每个测试脚本之前创建提供者和依赖项。

你学会了通过模拟服务来测试后端服务。当你独立开发 Angular 服务和组件时，这非常有用。

在下一节中，你将学习如何使用 Protractor 框架进行端到端测试。

# Protractor 框架简介

在前面的部分中，你学习了使用 Jasmine 进行单元测试。在本节中，你将学习如何使用 Protractor 框架进行 Angular 应用程序的端到端测试。

这就是官方网站如何解释 Protractor 的。

Protractor 是一个用于 Angular 和 AngularJS 应用程序的端到端测试框架。Protractor 在真实浏览器中运行测试，与用户交互。

Protractor 框架打包在 Angular CLI 工具中，我们可以在主项目目录中找到创建的`e2e`文件夹：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/c51d099a-d28f-4094-9f14-6c1d83c3bea4.png)

你将学习为你的 Angular 应用程序编写端到端测试，并将它们保存在`e2e`文件夹下。

记住，最好的做法是为每个功能或页面创建单独的 E2E 脚本。

# Protractor - 快速概述

Protractor 是 Selenium WebDriver 的封装，提供了许多内置的类和方法，我们可以用来编写端到端测试。

Protractor API 主要公开了各种类和方法，主要围绕`Browser`、`Element`、`Locators`和`ExpectedConditions`。

Protractor 支持 Chrome、Firefox、Safari 和 IE 的最新两个主要版本，这意味着我们可以编写测试脚本并在任何/所有可用的主流浏览器上运行它们。

为了编写端到端测试，我们需要定位页面中的元素，读取它们的属性，更新属性，并调用附加到元素的方法，或者发送和验证数据。

我们将讨论 Protractor 框架中提供的各种类和方法，通过这些方法，我们可以编写端到端测试来自动化应用程序功能。

让我们了解一下可用的方法和类，我们可以使用 Protractor 框架。

# Protractor 和 DOM

在本节中，您将学习如何使用 Protractor 与页面中的 DOM 元素进行交互。

Protractor API 支持并公开了用于定位页面中元素的类和方法。我们需要明确说明我们是需要定位特定元素，还是期望返回一组元素。

`element`函数用于在网页上查找 HTML 元素。它返回一个`ElementFinder`对象，可用于与元素交互或获取有关其属性和附加方法的信息。

我们需要动态地在页面中查找、编辑、删除和添加元素及其属性。但是，要实现这些用例，我们需要首先定义并找到目标元素。

我们可以使用以下方法定义目标元素：

+   `element`：此方法将返回单个/特定元素：

```ts
element( by.css ( 'firstName' ) );

```

+   `element.all`：此方法返回一个元素集合：

```ts
element.all(by.css('.parent'))

```

使用上述方法，我们可以定位页面中的任何元素。在下一节中，您将学习可以与`element`或`element.all`方法一起使用的可用方法。

# 一些可用于选择元素的方法

在前面的部分中，我们看到了一系列最常用的方法，用于选择或定位页面中的元素或多个元素。

要使用前面讨论的方法，您需要明确说明您是需要定位特定元素，还是期望返回一组元素。

在本节中，让我们了解一下在测试脚本中定位/选择元素的可用方法和方式。我们可以一次定位一个或多个元素。

我们可以使用几乎所有的属性、属性和自定义指令来定位特定的元素。

让我们看一下在测试脚本中定位元素的一些方法：

+   `by.css`：我们可以传递 CSS 选择器来选择一个或多个元素：

```ts
element( by.css('.firstName' ) );

```

CSS`选择器`是定位和选择元素最常用的方法。

+   `by.model`：我们使用这个来选择或定位使用绑定到元素的`ng-model`名称的元素：

```ts
element( by.model ( 'firstName' ) );

```

请注意，官方文档仍建议使用 CSS 选择器而不是模型。

+   `by.repeater`：我们使用这个方法来选择使用`ng-repeat`指令显示的元素：

```ts
element( by.repeater('user in users').row(0).column('name') );

```

+   `by.id`：我们使用这个方法来使用它的 ID 选择一个元素：

```ts
element( by.id( 'firstName' ) );

```

+   `by.binding`：使用这个来选择与单向或双向 Angular 绑定相关的元素：

```ts
element( by.binding( 'firstName' ) );

```

+   `by.xpath`：使用这个来通过`xpath`遍历选择元素：

```ts
element(by.css('h1')).element(by.xpath('following-
  sibling::div'));

```

+   `first()`、`last()`或特定元素：我们使用这些方法来获取特定位置或索引处的元素：

```ts
 element.all(by.css('.items li')).first();

```

我们了解了一些方法，可以使用它们的属性和信息来定位元素。有关可用方法的完整列表，请参阅 GitHub 上 Protractor 的官方文档。

在下一节中，您将了解可以使用的各种内置方法，以编写测试脚本来自动化应用程序逻辑。

# 探索 Protractor API

在本节中，您将了解 Protractor API 中各种内置类和方法，我们可以用来编写我们的测试脚本。

Protractor API 具有许多预定义的内置属性和方法，用于支持`Browser`、`Element`、`Locators`和`ExpectedConditions`。

它提供了许多内置方法，从点击事件到设置输入表单的数据，从获取文本到获取 URL 详细信息等等，以模拟应用程序页面中的操作和事件。

让我们快速看一下一些可用的内置方法来模拟用户交互：

+   `click`：使用这个方法，我们可以安排一个命令来点击这个元素。该方法用于模拟页面中的任何点击事件：

```ts
element.all( by.id('sendMail') ).click();

```

+   `getTagName`：这会获取元素的标签/节点名称：

```ts
element(by.css('.firstName')).getTagName()

```

+   `sendKeys`：使用这个方法，我们可以安排一个命令在 DOM 元素上输入一个序列：

```ts
element(by.css('#firstName')).sendKeys("sridhar");

```

+   `isDisplayed`：使用此方法，我们可以安排一个命令来测试此元素当前是否显示在页面中：

```ts
element(by.css('#firstPara')).isDisplayed();

```

+   `Wait`：使用此方法，我们可以执行一个命令来等待条件保持或承诺被解决：

```ts
browser.wait(function() {
  return true;
}).then(function () {
  // do some operation
});

```

+   `getWebElement`：使用此方法，我们可以找到由此`ElementFinder`表示的网页元素：

```ts
element(by.id('firstName')).getWebElement();

```

+   `getCurrentUrl`：使用此方法，我们可以检索当前应用程序页面的 URL。此方法与`browser`模块一起使用：

```ts
var curUrl = browser.getCurrentUrl();

```

有关属性和方法的完整列表，请参考 GitHub 上 Protractor 的官方文档。

在本节中，您了解了一些可用于编写测试脚本和在页面中自动化应用程序工作流程的方法。

我们将通过示例学习在以下部分中使用一些内置方法。在下一节中，我们将开始使用 Protractor 编写测试脚本。

# Protractor - 初步

在本节中，让我们开始使用 Protractor 编写测试脚本。我们将利用本章前面看到的方法和元素定位来编写我们的测试脚本。

Protractor 框架测试套件的一般语法如下：

```ts
describe("Sample Test Suite", function() {
 it("This is a spec that defines test", function() {
     // expect statement to assert the logic etc
 });
});

```

分析上述代码片段，您会意识到它与我们为 Jasmine 测试脚本创建的非常相似。太棒了！

为 Jasmine 和 Protractor 编写的测试套件看起来很相似。主要区别在于我们通过`element`和`browser`模块来定位页面中的任何特定 DOM 元素。

现在，在`app.e2e-specs.ts`文件中，我们编写我们的第一个端到端测试脚本；将以下代码片段添加到文件中：

```ts
import {element, by, browser} from 'protractor';

  describe('dashboard App', () => {
   it('should display message saying app works', () => {
    browser.get('/');
    let title = element(by.tagName('h1')).getText();
    expect(title).toEqual('Testing E2E');
   });
});

```

让我们详细分析上述代码片段。已遵循以下步骤：

1.  我们正在从`protractor`库中导入所需的模块`element`，`by`和`browser`到我们的测试脚本中。

1.  使用`describe`语句，我们为我们的端到端测试规范分配一个名称，并为其编写`specDefinitions`。

1.  我们使用`it`语句定义一个测试脚本，并在函数中使用`browser`导航到主页并检查`<H1>`标签和值是否等于`Testing E2E`。

我们已经定义了我们的`e2e`测试脚本；现在让我们使用`ng`命令运行测试，如下所示：

```ts
ng e2e

```

上述命令将运行，调用浏览器，执行`e2e`测试脚本，然后关闭浏览器。

您应该在终端中看到以下结果：

！[](assets/88c5d8ec-f9ec-4a0a-a16e-054e5253330c.png)

如果您看到所有测试脚本都通过了，那么我们所有的 E2E 测试都通过了。恭喜！

该命令需要在项目目录的父目录中运行。

# 使用 Protractor 编写 E2E 测试

在前面的部分中，您学会了如何使用 Protractor 编写您的第一个测试脚本。在本节中，我们将扩展我们的示例，并为其添加更多内容。

让我们来看看我们在示例中将自动化的用例：

1.  我们将检查我们的主页是否具有标题`Testing E2E`。

1.  我们将检查页面上是否显示了具有`firstPara` ID 的元素。

1.  我们将断言具有`firstPara` ID 的元素的`class`属性是否等于`'custom-style'`。

1.  最后，我们读取页面的当前 URL，并检查它是否等于我们在断言中传递的值。

现在让我们为此编写我们的 E2E 规范。在`app.e2e.spec.ts`文件中，添加以下代码行：

```ts
import { browser, by, element } from 'protractor';

describe('Form automation Example', function() {
 it('Check paragraphs inner text', function() {
    browser.get('/first-test');
    var s = element(by.css('#firstPara')).getText();
    expect(s).toEqual('Testing E2E');
  });

 it('Should check for getAttribute - class', function() {
    browser.get('/first-test');
    var frstPa = element(by.id('firstPara'));
    expect(frstPa.getAttribute('class')).toEqual('custom-style');
  });

 it('Should check element for isDisplayed method', function() {
    browser.get('/first-test');
    var ele = element(by.css('#firstPara')).isDisplayed();
    expect(ele).toBeTruthy();
  });

 it('Check the applications current URL', function() {
    var curUrl = browser.getCurrentUrl();
    expect(curUrl).toBe('http://localhost:49152/first-test');
  });

});

```

前面代码的分解和分析如下：

1.  我们从`protractor`导入了所需的模块`element`、`by`和`browser`。

1.  我们编写了一个`describe`语句，创建了一个名为“表单自动化示例”的测试套件。

1.  对于第一个测试脚本，我们告诉`protractor`使用`browser`通过`get`方法导航到`/first-test` URL。

1.  我们获得了具有`id`为`firstPara`的元素及其文本，并检查其值是否等于`Testing E2E`。

1.  在第二个测试脚本中，我们使用`get`方法导航到 URL`/first-test`，并获得具有`id`为`firstPara`的相同元素。

1.  现在使用`getAttribute`方法，我们获取元素的`class`属性，并检查其值是否与`'custom-style'`匹配。

1.  在第三个测试脚本中，我们告诉`protractor`使用`browser`通过`get`方法导航到`/first-test` URL。

1.  使用`isDisplayed`方法，我们检查元素是否在页面上显示。

1.  在第四个测试脚本中，我们告诉`protractor`使用`browser`方法`getCurrentUrl`来获取页面的`currentUrl`。

1.  我们检查`currentUrl`是否与测试脚本中传递的值匹配。

为了运行端到端测试，我们将使用`ng`命令。在项目目录中，运行以下命令：

```ts
ng e2e

```

以下截图显示了一旦所有测试通过后我们将看到的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/b9c29aa5-9c76-4e54-a0bf-2b88ffa01b5b.png)

创建和运行测试是多么简单和容易，对吧？

这是一个很好的开始，我们将继续学习使用高级技术编写更多的测试脚本。

继续前进，编写自动化测试脚本来插入你的逻辑和应用程序。

# 使用 Protractor 编写 E2E 测试-高级

到目前为止，在之前的章节中，我们已经涵盖了使用 Protractor 框架安装、使用和编写测试脚本。我们已经学习并实现了 Protractor API 公开的内置方法和类。

在本节中，我们将介绍编写高级测试脚本，这些脚本将在页面中进行交互，并对元素进行彻底测试。

让我们看一下我们将涵盖的用例：

1.  我们将测试我们的数组数值。

1.  我们将使用`class`属性来定位我们的元素。

1.  我们将检查页面的标题。

1.  我们将模拟附加在按钮上的`click`事件，然后验证另一个元素的文本更改。

让我们开始编写我们的测试脚本。

我们需要首先创建我们的`test-app.component.html`文件。创建文件，并将以下代码添加到文件中：

```ts
<h3 class="packtHeading">Using protractor - E2E Tests</h3>

<input id="sendEmailCopy" type="checkbox"> Send email copy

<!-- paragraph to load the result -->
<p class="afterClick">{{afterClick}}</p>

<!-- button to click -->
<button (click)="sendMail()">Send mail!</button>

```

上述代码片段的分析如下：

1.  我们定义了一个`h3`标题标签，并分配了一个`class`属性，值为`packtHeading`。

1.  我们创建了一个 ID 为`sendEmailCopy`的`input`类型`checkbox`元素。

1.  我们定义了一个带有`class`属性为`afterClick`的段落`p`标签，并绑定了`{{ }}`中的值。

1.  我们定义了一个`button`并附加了一个`click`事件来调用`sendMail`方法。

1.  `sendMail`方法的目的是改变`paragraph`标签内的文本。

现在我们已经定义了模板文件，是时候创建我们的组件文件了。

创建`test-app.component.ts`文件，并将以下代码片段添加到其中：

```ts
import { Component } from '@angular/core';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({ 
 selector: 'app-test-app',
 templateUrl: './test-app.component.html',
 styleUrls: ['./test-app.component.css']
})

export class TestAppComponent { 
  constructor() {} 

  public myModel = "Testing E2e";
  public authorName = 'Sridhar';
  public publisherName = 'Packt';
  public afterClick = 'Element is not clicked';

  public hiPackt() {
    return 'Hello ' + this.publisherName;  
  }
  public sendMail() {
   this.afterClick = 'Element is clicked';
  }
}

```

让我们详细分析上述代码片段：

1.  我们从`@angular/core`导入了`Component`和`Oninit`模块。

1.  我们还从`@angular/forms`导入了`FormsModule`。

1.  我们创建了`Component`并将 HTML 和 CSS 文件分别关联到`templateUrl`和`stylesUrl`。

1.  我们定义了`myModel`、`authorName`、`publisherName`和`afterClick`变量。

1.  我们为定义的变量赋值。

1.  我们定义了一个`hiPackt`方法，它将显示`Hello Packt`。

1.  我们定义了一个`sendMail`方法，当调用时将更新`afterClick`变量的值。

到目前为止，一切顺利。跟着我继续；我们很快就要编写出漂亮的测试脚本了。

现在，我们已经定义了模板文件并实现了组件文件；我们非常了解组件的功能。现在是时候开始测试部分了。

让我们创建测试规范`app.e2e.spec.ts`文件，并将以下代码片段添加到其中：

```ts
import {element, by, browser} from 'protractor';

describe('dashboard App', () => {
 beforeEach(function () {
   browser.get('/test-app');
 });

 it('should display message saying app works', () => {
  const title = element(by.tagName('h1')).getText();
  expect(title).toEqual('Learning Angular - Packt Way');
 });

 it('should display message saying app works', () => {
  element(by.tagName('button')).click();
  const title = element(by.css('.afterClick')).getText();
  expect(title).toEqual('Element is not clicked');
 });

 it('Should check is radio button is selected or deselected',  
  function() {
    var mailCopy = element(by.id('sendEmailCopy'));
    expect(mailCopy.isSelected()).toBe(false);
    mailCopy.click();
    expect(mailCopy.isSelected()).toBe(true);
 });

 it('Check the applications current URL', function() {
   var curUrl = browser.getCurrentUrl();
   expect(curUrl).toBe('http://localhost:49152/test-app');
 });

});

```

让我们详细看看我们的测试规范中发生了什么：

1.  我们定义了一个`beforeEach`方法，它将在测试脚本之前执行，并打开浏览器 URL。

1.  现在，我们编写一个测试脚本来测试`h1`标签的`title`值，使用断言`toEqual`。

1.  在第二个测试脚本中，我们使用`tagName`获取`button`元素，并调用`click`方法。

1.  由于方法是`clicked`，段落的值已经更新。

1.  我们将使用`by.css`检索段落元素，并获取其中的段落文本`value`。

1.  我们断言新更新的`value`是否等于`Element is clicked`。

1.  在第三个测试脚本中，我们使用`isSelected`方法检查`input`元素类型`checkbox`是否被选中。

1.  使用`click`方法，我们现在切换`checkbox`并再次检查值。这个测试脚本是为了向您展示如何操作表单元素。

1.  最后，在最后一个测试脚本中，我们使用`getCurrentUrl`获取当前页面的 URL，并检查它是否匹配`/test-app`。

就这样，全部完成了。现在，我们已经有了模板文件，创建了组件，也有了测试规范文件。

现在是展示时间。让我们运行应用程序，我们应该看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/exp-ng/img/4a305d2c-67c0-4fbe-82f6-05e59467efef.png)

在本节中，您学会了使用 Protractor 框架编写测试脚本。我们探索了框架中所有内置的可用方法，供我们在编写脚本时使用。

我们注意到编写的测试脚本与 Jasmine 测试脚本类似。我们还看到了如何使用各种方法（如`by.css`、`by.binding`和`by.id`）来定位特定元素或元素集合。

我们讨论了使用 Protractor 框架进行事件处理和绑定。

# 总结

测试是应用程序开发中最关键和重要的方面之一。在本章中，您学习了如何使用 Angular CLI、Jasmine 和 Protractor 框架。使用 Jasmine 和 Protractor 进行自动化测试可以帮助您节省时间和精力。

您学习了为 Angular 组件和服务编写单元测试脚本，以及如何为工作流自动化测试编写 E2E 测试用例。您详细了解了 Jasmine 框架和 Protractor 框架中内置到函数中的方法和变量。

我们深入研究了针对特定元素的定位，以及一起检索元素集合以读取、更新和编辑属性和数值。继续使用这些出色的测试框架来自动化您的应用程序。

在下一章中，您将学习 Angular 中的设计模式。Typescript 是一种面向对象的编程语言，因此我们可以利用几十年关于面向对象架构的知识。您还将探索一些最有用的面向对象设计模式，并学习如何在 Angular 中应用它们。
