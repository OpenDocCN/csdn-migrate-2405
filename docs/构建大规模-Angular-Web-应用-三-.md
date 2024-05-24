# 构建大规模 Angular Web 应用（三）

> 原文：[`zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43`](https://zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：深入了解 Angular 指令

**指令** 始终随处可见。它们是 Angular 的基本构建块。每个应用程序的扩展都导致我们创建新的 **组件指令**。这些组件指令进一步使用了 **属性指令**（如`NgClass`和 `NgStyle`）和 **结构指令**（如`NgIf`和 `NgFor`）来扩展其行为。

虽然我们已经构建了许多组件指令和一个单独的属性指令，但仍有一些值得探索的指令构建概念。特别是对于属性和结构指令，我们尚未详细介绍。

本章将涵盖以下主题：

+   **构建指令**：我们构建多个指令，并学习指令的有用之处，它们与组件的区别，以及指令如何相互通信和/或与它们的宿主组件通信。我们探讨包括*组件指令*、*属性指令*和*结构指令*在内的所有指令类型。

+   **异步验证**：Angular 可以轻松验证需要服务器交互和因此是异步的规则。在本章中，我们将构建我们的第一个异步验证器。

+   **使用渲染器进行视图操作**：渲染器允许以与平台无关的方式进行视图操作。我们将利用渲染器来实现繁忙指示器指令，并学习其 API。

+   **宿主绑定**：宿主绑定允许指令与其*宿主元素*进行通信。本章将涵盖如何利用这样的绑定来进行指令。

+   **指令注入**：Angular DI 框架允许基于指令在 HTML 层次结构中的声明位置进行指令注入。我们将介绍与此类注入相关的多种情景。

+   **使用视图子和内容子**：组件具有将外部视图模板包含到其自身视图中的能力。我们将介绍如何处理注入的内容。

+   **理解 NgIf 平台指令**：我们将深入了解`NgIf`平台指令的内部工作，并尝试理解*结构指令*（如`NgIf`）的工作方式。

+   **Angular 组件的视图封装**：我们将学习 Angular 如何使用来自*Web 组件*的概念来支持视图和样式的封装。

# 构建远程验证器指令

我们以*支持服务器数据持久性*的第三章 结束了 *Workout Runner* 能够在 MongoDB 存储中管理锻炼。由于每个锻炼都应具有唯一名称，我们需要执行唯一性约束。因此，在创建/编辑锻炼时，每当用户更改锻炼名称时，我们可以查询 MongoDB 来验证该名称是否已存在。

与任何远程调用一样，这个检查是异步进行的，因此需要一个 *远程验证器*。我们将使用 Angular 的 *异步验证器支持* 来构建这个远程验证器。

**异步验证器**与标准自定义验证器类似，只是返回的不是键-值对象映射或 null，而是一个**promise**。这个 promise 最终将根据验证状态进行解析（如果有错误，则设置为相应状态），如果验证成功，则返回 null。

我们将创建一个验证指令，用于进行工作名称检查。针对这样的指令，有两种可能的实现方法：

+   我们可以专门为唯一名称验证创建一个指令

+   我们可以创建一个通用指令，可以执行任何远程验证。

验证指令

尽管我们正在构建一个验证指令，但我们也可以构建一个标准的自定义验证器类。创建指令的优势在于它可以让我们将指令嵌入到模板驱动的表单中，在视图 HTML 中使用指令。或者，如果表单是使用模型（响应式方法）生成的，我们可以在创建`Control`对象时直接使用验证器类。

起初，针对数据源（*mLab*数据库）检查重复名称的要求似乎是一个过于具体的要求，无法通过通用验证器来处理。但通过一些明智的假设和设计选择，我们仍然可以实现一个能够处理所有类型远程验证的验证器，包括工作名称验证。

计划是创建一个外部化实际验证逻辑的验证器。该指令将以验证函数作为输入。这意味着实际验证逻辑不是验证器的一部分，而是实际需要验证输入数据的组件的一部分。指令的工作仅是调用函数并根据函数的返回值返回相应的错误键。

让我们把这个理论付诸实践，构建我们的远程验证指令，恰如其名的`RemoteValidatorDirective`。

以下部分的伴随代码基于 Git 分支`checkpoint6.1`。您可以与我们一起工作，或者查看上述文件夹中提供的实现。或者，如果您不使用 Git，可以从 GitHub 位置[`bit.ly/ng2be-checkpoint6-1`](http://bit.ly/ng2be-checkpoint6-1)下载`checkpoint6.1`的快照（ZIP 文件）。在首次设置快照时，请参考`trainer`文件夹中的`README.md`文件。

# 使用异步验证器验证工作名称

与自定义验证器类似，异步验证器也继承自相同的`Validator`类；但这次，异步验证器返回一个`Promise`而不是对象映射。

让我们来看看验证器的定义。从 GitHub（[`bit.ly/ng6be-6-1-remote-validator-directive-ts`](http://bit.ly/ng6be-6-1-remote-validator-directive-ts)）文件夹中复制验证器的定义，并将其添加到`shared`模块文件夹。验证器的定义如下：

```ts
import { Directive, Input } from '@angular/core';
import { NG_ASYNC_VALIDATORS, FormControl } from '@angular/forms';

@Directive({
  selector: '[abeRemoteValidator][ngModel]',
  providers: [{ provide: NG_ASYNC_VALIDATORS, useExisting: RemoteValidatorDirective, multi: true }]
})
export class RemoteValidatorDirective {

  @Input() abeRemoteValidator: string;
  @Input() validateFunction: (value: string) => Promise<boolean>;

  validate(control: FormControl): { [key: string]: any } {
    const value: string = control.value;
    return this.validateFunction(value).then((result: boolean) => {
      if (result) {
        return null;
      }
      else {
        const error: any = {};
        error[this.abeRemoteValidator] = true;
        return error;
      }
    });
  }
} 
```

切记要从共享模块导出这个指令，以便我们可以在锻炼构建器模块中使用它。

由于我们将验证器注册为指令，而不是使用 `FormControl` 实例进行注册（通常用于以*响应式方式*构建表单时），我们需要额外的提供者配置设置（在前述`@Directive`元数据中添加）,通过以下语法：

```ts
 providers:[{ provide: NG_ASYNC_VALIDATORS, useExisting: RemoteValidatorDirective,  multi: true }] 
```

此语句将验证器注册到现有的异步验证器中。

在接下来的部分中，我们将构建一个繁忙指示器指令，解释在前述代码中使用的奇怪的指令选择器`selector: `[abeRemoteValidator][ngModel]`。

在我们深入研究验证器实现之前，让我们将其添加到锻炼名称输入中。这将帮助我们将验证器的行为与其使用联系起来。

用验证器声明更新锻炼名称输入（`workout.component.html`）：

```ts
<input type="text" name="workoutName" ... 
 abeRemoteValidator="workoutname"[validateFunction]="validateWorkoutName"> 
```

为指令选择器添加前缀

始终使用一个标识符（正如你刚刚看到的`abe`）作为你的指令前缀，以将其与框架指令和其他第三方指令区分开来。

**注意**：如果 `ngModelOptions`，`updateOn` 设置为 `submit,`，则更改为 `blur`。

指令实现通过指令属性`abeRemoveValidator`接受两个输入：*validation key*，用于设置*error key*，和*validation function*（`validateFunction`），用于验证控件的值。这两个输入都用`@Input`装饰器进行了注解。

输入参数`@Input("validateFunction") validateFunction: (value: string) => Promise<boolean>;`，绑定到一个函数，而不是标准的组件属性。由于底层语言 TypeScript 的性质（以及 JavaScript），我们可以把这个函数当作属性对待。

当异步验证触发（输入更改时），Angular 调用该函数，并传入基础的`control`。作为第一步，我们提取当前的输入值，然后使用该输入调用 `validateFunction` 函数。`validateFunction` 返回一个 promise，最终应该解析为 `true` 或 `false`：

+   如果 promise 解析为`true`，则验证成功，promise 回调函数返回`null`。

+   如果是 `false`，则验证失败，返回一个错误键值映射。这里的*key*是我们在使用验证器时设置的字符串字面量（`a2beRemoteValidator="workoutname"`）。

这个*key*在输入上有多个验证器声明时非常有用，可以帮助我们识别失败的验证。

接下来在锻炼组件中为这个失败添加一个验证消息。在现有的*workout name*的验证`label`后添加此标签声明：

```ts
<label *ngIf="name.control.hasError('workoutname')" class="alert alert-danger validation-message">A workout with this name already exists.</label> 
```

然后将这两个标签包裹在 `div` 中，就像我们为*workout title*错误标签做的那样。

`hasError` 函数检查`'workoutname'`验证键是否存在。

这个实现缺少的最后一部分是我们在应用指令时分配的实际验证函数（`[validateFunction]="**validateWorkoutName**""`），但尚未实现。

将 `validateWorkoutName` 函数添加到 `workout.component.ts` 中。

```ts
validateWorkoutName = (name: string): Promise<boolean> => {
    if (this.workoutName === name) { return Promise.resolve(true); }
    return this.workoutService.getWorkout(name).toPromise()
      .then((workout: WorkoutPlan) => {
        return !workout;
      }, error => {
        return true;
      });
  }  
```

在探索前面的函数功能之前，我们需要对 `WorkoutComponent` 类进行一些其他修复。`validateWorkoutName` 函数依赖于 `WorkoutService` 来获取具有特定名称的训练计划。让我们在构造函数中注入该服务，并在导入部分添加必要的导入。

```ts
import { WorkoutService }  from "../../core/workout.service"; 
... 
constructor(... , private workoutService: WorkoutService) { 
```

然后声明 `workoutName` 和 `queryParamsSub` 变量。

```ts
private workoutName: string;
queryParamsSub: Subscription
```

并在 `ngOnInit` 中添加这个语句。

```ts
this.queryParamsSub = this.route.params.subscribe(params => this.workoutName = params['id']); 
```

前述语句通过观察（订阅）`route.params` 服务的 observable 来设置当前的训练计划名称。`workoutName` 用于在使用原始训练计划名称时跳过训练计划名称验证。

之前创建的订阅需要清除以避免内存泄漏，因此将此行添加到 `ngDestroy` 函数中。

```ts
this.queryParamsSub.unsubscribe();
```

将 `validateWorkoutName` 函数定义为*实例函数*（使用*箭头运算符*）而不是标准函数（在*原型*上声明函数）的原因是 `'this'` 作用域问题。

查看 `RemoteValidatorDirective` 中 `validateFunction` 指令的验证器函数调用（使用 `@Input("validateFunction") validateFunction;` 进行声明）。

```ts
return this.validationFunction(value).then((result: boolean) => { ... }); 
```

当函数（名为 `validateFunction`）被调用时，`this` 引用被绑定到 `RemoteValidatorDirective`，而不是 `WorkoutComponent`。由于 `execute` 在前述设置中引用了 `validateWorkoutName` 函数，所以内部对 `this` 的任何访问都会有问题。

这会导致 `validateWorkoutName` 内部的 `if (this.workoutName === name)` 语句失败，因为 `RemoteValiatorDirective` 没有 `workoutName` 实例成员。通过将 `validateWorkoutName` 定义为实例函数，TypeScript 编译器在函数定义时*创建了一个闭包*，捕获了 `this` 的值。

通过新的声明，`validateWorkoutName` 内部的 `this` 始终指向 `WorkoutComponent`，不管函数是如何被调用的。

我们还可以查看 `WorkoutComponent` 的编译后的 JavaScript 代码，了解闭包是如何与 `validateWorkoutName` 一起工作的。我们关注的生成代码部分如下：

```ts
function WorkoutComponent(...) { 
 var _this = this; 
  ... 
  this.validateWorkoutName = function (name) { 
 if (_this.workoutName === name) 
      return Promise.resolve(true); 
```

如果我们查看验证函数的实现，我们会发现它涉及查询 *mLab* 以获取特定的训练计划名称。`validateWorkoutName` 函数在未找到同名训练计划时返回 `true`，在找到同名训练计划时返回 `false`（实际上返回的是一个*promise*）。

`WorkoutService` 上的 `getWorkout` 函数返回一个*observable*，但我们通过调用 observable 上的 `toPromise` 函数将其转换为一个*promise*。

现在可以测试验证指令了。创建一个新的训练，并输入一个已有的训练名称，如`7minworkout`。看看验证错误消息是如何最终显示出来的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3f7be3d2-984e-406c-858c-02aca3b262ce.png)

很棒！看起来很不错，但仍然缺少一些东西。用户并不知道我们正在验证训练名称。我们可以改善这个体验。

# 创建一个忙碌指示器指令

当远程验证训练名称时，我们希望用户意识到后台的活动。在远程验证发生时围绕输入框提供视觉线索应该能达到目的。

仔细思考一下；有一个带有异步验证器（执行远程验证）的输入框，我们想要在验证期间用一个视觉线索装饰输入框。看起来像一个常见的解决模式？的确如此，所以让我们创建另一个指令！

但在我们开始实施之前，必须明确理解我们并不孤军奋战。忙碌指示器指令需要另一个指令`NgModel`的帮助。我们已经在第二章*个人教练*中的`input`元素上使用了`NgModel`指令。`NgModel`帮助我们跟踪输入元素的状态。以下示例取自第二章《个人教练》，突出了`NgModel`如何帮助我们验证输入：

```ts
<input type="text" name="workoutName" #name="ngModel"  class="form-control" id="workout-name" ... [(ngModel)]="workout.name" required> 
... 
<label *ngIf="name.control.hasError('required') && (name.touched || submitted)" class="alert alert-danger">Name is required</label>  
```

即使在上一部分中完成了唯一的训练名称验证，也是使用了相同的`NgModel`技术来检查验证状态。

让我们从定义指令的概要开始。在`src/app/shared`文件夹中使用 CLI 生成器创建一个`busy-indicator.directive.ts`文件：

```ts
ng generate directive busy-indicator
```

同样，通过将指令添加到共享模块文件`shared.module.ts`中的`exports`数组中导出它。

接下来，使用`NgModel`注入来更新指令的构造函数，并从`@angular/forms`中导入`NgModel`引用：

```ts
constructor(private model: NgModel) { }
```

这告诉 Angular 要对声明指令的元素注入`NgModel`实例。记住，`NgModel`指令已经存在于`input`（`workoutname`）上了：

```ts
<input... name="workoutName" #name="ngModel" [(ngModel)]="workout.name" ...>
```

这已经足够将我们的新指令集成到训练视图中了，让我们快速做吧。

打开`workout-builder`中的`workout.component.html`，并在训练名称`input`中添加忙碌指示器指令：

```ts
<input type="text" name="workoutName" ... abeBusyIndicator> 
```

创建一个新的训练或打开一个现有的训练，查看`BusyIndicatorDirective`是否已加载并且`NgModel`注入是否正常工作。这可以通过在`BusyIndicatorDirective`构造函数内设置断点来轻松验证。

Angular 将相同的`NgModel`实例注入到`BusyIndicatorDirective`中，就像在输入 HTML 中遇到`ngModel`时创建的那样。

也许你会想知道，如果我们将这个指令应用于没有`ngModel`属性的输入元素，或者实际上任何 HTML 元素/组件，会发生什么，例如这样：

```ts
<div abeBusyIndicator></div> 
<input type="text" abeBusyIndicator> 
```

注射会起作用吗？

当然不是！我们可以在创建锻炼视图中试一下。打开`workout.component.html`，并在锻炼名称`input`上面添加以下`input`。刷新应用：

```ts
<input type="text" name="workoutName1" a2beBusyIndicator> 
```

Angular 抛出一个异常，如下所示：

```ts
 EXCEPTION: No provider for NgModel! (BusyIndicatorDirective -> NgModel)
```

如何避免这个问题？嗯，Angular 的 DI 可以在这里拯救我们，因为它允许我们声明一个可选的依赖关系。

在继续之前删除刚刚添加的`input`控件。

# 用`@Optional`装饰器注入可选依赖项

Angular 有一个`@Optional`装饰器，当应用于构造函数参数时，指示 Angular *注入器*在找不到依赖项时注入`null`。

因此，繁忙指示符构造函数可以写成如下所示：

```ts
constructor(@Optional() private model: NgModel) { } 
```

问题解决了吗？并没有；正如先前所述，我们需要`NgModel`指令使`BusyIndicatorDirective`起作用。因此，虽然我们学到了一些新知识，但在当前情况下并不是很有用。

在继续之前，请记得将`workoutname``input`还原为初始状态，应用`abeBusyIndicator`。

只有在元素上已经存在`NgModel`指令时，才能应用`BusyIndicatorDirective`。

这次，`selector`指令将会拯救我们。将`BusyIndicatorDirective`选择器更新为如下所示：

```ts
selector: `[abeBusyIndicator][ngModel]` 
```

如果元素上同时存在`a2beBusyIndicator`和`ngModel`属性的组合，那么这个选择器将创建`BusyIndicatorDirective`。问题解决了！

是时候添加实际的实现了。

# 实现一 - 使用渲染器

要使`BusyIndicatorDirective`起作用，它需要知道`input`上的异步验证何时触发以及何时结束。这些信息只能由`NgModel`指令提供。`NgModel`有一个`control`属性，它是`Control`类的一个实例。正是这个`Control`类跟踪输入的当前状态，包括以下内容：

+   当前分配的验证器（同步和异步）

+   当前值

+   输入元素的状态，比如`pristine`、`dirty`和`touched`

+   输入验证状态可能是`valid`、`invalid`或者在异步执行验证时是`pending`之一

+   跟踪数值变化或验证状态变化的事件

`Control`看起来是一个很有用的类，它的`pending`状态引起了我们的兴趣！

让我们为`BusyIndicatorDirective`类添加第一个实现。用以下代码更新类：

```ts
private subscriptions: Array<any> = []; 
ngAfterViewInit(): void {
    this.subscriptions.push(
      this.model.control.statusChanges.subscribe((status: any) => {
        if (this.model.control.pending) {
          this.renderer.setElementStyle(this.element.nativeElement, 'border-width', '3px');
          this.renderer.setElementStyle(this.element.nativeElement, 'border-color', 'gray');
        }
        else {
          this.renderer.setElementStyle(this.element.nativeElement, 'border-width', null);
          this.renderer.setElementStyle(this.element.nativeElement, 'border-color', null);
        }
      }));
  }  
```

需要向构造函数添加两个新的依赖项，因为我们在`ngAfterViewInit`函数中使用它们。将`BusyIndicatorDirective`构造函数更新如下：

```ts
constructor(private model: NgModel,  
 private element: ElementRef, private renderer: Renderer) { }
```

还需要在`'@angular/core'`中导入`ElementRef`和`Renderer`。

`ElementRef`是对底层 HTML 元素（在本例中是`input`）的包装对象。`MyAudioDirective`指令使用`ElementRef`来获取底层的`Audio`元素。

`Renderer` 注入值值得一提。调用 `setElementStyle` 很明显是 `Renderer` 负责管理 DOM 的标志。 但在更深入地了解 `Renderer` 的角色之前，让我们尝试理解前面的代码在做什么。

在前面的代码中，模型（`NgModel` 实例）上的 `control` 属性定义了一个事件（一个 `Observable`），`statusChanges`，我们可以订阅以了解控件验证状态何时更改。 可用的验证状态是`valid`、`invalid` 和 `pending`。

订阅检查控件状态是否为`pending`，并相应地使用 `Renderer` API 函数 `setElementStyle` 装饰底层元素。 我们设置 `input` 的 `border-width` 和 `border-color`。

前述的实现添加到 `ngAfterViewInit` 指令生命周期钩子中，该生命周期钩子在视图初始化后调用。

让我们试一试。打开创建锻炼页面或现有的 *7 分钟锻炼*。 一旦我们离开锻炼名称输入，`input` 样式会更改，并在锻炼名称的远程验证完成后恢复。 好！

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/298a4f9b-ed8c-4e43-8f9d-b98633a24d68.png)

在继续之前，还要将取消订阅代码添加到 `BusyIndicatorDirective` 中以避免内存泄漏。 将此函数（生命周期钩子）添加到 `BusyIndicatorDirective` 中：

```ts
ngOnDestroy() { 
    this.subscriptions.forEach((s) => s.unsubscribe()); 
} 
```

始终取消订阅 observables

要始终记住取消对代码中已完成的任何 `Observable`/`EventEmitter` 订阅，以避免内存泄漏。

实现看起来不错。`Renderer`正在发挥作用。但还有一些未解答的问题。

为什么不直接获取底层 DOM 对象并使用标准 DOM API 来操作输入样式？ 为什么我们需要 *renderer*？

# Angular 渲染器，翻译层

Angular 2 的主要设计目标之一是使其在各种环境、框架和设备上运行。 Angular 通过将核心框架实现分为**应用层**和**呈现层**来实现了这一目标。 应用层具有我们交互的 API，而呈现层提供了一个抽象，应用层可以使用它而不必担心视图的实际渲染位置。

通过分离渲染层，Angular 理论上可以在各种设置中运行。其中包括（但不限于）：

+   浏览器

+   浏览器主线程和网络工作线程，出于明显的性能原因

+   服务器端渲染

+   原生应用程序框架；正在努力将 Angular 与 `NativeScript` 和 `ReactNative` 集成。

+   测试，允许我们在网络浏览器之外测试应用程序 UI

Angular 在浏览器中使用的 `Renderer` 实现是 `DOMRenderer`。 它负责将我们的 API 调用转换为浏览器 DOM 更新。 实际上，我们可以通过在 `BusyIndicatorDirective` 的构造函数中添加断点并查看 `renderer` 的值来验证渲染器类型。

准确因此，我们避免在`BusyIndicatorDirective`内部直接操纵 DOM 元素。您永远不知道代码最终将在哪里运行。我们本来很容易就可以这样做：

```ts
this.element.nativeElement.style.borderWidth="3px"; 
```

相反，我们使用了`Renderer`以平台无关的方式来做同样的事情。

查看`Renderer`API 函数，`setElementStyle`：

```ts
this.renderer.setElementStyle( 
             this.element.nativeElement, "border-width", "3px"); 
```

它接受要设置样式的元素，要更新的样式属性和要设置的值。`element`引用了注入到`BusyIndicatorDirective`中的`input`元素。

重置样式

通过调用`setElementStyle`设置的样式可以通过在第三个参数中传递`null`值来重置。请查看前面代码中的`else`条件。

`Renderer`API 还有许多其他方法可用于设置属性、设置属性、监听事件，甚至创建新视图。每当您构建新指令时，请记得评估`Renderer`API 以进行 DOM 操作。

有关`Renderer`及其应用的更详细解释，请参阅 Angular 的设计文档的这里：[`bit.ly/ng2-render`](http://bit.ly/ng2-render)

我们还没有完成！借助 Angular 的强大功能，我们可以改进此实现。Angular 允许我们在指令实现中进行*主机绑定*，帮助我们避免大量样板代码。

# 指令中的主机绑定

在 Angular 领域，指令附加到的组件/元素被称为**宿主元素**：一个承载我们的指令/组件的容器。对于`BusyIndicatorDirective`，`input`元素就是*宿主*。

虽然我们可以使用`Renderer`来操纵宿主（我们也是这样做的），但是 Angular 数据绑定基础设施可以进一步减少代码。它提供了一种声明性的方式来管理指令-宿主交互。使用主机绑定概念，我们可以操纵元素的*属性*和*属性*，并订阅其*事件*。

让我们了解每种主机绑定的能力，最后，我们将修复我们的`BusyIndicatorDirective`实现。

# 使用@HostBinding 进行属性绑定

使用**主机属性绑定**将*指令属性*绑定到*宿主元素属性*。在变更检测阶段，对指令属性的任何更改都将与链接的主机属性同步。

我们只需要在想要同步的指令属性上使用`@HostBinding`装饰器。例如，考虑这样的绑定：

```ts
@HostBinding("readOnly") get busy() {return this.isbusy}; 
```

当应用于`input`时，当`isbusy`指令属性为`true`时，它将将`input``readOnly`属性设置为`true`。

注意，`readonly`也是`input`上的*属性*。这里指的是我们所说的输入*属性*`readOnly`。

# 属性绑定

**属性绑定**将指令属性绑定到宿主组件属性。例如，考虑具有以下绑定的指令：

```ts
@HostBinding("attr.disabled") get canEdit(): string  
  { return !this.isAdmin ? "disabled" : null }; 
```

如果应用于输入，当`isAdmin`标志为`false`时，它将在`input`上添加`disabled`属性，并在`isAdmin`为真时清除它。我们在这里也遵循 HTML 模板中使用的相同属性绑定符号。属性名称前缀为字符串字面量`attr`。

我们也可以使用*class*和*style 绑定*来做类似的事情。考虑以下行：

```ts
@HostBinding('class.valid')  
   get valid { return this.control.valid; } 
```

这一行设置了一个类绑定，下一行创建了一个样式绑定：

```ts
@HostBinding("style.borderWidth")  
   get focus(): string { return this.focus?"3px": "1px"}; 
```

# 事件绑定

最后，**事件绑定**用于订阅宿主组件/元素引发的事件。考虑这个例子：

```ts
@Directive({ selector: 'button, div, span, input' }) 
class ClickTracker { 
  @HostListener('click', ['$event.target']) 
  onClick(element: any) { 
    console.log("button", element, "was clicked"); 
  } 
} 
```

这在宿主事件`click`上建立了一个监听器。Angular 将为视图上的每个*button*、*div*、*span*和*input*实例化前述指令，并为`onClick`函数设置宿主绑定。`$event`变量包含引发的事件数据，`target`指的是所点击的元素/组件。

事件绑定也适用于组件。考虑以下例子：

```ts
@Directive({ selector: 'workout-runner' }) 
class WorkoutTracker { 
  @HostListener('workoutStarted', ['$event']) 
  onWorkoutStarted(workout: any) { 
    console.log("Workout has started!"); 
  } 
} 
```

通过这个指令，我们跟踪了在`WorkoutRunner`组件上定义的`workoutStarted`事件。当锻炼开始时，将调用`onWorkoutStarted`函数，并带上已开始的锻炼的详情。

现在我们了解了这些绑定是如何工作的，我们可以改进我们的`BusyIndicatorDirective`实现。

# 实施二 - 具有宿主绑定的 BusyIndicatorDirective

你可能已经猜到了！我们将使用*宿主属性绑定*而不是`Renderer`来设置样式。想要试试吗？试一试吧！清除现有的实现，尝试在不查看以下实现的情况下为`borderWidth`和`borderColor`样式属性设置宿主绑定。

在宿主绑定实现之后，指令将如下所示：

```ts
import {Directive, HostBinding} from '@angular/core'; 
import {NgModel} from '@angular/forms'; 

@Directive({ selector: `[abeBusyIndicator][ngModel]`}) 
export class BusyIndicatorDirective {
  private get validating(): boolean {
    return this.model.control != null && this.model.control.pending;
  }
  @HostBinding('style.borderWidth') get controlBorderWidth():
        string { return this.validating ? '3px' : null; }
  @HostBinding('style.borderColor') get controlBorderColor():
        string { return this.validating ? 'gray' : null; }

  constructor(private model: NgModel) { }
}

```

我们已经将`pending`状态检查移到了名为`validating`的指令属性中，然后使用了`controlBorderWidth`和`controlBorderColor`属性进行样式绑定。这绝对比我们之前的方法更简洁！去测试一下吧。

如果我们告诉你，这可以不需要自定义指令来完成，你不要感到惊讶！这就是我们做的，只需在锻炼名称`input`上使用样式绑定即可：

```ts
<input type="text" name="workoutName" ... 
[style.borderColor]="name.control.pending ? 'gray' : null" [style.borderWidth]="name.control.pending ? '3px' : null">
```

我们得到了相同的效果！

不，我们的努力并不是白费的。我们学到了**renderer**和**host binding**。这些概念在构建提供复杂行为扩展而不仅仅是设置元素样式的指令时会派上用场。

如果你在运行代码时遇到问题，请查看 Git 分支`checkpoint6.1`，查看我们迄今为止所做的工作的可运行版本。或者，如果你没有使用 Git，请从[`bit.ly/ng6be-checkpoint-6-1`](http://bit.ly/ng6be-checkpoint-6-1)下载`checkpoint6.1`的快照（ZIP 文件）。在第一次设置快照时，请查看`trainer`文件夹中的`README.md`文件。

我们接下来要讨论的主题是*指令注入*。

# 指令注入

回到几页前，看一下使用*renderer*的`BusyIndicatorDirective`实现，特别是构造函数：

```ts
constructor(private model: NgModel ...) { } 
```

Angular 会自动定位为指令元素创建的`NgModel`指令，并将其注入到`BusyIndicatorDirective`中。这是可能的，因为这两个指令都声明在同一个*宿主元素*上。

好消息是我们可以影响这种行为。在父 HTML 树或子树上创建的指令也可以被注入。接下来的几节将讨论如何在组件树中跨指令进行注入，这是一个非常实用的功能，允许具有*共同血统*（在视图中）的指令进行跨指令通信。

我们将使用 StackBlitz（[`stackblitz.com/edit/angular-pzljm3`](https://stackblitz.com/edit/angular-pzljm3)）来演示这些概念。StackBlitz 是一个在线 IDE，用于运行 Angular 应用程序！

首先，查看文件`app.component.ts`。它有三个指令：`Relation`，`Acquaintance`和`Consumer`，并定义了这个视图层次结构：

```ts
<div relation="grand-parent" acquaintance="jack"> 
    <div relation="parent"> 
 <div relation="me" consumer> 
        <div relation="child-1"> 
          <div relation="grandchild-1"></div> 
        </div> 
        <div relation="child-2"></div> 
      </div> 
    </div> 
</div> 
```

在接下来的几节中，我们将描述不同方式将不同的`Relation`和`Acquaintance`指令注入到`consumer`指令中。在`ngAfterViewInit`生命周期钩子期间，查看浏览器控制台中我们记录的注入依赖项。

# 注入在同一元素上定义的指令

默认情况下，构造函数注入支持在同一元素上定义的指令。构造函数只需要声明我们要注入的指令类型变量即可：

```ts
variable:DirectiveType 
```

我们在`BusyIndicatorDirective`中进行的`NgModel`注入就属于这一类。如果在当前元素上找不到指令，那么 Angular DI 将抛出错误，除非我们将依赖标记为`@Optional`。

可选依赖

`@Optional` 装饰器不仅限于指令注入。它用于标记任何类型的可选依赖。

从 plunk 示例中，第一个注入（在`Consumer`指令实现中）将带有`me`属性（`relation="me"`）的`Relation`指令注入到消费者指令中：

```ts
constructor(private me:Relation ... 
```

# 从父级注入指令依赖

使用`@Host`装饰符对构造函数参数进行前缀，指示 Angular 在*当前元素*、*其父级*或其*父级*中搜索依赖项，直到它达到组件边界（在其视图层次结构中的某个地方有指令的组件）。查看第二个`consumer`注入：

```ts
constructor(..., @Host() private myAcquaintance:Acquaintance  
```

此语句将注入两层上层声明的`Acquaintance`指令实例。

像前面描述的`@Optional`装饰器一样，`@Host()`的使用也不仅限于指令。Angular 服务注入也遵循相同的模式。如果服务标记为`@Host`，那么搜索将停在宿主组件处。它不会继续向上查找组件树。

`@Skipself` 装饰器可用于跳过当前元素以进行指令搜索。

从 StackBlitz 示例中，这个注入将带有`relation="parent"`（`relation`属性值为`parent`）的`Relation`指令注入`consumer`中：

```ts
@SkipSelf() private myParent:Relation 
```

# 注入子指令（或多个指令）

如果需要将嵌套 HTML 中定义的指令注入到父指令/组件中，有四个装饰器可以帮助我们：

+   `@ViewChild`/`@ViewChildren`

+   `@ContentChild`/`@ContentChildren`

正如这些命名约定所暗示的，有用于注入单个子指令或多个子指令的装饰器：

要理解`@ViewChild/@ViewChildren`与`@ContentChild/@ContentChildren`的重要性，我们需要看一下什么是视图和内容子项，这是我们很快要讨论的一个主题。但现在，了解视图子项是组件自己视图的一部分，而内容子项是注入到组件视图中的外部 HTML 就足够了。

看看在 StackBlitz 的示例中，`ContentChildren`装饰器是如何用于将子`Relation`指令注入到`Consumer`中的：

```ts
@ContentChildren(Relation) private children:QueryList<Relation>; 
```

可笑的是，变量`children`的数据类型不是数组，而是一个自定义类-`QueryList`。`QueryList`类并不是典型的数组，而是一个由 Angular 在添加或移除依赖项时保持更新的集合。这可能发生在使用`NgIf`或`NgFor`等结构指令创建/销毁 DOM 树时。我们在接下来的章节中也会更多地讨论`QueryList`。

您可能已经注意到，前面的注入不是构造函数注入，就像前面的两个例子一样。这是有原因的。注入的指令将在底层的组件/元素内容初始化之前不可用。出于这个特定的原因，我们在`ngAfterViewInit`生命周期钩子内有`console.log`语句。我们应该只在此生命周期钩子执行后访问内容子项。

前面的示例代码将所有三个子`relation`对象注入到`consumer`指令中。

# 注入后代指令

标准的`@ContentChildren`装饰器（或事实上也是`@ViewChildren`）只会注入指令/组件的直接子项，而不是其后代。要包含所有后代，我们需要向`Query`提供参数：

```ts
@ContentChildren(Relation, {descendants: true}) private 
allDescendents:QueryList<Relation>; 
```

传递`descendants: true`参数将指示 Angular 搜索所有后代。

如果您查看控制台日志，前面的语句会注入所有四个后代。

尽管 Angular DI 看起来很容易使用，但它拥有很多功能。它管理我们的服务、组件和指令，并在正确的时间将正确的东西提供给我们的正确位置。在组件和其他指令中注入指令提供了一种指令相互通信的机制。这样的注入允许一个指令访问另一个指令的公共 API（公共函数/属性）。

现在是探索新事物的时候了。我们将构建一个 Ajax 按钮组件，允许我们将外部视图注入组件中，这个过程也被称为**内容转译**。

# 构建一个 Ajax 按钮组件

当我们保存/更新练习或锻炼时，总是存在重复提交的可能性（或重复的`POST`请求）。当前的实现不提供任何关于保存/更新操作何时开始以及何时完成的反馈。由于缺乏视觉线索，应用程序的用户可能会有意或无意地多次点击保存按钮。

让我们尝试通过创建一个专用按钮来解决这个问题——一个*Ajax 按钮*，当点击时提供一些视觉线索，并阻止重复的 Ajax 提交。

按钮组件将按照这些行工作。它接受一个函数作为输入。此输入函数（输入参数）应返回与远程请求相关的 promise。单击按钮时，按钮内部调用远程调用（使用输入函数），跟踪底层 promise，并在此过程中显示一些忙碌的线索。此外，为了避免重复提交，按钮在远程调用完成之前保持禁用状态。

以下部分的伴随代码基于 Git 分支`checkpoint6.2`。您可以与我们一起工作，或者查看分支中提供的实现。或者如果您不使用 Git，请从 GitHub 位置 [`bit.ly/ng6be-checkpoint-6-2`](http://bit.ly/ng6be-checkpoint-6-2) 下载`checkpoint6.2`的快照（ZIP 文件）。在第一次设置快照时，请参考`trainer`文件夹中的`README.md`文件。

让我们创建组件大纲以使事情更清晰。使用以下命令在应用程序的共享模块 (`src/app/shared`) 下创建一个`ajax-button`组件，**然后从`SharedModule`导出该组件**：

```ts
ng generate component ajax-button -is
```

也需要更新组件定义并从`@angular/core`导入它们：

```ts
export class AjaxButtonComponent implements OnInit { 
  busy: boolean = null; 
  @Input() execute: any; 
  @Input() parameter: any; 
} 
```

需要将以下 HTML 模板添加到`ajax-button.component.html`中：

```ts
<button [attr.disabled]="busy" class="btn btn-primary"> 
    <span [hidden]="!busy">
        <div class="ion-md-cloud-upload spin"></div>
    </span>
    <span>Save</span> 
</button> 
```

该组件（`AjaxButtonComponent`）具有两个属性绑定，`execute`和`parameter`。`execute`属性指向在单击 Ajax 按钮时调用的函数。`parameter`是可以传递给此函数的数据。

查看视图中`busy`标志的使用方式。当`busy`标志被设置时，我们禁用按钮并显示旋转图标。让我们添加使一切正常工作的实现。将此代码添加到`AjaxButtonComponent`类中：

```ts
@HostListener('click', ['$event'])
onClick(event: any) {
    const result: any = this.execute(this.parameter);
    if (result instanceof Promise) {
      this.busy = true;
      result.then(
        () => { this.busy = null; },
        (error: any) => { this.busy = null; });
    }
}
```

我们设置了一个*主机事件绑定*，将点击事件绑定到`AjaxButtonComponent`组件。每当单击`AjaxButtonComponent`组件时，都会调用`onClick`函数。

需要将`HostListener`导入添加到`'@angular/core'`模块中。

`onClick` 实现使用`parameter`作为唯一参数调用输入函数。调用的结果存储在`result`变量中。

`if` 条件检查 `result` 是否为 `Promise` 对象。如果是，`busy`指示器就会被设置为 `true`。然后按钮等待 promise 被解决，使用 `then` 函数。无论 promise 是否解决为*成功*还是*错误*，忙标志都被设置为`null`。

忙标志被设置为`null`而不是`false`的原因是由于这个属性绑定`[attr.disabled]="busy"`。除非`busy`是`null`，否则`disabled`属性不会被移除。请记住，在 HTML 中，`disabled="false"`不会使按钮处于可点击状态。在按钮再次可点击之前，需要删除属性。

如果我们对这一行感到困惑：

```ts
    const result: any = this.execute(this.parameter); 
```

然后你需要看一下组件的使用方式。打开`workout.component.html`，将`保存`按钮的 HTML 替换为以下内容：

```ts
<abe-ajax-button [execute]="save" [parameter]="f"></abe-ajax-button> 
```

`Workout.save` 函数绑定到 `execute`，而 `parameter` 获取 `FormControl` 对象 `f`。

我们需要更改 `Workout` 类中的 `save` 函数以返回 `AjaxButtonComponent` 的 promise 才能工作。将 `save` 函数的实现更改为以下内容：

```ts
save = (formWorkout: any): Promise<Object | WorkoutPlan> => {
    this.submitted = true;
    if (!formWorkout.valid) { return; }
    const savePromise = this.workoutBuilderService.save().toPromise();

    savePromise.then(
      result => this.router.navigate(['/builder/workouts']),
      err => console.error(err)
    );
    return savePromise;
  } 
```

`save` 函数现在返回一个*promise*，我们通过调用从`workoutBuilderService.save()`调用返回的*observable*上的 `toPromise` 函数来构建它。

注意我们如何将 `save` 函数定义为*实例函数*（使用箭头操作符）以使其在*this*上创建闭包。这是我们之前在构建*远程验证器指令*时做的事情。

是时候测试我们的实现了！刷新应用程序，打开创建/编辑锻炼视图。点击保存按钮，看到 Ajax 按钮的效果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/998a8485-f94b-4114-ba5b-9830963b9fb3.png)

前面的动画可能只是短暂的，因为我们在保存后返回到锻炼列表页面。我们可以临时禁用导航以查看新更改。

我们从这一部分开始，旨在突显外部元素/组件如何被传递到组件中。让我们来做吧！

# 将外部组件/元素传递到一个组件中

从一开始，我们就需要了解**传递**意味着什么。了解这个概念的最佳方式是看一个例子。

到目前为止，我们建立的任何组件都没有从外部借用内容。不确定这意味着什么？

考虑在`workout.component.html`中的前面的 `AjaxButtonComponent` 示例：

```ts
<ajax-button [execute]="save" [parameter]="f"></ajax-button> 
```

如果我们将`ajax-button`的使用更改为以下内容会怎样？

```ts
<ajax-button [execute]="save" [parameter]="f">Save Me!</ajax-button> 
```

“保存我！”的文本会显示在按钮上吗？不会，试一下！

`AjaxButtonComponent` 组件已经有一个模板，并拒绝了我们在前面的声明中提供的内容。如果我们能够以某种方式将内容（在前面的例子中的“保存我！”）注入`AjaxButtonComponent`内部呢？这种将外部视图片段注入组件视图的行为就是我们所说的**传递**，框架提供了必要的构造来启用传递。

现在是时候介绍两个新概念，*内容子级*和*视图子级*。

# 内容子级和视图子级

简洁地定义，组件内部定义的 HTML 结构（使用`template 或 templateUrl`）是组件的**视图子级**。然而，作为组件使用的一部分提供的 HTML 视图添加到宿主元素（例如`<ajax-button>**Save Me!**</ajax-button>`）中，定义了组件的**内容子级**。

默认情况下，Angular 不允许将*内容子级*嵌入，就像我们之前看到的那样。`Save Me!`文本从未被发送。我们需要明确告诉 Angular 在*组件视图模板*内的哪里发出*内容子级*。为了理解这个概念，让我们来修复`AjaxButtonComponent`的视图。打开`ajax-button.component.ts`并更新视图模板定义如下：

```ts
<button [attr.disabled]="busy" class="btn btn-primary"> 
    <span [hidden]="!busy"> 
        <ng-content select="[data-animator]"></ng-content> 
   </span> 
 <ng-content select="[data-content]"></ng-content> 
</button>
```

前述视图中的两个`ng-content`元素定义了*内容注入位置*，内容子级可以被注入/跨越。`selector`属性定义了注入到主机中时应使用的*CSS 选择器*。

一旦我们在`workout.component.html`中修复了`AjaxButtonComponent`的使用情况，它就会变得更有意义。将其更改为如下：

```ts
<ajax-button [execute]="save" [parameter]="f">
    <div class="ion-md-cloud-upload spin" data-animator></div>
 <span data-content>Save</span>
</ajax-button> 
```

带有`data-animator`的`span`被注入到具有`select=[data-animator]`属性的`ng-content`中，而另一个带有`data-content`属性的`span`被注入到第二个`ng-content`声明中。

再次刷新应用程序，尝试保存锻炼。虽然最终结果是相同的，但最终视图是多个视图片段的组合：一个用于组件定义的部分（*视图子级*），另一个用于组件使用的部分（*内容子级*）。

下图突出显示了渲染的`AjaxButtonComponent`的不同之处：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/f1721b2e-ffe9-4e35-a57c-fca2c3bf62cb.png)

`ng-content`可以在不带有`selector`属性的情况下声明。在这种情况下，将注入组件标记内定义的全部内容。

*内容注入*进入现有组件视图是一个非常强大的概念。它允许组件开发人员提供扩展点，组件消费者可以轻松消费并自定义组件的行为，而且是在受控的方式。

我们为`AjaxButtonComponent`定义的内容注入允许消费者更改忙碌指示动画和按钮内容，同时保持按钮的行为不变。

Angular 的优势并不止于此。它具有将*内容子级*和*视图子级*注入到*组件代码/实现*中的能力。这使得组件可以与其内容/视图子级交互并控制它们的行为。

# 使用@ViewChild 和@ViewChildren 注入视图子级

让我们看一下`WorkoutAudioComponent`实现的相关部分。视图定义如下：

```ts
<audio #ticks="MyAudio" loop src="img/tick10s.mp3"></audio>
<audio #nextUp="MyAudio" src="img/nextup.mp3"></audio>
<audio #nextUpExercise="MyAudio" [src]="'/assets/audio/' + nextupSound"></audio>
// Some other audio elements 
```

注入的样式如下：

```ts
@ViewChild('ticks') private _ticks: MyAudioDirective; 
@ViewChild('nextUp') private _nextUp: MyAudioDirective; 
@ViewChild('nextUpExercise') private _nextUpExercise: MyAudioDirective; 
```

与`audio`标签相关联的指令(`MyAudioDirective`)被注入到`WorkoutAudio`的实现中，使用`@ViewChild`装饰器。传递给`@ViewChild`的参数是用于在视图定义中定位元素的*模板变量*名称（例如`tick`）。然后`WorkoutAudio`组件使用这些音频指令来控制*7 分钟锻炼*的音频播放。

尽管前面的实现注入了`MyAudioDirective`，但甚至子组件也可以被注入。例如，我们构建了一个`MyAudioComponent`，与`MyAudioDirective`相似，如下所示:

```ts
@Component({ 
  selector: 'my-audio', 
  template: '<audio ...></audio>', 
}) 
export class MyAudioComponent { 
  ... 
} 
```

然后我们可以使用`audio`标签的方式代替它:

```ts
<my-audio #ticks loop  
  src="img/tick10s.mp3"></my-audio> 
```

注入仍然可以工作。

如果组件视图中定义了多个相同类型的指令/组件会发生什么？使用`@ViewChildren`装饰器。它允许您查询一个类型的注入。使用`@ViewChildren`的语法如下:

```ts
@ViewChildren(directiveType) children: QueryList<directiveType>; 
```

这会注入所有类型为`directiveType`的视图子元素。对于前面所述的`WorkoutAudio`组件示例，我们可以使用以下语句来获取所有的`MyAudioDirective`:

```ts
@ViewChildren(MyAudioDirectives) private all: QueryList<MyAudioDirectives>; 
```

`ViewChildren`装饰器也可以接受用逗号分隔的选择器列表（*模板变量名*）而不是类型。例如，要在`WorkoutAudio`组件中选择多个`MyAudioDirective`实例，我们可以使用以下内容：

```ts
 @ViewChildren('ticks, nextUp, nextUpExercise, halfway, aboutToComplete') private all: QueryList<MyAudioDirective>; 
```

`QueryList`类是 Angular 提供的特殊类。我们在本章前面的*注入后代指令*部分介绍了`QueryList`。让我们进一步探讨`QueryList`。

# 使用`QueryList`跟踪注入的依赖

对于需要注入多个组件/指令的组件（使用`@ViewChildren`或`@ContentChildren`），注入的依赖是一个`QueryList`对象。

`QueryList`类是一个*只读*的**集合*，包含注入的组件/指令。Angular 根据用户界面当前的状态来保持此集合同步。

举个例子，`WorkoutAudio`指令视图有五个`MyAudioDirective`实例。因此，对于以下集合，我们将有五个元素:

```ts
@ViewChildren(MyAudioDirective) private all: QueryList<MyAudioDirective>; 
```

虽然前面的例子没有突出显示同步部分，Angular 可以跟踪从视图中添加或删除的组件/指令。这是在使用`ngFor`等内容生成指令时发生的。

以这个假设的模板为例:

```ts
<div *ngFor="let audioData of allAudios"> 
  <audio [src]="audioData.url"></audio> 
</div> 
```

这里注入的`MyAudioDirective`指令的数量等于`allAudios`数组的大小。程序执行过程中，如果向`allAudios`数组添加或删除元素，则框架也会同步更新指令集合。

虽然`QueryList`类不是数组，但它可以通过 `for (var item in queryListObject)` 语法进行迭代（因为它实现了**ES6 iterable 接口**）。它还有一些其他有用的属性，如 `length`、`first` 和 `last`，可以派上用场。查看框架文档（[`bit.ly/ng2-querylist-class`](http://bit.ly/ng2-querylist-class)）以获取更多详细信息。

从上面的讨论中，我们可以得出结论，`QueryList` 可以为组件开发人员节省大量样板代码，在需要手动追踪时会很麻烦。

视图子代访问时机

当组件/指令初始化时，视图子代注入是不可用的。Angular 确保视图子代注入在`ngAfterViewInit`生命周期事件之前可用于组件。确保只在（或之后）`ngAfterViewInit`事件触发后访问被注入的组件/指令。

现在让我们看看内容子代注入，这几乎相同，只不过有一些细微差别。

# 使用 @ContentChild 和 @ContentChildren 注入内容子代

Angular 也允许我们*注入内容子代*，使用一组并行属性：`@ContentChild`用于注入特定内容子代，`@ContentChildren`用于注入特定类型的内容子代。

如果我们回顾一下 `AjaxButtonComponent` 的用法，其内容子代 span 可以通过以下方式注入到 `AjaxButtonComponent` 实现中：

```ts
@ContentChild('spinner') spinner:ElementRef; 
@ContentChild('text') text:ElementRef; 
```

并在`workout.component.html`中对应的 span 上添加模板变量：

```ts
<div class="ion-md-cloud-upload spin" data-animator #spinner></div>
<span data-content #text>Save</span>
```

在前面的注入中，它是`ElementRef`，但也可以是一个组件。如果我们为旋转器定义了一个组件，比如：

```ts
<ajax-button> 
    <busy-spinner></busy-spinner> 
    ... 
</ajax-button> 
```

我们也可以使用以下方式进行注入：

```ts
@ContentChild(BusySpinner) spinner: BusySpinner; 
```

对于指令也是一样的。在`AjaxButtonComponent`上声明的任何指令都可以注入到`AjaxButtonComponent`实现中。对于上述情况，由于被传递的元素是标准 HTML 元素，我们注入了`ElementRef`，这是 Angular 为任何 HTML 元素创建的包装器。

与*视图子代*类似，Angular 确保在`ngAfterContentInit`生命周期事件之前，内容子代引用绑定到被注入的变量。

当我们谈论注入依赖项时，让我们谈谈一些关于*将服务注入到组件中**的变体。

# 使用`viewProvider`进行依赖注入

我们已经熟悉 Angular 中的 DI 注册机制，在那里我们通过将其添加到任何模块声明中将依赖项注册到全局级别。

或者我们可以在组件级别使用`@Component`装饰器上的`providers`属性进行：

```ts
providers:[WorkoutHistoryTracker, LocalStorage] 
```

为了避免混淆，我们现在讨论的是注入除指令/组件对象之外的依赖项。在能够使用装饰器提示（如 `@Query`、`@ViewChild`、`@ViewChildren` 等）注入之前，指令/组件需要在模块的`declarations`数组中进行注册。

在组件级别注册的依赖项可供其*视图子组件*和*内容子组件*及其后代使用。

在我们继续之前，我们希望*视图*和*内容子组件*之间的区别对每个人都非常清晰。如有疑问，请再次参考*内容子组件和视图子组件*部分。

让我们以第二章中的一个例子，*个人教练*为例。`WorkoutBuilderService` 服务在锻炼构建模块（`WorkoutBuilderModule`）中以应用程序级别注册：

```ts
providers: [ExerciseBuilderService, ...  
 WorkoutBuilderService]);
```

这样可以让我们在整个应用程序中注入 `WorkoutBuilderService` 以构建锻炼，同时运行锻炼。相反，我们也可以在 `WorkoutBuilderComponent` 级别注册服务，因为它是所有锻炼/练习创建组件的父组件，类似以下示例：

```ts
@Component({ 
    template: `...` 
 providers:[ WorkoutBuilderService ] 
}) 
export class WorkoutBuilderComponent { 
```

这个改变将禁止在 `WorkoutRunner` 或与锻炼相关的任何组件中注入 `WorkoutBuilderService`。

如果 `WorkoutBuilderService` 服务在应用程序级别和组件级别（如上例所示）都注册了，会发生什么？注入会如何进行？根据我们的经验，我们知道 Angular 会将 `WorkoutBuilderService` 服务的不同实例注入到 `WorkoutBuilderComponent`（及其后代）中，而应用程序的其他部分（*Workout runner*）会获得全局依赖。记住**层次注入器**！

Angular 还不止于此。它使用 `viewProviders` 属性提供了一些进一步的依赖项作用域限定。`@Component` 装饰器上的 `viewProviders` 属性允许注册只能在视图子组件中注入的依赖项。

让我们再次考虑 `AjaxButtonComponent` 的例子，并且考虑一个简单的指令实现，名为 `MyDirective`，以阐明我们的讨论：

```ts
@Directive({ 
  selector: '[myDirective]', 
}) 
export class MyDirective { 
  constructor(service:MyService) { } 
  ... 
} 
```

`MyDirective` 类依赖于一个名为 `MyService` 的服务。

要将此指令应用于 `AjaxButtonComponent` 模板中的*按钮元素*，我们也需要注册 `MyService` 的依赖（假设 `MyService` 尚未全局注册）：

```ts
@Component({ 
  selector: 'ajax-button', 
  template:` <button [attr.disabled]="busy" ... 
 myDirective> 
                ... 
             <button>` 
 providers:[MyService], 
... 
```

由于 `MyService` 已与 `AjaxButtonComponent` 注册，因此 `MyDirective` 也可以添加到其内容子组件中。因此，在 *spinner HTML* 上应用 `myDirective` 也将起作用（`workout.component.html` 中的代码）：

```ts
<div class="ion-md-cloud-upload spin" data-animator myDirective></div>
```

但将 `providers` 属性更改为 `viewProviders`：

```ts
viewProviders:[MyService]
```

会导致 `AjaxButtonComponent` 的内容子组件（上述代码中的 `div`）中的 `MyService` 注入失败，控制台会显示 DI 错误。

使用 `viewProviders` 注册的依赖对其内容子组件不可见。

视图和内容子级别的依赖作用域乍看起来可能并不有用，但它确实有其好处。 想象一下，我们正在构建一个可重用的组件，我们希望将其打包并交付给开发人员使用。 如果组件有一个预打包的服务依赖项，我们需要特别小心。 如果这样的组件允许*内容注入*（内容子级别），则在组件上使用基于*提供者*的注册时，依赖服务将被广泛暴露。 任何内容子级别都可以获取服务依赖并使用它，这会导致不良后果。 通过使用`viewProvider`注册依赖项，只有组件实现和其子视图才能访问到依赖项，提供了必要的封装层。

我们再次对 DI 框架提供的灵活性和定制级别感到惊讶。 尽管对于初学者来说可能有些令人生畏，但一旦我们开始使用 Angular 构建越来越多的组件/指令，我们总会发现这些概念使我们的实现变得更简单的地方。

让我们把焦点转向指令的第三个分类：*结构指令*。

# 理解结构指令

虽然我们经常使用结构指令，比如`NgIf`和`NgFor`，但很少需要创建一个结构指令。仔细考虑。如果我们需要一个新的视图，我们会创建一个*组件*。如果我们需要扩展现有的元素/组件，我们使用*指令*。 而结构指令最常见的用途是克隆视图的一部分（也称为*模板视图*），然后根据一些条件：

+   要么注入/销毁这些模板（`NgIf`和`NgSwitch`）

+   或者复制这些模板（`NgFor`）

使用结构指令实现的任何行为都会无意中落入这两个类别之一。

有了这个事实，与其构建我们自己的结构指令，不如看看`NgIf`实现的源代码。

以下是引起我们兴趣的`NgIf`指令的摘录。 我们特意忽略了摘录中的`ngIfElse`部分：

```ts
@Directive({selector: '[ngIf]'})
export class NgIf {
 constructor(private _viewContainer: ViewContainerRef, templateRef: TemplateRef<NgIfContext>) {
    this._thenTemplateRef = templateRef;
 }

 @Input()
  set ngIf(condition: any) {
    this._context.$implicit = this._context.ngIf = condition;
    this._updateView();
 }
 private _updateView() {
    if (this._context.$implicit) {
      if (!this._thenViewRef) {
        this._viewContainer.clear();
        this._elseViewRef = null;
        if (this._thenTemplateRef) {
          this._thenViewRef =
              this._viewContainer.createEmbeddedView(this._thenTemplateRef, this._context);
        }
      }
    }
    ...
}
```

这里没有什么神奇的，只是一个简单的结构指令，检查一个布尔条件（`this._context.$implicit`）来创建/销毁视图！

上面的第一个 if 条件检查条件`this._context.$implicit`是否为`true`。 接下来的条件确保视图已经不是通过检查变量`_thenViewRef`渲染的。 如果`this._context.$implicit`从`false`转换为`true`，我们只希望翻转视图。 如果两个 if 条件都为 true，则清除现有视图（`this._viewContainer.clear()`）并清除 else 视图的引用。 最内层的 if 条件确保 if 的模板引用可用。 最后，代码调用`_viewContainer.createEmbeddedView`来渲染（或重新渲染）视图。

理解指令的工作原理并不困难。需要详细说明的是两个新的注入，`ViewContainerRef(_viewContainer)` 和 `TemplateRef(_templateRef)`。

# TemplateRef

`TemplateRef` 类（`_templateRef`）存储了结构指令所引用的模板的引用。还记得来自第一章，*构建我们的第一个应用程序 - 7 分钟锻炼*的结构指令的讨论吗？所有结构指令都会使用模板 HTML。当我们使用`NgIf`这样的指令时：

```ts
<h3 *ngIf="currentExercise.exercise.name=='rest'"> 
  ... 
</h3> 
```

Angular 在内部将该声明转换为以下内容：

```ts
<ng-template [ngIf]="currentExercise.exercise.name=='rest'"> 
  <h3> ... </h3> 
</ng-template> 
```

这是结构指令使用的模板，`_templateRef`指向这个模板。

另一个注入是`ViewContainerRef`。

# ViewContainerRef

`ViewContainerRef` 类指向模板渲染的容器。这个类有许多便利的方法来管理视图。`NgIf` 实现使用的两个函数`createEmbeddedView`和`clear`，用于添加和移除模板 HTML。

`createEmbeddedView` 函数接受模板引用（再次注入到指令中）并渲染视图。

`clear`函数销毁已经注入的元素/组件并清除视图容器。因为模板（`TemplateRef`）中引用的每个组件及其子元素都被销毁，所有相关的绑定也随之消失。

结构指令有一个非常具体的应用领域。不过，我们可以使用`TemplateRef`和`ViewContainerRef`类做很多巧妙的技巧。

我们可以实现一个结构指令，根据用户角色显示/隐藏视图模板。

考虑一个假设的结构指令`forRoles`的例子：

```ts
<button *forRoles="admin">Admin Save</button> 
```

如果用户不属于*admin*角色，`forRoles`指令将不会渲染按钮。核心逻辑可能看起来像下面这样：

```ts
if(this.loggedInUser.roles.indexOf(this.forRole) >=0){ 
      this.viewContainer.createEmbeddedView(this.templateRef); 
} 
else { 
      this.viewContainer.clear(); 
}  
```

指令的实现将需要某种返回已登录用户详情的服务。我们将把这样的指令的实现留给读者。

`forRoles`指令所做的事情也可以使用`NgIf`来实现：

```ts
<button *ngIf="loggedInUser.roles.indexOf('admin')>=0">Admin Save</button> 
```

但是`forRoles`指令只是为模板的可读性增加了明确的意图。

结构指令的一个有趣的应用可能涉及创建一个只是复制传递给它的模板的指令。构建一个将会非常简单；我们只需调用`createEmbeddedView`两次：

```ts
ngOnInit() {       
 this.viewContainer.createEmbeddedView(this._templateRef);        
 this.viewContainer.createEmbeddedView(this._templateRef); 
}  
```

另一个有趣的练习！

`ViewContainerRef` 类还有一些其他函数，允许我们注入*组件*，获取嵌入视图的数量，重新排序视图等等。查看`ViewContainerRef`的框架文档（[`bit.ly/view-container-ref`](http://bit.ly/view-container-ref)）获取更多详细信息。

我们对结构指令的讨论就到这里，是时候开始一些新的东西了！

我们迄今为止构建的组件从通用*bootstrap 样式表*和`app.css`中定义的一些自定义样式中获取它们的样式（CSS）。Angular 在这方面提供了更多。一个真正可重复使用的组件应该是完全自包含的，无论是行为还是用户界面。

# 组件样式和视图封装

在 Web 应用程序开发中长期存在的一个问题是，当涉及 DOM 元素的行为和样式时缺乏封装性。我们无法通过任何机制将应用程序的一个部分与另一个部分隔离开来。

事实上，我们拥有太多的强大功能。通过诸如 jQuery 和强大的*CSS 选择器*等库，我们可以获得任何 DOM 元素并更改其行为。在访问方面，我们的代码与任何外部库的代码之间没有区别。每一段代码都可以操作任何渲染的 DOM 部分。因此，封装层被破坏了。一个编写不良的库可能会引发一些难以调试的严重问题。

CSS 样式也同样适用。如果库实现希望这样做，任何 UI 库实现都可以覆盖全局样式。

这些都是任何库开发者在构建可重复使用库时所面临的真正挑战。一些新兴的 Web 标准试图通过提出**web 组件**等概念来解决这个问题。

**Web 组件**简单来说，是可重复使用的用户界面部件，它们封装了*状态*，*样式*，*用户界面*和*行为*。功能通过明确定义的 API 暴露，用户界面部分也被封装。

*web 组件*的概念的实现依赖于四个标准：

+   HTML 模板

+   Shadow DOM

+   自定义元素

+   HTML 导入

在这个讨论中，我们感兴趣的技术标准是**Shadow DOM**。

# Shadow DOM 概述

**Shadow DOM**就像一个并行的 DOM 树，嵌套在一个组件内部（*一个 HTML 元素，*与 Angular 组件不要混淆*）中，隐藏在主 DOM 树之外。除了组件本身，应用程序的任何部分都无法访问这个 Shadow DOM。

实现 Shadow DOM 标准允许视图，样式和行为封装。了解 Shadow DOM 的最佳方式是查看 HTML5 的`video`和`audio`标签。

你曾经想过这个`audio`声明是如何实现的吗：

```ts
<audio src="img/nextup.mp3" controls></audio> 
```

产生以下结果？

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/1db22226-a91d-457a-82bc-44c19d34ac5f.png)

是浏览器生成潜在的 Shadow DOM 来渲染音频播放器。令人惊讶的是，我们甚至可以查看生成的 DOM！以下是我们如何实现它的步骤：

+   拿前面的 HTML，创建一个虚拟的 HTML 页面，并在 Chrome 中打开它。

+   然后打开开发者工具窗口（*F12*）。单击左上角的设置图标。

+   在常规设置中，单击如下屏幕截图中突出显示的复选框，以启用查看 Shadow DOM 的检查功能：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/a95f3b1d-c9b0-476f-8a25-65a2d9e37851.png)

刷新页面，现在如果检查生成的`audio` HTML，影子 DOM 就会显示出来：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d2af88cb-b2c8-4b3a-9987-cedfb585e570.png)

在`shadow-root`下，有一个其他部分的页面和脚本无法访问的全新世界。

在影子 DOM 领域中，**shadow-root**（在上述代码中的`#shadow-root`）是生成的 DOM 的根节点，托管在**shadow host**（在这种情况下是`audio`标签）内。当浏览器渲染这个元素/组件时，渲染的是*shadow root*的内容，而不是*shadow host*的内容。

从这次讨论中，我们可以得出结论，影子 DOM 是浏览器创建的一个并行 DOM，它封装了 HTML 元素的*标记*、*样式*和*行为*（DOM 操纵）。

这是对影子 DOM 的一个初步介绍。要了解更多关于影子 DOM 如何工作的信息，我们建议参阅 Rob Dodson 的系列文章：[`bit.ly/shadow-dom-intro`](http://bit.ly/shadow-dom-intro)

但这一切与 Angular 有什么关系呢？事实证明，Angular 组件也支持某种视图封装！这也允许我们为 Angular 组件隔离样式。

# 影子 DOM 和 Angular 组件

要理解 Angular 如何应用影子 DOM 的概念，我们首先必须学习如何为 Angular 组件设置样式。

当涉及到对本书构建的应用进行样式设置时，我们采取了一种保守的方法。无论是*工作构建器*还是*工作程序*（*7 分钟锻炼*）应用，我们构建的所有组件都派生其样式于*bootstrap CSS*和在`app.css`中定义的自定义样式。没有一个组件定义了自己的样式。

虽然这符合 Web 应用开发的标准实践，但有时我们确实需要偏离。特别是当我们构建自包含、打包和可重用的组件时。

Angular 通过在`@Component`装饰器上使用`style`（用于内联样式）和`styleUrl`（外部样式表）属性，允许我们为组件定义特定样式。让我们尝试一下`style`属性，看看 Angular 会做什么。

在下一个练习中，我们将使用`AjaxButtonComponent`实现来作为我们的实验场所。但在这之前，让我们先看看`AjaxButtonComponent`的 HTML。`AjaxButtonComponent`的 HTML 树如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/4bf43910-2297-4538-836e-3652883be3d0.png)

让我们使用`styles`属性覆盖一些样式：

```ts
@Component({ 
  ... 
  styles:[` 
    button { 
      background: green; 
    }`] 
}) 
```

前面的*CSS 选择器*将`background`属性设置为`green`，应用于所有 HTML 按钮。保存前面的样式并刷新工作构建器页面。按钮样式已更新。没有惊喜吗？不对，实际上有！看一下生成的 HTML：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/c7ed693e-b585-41c5-ac7a-06653cb7e447.png)

一些新属性被添加到许多 HTML 元素上。而最近定义的样式又落在了哪里呢？正如图片显示的，位于`head`标签的顶部：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/536978ea-de4e-4426-9ae0-8cc238f36954.png)

在`head`部分定义的样式具有额外的作用域，带有`_ngcontent-c1`属性（在您的情况下可能属性名不同）。这种作用域允许我们独立地为`AjaxButtonComponent`设置样式，它不能覆盖任何全局样式。

即使我们使用了`styleUrls`属性，Angular 也会这样做。假设我们已经将相同的 CSS 嵌入到外部 CSS 文件中并使用了这个：`styleUrls:['static/css/ajax-button.css']`，Angular 仍然会将样式嵌入到`head`部分，通过获取 CSS，解析它，然后注入它。

根据定义，本应影响应用程序中所有按钮外观的样式没有产生任何效果。Angular 对这些样式进行了作用域限定。

这种作用域确保组件样式不会干扰已定义的样式，但反之则不成立。全局样式仍会影响组件，除非在组件本身中进行覆盖。

这种作用域样式是 Angular 试图模拟影子 DOM 范式的结果。组件上定义的样式永远不会泄漏到全局样式中。所有这些都是无需任何努力的美妙之处！

如果您正在构建定义自己样式并希望具有一定隔离性的组件，请使用组件的`style`/`styleUrl`属性，而不是使用有一个公共 CSS 文件的老式方法。

我们可以通过使用名为**encapsulation**的`@Component`装饰器属性进一步控制这种行为。该属性的 API 文档提到：

**encapsulation:** `ViewEncapsulation`指定模板和样式应如何封装。如果视图具有样式，则默认为`ViewEncapsulation.Emulated`，否则为`ViewEncapsulation.None`。

正如我们所看到的，一旦我们在组件上设置了样式，封装效果就是`Emulated`。否则，它是`None`。

如果我们将`encapsulation`明确设置为`ViewEncapsulation.None`，则作用域属性将被移除，样式将嵌入到头部部分，就像普通样式一样。

还有第三种选项，`ViewEncapsulation.Native`，在其中 Angular 实际上为组件视图创建了影子 DOM。将`AjaxButtonComponent`实现中的`encapsulation`属性设置为`ViewEncapsulation.Native`，现在查看渲染的 DOM：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2a817126-9d31-49b5-982f-d80bac011607.png)

`AjaxButtonComponent`现在有了影子 DOM！这也意味着按钮的完整样式丢失（来自 bootstrap CSS 的样式），现在按钮需要定义自己的样式。

Angular 竭尽全力确保我们开发的组件可以独立工作并且是可重用的。每个组件已经有了自己的模板和行为。除此之外，我们还可以封装组件样式，使我们能够创建健壮的独立组件。

这让我们来到了本章的结尾，是时候总结一下我们所学到的内容了。

# 总结

随着我们结束本章，我们现在对指令的工作原理和如何有效使用它们有了更好的理解。

我们从构建`RemoteValidatorDirective`开始本章，了解了很多关于 Angular 对*异步验证*的支持。

接下来是`BusyIndicatorDirective`，再次是一个很好的学习机会。我们探索了**renderer**服务，它允许以跨平台的方式操纵组件视图。我们还了解了**host bindings**，它让我们绑定到主机元素的*事件*，*属性*和*属性*。

Angular 允许将指令声明在视图血统中，以便将其注入到血统中。我们专门花了一些时间来理解这种行为。

我们创建的第三个指令（组件）是`AjaxButtonComponent`。它帮助我们理解了*内容子级*和*视图子级*对于组件的关键区别。

我们还涉及了结构指令，其中我们探索了`NgIf`平台指令。

最后，我们从 Angular 在视图封装方面的能力来看。我们探索了 Shadow DOM 的基础知识，并了解了框架如何采用 Shadow DOM 范式来提供视图加样式封装。

从教育的角度来看，所有这些都很有趣。它没有描述房间里的大象，当事情变得复杂时，我们如何管理我们的数据？我们需要处理的问题有:

+   双向数据流

+   预测性不足（一个变化可能导致级联变化）

+   分散状态（没有真正的事实来源，我们的组件可以处于部分更新的状态）

让我们牢记这些问题，当我们开始进入第五章，“1.21 Gigawatt - Flux Pattern Explained”时。


# 第五章：1.21 吉瓦特 - Flux 模式解释

你的应用程序已经发展壮大，在这个过程中，你慢慢地感到你正在失去应用程序在某个时间点的知识，我们称之为应用程序的状态。可能还会出现其他问题，比如你的应用程序的某些部分与它们所知道的不一致。在一个部分发生的更新可能没有应用到其他部分，你想着这真的应该这么难吗，有没有更好的答案？

你可能只是因为听说 NgRx 是构建应用程序结构的方式而拿起这本书，你很好奇想要了解更多。

让我们先解释一下我们的标题。我们说的 1.21 吉瓦特是什么意思？我要引用电影《回到未来》中的 Doc Brown 角色（[`www.imdb.com/name/nm0000502/?ref_=tt_trv_qu`](http://www.imdb.com/name/nm0000502/?ref_=tt_trv_qu)）：

"Marty, 对不起，但是产生 1.21 吉瓦特电力的唯一能源就是一道闪电。"

为什么我们要谈论电影《回到未来》？这就是 Flux 这个名字的来源。现在是时候再引用同一部电影的台词了：

"是的！当然！1955 年 11 月 5 日！那天我发明了时间旅行。我还记得清楚。我站在马桶的边缘挂钟，瓷器是湿的，我滑倒了，撞到了水池，当我醒来时，我有了一个启示！一个幻觉！我脑海中有了一个画面！这个画面使时间旅行成为可能：**flux**电容器！"

所以你可以看到，对于名为 Flux 的名字有一个解释。很明显，它允许我们时间旅行。至少对于 Redux 来说，我们稍后会在这本书中写到，通过一种称为时间旅行调试的东西，时间旅行是可能的。是否需要一道闪电，那就由你这位亲爱的读者来掐腕验证。

Flux 是 Facebook 创建的一种架构模式。它的产生是因为人们认为 MVC 模式根本无法扩展。随着越来越多的功能被添加，大型的代码库变得脆弱、复杂，最重要的是，不可预测。现在让我们停顿一下，想一想这个词，不可预测。

当模型和视图的数量真正增长时，大型系统被认为会变得不可预测，因为它们之间存在双向数据流，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/cd476946-b1c8-428f-a290-4d626e5b0794.png)

在这里，我们可以看到模型和视图的数量开始增长。只要一个模型与一个视图进行交流并且反之亦然，一切都还算控制在一定范围内。然而，这种情况很少发生。在上述图表中，我们看到突然之间一个视图可以与多个模型交流，反之亦然，这意味着系统产生了级联效应，我们突然失去了控制。当然，只有一个偏离的箭头看起来并不那么糟糕，但想象一下，如果这个箭头突然变成了十个箭头，我们就真的遇到了严重的问题。

正是因为我们允许双向数据流发生，事情才变得复杂，我们失去了可预测性。对此的解药或治疗被认为是一种更简单类型的数据流，即单向流。现在，有一些关键角色参与了启用单向数据流，这就是这一章节要教我们的内容。

在本章中，我们将学到：

+   动作和动作创建者是什么

+   分发者在你的应用程序中扮演了一个中心角色，作为消息的中心

+   使用存储库进行状态管理

+   如何通过编码一个 Flux 应用程序流将我们对 Flux 的知识付诸实践

# 核心概念概述

Flux 模式的核心是单向数据流。它使用一些核心概念来实现这种流。主要思想是当 UI 上创建了一个事件，通过用户的交互，会产生一个动作。这个动作包括一个意图和一个载荷。意图是你想要实现的目标。把意图想象成一个动词。添加一个项目，删除一个项目，等等。载荷是需要发生的数据变化，以实现我们的意图。如果我们试图添加一个项目，那么载荷就是新添加的项目。然后，动作通过分发者在流中传播。动作及其数据最终会进入存储库。

组成 Flux 模式的概念包括：

+   动作和动作创建者，其中我们设定了一个意图和数据的载荷

+   分发者，我们的网页蜘蛛，能够左右发送消息

+   存储库，我们的状态和状态管理的中心位置

所有这些构成了 Flux 模式，并促进了单向数据流。考虑下面的图表：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/89837a9b-d48e-4a33-890c-c61bd5a326d6.png)

这里描绘的是一个单向数据流。数据从**视图**到**动作**，从**动作**到**分发者**，从**分发者**到**存储库**。触发流的有两种可能的方式：

+   应用程序第一次加载时，会从**存储库**中提取数据，以填充视图。

+   用户在视图中发生交互，导致了改变的意图。意图被封装在一个**动作**中，并随后通过**分发者**发送到**存储库**。在**存储库**中，它可以被持久化到数据库中，通过**API**或保存为应用程序状态，或两者兼而有之。

让我们在接下来的章节中深入探讨每个概念，并强调一些代码示例。

# 一个统一的数据流

让我们从最顶部开始介绍参与我们统一数据流中的所有方，概念概念地一步一步向下展开。我们将构建一个应用程序，由两个视图组成。在第一个视图中，用户将从列表中选择一个项目。这应该导致创建一个动作。然后，该动作将由调度器分派。该动作及其载荷最终将进入存储。与此同时，另一个视图将从存储中监听变化。当选定项目时，第二个视图将知道并因此可以在其 UI 中指示特定项目已被选定。在高层次上，我们的应用程序及其流程将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/13f7b397-8882-49b9-a11a-63fa225bc683.png)

# 动作 - 捕捉意图

一个动作就是一个简单的意图，伴随着数据，也就是一条消息。但是一个动作是如何产生的呢？一个动作是由用户与 UI 交互时产生的。用户可能会在列表中选择特定的项目，或者按下按钮意图提交表单。提交表单应该导致产品被创建。

让我们看看两种不同的动作：

+   在列表中选择项目，这里我们感兴趣的是保存所选项目的索引

+   将待办事项保存到待办事项列表中

一个动作由一个对象表示。该对象具有两个感兴趣的属性：

+   类型：这是一个唯一的字符串，告诉我们动作的意图，例如，`选择项目`

+   数据：这是我们打算持久保存的数据，例如所选项目的数值索引

考虑到我们的第一个示例动作，该动作的代码表示看起来像下面这样：

```ts
{
  type: 'SELECT_ITEM',
  data: 3 // selected index
}
```

好的，我们已经准备好我们的动作，我们也可以将其视为一条消息。我们希望发送消息以便在 UI 中突出显示所选项。由于这是一个单向流动，我们需要遵循一条既定的航线，并将消息传递给下一个方，也就是调度器。

# 调度器 - 网络中的蛛网

将调度器视为处理传递给它的消息的网络中的蜘蛛。你也可以将调度器视为一名邮差，承诺您的消息将到达目的地。调度器存在的一个作用就是将消息分派给任何愿意倾听的人。在 Flux 架构中通常只有一个`调度器`，典型的用法看起来像这样：

```ts
dispatcher.dispatch(message);
```

# 听取调度器的消息

我们已经确定调度器会将消息分派给任何愿意倾听的人。现在是时候成为那个倾听者了。调度器需要一个`注册`或`订阅`方法，以便你这个倾听者有能力倾听传入的消息。通常的设置看起来像这样：

```ts
dispatcher.register(function(message){});
```

现在，当你这样设置监听器时，它将有能力监听到发送的任何消息类型。你需要缩小范围；通常，监听器被指定为只处理围绕某一主题的几种消息类型。您的监听器大多看起来像这样：

```ts
dispatcher.register((message) => {
  switch(message.type) {
    case 'SELECT_ITEM':
      // do something
  }
});
```

好的，我们可以筛选出我们关心的消息类型，但在填写实际代码之前，我们需要考虑一下这个监听器是谁。答案很简单：就是 store。

# store - 管理状态，数据检索和回调方法

容易认为 store 是数据存储的地方。然而，这并不是它的全部功能。下面的列表可以表达 store 的责任是什么：

+   状态的持有者

+   管理状态，可以根据需要进行更新

+   能够处理通过 HTTP 获取/持久化数据等副作用

+   处理回调方法

如你所见，这不只是存储状态。现在让我们重新连接到设置与`dispatcher`监听器相关的工作。让我们将该代码移动到我们的 store 文件`store.js`中，并将我们的消息内容保存在 store 中：

```ts
// store.js

let store = {};

function selectIndex(index) {
  store["selectedIndex"] = index;
}

dispatcher.register(message => {
  switch (message.type) {
    case "SELECT_INDEX":
      selectIndex(message.data);
      break;
  }
});
```

好的，现在 store 已经知道了新索引的情况，但重要的一点被遗漏了，我们该如何告诉 UI？我们需要一种方法告诉 UI 发生了变化。变化意味着 UI 应该重新读取它的数据。

# 视图

要告诉视图发生了什么并对其进行操作，需要发生三件事：

+   视图需要注册为 store 的监听器

+   store 需要发送一个传达变化已发生的事件

+   视图需要重新加载其数据

从 store 开始，我们需要构建它，以便您可以注册为其事件的监听器。因此，我们添加`addListener()`方法：

```ts
// store-with-pubsub.js

function selectIndex(index) {
  store["selectedIndex"] = index;
}

// registering with the dispatcher
dispatcher.register(message => {
  switch (message.type) {
    case "SELECT_INDEX":
      selectIndex(message.data);

      // signals to the listener that a change has happened
      store.emitChange();
 break;
 }
});

class Store {
  constructor() {
    this.listeners = [];
  }

  addListener(listener) {
 if (!this.listeners["change"]) {
      this.listeners["change"] = [];
    }
 this.listeners["change"].push(listener);
  }

  emitChange() {
    if (this.listeners["change"]) {
      this.listeners["change"].forEach(cb => cb());
    }
  }

  getSelectedItem() {
    return store["selectedIndex"];
  }
}

const store = new Store();
export default store;
```

在前述代码中，我们还添加了使用`emitChange()`方法发出事件的能力。您可以很容易地切换该实现以使用`EventEmitter`或类似的东西。现在是将我们的视图与 store 连接的时候了。我们通过以下方式调用`addListener()`方法来实现：

```ts
// view.js

import store from "./store-with-pubsub";

class View {
  constructor(store) {
    this.index = 0;
    store.addListener(this.notifyChanged);
  }

  // invoked from the store
  notifyChanged() {
    // rereads data from the store
 this.index = store.getSelectedItem();

    // reloading the data
    render();
  }
  render() {
    const elem = document.getElementById('view');
    elem.innerHTML = `Your selected index is: ${this.index}`;
  }
}

let view = new View();

// view.html
<html>
  <body>
    <div id="view"></div>
  </body>
</html>
```

在前述代码中，我们实现了`notifyChanged()`方法，当调用时会从 store 中调用`getSelectedItem()`方法，从而接收到新的值。

在这一点上，我们已经描述了整个链条：一个视图如何接收用户交互，将其转换为操作，然后发送到 store，然后更新 store 的状态。然后 store 发出一个其他视图正在监听的事件。当事件被接收时，在视图中从 store 中重新读取状态，然后视图可以自由地渲染这个刚刚读取的状态，以它认为合适的方式。

我们在这里描述了两件事情：

+   如何设置流程

+   Flux 中的信息流

设置流程可以通过以下图示来描述：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3d1c5a2f-b842-474e-af21-201423bf19e4.png)

至于第二种情况，信息流如何通过系统流动，可以用下面的方式来描述：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2f60552e-7c94-4269-b885-5005f7bab5fa.png)

# 演示统一数据流

好的，我们已经描述了我们的应用程序包括的部分：

+   用户可以选择索引的视图

+   一个允许我们发送消息的分发器

+   包含我们选择的索引的存储器

+   从存储器中读取所选索引的第二个视图

让我们从所有这些中构建一个真正的应用程序。以下代码可以在`Chapter2/demo`目录下的代码库中找到。

# 创建选择视图

首先我们需要我们的视图，在其中我们将执行选择:

```ts
// demo/selectionView.js

import dispatcher from "./dispatcher";

console.log('selection view loaded');

class SelectionView {
  selectIndex(index) {
 console.log('selected index ', index);
    dispatcher.dispatch({
 type: "SELECT_INDEX",
      data: index
 });
 }
}

const view = new SelectionView();
export default view;
```

我们已经用粗体标出了上面我们打算使用的`selectIndex()`方法。

# 添加分发器

接下来，我们需要一个分发器，能够接受我们的消息，如下所示:

```ts
// demo/dispatcher.js

class Dispatcher {
  constructor() {
    this.listeners = [];
  }

  dispatch(message) {
    this.listeners.forEach(listener => listener(message));
  }

  register(listener) {
    this.listeners.push(listener);
  }
}

const dispatcher = new Dispatcher();
export default dispatcher;
```

# 添加存储器

存储器将作为我们状态的数据源，但也能够在存储器发生更改时告诉任何监听器:

```ts
// demo/store.js

import dispatcher from './dispatcher';

function selectIndex(index) {
  store["selectedIndex"] = index;
}

// 1) store registers with dispatcher
dispatcher.register(message => {
  switch (message.type) {
    // 3) message is sent by dispatcher ( that originated from the first view)
    case "SELECT_INDEX":
      selectIndex(message.data);
      // 4) listener, a view, is being notified of the change
      store.emitChange();
      break;
    }
});

class Store {
  constructor() {
    this.listeners = [];
  }

  // 2) listener is added by a view
  addListener(listener) {
    if (!this.listeners["change"]) {
      this.listeners["change"] = [];
    }

    this.listeners["change"].push(listener);
  }

  emitChange() {
    if (this.listeners["change"]) {
      this.listeners["change"].forEach(cb => cb());
    }
  }

  getSelectedItem() {
    return store["selectedIndex"];
  }
}

const store = new Store();
export default store;
```

# 添加一个选择视图

此视图将向存储器注册自身，并要求更新其内容。如果有任何更新，它将收到通知，并且将从存储器中读取数据，此视图将传达存储器值的现在是什么:

```ts
// demo/selectedView.js

import store from "./store";

console.log('selected view loaded');

class SelectedView {
  constructor() {
    this.index = 0;
    store.addListener(this.notifyChanged.bind(this));
  }

  notifyChanged() {
    this.index = store.getSelectedItem();
    console.log('new index is ', this.index);
  }
}

const view = new SelectedView();
export default SelectedView;
```

# 运行演示

在我们运行演示之前，我们需要一个应用文件`app.js`。`app.js`文件应该要求我们的视图，并且执行选择:

```ts
// demo/app.js

import selectionView from './selectionView';
import selectedView from './selectedView';

// carry out the selection
selectionView.selectIndex(1);

```

要运行我们的演示，我们需要编译它。上面我们使用了 ES2015 模块。为了编译这些模块，我们将使用`webpack`。我们需要在我们的终端中键入以下内容来安装`webpack`：

```ts
npm install webpack webpack-cli --save-dev
```

一旦我们这样做了，我们需要创建`webpack.config.js`文件，告诉 Webpack 如何编译我们的文件以及将生成的捆绑包放在哪里。该文件如下所示:

```ts
// webpack.config.js

module.exports = {
  entry: "./app.js",
  output: { 
    filename: "bundle.js"
  },
  watch: false
};
```

这告诉 Webpack`app.js`是我们应用程序的入口点，并且在创建输出文件`bundle.js`时应该爬取所有的依赖项。Webpack 默认会将`bundle.js`放在`dist`目录中。

还有一件事，我们需要一个名为`index.html`的 HTML 文件。我们将放在`dist`文件夹下。它应该是这样的:

```ts
// demo/dist/index.html

<html>
  <body>
    <script src="img/bundle.js"></script>
  </body>
</html>

```

最后，为了运行我们的应用程序，我们需要使用 Webpack 编译它，并启动一个 HTTP 服务器并打开浏览器。我们将在`demo`目录中使用以下命令完成所有操作：

```ts
webpack && cd dist && http-server -p 5000
```

现在，打开浏览器并导航到`http://localhost:5000`。您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/999c31ff-43ad-4cc8-b1f2-9ce4d710869a.png)

所有这些演示了如何使用分发器和存储器进行视图通信。

# 在我们的流程中添加更多操作

让我们来做一个现实检查。我们还没有将 Flux 流组织得像我们可以使它美观。总体概览是正确的，但如果我们能稍微整理一下，为更多操作留出空间，那将��很好，这样我们就可以更好地了解应用程序应该如何从这里发展。

# 清理视图

首要任务是查看我们的第一个视图以及它如何对用户交互的反应。目前它看起来像这样：

```ts
// first.view.js

import dispatcher from "./dispatcher";

class FirstView {
  selectIndex(index) {
    dispatcher.dispatch({
      type: "SELECT_INDEX",
      data: index
    });
  }
}

let view = new FirstView();
```

在我们的流程中添加更多操作意味着我们将向视图中添加一些方法，如下所示:

```ts
// first.viewII.js

import dispatcher from "./dispatcher";

class View {
  selectIndex(data) {
    dispatcher.dispatch({
      type: "SELECT_INDEX",
      data
    });
  }

  createProduct(data) {
    dispatcher.dispatch({
      type: "CREATE_PRODUCT",
      data
    });
  }

  removeProduct(data) {
    dispatcher.dispatch({
      type: "REMOVE_PRODUCT",
      data
    });
  }
}

let view = new View(); 
```

好的，现在我们知道如何添加动作了。但是看起来有点丑陋，因为有这么多调用`dispatcher`和魔术字符串，所以我们通过创建一个包含常量的文件`product.constants.js`稍微清理一下，其中包含以下代码：

```ts
// product.constants.js

export const SELECT_INDEX = "SELECT_INDEX",
export const CREATE_PRODUCT = "CREATE_PRODUCT",
export const REMOVE_PRODUCT = "REMOVE_PRODUCT"
```

让我们再做一件事。让我们把`dispatcher`移到`product.actions.js`中；这通常被称为动作创建者。它将包含`dispatcher`并引用我们的`product.constants.js`文件。所以让我们创建该文件：

```ts
// product.actions.js

import {
  SELECT_INDEX,
  CREATE_PRODUCT,
  REMOVE_PRODUCT
} from "./product-constants";
import dispatcher from "./dispatcher";
import ProductConstants from "./product.constants";

export const selectIndex = data =>
  dispatcher.dispatch({
    type: SELECT_INDEX,
    data
  });

export const createProduct = data =>
  dispatcher.dispatch({
    type: CREATE_PRODUCT,
    data
  });

export const removeProduct = data =>
  dispatcher.dispatch({
    type: REMOVE_PRODUCT,
    data
  });
```

使用这些结构，我们可以大大简化视图，看起来像这样：

```ts
// first.viewIII.js

import { 
  selectIndex, 
  createProduct, 
  removeProduct 
} from 'product.actions';

function View() {
  this.selectIndex = index => {
    selectIndex(index);
  };

  this.createProduct = product => {
    createProduct(product);
  };

  this.removeProduct = product => {
    removeProduct(product)
  };
}

var view = new View();
```

# 清理商店

我们可以对商店做出改进。没有必要编写我们目前所做的所有代码。实际上，市面上有一些库能更好地处理某些功能。

在我们计划应用所有这些变化之前，让我们回顾一下我们的商店到底能做些什么，以及清理工作完成后仍需要具备哪些功能。

让我们想一想，到目前为止我们的商店能做什么：

+   处理状态变化：它处理状态变化；无论是创建、更新、列出还是删除状态，商店都能改变状态。

+   可订阅的：它可以让您订阅它；商店具有订阅功能对于视图来说很重要，例如，当状态发生变化时，视图可以监听商店的状态。视图可能会根据新数据重新渲染。

+   可以传达状态变化：它可以发送状态已更改的事件；这与能够订阅商店相搭配使用，但这实际上是通知监听器状态已更改的行为。

# 添加 EventEmitter

最后两点实际上可以归结为一个主题，即事件处理，或者能够注册并触发事件的功能。

那么清理商店是什么样子的，为什么我们需要清理呢？清理的原因是使代码更简单。通常在构建商店时会使用一个标准库，称为`EventEmitter`。该库处理了我们之前提到的内容，即能够注册和触发事件。这是发布-订阅模式的简单实现。基本上，`EventEmitter`允许您订阅特定事件，并且也允许您触发事件。有关模式本身的更多信息，请参阅以下链接：[`en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern`](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern)。

你肯定能为此编写自己的代码，但能够使用专用库让您可以专注于其他重要事项，比如解决业务问题，这真的很好。

我们决定使用`EventEmitter`库，并且我们这样做：

```ts
// store-event-emitter.js

export const Store = (() => {
  const eventEmitter = new EventEmitter();
  return {
    addListener: listener => {
      eventEmitter.on("changed", listener);
    },
    emitChange: () => {
      eventEmitter.emit("changed");
    },
    getSelectedItem: () => store["selectedItem"]
  };
})();
```

这使我们的代码变得更清晰，因为我们不再需要保存内部订阅者列表。虽然我们可以做更多的改变，但让我们在下一节中讨论一下。

# 添加和清理注册方法

存储的工作之一是处理事件，特别是当存储想要向视图传达其状态发生了变化时。在`store.js`文件中，还发生着其他一些事情，比如注册我们自己与`dispatcher`并能够接收分发的操作。我们使用这些操作来改变存储的状态。让我们提醒自己那是什么样子：

```ts
// store.js

let store = {};

function selectIndex(index) {
  store["selectedIndex"] = index;
}

dispatcher.register(message => {
  switch (message.type) {
    case "SELECT_INDEX":
      selectIndex(message.data);
      break;
  }
});
```

这里，我们只支持一个操作，即`SELECT_INDEX`。我们在这里需要做两件事：

+   添加另外两个操作，`CREATE_PRODUCT`和`REMOVE_PRODUCT`，以及相应的函数`createProduct()`和`removeProduct()`

+   停止使用神秘字符串，开始使用我们的常量文件

+   使用我们在`store-event-emitter.js`文件中创建的存储

让我们实现前面列表中建议的更改：

```ts
// store-actions.js

import dispatcher from "./dispatcher";
import {
  SELECT_INDEX,
  CREATE_PRODUCT,
  REMOVE_PRODUCT
} from "./product.constants";

let store = {};

function selectIndex(index) {
  store["selectedIndex"] = index;
}

export const Store = (() => {
  var eventEmitter = new EventEmitter();
  return {
    addListener: listener => {
      eventEmitter.on("changed", listener);
    },
    emitChange: () => {
      eventEmitter.emit("changed");
    },
    getSelectedItem: () => store["selectedItem"]
  };
})();

dispatcher.register(message => {
  switch (message.type) {
    case "SELECT_INDEX":
      selectIndex(message.data);
      break;
  }
});

const createProduct = product => {
  if (!store["products"]) {
    store["products"] = [];
  }
 store["products"].push(product);
};

const removeProduct = product => {
  var index = store["products"].indexOf(product);
  if (index !== -1) {
    store["products"].splice(index, 1);
  }
};

dispatcher.register(({ type, data }) => {
  switch (type) {
    case SELECT_INDEX:
      selectIndex(data);
      break;
    case CREATE_PRODUCT:
      createProduct(data);
 break;
    case REMOVE_PRODUCT:
      removeProduct(data);
 }
});
```

# 更多的改进

我们的代码肯定还有更多的改进空间。我们使用了 ES2015 的导入来导入其他文件，但我们大部分的代码都是用 ES5 编写的，所以为什么不充分利用 ES2015 给我们的大多数功能呢？我们可以做的另一个改进是引入不可变性，并确保我们的存储不是被突变的，而是从一个状态过渡到另一个状态。

让我们看一下存储文件，因为那是我们可以添加最多 ES2015 语法的地方。我们目前的模块模式看起来是这样的：

```ts
// store-event-emitter.js

var Store = (function(){
  const eventEmitter = new EventEmitter();

  return {
    addListener: listener => {
      eventEmitter.on("changed", listener);
    },
    emitChange: () => {
      eventEmitter.emit("changed");
    },
    getSelectedItem: () => store["selectedItem"]
  };
})();
```

它可以用一个简单的类来替换，而不是实例化一个`EventEmitter`，我们可以继承它。公平地说，我们可以使用 ES2015 继承或合并库来避免创建一个单独的`EventEmitter`实例，但这展示了 ES2015 可以使事情多么简洁：

```ts
// store-es2015.js

import { EventEmitter } from "events";
import {
SELECT_INDEX,
CREATE_PRODUCT,
REMOVE_PRODUCT
} from "./product.constants";

let store = {};

class Store extends EventEmitter {
  constructor() {}
    addListener(listener) {
 this.on("changed", listener);
  }

 emitChange() {
 this.emit("changed");
  }

 getSelectedItem() {
 return store["selectedItem"];
  }
}

const storeInstance = new Store();

function createProduct(product) {
  if (!store["products"]) {
    store["products"] = [];
  }
  store["products"].push(product);
}

function removeProduct(product) {
  var index = store["products"].indexOf(product);
  if (index !== -1) {
    store["products"].splice(index, 1);
  }
}

dispatcher.register(({ type, data }) => {
  switch (type) {
    case SELECT_INDEX:
      selectIndex(data);
      storeInstance.emitChange();
      break;
    case CREATE_PRODUCT:
      createProduct(data);
      storeInstance.emitChange();
      break;
    case REMOVE_PRODUCT:
      removeProduct(data);
      storeInstance.emitChange();
  }
});
```

# 增加不可变性

我们可以做的另一件事是增加不可变性。首先使用不可变性的理由是使您的代码更可预测，一些框架可以使用这一点进行更简单的变化检测，并且可以依靠引用检查而不是脏检查。当 AngularJS 的整个变化检测机制在编写 Angular 时改变时，情况就是如此。从实际的角度来看，这意味着有一些函数我们可以在我们的存储中进行操作，并应用不可变性原则。第一个原则是不要改变，而是创建一个全新的状态，而不是新状态是*旧状态+状态变化*。一个简单的例子是：

```ts
var oldState = 3;
var newState = oldState + 2
```

在这里，我们创建了一个新变量`newState`，而不是突变我们的`oldState`变量。有一些函数可以帮助我们做到这一点，叫做`Object.assign`和函数 filter。我们可以用它们来更新情况，以及从列表中添加或删除东西。让我们使用它们并重新编写我们的存储代码的一部分。让我们突出显示我们打算更改的代码：

```ts
// excerpt from store-actions.js

const createProduct = product => {
  if (!store["products"]){ 
    store["products"] = [];
  }
  store["products"].push(product);
};

const removeProduct = product => {
  var index = store["products"].indexOf(product);
  if (index !== -1) {
    store["products"].splice(index, 1);
  }
};
```

让我们应用`Object.assign`和 `filter()`，并记得不要改变东西。 最终结果应该是这样的：

```ts
// excerpt from our new store-actions-immutable.js

const createProduct = product => {
  if (!store["products"]) {
    store["products"] = [];
  }
  store.products = [...store.products, Object.assign(product)];
};

const removeProduct = product => {
  if (!store["products"]) return;

  store["products"] = products.filter(p => p.id !== product.id);
};
```

我们可以看到`createProduct()`方法使用了一个 ES2015 构造，即 spread 参数，`...`，它接受一个列表并将其成员转换为逗号分隔的项目列表。`Object.assign()`用于复制对象的所有值，因此我们存储的是对象的值而不是它的引用。 使用 filter 方法时，`removeProduct()`方法变得非常简单。 我们只需创建一个投影，不包括应该删除的产品；删除从未如此简单或优雅。 我们没有改变任何东西。

# 总结

我们的清理从视图开始；我们想要删除对 dispatcher 的直接连接，也不再需要使用魔术字符串，因为这非常容易出错，并且很容易拼错。 相反，我们可以依赖于常量。 为了解决这个问题，我们创建了一个与 dispatcher 通信的 action creator 类。

我们还创建了一个常量模块来删除魔术字符串。

此外，我们通过开始使用`EventEmitter`来改进存储。 最后，我们通过给它添加更多动作并开始引用常量来进一步改进存储。

在这一点上，我们的解决方案已经准备好接受更多的动作，并且我们应该非常清楚需要添加到哪些文件中，因为我们支持越来越多的用户交互。

最后，我们围绕 ES2015 和不可变性进行了改进，使得我们的代码看起来更加整洁。 有了这个基础，我们现在可以从静态数据转为涉及副作用和 Ajax 的工作。

让我们在图表中总结我们所有的改进，显示添加到我们流程中的构造：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d3e6216d-ff51-4e48-bac1-369b8349deac.png)

很明显，使用 action creator 并不是必须的，但它确实清理了代码，并且对存储使用 `EventEmitter`也是如此；很好但不是必需的。

# 添加 AJAX 调用

到目前为止，我们在 Flux 流中只处理静态数据。 现在是时候向流程添加真实数据连接，因此添加真实数据。 是时候开始通过 AJAX 和 HTTP 与 API 进行通信了。 获取数据现在相当容易，多亏了 fetch API 和 RxJS 等库。 在将其纳入流程时，你需要考虑以下事项：

+   在哪里进行 HTTP 调用

+   如何确保存储得到更新并通知感兴趣的视图

我们注册存储到`dispatcher`的代码如下：

```ts
// excerpt from store-actions-immutable.js

const createProduct = (product) => {
  if (!store["products"]) {
    store["products"] = [];
  }

  store.products = [...store.products, Object.assign(product)];
}

dispatcher.register(({ type, data }) => {
  switch (type) {
    case CREATE_PRODUCT:
      createProduct(data);
      store.emitChange();
      break;
      /* other cases below */
  }
})
```

如果我们真的这么做，即调用 API 来保存这个产品，`createProduct()`将是我们调用 API 的地方，如下所示：

```ts
// example use of fetch()

fetch(
  '/products' ,
  { method : 'POST', body: product })
  .then(response => {
   // send a message to the dispatcher that the list of products should be reread
}, err => {  
  // report error
});
```

调用 `fetch()` 返回一个 `Promise`。 然而，让我们使用 async/await，因为它使调用变得更加可读。 代码上的差异可见以下示例：

```ts
// contrasting example of 'fetch() with promise' vs 'fetch with async/await'

fetch('url')
 .then(data => console.log(data))
 .catch(error => console.error(error));

 // using async/await
 try {
   const data = await fetch('url');
   console.log(data);
 } catch (error) {
   console.error(error);
 }
```

用这种方法替换`createProduct()`中发生的事情会添加大量噪音的代码，因此将您的 HTTP 交互封装在 API 结构中是一个好主意，如下所示：

```ts
// api.js 

export class Api {
  createProduct(product) {
    return fetch("/products", { method: "POST", body: product });
  }
}
```

现在让我们用调用我们的 API 结构来替换`createProduct()`方法的内容，如下所示：

```ts
// excerpt from store-actions-api.js

import { Api } from "./api";

const api = new Api();

createProduct() {
  api.createProduct();
}
```

不过，这还不够。因为我们通过 API 调用创建了一个产品，所以我们应该发出一个强制产品列表重新读取的动作。我们没有这样的动作或支持方法在存储中处理它，所以让我们添加一个：

```ts
// product.constants.js

export const SELECT_INDEX = "SELECT_INDEX";
export const CREATE_PRODUCT = "CREATE_PRODUCT";
export const REMOVE_PRODUCT = "REMOVE_PRODUCT";
export const GET_PRODUCTS = "GET_PRODUCTS";
```

现在让我们在存储中添加所需的方法，并处理它的情况：

```ts
// excerpt from store-actions-api.js

import { Api } from "./api";
import {
  // other actions per usual
  GET_PRODUCTS,
} from "./product.constants";

const setProducts = (products) => {
 store["products"] = products;
}

const setError = (error) => {
  store["error"] = error;
}

dispatcher.register( async ({ type, data }) => {
  switch (type) {
    case CREATE_PRODUCT:
      try {
        await api.createProduct(data);
        dispatcher.dispatch(getProducts());
      } catch (error) {
        setError(error);
        storeInstance.emitError();
      }
      break;
    case GET_PRODUCTS:
 try {
 const products = await api.getProducts();
 setProducts(products);
 storeInstance.emitChange();
 }
 catch (error) {
 setError(error);
 storeInstance.emitError();
 }
 break;
  }
});
```

我们可以看到`CREATE_PRODUCT`情况将调用相应的 API 方法`createProduct()`，在完成时将分发`GET_PRODUCTS`动作。这样做的原因是，当我们成功创建产品时，我们需要从端点读取以获取产品列表的更新版本。我们不能详细看到这一点，但它是通过我们调用`getProducts()`来调用的。同样，封装每个被分发的东西是很好的，这个封装就是一个动作创建者。

整个文件看起来像这样：

```ts
// store-actions-api.js

import dispatcher from "./dispatcher";
import { Action } from "./api";
import { Api } from "./api";
import {
  CREATE_PRODUCT,
  GET_PRODUCTS,
  REMOVE_PRODUCT,
  SELECT_INDEX
} from "./product.constants";

let store = {};

class Store extends EventEmitter {
  constructor() {}
  addListener(listener) {
    this.on("changed", listener);
  }

  emitChange() {
    this.emit("changed");
  }

  emitError() {
    this.emit("error");
  }

  getSelectedItem() {
    return store["selectedItem"];
  }
}

const api = new Api();
const storeInstance = new Store();

const selectIndex = index => {
  store["selectedIndex"] = index;
};

const createProduct = product => {
  if (!store["products"]) {
    store["products"] = [];
  }
  store.products = [...store.products, Object.assign(product)];
};

const removeProduct = product => {
  if (!store["products"]) return;
  store["products"] = products.filter(p => p.id !== product.id);
};

const setProducts = products => {
  store["products"] = products;
};

const setError = error => {
  store["error"] = error;
};

dispatcher.register(async ({ type, data }) => {
  switch (type) {
    case "SELECT_INDEX":
      selectIndex(message.data);
      storeInstance.emitChange();
      break;
    case CREATE_PRODUCT:
      try {
        await api.createProduct(data);
        storeInstance.emitChange();
      } catch (error) {
        setError(error);
        storeInstance.emitError();
      }
      break;
    case GET_PRODUCTS:
      try {
        const products = await api.getProducts();
        setProducts(products);
        storeInstance.emitChange();
      } catch (error) {
        setError(error);
        storeInstance.emitError();
      }
      break;
   }
});
```

# 更大的解决方案

到目前为止，我们一直在描述一个只包含产品主题的解决方案，通信只发生在一个视图到另一个视图。在一个更现实的应用程序中，我们将有许多主题，如用户管理、订单等；它们的确切名称取决于您应用程序的领域。至于视图，很可能你会有大量的视图监听另一个视图，就像这个例子中一样：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/95cff40e-3af8-43de-904f-36ade57a8316.png)

这描述了一个包含四个不同视图组件的应用程序，围绕它们自己的主题。**客户视图**包含客户列表，并且允许我们更改我们当前想要关注的客户。另外三个支持视图显示**订单**，**消息**和**朋友**，它们的内容取决于当前突出显示的客户。从 Flux 的角度来看，**订单**，**消息**和**朋友**视图可以轻松地向存储注册，以知道何时更新了，因此它们可以获取/重新获取它们需要的数据。然而，想象一下，支持视图自身想要支持 CRUD 操作；然后它们将需要自己的一组常量、动作创建者、API 和存储。因此，现在您的应用程序需要看起来像这样：

```ts
/customers 
  constants.js
  customer-actions.js
  customer-store.js
  customer-api.js
/orders
  constants.js
  orders-actions.js
  orders-store.js
  orders-api.js
/messages
  constants.js
  messages-actions.js
  messages-store.js
  messages-api.js
/friends
  constants.js
  friends-actions.js
  friends-store.js
  friends-api.js
/common
  dispatcher.js
```

这里存在两种有趣的情况：

+   您有一个独立的视图；所有 CRUD 操作都在它内部发生

+   您有一个需要监听其他视图的视图

对于第一种情况，一个很好的经验法则是创建自己的一组常量、动作创建者、API 和存储。

对于第二种情况，请确保您的视图向该主题的存储注册自己。例如，如果朋友视图需要监听客户视图，那么它需要向客户存储注册自己。

# 摘要

我们开始只是想解释 Flux 架构模式。很容易就开始提及它如何与 React 配合，以及有哪些支持 Flux 和 React 的好用库和工具。然而，这样做会使我们的焦点偏离了从更加框架无关的角度解释这一模式的初衷。因此，本章的其他部分致力于解释核心概念，如动作、动作创建者、分发器、仓库和统一数据流。我们逐渐改进了代码，开始使用常量、动作创建者和一个很好的支持库，比如`EventEmitter`。我们解释了 HTTP 如何嵌入其中，最后，我们讨论了如何构建我们的应用程序。关于 Flux 还有很多可以说的，但我们选择限制范围，以便了解基本原理，这样我们就可以在后续章节中深入研究 Redux 和 NgRx 的方式进行比较。

下一章将在此基础上介绍**函数响应式编程**（**FRP**）的概念。它更多地处理的是如何理解数据似乎随时到来的事实。尽管听起来很混乱，但甚至这也可以被建模为创建一种结构和秩序的感觉，只要我们把我们的数据看作是一种流。关于这一点，下一章会详细介绍。
