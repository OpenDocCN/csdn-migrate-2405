# Angular 学习手册第二版（三）

> 原文：[`zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048`](https://zh.annas-archive.org/md5/6C06861E49CB1AD699C8CFF7BAC7E048)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Angular 组件构建应用程序

我们已经达到了一个阶段，在这个阶段，我们可以通过在其他组件中嵌套组件来成功开发更复杂的应用程序，形成一种组件树。然而，将所有组件逻辑捆绑在一个唯一的文件中绝对不是正确的方法。我们的应用程序很快可能变得难以维护，并且正如我们将在本章后面看到的那样，我们将错过 Angular 的依赖管理机制可以为游戏带来的优势。

在本章中，我们将看到如何基于组件树构建应用程序架构，以及新的 Angular 依赖注入机制如何帮助我们以最小的工作量和最佳结果声明和使用应用程序中的依赖项。

在本章中，我们将涵盖以下主题：

+   目录结构和命名约定的最佳实践

+   依赖注入的不同方法

+   将依赖项注入到我们的自定义类型中

+   在整个组件树中覆盖全局依赖项

+   与宿主组件交互

+   概述指令生命周期

+   概述组件生命周期

# 介绍组件树

基于 Web 组件架构的现代 Web 应用程序通常符合一种树形层次结构，其中顶层主要组件（通常放置在主 HTML 索引文件的某个位置）充当全局占位符，子组件成为其他嵌套子组件的宿主，依此类推。

这种方法有明显的优势。一方面，可重用性不会受到损害，我们可以轻松地在组件树中重用组件。其次，由此产生的细粒度减少了构想、设计和维护更大型应用程序所需的负担。我们可以简单地专注于单个 UI 部分，然后将其功能包装在新的抽象层周围，直到我们从头开始包装一个完整的应用程序。

或者，我们可以从另一个角度来处理我们的 Web 应用程序，从更通用的功能开始，最终将应用程序拆分为更小的 UI 和功能部分，这些部分成为我们的 Web 组件。后者已成为构建基于组件的架构时最常见的方法。我们将在本书的其余部分坚持这一方法，将架构视为下图所示的架构：

```ts
Application bootstrap
Root module
 Root component that is Application component
 Component A
 Component B
 Component B-I
 Component B-II
 Component C
 Component D
Feature module
 Component E
 Component F
Common module
 Component G
 Component H
```

为了清晰起见，本章将借用我们在前几章中编写的代码，并将其拆分为组件层次结构。我们还将为最终应用程序中所有支持类和模型分配一些空间，以塑造我们的番茄工具。这将成为学习 Angular 中内置的依赖注入机制的绝佳机会，我们将在本章后面看到。

# 可扩展应用程序的通用约定

公平地说，我们已经解决了现代网页开发人员在构建应用程序时所面临的许多常见问题，无论是小型还是大型应用程序。因此，定义一个架构来将上述问题分离成单独的领域文件夹，满足媒体资产和共享代码单元的需求是有意义的。

Angular 将代码和资产分离的方法是通过将它们组织到不同的文件夹中，同时引入 Angular 模块的概念。在这些模块中注册构造。通过引入模块，我们的组件中的许多噪音已经消失，我们的组件可以自由地使用同一模块中的其他构造，有时甚至可以使用其他模块中的构造，前提是导入其所在的模块。

值得强调的是，当我们谈论 Angular 模块时，我们指的是`@NgModule`装饰器，当我们谈论模块时，我们指的是 ES2015 构造。

有时，两个上下文可能需要共享相同的实体，这是可以接受的（只要在我们的项目中不成为常见情况，这将表示严重的设计问题）。还值得强调的是，我们使用“上下文”一词来描述构造的逻辑边界。上下文最好保留在一个 Angular 模块中。因此，每当使用“上下文”一词时，都要考虑在代码中将其转换为一个 Angular 模块。

以下示例应用于我们之前在番茄工作法组件上的工作，基本上构成了我们整个应用程序的上下文和不同构造。

+   任务上下文：

+   任务模块

+   任务模型

+   任务服务

+   任务表组件

+   任务番茄钟组件

+   任务工具提示指令

+   计时器上下文：

+   计时器模块

+   计时器功能

+   计时器组件

+   管理员上下文：

+   管理员模块

+   认证服务

+   登录组件

+   编辑器组件

+   共享上下文：

+   共享模块

+   跨功能共享的组件

+   跨功能共享的管道

+   跨功能共享的指令

+   全局模型和服务

+   共享媒体资产

正如我们所看到的，第一步是定义应用程序需要的不同功能，要记住的是，每个功能在与其他功能隔离时应该是有意义的。一旦我们定义了所需的功能集，我们将为每个功能创建一个模块。然后，每个模块将填充代表其特征的组件、指令、管道、模型和服务。在定义功能集时，请始终记住封装和可重用性的原则。

最初，在启动项目时，您应该根据它们的名称命名您的构造，所以说我们有`Admin`上下文，它应该看起来像这样：

```ts
//admin/

admin.module.ts
authentication.service.ts
login.component.ts
editor.component.ts
```

通过快速浏览，您应该能够看到构造包含的内容，因此使用类似于以下的命名标准：

```ts
<name>.<type>.ts // example login.service.ts
```

当然，这不是唯一的方法。还有另一种完全可以接受的方法，即为每种类型创建子目录，因此您之前的`admin`目录可能看起来像这样：

```ts
//admin/

admin.module.ts
services/
 authentication.service.ts
components/
 login.component.ts
 login.component.html
 editor.component.ts
 create-user.component.ts
pipes/
 user.pipe.ts
```

值得注意的是，为了便于调试，您应该在文件名中保留类型。否则，当在浏览器中寻找特定文件以设置断点时，比如登录服务，如果您开始输入`login.ts`，然后出现以下情况可能会相当令人困惑：

+   `components/login.ts`

+   `services/login.ts`

+   `pipes/login.ts`

有一个官方的样式指南，告诉您应该如何组织代码以及如何命名您的构造。遵循指南肯定有好处；对新手来说很容易，代码看起来更一致等等。您可以在这里阅读更多信息；[`angular.io/guide/styleguide`](https://angular.io/guide/styleguide)。请记住，无论您选择是否完全遵循此样式指南，一致性都很重要，因为这将使维护代码变得更容易。

# 文件和 ES6 模块命名约定

我们的每个功能文件夹将托管各种文件，因此我们需要一致的命名约定，以防止文件名冲突，同时确保不同的代码单元易于定位。

以下列表总结了社区强制执行的当前约定：

+   每个文件应包含一个代码单元。简而言之，每个组件、指令、服务、管道等都应该存在于自己的文件中。这样，我们有助于更好地组织代码。

+   文件和目录以小写 kebab-case 命名。

+   表示组件、指令、管道和服务的文件应该在它们的名称后面添加一个类型后缀：`video-player.ts`将变成`video-player.component.ts`。

+   任何组件的外部 HTML 模板或 CSS 样式表文件名都将与组件文件名匹配，包括后缀。例如，我们的`video-player.component.ts`可能会有`video-player.component.css`和`video-player.component.html`。

+   指令选择器和管道名称采用驼峰式命名，而组件选择器采用小写 kebab-case 命名。此外，强烈建议添加我们选择的自定义前缀，以防止与其他组件库发生名称冲突。例如，跟随我们的视频播放器组件，它可以表示为`<vp-video-player>`，其中`vp-`（代表 video-player）是我们的自定义前缀。

+   模块的命名遵循 PascalCased 规则

自描述名称，以及它所代表的类型。例如，如果我们看到一个名为`VideoPlayerComponent`的模块，我们可以轻松地知道它是一个组件。在选择器中使用的自定义前缀（在我们的示例中为`vp-`）不应该成为模块名称的一部分。

+   模型和接口需要特别注意。根据您的应用程序架构，模型类型的相关性会更多或更少。诸如 MVC、MVVM、Flux 或 Redux 的架构从不同的角度和重要性等级处理模型。最终，您和您选择的架构设计模式将决定以一种方式或另一种方式处理模型和它们的命名约定。本书在这方面不会表达观点，尽管我们在示例应用程序中强制执行接口模型，并将为它们创建模块。

+   我们应用程序中的每个业务逻辑组件和共享上下文都旨在以简单直接的方式与其他部分集成。每个子域的客户端都不关心子域本身的内部结构。例如，如果我们的定时器功能发展到需要重新组织成不同的文件夹层次结构，其功能的外部消费者应该保持不受影响。

# 从 facade/barrel 到 NgModule

随着应用程序的增长，有必要将构造分组为逻辑组。随着应用程序的增长，您还意识到并非所有构造都应该能够相互通信，因此您还需要考虑限制这一点。在框架中添加`@NgModule`之前，自然的做法是考虑外观模块，这基本上意味着我们创建了一个具有决定将被导出到外部世界的唯一目的的特定文件。这可能看起来像下面这样：

```ts
import TaskComponent from './task.component';
import TaskDetailsComponent from './task-details.component';
// and so on
export {
 TaskComponent,
 TaskDetailsComponent,
 // other constructs to expose
}
```

一切未明确导出的内容都将被视为私有或内部特性。使用其中一个导出的构造将像输入一样简单：

```ts
import { TaskComponent } from './task.component.ts';
// do something with the component above
```

这是一种处理分组和限制访问的有效方式。当我们深入研究下一小节中的`@NgModule`时，我们将牢记这两个特性。

# 使用 NgModule

随着`@NgModule`的到来，我们突然有了一种更合乎逻辑的方式来分组我们的构造，并且也有了一种自然的方式来决定什么可以被导出或不导出。以下代码对应于前面的外观代码，但它使用了`@NgModule`：

```ts
import { NgModule } from  '@angular/core'; import { TaskDetailComponent } from  './task.detail.component'; import { TaskDetailsComponent } from  './task.details.component'; import { TaskComponent } from  './task.component';   @NgModule({
  declarations: [TaskComponent, TaskDetailsComponent], exports: [TaskComponent, TaskDetailComponent] })
export  class  TaskModule { }
```

这将创建相同的效果，该构造称为特性模块。`exports`关键字表示了什么是公开访问的或不是。然而，获取公开访问的内容看起来有点不同。而不是输入：

```ts
import { TaskDetailComponent } from 'app/tasks/tasks';
```

我们需要将我们的特性模块导入到我们的根模块中。这意味着我们的根模块将如下所示：

```ts
import { TaskModule } from './task.module';

@NgModule({
  imports: [ TasksModule ]
 // the rest is omitted for brevity
}) 
```

这将使我们能够在模板标记中访问导出的组件。因此，在您即将构建的应用程序中，请考虑什么属于根模块，什么是特性的一部分，以及什么是更常见的并且在整个应用程序中都使用。这是您需要拆分应用程序的方式，首先是模块，然后是适当的构造，如组件、指令、管道等。

# 在 Angular 中依赖注入是如何工作的

随着我们的应用程序的增长和发展，我们的每一个代码实体在内部都需要其他对象的实例，这在软件工程领域更为常见的称为依赖关系。将这些依赖关系传递给依赖客户端的行为称为注入，它还涉及另一个名为注入器的代码实体的参与。注入器将负责实例化和引导所需的依赖关系，以便在成功注入客户端后立即可以使用。这非常重要，因为客户端对如何实例化自己的依赖关系一无所知，只知道它们实现的接口以便使用它们。

Angular 具有一流的依赖注入机制，可以轻松地将所需的依赖关系暴露给 Angular 应用程序中可能存在的任何实体，无论是组件、指令、管道还是任何其他自定义服务或提供者对象。事实上，正如我们将在本章后面看到的，任何实体都可以利用 Angular 应用程序中的依赖注入（通常称为 DI）。在深入讨论这个主题之前，让我们先看看 Angular 的 DI 试图解决的问题。

让我们看看我们是否有一个音乐播放器组件，它依赖于一个“播放列表”对象来向用户播放音乐：

```ts
import { Component } from  '@angular/core'; import { Playlist } from  './playlist.model'; @Component({
  selector:  'music-player', templateUrl:  './music-player.component.html' })
export  class  MusicPlayerComponent { playlist:  Playlist; constructor() { this.playlist  =  new  Playlist();
 }}
}
```

“播放列表”类型可能是一个通用类，在其 API 中返回一个随机的歌曲列表或其他内容。现在这并不重要，因为唯一重要的是我们的`MusicPlayerComponent`实体确实需要它来提供功能。不幸的是，先前的实现意味着这两种类型紧密耦合，因为组件在自己的构造函数中实例化了播放列表。这意味着如果需要，我们无法以整洁的方式更改、覆盖或模拟“播放列表”类。这也意味着每次我们实例化一个`MusicPlayerComponent`时都会创建一个新的“播放列表”对象。在某些情况下，这可能是不希望的，特别是如果我们希望在整个应用程序中使用单例并因此跟踪播放列表的状态。

依赖注入系统试图通过提出几种模式来解决这些问题，而构造函数注入模式是 Angular 强制执行的模式。前面的代码片段可以重新思考如下：

```ts
import { Component } from  '@angular/core'; import { Playlist } from  './playlist.model'; @Component({
 selector: 'music-player',
 templateUrl: './music-player.component.html'
})
export class MusicPlayerComponent {
 constructor(private playlist: Playlist) {}
}
```

现在，`Playlist`是在我们的组件外部实例化的。另一方面，`MusicPlayerComponent`期望在组件实例化之前已经有这样一个对象可用，以便通过其构造函数注入。这种方法使我们有机会覆盖它或者模拟它。

基本上，这就是依赖注入的工作原理，更具体地说是构造函数注入模式。但是，这与 Angular 有什么关系呢？Angular 的依赖注入机制是通过手动实例化类型并通过构造函数注入它们吗？显然不是，主要是因为我们也不会手动实例化组件（除非编写单元测试时）。Angular 具有自己的依赖注入框架，顺便说一句，这个框架可以作为其他应用程序的独立框架使用。

该框架提供了一个实际的注入器，可以审视构造函数中用于注释参数的标记，并返回每个依赖类型的单例实例，因此我们可以立即在类的实现中使用它，就像前面的例子一样。注入器不知道如何创建每个依赖项的实例，因此它依赖于在应用程序引导时注册的提供者列表。这些提供者实际上提供了对标记为应用程序依赖项的类型的映射。每当一个实体（比如一个组件、一个指令或一个服务）在其构造函数中定义一个标记时，注入器会在该组件的已注册提供者池中搜索与该标记匹配的类型。如果找不到匹配项，它将委托给父组件的提供者进行搜索，并将继续向上进行提供者的查找，直到找到与匹配类型的提供者或者达到顶层组件。如果提供者查找完成后没有找到匹配项，Angular 将抛出异常。

后者并不完全正确，因为我们可以使用`@Optional`参数装饰器在构造函数中标记依赖项，这种情况下，如果找不到提供者，Angular 将不会抛出任何异常，并且依赖参数将被注入为 null。

每当提供程序解析为与该令牌匹配的类型时，它将返回此类型作为单例，因此将被注入器作为依赖项注入。公平地说，提供程序不仅仅是将令牌与先前注册的类型进行配对的键/值对集合，而且还是一个工厂，它实例化这些类型，并且也实例化每个依赖项自己的依赖项，以一种递归依赖项实例化的方式。

因此，我们可以这样做，而不是手动实例化`Playlist`对象：

```ts
import { Component } from  '@angular/core'; import { Playlist } from  './playlist'; @Component({
  selector:  'music-player', templateUrl:  './music-player.component.html', providers: [Playlist**]** })
export  class  MusicPlayerComponent { constructor(private  playlist:  Playlist) {} }
```

`@Component`装饰器的`providers`属性是我们可以在组件级别注册依赖项的地方。从那时起，这些类型将立即可用于该组件的构造函数注入，并且，正如我们将在接下来看到的，也可用于其子组件。

# 关于提供程序的说明

在引入`@NgModule`之前，Angular 应用程序，特别是组件，被认为是负责其所需内容的。因此，组件通常会要求其需要的依赖项以正确实例化。在上一节的示例中，`MusicPlayerComponent`请求一个`Playlist`依赖项。虽然这在技术上仍然是可能的，但我们应该使用我们的新`@NgModule`概念，而不是在模块级别提供构造。这意味着先前提到的示例将在模块中注册其依赖项，如下所示：

```ts
@NgModule({
 declarations: [MusicComponent, MusicPlayerComponent]
 providers: [Playlist, SomeOtherService]
})
```

在这里，我们可以看到`Playlist`和`SomeOtherService`将可用于注入，对于在 declarations 属性中声明的所有构造。正如你所看到的，提供服务的责任在某种程度上已经转移。正如之前提到的，这并不意味着我们不能在每个组件级别上提供构造，存在这样做有意义的用例。然而，我们想强调的是，通常情况是将需要注入的服务或其他构造放在模块的`providers`属性中，而不是组件中。

# 跨组件树注入依赖项

我们已经看到，provider 查找是向上执行的，直到找到匹配项。一个更直观的例子可能会有所帮助，所以让我们假设我们有一个音乐应用程序组件，在其指令属性（因此也在其模板中）中托管着一个音乐库组件，其中包含我们下载的所有曲目的集合，还托管着一个音乐播放器组件，因此我们可以在我们的库中播放任何曲目：

```ts
MusicAppComponent
 MusicLibraryComponent
 MusicPlayerComponent
```

我们的音乐播放器组件需要我们之前提到的`Playlist`对象的一个实例，因此我们将其声明为构造函数参数，并方便地用`Playlist`标记进行注释：

```ts
MusicAppComponent
 MusicLibraryComponent
 MusicPlayerComponent(playlist: Playlist)
```

当`MusicPlayerComponent`实体被实例化时，Angular DI 机制将会遍历组件构造函数中的参数，并特别关注它们的类型注解。然后，它将检查该类型是否已在组件装饰器配置的 provider 属性中注册。代码如下：

```ts
@Component({
 selector: 'music-player',
 providers: [Playlist]
})
export class MusicPlayerComponent {
 constructor(private playlist: Playlist) {}
}
```

但是，如果我们想在同一组件树中的其他组件中重用`Playlist`类型呢？也许`Playlist`类型在其 API 中包含了一些不同组件在应用程序中同时需要的功能。我们需要为每个组件在 provider 属性中声明令牌吗？幸运的是不需要，因为 Angular 预见到了这种必要性，并通过组件树带来了横向依赖注入。

在前面的部分中，我们提到组件向上进行 provider 查找。这是因为每个组件都有自己的内置注入器，它是特定于它的。然而，该注入器实际上是父组件注入器的子实例（依此类推），因此可以说 Angular 应用程序不是一个单一的注入器，而是同一个注入器的许多实例。

我们需要以一种快速且可重用的方式扩展`Playlist`对象在组件树中的注入。事先知道组件从自身开始执行提供者查找，然后将请求传递给其父组件的注入器，我们可以通过在父组件中注册提供者，甚至是顶级父组件中注册提供者来解决这个问题，这样依赖项将可用于每个子组件的注入。在这种情况下，我们可以直接在`MusicAppComponent`中注册`Playlist`对象，而不管它是否需要它进行自己的实现：

```ts
@Component({
 selector: 'music-app',
 providers: [Playlist],
 template: '<music-library></music-library>'
})
export class MusicAppComponent {}
```

即使直接子组件可能也不需要依赖项进行自己的实现。由于它已经在其父`MusicAppComponent`组件中注册，因此无需再次在那里注册：

```ts
@Component({
 selector: 'music-library',
 template: '<music-player></music-player>'
})
export class MusicLibraryComponent {}
```

最后，我们到达了我们的音乐播放器组件，但现在它的`providers`属性中不再包含`Playlist`类型作为注册令牌。实际上，我们的组件根本没有`providers`属性。它不再需要这个，因为该类型已经在组件层次结构的某个地方注册，立即可用于所有子组件，无论它们在哪里：

```ts
@Component({
 selector: 'music-player'
})
export class MusicPlayerComponent {
 constructor(private playlist: playlist) {}
}
```

现在，我们看到依赖项如何向下注入组件层次结构，以及组件如何执行提供者查找，只需检查其自己注册的提供者并将请求向上冒泡到组件树中。但是，如果我们想限制这种注入或查找操作呢？

# 限制依赖项向下注入组件树

在我们之前的例子中，我们看到音乐应用组件在其提供者集合中注册了播放列表令牌，使其立即可用于所有子组件。有时，我们可能需要限制依赖项的注入，仅限于层次结构中特定组件旁边的那些指令（和组件）。我们可以通过在组件装饰器的`viewProviders`属性中注册类型令牌来实现这一点，而不是使用我们已经看到的 providers 属性。在我们之前的例子中，我们可以仅限制`Playlist`的向下注入一级：

```ts
@Component({
 selector: 'music-app',
 viewProviders : [Playlist],
 template: '<music-library></music-library>'
})
export class MusicAppComponent {}
```

我们正在告知 Angular，`Playlist`提供程序只能被位于`MusicAppComponent`视图中的指令和组件的注入器访问，而不是这些组件的子级。这种技术的使用是组件的专属，因为只有它们具有视图。

# 限制提供程序查找

就像我们可以限制依赖注入一样，我们可以将依赖查找限制在仅限于直接上一级。为此，我们只需要将`@Host()`装饰器应用于那些我们想要限制提供程序查找的依赖参数：

```ts
import {Component, Host} from '@angular/core';

@Component {
 selector: 'music-player'
}
export class MusicPlayerComponent {
 constructor(@Host() playlist:Playlist) {}
}
```

根据前面的例子，`MusicPlayerComponent`注入器将在其父组件的提供程序集合（在我们的例子中是`MusicLibraryComponent`）中查找`Playlist`类型，并在那里停止，抛出异常，因为`Playlist`没有被父级注入器返回（除非我们还用`@Optional()`参数装饰器装饰它）。

为了澄清这个功能，让我们做另一个例子：

```ts
@Component({
 selector: 'granddad',
 template: 'granddad <father>'
 providers: [Service]
})
export class GranddadComponent {
 constructor(srv:Service){}
}

@Component({
 selector: 'father',
 template: 'father <child>'
})
export class FatherComponent {
 constructor(srv:Service) {} // this is fine, as GranddadComponent provides Service
}

@Component({
 selector: 'child',
 template: 'child'
})
export class ChildComponent {
  constructor(@Host() srv:Service) {} // will cause an error
}
```

在这种情况下，我们会得到一个错误，因为`Child`组件只会向上查找一级，尝试找到服务。由于它向上两级，所以找不到。

# 在注入器层次结构中覆盖提供程序

到目前为止，我们已经看到了 Angular 的 DI 框架如何使用依赖标记来内省所需的类型，并从组件层次结构中可用的任何提供程序集中返回它。然而，在某些情况下，我们可能需要覆盖与该标记对应的类实例，以便需要更专业的类型来完成工作。Angular 提供了特殊工具来覆盖提供程序，甚至实现工厂，该工厂将返回给定标记的类实例，不一定匹配原始类型。

我们在这里不会详细涵盖所有用例，但让我们看一个简单的例子。在我们的例子中，我们假设`Playlist`对象应该在组件树中的不同实体中可用。如果我们的`MusicAppComponent`指令托管另一个组件，其子指令需要`Playlist`对象的更专业版本，该怎么办？让我们重新思考我们的例子：

```ts
MusicAppComponent
 MusicChartsComponent
 MusicPlayerComponent
 MusicLibraryComponent
 MusicPlayerComponent
```

这是一个有点牵强的例子，但它肯定会帮助我们理解覆盖依赖项的要点。 `Playlist`实例对象从顶部组件向下都是可用的。 `MusicChartsComponent`指令是一个专门为畅销榜中的音乐提供服务的组件，因此其播放器必须仅播放热门歌曲，而不管它是否使用与`MusicLibraryComponent`相同的组件。我们需要确保每个播放器组件都获得适当的播放列表对象，这可以在`MusicChartsComponent`级别通过覆盖与`Playlist`标记对应的对象实例来完成。以下示例描述了这种情况，利用了`provide`函数的使用：

```ts
import { Component } from '@angular/core';
import { Playlist } from './playlist';

import { TopHitsPlaylist } from './top-hits/playlist';

@Component({
 selector: 'music-charts',
 template: '<music-player></music-player>',
 providers: [{ provide : Playlist, useClass : TopHitsPlaylist }]
})
export class MusicChartsComponent {}
```

`provide`关键字创建了一个与第一个参数中指定的标记（在本例中为`Playlist`）映射的提供程序，而`useClass`属性本质上是用来从该组件和下游重写播放列表为`TopHitsPlaylist`。

我们可以重构代码块以使用`viewProviders`，以确保（如果需要）子实体仍然接收`Playlist`的实例，而不是`TopHitsPlaylist`。或者，我们可以走额外的路线，并使用工厂根据其他要求返回我们需要的特定对象实例。以下示例将根据布尔条件变量的评估返回`Playlist`标记的不同对象实例：

```ts
function playlistFactory() {
 if(condition) { 
 return new Playlist(); 
 }
 else { 
 return new TopHitsPlaylist(); 
 }
}

@Component({
 selector: 'music-charts',
 template: '<music-player></music-player>',
 providers: [{ provide : Playlist, useFactory : playlistFactory }]
})
export class MusicChartsComponent {}
```

所以，你可以看到这有多强大。例如，我们可以确保在测试时，我们的数据服务突然被模拟数据服务替换。关键是很容易告诉 DI 机制根据条件改变其行为。

# 扩展注入器支持到自定义实体

指令和组件需要依赖项进行内省、解析和注入。其他实体，如服务类，通常也需要这样的功能。在我们的示例中，我们的`Playlist`类可能依赖于与第三方通信的 HTTP 客户端的依赖项，以获取歌曲。注入这种依赖的操作应该像在类构造函数中声明带注释的依赖项一样简单，并且有一个注入器准备好通过检查类提供程序或任何其他提供程序来获取对象实例。

只有当我们认真思考后者时，我们才意识到这个想法存在一个漏洞：自定义类和服务不属于组件树。因此，它们不会从任何内置的注入器或父注入器中受益。我们甚至无法声明提供者属性，因为我们没有用`@Component`或`@Directive`装饰器修饰这些类型的类。让我们看一个例子：

```ts
class Playlist {
 songs: Song[];
 constructor(songsService: SongsService) {
 this.songs = songsService.fetch();
 }
}
```

我们可能会尝试这样做，希望当实例化这个类以将其注入到`MusicPlayerComponent`中时，Angular 的 DI 机制会内省`Playlist`类构造函数的`songsService`参数。不幸的是，我们最终得到的只是这样的异常：

```ts
It cannot resolve all parameters for Playlist (?). Make sure they all have valid type or annotations.
```

这有点误导，因为`Playlist`中的所有构造函数参数都已经被正确注释了，对吧？正如我们之前所说，Angular DI 机制通过内省构造函数参数的类型来解析依赖关系。为了做到这一点，需要预先创建一些元数据。每个被装饰器修饰的 Angular 实体类都具有这些元数据，这是 TypeScript 编译装饰器配置细节的副产品。然而，还需要其他依赖项的依赖项没有装饰器，因此也没有为它们创建元数据。这可以通过`@Injectable()`装饰器轻松解决，它将为这些服务类提供 DI 机制的可见性。

```ts
import { Injectable } from '@angular/core';

@Injectable()
class Playlist {
 songs: string[];

 constructor(private songsService: SongsService) {
 this.songs = this.songsService.fetch();
 }
}
```

你会习惯在你的服务类中引入装饰器，因为它们经常依赖于与组件树无关的其他依赖项，以便提供功能。

实际上，无论构造函数是否具有依赖关系，都将所有服务类装饰为`@Injectable()`是一个很好的做法。这样，我们可以避免因为忽略这一要求而导致的错误和异常，一旦服务类增长，并且在将来需要更多的依赖关系。

# 使用`bootstrapModule()`初始化应用程序

正如我们在本章中所看到的，依赖查找一直冒泡直到顶部的第一个组件。这并不完全正确，因为 DI 机制还会检查`bootstrapModule()`函数的额外步骤。

据我们所知，我们使用 `bootstrapModule()` 函数来通过在其第一个参数中声明根模块来启动我们的应用程序，然后指出根组件，从而启动应用程序的组件树。

在文件 `main.ts` 中，典型的引导看起来像下面这样：

```ts
import { enableProdMode } from  '@angular/core'; import { platformBrowserDynamic } from  '@angular/platform-browser-dynamic'; import { AppModule } from  './app/app.module'; import { environment } from  './environments/environment'; if (environment.production) {
  enableProdMode(); }

platformBrowserDynamic().bootstrapModule(AppModule);
```

从上述代码中可以得出的结论是，Angular 已经改变了引导的方式。通过添加 `@NgModule`，我们现在引导一个根模块而不是一个根组件。然而，根模块仍然需要指向一个应用程序启动的入口点。让我们来看看根模块是如何做到这一点的：

```ts
import { NgModule } from '@angular/core';
import { AppComponent } from './app.component';

@NgModule({
 bootstrap: [AppComponent]
 // the rest omitted for brevity
})
```

注意 `bootstrap` 键的存在，我们如何指出根组件 `AppComponent`。还要注意 `bootstrap` 属性是一个数组。这意味着我们可以有多个根组件。每个根组件都将具有自己的注入器和服务单例集，彼此之间没有任何关系。接下来，让我们谈谈我们可以在其中进行修改的不同模式。

# 在开发和生产模式之间切换

Angular 应用程序默认在开发模式下引导和初始化。在开发模式下，Angular 运行时会向浏览器控制台抛出警告消息和断言。虽然这对于调试我们的应用程序非常有用，但当应用程序处于生产状态时，我们不希望显示这些消息。好消息是，可以禁用开发模式，转而使用更为安静的生产模式。这个操作通常是在引导我们的应用程序之前执行的：

```ts
import { environment } from './environments/environment';
// other imports omitted for brevity
if(environment.production) {
 enableProdMode();
}

//bootstrap
platformBrowserDynamic().bootstrapModule(AppModule);
```

我们可以看到，调用 `enableProdMode()` 是启用生产模式的方法。

# Angular CLI 中的不同模式

值得注意的是，将不同的环境配置保存在不同的文件中是一个好主意，如下所示：

```ts
import { environment } from './environments/environment';
```

environments 目录包括两个不同的文件：

+   `environment.ts`

+   `environment.prod.ts`

第一个文件看起来像这样：

```ts
export const environment = {
 production: false
}
```

第二个文件看起来像这样：

```ts
export const environment = {
 production: true
}
```

根据我们调用 `ng build` 命令的方式，将使用其中的一个文件：

```ts
ng build --env=prod // uses environment.prod.ts
ng build // by default uses environment.ts 
```

要找出哪些文件映射到哪个环境，您应该查看 `angular-cli.json` 文件：

```ts
// config omitted for brevity
"environments" : {
 "dev": "environments/environment.ts",
 "prod": "environments/environment.prod.ts"
}
```

# 介绍应用程序目录结构

在前几章和本章的各个部分中，我们已经看到了布局 Angular 应用程序的不同方法和良好实践。这些准则涵盖了从命名约定到如何组织文件和文件夹的指针。从现在开始，我们将通过重构所有不同的接口、组件、指令、管道和服务，将所有这些知识付诸实践，使其符合最常见的社区约定。

到本章结束时，我们将拥有一个最终的应用程序布局，将我们迄今所见的一切都包含在以下站点架构中：

```ts
app/
 assets/ // global CSS or image files are stored here
 core/
 (application wide services end up here)
 core.module.ts
 shared/
 shared.module.ts // Angular module for shared context
 timer/
 ( timer-related components and directives )
 timer.module.ts // Angular module for timer context
 tasks/
 ( task-related components and directive )
 task.module.ts // Angular module for task context
 app
 app.component.ts
 app.module.ts // Angular module for app context
 main.ts // here we bootstrap the application
 index.html
 package.json
 tsconfig.json
 typings.json

```

很容易理解项目的整体原理。现在，我们将组合一个应用程序，其中包含两个主要上下文：计时器功能和任务列表功能。每个功能可以包含不同范围的组件、管道、指令或服务。每个功能的内部实现对其他功能或上下文是不透明的。每个功能上下文都公开了一个 Angular 模块，该模块导出了每个上下文提供给上层上下文或应用程序的功能部分（即组件，一个或多个）。所有其他功能部分（内部指令和组件）对应用程序的其余部分是隐藏的。

可以说很难划清界限，区分哪些属于特定上下文，哪些属于另一个上下文。有时，我们构建功能部分，比如某些指令或管道，可以在整个应用程序中重用。因此，将它们锁定到特定上下文并没有太多意义。对于这些情况，我们确实有共享上下文，其中存储着任何旨在在应用程序级别可重用的代码单元，而不是与组件无关的媒体文件，如样式表或位图图像。

主`app.component.ts`文件包含并导出应用程序根组件，该组件声明并在其自己的注入器中注册其子组件所需的依赖项。正如您已经知道的，所有 Angular 应用程序必须至少有一个根模块和一个根组件，由`bootstrapModule()`函数初始化。这个操作实际上是在`main.ts`文件中执行的，该文件由`index.html`文件触发。

在这样的上下文中定义一个组件或一组相关组件可以提高可重用性和封装性。唯一与应用程序紧密耦合的组件是顶级根组件，其功能通常非常有限，基本上是在其模板视图中呈现其他子组件或作为路由器组件，正如我们将在后续章节中看到的那样。

最后一部分是包含 TypeScript 编译器、类型和`npm`配置的 JSON 文件。由于 Angular 框架的版本不断发展，我们不会在这里查看这些文件的实际内容。你应该知道它们的目的，但一些具体内容，比如对等依赖版本，经常会发生变化，所以最好参考本书的 GitHub 仓库获取每个文件的最新版本。不过，`package.json`文件需要特别提及。有一些常见的行业惯例和流行的种子项目，比如 Angular 官方网站提供的项目。我们提供了几个`npm`命令来简化整个安装过程和开发工作。

# 按照 Angular 的方式重构我们的应用程序

在本节中，我们将把我们在前几章中创建的代码分割成代码单元，遵循单一职责原则。因此，除了将每个模块分配到其自己的专用文件中之外，不要期望代码有太多变化。这就是为什么我们将更多地关注如何分割事物，而不是解释每个模块的目的，你应该已经知道了。无论如何，如果需要，我们将花一分钟讨论变化。

让我们从在你的工作文件夹中创建与前一节中看到的相同的目录结构开始。我们将在路上为每个文件夹填充文件。

# 共享上下文或将所有内容存储在一个公共模块中

共享上下文是我们存储任何构造的地方，其功能旨在一次被多个上下文使用，因为它对这些上下文也是不可知的。一个很好的例子是我们一直在用来装饰我们组件的番茄钟位图，它应该存储在`app/shared/assets/img`路径下（顺便说一句，请确实将它保存在那里）。

另一个很好的例子是对模型数据建模的接口，特别是当它们的模式可以在不同功能上下文中重复使用时。例如，当我们在第四章中定义了`QueuedOnlyPipe`时，我们只对记录集中项目的排队属性进行了操作。然后，我们可以认真考虑实现一个`Queued`接口，以便以后在具有该属性的模块中提供类型检查。这将使我们的管道更具重用性和模型无关性。代码如下：

```ts
//app/shared/queueable.model.ts

export interface Queueable {
 queued: boolean;
}
```

请注意这个工作流程：首先，我们定义与这个代码单元对应的模块，然后导出它，并将其标记为默认，这样我们就可以从其他地方按名称导入它。接口需要以这种方式导出，但在本书的其余部分，我们通常会在同一语句中声明并导出模块。

有了这个接口，我们现在可以安全地重构`QueuedOnlyPipe`，使其完全不依赖于`Task`接口，以便在任何需要过滤记录集的上下文中完全重用，无论它们代表什么。代码如下：

```ts
// app/shared/queued.only.pipe.ts
import { Pipe, PipeTransform } from '@angular/core';
import { Queueable } from '../interfaces/queuable';

@Pipe({ name : 'queuedOnly' })
export class QueuedOnlyPipe implements PipeTransform {
 transform(queueableItems: Queueable[], ...args) :Queueable[] {
 return queuableItems.filter( 
 queueableItem:Queueable => queueableItem.queued === args[0]
 )
 }
}
```

正如您所看到的，每个代码单元都包含一个单一的模块。这个代码单元符合 Angular 文件名的命名约定，清楚地以驼峰命名法陈述了模块名称，再加上类型后缀（在这种情况下是`.pipe`）。实现也没有改变，除了我们用`Queuable`类型注释了所有可排队的项目，而不是之前的任务注释。现在，我们的管道可以在任何实现`Queueable`接口的模型存在的地方重复使用。

然而，有一件事情需要引起您的注意：我们不是从源位置导入`Queuable`接口，而是从一个名为`shared.ts`的文件中导入，该文件位于上一级目录。这是共享上下文的门面文件，我们将从该文件公开所有公共共享模块，不仅供消费共享上下文模块的客户端使用，还供共享上下文内部的模块使用。这是一个情况：如果共享上下文内的任何模块更改其位置，我们需要更新门面，以便任何其他引用该模块的元素在同一上下文中保持不受影响，因为它通过门面来消费它。现在是一个很好的时机来介绍我们的共享模块，以前它将是一个门面文件：

```ts
//app/shared/shared.module.ts

import { QueuedOnlyPipe } from './pipes/queued-only.pipe';

@NgModule({
 declarations: [QueuedOnlyPipe],
 exports: [QueuedOnlyPipe]
})
export class SharedModule {}
```

与门面文件的主要区别在于，我们可以通过向`SharedModule`添加方法和注入服务等方式向其添加各种业务逻辑。

到目前为止，我们只通过`SharedModule`的 exports 属性公开了管道、指令和组件，但是其他东西如类和接口呢？嗯，我们可以在需要时直接要求它们，就像这样：

```ts
import { Queueable } from '../shared/queueable';

export class ProductionService {
 queueable: Queueable;
}
```

现在我们有一个可工作的`Queuable`接口和一个`SharedModule`，我们可以创建其他接口，这些接口将在整本书中使用，对应于`Task`实体，以及我们需要的其他管道：

```ts
//app/task/task.model.ts

import { Queueable } from './queueable';

export interface Task extends Queueable {
 name: string;
 deadline: Date;
 pomodorosRequired: number;
}
```

我们通过使用 extends（而不是 implements）在 TypeScript 中将一个接口实现到另一个接口上。现在，对于`FormattedTimePipe`：

```ts
//app/shared/formatted.time.pipe.ts

import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name : 'formattedTime' })
export class FormattedTimePipe {
 transform(totalMinutes: number) {
 let minutes: number = totalMinutes % 60;
 let hours: number = Math.floor( totalMinutes / 60 );
 return `${hours}h:${minutes}m`;
 }
}
```

最后，我们需要更新我们的`SharedModule`，以包含这个`Pipe`：

```ts
//app/shared/shared.module.ts

import { QueuedOnlyPipe } from './pipes/queued-only.pipe';
import { FormattedTimePipe } from './pipes/formatted-time.pipe';

@NgModule({
 declarations: [QueuedOnlyPipe, FormattedTimePipe],
 exports: [QueuedOnlyPipe, FormattedTimePipe]
})
export class SharedModule {}
```

总结一下我们在这里做的事情，我们创建了两个接口，`Task`和`Queueable`。我们还创建了两个管道，`QueuedOnlyPipe`和`FormattedTimePipe`。我们将后者添加到我们的`@NgModule`的 declarations 关键字中，至于接口，我们将使用`import`关键字根据需要将它们引入应用程序。不再需要通过门面文件公开它们。

# 共享上下文中的服务

让我们谈谈在共享上下文中拥有服务的影响，以及`@NgModule`的添加带来了什么。我们需要关心两种类型的服务：

+   一个瞬态服务；这个服务创建自己的新副本，可能包含内部状态，对于每个创建的副本，它都有自己的状态

+   一个单例，只能有一个此服务，如果它有状态，我们需要确保在整个应用程序中只有一个此服务的副本

在 Angular 中使用依赖注入，将服务放在模块的提供者中将确保它们最终出现在根注入器上，因此如果我们有这种情况，它们将只创建一个副本：

```ts
// app/task/task.module.ts

@NgModule({
 declarations: [TaskComponent],
 providers: [TaskService]
})
export class TaskModule {} 
```

早些时候，我们在`TaskModule`中声明了一个`TaskService`。让我们来定义另一个模块：

```ts
@NgModule({
 declarations: [ProductsComponent]
 providers: [ProductsService] 
})
export class ProductsModule {}
```

只要我们在根模块中导入这两个模块，就像这样：

```ts
//app/app.module.ts

@NgModule({
 imports: [TaskModule, ProductsModule]
})
export class AppModule {}
```

我们现在已经创建了一个情况，`ProductsService`和`TaskService`可以被注入到`ProductsComponent`或`TaskComponent`的构造函数中，这要归功于`ProductsModule`和`TaskModule`都被导入到`AppModule`中。到目前为止，我们还没有问题。然而，如果我们开始使用延迟加载，我们就会遇到问题。在延迟加载中，用户导航到某个路由，我们的模块与其构造一起被加载到包中。如果延迟加载的模块或其构造之一实际上注入了，比如`ProductsService`，那么它将不是`TaskModule`或`ProductsModule`正在使用的相同`ProductsService`实例，这可能会成为一个问题，特别是如果状态是共享的。解决这个问题的方法是创建一个核心模块，一个被`AppModule`导入的模块；这将确保服务永远不会因错误而被再次实例化。因此，如果`ProductsService`在多个模块中使用，特别是在延迟加载的模块中使用，建议将其移动到核心模块。因此，我们从这样做：

```ts
@NgModule({
 providers: [ProductsService],
})
export class ProductsModule {}
```

将我们的`ProductService`移动到核心模块：

```ts
@NgModule({
 providers: [ProductsService]
})
export class CoreModule {}
```

当然，我们需要将新创建的`CoreModule`添加到我们的根模块中，就像这样：

```ts
@NgModule({
 providers: [],
 imports: [CoreModule, ProductsModule, TasksModule]
})
export class AppModule {}
```

有人可能会认为，如果我们的应用程序足够小，早期创建一个核心模块可能被视为有点过度。反对这一观点的是，Angular 框架采用移动优先的方法，作为开发人员，你应该延迟加载大部分模块，除非有充分的理由不这样做。这意味着当你处理可能被共享的服务时，你应该将它们移动到一个核心模块中。

在上一章中，我们构建了一个数据服务来为我们的数据表填充任务数据集。正如我们将在本书后面看到的那样，数据服务将被应用程序的其他上下文所使用。因此，我们将其分配到共享上下文中，并通过我们的共享模块进行暴露：

```ts
//app/task/task.service.ts

import { Injectable } from '@angular/core';
import { Task } from '../interfaces/task';

@Injectable()
export class TaskService {
 taskStore: Task[] = [];
 constructor() {
 const tasks = [
 {
 name : 'task 1',
 deadline : 'Jun 20 2017 ',
 pomodorosRequired : 2
 },
 {
 name : 'task 2',
 deadline : 'Jun 22 2017',
 pomodorosRequired : 3
 }
 ];

 this.taskStore = tasks.map( task => {
 return {
 name : task.name,
 deadline : new Date(task.deadline),
 queued : false,
 pomodorosRequired : task.pomodorosRequired
 }
 });
 }
}
```

请注意我们如何导入`Injectable()`装饰器并在我们的服务上实现它。它在构造函数中不需要任何依赖项，因此依赖于此服务的其他模块在声明构造函数时不会有任何问题。原因很简单：在我们的服务中默认应用`@Injectable()`装饰器实际上是一个很好的做法，以确保它们在开始依赖其他提供者时仍然能够无缝注入，以防我们忘记对它们进行装饰。

# 从中央服务配置应用程序设置

在之前的章节中，我们在我们的组件中硬编码了很多东西：标签、持续时间、复数映射等等。有时，我们的上下文意味着具有高度的特定性，并且在那里拥有这些信息是可以接受的。但是，有时我们可能需要更灵活和更方便的方式来全局更新这些设置。

对于这个例子，我们将使所有`l18n`管道映射和设置都可以从共享上下文中的一个中央服务中获得，并像往常一样从`shared.ts`门面暴露出来。

以下代码描述了一个将保存应用程序所有配置的`SettingsService`：

```ts
// app/core/settings.service.ts
import { Injectable } from '@angular/core';

@Injectable()
export class SettingsService {
 timerMinutes: number;
 labelsMap: any;
 pluralsMap: any;

 contructor() {
 this.timerMinutes = 25;
 this.labelsMap = {
 timer : {
 start : 'Start Timer',
 pause : 'Pause Timer',
 resume : 'Resume Countdown',
 other : 'Unknown'
 }
 };

 this.pluralsMap = {
 tasks : {
 '=0' : 'No pomodoros',
 '=1' : 'One pomodoro',
 'other' : '# pomodoros'
 }
 }
 }
}
```

请注意我们如何将与上下文无关的映射属性暴露出来，这些属性实际上是有命名空间的，以更好地按上下文分组不同的映射。

将此服务分成两个特定的服务并将它们放置在各自的上下文文件夹中，至少就`l18n`映射而言，这是完全可以的。请记住，诸如时间持续等数据将在不同的上下文中使用，正如我们将在本章后面看到的那样。

# 在我们的共享模块中将所有内容整合在一起

通过所有最新的更改，我们的`shared.module.ts`应该是这样的：

```ts
// app/shared/shared.module.ts

import { NgModule } from '@angular/core';
import { FormattedTimePipe } from './pipes/formatted-time-pipe';
import { QueuedOnlyPipe } from './pipes/queued-only-pipe';

import { SettingsService } from './services/settings.service';
import { TaskService } from './services/task.service';

@NgModule({
 declarations: [FormattedTimePipe, QueuedOnlyPipe],
  providers: [SettingsService, TaskService],
  exports: [FormattedTimePipe, QueuedOnlyPipe]
})
export class SharedModule {}
```

我们的`SharedModule`从前面暴露了`FormattedTimePipe`和`QueuedOnlyPipe`，但是有一些新的添加；即，我们添加了`provider`关键字的内容。我们添加了我们的服务，`SettingsService`和`TaskService`。

现在，当这个模块被另一个模块消耗时，会发生一件有趣的事情；所以，让我们在下面的代码中看看这样的情景：

```ts
// app/app.module.ts

import { NgModule } from '@angular/core';
import { SharedModule } from './shared/shared.module';

@NgModule({
  imports: [SharedModule]
 // the rest is omitted for brevity
})
export class AppModule {}
```

从前面部分部分知道了导入另一个模块的影响。我们知道`SharedModule`中包含的所有内容现在都可以在`AppModule`中使用，但还有更多。`SharedModule`中`provider`关键字中提到的任何内容都可以被注入。所以，假设我们有以下`app.component.ts`文件：

```ts
// app/app.component.ts

import { AppComponent } from './app.component';

@Component({
 selector: 'app',
 template: 'app'
})
export class AppComponent {
 constructor(
    private settingsService:SettingsService, 
 private taskService: TaskService
 ) {}
}
```

正如你所看到的，现在我们可以自由地注入来自其他模块的服务，只要它们是：

+   在其模块的`provider`关键字中提到

+   它们所在的模块被另一个模块导入

总之，到目前为止，我们已经学会了如何将组件和服务添加到共享模块中，还学会了我们需要在声明和`export`关键字中注册组件，对于服务，我们需要将它们放在`provider`关键字中。最后，我们需要`import`它们所在的模块，你的共享构件就可以在应用程序中使用了。

# 创建我们的组件

有了我们共享的上下文，现在是时候满足我们的另外两个上下文了：定时器和任务。它们的名称足够描述它们的功能范围。每个上下文文件夹将分配组件、HTML 视图模板、CSS 和指令文件，以提供它们的功能，还有一个外观文件，导出此功能的公共组件。

# 生命周期钩子简介

生命周期钩子是你在指令或组件的生命周期中监视阶段的能力。这些钩子本身是完全可选的，但如果你了解如何使用它们，它们可能会有很大的帮助。有些钩子被认为是最佳实践，而其他钩子则有助于调试和理解应用程序中发生的情况。一个钩子带有一个定义你需要实现的方法的接口。Angular 框架确保调用钩子，只要你将接口添加到组件或指令中，并通过实现接口指定的方法来履行合同。因为我们刚刚开始学习如何构建你的应用程序，现在可能还没有理由使用某些钩子。所以，我们将有理由在后面的章节中返回这个主题。

你可以使用的钩子如下：

+   `OnInit`

+   `OnDestroy`

+   `OnChanges`

+   `DoCheck`

+   `AfterContentInit`

+   `AfterContentChecked`

+   `AfterViewInit`

+   `AfterViewChecked`

在本节中，我们将涵盖本章中的前三个钩子，因为其余的涉及到更复杂的主题。我们将在本书的后续章节中重新讨论剩下的五个钩子。

# OnInit - 一切开始的地方

使用这个钩子就像添加`OnInit`接口并实现`ngOnInit()`方法一样简单：

```ts
export class ExampleComponent implements OnInit {
 ngOnInit() {}
}
```

不过，让我们谈谈为什么存在这个钩子。构造函数应该相对空，并且除了设置初始变量之外不应包含逻辑。在构造对象时不应该有任何意外，因为有时您构造的是用于业务使用的对象，有时它是在单元测试场景中创建的。

以下是在类的构造函数中执行的适当操作的示例。在这里，我们展示了对类成员变量的赋值：

```ts
export class Component {
 field: string;
 constructor(field: string) {
 this.field = field;
 }
}
```

以下示例显示了不应该做的事情。在代码中，我们在构造函数中订阅了一个 Observable。在某些情况下，这是可以接受的，但通常更好的做法是将这种代码放在`ngOnInit()`方法中：

```ts
export class Component {
 data:Entity;
 constructor(private http:Http) {
 this.http.get('url')
 .map(mapEntity)
 .subscribe( x => this.data = x);
 }
}
```

最好建立订阅，如之前使用`OnInit`接口提供的`ngOnInit()`方法所示。

当然，这是一个建议，而不是一项法律。如果您没有使用这个钩子，那么显然您需要使用构造函数或类似的方法来执行前面的 HTTP 调用。除了仅仅说构造函数应该为空以美观和处理测试时，还有另一个方面，即输入值的绑定。输入变量不会立即设置，因此依赖于构造函数中的输入值会导致运行时错误。让我们举例说明上述情景：

```ts
@Component({
 selector: 'father',
 template: '<child [prop]='title'></child>'
})
export class FatherComponent {
 title: string = 'value';
}

@Component({
 selector: 'child',
 template: 'child'
})
export class ExampleComponent implements OnInit {
 @Input prop;

 constructor(private http:Http) {
    // prop NOT set, accessing it might lead to an error
 console.log('prop constructor',prop) 
 }

 ngOnInit() {
    console.log('prop on init', prop) // prop is set and is safe to use
 }
}
```

在这个阶段，您可以确保所有绑定已经正确设置，并且可以安全地使用 prop 的值。如果您熟悉 jQuery，那么`ngOnInit`的作用很像`$(document).ready()`的构造，总的来说，当组件设置完成时发生的仪式在这一点上已经发生。

# OnDestroy - 当组件从 DOM 树中移除时调用

这种典型用例是在组件即将离开 DOM 树时进行一些自定义清理。它由`OnDestroy`接口和`ngOnDestroy()`方法组成。

为了演示其用法，让我们看一下下面的代码片段，我们在其中实现了`OnDestroy`接口：

```ts
@Component({
 selector: 'todos',
 template: `
 <div *ngFor="let todo of todos">
 <todo [item]="todo" (remove)="remove($event)">
 </div>
 `
})
export class TodosComponent {
 todos;

 constructor() {
 this.todos = [{
 id : 1,
 name : 'clean'
 }, {
 id : 2,
 name : 'code' 
 }]
 }

 remove(todo) {
    this.todos = this.todos.filter( t => t.id !== todo.id );
 }
}

@Component({
 selector: 'todo',
 template: `
 <div *ngIf="item">{{item.name}} <button (click)="remove.emit(item)">Remove</button></div>
 `
})
export class TodoComponent implements OnDestroy {
 @Output() remove = new EventEmitter<any>();
 @Input() item;
  ngOnDestroy() { console.log('todo item removed from DOM'); }
}
```

我们之前的片段试图突出显示当`TodoComponent`的一个实例从 DOM 树中移除时。`TodosComponent`渲染了一个`TodoComponents`列表，当调用`remove()`方法时，目标`TodoComponent`被移除，从而触发`TodoComponent`上的`ngOnDestroy()`方法。

好的，很好，所以我们有一种方法来捕获组件被销毁的确切时刻...那又怎样呢？

这是我们清理资源的地方；通过清理，我们的意思是：

+   超时，间隔应该在这里被取消订阅

+   可观察流应该被取消订阅

+   其他清理

基本上，任何导致印记的东西都应该在这里清理。

# OnChanges - 发生了变化

这个钩子的使用方式如下：

```ts
export class ExampleComponent implements OnChanges {
 ngOnChanges(changes:  SimpleChanges) { }
}
```

注意我们的方法如何接受一个名为`changes`的输入参数。这是一个对象，其中所有已更改的属性作为`changes`对象的键。每个键指向一个对象，其中包含先前值和当前值，如下所示：

```ts
{
 'prop' : { currentValue : 11, previousValue : 10 }
 // below is the remaining changed properties
}
```

上述代码假设我们有一个带有`prop`字段的类，如下所示：

```ts
export class ExampleComponent {
 prop: string;
}
```

那么，是什么导致事物发生变化？嗯，这是绑定的变化，也就是说，我们设置了`@Input`属性，如下所示：

```ts
export  class  TodoComponent  implements  OnChanges { @Input() item; ngOnChanges(changes:  SimpleChanges) { for (let  change  in  changes) { console.log(` '${change}' changed from
 '${changes[change].previousValue}' to
 '${changes[change].currentValue}' `
 ) }
 }
}
```

这里值得注意的一点是，我们跟踪的是引用的变化，而不是对象的属性变化。例如，如果我们有以下代码：

```ts
<todo [item]="todoItem">
```

如果`todoItem`上的 name 属性发生了变化，使得`todoItem.name`变为`code`而不是`coding`，这不会导致报告变化。然而，如果整个项目被替换，就像下面的代码一样：

```ts
this.todoItem = { ...this.todoItem, { name : 'coding' });
```

那么这将导致一个变化事件被发出，因为`todoItem`现在指向一个全新的引用。希望这能稍微澄清一点。

# 计时器功能

我们的第一个功能是属于计时器功能的，这也是最简单的功能。它包括一个独特的组件，其中包含我们在前几章中构建的倒计时计时器：

```ts
import { Component } from  '@angular/core'; import { SettingsService } from  "../core/settings.service"; @Component({
  selector:  'timer-widget', template: ` <div  class="text-center"> <h1> {{ minutes }}:{{ seconds  |  number }}</h1> <p>
 <button  (click)="togglePause()"  class="btn btn-danger"> {{ buttonLabelKey  |  i18nSelect: buttonLabelsMap }} </button>
 </p>
 </div>
 `
})
export  class  TimerWidgetComponent  {
 minutes:  number; seconds:  number; isPaused:  boolean; buttonLabelKey:  string; buttonLabelsMap:  any; constructor(private  settingsService:  SettingsService) { this.buttonLabelsMap  =  this.settingsService.labelsMap.timer; }

 ngOnInit() { this.reset(); setInterval(()  =>  this.tick(),  1000); }

 reset() { this.isPaused  =  true; this.minutes  =  this.settingsService.timerMinutes  -  1; this.seconds  =  59; this.buttonLabelKey  =  'start'; }

 private  tick():  void  { if  (!this.isPaused) { this.buttonLabelKey  =  'pause'; if  (--this.seconds  <  0) {
 this.seconds  =  59;
 if  (--this.minutes  <  0) {
 this.reset();
 }
 }
 }
 }

 togglePause():  void  {
 this.isPaused  =  !this.isPaused;
 if  (this.minutes  <  this.settingsService.timerMinutes  ||
 this.seconds  <  59
 ) {
 this.buttonLabelKey  =  this.isPaused  ?  'resume'  :  'pause';
 }
 }
}
```

正如你所看到的，实现方式与我们在第一章中已经看到的*在 Angular 中创建我们的第一个组件*基本相同，唯一的区别是通过`OnInit`接口钩子在 init 生命周期阶段初始化组件。我们利用`l18nSelect`管道更好地处理定时器每个状态所需的不同标签，从`SettingsService`中消耗标签信息，该服务在构造函数中注入。在本章的后面部分，我们将看到在哪里注册该提供程序。分钟数也是从服务中获取的，一旦后者绑定到类字段。

通过我们将其添加到`declarations`关键字以及`exported`关键字，后者用于启用外部访问，该组件通过`TimerModule`文件`timer.module.ts`公开导出：

```ts
import { NgModule } from '@angular/core';

@NgModule({
 // tell other constructs in this module about it
 declarations: [TimerWidgetComponent], 
 // usable outside of this module
 exports: [TimerWidgetComponent] 
})
export class TimerModule() {}
```

我们还需要记住将我们新创建的模块导入到`app.module.ts`中的根模块中：

```ts
import { NgModule } from '@angular/core';
import { TimerModule } from './timer/timer.module';

@NgModule({
  imports: [TimerModule]
 // the rest is omitted for brevity
})
```

在这一点上，我们已经创建了一个很好的结构，然后我们将为定时器功能创建更多构造。

# 任务功能

任务功能包含了一些更多的逻辑，因为它涉及两个组件和一个指令。让我们从创建`TaskTooltipDirective`所需的核心单元开始：

```ts
import { Task } from  './task.model'; import { Input, Directive, HostListener } from  '@angular/core'; @Directive({
  selector:  '[task]' })
export  class  TaskTooltipDirective { private  defaultTooltipText:  string;
 @Input() task:  Task;
 @Input() taskTooltip:  any;

 @HostListener('mouseover')
 onMouseOver() {
 if (!this.defaultTooltipText  &&  this.taskTooltip) {
 this.defaultTooltipText  =  this.taskTooltip.innerText;
 }
 this.taskTooltip.innerText  =  this.defaultTooltipText;
 }
}
```

指令保留了所有原始功能，并只导入了 Angular 核心类型和所需的任务类型。现在让我们来看一下`TaskIconsComponent`：

```ts
import { Component, Input, OnInit } from '@angular/core';
import { Task } from './task.model';

@Component({
 selector: 'task-icons',
 template: `
 <img *ngFor="let icon of icons"
 src="/app/shared/assets/img/pomodoro.png"
 width="{{size}}">`
})
export class TaskIconsComponent implements OnInit {
 @Input() task: Task;
 @Input() size: number;
 icons: Object[] = [];

 ngOnInit() {
 this.icons.length = this.task.noRequired;
 this.icons.fill({ name : this.task.name });
 }
}
```

到目前为止一切顺利。现在，让我们转到`TasksComponent`。这将包括：

+   组件文件`tasks.component.ts`，其中用 TypeScript 描述了逻辑

+   CSS 文件`tasks.component.css`，其中定义了样式

+   模板文件`tasks.component.html`，其中定义了标记

从 CSS 文件开始，它将如下所示：

```ts
// app/task/tasks.component.css

h3, p {
 text-align: center;
}

.table {
 margin: auto;
 max-width: 860px;
}
```

继续 HTML 标记：

```ts
// app/task/tasks.component.html

<div  class="container text-center"> <h3>
 One point = 25 min, {{ queued | i18nPlural: queueHeaderMapping }} 
 for today
 <span  class="small" *ngIf="queued > 0">
 (Estimated time : {{ queued * timerMinutes | formattedTime }})
 </span>
 </h3>
 <p>
 <span  *ngFor="let queuedTask of tasks | queuedOnly: true"> <task-icons
 [task]="queuedTask" [taskTooltip]="tooltip"
 size="50">
 </task-icons>
 </span>
 </p>
 <p  #tooltip  [hidden]="queued === 0">
 Mouseover for details
 </p>
 <h4>Tasks backlog</h4>
 <table  class="table">
 <thead>
 <tr>
 <th>Task ID</th>
 <th>Task name</th>
 <th>Deliver by</th>
 <th>Points required</th>
 <th>Actions</th>
 </tr>
 </thead>
 <tbody>
 <tr  *ngFor="let task of tasks; let i = index">
 <th  scope="row">{{ (i+1) }}
 <span  *ngIf="task.queued"  class="label label-info">
 Queued</span>
 </th>
 <td>{{ task.name | slice:0:35 }}
 <span  [hidden]="task.name.length < 35">...</span>
 </td>
 <td>{{ task.deadline | date: 'fullDate' }}
 <span  *ngIf="task.deadline < today"  class="label label-danger">
 Due</span>
 </td>
 <td  class="text-center">{{ task.noRequired }}</td>
 <td>
 <button  type="button"  class="btn btn-default btn-xs"  [ngSwitch]="task.queued"  (click)="toggleTask(task)">
 <ng-template  [ngSwitchCase]="false">
 <i  class="glyphicon glyphicon-plus-sign"></i>
 Add
 </ng-template>
 <ng-template  [ngSwitchCase]="true">
 <i  class="glyphicon glyphicon-minus-sign"></i>
 Remove
 </ng-template>
 <ng-template  ngSwitchDefault>
 <i  class="glyphicon glyphicon-plus-sign"></i>
 Add
 </ng-template>
 </button>
 </td>
 </tr>
 </tbody>
 </table>
</div>
```

请花一点时间查看应用于外部组件文件的命名约定，文件名与组件自身匹配，以便在上下文文件夹内的扁平结构中识别哪个文件属于什么。还请注意我们如何从模板中移除了主位图，并用名为`timerMinutes`的变量替换了硬编码的时间持续。这个变量在绑定表达式中计算完成所有排队任务的时间估计。我们将看到这个变量是如何在以下组件类中填充的：

```ts
// app/task/tasks.component.ts

import { Component, OnInit } from  '@angular/core'; import { TaskService } from  './task.service'; import { Task } from  "./task.model"; import { SettingsService } from  "../core/settings.service"; @Component({
  selector:  'tasks', styleUrls: ['tasks.component.css'], templateUrl:  'tasks.component.html' })
export  class  TasksComponent  implements  OnInit { today:  Date;
 tasks:  Task[];
 queued:  number;
 queueHeaderMapping:  any;
 timerMinutes:  number; constructor( private  taskService:  TaskService,
 private  settingsService:  SettingsService) {
 this.tasks  =  this.taskService.taskStore;
 this.today  =  new  Date();
 this.queueHeaderMapping  =  this.settingsService.pluralsMap.tasks;
 this.timerMinutes  =  this.settingsService.timerMinutes;
 }

 ngOnInit():  void  { this.updateQueued(); }

 toggleTask(task:  Task):  void  { task.queued  =  !task.queued;
 this.updateQueued();
 }

 private  updateQueued():  void  { this.queued  =  this.tasks
 .filter((Task:  Task)  =>  Task.queued)
 .reduce((no:  number,  queuedTask:  Task)  =>  {
 return  no  +  queuedTask.noRequired;
 },  0);
 }
}
```

`TasksComponent`的实现有几个值得强调的方面。首先，我们可以在组件中注入`TaskService`和`SettingsService`，利用 Angular 的 DI 系统。这些依赖项可以直接从构造函数中注入访问器，立即成为私有类成员。然后从绑定的服务中填充任务数据集和时间持续时间。

现在让我们将所有这些构造添加到`TaskModule`中，也就是文件`task.module.ts`，并导出所有指令或组件。然而，值得注意的是，我们这样做是因为我们认为所有这些构造可能需要在应用的其他地方引用。我强烈建议您认真考虑在`exports`关键字中放什么，不要放什么。您的默认立场应该是尽量少地进行导出：

```ts
import { NgModule } from '@angular/core';
@NgModule({
  declarations: [TasksComponent, TaskIconsComponent, TasksTooltipDirective],
  exports: [TasksComponent],
 providers: [TaskService]
 // the rest omitted for brevity
})
```

我们现在已经将构造添加到`declarations`关键字中，以便模块知道它们，还有`exports`关键字，以便导入我们的`TaskModule`的其他模块能够使用它们。下一个任务是设置我们的`AppComponent`，或者也称为根组件。

# 定义顶级根组件

准备好所有功能上下文后，现在是时候定义顶级根组件了，它将作为整个应用程序的启动组件，以树形层次结构的一簇组件展开。根组件通常具有最少的实现。主要子组件最终会演变成子组件的分支。

以下是根组件模板的示例。这是您的应用程序将驻留在其中的主要可视组件。在这里，定义应用程序标题、菜单或用于路由的视口是有意义的。

```ts
//app/app.component.ts

import { Component } from '@angular/core';

@Component({
 selector: 'app',
 template: `
 <nav class="navbar navbar-default navbar-static-top">
 <div class="container">
 <div class="navbar-header">
 <strong class="navbar-brand">My App</strong>
 </div>
 </div>
 </nav>
 <tasks></tasks>
 `
})
export class AppComponent {}
```

之前已经提到过，但值得重复。我们在`app.component.ts`文件中使用的任何构造都不属于`AppModule`，都需要被导入。从技术上讲，被导入的是这些构造所属的模块。您还需要确保这些构造通过在所述模块的`exports`关键字中提到而得到适当的暴露。通过前面的根组件，我们可以看到在`app.component.ts`的模板中使用了两个不同的组件，即`<timer-widget>`和`<pomodoro-tasks>`。这两个组件属于不同的模块，第一个组件属于`TimerModule`，第二个组件属于`TaskModule`。这意味着`AppModule`需要导入这两个模块才能编译。因此，`app.module.ts`应该如下所示：

```ts
import { NgModule } from '@angular/core';
import { TimerModule } from './timer/timer.module';
import { TasksModule } from './tasks/tasks.module';

@NgModule({
 imports: [ TimerModule, TasksModule ]
 // omitted for brevity
})
export class AppModule {}
```

# 总结

本章确实为您从现在开始将在 Angular 上构建的所有优秀应用奠定了基础。实际上，Angular 依赖管理的实现是这个框架的一大亮点，也是一个节省时间的工具。基于组件树的应用架构不再是什么高深的技术，我们在构建其他框架（如 AngularJS 和 React）中的 Web 软件时在某种程度上也遵循了这种模式。

本章结束了我们对 Angular 核心及其应用架构的探索，建立了我们在这个新的令人兴奋的框架上构建应用时将遵循的标准。

在接下来的章节中，我们将专注于非常具体的工具和模块，这些工具和模块可以帮助我们解决日常问题，从而打造我们的 Web 项目。我们将看到如何使用 Angular 开发更好的 HTTP 网络客户端。


# 第七章：使用 Angular 进行异步数据服务

连接到数据服务和 API，并处理异步信息是我们作为开发人员在日常生活中的常见任务。在这方面，Angular 为其热情的开发人员提供了无与伦比的工具集，帮助他们消费、消化和转换从数据服务中获取的各种数据。

有太多的可能性，需要一本整书来描述你可以通过连接到 API 或通过 HTTP 异步地从文件系统中消费信息所能做的一切。在本书中，我们只是浅尝辄止，但本章涵盖的关于 HTTP API 及其伴随的类和工具的见解将为您提供一切所需，让您的应用程序在短时间内连接到 HTTP 服务，而您可以根据自己的创造力来发挥它们的全部潜力。

在本章中，我们将：

+   看看处理异步数据的不同策略

+   介绍 Observables 和 Observers

+   讨论函数式响应式编程和 RxJS

+   审查 HTTP 类及其 API，并学习一些不错的服务模式

+   了解 Firebase 以及如何将其连接到您的 Angular 应用程序

+   通过实际的代码示例来看待前面提到的所有要点

# 处理异步信息的策略

从 API 中获取信息是我们日常实践中的常见操作。我们一直在通过 HTTP 获取信息——当通过向认证服务发送凭据来对用户进行身份验证时，或者在我们喜爱的 Twitter 小部件中获取最新的推文时。现代移动设备引入了一种无与伦比的消费远程服务的方式，即推迟请求和响应消费，直到移动连接可用。响应速度和可用性变得非常重要。尽管现代互联网连接速度超快，但在提供此类信息时总会涉及响应时间，这迫使我们建立机制以透明地处理应用程序中的状态，以便最终用户使用。

这并不局限于我们需要从外部资源消费信息的情景。

# 异步响应-从回调到承诺

有时，我们可能需要构建依赖于时间作为某个参数的功能，并且需要引入处理应用程序状态中这种延迟变化的代码模式。

针对所有这些情况，我们一直使用代码模式，比如回调模式，触发异步操作的函数期望在其签名中有另一个函数，该函数在异步操作完成后会发出一种通知，如下所示：

```ts
function  notifyCompletion() {
 console.log('Our asynchronous operation has been completed'); }

function  asynchronousOperation(callback) {
 setTimeout(() => { callback(); }, 5000); }

asynchronousOperation(notifyCompletion);
```

这种模式的问题在于，随着应用程序的增长和引入越来越多的嵌套回调，代码可能变得相当混乱和繁琐。为了避免这种情况，`Promises`引入了一种新的方式来构想异步数据管理，通过符合更整洁和更稳固的接口，不同的异步操作可以在同一级别链接甚至可以从其他函数中分割和返回。以下代码介绍了如何构造`Promise`：

```ts
function getData() {
 return new Promise((resolve, reject) => {
 setTimeout(() => { 
 resolve(42); 
 }, 3000);
 })
}

getData().then((data) => console.log('Data',data)) // 42
```

前面的代码示例可能有点冗长，但它确实为我们的函数提供了更具表现力和优雅的接口。至于链式数据，我们需要了解我们要解决的问题。我们正在解决一种称为回调地狱的东西，看起来像这样：

```ts
getData(function(data){
 getMoreData(data, function(moreData){
 getEvenMoreData(moreData, function(evenMoreData) {
 // done here
 });
 });
});
```

如前面的代码所示，我们有一个情况，即在执行下一个异步调用之前，我们依赖于先前的异步调用和它带回的数据。这导致我们不得不在回调中执行一个方法，然后在回调中执行另一个方法，依此类推。你明白了吧——代码很快就会变得很糟糕，也就是所谓的*回调地狱*。继续讨论链式异步调用的主题，链式是解决*回调地狱*的答案，`Promises`允许我们像这样链接它们：

```ts
getData()
 .then(getMoreData)
 .then(getEvenMoreData);

function getData() { 
 return new Promise(resolve) => resolve('data'); 
}

function getMoreData(data) {
 return new Promise((resolve, reject) => resolve('more data'));
}

function getEvenMoreData(data) {
 return new Promise((resolve, reject) => resolve('even more data'));
}
```

在前面的代码中，`.then()`方法调用的链接显示了我们如何清晰地将一个异步调用排在另一个异步调用之后，并且先前的异步调用已经将其结果输入到即将到来的`async`方法中。

因此，`Promises`以其强大的编码能力风靡编程领域，似乎没有开发人员会质疑它们为游戏带来的巨大价值。那么，为什么我们需要另一种范式呢？嗯，因为有时我们可能需要产生一个响应输出，该输出遵循更复杂的处理过程，甚至取消整个过程。这不能通过`Promises`来实现，因为它们一旦被实例化就会被触发。换句话说，`Promises`不是懒惰的。另一方面，在异步操作被触发但尚未完成之前取消它的可能性在某些情况下可能非常方便。`Promises`只允许我们解决或拒绝异步操作，但有时我们可能希望在达到那一点之前中止一切。此外，`Promises`表现为一次性操作。一旦它们被解决，我们就不能期望收到任何进一步的信息或状态变化通知，除非我们从头开始重新运行一切。此外，我们有时需要更主动地实现异步数据处理。这就是 Observable 出现的地方。总结一下 Promises 的限制：

+   它们无法被取消

+   它们会立即执行

+   它们只是一次性操作；没有简单的重试方法

+   它们只会响应一个值

# Observable 简而言之

Observable 基本上是一个异步事件发射器，通知另一个元素，称为观察者，状态已经改变。为了做到这一点，Observable 实现了所有需要产生和发射这样的异步事件的机制，并且可以在任何时候被触发和取消，无论它是否已经发出了预期的数据事件。

这种模式允许并发操作和更高级的逻辑，因为订阅 Observable 异步事件的观察者将会反应 Observable 的状态变化。

这些订阅者，也就是我们之前提到的观察者，会一直监听 Observable 中发生的任何事情，直到 Observable 被处理掉，如果最终发生的话。与此同时，信息将在整个应用程序中更新，而不会触发例行程序。

我们可能可以在一个实际的例子中更透明地看到所有这些。让我们重新设计我们在评估基于 Promise 的异步操作时涵盖的示例，并用`setInterval`命令替换`setTimeout`命令：

```ts
function notifyCompletion() {
 console.log('Our asynchronous operation has been completed');
}

function asynchronousOperation() {
 let promise = new Promise((resolve, reject) => {
 setInterval(resolve, 2000); });

 return promise;
}

asynchronousOperation().then(notifyCompletion);
```

复制并粘贴上述片段到浏览器的控制台窗口，看看会发生什么。文本“我们的异步操作已经完成”将在 2 秒后只显示一次，并且不会再次呈现。承诺自行解决，整个异步事件在那一刻终止。

现在，将浏览器指向在线 JavaScript 代码 playground，比如 JSBIN（[`jsbin.com/`](https://jsbin.com/)），并创建一个新的代码片段，只启用 JavaScript 和 Console 选项卡。然后，确保您从“添加库”选项下拉菜单中添加 RxJS 库（我们将需要这个库来创建 Observables，但不要惊慌；我们将在本章后面介绍这个库），并插入以下代码片段：

```ts
let observable$ = Rx.Observable.create(observer => {
 setInterval(() => {
 observer.next('My async operation');
 }, 2000);
});

observable$.subscribe(response => console.log(response));
```

运行它，并期望在右窗格上出现一条消息。2 秒后，我们将看到相同的消息出现，然后再次出现。在这个简单的例子中，我们创建了一个`observable`，然后订阅了它的变化，将其发出的内容（在这个例子中是一个简单的消息）作为一种推送通知输出到控制台。

Observable 返回一系列事件，我们的订阅者会及时收到这些事件的通知，以便他们可以相应地采取行动。这就是 Observable 的魔力所在——Observable 不执行异步操作并终止（尽管我们可以配置它们这样做），而是开始一系列连续的事件，我们可以订阅我们的订阅者。

如果我们注释掉最后一行，什么也不会发生。控制台窗格将保持沉默，所有的魔法将只在我们订阅我们的源对象时开始。

然而，这还不是全部。在这些事件到达订阅者之前，这个流可以成为许多操作的主题。就像我们可以获取一个集合对象，比如数组，并对其应用`map()`或`filter()`等函数方法来转换和操作数组项一样，我们也可以对我们的 Observable 发出的事件流进行相同的操作。这就是所谓的响应式函数编程，Angular 充分利用这种范式来处理异步信息。

# 在 Angular 中的响应式函数编程

Observable 模式是我们所知的响应式函数编程的核心。基本上，响应式函数脚本的最基本实现涵盖了我们需要熟悉的几个概念：

+   可观察对象

+   观察者

+   时间线

+   一系列具有与对象集合相同行为的事件

+   一组可组合的操作符，也称为响应式扩展

听起来令人生畏？其实不是。相信我们告诉你，到目前为止你所经历的所有代码比这复杂得多。这里的重大挑战是改变你的思维方式，学会以一种反应式的方式思考，这是本节的主要目标。

简而言之，我们可以说，响应式编程涉及将异步订阅和转换应用于事件的 Observable 流。我们可以想象你现在的无表情，所以让我们组合一个更具描述性的例子。

想想交互设备，比如键盘。键盘上有用户按下的按键。用户按下每一个按键都会触发一个按键事件。该按键事件包含大量元数据，包括但不限于用户在特定时刻按下的特定按键的数字代码。当用户继续按键时，会触发更多的**keyUp**事件，并通过一个虚拟时间线传输。keyUp 事件的时间线应该如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-2e/img/980af034-ac9f-4795-bf54-820c5e6674c8.png)

从前面的 keyUps 时间线中可以看出，这是一系列连续的数据，其中 keyUp 事件可以在任何时候发生；毕竟，用户决定何时按下这些按键。还记得我们写的 Observable 代码，包含`setTimeout`吗？那段代码能够告诉一个概念观察者，每隔 2 秒就应该发出另一个值。那段代码和我们的 keyUps 有什么区别？没有。嗯，我们知道定时器间隔触发的频率，而对于 keyUps，我们并不知道，因为这不在我们的控制之中。但这真的是唯一的区别，这意味着 keyUps 也可以被视为一个 Observable：

```ts
let key = document.getElementId('.search'); 
/* 
we assume there exist a button in the DOM like this 
<input class="search" placeholder="searchfor"></input>
*/

let stream = Rx.Observable.fromEvent(key, 'keyUp');
stream.subscribe((data) => console.log('key up happened', data))
```

所以，我真正告诉你的是，超时以及 keyUps 可以被视为同一个概念，即 Observable。这样更容易理解所有异步事物。然而，我们还需要另一个观察，即无论发生什么异步概念，它都是以列表的方式发生的。

尽管时间可能不同，但它仍然是一系列事件，就像一个列表。列表通常有一堆方法来投影、过滤或以其他方式操作它的元素，猜猜，Observable 也可以。列表可以执行这样的技巧：

```ts
let mappedAndFiltered = list
 .map(item => item + 1)
 .filter(item > 2);
```

因此，Observables 可以如下：

```ts
let stream = Rx.Observable
 .create(observer => {
 observer.next(1);
 observer.next(2);
 })
 .map(item => item + 1)
 .filter(item > 2);
```

在这一点上，区别只是命名不同。对于列表，`.map()`和`.filter()`被称为方法。对于 Observable，相同的方法被称为 Reactive Extensions 或操作符。想象一下，在这一点上，`keyUps`和超时可以被描述为 Observables，并且我们有操作符来操作数据。现在，更大的飞跃是意识到任何异步的东西，甚至是 HTTP 调用，都可以被视为 Observables。这意味着我们突然可以混合和匹配任何异步的东西。这使得一种称为**丰富组合**的东西成为可能。无论异步概念是什么，它和它的数据都可以被视为一个流，你是一个可以按照自己的意愿来弯曲它的巫师。感到有力量——你现在可以将你的应用程序转变为一个反应式架构。

# RxJS 库

如前所述，Angular 依赖于 RxJS，这是 ReactiveX 库的 JavaScript 版本，它允许我们从各种情景中创建 Observables 和 Observable 序列，比如：

+   交互事件

+   承诺

+   回调函数

+   事件

在这个意义上，响应式编程并不旨在取代承诺或回调等异步模式。相反，它也可以利用它们来创建 Observable 序列。

RxJS 提供了内置支持，用于转换、过滤和组合生成的事件流的广泛的可组合操作符。其 API 提供了方便的方法来订阅观察者，以便我们的脚本和组件可以相应地对状态变化或交互输入做出响应。虽然其 API 如此庞大，以至于详细介绍超出了本书的范围，但我们将重点介绍其最基本的实现，以便您更好地理解 Angular 如何处理 HTTP 连接。

在深入研究 Angular 提供的 HTTP API 之前，让我们创建一个简单的 Observable 事件流的示例，我们可以用 Reactive Extensions 来转换，并订阅观察者。为此，让我们使用前一节中描述的情景。

我们设想用户通过键盘与我们的应用程序进行交互，可以将其转化为按键的时间线，因此成为一个事件流。回到 JSBIN，删除 JavaScript 窗格的内容，然后写下以下片段：

```ts
let keyboardStream$ = Rx.Observable
 .fromEvent(document, 'keyup')
 .map(x => x.which);
```

前面的代码相当自描述。我们利用`Rx.Observable`类及其`fromEvent`方法来创建一个事件发射器，该发射器流式传输在文档对象范围内发生的`keyup`事件。每个发射的事件对象都是一个复杂对象。因此，我们通过将事件流映射到一个新流上，该新流仅包含与每次按键对应的键码，来简化流式传输的对象。`map`方法是一种响应式扩展，具有与 JavaScript 中的`map`函数方法相同的行为。这就是为什么我们通常将这种代码风格称为响应式函数式编程。

好了，现在我们有了一个数字按键的事件流，但我们只对观察那些通知我们光标键击中的事件感兴趣。我们可以通过应用更多的响应式扩展来从现有流构建一个新流。因此，让我们用`keyboardStream`过滤这样一个流，并仅返回与光标键相关的事件。为了清晰起见，我们还将这些事件映射到它们的文本对应项。在前面的片段后面添加以下代码块：

```ts
let cursorMovesStream$ = keyboardStream
 .filter(x => {
 return  x > 36 && x < 41;
 })
 .map(x => {
 let direction;
 switch(x) {
 case 37:
 direction = 'left';
 break;
 case 38:
 direction = 'up';
 break;
 case 39:
 direction = 'right';
 break;
 default:
 direction = 'down';
 }
 return direction;
 });
```

我们本可以通过将`filter`和`map`方法链接到`keyboardStream` Observable 来一次性完成所有操作，然后订阅其输出，但通常最好分开处理。通过以这种方式塑造我们的代码，我们有一个通用的键盘事件流，以后可以完全不同的用途重复使用。因此，我们的应用程序可以扩展，同时保持代码占用空间最小化。

既然我们提到了订阅者，让我们订阅我们的光标移动流，并将`move`命令打印到控制台。我们在脚本的末尾输入以下语句，然后清除控制台窗格，并单击输出选项卡，以便我们可以在上面输入代码，以便我们可以尝试不同的代码语句：

```ts
cursorMovesStream$.subscribe(e => console.log(e));
```

单击输出窗格的任意位置将焦点放在上面，然后开始输入随机键盘键和光标键。

你可能想知道我们如何将这种模式应用到从 HTTP 服务中获取信息的异步场景中。基本上，你到目前为止已经习惯了向 AJAX 服务提交异步请求，然后通过回调函数处理响应或者通过 promise 进行处理。现在，我们将通过返回一个 Observable 来处理调用。这个 Observable 将在流的上下文中作为事件发出服务器响应，然后通过 Reactive Extensions 进行更好地处理响应。

# 介绍 HTTP API

现在，在我们深入描述 Angular 框架在`HttpClient`服务实现方面给我们的东西之前，让我们谈谈如何将`XmlHttpRequest`包装成一个 Observable。为了做到这一点，我们首先需要意识到有一个合同需要履行，以便将其视为成功的包装。这个合同由以下内容组成：

+   使用`observer.next(data)`来发出任何到达的数据

+   当我们不再期望有更多的数据时，我们应该调用`observer.complete()`

+   使用`observer.error(error)`来发出任何错误

就是这样；实际上非常简单。让我们看看`XmlHttpRequest`调用是什么样子的：

```ts
const request = new XMLHttpRequest();

request.onreadystatechange = () => {
 if(this.readyState === 4 and this.state === 200) {
 // request.responseText
 } else {
 // error occurred here
 }
}

request.open("GET", url);
request.send();
```

好的，所以我们有一个典型的回调模式，其中`onreadystatechange`属性指向一个方法，一旦数据到达就会被调用。这就是我们需要知道的所有内容来包装以下代码，所以让我们来做吧：

```ts
let stream$ = Rx.Observable.create(observer => {
 let request = new XMLHttpRequest();
 request.onreadystatechange = () => {
 if(this.readyState === 4 && this.state === 200) {
 observer.next( request.responseText )
 observer.complete();
 } else {
 observer.error( request.responseText ) 
 }
 }
})
```

就是这样，包装完成了；你现在已经构建了自己的 HTTP 服务。当然，这还不够，我们还有很多情况没有处理，比如 POST、PUT、DELETE、缓存等等。然而，重要的是让你意识到 Angular 中的 HTTP 服务为你做了所有繁重的工作。另一个重要的教训是，将任何类型的异步 API 转换为与我们其他异步概念很好契合的 Observable 是多么容易。所以，让我们继续使用 Angular 的 HTTP 服务实现。从这一点开始，我们将使用`HttpClient`服务。

`HttpClient`类提供了一个强大的 API，它抽象了处理通过各种 HTTP 方法进行异步连接所需的所有操作，并以一种简单舒适的方式处理响应。它的实现经过了很多精心的考虑，以确保程序员在开发利用这个类连接到 API 或数据资源的解决方案时感到轻松自在。

简而言之，`HttpClient`类的实例（已经作为`Injectable`资源实现，并且可以在我们的类构造函数中作为依赖提供者注入）公开了一个名为`request()`的连接方法，用于执行任何类型的 HTTP 连接。Angular 团队为最常见的请求操作（如 GET、POST、PUT 以及每个现有的 HTTP 动词）创建了一些语法快捷方式。因此，创建一个异步的 HTTP 请求就像这样简单：

```ts
let  request  =  new  HttpRequest('GET', 'jedis.json');
let myRequestStream:Observable<any> = http.request(request);
```

而且，所有这些都可以简化为一行代码：

```ts
let myRequestStream: Observable<any> = http.get('jedis.json');
```

正如我们所看到的，`HttpClient`类的连接方法通过返回一个 Observable 流来操作。这使我们能够订阅观察者到流中，一旦返回，观察者将相应地处理信息，可以多次进行：

```ts
let myRequestStream = http
 .get<Jedi[]>('jedis.json')
  .subscribe(data => console.log(data));
```

在前面的例子中，我们给`get()`方法一个模板化类型，它为我们进行了类型转换。让我们更加强调一下这一点：

```ts
.get<Jedi[]>('jedis.json')
```

这个事实使我们不必直接处理响应对象并执行映射操作将我们的 JSON 转换为 Jedi 对象列表。我们只需要记住我们资源的 URL，并指定一个类型，你订阅的内容就可以立即用于我们服务的订阅。

通过这样做，我们可以根据需要重新发起 HTTP 请求，我们的其余机制将相应地做出反应。我们甚至可以将 HTTP 调用表示的事件流与其他相关调用合并，并组合更复杂的 Observable 流和数据线程。可能性是无限的。

# 处理头部

在介绍`HttpClient`类时，我们提到了`HttpRequest`类。通常情况下，您不需要使用低级别的类，主要是因为`HttpClient`类提供了快捷方法，并且需要声明正在使用的 HTTP 动词（GET、POST 等）和要消耗的 URL。话虽如此，有时您可能希望在请求中引入特殊的 HTTP 头，或者自动附加查询字符串参数到每个请求中，举例来说。这就是为什么这些类在某些情况下会变得非常方便。想象一个使用情况，您希望在每个请求中添加身份验证令牌，以防止未经授权的用户从您的 API 端点中读取数据。

在以下示例中，我们读取身份验证令牌并将其附加为标头到我们对数据服务的请求。与我们的示例相反，我们将`options`哈希对象直接注入到`HttpRequest`构造函数中，跳过创建对象实例的步骤。Angular 还提供了一个包装类来定义自定义标头，我们将在这种情况下利用它。假设我们有一个 API，希望所有请求都包括名为`Authorization`的自定义标头，附加在登录系统时收到的`authToken`，然后将其持久化在浏览器的本地存储层中，例如：

```ts
const authToken = window.localStorage.getItem('auth_token');

let headers = new HttpHeaders();
headers.append('Authorization', `Token ${authToken}`);
let request = new HttpRequest('products.json', { headers: headers });

let authRequest = http.request(request);
```

再次强调，除了这种情况，您很少需要创建自定义请求配置，除非您希望在工厂类或方法中委托请求配置的创建并始终重用相同的`Http`包装器。Angular 为您提供了所有的灵活性，可以在抽象化应用程序时走得更远。

# 处理执行 HTTP 请求时的错误

处理我们请求中引发的错误，通过检查`Response`对象返回的信息实际上非常简单。我们只需要检查其`Boolean`属性的值，如果响应的 HTTP 状态在 2xx 范围之外，它将返回`false`，清楚地表明我们的请求无法成功完成。我们可以通过检查`status`属性来双重检查，以了解错误代码或`type`属性，它可以假定以下值：`basic`，`cors`，`default`，`error`或`opaque`。检查响应标头和`HttpResponse`对象的`statusText`属性将提供有关错误来源的深入信息。

总的来说，我们并不打算在每次收到响应消息时检查这些属性。Angular 提供了一个 Observable 操作符来捕获错误，在其签名中注入我们需要检查的`HttpResponse`对象的先前属性：

```ts
http.get('/api/bio')
.subscribe(bio => this.bio = bio)
.catch(error: Response => Observable.of(error));
```

值得注意的是，我们通过使用`catch()`操作符捕获错误，并通过调用`Observable.of(error)`返回一个新的操作符，让我们的错误作为我们创建的新 Observable 的输入。这对我们来说是一个不会使流崩溃的方法，而是让它继续存在。当然，在更真实的情况下，我们可能不只是创建一个新的 Observable，而是可能记录错误并返回完全不同的东西，或者添加一些重试逻辑。关键是，通过`catch()`操作符，我们有一种捕获错误的方法；如何处理它取决于您的情况。

在正常情况下，您可能希望检查除了错误属性之外的更多数据，除了在更可靠的异常跟踪系统中记录这些信息之外。

# 注入 HttpClient 服务

`HttpClient`服务可以通过利用 Angular 独特的依赖注入系统注入到我们自己的组件和自定义类中。因此，如果我们需要实现 HTTP 调用，我们需要导入`HttpClientModule`并导入`HttpClient`服务：

```ts
// app/biography/biography.module.ts
import { HttpClientModule } from '@angular/common/http';

@NgModule({
  imports: [ HttpClientModule ]
})
export class BiographyModule {}

// app/biography/biography.component.ts

import { Component } from '@angular/core';
import { HttpClient } from '@angular/http';

@Component({
 selector: 'bio',
 template: '<div>{{bio}}</div>'
})
export class BiographyComponent {
 bio: string;

 constructor(private http: HttpClient) {
 const  options  = {}; this.http.get('/api/bio', { ...options, responseType:  'text' }) .catch(err  =>  Observable.of(err)) .subscribe(x  => this.bio= bio)
 }
}
```

在提供的代码中，我们只是按照我们在上一节中指出的`bio`示例进行。请注意我们如何导入`HttpClient`类型，并将其作为依赖项注入到`Biography`构造函数中。

通常，我们需要在应用程序的不同部分执行多个 HTTP 调用，因此通常建议创建一个`DataService`和一个`DataModule`，它包装了`HttpClientModule`和`HttpClient`服务。

以下是创建这样一个`DataService`的示例：

```ts
import {Http} from '@angular/http';
import {Injectable} from '@angular/core';

@Injectable()
export class DataService {
 constructor(private http:HttpClient) {}

 get(url, options?) {}
 post(url, payload, options?) {}
 put(url, payload, options?) {}
 delete(url) {}
}
```

相应的`DataModule`将如下所示：

```ts
import {DataService} from './data.service';
import {HttpModule} from '@angular/http';

@NgModule({
  imports: [HttpClientModule],
 providers: [DataService] 
})
```

如果您想为调用后端添加自己的缓存或授权逻辑，这就是要做的地方。另一种方法是使用`HttpInterceptors`，在本章的即将到来的部分中将提供使用`HttpInterceptors`的示例。

当然，任何想要使用这个`DataModule`的模块都需要导入它，就像这样：

```ts
@NgModule({
  imports: [DataModule],
 declarations: [FeatureComponent]
})
export class FeatureModule {}
```

我们的`FeatureModule`中的任何构造现在都可以注入`DataService`，就像这样：

```ts
import { Component } from '@angular/core';

@Component({})
export class FeatureComponent {
 constructor(private service: DataService) { }
}
```

# 一个真实的案例研究 - 通过 HTTP 提供 Observable 数据

在上一章中，我们将整个应用程序重构为模型、服务、管道、指令和组件文件。其中一个服务是`TaskService`类，它是我们应用程序的核心，因为它提供了我们构建任务列表和其他相关组件所需的数据。

在我们的示例中，TaskService 类包含在我们想要传递的信息中。在实际情况下，您需要从服务器 API 或后端服务中获取该信息。让我们更新我们的示例以模拟这种情况。首先，我们将从 TaskService 类中删除任务信息，并将其包装成一个实际的 JSON 文件。让我们在共享文件夹中创建一个新的 JSON 文件，并用我们在原始 TaskService.ts 文件中硬编码的任务信息填充它，现在以 JSON 格式：

```ts
[{
 "name": "Code an HTML Table",
 "deadline": "Jun 23 2015",
 "pomodorosRequired": 1

}, {
 "name": "Sketch a wireframe for the new homepage",
 "deadline": "Jun 24 2016",
 "pomodorosRequired": 2

}, {
 "name": "Style table with Bootstrap styles",
 "deadline": "Jun 25 2016",
 "pomodorosRequired": 1

}, {
 "name": "Reinforce SEO with custom sitemap.xml",
 "deadline": "Jun 26 2016",
 "pomodorosRequired": 3
}]
```

将数据正确包装在自己的文件中后，我们可以像使用实际后端服务一样从我们的 TaskService 客户端类中使用它。但是，为此我们需要在 main.ts 文件中进行相关更改。原因是，尽管在安装所有 Angular 对等依赖项时安装了 RxJS 包，但反应式功能操作符（例如`map()`）并不会立即可用。我们可以通过在应用程序初始化流的某个步骤中插入以下代码行来一次性导入所有这些内容，例如在`main.ts`的引导阶段：

```ts
import 'rxjs/Rx';
```

然而，这将导入所有反应式功能操作符，这些操作符根本不会被使用，并且会消耗大量带宽和资源。相反，惯例是只导入所需的内容，因此在 main.ts 文件的顶部追加以下导入行：

```ts
import 'rxjs/add/operator/map';
import { bootstrap } from '@angular/platform-browser-dynamic';
import AppModule from './app.module';

bootstrapModule(AppModule);
```

当以这种方式导入反应式操作符时，它会自动添加到 Observable 原型中，然后可以在整个应用程序中使用。应该说，可讳操作符的概念刚刚在 RxJS 5.5 中引入。在撰写本书时，我们刚刚在修补操作员原型的转变中，如上所述，并进入可讳操作符空间。对于感兴趣的读者，请查看这篇文章，其中详细描述了这对您的代码意味着什么。更改并不是很大，但仍然有变化：[`blog.angularindepth.com/rxjs-understanding-lettable-operators-fe74dda186d3`](https://blog.angularindepth.com/rxjs-understanding-lettable-operators-fe74dda186d3)

# 利用 HTTP - 重构我们的 TaskService 以使用 HTTP 服务

所有依赖项都已经就位，现在是重构的时候了

我们的 TaskService.ts 文件。打开服务文件，让我们更新导入语句块：

```ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';

import { Task } from './task.model';
```

首先，我们导入`HttpClient`和`Response`符号，以便稍后可以注释我们的对象。Observable 符号是从 RxJS 库导入的，以便我们可以正确注释我们的异步 HTTP 请求的返回类型。我们还从文件`task.model.ts`导入`Task`作为模型（它是一个接口），如下所示：

```ts
export interface Task {
 name: string;
 deadline: string;
 pomodorosRequired: number;
 queued: boolean;
}
```

我们将通过两个步骤重构此服务：

1.  重写服务以使用 HTTP 服务。

1.  实现存储/反馈模式并给服务一个状态。

# 使用 Angular HTTP 服务

现在，我们将使用 HTTP 服务替换现有的静态数据实现。为此，我们调用 HTTP 服务的`http.get()`方法来获取数据，但我们还需要使用 map 操作符来获得我们可以向外显示的结果：

```ts
import { HttpClient } from '@angular/common/http';
import { Task } from './task.model';

export default class TaskService {
 constructor(private http:HttpClient) {}

 getTasks(): Observable<Task[]> {
 return this.http.get<Task[]>(`tasks.json`)
 }
}
```

要使用先前定义的服务，我们只需要告诉模块关于它。我们通过将其添加到`providers`关键字来实现这一点：

```ts
// app/tasks/task.module.ts

@NgModule({
 imports: [ /* add dependant modules here */ ],
 declarations: [ ./* add components and directives here */ ]
 providers: [TaskService],
})
export class TaskModule {}
```

此后，我们需要在使用者组件中注入`TaskService`并以适当的方式显示它：

```ts
// app/tasks/task.component.ts

@Component({
 template: `
 <div *ngFor="let task of tasks">
 {{ task.name }}
 </div>
 `
})
export class TasksComponent {
 tasks:Task[];
 constructor(private taskService:TaskService){
 this.taskService.getTasks().subscribe( tasks => this.tasks = tasks)
 }
}
```

# 大多数情况下使用有状态的 TaskService

到目前为止，我们已经介绍了如何将 HTTP 服务注入到服务构造函数中，并且已经能够从组件订阅这样的服务。在某些情况下，组件可能希望直接处理数据而不是使用 Observables。实际上，我们大多数情况下都是这样。因此，我们不必经常使用 Observables；HTTP 服务正在利用 Observables，对吧？我们正在谈论组件层。目前，我们在组件内部正在发生这种情况：

```ts
// app/tasks/task.service.ts

@Component({
 template: `
 <div *ngFor="let task of tasks$ | async">
 {{ task.name }}
 </div>
 `
})
export class TaskListComponent {
  tasks$:Observable<Task[]>; 
 constructor(private taskService: TaskService ) {}

 ngOnInit() {
 this.tasks$ = this.taskService.getTasks(); 
 }
} 
```

在这里，我们看到我们将`taskService.getTasks()`分配给一个名为`tasks$`的流。`tasks$`变量末尾的`$`是什么？这是我们用于流的命名约定；让我们尝试遵循任何未来流/可观察字段的命名约定。我们在 Angular 的上下文中将 Observable 和 stream 互换使用，它们的含义是相同的。我们还让`| async`异步管道与`*ngFor`一起处理它并显示我们的任务。

我们可以以更简单的方式做到这一点，就像这样：

```ts
// app/tasks/tas.alt.component.ts

@Component({
 template: `
 <div *ngFor="let task of tasks">
 {{ task.name }}
 </div>
 `
})
export class TaskComponent {
 constructor(private taskService: TaskService ) {}

  get tasks() {
 return this.taskService.tasks;
 } 
} 
```

因此，发生了以下更改：

+   `ngOnInit()`和分配给`tasks$`流的部分被移除了

+   异步管道被移除

+   我们用`tasks`数组替换了`tasks$`流

这还能工作吗？答案在于我们如何定义我们的服务。我们的服务需要暴露一个项目数组，并且我们需要确保当我们从 HTTP 获取到一些数据时，或者当我们从其他地方接收到数据时，比如来自 Web 套接字或类似 Firebase 的产品时，数组会发生变化。

我们刚刚提到了两种有趣的方法，套接字和 Firebase。让我们解释一下它们是什么，以及它们如何与我们的服务相关。Web 套接字是一种利用 TCP 协议建立双向通信的技术，所谓的*全双工连接*。那么，在 HTTP 的背景下提到它为什么有趣呢？大多数情况下，您会有简单的场景，您可以通过 HTTP 获取数据，并且可以利用 Angular 的 HTTP 服务。有时，数据可能来自全双工连接，除了来自 HTTP。

那么 Firebase 呢？Firebase 是谷歌的产品，允许我们在云中创建数据库。正如可以预料的那样，我们可以对数据库执行 CRUD 操作，但其强大之处在于我们可以设置订阅并监听其发生的更改。这意味着我们可以轻松创建协作应用程序，其中许多客户端正在操作相同的数据源。这是一个非常有趣的话题。这意味着您可以快速为您的 Angular 应用程序提供后端，因此，出于这个原因，它值得有自己的章节。它也恰好是本书的下一章。

回到我们试图表达的观点。从理论上讲，添加套接字或 Firebase 似乎会使我们的服务变得更加复杂。实际上，它们并不会。您需要记住的唯一一件事是，当这样的数据到达时，它需要被添加到我们的`tasks`数组中。我们在这里做出的假设是，处理来自 HTTP 服务以及来自 Firebase 或 Web 套接字等全双工连接的任务是有趣的。

让我们看看在我们的代码中涉及 HTTP 服务和套接字会是什么样子。您可以通过使用包装其 API 的库轻松利用套接字。

大多数浏览器原生支持 WebSockets，但仍被认为是实验性的。话虽如此，依然有意义依赖于一个帮助我们处理套接字的库，但值得注意的是，当 WebSockets 变得不再是实验性的时候，我们将不再考虑使用库。对于感兴趣的读者，请查看官方文档[`developer.mozilla.org/en-US/docs/Web/API/WebSockets_API`](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)

有一个这样的库是`socket.io`库；可以通过以下方式安装它：

```ts
npm install socket.io
```

要开始在 Angular 中使用这个，您需要：

1.  导入`socket.io-client`。

1.  通过调用`io(url)`建立连接；这将返回一个套接字，您可以向其添加订阅。

1.  等待包含我们想要在应用程序中显示的有效负载的传入事件。

1.  生成事件并在想要与后端通信时发送可能的有效负载

以下代码将只向您展示如何执行这些步骤。然而，套接字的实现还有更多，比如创建后端。要了解使用 Angular 和`socket.io`的完整示例是什么样子，鼓励感兴趣的读者查看 Torgeir Helgwold 的以下文章：

[`www.syntaxsuccess.com/viewarticle/socket.io-with-rxjs-in-angular-2.0`](http://www.syntaxsuccess.com/viewarticle/socket.io-with-rxjs-in-angular-2.0)

这实际上不是一个 HTTP 主题，这就是为什么我们只显示代码中感兴趣的部分，这是我们将接收数据并将其添加到任务数组中的地方。我们还强调了套接字的设置和拆除。强调是用粗体来做的，如下所示：

```ts
import * as io from 'socket.io-client'**;** export class TaskService {
 subscription;
 tasks:Task[] = [];
 constructor(private http:HttpClient) {
 this.fetchData();

    this.socket = io(this.url**);  // establishing a socket connection** this.socket.on('task', (data) => { 
 // receive data from socket based on the 'task' event happening
 this.tasks = [ ..this.tasks, data ];
 });
 }

 private fetchData() {
 this.subscription = 
 this.http.get<Task[]>('/tasks')
 .subscribe( data => this.tasks = data );
 }

 // call this from the component when component is being destroyed
 destroy() {
    this.socket.removeAllListeners('task');  // clean up the socket
 connection
 } 
}
```

这是一个非常简单的示例，非常适合在模板中显示数据，并在`tasks`数组更改时更新模板。正如您所看到的，如果我们涉及`socket`，那也没关系；我们的模板仍然会被更新。

这种做法还包括另一种情况——两个或更多兄弟组件如何通信？答案很简单：它们使用`TaskService`。如果您希望其他组件的模板得到更新，那么只需更改任务数组的内容，它将反映在 UI 中。以下是此代码：

```ts
@Component({
 template: `
 <div *ngFor="let task of tasks">
 {{ task.name }}
 </div>
 <input [(ngModel)]="newTask" />
 <button (click)="addTask()" ></button>
 ` 
})
export class FirstSiblingComponent {
 newTask: string;

 constructor(private service: TaskService) {}

  get tasks() {
 return this.taskService.tasks;
 }

  addTask() {
 this.service.addTask({ name : this.newTask });
 this.newTask = '';
 }
}
```

这意味着我们还需要向我们的服务添加一个`addTask()`方法，如下所示：

```ts
import * as io from 'socket.io-client'**;** export class TaskService {
 subscription;
 tasks: Task[] = [];
 constructor(private http:Http) {
 this.fetchData();

 this.socket = io(this.url);  // establishing a socket connection

 this.socket.on('task', (data) => { 
 // receive data from socket based on the 'task' event happening
 this.tasks = [ ..this.tasks, data ];
 });
 }

 addTask(task: Task) {
 this.tasks = [ ...this.tasks, task]; 
 }

 private fetchData() {
 this.subscription = 
 this.http.get('/tasks')
 .subscribe(data => this.tasks = data);
 }

 // call this from the component when component is being destroyed
 destroy() {
 this.socket.removeAllListeners('task');  // clean up the socket
 connection
 } 
}
```

另一个组件在设置`taskService`、公开`tasks`属性和操作`tasks`列表方面看起来基本相同。无论哪个组件采取主动通过用户交互更改任务列表，另一个组件都会收到通知。我想强调这种通用方法的工作原理。为了使这种方法起作用，您需要通过组件中的 getter 公开任务数组，如下所示：

```ts
get tasks() {
 return this.taskService.tasks;
}
```

否则，对它的更改将不会被接收。

然而，有一个缺点。如果我们想确切地知道何时添加了一个项目，并且，比如说，基于此显示一些 CSS，那该怎么办？在这种情况下，您有两个选择：

+   在组件中设置套接字连接并在那里监听数据更改。

+   在任务服务中使用行为主题而不是任务数组。来自 HTTP 或套接字的任何更改都将通过`subject.next()`写入主题。如果这样做，那么当发生更改时，您可以简单地订阅该主题。

最后一个选择有点复杂，无法用几句话解释清楚，因此下一节将专门解释如何在数组上使用`BehaviourSubject`。

# 进一步改进-将 TaskService 转变为有状态、更健壮的服务

RxJS 和 Observables 并不仅仅是为了与 Promises 一一对应而到来。RxJS 和响应式编程到来是为了推广一种不同类型的架构。从这样的架构中出现了适用于服务的存储模式。存储模式是确保我们的服务是有状态的，并且可以处理来自 HTTP 以外更多地方的数据。数据可能来自的潜在地方可能包括，例如：

+   HTTP

+   localStorage

+   套接字

+   Firebase

# 在网络连接间歇性中断时处理服务调用

首先，您应该确保如果网络连接中断，应用程序仍然可以正常工作，至少在读取数据方面，您对应用程序用户有责任。对于这种情况，如果 HTTP 响应未能传递，我们可以使用`localStorage`进行回答。然而，这意味着我们需要在我们的服务中编写以下方式工作的逻辑：

```ts
if(networkIsDown) { 
 /* respond with localStorage instead */
} else { 
 /* respond with network call */
}
```

让我们拿出我们的服务，并稍微修改一下以适应离线状态：

```ts
export class TaskService {
 getTasks() {
 this.http .get<Task[]>('/data/tasks.json')  .do( data  => {  localStorage.setItem('tasks', JSON.stringify(data)) })
      .catch(err) => {
 return this.fetchLocalStorage();
 })
 }

 private fetchLocalStorage(){
 let tasks = localStorage.getItem('tasks');
 const tasks = localStorage.getItem('tasks') || [];
    return Observable.of(tasks);
 }
}
```

正如您所看到的，我们做了两件事：

+   我们添加`.do()`运算符来执行副作用；在这种情况下，我们将响应写入`localStorage`

+   我们添加了`catch()`操作符，并响应一个包含先前存储的数据或空数组的新 Observable

用这种方式解决问题没有错，而且在很多情况下，这甚至可能足够好。然而，如果像之前建议的那样，数据从许多不同的方向到达，会发生什么？如果是这种情况，那么我们必须有能力将数据推送到流中。通常，只有观察者可以使用`observer.next()`推送数据。

还有另一个构造，`Subject`。`Subject`具有双重性质。它既能向流中推送数据，也可以被订阅。让我们重写我们的服务以解决外部数据的到达，然后添加`Sock.io`库支持，这样您就会看到它是如何扩展的。我们首先使服务具有状态。诱人的做法是直接编写如下代码：

```ts
export class TaskService {
  tasks: Task[];
 getTasks() {
 this.http .get<Task[]>('/data/tasks.json')  .do( data  => { **this.tasks = mapTasks( data );** localStorage.setItem('tasks', JSON.stringify(data)) })
 .catch(err) => {
 return this.fetchLocalStorage();
 })
 }
}
```

我们建议的前述更改是加粗的，并且包括创建一个`tasks`数组字段，并对到达的数据进行任务字段的赋值。这样做是有效的，但可能超出了我们的需求。

# 引入 store/feed 模式

不过，我们可以做得更好。我们可以更好地做到这一点，因为我们实际上不需要创建那个最后的数组。在这一点上，你可能会想，让我弄清楚一下；你希望我的服务具有状态，但没有后备字段？嗯，有点，而且使用一种称为`BehaviourSubject`的东西是可能的。`BehaviourSubject`具有以下属性：

+   它能够充当`Observer`和`Observable`，因此它可以推送数据并同时被订阅

+   它可以有一个初始值

+   它将记住它上次发出的值

因此，使用`BehaviourSubject`，我们实际上一举两得。它可以记住上次发出的数据，并且可以推送数据，使其在连接到其他数据源（如 Web 套接字）时非常理想。让我们首先将其添加到我们的服务中：

```ts
export class TaskService {
  private internalStore:BehaviourSubject;

 constructor() {
    this.internalStore = new BehaviourSubject([]); // setting initial
 value 
 }

 get store() {
    return this.internalStore.asObservable();
 }

 private fetchTasks(){
 this.http .get<Task[]>('/data/tasks.json')  .map(this.mapTasks) .do(data  => { **this.internalStore.next( data )** localStorage.setItem('tasks', JSON.stringify(data)) })
 .catch( err  => {
 return this.fetchLocalStorage();
 });
 }
}
```

在这里，我们实例化了`BehaviourSubject`，并且可以看到它的默认构造函数需要一个参数，即初始值。我们给它一个空数组。这个初始值是呈现给订阅者的第一件事。从应用程序的角度来看，在等待第一个 HTTP 调用完成时展示第一个值是有意义的。

我们还定义了一个`store()`属性，以确保当我们向外部公开`BehaviourSubject`时，我们将其作为`Observable`。这是防御性编码。因为主题上有一个`next()`方法，允许我们将值推送到其中；我们希望将这种能力从不在我们服务中的任何人身上夺走。我们这样做是因为我们希望确保任何添加到其中的内容都是通过`TaskService`类的公共 API 处理的：

```ts
get store() {
 return this.internalStore.asObservable();
}
```

最后的更改是添加到`.do()`操作符的

```ts
// here we are emitting the data as it arrives
.do(data  => { this.internalStore.next(data)  })
```

这将确保我们服务的任何订阅者始终获得最后发出的数据。在组件中尝试以下代码：

```ts
@Component({})
export class TaskComponent {
 constructor(taskService: TaskService ) {
 taskService.store.subscribe( data => {
 console.log('Subscriber 1', data);
 })

 setTimeout(() => {
 taskService.store
 .subscribe( data => console.log('Subscriber 2', data)); // will get the latest emitted value
 }, 3000)
 } 
}
```

在这一点上，我们已经确保无论何时开始订阅`taskService.store`，无论是立即还是在 3 秒后，如前面的代码所示，我们仍然会获得最后发出的数据。

# 持久化数据

如果我们需要持久化来自组件表单的内容怎么办？那么，我们需要做以下操作：

+   在我们的服务上公开一个`add()`方法

+   进行一个`http.post()`调用

+   调用`getTasks()`以确保它重新获取数据

让我们从更简单的情况开始，从组件中添加任务。我们假设用户已经输入了创建应用程序 UI 中的`Task`所需的所有必要数据。从组件中调用了一个`addTask()`方法，这反过来调用了服务上类似的`addTask()`方法。我们需要向我们的服务添加最后一个方法，并且在该方法中调用一个带有 POST 请求的端点，以便我们的任务得到持久化，就像这样：

```ts
export class TaskService {
 addTask(task) {
 return this.http.post('/tasks', task);
 }
}
```

在这一点上，我们假设调用组件负责在组件上执行各种 CRUD 操作，包括显示任务列表。通过添加任务并持久化它，提到的列表现在将缺少一个成员，这就是为什么有必要对`getTasks()`进行新的调用。因此，如果我们有一个简单的服务，只有一个`getTasks()`方法，那么它将返回一个任务列表，包括我们新持久化的任务，如下所示：

```ts
@Component({})
export class TaskComponent implements OnInit {
 ngOnInit() {
 init();
 }

 private init(){
 this.taskService.getTasks().subscribe( data => this.tasks = data )
 }

 addTask(task) {
 this.taskService.addTask(task).subscribe( data => {
 this.taskService.getTasks().subscribe(data => this.tasks = data)
 });
 }
}
```

好的，如果我们有一个简化的`TaskService`，缺少我们漂亮的存储/反馈模式，那么这将起作用。不过，有一个问题——我们在使用 RxJS 时出错了。我们所说的错误是什么？每次我们使用`addTask()`时，我们都建立了一个新的订阅。

你想要的是以下内容：

+   订阅任务流

+   清理阶段，订阅被取消订阅

让我们先解决第一个问题；一个流。我们假设我们需要使用我们的`TaskService`的有状态版本。我们将组件代码更改为这样：

```ts
@Component({})
export class TaskComponent implements OnInit{
 private subscription;

 ngOnInit() {
 this.subscription = this.taskService.store.subscribe( data => this.tasks = data );
 }

 addTask(task) {
 this.taskService.addTask( task ).subscribe( data => {
 // tell the store to update itself? 
 });
 }
}
```

正如你所看到的，我们现在订阅了 store 属性，但是我们已经将`taskService.addTask()`方法内的重新获取行为移除，改为这样：

```ts
this.taskService.addTask(task).subscribe( data => {
 // tell the store to update itself? 
})
```

我们将把这个刷新逻辑放在`taskService`中，像这样：

```ts
export class TaskService {
 addTask(task) {
 this.http
 .post('/tasks', task)
 .subscribe( data => { this.fetchTasks(); })
 }
}
```

现在，一切都按预期运行。我们在组件中有一个订阅任务流，刷新逻辑被我们通过调用`fetchTasks()`方法推回到服务中。

我们还有一项业务要处理。我们如何处理订阅，更重要的是，我们如何处理取消订阅？记得我们如何向组件添加了一个`subscription`成员吗？那让我们完成了一半。让我们为我们的组件实现一个`OnDestroy`接口并实现这个约定：

```ts
@Component({
 template : `
 <div *ngFor="let task of tasks">
 {{ task.name }}
 </div>
 `
})
export class TaskComponent implements OnInit, implements OnDestroy{
 private subscription;
 tasks: Task[];

 ngOnInit() {
 this.subscription = this.taskService.store.subscribe( data => this.tasks = data );
 }

   ngOnDestroy() { 
 this.subscription.unsubscribe();
 }

 addTask(task) {
 this.taskService.addTask( task );
 }
} 
```

通过实现`OnDestroy`接口，我们有一种方法在订阅上调用`unsubscribe()`，我们在`OnDestroy`接口让我们实现的`ngOnDestroy()`方法中这样做。因此，我们为自己清理了一下。

实现`OnInit`接口和`OnDestroy`接口的模式是在创建组件时应该做的事情。在`ngOnInit()`方法中设置订阅和组件需要的其他任何内容是一个良好的实践，相反，在`ngOnDestroy()`方法中取消订阅和其他类型的构造是一个良好的实践。

然而，还有一种更好的方法，那就是使用`async`管道。`async`管道将消除保存订阅引用并调用`.unsubscribe()`的需要，因为这在`async`管道内部处理。我们将在本章的后续部分更多地讨论`async`管道，但是这是组件利用它而不是`OnDestroy`接口的样子：

```ts
@Component({
 template: `
 <div *ngFor="let task of tasks | async">
 {{ task.name }}
 </div>
 `
})
export class TaskComponent implements OnInit{
 get tasks() {
 return this.taskService.store; 
 }

 addTask(task) {
 this.taskService.addTask( task );
 }
} 
```

我们的代码刚刚删除了很多样板代码，最好的部分是它仍然在工作。只要你的所有数据都在一个组件中显示，那么`async`管道就是最好的选择；然而，如果你获取的数据是在其他服务之间共享或者作为获取其他数据的先决条件，那么使用`async`管道可能就不那么明显了。

最重要的是，最终你要求使用这些技术之一。

# 刷新我们的服务

我们几乎描述完了我们的`TaskService`，但还有一个方面我们需要涵盖。我们的服务没有考虑到第三方可能对终端数据库进行更改。如果我们远离组件或重新加载整个应用程序，我们将看到这些更改。如果我们想在更改发生时看到这些更改，我们需要有一些行为告诉我们数据何时发生了变化。诱人的是想到一个轮询解决方案，只是在一定的时间间隔内刷新数据。然而，这可能是一个痛苦的方法，因为我们获取的数据可能包含一个庞大的对象图。理想情况下，我们只想获取真正发生变化的数据，并将其修改到我们的应用程序中。在宽带连接时代，为什么我们如此关心这个问题？这是问题所在——一个应用程序应该能够在移动应用上使用，速度和移动数据合同可能是一个问题，所以我们需要考虑移动用户。以下是一些我们应该考虑的事情：

+   数据的大小

+   轮询间隔

如果数据的预期大小真的很大，那么向一个端点发出请求并询问它在一定时间后发生了什么变化可能是一个好主意；这将大大改变有效载荷的大小。我们也可以只要求返回一个部分对象图。轮询间隔是另一个需要考虑的事情。我们需要问自己：我们真的需要多久才能重新获取所有数据？答案可能是从不。

假设我们选择一种方法，我们要求获取增量（在一定时间后的变化）；它可能看起来像下面这样：

```ts
constructor(){
 lastFetchedDate;
 INTERVAL_IN_SECONDS = 30;

 setInterval(() => {
 fetchTasksDelta( lastFetchedDate );
 lastFetchedDate = DateTime.now;
 }, this.INTERVAL_IN_SECONDS * 1000)
}
```

无论你采取什么方法和考虑，记住并不是所有用户都在宽带连接上。值得注意的是，越来越多的刷新场景现在 tend to be solved with Web Sockets，所以你可以在服务器和客户端之间创建一个开放的连接，服务器可以决定何时向客户端发送一些新数据。我们将把这个例子留给你，亲爱的读者，使用 Sockets 进行重构。

我们现在有一个可以：

+   无状态

+   能够处理离线连接

+   为其他数据服务提供服务，比如 sockets

+   能够在一定的时间间隔内刷新数据

所有这些都是通过`BehaviourSubject`和`localStorage`实现的。不要把 RxJS 只当作`Promise`的附加功能，而是使用它的构造和操作符来构建健壮的服务和架构模式。

# HttpInterceptor

拦截器是一段可以在您的 HTTP 调用和应用程序的其余部分之间执行的代码。它可以在您即将发送请求时以及接收响应时挂钩。那么，我们用它来做什么呢？应用领域有很多，但有些可能是：

+   为所有出站请求添加自定义令牌

+   将所有传入的错误响应包装成业务异常；这也可以在后端完成

+   重定向请求到其他地方

`HttpInterceptor`是从`@angular/common/http`导入的一个接口。要创建一个拦截器，您需要按照以下步骤进行：

1.  导入并实现`HttpInterceptor`接口

1.  在根模块提供程序中注册拦截器

1.  编写请求的业务逻辑

# 创建一个模拟拦截器

让我们采取所有先前提到的步骤，并创建一个真正的拦截器服务。想象一下，对某个端点的所有调用都被定向到一个 JSON 文件或字典。这样做将创建一个模拟行为，您可以确保所有出站调用都被拦截，并在它们的位置上，您用适当的模拟数据回应。这将使您能够以自己的节奏开发 API，同时依赖于模拟数据。让我们深入探讨一下这种情况。

让我们首先创建我们的服务。让我们称之为`MockInterceptor`。它将需要像这样实现`HttpInterceptor`接口：

```ts
import { HttpInterceptor } from '@angular/common/http'; export  class  MockInterceptor  implements  **HttpInterceptor** {  constructor() { } intercept(request:  HttpRequest<any>, next:  HttpHandler):  Observable<HttpEvent<any>> { }
}
```

为了履行接口的约定，我们需要有一个接受请求和`next()`处理程序作为参数的`intercept()`方法。此后，我们需要确保从`intercept()`方法返回`HttpEvent`类型的 Observable。我们还没有在那里写任何逻辑，所以这实际上不会编译。让我们在`intercept()`方法中添加一些基本代码，使其工作，像这样：

```ts
import { HttpInterceptor } from '@angular/common/http'; export  class  MockInterceptor  implements  HttpInterceptor {  constructor() { } intercept(request:  HttpRequest<any>, next:  HttpHandler):  Observable<HttpEvent<any>> { return  next.handle(request**);** }
}
```

我们添加了对`next.handle(request)`的调用，这意味着我们接受传入的请求并将其传递到管道中。这段代码并没有做任何有用的事情，但它可以编译，并且教会我们，无论我们在`intercept()`方法中做什么，我们都需要使用请求对象调用`next.handle()`。

让我们回到最初的目标——模拟出站请求。这意味着我们想要用`我们的`请求替换出站请求。为了实现我们的模拟行为，我们需要做以下事情：

+   调查我们的出站请求，并确定我们是要用模拟来回应还是让它通过

+   如果我们想要模拟它，构造一个模拟响应

+   使用`providers`为一个模块注册我们的新拦截器

让我们在`intercept()`方法中添加一些代码，如下所示：

```ts
import { HttpInterceptor } from '@angular/common/http';

export class MockInterceptor implements HttpInterceptor {
 constructor() { }

 intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
 if (request.url.startsWith('/starwars') &&  request.method  ===  'GET') { const  url  =  request.url; const  newUrl  =  `data${url.substring('/starwars'.length)}.json`; const  req  =  new  HttpRequest('GET', newUrl); return  next.handle(req); } else { return  next.handle(request); }
 }
}
```

我们在这里基本上是在说，我们正在尝试对某个东西执行 GET 请求。`/starwars`将会拦截它，而不是响应一个 JSON 文件。所以，`/starwars/ships`将会导致我们响应`ships.json`，`/starwars/planets`将会导致`planets.json`。你明白了吧；所有其他请求都会被放行。

我们还有一件事要做——告诉我们的模块这个拦截器存在。我们打开我们的模块文件并添加以下内容：

```ts
@NgModule({
 imports: [BrowserModule, HttpClientModule]
 providers: [{ 
 provide:  HTTP_INTERCEPTORS, 
 useClass:  MockInterceptor, 
 multi:  true **}**] })
```

# 一些最佳实践

在处理 Angular 中的数据服务时，特别是涉及到 Observables 时，有一些最佳实践需要遵循，其中包括：

+   处理你的错误。这是不言而喻的，希望这对你来说并不是什么新鲜事。

+   确保任何手动创建的 Observables 都有一个清理方法。

+   取消订阅你的流/可观察对象，否则可能会出现资源泄漏。

+   使用 async 管道来为你管理订阅/取消订阅过程。

到目前为止，我们还没有讨论如何在手动创建 Observables 时创建清理方法，这就是为什么我们将在一个小节中进行讨论。

在 Firebase 部分已经提到了 async 管道几次，但值得再次提及并通过解释它在订阅/取消订阅流程中的作用来建立对它的了解。

# 异步操作符

async 管道是一个 Angular 管道，因此它用在模板中。它与流/可观察对象一起使用。它发挥了两个作用：它帮助我们少打字，其次，它节省了整个设置和拆除订阅的仪式。

如果它不存在，当尝试从流中显示数据时，很容易会输入以下内容：

```ts
@Component({
 template: `{{ data }}`
})
export class DataComponent implements OnInit, implements OnDestroy {
 subscription;
 constructor(private service){ }

 ngOnInit() {
 this.subscription = this.service.getData()
 .subscribe( data => this.data = data )
 }

 ngOnDestroy() {
 this.subscription.unsubscribe(); 
 }
}
```

正如你所看到的，我们需要订阅和取消订阅数据。我们还需要引入一个数据属性来分配它。async 管道为我们节省了一些按键，所以我们可以像这样输入我们的组件：

```ts
@Component({
 template: `{{ data | async }}`
})
export class DataComponent implements OnInit {
 data$;
 constructor(private service){ }

 ngOnInit() {
 this.data$ = this.service.getData();
 }
}
```

这是少了很多代码。我们删除了：

+   `OnDestroy`接口

+   `subscription`变量

+   任何订阅/取消订阅的调用

我们确实需要添加`{{ data | async }}`，这是一个相当小的添加。

然而，如果我们得到的是一个更复杂的对象，并且我们想要显示它的属性，我们必须在模板中输入类似这样的内容：

```ts
{{ (data | ansync)?.title }}
{{ (data | ansync)?.description }}
{{ (data | ansync)?.author }}
```

我们这样做是因为数据还没有设置，此时访问属性会导致运行时错误，因此我们使用了`?`操作符。现在，这看起来有点冗长，我们可以使用`-`操作符来解决这个问题，就像这样：

```ts
<div *ngIf="data | async as d">
 {{ d.title }}
 {{ d.description }}
 {{ d.author }}
</div>
```

现在看起来好多了。使用`async pipe`将减少大量样板代码。

# 做一个好公民 - 在自己之后清理

好的，所以我已经告诉过你调用`.unsubscribe()`的重要性，你现在应该相信我，如果不调用它，资源就不会被清理。当你处理有着永无止境的数据流的流时，比如滚动事件，或者在需要创建自己的 Observables 时，了解这一点非常重要。我现在将展示一些 Observable 的内部，以使事情更清晰：

```ts
let stream$ = Observable.create( observer => {
 let i = 0;
 let interval = setInterval(() => {
 observer.next(i++);
 }, 2000)
})

let subscription = stream$.subscribe( data => console.log( data ));
setTimeout((
 subscription.unsubscribe();
) =>, 3000)

```

这是一个创建自己的 Observable 的例子。你以为只因为你按照指示调用了`.unsubscribe()`就安全了？错。间隔会继续计时，因为你没有告诉它停止。慌乱中，你关闭了浏览器标签，希望 Observable 消失 - 现在你是安全的。正确的方法是添加一个清理函数，就像这样：

```ts
let stream$ = Observable.create( observer => {
 let i = 0;
 let interval = setInterval(() => {
 observer.next(i++);
 }, 2000);

 return function cleanUp() {
 clearInterval( interval );
 }
})

let subscription = stream$.subscribe( data => console.log( data ));
setTimeout(() => subscription.unsubscribe(), 3000);
```

调用`subscription.unsubscribe()`时，它将在内部调用`cleanUp()`函数。大多数，如果不是全部，用于创建 Observables 的工厂方法都会定义自己的`cleanUp()`函数。重要的是，你应该知道，如果你冒险创建自己的 Observable，请参考本节，做一个好公民，并实现`cleanUp()`函数。

# 总结

正如我们在本章开头指出的，要详细介绍 Angular HTTP 连接功能所能做的所有伟大事情，需要不止一个章节，但好消息是我们已经涵盖了几乎所有我们需要的工具和类。

其余的就留给你的想象力了，所以随时可以尽情发挥，通过创建全新的 Twitter 阅读客户端、新闻源小部件或博客引擎，以及组装各种你选择的组件来将所有这些知识付诸实践。可能性是无限的，你可以选择各种策略，从 Promises 到 Observables。你可以利用响应式功能扩展和强大的`Http`类的令人难以置信的功能。

正如我们已经强调的那样，天空是无限的。但是，我们还有一条漫长而令人兴奋的道路在前方。现在我们知道了如何在我们的组件中消费异步数据，让我们来探索如何通过将用户路由到不同的组件中，为我们的应用提供更广泛的用户体验。我们将在下一章中介绍这个内容。
