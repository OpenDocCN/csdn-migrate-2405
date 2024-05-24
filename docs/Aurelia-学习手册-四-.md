# Aurelia 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F`](https://zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：设计关注 - 组织和解耦

组织大型应用程序可能会变得复杂。取决于应用程序的结构以及其部分之间必须如何相互依赖，决定如何组织代码并不总是显而易见的。当你不熟悉框架时，这一点更是如此。

组织 Aurelia 应用程序有很多方法。像设计和架构相关的任何事物一样，选择一个组织模型是一个权衡许多标准的问题。显然，选择一个模型而不是另一个意味着从中受益，但也需要处理其缺点和限制。

在本章中，我们首先将了解组织应用程序的不同方法，以及框架可以帮助我们做到这一点的各种特性。当然，我们将对我们的联系管理应用程序进行重构，使其具有更可扩展的结构。我们会尝试不同的想法，直到找到一个稳定的结构。

其次，如果构成我们应用程序的组件紧密耦合，基于组件的框架就是徒劳的。在本章的第二部分，我们将看到不同的方法来解耦组件，使用数据绑定、共享服务或 Aurelia 的事件聚合器。

# 重新组织我们的应用程序

在探索应用程序结构的可能性之前，我们首先需要决定我们的目标是什么。如果我们不知道我们正在努力争取的组织模型的属性，我们就无法做出明智的决定。

当然，这里的属性将是绝对任意的。在真实项目中，有真实的客户、真实的利益相关者和真实的用户，我们至少会有一些线索来了解这些属性可能是什么。在我们联系管理应用程序的案例中，我们将坚持最常见的中型到大型项目中需要的属性。

首先，我们将假设我们的应用程序注定要增长。现在，它只管理联系人，但我们可以想象我们的产品所有者对应用程序有宏伟的计划，最终我们会添加一些完全不相关的功能。

当前的结构，或者它的缺失，适合一个小应用程序。对于一个具有更多独特功能的大型应用程序，项目必须以这样的方式组织，以使开发人员不会在代码中迷失。在我们应用程序的背景下，我们需要选择一个结构，以最小化将来需要重新组织的机会，因为它的结构无法扩展。

第二，我们将努力实现一种允许功能尽可能解耦和独立的架构。目标是使包括和排除应用程序的功能尽可能容易。这个要求对大多数应用程序来说并不典型，但在这个情况下，它将允许我们了解当需要时 Aurelia 如何帮助我们做到这一点。

## 重构结构

目前，我们的应用程序基本上没有结构，除了全局资源和验证设置，它们作为特性在自己的目录中分组。所有与联系人管理特性相关的文件都位于`src`目录的根目录中，组件与 API 网关和模型混合在一起。让我们在那里面整理一下。

### 注意

在`chapter-6/samples/app-reorganized`中找到的示例展示了经过以下章节描述的结构调整后的应用程序。它可以作为参考。

首先，让我们将所有与联系人管理相关的代码放在一个`contacts`目录中。这使得每个功能都向隔离在自己的目录中迈出了一步。此外，为了减少冗余，让我们将以`contact-`开头的文件重命名为不带前缀的名称。

项目结构应该像这样之后：

![重构结构](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_06_001.jpg)

这已经更好了。然而，我们可以通过创建子目录来增强聚合性，按其责任类型对文件进行分组。在这里，我们首先有组件`creation`、`details`、`edition`、`list`和`photo`。我们还有一个服务：网关。最后，我们有一些`models`，它们都被放在同一个文件里。

### 分解模型

让我们先将模型分解成一个新的`models`目录，并通过爆炸`models.js`文件，将每个模型类移动到这个新目录内部的各自文件中。它应该看起来像这样：

![分解模型](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_06_007.jpg)

现在，通过简单的查看`models`目录，开发者可以看到我们有多个模型以及它们的名称。

当然，这意味着我们必须对这些类进行一些更改。首先，我们必须在`address.js`、`email-address.js`、`phone-number.js`和`social-profile.js`文件的顶部添加一个用于验证的`import`语句：

```js
import {ValidationRules} from 'aurelia-validation'; 

```

接下来，在`contact.js`文件的顶部必须添加其他模型类的`import`语句：

```js
import {PhoneNumber} from './phone-number'; 
import {EmailAddress} from './email-address'; 
import {Address} from './address'; 
import {SocialProfile} from './social-profile'; 

```

### 隔离网关

`gateway`与文件中的其他内容不同，它是一个服务。通常，服务是单例，为应用程序的其他部分提供一些功能。在这里，我们只有这个一个服务，但仍然值得为其创建一个自己的目录，以便更容易找到。

让我们创建一个`services`目录，并将`gateway`移动到那里：

![隔离网关](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_06_003.jpg)

为了让`gateway`像以前一样工作，需要做的第一个改变是使`environment import`语句的路径绝对，通过移除`./`前缀：

```js
import environment from 'environment'; 

```

我们还需要更改导入`Contact`类的路径：

```js
import {Contact} from '../models/contact'; 

```

### 组件分组

最后，我们可以将视觉组件分组到它们自己的目录中。让我们创建一个`components`目录，并将剩下的文件移动到里面：

![组件分组](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_06_004.jpg)

此时，应用程序已损坏。我们需要做两件事：修复组件中的模型类和网关的`import`和`require`语句，以及修复`app`组件的路由声明。

首先，在`creation.js`、`details.js`、`edition.js`、`list.js`和`photo.js`中，必须修复网关的`import`语句：

```js
import {ContactGateway} from '../services/gateway'; 

```

此外，`Contact`模型在`creation.js`中的`import`语句也必须修复：

```js
import {Contact} from '../models/contact'; 

```

最后，我们需要通过修复路径并添加别名来更改`creation.html`和`edition.html`中的`require`语句，以便`form.html`模板仍作为`contact-form`自定义元素加载：

```js
<require from="./form.html" as="contact-form"></require> 

```

至此，我们的`contacts/components`已准备就绪。我们只需要修复`app`组件内所有路由声明的组件路径：

```js
config.map([ 
  { route: '', redirect: 'contacts' }, 
  { route: 'contacts', name: 'contacts',  
    moduleId: 'contacts/components/list', nav: true, title: 'Contacts' }, 
  { route: 'contacts/new', name: 'contact-creation',  
    moduleId: 'contacts/components/creation', title: 'New contact' }, 
  { route: 'contacts/:id', name: 'contact-details',  
    moduleId: 'contacts/components/details' }, 
  { route: 'contacts/:id/edit', name: 'contact-edition',  
    moduleId: 'contacts/components/edition' }, 
  { route: 'contacts/:id/photo', name: 'contact-photo',  
    moduleId: 'contacts/components/photo' }, 
]); 

```

文件结构现在要干净得多。如果你现在运行应用程序，一切应该还是和之前一样工作。

### 没有一劳永逸的解决方案。

我们刚刚重构的结构并不是绝对的真理。在这种决策中，品味和观点总是起到一定的作用，对于这类问题没有正确或错误的答案。

然而，这种结构的背后的理由是简单且可以归结为几个原则：

+   通用或应用程序范围内的资源位于`resources`特性中。像`order-by`值转换器或`file-picker`自定义元素这样的东西应该放在那里。

+   类似地，不属于特定特性的服务和服务模型，应该位于`src`目录的根目录下的各自目录中；例如，在`src/services`和`src/models`中。在我们的应用程序中没有这些。

+   每个领域特性都位于自己的目录中，例如`contacts`目录。

+   也可以存在技术特性，例如`validation`特性。这些特性的目的是提供一些通用行为或扩展其他特性。

+   在特性目录内，文件按责任类型分组。组件，无论是像`creation`、`details`、`edition`、`list`和`photo`这样的路由组件，还是像`form.html`模板这样的专用小部件或自定义元素，都位于`components`子目录内。服务和模型也有各自的目录。如果给定特性存在特殊的值转换器或绑定行为，它们也应该位于特性目录内的各自目录中。

这些都是我在构建 Aurelia 应用程序时遵循的指导原则。当然，通常还有需要深思熟虑的情况，要么是因为它们不适合现有的槽位，要么是因为盲目应用这些规则会搞得一团糟。

例如，如果我们的路由组件和专用小部件很多，将`components`目录分成两个，比如命名为`screens`和`widgets`可能是个好主意。这样，更容易识别哪些是路由组件，哪些是特定功能的定制元素或组合小部件。

此外，有时在结构中添加另一层分类会更好，无论是按子域或类别分组功能，还是按更具体的目的分组服务、模型或组件。这里的真正指南是尽量使结构传达意图和隐性知识，以及尽可能容易地理解每个部分的位置。

我尝试遵循的另一条指南是使域功能目录反映出导航菜单结构。当然，当菜单结构过于复杂时，这是不可能的，尽管这可能是一个需要重新思考的信号。当可能时，这显然可以使开发人员更容易、更直观地导航代码和应用程序。

## 利用子路由

此时，所有与联系人管理相关的代码都位于`contacts`目录中。但这真的正确吗？实际上，并不正确。路由定义仍然位于`app`组件中。我们如何将这些移动到`contact`目录内？

第一个可能性是利用子路由。这样，我们可以在`contacts`内部声明一个`main`组件，负责声明到各种联系人管理组件的路由，如`list`、`creation`和`edition`。然后，`app`组件需要一个通往联系人`main`组件的单一路由，并且不需要知道更专业的`contacts`路由。

### 注意

在以下部分，我们将尝试不同的事情。为了更容易地将代码恢复到每次尝试之前的样子，我建议您在此时以某种方式备份您的应用程序，无论是简单地复制和粘贴项目目录，还是如果您从 GitHub 克隆了代码，则在您的源控制中创建一个分支。此外，在`chapter-6/samples/app-using-child-router`中找到的示例展示了如下一节中描述的应用程序修改。它可以作为参考。

### 更改根路由

首先，更改根路由配置：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.map([ 
 { route: '', redirect: 'contacts' }, 
 { route: 'contacts', name: 'contacts', moduleId: 'contacts/main', 
 nav: true, title: 'Contacts' }, 
 ]); 
    config.mapUnknownRoutes('not-found'); 
  } 
} 

```

这里，我们移除了所有指向各种联系人管理组件的路由，并用一个映射到`contacts` URL 前缀的单一路由替换它们。此路由通往`contacts`的`main`组件。当然，我们保留了默认路由，它重定向到这个`contacts`路由。

### 配置联系人子路由

接下来，我们需要创建`contacts`的`main`组件：

`src/contacts/main.js`

```js
import {inlineView} from 'aurelia-framework'; 

@inlineView('<template><router-view></router-view></template>') 
export class Contacts { 
  configureRouter(config) { 
    config.map([ 
      { route: '', name: 'contacts',  
        moduleId: './components/list', title: 'Contacts' }, 
      { route: 'new', name: 'contact-creation',  
        moduleId: './components/creation', title: 'New contact' }, 
      { route: ':id', name: 'contact-details',  
        moduleId: './components/details' }, 
      { route: ':id/edit', name: 'contact-edition',  
        moduleId: './components/edition' }, 
      { route: ':id/photo', name: 'contact-photo',  
        moduleId: './components/photo' }, 
    ]); 
  } 
} 

```

在这里，我们首先使用`inlineView`装饰器声明一个模板，该模板简单地使用`router-view`元素来渲染子路由器的活动组件。这个子路由器是通过`configureRouter`方法配置的，该方法声明了之前在`app`组件中的`contacts`路由。

当然，路由声明需要做一点小修改。首先，必须从每个路由的`route`属性中删除`contacts/`前缀，因为它现在由父路由器处理。因此，指向`list`组件的路由现在是子路由器的默认路由，因为它的模式与空字符串匹配。此外，`moduleId`属性可以改为相对路径，而不是像以前那样的绝对路径。这将减少如果我们改名或移动`contacts`目录时需要做的更改。最后，由于这个子路由器的导航模型不用于渲染任何菜单，我们可以从指向列表的路由中删除`nav`属性。

### 含义

如果你运行应用程序并对其进行测试，你可能会注意到，现在在通过`creation`、`details`、`edition`和`photo`组件导航时，**联系人**顶菜单项保持高亮状态，而之前只有在`list`组件活动时才高亮。

这是因为这个菜单项是使用指向`contacts`组件的`main`路由生成的，当我们在任何子路由上时，它保持激活状态。这是一个有趣的副作用，增加了用户的反馈，使顶级菜单的行为更加一致。

此外，使用子路由器将声明模块路由的责任移到了模块本身内部。如果需要更改模块的路由，更改将在模块的范围内进行，对应用程序的其余部分没有影响。

然而，子路由器有一些限制。通常，在编写本文时，路由器在生成 URL 时只访问自己的路由。这意味着你不能使用`route-href`属性，也不能使用`Router`类的`generate`或`navigateToRoute`方法为其他路由器中定义的路由生成 URL，无论这些路由器是父路由器、子路由器还是兄弟路由器。当模块需要彼此之间有直接链接时，这可能是个问题。必须手动生成路由，这意味着路由模式可能在不止一个地方定义，这增加了如果路由模式更改并且开发者只更新了一些模式实例时引入错误的风险。

## 在功能中声明根路由

这里另一个可能会有帮助的工具是 Aurelia 的`feature`系统。我们可以利用一个`configure`函数直接在根路由器上注册联系人管理路由。

让我们恢复到在插入子路由器之前的状态，看看这可能会导致什么结果。

### 注意

在`chapter-6/samples/app-using-feature`找到的示例展示了根据以下部分修改后的应用程序。它可以作为参考。

### 创建特性

我们首先需要创建一个`index.js`文件来配置我们新的特性：

`src/contacts/index.js`

```js
import {Router} from 'aurelia-router'; 

const routes = [ 
  { route: 'contacts', name: 'contacts',  
    moduleId: 'contacts/components/list', nav: true, title: 'Contacts' }, 
  { route: 'contacts/new', name: 'contact-creation',  
    moduleId: 'contacts/components/creation', title: 'New contact' }, 
  { route: 'contacts/:id', name: 'contact-details',  
    moduleId: 'contacts/components/details' }, 
  { route: 'contacts/:id/edit', name: 'contact-edition',  
    moduleId: 'contacts/components/edition' }, 
  { route: 'contacts/:id/photo', name: 'contact-photo',  
    moduleId: 'contacts/components/photo' }, 
]; 

export function configure(config) { 
  const router = config.container.get(Router); 
  routes.forEach(r => router.addRoute(r)); 
} 

```

在这里，`configure`函数简单地从 DI 容器中获取根路由器，然后使用`Router`类的`addRoute`方法注册路由。由于这里没有子路由，所以路由使用它们的完整 URL，包括`contacts/`前缀，并且它们使用绝对路径来引用它们的组件，因为它们相对于声明根`configureRouter`方法的组件，这里是`app`。

当然，这意味着我们需要将这个功能加载到应用程序的主要`configure`函数中：

`src/main.js`

```js
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .feature('validation') 
    .feature('resources') 
    .feature('contacts'); 
  //Omitted snippet... 
} 

```

### 更改根路径

最后，我们需要从`app`组件中移除联系人管理路径：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.map([ 
 { route: '', redirect: 'contacts' }, 
 ]); 
    config.mapUnknownRoutes('not-found'); 
  } 
} 

```

在这里，我们简单地移除了所有通往各种联系人管理组件的路径，除了默认路径重定向到显示`list`组件的`contacts`路径。

### 减少特性之间的耦合

应用程序仍然以两种方式依赖于`contacts`特性：它将其加载到主要的`configure`函数中，默认路径重定向到`app`组件中的其一个路径。如果我们想要移除这个特性，现在有两个地方需要更新。我们如何从`app`组件中移除依赖？

一种首先的可能性是简单地添加一个`home`组件，或者某种欢迎仪表板，并将其作为默认路径。这样，访问应用程序根目录的用户总是在同一个地方受到欢迎，即使应用程序功能发生了变化。除了在主要的`configure`函数中，我们也不会有任何关于`contacts`功能的引用。

Alternatively, we could dynamically select the route to which the default route redirects. Since the `app` component's `configureRouter` method is called during the component's activation lifecycle, the feature has already been configured at that time and its routes have already been added to the root router. We could simply take the router's first navigation model entry and have the default route redirect to it:

`src/app.js`

```js
function findDefaultRoute(router) { 
  return router.navigation[0].relativeHref; 
} 

export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.map([ 
      { route: '', redirect: findDefaultRoute(router) }, 
    ]); 
    config.mapUnknownRoutes('not-found'); 
  } 
} 

```

这种解决方案的优势在于，默认路径总是会重定向到顶部菜单中显示的第一个路径，这对于没有明显主页屏幕的绝大多数应用程序来说是一种合理的行为。

然而，如果应用程序中移除了所有特性，导航模型将会为空，这段代码将会断裂。在这种情况下，拥有一个明确的主页可能能够挽救局面，尽管在大多数情况下，一个没有特性但有一个简单主页的应用程序是没有意义的。

### 含义

定义应用程序中所有路由在根路由器上，通过特性或`app`组件的主要优点之一是，所有路由都被根路由器所知晓，这意味着它可以为应用程序中的任何路由生成 URL。

当组件和特性之间存在大量链接时，这种区别不容忽视。在这种情况下，使用子路由器并且不能依赖路由器生成大部分 URL 是痛苦的。

## 为什么不两者都使用呢？

我们刚刚探索的这两种解决方案都有各自的优缺点。使用子路由器感觉是正确的事情，主要是因为它修复了顶部菜单的不一致行为，这让我感到烦恼，也许比它应得的还要多，但它使跨特性的链接变得复杂。此外，它需要在`app`组件中声明一个指向联系人`main`组件的路由。

另一方面，使用特性也感觉是正确的。特性正是为这类用例设计的。

让我们尝试合并这两种策略：在`main`组件中声明一个子路由器来处理联系人的路由，并使用一个特性在根路由器上添加到这个`main`组件的路由。

### 注意

以下代码片段是本章完成示例应用程序的摘录，可以在`chapter-6/app`中找到。

如果我们保留上一节中引入`contacts`特性时所做的修改，这意味着我们需要像使用子路由器一样添加一个`main`组件：

`src/contacts/main.js`

```js
import {inlineView} from 'aurelia-framework'; 

@inlineView('<template><router-view></router-view></template>') 
export class Contacts { 
  configureRouter(config) { 
    config.map([ 
      { route: '', name: 'contacts',  
        moduleId: './components/list', title: 'Contacts' }, 
      { route: 'new', name: 'contact-creation',  
        moduleId: './components/creation', title: 'New contact' }, 
      { route: ':id', name: 'contact-details',  
        moduleId: './components/details' }, 
      { route: ':id/edit', name: 'contact-edition',  
        moduleId: './components/edition' }, 
      { route: ':id/photo', name: 'contact-photo',  
        moduleId: './components/photo' }, 
    ]); 
  } 
} 

```

接下来，必须更改特性的`configure`函数，使其添加到`contacts`的`main`组件的路由：

`src/contacts/index.js`

```js
import {Router} from 'aurelia-router'; 

export function configure(config) { 
  const router = config.container.get(Router); 
  router.addRoute({ route: 'contacts', name: 'contacts', 
 moduleId: 'contacts/main', nav: true, title: 'Contacts' }); 
} 

```

使用这种模式，可以轻松添加新特性，而无需更改除了将其加载到主`configure`函数之外的其他内容。唯一需要更改`app`组件的情况是，当你不使用动态方法时，需要更改默认路由重定向到的特性。

### 注意

我并不是提倡在每一个 Aurelia 应用程序中都使用这种模式。它增加了复杂性，因此，只有真正需要时才应该使用。这里的主要目标是展示框架提供的可能性。

# 解耦组件

决定一个程序的组件如何相互依赖和通信就是设计的核心。设计一个 Aurelia 应用程序也不例外。然而，为了做出明智的设计选择，你需要知道框架提供了哪些技术。

在 Aurelia 应用程序中，通常有四种方法可以使组件相互通信：使用数据绑定，使用远程服务，使用共享服务，和使用事件。

到目前为止，我们的应用程序主要依赖于数据绑定和远程服务，即我们的后端。路由组件之间没有直接通信，而是通过后端进行通信。每个路由组件在激活时从后端检索所需的数据，然后将用户执行的任何操作委派给后端。此外，路由组件由其他可重用组件组成，并通过数据绑定与它们通信。

在以下部分，我们首先快速总结我们已经使用的技术，然后我们将讨论其他技术：事件和共享服务。这样做的同时，我们也将对联系人管理应用程序进行大量重构，这样我们就可以尝试一种完全不同的基于这些技术的架构。

作为一个实验，我们首先重构应用程序，使其能够监听后端发送的事件并在本地分派这些事件。这样，任何需要对这类事件做出反应的组件都可以简单地订阅本地事件。

完成这一步后，我们将利用这些本地事件进一步重构我们的应用程序，这次是朝着实时、多用户同步的方向。我们将创建一个服务，用来加载联系人列表，然后监听变更事件以保持联系人同步。我们将重构所有路由组件，使它们从本地联系人列表而不是每次激活时都从后端获取数据。

流程将与以下类似：

![解耦组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_06_005.jpg)

当用户执行某个操作，比如创建一个新的联系人或更新一个现有的联系人时，一个命令将被发送到后端。这一点是不变的。然而，下次联系人列表组件显示时，应用程序将仅仅显示其本地的数据副本，因为它将通过监听由后端每次发送命令时发出的变更事件来保持其最新。

这种新设计借鉴了**CQRS/ES**模式的一些概念。这种模式的一个优点是，每当任何用户对数据进行更改时，应用程序都会立即收到通知，因此应用程序不断地与服务器的状态保持同步。

### 注意

CQRS 代表命令和查询责任分离，ES 代表事件源。由于定义这些模式超出了本书的范围，如果你对此感到好奇，可以去查看马丁·福勒（Martin Fowler）关于它们的说法：[`martinfowler.com/bliki/CQRS.html`](http://martinfowler.com/bliki/CQRS.html) 和 [`martinfowler.com/eaaDev/EventSourcing.html`](http://martinfowler.com/eaaDev/EventSourcing.html)。

当然，在生产就绪的应用程序中，整个同步机制将需要某种形式的冲突管理。实际上，当一个用户正在编辑一个联系人时，如果另一个用户对同一个联系人进行更改，第一个用户将看到表单实时更新，新值覆盖他自己的更改。那是糟糕的。然而，我们不会深入探讨这个问题。让我们将这视为一个概念验证和一个关于使组件通信的实验。

## 使用数据绑定

使组件通信最常见且简单的方式是通过数据绑定。我们已经看到了很多这样的例子；当我们将`edit`组件的`contact`属性与`form`组件的`contact`可绑定属性绑定在一起时，我们就使它们进行了通信。

数据绑定允许在模板内松散地耦合组件。当然，它有一些内在的限制：绑定是由父组件声明的，通信限于应用程序树中的一层组件。要使通信超过一个层次，需要树中的每个组件都与其子组件数据绑定。我们可以看到这在`photo`组件中，其`files`属性与`file-picker`的`files`属性绑定，后者又与`file-drop-target`属性绑定，从而使跨多层组件进行通信成为可能。

这也是使组件通信更加灵活的方式，因为它非常容易更改，并且依赖关系存在于模板中，组件本身就是在那里声明和组合的。

## 使用远程服务

使组件通信的另一种方式是通过远程服务。在我们的应用程序中，我们也大量使用了这种技术。应用程序存储非常少的状态；后端才是实际的状态库。

为了显示一个联系人的修改版本，`edition`组件向后端查询该联系人的数据。当用户保存联系人的修改时，向后端发送一个更新命令，后端将其应用于内部状态。然后，当应用程序将用户带回到联系人的详细信息时，组件查询联系人的最新数据副本。当导航到联系人列表时，也是同样的情况：每次都查询后端，并且每次都获取联系人列表的整个副本。

这种技术非常普遍。在这种情况下，应用程序认为其后端是唯一真实的数据来源，并依赖其后端处理一切。这样的应用程序可以更简单，因为业务规则和命令的复杂副作用可以完全由后端处理。应用程序只是一个富用户界面，位于后端之上。

然而，这种技术的缺点是，如果通信线路中断，应用程序就变得无用。在网络故障或后端由于某种原因无法响应的情况下，应用程序就无法再工作。

## 使用事件

广泛用于减少耦合的一种设计技术是**发布**/**订阅**模式。当应用这个模式时，组件可以订阅消息总线，以便在发送特定类型的消息时收到通知。其他组件可以使用这个相同的消息总线发送消息，而无需知道哪些组件将处理它们。

使用这种模式，各个组件之间没有任何依赖关系。相反，它们都依赖于消息总线，它充当了它们之间的某种抽象层。此外，这种模式极大地提高了设计的灵活性和可扩展性，因为新组件可以非常容易地订阅现有消息类型，而无需更改其他组件。

Aurelia 通过其`aurelia-event-aggregator`库提供了一个`EventAggregator`类，该类可以充当这样的消息总线。我们将在下一节中看到如何利用这个类。

### 事件聚合器

`aurelia-event-aggregator`库是默认配置的一部分，因此，默认情况下，我们不需要安装或加载任何内容就可以使用它。

这个库导出了`EventAggregator`类，该类暴露了三个方法：

+   `publish(name: string, payload?: any): void`: 发布一个带有可选负载的命名事件。

+   `subscribe(name: string, callback: function): Subscription`: 订阅一个命名的事件。当发布一个带有订阅的`name`的事件时，将调用`callback`函数。`publish`方法传递的`payload`将作为第一个参数传递给`callback`函数。

+   `subscribeOnce(name: string, callback: function): Subscription`: 订阅一个命名的事件，但只有一次。当事件第一次发布时，订阅会自动被销毁。返回的订阅可以手动在事件发布之前就销毁。

`subscribe`和`subscribeOnce`方法返回的`Subscription`对象有一个单一的方法，名为`dispose`。这个方法简单地将`callback`函数从注册的处理程序中移除，这样当事件发布时它就不会再被调用。

例如，某个组件可以使用以下代码发布一个名为`something-happened`的事件：

```js
import {inject} from 'aurelia-framework'; 
import {EventAggregator} from 'aurelia-event-aggregator'; 

@inject(EventAggregator) 
export class SomeComponent { 
  constructor(eventAggregator) { 
    this.eventAggregator = eventAggregator; 
  }       

  doSomething(args) { 
    this.eventAggregator.publish('something-happened', { args }); 
  } 
} 

```

在这里，组件的构造函数将被注入一个`EventAggregator`实例，然后将其存储在组件中。然后，当`doSomething`方法被调用时，会在事件聚合器上发布一个名为`something-happened`的事件。事件的负载是一个具有`args`属性的对象，该属性包含传递给`doSomething`方法的`args`参数。

为了响应这个事件，另一个组件可以对其进行订阅：

```js
import {inject} from 'aurelia-framework'; 
import {EventAggregator} from 'aurelia-event-aggregator'; 

@inject(EventAggregator) 
export class AnotherComponent { 
  constructor(eventAggregator) { 
    this.eventAggregator = eventAggregator; 
  }       

  activate() { 
    this.subscription = this.eventAggregator.subscribe('something-happened', e => { 
      console.log('Something happened.', e.args); 
    }); 
  } 

  deactivate() { 
    this.subscription.dispose(); 
  } 
} 

```

在这里，另一个组件的构造函数也被注入了事件聚合器，该事件聚合器存储在组件中。当激活时，组件开始监听`something-happened`事件，所以它可以在每次发布一个时向浏览器的控制台写入日志。它还保留了对订阅的引用，以便在停用时可以`dispose`它并停止监听该事件。

这种模式在与事件聚合器在组件中工作时非常常见。使用它确保组件只在它们处于活动状态时监听事件。它还可以防止内存泄漏；实际上，如果事件聚合器仍然引用它，组件不能被垃圾回收。

### 扩展具有事件的对象

除了`EventAggregator`类之外，`aurelia-event-aggregator`库还导出一个名为`includeEventsIn`的函数。它期望一个对象作为其单个参数。

这个函数可以用来扩展具有事件聚合器功能的对象。它将在内部创建一个`EventAggregator`实例，并向对象添加一个`publish`、一个`subscribe`和一个`subscribeOnce`方法，所有这些方法都委托给这个新的`EventAggregator`实例的对应方法。

例如，通过在类构造函数中调用这个函数，可以使所有类实例具有自己的本地事件。让我们想象以下类：

```js
import {includeEventsIn} from 'aurelia-event-aggregator'; 

export class SomeModel { 
  constructor() { 
    includeEventsIn(this); 
  }       

  doSomething() { 
    this.publish('something-happened'); 
  } 
} 

```

`something-happened`事件可以直接在`SomeModel`实例上订阅：

```js
const model = new SomeModel(); 
model.subscribe('something-happened', () => { 
  console.log('Something happened!'); 
}); 

```

由于每个实例都有自己的私有`EventAggregator`实例，事件不会在整个应用程序之间或多个实例之间共享。相反，事件将单独每个实例范围内。

### 使用事件类

`publish`、`subscribe`和`subscribeOnce`方法可以使用命名事件，但它们也支持类型化事件。因此，以下签名也是有效的：

+   `publish(event: object): void`：发布一个事件对象。使用对象的 prototype 作为键来选择要调用的回调函数。

+   `subscribe(type: function, callback: function): Subscription`：订阅一个事件类型。每次发布一个属于订阅`type`的事件实例时，`callback`函数将被调用。发布的事件对象本身将作为单个参数传递给`callback`函数。

+   `subscribeOnce(type: function, callback: function): Subscription`：订阅一个事件类型，但只有一次。

作为一个例子，让我们想象以下事件类：

```js
export class ContactCreated { 
  constructor(contact) { 
    this.contact = contact; 
  } 
} 

```

发布此类事件将这样做：

```js
eventAggregator.publish(new ContactCreated(newContact)); 

```

在这里，我们可以想象`eventAggregator`变量包含`EventAggregator`类的实例，`newContact`变量包含表示新创建联系人的一些对象。

订阅此事件将像这样进行：

```js
eventAggregator.subscribe(ContactCreated, e => { 
  console.log(e.contact.fullName); 
}); 

```

在这里，每次发布一个`ContactCreated`事件时，回调将被调用，其`e`参数将是发布的`ContactCreated`实例。

此外，`EventAggregator`在处理事件类时支持继承。这意味着你可以订阅一个事件基类，每次有任何继承自这个基类的事件类发布时，回调函数都会被调用。

让我们回到我们之前的例子，并添加一些事件类：

```js
export class ContactEvent { 
  constructor(contact) { 
    this.contact = contact; 
  } 
} 

export class ContactCreated extends ContactEvent { 
  constructor(contact) { 
    super(contact); 
  } 
} 

```

在这里，我们定义了一个名为`ContactEvent`的类，`ContactCreated`类从中继承。

现在让我们想象一下以下两个订阅：

```js
eventAggregator.subscribe(ContactCreated, e => { 
  console.log('A contact was created'); 
}); 
eventAggregator.subscribe(ContactEvent, e => { 
  console.log('Something happened to a contact'); 
}); 

```

执行此代码后，如果发布了一个`ContactEvent`实例，将在控制台记录文本`Something happened to a contact`。

然而，如果发布了一个`ContactCreated`实例，将在控制台记录文本`A contact was created`和`Something happened to a contact`，因为事件聚合器将遍历原型链并尝试找到所有祖先的订阅。当处理复杂的事件层次结构时，这个功能可能非常强大。

基于类的事件为消息添加了一些结构，因为它们强制事件有效负载遵守一个预定义的合同。根据你的编程风格，你可能会更喜欢使用强类型事件而不是带有未类型载荷的命名事件。它特别适合于像 TypeScript 这样的强类型 JS 超集。

### 创建一个互动连接

以下内容某种程度上是一种实验，或者是一个概念证明，我建议你在这一点上以某种方式备份你的应用程序，无论是简单地复制和粘贴项目目录，还是如果你从 GitHub 克隆了代码，就在你的源代码控制中创建一个分支。这样，当你继续下一章节时，你就能从当前点开始。

### 注意

另外，在`chapter-6/samples/app-using-server-events`找到的示例展示了应用程序按照以下章节修改后的样子。它可以作为参考。

我们使用的后端接受互动连接，以便将事件分发给客户端应用程序。使用这种互动连接，它可以在每次创建、更新或删除联系时通知连接的客户端。为了分发这些事件，后端依赖于**WebSocket**协议。

### 注意

WebSocket 协议允许客户端与服务器之间建立长生命周期的、双向的连接。因此，它允许服务器向连接的客户端发送基于事件的消息。

在本节中，我们将创建一个名为`ContactEventDispatcher`的服务。这个服务将与后端创建一个 WebSocket 连接，并监听服务器发送的更改事件，以便通过应用程序的事件聚合器在本地分派它们。

为了与服务器创建一个互动连接，我们将使用**socket.io**库。

### 注意

`socket.io`库为交互式连接提供了客户端实现和 node.js 服务器，两者都支持 WebSocket，并在 WebSocket 不受支持时提供回退实现。后端已经使用这个库来处理应用程序的交互式连接。它可以在[`socket.io/`](http://socket.io/)找到。

首先安装`socket.io`客户端。在项目的目录中打开一个控制台，并运行以下命令：

```js
> npm install socket.io-client --save

```

当然，新的依赖项必须添加到应用程序的捆绑包中。在`aurelia_project/aurelia.json`中，在`build`下的`bundles`中，在名为`vendor-bundle.js`的捆绑包的`dependencies`部分，添加以下条目：

```js
{ 
  "name": "socket.io-client", 
  "path": "../node_modules/socket.io-client/dist", 
  "main": "socket.io.min" 
}, 

```

现在我们可以创建`ContactEventDispatcher`类。由于这个类是一个服务，我们将在`contacts`特性的`services`目录中创建它：

`src/contacts/services/event-dispatcher.js`。

```js
import {inject} from 'aurelia-framework'; 
import io from 'socket.io-client'; 
import environment from 'environment'; 
import {EventAggregator} from 'aurelia-event-aggregator'; 
import {Contact} from '../models/contact'; 

@inject(EventAggregator) 
export class ContactEventDispatcher { 

  constructor(eventAggregator) { 
    this.eventAggregator = eventAggregator; 
  } 

  activate() { 
    if (!this.connection) { 
      this.connection = io(environment.contactsUrl); 

      this.connecting = new Promise(resolve => { 
        this.connection.on('contacts.loaded', e => { 
          this.eventAggregator.publish('contacts.loaded', { 
            contacts: e.contacts.map(Contact.fromObject) 
          }); 
          resolve(); 
        }); 
      }); 
    } 

    return this.connecting; 
  } 

  deactivate() { 
    this.connection.close(); 
    this.connection = null; 
    this.connecting = null; 
  } 
} 

```

这个类需要一个`EventAggregator`实例作为其构造函数的参数，并声明了一个`activate`方法，该方法使用从`socket.io`客户端库中导入的`io`函数，使用`environment`的`contactUrl`与服务器创建一个`connection`。然后创建一个新的`Promise`，将其分配给`connecting`属性，并通过`activate`方法返回。这个`Promise`允许监控连接到后端的过程状态，因此调用者可以连接到它以在连接建立时做出反应。此外，该方法还确保在任何给定时间只打开一个到后端的`connection`。如果多次调用`activate`，则返回`connecting` `Promise`。

当后端接收到一个新的连接时，它会发送当前联系人列表作为一个名为`contacts.loaded`的事件。因此，一旦`activate`方法初始化连接，它就会监听这个事件，并在事件聚合器上重新发布它。这样做时，它还将从服务器接收的初始对象列表转换为`Contact`对象的数组。最后，它解决`connecting` `Promise`以通知调用者`activate`操作已完成。

该类还暴露了一个`deactivate`方法，该方法关闭并清除连接。

在这个阶段，当它开始时，分发器发布一个包含当前联系人列表的`contacts.loaded`事件。然而，后端还可以发送多达三种类型的事件：

+   `contact.created`，当创建新的联系人时。

+   `contact.updated`，当更新联系人时。

+   `contact.deleted`，当一个联系人被删除时。

这些事件的每个负载都有一个`contact`属性，其中包含执行命令的联系人。

根据这些信息，我们可以修改分发器，使其监听这些事件并在本地重新发布它们：

`src/contacts/services/event-dispatcher.js`。

```js
//Omitted snippet... 
export class ContactEventDispatcher { 
  //Omitted snippet... 

  activate() { 
    if (!this.connection) { 
      this.connection = io(environment.contactsUrl); 

      this.connecting = new Promise(resolve => { 
        this.connection.on('contacts.loaded', e => { 
          this.eventAggregator.publish('contacts.loaded', { 
            contacts: e.contacts.map(Contact.fromObject) 
          }); 
          resolve(); 
        }); 
      }); 

      this.connection.on('contact.created', e => { 
 this.eventAggregator.publish('contact.created', { 
 contact: Contact.fromObject(e.contact) 
 }); 
 }); 
 this.connection.on('contact.updated', e => { 
 this.eventAggregator.publish('contact.updated', { 
 contact: Contact.fromObject(e.contact) 
 }); 
 }); 
 this.connection.on('contact.deleted', e => { 
 this.eventAggregator.publish('contact.deleted', { 
 contact: Contact.fromObject(e.contact) 
 }); 
 }); 
    } 

    return this.connecting; 
  } 

  //Omitted snippet... 
} 

```

在这里，我们添加事件处理程序，以便当后端发送`contact.created`事件、`contact.updated`事件或`contact.deleted`事件时，受影响的信息条目被转换为`Contact`对象，并将事件重新发布到应用程序的事件聚合器上。

一旦准备好，我们需要在`contacts`特性的`configure`函数中`activate`事件监听器。然而，分发器在初始化连接时使用`Contact`类将来自后端的对象列表转换为`Contact`实例。由于`Contact`类依赖于`aurelia-validation`插件的加载，并且我们不能确定当我们的`configure`函数被调用时插件确实已加载，因此我们在这里不能使用`Contact`，否则在初始化`Contact`的验证规则时可能会抛出错误。我们该怎么办呢？

Aurelia 框架配置过程支持后配置任务。这样的任务只是将在所有插件和功能都加载完成后调用的函数，可以通过将配置对象的`postTask`方法传递给`configure`函数来添加：

`src/contacts/index.js`

```js
import {Router} from 'aurelia-router'; 
import {ContactEventDispatcher} from './services/event-dispatcher'; 

export function configure(config) { 
  const router = config.container.get(Router); 
  router.addRoute({ route: 'contacts', name: 'contacts', moduleId: 'contacts/main', nav: true, title: 'Contacts' }); 

 config.postTask(() => {
const dispatcher = config.container.get(ContactEventDispatcher); 
 return dispatcher.activate();
 }); 
} 

```

在这里，我们添加了一个后配置任务，当所有插件和功能都加载完成后激活分发器。此外，由于后配置任务支持`Promise`s，我们可以返回由`activate`返回的`Promise`，因此我们确信当框架的引导过程完成后，与后端的交互式连接已完成，并且初始联系人已加载。

### 添加通知

至此，我们的`main`组件的`contacts`列表监听服务器事件，并在本地分发它们。然而，我们仍然对那些事件不做任何事情。让我们添加一些通知，当服务器上发生某些事情时告诉用户。

我们将添加一个通知系统，每当后端发送一个变更事件时，都会让用户知道。因此，我们将使用一个名为`humane.js`的库，该库可以在[`wavded.github.io/humane-js/`](http://wavded.github.io/humane-js/)找到。您可以通过在项目目录中打开控制台窗口并运行以下命令来安装它：

```js
> npm install humane-js --save

```

一旦完成，您还必须让打包工具知道这个库。在`aurelia_project/aurelia.json`中，在`build`下的`bundles`中，在名为`vendor-bundle.js`的包的`dependencies`部分，添加以下代码片段：

```js
{ 
  "name": "humane-js", 
  "path": "../node_modules/humane-js", 
  "main": "humane.min" 
}, 

```

为了隔离这个库的使用，我们将围绕它创建一个自定义元素：

`src/contacts/components/notifications.js`

```js
import {inject, noView} from 'aurelia-framework'; 
import {EventAggregator} from 'aurelia-event-aggregator'; 
import Humane from 'humane-js'; 

@noView 
@inject(EventAggregator, Humane) 
export class ContactNotifications { 

  constructor(events, humane) { 
    this.events = events; 
    this.humane = humane; 
  } 

  attached() { 
    this.subscriptions = [ 
      this.events.subscribe('contact.created', e => { 
        this.humane.log(`Contact '${e.contact.fullName}' was created.`); 
      }), 
      this.events.subscribe('contact.updated', e => { 
        this.humane.log(`Contact '${e.contact.fullName}' was updated.`); 
      }), 
      this.events.subscribe('contact.deleted', e => { 
        this.humane.log(`Contact '${e.contact.fullName}' was deleted.`); 
      }) 
    ]; 
  } 

  detached() { 
    this.subscriptions.forEach(s => s.dispose()); 
    this.subscriptions = null; 
  } 
} 

```

这个自定义元素首先需要一个`EventAggregator`实例和一个`Humane`对象被注入到其构造函数中。当它被`attached`到 DOM 时，它会订阅`contact.created`、`contact.updated`和`contact.deleted`事件，在发布时显示适当的通知。它还存储由`EventAggregator`的`subscribe`方法返回的订阅在一个数组中，这样它就可以在从 DOM 中`detached`时释放这些订阅。

为了使用这个自定义元素，我们需要通过添加一个`require`语句和一个这个元素的实例来修改功能`main`组件的模板。

然而，`main`模板正在变得更大，所以让我们从视图模型类中移除`inlineView`装饰器，并将模板移动到其自己的文件中：

`src/contacts/main.html`

```js
<template> 
  <require from="./components/notifications"></require>
<contact-notifications></contact-notifications> 
  <router-view></router-view> 
</template> 

```

最后，我们需要添加`humane.js`的一个主题样式的样式表，以便通知被正确样式化：

`index.html`

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <!-- Omitted snippet... --> 
 <link href="node_modules/humane-js/themes/flatty.css" rel="stylesheet"> 
  </head> 
  <body> 
    <!-- Omitted snippet... --> 
  </body> 
</html> 

```

如果您在这个时候运行应用程序并修改一个联系人，您会看到通知没有显示。我们错过了什么？

### 摆脱陷阱

这是我在将库与 Aurelia 集成时遇到的一个棘手的问题。这是由于`aurelia-app`属性在`body`元素上引起的。

确实，有些库在加载时会向`body`添加元素。`humane.js`就是这样做的。当它加载时，它会创建一个 DOM 子树，将其作为显示通知的容器，并将其附加到`body`上。

然而，当 Aurelia 的引导过程结束，应用程序被渲染时，包含`aurelia-app`属性的元素的內容会被替换为`app`组件的渲染视图。这意味着 DOM 元素的`humane.js`将尝试使用它来显示通知，但这些通知将不再在 DOM 上。哎呀。

解决这个问题相当简单。我们需要将`aurelia-app`属性移动到另一个元素，以便在应用程序被渲染时，`body`元素的內容不会被清除：

`index.html`

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <!-- Omitted snippet... --> 
  </head> 
  <body> 
    <div aurelia-app="main"> 
      <!-- Omitted snippet... --> 
    </div> 
  </body> 
</html> 

```

现在，如果您刷新浏览器然后执行某些操作，例如更新一个联系人，您应该会在视图区域的顶部看到一个通知显示几秒钟。

### 注意

作为一个经验法则，我从不直接在`body`中放置`aurelia-app`属性。我通过多次花费太多时间试图弄清楚为什么我项目中集成的外部库不起作用而学到了这个教训。

### 模拟多用户场景

至此，我们的应用程序能够在服务器上发生更改时通知用户，即使这是由另一个用户完成的。让我们测试一个多用户场景。为此，应用程序必须使用除了 Aurelia 的 CLI 之外的东西运行，因为截至撰写本文时，浏览器同步功能会与我们的一致性机制发生冲突。

最简单的解决方案是安装`http-server`节点模块，如果你还没有安装，可以通过运行以下命令来安装：

```js
> npm install -g http-server

```

然后，你可以构建我们的应用程序：

```js
> au build

```

一旦这个命令完成，你可以启动一个简单的 HTTP 服务器：

```js
> http-server -o -c-1

```

然后，你可以在两个浏览器窗口中打开应用程序，并将它们并排放置。在一个窗口中执行创建新联系人或更新现有联系人的操作。你应该会在两个窗口中都看到通知弹出。

## 使用共享服务

目前，我们的应用程序大部分是无状态的，因为每个路由组件都从服务器加载其数据。没有路由组件依赖于其范围之外的全局状态。

然而，有时应用程序需要存储一个全局状态。这个状态通常由某种服务管理，可以通过数据绑定将状态传播给组件，或者通过依赖注入系统将它们注入，在这种情况下，依赖关系在 JS 代码中声明和控制，而不是在模板中。

有很多场景在本地存储状态是有利的，甚至是必需的。它可以让节省带宽，减少对后端的调用。如果你想让你的应用离线可用，你可能需要在某个时候本地存储一个状态。

在本节中，我们将通过创建一个服务来重构我们的应用程序，这个服务将被所有路由组件共享，并允许它们访问相同的本地数据。这个服务将作为本地数据存储，并依赖于我们在上一节中创建的分发器发布的事件来初始化其状态并与服务器的状态保持同步。

### 创建内存中的存储

我们将通过创建一个名为`ContactStore`的新服务来开始我们的重构：

`src/contacts/services/store.js`

```js
import {inject} from 'aurelia-framework'; 
import {EventAggregator} from 'aurelia-event-aggregator';  
import {Contact} from '../models/contact'; 

@inject(EventAggregator) 
export class ContactStore { 

  contacts = []; 

  constructor(eventAggregator) { 
    this.eventAggregator = eventAggregator; 
  } 

  activate() { 
    this.subscriptions = []; 
  } 

  detached() { 
    this.subscriptions.forEach(s => s.dispose()); 
    this.subscriptions = null; 
  } 

  getById(id) { 
    const index = this.contacts.findIndex(c => c.id == id); 
    if (index < 0) { 
      return Promise.reject(); 
    } 
    return Promise.resolve(Contact.fromObject(this.contacts[index])); 
  } 
} 

```

这个存储首先声明了一个`contacts`属性，它被赋值为一个空数组。这个数组将包含联系人列表的本地副本。接下来，该类期望一个`EventAggregator`实例在其构造函数中被注入，然后存储在`eventAggregator`属性上。

然后，该类定义了一个`activate`方法，它将在聚合器上订阅一些事件，以及一个`deactivate`方法，它将解除这些订阅。这是我们编写通知组件时实现的模式。

`ContactStore`还暴露了一个`getById`方法，该方法期望一个联系人的`id`作为其参数，如果找不到联系人，则返回一个拒绝的`Promise`，如果找到了，则返回一个使用联系人的副本解决的`Promise`。这个方法将被一些路由组件用来代替网关的`getById`方法，所以它模仿了其签名，以最小化我们必须做的更改。

现在`activate`方法需要添加一些事件订阅，以便它可以响应它们：

`src/contacts/services/store.js`

```js
// Omitted snippet... 
export class ContactStore { 
  // Omitted snippet... 

  activate() { 
    this.subscriptions = [ 
      eventAggregator.subscribe('contacts.loaded', e => { 
 this.contacts.splice(0); 
 this.contacts.push.apply(this.contacts, e.contacts); 
 }), 
 eventAggregator.subscribe('contact.created', e => { 
 const index = this.contacts.findIndex(c => c.id == e.contact.id); 
 if (index < 0) { 
 this.contacts.push(e.contact); 
 } 
 }), 
 eventAggregator.subscribe('contact.updated', e => { 
 const index = this.contacts.findIndex(c => c.id == e.contact.id); 
 if (index >= 0) { 
 Object.assign(this.contacts[index], e.contact); 
 } 
 }), 
 eventAggregator.subscribe('contact.deleted', e => { 
 const index = this.contacts.findIndex(c => c.id == e.contact.id); 
 if (index >= 0) { 
 this.contacts.splice(index, 1); 
 } 
 }), 
    ]; 
  } 

  // Omitted snippet... 
} 

```

在这里，`activate`方法订阅了分发器发布的各种事件，以便它可以保持其联系人列表的最新：

+   当他接收到`contacts.loaded`事件时，它使用事件负载中包含的新联系人列表重置`contacts`数组

+   当他接收到`contact.created`事件时，它首先确保联系人不已经在数组中使用其`id`，如果不在，则添加它

+   当他接收到`contact.updated`事件时，它使用其`id`检索更新后的联系人的本地副本并更新其所有属性

+   当他接收到`contact.deleted`事件时，他在数组中找到联系人的索引，总是使用它的`id`，并把它拿出来

这个存储现在能够从服务器检索联系人的本地列表，并保持自己最新。

### 使用存储

我们现在可以修改所有执行读操作的路由组件，使它们使用这个存储而不是网关。让我们逐一进行。

首先，`creation`组件不需要更改。

接下来，必须修改`details`、`edition`和`photo`组件。对于它们中的每一个，我们需要做的是：

1.  导入`ContactStore`类

1.  在`inject`装饰器中添加`ContactStore`类，以便在构造函数中注入

1.  在构造函数中添加一个`store`参数

1.  在构造函数中，将`store`参数分配给`store`属性

1.  在`activate`方法中，用对`store`的调用替换对`gateway`的`getById`方法的调用

以下是更改后的`details`组件的样子：

`src/contacts/components/details.js`

```js
import {inject} from 'aurelia-framework'; 
import {Router} from 'aurelia-router'; 
import {ContactStore} from '../services/store'; 
import {ContactGateway} from '../services/gateway'; 

@inject(ContactStore, ContactGateway, Router) 
export class ContactDetails { 

  constructor(store, gateway, router) { 
    this.store = store; 
    this.gateway = gateway; 
    this.router = router; 
  } 

  activate(params, config) { 
    return this.store.getById(params.id).then(contact => { 
      this.contact = contact; 
      config.navModel.setTitle(this.contact.fullName); 
    }); 
  } 

  tryDelete() { 
    if (confirm('Do you want to delete this contact?')) { 
      this.gateway.delete(this.contact.id) 
        .then(() => { this.router.navigateToRoute('contacts'); }); 
    } 
  } 
} 

```

注意`gateway`上`delete`操作仍然被调用。实际上，所有的写操作仍然使用`ContactGateway`类执行。然而，所有的读操作现在将使用`ContactStore`服务执行，因为它保持了与服务器状态同步的本地副本。

因此，最后，`list`组件也必须进行修改。我们需要做的是：

1.  将`ContactGateway`导入更改为`ContactStore`导入

1.  在`inject`装饰器中将`ContactGateway`类的依赖更改为`ContactStore`类

1.  删除`contacts`属性声明和初始化

1.  将构造函数的`gateway`参数替换为`store`参数

1.  在构造函数中，通过将`store`参数的`contacts`属性分配给`this.contacts`来删除`gateway`属性的分配

1.  删除`activate`回调方法

新的`list`组件现在已经简化为最小：

`src/contacts/components/list.js`

```js
import {inject, computedFrom} from 'aurelia-framework'; 
import {ContactStore} from '../services/store'; 

@inject(ContactStore) 
export class ContactList { 

  constructor(store) { 
    this.contacts = store.contacts; 
  } 
} 

```

我们可以在这里看到状态共享的核心。`store`的`contacts`属性包含一个数组，它是实际的状态持有者。正是这个数组，通过`ContactStore`实例在组件之间共享，使得相同的数据可以从不同的屏幕访问。因此，这个数组绝不应该被覆盖，只能被变异，以便 Aurelia 的绑定系统能够与之无缝工作。

然而，我们仍然需要在某个地方`activate``ContactStore`实例，以便它开始监听变更事件。让我们在特性的`configure`函数中，在我们激活事件分发器之前这样做：

`src/contacts/index.js`

```js
import {Router} from 'aurelia-router';  
import {ContactStore} from './services/store'; 
import {ContactEventDispatcher} from './services/event-dispatcher'; 

export function configure(config) { 
  const router = config.container.get(Router); 
  router.addRoute({ route: 'contacts', name: 'contacts', moduleId: 'contacts/main', nav: true, title: 'Contacts' }); 

  config.postTask(() => { 
    const store = config.container.get(ContactStore); 
 store.activate(); 

    const dispatcher = config.container.get(ContactEventDispatcher); 
    return dispatcher.activate(); 
  }); 
} 

```

在这里，我们通过检索来强制 DI 容器初始化唯一的`ContactStore`实例，然后简单地`activate`它。

最后，我们还可以去删除`ContactGateway`类中的`getAll`和`getById`方法，因为它们已经不再使用了。

在此阶段，如果你运行应用程序，一切应该仍然和以前一样工作。

# 总结

设计有价值的应用程序几乎从来不是简单的。它总是关于权衡许多因素，决定哪些利弊是有益的，哪些是可以接受的：

+   子路由使得顶部菜单的活动项目表现更好，而根路由则不然。

+   子路由使得跨特性拥有链接变得困难，而根路由则使之变得容易。

+   特性有助于在 Aurelia 应用程序中隔离和集成领域或技术特性。

+   数据绑定是连接组件的最简单方法。然而，它有局限性。

+   使用一个删除服务来通信数据是让组件通信的另一种非常简单的方法。然而，它可能会占用带宽，可能会对远程服务造成一些负载，并且使远程服务器成为单点故障，如果用户没有网络连接或远程服务宕机，应用程序将无法使用。

+   将服务共享给组件以实现通信是多功能的，但增加了复杂性。

+   使用事件来让组件进行通信增加了可扩展性和解耦，但也增加了复杂性。在大型应用程序中，需要有纪律性，以便事件容易被发现。

有些利弊可能看起来很微小，我倾向于同意，在大多数情况下，一个菜单项不是一直高亮显示并不是什么大问题，但在一些项目中这可能无法接受。我所能做的就是给你提供工具，让你自己做出明智的决策。


# 第七章：测试所有事物

自动化测试已经成为大多数现代软件开发过程的重要组成部分。敏捷方法论和软件工艺等方法强调自动化测试的重要性，并经常提倡进行全面测试驱动开发（TDD）的实践。

一套良好的自动化测试可以为项目增加巨大价值，因为它确保了任何破坏现有特性的代码更改都不会被忽视。因此，测试建立了信心。多亏了它们，开发者才不怕更改事物，玩转想法，重构，让代码变得更好。他们控制着自己的代码库。

无论你是否实践 TDD，你可能都希望对你的 Aurelia 应用进行一定程度的自动测试。这就是这一章要讲的内容。

为了使测试 Aurelia 项目更容易，Aurelia 团队选择了一组通常用于测试 JavaScript 项目的库**Jasmine**、**Karma**和**Protractor**，并将它们包括在项目骨架和 CLI 项目生成器中，以及它们相应的配置和项目中的测试运行任务。

+   Jasmine 是一个流行的 JS 测试框架，我们将用它来进行单元测试和端到端测试。它的位置在 [`jasmine.github.io/`](http://jasmine.github.io/)。

+   Karma 是一个测试运行器，被测试任务在幕后使用。它的位置在 [`karma-runner.github.io/`](https://karma-runner.github.io/)。

+   Protractor 是一个端到端测试框架，提供了一个丰富的 API 来与浏览器交互。它的位置在 [`www.protractortest.org/`](http://www.protractortest.org/)。

# 单元测试

在下一节中，我们将探讨如何对 Aurelia 应用进行单元测试，主要是通过在我们的联系人管理应用中添加单元测试。

### 注意

如果你不熟悉 Jasmine，你应该将其文档放在手边，因为阅读这一章时你可能需要查阅： [`jasmine.github.io/2.0/introduction.html`](http://jasmine.github.io/2.0/introduction.html)。

## 运行单元测试

使用 CLI 创建的项目包括一个运行单元测试的任务。这个任务定义在`aurelia_project/tasks/test.js`文件中，它只是使用位于项目根目录的配置文件`karma.conf.js`来启动 Karma。

这个任务可以通过在项目目录中打开控制台并运行以下命令来执行：

```js
> au test

```

这个命令将启动单个测试运行，并在控制台输出结果。

与 `run` 任务类似，`test` 任务可以通过添加 `watch` 开关来修改，使其监视测试文件，并在检测到任何更改时重新运行：

```js
> au test --watch

```

这个命令将启动一个测试运行，并监视测试文件，在每次更改后重新运行测试。

## 配置验证

如果你查看了`aurelia-validation`的代码，你可能会注意到这个插件需要在`ValidationRules`类使用之前加载。这是因为`ValidationRules`暴露的方法需要类的静态初始化，用一个`ValidationParser`实例，以便在错误消息中解析字符串插值等。

由于我们的模型类，如`Contact`、`PhoneNumber`、`Address`等，在其构造函数中依赖于`ValidationRules`类，如果我们不首先初始化它，我们将无法在任何一个测试中使用这些模型类。另外，我们的自定义验证规则在使用之前也必须加载。

因此，让我们添加一个设置文件，它将在每次测试运行开始时初始化验证：

`test/unit/setup-validation.js`

```js
import {Container} from 'aurelia-dependency-injection'; 
import {BindingLanguage} from 'aurelia-templating'; 
import {TemplatingBindingLanguage}  
  from 'aurelia-templating-binding'; 
import {ValidationParser, ValidationRules}  
  from 'aurelia-validation'; 
import '../../src/validation/rules'; 

const container = new Container(); 
container.registerSingleton( 
  BindingLanguage, TemplatingBindingLanguage); 
const parser = container.invoke(ValidationParser); 
ValidationRules.initialize(parser); 

```

在这里，我们首先导入`rules`文件，以便我们的自定义验证规则被正确注册。

接下来，我们将创建一个 DI 容器并初始化解析器所需的绑定语言实现，然后使用它来创建一个`ValidationParser`实例，我们用它来初始化`ValidationRules`类。

最后，让我们将此文件添加到单元测试设置中：

`test/aurelia-karma.js`

```js
//Omitted snippet... 
function requireTests() { 
  var TEST_REGEXP = /(spec)\.js$/i; 
  var allTestFiles = [ 
    '/base/test/unit/setup.js', 
    '/base/test/unit/setup-validation.js' 
  ]; 

  Object.keys(window.__karma__.files).forEach(function(file) { 
    if (TEST_REGEXP.test(file)) { 
      allTestFiles.push(file); 
    } 
  }); 

  require(allTestFiles, window.__karma__.start); 
} 
//Omitted snippet... 

```

在这里，我们只需将`setup-validation.js`文件添加到 Karma 在开始测试运行时使用`require`加载的文件列表中。

## 配置 Bluebird 警告

让我们也配置 Bluebird Promise 库的警告，以便我们的控制台不会充斥着警告：

`test/unit/setup.js`

```js
import 'aurelia-polyfills'; 
import {initialize} from 'aurelia-pal-browser'; 
initialize(); 

Promise.config({ 
  warnings: { 
    wForgottenReturn: false 
  } 
}); 

```

在这里，我们只需复制并粘贴`src/main.js`顶部的`Promise`配置。

在这个阶段，我们可以开始舒适地编写单元测试。

### 注意

`test/unit/app.spec.js`文件包含了由 CLI 在初始化项目时创建的`app`组件的示例测试。因为自我们开始以来这个组件已经完全改变了，所以这些测试不再相关并且会失败，所以你应该删除这个文件。

按照约定，包含单元测试的文件具有`.spec.js`扩展名。Aurelia 项目中的默认 Karma 配置期望测试位于遵循此命名约定的文件中，因此在我们联系管理应用程序中我们将遵循这一约定。

## 模型单元测试

我们将首先测试模型类。它们包含一些关键功能，我们想确保它们能正常工作。

然而，让我们首先确保我们的包是最新的，通过打开一个控制台并运行一个构建：

```js
> au build

```

然后，为了让编写测试的过程更加流畅，让我们首先启动一个控制台并开始持续测试过程：

```js
> au test -watch

```

任务应该开始运行，并且应该显示类似这样的内容：

```js
Chrome 53.0.2785 (Windows 10 0.0.0): Executed 0 of 0 ERROR (0.015 secs / 0 secs)

```

测试运行返回一个错误，因为它找不到要运行的任何测试。让我们改变这个。

### 测试静态工厂方法

我们要写的第一个测试将确保用一个空对象调用`fromObject`方法创建一个空的`PhoneNumber`对象：

`test/unit/contacts/models/phone-number.spec.js`

```js
import {PhoneNumber} from '../../../../src/contacts/models/phone-number'; 

describe('the PhoneNumber class', () => { 
  it('should create empty PhoneNumber when creating from empty object',  
  () => { 
    const result = PhoneNumber.fromObject({}); 
    expect(result).toEqual(new PhoneNumber()); 
  }); 
}); 

```

在这里，我们定义了一个测试用例，使用一个空对象调用`fromObject`静态方法，然后确保结果等于一个空`PhoneNumber`对象。

如果你保存文件并查看控制台，你应该会看到类似这样的消息：

```js
Chrome 53.0.2785 (Windows 10 0.0.0): Executed 1 of 1 SUCCESS (0.016 secs / 0.008 secs)

```

让我们再写一个测试，测试`fromObject`方法的另一个角度。它会确保标量属性被正确地复制到新的`PhoneNumber`对象中：

`test/unit/contacts/models/phone-number.spec.js`

```js
import {PhoneNumber} from '../../../../src/contacts/models/phone-number'; 

describe('the PhoneNumber class', () => { 
  //Omitted snippet... 

  it('should map all properties when creating from object', () => { 
    const src = { 
      type: 'Mobile', 
      number: '1234567890' 
    }; 
    const result = PhoneNumber.fromObject(src);
for (let property in src) { 
      expect(result[property]).toEqual(src[property]); 
    } 
  }); 
}); 

```

在这里，我们的新测试使用一个具有预期标量属性的对象调用`fromObject`静态方法：`type`和`number`。然后，我们确保每个属性都被正确地复制到结果的`PhoneNumber`对象中。

这样的测试也应添加到`EmailAddress`、`Address`和`SocialProfile`类中，每个类在自己的文件中：`email-address.spec.js`、`address.spec.js`和`social-profile.spec.js`，遵循相同的模式。我将留下这个作为读者的练习。本章节的示例应用程序可以作为参考。

既然已经测试了列表项类，让我们为`Contact`类写测试。我们从之前写的相同类型的测试开始：

`test/unit/contacts/models/contact.spec.js`

```js
import {Contact} from '../../../../src/contacts/models/contact'; 

describe('the Contact class', () => { 

  it('should create empty Contact when creating from empty object', () => { 
    const result = Contact.fromObject({}); 
    expect(result).toEqual(new Contact()); 
  }); 

  it('should map all properties when creating from object', () => { 
    const src = { 
      firstName: 'Never gonna give you up', 
      lastName: 'Never gonna let you down', 
      company: 'Never gonna run around and desert you', 
      birthDay: '1987-11-16', 
      note: 'Looks like you've been rickrolled' 
    }; 
    const result = Contact.fromObject(src); 

    for (let property in src) { 
      expect(result[property]).toEqual(src[property]); 
    } 
  }); 
}); 

```

然而，`Contact`类的`fromObject`方法不仅仅是复制属性，它还将列表项映射到相应的模型类。让我们添加一些测试来确保这能正常工作：

`test/unit/contacts/models/contact.spec.js`

```js
import {Contact} from '../../../../src/contacts/models/contact'; 
import {Address} from '../../../../src/contacts/models/address'; 
import {EmailAddress} from '../../../../src/contacts/models/email-address'; 
import {PhoneNumber} from '../../../../src/contacts/models/phone-number'; 
import {SocialProfile} from '../../../../src/contacts/models/social-profile'; 

describe('the Contact class', () => { 
  //Omitted snippet... 

  it ('should map phone numbers when creating from object', () => { 
    const result = Contact.fromObject({ phoneNumbers: [{}, {}] }); 
    const expected = [new PhoneNumber(), new PhoneNumber()]; 

    expect(result.phoneNumbers).toEqual(expected); 
  }); 

  it ('should map email addresses when creating from object', () => { 
    const result = Contact.fromObject({ emailAddresses: [{}, {}] }); 
    const expected = [new EmailAddress(), new EmailAddress()]; 

    expect(result.emailAddresses).toEqual(expected); 
  }); 

  it ('should map addresses when creating from object', () => { 
    const result = Contact.fromObject({ addresses: [{}, {}] }); 
    const expected = [new Address(), new Address()]; 

    expect(result.addresses).toEqual(expected); 
  });
it ('should map social profiles when creating from object', () => { 
    const result = Contact.fromObject({ socialProfiles: [{}, {}] }); 
    const expected = [new SocialProfile(), new SocialProfile()];
expect(result.socialProfiles).toEqual(expected); 
  }); 
}); 

```

在这里，我们添加了列表项类的`import`语句。然后我们添加了四个测试用例，每个测试用例对应一个列表项类，确保每个情况下对象数组被正确地映射到相应的类中。

### 测试计算属性

当涉及到单元测试时，计算属性与函数没有什么不同。让我们写一些测试来覆盖`Contact`类的`isPerson`属性：

`test/unit/contacts/models/contact.spec.js`

```js
//Omitted snippet... 
it('should be a person if it has a firstName and no lastName', () => { 
  const sut = Contact.fromObject({ firstName: 'A first name' }); 
  expect(sut.isPerson).toBeTruthy(); 
}); 

it('should be a person if it has a lastName and no firstName', () => { 
  const sut = Contact.fromObject({ lastName: 'A last name' }); 
  expect(sut.isPerson).toBeTruthy(); 
}); 

it('should be a person if it has a firstName and a lastName', () => { 
  const sut = Contact.fromObject({  
    firstName: 'A first name', 
    lastName: 'A last name' 
  }); 
  expect(sut.isPerson).toBeTruthy(); 
}); 

it('should not be a person if it has no firstName and no lastName', () => { 
  const sut = Contact.fromObject({ company: 'A company' }); 
  expect(sut.isPerson).toBeFalsy(); 
}); 
//Omitted snippet... 

```

在这里，我们添加了四个测试用例，以确保`isPerson`属性正确地行为。

### 注意

存储测试将应用的实例的变量名为`sut`，代表被测试的系统。许多自动化测试的作者认为这是一个标准术语。我喜欢使用这个缩写，因为它能清楚地标识测试的对象。

我将留给读者作为练习来编写`fullName`和`firstLetter`属性的测试用例。本章节的示例应用程序可以作为参考。

## 单元测试服务

测试服务也是非常直接的。在我们的联系人管理应用程序中，我们有一个服务：`ContactGateway`。然而目前它并不是非常便于测试，主要问题是它的构造函数，它配置了`HttpClient`实例。

### 从网关构造函数中移除配置

让我们重构我们的网关，使其更容易测试。我们将把`HttpClient`的配置移动到功能的`configure`函数中，这样`ContactGateway`的构造函数就不包含任何配置逻辑：

`src/contacts/index.js`

```js
import {Router} from 'aurelia-router'; 
import {HttpClient} from 'aurelia-fetch-client'; 
import {ContactGateway} from './services/gateway'; 
import environment from 'environment'; 

export function configure(config) { 
  const router = config.container.get(Router); 
  router.addRoute({ route: 'contacts', name: 'contacts',  
    moduleId: 'contacts/main', nav: true, title: 'Contacts' }); 

  const httpClient = config.container.invoke(HttpClient) 
    .configure(config => { config 
      .useStandardConfiguration() 
      .withBaseUrl(environment.contactsUrl); 
    }); 
  config.container.registerInstance(ContactGateway,  
    new ContactGateway(httpClient)); 
} 

```

在这里，我们使用 DI 容器创建一个`HttpClient`实例并对其进行配置，然后创建一个`ContactGateway`实例，我们在 DI 容器中注册它。您可能会注意到我们没有在容器中注册`HttpClient`本身。在大多数应用程序中，这样做是完全没问题的。然而，由于我们希望功能尽可能独立，其他功能可能会使用不同的`HttpClient`实例来调用不同的后端，所以我们不注册这个，因为它可能会与其他功能发生冲突。

接下来，我们可以从`ContactGateway`的构造函数中删除配置代码：

`src/contacts/services/gateway.js`

```js
import {inject} from 'aurelia-framework'; 
import {HttpClient, json} from 'aurelia-fetch-client'; 
import {Contact} from '../models/contact'; 

@inject(HttpClient) 
export class ContactGateway { 

  constructor(httpClient) { 
    this.httpClient = httpClient; 
  } 

  //Omitted snippet... 
} 

```

`ContactGateway`的构造函数现在没有任何配置逻辑。

自从我们在应用程序中更改了代码后，在添加测试之前我们需要重新构建它：

```js
> au build

```

### 测试读方法

让我们先为`ContactGateway`的两个读方法编写一些测试：

`test/unit/contacts/services/gateway.spec.js`

```js
import {ContactGateway}  
  from '../../../../src/contacts/services/gateway';  
import {Contact} from '../../../../src/contacts/models/contact'; 

describe('the ContactGateway class', () => { 

  let httpClient, sut; 

  beforeEach(() => { 
    httpClient = jasmine.createSpyObj('HttpClient', ['fetch']); 
    sut = new ContactGateway(httpClient); 
  }); 

  function createContact() { 
    return Contact.fromObject({ id: 1, company: 'Blue Spire' }); 
  } 

  function createJsonResponseMock(content) { 
    return { json: () => Promise.resolve(content) }; 
  } 

  it('should fetch all contacts', done => { 
    const contacts = [createContact()]; 
    httpClient.fetch.and.returnValue(Promise.resolve( 
      createJsonResponseMock(contacts))); 

    sut.getAll() 
      .then(result => expect(result).toEqual(contacts)) 
      .then(() => expect(httpClient.fetch) 
        .toHaveBeenCalledWith('contacts')) 
      .then(done); 
  }); 

  it('should fetch a contact by its id', done => { 
    const contact = createContact(); 
    httpClient.fetch.and.returnValue(Promise.resolve( 
      createJsonResponseMock(contact))); 

    sut.getById(contact.id) 
      .then(result => expect(result).toEqual(contact)) 
      .then(() => expect(httpClient.fetch) 
        .toHaveBeenCalledWith(`contacts/${contact.id}`)) 
      .then(done); 
  }); 
}); 

```

在这里，我们首先使用 Jasmine 的`beforeEach`函数定义一个测试设置。这个测试设置将在每个测试用例之前执行。在这个设置中，我们首先为`HttpClient`创建一个模拟对象，然后我们创建一个`ContactGateway`实例，我们的测试将对其进行操作。

接下来，我们定义了两个帮助函数：第一个用于创建一个`Contact`对象，第二个用于创建一个具有 JSON 正文的响应对象的模拟。这两个函数将被我们的测试用例使用。

最后，我们编写测试用例以验证`getAll`和`getById`方法是否正常工作。这两个测试用例都是异步测试，所以它们需要一个`done`函数作为参数，当测试完成后它们将调用这个函数。它们都遵循相同的模式：

1.  创建应该由测试方法返回的`Contact`对象。

1.  配置模拟的`HttpClient`的`fetch`方法，使其返回一个`Promise`，该`Promise`解析为一个模拟的响应对象，它暴露出作为 JSON 正文返回的数据。

1.  调用测试方法，当它解析时：

+   检查返回的`Promise`解析为预期的数据

+   检查`HttpClient`的`fetch`方法是否用适当的参数调用

### 测试写方法

测试写方法相当相似。然而，它需要做一些额外的工作，因为目前 HTML5 File API 没有提供一种简单的方法来比较`Blob`对象。所以为了测试我们网关发送的请求的正文，我们需要编写一些帮助函数：

`test/unit/contacts/services/gateway.spec.js`

```js
//Omitted snippet... 

function readBlob(blob) { 
  return new Promise(resolve => { 
    let reader = new FileReader(); 
    reader.addEventListener("loadend", () => {  
      resolve(reader.result); 
    }); 
    reader.readAsText(blob); 
  }); 
} 

function expectBlobsToBeEqual(result, expected) { 
  expect(result.type).toEqual(expected.type); 
  expect(result.size).toEqual(expected.size); 

  return Promise 
    .all([ readBlob(result), readBlob(expected) ]) 
    .then(([c1, c2]) => expect(c1).toEqual(c2)); 
} 

function expectFetchToHaveBeenCalled(expectedPath,  
                                     expectedProperties) { 
  let expectedBody; 
  if (expectedProperties.body) { 
    expectedBody = expectedProperties.body; 
    delete expectedProperties.body; 
  } 

  expect(httpClient.fetch).toHaveBeenCalledWith(expectedPath,    
    jasmine.objectContaining(expectedProperties)); 
  if (expectedBody) { 
    return expectBlobsToBeEqual( 
      httpClient.fetch.calls.mostRecent().args[1].body,  
      expectedBody); 
  } 
} 
//Omitted snippet... 

```

第一个助手函数，名为`readBlob`，简单地接受一个`Blob`对象作为其参数，并返回一个`Promise`，该`Promise`解析为`Blob`内容作为一个字符串。由于读取`Blob`内容的过程是异步的，它只是用一个`Promise`包装这个过程。

第二个助手函数，名为`expectBlobsToBeEqual`，期望两个`Blob`对象作为其参数。它首先比较它们的`type`和`size`属性以确保它们相等，然后使用`readBlob`来检索两个`Blob`对象的内容并比较结果以确保它们也相等，返回结果`Promise`。

最后一个助手函数，名为`expectFetchToHaveBeenCalled`，接收预期的路径和预期的请求属性。它首先从预期的请求属性中提取预期的主体，如果有，从对象中删除它。然后，它确保`HttpClient`的模拟`fetch`方法已经用预期的路径和减去主体的预期请求属性被调用，因为比较`Blob`对象是一个必须单独执行的异步过程。最后，如果提供了预期的主体，它使用传递给最后一个`fetch`调用的主体和预期的主体调用`expectBlobsToBeEqual`函数，并返回结果`Promise`。

这个最后的助手函数将帮助我们编写关于我们的网关如何调用其`HttpClient`的`fetch`方法的断言。让我们从一个`create`方法的测试开始：

`test/unit/contacts/services/gateway.spec.js`

```js
import {json} from 'aurelia-fetch-client'; 
//Omitted snippet... 

it('should create a contact', done => { 
  const contact = createContact(); 
  httpClient.fetch.and.returnValue(Promise.resolve()); 

  sut.create(contact) 
    .then(() => expectFetchToHaveBeenCalled( 
      'contacts',  
      { method: 'POST', body: json(contact) })) 
    .then(done); 
}); 
//Omitted snippet... 

```

在这里，我们首先从 Fetch 客户端导入`json`函数。我们将使用它将预期的请求负载转换为 JSON 编码的`Blob`对象。

这个测试本身相当直接，为接下来的测试设定了路径，这些测试将遵循相同的模式：

1.  创建一个`Contact`对象，将被传递给被测试的方法。

1.  配置`HttpClient`的模拟`fetch`方法，使其返回一个解决的`Promise`。

1.  调用被测试的方法，当它解决时，检查`HttpClient`的`fetch`方法是否用正确的参数被调用。

`update`和`updatePhoto`方法的压力测试非常相似：

`test/unit/contacts/services/gateway.spec.js`

```js
//Omitted snippet... 
it('should update a contact', done => { 
  const contact = createContact(); 
  httpClient.fetch.and.returnValue(Promise.resolve()); 

  sut.update(contact.id, contact) 
    .then(() => expectFetchToHaveBeenCalled( 
      `contacts/${contact.id}`,  
      { method: 'PUT', body: json(contact) })) 
    .then(done); 
}); 

it("should update a contact's photo", done => { 
  const id = 9; 
  const contentType = 'image/png'; 
  const file = new File(['some binary content'], 'img.png', { 
    type: contentType 
  }); 
  httpClient.fetch.and.returnValue(Promise.resolve()); 

  const expectedRequestProperties = { 
    method: 'PUT', 
    headers: { 'Content-Type': contentType }, 
    body: file 
  }; 
  sut.updatePhoto(id, file) 
    .then(() => expectFetchToHaveBeenCalled( 
      `contacts/${id}/photo`,  
      expectedRequestProperties)) 
    .then(done); 
}); 
//Omitted snippet... 

```

这两个测试遵循与之前一个相同的模式。

## 对值转换器进行单元测试

测试值转换器与测试服务并没有太大区别。当然，这取决于你需要测试的转换器的复杂性。在我们的联系人管理应用程序中，值转换器相当简单。

让我们为我们的`orderBy`值转换器写一个或两个测试来了解一下它：

`test/unit/resources/value-converters/order-by.spec.js`

```js
import {OrderByValueConverter}  
  from '../../../../src/resources/value-converters/order-by'; 

describe('the orderBy value converter', () => { 
  let sut; 

  beforeEach(() => { 
    sut = new OrderByValueConverter(); 
  }); 

  it('should sort values using property', () => { 
    const array = [ { v: 3 }, { v: 2 }, { v: 4 }, { v: 1 }, ]; 
    const expectedResult = [ { v: 1 }, { v: 2 },  
      { v: 3 }, { v: 4 }, ]; 

    const result = sut.toView(array, 'v'); 

    expect(result).toEqual(expectedResult); 
  }); 

  it('should sort values in reverse order when direction is "desc"', () => { 
    const array = [ { v: 3 }, { v: 2 }, { v: 4 }, { v: 1 }, ]; 
    const expectedResult = [ { v: 4 }, { v: 3 },  
      { v: 2 }, { v: 1 }, ]; 

    const result = sut.toView(array, 'v', 'desc'); 

    expect(result).toEqual(expectedResult); 
  }); 
}); 

```

在这里，我们首先定义一个简单的测试设置，创建测试主题，然后我们添加两个测试用例。第一个验证传递给`toView`方法的数组是否正确地使用指定的属性进行排序。第二个验证当`"desc"`作为第三个参数传递时，传递给`toView`方法的数组是否按降序排序。

当然，如果测试支持的值转换器支持双向绑定并且有一个`fromView`方法，应该添加额外的测试用例来涵盖这个第二个方法。

我将留给读者一个练习，为`groupBy`和`filterBy`值转换器编写测试。本章的示例应用程序可以作为参考。

## 单元测试自定义元素和属性

到目前为止我们所写的所有测试都与 Aurelia 关系不大。我们测试的代码可以在一个完全不同的 UI 框架中使用，而且很可能不需要做任何改变。这是因为我们还没有测试任何视觉方面。

当测试自定义元素和属性时，我们可能会满足于我们之前编写的测试类型，并且只测试它们的视图模型。这些测试将只涵盖组件的行为方面。然而，能够涵盖组件整体的测试，包括它们的视图对应部分，将会更加强大。

### 组件测试器

幸运的是，Aurelia 提供了`aurelia-testing`库，可以用来全面测试组件。因此，它导出两个重要的类：`StageComponent`和`ComponentTester`。

`StageComponent`类有一个单一的静态方法：

```js
withResources(resources: string | string[]): ComponentTester 

```

这个方法简单地在幕后创建一个`ComponentTester`类的实例，调用它自己的`withResources`方法，然后返回它。`StageComponent`基本上只是对组件测试器的 API 糖。以下两行可以互换而不产生任何效果：

```js
var tester = StageComponent.withResources('some/resources') 
var tester = new ComponentTester().withResources('some/resources') 

```

`ComponentTester`类提供了一个 API 来配置一个短暂存在的、沙盒化的 Aurelia 应用程序，在该应用程序中，被测试的组件将在测试期间运行：

+   `withResources(resources: string | string[]): ComponentTester`: 将提供的资源作为全局资源加载到沙盒应用程序中。

+   `inView(html: string): ComponentTester`: 使用提供的 HTML 作为沙盒应用程序的根视图。

+   `boundTo(bindingContext: any): ComponentTester`: 使用提供的值作为沙盒应用程序的根视图的绑定上下文。

+   `manuallyHandleLifecycle(): ComponentTester`: 告诉组件测试器应用程序的生命周期应该由测试用例手动处理。

+   `bootstrap(configure: (aurelia: Aurelia) => void): void`: 使用提供的函数配置沙盒 Aurelia 应用程序。默认情况下，应用程序使用`aurelia.use.standardConfiguration()`进行配置。这个方法可以用来加载组件所需的额外插件或功能。

+   `create(bootstrap: (aurelia: Aurelia) => Promise<void>): Promise<void>`：使用提供的引导函数创建沙盒应用程序。通常，这里会使用`aurelia-bootstrapper`库的`bootstrap`函数。返回的`Promise`在应用程序加载并启动后解决。

+   `bind(): Promise<void>`：绑定沙盒应用程序。它只能在手动处理应用程序生命周期时使用。

+   `attached(): Promise<void>`：将沙盒应用程序附加到 DOM。它只能在手动处理应用程序生命周期时使用。

+   `detached(): Promise<void>`：将沙盒应用程序从 DOM 中分离。它只能在手动处理应用程序生命周期时使用。

+   `unbind(): Promise<void>`：解绑沙盒应用程序。它只能在手动处理应用程序生命周期时使用。

+   `dispose()`：清理沙盒应用程序的所有资源并完全将其从 DOM 中移除。

在撰写本文时，`aurelia-testing`库仍处于测试阶段，因此在发布之前可能会向其添加一些新功能。

### 测试 file-drop-target 属性

让我们通过编写一个针对我们在第五章，*创建可复用组件*中编写的`file-drop-target`自定义属性的测试套件，看看如何使用组件测试器：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
import {StageComponent} from 'aurelia-testing'; 
import {bootstrap} from 'aurelia-bootstrapper'; 

describe('the file-drop-target custom attribute', () => { 

  let viewModel, component, element; 

  beforeEach(() => { 
    viewModel = { files: null }; 
    component = StageComponent 
      .withResources('resources/attributes/file-drop-target') 
      .inView('<div file-drop-target.bind="files"></div>') 
      .boundTo(viewModel); 
  }); 

  function create() { 
    return component.create(bootstrap).then(() => { 
      element = document 
        .querySelector('[file-drop-target\\.bind]'); 
    }); 
  } 

  afterEach(() => { 
    component.dispose(); 
  }); 
}); 

```

在这里，我们首先创建一个空的测试套件，它包含使用`beforeEach`函数的测试设置和使用`afterEach`函数的测试清理。在测试设置中，我们首先创建一个具有`files`属性的`viewModel`对象，该属性将绑定到我们的`file-drop-target`属性。其次，我们使用`StageComponent`类创建一个沙盒 Aurelia 应用程序，在该应用程序中，我们的自定义属性将在每次测试中运行。

这个沙盒应用程序将`file-drop-target`属性作为全局资源加载。其根视图将是一个带有`file-drop-target`属性的`div`元素，绑定到根绑定上下文的`files`属性，这将是`viewModel`对象。

我们还定义了一个`create`辅助函数，该函数将创建和引导沙盒应用程序，并在应用程序渲染后检索托管我们的`file-drop-target`属性的`element`。

最后，在测试清理过程中，我们只需`dispose`沙盒。

为了测试`file-drop-target`自定义属性，我们将需要在我们正在测试的属性托管的`element`上触发拖放事件。因此，让我们先编写一个工厂函数来创建此类事件：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
import {DOM} from 'aurelia-pal'; 
//Omitted snippet...  
function createDragEvent(type, dataTransfer) { 
  const e = DOM.createCustomEvent(type, { bubbles: true }); 
  e.dataTransfer = dataTransfer; 
  return e; 
} 
//Omitted snippet... 

```

这个函数相当直接。它只是使用作为参数传递的事件的`type`创建一个`Event`对象。它还告诉事件在触发时应该在 DOM 上冒泡。最后，它在返回之前将提供的`dataTransfer`对象分配给事件。

我们将在许多其他函数中使用这个函数，这些函数将用于触发拖放过程的各种步骤：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
//Omitted snippet... 
function dragOver() { 
  element.dispatchEvent(createDragEvent('dragover')); 
  return new Promise(setTimeout); 
} 

function drop(dataTransfer) { 
  element.dispatchEvent(createDragEvent('drop', dataTransfer)); 
  return new Promise(setTimeout); 
} 

function dragEnd(dataTransfer) { 
  element.dispatchEvent(createDragEvent('dragend', dataTransfer)); 
  return new Promise(setTimeout); 
} 
//Omitted snippet... 

```

这三个函数各自创建并派发一个特定的拖放事件。它们还返回一个`Promise`，其解决将在浏览器的事件队列被清空时发生。

更新绑定通常是一个异步过程，取决于绑定类型。Aurelia 的绑定引擎严重依赖于浏览器的事件循环，以使更新绑定的过程尽可能平滑。

因此，返回一个`Promise`，其`resolve`函数被推送到浏览器事件队列的末尾，使用`setTimeout`是一种在测试中使用的技术，以确保需要对属性进行更新或事件派发时，有足够的时间更新绑定。

最后，我们需要创建`File`对象以在我们的测试中使用：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
//Omitted snippet... 
function createFile() { 
  return new File( 
    ['some binary content'],  
    'test.txt',  
    { type: 'text/plain' }); 
} 
//Omitted snippet... 

```

现在我们有了编写第一个测试用例所需的所有工具：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
//Omitted snippet... 
it('should assign dropped files to bounded instruction', done => { 
  const files = [createFile()]; 

  create() 
    .then(() => dragOver()) 
    .then(() => drop({ files })) 
    .then(() => expect(viewModel.files).toEqual(files)) 
    .then(done); 
}); 
//Omitted snippet... 

```

这个测试确保，当拖动然后将一个文件列表拖放到承载我们自定义属性的元素上时，事件中的文件被分配给绑定属性的属性。

这个测试首先创建一个`files`列表并派发一个`dragover`事件，本身没有用，但只是为了遵循拖放操作的标准过程。接下来，它使用之前创建的`files`派发一个`drop`事件。最后，它确保`files`被正确分配给`viewModel`的`files`属性。

最后，让我们添加另一个测试用例，以确保事件数据被正确清除：

`test/unit/resources/attributes/file-drop-target.spec.js`

```js
//Omitted snippet... 
it('should clear data when drag ends', done => { 
  const files = [createFile()]; 
  const clearData = jasmine.createSpy('clearData'); 

  create() 
    .then(() => dragOver()) 
    .then(() => drop({ files })) 
    .then(() => dragEnd({ clearData })) 
    .then(() => expect(clearData).toHaveBeenCalled()) 
    .then(done); 
  }); 
//Omitted snippet... 

```

如果你现在运行测试，它们都应该通过。

### 测试 list-editor 元素

对自定义元素进行单元测试非常相似。让我们通过测试我们之前编写的`list-editor`自定义元素来看看它是如何工作的：

`test/unit/resources/elements/list-editor.spec.js`

```js
import {StageComponent} from 'aurelia-testing'; 
import {bootstrap} from 'aurelia-bootstrapper'; 

describe('the list-editor custom element', () => { 

  let items, createItem, component, element; 

  beforeEach(() => { 
    items = []; 
    createItem = jasmine.createSpy('createItem'); 
    component = StageComponent 
      .withResources('resources/elements/list-editor') 
      .inView(`<list-editor items.bind="items"  
          add-item.call="createItem()"></list-editor>`) 
      .boundTo({ items, createItem }); 
  }); 

  function create() { 
    return component.create(bootstrap).then(() => { 
      element = document.querySelector('list-editor'); 
    }); 
  } 

  afterEach(() => { 
    component.dispose(); 
  }); 
}); 

```

在这里，我们首先创建一个测试套件，它有一个创建一个空`items`数组的测试设置，并模拟一个用于创建新项目的函数。它还创建了一个组件测试器，将`list-editor`作为全局资源加载，在其根视图中使用`list-editor`元素，并将包含`items`数组和模拟的`createItem`函数的对象定义为根绑定上下文，该函数将绑定到`list-editor`实例。

我们还定义了一个`create`函数，它将创建并引导沙盒应用程序，在该应用程序中，测试元素将在每次测试期间运行。它在应用程序启动后还会检索`list-editor` DOM 元素。

最后，我们定义了一个测试清理函数，它将简单地`dispose`组件测试器。

当然，我们需要用项目作为对象。让我们创建一个简单的类，我们可以在测试用例中使用：

`test/unit/resources/elements/list-editor.spec.js`

```js
//Omitted snippet... 
class Item { 
  constructor(text) { 
    this.text = text; 
  } 

  toString() { 
    return this.text; 
  } 
} 

```

这个简单的`Item`类在构造函数中期望有一个`text`值，当转换为字符串时返回这个`text`。

在我们的测试中，我们需要检索由`list-editor`渲染的各种元素，以检查某些事情是否正确渲染，或者触发操作。因此，让我们在`list-editor`的视图中添加一些 CSS 类。这些类将帮助我们选择特定的元素，而不依赖于 HTML 结构本身，这会使测试变得脆弱，因为任何对 HTML 结构的更改都可能破坏它们。

`src/resources/elements/list-editor.html`

```js
<template> 
  <div class="form-group le-item" repeat.for="item of items"> 
    <template with.bind="item"> 
      <template replaceable part="item"> 
        <div class="col-sm-2 col-sm-offset-1"> 
          <template replaceable part="label"></template> 
        </div> 
        <div class="col-sm-8"> 
          <template replaceable part="value">${$this}</template> 
        </div> 
        <div class="col-sm-1"> 
          <template replaceable part="remove-btn"> 
            <button type="button"  
                    class="btn btn-danger le-remove-btn"  
                    click.delegate="items.splice($index, 1)"> 
              <i class="fa fa-times"></i> 
            </button> 
          </template> 
        </div> 
      </template> 
    </template> 
  </div> 
  <div class="form-group" show.bind="addItem"> 
    <div class="col-sm-9 col-sm-offset-3"> 
      <button type="button" class="btn btn-primary le-add-btn"  
              click.delegate="addItem()"> 
        <slot name="add-button-content"> 
          <i class="fa fa-plus-square-o"></i> 
          <slot name="add-button-label">Add</slot> 
        </slot> 
      </button> 
    </div> 
  </div> 
</template> 

```

在这里，我们简单地在每个作为每个项目根的元素上添加了一个`le-item` CSS 类。我们还在每个允许我们从列表中删除项目的按钮上添加了一个`le-remove-btn` CSS 类。最后，我们在允许向列表中添加项目的按钮上添加了一个`le-add-btn` CSS 类。

### 注意

`le`前缀代表列表编辑器。这不是尝试写法语卡通。

就像我们之前做的那样，我们必须重新构建应用程序，以便包是更新的，并且包括在`list-editor`模板中的新 CSS 类：

```js
> au build

```

让我们添加一些助手函数，以便在我们的测试元素内检索元素、执行操作或断言渲染 DOM 的结果：

`test/unit/resources/elements/list-editor.spec.js`

```js
//Omitted snippet... 
describe('the list-editor custom element', () => { 
  //Omitted snippet... 

  function getItemsViews() { 
    return Array.from(element.querySelectorAll('.le-item'));   
  }
function clickRemoveButtonAt(index) { 
    const removeBtn = element 
      .querySelectorAll('.le-remove-btn')[index]; 
    removeBtn.click(); 
    return new Promise(setTimeout); 
  }
function clickAddButton() { 
    const addBtn = element.querySelector('.le-add-btn'); 
    addBtn.click(); 
    return new Promise(setTimeout); 
  }
function isItemRendered(item, itemsViews) { 
    return (itemsViews || getItemsViews()) 
      .some(iv => iv.textContent.includes(item.text)); 
  }
function areAllItemsRendered() { 
    const itemsViews = getItemsViews(); 
    return items.every(i => isItemRendered(i, itemsViews)); 
  } 
}); 

```

在这里，我们定义了以下函数：

+   `getItemsViews`：检索元素（每个`items`的根）。

+   `clickRemoveButtonAt`：检索给定索引处的项目的**删除**按钮，并在其上触发一个`click`事件。它返回一个`Promise`，当浏览器的事件队列清空时，它将解决，以确保所有绑定都是最新的。

+   `clickAddButton`：检索**添加**按钮，并在其上触发一个`click`事件。它返回一个`Promise`，当浏览器的事件队列清空时，它将解决，以确保所有绑定都是最新的。

+   `isItemRendered`：如果提供的项目已经在`list-editor`的 DOM 中渲染，则返回`true`，否则返回`false`。

+   `areAllItemsRendered`：如果所有项目已经在`list-editor`的 DOM 中渲染，则返回`true`，否则返回`false`。

此时，我们已经有了编写测试所需的一切。

首先验证所有项目是否正确渲染：

`test/unit/resources/elements/list-editor.spec.js`

```js
//Omitted snippet... 
it('should render one form-group per item', done => { 
  items.push(new Item('test item 1')); 
  items.push(new Item('test item 2')); 

  create() 
    .then(() => expect(areAllItemsRendered()).toBe(true)) 
    .then(done); 
}); 
//Omitted snippet... 

```

接下来，让我们添加一些测试，以确保当点击项目的**删除**按钮时，该项目会被删除：

`test/unit/resources/elements/list-editor.spec.js`

```js
//Omitted snippet... 
it('should remove the item when the remove button is clicked', done => { 
  items.push(new Item('test item 1')); 
  items.push(new Item('test item 2')); 
  items.push(new Item('test item 3')); 

  const indexToRemove = 1; 
  const itemToRemove = items[indexToRemove]; 

  create() 
    .then(() => clickRemoveButtonAt(indexToRemove))  
    .then(() => expect(items.indexOf(itemToRemove)).toBe(-1)) 
    .then(() => expect(isItemRendered(itemToRemove)).toBe(false)) 
    .then(done); 
}); 
//Omitted snippet... 

```

最后，让我们添加一个测试用例，以确保点击**添加**按钮将创建一个新项目，并将其添加到列表中：

`test/unit/resources/elements/list-editor.spec.js`

```js
//Omitted snippet... 
it('should add new item when the add item button is clicked', done => { 
  items.push(new Item('test item 1')); 
  items.push(new Item('test item 2')); 

  const indexOfItemToAdd = items.length; 
  const itemToAdd = new Item('test item 3'); 
  createItem.and.callFake(() => { items.push(itemToAdd); }); 

  create() 
    .then(() => clickAddButton()) 
    .then(() => expect(items.indexOf(itemToAdd)) 
      .toBe(indexOfItemToAdd)) 
    .then(() => expect(isItemRendered(itemToAdd)).toBe(true)) 
    .then(done); 
}); 
//Omitted snippet... 

```

此时，所有测试都应该通过。

## 单元测试路由组件

在撰写本文时，没有一种方法可以利用`ComponentTester`测试路由组件。我们只能在单元测试中测试视图模型的行为，并依赖端到端测试来验证视图。然而，Aurelia 团队计划添加这个功能；你应该查看一下，以防在你阅读这本书时它已经被发布了。

对这类组件的视图模型进行单元测试与我们已经编写的大多数测试并没有太大区别，但让我们通过编写一个联系人创建组件的测试套件来举一个快速的例子：

`test/unit/contacts/components/creation.spec.js`

```js
 import {ValidationError}
  from 'aurelia-validation';
import {ContactCreation}
  from '../../../../src/contacts/components/creation';
import {Contact} from '../../../../src/contacts/models/contact';

describe('the contact creation component', () => {
  let gateway, validationController, router, sut;
  beforeEach(() => {
    gateway = jasmine.createSpyObj('ContactGateway', ['create']);
    validationController = jasmine.createSpyObj(
       'ValidationController', ['validate']);
    router = jasmine.createSpyObj('Router', ['navigateToRoute']);
    sut = new ContactCreation(gateway, validationController,
    router);
   });
});
```

在此，我们首先创建一个测试套件，该套件包含一个测试设置，用于创建一组模拟对象，然后使用这些模拟对象创建被测试系统（SUT）。

我们还需要添加一个帮助函数来创建验证错误：

`test/unit/contacts/components/creation.spec.js`

```js
//Omitted snippet... 
function createValidationError() { 
  return new ValidationError({}, 'Invalid', sut.contact,  
    'firstName'); 
} 
//Omitted snippet... 

```

最后，让我们添加一个测试用例，以确保在尝试保存无效联系人时什么也不会发生，再添加一个测试用例，以确保保存有效联系人时能做正确的事情：

`test/unit/contacts/components/creation.spec.js`

```js
//Omitted snippet... 
it('should do nothing when contact is invalid', done => { 
  const errors = [createValidationError()]; 
  validationController.validate.and 
    .returnValue(Promise.resolve(errors)); 

  sut.save() 
    .then(() => expect(gateway.create).not.toHaveBeenCalled()) 
    .then(() => expect(router.navigateToRoute) 
      .not.toHaveBeenCalled()) 
    .then(done); 
}); 

it('should create and navigate when contact is valid', done => { 
  validationController.validate.and 
    .returnValue(Promise.resolve([])); 
  gateway.create.and.returnValue(Promise.resolve()); 

  sut.save() 
    .then(() => expect(gateway.create) 
      .toHaveBeenCalledWith(sut.contact)) 
    .then(() => expect(router.navigateToRoute) 
      .toHaveBeenCalledWith('contacts')) 
    .then(done); 
}); 
//Omitted snippet... 

```

这给出了一个很好的测试路由组件视图模型的想法。我将留给读者作为练习，为`contacts`特性中的其他路由组件添加测试。本章节的示例应用程序可以作为参考。

# 端到端测试

单元测试的目的是验证代码单元的隔离，而端到端（**E2E**）测试的目的是验证整个应用程序。这些测试可以有不同的深度。它们的范围可能限于客户端应用程序本身。在这种情况下，应用程序所使用的任何远程服务都需要以某种方式被模拟。

它们也可以涵盖整个系统。大多数时候，这意味着支持应用程序的服务必须部署到一个测试位置，并用受控的测试数据进行初始化。

无论你的端到端测试策略是什么，技术上基本保持不变。在本节中，我们将了解如何利用 Protractor 为我们的联系人管理应用程序编写功能测试场景。

## 设置环境

在撰写本文时，CLI 不包括 Protractor 的设置。由于我们是用 CLI 开始项目的，让我们看看如何向我们的应用程序添加端到端测试的支持。

我们首先需要安装 Gulp 的`protractor`插件以及`del`库。在项目的目录中打开一个控制台，并运行以下命令：

```js
> npm install gulp-protractor del --save-dev

```

接下来，我们需要存储一些关于端到端测试过程的配置值。让我们把这些添加到`aurelia.json`文件中：

`aurelia_project/aurelia.json`

```js
{ 
  //Omitted snippet... 
  "unitTestRunner": { 
    "id": "karma", 
    "displayName": "Karma", 
    "source": "test\\unit\\**\\*.js" 
  }, 
 "e2eTestRunner": { 
    "id": "protractor", 
    "displayName": "Protractor", 
    "source": "test/e2e/src/**/*.js", 
    "output": "test/e2e/dist/", 
    "transpiler": { 
      "id": "babel", 
      "displayName": "Babel", 
      "options": { 
        "plugins": [ 
          "transform-es2015-modules-commonjs" 
        ] 
      } 
    } 
  }, 
  //Omitted snippet... 
} 

```

这个新部分包含路径和转换器选项，这些将被我们的端到端任务使用。

这个任务相当直接：它使用 Babel 转换测试套件，因此可以在 Node 上运行，然后启动 Protractor。让我们首先编写任务描述符：

`aurelia_project/tasks/e2e.json`

```js
{ 
  "name": "e2e", 
  "description":  
    "Runs all end-to-end tests and reports the results.", 
  "flags": [] 
} 

```

接下来，让我们编写任务本身：

`aurelia_project/tasks/e2e.js`

```js
import gulp from 'gulp'; 
import del from 'del'; 
import {webdriver_update, protractor} from 'gulp-protractor'; 
import plumber from 'gulp-plumber'; 
import notify from 'gulp-notify'; 
import changedInPlace from 'gulp-changed-in-place'; 
import sourcemaps from 'gulp-sourcemaps'; 
import babel from 'gulp-babel'; 
import project from '../aurelia.json'; 
import {CLIOptions} from 'aurelia-cli'; 

function clean() { 
  return del(project.e2eTestRunner.output + '*'); 
} 

function build() { 
  return gulp.src(project.e2eTestRunner.source) 
    .pipe(plumber({ 
      errorHandler: notify.onError('Error: <%= error.message %>') 
    })) 
    .pipe(changedInPlace({firstPass:true})) 
    .pipe(sourcemaps.init()) 
    .pipe(babel(project.e2eTestRunner.transpiler.options)) 
    .pipe(gulp.dest(project.e2eTestRunner.output)); 
} 

function run() { 
  return gulp.src(project.e2eTestRunner.output + '**/*.js') 
    .pipe(protractor({ 
      configFile: 'protractor.conf.js', 
      args: ['--baseUrl', 'http://127.0.0.1:9000'] 
    })) 
    .on('end', () => { process.exit(); }) 
    .on('error', e => { throw e; }); 
} 

export default gulp.series( 
  webdriver_update, 
  clean, 
  build, 
  run 
); 

```

如果你不熟悉 Gulp，让我快速解释一下这个任务做什么：

+   如有需要，它将更新 WebDriver。

+   它清理输出目录，那里存放着编译后的测试套件。

+   它将测试套件编译到输出目录中。

+   它启动了 Protractor。

    ### 注意

    Protractor 主要是一个 API，它建立在 Selenium 之上，Selenium 是允许我们在浏览器中播放场景的实际引擎。WebDriver 是 Node 绑定，允许我们与 Selenium 通信。

你可能注意到了一个配置文件路径被传递给了 Protractor。让我们编写这个配置：

`protractor.conf.js`

```js
exports.config = { 
  directConnect: true, 

  capabilities: { 
    'browserName': 'chrome' 
  }, 

  specs: ['test/e2e/dist/**/*.js'], 

  plugins: [{ 
    package: 'aurelia-tools/plugins/protractor' 
  }], 

  jasmineNodeOpts: { 
    showColors: true, 
    defaultTimeoutInterval: 30000 
  } 
}; 

```

深入探索 Protractor 超出了本书的范围。然而，从这个配置中，你可能可以理解到它将使用 Google Chrome 来运行测试，它期望测试文件位于`test/e2e/dist`目录中，这是我们配置任务以编译我们的测试套件的地方，并且从`aurelia-tools`包中加载了一个插件。`aurelia-tools`库已经包含在基于 CLI 的项目中，所以不需要安装。

这一部分相当重要，因为这个插件向 Protractor API 添加了一些 Aurelia 特定的方法。我们将在下一节中看到这些方法。

## 模拟后端

我们的联系人管理应用程序并不是独立存在的。它建立在一个基于 HTTP 的 API 之上，该 API 允许应用程序访问数据和执行操作。因此，我们需要一个受控的 API 版本，实际上是一个模拟，它将包含一组预定义的数据，并且我们可以在每次测试之前将其重置为原始状态。

你可以从本书的工件中获取这个模拟的 API。只需将`samples`中的`chapter-7\app\test\e2e\api-mock`目录复制到您自己项目的`test\e2e`目录中。您可能需要先创建`e2e`目录。

一旦完成这个步骤，请确保通过在`api-mock`目录中打开控制台并运行以下命令来恢复 API 模拟器所需的所有依赖项：

```js
> npm install

```

API 模拟器现在准备运行。

为了在每次测试之前重置数据集，我们将需要一个帮助函数：

`test/e2e/src/contacts/api-mock.js`

```js
import http from 'http'; 

export function resetApi() { 
  const deferred = protractor.promise.defer(); 

  const request = http.request({ 
    protocol: 'http:', 
    host: '127.0.0.1', 
    port: 8000, 
    path: '/reset', 
    method: 'POST' 
  }, response => { 
    if (response.statusCode < 200 || response.statusCode >= 300) { 
      deferred.reject(response); 
    } else { 
      deferred.fulfill(); 
    } 
  }); 
  request.end(); 

  return deferred.promise; 
} 

```

如果你不知道，Protractor 是在 Node 上运行的，而不是在浏览器中。因此，我们首先导入 Node 的`http`模块。接下来，我们定义并导出一个`resetApi`函数，该函数简单地向我们 HTTP API 的`/reset`端点发送一个`POST`请求。它还返回一个`Promise`，当 HTTP 请求完成时解析。

这个函数告诉后端将它的数据集重置为其原始状态。我们将在每个测试之前调用它，所以每个测试都可以确信它是在相同的数据集上工作，即使之前的测试创建了一个新的联系人或更新了一个现有的联系人。

## 页面对象模式

一个典型的端到端测试将加载一个给定的 URL，从文档中检索一个或多个 DOM 元素，对这个或这些元素执行一个动作或分发一个事件，然后验证是否达到了预期的结果。

因此，选择元素并在它们上执行操作可以迅速使测试代码膨胀。另外，通常需要在多个测试用例中选择一组给定的元素。在很多地方重复选择代码使得代码变得僵硬且难以更改。测试变得比解放更具有限制性。

为了使我们的测试更具描述性且更容易更改，我们将使用页面对象模式。这个模式描述了我们如何创建一个类来表示给定页面或组件的 UI，以封装选择特定元素并在它们上执行操作的逻辑。

让我们通过为联系人列表组件创建这样的类来说明这一点：

`test/e2e/src/contacts/list.po.js`

```js
export class ContactsListPO { 

  getTitle() { 
    return element(by.tagName('h1')).getText(); 
  } 

  getAllContacts() { 
    return element.all(by.css('.cl-details-link')) 
      .map(link => link.getText()); 
  } 

  clickContactLink(index) { 
    const result = {}; 
    const link = element.all( 
      by.css(`.cl-details-link`)).get(index); 
    link.getText().then(fullName => { 
      result.fullName = fullName; 
    }); 
    link.click(); 
    return browser.waitForRouterComplete().then(() => result); 
  } 

  clickNewButton() { 
    element(by.css('.cl-create-btn')).click(); 
    return browser.waitForRouterComplete(); 
  } 

  setFilter(value) { 
    element(by.valueBind('filter & debounce')) 
      .clear().sendKeys(value); 
    return browser.sleep(200); 
  } 

  clickClearFilter() { 
    element(by.css('.cl-clear-filter-btn')).click(); 
    return browser.sleep(200); 
  } 
} 

```

这个类以一个`getAllContacts`方法开始。这个方法使用 Protractor API 选择所有具有`cl-details-link` CSS 类的元素，然后将它们映射到它们的文本内容。这个方法允许我们获取一个包含所有显示联系人的全名的数组。

接下来，它暴露了一个`clickContactLink`方法，该方法检索具有`cl-details-link` CSS 类的那些元素中的第`index`个元素，然后获取其文本内容，将其分配给`result`对象上的`fullName`属性，在执行元素上的点击操作之前。然后，它使用 Aurelia 的 Protractor 插件提供的扩展方法之一来等待路由完成其导航周期，这将是通过点击链接触发的，并返回结果`Promise`，其结果被改变为`result`对象。

### 注意

如前所述，深入探索 Protractor 超出了本书的范围。然而，如果你不熟悉它，了解所有 Protractor API 中的方法返回`Promise`是很重要的，但通常没有必要使用`then`来链接它们，因为 Protractor 内部会为所有异步操作排队。

我强烈建议你在尝试编写广泛的端到端测试套件之前，先熟悉 Protractor 这一方面。

`clickNewButton`方法相当简单；它选择具有`cl-create-btn` CSS 类的元素并对其执行点击操作，然后等待路由完成其导航周期。

`setFilter`方法使用 Protractor 的 Aurelia 插件提供的另一个扩展方法来选择与`filter`属性绑定且具有`debounce`绑定行为的元素。它然后清除其值并向其发送给定的一系列键盘输入，然后让浏览器休眠 200 毫秒。

最后，`clickClearFilter`方法选择具有`cl-clear-filter-btn` CSS 类的元素并执行点击操作。然后让浏览器休眠 200 毫秒。

### 注意

在撰写本文时，在操作后使用`sleep`指令是必要的，以确保所有可能需要对操作做出反应的绑定都已更新。

页面对象的目的是封装并抽象掉与视图的交互。由于所有与组件 HTML 相关的代码都集中在一个单一的类中，因此修改组件视图的影响将限于这个类。另外，正如我们将在下一节中看到的，测试用例本身只需要处理与视图的高级 API，而不需要处理 HTML 结构本身的复杂性。大多数对 Protractor API 的调用都将隐藏在我们的页面对象内部。

您可能注意到，前面代码片段中的大多数选择器都使用新的 CSS 类来选择元素。让我们将这些添加到联系人列表模板中：

`src/contacts/components/list.html`

```js
<template> 
  <section class="container"> 
    <h1>Contacts</h1> 

    <div class="row"> 
      <div class="col-sm-1"> 
        <a route-href="route: contact-creation"  
           class="btn btn-primary cl-create-btn"> 
          <i class="fa fa-plus-square-o"></i> New 
        </a> 
      </div> 
      <div class="col-sm-2"> 
        <div class="input-group"> 
          <input type="text" class="form-control"  
                 placeholder="Filter"  
                 value.bind="filter & debounce"> 
          <span class="input-group-btn" if.bind="filter"> 
            <button class="btn btn-default cl-clear-filter-btn"  
                    type="button"  
                    click.delegate="filter = ''"> 
              <i class="fa fa-times"></i> 
              <span class="sr-only">Clear</span> 
            </button> 
          </span> 
        </div> 
      </div> 
    </div> 

    <group-list items.bind="contacts  
                  | filterBy:filter:'firstName':'lastName': 
                    'company'" 
                group-by="firstLetter" order-by="fullName"> 
      <template replace-part="item"> 
        <a route-href="route: contact-details;  
                       params.bind: { id: id }"  
           class="cl-details-link"> 
          <span if.bind="isPerson"> 
            ${firstName} <strong>${lastName}</strong> 
          </span> 
          <span if.bind="!isPerson"> 
            <strong>${company}</strong> 
          </span> 
        </a> 
      </template> 
    </group-list> 
  </section> 
</template> 

```

最后，在我们进入第一个测试用例之前，让我们快速添加两个我们将在测试中需要的其他页面对象：

`test/e2e/src/contacts/creation.po.js`

```js
export class ContactCreationPO { 

  getTitle() { 
    return element(by.tagName('h1')).getText(); 
  } 
} 

```

`test/e2e/src/contacts/details.po.js`

```js
export class ContactDetailsPO { 

  getFullName() { 
    return element(by.tagName('h1')).getText(); 
  } 
} 

```

第一个页面对象封装了联系人创建组件。它简单地暴露了一个`getTitle`方法，该方法选择`h1`元素并返回其文本内容。

第二个页面对象是用于联系详情组件的。它有一个`getFullName`方法，该方法允许我们通过选择`h1`元素并返回其文本内容来检索联系人的显示全名。

## 编写第一个测试用例

现在所有我们需要的工具都已经准备好了，让我们为联系人列表组件编写第一个测试用例：

`test/e2e/src/contacts/list.spec.js`

```js
import {resetApi} from './api-mock.js'; 
import {ContactsListPO} from './list.po.js'; 

describe('the contacts list page', () => { 

  let listPo; 

  beforeEach(done => { 
    listPo = new ContactsListPO(); 

    resetApi().then(() => { 
      browser 
        .loadAndWaitForAureliaPage('http://127.0.0.1:9000/') 
        .then(done); 
    }); 
  }); 

  it('should display the list of contacts', () => { 
    expect(listPo.getTitle()).toEqual('Contacts'); 
    listPo.getAllContacts().then(names => { 
      expect(names.length).toBeGreaterThan(0); 
    }); 
  }); 
}); 

```

在这里，我们从测试设置开始，该设置创建了一个联系人列表页面对象的实例，重置了 API，然后使用了 Aurelia 的 Protractor 插件提供的另一个扩展方法来加载给定 URL，然后等待 Aurelia 应用程序完成启动。

接下来，我们定义了一个第一个测试用例，该测试用例使用页面对象的方法来确保某些联系人被显示。

### 注意

尽管使用 Protractor 运行的测试是异步的，但大多数情况下，没有必要使用 Jasmine 的`done`函数来让框架知道测试用例何时完成，因为 Protractor 修改了 Jasmine 的函数，使其自身使用自己的内部任务队列来处理异步性。

这个规则的例外是在执行 Protractor 未处理的异步操作时，比如在`beforeEach`函数中，我们使用异步 HTTP 请求重置 API。

## 运行测试

在此阶段，我们已经准备就绪并运行了我们的 E2E 测试。为此，我们首先需要运行 API 模拟，通过在我们的项目中的`test/e2e/api-mock`目录中打开一个控制台并执行以下命令：

```js
> npm start

```

一旦 API 运行，我们还需要启动应用程序本身，通过在项目的目录中打开一个控制台并运行以下命令来实现：

```js
> au run

```

这两个命令是必要的，因为端到端测试需要在我们应用程序中加载浏览器来执行，并且需要在每次测试前调用 API 来重置其数据。当然，应用程序本身也需要 API 来请求数据和执行操作。

一旦 API 模拟和应用程序都在运行，我们就可以通过在项目目录中打开第三个控制台并运行以下命令来启动端到端测试：

```js
> au e2e

```

你将看到任务开始，在过程中会出现一个 Chrome 实例。你会看到应用程序加载并且测试案例场景在你眼前播放，然后 Chrome 关闭并且任务完成。完整的输出应该类似于这样：

![运行测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_07_001.jpg)

### 注意

`e2e`任务在 WebDriver 需要首先更新自己时，偶尔可能需要一些时间才能启动。

## 测试联系人列表

既然我们知道一切工作正常，让我们为联系人列表组件添加一些测试：

`test/e2e/src/contacts/list.spec.js`

```js
import {resetApi} from './api-mock.js'; 
import {ContactsListPO} from './list.po.js'; 
import {ContactDetailsPO} from './details.po.js'; 
import {ContactCreationPO} from './creation.po.js'; 

describe('the contacts list page', () => { 

  let listPo, detailsPo, creationPo; 

  beforeEach(done => { 
    listPo = new ContactsListPO(); 
    detailsPo = new ContactDetailsPO(); 
    creationPo = new ContactCreationPO(); 

    resetApi().then(() => { 
      browser 
        .loadAndWaitForAureliaPage('http://127.0.0.1:9000/') 
        .then(done); 
    }); 
  }); 

  it('should load the list of contacts', () => { 
    expect(listPo.getTitle()).toEqual('Contacts'); 
    listPo.getAllContacts().then(names => { 
      expect(names.length).toBeGreaterThan(0); 
    }); 
  }); 

  it('should display details when clicking a contact link', () => { 
    listPo.clickContactLink(0).then(clickedContact => { 
      expect(detailsPo.getFullName()) 
        .toEqual(clickedContact.fullName); 
    }); 
  }); 

  it('should display the creation form when clicking New', () => { 
    listPo.clickNewButton(); 

    expect(creationPo.getTitle()).toEqual('New contact'); 
  }); 

  it('should filter the list', () => { 
    const searched = 'Google'; 

    listPo.setFilter(searched); 

    listPo.getAllContacts().then(names => { 
      expect(names.every(n => n.includes(searched))).toBe(true); 
    }); 
  }); 

  it('should reset unfiltered list when clicking clear filter', () =>  
  { 
    let unfilteredNames; 
    listPo.getAllContacts().then(names => { 
      unfilteredNames = names; 
    }); 
    listPo.setFilter('Google'); 

    listPo.clickClearFilter(); 

    listPo.getAllContacts().then(names => { 
      expect(names).toEqual(unfilteredNames); 
    }); 
  }); 
}); 

```

+   这些新测试案例中的第一个确保点击列表中的一个联系人条目时，应用程序导航到联系人的详细信息组件

+   第二个测试确保点击**新建**按钮时，应用程序导航到联系人创建组件

+   第三个确保当在筛选文本框中输入搜索词时，列表使用这个搜索词进行筛选。

+   最后，第四个测试确保在搜索后清除筛选文本框，列表将恢复未筛选状态

这个测试套件现在覆盖了联系人列表组件的所有功能。如果你在这个时候运行端到端测试，你应该看到五个测试案例通过。

## 测试联系人创建

让我们尝试通过为联系人创建组件添加一个测试套件来使事情变得复杂一些，该组件包括一个带有验证规则的复杂表单。

首先，我们将编写一个可重用的类，遵循页面对象模式，该类将封装联系人表单视图。这样，我们就能使用这个类来测试联系人创建，也能最终测试联系人的编辑。

我们将从为列表编辑器编写基本页面对象开始。这个类将封装如何访问并在联系表单组件的`list-editor`元素上执行操作的细节。

`test/e2e/src/contacts/form.po.js`

```js
class ListEditorPO { 

  constructor(property) { 
    this.property = property; 
  }  

  _getContainer() { 
    return element(by.css( 
      `list-editor[items\\.bind=contact\\.${this.property}]`)); 
  } 

  _getItem(index) { 
    return this._getContainer() 
      .all(by.css(`.le-item`)) 
      .get(index); 
  }  

  _selectOption(index, name, value) { 
    this._getItem(index) 
      .element(by.valueBind(`${name} & validate`)) 
      .element(by.css(`option[value=${value}]`)) 
      .click(); 
    return browser.sleep(200); 
  } 

  _setText(index, name, value) { 
    this._getItem(index) 
      .element(by.valueBind(`${name} & validate`)) 
      .clear() 
      .sendKeys(value); 
    return browser.sleep(200); 
  } 

  clickRemove(index) { 
    this._getItem(index) 
      .element(by.css(`.le-remove-btn`)) 
      .click(); 
    return browser.sleep(200); 
  } 

  clickAdd() { 
    this._getContainer() 
      .element(by.css(`.le-add-btn`)) 
      .click(); 
    return browser.sleep(200); 
  } 
} 

```

在这里，我们首先定义一个名为`ListEditorPO`的基本类。这个类封装与联系表单中的单个`list-editor`元素的交互，并知道如何：

1.  在绑定给定属性的列表中给定索引的`select`中选择给定的`option`。

1.  向绑定给给定属性的列表中给定索引的字段发送给定的一系列键。

1.  点击列表中给定索引的**删除**按钮。

1.  点击**添加**按钮。

接下来，我们将通过编写四个特殊化的页面对象来扩展这个类，每个对象对应联系人可以有的每种类型的项目：

`test/e2e/src/contacts/form.po.js`

```js
//Omitted snippet... 

class PhoneNumberListEditorPO extends ListEditorPO { 

  constructor() { 
    super('phoneNumbers'); 
  } 

  setType(index, value) { 
    return this._selectOption(index, 'type', value); 
  } 

  setNumber(index, value) { 
    return this._setText(index, 'number', value); 
  } 
} 

class EmailAddressListEditorPO extends ListEditorPO { 

  constructor() { 
    super('emailAddresses'); 
  } 

  setType(index, value) { 
    return this._selectOption(index, 'type', value); 
  } 

  setAddress(index, value) { 
    return this._setText(index, 'address', value); 
  } 
} 

class AddressListEditorPO extends ListEditorPO { 

  constructor() { 
    super('addresses'); 
  } 

  setType(index, value) { 
    return this._selectOption(index, 'type', value); 
  } 

  setNumber(index, value) { 
    return this._setText(index, 'number', value); 
  } 

  setStreet(index, value) { 
    return this._setText(index, 'street', value); 
  } 

  setPostalCode(index, value) { 
    return this._setText(index, 'postalCode', value); 
  } 

  setState(index, value) { 
    return this._setText(index, 'state', value); 
  } 

  setCountry(index, value) { 
    return this._setText(index, 'country', value); 
  } 
} 

class SocialProfileListEditorPO extends ListEditorPO { 

  constructor() { 
    super('socialProfiles'); 
  } 

  setType(index, value) { 
    return this._selectOption(index, 'type', value); 
  } 

  setUsername(index, value) { 
    return this._setText(index, 'username', value); 
  } 
} 

```

在这里，我们定义了一些扩展基本`ListEditorPO`类的类：`PhoneNumberListEditorPO`、`EmailAddressListEditorPO`、`AddressListEditorPO`和`SocialProfileListEditorPO`。它们都：

+   指定底层`list-editor`元素绑定的属性

+   添加专用方法来设置底层`list-editor`中每个项目的字段值，例如用于电话号码的`setType`和`setNumber`，或用于地址的`setStreet`和`setCity`。

最后，我们将为联系表单本身编写一个页面对象：

`test/e2e/src/contacts/form.po.js`

```js
//Omitted snippet... 

export class ContactFormPO { 

  constructor() { 
    this.phoneNumbers = new PhoneNumberListEditorPO(); 
    this.emailAddresses = new EmailAddressListEditorPO(); 
    this.addresses = new AddressListEditorPO(); 
    this.socialProfiles = new SocialProfileListEditorPO(); 
  } 

  _setText(name, value) { 
    element(by.valueBind(`contact.${name} & validate`)) 
      .clear() 
      .sendKeys(value); 
    return browser.sleep(200); 
  } 

  setFirstName(value) { 
    return this._setText('firstName', value); 
  } 

  setLastName(value) { 
    return this._setText('lastName', value); 
  } 

  setCompany(value) { 
    return this._setText('company', value); 
  } 

  setBirthday(value) { 
    return this._setText('birthday', value); 
  } 

  setNote(value) { 
    return this._setText('note', value); 
  } 

  getValidationErrors() { 
    return element.all(by.css('.validation-message')) 
      .map(x => x.getText()); 
  } 
} 

```

在这里，我们导出一个名为`ContactFormPO`的类，它封装了与联系表单视图的交互。它有每个扩展`ListEditorPO`类的实例，因此测试可以与电话号码、电子邮件地址、地址和社会资料的各个`list-editor`元素交互。它还有允许我们设置名字、姓氏、公司、生日和备注值的方法。最后，它有一个允许我们检索表单上所有验证错误消息的方法。

在能够编写我们的新测试之前，我们需要将此表单页面对象与联系创建组件的页面对象连接。我们还将向其中添加几个方法：

`test/e2e/src/contacts/creation.po.js`

```js
import {ContactFormPO} from './form.po.js'; 

export class ContactCreationPO extends ContactFormPO { 

  getTitle() { 
    return element(by.tagName('h1')).getText(); 
  } 

  clickSave() { 
    element(by.buttonText('Save')).click(); 
    return browser.sleep(200); 
  } 

  clickCancel() { 
    element(by.linkText('Cancel')).click(); 
    return browser.sleep(200);
 } 
} 

```

在这里，我们首先使`ContactCreationPO`类继承`ContactFormPO`类，然后添加一个方法来点击**保存**按钮，另一个方法来点击**取消**链接。

有了这个准备，编写联系创建组件的测试套件就相当直接了：

`test/e2e/src/contacts/creation.spec.js`

```js
import {resetApi} from './api-mock.js'; 
import {ContactsListPO} from './list.po.js'; 
import {ContactCreationPO} from './creation.po.js'; 

describe('the contact creation page', () => { 

  let listPo, creationPo; 

  beforeEach(done => { 
    listPo = new ContactsListPO(); 
    creationPo = new ContactCreationPO(); 

    resetApi().then(() => { 
      browser.loadAndWaitForAureliaPage('http://127.0.0.1:9000/'); 
      listPo.clickNewButton().then(done); 
    }); 
     });   
}); 

```

在这个测试套件的设置中，我们首先创建列表和创建组件的页面对象。我们重置 API 的数据，然后加载应用程序，点击**新建**按钮导航到联系创建组件。

我们现在可以丰富这个测试套件，添加一些验证联系创建组件行为的测试用例：

```js
it('should display errors when clicking save and form is invalid', () => { 
  creationPo.setBirthDay('this is absolutely not a date'); 
  creationPo.phoneNumbers.clickAdd(); 
  creationPo.emailAddresses.clickAdd(); 
  creationPo.addresses.clickAdd(); 
  creationPo.socialProfiles.clickAdd(); 

  creationPo.clickSave(); 

  expect(creationPo.getTitle()).toEqual('New contact'); 
  expect(creationPo.getValidationErrors()).toEqual([ 
    'Birthday must be a valid date.',  
    'Address is required.',      
    'Number is required.',  
    'Street is required.',  
    'Postal Code is required.',  
    'City is required.',  
    'Country is required.',  
    'Username is required.' 
  ]); 
}); 

it('should create contact when clicking save and form is valid', () => { 
  creationPo.setFirstName('Chuck'); 
  creationPo.setLastName('Norris'); 
  creationPo.setBirthDay('1940-03-10'); 

  creationPo.emailAddresses.clickAdd(); 
  creationPo.emailAddresses.setType(0, 'Office'); 
  creationPo.emailAddresses.setAddress(0,  
    'himself@chucknorris.com'); 

  creationPo.clickSave(); 

  expect(listPo.getTitle()).toEqual('Contacts'); 
  expect(listPo.getAllContacts()).toContain('Chuck Norris'); 
}); 

it('should not create contact when clicking cancel', () => { 
  creationPo.setFirstName('Steven'); 
  creationPo.setLastName('Seagal'); 

  creationPo.clickCancel(); 

  expect(listPo.getTitle()).toEqual('Contacts'); 
  expect(listPo.getAllContacts()).not.toContain('Steven Seagal'); 
}); 

```

在这里，我们定义了三个测试用例。第一个确保当表单处于无效状态并且点击**保存**按钮时，不会发生导航并且显示适当的验证消息。第二个确保当表单处于有效状态并且点击**保存**按钮时，应用程序导航回到联系人列表组件。它还确保新联系人在列表中显示。第三个测试用例确保点击**取消**使应用程序导航回到联系人列表组件。它还确保列表中没有显示新联系人。

## 进一步测试

这一章节本可以更长，通过添加我们应用程序中其他功能的测试来扩展，但编写额外的测试对 Aurelia 本身的学习体验增加的价值不大。使用 Protractor 对 Aurelia 应用程序进行端到端测试是一个值得单独成书的话题。然而，当前节点的目标只是让你稍稍了解一下并开始入门。希望，它做到了。

# 总结

能够既使用单元测试在微观层面测试，又使用端到端测试在宏观层面测试，对于一个框架来说是非常有价值的品质。得益于其模块化架构和面向组件的特性，Aurelia 使得编写这类测试相对容易。

事实上，自动化测试是一个广泛的主题。有专门关于这个话题的书籍，因此试图在单个章节中深入探讨它是徒劳的。然而，此时你应该已经拥有开始为你的 Aurelia 应用程序编写自动化测试的最基本知识了。

在这本书的这个阶段，构建使用 Aurelia 的单页应用程序所需的大部分主要工具应该已经掌握在你手中了。你可能还没有完全掌握它们，但你知道它们是什么以及它们的用途是什么。

然而，还有一些主题尚未涉及，其中之一就是国际化。这是我们将在下一章讨论的内容。
