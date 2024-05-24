# VueJS2 学习指南（一）

> 原文：[`zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246`](https://zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书是关于 Vue.js 的。我们将开始我们的旅程，试图理解 Vue.js 是什么，它与其他框架相比如何，以及它允许我们做什么。我们将在构建小型有趣的应用程序的同时学习 Vue.js 的不同方面，并将这些方面应用到实践中。最后，我们将回顾所学到的内容，并展望未来，看看我们还能学到什么并做些什么。因此，您将学到以下内容：

+   Vue.js 是什么以及它是如何工作的

+   Vue.js 的响应性和数据绑定

+   Vue.js 可重用组件

+   Vue.js 的插件

+   测试和部署使用 Vue.js 编写的应用程序

本书中的所有示例都是基于最近发布的 Vue 2.0 版本构建的。该书还包含了对先前版本的引用，涉及框架的已弃用或已更改的方面。

我相信您会喜欢使用本书构建 Vue.js 应用程序的过程。

# 本书涵盖的内容

第一章《使用 Vue.js 购物》，包括对 Vue.js 的介绍，本书中使用的术语以及第一个基本示例。

第二章《基础知识-安装和使用》解释了 Vue.js 的幕后情况，提供了对架构模式的理论见解，涵盖了几乎所有主要的 Vue.js 概念，并引导了本书中将开发的应用程序。

第三章《组件-理解和使用》深入探讨了组件，并解释了如何使用简单的组件系统和单文件组件重写应用程序。

第四章《响应性-将数据绑定到您的应用程序》详细解释了 Vue.js 中数据绑定机制的用法。

第五章《Vuex-管理应用程序中的状态》包含了对 Vuex 的详细介绍，Vuex 是 Vue.js 的状态管理系统，并解释了如何在应用程序中使用它以实现良好的可维护架构。

第六章，“插件-用自己的砖头建造你的房子”，展示了如何在 Vue 应用程序中使用插件，并解释了如何在应用程序中使用现有插件，并解释了如何构建我们自己的插件然后使用它。

第七章，“测试-测试我们到目前为止所做的事情的时间！”，包含了 Vue 应用程序中可以使用的测试技术的介绍，以将它们带到所需的质量水平。我们通过展示如何编写单元测试以及如何为本书中的应用程序开发端到端测试来解决这个问题。

第八章，“部署-是时候上线了！”，展示了如何将您的 Vue 应用程序带到世界上，并通过持续集成工具保证其质量。它解释了如何将 GitHub 存储库连接到 Travis 持续集成系统和 Heroku 云部署平台。

第九章，“接下来是什么”，总结了到目前为止所做的一切，并留给读者后续步骤。

附录，“练习解决方案”，提供了前三章练习的解决方案。

# 这本书需要什么

这本书的要求如下：

+   带有互联网连接的计算机

+   文本编辑器/集成开发环境

+   Node.js

# 这本书适合谁

这本书适用于 Web 开发人员或想要成为 Web 开发人员的人。无论您刚开始使用 Web 技术还是已经是 Web 技术浩瀚海洋中框架和语言的大师，这本书可能会在响应式 Web 应用程序的世界中向您展示一些新东西。如果您是 Vue 开发人员并且已经使用过 Vue 1.0，这本书可能是您迁移到 Vue 2.0 的有用指南，因为本书的所有示例都基于 Vue 2.0。即使您已经在使用 Vue 2.0，这本书也可能是一个很好的练习，从头开始构建一个应用程序，应用所有 Vue 和软件工程概念，并将其推向部署阶段。

至少需要一些技术背景。如果你已经能够用 JavaScript 编写代码，那将是一个巨大的优势。

# 惯例

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名都会显示如下：“您的插件必须提供`install`方法。”

代码块设置如下：

```js
export default {
  components: {
    ShoppingListComponent,
    ShoppingListTitleComponent
  },
  computed: mapGetters({
    shoppinglists: 'getLists'
  })
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
export default {
  components: {
    ShoppingListComponent,
    ShoppingListTitleComponent
  },
  computed: mapGetters({
    shoppinglists: 'getLists'
  }),
  **methods: mapActions(['populateShoppingLists']),**
  store,
  **mounted () {**
**    this.populateShoppingLists()**
**  }**
}
```

任何命令行输入或输出都会按照以下方式书写：

```js
**cd shopping-list**
**npm install vue-resource --save-dev**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“勾选**`开发者模式`**复选框”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：使用 Vue.js 去购物

> *"Vue.js 是一个用于构建惊人的 Web 应用程序的 JavaScript 框架。Vue.js 是一个用于创建 Web 界面的 JavaScript 库。Vue.js 是一种利用 MVVM 架构的工具。"*

简化的 JavaScript 术语建议 Vue.js 是一个基于底层数据模型创建用户界面（视图）的 JavaScript 库（[`jargon.js.org/_glossary/VUEJS.md`](http://jargon.js.org/_glossary/VUEJS.md)）。

官方的 Vue.js 网站（[`vuejs.org/`](https://vuejs.org/)）在几个月前表示，Vue.js 是用于现代 Web 界面的反应式组件。

![使用 Vue.js 去购物](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00216.jpeg)

现在它说明了 Vue.js 是一个渐进式的 JavaScript 框架：

![使用 Vue.js 去购物](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00217.jpeg)

那么 Vue.js 到底是什么？框架？工具？库？它应该用于构建全栈 Web 应用程序，还是仅用于添加一些特殊功能？我应该从我喜欢的框架转到它吗？如果是的话，为什么？我可以在我的项目中同时使用它和其他工具吗？它可能带来什么优势？

在本章中，我们将尝试找到所有这些问题的答案。我们将稍微涉及 Vue.js，并在一些小而简单的示例中使用它。

更具体地说，我们将做以下事情：

+   了解 Vue.js 是什么，它的重要部分和历史

+   了解哪些项目使用了 Vue.js

+   使用 Vue.js 构建一个简单的购物清单，并将其实现与相同应用程序的 jQuery 实现进行比较

+   使用 Vue.js 构建一个简单的番茄工作法计时器

+   享受一个小而简单的练习

# 流行词

在本书中将会有很多流行词、缩写和其他时髦的字母组合。请不要害怕它们。我可以告诉你更多，但是，对于使用 Vue.js 或任何其他框架需要做的大部分事情，你不需要全部都牢记在心！但是，无论如何，让我们把词汇表放在这里，这样你在书的任何地方都会对术语感到困惑，你可以回到这里看一看：

+   **应用状态**：这是应用程序的全局集中状态。当应用程序启动时，此状态中的数据被初始化。任何应用程序组件都可以访问此数据；但是，它们不能轻易地更改它。状态的每个项目都有一个附加的变异，可以在应用程序组件内发生的特殊事件上分派。

+   Bootstrap：这是一个项目，提供了一组样式和 JavaScript 工具，用于开发响应式和美观的应用程序，而无需过多考虑 CSS。

+   内容分发网络（CDN）：这是一个特殊的服务器，其目的是以高可用性和高性能向用户传递数据。开发框架的人和公司喜欢通过 CDN 分发它们，因为它们只需在安装说明中指出 CDN 的 URL。Vue.js 托管在 npmcdn（[`npmcdn.com/`](https://npmcdn.com/)），这是一个可靠的全球网络，用于发布到 npm 的内容。

+   组件：这些是应用程序的部分，具有自己的数据和视图，可以在整个应用程序中重复使用，就像建造房子的砖块一样。

+   层叠样式表（CSS）：这是一组样式，应用于 HTML 文档，使其变得美观漂亮。

+   声明式视图：这些是提供了一种直接数据绑定的视图，可以在普通的 JavaScript 数据模型和表示之间进行绑定。

+   指令：这是 Vue.js 中的特殊 HTML 元素属性，允许以不同的方式进行数据绑定。

+   文档对象模型（DOM）：这是一种表示标记语言节点的约定，例如 HTML、XML 和 XHTML。文档的节点被组织成 DOM 树。当有人说与 DOM 交互时，这只是他们花哨地说与 HTML 元素交互。

+   npm：这是 JavaScript 的包管理器，允许搜索、安装和管理 JavaScript 包。

+   Markdown：这是一种人性化的语法，允许网络作者编写文本而不必担心样式和 HTML 标记。Markdown 文件的扩展名为`.md`。

+   模型视图视图模型（MVVM）：这是一种架构模式，其核心是视图模型，充当视图和数据模型之间的桥梁，允许它们之间的数据流动。

+   模型视图控制器（MVC）：这是一种架构模式。它允许将视图与模型分离，以及信息从视图流向模型，反之亦然。

+   单向数据绑定：这是一种数据绑定类型，其中数据模型中的更改会自动传播到视图层，但反之则不会。

+   快速原型制作：在 Web 中，这是一种轻松快速地构建用户界面模型的技术，包括一些基本的用户交互。

+   响应性：在 Web 中，这实际上是数据的任何更改立即传播到视图层。

+   双向数据绑定：这是一种数据绑定类型，其中数据模型的更改会自动传播到视图层，而视图层中发生的更改会立即反映在数据模型中。

+   用户界面（UI）：这是一组视觉组件，允许用户与应用程序进行交互。

+   Vuex：这是 Vue 应用程序的架构，允许简单地管理应用程序状态。

# Vue.js 历史

当 Vue.js 的创始人 Evan You（[`evanyou.me/`](http://evanyou.me/)）在 Google 创意实验室的一个项目上工作时，他们需要快速原型制作一个相当大的 UI 界面。编写大量重复的 HTML 显然是耗时和耗资源的，这就是为什么 Evan 开始寻找已经存在的工具来实现这个目的。令他惊讶的是，他发现没有工具、库或框架能够完全符合快速原型制作的目的！那时，Angular 被广泛使用，React.js 刚刚开始，Backbone.js 等框架被用于具有 MVC 架构的大型应用程序。对于需要非常灵活和轻量级的快速 UI 原型制作的项目来说，这些复杂的框架都不太合适。

当你意识到某个酷炫的东西不存在，而你又能够创造它时——*就去做吧*！

### 注意

Vue.js 诞生于快速原型制作工具。现在它可以用来构建复杂可扩展的响应式 Web 应用程序。

这就是 Evan 所做的。这就是他想到创建一个库的想法，通过提供一种简单灵活的响应式数据绑定和可重用组件的方式来帮助快速原型制作。

像每个优秀的库一样，Vue.js 一直在不断成长和发展，因此提供了比最初承诺的更多功能。目前，它提供了一种简单的附加和创建插件、编写和使用混合物的方法，以及总体添加自定义行为。Vue 可以以如此灵活的方式使用，并且对应用程序结构没有明确的意见，以至于它绝对可以被视为一个能够支持端到端构建复杂 Web 应用程序的框架。

# 关于 Vue.js 最重要的一点

Vue.js 允许你简单地将你的数据模型绑定到表示层。它还允许你在整个应用程序中轻松重用组件。

你不需要创建特殊的模型或集合，并在其中注册事件对象。你不需要遵循某种特殊的语法。你不需要安装任何无休止的依赖。

你的模型是普通的 JavaScript 对象。它们被绑定到你在视图中想要的任何东西（文本、输入文本、类、属性等），它就能正常工作。

你可以简单地将`vue.js`文件添加到你的项目中并使用它。或者，你可以使用`vue-cli`与 Webpack 和 Browserify 系列，它不仅可以快速启动整个项目，还支持热重载并提供开发者工具。

你可以将视图层与样式和 JavaScript 逻辑分开，也可以将它们放在同一个 Vue 文件中，并在同一个地方构建你的组件结构和逻辑。所有现代和常用的 IDE 都支持插件。

你可以使用任何预处理器，并且你可以使用 ES2015。你可以将它与你一直在开发的喜爱框架一起使用，或者你可以单独使用它。你可以仅仅用它来添加一些小功能，或者你可以使用整个 Vue 生态系统来构建复杂的应用程序。

如果你想要比较它与其他框架，比如 Angular 或 React，那么请访问[`vuejs.org/guide/comparison.html`](http://vuejs.org/guide/comparison.html)。

如果你想了解关于 Vue.js 的所有惊人之处，那么欢迎访问[`github.com/vuejs/awesome-vue`](https://github.com/vuejs/awesome-vue)。

# 我们去购物吧！

我不知道为什么，但我能感觉到你的周末即将到来，你开始考虑去购物买下周所需的杂货。除非你是一个能够在脑海中维护整个清单的天才，或者你是一个不需要那么多的谦逊的人，你可能在去购物前会列一个购物清单。也许你甚至会使用一些应用程序来帮助。现在，我问你：为什么不使用你自己的应用程序呢？你对创建和设计它有什么感觉？让我们做吧！让我们创建我们自己的购物清单应用程序。让我们从创建一个快速原型开始。这是一个非常简单的任务——为购物清单构建一个交互式原型。

它应该显示列表并允许我们添加和删除项目。实际上，这与待办事项列表非常相似。让我们开始使用经典的 HTML + CSS + JS + jQuery 方法来做这件事。我们还将使用 Bootstrap 框架（[`getbootstrap.com/`](http://getbootstrap.com/)）来使事情看起来更美观，而无需编写大量的 CSS 代码。（是的，因为我们的书不是关于 CSS，因为使用 Bootstrap 制作东西是如此地简单！）

## 使用 jQuery 实现购物清单

可能，您的代码最终看起来会像以下内容：

以下是 HTML 代码：

```js
<div class="container"> 
  <h2>My Shopping List</h2> 
  <div class="input-group"> 
    <input placeholder="add shopping list item"        
      type="text" class="js-new-item form-control"> 
    <span class="input-group-btn"> 
      <button @click="addItem" class="js-add btn btn-default"          
        type="button">Add!</button> 
    </span> 
  </div> 
  <ul> 
    <li> 
      <div class="checkbox"> 
        <label> 
          <input class="js-item" name="list"              
            type="checkbox"> Carrot 
        </label> 
      </div> 
    </li> 
    <li> 
      <div class="checkbox"> 
        <label> 
          <input class="js-item" name="list" type="checkbox"> Book 
        </label> 
      </div> 
    </li> 
    <li class="removed"> 
      <div class="checkbox"> 
        <label> 
          <input class="js-item" name="list" type="checkbox"              
            checked> Gift for aunt's birthday 
        </label> 
      </div> 
    </li> 
  </ul> 
</div> 

```

以下是 CSS 代码：

```js
.container { 
  width: 40%; 
  margin: 20px auto 0px auto; 
} 

.removed { 
  color: gray; 
} 

.removed label { 
  text-decoration: line-through; 
} 

ul li { 
  list-style-type: none; 
} 

```

以下是 JavaScript/jQuery 代码：

```js
$(document).ready(function () { 
  /** 
   * Add button click handler 
   */ 
  function onAdd() { 
    var $ul, li, $li, $label, $div, value; 

    value = $('.js-new-item').val(); 
    //validate against empty values 
    if (value === '') { 
      return; 
    } 
    $ul = $('ul'); 
    $li = $('<li>').appendTo($ul); 
    $div = $('<div>') 
        .addClass('checkbox') 
        .appendTo($li); 
    $label = $('<label>').appendTo($div); 
    $('<input>') 
        .attr('type', 'checkbox') 
        .addClass('item') 
        .attr('name', 'list') 
        .click(toggleRemoved) 
        .appendTo($label); 
    $label 
        .append(value); 
    $('.js-new-item').val(''); 
  } 

  /** 
   * Checkbox click handler - 
   * toggles class removed on li parent element 
   * @param ev 
   */ 
  function toggleRemoved(ev) { 
    var $el; 

    $el = $(ev.currentTarget); 
    $el.closest('li').toggleClass('removed'); 
  } 

  $('.js-add').click(onAdd); 
  $('.js-item').click(toggleRemoved); 
}); 

```

### 提示

**`下载示例代码`** 下载代码包的详细步骤在本书的前言中有提到。该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learning-Vue.js-2`](https://github.com/PacktPublishing/Learning-Vue.js-2)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

如果您在浏览器中打开页面，您可能会看到类似以下内容：

![使用 jQuery 实现购物清单](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00218.jpeg)

使用 HTML + CSS + jQuery 方法实现购物清单

请查看[`jsfiddle.net/chudaol/u5pcnLw9/2/`](https://jsfiddle.net/chudaol/u5pcnLw9/2/)上的 JSFiddle。

正如你所看到的，这是一个非常基本的 HTML 代码片段，其中包含一个无序元素列表，每个元素都用复选框和文本呈现 - 一个用于用户文本和**`Add!`**按钮的输入。每次单击**`Add!`**按钮时，文本输入的内容都会被转换为列表条目并附加到列表中。当单击任何项目的复选框时，条目的状态会从**`to buy`**（未选中）切换到**`bought`**（已选中）。

让我们还添加一个功能，允许我们更改列表的标题（如果我们最终在应用程序中实现多个购物清单，这可能会很有用）。

因此，我们将最终得到一些额外的标记和一些更多的 jQuery 事件监听器和处理程序：

```js
<div class="container"> 
  <h2>My Shopping List</h2> 
  <!-- ... --> 
  <div class="footer"> 
    <hr/> 
    <em>Change the title of your shopping list here</em> 
    <input class="js-change-title" type="text"
      value="My Shopping List"/> 
  </div> 
</div> 

//And javascript code: 
function onChangeTitle() { 
  $('h2').text($('.js-change-title').val()); 
} 
$('.js-change-title').keyup(onChangeTitle); 

```

在[`jsfiddle.net/chudaol/47u38fvh/3/`](https://jsfiddle.net/chudaol/47u38fvh/3/)上查看 JSFiddle。

## 使用 Vue.js 实现购物清单

这是一个非常简单的例子。让我们尝试使用 Vue.js 逐步实现它。有很多种方法可以将`vue.js`包含到您的项目中，但在本章中，我们将通过添加来自**CDN**的 JavaScript Vue 文件来包含它：

```js
<script  src="https://cdnjs.cloudflare.com/ajax/libs/vue/2.0.3/vue.js">  </script> 

```

所以，让我们从渲染元素列表开始。

创建 HTML 文件并添加以下标记：

```js
<div id="app" class="container"> 
  <h2>{{ title }}</h2> 
  <ul> 
    <li>{{ items[0] }}</li> 
    <li>{{ items[1] }}</li> 
  </ul> 
</div> 

```

现在添加以下 JavaScript 代码：

```js
var data = { 
  items: ['Bananas', 'Apples'], 
  title: 'My Shopping List' 
}; 

new Vue({ 
  el: '#app', 
  data: data 
}); 

```

在浏览器中打开它。您会看到列表已经渲染出来了：

![使用 Vue.js 实现购物清单](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00219.jpeg)

使用 Vue.js 实现的购物清单

让我们分析一下这个例子。Vue 应用程序代码以新的`Vue`关键字开始。我们如何将标记片段绑定到应用程序数据？我们将 DOM 元素传递给`Vue`实例，该元素必须与其绑定。页面中的任何其他标记都不会受到影响，也不会识别 Vue 的魔法。

正如你所看到的，我们的标记被包裹在`#app`元素中，并作为`Vue`选项映射中的第一个参数传递。`data`参数包含在标记中使用双大括号(`{{}}`)的对象。如果您熟悉模板预处理器（例如 handlebars），您可能会发现这种注释非常容易理解；有关更多信息，请访问[`handlebarsjs.com/`](http://handlebarsjs.com/)。

那又怎样？—你可能会惊叹。你要教我什么？如何使用模板预处理器？非常感谢，但我宁愿喝点啤酒，看看足球。

停下来，亲爱的读者，别走，拿起你的啤酒，让我们继续我们的例子。你会发现这将是非常有趣的！

## 使用开发者工具分析数据绑定

让我们看看数据绑定的实际操作。打开浏览器的开发者工具，找到您的 JavaScript 代码，并在脚本的开头添加一个断点。现在分析一下 Vue 应用程序初始化之前和之后数据对象的样子。你会发现，它变化很大。现在`data`对象已经准备好进行反应式数据绑定了：

![使用开发者工具分析数据绑定](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00220.jpeg)

Vue 对象初始化之前和之后的数据对象

现在，如果我们从开发者工具控制台更改`data`对象的`title`属性（我们可以这样做，因为我们的`data`是一个全局对象），它将自动反映在页面上的标题中：

![使用开发者工具分析数据绑定](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00221.jpeg)

数据绑定：更改对象属性会立即影响视图

## 通过双向绑定将用户输入带入数据

因此，在我们的示例中，我们能够将数据从普通的 JavaScript 数据模型带到页面上。我们为它提供了一种从应用程序代码到页面的飞行。你不觉得如果我们能为我们的数据提供双向飞行会很好吗？

现在让我们看看如何实现双向数据绑定，以及如何从页面更改`data`属性的值。

复制标题的 HTML 标记，更改第一个 jQuery 示例中的输入，并向`input`元素添加属性`v-model="title"`。

### 提示

您已经听说过 Vue.js 中的指令了吗？恭喜，您刚刚使用了一个！实际上，`v-model`属性是 Vue.js 的一个指令，提供了双向数据绑定。您可以在官方 Vue 页面上阅读更多关于它的信息：[`vuejs.org/api/#v-model`](http://vuejs.org/api/#v-model)。

现在，我们的购物清单应用程序代码的 HTML 代码如下：

```js
<div id="app" class="container"> 
  <h2>{{ title }}</h2> 
  <ul> 
    <li>{{ items[0] }}</li> 
    <li>{{ items[1] }}</li> 
  </ul> 
  <div class="footer"> 
    <hr/> 
    <em>Change the title of your shopping list here</em> 
    <input v-model="title"/> 
  </div> 
</div> 

```

就是这样！

现在刷新页面并修改输入。您会看到标题在您输入时自动更新：

![通过双向绑定将用户输入带入数据](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00222.jpeg)

数据绑定：更改绑定到模型属性的文本会立即影响绑定到同一属性的文本。

因此，一切都很好；然而，这个例子只是抓取了两个项目元素，并将它们呈现为列表项。我们希望它能够独立于列表大小呈现项目列表。

## 使用 v-for 指令渲染项目列表

因此，我们需要一些机制来遍历`items`数组，并在我们的`<ul>`元素中呈现每个项目。

幸运的是，Vue.js 为我们提供了一个很好的指令，用于遍历迭代的 JavaScript 数据结构。它被称为`v-for`。我们将在列表项`<li>`元素中使用它。修改列表的标记，使其看起来像下面这样：

```js
  <ul> 
    <li v-for="item in items">{{ item }}</li> 
  </ul> 

```

### 注意

在本书中，您将学习到其他很好的指令，如`v-if`、`v-else`、`v-show`、`v-on`、`v-bind`等等，所以请继续阅读。

刷新页面并查看。页面保持不变。现在，尝试从开发者工具控制台将项目推入`items`数组中。也尝试弹出它们。您会不会惊讶地看到`items`数组的操作立即反映在页面上：

![使用 v-for 指令渲染项目列表](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00223.jpeg)

数据绑定：更改数组会立即影响基于它的列表

所以，现在我们有一个项目列表，只需一行标记就可以在页面上呈现出来。然而，我们仍然需要这些项目有一个复选框，允许我们在需要时勾选已购买的项目或取消勾选它们。

## 勾选和取消勾选购物清单项目

为了实现这种行为，让我们稍微修改我们的`items`数组，将我们的字符串项目更改为具有两个属性`text`和`checked`（以反映状态）的对象，并修改标记以为每个项目添加复选框。

因此，我们的数据声明的 JavaScript 代码将如下所示：

```js
var data = { 
  items: [{ text: 'Bananas', checked: true },    
          { text: 'Apples',  checked: false }], 
  title: 'My Shopping List', 
  newItem: '' 
}; 

```

我们的列表标记将如下所示：

```js
<ul> 
  <li v-for="item in items" v-bind:class="{ 'removed':      
    item.checked }"> 
    <div class="checkbox"> 
      <label> 
        <input type="checkbox" v-model="item.checked"> {{            
          item.text }} 
      </label> 
    </div> 
  </li> 
</ul>  

```

刷新页面并检查`items`复选框的`checked`属性，以及每个列表项`<li>`的移除类，是否与项目的`checked`布尔状态绑定。尝试点击复选框，看看会发生什么。仅仅用两个指令就能够传播项目的状态并改变相应的`<li>`HTML 元素的类，是不是很棒？

## 使用 v-on 指令添加新的购物清单项目

所以现在我们只需要对我们的代码进行一点小的修改，就能够真正地添加购物清单项目了。为了实现这一点，我们将在我们的数据中再添加一个对象，称之为`newItem`。我们还将添加一个小方法，将新项目推送到`items`数组中。我们将在标记页中使用`v:on`指令调用这个方法，该指令用于 HTML 输入元素和用于单击以添加新项目的按钮。

因此，我们的 JavaScript 代码将如下所示：

```js
var data = { 
  items: [{ text: 'Bananas', checked: true },    
          { text: 'Apples', checked: false }], 
  title: 'My Shopping List', 
  **newItem: ''** 
}; 
new Vue({ 
  el: '#app', 
  data: data, 
  **methods: { 
    addItem: function () { 
      var text; 

      text = this.newItem.trim(); 
      if (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }); 
        this.newItem = ''; 
      } 
    }** 
  } 
}); 

```

我们在`data`对象中添加了一个名为`newItem`的新属性。然后我们在 Vue 初始化`options`对象中添加了一个名为`methods`的新部分，并在该部分中添加了`addItem`方法。所有的数据属性都可以通过`this`关键字在`methods`部分中访问。因此，在这个方法中，我们只需获取`this.newItem`并将其推送到`this.items`数组中。现在我们必须将对这个方法的调用绑定到某个用户操作上。正如已经提到的，我们将使用`v-on`指令，并将其应用于新项目输入的`enter`键盘事件和**`Add!`**按钮的单击事件。

在我们的项目列表之前添加以下标记：

```js
<div class="input-group"> 
  <input v-model="newItem" **v-on:keyup.enter="addItem"**      
    placeholder="add shopping list item" type="text" class="form-      
    control"> 
  <span class="input-group-btn"> 
    <button **v-on:click="addItem"** class="btn btn-default"            
      type="button">Add!</button> 
  </span> 
</div> 

```

### 注意

`v-on`指令将事件侦听器附加到元素。快捷方式是`@`符号。因此，你可以用`@keyup="addItem"`来代替`v-on:keyup="addItem"`。你可以在官方文档网站上阅读更多关于`v-on`指令的信息，网址是[`vuejs.org/api/#v-on`](http://vuejs.org/api/#v-on)。

让我们完成。整个代码现在看起来像下面这样：

这是 HTML 代码：

```js
<div id="app" class="container"> 
  <h2>{{ title }}</h2> 
  <div class="input-group"> 
    <input v-model="newItem" @keyup.enter="addItem"        
      placeholder="add shopping list item" type="text" 
      class="form-control"> 
  <span class="input-group-btn"> 
    <button @click="addItem" class="btn btn-default"        
      type="button">Add!</button> 
  </span> 
  </div> 
  <ul> 
    <li v-for="item in items" :class="{ 'removed': item.checked      
      }"> 
      <div class="checkbox"> 
        <label> 
          <input type="checkbox" v-model="item.checked"> {{              
            item.text }} 
        </label> 
      </div>     
    </li> 
  </ul> 
  <div class="footer hidden"> 
    <hr/> 
    <em>Change the title of your shopping list here</em> 
    <input v-model="title"/> 
  </div> 
</div> 

```

这是 JavaScript 代码：

```js
var data = { 
  items: [{ text: 'Bananas', checked: true },    
          { text: 'Apples', checked: false }], 
  title: 'My Shopping List', 
  newItem: '' 
}; 

new Vue({ 
  el: '#app', 
  data: data, 
  methods: { 
    addItem: function () { 
      var text; 

      text = this.newItem.trim(); 
      if (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }); 
        this.newItem = ''; 
      } 
    } 
  } 
}); 

```

这是 JSFiddle 的链接：[`jsfiddle.net/chudaol/vxfkxjzk/3/`](https://jsfiddle.net/chudaol/vxfkxjzk/3/)。

# 在现有项目中使用 Vue.js

我现在可以感觉到你已经看到了将模型的属性绑定到表示层有多容易，你已经开始考虑如何在现有项目中使用它。但是然后你会想：天啊，不，我需要安装一些东西，运行`npm install`，改变项目的结构，添加指令，改变代码。

在这里我可以告诉你：不！不需要安装，不需要 npm，只需获取`vue.js`文件，将其插入到你的 HTML 页面中，然后使用它。就这样，不需要改变结构，不需要架构决策，也不需要讨论。只需使用它。我将向你展示我们在 EdEra（[`www.ed-era.com`](https://www.ed-era.com)）中如何在 GitBook 章节的末尾包含一个小的“自我检查”功能。

EdEra 是一个总部位于乌克兰的在线教育项目，其目标是将整个教育系统转变为现代、在线、互动和有趣的东西。实际上，我是这个年轻的美好项目的联合创始人兼首席技术官，负责整个技术部分。因此，在 EdEra，我们有一些建立在开放的 EdX 平台（[`open.edx.org/`](https://open.edx.org/)）之上的在线课程，以及一些建立在伟大的 GitBook 框架（[`www.gitbook.org`](http://www.gitbook.org)）之上的互动教育书籍。基本上，GitBook 是一个基于 Node.js 技术栈的平台。它允许具有对 Markdown 语言和基本 Git 命令的基本知识的人编写书籍并将它们托管在 GitBook 服务器上。EdEra 的书籍可以在[`ed-era.com/books`](http://ed-era.com/books)找到（注意，它们都是乌克兰语）。

让我们看看我们在书中使用 Vue.js 做了什么。

在某个时候，我决定在教授英语的书籍中关于人称代词的章节末尾包含一个小测验。因此，我包含了`vue.js` JavaScript 文件，编辑了相应的`.md`文件，并包含了以下 HTML 代码：

```js
<div id="pronouns"> 
    <p><strong>Check yourself :)</strong></p> 
    <textarea class="textarea" v-model="text" v-      
      on:keyup="checkText"> 
        {{ text }} 
    </textarea><i  v-bind:class="{ 'correct': correct,      
      'incorrect': !correct }"></i> 
</div> 

```

然后我添加了一个自定义的 JavaScript 文件，其中包含了以下代码：

```js
$(document).ready(function() { 
  var initialText, correctText; 

  initialText = 'Me is sad because he is more clever than I.'; 
  correctText = 'I am sad because he is more clever than me.'; 

  new Vue({ 
    el: '#pronouns', 
    data: { 
      text: initialText, 
      correct: false 
    }, 
    methods: { 
      checkText: function () { 
        var text; 
        text = this.text.trim(); 
        this.correct = text === correctText; 
      } 
    } 
  }); 
}); 

```

### 注意

你可以在这个 GitHub 页面上查看这段代码：[`github.com/chudaol/ed-era-book-english`](https://github.com/chudaol/ed-era-book-english)。这是一个用 markdown 编写并插入 HTML 的页面的代码：[`github.com/chudaol/ed-era-book-english/blob/master/2/osobovi_zaimenniki.md`](https://github.com/chudaol/ed-era-book-english/blob/master/2/osobovi_zaimenniki.md)。这是一个 JavaScript 代码：[`github.com/chudaol/ed-era-book-english/blob/master/custom/js/quiz-vue.js`](https://github.com/chudaol/ed-era-book-english/blob/master/custom/js/quiz-vue.js)。你甚至可以克隆这个存储库，并使用`gitbook-cli`在本地尝试（[`github.com/GitbookIO/gitbook/blob/master/docs/setup.md`](https://github.com/GitbookIO/gitbook/blob/master/docs/setup.md)）。

让我们来看看这段代码。你可能已经发现了你已经看过甚至尝试过的部分：

+   `data`对象包含两个属性：

+   字符串属性 text

+   布尔属性 correct

+   `checkText`方法只是获取`text`属性，将其与正确的文本进行比较，并将值分配给正确的值

+   `v-on`指令在键盘松开时调用`checkText`方法

+   `v-bind`指令将类`correct`绑定到`correct`属性

这是我的 IDE 中的代码样子：

![在现有项目中使用 Vue.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00224.jpeg)

在驱动项目中使用 Vue

接下来是在浏览器中的样子：

![在现有项目中使用 Vue.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00225.jpeg)

Vue.js 在 GitBook 页面内的实际应用

![在现有项目中使用 Vue.js](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00226.jpeg)

Vue.js 在 GitBook 页面内的实际应用

在[`english.ed-era.com/2/osobovi_zaimenniki.html`](http://english.ed-era.com/2/osobovi_zaimenniki.html)查看它。

很棒，对吧？非常简单，非常响应！

# Vue.js 2.0！

在撰写本文时，Vue.js 2.0 已经宣布（[`vuejs.org/2016/04/27/announcing-2.0/`](https://vuejs.org/2016/04/27/announcing-2.0/)）。请查看相关链接：

+   [`www.infoworld.com/article/3063615/javascript/vuejs-lead-our-javascript-framework-is-faster-than-react.html`](http://www.infoworld.com/article/3063615/javascript/vuejs-lead-our-javascript-framework-is-faster-than-react.html)

+   [`www.reddit.com/r/vuejs/comments/4gq2r1/announcing_vuejs_20/`](https://www.reddit.com/r/vuejs/comments/4gq2r1/announcing_vuejs_20/)

Vue.js 的第二个版本与其前身相比有一些显著的区别，从处理数据绑定的方式开始，到其 API。它使用轻量级虚拟 DOM 实现进行渲染，支持服务器端渲染，并且更快、更精简。

在撰写本文时，Vue 2.0 处于早期 alpha 阶段。不过不用担心。本书中涵盖的所有示例都基于 Vue 2.0 的最新稳定版本，并且与两个版本都完全兼容。

# 使用 Vue.js 的项目

也许，此时你想知道有哪些项目是建立在 Vue.js 之上，或者将其作为其代码库的一部分。有很多不错的开源、实验性和企业项目在使用它。这些项目的完整和不断更新的列表可以在[`github.com/vuejs/awesome-vue#projects-using-vuejs`](https://github.com/vuejs/awesome-vue#projects-using-vuejs)找到。

让我们来看看其中一些。

## Grammarly

Grammarly（[`www.grammarly.com/`](https://www.grammarly.com/)）是一个帮助您正确书写英语的服务。它有几个应用程序，其中一个是一个简单的 Chrome 扩展，只是检查您填写的任何文本输入。另一个是一个在线编辑器，您可以用它来检查大块的文本。这个编辑器是使用 Vue.js 构建的！以下是 Grammarly 在线编辑器中正在编辑的文本的截图：

![Grammarly](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00227.jpeg)

Grammarly：一个建立在 Vue.js 之上的项目

## Optimizely

Optimizely（[`www.optimizely.com/`](https://www.optimizely.com/)）是一个帮助您测试、优化和个性化您的网站的服务。我曾使用 Packt 网站创建了一个 Optimizely 实验，并在这个资源中查看了 Vue.js 的实际效果。它看起来像下面这样：

![Optimizely](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00228.jpeg)

Optimizely：一个建立在 Vue.js 之上的项目

鼠标悬停可以打开上下文菜单，允许对页面数据进行不同的操作，包括最简单的文本编辑。让我们试试这个：

![Optimizely](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00229.jpeg)

使用 Optimizely 并观看 Vue.js 的实际操作

文本框已打开。当我在其中输入时，标题中的文本会被动地更改。我们使用 Vue.js 看到并实现了它：

![Optimizely](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00230.jpeg)

使用 Optimizely 并观看 Vue.js 的实际操作

## FilterBlend

FilterBlend（[`github.com/ilyashubin/FilterBlend`](https://github.com/ilyashubin/FilterBlend)）是一个开源的 CSS 背景混合模式和滤镜属性的游乐场。

您可以加载您的图像并将混合与滤镜相结合。

如果您想尝试 FilterBlend，您可以在本地安装它：

1.  克隆存储库：

```js
**git clone https://github.com/ilyashubin/FilterBlend.git**

```

1.  进入`FilterBlend`目录：

```js
**cd FilterBlend**

```

1.  安装依赖项：

```js
**npm install**

```

1.  运行项目：

```js
**gulp**

```

在`localhost:8000`上打开您的浏览器并进行操作。您会发现，一旦您在右侧菜单中更改了某些内容，它会立即传播到左侧的图像中。所有这些功能都是使用 Vue.js 实现的。在 GitHub 上查看代码。

![FilterBlend](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00231.jpeg)

FilterBlend：一个基于 Vue.js 构建的项目

## PushSilver

PushSilver（[`pushsilver.com`](https://pushsilver.com)）是一个为忙碌的人创建简单发票的良好而简单的服务。它允许创建发票，向客户发送和重新发送它们，并跟踪它们。它是由一位进行自由咨询的开发人员创建的，他厌倦了每次为每个小项目创建发票。这个工具运行良好，它是使用 Vue.js 构建的：

![PushSilver](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00232.jpeg)

PushSilver：基于 Vue.js 构建的发票管理应用程序

![PushSilver](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00233.jpeg)

PushSilver：基于 Vue.js 构建的发票管理应用程序

# 书籍路线图

这本书，像大多数技术书籍一样，是以这样一种方式组织的，您不需要从头到尾阅读它。您可以选择您最感兴趣的部分并跳过其余部分。

本书的组织如下：

+   如果您正在阅读本书，就无需说明第一章中正在发生什么。

+   第二章，“基础知识-安装和使用”，是非常理论性的，将解释 Vue.js 及其主要部分背后发生了什么。因此，如果你不喜欢理论，想要动手编码，可以跳过这部分。在这一部分，我们还将介绍安装和设置过程。

+   从第三章到第八章，我们将在构建应用程序的同时探索 Vue.js 的主要特性。

+   在第三章，“组件-理解和使用”，我们将介绍 Vue 组件，并将这些知识应用到我们的应用程序中。

+   在第四章，“反应性-将数据绑定到您的应用程序”，我们将使用 Vue 提供的所有数据绑定机制。

+   在第五章，“Vuex-管理应用程序中的状态”，我们将介绍 Vuex 状态管理系统，并解释如何在我们的应用程序中使用它。

+   在第六章，“插件-用自己的砖建造你的房子”，我们将学习如何为 Vue 应用程序创建和使用插件，以丰富其功能。

+   在第七章，“测试-是时候测试我们到目前为止所做的了！”，我们将涵盖并探索 Vue.js 的自定义指令，并在我们的应用程序中创建一些。

+   在第八章，“部署-是时候上线了！”，我们将学习如何测试和部署使用 Vue.js 编写的 JavaScript 应用程序。

+   在第九章，“接下来是什么？”，我们将总结我们所学到的内容，并看看接下来我们可以做些什么。

# 让我们管理好时间！

此时此刻，我已经知道你对这本书非常热情，想要一口气读到底。但这是不对的。我们应该管理好我们的时间，给自己一些工作时间和休息时间。让我们创建一个小应用程序，实现番茄工作法定时器，以帮助我们管理工作时间。

### 注意

**Pomodoro**技术是一种以厨房番茄计时器命名的时间管理技术（事实上，Pomodoro 在意大利语中意味着番茄）。这种技术包括将工作时间分解为短暂休息间隔。在官方网站上了解更多关于 Pomodoro 技术的信息：[`pomodorotechnique.com/`](http://pomodorotechnique.com/)。

因此，我们的目标非常简单。我们只需要创建一个非常简单的时间计数器，直到工作间隔结束，然后重新开始并递减直到休息时间结束，依此类推。

让我们开始吧！

我们将引入两个 Vue 数据变量，`minute`和`second`，它们将显示在我们的页面上。每秒钟的主要方法将递减`second`；当`second`变为`0`时，它将递减`minute`；当`minute`和`second`变量都变为`0`时，应用程序应在工作和休息间隔之间切换：

我们的 JavaScript 代码将如下所示：

```js
const POMODORO_STATES = { 
  WORK: 'work', 
  REST: 'rest' 
}; 
const WORKING_TIME_LENGTH_IN_MINUTES = 25; 
const RESTING_TIME_LENGTH_IN_MINUTES = 5; 

new Vue({ 
  el: '#app', 
  data: { 
    minute: WORKING_TIME_LENGTH_IN_MINUTES, 
    second: 0, 
    pomodoroState: POMODORO_STATES.WORK, 
    timestamp: 0 
  }, 
  methods: { 
    start: function () { 
      this._tick(); 
      this.interval = setInterval(this._tick, 1000); 
    }, 
    _tick: function () { 
      //if second is not 0, just decrement second 
      if (**this.second** !== 0) { 
        **this.second**--; 
        return; 
      } 
      //if second is 0 and minute is not 0,        
      //decrement minute and set second to 59 
      if (**this.minute** !== 0) { 
        **this.minute**--; 
        **this.second** = 59; 
        return; 
      } 
      //if second is 0 and minute is 0,        
      //toggle working/resting intervals 
      this.pomodoroState = this.pomodoroState ===        
      POMODORO_STATES.WORK ? POMODORO_STATES.REST :        
      POMODORO_STATES.WORK; 
      if (this.pomodoroState === POMODORO_STATES.WORK) { 
        **this.minute** = WORKING_TIME_LENGTH_IN_MINUTES; 
      } else { 
        **this.minute** = RESTING_TIME_LENGTH_IN_MINUTES; 
      } 
    } 
  } 
}); 

```

在我们的 HTML 代码中，让我们为`minute`和`second`创建两个占位符，并为我们的 Pomodoro 计时器创建一个开始按钮：

```js
<div id="app" class="container"> 
  <h2> 
    <span>Pomodoro</span> 
    <button  **@click="start()"**> 
      <i class="glyphicon glyphicon-play"></i> 
    </button> 
  </h2> 
  <div class="well"> 
    <div class="pomodoro-timer"> 
      <span>**{{ minute }}**</span>:<span>{{ second }}</span> 
    </div> 
  </div> 
</div> 

```

再次，我们使用 Bootstrap 进行样式设置，因此我们的 Pomodoro 计时器看起来像下面这样：

![让我们管理时间！](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00234.jpeg)

使用 Vue.js 构建的倒计时器

我们的 Pomodoro 很好，但它也有一些问题：

+   首先，我们不知道正在切换的状态是哪个州。我们不知道我们是应该工作还是休息。让我们引入一个标题，每次 Pomodoro 状态改变时都会改变。

+   另一个问题是分钟和秒数的显示不一致。例如，对于 24 分钟 5 秒，我们希望看到 24:05 而不是 24:5。让我们通过在应用程序数据中引入计算值并显示它们而不是普通值来解决这个问题。

+   还有另一个问题是我们的开始按钮可以一遍又一遍地点击，这会在每次点击时创建一个计时器。尝试多次点击它，看看你的计时器会变得多么疯狂。让我们通过引入开始、暂停和停止按钮，将应用程序状态应用到它们，并根据状态禁用按钮来解决这个问题。

## 使用计算属性切换标题

让我们首先通过创建计算属性标题来解决第一个问题，并在我们的标记中使用它。

### 注意

**计算属性**是`data`对象中的属性，它们允许我们避免在模板中添加额外的逻辑。您可以在官方文档网站上找到有关计算属性的更多信息：[`vuejs.org/guide/computed.html`](http://vuejs.org/guide/computed.html)。

在 Vue 的`options`对象中添加`computed`部分，并在那里添加`title`属性：

```js
data: { 
  //... 
}, 
computed: { 
  title: function () { 
    return this.pomodoroState === POMODORO_STATES.WORK ? 'Work!' :      
    'Rest!' 
  } 
}, 
methods: { 
//... 

```

现在只需在标记中将以下属性用作普通的 Vue `data`属性：

```js
  <h2> 
    <span>Pomodoro</span> 
    <!--!> 
  </h2> 
  **<h3>{{ title }}</h3>** 
  <div class="well"> 

```

看！现在我们有一个标题，每当 Pomodoro 状态被切换时都会更改：

![使用计算属性切换标题](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00235.jpeg)

基于计时器状态自动更改标题

不错，是吧？

## 使用计算属性进行左填充时间值

现在让我们对`minute`和`second`数字应用相同的逻辑进行左填充。在我们的`computed`部分中的`data`选项中添加两个计算属性，`min`和`sec`，并应用简单的算法在左侧填充数字为`0`。当然，我们可以使用著名的 left-pad 项目（[`github.com/stevemao/left-pad`](https://github.com/stevemao/left-pad)），但为了保持简单并且不破坏整个互联网（[`www.theregister.co.uk/2016/03/23/npm_left_pad_chaos/`](http://www.theregister.co.uk/2016/03/23/npm_left_pad_chaos/)），让我们应用自己的简单逻辑：

```js
computed: { 
  title: function () { 
    return this.pomodoroState === POMODORO_STATES.WORK ? 'Work!' :      
    'Rest!' 
  }, 
  **min**: function () { 
    if (this.minute < 10) { 
      return '0' + this.minute; 
    } 

    return this.minute; 
  }, 
  **sec**: function () { 
    if (this.second < 10) { 
      return '0' + this.second; 
    } 

    return this.second; 
  } 
} 

```

并且在我们的 HTML 代码中使用这些属性代替`minute`和`second`：

```js
   <div class="pomodoro-timer"> 
    <span>**{{ min }}**</span>:<span>{{ sec }}</span> 
   </div> 

```

刷新页面并检查我们的数字现在有多美：

![使用计算属性进行左填充时间值](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00236.jpeg)

在 Vue.js 中使用计算属性进行左填充

## 使用开始、暂停和停止按钮保持状态

因此，为了解决第三个问题，让我们引入三种应用状态，`started`、`paused`和`stopped`，并且让我们有三种方法可以允许我们在这些状态之间进行排列。我们已经有了启动应用程序的方法，所以我们只需在那里添加逻辑来将状态更改为`started`。我们还添加了另外两种方法，`pause`和`stop`，它们将暂停计时器并更改为相应的应用程序状态：

```js
**const POMODORO_STATES = { 
  WORK: 'work', 
  REST: 'rest' 
}; 
const STATES = { 
  STARTED: 'started', 
  STOPPED: 'stopped', 
  PAUSED: 'paused' 
};** 
//<...> 
new Vue({ 
  el: '#app', 
  data: { 
    **state: STATES.STOPPED**, 
    //<...> 
  }, 
  //<...> 
  methods: { 
    start: function () { 
      **this.state = STATES.STARTED**; 
      this._tick(); 
      this.interval = setInterval(this._tick, 1000); 
    }, 
    **pause**: function () { 
      **this.state = STATES.PAUSED;** 
      clearInterval(this.interval); 
    }, 
    **stop**: function () { 
      **this.state = STATES.STOPPED;** 
      clearInterval(this.interval);  
      this.pomodoroState = POMODORO_STATES.WORK; 
      this.minute = WORKING_TIME_LENGTH_IN_MINUTES; 
      this.second = 0; 
    }, 
    //<...> 
  } 
}); 

```

然后，在我们的 HTML 代码中添加两个按钮，并添加调用相应方法的`click`监听器：

```js
    <button **:disabled="state==='started'"**
**@click="start()"**> 
      <i class="glyphicon glyphicon-play"></i> 
    </button> 
    <button **:disabled="state!=='started'"       
      @click="pause()"**> 
      <i class="glyphicon glyphicon-pause"></i> 
    </button> 
    <button **:disabled="state!=='started' && state !== 'paused'"      
       @click="stop()"**> 
      <i class="glyphicon glyphicon-stop"></i> 
    </button> 

```

现在我们的应用程序看起来很好，并且允许我们启动、暂停和停止计时器：

![使用开始、暂停和停止按钮保持状态](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00237.jpeg)

根据应用程序状态切换开始、停止和暂停按钮

在 JSFiddle 中查看整个代码的样子：[`jsfiddle.net/chudaol/b6vmtzq1/1/`](https://jsfiddle.net/chudaol/b6vmtzq1/1/)。

经过这么多的工作和新术语和知识，你肯定值得拥有一只小猫！我也喜欢小猫，所以这里有一只来自[`thecatapi.com/`](http://thecatapi.com/)的随机小猫：

![使用开始、暂停和停止按钮保持状态](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00238.jpeg)

# 练习

在本章结束时，我想提出一个小练习。我们在前几章中构建的番茄钟定时器无疑非常棒，但仍然缺少一些不错的功能。它可以提供的一个非常好的功能是在休息时间显示来自[`thecatapi.com/`](http://thecatapi.com/)的随机小猫。你能实现这个吗？当然可以！但请不要把休息时间和工作时间搞混了！我几乎可以肯定，如果你盯着小猫而不是工作，你的项目经理是不会太喜欢的。

这个练习的解决方案可以在附录中找到，*练习解答*。

# 摘要

我非常高兴你已经达到了这一点，这意味着你已经知道了 Vue.js 是什么，如果有人问你它是一个工具、一个库还是一个框架，你肯定会找到答案。你还知道如何使用 Vue.js 启动应用程序，以及如何在已有项目中使用 Vue 的功能。你已经玩过一些用 Vue.js 编写的非常棒的项目，并且开始开发一些属于自己的项目！现在你不仅仅是去购物，现在你是用 Vue.js 创建的购物清单去购物！现在你不需要从厨房偷一个番茄定时器来用作番茄钟定时器了；你可以使用自己用 Vue.js 制作的数字番茄钟定时器。最后但同样重要的是，现在你也可以在 JavaScript 应用程序中插入随机小猫，同样使用 Vue.js。

在下一章中，我们将介绍 Vue 的幕后工作原理，以及它是如何工作的，以及它使用的架构模式。每个概念都将以示例来加以说明。然后我们将准备深入代码，改进我们的应用程序，将它们提升到令人惊叹的状态。


# 第二章：基础知识-安装和使用

在上一章中，我们对 Vue.js 有了一些了解。我们能够在两个不同的应用程序中使用它，这两个应用程序是从头开始创建的。我们学会了如何将 Vue.js 集成到已经存在的项目中。我们能够看到 Vue 的响应式数据绑定是如何运作的。

现在，你可能会问自己：它是如何工作的？在数据模型发生变化时，它是如何实现快速 UI 变化的行为？也许，你决定在你的项目中使用 Vue.js，并且现在想知道它是否遵循某种架构模式或范式，以便你应该在你的项目中采用它。在本章中，我们将探讨 Vue.js 框架的关键概念，以了解其所有幕后功能。此外，在本章中，我们将分析安装 Vue.js 的所有可能方式。我们还将为我们的应用程序创建一个骨架，我们将通过接下来的章节来开发和增强它。我们还将学习调试和测试我们应用程序的方法。

因此，在本章中，我们将学习：

+   MVVM 架构范式是什么，以及它如何应用于 Vue.js

+   什么是声明式视图

+   Vue.js 如何探索定义的属性、getter 和 setter

+   Vue.js 中响应性和数据绑定的工作原理

+   什么是脏检查、DOM 和虚拟 DOM

+   Vue.js 1.0 和 Vue.js 2.0 之间的主要区别

+   可重用组件是什么

+   Vue.js 中插件、指令、自定义插件和自定义指令的工作原理

+   如何安装、启动、运行和调试 Vue 应用程序

# MVVM 架构模式

你还记得我们在第一章中如何创建`Vue`实例吗？我们通过调用`new Vue({...})`来实例化它。你还记得在选项中，我们传递了页面上应该绑定这个`Vue`实例的元素，以及包含我们想要绑定到我们视图的属性的`data`对象。`data`对象是我们的模型，而`Vue`实例绑定的 DOM 元素是我们的视图：

![MVVM 架构模式](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00239.jpeg)

经典的视图-模型表示，其中 Vue 实例将一个绑定到另一个

与此同时，我们的`Vue`实例是帮助将我们的模型绑定到视图以及反之的东西。因此，我们的应用程序遵循**模型-视图-视图模型**（**MVVM**）模式，其中`Vue`实例是视图模型：

![MVVM 架构模式](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00240.jpeg)

模型-视图-视图模型模式的简化图表

我们的**Model**包含数据和一些业务逻辑，我们的**View**负责其表示。**ViewModel**处理数据绑定，确保在**Model**中更改的数据立即影响**View**层，反之亦然。

因此，我们的视图完全是数据驱动的。**ViewModel**负责控制数据流，使数据绑定对我们来说完全是声明性的。

# DefineProperty、getter 和 setter

那么，一旦数据传递给`Vue`实例，会发生什么？`Vue`对其应用了哪些转换，使其自动绑定到 View 层？

让我们分析一下，如果我们有一个字符串，每次它改变时，我们想对某个 DOM 元素应用一些转换，我们会怎么做。我们会如何应用字符串更改的监听函数？我们会将它附加到什么上？没有`var stringVar='hello';stringVar.onChange(doSomething)`这样的东西。

所以我们可能会将字符串的值设置和获取包装在某种函数中，该函数会做一些事情，例如每次字符串更新时更新 DOM。你会如何实现它？当你考虑这个问题时，我会准备一个有趣的快速演示。

打开您的购物清单应用程序的开发者工具。让我们写一点代码。创建一个`obj`变量和另一个`text`变量：

```js
var obj = {}; 
var text = ''; 

```

让我们将 DOM 元素`h2`存储在一个变量中：

```js
var h2 = document.getElementsByTagName('h2')[0]; 

```

如果我们将`text`分配给`obj.text`属性，如何才能在每次更改此属性时，`h2`的`innerHTML`也会相应更改？

让我们使用`Object.defineProperty`方法（[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty)）。

该方法允许创建 getter 和 setter 函数，从而指定在访问或更改属性时必须发生什么：

```js
Object.defineProperty(obj, 'text', { 
  get: function () { 
    return text; 
  }, 
  set: function (newVal) { 
    text = newVal;  
    **h2.innerHTML = text;** 
  } 
}); 

```

现在尝试从控制台更改`obj.text`属性。看看标题：

![DefineProperty, getter 和 setter](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00241.jpeg)

每次属性更改时都会调用对象.defineProperty 的 set 方法

这个确切的机制被 Vue.js 使用过。一旦数据被传递给`Vue`实例，它的所有属性都会通过`Object.defineProperty`方法，为它们分配响应式的 getter 和 setter。对于页面上存在的每个指令，都会添加一个观察者，它会在`set`方法中被通知。在控制台中打开`vue.js`代码，并搜索一下说`set: function reactiveSetter(newVal)`的那一行。添加一个断点，尝试在输入框中更改购物清单的标题。现在一步步执行，直到达到这个函数中的最后一个调用，它说`dep.notify()`：

![DefineProperty, getters, and setters](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00242.jpeg)

在调用观察者通知方法的 setter 函数内部设置断点

进入这个函数。你会看到这个函数正在遍历属性的观察者并更新它们。如果你跳过这个调用，你会发现 DOM 没有被更新。这是因为在同一个事件循环中执行的更新被放入了定期刷新的队列中。

找到`runBatcherQueue`函数并在其中设置一个断点。再次尝试更改标题。你会看到这个函数遍历了所有等待在队列中的观察者，并在每个观察者上调用`run`方法。如果你进入这个方法，你会看到它将新值与先前的值进行比较：

```js
if (value !== this.value ||... 

```

然后它调用了回调的执行：

```js
this.cb.call(this.vm, value, oldValue); 

```

如果你进入这个回调函数，你会看到最终它会更新 DOM 的值：

```js
    update: function update(value) { 
      **this.el[this.attr] = _toString(value);** 
    } 

```

这不是很简单吗？

### 注意：

在这个调试中使用的是 Vue 版本 1.0。

所以 Vue.js 响应式数据绑定背后的机制非常简单。观察者被分配给所有的指令和数据属性。然后，在`Object.defineProperty`的`set`方法中，观察者被通知，然后它们更新相应的 DOM 或数据：

![DefineProperty, getters, and setters](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00243.jpeg)

从数据对象到 DOM 的数据流

具有指令的 DOM 元素附加了监听器，监听它们的更新并调用相应的数据属性 setter，然后唤醒它们的观察者。

# 与其他框架相比

当你尝试一个新的工具时，你想知道它与其他工具或框架相比如何。你可以在 Vue.js 的官方页面上找到关于这方面的深入分析：[`vuejs.org/guide/comparison.html`](http://vuejs.org/guide/comparison.html)。我只会指出一些我认为对于大多数使用的框架很重要的主题。

## React

React 和 Vue 非常相似。它们都使用虚拟 DOM，具有可重用的组件，并且都是关于反应性数据。然而，值得一提的是，Vue 只从其第二个主要版本开始使用虚拟 DOM。在 Vue 2.0 之前，它使用真实的 DOM。Vue 2.0 发布不仅比 Vue 1.0 更高效，而且比 React 更高效（[`vuejs.org/guide/comparison.html#Performance-Profiles`](http://vuejs.org/guide/comparison.html#Performance-Profiles)）。

最显著的区别可能是两个框架中如何创建组件的方式。你可能已经知道在 React 中，一切都是 JavaScript。即使是模板，也是用 JavaScript 开发的，这实际上可能是好的，因此程序员总是在相同的范围内，渲染变得更加灵活。

然而，对于一些想要进行快速原型设计的设计师，或者对编程技能不是很强的开发人员，或者只是不想学习 JSX 的人来说，这可能会变得非常痛苦。在 Vue 组件中，你实际上也可以使用 JSX，但你仍然可以遵循常见的 Web 开发结构：在`<style>`标签内编写 CSS，在`<template>`标签内编写 HTML 代码，在`<script>`标签内编写组件的逻辑。例如，比较一下 React 中渲染函数内的模板和你可以在 Vue 组件内编写的模板。在这个例子中，我将展示如何渲染我们之前看到的购物清单的项目列表。因此，在 React 中，你最终会得到类似于这样的 JSX 代码：

```js
render () { 
  return ( 
    <ul> 
    {items.map(item => 
    <li className={item.checked && 'removed'}> 
      <div className='checkbox'> 
        <input type='checkbox' checked={item.checked}>          
        { item.text } 
      </div> 
    </li> 
    )} 
    </ul> 
  ) 
}); 

```

使用 Vue，你只需在`template`标签内写入以下 HTML 代码：

```js
<template> 
<ul> 
  <li v-for="item in items" :class="{ 'removed': item.checked }"> 
    <div class="checkbox"> 
    <label> 
    <input type="checkbox" v-model="item.checked"> {{ item.text }} 
  </label> 
  </div> 
  </li> 
</ul> 
</template>
```

我个人喜欢将这些东西分开，因此我觉得 Vue 提供了这种可能性很好。

Vue 的另一个好处是它允许使用`scoped`属性附加到`style`标签来在组件内部限定样式：

```js
<style **scoped**> 
</style> 

```

在这种样式中，如果你使用预处理器，你仍然可以访问所有全局定义的变量，并且可以创建或重新定义只能由该组件访问的样式。

还值得一提的是，这两个框架的学习曲线。要开始使用 React 开发应用程序，您可能需要学习 JSX 和 ES2105 语法，因为官方 React 文档中的大多数示例都使用它。而对于 Vue，您可以从零开始。只需将其包含在页面中，就像您使用 jQuery 一样，您就可以使用相当简单和易于理解的语法来使用 Vue 模型和数据绑定，以及您喜欢使用的任何 JavaScript 版本。之后，您可以在学习和应用程序风格上进行扩展。

如果您想对这两个框架进行更深入的分析，请查看文档，尝试阐述类似的例子，并检查哪个更适合您的需求。

## Angular

Angular 1 和 Angular 2 之间有很大的区别。我们都知道，Angular 的第二个版本与其前身完全不同。它提供了更高的性能，API 也不同，并且底层实现已经被重写。

这两个版本的区别如此之大，以至于在 Vue 的官方文档中，您会发现对比两个 Angular 版本的比较，就像对比两个不同的框架一样。然而，学习曲线以及每个框架强制您构建应用程序的方式对于两个 Angular 版本都是横跨的。事实证明，Vue 比 Angular 1 和 Angular 2 都不那么武断。只需比较一下 Angular 的快速入门指南和 Vue 的 hello world 应用程序，就可以看出这一点。[`angular.io/docs/js/latest/quickstart.html`](https://angular.io/docs/js/latest/quickstart.html) 和 [`vuejs.org/guide/index.html#Hello-World`](http://vuejs.org/guide/index.html#Hello-World) 。

|   | *"即使没有 TypeScript，Angular 的快速入门指南也从一个使用 ES2015 JavaScript、NPM 的应用程序开始，有 18 个依赖项，4 个文件，超过 3000 个字来解释这一切 - 只是为了说 Hello World。"* |   |
| --- | --- | --- |
|   | --*http://vuejs.org/guide/comparison.html#Learning-Curve* |

如果您仍在使用 Angular 1，值得一提的是，这个框架与 Vue 之间的重大区别在于，在这个版本的 Angular 中，每次作用域发生变化时，都会重新评估所有的观察者，从而执行脏检查，因此当观察者的数量变得相当高时，性能会降低。因此，在 Vue 中，当作用域中的某些内容发生变化时，只有这个属性的观察者会被重新评估。其他观察者都会保持空闲，等待它们各自的调用。

## Vue

不，这不是打字错误。值得一提的是，Vue 也值得与 Vue 进行比较。Vue 最近推出了它的第二个版本，比起前身更快更干净。如果你仍在使用 Vue 1.0，值得升级。如果你对 Vue 的版本一无所知，值得了解它的发展以及新版本允许做什么。查看 Vue 在 2016 年 4 月发布 Vue 2.0 的博客文章[`vuejs.org/2016/04/27/announcing-2.0/`](https://vuejs.org/2016/04/27/announcing-2.0/)。

# Vue.js 基础知识

在将我们的手放入代码并开始用组件、插件、混合、模板和其他东西增强我们的应用程序之前，让我们回顾一下主要的 Vue 特性。让我们分析可重用组件是什么，以及如何管理应用程序状态，还谈论插件、过滤器和混合。在本节中，我们将对这些特性进行简要概述。我们将在接下来的章节中深入学习它们。

## 可重用组件

现在你不仅知道 Vue.js 中的数据绑定是什么以及如何使用它，还知道它是如何工作的，现在是时候介绍 Vue.js 的另一个强大特性了。使用 Vue.js 创建的组件可以在应用程序中被使用和重复使用，就像你用砖块建造房子一样。每个组件都有自己的样式和绑定范围，与其他组件完全隔离。

组件创建语法与我们已经了解的`Vue`实例创建非常相似，你只需要使用`Vue.extend`而不是`Vue`：

```js
var CustomComponent = Vue.extend({...}) 

```

![可重用组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00244.jpeg)

Vue.js 中的自定义组件

例如，让我们尝试将我们的购物清单代码分成组件。你记得，我们的购物清单基本上由三部分组成：包含购物清单项目的部分，包含添加新项目的输入的另一部分，以及允许更改购物清单标题的第三部分。

![可重用组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00245.jpeg)

购物清单应用程序的三个基本部分

让我们修改应用程序的代码，使其使用三个组件，每个部分一个组件。

我们的代码看起来像下面这样：

```js
var data = { 
  items: [{ text: 'Bananas', checked: true },    
          { text: 'Apples', checked: false }], 
  title: 'My Shopping List', 
  newItem: '' 
}; 

new Vue({ 
  el: '#app', 
  data: data, 
  methods: { 
    addItem: function () { 
      var text; 

      text = this.newItem.trim(); 
      if (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }); 
        this.newItem = ''; 
      } 
    } 
  } 
}); 

```

现在我们将创建三个组件：`ItemsComponent`、`ChangeTitleComponent` 和 `AddItemComponent`。它们都将具有带有 `data` 对象的 `data` 属性。`addItem` 方法将从主 `Vue` 实例跳转到 `ChangeTitleComponent`。所有必要的 HTML 将从我们的 `index.html` 文件转移到每个组件中。因此，最终，我们的主脚本将如下所示：

```js
var data = { 
  items: [{ text: 'Bananas', checked: true },
          { text: 'Apples', checked: false }], 
  title: 'My Shopping List', 
  newItem: '' 
}; 

/** 
 * Declaring components 
 */ 
var **ItemsComponent** = Vue.extend({ 
  data: function () { 
    return data; 
  }, 
  template: '<ul>' + 
  '           <li v-for="item in items"
              :class="{ 'removed': item.checked }">' + 
  '             <div class="checkbox">' + 
  '               <label>' + 
  '                 <input type="checkbox"                       
                    v-model="item.checked"> {{ item.text }}' + 
  '               </label>' + 
  '             </div>' + 
  '           </li>' + 
  '         </ul>' 
}); 
var **ChangeTitleComponent** = Vue.extend({ 
  data: function () { 
    return data; 
  }, 
  template: '<input v-model="title"/>' 
}); 
var **AddItemComponent** = Vue.extend({ 
  data: function () { 
    return data; 
  }, 
  methods: { 
    addItem: function () { 
      var text; 

      text = this.newItem.trim(); 
      if (text) { 
        this.items.push({ 
          text: text, 
          checked: false 
        }); 
        this.newItem = ""; 
      } 
    } 
  }, 
  template: 
  '<div class="input-group">' + 
    '<input v-model="newItem" @keyup.enter="addItem"        
     placeholder="add shopping list item" type="text"       
     class="form-control">'  + 
    '<span class="input-group-btn">'  + 
    '  <button @click="addItem" class="btn btn-default"           
       type="button">Add!</button>'  + 
    '</span>'  + 
  '</div>' 
}); 

/** 
 * Registering components 
 */ 
**Vue.component('items-component', ItemsComponent); 
Vue.component('change-title-component', ChangeTitleComponent); 
Vue.component('add-item-component', AddItemComponent);** 
/** 
 * Instantiating a Vue instance 
 */ 
new Vue({ 
  el: '#app', 
  data: data 
}); 

```

我们如何在视图中使用这些组件？我们只需用注册组件的标签替换相应的标记。我们的标记看起来像下面这样：

![可重用组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00246.jpeg)

具有定义组件的购物清单应用程序标记

因此，我们将用 `<add-item-component></add-item-component>` 标签替换第一个高亮区域，用 `<items-component></items-component>` 标签替换第二个高亮区域，用 `<change-title-component></change-title-component>` 标签替换第三个高亮区域。因此，我们之前庞大的标记现在看起来像下面这样：

```js
<div id="app" class="container"> 
  <h2>{{ title }}</h2> 
  **<add-item-component></add-item-component> 
  <items-component></items-component>** 
  <div class="footer"> 
    <hr/> 
    <em>Change the title of your shopping list here</em> 
    **<change-title-component></change-title-component>** 
  </div> 
</div> 

```

我们将在下一章深入研究组件，并学习一种更好的组织方式。敬请关注！

## Vue.js 指令

在上一章中，您已经学习了指令是什么，以及它们如何用于增强应用程序的行为。

您已经使用了一些指令，这些指令以不同的方式允许数据绑定到视图层（`v-model`、`v-if`、`v-show`等）。除了这些默认指令之外，Vue.js 还允许您创建自定义指令。自定义指令提供了一种机制，可以实现 DOM 到数据的自定义映射行为。

在注册自定义指令时，您可以提供三个函数：`bind`、`update` 和 `unbind`。在 `bind` 函数中，您可以将事件侦听器附加到元素，并在那里执行任何需要执行的操作。在接收旧值和新值作为参数的 `update` 函数中，您可以定义数据更改时应该发生的自定义行为。`unbind` 方法提供了所有所需的清理操作（例如，分离事件侦听器）。

### 提示

在 Vue 2.0 中，指令显著减少了责任范围，现在它们只用于应用低级别的直接 DOM 操作。Vue 的变更指南建议优先使用组件而不是自定义指令（[`github.com/vuejs/vue/issues/2873`](https://github.com/vuejs/vue/issues/2873)）。

因此，自定义指令的完整版本将如下所示：

```js
Vue.directive('my-directive', { 
  bind: function () { 
    // do the preparation work on element binding 
  }, 
  update: function (newValue, oldValue) { 
    // do something based on the updated value 
  }, 
  unbind: function () { 
    // do the clean-up work 
  } 
}) 

```

简化版本，如果您只需要在值更新时执行某些操作，则只能具有`update`方法，该方法可以直接作为指令函数的第二个参数传递：

```js
Vue.directive('my-directive', function (el, binding) { 
  // do something with binding.value 
}) 

```

理论很好，但没有一个小例子，它就会变得无聊。所以让我们看一个非常简单的例子，每次更新其值时都会显示数字的平方。

我们的自定义指令将如下所示：

```js
Vue.directive('square', function (el, binding) { 
  el.innerHTML = Math.pow(binding.value, 2); 
}); 

```

在模板文件中使用`v-`前缀使用此指令：

```js
<div v-square="item"></div> 

```

在其数据中实例化`Vue`实例，并尝试更改`item`的值。您会看到`div`元素内的值将立即显示更改后的值的平方数。此自定义指令的完整代码可以在 JSFiddle 上找到[`jsfiddle.net/chudaol/we07oxbd/`](https://jsfiddle.net/chudaol/we07oxbd/)。

## 在 Vue.js 中的插件

Vue 的核心功能，正如我们已经分析的那样，提供了声明性数据绑定和组件组合。这种核心行为通过提供丰富功能的插件得到增强。有几种类型的插件：

+   添加一些全局属性或方法（`vue-element`）的插件

+   添加一些全局资源（`vue-touch`）的插件

+   添加`Vue`实例方法并将它们附加到 Vue 的原型上的插件

+   提供一些外部功能或 API（`vue-router`）的插件

插件必须提供一个`install`方法，该方法可以访问全局`Vue`对象，以增强和修改它。为了使用此插件，Vue 提供了`use`方法，该方法接收插件实例（`Vue.use(SomePlugin)`）。

### 提示

您还可以编写自己的 Vue 插件，以启用对`Vue`实例的自定义行为。

让我们使用先前的自定义指令示例，并创建一个实现数学平方和平方根指令的简约插件。创建一个名为`VueMathPlugin.js`的文件，并添加以下代码：

```js
export default { 
  **install**: function (Vue) { 
    Vue.directive('square', function (el, binding) { 
      el.innerHTML = Math.pow(binding.value, 2); 
    }); 
    Vue.directive('sqrt', function (el, binding) { 
      el.innerHTML = Math.sqrt(binding.value); 
    }); 
  } 
}; 

```

现在创建一个名为`script.js`的文件。让我们将主要脚本添加到此文件中。在此脚本中，我们将同时导入`Vue`和`VueMathPlugin`，并将调用 Vue 的`use`方法，以告诉它使用插件并调用插件的`install`方法。然后我们将像往常一样初始化一个`Vue`实例：

```js
import Vue from 'vue/dist/vue.js'; 
import VueMathPlugin from './VueMathPlugin.js'; 

**Vue.use(VueMathPlugin);** 

new Vue({ 
  el: '#app', 
  data: { item: 49 } 
}); 

```

现在创建一个包含`main.js`文件的`index.html`文件（我们将使用 Browserify 和 Babelify 构建它）。在这个文件中，让我们使用`v-model`指令添加一个输入，用于更改项目的值。使用`v-square`和`v-sqrt`指令创建两个 span：

```js
<body> 
  <div id="app"> 
    <input v-model="item"/> 
    <hr> 
    <div>Square: <span **v-square="item"**></span></div> 
    <div>Root: <span **v-sqrt="item"**></span></div> 
  </div> 
  <script src="main.js"></script> 
</body> 

```

创建一个`package.json`文件，包括构建项目所需的依赖项，并添加一个构建`main.js`文件的脚本：

```js
{ 
  "name": "vue-custom-plugin", 
  "scripts": { 
    "build": **"browserify script.js -o main.js -t
       [ babelify --presets [ es2015 ] ]"** 
  }, 
  "version": "0.0.1", 
  "devDependencies": { 
    "babel-preset-es2015": "⁶.9.0", 
    "babelify": "⁷.3.0", 
    "browserify": "¹³.0.1", 
    "vue": "².0.3" 
  } 
} 

```

现在使用以下命令安装依赖并构建项目：

```js
**npm install**
**npm run build**

```

在浏览器中打开`index.html`。尝试更改输入框中的数字。正方形和平方根的值都会立即改变：

![Vue.js 中的插件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00247.jpeg)

数据的更改立即应用于作为自定义插件的一部分创建的指令

## 练习

使用三角函数（正弦、余弦和正切）增强`MathPlugin`。

此练习的可能解决方案可以在*附录*中找到。

## 应用状态和 Vuex

当应用程序达到相当大的规模时，可能需要我们以某种方式管理全局应用程序状态。受 Flux（[`facebook.github.io/flux/`](https://facebook.github.io/flux/)）的启发，有一个 Vuex 模块，允许我们在 Vue 组件之间管理和共享全局应用程序状态。

### 提示

不要将应用程序状态视为复杂和难以理解的东西。实际上，它只不过是数据。每个组件都有自己的数据，“应用程序状态”是可以在所有组件之间轻松共享的数据！

![应用状态和 Vuex](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00248.jpeg)

Vuex 存储库如何管理应用程序状态更新

与其他插件一样，为了能够使用和实例化 Vuex 存储库，您需要指示 Vue 使用它：

```js
import Vuex from 'vuex'; 
import Vue from 'vue'; 

Vue.use(Vuex); 

var store = new Vuex.Store({ 
  state: { <...> }, 
  mutations: { <...> } 
}); 

```

然后，在初始化主组件时，将存储实例分配给它：

```js
new Vue({ 
  components: components, 
  store: store 
}); 

```

现在，主应用程序及其所有组件都知道存储库，可以访问其中的数据，并能够在应用程序的任何生命周期中触发操作。我们将在接下来的章节中深入挖掘应用程序状态。

## vue-cli

是的，Vue 有自己的命令行界面。它允许我们使用任何配置初始化 Vue 应用程序。您可以使用 Webpack 样板初始化它，使用 Browserify 样板初始化它，或者只是使用一个简单的样板，只需创建一个 HTML 文件并为您准备好一切，以便开始使用 Vue.js 进行工作。

使用`npm`安装它：

```js
**npm install -g vue-cli**

```

初始化应用程序的不同方式如下：

```js
**vue init webpack**
**vue init webpack-simple**
**vue init browserify**
**vue init browserify-simple**
**vue init simple**

```

为了看到区别，让我们分别使用简单模板和 Webpack 模板运行`vue init`，并查看生成结构的差异。以下是两个命令的输出差异：

![vue-cli](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00249.jpeg)

命令`vue init webpack`和`vue init simple`的输出

以下是应用程序结构的不同之处：

![vue-cli](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00250.jpeg)

使用`vue init simple`和`vue init webpack`脚手架生成的应用程序结构的不同之处

简单配置中的`index.html`文件已经包含了来自 CDN 的 Vue.js，所以如果你只需要做一些非常简单的事情，比如快速原型设计，就可以使用这个。

但是，如果你要开始一个需要在开发过程中进行测试和热重载的复杂**单页面应用程序**（**SPA**）项目，请使用 Webpack 或 Browserify 配置。

## IDE 的 Vue 插件

有一些主要 IDE 的 Vue 语法高亮插件。我会给你留下最潮的链接：

| **IDE** | **链接到 Vue 插件** |
| --- | --- |
| Sublime | [`github.com/vuejs/vue-syntax-highlight`](https://github.com/vuejs/vue-syntax-highlight) |
| Webstorm | [`github.com/postalservice14/vuejs-plugin`](https://github.com/postalservice14/vuejs-plugin) |
| Atom | [`github.com/hedefalk/atom-vue`](https://github.com/hedefalk/atom-vue) |
| Visual Studio Code | [`github.com/LiuJi-Jim/vscode-vue`](https://github.com/LiuJi-Jim/vscode-vue) |
| vim | [`github.com/posva/vim-vue`](https://github.com/posva/vim-vue) |
| Brackets | [`github.com/pandao/brackets-vue`](https://github.com/pandao/brackets-vue) |

# 安装、使用和调试 Vue.js 应用程序

在本节中，我们将分析安装 Vue.js 的所有可能方式。我们还将为我们将在接下来的章节中开发和增强的应用程序创建一个骨架。我们还将学习调试和测试我们的应用程序的方法。

## 安装 Vue.js

有许多种安装 Vue.js 的方式。从经典的开始，包括将下载的脚本放入 HTML 的`<script>`标签中，使用诸如 bower、npm 或 Vue 的命令行接口（`vue-cli`）等工具，以启动整个应用程序。

让我们看看所有这些方法，并选择我们喜欢的。在所有这些示例中，我们只会在页面上显示一个标题，写着**`学习 Vue.js`**。

### 独立使用

下载`vue.js`文件。有两个版本，压缩和开发者版本。开发版本在[`vuejs.org/js/vue.js`](https://vuejs.org/js/vue.js)。压缩版本在[`vuejs.org/js/vue.min.js`](https://vuejs.org/js/vue.min.js)。

### 提示

如果您正在开发，请确保使用 Vue 的开发非压缩版本。您会喜欢控制台上的良好提示和警告。

然后只需在`<script>`标签中包含`vue.js`，如下所示：

```js
<script src="vue.js"></script> 

```

Vue 已在全局变量中注册。您可以开始使用它。

我们的示例将如下所示：

```js
  <div id="app"> 
    <h1>{{ message }}</h1> 
  </div> 
  **<script src="vue.js"></script>** 
  <script> 
     var data = { 
       message: 'Learning Vue.js' 
     }; 

     new Vue({ 
       el: '#app', 
       data: data 
     }); 
  </script> 

```

### CDN

Vue.js 在以下 CDN 中可用：

+   **jsdelivr**：[`cdn.jsdelivr.net/vue/2.0.3/vue.js`](https://cdn.jsdelivr.net/vue/2.0.3/vue.js)

+   **cdnjs**：[`cdnjs.cloudflare.com/ajax/libs/vue/2.0.3/vue.js`](https://cdnjs.cloudflare.com/ajax/libs/vue/2.0.3/vue.js)

+   **unpkg**：[`unpkg.com/vue@2.0.3/dist/vue.js`](https://unpkg.com/vue@2.0.3/dist/vue.js)（推荐）

只需将 URL 放在`script`标签中的源中，您就可以使用 Vue 了！

```js
<script src="  https://cdnjs.cloudflare.com/ajax/libs/vue/2.0.3/vue.js"></script> 

```

### 提示

请注意 CDN 版本可能与 Vue 的最新可用版本不同步。

因此，示例看起来与独立版本完全相同，但是我们使用 CDN URL 而不是在`<script>`标签中使用下载的文件。

### Bower

如果您已经在 Bower 中管理您的应用程序，并且不想使用其他工具，Vue 也有一个 Bower 分发版本。只需调用`bower install`：

```js
**# latest stable release**
**bower install vue**

```

我们的示例看起来与前两个示例完全相同，但它将包括来自`bower`文件夹的文件：

```js
<script src="bower_components/vue/dist/vue.js"></script> 

```

### 符合 CSP

**内容安全策略**（**CSP**）是一种安全标准，提供了一组规则，必须由应用程序遵守，以防止安全攻击。如果您正在为浏览器开发应用程序，您可能熟悉这个策略！

对于需要符合 CSP 的脚本的环境，Vue.js 有一个特殊版本，位于[`github.com/vuejs/vue/tree/csp/dist`](https://github.com/vuejs/vue/tree/csp/dist)。

让我们将我们的示例作为 Chrome 应用程序，看看符合 CSP 的 Vue.js 在其中的表现！

首先创建一个文件夹用于我们的应用程序示例。Chrome 应用程序中最重要的是`manifest.json`文件，它描述了您的应用程序。让我们创建它。它应该如下所示：

```js
{ 
  "manifest_version": 2, 
  "name": "Learning Vue.js", 
  "version": "1.0", 
  "minimum_chrome_version": "23", 
  "icons": { 
    "16": "icon_16.png", 
    "128": "icon_128.png" 
  }, 
  "app": { 
    "background": { 
      "scripts": ["main.js"] 
    } 
  } 
} 

```

下一步是创建我们的`main.js`文件，这将是 Chrome 应用程序的入口点。该脚本应监听应用程序的启动并打开一个给定大小的新窗口。让我们创建一个大小为 500 x 300 的窗口，并使用`index.html`打开它：

```js
chrome.app.runtime.onLaunched.addListener(function() { 
  // Center the window on the screen. 
  var screenWidth = screen.availWidth; 
  var screenHeight = screen.availHeight; 
  var width = 500; 
  var height = 300; 

  chrome.app.window.create(**"index.html"**, { 
    id: "learningVueID", 
    outerBounds: { 
      width: width, 
      height: height, 
      left: Math.round((screenWidth-width)/2), 
      top: Math.round((screenHeight-height)/2) 
    } 
  }); 
}); 

```

此时，Chrome 特定的应用程序魔法已经结束，现在我们只需创建一个`index.html`文件，该文件将执行与之前示例中相同的操作。它将包括`vue.js`文件和我们的脚本，我们将在其中初始化我们的 Vue 应用程序：

```js
<html lang="en"> 
<head> 
    <meta charset="UTF-8"> 
    <title>Vue.js - CSP-compliant</title> 
</head> 
<body> 
<div id="app"> 
    <h1>{{ message }}</h1> 
</div> 
<script src="assets/vue.js"></script> 
<script src="assets/app.js"></script> 
</body> 
</html> 

```

下载符合 CSP 标准的 Vue.js 版本，并将其添加到`assets`文件夹中。

现在让我们创建`app.js`文件，并添加我们已经多次编写的代码：

```js
var data = { 
  message: "Learning Vue.js" 
}; 

new Vue({ 
  el: "#app", 
  data: data 
}); 

```

将其添加到`assets`文件夹中。

不要忘记创建两个 16 和 128 像素的图标，并分别将它们命名为`icon_16.png`和`icon_128.png`。

最后，您的代码和结构应该看起来与以下内容差不多：

![CSP-compliant](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00251.jpeg)

使用 vue.js 创建示例 Chrome 应用程序的结构和代码

现在最重要的事情。让我们检查它是否有效！这非常非常简单：

1.  在 Chrome 浏览器中转到`chrome://extensions/url`。

1.  勾选**“开发者模式”**复选框。

1.  单击**“加载未打包的扩展程序...”**，并检查我们刚刚创建的文件夹。

1.  您的应用程序将出现在列表中！现在只需打开一个新标签，单击应用程序，然后检查您的应用程序是否存在。单击它！

![CSP-compliant](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00252.jpeg)

在 Chrome 应用程序列表中使用 vue.js 的示例 Chrome 应用程序

恭喜！您刚刚创建了一个 Chrome 应用程序！

### npm

建议对于大型应用程序使用`npm`安装方法。只需按照以下方式运行`npm install vue`：

```js
**# latest stable release**
**npm install vue**
**# latest stable CSP-compliant release**
**npm install vue@csp**

```

然后需要引入它：

```js
**var Vue = require("vue");**

```

或者，对于 ES2015 爱好者，请运行以下命令：

```js
**import Vue from "vue";**

```

我们的 HTML 将与之前的示例完全相同：

```js
<html lang="en"> 
<head> 
  <meta charset="UTF-8"> 
  <title>Vue.js - NPM Installation</title> 
</head> 
<body> 
  <div id="app"> 
    <h1>{{ message }}</h1> 
  </div> 
  <script src=**"main.js"**></script> 
</body> 
</html> 

```

现在让我们创建一个`script.js`文件，它几乎与独立版本或 CDN 版本完全相同，唯一的区别是它将需要`vue.js`：

```js
**var Vue = require('vue/dist/vue.js');** 

var data = { 
  message: 'Learning Vue.js' 
}; 

new Vue({ 
  el: '#app', 
  data: data 
}); 

```

让我们安装 Vue 和 Browserify，以便能够将我们的`script.js`文件编译成`main.js`文件：

```js
**npm install vue --save-dev**
**npm install browserify --save-dev**

```

在`package.json`文件中，添加一个构建脚本，该脚本将在`script.js`上执行 Browserify，将其转换为`main.js`。因此，我们的`package.json`文件将如下所示：

```js
{ 
  "name": "learningVue", 
  "scripts": { 
    "build": "browserify script.js -o main.js" 
  }, 
  "version": "0.0.1", 
  "devDependencies": { 
    "browserify": "¹³.0.1", 
    "vue": "².0.3" 
  } 
} 

```

现在运行以下命令：

```js
**npm run build**

```

然后在浏览器中打开`index.html`。

我有一个朋友在这一点上会说类似的话：真的吗？这么多步骤，安装，命令，解释...只是为了输出一些标题？我不干了！

如果您也在思考这个问题，请等一下。是的，这是真的，现在我们以一种相当复杂的方式做了一些非常简单的事情，但是如果您和我一起坚持一会儿，您将看到如果我们使用适当的工具，复杂的事情变得容易实现。另外，不要忘记检查您的番茄钟，也许是休息的时候了！

### vue-cli

正如我们在上一章中已经提到的，Vue 提供了自己的命令行界面，允许使用您想要的任何工作流来引导单页应用程序。它立即提供了热重载和测试驱动环境的结构。安装了`vue-cli`之后，只需运行`vue init <desired boilerplate> <project-name>`，然后只需安装和运行：

```js
**# install vue-cli**
**$ npm install -g vue-cli**
**# create a new project**
**$ vue init webpack learn-vue**
**# install and run**
**$ cd learn-vue**
**$ npm install**
**$ npm run dev** 

```

现在在`localhost:8080`上打开您的浏览器。您刚刚使用`vue-cli`来搭建您的应用程序。让我们将其调整到我们的示例中。打开一个源文件夹。在`src`文件夹中，您将找到一个`App.vue`文件。您还记得我们谈到过 Vue 组件就像是您构建应用程序的砖块吗？您还记得我们是如何在主脚本文件中创建和注册它们的，并且我提到我们将学习以更优雅的方式构建组件吗？恭喜，您正在看一个以时髦方式构建的组件！

找到说`import Hello from './components/Hello'`的那一行。这正是组件在其他组件中被重用的方式。看一下组件文件顶部的模板。在某个地方，它包含`<hello></hello>`标记。这正是在我们的 HTML 文件中`hello`组件将出现的地方。看一下这个组件；它在`src/components`文件夹中。正如您所看到的，它包含一个带有`{{ msg }}`的模板和一个导出带有定义的`msg`数据的脚本。这与我们在之前的示例中使用组件时所做的完全相同。让我们稍微修改代码，使其与之前的示例相同。在`Hello.vue`文件中，更改`data`对象中的`msg`：

```js
<script> 
export default { 
  data () { 
    return { 
   msg: **"Learning Vue.js"** 
    } 
  } 
} 
</script> 

```

在`App.vue`组件中，从模板中删除除了`hello`标记之外的所有内容，使模板看起来像下面这样：

```js
<template> 
  <div id="app"> 
    <hello></hello> 
  </div> 
</template> 

```

现在，如果重新运行应用程序，您将看到我们的示例具有美丽的样式，而我们没有触及：

![vue-cli](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00253.jpeg)

使用 vue-cli 引导的 Vue 应用程序

### 提示

除了 Webpack 样板模板，你可以使用以下配置与你的`vue-cli`一起使用：

+   `webpack-simple`：一个用于快速原型设计的简单 Webpack + vue-loader 设置

+   `browserify`：一个具有热重载、linting 和单元测试的全功能 Browserify + Vueify 设置

+   `browserify-simple`：一个用于快速原型设计的简单 Browserify + Vueify 设置

+   `simple`：一个在单个 HTML 文件中的最简单的 Vue 设置

### Dev build

亲爱的读者，我能看到你闪亮的眼睛，我能读懂你的心思。现在你知道如何安装和使用 Vue.js 以及它的工作原理，你肯定想深入了解核心代码并做出贡献！

我理解你。为此，你需要使用 Vue.js 的开发版本，你需要从 GitHub 上下载并自行编译。

让我们用这个开发版本的 Vue 来构建我们的示例。创建一个新文件夹，例如`dev-build`，并将所有文件从 npm 示例复制到此文件夹中。

不要忘记复制`node_modules`文件夹。你应该`cd`进入它，并从 GitHub 下载文件到其中，然后运行`npm install`和`npm run build`：

```js
**cd <APP-PATH>/node_modules**
**rm -rf vue**
**git clone https://github.com/vuejs/vue.git**
**cd vue**
**npm install**
**npm run build**

```

现在构建我们的示例应用程序：

```js
**cd <APP-PATH>**
**npm run build**

```

在浏览器中打开`index.html`，你会看到通常的**`学习 Vue.js`**标题。

现在让我们尝试更改`vue.js`源代码中的一些内容！转到`node_modules/vue/src/compiler/parser`文件夹，并打开`text-parser.js`文件。找到以下行：

```js
const defaultTagRE = /\{\{((?:.|\n)+?)\}\}/g  

```

实际上，这个正则表达式定义了 HTML 模板中使用的默认定界符。这些定界符内的内容被识别为 Vue 数据或 JavaScript 代码。让我们改变它们！让我们用双百分号替换`{`和`}`！继续编辑文件：

```js
const defaultTagRE = /\%\%((?:.|\n)+?)\%\%/g  

```

现在重新构建 Vue 源代码和我们的应用程序，然后刷新浏览器。你看到了什么？

![Dev build](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00254.jpeg)

更改 Vue 源代码并替换定界符后，{{}}定界符不再起作用！

`{{}}`中的消息不再被识别为我们传递给 Vue 的数据。实际上，它被呈现为 HTML 的一部分。

现在转到`index.html`文件，并用双百分号替换我们的花括号定界符，如下所示：

```js
<div id="app"> 
  <h1>**%% message %%**</h1> 
</div> 

```

重新构建我们的应用程序并刷新浏览器！现在怎么样？你看到了改变框架代码并尝试你的改变是多么容易。我相信你有很多关于如何改进或添加一些功能到 Vue.js 的想法。所以改变它，重新构建，测试，部署！愉快的拉取请求！

# 调试您的 Vue 应用程序

您可以像调试任何其他 Web 应用程序一样调试您的 Vue 应用程序。使用开发者工具（firebug），断点，调试器语句等。如果您想深入了解 Chrome 调试工具，请查看 Chrome 的文档[`developer.chrome.com/devtools`](https://developer.chrome.com/devtools)。

Vue 还提供了*Vue.js devtools*，因此调试 Vue 应用程序变得更容易。您可以从 Chrome 网络商店下载并安装它[`chrome.google.com/webstore/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd`](https://chrome.google.com/webstore/detail/vuejs-devtools/nhdogjmejiglipccpnnnanhbledajbpd)。

不幸的是，它不适用于本地打开的文件，因此请使用一些简单的 HTTP 服务器来将我们的示例作为 Web 页面提供（例如，[`www.npmjs.com/package/http-server`](https://www.npmjs.com/package/http-server)）。

安装后，打开，例如，我们的购物清单应用程序。打开开发者工具。您将看到**`Vue`**选项卡已自动出现：

![调试您的 Vue 应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00255.jpeg)

Vue devtools

在我们的情况下，我们只有一个组件—**`<Root>`**。可以想象，一旦我们开始使用组件并且有很多组件，它们都会出现在 Vue devtools 调色板的左侧。单击**`<Root>`**组件并对其进行检查。您将看到附加到此组件的所有数据。如果您尝试更改某些内容，例如添加购物清单项目，检查或取消复选框，更改标题等，所有这些更改都将立即传播到 Vue devtools 中的数据。您将立即在其右侧看到更改。例如，让我们尝试添加一个购物清单项目。一旦开始输入，您会看到`newItem`如何相应更改：

![调试您的 Vue 应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00256.jpeg)

模型中的更改立即传播到 Vue devtools 数据

当我们开始添加更多组件并向我们的 Vue 应用程序引入复杂性时，调试肯定会变得更有趣！

# 搭建我们的应用程序

你还记得我们在第一章开始工作的两个应用程序，购物清单应用程序和番茄钟应用程序吗？在本节中，我们将使用`vue-cli`工具搭建这些应用程序，以便它们准备好包含可重用组件，进行测试和部署。一旦我们引导这些应用程序，我们将在本书的最后工作。所以让我们小心谨慎地做，并充满爱心！

## 搭建购物清单应用程序

我们将使用`vue-cli` Webpack 配置来搭建购物清单应用程序。

### 提示

如果你忽略了与`vue-cli`相关的所有先前的实际练习，请不要忘记在继续下一步之前安装它：**npm install -g vue-cli**

如果你已经安装了`vue-cli`，请转到要引导应用程序的目录并运行以下命令：

```js
**vue init webpack shopping-list**

```

对所有问题回答 yes（只需点击回车键），voilà！你已经引导了应用程序：

![搭建购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00257.jpeg)

使用 vue-cli 引导购物清单应用程序

切换到购物清单目录并运行`npm install`和`npm run dev`。在`localhost:8080`上打开你的浏览器。你会看到新创建的 Vue 应用程序的**`Hello World`**页面：

![搭建购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00258.jpeg)

新引导应用程序的 Hello World 视图

让我们清理引导代码，使应用程序准备好填充我们的特定应用程序代码。转到`App.vue`文件并删除所有内容，只留下定义应用程序结构的标签：

+   `<template>`与主要的`<div>`内部

+   `<script>`标签

+   `<style>`标签

因此，最终，你的`App.vue`文件看起来像下面这样：

```js
<template>
  <div id="app">
  </div>
</template>

<script>
</script>

<style>
</style>

```

看看在浏览器中打开的页面。有趣的是，你什么都没做，但页面现在不再包含默认的**`Hello World`**。页面是空的！它自动改变了！

尝试在`<template>`标签内添加一些内容。查看页面；一旦你引入更改，它会自动重新加载。这是因为`vue-hot-reload`插件会检测你的 Vue 组件的更改，并自动重建项目并重新加载浏览器页面。尝试在`<script>`标签内写一些不符合 lint 标准的 JavaScript 代码，例如使用`notDefinedVariable`：

```js
<script> 
  **notDefinedVariable = 5;** 
</script> 

```

浏览器中的页面没有刷新。看看你的 shell 控制台。它显示了*lint*错误，并且“拒绝”构建你的应用程序：

![搭建购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00259.jpeg)

每次应用程序更改时都会检查 lint 规则

这是因为 ESLint 插件会检查代码是否符合 lint 规则，每次应用程序更改时都会发生这种情况。

有了这个，我们可以确信我们的代码将遵循最佳的质量标准。

说到质量，我们还应该准备好我们的应用程序能够运行单元测试。幸运的是，`vue-cli`与 Webpack 已经为我们做好了准备。运行`npm run unit`来运行单元测试，运行`npm run e2e`来运行端到端的 nightwatch 测试。端到端测试不会与正在运行的应用程序并行运行，因为两者都使用相同的端口。因此，如果你想在开发过程中运行测试，你应该在`config/index.js`配置文件中更改端口，或者在运行测试之间简单地停止应用程序。运行测试后，你会看到端到端测试失败。这是因为它们正在检查我们已经删除的应用程序特定元素。打开`test/e2e/specs/`目录下的`test.js`文件，并清除所有我们不再需要的断言。现在它应该看起来像下面这样：

```js
module.exports = { 
  'default e2e tests': function (browser) { 
    browser 
    .url('http://localhost:8080') 
      .waitForElementVisible('#app', 5000) 
      .end() 
  } 
} 

```

重新运行测试。现在它们应该通过了。从现在开始，当我们向我们的应用程序添加代码时，我们将添加单元测试和端到端测试。

## 启动你的番茄钟应用程序

对于番茄钟应用程序，做与购物清单应用程序相同的事情。运行`vue init webpack pomodoro`，并重复所有必要的步骤，以确保结构已准备好用于填充番茄钟应用程序的代码！

# 练习

将我们的番茄钟应用程序实现为 Chrome 应用程序！你只需要使用符合 CSP 的 Vue.js 版本，并添加一个`manifest.json`文件。

# 总结

在本章中，我们分析了 Vue.js 的幕后情况。你学会了如何实现数据的响应性。你看到了 Vue.js 如何利用`Object.defineProperty`的 getter 和 setter 来传播数据的变化。你看到了 Vue.js 概念的概述，比如可重用组件、插件系统和使用 Vuex 进行状态管理。我们已经启动了我们将在接下来的章节中开发的应用程序。

在下一章中，我们将更深入地了解 Vue 的组件系统。我们将在我们的应用程序中使用组件。
