# Vue2 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3`](https://zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue.js 2 是一个简单而强大的框架。它将使你能够快速原型化开发小型应用程序，并且在构建大型前端系统时不会阻碍。本书是一本食谱书，每一段都是一个菜谱；就像普通的食谱书一样，你可以快速跳到你感兴趣的菜谱，或者从头到尾阅读，成为一位优秀的厨师。

所有的菜谱（除了一小部分）都是基于可工作的 Vue 应用程序，所以在学习结束时你永远不会一无所获。当我编写它们时，我尽量给出有意义的例子，并尽可能增添一些乐趣。所有的菜谱在执行相同的任务时都稍有不同，所以即使实施非常相似的菜谱，你也会学到一些新的东西。

这本书花了大约 6 个月的时间来写，即使在这短暂的时间内，我不得不回过头来更新图片和 API 的变化，以及添加新的概念。然而，许多菜谱都融入了可重用性和良好工程的永恒概念，所以我希望这本书的一部分将作为有用的技术留在你心中，并在你的应用程序中进行重用。

最后，虽然我确保了每一章都有足够的图片来说明预期的输出，但我认为对你来说实际键入和尝试这些菜谱是非常重要的。

祝愿你构建出伟大的东西并玩得开心！

# 本书涵盖内容

第一章，*开始*，是您创建第一个 Vue 应用程序并熟悉最常见的功能和开发工具的地方。

第二章，*基本 Vue.js 特性*，是您轻松构建列表和表单，并学习如何样式化它们的地方。

第三章，*过渡和动画*，是您了解过渡和动画如何为应用程序带来更多活力的地方。您还将集成外部 CSS 库。

第四章，*组件！*，是您意识到在 Vue 中一切都是组件，并可以利用它来减少重复并重用您的代码的地方。

第五章，*与互联网通信*，是您进行第一次 AJAX 调用并创建表单和完整的 REST 客户端（以及服务器！）的地方。

第六章，*单页应用程序*，是您使用 vue-router 创建静态和动态路由以创建现代 SPA 的地方。

第七章，*单元测试和端对端测试*，是您通过添加 Karma、Chai、Moka、Sinon.JS 和 nightwatch 来学习创建专业软件，以确保可以自信地重构应用程序的地方。

第八章，*组织+自动化+部署=Webpack*，是您实际将精确制作的组件发布到 npm 并学习 Webpack 和 Vue 如何共同工作的地方。

【第九章】*Advanced Vue.js* , 探索指令、插件、功能组件和 JSX。

【第十章】*Large Application Patterns with Vuex* , 使用 Vuex 对应用程序进行结构化，使用经过测试的模式来确保应用程序的可维护性和性能。

【第十一章】*Integrating with External Frameworks* , 使用 Vue 和 Electron、Firebase、Feathers 和 Horizon 构建四个不同的应用程序。

# 阅读本书所需的条件

为了能够跟上本书的内容，您需要一台连接互联网的计算机。您可以选择在线使用 Chrome 完成示例。在某个阶段，您至少需要一个文本编辑器；我强烈推荐 Microsoft Visual Studio Code 来完成这项工作。

# 本书的读者对象

这本书已经在一些连 JavaScript 都不懂的人身上进行了测试。他们通过阅读第一章就能够学会 Vue！在继续深入学习中，您将会遇到更加高级的概念，即使您已经熟悉 Vue 2，您也可能会发现一些之前不知道的技巧或者对您有所帮助的智慧建议。

这本书，如果你从头到尾按照步骤进行，将能够使你成为一名熟练的 Vue 开发者。另一方面，如果你已经是一名熟练的开发者，它也提供了许多不同功能和技术的良好参考，适用于一些偶尔需要的情况。最后，如果你已经尝试过 Vue 1，并且对变化感到不知所措，这本书也是一个有效的迁移指南。

# 章节

在本书中，您会经常看到几个标题（准备工作、操作步骤、工作原理、更多信息、另请参阅）。

为了清楚地说明如何完成一个示例，我们将这些章节分以下几个部分：

# 准备工作

本节告诉您在示例中可以预期的情况，并描述了设置示例所需的任何软件或预备设置的方法。

# 操作步骤

本节包含了跟随示例所需的步骤。

# 工作原理

本节通常会对上一节中发生的情况进行详细解释。

# 更多信息

本节包含有关示例的其他信息，以便读者对示例有更多了解。

# 另请参阅

本节提供了有关示例的其他有用信息的链接。

# 约定

在本书中，您会找到一些用来区分不同类型信息的文本样式。以下是一些样式的示例及其含义的解释。

以下是文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 账户的展示方式：“我将要更新`EngineTest`项目中已存在的`ChasePlayerComponent`类。”

代码块设置如下：

当我们希望引起您对代码块的特定部分的注意时，相关行或项会以粗体显示：

命令行输入或输出以以下方式显示：

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的词，例如菜单或对话框中的词，以此文本形式出现：“打开 Webstorm 并创建一个新的空项目”

警告或重要提示以此方式显示。提示和技巧以此方式显示。


# 第一章：使用 Vue.js 入门

本章将介绍以下内容：

+   使用 Vue.js 编写 Hello World

+   编写列表

+   创建一个动态和动画列表

+   响应事件，如点击和按键

+   选择开发环境

+   使用过滤器格式化文本

+   使用 Mustaches 调试应用程序（例如 JSON 过滤器）

+   使用 Vue 开发者工具分析应用程序

+   升级到 Vue.js 2

# 简介

Vue 是一个非常强大的框架，但其优势之一是它非常轻量级且容易上手。事实上，在第一个示例中，您将在几分钟内构建一个简单但功能齐全的程序，无需任何设置即可完成。

在本章中，您将学习如何创建重复元素的网页列表（如目录）。此外，您将构建一个带有事件监听器的交互式页面。

为了让您更好地选择开发环境，我们还介绍了一些开发环境。您将使用一些调试技巧来快速开发自己的代码，并更好地理解如何解决应用程序中的错误。

请注意，在撰写本文时，ES5 是浏览器中 JavaScript 最好支持的标准。在这一章中，我将使用 ES5，这样即使您的浏览器不支持更新的 ES6，您也可以跟着学习。请记住，在后续章节中将使用 ES6。目前，Chrome 与大多数 ES6 的重要构造兼容，但通常您应该使用**Babel**使您的应用程序兼容旧版浏览器。当您准备好使用 Babel 时，请参考第八章中的配方*如何使用 Babel 编译 ES6*，以及*组织 + 自动化 + 部署 = Webpack*。

# 用 Vue.js 编写 Hello World

让我们使用 Vue.js 创建最简单的程序，即必备的 Hello World 程序。我们的目标是让您熟悉 Vue 如何操作您的网页以及数据绑定是如何工作的。

# 准备工作

完成这个入门示例，我们只需要使用浏览器。也就是说，我们将使用 JSFiddle 来编写代码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00004.jpg)

如果您从未使用过 JSFiddle，请不要担心；您即将成为一名专业的前端开发人员，使用 JSFiddle 将成为您口袋中的有用工具：

1.  将您的浏览器导航到[`jsfiddle.net`](https://jsfiddle.net)：

您将看到一个空白页面分为四个象限。左下方是我们将编写 JavaScript 代码的地方。按顺时针方向，我们有一个 HTML 部分，一个 CSS 部分，最后是我们预览的结果页面。

开始之前，我们应该告诉 JSFiddle 我们想要使用 Vue 库。

1.  在 JavaScript 象限的右上角，点击齿轮图标并从列表中选择 Vue 2.2.1（你会找到多个版本，“edge”代表最新版本，在撰写时对应的是 Vue 2）。

现在我们准备好编写我们的第一个 Vue 程序了。

# 具体步骤如下：

1.  在 JavaScript 部分写入：

```js
        new Vue({el:'#app'})

```

1.  在 HTML 象限中，创建`<div>`：

```js
        <div id="app">

          {{'Hello ' + 'world'}}

        </div>

```

1.  点击左上角的运行按钮，我们可以看到页面显示 Hello world：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00005.jpg)

# 工作原理如下：

`new Vue({el:'#app'})`将实例化一个新的 Vue 实例。它接受一个选项对象作为参数。这个对象在 Vue 中是核心的，它定义和控制数据和行为。它包含了创建 Vue 实例和组件所需的所有信息。在我们的例子中，我们只指定了`el`选项，它接受一个选择器或一个元素作为参数。`#app`参数是一个选择器，将返回页面中以`app`作为标识符的元素。例如，在这样的页面中：

```js
<!DOCTYPE html> 

<html> 

  <body> 

    <div id="app"></div> 

  </body> 

</html>

```

我们在具有 ID 为`app`的`<div>`中编写的所有内容都将在 Vue 的范围之内。

现在，JSFiddle 会将我们在 HTML 象限中编写的所有内容包装在 body 标签中。这意味着，如果我们只需要在 HTML 象限中写入`<div>`，JSFiddle 会负责将其包装在 body 标签中。

还有一点要注意，将`#app`放置在`body`或`html`标签上会抛出错误，因为 Vue 建议我们将应用挂载在普通元素上，选择`body`也是同样的情况。

花括号（或者叫 handlebars）是告诉 Vue 将其内部的所有内容解析为代码的一种方法。引号是 JavaScript 中声明字面字符串的一种正常方法，所以 Vue 只会返回`hello`和`world`的字符串拼接。没有什么花哨的东西，我们只是将两个字符串拼接在一起并显示结果。

# 更多内容

我们可以利用这一点做一些更有趣的事情。如果我们是外星人，想要同时问候多个世界，我们可以这样写：

```js
We conquered 5 planets.<br/> 

{{'Hello ' + 5 + ' worlds'}}

```

我们可能会追踪不住我们征服了多少个世界。没问题，我们可以在花括号内进行数学运算。另外，让我们将`Hello`和`worlds`放在花括号之外：

```js
We conquered {{5 + 2}} planets.<br/> 

Hello {{5 + 2}} worlds

```

在花括号内使用原始数字表示世界的数量会显得很混乱。我们将使用数据绑定将其放在实例中的一个命名变量中：

```js
<div id="app"> 

  We conquered {{countWorlds}} planets.<br/> 

  Hello {{countWorlds}} worlds 

</div>

new Vue({ 

  el:'#app', 

  data: { 

    countWorlds: 5 + 2 

  } 

})

```

这是整洁应用程序的实现方式。现在，每次我们征服一个星球，我们只需要编辑`countWorlds`变量。反过来，每次我们修改这个变量，HTML 将自动更新。

恭喜，您已经完成了进入 Vue 世界的第一步，现在可以使用响应式数据绑定和字符串插值构建简单的交互式应用程序。

# 编写列表

生产列表的欲望似乎是人类天性中固有的一部分。通过观察一个井然有序的列表在计算机屏幕上滚动，人们可以获得一种深深满足的感觉。

借助 Vue，我们可以使用出色的外观和极大的便利性制作各种类型的列表。

# 准备工作

在本篇文章中，我们将使用基本的数据绑定，如果您遵循了最初的教程，您已经很熟悉它了。

# 具体操作如下...

我们将以几种不同的方式构建列表：使用一系列数字、使用数组以及使用对象。

# 一系列数字

要开始创建列表，请像前面的教程中一样设置您的 JSFiddle，并添加 Vue.js 作为框架。选择 Vue 2.2.1（或 Vue（edge））：

1.  在 JavaScript 部分编写如下内容：

```js
        new Vue({el:'#app'})

```

1.  在 HTML 中编写如下内容：

```js
        <div id="app"> 

          <ul> 

            <li v-for="n in 4">Hello!</li> 

          </ul> 

        </div>

```

这将导致一个列表，其中*Hello!*重复出现四次。几秒钟后，您的第一个列表就完成了，做得好！

我们可以使用这种技术编写一个倒计时 - 在 HTML 中，将<div>标签的内容替换为以下内容：

```js
<div id="app"> 

  <ul> 

    <li v-for="n in 10">{{11-n}}</li> 

    <li>launch missile!</li> 

  </ul> 

</div>

```

# 数组

1.  在 HTML 中，为了得到相同的结果，编辑列表以反映以下内容：

```js
        <ul> 

            <li v-for="n in [10,9,8,7,6,5,4,3,2,1]">{{n}}</li> 

            <li>launch missile!</li> 

        </ul>

```

尽管这个列表与上一个列表相同，但我们不应该在 HTML 标记中放置字面数组。

1.  最好使用一个包含数组的变量。将前面的代码修改为以下内容：

```js
        <ul> 

          <li v-for="n in countdown">{{n}}</li> 

          <li>launch missile!</li> 

        </ul>

```

1.  然后在 JavaScript 中放置数组倒计时：

```js
        new Vue({ 

          el:'#app', 

          data: { 

            countdown: [10,9,8,7,6,5,4,3,2,1] 

          } 

        })

```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00006.jpg)

# 使用索引表示的数组

当枚举一个数组时，我们还可以访问索引，由变量`i`在下面的代码中代表:

1.  HTML 如下:

```js
        <div id="app"> 

          <ul> 

            <li v-for="(animal, i) in animals">

              The {{animal}} goes {{sounds[i]}}

            </li> 

          </ul> 

        </div>

```

1.  在代码部分中，写:

```js
        new Vue({ 

          el: '#app', 

          data: { 

            animals: ['dog', 'cat', 'bird'], 

            sounds: ['woof', 'meow', 'tweet'] 

          } 

        })

```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00007.jpg)

# 对象

前面的例子可以进行重构，以匹配动物的名称和声音，这样索引的意外错位就不会影响我们的列表。

1.  HTML 如下:

```js
        <div id="app"> 

          <ul> 

            <li v-for="(sound, name) in animals"> 

              The {{name}} goes {{sound}} 

            </li> 

          </ul> 

        </div>

```

1.  我们需要在 JavaScript 中创建`animals`对象:

```js
        new Vue({ 

          el: '#app', 

          data: { 

            animals: { 

              dog: 'woof', cat: 'meow', bird: 'tweet' 

            } 

          } 

        })

```

# 工作原理...

列表的工作原理非常简单; 这里对语法进行了更多解释。

# 数字范围

变量`n`在`<li>`标签内是可见的。为了证明这一点，你可以快速构建一个倒计时列表，如下所示:

```js
<ul> 

  <li v-for="n in 10">{{11 - n}}</li> 

  <li>launch missile!</li> 

</ul>

```

我们写`11`而不是`10`，因为在 Vue 中枚举是从 1 开始计数的；这意味着`10`中的`n`将从`1`开始计数，而不是从`0`开始计数，而有些人可能会期望从`0`开始，并一直增加到`10`。如果我们希望倒计时从`10`开始，那么我们必须写`11`。最后一个数将是`10`，所以在导弹发射前，我们将会有`1`作为最后一个数字。

`v-for="n in 10"`的作用是调用**枚举**; 具体来说，我们正在枚举一个数字范围（从 1 到 10）。

# 数组

Vue 也允许我们枚举数组。一般的语法如下:

```js
v-for="(element, index) in array"

```

如上所示，如果我们只想要数组元素，索引和括号可以省略。

这种枚举形式是有序的。换句话说，数组中元素的有序序列将与屏幕上看到的相同；而当枚举对象时则不是这样。

# 对象

语法是`v-for =“（value，property）”`，如果你想的话也可以加上索引`v-for =“（value，property，index）”`。后者不推荐使用，因为如前所述，枚举属性的顺序是不固定的。实际上，在大多数浏览器中，顺序与插入顺序相同，但不保证一定如此。

# 创建一个动态和动画列表

在 Vue 中，大部分数据都是响应式的。实际上，这意味着如果我们的视图模型中有变化，我们将立即看到结果。这就是让您专注于应用本身，抛开所有绘图逻辑的原因。在本篇中，我们还将了解此系统的一些限制。

# 准备工作

要完成这个教程，你应该知道如何使用基本的数据绑定（在第一个教程中介绍）以及如何创建列表（第二个教程）。

# 操作步骤

在之前的教程中，我们为导弹发射倒计时构建了一个列表：

```js
<div id="app"> 

  <ul> 

    <li v-for="n in countdown">{{n}}</li> 

    <li>launch missile!</li> 

  </ul> 

</div>

```

```js
new Vue({

  el:'#app',

  data: {

    countdown: 

      [10,9,8,7,6,5,4,3,2,1]

  }

})

```

如果它能被动画化就好了！我们可以调整 JavaScript 代码，以使倒计时在秒数增加时添加数字：

1.  将上述代码复制到 JSFiddle 的 HTML 和 JavaScript 区域，除了我们将自己填充倒计时，所以将其设置为空数组。

要获取倒计时变量，我们必须通过 Vue 实例本身传递该变量。

1.  将 Vue 实例分配给一个变量以供以后参考：

```js
        var vm = new Vue({

          el:'#app',

          data: {

            countdown: []

          }

        })

```

这样我们就可以使用`vm`来访问 Vue 实例。

1.  从 10 开始初始化倒计时：

```js
        var counter = 10

```

1.  设置一个函数，该函数重复将剩余秒数添加到现在为空的`countdown`数组中：

```js
        setInterval(function () { 

          if (counter > 0) { 

            vm.countdown.push(counter--) 

          } 

        }, 1000)

```

# 它是如何工作的...

我们要做的是获取`countdown`数组的引用，并借助于`setInterval`将其填充为递减的数字。

我们通过在`vm.countdown.push(counter--)`行中设置的`vm`变量来访问`countdown`，因此每次向数组添加新数字时，我们的列表都将更新。

这段代码非常简单，只需注意我们必须使用`push`函数将元素添加到数组中。使用方括号表示法添加元素将无效：

```js
vm.countdown[counter] = counter-- // this won't work

```

数组将被更新，但是由于 JavaScript 的实现方式，这种赋值方式将跳过 Vue 的响应式系统。

# 还有更多内容

现在运行代码将一次添加一个倒计时数字；很好，但是最后一个元素`发射导弹`呢？我们希望它只在最后出现。

为了做到这一点，在 HTML 中我们可以直接进行一个小的技巧：

```js
<ul> 

  <li v-for="n in countdown">{{n}}</li> 

  <li>{{ countdown.length === 10 ? 'launch missile!' : '...' }}</li> 

</ul>

```

这个解决方案不是我们所能做到的最好的；在`v-show`的示例中了解更多内容。

我们刚刚了解到，如果我们希望在视图中更新，不能使用方括号表示法向响应式数组中添加元素。对于使用方括号修改元素和手动更改数组长度也是如此：

```js
vm.reactiveArray[index] = 'updated value' // won't affect the view 

vm.reactiveArray.length = 0 // nothing happens apparently

```

您可以使用 splice 方法克服这个限制：

```js
vm.reactiveArray.splice(index, 1, 'updated value') 

vm.reactiveArray.splice(0)

```

# 对于点击和按键等事件的响应

每个应用程序的一个基本部分是与用户的交互。Vue 提供了简化的方式来拦截大多数用户事件，并将它们与相关操作连接起来。

# 准备工作

要成功完成这个示例，您应该知道如何创建一个列表。如果不知道，请查看第二章的*使用计算属性过滤列表*这个示例，以及*Vue.js 基本特性*。

# 如何操作...

以下代码片段显示了如何对`click`事件作出反应：

1.  填写以下 HTML：

```js
        <div id="app"> 

          <button v-on:click="toast">Toast bread</button> 

        </div>

```

1.  至于 JavaScript，写下以下内容：

```js
        new Vue({el:'#app', methods:{toast(){alert('Tosted!')}}})

```

1.  执行代码！一个事件监听器将会安装在按钮上。

1.  点击按钮，您会看到一个弹出窗口，上面写着*Toasted！*

# 它是如何工作的...

运行上述代码将在按钮上安装一个事件处理程序。语法是`v-on:DOMevent="methodEventHandler"`。处理程序必须是一个方法，即在 methods 选项中的一个函数。在上面的示例中，`toast`就是处理程序。

# 双向数据绑定

在大多数情况下，v-on 属性可以满足您的需求，特别是当事件来自元素时。另一方面，对于某些任务来说，它可能有时过于冗长。

例如，如果我们有一个文本框，并且我们想要使用文本框的内容更新一个变量，并确保文本框始终具有变量的更新值（这称为**双向数据绑定**），我们必须编写几个处理程序。

然而，这个操作是由`v-model`属性完成的，如下面的代码所示：

```js
<div id="app"> 

  <button v-on:click="toast">Toast bread</button> 

  <input v-model="toastedBreads" /> 

  Quantity to put in the oven: {{toastedBreads}} 

</div>

new Vue({ 

  el: '#app', 

  methods: { 

    toast () { 

      this.toastedBreads++ 

    } 

  }, 

  data: { 

    toastedBreads: 0 

  } 

})

```

玩一下这个应用程序，并注意到保持文本框同步不需要处理程序。每次更新`toastedBreads`时，文本也会更新；反之，每次你写一个数字，数量也会更新。

# 还有更多

如果你遵循本章的第一个示例，你会记得我们向一个变量打招呼，变量可以包含数量不定的单词；我们可以使体验更加互动。让我们建立一个我们想要问候的行星列表：

```js
<div id="app"> 

  <ul> 

    <li v-for="world in worlds">{{world}}</li> 

  </ul> 

</div>

new Vue({ 

  el: '#app', 

  data: { 

    worlds: ['Terran', 'L24-D', 'Ares', 'New Kroy', 'Sebek', 'Vestra'] 

  } 

})

```

我们希望能够追踪新征服的星球并删除我们摧毁的星球。这意味着在列表中添加和删除元素。考虑以下 HTML：

```js
<ul> 

  <li v-for="(world, i) in worlds"> 

    {{world}} 

  <button @click="worlds.splice(i, 1)">Zap!</button> 

  </li> 

</ul> 

<input v-model="newWorld"/> 

<button @click="worlds.push(newWorld)">Conquer</button>

```

在这里，`@`符号是`v-on`的简写：让我们来看看修改的地方：

+   我们添加了一个按钮来删除行星（我们需要在`v-for`中写出索引）

+   我们放置了一个文本框，它绑定到数据变量`newWorld`

+   我们放置了一个相应的按钮，将文本框中的内容添加到列表中

运行这段代码将会起作用。但是如果你看一下控制台，你会看到在更新文本字段时会有一个警告。

```js
[Vue warn]: Property or method "newWorld" is not defined on the instance but referenced during render. Make sure to declare reactive data properties in the data option. (found in root instance)

```

这是因为我们没有在 Vue 实例中声明`newWorld`，但这很容易修复：

```js
new Vue({ 

  el: '#app', 

  data: { 

    worlds: ['Terran', 'L24-D', 'Ares', 'New Kroy', 'Sebek', 'Vestra'], 

    newWorld: '' 

  } 

})

```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00008.jpg)

# 选择开发环境

我们将探索一些不同的开发方式，从简单的 JSFiddle 方法到更健壮的 WebStorm 支持方法。由于我们想要使用库来为我们的软件添加新功能，所以我将为您提供一个添加库的指南，无论您选择的开发方法如何。

# 操作步骤如下：

我将从最简单的方法开始，然后为您呈现一些更复杂的用于大型项目的方法。

# 仅使用浏览器

有一系列的网站（如 JSFiddle、CodePen 和 JS Bin 等）可以让您直接在浏览器中编写 Vue 应用程序，这些网站非常适合测试新功能并尝试本书中的示例。另一方面，它们在代码组织方面的限制太多，无法开发更复杂的项目。在本章的第一个示例中，使用了这种开发方式，请参考该示例以了解如何仅使用浏览器进行开发。一般来说，您应该通过使用这种方式来学习，并将其转化为更结构化的项目，具体取决于您正在开发的内容。

# 仅使用浏览器添加依赖项

每当我提到一个外部库时，您可以在互联网上搜索相关的`.js`文件，最好通过 CDN（内容分发网络）来分发，并将其添加到 JSFiddle 的左侧菜单中。让我们尝试一下 moment.js。

1.  在浏览器中打开一个新的 JSFiddle（将浏览器指向[`jsfiddle.net/`](https://jsfiddle.net/)）。

1.  在另一个标签页中，在你喜欢的搜索引擎中搜索`momentjs CDN`。

1.  第一个结果应该会带你到一个 CDN 网站，上面有一列链接；你应该最终能找到一些像`https://somecdn.com/moment.js/X.X.X/moment.js`的链接，其中*X*代表版本号。

1.  复制你找到的链接，然后回到 JSFiddle。

1.  在左侧边栏的“External Resources”部分，粘贴你的链接，然后按下“Enter”键。

对于许多库来说这样就足够了；有些库不支持这种方式，你就需要用其他方式将它们包含在 JSFiddle 中。

# 文本编辑器

最简单的方式是使用文本编辑器和浏览器。对于简单的、自包含的组件来说这完全合法。

现在有很多文本编辑器可供选择。我喜欢使用的是 Microsoft Visual Studio Code（[`github.com/Microsoft/vscode`](https://github.com/Microsoft/vscode)）。如果你使用其他编辑器也没什么大不了的，只是恰巧 Code 有一个针对 Vue 的插件：

1.  创建一个名为`myapp.html`的新文件，在其中编写如下内容：

```js
        <!DOCTYPE html> 

        <html> 

          <head> 

            <title>Vue.js app</title> 

          </head> 

          <body> 

            <div id="app"> 

              {{'hello world'}} 

            </div> 

            <script 

              src="https://cdnjs.cloudflare.com/ajax

               /libs/vue/2.0.0/vue.js">

            </script> 

            <script> 

              new Vue({el:'#app'}) 

            </script> 

          </body> 

        </html>

```

1.  在浏览器中打开刚刚创建的文件。

Vue 会从[`cdnjs.com/`](https://cdnjs.com/)下载，然后文本`hello world`应该会显示出来（如果看到了花括号，则可能出现了问题，请检查控制台是否有错误）。

这种方法类似于 JSFiddle 的方法：在顶部有一个 HTML 部分、一个 JavaScript 部分和一个 CSS 部分。我们只是将所有内容都控制在自己手中。此外，这种方式我们还可以使用 Vue 开发者工具（查看配方“使用 Vue 开发者工具扫描你的应用程序”了解介绍）。

# 用文本编辑器添加依赖项

在此配置中添加外部库只需将另一个`<script>`标签添加到你的文件中，然后将源属性设置为相应的链接。如果我们想添加`moment.js`，我们按照之前解释的方式查找该库，然后将以下代码片段添加到我们的页面中：

```js
<script src="https://somecdn.com/moment.js/X.X.X/moment.js "></script>

```

请注意，你需要将找到的链接粘贴到前面代码片段中虚假链接的位置。

# Node 包管理器（npm）

与 Vue 项目一起工作的规范方式，也是 Vue 社区官方支持的方式，涉及使用 npm，尤其是一个名为`vue-cli`的 npm 包。

如果您对 npm 不太熟悉，将其列入您计划广泛使用 JavaScript 进行开发的事项清单中是一个好主意。

简而言之，npm 是一个用于组织和共享代码的工具，超越了在项目中使用其他人的代码。更正式地说，它是一个用于 JavaScript 的软件包管理器。我们将在本书中使用一些基本命令，以及一些更高级的命令，但是我鼓励您自己学习更多：

1.  安装 npm。由于它与 Node.js 捆绑在一起，因此最好直接安装 Node.js。您可以在[`nodejs.org/en/download/`](https://github.com/Microsoft/vscode)上找到安装说明。

1.  安装完 npm 后，打开命令行并输入`npm install -g vue-cli`，这将安装`vue-cli`。选项`-g`表示全局安装，这意味着无论您身在何处，都可以输入`vue`来运行该程序。

1.  创建一个作为工作区的新目录。我们将把所有项目放在这个目录中。

1.  输入`vue list`，我们可以从官方 Vue 模板仓库中获取所有可用的模板。其他来源的模板也可以使用。

`simple`模板将创建一个类似于前面几段所做内容的页面。我邀请您运行`vue init simple`并检查一下；请注意它与我们所做的内容之间的差异。我们现在要做的是更进一步。我们将使用更复杂的模板，该模板包括一个打包工具。有一个用于`webpack`和`browserify`的模板；我们选择使用第一个。

如果您对`webpack`或`browserify`不太熟悉，它们是用于控制从源代码和资源（图像、CSS 文件等）到定制捆绑包的 JavaScript 程序的构建过程的程序。例如，对于单个`.js`文件：

1.  输入`vue init webpack-simple`，程序将询问您有关项目的一些问题。如果您不知道如何回答，请按下*Enter*键使用默认选项。

我们也可以选择等效地选择`browserify-simple`模板；这两个库可以达到相同的结果。

1.  完成脚手架后，输入`npm install`。这将负责下载和安装我们编写 Vue 应用所需的所有 npm 软件包。

完成后，您将已经拥有一个具备功能的演示应用程序。

1.  输入`npm run dev`来运行你的应用程序。进一步的指导会在屏幕上出现，并告诉你访问一个特定的网址，但你的浏览器很有可能会自动打开。

1.  将浏览器定位到指定的地址。你应该能够立即看到演示应用程序。

通过`vue-cli`创建的源文件中，你会发现两个值得注意的文件。第一个文件是你的应用程序的入口点，`src/main.js`。它将包含类似以下的内容：

```js
import Vue from 'vue' 

import App from './App.vue'

new Vue({ 

 el: '#app', 

 render: h => h(App) 

})

```

这段代码加载在你刚刚看到的`index.html`页面中。它只是告诉主 Vue 实例在被`#app`选择的元素中（在我们的情况下是一个带有`id="app"`属性的`<div>`元素）加载和渲染`App`组件。

你将在`App.vue`文件中找到一种自包含的方式来编写 Vue 组件。关于组件的更多内容将在其他教程中介绍，但现在请将其视为一种更进一步划分你的应用程序以保持其有序的方法。

以下代码与官方模板中的代码不同，但概括了一般的结构：

```js
<template> 

  <div id="app"> 

    <img src="./assets/logo.png"> 

    <h1>\{{ msg }}</h1> 

  </div> 

</template>

<script> 

export default { 

  data () { 

    return { 

      msg: 'Hello Vue 2.0!' 

    } 

  } 

} 

</script> 

<style> 

body { 

  font-family: Helvetica, sans-serif; 

} 

</style>

```

你可以看到将代码划分为 HTML、JavaScript 和 CSS 是一种重复出现的模式。在这个文件中，我们可以看到与我们在第一个例子中在 JSFiddle 中看到的类似的东西。

在`<template>`标签中，我们放置我们的 HTML，在`<script>`标签中放置 JavaScript 代码，并使用`<style>`标签为我们的应用程序添加一些样式。

运行`npm run dev`后，你可以尝试在这个文件中编辑`msg`变量；在保存修改后，网页会自动重新加载组件。

# 使用 npm 添加依赖项

要在此配置中添加外部库，只需键入`npm install`后跟库的名称。然后在你的代码中，使用以下类似的方式使用它：

```js
import MyLibrary from 'mylibrary'

```

我们可以使用以下命令导入`moment.js`：

```js
npm install moment

```

然后在我们的 JavaScript 中添加以下行：

```js
import moment from 'moment'

```

# IDE

如果你有一个非常庞大的项目，很有可能你已经在使用 IntelliJ 或 Webstorm 等工具。在这种情况下，我建议你在大部分工作中坚持使用嵌入的控制台，并只使用诸如语法高亮和代码补全等功能。这是因为 Vue 的开发工具还不成熟，你很可能会花更多的时间来配置工具，而不是实际编程：

1.  打开 Webstorm 并创建一个新的空项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00009.jpg)

1.  在左下角，你应该能够打开控制台或终端：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00010.jpg)

1.  从这个提示中，你应该能够按照前面的段落中所解释的那样使用 npm。如果你还没有看过，请阅读一下。在我们的例子中，我们假设已经安装了 Node 和 vue-cli。

1.  输入`vue init simple`并回答问题；你应该得到类似于以下内容的东西：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00011.jpg)

1.  双击打开`index.html`文件。

1.  将鼠标悬停在`index.html`文件的右上角，你应该能够看到浏览器图标；点击其中一个：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00012.jpg)

1.  你的示例应用程序已经启动运行了！

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00013.jpg)

# 总结

你可以在专门的案例中了解更多关于这个的工作原理。在这里，我希望你对使用 Vue 进行开发的可能性有一个概述。对于快速原型，你可以使用 JSFiddle。当你需要自己的环境或者只需要使用 Vue 开发工具的时候，使用文本编辑器就足够了。然而，对于大多数严肃的项目，你应该熟悉 npm、webpack 或者 Browserify，并使用 vue-cli 来创建你的新项目。

# 使用过滤器格式化你的文本

Vue 的第一个版本附带了一些文本过滤器，用于帮助格式化文本和解决一些常见问题。

在这个新版本中，没有内置的过滤器（除了下一个案例中介绍的 JSON 等效过滤器）。我认为这是因为编写自己的过滤器非常容易，而且在专门情况下可以很容易地找到在线库来完成更好的工作。最后，过滤器的用途有些变化：它们现在更多用于后处理，而不是实际的过滤和排序数组。

为了演示创建过滤器有多容易，我们将重新创建 Vue 旧版本中的一个过滤器：capitalize。

# 准备工作

你不需要任何特殊的知识来完成这个案例。

# 操作步骤

有时候我们有一些字符串漂浮在我们的变量中，比如标签。当我们把它们放在句子中间时，它们工作得很好，但是在句子或者项目符号的开头，它们看起来就不太好了。

我们想要编写一个过滤器，可以将我们放入其中的任何字符串都变成大写。如果，例如，我们希望字符串`hello world`以大写字母`H`开头，我们希望能够这样写：

```js
{{'hello world' | capitalize }}

```

如果我们尝试在 Vue 应用程序中将其作为 HTML 运行，它会报错`[Vue warn]: Failed to resolve filter: capitalize`。

让我们创建这个过滤器并将它添加到 Vue 的内部过滤器列表中：

1.  写下以下 JavaScript 代码以注册一个过滤器并实例化 Vue：

```js
        Vue.filter('capitalize', function (string) { 

          var capitalFirst = string.charAt(0).toUpperCase() 

          var noCaseTail = string.slice(1, string.length) 

            return capitalFirst + noCaseTail 

        }) 

        new Vue({el:'#app'})

```

1.  在 HTML 部分中，写下以下内容：

```js
        {{'hello world' | capitalize }}

```

1.  运行代码并注意到文本现在显示为“Hello world”。

# 工作原理如下...

竖线表示以下内容是一个过滤器的名称；在我们的例子中，`capitalize`不在 Vue 的过滤器列表中，因此会有警告。Vue 将按原样打印字符串。

在 Vue 开始之前，它会在资产库中注册我们的过滤器（使用`Vue.filter`）。Vue 有一个内部过滤器对象，并将创建一个新条目：`capitalize`。每次遇到竖线符号时，Vue 都会查找相应的过滤器。记得在 Vue 实例的实际创建之前写好它，否则 Vue 将找不到它。

过滤器的工作原理非常基本的 JavaScript，事实上，使用 ES6 来编写这个过滤器会更好：

```js
Vue.filter('capitalize', function (string) { 

  var [first, ...tail] = string 

  return first.toUpperCase() + tail.join('') 

})

```

如果您不熟悉 ES6，这里有一个简要的解释。第二行被称为**解构**赋值字符串；我们将字符串解释为一个字符数组，将第一个字符分割为第一个字符，并将所有其他字符放入`tail`中。这是将数组的不同部分分配给多个变量的更快的方法。可能看起来神秘的另一点是`join('')`。由于`tail`现在是一个字符数组，我们需要一些方法将单个字母重新连接成一个紧凑的字符串。`join`的参数表示单个字符之间的分隔符。我们不想要任何分隔符，所以传递一个空字符串。

在下一章中，您将找到更多关于过滤器的用例，并涵盖其他实际用途。

# 使用`mustaches`（例如`JSON`过滤器）调试应用程序

在前面的用例中，我们全面了解了过滤器，并说 Vue 除了`JSON`过滤器的等效功能之外没有内置过滤器。这个过滤器非常有用，虽然使用它来调试并不是真正正统的做法，但有时它确实能让生活更轻松。现在我们可以直接使用它而不需要自己编写。

# 操作步骤如下...

为了看到实际效果，我们可以在 Vue 实例中简单显示一个对象的值。

1.  编写以下 JavaScript：

```js
        new Vue({ 

          el: '#app', 

          data: { 

            cat: { 

              sound: 'meow' 

            } 

          } 

        })

```

这只是在我们的代码中创建了一个包含字符串的 `cat` 对象。

1.  编写以下 HTML：

```js
        <p>Cat object: {{ cat }}</p>

```

1.  运行您的应用程序并注意到 `cat` 对象以所有其美丽的形式输出，就像 `JSON.stringify` 一样。

# 工作原理如下...

`Cat` 将显示 `cat` 对象的内容。在旧的 Vue 中，要获得这个结果，我们必须写成 `{{ cat | json }}`。

需要小心的一件事是我们对象中的循环。如果我们的对象包含循环引用，并且用花括号括起来，这将不起作用。这些对象比你想象的更常见。例如，HTML 元素是包含对父节点的引用的 JavaScript 对象；父节点反过来包含对其子节点的引用。任何这样的树结构都会导致花括号打印对象的无限描述。当你实际这样做时，Vue 只是抛出一个错误并拒绝工作。你在控制台中看到的错误实际上是由用于打印 `JSON.stringify`对象的内部方法抛出的。

使用花括号的一个实际情况是当同一个值在多个位置被改变时，或者当你想快速检查变量的内容时。花括号甚至可以用于演示目的，正如你在本书中将看到的用法那样。

# 用 Vue 开发者工具对应用进行透视

使用花括号是显示对象内容的一种快捷方式。然而，它也有一些限制；其中一个在前面的示例中详细说明了，就是它默认情况下无法处理包含循环引用的对象。一个不会出现这个限制并且具有更多调试功能的工具是 Vue 开发者工具。有一个 Chrome 扩展程序，可以在开发的每一步中帮助您，可视化组件的状态，它们在页面中的位置以及更多。它还与 **Vuex**（在后面的示例中介绍）深度集成，并具有一个时间机器功能，可以直接从浏览器中倒回事件流。

# 准备工作

要安装它，只需在 Chrome Web Store 的扩展类别中下载扩展。只需搜索 Vue.js devtools 即可找到它，点击**添加到 Chrome**按钮，然后您就可以开始使用了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00014.jpg)

不幸的是，您将无法在某些配置中使用它；特别是它目前似乎无法在 `iframe` 环境和 JSFiddle 中工作，所以为了看到它，您至少要使用在*选择开发环境*示例中概述的*one page approach*。

。

# 怎么做...

1.  访问 Chrome 开发者工具（通常使用 *c* *md* + *opt* + *I* 或 *Ctrl* + *Shift* + *I* ），你会看到一个新的标签页说 Vue。点击它将呈现出开发者工具。

为了使其能够在通过`file://`协议打开的页面上运行，您需要在 Chrome 的扩展管理面板中检查允许访问文件 URL 以便为该扩展程序添加权限。![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00015.jpg)

您将看到一个按层次结构排列在页面上的组件树，通过选择它们，您将能够实时深入地查看所有的变量。

1.  单击树中的各个对象以查看详细信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00016.jpg)

此外，您还将看到一个有用的按钮：检查 DOM 按钮（眼睛）将滚动页面到元素的位置，并在 Chrome 开发人员工具中显示 DOM 表示。此外，当您单击一个组件（详见插图中的根组件）时，您将在控制台中可以使用一个名为`$vm0`的变量。例如，您可以执行方法或检查变量。

1.  单击根组件，并在控制台中输入以下内容以探索`$vm0.docsUrl`属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00017.jpg)

# 升级到 Vue.js 2

如果您需要将 Vue 应用程序升级到 2 版本，大部分代码都可以正常使用。但是，有几个功能需要进行一些修改。有些是简单的重命名，有些则比较复杂。

# 操作步骤如下：

为了让您的迁移开始，Chris Fitz（Vue 核心团队成员）创建了一个小助手应用程序，它将扫描您的代码并指导您进行迁移：

1.  使用以下 npm 命令安装 Vue Migration Helper:

```js
 npm install -g git://github.com/vuejs/vue-migration-helper.git

```

1.  导航到您的应用程序文件夹。

1.  使用以下命令运行程序：

```js
 vue-migration-helper

```

需要进行更改的所有行将被突出显示。更新完成后，或者如果您仍然有疑问，您应该查看官方文档迁移页面[`rc.vuejs.org/guide/migration.html`](https://rc.vuejs.org/guide/migration.html)。

# 它的工作原理是...

阅读文档将帮助您了解需要更新的关键点。在这里，我将为您提供一些最具挑战性修改的基本原理。

# $broadcast、$dispatch 和 events 选项的弃用

方法`$broadcast`和`$dispatch`现在已与旧版本相同的语法合并到`$emit`方法中。不幸地是，将每个`$broadcast`和`$dispatch`实例都替换为`$emit`并不保证总是有效，因为现在用于管理事件的模式有些不同。

在 Vue 1 中，事件沿着层次结构树向下（对于`$broadcast`）或向上（对于`$dispatch`）以及水平（对于`$emit`）的路径传播。

说实话，我从来都不喜欢有两种（如果算上旧的 `$emit` ，则是三种）方法来触发事件。即使在最小的上下文中，它也很令人困惑，因为你必须问自己“这个事件是给父级还是子级的？”大部分情况下，这个区分并不重要，你只是想要调用你的方法。但是，不会有免费的午餐；为了使一切在新的范式下运行，我们必须添加一个移动部件到系统中。

现在，所有事件都应该通过一个或多个中央枢纽传递。这个中央枢纽的角色可以由一个 Vue 实例来承担，因为它们实现了必要的接口。

当触发一个`v-on`消费的事件时，你只需要用`$emit`替换`$broadcast`，因为事件不需要传递很远。另一方面，如果你在事件方面定义一个组件的接口，你将不得不告别事件选项，因为它将不再起作用。这是通过所有事件通过一个中央枢纽传递的直接结果 - 事件选项将不知道在哪里注册所有事件。这是只有一个发射方法的代价：它向所有方向触发，但只在一个精确的管道中触发。

假设你有一个专门的空的 Vue 实例作为事件中心：

```js
var eventBus = new Vue()

```

如果你正在编写一个茶壶组件，并且你想要注册 brew 事件，你可以在 created 钩子中写入以下内容：

```js
new Vue({ 

  el: '#app', 

  components: { 

   comp1: { 

         template: '<div/>', 

         created () { 

         eventBus.$on('brew', () => { 

         console.log('HTTP Error 418: I'm a teapot') 

        }) 

      } 

    }, 

    comp2: { 

         template: '<div/>', 

         created () { 

         eventBus.$emit('brew') 

      } 

    } 

  } 

})

```

HTML 如下：

```js
<div id="app"> 

  <comp1></comp1> 

  <comp2></comp2> 

</div>

```

每当使用`eventBus.$emit('brew')`触发`brew`事件时，控制台将输出一条消息。

正如你所看到的，这个示例不太可扩展。你不能在 created 钩子中注册很多事件，然后期望轻松跟踪它们的功能以及它们在哪个中央枢纽中注册。对于这些更复杂的场景，建议的做法是使用后面介绍的 Vuex。

你编写的任何组件都可以充当事件中心。你还可以使用 API 方法`$off`来删除监听器，以及`$once`来监听事件，但只监听一次。

# 数组过滤器的弃用

如果你有很多经过过滤的`v-for`列表，我有个坏消息告诉你。即使在实际情况中，最常见的过滤器用法是与`v-for`一起使用，社区还是选择移除了这个特性。原因主要是因为有很多过滤器，经常连在一起使用，很难理解和维护。

推荐的过滤列表的新方法是使用计算属性。幸运的是，我们有一整个关于如何做到这一点的示例。在下一章节中查看示例*使用计算属性过滤列表*。

# Vue.config.delimiters 的弃用

自定义定界符不作用于组件级别。如果需要，可以创建两个使用不同定界符的不同组件。

这个升级非常简单，并且允许你编写组件，以便在其他模板引擎中使用：

```js
<div id="app"> 

  {!msg!} 

</div>

new Vue({ 

 el: '#app', 

 data: { 

   msg:'hello world' 

 }, 

 delimiters: ['{!','!}'] 

})

```

# 生命周期钩子的重命名

生命周期现在有更一致的命名，能够帮助长期记住它们的名称：

| **旧的钩子** | **新的钩子** |
| --- | --- |
| `init` | `beforeCreate` |
| `created` | `created` |
| `beforeCompile` | `created` |
| `没有等价项` | `beforeMount` |
| `compiled` | `mounted` |
| `ready` | `mounted` |
| `attached` | `没有等价项` |
| `detached` | `没有等价项` |
| `没有等价项` | `beforeUpdate` |
| `没有等价项` | `updated` |


# 第二章：Vue.js 的基本功能

本章将介绍以下内容：

+   学习如何使用计算属性

+   使用计算属性对列表进行筛选

+   使用计算属性对列表进行排序

+   使用过滤器格式化货币

+   使用过滤器格式化日期

+   根据条件显示和隐藏元素

+   根据条件添加样式

+   通过 CSS 过渡为您的应用程序增添一些乐趣

+   输出原始 HTML

+   创建带有复选框的表单

+   创建带有单选按钮的表单

+   创建带有选择元素的表单

# 介绍

在本章中，您将找到开发完全功能、交互式、独立的 Vue 应用程序所需的所有构建块。在第一个示例中，您将创建计算属性，这些属性封装了用于创建更语义化应用程序的逻辑；然后，您将使用过滤器和`v-html`指令进一步探索一些文本格式化。您将使用条件渲染和过渡创建一个图形吸引人的应用程序。最后，我们将构建一些表单元素，例如复选框和单选按钮。

从现在开始，所有示例都将专门使用 ES6 编写。在撰写本文时，如果您使用 Chrome 9x 和 JSFiddle 进行跟随，它们应该能够无缝运行；如果您将此代码集成到一个更大的项目中，请记得使用 Babel（有关更多信息，请参见第八章中的*使用 Babel 编译 ES6*示例，*组织+自动化+部署=Webpack*）。

# 学习如何使用计算属性

计算属性是 Vue 组件中依赖于其他更原始数据的某些计算的数据。当这些原始数据是响应式的时，计算属性会自动更新并响应式地更新。在这个上下文中，原始数据是一个相对的概念。您当然可以基于其他计算属性构建计算属性。

# 准备工作

在开始准备这个示例之前，请确保熟悉`v-model`指令和`@event`表示法。如果您不确定，可以在前一章中完成*对点击和按键等事件做出反应*示例。

# 操作步骤

一个简单的例子将清晰地说明计算属性是什么：

```js
<div id="app"> 

  <input type="text" v-model="name"/> 

  <input type="text" id="surname" value='Snow'/> 

  <button @click="saveSurname">Save Surname</button> 

  <output>{{computedFullName}}</output> 

</div> 

let surname = 'Snow' 

new Vue({ 

  el: '#app', 

  data: { 

    name: 'John' 

  }, 

  computed: { 

    computedFullName () { 

      return this.name + ' ' + surname 

    } 

  }, 

  methods: { 

    saveSurname () { 

      surname = this.$el.querySelector('#surname').value 

    } 

  } 

})

```

运行此示例将显示两个输入字段：一个用于名字，一个用于姓氏，以及一个专门保存姓氏的按钮。检查 JavaScript 代码将发现，虽然名字是在对象的数据部分声明的，但姓氏是在 Vue 实例之外的开头声明的。这意味着它不会被 Vue 识别为反应性变量。我们可以通过编辑来检查，名字会影响计算值，而编辑姓氏则不会，即使姓氏变量本身实际上发生了变化，我们可以在浏览器控制台中检查到：

1.  在 JSFiddle 上运行应用程序；你会在输入字段中看到`John`和`Snow`，并且由于`computedFullName`的结果，你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00018.jpg)

1.  将`John`替换为`Johnny`，你会看到计算属性实时变化。这是因为变量名是响应式的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00019.jpg)

1.  将`Snow`替换为`Rain`，然后点击“保存姓氏”。不会发生任何事情，因为`surname`不是响应式的。它不会触发视图的更新。让我们来检查它是否确实被保存了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00020.jpg)

1.  用`John`替换`Johnny`。计算属性中的姓氏立即变为“Rain”。这是因为更改名字触发了计算属性的更新：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00021.jpg)

我们刚刚实验证实了，尽管变量的更改被保存到内存中，但当编辑非响应式变量时，并不会触发视图刷新。

值得注意的是，对于反应性来说，在这里也存在相同的限制--如果变量是数组，在使用方括号表示法更改元素不起作用，不使用`$remove`删除元素也不起作用。有关计算属性的其他限制，您应该看一下官方文档[`vuejs.org/v2/guide/computed.html`](https://vuejs.org/v2/guide/computed.html)。

# 还有更多...

在下文中，通过“依赖项”一词，我指的是在计算属性内部使用的反应性变量。当依赖项发生变化时，计算属性会被计算出来。

计算属性不适用于记忆数据，但如果直接设置值而不是通过其依赖项间接操作值更合理的话，可以定义一个 setter。而且，如果计算属性返回一个对象，每次都会是一个新对象，而不是之前版本的修改版。最后，只有所有依赖项都发生了变化，计算属性才会被调用。

这个缓存机制和 setter 的定义将在以下几节中进行分析。

# 缓存计算属性

虽然在 methods 选项中的函数在每次调用时都会执行，但在 computed 中的函数将根据依赖项进行缓存，而这些依赖项又是由函数中发现的所有响应式内容定义的。

在接下来的示例中，我们将探讨组合计算属性，但您可以很容易地想象出在计算属性上进行非常繁重的计算的情况：

```js
computed: { 

  trillionthDigitOfPi () { 

    // hours of computations and terabytes later... 

    return 2 

  } 

}

```

然后，您可以反复使用相同的属性，而无需重新计算：

```js
unnecessarilyComplexDoubler (input) { 

  return input * this.trillionthDigitOfPi 

}

```

每次调用此函数时，我们只需获取`trillionthDigitOfPi`的缓存值；不需要再次进行计算。

# 计算属性的 setter

有时，我们有一个计算属性，它真正表示我们模型中的一个明确对象，并且直接编辑它比修改其依赖关系更加清晰。

在表格工厂的背景下，我们希望指定要构建的表格数量或腿的数量：

```js
<div id="app"> 

  <label>Legs: <input v-model="legCount" type="range"></label><br> 

  <label>Tops: <input @input="update" :value="tableCount"></label><br> 

  <output> 

    We are going to build {{legCount}} legs 

    and assembly {{tableCount}} tables. 

  </output> 

</div>

```

我们的状态仅由`legCount`确定，并且表格的数量将自动确定。创建一个新的 Vue 实例：

```js
new Vue({ 

  el: '#app', 

  data: { 

    legCount: 0 

  }   

}

```

要知道表格的数量，我们有一个`tableCount`计算属性：

```js
computed: { 

  tableCount: { 

    get () { 

      return this.legCount / 4 

    }, 

    set (newValue) { 

      this.legCount = newValue * 4 

    } 

  } 

}

```

`get`部分通常是任何时候属性的值，setter 允许我们直接设置表格的数量（以及腿的数量）。然后，我们可以编写`update`方法，该方法在更改表格数量时触发：

```js
update (e) { 

  this.tableCount = e.target.value 

}

```

# 使用计算属性过滤列表

在早期版本的 Vue 中，过滤器在`v-for`指令中用于提取一些值。它们仍然被称为过滤器，但不再以这种方式使用。它们被降级为用于文本的后处理。老实说，我从来都不真正理解如何在 Vue 1 中使用过滤器来过滤列表，但在版本 2 中使用计算属性是过滤列表的唯一正确方式。

借助这个示例，您可以从最简单的待办事项列表到最复杂的太空船物料清单中对列表进行筛选。

# 准备工作

您应该对 Vue 列表有一定的了解，并了解计算属性的基础知识；如果不了解，阅读*编写列表*和*学习如何使用计算属性*这两篇文章将帮助您了解基础知识。

# 操作步骤：

要开始使用这个食谱，我们需要一个示例列表来筛选我们最喜欢的元素。假设我们在*ACME 研究与开发实验室*工作，我们负责在任何领域复制一些实验。我们可以从以下列表中选择一个实验：

```js
data: { 

  experiments: [ 

    {name: 'RHIC Ion Collider', cost: 650, field: 'Physics'}, 

    {name: 'Neptune Undersea Observatory', cost: 100, field: 'Biology'}, 

    {name: 'Violinist in the Metro', cost: 3, field: 'Psychology'}, 

    {name: 'Large Hadron Collider', cost: 7700, field: 'Physics'}, 

    {name: 'DIY Particle Detector', cost: 0, field: 'Physics'} 

  ] 

}

```

让我们使用一个简单的`<ul>`元素立即打印出列表：

```js
<div id="app"> 

  <h3>List of expensive experiments</h3> 

  <ul> 

    <li v-for="exp in experiments"> 

      {{exp.name}} ({{exp.cost}}m 

) 

    </li> 

  </ul> 

</div>

```

如果你不是物理学的铁粉，你可能想从这个列表中筛选掉物理实验。为此，我们创建一个新的变量，它将只保存`nonPhysics`实验。这个变量将作为一个计算属性：

```js
computed: { 

  nonPhysics () { 

    return this.experiments.filter(exp => exp.field !== 'Physics') 

  } 

}

```

当然，我们现在希望列表从这里绘制一个元素：

```js
<li v-for="exp in nonPhysics"> 

  {{exp.name}} ({{exp.cost}}m 

) 

</li>

```

如果我们现在启动程序，只有非物理实验会出现在列表中：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00023.jpg)

# 它的工作原理是...

`nonPhysics`计算属性将包含带有指定处理方式的数组副本。它将简单地检查字段不是`Physics`的实验，并将新数组传递给`v-for`进行渲染。

正如你所看到的，过滤是完全任意的。我们可以选择从一个变量中获取一个单词，而不是`Physics`，该变量再从一个文本框中获取：

```js
<input v-model="term"> // HTML 

// inside the Vue instance 

data: { 

  term: '' 

}, 

computed: { 

  allExceptTerm () { 

    return this.experiments 

      .filter(exp => exp.field.indexOf(this.term) === -1) 

  } 

}

```

# 更多内容...

事实证明，我们想重现这样的实验，但我们的预算有限；超过 300 万欧元的任何东西都在我们的限制之外。让我们创建一个过滤器：

```js
lowCost () { 

  return this.experiments.filter(exp => exp.cost <= 3) 

}

```

如果我们使用这个过滤器替换之前的过滤器，我们仍然可以看到*自己动手做粒子探测器*的物理实验。由于我们不喜欢物理学，我们希望结合这两个过滤器。

在旧版的 Vue 中，你可以在`v-for`中同时使用两个过滤器；在这里，我们将刚刚创建的计算属性移动到方法部分，并将它们转换成纯函数：

```js
methods: { 

  nonPhysics (list) { 

    return list.filter(exp => exp.field !== 'Physics') 

  }, 

  lowCost (list) { 

    return list.filter(exp => exp.cost <= 3) 

  } 

}

```

这样，过滤器就是可组合的；我们可以在`v-for`中这样使用它们：

```js
<li v-for="exp in nonPhysics(lowCost(experiments))"> 

  {{exp.name}} ({{exp.cost}}m 

) 

</li>

```

减少 HTML 中的逻辑的另一种方法是将所有内容封装在一个专用的计算属性中：

```js
filteredExperiments () { 

  return this.lowCost(this.nonPhysics(this.experiments)) 

}

```

HTML 变为如下所示：

```js
<li v-for="exp in filteredExperiments"> 

  {{exp.name}} ({{exp.cost}}m 

) 

</li>

```

最后，在经过所有这些过滤后，列表中唯一剩下的元素是*地铁里的小提琴手*，而且公平地说，300 万欧元是小提琴的成本，而不是整个实验的成本。

# 使用计算属性对列表进行排序

在 Vue 1 中，使用过滤器对`v-for`进行排序是被考虑移除的另一件事情，在当前版本中没有幸存下来。

使用计算属性对列表进行排序提供了更大的灵活性，我们可以实现任何自定义的排序逻辑。在这个示例中，您将创建一个包含一些数字的列表；我们将使用它们对列表进行排序。

# 准备工作

要完成这个示例，您只需要对列表和计算属性有一些熟悉；您可以通过《编写列表》和《学习如何使用计算属性》这两个示例来了解它们。

# 操作步骤

让我们编写一个世界上最大的水坝列表。

首先，我们需要一个包含三列（名称，国家，电力）的 HTML 表格：

```js
<div id="app"> 

<table> 

  <thead> 

    <tr> 

      <th>Name</th> 

      <th>Country</th> 

      <th>Electricity</th> 

    </tr> 

  </thead> 

  <tbody> 

  </tbody> 

</table> 

</div>

```

此外，我们还需要 Vue 实例的 JavaScript 代码，目前只包含了一组小型水坝的数据库、它们的位置以及它们产生的电力：

```js
new Vue({ 

  el: '#app', 

  data: { 

    dams: [ 

      {name: 'Nurek Dam', country: 'Tajikistan', electricity: 3200}, 

      {name: 'Three Gorges Dam', country: 'China', electricity: 22500}, 

      {name: 'Tarbela Dam', country: 'Pakistan', electricity: 3500}, 

      {name: 'Guri Dam', country: 'Venezuela', electricity: 10200} 

    ] 

  } 

})

```

在`<tbody>`标签内，我们放置了一个`v-for`，它将简单地迭代我们刚刚创建的水坝列表：

```js
<tr v-for="dam in dams"> 

  <td>{{dam.name}}</td> 

  <td>{{dam.country}}</td> 

  <td>{{dam.electricity}} MegaWatts</td> 

</tr>

```

这将渲染为以下表格：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00024.jpg)

我们希望按照已安装的电力对这些水坝进行排序。为此，我们将创建一个计算属性`damsByElectricity`，它将返回一个有序的水坝集合：

```js
computed: { 

  damsByElectricity () { 

    return this.dams.sort((d1, d2) => d2.electricity - d1.electricity); 

  } 

}

```

在添加计算属性后，我们只需要在 HTML 中写入`damsByElectricity`而不是 dams。其他都保持不变，行为也相同：

```js
<tr v-for="dam in damsByElectricity"> 

  <td>{{dam.name}}</td> 

  <td>{{dam.country}}</td> 

  <td>{{dam.electricity}} MegaWatts</td> 

</tr>

```

# 它的工作原理是...

我们刚刚创建的计算属性`damsByElectricity`将返回一个数组，它将是`this.dams`的一个排序克隆。与计算属性一样，结果将被缓存（或记住）；每次我们需要结果时，如果原始列表没有变化，函数将不会被调用，缓存的结果将被返回。

`sort`函数接受两个参数：列表的两个成员。如果第二个成员在第一个成员之后，则返回值必须是正数；如果相反，则返回值必须是负数。

通过`d2.electricity - d1.electricity`获得的顺序是降序的；如果我们想要升序的顺序，我们需要交换两个操作数或将它们乘以*-1*。

# 更多内容...

我们可以通过将点击事件绑定到表头中的字段来扩展我们的列表，以便反转排序，这样当我们点击`Electricity`时，将以反方向对水坝进行排序。

我们将使用条件样式；如果您对它不熟悉，在完成《有条件地添加样式》这个示例后，您将会了解它。

为了清楚地表明我们的排序方式，我们应引入两个 CSS 类：

```js
.ascending:after { 

  content: "25B2" 

} 

.descending:after { 

  content: "25BC" 

}

```

在这里，内容是指向上的箭头的 Unicode 表示，表示升序，而指向下的箭头表示降序。

首先，我们应该使用变量 order 跟踪顺序，当升序时 order 为 1，当降序时 order 为-1：

```js
data: { 

  dams: [ 

    // list of dams 

  ], 

  order: 1 // means ascending 

},

```

条件样式是一个简单的三元运算符。有关条件样式的更多信息，请参阅《条件样式》中的章节：

```js
<th>Name</th> 

<th>Country</th> 

<th v-bind:class="order === 1 ? 'descending' : 'ascending'" 

    @click="sort">Electricity</th>

```

这里，sort 方法的定义如下：

```js
methods: { 

  sort () { 

    this.order = this.order * -1 

  } 

}

```

我们需要做的最后一件事是编辑 damsByElectricity 计算属性以考虑顺序：

```js
damsByElectricity () { 

  return this.dams.sort((d1, d2) => 

    (d2.electricity - d1.electricity) * this.order); 

}

```

这样，当 order 为-1 时，顺序将被反转，表示升序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00025.jpg)

# 使用过滤器格式化货币

在 Vue 1 中，格式化货币有一定的局限性；我们将使用优秀的 accounting.js 库来构建一个更强大的过滤器。

# 准备工作

过滤器的基础知识在“使用过滤器格式化文本”一章中得到了探讨；在此之前，你需要构建一个基本过滤器，确保你完成了那部分，然后再回到这里。

# 操作步骤

将 accounting.js 添加到你的页面中。有关如何操作的更多详细信息，请参考[`openexchangerates.github.io/accounting.js/`](https://vuejs.org/v2/guide/computed.html)。不过，如果你在使用 JSFiddle，你可以将其作为外部资源添加到左侧菜单。你可以添加一个 CDN 链接来提供资源，例如[`cdn.jsdelivr.net/accounting.js/0.3.2/accounting.js`](http://openexchangerates.github.io/accounting.js/)。

这个过滤器非常简单：

```js
Vue.filter('currency', function (money) { 

  return accounting.formatMoney(money) 

})

```

你可以在 HTML 中尝试使用一行代码：

```js
I have {{5 | currency}} in my pocket

```

它将默认显示为美元，并打印"I have $5.00 in my pocket"。

# 工作原理是这样的...

当你在 JSFiddle 中或手动在页面中添加`accounting.js`时（或者使用`import`导入），你将使`accounting`对象可用。这样，你可以在过滤器中使用外部库（以及代码的任何其他地方）。

# 还有更多...

货币通常出现在表格中，它们需要对齐；让我们看看如何做到这一点。我们从如下 HTML 表格开始：

```js
<div id="app"> 

<table> 

  <thead> 

    <tr> 

      <th>Item</th> 

      <th>Price</th> 

    </tr> 

  </thead> 

  <tbody> 

    <tr v-for="item in inventory"> 

      <td>{{item.name}}</td> 

      <td>{{item.price}} 

    </td> 

  </tr> 

  </tbody> 

</table> 

</div>

```

我们正在遍历一个库存，当然，我们需要在 JavaScript 中指定它：

```js
new Vue({ 

  el:'#app', 

  data: { 

    inventory: [ 

      {name: 'tape measure', price: '7'}, 

      {name: 'stamp', price: '0.01'}, 

      {name: 'shark tooth', price: '1.5'}, 

      {name: 'iphone', price: '999'} 

    ] 

  } 

})

```

这时，我们有一个价格在页面上呈现的表格，但是没有货币符号，没有小数点后的位数一致性，也没有对齐。

我们计划使用我们的过滤器来帮助我们添加这三个。

在继续之前，最敏锐的读者可能会注意到我使用字符串来表示价格。为什么不用数字？这是因为 JavaScript 中的数字是浮点数；换句话说，它们不精确，因为小数位数是“浮动的”。

如果我们的销售中有一个售价为 0.83 欧元的小猫钥匙链，并且我们对此进行 50％的折扣，那么我们应该以 0.415 欧元的价格出售。由于不存在 0.5 分钱，我们将进行一些四舍五入。

一个客户在我们的在线商店上浏览，并对我们关于小猫的折扣感到惊讶。他购买了 3 个。如果你计算一下，应该是 1.245 欧元；我们对其应用`Math.round`函数，应该会得到 1.25 欧元。我们可以用以下代码进行检查：

```js
Math.round(1.245 * 100) / 100 

// output: 1.25

```

然而，请考虑到我们编码了所有的计算：

```js
var kittenKeychain = 0.83 

var kittyDiscount = 0.5 

var discountedKittenKeychain = kittenKeychain * kittyDiscount 

var boughtKeychains = discountedKittenKeychain * 3 

Math.round(boughtKeychains * 100) / 100 

// outputs: 1.24

```

在这个过程中我们损失了一分钱。设想一下，如果有一个大型应用程序处理成千上万的此类交易，或者设想一下如果这不是一个价格而是一个汇率。设想一下你需要将这个结果返回给后端，并且计算结果不匹配。误差可能会累积，最终的数字可能会有很大的差异。这只是一个小例子，但是在处理货币时使用浮点数还有更多的可能出错的地方。

使用字符串（或整数）表示货币可以给您想要的精度级别。

使用我们之前的过滤器将在小数点后引入美元符号和两个数字，但我们还是缺乏我们想要的对齐方式。我们应该为我们的 CSS 添加一个新的样式：

```js
.price { 

  text-align: right 

}

```

将价格列分配给类名为 price 的类将确保在小数点上对齐。以下是完整的代码：

```js
<div id="app"> 

<table> 

  <thead> 

    <tr> 

      <th>Item</th> 

      <th>Price</th> 

      </tr> 

  </thead> 

  <tbody> 

    <tr v-for="item in inventory"> 

      <td>{{item.name}}</td> 

      <td class="price">{{item.price | dollars}}</td> 

    </tr> 

  </tbody> 

</table> 

</div>

```

以下是用于 JavaScript 的代码：

```js
Vue.filter('dollars', function (money) { 

  return accounting.formatMoney(money) 

}) 

new Vue({ 

  el:'#app', 

  data: { 

    inventory: [ 

      {name: 'tape measure', price: '7'}, 

      {name: 'stamp', price: '0.01'}, 

      {name: 'shark tooth', price: '1.5'}, 

      {name: 'iphone', price: '999'} 

    ] 

  } 

})

```

# 使用过滤器格式化日期

有时，您需要一个比基本过滤器更强大的过滤器。您必须多次使用类似的过滤器，但每次都有微小的变化。过多的过滤器可能会造成混乱。这个关于日期的示例将说明问题和解决方案。

# 准备工作

在继续之前，通过阅读“在第一章中使用过滤器格式化文本”这一节，使自己更加熟悉过滤器；如果您已经了解过滤器，请继续阅读。

# 如何操作

假设我们正在策划一个学习历史的互动页面。我们有一个包含以下内容的 Vue 实例和 JavaScript 代码：

```js
new Vue({ 

  el:'#app', 

  data: { 

    bastilleStormingDate: '1789-07-14 17 h' 

  } 

})

```

在我们的数据中，我们有一个以字符串形式非正式地写入的日期在我们的实例数据中。我们的 HTML 可以包含法国大革命的时间线，并且在某个时候可以包含以下内容：

```js
<div id="app"> 

  The Storming of the Bastille, happened on {{bastilleStormingDate | date}} 

</div>

```

我们需要一个能够完成句子的过滤器。为此，一个可能的库是优秀的`moment.js`，而且，为了我们的目的，我们选择了本地化版本：[`cdnjs.cloudflare.com/ajax/libs/moment.js/2.14.1/moment-with-locales.js`](https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.14.1/moment-with-locales.js)。

在添加了库之后，编写以下过滤器：

```js
Vue.filter('date', function (date) { 

  return moment(date).format('LL') 

})

```

这将显示一个格式良好的日期：`The Storming of the Bastille, happened on July 14, 1789`。

如果我们想要一个多语言网站，并且希望日期以法语格式显示呢？`moment.js`库对于本地化非常好；实际上，让我们用法语写同样的文本：

```js
La prise de la Bastille, survenue le {{bastilleStormingDate | date}}

```

我们必须使用以下内容修改我们的过滤器：

```js
Vue.filter('date', function (date) { 

  moment.locale('fr') 

  return moment(date).format('LL') 

})

```

我们的结果是`La prise de la Bastille, survenue le 14 juillet 1789`，非常好！然而，我们不想在每个页面中硬编码语言。最好的方法是在过滤器中添加一个参数。我们希望可以通过变量将语言传递给过滤器，就像这样：

```js
La prise de la Bastille, survenue le {{bastilleStormingDate | date('fr')}}

```

为了实现这一点，我们必须在过滤器声明中添加第二个参数：

```js
Vue.filter('date', function (date, locale) { 

  moment.locale(locale) 

  return moment(date).format('LL') 

})

```

这样，我们就可以通过页面中的一个变量将语言作为参数传递了，例如，根据选择的语言而定。

# 有条件地显示和隐藏元素

有条件地显示和隐藏网页上的元素对某些设计来说是基本的。你可以有一个弹出窗口，一组你想要逐个显示的元素，或者只在点击按钮时显示的东西。

在这个示例中，我们将使用条件显示，并了解重要的`v-if`和`v-show`指令。

# 准备工作

在进入这个示例之前，请确保你对计算属性有足够的了解，或者请查看《使用计算属性过滤列表》一节。

# 如何做到这一点...

让我们构建一个只在夜晚可见的幽灵：

```js
<div id="ghost"> 

  <div v-show="isNight"> 

    I'm a ghost! Boo! 

  </div> 

</div>

```

`v-show`保证只有在`isNight`为`true`时才会显示`<div>`幽灵。例如，我们可以写为：

```js
new Vue({ 

  el: '#ghost', 

  data: { 

    isNight: true 

  } 

})

```

这将使幽灵可见。为了使示例更真实，我们可以将`isNight`作为一个计算属性来写：

```js
new Vue({ 

    el: '#ghost', 

    computed: { 

      isNight () { 

        return new Date().getHours() < 7 

    } 

  } 

})

```

如果你在 JSFiddle 中加载这个程序，你将在午夜后和早上 7 点之前看到幽灵。如果你真的等不及要看到幽灵，你可以作弊并在夜间插入一个时间，例如：

```js
return (new Date('4 January 03:30')).getHours() < 7

```

# 它是如何工作的...

`v-show`指令计算`isNight`计算属性，并在元素的`style`属性中放置一个`display: none`。

这意味着该元素完全由 Vue 渲染；它只是看不见，就像幽灵一样。

另一个用于条件显示元素的指令是`v-if`指令。行为与`v-show`相同，只是在 DOM 中找不到该元素。当`v-if`评估为`true`时，该元素将被动态添加，没有元素样式的参与。要试用它，只需将`v-show`替换为`v-if`：

```js
<div id="ghost"> 

  <div v-if="isNight"> 

    I'm a ghost! Boo! 

  </div> 

</div>

```

一般来说，如果没有区别，使用`v-show`更好，因为从长远来看，它需要更少的资源。另一方面，如果你甚至不确定某些元素是否会出现在页面上，使用`v-if`可以让用户节省一些 CPU 时间（你永远不知道你的应用何时会爆红，并拥有数百万用户；通过选择正确的方式，你可以节省大量能量！）。

顺便说一句，在午夜之前不要等在页面前面。什么都不会发生。计算属性仅在其中的响应式属性发生更改时重新评估。在这种情况下，我们有一个非响应式的`Date`，因此不会触发任何更新。

# 有条件地添加样式

现代网页架构的一个伟大特性是可以在 CSS 中打包大量的显示逻辑。这意味着您可以拥有非常干净且表达力强的 HTML，同时通过 CSS 创建令人印象深刻的交互页面。

Vue 在表达 HTML 和 CSS 之间的关系方面特别擅长，并允许您将复杂的逻辑封装为易于使用的函数。

在本示例中，我们将探讨使用 Vue 进行样式设置的基础知识。

# 操作步骤如下：

我们将构建一个文本区域，当您接近允许的最大字符数时会发出警告：

```js
<div id="app"> 

  <textarea 

    v-model="memeText" 

    :maxlength="limit"> 

  </textarea> 

  {{memeText.length}} 

</div>

```

所写的文本将与`memeText`变量绑定，文本的`length`将通过双大括号写在末尾。

当仅剩下 10 个字符时，我们想要更改背景颜色。为此，我们必须创建一个名为`warn`的 CSS 类：

```js
.warn { 

  background-color: mistyrose 

}

```

我们将在`textarea`上使用此类来表示即将达到的写入上限。让我们看一下 JavaScript 代码：

```js
new Vue({ 

  el: '#app', 

  data: { 

    memeText: 'What if I told you ' + 

              'CSS can do that', 

    limit: 50 

  } 

})

```

这只是我们的模型；我们想要添加一个名为`longText`的函数，当我们达到 40 个字符时（距离 50 个字符还有 10 个字符）评估为 true：

```js
computed: { 

  longText () { 

    if (this.limit - this.memeText.length <= 10) { 

        return true 

    } else { 

        return false 

    } 

  } 

}

```

现在一切就位，来条件性地添加 warn 样式。为此，我们有两个选项：**对象语法**和**数组语法**。我们先尝试使用对象语法：

```js
<div id="app"> 

  <textarea 

    v-model="memeText" 

    :class="{ warn: longText }" 

    :maxlength="limit"> 

  </textarea> 

  {{memeText.length}} 

</div>

```

这意味着，每当`longText`评估为`true`（或一般为真值）时，类`warn`将被添加到`textarea`中。

# 工作原理...

如果您尝试在文本区域中输入超过 39 个字符，背景色将变为薄雾的玫瑰色。通常，*n*个类的对象语法如下所示：

```js
:class="{ class1: var1, class2: var2, ..., classn: varn }"

```

然而，有几种代替此语法的方法。首先，您不需要在 HTML 中编写完整的对象；您还可以绑定到一个对象。一般的做法如下所示：

```js
<div :class="classes"></div> // in HTML 

// in your Vue instance 

data: { 

  classes: { 

    warn: true 

  } 

}

```

此时，操纵类对象将向`<div>`添加或移除`warn`类。一种更聪明的绑定方式是绑定到一个计算属性，该计算属性本身返回一个对象：

```js
<div :class="classes"></div> 

computed: { 

  classes () { 

    return { 

      warn: true 

    } 

  } 

}

```

当然，将一些自定义逻辑放在计算属性中会更容易：

```js
computed: { 

  classes () { 

    const longText = this.limit - this.memeText.length <= 10 

    return { 

      warn: longText 

    } 

  } 

}

```

# 通过 CSS 过渡为应用程序增加一些乐趣

过渡是在元素被插入、更新和从 DOM 中移除时应用的效果。

对于本示例，我们将为朋友们建立一个小谜题。当他们想知道答案时，它将以淡入效果出现。

# 准备工作

要完成本课程，您应该已经了解条件显示和条件渲染。 *条件显示和隐藏元素* 将教您如何做到这一点。

# 具体操作步骤...

让我们在 HTML 中设置谜题：

```js
<div id="app"> 

  <article> 

    They call me fruit.<br> 

    They call me fish.<br> 

    They call me insect.<br> 

    But actually I'm not one of those. 

    <div id="solution" @click="showSolution = true"> 

      I am a <span id="dragon" v-show="showSolution">Dragon</span> 

    </div> 

  </article> 

</div>

```

Vue 实例的初始化非常简单，您只需编写以下内容：

```js
new Vue({ 

    el: '#app', 

  data: { 

    showSolution: false 

  } 

})

```

在 CSS 中，我们希望清楚地表明`<div>`解决方案可以被点击，因此我们添加了以下规则：

```js
#solution { 

  cursor: pointer; 

}

```

现在应用程序可以工作了，但是您会立即看到 Dragon。我们想为我们的谜题增添一些优雅的效果，并通过淡入效果使龙出现。

我们需要两个 CSS 类；第一个类在解决方案出现时将被应用一次：

```js
.fade-enter { 

  opacity: 0 

}

```

第二个类将在第一个类之后持续存在：

```js
.fade-enter-active { 

  transition: opacity .5s;  

}

```

最后，我们将解决方案包装在一个过渡中：

```js
I am a <transition name="fade"> 

  <span id="dragon" v-show="showSolution">Dragon</span> 

</transition>

```

# 工作原理...

过渡的名称是 CSS 类选择器的第一个单词`(fade )`，Vue 将根据元素出现或从屏幕上消失来查找它们。如果未指定名称并且只使用了`<transition>`，Vue 将使用过渡名称`v`作为 CSS。

在我们的情况下，之前看不见的龙正出现了，所以`fade-enter`将在一个刻度中应用（刻度是刷新视图的一个周期，但你可以把它看作是动画中的一个帧）。这意味着在开始时`<span>`实际上是不可见的，因为透明度将被设置为`0`。

之后，`fade-enter`类将被移除，而附加在`fade-enter`上的`fade-enter-active`现在是唯一剩下的类。从该类的规则可以看出，透明度将在半秒钟内变为`1`。1 是在哪里指定的？这是默认值。

Vue 在过渡中要寻找的完整类集如下：

+   `name-enter`：这是`enter`的起始类；它在元素插入之前应用，并在一帧之后被移除。

+   `name-enter-active`：这是`enter`的持续类。它在元素插入之前应用，并在过渡/动画完成时被移除。使用它来定义过渡的特性，如持续时间和缓动。

+   `name-enter-to`：这是`enter`的结束类。在移除了`name-enter`时应用。

+   `name-leave`：这是`leave`的起始类。在触发`leave`过渡时应用，并在一帧之后被移除。

+   `name-leave-active`：这是`leave`的持续类。在触发`leave`过渡时应用，并在过渡/动画完成时被移除。

+   `name-leave-to`：这取代了`name-leave`。

这里，`name`是您过渡的名称（在未指定名称时为`v`）。

# 还有更多...

过渡很酷，但是在这个示例中有一个遮挡我们视图的树，这破坏了过渡的声誉。为了跟进，请考虑以下 HTML：

```js
<div id="app"> 

  <p> 

    Transitions are awesome, careful<br/> 

    please don't use them always. 

  </p> 

  <transition name="fade"> 

    <img id="tree" 

      src="http://i.imgur.com/QDpnaIE.png" 

      v-show="show" 

      @click="show = false"/> 

  </transition> 

</div>

```

一小段 CSS 如下所示：

```js
#tree { 

  position: absolute; 

  left: 7.5em; 

  top: 0em; 

  cursor: pointer; 

} 

.fade-leave-active { 

  transition: opacity .5s; 

  opacity: 0 

}

```

最后，需要一个简单的 Vue 实例：

```js
new Vue({ 

    el: '#app', 

  data: { 

    show: true 

  } 

})

```

当我们运行应用程序时，我们得到的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00026.jpg)

点击树会显示真正的消息。

# 输出原始 HTML

有时，您需要插入 HTML 内容，例如换行符（`<br>`），到您的应用程序数据中。这可以通过使用`v-html`指令轻松实现。

在这个示例中，我们将构建一个感谢信。

# 准备工作

对于这个示例，您不需要任何特殊的知识，但我们将建立在一些基本的 Vue 功能之上；如果您在本章节或上一章节中完成了一个示例，您就可以开始了。

# 如何做...

假设你有一个朋友约翰。在收到礼物之前，你想要准备一封格式化的感谢信，但是你不知道他会送给你什么。你预先写了三份文本：

```js
new Vue({ 

    el: '#app', 

  data: { 

    htmlTexts: [ 

    'Dear John,<br/>thank you for the <pre>Batman vs Superman</pre> DVD!', 

    'Dear John,<br/>thank you for <i>Ghostbusters 3</i>!', 

    'Dear John,<br/>thanks, <b>Gods of Egypt</b> is my new favourite!' 

    ] 

  } 

})

```

考虑到你会将这个变量直接输出在花括号内，如下所示：

```js
<div id="app"> 

  {{htmlTexts[0]}} 

</div>

```

问题在于，这种情况下，你会得到纯文本和所有的 HTML 乱码：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00027.jpg)

这不是你要寻找的；你希望你的感谢信按照 HTML 标签的格式进行良好的排版。

你需要做的是使用`v-html`指令，如下所示：

```js
<div id="app" v-html="htmlTexts[0]"> 

</div>

```

这样，HTML 标签就不会被 Vue 转义，并且会在我们的组件中按原样解释：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00028.jpg)

# 工作原理是这样的...

一般情况下，输出原始 HTML 是非常危险的。解释网站安全性超出了本书的范围，但只是为了让你有一个想法，想象一下你的网站上有一个评论部分，有人在评论中放置了一个`<img>`标签。如果你将其解释为 HTML 并展示给其他用户，你可能会让你的用户下载一个他们并不一定想要的图片；如果这个图片不属于你，你可能会因此被收取你没有计划的带宽费用。现在你可以扩展这个理由。如果一个用户在评论中放置了一个`<script>`标签，这将带来更大的风险，因为脚本可以做几乎任何事情。

默认情况下，Vue 通过不让你默认输出 HTML 来避免这个问题；这就是为什么我们需要特殊的`v-html`指令来查看它。也就是说，始终确保你对输出内容有完全控制。

# 还有更多...

还有另一种输出原始 HTML 的方法；这种方法更加先进，但更加清晰和可维护，尤其是对于那些严重依赖 HTML 格式化的组件来说。

在这些更加矫揉造作的情况下，你可以选择使用详细介绍在第九章的*创建一个函数式组件*配方中涵盖的**函数式组件**，但这里你将找到一个扩展了我们刚才所做的示例。

你应该写的 HTML 如下所示：

```js
<div id="app"> 

  <thanks gift="Batman" decoration="strong"></thanks> 

</div>

```

你已经可以看到意图很明确：使用 HTML `<strong>`作为装饰来写一封关于蝙蝠侠礼物的感谢信。创建`<thanks>`组件的 JavaScript 代码如下所示：

```js
Vue.component('thanks', { 

    functional: true, 

  render: function (createElement, context) { 

    let decoratedGift = 

      createElement(context.props.decoration, context.props.gift) 

    return createElement('p', ['Dear John, thanks for ', decoratedGift]) 

  }, 

  props: { 

    gift: String, 

    decoration: String 

  } 

})

```

当然，你还需要 Vue 实例。

# 创建一个带有复选框的表单

在当今的 Web 应用中，询问用户的输入是基本的。向用户展示多个选择使界面更有趣，对于结构化输入是必要的。

在这个教程中，你将学习如何通过构建确认页面来创建复选框，用于你自己的打印店！

# 准备工作

我们已经了解了 Vue 中的数据绑定是如何工作的，所以你可以开始操作了。否则，请返回第一个教程，收集 200 积分，然后继续阅读第一章中的*响应点击和按键事件*教程，以了解更多关于`v-model`指令的内容。

# 操作步骤

假设你需要为你的火星打印店设置三个不同的打印机：

+   - 单色打印机

+   - 等离子彩色打印机

+   - 3D DNA 克隆打印机

确认页面基本上只是一个表单：

```js
<div id="app"> 

  <form> 

    <!-- list of printers go here --> 

  </form> 

</div>

```

我们将使用`v-model`而不是名称来将我们的模型绑定到视图上：

```js
<label> 

  <input type="checkbox" v-model="outputPrinter" value="monochrome"/> 

  Monochrome 

</label>

```

每个具有相同`v-model`的`<input>`复选框都将参与一个反应性数组，在实时更新中插入和删除数组中的项。让我们在 Vue 实例中声明这个数组：

```js
new Vue({ 

    el:'#app', 

  data:{ 

    outputPrinter: [] 

  } 

})

```

这只是一个普通的数组。所有选中的打印机将自动插入和从数组中移除。以下是完整的 HTML 代码：

```js
<div id="app"> 

  <form> 

    <fieldset> 

      <legend>What printers you want to use?</legend> 

      <label> 

        <input type="checkbox" v-model="outputPrinter" value="monochrome"/> 

        Monochrome</label><br> 

      <label> 

        <input type="checkbox" v-model="outputPrinter" value="plasma"/> 

        Plasma Color</label><br> 

      <label> 

        <input type="checkbox" v-model="outputPrinter" value="cloner"/> 

        3D DNA Cloner</label><br> 

      <input type="submit" value="Print now"/> 

    </fieldset> 

  </form> 

</div>

```

这将生成一个类似下面的表单：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00029.jpg)

在你的应用程序的任何地方的`<div>`标签内放置`{{ outputPrinter }}`，并通过选择打印机来实时查看数组的变化。

# 工作原理...

如果你选中第一个和最后一个打印机，数组将如下所示：

```js
outputPrinter: ['monochrome', 'cloner']

```

然后，你可以使用这个数组将其通过 AJAX 发送到一个 Web 服务或进一步进行其他操作。

在 Vue 中，复选框只是普通的`<input>`元素，唯一的区别是我们实际上不需要在传统表单中使用的 name 属性。这是因为我们将不需要第二个页面来提交我们的值（通常使用 name 属性读取值的页面）。

# 更多内容...

要进入我所说的“第二个页面”，只需点击提交按钮。这是默认行为，在我们的情况下并不是我们想要的；因为我们通常不喜欢在处理 Vue 时需要改变页面，我将向你展示如何阻止默认行为。

现代网站倾向于在同一页上为你的操作提供反馈，有时甚至不会中断你的工作流程（如果你想在同一会话中克隆另外五个或六个实体怎么办？）

让我们将其变得更加有用。首先，我们必须阻止按钮的默认操作，即改变页面；为此，我们使用 prevent 修饰符：

```js
<input type="submit" value="Print now" @click.prevent="printHandler"/>

```

`printHandler`将是我们 Vue 实例中的一个方法，它将为我们提供一些反馈。您可以自由地添加处理程序，例如一个弹出窗口告诉您打印正在进行中；也许您可以返回主页。

在这个示例中，我们将使用警报弹出窗口来检查按钮是否正常工作：

```js
methods: { 

  printHandler () { 

    let printers = this.outputPrinter 

    alert('Printing with: ' + 

      (printers.length ? printers.join(', ') : 'none') + '.') 

  } 

}

```

# 创建一个带单选按钮的表单

单选按钮让您在多个选项中选择一个选项。当用户选择一个单选按钮时，任何先前选择的单选按钮将被取消选择。其常见用途是在创建注册表单时选择男性或女性。

# 准备工作

这个案例类似于“创建一个带复选框的表单”案例，因为我们使用了类似的技术。我建议你完成这两个案例，以成为 Vue 表单黑带。

# 操作步骤…

首先，我们需要一些可选择的内容，所以我们在 Vue 实例中编写一个数组：

```js
new Vue({ 

  el: '#app', 

  data: { 

    genders: ['male', 'female', 'alien'], 

    gender: undefined 

  } 

})

```

我们将使用变量 gender（单数）来保存所选选项的值。从这里开始，我们可以通过几行代码来设置一个表单：

```js
<div id="app"> 

  <form> 

    <fieldset> 

      <legend>Choose your gender</legend> 

      <label> 

        <input type="radio" v-model="gender" value="male"/> 

          Male 

      </label><br> 

      <label> 

        <input type="radio" v-model="gender" value="female"/> 

          Female 

      </label> <br>

      <label> 

        <input type="radio" v-model="gender" value="alien"/> 

          Alien 

      </label> 

    </fieldset> 

  </form> 

</div>

```

您可以运行应用程序，它将工作；但是，您需要在 form 后面添加一个胡子括号，以查看发生了什么：

```js
<div> 

  Choosen gender: '{{ gender }}' 

</div>

```

这样，您可以看到单选按钮的点击如何影响内部数据：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00030.jpg)

# 工作原理…

这里我们只插入了三个单选按钮。由于它们都有`v-model =“gender”`，它们在逻辑上属于同一组。这意味着在任何给定的时间只能选择一个值。我们可以在同一个表单中有任意多个组。

# 进一步了解...

在这个案例中，单选按钮的值完全是固定的：

```js
<input type="radio" v-model="gender" value="male"/>

```

我们可以修改`value =“male”`，使用`v-bind：value`使其动态响应。这会将值绑定到我们传递给它的任何变量。例如，假设我们的模型中有一个性别数组：

```js
genders: ['male', 'female']

```

我们可以像这样重写前面的单选按钮：

```js
<input type="radio" v-model="gender"**:value="genders[1]"**

/>

```

在这里，`:value`是`v-bind：value`的简写形式。

为了将我们学到的知识付诸实践，让我们构建一个简单的游戏。

假设您是一位农民，您的农场一开始没有动物。每天，动物市场上都有新的动物出售。您一次只能买一只。我们可以使用单选按钮来表示这个选择！

所以我们在我们的模型中有一个动物数组，一个包含我们每天选择的动物的变量，以及一个表示我们养殖场的农场数组（最初为空）。我们使用`i`变量添加了一点随机性，以保存表示当天可用动物的随机数：

```js
data:{ 

  animals: ['

', '

', '

'], 

  animal: undefined, 

  farm: [], 

  i: 0 

}

```

我使用表情符号来表示动物，因为它们非常有趣。如果你不知道在哪里找到它们，只需从[`emojipedia.org/`](http://emojipedia.org/)复制并粘贴它们，然后搜索动物。

我们可以从最初使用的相同 HTML 开始；我们只需要改变图例：

```js
<legend>Today's animals</legend>

```

此时，我们应该添加一个动物列表供选择，但我们希望它是动态的，也就是说，每天都有不同的动物对：

```js
<label> 

  <input type="radio" v-model="animal" :value="animals[i]"/> 

  {{animals[i]}} 

</label><br> 

<label> 

  <input type="radio" v-model="animal" :value="animals[i+1]"/> 

  {{animals[i+1]}} 

</label><br>

```

这意味着随着`i`变量的改变，单选按钮的值（和标签）将会改变。

唯一剩下的就是一种购买动物、将其添加到农场并等待下一天的方法。我们将在提交按钮中总结所有这些：

```js
<input type="submit" value="Add to Farm" @click.prevent="addToFarm"/>

```

在这里，`addToFarm`方法由以下内容定义：

```js
addToFarm () { 

    if (this.animal === undefined) { return } 

    this.farm.push(this.animal) 

    this.i = Math.floor(Math.random() * (this.animals.length - 1)) 

  this.animal = undefined 

}

```

如果没有选择动物，则不执行任何操作；否则，将动物添加到农场，为下一天生成一个随机数，并重置选择。要查看你的农场，请将以下内容添加到你的 HTML 中：

```js
<div> 

  Your farm is composed by {{ farm.join(' ') }} 

</div>

```

你的应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00034.jpg)

# 创建一个带有选择元素的表单

当单选按钮无法满足需求时，选择元素或“下拉列表”用于表单，无论是因为选择太多还是因为无论有多少选项，它们始终占据相同的空间。

# 准备工作

我建议您在深入研究选择元素之前先完成有关数据绑定或表单的教程。有关单选按钮的教程将使您熟悉单选按钮，其功能类似于选择元素。

# 如何操作...

在本教程中，我们将创建一个简单的国家选择器。我将首先在没有 Vue 的帮助下编写选择器，只是为了复习 HTML。首先，创建一个`form`，在其中放置`select`元素：

```js
<form> 

  <fieldset> 

    <legend>Choose your country</legend> 

      <!-- here goes the select element --> 

  </fieldset> 

</form>

```

在`fieldset`中，编写`select`元素的代码：

```js
<select> 

  <option>Japan</option> 

  <option>India</option> 

  <option>Canada</option> 

</select>

```

运行应用程序。从一开始就有一个可工作的选择元素。结构非常简单。每个`<option>`将增加可选择的事物列表。

目前，对于这个元素来说，还没有太多可以做的。让我们将选择的国家与 Vue 绑定到一个变量上。您需要编辑您的 HTML：

```js
<select v-model="choosenCountry">

```

现在，您需要将`choosenCountry`添加到您的模型中：

```js
new Vue({ 

    el:'#app', 

  data:{ 

    choosenCountry: undefined 

  } 

})

```

不要忘记用`<div id="app">`将表单包围起来，否则 Vue 将无法识别它。

现在运行应用程序，你会注意到，之前下拉菜单以日本为默认选择，现在它遵循了我们在代码中的初始化。

这意味着初始状态下没有选择任何国家。我们可以添加一个花括号来查看变量的当前状态：

```js
<div> 

  {{choosenCountry}} 

</div>

```

国家选择器将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00035.jpg)

# 它是如何工作的...

当你使用`v-model`将`<select>`元素绑定时，所选选项将填充绑定的变量。

请注意，如果为选项设置了值，变量将使用该值，而不是标签中写的内容。例如，你可以这样写：

```js
<select> 

  <option value="1">Japan</option> 

  <option value="2">India</option> 

  <option value="7">Canada</option> 

</select>

```

这样可以确保每个国家都绑定到一个数值。

# 还有更多...

通常，国家和城市以层次结构的方式排列。这意味着我们需要两个或更多的下拉菜单来确定用户的出生地，例如。在本段中，我们将使用生物学的等价物来选择动物：

```js
clans: { 

  mammalia: { 

    'have fingers': { 

      human: 'human', 

      chimpanzee: 'chimpanzee' 

    }, 

    'fingerless': { 

      cat: 'cat', 

      bear: 'bear' 

    } 

  }, 

  birds: { 

    flying: { 

      eagle: 'eagle', 

      pidgeon: 'pidgeon' 

    }, 

    'non flying': { 

      chicken: 'chicken' 

    } 

  } 

}

```

我们将把顶层称为`clan`，第二层称为`type`，最后一层将是一个动物。我知道这是一种非正统的分类动物的方式，但对于这个例子来说，它是有效的。

让我们为 Vue 模型添加两个保存状态的变量：

```js
clan: undefined, 

type: undefined

```

现在我们可以添加第一个`select`元素：

```js
<select v-model="clan"> 

  <option v-for="(types, clan) in clans">{{clan}}</option> 

</select>

```

这将创建一个下拉菜单，其中包含以下内容：

+   哺乳动物

+   鸟类

在这种特殊情况下，变量`types`实际上没有起作用。

我们希望用特定`clan`的`type`填充第二个下拉菜单：

```js
<select v-model="type"> 

  <option v-for="(species, type) in clans[clan]">{{type}}</option> 

</select>

```

当变量`clan`有值时，这个选择元素将让你选择动物的类型。请注意，尽管我们为物种添加了第三个选择：

```js
<select> 

  <option v-for="(animals, species) in clans[clan][type]">{{species}}</option> 

</select>

```

它会导致我们的程序出错，因为`clans[clan]`是未定义的，Vue 将尝试对其进行求值。为了纠正这个问题，我们可能希望只有在第一个和第二个选择有值时才显示第三个选择元素。为此，我们可以使用`v-show`指令，但问题是 Vue 会渲染带有`v-show`的元素，只有在渲染之后才会隐藏它们。这意味着错误仍然会被抛出。

正确的方法是使用`v-if`，如果内部条件不满足，则阻止元素的渲染，如下所示：

```js
<select v-if="clans[clan]"> 

  <option v-for="(animals, species) in clans[clan][type]">{{species}}</option> 

</select>

```

现在，继续选择你最喜欢的动物层次结构吧！
