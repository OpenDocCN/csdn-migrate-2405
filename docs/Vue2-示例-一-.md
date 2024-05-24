# Vue2 示例（一）

> 原文：[`zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42`](https://zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将介绍 Vue.js 2 的使用。Vue 可以作为前端框架通过包含一个 JS 文件来使用，也可以作为后端框架与 Node.js 一起使用。本书是使用前端版本的框架编写的，尽管会指出，如果需要的话，它可以很容易地转换为使用 Node 版本，因为这两个版本的框架的基本原理是相同的。

Vue 是一个可以用于简单数据显示和创建完整 Web 应用程序的框架。本书将尝试涵盖这两个方面，并介绍插件和附加组件，以帮助创建更大的应用程序。

本书还将介绍使用 Vue 组件的方法，包括使用它们而不是将所有数据和方法都包含在主 Vue 实例中的好处。本书还将介绍使用 Vue 的两个最流行的插件：Vuex 和 Vue-Router。本书不涵盖应用程序的样式处理过程。

Vuex 是 Vue 的集中式状态管理模式和库。它使存储、操作和访问数据变得更加可管理，并且非常适用于需要显示大量数据的应用程序。Vue-Router 用于处理应用程序的导航，根据 URL 加载不同的组件。

从一个 JSON 数据集开始，本书的第一部分将涵盖 Vue 对象及其如何利用每个对象。通过探索从 JSON 数据集中显示数据的不同方式来进行讲解。然后我们将继续使用过滤器和搜索来操作数据，并创建动态值。

完成后，我们将学习如何通过 API 动态加载数据，以 Dropbox API 为例。数据加载完成后，本书将介绍如何在文件夹之间导航，同时更新 URL 并创建文件的下载链接。然后，我们将加载 Vuex，并学习如何存储每个文件夹的数据，然后进行预缓存文件夹，使应用程序的导航速度更快。

最后，我们将学习如何使用之前项目中学到的技能以及引入新技能来创建一个电子商务前端。首先，产品将以列表的形式显示；使用过滤器和搜索，您将能够点击产品以获取更多信息并将其添加到购物篮中。准备好后，"客户"将能够查看他们的购物篮，更新商品和数量，并最终结账。

# 本书内容

第一章，“开始使用 Vue.js”，展示了如何通过包含 JavaScript 文件来开始使用 Vue。然后，我们开始初始化第一个 Vue 实例，并查看数据对象，以及计算函数和属性，最后学习 Vue 方法。

第二章，“显示、循环、搜索和过滤数据”，介绍了如何使用 Vue 使用`v-if`、`v-else`和`v-for`来显示列表和更复杂的数据。然后，它介绍了如何使用表单元素来过滤列表，并根据数据应用条件性的 CSS 类。

第三章，“优化我们的应用程序并使用组件显示数据”，是关于通过减少重复和逻辑组织我们的代码来优化我们的 Vue.js 代码。完成后，它介绍了如何创建 Vue 组件并与 Vue 一起使用它们，如何在组件中使用 props 和 slots，并利用事件在组件之间传递数据。

第四章，“使用 Dropbox API 获取文件列表”，介绍了如何加载和查询 Dropbox API，并列出 Dropbox 帐户中的目录和文件。然后，它介绍了如何为应用程序添加加载状态，并使用 Vue 动画。

第五章，“浏览文件树和从 URL 加载文件夹”，解释了如何为文件和文件夹创建组件，并在文件夹组件中添加链接以更新目录列表。它还涵盖了如何为文件组件添加下载按钮，并创建一个面包屑组件，以便用户可以轻松地向上导航树，并动态更新浏览器的 URL，这样如果一个文件夹被收藏或链接被分享，正确的文件夹将被加载。

第六章，“使用 Vuex 缓存当前文件夹结构”，展示了如何开始使用 Vuex，并从 Vuex Store 中存储和检索数据。然后，它介绍了如何将 Vuex 与我们的 Dropbox 应用程序集成，如何缓存当前 Dropbox 文件夹的内容，并在需要时从存储中加载数据。

第七章，“预缓存其他文件夹和文件以实现更快的导航”，描述了预缓存文件夹的过程，存储父文件夹的内容，以及如何缓存文件的下载链接。

第八章，*介绍 Vue-Router 和加载基于 URL 的组件*，探讨了 Vue-Router 的初始化及其选项以及如何使用 Vue-Router 创建链接。然后，它介绍了如何根据 URL 创建动态路由来更新视图。从那里开始，它描述了如何在 URL 中使用 props，嵌套和命名路由，并进行程序化导航。

第九章，*使用 Vue-Router 动态路由加载数据*，介绍了我们的组件和路由的概述，加载产品 CSV 文件并创建带有图像和产品变体的单个产品页面。

第十章，*构建电子商务商店，浏览产品*，描述了如何创建一个具有特定产品的主页列表页面，创建一个具有可重用组件的类别页面，创建一个订购机制，动态创建过滤器，并允许用户过滤产品。

第十一章，*构建电子商务商店，添加结账功能*，介绍了构建功能的过程，允许用户将产品添加到购物篮中，允许用户结账并添加订单确认页面。

第十二章，*使用 Vue 开发工具和测试您的 SPA*，介绍了使用 Vue 开发工具与我们开发的应用程序，并概述了测试工具和应用程序的用法。

# 您需要为本书准备的内容

对于本书，读者需要以下内容：

+   一个文本编辑器或 IDE 来编写代码。它可以是简单的记事本或 TextEdit，但建议使用具有语法高亮功能的 Sublime Text、Atom 或 Visual Studio Code。

+   一个网络浏览器。

+   一个带有文件和文件夹的 Dropbox 用户帐户。

# 本书适用对象

本书适用于熟悉 JavaScript 但希望探索 JavaScript MVVM 框架用于**单页应用程序**（**SPA**）的开发人员。他们应该熟悉 HTML 并熟悉 CSS，以便能够构建和样式化 SPA 的界面。本书将引导读者从初始化 Vue 及其基本功能一直到使用高级 Vue 插件和技术。读者应该熟悉 JavaScript 函数和变量以及使用 ES6/ES2015 箭头函数的用法。

# 本书的约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名以如下方式显示：“只需将要激活的图层名称分配给`VK_INSTANCE_LAYERS`环境变量。”

代码块设置如下：

```js
      <div id="app">
        {{ calculateSalesTax(shirtPrice) }}
      </div>
```

任何命令行输入或输出都以如下方式书写：

```js
 app.salesTax = 20
```

**新术语**和**重要词汇**以粗体显示。屏幕上显示的词汇，例如菜单或对话框中的词汇，以如下方式出现在文本中：“从管理面板中选择系统信息。”

警告或重要提示以如下方式出现在一个框中。技巧和窍门以如下方式出现。


# 第一章：开始使用 Vue.js

Vue（发音为 view）是一个非常强大的 JavaScript 库，用于构建交互式用户界面。尽管具有处理大型单页应用程序的能力，但 Vue 也非常适合为小型个别用例提供框架。它的小文件大小意味着可以将其集成到现有生态系统中而不会增加太多冗余。

它被设计成具有简单的 API，与其竞争对手 React 和 Angular 相比，更容易入门。尽管它借鉴了这些库的一些逻辑和方法，但它已经确定开发人员需要一个更简单的库来构建应用程序。

与 React 或 Angular 不同，Vue 的一个优点是它产生的 HTML 输出干净。其他 JavaScript 库往往会在代码中散布额外的属性和类，而 Vue 会删除这些内容以产生干净、语义化的输出。

在本书的第一部分中，我们将构建一个使用 JSON 字符串来显示数据的应用程序。然后，我们将研究数据过滤和操作，然后转向构建可重用组件以减少代码重复。

在本章中，我们将讨论以下内容：

+   如何通过包含 JavaScript 文件来开始使用 Vue

+   如何初始化您的第一个 Vue 实例并查看数据对象

+   检查计算函数和属性

+   了解 Vue 方法

# 创建工作空间

要使用 Vue，我们首先需要在 HTML 中包含该库并初始化它。对于本书第一部分的示例，我们将在单个 HTML 页面中构建我们的应用程序。这意味着用于初始化和控制 Vue 的 JavaScript 将放置在页面底部。这将使我们的所有代码都保持在一个地方，并且意味着它可以轻松在您的计算机上运行。打开您喜欢的文本编辑器并创建一个新的 HTML 页面。使用以下模板作为起点：

```js
      <!DOCTYPE html>
      <html>
        <head>
        <meta charset="utf-8">
        <title>Vue.js App</title>
        </head>
        <body>
        <div id="app">
          </div>
          <script src="https://unpkg.com/vue"></script>
          <script type="text/javascript">
            // JS Code here
          </script>
        </body>
      </html>
```

主要的 HTML 标签和结构对您来说应该是熟悉的。让我们简要介绍一下其他一些方面。

# 应用空间

这是您的应用程序容器，并为 Vue 提供了一个工作画布。所有的 Vue 代码都将放置在这个标签中。实际的标签可以是任何 HTML 元素-主要是 main、section 等。元素的 ID 需要是唯一的，但可以是任何您希望的。这允许您在一个页面上拥有多个 Vue 实例，或者确定哪个 Vue 实例与哪个 Vue 代码相关联：

```js
      <div id="app">
      </div>
```

在教程中，将使用具有 ID 的此元素称为应用空间或视图。应注意，所有 HTML、标签和代码都应放置在此容器中。

尽管您可以在应用程序空间中使用大多数 HTML 标签，但不能在`<body>`或`<HTML>`标签上初始化 Vue - 如果这样做，Vue 将抛出 JavaScript 错误并无法初始化。您必须在`body`内使用一个元素。

# Vue 库

在本书的示例中，我们将使用来自 CDN（内容分发网络）unpkg 的 Vue.js 的托管版本。这确保我们的应用程序中有最新版本的 Vue，并且还意味着我们不需要创建和托管其他 JavaScript 文件。Unpkg 是一个独立的托管流行库的网站。它使您能够快速轻松地将 JavaScript 包添加到您的 HTML 中，而无需下载和托管文件：

```js
      <script src="https://unpkg.com/vue"></script>
```

在部署代码时，最好从本地文件提供库，而不是依赖于 CDN。这样可以确保您的实现将与当前保存的版本一起工作，以防他们发布更新。它还会增加应用程序的速度，因为它不需要从另一个服务器请求文件。

在包含库的`script`块中，我们将编写我们 Vue 应用程序的所有 JavaScript 代码。

# 初始化 Vue 并显示第一条消息

现在我们已经设置好了一个模板，我们可以使用以下代码初始化 Vue 并将其绑定到 HTML 应用空间：

```js
      const app = new Vue().$mount('#app');
```

此代码创建了 Vue 的一个新实例，并将其挂载在具有 ID 为`app`的 HTML 元素上。如果您保存文件并在浏览器中打开它，您会注意到没有发生任何事情。然而，在幕后，这一行代码将`div`与`app`变量链接在一起，`app`是 Vue 应用程序的一个实例。

Vue 本身有许多对象和属性，我们现在可以使用它们来构建我们的应用程序。您将遇到的第一个是`el`属性。使用 HTML 的 ID，此属性告诉 Vue 它应该绑定到哪个元素以及应用程序将被包含在哪里。这是挂载 Vue 实例的最常见方式，所有 Vue 代码都应该在此元素内进行：

```js
      const app = new Vue({
        el: '#app'
      });
```

当实例中没有指定`el`属性时，Vue 会初始化为未挂载状态，这允许在挂载之前运行和完成任何指定的函数或方法。然后，当准备好时，可以独立调用挂载函数。在使用`el`属性时，Vue 在幕后使用`$.mount`函数来挂载实例。如果确实想要等待，可以单独调用`$mount`函数，例如：

```js
      const app = new Vue();

      // When ready to mount app:
      app.$mount('#app');
```

然而，由于我们在整本书中不需要延迟执行挂载时机，所以可以使用`el`元素与 Vue 实例一起使用。使用`el`属性也是挂载 Vue 应用程序的最常见方式。

除了`el`值之外，Vue 还有一个包含我们需要访问应用程序或应用程序空间的任何数据的`data`对象。在 Vue 实例中创建一个新的数据对象，并通过以下方式为属性赋值：

```js
      const app = new Vue({
        el: '#app',

        data: {
 message: 'Hello!'
 }
      });
```

在应用程序空间中，我们现在可以访问`message`变量。为了在应用程序中显示数据，Vue 使用 Mustache 模板语言来输出数据或变量。通过将变量名放在双花括号`{{ 变量 }}`之间来实现。逻辑语句，如`if`或`foreach`，获取 HTML 属性，这将在本章后面进行介绍。

在应用程序空间中，添加代码来输出字符串：

```js
      <div id="app">
        {{ message }}
      </div>
```

保存文件，用浏览器打开，应该会显示出 Hello!字符串。

如果没有看到任何输出，请检查 JavaScript 控制台是否有错误。确保远程 JavaScript 文件正确加载，因为某些浏览器和操作系统在本地计算机上查看页面时，需要额外的安全步骤才能允许加载某些远程文件。

`data`对象可以处理多个键和数据类型。向数据对象添加更多的值，看看会发生什么-确保在每个值后面添加逗号。数据值是简单的 JavaScript，也可以处理基本的数学运算-尝试添加一个新的`price`键，并将值设置为`18 + 6`，看看会发生什么。或者，尝试添加一个 JavaScript 数组并将其打印出来：

```js
      const app = new Vue({
        el: '#app',

        data: {
         message: 'Hello!',
 price: 18 + 6,
 details: ['one', 'two', 'three']
       }
     });
```

在应用程序空间中，现在可以输出每个值-`{{ price }}`和`{{ details }}`现在输出数据-尽管列表可能不是您预期的样子。我们将在第二章中介绍如何使用和显示列表，*显示、循环、搜索和过滤数据*。

Vue 中的所有数据都是响应式的，可以由用户或应用程序更新。可以通过打开浏览器的 JavaScript 控制台并自己更新内容来测试。尝试输入`app.message = 'Goodbye!';`并按下*Enter*键-您的应用程序的内容将更新。这是因为您直接引用了属性-第一个`app`是指您在 JavaScript 中初始化应用程序的`const app`变量。句点表示其中的属性，而`message`表示数据键。您还可以将`app.details`或`price`更新为任何您想要的内容！

# 计算值

Vue 中的`data`对象非常适合直接存储和检索数据，但有时您可能希望在将数据输出到应用程序中之前对其进行操作。我们可以使用 Vue 中的`computed`对象来实现这一点。使用这种技术，我们能够开始遵循 MVVM（模型-视图-视图模型）方法论。

MVVM 是一种软件架构模式，将应用程序的各个部分分离成不同的部分。模型（或数据）是原始数据输入，可以来自 API、数据库或硬编码的数据值。在 Vue 的上下文中，这通常是我们之前使用的`data`对象。

视图是应用程序的前端。它只用于从模型输出数据，不应包含任何逻辑或数据操作，除非有一些无法避免的`if`语句。对于 Vue 应用程序来说，这些代码都放在`<div id="app"></div>`标签中。

视图模型是两者之间的桥梁。它允许您在视图输出之前操作模型中的数据。例如，将字符串转换为大写或添加货币符号前缀，或者从列表中过滤出折扣产品或计算数组中字段的总值等。在 Vue 中，这就是`computed`对象的作用。

计算对象可以有任意多个属性，但它们必须是函数。这些函数可以利用 Vue 实例上已有的数据并返回一个值，无论是字符串、数字还是数组，都可以在视图中使用。

第一步是在 Vue 应用程序中创建一个计算对象。在这个例子中，我们将使用计算值将字符串转换为小写，所以将`message`的值设置为一个字符串：

```js
      const app = new Vue({
          el: '#app',

        data: {
           message: 'Hello Vue!'
       },
          computed: {
 }
      });
```

不要忘记在数据对象的闭合大括号(`}`)之后添加逗号(`,`)，以便 Vue 知道要期望一个新对象。

下一步是在计算对象内创建一个函数。开发中最困难的部分之一是给事物命名 - 确保函数的名称具有描述性。由于我们的应用程序非常小且操作基本，我们将把它命名为`messageToLower`：

```js
      const app = new Vue({
        el: '#app',
        data: {
          message: 'HelLO Vue!'
        },
        computed: {
          messageToLower() {
 return 'hello vue!';
 }
        }
     });
```

在上面的示例中，我将其设置为返回一个硬编码的字符串，该字符串是`message`变量内容的小写版本。计算函数可以像在视图中使用数据键一样使用。将视图更新为输出`{{ messageToLower }}`而不是`{{ message }}`，然后在浏览器中查看结果。

然而，这段代码存在一些问题。首先，如果`messageToLower`的值是硬编码的，我们可以将其添加到另一个数据属性中。其次，如果`message`的值发生变化，小写版本将不再正确。

在 Vue 实例中，我们可以使用`this`变量访问数据值和计算值 - 我们将更新函数以使用现有的`message`值：

```js
      computed: {
        messageToLower() {
          return this.message.toLowerCase();
        }
      }
```

`messageToLower`函数现在引用现有的`message`变量，并使用原生 JavaScript 函数将字符串转换为小写。尝试在应用程序中或 JavaScript 控制台中更新`message`变量，以查看其更新。

计算函数不仅限于基本功能 - 请记住，它们旨在从视图中删除所有逻辑和操作。一个更复杂的例子可能是以下内容：

```js
      const app = new Vue({
        el: '#app',
             data: {
          price: 25,
          currency: '$',
          salesTax: 16
        },
        computed: {
          cost() {
       // Work out the price of the item including 
          salesTax
            let itemCost = parseFloat(
              Math.round((this.salesTax / 100) * 
              this.price) + this.price).toFixed(2);
            // Add text before displaying the currency and   
             amount
            let output = 'This item costs ' + 
            this.currency + itemCost;
           // Append to the output variable the price 
             without salesTax
             output += ' (' + this.currency + this.price + 
        ' excluding salesTax)';
             // Return the output value
              return output;
           }
        }
     });
```

虽然乍一看可能很高级，但该代码是将固定价格与添加了销售税后的价格进行计算。`price`、`salesTax`和`currency`符号都存储为数据对象上的值，并在`cost()`计算函数中访问。视图输出`{{ cost }}`，产生以下结果：

此商品价格为$29.00（不含销售税为$25）

如果更新了任何数据，无论是用户还是应用程序本身，计算函数都会重新计算和更新。这使得我们的函数可以根据`price`和`salesTax`值动态更新。在浏览器的控制台中尝试以下命令之一：

```js
 app.salesTax = 20
```

```js
 app.price = 99.99
```

段落和价格将立即更新。这是因为计算函数对`data`对象和应用程序的其余部分都是响应式的。

# 方法和可重用函数

在您的 Vue 应用程序中，您可能希望以一致或重复的方式计算或操作数据，或者运行不需要将输出传递给视图的任务。例如，如果您想要计算每个价格的销售税或从 API 检索一些数据，然后将其分配给某些变量。

与其为每次需要执行此操作时创建计算函数，Vue 允许您创建函数或方法。这些在您的应用程序中声明，并且可以从任何地方访问 - 类似于`data`或`computed`函数。

在您的 Vue 应用程序中添加一个方法对象，并注意数据对象的更新：

```js
      const app = new Vue({
        el: '#app',

        data: {
          shirtPrice: 25,
          hatPrice: 10,

          currency: '$',
          salesTax: 16
        },
        methods: {

 }
      });
```

在`data`对象中，`price`键已被替换为两个价格 - `shirtPrice`和`hatPrice`。我们将创建一个方法来计算每个价格的销售税。

类似于为计算对象创建函数，创建一个名为`calculateSalesTax`的方法函数。此函数需要接受一个参数，即`price`。在内部，我们将使用前面示例中的代码来计算销售税。请记住，将`this.price`替换为参数名`price`，如下所示：

```js
      methods: {
        calculateSalesTax(price) {
          // Work out the price of the item including   
          sales tax
          return parseFloat(
          Math.round((this.salesTax / 100) * price) 
         + price).toFixed(2);
        }
      }
```

保存不会对我们的应用程序产生任何影响 - 我们需要调用该函数。在您的视图中，更新输出以使用该函数并传入`shirtPrice`变量：

```js
      <div id="app">
        {{ calculateSalesTax(shirtPrice) }}
      </div>
```

保存您的文档并在浏览器中检查结果 - 是否符合您的预期？下一个任务是在数字前面添加货币符号。我们可以通过添加第二个方法来实现这一点，该方法返回传入函数的参数，并在数字前面添加货币符号：

```js
      methods: {
        calculateSalesTax(price) {
          // Work out the price of the item including 
          sales tax
          return parseFloat(
            Math.round((this.salesTax / 100) * price) +   
            price).toFixed(2);
         },
         addCurrency(price) {
 return this.currency + price;
 }
      }
```

然后，在我们的视图中更新输出以同时利用这两个方法。我们可以将第一个函数`calculateSalesTax`作为第二个`addCurrency`函数的参数传递，而不是赋值给一个变量。这是因为第一个方法`calculateSalesTax`接受`shirtPrice`参数并返回新的金额。我们不再将其保存为变量并将变量传递给`addCurrency`方法，而是直接将结果传递给此函数，即计算出的金额。

```js
      {{ addCurrency(calculateSalesTax(shirtPrice)) }}
```

然而，每次需要输出价格时编写这两个函数会变得繁琐。从这里开始，我们有两个选择：

+   我们可以创建第三个方法，名为`cost()` - 它接受价格参数并将输入通过这两个函数传递

+   创建一个计算函数，例如`shirtCost`，它使用`this.shirtPrice`而不是传入参数

或者，我们可以创建一个名为`shirtCost`的方法，它与我们的计算函数相同；然而，在这种情况下最好练习使用计算函数。

这是因为`computed`函数是被缓存的，而`method`函数不是。如果想象一下我们的方法比目前复杂得多，反复调用函数（例如，如果我们想在多个位置显示价格）可能会对性能产生影响。使用计算函数，只要数据不变，您可以随意调用它，应用程序会将结果缓存。如果数据发生变化，它只需要重新计算一次，并重新缓存该结果。

为`shirtPrice`和`hatPrice`创建计算函数，以便两个变量都可以在视图中使用。不要忘记在内部调用函数时必须使用`this`变量 - 例如，`this.addCurrency()`。使用以下 HTML 代码作为视图的模板：

```js
      <div id="app">
        <p>The shirt costs {{ shirtCost }}</p>
        <p>The hat costs {{ hatCost }}</p>
      </div>
```

在与以下代码进行比较之前，请尝试自己创建计算函数。不要忘记在开发中有很多方法可以做事情，所以如果你的代码能够工作但与以下示例不匹配，不要担心：

```js
      const app = new Vue({
        el: '#app',
        data: {
          shirtPrice: 25,
          hatPrice: 10,

          currency: '$',
          salesTax: 16
        },
        computed: {
          shirtCost() {
            returnthis.addCurrency(this.calculateSalesTax(
              this.shirtPrice))
          },
          hatCost() {
          return this.addCurrency(this.calculateSalesTax(
          this.hatPrice))
          },
        },
        methods: {
          calculateSalesTax(price) {
            // Work out the price of the item including 
            sales tax
            return parseFloat(
              Math.round((this.salesTax / 100) * price) + 
              price).toFixed(2);
                },
                addCurrency(price) {
            return this.currency + price;
          }
        }
      });
```

尽管基本，但结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00005.jpeg)

# 总结

在本章中，我们学习了如何开始使用 Vue JavaScript 框架。我们检查了 Vue 实例中的`data`、`computed`和`methods`对象。我们介绍了如何在框架中使用每个对象并利用它们的优势。


# 第二章：显示、循环、搜索和过滤数据

在第一章中，我们介绍了 Vue 中的`data`，`computed`和`method`对象以及如何显示静态数据值。在本章中，我们将介绍以下内容：

+   使用`v-if`，`v-else`和`v-for`显示列表和更复杂的数据

+   使用表单元素过滤列表

+   根据数据应用条件性的 CSS 类

我们将使用 JSON 生成器服务（[`www.json-generator.com/`](http://www.json-generator.com/)）随机生成要使用的数据。这个网站允许我们获取虚拟数据进行练习。以下模板用于生成我们将使用的数据。将以下内容复制到左侧以生成具有相同格式的数据，以便属性与代码示例匹配，如下所示：

```js
      [
        '{{repeat(5)}}',
        {
          index: '{{index()}}',
          guid: '{{guid()}}',
          isActive: '{{bool()}}',
          balance: '{{floating(1000, 4000, 2, "00.00")}}',
          name: '{{firstName()}} {{surname()}}',
          email: '{{email()}}',
          registered: '{{date(new Date(2014, 0, 1), new Date(), "YYYY-            
         MM-ddThh:mm:ss")}}'
        }
      ]
```

在构建我们的简单应用程序并显示用户之前，我们将介绍 Vue 的更多功能和视图中可用的 HTML 特定属性。这些功能从动态渲染内容到循环遍历数组等。

# HTML 声明

Vue 允许您使用 HTML 标签和属性来控制和修改应用程序的视图。这包括动态设置属性，如`alt`和`href`。它还允许您根据应用程序中的数据来渲染标签和组件。这些属性以`v-`开头，并且如本书开头所提到的，在渲染时会从 HTML 中删除。在我们开始输出和过滤数据之前，我们将介绍一些常见的声明。

# v-html

`v-html`指令允许您输出内容而不使用花括号语法。如果输出包含 HTML 标签，它也可以用于将输出呈现为 HTML 而不是纯文本。HTML 属性的值是数据键或计算函数名称的值：

**View**:

在您的视图应用空间中，将`v-html`属性添加到一个元素中：

```js
      <div id="app">
        <div v-html="message"></div>
      </div>
```

**JavaScript**:

在 JavaScript 中，将`message`变量设置为包含一些 HTML 元素的字符串：

```js
      const app = new Vue({
        el: '#app',

        data: {
          message: '<h1>Hello!</h1>'
        }
      });
```

你应该尽量避免将 HTML 添加到 Vue 实例中，因为这会混淆我们的 MVVM 结构中的视图和 ViewModel 和 Model。还有一个危险，你可能会在另一个 HTML 标签中输出一个无效的 HTML 标签。只有在你信任的数据上使用`v-html`，因为在外部 API 上使用它可能会带来安全问题，因为它允许 API 控制你的应用程序。一个潜在的恶意 API 可以使用`v-html`来注入不需要的内容和 HTML。只有在你完全信任的数据上使用`v-html`。

# 声明式渲染

使用 Vue，可以使用`v-bind:`属性动态填充常规 HTML 属性，例如`<img>`标签的`src`。这允许你使用 Vue 应用程序中的数据填充任何现有属性。这可能是图像源或元素 ID。

`bind`选项通过在要填充的属性前面添加属性来使用。例如，如果你想使用名为`imageSource`的数据键的值填充图像源，你可以这样做：

**视图**：

在视图应用空间中创建一个带有动态`src`属性的 img 标签，使用`v-bind`和一个名为`imageSource`的变量。

```js
      <div id="app">
        <img v-bind:src="imageSource">
      </div>
```

**JavaScript**：

在 Vue 的 JavaScript 代码中创建一个名为`imageSource`的变量。添加所需图像的 URL：

```js
      const app = new Vue({
        el: '#app',

        data: {
          imageSource: 'http://via.placeholder.com/350x150'
        }
      });
```

`v-bind:`属性可以缩写为`:`，所以，例如，`v-bind:src`将变为`:src`。

# 条件渲染

使用自定义 HTML 声明，Vue 允许你根据数据属性或 JavaScript 声明有条件地渲染元素和内容。这些包括`v-if`，用于在声明等于 true 时显示容器，以及`v-else`，用于显示替代内容。

# v-if

最基本的例子是`v-if`指令-根据条件确定是否显示块的值或函数。

在视图中创建一个带有单个`div`的 Vue 实例，并设置一个名为`isVisible`的数据键，值为`false`。

**视图**：

从以下视图代码开始：

```js
      <div id="app">
        <div>Now you see me</div>
      </div>
```

**JavaScript**：

在 JavaScript 中，初始化 Vue 并创建一个`isVisible`数据属性：

```js
      const app = new Vue({
        el: '#app',

        data: {
          isVisible: false
        }
      });
```

现在，你的 Vue 应用程序将显示元素的内容。现在在 HTML 元素中添加`v-if`指令，值为`isVisible`：

```js
      <div id="app">
        <div v-if="isVisible">Now you see me</div>
      </div>
```

保存后，你的文本应该消失。这是因为标签根据值进行条件渲染，而当前值为`false`。如果你打开 JavaScript 控制台并运行以下代码，你的元素应该重新出现：

```js
      app.isVisible = true
```

`v-if`不仅适用于布尔值 true/false。您可以检查数据属性是否等于特定字符串：

```js
      <div v-if="selected == 'yes'">Now you see me</div>
```

例如，上述代码检查所选数据属性是否等于`yes`的值。`v-if`属性接受 JavaScript 运算符，因此可以检查不等于、大于或小于。

危险在于您的逻辑开始从 ViewModel 中渗入到 View 中。为了解决这个问题，该属性还可以将函数作为值。该方法可以是复杂的，但最终必须返回`true`以显示代码和`false`以隐藏代码。请记住，如果函数返回除 false 值（例如`0`或`false`）之外的任何值，则结果将被解释为 true。

这将看起来像这样：

```js
      <div v-if="isSelected">Now you see me</div>
```

您的方法可以是这样的：

```js
      isSelected() {
        return selected == 'yes';
      }
```

如果您不希望完全删除元素，只是隐藏它，那么有一个更合适的指令`v-show`。这将应用 CSS 显示属性而不是操作 DOM - `v-show`将在本章后面介绍。

# v-else

`v-else`允许您根据`v-if`语句的相反情况渲染替代元素。如果结果为 true，则显示第一个元素；否则，显示包含`v-else`的元素。

具有`v-else`的元素需要直接跟在包含`v-if`的元素后面；否则，您的应用程序将抛出错误。

`v-else`没有值，并且放置在元素标签内部。

```js
      <div id="app">
        <div v-if="isVisible">
          Now you see me
        </div>
        <div v-else>
          Now you don't
        </div>
      </div>
```

将上述 HTML 添加到您的应用程序空间将只显示一个`<div>`元素 - 在控制台中切换值，就像我们之前做的那样，将显示另一个容器。如果您希望链接您的条件，您还可以使用`v-else-if`。`v-else-if`的示例如下：

```js
      <div id="app">
        <div v-if="isVisible">
          Now you see me
        </div>
        <div v-else-if="otherVisible">
          You might see me
        </div>
        <div v-else>
          Now you don't
        </div>
      </div>
```

如果`isVisible`变量等于`false`，则可能会看到`me`，但`otherVisible`变量等于`true`。

应谨慎使用`v-else`，因为它可能会产生歧义，并可能导致错误的情况。

# v-for 和显示我们的数据

下一个 HTML 声明意味着我们可以开始显示数据并将其中一些属性应用到实践中。由于我们的数据是一个数组，我们需要循环遍历它以显示每个元素。为此，我们将使用`v-for`指令。

生成您的 JSON 并将其分配给名为`people`的变量。在这些示例中，生成的 JSON 循环将显示在代码块中，如`[...]`。您的 Vue 应用程序应如下所示：

```js
      const app = new Vue({
        el: '#app',

        data: {
          people: [...]
        }
      });
```

现在我们需要将每个人的姓名显示为项目符号列表。这就是`v-for`指令的作用：

```js
      <div id="app">
        <ul>
          <li v-for="person in people">
            {{ person }}
          </li>
        </ul>
      </div>
```

`v-for`循环遍历 JSON 列表，并临时将其分配给`person`变量。然后，我们可以输出变量的值或属性。

`v-for`循环需要应用于要重复的 HTML 元素，例如`<li>`。如果您没有包装元素或不希望使用 HTML，可以使用 Vue 的`<template>`元素。这些元素在运行时被移除，同时仍然为您创建一个容器来输出数据：

```js
      <div id="app">
        <ul>
          <template v-for="person in people">
            <li>
              {{ person }}
            </li>
          </template>
        </ul>
      </div>
```

模板标签还可以隐藏内容，直到应用程序初始化完成，这在您的网络速度较慢或 JavaScript 需要一段时间才能触发时可能很有用。

如果我们只是让我们的视图输出`{{ person }}`，将会创建一个长字符串的信息，对我们没有任何用处。更新输出以定位`person`对象的`name`属性：

```js
      <li v-for="person in people">
        {{ person.name }}
      </li>
```

在浏览器中查看结果应该会显示一个用户姓名的列表。更新 HTML 以在表格中列出用户的姓名、电子邮件地址和余额。将`v-for`应用于`<tr>`元素：

```js
      <table>
        <tr v-for="person in people">
          <td>{{ person.name }}</td>
          <td>{{ person.email }}</td>
          <td>{{ person.balance }}</td>
          <td>{{ person.registered }}</td>
        </tr>
      </table>
```

在您的表格中添加一个额外的单元格。这将使用`person`对象上的`isActive`属性显示 Active（活动）或 Inactive（非活动）。这可以通过两种方式实现 - 使用`v-if`指令或使用三元`if`。三元 if 是内联的`if`语句，可以放置在视图的花括号中。如果我们想要使用 HTML 元素来应用一些样式，我们将使用`v-if`。

如果我们使用三元'if'，单元格将如下所示：

```js
      <td>{{ (person.isActive) ? 'Active' : 'Inactive' }}</td>
```

如果我们选择使用带有`v-else`的`v-if`选项，允许我们使用所需的 HTML，它将如下所示：

```js
      <td>
        <span class="positive" v-if="person.isActive">Active</span>
        <span class="negative" v-else>Inactive</span>
      </td>
```

这个活动元素是 Vue 组件非常理想的一个例子 - 我们将在第三章中介绍，*优化我们的应用程序并使用组件显示数据*。作为符合我们的 MVVM 方法论的替代方案，我们可以创建一个方法，该方法返回状态文本。这将整理我们的视图并将逻辑移动到我们的应用程序中：

```js
      <td>{{ activeStatus(person) }}</td>
```

我们的方法将执行与我们的视图相同的逻辑：

```js
activeStatus(person) {
  return (person.isActive) ? 'Active' : 'Inactive';
}
```

我们的表格现在将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00006.jpeg)

# 使用`v-html`创建链接

下一步是将电子邮件地址链接起来，以便用户在查看人员列表时可以点击。在这种情况下，我们需要在电子邮件地址之前添加`mailto:`来连接字符串。

第一反应是执行以下操作：

```js
      <a href="mailto:{{person.email}}">{{ person.email }}</a>
```

但是 Vue 不允许在属性内插值。相反，我们必须在`href`属性上使用`v-bind`指令。这将属性转换为 JavaScript 变量，因此任何原始文本必须用引号括起来，并与所需的变量连接起来：

```js
<a v-bind:href="'mailto:' + person.email">{{ person.email }}</a>
```

注意添加了`v-bind:`、单引号和连接符`+`。

# 格式化余额

在进行用户过滤之前，添加一个方法来正确格式化余额，在数据对象中定义一个货币符号，并确保小数点后有两个数字。我们可以从第一章中调整我们的方法，以实现这一点。我们的 Vue 应用程序现在应该是这样的：

```js
      const app = new Vue({
        el: '#app',

        data: {
          people: [...],
          currency: '$'
        },
        methods: {
          activeStatus(person) {
            return (person.isActive) ? 'Active' : 'Inactive';
          },
          formatBalance(balance) {
            return this.currency + balance.toFixed(2);
          }
        }
    });
```

我们可以在视图中利用这个新方法：

```js
      <td>{{ formatBalance(person.balance) }}</td>
```

# 格式化注册日期

数据中的注册日期字段对计算机友好，但对人类来说不太友好。创建一个名为`formatDate`的新方法，它接受一个参数，类似于之前的`formatBalance`方法。

如果您想要完全自定义日期的显示，有几个可用的库，比如`moment.js`，可以在任何日期和时间数据的输出上提供更大的灵活性。对于这个方法，我们将使用一个原生的 JavaScript 函数`toLocaleString()`：

```js
      formatDate(date) {
        let registered = new Date(date);
        return registered.toLocaleString('en-US');
      }
```

对于注册日期，我们将其传递给原生的`Date()`函数，以便 JavaScript 知道将字符串解释为日期。一旦存储在注册变量中，我们使用`toLocaleString()`函数将对象返回为字符串。该函数接受一个巨大的选项数组（如 MDN 中所述），用于自定义日期的输出。目前，我们将传递所希望显示的区域设置，并使用该位置的默认设置。现在我们可以在视图中利用我们的方法：

```js
      <td>{{ formatDate(person.registered) }}</td>
```

每个表格行现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00007.jpeg)

# 过滤我们的数据

在列出数据后，我们现在要构建过滤功能。这将允许用户选择要过滤的字段和输入查询的文本字段。Vue 应用程序将在用户输入时过滤行。为此，我们将绑定一些表单输入到`data`对象中的各个值，创建一个新的方法，并在表格行上使用一个新的指令`v-show`。

# 构建表单

首先，在视图中创建 HTML。创建一个`<select>`框，每个要过滤的字段都有一个`<option>`，一个用于查询的`<input>`，以及一对单选按钮 - 我们将使用这些按钮来过滤活动和非活动用户。确保每个`<option>`的 value 属性反映了用户数据中的键 - 这将减少所需的代码并使选择框的目的更明显。

我们过滤的数据不需要显示出来，但是在这里需要考虑用户体验。如果显示一个表格行，但没有你要过滤的数据，这是否有意义？

创建用于过滤的表单：

```js
      <form>
        <label for="fiterField">
          Field:
          <select id="filterField">
            <option value="">Disable filters</option>
            <option value="isActive">Active user</option>
            <option value="name">Name</option>
            <option value="email">Email</option>
            <option value="balance">Balance</option>
            <option value="registered">Date registered</option>
          </select>
        </label>

        <label for="filterQuery">
          Query:
          <input type="text" id="filterQuery">
        </label>

        <span>
          Active:
          <label for="userStateActive">
            Yes:
            <input type="radio" value="true" id="userStateActive"                   
          selected>
          </label>
          <label for="userStateInactive">
            No:
            <input type="radio" value="false" id="userStateInactive">
          </label>
        </span>
      </form>
```

该表单包括一个选择框，用于选择要过滤的字段，一个输入框，允许用户输入要过滤的查询，以及一对单选按钮，用于当我们希望按活动和非活动用户进行过滤时。想象中的用户流程是这样的：用户将选择他们希望按数据进行过滤的字段，并输入查询或选择单选按钮。当在选择框中选择`isActive`（活动用户）选项时，将显示单选按钮，并隐藏输入框。我们已经确保默认选择了第一个单选按钮以帮助用户。

过滤输入不需要包含在表单中才能工作；然而，即使在 JavaScript 应用程序中，保留语义化的 HTML 也是一个好的实践。

# 绑定输入

要将输入绑定到可以通过 Vue 实例访问的变量，需要在字段中添加一个 HTML 属性，并在`data`对象中添加一个相应的键。为每个字段在`data`对象中创建一个变量，以便我们可以将表单元素绑定到它们：

```js
      data: {
        people: [...],

        currency: '$',

        filterField: '',
 filterQuery: '',
 filterUserState: ''
      }
```

数据对象现在有三个额外的键：`filterField`，用于存储下拉框的值；`filterQuery`，用于存储输入到文本框中的数据的占位符；以及`filterUserState`，允许我们存储单选按钮的复选框。

现在有了可利用的数据键，我们可以将表单元素绑定到它们上。为每个表单字段应用一个`v-model=""`属性，其值为数据键。

以下是一个例子：

```js
      <input type="text" id="filterQuery" v-model="filterQuery">
```

确保两个单选按钮具有完全相同的`v-model=""`属性：这样它们才能更新相同的值。为了验证它是否起作用，现在可以输出数据变量并获取字段的值。

尝试输出`filterField`或`filterQuery`并更改字段。

```js
      {{ filterField }}
```

如果你输出`filterUserState`变量，你可能会注意到它似乎在工作，但实际上它没有得到期望的结果。变量的输出将是根据 value 属性设置的`true`和`false`。

仔细检查后，实际上这些值是字符串，而不是布尔值。布尔值是`true`或`false`、`1`或`0`，你可以轻松地进行比较，而字符串则需要对硬编码的字符串进行精确检查。可以通过输出`typeof`变量来验证它是什么类型：

```js
      {{ typeof filterUserState }}
```

可以通过将单选按钮的值绑定到`v-bind:value`属性来解决这个问题。该属性允许您指定 Vue 要解释的值，并且可以接受布尔值、字符串或对象值。现在，我们将传递`true`和`false`，就像我们已经在标准值属性中做的那样，但是 Vue 将知道将其解释为布尔值：

```js
      <span>
        Active:
        <label for="userStateActive">
          Yes:
          <input type="radio" v-bind:value="true" id="userStateActive"       
         v-model="filterUserState" selected>
        </label>
        <label for="userStateInactive">
          No:
          <input type="radio" v-bind:value="false"       
         id="userStateInactive" v-model="filterUserState">
        </label>
      </span>
```

下一步是根据这些过滤器显示和隐藏表格行。

# 显示和隐藏 Vue 内容

除了使用`v-if`来显示和隐藏内容外，还可以使用`v-show=""`指令。`v-show`与`v-if`非常相似；它们都会添加到 HTML 包装器中，并且都可以接受相同的参数，包括一个函数。

两者之间的区别是，`v-if`会改变标记，根据需要删除和添加 HTML 元素，而`v-show`无论如何都会渲染元素，通过内联 CSS 样式隐藏和显示元素。`v-if`更适合运行时渲染或不频繁的用户交互，因为它有可能重构整个页面。当大量元素快速进入和退出视图时，例如进行过滤时，`v-show`更可取！

当使用带有方法的`v-show`时，函数需要返回一个`true`或`false`。函数没有概念知道它在哪里被使用，所以我们需要传入当前正在渲染的人来计算是否应该显示它。

在你的 Vue 实例上创建一个名为`filterRow()`的方法，并在内部将其设置为`return true`：

```js
      filterRow(person) {
         return true;
      }
```

该函数接受一个参数，这个参数是我们从 HTML 中传递进来的人。在你的视图中，给`<tr>`元素添加`v-show`属性，值为`filterRow`，同时传入人物对象：

```js
      <table>
        <tr v-for="person in people" v-show="filterRow(person)">
          <td>{{ person.name }}</td>
          ...
```

作为一个简单的测试，将`isActive`的值返回给人物。这应该立即过滤掉任何不活跃的人，因为他们的值将返回`false`：

```js
      filterRow(person) {
        return person.isActive;
      }
```

# 过滤我们的内容

现在我们可以控制我们的人员行和视图中的一些过滤器控件，我们需要让我们的过滤器起作用。我们已经通过`isActive`键进行了过滤，所以单选按钮将是第一个被连接的。我们已经以布尔形式拥有了单选按钮的值和我们将进行过滤的键的值。为了使这个过滤器起作用，我们需要将`isActive`键与单选按钮的值进行比较。

+   如果`filterUserState`的值为`true`，则显示`isActive`为`true`的用户

+   然而，如果`filterUserState`的值为`false`，则只显示`isActive`值也为`false`的用户

这可以通过比较这两个变量来写成一行：

```js
      filterRow(person) {
        return (this.filterUserState === person.isActive);
      }
```

在页面加载时，不会显示任何用户，因为`filterUserState`键既不设置为`true`也不设置为`false`。点击其中一个单选按钮将显示相应的用户。

让过滤器只在下拉菜单中选择了活跃用户选项时起作用：

```js
      filterRow(person) {
        let result = true;

        if(this.filterField === 'isActive') {
          result = this.filterUserState === person.isActive;
        }

        return result;
      }
```

这段代码将一个变量设置为`true`作为默认值。然后我们可以立即返回这个变量，这样我们的行就会显示出来。然而，在返回之前，它会检查选择框的值，如果是期望的值，那么就会按照我们的单选按钮进行过滤。由于我们的选择框与`filterField`值绑定，就像`filterUserState`变量一样，它会在我们与应用程序交互时更新。尝试在选择框中选择“活跃用户”选项并更改单选按钮。

下一步是在未选择活跃用户选项时使用输入查询框。我们还希望我们的查询是一个模糊搜索 - 例如，匹配包含搜索查询的单词，而不是完全匹配。我们还希望它是不区分大小写的：

```js
      filterRow(person) {
        let result = true;

        if(this.filterField) {

          if(this.filterField === 'isActive') {
            result = this.filterUserState === person.isActive;
          } else {
 let query = this.filterQuery.toLowerCase(),
 field =  person[this.filterField].toString().toLowerCase(); result = field.includes(query);
 }

        }

        return result;
      }
```

为了使这个方法起作用，我们需要添加一些东西。第一步是检查我们的选择字段是否有一个值来开始过滤。由于我们的选择字段中的第一个选项的`value=""`，这等于`false`。如果是这种情况，该方法返回默认值`true`。

如果它有一个值，它将进入我们原来的`if`语句。这将检查特定值是否与`isActive`匹配 - 如果匹配，则运行我们之前编写的代码。如果不匹配，则开始我们的备用过滤。建立一个名为`query`的新变量，它获取输入的值并转换为小写。

第二个变量是我们要进行过滤的数据。这使用选择框的值，即人员的字段键，提取要过滤的值。该值被转换为字符串（在日期或余额的情况下），转换为小写并存储为`field`变量。最后，我们使用`includes`函数来检查字段是否包含输入的查询。如果是，则返回`true`并显示行；否则，隐藏行。

我们可以解决的下一个问题是使用数字进行过滤时。对于用户来说，输入他们想要的用户的确切余额并不直观 - 更自然的搜索方式是找到余额低于或高于某个特定金额的用户，例如，`< 2000`。

这样做的第一步是只在`balance`字段上应用这种类型的过滤。我们可以有两种方法来处理这个问题 - 我们可以检查字段名是否为`balance`，类似于我们检查`isActive`字段的方式，或者我们可以检查我们正在过滤的数据的类型。

检查字段名更简单。我们可以在我们的方法中使用`else if()`，或者甚至迁移到`switch`语句以便更容易阅读和扩展。然而，检查字段类型的替代方法更具可扩展性。这意味着我们可以通过添加更多的数字字段来扩展我们的数据集，而无需扩展或更改我们的代码。然而，这也意味着我们的代码中将有进一步的`if`语句。

我们首先要做的是修改我们的存储方法，因为我们不想将字段或查询转换为小写：

```js
      if(this.filterField === 'isActive') {
        result = this.filterUserState === person.isActive;
      } else {

        let query = this.filterQuery,
 field = person[this.filterField]; 
 }
```

下一步是确定字段变量中的数据类型。这可以通过再次使用`typeof`运算符来确定。可以在`if`语句中使用它来检查字段的类型是否为数字：

```js
      if(this.filterField === 'isActive') {
        result = this.filterUserState === person.isActive;
      } else {

        let query = this.filterQuery,
            field = person[this.filterField];

        if(typeof field === 'number') {
          // Is a number
 } else {
 // Is not a number
          field = field.toLowerCase();
          result = field.includes(query.toLowerCase());
 }

      }
```

一旦我们的检查完成，我们可以回到我们原来的查询代码。如果选择选项不是`isActive`，并且我们正在过滤的数据不是数字，它将使用这个代码。如果是这种情况，它将将字段转换为小写，并查看在转换为小写之前在查询框中输入的内容是否包含在内。

下一阶段是实际比较我们的数字数据与查询框中的内容。为此，我们将使用原生的 JavaScript `eval`函数。

`eval`函数可能是一个潜在的危险函数，在没有一些严格的输入消毒检查的情况下不应在生产代码中使用，而且它的性能比较低。它会将所有内容作为原生 JavaScript 运行，因此可能会被滥用。然而，由于我们将其用于一个虚拟应用程序，重点是 Vue 本身而不是创建一个完全安全的 Web 应用程序，在这种情况下是可以接受的。您可以在 24 种方式中了解更多关于`eval`的信息：

```js
      if(this.filterField === 'isActive') {
       result = this.filterUserState === person.isActive;
      } else {

        let query = this.filterQuery,
            field = person[this.filterField];

        if(typeof field === 'number') {
          result = eval(field + query);
        } else {
          field = field.toLowerCase();
          result = field.includes(query.toLowerCase());
        }

      }
```

这将字段和查询都传递给`eval()`函数，并将结果（`true`或`false`）传递给我们的`result`变量，以确定行的可见性。`eval`函数会直接评估表达式，并确定其是否为`true`或`false`。以下是一个示例：

```js
      eval(500 > 300); // true
      eval(500 < 400); // false
      eval(500 - 500); // false
```

在这个例子中，数字`500`是我们的字段，或者在这个具体的例子中是`balance`。任何在此之后的内容都是由用户输入的。您的过滤代码现在已经准备就绪。尝试从下拉菜单中选择余额，并过滤出余额大于`2000`的用户。

在我们继续之前，我们需要添加一些错误检查。如果你打开了 JavaScript 控制台，你可能会注意到在输入第一个大于或小于符号时出现了一个错误。这是因为`eval`函数无法评估`X >`（其中`X`是余额）。你可能也想输入`*$2000*`与货币一起使用，并意识到这不起作用。这是因为货币是在渲染视图时应用的，而我们是在渲染之前过滤数据。

为了解决这两个错误，我们必须删除查询中输入的任何货币符号，并在依赖它返回结果之前测试我们的`eval`函数。使用原生的 JavaScript `replace()`函数来删除货币符号。如果它发生变化，使用应用程序中存储的货币符号，而不是硬编码当前使用的货币符号。

```js
      if(typeof field == 'number') {
        query = query.replace(this.currency, '');
        result = eval(field + query);
      }
```

现在我们需要测试`eval`函数，以便它在每次按键时不会抛出错误。为此，我们使用`try...catch`语句：

```js
      if(typeof field == 'number') {
        query = query.replace(this.currency, '');

        try {
          result = eval(field + query);
 } catch(e) {}
      }
```

由于我们不希望在输入错误时输出任何内容，所以可以将`catch`语句留空。我们可以将`field.includes(query)`语句放在这里，这样它就会回退到默认功能。我们的完整的`filterRow()`方法现在看起来是这样的：

```js
      filterRow(person) {
        let result = true;

        if(this.filterField) {

          if(this.filterField === 'isActive') {

            result = this.filterUserState === person.isActive;

          } else {

            let query = this.filterQuery,
          field = person[this.filterField];

            if(typeof field === 'number') {

              query = query.replace(this.currency, '');        
              try {
                result = eval(field + query);
              } catch (e) {}

            } else {

              field = field.toLowerCase();
              result = field.includes(query.toLowerCase());

            }
          }
        }

        return result;

      }
```

# 过滤我们的过滤器

现在我们已经完成了过滤，我们只需要在下拉菜单中选择`isActive`选项时才显示单选按钮。根据我们所学的知识，这应该相对简单。

创建一个新的方法，检查选择框的值，并在我们的下拉菜单中选择“Active User”时返回`true`：

```js
      isActiveFilterSelected() {
        return (this.filterField === 'isActive');
      }
```

现在我们可以在查询框上使用`v-show`，并在查询框上反转效果：

```js
      <label for="filterQuery" v-show="!isActiveFilterSelected()">
        Query:
        <input type="text" id="filterQuery" v-model="filterQuery">
      </label>
      <span v-show="isActiveFilterSelected()">
        Active:
        <label for="userStateActive">
          Yes:
          <input type="radio" v-bind:value="true" id="userStateActive"           
         v-model="filterUserState">
        </label>
        <label for="userStateInactive">
          No:
     <input type="radio" v-bind:value="false" id="userStateInactive" v-
      model="filterUserState">
        </label>
      </span>
```

请注意输入字段上方法调用之前的感叹号。这表示否定，并有效地颠倒了函数的结果，例如`not true`等同于`false`，反之亦然。

为了改进用户体验，我们还可以在显示任何输入之前检查过滤是否处于活动状态。这可以通过在我们的`v-show`属性中包含一个次要检查来实现：

```js
      <label for="filterQuery" v-show="this.filterField &&        
      !isActiveFilterSelected()">
        Query:
        <input type="text" id="filterQuery" v-model="filterQuery">
      </label>
```

现在，这将检查`filterField`是否有值，并且选择框是否未设置为`isActive`。确保将此添加到单选按钮中。

进一步改进用户体验的方法是，确保在选择`isActive`选项时，所有用户都不会消失。这是因为默认设置为字符串，与字段的`true`或`false`值不匹配。在对该字段进行过滤之前，我们应该检查`filterUserState`变量是否为`true`或`false`，即布尔值。我们可以再次使用`typeof`来实现这一点：

```js
      if(this.filterField === 'isActive') {
        result = (typeof this.filterUserState === 'boolean') ?                  
        (this.filterUserState === person.isActive) : true;
      }
```

我们使用三元运算符来检查要过滤的结果是否为布尔值。如果是，那么就像我们之前一样进行过滤；如果不是，则只显示该行。

# 更改 CSS 类

与任何 HTML 属性一样，Vue 能够操作 CSS 类。与 Vue 中的其他所有内容一样，可以通过多种方式实现，从对象本身的属性到利用方法。我们将首先添加一个类，如果用户处于活动状态。

绑定 CSS 类与其他属性类似。该值接受一个对象，可以在视图中计算逻辑或抽象到我们的 Vue 实例中。这完全取决于操作的复杂性。

首先，如果用户处于活动状态，让我们给包含`isActive`变量的单元格添加一个类：

```js
      <td v-bind:class="{ active: person.isActive }">
        {{ activeStatus(person) }}
      </td>
```

类 HTML 属性首先由`v-bind:`前缀，以让 Vue 知道它需要处理该属性。然后，值是一个对象，CSS 类作为键，条件作为值。此代码在表格单元格上切换`active`类，如果`person.isActive`变量等于`true`。如果我们想在用户不活动时添加一个`inactive`类，我们可以将其添加到对象中：

```js
      <td v-bind:class="{ active: person.isActive, inactive: 
      !person.isActive }">
        {{ activeStatus(person) }}
      </td>
```

这里我们再次使用感叹号来反转状态。如果您运行此应用程序，您应该会发现 CSS 类按预期应用。

如果我们只是根据一个条件应用两个类，可以在类属性内部使用三元`if`语句：

```js
      <td v-bind:class="person.isActive ? 'active' : 'inactive'">
        {{ activeStatus(person) }}
      </td>
```

请注意类名周围的单引号。然而，逻辑又开始渗入我们的视图中，如果我们希望在其他地方也使用这个类，它就不太可扩展了。

在我们的 Vue 实例上创建一个名为`activeClass`的新方法，并将逻辑抽象到其中 - 不要忘记传递 person 对象：

```js
      activeClass(person) {
        return person.isActive ? 'active' : 'inactive';
      }
```

现在我们可以在视图中调用该方法：

```js
      <td v-bind:class="activeClass(person)">
        {{ activeStatus(person) }}
      </td>
```

我知道这是一个相当简单的执行过程；让我们尝试一个稍微复杂一点的。我们想根据余额单元格的值添加一个条件类。如果他们的余额低于$2000，我们将添加一个`error`类。如果在$2000 和$3000 之间，将应用一个`warning`类，如果超过$3000，将添加一个`success`类。

除了`error`、`warning`和`success`类之外，如果余额超过$500，还会添加一个`increasing`类。例如，$2,600 的余额将同时获得`warning`和`increasing`类，而$2,400 只会获得`warning`类。

由于这里包含了几个逻辑部分，我们将在实例中创建一个方法。创建一个`balanceClass`方法，并将其绑定到包含余额的单元格的类 HTML 属性上。首先，我们将添加`error`、`warning`和`success`类。

```js
      <td v-bind:class="balanceClass(person)">
        {{ formatBalance(person.balance) }}
      </td>
```

在该方法中，我们需要访问传入的 person 的`balance`属性，并返回我们希望添加的类的名称。现在，我们将返回一个固定的结果来验证它是否工作：

```js
      balanceClass(person) {
        return 'warning';
      }
```

现在我们需要评估我们的余额。由于它已经是一个数字，与我们的条件进行比较不需要进行任何转换：

```js
      balanceClass(person) {
        let balanceLevel = 'success';

        if(person.balance < 2000) {
          balanceLevel = 'error';
        } else if (person.balance < 3000) {
          balanceLevel = 'warning';
        }

        return balanceLevel;
      }
```

在上述方法中，类输出默认设置为`success`，因为我们只需要在小于`3000`时更改输出。第一个`if`检查余额是否低于我们的第一个阈值-如果是，则将输出设置为`error`。如果不是，则尝试第二个条件，即检查余额是否低于`3000`。如果成功，则应用的类变为`warning`。最后，它输出所选的类，直接应用于元素。

现在我们需要考虑如何使用`increasing`类。为了使其与现有的`balanceLevel`类一起输出，我们需要将输出从单个变量转换为数组。为了验证这是否有效，将额外的类硬编码到输出中：

```js
      balanceClass(person) {
        let balanceLevel = 'success';
        if(person.balance < 2000) {
          balanceLevel = 'error';
        } else if (person.balance < 3000) {
          balanceLevel = 'warning';
        }
        return [balanceLevel, 'increasing'];
      }
```

这将向元素添加两个类。将字符串转换为变量，并默认设置为`false`。Vue 不会为传入数组的`false`值输出任何内容。

为了确定我们是否需要增加的类，我们需要对余额进行一些计算。因为我们希望如果余额超过 500，无论在哪个范围内，都需要增加的类，所以我们需要四舍五入并进行比较：

```js
      let increasing = false,
          balance = person.balance / 1000;

      if(Math.round(balance) == Math.ceil(balance)) {
        increasing = 'increasing';
      }
```

最初，我们将`increasing`变量默认设置为`false`。我们还存储了余额除以`1000`的版本。这意味着我们的余额变成了 2.45643，而不是 2456.42。从那里，我们将通过 JavaScript 将数字四舍五入后（例如 2.5 变成 3，而 2.4 变成 2）与强制四舍五入后的数字（例如 2.1 变成 3，以及 2.9）进行比较。

如果输出的数字相同，则将`increasing`变量设置为我们想要设置的类的字符串。然后，我们可以将此变量与`balanceLevel`变量一起作为数组传递出去。完整的方法现在看起来如下：

```js
      balanceClass(person) {
        let balanceLevel = 'success';

        if(person.balance < 2000) {
          balanceLevel = 'error';
        } else if (person.balance < 3000) {
          balanceLevel = 'warning';
        } 

        let increasing = false,
            balance = person.balance / 1000;

        if(Math.round(balance) == Math.ceil(balance)) {
          increasing = 'increasing';
        }

        return [balanceLevel, increasing];
      }
```

# 筛选和自定义类

现在我们有了一个完整的用户列表/注册表，可以根据选定的字段进行筛选，并根据条件设置自定义 CSS 类。回顾一下，我们的视图现在是这样的：

```js
      <div id="app">
        <form>
          <label for="fiterField">
            Field:
            <select id="filterField" v-model="filterField">
              <option value="">Disable filters</option>
              <option value="isActive">Active user</option>
              <option value="name">Name</option>
              <option value="email">Email</option>
              <option value="balance">Balance</option>
              <option value="registered">Date registered</option>
            </select>
          </label>

          <label for="filterQuery" v-show="this.filterField &&                  
          !isActiveFilterSelected()">
            Query:
            <input type="text" id="filterQuery" v-model="filterQuery">
          </label>

          <span v-show="isActiveFilterSelected()">
         Active:
        <label for="userStateActive">
        Yes:
        <input type="radio" v-bind:value="true" id="userStateActive" v-
         model="filterUserState">
      </label>
      <label for="userStateInactive">
        No:
        <input type="radio" v-bind:value="false" id="userStateInactive"          
      v-model="filterUserState">
      </label>
          </span>
        </form>

        <table>
          <tr v-for="person in people" v-show="filterRow(person)">
            <td>{{ person.name }}</td>
            <td>
         <a v-bind:href="'mailto:' + person.email">{{ person.email }}            
           </a>
            </td>
            <td v-bind:class="balanceClass(person)">
              {{ formatBalance(person.balance) }}
            </td>
            <td>{{ formatDate(person.registered) }}</td>
            <td v-bind:class="activeClass(person)">
              {{ activeStatus(person) }}
            </td>
          </tr>
        </table>

      </div>
```

我们 Vue 应用的 JavaScript 应该如下所示：

```js
      const app = new Vue({
        el: '#app',

        data: {
          people: [...],

          currency: '$',

          filterField: '',
          filterQuery: '',
          filterUserState: ''
        },
        methods: {
          activeStatus(person) {
            return (person.isActive) ? 'Active' : 'Inactive';
          },

          activeClass(person) {
            return person.isActive ? 'active' : 'inactive';
          },
          balanceClass(person) {
            let balanceLevel = 'success';

            if(person.balance < 2000) {
              balanceLevel = 'error';
            } else if (person.balance < 3000) {
              balanceLevel = 'warning';
            }

            let increasing = false,
          balance = person.balance / 1000;

            if(Math.round(balance) == Math.ceil(balance)) {
              increasing = 'increasing';
            }

            return [balanceLevel, increasing];
          },

          formatBalance(balance) {
            return this.currency + balance.toFixed(2);
          },
          formatDate(date) {
            let registered = new Date(date);
            return registered.toLocaleString('en-US');
          },

          filterRow(person) {
            let result = true;
            if(this.filterField) {

              if(this.filterField === 'isActive') {

              result = (typeof this.filterUserState === 'boolean') ?       
              (this.filterUserState === person.isActive) : true;
             } else {

          let query = this.filterQuery,
              field = person[this.filterField];

          if(typeof field === 'number') {
            query.replace(this.currency, '');
            try {
              result = eval(field + query);
            } catch(e) {}
          } else {
            field = field.toLowerCase();
            result = field.includes(query.toLowerCase());
            }
          }
        }

            return result;
          },

          isActiveFilterSelected() {
            return (this.filterField === 'isActive');
          }
        }
      });
```

通过少量的 CSS，我们的人员筛选应用现在看起来如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00008.jpeg)

# 总结

在本章中，我们学习了 Vue 的 HTML 声明，根据需要有条件地渲染我们的 HTML 并显示替代内容。我们还实践了关于方法的知识。最后，我们为表格构建了一个过滤组件，允许我们显示活动和非活动用户，查找具有特定名称和电子邮件的用户，并根据余额过滤行。

现在我们的应用程序已经达到了一个很好的点，这是一个很好的机会来检查我们的代码，看看是否可以进行任何优化。通过优化，我指的是减少重复，尽可能简化代码，并将逻辑抽象成更小、可读和可重用的部分。

在第三章中，我们将优化我们的代码，并将 Vue 组件作为将逻辑分离到单独的段落和部分的一种方式。


# 第三章：优化您的应用程序并使用组件显示数据

在第二章中，*显示、循环、搜索和过滤数据*，我们让 Vue 应用程序显示了我们的人员目录，我们可以利用这个机会来优化我们的代码并将其分离成组件。这使得代码更易于管理，更容易理解，并且使其他开发人员能够更容易地了解数据流程（或者在几个月后再次查看代码时，您自己也能更容易理解）。

本章将涵盖以下内容：

+   通过减少重复和逻辑组织我们的代码来优化我们的 Vue.js 代码

+   如何创建 Vue 组件并在 Vue 中使用它们

+   如何在组件中使用 props 和 slots

+   利用事件在组件之间传递数据

# 优化代码

当我们在解决问题时编写代码时，有一个时刻你需要退后一步，审视你的代码以进行优化。这可能包括减少变量和方法的数量，或者创建方法来减少重复的功能。我们当前的 Vue 应用程序如下所示：

```js
      const app = new Vue({
        el: '#app',
        data: {
          people: [...],
          currency: '$',
          filterField: '',
          filterQuery: '',
          filterUserState: ''
        },
        methods: {
          activeStatus(person) {
            return (person.isActive) ? 'Active' : 
             'Inactive';
          },
          activeClass(person) {
            return person.isActive ? 'active' : 
            'inactive';
          },
          balanceClass(person) {
            let balanceLevel = 'success';
            if(person.balance < 2000) {
              balanceLevel = 'error';
            } else if (person.balance < 3000) {
              balanceLevel = 'warning';
            }
            let increasing = false,
            balance = person.balance / 1000;
            if(Math.round(balance) == 
             Math.ceil(balance)) {
              increasing = 'increasing';
            }
            return [balanceLevel, increasing];
          },
          formatBalance(balance) {
            return this.currency + balance.toFixed(2);
          },
          formatDate(date) {
            let registered = new Date(date);
            return registered.toLocaleString('en-US');
          },
          filterRow(person) {
            let result = true;
            if(this.filterField) {
              if(this.filterField === 'isActive') {
                result = (typeof this.filterUserState 
                 === 'boolean') ? (this.filterUserState 
                 === person.isActive) : true;
              } else {
                let query = this.filterQuery,
                    field = person[this.filterField];
                if(typeof field === 'number') {
                  query.replace(this.currency, '');
                  try {
                    result = eval(field + query);
                  } catch(e) {}
                } else {
                  field = field.toLowerCase();
                  result =        
            field.includes(query.toLowerCase());
                }
              }
            }
            return result;
          },
          isActiveFilterSelected() {
            return (this.filterField === 'isActive');
          }
        }
      });
```

查看上述代码，我们可以进行一些改进。这些包括：

+   减少过滤变量的数量并进行逻辑分组

+   合并格式化函数

+   减少硬编码的变量和属性的数量

+   将方法重新排序为更合理的顺序

我们将逐个讨论这些要点，以便我们有一个干净的代码库来构建组件。

# 减少过滤变量的数量并进行逻辑分组

当前的过滤使用了三个变量`filterField`，`filterQuery`和`filterUserState`。目前唯一将这些变量联系在一起的是名称，而不是它们自己的对象以系统地将它们链接在一起。这样做可以避免任何关于它们是否与同一组件相关或仅仅是巧合的歧义。在数据对象中，创建一个名为`filter`的新对象，并将每个变量移动到其中：

```js
      data: {
        people: [..],
        currency: '$',
        filter: {
          field: '',
          query: '',
          userState: '',
        }
      }
```

要访问数据，请将`filterField`的任何引用更新为`this.filter.field`。注意额外的点，表示它是过滤器对象的键。不要忘记更新`filterQuery`和`filterUserState`的引用。例如，`isActiveFilterSelected`方法将变为：

```js
      isActiveFilterSelected() {
        return (this.filter.field === 'isActive');
      }
```

您还需要在视图中更新`v-model`和`v-show`属性-有五个不同变量的出现。

在更新过滤变量的同时，我们可以利用这个机会删除一个变量。根据我们当前的过滤，我们一次只能有一个过滤器处于活动状态。这意味着 `query` 和 `userState` 变量在任何时候只被使用一次，这给我们合并这两个变量的机会。为了做到这一点，我们需要更新视图和应用程序代码来适应这个变化。

从您的过滤数据对象中删除 `userState` 变量，并将视图中的任何 `filter.userState` 出现更新为 `filter.query`。现在，在您的 Vue JavaScript 代码中进行*查找和替换*，将 `filter.userState` 替换为 `filter.query`。

在浏览器中查看您的应用程序时，它将首先显示正常，可以通过字段对用户进行筛选。然而，如果您按状态筛选，然后切换到任何其他字段，查询字段将不会显示。这是因为使用单选按钮将值设置为布尔值，当尝试将其转换为小写以用于查询字段时，无法成功。为了解决这个问题，我们可以使用原生的 JavaScript `String()` 函数将 `filter.query` 变量中的任何值转换为字符串。这确保我们的过滤函数可以处理任何过滤输入：

```js
      if(this.filter.field === 'isActive') {
        result = (typeof this.filter.query ===        
       'boolean') ? (this.filter.query ===             
        person.isActive) : true;
         } else {
        let query = String(this.filter.query),
            field = person[this.filter.field];
           if(typeof field === 'number') {
           query.replace(this.currency, '');
          try {
            result = eval(field + query);
          } catch(e) {}
        } else {
          field = field.toLowerCase();
          result = field.includes(query.toLowerCase());
        }
```

现在将这个添加到我们的代码中，确保我们的查询数据可以使用任何值。现在创建的问题是当用户在字段之间切换进行筛选时。如果您选择了活动用户并选择了一个单选按钮，过滤将按预期工作，然而，如果您现在切换到电子邮件或其他字段，输入框将预填充为 `true` 或 `false`。这会立即进行过滤，并且通常不会返回任何结果。当在两个文本过滤字段之间切换时，也会发生这种情况，这不是期望的效果。

我们希望的是，无论是单选按钮还是输入框，每当选择框更新时，过滤查询都应该被清除。选择一个新字段应该重置过滤查询，这样可以开始一个新的搜索。

这是通过删除选择框与 `filter.field` 变量之间的链接，并创建我们自己的方法来处理更新来完成的。然后，在选择框更改时触发该方法。该方法将清除 `query` 变量并将 `field` 变量设置为选择框的值。

在选择框上删除 `v-model` 属性，并添加一个新的 `v-on:change` 属性。我们将传递一个方法名给它，每当选择框更新时都会触发该方法。

`v-on`是一个我们之前没有遇到过的新的 Vue 绑定。它允许您将元素的操作绑定到 Vue 方法。例如，`v-on:click`是最常用的一个 - 它允许您将`click`函数绑定到元素上。我们将在本书的下一节中详细介绍这个。

在 v-bind 可以简写为冒号的情况下，v-on 可以缩写为@符号，允许您使用@click=""，例如：

```js
      <select v-on:change="changeFilter($event)"     
       id="filterField">
        <option value="">Disable filters</option>
        <option value="isActive">Active user</option>
        <option value="name">Name</option>
        <option value="email">Email</option>
        <option value="balance">Balance</option>
        <option value="registered">Date 
         registered</option>
      </select>
```

该属性在每次更新时触发`changeFilter`方法，并传递`$event`更改的数据。这个默认的 Vue 事件对象包含了很多我们可以利用的信息，但我们关注的是`target.value`数据。

在您的 Vue 实例中创建一个接受事件参数并更新`query`和`field`变量的新方法。`query`变量需要被清除，所以将其设置为空字符串，而`field`变量可以设置为选择框的值：

```js
      changeFilter(event) {
        this.filter.query = '';
        this.filter.field = event.target.value;
      }
```

现在查看您的应用程序应该清除任何过滤查询，同时仍然按预期运行。

# 组合格式函数

我们下一个优化将是将`formatBalance`和`formatDate`方法合并到我们的 Vue 实例中。这将允许我们扩展我们的格式函数，而不会用几个具有相似功能的方法膨胀代码。有两种方法可以处理格式样式函数 - 我们可以自动检测输入的格式，或者将所需的格式选项作为第二个选项传递。两种方法都有其优缺点，但我们将逐步介绍两种方法。

# 自动检测格式化

当传递给函数时，自动检测变量类型对于代码更清晰很有帮助。在您的视图中，您可以调用该函数并传递您希望格式化的一个参数。例如：

```js
      {{ format(person.balance) }}
```

然后，该方法将包含一个`switch`语句，并根据`typeof`值对变量进行格式化。`switch`语句可以评估单个表达式，然后根据输出执行不同的代码。`switch`语句非常强大，因为它允许构建子句 - 根据结果利用几个不同的代码片段。有关`switch`语句的更多信息可以在 MDN 上阅读。

如果您正在比较相同的表达式，那么`switch`语句是`if`语句的一个很好的替代方案。您还可以为一个代码块设置多个情况，甚至在之前的情况都不满足时包含一个默认情况。例如，我们使用的一个示例是 format 方法可能如下所示：

```js
      format(variable) {
        switch (typeof variable) {
          case 'string':
          // Formatting if the variable is a string
          break;
          case 'number':
          // Number formatting
          break;
          default:
          // Default formatting
          break;
        }
      }
```

需要注意的重要事项是`break;`行。这些行结束了每个`switch` case。如果省略了`break`，代码将继续执行下一个 case，有时这是期望的效果。

自动检测变量类型和格式化是简化代码的好方法。然而，对于我们的应用程序来说，这不是一个合适的解决方案，因为我们正在格式化日期，而在输出`typeof`结果时，日期会被转换为字符串，并且无法与我们可能希望格式化的其他字符串区分开来。

# 传入第二个变量

与前面的自动检测相反，我们可以将第二个变量传入`format`函数中。这样做可以使我们在需要格式化其他字段时具有更大的灵活性和可扩展性。对于第二个变量，我们可以传入一个固定的字符串，与我们`switch`语句中的预选列表匹配，或者我们可以直接传入字段本身。在视图中使用固定字符串的示例如下：

```js
      {{ format(person.balance, 'currency') }}
```

如果我们有几个不同的字段都需要像`balance`一样进行格式化，那么这种方法将非常完美，但是在使用`balance`键和`currency`格式时似乎存在一些重复。

为了妥协，我们将把`person`对象作为第一个参数传入，这样我们就可以访问所有的数据，将字段的名称作为第二个参数传入。然后我们将使用这个参数来确定所需的格式化方法，并返回特定的数据。

# 创建方法

在您的视图中，用一个格式化函数替换`formatDate`和`formatBalance`函数，将`person`变量作为第一个参数传入，将字段用引号括起来作为第二个参数：

```js
      <td v-bind:class="balanceClass(person)">
        {{ format(person, 'balance') }}
      </td>
      <td>
        {{ format(person, 'registered') }}
      </td>
```

在您的 Vue 实例中创建一个新的格式化方法，接受两个参数：`person`和`key`。作为第一步，使用`person`对象和`key`变量检索字段：

```js
      format(person, key) {
        let field = person[key],
            output = field.toString().trim();      
        return output;
      }
```

我们还在函数内部创建了一个名为`output`的第二个变量，这将在函数结束时返回，并默认设置为`field`。这样可以确保如果我们的格式化键与传入的键不匹配，将返回未经处理的字段数据。但是，我们会将字段转换为字符串并删除变量中的任何空格。现在运行应用程序将返回没有任何格式化的字段。

添加一个`switch`语句，将表达式设置为`key`。在`switch`语句中添加两个 case，一个是`balance`，另一个是`registered`。由于我们不希望在输入不匹配 case 时发生任何操作，所以我们不需要有一个`default`语句：

```js
      format(person, key) {
        let field = person[key],
            output = field.toString().trim();

        switch(key) {
 case 'balance':
 break;
 case 'registered':
 break;
 }
        return output;
      }
```

现在我们只需要将原始格式化函数中的代码复制到各个 case 中：

```js
      format(person, key) {
        let field = person[key],
            output = field.toString().trim();

        switch(key) {
          case 'balance':
            output = this.currency + field.toFixed(2);
            break;

          case 'registered':
           let registered = new Date(field);
 output = registered.toLocaleString('en-US');
          break;
        }
        return output;
      }
```

这个格式化函数现在更加灵活。如果我们需要处理更多字段（例如处理`name`字段），我们可以添加更多的`switch` case，或者我们可以在现有代码中添加新的 case。例如，如果我们的数据包含一个字段，详细说明用户`停用`帐户的日期，我们可以轻松地以与注册日期相同的格式显示它：

```js
      case 'registered':
 case 'deactivated':
        let registered = new Date(field);
        output = registered.toLocaleString('en-US');
        break;
```

# 减少硬编码的变量和属性的数量，减少冗余

当查看 Vue JavaScript 时，很快就会发现可以通过引入全局变量并在函数中设置更多的局部变量来进行优化，以使其更易读。我们还可以使用现有功能来避免重复。

第一个优化是在我们的`filterRow()`方法中，我们检查`filter.field`是否处于活动状态。这也在我们用于显示和隐藏单选按钮的`isActiveFilterSelected`方法中重复出现。更新`if`语句以使用此方法，代码如下：

```js
      ...

    if(this.filter.field === 'isActive') {
    result = (typeof this.filter.query === 'boolean') ?       
    (this.filter.query === person.isActive) : true;
      } else {

      ...
```

上述代码已删除`this.filter.field === 'isActive'`代码，并替换为`isActiveFilterSelected()`方法。现在它应该是这样的：

```js
      ...

    if(this.isActiveFilterSelected()) {
    result = (typeof this.filter.query === 'boolean') ?     
     (this.filter.query === person.isActive) : true;
     } else {

      ...
```

当我们在`filterRow`方法中时，我们可以通过在方法开始时将`query`和`field`存储为变量来减少代码。`result`也不是正确的关键字，所以让我们将其更改为`visible`。首先，在开头创建和存储我们的两个变量，并将`result`重命名为`visible`：

```js
      filterRow(person) {
        let visible = true,
 field = this.filter.field,
 query = this.filter.query;      ...
```

替换该函数中所有变量的所有实例，例如，方法的第一部分将如下所示：

```js
      if(field) {
          if(this.isActiveFilterSelected()) {
            visible = (typeof query === 'boolean') ?   
            (query === person.isActive) : true;
          } else {

          query = String(query),
          field = person[field];
```

保存文件并在浏览器中打开应用程序，以确保优化不会破坏功能。

最后一步是将方法重新排序，使其对您有意义。可以随意添加注释来区分不同类型的方法，例如与 CSS 类或过滤相关的方法。我还删除了`activeStatus`方法，因为我们可以利用我们的`format`方法来*格式化*此字段的输出。优化后，JavaScript 代码现在如下所示：

```js
      const app = new Vue({
        el: '#app',
         data: {
          people: [...],
          currency: '$',
          filter: {
            field: '',
            query: ''
          }
        },
        methods: {
          isActiveFilterSelected() {
            return (this.filter.field === 'isActive');
          },
          /**
           * CSS Classes
           */
          activeClass(person) {
             return person.isActive ? 'active' : 
             'inactive';
          },
           balanceClass(person) {
            let balanceLevel = 'success';
            if(person.balance < 2000) {
              balanceLevel = 'error';
            } else if (person.balance < 3000) {
              balanceLevel = 'warning';
            }
                let increasing = false,
                balance = person.balance / 1000;
            if(Math.round(balance) == 
             Math.ceil(balance)) {
              increasing = 'increasing';
            }
            return [balanceLevel, increasing];
          },
          /**
           * Display
           */
          format(person, key) {
            let field = person[key],
            output = field.toString().trim();
            switch(key) {
              case 'balance':
                output = this.currency + 
              field.toFixed(2);
                break;
              case 'registered':
          let registered = new Date(field);
          output = registered.toLocaleString('en-US');
          break;  
        case 'isActive':
          output = (person.isActive) ? 'Active' : 
          'Inactive';
            }
        return output;
          },  
          /**
           * Filtering
           */
          changeFilter(event) {
            this.filter.query = '';
            this.filter.field = event.target.value;
          },
          filterRow(person) {
            let visible = true,
                field = this.filter.field,
                query = this.filter.query; 
            if(field) {  
              if(this.isActiveFilterSelected()) {
                visible = (typeof query === 'boolean') ?
               (query === person.isActive) : true;
              } else { 
                query = String(query),
                field = person[field];
                if(typeof field === 'number') {
                  query.replace(this.currency, '');  
                  try {
                    visible = eval(field + query);
                  } catch(e) {}  
                } else {  
                  field = field.toLowerCase();
                  visible = 
                  field.includes(query.toLowerCase());         
                }
              }
            }
            return visible;
          }
        }
      });
```

# 创建 Vue 组件

现在我们对代码的清理更有信心，我们可以继续为应用程序的各个部分创建 Vue 组件。暂时放下您的代码，打开一个新文档，同时熟悉组件。

Vue 组件非常强大，是任何 Vue 应用程序的重要组成部分。它们允许您创建可重用代码的包，包括它们自己的数据、方法和计算值。

对于我们的应用程序，我们有机会创建两个组件：一个用于每个人，一个用于我们应用程序的过滤部分。我鼓励您在可能的情况下始终考虑将应用程序拆分为组件，这有助于将代码分组为相关的功能。

组件看起来像是小型的 Vue 实例，因为每个组件都有自己的数据、方法和计算属性对象，还有一些特定于组件的选项，我们很快就会介绍。当涉及到创建具有不同页面和部分的应用程序时，组件也非常有用，这将在第八章《介绍 Vue-Router 和加载基于 URL 的组件》中介绍。

当注册一个组件时，您需要创建一个自定义的 HTML 元素来在视图中使用，例如：

```js
      <my-component></my-component>
```

在命名组件时，可以使用短横线命名法（连字符）、帕斯卡命名法（没有标点符号，但每个单词首字母大写）或驼峰命名法（类似于帕斯卡命名法，但第一个单词首字母小写）。Vue 组件不受 W3C Web 组件/自定义元素规则的限制或关联，但按照使用短横线命名法的惯例是一个好的做法。

# 创建和初始化您的组件

Vue 组件使用`Vue.component(tagName, options)`语法进行注册。每个组件必须有一个关联的标签名。`Vue.component`的注册**必须**在初始化 Vue 实例之前发生。至少，每个组件应该有一个`template`属性 - 表示在使用组件时应该显示什么。模板必须始终有一个包装元素；这样自定义的 HTML 标签才能被父容器替换。

例如，你不能将以下内容作为你的模板：

```js
      <div>Hello</div><div>Goodbye</div>
```

如果你传递了这种格式的模板，Vue 会在浏览器的 JavaScript 控制台中抛出一个错误警告你。

自己创建一个简单的固定模板的 Vue 组件：

```js
 Vue.component('my-component', {
 template: '<div>hello</div>'
 });

      const app = new Vue({
        el: '#app',

       // App options
      });
```

有了这个声明的组件，现在我们可以在视图中使用`<my-component></my-component>` HTML 标签了。

你也可以在 Vue 实例本身上指定组件。如果你在一个站点上有多个 Vue 实例，并希望将一个组件限制在一个实例中，可以使用这种方法。为此，将你的组件创建为一个简单的对象，并在 Vue 实例的`components`对象中分配`tagName`：

```js
      let Child = {
        template: '<div>hello</div>'
      }

      const app = new Vue({
        el: '#app',

        // App options

        components: {
          'my-component': Child
        }
      });
```

然而，对于我们的应用程序，我们将继续使用`Vue.component()`方法来初始化我们的组件。

# 使用你的组件

在你的视图中，添加你的自定义 HTML 元素组件：

```js
      <div id="app">
        <my-component></my-component>
      </div>
```

在浏览器中查看时，应该将`<my-component>` HTML 标签替换为一个`<div>`和一个 hello 消息。

有些情况下，自定义的 HTML 标签可能无法被解析和接受 - 这些情况通常出现在`<table>`、`<ol>`、`<ul>`和`<select>`元素中。如果是这种情况，你可以在标准 HTML 元素上使用`is=""`属性：

```js
      <ol>
        <li is="my-component"></li>
      </ol>
```

# 使用组件数据和方法

由于 Vue 组件是 Vue 应用程序中独立的元素，它们各自拥有自己的数据和函数。这在同一页上重复使用组件时非常有用，因为信息是每个组件实例自包含的。`methods`和`computed`函数的声明方式与在 Vue 应用程序中相同，但是数据键应该是一个返回对象的函数。

组件的数据对象必须是一个函数。这样每个组件都有自己独立的数据，而不会在同一个组件的不同实例之间混淆和共享数据。这个函数仍然必须返回一个对象，就像在 Vue 应用程序中一样。

创建一个名为`balance`的新组件，为您的组件添加一个`data`函数和`computed`对象，并暂时将一个空的`<div>`添加到`template`属性中：

```js
      Vue.component('balance', {
        template: '<div></div>',
        data() {
          return {

          }
        },
        computed: {

        }
      });
```

接下来，向您的`cost`数据对象添加一个键/值对，其中包含一个整数，并将变量添加到您的模板中。在您的视图中添加`<balance></balance>`自定义 HTML 元素，您应该看到一个整数：

```js
      Vue.component('balance', {
        template: '<div>{{ cost }}</div>',
        data() {
          return {
            cost: 1234
          }
        },
        computed: {

        }
      });
```

与我们在第一章中的 Vue 实例一样，添加一个函数到`computed`对象，将货币符号附加到整数上，并确保有两位小数。不要忘记将货币符号添加到您的 data 函数中。

更新模板，输出计算后的值而不是原始成本：

```js
      Vue.component('balance', {
        template: '<div>{{ formattedCost }}</div>',
        data() {
          return {
            cost: 1234,
            currency: '$'
          }
        },
        computed: {
          formattedCost() {
 return this.currency + this.cost.toFixed(2);
 }
        }
      });
```

这是一个组件的基本示例，但它在组件本身上的`cost`是固定的。

# 向组件传递数据 - props

将余额作为一个组件是很好的，但如果余额是固定的，那就不太好了。当您通过 HTML 属性传递参数和属性时，组件真正发挥作用。在 Vue 世界中，这些被称为**props**。Props 可以是静态的或变量的。为了让您的组件期望这些属性，您需要使用`props`属性在组件上创建一个数组。

如果我们想要创建一个`heading`组件，可以这样做：

```js
      Vue.component('heading', {
        template: '<h1>{{ text }}</h1>',

        props: ['text']
      });
```

然后，该组件将在视图中使用如下：

```js
      <heading text="Hello!"></heading>
```

使用 props，我们不需要在数据对象中定义`text`变量，因为在 props 数组中定义它会自动使其在模板中可用。props 数组还可以接受进一步的选项，允许您定义所期望的输入类型，是否需要输入或省略时使用的默认值。

向 balance 组件添加一个 prop，以便我们可以将成本作为 HTML 属性传递。您的视图现在应该是这样的：

```js
      <balance cost="1234"></balance> 
```

现在，我们可以在 JavaScript 中将 cost prop 添加到组件中，并从我们的 data 函数中删除固定值：

```js
      template: '<div>{{ formattedCost }}</div>',
 props: ['cost'],
      data() {
        return {
          currency: '$'
        }
      },
```

然而，在浏览器中运行这个模板会在 JavaScript 控制台中抛出一个错误。这是因为，原生地，传入的 props 被解释为字符串。我们可以通过两种方式解决这个问题；要么在`formatCost()`函数中将我们的 prop 转换为数字，要么使用`v-bind:` HTML 属性告诉 Vue 接受输入的内容。

如果您记得，我们在`true`和`false`值的过滤器中使用了这种技术-允许它们作为布尔值而不是字符串使用。在`cost` HTML 属性前面添加`v-bind:`：

```js
      <balance v-bind:cost="15234"></balance> 
```

我们可以采取额外的步骤来确保 Vue 知道要期望什么样的输入，并通知其他用户您的代码应该传递什么。这可以在组件本身中完成，并且除了格式之外，还允许您指定默认值以及属性是否为必需的。

将您的`props`数组转换为一个对象，其中`cost`作为键。如果您只是定义字段类型，可以使用 Vue 的简写方式来声明，将值设置为字段类型。这些可以是字符串、数字、布尔值、函数、对象、数组或符号。由于我们的成本属性应该是一个数字，所以将其添加为键：

```js
      props: {
 cost: Number
 },
```

如果我们的组件在未定义任何内容时不抛出错误，而是渲染`$0.00`，那将很好。我们可以通过将默认值设置为`0`来实现这一点。要定义默认值，我们需要将我们的 prop 转换为一个对象本身-包含一个`type`键，其值为`Number`。然后，我们可以定义另一个`default`键，并将值设置为`0`：

```js
      props: {
        cost: {
          type: Number,
 default: 0
 }
      },
```

在浏览器中渲染组件应该显示传递到成本属性的任何值，但是如果删除此属性，将显示`$0.00`。

回顾一下，我们的组件如下：

```js
      Vue.component('balance', {
        template: '<div>{{ formattedCost }}</div>',

        props: {
          cost: {
            type: Number,
            default: 0
          }
        },

        data() {
          return {
            currency: '$'
          }
        },

        computed: {
          formattedCost() {
            return this.currency +       
            this.cost.toFixed(2);
          }
        }
      });
```

当我们制作列表应用程序的`person`组件时，我们应该能够在此示例上进行扩展。

# 向组件传递数据-插槽

有时您可能需要将 HTML 块传递给组件，这些 HTML 块不存储在属性中，或者您希望在组件中显示之前进行格式化。与其尝试在计算变量或类似变量中进行预格式化，不如在组件中使用插槽。

插槽就像占位符，允许您在组件的开头和结尾标签之间放置内容，并确定它们将显示在哪里。

一个完美的例子是模态窗口。这些通常有几个标签，并且通常由大量的 HTML 组成，如果您希望在应用程序中多次使用它，则需要复制和粘贴。相反，您可以创建一个`modal-window`组件，并通过插槽传递您的 HTML。

创建一个名为`modal-window`的新组件。它接受一个名为`visible`的属性，默认为`false`，接受一个布尔值。对于模板，我们将使用*Bootstrap modal*中的 HTML 作为一个很好的示例，说明使用插槽的组件如何简化你的应用程序。为了确保组件被样式化，请确保在文档中包含 bootstrap 的*asset 文件*：

```js
      Vue.component('modal-window', {
        template: `<div class="modal fade">
          <div class="modal-dialog" role="document">
            <div class="modal-content">
              <div class="modal-header">
               <button type="button" class="close" 
               data-dismiss="modal" aria-label="Close">
               <span aria-hidden="true">&times;</span>
              </button>
             </div>
          <div class="modal-body">
          </div>
           <div class="modal-footer">
            <button type="button" class="btn btn-  
             primary">Save changes</button>
            <button type="button" class="btn btn-      
             secondary" data-dismiss="modal">Close
            </button>
            </div>
          </div>
         </div>
      </div>`,

      props: {
        visible: {
          type: Boolean,
          default: false
        }
       }
    });
```

我们将使用 visible 属性来确定模态窗口是否打开。在外部容器中添加一个`v-show`属性，接受`visible`变量：

```js
      Vue.component('modal-window', {
          template: `<div class="modal fade" v-
            show="visible">
          ...
        </div>`,

        props: {
          visible: {
            type: Boolean,
            default: false
          }
        }
      });
```

将你的`modal-window`组件添加到应用程序中，暂时将`visible`设置为`true`，这样我们就可以理解和看到发生了什么：

```js
      <modal-window :visible="true"></modal-window>
```

现在我们需要向模态框传递一些数据。在两个标签之间添加一个标题和一些段落：

```js
      <modal-window :visible="true">
        <h1>Modal Title</h1>
 <p>Lorem ipsum dolor sit amet, consectetur                
         adipiscing elit. Suspendisse ut rutrum ante, a          
         ultrices felis. Quisque sodales diam non mi            
         blandit dapibus. </p>
 <p>Lorem ipsum dolor sit amet, consectetur             
          adipiscing elit. Suspendisse ut rutrum ante, a             
          ultrices felis. Quisque sodales diam non mi             
          blandit dapibus. </p>
       </modal-window>
```

在浏览器中按下刷新按钮不会有任何反应，因为我们需要告诉组件如何处理数据。在模板中，添加一个`<slot></slot>`的 HTML 标签，用于显示内容。将其添加到具有`modal-body`类的`div`中：

```js
      Vue.component('modal-window', {
        template: `<div class="modal fade" v-      
        show="visible">
          <div class="modal-dialog" role="document">
            <div class="modal-content">
              <div class="modal-header">
          <button type="button" class="close" data-              
              dismiss="modal" aria-label="Close">
               <span aria-hidden="true">&times;</span>
             </button>
              </div>
              <div class="modal-body">
                <slot></slot>
              </div>
              <div class="modal-footer">
              <button type="button" class="btn btn-  
             primary">Save changes</button>
             <button type="button" class="btn btn-                   
               secondary" data-
            dismiss="modal">Close</button>
           </div>
           </div>
        </div>
        </div>`,

         props: {
          visible: {
            type: Boolean,
            default: false
          }
        }
      });
```

现在查看你的应用程序，将会在模态窗口中显示你传递的内容。通过这个新的组件，应用程序看起来更加清晰。

查看 Bootstrap 的 HTML，我们可以看到有一个头部、主体和底部的空间。我们可以使用命名插槽来标识这些部分。这样我们就可以将特定的内容传递到组件的特定区域。

在模态窗口的头部和底部创建两个新的`<slot>`标签。给这些新的标签添加一个 name 属性，但保留现有的标签为空：

```js
      template: `<div class="modal fade" v-              
      show="visible">
        <div class="modal-dialog" role="document">
          <div class="modal-content">
            <div class="modal-header">
              <slot name="header"></slot>
              <button type="button" class="close" data-
               dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
             </button>
          </div>
           <div class="modal-body">
            <slot></slot>
          </div>
          <div class="modal-footer">
            <slot name="footer"></slot>
            <button type="button" class="btn btn-  
            primary">Save changes</button><button type="button" class="btn btn-
           secondary" data-
           dismiss="modal">Close</button>
           </div>
        </div>
       </div>
     </div>`,
```

在我们的应用程序中，我们现在可以通过在 HTML 中指定一个`slot`属性来指定内容放在哪里。这可以放在特定的标签或包围几个标签的容器上。任何没有`slot`属性的 HTML 也将默认为无名插槽：

```js
      <modal-window :visible="true">
        <h1 slot="header">Modal Title</h1>

        <p>Lorem ipsum dolor sit amet, consectetur             
        adipiscing elit. Suspendisse ut rutrum ante, a 
        ultrices felis. Quisque sodales diam non mi 
         blandit dapibus. </p>

        <p slot="footer">Lorem ipsum dolor sit amet,            
         consectetur adipiscing elit. Suspendisse ut 
         rutrum ante, a ultrices felis. Quisque sodales 
           diam non mi blandit dapibus. </p>
      </modal-window>
```

我们现在可以指定并将我们的内容定向到特定的位置。

插槽的最后一件事是指定一个默认值。例如，您可能希望大部分时间在底部显示按钮，但如果需要，可以替换它们。使用`<slot>`，在标签之间放置的任何内容都将显示，除非在应用程序中指定组件时被覆盖。

创建一个名为`buttons`的新插槽，并将按钮放在底部。尝试用其他内容替换它们。

模板变为：

```js
      template: `<div class="modal fade" v-
      show="visible">
        <div class="modal-dialog" role="document">
          <div class="modal-content">
            <div class="modal-header">
              <slot name="header"></slot>
              <button type="button" class="close" data-
              dismiss="modal" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div class="modal-body">
              <slot></slot>
            </div>
            <div class="modal-footer">
              <slot name="footer"></slot>
              <slot name="buttons">
                <button type="button" class="btn btn-
                 primary">Save changes</button>
                <button type="button" class="btn btn-
                 secondary" data-
                 dismiss="modal">Close</button>
              </slot>
            </div>
          </div>
        </div>
      </div>`,
```

HTML 变为：

```js

     <modal-window :visible="true">
     <h1 slot="header">Modal Title</h1>
      <p>Lorem ipsum dolor sit amet, consectetur 
      adipiscing elit. Suspendisse ut rutrum ante, a 
      ultrices felis. Quisque sodales diam non mi blandit 
      dapibus. </p>

        <p slot="footer">Lorem ipsum dolor sit amet, 
       consectetur adipiscing elit. Suspendisse ut rutrum 
       ante, a ultrices felis. Quisque sodales diam non mi 
       blandit dapibus. </p>

        <div slot="buttons">
 <button type="button" class="btn btn-      
           primary">Ok</button> </div>
       </modal-window>
```

虽然我们不会在人员列表应用程序中使用插槽，但了解 Vue 组件的功能是很好的。如果你希望使用这样的模态框，你可以将可见性设置为默认为 false 的变量。然后，你可以添加一个具有点击方法的按钮，将变量从`false`更改为`true`-显示模态框。

# 创建一个可重复使用的组件

组件的美妙之处在于能够在同一个视图中多次使用它们。这使得你可以为该数据的布局拥有一个单一的“真实来源”。我们将为人员列表创建一个可重复使用的组件，并为过滤部分创建一个单独的组件。

打开你在前几章中创建的人员列表代码，并创建一个名为`team-member`的新组件。不要忘记在 Vue 应用程序初始化之前定义组件。为组件添加一个`prop`，允许传入人员对象。为了验证目的，只指定它可以是一个`Object`：

```js
      Vue.component('team-member', {
        props: {
          person: Object
        }
      });
```

现在，我们需要将我们的模板整合到组件中，这是我们视图中的（包括）`tr`内的所有内容。

组件中的模板变量只接受一个没有换行符的普通字符串，所以我们需要做以下其中一种：

+   内联我们的 HTML 模板-非常适用于小型模板，但在这种情况下会牺牲可读性。

+   使用`+`字符串连接添加新行-非常适用于一两行，但会使我们的 JavaScript 变得臃肿

+   创建一个模板块-Vue 允许我们使用在视图中使用`text/x-template`语法和 ID 定义的外部模板的选项

由于我们的模板相当大，我们将选择第三个选项，在我们的视图末尾声明我们的模板。

在你的 HTML 中，在你的应用程序之外，创建一个新的脚本块，并添加`type`和`ID`属性：

```js
      <script type="text/x-template" id="team-member-            
       template">
      </script>
```

然后，我们可以将人员模板移到这个块中，并删除`v-for`属性-我们仍然会在应用程序本身中使用它：

```js
      <script type="text/x-template" id="team-member-
      template">
        <tr v-show="filterRow(person)">
 <td>
 {{ person.name }}
 </td>
 <td>
 <a v-bind:href="'mailto:' + person.email">{{                
             person.email }}</a>
 </td>
 <td v-bind:class="balanceClass(person)">
 {{ format(person, 'balance') }}
 </td>
 <td>
 {{ format(person, 'registered') }}
 </td>
 <td v-bind:class="activeClass(person)">
 {{ format(person, 'isActive') }}
 </td>
 </tr>
      </script>
```

现在，我们需要更新视图，使用`team-member`组件代替固定的代码。为了使我们的视图更清晰易懂，我们将利用之前提到的`<template>` HTML 属性。创建一个`<template>`标签，并添加我们之前使用的`v-for`循环。为了避免混淆，将循环更新为使用`individual`作为每个人的变量。它们可以相同，但如果变量、组件和 props 具有不同的名称，代码会更容易阅读。将`v-for`更新为`v-for="individual in people"`：

```js
      <table>
       <template v-for="individual in people">
       </template>
      </table>
```

在视图的`template`标签中，添加一个新的`team-member`组件实例，将`individual`变量传递给`person` prop。不要忘记在 person prop 前添加`v-bind:`，否则组件将将其解释为一个固定字符串，其值为 individual：

```js
      <table>
        <template v-for="individual in people">
          <team-member v-bind:person="individual"></team-           
            member>
        </template>
      </table>
```

现在，我们需要更新组件，使用我们声明的模板作为`template`属性和脚本块的 ID 作为值：

```js
      Vue.component('team-member', {
        template: '#team-member-template',
        props: {
          person: Object
        }
      });
```

在浏览器中查看应用程序将在 JavaScript 控制台中创建多个错误。这是因为我们引用了一些不再可用的方法 - 因为它们在父 Vue 实例上，而不是在组件上。如果您想验证组件是否工作，请将代码更改为仅输出人员的名称，然后按刷新：

```js
      <script type="text/x-template" id="team-member-             
        template">
        <tr v-show="filterRow()">
          <td>
            {{ person.name }}
          </td>
        </tr>
      </script>
```

# 创建组件方法和计算函数

现在，我们需要在子组件上创建我们在 Vue 实例上创建的方法，以便可以使用它们。我们可以做的一件事是将父组件中的方法剪切并粘贴到子组件中，希望它们能够工作；然而，这些方法依赖于父组件的属性（如过滤数据），我们还有机会利用`computed`属性，它可以缓存数据并加快应用程序的速度。

现在，从`tr`元素中删除`v-show`属性 - 因为这涉及到过滤，而这将在我们的行正确显示后进行讨论。我们将逐步解决错误，并逐个解决，以帮助您理解使用 Vue 进行问题解决。

# CSS 类函数

在浏览器中查看应用程序时，我们遇到的第一个错误是：

属性或方法“balanceClass”未定义

第一个错误涉及到我们使用的`balanceClass`和`activeClass`函数。这两个函数根据人员的数据添加 CSS 类，一旦组件被渲染，这些数据就不会改变。

因此，我们可以使用 Vue 中的缓存。将方法移到组件中，但将它们放在一个新的`computed`对象中，而不是`methods`对象中。

使用组件时，每次调用都会创建一个新的实例，因此我们可以依赖通过`prop`传递的`person`对象，不再需要将`person`传递给函数。从函数和视图中删除参数，并将函数内部对`person`的任何引用更新为`this.person`，以引用存储在组件上的对象：

```js
 computed: {
        /**
         * CSS Classes
         */
        activeClass() {
          return this.person.isActive ? 'active' : 
      'inactive';
        },

        balanceClass() {
          let balanceLevel = 'success';

          if(this.person.balance < 2000) {
            balanceLevel = 'error';
          } else if (this.person.balance < 3000) {
            balanceLevel = 'warning';
          }

          let increasing = false,
              balance = this.person.balance / 1000;

          if(Math.round(balance) == Math.ceil(balance)) {
            increasing = 'increasing';
          }

          return [balanceLevel, increasing];
        }
 },
```

使用此函数的组件模板部分现在应该如下所示：

```js
      <td v-bind:class="balanceClass">
    {{ format(person, 'balance') }}
      </td>
```

# 格式化值函数

当将`format()`函数移动到组件中格式化我们的数据时，我们面临两个选择。我们可以按照原样移动它并将其放在`methods`对象中，或者我们可以利用 Vue 的缓存和约定，为每个值创建一个`computed`函数。

我们正在构建这个应用程序以实现可扩展性，因此建议为每个值创建计算函数，这也有助于整理我们的模板。在计算对象中创建三个函数，分别命名为`balance`、`dateRegistered`和`status`。将`format`函数的相应部分复制到每个函数中，再次将`person`的引用更新为`this.person`。

在使用函数参数检索字段的地方，现在可以在每个函数中修复该值。您还需要在`props`之后添加一个包含货币符号的数据对象，以供余额函数使用：

```js
      data() {
        return {
          currency: '$'
        }
      },
```

由于`team-member`组件是我们唯一使用货币符号的地方，我们可以将其从 Vue 应用程序本身中删除。我们还可以从父 Vue 实例中删除格式化函数。

总的来说，我们的 Vue `team-member`组件应该如下所示：

```js
      Vue.component('team-member', {
        template: '#team-member-template',
        props: {
          person: Object 
       },
        data() {
          return {
            currency: '$'
          }
        },
        computed: {
          /**
           * CSS Classes
           */
          activeClass() {
            return this.person.isActive ? 'active' : 
            'inactive';
          },
          balanceClass() {
            let balanceLevel = 'success';   
            if(this.person.balance < 2000) {
              balanceLevel = 'error';
            } else if (this.person.balance < 3000) {
              balanceLevel = 'warning';
            }
          let increasing = false,
                balance = this.person.balance / 1000; 
            if(Math.round(balance) == Math.ceil(balance))                           
            {
              increasing = 'increasing';
            }
            return [balanceLevel, increasing];
          }, 
          /**
           * Fields
           */
          balance() {
            return this.currency +       
            this.person.balance.toFixed(2);
          },
          dateRegistered() {
            let registered = new 
            Date(this.person.registered);
            return registered.toLocaleString('en-US');
          },
          status() {
            return (this.person.isActive) ? 'Active' : 
            'Inactive';
          }
        }
      });
```

与之前相比，我们的`team-member-template`应该看起来相对简单：

```js
      <script type="text/x-template" id="team-member-
      template">
        <tr v-show="filterRow()">
          <td>
            {{ person.name }}
          </td>
          <td>
            <a v-bind:href="'mailto:' + person.email">{{ 
            person.email }}</a>
          </td>
          <td v-bind:class="balanceClass">
            {{ balance }}
          </td>
          <td>
            {{ dateRegistered }}
          </td>
          <td v-bind:class="activeClass">
            {{ status }}
          </td>
        </tr>
      </script>
```

最后，我们的 Vue 实例应该显得更小：

```js
      const app = new Vue({
        el: '#app',
        data: {
          people: [...],
          filter: {
            field: '',
            query: ''
          }
        },
        methods: {
          isActiveFilterSelected() {
            return (this.filter.field === 'isActive');
          },   
          /**
           * Filtering
           */
          filterRow(person) {
            let visible = true,
                field = this.filter.field,
                query = this.filter.query;  
            if(field) {   
              if(this.isActiveFilterSelected()) {
                visible = (typeof query === 'boolean') ? 
                  (query === person.isActive) : true;
              } else {
                query = String(query),
                field = person[field]; 
          if(typeof field === 'number') {
            query.replace(this.currency, '');
                  try {
                    visible = eval(field + query);
                  } catch(e) {}   
                } else {
                  field = field.toLowerCase();
                  visible = 
                  field.includes(query.toLowerCase())  
                }
              }
            }
            return visible;
          }
          changeFilter(event) {
            this.filter.query = '';
            this.filter.field = event.target.value;
          }
        }
      });
```

在浏览器中查看应用程序，我们应该看到我们的人员列表，并在表格单元格中添加了正确的类，并在字段中添加了格式。

# 使过滤器与 props 再次正常工作

在模板中的包含`tr`元素中重新添加`v-show="filterRow()"`属性。由于我们的组件在每个实例上都有缓存的 person 对象，所以我们不再需要将 person 对象传递给该方法。刷新页面将在 JavaScript 控制台中给出一个新的错误：

```js
Property or method "filterRow" is not defined on the instance but referenced during render
```

这个错误是因为我们的组件有`v-show`属性，根据我们的过滤器和属性来显示和隐藏，但没有相应的`filterRow`函数。由于我们不在其他地方使用它，我们可以将该方法从 Vue 实例移动到组件中，将其添加到`methods`组件中。删除 person 参数并更新方法以使用`this.person`：

```js
      filterRow() {
        let visible = true,
            field = this.filter.field,
            query = this.filter.query;
            if(field) {
            if(this.isActiveFilterSelected()) {
            visible = (typeof query === 'boolean') ?                 
           (query === this.person.isActive) : true;
            } else {

            query = String(query),
            field = this.person[field];

            if(typeof field === 'number') {
              query.replace(this.currency, '');
              try {
                visible = eval(field + query);
              } catch(e) {}
              } else {

              field = field.toLowerCase();
              visible = 
            field.includes(query.toLowerCase());
            }
          }
        }
        return visible;
      }
```

控制台中的下一个错误是：

```js
Cannot read property 'field' of undefined
```

过滤不起作用的原因是`filterRow`方法在组件上寻找`this.filter.field`和`this.filter.query`，而不是它所属的父 Vue 实例。

作为一个快速修复，你可以使用`this.$parent`来引用父元素上的数据，但是这不被推荐，只应在极端情况下或快速传递数据时使用。

为了将数据传递给组件，我们将使用另一个 prop - 类似于我们如何将 person 传递给组件。幸运的是，我们已经将我们的过滤器数据分组了，所以我们可以传递一个对象而不是`query`或`field`的单个属性。在你的组件上创建一个新的 prop，命名为`filter`，并确保只允许传递一个`Object`：

```js
      props: {
        person: Object,
        filter: Object
      },
```

然后我们可以将这个 prop 添加到`team-member`组件中，以便我们可以传递数据：

```js
      <table>
        <template v-for="individual in people">
          <team-member v-bind:person="individual" v-               
           bind:filter="filter"></team-member>
        </template>
      </table>
```

为了使我们的过滤器工作，我们需要传入另一个属性-`isActiveFilterSelected()`函数。创建另一个 prop，命名为`statusFilter`，只允许值为`Boolean`（因为这是函数的返回值），并将函数传递进去。更新`filterRow`方法以使用这个新值。我们的组件现在如下所示：

```js
      Vue.component('team-member', {
        template: '#team-member-template',
        props: {
          person: Object,
          filter: Object,
          statusFilter: Boolean
        },
        data() {
          return {
            currency: '$'
          }
        },
        computed: {
          /**
           * CSS Classes
           */
          activeClass() {
            return this.person.isActive ? 'active' : 
            'inactive';
            },
            balanceClass() {
            let balanceLevel = 'success';

         if(this.person.balance < 2000) {
           balanceLevel = 'error';
          } else if (this.person.balance < 3000) {
            balanceLevel = 'warning';
          }
          let increasing = false,
            balance = this.person.balance / 1000;
           if(Math.round(balance) == Math.ceil(balance)) {
             increasing = 'increasing';
          }
          return [balanceLevel, increasing];
        },
       /**
       * Fields
         */
       balance() {
       return this.currency +    
       this.person.balance.toFixed(2);
       },
      dateRegistered() {
       let registered = new Date(this.registered); 
        return registered.toLocaleString('en-US');
        },
        status() {
           return output = (this.person.isActive) ?    
          'Active' : 'Inactive';
         }
       },
       methods: {
        filterRow() {
         let visible = true,
            field = this.filter.field,
            query = this.filter.query;

         if(field) {  
           if(this.statusFilter) {
             visible = (typeof query === 'boolean') ? 
            (query === this.person.isActive) : true;
           } else {
             query = String(query),
            field = this.person[field];  
              if(typeof field === 'number') {
                query.replace(this.currency, '');  
                 try {
                 visible = eval(field + query);
                } catch(e) {
            } 
           } else {   
            field = field.toLowerCase();
            visible = field.includes(query.toLowerCase());
             }
            }
           }
           return visible;
        }
       }
     });
```

现在，视图中的组件带有额外的 props，如下所示。请注意，当作为 HTML 属性使用时，驼峰式的 prop 变成了蛇形式（用连字符分隔）：

```js
      <template v-for="individual in people">
          <team-member v-bind:person="individual" v-               bind:filter="filter" v-bind:status-      
            filter="isActiveFilterSelected()"></team-
            member>
       </template>
```

# 将过滤器作为一个组件

现在我们需要将过滤器部分作为一个独立的组件。在这种情况下，这并不是必需的，但这是一个好的实践，并且给我们带来了更多的挑战。

我们在将过滤器作为组件时面临的问题是在过滤器组件和`team-member`组件之间传递过滤器数据的挑战。Vue 通过自定义事件来解决这个问题。这些事件允许你将数据传递（或"emit"）给父组件或其他组件。

我们将创建一个过滤组件，当过滤器发生变化时，将数据传递回父 Vue 实例。这些数据已经通过`team-member`组件传递给过滤器。

# 创建组件

与`team-member`组件一样，在您的 JavaScript 中声明一个新的`Vue.component()`，引用模板 ID 为`#filtering-template`。在视图中创建一个新的`<script>`模板块，并给它相同的 ID。将视图中的过滤表单替换为`<filtering>`自定义 HTML 模板，并将表单放在`filtering-template`脚本块中。

您的视图应该如下所示：

```js
      <div id="app">
       <filtering></filtering>
       <table>
         <template v-for="individual in people">
           <team-member v-bind:person="individual" v-
            bind:filter="filter" v-
            bind:statusfilter="isActiveFilterSelected()">           </team-member>
         </template>
       </table>
      </div>

 <script type="text/x-template" id="filtering-
      template">
        <form>
          <label for="fiterField">
            Field:
            <select v-on:change="changeFilter($event)"                 id="filterField">
           <option value="">Disable filters</option>
           <option value="isActive">Active user</option>
           <option value="name">Name</option>
           <option value="email">Email</option>
           <option value="balance">Balance</option>
           <option value="registered">Date      
            registered</option>
           </select>
         </label>
        <label for="filterQuery" v-show="this.filter.field 
         && !isActiveFilterSelected()">
            Query:
            <input type="text" id="filterQuery" v-
            model="filter.query">
          </label>
          <span v-show="isActiveFilterSelected()">
            Active:
         <label for="userStateActive">
            Yes:
             <input type="radio" v-bind:value="true"       id="userStateActive" v-model="filter.query">
          </label>
            <label for="userStateInactive">
            No:
        <input type="radio" v-bind:value="false" 
        id="userStateInactive" v-model="filter.query">
         </label>
       </span>
      </form>
 </script>
      <script type="text/x-template" id="team-member-
       template">
       // Team member template
    </script>
```

在您的 JavaScript 中应该有以下内容：

```js
      Vue.component('filtering', {
        template: '#filtering-template'
      });
```

# 解决 JavaScript 错误

与`team-member`组件一样，您将在 JavaScript 控制台中遇到一些错误。通过复制父实例中的`filter`数据对象以及`changeFilter`和`isActiveFilterSelected`方法来解决这些错误。我们现在将它们保留在组件和父实例中，但稍后将删除重复部分：

```js
      Vue.component('filtering', {
        template: '#filtering-template',

        data() {
 return {
 filter: {
 field: '',
 query: ''
 }
 }
 },

 methods: {
 isActiveFilterSelected() {
 return (this.filter.field === 'isActive');
 },

 changeFilter(event) {
 this.filter.query = '';
 this.filter.field = event.target.value;
 }
 }
      });
```

运行应用程序将显示过滤器和人员列表，但是过滤器尚未与人员列表进行通信，因此不会更新。

# 使用自定义事件来更改过滤字段

使用自定义事件，您可以使用`$on`和`$emit`函数将数据传递回父实例。对于这个应用程序，我们将在父 Vue 实例上存储过滤数据，并从组件中更新它。然后，`team-member`组件可以从 Vue 实例中读取数据并进行相应的过滤。

第一步是利用父 Vue 实例上的过滤器对象。从组件中删除`data`对象，并通过 prop 传递父对象 - 就像我们在`team-member`组件中所做的那样：

```js
      <filtering v-bind:filter="filter"></filtering>
```

现在，我们将修改`changeFilter`函数以发出事件数据，以便父实例可以更新`filter`对象。

从`filtering`组件中删除现有的`changeFilter`方法，并创建一个名为`change-filter-field`的新方法。在这个方法中，我们只需要通过`$emit`方法将下拉菜单中选择的字段的名称传递出去。`$emit`函数接受两个参数：一个键和一个值。使用多个单词的变量（例如`changeFilterField`）时，确保事件名称（`$emit`函数的第一个参数）和 HTML 属性使用连字符分隔：

```js
      changeFilterField(event) {
        this.$emit('change-filter-field', 
      event.target.value);
      }
```

为了将数据传递给父 Vue 实例上的 changeFilter 方法，我们需要在我们的`<filtering>`元素中添加一个新的 prop。这使用`v-on`绑定到自定义事件名称。然后将父方法名称作为属性值。将属性添加到您的元素中：

```js
      <filtering v-bind:filter="filter" v-on:change-filter-field="changeFilter"></filtering>
```

前面的属性告诉 Vue 在发出`change-filter-field`事件时触发`changeFilter`方法。然后我们可以调整我们的方法来接受该参数作为值：

```js
      changeFilter(field) {
        this.filter.query = '';
        this.filter.field = field;
      }
```

然后清除过滤器并更新字段值，然后通过 props 传递给我们的组件。

# 更新过滤器查询

为了发出查询字段，我们将使用一个之前没有使用过的新的 Vue 键，称为`watch`。`watch`函数跟踪数据属性并可以根据输出运行方法。它还能够发出事件。由于我们的文本字段和单选按钮都设置为更新`field.query`变量，所以我们将在此上创建一个新的`watch`函数。

在组件的方法之后创建一个新的`watch`对象：

```js
      watch: {
        'filter.query': function() {
        }
      }
```

关键是你想要监视的变量。由于我们的变量包含一个点，所以需要用引号括起来。在这个函数中，创建一个名为`change-filter-query`的新的`$emit`事件，输出`filter.query`的值：

```js
     watch: {
         'filter.query': function() {
         this.$emit('change-filter-query', 
         this.filter.query)
         }
       }
```

现在我们需要将这个方法和自定义事件绑定到视图中的组件上，以便能够将数据传递给父实例。将属性的值设置为`changeQuery` - 我们将创建一个处理此方法的方法：

```js
      <filtering v-bind:filter="filter" v-on:change-      
      filter-field="changeFilter" v-on:change-filter-          
      query="changeQuery"></filtering>
```

在父 Vue 实例上创建一个名为`changeQuery`的新方法，它只是根据输入更新`filter.query`的值：

```js
     changeQuery(query) {
       this.filter.query = query;
     }
```

我们的过滤器现在又可以工作了。更新选择框和输入框（或单选按钮）将会更新我们的人员列表。我们的 Vue 实例变得更小了，我们的模板和方法都包含在独立的组件中。

最后一步是避免在`team-member`组件上重复使用`isActiveFilterSelected()`方法，因为这个方法只在`team-member`组件上使用一次，但在`filtering`组件上使用多次。从父 Vue 实例中删除该方法，从`team-member` HTML 元素中删除该 prop，并将`team-member`组件中的`filterRow`方法中的`statusFilter`变量替换为通过的函数的内容。

最终的 JavaScript 代码如下：

```js
      Vue.component('team-member', {
        template: '#team-member-template',
        props: {
          person: Object,
          filter: Object
        },
        data() {
          return {
            currency: '$'
          }
        },
        computed: {
          /**
           * CSS Classes
           */
           activeClass() {
            return this.person.isActive ? 'active' : 'inactive';
          },
          balanceClass() {
            let balanceLevel = 'success';    
            if(this.person.balance < 2000) {
              balanceLevel = 'error';
            } else if (this.person.balance < 3000) {
              balanceLevel = 'warning';
            }
           let increasing = false,
            balance = this.person.balance / 1000;      
            if(Math.round(balance) == Math.ceil(balance))             {
             increasing = 'increasing';
            } 
            return [balanceLevel, increasing];
          },
          /**
           * Fields
           */
          balance() {
            return this.currency +       
          this.person.balance.toFixed(2);
          },
          dateRegistered() {
            let registered = new Date(this.registered);  
            return registered.toLocaleString('en-US');
          },
          status() {
            return output = (this.person.isActive) ? 
           'Active' : 'Inactive';
          }
        },
          methods: {
          filterRow() {
            let visible = true,
            field = this.filter.field,
            query = this.filter.query;         
            if(field) {      
              if(this.filter.field === 'isActive') {
              visible = (typeof query === 'boolean') ? 
             (query === this.person.isActive) : true;
              } else {   
                query = String(query),
                field = this.person[field]; 
                if(typeof field === 'number') {
                  query.replace(this.currency, '');
               try {
              visible = eval(field + query);
            } catch(e) {}

          } else {

            field = field.toLowerCase();
            visible = field.includes(query.toLowerCase());  
              }
           }
          }
            return visible;
          }
          }
         });

     Vue.component('filtering', {
     template: '#filtering-template',
       props: {
       filter: Object
     },
       methods: {
       isActiveFilterSelected() {
        return (this.filter.field === 'isActive');
       },     
        changeFilterField(event) {
        this.filedField = '';
       this.$emit('change-filter-field',                     
        event.target.value);
          },
        },
        watch: {
    'filter.query': function() {
      this.$emit('change-filter-query', this.filter.query)
          }
        }
      });

      const app = new Vue({
        el: '#app',

        data: {
          people: [...],
          filter: {
            field: '',
            query: ''
          }
        },
        methods: { 
          changeFilter(field) {
            this.filter.query = '';
            this.filter.field = field;
          },
          changeQuery(query) {
            this.filter.query = query;
          }
        }
      });
```

现在的视图是：

```js
     <div id="app">
        <filtering v-bind:filter="filter" v-on:change-
         filter-field="changeFilter" v-on:change-filter-
          query="changeQuery"></filtering>
       <table>
         <template v-for="individual in people">
          <team-member v-bind:person="individual" v-  
          bind:filter="filter"></team-member>
         </template>
        </table>
     </div>
    <script type="text/x-template" id="filtering-
     template">
       <form>
      <label for="fiterField">
       Field:
      <select v-on:change="changeFilterField($event)" 
         id="filterField">
        <option value="">Disable filters</option>
        <option value="isActive">Active user</option>
        <option value="name">Name</option>
        <option value="email">Email</option>
        <option value="balance">Balance</option>
        <option value="registered">Date     
          registered</option>
         </select>
          </label>
         <label for="filterQuery" v-
         show="this.filter.field && 
          !isActiveFilterSelected()">
         Query:
        <input type="text" id="filterQuery" v-    
         model="filter.query">
          </label>

          <span v-show="isActiveFilterSelected()">
           Active:

            <label for="userStateActive">
              Yes:
            <input type="radio" v-bind:value="true"   
          id="userStateActive" v-model="filter.query">
           </label>
          <label for="userStateInactive">
           No:
            <input type="radio" v-bind:value="false"                 id="userStateInactive" v-model="filter.query">
            </label>
          </span>
        </form>
      </script>
      <script type="text/x-template" id="team-member-
      template">
        <tr v-show="filterRow()">
          <td>
            {{ person.name }}
          </td>
          <td>
            <a v-bind:href="'mailto:' + person.email">{{                person.email }}</a>
          </td>
          <td v-bind:class="balanceClass">
            {{ balance }}
          </td>
          <td>
            {{ dateRegistered }}
          </td>
          <td v-bind:class="activeClass">
            {{ status }}
          </td>
        </tr>
      </script>
```

# 概述

在过去的三章中，您已经学会了如何初始化一个新的 Vue 实例，computed、method 和 data 对象背后的含义，以及如何列出对象中的数据并对其进行正确显示的操作。您还学会了如何创建组件以及保持代码整洁和优化的好处。

在本书的下一节中，我们将介绍 Vuex，它可以帮助我们更好地存储和操作存储的数据。
