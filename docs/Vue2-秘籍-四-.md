# Vue2 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3`](https://zh.annas-archive.org/md5/dd7447834c754d87cebc9999e0cff7f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：单元测试和端到端测试

本章将介绍以下内容：

+   使用 Jasmine 进行 Vue 测试

+   将 Karma 添加到工作流程中

+   测试应用程序的状态和方法

+   测试 DOM

+   测试 DOM 异步更新

+   使用 nightwatch 进行端到端测试

+   在 nightwatch 中模拟双击

+   不同风格的单元测试

+   使用 Sinon.JS 对外部 API 调用进行存根

+   测量代码的覆盖率

# 介绍

测试是真正区分专业软件和业余软件的关键。根据行业经验和研究，发现软件成本的很大一部分在于在软件投入生产时纠正错误。测试软件可以减少生产中的错误，并使纠正这些错误的成本大大降低。

在本章中，您将学习如何设置测试工具和编写单元测试和集成测试，以加快应用程序开发速度，并使其在复杂性增加时不留下错误。

在完成这些示例后，您将熟悉最流行的测试框架和术语；您将能够自信地发布按预期工作的软件。

# 使用 Jasmine 进行 Vue 测试

Jasmine 是一个用于测试的库，非常易于使用，并且能够直接在浏览器中显示测试结果。在这个示例中，您将构建一个简单的 Vue 应用程序，并使用 Jasmine 进行测试。

# 准备工作

希望您不是从这个示例开始学习 Vue，因为我将假设，就像本章的其他部分一样，您已经了解了在 Vue 中构建简单应用程序的基础知识。

您还应该能够在互联网上找到四个文件。我将在写作时提供链接，但是当然，它们可能会发生变化：

+   [`cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/jasmine.css`](https://cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/jasmine.css)

+   https://cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/jasmine.js

+   [`cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/jasmine-html.js`](https://cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/jasmine-html.js) 的中文翻译如下：

+   https://cdnjs.cloudflare.com/ajax/libs/jasmine/2.5.2/boot.js

您可以方便地从[`cdnjs.com/libraries/jasmine`](https://cdnjs.com/libraries/jasmine)页面复制粘贴所有链接。

这些文件彼此依赖，因此添加它们的顺序很重要！特别是，`boot.js` 依赖于 `jasmine-html.js`，而 `jasmine-html.js` 又依赖于 `jasmine.js`。

# 如何做到这一点...

Jasmine 是一个由各种模块组成的库。为了使其工作，您需要安装一些与 Jasmine 相关的依赖项。我假设您正在使用 JSFiddle 进行操作。如果您使用的是 npm 或其他方法，您应该能够根据原则简单地推导出需要更改的内容。

要在您的应用程序中安装 Jasmine，您将需要四个不同的依赖项，其中一个仅用于 CSS 样式。

这四个文件的顺序（按依赖关系排序）是：

+   `jasmine.css`

+   `jasmine.js` 是一个用于 JavaScript 测试的开源框架。它提供了一套简洁的语法和功能，用于编写和执行单元测试和集成测试。`jasmine.js` 可以帮助开发人员轻松地编写可靠的测试用例，以确保代码的质量和稳定性。无论是在前端还是后端开发中，`jasmine.js` 都是一个非常有用的工具。

+   `jasmine-html.js`（依赖于前面的 js 文件）

+   `boot.js`（依赖于前面的 js 文件）

你应该能够在 CDNJS 或其他 CDN 上找到所有这些文件。按照显示的顺序安装它们，否则它们将无法正常工作。

当你把所有文件放好后，写下以下 HTML 代码：

```js
<div id="app">

  <p>{{greeting}}</p>

</div>

```

然后，将以下脚本添加为 JavaScript 部分：

```js
new Vue({

  el: '#app',

  data: {

    greeting: 'Hello World!'

  }

})

```

现在可以启动应用程序了，正如预期的那样，屏幕上会出现`Hello World`的消息。

我们希望在对应用程序进行修改和添加新功能时，能够确保我们的应用程序始终显示这条消息。

在这方面，Jasmine 将帮助我们。在 Vue 实例之后，我们编写以下 JavaScript 代码：

```js
describe('my app', () => {

  it('should say Hello World', () => {

    expect(document.querySelector('p').innerText)

      .toContain('Hello World')

  })

})

```

为了使其在 JSFiddle 中工作，需要将 Load Type 设置为 No wrap - in <body>。如果保持默认的 Load Type onLoad，它将在 Vue 有机会启动之前加载 Jasmine。

现在尝试启动应用程序。您将在页面末尾看到 Jasmine 的详细报告，告诉您应用程序是否有问题。

如果一切如预期，您应该会看到一个快乐的绿色条，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00131.jpg)

# 工作原理...

您为 Vue 应用程序编写了第一个单元测试。如果您已经编写了单元测试，那么一切都应该很清楚，因为我们没有使用任何 Vue 特有的功能来编写测试。

无论如何，让我们花点时间分析我们编写的代码；之后，我将提供一些关于在编写真实应用程序时何时编写类似测试的考虑事项。

我们编写的测试在网页上读作“我的应用程序应该说 Hello World”。

这是一条相当通用的消息；然而，让我们仔细看一下代码：

```js
expect(document.querySelector('p').innerText)

  .toContain('Hello World')

```

将其作为一个英语短语来阅读-我们期望文档中的`<p>`元素包含文本`Hello World`。

`document.querySelector('p')`代码选择页面内的第一个`p`元素，确切地说。`innerText`查找 HTML 元素内部并返回可读的文本。然后，我们验证该文本是否包含`Hello World`。

在实际应用中，你不会将测试代码直接写在网页下方。测试对于开发者来说非常重要，可以在每次代码更改后自动验证每个功能是否正常工作，而无需手动验证。另一方面，你不希望用户看到测试结果。

通常情况下，您将拥有一个专门的页面，只有开发人员可以访问，该页面会为您运行所有的测试。

# 还有更多...

在软件开发中有一种广泛的实践叫做**TDD**或者**测试驱动开发**。它鼓励你将软件的功能视为测试。这样一来，你可以通过测试本身的工作来确保软件中的功能正常运行。

在这一部分中，我们将使用 TDD 为我们的食谱添加一个功能。我们希望页面上有一个标题，上面写着“欢迎”。

首先，在 hello world 测试之后，我们将为`describe`函数内的功能编写一个（失败的）测试。

```js
it('should have an header that says `Welcome`', () => {

  expect(document.querySelector('h1').innerText)

    .toContain('Welcome')

})

```

当我们启动测试时，我们应该看到它失败：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00132.jpg)

现在，不要太关注堆栈跟踪。你应该注意的重要事情是，我们有一个测试失败的名称（另一个测试仍然有效）。

在实现功能本身之前，编写测试并确保它失败是很重要的。要理解为什么，试着想象一下，我们在实现功能之前编写了测试，然后我们启动它，然后它成功了。这意味着测试实际上并没有起作用，因为我们从一开始就没有实现功能。

如果你认为这只是奇怪和不可能的，请再次思考。在实践中，经常发生这样的情况，一个看起来完全正常的测试实际上并没有测试任何东西，并且无论功能是否损坏，它总是成功的。

在这一点上，我们已经准备好实际实现功能了。我们编辑 HTML 布局，像这样：

```js
<div id="app">

  <h1>Welcome</h1>

  <p>{{greeting}}</p>

</div>

```

当我们启动页面时，结果应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00133.jpg)

# 为你的工作流添加一些 Karma

Karma 是一个 JavaScript 测试运行器。这意味着它将为您运行测试。软件往往会迅速增长，Karma 为您提供了一种同时运行所有单元测试的方法。它还为您提供了添加监视测试覆盖率和代码质量的工具的能力。

Karma 在 Vue 项目中传统上被使用，并且作为一个工具存在于官方 Vue 模板中。学习 Karma 是您 JavaScript 工具箱的一个很好的补充，即使您不使用 Vue 也是如此。

# 准备工作

我认为已经完成了“使用 Jasmine 测试 Vue”的先决条件。由于 Karma 是一个测试运行器，所以您应该首先能够编写测试。

在这个教程中，我们将使用 npm，所以在继续之前，请确保已经安装了它，并阅读有关如何使用它的基础知识。

# 如何操作...

对于这个教程，我们将需要命令行和 npm，所以在继续之前，请确保已经安装了它。

在一个新的文件夹中，创建一个名为`package.json`的文件，并在其中写入以下内容：

```js
{

  "name": "my-vue-project",

  "version": "1.0.0"

}

```

只要将此文件放在您的文件夹中，就会创建一个新的 npm 项目。我们稍后会编辑这个文件。

在命令行中，进入项目所在的目录，并在其中输入以下命令来安装必要的依赖项：

```js
npm install --save-dev vue karma jasmine karma-jasmine karma-chrome-launcher

```

这将安装 Vue 以及 Karma、Jasmine 和 Karma 的一些插件作为我们项目的依赖项。

如果您现在查看`package.json`，您会看到它已相应地更改。

下一个命令将创建一个名为`karma.conf.js`的文件，其中包含 Karma 的配置：

```js
./node_modules/karma/bin/karma init

```

这将询问您一些问题，除了询问源文件和测试文件的位置时，其他问题都选择默认值。对于该问题，只需写入`*.js`。完成后，您应该能够在目录中看到`karma.conf.js`文件。打开它并快速查看您通过回答问题设置的所有设置。

由于 Karma 不知道 Vue，您需要进行一些小的修改，将 Vue 添加为 Karma 的依赖项。有几种方法可以做到这一点；最快的方法可能是在要加载的文件列表中添加一行。在`karma.conf.js`文件中，在`files`数组中添加以下行：

```js
...    

    // list of files / patterns to load in the browser 

files:

 [ 

'node_modules/vue/dist/vue.js'

 **,** 

'*.js' 

 ],

... 

```

请注意，当您回答问题时，您也可以直接添加该行。

下一步是编写我们要测试的应用程序。

在您的文件夹中，创建一个名为`myApp.js`的文件；在其中写入以下内容：

```js
const myApp = {

  template: `

    <div>

      <p>{{greetings}}</p>

    </div>

  `,

  data: {

    greetings: 'Hello World'

  }

}

```

我们分配给`myApp`的对象只是一个简单的 Vue 实例。

接下来，我们将为其创建一个测试。具体来说，我们将检查组件中是否包含`Hello World`文本。

创建一个名为`test.js`的文件，并在其中写入以下内容：

```js
describe('my app', () => {

  beforeEach(() => {

    document.body.innerHTML = `

      <div id="app"></div>

    `

    new Vue(myApp)

      .$mount('#app')

  })

  it('should say Hello World', () => {

    expect(document.querySelector('p').innerText)

      .toContain('Hello World')

  })

})

```

`beforeEach`块将在每个测试之前运行（现在我们只有一个测试），在检查其他功能之前重置我们的 Vue 应用程序的状态。

现在，我们可以运行我们的测试了。在终端中输入以下命令：

```js
./node_modules/karma/bin/karma start

```

你应该看到 Chrome 启动，如果你回到命令行，你应该收到类似于以下消息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00134.jpg)

这意味着你的测试成功了。

# 工作原理...

在你的配方完成后，你应该注意你的应用程序的一般结构。你有应用程序本身在`myApp.js`中，然后你有你的测试在`test.js`中。你有一些配置文件，如`karma.conf.js`和`package.json`，你的库在`node_modules`目录中。所有这些文件一起工作，使你的应用程序可测试。

在一个真实的应用程序中，你可能会有更多的源代码和测试文件，而配置文件通常增长得更慢。

在整个设置中，你可能会想知道如何启动应用程序本身。毕竟，没有 HTML，我们只启动了测试；我们从来没有见过这个`Hello World`程序。

实际上，你是对的；这里没有要启动的程序。事实上，我们必须在测试的`beforeEach`中为 HTML 布局编写一个固定装置：

```js
beforeEach(() => {

  document.body.innerHTML = `

    <div id="app"></div>

  `

  new Vue(window.myApp)

    .$mount('#app')

})

```

在上述代码中，我们注入了 HTML，它只包含一个`<div>`元素（其余的布局在`myApp.js`中）在页面中。

然后，我们创建一个新的 Vue 实例，传递在`myApp.js`中定义的`myApp`变量中包含的选项对象；然后我们使用`$mount('#app')` Vue API，在我们刚刚注入的`<div>`元素中实际地实现应用程序。

# 还有更多...

每次从`node_modules`目录中调用 Karma 可能会很烦人。有两种方法可以使这更愉快：我们可以全局安装 Karma，或者我们可以将 Karma 添加到我们的 npm 脚本中；我们将两者都做。

首先，让我们将 Karma 添加到我们的 npm 脚本中。进入`package.json`文件，并添加以下代码块：

```js
...

"version": "1.0.0",

  "scripts": {

    "test": "./node_modules/karma/bin/karma start"

  },

"devDependencies": {

...

```

现在，你可以输入`npm run test`，Karma 将自动启动。接下来，我们可以使用以下命令全局安装 Karma：

```js
npm install -g karma

```

现在我们可以编写诸如`karma init`和`karma start`之类的命令，并且它们将被识别。我们还可以编辑我们的`package.json`，像这样：

```js
...

"version": "1.0.0",

  "scripts": {

    "test": "karma start"

  },

"devDependencies": {

...

```

# 测试应用程序的状态和方法

在这个示例中，我们将编写一个单元测试来直接触摸和检查我们的 Vue 实例的状态。测试组件状态的优势是我们不必等待 DOM 更新，即使 HTML 布局发生变化，状态变化也会慢得多，从而减少了测试所需的维护量。

# 准备工作

在尝试这个示例之前，您应该完成*将一些 Karma 添加到您的工作流程*，因为我们将描述如何编写测试，但我们不会提及测试环境的设置。

# 如何做...

假设我们有一个应用程序，它用`Hello World!`来问候您，但它还有一个按钮可以将问候语翻译成意大利语，即`Ciao Mondo!`。

为此，您需要在一个新文件夹中创建一个新的 npm 项目。在那里，您可以使用以下命令安装此示例所需的依赖项：

```js
npm install --save-dev vue karma jasmine karma-jasmine karma-chrome-

   launcher

```

要设置 Karma，就像在前一个示例中一样，运行以下命令：

```js
./node_modules/karma/bin/karma init

```

除了问题`您的源文件和测试文件的位置是什么？`，保留默认答案；对于这个问题，您应该用以下两行回答：

+   `node_modules/vue/dist/vue.js`

+   `*.js`

创建一个名为`test.js`的文件，并在其中编写一个`beforeEach`，以便将应用程序恢复到其起始状态，以便可以独立于其他测试进行测试：

```js
describe('my app', () => {

  let vm

  beforeEach(() => {

    vm = new Vue({

      template: `

        <div>

          <p>{{greetings}}</p>

          <button @click="toItalian">

            Translate to Italian

          </button>

        </div>

      `,

      data: {

        greetings: 'Hello World!'

      },

      methods: {

        toItalian () {

          this.greetings = 'Ciao Mondo!'

        }

      } 

    }).$mount()

  })

})

```

请注意，您在开始时声明了`vm`变量来引用我们的 Vue 实例。

在`beforeEach`之后（但在`describe`内部），添加以下（目前为空）测试：

```js
it(`should greet in Italian after

  toItalian is called`, () => {

})

```

在测试的第一部分中，您将使组件达到所需的状态（在调用`toItalian`之后）：

```js
it(`should greet in Italian after

    toItalian is called`, () => {

 vm.toItalian()

})

```

现在，我们想要检查问候语是否已更改：

```js
it(`should greet in Italian after

    toItalian is called`, () => {

  vm.toItalian()

 expect(vm.greetings).toContain('Ciao Mondo')

})

```

现在，为了证明每个测试之前状态都被重置了，添加以下内容：

```js
it('should greet in English', () => {

  expect(vm.greetings).toContain('Hello World')

})

```

如果状态真的被重置了，它应该包含英文问候语，如果你启动测试（使用`./node_modules/karma/bin/karma start`命令），你会发现（如果没有错误的话）确实是这样的。

# 工作原理...

由于我们有 Vue 实例本身的引用，我们可以直接在测试中访问方法和状态变量。

我希望你花一些时间欣赏测试的名称。第一个标题为`should greet in Italian after toItalian is called`。它没有提到页面或图形，并且没有对前提条件做任何假设。请注意，按钮从未被点击过，事实上，在测试标题中也没有提到按钮。

如果我们将测试标题命名为`should display 'Ciao Mondo' when Translate button is clicked on`，那么我们就会撒谎，因为我们从未检查问候语是否实际显示，并且我们在测试中从未点击按钮。

在真实应用程序中，正确命名测试非常重要，因为当你有成千上万个测试时，如果有一个测试失败，你首先读到的是标题或测试应该检查的内容。如果标题误导了，你将花费很多时间追逐一个错误的线索。

# 测试 DOM

在这个示例中，您将学习一种技术，可以快速测试 DOM 或网页本身是否符合预期，即使 Vue 组件不在页面中。

# 准备工作

对于这个示例，您应该已经有一个已经设置好并且工作正常的测试环境；如果您不知道这是什么意思，请完成*使用 Jasmine 进行 Vue 测试*示例。

我假设您已经安装了 Jasmine 并且可以执行测试。

基本上，您只需要一个网页（JSFiddle 可以）和这四个已安装的依赖项：

+   `jasmine.css`

+   `jasmine.js`

+   `jasmine-html.js`

+   `boot.js`

如果您正在使用 JSFiddle 或手动添加它们，请记住按指定的顺序添加它们。

在“使用 Jasmine 进行 Vue 测试”配方中找到这些文件的链接。

# 操作步骤如下：

假设您正在编写一个显示“Hello World！”问候语的组件；您希望测试该问候语是否实际显示，但您正在测试的网页已经足够复杂，您希望在隔离环境中测试您的组件。

事实证明，您不必实际显示组件来证明它的工作。您可以在文档之外显示和测试您的组件。

在您的测试文件或页面的测试部分中，编写以下设置来显示问候语：

```js
describe('my app', () => {

  let vm

  beforeEach(() => {

    vm = new Vue({

      template: '<div>{{greetings}}</div>',

      data: {

        greetings: 'Hello World'

      }

    })

  })

})

```

为了将我们的 Vue 实例实现为一个文档之外的元素，我们只需要添加`$mount()` API 调用：

```js
beforeEach(() => {

    vm = new Vue({

      template: '<div>{{greetings}}</div>',

      data: {

        greetings: 'Hello World'

      }

    }).$mount()

  })

```

由于我们有对`vm`的引用，我们现在可以测试我们的组件以访问在文档之外渲染的元素：

```js
it('should say Hello World', () => {

  expect(vm.$el.innerText).toContain('Hello World')

})

```

`vm.$el`元素代表我们的组件，但无法从正常的 DOM 中访问。

# 工作原理如下：

在初始化时，Vue 实例会检查是否有`el`选项。在我们的示例中，我们通常包含一个`el`选项，但这次我们有一个模板：

```js
vm = new Vue({

  template: '<div>{{greetings}}</div>',

  data: {

    greetings: 'Hello World'

  }

}).$mount()

```

当 Vue 实例具有`el`选项时，它会自动挂载到该元素（如果找到）；在我们的情况下，Vue 实例等待`$mount`调用。我们不提供任何参数给函数，因此组件会在文档之外渲染。

此时，从 DOM 中检索它的唯一方法是通过`$el`属性。一旦组件被挂载，`$el`属性始终存在，无论组件是手动挂载还是自动挂载。

从那里，我们可以像访问任何普通组件一样访问它，并测试一切是否符合我们的预期。

# 测试 DOM 的异步更新。

在 Vue 中，当组件的状态发生变化时，DOM 会相应地发生变化；这就是为什么我们称之为响应式状态的原因。唯一需要注意的是，更新不是同步的；我们必须等待额外的时间来实际传播这些变化。

# 准备中

对于这个配方，我假设你已经完成了“使用 Jasmine 进行 Vue 测试”的配方，并且知道如何编写基本测试。

# 如何做到这一点...

我们将编写的测试是 Vue 更新机制工作原理的示例。从那里，您将能够自己编写异步测试。

在我们的测试套件的`beforeEach`函数中，编写以下 Vue 实例：

```js
describe('my app', () => {

  let vm

  beforeEach(() => {

    vm = new Vue({

      template: `

        <div>

          <input id="name" v-model="name">

          <p>Hello from 

            <span id="output">{{name}}</span>

          </p>

        </div>

      `,

      data: {

        name: undefined

      }

    }).$mount()

  })

})

```

这将创建一个组件，其中包含一个文本框和一个 span 元素，该 span 元素将包含`Hello from ...`短语以及文本框中输入的任何内容。

我们将如何测试这个组件是，在文本框中编写`Herman`（通过编程方式，而不是手动），然后等待 DOM 更新。当 DOM 更新后，我们检查是否出现了`Hello from Herman`这个短语。

让我们从`beforeEach`函数之后的一个空测试开始：

```js
it('should display Hello from Herman after Herman is typed in the text-box', done => {

  done()

})

```

前面的测试已经通过了。请注意，我们正在接收`done`参数，然后将其作为函数调用。只有在调用`done()`之后，测试才会通过。

将`<span>`元素分配给一个变量以方便操作，然后将文本`Herman`插入到文本框中。

```js
it('should display Hello from Herman after Herman is typed in the text-box', done => {

 const outputEl = vm.$el.querySelector('#output')

 vm.$el.querySelector('#name').value = 'Herman'

  done()

})

```

当我们修改状态时，我们必须等待 DOM 更新，但反之则不然；当我们修改了 DOM 时，我们可以立即检查`name`变量是否已更改。

```js
it('should display Hello from Herman after Herman is typed in the text-box', done => {

  const outputEl = vm.$el.querySelector('#output')

  vm.$el.querySelector('#name').value = 'Herman'

 expect(vm.name = 'Herman')

  done()

})

```

在您编辑测试时，启动它以检查是否正常工作。

接下来，我们将为`Vue`组件的下一个更新周期安装一个监听器，称为 tick。

```js
it('should display Hello from Herman after Herman is typed in the text-box', done => {

  const outputEl = vm.$el.querySelector('#output')

  vm.$el.querySelector('#name').value = 'Herman'

  expect(vm.name = 'Herman')

 vm.$nextTick(() => {

    done()

 })

})

```

`$nextTick`块中的所有内容只有在 DOM 更新后才会运行。我们将检查`<span>`元素的内容是否已更改。

```js
it('should display Hello from Herman after Herman is typed in the text-box', done => {

  const outputEl = vm.$el.querySelector('#output')

  vm.$el.querySelector('#name').value = 'Herman'

 expect(outputEl.textContent).not.toContain('Herman')

  expect(vm.name = 'Herman')

  vm.$nextTick(() => {

 expect(outputEl.textContent).toContain('Herman')

    done()

  })

})

```

请注意，在进行下一次操作之前，我们还会验证 DOM 是否未更改。

# 工作原理如下...

官方文档中指出：

<q>Vue 以**异步**方式执行 DOM 更新。每当观察到数据变化时，它将打开一个队列并缓冲在同一事件循环中发生的所有数据变化。</q>

因此，许多测试需要使用`$nextTick`辅助函数。然而，目前正在努力创建更好的工具来处理测试和同步性，因此，尽管本文档说明了问题，但可能不是处理测试的最新方法。

# 使用 Nightwatch 进行端到端测试

有时单元测试并不能满足需求。我们可能需要集成两个独立开发的功能，并且尽管每个功能都经过了单元测试并且可以正常工作，但没有简单的方法来同时测试它们。此外，这也违背了单元测试的目的-测试软件的原子单元。在这种情况下，可以进行集成测试和端到端（end-to-end）测试。Nightwatch 是一种模拟用户在网站上点击和输入的软件。这可能是我们想要的最终验证整个系统是否正常工作的方式。

# 准备工作

在开始进行这个稍微高级的示例之前，您应该已经熟悉命令行和 npm。如果您对它们不熟悉，请查看*选择开发环境*示例。

# 操作步骤...

为这个示例创建一个新文件夹，并在其中创建一个名为`index.html`的新文件。

这个文件将包含我们的 Vue 应用程序，也是我们要测试的内容。在这个文件中写入以下内容：

```js
<!DOCTYPE html>

<html>

<head>

  <title>Nightwatch tests</title>

  <script src="https://unpkg.com/vue/dist/vue.js"></script>

</head>

<body>

  <div id="app">

  </div>

  <script>

  </script>

</body>

</html>

```

正如您所看到的，这只是一个小型 Vue 应用程序的常规样板。在`<div>`标签内放置一个标题和一个按钮；当我们点击按钮时，将显示文本`Hello Nightwatch!`：

```js
<div id="app">

  <h2>Welcome to my test page</h2>

  <button @click="show = true">Show</button>

  <p v-show="show">Hello Nightwatch!</p>

</div>

```

在`<script>`标签内，写入以下 JavaScript 代码使其工作：

```js
<script>

  const vm = new Vue({

    el: '#app',

    data: {

      show: false

    }

  })

</script>

```

我们的应用程序已经完成；现在我们进入了示例的测试部分。

执行以下命令来安装您的依赖项：

```js
npm install -g selenium-standalone http-server nightwatch

```

这将安装 Selenium 服务器，这是自动化浏览器操作所必需的，也是使 nightwatch 工作的真正原因。`http-server`命令将有助于在不必记住长文件路径的情况下提供我们的工作网站。最后，它将安装 nightwatch 本身，它在很大程度上是 Selenium 的包装器和 JavaScript API。

当 npm 完成安装所有这些工具后，创建一个名为`nightwatch.json`的新文件，其中包含 nightwatch 的配置，并在其中写入以下内容：

```js
{

  "src_folders" : ["tests"],

  "test_settings" : {

    "default" : {

      "desiredCapabilities": {

        "browserName": "chrome"

      }

    }

  }

}

```

第一个设置表示您将在名为 tests 的文件夹中编写所有测试（我们将创建该文件夹）；第二个设置只是将 Chrome 设置为我们运行测试的默认浏览器。

现在，在`test`目录下创建一个`test.js`文件。在该文件中，我们将测试应用程序。我们将验证当应用程序启动时，`<p>`标签是不可见的，并且当我们点击按钮时，它应该出现。

一个空的测试看起来像这样：

```js
module.exports = {

  'Happy scenario' :client => {}

}

```

在这里，客户端是浏览器（在本例中为 Chrome）。

我们将在`http://localhost:8080`地址上提供我们的应用程序，所以首先我们希望浏览器转到这个地址。为此，我们将编写以下代码：

```js
module.exports = {

  'Happy scenario' :client => {

    client

 .url('http://localhost:8080')

  }

}

```

接下来，我们等待页面加载；我们通过等待具有`id="app"`的`<div>`出现来间接实现这一点：

```js
module.exports = {

  'Happy scenario' :client => {

    client

      .url('http://localhost:8080')

 .waitForElementVisible('#app', 1000)

  }

}

```

第二个参数是在考虑测试失败之前愿意等待的毫秒数。

接下来，我们希望确保标题也正确显示，并且没有可见的`<p>`元素：

```js
module.exports = {

  'Happy scenario' :client => {

    client

      .url('http://localhost:8080')

      .waitForElementVisible('#app', 1000)

      .assert.containsText('h2', 'Welcome to')

 .assert.hidden('p')

  }

}

```

然后，我们点击按钮并断言`<p>`元素是可见的并且包含单词`Nightwatch`：

```js
module.exports = {

  'Happy scenario' :client => {

    client

      .url('http://localhost:8080')

      .waitForElementVisible('#app', 1000)

      .assert.containsText('h2', 'Welcome to')

      .assert.hidden('p')

      .click('button')

 .waitForElementVisible('p', 1000)

 .assert.containsText('p', 'Nightwatch')

 .end();

  }

}

```

`end()`函数将标记测试已成功，因为没有更多需要检查的内容。

要实际运行此测试，您需要运行以下命令：

```js
selenium-standalone install

```

这将安装 Selenium，然后打开三个不同的命令行。在第一个命令行中，使用以下命令启动 Selenium 服务器：

```js
selenium-standalone start

```

在第二个命令行中，进入你的食谱文件夹的根目录，即`index.html`所在的位置，并启动`http-server`：

```js
http-server .

```

启动后，它会告诉你你的网站在`http://localhost:8080`上提供服务。这就像我们在测试中写的地址一样。你现在可以导航到该地址查看应用程序的运行情况：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00135.jpg)

最后，在第三个命令行中，再次进入你的食谱文件夹，并输入以下命令：

```js
nightwatch

```

如果一切顺利，你会看到浏览器在你眼前闪烁，并在一瞬间（取决于你的计算机速度）显示应用程序，在控制台中，你应该看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00136.jpg)

# 工作原理...

如果这个食谱看起来很费劲，不要灰心，Vue 模板已经在其中解决了所有的设置。你知道所有这些机制是如何工作的，但是当我们在后面的食谱中使用 Webpack 时，你只需要一个命令来运行端到端测试，因为一切都已经设置好了。

注意端到端测试的标题是相当通用的，它指的是一个特定的操作流程，而不是详细描述上下文和期望的内容。这在端到端测试中很常见，因为通常最好先构建用户故事，然后将它们分支，并为每个分支命名一个特定的场景。所以，举个例子，如果我们期望从服务器得到一个响应，但没有返回，我们可以测试一个场景，在这个场景中我们会出现一个错误，并将测试称为*服务器错误场景*。

# 在 nightwatch 中模拟双击

这个食谱对于那些在 nightwatch 中模拟双击而苦苦挣扎的人来说是一种享受。作为其中之一，我对此表示同情。事实证明，在 nightwatch 中有一个`doubleClick`函数，但至少在作者的意见中，它并不像预期的那样工作。

# 准备就绪

这个配方适用于刚开始使用 nightwatch 并且在这个特定问题上遇到困难的开发人员。你想学习如何模拟双击进行测试，但你不了解 nightwatch 吗？回到上一个配方。

我假设你已经设置好了 nightwatch，并且可以启动测试。我还假设你已经安装了前面配方中的所有命令。

# 工作原理...

假设你有一个 Vue 应用程序，它在一个`index.html`文件中：

```js
<!DOCTYPE html>

<html>

<head>

  <title>7.6</title>

  <script src="https://unpkg.com/vue/dist/vue.js"></script>

</head>

<body>

  <div id="app">

    <h2>Welcome to my test page</h2>

    <button id="showBtn" @dblclick="show = true">

      Show

    </button>

    <p v-show="show">Hello Nightwatch!</p>

  </div>

</body>

</html>

```

在`<div>`元素之后，添加以下脚本：

```js
<script>

  const vm = new Vue({

    el: '#app',

    data: {

      show: false

    }

  })

</script>

```

你可以使用`http-server`来提供你的应用程序。在浏览器中打开`http://localhost:8080`，然后尝试双击按钮以使文本出现。

现在，如果我们想要测试这个，我们查看 nightwatch 的 API，发现它有一个名为`doubleClick()`的函数调用。

然后我们可以编写一个类似于前面配方中的测试：

```js
'Happy scenario' : function (client) {

  client

    .url('http://localhost:8080')

    .waitForElementVisible('#app', 1000)

    .assert.containsText('h2', 'Welcome to')

    .assert.hidden('p')

    .doubleClick('button') // not working

    .waitForElementVisible('p', 1000)

    .assert.containsText('p', 'Nightwatch')

    .end();

 }

```

除了这个不会按预期工作。正确的方法是：

```js
'Happy scenario' : function (client) {

  client

    .url('http://localhost:8080')

    .waitForElementVisible('#app', 1000)

    .assert.containsText('h2', 'Welcome to')

    .assert.hidden('p')

    .moveToElement('tag name', 'button', 0, 0)

 .doubleClick()

    .waitForElementVisible('p', 1000)

    .assert.containsText('p', 'Nightwatch')

    .end();

 }

```

只有在你首先*移动*到你想要双击的元素上时，双击才起作用；只有这样，你才能调用`doubleClick`而不带任何参数。

# 工作原理...

`moveToElement`函数的参数如下：

+   `selector`：我们使用`tag name`作为选择器

+   `tag` / `selector`：我们寻找`button`标签；如果我们在这里使用了另一个选择器，我们会使用不同的格式

+   `xoffset`：这是虚拟鼠标在 x 坐标上的位置；对我们来说，0 是可以的，因为即使在按钮的边缘，点击也是有效的

+   `yoffset`：这与前面的参数类似，但在 y 轴上

在正确位置后，有一系列的命令可以释放事件。我们使用了`doubleClick`，但还有其他命令。

# 不同风格的单元测试

我们在之前的示例中发现并使用了 Jasmine。在这个示例中，我们将探索和比较不同的单元测试风格。这是特别相关的，因为 Vue 模板预装了 Mocha 和 Chai。Chai 使您能够以三种不同的风格编写测试。

# 准备工作

这个示例不需要任何特定的先前知识，但我强烈建议您完成“使用 Jasmine 进行 Vue 测试”的示例。

# 操作步骤

为了使这个示例工作，您需要两个依赖项：Mocha 和 Chai。您可以在 Google 上很快找到它们；只需记住，Mocha 有两个不同的文件：`mocha.js`和`mocha.css`。如果您希望显示得漂亮，您必须同时添加它们。

如果您正在使用 JSFiddle，请按照通常的方式继续；否则，请确保依赖项中也有 Vue。

我们的 HTML 布局将如下所示：

```js
<div id="app">

  <p>{{greeting}}</p>

</div>

<div id="mocha">

</div>

```

mocha 部分是显示所有结果的地方。

在 JavaScript 部分，编写最简单的`Vue`应用程序并将其分配给一个变量：

```js
const vm = new Vue({

  el: '#app',

  data: {

    greeting: 'Hello World!'

  }

})

```

我们将编写一个测试来查看`Hello world`文本是否真的被显示出来。

在`Vue`应用程序完成后，写入以下内容：

```js
mocha.setup('bdd')

chai.should()

describe('my app', () => {

  it('should say Hello World', () => {

    vm.$el.innerText.should.contain('Hello World')

  })

})

mocha.run()

```

上述代码准备了`mocha`和`chai`（通过安装`describe`，`it`和`should`函数），然后断言我们组件的内部文本应该包含`Hello World`。相当易读，不是吗？

您可以启动应用程序，然后您将看到这个：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00137.jpg)

chai 还允许我们以另外两种方式编写完全相同的测试。第一种方式如下所示：

```js
 vm.$el.innerText.should.contain('Hello World')

```

要使用第二种方式，您必须在之前添加`const expect = chai.expect`：

```js
expect(vm.$el.innerText).to.contain('Hello World')

```

最后，在之前添加`const assert = chai.assert`行：

```js
assert.include(vm.$el.innerText,

  'Hello World',

  'Component innerText include Hello World')

```

在 assert 风格中，将消息作为附加参数添加是惯用的做法，以使测试在出现问题时更加详细。

# 它是如何工作的...

Chai 是一个简单的库，它实现了一些函数，并在某些条件不满足时抛出异常。另一方面，Mocha 运行某些代码片段，收集异常，并尝试以友好的方式向用户显示它们。

虽然使用哪种风格主要是品味问题，但这三种风格之间存在一些细微的差别。

+   `Should`更加雄辩和可读。不幸的是，它扩展了`Object`，将`should`函数添加到了所有对象上。如果你不知道如何对待最后一句话，你不应该介意，但正确的行为方式是奔跑并尖叫痛苦；永远不要扩展`Object`。

+   `Assert`意味着对每个断言编写详细的描述，如果你为每个测试编写多个断言，这通常是很好的。就个人而言，我认为每个测试最多只应该有一个断言，并且应该集中在标题上进行描述。

+   `Expect`不扩展`Object`，非常可读且平衡良好，通常我更喜欢使用它而不是其他替代方案。

# 使用 Sinon.JS 进行外部 API 调用的存根化

通常，在进行端到端测试和集成测试时，您将运行并准备好后端服务器以响应您的请求。我认为有很多情况下这是不可取的。作为前端开发人员，您会抓住每一个机会责怪后端人员。

# 准备工作

完成这个示例不需要特殊的技能，但您应该将 Jasmine 安装为依赖项；这在*使用 Jasmine 进行 Vue 测试*示例中有详细说明。

# 如何操作...

首先，让我们安装一些依赖项。对于这个示例，我们将使用 Jasmine 来运行整个测试；您可以在*使用 Jasmine 进行 Vue 测试*示例中找到详细的说明（这四个文件分别是`jasmine.css`，`jasmine.js`，`jasmine-html.js`和`boot.js`，按照这个顺序）。

在继续之前，还要安装 Sinon.JS 和 Axios；您只需要添加与它们相关的`js`文件。

我们将构建一个在点击按钮时检索帖子的应用程序。在 HTML 部分中，编写以下内容：

```js
<div id="app">

  <button @click="retrieve">Retrieve Post</button>

  <p v-if="post">{{post}}</p>

</div>

```

相反，JavaScript 部分将如下所示：

```js
const vm = new Vue({

  el: '#app',

  data: {

    post: undefined

  },

  methods: {

  retrieve () {

    axios

      .get('https://jsonplaceholder.typicode.com/posts/1')

      .then(response => {

        console.log('setting post')

        this.post = response.data.body

      })

    }

  }

})

```

如果您现在启动应用程序，应该能够看到它正在工作：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00138.jpg)

现在我们想要测试应用程序，但我们不想连接到真实的服务器。这将需要额外的时间，并且不可靠；相反，我们将从服务器获取一个正确的样本响应并使用它。

Sinon.JS 有一个沙盒的概念。这意味着每当一个测试开始时，一些依赖项（如 Axios）都会被覆盖。每个测试结束后，我们可以丢弃沙盒，一切都恢复正常。

使用 Sinon.JS 的空测试如下所示（在`Vue`实例之后添加）：

```js
describe('my app', () => {

  let sandbox

  beforeEach(() => sandbox = sinon.sandbox.create())

  afterEach(() => sandbox.restore())

})

```

我们想要为 axios 的`get`函数存根调用：

```js
describe('my app', () => {

  let sandbox

  beforeEach(() => sandbox = sinon.sandbox.create())

  afterEach(() => sandbox.restore())

  it('should save the returned post body', done => {

    const promise = new Promise(resolve => 

 resolve({ data: { body: 'Hello World' } })

 )

 sandbox.stub(axios, 'get').returns(promise)

 ...

 done()

 })

})

```

我们在这里覆盖了 axios。我们说现在`get`方法应该返回`resolved`的 promise：

```js
describe('my app', () => {

  let sandbox

  beforeEach(() => sandbox = sinon.sandbox.create())

  afterEach(() => sandbox.restore())

 it

('

should save the returned post body'

,

 done

 =>

 {

    const promise = new Promise(resolve => 

      resolve({ data: { body: 'Hello World' } })

    )

    sandbox

.

stub

(

axios

,

 'get'

).

returns

(

promise

)

    vm

.

retrieve

()

    promise.then(() => {

      expect

(

vm

.

post

).

toEqual

(

'Hello World'

)

      done

()

    }) 

  }) 

})

```

由于我们返回了一个 promise（我们需要返回一个 promise，因为`retrieve`方法正在调用它的`then`方法），所以我们需要等待它解析。

我们可以启动页面并查看它是否工作：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00139.jpg)

如果您使用 JSFiddle，请记住将加载类型设置为 No wrap - in `<body>`，否则 Vue 将没有机会启动。

# 它是如何工作的...

在我们的案例中，我们使用沙盒来存根其中一个依赖项的方法。这样，axios 的`get`方法就不会被触发，我们会收到一个类似于后端将给我们的对象。

存根 API 响应将使您与后端及其怪癖隔离开来。如果出现问题，您不会在意，而且您可以在不依赖于后端正确运行的情况下运行测试。

有许多库和技术可以存根 API 调用，不仅与 HTTP 相关。希望这个示例为您提供了一个起步。

# 测量代码的覆盖率

代码覆盖率是评估软件质量最常用和易于理解的指标之一。如果一个测试执行了特定的代码部分，那么该代码被认为是被覆盖的。这意味着该特定代码部分正常工作且包含错误的可能性较小。

# 准备就绪

在测量代码覆盖率之前，请确保完成“将一些 Karma 添加到你的工作流程”这个步骤，因为我们将使用 Karma 来帮助我们。

# 如何操作...

创建一个新目录，并在其中放置一个名为`package.json`的文件。在其中写入以下内容：

```js
{

 "name": "learning-code-coverage",

 "version": "1.0.0"

}

```

这将创建一个 npm 项目。在同一目录中，运行以下命令来安装我们的依赖项：

```js
npm install vue karma karma jasmine karma-jasmine karma-coverage karma-chrome-launcher --save-dev

```

`package.json`文件会相应地更改。

`karma-coverage`插件使用底层软件 Istanbul 来测量和显示我们的测试覆盖率。

为了使下一步更容易一些，我们将全局安装 Karma（如果你还没有安装）。运行以下命令：

```js
npm install -g karma

```

当安装了 Karma 后，在你的目录中运行以下命令；它将创建一个 Karma 配置文件：

```js
karma init

```

除非它要求你加载文件，否则回答所有问题的默认值；在这种情况下，写下以下两行：

+   `node_modules/vue/dist/vue.js`

+   `*.js`

在此之后留一个空行以确认。

这将加载 Vue 和以`js`扩展名结尾的所有文件到目录的根目录中。

打开 Karma 创建的文件；它应该被称为`karma.conf.js`，并且应该与其他文件一起在你的目录中。

应该有一个类似以下的部分：

```js
preprocessors: {

},

```

在 preprocessors 对象中，插入 coverage，如下所示：

```js
preprocessors: {

  'myApp.js': ['coverage']

},

```

这意味着我们想要使用 coverage 预处理器对`myApp.js`文件进行预处理。`myApp.js`文件将包含我们要测试的应用程序。

紧接着，在`reporters`数组中添加 coverage：

```js
reporters: ['progress', 'coverage'

],

```

这将使 coverage 报告生成一个包含覆盖率测量的网页。

为了使设置正常工作，您需要在`frameworks`和`files`之间设置另一个属性，称为`plugins`：

```js
plugins: [

 'karma-jasmine',

 'karma-coverage',

 'karma-chrome-launcher'

],

```

接下来，我们将编写一个简单的 Vue 应用程序进行测试。

创建一个名为`myApp.js`的文件；我们将创建一个猜数字游戏。

在文件中写入以下内容：

```js
const myApp = {

  template: `

    <div>

      <p>

        I am thinking of a number between 1 and 20.

      </p>

      <input v-model="guess">

      <p v-if="guess">{{output}}</p>

    </div>

  `

}

```

用户将输入一个数字，输出将显示一个提示或者一个文本来庆祝胜利，如果数字正确。将以下状态添加到`myApp`对象中：

```js
data: {

  number: getRandomInt(1, 20),

  guess: undefined

}

```

在文件的顶部，您可以添加一个名为`getRandomInt`的函数，如下所示：

```js
function getRandomInt(min, max) {

  return Math.floor(Math.random() * (max - min)) + min;

}

```

我们还需要一个计算属性来显示提示：

```js
computed: {

  output () {

    if (this.guess < this.number) {

      return 'Higher...'

    }

    if (this.guess > this.number) {

      return 'Lower...'

    }

    return 'That's right!'

  }

}

```

我们的应用程序已经完成。让我们测试一下它是否按预期工作。

在目录的根目录下创建一个名为`test.js`的文件，并编写以下测试：

```js
describe('my app', () => {

  let vm

  beforeEach(() => {

    vm = new Vue(myApp).$mount()

    vm.number = 5

  })

  it('should output That's right! if guess is 5', () => {

    vm.guess = 5

    expect(vm.output).toBe('That's right!')

  })

})

```

要运行测试，请使用以下命令：

```js
karma start

```

如果前面的命令在已经安装了`karma-coverage`插件的情况下没有要求安装该插件，您可以全局安装插件，或者使用本地安装的 Karma 从`./node-modules/karma/bin/karma start`运行测试。

如果您的浏览器打开了，请返回控制台，当测试完成时，按下*Ctrl* + *C*停止 Karma。

如果一切顺利，您应该会看到一个名为 coverage 的新文件夹，其中包含一个名为 Chrome 的目录。您还应该在其中找到一个名为`index.html`的文件。打开它，您会看到一个类似于这样的页面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00140.jpg)

从一开始，我们就可以看到黄色表示出现了问题。我们测试了 100％的函数，但只测试了 50％的 if 分支。

如果您浏览并打开`myApp.js`文件的详细信息，您会发现我们没有测试`if`语句的两个分支：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00141.jpg)

这些分支内部可能会出现错误，我们甚至可能不知道！

尝试在测试文件中添加以下两个测试：

```js
it('should output Lower... if guess is 6', () => {

  vm.guess = 6

  expect(vm.output).toBe('Lower...')

})

it('should output Higher... if guess is 4', () => {

  vm.guess = 4

  expect(vm.output).toBe('Higher...')

})

```

现在，如果您运行测试并打开报告，它看起来会更加绿色：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00142.jpg)

# 工作原理如下...

我们甚至没有打开应用程序，但我们已经非常确定它能正常工作，这要归功于我们的测试。

此外，我们有一份报告显示我们覆盖了 100%的代码。尽管我们只测试了猜数字游戏的三个数字，但我们覆盖了所有可能的分支。

我们永远无法确定我们的软件没有错误，但这些工具对我们开发人员在添加功能到我们的软件时非常有帮助，而不必担心可能会出现问题。


# 第七章：组织+自动化+部署=Webpack

在本章中，我们将讨论以下主题：

+   从组件中提取逻辑以保持代码整洁

+   使用 Webpack 打包您的组件[预览](https://cdp.packtpub.com/vue_js_2_cookbook/wp-admin/post.php?post=70&action=pdfpreview)

+   使用 Webpack 组织您的依赖项

+   在 Webpack 项目中使用外部组件

+   使用热重载进行连续反馈的开发

+   使用 Babel 编译 ES6

+   在开发过程中运行代码检查器

+   只使用一个命令构建压缩和开发.js 文件

+   将您的组件发布到公共场所

# 引言

Webpack 与 npm 结合是一个非常强大的工具。本质上，它只是一个打包工具，将一些文件及其依赖项打包成一个或多个可消费的文件。它现在已经进入第二个版本，并且对于 Vue 开发人员来说比以前更重要。

Webpack 将使您能够方便地在单个文件中编写组件，并可通过命令进行发布。它将使您能够使用不同的 JavaScript 标准，如 ES6，以及其他语言，这都要归功于**加载器**，这个概念将在后续的示例中反复出现。

# 从组件中提取逻辑以保持代码整洁

Vue 组件有时可能变得非常复杂。在这些情况下，最好将它们拆分并尝试使用抽象隐藏一些复杂性。放置此类复杂性的最佳位置是外部 JavaScript 文件。这样做的好处是，如果需要的话，更容易与其他组件共享提取的逻辑。

# 准备工作

这个示例是中级水平的。在来到这里之前，您应该已经完成了第一章中的“选择开发环境”示例，以及“开始使用 Vue.js”，并且应该知道如何使用 npm 设置项目。

还要确保您已经全局安装了`vue-cli`包，使用以下命令：

```js
npm install -g vue-cli

```

# 如何做...

我们将构建一个复利计算器；您将发现在初始投资后您将拥有多少钱。

# 创建一个干净的 Webpack 项目

创建一个新目录，并使用以下命令在其中创建一个新的`Vue`项目：

```js
vue init webpack

```

您可以选择问题的默认值。

运行`npm install`来安装所有所需的依赖项。

然后，导航到目录结构中的`src/App.vue`，并删除文件中的几乎所有内容。

最终结果应该如下所示：

```js
<template>

  <div id="app">

  </div>

</template>

<script>

export default {

  name: 'app'

}

</script>

<style>

</style>

```

我已经为您完成了这个任务，您可以使用以下命令来使用另一个模板：

`vue init gurghet/webpack`

# 构建复利计算器。

要构建复利计算器，您需要三个字段：初始资本或本金、年利率和投资期限。然后，您将添加一个输出字段来显示最终结果。以下是相应的 HTML 代码：

```js
<div id="app">

  <div>

    <label>principal capital</label>

    <input v-model.number="principal">

  </div>

  <div>

    <label>Yearly interestRate</label>

    <input v-model.number="interestRate">

  </div>

  <div>

    <label>Investment length (timeYears)</label>

    <input v-model.number="timeYears">

  </div>

  <div>

    You will gain:

    <output>{{final}}</output>

  </div>

</div>

```

我们使用`.number`修饰符，否则我们放入的数字将被 JavaScript 转换为字符串。

在 JavaScript 部分，通过编写以下代码声明三个模型变量：

```js
export default {

  name: 'app',

  data () {

    return {

      principal: 0,

      interestRate: 0,

      timeYears: 0

    }

  }

}

```

为了计算复利，我们采用数学公式：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00143.gif)

在 JavaScript 中，可以这样写：

```js
P * Math.pow((1 + r), t)

```

您需要将此添加到`Vue`组件中作为计算属性，如下所示：

```js
computed: {

  final () {

    const P = this.principal

    const r = this.interestRate

    const t = this.timeYears

    return P * Math.pow((1 + r), t)

  }

}

```

您可以使用以下命令运行应用程序（从您的目录启动）：

```js
npm run dev

```

现在我们的应用程序可以工作了，您可以看到将 0.93 美元存入一个年利率为 2.25%的银行账户并沉睡 1000 年后我们将获得多少钱（43 亿美元！）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00144.jpg)

目前，代码中的公式并不重要。但是，如果我们有另一个组件也执行相同的计算，我们也希望更明确地表明我们正在计算复利，而不关心此范围内的公式实际上是什么。

在`src`文件夹中创建一个名为`compoundInterest.js`的新文件；在其中编写以下代码：

```js
export default function (Principal, yearlyRate, years) {

  const P = Principal

  const r = yearlyRate

  const t = years

  return P * Math.pow((1 + r), t)

}

```

然后相应地修改`App.vue`中的代码：

```js
computed: {

  final () {

    return compoundInterest(

 this.principal,

 this.interestRate,

 this.timeYears

 )

  }

}

```

另外，请记住在 JavaScript 部分的顶部导入我们刚刚创建的文件：

```js
<script>

 import compoundInterest from './compoundInterest'

  export default {

  ...

```

# 它是如何工作的...

在组件中工作或者一般编程时，将代码的范围减小到只有一个抽象层级会更好。当我们编写一个计算函数来返回最终的资本值时，我们只需要担心调用正确的函数-适用于我们目的的函数。公式的内部在更低的抽象层级上，我们不想处理它。

我们所做的是将所有繁琐的计算工作放在一个单独的文件中。然后，我们使用以下代码从文件中导出函数：

```js
export default function (Principal, yearlyRate, years) {

...

```

这样，当我们从`Vue`组件导入文件时，默认情况下该函数可用：

```js
import compoundInterest from './compoundInterest'

...

```

所以，现在`compoundInterest`是我们在另一个文件中定义的函数。此外，这种关注点的分离使我们能够在代码的任何地方使用此函数来计算复利，甚至在其他文件中（潜在地也可以是其他项目中）。

# 使用 Webpack 打包您的组件

Webpack 允许您将项目打包成压缩的 JavaScript 文件。然后，您可以分发这些文件或自己使用它们。当您使用`vue-cli`附带的内置模板时，Webpack 会配置为构建一个完整的工作应用程序。有时我们想要构建一个库以发布或在另一个项目中使用。在这个示例中，您将调整 Webpack 模板的默认配置以发布一个组件。

# 准备工作

只有在您安装了 npm（参考第一章中的*选择开发环境*示例，*开始使用 Vue.js*）并熟悉`vue-cli`和 Webpack 模板后，这个示例才会有意义。

# 如何做...

对于这个教程，您将构建一个可重用的组件，可以抖动您放入其中的任何内容；为此，我们将使用优秀的 CSShake 库。

基于 Webpack 模板创建一个新的干净项目。您可以查看之前的教程来了解如何做到这一点，或者您可以使用我制作的预构建模板。您可以通过创建一个新目录并运行此命令来使用我的模板：

```js
vue init gurghet/webpack

```

如果您不知道它们的含义，请选择默认答案。记得运行`npm install`来引入依赖项。

首先，让我们重命名一些东西：将`App.vue`文件重命名为`Shaker.vue`。

在其中，将以下内容作为 HTML 模板写入：

```js
<template>

  <span id="shaker" class="shake">

    <link rel="stylesheet" type="text/css" href="https://csshake.surge.sh/csshake.min.css">

    <slot></slot>

  </span>

</template>

```

请注意，与原始模板相比，我们将`<div>`更改为`<span>`。这是因为我们希望我们的抖动器成为一个内联组件。

组件本身已经完成了；我们只需要在 JavaScript 部分进行一些微小的美化编辑：

```js
<script>

  export default {

    name: 'shaker

'

  }

</script>

```

为了手动测试我们的应用程序，我们可以按照以下方式修改`main.js`文件（突出显示的文本是修改后的代码）：

```js
// The Vue build version to load with the `import` command

// (runtime-only or standalone) has been set in webpack.base.conf with an alias.

import Vue from 'vue'

import Shaker from './Shaker'

/* eslint-disable no-new */

new Vue({

  el: '#app',

 template: `

    <div>

      This is a <Shaker>test</Shaker>

    </div>

  `, 

  components: { Shaker

 }

})

```

这将创建一个示例页面，如下图所示，在其中我们可以使用热重载来原型化我们的组件。通过运行以下命令来启动它：

```js
npm run dev

```

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00145.jpg)

将光标放在单词`test`上应该使其抖动。

现在，我们希望将此组件打包到一个单独的 JavaScript 文件中，以便将来可以重用。

默认模板中没有此配置，但很容易添加一个。

首先，在`build`文件夹中的`webpack.prod.js`文件中进行一些修改。

让我们摆脱一些我们在发布库时不需要的插件；找到文件中的`plugins`数组。它是一个包含以下代码形式的插件数组：

```js
plugins: [

  new Plugin1(...),

  new Plugin2(...),

  ...

  new PluginN(...)

]

```

我们只需要以下插件：

+   `webpack.DefinePlugin`

+   `webpack.optimize.UglifyJsPlugin`

+   `webpack.optimize.OccurrenceOrderPlugin`

摆脱所有其他插件，因为我们不需要它们；最终的数组应该是这样的：

```js
plugins: [

  new webpack.DefinePlugin({

    'process.env': env

  }),

  new webpack.optimize.UglifyJsPlugin({

    compress: {

      warnings: false

    }

  }),

  new webpack.optimize.OccurrenceOrderPlugin()

]

```

第一个允许您添加一些其他配置，第二个插件将文件进行了缩小，第三个插件将优化生成文件的大小。

我们还需要编辑的另一个属性是`output`，因为我们希望简化输出路径。

原始属性如下所示：

```js
output: {

  path: config.build.assetsRoot,

  filename: utils.assetsPath('js/[name].[chunkhash].js'),

  chunkFilename: utils.assetsPath('js/[id].[chunkhash].js')

}

```

原始代码会创建一个`js`目录中的一系列输出文件。方括号中有一些变量；因为您只有一个自包含模块用于我们的应用程序，我们将其称为*shaker*。我们需要获得以下代码：

```js
output: {

  path: config.build.assetsRoot,

 filename: utils.assetsPath('shaker.js') 

}

```

由于，正如刚才所说，您希望组件是自包含的，我们需要进行一些其他的修改，这也取决于您的需求。

如果您希望组件内置任何 CSS 样式（在我们的情况下，我们使用的是外部 CSS 库），您应该禁用`ExtractTextPlugin`；我们已经从列表中删除了该插件，但仍有其他文件在使用它。在`vue-loader.conf.js`文件中找到`extract`选项（某些版本中的`vue`部分）并将其替换为以下代码：

```js
... {

  loaders: utils.cssLoaders({

    ...

    extract: false

  })

}

```

我们的组件通常会包含 Vue 库；如果您想在 Vue 项目中使用该组件，您不需要这个库，因为它会造成重复的代码。您可以告诉 Webpack 只在外部搜索依赖项而不包含它们。在您刚刚修改的`webpack.prod.js`文件中的`plugins`之前添加以下属性：

```js
externals: {

  'vue': 'Vue'

}

```

这将告诉 Webpack 不将 Vue 库写入捆绑包中，而是只需使用一个全局的名为`Vue`的变量，在我们的代码中导入`vue`依赖项时使用它。Webpack 配置几乎完成了；我们只需要在`module`属性之前添加另一个属性：

```js
var webpackConfig = merge(baseWebpackConfig, {

  entry: {

 app: './src/dist.js'

 },

  module: {

  ...

```

这将从`dist.js`文件开始编译代码。等一下，这个文件还不存在。让我们创建它并在内部添加以下代码：

```js
import Vue from 'vue'

import Shaker from './Shaker'

Vue.component('shaker', Shaker)

```

在最终的 JavaScript 压缩文件中，Vue 依赖将被外部引用，然后我们将组件全局注册。

作为最后的更改，我建议修改保存压缩文件的文件夹。在`config/index.js`文件中，编辑以下行：

```js
assetsSubDirectory: 'static',

```

将上述行与以下代码进行交换：

```js
assetsSubDirectory: '.',

```

现在使用 npm 运行命令来构建压缩文件：

```js
npm run build

```

您将看到一个类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00146.jpg)

为了测试我们的文件，我们可以使用 JSFiddle。

复制您在`dist/shaker.js`中创建的文件的内容，然后转到[`gist.github.com/`](https://gist.github.com/)（您可能需要注册），将文件的内容粘贴到文本区域内。将其命名为`shaker.js`：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00147.jpg)

由于文本是单行的，使用“No wrap”选项时您将看不到太多内容。点击“创建公共 gist”，当您看到下一页时，点击“Raw”，如下图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00148.jpg)

复制地址栏中的 URL，然后转到[`rawgit.com/`](http://rawgit.com/)，在那里您可以粘贴链接：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00149.jpg)

点击并复制右侧获得的链接。恭喜，您刚刚将您的组件发布到了 Web 上！

现在转到 JSFiddle 并选择 Vue 作为库。您现在可以在左侧添加您复制的链接，您的组件就可以使用了：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00150.jpg)

# 工作原理...

官方模板中的 Webpack 配置相当复杂。另一方面，不要试图一下子理解所有内容，否则您会陷入困境，也无法学到太多东西。

我们创建了一个**UMD**（**通用模块定义**）模块，它将尝试查看是否有可用的 Vue 依赖，并将自身安装为一个组件。

您甚至可以为您的组件添加 CSS 和样式，我们配置的 Webpack 将会将样式与组件一起发布。

# 还有更多...

在本章的“将组件发布到公共场所”示例中，您将学习如何将组件发布到 npm 发布注册表中。我们将使用与此不同的方法，但您可以在那里找到将其发布到注册表的缺失步骤。

# 使用 Webpack 组织您的依赖关系

Webpack 是一个用于组织代码和依赖关系的工具。此外，它还提供了一种开发和构建 JavaScript 文件的方式，这些文件包含了我们传递给它们的所有依赖和模块。我们将在这个示例中使用它来构建一个小型的 Vue 应用程序，并将所有内容打包到一个单独的文件中。

# 准备就绪

这个示例不需要任何特殊的技能，只需要使用 npm 和一些命令行的知识。您可以在本章的“使用 Webpack 组织您的依赖关系”示例中了解更多信息。

# 如何做到...

为您的示例创建一个新的文件夹，并在其中创建一个包含以下内容的`package.json`文件：

```js
{

 "name": "recipe",

 "version": "1.0.0"

}

```

这在我们的文件夹中定义了一个 npm 项目。当然，如果你知道你在做什么，你可以使用`npm init`或`yarn init`。

我们将为这个示例安装 Webpack 2。要将其添加到您的项目依赖项中，请运行以下命令：

```js
npm install --save-dev webpack@2

```

`--save-dev`选项意味着我们不会在最终产品中发布 Webpack 的代码，而只会在开发过程中使用它。

创建一个新的`app`目录，并在其中创建一个`App.vue`文件。

这个文件将是一个简单的`Vue`组件；它可以像下面这样简单：

```js
<template>

  <div>

    {{msg}}

  </div>

</template>

<script>

export default {

  name: 'app',

  data () {

    return {

      msg: 'Hello world'

    }

  }

}

</script>

<style>

</style>

```

我们需要告诉 Webpack 如何将`.vue`文件转换为`.js`文件。为此，我们在根文件夹中创建一个名为`webpack.config.js`的配置文件；这个文件将被 Webpack 自动识别。在这个文件中，写入如下内容：

```js
module.exports = {

  module: {

    rules: [

      {test: /.vue$/, use: 'vue-loader'}

    ]

  }

}

```

规则中的行表示以下内容：

<q>嘿 Webpack，当你看到一个以`.vue`结尾的文件时，使用`vue-loader`将其转换为 JavaScript 文件。</q>

我们需要使用以下命令使用 npm 安装这样的加载器：

```js
npm install --save-dev vue-loader

```

此加载器内部使用其他依赖项，这些依赖项不会自动安装；我们需要通过运行以下命令手动安装它们：

```js
npm install --save-dev vue-template-compiler css-loader

```

我们还可以趁此机会安装 Vue 本身：

```js
npm install --save vue

```

现在我们的`Vue`组件已经准备好了。我们需要编写一个页面来放置它并尝试它。在`app`文件夹中创建一个名为`index.js`的文件。我们将在 Vue 实例中实例化该组件。在`index.js`中写入以下内容：

```js
import Vue from 'vue'

import App from './App.vue'

new Vue({

  el: '#app',

  render: h => h(App)

})

```

这将在具有`id="app"`的元素内挂载 Vue 实例，并且它将包含一个单独的组件-我们的`App.vue`。

我们还需要一个 HTML 文件。在根目录中创建`index.html`，并使用以下代码：

```js
<!DOCTYPE html>

<html>

  <head>

    <title>Webpack 2 demo</title>

  </head>

  <body>

    <div id="app"></div>

    <script src="dist/bundle.js"></script>

  </body>

</html>

```

我们不想直接引用`app/index.js`，这是因为`index.js`本身并不包含太多内容。它有一个浏览器无法识别的`import`语句。Webpack 可以轻松地创建包含`index.js`及其所有依赖项的`dist/bundle.js`。要做到这一点，请运行以下命令：

```js
./node_modules/webpack/bin/webpack.js app/index.js dist/bundle.js

```

这应该生成类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00151.jpg)

现在，您可以打开`index.html`，您将看到组件正在工作。

然而，每次都运行这个长命令并不那么有趣。Webpack 和 npm 可以做得更好。

在`webpack.config.js`中添加以下属性：

```js
module.exports = {

  entry: './app/index.js',

 output: {

 filename: 'bundle.js',

 path: __dirname + '/dist'

 },

  module: {

  ...

```

这将指定 Webpack 的入口点和结果文件的保存位置。

我们还可以在`package.json`中添加一个脚本：

```js
"scripts": {

  "build": "webpack"

}

```

现在，运行`npm run build`将产生与我们使用的长命令相同的效果。

# 它是如何工作的...

在这个示例中，我们基本上创建了一个同时包含 Vue 和我们编写的组件的 JavaScript 文件（`bundle.js`）。在`index.html`中，没有 Vue 的痕迹，因为它被嵌入在`bundle.js`中。

当我们有很多依赖关系时，这种工作方式要好得多。我们不再需要在页面的头部或正文中添加很多标签。此外，我们不必担心加载不需要的依赖关系。

作为额外的奖励，Webpack 具有将我们的最终文件和其他高级优化压缩的能力和灵活性，这是通过手动加载依赖项无法实现的。

# 在您的 Webpack 项目中使用外部组件

在自己的项目中使用外部 Vue 组件通常很简单。然而，有时候事情并不那么简单。特别是，在官方模板中有一些 Webpack 的配置（奇怪的是）实际上会阻止您使用某些外部组件。在这个示例中，我们将安装 Bulma 项目中的一个模态对话框组件。

# 准备工作

在这个示例中，我们将调整 Webpack 配置。建议在开始此任务之前完成“使用 Webpack 组织依赖项”示例。

# 如何操作...

我们将从一个全新的 Webpack 项目开始。您可以使用`vue-cli`和官方 Webpack 模板创建一个新项目。然而，我建议您使用我的 Webpack 模板开始，这是一个干净的模板。要这样做，请在一个新的目录中运行以下命令：

```js
vue init gurghet/webpack

```

我们将安装`vue-bulma-modal`，这是一个使用 Bulma CSS 框架编写的 Vue 组件：

```js
npm install --save vue-bulma-modal bulma

```

在上述命令中，我们还安装了`bulma`，其中包含实际的 CSS 样式。

为了使样式起作用，我们需要将它们转换为 Webpack 的 JavaScript 代码；这意味着我们需要安装一些加载器：

```js
npm install --save-dev node-sass sass-loader

```

SASS 加载器已经配置好了，所以不需要做任何修改。但我们将修改与 Babel 加载器相关的 Webpack 配置（在“使用热重载进行连续反馈开发”示例中了解更多信息）。

在官方模板中（但这可能会改变，请注意），有一行代码阻止 Webpack 编译依赖项。打开`build/webpack.base.conf.js`文件，找到以下代码块：

```js
{

  test: /.js$/,

  loader: 'babel-loader',

  include: [

    path.join(projectRoot, 'src')

  ],

 exclude: /node_modules/

},

```

根据您使用的 Webpack 版本，您可能需要稍微调整加载器语法。例如，在旧版本的 Webpack 中，您需要写`babel`而不是`babel-loader`。

您必须删除突出显示的行，并改为编写以下内容：

```js
{

  test: /.js$/,

  loader: 'babel-loader',

  include: [

    path.join(projectRoot, 'src'),

 path.join(projectRoot, 'node_modules/vue-bulma-modal')

  ]

},

```

这告诉 Webpack 使用`babel-loader`编译我们刚刚安装的组件。

现在，在`App.vue`中编写以下 HTML 布局：

```js
<template>

  <div id="app">

    <card-modal

      @ok="accept"

      ok-text="Accept"

      :visible="popup"

      @cancel="cancel"

    >

      <div class="content">

        <h1>Contract</h1>

          <p>

            I hereby declare I have learned how to

            install third party components in my

            own Vue project.

          </p>

        </div>

      </card-modal>

    <p v-if="signed">It appears you signed!</p>

  </div>

</template>

```

然后，您可以按照 JavaScript 中所示的逻辑编写代码：

```js
<script>

import { CardModal } from 'vue-bulma-modal'

export default {

  name: 'app',

  components: { CardModal },

  data () {

    return {

      signed: false,

      popup: true

    }

  },

  methods: {

    accept () {

      this.popup = false

      this.signed = true

    },

    cancel () {

      this.popup = false

    }

  }

}

</script>

```

要实际使用 Bulma 样式，我们需要启用 SASS 加载器并导入`bulma`文件。添加以下行：

```js
<style lang="sass">

@import '~bulma';

</style>

```

请注意，我们在第一行中指定了样式的语言（我们编写的是 SCSS，但在这种情况下我们按原样编写）。

如果您现在尝试使用`npm run dev`命令运行应用程序，您将看到 Bulma 模态对话框以其全部辉煌出现：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00152.jpg)

# 工作原理如下...

官方的 Webpack 模板包含了一个配置规则，不要编译`node_modules`目录中的文件。这意味着 Web 组件的作者被鼓励分发一个已经编译好的文件，否则用户将在他们的项目中导入原始的 JavaScript 文件（因为 Webpack 不会编译它们），从而在浏览器中引发各种错误。就个人而言，我认为这不是一个好的工程实践。这种设置的一个问题是，由于您在项目中导入的文件是针对一个版本的 Vue 进行编译的，所以如果您使用较新版本的 Vue，组件可能无法正常工作（实际上过去确实发生过这种情况）。

更好的方法是导入原始文件和组件，让 Webpack 将它们编译成一个单独的文件。不幸的是，大多数在外部可用的组件都已经编译好了，所以虽然使用官方模板很快就可以导入它们，但更有可能遇到兼容性问题。

在导入外部组件时，首先要做的是检查它们的`package.json`文件。让我们看看`vue-bulma-modal`包在此文件中包含了什么：

```js
{

  "name": "vue-bulma-modal",

  "version": "1.0.1",

  "description": "Modal component for Vue Bulma",

 "main": "src/index.js", 

  "peerDependencies": {

    "bulma": ">=0.2",

    "vue": ">=2"

  },

  ...

  "author": "Fangdun Cai <cfddream@gmail.com>",

  "license": "MIT"

}

```

当我们在 JavaScript 中编写以下行时，`main`属性引用的文件是我们导入的文件：

```js
import { CardModal } from 'vue-bulma-modal'

```

`src/index.js`文件中包含以下代码：

```js
import Modal from './Modal'

import BaseModal from './BaseModal'

import CardModal from './CardModal'

import ImageModal from './ImageModal'

export {

  Modal,

  BaseModal,

  CardModal,

  ImageModal

}

```

这不是一个编译文件；它是原始的 ES6 代码，我们知道这一点是因为在常规的 JavaScript 中没有定义`import`。这就是为什么我们需要 Webpack 来为我们编译它。

另一方面，考虑到我们编写了以下内容：

```js
<style lang="sass">

@import '~bulma';

</style>

```

使用波浪号（`~`），我们告诉 Webpack 像处理模块一样解析样式，因此，我们真正导入的是`bulma`包的`package.json`中`main`属性所引用的文件，如果我们检查一下，它看起来如下：

```js
{

  "name": "bulma",

  "version": "0.3.1",

  ...

 "main": "bulma.sass",

  ...

}

```

由于我们使用 SASS 语法导入了一个 SASS 文件，所以我们需要在 Vue 组件中指定`lang="sass"`。

# 使用热重载进行连续反馈的开发

热重载是一项非常有用的技术，它允许您在浏览器中查看结果而无需刷新页面即可进行开发。这是一个非常紧密的循环，可以真正加快开发过程。在官方的 Webpack 模板中，默认安装了热重载。在本教程中，您将学习如何自己安装它。

# 准备工作

在尝试这个教程之前，您应该对 Webpack 的工作原理有一个大致的了解；本章中的“使用 Webpack 组织依赖项”教程将为您提供帮助。

# 如何做到这一点...

在一个新的目录中创建一个新的 npm 项目，可以使用`npm init -y`或`yarn init -y`。我个人更喜欢第二种方法，因为生成的`package.json`更加简洁。

要安装 Yarn，你可以使用`npm install -g yarn`命令。Yarn 的主要好处是你将能够将你的依赖锁定到已知版本。这可以防止在团队合作中出现错误，当应用程序从 Git 克隆时，可能会有略微不同的版本引入不兼容性。

你将创建一个数字咒骂罐。每次你说脏话，你就会向一个长期目标的咒骂罐捐赠一定金额的钱。

创建一个名为`SwearJar.vue`的新文件，并在其中添加以下代码：

```js
<template>

  <div>

    Swears: {{counter}} $$

    <button @click="addSwear">+</button>

  </div>

</template>

<script>

export default {

  name: 'swear-jar',

  data () {

    return {

      counter: 0

    }

  },

  methods: {

    addSwear () {

      this.counter++

    }

  }

}

</script>

```

你将把这个组件插入到一个网页中。

在同一个目录下创建一个名为`index.html`的文件，并写入以下代码：

```js
<!DOCTYPE html>

<html>

  <head>

    <title>Swear Jar Page</title>

  </head>

  <body>

    <div id="app"></div>

    <script src="bundle.js"></script>

  </body>

</html>

```

`bundle.js`文件将由 Webpack（在内存中）为我们创建。

你需要的最后一个应用程序文件是一个包含 Vue 根实例的 JavaScript 文件。在同一个目录下创建一个名为`index.js`的文件，并将以下内容放入其中：

```js
import Vue from 'vue'

import SwearJar from './SwearJar.vue'

new Vue({

  el: '#app',

  render: h => h(SwearJar)

})

```

现在你需要创建一个名为`webpack.config.js`的文件，告诉 Webpack 一些事情。第一件事是我们应用程序的入口点（`index.js`）以及我们想要放置编译文件的位置：

```js
module.exports = {

  entry: './index.js',

  output: {

    path: 'dist',

    filename: 'bundle.js'

  }

}

```

接下来，我们将告诉 Webpack 将`.vue`文件转换为 JavaScript 文件，使用`vue-loader`：

```js
module.exports = {

  entry: './index.js',

  output: {

    path: 'dist',

    filename: 'bundle.js'

  },

  module: {

 rules: [

 {

 test: /.vue$/,

 use: 'vue-loader'

 }

 ]

 }

}

```

为了使一切正常工作，我们仍然需要安装我们在代码中隐含的依赖项。我们可以使用以下两个命令来安装它们：

```js
npm install --save vue

npm install --save-dev vue-loader vue-template-compiler webpack webpack-dev-server

```

特别是最后一个--`webpack-dev-server`--是一个开发服务器，将帮助我们进行热重载开发。

运行以下命令启动服务器：

```js
./node_modules/webpack-dev-server/bin/webpack-dev-server.js --output-path / --inline --hot --open

```

实际上，让我们将这个命令放在一个 npm 脚本中。

打开`package.json`并添加以下行：

```js
"scripts": {

  "dev": "webpack-dev-server --output-path / --inline --hot --open"

}

```

现在我们可以运行`npm run dev`，我们将得到与下面的截图中所示相同的结果--一个浏览器将弹出：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00153.jpg)

点击加号按钮将使计数器增加，但是这个应用程序的样式呢？让我们让它更有吸引力。

打开你的代码编辑器和窗口并排放置，并对`SwearJar.vue`进行以下修改：

```js
<template>

  <div>

    <p>

Swears: {{counter}} $$</p>

    <button @click="addSwear">Add Swear

</button>

  </div>

</template>

```

保存文件，你会看到页面自动更新。更好的是，如果计数器已经设置为大于零的值，状态将会保留，这意味着如果你有一个复杂的组件，在每次修改后你不需要手动将其带回相同的状态。尝试将脏话计数设置为某个数字并编辑模板。大多数情况下，计数器不会被重置为零。

# 它是如何工作的...

Webpack 开发服务器是非常有帮助的软件，它让你能够以非常紧密的反馈循环进行开发。我们使用了很多参数来使其运行：

```js
webpack-dev-server --output-path / --inline --hot --open

```

所有这些参数在`webpack.config.js`中是相同的。相反，我们将这些参数放在命令行中是为了方便。`--output-path`是 Webpack 服务器将服务的`bundle.js`的位置；在我们的例子中，我们说我们希望它在根路径下服务，所以它将有效地将`/bundle.js`路径绑定到实际的`bundle.js`文件。

第二个参数`--inline`将在我们的浏览器中注入一些 JavaScript 代码，以便我们的应用程序可以与 Webpack 开发服务器通信。

`--hot`参数将激活热模块替换插件，它将与`vue-loader`（实际上是与其中的`vue-hot-reload-api`）通信，并且将重新启动或重新渲染（保留状态）页面中的每个 Vue 模型。

最后，`--open`只是为我们打开默认的浏览器。

# 使用 Babel 编译 ES6

ES6 有很多有用的功能，在这个示例中，你将学习如何在你的项目中使用它。值得注意的是，ES6 目前在浏览器上有很好的支持。你不会在 80%的浏览器中遇到兼容性问题，但是根据你的受众，你可能需要甚至要接触仍在使用 Internet Explorer 11 的人，或者你可能只是想最大化你的受众。此外，一些用于开发和 Node.js 的工具仍然不完全支持 ES6，因此即使是开发也需要使用 Babel。

# 准备就绪

在这个示例中，我们将使用 npm 和命令行。如果你在第一章的*选择开发环境*示例中完成了*开始使用 Vue.js*，那么你可能已经准备好了。

# 如何做...

创建一个带有空的 npm 项目的新目录。你可以使用`npm init -y`命令，或者如果你已经安装了 Yarn，你可以在目录中使用`yarn init -y`。这个命令将在目录中创建一个新的`package.json`文件。（请参考 Yarn 上的*使用热重载进行连续反馈开发*示例中的注意事项。）

对于这个 npm 项目，除了 Vue 之外，我们还需要一些其他的依赖项：Webpack 和 Babel（以 Webpack 的 loader 形式）。是的，我们还需要`vue-loader`来使用 Webpack。要安装它们，请执行以下两个命令：

```js
npm install --save vue

npm install --save-dev webpack babel-core babel-loader babel-preset-es2015 vue-loader vue-template-compiler

```

在同一个目录下，让我们编写一个使用 ES6 语法的组件；让我们称之为`myComp.vue`：

```js
<template>

  <div>Hello</div>

</template>

<script>

var double = n => n * 2

export default {

  beforeCreate () {

    console.log([1,2,3].map(double))

  }

}

</script>

```

这个组件除了将`[2,4,6]`数组打印到控制台外，没有做太多事情，但是它在下一行使用了箭头语法：

```js
var double = n => n * 2

```

这对于一些浏览器和工具来说是无法理解的；我们需要使用 Webpack 编译这个组件，但是我们需要使用 Babel loader 来完成。

创建一个新的`webpack.config.js`文件，并在其中写入以下内容：

```js
module.exports = {

  entry: 'babel-loader!vue-loader!./myComp.vue',

  output: {

    filename: 'bundle.js',

    path: 'dist'

  }

}

```

这将告诉 Webpack 从我们的`myComp.vue`文件开始编译，但在此之前，它将通过`vue-loader`处理它，将其转换为 js 文件，然后通过`babel-loader`将箭头函数转换为更简单和更兼容的形式。

我们可以使用不同且更标准的配置来实现相同的效果：

```js
module.exports = {

 entry: './myComp.vue', 

  output: {

    filename: 'bundle.js'

  },

  module: {

    rules: [

      {

        test: /.vue$/,

        use: 'vue-loader'

      },

      {

        test: /.js$/,

        use: 'babel-loader'

      }

    ]

  }

}

```

这是一个更通用的配置，它表示每当我们遇到以`.vue`结尾的文件时，应该使用`vue-loader`进行解析和处理，以及以`.js`结尾的文件应该使用`babel-loader`进行处理。

要配置 Babel 加载器，有几个选项；我们将遵循推荐的方式。在项目文件夹中创建一个名为`.babelrc`的文件（注意初始点），并指定我们要应用`es2015`预设，写入以下代码：

```js
{

  "presets": ["es2015"]

}

```

最后，我总是喜欢在`package.json`文件中添加一个新的脚本，以便更容易地启动命令。在文件末尾（但在最后一个大括号之前）添加以下行：

```js
"scripts": {

  "build": "webpack"

}

```

然后运行`npm run build`。这将在`dist`目录中创建一个名为`bundle.js`的文件；打开它并搜索包含例如`double`的行。你应该会找到类似于这样的内容：

```js
...

var double = function double(n) {

  return n * 2;

};

...

```

这是我们的`var double = n => n * 2`，从 ES6 转换为*常规*JavaScript。

# 它是如何工作的...

`es2015` Babel 预设是一组 Babel 插件，旨在将 ECMAScript2015（ES6）语法转换为更简单的 JavaScript。例如，它包含了`babel-plugin-transform-es2015-arrow-functions`插件，它可以将箭头函数转换为：

```js
var addOne = n => n + 1

```

将箭头函数转换为更简单的 JavaScript，如下所示：

```js
var addOne = function addOne(n) {

  return n + 1

}

```

为了选择文件及其相应的加载器，我们在`webpack.config.js`中填写了测试字段，并为匹配的`.vue`文件编写了以下内容：

```js
test: /\.vue$/

```

这个语法是一个正则表达式，它总是以一个正斜杠开始，以另一个正斜杠结束。它匹配的第一个字符是点，表示为`\.`，因为`.`字符已经被用于其他目的。点后面必须跟着`vue`字符串，字符串的结束字符表示为美元符号。如果把它们都放在一起，它将匹配所有以`.vue`结尾的字符串。对于`.js`文件也是类似的。

# 在开发过程中运行代码检查器

对代码进行 linting 可以大大减少在开发过程中累积的小错误和低效，它保证了团队或组织中的编码风格的一致性，并使您的代码更易读。与偶尔运行 linter 不同，将其始终运行是有用的。本教程将教您如何在 Webpack 中实现此功能。

# 准备工作

在本教程中，我们将再次使用 Webpack。您将使用`webpack-dev-server`构建一个紧密循环，该循环在*使用热重载进行连续反馈开发*教程中有所涵盖。

# 如何实现...

在一个新的文件夹中，创建一个新的 npm 项目（可以使用`npm init -y`或`yarn init -y`）。

在文件夹中，创建一个名为`src`的新目录，并在其中放置一个名为`MyComp.vue`的文件。让文件包含以下代码：

```js
<template>

  <div>

    Hello {{name}}!

  </div>

</template>

<script>

export default {

  data () {

    return {

      name: 'John',

      name: 'Jane'

    }

  }

}

</script>

```

我们已经发现了一个问题-`John`的 name 属性将被后面的具有相同键的属性`Jane`覆盖。让我们假装没有注意到这一点，并将组件放在一个网页中。为此，我们需要另一个文件，名为`index.js`，在`src`目录中。在其中写入以下代码：

```js
import Vue from 'vue'

import MyComp from './MyComp.vue'

new Vue({

  el: '#app',

  render: h => h(MyComp)

})

```

在根目录中，放置一个名为`index.html`的文件，其中包含以下代码：

```js
<!DOCTYPE html>

<html>

  <head>

    <title>Hello</title>

  </head>

  <body>

    <div id="app"></div>

      <script src="bundle.js"></script>

    </body>

</html>

```

现在我们需要一个`webpack.config.js`文件来告诉 Webpack 如何编译我们的文件；在其中写入以下内容：

```js
module.exports = {

  entry: './src/index.js',

  module: {

    rules: [

      { 

        test: /.vue$/,

        use: 'vue-loader'

      }

    ]

  }

}

```

这只是告诉 Webpack 从`index.js`文件开始编译，并且每当它找到一个`.vue`文件时，将其转换为 JavaScript 与`vue-loader`。除此之外，我们还希望使用一个 linter 扫描所有的文件，以确保我们的代码中没有愚蠢的错误。

将以下 loader 添加到`rules`数组中：

```js
{

  test: /.(vue|js)$/,

  use: 'eslint-loader',

  enforce: 'pre'

}

```

`enforce: 'pre'`属性将在其他 loader 之前运行此 loader，因此它将应用于您编写的代码而不是其转换。

我们最后需要做的是配置 ESLint。在根目录中创建一个名为`.eslintrc.js`的新文件，并在其中添加以下内容：

```js
module.exports = {

  "extends": "eslint:recommended",

  "parser": "babel-eslint",

  plugins: [

    'html'

  ]

}

```

我们在这里说了几件事。首先是我们想要应用于我们的代码的一组规则；换句话说，我们的规则集（现在为空）正在扩展推荐的规则集。其次，我们使用`babel-eslint`解析器而不是默认的解析器。最后，我们使用 HTML ESLint 插件，它将帮助我们处理`.vue`文件并提取其中的 JavaScript 代码。

现在我们已经准备好启动我们的开发机器了，但首先我们需要使用以下命令安装依赖项：

```js
npm install --save vue

npm install --save-dev babel-eslint eslint eslint-loader eslint-plugin-html vue-loader vue-template-compiler webpack webpack-dev-server

```

我们可以直接启动 Webpack 开发服务器，但我强烈建议将以下代码添加到`package.json`文件中：

```js
"scripts": {

  "dev": "webpack-dev-server --entry ./src/index.js --inline --hot --open"

}

```

现在，如果我们启动`npm run dev`，浏览器应该打开并显示以下错误的组件：

`<q>Hello Jane!</q>`

您还应该能够在控制台中看到问题：

`11:7  error  Duplicate key 'name'  no-dupe-keys`

这意味着我们有两个具有相同“name”的键。通过删除该属性来纠正错误：

```js
data () {

  return {

    name: 'John'

  }

}

```

在控制台中，当您保存 Vue 组件后，您应该注意到 Webpack 已经再次执行了编译，这次没有错误。

# 工作原理是...

基本上，在此处发生的是，linter 加载器在其他编译步骤之前处理文件并将错误写入控制台。这样，您就可以在不断开发的过程中看到代码中的不完美之处。

ESLint 和 Webpack 在 Vue 官方模板中可用。现在您知道，如果出于某种原因，您想要修改 ESLint 规则，可以从`.eslintrc.js`文件中进行修改，并且如果您想要使用其他 linter，可以在 Webpack 配置文件中使用另一个加载器。

# 只使用一个命令来构建一个压缩和一个开发的.js 文件

在开发组件时，您可能需要一个可靠的流程来发布构建的文件。一个常见的操作是发布库/组件的两个版本：一个用于开发目的，一个用于在生产代码中使用，通常是经过压缩的。在这个配方中，您将调整官方模板，同时发布一个经过压缩和一个开发的 JavaScript 文件。

# 准备就绪

如果您已经在构建和分发自己的组件，那么这个配方就有意义。如果您想了解更多信息，我建议您参考“使用 Webpack 打包您的组件”配方。

# 如何操作...

我们将从官方的 Webpack 模板开始一个项目。您可以使用自己的模板，或者使用`vue init webpack`创建一个新项目，并使用“npm install”安装依赖项。

进入`build`目录。当您运行`npm run build`命令时，实际上是在该目录中运行`build.js`文件。

如果您检查文件，您会在末尾找到类似以下内容的内容：

```js
webpack(webpackConfig, function (err, stats) {

...

})

```

这相当于使用相同配置在命令行中启动 Webpack，指定在第一个参数`webpackConfig`中指定的配置。为了获得一个经过压缩和一个非经过压缩的文件，我们必须将`webpackConfig`带到一个公共的基准，然后只指定开发和生产版本之间的差异。

为此，请进入同一目录中的`webpack.prod.conf.js`。在这里，您可以看到我们正在传递的配置；特别是，您会发现`UglifyJsPlugin`，它负责压缩文件（如果您查看插件数组）。删除该插件，因为它代表了两个版本之间的主要区别。

现在，在 Webpack 命令之前，在`build.js`中写入以下内容：

```js
const configs = [

  {

    plugins: [

      new webpack.optimize.UglifyJsPlugin({

        compress: {

          warnings: false

        },

        sourceMap: true

      })

    ]

  },

  {

    plugins: []

  }

]

```

现在你有了一个包含两个不同配置的数组，一个带有压缩文件所需的插件，一个没有。如果你将它们与`webpack.prod.conf.js`中的配置合并，你将得到不同的结果。

为了合并这两个配置，我们将使用`webpack-merge`包。在文件顶部添加以下行：

```js
var merge = require('webpack-merge')

```

然后，将 Webpack 命令的第一行修改为以下内容：

```js
configs.

map(c =>

 webpack(merge(webpackConfig, c)

, function (err, stats) {

...

```

这将启动与我们在配置数组中指定的配置数量一样多的不同合并配置。

现在你可以运行`npm run build`命令了，但问题是文件将具有相同的名称。从`webpack.prod.conf.js`中剪切输出属性，并将其粘贴到`config`数组中，现在它应该是这样的：

```js
const configs = [

  {

    output: {

 path: <whatever is your path>,

 filename: 'myFilename.min.js'),

 <other options you may have>

 },

    plugins: [

      new webpack.optimize.UglifyJsPlugin({

        compress: {

          warnings: false

        }

      })

    ]

  },

  {

    output: {

 path: <whatever is your path>,

 filename: 'myFilename.js'),

 <other options you may have>

 },

    plugins: []

  }

]

```

如果你现在构建你的项目，你将得到一个压缩和一个开发文件。当然，你可以根据需要个性化你的配置，使它们变得非常不同。例如，你可以在一个配置中添加源映射，而将另一个配置保持不变。

# 它是如何工作的...

我们首先创建了一个表示 Webpack 配置差异的对象数组。然后，我们使用`webpack-merge`的帮助将每个配置片段映射到一个更大的公共配置中。当我们现在调用`npm run build`命令时，两个配置将依次运行。

将文件名的后缀命名为`min`是一种常见的约定，表示该文件已经被压缩并准备好在生产环境中使用。

# 发布你的组件到公共领域

在某个时刻，当你想要回馈社区时，会有一个时刻。也许你建了一个“放屁按钮”，或者你建了一个自动化股票期权交易者；无论你建了什么，JavaScript 和 Vue 社区都会很高兴欢迎你。在市场营销和许可方面还有很多事情要做，但在这个教程中，你将集中关注更多的技术方面。

# 准备工作

这个教程是针对那些想要与 Vue 社区分享他们的工作的人。在*使用 Webpack 打包你的组件*教程中，你会找到如何调整官方 Webpack 模板以正确打包你的组件；这个教程可以看作是第二部分。不过我们不会使用官方模板。

# 如何操作...

我在这个教程中采用的方法是使用*Guillaume Chau*的优秀`vue-share-components`模板。我们将从这个起点构建一个笑话按钮。

在命令行中，创建一个新的目录并在其中输入以下命令：

```js
vue init Akryum/vue-share-components

```

它会询问你一些问题；你可以从下面的图片中复制回答。需要注意的是，你（可悲地）不能使用`joke-button`作为你的项目名称，因为在编写这个教程时我已经注册了它。不过，你可以想出一个类似的名称（在继续之前，你可能需要检查该名称在`npm`注册表中是否可用）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00154.jpg)

项目创建完成后，你可以像控制台输出一样使用`npm install`安装依赖项。

在项目内部，让我们创建一个笑话按钮组件。在`component`文件夹内，你会找到一个`Test.vue`组件；将其重命名为`JokeButton.vue`并使其看起来像以下代码：

```js
<template>

  <div class="test">

    <button @click="newJoke">New Joke</button>

    <p>{{joke}}</p>

  </div>

</template>

<script>

const jokes = [

 'Chuck Norris/'s keyboard has the Any key.',

 'Chuck Norris can win at solitaire with only 18 cards.',

 'Chuck Norris/' first job was as a paperboy. There were no survivors.',

 'When Chuck Norris break the build, you can/'t fix it.',

]

export default {

  name: 'joke-button',

  data () {

    return {

      joke: '...',

    }

  },

  methods: {

    newJoke () {

      this.joke = jokes[Math.floor(Math.random() * jokes.length)]

    },

  },

}

</script>

```

显然，你可以创建你喜欢的组件；这只是一个例子。

在`index.js`文件中，你会看到导入和安装了`Test`组件；你需要安装`JokeButton`代替。需要更改的行已经被标出：

```js
import JokeButton

 from './components/JokeButton

.vue'

// Install the components

export function install (Vue) {

  Vue.component('jokeButton

', JokeButton

)

  /* -- Add more components here -- */

}

// Expose the components

export {

  JokeButton

,

  /* -- Add more components here -- */

}

...

```

我们的组件已经准备好了！

现在你需要去 npm 网站注册一个账号（如果你还没有的话）。

前往[npmjs.com](https://www.npmjs.com/)：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00155.jpg)

点击注册并输入你的详细信息，就像我在这里做的一样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00156.jpg)

当然，如果你喜欢的话，你可以订阅 npm 每周的新闻通讯。

注册完成后，你就完成了，可以回到命令行了。你必须使用以下命令从终端登录到 npm 注册表：

```js
npm adduser

```

你将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00157.jpg)

你将需要输入刚刚为 npm 网站输入的密码。

下一个命令将会在公共仓库中发布你的库：

```js
npm publish

```

现在你甚至可以查找你的包，确保你会在下面的截图中找到它：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-cb/img/Image00158.jpg)

要尝试它，你可以在你自己的 `README` 中找到说明，多酷啊！

# 它是如何工作的...

`vue-share-components` 比官方模板更简单，所以通过检查它是一个很好的学习方式。

我们可以首先看一下 `package.json` 文件。以下几行是相关的：

```js
...

"main": "dist/joke-button.common.js",

"unpkg": "dist/joke-button.browser.js",

"module": "index.js",

"scripts": {

  "dev": "cross-env NODE_ENV=development webpack --config config/webpack.config.dev.js --progress --watch",

  "build": "npm run build:browser && npm run build:common",

  "build:browser": "cross-env NODE_ENV=production webpack --config config/webpack.config.browser.js --progress --hide-modules",

  "build:common": "cross-env NODE_ENV=production webpack --config config/webpack.config.common.js --progress --hide-modules",

  "prepublish": "npm run build"

},

...

```

`main` 属性是我们在程序中写入以下命令时实际得到的内容：

```js
import JokeButton from 'JokeButton'

```

或者，我们在添加以下代码时获得它：

```js
var JokeButton = require("JokeButton")

```

所以，`JokeButton` 变量实际上将包含在我们的 `joke-button.common.js` 中导出的内容。

你可以编辑 `package.json` 的 `main` 属性，直接指向一个 `.vue` 组件。这样，你就把编译组件的责任交给了用户。虽然这对用户来说更多了一些工作，但当你想要自由地编译最新版本的 Vue 时，这也是有帮助的。

在后一种情况下，如果你的组件的一些逻辑是在 `external.js` 文件中导出的（就像本章的第一个示例中一样），请始终记得在 Webpack 规则中添加目录，如下所示：

`{`

`  test: /.js$/,`

`  loader: 'babel-loader',`

`  include: [resolve('src'), resolve('test'), resolve('node_modules/myComponent')]`

`},`

unpkg 是 [unpkg.com](https://unpkg.com/#/) 的特定部分，它是一个 CDN。这非常好，因为一旦我们发布了项目，我们的脚本将会在 [`unpkg.com/joke-button`](https://unpkg.com/joke-button) 上发布，并且它将指向适用于浏览器的 `joke-button.browser.js` 文件。

`prepublish`脚本是一个特殊的脚本，在使用`npm publish`命令将项目发布到 npm 之前调用。这消除了在发布组件之前忘记构建文件的可能性（这在我身上发生过很多次，所以我被迫人为地增加软件版本，手动构建文件，然后再次发布）。

另一个有趣的事实是`webpack.config.common.js`和`webpack.config.browser.js`之间的区别，前者输出`joke-button.common.js`文件，后者输出`joke-button.browser.js`文件。

第一个文件的输出设置如下：

```js
output: {

  path: './dist',

  filename: outputFile + '.common.js',

  libraryTarget: 'commonjs2',

},

target

:

 '

node' 

,

```

因此，它将输出一个公开 commonJS 接口的库；这是为非浏览器环境定制的，您需要使用 require 或 import 来使用该库。另一方面，用于浏览器的第二个文件具有以下输出：

```js
output: {

  path: './dist',

  filename: outputFile + '.browser.js',

  library: globalName,

  libraryTarget: 'umd',

},

```

UMD 将在全局范围内公开自身，无需导入任何内容，因此它非常适合浏览器，因为我们可以将文件包含在 Vue 网页中并自由使用组件。这也是可能的，多亏了`index.js`的自动安装功能：

```js
/* -- Plugin definition & Auto-install -- */

/* You shouldn't have to modify the code below */

// Plugin

const plugin = {

 /* eslint-disable no-undef */

 version: VERSION,

 install,

}

export default plugin

// Auto-install

let GlobalVue = null

if (typeof window !== 'undefined') {

 GlobalVue = window.Vue

} else if (typeof global !== 'undefined') {

 GlobalVue = global.Vue

}

if (GlobalVue) {

 GlobalVue.use(plugin)

}

```

这段代码的作用是将安装函数（用于在 Vue 中注册组件）封装在`plugin`常量中，并同时导出它。然后，它检查是否定义了`window`或`global`，如果是这样，它获取代表 Vue 库的`Vue`变量，并使用插件 API 来安装组件。
