# JavaScript 高性能实用指南（二）

> 原文：[`zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774`](https://zh.annas-archive.org/md5/C818A725F2703F2B569E2EC2BCD4F774)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：实际示例-看看 Svelte 和 Vanilla

由于过去几章讨论了现代网络和我们可用的 API，现在我们将实际示例中使用这些 API。在创建与之相关的一种*运行时*的 Web 框架方面已经有了相当多的发展。这个*运行时*几乎可以归因于**虚拟 DOM**（**VDOM**）和状态系统。当这两个东西相互关联时，我们能够创建丰富和反应灵敏的前端。这些框架的例子包括 React、Vue 和 Angular。

但是，如果我们摆脱 VDOM 和运行时概念，并以某种方式将所有这些代码编译为纯 JavaScript 和 Web API 调用，会发生什么？这就是 Svelte 框架的创建者所考虑的：利用浏览器中已有的内容，而不是创建我们自己的浏览器版本（这显然是一个过度简化，但并不太离谱）。在本章中，我们将看看 Svelte 以及它如何实现一些魔术，以及使用这个框架编写的一些应用程序示例。这应该让我们对 Svelte 和存在的*无运行时*框架有一个很好的理解，以及它们如何潜在地加快我们的应用程序运行速度。

本章涉及的主题如下：

+   纯速度的框架

+   构建基础-待办事项应用程序

+   变得更花哨-基本天气应用程序

# 技术要求

本章需要以下内容：

+   诸如**Visual Studio Code**（**VS Code**）之类的编辑器或 IDE

+   Node 环境设置

+   对 DOM 的良好理解

+   Chrome 等 Web 浏览器

+   在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter04)找到的代码。

# 纯速度的框架

Svelte 框架决定将焦点从基于运行时的系统转移到基于编译器的系统。这可以在他们的网站上看到，位于[`svelte.dev`](https://svelte.dev)。在他们的首页上，甚至明确指出了以下内容：

Svelte 将您的代码编译为微小的、无框架的 vanilla JS-您的应用程序启动快速并保持快速。

通过将步骤从运行时移至初始编译，我们能够创建下载和运行速度快的应用程序。但是，在我们开始研究这个编译器之前，我们需要将其安装到我们的机器上。以下步骤应该使我们能够开始为 Svelte 编写代码（直接从[`svelte.dev/blog/the-easiest-way-to-get-started`](https://svelte.dev/blog/the-easiest-way-to-get-started)获取）：

```js
> npx degit sveltejs/template todo
> cd todo
> npm install
> npm run dev
```

有了这些命令，我们现在有一个位于`localhost:5000`的运行中的 Svelte 应用程序。让我们看看让我们如此快速启动的`package.json`中有什么。首先，我们会注意到我们有一堆基于 Rollup 的依赖项。Rollup 是 JavaScript 的模块捆绑器，还有一套丰富的工具来执行许多其他任务。它类似于 webpack 或 Parcel，但这是 Svelte 决定依赖的工具。我们将在第十二章中更深入地了解 Rollup，*构建和部署完整的 Web 应用程序*。只需知道它正在为我们编译和捆绑我们的代码。

似乎我们有一个名为`sirv`的东西（可以在`package.json`文件中看到）。如果我们在`npm`中查找`sirv`，我们会发现它是一个静态资产服务器，但是，它不是直接在文件系统上查找文件（这是一个非常昂贵的操作），而是将请求头和响应缓存在内存中一段时间。这使得它能够快速提供可能已经被提供的资产，因为它只需要查看自己的内存，而不是进行 I/O 操作来查找资产。**命令行界面**（**CLI**）使我们能够快速设置服务器。

最后，我们以开发模式启动我们的应用程序。如果我们查看`package.json`文件的`scripts`部分，我们会看到它运行以下命令：`run-p start:dev autobuild`。`run-p`命令表示并行运行所有后续命令。`start:dev`命令表示在开发模式下启动我们的`sirv`服务器，`autobuild`命令告诉 Rollup 编译和监视我们的代码。这意味着每当我们对文件进行更改时，它都会自动为我们构建。让我们快速看看它的运行情况。让我们进入`src`文件夹并对`App.svelte`文件进行更改。添加以下内容：

```js
//inside of the script tag
export let name;
export let counter;

function clicker() {
   counter += 1;
}

//add to the template
<span>We have been clicked {counter} times</span>
<button on:click={clicker}>Click me!</button>
```

我们会注意到我们的网页已经自动更新，现在我们有一个基于事件的响应式网页！这在开发模式下非常好，因为我们不必不断触发编译器。

这些示例中的首选编辑器是 VS Code。如果我们转到 VS Code 的扩展部分，那里有一个很好的 Svelte 插件。我们可以利用这个插件进行语法高亮和一些警报，当我们做错事时。如果首选编辑器没有 Svelte 插件，请尝试至少启用编辑器的 HTML 高亮显示。

好的：这个简单的例子已经给了我们很多东西可以看。首先，`App.svelte`文件给我们提供了类似 Vue 文件的语法。我们有一个 JavaScript 部分，一个样式部分，和一个增强的 HTML 部分。我们导出了两个变量，名为`name`和`counter`。我们还有一个函数，我们在按钮的点击处理程序中使用。我们还为我们的`h1`元素启用了样式。

看起来花括号添加了我们从这些响应式框架中期望的单向数据绑定。它看起来也像是我们通过简单的`on:<event>`绑定来附加事件，而不是利用内置的`on<event>`系统。

如果我们现在进入`main.js`文件，我们会看到我们正在导入刚刚查看的 Svelte 文件。然后我们创建一个新的*app*（它应该看起来很熟悉，类似其他响应式框架），并且将我们的应用程序定位到文档的主体。除此之外，我们还设置了一些属性，即我们之前导出的`name`和`counter`变量。然后我们将其作为此文件的默认导出进行导出。

所有这些都应该与前一章非常相似，当我们查看内置于浏览器中的类和模块系统时。Svelte 只是借用了这些类似的概念来编写他们的编译器。现在，我们应该看一下编译过程的输出。我们会注意到我们有一个`bundle.css`和一个`bundle.js`文件。如果我们首先查看生成的`bundle.css`文件，我们会看到类似以下的内容：

```js
h1.svelte-i7qo5m{color:purple}
```

基本上，Svelte 通过将它们放在一个唯一的命名空间下来*模仿*Web 组件，这种情况下是`svelte-i7qo5m`。这非常简单，那些使用过其他系统的人会注意到这是许多框架创建作用域样式表的方式。

现在，如果我们进入`bundle.js`文件，我们会看到一个完全不同的情况。首先，我们有一个**立即调用的函数表达式**（**IIFE**），这是实时重新加载代码。接下来，我们有另一个 IIFE，它将我们的应用程序分配给一个名为`app`的全局变量。然后，代码内部有一堆样板代码，如`noop`，`run`和`blank_object`。我们还可以看到 Svelte 包装了许多内置方法，例如 DOM 的`appendChild`和`createElement`API。以下代码可以看到：

```js
function append(target, node) {
    target.appendChild(node);
}
function insert(target, node, anchor) {
    target.insertBefore(node, anchor || null);
}
function detach(node) {
    node.parentNode.removeChild(node);
}
function element(name) {
    return document.createElement(name);
}
function text(data) {
    return document.createTextNode(data);
}
function space() {
    return text(' ');
}
```

他们甚至将`addEventListener`系统包装在自己的形式中，以便他们可以控制回调和生命周期事件。以下代码可以看到：

```js
function listen(node, event, handler, options) {
    node.addEventListener(event, handler, options);
    return () => node.removeEventListener(event, handler, options);
}
```

他们随后有一堆数组，它们被用作各种事件的队列。他们循环遍历这些数组，弹出并运行事件。这可以在他们设计的 flush 方法中看到。有一个有趣的地方是他们设置了`seen_callbacks`。这是为了通过计算可能导致无限循环的方法/事件来阻止无限循环。例如，组件*A*得到一个更新，随后发送一个更新给组件*B*，然后组件*B*再发送一个更新给组件*A*。在这里，`WeakSet`可能是一个更好的选择，但他们选择使用常规的`Set`，因为一旦 flush 方法完成，它将被清除。

一个很好查看的最终函数是`create_fragment`方法。我们会注意到它返回一个对象，其中有一个名为`c`的 create 函数。正如我们所看到的，这将创建我们在 Svelte 文件中拥有的 HTML 元素。然后我们会看到一个`m`属性，这是将我们的 DOM 元素添加到实际文档中的 mount 函数。`p`属性更新了我们绑定到这个 Svelte 组件的属性（在这种情况下是`name`和`counter`属性）。最后，我们有`d`属性，它与`destroy`方法相关，它会删除所有 DOM 元素和 DOM 事件。

通过查看这段代码，我们可以看到 Svelte 正在利用我们如果从头开始构建 UI 并自己利用 DOM API 时会使用的许多概念，但他们只是将它包装成一堆方便的包装器和巧妙的代码行。

了解一个库的一个很好的方法是阅读源代码或查看它的输出。通过这样做，我们可以找到魔力通常存在的地方。虽然这可能不会立即有益，但它可以帮助我们为框架编写代码，甚至利用我们在他们的代码中看到的一些技巧来编写我们自己的代码库。学习的一种方式是模仿他人。

在所有这些中，我们可以看到 Svelte 声称没有运行时。他们利用了 DOM 提供的基本元素，以一些方便的包装器的形式。他们还为我们提供了一个很好的文件格式来编写我们的代码。尽管这可能看起来像一些基本的代码，但我们能够以这种风格编写复杂的应用程序。

我们将编写的第一个应用程序是一个简单的待办事项应用程序。我们将为其添加一些自己的想法，但它起初将是一个传统的待办事项应用程序。

# 构建基础-一个待办事项应用程序

为了开始我们的待办事项应用程序，让我们继续使用我们已经有的模板。现在，在大多数待办事项应用程序中，我们希望能够做以下事情：

+   添加

+   删除/标记为完成

+   更新

所以我们拥有一个基本的 CRUD 应用程序，没有任何服务器操作。让我们继续编写我们期望在这个应用程序中看到的 Svelte HTML：

```js
<script>
    import { createEventDispatcher } from 'svelte';
    export let completed;
    export let num;
    export let description;

    const dispatch = createEventDispatcher();
</script>
<style>
    .completed {
        text-decoration: line-through;
    }
</style>
<li class:completed>
    Task {num}: {description}
    <input type="checkbox" bind:checked={completed} />
    <button on:click="{() => dispatch('remove', null)}">Remove</button>
</li>
```

我们将我们的待办事项应用程序分成了一个待办事项组件和一个通用应用程序。待办事项元素将包含我们的所有逻辑，用于完成和删除元素。正如我们从前面的例子中看到的，我们正在做以下事情：

+   我们公开这项任务的编号和描述。

+   我们有一个隐藏在主应用程序中的已完成属性。

+   我们有一个用于样式化已完成项目的类。

+   列表元素与完成变量绑定到完成类。

+   `num`和`description`属性与信息相关联。

+   当我们完成一个项目时，会添加一个复选框。

+   还有一个按钮，它会告诉我们的应用程序我们想要删除什么。

这是相当多的内容需要消化，但当我们把它们放在一起时，我们会发现这包含了大部分单个待办事项的逻辑。现在，我们需要添加我们应用程序的所有逻辑。它应该看起来像下面这样：

```js
<script>
    import Todo from './Todo.svelte';

    let newTodoText = '';
    const Todos = new Set();

    function addTodo() {
        const todo = new Todo({
            target: document.querySelector('#main'),
            props: {
                num : Todos.size,
                description : newTodoText
            }
        });
        newTodoText = '';
        todo.$on('remove', () => {
            Todos.delete(todo);
            todo.$destroy();
        });
        Todos.add(todo);
    }
</script>
<style></style>
<h1>Todo Application!</h1>
<ul id="main">
</ul>
<button on:click={addTodo}>Add Todo</button>
<input type="text" bind:value={newTodoText} />
```

首先导入我们之前创建的“待办事项”。然后，我们将`newTodoText`作为与我们的输入文本绑定的属性。然后，我们创建一个集合来存储我们所有的“待办事项”。接下来，我们创建一个`addTodo`方法，该方法将绑定到我们的“添加待办事项”按钮的`click`事件上。这将创建一个新的“待办事项”，将元素绑定到我们的无序列表，并将属性设置为我们的集合大小和输入文本。我们重置“待办事项”文本，并添加一个移除监听器来销毁“待办事项”，并从我们的集合中删除它。最后，我们将其添加到我们的集合中。

我们现在有了一个基本的待办事项应用程序！所有这些逻辑应该都很简单。让我们添加一些额外的功能，就像在上一章中一样。我们将向我们的待办事项应用程序添加以下内容，使其更加健壮和有用：

+   每个“待办事项”都有关联的截止日期

+   保持所有“待办事项”的计数

+   创建过期、已完成和全部过滤器

+   基于过滤器和每个“待办事项”的添加进行过渡

首先，让我们向我们的待办事项应用程序添加一个截止日期。我们将在我们的`Todo.svelte`文件中添加一个名为`dueDate`的新导出字段，并将其添加到我们的模板中，如下所示：

```js
//inside of script tag
export let dueDate;

//part of the template
<li class:completed>
    Task {num}: {description} - Due on {dueDate}
    <input type="checkbox" bind:checked={completed} />
    <button on:click="{() => dispatch('remove', null)}">Remove</button>
</li>
```

然后，在我们的`App.svelte`文件中，我们将添加一个日期控件，并确保当我们将我们的“待办事项”添加到列表时，我们还要确保将此字段放回去。这应该看起来像以下内容：

```js
//inside of the script tag
let newTodoDate = null;
function addTodo() {
    const todo = new Todo({
        target: document.querySelector('#main'),
        props: {
            num : Todos.size + 1,
            dueDate : newTodoDate,
            description : newTodoText
        }
    });
    newTodoText = '';
    newTodoDate = null;
    todo.$on('remove', () => {
        Todos.delete(todo);
        todo.$destroy();
    });
    Todos.add(todo);
}

//part of the template
<input type="date" bind:value={newTodoDate} />
```

我们现在有一个完全功能的截止日期系统。接下来，我们将在我们的应用程序中添加当前“待办事项”的数量。这只需要将一些文本绑定到我们集合的大小的 span 中，如下所示：

```js
//inside of script tag
let currSize = 0;
function addTodo() {
    const todo = new Todo({
        // code removed for readability
    });
    todo.$on('remove', () => {
        Todos.delete(todo);
        currSize = Todos.size;
        todo.$destroy();
    });
    Todos.add(todo);
    currSize = Todos.size;
}

//part of the template
<h1>Todo Application! <span> Current number of Todos: {currSize}</span></h1>
```

好了，现在我们想要对所有日期和已完成状态做一些处理。让我们添加一些过滤器，这样我们就可以删除不符合我们条件的“待办事项”。我们将添加已完成和过期过滤器。我们将把它们做成复选框，因为一项任务可以同时过期和已完成：

```js
//inside of script tag
let completed = false;
let overdue = false;

//part of the template
<label><input type="checkbox" bind:checked={completed}
    on:change={handleFilter}/>Completed</label>
<label><input type="checkbox" bind:checked={overdue}
    on:change={handleFilter}/>Overdue</label>
```

我们的处理过滤逻辑应该看起来像以下内容：

```js
function handleHide(item) {
    const currDate = Date.now();
    if( completed && overdue ) {
        item.hidden = !item.completed || new Date(item.dueDate).getTime() < currDate;
        return;
    }
    if( completed ) {
        item.hidden = !item.completed;
        return;
    }
    if( overdue ) {
        item.hidden = new Date(item.dueDate).getTime() < currDate;
        return;
    }
    item.hidden = false;
}

function handleFilter() {
    for(const item of Todos) {
        handleHide(item);
    }
}
```

我们还需要确保对任何新的“待办事项”项目都有相同的隐藏逻辑：

```js
const todo = new Todo({
    target: document.querySelector('#main'),
    props: {
        num : Todos.size + 1,
        dueDate : newTodoDate,
        description : newTodoText
    }
});
handleHide(todo);
```

最后，我们的`Todo.svelte`组件应该看起来像以下内容：

```js
<svelte:options accessors={true} />
<script>
    import { createEventDispatcher } from 'svelte';

    export let num;
    export let description;
    export let dueDate;
    export let hidden = false;
    export let completed = false;

    const dispatch = createEventDispatcher();
</script>
<style>
    .completed {
        text-decoration: line-through;
    }
    .hidden {
        display : none;
    }
</style>
<li class:completed class:hidden>
    Task {num}: {description} - Due on {dueDate}
    <input type="checkbox" bind:checked={completed} />
    <button on:click="{() => dispatch('remove', null)}">Remove</button>
</li>
```

这些大部分应该看起来很熟悉，除了顶部部分。我们可以在 Svelte 文件中添加特殊标签，以便访问某些属性，例如以下内容：

+   `<svelte:window>` 给了我们访问窗口事件的权限。

+   `<svelte:body>` 给了我们访问 body 事件的权限。

+   `<svelte:head>` 给了我们访问文档头部的权限。

+   `<svelte:component>` 给了我们访问自己作为 DOM 元素的权限。

+   `<svelete:self>` 允许我们包含自己（用于递归结构，如树）。

+   `<svelte:options>` 允许我们向组件添加编译器选项。

在这种情况下，我们希望我们的父组件能够通过 getter/setter 访问我们的属性，因此我们将`accessors`选项设置为`true`。这就是我们能够在`App.svelte`文件中更改我们的隐藏属性，并允许我们获取每个“待办事项”的属性的方式。

最后，让我们添加一些淡入淡出的过渡效果。Svelte 在添加/删除元素时带有一些不错的动画。我们要使用的是`fade`动画。因此，我们的`Todo.svelte`文件现在将添加以下内容：

```js
//inside of script tag
import { fade } form 'svelte/transition';

//part of template
{#if !hidden}
    <li in:fade out:fade class:completed>
        Task {num}: {description} - Due on {dueDate}
        <input type="checkbox" bind:checked={completed} />
        <button on:click="{() => dispatch('remove', null)}">Remove</button>
    </li>
{/if}
```

这种特殊的语法是用于条件性 DOM 添加/删除。就像我们可以用 DOM API 添加/删除子元素一样，Svelte 也在做同样的事情。接下来，我们可以看到我们在列表元素上添加了`in:fade`和`out:fade`指令。现在，当元素从 DOM 中添加或移除时，它将淡入和淡出。

我们现在有一个相当功能齐全的待办事项应用程序。我们有过滤逻辑，与截止日期相关的“待办事项”，甚至还有一点动画。下一步是稍微整理一下代码。我们可以通过 Svelte 内置的存储来实现这一点。

存储是一种在不必使用一些我们在应用程序中必须使用的技巧的情况下共享状态的方法（当我们可能不应该打开访问者系统时）。我们的`Todos`和我们的主应用程序之间的共享状态是过期和已完成的过滤器。每个`Todo`很可能应该控制这个属性，但我们目前正在利用访问者选项，并且所有的过滤都是在我们的主应用程序中完成的。有了可写存储，我们就不再需要这样做了。

首先，我们编写一个`stores.js`文件，如下所示：

```js
import { writable } from 'svelte/store';

export const overdue = writable(false);
export const completed = writable(false);
```

接下来，我们更新我们的`App.svelte`文件，不再针对`Todos`中的`hidden`属性，并将我们的复选框输入的`checked`属性绑定到存储，如下所示：

```js
//inside of script tag
import { completed, overdue } from './stores.js';

//part of the template
<label><input type="checkbox" bind:checked={$completed} />Completed</label>
<label><input type="checkbox" bind:checked={$overdue} />Overdue</label>
```

我们脚本中的存储前面的美元符号表示这些是存储而不是变量。它允许我们在销毁时更新和订阅存储，而无需取消订阅。最后，我们可以更新我们的`Todo.svelte`文件，使其如下所示：

```js
<script>
    import { overdue, completed } from './stores.js';
    import { createEventDispatcher, onDestroy } from 'svelte';
    import { fade } from 'svelte/transition';

    export let num;
    export let description;
    export let dueDate;
    let _completed = false;

    const dispatch = createEventDispatcher();
</script>
<style>
    .completed {
        text-decoration: line-through;
    }
</style>
{#if
    !(
         ($completed && !_completed) ||
         ($overdue && new Date(dueDate).getTime() >= Date.now())
     )
}
    <li in:fade out:fade class:_completed>
        Task {num}: {description} - Due on {dueDate}
        <input type="checkbox" bind:checked={_completed} />
        <button on:click="{() => dispatch('remove', null)}">Remove</button>
    </li>
{/if}
```

我们已经将过期和已完成的存储添加到我们的系统中。您可能已经注意到，我们已经摆脱了文件顶部的编译器选项。然后我们将我们的`#if`条件链接到这些存储。我们现在已经将隐藏`Todos`的责任放在了`Todos`自身上，同时也删除了相当多的代码。很明显，我们可以以多种方式构建 Svelte 应用程序，并对应用程序保持相当多的控制。

在进入下一个应用程序之前，继续查看捆绑的 JavaScript 和 CSS，并向应用程序添加新功能。接下来，我们将看看如何构建一个天气应用程序并从服务器获取这些信息。

# 变得更加花哨-一个基本的天气应用程序

很明显，Svelte 已经建立起了与大多数现代 ECMAScript 标准兼容的编译器。他们没有提供任何获取数据的包装器的领域是在这里。添加这个并看到效果的一个好方法是构建一个基本的天气应用程序。

天气应用程序在其核心需要能够输入邮政编码或城市，并输出该地区的当前天气信息。我们还可以根据这个位置得到天气的预测。最后，我们还可以将这些选择保存在浏览器中，这样我们在回到应用程序时就可以使用它们。

对于我们的天气数据，我们将从[`openweathermap.org/api`](https://openweathermap.org/api)获取。在这里，免费服务将允许我们获取当前天气。除此之外，我们还需要一个输入系统，可以接受以下内容：

+   城市/国家

+   邮政编码（如果没有给出国家，我们将假设是美国，因为这是 API 的默认值）

当我们输入正确的值时，我们将把它存储在`LocalStorage`中。在本章的后面，我们将更深入地研究`LocalStorage`API，但请注意它是浏览器中的键值存储机制。当我们输入输入值时，我们将得到所有先前搜索的下拉列表。我们还将添加删除列表中任何一个结果的功能。

首先，我们需要获取一个 API 密钥。要做到这一点，请按照以下步骤进行：

1.  前往[`openweathermap.org/api`](https://openweathermap.org/api)并按照说明获取 API 密钥。

1.  一旦我们创建了一个帐户并验证它，我们就能够添加 API 密钥。

1.  登录后，应该有一个标签，上面写着**API keys**。如果我们去那里，应该会看到一个*no api keys*的消息。

1.  我们可以创建一个密钥并为其添加一个名称（我们可以称之为`default`）。

1.  有了这个密钥，我们现在可以开始调用他们的服务器。

让我们继续设置一个测试调用。以下代码应该可以工作：

```js
let api_key = "<your_api_key>";
fetch(`https://api.openweathermap.org/data/2.5/weather?q=London&appid=${api_key}`)
    .then((res) => res.json())
    .then((final) => console.log(final));
```

如果我们将这些放入代码片段中，我们应该会得到一个包含大量数据的 JSON 对象。现在我们可以继续使用 Svelte 来利用这个 API 创建一个漂亮的天气应用程序。

让我们以与设置 Todo 应用程序相同的方式设置我们的应用程序。运行以下命令：

```js
> cd ..
> npx degit sveltejs/template weather
> cd weather
> npm install
> npm run dev
```

现在我们已经启动了环境，让我们创建一个带有一些基本样式的样板应用程序。在`global.css`文件中，将以下行添加到 body 中：

```js
display: flex;
flex-direction : column;
align-items : center;
```

这将确保我们的元素都是基于列的，并且它们将从中心开始并向外扩展。这将为我们的应用程序提供一个漂亮的外观。接下来，我们将创建两个 Svelte 组件，一个`WeatherInput`和一个`WeatherOutput`组件。接下来，我们将专注于输入。

我们需要以下项目，以便从用户那里获得正确的输入：

+   输入邮政编码或城市

+   输入国家代码

+   一个提交按钮

我们还将向我们的应用程序添加一些条件逻辑。我们将根据输入框左侧的复选框有条件地呈现文本或数字输入，而不是尝试解析输入。有了这些想法，我们的`WeatherInput.svelte`文件应该如下所示：

```js
<script>
    import { zipcode } from './stores.js';
    const api_key = '<your_api_key>'

    let city = null;
    let zip = null;
    let country_code = null;

    const submitData = function() {
        fetch(`https://api.openweathermap.org/data/2.5/weather?q=${zipcode 
         ? zip : city},${country_code}&appid=${api_key}`)
            .then(res => res.json())
            .then(final => console.log(final));
    }
</script>
<style>
    input:valid {
        border: 1px solid #333;
    }
    input:invalid {
        border: 1px solid #c71e19;
    }
</style>
<div>
    <input type="checkbox" bind:checked={$zipcode} />
    {#if zipcode}
        <input type="number" bind:value={zip} minLength="6" maxLength="10" 
         require />
    {:else}
        <input type="text" bind:value={city} required />
    {/if}
    <input type="text" bind:value={country_code} minLength="2" 
     maxLength="2" required />
    <button on:click={submitData}>Check</button>
</div>
```

有了这个，我们就有了我们输入的基本模板。首先，我们创建一个`zipcode`存储，以有条件地显示数字或文本输入。然后，我们创建了一些本地变量，将它们绑定到我们的输入值上。`submitData`函数将在我们准备好获得某种响应时提交所有内容。目前，我们只是将输出记录到开发者控制台中。

对于样式，我们只是为有效和无效的输入添加了一些基本样式。我们的模板给了我们一个复选框，用于打开`zipcode`功能或关闭它。然后我们有条件地显示`zipcode`或城市文本框。每个文本框都添加了内置验证。接下来，我们添加了另一个文本字段，以从用户那里获取国家代码。最后，我们添加了一个按钮，将会去检查数据。

在 Svelte 中，括号被大量使用。输入验证的一个特性是基于正则表达式的。该字段称为模式。如果我们在这里尝试使用括号，将会导致 Svelte 编译器失败。请注意这一点。

在进行输出之前，让我们先给我们的输入添加一些标签，以使用户更容易使用。以下内容应该可以做到：

```js
//in the style tag
input {
    margin-left: 10px;
}
label {
    display: inline-block;
}
#cc input {
    width: 3em;
}
```

对于每个`input`元素，我们已经将它们包装在`label`中，如下所示：

```js
<label id="cc">Country Code<input type="text" bind:value={country_code} minLength="2" maxLength="2" required /></label>
```

有了这个，我们有了`input`元素的基本用户界面。现在，我们需要让`fetch`调用实际输出到可以在我们创建后可用于`WeatherOutput`元素的东西。让我们创建一个自定义存储来实现`gather`方法，而不是只是将这些数据作为 props 传递出去。在`stores.js`中，我们应该有以下内容：

```js
function createWeather() {
    const { subscribe, update } = writable({});
    const api_key = '<your_api_key>';
    return {
        subscribe,
        gather: (cc, _z, zip=null, city=null) => {
            fetch(`https://api.openweathermap.org/data/2.5/weather?=${_z ? 
             zip : city},${cc}&appid=${api_key})
                .then(res => res.json())
                .then(final => update(() => { return {...final} }));
        }
    }
}
```

我们现在已经将获取数据的逻辑移到了存储中，现在我们可以订阅这个存储来更新自己。这意味着我们可以让`WeatherOutput`组件订阅这个存储以获得一些基本输出。以下代码应该放入`WeatherOtuput.svelte`中：

```js
<script>
    import { weather } from './stores.js';
</script>
<style>
</style>
<p>{JSON.stringify($weather)}</p>
```

现在我们所做的就是将我们的天气输出放入一个段落元素中，并对其进行字符串化，以便我们可以在不查看控制台的情况下阅读输出。我们还需要更新我们的`App.svelte`文件，并像这样导入`WeatherOutput`组件：

```js
//inside the script tag
import WeatherOutput from './WeatherOutput.svelte'

//part of the template
<WeatherOutput></WeatherOutput>
```

如果我们现在测试我们的应用程序，我们应该会得到一些难看的 JSON，但是我们现在通过存储将我们的两个组件联系起来了！现在，我们只需要美化输出，我们就有了一个完全功能的天气应用程序！更改`WeatherOutput.svelte`中的样式和模板如下：

```js
<div>
    {#if $weather.error}
        <p>There was an error getting your data!</p>
    {:else if $weather.data}
        <dl>
            <dt>Conditions</dt>
            <dd>{$weather.weather}</dd>
            <dt>Temperature</dt>
            <dd>{$weather.temperature.current}</dd>
            <dd>{$weather.temperature.min}</dd>
            <dd>{$weather.temperature.max}</dd>
            <dt>Humidity</dt>
            <dd>{$weather.humidity}</dd>
            <dt>Sunrise</dt>
            <dd>{$weather.sunrise}</dd>
            <dt>Sunset</dt>
            <dd>{$weather.sunset}</dd>
            <dt>Windspeed</dt>
            <dd>{$weather.windspeed}</dd>
            <dt>Direction</dt>
            <dd>{$weather.direction}</dd>
        </dl>
    {:else}
        <p>No city or zipcode has been submitted!</p>
    {/if}
</div>
```

最后，我们应该添加一个新的控件，让我们的用户可以选择输出的公制或英制单位。将以下内容添加到`WeatherInput.svelte`中：

```js
<label>Metric?<input type="checkbox" bind:checked={$metric}</label>
```

我们还将在`stores.js`文件中使用一个新的`metric`存储，默认值为`false`。有了这一切，我们现在应该有一个功能齐全的天气应用程序了！我们唯一剩下的部分是添加`LocalStorage`功能。

有两种类型的存储可以做类似的事情。它们是`LocalStorage`和`SessionStorage`。主要区别在于它们的缓存时间有多长。`LocalStorage`会一直保留，直到用户删除缓存或应用程序开发人员决定删除它。`SessionStorage`在页面的生命周期内保留在缓存中。一旦用户决定离开页面，`SessionStorage`就会清除。离开页面意味着关闭标签页或导航离开；它不意味着重新加载页面或 Chrome 崩溃并且用户恢复页面。由设计者决定使用哪种方式。

利用`LocalStorage`非常容易。在我们的情况下，该对象保存在窗口上（如果我们在工作程序中，它将保存在全局对象上）。需要记住的一件事是，当我们使用`LocalStorage`时，它会将所有值转换为字符串，因此如果我们想要存储复杂对象，我们需要进行转换。

要更改我们的应用程序，让我们专门为我们的下拉列表创建一个新组件。让我们称之为`Dropdown`。首先，创建一个`Dropdown.svelte`文件。接下来，将以下代码添加到文件中：

```js
<script>
    import { weather } from './stores.js';
    import { onDestroy, onMount } from 'svelte';

    export let type = "text";
    export let name = "DEFAULT";
    export let value = null;
    export let required = true;
    export let minLength = 0;
    export let maxLength = 100000;
    let active = false;
    let inputs = [];
    let el;

    const unsubscribe = weather.subscribe(() => {
        if(!inputs.includes(value) ) {
            inputs = [...inputs, value];
            localStorage.setItem(name, inputs);
        }
        value = '';
    });
    const active = function() {
        active = true;
    }
    const deactivate = function(ev) {
        if(!ev.path.includes(el) ) 
            active = false;
    }
    const add = function(ev) {
        value = ev.target.innerText;
        active = false;
    }
    const remove = function(ev) {
        const text = ev.target.parentNode.querySelector('span').innerText;
        const data = localStorage.getItem(name).split(',');
        data.splice(data.indexOf(text));
        inputs = [...data];
        localStorage.setItem(name, inputs);
    }
    onMount(() => {
        const data = localStorage.getItem(name);
        if( data === "" ) { inputs = []; }
        else { inputs = [...data.split(',')]; }
    });
    onDestroy(() => {
        unsubscribe();
    });
</script>
<style>
    input:valid {
        border 1px solid #333;
    }
    input:invalid {
        border 1px solid #c71e19;
    }
    div {
        position : relative;
    }
    ul {
        position : absolute;
        top : 100%;
        list-style-type : none;
        background : white;
        display : none;
    }
    li {
        cursor : hand;
        border-bottom : 1px solid black;
    }
    ul.active {
        display : inline-block;
    }
</style>
<svelte:window on:mousedown={deactivate} />
<div>
    {#if type === "text"}
        <input on:focus={activate} type="text" bind:value={value} 
         {minLength} {maxLength} {required} />
    {:else}
        <input on:focus={activate} type="number" bind:value={value} 
         {minLength} {maxLength} {required} />
    {/if}
    <ul class:active bind:this={el}>
        {#each inputs as input }
            <li><span on:click={add}>{input}</span> <button 
             on:click={remove}>&times;</button></li>
        {/each}
    </ul>
</div>
```

这是相当多的代码，让我们分解一下我们刚刚做的事情。首先，我们将我们的输入更改为`dropdown`组件。我们还将许多状态内部化到这个组件中。我们打开各种字段，以便用户能够自定义字段本身。我们需要确保设置的主要字段是`name`。这是我们用于存储搜索的`LocalStorage`键。

接下来，我们订阅`weather`存储。我们不使用实际数据，但我们确实获得事件，因此如果选择是唯一的（可以使用集合而不是数组），我们可以将其添加到存储中。如果我们想要激活下拉列表，我们还添加了一些基本逻辑，如果我们聚焦或者点击了下拉列表之外。我们还为列表元素的点击事件添加了一些逻辑（实际上是将其添加到列表元素的子元素），以将文本放入下拉列表或从我们的`LocalStorage`中删除。最后，我们为组件的`onMount`和`onDestroy`添加了行为。`onMount`将从`localStorage`中获取并将其添加到我们的输入列表中。`onDestroy`只是取消了我们的订阅，以防止内存泄漏。

其余的样式和模板应该看起来很熟悉，除了无序列表系统中的`bind:this`。这允许我们将变量绑定到元素本身。这使我们能够在事件路径中的元素不在列表中时取消激活我们的下拉列表。

有了这些，对`WeatherInput.svelte`进行以下更新：

```js
//inside the script tag
import Dropdown from './Dropdown.svelte';

//part of the template
{#if $zipcode}
    <label>Zip<Dropdown name="zip" type="number" bind:value={zip} 
     minLength="6" maxLength="10"></Dropdown></label>
{:else}
    <label>City<Dropdown name="city" bind:value={city}></Dropdown></label>
{/if}
<label>Country Code<Dropdown name="cc" bind:value={country_code} 
 minLength="2" maxLength="2"></Dropdown></label>
```

我们现在已经创建了一个半可重用的`dropdown`组件（我们依赖于天气存储，因此它实际上只适用于我们的应用程序），并且已经创建了一个看起来像单个组件的东西。

# 总结

Svelte 是一个有趣的框架，我们将代码编译成原生 JavaScript。它利用现代思想，如模块、模板和作用域样式。我们还能够以简单的方式创建可重用的组件。虽然我们可以对我们构建的应用程序进行更多的优化，但我们可以看到它们确实有多快。虽然 Svelte 可能不会成为应用程序开发的主流选择，但它是一个很好的框架，可以看到我们在之前章节中探讨的许多概念。

接下来，我们将暂时离开浏览器，看看如何利用 Node.js 在服务器上使用 JavaScript。我们在这里看到的许多想法将被应用在那里。我们还将看到编写应用程序的新方法，以及如何在整个网络生态系统中使用一种语言。


# 第五章：切换上下文-没有 DOM，不同的 Vanilla

当我们把注意力从浏览器转向其他地方时，我们将进入大多数后端程序员熟悉的环境。Node.js 为我们提供了一个熟悉的语言，即 JavaScript，可以在系统环境中使用。虽然 Node.js 以用于编写服务器的语言而闻名，但它可以用于大多数其他语言所用的大多数功能。例如，如果我们想创建一个**命令行界面**（**CLI**）工具，我们就有能力做到。

Node.js 还为我们提供了类似于浏览器中看到的编程环境。我们得到了一个允许我们进行异步**输入和输出**（**I/O**）的事件循环。这是通过 libuv 库实现的。在本章的后面，我们将解释这个库以及它如何帮助我们提供我们习惯的常见事件循环。首先，我们将看看如何启动和运行 Node.js，以及编写一些简单的程序。

在本章中，我们将涵盖以下主题：

+   获取 Node.js

+   理解无 DOM 的世界

+   调试和检查代码

让我们开始吧。

# 技术要求

本章需要以下技术要求：

+   像 VS Code 这样的编辑器或 IDE

+   本章的代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter05)找到。

# 获取 Node.js

之前的章节要求有一个 Node.js 运行时。在本章中，我们将看看如何在我们的系统上安装它。如果我们前往[`Node.js.org/en/`](https://nodejs.org/en/)，我们将能够下载**长期支持**（**LTS**）版本或当前版本。对于本书来说，建议获取当前版本，因为模块支持更好。

对于 Windows，我们只需要下载并运行可执行文件。对于 OS X 和 Linux，这也应该很简单。特别是对于 Linux 用户，可能在特定发行版的存储库中有一个版本，但这个版本可能很旧，或者与 LTS 版本一致。记住：我们希望运行最新版本的 Node.js。

一旦我们安装好了，我们应该能够从任何命令行调用`node`命令（Linux 用户可能需要调用`Node.js`命令，因为一些存储库已经在其存储库中包含了一个 node 包）。一旦调用，我们应该会看到一个**读取评估打印循环**（**REPL**）工具。这使我们能够在实际将代码写入文件之前测试一些代码。运行以下代码片段：

```js
1 + 2 //3
typeof("this") //'string'
const x = 'what' //undefined
x //'what'
x = 'this' //TypeError: Assignment to a constant variable
const fun = function() { console.log(x); } //undefined
fun() //'what' then undefined
fun = 'something' //TypeError: Assignment to a constant variable
```

从这些例子中，很明显我们正在一个类似于我们在浏览器中使用的环境中工作。我们可以访问大多数我们在浏览器中拥有的数据操作和功能概念。

我们无法访问许多特定于浏览器的库/ API，比如 DOM API。我们也无法访问任何浏览器外部资源访问库，比如`Fetch`或`XMLHttpRequest`。我们将稍后讨论它们的较低级版本，但应该注意的是，在某些方面，它并不像调用 fetch API 那样简单。

继续玩一下 REPL 系统。如果我们想退出，只需要在 Windows 上按两次*Ctrl* + *C*（Linux 应该是一样的；对于 OS X，我们需要使用*command* + *C*）。现在，要运行一个脚本，我们只需要把一些代码放在一个 JavaScript 文件中，然后调用**`node <filename>`**。这应该在立即模式下运行我们的脚本。这可以在以下的`example.js`文件中看到：

```js
const x = 'what';
console.log('this is the value of x', x); //'this is the value of x what'
const obj = {
    what : 'that',
    huh : 'this',
    eh : 'yeah'
}
console.log(obj); // { what : 'that', huh : 'this', eh : 'yeah' }
```

为了访问 Node.js 给我们的各种内置库，我们可以利用两种不同的方法。首先，我们可以使用旧的`require`系统。以下脚本展示了这种能力：

```js
const os = require('os');

console.log(os.arch()); //prints out x64 on 64-bit OS
console.log(os.cpus()); //prints out information on our CPU
```

这是当前引入内置/用户构建模块的方式。这是 Node 团队决定的风格，因为没有常见的引入模块的方式。我们有 RequireJS 或 CommonJS 等系统，Node.js 决定采用 CommonJS 风格引入模块。然而，正如我们所了解的，也有一种标准化的方式将模块引入浏览器。对于 Node.js 平台也是如此。

模块系统目前处于实验阶段，但如果需要，可以使用诸如 RollupJS 之类的系统将代码更改为通用识别的系统版本，例如**通用模块依赖**（**UDM**）系统。

这个系统看起来应该很熟悉。以下脚本显示了先前的示例，但是在模块导入系统中：

```js
import os from 'os';

console.log(os.arch());
console.log(os.cpus());
```

我们还需要一个`package.json`文件，在其清单中有`"type" : "module"`。

# package.json 文件概述

`package.json`文件包含了我们正在构建的包的所有信息。它甚至让我们能够将其与我们的版本控制系统联系起来，甚至可以将其与我们的构建系统联系起来。让我们现在来看一下。

首先，`package.json`文件应该填写以下字段：

+   `name`：这是包的名称。

+   `version`：这是我们软件包的当前版本。

+   `type`：这应该是`module`或`commonjs`。这将允许我们区分传统系统和新的 ECMAScript 模块系统。

+   `license`：这是我们想要许可我们的模块的方式。大多数情况下，只需放置 MIT 许可证。然而，如果我们想要更严格地限制它，我们可以随时使用 GPL 或 LGPL 许可证。

+   `author`：这是一个带有`name`、`email`和`url`字段的对象。这为软件提供了归属，并帮助人们知道是谁构建了它。

+   `main`：这是模块的主入口点。这将允许其他人使用我们的模块并要求/导入它。它还将让系统知道在哪里寻找我们模块的起始点。

还有许多其他可以使用的字段，如下：

+   `man`：这允许`man`命令找到我们希望为我们的文档提供的文件。

+   `description`：这允许我们提供关于我们的模块及其功能的更多信息。如果描述超过两到三句，建议附带一个`README`文件。

+   `repository`：这允许其他人找到存储库并为其做出贡献或提交错误报告/功能请求。

+   `config`：这是一个对象，可以被我们在`package.json`文件的脚本部分定义的脚本使用。脚本将很快会详细讨论。

+   `dependencies`：这是我们的模块依赖的模块列表。这可以是来自公共`npm`注册表、私有存储库、Git 存储库、tarballs，甚至是本地文件路径用于本地开发。

+   `devDependencies`：这是需要用于此软件包开发的依赖列表。

+   `peerDependencies`：这是我们的包可能需要的依赖列表，如果有人使用系统的一部分。这允许我们的用户下载核心系统，如果他们想要使用其他部分，他们可以下载这些其他子系统需要的对等依赖。

+   `OS`：这是我们运行的操作系统列表。这也可以是其否定版本，比如`!darwin`，意味着这个系统将在除 OS X 之外的所有操作系统上运行。

+   `engines`：我们运行的 Node.js 版本。当我们使用最近版本引入的功能（例如 ECMAScript 模块）时，我们将要使用这个。如果我们使用已被弃用的模块并希望将 Node.js 版本锁定到旧版本，我们也可能想要使用这个功能。

`package.json`文件中还有一些其他字段，但这些是最常见的。

我们想要查看的`package.json`文件的一个特定部分是脚本部分。如果我们去查看`npm`的网站关于脚本部分的信息，它陈述了以下内容：

`scripts`属性是一个包含在包的生命周期中的各个时间点运行的脚本命令的字典。键是生命周期事件，值是在该点运行的命令。

如果我们进入更多细节部分，我们将看到我们可以使用生命周期钩子，以便我们可以通过捆绑和分发过程运行各种脚本。

值得注意的是，这些信息特定于**Node Package Manager**（**npm**）。在学习 Node.js 的过程中，我们会经常遇到`npm`，因此学习 Node.js 也意味着学习`npm`。

我们感兴趣的一些具体点是打包生命周期的**prepare**和**install**部分。让我们看看这些部分涵盖了什么：

+   **Prepare**将在将包打包成 tarball 并发布到远程存储库之前运行脚本。这是运行编译器和捆绑器以准备部署我们的包的好方法。

+   **Install**将在安装完包后运行脚本。当我们拉取一个包并想要运行诸如`node-gyp`之类的东西，或者我们的包可能需要的特定于操作系统的东西时，这非常有用。

`scripts`部分的另一个好处是，我们可以在这里放任意字符串并运行`npm run <script>`。无论我们决定使用什么值，都将在运行命令时进行评估。让我们将以下内容添加到我们的`package.json`文件中：

```js
"config" : {
    "port" : 8080,
    "name" : "example",
    "testdata" : {
        "thing" : 5,
        "other" : 10
    }
},
"scripts" : {
    "example-script" : "node main.js"
}
```

这将使我们能够获取配置数据。除此之外，我们还添加了一个可以通过`npm run example-script`命令运行的脚本。如果我们创建一个`main.js`文件并向其中添加以下字段，我们应该会得到以下输出：

```js
console.log(process.env.npm_package_config_port); //8080
console.log(process.env.npm_package_config_name); //'example'
console.log(process.env.npm_package_config_testdata); //undefined
```

这表明我们可以在配置中放入原始值，但我们不能尝试访问复杂对象。我们可以这样做来获取`testdata`对象的属性：

```js
console.log(process.env.npm_package_config_testdata_thing) //5
console.log(process.env.npm_package_config_testdata_other) //10
```

现在我们对 Node.js 和`npm`生态系统有了一些了解，让我们来看看 Node.js 是如何组合在一起的，以及我们将在接下来的章节中使用的一些关键模块。

# 理解无 DOM 世界

正如我们在介绍中所述，Node.js 的出现是基于这样一个想法：如果我们在浏览器中编写代码，那么我们应该能够在服务器上运行它。在这里，我们有一个语言适用于两种情境，无论我们在哪个部分工作，都不必切换上下文。

Node.js 可以通过两个库的混合方式运行。这些库是 V8，我们应该已经熟悉了，以及 libuv，我们目前还不熟悉。libuv 库为我们提供了异步 I/O。每个操作系统都有不同的处理方式，所以 libuv 为我们提供了一个很好的 C 包装器来处理所有这些实例。

libuv 库将 I/O 请求排队到请求堆栈上。然后，它将它们分配给一定数量的线程（Node.js 默认使用四个）。一旦这些线程的响应返回，libuv 将它们放在响应堆栈上，并通知 V8 响应已准备好被消耗。一旦 V8 注意到这个通知，它将从中取出值并将其用于对我们发出的请求的响应。这就是 Node.js 运行时如何能够具有异步 I/O 并仍然保持单线程执行的方式（至少对用户来说是这样看的）。

有了这些基本理解，我们应该能够开始编写一些处理各种 I/O 操作并利用使 Node.js 特殊的想法之一的基本脚本：流系统。

# 流的第一印象

正如我们在 DOM 中看到的那样，流给了我们控制数据流的能力，并且能够以创建非阻塞系统的方式处理数据。通过创建一个简单的流，我们可以看到这一点。让我们继续利用 Node.js 提供的内置流之一，`readFileStream`。让我们编写以下脚本：

```js
import fs from 'fs';
import { PassThrough } from 'stream'

const str = fs.createReadStream('./example.txt');
const pt = new PassThrough();
str.pipe(pt);
pt.on('data', (chunk) => {
    console.log(chunk);
});
```

在这里，我们导入了`fs`库和`stream`库中的`PassThrough`流。然后，我们为`example.txt`文件创建了一个读取流，以及一个`PassThrough`流。

`PassThrough`流允许我们处理数据，而无需显式创建流。我们读取数据并将其传输到我们的`PassThrough`流。

从这里，我们能够获得数据事件的处理，这给了我们一块数据。除此之外，我们还确保在`pipe`方法之后放置了我们的数据事件监听器。通过这样做，我们确保在附加监听器之前没有`data`事件运行。

让我们创建以下`example.txt`文件：

```js
This is some data
it should be processed by our system
it should be coming in chunks that our system can handle
most likely this will all come in one chunk
```

现在，如果我们运行`node --experimental-modules read_file_stream.js`命令，我们将看到它打印出一个`Buffer`。除非我们明确将其设置为对象模式，否则所有数据处理都是以二进制块包装在`Buffer`对象中的。如果我们将控制台日志命令更改为打印以下内容，我们应该得到纯文本输出：

```js
console.log(chunk.toString('utf8'));
```

让我们创建一个程序，统计文本中单词`the`的使用次数。我们可以使用我们的`PassThrough`流来做到这一点，如下所示：

```js
import fs from 'fs';
import { PassThrough } from 'stream';

let numberOfThe = 0;
const chars = Buffer.from('the');
let currPos = 0;
const str = fs.createReadStream('./example.txt');
const pt = new PassThrough();
str.pipe(pt);
pt.on('data', (chunk) => {
    for(let i = 0; i < chunk.byteLength; i++) {
        const char = chunk[i];
        if( char === chars[currPos] ) {
            if( currPos === chars.byteLength - 1 ) // we are at the end so 
             reset
                numberOfThe += 1;
                currPos = 0;
            } else {
                currPos += 1;
            }
        } else {
            currPos += 1;
        }
    }
});
pt.on('end', () => {
    console.log('the number of THE in the text is: ', numberOfThe);
});
```

我们需要记录单词`the`出现的次数。我们还将创建一个`the`字符串的字节缓冲区。我们还需要跟踪我们当前的位置。通过这样做，每当我们获得数据时，我们可以运行并测试每个字节。如果字节与我们持有的当前位置匹配，那么我们需要进行另一个检查。如果它等于单词`the`的字符字节计数，那么我们更新`the`的数量并重置我们的当前位置。否则，我们将当前位置设置为下一个索引。如果我们没有找到匹配，我们需要重置当前位置；否则，我们将得到字符*t*、*h*和*e*的任意组合。

这是一个有趣的例子，展示了如何利用`PassThrough`流，但让我们继续创建我们自己的写`Transform`流。我们将应用与之前相同的操作，但我们将构建一个自定义流。正如文档中所述，我们必须编写`_transform`函数，并且可以选择实现`_flush`函数。我们将实现`_transform`和`_flush`函数。我们还将利用新的类语法，而不是利用旧的基于原型的系统。在构建我们自己的自定义流时要记住的一件事是，在流中做任何其他事情之前运行`super(options)`方法。这将允许用户传递各种流选项，而无需我们做任何事情。

考虑到所有这些，我们应该得到类似以下的东西：

```js
import { Transform } from 'stream';

class GetThe extends Transform {
    #currPos = 0;
    #numberOfThe = 0;

    static chars = Buffer.from('the');
    constructor(options) {
        super(options);
    }
    _transform(chunk, encoding, callback) {
        for(let i = 0; i < chunk.byteLength; i++) {
            const char = chunk[i];
            if( char === GetThe.chars[this.#currPos]) {
                if( this.#currPos === GetThe.chars.byteLength - 1 ) {
                    this.#numberOfThe += 1;
                    this.#currPos = 0;
                } else {
                    this.#currPos += 1;
                }
            } else {
                this.#currPos = 0;
            }
        }
        callback();
    }
    _flush(callback) {
        callback(null, this.#numberOfThe.toString());
    }
}

export default GetThe;

```

首先，我们从`stream`基础库中导入`Transform`流。我们扩展它并创建一些私有变量，即`the`缓冲区中的当前位置和流中`the`的当前计数。我们还为我们要进行比较的缓冲区创建了一个静态变量。然后，我们有我们的构造函数。这是我们将选项传递给`Transform`流构造函数的地方。

接下来，我们以与我们在`PassThrough`流的`data`事件上实现的方式实现`_transform`方法。唯一的新部分应该是在最后调用回调函数。这让我们的流知道我们已经准备好处理更多数据。如果我们需要出错，我们可以将其作为第一个参数传递。我们还可以传递第二个参数，就像在`_flush`函数中所示的那样。这允许我们将处理过的数据传递给可能正在监听的人。在我们的情况下，我们只想传递我们在文本中找到的`the`的数量。我们还可以只传递`Buffer`、`String`或`Uint8Array`，所以我们决定传递我们数字的字符串版本（我们本可以使用`Buffer`，这可能是更好的选择）。最后，我们从我们的模块中导出这个。

在我们的`read_file_stream`文件中，我们将使用以下命令导入此模块：

```js
import GetThe from './custom_transform.js';
```

然后，我们可以使用以下代码：

```js
const gt = new GetThe();
gt.on('data', (data) => {
    console.log('the number of THE produced by the custom stream is: ', 
     data.toString('utf8'));
});
const str2 = fs.createReadStream('./example.txt');
str2.pipe(gt);
```

通过这样做，我们将所有这些逻辑封装到一个单独的模块和可重用的流中，而不仅仅是在`PassThrough`的`data`事件中这样做。我们还可以将我们的流实现链接到另一个流（在这种情况下，除非我们要将其传递给套接字，否则可能没有意义）。

这是流接口的简短介绍，并概述了我们将在后面章节中详细讨论的内容。接下来，我们将看一下 Node.js 附带的一些模块以及它们如何帮助我们编写服务器应用程序。

# 模块的高级视图

有三个 I/O 模块允许我们的应用程序与文件系统和外部世界进行交互。它们分别是：

+   `fs`

+   `net`

+   `http`

这三个模块很可能是用户在开发 Node.js 应用程序时将使用的主要模块。让我们分别来看看它们。

# fs 模块

首先，让我们创建一个访问文件系统、打开文件、添加一些文本、关闭文件，然后再追加一些文本的基本示例。这看起来类似于以下内容：

```js
import { promises } from 'fs';

(async() => {
    await promises.writeFile('example2.txt', "Here is some text\n");
    const fd = await promises.open('example2.txt', 'a');
    await fd.appendFile("Here is some more text\n");
    await fd.close();
    console.log(await promises.readFile('example2.txt', 'utf8'));
})();
```

首先，我们正在获取基于 Promise 的库版本。大多数内置模块都有基于 Promise 的版本，这可以导致看起来很好的代码，特别是与回调系统相比。接下来，我们写入一个文件并给它一些文本。`writeFile`方法允许我们写入文件并在文件不存在时创建文件。之后，我们打开我们文件的`FileHandle`。

Node.js 采用了 POSIX 风格的 I/O。这意味着一切都像文件一样对待。在这种情况下，一切都被分配了一个**文件描述符**（**fd**）。这对我们来说看起来像是 C++等语言中的一个数字。之后，我们可以将这个数字传递给我们可用的各种文件函数。在 Promises API 中，Node.js 决定切换到`FileHandle`对象，这是我们得到的而不是这个文件描述符。这导致了更清晰的代码，并且有时需要在系统上提供一层抽象。

我们可以看到作为第二个参数的`a`表示我们将如何使用文件。在这种情况下，我们将追加到文件中。如果我们用`r`打开它，这意味着我们要从中读取，而如果我们用`w`打开它，这意味着我们要覆盖已经存在的内容。

了解 Unix 系统可以帮助我们更好地理解 Node.js 的工作原理，以及所有这些与我们试图编写的程序之间的对应关系。

然后，我们向文件追加一些文本并关闭它。最后，我们在控制台记录文件中的内容，并声明我们要以 UTF-8 文本而不是二进制形式读取它。

与文件系统相关的 API 还有很多，建议查看 Promise 文档以了解我们有哪些能力，但它们都归结为我们可以访问文件系统，并能够读取/写入/追加到各种文件和目录。现在，让我们继续讨论`net`模块。

# 网络模块

`net`模块为我们提供了对底层套接字系统甚至本地**进程间通信**（**IPC**）方案的访问权限。IPC 方案是允许我们在进程之间进行通信的通信策略。进程不共享内存，这意味着我们必须通过其他方式进行通信。在 Node.js 中，这通常意味着三种不同的策略，它们都取决于我们希望系统有多快速和紧密耦合。这三种策略如下：

+   无名管道

+   命名管道/本地域套接字

+   TCP/UDP 套接字

首先，我们有无名管道。这些是单向通信系统，不会出现在文件系统中，并且在`parent`和`child`进程之间共享。这意味着`parent`进程会生成一个`child`进程，并且`parent`会将管道一端的*位置*传递给`child`。通过这样做，它们可以通过这个通道进行通信。一个例子如下：

```js
import { fork } from 'child_process';

const child = fork('child.js');
child.on('message', (msg) => {
    switch(msg) {
        case 'CONNECT': {
            console.log('our child is connected to us. Tell it to dispose 
             of itself');
            child.send('DISCONNECT');
            break;
        }
        case 'DISCONNECT': { 
            console.log('our child is disposing of itself. Time for us to 
             do the same');
            process.exit();
            break;
        }
    }
});
```

我们的`child`文件将如下所示：

```js
process.on('message', (msg) => {
    switch(msg) {
        case 'DISCONNECT': {
            process.exit();
            break;
        }
    }
});
process.send('CONNECT');
```

我们从`child_process`模块中获取 fork 方法（这允许我们生成新的进程）。然后，我们从`child` JavaScript 文件中 fork 一个新的`child`，并获得对该`child`进程的处理程序。作为 fork 过程的一部分，Node.js 会自动为我们创建一个无名管道，以便我们可以在两个进程之间进行通信。然后，我们监听`child`进程上的事件，并根据接收到的消息执行各种操作。

在`child`端，我们可以自动监听来自生成我们的进程的事件，并且可以通过我们的进程接口发送消息（这在每个启动的 Node.js 文件中都是全局的）。如下面的代码所示，我们能够在两个独立的进程之间进行通信。如果我们想要真正看到这一点，我们需要在`parent`进程中添加一个超时，以便在`15`秒内不发送`DISCONNECT`消息，就像这样：

```js
setTimeout(() => {
    child.send('DISCONNECT');
}, 15000);
```

现在，如果我们打开任务管理器，我们会看到启动了两个 Node.js 进程。其中一个是`parent`，另一个是`child`。我们正在通过一个无名管道进行通信，因此它们被认为是紧密耦合的，因为它们是唯一共享它的进程。这对于我们希望有`parent`/`child`关系的系统非常有用，并且不希望以不同的方式生成它们。

与在两个进程之间创建紧密链接不同，我们可以使用称为命名管道的东西（在 OS X 和 Linux 上称为 Unix 域套接字）。它的工作方式类似于无名管道，但我们能够连接两个不相关的进程。为了实现这种类型的连接，我们可以利用`net`模块。它提供了一个低级 API，可以用来创建、连接和监听这些连接。我们还会得到一个低级套接字连接，因此它的行为类似于`http(s)`模块。

要建立连接，我们可以这样做：

```js
import net from 'net';
import path from 'path';
import os from 'os';

const pipeName = (os.platform() === 'win32' ?
    path.join('\\\\?\\pipe', process.cwd(), 'temp') :
    path.join(process.cwd(), 'temp');
const server = net.createServer().listen(pipeName);
server.on('connection', (socket) => {
    console.log('a socket has joined the party!');
    socket.write('DISCONNECT');
    socket.on('close', () => {
        console.log('socket has been closed!');
    });
});
```

在这里，我们导入了`net`、`path`和`os`模块。`path`模块帮助我们创建和解析文件系统路径，而无需为特定的操作系统编写路径表达式。正如我们之前看到的，`os`模块可以为我们提供有关当前所在的操作系统的信息。在创建管道名称时，Windows 需要在`\\?\pipe\<something>`。在其他操作系统上，它可以只是一个常规路径。还有一点需要注意的是，除了 Windows 之外的任何其他操作系统在我们使用完管道后都不会清理它。这意味着我们需要确保在退出程序之前删除文件。

在我们的情况下，我们根据平台创建一个管道名称。无论如何，我们确保它在我们当前的工作目录（`process.cwd()`）中，并且它被称为`temp`。从这里，我们可以创建一个服务器，并在这个文件上监听连接。当有人连接时，我们收到一个`Socket`对象。这是一个完整的双工流，这意味着我们可以从中读取和写入。我们还能够将信息传送到其中。在我们的情况下，我们想要记录到控制台`socket`加入，然后发送一个`DISCONNECT`消息。一旦我们收到关闭事件，我们就会记录`socket`关闭。

对于我们的客户端代码，我们应该有类似以下的东西：

```js
import net from 'net';
import path from 'path';
import os from 'os';

const pipeName = (os.platform() === 'win32') ? 
    path.join('\\\\?\\pipe', process.cwd(), 'temp') :
    path.join(process.cwd(), 'temp');
const socket = new net.Socket().connect(pipeName);
socket.on('connect', () => {
    console.log('we have connected');
});
socket.on('data', (data) => {
    if( data.toString('utf8') === 'DISCONNECT' ) {
        socket.destroy();
    }
});
```

这段代码与之前的代码非常相似，只是我们直接创建了一个`Socket`对象并尝试连接到相同的管道名称。一旦连接成功，我们就会记录下来。当我们收到数据时，我们会检查它是否等于我们的`DISCONNECT`消息，如果是，我们就会摆脱这个套接字。

IPC 机制的好处在于我们可以在不同语言编写的不同程序之间传递消息。它们唯一需要共同拥有的是某种形式的共同*语言*。有许多系统可以做到这一点。尽管这不是本书的重点，但请注意，如果我们需要连接到另一个程序，我们可以使用`net`模块相当容易地实现这一点。

# http 模块

我们要高层次地看一下的最后一个模块是`http`模块。这个模块允许我们轻松创建`http`服务器。以下是一个简单的`http`服务器示例：

```js
import http from 'http';

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type' : 'application/json'});
    res.end(JSON.stringify({here : 'is', some : 'data'}));
});
server.listen(8000, '127.0.0.1');
```

如果我们在浏览器中输入`localhost:8000`，我们应该能在浏览器中看到 JSON 对象。如果我们想变得更加花哨，我们可以发送一些基本的 HTML，比如下面这样：

```js
const server = https.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type' : 'text/html' });
    res.end(`
        <html>
            <head></head>
            <body>
                <h1>Hello!</h1>
                <p>This is from our server!</p>
            </body>
        </html>
    `);
});
```

我们将内容类型设置为`text/html`，而不是`application/json`，以便浏览器知道如何解释这个请求。然后，我们用我们的基本 HTML 结束响应。如果我们的 HTML 请求 CSS 文件，我们将如何响应服务器？

我们需要解释请求并能够发送一些 CSS。我们可以使用以下方式来做到这一点：

```js
const server = http.createServer((req, res) => {
    if( req.method === 'GET' &&
        req.url === '/main.css' ) {
        res.writeHead(200, { 'Content-Type' : 'text/css' });
        res.end(`
            h1 {
                color : green;
            }
            p {
                color : purple;
            }
        `);
    } else {
        res.writeHead(200, { 'Content-Type' : 'text/html' });
        // same as above
    }
});
```

我们能够从接收到的请求中提取各种信息。在这种情况下，我们只关心这是否是一个`GET`请求，并且它是否在请求`main.css`资源。如果是，我们返回 CSS；否则，我们只返回我们的 HTML。值得注意的是，这段代码应该看起来与诸如 Express 之类的 Web 服务器框架相似。Express 添加了许多辅助方法和保护服务器的方法，但值得注意的是，我们可以通过利用 Node.js 内部的模块编写简单的服务器，减少依赖。

我们还可以使用`http`模块从各种资源中获取数据。如果我们使用内置在`http`模块中的`get`方法，甚至更通用的请求方法，我们可以从各种其他服务器获取资源。以下代码说明了这一点：

```js
import https from 'https';

https.get('https://en.wikipedia.org/wiki/Surprise_(emotion)', (res) => {
    if( res.statusCode === 200 ) {
        res.on('data', (data) => {
            console.log(data.toString('utf8'));
        });
        res.on('end', () => {
            console.log('no more information');
        });
    } else {
        console.error('bad error code!', res.statusCode);
    }
});
```

首先，我们可以看到我们必须利用`https`模块。由于这个网页位于一个使用**安全套接字层**（**SSL**）证书的服务器上，我们必须使用安全连接方法。然后，我们只需调用`get`方法，传入我们想要的 URL，并从响应中读取数据。如果出现某种原因，我们没有得到一个 200 响应（一个正常的消息），我们就会出错。

这三个模块应该展示了我们在 Node.js 生态系统中有相当大的能力，并且应该引发一些好奇心，让我们想知道如何在没有任何依赖的情况下使用 Node.js 来制作有用的系统。在下一节中，我们将看看如何在命令行调试器中调试我们的 Node.js 代码，以及我们习惯于在 Chrome 中使用的代码检查系统。

# 调试和检查代码

新的 Node.js 开发人员常常在调试代码方面遇到困难。与检查员不同，我们有一个系统，第一次崩溃会将一些信息转储到屏幕上，然后立即将我们踢到命令行。以下代码可以看到这一点：

```js
const thing = 'this';
console.log(thing);
thing = 10;
```

在这里，我们可以看到我们正在尝试重新分配一个常量，所以 Node.js 将抛出类似以下的错误：

```js
TypeError: Assignment to constant variable. 
 at Object.<anonymous> (C:\Code\Ch5\bad_code.js:3:7) 
 at Module._compile (internal/modules/cjs/loader.js:774:30) 
 at Object.Module._extensions..js (internal/modules/cjs/loader.js:785:10) 
 at Module.load (internal/modules/cjs/loader.js:641:32) 
 at Function.Module._load (internal/modules/cjs/loader.js:556:12) 
 at Function.Module.runMain (internal/modules/cjs/loader.js:837:10) 
 at internal/main/run_main_module.js:17:11
```

虽然这可能让人感到害怕，但它也向我们展示了错误的位置。这个堆栈跟踪中的第一行告诉我们它在*第 3 行*，*第 7 个字符*。

堆栈跟踪是系统向开发人员提供有关调用了什么函数的信息的一种方式。在我们的情况下，`Object.<anonymous>`被`Module.__compile`调用，依此类推。当堆栈的大部分是我们自己的时候，错误实际上发生在更远的地方时，这可能有所帮助。

有了这些信息，我们知道如何纠正问题，但如果我们想在特定语句或特定行上中断怎么办？这就是检查员系统发挥作用的地方。在这里，我们可以利用类似于我们在代码的 Web 版本中看到的语句。如果我们在代码的中间插入一个调试语句，我们的命令行将在那一点停止。

让我们创建一些基本的代码来展示这一点。以下代码应该足够展示检查员的使用：

```js
const fun = function() {
    const item = 10;
    for(let i = 0; i < item; i++) {
        const tempObj = {};
        tempObj[i] = "what " + i;
    }
    return function() {
        console.log('we will have access to other things');
        const alternative = 'what';
        debugger;
        return item;
    }
}

console.log('this is some code');
const x = 'what';
debugger;
fun()();
```

这段代码将允许我们玩弄检查员的各个部分。如果我们运行`npm inspect bad_code.js`命令，我们应该会在对`fun`的调用上中断。我们会看到一个终端界面，指出我们处于调试模式。现在我们在这里停止执行，我们可以设置一个监视器。这允许我们捕获各种变量和表达式，并查看它们在下一个中断时的结果。在这里，我们通过在调试器中执行`watch('x')`来设置一个监视器，监视`x`变量。从这里，如果我们输入`next`，我们将移动到下一行。如果我们这样做几次，我们会注意到一旦我们通过变量的赋值，监视器将把`x`变量从未定义变为 10。

当我们需要调试一个在相当多的对象之间共享状态的有状态系统时，这可能特别有帮助。当我们试图查看我们可以访问的内容时，这也可能有所帮助。让我们设置几个更多的监视器，以便在下一个调试语句被触发时看到它们的值。在以下变量上设置监视器：`item`、`tempObj`和`alternative`。现在，输入`cont`。这将把我们移动到下一个调试器语句。让我们看看我们的监视器打印出了什么。当我们移动到下一个点时，我们会看到`tempObj`和`x`未定义，但我们可以访问`item`和`alternative`。

这是我们所期望的，因为我们被限定在外部`fun`函数内部。我们可以用这个版本的检查员做更多事情，但我们也可以连接到我们习惯的检查员。

现在，如果我们使用以下命令运行我们的代码，我们将能够将调试工具附加到我们的脚本上：

```js
 > node --inspect bad_code.js 
```

有了这个，我们将得到一个我们可以连接的地址。让我们这样做。我们还需要有一些长时间运行的代码；否则，脚本将退出，我们将没有任何东西可以监听。让我们回到`named_pipe.js`示例。运行`node --inspect -–experimental-modules named_pipe.js`。

我们应该得到类似以下的东西：

```js
Debugger listening on ws://127.0.0.1:9229/6abd394d-d5e0-4bba-8b28-69069d2cb800
```

如果我们在 Chrome 浏览器中输入以下地址，我们应该会看到一个熟悉的界面：

```js
chrome-devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=<url>
```

现在，我们可以在 Node.js 代码中使用 Chrome 的检查器的全部功能。在这里，我们可以看到，如果我们用`named_pipe_child.js`文件连接到我们的命名管道服务器，我们将在调试器中看到控制台日志。现在，如果我们添加调试器语句，我们应该能够在检查器中得到断点。如果我们在套接字连接到我们时添加一个调试语句，当我们用子套接字连接时，我们将能够以与在浏览器中一样的方式运行我们的代码！这是调试和逐步执行我们的代码的好方法。

我们还可以进行内存分析。如果我们转到内存选项卡并创建堆快照，我们将得到一个漂亮的内存转储。它应该看起来非常熟悉，就像我们已经看到的那样。

有了这些知识，我们可以进入围绕 Node.js 的更复杂的主题。

# 总结

随着 Node.js 的出现，我们能够使用一种编程语言，可以在客户端和服务器上都使用。虽然 Node.js 给我们的 API 可能看起来不太熟悉，但我们可以用它们创建强大的服务器应用程序。

在本章中，我们介绍了流的基础知识以及一些允许我们创建强大服务器应用程序的 API。我们还看了一些工具，可以让我们在有 GUI 和没有 GUI 的情况下进行调试。

有了这些知识，下一章中，我们将更深入地探讨我们可以使用的机制，以在线程和进程之间传递数据。


# 第六章：消息传递 - 了解不同类型

在上一章中，我们看了 Node.js 和我们需要创建服务器端应用程序的基本环境。现在，我们将看看如何利用我们之前学习的通信技术来编写可扩展的系统。消息传递是应用程序解耦但仍然能够共同工作的一种很好的方式。这意味着我们可以创建相互独立工作的模块，无论是通过进程还是线程，仍然可以实现共同的目标。

在本章中，我们将涵盖以下主题：

+   使用 net 模块进行本地通信

+   利用网络

+   快速浏览 HTTP/3

我们还将在查看正在开发的 HTTP/3 标准时，了解客户端/服务器通信的未来。然后，我们将查看 QUIC 协议的实现，这是由 Google 开发的协议，HTTP/3 从中汲取了一些想法。

让我们开始吧！

# 技术要求

对于本章，您将需要以下技术要求：

+   一个 IDE 或代码编辑器（首选 VS Code）

+   运行中的 Node.js 环境

+   OpenSSL 或安装 Cygwin 的能力

+   本章的代码可以在[`github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-High-Performance-Web-Development-with-JavaScript/tree/master/Chapter06)找到。

# 使用 net 模块进行本地通信

虽然许多应用程序可以在单个线程上运行并利用事件循环来运行，但当我们编写服务器应用程序时，我们将希望尽量利用我们可用的所有核心。我们可以通过使用**进程**或**线程**来实现这一点。在大多数情况下，我们将希望使用线程，因为它们更轻量级且启动速度更快。

我们可以根据我们是否需要在主系统死机后仍然运行子系统来确定我们是否需要进程还是线程。如果我们不在乎，我们应该利用线程，但如果我们需要在主进程死机后仍然运行该子系统，我们应该利用一个解耦的进程。这只是考虑何时使用进程或线程的一种方式，但它是一个很好的指标。

在浏览器和 Node.js 中，我们有 Web Workers 来代替传统系统中的线程。虽然它们与其他语言的线程有许多相同的概念，但它们无法共享状态（在我们的情况下，这是首选）。

有一种方法可以在 worker 之间共享状态。这可以通过`SharedArrayBuffer`来实现。虽然我们可以利用这一点来共享状态，但我们要强调事件系统和 IPC 几乎总是足够快，可以在不同的部分之间移动状态和协调。此外，我们不必处理锁等概念。

要启动一个 worker，我们需要调用`new Worker(<script here>)`。让我们来看看这个概念：

1.  创建一个名为`Main_Worker.js`的文件，并将以下代码添加到其中：

```js
import { Worker } from 'worker_threads';

const data = {what: 'this', huh: 'yeah'};
const worker = new Worker('./worker.js');
worker.postMessage(data);
worker.on('message', (data) => {
    worker.terminate();
});
worker.on('exit', (code) => {
    console.log('our worker stopped with the following code: ', 
     code);
});
```

1.  创建一个名为`worker.js`的文件，并将以下代码添加到其中：

```js
import { parentPort } from 'worker_threads'

parentPort.on('message', (msg) => {
    console.log('we received a message from our parent: ', msg);
    parentPort.postMessage({RECEIVED: true});
});
```

正如我们所看到的，这个系统与浏览器中的系统类似。首先，我们从`worker_threads`模块中导入 worker。然后，我们启动它。线程将启动，这意味着我们可以向其发送消息并监听事件，就像我们在上一章中能够与进程一样。

在`worker.js`文件中，我们从`worker_threads`模块中导入`parentPort`消息通道。我们监听并传递消息的方式与父级相同。一旦我们收到消息，我们就会声明我们收到了消息。然后父级终止我们，我们打印出我们已经被终止。

现在，如果我们想要紧密耦合所有子系统，这种形式的消息传递是完全可以的。但是，如果我们希望不同的线程有不同的工作，该怎么办？我们可以有一个只为我们缓存数据的线程。另一个可能为我们发出请求。最后，我们的主线程（起始进程）可以移动所有这些数据并从命令行中接收数据。

要做到所有这些，我们可以简单地使用内置系统。或者，我们可以利用我们在上一章中看到的机制。这不仅使我们拥有高度可扩展的系统，还允许我们将这些各个子系统从线程转换为进程，如果需要的话。这也允许我们在需要时用另一种语言编写这些单独的子系统。现在让我们来看一下：

1.  让我们继续制作这个系统。我们将创建四个文件：`main.js`，`cache.js`，`send.js`和`package.json`。我们的`package.json`文件应该看起来像这样：

```js
{
    "name" : "Chapter6_Local",
    "version" : "0.0.1",
    "type" : "module",
    "main" : "main.js"
}
```

1.  接下来，将以下代码添加到`cache.js`文件中：

```js
import net from 'net';
import pipeName from './helper.js';

let count = 0;
let cacheTable = new Map();
// these correspond to !!!BEGIN!!!, !!!END!!!, !!!GET!!!, and 
// !!!DELETE!!! respectively
const begin, end, get, del; //shortened for readability they will use the Buffer.from() methods
let currData = [];

const socket = new net.Socket().connect(pipeName());
socket.on('data', (data) => {
    if( data.toString('utf8') === 'WHOIS' ) {
        return socket.write('cache');
    }
    if( data.includes(get) ) {
        const loc = parseInt(data.slice(get.byteLength).toString('utf8'));
        const d = cacheTable.get(loc);
        if( typeof d !== 'undefined' ) {
            socket.write(begin.toString('utf8') + d + 
             end.toString('utf8'));
        }
    }
    if( data.includes(del) ) {
        if( data.byteLength === del.byteLength ) {
            cacheTable.clear();
        } else {
            const loc = parseInt(data.slice(del.byteLength).toString('utf8'));
            cacheTable.delete(loc);
        }
    }
    if( data.includes(begin) ) {
        currData.push(data.slice(begin.byteLength).toString('utf8'));
    }
    if( currData.length ) {
        currData.push(data.toString('utf8'));
    }
    if( data.includes(end) ) {
        currData.push(data.slice(0, data.byteLength - 
         end.byteLength).toString('utf8'));
        cacheTable.set(count, currData.join(''));
        currData = [];
    }
});
```

这绝对不是处理流数据的万无一失的机制。`!!!BEGIN!!!`和其他命令消息可能会被分块，我们永远看不到它们。虽然我们保持简单，但要记住，生产级别的流处理需要处理所有这些类型的问题。

`cache`子模块检查消息上的不同标头。根据每种类型，我们将执行该类型的操作。这可以被视为一种简单的远程过程调用。以下列表描述了我们根据每个事件所做的操作：

+   `!!!BEGIN!!!`：我们需要开始监听线路上的更多数据，因为这意味着我们将存储数据。

+   `!!!END!!!`：一旦我们看到这条消息，我们就可以将所有这些数据放在一起并根据缓存中的计数存储它。

+   `!!!GET!!!`：我们将尝试获取由服务器提供给我们的编号位置存储的文件。

+   `!!!DELETE!!!`：如果消息的长度与此字符串一样长，这意味着我们想要从缓存中删除所有内容。否则，我们将尝试删除稍后在消息中指定的位置的数据。

1.  将以下代码添加到`send.js`文件中：

```js
import net from 'net'
import https from 'https'
import pipeName from './helpers.js'

const socket = new net.Socket().connect(pipeName());
socket.on('data', (data) => {
    if( data.toString('utf8') === 'WHOIS' ) {
        return socket.write('send');
    }
    const all = [];
    https.get(data.toString('utf8'), (res) => {
        res.on('data', (data) => {
            all.push(data.toString('utf8'));
        });
        res.on('end', () => {
            socket.write('!!!BEGIN!!!');
            socket.write(all.join(''));
            socket.write('!!!END!!!');
        });
    }).on('error', (err) => {
        socket.write('!!!FALSE!!!');
    });
    console.log('we received data from the main application',  
     data.toString('utf8'));
});
```

对于我们拥有的每个子模块，我们处理可能通过网络传输的特定命令。正如`send`子模块所示，我们处理除了`WHOIS`命令之外的任何网络传输，该命令告诉主应用程序谁连接到它。我们尝试从指定的地址获取文件并将其写回主应用程序，以便将其存储在缓存中。

我们还添加了我们自己的*协议*来发送数据。虽然这个系统并非万无一失，我们应该添加某种类型的锁定（比如一个布尔值，这样我们在完全发送当前数据之前不会尝试接收更多数据），但它展示了我们如何在系统中发送数据。在第七章中，*流-理解流和非阻塞 I/O*，我们将看到一个类似的概念，但我们将利用流，这样我们就不会在每个线程中使用太多内存。

正如我们所看到的，我们只导入了`https`模块。这意味着我们只能向通过 HTTPS 提供的地址发出请求。如果我们想要支持 HTTP，我们将不得不导入`http`模块，然后检查用户输入的地址。在我们的情况下，我们尽可能地简化了它。

当我们想要发送数据时，我们发送`!!!BEGIN!!!`消息，以让接收方知道我们将发送无法适应单个帧的数据。然后，我们用`!!!END!!!`消息结束我们的消息。

如果我们无法读取我们尝试抓取的端点或者我们的连接超时（这两种情况都会进入错误条件），我们将发送`!!!FALSE!!!`消息，以让接收方知道我们无法完全传输数据。

在几乎所有数据传输系统中，都使用了将我们的数据包装在*帧*中的概念。没有帧，我们将不得不发送一个标头，说明数据传输的大小。然而，这意味着我们需要在发送之前知道内容的大小。帧给了我们选择不发送消息的长度的选项，因此我们可以处理无限大的消息。

在任何地方都会对数据进行包装或装箱。例如，如果我们看一下如何创建数据包，这个概念仍然适用。理解这个概念是理解通信堆栈的较低层次的关键。另一个需要了解的概念是，并非所有数据都一次性发送。它是分批发送的。一次可以发送的数量通常在操作系统级别设置。我们可以设置的唯一属性之一是流的`highWaterMark`属性。该属性允许我们说出在停止读取/写入之前我们将在内存中保存多少数据。

缓存应用程序类似于发送子模块，只是它响应更多的命令。如果我们收到一个`get`命令，我们可以尝试从缓存中获取该项并将其发送回主模块；否则，我们只是发送回`null`。如果我们收到一个`delete`命令，如果没有其他参数，我们将删除整个缓存；否则，我们将删除特定位置的项目。最后，如果我们收到开始或结束包装，我们将处理数据并将其缓存。

目前，我们的缓存是无限增加的。我们可以很容易地添加一个允许数据在缓存中停留的一定时间阈值（**生存时间**或**TTL**），或者只保留一定数量的记录，通常通过利用**最近最少使用**（**LRU**）销毁系统。我们将看看如何在第九章中实现缓存策略，*实际示例 - 构建静态服务器*。只需注意，这些概念在缓存和缓存策略中是非常普遍的。

回到代码中，创建`main.js`并添加以下代码：

1.  为我们的状态变量创建占位符。这些对应于我们的消息可能处于的各种状态以及通过套接字传递的数据：

```js
// import required modules and methods
const table = new Map();
let currData = [];
// These three items correspond to the buffers for: !!!FALSE!!!, 
// !!!BEGIN!!!, and !!!END!!! respectively
const failure, begin, end;
const methodTable = new WeakMap();
```

1.  创建处理通过我们的缓存传入的数据的方法：

```js

const cacheHandler = function(data) {
    if( data.includes(begin) || currData.length ) {
        currData.push(data.toString('utf8'));
    }
    if( data.includes(end) ) {
        currData.push(data.toString('utf8'));
        const final = currData.join('');
        console.log(final.substring(begin.byteLength, 
         final.byteLength - end.byteLength));
        currData = [];
    }
}
```

1.  接下来，添加一个方法来处理我们的`send`工作进程发送的消息：

```js

const sendHandler = function(data) {
    if( data.equals(failure) ) { //failure }
    if( data.includes(begin) ) { 
     currData.push(data.toString('utf8')); }
    if( currData.length ) { currData.push(data.toString('utf8')); }
    if( data.includes(end) ) { 
        table.get('cache').write(currData.join(''));
        currData = [];
    }
}
```

1.  创建两个最终的辅助方法。这些方法将测试我们拥有的工作进程数量，以便知道何时准备就绪，另一个将向每个工作进程套接字添加方法处理程序：

```js

const testConnections = function() {
    return table.size === 2;
}
const setupHandler = function() {
    table.forEach((value, key) => {
        value.on('data', methodTable.get(value.bind(value));
    });
}
```

1.  最终的大型方法将处理我们通过命令行接收到的所有消息：

```js
const startCLIMode = function() {
    process.stdin.on('data', function(data) {
        const d = data.toString('utf8');
        const instruction = d.trim().split(/\s/ig);
        switch(instruction[0]) {
            case 'delete': {
                table.get('cache').write(`!!!DELETE!!!${instruction[1] || ''}`);
                break; }
            case 'get': {
                if( typeof instruction[1] === 'undefined' ) {
                    return console.log('get needs a number 
                     associated with it!');
                }
                table.get('cache').write(`!!!GET!!!${instruction[1]}`);
                break; }
            case 'grab': {
                table.get('send').write(instruction[1]);
                break; }
            case 'stop': {
                table.forEach((value, key) => value.end());
                process.exit();
                break; }
    }});
}
```

1.  最后，创建服务器并启动工作进程：

```js
const server = net.createServer().listen(pipeName());
server.on('connection', (socket) => {
    socket.once('data', (data) => {
        const type = data.toString('utf8');
        table.set(type, socket);
        if( testConnections() ) {
            setupHandlers();
            startCLIMode();
        }
    });
    socket.once('close', () => {
        table.delete(type);
    });
    socket.write('WHOIS');
});

const cache = new Worker('./cache.js');
const send = new Worker('./send.js');
```

为了缩短本书中的代码量，主文件的某些部分已被删除。完整的示例可以在本书的 GitHub 存储库中找到。

在这里，我们有一堆辅助程序，将处理来自缓存和发送子系统的消息。我们还将套接字映射到我们的处理程序。使用`WeakMap`的好处是，如果这些子系统崩溃或以某种方式被移除，我们就不需要清理。我们还将子系统的名称映射到套接字，以便我们可以轻松地向正确的子系统发送消息。最后，我们创建一个服务器并处理传入的连接。在我们的情况下，我们只想检查两个子系统。一旦我们看到两个，我们就启动我们的程序。

我们包装消息的方式存在一些缺陷，测试连接数量以查看我们是否准备就绪也不是处理程序的最佳方式。然而，这确实使我们能够创建一个相当复杂的应用程序，以便我们可以快速测试这里所见的想法。有了这个应用程序，我们现在能够从远程资源缓存各种文件，并在需要时获取它们。这是一种类似于某些静态服务器工作方式的系统。

通过查看前面的应用程序，很容易看出我们可以利用本地连接来创建一个只使用核心 Node.js 系统的消息传递系统。同样有趣的是，我们可以将`listen`方法的参数从管道名称替换为端口号，这样我们就可以将这个应用程序从使用命名管道/Unix 域套接字转换为使用 TCP 套接字。

在 Node.js 中有这些工作线程之前，我们必须用进程将所有东西分开。起初，我们只有 fork 系统。当我们开始创建更多的进程时，这使得一些系统变得非常复杂。为了帮助我们理解这个概念，创建了`cluster`模块。使用`cluster`模块，更容易管理主/从架构中的进程。

# 了解 cluster 模块

虽然`cluster`模块可能不像过去那样经常使用，因为我们在 Node.js 中有工作线程，但仍有一个概念使其强大。我们能够在应用程序中的各个工作线程之间共享服务器连接。我们的主进程将使用一种策略，以便我们只向其中一个从进程发送请求。这使我们能够处理许多同时运行在完全相同的地址和端口上的连接。

有了这个概念，让我们利用`cluster`模块来实现前面的程序。现在，我们将确保发送和缓存子系统与主进程绑定。我们的子进程将负责处理通过我们的服务器传入的请求。要记住的一件事是，如果父进程死亡，我们的子进程也会死亡。如果我们不希望出现这种行为，在我们的主进程内调用 fork 时，我们可以传递`detached : true`选项。这将允许工作线程继续运行。这通常不是我们在使用`cluster`模块时想要的行为，但知道它是可用的是很好的。

我们已将以下程序分成更易管理的块。要查看完整的程序，请转到本章的代码存储库。

现在，我们应该能够编写一个类似于我们的 IPC 程序的程序。让我们来看一下：

1.  首先，我们将导入在`cluster`模式下实现我们之前示例所需的所有 Node 模块：

```js
import cluster from 'cluster';
import https from 'https';
import http from 'http';
import { URL } from 'url';
```

1.  接下来，我们设置可以在各个进程中使用的常量：

```js
const numWorkers = 2;
const CACHE = 0;
const SEND = 1;
const server = '127.0.0.1';
const port = 3000;
```

1.  然后，我们添加一个`if/else`检查，以查看我们是主进程还是从进程。同一文件用于两种类型的进程，因此我们需要一种区分两者的方法：

```js
if( cluster.isMaster ) {
    // do master work
} else {
    // handle incoming connections
}
```

1.  现在，编写主代码。这将进入`if/else`语句的第一个块中。我们的主节点需要启动从节点，并初始化我们的缓存：

```js
let count = 1; //where our current record is at. We start at 1
const cache = new Map();
for(let i = 0; i < numWorkers; i++ ) {
    const worker = cluster.fork();
    worker.on('message', (msg) => {
        // handle incoming cache request
    });
}
```

1.  添加一些代码来处理每个请求，就像我们在之前的例子中所做的那样。记住，如果我们停止主进程，它将销毁所有从进程。如果我们收到`STOP`命令，我们将只杀死主进程：

```js
// inside of the worker message handler
switch(msg.cmd) {
    case 'STOP': {
        process.exit();
        break;
    }
    case 'DELETE': {
        if( msg.opt != 'all' ) {
            cache.delete(parseInt(msg.opt);
        } else {
            cache.clear();
        }
        worker.send({cmd : 'GOOD' });
        break;
    }
    case 'GET': {
        worker.send(cache.get(parseInt(msg.opt));
        break;
    }
    case 'GRAB': {
        // grab the information
        break;
    }
}
```

1.  编写`GRAB` case 语句。为此，利用`https`模块请求资源：

```js
// inside the GRAB case statement
const buf = [];
https.get(msg.opt, (res) => {
    res.on('data', (data) => {
        buf.push(data.toString('utf8'));
    });
    res.on('end', () => {
        const final = buf.join('');
        cache.set(count, final);
        count += 1;
        worker.send({cmd : 'GOOD' });
    });
});
```

现在，我们将编写从节点代码。所有这些将保存在`else`块中。记住我们可以在从节点之间共享相同的服务器位置和端口。我们还将通过传递给我们的 URL 的搜索参数来处理所有传入的请求。这就是为什么我们从`url`模块导入了`URL`类。让我们开始吧：

1.  通过启动一个`HTTP`服务器来启动从节点代码。记住它们将共享相同的位置和端口：

```js
// inside of the else block
http.Server((req, res) => {
    const search = new URL(`${location}${req.url}`).searchParams;
    const command = search.get('command');
    const params = search.get('options');
    // handle the command
    handleCommand(res, command, params);
}).listen(port);
```

1.  现在，我们可以处理传递给我们的命令。这将类似于我们之前的例子，只是我们将通过**进程间通信**（**IPC**）与主进程交谈，并通过 HTTP/2 服务器处理请求。这里只显示了`get`命令；其余内容可以在本章的 GitHub 存储库中找到：

```js
const handleCommand = function(res, command, params=null) {
    switch(command) {
        case 'get': {
            process.send({cmd: 'GET', opt : params});
            process.once('message', (msg) => {
                res.writeHead(200, { 'Content-Type' : 'text/plain' });
                res.end(msg);
            });
            break;
        }
    }
}
```

在这里，我们可以看到两个工作进程都创建了一个`HTTP`服务器。虽然它们都创建了独立的对象，但它们共享底层端口。这对我们来说完全是隐藏的，但这是通过`cluster`模块完成的。如果我们尝试使用自己的版本来做类似的事情，同时使用`child_process`的 fork 方法，我们将会收到一个错误，指出`EADDRINUSE`。

如果我们请求以 HTML 格式存储的数据，我们将看到它以纯文本形式返回。这涉及到`writeHead`方法。我们告诉浏览器我们正在写`text/plain`。浏览器接收这些信息并利用它来查看它需要如何解析数据。由于它被告知数据是纯文本，它将只是在屏幕上显示它。如果我们在获取 HTML 数据时将其更改为`text/html`，它将解析并尝试呈现它。

通过这两种方法，我们能够编写能够充分利用系统上所有核心的程序，同时仍然能够协同工作。第一种架构为我们提供了一个良好的解耦系统，是大多数应用程序应该编写的方式，但`cluster`模块为我们提供了一个处理服务器的好方法。通过结合这两种方法，我们可以创建一个高吞吐量的服务器。在 Node.js 中构建这些客户端/服务器应用程序可能很容易，但也有一些需要注意的事项。

# 新开发人员常见的陷阱

在使用 Unix 域套接字/Windows 命名管道时，这两个系统之间存在一些差异。Node.js 试图隐藏这些细节，以便我们可以专注于我们想要编写的应用程序，但它们仍然会显现出来。新开发人员可能会遇到的两个最常见的问题是：

+   Windows 命名管道在应用程序退出时会自动销毁。Unix 域套接字则不会。这意味着当我们退出应用程序时，我们应该尝试使用`fs`模块，并通过`unlink`或`unlinkSync`方法取消链接文件。我们还应该在启动时检查它是否存在，以防我们不能正常退出。

+   Windows 的数据帧可能比 Unix 域套接字大。这意味着一个应用程序在 Windows 上可能正常工作，但在 Unix 系统上会失败。这就是我们创建我们所做的数据帧系统的原因。特别是当我们可能想要使用外部库来处理构建 IPC 系统的部分时，要牢记这一点是很重要的，因为一些系统并没有考虑到这一点，因此可能会很容易出现错误。

Node.js 的目标是完全跨操作系统兼容，但这些系统在实际跨系统操作时总是有一些小问题。如果我们想要确保它能够正常工作，就像我们必须在不能保证我们的最终用户将使用什么浏览器一样，那么我们需要在所有系统上进行测试。

虽然开发跨越单台计算机的服务器应用程序很常见，但我们仍然需要连接所有这些应用程序。当我们不能再使用单台计算机时，我们需要通过网络进行通信。接下来我们将看看这些协议。

# 利用网络

构建能够在同一台机器上相互通信的应用程序可能很酷，但最终我们需要与外部系统进行通信。在我们的情况下，大多数这些系统将是浏览器，但它们也可能是其他服务器。由于我们无法通过这些通道使用命名管道/Unix 域套接字，我们需要使用各种网络协议。

从技术上讲，我们仍然可以通过使用共享驱动器/文件系统共享来跨服务器使用前面两个概念，但这不是一个好主意。我们已经表明我们可以将`listen`方法从指向文件更改为指向端口。在最坏的情况下，我们可以使用共享文件系统，但这远非最佳选择，应该转换为使用我们将在这里介绍的协议之一。

我们将重点关注两种低级协议，即传输控制协议（TCP）和用户数据报协议（UDP）。我们还将研究网络的高级协议：超文本传输协议版本 2（HTTP/2）。通过这些协议，我们将能够创建高度可用的应用程序，可以通过网络访问。

# TCP/UDP

TCP 和 UDP 是 Node.js 中我们可以访问的两种低级网络协议。这两种协议都允许我们发送和接收消息，但它们在一些关键领域有所不同。首先，TCP 需要连接的接收方和发送方。因此，我们不能只在一个通道上广播，而不关心是否有人在听。

其次，除了 TCP 需要握手过程外，它还为我们提供了可靠的传输。这意味着我们知道当我们发送数据时，它应该到达另一端（显然，这也有失败的可能，但我们不打算讨论这个）。最后，TCP 保证了传递的顺序。如果我们在一个通道上向接收方发送数据，它将按照我们发送的顺序接收数据。因为这些原因，当我们需要保证传递和顺序时，我们使用 TCP。

实际上，TCP 并不一定需要按顺序发送数据。所有数据都是以数据包的形式发送的。它们实际上可以发送到不同的服务器，路由逻辑可能意味着后续数据包会比后来的更早到达接收方。然而，我们接收方的网络卡会为我们重新排序它们，使得看起来我们是按顺序接收它们的。TCP 还有许多其他很酷的方面，包括数据的传输，这些都超出了本书的范围，但任何人都可以查阅网络并了解更多这些概念以及它们是如何实现的。

话虽如此，TCP 似乎是我们总是想要使用的东西。为什么我们不使用能够保证传递的东西呢？此外，如果我们可以遍历所有当前的连接并将数据发送给每个人，我们就不需要广播。然而，由于所有这些保证，这使得 TCP 更加沉重和缓慢。这对于我们需要尽快发送数据的系统来说并不好。对于这种类型的数据传输，我们可以利用 UDP。UDP 给我们提供了一种称为无状态传输的东西。无状态传输意味着我们可以在一个通道上发送数据，它会将数据发送出去然后忘记。我们不需要连接到一个地址；相反，我们可以直接发送数据（只要没有其他人绑定到该地址和端口）。我们甚至可以建立一个多播系统，任何人都可以收听该地址，它可能会接收到数据。

这种类型的传输希望/需要的一些领域如下：

+   发送股票交易的买卖订单。由于数据传输速度很快，我们只关心最新的信息。因此，如果我们没有收到一些买卖订单，也并不重要。

+   视频游戏中的玩家位置数据。我们只能以有限的速度更新游戏。如果我们已经知道玩家移动的方向和速度，我们还可以插值或推断玩家在屏幕上的位置。因此，我们可以以任何速率接收玩家位置，并计算出他们应该在哪里（这有时被称为服务器的 tick 率）。

+   电信数据并不一定在乎我们发送的所有数据，只要我们发送了大部分数据即可。我们不需要保证完整视频/音频信号的传递，因为我们仍然可以用大部分数据获得很好的画面。

这只是 UDP 发挥作用的一些领域。通过对这两种系统的理解，我们将通过构建一个高度简化和不切实际的股票应用程序来研究它们。行为将如下所示：

1.  服务器将发布新的股票代码和可用股票数量。然后，它将在已知端口上通过 UDP 向所有人广播信息。

1.  服务器将存储与客户持仓相关的所有信息。这样，客户端就无法操纵他们可能拥有的股票数量。

1.  客户端将向服务器发送买入或卖出订单。服务器将确定它是否能处理该请求。所有这些流量都将通过 TCP 进行，因为我们需要确保知道服务器收到了我们的消息。

1.  服务器将以错误或成功的消息作出回应，告诉客户端他们的订单已更新。

1.  服务器将通过 UDP 通道广播股票的买入或卖出发生了。

这个应用程序看起来如下：

```js
import dgram from 'dgram';
import { Socket } from 'net';
const multicastAddress = '239.192.0.0';
const sendMessageBadOutput = 'message needs to be formatted as follows: BUY|SELL <SYMBOL> <NUMBER>';
const recvClient = dgram.createSocket({type : 'udp4', reuseAddr: true }); //1.
const sendClient = new Socket().connect(3000, "127.0.0.1");
// receiving client code seen below
process.stdin.setEncoding('utf8');
process.stdin.on('data', (msg) => {
    const input = msg.split(' ');
    if( input.length !== 3 ) {
        console.log(sendMessageBadOutput);
        return;
    }
    const num = parseInt(input[2]);
    if( num.toString() === 'NaN' ) {
        console.log(sendMessageBadOutput);
        return;
    }
    sendClient.write(msg);
});
sendClient.on('data', (data) => {
    console.log(data.toString('utf8'));
});
```

前面的大部分程序应该是熟悉的，除了我们正在使用的新模块：`dgram`模块。这个模块允许我们在使用 UDP 时发送数据。

在这里，我们创建了一个使用 UDP4（IPv4 上的 UDP，或者我们通常知道的 IP 地址）的套接字。我们还声明我们正在重用地址和端口。我们这样做是为了在本地测试。在其他情况下我们不希望这样做：

```js
recvClient.on('connect', () => {
    console.log('client is connected to the server');
});
recvClient.on('message', (msg) => {
    console.log('client received message', msg.toString('utf8'));
});
recvClient.bind(3000, () => {
    recvClient.addMembership(multicastAddress);
});
```

我们绑定到端口`3000`，因为服务器将在那里发送数据。然后，我们声明我们要将自己添加到多播地址。为了使多播工作，服务器需要通过多播地址发送数据。这些地址通常是操作系统设置的特定地址。每个操作系统都可以决定使用哪些地址，但我们选择的地址应该在任何操作系统上都可以使用。

一旦我们收到消息，我们就打印出来。再次，这应该看起来很熟悉。Node.js 是基于事件和流的，它们通常以相同的名称命名以保持一致性。

这个程序的其他部分处理用户输入，然后通过我们创建新套接字时打开的 TCP 通道发送数据（这应该类似于我们之前的 IPC 程序，只是我们传递了一个端口和一个 IP 地址）。

这个应用程序的服务器涉及的内容更多，因为它包含了股票应用程序的所有逻辑。我们将把这个过程分解为几个步骤：

1.  创建一个名为`main.js`的文件，并将`dgram`和`net`模块导入其中：

```js
import dgram from 'dgram';
import net from 'net';
```

1.  为我们的多播地址、错误消息和股票代码和客户端的`Maps`添加一些常量：

```js
const multicastAddress = '239.192.0.0';
const badListingNumMessage = 'to list a new ticker the following format needs to be followed <SYMBOL>
<NUMBER>';
const symbolTable = new Map();
const clientTable = new Map();
```

1.  接下来，我们创建两个服务器。第一个用于监听 UDP 消息，而第二个用于接收 TCP 消息。我们将利用 TCP 服务器来处理客户端请求。TCP 是可靠的，而 UDP 不是：

```js
const server = dgram.createSocket({type : 'udp4', reuseAddr : true}).bind(3000);
const recvServer = net.createServer().listen(3000, '127.0.0.1');
```

1.  然后，我们需要在 TCP 服务器上设置一个监听器以接受任何连接。一旦有客户端连接，我们将为他们设置一个临时表，以便我们可以存储他们的投资组合：

```js
recvServer.on('connection', (socket) => {
    const temp = new Map();
    clientTable.set(socket, temp);
});
```

1.  现在，为客户端设置一个数据监听器。当我们收到数据时，我们将根据以下格式解析消息，`SELL/BUY <Ticker> <Number>`：

```js
// inside of the connection callback for recvServer
socket.on('data', (msg) => {
    const input = msg.toString('utf8').split(' ');
    const buyOrSell = input[0];
    const tickerSymbol = input[1];
    const num = parseInt(input[2]);
});
```

1.  根据这个解析，我们检查客户端是否能执行这个操作。如果可以，我们将更改他们的投资组合，并发送一条消息告诉他们更改成功了：

```js
// inside the socket 'data' handler
const numHeld = symbolTable.get(input[1]);
if( buyOrSell === "BUY" && (num <= 0 || numHeld - num <= 0) ) {
    socket.write("ERROR!");
    return;
} 
const clientBook = clientTable.get(socket);
const clientAmount = clientBook.get(tickerSymbol);
if( buyOrSell === "SELL" && clientAmount - num < 0 ) {
    socket.write("ERROR!");
    return;
}
if( buyOrSell === "BUY" ) {
    clientBook.set(tickerSymbol, clientAmount + num);
    symbolTable.set(tickerSymbol, numHeld - num);
} else if( buyOrSell === "SELL" ) {
    clientBook.set(tickerSymbol, clientAmount - num);
    symbolTable.set(tickerSymbol, numHeld + num);
}
socket.write(`successfully processed request. You now hold ${clientBook.get(tickerSymbol)}` of ${tickerSymbol}`);
```

1.  一旦我们告诉客户端我们已处理他们的请求，我们可以通过 UDP 服务器向所有客户端写入：

```js
// after the socket.write from above
const msg = Buffer.from(`${tickerSymbol} ${symbolTable.get(tickerSymbol)}`);
server.send(msg, 0, msg.byteLength, 3000, multicastAddress);
```

1.  最后，我们需要通过标准输入处理来自服务器的新股票代码。一旦我们处理了请求，我们就通过 UDP 服务器发送数据，以便每个客户端都知道新股票的情况。

```js
process.stdin.setEncoding('utf8');
process.stdin.on('data', (data) => {
    const input = data.split(' ');
    const num = parseInt(input[1]);
    symbolTable.set(input[0], num);
    for(const client of clientTable) {
        client[1].set(input[0], 0);
    }

    server.send(Buffer.from(data), 0, data.length, 3000, multicastAddress);
});
```

为了清晰起见，几乎所有的错误逻辑都已被移除，但你可以在本书的 GitHub 存储库中找到它们。正如前面的例子所示，利用所有接口向其他点发送数据非常简单，无论是我们应用程序的其他部分还是监听数据的远程客户端。它们几乎都使用相同的接口，只在细微的实现细节上有所不同。只需记住，如果需要保证交付，应使用 TCP；否则，UDP 也是一个不错的选择。

接下来，我们将看一下 HTTP/2 标准以及与`net`、`dgram`和`http`/`https`模块相比，Node.js 中的服务器系统有些不同。

# HTTP/2

虽然它是在 2015 年引入的，但技术的采用速度很慢。HTTP/2 建立在 HTTP/1.1 协议的基础上，允许各种功能，这些功能在以前的系统中引起了问题。这使我们能够使用单个 TCP 连接接收不同的请求。这在 HTTP/1.1 中是不可能的，它引起了一个叫做头部阻塞的问题。这意味着我们实际上只能处理那么多的 TCP 连接，如果我们有一个长时间运行的 TCP 连接，它可能会阻塞之后的所有请求。

HTTP/2 还赋予了我们推送服务器端资源的能力。这意味着如果服务器知道浏览器将需要一个资源，比如一个 CSS 文件，它可以在需要之前将其推送到服务器。最后，HTTP/2 赋予了我们内置的流式传输能力。这意味着我们能够使用连接并将数据作为流发送，而不需要一次性发送所有数据。

HTTP/2 还给我们带来了其他好处，但这些是主要的好处。虽然`http`和`https`模块可能还会在未来一段时间内使用，但 Node.js 中的`http2`模块应该用于任何新的应用程序。

Node.js 中的`http2`模块与`http`和`https`模块有一些不同之处。虽然它不遵循许多其他 IPC/网络模块给我们的标准，但它确实为我们提供了一些很好的方法来通过 HTTP/2 发送数据。其中一个允许我们直接从文件系统流式传输文件，而不需要为文件创建管道并将其发送给发送方。以下代码中可以看到其中一些差异：

```js
import http2 from 'http2';
import fs from 'fs';
const server = http2.createSecureServer({
    key : fs.readFileSync('server.key.pem'),
    cert : fs.readFileSync('server.crt.pem')
});
server.on('error', (err) => console.error(err));
server.on('stream', (stream, headers) => {
    stream.respond({
        'content-type': 'text/plain',
        ':status' : 200
    });
    stream.end('Hello from Http2 server');
});
server.listen(8081, '127.0.0.1');
```

首先，注意服务器需要一个私钥和一个公共证书。这些用于确保建立的连接是安全的，这意味着没有人可以看到正在发送的内容。为了能够做到这一点，我们需要一个工具，比如`openssl`来创建这些密钥和证书。在 Windows 10 和其他 Unix 操作系统中，我们可以免费获得这个工具。否则，我们需要下载 Cygwin（[`www.cygwin.com/`](http://www.cygwin.com/)）。使用`openssl`，我们可以运行以下命令：

```js
> openssl req -x509 -newkey rsa:4096 -keyout server.key.pem -out server.crt.pem -days 365
```

这个命令生成了服务器和客户端进行安全通信所需的私钥和公共证书。我们不会在这里详细介绍它是如何实现的，但关于如何使用 SSL/TLS 实现这一点的信息可以在这里找到：[`www.cloudflare.com/learning/ssl/transport-layer-security-tls/`](https://www.cloudflare.com/learning/ssl/transport-layer-security-tls/)。

生成了我们的证书和密钥后，我们可以读取它们，以便我们的服务器可以开始运行。我们还会注意到，与响应消息事件或请求事件不同，我们响应流事件。HTTP/2 使用流而不是尝试一次性发送所有数据。虽然 Node.js 为我们封装了流的请求和响应，但这并不是操作系统层面可能处理的方式。HTTP/2 立即使用流。这就是为什么事件被称为流的原因。

接下来，我们不是调用`writeHead`方法，而是响应流。当我们想要发送信息时，我们利用`respond`方法并以这种方式发送头部。我们还会注意到一些头部是以冒号为前缀的。这是`http2`模块特有的，如果在发送特定头部时发现问题，加上冒号可能会解决问题。

除了我们在这里讨论的内容之外，这应该看起来与我们在 Node.js 中编写的普通 HTTP(s)服务器非常相似。然而，`http2`模块还有一些其他好处，其中之一是响应文件而不是必须读取文件并以这种方式发送。这可以在以下代码中看到：

```js
import http2 from 'http2';
import fs from 'fs';
import path from 'path';

const basePath = process.env.npm_package_config_static; //1.
const supportedTypes = new Set(['.ico', '.html', '.css', '.js']);
const server = http2.createSecureServer({
    key : fs.readFileSync(process.env.npm_package_config_key),
    cert : fs.readFileSync(process.env.npm_package_config_cert),
    allowHTTP1 : true //2.
});
server.on('error', (err) => console.error(err));
server.on('stream', (stream, header) => {
    const fileLoc = header[':path'];
    const extension = path.extname(fileLoc); //3.
    if(!supportedTypes.has(extension)) {
        stream.respond({
            ':status' : 400,
            'content-type' : 'application/json'
        });
        stream.end(JSON.stringify({
            error : 'unsupported data type!',
            extension
        }));
        return;
    }
    stream.respondWithFile( //4.
        path.join(process.cwd(), basePath, fileLoc),
        {
            ':status' : 200,
            'content-type' :
                extension === ".html" ?
                'text/html' :
                extension === ".css" ?
                'text/css' :
                'text/javascript'
        },
        {
            onError : (err) => { //5.
                if( err.code === 'ENOENT') {
                    stream.respond({ ':status' : 404 });
                } else {
                    stream.respond({ ':status' : 500 });
                }
                stream.end();
            }
        }
    )
});
server.listen(80, '127.0.0.1');
```

程序编号是关键的兴趣点，它们的工作方式如下：

1.  我们正在从`package.json`文件中读取信息，就像我们在上一章中所做的那样。我们还通过`npm run <script>`命令运行这个。查看上一章，了解如何做到这一点，以及我们如何在程序中使用`package.json`文件中的配置数据。

1.  我们为服务器设置了特定的配置选项。如果连接到我们的客户端无法使用 HTTP/2，那么我们将自动将一切转换回协商的协议，例如 HTTP/1.1。

1.  我们从 URL 中获取扩展名。这样，我们可以看到我们是否支持该文件类型，并发送适当的文件；否则，我们将返回一个 400 错误消息，并声明这是一个错误的请求。

1.  这种方法允许我们传入一个路径。然后，核心系统将帮助我们发送文件。我们所需要做的就是确保正确设置内容类型，以便浏览器可以解释数据。

1.  如果在任何时候出现错误，比如文件不存在，我们将以正确的状态做出响应，比如 404 或 500 错误。

虽然我们在这里呈现的只是`http2`模块的一小部分，但这展示了`http2`模块的不同之处，以及我们如何可以快速设置一个。如果需要，可以参考[`Node.js.org/dist/latest-v12.x/docs/api/http2.html`](https://nodejs.org/dist/latest-v12.x/docs/api/http2.html)来了解`http2`模块与`http`的不同之处以及它带来的所有功能。现在，我们将看一下网络的未来状态，并了解 Node.js 中的 HTTP/3。

# 快速浏览 HTTP/3

虽然我们所讨论的是进程、线程和其他计算机之间通信的现状，但有一种新的信息传递方式。新标准称为 HTTP/3，与前两个版本有很大不同。

# QUIC 协议

**Quick UDP Internet Connections** (**QUIC**)是由 Google 于 2012 年推出的。它是一种类似于 TCP、**传输层安全**（**TLS**）和 HTTP/2 协议的协议，但它全部通过 UDP 传输。这意味着 TCP 中内置的许多开销已经被移除，并用一种新的发送数据的方法替代。除此之外，由于 TLS 内置到协议中，这意味着在已定义的协议中添加安全性的开销已经被移除。

QUIC 目前被 Google 用于诸如 YouTube 之类的事物。虽然 QUIC 从未获得大规模的吸引力，但它帮助产生了将创建 HTTP/3 标准委员会的团体，并帮助指导委员会利用 UDP 作为协议的基础层。它还展示了安全性可以内置到协议中，并已经使 HTTP/3 具备了这一特性。

其他公司已经开始实施 QUIC 协议，而 HTTP/3 正在开发中。这个名单中一个显著的包括 Cloudflare。他们关于实施 QUIC 的博客文章可以在这里找到：[`blog.cloudflare.com/the-road-to-quic/`](https://blog.cloudflare.com/the-road-to-quic/)。

虽然 HTTP/3 尚未添加到 Node.js 中，但有一些包实现了 QUIC 协议。

# 对 node-quic 的一瞥

虽然 QUIC 目前不是最容易使用的，而且唯一的官方实现是在 Chromium 源代码中编写的，但已经有其他实现允许我们玩弄这个协议。`node-quic`模块已经被弃用，而 QUIC 实现正在尝试直接构建到 Node.js 中，但我们仍然可以使用它来看看我们将来如何利用 QUIC 甚至 HTTP/3。

首先，我们需要通过运行`npm install node-quic`命令来安装模块。有了这个，我们就能够编写一个简单的客户端-服务器应用程序。客户端应该看起来像下面这样：

```js
import quic from 'node-quic'

const port = 3000;
const address = '127.0.0.1';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (data) => {
    quic.send(port, address, data.trim())
        .onData((data) => {
            console.log('we received the following back: ', data);
        });
});
```

我们会注意到，发送数据类似于我们在 UDP 系统中所做的方式；也就是说，我们可以发送数据而不需要绑定到端口和地址。除此之外，该系统运行方式类似于使用`http`或`http2`模块编写的其他应用程序。这里值得注意的一件事是，当我们从`quic`流中接收数据时，数据会自动转换为字符串。

上一个客户端的服务器将如下所示：

```js
import quic from 'node-quic'

const port = 3000;
const address = '127.0.0.1';
quic.listen(port, address)
    .then(() => {})
    .onError((err) => console.error(err))
    .onData((data, stream, buffer) => {
        console.log('we received data:', data);
        if( data === 'quit' ) {
            console.log('we are going to stop listening for data');
            quic.stopListening();
        } else {
            stream.write("Thank you for the data!");
        }
    });
```

再次，这应该看起来与我们编写的其他应用程序类似。这里的一个主要区别是，这个模块是针对 promise 编写的。除此之外，我们接收的数据是一个字符串，所以如果我们接收到`quit`，我们通过运行`stopListening`方法关闭自己。否则，我们将要发送的数据写入流中，类似于我们在 HTTP/2 协议中所做的。

为了了解 HTTP/3 的实现状态，建议您查看以下链接并定期检查：[`quicwg.org/`](https://quicwg.org/)。

正如我们所看到的，使用这个模块来利用 QUIC 协议是相当简单的。这对内部应用程序也可能很有用。只要注意，QUC 协议和 HTTP/3 标准都还没有完全完成，可能还需要几年的时间。这并不意味着你不应该利用它们，只是意味着在标准不稳定的时候事情可能会发生很快。

# 摘要

在不同系统之间发送数据，无论是线程、进程，甚至其他计算机，这是我们作为开发人员所做的。我们可以使用许多工具来做到这一点，我们已经看过大部分。只要记住，虽然一个选项可能使应用程序变得简单，但这并不总是意味着它是最好的选择。当我们需要拆分系统时，通常希望将特定的工作分配给一个单元，并使用某种形式的 IPC，比如命名管道，进行通信。如果我们需要将该任务移动到另一台计算机，我们总是可以切换到 TCP。

有了这些 IPC 和 Web 协议的基础，我们将能够轻松解决 Node.js 中的大多数问题，并在涉及 Web 应用程序时编写客户端和服务器端代码。然而，Node.js 并不仅仅是为 Web 应用程序而构建的。我们几乎可以做任何其他语言可以做的事情，甚至拥有大多数其他语言拥有的工具。本章应该有助于澄清这一点，并帮助巩固 Node.js 如何构建到已经开发的应用程序生态系统中。

考虑到所有这些，我们将研究流和如何在 Node.js 中实现我们自己的流。
