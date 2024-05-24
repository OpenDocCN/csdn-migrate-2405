# Vue2 Web 开发项目（二）

> 原文：[`zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055`](https://zh.annas-archive.org/md5/632F664CBB74089B16065B30D26C6055)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：高级项目设置

在本章之后，我们将开始构建更复杂的应用程序，我们将需要一些额外的工具和库。我们将涵盖以下主题：

+   设置我们的开发环境

+   使用 vue-cli 搭建 Vue 应用程序

+   编写和使用单文件组件

# 设置我们的开发环境

为了创建更复杂的单页应用程序，建议使用一些工具来简化开发。在本节中，我们将安装它们以准备好良好的开发环境。您需要在计算机上安装 Node.js 和 npm。确保您至少拥有 Node 8.x，但建议使用最新的 Node 版本。

# 安装 vue-cli，官方命令行工具

我们首先需要的包是 vue-cli，这是一个命令行工具，将帮助我们创建 Vue 应用程序：

1.  在终端中输入此命令，它将安装 vue-cli 并将其保存为全局包：

```js
 npm install -g vue-cli
```

您可能需要以管理员身份运行此命令。

1.  要测试 vue-cli 是否正常工作，请使用以下命令打印其版本：

```js
 vue --version
```

# 代码编辑器

任何文本编辑器都可以，但我建议使用 Visual Studio Code（[`code.visualstudio.com/`](https://code.visualstudio.com/)）或 Atom（[`atom.io/`](https://atom.io/)）。对于 Visual Studio Code，您需要来自 octref 的`vetur`扩展（[`github.com/vuejs/vetur`](https://github.com/vuejs/vetur)），对于 Atom，您需要来自 hedefalk 的`language-vue`扩展（[`atom.io/packages/language-vue`](https://atom.io/packages/language-vue)）。

最近版本的 Jetbrains 的 WebStorm IDE 支持 Vue。

您还可以安装添加对预处理器语言（如 Sass、Less 或 Stylus）的支持的扩展。

# 我们的第一个完整的 Vue 应用程序

之前的应用程序都是以相当老式的方式制作的，使用`script`标签和简单的 JavaScript。在本节中，我们将发现使用一些强大功能和工具创建 Vue 应用程序的新方法。在这部分中，我们将创建一个迷你项目来演示我们将在接下来使用的新工具。

# 搭建项目脚手架

vue-cli 工具使我们能够创建即用型的应用程序框架，以帮助我们开始新项目。它使用一个项目模板系统，可以向您询问一些问题，以自定义框架以满足您的需求：

1.  用以下命令列出官方项目模板：

```js
 vue list
```

以下是终端中显示的列表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8caaafd7-e612-44c7-b349-3375f93bc7c3.png)

官方模板有三种主要类型：

+   simple：不使用构建工具

+   webpack：使用非常流行的 webpack 打包工具（推荐）

+   browserify：使用 browserify 构建工具

推荐的官方模板是`webpack`模板。它包含了创建一个具有 Vue 的全尺寸 SPA 所需的一切。为了本书的目的，我们将使用`webpack-simple`并逐步介绍功能。

要使用这些模板之一创建一个新的应用程序项目，请使用`npm init`命令：

```js
vue init <template> <dir>
```

我们将在一个新的`demo`文件夹中使用`webpack-simple`官方模板：

1.  运行以下命令：

```js
 vue init webpack-simple demo
```

这个项目模板具有一个准备好使用的最小 webpack 配置。该命令将会询问一些问题。

1.  像这样回答 vue-cli 的问题：

```js
      ? Project name demo
      ? Project description Trying out Vue.js!
      ? Author Your Name <your-mail@mail.com>
      ? License MIT
      ? Use sass? No
```

Vue-cli 现在应该已经创建了一个`demo`文件夹。它有一个`package.json`文件和其他配置文件已经为我们填充。`package.json`文件非常重要；它包含有关项目的主要信息；例如，它列出了项目所依赖的所有软件包。

1.  转到新创建的`demo`文件夹，并安装`webpack-simple`模板已经在`package.json`文件中声明的默认依赖项（如 vue 和 webpack）：

```js
 cd demo
 npm install
```

我们的应用现在已经设置好了！

从现在开始，我们将完全使用 ECMAScript 2015 语法和`import`/`export`关键字来使用或公开模块（这意味着导出 JavaScript 元素的文件）。

# 创建应用程序

任何 Vue 应用程序都需要一个 JavaScript 入口文件，代码将从那里开始：

1.  删除`src`文件夹的内容。

1.  创建一个名为`main.js`的新的 JavaScript 文件，内容如下：

```js
      import Vue from 'vue'

      new Vue({
        el: '#app',
        render: h => h('div', 'hello world'),
      })
```

首先，我们将 Vue 核心库导入文件中。然后，我们创建一个新的根 Vue 实例，将其附加到页面中`id`为 app 的元素上。

vue-cli 提供了一个默认的`index.html`文件，其中包含一个空的`<div id="app"></div>`标签。您可以编辑它以更改页面 HTML 以满足您的喜好。

最后，我们通过`render`选项显示包含`'hello world'`文本的`div`元素，这要归功于我们将在“渲染函数”部分介绍的`render`选项。

# 运行我们的应用程序

运行由 vue-cli 生成的`dev` npm 脚本以在开发模式下启动应用程序：

```js
npm run dev
```

这将在 web 服务器端口上启动一个 web 应用程序。终端应该显示编译成功以及访问应用程序的 URL：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/70045016-b634-4ec2-a1ad-a9262aa61474.png)

在浏览器中打开此 URL 以查看结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/cddefb10-81c2-4e72-aa4c-3caf893cdc3d.png)

# 渲染函数

Vue 使用虚拟 DOM 实现，由 JavaScript 对象组成的元素树。然后通过计算两者之间的差异，将虚拟 DOM 应用于真实的浏览器 DOM。这有助于尽量避免 DOM 操作，因为它们通常是主要的性能瓶颈。

实际上，当您使用模板时，Vue 会将其编译为渲染函数。如果您需要 JavaScript 的全部功能和灵活性，可以直接编写渲染函数，或编写稍后将讨论的 JSX。

渲染函数返回树的一小部分，该部分特定于其组件。它使用`createElement`方法作为第一个参数。

按照惯例，`h`是`createElement`的别名，这是非常常见的，也是编写 JSX 所需的。它来自于用 JavaScript 描述 HTML 的技术名称--Hyperscript。

`createElement`（或`h`）方法最多接受三个参数：

1.  第一个是元素的类型。它可以是 HTML 标签名（如`'div'`），在应用程序中注册的组件名称，或直接是组件定义对象。

1.  第二个参数是可选的。它是定义属性、props、事件监听器等的数据对象。

1.  第三个参数也是可选的。它可以是简单的纯文本，也可以是用`h`创建的其他元素数组。

考虑以下`render`函数作为示例：

```js
render (h) {
  return h('ul', { 'class': 'movies' }, [
    h('li', { 'class': 'movie' }, 'Star Wars'),
    h('li', { 'class': 'movie' }, 'Blade Runner'),
  ])
}
```

它将在浏览器中输出以下 DOM：

```js
<ul class="movies">
  <li class="movie">Star Wars</li>
  <li class="movie">Blade Runner</li>
</ul>
```

我们将在第六章中更详细地介绍渲染函数，*项目 4-地理定位博客*。

# 配置 babel

Babel 是一个非常流行的工具，它编译 JavaScript 代码，以便我们可以在较旧和当前的浏览器中使用新功能（如 JSX 或箭头函数）。建议在任何严肃的 JavaScript 项目中使用 babel。

默认情况下，`webpack-simple`模板带有默认的 babel 配置，使用支持 ES2015 中所有稳定 JavaScript 版本的`env` babel 预设。它还包括另一个名为`stage-3`的 babel 预设，支持即将到来的 JavaScript 特性，如`async/await`关键字和 Vue 社区常用的对象扩展运算符。

我们需要添加第三个特定于 Vue 的预设，它将为 JSX 添加支持（我们将在本章后面的“JSX”部分中需要它）。

我们还需要包括 babel 提供的 polyfills，以便在旧的浏览器中使用新功能，比如`Promise`和生成器。

Polyfill 是一种代码，用于检查浏览器中是否有某个功能，如果没有，则实现此功能，使其像本地功能一样工作。

# Babel Vue 预设

我们现在将在应用程序的 Babel 配置中安装和使用`babel-preset-vue`。

1.  首先，我们需要在开发依赖项中安装这个新的预设：

```js
 npm i -D babel-preset-vue
```

主要的 babel 配置已经在项目根目录中的`.babelrc` JSON 文件中完成。

这个文件可能在您的文件资源管理器中被隐藏，这取决于系统（它的名称以点开头）。但是，如果它有文件树视图，它应该在您的代码编辑器中可见。

1.  打开这个`.babelrc`文件，并将`vue`预设添加到相应的列表中：

```js
      {
        "presets": [
          ["env", { "modules": false }],
          "stage-3",
          "vue"
        ]
      }
```

# Polyfills

让我们还添加 Babel polyfills，以在旧的浏览器中使用新的 JavaScript 功能。

1.  在开发依赖项中安装`babel-polyfill`软件包：

```js
 npm i -D babel-polyfill
```

1.  在`src/main.js`文件的开头导入它：

```js
 import  'babel-polyfill'
```

这将为浏览器启用所有必要的 polyfills。

# 更新依赖项

项目脚手架完成后，您可能需要更新它使用的软件包。

# 手动更新

要检查项目中使用的软件包是否有新版本可用，请在根文件夹中运行此命令：

```js
npm outdated
```

如果检测到新版本，将显示一个表格：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/b35444cf-12e8-4295-abf4-2c45b60a5fd5.png)

`Wanted`列是与`package.json`文件中指定的版本范围兼容的版本号。要了解更多信息，请访问 npm 文档[http s://docs.npmjs.com/getting-started/semantic-versioning](https://docs.npmjs.com/getting-started/semantic-versioning)。

要手动更新软件包，请打开`package.json`文件并找到相应的行。更改版本范围并保存文件。然后，运行此命令以应用更改：

```js
npm install
```

不要忘记阅读您更新的软件包的更改日志！可能会有重大变化或改进，您会很乐意了解。

# 自动更新

要自动更新软件包，请在项目的根文件夹中使用此命令：

```js
npm update
```

这个命令只会更新与`package.json`文件中指定版本兼容的版本。如果您想要更新包到其他版本，您需要手动进行。

# 更新 Vue

当您更新包含核心库的`vue`包时，您也应该更新`vue-template-compiler`包。这是一个在使用 webpack（或其他构建工具）时编译所有组件模板的包。

这两个包必须始终处于相同的版本。例如，如果您使用`vue 2.5.3`，那么`vue-template-compiler`也应该是版本`2.5.3`。

# 为生产构建

当您需要将您的应用程序部署到真实服务器上时，您需要运行这个命令来编译您的项目：

```js
npm run build
```

默认情况下，使用`webpack-simple`模板时，它会将 JavaScript 文件输出到项目的`/dist`文件夹中。您只需要上传这个文件夹和根文件夹中存在的`index.html`文件。您的服务器上应该有以下文件树：

```js
- index.html
- favicon.png
- [dist] - build.js
         ∟ build.map.js
```

# 单文件组件

在这一部分，我们将介绍一个在创建真实生产 Vue 应用程序中广泛使用的重要格式。

Vue 有自己的格式称为**单文件组件**（**SFC**）。这个格式是由 Vue 团队创建的，文件扩展名是`.vue`。它允许您在一个地方编写一个文件的模板、逻辑和样式。这个地方的主要优势是每个组件都是清晰自包含的，更易维护和共享。

SFC 使用类似 HTML 的语法描述了一个 Vue 组件。它可以包含三种类型的根块：

+   `<template>`，描述了组件的模板，使用了我们已经使用过的模板语法

+   `<script>`，其中包含组件的 JavaScript 代码

+   `<style>`，其中包含组件使用的样式

以下是一个 SFC 的示例：

```js
<template>
  <div>
    <p>{{ message }}</p>
    <input v-model="message"/>
  </div>
</template>

<script>
export default {
  data () {
    return {
      message: 'Hello world',
    }
  },
}
</script>

<style>
p {
  color: grey;
}
</style>
```

现在让我们尝试这个组件！

1.  将上述组件源代码放入`src`文件夹中的新`Test.vue`文件中。

1.  编辑`main.js`文件，并使用`import`关键字导入 SFC：

```js
      import Test from './Test.vue'
```

1.  删除`render`选项，而是使用对象扩展运算符复制`Test`组件的定义：

```js
      new Vue({
        el: '#app',
        ...Test,
      })
```

在前面的片段中，我演示了将根组件添加到应用程序的另一种方法--使用 JavaScript Spread 运算符--因此`...App`表达式将将属性复制到应用程序定义对象。主要优点是我们将不再在开发工具中有一个无用的顶级组件；它现在将是我们的直接根组件。

1.  继续打开终端中显示的 URL 以查看结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/bcd377ab-9146-4ad7-8711-97d392d83d4d.png)

# Template

`<template>`标签包含组件的模板。与之前一样，它是 HTML，具有 Vue 特殊语法（指令，文本插值，快捷方式等）。

以下是 SFC 中`<template>`标签的示例：

```js
<template>
  <ul class="movies">
    <li v-for="movie of movies" class="movie">
      {{ movie.title }}
    </li>
  </ul>
</template>
```

在此示例中，我们组件的模板将包含一个包含显示电影标题的`li`元素列表的`ul`元素。

如果在 SFC 中不放置`<template>`标签，您将需要编写一个渲染函数，否则您的组件将无效。

# 使用 Pug

Pug（以前叫 Jade）是一种编译成 HTML 的语言。我们可以在`<template>`标签中使用它，`lang`属性设置为“pug”：

```js
<template lang="pug">
ul.movies
  li.movie Star Wars
  li.movie Blade Runner
</template>
```

要编译 SFC 中的 Pug 代码，我们需要安装这些包：

```js
npm install --save-dev pug pug-loader
```

开发所需的包称为开发依赖项，并应使用`--save-dev`标志安装。应使用`--save`标志安装应用程序运行所需的直接依赖项（例如，将 markdown 编译为 HTML 的包）。

# Script

`<script>`标签包含与组件关联的 JavaScript 代码。它应该导出组件定义对象。

以下是`<script>`标签的示例：

```js
<script>
export default {
  data () {
    return {
      movies: [
        { title: 'Star Wars' },
        { title: 'Blade Runner' },
      ],
    }
  },
}
</script>
```

在此示例中，组件将具有返回具有`movies`数组的初始状态的`data`钩子。

如果您不需要组件选项中的任何选项，默认为空对象，则`<script>`标签是可选的。

# JSX

JSX 是在 JavaScript 代码中使用的一种特殊表示法，用于表示 HTML 标记。它使代码负责描述视图的方式更接近纯 HTML 语法，同时仍然具有 JavaScript 的全部功能。

以下是使用 JSX 编写的渲染函数示例：

```js
<script>
export default {
  data () {
    return {
      movies: [
        { title: 'Star Wars' },
        { title: 'Blade Runner' },
      ],
    }
  },
  render (h) {
    const itemClass = 'movie'
    return <ul class='movies'>
      {this.movies.map(movie =>
        <li class={ itemClass }>{ movie.title }</li>
      )}
    </ul>
  },
}
</script>
```

您可以在单括号内使用任何 JavaScript 表达式。

正如您在此示例中所看到的，我们可以使用任何 JavaScript 代码来组成我们的视图。我们甚至可以使用`movies`数组的`map`方法为每个项目返回一些 JSX。我们还使用了一个变量来动态设置电影元素的 CSS 类。

在编译过程中，真正发生的是一个名为`babel-plugin-transform-vue-jsx`的特殊模块包含在`babel-preset-vue`中，将 JSX 代码转换为纯 JavaScript 代码。编译后，前面的渲染函数将如下所示：

```js
render (h) {
  const itemClass = 'movie'
  return h('ul', { class: 'movies' },
    this.movies.map(movie =>
      h('li', { class: itemClass }, movie.title)
    )
  )
},
```

如您所见，JSX 是一种帮助编写渲染函数的语法。最终的 JavaScript 代码将与我们手动使用`h`（或`createElement`）编写的代码非常接近。

我们将在第六章中更详细地介绍渲染函数，*项目 4 - 地理定位博客*。

# 样式

单文件组件可以包含多个`<style>`标签，以向应用程序添加与此组件相关的 CSS。

以下是一个非常简单的组件样式应用一些 CSS 规则到`.movies`类：

```js
<style>
.movies {
  list-style: none;
  padding: 12px;
  background: rgba(0, 0, 0, .1);
  border-radius: 3px;
}
</style>
```

# 作用域样式

我们可以使用作用域属性将包含在`<style>`标签中的 CSS 限定为当前组件。这意味着此 CSS 仅应用于此组件模板的元素。

例如，我们可以使用通用的类名，如 movie，并确保它不会与应用程序的其余部分发生冲突：

```js
<style scoped>
.movie:not(:last-child) {
  padding-bottom: 6px;
  margin-bottom: 6px;
  border-bottom: solid 1px rgba(0, 0, 0, .1);
}
</style>
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/c0c86f93-a28f-4002-8141-78469f0d8495.png)

这是有效的，多亏了应用于模板和 CSS 的特殊属性，使用 PostCSS（一种处理工具）。例如，考虑以下作用域样式组件：

```js
<template>
  <h1 class="title">Hello</h1>
</template>

<style scoped>
.title {
  color: blue;
}
</style>
```

它相当于以下内容：

```js
<template>
  <h1 class="title" data-v-02ad4e58>Hello</h1>
</template>

<style>
.title[data-v-02ad4e58] {
  color: blue;
}
</style>
```

如您所见，为所有模板元素和所有 CSS 选择器添加了一个唯一的属性，以便它只匹配此组件的模板，不会与其他组件冲突。

作用域样式并不能消除对类的需求；由于浏览器呈现 CSS 的方式，当选择一个带有属性的普通元素时，可能会出现性能损失。例如，`li { color: blue; }`在组件范围内将比`.movie { color: blue; }`慢得多。

# 添加预处理器

现在，CSS 很少被直接使用。通常会使用功能更强大、功能更丰富的预处理器语言来编写样式。

在`<style>`标签上，我们可以使用`lang`属性指定其中一种语言。

我们将以此模板作为我们组件的基础：

```js
<template>
  <article class="article">
    <h3 class="title">Title</h3>
  </article>
</template>
```

# Sass

Sass 是许多技术公司使用的知名 CSS 预处理器：

1.  要在组件中启用 Sass，请安装以下软件包：

```js
 npm install --save-dev node-sass sass-loader
```

1.  然后，在您的组件中，添加一个`<style>`标签，其中`lang`属性设置为`"sass"`：

```js
      <style lang="sass" scoped>
      .article
        .title
          border-bottom: solid 3px rgba(red, .2)
      </style>
```

1.  现在，使用`vue build`命令测试您的组件。您应该有一个类似于这样的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a154cb93-95aa-4ac3-8734-6c1c337db551.png)如果您想使用 Sass 的 SCSS 语法变体，您需要使用`lang="scss"`。

# Less

Less 的语法比其他 CSS 预处理语言更简单：

1.  要使用 Less，您需要安装以下包：

```js
 npm install --save-dev less less-loader
```

1.  然后，在您的组件中，将`lang`属性设置为`"less"`：

```js
      <style lang="less" scoped>
      .article {
        .title {
          border-bottom: solid 3px fade(red, 20%);
        }
      }
      </style>
```

# Stylus

Stylus 比 Less 和 Sass 更新，也非常受欢迎：

1.  最后，对于 Stylus，您需要这些包：

```js
 npm install --save-dev stylus stylus-loader
```

1.  在`<style>`标签上，将`lang`属性设置为`"stylus"`：

```js
      <style lang="stylus" scoped>
      .article
        .title
          border-bottom solid 3px rgba(red, .2)
      </style>
```

# 组件内部的组件

现在我们知道如何编写单文件组件，我们希望在其他组件中使用它们来组成应用程序的界面。

要在另一个组件中使用组件，我们需要导入它并将其公开给模板：

1.  首先，创建一个新的组件。例如，这是一个`Movie.vue`组件：

```js
      <template>
        <li class="movie">
          {{ movie.title }}
        </li>
      </template>

      <script>
      export default {
        props: ['movie'],
      }
      </script>

      <style scoped>
      .movie:not(:last-child) {
        padding-bottom: 6px;
        margin-bottom: 6px;
        border-bottom: solid 1px rgba(0, 0, 0, .1);
      }
      </style>
```

如果您还没有创建`Movies.vue`组件，我们还需要一个。它应该是这样的：

```js
<template>
  <ul class="movies">
    <li v-for="movie of movies" class="movie">
      {{ movie.title }}
    </li>
  </ul>
</template>

<script>
export default {
  data () {
    return {
      movies: [
        { id: 0, title: 'Star Wars' },
        { id: 1, title: 'Blade Runner' },
      ],
    }
  },
}
</script>
```

1.  然后，在`Movies`组件的脚本中导入`Movie` SFC：

```js
      <script>
      import Movie from './Movie.vue'

      export default {
        // ...
      }
      </script>
```

1.  将`components`选项设置为向模板公开一些组件，使用一个对象（键是我们将在模板中使用的名称，值是组件定义）：

```js
      export default {
        components: {
          Movie,
          // Equivalent to `Movie: Movie,`
        },

        // ...
      }
```

1.  我们现在可以在模板中使用`Movie`标签使用组件：

```js
      <template>
        <ul class="movies">
          <Movie v-for="movie of movies"
            :key="movie.id"
            :movie="movie" />
        </ul>
      </template>
```

如果您使用 JSX，则不需要`components`选项，因为如果以大写字母开头，可以直接使用组件定义：

```js
import Movies from './Movies.vue'

export default {
  render (h) {
    return <Movies/>
    // no need to register Movies via components option
  }
}
```

# 总结

在本章中，我们安装了几个工具，这些工具将允许我们使用推荐的方法编写真正的生产就绪应用程序。现在，我们可以搭建整个项目骨架来开始构建出色的新应用程序。我们可以以各种方式编写组件，但是我们可以使用单文件组件以一致和可维护的方式进行编写。我们可以在我们的应用程序内部或在其他组件内部使用这些组件来组成我们的用户界面，其中包含多个可重用组件。

在下一章中，我们将使用我们到目前为止学到的所有知识创建我们的第三个应用程序，还有一些新的主题，比如路由！


# 第五章：项目 3 - 支持中心

在本章中，我们将构建一个更复杂的应用程序，具有路由系统（这意味着多个虚拟页面）。这将是一个名为“我的衬衫店”的虚构公司的支持中心。它将有两个主要部分：

+   一个包含一些问题和答案的常见问题页面

+   一个支持工单管理页面，用户将能够显示和创建新工单

该应用程序将具有身份验证系统，允许用户创建帐户或登录。

我们将首先创建一些基本路由，然后将集成此帐户系统，最后涉及更高级的路由主题。在整个章节中，我们将尽可能重用我们的代码并应用最佳实践。

# 一般应用程序结构

在第一部分中，我们将创建项目结构并了解更多关于路由和页面的知识。

# 设置项目

为了设置项目，需要按照以下步骤进行操作：

1.  首先，使用 `vue init webpack-simple <folder>` 命令生成一个 Vue 项目，就像我们在第四章中所做的那样，*高级项目设置*：

```js
 vue init webpack-simple support-center
 cd support-center
 npm install
      npm install --save babel-polyfill
```

1.  安装编译 Stylus 代码所需的软件包（我们的样式将使用 Stylus 编写）：

+   `stylus`

+   `stylus-loader`

```js
 npm install --save-dev stylus stylus-loader
```

不要忘记使用 `--save-dev` 标志将开发工具包保存在 `package.json` 文件的开发依赖项中。

1.  删除 `src` 文件夹的内容，我们将把所有应用程序源代码放在其中。

1.  然后创建一个 `main.js` 文件，其中包含创建 Vue 应用程序所需的代码：

```js
      import 'babel-polyfill'
      import Vue from 'vue'

      new Vue({
        el: '#app',
        render: h => h('div', 'Support center'),
      })
```

现在可以使用 `npm run dev` 命令运行应用程序了！

1.  大多数应用程序的样式已经可用。下载它（[`github.com/Akryum/packt-vue-project-guide/tree/master/chapter5-download)`](https://github.com/Akryum/packt-vue-project-guide/tree/master/chapter5-download) 并将 Stylus 文件提取到 `src` 目录内的 `style` 文件夹中。也提取 `assets` 文件夹。

# 路由和页面

我们的应用程序将组织在六个主要页面中：

+   主页

+   公共常见问题页面

+   登录页面

+   工单页面

+   发送新工单的页面

+   显示一个工单详情和对话的页面

路由是表示应用程序状态的路径，通常以页面的形式存在。每个路由都与一个 URL 模式相关联，当地址匹配时将触发路由。然后，相应的页面将呈现给用户。

# Vue 插件

为了在我们的应用程序中启用路由，我们需要一个名为`vue-router`的官方 Vue 插件。Vue 插件是一些设计用来为 Vue 库添加更多功能的 JavaScript 代码。您可以在 npm 注册表上找到许多插件，我推荐使用 awesome-vue GitHub 存储库（[`github.com/vuejs/awesome-vue`](https://github.com/vuejs/awesome-vue)）按类别列出它们：

1.  在项目目录中使用以下命令从 npm 下载`vue-router`包：

```js
 npm install --save vue-router
```

我们将把所有与路由相关的代码放在`main.js`文件旁边的新`router.js`文件中，您需要创建该文件。然后，我们需要使用全局的`Vue.use()`方法安装我们想要使用的插件（在我们的情况下是`vue-router`）。

1.  创建`router.js`文件，并从它们对应的包中导入`Vue`库和`VueRouter`插件：

```js
      import Vue from 'vue'
      import VueRouter from 'vue-router'
```

1.  然后将插件安装到 Vue 中：

```js
 Vue.use(VueRouter)
```

`vue-router`插件现在已准备好使用！

# 我们的第一个使用 vue-router 的路由

在本节中，我们将介绍在 Vue 应用程序中设置路由所需的步骤。

# 使用 router-view 的布局

在添加路由之前，我们需要为应用程序设置一个布局，路由组件将在其中呈现。

1.  让我们在`src`目录内的新`components`文件夹中创建一个名为`AppLayout.vue`的组件。

1.  编写组件的模板--包含一个带有图像和一些文本的`<header>`的`<div>`元素。然后，在标题后添加一个`<router-view />`组件：

```js
      <template>
        <div class="app-layout">
          <header class="header">
            <div><img class="img"
              src="../assets/logo.svg"/></div>
            <div>My shirt shop</div>
          </header>

          <!-- Menu will be here -->

          <router-view />
        </div>
      </template>
```

`<router-view />`组件是由`vue-router`插件提供的特殊组件，它将呈现当前匹配路由的组件。它不是一个真正的组件，因为它没有自己的模板，并且不会出现在 DOM 中。

1.  在模板之后，添加一个`style`标签，从*设置项目*部分中下载的`styles`文件夹中导入主 Stylus 文件。不要忘记使用`lang`属性指定我们正在使用`stylus`：

```js
      <style lang="stylus">
      @import '../style/main';
      </style>
```

1.  由于我们可以在 SFC 中拥有尽可能多的`style`标签，因此再添加一个，但这次是有作用域的。我们将在第二个样式部分中指定`header`标志的大小：

```js
      <style lang="stylus" scoped>
      .header {
        .img {
          width: 64px;
          height: 64px;
        }
      }
      </style>
```

为了提高性能，建议在有作用域的样式中使用类。

我们的布局组件已准备好包含在我们的应用程序中！

1.  在`main.js`文件中导入它并在`root`Vue 实例上呈现它：

```js
      import AppLayout from './components/AppLayout.vue'

      new Vue({
        el: '#app',
        render: h => h(AppLayout),
      })
```

我们还不能启动应用程序，因为我们的路由还没有完成！

如果你查看浏览器的控制台，你可能会看到一个错误消息，抱怨`<router-view />`组件丢失了。这是因为我们没有导入`router.js`文件，我们在其中将`vue-router`插件安装到 Vue 中，所以代码还没有包含在我们的应用程序中。

# 创建路由

让我们为测试路由创建一些愚蠢的页面：

1.  在`components`文件夹中，创建一个`Home.vue`组件，其中包含一个非常简单的模板，包括一个`<main>`元素，一个标题和一些文本：

```js
      <template>
        <main class="home">
          <h1>Welcome to our support center</h1>
          <p>
            We are here to help! Please read the <a>F.A.Q</a> first,
            and if you don't find the answer to your question, <a>send                  
            us a ticket!</a>
          </p>
        </main>
      </template>
```

1.  然后，在`Home.vue`旁边创建一个`FAQ.vue`组件。它也应该包含一个`<main>`元素，其中你可以添加一个简单的标题：

```js
      <template>
        <main class="faq">
          <h1>Frenquently Asked Questions</h1>
        </main>
      </template>
```

现在我们有了创建一些路由所需的东西。

1.  在`router.js`文件中，导入我们刚刚创建的两个组件：

```js
      import Home from './components/Home.vue'
      import FAQ from './components/FAQ.vue'
```

1.  然后，创建一个`routes`数组：

```js
      const routes = [
        // Routes will be here
      ]
```

路由是一个包含路径、名称和要渲染的组件的对象：

```js
{ path: '/some/path', name: 'my-route', component: ... }
```

路径是当前 URL 应该匹配的模式，以激活路由。组件将呈现在特殊的`<router-view />`组件中。

路由名称是可选的，但我强烈建议使用它。它允许您指定路由的名称而不是路径，这样您就可以移动和更改路由而不会出现断开的链接。

1.  考虑到这一点，我们现在可以在`routes`数组中添加我们的两个路由：

```js
      const routes = [
        { path: '/', name: 'home', component: Home },
        { path: '/faq', name: 'faq', component: FAQ },
      ]
```

让我们来回顾一下它将会做什么：

+   当浏览器 URL 为`http://localhost:4000/`时，将呈现`Home.vue`组件

+   当 URL 为`http://localhost:4000/faq/`时，将显示`FAQ.vue`组件

# 路由对象

有了我们准备好的路由，我们需要创建一个`router`对象来负责管理路由。我们将使用`vue-router`包中的`VueRouter`构造函数。它接受一个`options`参数，现在，我们将使用`routes`参数：

1.  在`router.js`文件中的`routes`数组之后，创建一个新的`router`对象并指定`routes`参数：

```js
      const router = new VueRouter({
        routes,
      })
```

我们安装的插件也是路由构造函数，所以我们使用相同的`VueRouter`变量。`VueRouter`实际上是一个有效的 Vue 插件，因为它有一个`install`方法。在本章中，我们将创建自己的插件！

1.  将`router`对象导出为模块的默认导出值：

```js
 export default router
```

1.  现在回到我们的`main.js`文件，我们需要将`router`对象提供给 Vue 应用程序。导入我们刚刚创建的`router`：

```js
      import router from './router'
```

1.  然后将其作为根 Vue 实例的定义选项添加：

```js
      new Vue({
        el: '#app',
        render: h => h(AppLayout),
        // Provide the router to the app
        router,
      })
```

这就是我们让路由工作所需的全部！现在你可以尝试在浏览器中更改 URL 为`http://localhost:4000/#/`或`http://localhost:4000/#/faq`，每次都会得到不同的页面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/573630b2-2281-4d69-a433-340ca757d243.png)不要忘记 URL 中的尖号`#`字符；在不更改真正的网页的情况下，需要伪造路由更改。这是称为`hash`的默认路由器模式，并且可以与任何浏览器和服务器一起使用。

# 路由器模式

我们可以通过构造函数选项中的`mode`参数来更改路由器模式。它可以是`'hash'`（默认值）、`'history'`或`'abstract'`。

`hash`模式是我们已经在使用的默认模式。这是“最安全”的选择，因为它与任何浏览器和服务器兼容。它包括使用 URL 的`hash`部分（也就是尖号后面的部分）并更改它或对其进行反应。最大的优势是更改哈希部分不会更改我们的应用程序正在运行的真正网页（这将是非常不幸的）。显而易见的缺点是它强迫我们用不太漂亮的尖号符号将 URL 分成两部分。

由于 HTML5 的`history.pushState` API，我们可以摆脱这个尖锐字符，并为我们的应用程序获得一个真正的 URL！我们需要在构造函数中将模式更改为`'history'`：

```js
const router = new VueRouter({
  routes,
  mode: 'history',
})
```

现在我们可以在我们的单页面应用程序中使用漂亮的 URL，比如`http://localhost:4000/faq`！不过有两个问题：

+   浏览器需要支持这个 HTML5 API，这意味着它在 Internet Explorer 9 或更低版本上无法工作（其他主要浏览器已经支持了相当长的时间）。

+   服务器必须配置为在访问`/faq`这样的路由时发送主页，而不是抛出 404 错误，因为它实际上并不存在（你没有一个名为`faq.html`的文件）。这也意味着我们将不得不自己实现 404 页面。

值得庆幸的是，由`vue build`使用的 webpack 服务器默认配置为支持这一点。所以你可以继续尝试新的`http://localhost:4000/faq` URL！

有第三种模式称为“抽象”，可以在任何 JavaScript 环境中使用（包括 Node.js）。如果没有浏览器 API 可用，路由将被迫使用此模式。

# 创建导航菜单

与手动输入 URL 相比，在我们的应用程序中拥有一个合适的导航`菜单`将会很棒！让我们在我们的`components`文件夹中创建一个新的`NavMenu.vue`文件：

```js
<template>
  <nav class="menu">
    <!-- Links here -->
  </nav>
</template>
```

接下来，我们将在布局中添加它。在`AppLayout`中导入新组件：

```js
<script>
import NavMenu from './NavMenu.vue'
export default {
  components: {
    NavMenu,
  },
}
</script>
```

然后将其添加到`AppLayout`模板中：

```js
<header class="header">
  <div><img class="img" src="../assets/logo.svg"/></div>
  <div>My shirt shop</div>
</header>

<NavMenu />
```

# 路由链接

`vue-router`插件为我们提供了另一个方便的特殊组件--`<router-link>`。这是一个组件，当单击时将切换到指定的路由，这要归功于它的`to`属性。默认情况下，它将是一个`<a>` HTML 元素，但可以使用`tag`属性进行自定义。

例如，指向 FAQ 页面的链接将是：

```js
<router-link to="/faq">FAQ</router-link>
```

`to`属性也可以获得一个具有名称属性而不是路径的对象：

```js
<router-link :to="{ name: 'faq' }">FAQ</router-link>
```

这将动态生成路由的正确路径。我建议您使用这种第二种方法，而不是仅指定路径--这样，如果您更改路由的路径，您的导航链接仍将起作用。

在使用对象表示法时，不要忘记使用`v-bind`或`:`简写将`to`属性绑定到`router-link`组件，否则`router-link`组件将获得一个字符串，并且不会理解它是一个对象。

现在我们可以将链接添加到我们的`NavMenu`组件中：

```js
<template>
  <nav class="menu">
    <router-link :to="{ name: 'home' }">Home</router-link>
    <router-link :to="{ name: 'faq' }">FAQ</router-link>
  </nav>
</template>
```

现在您应该在应用程序中有一个可用的菜单：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/09491639-cb34-4468-a2ec-e31562b55427.png)

# 活动类

当与其关联的路由当前处于活动状态时，路由链接将获得活动类。默认情况下，组件会获得`router-link-active` CSS 类，因此您可以相应地更改其外观：

1.  在我们的`NavMenu.vue`组件中，声明一些作用域样式，使用 Stylus 为活动链接添加底部边框：

```js
      <style lang="stylus" scoped>
      @import '../style/imports';

      .router-link-active {
        border-bottom-color: $primary-color;
      }
      </style>
```

我们在`@import '../style/imports';`语句中包含了`$primary-color`变量，该语句导入了包含 Stylus 变量的`imports.styl`文件。

如果您现在尝试该应用程序，您会发现我们的菜单出现了一些奇怪的情况。如果您转到主页，它会按预期工作：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/fcd3f66c-a061-4b55-8c19-ba01405e923f.png)

但当您转到 FAQ 页面时，主页和 FAQ 链接都会被突出显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/8baa75ec-9101-4117-8793-7168c1a06fd4.png)

这是因为默认情况下，活动类匹配行为是包容的！这意味着`<router-link to="/faq">`如果路径是`/faq`或以`/faq/`开头，将获得活动类。但这也意味着`<router-link to="/">`如果当前路径以`/`开头，将获得该类，这些都是可能的路径！这就是为什么我们的主页链接总是会获得该类。

为了防止这种情况发生，有一个`exact`属性，它是一个布尔值。如果设置为`true`，则只有在当前路径完全匹配时，链接才会获得活动类。

1.  将`exact`属性添加到主页链接：

```js
      <router-link :to="{ name: 'home' }" exact>Home</router-link>
```

现在，只有 FAQ 链接应该被突出显示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/218e9760-554f-4d93-bd60-423a3ca235d1.png)

# FAQ - 使用 API

在本节中，我们将创建 FAQ 页面，该页面将从服务器获取数据。它将显示加载动画，然后显示问题和答案列表。

# 服务器设置

这是我们的第一个与服务器通信的应用程序。您将获得一个带有可用 API 的服务器。

您可以下载服务器文件（[`github.com/Akryum/packt-vue-project-guide/tree/master/chapter5-download`](https://github.com/Akryum/packt-vue-project-guide/tree/master/chapter5-download)）。将它们解压到与我们的应用程序不同的文件夹中，并运行以下命令来安装依赖项并启动服务器：

```js
cd server_folder
npm install
npm start
```

现在您应该在端口 3000 上运行服务器。完成后，我们可以继续构建我们的应用程序，这次使用真正的后端！

# 使用 fetch

在`FAQ.vue`单文件组件中，我们将使用 Web 浏览器的标准`fetch` API 从服务器检索问题。请求将是一个非常简单的`GET`请求到`http://localhost:3000/questions`，不需要身份验证。每个问题对象将有`title`和`content`字段：

1.  打开`FAQ.vue`，并首先在组件脚本中添加`questions`数据属性，该属性将保存从服务器检索的问题数组。我们还需要一个`error`属性，在网络请求期间出现问题时显示消息：

```js
      <script>
      export default {
        data () {
          return {
            questions: [],
            error: null,
          }
        },
      }
      </script>
```

1.  现在我们可以使用`v-for`循环将问题和答案添加到模板中，并显示以下错误消息：

```js
      <template>
        <main class="faq">
          <h1>Frequently Asked Questions</h1>

          <div class="error" v-if="error">
            Can't load the questions
          </div>

          <section class="list">
            <article v-for="question of questions">
              <h2 v-html="question.title"></h2>
              <p v-html="question.content"></p>
```

```js
            </article>
          </section>
        </main>
      </template>
```

我们准备好进行获取了！fetch API 是基于 promise 的，非常简单易用。以下是`fetch`用法示例：

```js
fetch(url).then(response => {
  if (response.ok) {
    // Returns a new promise
    return response.json()
  } else {
    return Promise.reject('error')
  }
}).then(result => {
  // Success
  console.log('JSON:', result)
}).catch(e => {
  // Failure
  console.error(e)
})
```

我们首先使用请求的 URL 作为第一个参数调用`fetch`。它返回一个带有`response`对象的 promise，该对象保存有关请求结果的信息。如果成功，我们使用`response.json()`，它返回一个解析后的 JSON 结果对象的新 promise。

请求将在组件内部进行，一旦创建时路由匹配，这意味着您应该在组件定义中使用`created`生命周期钩子：

```js
data () {
  // ...
},
created () {
  // fetch here
},
```

如果一切顺利，我们将使用 JSON 解析后的结果设置问题属性。否则，我们将显示错误消息。

1.  从正确的 URL 调用`fetch`开始：

```js
 created () {
        fetch('http://localhost:3000/questions')
      },
```

1.  添加第一个`then`回调与`response`对象：

```js
      fetch('http://localhost:3000/questions').then(response => {
        if (response.ok) {
          return response.json()
        } else {
          return Promise.reject('error')
        }
      })
```

1.  由于`response.json()`返回一个新的 promise，我们需要另一个`then`回调：

```js
        // ...
      }).then(result => {
        // Result is the JSON parsed object from the server
        this.questions = result
      })
```

1.  最后，我们捕获所有可能的错误以显示错误消息：

```js
        // ...
      }).catch(e => {
        this.error = e
      })
```

以下是我们`created`钩子的摘要：

```js
created () {
  fetch('http://localhost:3000/questions').then(response => {
    if (response.ok) {
      return response.json()
    } else {
      return Promise.reject('error')
    }
  }).then(result => {
    this.questions = result
  }).catch(e => {
    this.error = e
  })
},
```

我们可以使用`async`和`await` JavaScript 关键字重写此代码，使其看起来像顺序代码：

```js
async created () {
  try {
    const response = await fetch('http://localhost:3000/questions')
    if (response.ok) {
      this.questions = await response.json()
    } else {
      throw new Error('error')
    }
  } catch (e) {
    this.error = e
  }
},
```

现在您可以尝试该页面，该页面应该显示一个问题和答案的列表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/ad13159c-6d51-4eaf-b5b4-bdcc1805b9ce.png)

要查看我们的错误管理是否有效，您可以转到运行服务器的控制台，并停止它（例如，使用 C*trl*+*C*键盘快捷键）。然后，您可以重新加载应用程序，应该显示以下错误消息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/409552ab-7806-49a0-bf57-e5ca5a8cd921.png)

# 加载动画

还有一件事情遗漏了--我们应该显示一个加载动画来通知用户操作正在进行中，而不是一个空屏幕。为此，服务器在`/questions`请求上伪造了 1.5 秒的延迟，这样我们就可以轻松看到加载动画。

由于我们将在多个组件中显示加载动画，我们将创建一个新的全局组件：

1.  在`components`文件夹中，创建一个名为`Loading.vue`的新文件，内容如下模板：

```js
      <template>
        <div class="loading">
          <div></div>
        </div>
      </template>
```

1.  在`main`文件夹中的`main.js`文件旁边创建一个新的`global-components.js`文件。在这个文件中，我们将使用`Vue.component()`方法全局注册`Loading`组件：

```js
      import Vue from 'vue'
      import Loading from './components/Loading.vue'

      Vue.component('Loading', Loading)
```

这是我们将注册所有应用程序中使用的全局组件的文件。

1.  然后，在`main.js`文件中，导入`global-components.js`模块：

```js
      import './global-components'
```

1.  回到我们的`FAQ.vue`组件，我们需要一个新的`loading`布尔数据属性来切换动画的显示：

```js
      data () {
        return {
          questions: [],
          error: null,
          loading: false,
        }
      },
```

1.  在模板中添加加载动画：

```js
      <Loading v-if="loading" />
```

1.  最后，通过在`created`钩子中将`loading`设置为`true`开头，当一切都完成时设置为`false`，稍微改变`created`钩子：

```js
      async created () {
        this.loading = true
        try {
          const response = await                             
       fetch('http://localhost:3000/questions')
          // ...
        } catch (e) {
          this.error = e
        }
        this.loading = false
      }
```

现在您可以重新加载页面，在问题出现之前短暂地看到加载动画：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/436a47ea-2274-4dbd-8f07-146d12974f14.png)

# 使用我们自己的插件扩展 Vue

由于我们将在应用程序的多个组件中使用 fetch，并且我们希望尽可能多地重用代码，因此最好在所有组件上都有一个向服务器发出预定义 URL 请求的方法。

这是一个很好的自定义 Vue 插件使用案例！别担心，编写插件实际上非常简单。

# 创建插件

要创建一个插件，只有一个规则--插件应该是一个带有`install`方法的对象，该方法以 Vue 构造函数作为第一个参数，并且可选的`options`参数。然后，该方法将通过修改构造函数来为框架添加新功能：

1.  在`src`文件夹中创建一个新的`plugins`文件夹。

1.  在`plugins`文件夹中，创建一个`fetch.js`文件，我们将在这里编写我们的插件。在这种情况下，我们的插件将在所有组件上添加一个新的`$fetch`特殊方法。我们将通过改变 Vue 的原型来实现这一点。

1.  让我们尝试创建一个非常简单的插件，通过导出一个带有`install`方法的对象：

```js
      export default {
        install (Vue) {
          console.log('Installed!')
        }
      }
```

就是这样！我们已经创建了一个 Vue 插件！现在，我们需要将其安装到我们的应用程序中。

1.  在`main.js`文件中，导入插件，然后调用`Vue.use()`方法，就像我们为`vue-router`做的那样：

```js
      import VueFetch from './plugins/fetch'
      Vue.use(VueFetch)
```

现在你应该在浏览器控制台中看到`'Installed!'`消息。

# 插件选项

我们可以使用`options`参数配置插件：

1.  编辑`install`方法，在`Vue`之后添加这个参数：

```js
      export default {
        install (Vue, options) {
          console.log('Installed!', options)
        },
      }
```

现在，我们可以在`main.js`文件中的`Vue.use()`方法中添加一个配置对象。

1.  让我们在配置中添加一个`baseUrl`属性：

```js
      Vue.use(VueFetch, {
        baseUrl: 'http://localhost:3000/',
      })
```

现在你应该在浏览器控制台中看到`options`对象。

1.  将`baseUrl`存储到一个变量中，以便我们以后可以使用它：

```js
      let baseUrl

      export default {
        install (Vue, options) {
          console.log('Installed!', options)

          baseUrl = options.baseUrl
        },
      }
```

# 获取方法

现在，我们将编写`$fetch`方法。我们将使用 FAQ 组件的`created`钩子中使用的大部分代码：

1.  使用`fetch`实现`$fetch`方法：

```js
      export async function $fetch (url) {
        const response = await fetch(`${baseUrl}${url}`)
        if (response.ok) {
          const data = await response.json()
          return data
        } else {
          const error = new Error('error')
          throw error
        }
      }
```

我们将其导出，以便我们也可以在我们的纯 JavaScript 代码中使用它。现在`url`参数只是查询的路径，不包括域名，域名现在在我们的`baseUrl`变量中--这使我们可以轻松地更改它，而不必重构每个组件。我们还负责 JSON 解析，因为服务器上的所有数据都将以 JSON 编码。

1.  为了使它在所有组件中可用，只需将其添加到`Vue`的原型中（这是用于创建组件的构造函数）：

```js
      export default {
        install (Vue, options) {
          // Plugin options
          baseUrl = options.baseUrl

          Vue.prototype.$fetch = $fetch
        },
      }
```

1.  然后，重构 FAQ 组件，使用我们新的特殊`$fetch`方法在创建钩子中：

```js
      this.loading = true
      try {
        this.questions = await this.$fetch('questions')
      } catch (e) {
        this.error = e
      }
      this.loading = false
```

我们组件中的代码现在更短、更易读，并且更具可扩展性，因为我们可以轻松地更改基本 URL。

# 使用 mixin 重用代码

我们已经看到了如何创建插件，但还有另一种改进我们的代码的方法--如果我们可以在多个组件之间重用组件定义，比如计算属性、方法或观察者，会怎么样？这就是 mixin 的作用！

混合是一个可以应用到其他定义对象（包括其他混合）的组件定义对象。它非常简单，因为它看起来和常规组件定义完全一样！

我们的目标是有一个`RemoteData`混合，它将允许任何组件向服务器发出请求以获取数据。让我们在`src`目录下添加一个新的`mixins`文件夹，并创建一个新的`RemoteData.js`文件：

1.  我们将从导出一个带有数据属性的定义开始简单：

```js
      export default {
        data () {
          return {
            remoteDataLoading: 0,
          }
        },
      }
```

这个`remoteDataLoading`属性将用于计算当前正在加载的请求数量，以帮助我们显示加载动画。

1.  现在，要在我们的 FAQ 组件中使用这个混合，我们需要导入它并将其添加到`mixins`数组中：

```js
      <script>
      import RemoteData from '../mixins/RemoteData'

      export default {
        mixins: [
          RemoteData,
        ],

        // ...
      }
      </script>
```

如果你检查组件，你现在应该看到一个额外的`remoteDataLoading`属性被显示出来：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/be837ea2-b9ad-4921-9e14-2231c38ab64d.png)

发生了什么？混合被应用并合并到了`FAQ.vue`的组件定义中，这意味着数据钩子被调用了两次--首先是来自混合，然后是来自 FAQ 定义，并且添加了一个新属性！

Vue 将自动合并标准选项，如钩子、数据、计算属性、方法和监视器，但是如果你有，例如，一个具有相同名称的属性或方法，最后一个应用的将覆盖之前的。

1.  让我们尝试用另一个值覆盖组件中的新属性：

```js
      data () {
        return {
          questions: [],
          error: null,
          loading: false,
          remoteDataLoading: 42,
        }
      },
```

正如你在组件检查器中所看到的，最终的组件定义比混合具有更高的优先级。另外，你可能已经注意到`mixins`选项是一个数组，因此我们可以将多个混合应用到定义中，它们将按顺序合并。例如，假设我们有两个混合并希望将它们应用到组件定义中。下面是会发生的事情：

1.  1.  定义对象包含混合 1 的选项。

1.  混合 2 的选项被合并到定义对象中（现有属性/方法名称被覆盖）。

1.  同样，组件的选项会合并到最终的定义对象中。

你现在可以从 FAQ 组件定义中删除重复的`remoteDataLoading: 42,`。

像`data`、`created`、`mounted`这样的钩子会按照它们被应用到最终定义的顺序分别被调用。这也意味着最终组件定义的钩子将会最后被调用。

# 获取远程数据

我们有一个问题--每个使用我们的`RemoteData` mixin 的组件将具有不同的数据属性需要获取。因此，我们需要向我们的 mixin 传递参数。由于 mixin 本质上是一个定义对象，为什么不使用一个可以接受参数并返回定义对象的函数呢？这就是我们在这种情况下要做的事情！

1.  将我们定义的对象包装在一个带有`resources`参数的函数中：

```js
 export default function (resources) {
        return {
          data () {
            return {
              remoteDataLoading: 0,
            }
          },
        }
      }
```

`resources`参数将是一个对象，其中每个键都是我们要添加的数据属性的名称，值是需要向服务器发出的请求的路径。

1.  因此，我们需要更改我们在`FAQ.vue`组件中使用 mixin 的方式，改为函数调用：

```js
      mixins: [
        RemoteData({
          questionList: 'questions',
        }),
      ],
```

在这里，我们将获取`http://localhost:3000/questions` URL（使用我们之前创建的特殊`$fetch`方法）并将结果放入`questionList`属性中。

现在让我们来看看我们的`RemoteData` mixin！

1.  首先，我们需要将每个数据属性初始化为`null`值，这样 Vue 才能在其上设置响应性：

```js
 data () {
        let initData = {
          remoteDataLoading: 0,
        }

        // Initialize data properties
        for (const key in resources) {
          initData[key] = null
        }

        return initData
      },
```

这一步很重要--如果您不初始化数据，Vue 不会使其具有响应性，因此当属性更改时，组件将不会更新。

您可以尝试该应用程序，并在组件检查器中查看`FAQ`组件中已添加了一个新的`questionList`数据属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/3e9d5417-0726-4394-8b40-50815458cf77.png)

1.  然后，我们将创建一个新的`fetchResource`方法，该方法获取一个资源并更新相应的数据属性：

```js
 methods: {
        async fetchResource (key, url) {
          try {
            this.$data[key] = await this.$fetch(url)
          } catch (e) {
            console.error(e)
          }
        },
      },
```

我们的组件现在可以直接访问这个新方法并使用它。

1.  为了使我们的 mixin 更智能，我们将在`created`钩子内自动调用它（将被合并）：

```js
 created () {
        for (const key in resources) {
          let url = resources[key]
          this.fetchResource(key, url)
        }
      },
```

您现在可以验证`questionList`数据属性是否随着向服务器发出的新请求而更新：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/3eee8bfd-5850-4a4e-8d45-c5c574fd1549.png)

1.  然后，您可以在`FAQ.vue`组件中删除具有`questions`属性的旧代码，并更改模板以使用新属性：

```js
      <article v-for="question of questionList">
```

# 加载管理

我们接下来要做的事情是提供一种方法来知道是否应该显示加载动画。由于我们可能会有多个请求，所以我们将使用一个数字计数器而不是布尔值--`remoteDataLoading`，我们已经在`data`钩子中声明了。每次发出请求时，我们都会递增计数器，当请求完成时，我们会递减计数器。这意味着如果它等于零，当前没有挂起的请求，如果大于或等于一，我们应该显示加载动画：

1.  在`fetchResource`方法中添加两个语句，递增和递减`remoteDataLoading`计数器：

```js
      async fetchResource (key, url) {
        this.$data.remoteDataLoading++
        try {
          this.$data[key] = await this.$fetch(url)
        } catch (e) {
          console.error(e)
        }
        this.$data.remoteDataLoading--
      },
```

1.  为了在使用 mixin 时使我们的生活更轻松，让我们添加一个名为`remoteDataBusy`的计算属性，当我们需要显示加载动画时将为`true`：

```js
 computed: {
        remoteDataBusy () {
          return this.$data.remoteDataLoading !== 0
        },
      },
```

1.  回到我们的 FAQ 组件，现在我们可以删除`loading`属性，更改`Loading`组件的`v-if`表达式，并使用`remoteDataLoading`计算属性：

```js
      <Loading v-if="remoteDataBusy" />
```

您可以尝试刷新页面，以查看在检索数据之前显示的加载动画。

# 错误管理

最后，我们可以管理可能发生的任何资源请求的错误。

1.  我们将为每个资源存储错误在一个新的`remoteErrors`对象中，这需要初始化：

```js
      // Initialize data properties
      initData.remoteErrors = {}
      for (const key in resources) {
        initData[key] = null
        initData.remoteErrors[key] = null
      }
```

`remoteErrors`对象的键将与资源相同，值将是错误或`null`（如果没有错误）。

接下来，我们需要修改`fetchResource`方法：

+   在请求之前，通过将其设置为`null`来重置错误

+   如果在 catch 块中有错误，请将其放入正确的键的`remoteErrors`对象中

1.  `fetchResource`方法现在应该如下所示：

```js
      async fetchResource (key, url) {
        this.$data.remoteDataLoading++
        // Reset error
        this.$data.remoteErrors[key] = null
        try {
          this.$data[key] = await this.$fetch(url)
        } catch (e) {
          console.error(e)
          // Put error
          this.$data.remoteErrors[key] = e
        }
        this.$data.remoteDataLoading--
      },
```

我们现在可以为每个资源显示特定的错误消息，但在这个项目中我们将简单地显示一个通用的错误消息。让我们添加另一个名为`hasRemoteErrors`的计算属性，如果至少有一个错误，则返回 true。

1.  使用 JavaScript 的“Object.keys（）”方法，我们可以迭代`remoteErrors`对象的键，并检查某些值是否不是`null`（这意味着它们为真）：

```js
      computed: {
        // ...

        hasRemoteErrors () {
          return Object.keys(this.$data.remoteErrors).some(
            key => this.$data.remoteErrors[key]
          )
        },
      },
```

1.  现在我们可以再次通过用新的替换 FAQ 组件模板`error`属性：

```js
      <div class="error" v-if="hasRemoteErrors">
```

就像以前一样，您可以关闭服务器以查看显示的错误消息。

我们现在已经完成了 FAQ 组件，其脚本现在应该如下所示：

```js
<script>
import RemoteData from '../mixins/RemoteData'

export default {
  mixins: [
    RemoteData({
      questionList: 'questions',
    }),
  ],
}
</script>
```

如您所见，现在非常简洁！

# 支持票

在最后一部分中，我们将创建应用程序的经过身份验证的部分，用户将能够添加和查看支持票。您已经下载的服务器上已经有所有必要的请求，如果您对在 node 中如何使用`passport.js`完成这些操作感到好奇，您可以查看源代码！

# 用户认证

在这个第一部分，我们将处理应用程序的用户系统。我们将有登录和注册组件，以便能够创建新用户。

# 将用户存储在集中状态中

我们将像我们在第三章中所做的那样，将用户数据存储在状态对象中，*项目 2* - *城堡决斗浏览器游戏*，这样我们就可以在应用程序的任何组件中访问它：

1.  在`main.js`旁边创建一个新的`state.js`文件，导出状态对象：

```js
      export default {
        user: null,
      }
```

当没有用户登录时，`user`属性将为 null，否则它将包含用户数据。

1.  然后，在`main.js`文件中，导入状态：

```js
      import state from './state'
```

1.  然后，将其用作根实例的数据，这样 Vue 就会使其具有反应性：

```js
      new Vue({
        el: '#app',
        data: state,
        router,
        render: h => h(AppLayout),
      })
```

# 另一个插件

然后，我们可以在组件文件中导入状态，但能够像我们为`fetch`插件做的那样，在 Vue 原型上使用一个特殊的 getter`$state`来访问它会更方便。我们将状态对象传递给插件选项，getter 将返回它。

1.  在`plugins`文件夹中，创建一个导出新插件的`state.js`文件：

```js
      export default {
        install (Vue, state) {
          Object.defineProperty(Vue.prototype, '$state', {
            get: () => state,
          })
        }
      }
```

在这里，我们使用 JavaScript 的`Object.defineProperty()`方法在 Vue 原型上设置一个 getter，所以每个组件都会继承它！

最后一件事——我们需要安装状态插件！

1.  在`main.js`文件中，导入新插件：

```js
      import VueState from './plugins/state'
```

1.  然后使用状态对象作为选项参数安装它：

```js
 Vue.use(VueState, state)
```

现在我们可以在组件中使用`$state`来访问全局状态了！这里是一个例子：

```js
console.log(this.$state)
```

这应该输出带有`user`属性的状态对象。

# 登录表单

在这一部分，我们将首先创建新的组件来帮助我们更快地构建表单，然后我们将使用`Login.vue`组件将注册和登录表单添加到应用程序中。在后面的部分，我们将创建另一个表单来提交新的支持票。

# 智能表单

这个通用组件将负责我们表单组件的非常一般的结构，并且会自动调用一个`operation`函数，显示一个加载动画和操作抛出的错误消息。大多数情况下，操作将是向服务器发出的`POST`请求。

模板本质上是一个带有标题的表单，一个默认插槽，用于呈现输入，一个用于按钮的`actions`插槽，一个加载动画，以及一个用于错误消息的位置。这将足够通用，适用于应用程序中我们需要的两个表单：

1.  在`components`文件夹中创建一个新的`SmartForm.vue`组件：

```js
      <template>
        <form @submit.prevent="submit">
          <section class="content">
            <h2>{{ title }}</h2>

            <!-- Main content -->
            <slot />

            <div class="actions">
              <!-- Action buttons -->
              <slot name="actions" />
            </div>

            <div class="error" v-if="error">{{ error }}</div>
          </section>

          <transition name="fade">
            <!-- Expanding over the form -->
            <Loading v-if="busy" class="overlay" />
          </transition>
        </form>
      </template>
```

在`<form>`元素上，我们在`'submit'`事件上设置了一个事件监听器，使用`prevent`修饰符阻止了浏览器的默认行为（重新加载页面）。

目前，`SmartForm`组件将有三个 props：

+   `标题`：这将显示在`<h2>`元素中。

+   `operation`：表单提交时调用的异步函数。它应该返回一个 promise。

+   `valid`：一个布尔值，用于防止在表单无效时调用操作。

1.  将它们添加到组件的`script`部分：

```js
      <script>
      export default {
        props: {
          title: {
            type: String,
            required: true,
          },
          operation: {
            type: Function,
            required: true,
          },
          valid: {
            type: Boolean,
            required: true,
          },
        },
      }
      </script>
```

正如你所看到的，我们现在正在使用一种不同的方式来声明 props--通过使用对象，我们可以指定 props 的更多细节。例如，使用`required: true`，Vue 会在我们忘记一个 prop 时警告我们。我们还可以放置 Vue 将检查的类型。这种语法是推荐的，因为它既有助于理解组件的 props，又能避免错误。

我们还需要两个数据属性：

+   `busy`：一个布尔值，用于切换加载动画的显示

+   `error`：这是错误消息，如果没有则为`null`

1.  使用`data`钩子添加它们：

```js
 data () {
        return {
          error: null,
          busy: false,
        }
      },
```

1.  最后，我们需要编写在表单提交时调用的`submit`方法：

```js
 methods: {
        async submit () {
          if (this.valid && !this.busy) {
            this.error = null
            this.busy = true
            try {
              await this.operation()
            } catch (e) {
              this.error = e.message
            }
            this.busy = false
          }
        },
      },
```

如果表单无效或仍在忙碌中，我们不调用操作。否则，我们重置`error`属性，然后调用`operation` prop，使用`await`关键字，因为它应该是一个返回 promise 的异步函数。如果我们捕获到错误，我们将消息设置为`error`属性，以便显示。

1.  现在我们的通用表单已经准备好了，我们可以在`global-components.js`文件中注册它：

```js
      import SmartForm from './components/SmartForm.vue'
      Vue.component('SmartForm', SmartForm)
```

# 表单输入组件

在我们的表单中，我们将有许多具有相同标记和功能的输入。这是制作另一个通用且可重用组件的绝佳机会。它将有一个小模板，主要是一个`<input>`元素，并且能够通过红色边框向用户显示它是无效的：

1.  首先创建一个新的`FormInput.vue`组件，具有以下 props：

+   `name`是输入的 HTML 名称，需要用于浏览器自动完成功能。

+   `type`默认为`'text'`，但最终我们需要设置为`'password'`。

+   `value`是输入框的当前值。

+   `placeholder`是显示在输入框内部的标签。

+   `invalid`是一个布尔值，用于切换无效显示（红色边框）。它默认为`false`。

脚本应该像这样使用 prop 对象表示法：

```js
<script>
export default {
  props: {
    name: {
      type: String,
    },
    type: {
      type: String,
      default: 'text',
    },
    value: {
      required: true,
    },
    placeholder: {
      type: String,
    },
    invalid: {
      type: Boolean,
      default: false,
    },
  },
}
</script>
```

1.  对于无效显示，我们将添加一个计算属性来动态更改输入框的 CSS 类：

```js
 computed: {
        inputClass () {
          return {
            'invalid': this.invalid,
          }
        },
      },
```

1.  现在我们可以编写我们的模板。它将包含一个包含`<input>`的`<div>`元素：

```js
      <template>
        <div class="row">
          <input
            class="input"
            :class="inputClass"
            :name="name"
            :type="type"
            :value.prop="value"
            :placeholder="placeholder"
          />
        </div>
      </template>
```

我们在`v-bind:value`指令上使用`prop`修饰符，告诉 Vue 直接设置 DOM 节点的`value`属性，而不是设置 HTML 属性。在处理诸如输入 HTML 元素的`value`等属性时，这是一个很好的做法。

1.  为了开始测试它，我们可以在`global-components.js`文件中注册组件：

```js
      import FormInput from './components/FormInput.vue'
      Vue.component('FormInput', FormInput)
```

1.  使用`FormInput`组件创建一个新的`Login.vue`组件：

```js
      <template>
        <main class="login">
          <h1>Please login to continue</h1>
          <form>
            <FormInput
              name="username"
              :value="username"
              placeholder="Username" />
          </form>
        </main>
      </template>

      <script>
      export default {
        data () {
          return {
            username: '',
          }
        },
      }
      </script>
```

1.  不要忘记在`router.js`文件中添加相应的路由：

```js
      import Login from './components/Login.vue'

      const routes [
        // ...
        { path: '/login', name: 'login', component: Login },
      ]
```

您可以通过在 URL 中使用`/login`路径打开应用程序来测试组件：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/5730642f-6612-40ca-8845-041eaa6f0b34.png)

目前，`FormInput`组件是只读的，因为当用户在字段中输入时，我们不做任何操作。

1.  让我们添加一个方法来处理这个问题：

```js
 methods: {
        update (event) {
          console.log(event.currentTarget.value)
        },
      },
```

1.  然后我们可以监听文本字段上的`input`事件：

```js
 @input="update"
```

现在，如果你在文本框中输入，内容应该会打印到控制台上。

1.  在`update`方法中，我们将发出一个事件来将新值发送到父组件。默认情况下，`v-model`指令监听`input`事件，新值是第一个参数：

```js
      methods: {
        update (event) {
          this.$emit('input', event.currentTarget.value)
        },
      },
```

为了理解事情是如何工作的，我们暂时不会使用`v-model`。

1.  我们现在可以监听`input`事件并更新`username`属性：

```js
      <FormInput
       name="username"
       :value="username"
       @input="val => username = val"
       placeholder="Username" />
```

`username`属性的值应该在`Login`组件上更新：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a4105d26-4d80-40f0-9e45-8e9b20793a4e.png)

1.  使用`v-model`指令，我们可以简化这段代码：

```js
      <FormInput
       name="username"
       v-model="username"
       placeholder="Username" />
```

它将使用`value`属性并为我们监听`input`事件！

# 自定义 v-model

默认情况下，`v-model`使用`value`属性和`input`事件，正如我们刚才看到的，但我们可以自定义：

1.  在`FormInput`组件内部，添加`model`选项：

```js
 model: {
       prop: 'text',
       event: 'update',
      },
```

1.  然后我们需要将我们的`value`属性的名称更改为`text`：

```js
      props: {
        // ...
        text: {
          required: true,
        },
      },
```

1.  在模板中：

```js
      <input
       ...
       :value="text"
       ... />
```

1.  另外，`input`事件应该被重命名为`update`：

```js
      this.$emit('update', event.currentTarget.value)
```

该组件应该仍然在`Login`组件中工作，因为我们告诉`v-model`使用`text`属性和`update`事件！

我们的输入组件现在已经准备好了！对于这个项目，我们将这个组件保持简单，但如果您愿意，您可以添加更多功能，比如图标、错误消息、浮动标签等。

# 登录组件

我们现在可以继续构建`Login`组件，该组件将负责登录和注册用户。

这个组件状态需要几个数据属性：

+   `模式`：这可以是`'login'`或`'signup'`。我们将根据此更改布局。

+   `用户名`：在两种模式下使用。

+   `密码`：也在两种模式下使用。

+   `password2`：用于在注册时验证密码。

+   电子邮件：用于注册模式。

1.  我们的`data`钩子现在应该是这样的：

```js
 data () {
        return {
          mode: 'login',
          username: '',
          password: '',
          password2: '',
          email: '',
        }
      },
```

1.  然后，我们可以添加一个`title`计算属性，根据模式更改表单标题：

```js
 computed: {
        title () {
          switch (this.mode) {
            case 'login': return 'Login'
            case 'signup': return 'Create a new account'
          }
        },
      },
```

我们还将添加一些基本的输入验证。首先，当重新输入的`密码`与第一个密码不相等时，我们希望突出显示它。

1.  让我们为此添加另一个计算属性：

```js
 retypePasswordError () {
        return this.password2 && this.password !== this.password2
      },
```

然后，我们还将检查没有字段为空，因为它们都是必填的。

1.  这次，我们将将其分解为两个计算属性，因为我们不希望在`login`模式下检查注册特定字段：

```js
 signupValid () {
        return this.password2 && this.email &&             
        !this.retypePasswordError
      },
      valid () {
        return this.username && this.password &&
        (this.mode !== 'signup' || this.signupValid)
      },
```

1.  接下来，添加我们将用于`登录`或`注册`用户的方法（我们将在*注册操作*和*登录操作*部分中稍后实现它们）：

```js
 methods: {
        async operation() {
          await this[this.mode]()
        },
        async login () {
          // TODO
        },
        async signup () {
          // TODO
        },
      }
```

1.  我们现在可以转到模板。首先添加一个`SmartForm`组件：

```js
      <template>
        <main class="login">
          <h1>Please login to continue</h1>
          <SmartForm
            class="form"
            :title="title"
            :operation="operation"
            :valid="valid">
            <!-- TODO -->
          </SmartForm>
        </main>
      </template>
```

1.  然后我们可以添加`input`字段：

```js
      <FormInput
        name="username"
        v-model="username"
        placeholder="Username" />
      <FormInput
        name="password"
        type="password"
        v-model="password"
        placeholder="Password" />
      <template v-if="mode === 'signup'">
        <FormInput
          name="verify-password"
          type="password"
          v-model="password2"
          placeholder="Retype Password"
          :invalid="retypePasswordError" />
        <FormInput
          name="email"
          type="email"
          v-model="email"
          placeholder="Email" />
      </template>
```

不要忘记`name`属性--它将允许浏览器自动完成字段。

1.  在`input`字段下面，我们需要两个不同的按钮，用于每种模式。对于登录模式，我们需要一个`注册`和`登录`按钮。对于`注册`模式，我们需要一个返回按钮和一个创建帐户按钮：

```js
      <template slot="actions">
        <template v-if="mode === 'login'">
          <button
            type="button"
            class="secondary"
            @click="mode = 'signup'">
            Sign up
          </button>
          <button
            type="submit"
            :disabled="!valid">
            Login
          </button>
        </template>
        <template v-else-if="mode === 'signup'">
          <button
            type="button"
            class="secondary"
            @click="mode = 'login'">
            Back to login
          </button>
          <button
            type="submit"
            :disabled="!valid">
            Create account
          </button>
        </template>
      </template>
```

现在您可以测试组件并在`登录`和`注册`模式之间切换：

！[](assets/472e2d84-4be7-41cf-b5dd-f4be4516d939.png)

# 样式作用域元素的子元素

表单目前占用了所有可用空间。最好将其缩小一点。

为了使本节起作用，您需要在项目中安装最新的`vue-loader`包。

让我们添加一些样式来给表单设置最大宽度：

```js
<style lang="stylus" scoped>
.form {
  >>> .content {
    max-width: 400px;
  }
}
</style>
```

`>>>`组合器允许我们定位模板中使用的组件内的元素，同时仍然限定其余的`CSS`选择器。在我们的示例中，生成的`CSS`将如下所示：

```js
.form[data-v-0e596401] .content {
  max-width: 400px;
}
```

如果我们没有使用这个组合器，我们将会有这个`CSS`：

```js
.form .content[data-v-0e596401] {
  max-width: 400px;
}
```

这不起作用，因为`.content`元素在我们在模板中使用的`SmartForm`组件内部。

如果您使用 SASS，则需要使用`/deep/`选择器而不是`>>>`组合器。

现在表单应该是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/1e6f948a-9608-463b-a8ba-db80dc50186a.png)

# 改进我们的 fetch 插件

目前，我们的`$fetch`方法只能向服务器发出`GET`请求。对于加载 FAQ 来说已经足够了，但现在我们需要为其添加更多功能：

1.  在`plugins/fetch.js`文件中，编辑函数的签名以接受一个新的`options`参数：

```js
      export async function $fetch (url, options) {
        // ...
      }
```

`options`参数是浏览器`fetch`方法的可选对象，它允许我们更改不同的参数，比如使用的 HTTP 方法，请求体等。

1.  在`$fetch`函数的开头，我们想为这个`options`参数设置一些默认值：

```js
      const finalOptions = Object.assign({}, {
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      }, options)
```

默认选项告诉服务器我们将始终在请求体中发送 JSON，并告诉浏览器，如果用户已登录，我们还将包括必要的授权令牌。然后，如果有提供`options`参数，将其值添加到`finalOptions`对象中（例如`method`属性或`body`属性）。

1.  接下来，我们将新的选项添加到`fetch`浏览器方法中：

```js
      const response = await fetch(`${baseUrl}${url}`, finalOptions)
```

1.  此外，服务器将始终以文本形式发送错误，因此我们可以捕获并向用户显示它们：

```js
      if (response.ok) {
        const data = await response.json()
        return data
      } else {
        const message = await response.text()
 const error = new Error(message)
 error.response = response
        throw error
      }
```

现在我们准备向服务器发出第一个`POST`请求，以为用户创建一个新帐户，然后登录！

# 注册操作

我们将从帐户创建开始，因为我们还没有任何用户。在服务器上调用的路径是`/signup`，它期望一个带有新帐户的用户名、密码和电子邮件的 JSON 对象的`POST`请求：

让我们使用我们刚刚改进的`$fetch`方法来实现这一点：

```js
async signup () {
  await this.$fetch('signup', {
    method: 'POST',
    body: JSON.stringify({
      username: this.username,
      password: this.password,
      email: this.email,
    }),
  })
  this.mode = 'login'
},
```

我们不在这里处理错误，因为这是我们之前构建的`SmartForm`组件的工作。

就是这样！现在您可以使用一个简单的`密码`创建一个新帐户，以便以后记住。如果帐户创建成功，表单将返回到`登录`模式。

这里我们没有做的一件事是让用户知道他们的帐户已经创建，他们现在可以登录。您可以在表单下方添加一条消息，甚至让浮动通知出现！

# 登录操作

登录方法几乎与注册相同。区别在于：

+   我们只在请求体中发送`username`和`password`到`/login`路径

+   响应是我们需要设置到全局状态中的用户对象，以便每个组件都可以知道是否有连接的用户（使用我们制作的插件暴露的`$state`属性）

+   然后重定向到主页

现在它应该是这样的：

```js
async login () {
  this.$state.user = await this.$fetch('login', {
    method: 'POST',
    body: JSON.stringify({
      username: this.username,
      password: this.password,
    }),
  })
  this.$router.push({ name: 'home' })
},
```

您现在可以尝试使用之前用来创建帐户的`用户名`和`密码`进行登录。如果登录成功，您应该通过`router.push()`方法被重定向到主页。

此请求返回的`user`对象包含将显示在导航菜单中的`username`字段。

# 用户菜单

现在是时候将与用户相关的功能添加到我们在`NavMenu.vue`文件开头制作的导航菜单中了：

1.  我们希望它们出现在菜单的最右侧，因此我们将在我们已经编写的路由链接之后添加这个元素：

```js
      <div class="spacer"></div>
```

这将简单地扩展以占用菜单中所有可用的空间，使用 CSS flexbox 属性，这样我们放在后面的任何东西都会被推到右边。

由于我们在*将用户存储在集中状态*部分中制作的插件，我们可以通过`$state`属性访问全局状态。它包含`user`对象，允许我们知道用户是否已登录，并显示他们的`username`和`logout`链接。

1.  在`NavMenu.vue`组件中添加用户菜单：

```js
      <template v-if="$state.user">
        <a>{{ $state.user.username }}</a>
        <a @click="logout">Logout</a>
      </template>
```

1.  如果用户未连接，我们只显示一个`登录`链接（在我们刚刚添加的`template`下面添加这个）：

```js
      <router-link v-else :to="{name: 'login'}">Login</router-link>
```

`logout`链接需要一个新的`logout`方法，我们现在将创建它。

# 登出方法

登出方法包括简单地调用服务器上的`/logout`路径，该路径应返回一个带有`status`属性等于`'ok'`的对象：

```js
<script>
export default {
  methods: {
    async logout () {
      const result = await this.$fetch('logout')
      if (result.status === 'ok') {
        this.$state.user = null
      }
    },
  },
}
</script>
```

如果用户成功登出，我们会重置全局状态中的`user`值。

# 带有导航守卫的私有路由

现在我们已经准备好认证系统，我们可以有不同类型的路由：

+   公共路由始终可访问

+   私有路由仅限于已登录用户

+   访客路由仅对尚未连接的用户可访问

我们将提前创建一个路由组件来测试我们的代码：

1.  让我们创建`TicketsLayout.vue`组件，稍后我们将用它来显示用户支持票据：

```js
      <template>
        <main class="tickets-layout">
          <h1>Your Support tickets</h1>
          <!-- TODO -->
        </main>
      </template>
```

1.  然后，在`router.js`文件中添加相应的路由：

```js
      import TicketsLayout from './components/TicketsLayout.vue'

      const routes = [
        // ...
        { path: '/tickets', name: 'tickets',
 component: TicketsLayout },
      ]
```

1.  最后，在导航菜单中添加到这个新页面的链接：

```js
      <router-link :to="{ name: 'tickets' }">
        Support tickets</router-link>
```

# 路由元属性

我们可以在`router.js`文件中的受影响路由的`meta`对象中添加页面访问类型信息。

我们刚刚创建的路由应该是私有的，只能由已连接的用户访问：

+   在路由上的`meta`对象中添加`private`属性：

```js
      { path: '/tickets', /* ... */, meta: { private: true } },
```

现在，如果您转到票务页面并检查任何组件，您应该看到`vue-router`插件公开的`$route`对象。它在`meta`对象中包含`private`属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/febb8fe5-3e14-4956-a451-eb4cbd4a167f.png)您可以在路由的`meta`对象中放入任何额外的信息，以扩展路由器的功能。

# 路由器导航守卫

现在我们知道票务路线是私人的，我们想在路线解析之前执行一些逻辑，以检查用户是否已连接。这就是导航守卫派上用场的地方--它们是在路由方面发生某些事情时调用的函数钩子，它们可以改变路由器的行为。

我们需要的导航守卫是`beforeEach`，它在每次解析路由之前运行。它允许我们根据需要替换目标路由。它接受一个带有三个参数的回调函数：

+   `to`是当前正在定位的路由

+   `from`是上一个路由

+   `next`是一个我们必须在某个时候调用以便解析继续进行的函数

如果您忘记在导航守卫中调用`next`，您的应用程序将会被卡住。这是因为您可以在调用它之前执行异步操作，所以路由器不会自行做出任何假设。

1.  在导出路由实例之前，在`router.js`文件中添加`beforeEach`导航守卫：

```js
      router.beforeEach((to, from, next) => {
        // TODO
        console.log('to', to.name)
        next()
      })
```

1.  现在我们需要确定我们要定位的路由是否是私有路由：

```js
      if (to.meta.private) {
        // TODO Redirect to login
      }
```

1.  要检查用户是否已连接，我们需要全局状态--您可以在文件开头导入它：

```js
      import state from './state'
```

1.  更改条件以检查用户状态：

```js
      if (to.meta.private && !state.user) {
        // TODO Redirect to login
      }
```

下一个函数可以使用路由参数调用，将导航重定向到另一个路由。

1.  因此，在这里，我们可以像使用`router.push()`方法一样重定向到登录路由：

```js
      if (to.meta.private && !state.user) {
        next({ name: 'login' })
 return
      }
```

不要忘记返回，否则您将在函数结束时第二次调用`next`！

现在我们可以尝试注销并点击支持票链接。您应该立即被重定向到登录页面。

使用`next`重定向时，每次重定向都不会向浏览器历史记录中添加额外的条目。只有最终路由有历史记录条目。

正如您在浏览器控制台中所看到的，每次我们尝试解析到一个路由时，导航守卫都会被调用：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/a7f7d374-8b84-4412-80d1-1b21b70356ef.png)

这就解释了为什么这个函数被称为 `next`--解析过程将继续，直到我们不再重定向到另一个路由。

这意味着导航守卫可以被多次调用，但这也意味着您应该小心，不要创建无限的解析“循环”！

# 重定向到想要的路由

用户登录后，应用程序应将其重定向到他们最初想要浏览的页面：

1.  将当前想要的 URL 作为参数传递给登录路由：

```js
      next({
        name: 'login',
        params: {
          wantedRoute: to.fullPath,
        },
      })
```

现在，如果您单击支持票链接并被重定向到登录页面，您应该在任何组件的 `$route` 对象中看到 `wantedRoute` 参数：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/d3bca6d2-077c-46fd-a9b6-f5c59b653462.png)

1.  在 `Login` 组件中，我们可以在 `login` 方法中更改重定向，并使用此参数：

```js
      this.$router.replace(this.$route.params.wantedRoute ||
        { name: 'home' })
```

`router.replace()` 方法与 `router.push()` 方法非常相似，不同之处在于它用新路由替换浏览器历史记录中的当前条目，而不是添加新条目。

现在，如果您登录，应该被重定向到支持票务页面，而不是主页。

# 初始化用户身份验证

当页面加载和应用程序启动时，我们需要检查用户是否已连接。出于这个原因，服务器有一个 `/user` 路径，如果用户已登录，则返回用户对象。我们将把它放在全局状态中，就像我们已经登录一样。然后，我们将启动 Vue 应用程序：

1.  在 `main.js` 文件中，从我们的插件中导入 `$fetch`：

```js
      import VueFetch, { $fetch } from './plugins/fetch'
```

1.  然后，我们需要创建一个名为 `main` 的新异步函数，在其中我们将请求用户数据，然后启动应用程序：

```js
      async function main () {
        // Get user info
        try {
          state.user = await $fetch('user')
        } catch (e) {
          console.warn(e)
        }
        // Launch app
        new Vue({
          el: '#app',
          data: state,
          router,
          render: h => h(AppLayout),
        })
      }

      main()
```

现在，如果您登录然后刷新页面，您仍然应该保持连接！

# 访客路由

还有另一种情况我们尚未处理--我们不希望已连接的用户访问登录路由！

1.  这就是为什么我们将其标记为访客路由的原因：

```js
      { path: '/login', name: 'login', component: Login,
        meta: { guest: true } },
```

1.  在 `beforeEach` 导航守卫中，我们将检查路由是否仅限访客，以及用户是否已连接，然后重定向到主页：

```js
      router.beforeEach((to, from, next) => {
        // ...
        if (to.meta.guest && state.user) {
          next({ name: 'home' })
          return
        }
        next()
      })
```

如果您已登录，可以尝试转到登录 URL--您应该立即被重定向到主页！只有在未登录时才能访问此页面。

# 显示和添加票务

在本节中，我们将向应用程序添加票务支持内容。首先我们将显示它们，然后构建一个表单让用户创建新的票务。我们将为此创建两个组件，嵌套在我们之前创建的`TicketsLayout`组件中。

不用担心！当您创建您的账户时，一个示例支持票务会自动为您的用户创建。

# 票务列表

可以在服务器上的`/tickets`请求票务：

1.  创建一个新的`Tickets.vue`组件，它将与 FAQ 组件非常相似。

1.  使用`RemoteData` mixin 来获取票务：

```js
      <script>
      import RemoteData from '../mixins/RemoteData'

      export default {
        mixins: [
          RemoteData({
            tickets: 'tickets',
          }),
        ],
      }
      </script>
```

1.  然后添加一个带有加载动画、空消息和票务列表的模板：

```js
      <template>
        <div class="tickets">
          <Loading v-if="remoteDataBusy"/>

          <div class="empty" v-else-if="tickets.length === 0">
            You don't have any ticket yet.
          </div>

          <section v-else class="tickets-list">
            <div v-for="ticket of tickets" class="ticket-item">
              <span>{{ ticket.title }}</span>
              <span class="badge">{{ ticket.status }}</span>
              <span class="date">{{ ticket.date }}</span>
            </div>
          </section>
        </div>
      </template>
```

我们需要一个过滤器来显示票务日期！

1.  终止客户端编译，并使用以下命令安装`momentjs`：

```js
 npm install --save moment
```

1.  在`main.js`文件旁边创建一个新的`filters.js`文件，其中包含一个`date`过滤器：

```js
      import moment from 'moment'

      export function date (value) {
        return moment(value).format('L')
      }
```

1.  然后在`main.js`中，导入`filters`并使用一个方便的循环进行注册：

```js
      import * as filters from './filters'

      for (const key in filters) {
        Vue.filter(key, filters[key])
      }
```

1.  现在我们可以在`Tickets`组件中以更加人性化的方式显示日期：

```js
      <span class="date">{{ ticket.date | date }}</span>
```

然后将这个新组件添加到`TicketsLayout`组件中并获取票务列表：

！[](assets/32ded18f-6a20-4a04-a4d2-8e5af3f44dd2.png)

不要忘记导入`Tickets`并将其设置在`components`选项中！

# 会话过期

一段时间后，用户会话可能会变得无效。这可能是因为定时到期（对于这个服务器，设置为三个小时），或者仅仅是因为服务器重新启动。让我们尝试重现这种情况--我们将重新启动服务器并尝试再次加载票务：

1.  确保您已登录到应用程序中。

1.  在运行服务器的终端中键入`rs`，然后按`Return`键以重新启动它。

1.  在应用程序中点击主页按钮。

1.  点击支持票务按钮返回到票务列表页面。

您应该在控制台中看到一个卡住的加载动画和一个错误消息：

！[](assets/a356239a-cb14-4919-82be-6145adbf8c1d.png)

服务器返回了未经授权的错误--这是因为我们已经退出登录了！

为了解决这个问题，如果我们在私人路线上，我们需要注销用户并将其重定向到登录页面。

放置我们代码的最佳位置是`plugins/fetch.js`文件中的所有组件中使用的`$fetch`方法。当尝试访问连接用户限制的路径时，服务器将始终返回 403 错误。

1.  在修改方法之前，我们需要导入状态和路由：

```js
      import state from '../state'
      import router from '../router'
```

1.  让我们在响应处理中添加一个新的情况：

```js
      if (response.ok) {
        // ...
      } else if (response.status === 403) {
        // If the session is no longer valid
        // We logout
        state.user = null

        // If the route is private
        // We go to the login screen
        if (router.currentRoute.matched.some(r => r.meta.private)) {
          router.replace({ name: 'login', params: {
            wantedRoute: router.currentRoute.fullPath,
          }})
        }
      } else {
        // ...
      }
```

我们使用`replace`方法而不是`push`，因为我们不希望在浏览器历史记录中创建新的导航。想象一下，如果用户单击返回按钮，它将再次重定向到登录页面，用户将无法返回到私人页面之前的页面。

现在您可以再试一次--当您重新启动服务器并单击支持票务链接时，您应该会被重定向到登录页面，并且导航菜单不应再显示您的用户名。

# 嵌套路由

由于我们还想在此页面切换到一个表单，因此将组件结构化为嵌套路由是一个好主意--如果至少有一个路由视图，每个路由都可以有子路由！因此，在`/tickets`路由器下，我们现在将有两个子路由：

+   `''`将是票务列表（完整路径将是`/tickets/`）。它就像是`/tickets`下的默认路由。

+   `'/new'`将是发送新票务的表单（完整路径将是`/tickets/new/`）。

1.  创建一个临时模板的新`NewTicket.vue`组件：

```js
      <template>
        <div class="new-ticket">
          <h1>New ticket</h1>
        </div>
      </template>
```

1.  在`routes.js`文件中，在`children`属性下的`/tickets`路由下添加两个新路由：

```js
      import Tickets from './components/Tickets.vue'
      import NewTicket from './components/NewTicket.vue'

      const routes = [
        // ...
        { path: '/tickets', component: TicketsLayout,
          meta: { private: true }, children: [
          { path: '', name: 'tickets', component: Tickets },
          { path: 'new', name: 'new-ticket', component: NewTicket },
        ] },
      ]
```

由于第一个子路由是空字符串，当解析父路由时它将成为默认路由。这意味着您应该将路由的名称（`'tickets'`）从父级移到它。

1.  最后，我们可以更改`TicketsLayout`组件，使用路由器视图以及一些按钮在子路由之间切换：

```js
      <template>
        <main class="tickets-layout">
          <h1>Your Support tickets</h1>

          <div class="actions">
            <router-link
              v-if="$route.name !== 'tickets'"
              tag="button"
              class="secondary"
              :to="{name: 'tickets'}">
              See all tickets
            </router-link>
            <router-link
              v-if="$route.name !== 'new-ticket'"
              tag="button"
              :to="{name: 'new-ticket'}">
              New ticket
            </router-link>
          </div>

          <router-view />
        </main>
      </template>
```

您可以在路由链接上使用`tag`属性来更改用于呈现它的 HTML 标签。

正如您所看到的，我们根据当前路由名称隐藏每个按钮--当我们已经在票务页面时，我们不希望显示显示票务按钮，当我们已经在相应的表单上时，我们也不希望显示新票务按钮！

现在您可以在两个子路由之间切换，并相应地看到 URL 更改：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/cf2479f9-c46e-42fc-a2b5-19b470ea7f57.png)

# 修复我们的导航守卫

如果您注销然后转到票务页面，您应该会惊讶地发现能够访问该页面！这是因为我们的`beforeEach`导航守卫实现存在缺陷--我们设计不当，没有考虑到可能存在嵌套路由！出现这个问题的原因是`to`参数只是目标路由，即`/tickets`路由的第一个子路由--它没有`private`元属性！

因此，我们不应该仅仅依赖于目标路由，还应该检查所有匹配的嵌套路由对象。幸运的是，每个路由对象都可以通过`matched`属性让我们访问这些路由对象的列表。然后我们可以使用`some`数组方法来验证是否至少有一个路由对象具有所需的 meta 属性。

我们可以在`router.js`文件中的`beforeEach`导航守卫中将条件代码更改为这样：

```js
router.beforeEach((to, from, next) => {
  if (to.matched.some(r => r.meta.private) && !state.user) {
    // ...
  }
  if (to.matched.some(r => r.meta.guest) && state.user) {
    // ...
  }
  next()
})
```

现在我们的代码可以在任意嵌套路由的情况下工作了！

强烈建议每次都使用`matched`属性来避免错误。

# 发送表单

在这一部分，我们将完成`NewTicket`组件，允许用户发送新的支持票。我们需要两个字段来创建一个新的票--`title`和`description`：

1.  在`NewTicket.vue`组件的模板中，我们已经可以添加一个标题为`InputForm`的`SmartForm`组件：

```js
      <SmartForm
       title="New ticket"      
       :operation="operation"
       :valid="valid">
        <FormInput
          name="title"
          v-model="title"
          placeholder="Short description (max 100 chars)"
          maxlength="100"
          required/>
      </SmartForm>
```

1.  我们还可以添加两个数据属性，`operation`方法和一些输入验证，使用`valid`计算属性：

```js
      <script>
      export default {
        data () {
          return {
            title: '',
            description: '',
          }
        },

        computed: {
          valid () {
            return !!this.title && !!this.description
          },
        },

        methods: {
          async operation () {
            // TODO
          },
        },
      }
      </script>
```

# 表单文本框

对于`description`字段，我们需要一个`<textarea>`元素，这样用户就可以编写多行文本。不幸的是，我们的`FormInput`组件还不支持这一点，所以我们需要稍微修改一下。我们将使用组件的`type`prop，值为`'textarea'`来将`<input>`元素更改为`<textarea>`元素：

1.  让我们创建一个新的计算属性来确定我们将要渲染哪种 HTML 元素：

```js
      computed: {
        // ...
        element () {
          return this.type === 'textarea' ? this.type : 'input'
        },
      },
```

当传递值`'textarea'`时，我们需要渲染一个`<textarea>`。所有其他类型都会使组件渲染一个`<input>`元素。

现在我们可以使用特殊的`<component>`组件，它可以根据`is`属性渲染元素，而不是静态的`<input>`元素。

1.  模板中的这一行现在应该是这样的：

```js
      <component
        :is="element"
        class="input"
        :class="inputClass"
        :name="name"
        :type="type"
        :value.prop="text"
        @input="update"
        :placeholder="placeholder"
      />
```

1.  现在我们可以在`NewTicket`表单中添加`description`文本框，就在`title`输入框之后：

```js
      <FormInput
        type="textarea"
        name="description"
        v-model="description"
        placeholder="Describe your problem in details"/>
```

# 绑定属性

除了其他元素，`<textarea>`有一些方便的属性，我们想要使用，比如`rows`属性。我们可以为每个属性创建一个 prop，但这可能会很快变得乏味。相反，我们将使用 Vue 组件的特殊`$attrs`属性，它将所有设置在组件上的非 prop 属性作为一个对象获取，键是属性的名称。

这意味着如果你在组件上有一个`text`prop，然后在另一个组件中写入这样的内容：

```js
<FormInput :text="username" required>
```

Vue 将把`required`视为属性，因为它不在`FormInput`组件公开的 props 列表中。然后您可以使用`$attrs.required`访问它！

`v-bind`指令可以获取一个对象，其中键是要设置的 props 和属性的名称。这将非常有用！

1.  我们可以在`FormInput.vue`组件中的`<component>`上写入这个：

```js
      <component
        ...
        v-bind="$attrs" />
```

1.  现在可以在`NewTicket.vue`组件的`description`输入上添加`rows`属性：

```js
      <FormInput
        ...
        rows="4"/>
```

您应该在渲染的 HTML 中看到该属性已设置在`FormInput`组件内的`<textarea>`元素上：

```js
<textarea data-v-ae2eb904="" type="textarea" placeholder="Describe your problem in details" rows="4" class="input"></textarea>
```

# 用户操作

现在我们将实现用户在表单中可以执行的几个操作：

1.  在`SmarForm`组件中，在输入框后添加这两个按钮：

```js
      <template slot="actions">
        <router-link
          tag="button"
          :to="{name: 'tickets'}"
          class="secondary">
          Go back
        </router-link>
        <button
          type="submit"
          :disabled="!valid">
          Send ticket
        </button>
      </template>
```

1.  然后实现`operation`方法，这将类似于我们在`Login`组件中所做的。我们需要将`POST`请求发送到的服务器路径是`/tickets/new`：

```js
      async operation () {
        const result = await this.$fetch('tickets/new', {
          method: 'POST',
          body: JSON.stringify({
            title: this.title,
            description: this.description,
          }),
        })
        this.title = this.description = ''
      },
```

现在可以创建新的票！

# 备份用户输入

为了改善用户体验，我们应该自动备份用户在表单中输入的内容，以防出现问题--例如，浏览器可能会崩溃，或者用户可能会意外刷新页面。

我们将编写一个 mixin，它将自动将一些数据属性保存到浏览器本地存储中，并在组件创建时恢复它们：

1.  在`mixins`文件夹中创建一个新的`PersistantData.js`文件。

1.  与我们之前做的另一个 mixin 一样，它将具有一些参数，因此我们需要将其导出为一个函数：

```js
      export default function (id, fields) {
        // TODO
      }
```

`id`参数是用来存储这个特定组件数据的唯一标识符。

首先，我们将监视 mixin 中传递的所有字段。

1.  为此，我们将动态创建`watch`对象，每个键都是字段，值是将值保存到本地存储的处理程序函数：

```js
      return {
        watch: fields.reduce((obj, field) => {
          // Watch handler
          obj[field] = function (val) {
            localStorage.setItem(`${id}.${field}`, JSON.stringify(val))
          }
          return obj
        }, {}),
      }
```

1.  返回`NewTicket`组件并添加 mixin：

```js
      import PersistantData from '../mixins/PersistantData'

      export default {
        mixins: [
          PersistantData('NewTicket', [
            'title',
            'description',
          ]),
        ],

       // ...
      }
```

因此，mixin 为组件添加了观察者，`reduce`生成了相当于这个的等价物：

```js
{
  watch: {
    title: function (val) {
      let field = 'title'
      localStorage.setItem(`${id}.${field}`, JSON.stringify(val))
    },
    description: function (val) {
      let field = 'description'
      localStorage.setItem(`${id}.${field}`, JSON.stringify(val))
    },
  },
}
```

我们将属性值保存为 JSON，因为本地存储只支持字符串。

您可以尝试在字段中输入，然后查看浏览器开发工具，看到已保存了两个新的本地存储项：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/f2105df0-659f-4c82-8e3f-71c21eb1e58c.png)

1.  在 mixin 中，当组件被销毁时，我们还可以保存字段：

```js
 methods: {
        saveAllPersistantData () {
          for (const field of fields) {
            localStorage.setItem(`${id}.${field}`,             
            JSON.stringify(this.$data[field]))
          }
        },
      },
      beforeDestroy () {
        this.saveAllPersistantData()
      },
```

1.  最后，我们需要在组件创建时恢复这些值：

```js
 created () {
        for (const field of fields) {
          const savedValue = localStorage.getItem(`${id}.${field}`)
          if (savedValue !== null) {
            this.$data[field] = JSON.parse(savedValue)
          }
        }
      },
```

现在，如果你在表单中输入一些内容，然后刷新页面，你输入的内容应该仍然在表单中！

通过我们添加到`$fetch`的会话过期管理，如果您在不再连接的情况下尝试发送新票务，您将被重定向到登录页面。然后，一旦您再次登录，您应该回到表单，并且您输入的内容仍然存在！

# 高级路由功能

这是本章的最后一节，我们将更深入地探讨路由！

# 带参数的动态路由

我们将在应用程序中添加的最后一个组件是`Ticket`，它通过其 ID 显示一个票务的详细视图。它将显示用户输入的标题和描述，以及日期和状态。

1.  创建一个新的`Ticket.vue`文件，并添加这个模板，其中包括通常的加载动画和`未找到`提示：

```js
      <template>
        <div class="ticket">
          <h2>Ticket</h2>

          <Loading v-if="remoteDataBusy"/>

          <div class="empty" v-else-if="!ticket">
            Ticket not found.
          </div>

          <template v-else>
            <!-- General info -->
            <section class="infos">
              <div class="info">
                Created on <strong>{{ ticket.date | date }}</strong>
              </div>
              <div class="info">
                Author <strong>{{ ticket.user.username }}</strong>
              </div>
              <div class="info">
                Status <span class="badge">{{ ticket.status }}</span>
              </div>
            </section>
            <!-- Content -->
            <section class="content">
              <h3>{{ ticket.title }}</h3>
              <p>{{ ticket.description }}</p>
            </section>
          </template>
        </div>
      </template>
```

1.  然后在组件中添加一个`id` prop：

```js
      <script>
      export default {
        props: {
          id: {
            type: String,
            required: true,
          },
        },
      }
      </script>
```

# 动态远程数据

`id` prop 将是我们将获取详细信息的票务的 ID。服务器以`/ticket/<id>`的形式提供动态路由，其中`<id>`是票务的 ID。

能够使用我们的`RemoteData` mixin 会很好，但它目前不支持动态路径！我们可以做的是将函数传递给 mixin 参数的值，而不是普通的字符串：

1.  在`RemoteData` mixin 中，我们只需要修改`created`钩子中处理参数的方式。如果值是一个函数，我们将使用`$watch`方法来观察它的值，而不是直接调用`fetchResource`方法：

```js
      created () {
        for (const key in resources) {
          let url = resources[key]
          // If the value is a function
          // We watch its result
          if (typeof url === 'function') {
            this.$watch(url, (val) => {
              this.fetchResource(key, val)
            }, {
              immediate: true,
            })
          } else {
            this.fetchResource(key, url)
          }
        }
      },
```

不要忘记在观察者中添加`immediate: true`选项，因为我们希望在观察值之前首先调用`fetchResource`方法。

1.  在`Ticket`组件中，我们现在可以使用这个 mixin 根据`id` prop 加载票务数据：

```js
      import RemoteData from '../mixins/RemoteData'

      export default {
        mixins: [
          RemoteData({
            ticket () {
              return `ticket/${this.id}`
            },
          }),
        ],
        // ...
      }
```

让我们在`Tickets`组件中尝试这个。

1.  将新的`Ticket`组件添加到其中，并添加一个新的`id`数据属性：

```js
      import Ticket from './Ticket.vue'

      export default {
        //...
        components: {
          Ticket,
        },
        data () {
          return {
            id: null,
          }
        },
      }
```

1.  然后在模板中添加一个`Ticket`组件：

```js
      <Ticket v-if="id" :id="id"/>
```

1.  在票务列表中，将标题更改为在`click`事件上设置`id`数据属性的链接：

```js
      <a @click="id = ticket._id">{{ ticket.title }}</a>
```

如果你在应用程序中点击票务，你应该能够在下面的列表中看到详细信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/291c8703-598a-43a2-b94e-af8a7c2de73e.png)

# 动态路由

由于我们将在另一个路由中放置票务详情，你可以撤消我们在`Tickets`组件中刚刚做的事情。

该路由将是票务路线的子路线，并且将采用`/tickets/<id>`的形式，其中`<id>`是正在显示的票的 ID。这要归功于 vue-router 的动态路由匹配功能！

您可以使用分号将动态段添加到路由路径中。然后，每个段都将暴露在路由`params`对象中。以下是一些带参数的路由示例：

| 模式 | 示例路径 | `$route.params`值 |
| --- | --- | --- |
| `/tickets/:id` | `/tickets/abc` | `{ id: 'abc' }` |
| `/tickets/:id/comments/:comId` | `/tickets/abc/comments/42` | `{ id: 'abc', comId: '42' }` |

1.  让我们将新路由添加到`router.js`文件中，作为`/tickets`的子路由：

```js
      import Ticket from './components/Ticket.vue'

      const routes = [
        // ...
        { path: '/tickets', component: TicketsLayout,
          meta: { private: true }, children: [
          // ...
          { path: ':id', name: 'ticket', component: Ticket },
        ] },
      ]
```

1.  在`Tickets`组件列表中，我们需要将标题元素更改为指向新路由的链接：

```js
<router-link :to="{name: 'ticket', params: { id: ticket._id }}">        {{ ticket.title }}</router-link>
```

现在，如果您点击一张票，`$route.params`对象将具有`id`属性设置为票的 ID。

我们可以更改我们的`Ticket`组件，使用计算属性而不是 prop：

```js
computed: {
  id () {
    return $route.params.id
  },
},
```

但这是一个坏主意--我们正在将组件与路由耦合！这意味着我们将无法轻松地以另一种方式重用它。最佳实践是使用 props 将信息传递给组件，所以让我们继续这样做！

1.  因此，我们将保留`Ticket`组件的 ID 属性，并告诉`vue-router`将所有路由参数作为带有`props`属性的 prop 传递给它：

```js
      { path: ':id', /* ... */, props: true },
```

这相当于基于函数的更灵活的语法，该函数将路由对象作为参数：

```js
{ path: ':id', /* ... */, props: route => ({ id: route.params.id }) },
```

还有一种基于对象的语法也存在（当 props 是静态的时候很有用）：

```js
{ path: ':id', /* ... */, props: { id: 'abc' } },
```

我们不会使用这种第三种语法，因为我们的`id` prop 应该等于路由的动态参数。

如果您需要组合静态和动态 props，请使用函数语法！如果路由参数和组件 props 名称不匹配，这也很有用。

现在，`id`参数作为 prop 传递给组件，当在列表中点击票时，您应该看到票的详细信息页面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/bbad02ee-1190-4f86-9416-dafa76a361f7.png)

# 未找到页面

目前，如果您在应用程序中输入无效的 URL，您将看到一个无聊的空白页面。这是`vue-router`的默认行为，但幸运的是它可以更改！我们现在将自定义我们应用程序的“未找到”页面！

1.  让我们创建一个更好的“未找到”页面，使用一个新的`NotFound.vue`组件：

```js
      <template>
        <main class="not-found">
          <h1>This page can't be found</h1>
          <p class="more-info">
            Sorry, but we can't find the page you're looking for.<br>
            It might have been moved or deleted.<br>
            Check your spelling or click below to return to the                           
            homepage.
          </p>
          <div class="actions">
            <router-link tag="button" :to="{name: 'home'}">Return to             
            home</router-link>
          </div>
        </main>
      </template>

      <style lang="stylus" scoped>
      .more-info {
        text-align: center;
      }
      </style>
```

1.  现在在`router.js`文件中，我们只需要添加一个匹配`'*'`路径的新路由：

```js
      import NotFound from './components/NotFound.vue'

      const routes = [
        // ...
        { path: '*', component: NotFound },
      ]
```

这意味着对于任何路由，我们都会显示`NotFound`组件。非常重要的事实是，我们将这个路由放在`routes`数组的末尾 - 这确保在匹配这个最后一个特定的捕获所有路由之前，所有合法的路由都会被匹配。

您现在可以尝试一个不存在的 URL，比如`/foo`，来显示页面：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-web-dev-pj/img/343904f2-8f5a-4a56-9b8b-c20d75db9122.png)

# 过渡

路由变化的动画非常容易 - 这与我们以前做的方式完全相同：

+   在`AppLayout`组件中，用这个过渡包装路由视图：

```js
      <transition name="fade" mode="out-in">
        <router-view />
      </transition>
```

`router-view`特殊组件将被路由的不同组件替换，从而触发过渡。

# 滚动行为

路由器的历史模式允许我们在路由更改时管理页面滚动。我们可以每次重置位置到顶部，或者在更改路由之前恢复用户之前的位置（当他们在浏览器中返回时非常有用）。

在创建路由器实例时，我们可以传递一个`scrollBehavior`函数，该函数将获得三个参数：

+   `to`是目标路由对象。

+   `from`是先前的路由对象。

+   `savedPosition`是为浏览器历史记录中的每个条目自动保存的滚动位置。直到路由更改之前，每个新条目都不会有这个。

`scrollBehavior`函数期望一个可以采用两种不同形式的对象。第一个是我们想应用的滚动的坐标；例如：

```js
{ x: 100, y: 200 }
```

第二个是我们要滚动到的 HTML 元素的选择器，带有可选的偏移量：

```js
{ selector: '#foo', offset: { x: 0, y: 200 } }
```

1.  因此，当路由更改时滚动到页面顶部，我们需要编写这样的代码：

```js
      const router = new VueRouter({
        routes,
        mode: 'history',
        scrollBehavior (to, from, savedPosition) {
          return { x: 0, y: 0 }
        },
      })
```

要每次滚动到`<h1>`元素，我们可以这样做：

```js
return { selector: 'h1' }
```

1.  相反，我们将检查路由是否有哈希来模仿浏览器的行为：

```js
      if (to.hash) {
        return { selector: to.hash }
      }
      return { x: 0, y: 0 }
```

1.  最后，如果有滚动位置，我们可以恢复滚动位置：

```js
 if (savedPosition) {
 return savedPosition
 }
      if (to.hash) {
        return { selector: to.hash }
      }
      return { x: 0, y: 0 }
```

就是这么简单！现在应用程序应该像一个旧的多页面网站一样运行。然后，您可以使用偏移或路由元属性来自定义滚动行为的方式。

# 总结

在本章中，我们借助 Vue 和官方的`vue-router`库创建了一个相当大的应用程序。我们创建了一些路由，并用链接将它们连接起来，形成了一个真正的导航菜单。然后，我们创建了一个通用且可重用的组件来构建应用程序表单，这帮助我们创建了登录和注册表单。然后，我们将用户认证系统与路由器集成，这样我们的应用程序就可以智能地对页面刷新或会话过期做出反应。最后，我们深入了解了`vue-router`的功能和能力，以进一步增强我们的应用程序和用户体验。

我们已经完成了这个应用，但请随意对其进行改进！以下是一些你可以实现的想法：

+   为工单添加评论。显示评论列表，并显示对应用户的名称。

+   添加关闭此工单按钮，防止用户添加新评论。

+   在工单列表中，为已关闭的工单旁边显示一个特殊图标！

+   给用户添加角色。例如，普通用户可以打开工单，但只有管理员用户可以关闭工单。

在下一章中，我们将创建一个地理定位的博客应用程序，并学习如何通过集中式状态解决方案扩展我们的应用程序，并集成第三方库以扩展 Vue 的功能。
