# Vue3 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C`](https://zh.annas-archive.org/md5/915E62C558C25E5846A894A1C2157B6C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用过渡和 CSS 为您的应用程序添加动画

为了使应用程序更加动态并吸引用户的全部注意力，使用动画是至关重要的。如今，CSS 动画出现在提示、横幅、通知甚至输入字段中。

有些情况下，您需要创建特殊的动画，称为过渡，并完全控制页面上发生的事情。为此，您必须使用自定义组件，并让框架帮助您渲染应用程序。

使用 Vue，我们可以使用两个自定义组件来帮助我们在应用程序中创建动画和过渡，这些组件是`Transition`和`TransitionGroup`。

在这一章中，我们将学习如何创建 CSS 动画，使用 Animate.css 框架创建自定义过渡，使用`Transition`组件钩子执行自定义函数，创建在组件渲染时执行的动画，为组和列表创建动画和过渡，创建可重用的自定义过渡组件，并在组件之间创建无缝过渡。

在这一章中，我们将涵盖以下内容：

+   创建你的第一个 CSS 动画

+   使用 Animate.css 创建自定义过渡类

+   使用自定义钩子创建交易

+   在页面渲染时创建动画

+   为列表和组创建动画

+   创建自定义过渡组件

+   在元素之间创建无缝过渡

# 技术要求

在这一章中，我们将使用**Node.js**和**Vue-CLI**。

注意 Windows 用户！您需要安装一个名为`windows-build-tools`的 NPM 包，以便能够安装以下所需的包。为此，请以管理员身份打开 PowerShell 并执行

`> npm install -g windows-build-tools` 命令。

要安装**Vue-CLI**，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

## 创建基础项目

在这一章中，我们将使用此项目作为每个配方的基础。在这里，我将指导您如何创建基础项目：

1.  打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create {replace-with-recipe-name}
```

1.  Vue-CLI 将要求您选择预设；使用*空格键*选择`手动选择功能`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ **Manually select features**
```

1.  现在，Vue-CLI 将询问您希望安装哪些功能。您需要选择`CSS 预处理器`作为默认功能之外的附加功能：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex ❯ CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  继续这个过程，选择一个 linter 和 formatter。在我们的情况下，我们将选择“ESLint + Airbnb 配置”：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  选择 linter 的附加功能。在我们的情况下，选择“保存时进行 lint”和“提交时进行 lint 和修复”：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  选择要放置 linter 和 formatter 配置文件的位置。在我们的情况下，我们将选择“在专用配置文件中”：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ **In dedicated config files****In package.json** 
```

1.  最后，CLI 会询问您是否要保存未来项目的设置；选择`N`。之后，Vue-CLI 将为您创建文件夹并安装依赖项：

```js
?  Save this as a preset for future projects?  (y/N) n
```

1.  从创建的项目中，打开位于`src`文件夹中的`App.vue`文件。在单文件组件的`<script>`部分，删除`HelloWorld`组件。添加一个`data`属性，并将其定义为一个返回具有名为`display`的属性和默认值为`true`的 JavaScript 对象的单例函数：

```js
<script> export default {
  name: 'App',
  data: () => ({
  display: true,
  }), }; </script>
```

1.  在单文件组件的`<template>`部分，删除`HelloWorld`组件，并添加一个带有文本`Toggle`的`button` HTML 元素。在`img` HTML 元素中，添加一个绑定到`display`变量的`v-if`指令。最后，在`button` HTML 元素中，添加一个`click`事件。在事件监听器中，将值定义为一个将`display`变量设置为`display`变量的否定的匿名函数：

```js
<template>
 <div id="app">
    <button @click="display = !display">
      Toggle
    </button>
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png">  </div> </template> 
```

有了这些说明，我们可以为本章中的每个示例创建一个基础项目。

# 创建您的第一个 CSS 动画

借助 CSS，我们可以在不需要手动通过 JavaScript 编程 DOM 元素的更改的情况下为我们的应用程序添加动画。使用专门用于控制动画的特殊 CSS 属性，我们可以实现美丽的动画和过渡效果。

要使用 Vue 中可用的动画，当将动画应用于单个元素时，我们需要使用一个名为`Transition`的组件，或者当处理组件列表时，需要使用一个名为`TransitionGroup`的组件。

在这个示例中，我们将学习如何创建一个 CSS 动画，并将此动画应用于 Vue 应用程序中的单个元素。

## 准备工作

以下是此示例的先决条件：

+   Node.js 12+

+   一个名为`cssanimation`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基础项目，为这个示例创建一个名为`cssanimation`的新项目，并打开项目文件夹。现在，按照以下步骤进行操作：

1.  打开`App.vue`文件。在单文件组件的`<template>`部分中，使用`Transaction`组件包装`img` HTML 元素。在`Transaction`组件中，添加一个`name`属性，其值为`"image"`：

```js
<transition name="image">
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png"> </transition>
```

1.  在单文件组件的`<style>`部分中，创建一个`.image-enter-active`类，其中包含一个值为`bounce-in .5s`的`animation`属性。然后，创建一个`.image-leave-active`类，其中包含一个值为`bounce-in .5s reverse`的`animation`属性：

```js
.image-enter-active {
  animation: bounce-in .5s; } .image-leave-active {
  animation: bounce-in .5s reverse; }
```

1.  最后，创建一个`@keyframes bounce-in` CSS 规则。在其中，执行以下操作：

+   创建一个`0%`规则，其中包含属性变换和值为`scale(0)`。

+   创建一个`50%`规则，其中包含属性变换和值为`scale(1.5)`。

+   创建一个`100%`规则，其中包含属性变换和值为`scale(1)`：

```js
@keyframes bounce-in {
  0% {
  transform: scale(0);
  }
  50% {
  transform: scale(1.5);
  }
  100% {
  transform: scale(1);
  } }
```

完成此操作后，当第一次按下切换按钮时，您的图像将放大并消失。再次按下时，动画完成后，图像将放大并保持正确的比例：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/ac24a78e-c253-4148-a39c-b17db2938711.png)

## 它是如何工作的...

首先，我们将 Vue 动画包装器添加到我们想要添加过渡效果的元素上，然后添加将在过渡中使用的 CSS 类的名称。

`Transition`组件使用预先制作的命名空间来要求必须存在的 CSS 类。这些是`-enter-active`，用于组件进入屏幕时，以及`-leave-active`，用于组件离开屏幕时。

然后，在`<style>`中创建 CSS 类，用于元素离开和进入屏幕的过渡，以及`bounce-in`动画的`keyframe`规则集，以定义其行为方式。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-overview.html#class-based-animations-transitions`](https://v3.vuejs.org/guide/transitions-overview.html#class-based-animations-transitions)找到有关使用 Vue 类进行基于类的动画和过渡的更多信息。

您可以在[`developer.mozilla.org/en-US/docs/Web/CSS/@keyframes`](https://developer.mozilla.org/en-US/docs/Web/CSS/@keyframes)找到有关 CSS 关键帧的更多信息。

# 使用 Animate.css 创建自定义过渡类

在`Transition`组件中，可以定义在每个过渡步骤中使用的 CSS 类。通过使用此属性，我们可以使`Transition`组件在过渡动画中使用 Animate.css。

在这个示例中，我们将学习如何在组件中使用 Animate.css 类与`Transition`组件，以创建自定义过渡效果。

## 准备工作

以下是此示例的先决条件：

+   Node.js 12+

+   一个名为`animatecss`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基础项目，为此示例创建一个名为`animatecss`的新项目，并打开项目文件夹。现在，按照以下步骤进行操作：

1.  在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令安装 Animate.css 框架：

```js
> npm install animate.css@3.7.2
```

1.  打开`src`文件夹中的`main.js`文件并导入 Animate.css 框架：

```js
import Vue from 'vue'; import App from './App.vue'; import 'animate.css';
```

1.  打开`src`文件夹中的`App.vue`文件，并将`Transition`组件添加为`img` HTML 元素的包装器。在`Transition`组件中，添加一个名为`enter-active-class`的属性，并将其定义为`"animated bounceInLeft"`。然后，添加另一个名为`leave-active-class`的属性，并将其定义为`"animated bounceOutLeft"`：

```js
<transition
  enter-active-class="animated bounceInLeft"
  leave-active-class="animated bounceOutLeft" >
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png"> </transition>
```

完成此操作后，当第一次按下切换按钮时，您的图像将向左滑出并消失。再次按下时，它将从左侧滑入：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/9ecf9f7a-2cc3-4af8-b067-fc4aedcb7388.png)

## 工作原理...

`Transition`组件最多可以接收六个属性，可以为交易的每个步骤设置自定义类。这些属性是`enter-class`、`enter-active-class`、`enter-to-class`、`leave-class`、`leave-active-class`和`leave-to-class`。在这个示例中，我们使用了`enter-active-class`和`leave-active-class`；这些属性定义了元素在屏幕上可见或离开屏幕时的自定义类。

为了使用自定义动画，我们使用了 Animate.css 框架，该框架提供了预先制作并准备好供使用的自定义 CSS 动画。我们使用了`bounceInLeft`和`bounceOutLeft`来使元素从屏幕中滑入和滑出。

## 还有更多...

您可以尝试更改`enter-active-class`和`leave-active-class`属性的类，以查看 CSS 动画在浏览器上的行为。

您可以在 Animate.css 文档中找到可用类的完整列表[`animate.style/`](https://animate.style/)。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-overview.html#class-based-animations-transitions`](https://v3.vuejs.org/guide/transitions-overview.html#class-based-animations-transitions)找到有关基于类的动画和 Vue 类的过渡的更多信息。

您可以在[`animate.style/`](https://animate.style/)找到有关 Animate.css 的更多信息。

# 使用自定义钩子创建交易

`Transaction`组件具有每个动画生命周期的自定义事件发射器。这些可以用于附加自定义函数和方法，以在动画周期完成时执行。

我们可以使用这些方法在页面交易完成或按钮动画结束后执行数据获取，从而按特定顺序链接动画，这些动画需要根据动态数据依次执行。

在这个配方中，我们将学习如何使用`Transaction`组件的自定义事件发射器来执行自定义方法。

## 准备就绪

以下是此配方的先决条件：

+   Node.js 12+

+   名为`transactionhooks`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做到...

使用基础项目，为此配方创建一个名为`transactionhooks`的新项目，并打开项目文件夹。现在，按照以下步骤：

1.  在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令以安装 Animate.css 框架：

```js
> npm install animate.css@3.7.2
```

1.  在`src`文件夹中打开`main.js`文件并导入 Animate.css 框架：

```js
import Vue from 'vue'; import App from './App.vue'; import 'animate.css';
```

1.  在`src`文件夹中打开`App.vue`文件。在单文件组件的`<script>`部分，在数据属性中，在单例函数中，添加一个名为`status`的新属性，并将其值定义为`"appeared"`：

```js
data: () => ({
  display: true,
  status: 'appeared', }),
```

1.  创建一个`methods`属性，并将其定义为 JavaScript 对象。在对象内部，添加两个名为`onEnter`和`onLeave`的属性。在`onEnter`属性中，将其定义为一个函数，并在其中将数据`status`变量设置为`"appeared"`。在`onLeave`属性中，将其定义为一个函数，并在其中将数据`status`变量设置为`"disappeared"`：

```js
methods: {
  onEnter() {
  this.status = 'appeared';
  },
  onLeave() {
  this.status = 'disappeared';
  }, },
```

1.  在单文件组件的`<template>`部分，添加一个`Transition`组件作为`img`HTML 元素的包装器。在`Transition`组件中，执行以下操作：

+   添加一个名为`enter-active-class`的属性，并将其定义为`"animated rotateIn"`。

+   添加另一个名为`leave-active-class`的属性，并将其定义为`"animated rotateOut"`。

+   添加事件监听器`after-enter`绑定并将其附加到`onEnter`方法。

+   添加事件监听器`after-leave`绑定并将其附加到`onLeave`方法：

```js
<transition
  enter-active-class="animated rotateIn"
  leave-active-class="animated rotateOut"
  @after-enter="onEnter"
  @after-leave="onLeave" >
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png"> </transition>
```

1.  创建一个`h1` HTML 元素作为`Transition`组件的兄弟元素，并添加文本`The image {{ status }}`：

```js
<h1>The image {{ status }}</h1>
```

现在，当点击按钮时，文本将在动画完成时更改。 它将显示动画完成后出现的图像和动画完成后消失的图像：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/db9d8f36-4b7d-4c65-8a22-2d4e9a8f0ce8.png)

## 工作原理...

`Transition`组件有八个自定义钩子。 这些钩子由 CSS 动画触发，当它们被触发时，它们会发出自定义事件，可以被父组件使用。 这些自定义事件是`before-enter`，`enter`，`after-enter`，`enter-cancelled`，`before-leave`，`leave`，`after-leave`和`leave-cancelled`。

在使用`after-enter`和`after-leave`钩子时，当 CSS 动画完成时，屏幕上的文本会相应地更改为每个钩子的事件监听器上定义的函数。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-enterleave.html#javascript-hooks`](https://v3.vuejs.org/guide/transitions-enterleave.html#javascript-hooks)找到有关转换钩子的更多信息。

您可以在[`animate.style/`](https://animate.style/)找到有关 Animate.css 的更多信息。 

# 在页面渲染时创建动画

在页面渲染时使用页面转换动画或自定义动画是常见的，有时需要引起应用程序用户的注意。

在 Vue 应用程序中可以创建此效果，无需刷新页面或重新渲染屏幕上的所有元素。 您可以使用`Transition`组件或`TransitionGroup`组件来实现这一点。

在本教程中，我们将学习如何使用`Transition`组件，以便在页面渲染时触发动画。

## 准备工作

本文档的先决条件如下：

+   Node.js 12+

+   一个名为`transactionappear`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基础项目，为本教程创建一个名为`transactionappear`的新项目，并打开项目文件夹。 现在，按照以下步骤：

1.  在项目文件夹中，打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows），并执行以下命令以安装 Animate.css 框架：

```js
> npm install animate.css@3.7.2
```

1.  在`src`文件夹中的`main.js`文件中导入 Animate.css 框架：

```js
import Vue from 'vue'; import App from './App.vue'; import 'animate.css';
```

1.  在`src`文件夹中的`App.vue`文件中，为`img` HTML 元素添加一个`Transition`组件作为包装器。在`Transition`组件中，执行以下操作：

+   添加一个名为`appear-active-class`的属性，并将其定义为`"animated jackInTheBox"`.

+   添加一个名为`enter-active-class`的属性，并将其定义为`"animated jackInTheBox"`。

+   添加另一个名为`leave-active-class`的属性，并将其定义为`"animated rollOut"`。

+   添加`appear`属性并将其定义为`true`：

```js
<transition
  appear
 appear-active-class="animated jackInTheBox"
  enter-active-class="animated jackInTheBox"
  leave-active-class="animated rollOut" >
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png"> </transition>
```

页面打开时，Vue 标志将像一个爆米花盒一样摇晃，并在动画完成后保持静止：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/82c607c2-9644-4610-b9e7-a00d9cc01133.png)

## 工作原理...

`Transition`组件有一个特殊属性叫做`appear`，当启用时，使元素在屏幕上呈现时触发动画。该属性带有三个控制动画 CSS 类的属性，分别为`appear-class`、`appear-to-class`和`appear-active-class`。

还有四个与此属性一起执行的自定义钩子，分别为`before-appear`、`appear`、`after-appear`和`appear-cancelled`。

在我们的案例中，当组件在屏幕上呈现时，我们使组件执行 Animate.css 框架中的`jackInTheBox`动画。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-enterleave.html#transitions-on-initial-render`](https://v3.vuejs.org/guide/transitions-enterleave.html#transitions-on-initial-render)找到有关初始渲染过渡的更多信息。

您可以在[`animate.style/`](https://animate.style/)找到有关 Animate.css 的更多信息。

# 为列表和组创建动画

有一些动画需要在一组元素或列表中执行。这些动画需要包装在`TransitionGroup`元素中才能工作。

该组件具有一些与`Transition`组件中相同的属性，但要使其工作，您必须为子元素和特定于该组件的组件定义一组特殊指令。

在此示例中，我们将创建一个动态图像列表，当用户点击相应按钮时将添加图像。这将在图像出现在屏幕上时执行动画。

## 准备工作

以下是此示例的先决条件：

+   Node.js 12+

+   一个名为`transactiongroup`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基础项目，为此示例创建一个名为`transactiongroup`的新项目并打开项目文件夹。现在，按照以下步骤进行：

1.  在项目文件夹中，打开 Terminal（macOS 或 Linux）或 Command Prompt/PowerShell（Windows），并执行以下命令来安装 Animate.css 框架：

```js
> npm install animate.css@3.7.2
```

1.  打开`src`文件夹中的`main.js`文件并导入 Animate.css 框架：

```js
import Vue from 'vue'; import App from './App.vue'; import 'animate.css';
```

1.  打开`src`文件夹中的`App.vue`文件。在单文件组件的`<script>`部分中，在`data`单例上返回一个名为`count`且值为`0`的属性：

```js
data: () => ({
  count: 0, }),
```

1.  在单文件组件的`<template>`部分中，删除`div#app` HTML 元素内的所有内容。然后，作为`div#app` HTML 元素的子元素，创建一个带有`tag`属性定义为`"ul"`和`enter-active-class`属性定义为`"animated zoomIn"`的`TransitionGroup`组件：

```js
<div id="app">
 <transition-group
  tag="ul"
  enter-active-class="animated zoomIn"
  ></transition-group>
</div>
```

1.  作为`TransitionGroup`组件的子元素，创建一个带有`v-for`指令的`li` HTML 元素，对`count`变量进行迭代，定义一个名为`key`的变量属性，其值为`i`，并定义一个`style`属性，其值为`"float: left"`。作为`li` HTML 组件的子元素，创建一个带有`src`属性定义为`"https://picsum.photos/100"`的`img` HTML 组件：

```js
<li
  v-for="i in count"
  :key="i"
  style="float: left" >
 <img src="https://picsum.photos/100"/> </li>
```

1.  然后，作为`TransitionGroup`组件的兄弟元素，创建一个带有`style`属性定义为`"clear: both"`的`hr` HTML 元素：

```js
<hr style="clear: both"/>
```

1.  最后，作为`hr` HTML 元素的兄弟，创建一个带有`click`事件的`button` HTML 元素，将`1`添加到当前的`count`变量，并将文本设置为`Increase`：

```js
<button
  @click="count = count + 1" >
  Increase
</button>
```

现在，当用户点击相应的按钮以增加列表时，它将向列表添加一个新项目，并触发放大动画：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/8fb8866e-08b9-40aa-a89f-0be48f10ee0d.png)

## 它是如何工作的...

`TransitionGroup`元素通过`tag`属性中声明的标记创建一个包装器元素。这将通过检查子元素的唯一键来管理将触发动画的自定义元素。因此，`TransitionGroup`组件内的所有子元素都需要声明一个`key`并且必须是唯一的。

在我们的案例中，我们使用`ul`和`li` HTML 元素创建了一个 HTML 列表，其中`TransitionGroup`是使用`ul`标签定义的，子元素是使用`li` HTML 元素定义的。然后，我们对数字进行了虚拟迭代。这意味着将有一个项目列表，并根据该列表上的项目数量在屏幕上显示图像。

为了增加我们的列表，我们创建了一个`button` HTML 元素，每次按下时都会将`count`变量的计数增加一。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-list.html#reusable-transitions`](https://v3.vuejs.org/guide/transitions-list.html#reusable-transitions)找到有关转换组的更多信息。

您可以在[`animate.style/`](https://animate.style/)找到有关 Animate.css 的更多信息。

# 创建自定义过渡组件

使用框架创建应用程序很好，因为您可以创建可重用的组件和可共享的代码。使用这种模式对简化应用程序的开发非常有帮助。

创建可重用的过渡组件与创建可重用组件相同，可以使用更简单的方法，因为它可以与函数渲染一起使用，而不是正常的渲染方法。

在本教程中，我们将学习如何创建一个可在我们的应用程序中使用的可重用的函数组件。

## 准备工作

本章的先决条件如下：

+   Node.js 12+

+   一个名为`customtransition`的 Vue-CLI 基本项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基本项目，为本教程创建一个名为`customtransition`的新项目，并打开项目文件夹。现在，按照以下步骤进行操作：

1.  在项目文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令来安装 Animate.css 框架：

```js
> npm install animate.css@3.7.2
```

1.  在`src`文件夹中的`main.js`文件中导入 Animate.css 框架：

```js
import Vue from 'vue'; import App from './App.vue'; import 'animate.css';
```

1.  在`src/components`文件夹中创建一个名为`CustomTransition.vue`的新文件，并打开它。在单文件组件的`<template>`部分，添加`functional`属性以启用组件的函数渲染。然后，创建一个`Transition`组件，将`appear`变量属性定义为`props.appear`。将`enter-active-class`属性定义为`"animated slideInLeft"`，将`leave-active-class`属性定义为`"animated slideOutRight"`。最后，在`Transition`组件内部，添加一个`<slot>`占位符：

```js
<template functional>
 <transition
  :appear="props.appear"
  enter-active-class="animated slideInLeft"
  leave-active-class="animated slideOutRight"
  >
 <slot />
 </transition> </template>
```

1.  在`src`文件夹中的`App.vue`文件中打开。在单文件组件的`<script>`部分，导入新创建的`CustomTransition`组件。在 Vue 对象上，添加一个名为`components`的新属性，将其定义为 JavaScript 对象，并添加导入的`CustomTransition`组件：

```js
<script> import CustomTransition from './components/CustomTransition.vue';   export default {
  name: 'App',
  components: {
  CustomTransition,
 },  data: () => ({
  display: true,
 }), }; </script>
```

1.  最后，在单文件组件的`<template>`部分，使用`CustomTransition`组件包装`img` HTML 元素：

```js
<custom-transition>
 <img
  v-if="display"
  alt="Vue logo" src="./assets/logo.png"> </custom-transition>
```

使用这个自定义组件，可以在不需要在组件上重新声明`Transition`组件和过渡 CSS 类的情况下重用过渡：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/5d4d098e-2b25-4bc7-ac51-8a5d7ff00517.png)

## 它是如何工作的...

首先，我们使用函数组件方法创建了一个自定义组件，不需要声明单文件组件的`<script>`部分。

在这个自定义组件中，我们使用`Transaction`组件作为基础组件。然后，我们使用注入的函数上下文`prop.appear`定义了`appear`属性，并为过渡添加了动画类，使其在组件呈现时从左侧滑入，销毁时从右侧滑出。

然后，在主应用程序中，我们使用这个自定义组件来包装`img` HTML 元素，并使其作为`Transition`组件工作。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-list.html#reusable-transitions`](https://v3.vuejs.org/guide/transitions-list.html#reusable-transitions)找到有关可重用过渡组件的更多信息。

您可以在[`animate.style/`](https://animate.style/)找到有关 Animate.css 的更多信息。

# 在元素之间创建无缝过渡

当两个组件之间有动画和过渡时，它们需要是无缝的，这样用户在将组件放置在屏幕上时就看不到 DOM 抖动和重绘。为了实现这一点，我们可以使用`Transition`组件和过渡模式属性来定义过渡的方式。

在这个示例中，我们将使用`Transition`组件和过渡模式属性来创建图像之间的过渡动画。

## 准备工作

本章的先决条件如下：

+   Node.js 12+

+   一个名为`seamlesstransition`的 Vue-CLI 基础项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

使用基础项目，为这个示例创建一个名为`seamlesstransition`的新项目，并打开项目文件夹。现在，按照以下步骤进行操作：

1.  在`src`文件夹中打开`App.vue`文件。在单文件组件的`<style>`部分，创建一个名为`.rotate-enter-active,.rotate-leave-active`的属性，并将`transition` CSS 样式属性定义为`transform .8s ease-in-out;`。然后，创建一个名为`.rotate-enter,.rotate-leave-active`的属性，并将`transform` CSS 样式属性定义为`rotate( -180deg );`，并将`transition`定义为`.8s ease-in-out;`：

```js
.rotate-enter-active, .rotate-leave-active {
  transition: transform .8s ease-in-out; }   .rotate-enter, .rotate-leave-active {
  transform: rotate( -180deg );
  transition: transform .8s ease-in-out; }
```

1.  在单文件组件的`<template>`部分，用`Transition`组件包裹`img` HTML 元素。然后，将`name`属性定义为`rotate`，`mode`属性定义为`out-in`：

```js
<transition
  name="rotate"
  mode="out-in" ></transition>
```

1.  在`Transition`组件中，对`img` HTML 元素添加一个`key`属性，并将其定义为`up`。然后，添加另一个`img` HTML 元素并添加一个`v-else`指令。添加一个`key`属性并将其定义为`down`，添加一个`src`属性并将其定义为`"./assets/logo.png"`，最后添加一个`style`属性并将其定义为`"transform: rotate(180deg)"`：

```js
<img
  v-if="display"
  key="up"
  src="./assets/logo.png"> <img
  v-else
 key="down"
  src="./assets/logo.png"
  style="transform: rotate(180deg)" >
```

当用户切换元素时，将执行离开动画，然后在完成后，进入动画将立即开始。这样就可以实现旧元素和新元素之间的无缝过渡：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/73ca085d-cca2-4228-af9a-c895b177ac7d.png)

## 它是如何工作的...

`Transition`组件有一个特殊的属性叫做`mode`，在这里可以定义元素过渡动画的行为。这种行为将创建一组规则，控制动画步骤在`Transition`组件内部的发生方式。在组件中可以使用`"in-out"`或`"out-in"`模式：

+   在`"in-out"`行为中，新元素的过渡将首先发生，当它完成后，旧元素的过渡将开始。

+   在`"out-in"`行为中，旧元素的过渡将首先发生，然后新元素的过渡将开始。

在我们的案例中，我们创建了一个动画，将 Vue 标志旋转到倒置状态。然后，为了处理这个无缝的变化，我们使用了`"out-in"`模式，这样新元素只会在旧元素完成过渡后才会显示出来。

## 另请参阅

您可以在[`v3.vuejs.org/guide/transitions-enterleave.html`](https://v3.vuejs.org/guide/transitions-enterleave.html)找到有关过渡模式的更多信息。


# 第九章：使用 UI 框架创建漂亮的应用程序

使用 UI 框架和库是提高生产力并帮助应用程序开发的好方法。您可以更多地专注于代码，而不是设计。

学习如何使用这些框架意味着您知道这些框架的行为和工作原理。这将有助于您在将来开发应用程序或框架的过程中。

在这里，您将学习在创建用户注册表单和页面所需的所有组件时，使用框架的更多用法。在本章中，我们将学习如何使用 Buefy、Vuetify 和 Ant-Design 创建布局、页面和表单。

在本章中，我们将涵盖以下示例：

+   使用 Buefy 创建页面、布局和用户表单

+   使用 Vuetify 创建页面、布局和用户表单

+   使用 Ant-Design 创建页面、布局和用户表单

# 技术要求

在这一章中，我们将使用 Node.js 和 Vue-CLI。

注意 Windows 用户：您需要安装一个名为`windows-build-tools`的`npm`包。为此，请以管理员身份打开 PowerShell 并执行以下命令：

`> npm install -g windows-build-tools`

要安装`Vue-CLI`，您需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> npm install -g @vue/cli @vue/cli-service-global
```

# 使用 Buefy 创建页面、布局和用户表单

Bulma 是最早用于快速原型设计和 Web 开发的框架之一，它不需要附加 JavaScript 库。所有需要编码的特殊组件都是使用框架的开发人员的责任。

随着 JavaScript 框架的出现和围绕 Bulma 框架创建的社区，为 Vue 创建了一个包装器。这个包装器承担了 JavaScript 组件开发的所有责任，并为开发人员提供了在其应用程序中使用 Bulma 框架的完整解决方案，而无需重新发明轮子。

在这个示例中，我们将学习如何在 Vue 中使用 Buefy 框架，以及如何创建布局、页面和用户注册表单。

## 准备工作

本示例的先决条件如下：

+   Node.js 12+

+   一个 Vue-CLI 项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

要使用 Buefy 框架创建一个 Vue-CLI 项目，我们首先需要创建一个 Vue-CLI 项目，然后将 Buefy 框架添加到项目中。我们将把这个步骤分为四个部分：创建 Vue-CLI 项目，将 Buefy 框架添加到项目中，创建布局和页面，最后创建用户注册表单。

### 创建 Vue-CLI 项目

在这里，我们将创建用于此示例的 Vue-CLI 项目。这个项目将具有自定义设置，以便能够与 Buefy 框架一起工作：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue create bulma-vue
```

1.  Vue-CLI 会要求您选择一个预设 - 选择`手动选择功能`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ Manually select features 
```

1.  现在 Vue-CLI 会要求选择功能，您需要在默认功能之上选择`CSS 预处理器`作为附加功能：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex ❯ CSS Pre-processors ❯ Linter / Formatter Unit Testing E2E Testing
```

1.  在这里，Vue-CLI 会询问您想要使用哪种 CSS 预处理器；选择`Sass/SCSS（使用 node-sass）`：

```js
?  Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules are supported by default): (Use arrow keys) Sass/SCSS (with dart-sass) ❯ Sass/SCSS (with node-sass) Less **Stylus** 
```

1.  继续这个过程，选择一个 linter 和格式化程序。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ ESLint + Airbnb config   ESLint + Standard config 
  ESLint + Prettier
```

1.  选择 linter 的附加功能（这里是`在提交时进行 Lint 和修复`）：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  选择您想要放置 linter 和格式化程序配置文件的位置（这里是`在专用配置文件中`）：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ In dedicated config files  **In package.json** 
```

1.  最后，Vue-CLI 会询问您是否要保存设置以供将来使用；您应该选择`N`。之后，Vue-CLI 将为您创建文件夹并安装依赖项：

```js
?  Save this as a preset for future projects?  (y/N) n
```

### 将 Buefy 添加到 Vue-CLI 项目中

要在 Vue 项目中使用 Bulma，我们将使用 Buefy UI 库。这个库是 Bulma 框架的一个包装器，并提供了所有原始框架可用的组件以及一些额外的组件来使用：

1.  在为 Vue-CLI 项目创建的文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue add buefy
```

1.  Vue-CLI 会询问您是否要选择一个样式来使用 Buefy；我们将选择`scss`：

```js
? Add Buefy style?  (Use arrow keys)
 none 
 css 
❯ scss 
```

1.  然后，Vue-CLI 会询问您是否要包括 Material Design 图标；对于这个项目，我们不会使用它们：

```js
? Include Material Design Icons? (y/N) n
```

1.  现在 Vue-CLI 会询问您是否要包括 Font Awesome 图标；我们将把它们添加到项目中：

```js
? Include Font Awesome Icons? (y/N) y
```

### 使用 Buefy 创建布局和页面

要创建一个页面，我们需要创建一个布局结构和页面的基本组件，比如页眉菜单、页脚和页面的主要部分。

#### 创建页眉菜单组件

在我们的设计中，我们将有一个页眉菜单，其中包含链接和呼吁行动按钮的基本组合：

1.  在`src/components`文件夹中创建一个名为`top-menu.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`TopMenu`：

```js
<script> export default {
  name: 'TopMenu',  }; </script>
```

1.  在单文件组件的`<template>`部分，创建一个带有`section`类的`section` HTML 元素，并添加一个带有`container`类的子`div` HTML 元素：

```js
<section class="section">
 <div class="container">
  </div>
</section>
```

1.  现在，在`div.container` HTML 元素的子级中创建一个`b-navbar`组件，并添加一个具有命名插槽`brand`的`template`占位符组件作为子级。在其中，添加一个带有`href`属性定义为`#`的`b-navbar-item`组件，并添加一个`img` HTML 元素作为子级：

```js
<b-navbar>
 <template slot="brand">
 <b-navbar-item href="#">
 <img src="https://raw.githubusercontent.com/buefy/buefy/dev
               /static/img/buefy-logo.png"
  alt="Lightweight UI components for Vue.js based on Bulma"
  >
 </b-navbar-item>
 </template> </b-navbar>
```

1.  在这个`template`占位符之后，创建另一个具有命名插槽`start`的`template`占位符。在其中，创建两个带有`href`属性定义为`#`的`b-navbar-item`组件。作为同级组件，创建一个带有`label`属性定义为`Info`的`b-navbar-dropdown`组件。在这个组件中，添加两个带有`href`属性定义为`#`的`b-navbar-item`组件作为子级：

```js
<template slot="start">
 <b-navbar-item href="#">
  Home
  </b-navbar-item>
 <b-navbar-item href="#">
  Documentation
  </b-navbar-item>
 <b-navbar-dropdown label="Info">
 <b-navbar-item href="#">
  About
    </b-navbar-item>
 <b-navbar-item href="#">
  Contact
    </b-navbar-item>
 </b-navbar-dropdown> </template>
```

1.  最后，在`template`中创建另一个具有命名插槽`end`的占位符。创建一个`b-navbar-item`组件作为子组件，`tag`属性定义为`div`，并在该组件的子级中添加一个带有`buttons`类的`div` HTML 元素。在`div` HTML 元素中，创建一个带有`button is-primary`类的`a` HTML 元素，以及另一个带有`button is-light`类的`a` HTML 元素：

```js
<template slot="end">
 <b-navbar-item tag="div">
 <div class="buttons">
 <a class="button is-primary">
 <strong>Sign up</strong>
 </a>
 <a class="button is-light">
  Log in
      </a>
 </div>
 </b-navbar-item> </template>  
```

#### 创建英雄区组件

我们将创建一个英雄区组件。英雄组件是一个全宽的横幅，为用户提供页面上的视觉信息：

1.  在`src/components`文件夹中创建一个名为`hero-section.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`HeroSection`：

```js
<script> export default {
  name: 'HeroSection', }; </script>
```

1.  在单文件组件的`<template>`部分，创建一个带有`hero is-primary`类的`section` HTML 元素，然后添加一个带有`hero-body`类的`div` HTML 元素作为子级：

```js
<section class="hero is-primary">
 <div class="hero-body">
  </div>
</section>
```

1.  在`div.hero-body` HTML 元素内部，创建一个带有`container`类的子`div` HTML 元素。然后，添加一个带有`title`类的`h1` HTML 元素作为子级，以及一个带有`subtitle`类的`h2` HTML 元素：

```js
<div class="container">
 <h1 class="title">
  user Registration
  </h1>
 <h2 class="subtitle">
  Main user registration form
  </h2> </div>  
```

#### 创建页脚组件

我们将在布局中使用的最终组件是页脚组件。这将显示为我们页面的页脚：

1.  在`src/components`文件夹中创建一个名为`Footer.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`FooterSection`：

```js
<script> export default {
  name: 'FooterSection', }; </script>
```

1.  在单文件组件的`<template>`部分，创建一个带有`footer`类的`footer` HTML 元素，然后添加一个带有`content has-text-centered`类的`div` HTML 元素：

```js
<footer class="footer">
 <div class="content has-text-centered">
  </div>
</footer>
```

1.  在`div.content` HTML 元素内，创建一个`p` HTML 元素作为初始页脚行，并创建第二个`p` HTML 元素作为第二行：

```js
<p>
 <strong>Bulma</strong> by <a href="https://jgthms.com">Jeremy
    Thomas</a>
  | <strong>Buefy</strong> by 
 <a href="https://twitter.com/walter_tommasi">Walter
         Tommasi</a> </p> <p>
  The source code is licensed 
 <a href="http://opensource.org/licenses/mit-license.php">MIT</a>.
  The website content is licensed 
 <a href="http://creativecommons.org/licenses/by-nc-sa/4.0/">CC
       BY NC SA 4.0</a>.
</p>  
```

#### 创建布局组件

为了创建布局组件，我们将使用所有创建的组件，并添加一个将容纳页面内容的插槽：

1.  在`src`文件夹中创建一个名为`layouts`的新文件夹，并创建一个名为`Main.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，导入`footer-section`组件和`top-menu`组件：

```js
import FooterSection from '../components/Footer.vue'; import TopMenu from '../components/top-menu.vue';
```

1.  然后，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`Mainlayout`，并定义`components`属性为导入的组件：

```js
export default {
  name: 'Mainlayout',
  components: {
  TopMenu,
  FooterSection,
  }, };
```

1.  最后，在单文件组件的`<template>`部分，创建一个带有子`top-menu`组件、一个`slot`占位符和`footer-section`组件的`div` HTML 元素：

```js
<template>
 <div>
 <top-menu />
 <slot/>
 <footer-section />
 </div> </template>  
```

### 使用 Buefy 创建用户注册表单

现在我们要创建用户注册表单并制作最终页面。在这一步中，我们将把所有其他步骤的输出合并到一个页面中：

1.  打开`src`文件夹中的`App.vue`文件。在单文件组件的`<script>`部分，导入`main-layout`组件和`hero-section`组件：

```js
import Mainlayout from './layouts/main.vue'; import HeroSection from './components/heroSection.vue';
```

1.  然后，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`App`，然后定义`components`属性为导入的组件。在 JavaScript 对象中添加`data`属性，包括`name`、`username`、`password`、`email`、`phone`、`cellphone`、`address`、`zipcode`和`country`属性：

```js
export default {
  name: 'App',
  components: {
  HeroSection,
  Mainlayout,
  },
  data: () => ({
  name: '',
  username: '',
  password: '',
  email: '',
  phone: '',
  cellphone: '',
  address: '',
  zipcode: '',
  country: '',
  }), };
```

1.  在单文件的`<template>`部分，添加导入的`main-layout`组件，并将`hero-section`作为子组件添加：

```js
<template>
 <main-layout>
 <hero-section/>
  </main-layout>
</template>
```

1.  在`hero-section`组件之后，创建一个兄弟`section` HTML 元素，带有`section`类，并添加一个带有`container`类的子`div` HTML 元素。在这个`div` HTML 元素中，创建一个带有`title is-3`类的`h1` HTML 元素和一个兄弟`hr` HTML 元素：

```js
<section class="section">
 <div class="container">
 <h1 class="title is-3">Personal Information</h1>
 <hr/>
  </div>
</section>
```

1.  然后，创建一个带有`Name`作为`label`的`b-field`组件，作为`hr` HTML 元素的兄弟，并添加一个带有`v-model`指令绑定到`name`的子`b-input`。对于`email`字段，做同样的操作，将`label`更改为`Email`，并将`v-model`指令绑定到`email`。在 email 的`b-input`中，添加一个定义为`email`的`type`属性：

```js
<b-field label="Name">
 <b-input
  v-model="name"
  /> </b-field> <b-field
  label="Email" >
 <b-input
  v-model="email"
  type="email"
  /> </b-field>
```

1.  创建一个带有`grouped`属性的`b-field`组件作为`b-field`组件的兄弟。然后，作为子组件，创建以下内容：

+   一个带有`expanded`属性和`label`定义为`Phone`的`b-field`组件。添加一个带有`v-model`指令绑定到`phone`和`type`为`tel`的子`b-input`组件。

+   一个带有`expanded`属性和`label`定义为`Cellphone`的`b-field`组件。添加一个带有`v-model`指令绑定到`cellphone`和`type`为`tel`的子`b-input`组件：

```js
<b-field grouped>  <b-field
  expanded
 label="Phone"
  >
 <b-input
  v-model="phone"
  type="tel"
  />
 </b-field>
 <b-field
  expanded
 label="Cellphone"
  >
 <b-input
  v-model="cellphone"
  type="tel"
  />
 </b-field> </b-field>
```

1.  然后，创建一个带有`title is-3`类的`h1` HTML 元素作为`b-field`组件的兄弟，并添加一个`hr` HTML 元素作为兄弟。创建一个带有`label`定义为`Address`的`b-field`组件，并添加一个带有`v-model`指令绑定到`address`的`b-input`组件：

```js
<h1 class="title is-3">Address</h1> <hr/> <b-field
  label="Address" >
 <b-input
  v-model="address"
  /> </b-field>
```

1.  创建一个`b-field`组件作为`b-field`组件的兄弟，带有`grouped`属性。然后，作为子组件，创建以下内容：

+   一个带有`expanded`属性和`label`定义为`Zipcode`的子`b-field`组件。添加一个带有`v-model`指令绑定到`zipcode`和`type`属性定义为`tel`的`b-input`组件。

+   一个带有`expanded`属性和`label`定义为`Country`的子`b-field`组件。添加一个带有`v-model`指令绑定到`country`和`type`属性定义为`tel`的`b-input`组件：

```js
<b-field grouped>
 <b-field
  expanded
 label="Zipcode"
  >
 <b-input
  v-model="zipcode"
  type="tel"
  />
 </b-field>
 <b-field
  expanded
 label="Country"
  >
 <b-input
  v-model="country"
  />
 </b-field> </b-field>
```

1.  然后，创建一个`h1` HTML 元素作为`b-field`组件的同级元素，使用`title is-3`类，并添加一个`hr` HTML 元素作为同级元素。创建一个带有`grouped`属性的`b-field`组件。创建一个子`b-field`组件，带有`expanded`属性和`label`定义为`username`，并添加一个带有`v-model`指令绑定到`username`的`b-input`组件。对于`Password`输入，做同样的事情，将`label`更改为`Password`，在`b-input`组件中定义`v-model`指令绑定到`password`，并添加`type`属性为`password`：

```js
<h1 class="title is-3">user Information</h1> <hr/> <b-field grouped>
 <b-field
  expanded
 label="username"
  >
 <b-input
  v-model="username"
  />
 </b-field>
 <b-field
  expanded
 label="Password"
  >
 <b-input
  v-model="password"
  type="password"
  />
 </b-field> </b-field>
```

1.  最后，创建一个`b-field`组件作为`b-field`组件的同级元素，定义`position`属性为`is-right`和`grouped`属性。然后，创建两个带有`control`类的`div` HTML 元素。在第一个`div` HTML 元素中，添加一个`button` HTML 元素作为子元素，使用`button is danger is-light`类，而在第二个`div` HTML 元素中，创建一个带有`button is-success`类的子`button` HTML 元素：

```js
<b-field
  position="is-right"
  grouped
>
  <div class="control">
    <button class="button is-danger is-light">Cancel</button>
  </div>
  <div class="control">
    <button class="button is-success">Submit</button>
  </div>
</b-field>
```

## 它是如何工作的...

首先，我们创建一个 Vue-CLI 项目，进行基本配置，并添加额外的 CSS 预处理器`node-sass`。然后，我们能够使用 Vue-CLI 和 Buefy 插件将 Buefy 框架添加到我们的项目中。使用 Buefy 框架，我们创建了一个布局页面组件，带有页眉菜单组件和页脚组件。

对于页面，我们使用 Bulma CSS 容器结构来定义我们的页面，并将用户注册表单放在默认的网格大小上。然后，我们添加了 hero 部分组件，用于页面标识，最后，我们创建了用户注册表单和输入。

这是最终项目正在运行的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b1d76a75-1cbf-4562-813c-d15ac38a51b1.png)

## 另请参阅

在[`bulma.io/`](http://bulma.io/)找到有关 Bulma 的更多信息。

在[`buefy.org/`](https://buefy.org/)找到有关 Buefy 的更多信息。

# 使用 Vuetify 创建页面、布局和用户表单

Vuetify 是 Vue 最知名的三个 UI 框架之一。基于 Google 的 Material Design，这个框架最初是由 John Leider 设计的，现在作为 Vue 生态系统中的首选 UI 框架，用于应用程序的初始开发。

在这个食谱中，我们将学习如何使用 Vuetify 创建一个布局组件包装器、一个页面和一个用户注册表单。

## 准备工作

此处的食谱先决条件如下：

+   Node.js 12+

+   一个 Vue-CLI 项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何操作...

我们将把这个教程分为四个主要部分。前两部分专门用于创建项目和安装框架，后两部分专门用于创建用户注册页面和创建所需组件。

### 创建 Vue-CLI 项目

要在 Vue-CLI 项目中使用 Vuetify，我们需要创建一个自定义的 Vue-CLI 项目，并预定义配置，以便充分利用框架和提供的样式选项：

1.  我们需要在终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）中执行以下命令：

```js
> vue create vue-vuetify
```

1.  首先，Vue-CLI 会要求你选择一个预设；使用空格键选择`手动选择特性`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ **Manually select features**
```

1.  现在 Vue-CLI 会要求选择特性，你需要选择`CSS 预处理器`作为默认特性之外的附加特性：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex ❯ CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  在这里，Vue-CLI 会问你想使用哪种`CSS 预处理器`；选择`Sass/SCSS（使用 node-sass）`：

```js
?  Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules   
  are supported by default): (Use arrow keys) Sass/SCSS (with dart-sass) ❯ **Sass/SCSS (with node-sass)** Less **Stylus**
```

1.  继续这个过程，选择一个代码检查工具和格式化工具。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  选择代码检查工具的附加特性（这里是`提交时进行代码检查和修复`）：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save ❯ Lint and fix on commit
```

1.  选择你想要放置代码检查工具和格式化工具配置文件的位置（这里是`在专用配置文件中`）：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use arrow keys) ❯ **In dedicated config files****In package.json** 
```

1.  最后，Vue-CLI 会问你是否要保存设置以供将来的项目使用；你会选择`N`。之后，Vue-CLI 会为你创建一个文件夹并安装依赖项：

```js
?  Save this as a preset for future projects?  (y/N) n
```

### 将 Vuetify 添加到 Vue-CLI 项目中

要在 Vue 项目中使用 Vuetify，我们将使用 Vue-CLI 插件安装框架：

1.  在你创建 Vue-CLI 项目的文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），执行以下命令：

```js
> vue add vuetify
```

1.  Vue-CLI 会问你是否要选择安装预设。选择默认预设。然后，Vue-CLI 将完成在项目上安装框架：

```js
? Choose a preset: (Use arrow keys)
❯ Default (recommended) 
 Prototype (rapid development) 
 Configure (advanced) 
```

1.  安装完成后，Vuetify 将配置项目内的文件以加载框架。现在你可以开始使用它了。

### 使用 Vuetify 创建布局

使用 Vuetify 作为 UI 框架，我们使用 Material Design 指南作为基础，因为通过使用 Material Design，我们可以遵循设计指南来创建我们的设计结构，这将意味着更具吸引力的结构。您可以在[`material.io/design/introduction#goals`](https://material.io/design/introduction#goals)找到 Material Design 指南。

#### 创建顶部栏组件

在这部分，我们将创建一个`top-bar`组件，该组件将用于我们页面的布局中：

1.  在`src/components`文件夹中，创建一个名为`TopBar.vue`的文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个具有`name`属性定义为`TopBar`的`default` JavaScript 对象：

```js
<script> export default {
  name: 'TopBar', }; </script> 
```

1.  在`<template>`部分内，创建一个带有`app`，`dark`和`dense`属性定义为`true`，以及`color`属性定义为`primary`的`v-app-bar`组件：

```js
<v-app-bar
  color="primary"   app
 dark dense ></v-app-bar>
```

1.  在组件内部，创建一个带有`click`事件的事件监听器的`v-app-bar-nav-icon`组件，在按钮被点击时发送一个名为`'open-drawer'`的事件：

```js
<v-app-bar-nav-icon
  @click="$emit('open-drawer')" />
```

1.  最后，作为`v-app-bar-nav-icon`组件的兄弟，添加一个`v-toolbar-title`组件，其中包含页面或应用程序的标题：

```js
<v-toolbar-title>Vue.JS 3 Cookbook - Packt</v-toolbar-title>
```

#### 创建抽屉菜单组件

在 Material Design 应用程序中，我们有一个弹出在页面上方的抽屉菜单。当用户点击我们刚刚在`TopBar`组件中创建的按钮时，这个菜单将被打开：

1.  在`src/components`文件夹中，创建一个名为`DrawerMenu.vue`的文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个具有三个属性的`default` JavaScript 对象：

+   `name`属性，定义为`DrawerMenu`。

+   `props`属性，定义为一个 JavaScript 对象，具有一个名为`value`的属性。这个属性将是另一个 JavaScript 对象，具有`type`，`required`和`default`属性。`type`属性定义为`Boolean`，`required`属性定义为`true`，`default`属性定义为`false`。

+   `data`属性，作为返回 JavaScript 对象的单例函数。该对象将具有一个`menu`属性，我们将其定义为将要使用的菜单项数组。数组将包含具有`name`、`link`和`icon`属性的 Javascript 对象。第一个菜单项的`name`定义为`Home`，`link`定义为`*#*`，`icon`定义为`mdi-home`。第二个菜单项的`name`定义为`Contact`，`link`定义为`#`，`icon`定义为`mdi-email`。最后，第三个菜单项的`name`定义为`Vuetify`，`link`定义为`#`，`icon`定义为`mdi-vuetify`。

```js
<script>
export default {
  name: 'DrawerMenu',
  props: {
    value: {
      type: Boolean,
      required: true,
      default: false,
    },
  },
  data: () => ({
    menu: [
      {
        name: 'Home',
        link: '#',
        icon: 'mdi-home',
      },
      {
        name: 'Contact',
        link: '#',
        icon: 'mdi-email',
      },
      {
        name: 'Vuetify',
        link: '#',
        icon: 'mdi-vuetify',
      },
    ],
  }),
};
</script>
```

1.  在`<template>`部分，创建一个`v-navigation-drawer`组件，其中`value`属性作为绑定到`value` props 的变量属性，`app`属性定义为`true`，并在`click`事件上添加事件监听器，发送一个`'input'`事件：

```js
<v-navigation-drawer
  :value="value"
  app
 @input="$emit('input', $event)" ></v-navigation-drawer>
```

1.  创建一个带有`dense`属性定义为`true`的`v-list`组件。作为子元素，创建一个`v-list-item`组件并定义以下内容：

+   `v-for`指令遍历`menu`项。

+   `key`属性与菜单项的`index`。

+   `link`属性定义为`true`。

+   在`v-list-item`内部，创建一个带有`VIcon`子元素的`v-list-item-action`，内部文本为`item.icon`。

+   在`v-list-item-action`的同级位置创建一个`v-list-item-content`组件，其中`v-list-item-title`作为子元素，内部文本为`item.name`：

```js
<v-list dense>
  <v-list-item
    v-for="(item, index) in menu"
    :key="index"
    link>
    <v-list-item-action>
      <v-icon>{{ item.icon }}</v-icon>
    </v-list-item-action>
    <v-list-item-content>
      <v-list-item-title>{{ item.name }}</v-list-item-
                                                 title>
    </v-list-item-content>
  </v-list-item>
</v-list>
```

#### 创建布局组件

要创建布局组件，我们将使用所有创建的组件，并添加一个插槽来容纳页面内容：

1.  在`src/components`文件夹中，创建一个名为`Layout.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，导入`top-bar`组件和`drawer-menu`组件：

```js
import TopBar from './TopBar.vue'; import DrawerMenu from './DrawerMenu.vue';
```

1.  然后，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`Layout`，然后创建`components`属性并导入组件。最后，将`data`属性添加为返回 JavaScript 对象的单例函数，其中`drawer`属性的值定义为`false`：

```js
export default {
  name: 'Layout',
  components: {
  DrawerMenu,
  TopBar,
  },
 data: () => ({
    drawer: false,
  }), };
```

1.  在`<template>`部分内，创建一个`v-app`组件。作为第一个子元素，添加`top-bar`组件，并在`open-drawer`事件监听器上添加事件监听器，将`drawer`数据属性更改为`drawer`属性的否定。然后，作为`top-bar`的同级，创建一个`drawer-menu`组件，其`v-model`指令绑定到`drawer`。最后，创建一个`v-content`组件，其中包含一个子`<slot>`元素：

```js
<template>
 <v-app>
 <top-bar
  @open-drawer="drawer = !drawer"
  />
 <drawer-menu
  v-model="drawer"
  />
 <v-content>
 <slot/>
 </v-content>
 </v-app> </template>
```

### 使用 Vuetify 创建用户注册表单

现在，布局组件准备好了，我们将创建用户注册表单。因为 Vuetify 在表单中内置了验证，我们将使用它来验证表单中的一些字段。

#### 单文件组件<script>部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`src`文件夹中，打开`App.vue`文件并清空其内容。

1.  导入`layout`组件：

```js
import Layout from './components/Layout.vue';
```

1.  然后，我们将导出一个`default` JavaScript 对象，其中`name`属性定义为`App`，然后定义导入组件的`components`属性。将`computed`和`methods`属性定义为空的 JavaScript 对象。然后创建一个`data`属性，定义为返回 JavaScript 对象的单例函数。在`data`属性中，创建以下内容：

+   一个`valid`属性，其值定义为`false`；

+   `name`，`username`，`password`，`email`，`phone`，`cellphone`，`address`，`zipcode`和`country`属性定义为空字符串：

```js
export default {
  name: 'App',    components: {
 Layout,
  },    data: () => ({
  valid: true,
  name: '',
  username: '',
  password: '',
  email: '',
  phone: '',
  cellphone: '',
  address: '',
  zipcode: '',
  country: '',
  }),
  computed: {},   methods: {}, };
```

1.  在`computed`属性中，创建一个名为`nameRules`的属性；这个属性是一个返回数组的函数，其中包含一个匿名函数，该函数接收一个值并返回该值的验证或错误文本。对`passwordRules`和`emailRules`属性也做同样的操作。在`emailRules`属性中，向返回的数组中添加另一个匿名函数，该函数通过正则表达式检查值是否为有效的电子邮件，如果值不是有效的电子邮件，则返回错误消息：

```js
computed: {
  nameRules() {
  return [
 (v) => !!v || 'Name is required',
  ];
  },
  passwordRules() {
  return [
 (v) => !!v || 'Password is required',
  ];
  },
  emailRules() {
  return [
 (v) => !!v || 'E-mail is required',
  (v) => /.+@.+\..+/.test(v) || 'E-mail must be valid',
  ];
  }, },
```

1.  最后，在`methods`属性内，创建一个名为`register`的新属性，它是一个调用`$refs.form.validate`函数的函数。还创建另一个名为`cancel`的属性，它是另一个调用`$refs.form.reset`函数的函数：

```js
methods: {
  register() {
  this.$refs.form.validate();
  },
  cancel() {
  this.$refs.form.reset();
  }, },
```

#### 单文件组件<template>部分

现在是创建单文件组件的`<template>`部分的时候。

1.  在`src`文件夹中，打开`App.vue`文件。

1.  在`<template>`部分，创建一个`layout`组件元素，并添加一个带有`fluid`属性定义为`true`的`v-container`组件作为子元素。

```js
<layout>
 <v-container
  fluid
  >
  </v-container>
</layout>
```

1.  在`v-container`组件内部，创建一个子 HTML `h1`元素作为页面标题，以及一个同级的`v-subheader`组件作为页面描述。

```js
<h1>user Registration</h1> <v-subheader>Main user registration form</v-subheader>
```

1.  之后，创建一个带有`ref`属性定义为`form`和`lazy-validation`属性定义为`true`的`v-form`组件。然后，该组件的`v-model`指令绑定到`valid`变量。创建一个子`v-container`组件，其中`fluid`属性定义为`true`。

```js
<v-form
  ref="form"
  v-model="valid"
  lazy-validation >
 <v-container
  fluid
 >  </v-container>
</v-form>
```

1.  在`v-container`组件内部，创建一个`v-row`组件，然后添加一个`v-col`组件作为子元素，其中`cols`属性定义为`12`。在`v-col`组件内部，创建一个带有`outlined`属性和`flat`定义为`true`，以及`class`定义为`mx-auto`的`v-card`组件。

```js
<v-row>
 <v-col
  cols="12"
  >
 <v-card
  outlined
 flat class="mx-auto"
  >
    </v-card>
  </v-col>
</v-row>
```

1.  作为`v-card`组件的子元素，创建一个带有卡片标题的`v-card-title`组件，然后作为同级元素创建一个`v-divider`组件。之后，创建一个带有`fluid`属性定义为`true`的`v-container`元素。在`v-container`元素内部，创建一个子`v-row`组件。

```js
<v-card-title>
  Personal Information
</v-card-title> <v-divider/> <v-container
  fluid >
 <v-row>
  </v-row>
</v-container>
```

1.  在`v-row`组件内部，创建一个子`v-col`元素，其中`cols`属性定义为`12`。然后在`v-col`组件内部，创建一个`v-text-field`，其中`v-model`指令绑定到`name`变量，`rules`变量属性定义为`nameRules`计算属性，`label`属性定义为`Name`，最后，`required`属性定义为`true`。

```js
<v-col
  cols="12" >
 <v-text-field
  v-model="name"
  :rules="nameRules"
  label="Name"
  required
  /> </v-col>
```

1.  作为`v-col`组件的同级元素，创建另一个`v-col`组件，其中`cols`属性定义为`12`。然后，将`v-text-field`组件作为子元素添加，其中`v-model`指令绑定到`email`变量，`rules`变量属性定义为`emailRules`计算属性，`type`属性为`email`，`label`属性为`E-mail`，最后，`required`属性定义为`true`。

```js
<v-col
  cols="12" >
 <v-text-field
  v-model="email"
  :rules="emailRules"
  type="email"
  label="E-mail"
  required
  /> </v-col>
```

1.  创建一个作为`v-col`组件同级的`v-col`组件，并将`cols`属性定义为`6`。然后，作为子组件添加`v-text-field`组件，其中`v-model`指令绑定到`phone`变量，`label`属性定义为`Phone`。对于`Cellphone`输入，必须更改`v-model`指令绑定到`cellphone`变量和`label`为`Cellphone`。

```js
<v-col
  cols="6" >
 <v-text-field
  v-model="phone"
  label="Phone"
  /> </v-col> <v-col
  cols="6" >
 <v-text-field
  v-model="cellphone"
  label="Cellphone"
  /> </v-col>
```

1.  现在我们将创建`地址`卡，作为`v-row`组件中`v-col`的同级元素。创建一个`v-col`组件，其中`cols`属性定义为`12`。在`v-col`组件内部，创建一个带有`outlined`属性和`flat`定义为`true`，以及`class`定义为`mx-auto`的`v-card`组件。作为`v-card`组件的子元素，创建一个`v-card-title`组件作为卡片标题；然后，作为同级元素，创建一个`v-divider`组件。之后，创建一个带有`fluid`属性定义为`true`的`v-container`元素。在`v-container`元素内部，创建一个子`v-row`组件：

```js
<v-col
  cols="12" >
 <v-card
  outlined
 flat class="mx-auto"
  >
 <v-card-title>
  Address
    </v-card-title>
 <v-divider/>
 <v-container
  fluid
  >
 <v-row>
      </v-row>
    </v-container>
  </v-card>
</v-col>
```

1.  在`v-container`组件中的`v-row`组件内，创建一个`v-col`组件，其中`cols`属性定义为`12`。然后，添加一个`v-text-field`作为子组件，其中`v-model`指令绑定到`address`变量，`label`属性定义为`Address`：

```js
<v-col
  cols="12" >
 <v-text-field
  v-model="address"
  label="Address"
  /> </v-col>
```

1.  作为同级元素，创建一个`v-col`组件，其中`cols`属性定义为`6`。添加一个`v-text-field`组件作为子元素。将`v-text-field`组件的`v-model`指令绑定到`zipcode`变量，并将`label`属性定义为`Zipcode`：

```js
<v-col
  cols="6" >
 <v-text-field
  v-model="zipcode"
  label="Zipcode"
  /> </v-col>
```

1.  然后，创建一个`v-col`组件，其中`cols`属性定义为`6`。作为子元素添加一个`v-text-field`组件，其中`v-model`指令绑定到`country`变量，`label`属性定义为`Country`：

```js
<v-col
  cols="6" >
 <v-text-field
  v-model="country"
  label="Country"
  /> </v-col>
```

1.  现在我们将创建`用户信息`卡作为`v-row`组件中`v-col`的同级元素。创建一个`v-col`组件，其中`cols`属性定义为`12`。在`v-col`组件内部，创建一个带有`outlined`属性和`flat`定义为`true`，以及`class`定义为`mx-auto`的`v-card`组件。作为`v-card`组件的子元素，创建一个`v-card-title`组件作为卡片标题；然后，作为同级元素，创建一个`v-divider`组件。之后，创建一个带有`fluid`属性定义为`true`的`v-container`元素。在`v-container`元素内部，创建一个子`v-row`组件：

```js
<v-col
  cols="12" >
 <v-card
  outlined
 flat class="mx-auto"
  >
 <v-card-title>
  user Information
    </v-card-title>
 <v-divider/>
 <v-container
  fluid
  >
 <v-row>
      </v-row>
    </v-container>
  </v-card>
</v-col>
```

1.  在`v-container`组件中的`v-row`组件内，创建一个`v-col`组件，其中`cols`属性定义为`6`。然后，添加一个`v-text-field`作为子组件，其中`v-model`指令绑定到`username`变量，`label`属性定义为`username`：

```js
<v-col
  cols="6" >
 <v-text-field
  v-model="username"
  label="username"
  /> </v-col>
```

1.  作为兄弟创建一个`v-col`组件，其中`cols`属性定义为`6`，并添加一个`v-text-field`组件作为子级，其中`v-model`指令绑定到`password`变量，`rules`变量属性定义为`passwordRules`计算属性，`label`属性定义为`Password`：

```js
<v-col
  cols="6" >
 <v-text-field
  v-model="password"
  :rules="passwordRules"
  label="Password"
  type="password"
  required
  /> </v-col>
```

1.  现在我们将创建操作按钮。作为顶部`v-row`组件上的`v-col`的兄弟，创建一个`v-col`组件，其中`cols`属性定义为`12`，`class`属性定义为`text-right`。在`v-col`组件内部，创建一个`v-btn`组件，其中`color`属性定义为`error`，`class`属性为`mr-4`，并将`click`事件侦听器附加到`cancel`方法。最后，创建一个`v-btn`组件作为兄弟，其中`disabled`变量属性为`valid`变量的否定，`color`属性为`success`，`class`属性为`mr-4`，并将`click`事件侦听器附加到`register`方法：

```js
<v-col
  cols="12"
  class="text-right" >
 <v-btn
  color="error"
  class="mr-4"
  @click="cancel"
  >
  Cancel
  </v-btn>
 <v-btn
  :disabled="!valid"
  color="success"
  class="mr-4"
  @click="register"
  >
  Register
  </v-btn> </v-col>
```

## 它是如何工作的...

在这个示例中，我们学习了如何使用 Vuetify 和 Vue-CLI 创建用户注册页面。要创建此页面，我们首先需要使用 Vue-CLI 工具创建项目，然后将 Vuetify 插件添加到其中，以便可以使用该框架。

然后，我们创建了`top-bar`组件，其中包含应用程序标题和菜单按钮切换。为了使用菜单，我们创建了`drawer-menu`组件来容纳导航项。最后，我们创建了`layout`组件来将`top-bar`和`drawer-menu`组件组合在一起，并添加了一个`<slot>`组件来放置页面内容。

对于用户注册表单页面，我们创建了三个包含输入表单的卡片，这些表单与组件上的变量绑定。表单中的一些输入与一组验证规则相关联，用于检查必填字段和电子邮件验证。

最后，在将数据发送到服务器之前，将检查用户注册表单是否有效。

这是最终项目正在运行的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/3a8d48ee-0302-4b60-83f6-e827179bf7bc.png)

## 另请参阅

您可以在[`vuetifyjs.com/en/`](https://vuetifyjs.com/en/)找到有关 Vuetify 的更多信息。

您可以在[`material.io/`](https://material.io/)找到有关 Material Design 的更多信息。

# 使用 Ant-Design 创建页面、布局和用户表单

Ant-Design 框架是由阿里巴巴集团创建的，具体由 AliPay 和 Ant Financial 背后的技术团队创建。它是一个生态系统设计，主要被亚洲科技巨头使用，并且在 React 和 Vue 社区中占据重要地位。专注于后台 UI，框架的主要核心是其解决自定义数据输入和数据表格的解决方案。

在这里，我们将学习如何使用 Ant-Design 和 Vue 创建一个用户注册表单，方法是创建一个顶部栏组件，一个抽屉菜单，一个布局包装器，以及一个带有表单的用户注册页面。

## 准备工作

这个教程的先决条件如下：

+   Node.js 12+

+   一个 Vue-CLI 项目

所需的 Node.js 全局对象如下：

+   `@vue/cli`

+   `@vue/cli-service-global`

## 如何做...

在这个教程中，我们将使用 Ant-Design 框架创建一个用户注册表单。为此，我们将创建一个布局包装器和所需的包装器组件，最后，我们将创建包含用户注册表单的页面。

### 创建 Vue-CLI 项目

我们需要创建一个 Vue-CLI 项目，以便安装 Ant-Design 插件并开始开发用户注册表单：

1.  我们需要打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows）并执行以下命令：

```js
> vue create antd-vue
```

1.  首先，Vue-CLI 会要求您选择一个预设；使用空格键选择`手动选择功能`：

```js
?  Please pick a preset: (Use arrow keys) default (babel, eslint) ❯ **Manually select features**
```

1.  现在 Vue-CLI 将要求选择功能，您需要选择`CSS 预处理器`作为默认功能的附加功能：

```js
?  Check the features needed for your project: (Use arrow keys) ❯ Babel
 TypeScript Progressive Web App (PWA) Support Router Vuex ❯ CSS Pre-processors ❯ Linter / Formatter
 Unit Testing E2E Testing
```

1.  在这里，Vue-CLI 将询问您要使用哪种`CSS 预处理器`；选择`Less`：

```js
?  Pick a CSS pre-processor (PostCSS, Autoprefixer and CSS Modules 
  are supported by default): (Use arrow keys) Sass/SCSS (with dart-sass)  Sass/SCSS (with node-sass) ❯ Less **Stylus** 
```

1.  通过选择一个 linter 和格式化程序来继续这个过程。在我们的情况下，我们将选择`ESLint + Airbnb`配置：

```js
?  Pick a linter / formatter config: (Use arrow keys) ESLint with error prevention only ❯ **ESLint + Airbnb config** ESLint + Standard config 
  ESLint + Prettier
```

1.  选择 linter 的附加功能（这里，`保存时进行 lint`）：

```js
?  Pick additional lint features: (Use arrow keys)  Lint on save  ❯ Lint and fix on commit
```

1.  选择您想要放置的 linter 和格式化程序配置文件的位置（这里，`在专用配置文件中`）：

```js
?  Where do you prefer placing config for Babel, ESLint, etc.?  (Use 
  arrow keys) ❯ **In dedicated config files****In package.json** 
```

1.  最后，CLI 会询问您是否要保存未来项目的设置；您应该选择`N`。之后，Vue-CLI 将为您创建一个文件夹并安装依赖项：

```js
?  Save this as a preset for future projects?  (y/N) n
```

### 将 Ant-Design 添加到 Vue-CLI 项目

将 Ant-Design 框架添加到 Vue-CLI 项目中，我们需要使用 Vue-CLI 插件将框架安装为项目依赖项，并使其在应用程序的全局范围内可用：

1.  在您创建 Vue-CLI 项目的文件夹中，打开终端（macOS 或 Linux）或命令提示符/PowerShell（Windows），并执行以下命令：

```js
> vue add ant-design
```

1.  Vue-CLI 将询问您如何导入 Ant-Design 组件；我们将选择`Fully import`选项：

```js
? How do you want to import Ant-Design-Vue? 
❯ Fully import 
 Import on demand
```

1.  Vue-CLI 将询问您是否要覆盖 Ant-Design 的`LESS`变量；我们将选择`N`：

```js
? Do you wish to overwrite Ant-Design-Vue's LESS variables? (y/N) 
```

1.  最后，Vue-CLI 将询问项目中 Ant-Design 将使用的主要语言；我们将选择`en_US`：

```js
? Choose the locale you want to load 
❯ en_US 
 zh_CN 
 zh_TW 
 en_GB 
 es_ES 
 ar_EG 
 bg_BG 
(Move up and down to reveal more choices)
```

### 使用 Ant-Design 创建布局

为了能够创建用户注册表单，我们将创建一个包装页面内容和表单的基本布局。在这里，我们将创建`top-bar`组件，`drawer-menu`组件和`layout`包装器。

#### 创建顶部栏组件

在`layout`包装器中，我们将有一个`top-bar`组件，用于保存用户当前位置的面包屑。现在我们将创建`top-bar`组件并使其可用于布局：

1.  在`src/components`文件夹中，创建一个名为`TopBar.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个带有`name`属性定义为`TopBar`的`default` JavaScript 对象：

```js
<script> export default {
  name: 'TopBar', }; </script>
```

1.  在单文件组件的`<style>`部分，我们将使`<style>`部分为`scoped`，并创建一个名为`header-bread`的类。现在，`background-color`将被定义为`#f0f2f5`，带有一个名为`bread-menu`的类，边距定义为`16px 0`：

```js
<style scoped>
  .header-bread {
  background-color: #f0f2f5;
  }    .bread-menu {
  margin: 16px 0;
  } </style>
```

1.  在单文件组件的`<template>`部分，我们将创建一个`a-layout-component`组件，`class`属性定义为`header-bread`。还要添加一个`a-breadcrumb`组件作为子元素，`class`属性为`bread-menu`：

```js
<template>
 <a-layout-header class="header-bread">
 <a-breadcrumb class="bread-menu">  </a-breadcrumb>
 </a-layout-header> </template>
```

1.  作为`a-breadcrumb`组件的子组件，创建两个`a-breadcrumb-item`组件，并为每个添加用户位置的方向。在我们的情况下，第一个将是`user`，第二个将是`Registration Form`：

```js
<a-breadcrumb-item>user</a-breadcrumb-item> <a-breadcrumb-item>Registration Form</a-breadcrumb-item>
```

#### 创建抽屉菜单

在布局设计中，我们将有一个抽屉菜单组件作为用户的导航菜单。在这里，我们将创建`Drawer`组件：

1.  在`src/components`文件夹中，创建一个名为`Drawer.vue`的文件并打开它。

1.  在单文件组件的`<script>`部分，我们将导出一个带有两个属性的`default` JavaScript 对象。`name`属性定义为`Drawer`，`data`属性定义为返回 JavaScript 对象的`singleton`函数。在`data`属性中，创建以下内容：

+   一个`drawer`属性，定义为`false`。

+   一个`menu`属性，我们将其定义为将要使用的菜单项数组。菜单数组将包含三个 JavaScript 对象，具有`name`和`icon`属性。这个数组将包括：

+   一个 JavaScript 对象，属性`name`定义为`Home`，`icon`定义为`home`

+   一个 JavaScript 对象，属性`name`定义为`Ant Design Vue`，`icon`定义为`ant-design`

+   一个 JavaScript 对象，属性`name`定义为`Contact`，`icon`定义为`mail`：

```js
<script> export default {
  name: 'Drawer',
  data: () => ({
  drawer: false,
  menu: [
 {  name: 'Home',
  icon: 'home',
  },
  {
  name: 'Ant Design Vue',
  icon: 'ant-design',
  },
  {
  name: 'Contact',
  icon: 'mail',
  },
  ],
  }), }; </script>
```

1.  在单文件组件的`<template>`部分，创建一个`a-layout-sider`组件，`v-model`指令绑定到`drawer`变量，`collapsible`属性定义为`true`。作为子组件，创建一个`a-menu`组件，`default-selected-keys`变量属性定义为`['1']`，`theme`属性定义为`dark`，`mode`属性定义为`inline`：

```js
<template>
 <a-layout-sider
  v-model="drawer"
  collapsible
  >
 <a-menu
  :default-selected-keys="['1']"
  theme="dark"
  mode="inline"
  >  </a-menu>
 </a-layout-sider> </template>
```

1.  最后，在`a-menu`组件内部，创建一个`a-menu-item`组件，使用`v-for`指令迭代`menu`变量，并创建`item`和`index`临时变量。然后，将`key`变量属性定义为`index`。创建一个子`AIcon`组件，`type`变量属性定义为`item.icon`，并创建一个兄弟`span` HTML 元素，内容为`item.name`：

```js
<a-menu-item
  v-for="(item,index) in menu"
  :key="index" >
 <a-icon
  :type="item.icon"
  />
 <span>{{ item.name }}</span> </a-menu-item>
```

#### 创建布局组件

在这里，我们将创建`layout`组件。这个组件将把`top-bar`组件和`Drawer`菜单组件连接起来，作为用户注册页面的包装器：

1.  在`src/components`文件夹中，创建一个名为`Layout.vue`的新文件并打开它。

1.  在单文件组件的`<script>`部分，导入`top-bar`组件和`drawer-menu`组件：

```js
import TopBar from './TopBar.vue'; import Drawer from './Drawer.vue';
```

1.  然后，我们将导出一个`default`的 JavaScript 对象，带有一个`name`属性，定义为`layout`。然后定义`components`属性，包括导入的组件。

```js
export default {
  name: 'layout',
  components: {
  Drawer,
  TopBar,
  },  };
```

1.  在单文件组件的`<template>`部分，创建一个`a-layout`组件，`style`属性定义为`min-height: 100vh`。然后，将`Drawer`组件作为子组件添加。作为`drawer`组件的兄弟，创建一个`a-layout`组件：

```js
<template>
 <a-layout
  style="min-height: 100vh"
  >
 <drawer />
 <a-layout>
 <top-bar />
 <a-layout-content style="margin: 0 16px">
 <div style="padding: 24px; background: #fff; 
            min-height: auto;">
 <slot />
 </div>
 </a-layout-content>
 <a-layout-footer style="text-align: center">
  Vue.js 3 Cookbook | Ant Design ©2020 Created by Ant UED
      </a-layout-footer>
 </a-layout>
 </a-layout> </template>
```

1.  向`a-layout`组件添加`top-bar`组件和一个兄弟`a-layout-content`组件，其中`style`属性定义为`margin: 0 16px`。作为该组件的子元素，创建一个`div` HTML 元素，其中`style`属性定义为`padding: 24px; background: #fff; min-height: auto;`，并添加一个`slot`占位符。最后，创建一个`a-layout-footer`组件，其中`style`属性定义为`text-align:center;`，并添加页面的页脚文本：

```js
<top-bar /> <a-layout-content style="margin: 0 16px">
 <div style="padding: 24px; background: #fff; min-height: auto;">
 <slot />
 </div> </a-layout-content> <a-layout-footer style="text-align: center">
  Vue.js 3 Cookbook | Ant Design ©2020 Created by Ant UED
</a-layout-footer>
```

### 使用 Ant-Design 创建用户注册表单

现在我们将创建用户注册页面和表单，该表单将放在前面步骤中创建的布局中。

#### 单文件组件<script>部分

在这里，我们将创建单文件组件的`<script>`部分：

1.  在`src`文件夹中，打开`App.vue`文件并清空其内容。

1.  导入`layout`组件：

```js
import Layout from './components/Layout.vue';
```

1.  然后，我们将导出一个`default`JavaScript 对象，其中`name`属性定义为`App`，定义导入组件的`components`属性，并最后将`data`属性定义为返回 JavaScript 对象的单例函数。在`data`属性中，创建以下内容：

+   一个`labelCol`属性，定义为 JavaScript 对象，其中`span`属性和值为`4`。

+   一个`wrapperCol`属性，定义为 JavaScript 对象，其中`span`属性和值为`14`。

+   一个`form`属性，定义为 JavaScript 对象，其中`name`，`username`，`password`，`email`，`phone`，`cellphone`，`address`，`zipcode`和`country`属性都定义为空字符串：

```js
export default {
  name: 'App',
  components: {
  Layout,
  },
  data() {
  return {
  labelCol: { span: 4 },
  wrapperCol: { span: 14 },
  form: {
  name: '',
  username: '',
  password: '',
  email: '',
  phone: '',
  cellphone: '',
  address: '',
  zipcode: '',
  country: '',
  },
  };
  }, };
```

#### 单文件组件<template>部分

现在是时候创建单文件组件的`<template>`部分了：

1.  在`src`文件夹中，打开`App.vue`文件。

1.  在`<template>`部分，创建一个`layout`组件元素，并添加一个`a-form-model`组件作为子元素，其中`model`变量属性绑定到`form`，`label-col`变量属性绑定到`labelCol`，`wrapper-col`变量属性绑定到`wrapperCol`：

```js
<layout>
 <a-form-model
  :model="form"
  :label-col="labelCol"
  :wrapper-col="wrapperCol"
  >
  </a-form-model>
</layout>
```

1.  然后，作为`layout`组件的兄弟组件，创建一个`h1` HTML 元素，页面标题为`用户注册`，以及一个`p` HTML 元素，页面副标题为`主用户注册表单`。然后，创建一个`a-card`元素，其中`title`属性定义为`个人信息`：

```js
<h1>
 User Registration
</h1> <p>Main user registration form</p> <a-card title="Personal Information"></a-card>
```

1.  在`a-card`组件中，创建一个`a-form-model-item`组件作为子元素，其中`label`属性定义为`姓名`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.name`变量：

```js
<a-form-model-item label="Name">
 <a-input v-model="form.name" /> </a-form-model-item>
```

1.  接下来，作为兄弟元素，创建一个`a-form-model-item`组件，其中`label`属性定义为`电子邮件`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.email`变量，`type`属性定义为`email`：

```js
<a-form-model-item label="Email">
 <a-input
  v-model="form.email"
  type="email"
  /> </a-form-model-item>
```

1.  创建一个`a-form-model-item`组件，其中`label`属性定义为`电话`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.phone`变量：

```js
<a-form-model-item label="Phone">
 <a-input v-model="form.phone" /> </a-form-model-item>
```

1.  创建一个`a-form-model-item`组件，其中`label`属性定义为`手机号码`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.cellphone`变量：

```js
<a-form-model-item label="Cellphone">
 <a-input v-model="form.cellphone" /> </a-form-model-item>
```

1.  作为`a-card`组件的兄弟元素，创建一个`a-card`组件，其中`title`属性定义为`地址`，`style`属性定义为`margin-top: 16px;`。然后，添加一个子`a-form-model-item`组件，其中`label`属性定义为`地址`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.address`变量。

```js
<a-card title="Address" style="margin-top: 16px">
 <a-form-model-item label="Address">
 <a-input v-model="form.address" />
 </a-form-model-item>  </a-card>
```

1.  接下来，作为`a-card`组件的兄弟元素，创建一个`a-form-model-item`组件，其中`label`属性定义为`邮政编码`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.zipcode`变量：

```js
<a-form-model-item label="Zipcode">
 <a-input v-model="form.zipcode" /> </a-form-model-item>
```

1.  创建一个`a-form-model-item`组件，其中`label`属性定义为`国家`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.country`变量：

```js
<a-form-model-item label="Country">
 <a-input v-model="form.country" /> </a-form-model-item>
```

1.  作为`a-card`组件的兄弟元素，创建一个`a-card`组件，其中`title`属性定义为`用户信息`，`style`属性定义为`margin-top: 16px;`。然后，添加一个子`a-form-model-item`组件，其中`label`属性定义为`用户名`，并添加一个子`a-input`组件，其中`v-model`指令绑定到`form.username`变量：

```js
<a-card title="user Information" style="margin-top: 16px">
 <a-form-model-item label="username">
 <a-input v-model="form.username" />
 </a-form-model-item>  </a-card>
```

1.  创建一个`a-form-model-item`组件，其中`label`属性定义为`密码`，并添加一个子`a-input-password`组件，其中`v-model`指令绑定到`form.password`变量，`visibility-toggle`属性定义为`true`，`type`属性定义为`password`：

```js
<a-form-model-item label="Password">
 <a-input-password
  v-model="form.password"
  visibility-toggle
 type="password"
  /> </a-form-model-item>
```

1.  最后，作为`a-card`组件的一个兄弟组件，创建`a-form-model-item`，并将`wrapper-col`变量属性定义为 JavaScript 对象`{span: 14, offset: 4}`。然后，添加一个子`a-button`，其中`type`定义为`primary`，文本为`Create`，另一个`a-button`，其中`style`属性定义为`margin-left: 10px;`，文本为`Cancel`：

```js
<a-form-model-item :wrapper-col="{ span: 14, offset: 4 }">
 <a-button type="primary">
  Create
  </a-button>
 <a-button style="margin-left: 10px;">
  Cancel
  </a-button> </a-form-model-item>
```

## 它是如何工作的...

在这个示例中，我们学习了如何使用 Ant-Design 和 Vue-CLI 创建用户注册页面。为了创建这个页面，我们首先需要使用 Vue-CLI 创建一个项目，并向其中添加 Ant-Design of Vue 插件，以便可以使用该框架。

然后，我们创建了`top-bar`组件，用于保存导航面包屑。为了用户导航，我们创建了一个自定义的`Drawer`组件，底部带有内联切换按钮。最后，我们创建了`layout`组件，将这两个组件放在一起，并添加了一个`<slot>`组件来放置页面内容。

最后，我们创建了用户注册表单页面，其中包含三个卡片，用于保存与组件上的变量绑定的输入表单。

这是最终项目正在运行的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue3-cb/img/b9e35ec5-200d-4c1a-9ae4-feed1cb1bb07.png)

## 另请参阅

您可以在[`vue.ant.design/`](https://vue.ant.design/)找到有关 Ant-Design 和 Vue 的更多信息。
