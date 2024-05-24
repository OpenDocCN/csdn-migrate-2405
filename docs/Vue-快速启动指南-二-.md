# Vue 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7`](https://zh.annas-archive.org/md5/056a1fe7509ea158cc95e0fe373880b7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：过滤器和混合器

在本章中，我们将展示如何使用过滤器来更改屏幕上呈现的内容，而不更改基础数据。我们还将介绍混合器，这是一种扩展组件并遵守编程的 DRY 规则的实用方法。

更具体地，在本章中，我们将讨论以下内容：

+   使用过滤器：

+   使用全局和本地过滤器

+   用过滤器替换条件指令

+   链接过滤器

+   使用混合器：

+   避免在混合器方法中重复代码

+   使用数据选项为我们的混合器添加更多功能

+   在混合器中使用生命周期钩子

# 使用过滤器

过滤器只是一个函数。它接受一些数据（作为参数传递给过滤器函数），并对该数据执行一些简单的操作。执行的操作的结果从过滤器函数返回，并显示在应用程序中的适当位置。重要的是要注意，过滤器不会影响基础数据；它们只会影响数据在屏幕上的显示方式。

就像组件一样，过滤器也可以注册为全局或本地。注册全局过滤器的语法如下：

```js
Vue.filter('justAnotherFilter', function(someData1, someData2, someDataN) {
  // the filter function definition goes here (it takes N number of arguments)
});
```

除了全局注册，我们还可以像这样在本地注册过滤器：

```js
filters: {
  justAnotherFilter(someData1, someData2, someDataN) {
    // the filter function is defined here...
  }
}
```

正如我们在这里所看到的，在本地注册的情况下，过滤器被添加为 Vue 组件的选项。

# 一个将学生成绩四舍五入的过滤器示例

假设我们有一个朋友是教授，他们需要一些帮助来处理他们学生的测试。学生参加的测试总是以小数形式产生分数。学生可以在该测试中获得的分数范围在 0 到 100 之间。

作为我们的好朋友，我们将制作一个简单的 Vue 应用程序，其中包含一个将小数分数四舍五入为整数的过滤器。我们还会偏向于学生，这意味着我们将始终将结果四舍五入。

此示例的代码可在[`codepen.io/AjdinImsirovic/pen/MqBNBR`](https://codepen.io/AjdinImsirovic/pen/MqBNBR)上找到。

我们的过滤器函数将非常简单：它将接受一个浮点数，并根据接收到的浮点数返回一个四舍五入的整数。过滤器函数将被称为`pointsRoundedUp`，并且看起来像这样：

```js
  filters: {
    pointsRoundedUp(points){
      return Math.ceil(parseFloat(points));
    }
  }
```

因此，我们的`pointsRoundedUp`函数接受来自应用程序`data()`函数的`points`实例，并使用 JavaScript 的内置`parseFloat()`和`Math.ceil()`函数调用`points`值返回这些`points`实例。

在我们的 HTML 中使用过滤器时，我们采用以下语法：

```js
{{ points| pointsRoundedUp }}
```

`points`值是应用程序中存储的实际数据。`pointsRoundedUp`是我们用来格式化从 Vue 组件的数据选项接收到的数据的过滤器。

一般来说，我们可以说所有过滤器的基本逻辑如下：

```js
{{ data | formattedData }}
```

这个一般原则可以这样阅读：为了格式化返回的数据，我们用管道符号(`|`)跟着调用特定的过滤器。

让我们检查一下我们应用程序的完整代码。HTML 将如下所示：

```js
<div id="app">
 <h1>A simple grade-rounding Vue app</h1>
 <p>Points from test: {{ points }}</p>
 <p>Rounded points are: {{ points | pointsRoundedUp }}</p>
</div>
```

JS 也将很简单：

```js
new Vue({
  el: "#app",
  data() {
    return {
      points: 74.44
    }
  },
  filters: {
    pointsRoundedUp(points){
      return Math.ceil(parseFloat(points));
    }
  }
});
```

应用程序将在屏幕上输出以下内容：

```js
A simple grade-rounding Vue app
Points from test: 74.44
Rounded points are: 75
```

应用程序现在已经完成。

然而，过了一段时间，我们的朋友又向我们请求另一个帮助：根据分数计算学生的等级。最初，我们意识到这只是一个小小的计算，我们可以简单地将其放入条件指令中。

更新示例的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/XPPrEN`](https://codepen.io/AjdinImsirovic/pen/XPPrEN)。

基本上，我们在这个新示例中所做的是用几个条件指令扩展了我们的 HTML。虽然这解决了问题，但我们混乱了我们的 HTML，而我们的 JS 保持不变。更新后的 HTML 代码如下：

```js
<div id="app">
  <h1>A simple grade-rounding Vue app</h1>
  <p>Points from test: {{ points }}</p>
  <p>Rounded points are: {{ points | pointsRoundedUp }}</p>
  <p v-if="points > 90">Final grade: A</p>
  <p v-else-if="points > 80 && points <= 90">Final grade: B</p>
  <p v-else-if="points > 70 && points <= 80">Final grade: C</p>
  <p v-else-if="points > 60 && points <= 70">Final grade: D</p>
  <p v-else-if="points > 50 && points <= 86">Final grade: E</p>
  <p v-else="points <= 50">Final grade: F</p>
</div>
```

我们的问题得到了解决。这次测试的分数是 94.44，应用程序成功地将以下信息打印到屏幕上：

```js
A simple grade-rounding Vue app
Points from test: 94.44
Rounded points are: 95
Final grade: A
```

然而，我们意识到我们的 HTML 现在很混乱。幸运的是，我们可以利用过滤器使事情变得不那么混乱。

# 使用过滤器替换条件指令

在本节中，我们将使用过滤器返回学生的适当等级。

更新后的应用程序代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/LJJPKm`](https://codepen.io/AjdinImsirovic/pen/LJJPKm)。

我们对该应用程序的 HTML 所做的更改如下：

```js
<div id="app">
  <h1>A simple grade-rounding Vue app</h1>
  <p>Points from test: {{ points }}</p>
  <p>Rounded points are: {{ points | pointsRoundedUp }}</p>
  <p>Final grade: {{ points | pointsToGrade }}</p>
</div>
```

我们将条件功能移到了我们的 JavaScript 中，即一个名为`pointsToGrade`的新过滤器中：

```js
new Vue({
  el: "#app",
  data() {
    return {
      points: 84.44
    }
  },
  filters: {
    pointsRoundedUp(points){
      return Math.ceil(parseFloat(points));
    },
    pointsToGrade(points){
      if(points>90) {
        return "A"
      } else if(points>80 && points<=90) {
        return "B"
      } else if(points>70 && points<=80) {
        return "C"
      } else if(points>60 && points<=70) {
        return "D"
      } else if(points>50 && points<=60) {
        return "E"
      } else {
        return "F"
      }
    }
  }
});
```

作为对我们更新的代码进行快速测试，我们还将点数更改为 84.44，成功地从`pointsToGrade`过滤器返回了 B 等级。

然而，不完全出乎意料的是，我们的朋友再次回来，并要求我们再次扩展应用程序。这一次，我们需要再次显示我们学生的姓名的正确格式，格式如下：

```js
Last name, First name, year of study, grade.
```

这意味着我们将不得不扩展我们的应用程序以获得额外的功能。幸运的是，这不难，因为我们可以利用过滤器的另一个很好的特性：链接。

# 在 Vue 中链接过滤器

我们应用的要求已经更新，现在我们需要在屏幕上显示一些额外的、格式良好的数据。

由于要求已经改变，我们还需要更新数据。

本节的代码可在此处找到：[`codepen.io/AjdinImsirovic/pen/BOOazy`](https://codepen.io/AjdinImsirovic/pen/BOOazy)。

这是更新后的 JavaScript。首先，我们将添加`el`和`data`选项：

```js
new Vue({
  el: "#app",
  data() {
    return {
      firstName: "JANE",
      lastName: "DOE",
      yearOfStudy: 1, 
      points: 84.44,
      additionalPoints: 8
    }
  },
```

在 JS 中，我们将添加过滤器：

```js
  filters: {
    pointsRoundedUp(points){
      return Math.ceil(parseFloat(points));
    },
    pointsToGrade(points){
      if(points>90) {
        return "A"
      }
      else if(points>80 && points<=90) {
        return "B"
      }
      else if(points>70 && points<=80) {
        return "C"
      }
      else if(points>60 && points<=70) {
        return "D"
      }
      else if(points>50 && points<=60) {
        return "E"
      }
      else {
        return "F"
      }
    },
    yearNumberToWord(yearOfStudy){
      // freshman 1, sophomore 2, junior 3, senior 4 
      if(yearOfStudy==1) {
        return "freshman"
      } else if(yearOfStudy==2){
        return "sophomore"
      } else if(yearOfStudy==3){
        return "junior"
      } else if(yearOfStudy==4){
        return "senior"
      } else {
        return "unknown"
      }
    },
    firstAndLastName(firstName, lastName){
      return lastName + ", " + firstName
    },
    toLowerCase(value){
      return value.toLowerCase()
    },
    capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
  }
});
```

更新后的 HTML 如下所示：

```js
<div id="app">
  <h1>A simple grade-rounding Vue app</h1>
  <p>Points from test: {{ points }}</p>
  <p>Rounded points are: {{ points | pointsRoundedUp }}</p>
  <p>Student info: 
  <!--
  <p>Name: {{ firstName, lastName | firstAndLastName | toLowerCase | capitalizeFirstLetter}}</p>
  -->
  <p>
    Name: 
    {{ lastName | toLowerCase | capitalizeFirstLetter }}, 
    {{ firstName | toLowerCase | capitalizeFirstLetter }}
  </p>
  <p>Year of study: {{ yearOfStudy | yearNumberToWord }}</p>
  <p>Final grade: <strong>{{ points | pointsToGrade }}</strong></p>
</div>
```

通过这些链接的过滤器，我们通过两个过滤器`toLowerCase`和`capitalizeFirstLetter`正确格式化了学生的姓名，通过这两个过滤器将数据（以全大写形式出现）传递过去。

我们还可以看到一个被注释掉的段落，显示了一个不成功的方法，它只将姓氏的第一个字母大写，而不是名字的第一个字母。原因是`firstAndLastName`过滤器，当应用时，将全名组合成一个字符串。

请注意，过滤器不会被缓存，这意味着它们将始终被运行，就像方法一样。

有关过滤器的更多信息，请参阅官方文档：[`vuejs.org/v2/guide/filters.html`](https://vuejs.org/v2/guide/filters.html)。

# 使用混合

混合是我们在 Vue 代码中抽象出可重用功能的一种方式。在前端世界中，由 Sass 广泛使用，混合的概念现在出现在许多现代 JavaScript 框架中。

当我们有一些功能希望在多个组件中重用时，最好使用混合。在接下来的例子中，我们将创建一个非常简单的 Vue 应用程序，在页面上显示两个 Bootstrap 警报。当用户点击其中任何一个警报时，浏览器的视口尺寸将被记录到控制台中。

为了使这个例子工作，我们需要从 Bootstrap 框架中获取一些普通的 HTML 组件。具体来说，我们将使用警报组件。

关于这个 Bootstrap 组件的官方文档可以在这个链接找到：[`getbootstrap.com/docs/4.1/components/alerts/`](https://getbootstrap.com/docs/4.1/components/alerts/)。

重要的是要注意，Bootstrap 组件和 Vue 组件是不同的东西，不应混淆。

运行应用程序时，将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-qk-st-gd/img/e09d84d6-6887-4b67-b0b4-470f14216b0f.png)

这个例子的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/jvvybq`](https://codepen.io/AjdinImsirovic/pen/jvvybq)。

# 在不同组件中构建具有重复功能的简单应用程序

首先，让我们构建我们简单的 HTML：

```js
<div id="app">
  <div class="container mt-4">
    <h1>{{heading}}</h1>
    <primary-alert></primary-alert>
    <warning-alert></warning-alert>
  </div>
</div>
```

我们正在使用 Bootstrap 的`container`和`mt-4`的 CSS 类。常规的 HTML `h1`标签也获得了一些特定于 Bootstrap 的样式。我们还在前面的代码中使用了两个 Vue 组件：`primary-alert`和`warning-alert`。

在我们的 JavaScript 代码中，我们将这两个组件定义为`primaryAlert`和`warningAlert`，然后在它们的父组件的`components`选项中列出它们：

```js
const primaryAlert = {
  template: `
    <div class="alert alert-primary" role="alert" v-on:click="viewportSizeOnClick">
      A simple primary alert—check it out!
    </div>`,
    methods: {
    viewportSizeOnClick(){
      const width = window.innerWidth;
      const height = window.innerHeight;
      console.log("Viewport width:", width, "px, viewport height:", height, "px");
    }
  }
}
const warningAlert = {
  template: `
    <div class="alert alert-warning" role="alert" v-on:click="viewportSizeOnClick">
      A simple warning alert—check it out!
    </div>`,
    methods: {
    viewportSizeOnClick(){
      const width = window.innerWidth;
      const height = window.innerHeight; 
      console.log("Viewport width:", width, "px, viewport height:", height, "px");
    }
  }
}
```

现在，仍然在 JS 中，我们可以指定构造函数：

```js
new Vue({
  el: '#app',
  data() {
    return {
      heading: 'Extracting reusable functionality into mixins in Vue'
    }
  },
  components: {
    primaryAlert: primaryAlert,
    warningAlert: warningAlert
  }
})
```

要查看这个小应用程序的结果，请打开控制台并单击两个警报组件中的任何一个。控制台输出将类似于以下内容：

```js
Viewport width: 930 px, viewport height: 969 px
```

正如我们在 JavaScript 代码中所看到的，我们还定义了一个`viewportSizeOnClick`

方法在`primaryAlert`和`warningAlert`组件的`methods`选项内。这种功能上的不必要重复是一个完美的抽象成 mixin 的候选，接下来我们将这样做。

# 使用 mixin 保持 DRY

改进后的应用程序的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/NLLgWP`](https://codepen.io/AjdinImsirovic/pen/NLLgWP)。

在这个例子中，虽然我们的 HTML 保持完全相同，但更新后的 JavaScript 代码将如下所示：

```js
const viewportSize = {
    methods: {
      viewportSizeOnClick(){
        const width = window.innerWidth;
        const height = window.innerHeight;
        console.log("Viewport width:", width, "px, viewport height:", height, "px");
      }
  } 
}
const primaryAlert = {
  template: `
    <div class="alert alert-primary" role="alert" v-on:click="viewportSizeOnClick">
      A simple primary alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
const warningAlert = {
  template: `
    <div class="alert alert-warning" role="alert" v-on:mouseenter="viewportSizeOnClick">
      A simple warning alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
new Vue({
  el: '#app',
  data() {
    return {
      heading: 'Extracting reusable functionality into mixins in Vue'
    }
  },
  components: {
    primaryAlert: primaryAlert,
    warningAlert: warningAlert
  }
})
```

正如在这里所看到的，我们已经从两个组件中删除了`methods`选项，并添加了一个名为`viewportSize`的新对象。在这个对象内部，我们已经移动了共享的`methods`选项：

```js
const viewportSize = {
    methods: {
      viewportSizeOnClick(){
        const width = window.innerWidth;
        const height = window.innerHeight;
        console.log("Viewport width:", width, "px, viewport height:", height, "px");
      }
  } 
}
```

`methods`选项只包含`viewportSizeOnClick`函数。

顺便说一句，`vieportSizeOnClick`方法的名称有点误导。如果你仔细看第二个组件（`warningAlert`组件）的代码，你会注意到我们更新了指令，所以它使用的是`v-on:mouseenter`，而不是`v-on:click`。这意味着方法的名称需要更改为更合适的名称。因此，我们将把方法重命名为`logOutViewportSize`。

另外，让我们想象一下，我们希望以另一种方式显示视口信息。例如，我们可能会在警报框中显示它，而不是将其记录到控制台中。这就是为什么我们将引入另一种方法`alertViewportSize`。

随着所有这些小改变的积累，现在是时候看到我们小应用的另一个更新版本了。新的代码可以在以下网址找到：[`codepen.io/AjdinImsirovic/pen/aaawJY`](https://codepen.io/AjdinImsirovic/pen/aaawJY)。

与以前的更新类似，更新后的示例只有对 JS 进行了更改，如下所示。我们从`viewportSize`开始：

```js
const viewportSize = {
    methods: {
      logOutViewportSize(){
        const width = window.innerWidth;
        const height = window.innerHeight; 
        console.log("Viewport width:", width, "px, viewport height:", height, "px");
      },
      alertViewPortSize() {
        const width = window.innerWidth;
        const height = window.innerHeight;
        alert("Viewport width: " + width + " px, viewport height: " + height + " px");
      }
  }
}
```

接下来，我们将设置警报：

```js
const primaryAlert = {
  template: `
    <div class="alert alert-primary" role="alert" v-on:click="alertViewPortSize">
      A simple primary alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
const warningAlert = {
  template: `
    <div class="alert alert-warning" role="alert" v-on:mouseenter="logOutViewportSize">
      A simple warning alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
```

最后，让我们用指定 Vue 构造函数来结束：

```js
new Vue({
  el: '#app',
  data() {
    return {
      heading: 'Extracting reusable functionality into mixins in Vue'
    }
  },
  components: {
    primaryAlert: primaryAlert,
    warningAlert: warningAlert
  }
})
```

在下一节中，我们将看看如何通过重构来进一步改进我们的混合方法。

# 重构我们的 viewportSize 混合方法

在本节中，我们将探讨进一步改进我们的混合方法。虽然我们的代码既可读又易于理解，但在`const`声明中存在一些代码重复。此外，我们将利用这个机会来探讨混合重构的方法。更新后的代码将包括一些基本的事件处理。

有关可用事件的列表，请参阅此链接：[`developer.mozilla.org/en-US/docs/Web/Events`](https://developer.mozilla.org/en-US/docs/Web/Events)。

由于我们还将使用 JavaScript 的内置`addEventListener()`方法，因此也很有必要在 MDN 上获取有关它的更多信息，网址如下：[`developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener)。

在我们开始重构之前，我们将利用混合的能力来插入 Vue 的生命周期功能（就像组件一样）。此外，在我们的混合的这个迭代中，我们除了`methods`之外还引入了另一个选项。我们使用的选项是`data`。为了避免在混合的`methods`选项中重复`const`声明，我们将要处理的值存储在`data`选项中。

虽然 HTML 仍然保持不变，但我们的 JavaScript 文件将会有很大的不同。让我们从设置数据开始：

```js
const viewportSize = {
    data(){
      return {
        viewport: {
          width: 0,
          height: 0
        }
      }
    },
```

接下来，我们将添加方法，即`getViewportSize`、`logOutViewportSize`和`alertViewportSize`：

```js
    methods: {
      measureViewportSize(){
        this.viewport.width = window.innerWidth;
        this.viewport.height = window.innerHeight;
      },
      logOutViewportSize(){
        console.log("Viewport width:", this.viewport.width, "px, viewport height:", this.viewport.height, "px");
      },
      alertViewPortSize() {
        alert("Viewport width: " + this.viewport.width + " px, viewport height: " + this.viewport.height + " px");
      }
  },
```

接下来，让我们添加`created`：

```js
created() {
    this.listener =
      window.addEventListener('mousemove',this.measureViewportSize); 
    this.measureViewportSize();
 }
}
```

现在，我们可以设置`primaryAlert`：

```js
const primaryAlert = {
  template: `
    <div class="alert alert-primary" role="alert" v-on:click="alertViewPortSize">
      A simple primary alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
```

我们将继续添加`warningAlert`：

```js
const warningAlert = {
  template: `
    <div class="alert alert-warning" role="alert" v-on:mouseenter="logOutViewportSize">
      A simple warning alert—check it out!
    </div>`,
  mixins: [viewportSize]
}
```

最后，让我们添加 Vue 构造函数：

```js
new Vue({
  el: '#app',
  data() {
    return {
      heading: 'Extracting reusable functionality into mixins in Vue'
    }
  },
  components: {
    primaryAlert: primaryAlert,
    warningAlert: warningAlert
  }
})
```

本节的代码可以在以下代码 pen 中找到：[`codepen.io/AjdinImsirovic/pen/oPPGLW`](https://codepen.io/AjdinImsirovic/pen/oPPGLW)。

在我们重构的混合中，我们有`data`、`methods`和`created`这些选项。`created`函数是一个生命周期钩子，我们使用这个钩子来监听`mousemove`事件。当发生这样的事件时，我们运行我们的混合的`this.getViewportSize`方法，该方法更新视口尺寸，然后将其记录下来或显示在警报框中。

永远不要使用全局混合！全局混合会影响应用程序中的所有组件。这种情况并不多见，所以通常最好避免使用全局混合。

通过这个，我们结束了对 Vue 中混合的简要讨论。有关此主题的更多信息，请访问此官方链接：

[`vuejs.org/v2/guide/mixins.html`](https://vuejs.org/v2/guide/mixins.html)

# 总结

在本章中，我们讨论了 Vue 中的过滤器和混合。我们讨论了在何种情况下使用过滤器是有意义的，并且我们看了一下如何使用全局和本地过滤器。我们还讨论了过滤器如何用来替换条件指令，并且我们研究了如何将过滤器串联在一起。

我们还探讨了如何通过将功能从组件移动到混合中来抽象可重用功能，并且我们看了一下如何避免在混合本身内部重复代码。我们用一个在混合中使用生命周期钩子的例子来结束了这一部分。

在下一章中，我们将看看如何构建我们自己的自定义指令。


# 第五章：制作您自己的指令和插件

在这一章中，我们将看看扩展 Vue 的方法。首先，我们将编写自己的指令并看看如何使用它们。接下来，我们将制作一个自定义的 Vue 插件。

更具体地，在这一章中，我们将研究以下内容：

+   自定义指令的结构以及如何制作它们

+   使用全局和本地自定义指令

+   向自定义指令传递值

+   编写 Vue 插件

+   发布 Vue 插件

# 制作我们自己的指令

在 Vue 2 中，组件是使用的主要策略，无论是保持 DRY 还是抽象化一些功能。然而，你可以采取的另一种方法是利用自定义指令。

# 理解自定义指令

正如我们在本书中之前讨论过的，指令帮助我们解释给 Vue 什么样的行为我们想要附加到一段标记上。正如我们之前看到的，Vue 内置了许多指令。一些例子是`v-on`，`v-if`，`v-model`等等。简单回顾一下，指令是以`v-`开头的 HTML 属性。

当我们需要构建一个自定义指令时，我们只需在连字符后面提供一个自定义单词。例如，我们可以创建一个自定义指令，我们将其称为`v-custom-directive`，然后我们可以在我们的标记中使用这个名称，例如，像这样：

```js
<div id="app">
  <div v-custom-directive>{{ something }}</div>
<!-- etc -->
```

请注意，拥有一个没有值的指令是完全正常的，就像为它提供一个值一样，就像这样：

```js
<div id="app">
  <div v-custom-directive="aValue">{{ something }}</div>
<!-- etc -->
```

接下来，在我们的 JS 代码中，我们需要注册这个指令，如下所示：

```js
Vue.directive('customDirective', {
  // details for the directive go here
}
```

因此，正如我们所看到的，提供给`Vue.directive`的第一个参数是我们自定义指令的名称。请注意，Vue 在 HTML 中使用 kebab-case，而在 JS 中使用 lowerCamelCase 的约定也适用于自定义指令。

提供给我们自定义指令的第二个参数是一个包含所有指令功能的对象。

正如你现在可能推断的那样，前面的代码给出了全局注册指令的一个例子。如果你想要本地注册一个指令，你需要为特定组件指定一个`directives`选项。

例如，我们可以注册一个本地组件如下：

```js
directives: {
  directiveName: {
    // some code to describe functionality
  }
}
```

就像组件一样，指令也使用钩子，这允许我们控制它们的功能何时被调用。有五个指令钩子：`bind`，`inserted`，`update`，`componentUpdated`和`unbind`。

有关某些这些钩子可以接受的参数的完整列表，您可以参考[`vuejs.org/v2/guide/custom-directive.html#Directive-Hook-Arguments`](https://vuejs.org/v2/guide/custom-directive.html#Directive-Hook-Arguments)。

# 构建一个简单的自定义指令

此示例的完整代码在此处可用：[`codepen.io/AjdinImsirovic/pen/yxWObV`](https://codepen.io/AjdinImsirovic/pen/yxWObV)。

在我们的 HTML 中，我们将添加以下简单代码：

```js
<div id="app" class="container mt-5">
  <h1 class="h2">{{ heading }}</h1>
  <div v-custom-directive>
    Just some text here
  </div>
</div>
```

在我们的 JS 中，我们将全局添加我们的`customDirective`：

```js
Vue.directive('customDirective', {
  inserted: function(el) {
    el.style.cssText = `
      color: blue; 
      border: 1px solid black; 
      background: gray; 
      padding: 20px; 
      width: 50%;
    `
  }
});

new Vue({
  el: '#app',
  data() {
    return {
      heading: 'A custom global directive'
    }
  }
});
```

在先前的代码中，我们使用了`inserted`指令钩子。使用此钩子，当将指令绑定到的元素*插入*到其父节点中时，将运行指令的代码。

当这种情况发生时，该元素将根据我们分配给`el.style.cssText`的值进行样式设置。

当然，没有什么能阻止我们在一个元素上使用多个自定义指令。例如，我们可以指定几个自定义指令，然后根据需要混合和匹配它们。

在下一节中，我们将重写全局自定义指令为本地自定义指令。

# 使用本地指令

现在让我们看看如何重写先前的代码，使我们的指令使用本地指令而不是全局指令。

在本节中，我们将构建一个非常简单的自定义指令。我们将使用第四章中的一个示例，*过滤器和混合*，并在此基础上构建，以便我们可以轻松地将其与先前的示例进行比较，只是这次使用一个简单的本地自定义指令。

此示例的代码在此处可用：[`codepen.io/AjdinImsirovic/pen/yxWJNp`](https://codepen.io/AjdinImsirovic/pen/yxWJNp)。

在我们的 HTML 中，我们将指定以下代码：

```js
<main id="app">
    <custom-article v-custom-directive></custom-article>
    <custom-article></custom-article>
    <another-custom-article v-another-custom></another-custom-article>
</main>
```

在我们的 JS 中，我们将指定以下代码：

```js
const anotherCustom = {
  inserted: function(el) {
    el.style.cssText = `
      color: green; 
      border: 1px solid black; 
      background: yellow; 
      padding: 20px; 
      width: 50%;
    ` 
  }
}

const customArticle = {
  template: `
    <article>
      Our own custom article component!
    </article>`
}

Vue.component('another-custom-article', {
  template: `
    <article>
      Another custom article component! 
      This one has it's own child component too!
      Here it is:
      <custom-article v-custom-directive></custom-article>
    </article>`,
    components: {
      'customArticle': customArticle
    },
    directives: {
      customDirective: {
        inserted: function(el) {
          el.style.cssText = `
            color: blue; 
            border: 1px solid black; 
            background: gray; 
            padding: 20px; 
            width: 50%;
          ` 
      }
    } 
  } 
})

new Vue({
    el: '#app',
    components: { 
      'customArticle': customArticle,
    },
    directives: {
      customDirective: {
        inserted: function(el) {
          el.style.cssText = `
            color: blue; 
            border: 1px solid black; 
            background: gray; 
            padding: 20px; 
            width: 50%;
          ` 
       }
     },
     'anotherCustom': anotherCustom
  }
})
```

在下一节中，我们将看到如何将值传递给自定义指令。

# 将值传递给自定义指令

我们将通过允许我们的自定义指令接收参数来改进本章的初始示例。此示例的代码在此笔中可用：[`codepen.io/AjdinImsirovic/pen/xaNgPN`](https://codepen.io/AjdinImsirovic/pen/xaNgPN)。

这是我们示例中将值传递给自定义指令的 HTML：

```js
<div id="app" class="container mt-5">
  <h1 class="h2">{{ heading }}</h1>
  <button v-buttonize="tomato">
    Just some text here
  </button>
  <button v-buttonize="lightgoldenrod">
    Just some text here
  </button>
  <button v-buttonize="potato">
    Just some text here
  </button> 
</div>
```

以下是 JavaScript 代码：

```js
Vue.directive('buttonize', {
  bind(el, binding) {
    var exp = binding.expression;
    el.style.cssText += `
      padding: 10px 20px; 
      border: none; 
      border-radius: 3px; 
      cursor: pointer
    `;
    switch(exp) {
      case 'tomato':
          el.style.cssText += `
            background: tomato;
            color: white;
          `;
          break;
       case 'lightgoldenrod':
          el.style.cssText += `
            background: darkgoldenrod;
            color: lightgoldenrod;
          `;
          break;
        default:
            el.style.cssText += `
              background: gray;
              color: white;
            `
    }
  }
});
```

最后，在 JS 中，我们添加带有`options`对象的 Vue 构造函数：

```js
new Vue({
  el: '#app',
  data() {
    return {
      heading: 'A custom global directive'
    }
  }
});
```

请注意，指令钩子参数的具体设置可以在[`vuejs.org/v2/guide/custom-directive.html#Directive-Hook-Arguments`](https://vuejs.org/v2/guide/custom-directive.html#Directive-Hook-Arguments)找到。对我们最感兴趣的一个参数是`binding`，它是一个带有这些属性的对象：`name`、`value`、`oldValue`、`expression`、`arg`和`modifiers`。

在上面的代码中，我们看到了传递两个不同值的示例，这些值根据传递的值给出了不同的结果。我们还看到了当我们传递一个无意义的值（利用`switch`语句的`default`分支）时会发生什么。

在下一节中，我们将讨论通过构建 Vue 插件来进一步扩展 Vue 功能的方法。

# 使用 Vue 插件。

一些流行的 Vue 插件是 Vuex 和 Vue-router。当我们需要为 Vue 全局提供额外的功能时，就会使用 Vue 插件。有一些非常常见的情况下，Vue 插件可能会有用：添加全局方法，添加全局资产，添加`Vue.prototype`上的实例方法，或者添加全局混合。

Vue 插件的亮点在于能够与社区共享。要了解 Vue 插件系统的广泛性，可以导航到以下网址：[`github.com/vuejs/awesome-vue#components--libraries`](https://github.com/vuejs/awesome-vue#components--libraries)和[`vuejsexamples.com/`](https://vuejsexamples.com/)。

接下来，我们将创建一个简单的 Vue 插件。

# 创建最简单的 Vue 插件

我们将从创建最简单的 Vue 插件开始。为了做到这一点，我们将再次使用 Vue CLI，版本 3。设置 Vue CLI 的说明在第三章中可用，*使用 Vue-CLI、组件、Props 和 Slots*。

首先，我们需要初始化一个新项目。将控制台导航到要创建新 Vue 项目的父文件夹，并运行以下命令：

```js
vue create simple-plugin
cd simple-plugin
npm run-serve
```

当我们运行这三个命令中的第一个时，会有一些问题，之后会运行大量的软件包。这可能需要一些时间——一个休息的好机会。一旦完成，并且我们已经运行了前面列出的另外两个命令，我们的样板 Vue 应用将在`localhost:8080`上可用。

首先，让我们在`src`文件夹内创建一个新的文件夹，并将其命名为`plugins`。接下来，在`plugins`文件夹内，让我们创建另一个文件夹，我们将其称为`SimplePlugin`。在`SimplePlugin`文件夹内，让我们创建一个新文件，并将其命名为`index.js`。

Vue 插件是一个对象。为了让我们的 Vue 应用程序可以访问插件对象，我们需要通过导出来使其可用。因此，让我们将这个导出代码添加到我们的`index.js`文件中：

```js
export default {

}
```

Vue 的插件对象有一个`install`方法。`install`方法接受两个参数。第一个参数是`Vue`对象，第二个参数是`options`对象。因此，我们将在`plugin`对象内添加`install`方法：

```js
export default {
    install(Vue, options) {
        alert('This is a simple plugin and currently the options argument is ' + options);
    }
}
```

目前，在我们的`install`方法内，我们只是向浏览器发出警报消息。这是我们的插件可以具有的功能的绝对最小值。有了这个功能，现在是时候在我们的应用程序中使用我们的插件了。

请注意，我们还将`options`参数连接到我们的警报消息中。如果我们不这样做，我们的 Vue-cli 将抛出一个错误，指出<q>options 已定义但从未使用</q>。显然，它更青睐于<q>(no-unused-vars)</q>的情况。

要使用插件，我们需要打开我们的`main.js`文件，并通过在`main.js`文件的第三行添加这两行代码来导入插件：

```js
import SimplePlugin from './plugins/SimplePlugin'
Vue.use(SimplePlugin)
```

首先，我们导入插件并指定导入路径。接下来，我们将我们的插件作为参数添加到`Vue.use`方法中。

有了这个，我们已经成功地创建了最简单的插件。打开本地项目`localhost:8080`，你将看到一个警报消息，其中说明：

```js
This is the simplest possible Vue plugin and currently the options argument is undefined
```

接下来，我们将看到如何将选项对象添加到我们的插件中。

# 创建带有定义选项的插件

由于我们设置项目的方式，我们将保持`SimplePlugin`不变，在 Vue 插件探索的这一部分，我们将在项目的`plugins`文件夹内添加另一个文件夹。我们将称这个文件夹为`OptionsPlugin`，并在其中再次创建一个`index.js`文件。

接下来，让我们更新`main.js`文件，使其看起来像这样：

```js
import Vue from 'vue'
import App from './App.vue'

//import SimplePlugin from './plugins/SimplePlugin'
import OptionsPlugin from './plugins/OptionsPlugin'

//Vue.use(SimplestPlugin)
Vue.use(OptionsPlugin)

Vue.config.productionTip = false

new Vue({
  render: h => h(App)
}).$mount('#app')
```

现在，回到`OptionsPlugin/index.js`，我们将添加以下代码：

```js
export default {
  install(Vue) {
    Vue.directive('text-length', {
        bind(el, binding, vnode) {
            const textLength = el.innerText.length;
            console.log("This element, " + el.nodeName + ", has text with " + textLength + " characters");

            el.style.cssText = "border: 2px solid tomato";
        }
    })
  }
}
```

请注意，我们在`install`方法中完全省略了`options`对象。原因很简单：`options`对象是可选的，不提供它不会破坏我们的代码。

在先前的插件定义中，我们获取了`el.innerText`字符串的长度，然后将其记录到控制台中。此外，应用了我们插件自定义的`v-text-length`指令的`el`也将通过红色边框更加显眼。

接下来，让我们在组件的模板中使用来自我们的插件的功能。具体来说，我们将在`src/components`文件夹中的`HelloWorld.vue`文件的开头使用它：

```js
<template>
  <div class="hello">
    <h1 v-text-length>{{ msg }}</h1>
```

此时在浏览器中运行我们的应用程序将在控制台中产生以下消息：

```js
This element, H1, has text with 26 characters
```

现在，我们可以引入我们的`options`对象。`options`对象的目的是允许我们自定义受`v-text-length`指令影响的 HTML 元素的显示方式。换句话说，我们可以决定让我们的插件的用户根据我们传递的选项来选择不同类型的样式。

因此，让我们使用以下代码更新我们的插件：

```js
const OptionsPlugin = { 
  install(Vue, options) {
    Vue.directive('text-length', {
        bind(el, binding, vnode) {
            const textLength = el.innerText.length;
            console.log("This element, " + el.nodeName + ", has text with " + textLength + " characters");

      if (textLength < 40) {
        el.style.cssText += "border:" + options.selectedOption.plum;
      } else if (textLength >= 40) {
        el.style.cssText += "border:" + options.selectedOption.orange;
      }
        }
    })
  }
};

export default OptionsPlugin;
```

在上述代码中发生了一些事情。首先，我们正在即时创建一个对象，并将其分配给`const OptionsPlugin`。在文件底部，我们正在导出我们刚刚定义的`OptionsPlugin`。

在`optionsPlugin`对象内部，我们使用了一些 if 语句，根据`el`元素的文本节点中找到的文本长度来提供不同的样式。如果文本长度小于 40 个字符，那么我们将为`options.selectedOption`赋值

将`.plum`赋给`border` CSS 属性。

否则，如果文本长度等于或大于 40 个字符，我们将在问题元素的内联`style`属性中的`border` CSS 属性赋值为`options.selectedOption.orange`的值。

接下来，让我们设置这些选项值。我们将在我们的`main.js`文件中进行。我们将更新使用插件的部分为以下代码：

```js
Vue.use(OptionsPlugin, {
  selectedOption: {
    plum: "5px dashed purple",
    orange: "10px double orange"
  }
})
```

最后，在`HelloWorld.vue`文件中，我们只进行了轻微的更新。我们将插件定义的指令添加到紧随`h1`标签之后的`p`标签中：

```js
<template>
  <div class="hello">
    <h1 v-text-length>{{ msg }}</h1>
    <p v-text-length>
```

现在，当我们运行我们的应用程序时，我们将在控制台中看到以下文本：

```js
This element, H1, has text with 26 characters
This element, P, has text with 121 characters
```

在我们的视口中，这个插件将在`h1`标签周围添加一个虚线紫色边框，并在`p`标签周围添加一个双层橙色边框。

现在我们了解了插件可以被创建和使用的基本方式，我们可以想出创造性的方法让我们的插件做一些更有用的事情。例如，我们可以通过添加一个工具提示来改进现有的插件，该工具提示将显示页面上不同元素中存在的单词数量。我们还可以添加颜色强度：单词越多，我们可以给这个“字符计数”徽章更多的颜色。

或者，我们可以列出样式属性或类属性中存在的值，或者两者都有。这个插件对于快速检查样式而不用打开开发工具可能会很有用，这在较小的屏幕或只有一个屏幕的工作站上可能会很有用。

接下来，我们将讨论如何发布一个 Vue 插件。具体来说，我们将发布我们刚刚制作的 OptionsPlugin。

# 发布一个 Vue 插件

撰写一个 `npm` 插件的先决条件是在网站上注册并验证你的电子邮件地址。因此，在 `npm` 上撰写你的 Vue 插件的第一步是访问 [`www.npmjs.com`](https://www.npmjs.com) 并注册一个账户。

我们将在 `npm` 上发布我们的 Vue 插件。首先，让我们检查是否已经有一个用户。在控制台中运行以下命令：

```js
npm whoami
```

如果出现错误，您需要通过运行此命令创建一个新用户：

```js
npm adduser
```

然后，只需按照说明将自己添加为用户。

# 添加一个简单的插件

添加一个简单的、单文件插件，只需在您选择的文件夹中运行 `npm init`。这个命令将帮助您创建一个 `package.json` 文件。

这是提供的问题和答案列表：

```js
package name: "vue-options-plugin"
version: (1.0.0)
description: A simple Vue plugin that shows how to use the options object
entry point: "OptionsPlugin.vue"
test command:
git repository:
keywords:
license: (ISC)
About to write to ...
Is this ok? (yes)
```

`npm init` 实用程序提供的默认答案列在圆括号中。要接受默认值，只需按 *Enter* 键。否则，只需输入所需的答案。

`npm` 作者还有一个作用域的概念。作用域就是你的用户名。不用担心作用域的最佳方法是在你的 `.npmrc` 文件中设置它，通过命令行运行以下命令：

```js
npm init --scope=username
```

当然，您需要用您的实际用户名替换 `username` 这个词。

完成后，运行 `dir` 命令列出文件夹的内容。它应该只列出一个文件：`package.json`。现在，我们可以创建另一个文件，命名为 `OptionsPlugin.vue`：

```js
touch OptionsPlugin.vue
```

让我们快速验证我们的 `package.json` 文件是否像这样：

```js
{
  "name": "vue-options-plugin",
  "version": "1.0.0",
  "description": "A simple Vue plugin that shows how to use options object",
  "main": "OptionsPlugin.vue",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "<your-username-here>",
  "license": "ISC"
}
```

接下来，让我们用这段代码更新 `OptionsPlugin.vue` 文件：

```js
const OptionsPlugin = { 
  install(Vue, options) {
    Vue.directive('text-length', {
        bind(el, binding, vnode) {
            const textLength = el.innerText.length;
            console.log("This element, " + el.nodeName + ", has text with " + textLength + " characters");

      if (textLength < 40) {
        el.style.cssText += "border:" + options.selectedOption.plum;
      } else if (textLength >= 40) {
        el.style.cssText += "border:" + options.selectedOption.orange;
      }
        }
    })
  }
};

export default OptionsPlugin;
```

最后，让我们添加一个`README.md`文件。`md`文件扩展名代表 Markdown，这是一种使在线内容编写变得非常容易的格式。我们将向`README`添加以下内容：

```js
# optionsplugin
<p> A demo of making a simple Vue 2 plugin and using it with values stored in the options object. This plugin logs out to the console the number of characters in an element. It also adds different CSS styles based on the length of characters in the element.</p>

## Installation
```bash

npm install --save optionsplugin

```js
## Configuration
```javascript

import Vue from 'vue';

import OptionsPlugin from 'optionsplugin'

Vue.use(OptionsPlugin, {

selectedOption: {

plum: "5px dashed purple",

orange: "10px double orange"

}

})

```js
## Usage
<p>To use it, simply add the plugin's custom directive of v-text-length to an element in your template's code.</p>
```

这应该是我们插件描述的一个很好的起点。我们随时可以稍后改进`README`。现在我们已经准备好`package.json`，`README.md`和`OptionsPlugin.vue`，我们可以通过运行以下命令简单地发布我们的插件：

```js
npm publish --access=public
```

我们需要为我们的`npm publish`命令提供`--access=public`标志，因为作用域包默认为私有访问，我们需要明确覆盖此设置。

一旦发布，我们的控制台将输出以下信息：

```js
+ vue-options-plugin@1.0.0
```

这是我们成功发布插件的标志。我们的新插件现在有了自己的主页，位于以下 URL：

[`www.npmjs.com/package/vue-options-plugin`](https://www.npmjs.com/package/vue-options-plugin)。

最后，让我们看看如何将我们新添加的插件安装到另一个项目中。

# 在 Vue CLI 3 中安装我们的 NPM 插件

从`npm`安装我们的 Vue 插件，我们需要首先创建一个新项目。让我们运行这些命令：

```js
vue create just-another-project
cd just-another-project
npm run-serve
```

现在，我们可以通过运行以下命令添加我们的`npm`插件：

```js
npm install --save vue-options-plugin
```

就是这样；现在，我们的插件已经在我们的项目中可用，我们可以像之前描述的那样导入它来使用：

```js
import VueOptionsPlugin from 'vue-options-plugin'
```

现在，我们可以根据需要使用我们插件的功能。

# 要学习的其他插件

查看其他人的代码的良好编码示例总是很有益的，这样我们就可以从中学习。我们可以学习并可能贡献的一些有用的插件包括：

+   一个引导游览插件，vue-tour：[`github.com/pulsardev/vue-tour`](https://github.com/pulsardev/vue-tour)

+   多选插件，vue-multiselect：[`vue-multiselect.js.org/`](https://vue-multiselect.js.org/)

+   一个工具提示插件，v-tooltip：[`akryum.github.io/v-tooltip`](https://akryum.github.io/v-tooltip)

# 摘要

在本章中，我们讨论了在 Vue 中创建自定义指令和自定义插件。我们介绍了如何构建自定义指令，以及如何创建全局和局部自定义指令。我们还讨论了如何向自定义指令传递数值以及如何使用 Vue 插件。我们还介绍了如何创建一些自定义 Vue 插件。最后，我们看到了如何将我们的插件发布到`npm`，以及如何从 NPM 在我们的项目中安装它。

在接下来的章节中，我们将探讨如何通过过渡和动画使我们的应用程序更具交互性。


# 第六章：过渡和动画

在这一章中，我们将看看如何在 Vue 中使用过渡和动画。这是一个很大的主题，需要更多的章节来覆盖。因此，我们将处理一些基本概念，以便在将来构建。

我们将重点关注以下主题：

+   理解 CSS 过渡和动画

+   使用`transition`组件实现过渡

+   在 Vue 中使用 CSS 过渡和动画

+   与第三方 CSS 和 JS 库集成

+   绑定 CSS 样式

+   与过渡组一起工作

+   JavaScript 动画钩子

阅读完本章后，您应该对 Vue 中如何使用过渡和动画有扎实的理解。

# CSS 中的过渡和动画

要了解 Vue.js 如何处理过渡和动画，我们首先需要快速复习一下它们在 CSS 中的工作原理。我们将专注于基础知识，目标是重新审视管理过渡和动画的原则。我们还将看看它们的区别。目标是更好地理解 Vue 如何帮助，而不是深入了解过渡和动画的细微差别。

# CSS 过渡的工作原理

当我们悬停在一个元素上时，我们将该元素置于悬停状态。当用户通过与我们的网页进行交互触发悬停状态时，我们可能希望*强调*这种状态的变化已经发生。

为了强调状态的变化，我们可以例如在用户悬停在元素上时改变该元素的 CSS `background-color`属性。

这就是 CSS 过渡发挥作用的地方。当我们为 CSS 过渡编写代码时，我们*指示*浏览器如何显示对该特定 CSS 属性所做的更改-在我们的例子中是`background-color`属性。

假设我们有一个 HTML `button`元素。该元素的 CSS 属性`background-color`设置为`red`：

```js
button {
  background-color: red;
}
```

当用户悬停在按钮上时，我们希望将`background-color`属性的值从`red`更改为`blue`。我们可以这样做：

```js
button:hover {
  background-color: blue;
}
```

示例代码在这里可用：[`codepen.io/AjdinImsirovic/pen/LJKJYY`](https://codepen.io/AjdinImsirovic/pen/LJKJYY)。

然而，这种颜色的变化是突然的。为了*平滑过渡*HTML 元素的 CSS 属性从一个值到另一个值，我们使用 CSS 的`transition`属性。`transition`属性是一个简写的 CSS 属性。它只是另一个我们在目标元素上指定的 CSS 属性，我们希望对其应用这种平滑过渡。

在我们的例子中，我们希望平滑地将按钮从红色背景过渡到蓝色背景。我们只需在按钮元素上添加简写的`transition`属性，并在这个`transition`属性上设置两个值：

```js
button {
 background-color: red;
 transition: background-color 4s;
}
button:hover {
 background-color: blue;
}
```

这是公式：

```js
transition: property-to-transition transition-duration, property-to-transition transition-duration
```

在我们的例子中，我们只为一个属性指定了持续时间，但我们可以根据需要添加更多。

# CSS 动画的工作原理

在上一个例子中，我们看到了一个简单的过渡。在这个例子中，我们将把过渡转换为动画。更新后的 CSS 代码将如下所示：

```js
button {
  background-color: red;
}
button:hover {
  animation: change-color 4s;
}
@keyframes change-color {
  0% {
    background: red;
  }
  100% {
    background: blue;
  }
}
```

在上一个代码中，我们已经将我们简单的 CSS 过渡转换为了 CSS 动画。

此示例可在此链接找到：[`codepen.io/AjdinImsirovic/pen/WaNePm`](https://codepen.io/AjdinImsirovic/pen/WaNePm)。

然而，它并不完全相同。当我们悬停在按钮上时，我们并没有得到与过渡示例中相同的行为。原因是我们已经指定了动画的初始状态（为`0%`）和最终状态（为`100%`）。因此，我们实际上是将我们在过渡示例中的行为映射到动画示例中的行为。

然而，当我们将鼠标指针从按钮上移开时，动画并不会倒回到初始状态，而是突然切换回原始的红色背景颜色。在 CSS 中，没有`mouseout`属性。

然而，我们可以在中间添加额外的步骤。例如，我们可以在变化动画的 50%处将背景颜色设置为绿色。结果可以在此 URL 中看到：[`codepen.io/AjdinImsirovic/pen/QZWWje`](https://codepen.io/AjdinImsirovic/pen/QZWWje)。

在我们深入了解 Vue 如何实现过渡和动画之前，让我们先看看它们在 CSS 中的区别。

# CSS 中过渡和动画的区别

以下是 CSS 中过渡和动画之间的两个快速、不完整的区别列表。

# CSS 过渡的规则

以下是 CSS 过渡的一些重要规则：

+   过渡只有暗示的开始和结束状态

+   浏览器决定了过渡的执行方式；换句话说，浏览器决定了过渡的中间步骤如何执行

+   我们只能指定要过渡的确切 CSS 属性，以及持续时间、缓动等

+   过渡是*被触发的；*触发可以是悬停或页面上元素的出现（通过 JavaScript）

+   过渡不能循环

+   当触发状态（悬停状态）被恢复时，过渡会以相反的方式播放，也就是当鼠标*取消悬停*时

+   过渡语法比动画的语法更简单

接下来，让我们列出 CSS 动画的重要概念。

# CSS 动画规则

以下是 CSS 动画的不完整规则列表：

+   动画允许我们指定 CSS 属性的初始状态、中间状态和结束状态

+   我们的 CSS 动画中可以有尽可能多的步骤

+   我们可以延迟动画，播放*x*次（无限次），或者以相反的方向播放它们

+   动画不一定要被触发，但它们可以被触发

在弄清楚这些基本区别之后，让我们接下来看看如何在 Vue 中处理过渡和动画。

# Vue 中的过渡元素

让我们看看之前的纯 CSS 过渡的示例，转换成 Vue。在下面的示例中，第一个按钮包裹在一个自定义组件中，而第二个按钮只是常规的 HTML 按钮元素。它们仍然共享相同的样式，如应用程序的 CSS 中指定的那样：

```js
<!-- HTML -->
<div id="app">
  <button>Hover me!</button>
  <custom-component></custom-component>
</div>

// JS
Vue.component('customComponent', {
  template: `
    <button>Hover me too!</button>
  `
});
new Vue({
  el: '#app'
});

/* CSS */
button {
  background-color: red;
  transition: background-color 4s;
}
button:hover {
  background-color: blue;
}
/* some additional styling */
* {
  border: none;
  color: white;
  padding: 10px;
  font-size: 18px;
  font-weight: 600;
}

```

之前的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/vVYERO`](https://codepen.io/AjdinImsirovic/pen/vVYERO)[.](https://codepen.io/AjdinImsirovic/pen/vVYERO) 如例所示，在这种情况下，Vue 并没有偏离纯 HTML 和 CSS 中过渡和动画的工作方式。

Vue 并不是为了覆盖 CSS 过渡和动画的正常用例而设计的，而是为了与它们一起工作，有一个特定的目标：在屏幕上过渡其*组件*的出现和移除。这些组件的添加和移除是通过 Vue 的`transition`元素来完成的。

例如，当您希望一个组件中的事件影响另一个组件的添加和移除时，您只需将另一个组件包裹在`transition`元素中。从之前的纯 CSS 示例构建，这是 Vue 中的一个简单实现：

```js
<!-- HTML -->
<div id="app">
  <button v-on:click="show = !show">
    Show? {{ show }}
  </button>
  <transition>
    <span v-if="show">
      <custom-component></custom-component>
    </span>
  </transition>
</div>

// JS
Vue.component('customComponent', {
  template: `
    <button>Hover me!</button>
  `
});
new Vue({
  el: '#app',
  data: {
    show: true
  }
});

/* CSS is the same as in the previous example */
```

示例代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/ZqExJO`](https://codepen.io/AjdinImsirovic/pen/ZqExJO)。

如果您需要元素在初始页面加载时平滑出现，而不受条件限制，那么您可以在转换包装器上使用`appear`属性，就像这样：`<transition appear>`。

在上面的代码中发生的是，我们有条件地切换`custom-component`元素的挂载，这取决于用户是否点击了第一个按钮。请注意，原始的 CSS 转换在两个按钮中仍然以完全相同的方式工作。当我们悬停在它们中的任何一个上时，我们仍然会得到从红色到蓝色的四秒过渡背景颜色。当我们从任何一个按钮悬停离开时，浏览器仍然会处理按钮背景的*反向*过渡。

然而，第二个按钮在屏幕上的挂载是没有任何转换的。第二个按钮简单地在点击第一个按钮时出现和消失，没有任何缓入或缓出。

为了实现这种逐渐出现和消失的效果，`transition`元素带有内置的 CSS 类名。这些内置的转换类名也被称为**动画钩子**。这些动画钩子描述了包裹在`transition`元素内的组件的起始状态、结束状态和中间状态；也就是说，它们描述了受影响的组件将如何在屏幕上切换开和关闭。

我们可以将动画钩子添加到*进入*转换或*离开*转换。进入转换类是`v-enter`，`v-enter-active`和`v-enter-to`。离开转换类是`v-leave`，`v-leave-active`和`v-leave-to`。

# 设置进入转换

为了在上一个例子的基础上进行扩展，我们将利用这些动画钩子使第二个按钮的出现和消失更加平滑。上一个例子和这个例子之间唯一的区别是在我们的 CSS 中添加了动画钩子：

```js
.v-enter {
  opacity: 0;
}
.v-enter-active {
 transition: opacity 3s;
}
```

这个例子的代码可以在以下链接找到：[`codepen.io/AjdinImsirovic/pen/MPWVNm`](https://codepen.io/AjdinImsirovic/pen/MPWVNm)。

如果我们将第二个按钮的外观想象成一个常规的 CSS 转换，那么`.v-enter`动画钩子将是初始转换状态，`.v-enter-active`将是中间步骤，`.v-enter-to`将是最终转换状态，也就是元素将要转换*到*的状态。

因为我们在示例中没有使用`.v-enter-to`动画钩子，所以我们得到的行为如下：当点击第一个按钮时，第二个按钮需要三秒钟才能从初始值零过渡到暗示的值一（不透明度）。这就完成了我们的进入过渡。

# 设置离开过渡

我们之前的示例有一个小问题：当我们再次点击第一个按钮时，第二个按钮会立即消失，因为它的不透明度值会在没有任何过渡的情况下重置为零。原因很简单：我们没有指定任何*离开*过渡钩子，所以按钮就会消失。我们将在下一个示例中修复这个问题，只需简单地指定离开过渡，就像这样：

```js
.v-leave {
  opacity: 1;
}
.v-leave-active {
  transition: opacity 3s;
}
.v-leave-to {
  opacity: 0;
}
```

完整的代码可以在这里找到：[`codepen.io/AjdinImsirovic/pen/XxWqOy`](https://codepen.io/AjdinImsirovic/pen/XxWqOy)。在这段代码中，我们做的是：当组件需要被动画移出时，我们过渡的初始状态是`.v-leave`。在`.v-leave`动画钩子中的 CSS 声明是`opacity: 1`。接下来，我们指定中间步骤：要过渡的 CSS 属性，即`opacity`，以及过渡的持续时间：`3s`。最后，我们指定过渡的完成状态，其中`opacity`被设置为零的值。

从这些示例中我们可以得出结论，*离开*过渡的动画钩子（`v-leave`，`v-leave-active`和`v-leave-to`）应该是*镜像的*，就像进入过渡的动画钩子（`v-enter`，`v-enter-active`和`v-enter-to`）一样。

我们还可以得出结论，过渡组件和随之而来的动画钩子用于在屏幕上挂载和卸载组件。当在屏幕上过渡组件时，动画钩子的自然进展是这样的：

```js
.v-enter --> .v-enter-active --> .v-enter-to --> .v-leave --> v-leave-active --> .v-leave-to
```

我们还可以将共享相同值的某些 CSS 选择器分组，如下所示：

```js
.v-enter, .v-leave-to {
  opacity: 0;
}
.v-enter-active, .v-leave-active {
  transition: opacity 3s;
}
.v-enter-to, .v-leave {
  opacity: 1;
}
```

这个示例可以在以下网址找到：[`codepen.io/AjdinImsirovic/pen/dgyKMG`](https://codepen.io/AjdinImsirovic/pen/dgyKMG)。

正如在这里所看到的，`.v-enter`（初始进入动画钩子）与`.v-leave-to`（最后离开动画钩子）被合并在一起，这是因为过渡必须以相反的方式播放，以获得最符合预期的行为。同样，我们将中间步骤，即`-active`钩子分组，以具有相同的`transition` CSS 属性。最后，进入动画的最终钩子需要与初始离开动画钩子共享 CSS 声明。此外，由于`.v-enter-to`和`.v-leave`的值默认情况下是隐含的，我们甚至可以省略它们，仍然可以拥有一个正常工作的组件过渡，类似于官方文档中描述的过渡。

为了简化推理，我们在最近的示例中还将`data`选项的`show`键更改为`false`的值。这样，最初组件不会挂载到 DOM 上。只有当用户点击第一个按钮时，第二个按钮的进入动画钩子才会启动，并平滑地过渡组件。再次点击时，第二个按钮的离开动画钩子将启动，并以相反的方式过渡组件。这很重要，因为最初我们让进入动画过渡组件的卸载，而离开动画过渡组件重新挂载到页面上，这可能会使事情变得更加复杂。

# 命名过渡组件

我们可以给过渡元素添加`name`属性。这样做会改变动画钩子的命名约定。例如，如果我们给过渡命名为`named`，那么动画钩子将需要按照以下方式重新命名。对于每个过渡类，我们将用`name`属性的值替换`v-`的开头。因此，`v-enter`将变成`named-enter`，`v-leave`将变成`named-leave`，依此类推。

让我们用一个命名过渡来重写前面的例子：

```js
<!-- HTML -->
<div id="app">
  <button v-on:click="show = !show">
    Show? {{ show }}
  </button>
  <transition name="named">
    <span v-if="show">
      <custom-component></custom-component>
    </span>
  </transition>
</div>

/* CSS */
/* 'named' transition */
.named-enter, .named-leave-to {
  opacity: 0;
}
.named-enter-active, .named-leave-active {
  transition: opacity 3s;
}
.named-enter-to, .named-leave {
  opacity: 1;
}

// JS is unchanged
```

此示例的代码可在此 CodePen 中找到：[`codepen.io/AjdinImsirovic/pen/MPWqgm`](https://codepen.io/AjdinImsirovic/pen/MPWqgm)。

# 使用过渡组件的 CSS 动画

CSS 动画也可以通过过渡组件来实现。以下是将以 CSS 过渡为例的先前示例转换为使用 CSS 动画的示例。我们将从 HTML 开始：

```js
<div id="app">
  <button v-on:click="show = !show">
    Show? {{ show }}
  </button>
  <transition name="converted">
    <span v-if="show">
      <custom-component></custom-component>
    </span>
  </transition>
</div>
```

接下来，我们将添加以下 JavaScript 代码：

```js
Vue.component('customComponent', {
  template: `
    <button>Lorem ipsum</button>
  `
});
new Vue({
  el: '#app',
  data: {
    show: false
  }
});
```

我们也会添加一些简单的样式：

```js
/* 'named' transition is replaced with 'converted' animation */
.converted-enter-active {
  animation: converted .5s;
}
.converted-leave-active {
  animation: converted .5s reverse;
}
@keyframes converted {
  0% { opacity: 0; }
  35% { background-color: purple; }
  65% { background-color: green; }
  100% { opacity: 1; }
}
/* other styles */
button {
  background-color: red;
  transition: background-color 4s;
}
button:hover {
  background-color: blue;
}
/* some additional styling */
* {
  border: none;
  color: white;
  padding: 10px;
  font-size: 18px;
  font-weight: 600;
}
span {
  display: inline-block;
}
```

此示例的代码在此处可用：[`codepen.io/AjdinImsirovic/pen/vVEXEv`](https://codepen.io/AjdinImsirovic/pen/vVEXEv)。转换后的动画与以前使用 CSS 过渡的示例完全相同，只是在动画完成的 35%和 65%处改变了动画行为。我们得到的效果有点像边框颜色效果，即使我们正在改变此元素的`background-color`属性。这证实了我们已经讨论过的一些结论，即以下内容：

+   Vue 中的`transition`元素影响整个`<transition>`组件的出现和消失，而不是其内容

+   实际动画可以有许多步骤；换句话说，要获得与 CSS 过渡示例中相同的效果，只需简单地删除我们在动画完成的 35%和 65%处指定的步骤即可。

在下一节中，我们将讨论自定义过渡类。

# 自定义过渡类

自定义过渡类在我们想要从第三方 CSS 动画库中添加功能时非常有用。在这个例子中，我们将使用`Animate.CSS`动画库，可以在这里找到：[`daneden.github.io/animate.css/`](https://daneden.github.io/animate.css/)。

官方文档在此 URL 上充分涵盖了自定义过渡类的使用：[`vuejs.org/v2/guide/transitions.html#Custom-Transition-Classes`](https://vuejs.org/v2/guide/transitions.html#Custom-Transition-Classes)。

唯一需要添加的是我们一直在构建的示例，可以在这里找到：[`codepen.io/AjdinImsirovic/pen/rqazXZ`](https://codepen.io/AjdinImsirovic/pen/rqazXZ)。

示例的代码如下。首先，我们将从 HTML 开始：

```js
<div id="app">
  <button v-on:click="show = !show">
    Show? {{ show }}
  </button>
  <transition :duration="4000"
     name="converted"
     enter-active-class="rubberBand animated"
     leave-active-class="bounceOut animated">
        <div v-if="show">
          <custom-component>
          </custom-component>
        </div>
  </transition>
</div>
```

接下来，让我们看看 JavaScript：

```js
Vue.component('customComponent', {
  template: `
    <button>Lorem ipsum</button>
  `
});
new Vue({
  el: '#app',
  data: {
    show: false
  }
});
```

最后，在我们的样式中，我们将设置一些基本的 CSS 声明：

```js
button {
  background-color: red;
  transition: background-color 4s;
}
button:hover {
  background-color: blue;
}

* {
  border: none;
  color: white;
  padding: 10px;
  font-size: 18px;
  font-weight: 600;
}
* { overflow: hidden }
```

基本上，我们指定了与动画钩子相同名称的属性，以及属性名称末尾的额外`-class`。因此，默认的`v-enter-active` CSS 类变成了自定义的`enter-active-class` HTML 属性。然后我们给这个自定义的 HTML 属性赋予我们选择的值。我们给它的值是我们之前选择的 CSS 动画库中要使用的效果的类名——在这种情况下是`Animate.CSS`库。在之前的代码中，我们还设置了`:duration`属性，指定过渡的持续时间为 4000 毫秒。在我们的示例中，如果我们设置的`:duration`属性比我们从第三方库提供的动画的持续时间短，这实际上只会产生效果。例如，尝试将`:duration`属性设置为 100 毫秒，看看动画被截断。这可能会产生一些有趣的效果。

# 结合过渡模式、持续时间、键和 v-if。

过渡模式用于在屏幕上平滑地移除一个元素，并无缝地替换为另一个元素。`<transition>`组件默认的过渡模式是同时过渡：一个元素被移除的同时另一个元素被添加。

但是，在某些过渡中，最好让新元素出现，只有当这个过渡完成时，旧元素才被移除。这种过渡模式被称为`in-out`过渡模式。要添加它，我们只需使用自定义模式 HTML 属性，并给它赋值`in-out`，就像这样：

```js
<transition mode="in-out">
```

或者，我们可能想要使用`out-in`过渡模式，首先让旧元素过渡出去，然后，当过渡完成时，新元素才过渡进来。

让我们看看实际操作。示例可在此处找到：[`codepen.io/AjdinImsirovic/pen/yRyPed`](https://codepen.io/AjdinImsirovic/pen/yRyPed)。

以下是 HTML 代码：

```js
<div id="app">
  <transition name="smooth" mode="out-in" :duration="500">
      <button v-if="show" 
              key="first" 
              v-on:click="show = !show">
                Show? {{ show }}
      </button>
      <button v-else
              key="second" 
              v-on:click="show = !show">
                Show? {{ show }}
      </button> 
  </transition>
  <transition :duration="1000"
     enter-active-class="slideInDown animated"
     leave-active-class="slideOutDown animated">
        <div v-if="show">
          <custom-component>
          </custom-component>
        </div>
  </transition>
</div>
```

我们仍然使用相同的 JS：

```js
Vue.component('customComponent', {
  template: `
    <button>Lorem ipsum</button>
  `
});
new Vue({
  el: '#app',
  data: {
    show: false
  }
});
```

我们的 CSS 发生了一些变化：

```js
/* CSS classes used are imported from the Animate CSS library
and can be found in Settings of this pen */
/* other styles */
.smooth-enter, .smooth-leave-to {
  opacity: 0;
}
.smooth-enter-active, .smooth-leave-active {
  transition: opacity .5s;
}
.smooth-enter-to, .smooth-leave {
  opacity: 1;
}

button {
  background-color: red;
  transition: background-color 4s;
}
button:hover {
  background-color: blue;
}

* {
  border: none;
  color: white;
  padding: 10px;
  font-size: 18px;
  font-weight: 600;
}
* { overflow: hidden }
```

我们在转换过渡中在两个`button`元素之间切换开关。由于这两个元素具有相同的标签名称，我们需要给它们不同的`key`属性，以便 Vue 可以区分它们。

此外，我们有条件地渲染我们的按钮。虽然我们在第一个按钮中保留了`v-if="show"`的检查，但在第二个按钮中，我们只是使用了`v-else`指令，而没有给它一个要检查的值。

# 在 Vue 中绑定 CSS 样式

在这一部分，我们将讨论如何在组件挂载或移除时，对页面的其他部分进行动画处理。为此，我们将使用`v-bind`指令，正如我们在前几章中所看到的，我们可以使用这个指令来绑定 HTML 属性。一旦绑定，这些属性就可以从我们的 Vue 实例中进行操作。

我们将演示 CSS 样式绑定的示例是一个简单的入职演示。在网页可用性方面，入职是向 Web 应用的新用户展示网页的整体功能的做法，这是通过突出显示页面的某个部分并显示一个包含一些信息的气泡窗口来实现的，进一步描述了入职过程中特定步骤的功能。

首先，我们需要了解，我们可以通过将`v-bind:class`指令的值作为对象来静态地绑定 CSS 类，就像下面的例子一样：

```js
<p v-bind:class="{}">Some text...</p>
```

在对象内部，我们可以简单地将 CSS 类添加为键，将布尔值`true`和`false`作为值。设置为`true`的 CSS 值将被使用，否则将不会被使用，就像下面的例子一样：

```js
<button v-bind:class="{'btn': true, 'btn-lg': true, 'btn-primary': true, 'btn-secondary': false}">A button</button>
```

在这个例子中，我们使用了 Bootstrap 框架的 CSS 类。我们将按钮设置为`btn-primary`类，因为它被设置为`true`，而不是`btn-secondary`，它被设置为 false。

因为`v-bind`指令允许我们以编程方式控制 HTML 属性，所以我们可能会在点击时使我们的应用切换 CSS 类。例如，在一个基本的 Vue 应用中，我们可能会在我们的 HTML 中这样做：

```js
<button v-bind:class="'btn':true','btn-lg':true, 'btn-primary':true, 'btn-secondary':btnClicked">
A button
</button>
```

在前面的代码中，我们将`btn`、`btn-lg`和`btn-primary`的类设置为`true`，并将`btn-secondary`的值设置为`btnClicked`。接下来，我们将在 JavaScript 中将`btnClicked`的值设置为`false`：

```js
data: {
  btnClicked: false,
}
```

最后，我们将为我们的按钮添加点击事件，因此当点击时，`btnClicked`的值将从`true`切换到`false`，反之亦然。以下是代码：

```js
<button 
  v-on:click="btnClicked = !btnClicked" 
  v-bind:class="'btn':true','btn-lg':true, 'btn-primary':true, 'btn-secondary':btnClicked">
    A button
</button>
```

此示例可在以下网址找到：[`codepen.io/AjdinImsirovic/pen/KGVvML`](https://codepen.io/AjdinImsirovic/pen/KGVvML)。

我们可以进一步扩展这个示例，使用`data`属性来存储一组 CSS 类，并使用 JavaScript 三元表达式来检查`btnClicked`值当前是否设置为`true`或`false`：

```js
<!-- HTML -->
<div id="app" class="p-4">
  <h1>Improving dynamic CSS classes example</h1>
  <p class="lead">Click the button below a few times</p>
  <button 
    v-on:click="btnClicked = !btnClicked" 
    v-bind:class="btnClicked ? btnPrimary : btnSecondary">
      btnClicked {{ btnClicked }} 
  </button>
</div>

// JS
new Vue({
  el: '#app',
  data() {
    return {
      btnClicked: false,
      btnPrimary: 'btn btn-lg btn-primary',
      btnSecondary: 'btn btn-lg btn-secondary'
    }
  }
})
```

前一个示例的代码可以在[`codepen.io/AjdinImsirovic/pen/wYMEJQ`](https://codepen.io/AjdinImsirovic/pen/wYMEJQ)找到。

# 使用动态 CSS 类在单击时为按钮添加动画

现在，我们可以通过简单地添加来自上述 Animate.CSS 动画库的额外 CSS 类来添加动画。对于前一个示例代码的更新很少。我们只在这里添加了两个 CSS 类：

```js
      btnPrimary: 'btn btn-lg btn-primary bounce animated',
```

当然，我们还必须包括 Animate.CSS 库，如下所示：[`codepen.io/AjdinImsirovic/pen/RerEyy`](https://codepen.io/AjdinImsirovic/pen/RerEyy)。要在两次点击时添加动画，我们只需将`btnSecondary`的条目更改为：

```js
btnSecondary: 'btn btn-lg btn-secondary tada animated'
```

现在，按钮将在每次点击时都会有动画。

# 使用过渡组

虽然单个过渡组件用于包装单个元素，但过渡组用于为多个元素添加动画。它们带有额外的动画钩子：`v-move`。

在接下来的示例中，我们将构建一个简单的功能，用户可以在线奖励一段内容，类似于[`medium.com/`](https://medium.com/)的鼓掌功能，工作原理如下：如果网站的访问者喜欢一段内容，他们可以通过点击鼓掌按钮最多 50 次来奖励它。因此，鼓掌功能就像是网站访问者对一段内容的欣赏程度的计数器。

在我们的实现中，我们将结合我们已经介绍的功能。不同之处在于，我们将使用`transition-group`组件而不是过渡。这是 HTML 代码：

```js
<!-- HTML -->
<div id="app">
    <div class="tale">
        <transition-group>
          <button 
                  class="bare" 
                  key="howManyClaps" 
                  v-if="clapCount">
                    {{ clapCount }}
          </button>
          <button 
                  class="fa fa-thumbs-o-up animated orange" 
                  key="theClapButton" 
                  v-on:click="aClap()">
          </button>
        </transition-group>
    </div>
</div>
```

以下是 JS 代码：

```js
new Vue({
  el: "#app",
  data: { 
    clapCount: false
  },
  methods: {
    aClap() {
      var target = document.querySelector('.fa-thumbs-o-up');
      if (!target.classList.contains('wobble')) {
        target.classList.add('wobble');
      }
      setTimeout(function() {
        target.classList.remove('wobble')}, 300
      )
      if (this.clapCount < 10) {
        this.clapCount++
      } else {
        target.classList.remove('orange','wobble')
      }
    }
  }
});
```

以下是 CSS 代码：

```js
button.bare {
  font-size: 30px;
  background: white;
  border: none;
  margin: 0 20px;
}
button:focus.bare, button:focus.fa {
  outline: 0;
}
button.fa {
  cursor: pointer;
  color: white;
  padding: 20px;
  border-radius: 50%;
  font-size: 30px;
  border: none;
}
.orange {
  background: orange;
}

/* animation hooks */
.v-enter,
.v-leave-to{
  opacity: 0;
  transform: translate(1000px, 500px);
}
.v-enter-active,
.v-leave-active {
  transition: opacity 5s, transform 1s
}
```

前面的代码可以在此 URL 作为笔记本使用：[`codepen.io/AjdinImsirovic/pen/JmXJgd`](https://codepen.io/AjdinImsirovic/pen/JmXJgd)。

这段代码中发生了几件事情。在 HTML 中，我们使用`transition-group`组件来处理两个按钮。在 JS 中，我们设置了我们掌声行为的逻辑。我们开始将`clapCount`设置为`false`，这将强制转换为零。在 CSS 中，我们为按钮设置样式，并使用动画钩子。`transform`和`transition`的值已经设置为极端值，以便通过调整这些值来更好地理解它们的工作方式（例如，在*X*轴上的平移为`1000 px`，在*Y*轴上的平移为`500 px`）。

# JavaScript 动画钩子

我们可以将 Vue 的`transition`类用作 JavaScript 方法。就像生命周期钩子一样，我们不必访问它们中的任何一个。或者我们可以挑选出我们想要使用的那些。首先，在我们的 Vue 构造函数的`methods`选项中，我们可以指定要对所有这些方法做什么：

```js
  methods: {
    // ENTER transitions...
    beforeEnter: function(el) {},
    enter: function(el, done) {},
    afterEnter: function(el) {},
    enterCancelled: function(el) {},
    // LEAVE transitions...
    beforeLeave: function(el) {},
    leave: function(el,done) {},
    afterLeave: function(el) {},
    leaveCancelled: function(el) {},
  }
```

正如我们所看到的，我们有四种进入过渡的方法，另外还有四种离开过渡的方法。所有的方法都接受`el`参数，而`enter`和`leave`方法还接受`done`参数，表示动画完成。如果没有使用`done`参数，钩子将在不等待`done`回调完成的情况下被调用，过渡将立即完成。

让我们使用这些 JavaScript 动画钩子来重写前面的例子。为了保持易于理解，我们将把官方文档的例子整合到我们的例子中，这样我们就可以看到当动画钩子仅通过 JavaScript 调用时，这个例子是如何工作的。

这是我们将在 HTML 中使用的代码：

```js
<transition 
  v-on:before-enter="beforeEnter"
  v-on:enter="enter"
  v-on:leave="leave"
  v-bind:css="false">
<p v-if="show" style="font-size:25px">Animation example with velocity</p>
</transition>
```

这是我们将在 JS 中使用的代码：

```js
new Vue({
  el: "#app",
  data: { 
    clapCount: false
  },
  methods: {
    beforeEnter: function(el) {
      el.style.opacity = 0
    },
        enter: function (el, done) {
      Velocity(el, { opacity: 1, fontSize: '1.4em' }, { duration: 300 })
      Velocity(el, { fontSize: '1em' }, { complete: done })
    },
    leave: function (el, done) {
      Velocity(el, { translateX: '15px', rotateZ: '50deg' }, { 
      duration: 600 })
      Velocity(el, { rotateZ: '100deg' }, { loop: 2 })
      Velocity(el, {
        rotateZ: '45deg',
        translateY: '30px',
        translateX: '30px',
        opacity: 0
      }, { complete: done })},
    aClap() {
      var target = document.querySelector('.fa-thumbs-o-up');
      if (!target.classList.contains('wobble')) {
        target.classList.add('wobble');
      }
      setTimeout(function() {
        target.classList.remove('wobble')}, 300
      )
      if (this.clapCount < 10) {
        this.clapCount++
      } else {
        target.classList.remove('orange','wobble')
      }
    }
  }
});
```

这是 CSS：

```js
button.bare {
  font-size: 30px;
  background: white;
  border: none;
  margin: 0 20px;
}
button:focus.bare, button:focus.fa {
  outline: 0;
}
button.fa {
  cursor: pointer;
  color: white;
  padding: 20px;
  border-radius: 50%;
  font-size: 30px;
  border: none;
}
.orange {
  background: orange;
}
```

示例在这里：[`codepen.io/AjdinImsirovic/pen/PyzqxM`](https://codepen.io/AjdinImsirovic/pen/PyzqxM)。

通过这种理解，很容易在我们的 Vue 构造函数中更改特定方法中的参数，以实现我们 JavaScript 动画的期望效果。

# 总结

在这一章中，我们讨论了在 Vue.js 中使用过渡和动画。具体来说，我们研究了 CSS 中过渡和动画的工作原理。我们分析了 CSS 中过渡和动画的区别，并建立了它们的规则。我们使用了 Vue 中的过渡和过渡组件，并讨论了动画钩子及其分组进入和离开过渡。我们看到了过渡组件如何命名，并给定了键值，以及如何分配自定义过渡类，以便更轻松地与第三方动画库集成。

我们解释了何时使用过渡模式，以及如何使用`:duration`和`conditional`指令进一步调整我们的动画。我们提到了在 Vue 中绑定 CSS 样式的重要性，以及这种方法如何用于为我们的 Web 应用程序添加动画。最后，我们看到了如何将基于 CSS 类的过渡转换为基于 JavaScript 的动画钩子。

在下一章中，我们将讨论如何使用 Vuex。
