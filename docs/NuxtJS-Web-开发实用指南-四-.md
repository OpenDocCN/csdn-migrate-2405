# NuxtJS Web 开发实用指南（四）

> 原文：[`zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19`](https://zh.annas-archive.org/md5/95454EEF6B1A13DFE0FAD028BE716A19)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

添加 Vue 表单

在本章中，您将使用`v-model`和`v-bind`创建表单。您将学习在将表单数据发送到服务器之前在客户端验证表单。您将创建具有基本元素的表单，绑定动态值，并使用修饰符修改输入元素的行为。您还将学习如何使用`vee-validate`插件验证表单并将其应用于 Nuxt 应用程序。在本章中学习如何在 Vue 表单中使用`v-model`和`v-bind`非常重要，因为我们将在接下来的章节中使用表单，例如在“添加 Vuex 存储”第十章和“创建用户登录和 API 身份验证”第十二章中。

本章中我们将涵盖以下主题：

+   理解`v-model`

+   使用基本数据绑定验证表单

+   创建动态值绑定

+   使用`vee-validate`验证表单

+   在 Nuxt 中应用 Vue 表单

# 第七章：理解`v-model`

`v-model`是 Vue 指令（自定义内置 Vue HTML 属性），允许我们在表单的`input`、`textarea`和`select`元素上创建双向绑定。您可以将表单输入与 Vue 数据绑定，以便在用户与输入字段交互时更新数据。`v-model`始终会跳过您在表单元素上设置的初始值，而将 Vue 数据视为真相的来源。因此，您应该在 Vue 端，在`data`选项或函数内声明初始值。

`v-model`将根据输入类型选择适当的方式来更新元素，这意味着如果您在`type="text"`的表单输入上使用它，它将使用`value`作为属性，并使用`input`作为事件来执行双向绑定。让我们看看在接下来的部分中包括哪些内容。

## 在文本和文本区域元素中使用 v-model

记得我们在《添加 Vue 组件》的第五章中使用`v-model`实现双向绑定来创建自定义输入组件吗？在该章节的“创建自定义输入组件”部分，我们学到了输入框的`v-model`语法 - `<input v-model="username">` - 实际上是以下内容的简写：

```js
<input
  v-bind:value="username"
  v-on:input="username = $event.target.value"
>
```

这个文本`input`元素在幕后绑定了`value`属性，该属性从处理程序`username`中获取值，而`username`又从`input`事件中获取值。因此，自定义的文本输入组件也必须始终在`model`属性中使用`value`属性和`input`事件，如下所示：

```js
Vue.component('custom-input', {
  props: {
    value: String
  },
  model: {
    prop: 'value',
    event: 'input'
  },
  template: `<input v-on:input="$emit('input', $event.target.value)">`,
})
```

这仅仅是因为`v-model`输入的性质是由`v-bind:value`和`v-on:input`组成。当在`textarea`元素中使用`v-model`指令时，情况也是一样的，如下例所示：

```js
<textarea v-model="message"></textarea>
```

这个`v-model` `textarea`元素是以下内容的简写：

```js
<textarea
  v-bind:value="message"
  v-on:input="message = $event.target.value"
></textarea>
```

这个`textarea`输入元素在幕后绑定了`value`属性，该属性从处理程序`message`中获取值，而`message`又从`input`事件中获取值。因此，自定义的`textarea`组件也必须始终遵守`v-model` `textarea`元素的性质，通过使用`value`属性和`input`事件在`model`属性中，如下所示：

```js
Vue.component('custom-textarea', {
  props: {
    value: null
  },
  model: {
    prop: 'value',
    event: 'input'
  }
})
```

简而言之，`v-model`文本`input`元素和`v-model` `textarea`输入元素始终将`value`属性与处理程序绑定，以在输入事件上获取新值，因此自定义输入组件也必须采用相同的属性和事件。那么复选框和单选按钮元素中的`v-model`又是怎样的呢？让我们在下一节中深入了解它们。

## 在复选框和单选按钮元素中使用 v-model

另一方面，`v-model`复选框和单选按钮输入元素始终将`checked`属性与在`change`事件上更新的布尔值绑定，如下例所示：

```js
<input type="checkbox" v-model="subscribe" value="yes" name="subscribe">
```

在上面的代码片段中，`v-model` `checkbox`输入元素确实是以下内容的简写：

```js
<input
  type="checkbox"
  name="subscribe"
  value="yes"
  v-bind:checked="false"
  v-on:change="subscribe = $event.target.checked"
>
```

因此，自定义的复选框输入元素也必须始终遵守`v-model`复选框输入元素的性质（如前面的代码块中所示），通过在`model`属性中采用`checked`属性和`change`事件，如下所示：

```js
Vue.component('custom-checkbox', {
  props: {
    checked: Boolean,
  },
  model: {
    prop: 'checked',
    event: 'change'
  }
})
```

同样适用于`v-model`单选按钮输入元素，如下所示：

```js
<input type="radio" v-model="answer" value="yes" name="answer">
```

前面的`v-model`元素是以下内容的另一种简写：

```js
<input
  type="radio"
  name="answer"
  value="yes"
  v-bind:checked="answer == 'yes'"
  v-on:change="answer = $event.target.value"
>
```

因此，自定义的单选按钮输入元素也必须始终遵守`v-model`元素的性质，如下所示：

```js
Vue.component('custom-radio', {
  props: {
    checked: String,
    value: String
  },
  model: {
    prop: 'checked',
    event: 'change'
  }
})
```

简而言之，`v-model`、`checkbox` 和 `radio` 按钮输入元素总是绑定 `value` 属性，并在 `change` 事件上更新，因此自定义输入组件也必须采用相同的属性和事件。现在，让我们看看 `v-model` 在下一节中如何在 `select` 元素中工作。

## 在选择元素中使用 v-model

毫不奇怪，`v-model` `select` 输入元素总是将 `value` 属性与在 `change` 事件上获取其选定值的处理程序绑定，如下例所示：

```js
<select
  v-model="favourite"
  name="favourite"
>
  //...
</select>
```

前面的 `v-model` `checkbox` 输入元素只是以下内容的另一种简写：

```js
<select
  v-bind:value="favourite"
  v-on:change="favourite = $event.target.value"
  name="favourite"
>
  //...
</select>
```

因此，自定义的 `checkbox` 输入元素也必须始终遵守 `v-model` 元素的特性，使用 `value` 属性和 `model` 属性中的 `change` 事件，如下所示：

```js
Vue.component('custom-select', {
  props: {
    value: String
  },
  model: {
    prop: 'value',
    event: 'change'
  }
})
```

正如你所看到的，`v-model` 在 `v-bind` 的基础上是一种语法糖，它将一个值绑定到标记上，并在用户输入事件上更新数据，这些事件可以是 `change` 或 `input` 事件。简而言之，`v-model` 在幕后结合了 `v-bind` 和 `v-on`，但重要的是要理解语法下面的内容，作为 Vue/Nuxt 应用程序开发者。

你可以在我们的 GitHub 存储库的`/chapter-7/vue/html/`目录中找到本节中涵盖的示例。

现在你已经了解了 `v-model` 指令在表单输入元素中的工作方式，让我们在下一节中在表单上使用这些 `v-model` 元素并对其进行验证。

# 使用基本数据绑定验证表单

表单是收集信息的文件。HTML `<form>` 元素是一个可以从网页用户那里收集数据或信息的表单。这个元素需要在其中使用 `<input>` 元素来指定我们想要收集的数据。但在接受数据之前，我们通常会希望对其进行验证和过滤，以便从用户那里获得真实和正确的数据。

Vue 允许我们轻松地从 `v-model` 输入元素中验证数据，因此让我们从单文件组件（SFC）Vue 应用程序和 webpack 开始，你可以在第五章中了解到，*添加 Vue 组件*，在*使用 webpack 编译单文件组件*部分。首先，我们将创建一个非常简单的表单，其中包括一个 `submit` 按钮和在 `<template>` 块中显示错误消息的标记，如下所示：

```js
// src/components/basic.vue
<form v-on:submit.prevent="checkForm" action="/" method="post">
  <p v-if="errors.length">
    <b>Please correct the following error(s):</b>
    <ul>
      <li v-for="error in errors">{{ error }}</li>
    </ul>
  </p>
  <p>
    <input type="submit" value="Submit">
  </p>
</form>
```

稍后我们将在`<form>`中添加其余的输入元素。现在，让我们设置基本结构并了解我们将需要什么。我们使用`v-on:submit.prevent`来防止浏览器默认发送表单数据，因为我们将在 Vue 实例的`<script>`块中使用`checkForm`方法来处理提交：

```js
// src/components/basic.vue
export default {
  data () {
    return {
      errors: [],
      form: {...}
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.errors.length) {
        this.processForm(e)
      }
    },
    processForm (e) {...}
  }
}
```

在 JavaScript 方面，我们定义一个数组来保存在验证过程中可能遇到的错误。`checkForm`逻辑验证我们稍后将在本节中添加的必填字段。如果必填字段未能通过验证，我们将错误消息推送到`errors`中。当表单填写正确和/或未发现错误时，它将被传递到`processForm`逻辑，在那里我们可以在将其发送到服务器之前对表单数据进行进一步处理。

## 验证文本元素

让我们开始添加一个用于单行文本的`<input>`元素：

```js
// src/components/basic.vue
<label for="name">Name</label>
<input v-model="form.name" type="text">

export default {
  data () {
    return {
      form: { name: null }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.form.name) {
        this.errors.push('Name required')
      }
    }
  }
}
```

在`<script>`块中，我们在`data`函数中定义了一个`name`属性，它保存初始的`null`值，并将在`<input>`元素的`input`事件上进行更新。当您点击`submit`按钮时，我们在`if`条件块中验证`name`数据；如果没有提供数据，那么我们将错误消息`push`到`errors`中。

## 验证文本区域元素

我们要添加的下一个元素是`<textarea>`，用于多行文本，其工作方式与`<input>`相同：

```js
// src/components/basic.vue
<label for="message">Message</label>
<textarea v-model="form.message"></textarea>

export default {
  data () {
    return {
      form: { message: null }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.form.message) {
        this.errors.push('Message required')
      }
    }
  }
}
```

在`<script>`块中，我们在`data`函数中定义了一个`message`属性，它保存初始的`null`值，并将在`<textarea>`元素的`input`事件上进行更新。当您点击`submit`按钮时，我们在`if`条件块中验证`message`数据；如果没有提供数据，那么我们将错误消息`push`到`errors`中。

## 验证复选框元素

下一个元素是一个单个复选框`<input>`元素，它将保存默认的布尔值：

```js
// src/components/basic.vue
<label class="label">Subscribe</label>
<input type="checkbox" v-model="form.subscribe">

export default {
  data () {
    return {
      form: { subscribe: false }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.form.subscribe) {
        this.errors.push('Subscription required')
      }
    }
  }
}
```

我们还将添加以下多个复选框`<input>`元素，它们绑定到同一个数组`books: []`：

```js
// src/components/basic.vue
<input type="checkbox" v-model="form.books" value="On the Origin of Species">
<label for="On the Origin of Species">On the Origin of Species</label>

<input type="checkbox" v-model="form.books" value="A Brief History of Time">
<label for="A Brief History of Time">A Brief History of Time</label>

<input type="checkbox" v-model="form.books" value="The Selfish Gene">
<label for="The Selfish Gene">The Selfish Gene</label>

export default {
  data () {
    return {
      form: { books: [] }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (this.form.books.length === 0) {
        this.errors.push('Books required')
      }
    }
  }
}
```

在`<script>`块中，我们在`data`函数中定义了一个`subscribe`属性，它保存初始的布尔值`false`，并将在复选框`<input>`元素的`change`事件上进行更新。当您点击`submit`按钮时，我们在`if`条件块中验证`subscribe`数据；如果没有提供数据或者为`false`，那么我们将错误消息`push`到`errors`中。

我们通过定义一个`books`属性来实现多个复选框`<input>`元素的相同功能，它保存了初始的空数组，并将在复选框`<input>`元素的`change`事件上进行更新。我们在`if`条件块中验证`books`数据；如果长度为`0`，那么我们将错误消息`push`到`errors`中。

## 验证单选按钮元素

接下来是绑定到相同属性名称的多个单选按钮`<input>`元素，即`gender`：

```js
// src/components/basic.vue
<label for="male">Male</label>
<input type="radio" v-model="form.gender" value="male">

<label for="female">Female</label>
<input type="radio" v-model="form.gender" value="female">

<label for="other">Other</label>
<input type="radio" v-model="form.gender" value="other">

export default {
  data () {
    return {
      form: { gender: null }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.form.gender) {
        this.errors.push('Gender required')
      }
    }
  }
}
```

在`<script>`块中，我们在`data`函数中定义了一个`gender`属性，它保存了初始的`null`值，并将在选定的`<input>`单选按钮元素的`change`事件上进行更新。当点击`submit`按钮时，我们在`if`条件块中验证`gender`数据。如果没有提供数据，那么我们将错误消息`push`到`errors`中。

## 验证选择元素

接下来是一个单个`<select>`元素，其中包含多个`<option>`元素，如下所示：

```js
// src/components/basic.vue
<select v-model="form.favourite">
  <option disabled value="">Please select one</option>
  <option value="On the Origin of Species">On the Origin of 
   Species</option>
  <option value="A Brief History of Time">A Brief History of Time</option>
  <option value="The Selfish Gene">The Selfish Gene</option>
</select>

export default {
  data () {
    return {
      form: { favourite: null }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (!this.form.favourite) {
        this.errors.push('Favourite required')
      }
    }
  }
}
```

最后是多个绑定到相同`Array`的多个`<option>`元素的多个`<select>`元素，即`favourites: []`：

```js
// src/components/basic.vue
<select v-model="form.favourites" multiple >
  <option value="On the Origin of Species">On the Origin of 
   Species</option>
  <option value="A Brief History of Time">A Brief History of Time</option>
  <option value="The Selfish Gene">The Selfish Gene</option>
</select>

export default {
  data () {
    return {
      form: { favourites: [] }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (this.form.favourites.length === 0) {
        this.errors.push('Favourites required')
      }
    }
  }
}
```

在`<script>`块中，我们在`data`函数中定义了一个`favourites`属性，它保存了初始的`null`值，并将在`<select>`元素的`change`事件上进行更新。当点击`submit`按钮时，我们在`if`条件块中验证`favourites`数据。如果没有提供数据，那么我们将错误消息`push`到`errors`中。对于多个`<select>`元素，我们也是通过定义一个`favourites`属性来实现相同的功能，它保存了初始的空数组，并将在`<select>`元素的`change`事件上进行更新。我们在`if`条件块中验证`favourites`数据；如果长度为`0`，那么我们将错误消息`push`到`errors`中。

然后我们将使用`processForm`逻辑完成这个表单，只有在`checkForm`逻辑中没有发现错误时才会调用。我们使用 Node.js 包`qs`对`this.form`对象进行字符串化，以便以以下格式将数据发送到服务器：

```js
name=John&message=Hello%20World&subscribe=true&gender=other
```

让我们使用 npm 安装`qs`：

```js
$ npm i qs

```

然后我们可以按照以下方式使用它：

```js
import axios from 'axios'
import qs from 'qs'

processForm (e) {
  var data = qs.stringify(this.form)
  axios.post('../server.php', data)
  .then((response) => {
    // success callback
  }, (response) => {
    // error callback
  })
}
```

我们使用`axios`发送数据，并从服务器获取响应（通常是 JSON 格式），然后您可以对响应数据进行操作，例如在服务器端显示“成功”或“失败”消息。

有关`qs`的更多信息，请访问[`www.npmjs.com/package/qs`](https://www.npmjs.com/package/qs)，有关`axios`，请访问[`github.com/axios/axios`](https://github.com/axios/axios)。

您可以在我们的 GitHub 存储库的`/chapter-7/vue/webpack/`中找到前面的示例应用程序。

然而，我们还没有完全完成，因为有时我们可能希望将动态值绑定到表单输入中，而不是从`v-model`中获取默认值。例如，在我们的示例应用程序中，我们只使用单个复选框`<input>`元素获取`subscribe`属性的布尔值，但我们希望使用字符串值`yes`或`no`。我们将在接下来的部分探讨如何更改默认值。

# 进行动态值绑定

在前一节的示例应用程序中，我们仅使用`v-model`获取`radio`，`checkbox`和`select`选项的字符串或布尔值。我们可以通过使用`true-value`，`false-value`和`v-bind`来更改此默认值。让我们深入了解。

## 用布尔值替换-复选框元素

我们可以通过使用`true-value`和`false-value`将我们的自定义值绑定到**单个**`checkbox`元素。例如，我们可以使用`true-value`将`yes`值绑定到替换默认的`true`布尔值，使用`false-value`将`no`值绑定到替换默认的`false`布尔值：

```js
// src/components/dynamic-values.vue
<input
  type="checkbox"
  v-model="form.subscribe"
  true-value="yes"
  false-value="no"
>

export default {
  data () {
    return {
      form: { subscribe: 'no' }
    }
  },
  methods:{
    checkForm (e) {
      this.errors = []
      if (this.form.subscribe !== 'yes') {
        this.errors.push('Subscription required')
      }
    }
  }
}
```

现在，当您将`subscribe`输入的值发送到服务器时，您将得到`yes`或`no`的响应。在`<script>`块中，我们现在将`no`声明为`subscribe`属性的初始值，并在`if`条件块中对其进行验证，以确保在点击`submit`按钮时它始终为`yes`，否则我们将错误消息推送到`errors`。

## 用动态属性替换字符串-单选按钮元素

关于单选按钮`<input>`元素，我们可以使用`v-bind`将它们的值绑定到 Vue 实例中的动态属性：

```js
// src/components/dynamic-values.vue
<input type="radio" v-model="form.gender" v-bind:value="gender.male">

export default {
  data () {
    return {
      gender: {
        male: 'm',
        female: 'f',
        other: 'o',
      },
      form: { gender: null }
    }
  }
}
```

现在，当选择此单选按钮时，您将得到`m`，验证逻辑与以前相同。

## 用对象替换字符串-选择选项元素

我们还可以使用`v-bind`将**非字符串**值（如`Object`）绑定到表单输入。请参阅以下示例：

```js
// src/components/dynamic-values.vue
<select v-model="form.favourite">
  <option v-bind:value="{ title: 'On the Origin of Species' }">On 
   the Origin of Species</option>
</select>

export default {
  data () {
    return {
      form: {
        favourite: null
      }
    }
  }
}
```

现在当选择此选项时，您将得到`typeof this.favourite`的`object`和`this.favourite.title`的`On the Origin of Species`。验证逻辑没有变化。

我们还可以使用动态值和`v-for`动态呈现`<option>`元素：

```js
// src/components/dynamic-values.vue
<select v-model="form.favourites" name="favourites_array[]" multiple >
  <option v-for="book in options.books" v-bind:value="book.value">
    {{ book.text }}
  </option>
</select>

data () {
  return {
    form: { favourites: [] },
    options: {
      books: [
        { value: { title: 'On the Origin of Species' }, text: 'On the 
         Origin of Species'},
        { value: { title: 'A Brief History of Time' }, text: 'A Brief 
         History of Time'},
        { value: { title: 'The Selfish Gene' }, text: 'The Selfish Gene'}
      ]
    }
  }
}
```

现在我们不再需要硬编码`<option>`元素了。我们可以从其他地方（如 API）获取`books`数据。

除了将动态值绑定到表单输入外，我们还可以修改输入元素上`v-model`的默认行为。例如，我们可以使用它们上的`change`事件，而不是将输入与数据同步。让我们在下一个主题中发现如何做到这一点。

# 使用修饰符

Vue 提供了这三个修饰符，`.lazy`、`.number`和`.trim`，我们可以与`v-model`一起使用，改变默认事件或为表单输入添加额外功能。让我们深入了解。

## 添加`.lazy`

我们可以使用`.lazy`和`v-model`来将`<input>`和`<textarea>`元素上的`input`事件改为`change`事件。看下面的例子：

```js
// src/components/modifiers.vue
<input v-model.lazy="form.name" type="text">
```

现在输入与数据在`change`之后同步，而不是默认的`input`事件。

## 添加`.number`

我们可以使用`.number`和`v-model`来改变`<input>`元素上`type="number"`的默认类型转换，将`string`转换为`number`。看下面的例子：

```js
// src/components/modifiers.vue
<input v-model.number="form.age" type="number">
```

现在你得到`typeof this.form.age`的`number`，而不是没有`.number`的`string`。

## 添加`.trim`

我们可以使用`.trim`和`v-model`来修剪用户输入的空白。看下面的例子：

```js
// src/components/modifiers.vue
<textarea v-model.lazy.trim="form.message"></textarea>
```

现在用户输入的文本会自动修剪。文本开头和结尾的任何额外空白都将被修剪掉。

虽然编写自定义验证逻辑是可能的，但已经有一个很棒的插件可以帮助轻松验证输入并显示相应的错误。这个插件叫做 VeeValidate，是一个基于 Vue 的模板验证框架。让我们在下一节中发现如何利用这个插件。

# 使用 VeeValidate 验证表单

使用 VeeValidate，我们将使用 VeeValidate 的组件来验证我们的 HTML 表单，并使用 Vue 的作用域插槽来暴露错误消息。例如，这是一个我们已经熟悉的`v-model`输入元素：

```js
<input v-model="username" type="text" />
```

如果你想用 VeeValidate 验证它，你只需要用`<ValidationProvider>`组件包装输入：

```js
<ValidationProvider name="message" rules="required" v-slot="{ errors }">
  <input v-model="username" name="username" type="text" />
  <span>{{ errors[0] }}</span>
</ValidationProvider>
```

通常情况下，我们使用`<ValidationProvider>`组件来验证`<input>`元素。我们可以使用`rules`属性将验证规则附加到这个组件上，并使用`v-slot`指令显示错误。让我们在以下步骤中发现如何利用这个插件来加快验证过程：

1.  使用 npm 安装 VeeValidate：

```js
$ npm i vee-validate
```

1.  在`/src/`目录中创建一个`.js`文件，并使用 VeeValidate 的`extend`函数添加规则：

```js
// src/vee-validate.js
import { extend } from 'vee-validate'
import { required } from 'vee-validate/dist/rules'

extend('required', {
  ...required,
  message: 'This field is required'
})
```

VeeValidate 提供了许多内置的验证规则，如`required`、`email`、`min`、`regex`等，因此我们可以导入我们应用程序所需的特定规则。因此，在上述代码中，我们导入`required`规则，并通过`extend`函数安装它，然后在`message`属性中添加我们的自定义消息。

1.  将`/src/vee-validate.js`导入到初始化 Vue 实例的主入口文件中：

```js
// src/main.js
import Vue from 'vue'
import './vee-validate'
```

1.  将`ValidationProvider`组件本地导入到页面中，并开始验证该页面上的输入字段：

```js
// src/components/vee-validation.vue
<ValidationProvider name="name" rules="required|min:3" v-slot="{ errors }">
  <input v-model.lazy="name" type="text" name="name">
  <span>{{ errors[0] }}</span>
</ValidationProvider>

import { ValidationProvider } from 'vee-validate'

export default {
  components: {
    ValidationProvider
  }
}
```

我们还可以在`/src/main.js`或`/src/plugins/vee-validate.js`中全局注册`ValidationProvider`：

```js
import Vue from 'vue'
import { ValidationProvider, extend } from 'vee-validate'

Vue.component('ValidationProvider', ValidationProvider)
```

但是，如果您不需要在应用程序的每个页面上使用此组件，这可能不是一个好主意。因此，如果您只需要在某个页面上使用它，则将其本地导入。

1.  本地导入`ValidationObserver`组件，并将`passes`对象添加到`v-slot`指令中。因此，让我们按照以下方式重构*步骤 4*中的 JavaScript 代码：

```js
// src/components/vee-validation.vue
<ValidationObserver v-slot="{ passes }">
  <form v-on:submit.prevent="passes(processForm)" novalidate="true">
    //...
    <input type="submit" value="Submit">
  </form>
</ValidationObserver>

import {
  ValidationObserver,
  ValidationProvider
} from 'vee-validate'

export default {
  components: {
    ValidationObserver,
    ValidationProvider
  },
  methods:{
    processForm () {
      console.log('Posting to the server...')
    }
  }
}
```

我们使用`<ValidationObserver>`组件来包装`<form>`元素，以在提交之前告知其是否有效。我们还在`<ValidationObserver>`组件的作用域插槽对象中使用`passes`属性，该属性用于在表单无效时阻止提交。然后我们将我们的`processForm`方法传递给表单元素上的`v-on:submit`事件中的`passes`函数。如果表单无效，则不会调用我们的`processForm`方法。

就是这样。我们完成了。您可以看到，我们不再需要`methods`属性中`v-on:submit`事件上的`checkForm`方法，因为 VeeValidate 已经为我们验证了元素，并且现在我们的 JavaScript 代码变得更短了。我们只需要使用`<ValidationProvider>`和`<ValidationObserver>`组件包装我们的输入字段。

如果您想了解有关 Vue 插槽和 VeeValidate 的更多信息，请访问以下链接：

+   [`logaretm.github.io/vee-validate/`](https://logaretm.github.io/vee-validate/) 用于 VeeValidate

+   [`vuejs.org/v2/guide/components-slots.html`](https://vuejs.org/v2/guide/components-slots.html) 用于 Vue 插槽

您可以在我们的 GitHub 存储库的`/chapter-7/vue/cli/`中找到我们先前的 Vue 应用程序的示例。

接下来，我们将在下一节中了解如何在 Nuxt 应用程序中应用 VeeValidate。

# 将自定义验证应用到 Nuxt 应用程序

让我们将自定义验证应用到我们已经有的示例网站中的联系页面。您可能已经注意到，现有的联系表单已经安装了 Foundation（Zurb）的验证。使用 Foundation 的表单验证是另一种提升我们的 HTML 表单验证的好方法。

如果您想了解更多关于 Foundation 的信息，可以在它们的官方指南中找到更多信息：[`foundation.zurb.com/sites/docs/abide.html`](https://foundation.zurb.com/sites/docs/abide.html)。

但是，如果我们想要在 Nuxt 中进行自定义验证，我们刚刚学习了在 Vue 应用程序中使用的 VeeValidate，那么让我们按照以下步骤安装和设置我们需要的内容：

1.  通过 npm 安装 VeeValidate：

```js
$ npm i vee-validate
```

1.  在`/plugins/`目录中创建一个插件文件，并添加我们需要的规则，如下所示：

```js
// plugins/vee-validate.js
import { extend } from 'vee-validate'
import {
  required,
  email
} from 'vee-validate/dist/rules'

extend('required', {
  ...required,
  message: 'This field is required'
})

extend('email', {
  ...email,
  message: 'This field must be a valid email'
})
```

这个文件中的一切都和我们在 Vue 应用程序中做的文件一样。

1.  在 Nuxt 配置文件的`plugins`选项中包含插件路径：

```js
// nuxt.config.js
plugins: [
  '~/plugins/vee-validate'
]
```

1.  在 Nuxt 配置文件的`build`选项中为`/vee-validate/dist/rules.js`文件添加一个例外。

```js
// nuxt.config.js
build: {
  transpile: [
    "vee-validate/dist/rules"
  ],
  extend(config, ctx) {}
}
```

在 Nuxt 中，默认情况下，`/node_modules/`文件夹被排除在转译之外，当使用`vee-validate`时，您将会收到一个错误消息`Unexpected token export`，因此在运行 Nuxt 应用程序之前，我们必须将`/vee-validate/dist/rules.js`添加到转译中。

1.  像我们在 Vue 应用程序中所做的那样，导入`ValidationObserver`和`ValidationProvider`组件：

```js
// pages/contact.vue
import {
  ValidationObserver,
  ValidationProvider
} from 'vee-validate'

export default {
  components: {
    ValidationObserver,
    ValidationProvider
  }
}
```

1.  从`<form>`元素中删除 Foundation 的`data-abide`属性，但使用`<ValidationObserver>`组件将其包装起来，并将`submit`事件与`passes`和`processForm`方法绑定到`<form>`元素，如下所示：

```js
// pages/contact.vue
<ValidationObserver v-slot="{ passes }" ref="observer">
  <form v-on:submit.prevent="passes(processForm)" novalidate>
  //...
  </form>
</option>
```

这一步和我们在 Vue 应用程序中所做的步骤是一样的，但在这个例子中，我们在*步骤 8*中添加了`ref="observer"`，因为我们将在后面需要它。

1.  开始使用`<ValidationProvider>`组件重构`<form>`元素内的所有`<input>`元素，如下所示：

```js
// pages/contact.vue
<ValidationProvider name="name" rules="required|min:3" v-slot="{ errors, invalid, validated }">
  <label v-bind:class="[invalid && validated ? {'is-invalid-label': 
   '{_field_}'} : '']">Name
    <input
      type="text"
      name="name"
      v-model.trim="name"
      v-bind:class="[invalid && validated ? {'is-invalid-input': 
       '{_field_}'} : '']"
    >
    <span class="form-error">{{ errors[0] }}</span>
  </label>
</ValidationProvider>
```

这一步和我们在 Vue 应用程序中所做的步骤是一样的，但在这个例子中，我们在`v-slot`指令中添加了两个作用域插槽数据属性，`invalid`和`validated`，以便根据条件将类绑定到`<label>`和`<input>`元素。因此，如果`invalid`和`validated`都为`true`，那么我们将分别将`is-invalid-label`和`is-invalid-input`类绑定到元素上。

有关验证提供程序的作用域插槽数据属性的更多信息，请访问[`vee-validate.logaretm.com/v2/guide/components/validation-provider.html#scoped-slot-data`](https://vee-validate.logaretm.com/v2/guide/components/validation-provider.html#scoped-slot-data)。

1.  通过向`<script>`块中的`data`函数添加以下数据属性来重构，以与`v-model`输入元素同步。我们还将在`methods`选项中添加两个方法，如下所示：

```js
// pages/contact.vue
export default {
  data () {
    return {
      name: null,
      email: null,
      subject: null,
      message: null
    }
  },
  methods:{
    clear () {
      this.name = null
      this.email = null
      this.subject = null
      this.message = null
    },
    processForm (event) {
      alert('Processing!')
      console.log('Posting to the server...')
      this.clear()
      this.$refs.observer.reset()
    }
  }
}
```

这一步与我们在 Vue 应用中所做的相同，但在这个例子中，我们在`methods`选项中的`processForm`中添加了`clear`方法和`reset`方法。`<ValidationObserver>`组件在提交后不会重置表单的状态，因此我们必须手动进行，通过在*步骤 6*中将观察者作为引用传递，然后我们可以通过`this.$refs`从 Vue 实例中访问它。

1.  将这三个作用域插槽数据属性`dirty`、`invalid`和`validated`添加到`<ValidationObserver>`组件中，以切换警报和成功消息，然后让我们按照以下方式重构这个组件：

```js
// pages/contact.vue
<ValidationObserver v-slot="{ passes, dirty, invalid, validated }" ref="observer">
  <div class="alert callout" v-if="invalid && validated">
    <p><i class="fi-alert"></i> There are some errors in your 
     form.</p>
  </div>
  //...
  <div class="success callout" v-if="submitted && !dirty">
    <p><i class="fi-like"></i>&nbsp; Thank you for contacting
      me.</p>
  </div>
</ValidationObserver>

export default {
  data () {
    return {
      submitted: false
      //...
    }
  },
  methods:{
    processForm (event) {
      console.log('Posting to the server...')
      this.submitted = true
      //...
    }
  }
}
```

在最后一步中，我们添加了一个默认为`false`的`submitted`数据属性，当表单在`processForm`方法中提交时，它将被设置为`true`。另一方面，当作用域插槽中的`invalid`和`validated`都为`true`时，警报消息块将可见，当`submitted`属性为`true`且`dirty`作用域插槽数据属性为`false`时，成功消息块将可见。如果输入字段中有一个字母存在，我们将从`dirty`属性中得到一个`true`。换句话说，当输入字段中存在字母时。

您可以看到，在我们的 Nuxt 应用中重构的代码与我们在 Vue 标准应用中所做的非常相似。但是在 Nuxt 应用中，我们为表单添加了更复杂的逻辑，例如切换警报和成功消息，有条件地将类绑定到`<label>`和`<input>`元素，并在表单提交时重置`<ValidationObserver>`组件。对于其余的输入元素，重构过程是相同的，您可以在书的 GitHub 存储库`/chapter-7/nuxt-universal/sample-website/`中找到。

# 摘要

在本章中，我们已经介绍了使用`v-model`在各种表单输入上进行 Vue 表单验证。您已经学会了基本和动态值绑定，以及如何使用修饰符来更改默认的输入事件和类型转换。您还学会了使用`vee-validate`插件来简化验证过程。最后，我们成功将这些应用到了 Nuxt 应用程序中。

在下一章中，我们将探讨如何在 Nuxt 应用程序中添加服务器端框架。您将学会使用 Koa 创建一个简单的 API，并将其与 Nuxt 集成，使用 HTTP 客户端 Axios 来请求 API 数据。此外，您还将介绍一个基于 webpack 的极简构建系统，称为 Backpack，它将简化我们用于单文件组件 Vue 应用程序的自定义 webpack 配置。您还将学会如何在 Nuxt 应用程序中使用这个构建系统。敬请关注！


# 第三部分：服务器端开发和数据管理

在本节中，我们将开始向 Nuxt 项目添加一个服务器端框架和数据库系统，以便我们可以在服务器端管理和获取数据。我们还将添加一个 Vuex 存储库，用于在 Nuxt 中管理全局数据。

本节包括以下章节：

+   第八章，*添加一个服务器端框架*

+   第九章，*添加一个服务器端数据库*

+   第十章，*添加一个 Vuex Store*


添加服务器端框架

在本章中，您将学习如何配置 Nuxt 与服务器端框架，以及如何使用`asyncData`方法从服务器端框架（如 Koa 或 Express）获取数据。使用 Nuxt 设置服务器端框架相当容易。我们只需要选择一个框架作为一等公民，并将 Nuxt 用作中间件。我们可以使用`npx create-nuxt-app <project-name>`来为我们设置，但我们将手把手地教您如何手动操作，以便更好地理解这两个应用是如何协同工作的。此外，在本章中，我们将使用**Backpack**作为我们应用的构建系统。

本章我们将涵盖以下主题：

+   介绍背包

+   介绍 Koa

+   将 Koa 与 Nuxt 集成

+   理解异步数据

+   在 asyncData 中访问上下文

+   使用 Axios 获取异步数据

# 第八章：介绍背包

Backpack 是一个用于构建现代 Node.js 应用的构建系统，零配置或最小配置。它支持最新的 JavaScript，并处理文件监视、实时重新加载、转译和打包，这些都是我们在前几章中使用 webpack 进行的操作。我们可以将其视为 webpack 的**包装器**，是我们在本书中迄今为止一直在使用的 webpack 配置的简化版本。您可以在[`github.com/jaredpalmer/backpack`](https://github.com/jaredpalmer/backpack)找到有关 Backpack 的更多信息。现在，让我们看看如何在接下来的章节中使用它来加快我们的应用开发。

## 安装和配置 Backpack

使用 Backpack 创建现代 Node.js 应用可以像实现以下步骤一样简单：

1.  通过 npm 安装 Backpack：

```js
$ npm i backpack-core
```

1.  在项目根目录中创建一个`/src/`目录和一个`package.json`文件，并在`dev`脚本中添加`backpack`，如下所示：

```js
{
  "scripts": {
    "dev": "backpack"
  }
}
```

请注意，您必须将`/src/`作为应用的**默认入口目录**。

1.  在项目根目录创建一个 Backpack 配置文件，并配置 webpack 的函数如下：

```js
// backpack.config.js
module.exports = {
  webpack: (config, options, webpack) => {
    // ....
    return config
  }
}
```

这一步是可选的，但如果您想要将应用的默认入口目录（即您在*步骤 2*中创建的`/src/`目录）更改为其他目录，例如`/server/`目录，可以按以下方式进行：

```js
webpack: (config, options, webpack) => {
  config.entry.main = './server/index.js'
  return config
}
```

1.  使用以下命令以开发模式启动您的应用：

```js
$ npm run dev
```

然后你可以在`/server/`目录中开发你的应用程序的源代码，并在浏览器上浏览到你设置的任何端口的应用程序。让我们在下一节中使用 Backpack 创建一个简单的 Express 应用程序。

## 使用 Backpack 创建一个简单的应用程序

使用 Backpack 创建一个 Express 应用程序可以像实现以下步骤一样简单：

1.  通过 npm 安装 Express：

```js
$ npm i express
```

1.  在`package.json`文件的`dev`脚本之后添加`build`和`start`脚本：

```js
// package.json
"scripts": {
  "dev": "backpack",
  "build": "backpack build",
  "start": "cross-env NODE_ENV=production node build/main.js"
}
```

1.  创建 Backpack 配置文件，并将`/server/`作为应用程序的入口文件夹，就像我们在上一节中向你展示的那样：

```js
// backpack.config.js
module.exports = {
  webpack: (config, options, webpack) => {
    config.entry.main = './server/index.js'
    return config
  }
}
```

1.  创建一个带有`'Hello World'`消息的简单路由：

```js
// server/index.js
import express from 'express'
const app = express()
const port = 3000

app.get('/', (req, res) =>
  res.send('Hello World')
)

app.listen(port, () =>
  console.log(Example app listening on port ${port}!)
)
```

1.  在开发模式下运行你的应用程序：

```js
$ npm run dev
```

现在你可以在浏览器上浏览`127.0.0.1:3000`上的应用程序。你应该在屏幕上看到 Hello World。你可以在我们的 GitHub 存储库的`/chapter-8/backpack/`中找到这个例子。接下来，让我们在下一节中使用 Koa 作为服务器端框架，允许我们以比 Express 更少的行数编写 ES2015 代码和异步函数。

# 介绍 Koa

Koa 是由带给你 Express 的同一个团队设计的 Node.js web 框架。该框架的主要目标是成为 Web 应用程序和 API 的更小、更具表现力的基础。如果你曾经在 Express 上工作过，并且在应用程序变得更大时厌倦了回调地狱，Koa 允许你摆脱回调，并通过利用异步函数大大增加错误处理。Koa 中另一个很酷的东西是**级联** - 你添加的中间件将会“下游”运行，然后再“上游”流动，这给你更可预测的控制。我们稍后将在本章中演示这一点。

如果你想了解更多关于 Koa 的信息，请访问[`koajs.com/`](https://koajs.com/)。

## 安装和配置 Koa

现在，让我们创建一个 Koa 应用程序，使用 Backpack 的默认配置（不创建 Backpack 配置文件），如下所示：

1.  通过 npm 安装 Koa：

```js
$ npm i koa
```

1.  使用`/src/`作为 Backpack 的默认入口目录，并在该目录中创建一个以 Koa 风格的最小代码的入口文件，如下所示：

```js
// src/index.js
const Koa = require('koa')
const app = new Koa()

app.use(async ctx => {
  ctx.body = 'Hello World'
})
app.listen(3000)
```

1.  在开发模式下运行 Koa 应用程序：

```js
$ npm run dev
```

当在浏览器上浏览`127.0.0.1:3000`时，你应该在屏幕上看到 Hello World。如果你一直在使用 Express 来创建你的 Node.js 应用程序，你会发现 Koa 是一个可以用来以更整洁的代码做同样事情的替代方案。接下来，让我们在接下来的章节中学习 Koa 上下文是什么，以及 Koa 中级联是如何工作的。

## ctx 是什么？

您可能想知道在我们在上一节中创建的最小代码中，`ctx`是什么，以及`req`和`res`对象在哪里，因为它们在 Express 应用程序中存在。它们在 Koa 中并没有消失。它们只是封装在 Koa 中的一个单一对象中，这就是 Koa 上下文，称为`ctx`。我们可以按如下方式访问`request`和`response`对象：

```js
app.use(async ctx => {
  ctx.request
  ctx.response
})
```

因此，您可以看到我们可以轻松使用`ctx.request`来访问 Node.js 的`request`对象，以及`ctx.response`来访问 Node.js 的`response`对象。这两个重要的 HTTP 对象在 Koa 中并没有消失！它们只是隐藏在 Koa 上下文 - `ctx`中。接下来，让我们在下一节中了解 Koa 中级联的工作原理。

## 了解 Koa 中级联的工作原理

简而言之，Koa 中的级联工作是通过按顺序调用下游中间件，然后控制它们按顺序向上游流动。最好创建一个简单的 Koa 应用程序来演示 Koa 中的这一重要特性：

1.  在`/src/`目录中创建一个`index.js`文件，就像我们在上一节中所做的那样：

```js
// src/index.js
const Koa = require('koa')
const app = new Koa()

app.use(async ctx => {
  console.log('Hello World')
  ctx.body = 'Hello World'
})
app.listen(3000)
```

1.  在`Hello World`中间件之前创建三个中间件，以便我们可以先运行它们：

```js
app.use(async (ctx, next) => {
  console.log('Time started at: ', Date.now())
  await next()
})

app.use(async (ctx, next) => {
  console.log('I am the first')
  await next()
  console.log('I am the last')
})

app.use(async (ctx, next) => {
  console.log('I am the second')
  await next()
  console.log('I am the third')
})
```

1.  在开发模式下运行应用程序，您应该在终端上获得以下输出：

```js
Time started at: 1554647742894
I am the first
I am the second
Hello World
I am the third
I am the last
```

在这个演示中，请求通过`Time started at:`流向`I am the first`，`I am the second`，并到达`Hello World`。当没有更多的中间件需要向下执行（下游）时，每个中间件将按以下顺序向上解开并恢复（上游）：`I am the third`，`I am the last`。

您可以在我们的 GitHub 存储库的`/chapter-8/koa/cascading/`中找到这个示例。

接下来，我们将为您介绍一些依赖项，您应该安装这些依赖项来开发一个全栈 Koa 应用程序，使其可以像 Express 应用程序一样工作。

## 安装 Koa 应用程序的依赖项

Koa 是极简的。它本质上是一个基本框架。因此，它的核心中没有任何中间件。Express 自带路由器，默认情况下，Koa 没有。这在使用 Koa 编写应用程序时可能会有挑战，因为你需要选择一个第三方包或从它们的 GitHub 主页上列出的包中选择一个。你可能会尝试一些包，发现它们不符合你的要求。有一些 Koa 包可用于路由；`koa-router`在本书中被广泛使用，以及其他用于使用 Koa 开发 API 的基本依赖项。让我们通过安装它们并创建一个骨架应用程序来发现它们是什么以及它们的作用，如下所示：

1.  安装`koa-router`模块并使用如下：

```js
$ npm i koa-router
```

在入口文件中导入`koa-router`，并创建一个主页路由`/`，如下所示：

```js
// src/index.js
const Router = require('koa-router')
const router = new Router()

router.get('/', (ctx, next) => {
  ctx.body = 'Hello World'
})

app
  .use(router.routes())
  .use(router.allowedMethods())
```

你可以在 Koa 的 GitHub 存储库中找到有关此中间件的更多信息。此模块是从`ZijianHe/koa-router`（https://github.com/ZijianHe/koa-router）分叉而来。它是 Koa 社区中最广泛使用的路由器模块。它提供了使用`app.get`、`app.put`、`app.post`等的 Express 风格路由。它还支持其他重要功能，如多个路由中间件和多个可嵌套的路由器。

1.  安装`koa-bodyparser`模块并使用如下：

```js
$ npm i koa-bodyparser
```

在入口文件中导入`koa-bodyparser`，注册它，并创建一个主页路由`/post`，如下所示：

```js
// src/index.js
const bodyParser = require('koa-bodyparser')
app.use(bodyParser())

router.post('/post', (ctx, next) => {
  ctx.body = ctx.request.body
})
```

你可以在 Koa 的 GitHub 存储库中找到有关此中间件的更多信息。也许你会想：什么是 body parser？当我们处理 HTML 表单时，我们使用`application/x-www-form-urlencoding`或`multipart/form-data`在客户端和服务器端之间传输数据，例如：

```js
// application/x-www-form-urlencoding
<form action="/update" method="post">
  //...
</form>

// multipart/form-data
<form action="/update" method="post" encrypt="multipart/form-data">
  //...
</form>
```

HTML 表单的默认类型是`application/x-www-urlencoded`，如果我们想要读取 HTTP `POST`、`PATCH`和`PUT`的数据，我们使用一个 body parser，它是一个解析传入请求的中间件，组装包含表单数据的**块**，然后创建一个填充有表单数据的 body 对象，以便我们可以从请求对象中的`ctx`对象中访问它们，如下所示：

```js
ctx.body = ctx.request.body
```

1.  安装`koa-favicon`模块并使用如下：

```js
$ npm i koa-favicon
```

在入口文件中导入`koa-favicon`并注册它，路径为`favicon`，如下所示：

```js
// src/index.js
const favicon = require('koa-favicon')
app.use(favicon('public/favicon.ico'))
```

您可以在 Koa 的 GitHub 存储库中的[`github.com/koajs/favicon`](https://github.com/koajs/favicon)找到有关此中间件的更多信息。这是一个提供`favicon`的中间件，因此让我们创建一个`favicon.ico`文件并将其保存在项目根目录中的`/public`文件夹中。当您刷新主页时，您应该在浏览器标签上看到`favicon`。

1.  安装`koa-static`模块并按以下方式使用它：

```js
$ npm i koa-static
```

在入口文件中导入`koa-static`并按照以下路径进行注册：

```js
const serve = require('koa-static')
app.use(serve('.'))
app.use(serve('static/fixtures'))
```

您可以在 Koa 的 GitHub 存储库中的[`github.com/koajs/static`](https://github.com/koajs/static)找到有关此中间件的更多信息。默认情况下，Koa 不允许您提供静态文件。因此，此中间件将允许您从 API 中提供静态文件。例如，我们刚刚设置的路径将允许我们从项目根目录中的`/static`文件夹访问以下文件：

+   在`127.0.0.1:3000/package.json`处获取`/package.json`。

+   在`127.0.0.1:3000/hello.txt`处获取`/hello.txt`。

在未来的章节中，我们将在创建 Koa API 时使用这个框架。现在，让我们在下一节中发现如何将 Koa 与 Nuxt 集成。

您可以在我们的 GitHub 存储库的`/chapter-8/koa/skeleton/`中找到此框架应用。

# 将 Koa 与 Nuxt 集成

将 Koa 和 Nuxt 集成可以在单域应用程序的单个端口上完成，也可以在跨域应用程序的不同端口上完成。在本章中，我们将进行单域集成，然后我们将指导您完成第十二章中的跨域集成，*创建用户登录和 API 身份验证*。我们将使用在上一节中开发的 Koa 框架来进行这两种类型的集成。单域集成需要在以下步骤中进行一些配置。让我们开始吧：

1.  在 Nuxt 项目的根目录中创建一个`/server/`目录，并在使用`create-nuxt-app`脚手架工具创建项目后，按以下方式构建服务器端目录：

```js
├── package.json
├── nuxt.config.js
├── server
│ ├── config
│ │ └── ...
│ ├── public
│ │ └── ...
│ ├── static
│ │ └── ...
│ └── index.js
└── pages
    └── ...
```

1.  修改默认的`package.json`文件中的默认脚本以使用默认的`Backpack`，该文件与脚手架工具一起提供。

```js
// package.json
"scripts": {
  "dev": "backpack",
  "build": "nuxt build && backpack build",
  "start": "cross-env NODE_ENV=production node build/main.js",
  "generate": "nuxt generate"
}
```

1.  在根目录中创建一个 Backpack 配置文件（我们在其中有 Nuxt 配置文件），将 Backpack 默认的入口目录更改为我们刚刚创建的`/server/`目录：

```js
// backpack.config.js
module.exports = {
  webpack: (config, options, webpack) => {
    config.entry.main = './server/index.js'
    return config
  }
}
```

1.  在`/server/`目录中创建一个`index.js`文件，以以下方式将 Koa（确保您已经安装了 Koa）作为主应用程序导入，并将 Nuxt 作为 Koa 中的中间件：

```js
// server/index.js
import Koa from 'koa'
import consola from 'consola'
import { Nuxt, Builder } from 'nuxt'
const app = new Koa()
const nuxt = new Nuxt(config)

async function start() {
  app.use((ctx) => {
    ctx.status = 200
    ctx.respond = false
    ctx.req.ctx = ctx
    nuxt.render(ctx.req, ctx.res)
  })
}
start()
```

请注意，我们创建了一个异步函数来使用 Nuxt 作为中间件，以便在下一步中可以使用`await`语句来运行 Nuxt 构建过程。

请注意，Consola 是一个控制台记录器，您必须在使用之前通过 npm 安装它。有关此软件包的更多信息，请访问[`github.com/nuxt-contrib/consola`](https://github.com/nuxt-contrib/consola)。

1.  在将 Nuxt 注册为中间件之前，在开发模式下导入 Nuxt 构建过程的配置：

```js
// server/index.js
let config = require('../nuxt.config.js')
config.dev = !(app.env === 'production')

if (config.dev) {
  const builder = new Builder(nuxt)
  await builder.build()
} else {
  await nuxt.ready()
}
```

1.  通过监听其端口和主机来运行应用程序，并使用 Consola 记录服务器状态如下：

```js
app.listen(port, host)
consola.ready({
  message: `Server listening on http://${host}:${port}`,
  badge: true
})
```

1.  在开发模式下启动应用程序：

```js
$ npm run dev
```

我们的 Nuxt 和 Koa 应用现在作为一个单一应用程序运行。您可能已经意识到，Nuxt 现在作为中间件在 Koa 下运行。我们所有的 Nuxt 页面仍然像以前一样在`localhost:3000`上运行，但是我们将在接下来的部分中将`localhost:3000/api`配置为 API 的主要端点。

## 添加路由和其他必要的中间件

在上一节中，我们建立了集成并构建了服务器端目录结构。现在让我们在接下来的步骤中完善一些 API 路由和其他中间件：

1.  通过 npm 安装 Koa Router 和 Koa Static 包：

```js
$ npm i koa-route
$ npm i koa-static
```

1.  创建一个服务器端配置文件：

```js
// server/config/index.js
export default {
  static_dir: {
    root: '../static'
  }
}
```

1.  在`/server/`目录中创建一个`routes.js`文件，用于定义我们将向公众公开的路由，并附带一些虚拟用户数据：

```js
// server/routes.js
import Router from 'koa-router'
const router = new Router({ prefix: '/api' })

const users = [
  { id: 1, name: 'Alexandre' },
  { id: 2, name: 'Pooya' },
  { id: 3, name: 'Sébastien' }
]

router.get('/', async (ctx, next) => {
  ctx.type = 'json'
  ctx.body = {
    message: 'Hello World!'
  }
})

router.get('/users', async (ctx, next) => {
  ctx.type = 'json'
  ctx.body = users
})

router.get('/users/:id', async (ctx, next) => {
  const id = parseInt(ctx.params.id)
  const found = users.find(function (user) {
    return user.id == id
  })
  if (found) {
    ctx.body = found
  } else {
    ctx.throw(404, 'user not found')
  }
})
```

1.  在单独的`middlewares.js`文件中导入其他中间件，并从*步骤 1*和*2*中导入路由和配置文件：

```js
// server/middlewares.js
import serve from 'koa-static'
import bodyParser from 'koa-bodyparser'
import config from './config'
import routes from './routes'

export default (app) => {
  app.use(serve(config.static_dir.root))
  app.use(bodyParser())
  app.use(routes.routes(), routes.allowedMethods())
}
```

我们不会在 API 中使用`koa-favicon`，因为我们以 JSON 格式导出数据，而`favicon.ico`的图像不会显示在浏览器标签上。此外，Nuxt 已经在 Nuxt 配置文件中为我们处理了`favicon.ico`，因此我们可以从骨架中删除`koa-favicon`中间件。相反，我们将创建一个中间件来将我们的 JSON 数据装饰成这两个最终的 JSON 输出

+   200 输出的格式：

```js
{"status":<status code>,"data":<data>}
```

+   所有错误输出的格式（例如 400，500）：

```js
{"status":<status code>,"message":<error message>}
```

1.  在`app.use(serve(config.static_dir.root))`行之前添加以下代码以创建前述格式：

```js
app.use(async (ctx, next) => {
  try {
    await next()
    if (ctx.status === 404) {
      ctx.throw(404)
    }
    if (ctx.status === 200) {
      ctx.body = {
        status: 200,
        data: ctx.body
      }
    }
  } catch (err) {
    ctx.status = err.status || 500
    ctx.type = 'json'
    ctx.body = {
      status: ctx.status,
      message: err.message
    }
    ctx.app.emit('error', err, ctx)
  }
})
```

因此，现在有了这个中间件，我们将不再获得诸如`{"message":"Hello World!"}`的输出，而是会得到以下装饰过的输出：

```js
{"status":200,"data":{"message":"Hello World!"}}
```

1.  在注册 Nuxt 之前，在主`index.js`文件中导入`middlewares.js`文件：

```js
// server/index.js
import middlewares from './middlewares'

middlewares(app)
app.use(ctx => {
  ...
  nuxt.render(ctx.req, ctx.res)
})
```

1.  以开发模式重新运行应用程序：

```js
$ npm run dev
```

1.  然后，如果您访问`localhost:3000/api`上的应用程序，您将在屏幕上获得以下输出：

```js
{"status":200,"data":{"message":"Hello World!"}}
```

如果您访问`localhost:3000/api/users`上的用户索引页面，您将在屏幕上获得以下输出：

```js
{"status":200,"data":[{"id":1,"name":"Alexandre"},{"id":2,"name":"Pooya"},{"id":3,"name":"Sébastien"}]}
```

您还可以使用`localhost:3000/api/users/<id>`来获取特定用户。例如，如果您使用`/api/users/1`，您将在屏幕上获得以下输出：

```js
{"status":200,"data":{"id":1,"name":"Alexandre"}}
```

您可以在我们的 GitHub 存储库的`/chapter-8/nuxt-universal/skeletons/koa/`中找到这个集成示例应用程序。

接下来，我们将看看如何在接下来的部分从 Nuxt 页面上的客户端使用`asyncData`方法请求前面的 API 数据。

# 理解异步数据

`asyncData`方法允许我们在组件初始化之前异步获取数据并在服务器端渲染它。这是一个额外的方法，只在 Nuxt 中可用。这意味着您不能在 Vue 中使用它，因为 Vue 没有这个默认方法。Nuxt 总是在渲染页面组件之前执行这个方法。当通过`<nuxt-link>`组件生成的路由重新访问该页面时，该方法将在服务器端的页面上执行一次，然后在客户端上执行。Nuxt 将从`asyncData`方法中返回的数据与`data`方法或`data`属性中的组件数据合并。该方法将`context`对象作为第一个参数，如下所示：

```js
export default {
  asyncData (context) {
    // ...
  }
}
```

请记住，这个方法总是在页面组件初始化之前执行，所以我们无法通过`this`关键字在这个方法内访问组件实例。有两种不同的使用方法；让我们在接下来的部分中探讨它们。

## 返回一个承诺

我们可以通过返回`Promise`在`asyncData`方法中使用`Promise`对象，例如：

```js
// pages/returning-promise.vue
asyncData (context) {
  const promise = new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve('Hello World by returning a Promise')
    }, 1000)
  })

  return promise.then((value) => {
    return { message: value }
  })
}
```

在前面的代码中，Nuxt 将等待 1 秒钟，直到承诺被解决，然后再使用'通过返回 Promise 来打招呼的 Hello World'渲染页面组件。

## 使用 async/await

我们还可以在`asyncData`方法中使用`async`/`await`语句，例如：

```js
// pages/using-async.vue
async asyncData (context) {
  const promise = new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve('Hello World by using async/await')
    }, 2000)
  })

  const result = await promise
  return { message: result }
}
```

在上述代码中，Nuxt 将等待 2 秒钟，直到承诺被解决，然后使用`'Hello World by using async/await'`消息呈现页面组件。使用`async`/`await`语句是编写异步 JavaScript 代码的新方法。它建立在`Promise`对象之上，并使我们的异步代码更易读。我们将在整本书中经常使用这个语句。

## 合并数据

正如我们之前提到的，`asyncData`方法中的异步数据将与`data`方法或`data`属性中的组件数据合并。这意味着如果您在组件数据中使用了与`asyncData`方法中相同对象键的一些默认数据，它们将被`asyncData`方法覆盖。以下是一个例子：

```js
// pages/merging-data.vue
<p>{{ message }}</p>

export default {
  data () {
    return { message: 'Hello World' }
  },
  asyncData (context) {
    return { message: 'Data Merged' }
  }
}
```

在上述代码中，Nuxt 将合并两组数据，并在屏幕上得到以下结果：

```js
<p>Data Merged</p>
```

您可以在我们的 GitHub 存储库的`/chapter-8/nuxt-universal/koa-nuxt/understanding-asyncdata/`中找到这些示例。

接下来，我们将看看如何在接下来的部分中从`asyncData`方法中访问`context`对象。

# 在 asyncData 中访问上下文

我们可以从 Nuxt 上下文中访问大量有用的数据。它们存储在上下文对象中，作为以下键：

|

+   应用

+   路由

+   存储

+   参数

+   查询

|

+   请求

+   res

+   重定向

+   错误

+   env

|

+   isDev

+   isHMR

+   beforeNuxtRender(fn)

+   来自

+   nuxtState

|

它们是额外提供的，特别是在 Nuxt 中，因此我们在 Vue 中找不到它们。我们可以使用`context.<key>`或`{ <key> }`来访问它们。让我们探索一些这些键，并看看我们如何在接下来的部分中利用它们。

有关 Nuxt 上下文的更多信息，请访问[`nuxtjs.org/api/context`](https://nuxtjs.org/api/context)。

## 访问 req/res 对象

当在服务器端执行`asyncData`方法时，我们可以访问`req`和`res`对象。它们包含用户发送的 HTTP 请求的有用信息。但在访问它们之前，我们应该始终检查`if`条件：

```js
// pages/index.vue
<p>{{ host }}</p>

export default {
  asyncData ({ req, res }) {
    if (process.server) {
     return { host: req.headers.host }
    }
    return { host: '' }
  }
}
```

在上述代码中，我们使用`if`条件来确保在获取请求头信息之前在服务器端调用`asyncData`方法。这两个对象在客户端不可用，因此在客户端访问它们时会得到`undefined`。因此，当页面在浏览器上首次加载时，我们将得到上述代码的结果`localhost:3000`，但是除非刷新该页面，否则当通过`<nuxt-link>`组件生成的路由重新访问此页面时，您将不会再看到该信息。

## 访问动态路由数据

当我们的应用程序中有动态路由时，我们可以通过`params`键访问动态路由数据。例如，如果我们在`/pages/`目录中有一个`_id.vue`文件，那么我们可以通过`context.params.id`来访问路由参数的值。

```js
// pages/users/_id.vue
<p>{{ id }}</p>

export default {
  asyncData ({ params }) {
    return { id: params.id }
  }
}
```

在上述代码中，当在浏览器上调用`users/1`时，`id`将得到`1`。

## 监听查询变化

默认情况下，`asyncData`方法不会在查询字符串更改时执行。例如，如果您在使用`<nuxt-link>`组件的路由上使用诸如`/users?id=<id>`的查询，那么当通过`<nuxt-link>`组件路由从一个查询更改到另一个查询时，`asyncData`将不会被调用。这是因为 Nuxt 默认禁用了查询更改的监听以提高性能。如果您想覆盖此默认行为，可以使用`watchQuery`属性来监听特定参数：

```js
// pages/users/index.vue
<p>{{ id }}</p>
<ul>
  <li>
    <nuxt-link :to="'users?id=1'">1</nuxt-link>
    <nuxt-link :to="'users?id=2'">2</nuxt-link>
  </li>
</ul>

export default {
  asyncData ({ query }) {
    return { id: query.id }
  },
  watchQuery: ['id']
}
```

在上述代码中，我们正在监听`id`参数，因此当导航到`/users?id=1`时，您将得到`1`，而当导航到`/users?id=2`时，您将得到`2`。如果您想为所有查询字符串设置一个观察器，只需将`watchQuery`设置为`true`。

## 处理错误

我们可以使用`context`对象中的`error`方法来调用 Nuxt 默认的错误页面并显示错误。您可以通过默认的`params.statusCode`和`params.message`属性传递错误代码和消息：

```js
// pages/users/error.vue
export default {
  asyncData ({ error }) {
    return error({
      statusCode: 404,
      message: 'User not found'
    })
  }
}
```

如果您想要更改传递给`error`方法的默认属性，您可以创建一个自定义错误页面，您在第四章中学到了如何创建自定义错误属性和布局。让我们按照以下步骤创建这些自定义错误属性和布局：

1.  创建一个要抛出自定义属性的页面：

```js
// pages/users/error-custom.vue
export default {
  asyncData ({ error }) {
    return error({
      status: 404,
      text: 'User not found'
    })
  }
}
```

1.  在`/layouts/`目录中创建一个自定义错误页面：

```js
// layouts/error.vue
<template>
  <div>
    <h1>Custom Error Page</h1>
    <h2>{{ error.status }} Error</h2>
    <p>{{ error.text }}</p>
    <nuxt-link to="/">Home page</nuxt-link>
  </div>
</template>

<script>
export default {
  props: ['error'],
  layout: 'layout-error'
}
</script>
```

1.  为这个错误页面创建一个自定义布局页面：

```js
// layouts/layout-error.vue
<template>
  <nuxt />
</template>
```

当访问`/users/error-custom`时，您应该看到自定义属性和布局。

您可以在我们的 GitHub 存储库的`/chapter-8/nuxt-universal/koa-nuxt/accessing-context/`中看到所有示例。

接下来，我们将看看如何在接下来的部分中使用 Axios，一个 HTTP 客户端，与`asyncData`方法一起请求 API 数据。

# 使用 Axios 获取异步数据

我们创建了一个简单的 API，使用 Koa 暴露了一些公共路由，用于访问其数据，比如`/api/users`和`/api/users/1`。我们还将这个 API 与 Nuxt 集成到一个单一的应用程序中，其中 Nuxt 充当中间件。您还学会了`asyncData`方法的工作原理以及如何利用 Nuxt 上下文。现在，让我们通过在请求 API 数据时使用 Axios 和`asyncData`方法将这三个部分整合在一起。

## 安装和配置 Axios

Axios 是一个基于 Promise 的 Node.js 应用程序的 HTTP 客户端。在上一节中，我们使用了`asyncData`方法与原始的 Promise 一起工作。我们可以使用 Axios 进一步简化我们的代码，并节省一些行数，它是由异步 JavaScript 和 XML（AJAX）支持的，用于进行异步 HTTP 请求。让我们在接下来的步骤中开始吧：

1.  通过 npm 安装 Axios：

```js
$ npm i axios
```

在使用 Axios 进行 HTTP 请求时，我们应该始终使用完整路径。

```js
axios.get('https://jsonplaceholder.typicode.com/posts')
```

但是在每个请求的路径中包含`https://jsonplaceholder.typicode.com/`可能会重复。此外，这个基本 URL 可能会随时间改变。因此，我们应该将其抽象出来并简化请求：

```js
axios.get('/posts')
```

1.  在`/plugins/`目录中创建一个 Axios 实例：

```js
// plugins/axios-api.js
import axios from 'axios'

export default axios.create({
  baseURL: 'http://localhost:3000'
})
```

1.  在组件中需要时导入这个插件：

```js
import axios from '~/plugins/axios-api'
```

安装和配置完成后，我们准备在下一节中获取异步数据。

## 使用 Axios 和 asyncData 获取数据

让我们在接下来的步骤中创建需要呈现数据的页面：

1.  创建一个用于列出所有用户的索引用户页面：

```js
// pages/users/index.vue
<li v-for="user in users" v-bind:key="user.id">
  <nuxt-link :to="'users/' + user.id">
    {{ user.name }}
  </nuxt-link>
</li>

<script>
import axios from '~/plugins/axios-api'
export default {
  async asyncData({error}) {
    try {
      let { data } = await axios.get('/api/users')
      return { users: data.data }
    } catch (e) {
      // handle error
    }
  }
}
</script>
```

在这个页面上，我们使用 Axios 的`get`方法来调用`/api/users`的 API 端点，它将被转换为`localhost:3000/api/users`，用户列表可以如下输出：

```js
{"status":200,"data":[{"id":1,"name":"Alexandre"},{"id":2,"name":"Pooya"},{"id":3,"name":"Sébastien"}]}
```

然后我们使用 JavaScript 的解构赋值`{ data }`来解开输出中的`data`键。在使用`async`/`await`语句时，将代码放在`try`/`catch`块中是一个好习惯。接下来，我们需要请求单个用户的数据。

1.  创建一个用于呈现单个用户数据的单个用户页面：

```js
// pages/users/_id.vue
<h2>
  {{ user.name }}
</h2>

<script>
import axios from '~/plugins/axios-api'
export default {
  name: 'id',
  async asyncData ({ params, error }) {
    try {
      let { data } = await axios.get('/api/users/' + params.id)
      return { user: data.data }
    } catch (e) {
      // handle error
    }
  }
}
</script>
```

在这个页面上，我们再次使用 Axios 的`get`方法来调用`/api/users/<id>`的 API 端点，这将被转换为`localhost:3000/api/users/<id>`，以获取单个用户的数据：

```js
{"status":200,"data":{"id":1,"name":"Alexandre"}}
```

再次使用 JavaScript 的解构赋值`{ data }`来解包输出中的`data`键，并将`async`/`await`代码包装在`try`/`catch`块中。

在下一节中，我们希望实现与本节相同的结果，即获取用户列表和特定用户的数据。但是我们将在单个页面上使用`watchQuery`属性，这是您在上一节中学到的。

## 监听查询变化

在本节中，我们将创建一个页面来监听查询字符串的变化并获取单个用户的数据。为此，我们只需要一个`.vue`页面来列出所有用户并监视查询，如果查询有任何变化，我们将从查询中获取`id`并使用`asyncData`方法中的 Axios 获取具有该`id`的用户。让我们开始吧：

1.  在`/pages/`目录中创建一个`users-query.vue`页面，并将以下模板添加到`<template>`块中：

```js
// pages/users-query.vue
<ul>
  <li v-for="user in users" v-bind:key="user.id">
    <nuxt-link :to="'users-query?id=' + user.id">
      {{ user.name }}
    </nuxt-link>
  </li>
</ul>
<p>{{ user }}</p>
```

在这个模板中，我们使用`v-for`指令来循环遍历每个`users`中的`user`，并将每个用户的查询添加到`<nuxt-link>`组件中。单个用户的数据将在`<ul>`标签之后的`<p>`标签内呈现。

1.  将以下代码添加到`<script>`块中：

```js
// pages/users-query.vue
import axios from '~/plugins/axios-api'

export default {
  async asyncData ({ query, error }) {
    var user = null
    if (Object.keys(query).length > 0) {
      try {
        let { data } = await axios.get('/api/users/' + query.id)
        user = data.data
      } catch (e) {
        // handle error
      }
    }

    try {
      let { data } = await axios.get('/api/users')
      return {
        users: data.data,
        user: user
      }
    } catch (e) {
      // handle error
    }
  },
  watchQuery: true
}
```

这段代码与`/pages/users/index.vue`相同；我们只是在`asyncData`中添加了一个`query`对象，并根据查询中的信息获取用户数据。当然，我们还添加了`watchQuery: true`或`watchQuery: ['id']`来监视查询的变化。因此，在浏览器中，当您从列表中点击一个用户，比如`users-query?id=1`，该用户的数据将呈现在`<p>`标签内，如下所示：

```js
{ "id": 1, "name": "Alexandre" }
```

干得好！您已经到达了本章的结尾。我们希望这对您来说是一个简单而容易的章节。除了使用 Axios 向 API 后端发出 HTTP 请求，我们还可以使用这些 Nuxt 模块之一：Axios 和 HTTP。在本书中，我们专注于原始的 Axios 和 Axios 模块。您还记得我们在第六章中介绍过 Axios 模块吗，*编写插件和模块*？我们将在接下来的章节中经常使用这个模块。现在，让我们总结一下您在本章学到的内容。

你可以在我们的 GitHub 存储库中的`/chapter-8/nuxt-universal/koa-nuxt/using-axios/axios-vanilla/`找到上述代码。如果您想了解更多关于 Nuxt HTTP 模块的信息，请访问[`http.nuxtjs.org/`](https://http.nuxtjs.org/)。

# 总结

在本章中，您已经学会了如何配置 Nuxt 与服务器端框架，本书中使用的是 Koa。您已经安装了 Koa 及其依赖项，以便创建 API。然后，您使用`asyncData`和 Axios 从 API 查询和获取数据。此外，您还了解了 Nuxt 上下文中的属性，可以从`asyncData`方法中解构和访问，例如`params`，`query`，`req`，`res`和`error`。最后，您开始在应用程序中使用 Backpack 作为一个极简的构建工具。

在下一章中，您将学习如何设置 MongoDB 并编写一些基本的 MongoDB 查询，如何向 MongoDB 数据库添加数据，如何将其与刚刚在本章中学习的服务器端框架 Koa 集成，最后，如何将其与 Nuxt 页面集成。我们将指导您学习一切，以便创建一个更完整的 API。所以，请继续关注。
