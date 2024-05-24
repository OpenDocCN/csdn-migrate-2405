# Vue2 设计模式最佳实践（五）

> 原文：[`zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8`](https://zh.annas-archive.org/md5/6E739FB94554764B9B3B763043E30DA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：模式

在本章中，我们将看看 Vue.js 中的各种反模式，并在高层次上回顾我们在整本书中学到的概念。我们将看看各种模式和反模式，以及我们如何编写能够在团队和自己的项目中保持一致的代码。

在将任何东西定义为*模式*或*反模式*之前，重要的是为读者准确定义两者。如果某事被认为是一种模式，这意味着在绝大多数情况下这是一种推荐的做法。相反，如果我将其定义为反模式，那么在绝大多数情况下，这很可能不是一种推荐的做法。关于这一点的更多信息，可以在[`github.com/pablohpsilva/vuejs-component-style-guide`](https://github.com/pablohpsilva/vuejs-component-style-guide)找到模式和指南的良好来源。

软件开发是一个主观的领域，有各种解决同一问题的方式，因此可能有一些被归类为你不同意的意识形态，这是可以的。在一天结束时，每个团队都有自己的风格，但开发人员应该努力坚持能够减少摩擦并加快开发速度的模式。

在本章中，我们将学习以下主题：

+   Vue 项目中的常见模式和反模式

+   容器/展示组件

+   如何编写可测试的 Vue.js 组件

# 组件

在 Vue 中，组件之间有许多通信方式，例如使用 props、事件和基于 store 的场景。Vue 还给我们提供了`$parent`和`$children`对象的访问权限，允许我们与父/子组件进行交互。让我们来看看这个，并看看为什么不应该使用它。

# 通信-反模式

想象一下我们熟悉的`TodoList`示例，在`TodoItem`组件中，我们希望能够完成特定的 Todo。如果我们想要将我们的 todos 保留在`TodoList`中，因此从`TodoItem`中调用完成方法，我们可以这样做：

```js
export default {
  props: ['todo'],
  methods: {
    completeTodo(todo) {
      this.$parent.$options.methods.completeTodo(todo);
    }
  }
}
```

出于许多原因，这是一个坏主意，主要是因为我们将这两个组件紧密耦合在一起，并假设父组件上始终会有一个`completeTodo`方法。

# 我们可以改变什么来使它变得更好？

我并不是说父/子组件不能通信，但你应该设计组件的方式是灵活的。根据应用程序的结构，使用事件或 Vuex 存储。这里有一个使用事件的例子：

```js
methods: {
  completeTodo(todo) {
    this.$emit('completeTodo', todo)
  }
}
```

# 子组件变异道具-反模式

重要的是我们不应该在子组件内修改道具。当传递给组件时，道具应被视为真相的来源，因此在子组件内更改值通常是不好的做法。然而，也有一些特殊情况，可能适当这样做，比如使用`.sync`修饰符实现双向数据绑定时。

如果我们使用先前的示例并在子组件内更改 todos 道具，我们将在控制台内收到警告：

```js
methods: {
  completeTodo(todo) {
    this.todo = [{id: 1, name: 'Do the dishes.'}];
    this.$emit('completeTodo', todo)
  }
}
```

# 我们应该做什么？

如果你想在子组件内使用道具，最好将道具保存为`data`选项内的新变量。这样可以使您变异道具的新版本，局限于此组件：

```js
export default {
  props: {
    age: {
      type: Number,
    }
  },
  data() {
    return {
      personAge: this.age
    }
  },
}
```

然后我们可以访问和变异`personAge`而不必担心任何副作用。另一个例子是创建一个可过滤的搜索框，而不是直接变异道具，可以创建一个执行所需功能的`computed`属性：

```js
export default {
  props: {
    filter: {
      type: String,
    }
  },
  computed: {
    trimFilter() {
      return this.filter.trim().toLowerCase()
    }
  }
}
```

# 变异属性数组

在 JavaScript 中传递数组和对象作为属性时，需要考虑的一个重要因素是它们是按引用传递的。这意味着在子组件内对原始数组的任何更改也会泄漏到父组件中。让我们看看这个例子：

```js
<template>
  <div>
    <h1>Parent Component</h1>
    <ul>
      <li v-for="friend in friendList" :key="friend.id">{{friend.name}}</li>
    </ul>

    <Person :friendList="friendList" />
  </div>
</template>

<script>
import Person from './components/Person';

export default {
  data() {
    return {
      friendList: [{ id: 1, name: 'John Doe' }]
    }
  },
  components: {
    Person
  }
}
</script>
```

在这里，我们有一个包含数组的组件（`App.vue`），我们将其显示在屏幕上并传递到子组件中。我们将在子组件内在屏幕上显示相同的数组，但还会给子组件一个按钮，用于向数组中添加新项：

```js
<template>
  <div>
    <h1>Child Component</h1>
    <ul>
      <li v-for="friend in friendList" :key="friend.id">{{friend.name}}</li>
    </ul>
    <button @click="addFriend">Add Friend</button>
  </div> 
</template>

<script>
export default {
  props: {
    friendList: {
      type: Array,
    }
  },
  methods: {
    addFriend() {
      this.friendList.push({ id: 2, name: 'Sarah Doe' })
    }
  }
}
</script>
```

当我们向朋友列表中添加一个新人时，这是我们的结果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/0d2c36e1-e927-4e12-b168-b6b066a619e2.png)

然后，两个组件都有相同的数组！这不是我们想要的。如果出于某种原因我们想要执行这样的操作，最好保留朋友列表的副本并进行变异，如下所示：

```js
export default {
  props: {
    friendList: {
      type: Array,
    }
  },
  data() {
    return {
      fList: [...this.friendList]
    }
  },
  methods: {
    addFriend() {
      this.fList.push({ id: 2, name: 'Sarah Doe' })
    }
  }
}
```

# 使用数据作为对象-反模式

在创建 Vue 组件时，重要的是数据选项是一个返回包含数据的新对象的函数，而不仅仅是一个普通的数据对象。

如果你简单地使用一个不是函数的数据对象，那么组件的所有实例将共享相同的数据。这是不好的，因为你可以想象到，每当数据发生变化时，组件的所有实例都会被更新为相同的数据。重要的是要确保每个组件都能够管理自己的数据，而不是在整个组件之间共享数据。

让我们来看一下问题所在：

```js
data: {
 recipeList: [],
 selectedCategory: 'Desserts'
}
```

我们可以通过这样做来修复这个问题：

```js
data () {
 return {
  recipeList: [],
  selectedCategory: 'Desserts'
 }
}
```

通过创建`return`语句，它允许每个创建的实例都有自己的对象，而不是共享一个对象。这样就可以在没有共享数据冲突的情况下多次使用代码。

接下来，让我们来看一下命名组件的最佳实践。

# 组件命名 - 反模式

将组件命名为单个单词并不是一个好主意，因为它有可能与原生 HTML 元素发生冲突。假设我们有一个注册表单和一个名为`Form.vue`的组件；在模板中使用时，什么样的名称才是合适的呢？

嗯，你可能会想象到，拥有一个名为`<form>`的组件将与`<form>`冲突，因此最佳实践是使用多于一个单词命名的组件。一个更好的例子可以是`signup-form`，`app-signup-form`或`app-form`，具体取决于个人偏好：

```js
// This would not be an appropriate name as it conflicts with HTML elements.
Vue.component('form', Form)

// This is a better name as it's multi-word and there are less chances to conflict.
Vue.component('signup-form', Form)
```

# 模板表达式

通常情况下，当我们在屏幕上显示项目时，我们可能需要计算值并调用函数来改变我们的数据外观。建议不要在模板内部进行这项工作，而是将其移到`computed`属性中，因为这样更容易维护。

```js
// Bad 
<nuxt-link :to="`/categories/${this.category.id}`" class="card-footer-item">View</nuxt-link>

// Good
<nuxt-link :to="categoryLink" class="card-footer-item">View</nuxt-link>

export default {
  props: ['category'],
  computed: {
    categoryLink () {
      return `/categories/${this.category.id}`
    }
  }
}
```

这意味着我们的模板中的任何更改都更容易处理，因为输出被映射到一个计算属性。

# 模式 - 容器/展示组件

组件设计的一个重要部分是确保你的组件是可测试的。你应该把每个组件都看作是应用程序中的一个独立模块，可以根据需要进行切换；因此，它不应该与另一个组件紧密耦合。

最好的方法是确保你的组件在确保轻耦合之后是可测试的，通过组件属性具有明确定义的公共 API，然后使用事件在父/子组件之间进行通信。这也有助于我们进行测试，因为我们能够更容易地模拟组件。

遵循这种模式时常见的模式是容器/展示组件。这意味着我们将所有业务逻辑和状态保留在“容器”中，然后将状态传递给“展示”组件以在屏幕上显示。

展示组件仍然可以通过事件与其他组件通信，如果必要的话，但不应修改或保存外部传入 props 之外的状态。这确保了我们的组件之间有一个共同的数据流，这意味着我们的应用程序更容易理解。

这是一个明确命名的组件—`DogContainer.vue`：

```js
<template>
  <dog-presentational :dogName="dogName" @woof="woof"></dog-presentational>
</template>

<script>
import DogPresentational from './DogPresentational'

export default {
  data() {
    return {
      dogName: 'Coco',
    }
  },
  components: {
    'dog-presentational': DogPresentational
  },
  methods: {
    woof() {
      alert('Woof!');
    }
  },
}
</script>
```

容器组件已将狗的名字（以及任何其他项目）作为属性传递到展示组件中。容器组件还在此组件上监听名为`woof`的事件，并在发出时调用`woof`方法。这是我们的展示组件：

```js
<template>
  <div>
    <h1>Name: {{dogName}}</h1>
    <button @click="woof">Woof</button>
  </div>
</template>

<script>
export default {
  props: ['dogName'],
  methods: {
    woof() {
      this.$emit('woof')
    }
  }
}
</script>
```

我们的组件关注点现在清晰地分离开来，并且它们之间有一个明确的通信路径。

这种组合可以在以下图中可视化：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/88c31e61-8f44-4bc8-a702-5768fe482873.png)组合组件

# Prop 验证

虽然我们应该通过 props 在子组件之间进行通信，但在验证属性时要考虑类型、要求、默认值等，是很重要的。在整本书中，我为简洁起见使用了这两种技术的混合，但在生产中，props 应该得到适当的验证。让我们首先看一些属性类型的示例：

```js
export default {
  props: {
    firstName: {
      type: String
    },
    lastName: {
      type: String
    },
    age: {
      type: Number
    },
    friendList: {
      type: Array
    }
  },
}
```

我们还有其他各种类型可用，例如布尔值、函数或任何其他构造函数（即 Person 类型）。通过准确定义我们期望的类型，这使我们（和我们的团队）更好地理解我们可以在这个组件中期望什么。

同时，我们还可以确保 props 是必需的。这应该在必要时进行，这样我们就可以确保每当组件被使用时，没有缺少必需的 props：

```js
  props: {
    firstName: {
      type: String,
      required: true,
      default: 'John'
    },
    lastName: {
      type: String,
      required: true,
      default: 'Doe'
    }
  }
```

我们应该始终在可能的情况下为我们的 props 提供默认值，因为这减少了必要的配置，但仍允许开发人员自定义组件。在处理对象和数组时，函数被用作默认参数，以避免实例共享相同的值的问题。

```js
props: {
  firstName: {
    type: String,
    default: 'John'
  },
  lastName: {
    type: String,
    default: 'Doe'
  },
  friendList: {
    type: Array,
    default: () => [{ id: 1, name: 'Paul Halliday'}]
  }
}
```

我们还可以为我们的属性分配一个自定义的“验证器”函数。假设我们有一个插槽“机器”组件，只有在用户年满 18 岁时才会被渲染：

```js
  props: {
    age: {
      type: Number,
      required: true,
      validator: value => {
        return value >= 18
      }
    },
  }
```

# 理解响应性

我们已经讨论了响应性以及它在之前的章节中如何使用，但重新考虑是很重要的。当我们在 Vue 中创建响应式数据对象时，它会使用`Object.defineProperty`来获取每个属性并添加适当的 getter/setter。这允许 Vue 处理对象的更改并通知观察者，随后更新组件[`vuejs.org/v2/guide/reactivity.html`](https://vuejs.org/v2/guide/reactivity.html)。可以这样来可视化：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/19fa61cd-d221-4b75-9d73-262ea5d107a8.png)可视化响应性

这意味着在数据选项中定义的任何属性都会自动变为响应式。这里有一个例子：

```js
export default {
  data() {
    return {
      name: 'Vue.js'
    }
  }
}
```

在这个 Vue 实例中，`name`属性是响应式的，但如果我们在 Vue 实例之外添加另一个属性，那么它就不会是响应式的。让我们看一个例子：

```js
export default {
  data() {
    return {
      items: [
        { id: 1, name: 'Bananas'},
        { id: 2, name: 'Pizza', quantity: 2},
        { id: 3, name: 'Cheesecake', quantity: 5}
      ] 
    }
  },
}
```

我们的`groceries`组件有一个包含各种对象的 items 数组。每个对象都有一个数量，除了`香蕉`对象，但我们想为其设置数量。在使用`v-for`时，包含`v-bind:key`（或简写为`:key`）是很重要的，因为它作为每个项目的唯一标识符，从而允许重用和重新排序每个节点。虽然`key`可能是`v-for`的属性，但请记住它还有其他用例场景。

```js
<template>
  <div>
    <ul>
      <li v-for="(item, index) in items" :key="item.id" @click="addQuantity(index)">
        {{item.name}} {{item.quantity}}
      </li>
    </ul>
  </div> 
</template>

<script>
export default {
  data() {
    return {
      items: [
        { id: 1, name: 'Bananas'},
        { id: 2, name: 'Pizza', quantity: 2},
        { id: 3, name: 'Cheesecake', quantity: 5}
      ] 
    }
  },
  methods: {
    addQuantity(selected) {
      this.items[selected].quantity = 1;
      console.log(this.items);
    }
  }
}
```

然后，我们转到浏览器，并使用开发工具访问`控制台`，我们可以看到数量已经被设置为保存我们对象的值。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/798a236b-ab31-40b6-9a58-52bccc0adba1.png)

请注意，当在数据对象中定义包含数量的数量对象时，会有响应式的 getter 和 setter。在事后向 items 添加属性意味着 Vue 不会添加适当的 getter/setter。如果我们想要这样做，我们必须使用`Vue.set`：

```js
methods: {
  addQuantity(selected) {
    const selectedItem = this.items[selected];
    this.$set(selectedItem, 'quantity', 2)
    console.log(this.items);
  }
}
```

这一次，我们的实例中的每个属性都有 getter/setter：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-dsn-ptn-best-prac/img/19cca632-7a91-4a97-baad-a18ac0e6a363.png)

# 总结

在本章中，我们看了反模式和模式，并且我们扩展了我们的知识，不仅知道它们是什么，还知道何时适合使用它们以符合最佳实践。不仅如此，我们还在本章中回顾了我们在整本书中学到的许多概念，同时考虑了一些新的想法和技术，可以在未来使用。

回顾之前的章节，我们可以回顾过去，看到我们已经覆盖了多少内容。实践本书中涵盖的技术将使您能够使用 Vue.js 创建可扩展的应用程序，并建立在您所学到的基础上。另一件重要的事情要记住的是，**web 开发一直在不断发展**，Vue 的*实际应用*数量不断增长，*你也应该如此*。

接下来呢？尝试新事物！建立新项目，参加 Vue.js 的会议和会议 - 找到新的方式来运用你的技能来教别人。你不仅会对他人产生积极影响，而且会重新确认自己作为开发者的技能。
