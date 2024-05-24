# VueJS 表单构建指南（二）

> 原文：[`zh.annas-archive.org/md5/89D4502ECBF31F487E1AF228404A6AC0`](https://zh.annas-archive.org/md5/89D4502ECBF31F487E1AF228404A6AC0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：创建模式驱动的表单

表单有不同的形状、大小和复杂程度。快速搭建一个登录表单或联系表单只需要几个字段，但是当你需要将其提升到下一个级别，并创建一个完全由 API 或模式驱动的动态表单时会发生什么？

到目前为止，我们已经使用了一个相对简单的表单，只要求用户提供一些基本数据，但是一切都是硬编码的静态表单。如果我们的模拟网站想要添加或删除表单中的一些字段，我们将不得不手动进行更改，部署到我们的服务器上，甚至可能还要调整后端来处理不同的字段。但是如果我们想要自动化整个过程呢？

在本章中，我们将构建一个完全由 API 端点驱动的示例动态表单。模式驱动的表单非常强大，因为它们可以直接由应用程序的 API 控制和修改。这意味着当后端发生变化时，你的表单将自动调整自己，不仅在前端，还会自我意识地理解如何将动态数据发送回 API。

本章将涵盖以下主题：

+   探索起始套件

+   准备模式

+   加载模式并创建`Renderer`组件

+   动态绑定用户数据

+   创建模拟 API

+   将新的 API 加载到应用程序中

+   将 API 转换为可用模式

# 技术要求

我假设你已经阅读或理解了前几章中介绍的概念，比如使用 Axios 进行 HTTP 调用和组件创建，并且在你的系统上安装了一个模拟 API 提供程序。你可以参考这个链接获取更多信息：[`mockoon.com/`](https://mockoon.com/)。

为了加快我们应用程序的搭建过程，我已经为我们设置了一个由 Vue CLI-3 驱动的起始存储库，其中包含一些自定义组件和一个示例静态表单。你可以从以下链接克隆或下载它：

[`github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter07`](https://github.com/PacktPublishing/Building-Forms-with-Vue.js/tree/master/Chapter07)。

查看以下视频，了解代码的运行情况：

[`bit.ly/2VMe3eU`](http://bit.ly/2VMe3eU)

# 探索起始套件

克隆或下载起始存储库后，您将发现自己拥有一个 Vue CLI 3 项目。首先要做的是看一下我们将要使用的内容！存储库中包含一个非常简单的表单，其中包含一些输入字段和一个选择框。您可以在`App.vue`中找到表单的结构。正如您所看到的，我们使用了两个不同的自定义组件，`BaseInput`和`BaseSelect`。这两个组件都可以在`src/components`文件夹中找到。它们分别包装了`input`和`select`标签，并公开了一些属性，我们可以使用这些属性将必要的数据注入到每个组件中，例如`labels`和`options`。

我已经在项目依赖项中添加了 Axios；您可以查看`package.json`来证实。Bootstrap 的 CSS 文件用于一些基本类已经在`main.js`中导入。

现在我们已经对项目结构有了一个很好的概述，让我们继续安装依赖项并在浏览器上运行它们。按照以下步骤进行：

1.  进入终端并运行以下命令：

```js
    > npm install
    > npm run serve
```

1.  完成后，检查浏览器上的表单并尝试操作字段。除了字段被`v-model`绑定到`App.vue`中的本地状态之外，没有任何花哨的东西。

提交按钮只会将消息记录到控制台-如果您想了解如何将表单数据发送到服务器，请查看本书的第二章，“最简单的表单”，进行复习。

现在您已经了解了我们应用程序的起点，我们将在下一节中准备演示模式。

# 准备模式

目前，我们的表单（如前所述）是硬编码的。开始使其成为动态表单所需的第一步是消除每次需要添加新字段时直接向我们的`App.vue`文件添加`BaseInput`或`BaseSelect`的需要。这意味着我们需要有一种有组织的结构或模式来表示我们为表单所要实现的内容。由于我们使用 JavaScript，以 JSON 对象格式来做这件事是最合乎逻辑的方式。这将使我们在以后想要更进一步并让我们的模拟 API 直接向我们的表单提供信息时更容易。

现在，我们将使用一个静态模式。让我们在 `src` 内创建一个 data 文件夹，并在其中创建一个新的 `schema.json` 文件。我们将用一些虚拟数据填充我们的 JSON 文件。为了举例说明，我选择将顶层元素设置为一个对象，其中每个属性代表表单中的一个字段。每个元素至少包括一个 `component` 属性和一个 `label` 属性。然而，在下拉菜单的情况下，我们还将包括 `options` 来填充它。

要创建演示模式，请将以下数据添加到 `schema.json` 中：

```js
      {   "firstName": {   
          "component": "BaseInput",
             "label": "First name"
          },
          "lastName": {
              "component": "BaseInput",
              "label": "Last name"
          },
          "favoriteAnimal": {
              "component": "BaseSelect",
              "label": "What's your favorite animal?",
              "options": [
                  { "label": "Cat", "value": "cat" },
                  { "label": "Dog", "value": "dog" },
                  { "label": "Sea Otter", "value": "onlyvalidanswer" }
              ]
          }
      }
```

现在我们有了一个结构化的模式作为我们动态表单理解的演示，我们可以继续到下一节——在那里我们将使用 `Renderer` 组件将这个模式加载到我们的应用程序中。

# 加载模式和创建 Renderer 组件

现在我们已经设置了一个基本的模式来使用，让我们继续加载到应用程序中以便我们可以使用它。在本章的后面，我们将创建一个虚拟的 API，以稍微不同的方式提供数据，并且我们将在我们的应用程序中对其进行转换以符合我们的应用程序的要求。

现在，让我们去 `App.vue` 并导入 JSON。我们将首先在顶部附近的其他导入语句中添加以下 `import` 语句：

```js
import schema from '@/data/schema.json';
```

现在我们的应用程序可以使用这些数据，我们需要一些组件来将这些信息解析成 `BaseInput` 和 `BaseSelect` 组件。让我们继续在 `components` 文件夹内创建一个新文件，并将其命名为 `Renderer.vue`。这个组件将有一个单一的目的：理解我们的模式并将正确的组件呈现到屏幕上。它目前将具有一个属性 `element`，代表我们模式中的每个元素。为此，请将以下代码添加到 `Renderer.vue` 中：

```js
      <template>
        <component 
          :is="component" 
          v-bind="props"
        />
      </template>
      <script>
      export default {
        props: {
          element: {
            type: Object,
            required: true
          }
        },
        computed: {
          component() {
            const componentName = this.element.component;
            return () => import(`./${componentName}`);
          },
          props() {
            return this.element;
          }
        }
      }
      </script>
```

在这个组件中有几个重要的事情需要注意。它们如下：

+   `element` 属性是一个对象，是必需的。没有它，这个组件根本无法工作。我们有两个计算属性。第一个组件负责动态加载我们需要的任何元素。首先，我们创建一个 `componentName` 常量，并将其赋值为 `element.component` 的值，这是我们组件的字符串名称存储在模式中的地方。

+   重要的是要提到，我们不只是为了清晰起见而添加这个`const`。关于缓存，计算属性的工作方式要求这个`const`存在，因为我们返回一个函数，这个函数不会被检查其依赖关系。

+   当`<component>`标签调用这个计算属性时，`:`是一个属性 - 它将加载组件并传递过去。请注意，这仅在组件全局注册的情况下才有效；在任何其他情况下，将需要一个需要正确组件的计算属性。有关动态组件的更多信息，请查看官方文档：[`vuejs.org/v2/guide/components-dynamic-async.html`](https://vuejs.org/v2/guide/components-dynamic-async.html)。

第二个计算属性`props`将简单地将整个元素及其属性作为`props`传递给我们使用`v-on`绑定加载的任何组件。例如，在`BaseSelect`组件上，它将将我们模式中的`options`属性传递给组件，以便它可以呈现正确的选项。如果你想知道为什么我们使用计算属性而不是直接将元素传递给`v-on`指令，你是对的。现在，绝对不需要，但是以这种方式设置它，可以让我们以后添加另一层逻辑或解析，这可能是特定组件所需的。

让我们回到`App.vue`。

我们需要导入我们的`Renderer`组件并将其添加到`template`中。我们还需要进行一些清理；我们不再需要手动导入`BaseInput`或`BaseSelect`，我们的表单本地状态很快将是动态的 - 因此，没有必要像下面的代码片段中静态声明它：

```js
      <template>
        <div id="app" class="container py-4">
          <div class="row">
            <div class="col-12">
              <form>
                <Renderer 
                 v-for="(element, name) in schema" 
                  :key="name" 
                  :element="element" 
                />
               <div class="form-group">
                  <button 
                    @click.prevent="onSubmit" 
                    type="submit" 
                   class="btn btn-primary"
                  >Submit</button>
                </div>
              </form>
           </div>
          </div>
        </div>
      </template>

      <script>
      import schema from '@/data/schema.json';
      import Renderer from '@/components/Renderer';
      export default {
        name: 'app',
        components: { Renderer },
        data() {
          return {
            schema: schema,
            form: {}
          }
        },
        methods: {
          onSubmit() {
            console.log('Submit clicked');
          }
        }
      }
      </script>
```

继续在浏览器中运行它，你应该会看到模式在`schema.json`中声明的三个输入，`<select>`中应该有我们的三个选项。此时你会得到一些控制台错误，因为我们还没有为组件的双向值绑定工作，并且它们被设置为必需。但不用担心，我们很快就会解决这个问题！

# 动态绑定用户的数据

如果我们无法使用用户输入的数据，那么任何表单有什么用呢？尽管我们可以根据模式完全动态地生成这些表单，这很酷，但我们仍然需要能够以某种方式存储这些值，以便以后根据需要对它们进行处理。我们的表单能够创建双向绑定的第一步是告诉`Renderer.vue`如何处理来自动态组件的输入事件。

按照以下步骤进行：

1.  让我们进入`Renderer.vue`，为`<component>`添加`:value`绑定，以及一个`@input`监听器：

```js
      <component 
        :is="component" 
        v-bind="props"
        :value="value"
        @input="handleComponentInput"
      />
```

记住，为了`v-model`或双向绑定到自定义组件，通常我们需要传入一个值并监听输入事件。在这种情况下，我们将明确监听输入事件，因为我们的自定义组件都会触发这种类型的事件以进行双向绑定。

1.  继续为我们的`Renderer`组件添加新的`value`属性：

```js
      props: {
        element: {
          type: Object,
          required: true
      },
        value: {
          required: true
        }
      }
```

最后，我们需要实现`handleComponentInput`方法。请记住，我选择将其作为一个方法而不是直接在`template`中触发`$emit`的原因有两个。第一个是我发现这样做更容易编写单元测试，第二，如果我们需要为具有特定要求的特定组件编写`if`语句或条件，它可以提供更大的灵活性。

1.  添加新的`handleComponentInput`方法：

```js
      methods: {
        handleComponentInput (value) {
          this.$emit('input', value);
        }
      }
```

现在渲染器已经准备好与`v-model`进行双向绑定了，让我们回到`App.vue`，在那里我们正在实现它并添加实际的绑定。我们将在`<Renderer>`中添加`v-model`属性，这里的诀窍是我们将它绑定到`form[name]`。记住，我们的模式具有一个结构，其中属性的名称是该字段的唯一标识符。打开`schema.json`来查看它。

例如，在第一个字段中，`firstName`是保存模式对象中第一个空格的属性的名称。这个属性是我们将要绑定的，这样我们以后就可以知道它在我们的数据中代表哪个字段。

1.  让我们在`App.vue`中的`<Renderer>`中添加我们的`v-model`：

```js
      <Renderer 
        v-for="(element, name) in schema" 
        :key="name" 
        :element="element" 
        v-model="form[name]"
      />
```

打开浏览器，查看你的表单；如果你开始填写字段并查看你的`Vue`开发工具，你会看到绑定都正常工作。渲染器通过动态的`v-model`所做的是将每个属性都绑定到本地数据表单的一个属性上。

1.  如果您想以更快的方式看到这个示例，而不必使用`dev`工具，可以将以下代码添加到`<Renderer>`组件中的`App.vue`中：

```js
      <pre>{{ form }}</pre>
```

我们只是简单地将表单放到屏幕上，并使用 HTML 的`<pre>`标签进行简单格式化。尝试进入`schema.json`并添加一些新字段。您将立即在浏览器上看到结果，因为渲染器将会注意到模式的更改，并且页面将自动重新加载（热重载）。有了新的模式，您将看到所有新字段都已就位。

我们正在快速取得进展！在接下来的部分，我们将再次准备演示 API。在实际应用中，您不会从文件中提供模式，而是从服务器中提供。启动 Mockoon，让我们开始吧！

# 创建模拟 API

我们演示的下一步是创建一个实际的模拟 API，然后将其转换为我们的渲染器理解的结构。为什么我们要这样解决这个问题呢？在实际工作场景中，后端通常不会完全匹配前端的需求。也许 API 是首先构建的，或者是根据早期版本的前端设计的，工作方式完全不同；有很多可能性，在这种情况下，我们将调整不兼容的 API，以学习如何防范这种情况。

这种方法还确保我们有一个中间人，将*翻译*并理解我们应用的 API。如果由于任何原因 API 发生变化，我们可以安全地只需更改这个中间人来调整变化，并且在大多数情况下甚至不必触及应用的任何内部组件。

按照这些步骤：

1.  启动 Mockoon，这是我们在整本书中用于虚拟 API 调用的应用程序。如果您还没有安装它，可以在这里找到下载链接：[`mockoon.com/`](https://mockoon.com/)。

1.  确保环境正在运行，点击绿色播放按钮，并在第二列顶部点击“添加路由”按钮。在右侧屏幕上，我们将添加一些数据。让我们从路径开始。

1.  在路由设置下，将 GET 保留为路由的默认动词，并继续命名路径为`/schema`。

1.  继续导航到第二个选项卡，标头，并将单个标头设置为 Content-Type：`application-json`。另一方面，这将为我们的下一部分提供一些漂亮的颜色编码。

1.  返回第一个选项卡，响应和正文。

1.  在 Body 部分，继续复制以下结构。请注意，这不是我们以前在`schema.json`文件中的内容，而是一个类似的结构，我们以后需要解释。我们甚至会忽略其中的一些数据，因为它对我们当前的表单没有用处——有时 API 返回的数据我们并不真的用到是很常见的：

```js
{
  "fieldCount": 4,
    "fields": [
        { 
            "type": "input",
            "id": "firstName",
            "label": "First Name"
        },
        {
            "type": "input",
            "id": "lastName",
            "label": "Last Name"
        },
        {
            "type": "input",
            "id": "email",
            "label": "Email"
        },
        {
            "type": "singleChoice",
            "label": "What's your favorite animal?",
            "opts": [
                { "label": "Cat", "value": "cat" },
                { "label": "Dog", "value": "dog" },
                { "label": "Sea Otter", "value": "onlyvalidanswer" 
                }
            ]
        }
    ]
}
```

仔细观察这种情况下 API 返回的 JSON 的结构。您将开始看到后端试图描述它需要什么，以及前端渲染器期望得到什么的一些相似之处。

如果您在日常生活中面临这种选择，您会意识到我们可以采取两种方式：

+   我们可以在组件级别上改变前端实现以适应新的 API，这在某些情况下可能是我们想要的。

+   或者，我们可以制作一个小型库或文件，用于解释我们后端的 API。出于我之前描述的原因，我们选择这个选择。

现在我们有了虚拟 API，我们可以教会我们的应用程序如何*翻译*这种新的 API 格式为它所理解的内容。这个过程的这一部分非常重要，因为您不希望在后端发生变化时每次都要修改整个应用程序。

# 将新的 API 加载到应用程序中

现在，如果您进入`App.vue`，您会注意到我们通过`import`语句加载静态模式，如下所示：

```js
import schema from '@/data/schema.json';.
```

这在以前对我们非常有效，因为它是一个静态文件，但这一次，我们需要调用我们的 API 端点来获取我们表单的模式。让我们首先删除导入语句；我们不再需要它，可以安全地删除它。您还可以进入`data()`属性并将`schema`设置为默认值，即一个空对象：

```js
schema: {},
```

我认为一个很好的加载表单模式的地方将是在我们的`App.vue`文件的 created hook 上。我们希望尽快完成这项工作，当加载时我们并不真的需要操作任何 DOM，只需设置对模式的内部属性的调用结果。

按照以下步骤：

1.  让我们在`App.vue`文件的顶部导入 Axios，靠近`Renderer`导入，因为我们很快就要用到它：

```js
      import axios from 'axios';
```

1.  继续向我们的`App.vue`组件添加一个新创建的 hook；在其中，我们将对我们的模拟 API 端点进行简单的 Axios 调用。记得检查 Mockoon 是否正在运行：

```js
      created() {
        axios.get('http://localhost:3000/schema')
        .then(response => {
          this.schema = response.data;
        })
        .catch(error => {
          console.log('Network error', error);
        })
      }
```

我们正在调用我们的新端点`http://localhost:3000/schema`，使用 Axios 的`GET`方法。确保检查 Mockoon 是否使用端口`3000`作为你的模拟 API，或者随时根据需要调整 URL。Axios 调用返回一个 promise——如果失败，我们将记录错误。然而，如果调用成功，我们要确保捕获整个响应，并将这个响应的`data`属性传递给模式的内部数据。重要的是要记住，在这种特殊情况下，API 返回给我们的响应应该是直接的 JSON 模式对象。如果你的 API 返回不同的结构，比如嵌套对象或数组，你将需要相应地进行调整。

如果需要，打开浏览器并重新加载页面。看起来我们完全搞砸了应用程序，这是预料之中的。当我们将新的 API 响应分配给我们模式的`data`属性时，应用程序试图将每个项目加载到渲染器中，但它并没有准备好理解我们后端提供的这种新模式格式。

在下一节中，我们将看看如何构建一个非常简洁的实用程序库，让我们能够将这个新结构解析成渲染器能够理解的内容。

# 将 API 翻译成可工作的模式

现在我们的模拟 API 正在运行，下一步是创建一种方法，让我们的应用程序解析或翻译这个 API 结构成为我们以前理解的模式结构。如果你此时好奇地尝试运行应用程序，你会遇到大量的控制台错误，指责你的属性类型检查失败和`v-model`绑定失败。这在此时是预料之中的。

继续，在`src`文件夹内创建一个新文件夹；我们将称之为`libraries`。这不是一个严格的命名约定，所以随意根据你或你的团队的需要进行命名。在这个文件夹内，我们将创建一个名为`Api.js`的新文件。我们的目标是将处理 API 模式解析的所有代码放在这里。这样，我们可以在组件中导入我们需要的内容，并且在 API 到模式的翻译方面有一个统一的真相来源——如果其中任何一端因任何原因发生变化，我们只需要在这里更新它。

按照以下步骤操作：

1.  让我们从添加一个入口点开始；它将是一个名为`parse`的函数，并将接受一个参数：来自 API 的`schema`端点的响应：

```js
      export const parse = schema => {
       return schema;
      }
```

现在，我们只是将`schema`原样返回，所以我们可以从小的步骤开始。

1.  继续并将此函数导入到`App.vue`的顶部：

```js
      import { parse } from '@/libraries/Api';
```

1.  然后，在创建的钩子内部，更新`then`块以在分配给状态之前使用该函数：

```js
      .then(response => {
       this.schema = parse(response.data);
      })
```

现在我们可以回到`Api.js`，并且我们将对此解析器进行基本实现。实际上，这里的代码复杂性将取决于您的应用程序要求与 API 结构之间的差异有多大。对我们来说，幸运的是，这只意味着几行代码。

将以下代码添加到`Api.js`：

```js
      export const parse = schema => {
        const fields = schema['fields'];
        const parsedSchema = {};
        for (let i = 0; i < fields.length; i++) {
          const field = fields[i];
          parsedSchema[field.id] = {
            component: componentForField(field.type),
            label: field.label,
            options: field.opts || null
          }
        }
        return parsedSchema;
      }
      function componentForField(field) {
        switch(field) {
          case 'singleChoice': return 'BaseSelect';

          default: return 'BaseInput';
        }
      }
```

让我们将这里发生的事情分解成小块：

1.  首先，我们创建一个常量字段，它将从我们的 API 数据中提取`fields`属性，因为它是嵌套在那里的，我们并不真正关心它发送的其他数据。

1.  我们创建一个新对象`parsedSchema`，在其中为表单的每个字段添加一个属性。

1.  我们循环遍历`fields`中的每个项目并为其创建一个属性。在我们的 API 模式中，`id`属性保存字段的唯一名称，因此我们将使用它作为我们的属性名`parsedSchema[field.id]`。

1.  我们为组件属性分配一个内部对象，这是我们新的`componentForField`函数的结果，在其中我们找出每种情况下我们必须使用哪个组件。

1.  对于`options`属性，我们检查 API 模式中是否存在`opts`属性，如果存在则将其设置为 null。重要的是要记住，即使`BaseInput`组件不期望这个属性，例如，它也不会在乎它是否存在并设置为 null 或未定义。

1.  最后，我们返回模式的解析版本，这样我们的应用程序就可以将表单呈现为其工作状态。

在浏览器中运行它，看到你的基于模式、基于 API 的动态表单！

# 总结

花点时间给自己一个巨大的鼓励。你不仅完成了本章，还完成了整本书！在本章中，您已经掌握了理解基于模式的表单的用例的知识和技能，以及创建`Renderer`组件来适应这些情况的能力。您知道如何创建一个库来解析后端输出到您自己的表单，并在需要时将表单数据反馈给 API。

现在，出去，制作一些动态的形式，然后多吃一些鳄梨！
