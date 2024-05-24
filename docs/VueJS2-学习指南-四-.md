# VueJS2 学习指南（四）

> 原文：[`zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246`](https://zh.annas-archive.org/md5/0B1D097C4A60D3760752681016F7F246)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：测试-是时候测试我们到目前为止所做的了！

在上一章中，您学会了如何使用和创建 Vue 插件。我们使用现有的`resource`插件为 Vue 创建了自己的`NoiseGenerator`插件。

在本章中，我们将确保番茄钟和购物清单应用程序的质量。我们将使用不同的测试技术来测试这些应用程序。首先，我们将对 Vue 组件和与 Vuex 相关的代码（如 actions、mutations 和 getters）执行经典的单元测试。之后，我们将学习如何使用 Nightwatch 执行端到端测试。因此，在本章中，我们将做以下事情：

+   谈论单元测试和端到端测试的重要性

+   为番茄钟和购物清单应用程序实现单元测试

+   学习如何在单元测试中模拟服务器响应

+   使用 Nightwatch 为两个应用程序实现端到端测试

# 为什么单元测试？

在我们开始编写单元测试之前，让我们试着理解我们试图通过编写它们来实现什么。为什么单元测试如此重要？有时当我写我的测试时，我唯一能想到的就是我的代码覆盖率；我想要达到 100%的水平。

代码覆盖率是一个非常重要的指标，对于理解代码流程和需要测试的内容有很大帮助。但这并不是单元测试质量的指标。这不是代码质量好坏的指标。你可以让你的代码 100%覆盖，只是因为你在测试代码中调用了所有的函数，但如果你的断言是错误的，那么代码也可能是错误的。编写良好的单元测试是一门需要时间和耐心的艺术。但是当你的单元测试足够好，当你专注于做出良好的断言时，关于边界情况和分支覆盖，它们提供以下内容：

+   帮助我们识别算法和逻辑中的失败

+   帮助我们提高代码质量

+   让我们编写易于测试的代码

+   防止未来的更改破坏功能

+   帮助我们拥有更可预测的截止日期和估算

易于进行单元测试覆盖的代码同时也是易于阅读的代码。易于阅读的代码更不容易出错，更易于维护。可维护性是应用程序质量的主要支柱之一。

### 注意

在[`chudaol.github.io/presentation-unit-testing`](https://chudaol.github.io/presentation-unit-testing)的演示中了解更多关于单元测试的内容。

让我们为我们的应用程序编写一些单元测试。

我们将使用 Karma 测试运行器，Mocha 测试框架，Chai 期望库和 Sinon 进行模拟。

有关这些工具的更多信息，请参考以下内容：

+   **Karma**: [`karma-runner.github.io/`](http://karma-runner.github.io/)

+   **Mocha**: [`mochajs.org`](https://mochajs.org)

+   **Chaijs**: [`chaijs.com/`](http://chaijs.com/)

+   **Sinon**: [`sinonjs.org/`](http://sinonjs.org/)

如果我们没有使用`vue-cli webpack`进行应用程序的引导，我们将不得不通过`npm`安装所有这些工具。但在我们的情况下，我们不需要进行这种安装。检查你的`package.json`文件，你会发现所有这些东西已经在那里：

```js
  "devDependencies": { 
    <...> 
    "**chai**": "³.5.0", 
    <...> 
    "**karma**": "⁰.13.15", 
    "karma-chrome-launcher": "².0.0", 
    "karma-coverage": "⁰.5.5", 
    "karma-mocha": "⁰.2.2", 
    "karma-phantomjs-launcher": "¹.0.0", 
    "**karma-sinon-chai**": "¹.2.0", 
    "**mocha**": "².4.5", 
    <...> 
  } 

```

你肯定知道为简单函数编写单元测试有多简单。这几乎就像说人类语言一样。它（这个函数）如果输入是*Y*，应该返回*X*。我期望它是*X*。

因此，如果我们有一个模块导出了一个返回两个参数之和的函数，那么这个函数的单元测试必须使用不同的参数调用该函数并期望一些输出。因此，让我们假设我们有一个如下的函数：

```js
function sum(a, b) { 
  return a + b 
} 

```

然后我们的单元测试可能如下所示：

```js
it('should follow commutative law', () => { 
  let a = 2; 
  let b = 3; 

  expect(sum(a, b)).to.equal(5); 
  expect(sum(b, a)).to.equal(5); 
}) 

```

当我们考虑对正在进行单元测试的函数的可能输入时，我们绝不应该害羞。空输入，负输入，字符串输入，一切都重要！你看过这条著名的推文吗（[`twitter.com/sempf/status/514473420277694465`](https://twitter.com/sempf/status/514473420277694465)）？

为什么要进行单元测试？

关于 QA 工程师思维方式的病毒推文

考虑所有可能的输入和适当的输出。用期望和断言来表达这一点。运行测试。看看哪里出了问题。修复你的代码。

# Vue 应用的单元测试

首先，让我们检查一些关于单元测试我们的 Vue 应用程序及其组件的特殊情况。为了能够为组件实例编写测试，首先必须实例化它！非常合乎逻辑，对吧？问题是，我们如何实例化 Vue 组件，以便其方法变得可访问和易于测试？要测试组件初始状态的基本断言，你只需导入它们并断言它们的属性。如果你想测试动态属性——一旦组件绑定到 DOM 后会发生变化的属性——你只需做以下三件事：

1.  导入一个组件。

1.  通过将其传递给`Vue`函数来实例化它。

1.  挂载它。

### 提示

当实例绑定到物理 DOM 时，一旦实例化，编译立即开始。在我们的情况下，我们没有将实例绑定到任何真正的物理 DOM 元素，因此我们必须通过手动调用`mount`方法（`$mount`）来显式地使其编译。

现在你可以使用创建的实例并访问它的方法。在伪代码中，它看起来像下面这样

```js
**import** MyComponent from <path to my component> 
var vm = **new Vue**(MyComponent).**$mount()** 

```

现在我们可以访问所有`vm`实例方法并测试它们。其余的东西，比如`data`，`props`等等，我们可以伪造。伪造东西没有问题，因为它为我们提供了轻松尝试各种输入并测试每种输入的所有可行输出的可能性。

如果你想在测试使用`props`的组件时拥有更真实的场景，这些`props`是由其父组件绑定到组件的，或者访问`vuex`存储等等，你可以使用`ref`属性将组件绑定到`Vue`实例。这个`Vue`实例，反过来，实例化存储和数据，并以通常的方式将数据项绑定到组件。之后，你可以通过使用`$refs` Vue 属性访问组件实例。这种绑定看起来像下面这样：

```js
import store from <path to store> 
import **MyComponent** from <path to my component> 
// load the component with a vue instance 
var vm = new Vue({ 
  template: '<div><test :items="items" :id="id" ref=testcomponent></test></div>', 
  components: { 
    'test': **MyComponent** 
  }, 
  data() { 
    return { 
      items: [], 
      id: 'myId' 
    } 
  }, 
  store 
}).$mount(); 

var myComponent = **vm.$refs.testcomponent**; 

```

现在你可以测试`myComponent`的所有方法，而不用担心覆盖它的`props`，`methods`和其他实例相关的东西。这是这种方法的一个好处；然而，正如你所看到的，这并不是最容易的设置，你应该考虑一切。例如，如果你的组件调用了一些存储的动作，这些动作调用了一些 API 的方法，你应该准备好伪造服务器的响应。

我个人喜欢尽可能简单地保持事情，伪造所有的数据输入，并集中在测试函数的可能输出和所有可能的边缘情况。但这只是我的个人观点，而且我们应该尝试生活中的一切，所以在这一章中，我们将尝试不同的方法。

# 编写购物清单应用的单元测试

在实际编写单元测试之前，让我们建立一些规则。对于我们的每个`.js`或`.vue`文件，都会存在一个相应的测试规范文件，它将具有相同的名称和一个`.spec.js`扩展名。这些规范的结构将遵循这种方法：

+   它将描述我们正在测试的文件

+   它将为正在测试的每个方法有一个`describe`方法

+   它将为我们描述的每种情况都有一个`it`方法

因此，如果我们有一个`myBeautifulThing.js`文件和它的规范，它可能看起来像下面这样：

```js
**// myBeautifulThing.js** 
export myBeautifulMethod1() { 
  return 'hello beauty' 
} 

export myBeautifulMethod2() { 
  return 'hello again' 
} 

**// myBeautifulThing.spec.js** 
import myBeautifulThing from <path to myBeautifulThing> 

describe('myBeautifulThing', () => { 
  //define needed variables 

  describe('myBeautifulMethod1', () => { 
    it('should return hello beauty', () { 
      expect(myBeautifulThing.myBeautifulMethod1()).to.equal('hello  
        beauty') 
    }) 
  }) 
}) 

```

让我们从覆盖`vuex`文件夹中的所有内容开始进行单元测试。

## 测试操作、getter 和 mutations

在本节中，请使用[chapter7/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/shopping-list)文件夹中的代码。不要忘记运行`npm install`命令。请注意，有两个新的 mutations：`ADD_SHOPPING_LIST`和`DELETE_SHOPPING_LIST`。这些 mutations 会将新的购物清单添加到列表中，并通过其 ID 删除列表。它们在`createShoppingList`和`deleteShoppingList`操作中被用于 promise 失败处理程序内：

```js
//actions.js  
createShoppingList: (store, shoppinglist) => { 
  api.addNewShoppingList(shoppinglist).then(() => { 
    store.dispatch('populateShoppingLists') 
  }, () => { 
    **store.commit(ADD_SHOPPING_LIST, shoppinglist)** 
  }) 
}, 
deleteShoppingList: (store, id) => { 
  api.deleteShoppingList(id).then(() => { 
    store.dispatch('populateShoppingLists') 
  }, () => { 
    **store.commit(DELETE_SHOPPING_LIST, id)** 
  }) 
} 

```

因此，即使我们的后端服务器宕机，我们仍然不会失去这个功能。

如果你再次检查你的项目结构，你会看到已经存在一个名为`test`的现有目录。在这个目录中，有两个目录，`unit`和`e2e`。现在，我们应该进入`unit`文件夹。在这里，你会看到另一个名为`specs`的目录。这是我们所有单元测试规范的所在地。让我们首先在`specs`内创建一个名为`vuex`的目录。这是我们所有与 Vuex 相关的 JavaScript 文件的规范所在地。

让我们从测试`mutations.js`方法开始。

创建一个`mutations.spec.js`文件。在这个文件中，我们应该导入`mutations.js`和 mutation 类型，以便我们可以轻松地调用 mutations。看一下`mutations.js`中声明的 mutations。它们都接收`state`和一些其他参数。让我们还创建一个带有`shoppinglist`数组的假`state`对象，这样我们就可以在我们的测试中使用它。

在每次测试之前，让我们也将其重置为空数组。

因此，在所有准备工作完成后，`mutations.js`的引导规范如下：

```js
// mutations.spec.js 
import mutations from 'src/vuex/mutations' 
import { ADD_SHOPPING_LIST, DELETE_SHOPPING_LIST, POPULATE_SHOPPING_LISTS, CHANGE_TITLE } from 'src/vuex/mutation_types' 

describe('mutations.js', () => { 
  var state 

  beforeEach(() => { 
    state = { 
      shoppinglists: [] 
    } 
  }) 
}) 

```

现在让我们为`ADD_SHOPPING_LIST`mutation 添加测试。

再次检查它在做什么：

```js
[types.ADD_SHOPPING_LIST] (state, newList) { 
  state.shoppinglists.push(newList) 
}, 

```

这个 mutation 只是将接收到的对象推送到`shoppinglists`数组中。非常直接和容易测试。

首先创建一个带有函数名称的`describe`语句：

```js
describe(**'ADD_SHOPPING_LIST'**, () => { 
}) 

```

现在，在这个`describe`回调中，我们可以添加带有所需断言的`it`语句。让我们想一想当我们将新的购物清单添加到`shoppinglists`数组时会发生什么。首先，数组的长度会增加，它还将包含新添加的购物清单对象。这是最基本的测试。我们的`it`函数与所需的断言将如下所示：

```js
  it('should add item to the shopping list array and increase its 
    length', () => { 
  //call the add_shopping_list mutations 
  **mutationsADD_SHOPPING_LIST** 
  //check that the array now equals array with new object 
  **expect(state.shoppinglists).to.eql([{id: '1'}])** 
  //check that array's length had increased 
  **expect(state.shoppinglists).to.have.length(1)** 
}) 

```

创建完这个函数后，整个规范的代码应该如下所示：

```js
// mutations.spec.js 
import mutations from 'src/vuex/mutations' 
import { ADD_SHOPPING_LIST, DELETE_SHOPPING_LIST, POPULATE_SHOPPING_LISTS, CHANGE_TITLE } from 'src/vuex/mutation_types' 

describe('mutations.js', () => { 
  var state 

  beforeEach(() => { 
    state = { 
      shoppinglists: [] 
    } 
  }) 

  describe('ADD_SHOPPING_LIST', () => { 
    it('should add item to the shopping list array and increase its 
      length', () => { 
      mutationsADD_SHOPPING_LIST 
      expect(state.shoppinglists).to.eql([{id: '1'}]) 
      expect(state.shoppinglists).to.have.length(1) 
    }) 
  }) 
}) 

```

让我们运行测试！在项目目录中打开控制台，运行以下命令：

```js
**npm run unit** 

```

你应该看到以下输出：

![测试操作、获取器和变异](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00304.jpeg)

运行我们的测试的输出

还记得关于 QA 工程师的笑话吗？我们可以测试`add_shopping_list`函数的所有可能输入。例如，如果我们在不传递任何对象的情况下调用它，会发生什么？理论上，它不应该添加到购物清单数组中，对吧？让我们测试一下。创建一个新的`it`语句，尝试在不传递第二个参数的情况下调用该函数。断言为空列表。

这个测试将看起来像下面这样：

```js
it('should not add the item if item is empty', () => { 
  mutationsADD_SHOPPING_LIST 
  **expect(state.shoppinglists).to.have.length(0)** 
}) 

```

使用`npm run unit`命令运行测试。哦，糟糕！它失败了！错误如下：

```js
expected [ undefined ] to have a length of 0 but got 1 

```

为什么？看看相应的变异。它只是将接收到的参数推送到数组中，而没有任何检查。这就是为什么我们能够添加任何垃圾、任何未定义和任何其他不合适的值！你还记得我说过编写良好的单元测试可以帮助我们创建更少容易出错的代码吗？现在我们意识到在将新项目推送到数组之前，我们应该可能运行一些检查。让我们添加检查，确保接收到的项目是一个对象。打开`mutations.js`文件中的`ADD_SHOPPING_LIST`变异，并将其重写如下：

```js
//mutations.js 
types.ADD_SHOPPING_LIST { 
  if (**_.isObject(newList)**) { 
    state.shoppinglists.push(newList) 
  } 
} 

```

现在运行测试。它们都通过了！

当然，我们可以更加精确。我们可以检查和测试空对象，还可以对该对象进行一些验证，以确保包含`id`、`items`和`title`等属性。我会把这个留给你作为一个小练习。尝试考虑所有可能的输入和所有可能的输出，编写所有可能的断言，并使代码与它们相对应。

## 良好的测试标准

一个好的单元测试是当你改变你的代码时会失败的测试。想象一下，例如，我们决定在将新的购物清单推送到数组之前为其分配一个默认标题。因此，变异看起来像下面这样：

```js
types.ADD_SHOPPING_LIST { 
  if (_.isObject(newList)) { 
    **newList.title = 'New Shopping List'**     
    state.shoppinglists.push(newList) 
  } 
} 

```

如果你运行测试，它们会失败：

![良好的测试标准](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00305.jpeg)

当代码发生变化时，单元测试失败

这非常好。当你的代码发生变化后测试失败，可能的结果是你修复测试，因为代码执行了预期的行为，或者你修复你的代码。

## 代码覆盖率

我相信你在运行测试后的控制台输出中已经注意到了一些测试统计信息。这些统计数据显示了我们在运行时测试所达到的不同类型的覆盖率。现在看起来是这样的：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00306.jpeg)

在为 ADD_SHOPPING_LIST mutation 编写两个测试后的 mutations.js 的代码覆盖率

你还记得我说过良好的代码覆盖率并不意味着我们的测试和代码是完美的吗？我们实际上有相当不错的语句、分支和行覆盖率，但我们只测试了一个文件的一个函数，甚至没有覆盖这个函数的所有可能输入。但数字不会说谎。我们几乎有 100%的分支覆盖率，因为我们的代码几乎没有分支。

如果你想看到更详细的报告，只需在浏览器中打开`test/unit/coverage/lcov-report`目录下的`index.html`文件。它会给你一个完整的代码图片，显示出你的代码覆盖了什么，以及覆盖了什么。目前看起来是这样的：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00307.jpeg)

我们代码库覆盖率的整体图片

你可以深入到文件夹中，打开文件，检查我们的代码是如何被覆盖的。让我们来检查`mutations.js`：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00308.jpeg)

actions.js 的覆盖率报告准确显示了哪些代码被覆盖了，哪些没有被覆盖

现在你知道还有什么需要测试。你想看看它如何报告`if…else`缺失的分支覆盖率吗？只需跳过我们的第二个测试：

```js
it.**skip**('should not add the item if item is empty', () => { 
  mutationsADD_SHOPPING_LIST 
  expect(state.shoppinglists).to.have.length(0) 
}) 

```

运行测试并刷新`actions.js`的报告。你会在`if`语句左边看到一个**`E`**图标：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00309.jpeg)

在 if 语句附近的 E 图标表示 else 分支没有被测试覆盖

这表明我们没有覆盖`else`分支。如果你跳过第一个测试，只留下一个空对象的测试，你会看到**`I`**图标，表示我们跳过了`if`分支：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00310.jpeg)

在 if 语句附近的 I 图标表示 if 分支没有被测试覆盖

为其余的变异编写测试。至少执行以下检查：

+   对于`DELETE_SHOPPING_LIST`变异，检查我们传递的 ID 对应的列表是否实际上被删除，如果它之前存在于列表中，并且调用具有在列表中不存在的 ID 的变异不会引起任何改变

+   对于`POPULATE_SHOPPING_LISTS`变异，检查当我们调用这个变异时，`shoppinglist`数组是否被我们传递的数组覆盖

+   对于`CHANGE_TITLE`变异，检查当我们传递新标题和 ID 时，确切地改变了这个对象的标题

最后，你的`mutation.spec.js`文件可能看起来像这个[gist](https://gist.github.com/chudaol/befd9fc5701ff72dff7fb68ef1c7f06a)。

经过这些测试，`mutation.js`的覆盖率看起来相当不错：

![代码覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00311.jpeg)

在为所有变异编写单元测试后，`mutations.js`的覆盖率为 100%

以完全相同的方式，我们可以测试我们的`getters.js`。创建一个`getters.spec.js`文件，并填充它以测试我们的两个 getter 函数。最后，它可能看起来像这个[gist](https://gist.github.com/chudaol/e89dd0f77b1563366d5eec16bd6ae4a9)。

在单元测试中缺少的唯一重要的存储组件是`actions.js`。但是我们的`actions.js`广泛使用了 API，而 API 又执行 HTTP 请求。它的函数也是异步的。这种类型的东西能像我们刚刚测试 getter 和 action 一样灵活和简单地进行单元测试吗？是的，可以！让我们看看如何使用`sinon.js`伪造服务器响应，以及如何使用`mocha.js`编写异步测试。

## 伪造服务器响应和编写异步测试

打开`actions.js`文件，检查第一个动作方法：

```js
//actions.js 
populateShoppingLists: ({ commit }) => { 
  api.fetchShoppingLists().then(response => { 
    commit(POPULATE_SHOPPING_LISTS, response.data) 
  }) 
} 

```

首先，让我们给这个函数添加一个`return`语句，使其返回一个 promise。我们这样做是为了让我们能够在 promise 解析后调用`.then`方法，以便我们可以测试期间发生的一切。因此，我们的函数看起来像下面这样：

```js
//actions.js 
populateShoppingLists: ({ commit }) => { 
  **return** api.fetchShoppingLists().then(response => { 
    commit(POPULATE_SHOPPING_LISTS, response.data) 
  }) 
} 

```

现在，检查这里发生了什么：

1.  这个函数接收带有`dispatch`方法的`store`。

1.  它执行对 API 的调用。API 又调用资源`get`方法，该方法只是向我们的服务器执行 HTTP 请求。

1.  在 API 的`fetchShoppingLists`承诺解决后，我们的方法将使用两个参数调用存储的`commit`方法：一个`POPULATE_SHOPPING_LISTS`字符串和响应中传入的数据。

我们如何对这个工作流进行单元测试？如果我们能够捕获请求并模拟响应，我们可以检查我们提供给服务器模拟的响应是否调用了`commit`方法（由我们传递，这意味着它也可以被模拟）。听起来混乱吗？一点也不！步骤如下：

1.  为`store`及其`commit`方法创建一个模拟。

1.  为假设的服务器响应创建一个模拟。

1.  创建一个假服务器，它将拦截 GET 请求并返回模拟的响应。

1.  检查`commit`方法是否以我们模拟的响应和`POPULATE_SHOPPING_LISTS`字符串被调用。

这意味着我们的测试可能看起来像下面这样：

```js
it('should test that commit is called with correct parameters', () => { 
  actions.populateShoppingLists({ commit }).then(() => { 
    expect(commit).to.have.been.calledWith(<...>) 
  }) 
}) 

```

这里的问题是我们的测试是同步的，这意味着代码永远不会达到我们`.then`回调中的内容。幸运的是，`mocha.js`提供了对异步测试的支持。在[`mochajs.org/#asynchronous-code`](https://mochajs.org/#asynchronous-code)查看。你所需要做的就是将`done`回调传递给`it()`，并在测试完成时调用它。这样，我们对这个测试的伪代码看起来如下：

```js
it('should test that commit is called with correct parameters', 
(**done**) => { 
  actions.populateShoppingLists({ commit }).then(() => { 
   expect(commit).to.have.been.calledWith(<...>) 
   **done()** 
  }) 
}) 

```

现在让我们编码！创建一个测试规范并将其命名为`actions.spec.js`，并编写所有所需的引导代码：

```js
// actions.spec.js 
import actions from 'src/vuex/actions' 
import { CHANGE_TITLE, POPULATE_SHOPPING_LISTS } from 'src/vuex/mutation_types' 

describe('actions.js', () => { 
  describe('populateShoppingLists', () => { 
    //here we will add our test case 
  }) 
}) 

```

现在让我们按步骤进行。首先，让我们模拟服务器响应。只需创建`lists`变量并在`beforeEach`方法中初始化它：

```js
//actions.spec.js 
describe('actions.js', () => { 
  **var lists** 

  beforeEach(() => { 
    **// mock shopping lists 
    lists = [{ 
      id: '1', 
      title: 'Groceries' 
    }, { 
      id: '2', 
      title: 'Clothes' 
    }]** 
  }) 

  describe('populateShoppingLists', () => { 
  }) 
}) 

```

现在，让我们模拟存储的`commit`方法：

```js
// actions.spec.js 
describe('actions.js', () => { 
  var lists, **store** 

  beforeEach(() => { 
    <...> 
    //mock store commit method 
    **store = { 
      commit: (method, data) => {}, 
      state: { 
        shoppinglists: lists 
      } 
    }** 
  }) 
  <...> 
}) 

```

现在，我们必须对这个`commit`方法进行间谍活动，以便能够断言它是否以所需的参数被调用。我们将使用`sinon.stub`方法来实现这一点。在这个问题上查看`sinon.js`的文档：[`sinonjs.org/docs/#stubs`](http://sinonjs.org/docs/#stubs)。在给定函数上创建一个存根非常容易。只需调用`sinon.stub`方法，并将我们想要进行间谍活动的对象及其方法传递给它：

```js
sinon.stub(store, 'commit')  

```

因此，我们的`beforeEach`函数将如下所示：

```js
beforeEach(() => { 
    <...> 
    // mock store commit method 
    store = { 
      commit: (method, data) => {}, 
      state: { 
        shoppinglists: lists 
      } 
    } 

    sinon.stub(store, 'commit') 
}) 

```

非常重要的是，在每个方法之后，我们*恢复*存根，以便每个测试方法在不受其他测试影响的干净环境中运行。为此，创建一个`afterEach`方法并添加以下行：

```js
afterEach(function () { 
  //restore stub 
  store.commit.restore() 
}) 

```

现在我们唯一需要做的就是用我们模拟的数据伪造服务器响应。让我们使用 Sinon 的`fakeServer`来实现这个目的。在[`sinonjs.org/docs/#fakeServer`](http://sinonjs.org/docs/#fakeServer)查看 sinon 的文档。我们只需要创建`fakeServer`并告诉它响应我们模拟的 GET 请求的响应：

```js
describe('actions.js', () => { 
  var lists, store, server 

  beforeEach(() => { 
    <...> 
    //mock server 
    **server = sinon.fakeServer.create() 
    server.respondWith('GET', /shoppinglists/, xhr => { 
      xhr.respond(200, {'Content-Type': 'application/json'}, 
      JSON.stringify(lists)) 
    })** 
  }) 
  <...> 
}) 

```

在做好这些准备之后，每个进行请求的测试都应该调用服务器的`respond`方法来调用服务器的功能。

然而，我们可以通过告诉服务器自动响应每个捕获的请求来简化这个过程：

```js
server.autoRespond = true 

```

因此，我们模拟服务器的代码将如下所示：

```js
beforeEach(() => { 
    <...> 
    //mock server 
    server = sinon.fakeServer.create() 
    server.respondWith('GET', /shoppinglists/, xhr => { 
      xhr.respond(200, {'Content-Type': 'application/json'}, 
      JSON.stringify(lists) 
    }) 
    **server.autoRespond = true**   
}) 

```

非常重要的是，在每个测试之后，我们要恢复我们的伪造服务器，以便这个测试不会影响其他测试。因此，在`afterEach`方法中添加以下行：

```js
afterEach(() => { 
  //restore stubs and server mock 
  store.commit.restore() 
  **server.restore()** 
}) 

```

现在我们已经模拟了一切可能模拟的东西，我们终于可以编写我们的测试用例了！所以，你记得，我们创建一个带有`done`回调的`it()`语句，调用我们的`populateShoppingLists`方法，并检查解析后的响应是否与我们模拟的`list`对象相同。进入`describe`方法，只需将我们刚刚描述的内容翻译成代码：

```js
it('should call commit method with POPULATE_SHOPPING_LIST and with mocked lists', done => { 
  actions.populateShoppingLists(store).then(() => { 
    **expect(store.commit).to.have.been.calledWith(POPULATE_SHOPPING_LISTS,
    lists) 
    done()** 
  }).catch(done) 
}) 

```

我们整个测试规范现在看起来像这个要点[`gist.github.com/chudaol/addb6657095406234bc6f659970f3eb8`](https://gist.github.com/chudaol/addb6657095406234bc6f659970f3eb8)。

用`npm run unit`运行测试。它有效了！

现在我们只需要模拟 PUT、POST 和 DELETE 方法的服务器响应。这些方法不返回任何数据；然而，为了能够测试响应，让我们返回伪造的成功消息，并在每个测试中检查返回的数据是否对应这些响应。在规范的顶部添加以下变量：

```js
  var server, store, lists, successPut, successPost, successDelete 

  **successDelete = {'delete': true} 
  successPost = {'post': true} 
  successPut = {'put': true}** 

```

并且在我们的服务器中添加以下伪造响应的方法：

```js
    server.respondWith(**'POST'**, /shoppinglists/, xhr => { 
      xhr.respond(200, {'Content-Type': 'application/json'}, 
        JSON.stringify(**successPost**)) 
    }) 
    server.respondWith(**'PUT'**, /shoppinglists/, xhr => { 
      xhr.respond(200, {'Content-Type': 'application/json'}, 
        JSON.stringify(**successPut**)) 
    }) 
    server.respondWith(**'DELETE'**, /shoppinglists/, xhr => { 
      xhr.respond(200, {'Content-Type': 'application/json'}, 
        JSON.stringify(**successDelete**)) 
    }) 

```

让我们看看它将如何工作，例如，对于`changeTitle`方法。在这个测试中，我们想要测试`commit`方法是否会以给定的 ID 和标题被调用。因此，我们的测试将如下所示：

```js
describe(**'changeTitle'**, () => { 
  it('should call commit method with CHANGE_TITLE string', (done) => { 
    let title = 'new title' 

    actions.changeTitle(store, {title: title, id: '1'}).then(() => { 
      **expect(store.commit).to.have.been.calledWith(CHANGE_TITLE, 
      {title: title, id: '1'})** 
      done() 
    }).catch(done) 
  }) 
}) 

```

为了使这个工作正常，我们还应该模拟存储的`dispatch`方法，因为它被用在`changeTitle`动作中。只需将`dispatch`属性添加到我们存储的模拟中，并返回一个 resolved promise：

```js
// mock store commit and dispatch methods 
store = { 
  commit: (method, data) => {}, 
  **dispatch: () => { 
    return Promise.resolve() 
  },** 
  state: { 
    shoppinglists: lists 
  } 
} 

```

在这一刻检查单元测试的最终代码[`gist.github.com/chudaol/1405dff6a46b84c284b0eae731974050`](https://gist.github.com/chudaol/1405dff6a46b84c284b0eae731974050)。

通过为`updateList`、`createShoppingList`和`deleteShoppingList`方法添加单元测试来完成`actions.js`的测试。在[chapter7/shopping-list2](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/shopping-list2)文件夹中检查到目前为止的所有单元测试代码。

## 测试组件

现在我们所有与 Vuex 相关的函数都经过了单元测试，是时候应用特定的 Vue 组件测试技术来测试我们购物清单应用程序的组件了。

你还记得本章第一节中提到的，为了准备`Vue`实例进行单元测试，我们必须导入、初始化（将其传递给新的`Vue`实例）并挂载它。让我们开始吧！在`test/unit/specs`目录下创建一个`components`文件夹。让我们从测试`AddItemComponent`组件开始。创建一个`AddItemComponent.spec.js`文件并导入`Vue`和`AddItemComponent`：

```js
//AddItemComponent.spec.js 
import Vue from 'vue' 
import AddItemComponent from 'src/components/AddItemComponent' 

describe('AddItemComponent.vue', () => { 

}) 

```

变量`AddItemComponent`可以用来直接访问组件的初始数据。因此，我们可以断言，例如，组件数据初始化为一个等于空字符串的`newItem`属性：

```js
describe('initialization', () => { 
  it('should initialize the component with empty string newItem', () => { 
    **expect(AddItemComponent.data()).to.eql({ 
      newItem: '' 
    })** 
  }) 
}) 

```

让我们现在检查一下这个组件的哪些方法可以用单元测试来覆盖。

这个组件只有一个方法，就是`addItem`方法。让我们来看看这个方法做了什么：

```js
//AddItemComponent.vue 
addItem () { 
  var text 

  text = this.newItem.trim() 
  if (text) { 
    this.$emit('add', this.newItem) 
    this.newItem = '' 
    this.$store.dispatch('updateList', this.id) 
  } 
} 

```

这个方法访问了存储，所以我们必须使用另一种初始化组件的策略，而不是直接使用导入的值。在这种情况下，我们应该将 Vue 主组件初始化为`AddItemComponent`的子组件，将所有必要的属性传递给它，并使用`$refs`属性访问它。因此，在测试方法中，组件的初始化将如下所示：

```js
var vm, addItemComponent; 

vm = new Vue({ 
  template: '<add-item-component :items="items" :id="id" 
  **ref="additemcomponent"**>' + 
  '</add-item-component>', 
  components: { 
    AddItemComponent 
  }, 
  data() { 
    return { 
      items: [], 
      id: 'niceId' 
    } 
  }, 
  store 
}).$mount(); 

**addItemComponent = vm.$refs.additemcomponent** 

```

回到方法的功能。所以，`addItem`方法获取实例的`newItem`属性，修剪它，检查它是否为假，如果不是，则触发自定义事件`add`，重置`newItem`属性，并在存储上调度`updateList`操作。我们可以通过为`component.newItem`和`component.id`分配不同的值并检查输出是否符合我们的期望来测试这个方法。

### 提示

**正面测试**意味着通过提供有效数据来测试系统。**负面测试**意味着通过提供无效数据来测试系统。

在我们的正面测试中，我们应该使用一个有效的字符串来初始化`component.newItem`属性。调用方法后，我们应该确保各种事情：

+   组件的`$emit`方法已经使用`add`和我们分配给`newItem`属性的文本进行了调用

+   `component.newItem`已重置为空字符串

+   store 的`dispatch`方法已经使用组件的`id`属性调用了

走吧！让我们从为`addItem`函数添加`describe`方法开始：

```js
describe(**'addItem'**, () => { 

}) 

```

现在我们可以添加`it()`方法，我们将为`component.newItem`分配一个值，调用`addItem`方法，并检查我们需要检查的一切：

```js
//AddItemComponent.spec.js 
it('should call $emit method', () => { 
  let newItem = 'Learning Vue JS' 
  // stub $emit method 
  sinon.stub(component, '$emit') 
  // stub store's dispatch method 
  sinon.stub(store, 'dispatch') 
  // set a new item 
  **component.newItem = newItem** 
  component.addItem() 
  // newItem should be reset 
  **expect(component.newItem).to.eql('')** 
  // $emit should be called with custom event 'add' and a newItem value 
  **expect(component.$emit).to.have.been.calledWith('add', newItem)** 
  // dispatch should be called with updateList and the id of the list 
  **expect(store.dispatch).to.have.been.calledWith('updateList', 
  'niceId')** 
  store.dispatch.restore() 
  component.$emit.restore() 
}) 

```

运行测试并检查它们是否通过，一切都正常。检查[chapter7/shopping-list3](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/shopping-list3)文件夹中的`AddItemComponent`的最终代码。

尝试为购物清单应用程序的其余组件编写单元测试。记得编写单元测试来覆盖你的代码，这样如果你改变了代码，它就会出错。

# 为我们的番茄钟应用程序编写单元测试

好的！让我们转到我们的番茄钟应用程序！顺便问一下，你上次休息是什么时候？也许，现在是时候在浏览器中打开应用程序，等待几分钟的番茄工作时间计时器，然后检查一些小猫。

我刚刚做了，这让我感觉真的很好，很可爱。

![为我们的番茄钟应用程序编写单元测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00312.jpeg)

我不是你的衣服...请休息一下

让我们从 mutations 开始。打开[chapter7/pomodoro](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/pomodoro)文件夹中的代码。打开`mutations.js`文件并检查那里发生了什么。有四个 mutations 发生：`START`，`STOP`，`PAUSE`和`TOGGLE_SOUND`。猜猜我们将从哪一个开始。是的，你猜对了，我们将从`start`方法开始。在`test/unit/specs`文件夹内创建一个`vuex`子文件夹，并添加`mutations.spec.js`文件。让我们准备好进行测试：

```js
// mutations.spec.js 
import Vue from 'vue' 
import mutations from 'src/vuex/mutations' 
import * as types from 'src/vuex/mutation_types' 

describe('mutations', () => { 
  var state 

  beforeEach(() => { 
    state = {} 
    // let's mock Vue noise plugin 
    //to be able to listen on its methods 
    **Vue.noise = { 
      start: () => {}, 
      stop: () => {}, 
      pause: () => {} 
    }** 
    sinon.spy(Vue.noise, 'start') 
    sinon.spy(Vue.noise, 'pause') 
    sinon.spy(Vue.noise, 'stop') 
  }) 

  afterEach(() => { 
    **Vue.noise.start.restore() 
    Vue.noise.pause.restore() 
    Vue.noise.stop.restore()** 
  }) 

  describe(**'START'**, () => { 
  }) 
}) 

```

请注意，我对噪音生成器插件的所有方法进行了模拟。这是因为在这个规范中，我们不需要测试插件的功能（实际上，在发布之前，我们必须在插件本身的范围内进行测试）。在这个测试范围内，我们应该测试插件的方法在需要调用时是否被调用。

为了能够测试 `start` 方法，让我们思考应该发生什么。在点击开始按钮后，我们知道应用程序的 `started`、`paused` 和 `stopped` 状态必须获得一些特定的值（实际上分别是 `true`、`false` 和 `false`）。我们还知道应用程序的间隔应该启动。我们还知道如果番茄钟的状态是 `working`，并且声音已启用，噪音生成器插件的 `start` 方法应该被调用。实际上，这就是我们的方法实际在做的事情：

```js
[types.START] (state) { 
  state.started = true 
  state.paused = false 
  state.stopped = false 
  state.interval = setInterval(() => tick(state), 1000) 
  if (state.isWorking && state.soundEnabled) { 
    Vue.noise.start() 
  } 
}, 

```

但即使它没有做所有这些事情，我们已经编写了测试来测试它，我们会立即意识到我们的代码中缺少了一些东西，并加以修复。让我们写我们的测试。让我们首先定义 `it()` 方法，测试所有属性是否被正确设置。为了确保在调用方法之前它们没有被设置，让我们还断言在测试开始时这些属性都未被定义：

```js
it('should set all the state properties correctly after start', () => { 
  // ensure that all the properties are undefined 
  // before calling the start method 
  expect(state.started).to.be.undefined 
  expect(state.stopped).to.be.undefined 
  expect(state.paused).to.be.undefined 
  expect(state.interval).to.be.undefined 
  // call the start method 
  mutationstypes.START 
  // check that all the properties were correctly set 
  expect(state.started).to.be.true 
  expect(state.paused).to.be.false 
  expect(state.stopped).to.be.false 
  expect(state.interval).not.to.be.undefined 
}) 

```

现在让我们检查 `Vue.noise.start` 方法。我们知道只有当 `state.isWorking` 为 `true` 且 `state.soundEnabled` 为 `true` 时才应该调用它。让我们写一个正面测试。在这个测试中，我们会将两个布尔状态都初始化为 `true`，并检查 `noise.start` 方法是否被调用：

```js
it('should call Vue.noise.start method if both state.isWorking and state.soundEnabled are true', () => { 
  state.**isWorking** = true 
  state.**soundEnabled** = true 
  mutationstypes.START 
  expect(Vue.noise.start).**to.have.been.called** 
}) 

```

让我们为每个状态添加两个负面测试，`isWorking` 和 `soundEnabled` 都设为 `false`：

```js
it('should not call Vue.noise.start method if state.isWorking is not true', () => { 
  **state.isWorking = false** 
  state.soundEnabled = true 
  mutationstypes.START 
  expect(Vue.noise.start).**to.not.have.been.called** 
}) 

it('should not call Vue.noise.start method if state.soundEnabled is not true', () => { 
  state.isWorking = true 
  **state.soundEnabled = false** 
  mutationstypes.START 
  expect(Vue.noise.start).**to.not.have.been.called** 
}) 

```

我们的 `start` 变异已经很好地测试了！在 [chapter7/pomodoro2](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/pomodoro2) 文件夹中检查代码的最终状态。我建议你现在写其余的单元测试，不仅测试变异，还要测试所有存储相关的函数，包括在 getters 和 actions 中的函数。之后，应用我们刚学到的技术来测试 Vue 组件，并测试我们番茄钟应用程序的一些组件。

在这一点上，我们已经完成了单元测试！

# 什么是端到端测试？

**端到端**（**e2e**）测试是一种技术，用于测试应用程序的整个流程。在这种测试中，既不使用模拟对象也不使用存根，而是对真实系统进行测试。进行端到端测试可以测试应用程序的所有方面——API、前端、后端、数据库、服务器负载，从而确保系统集成的质量。

在 Web 应用程序的情况下，这些测试是通过 UI 测试执行的。每个测试都描述了从打开浏览器到关闭浏览器的所有步骤。必须描述为实现某些系统功能而需要执行的所有步骤。实际上，这与您在应用程序页面上单击并执行一些操作的方式相同，但是是自动化和快速的。在本节中，我们将看到 Selenium webdriver 是什么，Nightwatch 是什么，以及它们如何用于为我们的应用程序创建端到端测试。

# 端到端的 Nightwatch

如果您已经使用过测试自动化，或者与使用测试自动化的人一起工作过，那么肯定已经听说过 Selenium 这个神奇的词语——Selenium 可以打开浏览器，点击，输入，像人一样做任何事情，以并行、良好分布、多平台和跨浏览器的方式。实际上，Selenium 只是一个包含 API 的 JAR 文件，用于在浏览器上执行不同的操作（点击、输入、滚动等）。

### 注意

查看 Selenium 的文档[`www.seleniumhq.org/`](http://www.seleniumhq.org/)。

当执行这个 JAR 文件时，它会连接到指定的浏览器，打开 API，并等待在浏览器上执行命令。发送到 Selenium 服务器的命令可以以各种不同的方式和语言执行。

有很多现有的实现和框架可以让您用几行代码调用 Selenium 命令：

+   您可以使用 Java 的原生 Selenium 框架（[`seleniumhq.github.io/selenium/docs/api/java/`](http://seleniumhq.github.io/selenium/docs/api/java/)）

+   您可以使用浏览器的 Firefox 插件（[`addons.mozilla.org/en-us/firefox/addon/selenium-ide/`](https://addons.mozilla.org/en-us/firefox/addon/selenium-ide/)）

+   您可以使用**Selenide**，这是 Java 的另一个实现，但比 Selenium 框架更容易使用（[`selenide.org/`](http://selenide.org/)）

+   如果您是 AngularJS 开发人员，可以使用 Protractor，这是一个非常好的用于 AngularJS 应用程序的端到端测试框架，也使用 Selenium webdriver（[`www.protractortest.org/`](http://www.protractortest.org/)）

在我们的案例中，我们将使用 Nightwatch，这是一个很好且非常易于使用的测试框架，可以使用 JavaScript 调用 Selenium 的命令。

查看 Nightwatch 的文档[`nightwatchjs.org/`](http://nightwatchjs.org/)。

Vue 应用程序使用`vue-cli webpack`方法引导时，已经包含了对 Nightwatch 测试的支持，无需安装任何东西。基本上，每个测试规范看起来都有点像下面这样：

```js
module.exports = { 
  'e2e test': function (browser) { 
    browser 
    .**url**('http://localhost:8080') 
      .**waitForElementVisible**('#app', 5000) 
      .assert.**elementPresent**('.logo') 
      .assert.**containsText**('h1', 'Hello World!') 
      .assert.**elementCount**('p', 3) 
      .end() 
  } 
} 

```

语法很好，易于理解。每个突出显示的方法都是一个 Nightwatch 命令，其背后会被转换为 Selenium 命令并被调用。在官方文档页面[`nightwatchjs.org/api#commands`](http://nightwatchjs.org/api#commands)上检查 Nightwatch 命令的完整列表。

# 为番茄钟应用编写端到端测试

现在我们知道了 UI 测试背后的所有理论，我们可以为我们的番茄钟应用创建我们的第一个端到端测试。让我们定义我们将执行的步骤和我们应该测试的事情。首先，我们应该打开浏览器。然后，我们可能应该检查我们的容器（具有`#app` ID）是否在页面上。

我们还可以尝试检查暂停和停止按钮是否禁用，以及页面上是否不存在声音切换按钮。

然后我们可以点击开始按钮，检查声音切换按钮是否出现，开始按钮是否变为禁用状态，暂停和停止按钮是否变为启用状态。还有无数种可能的点击和检查，但让我们至少执行描述的步骤。让我们用项目符号的形式写出来：

1.  在`http://localhost:8080`上打开浏览器。

1.  检查页面上是否有`#app`元素。

1.  检查`.toggle-volume`图标是否不可见。

1.  检查`'[title=pause]'`和`'[title=stop]'`按钮是否禁用，`'[title=start]'`按钮是否启用。

1.  点击`'[title=start]'`按钮。

1.  检查`'[title=pause]'`和`'[title=stop]'`按钮是否现在启用，`'[title=start]'`按钮是否禁用。

1.  检查`.toggle-volume`图标现在是否可见。

让我们开始吧！只需打开`tests/e2e/specs`文件夹中的`test.js`文件，删除其内容，并添加以下代码：

```js
module.exports = { 
  'default e2e tests': (browser) => { 
    // open the browser and check that #app is on the page 
    browser.url('http://localhost:8080') 
      .waitForElementVisible('#app', 5000); 
    // check that toggle-volume icon is not visible 
    browser.expect.element('.toggle-volume') 
      .to.not.be.visible 
    // check that pause button is disabled 
    browser.expect.element('[title=pause]') 
      .to.have.attribute('disabled') 
    // check that stop button is disabled 
    browser.expect.element('[title=stop]') 
      .to.have.attribute('disabled') 
    // check that start button is not disabled            
    browser.expect.element('[title=start]') 
      .to.not.have.attribute('disabled') 
    // click on start button, check that toggle volume 
    // button is visible 
    browser.click('[title=start]') 
      .waitForElementVisible('.toggle-volume', 5000) 
    // check that pause button is not disabled 
    browser.expect.element('[title=pause]') 
      .to.not.have.attribute('disabled') 
    // check that stop button is not disabled 
    browser.expect.element('[title=stop]') 
      .to.not.have.attribute('disabled') 
    // check that stop button is disabled 
    browser.expect.element('[title=start]') 
      .to.have.attribute('disabled') 
    browser.end() 
  } 
} 

```

你看到这种语言是多么友好吗？现在让我们进行一项检查，看看在工作时间结束后，小猫元素是否出现在屏幕上。为了使测试更短，不必等待很长时间才能通过测试，让我们将工作时间设定为 6 秒。在我们的`config.js`文件中更改这个值：

```js
//config.js 
export const WORKING_TIME = 0.1 * 60 

```

包含猫图片的元素具有`'div.well.kittens'`选择器，因此我们将检查它是否可见。让我们在这个测试中检查，在小猫元素出现后，图像的来源是否包含`'thecatapi'`字符串。这个测试将如下所示：

```js
'wait for kitten test': (browser) => { 
  browser.url('http://localhost:8080') 
    .waitForElementVisible('#app', 5000) 
  // initially the kitten element is not visible 
  browser.expect.element('.well.kittens') 
    .to.not.be.visible 
  // click on the start button and wait for 7s for 
  //kitten element to appear 
  browser.click('[title=start]') 
    .waitForElementVisible('.well.kittens', 7000) 
  // check that the image contains the src element 
  //that matches thecatapi string 
  browser.expect.element('.well.kittens img') 
    .to.have.attribute('src') 
    .which.matches(/thecatapi/); 
  browser.end() 
} 

```

运行测试。为了做到这一点，调用`e2e` npm 命令：

```js
**npm run e2e** 

```

你会看到浏览器自己打开并执行所有操作。

*这是一种魔法！*

我们所有的测试都通过了，所有的期望都得到了满足；查看控制台：

![为番茄钟应用程序编写 e2e 测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00313.jpeg)

所有测试都通过了！

恭喜！你刚刚学会了如何使用 Nightwatch 编写 e2e 测试。检查[chapter7/pomodoro3](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter7/pomodoro3)文件夹中的代码。为我们的番茄钟应用程序编写更多的测试用例。不要忘记我们的购物清单应用程序，它可能有更多的 UI 测试场景。编写它们并检查 Selenium 如何为你工作。如果你决定增强代码，你的代码质量不仅受到单元测试的保护，而且现在还应用了回归测试。每次更改代码时，只需运行一个命令来运行两种类型的测试：

```js
**npm test** 

```

现在你肯定值得休息一下。拿一杯咖啡或茶，打开番茄钟应用程序页面，等待 6 秒，欣赏我们的小毛绒朋友：

![为番茄钟应用程序编写 e2e 测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00314.jpeg)

实际上，这不是来自 thecatapi 的小猫。这是我的猫 Patuscas 祝愿大家有一个愉快的休息时间！

# 总结

在这一章中，我们已经测试了我们的两个应用程序。我们为 Vuex 方法和 Vue 组件编写了单元测试。我们使用了简单的单元测试和异步单元测试，并熟悉了 Sinon 的模拟技术，比如对方法进行间谍操作和伪造服务器响应。我们还学会了如何使用 Nightwatch 创建 UI 测试。我们的应用程序现在经过了测试，准备部署到生产环境！我们将在下一章中了解如何部署它们，下一章将专门讨论使用 Heroku 云应用平台部署应用程序。


# 第八章：部署-时间上线！

在上一章中，您学会了如何测试您的 Vue 应用程序。我们应用了不同的测试技术进行测试。一开始，我们对 Vue 组件和与 Vuex 相关的模块（如 actions、mutations 和 getters）进行了经典的单元测试。之后，我们学会了如何使用 Nightwatch 应用端到端测试技术。

在本章中，我们将通过将应用程序部署到服务器并使其对世界可用来使我们的应用程序上线。我们还将保证我们的应用程序进行持续集成和持续部署。这意味着每当我们提交对应用程序所做的更改时，它们将自动进行测试和部署。

考虑到这一点，在本章中，我们将做以下事情：

+   使用 Travis 设置持续集成流程

+   使用 Heroku 设置持续部署

# 软件部署

在开始部署我们的应用程序之前，让我们首先尝试定义它实际上意味着什么：

> *“软件部署是使软件系统可供使用的所有活动。” - 维基百科：https://en.wikipedia.org/wiki/Software_deployment*

这个定义意味着在我们执行所有必要的活动之后，我们的软件将对公众可用。在我们的情况下，由于我们正在部署 Web 应用程序，这意味着将有一个公共 URL，任何人都可以在其浏览器中输入此 URL 并访问该应用程序。如何实现这一点？最简单的方法是向您的朋友提供您自己的 IP 地址并运行该应用程序。因此，在您的私人网络内的人将能够在其浏览器上访问该应用程序。因此，例如，运行番茄钟应用程序：

```js
**> cd <path to pomodoro> 
> npm run dev** 

```

然后检查你的 IP：

```js
**ifconfig**

```

![软件部署](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00315.jpeg)

使用 ifconfig 命令检查 IP 地址

然后与在同一私人网络上的朋友分享地址。在我的情况下，它将是`http://192.168.1.6:8080`。

然而，只有在你的网络内的朋友才能访问该应用程序，显然这样并不那么有趣。

您可以使用一些软件来创建一个公共可访问的地址，从而将您的计算机转变为一个托管提供者，例如**ngrok**（[`ngrok.com/`](https://ngrok.com/)）。运行该应用程序，然后运行以下命令：

```js
**ngrok http 8080** 

```

这将创建一个地址，可以从任何地方访问，就像一个常规网站：

![软件部署](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00316.jpeg)

使用 ngrok 为本地主机提供隧道

在我的情况下，它将是`http://5dcb8d46.ngrok.io`。我可以在我的社交网络上分享这个地址，每个人都可以访问并尝试 Pomodoro 应用程序！但是停下…我可以让我的笔记本电脑整夜开着，但我不能永远让它开着。一旦我关闭它，网络连接就会丢失，我的应用程序就无法访问了。而且，即使我可以让它永远开着，我也不喜欢这个网站地址。这是一堆字母和数字，我希望它有意义。

还有更强大的方法。例如，我可以在**AWS**（**亚马逊网络服务**）上购买一个虚拟实例，将我的应用程序复制到这个实例上，在 GoDaddy 等域名提供商购买一个域名，将该域名与购买的实例 IP 关联，并在那里运行应用程序，它将是可访问的，维护、备份和由亚马逊服务照料。令人惊讶，但…贵得要命。让我们在我们的应用程序达到相应规模和回报水平时考虑这个解决方案。

就目前而言，在这一章中，我们希望我们的部署解决方案是便宜的（便宜意味着免费）、强大和简单。这就是为什么我们将部署我们的应用程序到 Heroku，一个云应用平台。为了做到这一点，我们将首先将我们的应用程序托管在 GitHub 上。你还记得部署是使我们的应用程序准备好使用的东西吗？我认为一个应用程序在经过测试并且测试没有失败时才能使用。这就是为什么在实际部署之前，我们还将使用 Travis 来保证我们应用程序的质量。因此，我们部署应用程序的必要活动将是以下内容：

1.  为应用程序创建 GitHub 存储库，并将应用程序移入存储库。

1.  使用 Travis 进行持续集成。

1.  将应用程序连接到 Heroku，并设置和配置它们，以便 Heroku 运行它们并向世界公开它们。

在接下来的三个小节中，我将简要介绍 GitHub、Travis 和 Heroku。

## GitHub 是什么？

GitHub 是基于 Git 的项目的托管提供商。

它可以在小型个人规模上用于个人私人和公共项目。它也可以用于大型企业项目和所有与开发相关的活动，如代码审查，持续集成等等。

生活在开源软件世界的每个人都知道 GitHub。如果你正在阅读这本关于 Vue 的书，它托管在 GitHub 上（[`github.com/vuejs/`](https://github.com/vuejs/)），我相信你会跳过这一小节，所以我可能会在这里写一些愚蠢的笑话，而你永远不会注意到它们！开玩笑！

## Travis 是什么？

Travis 是 GitHub 的一个工具，它允许我们将 GitHub 项目连接到它，并确保它们的质量。它在您的项目中运行测试，并告诉您构建是否通过，或者警告您构建失败了。在[`travis-ci.org/`](https://travis-ci.org/)上了解更多关于 Travis 以及如何使用它。

## Heroku 是什么？

Heroku 是一个用于部署应用程序的云平台。它非常容易使用。您只需创建一个应用程序，给它一个好的有意义的名称，将其连接到您的 GitHub 项目，然后就完成了！每次您推送到特定分支（例如`master`分支），Heroku 将运行您提供的脚本作为应用程序的入口点脚本，并重新部署它。

它是高度可配置的，还提供了命令行界面，这样您就可以从本地命令行访问所有应用程序，而无需检查 Heroku 仪表板网站。让我们开始学习并亲自做一切。

# 将应用程序移动到 GitHub 存储库

让我们从为我们的应用程序创建 GitHub 存储库开始。

请使用[chapter8/pomodoro](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter8/pomodoro)和[chapter8/shopping-list](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter8/shopping-list)目录中的代码。

如果您还没有 GitHub 帐户，请创建一个。现在登录到您的 GitHub 帐户并创建两个存储库，`Pomodoro`和`ShoppingList`：

![将应用程序移动到 GitHub 存储库](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00317.jpeg)

在 GitHub 上创建存储库

一旦你点击**`创建存储库`**按钮，会出现一个包含不同指令的页面。我们特别关注第二段，它说**`...或在命令行上创建一个新的存储库`**。复制它，粘贴到 Pomodoro 应用程序目录中的命令行中，删除第一行（因为我们已经有了 README 文件），并修改第三行以添加目录中的所有内容，然后点击*Enter*按钮：

```js
**git init**
**git add** 
**git commit -m "first commit"**
**git remote add origin https://github.com/chudaol/Pomodoro.git**
**git push -u origin master**

```

刷新你的 GitHub 项目页面，你会看到所有的代码都在那里！在我的情况下，它在[`github.com/chudaol/Pomodoro`](https://github.com/chudaol/Pomodoro)。

对于购物清单应用程序也是一样。我刚刚做了，现在在这里：[`github.com/chudaol/ShoppingList`](https://github.com/chudaol/ShoppingList)。

如果你不想创建自己的存储库，你可以直接 fork 我的。开源就是开放的！

# 使用 Travis 设置持续集成

为了能够使用 Travis 设置持续集成，首先你必须将你的 Travis 账户与你的 GitHub 账户连接起来。打开[`travis-ci.org/`](https://travis-ci.org/)，点击**`使用 GitHub 登录`**按钮：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00318.jpeg)

点击使用 GitHub 登录按钮

现在你可以添加要由 Travis 跟踪的存储库。点击加号（**`+`**）：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00319.jpeg)

点击加号添加你的 GitHub 项目

点击加号按钮后，你的 GitHub 项目的整个列表会出现。选择你想要跟踪的项目：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00320.jpeg)

选择你想要用 Travis 跟踪的项目

现在我们的项目已经连接到 Travis 构建系统，它会监听对`master`分支的每次提交和推送，我们需要告诉它一些东西，一旦它检测到变化。所有 Travis 的配置都应该存储在`.travis.yml`文件中。将`.travis.yml`文件添加到这两个项目中。至少我们要告诉它应该使用哪个节点版本。检查你系统的 Node 版本（这是你完全确定可以与我们的项目一起工作的版本）。只需运行以下命令：

```js
**node --version** 

```

在我的情况下，它是`v5.11.0`。所以我会把它添加到`.travis.yml`文件中：

```js
//.travis.yml 
language: node_js 
node_js: 
  - "**5.11.0**" 

```

如果你现在提交并推送，你会发现 Travis 会自动开始运行测试。默认情况下，它会在项目上调用`npm test`命令。等待几分钟，观察结果。不幸的是，在执行端到端（Selenium）测试时会失败。为什么会发生这种情况呢？

默认情况下，Travis 构建和测试环境的虚拟镜像没有安装 Chrome 浏览器。而我们的 Selenium 测试正试图在 Chrome 浏览器上运行。但幸运的是，Travis 提供了在构建之前执行一些命令的机制。这应该在 YML 文件的`before_script`部分中完成。让我们调用必要的命令来安装 Chrome 并导出`CHROME_BIN`变量。将以下内容添加到你的`.travis.yml`文件中：

```js
before_script: 
  - export CHROME_BIN=/usr/bin/google-chrome 
  - sudo apt-get update 
  - sudo apt-get install -y libappindicator1 fonts-liberation 
  - wget https://dl.google.com/linux/direct/google-chrome-
    stable_current_amd64.deb 
  - sudo dpkg -i google-chrome*.deb 

```

如你所见，为了执行安装和系统更新，我们必须使用`sudo`来调用命令。默认情况下，Travis 不允许你执行`sudo`命令，以防止不可信任的脚本造成意外损害。但你可以明确告诉 Travis 你的脚本使用了`sudo`，这意味着你知道自己在做什么。只需将以下行添加到你的`.travis.yml`文件中：

```js
sudo: required 
dist: trusty  

```

现在你的整个`.travis.yml`文件应该如下所示：

```js
//.travis.yml 
language: node_js 
**sudo: required 
dist: trusty** 
node_js: 
  - "5.11.0" 

before_script: 
  - export CHROME_BIN=/usr/bin/google-chrome 
  - sudo apt-get update 
  - sudo apt-get install -y libappindicator1 fonts-liberation 
  - wget https://dl.google.com/linux/direct/google-chrome-
    stable_current_amd64.deb 
  - sudo dpkg -i google-chrome*.deb 

```

尝试提交并检查你的 Travis 仪表板。

哦，不！它又失败了。这次，似乎是超时问题：

![使用 Travis 进行持续集成设置](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00321.jpeg)

即使安装了 Chrome，测试仍然会由于超时而悄悄失败

为什么会发生这种情况？让我们回想一下当我们运行端到端测试时实际发生了什么。每个测试都会打开浏览器，然后执行点击、输入和其他操作来测试我们的用户界面。最后一句话的关键词是*用户界面*。如果我们需要测试用户界面，我们需要一个**图形用户界面**（**GUI**）。Travis 虚拟镜像没有图形显示。因此，它们无法打开浏览器并在其中显示我们的用户界面。幸运的是，有一种叫做*Xvfb - X 虚拟帧缓冲*的好东西。

Xvfb 是一个显示服务器，实现了物理显示使用的协议。所有需要的图形操作都在内存中执行；因此，不需要物理显示。因此，我们可以运行一个 Xvfb 服务器，为我们的测试提供虚拟图形环境。如果您仔细阅读 Travis 文档，您会发现这正是它建议的运行需要 GUI 的测试的方法：[`docs.travis-ci.com/user/gui-and-headless-browsers/#Using-xvfb-to-Run-Tests-That-Require-a-GUI`](https://docs.travis-ci.com/user/gui-and-headless-browsers/#Using-xvfb-to-Run-Tests-That-Require-a-GUI)。因此，打开`.travis.yml`文件，并将以下内容添加到`before_script`部分：

```js
  - export DISPLAY=:99.0 
  - sh -e /etc/init.d/xvfb start 

```

整个 YML 文件现在看起来像下面这样：

```js
//.travis.yml 
language: node_js 
sudo: required 
dist: trusty 
node_js: 
  - "5.11.0" 

before_script: 
  - export CHROME_BIN=/usr/bin/google-chrome 
  - sudo apt-get update 
  - sudo apt-get install -y libappindicator1 fonts-liberation 
  - wget https://dl.google.com/linux/direct/google-chrome-
    stable_current_amd64.deb 
  - sudo dpkg -i google-chrome*.deb 
  - export DISPLAY=:99.0 
  - sh -e /etc/init.d/xvfb start 

```

提交并检查您的 Travis 仪表板。Pomodoro 应用程序已成功构建！

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00322.jpeg)

Pomodoro 应用程序构建成功！

然而，购物清单应用程序的构建失败了。请注意，Travis 甚至会为每个构建状态更改选项卡的标题颜色：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00323.jpeg)

Travis 根据构建状态更改选项卡标题上的图标

购物清单应用程序的构建发生了什么？在端到端测试中有一步检查页面上是否存在**`Groceries`**标题。问题是，这个标题来自我们的后端服务器，应该使用`npm run server`命令运行。你还记得我们在第六章中实现它的吗，*插件-用自己的砖头建造你的房子*，使用了`vue-resource`插件？这意味着在构建应用程序之前，我们需要告诉 Travis 运行我们的小服务器。只需将以下行添加到购物清单应用程序的`.travis.yml`文件中：

```js
- nohup npm run server & 

```

提交您的更改并检查 Travis 仪表板。构建通过了！一切都是绿色的，我们很高兴（至少我是，我希望成功的构建也能让你开心）。现在，如果我们能告诉世界我们的构建是通过的，那就太好了。我们可以通过将 Travis 按钮添加到我们的`README.md`文件中来实现这一点。这将使我们能够立即在项目的 GitHub 页面上看到构建状态。

在应用程序的 Travis 页面上点击**`构建通过`**按钮，从第二个下拉列表中选择**`Markdown`**选项，并将生成的文本复制到`README.md`文件中：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00324.jpeg)

点击通过构建按钮，从第二个下拉菜单中选择 Markdown 选项，并将文本复制到 README.md 文件中

看看它在我们项目的 GitHub 页面的 README 文件中是多么漂亮：

![使用 Travis 设置持续集成](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00325.jpeg)

Travis 按钮在 GitHub 页面上的项目的 README 文件中看起来真的很漂亮

现在我们的应用程序在每次提交时都会被检查，因此我们可以确保它们的质量，最终将它们部署到公共可访问的地方。

在开始部署过程之前，请在 Heroku（[`signup.heroku.com/dc`](https://signup.heroku.com/dc)）创建一个帐户并安装 Heroku Toolbelt（[`devcenter.heroku.com/articles/getting-started-with-nodejs#set-up`](https://devcenter.heroku.com/articles/getting-started-with-nodejs#set-up)）。

现在我们准备部署我们的项目。

# 部署番茄应用程序

让我们从在 Heroku 账户中添加新应用开始。在 Heroku 仪表板上点击**`创建新应用`**按钮。你可以创建自己的名称，也可以将名称输入字段留空，Heroku 会为你创建一个名称。我会将我的应用称为*catodoro*，因为它是有猫的番茄！

![部署番茄应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00326.jpeg)

使用 Heroku 创建一个新应用

点击**`创建应用`**按钮，然后选择一个部署流水线来部署你的应用。选择 GitHub 方法，然后从建议的 GitHub 项目下拉菜单中选择我们想要部署的项目：

![部署番茄应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00327.jpeg)

选择 GitHub 部署方法，并从 GitHub 项目中选择相应的项目

点击**`连接`**按钮后，你可能想要检查的两件事是 **`从主分支启用自动部署`** 和 **`等待 CI 通过后再部署`** 选项：

![部署番茄应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00328.jpeg)

勾选等待 CI 通过后再部署复选框，然后点击启用自动部署按钮

一切都准备好进行第一次部署，甚至可以单击**`Deploy Branch`**按钮，Heroku 将尝试执行构建，但是，如果您尝试在浏览器中打开应用程序，它将无法工作。如果您想知道原因，您应该始终查看执行此类操作时的运行日志。

## 检查日志

我希望您已经成功安装了 Heroku CLI（或 Heroku 工具包），现在您可以在命令行中运行`heroku`命令。让我们检查日志。在您的 shell 中运行`heroku logs`命令：

```js
**heroku logs --app catodoro --tail** 

```

当 Heroku 尝试执行构建时，您将看到一个持续运行的日志。错误是`npm ERR! missing script: start`。我们在`package.json`文件中没有`start`脚本。

这是完全正确的。为了创建一个启动脚本，让我们首先尝试了解如何为生产构建和运行 Vue 应用程序。README 文件告诉我们需要运行`npm run build`命令。让我们在本地运行它并检查发生了什么：

![检查日志](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00329.jpeg)

npm run build 命令的输出

因此，我们知道构建命令的结果会进入`dist`文件夹。我们还知道我们必须使用 HTTP 服务器从此文件夹中提供`index.html`文件。我们还知道我们必须在`package.json`文件的`scripts`部分中创建一个`start`脚本，以便 Heroku 知道如何运行我们的应用程序。

## 准备在 Heroku 上运行应用程序

通过检查日志文件，我们能够收集了大量信息。在继续部署应用程序的步骤之前，让我们在这里总结一下 Heroku 在运行应用程序之前的流程。

因此，Heroku 执行以下操作：

+   运行`npm install`脚本以安装所有所需的依赖项（它检查`package.json`文件的`dependencies`部分中的依赖项）

+   从`package.json`运行`npm start`脚本，并在已知的 web 地址上提供其结果

因此，根据这些信息和我们从日志和运行`npm build`脚本中收集到的信息，我们需要执行以下操作：

+   告诉 Heroku 安装所有所需的依赖项；为此，我们需要将项目依赖项从`package.json`文件的`devDependencies`部分移动到`dependencies`部分，以便 Heroku 安装它们

+   告诉 Heroku 在执行`npm install`后运行构建脚本；为此，我们需要在`package.json`文件中创建一个`postinstall`脚本，其中我们将调用`npm run build`命令。

+   创建一个`server.js`文件，从`dist`文件夹中提供`index.html`文件

+   提供 Heroku 运行`server.js`脚本的方法；为此，我们需要在`package.json`文件中创建一个`start`脚本来运行`server.js`脚本

首先，将`package.json`文件的`devDependencies`部分中除了与测试有关的依赖之外的所有依赖移动到`dependencies`部分中：

```js
"dependencies": { 
  "autoprefixer": "⁶.4.0", 
  "babel-core": "⁶.0.0", 
  "babel-eslint": "⁷.0.0", 
  "babel-loader": "⁶.0.0", 
  "babel-plugin-transform-runtime": "⁶.0.0", 
  "babel-polyfill": "⁶.16.0", 
  "babel-preset-es2015": "⁶.0.0", 
  "babel-preset-stage-2": "⁶.0.0", 
  "babel-register": "⁶.0.0", 
  "chalk": "¹.1.3", 
  "connect-history-api-fallback": "¹.1.0", 
  "cross-spawn": "⁴.0.2", 
  "css-loader": "⁰.25.0", 
  "es6-promise": "⁴.0.5", 
  "eslint": "³.7.1", 
  "eslint-config-standard": "⁶.1.0", 
  "eslint-friendly-formatter": "².0.5", 
  "eslint-loader": "¹.5.0", 
  "eslint-plugin-html": "¹.3.0", 
  "eslint-plugin-promise": "².0.1", 
  "eslint-plugin-standard": "².0.1", 
  "eventsource-polyfill": "⁰.9.6", 
  "express": "⁴.13.3", 
  "extract-text-webpack-plugin": "¹.0.1", 
  "file-loader": "⁰.9.0", 
  "function-bind": "¹.0.2", 
  "html-webpack-plugin": "².8.1", 
  "http-proxy-middleware": "⁰.17.2", 
  "inject-loader": "².0.1", 
  "isparta-loader": "².0.0", 
  "json-loader": "⁰.5.4", 
  "lolex": "¹.4.0", 
  "opn": "⁴.0.2", 
  "ora": "⁰.3.0", 
  "semver": "⁵.3.0", 
  "shelljs": "⁰.7.4", 
  "url-loader": "⁰.5.7", 
  "vue": "².0.1", 
  "vuex": "².0.0", 
  "vue-loader": "⁹.4.0", 
  "vue-style-loader": "¹.0.0", 
  "webpack": "¹.13.2", 
  "webpack-dev-middleware": "¹.8.3", 
  "webpack-hot-middleware": "².12.2", 
  "webpack-merge": "⁰.14.1" 
}, 
"devDependencies": { 
  "chai": "³.5.0", 
  "chromedriver": "².21.2", 
  "karma": "¹.3.0", 
  "karma-coverage": "¹.1.1", 
  "karma-mocha": "¹.2.0", 
  "karma-phantomjs-launcher": "¹.0.0", 
  "karma-sinon-chai": "¹.2.0", 
  "karma-sourcemap-loader": "⁰.3.7", 
  "karma-spec-reporter": "0.0.26", 
  "karma-webpack": "¹.7.0", 
  "mocha": "³.1.0", 
  "nightwatch": "⁰.9.8", 
  "phantomjs-prebuilt": "².1.3", 
  "selenium-server": "2.53.1", 
  "sinon": "¹.17.3", 
  "sinon-chai": "².8.0" 
} 

```

现在让我们创建一个`postinstall`脚本，在其中我们将告诉 Heroku 运行`npm run build`脚本。在`scripts`部分中，添加`postinstall`脚本：

```js
  "**scripts**": { 
    <...> 
    **"postinstall": "npm run build"** 
  }, 

```

现在让我们创建一个`server.js`文件，在其中我们将从`dist`目录中提供`index.html`文件。在项目文件夹中创建一个`server.js`文件，并添加以下内容：

```js
// server.js 
var express = require('express'); 
var serveStatic = require('serve-static'); 
var app = express(); 
app.use(serveStatic(__dirname + '/dist')); 
var port = process.env.PORT || 5000; 
app.listen(port); 
console.log('server started '+ port); 

```

好的，现在我们只需要在`package.json`文件的`scripts`部分创建一个`start`脚本，然后我们就完成了！我们的`start`脚本应该只运行`node server.js`，所以让我们来做吧：

```js
  "**scripts**": { 
    <...> 
    "postinstall": "npm run build", 
    **"start": "node server.js"** 
  }, 

```

提交您的更改，转到 Heroku 仪表板，然后点击**`Deploy Branch`**按钮。不要忘记检查运行日志！

哇哦！构建成功了！成功构建后，您被邀请点击**`View`**按钮；别害羞，点击它，您将看到您的应用程序在运行！

![准备在 Heroku 上运行应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00330.jpeg)

番茄钟应用程序已成功部署到 Heroku

现在您可以在任何地方使用您的番茄钟应用程序。现在您也可以邀请您的朋友使用它，只需提供 Heroku 链接即可。

恭喜！您刚刚部署了您的 Vue 应用程序，每个人都可以使用它。多么美好啊！

# 部署购物清单应用程序

为了部署我们的购物清单应用程序，我们需要执行与番茄钟应用程序完全相同的步骤。

在您的 Heroku 仪表板上创建一个新应用程序，并将其连接到您的 GitHub 购物清单项目。之后，从番茄钟应用程序中复制`server.js`文件，处理`package.json`文件中的依赖关系，并创建`postinstall`和`start`脚本。

然而，我们还有一步要做。不要忘记我们的后端服务器，为购物清单提供 REST API。我们也需要运行它。

或者更好的是，如果我们可以只运行一个服务器来完成所有工作，为什么我们需要运行两个服务器呢？我们可以通过为其提供路由路径来将我们的 JSON 服务器与我们的 express 服务器集成以提供购物清单端点，比如`api`。打开`server.js`文件，在那里导入`jsonServer`依赖项，并告诉 express 应用程序使用它。因此，你的`server.js`文件将如下所示：

```js
//server.js 
var express = require('express'); 
**var jsonServer = require('json-server');** 
var serveStatic = require('serve-static'); 
var app = express(); 

app.use(serveStatic(__dirname + '/dist')); 
**app.use('/api', jsonServer.router('server/db.json'));** 
var port = process.env.PORT || 5000; 
app.listen(port); 
console.log('server started '+ port); 

```

使用前一行，我们告诉我们的 express 应用程序使用`jsonServer`并在`/api/`端点上提供`db.json`文件。

我们还应该更改`Vue`资源中的端点地址。打开 API 文件夹中的`index.js`，并用`api`前缀替换`localhost:3000`：

```js
const ShoppingListsResource = Vue.resource('api/' + 'shoppinglists{/id}') 

```

我们还应该在`dev-server.js`中添加 JSON 服务器支持；否则，我们将无法以开发模式运行应用程序。因此，打开`build/dev-server.js`文件，导入`jsonServer`，并告诉 express 应用程序使用它：

```js
//dev-server.js 
var path = require('path') 
var express = require('express') 
**var jsonServer = require('json-server')** 
<...> 
// compilation error display 
app.use(hotMiddleware) 

**// use json server 
app.use('/api', jsonServer.router('server/db.json'));** 
<...> 

```

尝试以开发模式运行应用程序（`npm run dev`）。一切正常。

现在你也可以从`travis.yml`文件中删除运行服务器的命令（`- nohup npm run server &`）。你也可以从`package.json`中删除服务器脚本。

在本地运行测试并检查它们是否失败。

我们几乎完成了。让我们在本地尝试我们的应用程序。

## 尝试在本地使用 Heroku

有时候要让事情运行起来需要很多次尝试和失败的迭代。我们尝试一些东西，提交，推送，尝试部署，看看是否起作用。我们意识到我们忘记了一些东西，提交，推送，尝试部署，看错误日志。一遍又一遍地做。这可能会非常耗时，因为网络上的事情需要时间！幸运的是，Heroku CLI 提供了一种在本地运行应用程序的方法，就像它已经部署到 Heroku 服务器上一样。你只需要在构建应用程序后立即运行`heroku local web`命令：

```js
**npm run build 
heroku local web** 

```

试一下。

在浏览器中打开`http://localhost:5000`。是的，它起作用了！

![尝试在本地使用 Heroku](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00331.jpeg)

使用 Heroku 本地 web 命令在本地运行应用程序。它起作用了！

现在让我们提交并推送更改。

现在你可以等待 Travis 成功构建并 Heroku 自动部署，或者你可以打开你的 Heroku 仪表板，点击**`Deploy Branch`**按钮。等一会儿。然后... 它起作用了！这是我们今天执行的两次部署的结果：

+   **番茄钟应用程序**：[`catodoro.herokuapp.com/`](https://catodoro.herokuapp.com/)

+   **购物清单应用程序**：[`shopping-list-vue.herokuapp.com/`](https://shopping-list-vue.herokuapp.com/)

各自的 GitHub 存储库可以在[`github.com/chudaol/Pomodoro`](https://github.com/chudaol/Pomodoro)和[`github.com/chudaol/ShoppingList`](https://github.com/chudaol/ShoppingList)找到。

分叉，玩耍，测试，部署。此刻，您拥有增强，改进并向全世界展示这些应用程序所需的所有工具。感谢您与我一起经历这激动人心的旅程！


# 第九章：接下来是什么？

在上一章中，我们通过将应用程序部署到服务器并使其对外可用，使我们的应用程序上线。我们还保证了应用程序的持续集成和持续部署。这意味着每当我们提交对应用程序的更改时，它们将自动进行测试和部署。

看起来我们在这本书中的旅程已经结束了。但实际上，它才刚刚开始。尽管我们已经发现和学到了很多，但仍有很多工作要做！在本章中，我们将总结我们迄今为止学到的一切，看看我们还有什么需要学习，以及我们还可以做些什么来提升我们应用程序的酷炫程度。因此，在本章中，我们将做以下事情：

+   总结我们迄今为止学到的一切

+   列出后续事项

# 迄今为止的旅程

迄今为止，我们已经走过了一段很长的旅程，现在是时候总结我们所做的和所学到的。

在第一章*使用 Vue.js 去购物*中，我们与 Vue.js 有了第一次约会。我们谈论了 Vue.js 是什么，它是如何创建的，它的作用是什么，并看了一些基本示例。

在第二章*基础知识-安装和使用*中，我们深入了解了 Vue.js 的幕后情况。我们了解了 MVVM 架构模式，看到了 Vue.js 的工作原理，并接触了 Vue.js 的不同方面，如*组件*、*指令*、*插件*和应用程序*状态*。我们学习了安装 Vue.js 的不同方式，从使用简单的独立编译脚本开始，通过使用 CDN 版本、NPM 版本，然后使用 Vue.js 的开发版本，不仅可以使用它，还可以为其代码库做出贡献。我们学会了如何调试以及如何使用`Vue-cli`搭建 Vue.js 应用程序。我们甚至使用了符合 CSP 标准的 Vue 的简单 Chrome 应用程序。

在第三章*组件-理解和使用*中，我们深入了解了组件系统。我们学习了如何定义 Vue 组件，组件作用域的工作原理，以及组件之间的关系，我们开始在之前引导的应用程序中使用单文件组件。

在第四章中，*反应性-将数据绑定到您的应用程序*，我们深入研究了 Vue.js 的数据绑定和反应性。我们学习了如何使用指令、表达式和过滤器。我们将数据绑定引入了最初章节中开发的应用程序，并且由于 Vue.js 的反应性方式，使它们变得交互式。

在第五章中，*Vuex-管理您的应用程序中的状态*，我们学习了如何使用 Vuex 存储系统在 Vue 应用程序中管理全局状态。我们学习了如何使用状态、操作、获取器和突变来创建一个模块化和良好的应用程序结构，其中组件可以轻松地相互通信。我们将这些新知识应用到了我们在前几章中开发的应用程序中。

在第六章中，*插件-用自己的砖块建造你的房子*，我们学习了 Vue 插件如何与 Vue 应用程序合作。我们使用了现有的插件`vue-resource`，它帮助我们在浏览器刷新之间保存应用程序的状态。我们还为 Vue 应用程序创建了自己的插件，用于生成白噪声、棕噪声和粉红噪声。在这一点上，我们拥有了功能齐全的应用程序，具有相当不错的一套工作功能。

在第七章中，*测试-是时候测试我们到目前为止所做的了！*，我们学习了如何测试我们的 Vue 应用程序。我们学习了如何编写单元测试，以及如何使用 Selenium 驱动程序创建和运行端到端测试。我们了解了代码覆盖率以及如何在单元测试中伪造服务器响应。我们几乎用单元测试覆盖了我们的代码的 100％，并且我们看到 Selenium 驱动程序在运行端到端测试时的效果。

在第八章，“部署-上线时间！”中，我们最终将我们的应用程序暴露给了整个世界。我们将它们部署到 Heroku 云系统，现在它们可以从互联网存在的任何地方访问。更重要的是，我们使我们的部署过程完全自动化。每当我们将代码更改推送到`master`分支时，应用程序就会被部署！甚至更多。它们不仅在每次推送时部署，而且还会自动使用 Travis 持续集成系统进行测试。

因此，在这本书中，我们不仅学习了一个新的框架。我们运用我们的知识从头开始开发了两个简单但不错的应用程序。我们应用了最重要的 Vue 概念，使我们的应用程序具有响应性、快速、可维护和可测试。然而，这并不是结束。在写作本书期间，Vue 2.0 已经发布。它带来了一些新的可能性和一些新的东西需要学习和使用。

# Vue 2.0

Vue 2.0 于 2016 年 9 月 30 日发布。查看 Evan You 在[`medium.com/the-vue-point/vue-2-0-is-here-ef1f26acf4b8#.ifpgtjlek`](https://medium.com/the-vue-point/vue-2-0-is-here-ef1f26acf4b8#.ifpgtjlek)的帖子。

在整本书中，我们使用了最新版本；然而，每当有必要时，我都试图参考 Vue 第一代的做法。实际上，API 几乎是相同的；有一些轻微的变化，一些已弃用的属性，但提供给最终用户的整个界面几乎没有改变。

然而，它几乎是从头开始重写的！当然，有一些代码部分几乎 100%被重用，但总体上，这是一个重大的重构，一些概念完全改变了。例如，渲染层被完全重写。如果早些时候，渲染引擎使用的是真实的 DOM，现在它使用了轻量级的虚拟 DOM 结构（[`github.com/snabbdom/snabbdom`](https://github.com/snabbdom/snabbdom)）。它的性能超群！查看以下的基准图表：

![Vue 2.0](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00332.jpeg)

性能基准（数值越低越好）取自 https://medium.com/the-vue-point/vue-2-0-is-here-ef1f26acf4b8#.fjxegtv98

在这个新版本中还有另一个有趣的地方。如果你已经使用过第一代 Vue，并阅读过它并听过播客，你可能知道 Vue 和 React 之间的一个主要区别是 React Native（这个框架允许我们基于 React 构建原生应用程序）。Evan You 一直声称 Vue 只是一个用于 web 界面的微小层。现在，我们有新兴的**Weex**，一个将受 Vue 启发的组件渲染成原生应用程序的框架（[`github.com/alibaba/weex`](https://github.com/alibaba/weex)）。根据 Evan You 的说法，很快，“受 Vue 启发”的将变成“由 Vue 驱动”的！敬请期待。请继续关注。我想推荐这个令人惊叹的 Full Stack Radio 播客，Evan You 在其中谈到了 Vue 的新版本：[`www.fullstackradio.com/50`](http://www.fullstackradio.com/50)。

> *Vue 自其作为一个副产品的谦卑开始以来已经发展了很多。今天它是由社区资助的，在现实世界中被广泛采用，并且根据 stats.js.org 的统计数据，它在所有 JavaScript 库中拥有最强劲的增长趋势之一。我们相信 2.0 版本将进一步推动它。这是自 Vue 诞生以来最大的更新，我们很期待看到你用它构建的东西。- *Evan You*，https://medium.com/the-vue-point/vue-2-0-is-here-ef1f26acf4b8#.fjxegtv98)*

考虑到这一点，如果你来自 Vue 1.0 时代，升级你的应用程序将不会很困难。查看迁移指南，[`vuejs.org/guide/migration.html`](http://vuejs.org/guide/migration.html)，安装迁移助手，[`github.com/vuejs/vue-migration-helper`](https://github.com/vuejs/vue-migration-helper)，应用所有必要的更改，然后看看你的应用程序在那之后的表现如何。

# 重新审视我们的应用程序

让我们再次检查我们到目前为止做了什么。我们已经使用 Vue.js 开发了两个应用程序。让我们重新审视它们。

## 购物清单应用程序

我们在本书章节中开发的购物清单应用程序是一个允许以下操作的 web 应用程序：

+   创建不同的购物清单

+   向购物清单添加新项目并在购买后进行检查

+   重命名购物清单并删除它们

我们的购物清单应用程序驻留在 Heroku 云平台上：[`shopping-list-vue.herokuapp.com/`](https://shopping-list-vue.herokuapp.com/)。

它的代码托管在 GitHub 上：[`github.com/chudaol/ShoppingList`](https://github.com/chudaol/ShoppingList)。

它与 Travis 持续集成：[`travis-ci.org/chudaol/ShoppingList`](https://travis-ci.org/chudaol/ShoppingList)。

它的界面简单易懂：

![购物清单应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00333.jpeg)

使用 Vue.js 开发的购物清单应用程序的界面

它仍然远非你每次去购物都会使用的东西，不是吗？

## 番茄钟应用程序

我们在本书中开发的番茄钟应用程序是一个 Web 应用程序，它在工作的番茄钟期间实现了白噪音和间隔时间显示美丽的猫的计时器。它允许以下操作：

+   启动、暂停和停止应用程序

+   在工作时听白噪音，有助于集中注意力的噪音

+   静音和取消静音白噪音声音

+   在空闲时间盯着小猫

我们的番茄钟应用程序也托管在 Heroku 云平台上：[`catodoro.herokuapp.com/`](https://catodoro.herokuapp.com/)。

它的代码也托管在 GitHub 上：[`github.com/chudaol/Pomodoro`](https://github.com/chudaol/Pomodoro)。

它还是在每次推送时使用 Travis 持续集成平台进行构建和测试：[`travis-ci.org/chudaol/Pomodoro`](https://travis-ci.org/chudaol/Pomodoro)。

它的界面清晰易用。以下是它在 20 分钟工作的番茄钟间隔时间显示的内容：

![番茄钟应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00334.jpeg)

工作中的番茄钟应用程序

当 5 分钟休息时间到来时，会出现以下内容：

![番茄钟应用程序](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00335.jpeg)

间隔时间的番茄钟应用程序

它实际上相当可用，但仍然远非完美。

# 为什么这只是个开始？

在前一节中，我们总结了本书中开发的应用程序的功能。我们也同意（希望）它们仍然远非完美。远非完美的东西是我们想要改进的东西，因此它们给我们带来挑战和目的。实际上还有很多工作要做。我们的应用程序很好，但它们缺乏功能、风格、身份、UX 模式、扩展到其他平台等等。让我们看看我们还能做什么。

## 为我们的应用程序添加功能

我们的应用程序已经具有一些非常好的功能，但它们可以拥有更多。它们可以更具配置性。它们可以更加灵活。它们可以更加友好的 UI/UX。让我们逐个查看它们，并列出可以添加的功能列表。这将是你的家庭作业。

### 购物清单应用

在浏览器中打开我们的购物清单应用程序并查看它。您可以向其中添加清单和项目。您可以删除项目和清单。但是每个打开应用程序的人都可以做同样的事情。这意味着我们必须为每个人提供自己的购物清单应用程序的方式，这只有通过身份验证机制才可能。

还有一些用户体验问题。如果我们可以内联更改购物清单的名称，为什么要在页脚的输入字段中更改它呢？实际上，当我们学习如何在 Vue 应用程序中实现数据绑定时，购物清单名称编辑在输入字段中是我们实现的第一件事情。所以，当时是有道理的，但现在它可以并且应该得到改进。

另一件事与已删除的项目有关。没有清除它们的方法。如果我们有一个很长的项目列表，即使我们删除它们，除非我们删除整个购物清单，否则它们将永远存在。应该有一种方法来清除清单上已选项目的方式。

我们可以应用的另一个美观变化与样式有关。不同的清单可能有不同的背景颜色，不同的字体颜色，甚至可能有不同的字体样式和大小。因此，以下是购物清单应用的改进列表：

+   实现身份验证机制

+   实现内联名称编辑

+   实现清除已选项目

+   实现配置不同购物清单样式的机制，如背景颜色、文字颜色、字体大小和样式

您还可以为项目实现类别，并为每个类别添加图标。作为灵感，您可以查看 Splitwise 应用程序[`www.splitwise.com/`](https://www.splitwise.com/)。当您开始添加项目时，项目的图标是通用的。一旦您输入了有意义的内容，图标就会更改，如下面的屏幕截图所示：

![购物清单应用](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00336.jpeg)

Splitwise 应用程序的屏幕截图可以为图标类别提供灵感：它会根据您在输入字段中输入的内容进行调整

尝试为我们的购物清单应用程序实现这种分类。这将是一个非常好的和强大的奖励！

### 番茄钟应用程序

在浏览器中打开我们的番茄钟应用程序并尝试使用它。这很好，毫无疑问。它简单易用。但是，一些额外的配置可能会为其带来一些额外的功能。例如，为什么我要工作 20 分钟？也许我想要 15 分钟的工作番茄钟。或者我想要更长的工作番茄钟，比如 25 或 30 分钟。它肯定应该是可配置的。

让我们仔细检查维基百科上的番茄钟技术描述，看看我们是否漏掉了什么：[`en.wikipedia.org/wiki/Pomodoro_Technique`](https://en.wikipedia.org/wiki/Pomodoro_Technique)。

我很确定我们是。检查一下基本原则：

| “四个番茄钟后，休息更长时间（15-30 分钟），将您的勾号计数重置为零，然后转到步骤 1。” |
| --- |
| --*https://en.wikipedia.org/wiki/Pomodoro_Technique* |

啊哈！四个番茄钟后应该发生一些事情。更长的间隔，更多时间盯着猫（或者做任何你想做的事情）。嗯，也许能够配置这段时间会很好！

还有一件重要的事情。和任何人一样，努力工作后，我想看到一些进展。如果我们的番茄钟应用程序能够显示一些关于我们能够集中精力和工作的时间的统计数据，这不是很好吗？为此，我们可以收集一些统计数据，并在我们的番茄钟计时器中显示它们。

另外，将这些统计数据存储起来并能够在一段时间内进行可视化，比如一周、一个月、一年，这会很好吧？这就导致我们需要实现一个存储机制。这个存储应该为每个用户存储统计数据，因此，也需要一个身份验证机制。

让我们想想我们美丽的白色、棕色和粉色噪音。目前，我们只播放在我们的`App.vue`中硬编码的棕色噪音：

```js
<template>
 <div id="app" class="container" **v-noise="'brown'"**>
 </div>
</template> 

```

我们不应该能够在噪音之间切换并选择我们最喜欢的吗？因此，我们已经确定了要添加到应用程序配置中的另一项内容。现在就够了；让我们把这些都列在清单上：

+   实现身份验证机制

+   实现一个存储机制——它应该收集有关工作时间的统计数据，并将它们存储在某种持久层中

+   实现统计数据显示机制——它应该获取存储的统计数据并以一种漂亮干净的方式显示出来（例如，图表）

+   为番茄钟应用程序添加配置机制。这个配置应该允许以下操作：

+   配置番茄钟工作时间

+   配置休息间隔时间

+   在可配置的工作番茄数量之后配置一个长的休息时间（默认为 4 个）

+   配置工作间隔期间播放的首选噪音

正如你所看到的，你还有一些工作要做。好在你已经有一个可用的番茄钟计时器应用程序，可以在改进时使用！

## 美化我们的应用程序

目前两个应用程序都相当灰暗。只有番茄钟计时器应用程序在屏幕上出现猫时才会变得多彩一点。为它们添加一些设计会很好。让它们变得独特，赋予它们自己的特色；你为它们努力工作了这么久，显然它们值得一些漂亮的衣服。让我们想想我们可以用样式做些什么。

### 标志

从标志开始。一个好的标志定义了你的产品并使其独特。至少我可以帮你设计番茄钟应用程序的标志的想法。我有一个叫 Carina 的非常好的朋友为我设计了一个番茄，我尽力在上面加了一只小猫。看看吧。你可以直接使用它，或者只是作为发展你自己想法的参考。实际上，你的想象力没有极限！

![标志](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/lrn-vue2/img/image00337.jpeg)

番茄钟应用程序的标志的想法

为购物清单应用程序想一个漂亮的标志。它可以是什么？一只装杂货的袋子？一个复选框？只是首字母——SL？同样，没有限制。我希望在存储库的分支中看到你漂亮的标志。等不及了！

### 标识和设计

我们的应用程序确实需要一些独特的设计。使用一些 UX 技术为它们开发一个漂亮的标识指南。考虑颜色、字体以及页面上元素应该如何组合，以便为我们的用户提供独特的用户友好体验。

### 动画和过渡

动画和过渡是为应用程序带来生机的强大机制。然而，它们不能被滥用。考虑它们何时何地是有意义的。例如，悬停在购物清单标题上可能会导致一些突出显示，购物清单项目在被选中时可以进行一些微小的弹跳，更改购物清单标题的过程也可以以某种方式突出显示，等等。番茄钟应用程序可以在每个状态转换时更改其背景颜色。它还可以意识到一天中的时间并相应地着色背景。机会数不胜数。发挥你的创造力，利用 Vue 的力量实现你的想法。

## 将我们的应用程序扩展到其他设备

我们的两个应用程序都是 Web 应用程序。对于番茄钟应用程序来说，如果我们整天都在电脑上工作并使用 Web，这可能没问题，但对于购物清单应用程序来说可能有点不舒服。你去购物时不会带着笔记本电脑。当然，你可以在家里填写购物清单，然后在超市打开手机浏览器，但这可能会很慢，使用起来也不太好。使用 Weex（[`github.com/alibaba/weex`](https://github.com/alibaba/weex)）将我们的 Web 应用程序带到移动设备上。这两个应用程序也可以扩展为 Google Chrome 应用程序，就像我们在第二章中学到的那样，*基础知识-安装和使用*。将你的工作扩展到每一个设备上。我期待着检查你的工作。

# 总结

这是本书的最后一章。老实说，我对此感到有点难过。我和你在一起的时间真的很愉快。我知道我不认识你，但我觉得我认识你。我和你交谈，有时我觉得你也在和我交谈。到目前为止开发的一切，我不能说都是我开发的；我觉得我们一直在一起工作。

实际上，这是一种非常有趣的感觉，因为当你阅读这本书时（对我来说，这是未来），我同时处于现在和未来。而你现在处于你的现在，同时又在过去和我交谈。我喜欢书籍和技术建立的联系方式，不仅在人与人之间建立联系，还在不同的时间间隔之间建立联系。这太神奇了。

我真的希望你能像我一样成为 Vue.js 的粉丝。

我真的希望你能至少改进我们迄今为止开发的一个应用程序，并向我展示。如果你需要帮助，我会很乐意帮助你。不要犹豫给我发邮件`chudaol@gmail.com`。

谢谢你一直陪伴着我，希望很快能在下一本书中见到你！


# 第十章：练习解决方案

# 第一章的练习

在第一章的结尾，有以下练习：

### 注意

我们在前几章中构建的番茄钟毫无疑问非常棒，但仍然缺少一些不错的功能。它可以提供的一个非常好的功能是在休息时间显示来自[`thecatapi.com/`](http://thecatapi.com/)的随机小猫。你能实现这个吗？当然可以！但请不要把休息时间和工作时间搞混了！我几乎可以肯定，如果你盯着小猫而不是工作，你的项目经理是不会喜欢的 :)

让我们解决这个问题。

查看 Pomodoro 的代码[`jsfiddle.net/chudaol/b6vmtzq1/`](https://jsfiddle.net/chudaol/b6vmtzq1/)。

检查[`thecatapi.com/`](http://thecatapi.com/)网站。

让我们首先添加一个带有指向猫 API 的图像的 Bootstrap 元素：

```js
<div id="app" class="container">
  <...>
  **<div class="well">
    <img :src="’ http://thecatapi.com/api/images/get?**
 **type=gif&size=med’" />
  <div>**
</div>

```

如果你打开页面，你会发现图像总是可见的。这不是我们想要的，我们希望它只在我们的 Pomodoro 休息间隔时可见。你已经知道如何做了。有几种方法可以实现这一点；让我们使用类绑定方法，并在状态为工作时绑定一个隐藏的类：

```js
<div class="well" **:class="{ 'hidden': pomodoroState === 'work' }**">
  <img :src="'http://thecatapi.com/api/
    images/get?type=gif&size=med'" />
</div>

```

现在，如果你打开页面，你会发现图像只在工作的 Pomodoro 完成后出现。

然而，问题在于我们休息的所有时间，图像都是一样的。如果我们每隔，比如，10 秒更新一次，那就太好了。

让我们为此目的使用缓存破坏机制。如果我们将一些属性附加到我们的 URL 并每隔 10 秒更改它，URL 将改变，因此我们将获得另一只随机的猫。让我们向我们的 Vue 应用程序添加一个`timestamp`变量，并在`_tick`函数内更改它：

```js
<...>
new Vue({
  el: "#app",
  data: {
    <...>
    **timestamp: 0**
  },
  <...>
  methods: {
    <...>
    _tick: function () {
      //update timestamp that is used in image src
      **if (this.second % 10 === 0) {
        this.timestamp = new Date().getTime();
      }**
      <...>
    }
  }
});

```

时间戳创建和更新后，我们可以在图像源 URL 中使用它：

```js
<div class="well" :class="{ 'hidden': pomodoroState === 'work' }">
  <img :src="**'http://thecatapi.com/api/images/get?
    type=gif&size=med&ts=' + timestamp"** />
</div>
```

就是这样！在这个 JSFiddle 中检查整个代码[`jsfiddle.net/chudaol/4hnbt0pd/2/`](https://jsfiddle.net/chudaol/4hnbt0pd/2/)。

# 第二章的练习

## 增强 MathPlugin

用三角函数（正弦、余弦和正切）增强我们的`MathPlugin`。

实际上，这只是添加缺失的指令并在其中使用`Math`对象的函数。打开`VueMathPlugin.js`并添加以下内容：

```js
//VueMathPlugin.js
export default {
  install: function (Vue) {
    Vue.directive('square', function (el, binding) {
      el.innerHTML = Math.pow(binding.value, 2);
    });
    Vue.directive('sqrt', function (el, binding) {
      el.innerHTML = Math.sqrt(binding.value);
    });
    **Vue.directive('sin', function (el, binding) {
      el.innerHTML = Math.sin(binding.value);
    });
    Vue.directive('cos', function (el, binding) {
      el.innerHTML = Math.cos(binding.value);
    });
    Vue.directive('tan', function (el, binding) {
      el.innerHTML = Math.tan(binding.value);
    });**
  }
};
```

你可以在 HTML 文件中检查这个指令是如何工作的：

```js
//index.html 
<div id="app">
  <input v-model="item"/>
  <hr>
  <div><strong>Square:</strong> <span v-square="item"></span></div>
  <div><strong>Root:</strong> <span v-sqrt="item"></span></div> **<div><strong>Sine:</strong> <span v-sin="item"></span></div>
  <div><strong>Cosine:</strong> <span v-cos="item"></span></div>
  <div><strong>Tangent:</strong> <span v-tan="item"></span></div>**
</div>
```

就是这样！

## 创建 Pomodoro 计时器的 Chrome 应用程序

请结合使用符合 SCP 标准的 Vue.js 版本和我们在第一章中创建的简单番茄钟应用程序的解决方案。检查`chrome-app-pomodoro`文件夹中的代码。

# 第三章练习

## 练习 1

当我们使用简单组件重写购物清单应用程序时，我们失去了应用程序的功能。这个练习建议使用事件发射系统来恢复功能。

在本节中，我们最终得到的代码看起来与[chapter3/vue-shopping-list-simple-components](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/chapter3/vue-shopping-list-simple-components)文件夹中的代码类似。

为什么它不起作用？检查开发工具的错误控制台。它显示如下内容：

```js
**[Vue warn]: Property or method "addItem" is not defined on the instance but referenced during render. Make sure to declare reactive data properties in the data option.**
**(found in component <add-item-component>)**

```

啊哈！这是因为在`add-item-template`中，我们调用了不属于这个组件的`addItem`方法。这个方法属于父组件，当然，子组件没有访问权限。我们该怎么办？让我们发出事件！我们已经知道如何做了。所以，我们不需要做太多事情。实际上，我们只需要做三件小事：

+   将`addItem`方法附加到`add-item-component`中，我们将在其中发出一个事件，并将这个组件的`newItem`属性传递给它。

+   修改/简化父组件的`addItem`方法。现在它只需要接收一个文本并将其添加到其`items`属性中。

+   在主标记中，使用`v-on`修饰符和事件的名称将组件的调用绑定到`addItem`方法，每次事件被发出时都会调用它。

让我们首先将`addItem`方法添加到`add-item-component`中。每次点击添加按钮或按下*Enter*键时都会调用它。这个方法应该检查`newItem`属性，如果包含文本，就应该发出一个事件。让我们把这个事件叫做`add`。因此，我们组件的 JavaScript 代码现在应该如下所示：

```js
//add item component
Vue.component('add-item-component', {
  template: '#add-item-template',
  data: function () {
    return {
      newItem: ''
    }
  },
  **methods: {
    addItem: function () {
      var text;

      text = this.newItem.trim();
      if (text) {
        this.$emit('add', this.newItem);
        this.newItem = '';
      }
    }
  }**
});

```

当发出`add`事件时，一定要以某种方式调用主组件的`addItem`方法。让我们通过在`add-item-component`的调用中附加`v-on:add`修饰符来将`add`事件绑定到`addItem`：

```js
<add-item-component **v-on:add="addItem"** :items="items">
</add-item-component>
```

好吧。正如你所看到的，这种方法几乎与主组件的`addItem`方法之前所做的事情相同。它只是不将`newItem`推送到`items`数组中。让我们修改主组件的`addItem`方法，使其只接收已处理的文本并将其推入物品数组中：

```js
new Vue({
  el: '#app',
  data: data,
  methods: { **addItem: function (text) {
      this.items.push({
        text: text,
        checked: false
      });
    }** }
});

```

我们完成了！这个练习的完整解决方案可以在[附录/第三章/vue-shopping-list-simple-components](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/Appendix/chapter3/vue-shopping-list-simple-components)文件夹中找到。

## 练习 2

在第三章的*使用单文件组件重写购物清单应用程序*部分，*组件-理解和使用*，我们很好地改变了使用单文件组件的购物清单应用程序，但还有一些事情没有完成。我们有两个缺失的功能：向物品列表添加物品和更改标题。

为了实现第一个功能，我们必须从`AddItemComponent`中发出一个事件，并在主`App.vue`组件中的`add-item-component`调用上附加`v-on`修饰符，就像我们在处理简单组件的情况下所做的那样。你基本上只需复制并粘贴代码。

更改标题功能也是如此。我们还应该发出一个`input`事件，就像我们在简单组件示例中所做的那样。

不要忘记向`App.vue`组件添加样式，使其看起来与以前一样。

在[附录/第三章/shopping-list-single-file-components](https://github.com/PacktPublishing/Learning-Vue.js-2/tree/master/Appendix/chapter3/shopping-list-single-file-components)文件夹中检查完整的代码。

# 总结

在本章中，您学会了如何使我们的应用程序对每个人都可用。您还学会了如何使用 Heroku 与 GitHub 存储库集成部署它们。您还学会了如何在每次提交和推送时自动执行此操作。我们还使用 Travis 在每次部署时进行自动构建。现在我们的应用程序正在进行全面测试，并在每次提交更改时自动重新部署。恭喜！

你可能认为这是旅程的终点。不，不是。这只是开始。在下一章中，我们将看到您可以学到什么，以及您可以用 Pomodoro 和购物清单应用程序做些什么好事。和我在一起！
