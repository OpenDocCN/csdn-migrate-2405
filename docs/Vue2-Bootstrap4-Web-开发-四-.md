# Vue2 Bootstrap4 Web 开发（四）

> 原文：[`zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8`](https://zh.annas-archive.org/md5/7E556BCDBA065D692175F778ABE043D8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：测试测试和测试

在上一章中，我们实现了锻炼管理页面。我们学习了如何使用 Google Firebase 数据存储机制来存储静态文件，并且再次使用了实时数据库来存储锻炼对象。我们使用 Bootstrap 为锻炼管理页面构建了一个响应式布局，并学习了如何使用 Bootstrap 的模态组件在一个漂亮的弹出窗口中显示每个单独的锻炼。现在我们有一个完全负责的应用程序。多亏了 Bootstrap，我们不需要实现任何特殊的东西来获得一个漂亮的移动表示。在移动屏幕上添加新的锻炼的样子如下：

![测试测试和测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00141.jpeg)

在移动屏幕上添加新的锻炼

这是我们的模态在移动设备上的样子：

![测试测试和测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00142.jpeg)

在移动设备上显示的锻炼模态

现在是测试我们的应用程序的时候了。我们将使用 Jest（[`facebook.github.io/jest/`](https://facebook.github.io/jest/)）来构建单元测试和运行快照测试。在本章中，我们将做以下事情：

+   学习如何配置我们的 Vue.js 应用程序与 Jest 一起工作

+   使用 Jest 断言测试 Vuex 存储

+   学习如何使用`jest.mock`和`jest.fn`方法模拟复杂对象

+   学习如何为 Vue 组件实现快照测试

# 为什么测试很重要？

我们的 ProFitOro 应用程序运行得很好，是吗？我们在浏览器中打开了它很多次，检查了所有实现的功能，所以它只是工作，对吧？是的，这是真的。现在去你的设置页面，尝试将计时器的值更改为一些奇怪的值。尝试使用负值，尝试使用巨大的值，尝试使用字符串，尝试使用空值……你认为这可以称为良好的用户体验吗？

![为什么测试很重要？](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00143.jpeg)

你不会想要在这么多分钟内工作，对吧？

你尝试过创建一个奇怪的锻炼吗？你尝试过在创建时输入一个巨大的锻炼名称并看看它是如何显示的吗？有成千上万种边缘情况，所有这些都应该仔细测试。我们希望我们的应用程序是可维护的、可靠的，并且提供令人惊叹的用户体验。

# 什么是 Jest？

你知道 Facebook 的人永远不会厌倦创造新工具。React、redux、react-native 以及所有这些响应式家族对他们来说还不够，他们创建了一个真正强大、易于使用的测试框架，叫做 Jest：[`facebook.github.io/jest/`](https://facebook.github.io/jest/)。Jest 非常酷，因为它足够自包含，让你不必分心于繁琐的配置或寻找异步测试插件、模拟库或伪计时器来与你喜欢的框架一起使用。Jest 是一个多合一的工具，虽然非常轻量级。此外，在每次运行时，它只运行自上次测试运行以来发生变化的测试，这非常优雅和快速！

最初为测试 React 应用程序而创建，Jest 被证明适用于其他用途，包括 Vue.js 应用程序。

查看罗曼·库巴在 2017 年 6 月波兰 Vue.js 大会上的精彩演讲([`youtu.be/pqp0PsPBO_0`](https://youtu.be/pqp0PsPBO_0))，他在其中简要解释了如何使用 Jest 测试 Vue 组件。

我们的应用不仅仅是一个 Vue 应用程序，它是一个使用了 Vuex 存储和 Firebase 的 Nuxt 应用程序。所有这些依赖项使得测试变得有点困难，因为我们必须模拟所有这些东西，还有 Nuxt 应用程序本身的特殊性。然而，这是可能的，一切设置好之后，编写测试的乐趣是巨大的！让我们开始吧！

# 开始使用 Jest

让我们从测试一个小的求和函数开始，检查它是否正确地对两个数字求和。

首先当然是安装 Jest：

```js
**npm install jest**

```

创建一个名为`test`的目录，并添加一个名为`sum.js`的文件，内容如下：

```js
// test/sum.js
export default function sum (a, b) {
  return a + b
}
```

现在为这个函数添加一个测试规范文件：

```js
// sum.spec.js
import sum from './sum'

describe('sum', () => {
  **it('create sum of 2 numbers', () => {**
 **expect(sum(15, 8)).toBe(23)**
 **})**
})
```

我们需要一个命令来运行测试。在`package.json`文件中添加一个`"test"`条目，它将调用一个`jest`命令：

```js
// package.json
"scripts": {
  //...
  **"test": "jest"**
}
```

现在如果你运行`npm test`，你会看到一些错误：

![开始使用 Jest](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00144.jpeg)

使用 Jest 运行测试时的测试输出中的错误

这是因为我们的 Jest 不知道我们在使用*ES6*！所以，我们需要添加`babel-jest`依赖项：

```js
**npm install babel-jest --save-dev**

```

安装完*babel-jest*之后，我们需要添加一个`.babelrc`文件，内容如下：

```js
// .babelrc
{
  "presets": ["es2015"]
}
```

你是否对 IDE 关于`describe`、`it`和其他未被识别的全局变量的警告感到烦恼？只需在你的`.eslintrc.js`文件中添加一个`jest: true`条目：

```js
// .eslintrc.js
module.exports = {
  root: true,
  parser: 'babel-eslint',
  env: {
    browser: true,
    node: true,
    **jest: true**
  },
  extends: 'standard',
  // required to lint *.vue files
  plugins: [
    'html'
  ],
  // add your custom rules here
  rules: {},
  globals: {}
}
```

现在如果你运行`npm test`，测试通过了！

![开始使用 Jest](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00145.jpeg)

恭喜！你刚刚设置并运行了你的第一个 Jest 测试！

## 覆盖率

单元测试有助于确保它们检查的代码片段（单元）对于任何可能和不可能的输入都能正常工作。每个编写的单元测试都覆盖了相应的代码片段，就像一条毯子一样，保护这段代码免受未来的故障，并使我们对代码的功能和可维护性感到舒适。代码覆盖有不同的类型：语句覆盖、行覆盖、分支覆盖等等。代码覆盖越多，代码就越稳定，我们就越舒适。这就是为什么在编写单元测试时，每次运行时检查代码覆盖率非常重要。使用 Jest 很容易检查代码覆盖率。你不需要安装任何外部工具或编写额外的配置。只需执行带有覆盖率标志的测试命令：

```js
npm test -- --coverage
```

你会神奇地看到这个美丽的覆盖率输出：

![覆盖率](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00146.jpeg)

使用覆盖率运行 Jest 测试

像魔术一样，对吧？

在`chapter9/1/profitoro`目录中找到代码。别忘了在其上运行`npm install`。

# 测试实用函数

现在让我们测试我们的代码！让我们从 utils 开始。创建一个名为`utils.spec.js`的文件，并导入`leftPad`函数：

```js
import { leftPad } from '~/utils/utils'
```

再看看这个函数：

```js
// utils/utils.js
export const leftPad = value => {
  if (('' + value).length > 1) {
    return value
  }

  return '0' + value
}
```

如果输入字符串的长度大于`1`，则此函数应返回输入字符串。如果字符串的长度为`1`，则应返回带有前导`0`的字符串。

测试起来似乎很容易，对吧？我们将编写两个测试用例：

```js
// test/utils.spec.js
describe('utils', () => {
  describe('leftPad', () => {
    it('should return the string itself if its length is more than 1', () => {
      **expect(leftPad('01')).toEqual('01')**
    })
    it('should add a 0 from the left if the entry string is of the length of 1', () => {
      **expect(leftPad('0')).toEqual('00')**
    })
  })
})
```

啊...如果你运行这个测试，你会得到一个错误：

![测试实用函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00147.jpeg)

当然，可怜的 Jest，并不知道我们在 Nuxt 应用程序中使用的别名。对于它来说，`~`符号什么都不等于！幸运的是，这很容易解决。只需在`package.json`文件中添加`jest`条目，并在其中添加一个名称映射条目：

```js
// package.json
"jest": {
  "moduleNameMapper": {
    **"^~(.*)$": "<rootDir>/$1"**
  }
}
```

现在 Jest 将知道以`~`开头的所有内容都应映射到根目录。如果你现在运行`npm test -- --coverage`，你会看到测试通过了！

![测试实用函数](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00148.jpeg)

映射根目录别名后，测试可以正常运行

然而，代码覆盖率确实很低。这是因为我们的工具中还有另一个要测试的函数。检查`utils.js`文件。你能看到`numberOfSecondsFromNow`方法吗？它也需要一些测试覆盖率。它计算了从给定输入时间到现在经过的时间。我们应该如何处理这个`Date.now`？我们无法预测测试结果，因为我们无法保证测试运行时的*现在*时刻与我们检查时的时刻相同。每一毫秒都很重要。简单！我们应该模拟`Date.now`对象！

## 使用 Jest 进行模拟

事实证明，即使是看似不可能的事情（停止时间）在 Jest 中也是可能的。使用`jest.fn()`函数很容易模拟`Date.now`对象。

查看关于使用 Jest 进行模拟的文档：

[`facebook.github.io/jest/docs/en/snapshot-testing.html#tests-should-be-deterministic`](http://facebook.github.io/jest/docs/en/snapshot-testing.html#tests-should-be-deterministic)

我们可以通过调用`Date.now = jest.fn(() => 2000)`来模拟`Date.now`函数。

现在我们可以轻松测试`'numberOfSecondsFromNow'`函数：

```js
// test/utils.spec.js
import { leftPad, numberOfSecondsFromNow } from '~/utils/utils'
//...
describe(**'numberOfSecondsFromNow'**, () => {
  it('should return the exact number of seconds from now', () => {
    **Date.now = jest.fn(() => 2000)**
    expect(numberOfSecondsFromNow(1000)).toEqual(1)
  })
})
```

现在覆盖率更好了，但如果我们能覆盖我们有趣的`beep`函数，那就更完美了。我们应该在其中测试什么？让我们尝试测试一下，当调用`beep`函数时，`Audio.play`方法被调用。模拟函数有一个特殊的属性叫做**mock**，其中包含了关于这个函数的所有信息——已经对它执行的调用次数，传递给它的信息等等。因此，我们可以像这样模拟`Audio.prototype.play`方法：

```js
let mockAudioPlay = jest.fn()
Audio.prototype.play = mockAudioPlay
```

在调用 beep 方法后，我们可以像这样检查模拟上执行的调用次数：

```js
expect(mockAudioPlay.mock.calls.length).toEqual(1)
```

或者我们可以断言模拟已经被调用了，就像这样：

```js
expect(mockAudioPlay).toHaveBeenCalled()
```

整个测试可能看起来像下面这样：

```js
describe('beep', () => {
  it('should call the Audio.play functuon', () => {
    let mockAudioPlay = jest.fn()

    Audio.prototype.play = mockAudioPlay

    beep()
    expect(mockAudioPlay.mock.calls.length).toEqual(1)
    expect(mockAudioPlay).toHaveBeenCalled()
  })
})
```

为了避免由于模拟原生函数而产生的副作用，我们可能希望在测试后重置我们的模拟：

```js
it('should call the Audio.play functuon', () => {
  // ...
  expect(mockAudioPlay).toHaveBeenCalled()
  **mockAudioPlay.mockReset()**
})
```

在这方面查看 Jest 文档：[`facebook.github.io/jest/docs/en/mock-function-api.html#mockfnmockreset`](https://facebook.github.io/jest/docs/en/mock-function-api.html#mockfnmockreset)。

或者，您可以配置 Jest 设置，以便在每次测试后自动重置模拟。为此，在`package.json`文件中的 Jest`config`对象中添加`clearMocks`属性：

```js
//package.json
"jest": {
  **"clearMocks": true,**
  "moduleNameMapper": {
    "^~(.*)$": "<rootDir>/$1"
  }
},
```

耶！测试通过了。检查一下覆盖率。看起来相当不错；然而，分支覆盖率仍然不完美：

![使用 Jest 进行模拟](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00149.jpeg)

utils.js 文件的分支覆盖率仅为 75%

为什么会发生这种情况？首先，检查`未覆盖的行`列。它显示了测试未覆盖的行。这是`numberOfSecondsFromNow`方法的第`22`行：

```js
export const numberOfSecondsFromNow = startTime => {
  const SECOND = 1000
  if (!startTime) {
    **return 0**
  }
  return Math.floor((Date.now() - startTime) / SECOND)
}
```

作为替代方案，您可以检查项目目录中的`coverage`文件夹，并在浏览器中打开`lcov-report/index.html`文件，以更直观地了解发生了什么：

![使用 Jest 进行模拟](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00150.jpeg)

代码覆盖率 HTML 以一种美观的方式显示了覆盖和未覆盖的行

在这里，您可以清楚地看到第`22`行标记为红色，这意味着它没有被测试覆盖。好吧，让我们来覆盖它！只需添加一个新的测试，覆盖`startTime`属性未传递给此方法的情况，并确保它返回`0`：

```js
// test/utils.js
describe(**'numberOfSecondsFromNow'**, () => {
 **it('should return 0 if no parameter is passed', () => {**
 **expect(numberOfSecondsFromNow()).toEqual(0)**
 **})**
  it('should return the exact number of seconds from now', () => {
    Date.now = jest.fn(() => 2000)
    expect(numberOfSecondsFromNow(1000)).toEqual(1)
  })
})
```

现在带着覆盖标志运行测试。天啊！这不是很棒吗？

![使用 Jest 进行模拟](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00151.jpeg)

100%的代码覆盖率，是不是很棒？

本节的最终代码可以在`chapter9/2/profitoro`文件夹中找到。

# 使用 Jest 测试 Vuex 存储

现在让我们尝试测试我们的 Vuex 存储。我们要测试的存储最关键的部分是我们的操作和突变，因为它们实际上可以改变存储的状态。让我们从突变开始。在`test`文件夹中创建`mutations.spec.js`文件并导入`mutations.js`：

```js
// test/mutations.spec.js
import mutations from '~/store/mutations'
```

我们已经准备好为我们的突变函数编写单元测试。

## 测试突变

突变是非常简单的函数，它接收一个状态对象，并将其属性设置为给定值。因此，测试突变非常简单——我们只需模拟状态对象，并将其传递给我们想要测试的突变，以及我们想要设置的值。最后，我们必须检查该值是否已实际设置。例如，让我们测试`setWorkingPomodoro`突变。这是我们的突变的样子：

```js
// store/mutations.js
setWorkingPomodoro (state, workingPomodoro) {
  state.config.workingPomodoro = workingPomodoro
}
```

在我们的测试中，我们需要为状态对象创建一个模拟。它不需要代表完整的状态；它至少需要模拟状态的`config`对象的`workingPomodoro`属性。然后我们将调用突变，传递给它我们的模拟状态和`workingPomodoro`的新值，并断言这个值已经应用到我们的模拟中。因此，这些是步骤：

1.  为状态对象创建一个模拟：`let state = {config: {workingPomodoro: 1}}`

1.  使用新值调用突变：`mutations.setWorkingPomodoro(state, 30)`

1.  断言该值已设置为模拟对象：`expect(state.config).toEqual({workingPomodoro: 30})`

这个测试的完整代码看起来如下：

```js
// test/mutations.spec.js
import mutations from '~/store/mutations'

describe('mutations', () => {
  describe('setWorkingPomodoro', () => {
    it('should set the workingPomodoro property to 30', () => {
      let state = {config: {workingPomodoro: 1}}
      mutations.setWorkingPomodoro(state, 30)
      expect(state.config).toEqual({workingPomodoro: 30})
    })
  })
})
```

相同的机制应该被应用于测试其余的变化。继续并完成它们吧！

## 使用 Jest 进行异步测试——测试动作

让我们继续测试更复杂的东西——我们的动作！我们的动作大多是异步的，并且它们在内部使用复杂的 Firebase 应用程序对象。这使得它们非常具有挑战性，但我们确实喜欢挑战，不是吗？让我们来看看`actions.js`文件中的第一个动作。它是`uploadImages`动作，看起来是这样的：

```js
uploadImages ({state}, files) {
  return Promise.all(files.map(this._uploadImage))
}
```

我们可能在这里测试什么呢？例如，我们可以测试`_uploadImage`函数被调用的次数与传递的图像数组的大小完全相同。为此，我们必须模拟`_uploadImage`方法。为了做到这一点，让我们在`actions`中也导出它：

```js
// store/actions.js
function _uploadImage (file) {
  //...
}

export default {
  **_uploadImage**,
  uploadImages ({state}, files) {
    return Promise.all(files.map(**this._uploadImage**))
  }
  //...
}
```

现在我们可以模拟这个方法并检查`mock`被调用的次数。模拟本身非常简单；我们只需要将`actions._uploadImage`分配给`jest.fn()`：

```js
// test/actions.spec.js
it('should call method _uploadImage 3 times', () => {
  **actions._uploadImage = jest.fn()**
})
```

从现在开始，我们的`actions._uploadImage`具有一个特殊的魔法属性叫做`mock`，我们已经谈论过了。这个对象让我们有机会访问对`_uploadImage`方法的调用次数：

```js
actions._uploadImage.mock.calls
```

因此，要断言调用次数为三，我们只需运行以下断言：

```js
expect(**actions._uploadImage.mock.calls.length**).toEqual(**3**)
```

### 提示

在这里查看有关在 Jest 中模拟函数的完整文档：

[`facebook.github.io/jest/docs/mock-functions.html#content`](https://facebook.github.io/jest/docs/mock-functions.html#content)

很好，但我们应该在哪里调用这个期望呢？`uploadImages`函数是异步的；它返回一个 promise。不知何故，我们可以窥视未来并监听 promise 的解析，然后在那里调用我们的断言。我们应该定义一些*回调*，并在 promise 解析后调用它们吗？不，不需要。只需调用您的函数，并在`then`回调中运行断言。因此，我们的测试将如下所示：

```js
// test/actions.spec.js
import actions from '~/store/actions'

describe('actions', () => {
  describe('uploadImages', () => {
    it('should call method _uploadImage 3 times', () => {
      actions._uploadImage = jest.fn()
      actions.uploadImages({}, [1, 2, 3])**.then(() => {**
 **expect(actions._uploadImage.mock.calls.length).toEqual(3)**
 **})**
    })
  })
})
```

它就是这样工作的！

现在让我们创建一个更复杂的模拟——针对我们的`firebaseApp`。我们如何决定模拟什么以及如何模拟？只需查看代码并检查正在执行的操作。因此，让我们例如检查`createNewWorkout`方法：

```js
// store/actions.js
createNewWorkout ({commit, state}, workout) {
  //...
  **let newWorkoutKey = state.workoutsRef.push().key**
  let updates = {}
  updates['/workouts/' + newWorkoutKey] = workout
  updates['/user-workouts/' + state.user.uid + '/' + newWorkoutKey] = workout

  **return firebaseApp.database().ref().update(updates)**
}
```

这里发生了什么？状态的`workoutsReference`生成了一些新的键，然后创建了名为`updates`的对象。该对象包含两个条目 - 分别为保存了 workout 对象的 Firebase 数据库资源。

然后调用 Firebase 的数据库`update`方法与此对象。因此，我们必须模拟数据库的`update`方法，以便我们可以检查调用它时传入的数据。我们还必须以某种方式将此模拟注入到大型 Firebase 应用程序模拟中。创建一个文件夹来保存我们的模拟文件，并将其命名为`__mocks__`。在此目录中添加两个文件 - `firebaseMocks.js`和`firebaseAppMock.js`。在`firebaseMocks`文件中为`update`方法创建一个空函数：

```js
// __mocks__/firebaseMocks.js
export default {
  **update: () => {}**
}
```

创建一个`firebaseApp`对象的模拟，它将在其`database`方法内调用模拟的`update`函数：

```js
// __mocks__/firebaseAppMock.js
import firebaseMocks from './firebaseMocks'
export default {
  **database**: () => {
    return {
      ref: function () {
        return {
          **update: firebaseMocks.update**
        }
      }
    }
  }
}
```

为了测试`createNewWorkout`方法，我们将使用`jest.mock`函数将 Firebase 对象绑定到其模拟。查看有关`jest.mock`函数的详细文档：

[`facebook.github.io/jest/docs/en/jest-object.html#jestmockmodulename-factory-options`](http://facebook.github.io/jest/docs/en/jest-object.html#jestmockmodulename-factory-options)。

在导入`actions.js`模块之前，我们需要绑定我们的模拟。这样，它将已经使用模拟对象。因此，我们的导入部分将如下所示：

```js
// test/actions.spec.js
import mockFirebaseApp from '~/__mocks__/firebaseAppMock'
**jest.mock('~/firebase', () => mockFirebaseApp)**

**import actions from '~/store/actions'**

```

让我们看看`workout`对象的情况，以便了解如何模拟和进行确定性测试。我们有以下这些行：

```js
// actions.js
workout.username = state.user.displayName
workout.uid = state.user.uid
```

因此，我们状态对象的模拟必须包含具有预定义的`displayName`和`uid`的用户对象。让我们创建它：

```js
let state = {
  user: {
    displayName: 'Olga',
    uid: 1
  }}
```

接下来会发生什么？

```js
workout.date = Date.now()
workout.rate = 0
```

再次，我们需要模拟`Date.now`对象。让我们像在`utils`测试规范中所做的那样做同样的事情：

```js
Date.now = **jest.fn(() => 2000)**

```

让我们进一步阅读我们的方法。它包含一行代码，根据`workoutsRef`状态对象生成`newWorkoutKey`变量：

```js
let newWorkoutKey = state.workoutsRef.push().key
```

让我们在我们的状态模拟中也模拟`workoutsRef`：

```js
let state = {
  user: {
    displayName: 'Olga',
    uid: 1
  },
  **workoutsRef: {**
 **push: function () {**
 **return {**
 **key: 59**
 **}**
 **}**
  }}
```

现在我们知道，当我们调用`addNewWorkout`方法时，最终预期会调用 Firebase 数据库的`update`方法，该方法将包含两个条目的对象 - 一个带有键`/user-workouts/1/59`，另一个带有键`/workouts/59`，两者都具有相同的`workout`对象的条目：

```js
{
  'date': 2000,
  'rate': 0,
  'uid': 1,
  'username': 'Olga'
}
```

所以，首先我们需要创建一个间谍。间谍是一个特殊的函数，它将替换我们绑定到它的函数，并监视这个函数发生的任何事情。再次强调，你不需要为间谍安装任何外部插件或库。Jest 已经内置了它们。

### 注意

在官方文档中查看 Jest 间谍：

[`facebook.github.io/jest/docs/jest-object.html#jestspyonobject-methodname`](http://facebook.github.io/jest/docs/jest-object.html#jestspyonobject-methodname)

因此，我们想在`update`模拟函数上创建一个间谍。让我们创建一个间谍：

```js
const spy = jest.**spyOn**(firebaseMocks, 'update')
```

最后，我们的断言将如下所示：

```js
expect(spy).toHaveBeenCalledWith({
  '/user-workouts/1/59': {
    'date': 2000,
    'rate': 0,
    'uid': 1,
    'username': 'Olga'
  },
  '/workouts/59': {
    'date': 2000,
    'rate': 0,
    'uid': 1,
    'username': 'Olga'
  }
})
```

整个测试将如下所示：

```js
describe('createNewWorkout', () => {
  it('should call update with', () => {
    const spy = jest.spyOn(firebaseMocks, 'update')
    Date.now = jest.fn(() => 2000)
    let state = {
      user: {
        displayName: 'Olga',
        uid: 1
      },
      workoutsRef: {
        push: function () {
          return {
            key: 59
          }
        }
      }}
    actions.createNewWorkout({state: state}, {})
    expect(spy).toHaveBeenCalledWith({
      '/user-workouts/1/59': {
        'date': 2000,
        'rate': 0,
        'uid': 1,
        'username': 'Olga'
      },
      '/workouts/59': {
        'date': 2000,
        'rate': 0,
        'uid': 1,
        'username': 'Olga'
      }
    })
  })
})
```

现在你知道如何在不同的 Firebase 方法上创建模拟和如何在它们上创建间谍，你可以创建其余的测试规范来测试其余的操作。在`chapter9/3/profitoro`文件夹中查看此部分的代码。

让我们继续学习如何使用 Jest 实际测试我们的 Vue 组件！

# 使 Jest 与 Vuex、Nuxt.js、Firebase 和 Vue 组件一起工作

测试依赖于 Vuex 存储和 Nuxt.js 的 Vue 组件并不是一件容易的任务。我们必须准备好几件事情。

首先，我们必须安装`jest-vue-preprocessor`，以便告诉 Jest Vue 组件文件是有效的。我们还必须安装`babel-preset-stage-2`，否则 Jest 会抱怨 ES6 的*spread*操作符。运行以下命令：

```js
**npm install --save-dev jest-vue-preprocessor babel-preset-stage-2**

```

安装完依赖项后，在`.babelrc`文件中添加`stage-2`条目：

```js
// .babelrc
{
  "presets": ["es2015", "stage-2"]
}
```

现在我们需要告诉 Jest 它应该使用`babel-jest`转换器来处理常规的 JavaScript 文件，以及使用`jest-vue-transformer`来处理 Vue 文件。为了做到这一点，在`package.json`文件的 jest 条目中添加以下内容：

```js
// package.json
"jest": {
    **"transform": {**
 **"^.+\\.js$": "<rootDir>/node_modules/babel-jest",**
 **".*\\.(vue)$": "<rootDir>/node_modules/jest-vue-preprocessor"**
    }
  }
```

我们在我们的组件中使用了一些图像和样式。这可能会导致一些错误，因为 Jest 不知道这些 SVG 文件是什么。让我们在`package.json`文件的`moduleNameMapper` Jest 条目中再添加一个条目：

```js
// package.json
"jest": {
  "moduleNameMapper": {
     "\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$": **"<rootDir>/__mocks__/fileMock.js"**,
"\\.(css|scss)$": **"<rootDir>/__mocks__/styleMock.js"**,
    // ...
  }
}
```

我们这样做是因为我们并不真的想测试图片或 CSS/SCSS 文件。

将`styleMock.js`和`fileMock.js`添加到`__mocks__`目录，内容如下：

```js
// styleMock.js
module.exports = {}

// fileMock.js
module.exports = 'test-file-stub'
```

查看官方文档以获取更多相关细节：[`facebook.github.io/jest/docs/webpack.html`](https://facebook.github.io/jest/docs/webpack.html)。

为 Vue 和 Vuex 文件添加名称映射：

```js
// package.json
"jest": {
  // ...
  "moduleNameMapper": {
    // ...
    **"^vue$": "vue/dist/vue.common.js",**
 **"^vuex$": "vuex/dist/vuex.common.js",**
    "^~(.*)$": "<rootDir>/$1"
  }
},
```

作为配置的最后一步，我们需要映射 Vue 文件的名称。Jest 很笨，无法理解我们实际上是在导入 Vue 文件，如果我们没有导入它的扩展名。因此，我们必须告诉它，从`components`或`pages`文件夹导入的任何内容都是 Vue 文件。因此，在这些配置步骤的最后，我们的 jest 的`moduleNamMapper`条目将如下所示：

```js
"jest": {
  //...
  "moduleNameMapper": {
    "\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$": "<rootDir>/__mocks__/fileMock.js",
    "\\.(css|scss)$": "<rootDir>/__mocks__/styleMock.js",
    "^vue$": "vue/dist/vue.common.js",
    "^vuex$": "vuex/dist/vuex.common.js",
    **"^~/(components|pages)(.*)$": "<rootDir>/$1/$2.vue",**
    "^~(.*)$": "<rootDir>/$1"
  }
}
```

我们现在准备测试我们的组件。您可以在`chapter9/4/profitoro`文件夹中找到所有这些配置步骤的最终代码。

# 使用 Jest 测试 Vue 组件

让我们从测试`Header`组件开始。由于它依赖于 Vuex 存储，而 Vuex 存储又高度依赖于 Firebase，我们必须做与测试 Vuex 操作相同的事情——在将存储注入到被测试的组件之前模拟 Firebase 应用程序。首先创建一个名为`HeaderComponent.spec.js`的规范文件，并将以下内容粘贴到其`import`部分：

```js
import Vue from 'vue'
**import mockFirebaseApp from '~/__mocks__/firebaseAppMock'**
**jest.mock('~/firebase', () => mockFirebaseApp)**
**import store from '~/store'**
import HeaderComponent from '~/components/common/HeaderComponent'
```

请注意，我们首先模拟 Firebase 应用程序，然后导入我们的存储。现在，为了能够使用模拟存储正确测试我们的组件，我们需要将存储注入其中。这样做的最佳方法是在其中创建一个带有`HeaderComponent`的`Vue`实例：

```js
// HeaderComponent.spec.js
let $mounted

beforeEach(() => {
  $mounted = new Vue({
    template: '<header-component **ref="headercomponent"**></header-component>',
    **store: store()**,
    **components: {**
 **'header-component': HeaderComponent**
 **}**
  }).$mount()
})
```

请注意，我们已经将引用绑定到已安装的组件。现在我们将能够通过调用`$mounted.$refs.headercomponent`来访问我们的头部组件：

```js
**let $headerComponent = $mounted.$refs.headercomponent**

```

在这个组件中我们可以测试什么？它实际上没有太多的功能。它有一个名为`onLogout`的方法，该方法调用`logout`操作并将`/`路径推送到组件的`$router`属性。因此，我们实际上可以模拟`$router`属性，调用`onLogout`方法，并检查该属性的值。我们还可以对`logout`操作进行监视，并检查它是否已被调用。因此，我们对组件的`onLogout`方法的测试可以如下所示：

```js
// HeaderComponent.spec.js
test('onLogout', () => {
  let $headerComponent = $mounted.$refs.headercomponent
  **$headerComponent.$router = []**
  const spy = jest.spyOn($headerComponent, 'logout')
  $headerComponent.onLogout()
  **expect(spy).toHaveBeenCalled()**
 **expect($headerComponent.$router).toEqual(['/'])**
})
```

运行测试。您将看到许多与 Nuxt 组件未正确注册相关的错误：

![使用 Jest 测试 Vue 组件](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00152.jpeg)

关于 nuxt-link 组件的 Vue 错误

嗯，如果你能忍受这些错误，就忍受吧。否则，以生产模式运行您的测试：

```js
// package.json
"test": "NODE_ENV=production jest"
```

### 提示

请注意，如果您以生产模式运行测试，实际上可能会错过一些相关错误。

恭喜！您已经能够使用 Jest 测试依赖于 Nuxt、Vuex 和 Firebase 的 Vue 组件！检查`chapter9/5/profitoro`目录中的此测试代码。

# 使用 Jest 进行快照测试

Jest 最酷的功能之一是*快照测试*。什么是快照测试？当我们的组件被渲染时，它们会产生一些 HTML 标记，对吧？一旦你的应用程序稳定下来，很重要的一点是，新添加的功能不会破坏已经存在的稳定标记，你不觉得吗？这就是快照测试存在的原因。一旦你为某个组件生成了快照，它将保留在快照文件夹中，并在每次测试运行时，它将比较输出与现有的快照。创建快照非常容易。在挂载组件后，你只需要在该组件的 HTML 上调用期望的`toMatchSnapshot`：

```js
let $html = $mounted.$el.outerHTML
expect($html).**toMatchSnapshot()**

```

我将为一个测试套件文件中的所有页面运行快照测试。在这之前，我将模拟我们的 Vuex 存储器的 getter，因为有些页面使用未初始化的用户对象，从而导致错误。因此，在我们的`__mocks__`文件夹内创建一个名为`gettersMock`的文件，并添加以下内容：

```js
// __mocks__/gettersMock.js
export default {
  **getUser: () => {**
 **return {displayName: 'Olga'}**
 **}**,
  getConfig: () => {
    return {
      workingPomodoro: 25,
      shortBreak: 5,
      longBreak: 10,
      pomodorosTillLongBreak: 3
    }
  },
  getDisplayName: () => {
    return 'Olga'
  },
  getWorkouts: () => {
    return []
  },
  getTotalPomodoros: () => {
    return 10
  },
  isAuthenticated: () => {
    return false
  }
}
```

让我们回到导入部分。正如我们已经发现的那样，Jest 在确定导入内容时并不是很擅长，因此它会抱怨相对导入（那些从点开始的导入，例如，在每个`components`文件夹内的`index.js`文件中）。让我们用它们的绝对等价物替换所有这些相对导入路径：

```js
// components/landing/index.js
export {default as Authentication} from '**~/components**/landing/Authentication'
//...
```

我还在`package.json``jest`条目内的名称映射器条目中添加了一个映射：

```js
"jest": {
  "moduleNameMapper": {
    //...
    **"^~/(components/)(common|landing|workouts)$": "<rootDir>/$1/$2"**
    //...
  }
}
```

太棒了！创建一个`pages.snapshot.spec.js`文件，并导入所有必要的模拟对象和所有页面。不要忘记将相应的模拟对象绑定到 Vuex“getter”函数和 Firebase 应用程序对象。你的导入部分应该如下所示：

```js
// pages.snapshot.spec.js
import Vue from 'vue'
import mockFirebaseApp from '~/__mocks__/firebaseAppMock'
import mockGetters from '~/__mocks__/getterMocks'
**jest.mock('~/firebase', () => mockFirebaseApp)**
**jest.mock('~/store/getters', () => mockGetters)**
import store from '~/store'
**import IndexPage from '~/pages/index'**
**import AboutPage from '~/pages/about'**
**import LoginPage from '~/pages/login'**
**import PomodoroPage from '~/pages/pomodoro'**
**import SettingsPage from '~/pages/settings'**
**import StatisticsPage from '~/pages/statistics'**
**import WorkoutsPage from '~/pages/workouts'**

```

我们将为每个页面创建一个测试规范。我们将以与我们绑定`Header`组件相同的方式绑定每个页面组件。我们将导出我们想要测试的组件作为 Vue 实例的组件，并在创建后挂载此 Vue 实例。因此，索引组件绑定将如下所示：

```js
// pages.snapshot.spec.js
let $mounted = new Vue({
  template: '<index-page></index-page>',
  store: store(),
  components: {
    'index-page': IndexPage
  }
}).$mount()
```

你现在唯一需要做的就是执行快照期望。因此，索引页面的完整测试规范将如下所示：

```js
// pages.snapshot.spec.js
describe('pages', () => {
  test('index snapshot', () => {
    let $mounted = new Vue({
      template: '<index-page></index-page>',
      store: store(),
      components: {
        'index-page': IndexPage
      }
    }).$mount()
    **let $html = $mounted.$el.outerHTML**
 **expect($html).toMatchSnapshot()**
  })
})
```

对所有页面重复相同的步骤。运行测试！检查覆盖率。现在我们在谈论！我们实际上触及了几乎所有应用程序的组件！看看这个：

![使用 Jest 进行快照测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00153.jpeg)

我们应用程序的几乎所有组件和文件都出现在覆盖报告中！

最重要的事情，实际上是快照测试的整个目的，就是在测试文件夹内生成的名为`__snapshots__`的文件夹。在这里，您将找到所有页面的所有 HTML 标记的新生成快照。这些快照看起来像这样：

![使用 Jest 进行快照测试](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00154.jpeg)

ProFitOro 页面的 Jest 快照

每当您进行影响标记的操作时，测试将失败。如果您真的想要更新快照，请使用更新标志运行测试：

```js
**npm test -- --u**

```

我发现快照测试是一个非常有趣和令人兴奋的功能！

### 提示

非常重要的是要提交您的快照文件！查看官方 Jest 网站上有关快照测试的详细文档：

[`facebook.github.io/jest/docs/snapshot-testing.html`](https://facebook.github.io/jest/docs/snapshot-testing.html)

本章的最终代码可以在`chapter9/6/profitoro`文件夹中找到。

# 总结

在本章中，我们使用了非常热门的技术来测试我们的 Vue 应用程序。我们使用了 Jest，并学习了如何创建模拟，测试组件，并使用它进行快照测试。

在下一章中，我们将最终看到我们的应用程序上线！我们将使用 Google Firebase Hosting 部署它，并提供必要的 CI/CD 工具，以便我们的应用程序在每次推送到主分支时都会自动部署和测试。您准备好看到您的作品上线并运行了吗？让我们开始吧！


# 第十章：使用 Firebase 部署

在上一章中，我们为应用程序的代码设置了测试框架，从现在开始可以使用单元测试和快照测试。在本章中，我们将使我们的应用程序上线！我们还将设置**持续集成**（**CI**）和**持续部署**（**CD**）环境。因此，在本章中，我们将学习如何执行以下操作：

+   使用本地 Firebase 工具部署到 Firebase 托管

+   使用 CircleCI 设置 CI 工作流程

+   使用 Firebase 和 CircleCI 设置暂存和生产环境

# 从本地机器部署

在本节中，我们将使用 Firebase 命令行工具部署我们的应用程序。我们已经完成了。查看 Google Firebase 文档进行快速入门：[`firebase.google.com/docs/hosting/quickstart`](https://firebase.google.com/docs/hosting/quickstart)。

基本上，如果你还没有安装 Firebase 工具，请立即安装！

```js
**npm install -g firebase-tools**

```

现在切换到你的项目目录并初始化一个 Firebase 项目：

```js
**firebase init**

```

从下拉菜单中选择**托管**。

### 提示

这并不是很明显，所以请记住，要实际从列表中选择某个东西，你必须按下*空格*。

![从本地机器部署](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00155.jpeg)

按空格选择托管功能

之后，从列表中选择你的 ProFitOro 项目，然后指定`dist`文件夹作为构建输出目录：

![从本地机器部署](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00156.jpeg)

输入资产的公共目录 dist

回答下一个问题选择“否”，然后你就完成了！确保 Firebase 在你的项目文件夹中创建`firebase.json`和`.firebaserc`文件。

这就是`firebase.json`文件的样子：

```js
// firebase.json
{
  "hosting": {
    "public": "dist"
  }
}
```

这就是你的`.firebaserc`文件的样子：

```js
.firebasercs
{
  "projects": {
    "default": "profitoro-ad0f0"
  }
}
```

你已经完成了！现在，如果我们使用`npm run generate`命令生成静态资产，这些资产将最终出现在`dist`文件夹中。之后运行`firebase deploy`，你的应用程序将立即部署！

因此，请继续执行以下操作：

```js
**npm run generate**
**firebase deploy**

```

如果遇到错误或问题，请执行以下操作：

+   确保你的 Firebase CLI 是最新的

+   如果需要，使用`firebase login --reauth`重新进行身份验证

+   如果出现错误，请尝试使用`firebase use --add`添加项目

恭喜！你的应用程序已经启动运行！

### 注意

您可能会问，如果最终我们只是生成静态资产进行部署，为什么我们要费心使用整个 Nuxt 路由和服务器端渲染。问题是，不幸的是，Firebase 只托管静态文件。为了能够运行一个节点服务器，我们应该使用另一个容器，比如，例如 Heroku：[`stackoverflow.com/questions/30172320/firebase-hosting-with-own-server-node-js`](https://stackoverflow.com/questions/30172320/firebase-hosting-with-own-server-node-js)。

还有一件事情你应该知道：现在我们无法在本地运行我们的应用程序；如果我们尝试这样做，我们将会收到一个`webpack`错误：

![从本地计算机部署](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00157.jpeg)

当我们尝试在本地运行应用程序时出现 webpack 错误

出于某种原因，我们的`actions.js`文件尝试导入`firebase.json`而不是位于`firebase`目录内的 Firebase 应用程序`index.js`文件。这很容易解决。将 Firebase 目录重命名为`firebaseapp` - 最终，它就是位于内部的内容。请在`chapter10/1/profitoro`文件夹中找到与此部分对应的代码。注意根目录中的新`firebase.json`和`.firebaserc`文件，以及所有 Firebase 应用程序的导入已更改为`firebaseapp`文件夹。

# 使用 CircleCI 设置 CI/CD

现在，如果我们想部署我们的应用程序，我们首先必须在本地运行测试，以确保一切正常，然后使用`firebase deploy`命令进行部署。理想情况下，所有这些都应该是自动的。理想情况下，如果我们将代码推送到主分支，一切都应该自动进行，不需要我们的干预。具有自动化测试检查的自动化部署过程称为持续部署。这个术语的意思就像它听起来的那样 - 您的代码正在持续部署。有很多工具可以让您一次点击按钮或只需推送到主分支即可自动将代码部署到生产环境。从可靠的 Jenkins 开始，到 Codeship、CloudFlare、CircleCI、Travis……列表是无穷无尽的！我们将使用 CircleCI，因为它与 GitHub 集成得很好。如果您想了解如何使用 Travis 进行部署，请查看我之前关于 Vue.js 的书籍：

[`www.packtpub.com/web-development/learning-vuejs-2`](https://www.packtpub.com/web-development/learning-vuejs-2)

首先，你应该将你的项目托管在 GitHub 上。请按照 GitHub 文档学习如何初始化你的仓库：

[`help.github.com/articles/adding-an-existing-project-to-github-using-the-command-line/`](https://help.github.com/articles/adding-an-existing-project-to-github-using-the-command-line/)

或者只需 fork 我的：

[`github.com/chudaol/profitoro`](https://github.com/chudaol/profitoro)

一旦你的仓库上线，就在 CircleCI 上创建你的账户：

[`circleci.com`](https://circleci.com)

使用 CircleCI web 界面，创建一个新项目，并从列表中选择你的仓库。之后，选择 Linux 操作系统和 Node 作为语言：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00158.jpeg)

CircleCI 项目配置

现在我们必须为我们的项目添加一个 CircleCI 配置，这样第一次推送时就知道该做什么。创建一个名为`config.yml`的文件的`.circleci`文件夹，并包含以下内容：

```js
// .circleci/config.yml
# Javascript Node CircleCI 2.0 configuration file
#
# Check https://circleci.com/docs/2.0/language-javascript/ for more details
#
version: 2
jobs:
  build:
    docker:
      # specify the version you desire here
      - image: circleci/node:7.10

      # Specify service dependencies here if necessary
      # CircleCI maintains a library of pre-built images
      # documented at https://circleci.com/docs/2.0/circleci-images/
      # - image: circleci/mongo:3.4.4

    working_directory: ~/repo

    steps:
      - checkout

      # Download and cache dependencies
      - restore_cache:
          keys:
          - v1-dependencies-{{ checksum "package.json" }}
          # fallback to using the latest cache if no exact match is found
          - v1-dependencies-

      - run: npm install

      - save_cache:
          paths:
            - node_modules
          key: v1-dependencies-{{ checksum "package.json" }}

      # run tests!
      - run: npm test
```

提交并推送更改到主分支。转到 CircleCI 界面，点击**开始构建**按钮：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00159.jpeg)

点击开始构建按钮

如果你像我一样幸运，你会看到以下成功的输出：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00160.jpeg)

CircleCI 成功！

让我们在我们的`README.md`文件中添加一个状态徽章，这样它就会出现在 GitHub 上。转到你的 CircleCI 项目设置（点击项目名称旁边的齿轮）：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00161.jpeg)

点击项目名称旁边的齿轮以打开项目的设置选项卡

在**设置**部分，选择**通知**|**状态徽章**：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00162.jpeg)

导航到设置|通知|状态徽章

复制并粘贴 markdown 代码到你的`README.md`文件中，使其看起来如下：

```js
// README.md
# Profitoro

**[![CircleCI](https://circleci.com/gh/chudaol/profitoro.svg?style=svg)](https://circleci.com/gh/chudaol/profitoro)**

> Take breaks during work. Exercise during breaks.
```

提交并推送更改到主分支！

如果你现在打开你的 GitHub 仓库，你会看到这个漂亮的徽章上写着**通过**：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00163.jpeg)

CircleCI 徽章显示一个好消息：通过

但我们的整个目的不仅仅是看到一个漂亮的绿色徽章，而是真正能够部署到 Firebase 托管容器。为了做到这一点，我们必须配置 CircleCI。我们通过向`config.yml`文件添加`deploy`部分来实现这一点。查看[`circleci.com/docs/2.0/configuration-reference/#deploy`](https://circleci.com/docs/2.0/configuration-reference/#deploy)上的文档。为了能够部署到 Firebase 托管，我们需要登录。很明显，CircleCI 在任何情况下都没有登录到我们的 Firebase 帐户。幸运的是，这对我们来说很容易解决。我们需要生成一个 CI 令牌，然后在我们的`deploy`命令中使用它。

### 注意

可以使用`firebase login:ci`命令生成 Firebase CI 令牌。

只需在控制台中运行此命令：

```js
**firebase login:ci**

```

您将获得类似于此的输出：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00164.jpeg)

Firebase login:ci 命令的输出

转到您的 CircleCI 的 Web 界面，并找到您项目的设置。在左侧，您会看到名为**构建设置**的选项卡。单击**环境变量**链接，将弹出**环境变量**部分。单击**添加变量**按钮，添加名为`FIREBASE_TOKEN`的变量，值为`YOUR_GENERATED_TOKEN`：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00165.jpeg)

在您的 CircleCI 项目设置中添加一个新的环境变量

现在让我们在`config.yml`文件中添加一个部署步骤。在这之前，请记住我们必须调用`firebase deploy`命令。好吧，为此，我们应该在 CircleCI 服务器上全局安装 Firebase 工具。而不是在 CircleCI 服务器上污染一些全局安装的软件，让我们将其安装为*dev 依赖项*，然后从`node_modules`文件夹中调用命令。因此，首先，将`firebase-tools`安装为`dev`依赖项：

```js
**npm install --save-dev firebase-tools**

```

现在我们终于可以添加`deploy`步骤了。在这一步中，我们必须使用`npm run generate`命令生成资产，并使用我们的令牌运行`firebase deploy`（命令将是`firebase deploy --token=<YOUR_FIREBASE_TOKEN>`）。我们不必指定令牌本身，因为我们已经为其创建了一个环境变量，所以命令将如下所示：

```js
**firebase deploy --token=$FIREBASE_TOKEN**

```

整个`deploy`条目将如下所示：

```js
// .circleci/config.yml
jobs:
  build:
    #...

    steps:
      - checkout

      #...      
      # deploy!
      **- deploy:**
 **command: |**
 **if [ "${CIRCLE_BRANCH}" == "master" ]; then**
 **npm run generate**
 **./node_modules/.bin/firebase deploy --token=$FIREBASE_TOKEN --non-interactive**
 **fi**

```

推送更改。检查您的 CircleCI 控制台。成功部署后，检查您的 Firebase 控制台的**托管**选项卡，并确保最后一次部署正好在此时进行：

![使用 CircleCI 设置 CI/CD](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00166.jpeg)

确保最后一次部署正好在此时进行！

这不是很棒吗？每当您将新更改推送到主分支时，它们将首先进行测试，只有在所有测试都通过后才会部署到您的 Firebase 托管提供商！我们设置所有这些需要多长时间？20 分钟？太棒了！

# 设置暂存和生产环境

您可能知道，直接部署到生产环境并不是一个很好的做法。即使测试通过，我们也必须先检查一切是否正确，这就是为什么我们需要一个*暂存*环境。

让我们在 Firebase 控制台上创建一个新项目，并将其命名为`profitoro-staging`。现在使用 Firebase 命令行工具向我们的项目添加一个新环境。只需在控制台中运行此命令：

```js
**firebase use –add**

```

选择正确的项目：

![设置暂存和生产环境](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00167.jpeg)

选择一个新创建的 profitoro-staging 项目

在下一步中键入别名`staging`：

```js
What alias do you want to use for this project? (e.g. staging) **staging**

```

检查`.firebaserc`文件是否已添加新条目：

```js
// .firebaserc
{
  "projects": {
    "default": "profitoro-ad0f0",
    **"staging": "profitoro-staging"**
  }
}
```

如果您现在在本地运行`firebase use staging`命令，然后在其后运行`firebase deploy`，您的项目将部署到我们新创建的暂存环境。如果您想切换并部署到生产环境，只需运行`firebase use default`命令，然后是`firebase deploy`命令。

现在我们需要重新配置我们的 CircleCI 工作流程。我们想要实现的是自动将资产部署到暂存服务器，然后进行手动批准以便部署到生产环境。为此，我们将使用带有手动批准的工作流配置。请查看有关此事的 CircleCI 官方文档页面：[`circleci.com/docs/2.0/workflows/#holding-a-workflow-for-a-manual-approval`](https://circleci.com/docs/2.0/workflows/#holding-a-workflow-for-a-manual-approval)。

我们最终会得到两个非常相似的作业-第一个将被称为`build`，它将包含与以前完全相同的内容，唯一的区别是部署步骤将使用别名`staging`：

```js
version: 2
jobs:
  build:
    docker
    #...

      # **deploy to staging!**
      - deploy:
          command: |
            if [ "${CIRCLE_BRANCH}" == "master" ]; then
              npm run generate
              **./node_modules/.bin/firebase use staging**
              ./node_modules/.bin/firebase deploy --token=$FIREBASE_TOKEN --non-interactive
            fi
```

第二个任务将被称为`deploy`，它将执行与`staging`任务完全相同的步骤（只是为了确保一切都没问题）。唯一的区别是在部署之前它将使用`default`别名：

```js
**build**:
  #...
deploy:
  docker:
    # ...
    # **deploy to production!**
    - deploy:
        command: |
          if [ "${CIRCLE_BRANCH}" == "master" ]; then
            npm run generate
            **./node_modules/.bin/firebase use default**
            ./node_modules/.bin/firebase deploy --token=$FIREBASE_TOKEN --non-interactive
          fi
```

之后，我们将添加一个名为`workflows`的新条目，如下所示：

```js
// .circleci/config.yml
jobs:
  build:
    #...
  deploy:
    #...
workflows:
  version: 2
  build-and-approval-deploy:
    jobs:
      - build
      - hold:
         type: approval
         requires:
           - build
      - deploy:
          requires:
            - hold
```

提交并推送到主分支。检查您的 CircleCI 控制台。成功部署到暂存环境后，单击**Workflow**选项卡，并检查它实际上是**暂停**状态：

![设置暂存和生产环境](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00168.jpeg)

工作流程处于暂停状态

检查您的暂存环境网站，并确保一切正常。

在完全确信一切都没问题之后，我们可以将我们的构建推广到生产环境。单击您的工作流程，然后单击**批准**按钮：

![设置暂存和生产环境](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00169.jpeg)

现在我们可以手动批准生产部署。

过一会儿，将会取得巨大成功！这不是很棒吗？

### 提示

尽管这超出了本书的范围，但请记住，在对暂存环境运行一些检查时，您不希望搞砸生产数据库。因此，为了使暂存成为真正的暂存，生产成为真正的生产，我们还应该设置一个暂存数据库。

检查`chapter10/2/profitoro`文件夹中的此部分代码。您需要注意的唯一两件事是`.firebaserc`配置文件和位于`.circleci/config.yml`目录中的 CircleCI 配置。

# 我们取得了什么成就？

亲爱的读者，我们已经走过了一段漫长的旅程。我们从最开始构建了我们的响应式应用程序，直到部署。我们使用了诸如 Vue.js、Bootstrap 4 和 Google Firebase 等优秀的技术来构建我们的应用程序。我们不仅使用了所有这些技术并学习了它们如何协同工作，而且实际上遵循了整个软件开发过程。

我们从业务理念、需求定义、用户故事定义和模型创建开始。我们继续进行实际实施-前端和后端都有。我们使用 Jest 进行了彻底的测试，最终将应用程序部署到了两个不同的环境中。甚至不仅仅是部署-我们实施了一个 CD 策略，它将自动为我们执行部署过程。

最重要的是-我们最终得到了一个完全功能的应用程序，可以让我们在工作期间管理时间并保持健康！

[`profitorolife.com/`](https://profitorolife.com/)

我甚至创建了一个 Facebook 页面：

[`www.facebook.com/profitoro/`](https://www.facebook.com/profitoro/)

如果你喜欢 ProFitOro 的标志设计，请向我的朋友 Carina 表示爱意和感谢：

`<car.marg@gmail.com>`

如果你喜欢模拟设计的方式，你应该感谢我的朋友和同事 Safi：

[`github.com/Safure`](https://github.com/Safure)

如果你喜欢 ProFitOro 的设计和插图，请查看我的朋友 Vanessa 的其他作品（[`www.behance.net/MeegsyWeegsy`](https://www.behance.net/MeegsyWeegsy)），并与她交谈，如果你觉得她可能也能帮助你。

如果你喜欢使用 SCSS 实现设计的方式，请给我的朋友 Filipe 一些*赞*（[`github.com/fil090302`](https://github.com/fil090302)）。

# 总结

在本章中，我们使用了 CircleCI 和 Firebase 来保证我们不断部署的软件的持续质量。正如我已经提到的，看到你从零开始创建的东西运行起来是如此美好！

然而，我们的工作还没有完成。还有很多改进要做。我们需要验证。我们需要编写更多的测试来增加我们的代码覆盖率！我们需要更多的锻炼，而且我们需要它们看起来漂亮。我们可能需要一些后台管理，让负责人可以在实际出现在所有人可见的锻炼列表之前检查每个添加的锻炼并批准它。

我们需要一个合适的统计页面，带有一些漂亮的图形。我们需要优化图像渲染。我们需要为每个锻炼显示多张图片。我们可能需要为锻炼添加视频支持。我们还需要在番茄工作计时器结束后出现的锻炼屏幕上做一些工作。现在看起来是这样的：

![总结](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-bts4-web-dev/img/00170.jpeg)

这里有很多按钮！但实际上它们都不起作用 :(

这里有三个按钮，但它们都不起作用。

所以，正如你所看到的，虽然我们已经完成了这本书，也有了一个功能齐全的软件，但我们还有一些工作要做。实际上，这让我感到非常高兴，因为这让我觉得我现在不必说再见。

与我分享您的想法，做一些了不起的事情并与我分享，或在 GitHub 上创建一些拉取请求或问题。我很乐意回答您。如果您有任何问题，建议或想法，请给我发电子邮件至`<chudaol@gmail.com>`。

感谢阅读本书并……去工作……出去！

# 索引

## A

+   会计

+   关于/ AAA 解释

+   操作

+   定义/ 定义操作和突变

+   警报组件

+   参考/ 继续结合 Vue.js 和 Bootstrap

+   匿名用户

+   管理/ 管理匿名用户

+   应用程序

+   部署/ 部署您的应用程序

+   脚手架/ 搭建应用程序

+   异步测试

+   Jest，使用/ 使用 Jest 进行异步测试-测试操作

+   身份验证/ AAA 解释

+   身份验证

+   关于/ AAA 解释

+   使用 Firebase 工作/ Firebase 的身份验证工作原理是什么？

+   身份验证，Firebase 文档

+   参考/ 更新用户配置文件

+   身份验证 API，Firebase

+   参考/ 如何将 Firebase 身份验证 API 连接到 Web 应用程序

+   身份验证 UI

+   增强/ 再次使身份验证 UI 变得很棒

+   授权

+   关于/ AAA 解释

## B

+   引导

+   用于添加表单/ 使用 Bootstrap 添加表单

+   关于/ Bootstrap

+   参考/ Bootstrap

+   功能/ Bootstrap

+   组件/ Bootstrap 组件

+   工具/ Bootstrap 工具

+   布局/ Bootstrap 布局

+   Vue.js，结合/ 结合 Vue.js 和 Bootstrap, 继续结合 Vue.js 和 Bootstrap

+   用于检查倒计时计时器组件的响应性/ 使用 Bootstrap 检查倒计时计时器的响应和适应性

+   用于检查倒计时计时器组件的适应性/ 使用 Bootstrap 检查倒计时计时器的响应和适应性

+   Bootstrap 标记

+   添加/ 添加 Bootstrap 标记

+   Bootstrap-Vue

+   参考/ 继续结合 Vue.js 和 Bootstrap

+   Bootstrap 类

+   用于创建布局/ 使用 Bootstrap 类创建布局

+   Bootstrap 模态框

+   用于显示锻炼/ 使用 Bootstrap 模态框显示每个锻炼, 锻炼

+   参考 / 使用 Bootstrap 模态框显示每个锻炼

+   Bootstrap 导航栏

+   使用，用于导航链接 / 使用 Bootstrap 导航栏进行导航链接

+   按钮

+   参考 / 倒计时计时器组件 - 让我们倒计时！

## C

+   驼峰式命名 / 定义 ProFitOro 组件

+   卡片 Bootstrap 组件

+   参考 / 结合 Vue.js 和 Bootstrap

+   卡片，Bootstrap 文档

+   参考 / 添加 Bootstrap 支持的标记

+   CI/CD

+   设置，使用 Circle CI / 使用 CircleCI 设置 CI/CD

+   Circle CI

+   用于设置 CI/CD / 使用 CircleCI 设置 CI/CD

+   CircleCI

+   参考 / 使用 CircleCI 设置 CI/CD, 设置暂存和生产环境

+   用于对齐的类，Bootstrap

+   参考 / 管理匿名用户

+   代码拆分 / 代码拆分或延迟加载

+   组件

+   消息卡，提取到 / 将消息卡提取到它们自己的组件中

+   组件，Bootstrap / Bootstrap 组件

+   组件，Vue / Vue 组件

+   倒计时计时器组件

+   响应性 / 使用 Bootstrap 实现倒计时器的响应和适应性

+   适应性 / 使用 Bootstrap 实现倒计时器的响应和适应性

+   倒计时，计数 / 倒计时组件-让我们倒计时！

+   自定义域

+   连接到 Firebase 项目 / 额外里程-将您的 Firebase 项目连接到自定义域

+   自定义模板，vue-cli

+   参考 / Vue-cli

## D

+   数据库条目

+   添加到 Firebase 应用程序数据库 / 向 Firebase 应用程序数据库添加第一个条目

## E

+   元素 / Vue.js

## F

+   文件上传

+   参考 / 使用 Firebase 数据存储存储图像

+   Firebase

+   关于 / 在 Firebase 控制台中创建项目, 什么是 Firebase？

+   服务 / 什么是 Firebase？

+   Firebase API 文档

+   参考 / 使用 Firebase 数据存储存储图像

+   Firebase 应用程序数据库

+   数据库条目，添加 / 向 Firebase 应用程序数据库添加第一个条目

+   Firebase 身份验证 API

+   工作流程/ Firebase 如何进行身份验证？

+   连接到 Web 应用程序/ 如何将 Firebase 身份验证 API 连接到 Web 应用程序

+   Firebase 控制台

+   项目，创建于/ 在 Firebase 控制台中创建项目

+   参考/ 在 Firebase 控制台中创建项目, 设置 Firebase 项目

+   Firebase 数据库

+   Vuex 存储，连接到/ 将 Vuex 存储连接到 Firebase 数据库

+   Firebase 数据存储

+   用于存储图像/ 使用 Firebase 数据存储存储图像, 让我们搜索！

+   Firebase 项目

+   Vue.js 应用程序，连接到/ 将 Vue.js 应用程序连接到 Firebase 项目

+   连接到自定义域/ 额外里程-将 Firebase 项目连接到自定义域

+   设置/ 设置 Firebase 项目

+   Firebase 实时数据库

+   用于存储锻炼/ 使用 Firebase 实时数据库存储新锻炼

+   文档，参考/ 使用 Firebase 实时数据库存储新锻炼

+   Firebase 实时数据库文档

+   参考 / 将 Vuex 存储连接到 Firebase 数据库

+   Firebase SDK

+   基于密码的身份验证 / Firebase 身份验证是如何工作的？

+   基于电子邮件的身份验证 / Firebase 身份验证是如何工作的？

+   联合实体提供者身份验证 / Firebase 身份验证是如何工作的？

+   基于电话号码的身份验证 / Firebase 身份验证是如何工作的？

+   自定义身份验证系统集成 / Firebase 身份验证是如何工作的？

+   匿名用户身份验证 / Firebase 身份验证是如何工作的？

+   flex-box

+   参考 / Bootstrap 实用工具

+   页脚

+   自定义 / 美化页脚

+   表单

+   添加，使用 Bootstrap / 使用 Bootstrap 添加表单

+   表单，Bootstrap 文档

+   参考 / 使用 Bootstrap 添加表单

+   功能，Bootstrap

+   引用 / Bootstrap

+   功能需求

+   收集 / 收集需求

## G

+   GoDaddy

+   参考 / 额外里程 – 将 Firebase 项目连接到自定义域

+   Google Firebase

+   参考 / 从本地机器部署

## H

+   Heroku

+   参考 / 从本地机器部署

+   历史 API

+   参考 / Vue 路由器

+   人机交互（HCI）

+   关于 / 模拟

## 我

+   图片

+   存储，使用 Firebase 数据存储 / 使用 Firebase 数据存储存储图片, 让我们搜索！

## J

+   Jest

+   关于 / 什么是 Jest？

+   参考 / 什么是 Jest？

+   使用 / 开始使用 Jest

+   覆盖率 / 覆盖率

+   模拟 / 使用 Jest 进行模拟

+   模拟，参考 / 使用 Jest 进行模拟

+   文档，参考 / 使用 Jest 进行模拟

+   用于测试 Vuex 存储 / 使用 Jest 测试 Vuex 存储

+   异步测试 / 使用 Jest 进行异步测试 - 测试操作

+   与 Vuex 一起工作 / 使用 Jest 与 Vuex、Nuxt.js、Firebase 和 Vue 组件

+   使用 Vue 组件工作 / 使用 Jest 与 Vuex、Nuxt.js、Firebase 和 Vue 组件

+   与 Nuxt.js 一起工作 / 使 Jest 与 Vuex、Nuxt.js、Firebase 和 Vue 组件一起工作

+   与 Firebase 一起工作 / 使 Jest 与 Vuex、Nuxt.js、Firebase 和 Vue 组件一起工作

+   用于测试 Vue 组件 / 使用 Jest 测试 Vue 组件

+   用于快照测试 / 使用 Jest 进行快照测试

+   jest.mock 函数

+   参考 / 使用 Jest 进行异步测试-测试操作

+   Jest 间谍

+   参考 / 使用 Jest 进行异步测试-测试操作

+   巨幕

+   参考 / 介绍锻炼

## K

+   KebabCased / 定义 ProFitOro 组件

## L

+   布局

+   创建，使用 Bootstrap 类 / 使用 Bootstrap 类创建布局

+   懒加载

+   关于 / 代码拆分或懒加载

+   参考 / 代码拆分或懒加载

+   本地机器

+   从本地机器部署 / 从本地机器部署

## M

+   菜单按钮

+   工作 / 练习-使菜单按钮工作

+   消息卡

+   提取到组件中 / 将消息卡提取到它们自己的组件中

+   模拟 / 使用 Jest 进行模拟

+   模拟功能

+   参考 / 使用 Jest 进行异步测试 - 测试操作

+   模型

+   关于 / 模型

+   登录页面 / 第一页 - 登录和注册

+   番茄钟计时器，显示 / 主页显示番茄钟计时器

+   锻炼，在休息期间 / 休息期间的锻炼

+   设置区域 / 设置

+   统计 / 统计

+   锻炼 / 锻炼

+   标志 / 标志

+   模式*历史选项

+   参考 / Vue 路由器

+   Moment.js 库

+   参考 / 添加实用功能以使事物看起来更好

+   moment.js 库

+   参考 / 练习

+   突变

+   定义 / 定义操作和突变

+   突变，Vuex 存储

+   参考 / Vuex 状态管理架构

## N

+   导航栏组件

+   参考 / 使用 Bootstrap 导航栏进行导航链接

+   导航

+   添加，使用 vue-router / 使用 vue-router 添加导航

+   根据身份验证限制 / 练习-根据身份验证限制导航

+   导航链接

+   使用 Bootstrap 导航栏 / 使用 Bootstrap 导航栏进行导航链接

+   名词

+   检索 / 名词

+   npm 包

+   参考 / 使用 Firebase 数据存储存储图像

+   nuxt-link

+   用于添加链接 / 使用 nuxt-link 添加链接

+   nuxt-starter 模板

+   关于 / Nuxt.js

+   参考 / Nuxt.js

+   Nuxt.js

+   关于 / Nuxt.js

+   URL / Nuxt.js

+   和 Vuex 存储 / Nuxt.js 和 Vuex 存储

+   Nuxt.js 中间件 / Nuxt.js 中间件

## O

+   偏移列

+   参考 / 使用 Bootstrap 响应式和自适应倒计时器

+   单向数据绑定 / Vue.js

## P

+   路径 SVG 元素

+   参考 / SVG 和三角函数

+   人物角色 / 人物角色

+   请介绍自己页面

+   参考 / 你好，用户

+   关于 / 你好，用户

+   番茄工作法

+   参考 / 陈述问题

+   番茄工作法计时器

+   主要原则/ 阐明问题

+   实现/ 实现番茄工作法计时器

+   SVG 和三角函数/ SVG 和三角函数, 练习

+   倒计时计时器组件，实现/ 实现倒计时计时器组件

+   关于/ 番茄工作法计时器, 练习

+   个性化/ 个性化番茄工作法计时器

+   预渲染 SPA 插件

+   参考/ 服务器端渲染

+   问题

+   阐明/ 阐明问题

+   profitoro

+   参考/ 使用 CircleCI 设置 CI/CD

+   ProFitOro 应用程序

+   认证到/ 认证到 ProFitOro 应用程序

+   ProFitOro 组件

+   定义/ 定义 ProFitOro 组件

+   项目

+   在 Firebase 控制台中创建/ 在 Firebase 控制台中创建项目

+   pull-*类

+   参考/ 使用 Bootstrap 实现倒计时计时器的响应性和适应性

+   push-*类

+   参考/ 使用 Bootstrap 实现倒计时计时器的响应性和适应性

## R

+   响应式应用程序

+   关于/ 我们取得了什么成就？

+   router-view 组件

+   参考/ Vue 路由器

## S

+   服务器端渲染（SSSR）

+   关于/ 服务器端渲染

+   参考/ 服务器端渲染

+   服务，Firebase

+   认证/ 什么是 Firebase？

+   数据库/ 什么是 Firebase？

+   托管/ 什么是 Firebase？

+   存储/ 什么是 Firebase？

+   单页面应用程序（SPA）/ Vue 路由器

+   快照测试

+   Jest，使用/ 使用 Jest 进行快照测试

+   参考/ 使用 Jest 进行快照测试

+   暂存和生产环境

+   设置/ 设置暂存和生产环境

+   样式

+   应用/ 是时候应用一些样式了

## T

+   模板文字

+   参考/ 倒计时组件- 让我们倒计时！

+   模板，vue-cli

+   webpack/ Vue-cli

+   webpack-simple/ Vue-cli

+   browserify/ Vue-cli

+   browserify-simple/ Vue-cli

+   简单/ Vue-cli

+   测试

+   重要性 / 为什么测试很重要？

+   Vue 文档

+   参考 / 练习

+   双向数据绑定 / Vue.js

## U

+   统一建模语言（UML） / 检索名词和动词

+   用户资料

+   更新 / 更新用户资料

+   用户故事 / 用户故事

+   实用函数

+   测试 / 测试实用函数

## V

+   v-on 指令

+   参考 / 倒计时组件- 让我们倒计时！

+   动词

+   检索 / 动词

+   Vue

+   组件 / Vue 组件

+   vue-cli

+   关于 / Vue-cli

+   参考 / Vue-cli, 搭建应用程序

+   vue-router

+   用于添加导航 / 使用 vue-router 添加导航

+   参考 / 使用 Bootstrap 导航栏进行导航链接

+   vue-router 库

+   参考 / Vue 路由器

+   Vue.js

+   功能，添加 / 使用 Vue.js 使事情功能化

+   实用函数，添加 / 添加实用函数使事情看起来更美观

+   关于 / Vue.js

+   参考 / Vue.js, 使用 CircleCI 设置 CI/CD

+   在脚本中包含 / 直接在脚本中包含

+   与 Bootstrap 结合 / 结合 Vue.js 和 Bootstrap, 继续结合 Vue.js 和 Bootstrap

+   Vue.js 应用程序

+   脚手架 / 搭建 Vue.js 应用程序

+   连接到 Firebase 项目 / 将 Vue.js 应用程序连接到 Firebase 项目

+   Vue 应用程序

+   URL / 服务器端渲染

+   Vue 组件

+   使用 Jest 进行测试 / 使用 Jest 测试 Vue 组件

+   Vue 指令

+   关于 / Vue 指令

+   条件渲染 / 条件渲染

+   文本，与 HTML / 文本与 HTML

+   循环 / 循环

+   数据，绑定 / 绑定数据

+   事件，处理 / 处理事件

+   Vue 文档

+   参考 / 搭建 Vue.js 应用程序

+   vuefire 包装器

+   参考 / 什么是 Firebase？

+   Vue 实例 / Vue.js

+   Vue 项目

+   关于 / Vue 项目-入门

+   CDN 版本，使用 / CDN

+   npm 依赖项，添加到 package.json 文件 / NPM

+   Vue 路由器 / Vue 路由器

+   Vuex

+   参考，用于模块 / 设置 Vuex 存储

+   Vuexfire

+   参考 / 将 Vuex 存储连接到 Firebase 数据库

+   Vuex 状态管理架构 / Vuex 状态管理架构

+   Vuex 存储

+   状态 / Vuex 状态管理架构, 设置 Vuex 存储

+   获取器 / Vuex 状态管理架构, 设置 Vuex 存储

+   突变 / Vuex 状态管理架构, 设置 Vuex 存储

+   设置 / 设置 Vuex 存储

+   行动 / 设置 Vuex 存储

+   连接到 Firebase 数据库 / 将 Vuex 存储连接到 Firebase 数据库

+   参考 / Nuxt.js 和 Vuex 存储

+   测试，使用 Jest / 使用 Jest 测试 Vuex 存储

+   测试，突变 / 测试突变

+   测试，操作 / 使用 Jest 进行异步测试 - 测试操作

## W

+   观察者

+   参考 / 练习

+   网络应用

+   Firebase 身份验证 API，连接到 / 如何将 Firebase 身份验证 API 连接到网络应用程序

+   webpack 文档

+   参考 / 代码拆分或延迟加载

+   WireframeSketcher

+   参考 / 模型

+   锻炼

+   使用 Firebase 实时数据库存储 / 使用 Firebase 实时数据库存储新的锻炼

+   使用 Bootstrap 模态框显示 / 使用 Bootstrap 模态框显示每个锻炼, 练习

+   锻炼

+   关于 / 介绍锻炼
