# Vue CLI3 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf`](https://zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：在 Vue CLI 3 中进行测试

在上一章中，我们研究了 Babel 在现代 JavaScript 开发中的作用。我们还看到了在 Vue 中使用它的一些实际例子。在本章中，我们将介绍 JS 中的测试。我们将了解测试的一般情况，并使用 Jest 和 Cypress 进行实践。我们将讨论断言和**测试驱动开发**（**TDD**）。然后，我们将继续了解 Jest 和 Cypress 如何与 Vue CLI 3 一起工作。我们将讨论测试工具和测试用例。具体来说，我们将看以下内容：

+   了解 Vue 插件

+   将 Jest 插件添加到我们的 Vue 应用程序

+   在 Vue 应用程序中使用 Jest 编写单元测试

+   从项目任务页面运行任务

+   在 Vue CLI UI 中运行单元测试

+   使用断言

+   实施 TDD

+   使用 Cypress

我们将从对 Vue 插件的简要概述开始本章。

# 了解 Vue 插件

使用 Vue CLI 从命令行创建新的 Vue 应用程序时，我们使用`vue create`命令。然后，我们需要选择一些步骤和提示，以便正确配置我们的应用程序。实际上，我们正在选择我们的应用程序将使用哪些 Vue 插件，而其他事情。

插件是向我们的 Vue 项目添加功能的一种方式。有些插件比其他插件更复杂；它们有时在安装过程中会出现自己的提示。我们的 Vue 应用程序的配置，即底层代码，将反映我们的选择。我们的应用程序的设置方式将基于我们对这些安装提示的回答。

项目的所有官方`npm`包都使用`@`符号进行范围限定，后面跟着项目名称。因此，由 Vue 维护者构建的官方 Vue 插件以`@vue`开头。

要了解有关范围限定`npm`包的更多信息，请访问：[`docs.npmjs.com/about-scopes.`](https://docs.npmjs.com/about-scopes)

要从命令行添加插件，我们使用`vue add`命令，但我们也可以使用 Vue UI，正如我们将在本章中看到的那样。Vue UI 也是搜索 Vue 插件的好方法，我们也将在本章中进行研究。

# 在全新的 Vue 应用程序上开始测试

在之前的章节中，我们已经看到了 Vue CLI 和 UI 中许多不同的选项。我们将通过使用最佳方法来开始一个新应用程序，即 Vue CLI UI，来开始本章。这将帮助我们了解 UI 的一些其他功能。在此过程中，我们还将慢慢向我们的项目引入测试。

# 使用 Vue CLI UI 添加新项目

现在让我们使用 Vue CLI UI 添加新项目：

1.  首先，让我们打开 Git Bash 并导航到所有项目的根文件夹`vue-cli-3-qsg`。

1.  现在我们将运行 Vue CLI UI 命令如下：

```js
vue ui
```

这将导致浏览器中提供新页面。默认地址为`http://localhost:8000/dashboard`。

1.  接下来，单击主页图标（或者在地址栏中键入此 URL：`http://localhost:8000/project/select`），这将带您到 Vue 项目管理器屏幕。

请注意，主页图标是 Vue CLI UI 页脚中最左边的图标：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/d066d2d2-1d87-47c5-b479-ab4fdbc8733d.png)

图 4.1：Vue CLI UI 中的主页图标

1.  无论您如何访问 Vue 项目管理器屏幕，它都会显示可用应用程序的列表，以及顶部的三个选项卡：*项目*，*创建*和*导入*。单击“创建”选项卡以创建新项目。

1.  单击“创建”选项卡后，您需要返回到项目的根目录，然后单击“在此处创建新项目”按钮如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/f50337fd-3de7-414c-8e66-f6dfbf260fc8.png)

图 4.2：创建，返回所有项目的根目录，点击“在此处创建新项目”按钮

一旦单击“在此处创建新项目”按钮，您将看到“创建新项目”屏幕。我们只会输入我们新应用程序的文件夹名称。我们将其称为`testing-debugging-vuecli3`。我们不会更改任何其他内容：我们将接受默认的软件包管理器和其他默认选项如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/e3d7bf4e-ac4d-4f63-993d-57ce8e52c478.png)

图 4.3：添加将容纳我们新应用程序的文件夹的名称

我们已经在“详细信息”选项卡中完成了所有必要的更改。

1.  点击“下一步”按钮，我们将进入预设屏幕。在那里，我们可以接受默认预设（babel，eslint）如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/3f893d8b-40a4-48d6-a106-e6516ad9c3c7.png)

图 4.4：接受默认预设

1.  接下来，我们将单击“创建项目”以搭建我们的项目。Vue CLI UI 完成项目搭建需要一些时间。完成后，我们将看到“欢迎来到您的新项目！”屏幕。

# 向我们的 Vue 应用程序添加 Jest 插件

现在让我们添加我们的 Jest 插件：

1.  点击插件图标（以下截图中标有数字 1）。

1.  一旦项目插件屏幕出现，点击“添加插件”按钮（以下截图中的 2）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/3e2f0239-9789-4a2b-a913-9d2b1e852732.png)

图 4.5：向我们的安装添加新插件

1.  这将带我们到“添加插件”屏幕，在那里我们有一个输入字段来搜索插件。我们需要找到一个单元测试插件，所以我们可以输入`cli-plugin-unit`如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/e2c3fc8e-4a03-426c-a3d6-6a4149a1c21f.png)

图 4.6：查找 Vue 的单元测试插件

1.  输入此搜索词将显示所有可用的单元测试插件。Jest 应该就在顶部。您可以在上一张截图中看到它，标记为 2。在插件名称下的描述中，您可以看到它是一个官方插件。与我们已经看到的`@vue/cli-plugin-babel`类似，您可以单击“更多信息”链接以查看有关所讨论插件的相应 GitHub 存储库（在上述截图中标记为 3）。这样做将带您到 vue-cli GitHub 页面。

您可以在以下 URL 的`npm`包页面上找到有关`@vue/cli-plugin-unit-jest`的更多信息：[`www.npmjs.com/package/@vue/cli-plugin-unit-jest.`](https://www.npmjs.com/package/@vue/cli-plugin-unit-jest)

1.  要安装 Jest 插件，只需在插件列表中单击它。这将在 Jest 插件旁边的绿色圆圈中添加一个复选框（在下一张截图中标记为 1）。还将出现一个新的安装按钮（在下一张截图中的框 2）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/368f8688-3b3a-4c26-b205-e6b72c0b1597.png)

图 4.7：添加 Jest 插件

1.  单击“安装@vue/cli-plugin-unit-jest”按钮将导致页面上出现加载器，并显示以下消息：安装@vue/cli-plugin-unit-jest....

1.  完成后，只需单击“完成安装”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/126f5dc8-06e3-4d38-9c8a-8de33ee9ef8e.png)

图 4.8：完成 Jest 插件的安装

1.  单击“完成安装”按钮将在屏幕上显示以下消息：调用@vue/cli-plugin-unit-jest....

1.  更新完成后，我们将看到另一个屏幕，显示文件的更改，并要求我们提交所做的更新：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/585749c2-edc5-4796-adb5-4a2e44f640c9.png)

图 4.9：Vue CLI UI 在安装 Jest 插件后显示更改

# 检查更新

在上述截图中，我们可以看到“更改的文件”选项卡是活动的。在“更改的文件”选项卡中，我们可以看到更改的文件数量（框 1）。

在使用 Vue CLI UI 构建项目时，我们被默认选项要求使用 Git 跟踪项目的更改，我们接受了这个默认设置；这就是为什么我们现在看到在上一个截图中标记为 2 的提交更改按钮。

我们还可以看到对两个现有文件`package-lock.json`和`package.json`所做的所有更改和更新，以及在安装插件时添加的三个新文件的内容：`jest.config.js`，`tests/unit/.eslintrc.js`和`tests/unit/example.spec.js`。

检查每个文件的内容将是有益的，以便更熟悉它们的设置以及对它们进行了哪些更改。我们需要注意的最重要的更改之一是在`package.json`文件中的`scripts`键中，如下所示：

```js
"test:unit":  "vue-cli-service test:unit"
```

前一行显示我们的`vue-cli-service`刚刚得到了一个新命令，`test:unit`，专门用于使用 Jest 进行单元测试。

一旦我们点击提交更改按钮，我们将看到一个对话框，邀请我们输入提交消息。我们可以输入一个简单的消息，比如`添加 Jest 插件`。

在我们添加了提交之后，我们将被带回到已安装插件的屏幕。现在我们可以看到`@vue/cli-plugin-unit-jest`也已添加：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/963f0ed0-fd7e-4e6e-84e7-07617b09ec13.png)

图 4.10：Vue CLI UI 在安装 Jest 插件后显示的更改

在接下来的部分中，我们将添加我们的应用程序，以便我们可以开始使用 Jest 进行测试。

# 添加我们的 Vue 应用程序的代码

要添加我们的应用程序，我们需要执行以下操作：

1.  在 Windows 资源管理器中导航到`testing-debugging-vuecli3`文件夹。

1.  接下来，在文件夹内的空白处右键单击，然后单击 Git Bash here 命令。

1.  一旦 Git Bash 打开，输入`code .`并按下*Enter*键。这将在 VS Code 中打开我们的`testing-debugging-vuecli3`项目。

我们目前的重点是 Jest。为了避免不必要的复杂性，我们将简单地复制并粘贴上一章中的整个`add-one-counter`应用程序。最简单的方法是将 Windows 资源管理器指向`add-one-counter`应用程序，并在文件夹内右键单击启动另一个 Git Bash 实例，如前所述。我们将再次在 Git Bash 中输入`code .`命令，另一个 VS Code 实例将打开，这次显示`add-one-counter`应用程序内的文件。现在只需要将所有文件和文件夹从`add-one-counter`复制并粘贴到`testing-debugging-vuecli3`中。

或者，您可以在 Git Bash 中使用 Linux 命令来复制相关文件。

无论您如何操作，更新后的项目结构现在将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/a4a82f25-9ba3-4340-82b4-3b4c35180c74.png)

图 4.11：testing-debugging-vuecli3 的更新项目结构

现在，我们准备使用 Jest 开始我们的第一个单元测试。

# 使用 Jest 在 Vue 应用程序中编写我们的第一个单元测试

在`tests`文件夹中，还有一个名为`unit`的文件夹。让我们向`unit`文件夹添加一个新文件。我们将这个新文件命名为`AnotherComponent.spec.js`。

任何具有`spec.js`扩展名的文件都将被 Jest 识别。

为了描述一个测试，我们使用`describe`函数，因此让我们将其添加到`AnotherComponent.spec.js`中，如下所示：

```js
describe()
```

`describe`函数接受两个参数。第一个参数是我们正在测试的 Vue 组件的名称，第二个参数是一个匿名函数，如下所示：

```js
describe('AnotherComponent.vue', function() {} )
```

我们可以使用箭头函数作为第二个参数来重写前面的代码，如下所示：

```js
describe('AnotherComponent.vue', () => {})
```

在匿名函数的主体中，我们调用另一个函数，`test`函数，如下所示：

```js
describe('AnotherComponent.vue', () => {
    test()
})
```

`test`函数接受两个参数：第一个参数是我们的测试名称，第二个参数是另一个匿名箭头函数，如下所示：

```js
describe('AnotherComponent.vue', () => {
    test('Jest is setup correctly and working', () => {})
})
```

我们正在指定一个名为`setup working`的测试，并且我们需要在第二个参数内给出一个断言，也就是在匿名函数的主体内，如下所示：

```js
describe('AnotherComponent.vue', () => {
    test('Jest is setup correctly and working', () => {
        expect(true).toBeTrue();
    })
})
```

这个断言将始终为真，因此我们给出以下代码：`expect(true).toBeTrue()`。

我们刚刚看到了 Jest 匹配器的一个示例。匹配器是在 Jest 中测试值的一种方式。检查某些东西是否为真的一种方式是使用`toBeTrue`匹配器。还有许多其他 Jest 匹配器。有关更多信息，请查看以下 URL 的官方 Jest 文档：[`jestjs.io/docs/en/using-matchers.`](https://jestjs.io/docs/en/using-matchers)

现在，让我们转到 Vue CLI UI，并运行我们的单元测试。

# 在 Vue CLI UI 中运行我们的第一个单元测试

要在 Vue CLI UI 中运行我们的单元测试，我们需要导航到`localhost:8080/tests`页面，可以直接从地址栏访问该 URL，也可以通过单击 Vue CLI UI 仪表板中最左侧列中的最低图标（Vue CLI UI 仪表板中的 Tests 图标）来导航到该页面。一旦我们这样做，我们将看到以下测试列表：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/8606c869-2f64-41d4-a36f-e97e81302adf.png)

图 4.12：查看 Vue CLI UI 中可用的任务

接下来，让我们准备点击`test:unit`任务来运行。这样做将导致在项目任务页面的右侧出现一个面板，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/75190c61-419f-4020-9037-b4bcf0fedffd.png)

图 4.13：运行 test:unit 命令的运行任务面板

这个运行任务面板给了我们一个很好的概览。现在让我们通过单击运行任务按钮来运行我们的测试。

以下信息将显示在输出部分：

```js
...
... 
PASS tests/unit/AnotherComponent.spec.js

Test Suites: 1 failed, 1 passed, 2 total
Tests: 1 passed, 1 total
Snapshots: 0 total
Time: 2.702s
Ran all test suites.

Total task duration: 3.93s
```

正如我们所看到的，我们的`AnotherComponent.spec.js`测试已经成功通过。在`AnotherComponent.spec.js`测试之前，有一个测试失败并记录输出的测试，那就是`HelloWorld.vue`组件的测试。我们在 Vue UI 构建应用程序后，已经将`HelloWorld.vue`文件从默认应用程序中移除了。

然而，`./tests/unit`文件夹中的`example.spec.js`文件是调用不存在的`HelloWorld.vue`文件的`test`文件。查看`example.spec.js`，我们可以看到它在第 2 行导入了`HelloWorld.vue`组件，如下所示：

```js
import HelloWorld from '@/components/HelloWorld.vue'
```

为什么会这样呢？难道我们不是已经在`describe`函数中指定了`AnotherComponent.vue`吗？

事实证明，我们可以在我们的单元测试中的 describe 函数的第一个参数中指定任何名称。例如，我们可以将我们的`AnotherComponent.spec.js`文件更新为以下代码：

```js
describe('whatever', () => {
    test('Jest is setup correctly and working', () => {
        expect(true).toBeTrue();
    })
})
```

如果我们再次运行我们的测试，它仍然会运行。

这意味着字符串`AnotherComponent.vue`是我们开发者作为第一个参数传递给我们的`describe`函数的，这样我们在项目中更容易工作。Jest 不在乎它的名字是什么。

然而，它在乎的是导入要测试的文件。正如我们在`HelloWorld.vue`导入中看到的，我们需要在我们的`AnotherComponent.spec.js`文件中添加一个类似的导入，这样现在它看起来如下：

```js
import AnotherComponent from '@/components/AnotherComponent.vue';

describe('AnotherComponent.vue', () => {
    test('Jest is setup correctly and working', () => {
        expect(true).toBeTrue();
    })
})
```

有趣的是，我们导入了一个 Vue 文件，但我们的测试仍然通过，即使`.vue`扩展名不是 JS。这是如何实现的？

如果我们打开位于项目根目录的`jest.config.js`文件，我们可以很容易地看到发生了什么。查看这个文件的前 12 行，我们会看到以下代码：

```js
module.exports = {
  moduleFileExtensions: [
    'js',
    'jsx',
    'json',
    'vue'
  ],
  transform: {
    '^.+\\.vue$': 'vue-jest',
    '.+\\.(css|styl|less|sass|scss|svg|png|jpg|ttf|woff|woff2)$': 'jest-transform-stub',
    '^.+\\.jsx?$': 'babel-jest'
  },
```

正如我们所看到的，`vue`扩展名在第 6 行上列出，`.vue`文件扩展名将使用`vue-jest`插件进行转换，如第 9 行所指定的。

在我们继续之前，让我们将我们的`example.spec.js`文件重命名为`example.js`，这样 Jest 就不会捕捉到它。我们仍然需要文件的内容，所以让我们不要删除它，而是只是重命名它。

# 从 test-utils 导入 mount 并编写另一个单元测试

我们将从`@vue/test-utils`中的`mount`导入开始，放在我们的`AnotherComponent.spec.js`文件的第一行，如下所示：

```js
import { mount } from '@vue/test-utils';
```

在我们继续之前，我们需要看一下这个语法的作用。为什么在`mount`周围有花括号？

要回答这个问题，了解这是被接受的 JS 语法是很重要的。为了解释发生了什么，我们需要从`package.json`文件开始。

这个文件是由我们的 Vue CLI 在构建项目时创建的。如果我们查看`package.json`文件的内容，我们会看到`@vue/test-utils`被列为我们项目的`devDependencies`之一。

在前面的代码中，我们从`@vue/test-utils` JS 模块中导入了一个单一函数`mount`。通过这样做，我们将`mount`函数插入到我们的`AnotherComponent.spec.js`文件的作用域中。

简单来说，我们从`@vue/test-utils`导入`mount`功能，这样我们就可以在`AnotherComponent.spec.js`文件中使用它，并且只测试这个组件。

在我们的浏览器中运行 Vue CLI UI，让我们通过访问以下 URL 来查看我们项目的依赖列表：`http://localhost:8000/dependencies`。

你应该会看到类似以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/8abc325a-aef6-4f62-9908-666c2197b2a1.png)

图 4.14：Vue CLI UI 仪表板中列出的项目的 devDependencies

像往常一样，点击`@vue/test-utils`项目依赖项的“更多信息”链接将带我们到该项目对应的 GitHub 存储库：[`github.com/vuejs/vue-test-utils#readme.`](https://github.com/vuejs/vue-test-utils#readme)

# 挂载要测试的组件

我们首先导入`mount`方法和要测试的组件，如下所示：

```js
import { mount } from '@vue/test-utils';
import AnotherComponent from '@/components/AnotherComponent.vue';
```

`mount`函数接收一个组件作为其参数。调用`mount`函数的结果是一个包装器，其中包含我们给定的组件的实例。这个包装器还带有帮助我们测试过程的附加函数。让我们首先将调用`mount(AnotherComponent)`的返回值分配给一个变量，如下所示：

```js
import { mount } from '@vue/test-utils';
import AnotherComponent from '@/components/AnotherComponent.vue';

describe('AnotherComponent.vue'), () => {
  test('Adds one when a user clicks the button', () => {
  const wrapped = mount(AnotherComponent);
}
```

# 编写一个失败的断言

当我们的应用程序最初加载到浏览器中时，我们期望计数器的当前值为`0`。然而，由于我们希望我们的断言最初失败，让我们断言计数器的值将是`1`而不是`0`，如下所示：

```js
import { mount } from '@vue/test-utils';
import AnotherComponent from '@/components/AnotherComponent.vue';

describe('AnotherComponent.vue'), () => {
  test('Adds one when a user clicks the button', () => {
  const wrapped = mount(AnotherComponent);
  expect(wrapped.text()).toContain('Current value of the counter: 1');
}  
```

在上述代码中，我们已经编写了一个失败的断言。我们声称我们期望我们的包装组件将包含以下文本：

```js
Current value of the counter: 1
```

我们的计数器的初始值不会是`1`；实际上将是`0`，因此前面的断言应该失败。

因此，让我们保存并运行我们的单元测试，方法是转到项目任务屏幕，并按照本章前面描述的方式运行测试。

输出将显示在项目任务中的 Run task 的输出面板中，如下所示：

```js
Test Suites: 1 failed, 1 total
Tests: 0 total
Snapshots: 0 total
Time: 1.947s
Ran all test suites.

Total task duration: 3.14s
```

接下来，我们将通过编写一个通过的断言来修复前面的测试。

# 编写一个通过的断言

要编写一个通过的断言，我们只需要将我们的`1`恢复为`0`，如下所示：

```js
expect(wrapped.text()).toContain('Current value of the counter: 0');
```

接下来，让我们在 Vue UI 中再次运行我们的任务，然后我们将得到以下输出：

```js
Test Suites: 1 passed, 1 total
Tests: 1 passed, 1 total
Snapshots: 0 total
Time: 2.418s
Ran all test suites.

Total task duration: 3.55s
```

接下来，我们将在我们的测试中触发一个按钮点击。

# 在我们的测试中触发按钮点击

我们如何在单元测试中测试按钮点击？执行以下步骤：

1.  我们需要找到要点击的按钮。这很容易，因为我们的应用程序中只有一个按钮。我们将使用`find`方法来做到这一点。

1.  我们将使用`trigger`方法触发按钮点击。

1.  我们需要检查计数器的值是否从`0`变为`1`。然而，由于我们首先需要编写一个失败的测试，我们将编写以下代码：

```js
import { mount } from '@vue/test-utils';
import AnotherComponent from '@/components/AnotherComponent.vue';

describe('AnotherComponent.vue', () => {
  test('Adds one when a user clicks the button', () => {
    const wrapped = mount(AnotherComponent);
    expect(wrapped.text()).toContain('Current value of the counter: 0');
    const button = wrapped.find('button');
    button.trigger('click');
    expect(wrapped.text()).toContain('Current value of the counter: 0');
  })
})
```

如预期的那样，在 Vue CLI UI 中运行我们的测试的输出如下：

```js
Test Suites: 1 failed, 1 total
Tests: 1 failed, 1 total
Snapshots: 0 total
Time: 2.383s
Ran all test suites.

Total task duration: 3.55s
```

通过编写两个测试并断言它们以使它们都通过，让事情变得更有趣，如下所示：

```js
import { mount } from '@vue/test-utils';
import AnotherComponent from '@/components/AnotherComponent.vue';

describe('AnotherComponent.vue', () => {
    const wrapped = mount(AnotherComponent);
    const button = wrapped.find('button');
    test('Checks that the initial counter value is 0', () => {
        expect(wrapped.text()).toContain('Current value of the counter: 0');
    });
    test('Adds one when a user clicks the button', () => {
        button.trigger('click');
        expect(wrapped.text()).toContain('Current value of the counter: 1');
    })
})
```

让我们再次保存我们的测试，并在 Vue CLI UI 中再次运行它作为一个任务。

以下是输出：

```js
AnotherComponent.vue
    √ Checks that the initial counter value is 0 (3ms)
    √ Adds one when a user clicks the button (4ms)

Test Suites: 1 passed, 1 total
Tests: 2 passed, 2 total
Snapshots: 0 total
Time: 2.307s
Ran all test suites.

Total task duration: 3.64s
```

我们已经成功地在一个测试套件中为 Vue 组件编写了两个单独的单元测试，并且我们的两个测试都通过了。

# 在 Vue CLI 3 中的测试驱动开发

TDD 是基于“红-绿-重构”周期的开发。与我们在前面的代码中看到的类似，我们首先编写我们的代码，使我们的测试失败。接下来，我们编写我们的代码，使我们的测试通过，最后我们重构我们的代码。

对于我们应用程序中的每个新功能，我们重复相同的过程。这本质上就是 TDD。

TDD 只是以一种简化的方式在任何语言或框架中编写任何应用程序。它通过允许我们将整个项目分割成可测试的、清晰分离的功能块来简化我们的工作。

红绿重构方法在项目任务页面的输出中也是清晰可见的。如果我们编写一个失败的测试，我们会看到单词“fail”的背景是红色的。如果我们编写一个通过的测试，我们会看到单词“pass”的背景是绿色的。

在本章的其余部分，我们将通过 Vue CLI 3 的帮助来了解与测试相关的一些其他概念。

# 在 Vue CLI 3 中改进我们的测试

我们可以利用 Jest 和其他测试平台在 Vue CLI 3 中进行更好的测试体验的几种方式。在接下来的章节中，我们将看到以下内容：

+   在 Vue CLI 3 中观察我们的单元测试

+   为我们的任务设置参数

+   使用 Cypress 编写端到端测试

让我们从使用 `--watch` 标志开始。

# 在 Vue CLI 3 中观察我们的测试

`test:unit` 命令带有 `--watch` 标志。要看到它的效果，我们只需要回到 Vue UI 中的项目任务页面，并在选择 `test:unit` 任务后，点击参数按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/2ce2cf08-6d56-4f96-9e0c-967d4a04cd8d.png)

图 4.15：test:unit 任务中的参数按钮

点击参数按钮将触发一个对话框，其中包含以下两个选项：

+   监视文件以进行更改并重新运行与更改文件相关的测试

+   在此测试运行期间重新记录每个失败的快照

点击第一个选项以打开观察模式。接下来的选项将立即出现在其下方：

+   在每次运行后显示通知

这个选项只有在观察模式启用时才可用。让我们也启用每次运行后显示通知选项，并点击保存。

你可以在`package.json`的 scripts 中设置这些选项。第一个选项是`--watch`，显示通知选项是`--notify`标志。

要做到这一点，只需更新项目的`package.json`中的 scripts 键到以下代码：

```js
"scripts": {
  "serve": "vue-cli-service serve",
  "build": "vue-cli-service build",
  "lint": "vue-cli-service lint",
  "test:unit": "vue-cli-service test:unit",
  "test:unit-watch": "vue-cli-service test:unit --watch --notify"
},
```

你会看到你的任务列表现在已经扩展到包括另一个测试任务：`test:unit-watch`。

然而，即使你可以，最好不要这样做。这不是最佳实践，而且这样做有点违背了使用 Vue UI 的初衷。不过，了解到这样可以做的话，我们对 Vue CLI UI 底层发生了更好的理解。

现在，让我们通过向`AnotherComponent.spec.js`文件添加更改来查看观察模式是否正常工作。只需在某个地方添加一个空格并保存更新即可。

# 使用 Cypress 编写端到端测试

端到端测试是一种测试实践，我们在其中从头到尾测试应用程序的流程。通过端到端测试，我们模拟用户从某种入口点流经我们的应用程序到达某种结果的场景。

例如，Web 应用程序的端到端测试可能包括以下流程：

+   用户在浏览器中打开 Web 应用程序的 URL

+   用户点击登录链接并登录

+   用户在 Web 应用程序中检查通知

+   用户登出

# 介绍 Cypress

在本节中，我们将使用 Cypress 进行端到端测试。Cypress 在 Chrome 浏览器中运行良好。或者，如果你想使用基于 Selenium 的工具，你可以在这个网站上查看 Nightwatch.js：[`nightwatchjs.org/.`](http://nightwatchjs.org/)

要了解更多关于 Cypress 的信息，请访问以下网址的官方网站：[`www.cypress.io/`](https://www.cypress.io/)。

如果你访问 Cypress 网站，你会看到它被描述为：

快速、简单、可靠的测试任何在浏览器中运行的东西。

让我们马上开始吧。

# 向我们的项目添加 Cypress 插件

现在让我们在运行 Vue CLI UI 的情况下向我们的项目添加一个 Cypress 插件：

1.  在浏览器中打开以下地址：

`http://localhost:8000/plugins/add`

1.  接下来，在搜索框中输入`cypress`，并找到`@vue/cli-plugin-e2e-cypress`插件。

1.  按照我们之前使用 Jest 插件的方式，按照插件安装步骤进行操作。

1.  一旦我们添加了 Cypress 插件，我们需要提交更改。与 Jest 一样，我们可以只用一个简单的消息提交，比如“添加 Cypress 插件”。

注意，安装 Cypress 会在我们的`tests`文件夹中添加一个名为`e2e`的新文件夹。在`e2e`文件夹中，我们可以找到以下子文件夹：`plugins`，`specs`和`support`。

让我们接着检查`package.json`文件的内容。

# 验证 Cypress 插件安装后对 package.json 的更新

让我们在 VS Code 中检查我们项目的`package.json`。我们会注意到`scripts`选项中有一个新的条目，如下所示：

```js
"test:e2e": "vue-cli-service test:e2e",
```

此外，我们的`devDependencies`已经通过 Cypress 插件进行了更新，我们还可以通过访问 Vue UI 仪表板并检查已安装的插件来看到这一点。

最后，如果我们点击任务图标，我们会看到`test:e2e`任务已添加到我们项目的任务列表底部，与我们在`package.json`文件中看到的完全相同。

如果我们点击`test:e2e`任务，右侧窗格将相应更新，运行任务按钮已准备好点击。点击运行任务按钮将产生以下输出：

```js
$ vue-cli-service test:e2e --mode development
 INFO Starting e2e tests...
 INFO Starting development server...

 DONE Compiled successfully in 1691ms18:06:27

  App running at:
  - Local: http://localhost:8082/
  - Network: http://192.168.1.70:8082/

  Note that the development build is not optimized.
  To create a production build, run npm run build.

It looks like this is your first time using Cypress: 3.2.0

[18:06:28] Verifying Cypress can run C:\Users\W\AppData\Local\Cypress\Cache\3.2.0\Cypress [started]

[18:06:30] Verified Cypress! C:\Users\W\AppData\Local\Cypress\Cache\3.2.0\Cypress [title changed]

[18:06:30] Verified Cypress! C:\Users\WAppData\Local\Cypress\Cache\3.2.0\Cypress [completed]

Opening Cypress...
```

一个新的由 Electron 驱动的窗口将在我们的计算机上打开。使用 Cypress 很容易。正如“帮助您入门……”窗口所告诉我们的那样，您可以在`examples`文件夹中运行测试，或者将您自己的测试文件添加到`cypress/integration`中。

如果您看一下 Cypress 窗口右上角，您会看到“运行所有规范”按钮。默认情况下，它将在 Chrome 中运行（指定版本号）。如果您点击下拉菜单，选择 Chrome，您可以切换到 Electron。无论您选择哪个选项，您的测试都将在一个新窗口中运行，无论是一个新的 Chrome 窗口还是一个新的 Electron 窗口。

此时，我们的端到端 Cypress 测试将失败，因为 Cypress 试图在默认的 Vue 脚手架项目上运行测试，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/971f01f8-35ae-4c62-8801-adb5dd518409.png)

图 4.16：Cypress 中的一个失败测试

如果您希望从一开始就看到这些测试通过，您需要创建一个全新的项目，并在配置中设置 Cypress`e2e`测试。我们将在本书的后面看看这些不同的选项。现在，让我们更新我们的测试，使它们通过。

# 更新我们 Vue 应用中的 Cypress 测试

回到 VS Code，在`./tests/e2e/specs/`文件夹中打开`test.js`文件。您会看到一个带有两个参数的`describe`函数。

要更好地理解 Cypress 术语，请参考以下网址：

[`docs.cypress.io/guides/core-concepts/writing-and-organizing-tests.html#Support-file`](https://docs.cypress.io/guides/core-concepts/writing-and-organizing-tests.html#Support-file)，以及

[`docs.cypress.io/guides/references/bundled-tools.html#Mocha.`](https://docs.cypress.io/guides/references/bundled-tools.html#Mocha)

在 Jest 中，我们看到`test`这个词作为单元测试函数的名称，而在 Cypress 中，我们看到使用`it`这个词。`cy`对象是实际的 Cypress 测试运行器。让我们看一下`test.js`文件的以下更新代码，并解释它是如何以及为什么工作的：

```js
describe('My First Test', () => {
  it('Visits the app root url', () => {
    cy.visit('/')
    cy.contains('article', 'Our own custom article component!')
  })
})
```

这次我们的测试通过了。请注意，我们只需要在 VS Code 中保存更新后的测试文件，测试就会自动运行。您可以转到`http://localhost:8000/tasks/`，并单击`test:e2e`任务以获取有关正在运行的任务的更多信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/eb9f0ea0-0c56-4be6-b23e-a2b9d57488f2.png)

图 4.17：我们 Vue 应用程序主页的 Cypress 测试通过的屏幕截图

另外请注意，如果你在测试结果上悬停在“CONTAINS”部分，那么服务的 Vue 应用程序的适当部分将被突出显示，这是一个关于我们正在测试的 Vue 应用程序的确切部分的美妙视觉提示。

# Summary

在本章中，我们通过 Vue CLI 3 的视角讨论了许多与测试相关的主题。TDD 是一种很棒的技术，应该被团队和个人广泛利用，而 Vue CLI 3、它的 UI 和 Jest 是优化这一过程的绝佳选择。与 Vue CLI 3 的其他方面一样，很多的管道工作都对我们隐藏起来，这使得编码体验非常棒。

在下一章中，我们将研究 Vue CLI 3 中的路由。


# 第五章：Vue CLI 3 和路由

在上一章中，我们看到了如何在 Vue 中使用一些测试套件，比如 Jest 和 Cypress。在本章中，我们将看看如何使用 vue-router，并将其与 Vue CLI 3 一起使用。我们将看一些实际任务，比如懒加载组件。我们将看看使用 Vue add 命令添加 vue-router 的原因以及如何减轻其影响的步骤。如果您想构建更大更复杂的应用程序，了解 Vue 中的路由是有益的。本章涵盖的主题如下：

+   使用 vue-router 和 vuex 添加一个新的 Vue 项目

+   通过 VS Code 的命令行配置预设选项

+   理解 vue-router 路由

+   使用命名路由

+   添加动态路由

+   从 Vue 实例的方法选项导航到一个路由

+   使用嵌套（子）路由

+   懒加载路由

我们将从添加一个新项目开始。

# 使用 vue-router 和 vuex 添加一个新的 Vue 项目

让我们从在文件系统中创建一个新文件夹开始。让我们把这个文件夹叫做`vueclichapter5`。

1.  从 Windows 资源管理器中打开`vueclichapter5`文件夹，在`vueclichapter5`文件夹内的空白处右键单击，然后单击“Git Bash here”命令。

1.  一旦 Git Bash 打开，输入`code .`并按*Enter*键。这将打开一个全新的 VS Code 实例，除了欢迎标签之外，没有其他文件或选项卡。

1.  接下来，我们将直接从 VS Code 的集成终端中添加一个新的 Vue 项目。要访问这个终端，点击 VS Code 窗口（使其获得焦点），然后按以下快捷键：*Ctrl* + *`*。

我们之前已经提到了***Ctrl*反引号快捷键**。作为提醒，*`*字符可以在键盘上按下*Tab*键上方的键时找到。

使用*Ctrl* + *`*键盘快捷键将在 VS Code 中打开终端。

1.  接下来，我们将运行`vue create`命令，后面跟着一个点，如下所示：

```js
vue create .
```

这样做将在现有文件夹中生成一个 Vue 项目，也就是说，它不会为我们的新 Vue 项目创建一个子文件夹，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/a8a439f6-4869-42f5-96f3-0939caa5afee.png)

图 5.1：从 VS Code 的终端在当前目录中生成项目

1.  按下*Y*键确认我们将在当前目录中生成我们的项目。

# 通过 VS Code 的命令行配置预设选项

接下来，我们将通过按一次向下箭头键，然后按*Enter*键来选择手动选择功能选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/2bfff656-09c8-4bd2-9eda-27f1c7ade9ff.png)

图 5.2：从 VS Code 的终端在当前目录生成一个项目

# 添加 vue-router 和 vuex

接下来，我们将使用向下箭头键和空格键来选择 Router 和 Vuex 作为我们项目中的附加功能，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/7be8a39d-e27e-4633-9983-18e2ca398eb6.png)

图 5.3：向我们的项目添加 vue-router 和 vuex 插件

一个提示会询问我们是否要为路由使用历史模式。

我们现在不想使用它，所以我们只需输入`n`并按*Enter*。

在本章的后面，我们将讨论历史模式的作用和工作原理。

# 添加 ESLint 和 Prettier

另一个提示询问我们关于我们的代码检查器或格式化程序的偏好。我们将使用 ESLint 和 Prettier，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/29763fc3-ed26-4ecf-893b-d55e05221821.png)

图 5.4：选择 ESLint 和 Prettier 作为我们的代码检查器/格式化程序配置

# 完成配置

最后，我们将接受默认的保存时 Lint 功能，并选择将 Babel、PostCSS、ESLint 等配置放在专门的配置文件中，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/93cc85fa-70b7-44ca-916c-597ff4a53ac6.png)

图 5.5：选择将配置保存在专门的配置文件中

最后，Vue CLI 会询问我们是否要将此设置为将来项目的预设。目前我们会选择不保存。

# 为我们的新项目安装所有插件

最后，Vue CLI 会安装所有插件，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/24449c9c-85df-4486-a99b-3c20096f7935.png)

图 5.6：Vue CLI 正在安装我们项目的插件

安装完成后，我们将拥有一个已安装 vue-router 和 vuex、ESLint 和 Prettier 设置好并准备使用的 Vue 项目。

# 通过 Vue CLI UI 为我们的项目提供服务

项目安装完成后，我们可以使用`npm run serve`命令来运行它。但是，我们将使用 Vue CLI UI 来运行它，所以让我们按照以下步骤使用`vue ui`：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/01b17519-548d-468e-a5c2-ca0da636f35d.png)

图 5.7：通过 vue UI 命令从 VS Code 命令行中为我们的项目提供服务

正如预期的那样，我们的 Vue CLI UI 将自动在浏览器窗口中打开，网址为`http://localhost:8000/dashboard`。此时，旧项目可能会加载在仪表板中，所以我们需要点击主页图标并导入我们的新`vueclichapter5`项目。

请注意，我们本来可以从一开始就使用 Vue CLI UI 安装新应用，但有趣的是，您可以在命令行和 UI 之间切换而不会出现问题。

项目加载完成后，我们可以点击插件链接以查看已安装的插件。请注意，缺少`Add vue-router`和`Add vuex`按钮。它们不存在，因为我们已经安装了它们。

# 从 UI 中运行 serve 任务

最后，我们将点击任务图标以打开可用任务列表，然后点击 serve 任务以编译和提供我们的项目。就像以前一样，运行任务面板将出现在仪表板的右侧，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/48f3aaff-94ae-4b60-9406-436adceb33a0.png)

图 5.8：运行 npm run serve 脚本的任务

在上面的截图中，我们可以看到 serve 任务屏幕的放大部分。点击运行任务按钮将开始构建应用程序，并且我们将在 Windows 开始栏上收到通知，我们的应用程序已成功构建。查看可用的选项卡，我们可以看到当前视图显示了我们 serve 任务的仪表板。点击当前活动的 serve 任务仪表板按钮左侧的输出按钮将显示日志信息，如下所示：

```js
  App running at:
  - Local: http://localhost:8082/
  - Network: http://192.168.1.70:8082/

  Note that the development build is not optimized.
  To create a production build, run npm run build.
```

当然，`vue-cli-service`将为我们的 Vue 应用提供服务的特定端口将取决于其他已经在使用的端口。现在，要在浏览器中打开我们正在运行的 Vue 应用，只需点击输出日志中列出的`Local`或`Network`URL 之一即可。

# 在 vue-router 中使用路由

在接下来的部分中，我们将研究 vue-router 中的路由工作原理，以及如何使用它们添加页面和路由。我们将从检查现有路由开始，然后添加额外的路由和它们对应的组件。

# 检查两个默认路由

这将打开一个带有 Vue 标志的熟悉的起始项目，稍作添加：顶部有一个链接指向关于页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/d35aaef5-d3a5-41e4-9077-a0c1385cb1fe.png)

图 5.9：安装了 vue-router 的项目的默认导航

如果您点击关于链接，您将看到另一个页面，其中有一个`h1`标签，里面是以下文本：

```js
This is an about page
```

请注意，关于页面的路由在页面名称前面有一个井号。在我们的示例应用程序中，它看起来像这样：`http://localhost:8082/#/about.`我们如何去掉井号？换句话说，我们如何将地址设置为`http://localhost:8082/about`？

答案很简单，我们只需要设置我们的服务器始终返回`index.html`页面，然后我们将添加另一个设置，即 vue-router 的`mode`设置，如下所示：`mode: 'history'`

您需要在`router.js`中的`export default new Router({`行下面添加上述代码。这样做将去掉井号。

接下来，我们将检查预安装了 vue-router 和 vuex 的项目的内容。

# 检查项目文件

返回 VS Code 并查看项目结构。您会看到与以前不同的一些差异。以下是我们`src`文件夹的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/9a64b06c-5bcf-4935-8626-096f4a5c7c4b.png)

图 5.10：带有预安装的 vue-router 和 vuex 的 src 文件夹的内容

在`src`文件夹中，我们可以看到一个以前没有见过的文件夹：`views`文件夹，其中包含两个视图文件：`Home.vue`和`About.vue`。在我们项目的根目录中，我们还可以看到一些额外的文件：`router.js`、`store.js`、`.browserslistrc`、`eslintrc.js`、`postcss.config.js`和`README.md`。

`router.js`文件是 vue-router 用来设置应用程序中路径的文件。`routes`数组是一组对象：一个对象对应一个路由。由于默认安装中有两个路由，所以`routes`数组中有两个对象。`store.js`文件是 vuex 用来跟踪我们应用程序的状态、mutations 和 actions 的文件；这些都被称为**vuex store**。`README.md`文件列出了与我们的应用程序一起使用的常见 npm 命令，我们项目根目录中的其他文件都是配置文件；在我们通过 Vue CLI 3 的旅程中的这一点上，这应该是可以预期的。

# main.js 的内容

就像我们以前看到的那样，`src`文件夹中的`main.js`文件导入了所有以下依赖项：

+   来自`node_modules`的 Vue 库

+   根组件`App.vue`

+   设置 vue-router 路由的路由器文件

+   设置 vuex store 的 store 文件

# App.vue 文件和 router-link 导航

通过检查根组件`App.vue`的内容，我们可以看到该文件与以前不同：没有`script`部分！

此外，`App.vue`内的模板标签包含所谓的*导航组件*。每个导航项都包含在`router-link`标签内。

为什么不只使用锚标签而不是`router-link`标签？因为锚标签会继续发送服务器请求。使用`router-link`标签可以避免这种行为。

如果我们检查`dist`文件夹中编译的 HTML 代码，我们将看到捆绑的 HTML 确实最终成为一个锚标签，如下所示在编译的生产代码中所见：

```js
<div id="nav">
    <a href="#/" class="router-link-active">Home</a> |
    <a href="#/about" class="router-link-exact-active router-link-active">About</a>
</div>
```

回到`view`文件夹内的`Home.vue`和`About.vue`文件，我们还可以看到`router-view`标签（在具有`id`为`nav`的`div`下方）。这实际上是渲染`Home view`或`About view`的地方。将要渲染的组件将由与`to`属性映射的内容确定。

# 渲染 Vue 实例并将其挂载到`#app`

最后，调用一个 Vue 的新实例，并传递一个选项对象作为参数。该对象接收以下键值对：`router: router`、`store: store`和`render: h => h(App)`。

用 ES5 代码编写，该代码看起来如下：

```js
new Vue({
    router: router,
    store: store,
    render: function render(h) {
        return h(App);
    }
}).$mount("#app");
```

我们的`main.js`文件幸运地采用了更现代的语法，因此当所有这些东西放在一起时，它看起来如下：

```js
import Vue from "vue";
import App from "./App.vue";
import router from "./router";
import store from "./store";

Vue.config.productionTip = false;

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount("#app");
```

渲染方法将获取我们应用程序的所有不同部分，将它们组合在一起，并准备好挂载。最后，我们的 Vue 应用程序将被挂载到`./public/index.html`中具有`id`为 app 的`div`内。

您可能会注意到我们当前应用程序的目录中没有`dist`文件夹。正如我们在第二章*中学到的，Vue CLI 3 中的 Webpack*，`dist`文件夹是 webpack 构建我们网站的产物。因此，让我们接下来在 Vue CLI 3 UI 中运行构建任务，以查看`dist`文件夹被创建和提供。

# 从 UI 中运行构建任务

要从 Vue CLI 3 UI 中运行构建任务，我们只需要转到`http://localhost:8000/tasks/`，然后点击`构建任务`，然后点击`运行任务`按钮。

我们运行的构建任务的输出选项卡将记录以下信息：

```js
  File Size Gzipped

  dist\js\chunk-vendors.1030118d.js 116.48 KiB 40.51 KiB
  dist\js\app.51b1d496.js 5.97 KiB 2.23 KiB
  dist\js\about.d288b4f1.js 0.44 KiB 0.31 KiB
  dist\css\app.08e7a232.css 0.42 KiB 0.26 KiB

  Images and other types of assets omitted.

 DONE Build complete. The dist directory is ready to be deployed.
 INFO Check out deployment instructions at https://cli.vuejs.org/guide/deployment.html
```

`./dist/js/`文件夹中的这些不同的 JavaScript 文件是什么？它们是 webpack 将我们的 Vue 应用程序的单文件组件、路由和存储打包成部署准备的捆绑包的结果。这些捆绑包现在已添加到编译和缩小的`index.html`页面中，位于我们的`dist`文件夹内，因此这就是它们最终出现在我们的生产就绪网页上的方式。

最后，让我们看看我们更新后的应用程序。为此，我们将单击 serve 任务，并通过单击停止任务按钮来停止任务。

# 从 UI 中以生产模式提供应用程序

要以生产模式提供应用程序，我们需要单击 serve 任务选定的 Run 任务面板内的参数按钮。

一旦单击参数按钮，我们将看到以下对话框：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/03355705-9e7e-4f7f-b307-7b7ac114a4a5.png)

图 5.11：在 Vue CLI 3 UI 中 serve 任务的参数对话框中指定 env 模式

在指定 env 模式设置中，单击下拉菜单，然后选择生产模式。保存更改，然后您将再次看到 serve 任务仪表板。现在，单击运行任务按钮。最后，为了确保一切仍然正常工作，请将浏览器指向 Vue 应用程序正在提供的任何端口。在本例中，正确的地址是`http://localhost:8082/`。接下来，单击关于链接。

回到 VS Code，将`About.vue`页面的`h1`标签更改为以下内容：

```js
<h1>This is an about page. HMR rocks!</h1>
```

保存文件并查看您的关于页面是否获得了 HMR 更新。

# 一些处理路由的基础知识

尽管本书是关于 Vue CLI 3 的，但我们将利用这个机会快速列出一些 vue-router 的特性。这绝不是一个详尽的列表：它只是对您需要了解的某些特性的快速概述：

+   使用命名路由

+   添加动态路由

+   从 Vue 实例中的方法选项导航到路由

+   使用嵌套（子）路由

+   延迟加载路由

我们将从理解`router-view`标签需要嵌套开始。

# router-view 标签需要嵌套

在我们开始之前，让我们看一下`App.vue`模板标签，如下所示：

```js
<template>
  <div id="app">
    <div id="nav">
      <router-link to="/">Home</router-link> |
      <router-link :to="{ name: 'about' }">About</router-link> | 
      <router-link :to="{ name: 'cars' }">Cars</router-link>
    </div>
    <router-view />
  </div>
</template>
```

请注意，`router-view`元素（从底部数第三行）被包裹在父`div`标签内，然后再包裹在`template`标签内。这很重要，因为您不能将`router-view`标签直接放在`template`标签的子级。换句话说，以下是不可能的：

```js
<template>
    <router-view />
</template>
```

现在我们知道这种方法行不通，我们可以继续讨论命名路由。

# 使用命名路由

要使用命名路由，只需将对象传递给`router-link`标签中的`to`属性，如下所示：

```js
<router-link :to="{ name: 'about' }">About</router-link>
```

注意`to`属性前面的`:`。每当我们想要添加命名路由时，都会添加这个`:`。

在传递给`to`属性的对象中使用`name`键，vue-router 将检查`router.js`中的`routes`数组。它将查找具有指定值的 name 键的对象，如果找到，它将重新路由到特定的视图组件。

# 通过触发 Vue 实例的方法导航到路由

Vue 中的每个组件都是一个独立的 Vue 实例。我们将在`HelloWorld.vue`组件中工作。要从`HelloWorld.vue`的`methods`选项中导航到路由，可以在组件的`scripts`部分中使用以下代码：

```js
methods: {
 goToAboutPage(){ 
 this.$router.push({path: '/About'}) 
 },
}
```

为了使其工作，我们需要添加一个`v-*`指令来确定何时触发具有上述代码的方法。因此，在`HelloWorld.vue`中，仍然在`template`标签中更新为以下内容：

```js
<template>
 <!-- code skipped for brevity -->
 <p v-on:mouseover="goToAboutPage" 
    style="color: red; font-size: 50px; background: gray; max-width: 500px; margin: 0 auto">
    Hover to see the About Page
 </p>
 <!-- code skipped for brevity -->
</template>
```

显然，上述`template`标签是不完整的。我们关注重要部分：文本颜色为红色，字体大小为`50`像素的`p`标签。你不能在屏幕上错过它！你可以在`vuecli3chapter5/HelloWorld.vue`中的第 4 行找到这行代码。

当你悬停在上面的段落时，Vue 会立即带你到关于页面。

现在让我们将主页上的相同功能添加到关于页面。因此，一旦你在关于页面上，你可以悬停在显眼的悬停上看到主页链接，它会带你回到主页。

为了使事情不那么跳跃，我们还可以使用老式的纯浏览器外观函数：`setTimeout`。以下是`About.vue`文件的更新代码：

```js
<template>
  <div class="about">
    <h1>This is an about page. HMR rocks!</h1>
    <p v-on:mouseover="goToHomePageSlowly" class="go">Hover to see the Home Page</p>
  </div>
</template>
<script>
export default {
  name: "About",
  props: {
    msg: String
  },
  methods: {
      goToHomePage(){ 
        this.$router.push({path: '/'}) 
      },
      goToHomePageSlowly(){
        setTimeout(() => this.goToHomePage(), 1000);
      }
  }
};
</script>
<style>
.go {
  color: purple; 
  font-size: 50px; 
  cursor: pointer;
  max-width: 500px;
  margin: 0 auto;
  background: #fabdab;
}
</style>
```

在上述代码中我们在`methods`选项中简单地添加了另一个方法。我们给这个新方法命名为`goToHomePageSlowly`。然后，在我们的 about 组件的模板标签中调用这个方法。

`goToHomePagesSlowly`使用`setTimeout`外观函数来实现浏览器的`setTimeout`功能。`setTimeout`函数以`1000`毫秒的延迟调用我们的`goToHomePage`函数，一旦运行，它将使用`$router`返回到主页。

接下来，我们将讨论嵌套路由。

# 使用嵌套路由

在开始使用嵌套路由之前，我们将在`src/views`文件夹中添加 Cars 组件，如下所示：

```js
<template>
  <div class="home">
    <HelloCars msg="Welcome to Your Cars" />
    <router-view></router-view>
  </div>
</template>

<script>
// @ is an alias to /src
import HelloCars from "@/components/HelloCars.vue";

export default {
  name: "cars",
  components: {
    HelloCars
  }
};
</script>
```

要使用嵌套路由，您需要在`router.js`中的`path`对象中添加一个`children`数组，如下例所示：

```js
routes: [
    {...},
    {...},
    {
      path: "/cars",
      name: "cars",
      component: Cars, 
      children: [
          { path: '/cars', component: CarsHome },
          { path: '/cars/cars-new', component: CarsNew },
          { path: '/cars/cars-used', component: CarsOld }
      ]
    }
]
```

每个子组件也需要路由。由于它们是嵌套路由，它们需要从各自的父组件中调用。在我们的情况下，这是`HelloCars`组件。我们将使用以下代码将`HelloCars.vue`组件添加到`components`文件夹中：

```js
<template>
 <div class="hello">
 <h1>{{ msg }}</h1>
 </div>
</template>

<script>
export default {
 name: "HelloCars",
 props: {
 msg: String
 }
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
* {
 margin: 0 auto;
}
</style>
```

现在我们只需要添加额外的子组件，我们的父组件`HelloCars.vue`将调用。

从`/cars`路由可用的默认子组件是`CarsHome.vue`组件，如下所示：

```js
<template>
  <div class="home">
    <div>
        This is Cars home
        <ul>
            <li><router-link to="/cars/cars-new">See new cars</router-link></li>
            <li><router-link to="/cars/cars-used">See old cars</router-link></li>
        </ul>
    </div>
  </div>
</template>

<style>
ul li { list-style-type: none }
</style>
```

如前所述，`HelloCars.vue`组件的一个子组件是`CarsNew.vue`组件，如下所示：

```js
<template>
  <div>
    <div>
        This is Cars New
        <ul>
            <li><router-link to="/cars">Back to cars home</router-link></li>
        </ul> 
    </div>
  </div>
</template>
```

`HelloCars.vue`组件的另一个子组件是`CarsOld.vue`，如下所示：

```js
<template>
  <div>
    <div>
        This is Cars Old
        <ul>
            <li><router-link to="/cars">Back to cars home</router-link></li>
        </ul> 
    </div>
  </div>
</template>
```

现在我们了解了嵌套路由的工作原理，我们将转移焦点，简要讨论懒加载路由。

# 懒加载路由

有时，webpack 生成的 JavaScript 包太大。这会减慢我们的 Web 应用程序加载时间，这当然是不可取的。

为了避免这种情况，我们可以回想一下 vue-router 的工作原理：每个路由都是一个单独的 Vue 组件。

我们已经在前面看到，webpack 在捆绑我们的 Vue 应用程序时会生成**块**。这种行为可以用于我们的优势，使每个组件都捆绑到一个单独的块中。这是通过 Vue 的**异步组件**和 webpack 中的**代码拆分**实现的。

# 使用动态路由

什么是动态路由？让我们想象一个购物平台，在其中任何待售物品的 URL 结构都列在一个链接中，看起来像这样：

```js
https://example.com/items/:id
```

`:id`部分是所谓的**动态段**。要使用动态段，您首先需要像任何其他路由一样在`router.js`中的路由对象数组中列出它们，如下所示：

```js
routes: [
    {...},
    {...},
    {
        path: "/item/:id",
        name: "item",
        component: Item
    }
]
```

显然，在上述代码中，我们使用三个点来节省空间。

回到`Item.vue`视图组件的模板标签中，我们需要添加以下语法：

```js
<template>
    <article>
        <h1>Shopping item: {{ $route.params.id }}</h1>
    </article>
</template>
```

我们活跃路由的状态存储在`$route`中。

至少可以单独撰写一整章关于动态路由，所以此时，我们需要继续讨论如何从 Vue 实例的`methods`选项中触发路由。

通过这个，我们结束了这一章。

# 总结

在这一章中，我们看了如何使用 vue-router 和 vuex 添加一个新的 Vue 项目。我们还通过 VS Code 的命令行配置了预设选项。我们讨论了 vue-router 的路由，并且学习了如何使用命名路由，添加动态路由，从 Vue 实例的方法选项导航到一个路由，并且处理嵌套（子）路由。

在下一章中，我们将看到如何在 Vue CLI 3 中使用 ESLint 和 Prettier。


# 第六章：在 Vue CLI 3 中使用 ESLint 和 Prettier

在本章中，我们将学习 ESLint 的用处，并看看如何使用它对我们的代码进行 lint。我们还将讨论不同的风格指南：标准、Airbnb 和 Google。具体来说，我们将看以下主题：

+   ESLint 是什么，以及如何单独配置它

+   本地安装 npm 包和全局安装 npm 包之间的区别

+   本地安装 ESLint 并使用 npx 运行它

+   在 Vue CLI 3 中使用 ESLint

+   使用 Vue CLI 3 UI 配置 ESLint

我们将首先看一下 ESLint 是什么，以及如何将其配置为一个独立的`npm`包。

# ESLint 是什么，以及如何单独配置它

在本章中，我们将讨论 ESLint 的作用。ESLint 与代码质量有关。当你在一个团队中工作时，每个团队成员都会带来自己对于如何编写 JavaScript 的最佳方式的小怪癖和想法。即使你的团队对特定的编码风格和如何编写代码有明确的规则，你如何保证每个团队成员都遵守规则？你如何确保他们提供一致的代码质量？毕竟，我们都是人类，这意味着我们都有那些我们尽力了，但简单地忘记了要注意的小事情的日子。

在足够长的时间内，我们的团队将开始产生风格不一致的代码。接下来会发生的事情是，团队中的每个人开始将 JavaScript 风格指南视为*建议*，而不是你应该*真正遵守*的东西。

幸运的是，有一些工具可以让我们自动改善代码的外观，并在不遵循规定的做事方式时对其进行格式化。ESLint 就是这样一个工具的例子。

基本上，ESLint 是让你把*制表符与空格*等类似辩论外包给一款软件的方式，这款软件将以一种流畅、一致的方式处理这些问题。

在本章中，我们还将简要提到全局和本地 node 模块之间的区别，即全局安装`npm`包和本地安装之间的区别。

# 全局安装 npm 包与本地安装 npm 包的区别

这是一个全局安装的例子：

```js
npm install eslint -g --verbose
```

这是一个本地安装的例子：

```js
npm install eslint --save-dev --verbose
```

那么，有什么区别呢？

全局包安装在计算机的一个特定位置。无论您在安装它们时所在的文件夹是什么，*它们都不会保存在该文件夹内*，并且在命令行中全局可用。因此，如果我们想要从命令行运行一个包，全局安装是一种方法。

您可以从命令行程序中运行`npm install`命令。命令行程序将始终从一个目录内运行。使用诸如`cd ..`来在您的操作系统文件系统中返回上一级目录，或者`cd <directory-name>`来进入一个目录，您可以选择在安装`npm`包时希望您的命令行程序所在的文件夹。

将`npm`包本地安装意味着该包保存在当前命令行程序指向的目录内。当运行`npm install`命令时，您正在安装的新包将保存在您所在的当前目录的`node_modules`目录中。如果`node_modules`目录不存在，当运行`npm install`命令时，它将被添加*在当前目录内*。

使用全局模块的缺点是版本问题。对于本地模块，您计算机上的每个不同目录和每个不同应用程序都有自己的模块版本。然而，如果您有一个全局包，并决定更新它，全局安装的模块的更新版本可能会因为与特定目录中特定应用程序中其余代码的兼容性问题而破坏您的应用程序。

作为一个经验法则，应该将`npm`包安装在本地，因为可以避免版本问题。

要了解更多关于本地安装`npm`包的信息，请访问此网页：

[`docs.npmjs.com/downloading-and-installing-packages-locally.`](https://docs.npmjs.com/downloading-and-installing-packages-locally)

使用本地安装的包的一个缺点是，特定命令，如`prettier`、`webpack`或`eslint`，不会在命令行上可用。相反，您需要将本地安装的节点模块作为 npm 脚本运行。

或者，这个本地安装的模块实际上可以直接在命令行上运行，使用`npx`命令，我们将在下一节中讨论。

# 什么是 Prettier？

Prettier 是一个代码格式化工具。它会在你保存文件时格式化你的代码。该项目网站可以在[`prettier.io/`](https://prettier.io/)找到。在接下来的示例中，我们将运行一个本地安装的 Prettier npm 模块。

# 使用 npx 在命令行上运行本地安装的 npm 模块

要开始使用 Prettier，我们将按照以下步骤启动一个新项目：

```js
mkdir Chapter6 && cd $_
```

接下来，在新的`Chapter6`文件夹中，我们将添加另一个文件夹`prettier-practice`，如下所示：

```js
mkdir prettier-practice && cd $_
```

接下来，我们将使用默认值初始化`npm`如下：

```js
npm init -y
```

接下来，让我们添加一个单独的文件`index.html`，如下所示：

```js
touch index.html && code .
```

上面的命令创建并打开了一个新的`index.html`文件在 VS Code 中。

我们将添加一个没有任何构建过程的小型 Vue 应用程序。让我们将以下代码添加到我们的`index.html`文件中：

```js
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>101 - using watchers in Vue</title>
    <style>
        body,
        input {
            font-family: Arial, sans-serif;
            font-size: 20px;
        }
    </style>
</head>

<body>
    <div id="example">
        <p>Enter owner name and the thing that is owned:
            <input v-model="ownerName" placeholder="enter owner">
            <input v-model="thing" placeholder="enter thing">
        </p>
        <span>{{ ownerName }}</span>
        <span> has a </span>
        <span>{{ thing }}</span>
    </div>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.10/vue.min.js'></script>
    <script>
        var example = new Vue({
            el: '#example',
            data: {
                ownerName: 'e.g Old McDonald',
                thing: 'e.g cow'
            },
            watch: {
                ownerName(currentValue, previousValue) {
console.log(`The value in the first input has changed from: ${previousValue} to: ${currentValue}`);
                }
            },
            computed: {
                // a computed getter
                ownerHasThing: function () {
                    // `this` points to the Vue instance's data option
                    return this.ownerName + " " + this.thing
                }
            }
        })
    </script>
</body>

</html>
```

你可以在 CodePen 上看到这个简单的 Vue 应用程序运行，网址是：[`codepen.io/AjdinImsirovic/pen/jprwKe.`](https://codepen.io/AjdinImsirovic/pen/jprwKe)

接下来，让我们添加 Prettier 来看它如何格式化我们的代码。

# 全局安装 Prettier 并在 index.html 上运行

要全局安装 Prettier，我们可以使用以下命令：

```js
npm install prettier -g --loglevel verbose
```

然后，要开始使用它，你可以运行`--help`标志来查看所有可用的选项，比如以下内容：

```js
prettier --help
```

现在，你可以运行`prettier index.html`命令来在控制台中查看格式化后的代码。或者，你可以运行命令`prettier index.html --write`，这样格式化后的输出实际上会保存在你指定的文件中。

接下来，我们将看看如何在本地安装 Prettier 并使用 npx 运行它。

# 使用 npx 运行 Prettier

npx 实用程序是一个**NPM 包运行器**。它在 2017 年的 5.2.0 版本中被添加到 NPM 中。它使得从`node_modules`目录中运行包变得更容易，因为我们不必像之前在`package.json`中那样依赖于`npm run <someScriptName>`。

在这个示例中，我们将看到如何将 Prettier 安装为开发依赖项，并如何使用 npx 运行它。首先，我们需要在我们的`prettier-practice`文件夹中使用`--save-dev`标志安装它，如下所示：

```js
npm install prettier --save-dev --verbose
```

完成后，我们的`package.json`将会被更新，然后我们可以开始使用 Prettier。

最简单的方法就是在 VS Code 的终端中简单地运行 Prettier 命令。

要查看可用的选项，我们可以运行以下命令：

```js
npx prettier
```

要实际运行带有一些选项的命令，我们可以运行这段代码：

```js
npx prettier --single-quote --trailing-coma es5 --write "index.html" --verbose
```

npx 还有许多其他用法，这是一个值得熟悉的好工具。

另一个有趣的练习是比较 Prettier 的格式化和 VS Code 自带的格式化工具。使用*Shift* + *Alt* + *F*组合键可以触发 VS Code 的格式化工具。我们可以在 VS Code 的控制台中按上箭头键，快速重新运行刚刚运行的`npx prettier`命令。

接下来，我们将创建另一个小项目来演示如何使用 ESLint。

# 使用 ESLint

ESLint 是一个 JavaScript 的代码检查工具。你可以在[`eslint.org/`](https://eslint.org/)找到它。代码检查工具会对你的代码进行分析，将其与特定的标准进行比较。你可以说它是一个检查代码质量的工具。代码检查工具非常适合团队环境，因为它们可以让我们的代码遵循特定的代码风格，并且确保在代码审查过程中少了一件需要讨论的事情。

代码风格的示例可以在这里找到：[`github.com/airbnb/javascript`](https://github.com/airbnb/javascript)。这是 Airbnb 的 JavaScript 代码风格指南。如果你在页面上滚动，你会发现有很多需要阅读的信息：如何访问原始类型，如何重新分配引用，如何在对象声明中分组简写属性等等。

重要的是要理解 ESLint 只是分析你的代码；它不运行它。但是，它可以找到错误，并且也可以修复它们。实际上，如果设置正确，它可以改变你的代码。

还有其他一些 JavaScript 代码检查工具，比如 JSLint 或 JSHint。ESLint 被宣传为更加可定制的工具。

# 全局安装 ESLint 并在命令行中运行失败

要全局安装 ESLint 节点模块，请运行以下命令：

```js
npm install eslint -g --loglevel verbose
```

现在，我们的`eslint`命令是全局可用的。

现在，我们将创建一个新的文件夹，`eslint-practice`。在其中，我们将创建一个新文件，`eslint-test.js`。

在 VS Code 中打开文件并添加以下代码：

```js
function (a) 
{
console.log(a, b);

}
```

保存文件。

接下来，在 VS Code 中使用*Ctrl* + *`*打开命令行，并运行以下命令：

```js
eslint eslint-test.js
```

你将收到的输出是：

```js
Oops! Something went wrong! :(

ESLint: 5.15.3.
ESLint couldn't find a configuration file. To set up a configuration file for this project, please run:

 eslint --init

ESLint looked for configuration files in C:\Users\Warrior Gaming\Desktop\Chapter6 and its ancestors. If it found none, it then looked in your home directory.
```

为什么会发生这种情况？没有 ESLint 配置文件，但为什么 ESLint 需要配置文件才能运行？

这是因为 ESLint 用来检查我们的代码的规则是在**配置**文件中指定的。如果没有配置文件，ESLint 就不知道在检查我们的代码时应用哪些规则。

这个问题的解决方案很有趣。没有`package.json`，我们就无法初始化 ESLint。因为我们必须安装一个新的 NPM 项目，我们可能会选择在本地安装 ESLint 节点模块。这不是必须的，但对于简化的工作流程来说，这是一个首选选项。

# 运行`eslint --init`命令

显然，我们不能在没有 ESLint 配置文件的情况下运行`eslint`命令。然而，我们也不能在没有`package.json`文件的情况下初始化 ESLint 配置文件。这意味着我们首先需要运行`npm init`，所以让我们现在这样做：

```js
npm init -y
```

现在，我们可以初始化`eslint`。当我们运行`eslint --init`命令时，我们将在命令行提示中被问到几个问题。我们选择的答案将取决于我们的 ESLint 配置。以下是我们需要为这个示例选择的选项：

+   选择`To check syntax, find problems, and enforce code style`

+   选择`None of these`

+   选择`None of these`（对于这个简单的演示，我们不会使用`Vue.js`，因为那将需要安装额外的依赖项，而在这一点上我们只是在测试 ESLint）

+   选择`Browser`

+   选择`Answer questions about your style`

+   选择`JSON`

+   选择`Spaces`

+   选择`Single`

+   选择`Windows`

+   输入*Y*（是的，我们确实需要分号）

+   选择*''*`JavaScript`*''*（作为你想要你的配置文件的格式是什么的答案）

一旦你回答了所有的问题，你将会看到以下输出：

```js
Local ESLint installation not found. 
The config that you've selected requires the following dependencies:
eslint@latest
Successfully created .eslintrc.js file in C:\Users\W\Desktop\Chapter6\eslint-practice
ESLint was installed locally. We recommend using this local copy instead of your globally-installed copy.
```

阅读这条消息，我们现在可以欣赏到 ESLint 的维护者正在引导我们朝着在计算机上限制全局安装的`npm`包的最佳实践，并选择在我们的项目中本地安装我们的 node 模块。前面的消息还提到我们需要`eslint@latest`依赖项才能运行我们的 ESLint 配置，所以让我们立即添加它，如下所示：

```js
npm install eslint@latest --save-dev --verbose
```

在本书中已经提到过，但现在是一个很好的复习时间：`--save-dev`标志意味着我们安装的包只用于开发，而不用于生产。`--save-dev`选项不会设置本地模块。你可以通过简单运行`npm install estlint@latest`来本地安装 ESLint。然而，`--save-dev`和`--verbose`标志都有它们的用处，但需要明确的是它们与本地安装`npm`包没有任何关系。

现在，我们准备在项目的 JavaScript 文件上运行 ESLint。在这样做之前，让我们检查一下`.eslintrc.js`的内容。

# 理解 .eslintrc.js 配置文件的结构

根据我们选择的规则，我们生成的 `.eslintrc.js` 文件如下所示：

```js
module.exports = {
    'env': {
        'browser': true,
        'es6': true
    },
    'extends': 'eslint:recommended',
    'globals': {
        'Atomics': 'readonly',
        'SharedArrayBuffer': 'readonly'
    },
    'parserOptions': {
        'ecmaVersion': 2018
    },
    'rules': {
        'indent': [
            'error',
            4
        ],
        'linebreak-style': [
            'error',
            'windows'
        ],
        'quotes': [
            'error',
            'single'
        ],
        'semi': [
            'error',
            'always'
        ]
    }
};
```

在配置文件中导出的对象内部，我们可以看到环境设置为 `browser`，`es6` 属性设置为 `true`，这意味着 ES6 语法会自动启用。

通过 `'extends': 'eslint:recommended'`，我们打开了推荐的核心规则，报告常见问题。这些规则列在以下页面上：[`eslint.org/docs/rules/`](https://eslint.org/docs/rules/)。

`'globals'` 条目列出了在使用指定配置运行 ESLint 时将访问的其他全局变量。

通过 `parserOptions` 属性，我们将 ECMA Script 版本设置为 `2018`，这当然是 ECMA Script 9。最后，`'rules'` 属性指定要应用的规则，以及**错误级别**。

# 在 JavaScript 文件上运行 ESLint

现在，我们可以在 `eslint-test.js` 文件上运行 `eslint` 命令。由于它是全局安装的，我们可以简单地运行 `eslint eslint-test.js`。

然而，由于这是被模块的维护者们不赞成的，让我们改为使用以下命令在本地运行它：

```js
npx eslint eslint-test.js
```

运行上述命令将产生以下输出：

```js
  1:10 error Parsing error: Unexpected token (

✖ 1 problem (1 error, 0 warnings)
```

我们还可以在 VS Code 中看到错误，作为一个单一字符，即 `(` 字符，在我们的 `eslint-test.js` 文件的第一行下划线标记为波浪红色。当然，这个错误意味着我们缺少函数的名称。所以让我们更新代码为：

```js
function  aFunction(a)  { console.log(a,  b)  }
```

注意，我们还删除了调用 `console.log` 方法后的分号。让我们再次运行 `eslint`。

这一次我们得到了五个新的错误，如下所示：

```js
  1:10 error 'aFunction' is defined but never used no-unused-vars
  3:1 error Expected indentation of 4 spaces but found 0 indent
  3:1 error Unexpected console statement no-console
  3:16 error 'b' is not defined no-undef
  3:18 error Missing semicolon semi

✖ 5 problems (5 errors, 0 warnings)
  2 errors and 0 warnings potentially fixable with the `--fix` option.
```

查看前述输出的每行末尾，我们可以看到我们的代码违反的具体**ESLint 规则**。在每行开头，我们可以看到行号，后跟一个冒号，再跟着违反 ESLint 规则的第一个字符的确切位置。因此，1:10 可以读作 *第 1 行，第 10 个位置的字符*。

让我们再次运行 `eslint`，并使用建议的 `--fix` 标志，如下所示：

```js
npx eslint eslint-test.js --fix
```

现在我们的代码被格式化，如下所示：

```js
function aFunction(a) 
{
    console.log(a, b);

}
```

然而，我们仍然会得到一些错误，如下所示：

```js
  1:10 error 'aFunction' is defined but never used no-unused-vars
  3:5 error Unexpected console statement no-console
  3:20 error 'b' is not defined no-undef

✖ 3 problems (3 errors, 0 warnings)
```

从这个小练习中我们可以得出结论，ESLint 将会执行以下操作：

+   指出我们代码中的规则违反。

+   允许我们传递 `--fix` 标志来纠正那些工具本身可以修复的错误。

接下来，我们将更新错误级别规则。

# 更新 ESLint 中的错误级别规则

默认情况下，所有规则的错误级别都设置为`'error'`。要手动设置不同的错误级别，比如`'warn'`，我们可以添加一个`errorLevel`常量，并将我们的规则更新为以下代码：

```js
const errorLevel1 = 'warn';
const errorLevel2 = 'error';
module.exports = {
    // ...
    // omitted this section to save space
    // ...
    'rules': {
        'indent': [
            'error',
            4
        ],
        'linebreak-style': [
            'error',
            'windows'
        ],
        'quotes': [
            'warn',
            'single'
        ],
        'semi': [
            'warn',
            'always'
        ]
    }
};
```

现在，通过这个更新，我们的`linebreak-style`和`indent`规则的错误级别将是`error`，而`quotes`和`semi`规则的错误级别将是`warn`。

接下来，我们将在 Vue CLI 3 中使用 ESLint。

# 在 Vue CLI 3 中配置 ESLint

现在我们已经熟悉了 Prettier 和 ESLint，我们将在 Vue CLI 3 中将它们安装到一个新项目中。让我们将 Git Bash 指向`Chapter6`文件夹的根目录，并运行以下命令：

```js
code .
```

一旦 VS Code 打开，我们将切换到命令行，并运行以下命令：

```js
vue create vc3-prettier-eslint
```

然后，我们将接受使用 Babel 和 ESLint 的默认安装，并等待应用程序安装完成。

接下来，类似于之前的操作，我们将运行`vue ui`，然后将`vc3-eslint`应用程序导入到我们的 Vue CLI 3 GUI 仪表板中。

正如我们所看到的，ESLint 作为 Vue CLI 3 应用的默认安装。但是，我们如何配置 ESLint，就像我们在本章的前一节中所做的那样呢？

# 在 Vue CLI 3 GUI 中设置 ESLint 配置

在 Vue CLI 3 UI 中加载我们的`vc3-eslint`应用程序后，让我们单击配置图标。

我们将单击 ESLint 配置，这将更新项目配置窗口右侧的面板，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/245a02c9-f576-489f-85a7-92884e8507f7.png)

图 6.1：单击配置图标显示应用程序的可能配置

在这个视图中，我们可以看到两个主要条目：保存时进行 Lint 和选择配置。

保存时进行 Lint 选项目前已经切换打开，但我们可以通过单击 Lint on save 选项右侧的绿色开关来切换关闭。

我们还可以在“选择配置”条目中选择不同的配置。默认设置可以更改为“强烈推荐”或“推荐”设置。我们在本章前面看到了如何在`eslintrc.js`文件中配置此设置。

您还可以选择点击页面右上角的“打开 eslintrc”按钮，打开我们项目的 ESLint 配置文件，这样您就可以直接编辑它。

最后，我们可以通过单击配置面板顶部的“规则”选项卡，查看项目中所有 ESLint 规则的列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/ef290a9f-6456-4c95-86dc-8a8eeca3c6e7.png)

图 6.2：在 Vue CLI 3 UI 中选择 ESLint 配置屏幕中的单个规则

屏幕将显示默认应用于我们 ESLint 配置的基本规则，而在“常规”选项卡上，我们可以通过单击“选择配置条目”中的下拉菜单来更改整个规则集；在规则选项卡中，我们可以混合和匹配单个规则，然后保存我们的更新。这样就可以更新规则并根据自己的喜好进行自定义更改。

# 在 Vue CLI 3 UI 项目中同时使用 ESLint 和 Prettier

如果您在 Vue CLI 3 UI 中从头开始一个项目，您也可以让 ESLint 和 Prettier 一起工作。方法如下：

1.  我们首先要将 Vue UI 指向根文件夹，如下所示。重要的是要验证您不在现有的 Vue 应用程序内：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/91292f7b-75fc-4cc6-97a6-c72f82a515ab.png)

图 6.3：在 Vue CLI 3 UI 中创建新项目

1.  接下来，我们将点击“选择此文件夹”按钮继续，然后按照以下方式选择我们项目的名称：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/201b603d-6613-4c65-a305-b32d971b8361.png)

图 6.4：添加项目名称

1.  接下来，我们将点击“选择此文件夹”按钮继续，然后选择我们项目的名称。点击“下一步”继续，您将被带到预设选项卡。

1.  一旦您在预设选项卡上，选择手动预设以手动选择功能，然后再次点击“下一步”。在功能选项卡上，Babel 和代码检查/格式化功能应该已经被预先选择，所以只需再次点击“下一步”进入配置屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/c963b523-75b9-4c53-add7-f5b575ef7274.png)

图 6.5：从配置屏幕中选择 ESLint + Prettier

1.  “选择一个代码检查/格式化配置”给了我们几个选项。在底部选择*ESLint + Prettier*。一旦我们点击它，就会出现一个选项来保存预设，所以让我们按照以下图片保存它：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/82ace185-cda8-4325-93a5-1bd033cf705f.png)

图 6.6：在 Vue CLI 3 UI 中保存新预设

1.  一旦我们点击“创建新预设”按钮，我们就完成了对项目的自定义，然后我们可以等待所有依赖项安装完成。

1.  完成后，您将看到“欢迎使用新项目”的消息。现在，您可以点击左侧菜单上的“项目依赖”链接。除了预期的依赖项（`babel-eslint`，`eslint`，`eslint-plugin-vue`和`vue-template-compiler`）之外，您还会看到`@vue/eslint-config-prettier`开发依赖项。正如我们所看到的，这是一个官方的`vue npm`模块，因为它有`@vue`命名空间。

# 总结

在本章中，我们已经看到了`npm`和`npx`、全局和本地安装节点模块之间的区别。我们进一步讨论了 ESLint 和 Prettier。我们看到了如何在独立项目中安装它们，以及如何在 Vue CLI 3 GUI 中配置 ESLint。我们还看到了如何在 Vue CLI 3 中设置 ESLint 和 Prettier。

在下一章中，我们将探讨在 Vue CLI 3 中使用 CSS、SCSS 和 PostCSS。


# 第七章：使用 SCSS 改进 CSS

在本章中，我们将讨论 SCSS 的基础知识以及它解决的问题。我们还将讨论引入的改进，使 CSS 更接近 SCSS。

我们还将使用我们在第五章中制作的应用程序，Vue CLI 3 和路由*。本章的目标是使用 CSS、SCSS，并通过使用 Bootstrap + Vue 插件来实现这一目标。

本章将涵盖以下主题：

+   安装 Bootstrap + Vue

+   使用 bootstrap-vue 插件为我们的项目添加样式

+   在我们的项目中使用 SCSS

# 安装 Bootstrap + Vue

在使用 Vue 时，为什么不从官方网站使用 Bootstrap？嗯，我们当然可以这样做，但 Bootstrap 依赖于 jQuery，而且由于我们希望将所有与 JavaScript 相关的内容都通过 Vue 运行，因此我们必须使用一个专为此目的构建的项目：BootstrapVue。

让我们从访问项目网站开始[`bootstrap-vue.js.org/`](https://bootstrap-vue.js.org/)。在这里，我们可以对项目有一个大致的了解。具体来说，阅读文档[`bootstrap-vue.js.org/docs#vue-cli-3`](https://bootstrap-vue.js.org/docs#vue-cli-3)将非常有用，该文档讨论了在 Vue CLI 3 项目中使用 BootstrapVue。

# 将 BootstrapVue 添加为插件

您可以通过 Vue CLI 3 UI 的帮助轻松创建一个新的 Vue 项目。这在本书中已经多次介绍过，您应该能够自己完成这个操作。

将您的新项目命名为“第七章”，并按照与第五章相同的安装步骤运行它，Vue CLI 3 和路由*。

在控制台中，转到项目的根目录并运行以下命令：

```js
vue add bootstrap-vue
```

您将在控制台内看到以下提示：

```js
Successfully installed plugin: vue-cli-plugin-bootstrap-vue
```

接下来将跟进以下问题：

```js
? Use babel/polyfill? (Y/n)
```

只需按下*Enter*键接受默认答案（是）。

无论您如何安装插件，您的插件列表现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/6b9ceee8-1410-4b59-bf18-850058b1e58b.png)

既然我们已经安装了它，我们可以开始使用它了。

# 使用 bootstrap-vue 插件为我们的项目添加样式

安装了`bootstrap-vue`插件后，让我们在项目中使用它！我们将从官方文档中添加一个`navbar`，该文档可在[`bootstrap-vue.js.org/docs/components/navbar#b-nav-item-dropdown`](https://bootstrap-vue.js.org/docs/components/navbar#b-nav-item-dropdown)找到，如下所示：

```js
  <b-navbar type="dark" variant="dark">
    <b-navbar-nav>
      <b-nav-item href="#">Home</b-nav-item>

      <!-- Navbar dropdowns -->
      <b-nav-item-dropdown text="Lang" right>
        <b-dropdown-item href="#">EN</b-dropdown-item>
        <b-dropdown-item href="#">ES</b-dropdown-item>
        <b-dropdown-item href="#">RU</b-dropdown-item>
        <b-dropdown-item href="#">FA</b-dropdown-item>
      </b-nav-item-dropdown>

      <b-nav-item-dropdown text="User" right>
        <b-dropdown-item href="#">Account</b-dropdown-item>
        <b-dropdown-item href="#">Settings</b-dropdown-item>
      </b-nav-item-dropdown>
    </b-navbar-nav>
  </b-navbar>
```

我们将在`App.vue`中的模板部分添加这个`navbar`。更新后的`template`元素现在看起来是这样的：

```js
<template>
  <div id="app">
    <div id="nav">

      <b-navbar type="dark" variant="secondary">
        <b-navbar-nav>
          <b-nav-item href="#">Home</b-nav-item>
          <!-- Navbar dropdowns -->
          <b-nav-item-dropdown text="Lang" right>
            <b-dropdown-item href="#">EN</b-dropdown-item>
            <b-dropdown-item href="#">ES</b-dropdown-item>
            <b-dropdown-item href="#">RU</b-dropdown-item>
            <b-dropdown-item href="#">FA</b-dropdown-item>
          </b-nav-item-dropdown>

          <b-nav-item-dropdown text="User" right>
            <b-dropdown-item href="#">Account</b-dropdown-item>
            <b-dropdown-item href="#">Settings</b-dropdown-item>
          </b-nav-item-dropdown>
        </b-navbar-nav>
      </b-navbar>
      <!--
      <router-link to="/">Home</router-link> |
      <router-link to="/about">About</router-link>
      -->
    </div>
    <router-view />
  </div>
</template>
```

我们还需要更新样式，使其看起来像这样：

```js
<style>
#app {
  text-align: center;
  color: #2c3e50;
}

#nav a {
  font-weight: bold;
  color: #2c3e50;
}

#nav a.router-link-exact-active {
  color: #42b983;
}
</style>
```

保存更改后，我们的主页将更新为以下截图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/2e7fc3c8-e6f3-436c-abc8-d803808b6f89.png)

要快速更改`bootstrap-vue navbar`的背景颜色，只需将 Bootstrap 颜色添加到`variant`自定义 HTML 属性中。接受的值为`primary`、`secondary`、`success`、`danger`、`info`、`warning`、`light`和`dark`。

在前面的例子中，我们使用了值为`secondary`的`variant`，这给了我们一个灰色的背景，鼠标悬停时显示白色的`nav`项。

# 在我们的项目中使用 SCSS

类似于 TypeScript 被称为 JavaScript 的*超集*，SCSS 经常被称为 CSS 的*超集*。但这个*超集*到底是什么？

语言的**超集**只是它周围的一个层，具有在*常规*实现中不存在的附加功能。还可能有额外的最佳实践、方法等。

在最核心的层面，SCSS 文件可能只包含普通的 CSS 语法。这是因为所有的 SCSS 最终都会编译成 CSS，并且作为这样，它会被提供给我们的浏览器。这使得它非常易于接近。对于 SCSS 新手来说，了解他们可以继续编写 CSS 并且它会在他们的 SCSS 中正常工作是令人放心的！

让我们把这作为我们的起点。首先，让我们更新我们的`bootstrap-vue`插件设置，以便我们使用 SCSS 而不是 CSS。

导航到我们应用程序的文件夹结构，并找到以下文件：`src/plugins/bootstrap-vue.js`。接下来，更新代码，使其看起来像下面这样：

```js
import Vue from 'vue'

import BootstrapVue from 'bootstrap-vue'
import 'bootstrap/scss/bootstrap.scss'
import 'bootstrap-vue/dist/bootstrap-vue.css'

Vue.use(BootstrapVue)
```

# 处理错误

可能会遇到“找不到 sass-loader”错误。您可以通过运行以下命令来解决它：

```js
npm install -D sass-loader sass
```

此时，如果您不确定加载程序是什么，可能值得重新阅读第二章*，Vue CLI 3 中的 Webpack*，以便对 webpack 加载程序进行复习。

可能会出现的另一个错误是：

```js
Module build failed (from ./node_modules/sass-loader/lib/loader.js): Error: Cannot find module 'node-sass'
```

你可以通过运行以下命令来解决这个错误：

```js
npm install node-sass
```

最后，在安装新包之后，你会看到一条消息，上面写着`found 1 high severity vulnerability`（或类似的内容）。你可以，也应该，根据控制台的提示修复这样的漏洞，并运行`npm audit fix`。

# 在我们的项目中编写一些 SCSS

现在我们已经导入了`bootstrap.scss`，我们可以开始使用它了。

让我们打开`App.vue`，并将`style`标签更新为以下内容：

```js
<style lang="scss">
#app {
  text-align: center;
  color: #2c3e50;
}

#nav {
  a {
    font-weight: bold;
  }
  a.router-link-exact-active {
    color: #42b983;
  }
}
</style>
```

在上面的代码中，我们看到了嵌套的例子，这是 SCSS 的一个特性，它允许我们在 SCSS 规则内模仿我们应用程序的 HTML 结构。

如果你在这个阶段查看你的项目在网页浏览器中的运行情况，你会注意到它仍在运行，并且没有改变。这是好的！这意味着一切都在正常工作，一切都得到了应有的服务。

现在让我们在我们的 SCSS 中添加一些变量、混合和插值。

# 覆盖 bootstrap-vue 样式

我们将首先添加一个自定义的 SCSS 文件。我们将把它命名为`custom.scss`，并将其放在项目的`assets`文件夹中。

现在让我们把这段代码添加到`custom.scss`中：

```js
$secondary: tomato;
```

我们刚刚覆盖了 Bootstrap 的变量。现在让我们在`App.vue`文件中使用它，通过导入`custom.scss`文件。我们还将在`#nav`元素内覆盖`.bg-secondary`类。更新后的`script`标签将如下所示：

```js
<style lang="scss">
@import './assets/custom.scss';
#app {
  text-align: center;
  color: #2c3e50;
}

#nav {
  a {
    font-weight: bold;
  }
  a.router-link-exact-active {
    color: #42b983;
  }
  .bg-secondary {
    background-color: $secondary;
  }
}
</style>
```

在我们保存了所有的更改之后，我们的项目将更新为如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/4fd83ec5-a839-4fac-9271-2c4ac97df62d.png)

接下来，我们将在`App.vue`文件中使用一些更高级的 SCSS 特性。

# 使用变量、混合和插值

在这一部分，我们将在 SCSS 中使用一些更多的变量、混合和插值语法。在我们开始本章之前，有必要提到一个网站，你可以在这个网站上练习编写 SCSS，并查看它生成的 CSS 输出。这个网站叫做 Sassmeister，网址是：[`www.sassmeister.com/`](https://www.sassmeister.com/)。

# 使用 Sassmeister 练习 SCSS

一旦你访问了这个网站，你可以通过悬停在选项上来选择你想使用的 Sass 或 SCSS 的风格，如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/633cd327-2100-4ee8-b017-cf8fa12bedce.png)

Sassmeister 网站是一个练习使用语言各种特性的好地方。例如，我们可以导航到我们项目的`node_modules`文件夹，并找到`bootstrap`文件夹。

如果您在`node_modules`中找不到 bootstrap 文件夹，可以使用`npm i bootstrap`进行安装。

接下来，打开`scss/mixins`文件夹，找到`_alert.scss`，其语法如下：

```js
@mixin alert-variant($background, $border, $color) {
  color: $color;
  @include gradient-bg($background);
  border-color: $border;

  hr {
    border-top-color: darken($border, 5%);
  }

  .alert-link {
    color: darken($color, 10%);
  }
}
```

正如我们所看到的，这是一个 mixin。让我们将其复制粘贴到 Sassmeister 中，看看我们得到什么输出。

实际上，我们不会得到任何输出。为什么呢？

原因很简单：在 Sass 或 SCSS 中的 mixin 实际上就像是其他语言中的函数，例如 JavaScript。因此，要在 SCSS 中使用 mixin，我们需要调用它，并传递一些参数。这里是一个例子：

```js
@include alert-variant(tomato, purple, white);
```

请注意，使用`@include`语法是运行 mixin 所必需的。

上述代码应该可以工作，但在我们的 mixin 定义内部，我们调用另一个 mixin，如下所示：

```js
@include gradient-bg($background);
```

这意味着为了使我们的代码在 Sassmeister 中编译，我们需要用其他内容替换上述行，例如，用以下内容：

```js
background: $background;
```

最后，我们的`@include` for `alert-custom`，需要应用于 CSS 规则。这意味着我们需要用 CSS 声明包装我们对`alert-custom`的调用，就像下面的例子一样：

```js
.alert-custom {
  @include alert-variant(tomato, purple, white);
}
```

将所有这些放在一起，这是我们的 SCSS 代码：

```js
@mixin alert-variant($background, $border, $color) {
  color: $color;
  background: $background;
  border-color: $border;

  hr {
    border-top-color: darken($border, 5%);
  }

  .alert-link {
    color: darken($color, 10%);
  }
}
.alert-custom {
  @include alert-variant(tomato, purple, white);
}
```

Sassmeister 将把上述代码编译为以下内容：

```js
.alert-custom {
  color: white;
  background: tomato;
  border-color: purple;
}

.alert-custom hr {
  border-top-color: #670067;
}

.alert-custom .alert-link {
  color: #e6e6e6;
}
```

既然我们知道如何使用 SCSS mixins，我们可以在我们的项目中使用它们。

# 在我们的 Vue 项目中使用 SCSS mixins 和插值

我们将从在`App.vue`中添加一个警报开始，如下所示：

```js
<b-alert show>Default Alert</b-alert>
```

这个简单的添加将更新我们的应用程序外观为这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/ac5d347f-094c-4c44-9758-95bc109d72df.png)

现在我们将添加一些 mixins 来更新样式。

我们将从添加我们的自定义 mixin 开始，以给我们添加的警报上色。以下是`custom.scss`的代码：

```js
$secondary: tomato!important;
$border: darken(#ff0000, 10%);

@mixin alert-variant($background, $border, $color) {
    color: $color;
    background: $background;
    border-color: $border;
    border-radius: 0;
    border-width: 5px;

    .alert-link {
      color: darken($color, 10%);
    }
  }
  .alert-info {
    @include alert-variant(rgb(255, 192, 181), #ff0000, white);
  }
```

保存上述文件后，我们的警报将如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/b956904c-0d93-4997-a41f-46741069cd24.png)

有了这个，我们结束本章。

# 摘要

SCSS 是一个庞大的主题。在像 Vue 这样的 VDOM 框架中使用 SCSS 可能会变得复杂，因为涉及的概念数量很多。本章为您提供了可用的内容以及如何入门的一瞥。

在本章中，我们已经涉及了在我们的项目中使用 SCSS。我们已经了解了如何在我们的 Vue 应用程序中使用 CSS 和 SCSS。我们还了解了 SCSS 的一些主要特性，如变量、mixins 和插值，还学会了如何在我们的 Vue 应用程序中实现 Bootstrap 4。接下来，我们学会了如何编辑 Vue 中 bootstrap-vue 插件的内置组件，并如何使用自定义 SCSS 代码对其进行更新。

在下一章中，我们将使用到目前为止学到的所有知识来构建一个简单的项目，并将其发布在 GitHub Pages 上。
