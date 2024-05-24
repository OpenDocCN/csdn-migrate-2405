# MobX 快速启动指南（三）

> 原文：[`zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7`](https://zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：探索 mobx-utils 和 mobx-state-tree

当你开始深入了解 MobX 的世界时，你会意识到某些类型的用例经常重复出现。第一次解决它们时，会有一种明确的成就感。然而，第五次之后，你会想要标准化解决方案。`mobx-utils`是一个 NPM 包，为你提供了几个标准实用程序，用于处理 MobX 中的常见用例。

为了进一步推动标准化水平，我们可以将更多结构化的意见引入我们的 MobX 解决方案中。这些意见是在多年的 MobX 使用中形成的，并包含了快速开发的各种想法。这一切都可以通过`mobx-state-tree` NPM 包实现。

在本章中，我们将更详细地介绍以下包：

+   `mobx-utils`提供了一系列实用功能

+   `mobx-state-tree`（**MST**）是一个有意见的 MobX

# 技术要求

你需要在系统上安装 Node.js。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter08`](https://github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter08)

查看以下视频，了解代码的实际操作：

[`bit.ly/2LiFSJO`](http://bit.ly/2LiFSJO)

# mobx-utils 的实用功能

`mobx-utils`提供了各种实用功能，可以简化 MobX 中的编程任务。你可以使用`npm`或`yarn`安装`mobx-utils`：

```jsx
$ npm install mobx-utils
```

在本节的其余部分，我们将重点介绍一些经常使用的实用程序。其中包括以下内容：

+   `fromPromise()`

+   `lazyObservable()`

+   `fromResource()`

+   `now()`

+   `createViewModel()`

# 使用 fromPromise()可视化异步操作

在 JavaScript 中，promise 是处理异步操作的好方法。在表示 React UI 上的操作状态时，我们必须确保处理 promise 的三种状态中的每一种。这包括 promise 处于`pending`（操作进行中）状态时，`fulfilled`（操作成功完成）状态时，或者`rejected`（失败）状态时。`fromPromise()`是处理 promise 的一种便利方式，并提供了一个很好的 API 来直观地表示这三种状态：

```jsx
newPromise = fromPromise(promiseLike)
```

`promiseLike`：`Promise`的实例或`(resolve, reject) => { }`

`fromPromise()`包装给定的 promise，并返回一个新的、带有额外可观察属性的、MobX 充电的 promise：

+   `state`：三个字符串值之一：`pending`、`fulfilled`或`rejected`：这些也作为`mobx-utils`包的常量可用：`mobxUtils.PENDING`、`mobxUtils.FULFILLED`和`mobxUtils.REJECTED`。

+   `value`：已解析的`value`或`rejected`错误。使用`state`来区分值。

+   `case({pending, fulfilled, rejected})`：这用于为三种状态提供 React 组件。

让我们通过一个例子来看看所有这些。我们将创建一个简单的`Worker`类，执行一些操作，这些操作可能会随机失败。这是跟踪操作的`Worker`类，通过调用`fromPromise()`来调用操作。请注意，我们将一个`promise`作为参数传递给`fromPromise()`：

```jsx
import { fromPromise, PENDING, FULFILLED, REJECTED } from 'mobx-utils';
class Worker {
    operation = null;
 start() {
 this.operation = fromPromise(this.performOperation());
    }
    performOperation() {
        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                clearTimeout(timeoutId);
                Math.random() > 0.25 ? resolve('200 OK') 
                    : reject(new Error('500 FAIL'));
            }, 1000);
        });
    }
}

```

为了可视化这个操作，我们可以利用`case()` API 来显示每个状态对应的 React 组件。这可以在以下代码中看到。随着操作从`pending`到`fulfilled`或`rejected`的进展，这些状态将以正确的 React 组件呈现。对于`fulfilled`和`rejected`状态，已解析的`value`或`rejected` `error`作为第一个参数传入：

```jsx
import { fromPromise, PENDING, FULFILLED, REJECTED } from 'mobx-utils';
import { observer } from 'mobx-react';

import React, { Fragment } from 'react';
import { CircularProgress, Typography } from '@material-ui/core/es/index';

@observer export class FromPromiseExample extends React.Component {
    worker;

    constructor(props) {
        super(props);

 this.worker = new Worker();
 this.worker.start();
    }

    render() {
        const { operation } = this.worker;
 return operation.case({
            [PENDING]: () => (
                <Fragment>
                    <CircularProgress size={50}  color={'primary'} />
                    <Typography variant={'title'}>
                        Operation in Progress
                    </Typography>
                </Fragment>
            ),
            [FULFILLED]: value => (
                <Typography variant={'title'}  color={'primary'}>
                    Operation completed with result: {value}
                </Typography>
            ),
            [REJECTED]: error => (
                <Typography variant={'title'}  color={'error'}>
                    Operation failed with error: {error.message}
                </Typography>
            ),
        });
    }
}
```

我们也可以手动切换可观察的`state`属性，而不是使用`case()`函数。实际上，`case()`在内部执行这个操作。

# 使用`lazyObservable()`进行延迟更新

对于执行代价高昂的操作，将其推迟到需要时是有意义的。使用`lazyObservable()`，您可以跟踪这些操作的结果，并在需要时更新。它接受一个执行计算并在准备就绪时推送值的函数：

```jsx
result = lazyObservable(sink => { }, initialValue)
```

在这里，`sink`是要调用的回调函数，将值推送到`lazyObservable`上。延迟可观察对象也可以以一些`initialValue`开始。

可以使用`result.current()`来检索`lazyObservable()`的当前值。一旦延迟可观察对象已更新，`result.current()`将有一些值。要再次更新延迟可观察对象，可以使用`result.refresh()`。这将重新调用计算，并最终通过`sink`回调推送新值。请注意，`sink`回调可以根据需要调用多次。

在以下代码片段中，您可以看到使用`lazyObservable()`来更新操作的值：

```jsx
import { lazyObservable } from 'mobx-utils';

class ExpensiveWorker {
    operation = null;

    constructor() {
 this.operation = lazyObservable(async sink => {
 sink(null); // push an empty value before the update
            const result = await this.performOperation();
 sink(result);
        });
    }

    performOperation() {
        return new Promise(resolve => {
            const timeoutId = setTimeout(() => {
                clearTimeout(timeoutId);
                resolve('200 OK');
            }, 1000);
        });
    }
}
```

MobX 跟踪对`current()`方法的调用，因此请确保仅在需要时调用它。在`render()`中使用此方法会导致 MobX 重新渲染组件。毕竟，组件的`render()`在 MobX 中转换为 reaction，每当其跟踪的 observable 发生变化时重新评估。

要在 React 组件（*observer*）中使用 lazy-observable，我们依赖于`current()`方法来获取其值。MobX 将跟踪此值，并在其更改时重新渲染组件。请注意，在按钮的`onClick`处理程序中，我们通过调用其`refresh()`方法来更新 lazy-observable：

```jsx
import { observer } from 'mobx-react';
import React, { Fragment } from 'react';
import {
    Button,
    CircularProgress,
    Typography,
} from '@material-ui/core/es/index'; **@observer** export class LazyObservableExample extends React.Component {
    worker;
    constructor(props) {
        super(props);

 this.worker = new ExpensiveWorker();
    }
   render() {
 const { operation } = this.worker;
 const result = operation.current();
        if (!result) {
            return (
                <Fragment>
                    <CircularProgress size={50}  color={'primary'} />
                    <Typography variant={'title'}>
                        Operation in Progress
                    </Typography>
                </Fragment>
            );
        }
         return (
            <Fragment>
                <Typography variant={'title'}  color={'primary'}>
                    Operation completed with result: {result}
                </Typography>
                <Button
  variant={'raised'}   color={'primary'}  onClick={() => operation.refresh()} >
                    Redo Operation
                </Button>
            </Fragment>
        );
    }
}
```

# 使用 fromResource()的通用 lazyObservable()

还有一种更一般化的`lazyObservable()`形式，称为`fromResource()`。类似于`lazyResource()`，它接受一个带有`sink`回调的函数。这充当*订阅*函数，仅在实际请求资源时调用。此外，它接受第二个参数，*取消订阅*函数，可用于在不再需要资源时进行清理：

```jsx
resource = fromResource(subscriber: sink => {}, unsubscriber: () => {},    
           initialValue)
```

`fromResource()` 返回一个 observable，当第一次调用它的`current()`方法时，它将开始获取值。它返回一个 observable，还具有`dispose()`方法来停止更新值。

在下面的代码片段中，您可以看到一个`DataService`类依赖于`fromResource()`来管理其 WebSocket 连接。数据的值可以使用`data.current()`来检索。这里，*data*充当 lazy-observable。在*订阅*函数中，我们设置了 WebSocket 并订阅了特定频道。我们在`fromResource()`的*取消订阅*函数中取消订阅此频道：

```jsx
import { **fromResource** } from 'mobx-utils';

class DataService {
    data = null;
    socket = null;

    constructor() {
 this.data = fromResource(
            async sink => {
                this.socket = new WebSocketConnection();
                await this.socket.subscribe('data');

                const result = await this.socket.get();

                sink(result);
            },
            () => {
                this.socket.unsubscribe('data');
                this.socket = null;
            },
        );
    }
}

const service = new DataService(); console.log(service.data.current());

// After some time, when no longer needed service.data.dispose();
```

我们可以使用`dispose()`方法显式处理资源。但是，MobX 足够聪明，知道没有更多观察者观察此资源时，会自动调用*取消订阅*函数。

mobx-utils 提供的一种特殊类型的 lazy-observable 是`now(interval: number)`。它将时间视为 observable，并以给定的间隔更新。您可以通过简单调用`now()`来检索其值，默认情况下每秒更新一次。作为 observable，它还会导致任何 reaction 每秒执行一次。在内部，`now()`使用`fromResource()`实用程序来管理计时器。

# 管理编辑的视图模型

在基于数据输入的应用程序中，通常会有表单来接受各种字段。在这些表单中，原始模型直到用户提交表单之前都不会发生变化。这允许用户取消编辑过程并返回到先前的值。这种情况需要创建原始模型的克隆，并在提交时推送编辑。尽管这种技术并不是非常复杂，但它确实增加了一些样板文件。

`mobx-utils`提供了一个方便的实用程序，名为`createViewModel()`，专门为这种情况量身定制：

```jsx
viewModel = createViewModel(model)
```

`model`是包含可观察属性的原始模型。`createViewModel()`包装了这个模型并代理了所有的读取和写入。这个实用程序具有一些有趣的特性，如下：

+   只要`viewModel`的属性没有更改，它将返回原始模型中的值。更改后，它将返回更新后的值，并将`viewModel`视为已修改。

+   要最终确定原始模型上的更新值，必须调用`viewModel`的`submit()`方法。要撤消任何更改，可以调用`reset()`方法。要恢复单个属性，请使用`resetProperty(propertyName: string)`。

+   要检查`viewModel`是否被修改，请使用`isDirty`属性。要检查单个属性是否被修改，请使用`isPropertyDirty(propertyName: string)`。

+   要获取原始模型，请使用方便的`model()`方法。

使用`createViewModel()`的优势在于，您可以将整个编辑过程视为单个事务。只有在调用`submit()`时才是最终的。这允许您过早取消并保留原始模型在其先前状态。

在以下示例中，我们正在创建一个包装`FormData`实例并记录`viewModel`和`model`属性的`viewModel`。您将注意到`viewModel`的代理效果以及值在`submit()`时如何传播回模型：

```jsx
class FormData {
    @observable name = '<Unnamed>';
    @observable email = '';
    @observable favoriteColor = '';
}

const viewModel = createViewModel(new FormData());

autorun(() => {
    console.log(
        `ViewModel: ${viewModel.name}, Model: ${
            viewModel.model.name
  }, Dirty: ${viewModel.isDirty}`,
    );
});

viewModel.name = 'Pavan';
viewModel.email = 'pavan@pixelingene.com';
viewModel.favoriteColor = 'orange';

console.log('About to reset');
viewModel.reset();

viewModel.name = 'MobX';

console.log('About to submit');
viewModel.submit();
```

`autorun()`的日志如下。您可以看到`submit()`和`reset()`对`viewModel.name`属性的影响：

```jsx
ViewModel: <Unnamed>, Model: <Unnamed>, Dirty: false ViewModel: Pavan, Model: <Unnamed>, Dirty: true About to reset... ViewModel: <Unnamed>, Model: <Unnamed>, Dirty: false ViewModel: MobX, Model: <Unnamed>, Dirty: true About to submit... ViewModel: MobX, Model: MobX, Dirty: false
```

# 还有很多可以发现的地方

这里描述的一些实用程序绝不是详尽无遗的。`mobx-utils`提供了更多实用程序，我们强烈建议您查看 GitHub 项目（[`github.com/mobxjs/mobx-utils`](https://github.com/mobxjs/mobx-utils)）以发现其余的实用功能。

有一些函数可以在 RxJS 流和 MobX Observables 之间进行转换，*processor-functions*可以在可观察数组附加时执行操作，MobX 的变体`when()`，它在超时后自动释放，等等。

# 一个有主见的 MobX 与 mobx-state-tree

MobX 在组织状态和应用各种操作和反应方面非常灵活。然而，它确实留下了一些问题需要你来回答：

+   应该使用类还是只是带有`extendObservable()`的普通对象？

+   数据应该如何规范化？

+   在序列化状态时如何处理循环引用？

+   还有很多

`mobx-state-tree`是一个提供了组织和结构化可观察状态的指导性指导的包。采用 MST 的思维方式会让你从一开始就获得几个好处。在本节中，我们将探讨这个包及其好处。

# 模型 - 属性、视图和操作

`mobx-state-tree`正如其名称所示，将状态组织在模型树中。这是一种以模型为先的方法，其中每个模型定义了需要捕获的状态。定义模型添加了在运行时对模型分配进行类型检查的能力，并保护您免受无意的更改。将运行时检查与像 TypeScript 这样的语言的使用结合起来，还可以获得编译时（或者说是设计时）类型安全性。通过严格类型化的模型，`mobx-state-tree`为您提供了安全的保证，并确保了您的类型模型的完整性和约束。这本身就是一个巨大的好处，特别是在处理像 JavaScript 这样的动态语言时。

让我们用一个简单的`Todo`模型来实现 MST：

```jsx
import { types } from 'mobx-state-tree';

const Todo = types.model('Todo', {
    title: types.string,
    done: false,
});
```

模型描述了它所持有的数据的形状。在`Todo`模型的情况下，它只需要一个`title` *string*和一个*boolean* `done`属性。请注意，我们将我们的模型分配给了一个大写的名称（`Todo`）。这是因为 MST 实际上定义了一个类型，而不是一个实例。

MST 中的所有内置类型都是`types`命名空间的一部分。`types.model()`方法接受两个参数：一个可选的字符串*name*（用于调试和错误报告）和一个定义类型各种属性的*object*。所有这些属性都将被严格类型化。让我们尝试创建这个模型的一个实例：

```jsx
const todo = Todo.create({
    title: 'Read a book',
    done: false,
});
```

请注意，我们已经将与模型中定义的相同的数据结构传递给了 `Todo.create()`。传递任何其他类型的数据将导致 MST 抛出类型错误。创建模型的实例也使其所有属性变成了可观察的。这意味着我们现在可以使用 MobX API 的全部功能。

让我们创建一个简单的反应，记录对 `todo` 实例的更改：

```jsx
import { autorun } from 'mobx';

autorun(() => {
    console.log(`${todo.title}: ${todo.done}`);
});

// Toggle the done flag todo.done = !todo.done; 
```

如果您运行此代码，您会注意到一个异常被抛出，如下所示：

```jsx
Error: [mobx-state-tree] Cannot modify 'Todo@<root>', the object is protected and can only be modified by using an action.
```

这是因为我们在动作之外修改了 `todo.done` 属性。您会回忆起前几章中的一个良好实践是将所有可观察的变化封装在一个动作内。事实上，甚至有一个 MobX API：`configure({ enforceActions: 'strict' })`，以确保这种情况发生。MST 对其状态树中的数据非常*保护*，并要求对所有变化使用动作。

这可能听起来非常严格，但它确实带来了额外的好处。例如，使用动作允许 MST 提供对中间件的一流支持。中间件可以*拦截*发生在状态树上的任何更改，并使实现诸如*日志记录、时间旅行*、*撤销*/*重做*、*数据库同步*等功能变得微不足道。

# 在模型上定义动作

我们之前创建的模型类型 `Todo` 可以通过链接的 API 进行扩展。`actions()` 就是这样一个 API，可以用来扩展模型类型的所有动作定义。让我们为我们的 `Todo` 类型做这件事：

```jsx
const Todo = types
  .model('Todo', {
        title: types.string,
        done: false,
    })
 .actions(self => ({
 toggle() {
 self.done = !self.done;
 },
 }));

const todo = Todo.create({
    title: 'Read a book',
    done: false,
});

autorun(() => {
    console.log(`${todo.title}: ${todo.done}`);
});

todo.toggle();
```

`actions()` 方法接受一个函数作为参数，该函数接收模型实例作为其参数。在这里，我们称之为 `self`。这个函数应该返回一个定义所有动作的键值映射。在前面的片段中，我们利用了 ES2015 的对象字面量语法，使动作对象看起来更易读。接受动作的这种风格有一些显著的好处：

+   使用函数允许您创建一个闭包，用于跟踪只被动作使用的私有状态。例如，设置在其中一个动作内部的 WebSocket 连接，不应该暴露给外部世界。

+   通过将模型的实例传递给 `actions()`，您可以保证 `this` 指针始终是正确的。您再也不必担心在 `actions()` 中定义的函数的上下文了。`toggle()` 动作利用 `self` 来改变模型实例。

定义的 actions 可以直接在模型实例上调用，这就是我们在`todo.toggle()`中所做的。MST 不再对直接突变提出异议，当`todo.done`改变时，`autorun()`也会触发。

# 使用视图创建派生信息

与 actions 类似，我们还可以使用`views()`扩展模型类型。在 MST 中，模型中的派生信息是使用`views()`来定义的。就像`actions()`方法一样，它可以链接到模型类型上：

```jsx
const Todo = types
  .model(/* ... */)
    .actions(/* ... */)
 .views(self => ({
 get asMarkdown() {
 return self.done
  ? `* [x] ~~${self.title}~~`
  : `* [ ] ${self.title}`;
 },

 contains(text) {
 return self.title.indexOf(text) !== -1;
 },
 })); const todo = Todo.create({
    title: 'Read a book',
    done: false,
});

autorun(() => {
    console.log(`Title contains "book"?: ${todo.contains('book')}`);
});

console.log(todo.asMarkdown);
// * [ ] Read a book

console.log(todo.contains('book')); // true
```

在`Todo`类型上引入了两个视图：

+   `asMarkdown()`是一个*getter*，它转换为一个 MobX 计算属性。像每个计算属性一样，它的输出被缓存。

+   `contains()`是一个常规函数，其输出不被缓存。然而，它具有在响应式上下文中重新执行的能力，比如`reaction()`或`autorun()`。

`mobx-state-tree`引入了一个非常严格的模型概念，其中明确定义了*state*、*actions*和*derivations*。如果你对在 MobX 中构建代码感到不确定，MST 可以帮助你应用 MobX 的理念并提供清晰的指导。

# 微调原始类型

到目前为止我们所看到的单一模型类型只是一个开始，几乎不能称为树。我们可以扩展领域模型使其更加真实。让我们添加一个`User`类型，他将创建`todo`项目：

```jsx
import { types } from 'mobx-state-tree';

const User = types.model('User', {
    name: types.string,
    age: 42,
    twitter: types.maybe(types.refinement(types.string, v => 
 /^\w+$/.test(v))),
});
```

在前面的定义中有一些有趣的细节，如下所示：

+   `age`属性被定义为常量`42`，这对应于`age`的默认值。当没有为用户提供值时，它将被设置为这个默认值。此外，MST 足够聪明，可以推断类型为`number`。这对于所有原始类型都适用，其中默认值的类型将被推断为属性的类型。此外，通过给出默认值，我们暗示`age`属性是可选的。声明属性的更详细形式是：`types.optional(types.number, 42)`。

+   `twitter`属性有一个更复杂的定义，但可以很容易地分解。`types.maybe()`表明`twitter`句柄是可选的，因此它可能是*undefined*。当提供值时，它必须是字符串类型。但不是任何字符串；只有与提供的正则表达式匹配的字符串。这为您提供了运行时类型安全性，并拒绝无效的 Twitter 句柄，如`Calvin & Hobbes`或空字符串。

MST 提供的类型系统非常强大，可以处理各种复杂的类型规范。它还很好地组合，并为您提供了一种将许多较小类型组合成较大类型定义的功能方法。这些类型规范为您提供了运行时安全性，并确保了您的领域模型的完整性。

# 组合树

现在我们有了`Todo`和`User`类型，我们可以定义顶层的`App`类型，它组合了先前定义的类型。`App`类型代表应用程序的状态。

```jsx
const App = types.model('App', {
 todos: types.array(Todo),
 users: types.map(User),
});

const app = App.create({
    todos: [
        { title: 'Write the chapter', done: false },
        { title: 'Review the chapter', done: false },
    ],
    users: {
        michel: {
            name: 'Michel Westrate',
            twitter: 'mwestrate',
        },
        pavan: {
            name: 'Pavan Podila',
            twitter: 'pavanpodila',
        },
    },
});

app.todos[0].toggle();
```

我们通过使用*高阶类型*（接受类型作为输入并创建新类型的类型）定义了`App`类型。在前面的片段中，`types.map()`和`types.array()`创建了这些高阶类型。

创建`App`类型的实例只是提供正确的 JSON 负载的问题。只要结构与类型规范匹配，MST 在运行时构建模型实例时就不会有问题。

记住：数据的形状始终会被 MST 验证。它永远不会允许不符合模型类型规范的数据更新。

请注意在前面的片段中，我们能够无缝调用`app.todos[0].toggle()`方法。这是因为 MST 能够成功构建`app`实例并用适当的类型包装 JSON 节点。

`mobx-state-tree`提升了对建模应用程序状态的重要性。为应用程序中的各种实体定义适当的类型对于其结构和数据完整性至关重要。一个很好的开始方式是将从服务器接收到的 JSON 编码为 MST 模型。下一步是通过添加更严格的类型、附加操作和视图来***加强***模型。

# 引用和标识符

到目前为止，本章一直在完全讨论在*树*中捕获应用程序的状态。树具有许多有趣的属性，易于理解和探索。但通常，当一个人开始将新技术应用于实际问题领域时，往往会发现树在概念上不足以描述问题领域。例如，*友谊关系*是双向的，不适合单向树。处理不是*组合*性质的关系，而是*关联*性质的关系，通常需要引入新的抽象层和技术，如*数据规范化*。

我们的应用程序中可以通过为`Todo`添加一个`assignee`属性来快速介绍这种关系。现在，很明显`Todo`并不*拥有*它的`assignee`，反之亦然；*todos*不是由单个用户拥有的，因为它们可以稍后被*重新分配*。因此，当组合不足以描述关系时，我们经常会退回到使用*外键*来描述关系。

换句话说，`Todo`项的 JSON 可以像下面的代码一样，其中`Todo`的`assignee`字段对应于`User`对象的`userid`字段：

使用`name`来存储`assignee`关系是一个坏主意，因为一个人的`name`并不是唯一的，而且它可能随时间改变。

```jsx
{
    todos: [
        {
            title: 'Learn MST',
            done: false,
            assignee: '37',
        },
    ],
    users: {
        '37': {
            userid: '37',
            name: 'Michel Weststrate',
            age: 33,
            twitter: 'mweststrate',
        },
    },
}
```

我们最初的想法可能是将`assignee`和`userid`属性类型化为`types.string`字段。然后，每当我们需要时，我们可以在`users`映射中查找指定的用户，因为用户存储在其自己的`userid`下。由于用户查找可能是一个常见的操作，我们甚至可以引入一个*视图*和*操作*来读取或写入该用户。这将使我们的用户模型如下所示的代码所示：

```jsx
import { types, getRoot } from 'mobx-state-tree';

const User = types.model('User', {
 userid: types.string, // uniquely identifies this User  name: types.string,
    age: 42,
    twitter: types.maybe(types.refinement(types.string, v => /^\w+$/.test(v))),
});

const Todo = types
  .model('Todo', {
 assignee: types.string, // represents a User  title: types.string,
        done: false,
    })
    .views(self => ({
 getAssignee() {
            if (!this.assignee) return undefined;
            return getRoot(self).users.get(this.assignee);
        },
    }))
    .actions(self => ({
 setAssignee(user) {
            if (typeof user === 'string') this.assignee = user;
            else if (User.is(user)) this.assignee = user.userid;
            else throw new Error('Not a valid user object or user id');
        },
    }));

const App = {
    /* as is */ };

const app = App.create(/* ... */);

console.log(app.todos[0].getAssignee().name); // Michel Weststrate 
```

在`getAssignee()`视图中，我们方便地利用了每个 MST 节点都知道自己在树中的位置这一事实。通过利用`getRoot()`实用程序，我们可以导航到`users`映射并获取正确的`User`对象。通过使用`getAssignee()`视图，我们获得了一个真正的`User`对象，以便我们可以直接访问和打印其`name`属性。

有几个有用的实用程序可以用来反映或处理树中的位置，例如`getPath()`、`getParent()`、`getParentOfType()`等。作为替代方案，我们可以将`getAssignee()`视图表示为`return resolvePath(self, "../../users/" + self.assignee)`。

我们可以将 MST 树视为状态的文件系统！`getAssignee()`只是将其转换为符号链接。

此外，我们引入了一个更新`assignee`属性的操作。为了确保`setAssignee()`操作可以方便地通过提供`userid`或实际*用户*对象来调用，我们应用了一些*类型区分*。在 MST 中，每种类型不仅公开了`create()`方法，还公开了`is`方法，以检查给定值是否属于相应的类型。

# 通过 types.identifier()和 types.reference()进行引用

我们可以在 MST 中清晰地表达这些查找/更新实用程序，这很好，但是如果您的问题领域很大，这将变得相当重复。幸运的是，这种模式内置在 MST 中。我们可以利用的第一种类型是`types.identifier()`，它表示某个字段唯一标识某个模型类型的实例。因此，在我们的示例中，我们可以将`userid`的类型定义为`types.identifier()`，而不是`types.string`。

其次，还有`types.reference()`。这种类型表示某个字段被序列化为原始值，但实际上表示对树中另一种类型的引用。MST 将自动为我们匹配`identifier`字段和`reference`字段，因此我们可以简化我们之前的状态树模型如下：

```jsx
import { types } from "mobx-state-tree"

const User = types.model("User", {
 userid: types.identifier(), // uniquely identifies this User
  name: types.string,
  age: 42,
  twitter: types.maybe(types.refinement(types.string, (v => /^\w+$/.test(v))))
})

const Todo = types.model("Todo", {
 assignee: types.maybe(types.reference(User)), // a Todo can be assigned to a User
  title: types.string,
  done: false
})

const App = /* as is */

const app = App.create(/* */)
console.log(app.todos[0].assignee.name) // Michel Weststrate
```

由于引用类型，读取`Todo`的`assignee`属性实际上将解析存储的标识符并返回正确的`User`对象。因此，我们可以立即在前面的示例中打印其名称。请注意，我们的状态仍然是一个树。还要注意的是，我们不必指定`User`实例的引用应该在何处或如何解析。MST 将自动维护一个内部的基于*类型+标识符*的查找表来解析引用。通过使用*引用*和*标识符*，MST 具有足够的类型信息来自动处理我们的*数据（去）规范化*。

`types.reference`非常强大，并且可以自定义，例如根据相对路径（就像真正的符号链接！）而不是标识符解析对象。在许多情况下，您将与上述一样结合`types.maybe`，以表达`Todo`不一定有`assignee`。同样，引用的数组和映射可以以类似的方式建模。

# 声明性模型的开箱即用的好处

MST 帮助您以声明性方式组织和建模复杂的问题领域。由于在您的领域中定义类型的一致方法，我们得到了清晰简单的心智模型的好处。这种一致性还为我们带来了许多开箱即用的功能，因为 MST 深入了解状态树。我们之前看到的一个例子是使用标识符和引用进行自动数据规范化。MST 内置了许多更多功能。其中，有一些功能在实际中最为实用。我们将在本节的其余部分简要讨论它们。

# 不可变的快照

MST 始终在内存中保留状态树的不可变版本，可以使用`getSnapshot()`API 检索。基本上，`const snapshot = getSnapshot(tree)`是`const tree = Type.create(snapshot)`的反向操作。`getSnapshot()`使得快速序列化整个树的状态非常方便。由于 MST 由 MobX 支持，我们也可以很好地跟踪这一点。

快照在模型实例上转换为计算属性。

以下代码片段在每次更改时自动将树的状态存储在*local-storage*中，但每秒最多一次：

```jsx
import { reaction } from 'mobx';
import { getSnapshot } from 'mobx-state-tree';

const app = App.create(/* as before */);

reaction(
    () => getSnapshot(app),
    snapshot => {
        window.localStorage.setItem('app', JSON.stringify(snapshot));
    },
    { delay: 1000 },
);
```

应该指出，MST 树中的每个节点本身都是 MST 树。这意味着在根上调用的任何操作也可以在其任何子树上调用。例如，如果我们只想存储整个状态的一部分，我们可以只获取子树的快照。

与`getSnapshot()`搭配使用的相关 API 是`applySnapshot()`。这可以用来以高效的方式使用快照更新树。通过结合`getSnapshot()`和`applySnapshot()`，你可以只用几行代码就构建一个时间旅行者！这留给读者作为练习。

# JSON 补丁

尽管快照有效地捕获了整个应用程序的状态，但它们不适合与服务器或其他客户端频繁通信。这是因为快照的大小与要序列化的状态的大小成线性增长。相反，对于实时更改，最好向服务器发送增量更新。*JSON-patch*（RFC-6902）是关于如何序列化这些增量更新的官方标准，MST 默认支持此标准。

`onPatch()`API 可用于监听作为更改副作用生成的`patches`。另一方面，`applyPatch()`执行相反的过程：给定一个补丁，它可以更新现有树。`onPatch()`监听器会生成由操作所做的状态更改产生的`patches`。它还公开了所谓的*inverse-patches*：一个可以撤消`patches`所做更改的集合。

```jsx
import { onPatch } from 'mobx-state-tree';

const app = App.create(/* see above */);

onPatch(app, (patches, inversePatches) => {
 console.dir(patches, inversePatches);
});

app.todos[0].toggle();
```

切换`todo`的前面代码在控制台上打印如下内容：

```jsx
// patches:   [{
 op: "replace", path: "/todos/0/done", value: true }]   // inverse-patches:   [{
 op: "replace", path: "/todos/0/done", value: false }]
```

# 中间件

我们在前面的部分简要提到了中间件，但让我们在这里扩展一下。中间件充当对状态树上调用的操作的拦截器。因为 MST 要求使用操作，我们可以确保每个 *操作* 都会通过中间件。中间件的存在使得实现几个横切面特性变得微不足道，例如以下内容：

+   日志记录

+   认证

+   时间旅行

+   撤销/重做

事实上，`mst-middlewares` NPM 包包含了一些先前提到的中间件，以及一些其他中间件。有关这些中间件的更多详细信息，请参阅：[`github.com/mobxjs/mobx-state-tree/blob/master/packages/mst-middlewares/README.md`](https://github.com/mobxjs/mobx-state-tree/blob/master/packages/mst-middlewares/README.md)。

# 进一步阅读

我们几乎只是触及了 MobX-State-Tree 的表面，但希望它已经在组织和构建 MobX 中的可观察状态方面留下了印象。这是一个明确定义的、社区驱动的方法，它融入了本书中讨论的许多最佳实践。要深入探索 MST，您可以参考官方入门指南：[`github.com/mobxjs/mobx-state-tree/blob/master/docs/getting-started.md#getting-started`](https://github.com/mobxjs/mobx-state-tree/blob/master/docs/getting-started.md#getting-started)。

# 总结

在本章中，我们涵盖了使用 `mobx-utils` 和 `mobx-state-tree` 等包采用 MobX 的实际方面。这些包将社区对于在各种场景中使用 MobX 的智慧编码化。

`mobx-utils` 为您提供了一组用于处理异步任务、处理昂贵的更新、为事务编辑创建视图模型等的实用工具。

`mobx-state-tree` 是一个全面的包，旨在简化使用 MobX 进行应用程序开发。它采用规范化的方法来构建和组织 MobX 中的可观察状态。通过这种声明性的方法，MST 能够更深入地理解状态树，并提供各种功能，例如运行时类型检查、快照、JSON 补丁、中间件等。总的来说，它有助于开发对 MobX 应用程序的清晰的心智模型，并将类型域模型置于前沿。

在下一章中，我们将通过一瞥了解 MobX 的内部工作，来完成 MobX 的旅程。如果 MobX 的某些部分看起来像*黑魔法*，下一章将驱散所有这些神话。


# 第九章：Mobx 内部

到目前为止我们所看到的 MobX 是从消费者的角度出发的，重点是如何使用它，最佳实践以及处理真实用例的 API。本章将向下一层，并揭示 MobX 响应式系统背后的机制。我们将看到支撑和构成*Observables-Actions-Reactions*三元组的核心抽象。

本章将涵盖的主题包括以下内容：

+   MobX 的分层架构

+   Atoms 和 ObservableValues

+   Derivations 和 reactions

+   什么是*透明函数式响应式编程*？

# 技术要求

您需要在系统上安装 Node.js。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter09`](https://github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter09)

查看以下视频以查看代码的运行情况：

[`bit.ly/2LvAouE`](http://bit.ly/2LvAouE)

# 分层架构

像任何良好的系统一样，MobX 由各个层构建而成，每个层提供了更高层的服务和行为。如果你把这个视角应用到 MobX 上，你可以从下往上看到这些层：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00037.jpeg)

+   **Atoms**：Atoms 是 MobX observables 的基础。顾名思义，它们是可观察依赖树的原子部分。它跟踪它的观察者，但实际上不存储任何值。

+   **ObservableValue，ComputedValue 和 Derivations**：`ObservableValue`扩展了`Atom`并提供了实际的存储。它也是包装 Observables 的核心实现。与此同时，我们有 derivations 和 reactions，它们是原子的*观察者*。它们对原子的变化做出响应并安排反应。`ComputedValue`建立在 derivations 之上，也充当一个 observable。

+   **Observable{Object, Array, Map}和 APIs**：这些数据结构建立在`ObservableValue`之上，并使用它来表示它们的属性和值。这也是 MobX 的 API 层，是与库从消费者角度交互的主要手段。

层的分离也在源代码中可见，不同的抽象层有不同的文件夹。这与我们在这里描述的情况并不是一一对应的，但在概念上，这些层在代码中也有很多相似之处。MobX 中的所有代码都是使用 TypeScript 编写的，并得到了一流的支持。

# 原子

MobX 的响应式系统由存在于可观察对象之间的依赖关系图支持。一个可观察对象的值可能依赖于一组可观察对象，而这些可观察对象又可能依赖于其他可观察对象。例如，一个购物车可以有一个名为`description`的*计算属性*，它依赖于它所持有的`items`数组和应用的任何`coupons`。在内部，`coupons`可能依赖于`CouponManager`类的`validCoupons` *计算属性*。在代码中，这可能看起来像这样：

```jsx
class Coupon {
    @observable isValid = false;

    /*...*/ }

class CouponManager {
    @observable.ref coupons = [];

    @computed
  get validCoupons() {
        return this.coupons.filter(coupon => coupon.isValid);
    }

    /*...*/ }

class ShoppingCart {
    @observable.shallow items = [];

    couponManager = new CouponManager();

    @computed
  get coupons() {
        return this.couponManager.validCoupons;
    }

    @computed
  get description() {
        return `Cart has ${this.items.length} item(s) with ${
            this.coupons.**length**
  } coupon(s) applied.`;
    }

    /*...*/ }
```

可视化这组依赖关系可能会给我们一个简单的图表，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00038.jpeg)

在运行时，MobX 将创建一个支持依赖树。这棵树中的每个节点都将由`Atom`的一个实例表示，这是 MobX 的核心构建块。因此，我们可以期望在前面图表中的树中的节点有五个*原子*。

原子有两个目的：

+   当它被*读取*时通知。这是通过调用`reportObserved()`来完成的。

+   当它被*改变*时通知。这是通过调用`reportChanged()`来完成的。

作为 MobX 响应性结构的一个节点，原子扮演着通知每个节点上发生的读取和写入的重要角色。

在内部，原子会跟踪其观察者并通知它们发生的变化。当调用`reportChanged()`时会发生这种情况。这里一个明显的遗漏是原子的实际值并没有存储在`Atom`本身。为此，我们有一个名为`ObservableValue`的子类，它是建立在`Atom`之上的。我们将在下一节中看到它。

因此，原子的核心约定包括我们之前提到的两种方法。它还包含一些像`observers`数组、是否正在被观察等一些管理属性。我们可以在讨论中安全地忽略它们：

```jsx
class Atom {
    observers = [];

 reportObserved() {}
 reportChanged() {}

    /* ... */ }
```

# 在运行时读取原子

MobX 还让你能够在运行时看到后台的原子。回到我们之前的计算`description`属性的例子，让我们探索它的依赖树：

```jsx
import { autorun, **$mobx**, **getDependencyTree** } from 'mobx';

const cart = new ShoppingCart();
const disposer = autorun(() => {
    console.log(cart.description);
});

const descriptionAtom = cart[$mobx].values.get('description'); console.log(getDependencyTree(descriptionAtom));
```

在前面的片段中有一些细节值得注意：

+   MobX 为您提供了一个特殊的符号`$mobx`，其中包含对可观察对象的内部维护结构的引用。`cart`实例使用`cart[$mobx].values`维护其所有可观察属性的映射。通过从此映射中读取，可以获得`description`属性的后备原子：`cart[$mobx].values.get('description')`。

+   我们可以使用 MobX 公开的`getDependencyTree()`函数获取此属性的依赖树。它以`Atom`作为输入，并返回描述依赖树的对象。

这是`description`属性的`getDependencyTree()`的输出。为了清晰起见，已经删除了一些额外的细节。您看到`ShoppingCart@16.items`被提到两次的原因是因为它指向`items`（引用）和`items.length`属性：

```jsx
{
    name: 'ShoppingCart@16.description',
    dependencies: [
        { name: 'ShoppingCart@16.items' },
        { name: 'ShoppingCart@16.items' },
        {
            name: 'ShoppingCart@16.coupons',
            dependencies: [
                {
                    name: 'CouponManager@19.validCoupons',
                    dependencies: [{ name: 'CouponManager@19.coupons' }],
                },
            ],
        },
    ],
};
```

还有一个方便的 API，`getAtom(thing: any, property: string)`，用于从可观察对象和观察者中读取原子。例如，在我们之前的示例中，我们可以使用`getAtom(cart, 'description')`来获取*description*原子，而不是使用特殊符号`$mobx`并读取其内部结构。`getAtom()`是从`mobx`包中导出的。作为练习，找出前一个代码片段中`autorun()`的依赖树。您可以使用`disposer[$mobx]`或`getAtom(disposer)`来获取反应实例。类似地，还有`getObserverTree()`实用程序，它可以给出依赖于给定可观察对象的观察者。看看您是否可以从支持`description`属性的原子找到与`autorun()`的连接。

# 创建一个原子

作为 MobX 用户，您很少直接使用`Atom`。相反，您会依赖 MobX 公开的其他便利 API 或数据结构，如`ObservableObject`、`ObservableArray`或`ObservableMap`。然而，现实世界总是会出现一些情况，您可能需要深入了解一些更深层次的内容。

MobX 确实为您提供了一个方便的工厂函数来创建原子，恰当地命名为`createAtom()`：

**`createAtom(name, onBecomeObservedHandler, onBecomeUnobservedHandler)`**

+   `name`（`string`）：原子的名称，由 MobX 中的调试和跟踪工具使用

+   `onBecomeObservedHandler`（`（）=> {}`）：当原子首次被观察时通知的回调函数

+   `onBecomeUnobservedHandler`（`（）=> {}`）：当原子不再被观察时通知的回调函数

`onBecomeObserved`和`onBecomeUnobserved`是原子在响应系统中变为活动和非活动的两个时间点。这些通常用于资源管理，分别用于设置和拆除。

# 原子钟示例

让我们看一个使用`Atom`的例子，也说明了原子如何参与响应系统。我们将创建一个*简单的时钟*，当原子被观察时开始滴答，并在不再被观察时停止。实质上，我们这里的资源是由`Atom`管理的计时器（时钟）：

```jsx
import { createAtom, autorun } from 'mobx';

class Clock {

    constructor() {
 this.atom = createAtom(
 'Clock',
 () => {
 this.startTicking();
 },
 () => {
 this.stopTicking();
 },
 );

        this.intervalId = null;
    }

    startTicking() {
        console.log('Clock started');
        this.tick();
        this.intervalId = setInterval(() => this.tick(), 1000);
    }

    stopTicking() {
        clearInterval(this.intervalId);
        this.intervalId = null;

        console.log('Clock stopped');
    }

    tick() {
 this.atom.reportChanged();
    }

    get() {
 this.atom.reportObserved();
        return new Date();
    }
}

const clock = new Clock();

const disposer = autorun(() => {
 console.log(clock.get());
});

setTimeout(disposer, 3000);
```

在前面的片段中有许多有趣的细节。让我们在这里列出它们：

+   在调用`createAtom()`时，我们提供了当原子被观察和不再被观察时的处理程序。当原子实际上变得被观察时，这可能看起来有点神秘。这里的秘密在于使用`autorun()`，它设置了一个副作用来读取原子钟的当前值。由于`autorun()`立即运行，调用了`clock.get()`，进而调用了`this.atom.reportObserved()`。这就是原子在响应系统中变为活动的方式。

+   一旦原子被观察，我们就开始时钟计时器，每秒滴答一次。这发生在`onBecomeObserved`回调中，我们在其中调用`this.startTicking()`。

+   每秒，我们调用`this.atom.reportChanged()`，将改变的值传播给所有观察者。在我们的例子中，我们只有一个`autorun()`，它重新执行并打印控制台日志。

+   我们不必存储当前时间，因为我们在每次调用`get()`时返回一个新值。

+   另一个神秘的细节是当原子变得*未被观察*时。这发生在我们在三秒后处理`autorun()`后，导致在原子上调用`onBecomeUnobserved`回调。在回调内部，我们停止计时器并清理资源。

由于`Atoms`只是依赖树的节点，我们需要一个可以存储可观察值的构造。这就是`ObservableValue`类的用处。将其视为带有值的`Atom`。MobX 在内部区分两种可观察值，`ObservableValue`和`ComputedValue`。让我们依次看看它们。

# ObservableValue

`ObservableValue`是`Atom`的子类，它增加了存储可观察值的能力。它还增加了一些功能，比如提供拦截值更改和观察值的钩子。这也是`ObservableValue`的定义的一部分。以下是`ObservableValue`的简化定义：

```jsx
class ObservableValue extends Atom {
    value;

    get() {
        /* ... */
 this.reportObserved();
    }

    set(value) {

        /* Pass through interceptor, which may modify the value (*newValue*) ... */

        this.value = newValue;
 this.reportChanged();
    }

    intercept(handler) {}
    observe(listener, fireImmediately) {}
}
```

请注意`get()`方法中对`reportObserved()`的调用以及`set()`方法中对`reportChanged()`的调用。这些是原子值被读取和写入的地方。通过调用这些方法，`ObservableValue`参与了响应系统。还要注意，`intercept()`和`observe()`实际上并不是响应系统的一部分。它们更像是钩入到可观察值发生的更改的*事件发射器*。这些事件不受事务的影响，这意味着它们不会排队等到批处理结束，而是立即触发。

`ObservableValue`也是 MobX 中所有高级构造的基础。这包括 Boxed Observables、Observable Objects、Observable Arrays 和 Observable Maps。这些数据结构中存储的值都是`ObservableValue`的实例。

包装在`ObservableValue`周围的最薄的包装器是箱式可观察值，您可以使用`observable.box()`创建它。这个 API 实际上会给您一个`ObservableValue`的实例。您可以使用它来调用`ObservableValue`的任何方法，就像在以下代码片段中看到的那样：

```jsx
import {observable} from 'mobx';

const count = observable.box(0);

count.intercept(change => {
    console.log('Intercepted:', change);

    return change; // No change
 // Prints // Intercepted: {object: ObservableValue$$1, type: "update", newValue: 1} // Intercepted: {object: ObservableValue$$1, type: "update", newValue: 2} });

count.observe(change => {
    console.log('Observed:', change);
    // Prints
 // Observed: {object: ObservableValue$$1, type: "update", newValue: 1} // Observed: {object: ObservableValue$$1, type: "update", newValue: 2, oldValue: 1} });

// Increment count.set(count.get() + 1);

count.set(count.get() + 1);
```

# ComputedValue

在可观察树中，您可以拥有的另一种*可观察值*是`ComputedValue`。这与`ObservableValue`在许多方面都不同。`ObservableValue`为基础原子提供存储并具有*自己的值*。MobX 提供的所有数据结构，如 Observable Object/Array/Map，都依赖于`ObservableValue`来存储叶级别的值。`ComputedValue`在某种意义上是特殊的，它没有自己的内在值。其*值*是从其他可观察值（包括其他计算值）计算得出的。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00039.jpeg)

这在`ComputedValue`的定义中变得明显，它不是`Atom`的子类。相反，它具有与`ObservableValue`类似的接口，除了拦截的能力。以下是一个突出显示有趣部分的简化定义：

```jsx
class ComputedValue {
    get() {
        /* ... */
 reportObserved(this);
        /* ... */
    }

    set(value) { /* rarely applicable */ }

    observe(listener, fireImmediately) {}
}
```

在前面的片段中需要注意的一件重要的事情是，由于`ComputedValue`不依赖于`Atom`，它对`reportObserved()`使用了不同的方法。这是一个更低级别的实现，它建立了可观察对象和观察者之间的链接。这也被`Atom`在内部使用，因此行为完全相同。此外，没有调用`reportChanged()`，因为`ComputedValue`的 setter 没有定义得很好。

正如你所看到的，`ComputedValue`主要是一个只读的可观察对象。虽然 MobX 提供了一种*设置*计算值的方法，但在大多数情况下，这并没有太多意义。计算值的 setter 必须对 getter 进行相反的计算。在大多数情况下，这几乎是不可能的。考虑一下本章前面的关于购物车`description`的例子。这是一个从其他可观察对象（如`items`和`coupons`）产生字符串的计算值。这个计算属性的*setter*会是什么样子？它必须解析字符串，并以某种方式得到`items`和`coupons`的值。这显然是不可能的。因此，一般来说，最好将`ComputedValue`视为只读的可观察对象。

由于计算值依赖于其他可观察对象，实际的*值计算*更像是一个副作用。它是依赖对象中任何一个变化的副作用。MobX 将这种计算称为派生。稍后我们将看到，派生与反应是同义词，强调了计算的副作用方面。

`ComputedValue`是依赖树中唯一一种既是可观察的又是观察者的节点。它的值是可观察的，并且由于它依赖于其他可观察值，它也是观察者。

`ObservableValue` = 仅可观察

`Reaction` = 仅观察者

`ComputedValue` = 可观察和观察者

# 高效的计算

`ComputedValue`的派生函数可能是一个昂贵的操作。因此，最好缓存这个值，并尽可能懒惰地计算。这是 MobX 的规范，并且它采用了一堆优化来使这个计算变成懒惰评估：

+   首先，除非明确请求或者有一个依赖于这个`ComputedValue`的反应，否则值永远不会被计算。如预期的那样，当没有观察者时，它根本不会被计算。

+   一旦计算出来，它的值将被缓存以供将来读取。它会一直保持这种状态，直到依赖的可观察对象发出变化信号（通过其`reportChanged()`）并导致推导重新评估。

+   `ComputedValue`可以依赖于其他计算值，从而创建依赖树。除非直接子级发生了变化，否则它不会重新计算。如果依赖树深处发生了变化，它将等待直接依赖项发生变化。这种行为提高了效率，不会进行不必要的重新计算。

正如您所看到的，`ComputedValue`中嵌入了多个级别的优化。强烈建议利用计算属性的强大功能来表示领域逻辑及其 UI 的各种细微差别。

# 推导

到目前为止，我们已经看到了 MobX 的构建模块，它用`Atoms`、`ObservableValue`和`ComputedValue`表示可观察状态。这些都是构建应用程序的反应状态图的良好选择。但是，反应性的真正力量是通过使用推导或反应来释放的。观察对象和反应一起形成了 MobX 的阴阳。它们彼此依赖，以推动反应系统。

推导或反应是跟踪发生的地方。它跟踪在推导或反应的上下文中使用的所有可观察对象。MobX 将监听它们的`reportObserved()`并将它们添加到被跟踪的可观察对象列表（`ObservableValue`或`ComputedValue`）。每当可观察对象调用`reportChanged()`（当它被改变时会发生），MobX 将安排运行所有连接的观察者。

我们将交替使用***推导***和***反应***。两者都旨在传达使用可观察对象产生新值（*推导*）或副作用（*反应*）的副作用执行。这两种类型之间的跟踪行为是共同的，因此我们将它们视为同义词使用。

# 推导的周期

MobX 使用`globalState`来保持对当前执行的*推导*或*反应*的引用。每当反应运行时，所有触发其`reportObserved()`的可观察对象都将被标记为该反应的一部分。事实上，这种关系是双向的。一个*可观察对象*跟踪其所有观察者（反应），而一个*反应*跟踪它当前正在观察的所有可观察对象。当前执行的反应将被添加为每个可观察对象的*观察者*。如果观察者已经被添加，它将被忽略。

当您设置观察者时，它们都会返回一个清理函数。我们已经在`autorun()`，`reaction()`或`when()`的返回值中看到了这一点，它们都是清理函数。调用此清理函数将从连接的可观察对象中删除观察者：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00040.jpeg)

在执行反应时，只有现有的可观察对象才会被考虑进行跟踪。然而，在同一反应的不同运行中，可能会引用一些新的可观察对象。当由于某些分支逻辑而原本被跳过的代码段执行时，这是可能的。由于在跟踪反应时可能会发现新的可观察对象，MobX 会对可观察对象进行检查。新的可观察对象将被添加到可观察对象列表中，而不再使用的可观察对象将被移除。可观察对象的移除不会立即发生；它们将在当前反应完成后排队等待移除。

在可观察对象和反应之间的相互作用中，**操作**似乎是非常缺失的。嗯，并非完全如此。它们确实有一定的作用要发挥。正如本书中多次提到的，操作是改变可观察对象的推荐方式。操作创建一个事务边界，并确保所有更改通知仅在完成后触发。这些操作也可以嵌套，导致嵌套事务。只有当最顶层的*操作*（或事务）完成时，通知才会被触发。这也意味着在事务（嵌套或非嵌套）进行时，*反应*都不会运行。MobX 将此事务边界视为**批处理**，并在内部跟踪嵌套。在批处理期间，所有反应将被排队并在最顶层批处理结束时执行。

当排队的反应执行时，循环再次开始。它将跟踪可观察对象，将它们与执行的派生链接起来，添加任何新发现的可观察对象，并在批处理期间排队任何发现的反应。如果没有更多的批处理，MobX 将认为自己是稳定的，并回到等待任何可观察变化的状态。

关于反应的一个有趣的事情是它们可以重新触发自己。在一个反应中，你可以读取一个可观察对象，并触发一个改变同一个*可观察对象*的动作。这可能发生在同一段代码中，也可能间接地通过从反应中调用的某个函数。唯一的要求是它不应该导致无限循环。MobX 期望反应尽快变得稳定。

如果由于某种原因，迭代超过 100 次并且没有稳定性，MobX 将以异常退出。

反应在 100 次迭代后没有收敛到稳定状态。可能是反应函数中存在循环：`Reaction[Reaction@14]`

如果没有 100 次迭代的上限，它会在运行时导致堆栈溢出，使得更难追踪其原因。MobX 通过**100 次迭代**的限制来保护你免受这种困境的影响。请注意，它并不禁止你使用循环依赖，而是帮助识别导致不稳定（无限循环）的代码。

即使在*100 次反应*之后仍然不稳定的简单片段如下所示。这个反应观察`counter`可观察对象，并通过调用`spinLoop()`动作来修改它。这导致反应一遍又一遍地运行，直到在*100 次迭代后放弃：*

```jsx
class Infinite {
    @observable counter = 0;

    constructor() {
        reaction(
 () => this.counter,
            counterValue => {
                console.log(`Counter is ${counterValue}`);
 this.spinLoop();
            },
        );
    }

    @action
  spinLoop() {
        this.counter = this.counter + 1;
    }
}

new Infinite().spinLoop();

/* Console log:
*Reaction doesn't converge to a stable state after 100 iterations. Probably there is a cycle in the reactive function: Reaction[Reaction@14]* */
```

正如你所知，执行派生或反应对于建立*可观察对象*和*观察者*之间的联系至关重要。没有*反应*，反应性系统中就没有生命。它只会是一组可观察对象。你仍然可以触发动作和改变它们，但它仍然会非常静态和非反应性。反应（派生）完成了*可观察对象-动作-反应*的三元组，并为这个反应性系统注入了生命。

最终，**反应**是*从你的状态中提取值*并启动整个反应过程的关键！

# 异常处理

处理错误被认为是 MobX 反应的一个重要部分。事实上，它为`autorun()`、`reaction()`和`when()`提供了一个提供错误处理程序(`onError`)的选项，在`computed()`的情况下，每当读取计算值时都会将错误抛回给你。在这些情况下，MobX 会像预期的那样继续工作。

在内部，MobX 在执行 reactions 和 derivations 时加入了额外的`try-catch`块。它会捕获这些块内部抛出的错误，并通过`onError`处理程序或在读取计算值时将它们传播回给你。这种行为确保你可以继续运行你的 reactions，并在`onError`处理程序内采取任何恢复措施。

如果对于一个 reaction 没有指定`onError`处理程序，MobX 也有一个全局的`onReactionError()`处理程序，它将被调用来处理 reaction 中抛出的任何异常。你可以注册一个监听器来处理这些全局 reaction 错误，比如错误监控、报告等：

`onReactionError(handler-function: (error, reaction) => { })`

**handler-function**：一个接受错误和 reaction 实例作为参数的函数。

在调用全局`onReactionError`处理程序之前，MobX 首先检查失败的 reaction 是否有一个`onError`处理程序。只有当不存在时，才会调用全局处理程序。

现在，如果出于某种原因，你不希望 MobX 捕获异常并在全局`onReactionError`处理程序上报告它，你有一个出路。通过配置 MobX 为`configure({ disableErrorBoundaries: true })`，你将会在*失败点*得到一个常规异常。现在你需要通过*try-catch*块在 reaction 内部直接处理它。

在正常情况下不应该使用`configure({ disableErrorBoundaries: true })`，因为不处理异常可能会破坏 MobX 的内部状态。然而，打开这个配置可以帮助你调试，因为它会使异常未被捕获。现在你可以在引起异常的确切语句上暂停调试器。

# API 层

这是 MobX 面向消费者的最外层层，建立在前面提到的基础之上。在这一层中，突出的 API 包括本书中遍布的`observable()`、`observable.box()`、`computed()`、`extendObservable()`、`action()`、`reaction()`、`autorun()`、`when()`等。当然，我们还有装饰器，比如`observable.ref`、`observable.deep`、`observable.shallow`、`action.bound`、`computed.struct`等。

核心数据结构，如`ObservableObject`、`ObservableArray`和`ObservableMap`依赖于`ObservableValue`来存储它们的所有值。

对于`ObservableObject...`：

+   键值对的值由`ObservableValue`支持。

+   每个计算属性都由`ComputedValue`支持。

+   `ObservableObject`的`keys()`方法也由`Atom`支持。这是必要的，因为您可能会在其中一个反应中对`keys()`进行迭代。当添加或删除键时，您希望您的反应再次执行。`keys()`的这个原子会对添加和删除触发`reportChanged()`，并确保连接的反应被重新执行。

对于`ObservableArray...`：

+   每个索引值都由`ObservableValue`支持。

+   `length`属性明确由`Atom`支持。请注意，*ObservableArray*具有与 JavaScript 数组相同的接口。在***MobX 4***中，它是一个类似数组的数据结构，在***MobX 5***中成为了真正的 JS 数组（由 ES6 的*Proxy*支持）。对`length`的读取和写入将导致在原子上调用`reportObserved()`和`reportChanged()`。实际上，当使用*map*、*reduce*、*filter*等方法时，将使用支持`Atom`来触发`reportObserved()`。对于任何类似*splice*、*push*、*pop*、*shift*等的变异方法，将触发`reportChanged()`。这确保了连接的反应按预期触发。

对于`ObservableMap...`：

+   *键-值*对的值由`ObservableValue`支持。

+   就像*ObservableObject*一样，它也为`keys()`方法维护了一个`Atom`的实例。任何添加或删除键的操作都会通过原子上的`reportChanged()`通知。调用`keys()`方法本身将在原子上触发`reportObserved()`。

MobX 中的集合，包括对象、数组和映射，本质上是可观察盒子（`ObservableValue`）的集合。它们可以组织为列表或映射，或者组合在一起创建复杂的结构。

所有这些数据结构还公开了`intercept()`和`observe()`方法，允许对值进行细粒度拦截和观察。通过构建在`Atom`、`ObservableValue`和*derivations*的基础上，MobX 为您提供了一个强大的 API 工具箱，用于在应用程序中构建复杂的状态管理解决方案。

# 透明的函数式响应式编程

MobX 被认为是**透明的函数式响应式编程**（**TFRP**）系统。是的，在那一行有太多的形容词！让我们逐字逐句地分解它。

# 它是透明的...

将*可观察对象*连接到*观察者*，使观察者能够对可观察对象的变化做出反应。这是我们对 MobX 的基本期望，我们建立这些连接的方式非常直观。除了使用装饰器和在观察者内部取消引用可观察对象之外，没有明确的连接。由于连接的开销很低，MobX 变得非常*声明式*，您可以表达您的意图，而不必担心机制。在*可观察对象*和*观察者*之间建立的自动连接使*反应系统*能够自主运行。这使 MobX 成为一个*透明*的系统，因为连接可观察对象和观察者的工作基本上被取消了。在反应中使用可观察对象就足以连接这两者。

# 它是反应性的...

这种反应性也非常细粒度。可观察对象的依赖树可以尽可能简单，也可以同样深入。有趣的是，您永远不必担心连接的复杂性或效率。MobX 深知您的依赖关系，并通过仅在需要时做出反应来确保效率。没有轮询或过多的事件被触发，因为依赖关系不断变化。因此，MobX 也是一个非常反应灵敏的系统。

# 它是功能性的...

正如我们所知，**功能**编程是利用函数的力量来执行数据流转换。通过使用各种功能操作符，如 map、reduce、filter、compose 等，我们可以对*输入数据*进行转换并产生输出值。在 MobX 的情况下，关键在于*输入数据*是可观察的，是一个随时间变化的值。MobX 结合了反应系统的特性，并确保在输入数据（可观察对象）发生变化时自动应用功能-转换。正如前面讨论的那样，它以一种透明的方式通过建立可观察对象和反应之间的隐式连接来实现这一点。

这些特质的结合使 MobX 成为一个 TFRP 系统。

从作者的角度来看，TFRP 的首字母缩略词的起源来自以下文章：[`github.com/meteor/docs/blob/version-NEXT/long-form/tracker-manual.md`](https://github.com/meteor/docs/blob/version-NEXT/long-form/tracker-manual.md)。

# 价值导向编程

MobX 也涉及**价值导向编程**（VOP），在这里你关注值的变化、它的依赖关系以及在响应系统中的传播。通过 VOP，你关注的是*连接的值是什么？*而不是*值是如何连接的？*它的对应物是**事件导向编程**（EOP），在这里你关注的是一系列事件来通知变化。事件只报告已发生的事情，没有依赖关系的概念。与价值导向编程相比，它在概念上处于较低级别。

VOP 依赖事件在内部执行其工作。当一个值发生变化时，会触发事件来通知变化。这些事件的处理程序将把值传播给所有监听器（***观察者***）的***可观察值***。这通常会导致调用反应/派生。因此，反应和派生，即值变化的副作用，处于值传播事件的尾端。

以 VOP 的方式思考会提高抽象级别，使你更接近正在处理的领域。与其担心值传播的机制，你只需专注于通过可观察值、计算属性和观察者（反应/派生）建立连接。正如我们所知，这就是 MobX 的三位一体：*可观察值-动作-反应*。这种思维方式在本质上非常***声明式***：*值的变化是什么*而不是*如何*。当你更深入地沉浸在这种思维模式中时，许多状态管理中的场景会变得更加可行。你会对这种范式提供的*简单、强大和高效*感到惊讶。

如果你确实需要深入了解事件层，MobX 有`intercept()`和`observe()`的 API。它们允许你钩入当可观察值*添加、更新或删除*时触发的事件。还有来自`mobx-utils` npm 包的`fromStream()`和`toStream()`的 API，它们提供了与 RxJS 兼容的事件流。这些事件不参与 MobX 事务（批处理），永远不会排队，总是立即触发。

在消费者代码中很少使用事件 API；它们主要被工具和实用函数（如`spy()`、`trace()`等）使用，以便深入了解 MobX 的事件层。

# 总结

通过这个深入了解 MobX 的窥视，您可以欣赏到 TFRP 系统的强大之处，它暴露了一个令人惊讶地简单的 API。从 `Atoms` 开始的功能层，由 `ObservableValue` 包装，具有 API 和更高级的数据结构，为您的领域建模提供了全面的解决方案。

在内部，MobX 管理着可观察对象和观察者（反应/推导）之间的所有连接。它会自动完成，几乎不会干扰您通常的编程风格。作为开发者，您编写的代码会感觉很自然，而 MobX 则消除了管理响应式连接的复杂性。

MobX 是一个经过各种领域的实战考验的开源项目，接受来自世界各地开发者的贡献，并在多年来不断成熟。通过这次对 MobX 的内部了解，我们希望能够降低对这个强大的状态管理库的贡献障碍。
